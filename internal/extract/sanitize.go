package extract

import (
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxSanitizeMarkdownScanBytes = 8 << 20 // 8 MiB linear scan cap (matches TS MAX_MARKDOWN_SANITIZE_CHARS)

var (
	reMintlifyDocIndexSanGo        = regexp.MustCompile(`(?i)^\s*>\s*##\s*Documentation Index[ \t]*\r?\n>\s*Fetch the complete documentation index at:\s*\S+[ \t]*\r?\n>\s*Use this file to discover all available pages before exploring further\.[ \t]*\r?\n+`)
	reMintlifyFooterSanGo          = regexp.MustCompile(`(?i)^This documentation is built and hosted on \[Mintlify\]\([^)\r\n]{1,300}\),\s*a developer documentation platform\.[ \t]*$`)
	reMinifiedSchemaJsonFenceSanGo = regexp.MustCompile("(?i)^`{3,}json[ \\t]*\\r?\\n\\{\\s*\"@context\"\\s*:\\s*\"https?://schema\\.org\"[^\\r\\n]{80,}\\r?\\n`{3,}$")
	reTwoslashWordSanGo            = regexp.MustCompile(`(?i)\btwoslash\b`)
	reTwoslashCutMarkerSanGo       = regexp.MustCompile(`(?m)^[ \t]*//[ \t]*---cut(?:-(?:before|after))?---[ \t]*$`)
	reTwoslashCutBeforeSanGo       = regexp.MustCompile(`(?m)^[ \t]*//[ \t]*---cut(?:-before)?---[ \t]*\r?\n`)
	reTwoslashCutAfterSanGo        = regexp.MustCompile(`\r?\n[ \t]*//[ \t]*---cut-after---[ \t]*(?:\r?\n|$)`)
	reTwoslashAnnotationSanGo      = regexp.MustCompile(`(?m)^[ \t]*//[ \t]*@(?:noErrors|errors:[ \t]*[\d \t]+|target:[ \t]*\S+|module:[ \t]*\S+|moduleResolution:[ \t]*\S+|lib:[ \t]*\S+|strict(?::[ \t]*\S+)?)[ \t]*\r?\n`)
	reAdmonitionDirectiveSanGo     = regexp.MustCompile(`(?im)^[ \t]*:{3,}[ \t]*(info|tip|note|warning|caution|danger|important|details)(?:[ \t]+([^\r\n]{1,200}))?[ \t]*$`)
	reAdmonitionCloseSanGo         = regexp.MustCompile(`(?im)^[ \t]*:{3,}(?:[ \t]*(?:code-group|tabs|tab(?:[ \t]+[^\r\n]{0,120})?|raw|v-pre))?[ \t]*$`)
	reBracketHeadingLinkSanGo      = regexp.MustCompile(`(?i)\[\s*<h([1-6])\b[^>"\n]{0,200}>([^<\n]{1,400})</h[1-6]>\s*\]\(([^)\s\n]+)\)`)
	reHelpfulPromptSanGo           = regexp.MustCompile(`(?i)(?:^|\n)Was this (?:page )?helpful\?[ \t]*(?:\n+(?:Yes[ \t]*No|Yes[ \t]*/[ \t]*No))?[ \t]*(?:\n|$)`)
	reOnThisPageTailSanGo          = regexp.MustCompile(`(?i)^\n##+[ \t]+On this page[ \t]*(?:\n+(?:[-*][ \t]+\[[^\[\]\n]{1,200}\]\(#[^)\n]{1,200}\)[ \t]*)+)?[ \t]*$`)
)

var uriNamedEntities = map[string]string{
	"amp":                   "&",
	"lt":                    "<",
	"gt":                    ">",
	"quot":                  "\"",
	"apos":                  "'",
	"nbsp":                  " ",
	"nonbreakingspace":      " ",
	"ensp":                  " ",
	"emsp":                  " ",
	"thinsp":                " ",
	"hairsp":                " ",
	"colon":                 ":",
	"tab":                   "\t",
	"newline":               "\n",
	"lpar":                  "(",
	"rpar":                  ")",
	"sol":                   "/",
	"bsol":                  "\\",
	"semi":                  ";",
	"equals":                "=",
	"num":                   "#",
	"quest":                 "?",
	"excl":                  "!",
	"commat":                "@",
	"lsqb":                  "[",
	"rsqb":                  "]",
	"grave":                 "`",
	"shy":                   "",
	"zwj":                   "",
	"zwnj":                  "",
	"lrm":                   "",
	"rlm":                   "",
	"alm":                   "",
	"wj":                    "",
	"wordjoiner":            "",
	"nobreak":               "",
	"af":                    "",
	"applyfunction":         "",
	"it":                    "",
	"invisibletimes":        "",
	"ic":                    "",
	"invisiblecomma":        "",
	"zerowidthspace":        "",
	"negativethinspace":     "",
	"negativeverythinspace": "",
	"negativemediumspace":   "",
	"negativethickspace":    "",
}

var markdownNamedEntities = map[string]string{
	"amp":                   "&",
	"lt":                    "<",
	"gt":                    ">",
	"quot":                  "\"",
	"apos":                  "'",
	"nbsp":                  " ",
	"rsquo":                 "\u2019",
	"lsquo":                 "\u2018",
	"rdquo":                 "\u201d",
	"ldquo":                 "\u201c",
	"ndash":                 "\u2013",
	"mdash":                 "\u2014",
	"hellip":                "\u2026",
	"bull":                  "\u2022",
	"middot":                "\u00b7",
	"copy":                  "\u00a9",
	"reg":                   "\u00ae",
	"trade":                 "\u2122",
	"deg":                   "\u00b0",
	"plusmn":                "\u00b1",
	"times":                 "\u00d7",
	"divide":                "\u00f7",
	"frac12":                "\u00bd",
	"frac14":                "\u00bc",
	"frac34":                "\u00be",
	"rarr":                  "\u2192",
	"larr":                  "\u2190",
	"uarr":                  "\u2191",
	"darr":                  "\u2193",
	"harr":                  "\u2194",
	"laquo":                 "\u00ab",
	"raquo":                 "\u00bb",
	"lsaquo":                "\u2039",
	"rsaquo":                "\u203a",
	"ensp":                  " ",
	"emsp":                  " ",
	"thinsp":                " ",
	"euro":                  "\u20ac",
	"pound":                 "\u00a3",
	"yen":                   "\u00a5",
	"cent":                  "\u00a2",
	"sect":                  "\u00a7",
	"para":                  "\u00b6",
	"dagger":                "\u2020",
	"Dagger":                "\u2021",
	"permil":                "\u2030",
	"prime":                 "\u2032",
	"Prime":                 "\u2033",
	"shy":                   "",
	"zwj":                   "",
	"zwnj":                  "",
	"lrm":                   "",
	"rlm":                   "",
	"alm":                   "",
	"wj":                    "",
	"wordjoiner":            "",
	"nobreak":               "",
	"af":                    "",
	"applyfunction":         "",
	"it":                    "",
	"invisibletimes":        "",
	"ic":                    "",
	"invisiblecomma":        "",
	"zerowidthspace":        "",
	"negativethinspace":     "",
	"negativeverythinspace": "",
	"negativemediumspace":   "",
	"negativethickspace":    "",
	"colon":                 ":",
	"tab":                   "\t",
	"newline":               "\n",
	"lpar":                  "(",
	"rpar":                  ")",
	"sol":                   "/",
	"bsol":                  "\\",
	"semi":                  ";",
	"equals":                "=",
	"num":                   "#",
	"quest":                 "?",
	"excl":                  "!",
	"commat":                "@",
	"lsqb":                  "[",
	"rsqb":                  "]",
	"grave":                 "`",
}

// SanitizeScrapedMeta strips NUL/smuggling code points, control newlines, raw HTML tags,
// and disallowed link schemes from single-line metadata fields (Title, Description, Author).
func SanitizeScrapedMeta(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 4096 {
		cut := 4096
		for cut > 0 && (s[cut]&0xC0) == 0x80 {
			cut--
		}
		s = s[:cut]
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	clean := stripInvisibleSmugglingCharsGo(s)
	var sb strings.Builder
	sb.Grow(len(clean))
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if c == '\r' || c == '\n' || c == '\t' {
			sb.WriteByte(' ')
			continue
		}
		if c == '<' {
			sb.WriteString("&lt;")
			continue
		}
		sb.WriteByte(c)
	}
	res := decodeMarkdownEntitiesPreservingLtGo(sb.String())
	res = stripInvisibleSmugglingCharsGo(res)
	res = neutralizeAllUnsafeMarkdownLinksLinearGo(res)
	res = escapeAllResidualLtInProseLinearGo(res, false)
	return strings.Join(strings.Fields(res), " ")
}

// SanitizeScrapedMarkdown applies the fail-closed Markdown sanitizer with empty baseURL.
func SanitizeScrapedMarkdown(md string) string {
	return SanitizeMarkdownWithOptions(md, "", false)
}

// SanitizeMarkdown enforces the fail-closed Markdown sanitization contract (`R11-S1` / `R11-S3`):
//   - ONLY top-level CommonMark fenced code blocks (`0..3` spaces, zero tabs, zero open containers) preceded by a
//     blank line or start of document keep raw content.
//   - Outside those top-level fences (including inside any container/list/blockquote fence or inline backtick code span),
//     EVERY residual `<` is escaped to `&lt;` and EVERY disallowed inline `](...)` or reference `[id]: ...`
//     link destination is neutralized.
//   - Runs in strictly O(N) linear time (<40ms on 7M `[` / 3.5M `](` / 2M `<`).
func SanitizeMarkdown(md, baseURL string) string {
	return SanitizeMarkdownWithOptions(md, baseURL, false)
}

func canFastEscapeCodeSpanOnlyLtInProseGo(prose string) bool {
	if strings.IndexByte(prose, '<') < 0 ||
		strings.IndexByte(prose, '`') < 0 ||
		strings.IndexByte(prose, '[') >= 0 ||
		strings.IndexByte(prose, '&') >= 0 ||
		strings.Contains(prose, ":::") ||
		strings.Contains(prose, "{/*") ||
		strings.Contains(prose, "://") ||
		strings.Contains(prose, "www.") ||
		strings.Contains(prose, "WWW.") ||
		strings.IndexByte(prose, '@') >= 0 ||
		strings.IndexByte(prose, '~') >= 0 ||
		strings.IndexByte(prose, '?') >= 0 ||
		strings.Contains(prose, "\n## ") ||
		strings.Contains(prose, "```") ||
		strings.Contains(prose, "\n\n\n") {
		return false
	}
	n := len(prose)
	var scannedByLen [32]int
	pos := 0
	for pos < n {
		nlRel := strings.IndexByte(prose[pos:], '\n')
		lineEnd := n
		if nlRel >= 0 {
			lineEnd = pos + nlRel
		}
		for k := range scannedByLen {
			scannedByLen[k] = pos
		}
		i := pos
		for i < lineEnd {
			ch := prose[i]
			if ch == '<' {
				return false
			}
			if ch == '`' {
				if i > pos {
					prev := prose[i-1]
					if prev == '\\' || prev == '_' || prev == '*' {
						return false
					}
				}
				tEnd := i + 1
				for tEnd < lineEnd && prose[tEnd] == '`' {
					tEnd++
				}
				tickLen := tEnd - i
				if tickLen >= 32 {
					return false
				}
				search := tEnd
				if scannedByLen[tickLen] > search {
					search = scannedByLen[tickLen]
				}
				closeStart := -1
				for search < lineEnd {
					rel := strings.IndexByte(prose[search:lineEnd], '`')
					if rel < 0 {
						scannedByLen[tickLen] = lineEnd
						break
					}
					hit := search + rel
					cEnd := hit + 1
					for cEnd < lineEnd && prose[cEnd] == '`' {
						cEnd++
					}
					if cEnd-hit == tickLen {
						closeStart = hit
						scannedByLen[tickLen] = cEnd
						break
					}
					search = cEnd
					scannedByLen[tickLen] = cEnd
				}
				if closeStart < 0 {
					return false
				}
				i = closeStart + tickLen
				continue
			}
			i++
		}
		if nlRel < 0 {
			break
		}
		pos = lineEnd + 1
	}
	return true
}

func stripMintlifyDocHygieneBannersGo(s string) string {
	headLim := minInt(len(s), 256)
	if strings.Contains(s[:headLim], "Documentation Index") {
		if m := reMintlifyDocIndexSanGo.FindStringIndex(s); len(m) == 2 && m[0] == 0 {
			s = s[m[1]:]
		}
	}
	const mintlifyNeedle = "this documentation is built and hosted on [mintlify]("
	tailStart := len(s) - 600
	if tailStart < 0 {
		tailStart = 0
	}
	tailLow := asciiLowerExtractString(s[tailStart:])
	if rel := strings.LastIndex(tailLow, mintlifyNeedle); rel >= 0 {
		absIdx := tailStart + rel
		if reMintlifyFooterSanGo.MatchString(s[absIdx:]) {
			cut := absIdx
			for cut > 0 && (s[cut-1] == '\n' || s[cut-1] == '\r') {
				cut--
			}
			s = s[:cut]
		}
	}
	return s
}

const (
	mdFlagDirtyChar  uint16 = 1 << iota // < 0x20 (except \t, \n) or >= 0x7F
	mdFlagNewline                       // '\n'
	mdFlagBacktick                      // '`'
	mdFlagTilde                         // '~'
	mdFlagLt                            // '<'
	mdFlagAmp                           // '&'
	mdFlagOpenBrack                     // '['
	mdFlagCloseBrack                    // ']'
	mdFlagColon                         // ':'
	mdFlagSlash                         // '/'
	mdFlagOpenBrace                     // '{'
	mdFlagQuest                         // '?'
)

var mdCharFlagTable = func() [256]uint16 {
	var t [256]uint16
	for i := 0; i < 256; i++ {
		if (i < 0x20 && i != '\t' && i != '\n') || i >= 0x7F {
			t[i] |= mdFlagDirtyChar
		}
	}
	t['\n'] |= mdFlagNewline
	t['`'] |= mdFlagBacktick
	t['~'] |= mdFlagTilde
	t['<'] |= mdFlagLt
	t['&'] |= mdFlagAmp
	t['['] |= mdFlagOpenBrack
	t[']'] |= mdFlagCloseBrack
	t[':'] |= mdFlagColon
	t['/'] |= mdFlagSlash
	t['{'] |= mdFlagOpenBrace
	t['?'] |= mdFlagQuest
	return t
}()

func scanMdCharFlagsGo(s string) uint16 {
	tbl := mdCharFlagTable
	var flags uint16
	i := 0
	n := len(s)
	for ; i+8 <= n; i += 8 {
		flags |= tbl[s[i]] | tbl[s[i+1]] | tbl[s[i+2]] | tbl[s[i+3]] |
			tbl[s[i+4]] | tbl[s[i+5]] | tbl[s[i+6]] | tbl[s[i+7]]
	}
	for ; i < n; i++ {
		flags |= tbl[s[i]]
	}
	return flags
}

// SanitizeMarkdownWithOptions sanitizes Markdown with optional PDF page marker preservation.
func SanitizeMarkdownWithOptions(md, baseURL string, allowPdfPageMarkers bool) string {
	if md == "" {
		return ""
	}
	bounded := md
	if len(bounded) > maxSanitizeMarkdownScanBytes {
		cut := maxSanitizeMarkdownScanBytes
		floor := maxSanitizeMarkdownScanBytes - 3
		for cut > floor && cut > 0 && (bounded[cut]&0xC0) == 0x80 {
			cut--
		}
		bounded = bounded[:cut]
	}

	flags := scanMdCharFlagsGo(bounded)
	var cleaned string
	if flags&mdFlagDirtyChar == 0 {
		cleaned = bounded
	} else {
		cleaned = normalizeMarkdownLineEndings(stripInvisibleSmugglingCharsGo(bounded))
	}
	cleaned = trimLeadingBlankLinesAndTrailingASCIIGo(stripMarkdownFrontmatterBody(cleaned))
	if cleaned == "" {
		return ""
	}
	cleaned = stripMintlifyDocHygieneBannersGo(cleaned)
	if cleaned == "" {
		return ""
	}
	const complexProseMask = mdFlagDirtyChar | mdFlagNewline | mdFlagBacktick | mdFlagTilde |
		mdFlagLt | mdFlagAmp | mdFlagOpenBrace | mdFlagQuest | mdFlagColon | mdFlagSlash
	const bracketPairMask = mdFlagOpenBrack | mdFlagCloseBrack
	if flags&complexProseMask == 0 && (flags&bracketPairMask) != bracketPairMask {
		return trimASCIIWhitespaceLinearGo(cleaned)
	}

	_, parts := recognizeAndHardenMarkdownFencesGo(cleaned, true)
	if len(parts) == 1 && !allowPdfPageMarkers && canFastEscapeCodeSpanOnlyLtInProseGo(parts[0]) {
		return trimASCIIWhitespaceLinearGo(replaceAllLtFastGo(parts[0]))
	}

	sanitizedParts := make([]string, len(parts))
	for idx, part := range parts {
		if idx%2 == 1 {
			sanitizedParts[idx] = cleanCodeFenceSegmentGo(part)
			continue
		}
		sanitizedParts[idx] = sanitizeProseSegmentGo(part, baseURL, allowPdfPageMarkers, idx == len(parts)-1)
	}
	for idx := range sanitizedParts {
		if idx%2 == 0 {
			sanitizedParts[idx] = dedupeConsecutiveStandaloneLinkParagraphsGo(sanitizedParts[idx])
		}
	}

	var assembled string
	if len(sanitizedParts) == 1 {
		assembled = sanitizedParts[0]
	} else {
		var sb strings.Builder
		total := 0
		for _, p := range sanitizedParts {
			total += len(p)
		}
		sb.Grow(total)
		for _, p := range sanitizedParts {
			sb.WriteString(p)
		}
		assembled = sb.String()
	}

	// Re-harden, re-split, and re-escape whenever fenced code markers exist so any fence boundary shifted or exposed
	// by prose HTML/comment/link stripping is guaranteed fail-closed across all Markdown renderers.
	if strings.Contains(assembled, "```") || strings.Contains(assembled, "~~~") {
		_, reParts := recognizeAndHardenMarkdownFencesGo(assembled, true)
		var rsb strings.Builder
		rtotal := 0
		for _, rp := range reParts {
			rtotal += len(rp)
		}
		rsb.Grow(rtotal)
		for idx, rp := range reParts {
			if idx%2 == 1 {
				rsb.WriteString(cleanCodeFenceSegmentGo(rp))
				continue
			}
			p := stripInvisibleSmugglingCharsGo(rp)
			p = neutralizeAllUnsafeMarkdownLinksLinearGo(p)
			p = escapeAllResidualLtInProseLinearGo(p, allowPdfPageMarkers)
			p = escapePostStripProseFencesGo(p)
			rsb.WriteString(p)
		}
		assembled = rsb.String()
	}

	return trimASCIIWhitespaceLinearGo(assembled)
}

func isASCIIWhitespaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func trimLeadingBlankLinesAndTrailingASCIIGo(s string) string {
	start := 0
	n := len(s)
	for start < n {
		p := start
		for p < n && (s[p] == ' ' || s[p] == '\t') {
			p++
		}
		if p < n && s[p] == '\n' {
			start = p + 1
			continue
		}
		if p >= n {
			return ""
		}
		break
	}
	end := n
	for end > start && isASCIIWhitespaceByte(s[end-1]) {
		end--
	}
	if end <= start {
		return ""
	}
	return s[start:end]
}

func isBlankASCIILineGo(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != ' ' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}

func trimASCIISpaceTabGo(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func trimASCIIWhitespaceLinearGo(s string) string {
	start := 0
	end := len(s)
	for start < end && isASCIIWhitespaceByte(s[start]) {
		start++
	}
	for end > start && isASCIIWhitespaceByte(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSafePrintableASCIIByte(b byte) bool {
	return (b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\t' || b == '\r'
}

func stripInvisibleSmugglingCharsGo(s string) string {
	if s == "" {
		return ""
	}
	// Fast pure-printable-ASCII scan with zero global table lookups (avoids runtime.raceread overhead under -race).
	purePrintable := true
	i := 0
	n := len(s)
	for ; i+8 <= n; i += 8 {
		b0, b1, b2, b3 := s[i], s[i+1], s[i+2], s[i+3]
		b4, b5, b6, b7 := s[i+4], s[i+5], s[i+6], s[i+7]
		m := (int(b0) - 0x20) | (int(b1) - 0x20) | (int(b2) - 0x20) | (int(b3) - 0x20) |
			(int(b4) - 0x20) | (int(b5) - 0x20) | (int(b6) - 0x20) | (int(b7) - 0x20) |
			(0x7E - int(b0)) | (0x7E - int(b1)) | (0x7E - int(b2)) | (0x7E - int(b3)) |
			(0x7E - int(b4)) | (0x7E - int(b5)) | (0x7E - int(b6)) | (0x7E - int(b7))
		if m < 0 {
			if !isSafePrintableASCIIByte(b0) || !isSafePrintableASCIIByte(b1) || !isSafePrintableASCIIByte(b2) || !isSafePrintableASCIIByte(b3) ||
				!isSafePrintableASCIIByte(b4) || !isSafePrintableASCIIByte(b5) || !isSafePrintableASCIIByte(b6) || !isSafePrintableASCIIByte(b7) {
				purePrintable = false
				break
			}
		}
	}
	if purePrintable {
		for ; i < n; i++ {
			if !isSafePrintableASCIIByte(s[i]) {
				purePrintable = false
				break
			}
		}
	}
	if purePrintable {
		return s
	}

	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
		n = len(s)
	}

	var sb strings.Builder
	sb.Grow(n)
	i = 0
	for i < n {
		// Strip ANSI CSI sequences: \x1b\[[0-9;?]*[ -/]*[@-~]
		if s[i] == 0x1B && i+1 < n && s[i+1] == '[' {
			p := i + 2
			for p < n && ((s[p] >= '0' && s[p] <= '9') || s[p] == ';' || s[p] == '?') {
				p++
			}
			for p < n && s[p] >= ' ' && s[p] <= '/' {
				p++
			}
			if p < n && s[p] >= '@' && s[p] <= '~' {
				i = p + 1
				continue
			}
		}
		if s[i] < 0x80 {
			b := s[i]
			if b == 0x7F || (b < 0x20 && b != '\t' && b != '\n' && b != '\r') {
				i++
				continue
			}
			sb.WriteByte(b)
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if (r >= 0x0080 && r <= 0x009F && r != 0x0085) ||
			r == 0x00AD || r == 0x061C || r == 0x180E ||
			(r >= 0x200B && r <= 0x200F) ||
			(r >= 0x202A && r <= 0x202E) ||
			(r >= 0x2060 && r <= 0x206F) ||
			r == 0xFEFF ||
			(r >= 0xE0000 && r <= 0xE007F) ||
			(r >= 0xE0100 && r <= 0xE01EF) {
			i += w
			continue
		}
		sb.WriteString(s[i : i+w])
		i += w
	}
	return sb.String()
}

func normalizeMarkdownLineEndings(s string) string {
	if strings.IndexByte(s, '\r') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' {
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			sb.WriteByte('\n')
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func stripMarkdownFrontmatterBody(md string) string {
	if !strings.HasPrefix(md, "---\n") {
		return md
	}
	headLim := minInt(len(md), 4200)
	head := md[:headLim]
	closeRel := strings.Index(head[4:], "\n---")
	if closeRel < 0 {
		return md
	}
	closeIdx := 4 + closeRel
	if closeIdx > 4004 {
		return md
	}
	afterClose := closeIdx + 4
	if afterClose < len(md) && md[afterClose] != '\n' {
		return md
	}
	for afterClose < len(md) && md[afterClose] == '\n' {
		afterClose++
	}
	fmBlock := head[4:closeIdx]
	hasYamlKV := false
	for _, line := range strings.Split(fmBlock, "\n") {
		trimmed := trimASCIISpaceTabGo(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		keyPart := strings.TrimRight(trimmed[:colon], " \t")
		if len(keyPart) == 0 || len(keyPart) > 64 {
			continue
		}
		validKey := true
		for i := 0; i < len(keyPart); i++ {
			c := keyPart[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				validKey = false
				break
			}
		}
		if validKey {
			hasYamlKV = true
			break
		}
	}
	if !hasYamlKV {
		return md
	}
	return md[afterClose:]
}

func isHTMLTagStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '/' || b == '!' || b == '?'
}

func isASCIIPunctByte(b byte) bool {
	return (b >= '!' && b <= '/') || (b >= ':' && b <= '@') || (b >= '[' && b <= '`') || (b >= '{' && b <= '~')
}

func isASCIIAlnumExtract(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isBackslashEscapedAt(s string, idx int) bool {
	bs := 0
	for p := idx - 1; p >= 0 && s[p] == '\\'; p-- {
		bs++
	}
	return (bs & 1) == 1
}

func measureLeadingIndentColsGo(raw string) (cols int, bytePos int, isBlank bool) {
	i := 0
	for i < len(raw) {
		ch := raw[i]
		if ch == ' ' {
			cols++
			i++
		} else if ch == '\t' {
			cols += 4 - (cols % 4)
			i++
		} else {
			break
		}
	}
	return cols, i, i >= len(raw)
}

func findThematicBreakMismatchGo(raw string, leadCols int, leadPos int, ch byte) int {
	if leadCols > 3 || leadPos >= len(raw) {
		return leadPos
	}
	count := 0
	for i := leadPos; i < len(raw); i++ {
		c := raw[i]
		if c == ch {
			count++
		} else if c != ' ' && c != '\t' {
			return i
		}
	}
	if count >= 3 {
		return -1
	}
	return len(raw)
}

func normalizeUnicodeLineSeparatorsGo(md string) string {
	if !strings.Contains(md, "\u2028") && !strings.Contains(md, "\u2029") && !strings.Contains(md, "\u0085") {
		return md
	}
	r := strings.ReplaceAll(md, "\u2028", " ")
	r = strings.ReplaceAll(r, "\u2029", " ")
	return strings.ReplaceAll(r, "\u0085", " ")
}

func scanContainerPrefixLinearGo(raw string) (prefixLen int, risky bool) {
	i := 0
	col := 0
	dashMismatch := -2
	starMismatch := -2
	for {
		runStartCol := col
		for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t') {
			if raw[i] == '\t' {
				col += 4 - (col % 4)
				risky = true
			} else {
				col++
			}
			i++
		}
		if col-runStartCol >= 4 {
			risky = true
		}
		if i >= len(raw) {
			break
		}
		c := raw[i]
		if c == '>' {
			risky = true
			i++
			col++
			continue
		}
		if (c == '-' || c == '*' || c == '+') && (i+1 >= len(raw) || raw[i+1] == ' ' || raw[i+1] == '\t') {
			isThematic := false
			relCols := col - runStartCol
			if i+1 < len(raw) && relCols <= 3 && (c == '-' || c == '*') {
				if c == '-' {
					if dashMismatch < i {
						dashMismatch = findThematicBreakMismatchGo(raw, relCols, i, '-')
					}
					isThematic = dashMismatch == -1
				} else {
					if starMismatch < i {
						starMismatch = findThematicBreakMismatchGo(raw, relCols, i, '*')
					}
					isThematic = starMismatch == -1
				}
			}
			if !isThematic {
				risky = true
				i++
				col++
				if i >= len(raw) {
					break
				}
				continue
			}
		}
		if c >= '0' && c <= '9' {
			j := i
			for j < len(raw) && j-i < 9 && raw[j] >= '0' && raw[j] <= '9' {
				j++
			}
			if j < len(raw) && (raw[j] == '.' || raw[j] == ')') && (j+1 >= len(raw) || raw[j+1] == ' ' || raw[j+1] == '\t') {
				risky = true
				col += j + 1 - i
				i = j + 1
				if i >= len(raw) {
					break
				}
				continue
			}
		}
		break
	}
	return i, risky
}

func scanContainerPrefixFlagsLinearGo(raw string) (prefixLen int, hasBlockquote bool, hasListMarker bool) {
	i := 0
	pCol := 0
	dashMismatch := -2
	starMismatch := -2
	for {
		runStartCol := pCol
		for i < len(raw) {
			ch := raw[i]
			if ch == ' ' {
				pCol++
				i++
			} else if ch == '\t' {
				pCol += 4 - (pCol % 4)
				i++
			} else {
				break
			}
		}
		if i >= len(raw) {
			break
		}
		c := raw[i]
		if c == '>' {
			hasBlockquote = true
			i++
			pCol++
			continue
		}
		if c == '-' || c == '*' || c == '+' {
			if i+1 >= len(raw) {
				hasListMarker = true
				i++
				break
			}
			nx := raw[i+1]
			if nx == ' ' || nx == '\t' {
				isThematic := false
				relCols := pCol - runStartCol
				if relCols <= 3 && (c == '-' || c == '*') {
					if c == '-' {
						if dashMismatch < i {
							dashMismatch = findThematicBreakMismatchGo(raw, relCols, i, '-')
						}
						isThematic = dashMismatch == -1
					} else {
						if starMismatch < i {
							starMismatch = findThematicBreakMismatchGo(raw, relCols, i, '*')
						}
						isThematic = starMismatch == -1
					}
				}
				if !isThematic {
					hasListMarker = true
					i++
					pCol++
					continue
				}
			}
		} else if c >= '0' && c <= '9' {
			j := i
			for j < len(raw) && j-i < 9 && raw[j] >= '0' && raw[j] <= '9' {
				j++
			}
			if j < len(raw) && (raw[j] == '.' || raw[j] == ')') {
				if j+1 >= len(raw) || raw[j+1] == ' ' || raw[j+1] == '\t' {
					hasListMarker = true
					pCol += j + 1 - i
					i = j + 1
					continue
				}
			}
		}
		break
	}
	return i, hasBlockquote, hasListMarker
}

func cleanFenceInfoStringLinearGo(rawInfo string) string {
	if rawInfo == "" {
		return ""
	}
	s := rawInfo
	if len(s) > 200 {
		s = s[:200]
	}
	for {
		idx := strings.Index(s, "theme={")
		if idx < 0 {
			break
		}
		wsStart := idx
		for wsStart > 0 && (s[wsStart-1] == ' ' || s[wsStart-1] == '\t') {
			wsStart--
		}
		closeBrace := strings.IndexByte(s[idx+7:], '}')
		if closeBrace >= 0 {
			s = s[:wsStart] + s[idx+7+closeBrace+1:]
		} else {
			s = s[:wsStart]
		}
	}
	for {
		idx := strings.Index(s, "[[")
		if idx < 0 {
			break
		}
		wsStart := idx
		for wsStart > 0 && (s[wsStart-1] == ' ' || s[wsStart-1] == '\t') {
			wsStart--
		}
		closeBr := strings.Index(s[idx+2:], "]]")
		if closeBr >= 0 {
			s = s[:wsStart] + s[idx+2+closeBr+2:]
		} else {
			s = s[:wsStart]
		}
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '[' || c == ']' || c == '<' || c == '>' {
			continue
		}
		if c == '\t' {
			sb.WriteByte(' ')
			continue
		}
		if c < 32 {
			continue
		}
		sb.WriteByte(c)
	}
	out := stripStandaloneTwoslashToken(sb.String())
	out = strings.TrimRight(out, " \t")
	if len(out) >= 100 {
		// Collapse huge trailing space tail after first word
		p := 0
		for p < len(out) && (out[p] == ' ' || out[p] == '\t') {
			p++
		}
		wStart := p
		for p < len(out) && out[p] != ' ' && out[p] != '\t' && out[p] != '`' && out[p] != '~' && p-wStart <= 64 {
			p++
		}
		if p > wStart && p-wStart <= 64 {
			spStart := p
			for p < len(out) && (out[p] == ' ' || out[p] == '\t') {
				p++
			}
			if p-spStart >= 8 {
				return strings.TrimRight(out[:spStart], " \t")
			}
		}
	}
	return out
}

func stripStandaloneTwoslashToken(s string) string {
	low := asciiLowerExtractString(s)
	if !strings.Contains(low, "twoslash") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	i := 0
	for i < len(s) {
		wsStart := i
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if (wsStart == 0 || i > wsStart) && i+8 <= len(s) && asciiLowerExtractString(s[i:i+8]) == "twoslash" &&
			(i+8 == len(s) || s[i+8] == ' ' || s[i+8] == '\t') {
			i += 8
			continue
		}
		sb.WriteString(s[wsStart:i])
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			sb.WriteByte(s[i])
			i++
		}
	}
	return sb.String()
}

type escapedUntrustedFenceGo struct {
	ch             byte
	length         int
	needBlockquote bool
}

type untrustedFenceStateGo struct {
	ch             byte
	length         int
	minIndent      int
	needBlockquote bool
}

type mdFenceRecognizerStateGo struct {
	inFence               bool
	fenceChar             byte
	fenceLen              int
	effectiveFenceLen     int
	prevLineWasASCIIBlank bool
	possiblyInList        bool
	escapedUntrusted      *escapedUntrustedFenceGo
	untrustedFence        *untrustedFenceStateGo
}

type fenceStepKindGo uint8

const (
	fenceStepProseGo fenceStepKindGo = iota
	fenceStepOpenTrustedGo
	fenceStepInTrustedGo
	fenceStepCloseTrustedGo
)

type fenceStepResultGo struct {
	kind                   fenceStepKindGo
	outLine                string
	openedInfo             string
	lengthenedEffectiveLen int
}

// stepCanonicalMarkdownFenceLineGo mirrors `stepCanonicalMarkdownFenceLine` in `hub/src/scrape-advanced.ts`
// 100% byte-for-byte (`R11-S1`, `R11-S2`, `R11-S3`):
//   - ONLY top-level fences (`0..3` spaces, zero tabs, zero open blockquote or list containers) preceded by a strict
//     ASCII blank line (`^[ \t]*$`) or start of document open a trusted raw fenced code block.
//   - Every fence opened while ANY container (list item or blockquote) is open, tab-indented, `>= 4`-col indented,
//     or not preceded by a blank line / start of document is treated strictly as prose (escaped when `harden == true`).
func stepCanonicalMarkdownFenceLineGo(raw string, state *mdFenceRecognizerStateGo, harden bool) fenceStepResultGo {
	if state.inFence {
		pos := 0
		col := 0
		sawTab := false
		for pos < len(raw) {
			ch := raw[pos]
			if ch == ' ' {
				col++
				pos++
			} else if ch == '\t' {
				col += 4 - (col % 4)
				pos++
				sawTab = true
			} else {
				break
			}
		}
		if pos < len(raw) && raw[pos] == state.fenceChar {
			p := pos
			for p < len(raw) && raw[p] == state.fenceChar {
				p++
			}
			runLen := p - pos
			if runLen >= state.fenceLen {
				onlyTrailingWs := isBlankASCIILineGo(raw[p:])
				if col <= 3 && !sawTab && onlyTrailingWs {
					closeLen := runLen
					if state.effectiveFenceLen > closeLen {
						closeLen = state.effectiveFenceLen
					}
					outLine := raw
					if harden {
						outLine = strings.Repeat(string(state.fenceChar), closeLen)
					}
					state.inFence = false
					state.fenceChar = 0
					state.fenceLen = 0
					state.effectiveFenceLen = 0
					state.prevLineWasASCIIBlank = false
					return fenceStepResultGo{kind: fenceStepCloseTrustedGo, outLine: outLine}
				}
				if harden && runLen >= state.effectiveFenceLen {
					state.effectiveFenceLen = runLen + 1
					return fenceStepResultGo{
						kind:                   fenceStepInTrustedGo,
						outLine:                raw,
						lengthenedEffectiveLen: state.effectiveFenceLen,
					}
				}
			}
		}
		return fenceStepResultGo{kind: fenceStepInTrustedGo, outLine: raw}
	}

	if len(raw) == 0 && state.untrustedFence == nil {
		if state.escapedUntrusted != nil && state.escapedUntrusted.needBlockquote {
			state.escapedUntrusted = nil
		}
		state.prevLineWasASCIIBlank = true
		return fenceStepResultGo{kind: fenceStepProseGo, outLine: raw}
	}

	if state.untrustedFence == nil && len(raw) > 0 {
		c0 := raw[0]
		if (c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') {
			if state.escapedUntrusted != nil && (state.escapedUntrusted.needBlockquote || state.prevLineWasASCIIBlank) {
				state.escapedUntrusted = nil
			}
			if state.prevLineWasASCIIBlank {
				state.possiblyInList = false
			}
			state.prevLineWasASCIIBlank = false
			return fenceStepResultGo{kind: fenceStepProseGo, outLine: raw}
		}
	}

	if state.untrustedFence == nil && len(raw) >= 3 && raw[0] == '>' && raw[1] == ' ' {
		c2 := raw[2]
		if (c2 >= 'A' && c2 <= 'Z') || (c2 >= 'a' && c2 <= 'z') {
			state.prevLineWasASCIIBlank = false
			return fenceStepResultGo{kind: fenceStepProseGo, outLine: raw}
		}
	}

	pos := 0
	col := 0
	sawTab := false
	for pos < len(raw) {
		ch := raw[pos]
		if ch == ' ' {
			col++
			pos++
		} else if ch == '\t' {
			col += 4 - (col % 4)
			pos++
			sawTab = true
		} else {
			break
		}
	}
	if pos >= len(raw) {
		if state.escapedUntrusted != nil && state.escapedUntrusted.needBlockquote {
			state.escapedUntrusted = nil
		}
		if state.untrustedFence != nil && state.untrustedFence.needBlockquote {
			state.untrustedFence = nil
		}
		if state.untrustedFence == nil {
			state.prevLineWasASCIIBlank = true
		}
		return fenceStepResultGo{kind: fenceStepProseGo, outLine: raw}
	}

	prefixLen, hasBlockquote, hasListMarker := scanContainerPrefixFlagsLinearGo(raw)

	if state.untrustedFence != nil {
		if (state.untrustedFence.needBlockquote && !hasBlockquote) ||
			(!state.untrustedFence.needBlockquote && state.untrustedFence.minIndent > 0 && col < state.untrustedFence.minIndent) {
			state.untrustedFence = nil
		} else {
			uPos := pos
			if prefixLen > uPos {
				uPos = prefixLen
			}
			if uPos < len(raw) && col <= state.untrustedFence.minIndent+3 && raw[uPos] == state.untrustedFence.ch {
				p := uPos
				for p < len(raw) && raw[p] == state.untrustedFence.ch {
					p++
				}
				if p-uPos >= state.untrustedFence.length && isBlankASCIILineGo(raw[p:]) {
					state.untrustedFence = nil
				}
			}
			state.prevLineWasASCIIBlank = false
			return fenceStepResultGo{kind: fenceStepProseGo, outLine: raw}
		}
	}

	if state.escapedUntrusted != nil && state.escapedUntrusted.needBlockquote && !hasBlockquote {
		state.escapedUntrusted = nil
	}

	if state.prevLineWasASCIIBlank && col <= 1 && !hasBlockquote && !hasListMarker {
		state.possiblyInList = false
	}
	if hasListMarker {
		state.possiblyInList = true
	}

	fPos := pos
	if prefixLen > fPos {
		fPos = prefixLen
	}
	if fPos+3 <= len(raw) {
		c0 := raw[fPos]
		if c0 == '`' || c0 == '~' {
			fEnd := fPos + 1
			for fEnd < len(raw) && raw[fEnd] == c0 {
				fEnd++
			}
			fLen := fEnd - fPos
			if fLen >= 3 && !(c0 == '`' && strings.IndexByte(raw[fEnd:], '`') >= 0) {
				onlyTrailingWs := isBlankASCIILineGo(raw[fEnd:])

				if harden && state.escapedUntrusted != nil && state.escapedUntrusted.ch == c0 && fLen >= state.escapedUntrusted.length && onlyTrailingWs {
					state.escapedUntrusted = nil
					state.prevLineWasASCIIBlank = false
					escapedRun := strings.Repeat(`\`+string(c0), fLen)
					return fenceStepResultGo{
						kind:    fenceStepProseGo,
						outLine: raw[:fPos] + escapedRun + raw[fEnd:],
					}
				}

				isTrustedTopLevel := state.prevLineWasASCIIBlank &&
					!sawTab &&
					col <= 3 &&
					fPos == pos &&
					!hasBlockquote &&
					!hasListMarker &&
					!state.possiblyInList

				if isTrustedTopLevel {
					state.escapedUntrusted = nil
					state.inFence = true
					state.fenceChar = c0
					state.fenceLen = fLen
					state.effectiveFenceLen = fLen
					state.prevLineWasASCIIBlank = false
					if harden {
						cleanInfo := cleanFenceInfoStringLinearGo(raw[fEnd:])
						return fenceStepResultGo{
							kind:       fenceStepOpenTrustedGo,
							outLine:    strings.Repeat(string(c0), fLen) + cleanInfo,
							openedInfo: cleanInfo,
						}
					}
					return fenceStepResultGo{
						kind:       fenceStepOpenTrustedGo,
						outLine:    raw,
						openedInfo: raw[fEnd:],
					}
				}

				state.prevLineWasASCIIBlank = false
				if harden {
					state.escapedUntrusted = &escapedUntrustedFenceGo{
						ch:             c0,
						length:         fLen,
						needBlockquote: hasBlockquote,
					}
					escapedRun := strings.Repeat(`\`+string(c0), fLen)
					return fenceStepResultGo{
						kind:    fenceStepProseGo,
						outLine: raw[:fPos] + escapedRun + raw[fEnd:],
					}
				}
				maxUntrustedCol := 3
				if state.possiblyInList {
					maxUntrustedCol = 7
				}
				if !hasListMarker && (hasBlockquote || col <= maxUntrustedCol) {
					minInd := 0
					if state.possiblyInList && !hasBlockquote {
						minInd = minInt(col, 2)
					}
					state.untrustedFence = &untrustedFenceStateGo{
						ch:             c0,
						length:         fLen,
						minIndent:      minInd,
						needBlockquote: hasBlockquote,
					}
				}
				return fenceStepResultGo{kind: fenceStepProseGo, outLine: raw}
			}
		}
	}

	if state.escapedUntrusted != nil && state.prevLineWasASCIIBlank && col == 0 && !hasBlockquote && !hasListMarker {
		state.escapedUntrusted = nil
	}

	if harden {
		checkBracketPos := -1
		if prefixLen > pos {
			checkBracketPos = prefixLen
		} else if col <= 3 {
			checkBracketPos = pos
		}
		if checkBracketPos >= 0 && checkBracketPos < len(raw) && raw[checkBracketPos] == '[' {
			tail := raw[checkBracketPos:]
			qLimit := minInt(len(tail), 1024)
			closeIdx := -1
			for q := 1; q < qLimit; q++ {
				if tail[q] == '\\' {
					q++
					continue
				}
				if tail[q] == ']' {
					closeIdx = q
					break
				}
			}
			if closeIdx < 0 && len(tail) < 1024 {
				state.prevLineWasASCIIBlank = false
				return fenceStepResultGo{
					kind:    fenceStepProseGo,
					outLine: raw[:checkBracketPos] + `\` + tail,
				}
			}
			if closeIdx >= 0 && closeIdx+1 < len(tail) && tail[closeIdx+1] == ':' && isBlankASCIILineGo(tail[closeIdx+2:]) {
				state.prevLineWasASCIIBlank = false
				return fenceStepResultGo{
					kind:    fenceStepProseGo,
					outLine: raw[:checkBracketPos] + tail[:closeIdx+1] + `\` + tail[closeIdx+1:],
				}
			}
		}
	}

	state.prevLineWasASCIIBlank = false
	return fenceStepResultGo{kind: fenceStepProseGo, outLine: raw}
}

type fenceSpanGo struct {
	openLine  int
	closeLine int
}

func recognizeAndHardenMarkdownFencesGo(rawMd string, harden bool) (string, []string) {
	if rawMd == "" {
		return rawMd, []string{rawMd}
	}
	md := normalizeUnicodeLineSeparatorsGo(normalizeMarkdownLineEndings(rawMd))
	if !strings.Contains(md, "```") && !strings.Contains(md, "~~~") {
		return md, []string{md}
	}

	lines := strings.Split(md, "\n")
	outLines := make([]string, 0, len(lines)+2)
	var fenceSpans []fenceSpanGo
	state := mdFenceRecognizerStateGo{prevLineWasASCIIBlank: true}
	fenceOpenOutIdx := -1
	fenceOpenInfo := ""

	for _, raw := range lines {
		activeFenceCh := state.fenceChar
		step := stepCanonicalMarkdownFenceLineGo(raw, &state, harden)

		switch step.kind {
		case fenceStepOpenTrustedGo:
			fenceOpenOutIdx = len(outLines)
			fenceOpenInfo = step.openedInfo
			outLines = append(outLines, step.outLine)
		case fenceStepCloseTrustedGo:
			outLines = append(outLines, step.outLine)
			fenceSpans = append(fenceSpans, fenceSpanGo{openLine: fenceOpenOutIdx, closeLine: len(outLines) - 1})
			fenceOpenOutIdx = -1
			fenceOpenInfo = ""
		case fenceStepInTrustedGo:
			if harden && step.lengthenedEffectiveLen > 0 && fenceOpenOutIdx >= 0 {
				outLines[fenceOpenOutIdx] = strings.Repeat(string(activeFenceCh), step.lengthenedEffectiveLen) + fenceOpenInfo
			}
			outLines = append(outLines, step.outLine)
		default:
			outLines = append(outLines, step.outLine)
		}
	}

	if state.inFence {
		if harden {
			outLines = append(outLines, strings.Repeat(string(state.fenceChar), state.effectiveFenceLen))
		}
		fenceSpans = append(fenceSpans, fenceSpanGo{openLine: fenceOpenOutIdx, closeLine: len(outLines) - 1})
	}

	hardened := strings.Join(outLines, "\n")
	if len(fenceSpans) == 0 {
		return hardened, []string{hardened}
	}

	segments := make([]string, 0, len(fenceSpans)*2+1)
	lineCursor := 0
	prefixLeadingNewline := false
	for _, sp := range fenceSpans {
		proseText := strings.Join(outLines[lineCursor:sp.openLine], "\n")
		if prefixLeadingNewline {
			proseText = "\n" + proseText
		}
		if sp.openLine > lineCursor {
			proseText = proseText + "\n"
		}
		segments = append(segments, proseText)

		fenceText := strings.Join(outLines[sp.openLine:sp.closeLine+1], "\n")
		segments = append(segments, fenceText)

		lineCursor = sp.closeLine + 1
		prefixLeadingNewline = lineCursor < len(outLines)
	}

	if lineCursor < len(outLines) {
		tailText := strings.Join(outLines[lineCursor:], "\n")
		if prefixLeadingNewline {
			segments = append(segments, "\n"+tailText)
		} else {
			segments = append(segments, tailText)
		}
	} else {
		segments = append(segments, "")
	}

	return hardened, segments
}

func splitMarkdownByCodeFencesGo(rawMd string) []string {
	_, segs := recognizeAndHardenMarkdownFencesGo(rawMd, false)
	return segs
}

func parseFenceHeaderPrefixGo(rawHeader string) (fencePrefix string, rawInfo string, ok bool) {
	sp := 0
	for sp < len(rawHeader) && sp <= 64 && (rawHeader[sp] == ' ' || rawHeader[sp] == '\t') {
		sp++
	}
	if sp > 64 || sp+3 > len(rawHeader) {
		return "", "", false
	}
	ch := rawHeader[sp]
	if ch != '`' && ch != '~' {
		return "", "", false
	}
	p := sp
	for p < len(rawHeader) && rawHeader[p] == ch {
		p++
	}
	if p-sp < 3 {
		return "", "", false
	}
	return rawHeader[:p], rawHeader[p:], true
}

func cleanCodeFenceSegmentGo(fenceBlock string) string {
	if len(fenceBlock) < 32768 && strings.Contains(fenceBlock, "schema.org") {
		if reMinifiedSchemaJsonFenceSanGo.MatchString(strings.TrimSpace(fenceBlock)) {
			return ""
		}
	}
	nlIdx := strings.IndexByte(fenceBlock, '\n')
	if nlIdx < 0 {
		h := strings.TrimSuffix(fenceBlock, "\r")
		if pfx, info, ok := parseFenceHeaderPrefixGo(h); ok {
			return pfx + cleanFenceInfoStringLinearGo(info)
		}
		return strings.ReplaceAll(fenceBlock, "<", "&lt;")
	}
	rawHeader := strings.TrimSuffix(fenceBlock[:nlIdx], "\r")
	var cleanHeader string
	rawInfo := ""
	if pfx, info, ok := parseFenceHeaderPrefixGo(rawHeader); ok {
		rawInfo = info
		cleanHeader = pfx + cleanFenceInfoStringLinearGo(info)
	} else {
		lim := minInt(len(rawHeader), 256)
		cleanHeader = strings.ReplaceAll(rawHeader[:lim], "<", "&lt;")
	}
	lastNL := strings.LastIndexByte(fenceBlock, '\n')
	if lastNL < nlIdx {
		return cleanHeader + fenceBlock[nlIdx:]
	}
	closingLine := fenceBlock[lastNL+1:]
	if _, rest, ok := parseFenceHeaderPrefixGo(closingLine); ok && strings.Trim(rest, " \t") == "" {
		innerEnd := lastNL
		if innerEnd > nlIdx+1 && fenceBlock[innerEnd-1] == '\r' {
			innerEnd--
		}
		innerCode := ""
		if innerEnd > nlIdx+1 {
			innerCode = fenceBlock[nlIdx+1 : innerEnd]
		}
		infoHead := rawInfo[:minInt(len(rawInfo), 256)]
		if reTwoslashWordSanGo.MatchString(infoHead) || reTwoslashCutMarkerSanGo.MatchString(innerCode) {
			if loc := reTwoslashCutBeforeSanGo.FindStringIndex(innerCode); len(loc) == 2 {
				innerCode = innerCode[loc[1]:]
			}
			if loc := reTwoslashCutAfterSanGo.FindStringIndex(innerCode); len(loc) == 2 {
				innerCode = innerCode[:loc[0]]
			}
			innerCode = reTwoslashAnnotationSanGo.ReplaceAllString(innerCode, "")
		}
		return cleanHeader + "\n" + innerCode + "\n" + closingLine
	}
	return cleanHeader + fenceBlock[nlIdx:]
}

func escapeGfmTaskListCheckboxesLinearGo(prose string) string {
	if prose == "" || strings.IndexByte(prose, '[') < 0 {
		return prose
	}
	lines := strings.Split(prose, "\n")
	changed := false
	for li, line := range lines {
		if strings.IndexByte(line, '[') < 0 {
			continue
		}
		i := 0
		n := len(line)
		sawListMarker := false
		for i < n {
			cols := 0
			j := i
			for j < n {
				if line[j] == ' ' {
					cols++
					j++
				} else if line[j] == '\t' {
					cols += 4 - (cols % 4)
					j++
				} else {
					break
				}
			}
			if !sawListMarker && cols > 3 {
				break
			}
			if j >= n {
				i = j
				break
			}
			mc := line[j]
			if cols <= 3 && mc == '>' {
				i = j + 1
				if i < n && (line[i] == ' ' || line[i] == '\t') {
					i++
				}
				continue
			}
			if (mc == '-' || mc == '*' || mc == '+') && j+1 < n && (line[j+1] == ' ' || line[j+1] == '\t') {
				sawListMarker = true
				i = j + 2
				continue
			}
			if mc >= '0' && mc <= '9' {
				d := j
				for d < n && d-j < 9 && line[d] >= '0' && line[d] <= '9' {
					d++
				}
				if d > j && d+1 < n && (line[d] == '.' || line[d] == ')') && (line[d+1] == ' ' || line[d+1] == '\t') {
					sawListMarker = true
					i = d + 2
					continue
				}
			}
			i = j
			break
		}
		if !sawListMarker {
			continue
		}
		if i+3 <= n && line[i] == '[' && (line[i+1] == ' ' || line[i+1] == 'x' || line[i+1] == 'X') && line[i+2] == ']' &&
			(i+3 == n || line[i+3] == ' ' || line[i+3] == '\t' || line[i+3] == '\r') {
			lines[li] = line[:i] + `\[` + line[i+1:]
			changed = true
		}
	}
	if !changed {
		return prose
	}
	return strings.Join(lines, "\n")
}

type mdLineCursorsGo struct {
	nextCloseBracket int
	noCloseBracket   bool
	nextCloseParen   int
	noCloseParen     bool
	noTickMask       uint32
	tickMissCount    int
	runsByLen        map[int][]int
}

func newMdLineCursorsGo() *mdLineCursorsGo {
	return &mdLineCursorsGo{
		nextCloseBracket: -1,
		nextCloseParen:   -1,
	}
}

func ensureLineBacktickIndexGo(line string, c *mdLineCursorsGo) map[int][]int {
	if c.runsByLen != nil {
		return c.runsByLen
	}
	m := make(map[int][]int)
	pos := 0
	for pos < len(line) {
		rel := strings.IndexByte(line[pos:], '`')
		if rel < 0 {
			break
		}
		idx := pos + rel
		runEnd := idx + 1
		for runEnd < len(line) && line[runEnd] == '`' {
			runEnd++
		}
		l := runEnd - idx
		m[l] = append(m[l], runEnd)
		pos = runEnd
	}
	c.runsByLen = m
	return m
}

func scanCodeSpanEndLinearGo(line string, start int, c *mdLineCursorsGo) (tickEnd int, spanEnd int) {
	tickEnd = start + 1
	for tickEnd < len(line) && line[tickEnd] == '`' {
		tickEnd++
	}
	tickLen := tickEnd - start
	if tickLen < 31 && (c.noTickMask&(uint32(1)<<tickLen)) != 0 {
		return tickEnd, -1
	}
	if c.runsByLen != nil || (len(line) > 512 && (tickLen >= 31 || c.tickMissCount >= 2)) {
		m := ensureLineBacktickIndexGo(line, c)
		list := m[tickLen]
		if len(list) == 0 {
			if tickLen < 31 {
				c.noTickMask |= uint32(1) << tickLen
			}
			return tickEnd, -1
		}
		lo, hi := 0, len(list)
		for lo < hi {
			mid := int(uint(lo+hi) >> 1)
			if list[mid]-tickLen >= tickEnd {
				hi = mid
			} else {
				lo = mid + 1
			}
		}
		if lo < len(list) {
			return tickEnd, list[lo]
		}
		if tickLen < 31 {
			c.noTickMask |= uint32(1) << tickLen
		}
		return tickEnd, -1
	}
	pos := tickEnd
	steps := 0
	for pos < len(line) {
		rel := strings.IndexByte(line[pos:], '`')
		if rel < 0 {
			break
		}
		idx := pos + rel
		runEnd := idx + 1
		for runEnd < len(line) && line[runEnd] == '`' {
			runEnd++
		}
		if runEnd-idx == tickLen {
			return tickEnd, runEnd
		}
		pos = runEnd
		steps++
		if steps >= 16 && len(line) > 512 {
			c.tickMissCount = 2
			return scanCodeSpanEndLinearGo(line, start, c)
		}
	}
	c.tickMissCount++
	if tickLen < 31 {
		c.noTickMask |= uint32(1) << tickLen
	}
	return tickEnd, -1
}

type parsedMdLinkTokenGo struct {
	isImage     bool
	rawLabel    string
	rawURL      string
	titleSuffix string
	end         int
}

func tryParseMarkdownLinkOrImageAtGo(line string, pos int, cursors *mdLineCursorsGo, allowNestedImage bool) *parsedMdLinkTokenGo {
	c0 := line[pos]
	isImage := false
	labelStart := pos + 1
	if c0 == '!' {
		if pos+1 >= len(line) || line[pos+1] != '[' {
			return nil
		}
		isImage = true
		labelStart = pos + 2
	} else if c0 != '[' {
		return nil
	}

	if cursors.noCloseBracket {
		return nil
	}
	if cursors.nextCloseBracket < labelStart {
		rel := strings.IndexByte(line[labelStart:], ']')
		if rel < 0 {
			cursors.noCloseBracket = true
			return nil
		}
		cursors.nextCloseBracket = labelStart + rel
	}
	if cursors.nextCloseBracket-labelStart > 1000 {
		return nil
	}

	labelMaxEnd := minInt(len(line), labelStart+1000)
	labelEnd := -1
	j := labelStart
	for j < labelMaxEnd {
		ch := line[j]
		if ch == '\\' {
			j += 2
			continue
		}
		if ch == '`' {
			tEnd, sEnd := scanCodeSpanEndLinearGo(line, j, cursors)
			if sEnd > 0 && sEnd <= labelMaxEnd {
				j = sEnd
				continue
			}
			j = tEnd
			continue
		}
		if ch == ']' {
			labelEnd = j
			break
		}
		if !isImage && allowNestedImage && ch == '!' && j+1 < labelMaxEnd && line[j+1] == '[' {
			nested := tryParseMarkdownLinkOrImageAtGo(line, j, newMdLineCursorsGo(), false)
			if nested == nil {
				return nil
			}
			j = nested.end
			continue
		}
		if ch == '[' || (ch == '!' && j+1 < labelMaxEnd && line[j+1] == '[') {
			return nil
		}
		j++
	}
	if labelEnd < 0 || labelEnd+1 >= len(line) || line[labelEnd+1] != '(' {
		return nil
	}

	destStart := labelEnd + 2
	if cursors.noCloseParen {
		return nil
	}
	if cursors.nextCloseParen < destStart {
		rel := strings.IndexByte(line[destStart:], ')')
		if rel < 0 {
			cursors.noCloseParen = true
			return nil
		}
		cursors.nextCloseParen = destStart + rel
	}
	if cursors.nextCloseParen-destStart > 2560 {
		return nil
	}

	k := destStart
	for k < len(line) && (line[k] == ' ' || line[k] == '\t') {
		k++
	}
	if k >= len(line) {
		return nil
	}

	var rawURL string
	if line[k] == '<' {
		angleLimit := minInt(len(line), k+2049)
		gt := -1
		for p := k + 1; p < angleLimit; p++ {
			pc := line[p]
			if pc == '>' {
				gt = p
				break
			}
			if pc == '<' || pc == '\n' || pc == '\r' {
				return nil
			}
		}
		if gt < 0 {
			return nil
		}
		rawURL = strings.TrimSpace(line[k+1 : gt])
		k = gt + 1
	} else {
		urlStart := k
		urlLimit := minInt(len(line), urlStart+2048)
		parenDepth := 0
		for k < urlLimit {
			uc := line[k]
			if uc == '\\' && k+1 < urlLimit {
				k += 2
				continue
			}
			if uc == ' ' || uc == '\t' {
				break
			}
			if uc == '(' {
				parenDepth++
				if parenDepth > 4 {
					return nil
				}
			} else if uc == ')' {
				if parenDepth == 0 {
					break
				}
				parenDepth--
			} else if uc == ']' && k+1 < urlLimit && line[k+1] == '(' {
				return nil
			}
			k++
		}
		if parenDepth != 0 {
			return nil
		}
		rawURL = line[urlStart:k]
	}

	wsStart := k
	for k < len(line) && (line[k] == ' ' || line[k] == '\t') {
		k++
	}
	titleSuffix := ""
	if k < len(line) && k > wsStart && (line[k] == '"' || line[k] == '\'') {
		qChar := line[k]
		tLim := minInt(len(line), k+512)
		qEnd := -1
		for p := k + 1; p < tLim; p++ {
			if line[p] == '\\' {
				p++
				continue
			}
			if line[p] == qChar {
				qEnd = p
				break
			}
		}
		if qEnd < 0 {
			return nil
		}
		titleSuffix = line[wsStart : qEnd+1]
		k = qEnd + 1
		for k < len(line) && (line[k] == ' ' || line[k] == '\t') {
			k++
		}
	}
	if k >= len(line) || line[k] != ')' {
		return nil
	}
	return &parsedMdLinkTokenGo{
		isImage:     isImage,
		rawLabel:    line[labelStart:labelEnd],
		rawURL:      rawURL,
		titleSuffix: titleSuffix,
		end:         k + 1,
	}
}

func detectParagraphBreakKindGo(line string, inBlockquote bool, inList bool) string {
	cols, bytePos, isBlank := measureLeadingIndentColsGo(line)
	if isBlank {
		return "blank_or_atomic"
	}
	c := line[bytePos]
	if cols <= 3 {
		if c == '#' {
			h := bytePos
			for h < len(line) && line[h] == '#' && h-bytePos < 7 {
				h++
			}
			if h-bytePos <= 6 && (h >= len(line) || line[h] == ' ' || line[h] == '\r') {
				return "atx_heading"
			}
		}
		if c == '>' {
			q := bytePos
			for q < len(line) && (line[q] == '>' || line[q] == ' ' || line[q] == '\t' || line[q] == '\r') {
				q++
			}
			if q == len(line) {
				return "blank_or_atomic"
			}
			if inBlockquote {
				return "none"
			}
			return "block_start"
		}
		if (c == '`' || c == '~') && bytePos+3 <= len(line) && line[bytePos+1] == c && line[bytePos+2] == c {
			fEnd := bytePos + 3
			for fEnd < len(line) && line[fEnd] == c {
				fEnd++
			}
			if !(c == '`' && strings.IndexByte(line[fEnd:], '`') >= 0) {
				return "blank_or_atomic"
			}
		}
		if c == '=' || c == '-' || c == '*' || c == '_' {
			rest := line[bytePos:]
			if isThematicBreakGo(rest) {
				return "blank_or_atomic"
			}
			if !inBlockquote && !inList && isSetextUnderlineOnlyGo(rest) {
				return "blank_or_atomic"
			}
		}
		if (c == '-' || c == '*' || c == '+') && bytePos+1 < len(line) && line[bytePos+1] == ' ' {
			return "block_start"
		}
		if c == '1' && bytePos+2 < len(line) && (line[bytePos+1] == '.' || line[bytePos+1] == ')') && line[bytePos+2] == ' ' {
			return "block_start"
		}
	}
	return "none"
}

func isThematicBreakGo(rest string) bool {
	if len(rest) > 0 && rest[len(rest)-1] == '\r' {
		rest = rest[:len(rest)-1]
	}
	if len(rest) < 3 {
		return false
	}
	ch := rest[0]
	if ch != '-' && ch != '*' && ch != '_' {
		return false
	}
	cnt := 0
	for i := 0; i < len(rest); i++ {
		if rest[i] == ch {
			cnt++
		} else if rest[i] != ' ' && rest[i] != '\t' {
			return false
		}
	}
	return cnt >= 3
}

func isSetextUnderlineOnlyGo(rest string) bool {
	if len(rest) == 0 {
		return false
	}
	ch := rest[0]
	if ch != '=' && ch != '-' {
		return false
	}
	i := 0
	for i < len(rest) && rest[i] == ch {
		i++
	}
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t' || rest[i] == '\r') {
		i++
	}
	return i == len(rest)
}

func lineStartsOrderedListSpaceGo(s string) bool {
	d := 0
	for d < len(s) && d < 9 && s[d] >= '0' && s[d] <= '9' {
		d++
	}
	return d > 0 && d+1 < len(s) && (s[d] == '.' || s[d] == ')') && s[d+1] == ' '
}

func computeTickPoisonedLinesGo(lines []string) []bool {
	poisoned := make([]bool, len(lines))
	carry := false
	inBlockquote := false
	inList := false
	for li, line := range lines {
		breakKind := detectParagraphBreakKindGo(line, inBlockquote, inList)
		cols, bytePos, isBlank := measureLeadingIndentColsGo(line)
		var leadChar byte
		if !isBlank && bytePos < len(line) {
			leadChar = line[bytePos]
		}
		lineStartsQuote := !isBlank && cols <= 3 && leadChar == '>'
		lineStartsList := !isBlank && cols <= 3 &&
			(((leadChar == '-' || leadChar == '*' || leadChar == '+') && bytePos+1 < len(line) && line[bytePos+1] == ' ') ||
				(leadChar >= '0' && leadChar <= '9' && lineStartsOrderedListSpaceGo(line[bytePos:minInt(len(line), bytePos+12)])))

		if breakKind == "blank_or_atomic" {
			carry = false
			inBlockquote = false
			inList = false
			continue
		}
		if breakKind == "block_start" || breakKind == "atx_heading" {
			carry = false
		}
		inBlockquote = lineStartsQuote
		if lineStartsList {
			inList = true
		}
		if carry {
			poisoned[li] = true
			continue
		}
		if strings.IndexByte(line, '`') < 0 {
			continue
		}
		cursors := newMdLineCursorsGo()
		lastTick := -2
		i := 0
		for i < len(line) {
			ch := line[i]
			if ch == '`' {
				if isBackslashEscapedAt(line, i) {
					i++
					continue
				}
				_, spanEnd := scanCodeSpanEndLinearGo(line, i, cursors)
				if spanEnd < 0 {
					poisoned[li] = true
					carry = true
					break
				}
				i = spanEnd
				continue
			}
			if (ch == '!' || ch == '[') && !isBackslashEscapedAt(line, i) {
				if tok := tryParseMarkdownLinkOrImageAtGo(line, i, cursors, true); tok != nil {
					if strings.IndexByte(tok.rawURL, '`') >= 0 || strings.IndexByte(tok.titleSuffix, '`') >= 0 {
						poisoned[li] = true
						carry = true
						break
					}
					i = tok.end
					continue
				}
			}
			if ch == ']' && i+1 < len(line) && line[i+1] == '(' {
				if lastTick == -2 {
					lastTick = strings.LastIndexByte(line, '`')
				}
				if lastTick > i {
					poisoned[li] = true
					carry = true
					break
				}
			}
			i++
		}
		if breakKind == "atx_heading" {
			carry = false
		}
	}
	return poisoned
}

func startsBareGfmURLAtGo(s string, pos int) bool {
	rem := asciiLowerExtractString(s[pos:minInt(len(s), pos+10)])
	return strings.HasPrefix(rem, "https://") || strings.HasPrefix(rem, "http://") || strings.HasPrefix(rem, "ftp://") || strings.HasPrefix(rem, "www.")
}

func looksLikeEmailDomainTail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at < 0 || at > 64 {
		return false
	}
	for i := 0; i < at; i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte(".!#$%&'*+/=?^_{|}~-", c) >= 0) {
			return false
		}
	}
	dom := s[at+1:]
	end := 0
	hasDot := false
	for end < len(dom) {
		c := dom[end]
		if isASCIIAlnumExtract(c) || c == '-' {
			end++
			continue
		}
		if c == '.' && end > 0 && dom[end-1] != '.' {
			hasDot = true
			end++
			continue
		}
		break
	}
	return hasDot && end >= 3 && dom[end-1] != '.'
}

func detachBareUrlsFromCodeSpansLinearGo(prose string) string {
	if prose == "" || strings.IndexByte(prose, '`') < 0 {
		return prose
	}
	if !strings.Contains(prose, "://") && !strings.Contains(prose, "www.") && !strings.Contains(prose, "WWW.") &&
		strings.IndexByte(prose, '@') < 0 && strings.IndexByte(prose, '~') < 0 {
		return prose
	}
	lines := strings.Split(prose, "\n")
	poisoned := computeTickPoisonedLinesGo(lines)
	changed := false

	for li, line := range lines {
		if strings.IndexByte(line, '`') < 0 {
			continue
		}
		cursors := newMdLineCursorsGo()
		firstTildeIdx := strings.IndexByte(line, '~')
		var out strings.Builder
		last := 0
		i := 0
		for i < len(line) {
			ch := line[i]
			if ch == '<' && i+4 < len(line) {
				low := asciiLowerExtractString(line[i+1 : minInt(len(line), i+10)])
				if strings.HasPrefix(low, "https:") || strings.HasPrefix(low, "http:") || strings.HasPrefix(low, "ftp:") || strings.HasPrefix(low, "mailto:") {
					gt := -1
					hasTick := false
					p := i + 1
					for p < len(line) {
						pc := line[p]
						if pc == '>' {
							gt = p
							break
						}
						if pc <= 32 || pc == '<' {
							break
						}
						if pc == '`' {
							hasTick = true
						}
						p++
					}
					if gt > 0 && hasTick {
						out.WriteString(line[last : i+1])
						out.WriteString(strings.ReplaceAll(line[i+1:gt], "`", "%60"))
						out.WriteByte('>')
						i = gt + 1
						last = i
						changed = true
						continue
					}
				}
			}

			if (ch == 'h' || ch == 'H' || ch == 'f' || ch == 'F' || ch == 'w' || ch == 'W') && startsBareGfmURLAtGo(line, i) {
				p := i + 4
				detachedAt := -1
				for p < len(line) {
					pc := line[p]
					if pc <= 32 || pc == '<' {
						break
					}
					if pc == '`' {
						detachedAt = p
						break
					}
					p++
				}
				if detachedAt >= 0 {
					out.WriteString(line[last:detachedAt])
					out.WriteByte(' ')
					last = detachedAt
					i = detachedAt
					changed = true
				} else {
					i = p
					continue
				}
			}

			if line[i] == '`' && !isBackslashEscapedAt(line, i) {
				if i > 0 && last < i {
					prev := line[i-1]
					if prev == '~' {
						out.WriteString(line[last:i])
						out.WriteByte(' ')
						last = i
						changed = true
					} else if isASCIIAlnumExtract(prev) || prev == '.' || prev == '_' || prev == '+' || prev == '-' {
						if looksLikeEmailDomainTail(line[i+1 : minInt(len(line), i+128)]) {
							out.WriteString(line[last:i])
							out.WriteByte(' ')
							last = i
							changed = true
						}
					}
				}
				if !poisoned[li] {
					tEnd, sEnd := scanCodeSpanEndLinearGo(line, i, cursors)
					if sEnd > 0 {
						if firstTildeIdx >= 0 && firstTildeIdx < i && sEnd < len(line) && line[sEnd] == '~' {
							out.WriteString(line[last:sEnd])
							out.WriteByte(' ')
							last = sEnd
							changed = true
						}
						i = sEnd
					} else {
						i = tEnd
					}
					continue
				}
			}
			i++
		}
		if last > 0 {
			out.WriteString(line[last:])
			lines[li] = out.String()
		}
	}
	if !changed {
		return prose
	}
	return strings.Join(lines, "\n")
}

func isRiskyAdjacentCodeSpanAtGo(line string, start int, spanEnd int, sawBracketInPara bool) bool {
	inner := line[start:spanEnd]
	if sawBracketInPara && strings.IndexByte(inner, ']') >= 0 {
		return true
	}
	if start > 0 {
		prev := line[start-1]
		if (prev == '_' || prev == '*') && strings.IndexByte(inner, prev) >= 0 {
			return true
		}
	}
	return false
}

func stashMarkdownInlineCodeSpansLinearGo(prose string, stash *[]string) string {
	if prose == "" || strings.IndexByte(prose, '`') < 0 {
		return prose
	}
	lines := strings.Split(prose, "\n")
	poisoned := computeTickPoisonedLinesGo(lines)
	sawBracketInPara := false
	inBlockquote := false
	inList := false
	changed := false

	for li, line := range lines {
		breakKind := detectParagraphBreakKindGo(line, inBlockquote, inList)
		cols, bytePos, isBlank := measureLeadingIndentColsGo(line)
		var leadChar byte
		if !isBlank && bytePos < len(line) {
			leadChar = line[bytePos]
		}
		if breakKind == "blank_or_atomic" {
			sawBracketInPara = false
			inBlockquote = false
			inList = false
		} else {
			if breakKind == "block_start" || breakKind == "atx_heading" {
				sawBracketInPara = false
			}
			inBlockquote = !isBlank && cols <= 3 && leadChar == '>'
			if !isBlank && cols <= 3 &&
				(((leadChar == '-' || leadChar == '*' || leadChar == '+') && bytePos+1 < len(line) && line[bytePos+1] == ' ') ||
					(leadChar >= '0' && leadChar <= '9' && lineStartsOrderedListSpaceGo(line[bytePos:minInt(len(line), bytePos+12)]))) {
				inList = true
			}
		}
		if strings.IndexByte(line, '`') < 0 || poisoned[li] {
			if strings.IndexByte(line, '[') >= 0 {
				sawBracketInPara = true
			}
			if breakKind == "atx_heading" {
				sawBracketInPara = false
			}
			continue
		}
		cursors := newMdLineCursorsGo()
		var out strings.Builder
		lastIdx := 0
		i := 0
		for i < len(line) {
			ch := line[i]
			if ch == '[' && !isBackslashEscapedAt(line, i) {
				sawBracketInPara = true
			}
			if ch == '`' {
				if isBackslashEscapedAt(line, i) {
					i++
					continue
				}
				tEnd, sEnd := scanCodeSpanEndLinearGo(line, i, cursors)
				if sEnd > 0 && !isRiskyAdjacentCodeSpanAtGo(line, i, sEnd, sawBracketInPara) {
					out.WriteString(line[lastIdx:i])
					idx := len(*stash)
					*stash = append(*stash, line[i:sEnd])
					out.WriteString("\x00EFMDINLINE")
					out.WriteString(strconv.Itoa(idx))
					out.WriteByte(0)
					i = sEnd
					lastIdx = i
					changed = true
					continue
				}
				i = tEnd
				continue
			}
			i++
		}
		if breakKind == "atx_heading" {
			sawBracketInPara = false
		}
		if lastIdx > 0 {
			out.WriteString(line[lastIdx:])
			lines[li] = out.String()
		}
	}
	if !changed {
		return prose
	}
	return strings.Join(lines, "\n")
}

func restoreMarkdownInlineCodeStashGo(s string, stash []string) string {
	if len(stash) == 0 || !strings.Contains(s, "\x00EFMDINLINE") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 32)
	pos := 0
	for pos < len(s) {
		rel := strings.Index(s[pos:], "\x00EFMDINLINE")
		if rel < 0 {
			sb.WriteString(s[pos:])
			break
		}
		hit := pos + rel
		sb.WriteString(s[pos:hit])
		dStart := hit + len("\x00EFMDINLINE")
		dEnd := dStart
		for dEnd < len(s) && s[dEnd] >= '0' && s[dEnd] <= '9' {
			dEnd++
		}
		if dEnd > dStart && dEnd < len(s) && s[dEnd] == 0 {
			if idx, err := strconv.Atoi(s[dStart:dEnd]); err == nil && idx >= 0 && idx < len(stash) {
				sb.WriteString(stash[idx])
			}
			pos = dEnd + 1
			continue
		}
		sb.WriteByte(s[hit])
		pos = hit + 1
	}
	return sb.String()
}

func isIgnorableURIRuneGo(r rune) bool {
	if r <= 0x20 || (r >= 0x7F && r <= 0x9F) {
		return true
	}
	switch {
	case r == 0x00A0, r == 0x00AD, r == 0x061C, r == 0x1680, r == 0x180E, r == 0x205F, r == 0x3000, r == 0xFEFF:
		return true
	case r >= 0x2000 && r <= 0x200F:
		return true
	case r >= 0x2028 && r <= 0x202F:
		return true
	case r >= 0x2060 && r <= 0x206F:
		return true
	case r >= 0xE0000 && r <= 0xE01EF:
		return true
	default:
		return false
	}
}

func collapseAmpEntityChainsGo(s string) string {
	if strings.IndexByte(s, '&') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	i := 0
	n := len(s)
	for i < n {
		if s[i] != '&' {
			sb.WriteByte(s[i])
			i++
			continue
		}
		p := i
		steps := 0
		for p < n && s[p] == '&' {
			if amt := matchAmpEntityPrefixLen(s[p:]); amt > 0 {
				p += amt
				steps++
				continue
			}
			break
		}
		if steps > 0 && p < n && looksLikeEntityBodyAfterAmp(s[p:]) {
			sb.WriteByte('&')
			i = p
			continue
		}
		sb.WriteByte('&')
		i++
	}
	return sb.String()
}

func matchAmpEntityPrefixLen(s string) int {
	if len(s) >= 5 && asciiLowerExtractString(s[:5]) == "&amp;" {
		return 5
	}
	if len(s) >= 3 && s[0] == '&' && s[1] == '#' {
		q := 2
		isHex := false
		if q < len(s) && (s[q] == 'x' || s[q] == 'X') {
			isHex = true
			q++
		}
		for q < len(s) && s[q] == '0' {
			q++
		}
		if isHex {
			if q+2 <= len(s) && s[q] == '2' && s[q+1] == '6' {
				q += 2
				if q < len(s) && s[q] == ';' {
					q++
				}
				return q
			}
		} else {
			if q+2 <= len(s) && s[q] == '3' && s[q+1] == '8' {
				q += 2
				if q < len(s) && s[q] == ';' {
					q++
				}
				return q
			}
		}
	}
	return 0
}

func looksLikeEntityBodyAfterAmp(s string) bool {
	if len(s) < 2 {
		return false
	}
	if s[0] == '#' {
		if s[1] >= '0' && s[1] <= '9' {
			return true
		}
		if (s[1] == 'x' || s[1] == 'X') && len(s) >= 3 {
			c := s[2]
			return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		}
		return false
	}
	if (s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z') {
		p := 1
		for p < len(s) && p <= 20 && isASCIIAlnumExtract(s[p]) {
			p++
		}
		return p >= 2 && p < len(s) && s[p] == ';'
	}
	return false
}

func decodeURIEntitiesLinearGo(raw string) string {
	if strings.IndexByte(raw, '&') < 0 {
		return raw
	}
	cur := collapseAmpEntityChainsGo(raw)
	for pass := 0; pass < 2 && strings.IndexByte(cur, '&') >= 0; pass++ {
		next := decodeURIEntitiesSinglePassGo(cur)
		if next == cur {
			break
		}
		cur = next
	}
	return cur
}

func decodeURIEntitiesSinglePassGo(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	i := 0
	n := len(s)
	for i < n {
		if s[i] != '&' || i+2 >= n {
			sb.WriteByte(s[i])
			i++
			continue
		}
		if s[i+1] == '#' {
			p := i + 2
			isHex := false
			if p < n && (s[p] == 'x' || s[p] == 'X') {
				isHex = true
				p++
			}
			for p < n && s[p] == '0' {
				p++
			}
			dStart := p
			maxDigits := 10
			if isHex {
				maxDigits = 8
			}
			for p < n && p-dStart < maxDigits {
				c := s[p]
				if isHex {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						break
					}
				} else if c < '0' || c > '9' {
					break
				}
				p++
			}
			if p > i+2 && (p > dStart || (p > 0 && s[p-1] == '0')) {
				digits := s[dStart:p]
				if digits == "" {
					digits = "0"
				}
				if p < n && s[p] == ';' {
					p++
				}
				base := 10
				if isHex {
					base = 16
				}
				if cp, err := strconv.ParseUint(digits, base, 32); err == nil && cp <= 0x10FFFF {
					if cp > 0 {
						sb.WriteRune(rune(cp))
					}
					i = p
					continue
				}
			}
		} else if (s[i+1] >= 'a' && s[i+1] <= 'z') || (s[i+1] >= 'A' && s[i+1] <= 'Z') {
			p := i + 2
			for p < n && p-(i+1) <= 20 && isASCIIAlnumExtract(s[p]) {
				p++
			}
			if p < n && s[p] == ';' {
				name := asciiLowerExtractString(s[i+1 : p])
				if mapped, ok := uriNamedEntities[name]; ok {
					sb.WriteString(mapped)
					i = p + 1
					continue
				}
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

// isDisallowedMarkdownLinkDestinationGo enforces the strict URI scheme allowlist (H1):
// ONLY `https://...`, `http://...`, `mailto:...`, single-slash `/...` (never `//` or `/\`), `./...`, `../...`,
// `#...`, `?...`, or clean relative paths with zero `:` and zero unparsed `&entity` before `/`, `?`, `#`.
func isDisallowedMarkdownLinkDestinationGo(rawHref string) bool {
	if rawHref == "" {
		return false
	}
	if len(rawHref) > 8192 {
		return true
	}
	// Zero-allocation fast path for clean printable ASCII schemes (`javascript:`, `data:`, `vbscript:`, `https://`, `http://`).
	if strings.IndexByte(rawHref, '&') < 0 && strings.IndexByte(rawHref, '\\') < 0 {
		cleanASCII := true
		for i := 0; i < len(rawHref) && i < 32; i++ {
			if rawHref[i] <= 0x20 || rawHref[i] >= 0x7f || rawHref[i] == '(' || rawHref[i] == '<' {
				cleanASCII = false
				break
			}
		}
		if cleanASCII {
			if len(rawHref) >= 11 && strings.EqualFold(rawHref[:11], "javascript:") {
				return true
			}
			if len(rawHref) >= 5 && strings.EqualFold(rawHref[:5], "data:") {
				return true
			}
			if len(rawHref) >= 9 && strings.EqualFold(rawHref[:9], "vbscript:") {
				return true
			}
			if len(rawHref) >= 5 && (strings.EqualFold(rawHref[:5], "file:") || strings.EqualFold(rawHref[:5], "blob:")) {
				return true
			}
		}
	}
	unescaped := rawHref
	if strings.IndexByte(unescaped, '\\') >= 0 {
		var sb strings.Builder
		sb.Grow(len(unescaped))
		for i := 0; i < len(unescaped); i++ {
			if unescaped[i] == '\\' && i+1 < len(unescaped) && isASCIIPunctByte(unescaped[i+1]) {
				sb.WriteByte(unescaped[i+1])
				i++
			} else {
				sb.WriteByte(unescaped[i])
			}
		}
		unescaped = sb.String()
	}
	decoded := decodeURIEntitiesLinearGo(unescaped)
	var cleanBuf strings.Builder
	cleanBuf.Grow(minInt(len(decoded), 264))
	sawDelimOrColon := false
	for _, r := range decoded {
		if isIgnorableURIRuneGo(r) {
			continue
		}
		if r == '/' || r == '?' || r == '#' || r == ':' {
			sawDelimOrColon = true
		}
		cleanBuf.WriteRune(r)
		if cleanBuf.Len() >= 256 && sawDelimOrColon {
			break
		}
		if cleanBuf.Len() > 4096 {
			return true
		}
	}
	clean := cleanBuf.String()
	start := 0
	for start < len(clean) && (clean[start] == '(' || clean[start] == '<') {
		start++
	}
	if start > 0 {
		clean = clean[start:]
	}
	if clean == "" {
		return false
	}

	if clean[0] == '/' {
		return len(clean) > 1 && (clean[1] == '/' || clean[1] == '\\')
	}
	if clean[0] == '#' || clean[0] == '?' {
		return false
	}
	if strings.HasPrefix(clean, "./") || strings.HasPrefix(clean, "../") {
		return false
	}

	firstDelim := len(clean)
	colonIdx := -1
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if c == '/' || c == '?' || c == '#' {
			firstDelim = i
			break
		}
		if c == ':' && colonIdx < 0 {
			colonIdx = i
		}
	}
	beforeDelim := clean[:firstDelim]
	if colonIdx >= 0 && colonIdx < firstDelim {
		scheme := asciiLowerExtractString(clean[:colonIdx])
		switch scheme {
		case "https", "http":
			return !(strings.HasPrefix(clean[colonIdx:], "://") && len(clean) > colonIdx+3)
		case "mailto":
			return len(clean) <= colonIdx+1
		default:
			return true
		}
	}

	if ampIdx := strings.IndexByte(beforeDelim, '&'); ampIdx >= 0 && ampIdx+1 < len(beforeDelim) {
		after := beforeDelim[ampIdx+1]
		if after == '#' || (after >= 'A' && after <= 'Z') || (after >= 'a' && after <= 'z') {
			return true
		}
	}
	return false
}

func skipOptionalMdContinuationPrefixGo(s string, nlPos int) int {
	p := nlPos + 1
	steps := 0
	for p < len(s) && steps < 64 {
		c := s[p]
		if c == ' ' || c == '\t' || c == '>' {
			p++
			steps++
			continue
		}
		break
	}
	if p < len(s) {
		c := s[p]
		if (c == '-' || c == '*' || c == '+') && p+1 < len(s) && (s[p+1] == ' ' || s[p+1] == '\t') {
			p++
			sp := 0
			for p < len(s) && sp < 8 && (s[p] == ' ' || s[p] == '\t') {
				p++
				sp++
			}
		} else if c >= '0' && c <= '9' {
			d := p
			for d < len(s) && d-p < 9 && s[d] >= '0' && s[d] <= '9' {
				d++
			}
			if d > p && d+1 < len(s) && (s[d] == '.' || s[d] == ')') && (s[d+1] == ' ' || s[d+1] == '\t') {
				p = d + 1
				sp := 0
				for p < len(s) && sp < 8 && (s[p] == ' ' || s[p] == '\t') {
					p++
					sp++
				}
			}
		}
	}
	return p
}

func consumeOptionalMdTitleGo(s string, pos int) int {
	ws := pos
	for ws < len(s) && isASCIIWhitespaceByte(s[ws]) {
		ws++
	}
	if ws > pos && ws < len(s) && (s[ws] == '"' || s[ws] == '\'') {
		q := s[ws]
		lim := minInt(len(s), ws+512)
		for p := ws + 1; p < lim; p++ {
			if s[p] == '\\' {
				p++
				continue
			}
			if s[p] == q {
				after := p + 1
				for after < len(s) && isASCIIWhitespaceByte(s[after]) {
					after++
				}
				return after
			}
		}
	}
	return ws
}

func scanDestinationTokenEndAndCheckUnsafeGo(s string, destStart int, isInlineParen bool) (unsafe bool, tokenEnd int, closeParenPos int) {
	n := len(s)
	if destStart >= n {
		return false, destStart, -1
	}
	if s[destStart] == '<' {
		p := destStart + 1
		for p < n {
			c := s[p]
			if c == '\\' && p+1 < n {
				p += 2
				continue
			}
			if c == '>' {
				inner := s[destStart+1 : p]
				if !isDisallowedMarkdownLinkDestinationGo(inner) {
					return false, p + 1, -1
				}
				afterTitle := consumeOptionalMdTitleGo(s, p+1)
				cp := -1
				if isInlineParen && afterTitle < n && s[afterTitle] == ')' {
					cp = afterTitle
				}
				tEnd := p + 1
				if cp >= 0 {
					tEnd = cp
				}
				return true, tEnd, cp
			}
			if c == '<' || c == '\n' || c == '\r' {
				break
			}
			p++
		}
		fallbackEnd := destStart + 1
		for fallbackEnd < n {
			fc := s[fallbackEnd]
			if isASCIIWhitespaceByte(fc) || fc == ')' {
				break
			}
			if fc == ']' && fallbackEnd+1 < n && s[fallbackEnd+1] == '(' {
				break
			}
			if fc == '[' && fallbackEnd > destStart+1 {
				win := s[fallbackEnd+1 : minInt(n, fallbackEnd+258)]
				if strings.Contains(win, "](") {
					break
				}
			}
			fallbackEnd++
		}
		if isDisallowedMarkdownLinkDestinationGo(s[destStart+1 : fallbackEnd]) {
			cp := -1
			if isInlineParen && fallbackEnd < n && s[fallbackEnd] == ')' {
				cp = fallbackEnd
			}
			return true, fallbackEnd, cp
		}
		return false, fallbackEnd, -1
	}

	// Fast O(1) first-byte rejection on `](](](...` so `strings.Repeat("](", 3_500_000) + ":"` runs in <15ms
	firstByte := s[destStart]
	if firstByte == ']' || firstByte == '[' || firstByte == ')' || firstByte == '`' {
		return false, destStart, -1
	}

	p := destStart
	depth := 0
	for p < n {
		c := s[p]
		if c > 0x20 && c != '\\' && c != ']' && c != '[' && c != '(' && c != ')' {
			rel := strings.IndexAny(s[p+1:], " \t\r\n\\][()")
			if rel < 0 {
				p = n
				break
			}
			p += 1 + rel
			continue
		}
		if c == '\\' && p+1 < n {
			p += 2
			continue
		}
		if isASCIIWhitespaceByte(c) {
			break
		}
		if c == ']' && p+1 < n && (s[p+1] == '(' || s[p+1] == ':') {
			break
		}
		if c == '[' && p > destStart {
			win := s[p:minInt(n, p+258)]
			if bp := strings.Index(win[1:], "]("); bp >= 0 && strings.IndexByte(win[:1+bp], '\n') < 0 {
				break
			}
		}
		if c == '(' {
			depth++
			if depth > 8 {
				break
			}
		} else if c == ')' {
			if !isInlineParen && depth == 0 {
				p++
				continue
			}
			if depth == 0 {
				break
			}
			depth--
		}
		p++
	}
	if p <= destStart {
		return false, destStart, -1
	}
	if !isDisallowedMarkdownLinkDestinationGo(s[destStart:p]) {
		return false, p, -1
	}
	afterTitle := p
	if isInlineParen {
		afterTitle = consumeOptionalMdTitleGo(s, p)
	}
	cp := -1
	if isInlineParen && afterTitle < n && s[afterTitle] == ')' {
		cp = afterTitle
	}
	tEnd := p
	if cp >= 0 {
		tEnd = cp
	}
	return true, tEnd, cp
}

func isASCIIAlphaExtract(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isHostLabelByteExtract(b byte) bool {
	return isASCIIAlnumExtract(b) || b == '-' || b >= 0x80
}

func escapeBareProtocolRelativeUrlsLinearGo(prose string) string {
	rel := strings.Index(prose, "//")
	if rel < 0 {
		return prose
	}
	n := len(prose)
	var sb strings.Builder
	last := 0
	changed := false
	idx := rel

	for idx >= 0 && idx < n {
		if idx >= 2 && prose[idx-1] == ':' && isASCIIAlphaExtract(prose[idx-2]) {
			nx := strings.Index(prose[idx+2:], "//")
			if nx < 0 {
				break
			}
			idx = idx + 2 + nx
			continue
		}
		if idx >= 1 {
			prev := prose[idx-1]
			if prev == '/' || prev == '\\' || prev == '_' || prev >= 0x80 || isASCIIAlnumExtract(prev) {
				nx := strings.Index(prose[idx+2:], "//")
				if nx < 0 {
					break
				}
				idx = idx + 2 + nx
				continue
			}
		}
		hostStart := idx + 2
		if hostStart < n {
			firstByte := prose[hostStart]
			matchedEnd := -1

			if firstByte == '[' {
				ipv6Limit := minInt(n, hostStart+64)
				for q := hostStart + 1; q < ipv6Limit; q++ {
					qc := prose[q]
					if qc == ']' && q > hostStart+1 {
						matchedEnd = q + 1
						break
					}
					if !((qc >= '0' && qc <= '9') || (qc >= 'A' && qc <= 'F') || (qc >= 'a' && qc <= 'f') || qc == ':' || qc == '.') {
						break
					}
				}
			} else if firstByte != '-' && isHostLabelByteExtract(firstByte) {
				if hostStart+9 <= n &&
					asciiLowerExtractString(prose[hostStart:hostStart+9]) == "localhost" &&
					(hostStart+9 == n || !isHostLabelByteExtract(prose[hostStart+9])) {
					matchedEnd = hostStart + 9
				} else {
					p := hostStart
					limit := minInt(n, hostStart+253)
					sawValidDot := false
					validLabels := true
					lastValidMultiEnd := -1
					for p < limit {
						hc := prose[p]
						if isHostLabelByteExtract(hc) {
							if sawValidDot && hc != '-' {
								lastValidMultiEnd = p + 1
							}
							p++
							continue
						}
						if hc == '.' {
							if p == hostStart || prose[p-1] == '.' || prose[p-1] == '-' {
								validLabels = false
								break
							}
							if p+1 >= limit || prose[p+1] == '-' || !isHostLabelByteExtract(prose[p+1]) {
								break
							}
							sawValidDot = true
							p++
							continue
						}
						break
					}
					if validLabels && sawValidDot {
						if prose[p-1] != '-' {
							matchedEnd = p
						} else if lastValidMultiEnd > hostStart {
							matchedEnd = lastValidMultiEnd
						}
					}
				}
			}

			if matchedEnd > hostStart {
				if !changed && sb.Cap() == 0 {
					sb.Grow(n + 8)
				}
				sb.WriteString(prose[last:idx])
				sb.WriteByte('\\')
				last = idx
				changed = true
				nx := strings.Index(prose[matchedEnd:], "//")
				if nx < 0 {
					break
				}
				idx = matchedEnd + nx
				continue
			}
		}
		nx := strings.Index(prose[idx+2:], "//")
		if nx < 0 {
			break
		}
		idx = idx + 2 + nx
	}

	if !changed {
		return prose
	}
	sb.WriteString(prose[last:])
	return sb.String()
}

func neutralizeAllUnsafeMarkdownLinksLinearGo(prose string) string {
	if prose == "" {
		return prose
	}
	hasInline := strings.Contains(prose, "](")
	hasRef := strings.Contains(prose, "]:")
	hasDoubleSlash := strings.Contains(prose, "//")
	if !hasInline && !hasRef {
		if hasDoubleSlash {
			return escapeBareProtocolRelativeUrlsLinearGo(prose)
		}
		return prose
	}
	if strings.IndexByte(prose, ':') < 0 && strings.IndexByte(prose, '&') < 0 &&
		strings.IndexByte(prose, '\\') < 0 && !hasDoubleSlash {
		return prose
	}

	var out strings.Builder
	last := 0
	i := 0
	n := len(prose)
	for i < n-1 {
		rel := strings.IndexByte(prose[i:], ']')
		if rel < 0 {
			break
		}
		i += rel
		if i >= n-1 {
			break
		}
		for i+128 <= n && prose[i:i+128] == "](](](](](](](](](](](](](](](](](](](](](](](](](](](](](](](](" {
			i += 126
		}
		for i+32 <= n && prose[i:i+32] == "](](](](](](](](](](](](](](](](" {
			i += 30
		}
		if i >= n-1 {
			break
		}
		if !isBackslashEscapedAt(prose, i) {
			nx := prose[i+1]
			if nx == '(' {
				if i+2 < n {
					fb := prose[i+2]
					if fb == ']' || fb == '[' || fb == ')' || fb == '`' {
						i += 2
						continue
					}
				}
				k := i + 2
				for k < n && isASCIIWhitespaceByte(prose[k]) {
					if prose[k] == '\n' {
						k = skipOptionalMdContinuationPrefixGo(prose, k)
						continue
					}
					k++
				}
				unsafe, tokEnd, closeParen := scanDestinationTokenEndAndCheckUnsafeGo(prose, k, true)
				if unsafe {
					if last == 0 {
						out.Grow(len(prose) + 8)
					}
					bangPos := -1
					searchFloor := last
					if i-1005 > searchFloor {
						searchFloor = i - 1005
					}
					for b := i - 1; b >= searchFloor; b-- {
						if prose[b] == '[' && !isBackslashEscapedAt(prose, b) {
							if b > last && prose[b-1] == '!' && !isBackslashEscapedAt(prose, b-1) {
								bangPos = b - 1
							}
							break
						}
					}
					if bangPos >= last {
						out.WriteString(prose[last:bangPos])
						out.WriteString(prose[bangPos+1 : i+2])
						out.WriteString("#)")
					} else {
						out.WriteString(prose[last : i+2])
						out.WriteString("#)")
					}
					if closeParen >= 0 {
						i = closeParen + 1
					} else {
						i = tokEnd
					}
					last = i
					continue
				}
			} else if nx == ':' {
				k := i + 2
				for k < n && (prose[k] == ' ' || prose[k] == '\t' || prose[k] == '\r') {
					k++
				}
				if k < n && prose[k] == '\n' {
					k = skipOptionalMdContinuationPrefixGo(prose, k)
				}
				unsafe, tokEnd, _ := scanDestinationTokenEndAndCheckUnsafeGo(prose, k, false)
				if unsafe {
					if last == 0 {
						out.Grow(len(prose) + 8)
					}
					out.WriteString(prose[last : i+1])
					out.WriteString(": #")
					i = tokEnd
					last = i
					continue
				}
			}
		}
		i++
	}
	res := prose
	if last > 0 {
		out.WriteString(prose[last:])
		res = out.String()
	}
	if strings.Contains(res, "//") {
		return escapeBareProtocolRelativeUrlsLinearGo(res)
	}
	return res
}

func isVerifiedPdfPageMarkerLineGo(trimmed string) bool {
	if !strings.HasPrefix(trimmed, "<!-- ") || !strings.HasSuffix(trimmed, " -->") {
		return false
	}
	inner := trimmed[5 : len(trimmed)-4]
	var digits string
	if strings.HasPrefix(inner, "page ") {
		digits = inner[5:]
	} else if strings.HasPrefix(inner, "pdf-page: ") {
		digits = inner[10:]
	} else {
		return false
	}
	if len(digits) < 1 || len(digits) > 6 {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	return true
}

func replaceAllLtFastGo(s string) string {
	ltCount := strings.Count(s, "<")
	if ltCount == 0 {
		return s
	}
	const lt16 = "&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;" // 16 * "&lt;" = 64 bytes
	buf := make([]byte, len(s)+ltCount*3)
	w := 0
	i := 0
	n := len(s)
	for i < n {
		rel := strings.IndexByte(s[i:], '<')
		if rel < 0 {
			w += copy(buf[w:], s[i:])
			break
		}
		if rel > 0 {
			w += copy(buf[w:], s[i:i+rel])
			i += rel
		}
		// Coalesce consecutive '<' runs in 16x chunks to minimize race-detector write barriers on dense '<' inputs.
		runEnd := i + 1
		for runEnd < n && s[runEnd] == '<' {
			runEnd++
		}
		rem := runEnd - i
		for rem >= 16 {
			w += copy(buf[w:], lt16)
			rem -= 16
		}
		for rem > 0 {
			w += copy(buf[w:], "&lt;")
			rem--
		}
		i = runEnd
	}
	return string(buf[:w])
}

func escapeAllResidualLtInProseLinearGo(prose string, allowPdfPageMarkers bool) string {
	if prose == "" || strings.IndexByte(prose, '<') < 0 {
		return prose
	}
	if !allowPdfPageMarkers {
		return replaceAllLtFastGo(prose)
	}
	lines := strings.Split(prose, "\n")
	changed := false
	for i, line := range lines {
		if strings.IndexByte(line, '<') < 0 {
			continue
		}
		if isVerifiedPdfPageMarkerLineGo(trimASCIIWhitespaceLinearGo(line)) {
			continue
		}
		lines[i] = replaceAllLtFastGo(line)
		changed = true
	}
	if !changed {
		return prose
	}
	return strings.Join(lines, "\n")
}

func decodeMarkdownEntitiesGo(input string) string {
	return stripInvisibleSmugglingCharsGo(decodeMarkdownEntitiesRawGo(input))
}

func decodeMarkdownEntitiesRawGo(input string) string {
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
						sb.WriteRune(rune(cp))
					}
					i = p + 1
					continue
				}
			}
		} else if (input[i+1] >= 'a' && input[i+1] <= 'z') || (input[i+1] >= 'A' && input[i+1] <= 'Z') {
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

func decodeMarkdownEntitiesPreservingLtGo(prose string) string {
	if prose == "" || strings.IndexByte(prose, '&') < 0 {
		return prose
	}
	// Fast skip when every `&` is already `&lt;` or `&LT;`
	hasOtherAmp := false
	for i := 0; i < len(prose); i++ {
		if prose[i] == '&' {
			if i+4 <= len(prose) && (prose[i:i+4] == "&lt;" || prose[i:i+4] == "&LT;") {
				i += 3
				continue
			}
			hasOtherAmp = true
			break
		}
	}
	if !hasOtherAmp {
		return prose
	}
	collapsed := collapseAmpEntityChainsGo(prose)
	// Guard `&lt;`, `&LT;`, `&#60;`, `&#0*60`, `&#x3c;` before decoding
	var guarded strings.Builder
	guarded.Grow(len(collapsed))
	i := 0
	n := len(collapsed)
	for i < n {
		if collapsed[i] == '&' {
			if i+4 <= n && (collapsed[i:i+4] == "&lt;" || collapsed[i:i+4] == "&LT;") {
				guarded.WriteString("\x00EFLT\x00")
				i += 4
				continue
			}
			if i+3 <= n && collapsed[i+1] == '#' {
				p := i + 2
				isHex := false
				if p < n && (collapsed[p] == 'x' || collapsed[p] == 'X') {
					isHex = true
					p++
				}
				for p < n && collapsed[p] == '0' {
					p++
				}
				if isHex {
					if p+2 <= n && collapsed[p] == '3' && (collapsed[p+1] == 'c' || collapsed[p+1] == 'C') {
						p += 2
						if p < n && collapsed[p] == ';' {
							p++
						}
						guarded.WriteString("\x00EFLT\x00")
						i = p
						continue
					}
				} else {
					if p+2 <= n && collapsed[p] == '6' && collapsed[p+1] == '0' {
						p += 2
						if p < n && collapsed[p] == ';' {
							p++
						}
						guarded.WriteString("\x00EFLT\x00")
						i = p
						continue
					}
				}
			}
		}
		guarded.WriteByte(collapsed[i])
		i++
	}
	decoded := strings.ReplaceAll(decodeMarkdownEntitiesRawGo(guarded.String()), "\x00EFLT\x00", "&lt;")
	if strings.Contains(decoded, "\x00EF") {
		return decoded
	}
	return stripInvisibleSmugglingCharsGo(decoded)
}

func resolveMarkdownRelativeHrefGo(href, baseURL string) string {
	if baseURL == "" {
		return href
	}
	isRel := (strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//")) ||
		strings.HasPrefix(href, "./") || strings.HasPrefix(href, "../")
	if !isRel {
		return href
	}
	baseParsed, err := url.Parse(baseURL)
	if err != nil || (baseParsed.Scheme != "https" && baseParsed.Scheme != "http") || baseParsed.Host == "" {
		return href
	}
	refParsed, err := url.Parse(href)
	if err != nil {
		return href
	}
	res := baseParsed.ResolveReference(refParsed)
	if res.Scheme == "https" || res.Scheme == "http" {
		return res.String()
	}
	return href
}

func resolveInlineHTMLHrefGo(rawHref, baseURL string, preserveHash bool) string {
	trimmedRaw := strings.TrimSpace(rawHref)
	if trimmedRaw == "" {
		return ""
	}
	trimmed := strings.TrimSpace(decodeMarkdownEntitiesGo(trimmedRaw))
	if trimmed == "" ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, `/\`) ||
		isDisallowedMarkdownLinkDestinationGo(trimmedRaw) ||
		isDisallowedMarkdownLinkDestinationGo(trimmed) {
		return ""
	}
	low := asciiLowerExtractString(trimmed[:minInt(len(trimmed), 12)])
	if strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "mailto:") ||
		strings.HasPrefix(low, "tel:") || strings.HasPrefix(low, "data:") {
		return ""
	}
	var resolved *url.URL
	if strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "http://") {
		u, err := url.Parse(trimmed)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return ""
		}
		resolved = u
	} else if baseURL != "" {
		baseParsed, err := url.Parse(baseURL)
		if err != nil || (baseParsed.Scheme != "https" && baseParsed.Scheme != "http") || baseParsed.Host == "" {
			return ""
		}
		ref, err2 := url.Parse(trimmed)
		if err2 != nil {
			return ""
		}
		res := baseParsed.ResolveReference(ref)
		if res.Scheme != "https" && res.Scheme != "http" {
			return ""
		}
		resolved = res
	}
	if resolved == nil {
		return ""
	}
	if !preserveHash || strings.ContainsAny(resolved.Fragment, " \t\r\n<>()") {
		resolved.Fragment = ""
		resolved.RawFragment = ""
	}
	return encodeUnsafeHrefCharsGo(resolved.String())
}

func encodeUnsafeHrefCharsGo(href string) string {
	if strings.IndexByte(href, ' ') < 0 && strings.IndexByte(href, '<') < 0 &&
		strings.IndexByte(href, '>') < 0 && strings.IndexByte(href, '`') < 0 {
		return href
	}
	r := strings.ReplaceAll(href, " ", "%20")
	r = strings.ReplaceAll(r, "<", "%3C")
	r = strings.ReplaceAll(r, ">", "%3E")
	r = strings.ReplaceAll(r, "`", "%60")
	return r
}

func isValidHttpAutolinkGo(s string) bool {
	low := asciiLowerExtractString(s[:minInt(len(s), 9)])
	if !strings.HasPrefix(low, "https://") && !strings.HasPrefix(low, "http://") {
		return false
	}
	schemeLen := 7
	if strings.HasPrefix(low, "https://") {
		schemeLen = 8
	}
	if len(s) <= schemeLen {
		return false
	}
	for i := schemeLen; i < len(s); i++ {
		c := s[i]
		if c <= 32 || c == '<' || c == '>' || c == '(' || c == ')' {
			return false
		}
	}
	return true
}

func isValidMailtoAutolinkGo(s string) bool {
	if len(s) < 10 || asciiLowerExtractString(s[:7]) != "mailto:" {
		return false
	}
	addr := s[7:]
	at := strings.IndexByte(addr, '@')
	if at <= 0 || strings.IndexByte(addr[at+1:], '@') >= 0 {
		return false
	}
	dot := strings.IndexByte(addr[at+1:], '.')
	if dot <= 0 || at+1+dot == len(addr)-1 {
		return false
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c <= 32 || c == '<' || c == '>' || c == '(' || c == ')' {
			return false
		}
	}
	return true
}

func sanitizeAndResolveMarkdownProseLinksLinearGo(prose, baseURL string) string {
	if prose == "" {
		return prose
	}
	if !strings.Contains(prose, "](") && strings.IndexByte(prose, '<') < 0 && !strings.Contains(prose, "]:") {
		if strings.Contains(prose, "//") {
			return neutralizeAllUnsafeMarkdownLinksLinearGo(prose)
		}
		return prose
	}
	lines := strings.Split(prose, "\n")
	changedLines := false
	for li, line := range lines {
		if (strings.IndexByte(line, '[') < 0 || !strings.Contains(line, "](")) && strings.IndexByte(line, '<') < 0 {
			continue
		}
		cursors := newMdLineCursorsGo()
		checkedNoLt := false
		nextGtOnLine := -1
		noGtOnLine := false
		var out strings.Builder
		lastCopyIdx := 0
		i := 0
		for i < len(line) {
			ch := line[i]
			if ch != '`' && ch != '<' && ch != '!' && ch != '[' {
				rel := strings.IndexAny(line[i+1:], "`<![")
				if rel < 0 {
					break
				}
				i += 1 + rel
				continue
			}
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

			if ch == '<' && !noGtOnLine && i+3 < len(line) && !isBackslashEscapedAt(line, i) && !(i >= 2 && line[i-2] == ']' && line[i-1] == '(') {
				if nextGtOnLine <= i {
					rel := strings.IndexByte(line[i+1:], '>')
					if rel < 0 {
						noGtOnLine = true
						if !strings.Contains(line, "](") {
							break
						}
					} else {
						nextGtOnLine = i + 1 + rel
					}
				}
				if !noGtOnLine && nextGtOnLine-i <= 2048 {
					gt := -1
					hasUnsafeAutoChar := false
					for p := i + 1; p <= nextGtOnLine; p++ {
						pc := line[p]
						if pc == '>' {
							gt = p
							break
						}
						if pc <= 32 || pc == '<' || pc == '"' || pc == '\'' {
							hasUnsafeAutoChar = true
							break
						}
					}
					if !hasUnsafeAutoChar && gt > i+2 {
						innerAutoRaw := line[i+1 : gt]
						innerAuto := innerAutoRaw
						if strings.IndexByte(innerAuto, '`') >= 0 {
							innerAuto = strings.ReplaceAll(innerAuto, "`", "%60")
						}
						if isDisallowedMarkdownLinkDestinationGo(innerAuto) {
							out.WriteString(line[lastCopyIdx:i])
							i = gt + 1
							lastCopyIdx = i
							continue
						}
						if isValidHttpAutolinkGo(innerAuto) {
							out.WriteString(line[lastCopyIdx:i])
							out.WriteByte('[')
							out.WriteString(innerAuto)
							out.WriteString("](")
							out.WriteString(innerAuto)
							out.WriteByte(')')
							i = gt + 1
							lastCopyIdx = i
							continue
						}
						if isValidMailtoAutolinkGo(innerAuto) {
							addr := innerAuto[7:]
							out.WriteString(line[lastCopyIdx:i])
							out.WriteByte('[')
							out.WriteString(addr)
							out.WriteString("](")
							out.WriteString(innerAuto)
							out.WriteByte(')')
							i = gt + 1
							lastCopyIdx = i
							continue
						}
					}
				}
			}

			if (ch == '!' || ch == '[') && !isBackslashEscapedAt(line, i) {
				if cursors.noCloseBracket || cursors.noCloseParen {
					if !checkedNoLt {
						checkedNoLt = true
						if strings.IndexByte(line[i+1:], '<') < 0 {
							break
						}
					}
					i++
					continue
				}
				if tok := tryParseMarkdownLinkOrImageAtGo(line, i, cursors, true); tok != nil {
					href := strings.TrimSpace(tok.rawURL)
					nextIdx := tok.end
					if href == "" {
						out.WriteString(line[lastCopyIdx:i])
						if !tok.isImage {
							lbl := tok.rawLabel
							if strings.Contains(lbl, "](") {
								lbl = sanitizeAndResolveMarkdownProseLinksLinearGo(lbl, baseURL)
							}
							out.WriteString(lbl)
						}
						i = nextIdx
						lastCopyIdx = i
						continue
					}
					if isDisallowedMarkdownLinkDestinationGo(href) {
						out.WriteString(line[lastCopyIdx:i])
						lbl := tok.rawLabel
						if strings.Contains(lbl, "](") {
							lbl = sanitizeAndResolveMarkdownProseLinksLinearGo(lbl, baseURL)
						}
						out.WriteByte('[')
						out.WriteString(lbl)
						out.WriteString("](#)")
						i = nextIdx
						lastCopyIdx = i
						continue
					}
					if !tok.isImage && strings.HasPrefix(href, "#") {
						trimmedSkip := strings.TrimSpace(tok.rawLabel)
						if strings.EqualFold(trimmedSkip, "skip to content") || strings.EqualFold(trimmedSkip, "skip to main content") {
							out.WriteString(line[lastCopyIdx:i])
							for nextIdx < len(line) && (line[nextIdx] == ' ' || line[nextIdx] == '\t') {
								nextIdx++
							}
							i = nextIdx
							lastCopyIdx = i
							continue
						}
					}
					href = encodeUnsafeHrefCharsGo(resolveMarkdownRelativeHrefGo(href, baseURL))
					if tok.isImage {
						out.WriteString(line[lastCopyIdx:i])
						out.WriteString("![")
						out.WriteString(tok.rawLabel)
						out.WriteString("](")
						out.WriteString(href)
						out.WriteString(tok.titleSuffix)
						out.WriteByte(')')
						i = nextIdx
						lastCopyIdx = i
						continue
					}
					labelOut := tok.rawLabel
					if strings.Contains(labelOut, "](") || strings.IndexByte(labelOut, '<') >= 0 {
						labelOut = sanitizeAndResolveMarkdownProseLinksLinearGo(labelOut, baseURL)
					}
					out.WriteString(line[lastCopyIdx:i])
					out.WriteByte('[')
					out.WriteString(labelOut)
					out.WriteString("](")
					out.WriteString(href)
					out.WriteString(tok.titleSuffix)
					out.WriteByte(')')
					i = nextIdx
					lastCopyIdx = i
					continue
				}
			}
			i++
		}
		if lastCopyIdx > 0 {
			out.WriteString(line[lastCopyIdx:])
			lines[li] = out.String()
			changedLines = true
		}
	}
	joined := prose
	if changedLines {
		joined = strings.Join(lines, "\n")
	}
	return neutralizeAllUnsafeMarkdownLinksLinearGo(joined)
}

func stripHtmlCommentsLinearGo(s string, allowPdfPageMarkers bool) string {
	pos := strings.Index(s, "<!--")
	if pos < 0 {
		return s
	}
	n := len(s)
	nextStd := -2
	nextBang := -2
	noCloseFrom := -1
	var sb strings.Builder
	wroteAny := false
	cursor := 0

	for pos >= 0 {
		bodyStart := pos + 4
		closeEnd := -1
		if bodyStart < n && s[bodyStart] == '>' {
			closeEnd = bodyStart + 1
		} else if bodyStart+1 < n && s[bodyStart] == '-' && s[bodyStart+1] == '>' {
			closeEnd = bodyStart + 2
		} else if noCloseFrom < 0 || bodyStart < noCloseFrom {
			if nextStd != -1 && nextStd < bodyStart {
				rel := strings.Index(s[bodyStart:], "-->")
				if rel < 0 {
					nextStd = -1
				} else {
					nextStd = bodyStart + rel
				}
			}
			if nextBang != -1 && nextBang < bodyStart {
				rel := strings.Index(s[bodyStart:], "--!>")
				if rel < 0 {
					nextBang = -1
				} else {
					nextBang = bodyStart + rel
				}
			}
			if nextStd < 0 && nextBang < 0 {
				if noCloseFrom < 0 || bodyStart < noCloseFrom {
					noCloseFrom = bodyStart
				}
			} else if nextStd >= 0 && (nextBang < 0 || nextStd <= nextBang) {
				closeEnd = nextStd + 3
			} else {
				closeEnd = nextBang + 4
			}
		}

		if closeEnd < 0 {
			// No `-->` or `--!>` exists anywhere after `pos + 4`: jump directly to any abrupt `<!-->` / `<!--->` if present!
			abrupt1 := strings.Index(s[bodyStart:], "<!-->")
			abrupt2 := strings.Index(s[bodyStart:], "<!--->")
			if abrupt1 < 0 && abrupt2 < 0 {
				break
			}
			if abrupt1 >= 0 && (abrupt2 < 0 || abrupt1 <= abrupt2) {
				pos = bodyStart + abrupt1
			} else {
				pos = bodyStart + abrupt2
			}
			continue
		}
		if allowPdfPageMarkers {
			lineStart := strings.LastIndexByte(s[:pos], '\n') + 1
			lineEndRel := strings.IndexByte(s[closeEnd:], '\n')
			lineEnd := n
			if lineEndRel >= 0 {
				lineEnd = closeEnd + lineEndRel
			}
			if strings.Trim(s[lineStart:pos], " \t") == "" && strings.Trim(s[closeEnd:lineEnd], " \t\r") == "" &&
				isVerifiedPdfPageMarkerLineGo(s[pos:closeEnd]) {
				if !wroteAny {
					sb.Grow(n)
					wroteAny = true
				}
				sb.WriteString(s[cursor:closeEnd])
				cursor = closeEnd
				rel := strings.Index(s[cursor:], "<!--")
				if rel < 0 {
					break
				}
				pos = cursor + rel
				continue
			}
		}
		if pos > cursor {
			if !wroteAny {
				sb.Grow(n)
				wroteAny = true
			}
			sb.WriteString(s[cursor:pos])
		}
		cursor = closeEnd
		rel := strings.Index(s[cursor:], "<!--")
		if rel < 0 {
			break
		}
		pos = cursor + rel
	}
	if cursor == 0 {
		return s
	}
	if !wroteAny {
		return s[cursor:]
	}
	if cursor < n {
		sb.WriteString(s[cursor:])
	}
	return sb.String()
}

type parsedHTMLTagGo struct {
	start       int
	end         int
	tagLower    string
	rawTag      string
	attrs       string
	isClosing   bool
	selfClosing bool
}

func scanNextHTMLTagQuoteAwareGo(s string, from int, noCloseDbl *bool, noCloseSgl *bool) (parsedHTMLTagGo, bool) {
	n := len(s)
	i := from
	for i < n {
		rel := strings.IndexByte(s[i:], '<')
		if rel < 0 {
			return parsedHTMLTagGo{}, false
		}
		lt := i + rel
		if lt+1 >= n {
			return parsedHTMLTagGo{}, false
		}
		p := lt + 1
		isClosing := false
		if s[p] == '/' {
			isClosing = true
			p++
		}
		if p >= n || !((s[p] >= 'a' && s[p] <= 'z') || (s[p] >= 'A' && s[p] <= 'Z')) {
			i = lt + 1
			continue
		}
		nameStart := p
		for p < n && ((s[p] >= 'a' && s[p] <= 'z') || (s[p] >= 'A' && s[p] <= 'Z') || (s[p] >= '0' && s[p] <= '9') || s[p] == '-' || s[p] == ':') {
			p++
		}
		if p < n && s[p] != '>' && s[p] != '/' && !isASCIIWhitespaceByte(s[p]) {
			i = lt + 1
			continue
		}
		nameLower := asciiLowerExtractString(s[nameStart:p])
		attrStart := p
		if isClosing {
			relGt := strings.IndexByte(s[p:], '>')
			if relGt < 0 {
				return parsedHTMLTagGo{}, false
			}
			gtIdx := p + relGt
			return parsedHTMLTagGo{
				start:       lt,
				end:         gtIdx + 1,
				tagLower:    nameLower,
				rawTag:      s[lt : gtIdx+1],
				attrs:       s[attrStart:gtIdx],
				isClosing:   true,
				selfClosing: false,
			}, true
		}
		j := p
		var quote byte
		for j < n {
			c := s[j]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
			} else {
				if c == '"' && !*noCloseDbl {
					quote = '"'
				} else if c == '\'' && !*noCloseSgl {
					quote = '\''
				} else if c == '>' {
					break
				}
			}
			j++
		}
		if j < n && s[j] == '>' {
			attrEnd := j
			selfClosing := false
			if !isClosing && attrEnd > attrStart && s[attrEnd-1] == '/' {
				selfClosing = true
				attrEnd--
			}
			return parsedHTMLTagGo{
				start:       lt,
				end:         j + 1,
				tagLower:    nameLower,
				rawTag:      s[lt : j+1],
				attrs:       s[attrStart:attrEnd],
				isClosing:   isClosing,
				selfClosing: selfClosing,
			}, true
		}
		if quote == '"' {
			*noCloseDbl = true
			continue
		}
		if quote == '\'' {
			*noCloseSgl = true
			continue
		}
		return parsedHTMLTagGo{}, false
	}
	return parsedHTMLTagGo{}, false
}

var dangerousHTMLBlockSetGo = map[string]bool{
	"script":   true,
	"style":    true,
	"textarea": true,
	"title":    true,
	"xmp":      true,
	"iframe":   true,
	"object":   true,
	"embed":    true,
	"applet":   true,
	"svg":      true,
	"math":     true,
	"form":     true,
	"noscript": true,
	"template": true,
	"head":     true,
	"meta":     true,
	"link":     true,
	"base":     true,
}

func isHTMLTagBoundaryByteGo(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r' || b == '/' || b == '>'
}

func findNextValidCloseTagGo(lower, src, closeNeedle string, from int) int {
	pos := from
	for pos < len(lower) {
		rel := strings.Index(lower[pos:], closeNeedle)
		if rel < 0 {
			return -1
		}
		hit := pos + rel
		after := hit + len(closeNeedle)
		if after < len(src) && isHTMLTagBoundaryByteGo(src[after]) {
			return hit
		}
		pos = after
	}
	return -1
}

func stripDangerousHTMLSubtreesGo(s string) string {
	var sb strings.Builder
	noDbl, noSgl := false, false
	last := 0
	pos := 0
	changed := false
	var lower string
	var cachedClose map[string]int

	for pos < len(s) {
		tag, ok := scanNextHTMLTagQuoteAwareGo(s, pos, &noDbl, &noSgl)
		if !ok {
			break
		}
		if dangerousHTMLBlockSetGo[tag.tagLower] {
			if !changed && sb.Cap() == 0 {
				sb.Grow(len(s))
			}
			sb.WriteString(s[last:tag.start])
			changed = true
			if tag.isClosing || tag.selfClosing || tag.tagLower == "meta" || tag.tagLower == "link" || tag.tagLower == "base" || tag.tagLower == "embed" {
				last = tag.end
				pos = tag.end
				continue
			}
			if cachedClose == nil {
				lower = asciiLowerExtractString(s)
				cachedClose = make(map[string]int)
			}
			closePos, seen := cachedClose[tag.tagLower]
			if !seen || (closePos != -1 && closePos < tag.end) {
				closePos = findNextValidCloseTagGo(lower, s, "</"+tag.tagLower, tag.end)
				cachedClose[tag.tagLower] = closePos
			}
			if closePos < 0 {
				if tag.tagLower == "script" || tag.tagLower == "style" || tag.tagLower == "textarea" || tag.tagLower == "title" || tag.tagLower == "xmp" {
					if len(s) > tag.start && s[len(s)-1] == '\n' {
						last = len(s) - 1
					} else {
						last = len(s)
					}
					break
				}
				last = tag.end
				pos = tag.end
				continue
			}
			closeEndRel := strings.IndexByte(s[closePos+2+len(tag.tagLower):], '>')
			if closeEndRel < 0 {
				if len(s) > tag.start && s[len(s)-1] == '\n' {
					last = len(s) - 1
				} else {
					last = len(s)
				}
				break
			}
			closeEnd := closePos + 2 + len(tag.tagLower) + closeEndRel + 1
			last = closeEnd
			pos = closeEnd
			continue
		}
		pos = tag.end
	}
	if !changed {
		return s
	}
	if last < len(s) {
		sb.WriteString(s[last:])
	}
	return sb.String()
}

var voidHTMLTagsGo = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "param": true, "source": true, "track": true, "wbr": true,
}

var alwaysHiddenOrChromeClassesGo = map[string]bool{
	"sr-only": true, "visually-hidden": true, "screenreader-only": true, "hideme": true,
	"unitheader-banner": true, "js-comment-minimize": true, "js-comment-hide-button": true,
	"js-suggestion-button-placeholder": true, "js-clipboard-copy": true, "zeroclipboard-container": true,
	"doc-anchor": true, "documentation-idlink": true, "headerlink": true, "pilcrow": true,
	"mw-editsection": true, "mw-editsection-bracket": true, "mw-editsection-divider": true,
	"sphinxsidebar": true, "katex-html": true, "mwe-math-fallback-image-inline": true,
	"mwe-math-fallback-image-display": true, "lnt": true, "line-numbers-rows": true,
	"line-numbers-wrapper": true, "hljs-ln-numbers": true, "swiper-slide-duplicate": true,
	"slick-cloned": true, "splide__slide--clone": true, "flickity-cloned": true,
	"glide__slide--clone": true, "owl-cloned": true,
}

var strippedLandmarkRolesGo = map[string]bool{
	"navigation": true, "search": true, "banner": true, "contentinfo": true,
	"dialog": true, "alertdialog": true, "menu": true, "menubar": true, "toolbar": true,
}

func isHiddenInlineStyleGo(styleVal string) bool {
	for _, decl := range strings.Split(styleVal, ";") {
		d := strings.TrimSpace(asciiLowerExtractString(decl))
		if d == "" {
			continue
		}
		colon := strings.IndexByte(d, ':')
		if colon <= 0 {
			continue
		}
		prop := strings.TrimSpace(d[:colon])
		val := strings.TrimSpace(d[colon+1:])
		switch prop {
		case "display":
			if val == "none" || strings.HasPrefix(val, "none ") || strings.HasPrefix(val, "none!") {
				return true
			}
		case "visibility":
			if val == "hidden" || strings.HasPrefix(val, "hidden ") || strings.HasPrefix(val, "hidden!") {
				return true
			}
		case "opacity":
			trimmedZero := strings.TrimRight(strings.TrimPrefix(val, "0."), "0")
			if val == "0" || (strings.HasPrefix(val, "0.") && trimmedZero == "" && len(val) > 2) {
				return true
			}
		case "font-size":
			if val == "0" || val == "0px" || val == "0em" || val == "0rem" || val == "0%" || val == "0pt" {
				return true
			}
		}
	}
	return false
}

func shouldStripHiddenOrChromeOpenTagGo(tagLower, attrStr string) bool {
	if attrStr == "" || tagLower == "html" || tagLower == "body" || tagLower == "main" || tagLower == "article" {
		return false
	}
	lowAttr := asciiLowerExtractString(attrStr)
	if !strings.Contains(lowAttr, "hidden") && !strings.Contains(lowAttr, "style") &&
		!strings.Contains(lowAttr, "role") && !strings.Contains(lowAttr, "class") {
		return false
	}
	attrs := parseHTMLTagAttrsGo(attrStr)
	if hv, hasHidden := attrs["hidden"]; hasHidden {
		hvTrim := strings.TrimSpace(asciiLowerExtractString(hv))
		if hvTrim != "false" && hvTrim != "0" {
			return true
		}
	}
	if sv, hasStyle := attrs["style"]; hasStyle && sv != "" {
		if !strings.Contains(lowAttr, "mwe-math") && !strings.Contains(lowAttr, "katex-mathml") && !strings.Contains(lowAttr, "mjx-assistive") {
			if isHiddenInlineStyleGo(sv) {
				return true
			}
		}
	}
	if rv, hasRole := attrs["role"]; hasRole && strippedLandmarkRolesGo[strings.TrimSpace(asciiLowerExtractString(rv))] {
		return true
	}
	if (tagLower == "span" || tagLower == "i") && strings.TrimSpace(asciiLowerExtractString(attrs["aria-hidden"])) == "true" {
		return true
	}
	if cv, hasClass := attrs["class"]; hasClass && cv != "" {
		lowClass := asciiLowerExtractString(cv)
		hasDNoneOrTw := false
		for _, tok := range strings.Fields(lowClass) {
			if alwaysHiddenOrChromeClassesGo[tok] {
				return true
			}
			if tok == "d-none" || tok == "tw-hidden" {
				hasDNoneOrTw = true
			}
		}
		if hasDNoneOrTw && !strings.Contains(lowClass, "-block") && !strings.Contains(lowClass, "-flex") &&
			!strings.Contains(lowClass, "-inline") && !strings.Contains(lowClass, "-grid") &&
			!strings.Contains(lowClass, "-table") && !strings.Contains(lowClass, ":block") &&
			!strings.Contains(lowClass, ":flex") && !strings.Contains(lowClass, ":inline") &&
			!strings.Contains(lowClass, ":grid") && !strings.Contains(lowClass, ":table") {
			return true
		}
	}
	return false
}

func stripHiddenAndChromeSubtreesGo(s string) string {
	low := asciiLowerExtractString(s)
	if !strings.Contains(low, "hidden") && !strings.Contains(low, "style") &&
		!strings.Contains(low, "role") && !strings.Contains(low, "class") {
		return s
	}
	var sb strings.Builder
	noDbl, noSgl := false, false
	lastKeepIdx := 0
	skipTag := ""
	skipDepth := 0
	skipStartIdx := 0
	changed := false
	pos := 0

	for pos < len(s) {
		tag, ok := scanNextHTMLTagQuoteAwareGo(s, pos, &noDbl, &noSgl)
		if !ok {
			break
		}
		if tag.attrs != "" && tag.attrs[0] != ' ' && tag.attrs[0] != '\t' && tag.attrs[0] != '\n' && tag.attrs[0] != '\r' && tag.attrs[0] != '\f' && tag.attrs[0] != '/' {
			pos = tag.end
			continue
		}
		isSelfClosing := !tag.isClosing && (voidHTMLTagsGo[tag.tagLower] || tag.selfClosing)
		if skipDepth > 0 {
			if tag.tagLower == skipTag {
				if tag.isClosing {
					skipDepth--
					if skipDepth == 0 {
						lastKeepIdx = tag.end
					}
				} else if !isSelfClosing {
					skipDepth++
				}
			}
			pos = tag.end
			continue
		}
		if !tag.isClosing && shouldStripHiddenOrChromeOpenTagGo(tag.tagLower, tag.attrs) {
			if !changed && sb.Cap() == 0 {
				sb.Grow(len(s))
			}
			sb.WriteString(s[lastKeepIdx:tag.start])
			changed = true
			if isSelfClosing {
				lastKeepIdx = tag.end
			} else {
				skipTag = tag.tagLower
				skipDepth = 1
				skipStartIdx = tag.start
			}
		}
		pos = tag.end
	}
	if !changed && skipDepth == 0 {
		return s
	}
	if skipDepth > 0 {
		sb.WriteString(s[skipStartIdx:])
	} else if lastKeepIdx < len(s) {
		sb.WriteString(s[lastKeepIdx:])
	}
	return sb.String()
}

func parseHTMLTagAttrsGo(attrStr string) map[string]string {
	res := make(map[string]string)
	i := 0
	n := len(attrStr)
	for i < n {
		for i < n && (isASCIIWhitespaceByte(attrStr[i]) || attrStr[i] == '/') {
			i++
		}
		if i >= n {
			break
		}
		kStart := i
		for i < n && !isASCIIWhitespaceByte(attrStr[i]) && attrStr[i] != '=' && attrStr[i] != '/' {
			i++
		}
		if i == kStart {
			i++
			continue
		}
		key := asciiLowerExtractString(attrStr[kStart:i])
		ws := i
		for ws < n && isASCIIWhitespaceByte(attrStr[ws]) {
			ws++
		}
		if ws < n && attrStr[ws] == '=' {
			vPos := ws + 1
			for vPos < n && isASCIIWhitespaceByte(attrStr[vPos]) {
				vPos++
			}
			if vPos < n && (attrStr[vPos] == '"' || attrStr[vPos] == '\'') {
				q := attrStr[vPos]
				vEnd := strings.IndexByte(attrStr[vPos+1:], q)
				if vEnd >= 0 {
					res[key] = attrStr[vPos+1 : vPos+1+vEnd]
					i = vPos + 1 + vEnd + 1
					continue
				}
			}
			vStart := vPos
			for vPos < n && !isASCIIWhitespaceByte(attrStr[vPos]) {
				vPos++
			}
			res[key] = attrStr[vStart:vPos]
			i = vPos
		} else {
			res[key] = ""
			i = ws
		}
	}
	return res
}

func hasInlineEventHandlerAttrGo(attrStr string) bool {
	attrs := parseHTMLTagAttrsGo(attrStr)
	for k := range attrs {
		if len(k) >= 3 && k[0] == 'o' && k[1] == 'n' && k[2] >= 'a' && k[2] <= 'z' {
			return true
		}
	}
	return false
}

func formatInlineCodeSpanGo(txt string) string {
	clean := strings.TrimSpace(strings.ReplaceAll(txt, "\n", " "))
	if clean == "" {
		return ""
	}
	maxRun := 0
	cur := 0
	for i := 0; i < len(clean); i++ {
		if clean[i] == '`' {
			cur++
			if cur > maxRun {
				maxRun = cur
			}
		} else {
			cur = 0
		}
	}
	fence := strings.Repeat("`", maxRun+1)
	if maxRun > 0 {
		return fence + " " + clean + " " + fence
	}
	return fence + clean + fence
}

func convertSimpleHTMLTablesInProseGo(s string) string {
	if !strings.Contains(s, "</") || !strings.Contains(asciiLowerExtractString(s), "<table") {
		return s
	}
	noDbl, noSgl := false, false
	var sb strings.Builder
	last := 0
	pos := 0
	for pos < len(s) {
		tag, ok := scanNextHTMLTagQuoteAwareGo(s, pos, &noDbl, &noSgl)
		if !ok {
			break
		}
		if !tag.isClosing && !tag.selfClosing && tag.tagLower == "table" {
			searchEnd := minInt(len(s), tag.end+16384)
			relClose := strings.Index(asciiLowerExtractString(s[tag.end:searchEnd]), "</table")
			if relClose >= 0 {
				cStart := tag.end + relClose
				afterName := cStart + 7
				for afterName < searchEnd && isASCIIWhitespaceByte(s[afterName]) {
					afterName++
				}
				if afterName < searchEnd && s[afterName] == '>' {
					cEnd := afterName + 1
					inner := s[tag.end:cStart]
					lowInner := asciiLowerExtractString(inner)
					if !strings.Contains(lowInner, "<table") && !strings.Contains(lowInner, "<pre") {
						var rows [][]string
						rNoDbl, rNoSgl := false, false
						rPos := 0
						for rPos < len(inner) {
							rTag, rOk := scanNextHTMLTagQuoteAwareGo(inner, rPos, &rNoDbl, &rNoSgl)
							if !rOk {
								break
							}
							if !rTag.isClosing && !rTag.selfClosing && rTag.tagLower == "tr" {
								rCloseRel := strings.Index(asciiLowerExtractString(inner[rTag.end:]), "</tr")
								if rCloseRel >= 0 {
									rcStart := rTag.end + rCloseRel
									rcAfter := rcStart + 4
									for rcAfter < len(inner) && isASCIIWhitespaceByte(inner[rcAfter]) {
										rcAfter++
									}
									if rcAfter < len(inner) && inner[rcAfter] == '>' {
										rowInner := inner[rTag.end:rcStart]
										var cells []string
										cNoDbl, cNoSgl := false, false
										cPos := 0
										for cPos < len(rowInner) {
											cTag, cOk := scanNextHTMLTagQuoteAwareGo(rowInner, cPos, &cNoDbl, &cNoSgl)
											if !cOk {
												break
											}
											if !cTag.isClosing && !cTag.selfClosing && (cTag.tagLower == "th" || cTag.tagLower == "td") {
												cNeedle := "</" + cTag.tagLower
												cCloseRel := strings.Index(asciiLowerExtractString(rowInner[cTag.end:]), cNeedle)
												if cCloseRel >= 0 {
													ccStart := cTag.end + cCloseRel
													ccAfter := ccStart + len(cNeedle)
													for ccAfter < len(rowInner) && isASCIIWhitespaceByte(rowInner[ccAfter]) {
														ccAfter++
													}
													if ccAfter < len(rowInner) && rowInner[ccAfter] == '>' {
														cellTxt := stripTagsInlineLinear(rowInner[cTag.end:ccStart])
														cellTxt = strings.ReplaceAll(cellTxt, "|", "\\|")
														cellTxt = strings.Join(strings.Fields(cellTxt), " ")
														cells = append(cells, cellTxt)
														cPos = ccAfter + 1
														continue
													}
												}
											}
											cPos = cTag.end
										}
										if len(cells) > 0 {
											rows = append(rows, cells)
										}
										rPos = rcAfter + 1
										continue
									}
								}
							}
							rPos = rTag.end
						}
						if len(rows) > 0 && len(rows[0]) > 0 {
							colCount := len(rows[0])
							var tsb strings.Builder
							tsb.WriteString("\n\n| ")
							for ci := 0; ci < colCount; ci++ {
								if ci > 0 {
									tsb.WriteString(" | ")
								}
								tsb.WriteString(rows[0][ci])
							}
							tsb.WriteString(" |\n| ")
							for ci := 0; ci < colCount; ci++ {
								if ci > 0 {
									tsb.WriteString(" | ")
								}
								tsb.WriteString("---")
							}
							tsb.WriteString(" |")
							for ri := 1; ri < len(rows); ri++ {
								tsb.WriteString("\n| ")
								for ci := 0; ci < colCount; ci++ {
									if ci > 0 {
										tsb.WriteString(" | ")
									}
									if ci < len(rows[ri]) {
										tsb.WriteString(rows[ri][ci])
									}
								}
								tsb.WriteString(" |")
							}
							tsb.WriteString("\n\n")
							if last == 0 && sb.Cap() == 0 {
								sb.Grow(len(s))
							}
							sb.WriteString(s[last:tag.start])
							sb.WriteString(tsb.String())
							last = cEnd
							pos = cEnd
							continue
						}
					}
				}
			}
		}
		pos = tag.end
	}
	if last > 0 {
		sb.WriteString(s[last:])
		return sb.String()
	}
	return s
}

func convertAnchorInnerWithBadgeImagesSanGo(inner, baseURL string) string {
	lowInner := asciiLowerExtractString(inner)
	if !strings.Contains(lowInner, "<img") {
		return stripTagsInlineLinear(inner)
	}
	noDbl, noSgl := false, false
	var sb strings.Builder
	last := 0
	pos := 0
	for pos < len(inner) {
		tag, ok := scanNextHTMLTagQuoteAwareGo(inner, pos, &noDbl, &noSgl)
		if !ok {
			break
		}
		if tag.tagLower == "img" && !tag.isClosing {
			sb.WriteString(inner[last:tag.start])
			if !hasInlineEventHandlerAttrGo(tag.attrs) {
				attrs := parseHTMLTagAttrsGo(tag.attrs)
				srcCand := attrs["src"]
				if srcCand == "" {
					srcCand = attrs["data-src"]
				}
				resolvedSrc := resolveSafeMarkdownHrefOrRelativeFullDocGo(srcCand, baseURL, false)
				alt := strings.NewReplacer("[", "", "]", "").Replace(stripTagsInlineLinear(attrs["alt"]))
				if resolvedSrc != "" && !isTinyOrAvatarImageURLFullDocGo(resolvedSrc, alt) {
					sb.WriteString(" ![" + alt + "](" + resolvedSrc + ") ")
				}
			}
			last = tag.end
		}
		pos = tag.end
	}
	if last > 0 {
		sb.WriteString(inner[last:])
		return stripTagsInlineLinear(sb.String())
	}
	return stripTagsInlineLinear(inner)
}

func convertInlineHTMLInProseGo(s string, baseURL string, inlineCodeStash *[]string) string {
	if strings.IndexByte(s, '[') >= 0 && strings.Contains(asciiLowerExtractString(s), "</h") {
		s = reBracketHeadingLinkSanGo.ReplaceAllStringFunc(s, func(m string) string {
			sub := reBracketHeadingLinkSanGo.FindStringSubmatch(m)
			if len(sub) < 4 {
				return m
			}
			lvl := int(sub[1][0] - '0')
			lbl := stripTagsInlineLinear(sub[2])
			href := strings.TrimSpace(sub[3])
			if lbl == "" || isDisallowedMarkdownLinkDestinationGo(href) {
				return lbl
			}
			return "\n\n" + strings.Repeat("#", lvl) + " [" + lbl + "](" + href + ")\n\n"
		})
	}
	s = convertSimpleHTMLTablesInProseGo(s)
	// 1. Convert paired inline elements (`a`, `h1`..`h6`, `summary`, `code`, `kbd`, `strong`, `b`, `em`, `i`, `sup`)
	pairedTargets := map[string]bool{
		"a": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
		"summary": true, "code": true, "kbd": true, "strong": true, "b": true, "em": true, "i": true, "sup": true,
	}
	if strings.Contains(s, "</") {
		noDbl, noSgl := false, false
		var sb strings.Builder
		last := 0
		pos := 0
		for pos < len(s) {
			tag, ok := scanNextHTMLTagQuoteAwareGo(s, pos, &noDbl, &noSgl)
			if !ok {
				break
			}
			if !tag.isClosing && !tag.selfClosing && pairedTargets[tag.tagLower] {
				// Find matching non-nested close tag within 8192 bytes
				closeNeedle := "</" + tag.tagLower
				searchEnd := minInt(len(s), tag.end+8192)
				relClose := strings.Index(asciiLowerExtractString(s[tag.end:searchEnd]), closeNeedle)
				if relClose >= 0 {
					cStart := tag.end + relClose
					afterName := cStart + len(closeNeedle)
					for afterName < searchEnd && isASCIIWhitespaceByte(s[afterName]) {
						afterName++
					}
					if afterName < searchEnd && s[afterName] == '>' {
						cEnd := afterName + 1
						inner := s[tag.end:cStart]
						txt := stripTagsInlineLinear(inner)
						replacement := ""
						handled := true
						switch tag.tagLower {
						case "a":
							attrs := parseHTMLTagAttrsGo(tag.attrs)
							trimmedInner := strings.TrimSpace(inner)
							if len(trimmedInner) >= 7 && trimmedInner[0] == '<' && (trimmedInner[1] == 'h' || trimmedInner[1] == 'H') && trimmedInner[2] >= '1' && trimmedInner[2] <= '6' {
								hLvl := int(trimmedInner[2] - '0')
								hClose := "</h" + string(trimmedInner[2]) + ">"
								if strings.HasSuffix(asciiLowerExtractString(trimmedInner), hClose) && txt != "" {
									href := resolveInlineHTMLHrefGo(attrs["href"], baseURL, true)
									if href != "" {
										replacement = "\n\n" + strings.Repeat("#", hLvl) + " [" + txt + "](" + href + ")\n\n"
									} else {
										replacement = "\n\n" + strings.Repeat("#", hLvl) + " " + txt + "\n\n"
									}
									break
								}
							}
							href := resolveSafeMarkdownHrefOrRelativeFullDocGo(attrs["href"], baseURL, true)
							lbl := convertAnchorInnerWithBadgeImagesSanGo(inner, baseURL)
							if lbl != "" {
								if href != "" {
									replacement = "[" + lbl + "](" + href + ")"
								} else {
									replacement = lbl
								}
							}
						case "h1", "h2", "h3", "h4", "h5", "h6":
							if txt != "" {
								lvl := int(tag.tagLower[1] - '0')
								replacement = "\n\n" + strings.Repeat("#", lvl) + " " + txt + "\n\n"
							}
						case "summary":
							if txt != "" {
								replacement = "\n\n**" + txt + "**\n\n"
							}
						case "code", "kbd":
							if txt != "" {
								span := formatInlineCodeSpanGo(txt)
								if span != "" {
									idx := len(*inlineCodeStash)
									*inlineCodeStash = append(*inlineCodeStash, span)
									replacement = "\x00EFMDINLINE" + strconv.Itoa(idx) + "\x00"
								}
							}
						case "strong", "b":
							if txt != "" {
								replacement = "**" + txt + "**"
							}
						case "em", "i":
							if txt != "" {
								replacement = "*" + txt + "*"
							}
						case "sup":
							if txt != "" {
								allCitation := true
								for k := 0; k < len(txt); k++ {
									c := txt[k]
									if !((c >= '0' && c <= '9') || c == ',' || c == '-' || c == ' ') {
										allCitation = false
										break
									}
								}
								if allCitation {
									replacement = " [" + txt + "]"
								} else {
									replacement = "^" + txt
								}
							}
						default:
							handled = false
						}
						if handled {
							if last == 0 && sb.Cap() == 0 {
								sb.Grow(len(s))
							}
							sb.WriteString(s[last:tag.start])
							sb.WriteString(replacement)
							last = cEnd
							pos = cEnd
							continue
						}
					}
				}
			}
			pos = tag.end
		}
		if last > 0 {
			sb.WriteString(s[last:])
			s = sb.String()
		}
	}

	// 2. Convert void/wrapper tags (`br`, `hr`, safe `img`, wrapper containers, PascalCase MDX tags)
	wrapperStrip := map[string]bool{
		"u": true, "sub": true, "details": true, "span": true, "div": true, "p": true, "button": true,
		"section": true, "article": true, "main": true, "header": true, "footer": true, "nav": true, "aside": true,
	}
	noDbl, noSgl := false, false
	var sb2 strings.Builder
	last2 := 0
	pos2 := 0
	for pos2 < len(s) {
		tag, ok := scanNextHTMLTagQuoteAwareGo(s, pos2, &noDbl, &noSgl)
		if !ok {
			break
		}
		rep := tag.rawTag
		replaceIt := false
		if tag.tagLower == "br" {
			lineStart := strings.LastIndexByte(s[:tag.start], '\n') + 1
			p := lineStart
			for p < len(s) && (s[p] == ' ' || s[p] == '\t') {
				p++
			}
			if p < len(s) && s[p] == '|' {
				rep = " / "
			} else {
				rep = "\n"
			}
			replaceIt = true
		} else if tag.tagLower == "hr" && !tag.isClosing {
			rep = "\n\n---\n\n"
			replaceIt = true
		} else if tag.tagLower == "img" && !tag.isClosing {
			if hasInlineEventHandlerAttrGo(tag.attrs) {
				rep = ""
			} else {
				attrs := parseHTMLTagAttrsGo(tag.attrs)
				srcRaw := attrs["src"]
				if srcRaw == "" {
					srcRaw = attrs["data-src"]
				}
				resolved := resolveSafeMarkdownHrefOrRelativeFullDocGo(srcRaw, baseURL, false)
				alt := stripTagsInlineLinear(attrs["alt"])
				if resolved == "" || isTinyOrAvatarImageURLFullDocGo(resolved, alt) {
					rep = ""
				} else {
					rep = "![" + alt + "](" + resolved + ")"
				}
			}
			replaceIt = true
		} else {
			firstPos := 1
			if tag.isClosing {
				firstPos = 2
			}
			if firstPos < len(tag.rawTag) && tag.rawTag[firstPos] >= 'A' && tag.rawTag[firstPos] <= 'Z' &&
				strings.IndexByte(tag.tagLower, ':') < 0 &&
				!(tag.start >= 2 && s[tag.start-2] == ']' && s[tag.start-1] == '(') {
				rep = ""
				if !tag.isClosing && !tag.selfClosing && tag.attrs != "" && strings.Contains(asciiLowerExtractString(tag.attrs), "title") {
					ls := strings.LastIndexByte(s[:tag.start], '\n') + 1
					leRel := strings.IndexByte(s[tag.end:], '\n')
					le := len(s)
					if leRel >= 0 {
						le = tag.end + leRel
					}
					if tag.start-ls <= 64 && le-tag.end <= 64 && isBlankASCIILineGo(s[ls:tag.start]) && isBlankASCIILineGo(s[tag.end:le]) {
						attrs := parseHTMLTagAttrsGo(tag.attrs)
						ht := attrs["title"]
						if ht == "" {
							ht = attrs["titletext"]
						}
						htClean := stripTagsInlineLinear(ht)
						if htClean != "" {
							rep = "\n\n**" + htClean + "**\n\n"
						}
					}
				}
				replaceIt = true
			} else if wrapperStrip[tag.tagLower] {
				rep = ""
				replaceIt = true
			}
		}
		if replaceIt {
			if last2 == 0 && sb2.Cap() == 0 {
				sb2.Grow(len(s))
			}
			sb2.WriteString(s[last2:tag.start])
			sb2.WriteString(rep)
			last2 = tag.end
		}
		pos2 = tag.end
	}
	if last2 > 0 {
		sb2.WriteString(s[last2:])
		return sb2.String()
	}
	return s
}

func collapseExcessBlankLinesGo(s string) string {
	if !strings.Contains(s, "\n\n\n") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	nlRun := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			nlRun++
			if nlRun <= 2 {
				sb.WriteByte('\n')
			}
		} else {
			nlRun = 0
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

func isStandaloneHttpLinkParagraphGo(s string) bool {
	if len(s) < 12 || s[0] != '[' || s[len(s)-1] != ')' || strings.IndexByte(s, '\n') >= 0 {
		return false
	}
	closeBr := strings.Index(s, "](")
	if closeBr <= 1 {
		return false
	}
	if strings.IndexByte(s[1:closeBr], ']') >= 0 {
		return false
	}
	urlPart := s[closeBr+2 : len(s)-1]
	low := asciiLowerExtractString(urlPart[:minInt(len(urlPart), 9)])
	if !strings.HasPrefix(low, "https://") && !strings.HasPrefix(low, "http://") {
		return false
	}
	for i := 0; i < len(urlPart); i++ {
		if urlPart[i] <= 32 || urlPart[i] == ')' {
			return false
		}
	}
	return true
}

func dedupeConsecutiveStandaloneLinkParagraphsGo(prose string) string {
	if !strings.Contains(prose, "\n\n") {
		return prose
	}
	var blocks []string
	i := 0
	for i < len(prose) {
		rel := strings.Index(prose[i:], "\n\n")
		if rel < 0 {
			blocks = append(blocks, prose[i:])
			break
		}
		bEnd := i + rel
		blocks = append(blocks, prose[i:bEnd])
		i = bEnd + 2
		for i < len(prose) && prose[i] == '\n' {
			i++
		}
	}
	if len(blocks) < 2 {
		return prose
	}
	out := make([]string, 0, len(blocks))
	changed := false
	for _, b := range blocks {
		tr := trimASCIIWhitespaceLinearGo(b)
		prev := ""
		if len(out) > 0 {
			prev = trimASCIIWhitespaceLinearGo(out[len(out)-1])
		}
		if tr != "" && tr == prev && isStandaloneHttpLinkParagraphGo(tr) {
			changed = true
			continue
		}
		out = append(out, b)
	}
	if !changed {
		return prose
	}
	return strings.Join(out, "\n\n")
}

func escapePostStripProseFencesGo(s string) string {
	if !strings.Contains(s, "```") && !strings.Contains(s, "~~~") {
		return s
	}
	lines := strings.Split(s, "\n")
	changed := false
	for idx, pLine := range lines {
		if !strings.Contains(pLine, "```") && !strings.Contains(pLine, "~~~") {
			continue
		}
		prefixLen, _ := scanContainerPrefixLinearGo(pLine)
		q := prefixLen
		for q < len(pLine) && (pLine[q] == ' ' || pLine[q] == '\t') {
			q++
		}
		if q+3 <= len(pLine) {
			fc := pLine[q]
			if (fc == '`' || fc == '~') && pLine[q+1] == fc && pLine[q+2] == fc {
				fe := q + 3
				for fe < len(pLine) && pLine[fe] == fc {
					fe++
				}
				tail := pLine[fe:]
				if !(fc == '`' && strings.IndexByte(tail, '`') >= 0) {
					lines[idx] = pLine[:q] + strings.Repeat(`\`+string(fc), fe-q) + tail
					changed = true
				}
			}
		}
	}
	if !changed {
		return s
	}
	return strings.Join(lines, "\n")
}

func sanitizeProseSegmentGo(part, baseURL string, allowPdfPageMarkers bool, isLastSegment bool) string {
	if part == "" {
		return ""
	}
	hadLeadingNL := strings.HasPrefix(part, "\n")
	hadTrailingNL := !isLastSegment && strings.HasSuffix(part, "\n")
	firstDetached := escapeGfmTaskListCheckboxesLinearGo(detachBareUrlsFromCodeSpansLinearGo(part))
	proseWork := firstDetached

	// Strip JSX / MDX inline comments `{/* ... */}` linearly
	if strings.Contains(proseWork, "{/*") {
		var outJsx strings.Builder
		outJsx.Grow(len(proseWork))
		cur := 0
		for cur < len(proseWork) {
			rel := strings.Index(proseWork[cur:], "{/*")
			if rel < 0 {
				outJsx.WriteString(proseWork[cur:])
				break
			}
			start := cur + rel
			outJsx.WriteString(proseWork[cur:start])
			endRel := strings.Index(proseWork[start+3:], "*/}")
			if endRel < 0 {
				outJsx.WriteString(proseWork[start:])
				break
			}
			cur = start + 3 + endRel + 3
		}
		proseWork = outJsx.String()
	}

	var inlineCodeStash []string
	if (strings.IndexByte(proseWork, '<') >= 0 && (strings.IndexByte(proseWork, '>') >= 0 || strings.Contains(proseWork, "<!--"))) ||
		strings.Contains(proseWork, ":::") ||
		strings.IndexByte(proseWork, '&') >= 0 {
		proseWork = stashMarkdownInlineCodeSpansLinearGo(proseWork, &inlineCodeStash)
	}

	if strings.Contains(proseWork, "<!--") {
		proseWork = stripHtmlCommentsLinearGo(proseWork, allowPdfPageMarkers)
	}

	if strings.IndexByte(proseWork, '<') >= 0 && strings.IndexByte(proseWork, '>') >= 0 {
		proseWork = stripDangerousHTMLSubtreesGo(proseWork)
		if strings.IndexByte(proseWork, '<') >= 0 && strings.IndexByte(proseWork, '>') >= 0 {
			proseWork = stripHiddenAndChromeSubtreesGo(proseWork)
		}
	}

	if strings.Contains(proseWork, ":::") {
		proseWork = reAdmonitionDirectiveSanGo.ReplaceAllStringFunc(proseWork, func(m string) string {
			sub := reAdmonitionDirectiveSanGo.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			kindRaw := sub[1]
			kindLabel := strings.ToUpper(kindRaw[:1]) + strings.ToLower(kindRaw[1:])
			custom := strings.TrimSpace(sub[2])
			if custom != "" && !strings.EqualFold(custom, kindRaw) {
				return "\n\n**" + kindLabel + ": " + custom + "**\n\n"
			}
			return "\n\n**" + kindLabel + "**\n\n"
		})
		proseWork = reAdmonitionCloseSanGo.ReplaceAllString(proseWork, "")
	}

	if strings.IndexByte(proseWork, '<') >= 0 && strings.IndexByte(proseWork, '>') >= 0 {
		proseWork = convertInlineHTMLInProseGo(proseWork, baseURL, &inlineCodeStash)
	}

	if strings.IndexByte(proseWork, '&') >= 0 &&
		(strings.Contains(proseWork, "](") || strings.IndexByte(proseWork, '<') >= 0 || strings.Contains(proseWork, "]:")) {
		proseWork = sanitizeAndResolveMarkdownProseLinksLinearGo(proseWork, baseURL)
	}
	proseWork = decodeMarkdownEntitiesPreservingLtGo(proseWork)
	if len(inlineCodeStash) > 0 {
		proseWork = restoreMarkdownInlineCodeStashGo(proseWork, inlineCodeStash)
	}
	proseWork = stripInvisibleSmugglingCharsGo(proseWork)
	if strings.IndexByte(proseWork, '?') >= 0 && strings.Contains(asciiLowerExtractString(proseWork), "helpful?") {
		proseWork = reHelpfulPromptSanGo.ReplaceAllString(proseWork, "\n")
	}
	if isLastSegment {
		tailStart := len(proseWork) - 2000
		if tailStart < 0 {
			tailStart = 0
		}
		if rel := strings.LastIndex(asciiLowerExtractString(proseWork[tailStart:]), "\n## on this page"); rel >= 0 {
			absIdx := tailStart + rel
			if reOnThisPageTailSanGo.MatchString(proseWork[absIdx:]) {
				proseWork = proseWork[:absIdx]
			}
		}
	}
	var detached string
	if proseWork == firstDetached && len(inlineCodeStash) == 0 {
		detached = proseWork
	} else {
		detached = escapeGfmTaskListCheckboxesLinearGo(detachBareUrlsFromCodeSpansLinearGo(proseWork))
	}
	resolved := sanitizeAndResolveMarkdownProseLinksLinearGo(detached, baseURL)
	escaped := escapeAllResidualLtInProseLinearGo(resolved, allowPdfPageMarkers)
	fenceSafe := escapePostStripProseFencesGo(escaped)
	collapsed := collapseExcessBlankLinesGo(fenceSafe)
	hadTrailingBlankLine := !isLastSegment && strings.HasSuffix(part, "\n\n")
	if collapsed == "" {
		if hadTrailingBlankLine && hadLeadingNL {
			return "\n\n"
		}
		if hadLeadingNL || hadTrailingNL {
			return "\n"
		}
		return ""
	}
	if hadLeadingNL && !strings.HasPrefix(collapsed, "\n") {
		collapsed = "\n" + collapsed
	}
	if hadTrailingBlankLine {
		if !strings.HasSuffix(collapsed, "\n") {
			collapsed = collapsed + "\n\n"
		} else if !strings.HasSuffix(collapsed, "\n\n") {
			collapsed = collapsed + "\n"
		}
	} else if hadTrailingNL {
		if !strings.HasSuffix(collapsed, "\n") {
			collapsed = collapsed + "\n"
		} else if hadLeadingNL && len(part) >= 2 && collapsed == "\n" {
			collapsed = "\n\n"
		}
	}
	return collapsed
}

func stripInvisibleAndNUL(s string) string {
	return stripInvisibleSmugglingCharsGo(s)
}

// stripTagsInlineLinear strips HTML/XML tags in guaranteed O(N) time (<= 3N byte visits even on adversarial
// `<"*n` or `<'*n` without closing quotes, while respecting quoted `>` inside valid attributes like `<a href="x>y">`).
func stripTagsInlineLinear(input string) string {
	if input == "" {
		return ""
	}
	if strings.IndexByte(input, '<') < 0 || strings.IndexByte(input, '>') < 0 {
		unescaped := stripInvisibleSmugglingCharsGo(html.UnescapeString(input))
		return strings.Join(strings.Fields(unescaped), " ")
	}

	var sb strings.Builder
	sb.Grow(len(input))
	n := len(input)
	noCloseDouble := false
	noCloseSingle := false
	cachedPlainGt := -1
	i := 0

	for i < n {
		if input[i] != '<' {
			sb.WriteByte(input[i])
			i++
			continue
		}
		if i+1 >= n || !isHTMLTagStartByte(input[i+1]) {
			sb.WriteByte('<')
			i++
			continue
		}
		if noCloseDouble && noCloseSingle {
			if cachedPlainGt < i+1 {
				rel := strings.IndexByte(input[i+1:], '>')
				if rel < 0 {
					sb.WriteString(input[i:])
					break
				}
				cachedPlainGt = i + 1 + rel
			}
			sb.WriteByte(' ')
			i = cachedPlainGt + 1
			continue
		}

		j := i + 1
		var quote byte
		for j < n {
			c := input[j]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
			} else {
				if c == '"' && !noCloseDouble {
					quote = '"'
				} else if c == '\'' && !noCloseSingle {
					quote = '\''
				} else if c == '>' {
					break
				}
			}
			j++
		}
		if j < n && input[j] == '>' {
			sb.WriteByte(' ')
			i = j + 1
			continue
		}
		if quote == 0 {
			sb.WriteString(input[i:])
			break
		}
		if quote == '"' {
			noCloseDouble = true
		} else {
			noCloseSingle = true
		}
	}

	unescaped := stripInvisibleSmugglingCharsGo(html.UnescapeString(sb.String()))
	return strings.Join(strings.Fields(unescaped), " ")
}
