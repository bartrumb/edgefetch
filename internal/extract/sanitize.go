package extract

import (
	"html"
	"strings"
)

// SanitizeScrapedMeta strips NUL bytes, bidi/tag smuggling runes, control newlines,
// raw HTML tags, and dangerous link schemes from single-line metadata fields (Title, Description, Author).
func SanitizeScrapedMeta(s string) string {
	if s == "" {
		return ""
	}
	clean := stripInvisibleAndNUL(s)
	var sb strings.Builder
	sb.Grow(len(clean))
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if c == '\r' || c == '\n' || c == '\t' {
			sb.WriteByte(' ')
			continue
		}
		if c == '<' && i+1 < len(clean) && isHTMLTagStartByte(clean[i+1]) {
			sb.WriteString("&lt;")
			continue
		}
		sb.WriteByte(c)
	}
	res := neutralizeDangerousMarkdownLinks(sb.String())
	return strings.Join(strings.Fields(res), " ")
}

// SanitizeScrapedMarkdown removes NUL/smuggling code points, neutralizes javascript:/vbscript:/data:
// Markdown links outside fenced code blocks, and escapes dangerous raw HTML tags (<script>, <img onerror=...>, etc.)
// outside fenced and inline code spans (M6).
func SanitizeScrapedMarkdown(md string) string {
	if md == "" {
		return ""
	}
	clean := stripInvisibleAndNUL(strings.ReplaceAll(md, "\r\n", "\n"))
	lines := strings.Split(clean, "\n")
	inFence := false
	var fenceChar byte
	fenceLen := 0

	for idx, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if len(trimmed) >= 3 && (trimmed[0] == '`' || trimmed[0] == '~') {
			ch := trimmed[0]
			run := 0
			for run < len(trimmed) && trimmed[run] == ch {
				run++
			}
			if run >= 3 {
				if !inFence {
					inFence = true
					fenceChar = ch
					fenceLen = run
					continue
				} else if ch == fenceChar && run >= fenceLen && strings.TrimSpace(trimmed[run:]) == "" {
					inFence = false
					fenceChar = 0
					fenceLen = 0
					continue
				}
			}
		}
		if inFence {
			continue
		}
		lines[idx] = sanitizeMarkdownProseLine(line)
	}
	return strings.Join(lines, "\n")
}

func isHTMLTagStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '/' || b == '!' || b == '?'
}

func sanitizeMarkdownProseLine(line string) string {
	if !strings.ContainsAny(line, "<]`:") {
		return line
	}
	// Walk outside inline code spans (`...`)
	var sb strings.Builder
	sb.Grow(len(line) + 8)
	n := len(line)
	i := 0
	for i < n {
		if line[i] == '`' && (i == 0 || line[i-1] != '\\') {
			tickRun := 0
			for i+tickRun < n && line[i+tickRun] == '`' {
				tickRun++
			}
			closeIdx := findMatchingBacktickRun(line, i+tickRun, tickRun)
			if closeIdx >= 0 {
				sb.WriteString(line[i : closeIdx+tickRun])
				i = closeIdx + tickRun
				continue
			}
			sb.WriteString(line[i : i+tickRun])
			i += tickRun
			continue
		}
		// Find next unescaped backtick
		segEnd := i + 1
		for segEnd < n {
			if line[segEnd] == '`' && line[segEnd-1] != '\\' {
				break
			}
			segEnd++
		}
		seg := neutralizeDangerousMarkdownLinks(line[i:segEnd])
		seg = escapeRawHTMLInProseSegment(seg)
		sb.WriteString(seg)
		i = segEnd
	}
	return sb.String()
}

func findMatchingBacktickRun(s string, from, wantRun int) int {
	n := len(s)
	i := from
	for i < n {
		idx := strings.IndexByte(s[i:], '`')
		if idx < 0 {
			return -1
		}
		pos := i + idx
		run := 0
		for pos+run < n && s[pos+run] == '`' {
			run++
		}
		if run == wantRun {
			return pos
		}
		i = pos + run
	}
	return -1
}

func escapeRawHTMLInProseSegment(seg string) string {
	if strings.IndexByte(seg, '<') < 0 {
		return seg
	}
	var sb strings.Builder
	sb.Grow(len(seg) + 8)
	for i := 0; i < len(seg); i++ {
		if seg[i] == '<' && i+1 < len(seg) && isHTMLTagStartByte(seg[i+1]) {
			sb.WriteString("&lt;")
			continue
		}
		sb.WriteByte(seg[i])
	}
	return sb.String()
}

func neutralizeDangerousMarkdownLinks(s string) string {
	// Neutralize inline `](javascript:...)`, `](vbscript:...)`, `](data:...)` and reference `]: javascript:...`
	lower := strings.ToLower(s)
	if !strings.Contains(lower, "javascript") && !strings.Contains(lower, "vbscript") && !strings.Contains(lower, "data:") && !strings.Contains(lower, "&#") && !strings.Contains(lower, "&colon") {
		return s
	}
	// Reference link definition: `^\s*(?:>\s*)*\[[^\]]+\]:\s*(javascript|vbscript|data):`
	trimmedRef := strings.TrimLeft(s, " \t>")
	if strings.HasPrefix(trimmedRef, "[") {
		if closeBr := strings.Index(trimmedRef, "]:"); closeBr > 1 {
			target := strings.TrimSpace(html.UnescapeString(trimmedRef[closeBr+2:]))
			if isDangerousSchemeTarget(target) {
				prefixLen := len(s) - len(trimmedRef) + closeBr + 2
				return s[:prefixLen] + " #"
			}
		}
	}

	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		idx := strings.Index(s[i:], "](")
		if idx < 0 {
			out.WriteString(s[i:])
			break
		}
		openParen := i + idx + 2
		out.WriteString(s[i:openParen])
		// Scan balanced parens for link destination
		depth := 1
		p := openParen
		for p < len(s) && depth > 0 {
			if s[p] == '\\' && p+1 < len(s) {
				p += 2
				continue
			}
			if s[p] == '(' {
				depth++
			} else if s[p] == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
			p++
		}
		if p < len(s) && depth == 0 {
			destRaw := s[openParen:p]
			if isDangerousSchemeTarget(html.UnescapeString(destRaw)) {
				out.WriteString("#)")
			} else {
				out.WriteString(destRaw)
				out.WriteByte(')')
			}
			i = p + 1
		} else {
			if isDangerousSchemeTarget(html.UnescapeString(s[openParen:])) {
				out.WriteByte('#')
				break
			}
			out.WriteString(s[openParen:])
			break
		}
	}
	return out.String()
}

func isDangerousSchemeTarget(raw string) bool {
	// Strip ASCII control/whitespace inside scheme
	var cleaned strings.Builder
	for i := 0; i < len(raw) && cleaned.Len() < 24; i++ {
		c := raw[i]
		if c <= 0x20 {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		cleaned.WriteByte(c)
	}
	head := cleaned.String()
	return strings.HasPrefix(head, "javascript:") || strings.HasPrefix(head, "vbscript:") || strings.HasPrefix(head, "data:")
}

func stripInvisibleAndNUL(s string) string {
	if s == "" {
		return ""
	}
	needsClean := false
	for _, r := range s {
		if r == 0 || (r >= 0xE0000 && r <= 0xE007F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			needsClean = true
			break
		}
	}
	if !needsClean {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if r == 0 || (r >= 0xE0000 && r <= 0xE007F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// stripTagsInlineLinear strips HTML/XML tags in guaranteed O(N) time (<= 3N byte visits even on adversarial
// `<"*n` or `<"*n` without closing quotes, while respecting quoted `>` inside valid attributes like `<a href="x>y">`).
func stripTagsInlineLinear(input string) string {
	if input == "" {
		return ""
	}
	if strings.IndexByte(input, '<') < 0 || strings.IndexByte(input, '>') < 0 {
		unescaped := html.UnescapeString(input)
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
		// Reached EOF without closing tag
		if quote == 0 {
			// Zero '>' left anywhere in input[i+1:]!
			sb.WriteString(input[i:])
			break
		}
		if quote == '"' {
			noCloseDouble = true
		} else {
			noCloseSingle = true
		}
		// Retry at same `i` with the unclosable quote disabled (happens at most twice total across the entire string!)
	}

	unescaped := html.UnescapeString(sb.String())
	return strings.Join(strings.Fields(unescaped), " ")
}
