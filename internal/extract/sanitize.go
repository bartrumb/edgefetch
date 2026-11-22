package extract

import (
	"html"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxSanitizeMarkdownScanBytes = 4 << 20 // 4 MiB linear scan cap

var dangerousSchemePrefixes = []string{
	"javascript:",
	"vbscript:",
	"data:",
	"file:",
	"blob:",
}

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
	res := sanitizeMarkdownProseBlock(sb.String())
	return strings.Join(strings.Fields(res), " ")
}

// SanitizeScrapedMarkdown removes NUL/smuggling code points, normalizes CRLF/CR line breaks idempotently,
// hardens CommonMark fenced code blocks (0..3 space indent, backtick info-string rule, container-dedent closure),
// tracks multi-line CommonMark inline code spans, neutralizes inline & reference links using dangerous URI schemes
// (`javascript:`, `vbscript:`, `data:`, `file:`, `blob:` including backslash/entity/whitespace/BOM obfuscation),
// neutralizes GFM task-list `<input>` checkboxes, and escapes raw HTML tags outside code spans/fences (R6-M6 / R7).
func SanitizeScrapedMarkdown(md string) string {
	if md == "" {
		return ""
	}
	if len(md) > maxSanitizeMarkdownScanBytes {
		cut := maxSanitizeMarkdownScanBytes
		for cut > 0 && !utf8.RuneStart(md[cut]) {
			cut--
		}
		md = md[:cut]
	}
	clean := normalizeMarkdownLineEndings(stripInvisibleAndNUL(md))
	segments := splitAndHardenMarkdownCodeFences(clean)
	for i := range segments {
		if segments[i].isCodeFence {
			segments[i].text = sanitizeCodeFenceHeader(segments[i].text)
		} else {
			segments[i].text = sanitizeMarkdownProseBlock(segments[i].text)
		}
	}
	var out strings.Builder
	total := 0
	for _, seg := range segments {
		total += len(seg.text)
	}
	out.Grow(total)
	for _, seg := range segments {
		out.WriteString(seg.text)
	}
	return out.String()
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

func isHTMLTagStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '/' || b == '!' || b == '?'
}

func isASCIIPunctByte(b byte) bool {
	return (b >= '!' && b <= '/') || (b >= ':' && b <= '@') || (b >= '[' && b <= '`') || (b >= '{' && b <= '~')
}

func isBackslashEscapedAt(s string, idx int) bool {
	bs := 0
	for p := idx - 1; p >= 0 && s[p] == '\\'; p-- {
		bs++
	}
	return (bs & 1) == 1
}

type mdSegment struct {
	text        string
	isCodeFence bool
}

// measureQuoteAndIndent parses leading blockquote markers (`>`) and counts expanded indent columns after the last `>`.
func measureQuoteAndIndent(line string) (quoteDepth int, indentCols int, contentPos int, isBlank bool) {
	i := 0
	cols := 0
	n := len(line)
	for i < n {
		// Up to 3 spaces before '>'
		spaces := 0
		j := i
		for j < n && line[j] == ' ' && spaces < 4 {
			spaces++
			j++
		}
		if spaces <= 3 && j < n && line[j] == '>' {
			quoteDepth++
			i = j + 1
			if i < n && line[i] == ' ' {
				i++
			} else if i < n && line[i] == '\t' {
				i++
			}
			cols = 0
			continue
		}
		break
	}
	for i < n {
		if line[i] == ' ' {
			cols++
			i++
		} else if line[i] == '\t' {
			cols += 4 - (cols % 4)
			i++
		} else {
			break
		}
	}
	return quoteDepth, cols, i, i >= n
}

func detectListMarkerContentCols(line string, baseCols int, contentPos int) (listContentCols int, ok bool) {
	if baseCols > 3 || contentPos >= len(line) {
		return 0, false
	}
	rem := line[contentPos:]
	c := rem[0]
	markerLen := 0
	if c == '-' || c == '*' || c == '+' {
		if len(rem) >= 2 && (rem[1] == ' ' || rem[1] == '\t') {
			markerLen = 1
		}
	} else if c >= '0' && c <= '9' {
		d := 0
		for d < len(rem) && d < 9 && rem[d] >= '0' && rem[d] <= '9' {
			d++
		}
		if d > 0 && d+1 < len(rem) && (rem[d] == '.' || rem[d] == ')') && (rem[d+1] == ' ' || rem[d+1] == '\t') {
			markerLen = d + 1
		}
	}
	if markerLen == 0 {
		return 0, false
	}
	cols := baseCols + markerLen
	p := contentPos + markerLen
	spacesAfter := 0
	for p < len(line) {
		if line[p] == ' ' {
			cols++
			spacesAfter++
			p++
		} else if line[p] == '\t' {
			step := 4 - (cols % 4)
			cols += step
			spacesAfter += step
			p++
		} else {
			break
		}
	}
	if p >= len(line) || spacesAfter > 4 {
		// CommonMark: empty list item or >4 spaces after marker uses marker + 1 space as content indent.
		return baseCols + markerLen + 1, true
	}
	return cols, true
}

func splitAndHardenMarkdownCodeFences(md string) []mdSegment {
	lines := strings.Split(md, "\n")
	var segments []mdSegment
	var curLines []string

	flush := func(isFence bool) {
		if len(curLines) == 0 {
			return
		}
		txt := strings.Join(curLines, "")
		curLines = curLines[:0]
		segments = append(segments, mdSegment{text: txt, isCodeFence: isFence})
	}

	inFence := false
	var fenceChar byte
	fenceLen := 0
	fenceQuoteDepth := 0
	fenceContainerCols := 0
	fenceCloseIndent := ""

	activeListCols := 0
	activeListQuote := 0

	for idx, line := range lines {
		hasTrailingNL := idx < len(lines)-1
		lineWithNL := line
		if hasTrailingNL {
			lineWithNL = line + "\n"
		}

		qDepth, indentCols, contentPos, isBlank := measureQuoteAndIndent(line)

		if inFence {
			// Check if blockquote or list container closed due to dedent!
			dedentedOutOfQuote := qDepth < fenceQuoteDepth
			dedentedOutOfList := !dedentedOutOfQuote && qDepth == fenceQuoteDepth && !isBlank && fenceContainerCols > 0 && indentCols < fenceContainerCols
			if dedentedOutOfQuote || dedentedOutOfList {
				// Emit explicit closing fence inside the code block before flushing so CommonMark parsers cannot keep the fence open!
				curLines = append(curLines, fenceCloseIndent+strings.Repeat(string(fenceChar), fenceLen)+"\n")
				flush(true)
				inFence = false
				fenceChar = 0
				fenceLen = 0
				fenceContainerCols = 0
				fenceQuoteDepth = 0
				fenceCloseIndent = ""
				if !isBlank && indentCols == 0 {
					activeListCols = 0
				}
				// Fall through to process `line` as normal prose/block!
			} else {
				// Check for explicit closing fence line
				if qDepth == fenceQuoteDepth && !isBlank && indentCols <= fenceContainerCols+3 {
					rem := line[contentPos:]
					if rem[0] == fenceChar {
						run := 0
						for run < len(rem) && rem[run] == fenceChar {
							run++
						}
						if run >= fenceLen && strings.Trim(rem[run:], " \t") == "" {
							curLines = append(curLines, lineWithNL)
							flush(true)
							inFence = false
							fenceChar = 0
							fenceLen = 0
							fenceContainerCols = 0
							fenceQuoteDepth = 0
							fenceCloseIndent = ""
							continue
						}
					}
				}
				curLines = append(curLines, lineWithNL)
				continue
			}
		}

		// Update active list container tracking in prose
		if !isBlank {
			if qDepth != activeListQuote || (activeListCols > 0 && indentCols < activeListCols) {
				activeListCols = 0
				activeListQuote = qDepth
			}
			if listCols, ok := detectListMarkerContentCols(line, indentCols, contentPos); ok {
				activeListCols = listCols
				activeListQuote = qDepth
			}
		}

		// Check if `line` opens a real CommonMark fenced code block:
		// Must be indented 0..3 columns relative to the active container (either top-level 0..3 or `activeListCols`..`activeListCols+3`).
		maxOpenCols := 3
		containerCols := 0
		if activeListCols > 0 && qDepth == activeListQuote && indentCols >= activeListCols && indentCols <= activeListCols+3 {
			maxOpenCols = activeListCols + 3
			containerCols = activeListCols
		}
		if !isBlank && indentCols <= maxOpenCols {
			rem := line[contentPos:]
			if len(rem) >= 3 && (rem[0] == '`' || rem[0] == '~') {
				ch := rem[0]
				run := 0
				for run < len(rem) && rem[run] == ch {
					run++
				}
				info := rem[run:]
				// CommonMark §4.5: backtick fence info strings CANNOT contain any backtick character!
				validInfo := ch != '`' || strings.IndexByte(info, '`') < 0
				if run >= 3 && validInfo {
					flush(false)
					inFence = true
					fenceChar = ch
					fenceLen = run
					fenceQuoteDepth = qDepth
					fenceContainerCols = containerCols
					fenceCloseIndent = line[:contentPos]
					curLines = append(curLines, lineWithNL)
					continue
				}
			}
		}

		curLines = append(curLines, lineWithNL)
	}

	if inFence {
		// Close unclosed EOF fence explicitly
		if len(curLines) > 0 && !strings.HasSuffix(curLines[len(curLines)-1], "\n") {
			curLines[len(curLines)-1] += "\n"
		}
		curLines = append(curLines, fenceCloseIndent+strings.Repeat(string(fenceChar), fenceLen))
		flush(true)
	} else {
		flush(false)
	}
	return segments
}

func sanitizeCodeFenceHeader(fenceSeg string) string {
	nl := strings.IndexByte(fenceSeg, '\n')
	head := fenceSeg
	rest := ""
	if nl >= 0 {
		head = fenceSeg[:nl]
		rest = fenceSeg[nl:]
	}
	if strings.IndexByte(head, '<') >= 0 {
		head = strings.ReplaceAll(head, "<", "&lt;")
	}
	return head + rest
}

func isIgnorableSchemeRune(r rune) bool {
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

// decodeURIEntitiesForScheme decodes named HTML entities (`&Tab;`, `&NewLine;`, `&colon;`, `&amp;`) and decimal/hex
// numeric character references WITH OR WITHOUT trailing semicolons (`&#58`, `&#x3a`, `&#0000106;`).
func decodeURIEntitiesForScheme(s string) string {
	cur := s
	for pass := 0; pass < 3; pass++ {
		if strings.IndexByte(cur, '&') < 0 {
			break
		}
		next := decodeURIEntitiesSinglePass(html.UnescapeString(cur))
		if next == cur {
			break
		}
		cur = next
	}
	return cur
}

func decodeURIEntitiesSinglePass(s string) string {
	if strings.IndexByte(s, '&') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '&' && i+2 < len(s) && s[i+1] == '#' {
			p := i + 2
			isHex := false
			if p < len(s) && (s[p] == 'x' || s[p] == 'X') {
				isHex = true
				p++
			}
			startDigits := p
			for p < len(s) && p-startDigits < 12 {
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
			if p > startDigits {
				digits := s[startDigits:p]
				if p < len(s) && s[p] == ';' {
					p++
				}
				base := 10
				if isHex {
					base = 16
				}
				if code, err := strconv.ParseUint(digits, base, 32); err == nil && code > 0 && code <= 0x10FFFF {
					sb.WriteRune(rune(code))
					i = p
					continue
				} else if err == nil && code == 0 {
					i = p
					continue
				}
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

func unescapeMarkdownBackslashes(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && isASCIIPunctByte(s[i+1]) {
			sb.WriteByte(s[i+1])
			i++
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func hasDangerousURIScheme(rawHref string) bool {
	if rawHref == "" {
		return false
	}
	unesc := unescapeMarkdownBackslashes(rawHref)
	decoded := decodeURIEntitiesForScheme(unesc)

	var acc strings.Builder
	acc.Grow(24)
	for _, r := range decoded {
		if isIgnorableSchemeRune(r) {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		acc.WriteRune(r)
		if acc.Len() >= 24 {
			break
		}
	}
	head := acc.String()
	for _, pref := range dangerousSchemePrefixes {
		if strings.HasPrefix(head, pref) {
			return true
		}
	}

	// Block residual unparsed entity before '/', '?', '#' (e.g. obfuscated scheme entity).
	beforePath := decoded
	if cut := strings.IndexAny(decoded, "/?#"); cut >= 0 {
		beforePath = decoded[:cut]
	}
	if amp := strings.IndexByte(beforePath, '&'); amp >= 0 && strings.IndexByte(beforePath[amp:], ':') < 0 {
		// Check if `&...` looks like an HTML entity before path separator
		rest := beforePath[amp+1:]
		if len(rest) > 0 && (rest[0] == '#' || (rest[0] >= 'a' && rest[0] <= 'z') || (rest[0] >= 'A' && rest[0] <= 'Z')) {
			return true
		}
	}
	return false
}

// destinationStartsWithDangerousScheme checks if `s[from:]` begins with `javascript:`, `vbscript:`, `data:`, `file:`, or `blob:`
// after streaming backslash/HTML-entity/control/whitespace/BOM decoding, returning the end offset of the destination token when true.
func destinationStartsWithDangerousScheme(s string, from int, angle bool) (int, bool) {
	var acc []byte
	p := from
	steps := 0
	for p < len(s) && steps < 4096 {
		steps++
		c := s[p]
		var piece string
		if c == '\\' && p+1 < len(s) && isASCIIPunctByte(s[p+1]) {
			piece = s[p+1 : p+2]
			p += 2
		} else if c == '&' {
			windowEnd := p + 24
			if windowEnd > len(s) {
				windowEnd = len(s)
			}
			win := s[p:windowEnd]
			consumed := 0
			if len(win) >= 3 && win[1] == '#' {
				q := 2
				isHex := false
				if q < len(win) && (win[q] == 'x' || win[q] == 'X') {
					isHex = true
					q++
				}
				dStart := q
				for q < len(win) && q-dStart < 12 {
					ch := win[q]
					if isHex {
						if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
							break
						}
					} else if ch < '0' || ch > '9' {
						break
					}
					q++
				}
				if q > dStart {
					digits := win[dStart:q]
					if q < len(win) && win[q] == ';' {
						q++
					}
					base := 10
					if isHex {
						base = 16
					}
					if code, err := strconv.ParseUint(digits, base, 32); err == nil && code <= 0x10FFFF {
						if code > 0 {
							piece = string(rune(code))
						}
						consumed = q
					}
				}
			} else {
				semi := strings.IndexByte(win, ';')
				if semi > 1 && semi <= 18 {
					cand := win[:semi+1]
					dec := decodeURIEntitiesForScheme(cand)
					if dec != cand {
						piece = dec
						consumed = semi + 1
					}
				}
			}
			if consumed > 0 {
				p += consumed
			} else {
				piece = "&"
				p++
			}
		} else {
			if angle {
				if c == '>' || c == '\n' || c == '\r' {
					return 0, false
				}
			} else if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ')' {
				return 0, false
			}
			r, w := utf8.DecodeRuneInString(s[p:])
			piece = string(r)
			p += w
		}

		for _, r := range piece {
			if isIgnorableSchemeRune(r) {
				continue
			}
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			if r >= 0x80 {
				return 0, false
			}
			acc = append(acc, byte(r))
			cur := string(acc)
			viable := false
			for _, sc := range dangerousSchemePrefixes {
				if cur == sc {
					// Advance `p` to end of the destination token so caller can replace the whole token cleanly
					endTok := p
					if angle {
						for endTok < len(s) && s[endTok] != '>' && s[endTok] != '\n' {
							endTok++
						}
					} else {
						depth := 0
						for endTok < len(s) {
							ec := s[endTok]
							if ec == '\\' && endTok+1 < len(s) {
								endTok += 2
								continue
							}
							if ec == ' ' || ec == '\t' || ec == '\n' || ec == '\r' {
								break
							}
							if ec == '(' {
								depth++
							} else if ec == ')' {
								if depth == 0 {
									break
								}
								depth--
							}
							endTok++
						}
					}
					return endTok, true
				}
				if strings.HasPrefix(sc, cur) {
					viable = true
				}
			}
			if !viable {
				return 0, false
			}
		}
	}
	return 0, false
}

func isSafeAutolinkInner(inner string) bool {
	if len(inner) < 8 || len(inner) > 2048 {
		return false
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c <= 0x20 || c == '<' || c == '>' || c == '`' {
			return false
		}
	}
	low := asciiLowerExtractString(inner[:minInt(len(inner), 10)])
	if strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "ftp://") {
		return true
	}
	if strings.HasPrefix(low, "mailto:") {
		addr := inner[7:]
		at := strings.IndexByte(addr, '@')
		return at > 0 && strings.IndexByte(addr[at+1:], '.') > 0
	}
	return false
}

// precleanAutolinksTaskListsAndBareURLTicks normalizes `<https://...`>` autolink backticks to `%60`, strips `<javascript:...>`
// autolinks, detaches bare GFM URLs/emails glued to backticks, percent-encodes “ ` “ inside valid `](https://...)` destinations,
// and escapes GFM task-list checkboxes (`- [ ] ` -> `- \[ ] `) so `marked` never emits raw `<input>` elements.
func precleanAutolinksTaskListsAndBareURLTicks(prose string) string {
	lines := strings.Split(prose, "\n")
	changed := false

	for li, line := range lines {
		// 1. Neutralize GFM task-list `[ ]` / `[x]` / `[X]` right after a list marker (`- [ ] `, `* [x] `, `1. [ ] `).
		qDepth, indentCols, contentPos, isBlank := measureQuoteAndIndent(line)
		_ = qDepth
		if !isBlank && indentCols <= 3 {
			rem := line[contentPos:]
			markerEnd := 0
			if len(rem) >= 5 && (rem[0] == '-' || rem[0] == '*' || rem[0] == '+') && (rem[1] == ' ' || rem[1] == '\t') {
				markerEnd = 1
			} else if rem[0] >= '0' && rem[0] <= '9' {
				d := 0
				for d < len(rem) && d < 9 && rem[d] >= '0' && rem[d] <= '9' {
					d++
				}
				if d > 0 && d+1 < len(rem) && (rem[d] == '.' || rem[d] == ')') && (rem[d+1] == ' ' || rem[d+1] == '\t') {
					markerEnd = d + 1
				}
			}
			if markerEnd > 0 {
				ws := markerEnd
				for ws < len(rem) && (rem[ws] == ' ' || rem[ws] == '\t') {
					ws++
				}
				if ws+3 <= len(rem) && rem[ws] == '[' && (rem[ws+1] == ' ' || rem[ws+1] == 'x' || rem[ws+1] == 'X') && rem[ws+2] == ']' &&
					(ws+3 == len(rem) || rem[ws+3] == ' ' || rem[ws+3] == '\t') {
					absPos := contentPos + ws
					line = line[:absPos] + `\[` + line[absPos+1:]
					lines[li] = line
					changed = true
				}
			}
		}

		if !strings.ContainsAny(line, "<`") {
			continue
		}

		var sb strings.Builder
		last := 0
		i := 0
		for i < len(line) {
			c := line[i]
			// Angle-bracket autolinks `<...>`
			if c == '<' && i+3 < len(line) && !isBackslashEscapedAt(line, i) {
				gtLim := minInt(len(line), i+2049)
				gt := -1
				hasTick := false
				validAngle := true
				for p := i + 1; p < gtLim; p++ {
					pc := line[p]
					if pc == '>' {
						gt = p
						break
					}
					if pc <= 0x20 || pc == '<' {
						validAngle = false
						break
					}
					if pc == '`' {
						hasTick = true
					}
				}
				if validAngle && gt > i+2 {
					inner := line[i+1 : gt]
					if hasDangerousURIScheme(inner) {
						sb.WriteString(line[last:i])
						i = gt + 1
						last = i
						changed = true
						continue
					}
					low := asciiLowerExtractString(inner[:minInt(len(inner), 10)])
					if hasTick && (strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "ftp://") || strings.HasPrefix(low, "mailto:")) {
						sb.WriteString(line[last : i+1])
						sb.WriteString(strings.ReplaceAll(inner, "`", "%60"))
						sb.WriteByte('>')
						i = gt + 1
						last = i
						changed = true
						continue
					}
				}
			}

			// Percent-encode backticks inside safe `](https://...)` / `](http://...)` link destinations so `[a](https://ok.example/`)`
			// never desynchronizes CommonMark backtick code-span pairing!
			if c == ']' && i+2 < len(line) && line[i+1] == '(' && !isBackslashEscapedAt(line, i) {
				destStart := i + 2
				for destStart < len(line) && (line[destStart] == ' ' || line[destStart] == '\t') {
					destStart++
				}
				low := asciiLowerExtractString(line[destStart:minInt(len(line), destStart+10)])
				if strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "http://") {
					p := destStart
					depth := 0
					hasTick := false
					for p < len(line) && p-destStart < 2048 {
						pc := line[p]
						if pc == '\\' && p+1 < len(line) {
							p += 2
							continue
						}
						if pc <= 0x20 {
							break
						}
						if pc == '(' {
							depth++
						} else if pc == ')' {
							if depth == 0 {
								break
							}
							depth--
						} else if pc == '`' {
							hasTick = true
						}
						p++
					}
					if hasTick && depth == 0 && p < len(line) && line[p] == ')' {
						sb.WriteString(line[last:destStart])
						sb.WriteString(strings.ReplaceAll(line[destStart:p], "`", "%60"))
						sb.WriteByte(')')
						i = p + 1
						last = i
						changed = true
						continue
					}
				}
			}

			// Bare GFM URL (`https://`, `http://`, `ftp://`, `www.`) glued to a backtick: detach with a space!
			if (c == 'h' || c == 'H' || c == 'f' || c == 'F' || c == 'w' || c == 'W') &&
				(i == 0 || !isASCIIAlnumExtract(line[i-1])) {
				low := asciiLowerExtractString(line[i:minInt(len(line), i+12)])
				if strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "ftp://") ||
					(strings.HasPrefix(low, "www.") && len(low) >= 5 && isASCIIAlnumExtract(low[4])) {
					p := i + 4
					lim := minInt(len(line), i+2048)
					detachedAt := -1
					for p < lim {
						pc := line[p]
						if pc <= 0x20 || pc == '<' || pc == '>' {
							break
						}
						if pc == '`' {
							detachedAt = p
							break
						}
						p++
					}
					if detachedAt >= 0 {
						sb.WriteString(line[last:detachedAt])
						sb.WriteByte(' ')
						last = detachedAt
						i = detachedAt
						changed = true
					}
				}
			}

			// Glued email local-part (`a`b@c.com`) swallowing an opening backtick in `marked`
			if c == '`' && i > 0 && !isBackslashEscapedAt(line, i) {
				prev := line[i-1]
				if isASCIIAlnumExtract(prev) || prev == '.' || prev == '_' || prev == '+' || prev == '-' {
					tail := line[i+1 : minInt(len(line), i+128)]
					if looksLikeEmailDomainTail(tail) {
						sb.WriteString(line[last:i])
						sb.WriteByte(' ')
						last = i
						changed = true
					}
				}
			}
			i++
		}
		if last > 0 {
			sb.WriteString(line[last:])
			lines[li] = sb.String()
		}
	}

	if !changed {
		return prose
	}
	return strings.Join(lines, "\n")
}

func isASCIIAlnumExtract(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func looksLikeEmailDomainTail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at < 0 || at > 64 {
		return false
	}
	for i := 0; i < at; i++ {
		c := s[i]
		if c <= 0x20 || c == '`' || c == '<' || c == '>' {
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

func isParagraphBreakLine(line string, prevQuoteDepth int, hasPrev bool) (breaksBefore bool, breaksAfter bool, quoteDepth int, isBlank bool) {
	qDepth, indentCols, contentPos, blank := measureQuoteAndIndent(line)
	if blank {
		return true, true, qDepth, true
	}
	if hasPrev && qDepth != prevQuoteDepth {
		breaksBefore = true
	}
	rem := line[contentPos:]
	c := rem[0]
	if indentCols <= 3 {
		// ATX heading `# ...`
		if c == '#' {
			h := 0
			for h < len(rem) && rem[h] == '#' && h < 7 {
				h++
			}
			if h <= 6 && (h == len(rem) || rem[h] == ' ' || rem[h] == '\t') {
				return true, true, qDepth, false
			}
		}
		// Setext underline (`===` / `---`) or thematic break (`***`, `---`, `___`)
		if c == '=' || c == '-' || c == '*' || c == '_' {
			if isSetextOrThematicBreak(rem) {
				return true, true, qDepth, false
			}
		}
		// List item start
		if _, isList := detectListMarkerContentCols(line, indentCols, contentPos); isList {
			return true, false, qDepth, false
		}
	}
	return breaksBefore, false, qDepth, false
}

func isSetextOrThematicBreak(rem string) bool {
	trimmed := strings.TrimRight(rem, " \t")
	if trimmed == "" {
		return false
	}
	if trimmed[0] == '=' || trimmed[0] == '-' {
		allSame := true
		for i := 0; i < len(trimmed); i++ {
			if trimmed[i] != trimmed[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	ch := trimmed[0]
	if ch != '-' && ch != '*' && ch != '_' {
		return false
	}
	count := 0
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == ch {
			count++
		} else if trimmed[i] != ' ' && trimmed[i] != '\t' {
			return false
		}
	}
	return count >= 3
}

func sanitizeMarkdownProseBlock(prose string) string {
	if prose == "" {
		return ""
	}
	work := precleanAutolinksTaskListsAndBareURLTicks(prose)
	if !strings.ContainsAny(work, "<]`:") {
		return work
	}

	// Split into CommonMark paragraphs so multi-line code spans (`a\nb`, `- `a\n  b``, `> `a\n> b``),
	// multi-line inline links (`[x](\njavascript:...)`), and multi-line reference definitions (`[y]:\njavascript:...`)
	// are analyzed with 100% paragraph-accurate backtick pairing!
	lines := strings.Split(work, "\n")
	var outLines []string
	outLines = make([]string, 0, len(lines))

	pStart := 0
	for pStart < len(lines) {
		_, breaksAfter0, q0, blank0 := isParagraphBreakLine(lines[pStart], 0, false)
		if blank0 {
			outLines = append(outLines, lines[pStart])
			pStart++
			continue
		}
		pEnd := pStart + 1
		if !breaksAfter0 {
			prevQ := q0
			for pEnd < len(lines) {
				bBefore, bAfter, qCur, _ := isParagraphBreakLine(lines[pEnd], prevQ, true)
				if bBefore {
					break
				}
				prevQ = qCur
				pEnd++
				if bAfter {
					break
				}
			}
		}
		para := strings.Join(lines[pStart:pEnd], "\n")
		sanPara := sanitizeSingleMarkdownParagraph(para)
		outLines = append(outLines, sanPara)
		pStart = pEnd
	}

	return strings.Join(outLines, "\n")
}

func findClosingBacktickRunInParagraph(s string, from int, wantRun int, isTable bool) (closePos int, crossedPipe bool) {
	n := len(s)
	i := from
	for i < n {
		idx := strings.IndexByte(s[i:], '`')
		if idx < 0 {
			return -1, false
		}
		pos := i + idx
		run := 0
		for pos+run < n && s[pos+run] == '`' {
			run++
		}
		if run == wantRun {
			if isTable {
				for p := from; p < pos; p++ {
					if s[p] == '|' && !isBackslashEscapedAt(s, p) {
						return -1, true
					}
				}
			}
			return pos, false
		}
		i = pos + run
	}
	return -1, false
}

func sanitizeSingleMarkdownParagraph(para string) string {
	if !strings.ContainsAny(para, "<]`:") {
		return para
	}
	isTable := strings.Contains(para, "|")

	// Walk the paragraph separating real CommonMark inline code spans from prose slices.
	// Also track whether an unescaped `[` has appeared earlier in the paragraph: in `marked`, `[a `](javascript:...) `x`
	// parses the link BEFORE the code span, so if `sawUnescapedOpenBracket` is true we still inspect code spans for
	// `](dangerous)` / `]: dangerous`!
	var sb strings.Builder
	sb.Grow(len(para) + 16)
	n := len(para)
	i := 0
	sawOpenBracket := false
	poisonTicks := false

	for i < n {
		if !poisonTicks && para[i] == '`' && !isBackslashEscapedAt(para, i) {
			run := 0
			for i+run < n && para[i+run] == '`' {
				run++
			}
			closePos, crossedPipe := findClosingBacktickRunInParagraph(para, i+run, run, isTable)
			if closePos >= 0 {
				span := para[i : closePos+run]
				if sawOpenBracket && (strings.Contains(span, "](") || strings.Contains(span, "]:")) {
					span = neutralizeProseLinksAndRefs(span)
				}
				sb.WriteString(span)
				i = closePos + run
				continue
			}
			if crossedPipe {
				// GFM table parsers split at `|` while pure CommonMark parsers pair across `|`, desynchronizing all subsequent backticks!
				poisonTicks = true
			}
			sb.WriteString(para[i : i+run])
			i += run
			continue
		}

		// Advance until next potential unescaped backtick
		segStart := i
		for i < n {
			if !poisonTicks && para[i] == '`' && !isBackslashEscapedAt(para, i) {
				break
			}
			if para[i] == '[' && !isBackslashEscapedAt(para, i) {
				sawOpenBracket = true
			}
			// If an unparsed `](` precedes a later `` ` `` in this paragraph, stop trusting subsequent backtick spans!
			if para[i] == ']' && i+1 < n && para[i+1] == '(' && !isBackslashEscapedAt(para, i) {
				if strings.IndexByte(para[i+2:], '`') >= 0 {
					poisonTicks = true
				}
			}
			i++
		}
		proseSlice := para[segStart:i]
		proseSlice = neutralizeProseLinksAndRefs(proseSlice)
		proseSlice = escapeRawHTMLPreservingAutolinks(proseSlice)
		sb.WriteString(proseSlice)
	}

	return sb.String()
}

func skipOptionalRefNewlinePrefix(s string, pos int) (int, bool) {
	if pos >= len(s) || s[pos] != '\n' {
		return pos, false
	}
	p := pos + 1
	// Skip leading blockquote `>` / spaces / tabs on the continuation line
	qDepth, indentCols, contentPos, _ := measureQuoteAndIndent(s[p:])
	_ = qDepth
	_ = indentCols
	p += contentPos
	return p, true
}

// neutralizeProseLinksAndRefs neutralizes all dangerous inline destinations `](...)` (including multi-line `[x](\njavascript:...)`,
// angle-bracket `[x](<javascript:...>)`, and after unbalanced `[x](\)` / `[x]((`) AND all dangerous reference link definitions
// `[id]: ...` / `[id]:\n...` (including inside lists `- [id]: ...` / `1. [id]: ...` and blockquotes `> [id]:\n> ...`).
func neutralizeProseLinksAndRefs(s string) string {
	if !strings.Contains(s, "](") && !strings.Contains(s, "]:") {
		return s
	}

	var out strings.Builder
	out.Grow(len(s) + 8)
	n := len(s)
	i := 0
	last := 0

	for i < n {
		if s[i] == ']' && i+1 < n && !isBackslashEscapedAt(s, i) {
			nx := s[i+1]
			if nx == '(' {
				// Inline link/image destination after `](`
				k := i + 2
				for k < n && (s[k] == ' ' || s[k] == '\t' || s[k] == '\n') {
					if s[k] == '\n' {
						nextK, _ := skipOptionalRefNewlinePrefix(s, k)
						k = nextK
						continue
					}
					k++
				}
				if k < n {
					angle := s[k] == '<'
					checkStart := k
					if angle {
						checkStart = k + 1
					}
					// 1) Try balanced destination scan bounded to 2048 bytes (stops on unescaped whitespace/newline unless angle)
					tokEnd, isDang := scanLinkDestinationDanger(s, k, angle)
					if isDang {
						out.WriteString(s[last : i+2])
						out.WriteByte('#')
						if tokEnd < n && s[tokEnd] == ')' {
							out.WriteByte(')')
							i = tokEnd + 1
						} else {
							i = tokEnd
						}
						last = i
						continue
					}
					// 2) Streaming prefix check (catches unbalanced `[x](javascript:alert(1)` without closing `)`)
					if streamEnd, ok := destinationStartsWithDangerousScheme(s, checkStart, angle); ok {
						out.WriteString(s[last : i+2])
						out.WriteByte('#')
						if angle && streamEnd < n && s[streamEnd] == '>' {
							streamEnd++
						}
						// Also consume optional whitespace + closing `)`
						ws := streamEnd
						for ws < n && (s[ws] == ' ' || s[ws] == '\t' || s[ws] == '\n') {
							ws++
						}
						if ws < n && s[ws] == ')' {
							out.WriteByte(')')
							i = ws + 1
						} else {
							i = streamEnd
						}
						last = i
						continue
					}
				}
			} else if nx == ':' {
				// Reference link definition `]: dest` or `]:\n  dest`
				k := i + 2
				crossedNL := false
				for k < n && (s[k] == ' ' || s[k] == '\t') {
					k++
				}
				if k < n && s[k] == '\n' {
					crossedNL = true
					k, _ = skipOptionalRefNewlinePrefix(s, k)
				}
				if k < n {
					angle := s[k] == '<'
					checkStart := k
					if angle {
						checkStart = k + 1
					}
					tokEnd, isDang := scanLinkDestinationDanger(s, k, angle)
					if !isDang {
						if se, ok := destinationStartsWithDangerousScheme(s, checkStart, angle); ok {
							isDang = true
							tokEnd = se
							if angle && tokEnd < n && s[tokEnd] == '>' {
								tokEnd++
							}
						}
					}
					if isDang {
						out.WriteString(s[last : i+1])
						if crossedNL {
							// Break `]:` with `]\:` AND replace the dangerous destination with `#`
							out.WriteString(`\: #`)
						} else {
							out.WriteString(": #")
						}
						i = tokEnd
						last = i
						continue
					}
				}
			}
		}
		i++
	}

	if last == 0 {
		return s
	}
	out.WriteString(s[last:])
	return out.String()
}

func scanLinkDestinationDanger(s string, k int, angle bool) (endPos int, dangerous bool) {
	n := len(s)
	limit := minInt(n, k+2048)
	if angle {
		gt := -1
		for p := k + 1; p < limit; p++ {
			if s[p] == '\\' && p+1 < limit {
				p++
				continue
			}
			if s[p] == '>' {
				gt = p
				break
			}
			if s[p] == '<' || s[p] == '\n' {
				return 0, false
			}
		}
		if gt < 0 {
			return 0, false
		}
		rawDest := s[k+1 : gt]
		if !hasDangerousURIScheme(rawDest) {
			return 0, false
		}
		end := gt + 1
		end = consumeOptionalLinkTitle(s, end)
		return end, true
	}

	p := k
	depth := 0
	for p < limit {
		c := s[p]
		if c == '\\' && p+1 < limit {
			p += 2
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			break
		}
		if c == ']' && p+1 < limit && s[p+1] == '(' {
			// Do not swallow a subsequent `[y](...)` when an earlier `[x]((` had unbalanced parens!
			return 0, false
		}
		if c == '(' {
			depth++
			if depth > 4 {
				return 0, false
			}
		} else if c == ')' {
			if depth == 0 {
				break
			}
			depth--
		}
		p++
	}
	if p == k {
		return 0, false
	}
	rawDest := s[k:p]
	if !hasDangerousURIScheme(rawDest) {
		return 0, false
	}
	end := consumeOptionalLinkTitle(s, p)
	return end, true
}

func consumeOptionalLinkTitle(s string, pos int) int {
	n := len(s)
	ws := pos
	for ws < n && (s[ws] == ' ' || s[ws] == '\t' || s[ws] == '\n') {
		ws++
	}
	if ws > pos && ws < n && (s[ws] == '"' || s[ws] == '\'') {
		q := s[ws]
		lim := minInt(n, ws+512)
		for p := ws + 1; p < lim; p++ {
			if s[p] == '\\' {
				p++
				continue
			}
			if s[p] == q {
				after := p + 1
				for after < n && (s[after] == ' ' || s[after] == '\t' || s[after] == '\n') {
					after++
				}
				return after
			}
		}
	}
	return ws
}

func escapeRawHTMLPreservingAutolinks(seg string) string {
	if strings.IndexByte(seg, '<') < 0 {
		return seg
	}
	var sb strings.Builder
	sb.Grow(len(seg) + 8)
	n := len(seg)
	i := 0
	for i < n {
		if seg[i] == '<' && i+1 < n && isHTMLTagStartByte(seg[i+1]) {
			// Preserve clean CommonMark `<https://...>`, `<http://...>`, `<ftp://...>`, `<mailto:...>` autolinks
			next := seg[i+1]
			if next == 'h' || next == 'H' || next == 'f' || next == 'F' || next == 'm' || next == 'M' {
				gtLim := minInt(n, i+2049)
				if relGt := strings.IndexByte(seg[i+1:gtLim], '>'); relGt > 2 {
					inner := seg[i+1 : i+1+relGt]
					if isSafeAutolinkInner(inner) {
						sb.WriteString(seg[i : i+1+relGt+1])
						i += 1 + relGt + 1
						continue
					}
				}
			}
			sb.WriteString("&lt;")
			i++
			continue
		}
		sb.WriteByte(seg[i])
		i++
	}
	return sb.String()
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
// `<"*n` or `<'*n` without closing quotes, while respecting quoted `>` inside valid attributes like `<a href="x>y">`).
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

	unescaped := html.UnescapeString(sb.String())
	return strings.Join(strings.Fields(unescaped), " ")
}
