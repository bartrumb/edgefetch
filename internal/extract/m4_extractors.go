package extract

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var (
	reUKGPreloadedDeclHTML     = newLazyRegexp(`(?i)window\.__PRELOADED_STATE__\s*=`)
	rePaylocityPageDataDeclHTML = newLazyRegexp(`(?i)window\.pageData\s*=`)
	reGiantDisallowedPath       = newLazyRegexp(`(?i)/(?:shop|cart|comparison|account|apiproxy)(?:/|$|\?)`)
)

func caseInsensitiveFieldM4(obj map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := obj[k]; ok && v != nil {
			return v
		}
	}
	for objK, objV := range obj {
		if objV == nil {
			continue
		}
		for _, k := range keys {
			if strings.EqualFold(objK, k) {
				return objV
			}
		}
	}
	return nil
}

func strFieldM4(obj map[string]any, keys ...string) string {
	return strings.TrimSpace(jsonScalarToString(caseInsensitiveFieldM4(obj, keys...)))
}

func isSafePathSegmentM4(seg string) bool {
	return seg != "" && seg != "." && seg != ".."
}

func formatJobsBoardMarkdownAndRecordsM4(boardTitle string, rows []map[string]any) (string, []string, [][]string) {
	var links []string
	seenLink := make(map[string]bool)
	var tableRows [][]string
	for _, r := range rows {
		title := strFieldM4(r, "title")
		loc := strFieldM4(r, "location")
		if loc == "" {
			loc = "-"
		}
		posted := strFieldM4(r, "postedAt")
		if posted == "" {
			posted = "-"
		} else if len(posted) > 10 {
			posted = sliceRunesMax(posted, 10)
		}
		u := strFieldM4(r, "url", "applyUrl")
		if isSafePublicHTTPSFeedURL(u) && !seenLink[u] {
			seenLink[u] = true
			links = append(links, u)
		}
		titleCell := escapeTableCellM4(title)
		if isSafePublicHTTPSFeedURL(u) {
			titleCell = fmt.Sprintf("[%s](%s)", escapeTableCellM4(title), PercentEncodeUnsafeRecordURLChars(u))
		}
		tableRows = append(tableRows, []string{
			titleCell,
			escapeTableCellM4(loc),
			escapeTableCellM4(posted),
		})
	}
	var blocks []string
	blocks = append(blocks, "# "+escapeDeclMarkdownBrackets(SanitizeScrapedMeta(boardTitle)))
	if len(tableRows) > 0 {
		blocks = append(blocks, formatDeclarativeGFMTable([]string{"Role", "Location", "Posted"}, tableRows))
	}
	return strings.Join(blocks, "\n\n"), links, tableRows
}

func escapeMarkdownBracketsOnlyGo(s string) string {
	if !strings.ContainsAny(s, "[]") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		if s[i] == '[' || s[i] == ']' {
			bs := 0
			for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 0 {
				sb.WriteByte('\\')
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func escapeTableCellM4(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	s = escapeMarkdownBracketsOnlyGo(s)
	s = strings.ReplaceAll(s, "|", "\\|")
	bs := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		bs++
	}
	if bs%2 == 1 {
		s += `\`
	}
	return s
}

func formatPaylocityFeedJSONGo(rawBytes []byte, params map[string]string, origURL string) (*DeclarativeFormattedDoc, bool) {
	parsed, ok := decodeJSONWithNumbers(rawBytes)
	if !ok || parsed == nil {
		return nil, false
	}
	var rawJobs []any
	switch v := parsed.(type) {
	case map[string]any:
		if arr, okA := caseInsensitiveFieldM4(v, "jobs").([]any); okA {
			rawJobs = arr
		}
	case []any:
		rawJobs = v
	}
	if len(rawJobs) == 0 {
		return nil, false
	}
	var records []map[string]any
	for _, el := range rawJobs {
		if len(records) >= 250 {
			break
		}
		obj, okO := el.(map[string]any)
		if !okO {
			continue
		}
		title := SanitizeScrapedMeta(strFieldM4(obj, "title"))
		if title == "" {
			continue
		}
		rawJobID := strFieldM4(obj, "jobId", "id")
		jobID := SanitizeScrapedMeta(rawJobID)
		dept := SanitizeScrapedMeta(strFieldM4(obj, "department", "departmentName"))
		loc := SanitizeScrapedMeta(strFieldM4(obj, "locationName", "location"))
		posted := SanitizeScrapedMeta(strFieldM4(obj, "publishedDate", "postedDate", "createdDate"))
		if len(posted) > 10 {
			posted = sliceRunesMax(posted, 10)
		}
		jobURL := strFieldM4(obj, "jobUrl", "applyUrl", "url")
		if jobURL == "" && isSafePathSegmentM4(rawJobID) {
			jobURL = "https://recruiting.paylocity.com/Recruiting/Jobs/Details/" + encodePathPcharSegment(rawJobID)
		}
		desc := SanitizeScrapedMeta(stripTagsInlineLinear(strFieldM4(obj, "description", "summary")))
		comp := SanitizeScrapedMeta(strFieldM4(obj, "compensation", "salary"))
		rec := map[string]any{
			"title":  title,
			"source": "paylocity",
		}
		if jobID != "" {
			rec["id"] = jobID
		}
		if dept != "" {
			rec["department"] = dept
		}
		if loc != "" {
			rec["location"] = loc
			rec["locations"] = []string{loc}
		}
		if posted != "" {
			rec["postedAt"] = posted
		}
		if isSafePublicHTTPSFeedURL(jobURL) {
			rec["url"] = jobURL
			rec["applyUrl"] = jobURL
		}
		if desc != "" {
			rec["description"] = sliceRunesMax(desc, 1000)
		}
		if comp != "" {
			rec["compensation"] = comp
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		return nil, false
	}
	guid := params["guid"]
	boardTitle := "Paylocity Job Board"
	if guid != "" {
		boardTitle = fmt.Sprintf("Paylocity Job Board (%s)", guid)
	}
	boardTitle = SanitizeScrapedMeta(boardTitle)
	md, links, _ := formatJobsBoardMarkdownAndRecordsM4(boardTitle, records)
	total := len(rawJobs)
	ret := len(records)
	trunc := total > ret
	return &DeclarativeFormattedDoc{
		Title:     boardTitle,
		Markdown:  md,
		Links:     links,
		Records:   records,
		Total:     &total,
		Returned:  &ret,
		Truncated: &trunc,
	}, true
}

func isJSIdentStartM4(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' || b == '$'
}

func isJSIdentCharM4(b byte) bool {
	return isJSIdentStartM4(b) || (b >= '0' && b <= '9')
}

func isJSRegexPrefixByteM4(b byte) bool {
	switch b {
	case 0, '{', '[', '(', ',', ':', ';', '=', '!', '&', '|', '?', '+', '-', '*', '%', '^', '~', '<', '>':
		return true
	default:
		return false
	}
}

func isJSRegexKeywordM4(ident string) bool {
	switch ident {
	case "return", "typeof", "void", "delete", "in", "of", "throw", "case", "else", "do", "yield", "await", "new", "instanceof":
		return true
	default:
		return false
	}
}

func scanJSQuotedStringM4(src string, quotePos, limit int) int {
	quote := src[quotePos]
	i := quotePos + 1
	for i < limit {
		if src[i] == '\\' {
			if i+1 < limit {
				i += 2
			} else {
				return limit
			}
			continue
		}
		if src[i] == quote {
			return i + 1
		}
		i++
	}
	return limit
}

func scanJSRegexLiteralM4(src string, slashPos, limit int) (int, bool) {
	j := slashPos + 1
	inClass := false
	for j < limit {
		rc := src[j]
		if rc == '\n' || rc == '\r' {
			return 0, false
		}
		if rc == '\\' && j+1 < limit {
			j += 2
			continue
		}
		if rc == '[' {
			inClass = true
		} else if rc == ']' {
			inClass = false
		} else if rc == '/' && !inClass {
			j++
			for j < limit && ((src[j] >= 'a' && src[j] <= 'z') || (src[j] >= 'A' && src[j] <= 'Z')) {
				j++
			}
			return j, true
		}
		j++
	}
	return 0, false
}

func scanJSBacktickLiteralM4(src string, tickPos, limit int) int {
	i := tickPos + 1
	for i < limit {
		ch := src[i]
		if ch == '\\' {
			if i+1 < limit {
				i += 2
			} else {
				return limit
			}
			continue
		}
		if ch == '$' && i+1 < limit && src[i+1] == '{' {
			i += 2
			exprDepth := 1
			lastNonWS := byte('{')
			lastIdent := ""
			var parenStmtStack []bool
			stmtHeaderJustClosed := false
			for i < limit && exprDepth > 0 {
				ec := src[i]
				if ec == '"' || ec == '\'' {
					i = scanJSQuotedStringM4(src, i, limit)
					lastNonWS = ec
					lastIdent = ""
					stmtHeaderJustClosed = false
					continue
				}
				if ec == '`' {
					i = scanJSBacktickLiteralM4(src, i, limit)
					lastNonWS = '`'
					lastIdent = ""
					stmtHeaderJustClosed = false
					continue
				}
				if ec == '/' && i+1 < limit && src[i+1] == '/' {
					i += 2
					for i < limit && src[i] != '\n' {
						i++
					}
					continue
				}
				if ec == '/' && i+1 < limit && src[i+1] == '*' {
					i += 2
					for i+1 < limit && !(src[i] == '*' && src[i+1] == '/') {
						i++
					}
					if i+1 < limit {
						i += 2
					} else {
						i = limit
					}
					continue
				}
				if ec == '/' && (isJSRegexPrefixByteM4(lastNonWS) || isJSRegexKeywordM4(lastIdent) || (lastNonWS == ')' && stmtHeaderJustClosed)) {
					if end, ok := scanJSRegexLiteralM4(src, i, limit); ok {
						i = end
						lastNonWS = '/'
						lastIdent = ""
						stmtHeaderJustClosed = false
						continue
					}
				}
				if isJSIdentStartM4(ec) {
					j := i + 1
					for j < limit && isJSIdentCharM4(src[j]) {
						j++
					}
					ident := src[i:j]
					if lastNonWS != '.' {
						lastIdent = ident
					} else {
						lastIdent = ""
					}
					lastNonWS = ident[len(ident)-1]
					stmtHeaderJustClosed = false
					i = j
					continue
				}
				if ec == '(' {
					isStmt := lastIdent == "if" || lastIdent == "while" || lastIdent == "for" || lastIdent == "with"
					parenStmtStack = append(parenStmtStack, isStmt)
				} else if ec == ')' {
					if len(parenStmtStack) > 0 {
						stmtHeaderJustClosed = parenStmtStack[len(parenStmtStack)-1]
						parenStmtStack = parenStmtStack[:len(parenStmtStack)-1]
					} else {
						stmtHeaderJustClosed = false
					}
				} else if ec == '{' {
					exprDepth++
					stmtHeaderJustClosed = false
				} else if ec == '}' {
					exprDepth--
					stmtHeaderJustClosed = false
					if exprDepth == 0 {
						i++
						break
					}
				} else if ec != ' ' && ec != '\t' && ec != '\r' && ec != '\n' {
					stmtHeaderJustClosed = false
				}
				if ec != ' ' && ec != '\t' && ec != '\r' && ec != '\n' {
					lastNonWS = ec
					lastIdent = ""
				}
				i++
			}
			continue
		}
		if ch == '`' {
			return i + 1
		}
		i++
	}
	return limit
}

func appendNormalizedJSStringM4(out []byte, raw string, quotePos, endAfterQuote int) []byte {
	quote := raw[quotePos]
	if quote == '`' {
		// Decode template literal escapes into a Go string and marshal as JSON string.
		endInner := endAfterQuote
		if endInner > quotePos+1 && raw[endInner-1] == '`' {
			endInner--
		}
		var sb strings.Builder
		for i := quotePos + 1; i < endInner; {
			ch := raw[i]
			if ch == '\\' && i+1 < endInner {
				nx := raw[i+1]
				switch nx {
				case 'n':
					sb.WriteByte('\n')
					i += 2
				case 'r':
					sb.WriteByte('\r')
					i += 2
				case 't':
					sb.WriteByte('\t')
					i += 2
				case 'b':
					sb.WriteByte('\b')
					i += 2
				case 'f':
					sb.WriteByte('\f')
					i += 2
				case '\\', '`', '$', '\'', '"', '/':
					sb.WriteByte(nx)
					i += 2
				case 'x':
					if i+3 < endInner {
						if v, err := strconv.ParseUint(raw[i+2:i+4], 16, 8); err == nil {
							sb.WriteRune(rune(v))
							i += 4
							continue
						}
					}
					sb.WriteByte('x')
					i += 2
				case 'u':
					if i+2 < endInner && raw[i+2] == '{' {
						if closeRel := strings.IndexByte(raw[i+3:endInner], '}'); closeRel > 0 && closeRel <= 8 {
							if cp, err := strconv.ParseUint(raw[i+3:i+3+closeRel], 16, 32); err == nil && cp <= 0x10FFFF {
								sb.WriteRune(rune(cp))
								i += 4 + closeRel
								continue
							}
						}
					} else if i+5 < endInner {
						if v, err := strconv.ParseUint(raw[i+2:i+6], 16, 16); err == nil {
							sb.WriteRune(rune(v))
							i += 6
							continue
						}
					}
					sb.WriteByte('u')
					i += 2
				case '0':
					if i+2 >= endInner || raw[i+2] < '0' || raw[i+2] > '7' {
						sb.WriteByte(0)
						i += 2
						continue
					}
					val := uint64(0)
					j := i + 1
					for k := 0; k < 3 && j < endInner && raw[j] >= '0' && raw[j] <= '7'; k++ {
						nextVal := val*8 + uint64(raw[j]-'0')
						if nextVal > 255 {
							break
						}
						val = nextVal
						j++
					}
					sb.WriteByte(byte(val))
					i = j
				case '\r':
					if i+2 < endInner && raw[i+2] == '\n' {
						i += 3
					} else {
						i += 2
					}
				case '\n':
					i += 2
				default:
					sb.WriteByte(nx)
					i += 2
				}
				continue
			}
			sb.WriteByte(ch)
			i++
		}
		if enc, err := json.Marshal(sb.String()); err == nil {
			return append(out, enc...)
		}
		return append(out, `""`...)
	}

	endInner := endAfterQuote
	if endInner > quotePos+1 && raw[endInner-1] == quote {
		endInner--
	}
	out = append(out, '"')
	for i := quotePos + 1; i < endInner; {
		ch := raw[i]
		if ch == '\\' && i+1 < endInner {
			nx := raw[i+1]
			switch nx {
			case '\'':
				out = append(out, '\'')
				i += 2
			case '"':
				out = append(out, '\\', '"')
				i += 2
			case '\\', '/', 'b', 'f', 'n', 'r', 't':
				out = append(out, '\\', nx)
				i += 2
			case 'x':
				if i+3 < endInner && isHexByteM4(raw[i+2]) && isHexByteM4(raw[i+3]) {
					out = append(out, '\\', 'u', '0', '0', lowerHexByteM4(raw[i+2]), lowerHexByteM4(raw[i+3]))
					i += 4
				} else {
					out = append(out, 'x')
					i += 2
				}
			case 'u':
				if i+2 < endInner && raw[i+2] == '{' {
					if closeRel := strings.IndexByte(raw[i+3:endInner], '}'); closeRel > 0 && closeRel <= 8 {
						if cp, err := strconv.ParseUint(raw[i+3:i+3+closeRel], 16, 32); err == nil && cp <= 0x10FFFF {
							if cp <= 0xFFFF {
								out = append(out, '\\', 'u',
									hexDigitsM4[(cp>>12)&0xf],
									hexDigitsM4[(cp>>8)&0xf],
									hexDigitsM4[(cp>>4)&0xf],
									hexDigitsM4[cp&0xf],
								)
							} else {
								adj := cp - 0x10000
								hi := 0xD800 + (adj >> 10)
								lo := 0xDC00 + (adj & 0x3FF)
								out = append(out, '\\', 'u',
									hexDigitsM4[(hi>>12)&0xf],
									hexDigitsM4[(hi>>8)&0xf],
									hexDigitsM4[(hi>>4)&0xf],
									hexDigitsM4[hi&0xf],
									'\\', 'u',
									hexDigitsM4[(lo>>12)&0xf],
									hexDigitsM4[(lo>>8)&0xf],
									hexDigitsM4[(lo>>4)&0xf],
									hexDigitsM4[lo&0xf],
								)
							}
							i += 4 + closeRel
							continue
						}
					}
					out = append(out, 'u')
					i += 2
				} else if i+5 < endInner && isHexByteM4(raw[i+2]) && isHexByteM4(raw[i+3]) && isHexByteM4(raw[i+4]) && isHexByteM4(raw[i+5]) {
					out = append(out, '\\', 'u', raw[i+2], raw[i+3], raw[i+4], raw[i+5])
					i += 6
				} else {
					out = append(out, 'u')
					i += 2
				}
			case '0':
				if i+2 >= endInner || raw[i+2] < '0' || raw[i+2] > '7' {
					out = append(out, '\\', 'u', '0', '0', '0', '0')
					i += 2
				} else {
					val := uint64(0)
					j := i + 1
					for k := 0; k < 3 && j < endInner && raw[j] >= '0' && raw[j] <= '7'; k++ {
						nextVal := val*8 + uint64(raw[j]-'0')
						if nextVal > 255 {
							break
						}
						val = nextVal
						j++
					}
					out = append(out, '\\', 'u', '0', '0', hexDigitsM4[val>>4], hexDigitsM4[val&0x0f])
					i = j
				}
			case '\r':
				if i+2 < endInner && raw[i+2] == '\n' {
					i += 3
				} else {
					i += 2
				}
			case '\n':
				i += 2
			default:
				if nx < 0x20 {
					out = append(out, '\\', 'u', '0', '0', hexDigitsM4[nx>>4], hexDigitsM4[nx&0x0f])
				} else {
					out = append(out, nx)
				}
				i += 2
			}
			continue
		}
		if ch == '"' {
			out = append(out, '\\', '"')
		} else if ch == '\n' {
			out = append(out, '\\', 'n')
		} else if ch == '\r' {
			out = append(out, '\\', 'r')
		} else if ch == '\t' {
			out = append(out, '\\', 't')
		} else if ch < 0x20 {
			out = append(out, '\\', 'u', '0', '0', hexDigitsM4[ch>>4], hexDigitsM4[ch&0x0f])
		} else {
			out = append(out, ch)
		}
		i++
	}
	out = append(out, '"')
	return out
}

const hexDigitsM4 = "0123456789abcdef"

func isHexByteM4(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func lowerHexByteM4(b byte) byte {
	if b >= 'A' && b <= 'F' {
		return b + ('a' - 'A')
	}
	return b
}

func scanValidJSONNumberM4(raw string, pos, limit int) (int, bool) {
	i := pos
	if i < limit && raw[i] == '-' {
		i++
	}
	if i >= limit || raw[i] < '0' || raw[i] > '9' {
		return pos, false
	}
	if raw[i] == '0' {
		i++
		if i < limit && raw[i] >= '0' && raw[i] <= '9' {
			return pos, false
		}
	} else {
		for i < limit && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
	}
	if i < limit && raw[i] == '.' {
		i++
		if i >= limit || raw[i] < '0' || raw[i] > '9' {
			return pos, false
		}
		for i < limit && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
	}
	if i < limit && (raw[i] == 'e' || raw[i] == 'E') {
		i++
		if i < limit && (raw[i] == '+' || raw[i] == '-') {
			i++
		}
		if i >= limit || raw[i] < '0' || raw[i] > '9' {
			return pos, false
		}
		for i < limit && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
	}
	if i < limit && (isJSIdentCharM4(raw[i]) || raw[i] == '.') {
		return pos, false
	}
	return i, true
}

func skipJSValueExprM4(raw string, pos, limit int) int {
	depth := 0
	lastNonWS := byte(0)
	lastIdent := ""
	var parenStmtStack []bool
	stmtHeaderJustClosed := false
	i := pos
	for i < limit {
		ch := raw[i]
		if depth == 0 && (ch == ',' || ch == '}' || ch == ']') {
			return i
		}
		if ch == '"' || ch == '\'' {
			i = scanJSQuotedStringM4(raw, i, limit)
			lastNonWS = ch
			lastIdent = ""
			stmtHeaderJustClosed = false
			continue
		}
		if ch == '`' {
			i = scanJSBacktickLiteralM4(raw, i, limit)
			lastNonWS = '`'
			lastIdent = ""
			stmtHeaderJustClosed = false
			continue
		}
		if ch == '/' && i+1 < limit && raw[i+1] == '/' {
			i += 2
			for i < limit && raw[i] != '\n' {
				i++
			}
			continue
		}
		if ch == '/' && i+1 < limit && raw[i+1] == '*' {
			i += 2
			for i+1 < limit && !(raw[i] == '*' && raw[i+1] == '/') {
				i++
			}
			if i+1 < limit {
				i += 2
			} else {
				i = limit
			}
			continue
		}
		if ch == '/' && (isJSRegexPrefixByteM4(lastNonWS) || isJSRegexKeywordM4(lastIdent) || (lastNonWS == ')' && stmtHeaderJustClosed)) {
			if end, ok := scanJSRegexLiteralM4(raw, i, limit); ok {
				i = end
				lastNonWS = '/'
				lastIdent = ""
				stmtHeaderJustClosed = false
				continue
			}
		}
		if isJSIdentStartM4(ch) {
			j := i + 1
			for j < limit && isJSIdentCharM4(raw[j]) {
				j++
			}
			ident := raw[i:j]
			if lastNonWS != '.' {
				lastIdent = ident
			} else {
				lastIdent = ""
			}
			lastNonWS = ident[len(ident)-1]
			stmtHeaderJustClosed = false
			i = j
			continue
		}
		if ch == '(' {
			isStmt := lastIdent == "if" || lastIdent == "while" || lastIdent == "for" || lastIdent == "with"
			parenStmtStack = append(parenStmtStack, isStmt)
			depth++
			stmtHeaderJustClosed = false
		} else if ch == ')' {
			if len(parenStmtStack) > 0 {
				stmtHeaderJustClosed = parenStmtStack[len(parenStmtStack)-1]
				parenStmtStack = parenStmtStack[:len(parenStmtStack)-1]
			} else {
				stmtHeaderJustClosed = false
			}
			if depth > 0 {
				depth--
			}
		} else if ch == '{' || ch == '[' {
			depth++
			stmtHeaderJustClosed = false
		} else if ch == '}' || ch == ']' {
			if depth > 0 {
				depth--
			}
			stmtHeaderJustClosed = false
		} else if ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n' {
			stmtHeaderJustClosed = false
		}
		if ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n' {
			lastNonWS = ch
			lastIdent = ""
		}
		i++
	}
	return limit
}

func scanBalancedJSDelimitedM4(raw string, startPos int, openB, closeB byte, limit int) (int, bool) {
	if startPos < 0 || startPos >= limit || raw[startPos] != openB {
		return 0, false
	}
	depth := 1
	lastNonWS := openB
	lastIdent := ""
	var parenStmtStack []bool
	stmtHeaderJustClosed := false
	i := startPos + 1
	for i < limit {
		ch := raw[i]
		if ch == '"' || ch == '\'' {
			i = scanJSQuotedStringM4(raw, i, limit)
			lastNonWS = ch
			lastIdent = ""
			stmtHeaderJustClosed = false
			continue
		}
		if ch == '`' {
			i = scanJSBacktickLiteralM4(raw, i, limit)
			lastNonWS = '`'
			lastIdent = ""
			stmtHeaderJustClosed = false
			continue
		}
		if ch == '/' && i+1 < limit && raw[i+1] == '/' {
			i += 2
			for i < limit && raw[i] != '\n' {
				i++
			}
			continue
		}
		if ch == '/' && i+1 < limit && raw[i+1] == '*' {
			i += 2
			for i+1 < limit && !(raw[i] == '*' && raw[i+1] == '/') {
				i++
			}
			if i+1 < limit {
				i += 2
			} else {
				i = limit
			}
			continue
		}
		if ch == '/' && (isJSRegexPrefixByteM4(lastNonWS) || isJSRegexKeywordM4(lastIdent) || (lastNonWS == ')' && stmtHeaderJustClosed)) {
			if end, ok := scanJSRegexLiteralM4(raw, i, limit); ok {
				i = end
				lastNonWS = '/'
				lastIdent = ""
				stmtHeaderJustClosed = false
				continue
			}
		}
		if isJSIdentStartM4(ch) {
			j := i + 1
			for j < limit && isJSIdentCharM4(raw[j]) {
				j++
			}
			ident := raw[i:j]
			if lastNonWS != '.' {
				lastIdent = ident
			} else {
				lastIdent = ""
			}
			lastNonWS = ident[len(ident)-1]
			stmtHeaderJustClosed = false
			i = j
			continue
		}
		if ch == '(' {
			isStmt := lastIdent == "if" || lastIdent == "while" || lastIdent == "for" || lastIdent == "with"
			parenStmtStack = append(parenStmtStack, isStmt)
			stmtHeaderJustClosed = false
		} else if ch == ')' {
			if len(parenStmtStack) > 0 {
				stmtHeaderJustClosed = parenStmtStack[len(parenStmtStack)-1]
				parenStmtStack = parenStmtStack[:len(parenStmtStack)-1]
			} else {
				stmtHeaderJustClosed = false
			}
		} else if ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n' {
			stmtHeaderJustClosed = false
		}
		if ch == openB {
			depth++
		} else if ch == closeB {
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
		if ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n' {
			lastNonWS = ch
			lastIdent = ""
		}
		i++
	}
	return 0, false
}

func skipBalancedJSParensAndBlockM4(raw string, openParenPos, limit int) (int, bool) {
	if openParenPos < 0 || openParenPos >= limit || raw[openParenPos] != '(' {
		return 0, false
	}
	afterParens, okP := scanBalancedJSDelimitedM4(raw, openParenPos, '(', ')', limit)
	if !okP {
		return 0, false
	}
	i := afterParens
	for i < limit {
		b := raw[i]
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			i++
			continue
		}
		if b == '/' && i+1 < limit && raw[i+1] == '/' {
			i += 2
			for i < limit && raw[i] != '\n' {
				i++
			}
			continue
		}
		if b == '/' && i+1 < limit && raw[i+1] == '*' {
			i += 2
			for i+1 < limit && !(raw[i] == '*' && raw[i+1] == '/') {
				i++
			}
			if i+1 < limit {
				i += 2
			} else {
				i = limit
			}
			continue
		}
		break
	}
	if i >= limit || raw[i] != '{' {
		return 0, false
	}
	return scanBalancedJSDelimitedM4(raw, i, '{', '}', limit)
}

func normalizeJSObjectLiteralToJSONM4(raw string) string {
	out := make([]byte, 0, len(raw)+32)
	n := len(raw)
	skipWSAndComments := func(pos int) int {
		for pos < n {
			b := raw[pos]
			if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
				pos++
				continue
			}
			if b == '/' && pos+1 < n && raw[pos+1] == '/' {
				pos += 2
				for pos < n && raw[pos] != '\n' {
					pos++
				}
				continue
			}
			if b == '/' && pos+1 < n && raw[pos+1] == '*' {
				pos += 2
				for pos+1 < n && !(raw[pos] == '*' && raw[pos+1] == '/') {
					pos++
				}
				if pos+1 < n {
					pos += 2
				} else {
					pos = n
				}
				continue
			}
			break
		}
		return pos
	}

	type jsCtxFrameM4 struct {
		kind     byte
		isVal    bool
		outStart int
	}
	var ctxStack []jsCtxFrameM4
	lastNonWS := byte(0)
	expectValue := false
	computedCount := 0

	i := skipWSAndComments(0)
	if i < n && raw[i] != '{' && raw[i] != '[' {
		expectValue = true
	}

	for i < n {
		c := raw[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			out = append(out, c)
			i++
			continue
		}
		if c == '/' && i+1 < n && raw[i+1] == '/' {
			i += 2
			for i < n && raw[i] != '\n' {
				i++
			}
			out = append(out, ' ')
			continue
		}
		if c == '/' && i+1 < n && raw[i+1] == '*' {
			i += 2
			for i+1 < n && !(raw[i] == '*' && raw[i+1] == '/') {
				i++
			}
			if i+1 < n {
				i += 2
			} else {
				i = n
			}
			out = append(out, ' ')
			continue
		}

		if c == '}' || c == ']' {
			if len(ctxStack) >= 2 {
				top := ctxStack[len(ctxStack)-1]
				if top.isVal && ((top.kind == '{' && c == '}') || (top.kind == '[' && c == ']')) {
					k := skipWSAndComments(i + 1)
					if k < n && raw[k] != ',' && raw[k] != '}' && raw[k] != ']' {
						ctxStack = ctxStack[:len(ctxStack)-1]
						out = out[:top.outStart]
						out = append(out, "null"...)
						lastNonWS = 'l'
						expectValue = false
						i = skipJSValueExprM4(raw, i+1, n)
						continue
					}
				}
			}
			// Strip trailing comma if present right before closing bracket/brace
			end := len(out)
			for end > 0 && (out[end-1] == ' ' || out[end-1] == '\t' || out[end-1] == '\r' || out[end-1] == '\n') {
				end--
			}
			if end > 0 && out[end-1] == ',' {
				out = out[:end-1]
			}
			out = append(out, c)
			if len(ctxStack) > 0 {
				ctxStack = ctxStack[:len(ctxStack)-1]
			}
			lastNonWS = c
			expectValue = false
			i++
			continue
		}

		if expectValue {
			if c == '{' {
				ctxStack = append(ctxStack, jsCtxFrameM4{kind: '{', isVal: len(ctxStack) > 0, outStart: len(out)})
				out = append(out, '{')
				lastNonWS = '{'
				expectValue = false
				i++
				continue
			}
			if c == '[' {
				ctxStack = append(ctxStack, jsCtxFrameM4{kind: '[', isVal: len(ctxStack) > 0, outStart: len(out)})
				out = append(out, '[')
				lastNonWS = '['
				expectValue = true
				i++
				continue
			}
			if c == '"' || c == '\'' || c == '`' {
				var endPos int
				if c == '`' {
					endPos = scanJSBacktickLiteralM4(raw, i, n)
				} else {
					endPos = scanJSQuotedStringM4(raw, i, n)
				}
				k := skipWSAndComments(endPos)
				if k >= n || raw[k] == ',' || raw[k] == '}' || raw[k] == ']' {
					out = appendNormalizedJSStringM4(out, raw, i, endPos)
					i = endPos
				} else {
					out = append(out, "null"...)
					i = skipJSValueExprM4(raw, i, n)
				}
				lastNonWS = '"'
				expectValue = false
				continue
			}
			if c == '/' {
				if endPos, closed := scanJSRegexLiteralM4(raw, i, n); closed {
					k := skipWSAndComments(endPos)
					if k >= n || raw[k] == ',' || raw[k] == '}' || raw[k] == ']' {
						if enc, err := json.Marshal(raw[i:endPos]); err == nil {
							out = append(out, enc...)
							i = endPos
							lastNonWS = '"'
							expectValue = false
							continue
						}
					}
				}
				out = append(out, "null"...)
				i = skipJSValueExprM4(raw, i, n)
				lastNonWS = 'l'
				expectValue = false
				continue
			}
			if isJSIdentStartM4(c) {
				j := i + 1
				for j < n && isJSIdentCharM4(raw[j]) {
					j++
				}
				ident := raw[i:j]
				k := skipWSAndComments(j)
				if (ident == "true" || ident == "false" || ident == "null" || ident == "undefined") && (k >= n || raw[k] == ',' || raw[k] == '}' || raw[k] == ']') {
					if ident == "undefined" {
						out = append(out, "null"...)
					} else {
						out = append(out, ident...)
					}
					i = j
				} else {
					out = append(out, "null"...)
					i = skipJSValueExprM4(raw, i, n)
				}
				lastNonWS = 'l'
				expectValue = false
				continue
			}
			if c == '-' || (c >= '0' && c <= '9') {
				if numEnd, okNum := scanValidJSONNumberM4(raw, i, n); okNum {
					k := skipWSAndComments(numEnd)
					if k >= n || raw[k] == ',' || raw[k] == '}' || raw[k] == ']' {
						out = append(out, raw[i:numEnd]...)
						i = numEnd
						lastNonWS = raw[numEnd-1]
						expectValue = false
						continue
					}
				}
			}
			out = append(out, "null"...)
			i = skipJSValueExprM4(raw, i, n)
			lastNonWS = 'l'
			expectValue = false
			continue
		}

		// Non-value position: key or punctuation
		isObjKeyPos := (lastNonWS == '{' || lastNonWS == ',') && len(ctxStack) > 0 && ctxStack[len(ctxStack)-1].kind == '{'
		if isObjKeyPos && c == '.' && i+2 < n && raw[i+1] == '.' && raw[i+2] == '.' {
			spreadEnd := skipJSValueExprM4(raw, i+3, n)
			k := skipWSAndComments(spreadEnd)
			if k < n && raw[k] == ',' {
				i = k + 1
			} else {
				i = k
			}
			expectValue = false
			continue
		}
		appendComputedKey := func() {
			out = append(out, `"__computed_`...)
			out = strconv.AppendInt(out, int64(computedCount), 10)
			out = append(out, '"')
			computedCount++
		}
		if c == '"' || c == '\'' || c == '`' {
			var endPos int
			if c == '`' {
				endPos = scanJSBacktickLiteralM4(raw, i, n)
			} else {
				endPos = scanJSQuotedStringM4(raw, i, n)
			}
			out = appendNormalizedJSStringM4(out, raw, i, endPos)
			k := skipWSAndComments(endPos)
			if isObjKeyPos && k < n && raw[k] == '(' {
				if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k, n); okM {
					out = append(out, ":null"...)
					lastNonWS = 'l'
					expectValue = false
					i = methodEnd
					continue
				}
			}
			lastNonWS = '"'
			i = endPos
			continue
		}
		if c == '{' {
			ctxStack = append(ctxStack, jsCtxFrameM4{kind: '{', isVal: false, outStart: len(out)})
			out = append(out, '{')
			lastNonWS = '{'
			expectValue = false
			i++
			continue
		}
		if c == '[' {
			if isObjKeyPos {
				if bEnd, okB := scanBalancedJSDelimitedM4(raw, i, '[', ']', n); okB {
					k := skipWSAndComments(bEnd)
					if k < n && raw[k] == '(' {
						if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k, n); okM {
							appendComputedKey()
							out = append(out, ":null"...)
							lastNonWS = 'l'
							expectValue = false
							i = methodEnd
							continue
						}
					}
					appendComputedKey()
					lastNonWS = '"'
					i = bEnd
					continue
				}
			}
			ctxStack = append(ctxStack, jsCtxFrameM4{kind: '[', isVal: false, outStart: len(out)})
			out = append(out, '[')
			lastNonWS = '['
			expectValue = true
			i++
			continue
		}
		if c == '*' && isObjKeyPos {
			k := skipWSAndComments(i + 1)
			if k < n && isJSIdentStartM4(raw[k]) {
				j := k + 1
				for j < n && isJSIdentCharM4(raw[j]) {
					j++
				}
				k2 := skipWSAndComments(j)
				if k2 < n && raw[k2] == '(' {
					if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k2, n); okM {
						out = append(out, '"')
						out = append(out, raw[k:j]...)
						out = append(out, "\":null"...)
						lastNonWS = 'l'
						expectValue = false
						i = methodEnd
						continue
					}
				}
			} else if k < n && (raw[k] == '"' || raw[k] == '\'' || raw[k] == '`') {
				var endPos int
				if raw[k] == '`' {
					endPos = scanJSBacktickLiteralM4(raw, k, n)
				} else {
					endPos = scanJSQuotedStringM4(raw, k, n)
				}
				k2 := skipWSAndComments(endPos)
				if k2 < n && raw[k2] == '(' {
					if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k2, n); okM {
						out = appendNormalizedJSStringM4(out, raw, k, endPos)
						out = append(out, ":null"...)
						lastNonWS = 'l'
						expectValue = false
						i = methodEnd
						continue
					}
				}
			} else if k < n && raw[k] == '[' {
				if bEnd, okB := scanBalancedJSDelimitedM4(raw, k, '[', ']', n); okB {
					k2 := skipWSAndComments(bEnd)
					if k2 < n && raw[k2] == '(' {
						if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k2, n); okM {
							appendComputedKey()
							out = append(out, ":null"...)
							lastNonWS = 'l'
							expectValue = false
							i = methodEnd
							continue
						}
					}
				}
			}
		}
		if c >= '0' && c <= '9' && isObjKeyPos {
			j := i + 1
			for j < n {
				b := raw[j]
				if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') ||
					b == 'x' || b == 'X' || b == 'o' || b == 'O' || b == '.' || b == '_' {
					j++
					continue
				}
				if (b == '+' || b == '-') && (raw[j-1] == 'e' || raw[j-1] == 'E') {
					j++
					continue
				}
				break
			}
			k := skipWSAndComments(j)
			if k < n && raw[k] == ':' {
				out = append(out, '"')
				out = append(out, raw[i:j]...)
				out = append(out, '"')
				lastNonWS = '"'
				i = j
				continue
			}
		}
		if c == ':' {
			out = append(out, ':')
			lastNonWS = ':'
			if len(ctxStack) > 0 && ctxStack[len(ctxStack)-1].kind == '{' {
				expectValue = true
			}
			i++
			continue
		}
		if c == ',' {
			out = append(out, ',')
			lastNonWS = ','
			if len(ctxStack) > 0 && ctxStack[len(ctxStack)-1].kind == '[' {
				expectValue = true
			} else {
				expectValue = false
			}
			i++
			continue
		}
		if isJSIdentStartM4(c) {
			j := i + 1
			for j < n && isJSIdentCharM4(raw[j]) {
				j++
			}
			ident := raw[i:j]
			k := skipWSAndComments(j)
			if isObjKeyPos && k < n && raw[k] == ':' {
				out = append(out, '"')
				out = append(out, ident...)
				out = append(out, '"')
				lastNonWS = '"'
				i = j
				continue
			}
			if isObjKeyPos {
				if k < n && raw[k] == '(' {
					if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k, n); okM {
						out = append(out, '"')
						out = append(out, ident...)
						out = append(out, "\":null"...)
						lastNonWS = 'l'
						expectValue = false
						i = methodEnd
						continue
					}
				}
				if ident == "async" || ident == "get" || ident == "set" {
					mk := k
					if ident == "async" && mk < n && raw[mk] == '*' {
						mk = skipWSAndComments(mk + 1)
					}
					if mk < n && isJSIdentStartM4(raw[mk]) {
						j2 := mk + 1
						for j2 < n && isJSIdentCharM4(raw[j2]) {
							j2++
						}
						ident2 := raw[mk:j2]
						k2 := skipWSAndComments(j2)
						if k2 < n && raw[k2] == '(' {
							if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k2, n); okM {
								out = append(out, '"')
								out = append(out, ident2...)
								out = append(out, "\":null"...)
								lastNonWS = 'l'
								expectValue = false
								i = methodEnd
								continue
							}
						}
					} else if mk < n && (raw[mk] == '"' || raw[mk] == '\'' || raw[mk] == '`') {
						var endPos int
						if raw[mk] == '`' {
							endPos = scanJSBacktickLiteralM4(raw, mk, n)
						} else {
							endPos = scanJSQuotedStringM4(raw, mk, n)
						}
						k2 := skipWSAndComments(endPos)
						if k2 < n && raw[k2] == '(' {
							if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k2, n); okM {
								out = appendNormalizedJSStringM4(out, raw, mk, endPos)
								out = append(out, ":null"...)
								lastNonWS = 'l'
								expectValue = false
								i = methodEnd
								continue
							}
						}
					} else if mk < n && raw[mk] == '[' {
						if bEnd, okB := scanBalancedJSDelimitedM4(raw, mk, '[', ']', n); okB {
							k2 := skipWSAndComments(bEnd)
							if k2 < n && raw[k2] == '(' {
								if methodEnd, okM := skipBalancedJSParensAndBlockM4(raw, k2, n); okM {
									appendComputedKey()
									out = append(out, ":null"...)
									lastNonWS = 'l'
									expectValue = false
									i = methodEnd
									continue
								}
							}
						}
					}
				}
				if k >= n || raw[k] == ',' || raw[k] == '}' {
					out = append(out, '"')
					out = append(out, ident...)
					out = append(out, "\":null"...)
					lastNonWS = 'l'
					expectValue = false
					i = j
					continue
				}
			}
			if ident == "undefined" && (lastNonWS == ':' || lastNonWS == '[' || lastNonWS == ',') && (k >= n || raw[k] != ':') {
				out = append(out, "null"...)
				lastNonWS = 'l'
				i = j
				continue
			}
			out = append(out, ident...)
			lastNonWS = ident[len(ident)-1]
			i = j
			continue
		}
		lastNonWS = c
		out = append(out, c)
		i++
	}
	return string(out)
}

func extractBalancedJSObjectAtM4(src string, startIdx, maxScanChars int) (string, int, bool) {
	if maxScanChars <= 0 {
		maxScanChars = 1_500_000
	}
	if startIdx < 0 {
		startIdx = 0
	}
	if startIdx >= len(src) {
		return "", 0, false
	}
	limit := len(src)
	if maxScanChars < limit-startIdx {
		limit = startIdx + maxScanChars
	}
	start := -1
	var openByte, closeByte byte
	for i := startIdx; i < limit; i++ {
		c := src[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '=' {
			continue
		}
		if c == '{' {
			start = i
			openByte = '{'
			closeByte = '}'
		} else if c == '[' {
			start = i
			openByte = '['
			closeByte = ']'
		}
		break
	}
	if start < 0 {
		return "", 0, false
	}

	depth := 0
	lastNonWS := byte(0)
	lastIdent := ""
	var parenStmtStack []bool
	stmtHeaderJustClosed := false
	for i := start; i < limit; {
		ch := src[i]
		if ch == '"' || ch == '\'' {
			i = scanJSQuotedStringM4(src, i, limit)
			lastNonWS = ch
			lastIdent = ""
			stmtHeaderJustClosed = false
			continue
		}
		if ch == '`' {
			i = scanJSBacktickLiteralM4(src, i, limit)
			lastNonWS = '`'
			lastIdent = ""
			stmtHeaderJustClosed = false
			continue
		}
		if ch == '/' && i+1 < limit && src[i+1] == '/' {
			i += 2
			for i < limit && src[i] != '\n' {
				i++
			}
			continue
		}
		if ch == '/' && i+1 < limit && src[i+1] == '*' {
			i += 2
			for i+1 < limit && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			if i+1 < limit {
				i += 2
			} else {
				i = limit
			}
			continue
		}
		if ch == '/' && (isJSRegexPrefixByteM4(lastNonWS) || isJSRegexKeywordM4(lastIdent) || (lastNonWS == ')' && stmtHeaderJustClosed)) {
			if end, ok := scanJSRegexLiteralM4(src, i, limit); ok {
				i = end
				lastNonWS = '/'
				lastIdent = ""
				stmtHeaderJustClosed = false
				continue
			}
		}
		if isJSIdentStartM4(ch) {
			j := i + 1
			for j < limit && isJSIdentCharM4(src[j]) {
				j++
			}
			ident := src[i:j]
			if lastNonWS != '.' {
				lastIdent = ident
			} else {
				lastIdent = ""
			}
			lastNonWS = ident[len(ident)-1]
			stmtHeaderJustClosed = false
			i = j
			continue
		}
		if ch == '(' {
			isStmt := lastIdent == "if" || lastIdent == "while" || lastIdent == "for" || lastIdent == "with"
			parenStmtStack = append(parenStmtStack, isStmt)
			stmtHeaderJustClosed = false
		} else if ch == ')' {
			if len(parenStmtStack) > 0 {
				stmtHeaderJustClosed = parenStmtStack[len(parenStmtStack)-1]
				parenStmtStack = parenStmtStack[:len(parenStmtStack)-1]
			} else {
				stmtHeaderJustClosed = false
			}
		} else if ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n' {
			stmtHeaderJustClosed = false
		}
		if ch == openByte {
			depth++
		} else if ch == closeByte {
			depth--
			if depth == 0 {
				return src[start : i+1], i + 1, true
			}
		}
		if ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n' {
			lastNonWS = ch
			lastIdent = ""
		}
		i++
	}
	return "", 0, false
}

func decodeJSOrJSONObjectM4(raw string) map[string]any {
	var state map[string]any
	if json.Unmarshal([]byte(raw), &state) == nil && state != nil {
		return state
	}
	norm := normalizeJSObjectLiteralToJSONM4(raw)
	if json.Unmarshal([]byte(norm), &state) == nil && state != nil {
		return state
	}
	return nil
}

func runUkgProHTMLExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	pathLow := strings.ToLower(ctx.path)
	if !strings.Contains(pathLow, "/jobboard") || strings.Contains(pathLow, "/jobboardview") {
		return nil
	}
	var records []map[string]any
	if loc := reUKGPreloadedDeclHTML.FindStringIndex(ctx.rawHTML); loc != nil {
		if balanced, _, okB := extractBalancedJSObjectAtM4(ctx.rawHTML, loc[1], 1_500_000); okB {
			if state := decodeJSOrJSONObjectM4(balanced); state != nil {
				if opps, okO := caseInsensitiveFieldM4(state, "opportunities", "jobs").([]any); okO {
					for _, el := range opps {
						if len(records) >= 250 {
							break
						}
						obj, okM := el.(map[string]any)
						if !okM {
							continue
						}
						title := SanitizeScrapedMeta(strFieldM4(obj, "Title", "title"))
						if title == "" {
							continue
						}
						id := SanitizeScrapedMeta(strFieldM4(obj, "Id", "id"))
						locStr := SanitizeScrapedMeta(strFieldM4(obj, "Location", "location", "Locations"))
						comp := SanitizeScrapedMeta(strFieldM4(obj, "Compensation", "compensation", "Salary", "salary"))
						posted := SanitizeScrapedMeta(strFieldM4(obj, "PostedDate", "postedDate", "postedAt"))
						if len(posted) > 10 {
							posted = sliceRunesMax(posted, 10)
						}
						applyURL := strFieldM4(obj, "ApplyUrl", "applyUrl", "Url", "url")
						if applyURL == "" {
							applyURL = ctx.baseURL
						}
						rec := map[string]any{
							"title":  title,
							"source": "ukg",
						}
						if id != "" {
							rec["id"] = id
						}
						if locStr != "" {
							rec["location"] = locStr
							rec["locations"] = []string{locStr}
						}
						if comp != "" {
							rec["compensation"] = comp
						}
						if posted != "" {
							rec["postedAt"] = posted
						}
						if isSafePublicHTTPSFeedURL(applyURL) {
							rec["url"] = applyURL
							rec["applyUrl"] = applyURL
						}
						records = append(records, rec)
					}
				}
			}
		}
	}
	if len(records) == 0 {
		return nil
	}
	doc := ParseHTMLDoc(ctx.rawHTML, 0)
	title := SanitizeScrapedMeta(strings.TrimSpace(doc.Text("h1")))
	if title == "" {
		title = SanitizeScrapedMeta(strings.TrimSpace(doc.Text("title")))
	}
	if title == "" {
		title = "UKG Pro Job Board"
	}
	md, links, _ := formatJobsBoardMarkdownAndRecordsM4(title, records)
	total := len(records)
	ret := len(records)
	trunc := false
	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Markdown:    md,
		Links:       links,
		Records:     records,
		Total:       &total,
		Returned:    &ret,
		Truncated:   &trunc,
	}
}

func runPaylocityHTMLExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	loc := rePaylocityPageDataDeclHTML.FindStringIndex(ctx.rawHTML)
	if loc == nil {
		return nil
	}
	balanced, _, okB := extractBalancedJSObjectAtM4(ctx.rawHTML, loc[1], 1_500_000)
	if !okB {
		return nil
	}
	state := decodeJSOrJSONObjectM4(balanced)
	if state == nil {
		return nil
	}
	rawJobs, okJ := caseInsensitiveFieldM4(state, "Jobs", "jobs").([]any)
	if !okJ || len(rawJobs) == 0 {
		return nil
	}
	var records []map[string]any
	for _, el := range rawJobs {
		if len(records) >= 250 {
			break
		}
		obj, okM := el.(map[string]any)
		if !okM {
			continue
		}
		title := SanitizeScrapedMeta(strFieldM4(obj, "Title", "title"))
		if title == "" {
			continue
		}
		rawJobID := strFieldM4(obj, "JobId", "jobId", "Id", "id")
		jobID := SanitizeScrapedMeta(rawJobID)
		locStr := SanitizeScrapedMeta(strFieldM4(obj, "LocationName", "locationName", "Location", "location"))
		posted := SanitizeScrapedMeta(strFieldM4(obj, "PublishedDate", "publishedDate", "PostedDate"))
		if len(posted) > 10 {
			posted = sliceRunesMax(posted, 10)
		}
		jobURL := strFieldM4(obj, "JobUrl", "jobUrl", "ApplyUrl", "applyUrl", "Url", "url")
		if jobURL == "" && isSafePathSegmentM4(rawJobID) {
			jobURL = "https://recruiting.paylocity.com/Recruiting/Jobs/Details/" + encodePathPcharSegment(rawJobID)
		}
		rec := map[string]any{
			"title":  title,
			"source": "paylocity",
		}
		if jobID != "" {
			rec["id"] = jobID
		}
		if locStr != "" {
			rec["location"] = locStr
			rec["locations"] = []string{locStr}
		}
		if posted != "" {
			rec["postedAt"] = posted
		}
		if isSafePublicHTTPSFeedURL(jobURL) {
			rec["url"] = jobURL
			rec["applyUrl"] = jobURL
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		return nil
	}
	doc := ParseHTMLDoc(ctx.rawHTML, 0)
	title := SanitizeScrapedMeta(strings.TrimSpace(doc.Text("h1")))
	if title == "" {
		title = SanitizeScrapedMeta(strings.TrimSpace(doc.Text("title")))
	}
	if title == "" {
		title = "Paylocity Job Board"
	}
	md, links, _ := formatJobsBoardMarkdownAndRecordsM4(title, records)
	total := len(records)
	ret := len(records)
	trunc := false
	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Markdown:    md,
		Links:       links,
		Records:     records,
		Total:       &total,
		Returned:    &ret,
		Truncated:   &trunc,
	}
}

func extractDoverLocationsM4(obj map[string]any) (string, []string) {
	var locs []string
	seen := make(map[string]bool)
	addLoc := func(raw string) {
		clean := SanitizeScrapedMeta(strings.TrimSpace(raw))
		if clean == "" || seen[clean] {
			return
		}
		seen[clean] = true
		locs = append(locs, clean)
	}
	if scalar := strFieldM4(obj, "location", "locationName"); scalar != "" {
		addLoc(scalar)
	}
	if rawLocs := caseInsensitiveFieldM4(obj, "locations"); rawLocs != nil {
		switch lv := rawLocs.(type) {
		case string:
			addLoc(lv)
		case []any:
			for _, el := range lv {
				switch item := el.(type) {
				case string:
					addLoc(item)
				case map[string]any:
					if nm := strFieldM4(item, "name", "location", "city", "label", "title"); nm != "" {
						addLoc(nm)
					}
				}
			}
		case map[string]any:
			if nm := strFieldM4(lv, "name", "location", "city", "label", "title"); nm != "" {
				addLoc(nm)
			}
		}
	}
	if len(locs) == 0 {
		return "", nil
	}
	return strings.Join(locs, "; "), locs
}

func extractDoverCompensationM4(obj map[string]any) string {
	if scalar := strFieldM4(obj, "compensation", "salary"); scalar != "" {
		return SanitizeScrapedMeta(scalar)
	}
	cMin := strFieldM4(obj, "compensation_min", "compensationMin", "salary_min", "salaryMin")
	cMax := strFieldM4(obj, "compensation_max", "compensationMax", "salary_max", "salaryMax")
	curr := strFieldM4(obj, "compensation_currency", "compensationCurrency", "currency")
	if cMin == "" && cMax == "" {
		if rawComp := caseInsensitiveFieldM4(obj, "compensation", "salary"); rawComp != nil {
			if cm, ok := rawComp.(map[string]any); ok {
				cMin = strFieldM4(cm, "min", "minValue", "minimum")
				cMax = strFieldM4(cm, "max", "maxValue", "maximum")
				if curr == "" {
					curr = strFieldM4(cm, "currency")
				}
			}
		}
	}
	if cMin == "" && cMax == "" {
		return ""
	}
	var rangeStr string
	switch {
	case cMin != "" && cMax != "":
		rangeStr = cMin + " - " + cMax
	case cMin != "":
		rangeStr = cMin + "+"
	default:
		rangeStr = "up to " + cMax
	}
	if curr != "" {
		return SanitizeScrapedMeta(curr + " " + rangeStr)
	}
	return SanitizeScrapedMeta(rangeStr)
}

func runDoverHTMLExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	inner, ok := findElementInnerLinearDeclHTML(ctx.rawHTML, "script", func(a string) bool {
		id, _ := getAttrValueLinearDeclHTML(a, "id")
		return id == "__NEXT_DATA__"
	}, 0)
	if !ok {
		return nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(inner)), &root); err != nil || root == nil {
		return nil
	}
	props, _ := caseInsensitiveFieldM4(root, "props").(map[string]any)
	pageProps, _ := caseInsensitiveFieldM4(props, "pageProps").(map[string]any)
	if pageProps == nil {
		return nil
	}
	companyName := ""
	companySlug := ""
	if coObj, okC := caseInsensitiveFieldM4(pageProps, "company").(map[string]any); okC {
		companyName = SanitizeScrapedMeta(strFieldM4(coObj, "name"))
		companySlug = strFieldM4(coObj, "slug")
	}
	if companySlug == "" && len(ctx.parts) >= 2 && strings.EqualFold(ctx.parts[0], "jobs") {
		companySlug = ctx.parts[1]
	}
	var rawJobs []any
	for _, key := range []string{"jobs", "jobPostings", "openRoles"} {
		if arr, okA := caseInsensitiveFieldM4(pageProps, key).([]any); okA && len(arr) > 0 {
			rawJobs = arr
			break
		}
	}
	if len(rawJobs) == 0 {
		return nil
	}
	var records []map[string]any
	for _, el := range rawJobs {
		if len(records) >= 250 {
			break
		}
		obj, okM := el.(map[string]any)
		if !okM {
			continue
		}
		title := SanitizeScrapedMeta(strFieldM4(obj, "title"))
		if title == "" {
			continue
		}
		id := SanitizeScrapedMeta(strFieldM4(obj, "id"))
		locStr, locList := extractDoverLocationsM4(obj)
		jobURL := strFieldM4(obj, "url", "applyUrl")
		if jobURL != "" && strings.HasPrefix(jobURL, "/") && !strings.HasPrefix(jobURL, "//") && ctx.u != nil {
			if ref, err := url.Parse(jobURL); err == nil {
				jobURL = ctx.u.ResolveReference(ref).String()
			}
		}
		if jobURL == "" {
			if slug := strFieldM4(obj, "slug"); isSafePathSegmentM4(slug) {
				if ctx.host == "app.dover.com" || (strings.HasSuffix(ctx.host, ".dover.com") && len(ctx.parts) >= 2 && strings.EqualFold(ctx.parts[0], "jobs")) {
					if isSafePathSegmentM4(companySlug) {
						jobURL = "https://app.dover.com/apply/" + encodePathPcharSegment(companySlug) + "/" + encodePathPcharSegment(slug)
					} else if companySlug == "" {
						jobURL = "https://app.dover.com/apply/" + encodePathPcharSegment(slug)
					}
				} else if ctx.u != nil {
					basePath := strings.TrimRight(ctx.u.Path, "/")
					jobURL = ctx.u.Scheme + "://" + ctx.u.Host + basePath + "/" + encodePathPcharSegment(slug)
				}
			}
		}
		if jobURL == "" {
			jobURL = ctx.baseURL
		}
		comp := extractDoverCompensationM4(obj)
		posted := SanitizeScrapedMeta(strFieldM4(obj, "postedAt", "publishedAt", "createdAt"))
		desc := SanitizeScrapedMeta(stripTagsInlineLinear(strFieldM4(obj, "description")))
		rec := map[string]any{
			"title":  title,
			"source": "dover",
		}
		if id != "" {
			rec["id"] = id
		}
		if companyName != "" {
			rec["company"] = companyName
		}
		if locStr != "" {
			rec["location"] = locStr
			rec["locations"] = locList
		}
		if comp != "" {
			rec["compensation"] = comp
		}
		if posted != "" {
			rec["postedAt"] = posted
		}
		if desc != "" {
			rec["description"] = sliceRunesMax(desc, 1000)
		}
		if isSafePublicHTTPSFeedURL(jobURL) {
			rec["url"] = jobURL
			rec["applyUrl"] = jobURL
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		return nil
	}
	boardTitle := "Dover Job Board"
	if companyName != "" {
		boardTitle = SanitizeScrapedMeta(fmt.Sprintf("%s — Dover Job Board (%d open roles)", companyName, len(records)))
	}
	md, links, _ := formatJobsBoardMarkdownAndRecordsM4(boardTitle, records)
	total := len(records)
	ret := len(records)
	trunc := false
	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       boardTitle,
		Markdown:    md,
		Links:       links,
		Records:     records,
		Total:       &total,
		Returned:    &ret,
		Truncated:   &trunc,
	}
}

func escapeMarkdownBracketsM4(s string) string {
	if s == "" {
		return ""
	}
	clean := neutralizeAllUnsafeMarkdownLinksLinearGo(s)
	return strings.NewReplacer("\r", " ", "\n", " ", "](", `\]\(`, "[", `\[`, "]", `\]`).Replace(clean)
}

func escapeMarkdownBlockM4(s string) string {
	out := strings.TrimSpace(escapeMarkdownBracketsM4(s))
	if strings.HasPrefix(out, "#") {
		out = `\` + out
	}
	return out
}

func runSitecoreJSSHTMLExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	inner, ok := findElementInnerLinearDeclHTML(ctx.rawHTML, "script", func(a string) bool {
		id, _ := getAttrValueLinearDeclHTML(a, "id")
		return id == "__NEXT_DATA__"
	}, 0)
	if !ok {
		return nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(inner)), &root); err != nil || root == nil {
		return nil
	}
	props, _ := caseInsensitiveFieldM4(root, "props").(map[string]any)
	pageProps, _ := caseInsensitiveFieldM4(props, "pageProps").(map[string]any)
	layoutData, _ := caseInsensitiveFieldM4(pageProps, "layoutData").(map[string]any)
	sitecore, _ := caseInsensitiveFieldM4(layoutData, "sitecore").(map[string]any)
	route, _ := caseInsensitiveFieldM4(sitecore, "route").(map[string]any)
	placeholders, _ := caseInsensitiveFieldM4(route, "placeholders").(map[string]any)
	if len(placeholders) == 0 {
		return nil
	}

	unwrapVal := func(fields map[string]any, key string) any {
		raw := caseInsensitiveFieldM4(fields, key)
		if raw == nil {
			return nil
		}
		if m, okM := raw.(map[string]any); okM {
			if val := caseInsensitiveFieldM4(m, "value"); val != nil {
				return val
			}
		}
		return raw
	}
	unwrapStr := func(fields map[string]any, keys ...string) string {
		for _, k := range keys {
			v := unwrapVal(fields, k)
			if s, okS := v.(string); okS && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
		return ""
	}
	toMD := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if strings.IndexByte(trimmed, '<') >= 0 && ctx.htmlToMD != nil {
			md, _ := ctx.htmlToMD(trimmed, ctx.baseURL)
			if strings.TrimSpace(md) != "" {
				return strings.TrimSpace(md)
			}
		}
		return stripTagsInlineLinear(trimmed)
	}
	toBodyMD := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if strings.IndexByte(trimmed, '<') >= 0 && ctx.htmlToMD != nil {
			md, _ := ctx.htmlToMD(trimmed, ctx.baseURL)
			if strings.TrimSpace(md) != "" {
				return strings.TrimSpace(md)
			}
		}
		return escapeMarkdownBlockM4(stripTagsInlineLinear(trimmed))
	}

	var links []string
	seenLink := make(map[string]bool)
	pushLink := func(href string) (string, bool) {
		trimmed := strings.TrimSpace(href)
		if trimmed == "" {
			return "", false
		}
		if strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "//") && ctx.u != nil {
			if ref, err := url.Parse(trimmed); err == nil {
				trimmed = ctx.u.ResolveReference(ref).String()
			}
		}
		if !isSafePublicHTTPSFeedURL(trimmed) {
			return "", false
		}
		if !seenLink[trimmed] {
			seenLink[trimmed] = true
			links = append(links, trimmed)
		}
		return trimmed, true
	}

	var docTitle string
	var blocks []string
	visited := 0

	var renderComponents func(arr []any, depth int)
	renderComponents = func(arr []any, depth int) {
		if depth > 6 || visited > 200 {
			return
		}
		for _, el := range arr {
			comp, okC := el.(map[string]any)
			if !okC {
				continue
			}
			visited++
			fields, _ := caseInsensitiveFieldM4(comp, "fields").(map[string]any)
			compName := strFieldM4(comp, "componentName")
			if fields != nil {
				if strings.EqualFold(compName, "PageTitle") {
					t := SanitizeScrapedMeta(toMD(unwrapStr(fields, "title", "heading")))
					sub := toBodyMD(unwrapStr(fields, "subtitle", "description"))
					if t != "" && docTitle == "" {
						docTitle = t
					} else if t != "" {
						blocks = append(blocks, "## "+escapeMarkdownBracketsM4(t))
					}
					if sub != "" {
						blocks = append(blocks, sub)
					}
				} else {
					heading := escapeMarkdownBracketsM4(SanitizeScrapedMeta(toMD(unwrapStr(fields, "heading", "title"))))
					body := toBodyMD(unwrapStr(fields, "content", "body", "text", "description"))
					if heading != "" {
						blocks = append(blocks, "## "+heading)
					}
					if body != "" {
						blocks = append(blocks, body)
					}
				}
				if items, okI := caseInsensitiveFieldM4(fields, "items").([]any); okI {
					for _, itemEl := range items {
						itemMap, okIM := itemEl.(map[string]any)
						if !okIM {
							continue
						}
						ih := escapeMarkdownBracketsM4(SanitizeScrapedMeta(toMD(unwrapStr(itemMap, "heading", "title"))))
						ib := toBodyMD(unwrapStr(itemMap, "body", "content", "text", "description"))
						if ih != "" && ib != "" {
							blocks = append(blocks, "### "+ih+"\n\n"+ib)
						} else if ih != "" {
							blocks = append(blocks, "### "+ih)
						} else if ib != "" {
							blocks = append(blocks, ib)
						}
					}
				}
				for _, linkKey := range []string{"ctaLink", "videoUrl", "link", "url"} {
					if lv, okL := unwrapVal(fields, linkKey).(map[string]any); okL {
						href := strFieldM4(lv, "href", "url")
						lText := strFieldM4(lv, "text", "title")
						if href != "" {
							if resolvedHref, okH := pushLink(href); okH && lText != "" {
								blocks = append(blocks, fmt.Sprintf("- [%s](%s)", escapeTableCellM4(lText), PercentEncodeUnsafeRecordURLChars(resolvedHref)))
							}
						}
					}
				}
			}
			if subPH, okPH := caseInsensitiveFieldM4(comp, "placeholders").(map[string]any); okPH {
				for _, pk := range sortedMapKeys(subPH) {
					if subArr, okSA := subPH[pk].([]any); okSA {
						renderComponents(subArr, depth+1)
					}
				}
			}
		}
	}

	if mainPH, okMain := caseInsensitiveFieldM4(placeholders, "storefront-main").([]any); okMain && len(mainPH) > 0 {
		renderComponents(mainPH, 0)
	}
	if len(blocks) == 0 && docTitle == "" {
		for _, pk := range sortedMapKeys(placeholders) {
			if strings.EqualFold(pk, "storefront-main") {
				continue
			}
			if arr, okA := placeholders[pk].([]any); okA && len(arr) > 0 {
				renderComponents(arr, 0)
			}
		}
	}
	if len(blocks) == 0 && docTitle == "" {
		return nil
	}
	docTitle = SanitizeScrapedMeta(docTitle)
	if docTitle == "" {
		doc := ParseHTMLDoc(ctx.rawHTML, 0)
		docTitle = SanitizeScrapedMeta(strings.TrimSpace(doc.Text("title")))
	}
	if docTitle == "" {
		docTitle = "NFPA Standard"
	}
	fullBlocks := append([]string{"# " + escapeMarkdownBracketsM4(docTitle)}, blocks...)
	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       docTitle,
		Markdown:    strings.Join(fullBlocks, "\n\n"),
		Links:       links,
	}
}

func runGiantLivHTMLExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	if reGiantDisallowedPath.MatchString(ctx.path) {
		return nil
	}
	doc := ParseHTMLDoc(ctx.rawHTML, 0)
	title := SanitizeScrapedMeta(strings.TrimSpace(doc.Text("main h1")))
	if title == "" {
		title = SanitizeScrapedMeta(strings.TrimSpace(doc.Text("h1")))
	}
	if title == "" {
		title = SanitizeScrapedMeta(strings.TrimSpace(doc.Text("title")))
	}
	if title == "" {
		return nil
	}

	var specLines []string
	for _, row := range doc.Select("#specifications li.datarow, ul.specifications li.datarow, li.datarow", 200) {
		lbl := strings.TrimSpace(row.Text(".label"))
		val := strings.TrimSpace(row.Text(".value"))
		if lbl != "" && val != "" {
			specLines = append(specLines, fmt.Sprintf("- **%s**: %s", escapeMarkdownBracketsM4(SanitizeScrapedMeta(lbl)), escapeMarkdownBracketsM4(SanitizeScrapedMeta(val))))
		}
	}

	var links []string
	var manualLinks []string
	seenLink := make(map[string]bool)
	isAllowedGiantLink := func(raw string) (string, bool) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			return "", false
		}
		if ctx.u != nil {
			if ref, err := url.Parse(trimmed); err == nil {
				trimmed = ctx.u.ResolveReference(ref).String()
			}
		}
		if !isSafePublicHTTPSFeedURL(trimmed) {
			return "", false
		}
		if reGiantDisallowedPath.MatchString(trimmed) {
			return "", false
		}
		return trimmed, true
	}

	var geometryMD string
	if geomTbl := doc.First("table.geometry"); geomTbl != nil && ctx.htmlToMD != nil {
		geomHTML := replacePairedHTMLElementsLinearFullDocGo(geomTbl.OuterHTML(), []string{"a"}, func(full, _, attrs, _ string) string {
			attrMap := parseTagAttrsFullDocGo(attrs)
			href := strings.TrimSpace(attrMap["href"])
			if href == "" || strings.HasPrefix(href, "#") {
				return full
			}
			if _, okAllowed := isAllowedGiantLink(href); !okAllowed {
				return ""
			}
			return full
		}, maxHTMLScanCharsFullDocGo, 16384)
		gmd, _ := ctx.htmlToMD(geomHTML, ctx.baseURL)
		geometryMD = strings.TrimSpace(gmd)
	}

	for _, a := range doc.Select("a[href]", 200) {
		href := a.AttrOrEmpty("href")
		resolved, okL := isAllowedGiantLink(href)
		if !okL || seenLink[resolved] {
			continue
		}
		seenLink[resolved] = true
		links = append(links, resolved)
		if strings.Contains(strings.ToLower(resolved), ".pdf") {
			label := strings.TrimSpace(a.Text())
			if label == "" {
				label = "Owner Manual (PDF)"
			}
			manualLinks = append(manualLinks, fmt.Sprintf("- [%s](%s)", escapeTableCellM4(label), PercentEncodeUnsafeRecordURLChars(resolved)))
		}
	}

	var blocks []string
	blocks = append(blocks, "# "+escapeMarkdownBracketsM4(title))
	if len(specLines) > 0 {
		blocks = append(blocks, "## Specifications\n\n"+strings.Join(specLines, "\n"))
	}
	if geometryMD != "" {
		blocks = append(blocks, "## Geometry\n\n"+geometryMD)
	}
	if len(manualLinks) > 0 {
		blocks = append(blocks, "## Manuals\n\n"+strings.Join(manualLinks, "\n"))
	}

	if len(specLines) == 0 && geometryMD == "" && len(manualLinks) == 0 {
		if mainEl := doc.First("main"); mainEl != nil && ctx.htmlToMD != nil {
			mainHTML := stripHTMLTagsLinearFullDocGo(mainEl.HTML(), []string{"nav", "footer", "header", "aside"}, "", maxHTMLScanCharsFullDocGo)
			mainHTML = replacePairedHTMLElementsLinearFullDocGo(mainHTML, []string{"a"}, func(full, _, attrs, _ string) string {
				attrMap := parseTagAttrsFullDocGo(attrs)
				href := strings.TrimSpace(attrMap["href"])
				if href == "" || strings.HasPrefix(href, "#") {
					return full
				}
				if _, okAllowed := isAllowedGiantLink(href); !okAllowed {
					return ""
				}
				return full
			}, maxHTMLScanCharsFullDocGo, 16384)
			mainMD, _ := ctx.htmlToMD(mainHTML, ctx.baseURL)
			cleaned := strings.TrimSpace(stripLeadingMarkdownH1Go(mainMD))
			if cleaned != "" {
				blocks = append(blocks, cleaned)
			}
		}
	} else if len(specLines) == 0 && geometryMD == "" {
		// Retain any non-list overview paragraphs inside <main> (excluding nav/footer/header/aside;
		// html_dom.go does not support :not() selectors, so filter via IsDescendantOf).
		var paras []string
		excludedChrome := doc.Select("main nav, main footer, main header, main aside", 100)
		for _, p := range doc.Select("main p", 100) {
			inChrome := false
			for _, ex := range excludedChrome {
				if p.IsDescendantOf(ex) {
					inChrome = true
					break
				}
			}
			if inChrome {
				continue
			}
			if txt := strings.TrimSpace(p.Text()); txt != "" {
				paras = append(paras, escapeMarkdownBlockM4(txt))
				if len(paras) >= 50 {
					break
				}
			}
		}
		if len(paras) > 0 {
			blocks = append(blocks, strings.Join(paras, "\n\n"))
		}
	}

	if len(blocks) <= 1 {
		return nil
	}
	return &DeclarativePostFetchResult{
		ExtractorID:  extractorID,
		Title:        title,
		Markdown:     strings.Join(blocks, "\n\n"),
		Links:        links,
		ReplaceLinks: true,
	}
}
