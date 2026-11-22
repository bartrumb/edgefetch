package extract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxYAMLBytes = 1 << 20 // 1 MiB manifest ceiling
	maxYAMLDepth = 32
)

type yamlLine struct {
	lineNo int
	indent int
	raw    string // original line without \r\n
	text   string // trimmed of leading spaces (inline comment stripped for non-scalar lines on demand)
	blank  bool
}

// ParseDeclarativeYAML parses a safe YAML 1.2 Core Schema subset into standard Go JSON-compatible values
// (`map[string]any`, `[]any`, `string`, `bool`, `json.Number`, `nil`).
// Explicitly rejects YAML anchors (`&`), aliases (`*`), merge keys (`<<`), custom tags (`!`), and tab indentation.
func ParseDeclarativeYAML(raw []byte) (any, error) {
	if len(raw) > maxYAMLBytes {
		return nil, fmt.Errorf("YAML manifest exceeds %d bytes", maxYAMLBytes)
	}
	s := strings.TrimPrefix(string(raw), "\ufeff")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	rawLines := strings.Split(s, "\n")

	lines := make([]yamlLine, 0, len(rawLines))
	for idx, ln := range rawLines {
		indent := 0
		for indent < len(ln) {
			if ln[indent] == ' ' {
				indent++
			} else if ln[indent] == '\t' {
				return nil, fmt.Errorf("yaml line %d: tab indentation is forbidden", idx+1)
			} else {
				break
			}
		}
		rest := ln[indent:]
		if rest == "" || rest[0] == '#' {
			lines = append(lines, yamlLine{lineNo: idx + 1, indent: indent, raw: ln, blank: true})
			continue
		}
		lines = append(lines, yamlLine{lineNo: idx + 1, indent: indent, raw: ln, text: rest})
	}

	p := &yamlParser{lines: lines}
	p.skipIgnorable()
	if p.pos < len(p.lines) && p.lines[p.pos].indent == 0 {
		cleanDoc := strings.TrimSpace(stripYAMLInlineComment(p.lines[p.pos].text))
		if cleanDoc == "---" {
			p.pos++
			p.skipIgnorable()
		} else if strings.HasPrefix(cleanDoc, "--- ") {
			return nil, fmt.Errorf("yaml line %d: directives/tags after --- are forbidden", p.lines[p.pos].lineNo)
		}
	}
	if p.pos >= len(p.lines) || p.isDocEnd(p.pos) {
		return nil, nil
	}

	val, err := p.parseNode(p.lines[p.pos].indent, 0)
	if err != nil {
		return nil, err
	}
	p.skipIgnorable()
	if p.pos < len(p.lines) && p.isDocEnd(p.pos) {
		p.pos++
		p.skipIgnorable()
	}
	if p.pos < len(p.lines) {
		return nil, fmt.Errorf("yaml line %d: unexpected trailing content (multi-document YAML is forbidden)", p.lines[p.pos].lineNo)
	}
	return val, nil
}

// YAMLToJSON converts a safe YAML document into canonical UTF-8 JSON bytes.
func YAMLToJSON(raw []byte) ([]byte, error) {
	v, err := ParseDeclarativeYAML(raw)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

type yamlParser struct {
	lines []yamlLine
	pos   int
}

func (p *yamlParser) skipIgnorable() {
	for p.pos < len(p.lines) && p.lines[p.pos].blank {
		p.pos++
	}
}

func (p *yamlParser) isDocEnd(idx int) bool {
	if idx >= len(p.lines) || p.lines[idx].blank || p.lines[idx].indent != 0 {
		return false
	}
	t := strings.TrimSpace(stripYAMLInlineComment(p.lines[idx].text))
	return t == "..." || t == "---"
}

func isYAMLSeqIndicator(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func (p *yamlParser) parseNode(expectedIndent, depth int) (any, error) {
	if depth > maxYAMLDepth {
		return nil, errors.New("yaml maximum nesting depth exceeded")
	}
	p.skipIgnorable()
	if p.pos >= len(p.lines) || p.isDocEnd(p.pos) {
		return nil, nil
	}
	ln := p.lines[p.pos]
	if ln.indent < expectedIndent {
		return nil, nil
	}
	clean := strings.TrimSpace(stripYAMLInlineComment(ln.text))
	if strings.HasPrefix(clean, "[") || strings.HasPrefix(clean, "{") {
		expr, err := p.collectFlowExpr(ln.indent)
		if err != nil {
			return nil, err
		}
		return parseYAMLFlowValue(expr, ln.lineNo, depth+1)
	}
	if isYAMLSeqIndicator(clean) || strings.HasPrefix(ln.text, "- ") {
		return p.parseBlockSeq(ln.indent, depth+1)
	}
	if findYAMLMappingColon(clean) >= 0 {
		return p.parseBlockMap(ln.indent, depth+1)
	}
	p.pos++
	return parseYAMLInlineScalarOrFlow(clean, ln.lineNo, depth+1)
}

func (p *yamlParser) parseBlockSeq(seqIndent, depth int) ([]any, error) {
	if depth > maxYAMLDepth {
		return nil, errors.New("yaml maximum nesting depth exceeded")
	}
	var out []any
	for {
		p.skipIgnorable()
		if p.pos >= len(p.lines) || p.isDocEnd(p.pos) {
			break
		}
		ln := p.lines[p.pos]
		if ln.indent < seqIndent {
			break
		}
		if ln.indent > seqIndent {
			return nil, fmt.Errorf("yaml line %d: unexpected indentation %d in sequence (expected %d)", ln.lineNo, ln.indent, seqIndent)
		}
		clean := strings.TrimSpace(stripYAMLInlineComment(ln.text))
		if !(clean == "-" || strings.HasPrefix(ln.text, "- ")) {
			break
		}

		if clean == "-" {
			p.pos++
			p.skipIgnorable()
			if p.pos >= len(p.lines) || p.isDocEnd(p.pos) || p.lines[p.pos].indent <= seqIndent {
				out = append(out, nil)
				continue
			}
			child, err := p.parseNode(p.lines[p.pos].indent, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, child)
			continue
		}

		// Line starts with "- ": compute exact column of first non-space character after '-'
		afterDashOffset := 1
		for afterDashOffset < len(ln.text) && ln.text[afterDashOffset] == ' ' {
			afterDashOffset++
		}
		itemIndent := seqIndent + afterDashOffset
		itemRaw := ln.text[afterDashOffset:]
		itemClean := strings.TrimSpace(stripYAMLInlineComment(itemRaw))

		if strings.HasPrefix(itemClean, "[") || strings.HasPrefix(itemClean, "{") {
			expr, err := p.collectInlineItemFlowExpr(itemClean, ln.lineNo, seqIndent)
			if err != nil {
				return nil, err
			}
			v, err := parseYAMLFlowValue(expr, ln.lineNo, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}

		if isYAMLSeqIndicator(itemClean) || strings.HasPrefix(itemRaw, "- ") {
			// Nested inline sequence `- - foo` — synthesize nested parse by rewriting current line temporarily
			savedPos := p.pos
			saved := p.lines[savedPos]
			p.lines[savedPos] = yamlLine{lineNo: ln.lineNo, indent: itemIndent, raw: ln.raw, text: itemRaw}
			nested, err := p.parseBlockSeq(itemIndent, depth+1)
			if err != nil {
				p.lines[savedPos] = saved
				return nil, err
			}
			out = append(out, nested)
			continue
		}

		if colonIdx := findYAMLMappingColon(itemClean); colonIdx >= 0 {
			p.pos++
			obj := make(map[string]any)
			if err := p.parseMapEntryInto(obj, itemClean, colonIdx, itemIndent, ln.lineNo, depth+1); err != nil {
				return nil, err
			}
			if err := p.parseBlockMapContinuation(obj, itemIndent, depth+1); err != nil {
				return nil, err
			}
			out = append(out, obj)
			continue
		}

		p.pos++
		v, err := parseYAMLInlineScalarOrFlow(itemClean, ln.lineNo, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (p *yamlParser) parseBlockMap(mapIndent, depth int) (map[string]any, error) {
	if depth > maxYAMLDepth {
		return nil, errors.New("yaml maximum nesting depth exceeded")
	}
	obj := make(map[string]any)
	if err := p.parseBlockMapContinuation(obj, mapIndent, depth); err != nil {
		return nil, err
	}
	return obj, nil
}

func (p *yamlParser) parseBlockMapContinuation(obj map[string]any, mapIndent, depth int) error {
	for {
		p.skipIgnorable()
		if p.pos >= len(p.lines) || p.isDocEnd(p.pos) {
			break
		}
		ln := p.lines[p.pos]
		if ln.indent < mapIndent {
			break
		}
		if ln.indent > mapIndent {
			return fmt.Errorf("yaml line %d: unexpected indentation %d in mapping (expected %d)", ln.lineNo, ln.indent, mapIndent)
		}
		clean := strings.TrimSpace(stripYAMLInlineComment(ln.text))
		if isYAMLSeqIndicator(clean) || strings.HasPrefix(ln.text, "- ") {
			break
		}
		colonIdx := findYAMLMappingColon(clean)
		if colonIdx < 0 {
			return fmt.Errorf("yaml line %d: expected key: value mapping entry, got %q", ln.lineNo, clean)
		}
		p.pos++
		if err := p.parseMapEntryInto(obj, clean, colonIdx, mapIndent, ln.lineNo, depth); err != nil {
			return err
		}
	}
	return nil
}

func (p *yamlParser) parseMapEntryInto(obj map[string]any, cleanLine string, colonIdx, mapIndent, lineNo, depth int) error {
	rawKey := strings.TrimSpace(cleanLine[:colonIdx])
	key, err := parseYAMLKey(rawKey, lineNo)
	if err != nil {
		return err
	}
	if key == "<<" {
		return fmt.Errorf("yaml line %d: YAML merge key '<<' is forbidden", lineNo)
	}
	if _, dup := obj[key]; dup {
		return fmt.Errorf("yaml line %d: duplicate YAML key %q", lineNo, key)
	}

	valPart := strings.TrimSpace(cleanLine[colonIdx+1:])
	if valPart == "" {
		p.skipIgnorable()
		if p.pos >= len(p.lines) || p.isDocEnd(p.pos) {
			obj[key] = nil
			return nil
		}
		next := p.lines[p.pos]
		nextClean := strings.TrimSpace(stripYAMLInlineComment(next.text))
		if next.indent > mapIndent {
			child, cErr := p.parseNode(next.indent, depth+1)
			if cErr != nil {
				return cErr
			}
			obj[key] = child
			return nil
		}
		if next.indent == mapIndent && (isYAMLSeqIndicator(nextClean) || strings.HasPrefix(next.text, "- ")) {
			child, cErr := p.parseBlockSeq(mapIndent, depth+1)
			if cErr != nil {
				return cErr
			}
			obj[key] = child
			return nil
		}
		obj[key] = nil
		return nil
	}

	if isBlockScalarHeader(valPart) {
		bs, bErr := p.parseBlockScalar(valPart, mapIndent, lineNo)
		if bErr != nil {
			return bErr
		}
		obj[key] = bs
		return nil
	}

	if strings.HasPrefix(valPart, "[") || strings.HasPrefix(valPart, "{") {
		expr, fErr := p.collectContinuationFlowExpr(valPart, lineNo, mapIndent)
		if fErr != nil {
			return fErr
		}
		v, vErr := parseYAMLFlowValue(expr, lineNo, depth+1)
		if vErr != nil {
			return vErr
		}
		obj[key] = v
		return nil
	}

	v, vErr := parseYAMLInlineScalarOrFlow(valPart, lineNo, depth+1)
	if vErr != nil {
		return vErr
	}
	obj[key] = v
	return nil
}

func isBlockScalarHeader(s string) bool {
	return s == "|" || s == "|-" || s == "|+" || s == ">" || s == ">-" || s == ">+"
}

func (p *yamlParser) parseBlockScalar(header string, parentIndent, lineNo int) (string, error) {
	folded := header[0] == '>'
	chomp := "clip"
	if len(header) == 2 {
		if header[1] == '-' {
			chomp = "strip"
		} else if header[1] == '+' {
			chomp = "keep"
		}
	}

	var collected []yamlLine
	blockIndent := -1
	scan := p.pos
	for scan < len(p.lines) {
		ln := p.lines[scan]
		if strings.TrimSpace(ln.raw) == "" {
			collected = append(collected, ln)
			scan++
			continue
		}
		if ln.indent <= parentIndent {
			break
		}
		if blockIndent < 0 {
			blockIndent = ln.indent
		}
		if ln.indent < blockIndent {
			return "", fmt.Errorf("yaml line %d: inconsistent block scalar indentation", ln.lineNo)
		}
		collected = append(collected, ln)
		scan++
	}
	p.pos = scan

	if blockIndent < 0 {
		if chomp == "keep" && len(collected) > 0 {
			return strings.Repeat("\n", len(collected)), nil
		}
		return "", nil
	}

	trailingBlanks := 0
	for len(collected) > 0 && strings.TrimSpace(collected[len(collected)-1].raw) == "" {
		trailingBlanks++
		collected = collected[:len(collected)-1]
	}

	contentLines := make([]string, len(collected))
	for i, ln := range collected {
		if len(ln.raw) >= blockIndent {
			contentLines[i] = ln.raw[blockIndent:]
		} else {
			contentLines[i] = ""
		}
	}

	var body string
	if !folded {
		body = strings.Join(contentLines, "\n")
	} else {
		var sb strings.Builder
		for i, cl := range contentLines {
			if i == 0 {
				sb.WriteString(cl)
				continue
			}
			prev := contentLines[i-1]
			prevIndented := len(prev) > 0 && prev[0] == ' '
			curIndented := len(cl) > 0 && cl[0] == ' '
			if cl == "" {
				sb.WriteByte('\n')
			} else if prev == "" {
				if i >= 2 && contentLines[i-2] == "" {
					// extra blank line already emitted a newline; ensure paragraph break
				} else {
					sb.WriteByte('\n')
				}
				sb.WriteString(cl)
			} else if prevIndented || curIndented {
				sb.WriteByte('\n')
				sb.WriteString(cl)
			} else {
				sb.WriteByte(' ')
				sb.WriteString(cl)
			}
		}
		body = sb.String()
	}

	_ = lineNo
	switch chomp {
	case "strip":
		return body, nil
	case "keep":
		return body + "\n" + strings.Repeat("\n", trailingBlanks), nil
	default: // clip
		return body + "\n", nil
	}
}

func (p *yamlParser) collectFlowExpr(minIndent int) (string, error) {
	startLine := p.lines[p.pos].lineNo
	first := strings.TrimSpace(stripYAMLInlineComment(p.lines[p.pos].text))
	p.pos++
	return p.collectContinuationFlowExpr(first, startLine, minIndent-1)
}

func (p *yamlParser) collectInlineItemFlowExpr(first string, startLine, seqIndent int) (string, error) {
	p.pos++
	return p.collectContinuationFlowExpr(first, startLine, seqIndent)
}

func (p *yamlParser) collectContinuationFlowExpr(initial string, startLine, parentIndent int) (string, error) {
	buf := initial
	for {
		bal, err := checkYAMLFlowBalance(buf, startLine)
		if err != nil {
			return "", err
		}
		if bal == 0 {
			return buf, nil
		}
		p.skipIgnorable()
		if p.pos >= len(p.lines) || p.lines[p.pos].indent <= parentIndent {
			return "", fmt.Errorf("yaml line %d: unclosed flow collection", startLine)
		}
		nextPart := strings.TrimSpace(stripYAMLInlineComment(p.lines[p.pos].text))
		p.pos++
		buf += " " + nextPart
	}
}

func canStartYAMLQuote(s string, i int) bool {
	if i == 0 {
		return true
	}
	prev := s[i-1]
	return prev == ' ' || prev == '\t' || prev == ':' || prev == '[' || prev == '{' || prev == ','
}

func checkYAMLFlowBalance(s string, lineNo int) (int, error) {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++
				continue
			}
			if quote == '\'' && c == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			if canStartYAMLQuote(s, i) {
				quote = c
			}
		case '[', '{':
			depth++
			if depth > maxYAMLDepth {
				return 0, fmt.Errorf("yaml line %d: flow nesting depth exceeded", lineNo)
			}
		case ']', '}':
			depth--
			if depth < 0 {
				return 0, fmt.Errorf("yaml line %d: mismatched closing '%c'", lineNo, c)
			}
		}
	}
	if quote != 0 {
		return 0, fmt.Errorf("yaml line %d: unclosed string quote", lineNo)
	}
	return depth, nil
}

func stripYAMLInlineComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++
				continue
			}
			if quote == '\'' && c == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if (c == '"' || c == '\'') && canStartYAMLQuote(s, i) {
			quote = c
			continue
		}
		if c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return s
}

func findYAMLMappingColon(s string) int {
	var quote byte
	flowDepth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++
				continue
			}
			if quote == '\'' && c == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			if canStartYAMLQuote(s, i) {
				quote = c
			}
		case '[', '{':
			flowDepth++
		case ']', '}':
			if flowDepth > 0 {
				flowDepth--
			}
		case ':':
			if flowDepth == 0 && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
				return i
			}
		}
	}
	return -1
}

func parseYAMLKey(rawKey string, lineNo int) (string, error) {
	if rawKey == "" {
		return "", fmt.Errorf("yaml line %d: empty mapping key", lineNo)
	}
	if rawKey[0] == '&' || rawKey[0] == '*' || rawKey[0] == '!' || rawKey[0] == '?' {
		return "", fmt.Errorf("yaml line %d: YAML anchors, aliases, complex keys, and tags are forbidden", lineNo)
	}
	var key string
	var err error
	if rawKey[0] == '"' || rawKey[0] == '\'' {
		key, err = parseYAMLQuotedString(rawKey, lineNo)
		if err != nil {
			return "", err
		}
	} else {
		key = rawKey
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] > 0x7e {
			return "", fmt.Errorf("yaml line %d: non-ASCII YAML key %q is forbidden", lineNo, key)
		}
	}
	return key, nil
}

func parseYAMLInlineScalarOrFlow(s string, lineNo, depth int) (any, error) {
	if depth > maxYAMLDepth {
		return nil, errors.New("yaml maximum nesting depth exceeded")
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '&' || trimmed[0] == '*' || trimmed[0] == '!' {
		return nil, fmt.Errorf("yaml line %d: YAML anchors, aliases, and tags are forbidden", lineNo)
	}
	if trimmed[0] == '[' || trimmed[0] == '{' {
		return parseYAMLFlowValue(trimmed, lineNo, depth+1)
	}
	if trimmed[0] == '"' || trimmed[0] == '\'' {
		return parseYAMLQuotedString(trimmed, lineNo)
	}
	switch trimmed {
	case "null", "Null", "NULL", "~":
		return nil, nil
	case "true", "True", "TRUE":
		return true, nil
	case "false", "False", "FALSE":
		return false, nil
	}
	if numNorm, okNum := parseYAMLCoreNumber(trimmed); okNum {
		return numNorm, nil
	}
	return trimmed, nil
}

func parseYAMLFlowValue(expr string, lineNo, depth int) (any, error) {
	if depth > maxYAMLDepth {
		return nil, errors.New("yaml maximum nesting depth exceeded")
	}
	trimmed := strings.TrimSpace(expr)
	if len(trimmed) < 2 {
		return nil, fmt.Errorf("yaml line %d: malformed flow value %q", lineNo, expr)
	}
	open := trimmed[0]
	closeCh := trimmed[len(trimmed)-1]
	if (open == '[' && closeCh != ']') || (open == '{' && closeCh != '}') {
		return nil, fmt.Errorf("yaml line %d: trailing characters after flow collection %q", lineNo, expr)
	}
	inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	if open == '[' {
		if inner == "" {
			return []any{}, nil
		}
		parts, err := splitYAMLFlowItems(inner, lineNo)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(parts))
		for _, part := range parts {
			pTrim := strings.TrimSpace(part)
			if pTrim == "" {
				continue
			}
			if pTrim[0] != '{' && pTrim[0] != '[' && pTrim[0] != '"' && pTrim[0] != '\'' && findYAMLMappingColon(pTrim) >= 0 {
				return nil, fmt.Errorf("yaml line %d: compact mapping inside flow sequence is forbidden (%q); wrap in {...}", lineNo, pTrim)
			}
			v, vErr := parseYAMLInlineScalarOrFlow(pTrim, lineNo, depth+1)
			if vErr != nil {
				return nil, vErr
			}
			out = append(out, v)
		}
		return out, nil
	}

	// Flow mapping '{ ... }'
	obj := make(map[string]any)
	if inner == "" {
		return obj, nil
	}
	parts, err := splitYAMLFlowItems(inner, lineNo)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		pTrim := strings.TrimSpace(part)
		if pTrim == "" {
			continue
		}
		colonIdx := findYAMLMappingColon(pTrim)
		if colonIdx < 0 {
			return nil, fmt.Errorf("yaml line %d: invalid flow mapping entry %q", lineNo, pTrim)
		}
		k, kErr := parseYAMLKey(strings.TrimSpace(pTrim[:colonIdx]), lineNo)
		if kErr != nil {
			return nil, kErr
		}
		if k == "<<" {
			return nil, fmt.Errorf("yaml line %d: YAML merge key '<<' is forbidden", lineNo)
		}
		if _, dup := obj[k]; dup {
			return nil, fmt.Errorf("yaml line %d: duplicate YAML key %q", lineNo, k)
		}
		vRaw := strings.TrimSpace(pTrim[colonIdx+1:])
		v, vErr := parseYAMLInlineScalarOrFlow(vRaw, lineNo, depth+1)
		if vErr != nil {
			return nil, vErr
		}
		obj[k] = v
	}
	return obj, nil
}

func splitYAMLFlowItems(inner string, lineNo int) ([]string, error) {
	var parts []string
	start := 0
	depth := 0
	var quote byte
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++
				continue
			}
			if quote == '\'' && c == '\'' && i+1 < len(inner) && inner[i+1] == '\'' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '[', '{':
			depth++
		case ']', '}':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("yaml line %d: unexpected '%c' in flow collection", lineNo, c)
			}
		case ',':
			if depth == 0 {
				parts = append(parts, inner[start:i])
				start = i + 1
			}
		}
	}
	if quote != 0 || depth != 0 {
		return nil, fmt.Errorf("yaml line %d: unclosed quote or bracket in flow collection", lineNo)
	}
	parts = append(parts, inner[start:])
	return parts, nil
}

func parseYAMLQuotedString(s string, lineNo int) (string, error) {
	if len(s) < 2 {
		return "", fmt.Errorf("yaml line %d: unclosed quoted string", lineNo)
	}
	q := s[0]
	if s[len(s)-1] != q {
		return "", fmt.Errorf("yaml line %d: unclosed or trailing text after quoted string %q", lineNo, s)
	}
	if q == '\'' {
		var sb strings.Builder
		inner := s[1 : len(s)-1]
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\'' {
				if i+1 < len(inner) && inner[i+1] == '\'' {
					sb.WriteByte('\'')
					i++
					continue
				}
				return "", fmt.Errorf("yaml line %d: unescaped single quote inside single-quoted string", lineNo)
			}
			sb.WriteByte(inner[i])
		}
		return sb.String(), nil
	}

	// Double-quoted YAML string
	inner := s[1 : len(s)-1]
	var sb strings.Builder
	sb.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '"' {
			return "", fmt.Errorf("yaml line %d: unescaped quote inside double-quoted string", lineNo)
		}
		if c != '\\' {
			sb.WriteByte(c)
			continue
		}
		i++
		if i >= len(inner) {
			return "", fmt.Errorf("yaml line %d: trailing backslash in double-quoted string", lineNo)
		}
		switch inner[i] {
		case '"', '\\', '/':
			sb.WriteByte(inner[i])
		case 'b':
			sb.WriteByte('\b')
		case 'f':
			sb.WriteByte('\f')
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 't':
			sb.WriteByte('\t')
		case '0':
			sb.WriteByte(0)
		case 'u':
			if i+4 >= len(inner) {
				return "", fmt.Errorf("yaml line %d: truncated \\u escape", lineNo)
			}
			v, err := strconv.ParseUint(inner[i+1:i+5], 16, 16)
			if err != nil {
				return "", fmt.Errorf("yaml line %d: invalid \\u escape: %w", lineNo, err)
			}
			r := rune(v)
			i += 4
			if utf16.IsSurrogate(r) {
				if i+6 < len(inner) && inner[i+1] == '\\' && inner[i+2] == 'u' {
					if v2, err2 := strconv.ParseUint(inner[i+3:i+7], 16, 16); err2 == nil {
						comb := utf16.DecodeRune(r, rune(v2))
						if comb != utf8.RuneError {
							sb.WriteRune(comb)
							i += 6
							continue
						}
					}
				}
				return "", fmt.Errorf("yaml line %d: unpaired UTF-16 surrogate in \\u escape", lineNo)
			}
			sb.WriteRune(r)
		case 'U':
			if i+8 >= len(inner) {
				return "", fmt.Errorf("yaml line %d: truncated \\U escape", lineNo)
			}
			v, err := strconv.ParseUint(inner[i+1:i+9], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return "", fmt.Errorf("yaml line %d: invalid \\U escape", lineNo)
			}
			sb.WriteRune(rune(v))
			i += 8
		default:
			return "", fmt.Errorf("yaml line %d: unsupported escape \\%c", lineNo, inner[i])
		}
	}
	return sb.String(), nil
}

func parseYAMLCoreNumber(s string) (json.Number, bool) {
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if n, err := strconv.ParseInt(s[2:], 16, 64); err == nil {
			return json.Number(strconv.FormatInt(n, 10)), true
		}
		return "", false
	}
	if strings.HasPrefix(s, "0o") || strings.HasPrefix(s, "0O") {
		if n, err := strconv.ParseInt(s[2:], 8, 64); err == nil {
			return json.Number(strconv.FormatInt(n, 10)), true
		}
		return "", false
	}
	idx := 0
	hasPlus := false
	if s[idx] == '-' || s[idx] == '+' {
		hasPlus = s[idx] == '+'
		idx++
		if idx >= len(s) {
			return "", false
		}
	}
	if s[idx] < '0' || s[idx] > '9' {
		return "", false
	}
	// YAML 1.2 Core Schema base-10 integer or float: multi-digit leading-zero base-10 integers like 007 are integers in YAML 1.2 Core
	for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
		idx++
	}
	norm := s
	if hasPlus {
		norm = s[1:]
	}
	if idx == len(s) {
		n, err := strconv.ParseInt(norm, 10, 64)
		if err != nil {
			return "", false
		}
		return json.Number(strconv.FormatInt(n, 10)), true
	}
	if s[idx] == '.' {
		idx++
		if idx >= len(s) || s[idx] < '0' || s[idx] > '9' {
			return "", false
		}
		for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
			idx++
		}
	}
	if idx < len(s) && (s[idx] == 'e' || s[idx] == 'E') {
		idx++
		if idx < len(s) && (s[idx] == '+' || s[idx] == '-') {
			idx++
		}
		if idx >= len(s) || s[idx] < '0' || s[idx] > '9' {
			return "", false
		}
		for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
			idx++
		}
	}
	if idx != len(s) {
		return "", false
	}
	f, err := strconv.ParseFloat(norm, 64)
	if err != nil {
		return "", false
	}
	_ = f
	// Normalize leading zeros before decimal if any (e.g. "00.5" -> "0.5")
	if strings.HasPrefix(norm, "-0") && len(norm) > 2 && norm[2] >= '0' && norm[2] <= '9' {
		trimmedZeros := strings.TrimLeft(norm[1:], "0")
		if trimmedZeros == "" || trimmedZeros[0] == '.' || trimmedZeros[0] == 'e' || trimmedZeros[0] == 'E' {
			trimmedZeros = "0" + trimmedZeros
		}
		norm = "-" + trimmedZeros
	} else if strings.HasPrefix(norm, "0") && len(norm) > 1 && norm[1] >= '0' && norm[1] <= '9' {
		trimmedZeros := strings.TrimLeft(norm, "0")
		if trimmedZeros == "" || trimmedZeros[0] == '.' || trimmedZeros[0] == 'e' || trimmedZeros[0] == 'E' {
			trimmedZeros = "0" + trimmedZeros
		}
		norm = trimmedZeros
	}
	return json.Number(norm), true
}
