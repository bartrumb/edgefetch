package extract

import (
	stdhtml "html"
	"strings"
	"unicode/utf8"
)

const (
	// DefaultMaxHTMLDocChars is the default 2 MiB input ceiling for ParseHTMLDoc.
	DefaultMaxHTMLDocChars = 2_097_152
	// HardMaxHTMLDocChars is the absolute 4 MiB ceiling for ParseHTMLDoc even when maxChars is larger.
	HardMaxHTMLDocChars = 4_194_304

	maxDepthDOM                 = 128
	maxNodesDOM                 = 40_000
	maxOverflowTagEventsDOM     = 1_024
	maxDocTotalVisitsDOM        = 90_000
	maxSerializeNodesPerCallDOM = 15_000
	maxDLMapVisitsDOM           = 4_000
	maxSelectorCharsDOM         = 256
	maxSelectorGroupsDOM        = 16
	maxCombinatorStepsDOM       = 8
	maxSelectLimitDOM           = 5_000
)

type domNodeKindDOM uint8

const (
	nodeDocumentDOM domNodeKindDOM = iota
	nodeElementDOM
	nodeTextDOM
)

type visitBudgetDOM struct {
	remaining int
}

type domNodeDOM struct {
	kind      domNodeKindDOM
	name      string
	attribs   map[string]string
	attrOrder []string
	data      string

	parent   *domNodeDOM
	prev     *domNodeDOM
	next     *domNodeDOM
	children []*domNodeDOM

	rawTextCached      string
	hasRawTextCached   bool
	cleanTextCached    string
	hasCleanTextCached bool
}

var strippedTextTagsDOM = map[string]bool{
	"script":    true,
	"style":     true,
	"noscript":  true,
	"template":  true,
	"svg":       true,
	"xmp":       true,
	"plaintext": true,
	"textarea":  true,
}

var voidTagsDOM = map[string]bool{
	"area":   true,
	"base":   true,
	"br":     true,
	"col":    true,
	"embed":  true,
	"hr":     true,
	"img":    true,
	"input":  true,
	"keygen": true,
	"link":   true,
	"meta":   true,
	"param":  true,
	"source": true,
	"track":  true,
	"wbr":    true,
}

var blockBoundaryTagsDOM = map[string]bool{
	"address":    true,
	"article":    true,
	"aside":      true,
	"blockquote": true,
	"br":         true,
	"caption":    true,
	"dd":         true,
	"details":    true,
	"div":        true,
	"dl":         true,
	"dt":         true,
	"fieldset":   true,
	"figcaption": true,
	"figure":     true,
	"footer":     true,
	"form":       true,
	"h1":         true,
	"h2":         true,
	"h3":         true,
	"h4":         true,
	"h5":         true,
	"h6":         true,
	"header":     true,
	"hr":         true,
	"li":         true,
	"main":       true,
	"nav":        true,
	"ol":         true,
	"p":          true,
	"pre":        true,
	"section":    true,
	"summary":    true,
	"table":      true,
	"tbody":      true,
	"td":         true,
	"tfoot":      true,
	"th":         true,
	"thead":      true,
	"tr":         true,
	"ul":         true,
}

var rawTextSerializerParentsDOM = map[string]bool{
	"style":     true,
	"script":    true,
	"xmp":       true,
	"iframe":    true,
	"noembed":   true,
	"noframes":  true,
	"plaintext": true,
	"noscript":  true,
}

var pCloseTriggersDOM = map[string]bool{
	"address":    true,
	"article":    true,
	"aside":      true,
	"blockquote": true,
	"details":    true,
	"div":        true,
	"dl":         true,
	"fieldset":   true,
	"figcaption": true,
	"figure":     true,
	"footer":     true,
	"form":       true,
	"h1":         true,
	"h2":         true,
	"h3":         true,
	"h4":         true,
	"h5":         true,
	"h6":         true,
	"header":     true,
	"hgroup":     true,
	"hr":         true,
	"main":       true,
	"menu":       true,
	"nav":        true,
	"ol":         true,
	"p":          true,
	"pre":        true,
	"section":    true,
	"table":      true,
	"ul":         true,
}

var tableStructureTagsDOM = map[string]bool{
	"table":    true,
	"thead":    true,
	"tbody":    true,
	"tfoot":    true,
	"tr":       true,
	"td":       true,
	"th":       true,
	"caption":  true,
	"colgroup": true,
}

// ── CSS Selector AST & Linear Memoized Matcher ──────────────────────────────────────────────────

type attrMatcherDOM struct {
	name       string
	op         string // "exists", "=", "*=", "^=", "$=", "~=", "|="
	value      string
	ignoreCase bool
}

type compoundStepDOM struct {
	tag        string // lowercase tag name, or "" for `*` / omitted
	hasTagName bool
	ids        []string
	classes    []string
	attrs      []attrMatcherDOM
}

type selectorStepDOM struct {
	combinatorFromPrev byte // 0, ' ', '>', '+'
	compound           compoundStepDOM
}

func isSimpleASCIIIdentCharDOM(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '-' ||
		ch == '_' ||
		ch == ':'
}

func isSimpleIdentCharNoColonDOM(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '-' ||
		ch == '_'
}

func splitSelectorGroupsDOM(raw string) ([]string, bool) {
	var groups []string
	bracketDepth := 0
	var quoteChar byte
	start := 0

	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '\\' {
			i++
			continue
		}
		if quoteChar != 0 {
			if ch == quoteChar {
				quoteChar = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quoteChar = ch
			continue
		}
		if ch == '[' {
			bracketDepth++
			continue
		}
		if ch == ']' {
			if bracketDepth == 0 {
				return nil, false
			}
			bracketDepth--
			continue
		}
		if ch == ',' && bracketDepth == 0 {
			part := strings.TrimSpace(raw[start:i])
			if part == "" {
				return nil, false
			}
			groups = append(groups, part)
			if len(groups) > maxSelectorGroupsDOM {
				return nil, false
			}
			start = i + 1
		}
	}

	if quoteChar != 0 || bracketDepth != 0 {
		return nil, false
	}
	tail := strings.TrimSpace(raw[start:])
	if tail == "" {
		return nil, false
	}
	groups = append(groups, tail)
	if len(groups) > maxSelectorGroupsDOM {
		return nil, false
	}
	return groups, true
}

func parseAttrSelectorDOM(src string, openBracketIdx int) (attrMatcherDOM, int, bool) {
	n := len(src)
	p := openBracketIdx + 1
	for p < n && src[p] <= ' ' {
		p++
	}

	nameStart := p
	for p < n && (isSimpleASCIIIdentCharDOM(src[p]) || src[p] == '.') {
		p++
	}
	if p == nameStart {
		return attrMatcherDOM{}, 0, false
	}
	attrName := strings.ToLower(src[nameStart:p])

	for p < n && src[p] <= ' ' {
		p++
	}
	if p >= n {
		return attrMatcherDOM{}, 0, false
	}

	if src[p] == ']' {
		return attrMatcherDOM{
			name: attrName,
			op:   "exists",
		}, p + 1, true
	}

	var op string
	c0 := src[p]
	if c0 == '=' {
		op = "="
		p++
	} else if p+1 < n && src[p+1] == '=' && (c0 == '*' || c0 == '^' || c0 == '$' || c0 == '~' || c0 == '|') {
		op = src[p : p+2]
		p += 2
	}
	if op == "" {
		return attrMatcherDOM{}, 0, false
	}

	for p < n && src[p] <= ' ' {
		p++
	}
	if p >= n {
		return attrMatcherDOM{}, 0, false
	}

	var value string
	q := src[p]
	if q == '"' || q == '\'' {
		p++
		var sb strings.Builder
		closed := false
		for p < n {
			ch := src[p]
			if ch == '\\' && p+1 < n {
				sb.WriteByte(src[p+1])
				p += 2
				continue
			}
			if ch == q {
				closed = true
				p++
				break
			}
			sb.WriteByte(ch)
			p++
		}
		if !closed {
			return attrMatcherDOM{}, 0, false
		}
		value = sb.String()
	} else {
		valStart := p
		for p < n && src[p] > ' ' && src[p] != ']' {
			p++
		}
		value = src[valStart:p]
	}

	for p < n && src[p] <= ' ' {
		p++
	}
	ignoreCase := false
	if p < n && (src[p] == 'i' || src[p] == 'I') {
		afterFlag := p + 1
		if afterFlag < n && (src[afterFlag] <= ' ' || src[afterFlag] == ']') {
			ignoreCase = true
			p = afterFlag
			for p < n && src[p] <= ' ' {
				p++
			}
		}
	}

	if p >= n || src[p] != ']' {
		return attrMatcherDOM{}, 0, false
	}
	if ignoreCase {
		value = strings.ToLower(value)
	}
	return attrMatcherDOM{
		name:       attrName,
		op:         op,
		value:      value,
		ignoreCase: ignoreCase,
	}, p + 1, true
}

func readSimpleIdentDOM(src string, startIdx int) (string, int, bool) {
	n := len(src)
	p := startIdx
	var sb strings.Builder
	for p < n {
		ch := src[p]
		if ch == '\\' && p+1 < n {
			// Decode UTF-8 rune after backslash so escaped multi-byte chars stay intact.
			_, width := utf8.DecodeRuneInString(src[p+1:])
			sb.WriteString(src[p+1 : p+1+width])
			p += 1 + width
			continue
		}
		if isSimpleIdentCharNoColonDOM(ch) {
			sb.WriteByte(ch)
			p++
			continue
		}
		break
	}
	if sb.Len() == 0 {
		return "", 0, false
	}
	return sb.String(), p, true
}

func parseSingleSelectorChainDOM(groupSrc string) ([]selectorStepDOM, bool) {
	var steps []selectorStepDOM
	n := len(groupSrc)
	p := 0

	for p < n && groupSrc[p] <= ' ' {
		p++
	}

	var pendingCombinator byte
	if p < n && (groupSrc[p] == '>' || groupSrc[p] == '+') {
		if groupSrc[p] != '>' {
			return nil, false
		}
		pendingCombinator = '>'
		p++
		for p < n && groupSrc[p] <= ' ' {
			p++
		}
		if p >= n {
			return nil, false
		}
	}

	for p < n {
		var tag string
		hasTagName := false
		hasExplicitUniversal := false
		var ids []string
		var classes []string
		var attrs []attrMatcherDOM

		if groupSrc[p] == '*' {
			hasExplicitUniversal = true
			p++
		} else {
			firstCh := groupSrc[p]
			if (firstCh >= 'a' && firstCh <= 'z') || (firstCh >= 'A' && firstCh <= 'Z') {
				ident, nextIdx, ok := readSimpleIdentDOM(groupSrc, p)
				if !ok {
					return nil, false
				}
				tag = strings.ToLower(ident)
				hasTagName = true
				p = nextIdx
			}
		}

		for p < n {
			ch := groupSrc[p]
			if ch == '#' {
				idIdent, nextIdx, ok := readSimpleIdentDOM(groupSrc, p+1)
				if !ok {
					return nil, false
				}
				ids = append(ids, idIdent)
				p = nextIdx
			} else if ch == '.' {
				clsIdent, nextIdx, ok := readSimpleIdentDOM(groupSrc, p+1)
				if !ok {
					return nil, false
				}
				classes = append(classes, clsIdent)
				p = nextIdx
			} else if ch == '[' {
				m, nextIdx, ok := parseAttrSelectorDOM(groupSrc, p)
				if !ok {
					return nil, false
				}
				attrs = append(attrs, m)
				p = nextIdx
			} else {
				break
			}
		}

		if !hasTagName && !hasExplicitUniversal && len(ids) == 0 && len(classes) == 0 && len(attrs) == 0 {
			return nil, false
		}

		steps = append(steps, selectorStepDOM{
			combinatorFromPrev: pendingCombinator,
			compound: compoundStepDOM{
				tag:        tag,
				hasTagName: hasTagName,
				ids:        ids,
				classes:    classes,
				attrs:      attrs,
			},
		})
		if len(steps) > maxCombinatorStepsDOM {
			return nil, false
		}

		sawSpace := false
		for p < n && groupSrc[p] <= ' ' {
			sawSpace = true
			p++
		}
		if p >= n {
			break
		}

		combCh := groupSrc[p]
		if combCh == '>' || combCh == '+' {
			pendingCombinator = combCh
			p++
			for p < n && groupSrc[p] <= ' ' {
				p++
			}
			if p >= n {
				return nil, false
			}
		} else if sawSpace {
			pendingCombinator = ' '
		} else {
			return nil, false
		}
	}

	if len(steps) == 0 {
		return nil, false
	}
	return steps, true
}

func parseSelectorDOM(selector string) ([][]selectorStepDOM, bool) {
	trimmed := strings.TrimSpace(selector)
	if trimmed == "" || len(trimmed) > maxSelectorCharsDOM {
		return nil, false
	}
	rawGroups, ok := splitSelectorGroupsDOM(trimmed)
	if !ok {
		return nil, false
	}
	chains := make([][]selectorStepDOM, 0, len(rawGroups))
	for _, g := range rawGroups {
		chain, okChain := parseSingleSelectorChainDOM(g)
		if !okChain {
			return nil, false
		}
		chains = append(chains, chain)
	}
	return chains, true
}

func hasClassTokenDOM(classAttr, target string) bool {
	if classAttr == "" || target == "" {
		return false
	}
	tLen := len(target)
	searchFrom := 0
	for searchFrom <= len(classAttr)-tLen {
		rel := strings.Index(classAttr[searchFrom:], target)
		if rel < 0 {
			return false
		}
		pos := searchFrom + rel
		beforeOK := pos == 0 || classAttr[pos-1] <= ' '
		afterIdx := pos + tLen
		afterOK := afterIdx == len(classAttr) || classAttr[afterIdx] <= ' '
		if beforeOK && afterOK {
			return true
		}
		searchFrom = pos + 1
	}
	return false
}

func matchesAttrDOM(el *domNodeDOM, m attrMatcherDOM) bool {
	if el.attribs == nil {
		return false
	}
	rawVal, exists := el.attribs[m.name]
	if !exists {
		return false
	}
	if m.op == "exists" {
		return true
	}
	actual := rawVal
	if m.ignoreCase {
		actual = strings.ToLower(rawVal)
	}
	expected := m.value
	switch m.op {
	case "=":
		return actual == expected
	case "*=":
		return expected != "" && strings.Contains(actual, expected)
	case "^=":
		return expected != "" && strings.HasPrefix(actual, expected)
	case "$=":
		return expected != "" && strings.HasSuffix(actual, expected)
	case "~=":
		return expected != "" && hasClassTokenDOM(actual, expected)
	case "|=":
		return actual == expected || strings.HasPrefix(actual, expected+"-")
	default:
		return false
	}
}

func matchesCompoundDOM(el *domNodeDOM, c compoundStepDOM) bool {
	if c.hasTagName && el.name != c.tag {
		return false
	}
	if len(c.ids) > 0 {
		if el.attribs == nil {
			return false
		}
		elID, ok := el.attribs["id"]
		if !ok {
			return false
		}
		for _, id := range c.ids {
			if elID != id {
				return false
			}
		}
	}
	if len(c.classes) > 0 {
		if el.attribs == nil {
			return false
		}
		cls := el.attribs["class"]
		if cls == "" {
			return false
		}
		for _, token := range c.classes {
			if !hasClassTokenDOM(cls, token) {
				return false
			}
		}
	}
	for _, attr := range c.attrs {
		if !matchesAttrDOM(el, attr) {
			return false
		}
	}
	return true
}

func prevElementSiblingDOM(el *domNodeDOM) *domNodeDOM {
	cur := el.prev
	for cur != nil {
		if cur.kind == nodeElementDOM {
			return cur
		}
		cur = cur.prev
	}
	return nil
}

type chainMemoDOM struct {
	step []map[*domNodeDOM]bool
	anc  []map[*domNodeDOM]bool
}

func hasMatchingAncestorDOM(
	el *domNodeDOM,
	steps []selectorStepDOM,
	prevStepIdx int,
	scopeRoot *domNodeDOM,
	memo *chainMemoDOM,
) bool {
	p := el.parent
	if p == nil || p == scopeRoot.parent || p.kind != nodeElementDOM {
		return false
	}

	ancMap := memo.anc[prevStepIdx]
	if hit, ok := ancMap[p]; ok {
		return hit
	}

	var path []*domNodeDOM
	res := false
	for p != nil && p != scopeRoot.parent && p.kind == nodeElementDOM {
		if cached, ok := ancMap[p]; ok {
			res = cached
			break
		}
		path = append(path, p)
		if p == scopeRoot {
			break
		}
		p = p.parent
	}

	for i := len(path) - 1; i >= 0; i-- {
		node := path[i]
		if !res {
			res = matchesChainAtStepDOM(node, steps, prevStepIdx, scopeRoot, memo)
		}
		ancMap[node] = res
	}
	return res
}

func matchesChainAtStepDOM(
	el *domNodeDOM,
	steps []selectorStepDOM,
	stepIdx int,
	scopeRoot *domNodeDOM,
	memo *chainMemoDOM,
) bool {
	stepMap := memo.step[stepIdx]
	if existing, ok := stepMap[el]; ok {
		return existing
	}

	step := steps[stepIdx]
	if !matchesCompoundDOM(el, step.compound) {
		stepMap[el] = false
		return false
	}

	if stepIdx == 0 {
		ok := true
		if step.combinatorFromPrev == '>' {
			ok = el.parent == scopeRoot
		}
		stepMap[el] = ok
		return ok
	}

	switch step.combinatorFromPrev {
	case '>':
		parent := el.parent
		if parent == nil || parent == scopeRoot.parent || parent.kind != nodeElementDOM {
			stepMap[el] = false
			return false
		}
		ok := matchesChainAtStepDOM(parent, steps, stepIdx-1, scopeRoot, memo)
		stepMap[el] = ok
		return ok
	case '+':
		prev := prevElementSiblingDOM(el)
		if prev == nil {
			stepMap[el] = false
			return false
		}
		ok := matchesChainAtStepDOM(prev, steps, stepIdx-1, scopeRoot, memo)
		stepMap[el] = ok
		return ok
	default:
		ok := hasMatchingAncestorDOM(el, steps, stepIdx-1, scopeRoot, memo)
		stepMap[el] = ok
		return ok
	}
}

// ── Text Normalization & Linear Cached Extraction ───────────────────────────────────────────────

func isASCIIOrUnicodeWhitespaceRuneDOM(r rune) bool {
	return r <= 0x20 ||
		r == 0x00A0 ||
		r == 0x1680 ||
		(r >= 0x2000 && r <= 0x200A) ||
		r == 0x2028 ||
		r == 0x2029 ||
		r == 0x202F ||
		r == 0x205F ||
		r == 0x3000 ||
		r == 0xFEFF
}

func stripTrailingColonsAndWhitespaceDOM(s string) string {
	end := len(s)
	for end > 0 {
		r, width := utf8.DecodeLastRuneInString(s[:end])
		if r == ':' || r == '：' || isASCIIOrUnicodeWhitespaceRuneDOM(r) {
			end -= width
		} else {
			break
		}
	}
	start := 0
	for start < end {
		r, width := utf8.DecodeRuneInString(s[start:end])
		if isASCIIOrUnicodeWhitespaceRuneDOM(r) {
			start += width
		} else {
			break
		}
	}
	return s[start:end]
}

func collapseAndTrimWhitespaceDOM(raw string) string {
	if raw == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(raw))
	inSpace := true
	chunkStart := -1
	i := 0
	for i < len(raw) {
		b := raw[i]
		if b < 0x80 {
			if b <= 0x20 {
				if chunkStart >= 0 {
					if sb.Len() > 0 {
						sb.WriteByte(' ')
					}
					sb.WriteString(raw[chunkStart:i])
					chunkStart = -1
				}
				inSpace = true
			} else if inSpace {
				chunkStart = i
				inSpace = false
			}
			i++
			continue
		}
		r, width := utf8.DecodeRuneInString(raw[i:])
		if isASCIIOrUnicodeWhitespaceRuneDOM(r) {
			if chunkStart >= 0 {
				if sb.Len() > 0 {
					sb.WriteByte(' ')
				}
				sb.WriteString(raw[chunkStart:i])
				chunkStart = -1
			}
			inSpace = true
		} else if inSpace {
			chunkStart = i
			inSpace = false
		}
		i += width
	}
	if chunkStart >= 0 {
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(raw[chunkStart:])
	}
	return sb.String()
}

func isSimpleLeafTextElementDOM(node *domNodeDOM) bool {
	if node.kind != nodeElementDOM {
		return false
	}
	if strippedTextTagsDOM[node.name] {
		return false
	}
	for _, child := range node.children {
		if child.kind != nodeTextDOM {
			return false
		}
	}
	return true
}

func leafTextContentDOM(node *domNodeDOM) string {
	if len(node.children) == 0 {
		return ""
	}
	if len(node.children) == 1 {
		return node.children[0].data
	}
	var sb strings.Builder
	for _, ch := range node.children {
		sb.WriteString(ch.data)
	}
	return sb.String()
}

type textEvalFrameDOM struct {
	target   *domNodeDOM
	childIdx int
	chunks   []string
}

func computeRawNodeTextCachedDOM(node *domNodeDOM, budget *visitBudgetDOM) string {
	if node.hasRawTextCached {
		return node.rawTextCached
	}
	if node.kind == nodeElementDOM && strippedTextTagsDOM[node.name] {
		node.rawTextCached = ""
		node.hasRawTextCached = true
		return ""
	}

	stack := []textEvalFrameDOM{{target: node, childIdx: 0}}
	for len(stack) > 0 {
		topIdx := len(stack) - 1
		top := &stack[topIdx]
		children := top.target.children
		if top.childIdx >= len(children) || budget.remaining <= 0 {
			joined := ""
			if len(top.chunks) == 1 {
				joined = top.chunks[0]
			} else if len(top.chunks) > 1 {
				joined = strings.Join(top.chunks, "")
			}
			finishedTarget := top.target
			finishedTarget.rawTextCached = joined
			finishedTarget.hasRawTextCached = true
			stack = stack[:topIdx]
			if len(stack) > 0 {
				parentFrame := &stack[len(stack)-1]
				isBlock := finishedTarget.kind == nodeElementDOM && blockBoundaryTagsDOM[finishedTarget.name]
				if isBlock {
					parentFrame.chunks = append(parentFrame.chunks, " ")
				}
				if joined != "" {
					parentFrame.chunks = append(parentFrame.chunks, joined)
				}
				if isBlock {
					parentFrame.chunks = append(parentFrame.chunks, " ")
				}
			}
			continue
		}

		budget.remaining--
		child := children[top.childIdx]
		top.childIdx++
		if child.kind == nodeTextDOM {
			if child.data != "" {
				top.chunks = append(top.chunks, child.data)
			}
			continue
		}
		if child.kind != nodeElementDOM {
			continue
		}
		tagLower := child.name
		if strippedTextTagsDOM[tagLower] {
			continue
		}
		if tagLower == "br" || tagLower == "hr" {
			top.chunks = append(top.chunks, " ")
			continue
		}
		if child.hasRawTextCached {
			isBlock := blockBoundaryTagsDOM[tagLower]
			if isBlock {
				top.chunks = append(top.chunks, " ")
			}
			if child.rawTextCached != "" {
				top.chunks = append(top.chunks, child.rawTextCached)
			}
			if isBlock {
				top.chunks = append(top.chunks, " ")
			}
			continue
		}
		stack = append(stack, textEvalFrameDOM{target: child, childIdx: 0})
	}
	return node.rawTextCached
}

func extractCleanNodeTextDOM(node *domNodeDOM, budget *visitBudgetDOM) string {
	if node.hasCleanTextCached {
		return node.cleanTextCached
	}
	if budget.remaining <= 0 {
		return ""
	}
	if node.kind == nodeElementDOM && strippedTextTagsDOM[node.name] {
		node.cleanTextCached = ""
		node.hasCleanTextCached = true
		return ""
	}
	var clean string
	if isSimpleLeafTextElementDOM(node) {
		budget.remaining--
		clean = collapseAndTrimWhitespaceDOM(leafTextContentDOM(node))
	} else {
		raw := computeRawNodeTextCachedDOM(node, budget)
		if raw != "" {
			clean = collapseAndTrimWhitespaceDOM(raw)
		}
	}
	node.cleanTextCached = clean
	node.hasCleanTextCached = true
	return clean
}

// ── Linear-Time HTML5 Tokenizer & Bounded DOM Tree Builder ──────────────────────────────────────

func stripNULAndZeroEntitiesDOM(s string) string {
	hasNUL := strings.IndexByte(s, 0) >= 0
	hasNumEnt := strings.Contains(s, "&#")
	if !hasNUL && !hasNumEnt {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		if c == 0 {
			i++
			continue
		}
		if c == '&' && i+3 < n && s[i+1] == '#' {
			p := i + 2
			if s[p] == 'x' || s[p] == 'X' {
				p++
				zStart := p
				for p < n && s[p] == '0' {
					p++
				}
				if p > zStart && p < n && s[p] == ';' {
					i = p + 1
					continue
				}
			} else if s[p] == '0' {
				for p < n && s[p] == '0' {
					p++
				}
				if p < n && s[p] == ';' {
					i = p + 1
					continue
				}
			}
		}
		sb.WriteByte(c)
		i++
	}
	return sb.String()
}

func decodeHTMLEntitiesSafeDOM(s string) string {
	if strings.IndexByte(s, '&') < 0 {
		return s
	}
	dec := stdhtml.UnescapeString(s)
	if strings.IndexByte(dec, 0) >= 0 {
		dec = strings.ReplaceAll(dec, "\x00", "")
	}
	return dec
}

func isTagNameBoundaryDOM(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v' || b == '/' || b == '>'
}

func isHTMLSpaceDOM(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func isASCIIAlphaDOM(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func appendChildLinearDOM(parent, child *domNodeDOM) {
	siblings := parent.children
	var prev *domNodeDOM
	if len(siblings) > 0 {
		prev = siblings[len(siblings)-1]
	}
	child.parent = parent
	child.prev = prev
	child.next = nil
	if prev != nil {
		prev.next = child
	}
	parent.children = append(siblings, child)
}

func isInForeignContextDOM(stack []*domNodeDOM) bool {
	for i := len(stack) - 1; i >= 1; i-- {
		nm := stack[i].name
		if nm == "svg" || nm == "math" {
			return true
		}
	}
	return false
}

func shouldAutoCloseTopTagDOM(topTag, newTag string) bool {
	if topTag == "p" && pCloseTriggersDOM[newTag] {
		return true
	}
	switch newTag {
	case "li":
		return topTag == "li"
	case "dt", "dd":
		return topTag == "dt" || topTag == "dd" || topTag == "p"
	case "td":
		return topTag == "td" || topTag == "th" || topTag == "thead" || topTag == "p"
	case "th":
		return topTag == "th" || topTag == "td" || topTag == "p"
	case "tr":
		return topTag == "tr" || topTag == "th" || topTag == "td" || topTag == "p"
	case "thead", "tbody", "tfoot":
		return topTag == "td" || topTag == "th" || topTag == "tr" ||
			topTag == "thead" || topTag == "tbody" || topTag == "tfoot" || topTag == "p"
	case "option":
		return topTag == "option"
	case "optgroup":
		return topTag == "option" || topTag == "optgroup"
	case "rt", "rp":
		return topTag == "rt" || topTag == "rp"
	default:
		return false
	}
}

func autoCloseImplicitOpenTagsDOM(stack *[]*domNodeDOM, newTag string) {
	for len(*stack) > 1 {
		top := (*stack)[len(*stack)-1].name
		if !shouldAutoCloseTopTagDOM(top, newTag) {
			break
		}
		*stack = (*stack)[:len(*stack)-1]
	}
}

func scanRawElementCloseDOM(html string, from int, tagLower string) (innerEnd int, afterClose int) {
	n := len(html)
	tLen := len(tagLower)
	pos := from
	for pos < n {
		rel := strings.IndexByte(html[pos:], '<')
		if rel < 0 {
			return n, n
		}
		lt := pos + rel
		if lt+2+tLen >= n || html[lt+1] != '/' {
			pos = lt + 1
			continue
		}
		matched := true
		for k := 0; k < tLen; k++ {
			c := html[lt+2+k]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != tagLower[k] {
				matched = false
				break
			}
		}
		afterName := lt + 2 + tLen
		if !matched || !isTagNameBoundaryDOM(html[afterName]) {
			pos = lt + 2
			continue
		}
		gtRel := strings.IndexByte(html[afterName:], '>')
		if gtRel < 0 {
			return lt, n
		}
		return lt, afterName + gtRel + 1
	}
	return n, n
}

func parseOpenTagAttribsDOM(html string, p int) (attribs map[string]string, order []string, selfClosing bool, afterGt int, ok bool) {
	n := len(html)
	for p < n {
		for p < n && isHTMLSpaceDOM(html[p]) {
			p++
		}
		if p >= n {
			return nil, nil, false, n, false
		}
		if html[p] == '>' {
			return attribs, order, false, p + 1, true
		}
		if html[p] == '/' {
			p++
			if p < n && html[p] == '>' {
				return attribs, order, true, p + 1, true
			}
			continue
		}
		nameStart := p
		for p < n && !isHTMLSpaceDOM(html[p]) && html[p] != '=' && html[p] != '>' && html[p] != '/' {
			p++
		}
		if p == nameStart {
			p++
			continue
		}
		attrName := strings.ToLower(html[nameStart:p])
		for p < n && isHTMLSpaceDOM(html[p]) {
			p++
		}
		attrVal := ""
		if p < n && html[p] == '=' {
			p++
			for p < n && isHTMLSpaceDOM(html[p]) {
				p++
			}
			if p >= n {
				return nil, nil, false, n, false
			}
			q := html[p]
			if q == '"' || q == '\'' {
				p++
				valStart := p
				closeRel := strings.IndexByte(html[p:], q)
				if closeRel < 0 {
					return nil, nil, false, n, false
				}
				attrVal = decodeHTMLEntitiesSafeDOM(html[valStart : p+closeRel])
				p += closeRel + 1
			} else {
				valStart := p
				for p < n && !isHTMLSpaceDOM(html[p]) && html[p] != '>' {
					p++
				}
				if p >= n {
					return nil, nil, false, n, false
				}
				attrVal = decodeHTMLEntitiesSafeDOM(html[valStart:p])
			}
		}
		if attribs == nil {
			attribs = make(map[string]string, 4)
		}
		if _, exists := attribs[attrName]; !exists {
			attribs[attrName] = attrVal
			order = append(order, attrName)
		}
	}
	return nil, nil, false, n, false
}

func buildBoundedDocumentDOM(html string) *domNodeDOM {
	root := &domNodeDOM{kind: nodeDocumentDOM}
	stack := []*domNodeDOM{root}
	nodeCount := 0
	overflowDepth := 0
	overflowEvents := 0
	overflowInForeign := false
	halted := false
	var coalescedBufs map[*domNodeDOM][]byte
	var coalescedOrder []*domNodeDOM

	emitText := func(raw string, decode bool) {
		if halted || raw == "" {
			return
		}
		txt := raw
		if decode {
			txt = decodeHTMLEntitiesSafeDOM(raw)
		}
		if txt == "" {
			return
		}
		parent := stack[len(stack)-1]
		siblings := parent.children
		if len(siblings) > 0 && siblings[len(siblings)-1].kind == nodeTextDOM {
			last := siblings[len(siblings)-1]
			if coalescedBufs == nil {
				coalescedBufs = make(map[*domNodeDOM][]byte)
			}
			buf, exists := coalescedBufs[last]
			if !exists {
				buf = make([]byte, 0, len(last.data)+len(txt)+64)
				buf = append(buf, last.data...)
				coalescedOrder = append(coalescedOrder, last)
			}
			coalescedBufs[last] = append(buf, txt...)
			return
		}
		if nodeCount >= maxNodesDOM {
			halted = true
			return
		}
		appendChildLinearDOM(parent, &domNodeDOM{
			kind: nodeTextDOM,
			data: txt,
		})
		nodeCount++
	}

	n := len(html)
	i := 0
	nextStdCommentClose := -2
	nextBangCommentClose := -2
	nextCDATAClose := -2

	for i < n && !halted {
		ltRel := strings.IndexByte(html[i:], '<')
		if ltRel < 0 {
			emitText(html[i:], true)
			break
		}
		if ltRel > 0 {
			emitText(html[i:i+ltRel], true)
			if halted {
				break
			}
		}
		lt := i + ltRel
		if lt+1 >= n {
			emitText("<", false)
			break
		}

		c1 := html[lt+1]

		// 1. Declarations / Comments / CDATA (`<!...`)
		if c1 == '!' {
			if lt+3 < n && html[lt+2] == '-' && html[lt+3] == '-' {
				bodyStart := lt + 4
				if bodyStart < n && html[bodyStart] == '>' {
					i = bodyStart + 1
					continue
				}
				if bodyStart+1 < n && html[bodyStart] == '-' && html[bodyStart+1] == '>' {
					i = bodyStart + 2
					continue
				}
				if nextStdCommentClose != -1 && nextStdCommentClose < bodyStart {
					rel := strings.Index(html[bodyStart:], "-->")
					if rel < 0 {
						nextStdCommentClose = -1
					} else {
						nextStdCommentClose = bodyStart + rel
					}
				}
				if nextBangCommentClose != -1 && nextBangCommentClose < bodyStart {
					rel := strings.Index(html[bodyStart:], "--!>")
					if rel < 0 {
						nextBangCommentClose = -1
					} else {
						nextBangCommentClose = bodyStart + rel
					}
				}
				if nextStdCommentClose < 0 && nextBangCommentClose < 0 {
					break
				}
				if nextStdCommentClose >= 0 && (nextBangCommentClose < 0 || nextStdCommentClose <= nextBangCommentClose) {
					i = nextStdCommentClose + 3
				} else {
					i = nextBangCommentClose + 4
				}
				continue
			}
			if lt+9 <= n && strings.HasPrefix(html[lt+2:], "[CDATA[") {
				bodyStart := lt + 9
				if nextCDATAClose != -1 && nextCDATAClose < bodyStart {
					rel := strings.Index(html[bodyStart:], "]]>")
					if rel < 0 {
						nextCDATAClose = -1
					} else {
						nextCDATAClose = bodyStart + rel
					}
				}
				if nextCDATAClose < 0 {
					if isInForeignContextDOM(stack) {
						emitText(html[bodyStart:], false)
					}
					break
				}
				if isInForeignContextDOM(stack) {
					emitText(html[bodyStart:nextCDATAClose], false)
				}
				i = nextCDATAClose + 3
				continue
			}
			gtRel := strings.IndexByte(html[lt+2:], '>')
			if gtRel < 0 {
				break
			}
			i = lt + 2 + gtRel + 1
			continue
		}

		// 2. Processing instructions (`<?...>`)
		if c1 == '?' {
			gtRel := strings.IndexByte(html[lt+2:], '>')
			if gtRel < 0 {
				break
			}
			i = lt + 2 + gtRel + 1
			continue
		}

		// 3. Closing tags (`</...>`)
		if c1 == '/' {
			if lt+2 >= n {
				emitText("</", false)
				break
			}
			if html[lt+2] == '>' {
				i = lt + 3
				continue
			}
			if !isASCIIAlphaDOM(html[lt+2]) {
				gtRel := strings.IndexByte(html[lt+2:], '>')
				if gtRel < 0 {
					break
				}
				i = lt + 2 + gtRel + 1
				continue
			}
			nameStart := lt + 2
			p := nameStart + 1
			for p < n && !isTagNameBoundaryDOM(html[p]) {
				p++
			}
			if p >= n {
				break
			}
			closeName := strings.ToLower(html[nameStart:p])
			gtRel := strings.IndexByte(html[p:], '>')
			if gtRel < 0 {
				break
			}
			i = p + gtRel + 1

			isVoid := voidTagsDOM[closeName] || (closeName == "image" && !isInForeignContextDOM(stack))
			if overflowDepth > 0 {
				if !isVoid {
					overflowDepth--
				}
				continue
			}
			if isVoid {
				if closeName == "br" && nodeCount < maxNodesDOM && len(stack)-1 < maxDepthDOM {
					appendChildLinearDOM(stack[len(stack)-1], &domNodeDOM{kind: nodeElementDOM, name: "br"})
					nodeCount++
				}
				continue
			}

			isTableTag := tableStructureTagsDOM[closeName]
			foundIdx := -1
			for sIdx := len(stack) - 1; sIdx >= 1; sIdx-- {
				curName := stack[sIdx].name
				if curName == closeName {
					foundIdx = sIdx
					break
				}
				if !isTableTag && (curName == "table" || curName == "td" || curName == "th" || curName == "template") {
					break
				}
			}
			if foundIdx >= 1 {
				stack = stack[:foundIdx]
			}
			continue
		}

		// 4. Opening tags (`<tag ...>`)
		if !isASCIIAlphaDOM(c1) {
			k := lt + 1
			for k < n && html[k] == '<' {
				if k+1 < n {
					nxt := html[k+1]
					if isASCIIAlphaDOM(nxt) || nxt == '/' || nxt == '!' || nxt == '?' {
						break
					}
				}
				k++
			}
			emitText(html[lt:k], false)
			i = k
			continue
		}

		nameStart := lt + 1
		p := nameStart + 1
		for p < n && !isTagNameBoundaryDOM(html[p]) {
			p++
		}
		if p >= n {
			break
		}
		tagName := strings.ToLower(html[nameStart:p])
		inForeign := isInForeignContextDOM(stack)
		if tagName == "image" && !inForeign {
			tagName = "img"
		}
		isVoid := voidTagsDOM[tagName]

		// Fast path when already overflowing or at maxDepthDOM
		if overflowDepth > 0 || len(stack)-1 >= maxDepthDOM {
			if overflowDepth == 0 {
				overflowInForeign = inForeign
			}
			attribs, order, selfClosing, afterGt, ok := parseOpenTagAttribsDOM(html, p)
			if !ok {
				break
			}
			i = afterGt
			if isVoid {
				// Void element at exact depth ceiling still skipped safely without pushing
				_ = attribs
				_ = order
				continue
			}
			if !(selfClosing && overflowInForeign) {
				overflowDepth++
			}
			overflowEvents++
			if overflowEvents >= maxOverflowTagEventsDOM {
				halted = true
				break
			}
			continue
		}

		attribs, order, selfClosing, afterGt, ok := parseOpenTagAttribsDOM(html, p)
		if !ok {
			break
		}
		i = afterGt

		autoCloseImplicitOpenTagsDOM(&stack, tagName)
		if nodeCount >= maxNodesDOM {
			halted = true
			break
		}
		el := &domNodeDOM{
			kind:      nodeElementDOM,
			name:      tagName,
			attribs:   attribs,
			attrOrder: order,
		}
		appendChildLinearDOM(stack[len(stack)-1], el)
		nodeCount++

		if isVoid || (selfClosing && (inForeign || tagName == "svg" || tagName == "math")) {
			continue
		}

		stack = append(stack, el)

		// Handle raw-text & RCDATA elements immediately in O(N)
		switch tagName {
		case "plaintext":
			if i < n {
				emitText(html[i:], false)
			}
			i = n
		case "script", "style", "xmp":
			innerEnd, afterClose := scanRawElementCloseDOM(html, i, tagName)
			if innerEnd > i {
				emitText(html[i:innerEnd], false)
			}
			i = afterClose
			if len(stack) > 1 && stack[len(stack)-1] == el {
				stack = stack[:len(stack)-1]
			}
		case "textarea", "title":
			innerEnd, afterClose := scanRawElementCloseDOM(html, i, tagName)
			if innerEnd > i {
				emitText(html[i:innerEnd], true)
			}
			i = afterClose
			if len(stack) > 1 && stack[len(stack)-1] == el {
				stack = stack[:len(stack)-1]
			}
		}
	}

	for _, tn := range coalescedOrder {
		tn.data = string(coalescedBufs[tn])
	}

	return root
}

// ── Subtree Walking & HTML Serialization ────────────────────────────────────────────────────────

type walkDirectiveDOM uint8

const (
	walkContinueDOM walkDirectiveDOM = iota
	walkSkipDOM
	walkStopDOM
)

func walkSubtreeElementsDOM(
	root *domNodeDOM,
	budget *visitBudgetDOM,
	visit func(el *domNodeDOM) walkDirectiveDOM,
) {
	if budget.remaining <= 0 {
		return
	}
	stack := make([]*domNodeDOM, 0, len(root.children))
	for i := len(root.children) - 1; i >= 0; i-- {
		stack = append(stack, root.children[i])
	}
	for len(stack) > 0 {
		if budget.remaining <= 0 {
			return
		}
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur.kind != nodeElementDOM {
			continue
		}
		budget.remaining--
		dir := visit(cur)
		if dir == walkStopDOM {
			return
		}
		if dir == walkSkipDOM {
			continue
		}
		for i := len(cur.children) - 1; i >= 0; i-- {
			stack = append(stack, cur.children[i])
		}
	}
}

func chargeSerializeBudgetDOM(nodes []*domNodeDOM, budget *visitBudgetDOM) bool {
	if budget.remaining <= 0 {
		return false
	}
	stack := make([]*domNodeDOM, 0, len(nodes))
	for i := len(nodes) - 1; i >= 0; i-- {
		stack = append(stack, nodes[i])
	}
	count := 0
	for len(stack) > 0 {
		if budget.remaining <= 0 || count >= maxSerializeNodesPerCallDOM {
			return false
		}
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		budget.remaining--
		count++
		if cur.kind == nodeElementDOM || cur.kind == nodeDocumentDOM {
			for i := len(cur.children) - 1; i >= 0; i-- {
				stack = append(stack, cur.children[i])
			}
		}
	}
	return true
}

func writeEscapedAttrValDOM(sb *strings.Builder, val string) {
	for i := 0; i < len(val); i++ {
		switch val[i] {
		case '&':
			sb.WriteString("&amp;")
		case '"':
			sb.WriteString("&quot;")
		default:
			sb.WriteByte(val[i])
		}
	}
}

func writeEscapedTextDataDOM(sb *strings.Builder, s string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		default:
			sb.WriteByte(s[i])
		}
	}
}

type serializeStepDOM struct {
	node       *domNodeDOM
	closingTag string
}

func serializeNodesDOM(nodes []*domNodeDOM) string {
	var sb strings.Builder
	stack := make([]serializeStepDOM, 0, len(nodes))
	for i := len(nodes) - 1; i >= 0; i-- {
		stack = append(stack, serializeStepDOM{node: nodes[i]})
	}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur.closingTag != "" {
			sb.WriteString("</")
			sb.WriteString(cur.closingTag)
			sb.WriteByte('>')
			continue
		}
		nd := cur.node
		switch nd.kind {
		case nodeDocumentDOM:
			for i := len(nd.children) - 1; i >= 0; i-- {
				stack = append(stack, serializeStepDOM{node: nd.children[i]})
			}
		case nodeTextDOM:
			if nd.parent != nil && nd.parent.kind == nodeElementDOM && rawTextSerializerParentsDOM[nd.parent.name] {
				sb.WriteString(nd.data)
			} else {
				writeEscapedTextDataDOM(&sb, nd.data)
			}
		case nodeElementDOM:
			sb.WriteByte('<')
			sb.WriteString(nd.name)
			for _, k := range nd.attrOrder {
				v := nd.attribs[k]
				sb.WriteByte(' ')
				sb.WriteString(k)
				sb.WriteString(`="`)
				writeEscapedAttrValDOM(&sb, v)
				sb.WriteByte('"')
			}
			sb.WriteByte('>')
			if voidTagsDOM[nd.name] {
				continue
			}
			stack = append(stack, serializeStepDOM{closingTag: nd.name})
			for i := len(nd.children) - 1; i >= 0; i-- {
				stack = append(stack, serializeStepDOM{node: nd.children[i]})
			}
		}
	}
	return sb.String()
}

// ── Public HTMLNode & HTMLDoc API ───────────────────────────────────────────────────────────────

// HTMLNode wraps a bounded DOM element or document root with linear-time CSS selection and extraction helpers.
type HTMLNode struct {
	tag    string
	node   *domNodeDOM
	budget *visitBudgetDOM
}

// HTMLDoc represents a parsed bounded HTML5 document ready for linear-time CSS querying.
type HTMLDoc struct {
	HTMLNode
}

// Tag returns the lowercase HTML tag name for element nodes, or "" for the document root.
func (n *HTMLNode) Tag() string {
	if n == nil {
		return ""
	}
	return n.tag
}

// Select returns up to limit matching descendant HTMLNodes in DOM document order (capped at 5,000).
func (n *HTMLNode) Select(selector string, limit int) []*HTMLNode {
	if n == nil || n.node == nil || limit <= 0 || n.budget == nil || n.budget.remaining <= 0 {
		return []*HTMLNode{}
	}
	cappedLimit := limit
	if cappedLimit > maxSelectLimitDOM {
		cappedLimit = maxSelectLimitDOM
	}
	chains, ok := parseSelectorDOM(selector)
	if !ok {
		return []*HTMLNode{}
	}

	memosByChain := make([]chainMemoDOM, len(chains))
	for g, c := range chains {
		stepMaps := make([]map[*domNodeDOM]bool, len(c))
		ancMaps := make([]map[*domNodeDOM]bool, len(c))
		for sIdx := range c {
			stepMaps[sIdx] = make(map[*domNodeDOM]bool)
			ancMaps[sIdx] = make(map[*domNodeDOM]bool)
		}
		memosByChain[g] = chainMemoDOM{step: stepMaps, anc: ancMaps}
	}

	results := make([]*HTMLNode, 0, 8)
	walkSubtreeElementsDOM(n.node, n.budget, func(el *domNodeDOM) walkDirectiveDOM {
		for g, steps := range chains {
			if matchesChainAtStepDOM(el, steps, len(steps)-1, n.node, &memosByChain[g]) {
				results = append(results, &HTMLNode{
					tag:    el.name,
					node:   el,
					budget: n.budget,
				})
				if len(results) >= cappedLimit {
					return walkStopDOM
				}
				break
			}
		}
		return walkContinueDOM
	})
	return results
}

// First returns the first matching descendant HTMLNode, or nil if none match.
func (n *HTMLNode) First(selector string) *HTMLNode {
	hits := n.Select(selector, 1)
	if len(hits) > 0 {
		return hits[0]
	}
	return nil
}

// Text returns clean text content (inserting spaces at block boundaries, stripping script/style/noscript/template/svg/xmp/plaintext/textarea,
// collapsing whitespace, and trimming). When subSelector is provided, reads from First(subSelector[0]).
func (n *HTMLNode) Text(subSelector ...string) string {
	if n == nil || n.node == nil || n.budget == nil {
		return ""
	}
	if len(subSelector) > 0 {
		target := n.First(subSelector[0])
		if target == nil {
			return ""
		}
		return target.Text()
	}
	return extractCleanNodeTextDOM(n.node, n.budget)
}

// HTML returns serialized inner HTML. When subSelector is provided, serializes the inner HTML of First(subSelector[0]).
func (n *HTMLNode) HTML(subSelector ...string) string {
	if n == nil || n.node == nil || n.budget == nil {
		return ""
	}
	if len(subSelector) > 0 {
		target := n.First(subSelector[0])
		if target == nil {
			return ""
		}
		return target.HTML()
	}
	if len(n.node.children) == 0 {
		return ""
	}
	if !chargeSerializeBudgetDOM(n.node.children, n.budget) {
		return ""
	}
	return serializeNodesDOM(n.node.children)
}

// OuterHTML returns serialized outer HTML of this node.
func (n *HTMLNode) OuterHTML() string {
	if n == nil || n.node == nil || n.budget == nil {
		return ""
	}
	single := []*domNodeDOM{n.node}
	if !chargeSerializeBudgetDOM(single, n.budget) {
		return ""
	}
	return serializeNodesDOM(single)
}

// Attr returns the value of attribute name (case-insensitive) and whether it exists on this element.
func (n *HTMLNode) Attr(name string) (string, bool) {
	if n == nil || n.node == nil || n.node.kind != nodeElementDOM || name == "" || n.node.attribs == nil {
		return "", false
	}
	v, ok := n.node.attribs[strings.ToLower(name)]
	return v, ok
}

// AttrOrEmpty returns the value of attribute name (case-insensitive), or "" if absent.
func (n *HTMLNode) AttrOrEmpty(name string) string {
	v, _ := n.Attr(name)
	return v
}

// AttrOf returns First(subSelector).AttrOrEmpty(name), or "" if absent.
func (n *HTMLNode) AttrOf(subSelector, name string) string {
	target := n.First(subSelector)
	if target == nil {
		return ""
	}
	return target.AttrOrEmpty(name)
}

// DLMap pairs <dt> -> following <dd> inside <dl> or wrapper containers, normalizing <dt> keys to lowercase trimmed strings with trailing colons stripped.
func (n *HTMLNode) DLMap(subSelector ...string) map[string]string {
	out := make(map[string]string)
	if n == nil || n.node == nil || n.budget == nil {
		return out
	}
	var containers []*HTMLNode
	if len(subSelector) > 0 {
		containers = n.Select(subSelector[0], 200)
	} else {
		containers = []*HTMLNode{n}
	}

	count := 0
	visits := 0
	seenElements := make(map[*domNodeDOM]bool)

	for _, container := range containers {
		if container == nil || container.node == nil {
			continue
		}
		if container.node.kind == nodeElementDOM && seenElements[container.node] {
			continue
		}
		pendingKey := ""
		walkSubtreeElementsDOM(container.node, n.budget, func(el *domNodeDOM) walkDirectiveDOM {
			visits++
			if visits > maxDLMapVisitsDOM {
				return walkStopDOM
			}
			seenElements[el] = true
			switch el.name {
			case "dt":
				pendingKey = stripTrailingColonsAndWhitespaceDOM(
					strings.ToLower(extractCleanNodeTextDOM(el, n.budget)),
				)
				return walkSkipDOM
			case "dd":
				if pendingKey != "" {
					val := extractCleanNodeTextDOM(el, n.budget)
					if val != "" {
						if _, exists := out[pendingKey]; !exists {
							out[pendingKey] = val
							count++
							if count >= 200 {
								return walkStopDOM
							}
						}
					}
					pendingKey = ""
				}
				return walkSkipDOM
			default:
				return walkContinueDOM
			}
		})
		if count >= 200 || visits > maxDLMapVisitsDOM || n.budget.remaining <= 0 {
			break
		}
	}
	return out
}

// TableRows extracts a 2D slice of cleaned cell text from <tr> -> <th>/<td> rows.
func (n *HTMLNode) TableRows(subSelector ...string) [][]string {
	if n == nil || n.node == nil || n.budget == nil {
		return [][]string{}
	}
	target := n
	if len(subSelector) > 0 {
		target = n.First(subSelector[0])
		if target == nil {
			return [][]string{}
		}
	}

	rows := make([][]string, 0)
	rootIsTable := target.node.kind == nodeElementDOM && target.node.name == "table"

	walkSubtreeElementsDOM(target.node, n.budget, func(el *domNodeDOM) walkDirectiveDOM {
		if rootIsTable && el.name == "table" {
			return walkSkipDOM
		}
		if el.name != "tr" {
			return walkContinueDOM
		}
		var cells []string
		hasNonEmpty := false
		for _, child := range el.children {
			if child.kind != nodeElementDOM {
				continue
			}
			if child.name == "td" || child.name == "th" {
				txt := extractCleanNodeTextDOM(child, n.budget)
				if txt != "" {
					hasNonEmpty = true
				}
				cells = append(cells, txt)
			}
		}
		if len(cells) > 0 && hasNonEmpty {
			rows = append(rows, cells)
			if len(rows) >= 500 {
				return walkStopDOM
			}
		}
		if rootIsTable {
			return walkSkipDOM
		}
		return walkContinueDOM
	})

	return rows
}

// ParseHTMLDoc parses rawHTML (capped at maxChars, defaulting to 2 MiB with a 4 MiB hard ceiling) into a linear-time queryable HTMLDoc.
func ParseHTMLDoc(rawHTML string, maxChars int) *HTMLDoc {
	effectiveMax := DefaultMaxHTMLDocChars
	if maxChars > 0 {
		if maxChars > HardMaxHTMLDocChars {
			effectiveMax = HardMaxHTMLDocChars
		} else {
			effectiveMax = maxChars
		}
	}
	safeHTML := rawHTML
	if len(safeHTML) > effectiveMax {
		cut := effectiveMax
		floor := effectiveMax - 3
		if floor < 0 {
			floor = 0
		}
		for cut > floor && (safeHTML[cut]&0xC0) == 0x80 {
			cut--
		}
		safeHTML = safeHTML[:cut]
	}
	safeHTML = stripNULAndZeroEntitiesDOM(safeHTML)
	root := buildBoundedDocumentDOM(safeHTML)
	return &HTMLDoc{
		HTMLNode: HTMLNode{
			tag:    "",
			node:   root,
			budget: &visitBudgetDOM{remaining: maxDocTotalVisitsDOM},
		},
	}
}
