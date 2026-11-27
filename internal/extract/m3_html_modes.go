package extract

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func stripDropTagsLinearDeclHTML(rawHTML string, dropTags map[string]bool, maxChars int) string {
	if rawHTML == "" || len(dropTags) == 0 {
		return rawHTML
	}
	if maxChars <= 0 {
		maxChars = HardMaxHTMLDocChars
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, maxChars)
	var chunks []string
	lastKeep := 0
	skipTag := ""
	skipDepth := 0
	skipStart := 0

	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		tLower := tag.tagNameLower
		isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tLower] || tag.isSelfClosing)
		if skipDepth > 0 {
			if tLower == skipTag {
				if tag.isClosing {
					skipDepth--
					if skipDepth == 0 {
						lastKeep = tag.end
					}
				} else if !isSelf {
					skipDepth++
				}
			}
			return true
		}
		if !tag.isClosing && dropTags[tLower] {
			chunks = append(chunks, src[lastKeep:tag.index])
			if isSelf {
				lastKeep = tag.end
			} else {
				skipTag = tLower
				skipDepth = 1
				skipStart = tag.index
			}
		}
		return true
	}, maxChars, true)

	if len(chunks) == 0 && skipDepth == 0 {
		return src
	}
	if skipDepth > 0 {
		// Unclosed drop tag: drop everything from skipStart onward for safety on <script>/<style>.
		_ = skipStart
	} else if lastKeep < len(src) {
		chunks = append(chunks, src[lastKeep:])
	}
	return strings.Join(chunks, "")
}

func stripTagsByClassLinearDeclHTML(rawHTML string, dropClasses map[string]bool, maxChars int) string {
	if rawHTML == "" || len(dropClasses) == 0 {
		return rawHTML
	}
	if maxChars <= 0 {
		maxChars = HardMaxHTMLDocChars
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, maxChars)
	var chunks []string
	lastKeep := 0
	skipTag := ""
	skipDepth := 0
	skipStart := 0

	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		tLower := tag.tagNameLower
		isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tLower] || tag.isSelfClosing)
		if skipDepth > 0 {
			if tLower == skipTag {
				if tag.isClosing {
					skipDepth--
					if skipDepth == 0 {
						lastKeep = tag.end
					}
				} else if !isSelf {
					skipDepth++
				}
			}
			return true
		}
		if !tag.isClosing && tag.attrs != "" && indexFoldASCIIExtract(tag.attrs, "class") >= 0 {
			attrs := parseTagAttrsFullDocGo(tag.attrs)
			if cls := attrs["class"]; cls != "" {
				matched := false
				for _, tok := range strings.Fields(strings.ToLower(cls)) {
					if dropClasses[tok] {
						matched = true
						break
					}
				}
				if matched {
					chunks = append(chunks, src[lastKeep:tag.index])
					if isSelf {
						lastKeep = tag.end
					} else {
						skipTag = tLower
						skipDepth = 1
						skipStart = tag.index
					}
				}
			}
		}
		return true
	}, maxChars, true)

	if len(chunks) == 0 && skipDepth == 0 {
		return src
	}
	if skipDepth > 0 {
		chunks = append(chunks, src[skipStart:])
	} else if lastKeep < len(src) {
		chunks = append(chunks, src[lastKeep:])
	}
	return strings.Join(chunks, "")
}

func stripDataImageURIsDeclHTML(rawHTML string) string {
	if rawHTML == "" || indexFoldASCIIExtract(rawHTML, "data:image/") < 0 {
		return rawHTML
	}
	var sb strings.Builder
	sb.Grow(len(rawHTML) / 2)
	pos := 0
	n := len(rawHTML)
	for pos < n {
		rel := indexFoldASCIIExtract(rawHTML[pos:], "data:image/")
		if rel < 0 {
			sb.WriteString(rawHTML[pos:])
			break
		}
		start := pos + rel
		sb.WriteString(rawHTML[pos:start])
		end := start + len("data:image/")
		for end < n {
			c := rawHTML[end]
			if c == '"' || c == '\'' || c == ')' || c == '>' || c == '<' ||
				c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				break
			}
			end++
		}
		pos = end
	}
	return sb.String()
}

func isValidBoschSuspenseIDDeclHTML(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) || len(id) <= len(prefix) || len(id) > 64 {
		return false
	}
	for i := len(prefix); i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ':' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func parseBoschRCPairsDeclHTML(src string) (map[string]string, map[string]bool) {
	bToS := make(map[string]string)
	refS := make(map[string]bool)
	pos := 0
	n := len(src)
	for pos < n && len(bToS) < 64 {
		rel := strings.Index(src[pos:], "$RC(")
		if rel < 0 {
			break
		}
		p := pos + rel + 4
		for p < n && (src[p] == ' ' || src[p] == '\t' || src[p] == '\r' || src[p] == '\n') {
			p++
		}
		if p >= n || (src[p] != '"' && src[p] != '\'') {
			pos = p
			continue
		}
		q1 := src[p]
		p++
		bStart := p
		for p < n && p-bStart <= 64 && src[p] != q1 && src[p] != '<' && src[p] != '>' && src[p] != '\n' && src[p] != '\r' {
			p++
		}
		if p >= n || src[p] != q1 {
			pos = p
			continue
		}
		bID := src[bStart:p]
		p++
		for p < n && (src[p] == ' ' || src[p] == '\t' || src[p] == '\r' || src[p] == '\n') {
			p++
		}
		if p >= n || src[p] != ',' {
			pos = p
			continue
		}
		p++
		for p < n && (src[p] == ' ' || src[p] == '\t' || src[p] == '\r' || src[p] == '\n') {
			p++
		}
		if p >= n || (src[p] != '"' && src[p] != '\'') {
			pos = p
			continue
		}
		q2 := src[p]
		p++
		sStart := p
		for p < n && p-sStart <= 64 && src[p] != q2 && src[p] != '<' && src[p] != '>' && src[p] != '\n' && src[p] != '\r' {
			p++
		}
		if p >= n || src[p] != q2 {
			pos = p
			continue
		}
		sID := src[sStart:p]
		p++
		for p < n && (src[p] == ' ' || src[p] == '\t' || src[p] == '\r' || src[p] == '\n') {
			p++
		}
		if p >= n || src[p] != ')' {
			pos = p
			continue
		}
		pos = p + 1
		if isValidBoschSuspenseIDDeclHTML(bID, "B:") && isValidBoschSuspenseIDDeclHTML(sID, "S:") {
			if _, exists := bToS[bID]; !exists {
				bToS[bID] = sID
			}
			refS[sID] = true
		}
	}
	return bToS, refS
}

type boschSpanKindDeclHTML uint8

const (
	boschSpanTpl boschSpanKindDeclHTML = iota
	boschSpanSDiv
	boschSpanUnclosedS
)

type boschSpanEventDeclHTML struct {
	kind       boschSpanKindDeclHTML
	id         string
	openStart  int
	openEnd    int
	outerEnd   int
	innerStart int
	innerEnd   int
	sIdx       int
	closeDivs  int
}

func rescueBoschSuspenseSlotsDeclHTML(rawHTML string) string {
	if rawHTML == "" || !strings.Contains(rawHTML, "$RC(") {
		return rawHTML
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, HardMaxHTMLDocChars)
	bToS, refS := parseBoschRCPairsDeclHTML(src)

	type openTpl struct {
		evIdx int
		depth int
	}
	type openSDiv struct {
		evIdx             int
		depth             int
		fallbackInnerEnd  int
		fallbackCloseDivs int
		innerContDepth    map[string]int
	}

	var events []boschSpanEventDeclHTML
	var tplStack []openTpl
	var sStack []openSDiv
	sByID := make(map[string]int) // sID -> index in events
	skipTag := ""
	skipDepth := 0

	forceCloseSStack := func(limitIdx int) {
		for len(sStack) > 0 {
			top := sStack[len(sStack)-1]
			sStack = sStack[:len(sStack)-1]
			ev := &events[top.evIdx]
			endIdx := limitIdx
			cd := top.depth
			if top.fallbackInnerEnd >= ev.innerStart && top.fallbackInnerEnd < endIdx {
				endIdx = top.fallbackInnerEnd
				cd = top.fallbackCloseDivs
			}
			if endIdx >= ev.innerStart {
				ev.kind = boschSpanSDiv
				ev.innerEnd = endIdx
				ev.outerEnd = endIdx
				if cd < 1 {
					cd = 1
				}
				if cd > 256 {
					cd = 256
				}
				ev.closeDivs = cd
				if _, exists := sByID[ev.id]; !exists {
					sByID[ev.id] = top.evIdx
				}
			}
		}
	}

	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		if tag.isDeclaration {
			return true
		}
		tLower := tag.tagNameLower
		isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tLower] || tag.isSelfClosing)
		if skipDepth > 0 {
			if tLower == skipTag {
				if tag.isClosing {
					skipDepth--
					if skipDepth == 0 {
						skipTag = ""
					}
				} else if !isSelf && skipTag != "script" && skipTag != "style" {
					skipDepth++
				}
			}
			return true
		}
		if tLower == "script" || tLower == "style" || tLower == "noscript" || tLower == "svg" {
			if tLower == "script" && len(sStack) > 0 && !tag.isClosing && !isSelf {
				// Record fallback boundary before React $RC/$RV streaming scripts.
				lookEnd := tag.end + 4096
				if lookEnd > len(src) {
					lookEnd = len(src)
				}
				scriptSlice := src[tag.end:lookEnd]
				if closeRel := indexFoldASCIIExtract(scriptSlice, "</script"); closeRel >= 0 {
					scriptSlice = scriptSlice[:closeRel]
				}
				if strings.Contains(scriptSlice, "$RC(") || strings.Contains(scriptSlice, "$RV(") {
					for i := range sStack {
						if sStack[i].fallbackInnerEnd < 0 {
							sStack[i].fallbackInnerEnd = tag.index
							sStack[i].fallbackCloseDivs = sStack[i].depth
						}
					}
				}
			}
			if !tag.isClosing && !isSelf {
				skipTag = tLower
				skipDepth = 1
			}
			return true
		}

		// If an unclosed S:x div hits a structural outer boundary (</body>, </html>, or
		// an unmatched </main>), bound and rescue it before that boundary.
		if len(sStack) > 0 {
			if tag.isClosing && (tLower == "body" || tLower == "html") {
				forceCloseSStack(tag.index)
				return true
			}
			if tag.isClosing && tLower == "main" {
				allZero := true
				for i := range sStack {
					if sStack[i].innerContDepth["main"] > 0 {
						sStack[i].innerContDepth["main"]--
						allZero = false
					}
				}
				if allZero {
					forceCloseSStack(tag.index)
					return true
				}
			} else if !tag.isClosing && !isSelf && tLower == "main" {
				for i := range sStack {
					if sStack[i].innerContDepth == nil {
						sStack[i].innerContDepth = make(map[string]int, 4)
					}
					sStack[i].innerContDepth["main"]++
				}
			}
			if tag.isClosing && (tLower == "article" || tLower == "section" || tLower == "blockquote") {
				for i := range sStack {
					if sStack[i].innerContDepth[tLower] > 0 {
						sStack[i].innerContDepth[tLower]--
					}
				}
			} else if !tag.isClosing && !isSelf {
				switch tLower {
				case "article", "section", "blockquote":
					for i := range sStack {
						if sStack[i].innerContDepth == nil {
							sStack[i].innerContDepth = make(map[string]int, 4)
						}
						sStack[i].innerContDepth[tLower]++
					}
				case "footer", "aside":
					for i := range sStack {
						if sStack[i].fallbackInnerEnd < 0 &&
							sStack[i].innerContDepth["article"] == 0 &&
							sStack[i].innerContDepth["section"] == 0 &&
							sStack[i].innerContDepth["blockquote"] == 0 {
							sStack[i].fallbackInnerEnd = tag.index
							sStack[i].fallbackCloseDivs = sStack[i].depth
						}
					}
				}
			}
		}

		switch tLower {
		case "template":
			if tag.isClosing {
				if len(tplStack) > 0 {
					top := &tplStack[len(tplStack)-1]
					top.depth--
					if top.depth == 0 {
						events[top.evIdx].outerEnd = tag.end
						tplStack = tplStack[:len(tplStack)-1]
					}
				}
				return true
			}
			if len(tplStack) > 0 && !tag.isSelfClosing {
				tplStack[len(tplStack)-1].depth++
				return true
			}
			if tag.attrs != "" && indexFoldASCIIExtract(tag.attrs, "id") >= 0 {
				attrs := parseTagAttrsFullDocGo(tag.attrs)
				if id := attrs["id"]; isValidBoschSuspenseIDDeclHTML(id, "B:") && len(events) < 256 {
					evIdx := len(events)
					events = append(events, boschSpanEventDeclHTML{
						kind:      boschSpanTpl,
						id:        id,
						openStart: tag.index,
						openEnd:   tag.end,
						outerEnd:  -1,
					})
					if tag.isSelfClosing {
						events[evIdx].outerEnd = tag.end
					} else {
						tplStack = append(tplStack, openTpl{evIdx: evIdx, depth: 1})
					}
				}
			}
		case "div":
			if len(tplStack) > 0 {
				return true
			}
			if tag.isClosing {
				if len(sStack) > 0 {
					top := &sStack[len(sStack)-1]
					top.depth--
					if top.depth == 0 {
						ev := &events[top.evIdx]
						ev.kind = boschSpanSDiv
						if top.fallbackInnerEnd >= ev.innerStart {
							ev.innerEnd = top.fallbackInnerEnd
							ev.outerEnd = top.fallbackInnerEnd
							cd := top.fallbackCloseDivs
							if cd < 1 {
								cd = 1
							}
							if cd > 256 {
								cd = 256
							}
							ev.closeDivs = cd
						} else {
							ev.innerEnd = tag.index
							ev.outerEnd = tag.end
							ev.closeDivs = 1
						}
						if _, exists := sByID[ev.id]; !exists {
							sByID[ev.id] = top.evIdx
						}
						sStack = sStack[:len(sStack)-1]
					}
				}
				return true
			}
			matchedS := false
			if tag.attrs != "" && indexFoldASCIIExtract(tag.attrs, "id") >= 0 {
				attrs := parseTagAttrsFullDocGo(tag.attrs)
				id := attrs["id"]
				_, hasHidden := attrs["hidden"]
				if isValidBoschSuspenseIDDeclHTML(id, "S:") && (hasHidden || refS[id]) && len(events) < 256 {
					matchedS = true
					// A new S: slot starts at top level; bound any prior unclosed S: slot before it.
					if len(sStack) > 0 {
						forceCloseSStack(tag.index)
					}
					evIdx := len(events)
					events = append(events, boschSpanEventDeclHTML{
						kind:       boschSpanUnclosedS,
						id:         id,
						openStart:  tag.index,
						openEnd:    tag.end,
						innerStart: tag.end,
						outerEnd:   tag.end,
						sIdx:       evIdx,
						closeDivs:  1,
					})
					if !tag.isSelfClosing {
						sStack = append(sStack, openSDiv{evIdx: evIdx, depth: 1, fallbackInnerEnd: -1, fallbackCloseDivs: 1})
					}
				}
			}
			if !matchedS && len(sStack) > 0 && !tag.isSelfClosing {
				sStack[len(sStack)-1].depth++
			}
		}
		return true
	}, HardMaxHTMLDocChars, true)

	if len(sStack) > 0 {
		forceCloseSStack(len(src))
	}

	if len(events) == 0 {
		return src
	}

	// Filter out unclosed <template id="B:..."> (outerEnd < 0); keep complete templates and S: divs.
	filtered := events[:0]
	idxMap := make(map[int]int, len(events))
	for i, ev := range events {
		if ev.kind == boschSpanTpl && ev.outerEnd < 0 {
			continue
		}
		idxMap[i] = len(filtered)
		filtered = append(filtered, ev)
	}
	events = filtered
	if len(events) == 0 {
		return src
	}
	for id, oldIdx := range sByID {
		if newIdx, ok := idxMap[oldIdx]; ok {
			sByID[id] = newIdx
		} else {
			delete(sByID, id)
		}
	}

	// Precompute which S: divs are consumed by a B: template substitution.
	tplTargetS := make(map[int]int) // tpl event index -> S event index
	consumedS := make(map[int]bool) // S event index -> consumed
	usedS := make(map[int]bool)     // guard against multiple B: slots duplicating a single S: div
	for i, ev := range events {
		if ev.kind != boschSpanTpl {
			continue
		}
		sID := bToS[ev.id]
		if sID == "" {
			cand := "S:" + strings.TrimPrefix(ev.id, "B:")
			if _, ok := sByID[cand]; ok {
				sID = cand
			}
		}
		if sID == "" {
			continue
		}
		sIdx, ok := sByID[sID]
		if !ok || usedS[sIdx] {
			continue
		}
		sEv := events[sIdx]
		// Prevent cycle if template is physically inside its own target S: div.
		if ev.openStart >= sEv.innerStart && ev.outerEnd <= sEv.innerEnd {
			continue
		}
		usedS[sIdx] = true
		consumedS[sIdx] = true
		tplTargetS[i] = sIdx
	}

	var sb strings.Builder
	sb.Grow(len(src))
	visitingS := make(map[int]bool)
	writeBounded := func(s string) {
		if sb.Len() >= HardMaxHTMLDocChars {
			return
		}
		rem := HardMaxHTMLDocChars - sb.Len()
		if len(s) > rem {
			sb.WriteString(truncateUTF8SafeFullDocGo(s, rem))
			return
		}
		sb.WriteString(s)
	}

	var emitRange func(start, end, depth int)
	emitRange = func(start, end, depth int) {
		if sb.Len() >= HardMaxHTMLDocChars || start >= end {
			return
		}
		cur := start
		startEv := sort.Search(len(events), func(i int) bool {
			return events[i].openStart >= start
		})
		for i := startEv; i < len(events); i++ {
			ev := events[i]
			if ev.openStart >= end {
				break
			}
			if ev.openStart < cur || ev.outerEnd > end {
				continue
			}
			if ev.openStart > cur {
				writeBounded(src[cur:ev.openStart])
			}
			switch ev.kind {
			case boschSpanTpl:
				if sIdx, ok := tplTargetS[i]; ok && depth < 8 && !visitingS[sIdx] {
					sEv := events[sIdx]
					visitingS[sIdx] = true
					writeBounded(`<div id="`)
					writeBounded(sEv.id)
					writeBounded(`" data-ef-suspense="1">`)
					emitRange(sEv.innerStart, sEv.innerEnd, depth+1)
					cd := sEv.closeDivs
					if cd < 1 {
						cd = 1
					}
					writeBounded(strings.Repeat("</div>", cd))
					delete(visitingS, sIdx)
				}
				cur = ev.outerEnd
			case boschSpanSDiv:
				if consumedS[i] {
					cur = ev.outerEnd
				} else {
					writeBounded(`<div id="`)
					writeBounded(ev.id)
					writeBounded(`" data-ef-suspense="1">`)
					emitRange(ev.innerStart, ev.innerEnd, depth+1)
					cd := ev.closeDivs
					if cd < 1 {
						cd = 1
					}
					writeBounded(strings.Repeat("</div>", cd))
					cur = ev.outerEnd
				}
			case boschSpanUnclosedS:
				writeBounded(`<div id="`)
				writeBounded(ev.id)
				writeBounded(`" data-ef-suspense="1">`)
				cur = ev.openEnd
			}
			if sb.Len() >= HardMaxHTMLDocChars {
				return
			}
		}
		if cur < end {
			writeBounded(src[cur:end])
		}
	}

	emitRange(0, len(src), 0)
	return sb.String()
}

// RawElementSelector describes a simple tag/id/class/attribute selector for
// slicing raw HTML without decoding entities via x/net/html.
type RawElementSelector struct {
	Tag        string
	ID         string
	Class      string
	Attr       string
	Val        string
	AttrSubstr string
}

type rawElementSpanDeclHTML struct {
	html  string
	start int
	end   int
}

func matchesRawElemSelectorStructDeclHTML(tag scannedTagFullDocGo, sel RawElementSelector) bool {
	if tag.isClosing || tag.isSelfClosing || tag.isDeclaration || voidHTMLTagsFullDocGo[tag.tagNameLower] {
		return false
	}
	if sel.Tag != "" && tag.tagNameLower != sel.Tag {
		return false
	}
	if sel.Class != "" && !hasClassTokenFullDocGo(tag.attrs, strings.ToLower(sel.Class)) {
		return false
	}
	if sel.ID != "" {
		if indexFoldASCIIExtract(tag.attrs, "id") < 0 {
			return false
		}
		attrs := parseTagAttrsFullDocGo(tag.attrs)
		if strings.TrimSpace(attrs["id"]) != sel.ID {
			return false
		}
	}
	if sel.Attr != "" {
		if indexFoldASCIIExtract(tag.attrs, sel.Attr) < 0 {
			return false
		}
		attrs := parseTagAttrsFullDocGo(tag.attrs)
		if sel.Val != "" {
			if !strings.EqualFold(strings.TrimSpace(attrs[sel.Attr]), sel.Val) {
				return false
			}
		} else if sel.AttrSubstr != "" {
			if indexFoldASCIIExtract(attrs[sel.Attr], sel.AttrSubstr) < 0 {
				return false
			}
		} else if _, ok := attrs[sel.Attr]; !ok {
			return false
		}
	}
	return true
}

func matchesRawElemSelectorDeclHTML(tag scannedTagFullDocGo, tagFilter, classFilterLower, attrKey, attrVal string) bool {
	return matchesRawElemSelectorStructDeclHTML(tag, RawElementSelector{
		Tag:   tagFilter,
		Class: classFilterLower,
		Attr:  attrKey,
		Val:   attrVal,
	})
}

// ExtractFirstRawElementHTML returns the raw outer HTML slice of the first balanced
// element matching any selector in selectors in document order (comment-aware,
// quote-aware, void-tag-safe, skipping <script>/<style>/<noscript>/<template>/<svg>).
// Returns ("", false) when no selector matches or tags are unbalanced.
func ExtractFirstRawElementHTML(rawHTML string, selectors ...RawElementSelector) (string, bool) {
	sp, ok := extractFirstRawElementHTMLInternal(rawHTML, false, selectors...)
	return sp.html, ok
}

// ExtractFirstRawElementOrBoundedHTML behaves like ExtractFirstRawElementHTML when
// the matched element is balanced, and on unbalanced inner tags slices raw HTML from
// the matched opening tag up to the next enclosing ancestor closing tag (e.g., </main>,
// </section>, </article>, </body>), structural sibling boundary (<footer, <aside), or
// bounded EOF, without x/net/html round-tripping.
func ExtractFirstRawElementOrBoundedHTML(rawHTML string, selectors ...RawElementSelector) (string, bool) {
	sp, ok := extractFirstRawElementHTMLInternal(rawHTML, true, selectors...)
	return sp.html, ok
}

func extractFirstRawElementSpanOrBoundedDeclHTML(rawHTML string, selectors ...RawElementSelector) (rawElementSpanDeclHTML, bool) {
	return extractFirstRawElementHTMLInternal(rawHTML, true, selectors...)
}

func extractFirstRawElementHTMLInternal(rawHTML string, allowBoundedFallback bool, selectors ...RawElementSelector) (rawElementSpanDeclHTML, bool) {
	if rawHTML == "" || len(selectors) == 0 {
		return rawElementSpanDeclHTML{}, false
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, HardMaxHTMLDocChars)
	matchTag := ""
	depth := 0
	startIdx := -1
	endIdx := -1
	enclosingEndIdx := -1
	siblingBoundaryIdx := -1
	skipTag := ""
	skipDepth := 0
	var innerContainerDepth map[string]int
	if allowBoundedFallback {
		innerContainerDepth = make(map[string]int, 8)
	}

	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		if tag.isDeclaration {
			return true
		}
		tLower := tag.tagNameLower
		isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tLower] || tag.isSelfClosing)
		if skipDepth > 0 {
			if tLower == skipTag {
				if tag.isClosing {
					skipDepth--
					if skipDepth == 0 {
						skipTag = ""
					}
				} else if !isSelf {
					skipDepth++
				}
			}
			return true
		}
		if tLower == "script" || tLower == "style" || tLower == "noscript" || tLower == "template" || tLower == "svg" {
			if !tag.isClosing && !isSelf {
				skipTag = tLower
				skipDepth = 1
			}
			return true
		}
		if depth == 0 {
			for _, sel := range selectors {
				if matchesRawElemSelectorStructDeclHTML(tag, sel) {
					matchTag = tLower
					startIdx = tag.index
					depth = 1
					return true
				}
			}
			return true
		}
		if tLower == matchTag {
			if tag.isClosing {
				depth--
				if depth == 0 {
					endIdx = tag.end
					return false
				}
			} else if !isSelf {
				depth++
			}
			return true
		}
		if allowBoundedFallback {
			if tag.isClosing {
				switch tLower {
				case "main", "section", "article", "body", "html", "form", "aside", "footer", "header", "nav":
					if innerContainerDepth[tLower] > 0 {
						innerContainerDepth[tLower]--
					} else {
						enclosingEndIdx = tag.index
						return false
					}
				case "blockquote":
					if innerContainerDepth[tLower] > 0 {
						innerContainerDepth[tLower]--
					}
				}
			} else if !isSelf {
				switch tLower {
				case "footer", "aside":
					if siblingBoundaryIdx < 0 && innerContainerDepth["article"] == 0 && innerContainerDepth["section"] == 0 && innerContainerDepth["blockquote"] == 0 {
						siblingBoundaryIdx = tag.index
					}
					innerContainerDepth[tLower]++
				case "main", "section", "article", "body", "html", "form", "header", "nav", "blockquote":
					innerContainerDepth[tLower]++
				}
			}
		}
		return true
	}, HardMaxHTMLDocChars, true)

	if startIdx >= 0 && endIdx > startIdx {
		return rawElementSpanDeclHTML{html: src[startIdx:endIdx], start: startIdx, end: endIdx}, true
	}
	if allowBoundedFallback && startIdx >= 0 {
		boundedEnd := -1
		if enclosingEndIdx > startIdx {
			boundedEnd = enclosingEndIdx
		}
		if siblingBoundaryIdx > startIdx && (boundedEnd < 0 || siblingBoundaryIdx < boundedEnd) {
			boundedEnd = siblingBoundaryIdx
		}
		if boundedEnd > startIdx {
			return rawElementSpanDeclHTML{html: src[startIdx:boundedEnd], start: startIdx, end: boundedEnd}, true
		}
		if len(src) > startIdx {
			return rawElementSpanDeclHTML{html: src[startIdx:], start: startIdx, end: len(src)}, true
		}
	}
	return rawElementSpanDeclHTML{}, false
}

func extractFirstRawElementSliceDeclHTML(src, tagFilter, classFilterLower, attrKey, attrVal string) (rawElementSpanDeclHTML, bool) {
	if src == "" {
		return rawElementSpanDeclHTML{}, false
	}
	matchTag := ""
	depth := 0
	startIdx := -1
	endIdx := -1
	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		if tag.isDeclaration {
			return true
		}
		if depth == 0 {
			if matchesRawElemSelectorDeclHTML(tag, tagFilter, classFilterLower, attrKey, attrVal) {
				matchTag = tag.tagNameLower
				startIdx = tag.index
				depth = 1
			}
			return true
		}
		if tag.tagNameLower == matchTag {
			if tag.isClosing {
				depth--
				if depth == 0 {
					endIdx = tag.end
					return false
				}
			} else if !tag.isSelfClosing && !voidHTMLTagsFullDocGo[tag.tagNameLower] {
				depth++
			}
		}
		return true
	}, HardMaxHTMLDocChars, true)
	if startIdx >= 0 && endIdx > startIdx {
		return rawElementSpanDeclHTML{html: src[startIdx:endIdx], start: startIdx, end: endIdx}, true
	}
	return rawElementSpanDeclHTML{}, false
}

func extractAllTopLevelRawElementSlicesDeclHTML(src, tagFilter, classFilterLower, attrKey, attrVal string, limit int) []rawElementSpanDeclHTML {
	if src == "" || limit <= 0 {
		return nil
	}
	var out []rawElementSpanDeclHTML
	matchTag := ""
	depth := 0
	startIdx := -1
	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		if tag.isDeclaration {
			return true
		}
		if depth == 0 {
			if matchesRawElemSelectorDeclHTML(tag, tagFilter, classFilterLower, attrKey, attrVal) {
				matchTag = tag.tagNameLower
				startIdx = tag.index
				depth = 1
			}
			return true
		}
		if tag.tagNameLower == matchTag {
			if tag.isClosing {
				depth--
				if depth == 0 {
					out = append(out, rawElementSpanDeclHTML{html: src[startIdx:tag.end], start: startIdx, end: tag.end})
					if len(out) >= limit {
						return false
					}
					matchTag = ""
					startIdx = -1
				}
			} else if !tag.isSelfClosing && !voidHTMLTagsFullDocGo[tag.tagNameLower] {
				depth++
			}
		}
		return true
	}, HardMaxHTMLDocChars, true)
	return out
}

func extractAllTopLevelRawElementSlicesOrBoundedDeclHTML(src, tagFilter, classFilterLower, attrKey, attrVal string, limit int, flushOnNestedMatch bool) []rawElementSpanDeclHTML {
	if src == "" || limit <= 0 {
		return nil
	}
	var out []rawElementSpanDeclHTML
	matchTag := ""
	depth := 0
	startIdx := -1
	siblingBoundaryIdx := -1
	skipTag := ""
	skipDepth := 0
	innerContainerDepth := make(map[string]int, 8)
	sel := RawElementSelector{Tag: tagFilter, Class: classFilterLower, Attr: attrKey, Val: attrVal}

	flushBounded := func(limitIdx int) {
		if startIdx < 0 {
			return
		}
		endIdx := limitIdx
		if siblingBoundaryIdx > startIdx && (endIdx < 0 || siblingBoundaryIdx < endIdx) {
			endIdx = siblingBoundaryIdx
		}
		if endIdx > startIdx {
			out = append(out, rawElementSpanDeclHTML{html: src[startIdx:endIdx], start: startIdx, end: endIdx})
		}
		matchTag = ""
		depth = 0
		startIdx = -1
		siblingBoundaryIdx = -1
		for k := range innerContainerDepth {
			delete(innerContainerDepth, k)
		}
	}

	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		if tag.isDeclaration {
			return true
		}
		tLower := tag.tagNameLower
		isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tLower] || tag.isSelfClosing)
		if skipDepth > 0 {
			if tLower == skipTag {
				if tag.isClosing {
					skipDepth--
					if skipDepth == 0 {
						skipTag = ""
					}
				} else if !isSelf {
					skipDepth++
				}
			}
			return true
		}
		if tLower == "script" || tLower == "style" || tLower == "noscript" || tLower == "template" || tLower == "svg" {
			if !tag.isClosing && !isSelf {
				skipTag = tLower
				skipDepth = 1
			}
			return true
		}
		if depth == 0 {
			if matchesRawElemSelectorStructDeclHTML(tag, sel) {
				matchTag = tLower
				startIdx = tag.index
				depth = 1
				siblingBoundaryIdx = -1
			}
			return true
		}
		if flushOnNestedMatch && !tag.isClosing && !isSelf && tLower == matchTag && matchesRawElemSelectorStructDeclHTML(tag, sel) {
			flushBounded(tag.index)
			if len(out) >= limit {
				return false
			}
			matchTag = tLower
			startIdx = tag.index
			depth = 1
			return true
		}
		if tLower == matchTag {
			if tag.isClosing {
				depth--
				if depth == 0 {
					out = append(out, rawElementSpanDeclHTML{html: src[startIdx:tag.end], start: startIdx, end: tag.end})
					if len(out) >= limit {
						return false
					}
					matchTag = ""
					startIdx = -1
					siblingBoundaryIdx = -1
					for k := range innerContainerDepth {
						delete(innerContainerDepth, k)
					}
				}
			} else if !isSelf {
				depth++
			}
			return true
		}
		if tag.isClosing {
			switch tLower {
			case "main", "section", "article", "body", "html", "form", "aside", "footer", "header", "nav":
				if innerContainerDepth[tLower] > 0 {
					innerContainerDepth[tLower]--
				} else {
					flushBounded(tag.index)
					if len(out) >= limit {
						return false
					}
				}
			case "blockquote":
				if innerContainerDepth[tLower] > 0 {
					innerContainerDepth[tLower]--
				}
			}
		} else if !isSelf {
			switch tLower {
			case "footer", "aside":
				if siblingBoundaryIdx < 0 && innerContainerDepth["article"] == 0 && innerContainerDepth["section"] == 0 && innerContainerDepth["blockquote"] == 0 {
					siblingBoundaryIdx = tag.index
				}
				innerContainerDepth[tLower]++
			case "main", "section", "article", "body", "html", "form", "header", "nav", "blockquote":
				innerContainerDepth[tLower]++
			}
		}
		return true
	}, HardMaxHTMLDocChars, true)

	if depth > 0 && startIdx >= 0 && len(out) < limit {
		flushBounded(len(src))
	}
	return out
}

func extractRawTitleBySelectorsDeclHTML(rawHTML string, doc *HTMLDoc, specs []RawElementSelector, cssFallbacks []string) string {
	for idx, spec := range specs {
		slices := extractAllTopLevelRawElementSlicesDeclHTML(rawHTML, spec.Tag, spec.Class, spec.Attr, spec.Val, 8)
		for _, sp := range slices {
			if t := SanitizeScrapedMeta(stripTagsInlineEscapingBracketEntitiesGo(sp.html)); t != "" {
				return t
			}
		}
		if doc != nil && idx < len(cssFallbacks) && cssFallbacks[idx] != "" {
			if rawText := strings.TrimSpace(doc.Text(cssFallbacks[idx])); rawText != "" {
				if t := SanitizeScrapedMeta(escapeMarkdownLinkLabelGo(rawText)); t != "" {
					return t
				}
			}
		}
	}
	return ""
}

func extractRawMetaTitleEscapingBracketsDeclHTML(rawHTML, key string) string {
	if indexFoldASCIIExtract(rawHTML, "<meta") < 0 {
		return ""
	}
	targetKey := strings.ToLower(key)
	result := ""
	scanHTMLTagsLinearFullDocGo(rawHTML, func(tag scannedTagFullDocGo) bool {
		if tag.isDeclaration || tag.isClosing || tag.tagNameLower != "meta" {
			return true
		}
		attrs := parseHTMLTagAttrsGo(tag.attrs)
		nameVal := attrs["name"]
		if nameVal == "" {
			nameVal = attrs["property"]
		}
		if nameVal == "" {
			nameVal = attrs["itemprop"]
		}
		if strings.ToLower(nameVal) == targetKey && attrs["content"] != "" {
			decoded := decodeMarkdownEntitiesEscapingLinkBracketsPreservingLtGo(strings.TrimSpace(attrs["content"]))
			if clean := SanitizeScrapedMeta(decoded); clean != "" {
				result = clean
				return false
			}
		}
		return true
	}, 120_000, true)
	return result
}

func formatXenForoQuoteBlockDeclHTML(quoteInnerHTML string, ctx *htmlExtractContextDeclHTML) string {
	cleanQuote := stripTagsByClassLinearDeclHTML(quoteInnerHTML, map[string]bool{
		"bbcodeblock-expandlink": true,
	}, 256*1024)
	qDoc := ParseHTMLDoc(cleanQuote, 256*1024)
	quoteTitle := ""
	if sp, ok := extractFirstRawElementSliceDeclHTML(cleanQuote, "", "bbcodeblock-title", "", ""); ok {
		quoteTitle = SanitizeScrapedMeta(stripTagsInlineEscapingBracketEntitiesGo(sp.html))
	} else if titleNode := qDoc.First(".bbCodeBlock-title"); titleNode != nil {
		quoteTitle = SanitizeScrapedMeta(escapeMarkdownLinkLabelGo(titleNode.Text()))
	}
	contentHTML := ""
	if rawExp, ok := ExtractFirstRawElementOrBoundedHTML(cleanQuote, RawElementSelector{Class: "bbcodeblock-expandcontent"}); ok {
		contentHTML = rawExp
	} else if rawCnt, ok := ExtractFirstRawElementOrBoundedHTML(cleanQuote, RawElementSelector{Class: "bbcodeblock-content"}); ok {
		contentHTML = rawCnt
	} else {
		contentHTML = cleanQuote
	}
	qMD, _ := ctx.htmlToMD(contentHTML, ctx.baseURL)
	qMD = strings.TrimSpace(qMD)
	if qMD == "" && quoteTitle == "" {
		return ""
	}
	var lines []string
	if quoteTitle != "" {
		lines = append(lines, "> **"+escapeMarkdownBracketsOnlyGo(quoteTitle)+"**")
	}
	if qMD != "" {
		for _, ln := range strings.Split(qMD, "\n") {
			tr := strings.TrimRight(ln, " \t\r")
			if tr == "" {
				lines = append(lines, ">")
			} else {
				lines = append(lines, "> "+tr)
			}
		}
	}
	return strings.Join(lines, "\n")
}

func convertXenForoBodyDeclHTML(bbHTML string, ctx *htmlExtractContextDeclHTML) (string, []string) {
	if strings.TrimSpace(bbHTML) == "" {
		return "", nil
	}
	if indexFoldASCIIExtract(bbHTML, "<blockquote") < 0 {
		return ctx.htmlToMD(bbHTML, ctx.baseURL)
	}
	type blockRange struct{ start, end, innerStart, innerEnd int }
	var blocks []blockRange
	depth := 0
	startIdx := 0
	innerStart := 0
	scanHTMLTagsLinearFullDocGo(bbHTML, func(tag scannedTagFullDocGo) bool {
		if tag.isDeclaration {
			return true
		}
		if tag.tagNameLower == "blockquote" {
			if !tag.isClosing && !tag.isSelfClosing {
				if depth == 0 {
					startIdx = tag.index
					innerStart = tag.end
				}
				depth++
			} else if tag.isClosing && depth > 0 {
				depth--
				if depth == 0 {
					blocks = append(blocks, blockRange{
						start:      startIdx,
						end:        tag.end,
						innerStart: innerStart,
						innerEnd:   tag.index,
					})
				}
			}
		}
		return true
	}, 512*1024, true)

	if len(blocks) == 0 {
		return ctx.htmlToMD(bbHTML, ctx.baseURL)
	}

	var mdParts []string
	var allLinks []string
	seenLink := make(map[string]bool)
	pushLinks := func(ls []string) {
		for _, l := range ls {
			if !seenLink[l] {
				seenLink[l] = true
				allLinks = append(allLinks, l)
			}
		}
	}

	cursor := 0
	for _, br := range blocks {
		if br.start > cursor {
			segHTML := bbHTML[cursor:br.start]
			if strings.TrimSpace(segHTML) != "" {
				segMD, segLinks := ctx.htmlToMD(segHTML, ctx.baseURL)
				pushLinks(segLinks)
				if tr := strings.TrimSpace(segMD); tr != "" {
					mdParts = append(mdParts, tr)
				}
			}
		}
		if br.innerEnd >= br.innerStart && br.innerEnd <= len(bbHTML) {
			inner := bbHTML[br.innerStart:br.innerEnd]
			if qFormatted := formatXenForoQuoteBlockDeclHTML(inner, ctx); qFormatted != "" {
				mdParts = append(mdParts, qFormatted)
			}
		}
		cursor = br.end
	}
	if cursor < len(bbHTML) {
		tailHTML := bbHTML[cursor:]
		if strings.TrimSpace(tailHTML) != "" {
			tailMD, tailLinks := ctx.htmlToMD(tailHTML, ctx.baseURL)
			pushLinks(tailLinks)
			if tr := strings.TrimSpace(tailMD); tr != "" {
				mdParts = append(mdParts, tr)
			}
		}
	}
	return strings.Join(mdParts, "\n\n"), allLinks
}

func runXenForoExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	lowPath := strings.ToLower(ctx.path)
	if strings.Contains(lowPath, "/forums/") ||
		strings.Contains(lowPath, "/forums-old/") ||
		strings.Contains(lowPath, "/sphere/search/") ||
		strings.Contains(lowPath, "/search/") {
		return nil
	}
	if !strings.Contains(ctx.rawHTML, "message--post") || !strings.Contains(ctx.rawHTML, "bbWrapper") {
		return nil
	}

	cleaned := stripDropTagsLinearDeclHTML(ctx.rawHTML, map[string]bool{
		"script": true, "style": true, "noscript": true, "template": true, "svg": true,
	}, HardMaxHTMLDocChars)
	cleaned = stripTagsByClassLinearDeclHTML(cleaned, map[string]bool{
		"p-body-sidebar":         true,
		"message-signature":      true,
		"bbcodeblock-expandlink": true,
		"reactionsbar":           true,
		"message-lastedit":       true,
		"message-footer":         true,
		"message-actionbar":      true,
		"message-attachments":    true,
		"js-selecttoquoteend":    true,
	}, HardMaxHTMLDocChars)

	doc := ParseHTMLDoc(cleaned, HardMaxHTMLDocChars)
	posts := doc.Select("article.message--post", 40)
	if len(posts) == 0 {
		return nil
	}

	threadTitle := extractRawTitleBySelectorsDeclHTML(
		cleaned,
		doc,
		[]RawElementSelector{
			{Tag: "h1", Class: "p-title-value"},
			{Tag: "h1"},
		},
		[]string{"h1.p-title-value", "h1"},
	)
	if threadTitle == "" {
		threadTitle = extractRawMetaTitleEscapingBracketsDeclHTML(ctx.rawHTML, "og:title")
	}
	if threadTitle == "" {
		threadTitle = extractRawTitleBySelectorsDeclHTML(
			cleaned,
			doc,
			[]RawElementSelector{{Tag: "title"}},
			[]string{"title"},
		)
	}
	if threadTitle == "" {
		threadTitle = "Forum Thread"
	}

	var sections []string
	sections = append(sections, "# "+escapeMarkdownBracketsOnlyGo(threadTitle))

	var postBlocks []string
	var records []map[string]any
	var collectedLinks []string
	seenLinks := make(map[string]bool)
	addLink := func(raw string) {
		resolved := resolveRelativeHTTPSURLDeclHTML(raw, ctx.u)
		if resolved != "" && !seenLinks[resolved] && len(collectedLinks) < 100 {
			seenLinks[resolved] = true
			collectedLinks = append(collectedLinks, resolved)
		}
	}
	addLink(ctx.baseURL)

	topAuthor := ""
	topPublished := ""
	replyNum := 0

	rawPosts := extractAllTopLevelRawElementSlicesOrBoundedDeclHTML(cleaned, "article", "message--post", "", "", 40, true)
	if len(rawPosts) == 0 {
		return nil
	}
	useAlignedPosts := len(rawPosts) == len(posts)

	for idx, rawPost := range rawPosts {
		var post *HTMLNode
		if useAlignedPosts {
			post = posts[idx]
		} else {
			pDoc := ParseHTMLDoc(rawPost.html, 256*1024)
			post = pDoc.First("article.message--post")
		}
		bbHTML, okBB := ExtractFirstRawElementOrBoundedHTML(rawPost.html,
			RawElementSelector{Tag: "div", Class: "bbwrapper"},
			RawElementSelector{Class: "bbwrapper"},
		)
		if !okBB || strings.TrimSpace(bbHTML) == "" {
			continue
		}
		bodyMD, postLinks := convertXenForoBodyDeclHTML(bbHTML, ctx)
		bodyMD = strings.TrimSpace(bodyMD)
		if bodyMD == "" {
			continue
		}
		for _, pl := range postLinks {
			if !seenLinks[pl] && len(collectedLinks) < 100 {
				seenLinks[pl] = true
				collectedLinks = append(collectedLinks, pl)
			}
		}

		author := ""
		if post != nil {
			author = SanitizeScrapedMeta(escapeMarkdownLinkLabelGo(post.AttrOrEmpty("data-author")))
		}
		if author == "" {
			if sp, ok := extractFirstRawElementSliceDeclHTML(rawPost.html, "", "message-name", "", ""); ok {
				author = SanitizeScrapedMeta(stripTagsInlineEscapingBracketEntitiesGo(sp.html))
			}
			if author == "" && post != nil {
				author = SanitizeScrapedMeta(escapeMarkdownLinkLabelGo(post.Text(".message-name")))
			}
		}
		if author == "" {
			author = "Member"
		}
		postID := ""
		if post != nil {
			postID = SanitizeScrapedMeta(post.AttrOrEmpty("data-content"))
			if postID == "" {
				postID = SanitizeScrapedMeta(post.AttrOrEmpty("id"))
			}
		}

		ts := ""
		var timeNode *HTMLNode
		if post != nil {
			timeNode = post.First("time.u-dt")
			if timeNode == nil {
				timeNode = post.First("time[datetime]")
			}
			if timeNode == nil {
				timeNode = post.First("time[data-time]")
			}
		}
		if timeNode != nil {
			if dt := strings.TrimSpace(timeNode.AttrOrEmpty("datetime")); dt != "" {
				ts = SanitizeScrapedMeta(dt)
			} else if epochStr := strings.TrimSpace(timeNode.AttrOrEmpty("data-time")); epochStr != "" {
				if sec, err := strconv.ParseInt(epochStr, 10, 64); err == nil && sec > 0 {
					ts = time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z")
				}
			}
			if ts == "" {
				ts = SanitizeScrapedMeta(timeNode.Text())
			}
		}

		safeAuthor := escapeMarkdownBracketsOnlyGo(author)
		safeTs := escapeMarkdownBracketsOnlyGo(ts)
		var heading string
		if idx == 0 {
			if safeTs != "" {
				heading = fmt.Sprintf("## Original Post — %s (%s)", safeAuthor, safeTs)
			} else {
				heading = fmt.Sprintf("## Original Post — %s", safeAuthor)
			}
			topAuthor = author
			topPublished = ts
		} else {
			replyNum++
			if safeTs != "" {
				heading = fmt.Sprintf("## Reply #%d — %s (%s)", replyNum, safeAuthor, safeTs)
			} else {
				heading = fmt.Sprintf("## Reply #%d — %s", replyNum, safeAuthor)
			}
		}
		postBlocks = append(postBlocks, heading+"\n\n"+bodyMD)
		rec := map[string]any{
			"author": author,
			"body":   bodyMD,
		}
		if postID != "" {
			rec["postId"] = postID
		}
		if ts != "" {
			rec["publishedAt"] = ts
		}
		records = append(records, rec)
	}

	if len(postBlocks) == 0 {
		return nil
	}

	if nextLink := doc.First("a.pageNav-jump--next"); nextLink != nil {
		addLink(nextLink.AttrOrEmpty("href"))
	}
	if canonLink := doc.First(`link[rel="canonical"]`); canonLink != nil {
		addLink(canonLink.AttrOrEmpty("href"))
	}

	sections = append(sections, strings.Join(postBlocks, "\n\n"))
	return &DeclarativePostFetchResult{
		ExtractorID:   extractorID,
		Title:         threadTitle,
		Author:        topAuthor,
		PublishedTime: topPublished,
		Markdown:      strings.Join(sections, "\n\n"),
		Links:         collectedLinks,
		Records:       records,
	}
}

func resolveRelativeHTTPSURLDeclHTML(raw string, base *url.URL) string {
	tr := strings.TrimSpace(raw)
	if tr == "" || base == nil {
		return ""
	}
	low := strings.ToLower(tr)
	if strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") ||
		strings.HasPrefix(low, "vbscript:") || strings.HasPrefix(low, "mailto:") || strings.HasPrefix(low, "tel:") {
		return ""
	}
	ref, err := url.Parse(tr)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	if resolved == nil || !strings.EqualFold(resolved.Scheme, "https") {
		return ""
	}
	resolved.Fragment = ""
	out := resolved.String()
	if !isSafePublicHTTPSFeedURL(out) {
		return ""
	}
	return out
}

func extractRawElemsInsideContainersDeclHTML(rawHTML string, containerSpecs []RawElementSelector, itemTags map[string]bool, limit int) []string {
	if rawHTML == "" || limit <= 0 {
		return nil
	}
	matchTag := ""
	cDepth := 0
	cStart := -1
	var containers []string
	scanHTMLTagsLinearFullDocGo(rawHTML, func(tag scannedTagFullDocGo) bool {
		if tag.isDeclaration {
			return true
		}
		if cDepth == 0 {
			for _, spec := range containerSpecs {
				if matchesRawElemSelectorStructDeclHTML(tag, spec) {
					matchTag = tag.tagNameLower
					cStart = tag.index
					cDepth = 1
					return true
				}
			}
			return true
		}
		if tag.tagNameLower == matchTag {
			if tag.isClosing {
				cDepth--
				if cDepth == 0 {
					containers = append(containers, rawHTML[cStart:tag.end])
					matchTag = ""
					cStart = -1
					if len(containers) >= 8 {
						return false
					}
				}
			} else if !tag.isSelfClosing && !voidHTMLTagsFullDocGo[tag.tagNameLower] {
				cDepth++
			}
		}
		return true
	}, HardMaxHTMLDocChars, true)

	var out []string
	for _, cHTML := range containers {
		type openRec struct {
			tagLower string
			start    int
			depth    int
			outIdx   int
		}
		var stack []openRec
		scanHTMLTagsLinearFullDocGo(cHTML, func(tag scannedTagFullDocGo) bool {
			if tag.isDeclaration {
				return true
			}
			tLower := tag.tagNameLower
			isSelf := !tag.isClosing && (tag.isSelfClosing || voidHTMLTagsFullDocGo[tLower])
			if !tag.isClosing && !isSelf && itemTags[tLower] && len(out) < limit {
				outIdx := len(out)
				out = append(out, "")
				stack = append(stack, openRec{tagLower: tLower, start: tag.index, depth: 1, outIdx: outIdx})
				return true
			}
			if len(stack) > 0 {
				for si := len(stack) - 1; si >= 0; si-- {
					if stack[si].tagLower == tLower {
						if tag.isClosing {
							stack[si].depth--
							if stack[si].depth == 0 {
								out[stack[si].outIdx] = cHTML[stack[si].start:tag.end]
								stack = append(stack[:si], stack[si+1:]...)
							}
						} else if !isSelf {
							stack[si].depth++
						}
						break
					}
				}
			}
			return true
		}, HardMaxHTMLDocChars, true)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func extractTechDocBreadcrumbsDeclHTML(rawHTML string, doc *HTMLDoc) string {
	var crumbs []string
	seen := make(map[string]bool)
	type crumbGroup struct {
		containers []RawElementSelector
		tags       map[string]bool
		fallback   string
	}
	groups := []crumbGroup{
		{
			containers: []RawElementSelector{{Class: "ft-breadcrumb"}},
			tags:       map[string]bool{"a": true, "span": true},
			fallback:   `.ft-breadcrumb a, .ft-breadcrumb span`,
		},
		{
			containers: []RawElementSelector{{Tag: "nav", Attr: "aria-label", AttrSubstr: "breadcrumb"}},
			tags:       map[string]bool{"a": true, "li": true, "span": true},
			fallback:   `nav[aria-label*="breadcrumb" i] a, nav[aria-label*="breadcrumb" i] li, nav[aria-label*="breadcrumb" i] span`,
		},
		{
			containers: []RawElementSelector{{Class: "breadcrumb"}},
			tags:       map[string]bool{"a": true, "li": true},
			fallback:   `.breadcrumb a, .breadcrumb li`,
		},
	}
	for _, g := range groups {
		rawElems := extractRawElemsInsideContainersDeclHTML(rawHTML, g.containers, g.tags, 24)
		for _, elHTML := range rawElems {
			if elHTML == "" {
				continue
			}
			t := SanitizeScrapedMeta(escapeMarkdownBracketsOnlyGo(stripTagsInlineEscapingBracketEntitiesGo(elHTML)))
			if t == "" || t == "/" || t == ">" || t == "›" || seen[t] {
				continue
			}
			seen[t] = true
			crumbs = append(crumbs, t)
		}
		if len(crumbs) == 0 && doc != nil {
			nodes := doc.Select(g.fallback, 24)
			for _, n := range nodes {
				t := SanitizeScrapedMeta(escapeMarkdownLinkLabelGo(n.Text()))
				if t == "" || t == "/" || t == ">" || t == "›" || seen[t] {
					continue
				}
				seen[t] = true
				crumbs = append(crumbs, t)
			}
		}
		if len(crumbs) > 0 {
			break
		}
	}
	return strings.Join(crumbs, " › ")
}

func extractTechDocModelsDeclHTML(ctx *htmlExtractContextDeclHTML, doc *HTMLDoc) []string {
	var models []string
	seen := make(map[string]bool)
	addModel := func(raw string) {
		for _, tok := range strings.Split(raw, ",") {
			m := SanitizeScrapedMeta(tok)
			if m != "" && len(m) <= 64 && !seen[m] && len(models) < 20 {
				seen[m] = true
				models = append(models, m)
			}
		}
	}
	if ctx != nil && ctx.u != nil {
		if qm := ctx.u.Query().Get("models"); qm != "" {
			addModel(qm)
		}
		if qm := ctx.u.Query().Get("model"); qm != "" {
			addModel(qm)
		}
	}
	for _, el := range doc.Select("[data-models], .ft-metadata-value, .model-badge", 20) {
		if dm := el.AttrOrEmpty("data-models"); dm != "" {
			addModel(dm)
		} else {
			addModel(el.Text())
		}
	}
	return models
}

func collectTechDocPDFLinksDeclHTML(doc *HTMLDoc, base *url.URL) []string {
	var pdfs []string
	seen := make(map[string]bool)
	for _, a := range doc.Select("a[href]", 300) {
		href := strings.TrimSpace(a.AttrOrEmpty("href"))
		if href == "" {
			continue
		}
		low := strings.ToLower(href)
		if !strings.Contains(low, ".pdf") {
			continue
		}
		resolved := resolveRelativeHTTPSURLDeclHTML(href, base)
		if resolved == "" {
			continue
		}
		u, err := url.Parse(resolved)
		if err != nil {
			continue
		}
		lowPath := strings.ToLower(u.Path)
		if !strings.HasSuffix(lowPath, ".pdf") && !strings.Contains(strings.ToLower(u.RawQuery), ".pdf") {
			continue
		}
		if !seen[resolved] && len(pdfs) < 40 {
			seen[resolved] = true
			pdfs = append(pdfs, resolved)
		}
	}
	return pdfs
}

func runSramDocsExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	bounded := truncateUTF8SafeFullDocGo(ctx.rawHTML, HardMaxHTMLDocChars)
	cleaned := stripDataImageURIsDeclHTML(bounded)
	cleaned = stripDropTagsLinearDeclHTML(cleaned, map[string]bool{
		"script": true, "style": true, "noscript": true, "template": true, "svg": true,
	}, HardMaxHTMLDocChars)
	cleaned = stripTagsByClassLinearDeclHTML(cleaned, map[string]bool{
		"dodo-service-include__error": true,
		"ft-toc":                      true,
		"ft-nav":                      true,
		"ft-feedback":                 true,
		"ft-actions":                  true,
		"ft-toolbar":                  true,
		"ft-breadcrumbs":              true,
	}, HardMaxHTMLDocChars)

	doc := ParseHTMLDoc(cleaned, HardMaxHTMLDocChars)
	title := extractRawTitleBySelectorsDeclHTML(
		cleaned,
		doc,
		[]RawElementSelector{
			{Tag: "h1", Class: "ft-topic-title"},
			{Tag: "h1"},
		},
		[]string{"h1.ft-topic-title", "h1"},
	)
	if title == "" {
		title = extractRawMetaTitleEscapingBracketsDeclHTML(ctx.rawHTML, "og:title")
	}
	if title == "" {
		title = extractRawTitleBySelectorsDeclHTML(
			cleaned,
			doc,
			[]RawElementSelector{{Tag: "title"}},
			[]string{"title"},
		)
	}

	breadcrumbs := extractTechDocBreadcrumbsDeclHTML(cleaned, doc)
	models := extractTechDocModelsDeclHTML(ctx, doc)
	pdfLinks := collectTechDocPDFLinksDeclHTML(doc, ctx.u)

	var bodyHTML string
	rawSramMatch := func(sel string) (string, bool) {
		switch sel {
		case ".ft-topic-content":
			return ExtractFirstRawElementOrBoundedHTML(cleaned, RawElementSelector{Class: "ft-topic-content"})
		case "article.topic":
			return ExtractFirstRawElementOrBoundedHTML(cleaned, RawElementSelector{Tag: "article", Class: "topic"})
		case "main article":
			if mainHTML, ok := ExtractFirstRawElementOrBoundedHTML(cleaned, RawElementSelector{Tag: "main"}); ok {
				if artHTML, ok2 := ExtractFirstRawElementOrBoundedHTML(mainHTML, RawElementSelector{Tag: "article"}); ok2 {
					return artHTML, true
				}
			}
			return "", false
		case "main":
			return ExtractFirstRawElementOrBoundedHTML(cleaned, RawElementSelector{Tag: "main"})
		case `[role="main"]`:
			return ExtractFirstRawElementOrBoundedHTML(cleaned, RawElementSelector{Attr: "role", Val: "main"})
		case "article":
			return ExtractFirstRawElementOrBoundedHTML(cleaned, RawElementSelector{Tag: "article"})
		}
		return "", false
	}
	for _, sel := range []string{".ft-topic-content", "article.topic", "main article", "main", `[role="main"]`, "article"} {
		if rawCand, ok := rawSramMatch(sel); ok && strings.TrimSpace(stripTagsInlineLinear(rawCand)) != "" {
			bodyHTML = rawCand
			break
		}
	}
	bodyHTML = stripDropTagsLinearDeclHTML(bodyHTML, map[string]bool{
		"nav": true, "aside": true, "footer": true,
	}, HardMaxHTMLDocChars)
	bodyMD := ""
	var bodyLinks []string
	if strings.TrimSpace(bodyHTML) != "" {
		md, ls := ctx.htmlToMD(bodyHTML, ctx.baseURL)
		bodyMD = strings.TrimSpace(stripLeadingMarkdownH1Go(md))
		bodyLinks = ls
	}
	if bodyMD == "" && len(pdfLinks) == 0 {
		return nil
	}

	if title == "" {
		title = "SRAM Technical Documentation"
	}
	var bullets []string
	if breadcrumbs != "" {
		bullets = append(bullets, "- **Breadcrumbs**: "+escapeMarkdownBracketsOnlyGo(breadcrumbs))
	}
	if len(models) > 0 {
		bullets = append(bullets, "- **Models**: "+escapeMarkdownBracketsOnlyGo(strings.Join(models, ", ")))
	}

	sections := []string{"# " + escapeMarkdownBracketsOnlyGo(title)}
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	if bodyMD != "" {
		sections = append(sections, bodyMD)
	}
	if len(pdfLinks) > 0 {
		var pdfLines []string
		for _, p := range pdfLinks {
			pdfLines = append(pdfLines, "- "+formatSafeMarkdownLinkSchemaGo(p, p))
		}
		sections = append(sections, "## PDF Manuals\n\n"+strings.Join(pdfLines, "\n"))
	}

	allLinks := append([]string(nil), pdfLinks...)
	allLinks = append(allLinks, bodyLinks...)
	outMD := stripDataImageURIsDeclHTML(strings.Join(sections, "\n\n"))
	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Markdown:    outMD,
		Links:       allLinks,
	}
}

func runBoschHelpExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	bounded := truncateUTF8SafeFullDocGo(ctx.rawHTML, HardMaxHTMLDocChars)
	cleaned := stripDataImageURIsDeclHTML(bounded)
	cleaned = rescueBoschSuspenseSlotsDeclHTML(cleaned)
	cleaned = stripDropTagsLinearDeclHTML(cleaned, map[string]bool{
		"script": true, "style": true, "noscript": true, "template": true, "svg": true,
	}, HardMaxHTMLDocChars)
	cleaned = stripTagsByClassLinearDeclHTML(cleaned, map[string]bool{
		"dodo-service-include__error": true,
		"cookie-banner":               true,
	}, HardMaxHTMLDocChars)

	doc := ParseHTMLDoc(cleaned, HardMaxHTMLDocChars)
	title := extractRawTitleBySelectorsDeclHTML(
		cleaned,
		doc,
		[]RawElementSelector{{Tag: "h1"}},
		[]string{"h1"},
	)
	if title == "" {
		title = extractRawMetaTitleEscapingBracketsDeclHTML(ctx.rawHTML, "og:title")
	}
	if title == "" {
		title = extractRawTitleBySelectorsDeclHTML(
			cleaned,
			doc,
			[]RawElementSelector{{Tag: "title"}},
			[]string{"title"},
		)
	}
	for _, suf := range []string{" - Bosch eBike Systems", " | Bosch eBike Systems"} {
		if strings.HasSuffix(title, suf) {
			title = strings.TrimSpace(strings.TrimSuffix(title, suf))
		}
	}

	breadcrumbs := extractTechDocBreadcrumbsDeclHTML(cleaned, doc)
	models := extractTechDocModelsDeclHTML(ctx, doc)
	pdfLinks := collectTechDocPDFLinksDeclHTML(doc, ctx.u)

	var bodySpan rawElementSpanDeclHTML
	hasBodySpan := false
	var bodyHTML string
	rawBoschMatch := func(sel string) (rawElementSpanDeclHTML, bool) {
		switch sel {
		case "article":
			return extractFirstRawElementSpanOrBoundedDeclHTML(cleaned, RawElementSelector{Tag: "article"})
		case ".article-body":
			return extractFirstRawElementSpanOrBoundedDeclHTML(cleaned, RawElementSelector{Class: "article-body"})
		case "main":
			return extractFirstRawElementSpanOrBoundedDeclHTML(cleaned, RawElementSelector{Tag: "main"})
		case `[role="main"]`:
			return extractFirstRawElementSpanOrBoundedDeclHTML(cleaned, RawElementSelector{Attr: "role", Val: "main"})
		case `div[data-ef-suspense="1"]`:
			return extractFirstRawElementSpanOrBoundedDeclHTML(cleaned, RawElementSelector{Tag: "div", Attr: "data-ef-suspense", Val: "1"})
		}
		return rawElementSpanDeclHTML{}, false
	}
	for _, sel := range []string{"article", ".article-body", "main", `[role="main"]`, `div[data-ef-suspense="1"]`} {
		if sp, ok := rawBoschMatch(sel); ok && len(strings.TrimSpace(stripTagsInlineLinear(sp.html))) >= 20 {
			bodySpan = sp
			hasBodySpan = true
			bodyHTML = sp.html
			break
		}
	}
	if hasBodySpan {
		rawSlots := extractAllTopLevelRawElementSlicesOrBoundedDeclHTML(cleaned, "div", "", "data-ef-suspense", "1", 16, false)
		if len(rawSlots) > 0 {
			var extra []string
			for _, sl := range rawSlots {
				if sl.start >= bodySpan.start && sl.end <= bodySpan.end {
					continue
				}
				if tr := strings.TrimSpace(sl.html); tr != "" {
					extra = append(extra, tr)
				}
			}
			if len(extra) > 0 {
				bodyHTML += "\n" + strings.Join(extra, "\n")
			}
		}
	} else {
		// Concatenate rescued Suspense slots if main/article was absent or < 20 chars.
		rawSlots := extractAllTopLevelRawElementSlicesOrBoundedDeclHTML(cleaned, "div", "", "data-ef-suspense", "1", 16, false)
		if len(rawSlots) > 0 {
			var parts []string
			for _, sl := range rawSlots {
				if tr := strings.TrimSpace(sl.html); tr != "" {
					parts = append(parts, tr)
				}
			}
			bodyHTML = strings.Join(parts, "\n")
		}
	}
	bodyHTML = stripDropTagsLinearDeclHTML(bodyHTML, map[string]bool{
		"nav": true, "aside": true, "footer": true, "header": true,
	}, HardMaxHTMLDocChars)

	bodyMD := ""
	var bodyLinks []string
	if strings.TrimSpace(bodyHTML) != "" {
		md, ls := ctx.htmlToMD(bodyHTML, ctx.baseURL)
		bodyMD = strings.TrimSpace(stripLeadingMarkdownH1Go(md))
		bodyLinks = ls
	}
	if bodyMD == "" && len(pdfLinks) == 0 {
		return nil
	}

	if title == "" {
		title = "Bosch eBike Systems Help"
	}
	var bullets []string
	if breadcrumbs != "" {
		bullets = append(bullets, "- **Breadcrumbs**: "+escapeMarkdownBracketsOnlyGo(breadcrumbs))
	}
	if len(models) > 0 {
		bullets = append(bullets, "- **Models**: "+escapeMarkdownBracketsOnlyGo(strings.Join(models, ", ")))
	}

	sections := []string{"# " + escapeMarkdownBracketsOnlyGo(title)}
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	if bodyMD != "" {
		sections = append(sections, bodyMD)
	}
	if len(pdfLinks) > 0 {
		var pdfLines []string
		for _, p := range pdfLinks {
			pdfLines = append(pdfLines, "- "+formatSafeMarkdownLinkSchemaGo(p, p))
		}
		sections = append(sections, "## PDF Manuals\n\n"+strings.Join(pdfLines, "\n"))
	}

	allLinks := append([]string(nil), pdfLinks...)
	allLinks = append(allLinks, bodyLinks...)
	outMD := stripDataImageURIsDeclHTML(strings.Join(sections, "\n\n"))
	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Markdown:    outMD,
		Links:       allLinks,
	}
}
