package extract

import (
	"encoding/json"
	"fmt"
	stdhtml "html"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// DeclarativePostFetchResult holds the structured output produced by a post-fetch declarative HTML site adapter.
type DeclarativePostFetchResult struct {
	ExtractorID   string           `json:"extractorId"`
	Title         string           `json:"title,omitempty"`
	Description   string           `json:"description,omitempty"`
	Author        string           `json:"author,omitempty"`
	PublishedTime string           `json:"publishedTime,omitempty"`
	Markdown      string           `json:"markdown"`
	Links         []string         `json:"links,omitempty"`
	ReplaceLinks  bool             `json:"-"`
	Records       []map[string]any `json:"records,omitempty"`
	Total         *int             `json:"total,omitempty"`
	Returned      *int             `json:"returned,omitempty"`
	Truncated     *bool            `json:"truncated,omitempty"`
	NextCursor    string           `json:"nextCursor,omitempty"`
}

type htmlExtractContextDeclHTML struct {
	u         *url.URL
	baseURL   string
	host      string
	path      string
	parts     []string
	rawHTML   string
	currentMD string
	htmlToMD  func(frag, base string) (string, []string)
}

var (
	regexCacheMuDeclHTML sync.RWMutex
	regexCacheDeclHTML   = make(map[string]*regexp.Regexp)

	reIETFPageFooterDeclHTML   = newLazyRegexp(`(?i)\[Page\s+\d+\]$`)
	reIETFRFCHeaderDeclHTML    = newLazyRegexp(`(?i)\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}$`)
	reIETFSectionDeclHTML      = newLazyRegexp(`^(\d+(?:\.\d+){0,3})\.\s+([A-Z][^\r\n]{1,90})$`)
	reJSRPublishedDeclHTML     = newLazyRegexp(`(?i)^Published\s+`)
	reMediaWikiGenDeclHTML     = newLazyRegexp(`(?i)\bcontent=["']MediaWiki\b`)
	reGistTitleSuffixDeclHTML  = newLazyRegexp(`(?i)\s*·\s*GitHub\s*$`)
	reSEClosedSuffixDeclHTML   = newLazyRegexp(`(?i)\s*\[(?:duplicate|closed)\]\s*$`)
	reSEAnswerIDDeclHTML       = newLazyRegexp(`(?i)^answer-\d+$`)
	reSEAcceptedIndDeclHTML    = newLazyRegexp(`(?i)\bjs-accepted-answer-indicator\b`)
	reHrefAmpEntDeclHTML       = newLazyRegexp(`(?i)&(?:amp|#0*38|#x0*26);`)
	reJSONLDScriptTypeDeclHTML = newLazyRegexp(`(?i)\btype[ \t\r\n]*=[ \t\r\n]*(?:["']application/ld\+json(?:[ \t]*;[^"']*)?[ \t]*["']|application/ld\+json(?:;[^ \t\r\n"'>]*)?(?:[ \t\r\n/>]|$))`)

	reIcimsSingleJobDeclHTML    = newLazyRegexp(`(?i)/jobs/\d+(?:/|$)`)
	reIcimsJobIDHrefDeclHTML    = newLazyRegexp(`(?i)/jobs/(\d+)(?:/|\?|$)`)
	reIcimsLeadDigitsDeclHTML   = newLazyRegexp(`^\d+\s*-\s*`)
	reIcimsJobTitlePrefDeclHTML = newLazyRegexp(`(?i)^(?:Job\s+Title|Title)\s*`)
	reIcimsSpanDateDeclHTML     = newLazyRegexp(`^\d{1,2}/\d{1,2}/\d{4}\b`)
	reIcimsExplicitZeroDeclHTML = newLazyRegexp(`(?i)\b(?:no\s+results\s+found|sorry,\s+no\s+jobs|currently\s+no\s+open\s+positions|there\s+are\s+currently\s+no\s+open|no\s+jobs\s+match(?:\s+your\s+search\s+criteria)?|no\s+open\s+(?:jobs|positions|roles)|0\s+results\s+available)\b`)
	reIcimsPageOfDeclHTML       = newLazyRegexp(`(?i)\bPage\s+(\d+)\s+of\s+(\d+)\b`)
	reIcimsCareerSuffixDeclHTML = newLazyRegexp(`(?i)\s*Career\s+Listings\s*$`)
	reIcimsIframeShellDeclHTML  = newLazyRegexp(`(?i)\bicims_content_iframe\b`)

	reShopifyPathDeclHTML         = newLazyRegexp(`(?i)/products/[^/]+`)
	reShopifyDomainDeclHTML       = newLazyRegexp(`(?i)[a-z0-9-]\.myshopify\.com\b`)
	reShopifyShopVarDeclHTML      = newLazyRegexp(`Shopify\.shop\s*=`)
	reShopifyActiveCurDeclHTML    = newLazyRegexp(`Shopify\.currency\s*=\s*\{[^}]{0,240}?"active"\s*:\s*"([A-Z]{3})"`)
	reShopifyLDCurDeclHTML        = newLazyRegexp(`(?i)"priceCurrency"\s*:\s*"([A-Z]{3})"`)
	reShopifyProdJSONIDDeclHTML   = newLazyRegexp(`(?i)^productjson\b`)
	reShopifyAvailTrueDeclHTML    = newLazyRegexp(`(?i)InStock|PreOrder|BackOrder|OnlineOnly`)
	reShopifyAvailFalseDeclHTML   = newLazyRegexp(`(?i)OutOfStock|SoldOut|Discontinued`)
	reShopifyPreorderDeclHTML     = newLazyRegexp(`(?i)PreOrder|BackOrder`)
	reWooSinglePathDeclHTML       = newLazyRegexp(`(?i)/product/[^/]+`)
	reISOCurrency3DeclHTML        = newLazyRegexp(`^[A-Z]{3}$`)
	reNonPublicMdImgDeclHTML      = newLazyRegexp(`!\[([^\]]*)\]\(([^)\r\n]+)\)`)
	reANSIEscapeDeclHTML          = newLazyRegexp("\x1b\\[[0-9;?]*[ -/]*[@-~]")
	reDangerousInlineLinkDeclHTML = newLazyRegexp(`(?i)\]\(\s*(?:javascript|vbscript|data|file|blob):[^)]*\)`)

	reMWFenceLineDeclHTML       = newLazyRegexp("^[ \t]{0,3}(`{3,}|~{3,})(.*)$")
	reMWFooterHeadingDeclHTML   = newLazyRegexp(`(?i)^(?:##+[ \t]+)?(?:Navigation menu|Namespaces|Views|Personal tools)\b`)
	reMWChromeLineDeclHTML      = newLazyRegexp(`(?i)^(?:\[[ \t]*\]|Edit links|Links bearbeiten|Modifier les liens|Editar enlaces|Modifica link|Toggle the table of contents|Move to sidebar|hide)$`)
	reMWJumpLineDeclHTML        = newLazyRegexp(`(?i)^\[(?:Jump to content|Zum Inhalt springen|Aller au contenu)\]\(#[^)]*\)$`)
	reMWWikidataLineDeclHTML    = newLazyRegexp(`(?i)^\[[^\]]{1,64}\]\(https?://(?:www\.)?wikidata\.org/wiki/Special:EntityPage/[^)]*\)$`)
	reMWTaglineDeclHTML         = newLazyRegexp(`(?i)^(?:From Wikipedia, the free encyclopedia|Aus Wikipedia, der freien Enzyklopädie|Un article de Wikipédia, l'encyclopédie libre\.?)$`)
	reMWLangCountDeclHTML       = newLazyRegexp(`(?i)^\d{1,4}[ \t]+(?:languages|language|Sprachen|langues|idiomas|lingue)$`)
	reMWCheckedLineDeclHTML     = newLazyRegexp(`(?i)^(?:\*{1,2})?(?:Checked|Gesichtet|Vérifié|Revisado)(?:\*{1,2})?$`)
	reMWWikidataHrefDeclHTML    = newLazyRegexp(`(?i)^https?://(?:www\.)?wikidata\.org/wiki/Special:EntityPage/`)
	reMWCiteHrefDeclHTML        = newLazyRegexp(`(?i)^#cite_(?:note|ref)|Wikipedia:(?:Citation_needed|Please_clarify|Disputed_statement)`)
	reMWCiteLabelDeclHTML       = newLazyRegexp(`(?is)^(?:\d{1,4}|[a-z]|(?:note|nb|lower-alpha|upper-alpha)[ \t]*\d{1,3}|citation needed|clarification needed|when\?|who\?|dubious.{0,48})$`)
	reMWFootnoteCaretDeclHTML   = newLazyRegexp(`(?i)^\[\^[a-z0-9]{1,32}\][ \t]*`)
	reMWInlineEditLabelDeclHTML = newLazyRegexp(`(?i)^\[(?:edit|Bearbeiten(?:[ \t]*\|[ \t]*Quelltext bearbeiten)?|modifier(?:[ \t]*\|[ \t]*modifier le code)?|editar|citation needed|clarification needed|when\?|who\?|dubious[ \t]*(?:–|-)[ \t]*discuss)\]$`)
	reMWInlineNumNoteDeclHTML   = newLazyRegexp(`(?i)^\[(?:\d{1,4}|(?:note|nb)[ \t]*\d{1,3})\]$`)
	reMWExcessBlankDeclHTML     = newLazyRegexp(`\n{3,}`)
)

func getCachedLinearRegexDeclHTML(pattern string) *regexp.Regexp {
	if pattern == "" || len(pattern) > 512 {
		return nil
	}
	regexCacheMuDeclHTML.RLock()
	cached, exists := regexCacheDeclHTML[pattern]
	regexCacheMuDeclHTML.RUnlock()
	if exists {
		return cached
	}
	compiled, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil
	}
	regexCacheMuDeclHTML.Lock()
	if len(regexCacheDeclHTML) < 512 {
		regexCacheDeclHTML[pattern] = compiled
	}
	regexCacheMuDeclHTML.Unlock()
	return compiled
}

// ── Linear HTML Tag / Meta / JSON-LD / Balanced Div Scanners ────────────────────────────────────

type linearOpenTagMatchDeclHTML struct {
	index       int
	openEnd     int
	attrStr     string
	selfClosing bool
}

func isHTMLTagBoundaryByteDeclHTML(b byte) bool {
	return b == '>' || b == '/' || b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func isHTMLWsByteDeclHTML(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func isAttrNameByteDeclHTML(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
		b == '-' || b == '_' || b == ':' || b == '.'
}

func getAttrValueLinearDeclHTML(attrStr, attrName string) (string, bool) {
	target := strings.ToLower(attrName)
	n := len(attrStr)
	i := 0
	for i < n {
		for i < n && isHTMLWsByteDeclHTML(attrStr[i]) {
			i++
		}
		if i >= n {
			break
		}
		nameStart := i
		for i < n && isAttrNameByteDeclHTML(attrStr[i]) {
			i++
		}
		if i == nameStart {
			i++
			continue
		}
		curName := strings.ToLower(attrStr[nameStart:i])
		for i < n && isHTMLWsByteDeclHTML(attrStr[i]) {
			i++
		}
		val := ""
		if i < n && attrStr[i] == '=' {
			i++
			for i < n && isHTMLWsByteDeclHTML(attrStr[i]) {
				i++
			}
			if i < n {
				q := attrStr[i]
				if q == '"' || q == '\'' {
					i++
					vStart := i
					closeRel := strings.IndexByte(attrStr[i:], q)
					if closeRel < 0 {
						val = attrStr[vStart:]
						i = n
					} else {
						val = attrStr[vStart : i+closeRel]
						i += closeRel + 1
					}
				} else {
					vStart := i
					for i < n && !isHTMLWsByteDeclHTML(attrStr[i]) && attrStr[i] != '>' {
						i++
					}
					val = attrStr[vStart:i]
				}
			}
		}
		if curName == target {
			return val, true
		}
	}
	return "", false
}

func attrHasTokenLinearDeclHTML(attrStr, attrName, token string) bool {
	val, ok := getAttrValueLinearDeclHTML(attrStr, attrName)
	if !ok || val == "" {
		return false
	}
	target := strings.ToLower(token)
	for _, f := range strings.Fields(strings.ToLower(val)) {
		if f == target {
			return true
		}
	}
	return false
}

func findOpenTagLinearDeclHTML(htmlSrc, tagName string, pred func(string) bool, startPos int) (linearOpenTagMatchDeclHTML, bool) {
	tagLower := strings.ToLower(tagName)
	tLen := len(tagLower)
	n := len(htmlSrc)
	pos := startPos
	if pos < 0 {
		pos = 0
	}
	if pos >= n {
		return linearOpenTagMatchDeclHTML{}, false
	}
	gtRel0 := strings.IndexByte(htmlSrc[pos:], '>')
	if gtRel0 < 0 {
		return linearOpenTagMatchDeclHTML{}, false
	}
	cachedGt := pos + gtRel0

	for pos < n {
		ltRel := strings.IndexByte(htmlSrc[pos:], '<')
		if ltRel < 0 {
			return linearOpenTagMatchDeclHTML{}, false
		}
		lt := pos + ltRel
		if lt+1+tLen >= n {
			return linearOpenTagMatchDeclHTML{}, false
		}
		matched := true
		for k := 0; k < tLen; k++ {
			c := htmlSrc[lt+1+k]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != tagLower[k] {
				matched = false
				break
			}
		}
		afterName := lt + 1 + tLen
		if !matched || !isHTMLTagBoundaryByteDeclHTML(htmlSrc[afterName]) {
			pos = lt + 1
			continue
		}
		if cachedGt < afterName {
			rel := strings.IndexByte(htmlSrc[afterName:], '>')
			if rel < 0 {
				return linearOpenTagMatchDeclHTML{}, false
			}
			cachedGt = afterName + rel
		}
		if nextLtRel := strings.IndexByte(htmlSrc[afterName:cachedGt], '<'); nextLtRel >= 0 {
			pos = afterName + nextLtRel
			continue
		}
		selfClosing := cachedGt > afterName && htmlSrc[cachedGt-1] == '/'
		attrEnd := cachedGt
		if selfClosing {
			attrEnd = cachedGt - 1
		}
		attrStr := htmlSrc[afterName:attrEnd]
		if pred == nil || pred(attrStr) {
			return linearOpenTagMatchDeclHTML{
				index:       lt,
				openEnd:     cachedGt + 1,
				attrStr:     attrStr,
				selfClosing: selfClosing,
			}, true
		}
		pos = cachedGt + 1
	}
	return linearOpenTagMatchDeclHTML{}, false
}

func findAllOpenTagsLinearDeclHTML(htmlSrc, tagName string, pred func(string) bool, maxItems int) []linearOpenTagMatchDeclHTML {
	var out []linearOpenTagMatchDeclHTML
	pos := 0
	for pos < len(htmlSrc) && len(out) < maxItems {
		m, ok := findOpenTagLinearDeclHTML(htmlSrc, tagName, pred, pos)
		if !ok {
			break
		}
		out = append(out, m)
		pos = m.openEnd
	}
	return out
}

func findCloseTagLinearDeclHTML(htmlSrc, tagLower string, startPos int) (closeStart, closeEnd int, ok bool) {
	tLen := len(tagLower)
	n := len(htmlSrc)
	pos := startPos
	if pos < 0 {
		pos = 0
	}
	for pos < n {
		ltRel := strings.IndexByte(htmlSrc[pos:], '<')
		if ltRel < 0 {
			return 0, 0, false
		}
		lt := pos + ltRel
		if lt+2+tLen >= n {
			return 0, 0, false
		}
		if htmlSrc[lt+1] != '/' {
			pos = lt + 1
			continue
		}
		matched := true
		for k := 0; k < tLen; k++ {
			c := htmlSrc[lt+2+k]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != tagLower[k] {
				matched = false
				break
			}
		}
		if !matched {
			pos = lt + 2
			continue
		}
		p := lt + 2 + tLen
		for p < n && isHTMLWsByteDeclHTML(htmlSrc[p]) {
			p++
		}
		if p < n && htmlSrc[p] == '>' {
			return lt, p + 1, true
		}
		pos = lt + 2
	}
	return 0, 0, false
}

func findElementInnerLinearDeclHTML(htmlSrc, tagName string, pred func(string) bool, startPos int) (string, bool) {
	tagLower := strings.ToLower(tagName)
	open, ok := findOpenTagLinearDeclHTML(htmlSrc, tagLower, pred, startPos)
	if !ok {
		return "", false
	}
	if open.selfClosing {
		return "", true
	}
	closeStart, _, okClose := findCloseTagLinearDeclHTML(htmlSrc, tagLower, open.openEnd)
	if !okClose {
		return "", false
	}
	return htmlSrc[open.openEnd:closeStart], true
}

func findAllElementInnersLinearDeclHTML(htmlSrc, tagName string, pred func(string) bool, maxItems int) []string {
	tagLower := strings.ToLower(tagName)
	var out []string
	pos := 0
	for pos < len(htmlSrc) && len(out) < maxItems {
		open, ok := findOpenTagLinearDeclHTML(htmlSrc, tagLower, pred, pos)
		if !ok {
			break
		}
		if open.selfClosing {
			out = append(out, "")
			pos = open.openEnd
			continue
		}
		closeStart, closeEnd, okClose := findCloseTagLinearDeclHTML(htmlSrc, tagLower, open.openEnd)
		if !okClose {
			break
		}
		out = append(out, htmlSrc[open.openEnd:closeStart])
		pos = closeEnd
	}
	return out
}

func extractBalancedDivAtDeclHTML(htmlSrc string, openTagIndex int) (string, bool) {
	if openTagIndex < 0 || openTagIndex+4 > len(htmlSrc) {
		return "", false
	}
	var noDbl, noSgl bool
	openTag, ok := scanNextHTMLTagQuoteAwareGo(htmlSrc, openTagIndex, &noDbl, &noSgl)
	if !ok || openTag.start != openTagIndex || openTag.tagLower != "div" || openTag.isClosing {
		return "", false
	}
	if openTag.selfClosing {
		return "", true
	}
	bodyStart := openTag.end
	depth := 1
	pos := bodyStart
	for pos < len(htmlSrc) {
		tag, okTag := scanNextHTMLTagQuoteAwareGo(htmlSrc, pos, &noDbl, &noSgl)
		if !okTag {
			return "", false
		}
		if tag.tagLower == "div" {
			if tag.isClosing {
				depth--
				if depth == 0 {
					return htmlSrc[bodyStart:tag.start], true
				}
			} else if !tag.selfClosing {
				depth++
			}
		}
		pos = tag.end
	}
	return "", false
}

func stripScriptsAndStylesDeclHTML(rawHTML string) string {
	return stripHTMLDropTagsDeclHTML(rawHTML, map[string]bool{
		"script": true,
		"style":  true,
		"svg":    true,
		"iframe": true,
		"object": true,
		"embed":  true,
	})
}

func stripScriptsStylesNoscriptDeclHTML(rawHTML string) string {
	return stripHTMLDropTagsDeclHTML(rawHTML, map[string]bool{
		"script":   true,
		"style":    true,
		"noscript": true,
	})
}

func stripHTMLDropTagsDeclHTML(rawHTML string, dropTags map[string]bool) string {
	src := rawHTML
	if len(src) > 2*1024*1024 {
		src = src[:2*1024*1024]
	}
	lower := asciiLowerExtractString(src)
	var sb strings.Builder
	sb.Grow(len(src))
	last := 0
	pos := 0
	var noDbl, noSgl bool
	for pos < len(src) {
		tag, ok := scanNextHTMLTagQuoteAwareGo(src, pos, &noDbl, &noSgl)
		if !ok {
			break
		}
		if !dropTags[tag.tagLower] {
			pos = tag.end
			continue
		}
		sb.WriteString(src[last:tag.start])
		if tag.isClosing || tag.selfClosing {
			last = tag.end
			pos = last
			continue
		}
		closeIdx := findNextValidCloseTagGo(lower, src, "</"+tag.tagLower, tag.end)
		if closeIdx < 0 {
			last = len(src)
			break
		}
		endRel := strings.IndexByte(src[closeIdx:], '>')
		if endRel < 0 {
			last = len(src)
			break
		}
		last = closeIdx + endRel + 1
		pos = last
	}
	if last == 0 {
		return src
	}
	sb.WriteString(src[last:])
	return sb.String()
}

func extractMetaContentDeclHTML(rawHTML, key string) string {
	if indexFoldASCIIExtract(rawHTML, "<meta") < 0 {
		return ""
	}
	targetKey := strings.ToLower(key)
	limit := len(rawHTML)
	if limit > 120_000 {
		limit = 120_000
	}
	src := rawHTML[:limit]
	pos := 0
	var noDbl, noSgl bool
	for pos < len(src) {
		tag, ok := scanNextHTMLTagQuoteAwareGo(src, pos, &noDbl, &noSgl)
		if !ok {
			break
		}
		pos = tag.end
		if tag.isClosing || tag.tagLower != "meta" {
			continue
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
			clean := strings.TrimSpace(stdhtml.UnescapeString(attrs["content"]))
			if clean != "" {
				return clean
			}
		}
	}
	return ""
}

func extractAllMetaContentsDeclHTML(rawHTML, key string) []string {
	if indexFoldASCIIExtract(rawHTML, "<meta") < 0 {
		return nil
	}
	targetKey := strings.ToLower(key)
	limit := len(rawHTML)
	if limit > 160_000 {
		limit = 160_000
	}
	src := rawHTML[:limit]
	var out []string
	seen := make(map[string]bool)
	pos := 0
	var noDbl, noSgl bool
	for pos < len(src) {
		tag, ok := scanNextHTMLTagQuoteAwareGo(src, pos, &noDbl, &noSgl)
		if !ok {
			break
		}
		pos = tag.end
		if tag.isClosing || tag.tagLower != "meta" {
			continue
		}
		attrs := parseHTMLTagAttrsGo(tag.attrs)
		nameVal := attrs["name"]
		if nameVal == "" {
			nameVal = attrs["property"]
		}
		if strings.ToLower(nameVal) == targetKey && attrs["content"] != "" {
			clean := strings.TrimSpace(stdhtml.UnescapeString(attrs["content"]))
			if clean != "" && !seen[clean] {
				seen[clean] = true
				out = append(out, clean)
			}
		}
	}
	return out
}

func parseJSONValueDeclHTML(raw string) (any, bool) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if trimmed == "" {
		return nil, false
	}
	return decodeJSONWithNumbers([]byte(trimmed))
}

func parseJSONObjectDeclHTML(raw string) (map[string]any, bool) {
	v, ok := parseJSONValueDeclHTML(raw)
	if !ok || v == nil {
		return nil, false
	}
	obj, isObj := v.(map[string]any)
	return obj, isObj
}

func extractJSONLDObjectsDeclHTML(rawHTML string, maxEntities int) []map[string]any {
	if indexFoldASCIIExtract(rawHTML, "ld+json") < 0 {
		return nil
	}
	capCount := maxEntities
	if capCount <= 0 {
		capCount = 100
	}
	if capCount > 250 {
		capCount = 250
	}
	src := rawHTML
	if len(src) > 2*1024*1024 {
		src = src[:2*1024*1024]
	}
	var results []map[string]any
	var pushItem func(item any, depth int)
	pushItem = func(item any, depth int) {
		if item == nil || depth > 16 || len(results) >= capCount {
			return
		}
		switch tv := item.(type) {
		case []any:
			for _, el := range tv {
				if len(results) >= capCount {
					break
				}
				pushItem(el, depth+1)
			}
		case map[string]any:
			results = append(results, tv)
			if graph, isArr := tv["@graph"].([]any); isArr {
				for _, g := range graph {
					if len(results) >= capCount {
						break
					}
					pushItem(g, depth+1)
				}
			}
		}
	}

	pos := 0
	for pos < len(src) && len(results) < capCount {
		open, ok := findOpenTagLinearDeclHTML(src, "script", func(attrStr string) bool {
			return reJSONLDScriptTypeDeclHTML.MatchString(attrStr)
		}, pos)
		if !ok {
			break
		}
		if open.selfClosing {
			pos = open.openEnd
			continue
		}
		closeStart, closeEnd, okClose := findCloseTagLinearDeclHTML(src, "script", open.openEnd)
		if !okClose {
			break
		}
		raw := strings.TrimSpace(src[open.openEnd:closeStart])
		pos = closeEnd
		if raw == "" || len(raw) > 2*1024*1024 {
			continue
		}
		parsed, okP := parseJSONValueDeclHTML(raw)
		if !okP && strings.IndexByte(raw, '&') >= 0 {
			parsed, okP = parseJSONValueDeclHTML(stdhtml.UnescapeString(raw))
		}
		if okP {
			pushItem(parsed, 0)
		}
	}
	return results
}

func jsonLDTypeStringDeclHTML(obj map[string]any) string {
	if obj == nil {
		return ""
	}
	switch t := obj["@type"].(type) {
	case string:
		return t
	case []any:
		var parts []string
		for _, el := range t {
			if s, ok := el.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func extractBalancedJSONAfterKeyLinearDeclHTML(src, keyName string) map[string]any {
	needle := `"` + keyName + `"`
	idx := strings.Index(src, needle)
	if idx < 0 {
		return nil
	}
	afterKey := idx + len(needle)
	openRel := strings.IndexByte(src[afterKey:], '{')
	if openRel < 0 {
		return nil
	}
	openIdx := afterKey + openRel
	depth := 0
	inStr := false
	esc := false
	endCap := openIdx + 120_000
	if endCap > len(src) {
		endCap = len(src)
	}
	for i := openIdx; i < endCap; i++ {
		ch := src[i]
		if inStr {
			if esc {
				esc = false
			} else if ch == '\\' {
				esc = true
			} else if ch == '"' {
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				obj, _ := parseJSONObjectDeclHTML(src[openIdx : i+1])
				return obj
			}
		}
	}
	return nil
}

func stripTagsPreservingNewlinesDeclHTML(s string) string {
	if strings.IndexByte(s, '<') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	i := 0
	n := len(s)
	nextGt := -2
	for i < n {
		if s[i] != '<' {
			sb.WriteByte(s[i])
			i++
			continue
		}
		if nextGt != -1 && nextGt <= i {
			rel := strings.IndexByte(s[i+1:], '>')
			if rel < 0 {
				nextGt = -1
			} else {
				nextGt = i + 1 + rel
			}
		}
		if nextGt == -1 {
			sb.WriteString(s[i:])
			break
		}
		i = nextGt + 1
	}
	return sb.String()
}

func unescapeHrefURLDeclHTML(rawHref string) string {
	return strings.TrimSpace(reHrefAmpEntDeclHTML.ReplaceAllString(rawHref, "&"))
}

// ── Mode 4: Markdown Clean Presets (`ietf_rfc`, `jsr_io`, `mediawiki`) ──────────────────────────

func stripMediaWikiInlineLinksDeclHTML(ln string) string {
	if !strings.Contains(ln, "](") || strings.IndexByte(ln, ')') < 0 {
		return ln
	}
	if !strings.Contains(ln, "wikidata.org/wiki/Special:EntityPage/") &&
		!strings.Contains(ln, "action=edit") &&
		!strings.Contains(ln, "#cite_note") &&
		!strings.Contains(ln, "#cite_ref") &&
		!strings.Contains(ln, "Wikipedia:Citation_needed") &&
		!strings.Contains(ln, "Wikipedia:Please_clarify") &&
		!strings.Contains(ln, "Wikipedia:Disputed_statement") {
		return ln
	}

	var out strings.Builder
	lastEmit := 0
	searchPos := 0
	n := len(ln)

	for searchPos < n {
		midRel := strings.Index(ln[searchPos:], "](")
		if midRel < 0 {
			break
		}
		mid := searchPos + midRel

		scanCap := mid + 2050
		if scanCap > n {
			scanCap = n
		}
		parenDepth := 1
		endParen := -1
		nextMid := -1
		for p := mid + 2; p < scanCap; p++ {
			ch := ln[p]
			if ch == ']' && p+1 < n && ln[p+1] == '(' {
				nextMid = p
				break
			}
			if ch == '(' {
				parenDepth++
			} else if ch == ')' {
				parenDepth--
				if parenDepth == 0 {
					endParen = p
					break
				}
			}
		}
		if nextMid >= 0 {
			searchPos = nextMid
			continue
		}
		if endParen < 0 {
			if scanCap >= n {
				break
			}
			searchPos = scanCap
			continue
		}

		isDoubleClose := mid > lastEmit && ln[mid-1] == ']'
		lblEnd := mid
		if isDoubleClose {
			lblEnd = mid - 1
		}
		minBack := lblEnd - 66
		if minBack < lastEmit {
			minBack = lastEmit
		}
		openBr := -1
		for b := lblEnd - 1; b >= minBack; b-- {
			bc := ln[b]
			if bc == '[' {
				openBr = b
				break
			}
			if bc == ']' {
				break
			}
		}

		if openBr >= 0 && lblEnd > openBr {
			hasDoubleOpen := isDoubleClose && openBr > lastEmit && ln[openBr-1] == '['
			if !isDoubleClose || hasDoubleOpen {
				openStart := openBr
				if hasDoubleOpen {
					openStart = openBr - 1
				}
				label := ln[openBr+1 : lblEnd]
				href := ln[mid+2 : endParen]
				isWikidataSitelink := !hasDoubleOpen && reMWWikidataHrefDeclHTML.MatchString(href)
				isActionEdit := strings.Contains(strings.ToLower(href), "?action=edit") || strings.Contains(strings.ToLower(href), "&action=edit")
				isCiteLink := reMWCiteHrefDeclHTML.MatchString(href) && reMWCiteLabelDeclHTML.MatchString(label)

				if isWikidataSitelink || isActionEdit || isCiteLink {
					cutStart := openStart
					if isWikidataSitelink || isActionEdit {
						for cutStart > lastEmit && (ln[cutStart-1] == ' ' || ln[cutStart-1] == '\t') {
							cutStart--
						}
					}
					out.WriteString(ln[lastEmit:cutStart])
					lastEmit = endParen + 1
					searchPos = endParen + 1
					continue
				}
			}
		}

		searchPos = endParen + 1
	}

	if lastEmit == 0 {
		return ln
	}
	out.WriteString(ln[lastEmit:])
	return out.String()
}

func stripMediaWikiUnlinkedBracketsDeclHTML(ln string) string {
	var sb strings.Builder
	sb.Grow(len(ln))
	n := len(ln)
	last := 0
	i := 0
	for i < n {
		rel := strings.IndexByte(ln[i:], '[')
		if rel < 0 {
			break
		}
		openIdx := i + rel
		closeRel := strings.IndexByte(ln[openIdx+1:], ']')
		if closeRel < 0 {
			break
		}
		closeIdx := openIdx + 1 + closeRel
		// Skip nested `[` before `]`
		if innerOpen := strings.IndexByte(ln[openIdx+1:closeIdx], '['); innerOpen >= 0 {
			i = openIdx + 1 + innerOpen
			continue
		}
		afterIdx := closeIdx + 1
		followedByLink := afterIdx < n && (ln[afterIdx] == '(' || ln[afterIdx] == ':')
		token := ln[openIdx:afterIdx]
		innerTrimmed := strings.Trim(ln[openIdx+1:closeIdx], " \t")

		if !followedByLink {
			if innerTrimmed == "" || reMWInlineEditLabelDeclHTML.MatchString(token) {
				cutStart := openIdx
				for cutStart > last && (ln[cutStart-1] == ' ' || ln[cutStart-1] == '\t') {
					cutStart--
				}
				sb.WriteString(ln[last:cutStart])
				last = afterIdx
				i = afterIdx
				continue
			}
			if reMWInlineNumNoteDeclHTML.MatchString(token) {
				sb.WriteString(ln[last:openIdx])
				last = afterIdx
				i = afterIdx
				continue
			}
		}
		i = afterIdx
	}
	if last == 0 {
		return ln
	}
	sb.WriteString(ln[last:])
	return sb.String()
}

func cleanMediaWikiMarkdownDeclHTML(rawMD string) string {
	bounded := rawMD
	if len(bounded) > 2*1024*1024 {
		bounded = bounded[:2*1024*1024]
	}
	lines := strings.Split(bounded, "\n")
	out := make([]string, 0, len(lines))
	inFence := false
	var fenceChar byte
	fenceLen := 0

	for i, rawLn := range lines {
		ln := rawLn
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" {
			out = append(out, "")
			continue
		}

		if len(ln) <= 4096 {
			if fm := reMWFenceLineDeclHTML.FindStringSubmatch(ln); len(fm) == 3 {
				ticks := fm[1]
				rest := fm[2]
				if !inFence {
					if !(ticks[0] == '`' && strings.IndexByte(rest, '`') >= 0) {
						inFence = true
						fenceChar = ticks[0]
						fenceLen = len(ticks)
						out = append(out, ln)
						continue
					}
				} else if ticks[0] == fenceChar && len(ticks) >= fenceLen && strings.Trim(rest, " \t") == "" {
					inFence = false
					fenceChar = 0
					fenceLen = 0
					out = append(out, ln)
					continue
				}
			}
		}
		if inFence {
			out = append(out, ln)
			continue
		}

		if len(trimmed) <= 256 && reMWFooterHeadingDeclHTML.MatchString(trimmed) {
			break
		}

		if !strings.HasPrefix(trimmed, "|") && len(trimmed) <= 512 {
			if reMWChromeLineDeclHTML.MatchString(trimmed) ||
				reMWJumpLineDeclHTML.MatchString(trimmed) ||
				reMWWikidataLineDeclHTML.MatchString(trimmed) ||
				reMWTaglineDeclHTML.MatchString(trimmed) ||
				reMWLangCountDeclHTML.MatchString(trimmed) ||
				(i < 40 && reMWCheckedLineDeclHTML.MatchString(trimmed)) {
				continue
			}
		}

		if strings.IndexByte(ln, '[') >= 0 && strings.IndexByte(ln, ']') >= 0 {
			ln = stripMediaWikiInlineLinksDeclHTML(ln)
			ln = stripMediaWikiUnlinkedBracketsDeclHTML(ln)
		}

		retrimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(retrimmed, "^") {
			caretIdx := strings.IndexByte(ln, '^')
			p := caretIdx + 1
			for p < len(ln) && (ln[p] == ' ' || ln[p] == '\t') {
				p++
			}
			if p > caretIdx+1 {
				restAfterCaret := ln[p:]
				if fnLoc := reMWFootnoteCaretDeclHTML.FindStringIndex(restAfterCaret); fnLoc != nil {
					ln = "^ " + restAfterCaret[fnLoc[1]:]
				} else {
					k := 0
					letterCount := 0
					for k+1 < len(restAfterCaret) {
						lc := restAfterCaret[k] | 32
						sc := restAfterCaret[k+1]
						if lc >= 'a' && lc <= 'z' && (sc == ' ' || sc == '\t') {
							letterCount++
							k += 2
							for k < len(restAfterCaret) && (restAfterCaret[k] == ' ' || restAfterCaret[k] == '\t') {
								k++
							}
						} else {
							break
						}
					}
					if letterCount >= 2 {
						ln = "^ " + restAfterCaret[k:]
					}
				}
			}
		}

		if trimmed != "" && strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, ln)
	}

	joined := strings.Join(out, "\n")
	joined = reMWExcessBlankDeclHTML.ReplaceAllString(joined, "\n\n")
	return strings.TrimSpace(joined)
}

func runMarkdownCleanPresetDeclHTML(preset string, ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	switch preset {
	case "ietf_rfc":
		preBlocks := findAllElementInnersLinearDeclHTML(ctx.rawHTML, "pre", func(a string) bool {
			return attrHasTokenLinearDeclHTML(a, "class", "newpage")
		}, 400)
		var sourceText string
		if len(preBlocks) > 0 {
			parts := make([]string, len(preBlocks))
			for i, inner := range preBlocks {
				parts[i] = stdhtml.UnescapeString(stripTagsPreservingNewlinesDeclHTML(inner))
			}
			sourceText = strings.Join(parts, "\n")
		} else {
			sourceText = ctx.currentMD
		}
		if strings.TrimSpace(sourceText) == "" || len(strings.TrimSpace(sourceText)) < 80 {
			return nil
		}

		norm := strings.ReplaceAll(strings.ReplaceAll(sourceText, "\r\n", "\n"), "\f", "\n")
		var cleanedLines []string
		for _, rawLine := range strings.Split(norm, "\n") {
			rTrim := strings.TrimRight(rawLine, " \t\r")
			if reIETFPageFooterDeclHTML.MatchString(rTrim) {
				continue
			}
			fullTrim := strings.TrimLeft(rTrim, " \t")
			if strings.HasPrefix(fullTrim, "RFC ") && strings.Contains(fullTrim, "  ") && reIETFRFCHeaderDeclHTML.MatchString(fullTrim) {
				continue
			}
			if rawLine == fullTrim {
				if secMatch := reIETFSectionDeclHTML.FindStringSubmatch(fullTrim); len(secMatch) == 3 {
					safeSecTitle := escapeDeclMarkdownBrackets(SanitizeScrapedMeta(secMatch[2]))
					depth := strings.Count(secMatch[1], ".") + 2
					if depth > 4 {
						depth = 4
					}
					cleanedLines = append(cleanedLines, fmt.Sprintf("\n%s %s. %s\n", strings.Repeat("#", depth), secMatch[1], safeSecTitle))
					continue
				}
			}
			safeLine := escapeUnescapedMarkdownBracketsGo(rawLine)
			safeLine = escapeDangerousRawHTMLInLineDeclGo(safeLine)
			trimmedSafe := strings.TrimLeft(safeLine, " \t")
			if strings.HasPrefix(trimmedSafe, "#") {
				leadingLen := len(safeLine) - len(trimmedSafe)
				safeLine = safeLine[:leadingLen] + `\` + trimmedSafe
			}
			cleanedLines = append(cleanedLines, safeLine)
		}

		md := strings.TrimSpace(reMWExcessBlankDeclHTML.ReplaceAllString(strings.Join(cleanedLines, "\n"), "\n\n"))
		rawTitle, _ := findElementInnerLinearDeclHTML(ctx.rawHTML, "title", nil, 0)
		title := SanitizeScrapedMeta(stripTagsInlineLinear(rawTitle))
		if title != "" && !strings.HasPrefix(md, "# ") {
			md = "# " + escapeDeclMarkdownBrackets(title) + "\n\n" + md
		}
		return &DeclarativePostFetchResult{
			ExtractorID: extractorID,
			Title:       title,
			Markdown:    md,
		}

	case "jsr_io":
		if ctx.currentMD == "" {
			return nil
		}
		body := ctx.currentMD
		skipIdx := strings.Index(strings.ToLower(body), "skip to main content")
		if skipIdx != -1 && skipIdx < 1500 {
			if h1Rel := strings.Index(body[skipIdx:], "\n# "); h1Rel != -1 {
				h1Idx := skipIdx + h1Rel
				lineStart := strings.LastIndexByte(body[:skipIdx], '\n')
				if lineStart == -1 {
					body = body[h1Idx:]
				} else {
					body = body[:lineStart] + body[h1Idx:]
				}
			}
		}
		var outLines []string
		for _, ln := range strings.Split(body, "\n") {
			tr := strings.TrimSpace(ln)
			if reJSRPublishedDeclHTML.MatchString(tr) {
				continue
			}
			if (strings.HasPrefix(tr, "[Overview](") || strings.HasPrefix(tr, "Overview")) &&
				(strings.Contains(tr, "Docs") || strings.Contains(tr, "Versions") || strings.Contains(tr, "Score")) {
				continue
			}
			outLines = append(outLines, ln)
		}
		cleaned := strings.TrimSpace(reMWExcessBlankDeclHTML.ReplaceAllString(strings.Join(outLines, "\n"), "\n\n"))
		if cleaned != "" && cleaned != strings.TrimSpace(ctx.currentMD) {
			return &DeclarativePostFetchResult{
				ExtractorID: extractorID,
				Markdown:    cleaned,
			}
		}
		return nil

	case "mediawiki":
		headSlice := ctx.rawHTML
		if len(headSlice) > 4000 {
			headSlice = headSlice[:4000]
		}
		if !strings.HasSuffix(ctx.host, ".wikipedia.org") &&
			ctx.host != "wiki.archlinux.org" &&
			!reMediaWikiGenDeclHTML.MatchString(headSlice) {
			return nil
		}
		cleaned := cleanMediaWikiMarkdownDeclHTML(ctx.currentMD)
		if cleaned != "" && (len(cleaned) != len(ctx.currentMD) || cleaned != strings.TrimSpace(ctx.currentMD)) {
			return &DeclarativePostFetchResult{
				ExtractorID: extractorID,
				Markdown:    cleaned,
			}
		}
		return nil
	default:
		return nil
	}
}

// ── Mode 5, 6, 7: Gist, StackExchange HTML, Reddit Shreddit ─────────────────────────────────────

func runGistExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	doc := ParseHTMLDoc(ctx.rawHTML, 0)
	desc := SanitizeScrapedMeta(doc.Text(`div[itemprop="about"]`))
	titleRaw := SanitizeScrapedMeta(strings.TrimSpace(reGistTitleSuffixDeclHTML.ReplaceAllString(doc.Text("title"), "")))

	var files []string
	for _, box := range doc.Select("div.file", 20) {
		name := SanitizeScrapedMeta(box.Text("strong.gist-blob-name"))
		if name == "" {
			continue
		}
		safeName := escapeDeclMarkdownBrackets(name)
		if mdArticleHTML := box.HTML("article.markdown-body"); mdArticleHTML != "" {
			md, _ := ctx.htmlToMD(mdArticleHTML, ctx.baseURL)
			files = append(files, "## "+safeName+"\n\n"+strings.TrimSpace(md))
			continue
		}
		tds := box.Select("td.blob-code-inner", 2000)
		if len(tds) > 0 {
			codeLines := make([]string, len(tds))
			for i, td := range tds {
				codeLines[i] = td.Text()
			}
			lang, _ := detectDeclarativeFenceLang(name)
			files = append(files, "## "+safeName+"\n\n"+safeDeclarativeFence(strings.Join(codeLines, "\n"), lang))
		}
	}
	if len(files) == 0 {
		return nil
	}
	title := titleRaw
	if title == "" {
		title = desc
	}
	if title == "" {
		title = "GitHub Gist"
	}
	sections := []string{"# " + escapeDeclMarkdownBrackets(title)}
	if desc != "" && desc != title {
		sections = append(sections, escapeDeclMarkdownBlock(desc))
	}
	sections = append(sections, strings.Join(files, "\n\n"))
	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Description: desc,
		Markdown:    strings.Join(sections, "\n\n"),
	}
}

func runStackExchangeExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	cleanHTML := stripScriptsAndStylesDeclHTML(ctx.rawHTML)
	var qHeaderInner string
	if qHeaderOpen, ok := findOpenTagLinearDeclHTML(cleanHTML, "div", func(a string) bool {
		id, _ := getAttrValueLinearDeclHTML(a, "id")
		return id == "question-header"
	}, 0); ok {
		qHeaderInner, _ = extractBalancedDivAtDeclHTML(cleanHTML, qHeaderOpen.index)
	}
	h1Scope := cleanHTML
	if qHeaderInner != "" {
		h1Scope = qHeaderInner
	}
	h1Inner, _ := findElementInnerLinearDeclHTML(h1Scope, "h1", nil, 0)
	title := SanitizeScrapedMeta(reSEClosedSuffixDeclHTML.ReplaceAllString(stripTagsInlineLinear(h1Inner), ""))

	qOpen, okQ := findOpenTagLinearDeclHTML(cleanHTML, "div", func(a string) bool {
		id, _ := getAttrValueLinearDeclHTML(a, "id")
		return id == "question"
	}, 0)
	if !okQ || title == "" {
		return nil
	}
	qInner, okQI := extractBalancedDivAtDeclHTML(cleanHTML, qOpen.index)
	if !okQI || qInner == "" {
		return nil
	}

	extractPostBody := func(block string) string {
		bodyOpen, okB := findOpenTagLinearDeclHTML(block, "div", func(a string) bool {
			return attrHasTokenLinearDeclHTML(a, "class", "s-prose") ||
				attrHasTokenLinearDeclHTML(a, "class", "js-post-body") ||
				attrHasTokenLinearDeclHTML(a, "class", "post-text")
		}, 0)
		if !okB {
			return ""
		}
		inner, okI := extractBalancedDivAtDeclHTML(block, bodyOpen.index)
		if !okI || inner == "" {
			return ""
		}
		md, _ := ctx.htmlToMD(inner, ctx.baseURL)
		return strings.TrimSpace(md)
	}

	extractComments := func(block string) []string {
		var out []string
		for _, cm := range findAllElementInnersLinearDeclHTML(block, "span", func(a string) bool {
			return attrHasTokenLinearDeclHTML(a, "class", "comment-copy")
		}, 6) {
			txt := escapeDeclMarkdownBrackets(SanitizeScrapedMeta(stripTagsInlineLinear(cm)))
			if txt != "" && len(out) < 6 {
				out = append(out, "> - *Comment*: "+txt)
			}
		}
		return out
	}

	qScore, hasQScore := getAttrValueLinearDeclHTML(qOpen.attrStr, "data-score")
	if !hasQScore {
		vcInner, _ := findElementInnerLinearDeclHTML(qInner, "div", func(a string) bool {
			return attrHasTokenLinearDeclHTML(a, "class", "js-vote-count")
		}, 0)
		qScore = stripTagsInlineLinear(vcInner)
	}
	qScore = escapeDeclMarkdownBrackets(SanitizeScrapedMeta(qScore))

	var tags []string
	seenTag := make(map[string]bool)
	for _, inner := range findAllElementInnersLinearDeclHTML(qInner, "a", func(a string) bool {
		return attrHasTokenLinearDeclHTML(a, "class", "post-tag")
	}, 16) {
		t := sanitizeDeclInlineCodeVal(SanitizeScrapedMeta(stripTagsInlineLinear(inner)))
		if t != "" && !seenTag[t] {
			seenTag[t] = true
			tags = append(tags, "`"+t+"`")
			if len(tags) >= 8 {
				break
			}
		}
	}

	qMd := extractPostBody(qInner)
	if qMd == "" {
		return nil
	}

	sections := []string{"# " + escapeDeclMarkdownBrackets(title)}
	var qMeta []string
	if qScore != "" {
		qMeta = append(qMeta, "**Votes**: "+qScore)
	}
	if len(tags) > 0 {
		qMeta = append(qMeta, "**Tags**: "+strings.Join(tags, ", "))
	}
	if len(qMeta) > 0 {
		sections = append(sections, strings.Join(qMeta, " · "))
	}
	sections = append(sections, "## Question\n\n"+qMd)
	if qComments := extractComments(qInner); len(qComments) > 0 {
		sections = append(sections, strings.Join(qComments, "\n"))
	}

	type seAnswer struct {
		accepted bool
		score    int
		md       string
		comments []string
	}
	var answers []seAnswer
	ansOpens := findAllOpenTagsLinearDeclHTML(cleanHTML, "div", func(a string) bool {
		id, _ := getAttrValueLinearDeclHTML(a, "id")
		return reSEAnswerIDDeclHTML.MatchString(id)
	}, 12)
	for _, am := range ansOpens {
		aInner, okA := extractBalancedDivAtDeclHTML(cleanHTML, am.index)
		if !okA || aInner == "" {
			continue
		}
		head := aInner
		if len(head) > 2000 {
			head = head[:2000]
		}
		accepted := attrHasTokenLinearDeclHTML(am.attrStr, "class", "accepted-answer") ||
			attrHasTokenLinearDeclHTML(am.attrStr, "class", "js-accepted-answer") ||
			reSEAcceptedIndDeclHTML.MatchString(head)
		scoreRaw, hasScore := getAttrValueLinearDeclHTML(am.attrStr, "data-score")
		if !hasScore {
			vcInner, _ := findElementInnerLinearDeclHTML(aInner, "div", func(a string) bool {
				return attrHasTokenLinearDeclHTML(a, "class", "js-vote-count")
			}, 0)
			scoreRaw = stripTagsInlineLinear(vcInner)
		}
		score, _ := strconv.Atoi(strings.TrimSpace(scoreRaw))
		md := extractPostBody(aInner)
		if md == "" {
			continue
		}
		answers = append(answers, seAnswer{
			accepted: accepted,
			score:    score,
			md:       md,
			comments: extractComments(aInner),
		})
	}

	sort.SliceStable(answers, func(i, j int) bool {
		if answers[i].accepted != answers[j].accepted {
			return answers[i].accepted
		}
		return answers[i].score > answers[j].score
	})
	maxAns := len(answers)
	if maxAns > 8 {
		maxAns = 8
	}
	for i := 0; i < maxAns; i++ {
		a := answers[i]
		var heading string
		if a.accepted {
			heading = fmt.Sprintf("## ✅ Accepted Answer (Score: %d)", a.score)
		} else {
			heading = fmt.Sprintf("## Answer %d (Score: %d)", i+1, a.score)
		}
		sections = append(sections, heading+"\n\n"+a.md)
		if len(a.comments) > 0 {
			sections = append(sections, strings.Join(a.comments, "\n"))
		}
	}

	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Markdown:    strings.Join(sections, "\n\n"),
	}
}

func runRedditShredditExtractorDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	doc := ParseHTMLDoc(ctx.rawHTML, 0)
	shPost := doc.First("shreddit-post")
	if shPost == nil {
		return nil
	}
	pTitle := SanitizeScrapedMeta(stdhtml.UnescapeString(shPost.AttrOrEmpty("post-title")))
	if pTitle == "" {
		return nil
	}
	author := SanitizeScrapedMeta(stdhtml.UnescapeString(shPost.AttrOrEmpty("author")))
	score := SanitizeScrapedMeta(stdhtml.UnescapeString(shPost.AttrOrEmpty("score")))
	sub := SanitizeScrapedMeta(stdhtml.UnescapeString(shPost.AttrOrEmpty("subreddit-prefixed-name")))
	bodyHTML := shPost.HTML()
	bodyMD := ""
	if bodyHTML != "" {
		md, _ := ctx.htmlToMD(bodyHTML, ctx.baseURL)
		bodyMD = strings.TrimSpace(md)
	}

	sections := []string{"# " + escapeDeclMarkdownBrackets(pTitle)}
	var meta []string
	if sub != "" {
		meta = append(meta, escapeDeclMarkdownBrackets(sub))
	}
	if author != "" {
		meta = append(meta, "u/"+escapeDeclMarkdownBrackets(author))
	}
	if score != "" {
		meta = append(meta, escapeDeclMarkdownBrackets(score)+" upvotes")
	}
	if len(meta) > 0 {
		sections = append(sections, "*"+strings.ReplaceAll(strings.Join(meta, " · "), "*", `\*`)+"*")
	}
	if bodyMD != "" {
		sections = append(sections, bodyMD)
	}

	var comments []string
	for _, cm := range doc.Select("shreddit-comment", 25) {
		cAuthor := SanitizeScrapedMeta(stdhtml.UnescapeString(cm.AttrOrEmpty("author")))
		if cAuthor == "" {
			cAuthor = "user"
		}
		cScore := escapeDeclMarkdownBrackets(SanitizeScrapedMeta(stdhtml.UnescapeString(cm.AttrOrEmpty("score"))))
		cDepth, _ := strconv.Atoi(strings.TrimSpace(cm.AttrOrEmpty("depth")))
		if cDepth < 0 {
			cDepth = 0
		}
		if cDepth > 5 {
			cDepth = 5
		}
		cHTML := cm.HTML()
		if cHTML != "" {
			rawCMd, _ := ctx.htmlToMD(cHTML, ctx.baseURL)
			cMd := strings.Join(strings.Fields(strings.TrimSpace(rawCMd)), " ")
			if cMd != "" {
				scorePart := ""
				if cScore != "" {
					scorePart = " (" + cScore + ")"
				}
				comments = append(comments, fmt.Sprintf("%s- **u/%s**%s: %s", strings.Repeat("  ", cDepth), escapeDeclMarkdownBrackets(cAuthor), scorePart, cMd))
			}
		}
	}
	if len(comments) > 0 {
		sections = append(sections, "## Comments\n\n"+strings.Join(comments, "\n"))
	}

	outAuthor := ""
	if author != "" {
		outAuthor = "u/" + author
	}
	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       pTitle,
		Author:      outAuthor,
		Markdown:    strings.Join(sections, "\n\n"),
	}
}

// ── Mode 8: iCIMS Portal (`parseIcimsPortalHtml` 1:1) ───────────────────────────────────────────

func stripQueryParamDeclHTML(u *url.URL, key string) string {
	cloned := *u
	if cloned.RawQuery != "" {
		q := cloned.Query()
		q.Del(key)
		cloned.RawQuery = q.Encode()
	}
	return cloned.String()
}

func parseIcimsPortalHTMLDeclHTML(rawHTML, origURL string, htmlToMD func(frag, base string) (string, []string), extractorID string) *DeclarativePostFetchResult {
	u, err := url.Parse(origURL)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	hostSlug := strings.Split(u.Hostname(), ".")[0]
	if hostSlug == "" {
		hostSlug = u.Hostname()
	}
	isSingleJob := reIcimsSingleJobDeclHTML.MatchString(u.Path)
	if !isSingleJob &&
		indexFoldASCIIExtract(rawHTML, "icims") < 0 &&
		!strings.Contains(rawHTML, "/jobs/") &&
		indexFoldASCIIExtract(rawHTML, "jobposting") < 0 &&
		indexFoldASCIIExtract(rawHTML, "no ") < 0 &&
		!strings.Contains(rawHTML, "0 ") {
		return nil
	}
	doc := ParseHTMLDoc(rawHTML, 0)

	if isSingleJob {
		ldObjects := extractJSONLDObjectsDeclHTML(rawHTML, 100)
		var jobLD map[string]any
		for _, o := range ldObjects {
			if strings.Contains(strings.ToLower(jsonLDTypeStringDeclHTML(o)), "jobposting") {
				jobLD = o
				break
			}
		}
		rawTitle := ""
		if jobLD != nil {
			if tStr, ok := jobLD["title"].(string); ok {
				rawTitle = stripTagsInlineLinear(tStr)
			}
		}
		if rawTitle == "" {
			rawTitle = doc.Text("h1.iCIMS_Header")
		}
		if rawTitle == "" {
			rawTitle = doc.Text("h1")
		}
		title := SanitizeScrapedMeta(rawTitle)
		if title == "" {
			return nil
		}

		rawCompany := ""
		if jobLD != nil {
			switch org := jobLD["hiringOrganization"].(type) {
			case string:
				rawCompany = stripTagsInlineLinear(org)
			case map[string]any:
				if nm, ok := org["name"].(string); ok {
					rawCompany = stripTagsInlineLinear(nm)
				}
			}
		}
		if rawCompany == "" {
			rawCompany = hostSlug
		}
		company := SanitizeScrapedMeta(rawCompany)

		var rawLocs []any
		if jobLD != nil && jobLD["jobLocation"] != nil {
			if arr, isA := jobLD["jobLocation"].([]any); isA {
				rawLocs = arr
			} else {
				rawLocs = []any{jobLD["jobLocation"]}
			}
		}
		var locations []string
		for _, loc := range rawLocs {
			locMap, okL := loc.(map[string]any)
			if !okL {
				continue
			}
			addr := locMap
			if sub, okA := locMap["address"].(map[string]any); okA {
				addr = sub
			}
			var parts []string
			for _, k := range []string{"addressLocality", "addressRegion", "addressCountry"} {
				if s, okS := addr[k].(string); okS && strings.TrimSpace(s) != "" {
					parts = append(parts, strings.TrimSpace(s))
				}
			}
			if len(parts) > 0 {
				locations = append(locations, strings.Join(parts, ", "))
			}
		}

		descHTML := ""
		if jobLD != nil {
			if dStr, ok := jobLD["description"].(string); ok && strings.TrimSpace(dStr) != "" {
				descHTML = dStr
			}
		}
		if descHTML == "" {
			descHTML = doc.HTML("div.iCIMS_JobContent")
		}
		if descHTML == "" {
			descHTML = doc.HTML("div.iCIMS_InfoMsg_Job")
		}
		bodyMD := ""
		if descHTML != "" {
			md, _ := htmlToMD(descHTML, origURL)
			bodyMD = strings.TrimSpace(md)
		}
		if bodyMD == "" && jobLD == nil {
			return nil
		}

		posted := ""
		empType := ""
		if jobLD != nil {
			if dp, ok := jobLD["datePosted"].(string); ok && len(dp) > 0 {
				posted = sliceRunesMax(dp, 10)
			}
			if et, ok := jobLD["employmentType"].(string); ok {
				empType = et
			}
		}
		canonicalJobURL := stripQueryParamDeclHTML(u, "in_iframe")

		bullets := []string{"- **Company**: " + escapeDeclMarkdownBrackets(company)}
		if len(locations) > 0 {
			bullets = append(bullets, "- **Location**: "+escapeDeclMarkdownBrackets(strings.Join(locations, "; ")))
		}
		if empType != "" {
			bullets = append(bullets, "- **Employment Type**: "+escapeDeclMarkdownBrackets(empType))
		}
		if posted != "" {
			bullets = append(bullets, "- **Posted**: "+escapeDeclMarkdownBrackets(posted))
		}

		fullTitle := title + " @ " + company
		headingLine := "# " + escapeDeclMarkdownBrackets(title) + " @ " + escapeDeclMarkdownBrackets(company)
		blocks := []string{headingLine, strings.Join(bullets, "\n")}
		if bodyMD != "" {
			blocks = append(blocks, bodyMD)
		}
		return &DeclarativePostFetchResult{
			ExtractorID:   extractorID,
			Title:         fullTitle,
			PublishedTime: posted,
			Markdown:      strings.Join(blocks, "\n\n"),
			Links:         []string{canonicalJobURL},
		}
	}

	cardsByJobID := make(map[string]*HTMLNode)
	for _, card := range doc.Select("li.iCIMS_JobCardItem, div.iCIMS_JobCardItem, div.iCIMS_JobsTable div.row, div.row", 200) {
		for _, cardLink := range card.Select(`a[href*="/jobs/"]`, 8) {
			href := unescapeHrefURLDeclHTML(cardLink.AttrOrEmpty("href"))
			if idM := reIcimsJobIDHrefDeclHTML.FindStringSubmatch(href); len(idM) == 2 && cardsByJobID[idM[1]] == nil {
				cardsByJobID[idM[1]] = card
				break
			}
		}
	}

	type icimsCard struct {
		id       string
		title    string
		url      string
		location string
		pay      string
		postedAt string
	}
	var jobs []icimsCard
	seenJobID := make(map[string]bool)

	originBase := &url.URL{Scheme: u.Scheme, Host: u.Host}
	for _, ao := range doc.Select(`a.iCIMS_Anchor, a[href*="/jobs/"]`, 200) {
		rawHref := unescapeHrefURLDeclHTML(ao.AttrOrEmpty("href"))
		idM := reIcimsJobIDHrefDeclHTML.FindStringSubmatch(rawHref)
		if len(idM) != 2 {
			continue
		}
		jobID := idM[1]
		if seenJobID[jobID] {
			continue
		}

		rawTitleAttr := strings.TrimSpace(reIcimsLeadDigitsDeclHTML.ReplaceAllString(ao.AttrOrEmpty("title"), ""))
		candTxt := ao.Text("h3")
		if candTxt == "" {
			candTxt = ao.Text("h2")
		}
		if candTxt == "" {
			candTxt = ao.Text()
		}
		candTxt = strings.TrimSpace(reIcimsJobTitlePrefDeclHTML.ReplaceAllString(candTxt, ""))
		if candTxt == "" {
			candTxt = rawTitleAttr
		}
		linkTitle := SanitizeScrapedMeta(candTxt)
		if linkTitle == "" {
			continue
		}

		refU, errR := url.Parse(rawHref)
		if errR != nil {
			continue
		}
		targetU := originBase.ResolveReference(refU)
		if targetU.Scheme != "https" {
			continue
		}
		resolvedURL := stripQueryParamDeclHTML(targetU, "in_iframe")
		if resolvedURL == "" {
			continue
		}

		var location, pay, postedAt string
		if cardNode := cardsByJobID[jobID]; cardNode != nil {
			for _, span := range cardNode.Select("span[title]", 12) {
				tVal := strings.TrimSpace(span.AttrOrEmpty("title"))
				if reIcimsSpanDateDeclHTML.MatchString(tVal) {
					fields := strings.Fields(tVal)
					if len(fields) > 0 {
						postedAt = fields[0]
					} else {
						postedAt = tVal
					}
					break
				}
			}
			for _, dlPairs := range []map[string]string{cardNode.DLMap("div.iCIMS_JobHeaderTag"), cardNode.DLMap()} {
				for _, dtTxt := range sortedMapKeys(dlPairs) {
					ddTxt := dlPairs[dtTxt]
					if ddTxt == "" {
						continue
					}
					if location == "" && strings.Contains(dtTxt, "location") {
						location = ddTxt
					} else if pay == "" && (strings.Contains(dtTxt, "salary") || strings.Contains(dtTxt, "pay") || strings.Contains(dtTxt, "compensation")) {
						pay = ddTxt
					}
				}
				if location != "" && pay != "" {
					break
				}
			}
		}

		seenJobID[jobID] = true
		jobs = append(jobs, icimsCard{
			id:       jobID,
			title:    linkTitle,
			url:      resolvedURL,
			location: location,
			pay:      pay,
			postedAt: postedAt,
		})
	}

	if len(jobs) == 0 {
		for _, ld := range extractJSONLDObjectsDeclHTML(rawHTML, 100) {
			if strings.Contains(strings.ToLower(jsonLDTypeStringDeclHTML(ld)), "jobposting") {
				ldURLRaw, _ := ld["url"].(string)
				ldURLRaw = strings.TrimSpace(ldURLRaw)
				idM := reIcimsJobIDHrefDeclHTML.FindStringSubmatch(ldURLRaw)
				ldTitleRaw, _ := ld["title"].(string)
				ldTitle := SanitizeScrapedMeta(stripTagsInlineLinear(ldTitleRaw))
				if len(idM) == 2 && ldTitle != "" && !seenJobID[idM[1]] {
					if refU, errR := url.Parse(ldURLRaw); errR == nil {
						targetU := originBase.ResolveReference(refU)
						if targetU.Scheme == "https" {
							posted := ""
							if dp, ok := ld["datePosted"].(string); ok {
								posted = sliceRunesMax(dp, 10)
							}
							seenJobID[idM[1]] = true
							jobs = append(jobs, icimsCard{
								id:       idM[1],
								title:    ldTitle,
								url:      stripQueryParamDeclHTML(targetU, "in_iframe"),
								postedAt: posted,
							})
						}
					}
				}
			}
		}
	}

	if len(jobs) == 0 {
		if reIcimsIframeShellDeclHTML.MatchString(rawHTML) {
			return nil
		}
		if !reIcimsExplicitZeroDeclHTML.MatchString(doc.Text()) {
			return nil
		}
		emptyTitle := hostSlug + " — iCIMS Career Portal"
		matchedEmpty := strings.TrimSpace(reIcimsExplicitZeroDeclHTML.FindString(doc.Text()))
		emptyBody := "No open positions currently listed (0 open roles)."
		if matchedEmpty != "" && !strings.Contains(strings.ToLower(matchedEmpty), "0 open roles") {
			emptyBody = matchedEmpty + " (0 open roles)."
		}
		zero := 0
		notTrunc := false
		return &DeclarativePostFetchResult{
			ExtractorID: extractorID,
			Title:       emptyTitle,
			Markdown:    "# " + escapeDeclMarkdownBrackets(emptyTitle) + "\n\n" + emptyBody,
			Links:       []string{},
			Records:     []map[string]any{},
			Total:       &zero,
			Returned:    &zero,
			Truncated:   &notTrunc,
		}
	}

	plainHeader := sliceRunesMax(doc.Text(), 80_000)
	curPage := 1
	totalPages := 1
	if pm := reIcimsPageOfDeclHTML.FindStringSubmatch(plainHeader); len(pm) == 3 {
		if cp, err1 := strconv.Atoi(pm[1]); err1 == nil && cp > 1 {
			curPage = cp
		}
		if tp, err2 := strconv.Atoi(pm[2]); err2 == nil && tp > 1 {
			totalPages = tp
		}
	}
	hasNextRel := doc.First(`[rel="next"]`) != nil
	hasMorePages := curPage < totalPages || (totalPages == 1 && hasNextRel)

	portalHeading := doc.Text("h1.iCIMS_Header")
	rawCompLabel := hostSlug
	if portalHeading != "" {
		if stripped := strings.TrimSpace(reIcimsCareerSuffixDeclHTML.ReplaceAllString(portalHeading, "")); stripped != "" {
			rawCompLabel = stripped
		}
	}
	companyLabel := SanitizeScrapedMeta(rawCompLabel)

	links := make([]string, len(jobs))
	for i, j := range jobs {
		links[i] = j.url
	}
	rowCap := len(jobs)
	if rowCap > 100 {
		rowCap = 100
	}
	rows := make([][]string, rowCap)
	for i := 0; i < rowCap; i++ {
		j := jobs[i]
		loc := j.location
		if loc == "" {
			loc = "-"
		}
		pay := j.pay
		if pay == "" {
			pay = "-"
		}
		rows[i] = []string{
			fmt.Sprintf("[%s](%s)", escapeDeclMarkdownBrackets(j.title), PercentEncodeUnsafeRecordURLChars(j.url)),
			"`" + strings.ReplaceAll(j.id, "`", "'") + "`",
			escapeDeclMarkdownBrackets(loc),
			escapeDeclMarkdownBrackets(pay),
		}
	}

	isTruncated := hasMorePages || len(jobs) > len(rows)
	nextCursor := ""
	if hasMorePages {
		nextCursor = fmt.Sprintf("pr=%d", curPage)
	} else if len(jobs) > len(rows) {
		nextCursor = strconv.Itoa(len(rows))
	}

	var title string
	if totalPages > 1 {
		title = fmt.Sprintf("%s — iCIMS Career Portal (Page %d of %d, %d shown)", companyLabel, curPage, totalPages, len(rows))
	} else {
		title = fmt.Sprintf("%s — iCIMS Career Portal (%d open roles)", companyLabel, len(jobs))
	}

	truncFooter := ""
	if isTruncated && nextCursor != "" {
		pagePart := ""
		if totalPages > 1 {
			pagePart = fmt.Sprintf(" on page %d of %d", curPage, totalPages)
		}
		qPart := "offset=" + nextCursor
		if strings.HasPrefix(nextCursor, "pr=") {
			qPart = nextCursor
		}
		truncFooter = fmt.Sprintf("\n\n*Showing %d open roles%s (list cut short — pass `?%s` for the next page).*", len(rows), pagePart, qPart)
	}

	records := make([]map[string]any, len(jobs))
	for i, j := range jobs {
		rec := map[string]any{
			"id":      j.id,
			"title":   j.title,
			"company": companyLabel,
			"url":     j.url,
			"source":  "icims",
		}
		if j.location != "" {
			rec["location"] = j.location
			rec["locations"] = []string{j.location}
		}
		if j.pay != "" {
			rec["payRaw"] = j.pay
			rec["salary"] = j.pay
		}
		if j.postedAt != "" {
			rec["postedAt"] = j.postedAt
		}
		records[i] = rec
	}

	retCount := len(rows)
	res := &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Markdown:    "# " + escapeDeclMarkdownBrackets(title) + "\n\n" + formatDeclarativeGFMTable([]string{"Role", "Job ID", "Location", "Salary"}, rows) + truncFooter,
		Links:       links,
		Records:     records,
		Returned:    &retCount,
		Truncated:   &isTruncated,
		NextCursor:  nextCursor,
	}
	if !hasMorePages {
		tot := len(jobs)
		res.Total = &tot
	}
	return res
}

// ── Mode 9 & 10: Shopify & WooCommerce Product HTML (`commerce-engine.ts` 1:1) ──────────────────

func sanitizeCommerceFieldDeclHTML(raw any, maxLen int) string {
	s, ok := raw.(string)
	if !ok || s == "" {
		return ""
	}
	if maxLen <= 0 {
		maxLen = 400
	}
	s = reANSIEscapeDeclHTML.ReplaceAllString(s, "")
	s = stripInvisibleSmugglingCharsGo(s)
	var flat strings.Builder
	flat.Grow(len(s))
	prevSpace := true
	for _, r := range s {
		if r <= 0x1F || r == 0x7F || r == 0x0085 || r == 0x2028 || r == 0x2029 || r == ' ' {
			if r == '\r' || r == '\n' || r == '\t' || r == 0x0085 || r == 0x2028 || r == 0x2029 || r == ' ' {
				if !prevSpace {
					flat.WriteByte(' ')
					prevSpace = true
				}
			}
			continue
		}
		prevSpace = false
		flat.WriteRune(r)
	}
	s = strings.TrimSpace(flat.String())
	if s == "" {
		return ""
	}
	if len(s) > maxLen {
		s = strings.TrimSpace(sliceRunesMax(s, maxLen))
		if s == "" {
			return ""
		}
	}
	if strings.Contains(s, "](") || strings.Contains(s, "]:") || strings.Contains(s, "//") {
		s = NeutralizeAllUnsafeMarkdownLinks(s)
	}
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	if strings.Contains(s, "](") {
		s = reDangerousInlineLinkDeclHTML.ReplaceAllString(s, "](#)")
	}
	var esc strings.Builder
	esc.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		bs := 0
		for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
			bs++
		}
		prevEsc := bs%2 == 1
		if !prevEsc {
			switch c {
			case '[', ']', '*', '_', '~', '`', '#':
				esc.WriteByte('\\')
				esc.WriteByte(c)
				continue
			case '(':
				if i > 0 && (s[i-1] == ']' || s[i-1] == ' ') {
					esc.WriteByte('\\')
					esc.WriteByte('(')
					continue
				}
			}
		}
		esc.WriteByte(c)
	}
	return esc.String()
}

func sanitizeCommerceTimestampDeclHTML(raw any) string {
	s, ok := raw.(string)
	if !ok || s == "" {
		return ""
	}
	s = reANSIEscapeDeclHTML.ReplaceAllString(s, "")
	s = stripInvisibleSmugglingCharsGo(s)
	var flat strings.Builder
	prevSpace := true
	for _, r := range s {
		if r <= 0x20 || (r >= 0x7F && r <= 0x9F) || r == 0x2028 || r == 0x2029 {
			if !prevSpace {
				flat.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		flat.WriteRune(r)
	}
	s = strings.TrimSpace(flat.String())
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(sliceRunesMax(s, 96))
	if s == "" {
		return ""
	}
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"*", `\*`,
		"_", `\_`,
		"#", `\#`,
		"`", "\\`",
		"|", "&#124;",
	)
	return r.Replace(s)
}

func formatCommerceSKUDisplayDeclHTML(sku string, escapePipesForProse bool) string {
	if sku == "" {
		return "`-`"
	}
	prepared := sku
	if escapePipesForProse {
		prepared = strings.ReplaceAll(prepared, "|", `\|`)
	}
	if !strings.ContainsAny(prepared, `\&|`) {
		return "`" + prepared + "`"
	}
	return prepared
}

func normalizePublicCommerceImageURLDeclHTML(raw any) string {
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 2048 || strings.Contains(s, `\`) {
		return ""
	}
	if strings.HasPrefix(s, "//") {
		if strings.HasPrefix(s, "///") {
			return ""
		}
		s = "https:" + s
	} else if !strings.HasPrefix(strings.ToLower(s), "https://") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return ""
	}
	if port := u.Port(); port != "" && port != "443" {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !isSafePublicHostnameGo(h) || IsPublicOrPrivateSuffix(h) {
		return ""
	}
	return u.String()
}

func stripNonPublicMarkdownImagesDeclHTML(md string) string {
	if md == "" || !strings.Contains(md, "![") {
		return md
	}
	return reNonPublicMdImgDeclHTML.ReplaceAllStringFunc(md, func(full string) string {
		sub := reNonPublicMdImgDeclHTML.FindStringSubmatch(full)
		if len(sub) < 3 {
			return full
		}
		trimmed := strings.TrimSpace(sub[2])
		var rawDest string
		if strings.HasPrefix(trimmed, "<") {
			gt := strings.IndexByte(trimmed, '>')
			if gt > 0 {
				rawDest = strings.TrimSpace(trimmed[1:gt])
			} else {
				rawDest = strings.TrimSpace(trimmed[1:])
			}
		} else {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 {
				rawDest = fields[0]
			}
		}
		if normalizePublicCommerceImageURLDeclHTML(rawDest) != "" {
			return full
		}
		return ""
	})
}

func isShopifyHTMLDeclHTML(rawHTML string) bool {
	if rawHTML == "" {
		return false
	}
	head := rawHTML
	if len(head) > 120_000 {
		head = head[:120_000]
	}
	return reShopifyDomainDeclHTML.MatchString(head) ||
		strings.Contains(head, "cdn.shopify.com") ||
		reShopifyShopVarDeclHTML.MatchString(head) ||
		strings.Contains(head, "shopify-digital-wallet") ||
		strings.Contains(head, "ShopifyAnalytics") ||
		strings.Contains(head, "shopify-section")
}

func extractShopifyCurrencyFromHTMLDeclHTML(rawHTML string) string {
	if rawHTML == "" {
		return ""
	}
	slice := rawHTML
	if len(slice) > 120_000 {
		slice = slice[:120_000]
	}
	if m := reShopifyActiveCurDeclHTML.FindStringSubmatch(slice); len(m) == 2 {
		return strings.ToUpper(m[1])
	}
	metaCur := extractMetaContentDeclHTML(slice, "og:price:currency")
	if metaCur == "" {
		metaCur = extractMetaContentDeclHTML(slice, "product:price:currency")
	}
	metaUpper := strings.ToUpper(strings.TrimSpace(metaCur))
	if reISOCurrency3DeclHTML.MatchString(metaUpper) {
		return metaUpper
	}
	if m := reShopifyLDCurDeclHTML.FindStringSubmatch(slice); len(m) == 2 {
		return strings.ToUpper(m[1])
	}
	return ""
}

func extractEmbeddedShopifyProductJSONDeclHTML(rawHTML string) map[string]any {
	scriptOpens := findAllOpenTagsLinearDeclHTML(rawHTML, "script", func(attr string) bool {
		t, _ := getAttrValueLinearDeclHTML(attr, "type")
		t = strings.ToLower(t)
		if t != "" && t != "application/json" && t != "text/json" {
			return false
		}
		id, _ := getAttrValueLinearDeclHTML(attr, "id")
		attrLow := strings.ToLower(attr)
		return strings.Contains(attrLow, "data-product-json") ||
			strings.Contains(attrLow, "data-product") ||
			reShopifyProdJSONIDDeclHTML.MatchString(id)
	}, 12)
	for _, sc := range scriptOpens {
		closeStart, _, ok := findCloseTagLinearDeclHTML(rawHTML, "script", sc.openEnd)
		if !ok {
			break
		}
		cand := strings.TrimSpace(rawHTML[sc.openEnd:closeStart])
		if parsed, okP := parseJSONObjectDeclHTML(cand); okP {
			if _, hasT := parsed["title"].(string); hasT {
				return parsed
			}
			if sub, okSub := parsed["product"].(map[string]any); okSub {
				if _, hasT := sub["title"].(string); hasT {
					return parsed
				}
			}
		}
	}

	metaMarker := strings.Index(rawHTML, "var meta = {")
	if metaMarker != -1 && metaMarker < 200_000 {
		braceRel := strings.IndexByte(rawHTML[metaMarker:], '{')
		if braceRel >= 0 {
			startBrace := metaMarker + braceRel
			endRel := indexFoldASCIIExtract(rawHTML[startBrace:], "</script>")
			if endRel > 0 && endRel < 200_000 {
				block := rawHTML[startBrace : startBrace+endRel]
				if semiIdx := strings.Index(block, "};"); semiIdx >= 0 {
					if parsed, okP := parseJSONObjectDeclHTML(block[:semiIdx+1]); okP {
						if p, okSub := parsed["product"].(map[string]any); okSub && p["id"] != nil {
							if vars, okV := p["variants"].([]any); okV && len(vars) > 0 {
								inferredTitle, _ := p["title"].(string)
								if inferredTitle == "" {
									if fv, okFV := vars[0].(map[string]any); okFV {
										if nm, okNm := fv["name"].(string); okNm {
											inferredTitle = strings.TrimSpace(strings.Split(nm, " - ")[0])
										}
									}
								}
								if inferredTitle != "" {
									clone := make(map[string]any, len(p)+1)
									for k, v := range p {
										clone[k] = v
									}
									clone["title"] = inferredTitle
									return clone
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func parseShopifyMoneyDeclHTML(raw any, isAjaxJS bool) (float64, bool) {
	if raw == nil {
		return 0, false
	}
	switch v := raw.(type) {
	case json.Number:
		s := v.String()
		if isAjaxJS && !strings.Contains(s, ".") {
			if cents, err := strconv.ParseInt(s, 10, 64); err == nil && cents >= 0 {
				return float64(cents) / 100.0, true
			}
		}
		f, err := v.Float64()
		if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		if isAjaxJS {
			return math.Round(f) / 100.0, true
		}
		return f, true
	case float64:
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		if isAjaxJS {
			return math.Round(v) / 100.0, true
		}
		return v, true
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, false
		}
		if isAjaxJS {
			allDigits := true
			for i := 0; i < len(trimmed); i++ {
				if trimmed[i] < '0' || trimmed[i] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				cents, err := strconv.ParseInt(trimmed, 10, 64)
				if err == nil && cents >= 0 {
					return float64(cents) / 100.0, true
				}
			}
		}
		f, err := strconv.ParseFloat(strings.ReplaceAll(trimmed, ",", ""), 64)
		return f, err == nil && f >= 0 && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}

func isRawJSONNumberDeclHTML(v any) bool {
	switch v.(type) {
	case json.Number, float64:
		return true
	default:
		return false
	}
}

func cleanVariantTitleDeclHTML(raw any) string {
	cleaned := sanitizeCommerceFieldDeclHTML(raw, 240)
	low := strings.ToLower(cleaned)
	if cleaned == "" || low == "default" || low == "default title" {
		return ""
	}
	return cleaned
}

func formatMoneyDisplayDeclHTML(amount float64, hasAmount bool, currency string) string {
	if !hasAmount {
		return "-"
	}
	fixed := fmt.Sprintf("%.2f", amount)
	if currency == "" || currency == "USD" {
		return "$" + fixed
	}
	return currency + " " + fixed
}

func enrichShopifyProductFromObjectDeclHTML(
	data map[string]any,
	productURL string,
	origin string,
	currency string,
	htmlToMD func(frag, base string) (string, []string),
	extractorID string,
) *DeclarativePostFetchResult {
	prod := data
	if sub, okSub := data["product"].(map[string]any); okSub {
		prod = sub
	}
	title := sanitizeCommerceFieldDeclHTML(prod["title"], 400)
	if title == "" {
		return nil
	}

	isAjaxJS := isRawJSONNumberDeclHTML(prod["price"])
	if !isAjaxJS {
		if vars, okV := prod["variants"].([]any); okV && len(vars) > 0 {
			if v0, ok0 := vars[0].(map[string]any); ok0 && isRawJSONNumberDeclHTML(v0["price"]) {
				isAjaxJS = true
			}
		}
	}

	productID := jsonScalarToString(prod["id"])
	handle := ""
	if h, okH := prod["handle"].(string); okH {
		handle = strings.TrimSpace(h)
	}
	prodCanonURL := origin
	if handle != "" {
		prodCanonURL = origin + "/products/" + encodeURIComponent(handle)
	}

	vendorStr := sanitizeCommerceFieldDeclHTML(prod["vendor"], 200)
	var vendorAny any
	if vendorStr != "" {
		vendorAny = vendorStr
	}

	rawType, _ := prod["product_type"].(string)
	if rawType == "" {
		rawType, _ = prod["type"].(string)
	}
	prodTypeStr := sanitizeCommerceFieldDeclHTML(rawType, 200)
	var prodTypeAny any
	if prodTypeStr != "" {
		prodTypeAny = prodTypeStr
	}

	var tags []string
	switch tv := prod["tags"].(type) {
	case []any:
		for _, el := range tv {
			if clean := sanitizeCommerceFieldDeclHTML(jsonScalarToString(el), 120); clean != "" {
				tags = append(tags, clean)
			}
		}
	case string:
		for _, tok := range strings.Split(tv, ",") {
			if clean := sanitizeCommerceFieldDeclHTML(tok, 120); clean != "" {
				tags = append(tags, clean)
			}
		}
	}
	if tags == nil {
		tags = []string{}
	}

	imageByID := make(map[string]string)
	imageByVariantID := make(map[string]string)
	allImageURLs := make([]string, 0)
	seenImg := make(map[string]bool)
	if rawImgs, okI := prod["images"].([]any); okI {
		for _, img := range rawImgs {
			switch iv := img.(type) {
			case string:
				u := normalizePublicCommerceImageURLDeclHTML(iv)
				if u != "" && !seenImg[u] && len(allImageURLs) < 250 {
					seenImg[u] = true
					allImageURLs = append(allImageURLs, u)
				}
			case map[string]any:
				cand := iv["src"]
				if cand == nil {
					cand = iv["url"]
				}
				u := normalizePublicCommerceImageURLDeclHTML(cand)
				if u == "" {
					continue
				}
				if !seenImg[u] && len(allImageURLs) < 250 {
					seenImg[u] = true
					allImageURLs = append(allImageURLs, u)
				}
				if idS := jsonScalarToString(iv["id"]); idS != "" && len(imageByID) < 1000 {
					imageByID[idS] = u
				}
				if vIDs, okVID := iv["variant_ids"].([]any); okVID {
					for _, vid := range vIDs {
						if vidS := jsonScalarToString(vid); vidS != "" && len(imageByVariantID) < 1000 {
							imageByVariantID[vidS] = u
						}
					}
				}
			}
		}
	}

	options := make([]map[string]any, 0)
	if rawOpts, okO := prod["options"].([]any); okO {
		for _, opt := range rawOpts {
			switch ov := opt.(type) {
			case string:
				cleanOpt := sanitizeCommerceFieldDeclHTML(ov, 120)
				if cleanOpt != "" && !strings.EqualFold(cleanOpt, "title") {
					options = append(options, map[string]any{"name": cleanOpt, "values": []string{}})
				}
			case map[string]any:
				oName := sanitizeCommerceFieldDeclHTML(ov["name"], 120)
				vals := make([]string, 0)
				if vArr, okVA := ov["values"].([]any); okVA {
					for _, rv := range vArr {
						cv := sanitizeCommerceFieldDeclHTML(jsonScalarToString(rv), 120)
						if cv != "" && !strings.EqualFold(cv, "default title") {
							vals = append(vals, cv)
						}
					}
				}
				if oName != "" && !(strings.EqualFold(oName, "title") && len(vals) == 0) {
					options = append(options, map[string]any{"name": oName, "values": vals})
				}
			}
		}
	}

	curNorm := strings.ToUpper(strings.TrimSpace(currency))
	var curAny any
	if reISOCurrency3DeclHTML.MatchString(curNorm) {
		curAny = curNorm
	} else {
		curNorm = ""
	}

	variants := make([]map[string]any, 0)
	var rows [][]string
	if rawVars, okRV := prod["variants"].([]any); okRV {
		if len(rawVars) > 250 {
			rawVars = rawVars[:250]
		}
		for idx, rvAny := range rawVars {
			rv, okM := rvAny.(map[string]any)
			if !okM {
				continue
			}
			variantID := jsonScalarToString(rv["id"])
			skuStr := sanitizeCommerceFieldDeclHTML(rv["sku"], 160)
			var skuAny any
			if skuStr != "" {
				skuAny = skuStr
			}
			barcodeStr := sanitizeCommerceFieldDeclHTML(rv["barcode"], 160)
			vTitleStr := cleanVariantTitleDeclHTML(rv["title"])
			var vTitleAny any
			if vTitleStr != "" {
				vTitleAny = vTitleStr
			}

			optValues := make([]string, 0)
			if oArr, okOA := rv["options"].([]any); okOA {
				for _, o := range oArr {
					co := sanitizeCommerceFieldDeclHTML(jsonScalarToString(o), 120)
					if co != "" && !strings.EqualFold(co, "default title") {
						optValues = append(optValues, co)
					}
				}
			} else {
				for _, okKey := range []string{"option1", "option2", "option3"} {
					co := sanitizeCommerceFieldDeclHTML(rv[okKey], 120)
					if co != "" && !strings.EqualFold(co, "default title") {
						optValues = append(optValues, co)
					}
				}
			}

			priceVal, hasPrice := parseShopifyMoneyDeclHTML(rv["price"], isAjaxJS)
			var priceAny any
			if hasPrice {
				priceAny = priceVal
			}
			compVal, hasComp := parseShopifyMoneyDeclHTML(rv["compare_at_price"], isAjaxJS)
			var compAny any
			if hasComp && compVal > 0 {
				compAny = compVal
			} else {
				hasComp = false
			}

			var availAny any
			hasAvail := false
			availBool := false
			if b, isB := rv["available"].(bool); isB {
				availAny = b
				hasAvail = true
				availBool = b
			}

			invPolicy := ""
			if pol, okPol := rv["inventory_policy"].(string); okPol && (pol == "continue" || pol == "deny") {
				invPolicy = pol
			}
			hasQty := false
			qtyInt := 0
			if qf, okQ := jsonValueToFloat(rv["inventory_quantity"]); okQ && isRawJSONNumberDeclHTML(rv["inventory_quantity"]) {
				hasQty = true
				qtyInt = int(qf)
			}
			var gramsAny any
			if gf, okG := jsonValueToFloat(rv["grams"]); okG && isRawJSONNumberDeclHTML(rv["grams"]) {
				gramsAny = int(math.Round(gf))
			}

			var imgStr string
			switch fi := rv["featured_image"].(type) {
			case string:
				imgStr = normalizePublicCommerceImageURLDeclHTML(fi)
			case map[string]any:
				cand := fi["src"]
				if cand == nil {
					cand = fi["url"]
				}
				imgStr = normalizePublicCommerceImageURLDeclHTML(cand)
			}
			if imgStr == "" {
				if imgID := jsonScalarToString(rv["image_id"]); imgID != "" {
					imgStr = imageByID[imgID]
				}
			}
			if imgStr == "" && variantID != "" {
				imgStr = imageByVariantID[variantID]
			}
			var imgAny any
			if imgStr != "" {
				imgAny = imgStr
			}

			vRec := map[string]any{
				"variantId": variantID,
				"sku":       skuAny,
				"title":     vTitleAny,
				"options":   optValues,
				"price":     priceAny,
				"compareAt": compAny,
				"currency":  curAny,
				"available": availAny,
				"grams":     gramsAny,
				"image":     imgAny,
			}
			if barcodeStr != "" {
				vRec["barcode"] = barcodeStr
			}
			if invPolicy != "" {
				vRec["inventoryPolicy"] = invPolicy
			}
			if hasQty {
				vRec["inventoryQuantity"] = qtyInt
			}
			variants = append(variants, vRec)

			if idx < 60 {
				dispTitle := vTitleStr
				if dispTitle == "" {
					dispTitle = title
				}
				availDisp := "-"
				if hasAvail {
					if !availBool {
						availDisp = "Out of Stock"
					} else if invPolicy == "continue" && hasQty && qtyInt <= 0 {
						availDisp = "Backorder / Preorder"
					} else {
						availDisp = "Available"
					}
				}
				rows = append(rows, []string{
					dispTitle,
					formatCommerceSKUDisplayDeclHTML(skuStr, false),
					formatMoneyDisplayDeclHTML(priceVal, hasPrice, curNorm),
					formatMoneyDisplayDeclHTML(compVal, hasComp, curNorm),
					availDisp,
				})
			}
		}
	}

	bodyHTML, _ := prod["body_html"].(string)
	if bodyHTML == "" {
		bodyHTML, _ = prod["description"].(string)
	}
	descriptionText := stripTagsInlineLinear(bodyHTML)
	bodyMD := ""
	if bodyHTML != "" {
		rawBodyMD, _ := htmlToMD(bodyHTML, productURL)
		bodyMD = strings.TrimSpace(stripNonPublicMarkdownImagesDeclHTML(strings.TrimSpace(rawBodyMD)))
	}

	publishedAt := sanitizeCommerceTimestampDeclHTML(prod["published_at"])
	updatedAt := sanitizeCommerceTimestampDeclHTML(prod["updated_at"])
	var pubAny, updAny any
	if publishedAt != "" {
		pubAny = publishedAt
	}
	if updatedAt != "" {
		updAny = updatedAt
	}

	record := map[string]any{
		"platform":        "shopify",
		"origin":          origin,
		"productId":       productID,
		"handle":          handle,
		"url":             prodCanonURL,
		"title":           title,
		"vendor":          vendorAny,
		"productType":     prodTypeAny,
		"tags":            tags,
		"descriptionText": descriptionText,
		"publishedAt":     pubAny,
		"updatedAt":       updAny,
		"images":          allImageURLs,
		"options":         options,
		"variants":        variants,
	}

	var bullets []string
	if vendorStr != "" {
		bullets = append(bullets, "- **Brand / Vendor**: "+vendorStr)
	}
	if prodTypeStr != "" {
		bullets = append(bullets, "- **Product Type**: "+prodTypeStr)
	}
	if len(tags) > 0 {
		bullets = append(bullets, "- **Tags**: "+strings.Join(tags, ", "))
	}
	if curNorm != "" {
		bullets = append(bullets, "- **Currency**: "+curNorm)
	}

	sections := []string{"# " + title}
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	if len(rows) > 0 {
		sections = append(sections, "## Variants & Pricing\n\n"+formatDeclarativeGFMTable([]string{"Variant", "SKU", "Price", "Compare At", "Availability"}, rows))
	}
	if bodyMD != "" {
		sections = append(sections, "## Product Details\n\n"+bodyMD)
	}

	return &DeclarativePostFetchResult{
		ExtractorID:   extractorID,
		Title:         title,
		Description:   sliceRunesMax(descriptionText, 260),
		Author:        vendorStr,
		PublishedTime: publishedAt,
		Markdown:      strings.Join(sections, "\n\n"),
		Links:         []string{prodCanonURL},
		Records:       []map[string]any{record},
	}
}

func extractShopifyProductHTMLDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	if !reShopifyPathDeclHTML.MatchString(ctx.path) {
		return nil
	}
	if !isShopifyHTMLDeclHTML(ctx.rawHTML) {
		return nil
	}
	origin := ctx.u.Scheme + "://" + strings.ToLower(ctx.u.Host)
	currency := extractShopifyCurrencyFromHTMLDeclHTML(ctx.rawHTML)

	if embeddedObj := extractEmbeddedShopifyProductJSONDeclHTML(ctx.rawHTML); embeddedObj != nil {
		if res := enrichShopifyProductFromObjectDeclHTML(embeddedObj, ctx.u.String(), origin, currency, ctx.htmlToMD, extractorID); res != nil {
			return res
		}
	}

	ldObjects := extractJSONLDObjectsDeclHTML(ctx.rawHTML, 100)
	var prodLD map[string]any
	for _, o := range ldObjects {
		tLower := strings.ToLower(jsonLDTypeStringDeclHTML(o))
		if strings.Contains(tLower, "product") {
			prodLD = o
			break
		}
	}
	if prodLD == nil {
		return nil
	}
	prodName, okName := prodLD["name"].(string)
	if !okName {
		return nil
	}
	title := sanitizeCommerceFieldDeclHTML(prodName, 400)
	if title == "" {
		return nil
	}

	brand := ""
	switch b := prodLD["brand"].(type) {
	case string:
		brand = sanitizeCommerceFieldDeclHTML(b, 200)
	case map[string]any:
		brand = sanitizeCommerceFieldDeclHTML(b["name"], 200)
	}
	desc := ""
	if dStr, okD := prodLD["description"].(string); okD {
		desc = sanitizeCommerceFieldDeclHTML(stripTagsInlineLinear(dStr), 1200)
	}

	rawOffers := prodLD["hasVariant"]
	if rawOffers == nil {
		rawOffers = prodLD["offers"]
	}
	var offersList []map[string]any
	switch ov := rawOffers.(type) {
	case []any:
		for _, el := range ov {
			if m, okM := el.(map[string]any); okM {
				offersList = append(offersList, m)
			}
		}
	case map[string]any:
		offersList = []map[string]any{ov}
	}

	handle := ""
	for idx, seg := range ctx.parts {
		if strings.EqualFold(seg, "products") && idx+1 < len(ctx.parts) {
			if dec, err := url.PathUnescape(ctx.parts[idx+1]); err == nil {
				handle = dec
			} else {
				handle = ctx.parts[idx+1]
			}
			break
		}
	}

	if len(offersList) > 60 {
		offersList = offersList[:60]
	}
	variants := make([]map[string]any, 0, len(offersList))
	var rows [][]string
	for i, off := range offersList {
		subOffer := off
		if subArr, okSA := off["offers"].([]any); okSA && len(subArr) > 0 {
			if sm, okSM := subArr[0].(map[string]any); okSM {
				subOffer = sm
			}
		} else if sm, okSM := off["offers"].(map[string]any); okSM {
			subOffer = sm
		}
		rawVName, _ := off["name"].(string)
		rawVName = strings.TrimSpace(rawVName)
		vTitleStr := ""
		if rawVName != "" && sanitizeCommerceFieldDeclHTML(rawVName, 240) != title {
			vTitleStr = cleanVariantTitleDeclHTML(rawVName)
		}
		var vTitleAny any
		vOpts := []string{}
		if vTitleStr != "" {
			vTitleAny = vTitleStr
			vOpts = []string{vTitleStr}
		}

		skuRaw := off["sku"]
		if skuRaw == nil {
			skuRaw = subOffer["sku"]
		}
		skuStr := sanitizeCommerceFieldDeclHTML(skuRaw, 160)
		var skuAny any
		if skuStr != "" {
			skuAny = skuStr
		}

		var barcodeRaw any
		for _, bk := range []string{"gtin13", "gtin12", "gtin"} {
			if off[bk] != nil {
				barcodeRaw = off[bk]
				break
			}
		}
		if barcodeRaw == nil {
			if subOffer["gtin13"] != nil {
				barcodeRaw = subOffer["gtin13"]
			} else {
				barcodeRaw = subOffer["gtin12"]
			}
		}
		barcodeStr := sanitizeCommerceFieldDeclHTML(barcodeRaw, 160)

		rawPrice := subOffer["price"]
		if rawPrice == nil {
			rawPrice = subOffer["lowPrice"]
		}
		var priceVal float64
		hasPrice := false
		if sPrice, isS := rawPrice.(string); isS {
			if f, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(sPrice), ",", ""), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				priceVal = f
				hasPrice = true
			}
		} else if f, okF := jsonValueToFloat(rawPrice); okF {
			priceVal = f
			hasPrice = true
		}
		var priceAny any
		if hasPrice {
			priceAny = priceVal
		}

		curRaw, _ := subOffer["priceCurrency"].(string)
		curRaw = strings.ToUpper(strings.TrimSpace(curRaw))
		vCur := currency
		if reISOCurrency3DeclHTML.MatchString(curRaw) {
			vCur = curRaw
		}
		var vCurAny any
		if vCur != "" {
			vCurAny = vCur
		}

		availRaw := jsonScalarToString(subOffer["availability"])
		var availAny any
		availState := 0 // 0=null, 1=true, -1=false
		if reShopifyAvailTrueDeclHTML.MatchString(availRaw) {
			availAny = true
			availState = 1
		} else if reShopifyAvailFalseDeclHTML.MatchString(availRaw) {
			availAny = false
			availState = -1
		}
		invPol := ""
		if reShopifyPreorderDeclHTML.MatchString(availRaw) {
			invPol = "continue"
		}

		imgCand := off["image"]
		if arrI, isA := imgCand.([]any); isA && len(arrI) > 0 {
			imgCand = arrI[0]
		}
		if mI, isM := imgCand.(map[string]any); isM {
			imgCand = mI["url"]
		}
		imgStr := normalizePublicCommerceImageURLDeclHTML(imgCand)
		var imgAny any
		if imgStr != "" {
			imgAny = imgStr
		}

		vID := jsonScalarToString(off["@id"])
		if vID == "" {
			vID = skuStr
		}
		if vID == "" {
			vID = strconv.Itoa(i + 1)
		}
		vRec := map[string]any{
			"variantId": variantIDOrFallbackDeclHTML(vID, i+1),
			"sku":       skuAny,
			"title":     vTitleAny,
			"options":   vOpts,
			"price":     priceAny,
			"compareAt": nil,
			"currency":  vCurAny,
			"available": availAny,
			"grams":     nil,
			"image":     imgAny,
		}
		if barcodeStr != "" {
			vRec["barcode"] = barcodeStr
		}
		if invPol != "" {
			vRec["inventoryPolicy"] = invPol
		}
		variants = append(variants, vRec)

		statusText := "-"
		if availState == 1 {
			if invPol == "continue" {
				statusText = "Backorder / Preorder"
			} else {
				statusText = "In Stock"
			}
		} else if availState == -1 {
			statusText = "Out of Stock"
		} else if availRaw != "" {
			parts := strings.Split(availRaw, "/")
			if last := parts[len(parts)-1]; last != "" {
				statusText = last
			}
		}

		dispV := vTitleStr
		if dispV == "" {
			dispV = title
		}
		dispSKU := "-"
		if skuStr != "" {
			dispSKU = formatCommerceSKUDisplayDeclHTML(skuStr, false)
		}
		dispPrice := "-"
		if hasPrice {
			curCode := vCur
			if curCode == "" {
				curCode = "USD"
			}
			dispPrice = fmt.Sprintf("%s %.2f", curCode, priceVal)
		}
		rows = append(rows, []string{dispV, dispSKU, dispPrice, statusText})
	}

	pubAt := sanitizeCommerceTimestampDeclHTML(prodLD["releaseDate"])
	if pubAt == "" {
		pubAt = sanitizeCommerceTimestampDeclHTML(prodLD["datePublished"])
	}
	updAt := sanitizeCommerceTimestampDeclHTML(prodLD["dateModified"])
	var pubAny, updAny, vendorAny, prodTypeAny any
	if pubAt != "" {
		pubAny = pubAt
	}
	if updAt != "" {
		updAny = updAt
	}
	if brand != "" {
		vendorAny = brand
	}
	if catStr := sanitizeCommerceFieldDeclHTML(prodLD["category"], 200); catStr != "" {
		prodTypeAny = catStr
	}
	prodID := jsonScalarToString(prodLD["productID"])
	if prodID == "" {
		prodID = jsonScalarToString(prodLD["sku"])
	}
	if prodID == "" {
		prodID = handle
	}

	record := map[string]any{
		"platform":        "shopify",
		"origin":          origin,
		"productId":       prodID,
		"handle":          handle,
		"url":             ctx.u.String(),
		"title":           title,
		"vendor":          vendorAny,
		"productType":     prodTypeAny,
		"tags":            []string{},
		"descriptionText": desc,
		"publishedAt":     pubAny,
		"updatedAt":       updAny,
		"images":          []string{},
		"options":         []any{},
		"variants":        variants,
	}

	var bullets []string
	if brand != "" {
		bullets = append(bullets, "- **Brand**: "+brand)
	}
	if cleanTopSKU := sanitizeCommerceFieldDeclHTML(prodLD["sku"], 160); cleanTopSKU != "" {
		bullets = append(bullets, "- **SKU**: "+formatCommerceSKUDisplayDeclHTML(cleanTopSKU, true))
	}
	sections := []string{"# " + title}
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	if len(rows) > 0 {
		sections = append(sections, "## Pricing & Availability\n\n"+formatDeclarativeGFMTable([]string{"Variant", "SKU", "Price", "Status"}, rows))
	}
	if desc != "" {
		sections = append(sections, "## Description\n\n"+desc)
	}

	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Description: sliceRunesMax(desc, 260),
		Author:      brand,
		Markdown:    strings.Join(sections, "\n\n"),
		Records:     []map[string]any{record},
	}
}

func variantIDOrFallbackDeclHTML(id string, idx1 int) string {
	if id != "" {
		return id
	}
	return strconv.Itoa(idx1)
}

func isWooCommerceHTMLDeclHTML(rawHTML string) bool {
	if rawHTML == "" {
		return false
	}
	slice := rawHTML
	if len(slice) > 100_000 {
		slice = slice[:100_000]
	}
	return strings.Contains(slice, "woocommerce-page") ||
		strings.Contains(slice, "wc-block-grid") ||
		strings.Contains(slice, "/plugins/woocommerce/") ||
		strings.Contains(slice, "WooCommerce") ||
		strings.Contains(slice, "wc_add_to_cart_params") ||
		strings.Contains(slice, "/wp-json/wc/store/")
}

func extractWooCommerceProductHTMLDeclHTML(ctx *htmlExtractContextDeclHTML, extractorID string) *DeclarativePostFetchResult {
	if !isWooCommerceHTMLDeclHTML(ctx.rawHTML) {
		return nil
	}
	bodyOpen, hasBody := findOpenTagLinearDeclHTML(ctx.rawHTML, "body", nil, 0)
	isSingleProduct := (hasBody && attrHasTokenLinearDeclHTML(bodyOpen.attrStr, "class", "single-product")) ||
		reWooSinglePathDeclHTML.MatchString(ctx.u.Path)
	if !isSingleProduct {
		return nil
	}

	ldObjects := extractJSONLDObjectsDeclHTML(ctx.rawHTML, 100)
	var prodLD map[string]any
	for _, o := range ldObjects {
		if strings.Contains(strings.ToLower(jsonLDTypeStringDeclHTML(o)), "product") {
			prodLD = o
			break
		}
	}
	clean := stripScriptsAndStylesDeclHTML(ctx.rawHTML)

	rawTitle := ""
	if prodLD != nil {
		if nm, ok := prodLD["name"].(string); ok && strings.TrimSpace(nm) != "" {
			rawTitle = strings.TrimSpace(nm)
		}
	}
	if rawTitle == "" {
		h1Inner, _ := findElementInnerLinearDeclHTML(clean, "h1", func(a string) bool {
			return attrHasTokenLinearDeclHTML(a, "class", "product_title")
		}, 0)
		rawTitle = stripTagsInlineLinear(h1Inner)
	}
	title := sanitizeCommerceFieldDeclHTML(rawTitle, 400)
	if title == "" {
		return nil
	}

	rawSKU := ""
	if prodLD != nil {
		if sk, ok := prodLD["sku"].(string); ok && strings.TrimSpace(sk) != "" {
			rawSKU = strings.TrimSpace(sk)
		}
	}
	if rawSKU == "" {
		skuInner, _ := findElementInnerLinearDeclHTML(clean, "span", func(a string) bool {
			return attrHasTokenLinearDeclHTML(a, "class", "sku")
		}, 0)
		rawSKU = stripTagsInlineLinear(skuInner)
	}
	sku := sanitizeCommerceFieldDeclHTML(rawSKU, 160)

	var offer map[string]any
	if prodLD != nil {
		switch ov := prodLD["offers"].(type) {
		case []any:
			if len(ov) > 0 {
				offer, _ = ov[0].(map[string]any)
			}
		case map[string]any:
			offer = ov
		}
	}
	var priceVal float64
	hasPrice := false
	if offer != nil {
		if f, okF := jsonValueToFloat(offer["price"]); okF {
			priceVal = f
			hasPrice = true
		}
	}
	var currencyAny any
	currencyStr := ""
	if offer != nil {
		if cr, ok := offer["priceCurrency"].(string); ok {
			crUp := strings.ToUpper(strings.TrimSpace(cr))
			if reISOCurrency3DeclHTML.MatchString(crUp) {
				currencyStr = crUp
				currencyAny = crUp
			}
		}
	}
	availRaw := ""
	if offer != nil {
		availRaw = jsonScalarToString(offer["availability"])
	}
	var availAny any
	availState := 0
	if strings.Contains(strings.ToLower(availRaw), "instock") {
		availAny = true
		availState = 1
	} else if strings.Contains(strings.ToLower(availRaw), "outofstock") {
		availAny = false
		availState = -1
	}

	desc := ""
	if prodLD != nil {
		if dStr, ok := prodLD["description"].(string); ok {
			desc = sanitizeCommerceFieldDeclHTML(stripTagsInlineLinear(dStr), 1200)
		}
	}
	if !hasPrice && sku == "" && desc == "" {
		return nil
	}

	var ldImgRaw any
	if prodLD != nil {
		ldImgRaw = prodLD["image"]
		if arr, isA := ldImgRaw.([]any); isA && len(arr) > 0 {
			ldImgRaw = arr[0]
		}
		if m, isM := ldImgRaw.(map[string]any); isM {
			ldImgRaw = m["url"]
		}
	}
	safeImg := normalizePublicCommerceImageURLDeclHTML(ldImgRaw)
	var imgAny any
	images := []string{}
	if safeImg != "" {
		imgAny = safeImg
		images = []string{safeImg}
	}

	pubAt := ""
	updAt := ""
	if prodLD != nil {
		pubAt = sanitizeCommerceTimestampDeclHTML(prodLD["releaseDate"])
		if pubAt == "" {
			pubAt = sanitizeCommerceTimestampDeclHTML(prodLD["datePublished"])
		}
		updAt = sanitizeCommerceTimestampDeclHTML(prodLD["dateModified"])
	}
	var pubAny, updAny, skuAny, priceAny any
	if pubAt != "" {
		pubAny = pubAt
	}
	if updAt != "" {
		updAny = updAt
	}
	if sku != "" {
		skuAny = sku
	}
	if hasPrice {
		priceAny = priceVal
	}

	handle := ""
	if len(ctx.parts) > 0 {
		handle = ctx.parts[len(ctx.parts)-1]
	}
	if handle == "" {
		handle = strings.ToLower(title)
	}
	prodID := sku
	if prodID == "" {
		prodID = handle
	}
	origin := ctx.u.Scheme + "://" + strings.ToLower(ctx.u.Host)

	record := map[string]any{
		"platform":        "woocommerce",
		"origin":          origin,
		"productId":       prodID,
		"handle":          handle,
		"url":             ctx.u.String(),
		"title":           title,
		"vendor":          nil,
		"productType":     nil,
		"tags":            []string{},
		"descriptionText": desc,
		"publishedAt":     pubAny,
		"updatedAt":       updAny,
		"images":          images,
		"options":         []any{},
		"variants": []map[string]any{
			{
				"variantId": prodID,
				"sku":       skuAny,
				"title":     nil,
				"options":   []string{},
				"price":     priceAny,
				"compareAt": nil,
				"currency":  currencyAny,
				"available": availAny,
				"grams":     nil,
				"image":     imgAny,
			},
		},
	}

	var bullets []string
	if sku != "" {
		bullets = append(bullets, "- **SKU**: "+formatCommerceSKUDisplayDeclHTML(sku, true))
	}
	if hasPrice {
		curDisp := currencyStr
		if curDisp == "" {
			curDisp = "USD"
		}
		bullets = append(bullets, fmt.Sprintf("- **Price**: %s %.2f", curDisp, priceVal))
	}
	if availState == 1 {
		bullets = append(bullets, "- **Availability**: In Stock")
	} else if availState == -1 {
		bullets = append(bullets, "- **Availability**: Out of Stock")
	}

	blocks := []string{"# " + title}
	if len(bullets) > 0 {
		blocks = append(blocks, strings.Join(bullets, "\n"))
	}
	if desc != "" {
		blocks = append(blocks, "## Description\n\n"+desc)
	}

	return &DeclarativePostFetchResult{
		ExtractorID: extractorID,
		Title:       title,
		Description: sliceRunesMax(desc, 260),
		Markdown:    strings.Join(blocks, "\n\n"),
		Links:       []string{ctx.u.String()},
		Records:     []map[string]any{record},
	}
}

// ── Mode 1: Declarative DOM Route (`runDomHtmlRoute` 1:1) ───────────────────────────────────────

func formatDomRawDeclHTML(raw any, spec DeclarativeHTMLVarSpec) string {
	if raw == nil {
		return ""
	}
	if arr, isArr := raw.([]any); isArr {
		lim := spec.Limit
		if lim <= 0 {
			lim = 20
		}
		if len(arr) > lim {
			arr = arr[:lim]
		}
		var items []string
		for _, el := range arr {
			var s string
			if m, isM := el.(map[string]any); isM {
				s = jsonScalarToString(m["name"])
				if s == "" {
					s = jsonScalarToString(m["value"])
				}
			} else {
				s = jsonScalarToString(el)
			}
			if s != "" {
				items = append(items, s)
			}
		}
		if len(items) == 0 {
			return ""
		}
		sep := spec.Join
		if sep == "" {
			sep = ", "
		}
		return strings.Join(items, sep)
	}
	return jsonScalarToString(raw)
}

func runDomRouteDeclHTML(
	hr DeclarativeHTMLRouteSpec,
	ctx *htmlExtractContextDeclHTML,
	params map[string]string,
	extractorID string,
) *DeclarativePostFetchResult {
	doc := ParseHTMLDoc(ctx.rawHTML, 0)
	var cachedCleanHTML string
	hasCleanHTML := false
	getCleanHTML := func() string {
		if !hasCleanHTML {
			cachedCleanHTML = stripScriptsAndStylesDeclHTML(ctx.rawHTML)
			hasCleanHTML = true
		}
		return cachedCleanHTML
	}

	var ldObj map[string]any
	if len(hr.JSONLdTypes) > 0 {
		ldList := extractJSONLDObjectsDeclHTML(ctx.rawHTML, 100)
		lowerTypes := make([]string, len(hr.JSONLdTypes))
		for i, t := range hr.JSONLdTypes {
			lowerTypes[i] = strings.ToLower(t)
		}
		for _, o := range ldList {
			tVal := strings.ToLower(jsonLDTypeStringDeclHTML(o))
			matched := false
			for _, want := range lowerTypes {
				if strings.Contains(tVal, want) {
					matched = true
					break
				}
			}
			if matched {
				ldObj = o
				break
			}
		}
	}

	var embeddedObj map[string]any
	if hr.EmbeddedBalancedKey != "" {
		embeddedObj = extractBalancedJSONAfterKeyLinearDeclHTML(ctx.rawHTML, hr.EmbeddedBalancedKey)
	}

	resolved := make(map[string]string, len(hr.Vars))
	visiting := make(map[string]bool)
	bodyLinksByVar := make(map[string][]string)

	var isHTMLVarMarkdownFormattedDeclHTML func(map[string]DeclarativeHTMLVarSpec, string, int) bool
	isHTMLVarMarkdownFormattedDeclHTML = func(vars map[string]DeclarativeHTMLVarSpec, varName string, depth int) bool {
		if varName == "" || depth > 4 {
			return false
		}
		spec, ok := vars[varName]
		if !ok {
			return false
		}
		if len(spec.CSSHTMLToMd) > 0 {
			return true
		}
		if spec.FallbackVar != "" && isHTMLVarMarkdownFormattedDeclHTML(vars, spec.FallbackVar, depth+1) {
			return true
		}
		return false
	}

	var lookup func(string) string
	var evalHTMLVar func(string, DeclarativeHTMLVarSpec) string

	lookup = func(name string) string {
		if v, exists := resolved[name]; exists {
			return v
		}
		spec, hasSpec := hr.Vars[name]
		if !hasSpec {
			return params[name]
		}
		if visiting[name] {
			return ""
		}
		visiting[name] = true
		v := evalHTMLVar(name, spec)
		delete(visiting, name)
		resolved[name] = v
		return v
	}

	evalHTMLVar = func(varName string, spec DeclarativeHTMLVarSpec) string {
		val := ""
		if spec.Template != "" {
			allOK := true
			for _, w := range spec.WhenVars {
				if lookup(w) == "" {
					allOK = false
					break
				}
			}
			anyOK := len(spec.WhenAnyVars) == 0
			for _, w := range spec.WhenAnyVars {
				if lookup(w) != "" {
					anyOK = true
					break
				}
			}
			if allOK && anyOK {
				val = expandTemplate(spec.Template, lookup)
			} else if spec.FallbackVar != "" {
				val = lookup(spec.FallbackVar)
			}
		} else {
			if val == "" && embeddedObj != nil && len(spec.EmbeddedPaths) > 0 {
				for _, ep := range spec.EmbeddedPaths {
					got := strings.TrimSpace(formatDomRawDeclHTML(getByDotPath(embeddedObj, ep), spec))
					if got != "" {
						val = got
						break
					}
				}
			}
			if val == "" && ldObj != nil && len(spec.JSONLdPaths) > 0 {
				for _, lp := range spec.JSONLdPaths {
					got := strings.TrimSpace(formatDomRawDeclHTML(getByDotPath(ldObj, lp), spec))
					if got != "" {
						val = got
						break
					}
				}
			}
			if val == "" && spec.AllMetaKey != "" {
				all := extractAllMetaContentsDeclHTML(ctx.rawHTML, spec.AllMetaKey)
				lim := spec.Limit
				if lim <= 0 {
					lim = 20
				}
				if len(all) > lim {
					all = all[:lim]
				}
				if len(all) > 0 {
					sep := spec.Join
					if sep == "" {
						sep = ", "
					}
					val = strings.Join(all, sep)
				}
			}
			if val == "" && len(spec.MetaKeys) > 0 {
				for _, mk := range spec.MetaKeys {
					got := extractMetaContentDeclHTML(ctx.rawHTML, mk)
					if got != "" && spec.StripRegexSuffix != "" {
						if re := getCachedLinearRegexDeclHTML(spec.StripRegexSuffix); re != nil {
							if loc := re.FindStringIndex(got); loc != nil {
								got = strings.TrimSpace(got[:loc[0]])
							}
						}
					}
					if got != "" {
						val = got
						break
					}
				}
			}
			if val == "" && len(spec.CSSText) > 0 {
				for _, sel := range spec.CSSText {
					if got := doc.Text(sel); got != "" {
						val = got
						break
					}
				}
			}
			if val == "" && spec.CSSAttr != nil {
				val = strings.TrimSpace(doc.AttrOf(spec.CSSAttr.Selector, spec.CSSAttr.Attr))
			}
			if val == "" && spec.CSSAllText != nil {
				ca := spec.CSSAllText
				selLim := ca.Limit
				if selLim <= 0 {
					selLim = 50
				}
				nodes := doc.Select(ca.Selector, selLim)
				dedupe := ca.Dedupe == nil || *ca.Dedupe
				seenTxt := make(map[string]bool)
				var list []string
				for _, n := range nodes {
					txt := n.Text()
					if txt == "" {
						continue
					}
					if dedupe {
						if seenTxt[txt] {
							continue
						}
						seenTxt[txt] = true
					}
					list = append(list, txt)
				}
				if spec.Limit > 0 && len(list) > spec.Limit {
					list = list[:spec.Limit]
				}
				if len(list) > 0 {
					sep := ca.Join
					if sep == "" {
						sep = ", "
					}
					val = strings.Join(list, sep)
				}
			}
			if val == "" && len(spec.CSSHTMLToMd) > 0 {
				for _, sel := range spec.CSSHTMLToMd {
					inner := doc.HTML(sel)
					if strings.TrimSpace(inner) != "" {
						md, lnks := ctx.htmlToMD(inner, ctx.baseURL)
						mdTrim := strings.TrimSpace(md)
						if mdTrim != "" {
							val = mdTrim
							bodyLinksByVar[varName] = lnks
							break
						}
					}
				}
				if val == "" && ldObj != nil && len(spec.JSONLdPaths) > 0 {
					for _, lp := range spec.JSONLdPaths {
						if rawFrag, isS := getByDotPath(ldObj, lp).(string); isS && strings.TrimSpace(rawFrag) != "" {
							md, lnks := ctx.htmlToMD(rawFrag, ctx.baseURL)
							mdTrim := strings.TrimSpace(md)
							if mdTrim != "" {
								val = mdTrim
								bodyLinksByVar[varName] = lnks
								break
							}
						}
					}
				}
			}
			if val == "" && spec.RegexExtract != nil {
				rx := spec.RegexExtract
				if re := getCachedLinearRegexDeclHTML(rx.Pattern); re != nil {
					var corpus string
					if rx.Source == "doc_text_and_img_alts" {
						imgs := doc.Select("img[alt]", 80)
						alts := make([]string, 0, len(imgs))
						for _, im := range imgs {
							alts = append(alts, im.AttrOrEmpty("alt"))
						}
						corpus = doc.Text() + " " + strings.Join(alts, " ")
					} else {
						ch := getCleanHTML()
						if len(ch) > 200_000 {
							ch = ch[:200_000]
						}
						corpus = ch
					}
					m := re.FindStringSubmatch(corpus)
					grpIdx := rx.Group
					if grpIdx <= 0 {
						grpIdx = 1
					}
					if grpIdx < len(m) && m[grpIdx] != "" {
						grp := m[grpIdx]
						switch rx.Transform {
						case "upper":
							val = strings.ToUpper(grp)
						case "lower":
							val = strings.ToLower(grp)
						default:
							val = grp
						}
					}
				}
			}
		}

		if val == "" {
			if spec.FallbackVar != "" {
				val = lookup(spec.FallbackVar)
			}
			if val == "" && spec.FallbackTemplate != "" {
				val = expandTemplate(spec.FallbackTemplate, lookup)
			}
			if val == "" && spec.Default != "" {
				val = spec.Default
			}
		}
		if spec.StripPrefix != "" && len(val) >= len(spec.StripPrefix) && strings.EqualFold(val[:len(spec.StripPrefix)], spec.StripPrefix) {
			val = strings.TrimSpace(val[len(spec.StripPrefix):])
		}
		if spec.StripSuffix != "" && len(val) >= len(spec.StripSuffix) && strings.EqualFold(val[len(val)-len(spec.StripSuffix):], spec.StripSuffix) {
			val = strings.TrimSpace(val[:len(val)-len(spec.StripSuffix)])
		}
		if spec.ReplaceAll != nil && val != "" {
			val = strings.ReplaceAll(val, spec.ReplaceAll.From, spec.ReplaceAll.To)
		}
		switch spec.Format {
		case "strip_tags":
			val = stripTagsInlineLinear(val)
		case "strip_leading_h1":
			val = stripLeadingMarkdownH1Go(val)
		case "free_or_currency":
			if val != "" {
				cur := "USD"
				if spec.CurrencyVar != "" {
					if cv := lookup(spec.CurrencyVar); cv != "" {
						cur = cv
					}
				}
				if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil && f == 0 {
					val = "Free"
				} else {
					val = cur + " " + val
				}
			}
		}
		if spec.Trim == nil || *spec.Trim {
			val = strings.TrimSpace(val)
		}
		val = stripInvisibleAndNUL(val)
		if spec.MinLen > 0 && len(val) < spec.MinLen {
			return ""
		}
		if spec.SliceMax > 0 && val != "" {
			val = sliceRunesMax(val, spec.SliceMax)
		}
		return val
	}

	for _, rv := range hr.RequireVars {
		if strings.TrimSpace(lookup(rv)) == "" {
			return nil
		}
	}
	for _, k := range sortedMapKeys(hr.Vars) {
		_ = lookup(k)
	}

	title := ""
	if hr.TitleWhenVar != "" {
		if lookup(hr.TitleWhenVar) != "" {
			title = expandTemplate(hr.TitleTemplate, lookup)
		} else {
			title = expandTemplate(hr.TitleFallbackTemplate, lookup)
		}
	} else {
		title = expandTemplate(hr.TitleTemplate, lookup)
		if strings.TrimSpace(title) == "" && hr.TitleFallbackTemplate != "" {
			title = expandTemplate(hr.TitleFallbackTemplate, lookup)
		}
	}
	title = SanitizeScrapedMeta(title)

	sanitizeDomInlineCodeVal := func(val string) string {
		r := strings.NewReplacer(
			"`", "'",
			"\r", " ",
			"\n", " ",
			"|", "&#124;",
		)
		return r.Replace(val)
	}
	sanitizeDomTextVal := func(val string) string {
		clean := neutralizeAllUnsafeMarkdownLinksLinearGo(val)
		r := strings.NewReplacer(
			"\r", " ",
			"\n", " ",
			"](", `\]\(`,
			"[", `\[`,
			"]", `\]`,
		)
		return r.Replace(clean)
	}
	sanitizeDomLinkURLVal := func(val string) string {
		cleaned := strings.NewReplacer("\r", "", "\n", "", "\t", "", " ", "%20").Replace(strings.TrimSpace(val))
		return PercentEncodeUnsafeRecordURLChars(cleaned)
	}
	expandDomPlainSegment := func(seg string) string {
		var sb strings.Builder
		pos := 0
		for pos < len(seg) {
			openIdx := strings.IndexByte(seg[pos:], '{')
			if openIdx < 0 {
				sb.WriteString(seg[pos:])
				break
			}
			absOpen := pos + openIdx
			closeIdx := strings.IndexByte(seg[absOpen+1:], '}')
			if closeIdx < 0 {
				sb.WriteString(seg[pos:])
				break
			}
			absClose := absOpen + 1 + closeIdx
			sb.WriteString(seg[pos:absOpen])
			name := seg[absOpen+1 : absClose]
			val := lookup(name)
			if absOpen >= 2 && seg[absOpen-2:absOpen] == "](" && absClose+1 < len(seg) && seg[absClose+1] == ')' {
				sb.WriteString(sanitizeDomLinkURLVal(val))
			} else {
				sb.WriteString(sanitizeDomTextVal(val))
			}
			pos = absClose + 1
		}
		return strings.NewReplacer("\r", " ", "\n", " ").Replace(sb.String())
	}
	expandDomBulletTemplate := func(tmpl string) string {
		if !strings.Contains(tmpl, "`") {
			return strings.TrimSpace(expandDomPlainSegment(tmpl))
		}
		var sb strings.Builder
		n := len(tmpl)
		i := 0
		for i < n {
			if tmpl[i] == '`' {
				end := strings.IndexByte(tmpl[i+1:], '`')
				if end >= 0 {
					inner := tmpl[i+1 : i+1+end]
					expanded := expandTemplate(inner, func(name string) string {
						return sanitizeDomInlineCodeVal(lookup(name))
					})
					sb.WriteByte('`')
					sb.WriteString(sanitizeDomInlineCodeVal(expanded))
					sb.WriteByte('`')
					i += end + 2
					continue
				}
			}
			nextTick := strings.IndexByte(tmpl[i:], '`')
			segEnd := n
			if nextTick >= 0 {
				segEnd = i + nextTick
			}
			if segEnd > i {
				sb.WriteString(expandDomPlainSegment(tmpl[i:segEnd]))
				i = segEnd
			} else {
				sb.WriteByte(tmpl[i])
				i++
			}
		}
		return strings.TrimSpace(sb.String())
	}

	var bulletLines []string
	for _, b := range hr.Bullets {
		if b.WhenVar != "" && lookup(b.WhenVar) == "" {
			continue
		}
		if b.UnlessVar != "" && lookup(b.UnlessVar) != "" {
			continue
		}
		rendered := expandDomBulletTemplate(b.Template)
		if rendered != "" {
			if b.Label != "" {
				bulletLines = append(bulletLines, fmt.Sprintf("- **%s**: %s", b.Label, rendered))
			} else {
				bulletLines = append(bulletLines, "- "+rendered)
			}
		}
	}

	if len(hr.RequireBulletsOrVars) > 0 && len(bulletLines) == 0 {
		hasAnyVar := false
		for _, v := range hr.RequireBulletsOrVars {
			if strings.TrimSpace(lookup(v)) != "" {
				hasAnyVar = true
				break
			}
		}
		if !hasAnyVar {
			return nil
		}
	}

	var blocks []string
	bodyVal := ""
	if hr.BodyVar != "" {
		bodyVal = strings.TrimSpace(lookup(hr.BodyVar))
	}
	bodyStartsH1 := strings.HasPrefix(bodyVal, "# ")

	h1Line := ""
	if title != "" {
		h1Line = "# " + escapeDeclMarkdownBrackets(title)
	}
	if hr.BlockquoteTemplate != "" && (hr.BlockquoteWhenVar == "" || lookup(hr.BlockquoteWhenVar) != "") {
		bq := strings.TrimSpace(expandDomBulletTemplate(hr.BlockquoteTemplate))
		if bodyStartsH1 && bq != "" {
			blocks = append(blocks, bq)
		} else {
			if h1Line != "" {
				blocks = append(blocks, h1Line)
			}
			if bq != "" {
				blocks = append(blocks, bq)
			}
		}
	} else if h1Line != "" {
		blocks = append(blocks, h1Line)
	}

	if hr.MetaItalicTemplate != "" && (hr.MetaItalicWhenVar == "" || lookup(hr.MetaItalicWhenVar) != "") {
		if mi := strings.ReplaceAll(strings.TrimSpace(expandDomBulletTemplate(hr.MetaItalicTemplate)), "*", `\*`); mi != "" {
			blocks = append(blocks, "*"+mi+"*")
		}
	}
	if hr.IntroVar != "" {
		if iv := strings.TrimSpace(lookup(hr.IntroVar)); iv != "" {
			if !isHTMLVarMarkdownFormattedDeclHTML(hr.Vars, hr.IntroVar, 0) {
				iv = escapeDeclMarkdownBlock(iv)
			}
			blocks = append(blocks, iv)
		}
	}
	if len(bulletLines) > 0 {
		blocks = append(blocks, strings.Join(bulletLines, "\n"))
	}
	if bodyVal != "" {
		if hr.BodyFallbackHeading != "" && !strings.HasPrefix(bodyVal, "#") {
			blocks = append(blocks, "## "+hr.BodyFallbackHeading+"\n\n"+bodyVal)
		} else {
			blocks = append(blocks, bodyVal)
		}
	}
	for _, sec := range hr.Sections {
		if txt := strings.TrimSpace(lookup(sec.TextVar)); txt != "" {
			if !isHTMLVarMarkdownFormattedDeclHTML(hr.Vars, sec.TextVar, 0) {
				txt = escapeDeclMarkdownBlock(txt)
			}
			blocks = append(blocks, "## "+sec.Heading+"\n\n"+txt)
		}
	}

	if hr.AppendCurrentMdDelta != nil && ctx.currentMD != "" {
		baseLen := 0
		if hr.AppendCurrentMdDelta.BaseVar != "" {
			baseLen = len(lookup(hr.AppendCurrentMdDelta.BaseVar))
		}
		if len(ctx.currentMD) > baseLen+hr.AppendCurrentMdDelta.MinExtraChars {
			if delta := strings.TrimSpace(stripLeadingMarkdownH1Go(ctx.currentMD)); delta != "" {
				blocks = append(blocks, delta)
			}
		}
	}

	if len(blocks) == 0 || (len(blocks) == 1 && h1Line != "" && blocks[0] == h1Line) {
		return nil
	}

	var links []string
	seenLink := make(map[string]bool)
	pushSafeLink := func(l string) {
		trimmed := strings.TrimSpace(l)
		if isSafePublicHTTPSFeedURL(trimmed) && !seenLink[trimmed] {
			seenLink[trimmed] = true
			links = append(links, trimmed)
		}
	}
	if hr.PreserveBodyLinksFromVar != "" {
		for _, l := range bodyLinksByVar[hr.PreserveBodyLinksFromVar] {
			pushSafeLink(l)
		}
	}
	for _, lt := range hr.LinkTemplates {
		pushSafeLink(expandTemplate(lt, lookup))
	}

	desc := ""
	if hr.DescriptionVar != "" {
		desc = lookup(hr.DescriptionVar)
	}
	author := ""
	if hr.AuthorVar != "" {
		author = lookup(hr.AuthorVar)
	}
	pubTime := ""
	if hr.PublishedTimeVar != "" {
		pubTime = lookup(hr.PublishedTimeVar)
	}

	return &DeclarativePostFetchResult{
		ExtractorID:   extractorID,
		Title:         title,
		Description:   desc,
		Author:        author,
		PublishedTime: pubTime,
		Markdown:      strings.TrimSpace(strings.Join(blocks, "\n\n")),
		Links:         links,
	}
}

// ── Mode 2: Embedded JSON (`scriptId` / `dataAttr`) ─────────────────────────────────────────────

func runEmbeddedJSONRouteDeclHTML(
	hr DeclarativeHTMLRouteSpec,
	ctx *htmlExtractContextDeclHTML,
	params map[string]string,
	extractorID string,
) *DeclarativePostFetchResult {
	if hr.Extract == nil {
		return nil
	}
	var rawJSON string
	if hr.ScriptID != "" {
		inner, ok := findElementInnerLinearDeclHTML(ctx.rawHTML, "script", func(a string) bool {
			id, _ := getAttrValueLinearDeclHTML(a, "id")
			return id == hr.ScriptID
		}, 0)
		if ok {
			rawJSON = strings.TrimSpace(inner)
		}
	} else if hr.DataAttr != "" {
		doc := ParseHTMLDoc(ctx.rawHTML, 0)
		if el := doc.First("[" + hr.DataAttr + "]"); el != nil {
			if rawAttr := el.AttrOrEmpty(hr.DataAttr); rawAttr != "" {
				rawJSON = strings.TrimSpace(stdhtml.UnescapeString(rawAttr))
			}
		}
	}
	if rawJSON == "" {
		return nil
	}
	tm := &DeclarativeTwinMatch{
		params:  params,
		origURL: ctx.baseURL,
	}
	formatted, ok := tm.formatJSONBytesTwin([]byte(strings.TrimPrefix(rawJSON, "\ufeff")), *hr.Extract)
	if !ok || formatted == nil {
		return nil
	}
	return &DeclarativePostFetchResult{
		ExtractorID:   extractorID,
		Title:         formatted.Title,
		Description:   formatted.Description,
		Author:        formatted.Author,
		PublishedTime: formatted.PublishedTime,
		Markdown:      formatted.Markdown,
		Links:         formatted.Links,
		Records:       formatted.Records,
		Total:         formatted.Total,
		Returned:      formatted.Returned,
		Truncated:     formatted.Truncated,
		NextCursor:    formatted.NextCursor,
	}
}

// ── Route Dispatcher & Public Post-Fetch / Twin Formatting Entrypoints ──────────────────────────

func sanitizePostFetchResultDeclHTML(out *DeclarativePostFetchResult) *DeclarativePostFetchResult {
	if out == nil {
		return nil
	}
	out.Title = SanitizeScrapedMeta(out.Title)
	out.Description = SanitizeScrapedMeta(out.Description)
	out.Author = SanitizeScrapedMeta(out.Author)
	out.PublishedTime = SanitizeScrapedMeta(out.PublishedTime)
	out.Markdown = SanitizeScrapedMarkdown(out.Markdown)

	if len(out.Links) > 0 {
		filtered := make([]string, 0, len(out.Links))
		seen := make(map[string]bool, len(out.Links))
		for _, l := range out.Links {
			clean := strings.TrimSpace(l)
			if isSafePublicHTTPSFeedURL(clean) && !seen[clean] {
				seen[clean] = true
				filtered = append(filtered, clean)
			}
		}
		if len(filtered) > 0 {
			out.Links = filtered
		} else {
			out.Links = nil
		}
	}
	return out
}

var (
	externalHTMLModesMu sync.RWMutex
	externalHTMLModes   = make(map[string]func(rawHTML, baseURL, currentMD, extractorID string) *DeclarativePostFetchResult)
)

// RegisterExternalHTMLMode registers an external HTML extractor mode (e.g. from internal/catalog)
// without creating a Go package import cycle.
func RegisterExternalHTMLMode(mode string, fn func(rawHTML, baseURL, currentMD, extractorID string) *DeclarativePostFetchResult) {
	if mode == "" || fn == nil {
		return
	}
	externalHTMLModesMu.Lock()
	externalHTMLModes[mode] = fn
	externalHTMLModesMu.Unlock()
}

func getExternalHTMLMode(mode string) func(rawHTML, baseURL, currentMD, extractorID string) *DeclarativePostFetchResult {
	externalHTMLModesMu.RLock()
	fn := externalHTMLModes[mode]
	externalHTMLModesMu.RUnlock()
	return fn
}

func executeDeclarativeHTMLRouteDeclHTML(
	manifest *DeclarativeAdapterManifest,
	hr DeclarativeHTMLRouteSpec,
	ctx *htmlExtractContextDeclHTML,
	rawParts []string,
) *DeclarativePostFetchResult {
	params, matched := matchDeclarativeRoute(hr.Match, ctx.u, ctx.host, rawParts)
	if !matched {
		return nil
	}
	extractorID := hr.ID
	if extractorID == "" {
		extractorID = manifest.ID
	}

	var out *DeclarativePostFetchResult
	switch hr.Mode {
	case "shopify_html":
		out = extractShopifyProductHTMLDeclHTML(ctx, extractorID)
	case "woocommerce_html":
		out = extractWooCommerceProductHTMLDeclHTML(ctx, extractorID)
	case "icims_portal":
		out = parseIcimsPortalHTMLDeclHTML(ctx.rawHTML, ctx.u.String(), ctx.htmlToMD, extractorID)
	case "xml_items_table":
		if hr.XML == nil {
			return nil
		}
		formatted, ok := formatXMLTwinGo(strings.TrimPrefix(ctx.rawHTML, "\ufeff"), hr.XML, params)
		if !ok || formatted == nil {
			return nil
		}
		out = &DeclarativePostFetchResult{
			ExtractorID: extractorID,
			Title:       formatted.Title,
			Markdown:    formatted.Markdown,
			Links:       formatted.Links,
		}
	case "markdown_clean":
		if hr.CleanPreset == "" {
			return nil
		}
		out = runMarkdownCleanPresetDeclHTML(hr.CleanPreset, ctx, extractorID)
	case "gist_files":
		out = runGistExtractorDeclHTML(ctx, extractorID)
	case "stackexchange_html":
		out = runStackExchangeExtractorDeclHTML(ctx, extractorID)
	case "reddit_shreddit":
		out = runRedditShredditExtractorDeclHTML(ctx, extractorID)
	case "xenforo_html":
		out = runXenForoExtractorDeclHTML(ctx, extractorID)
	case "sram_docs_html":
		out = runSramDocsExtractorDeclHTML(ctx, extractorID)
	case "bosch_help_html":
		out = runBoschHelpExtractorDeclHTML(ctx, extractorID)
	case "ukg_pro_html":
		out = runUkgProHTMLExtractorDeclHTML(ctx, extractorID)
	case "paylocity_html":
		out = runPaylocityHTMLExtractorDeclHTML(ctx, extractorID)
	case "dover_html":
		out = runDoverHTMLExtractorDeclHTML(ctx, extractorID)
	case "sitecore_jss_html":
		out = runSitecoreJSSHTMLExtractorDeclHTML(ctx, extractorID)
	case "giant_liv_html":
		out = runGiantLivHTMLExtractorDeclHTML(ctx, extractorID)
	case "embedded_json":
		out = runEmbeddedJSONRouteDeclHTML(hr, ctx, params, extractorID)
	case "dom":
		out = runDomRouteDeclHTML(hr, ctx, params, extractorID)
	default:
		if extFn := getExternalHTMLMode(hr.Mode); extFn != nil {
			out = extFn(ctx.rawHTML, ctx.baseURL, ctx.currentMD, extractorID)
		} else {
			return nil
		}
	}

	return sanitizePostFetchResultDeclHTML(out)
}

// ApplyDeclarativeHTMLExtractor runs matching post-fetch declarative htmlRoutes for baseURL across all embedded manifests.
func ApplyDeclarativeHTMLExtractor(
	rawHTML, baseURL, currentMD string,
	htmlToMD func(frag, base string) (string, []string),
) (*DeclarativePostFetchResult, bool) {
	trimmedBase := strings.TrimSpace(baseURL)
	if trimmedBase == "" {
		return nil, false
	}
	u, err := url.Parse(trimmedBase)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return nil, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return nil, false
	}

	if htmlToMD == nil {
		htmlToMD = func(frag, base string) (string, []string) {
			ext := ExtractHTMLDocumentFull("<!doctype html><html><body>"+frag+"</body></html>", FullExtractOptions{
				BaseURL:         base,
				OnlyMainContent: false,
				IncludeImages:   true,
				IsFragment:      true,
			})
			return ext.Markdown, ext.Links
		}
	}

	reg := loadRegistry()
	var candidates []*DeclarativeAdapterManifest
	seen := make(map[*DeclarativeAdapterManifest]bool)
	push := func(a *DeclarativeAdapterManifest) {
		if len(a.HTMLRoutes) > 0 && !seen[a] {
			seen[a] = true
			candidates = append(candidates, a)
		}
	}

	for _, a := range reg.byHost[host] {
		push(a)
	}
	for _, w := range reg.wildcards {
		switch w.kind {
		case "suffix":
			if strings.HasSuffix(host, w.pattern) && len(host) > len(w.pattern) {
				push(w.adapter)
			}
		case "prefix":
			if strings.HasPrefix(host, w.pattern) && len(host) > len(w.pattern) {
				push(w.adapter)
			}
		case "infix":
			if matchesHostPatternLinearGo(host, w.pattern) {
				push(w.adapter)
			}
		}
	}
	for _, uEng := range reg.universal {
		push(uEng)
	}
	if len(candidates) == 0 {
		return nil, false
	}

	rawParts := splitNonEmptyEscapedSegments(u.EscapedPath())
	decodedParts := make([]string, len(rawParts))
	for i, rp := range rawParts {
		if dec, dErr := url.PathUnescape(rp); dErr == nil {
			decodedParts[i] = dec
		} else {
			decodedParts[i] = rp
		}
	}

	ctx := &htmlExtractContextDeclHTML{
		u:         u,
		baseURL:   trimmedBase,
		host:      host,
		path:      u.Path,
		parts:     decodedParts,
		rawHTML:   rawHTML,
		currentMD: currentMD,
		htmlToMD:  htmlToMD,
	}

	for _, adapter := range candidates {
		for _, hr := range adapter.HTMLRoutes {
			out := executeDeclarativeHTMLRouteDeclHTML(adapter, hr, ctx, rawParts)
			if out != nil && strings.TrimSpace(out.Markdown) != "" {
				return out, true
			}
		}
	}
	return nil, false
}

// FormatDeclarativeTwinByURL resolves the declarative twin for requestURL, overrides origURL when non-empty, and formats rawBody.
func FormatDeclarativeTwinByURL(requestURL, rawBody, origURL string) (*DeclarativeFormattedDoc, bool) {
	m, ok := ResolveDeclarativeTwin(requestURL)
	if !ok || m == nil {
		return nil, false
	}
	if strings.TrimSpace(origURL) != "" {
		m.origURL = strings.TrimSpace(origURL)
	}
	return m.Format(rawBody)
}

// FormatYAMLFrontmatterCard parses YAML model/dataset card frontmatter (e.g. Hugging Face README.md) into a sanitized GFM metadata table + Markdown body.
func FormatYAMLFrontmatterCard(rawMD, fallbackTitle string) *DeclarativeFormattedDoc {
	bounded := rawMD
	if len(bounded) > 2*1024*1024 {
		cut := 2 * 1024 * 1024
		for cut > 0 && (bounded[cut]&0xC0) == 0x80 {
			cut--
		}
		bounded = bounded[:cut]
	}
	card := formatDeclarativeYAMLFrontmatterCard(stripInvisibleAndNUL(bounded), fallbackTitle)
	if card == nil {
		return nil
	}
	card.Title = SanitizeScrapedMeta(card.Title)
	card.Description = SanitizeScrapedMeta(card.Description)
	card.Markdown = escapeDangerousRawHTMLOutsideFencesDeclGo(card.Markdown)
	return card
}

// LookupBuiltInManifest returns the pre-validated built-in DeclarativeAdapterManifest by exact id in O(1) time.
func LookupBuiltInManifest(id string) *DeclarativeAdapterManifest {
	reg := loadRegistry()
	if reg == nil || reg.byID == nil {
		return nil
	}
	return reg.byID[id]
}

// ResolveTwinOnManifest evaluates twin resolution against an explicit (ad-hoc or custom) DeclarativeAdapterManifest.
func ResolveTwinOnManifest(m *DeclarativeAdapterManifest, rawURL string) (*DeclarativeTwinMatch, bool) {
	if m == nil {
		return nil, false
	}
	cp := *m
	if err := validateManifestRulesGo(&cp); err != nil {
		return nil, false
	}
	return ResolveTwinOnValidatedManifest(&cp, rawURL)
}

// ResolveTwinOnValidatedManifest evaluates twin resolution against an already-validated DeclarativeAdapterManifest.
func ResolveTwinOnValidatedManifest(cp *DeclarativeAdapterManifest, rawURL string) (*DeclarativeTwinMatch, bool) {
	if cp == nil {
		return nil, false
	}
	trimmed := strings.TrimSpace(rawURL)
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return nil, false
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !isSafePublicHostnameGo(host) {
		return nil, false
	}
	domainOK := cp.UniversalEngine
	for _, dp := range cp.Domains {
		if matchesHostPatternLinearGo(host, dp) {
			domainOK = true
			break
		}
	}
	if !domainOK {
		return nil, false
	}
	rawParts := splitNonEmptyEscapedSegments(u.EscapedPath())
	return resolveManifestTwinOnParsedURL(cp, u, host, rawParts)
}

// FormatTwinOnValidatedManifest resolves and formats a twin body against an already-validated DeclarativeAdapterManifest.
func FormatTwinOnValidatedManifest(m *DeclarativeAdapterManifest, requestURL, rawBody, origURL string) (*DeclarativeFormattedDoc, bool) {
	tm, ok := ResolveTwinOnValidatedManifest(m, requestURL)
	if !ok || tm == nil {
		return nil, false
	}
	if strings.TrimSpace(origURL) != "" {
		tm.origURL = strings.TrimSpace(origURL)
	}
	return tm.Format(rawBody)
}

// FormatTwinOnManifest resolves and formats a twin body against an explicit DeclarativeAdapterManifest.
func FormatTwinOnManifest(m *DeclarativeAdapterManifest, requestURL, rawBody, origURL string) (*DeclarativeFormattedDoc, bool) {
	tm, ok := ResolveTwinOnManifest(m, requestURL)
	if !ok || tm == nil {
		return nil, false
	}
	if strings.TrimSpace(origURL) != "" {
		tm.origURL = strings.TrimSpace(origURL)
	}
	return tm.Format(rawBody)
}

// ExtractHTMLOnManifest executes HTMLRoutes against an explicit DeclarativeAdapterManifest.
func ExtractHTMLOnManifest(m *DeclarativeAdapterManifest, rawHTML, baseURL, currentMD string, htmlToMD func(frag, base string) (string, []string)) (*DeclarativePostFetchResult, bool) {
	if m == nil {
		return nil, false
	}
	cp := *m
	if err := validateManifestRulesGo(&cp); err != nil || len(cp.HTMLRoutes) == 0 {
		return nil, false
	}
	return ExtractHTMLOnValidatedManifest(&cp, rawHTML, baseURL, currentMD, htmlToMD)
}

// ExtractHTMLOnValidatedManifest executes HTMLRoutes against an already-validated DeclarativeAdapterManifest.
func ExtractHTMLOnValidatedManifest(cp *DeclarativeAdapterManifest, rawHTML, baseURL, currentMD string, htmlToMD func(frag, base string) (string, []string)) (*DeclarativePostFetchResult, bool) {
	if cp == nil || len(cp.HTMLRoutes) == 0 {
		return nil, false
	}
	trimmedBase := strings.TrimSpace(baseURL)
	u, err := url.Parse(trimmedBase)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return nil, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	domainOK := cp.UniversalEngine
	for _, dp := range cp.Domains {
		if matchesHostPatternLinearGo(host, dp) {
			domainOK = true
			break
		}
	}
	if !domainOK {
		return nil, false
	}
	if htmlToMD == nil {
		htmlToMD = func(frag, base string) (string, []string) {
			ext := ExtractHTMLDocumentFull("<!doctype html><html><body>"+frag+"</body></html>", FullExtractOptions{BaseURL: base, OnlyMainContent: false, IncludeImages: true, IsFragment: true})
			return ext.Markdown, ext.Links
		}
	}
	rawParts := splitNonEmptyEscapedSegments(u.EscapedPath())
	decodedParts := make([]string, len(rawParts))
	for i, rp := range rawParts {
		if dec, dErr := url.PathUnescape(rp); dErr == nil {
			decodedParts[i] = dec
		} else {
			decodedParts[i] = rp
		}
	}
	ctx := &htmlExtractContextDeclHTML{
		u:         u,
		baseURL:   trimmedBase,
		host:      host,
		path:      u.Path,
		parts:     decodedParts,
		rawHTML:   rawHTML,
		currentMD: currentMD,
		htmlToMD:  htmlToMD,
	}
	for _, hr := range cp.HTMLRoutes {
		out := executeDeclarativeHTMLRouteDeclHTML(cp, hr, ctx, rawParts)
		if out != nil && strings.TrimSpace(out.Markdown) != "" {
			return out, true
		}
	}
	return nil, false
}

// MatchDeclarativeRouteURL matches a DeclarativeMatchSpec against a raw URL string.
func MatchDeclarativeRouteURL(spec DeclarativeMatchSpec, rawURL string) (map[string]string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return nil, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	rawParts := splitNonEmptyEscapedSegments(u.EscapedPath())
	return matchDeclarativeRoute(spec, u, host, rawParts)
}
