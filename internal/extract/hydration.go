package extract

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// HydratedFrameworkStateResult holds rich prose and/or homogeneous structured records
// extracted from SSR hydration containers (`framework-hydration.ts` parity).
type HydratedFrameworkStateResult struct {
	Title                       string           `json:"title,omitempty"`
	Description                 string           `json:"description,omitempty"`
	Markdown                    string           `json:"markdown"`
	Framework                   string           `json:"framework"`
	Records                     []map[string]any `json:"records,omitempty"`
	Structured                  map[string]any   `json:"structured,omitempty"`
	Total                       int              `json:"total,omitempty"`
	Returned                    int              `json:"returned,omitempty"`
	Truncated                   bool             `json:"truncated,omitempty"`
	NextCursor                  string           `json:"nextCursor,omitempty"`
	RawDecodedStringsForPICheck string           `json:"rawDecodedStringsForPiCheck,omitempty"`
}

// CapturedJSONPayloadInput represents a network response captured during Chromium CDP rendering.
type CapturedJSONPayloadInput struct {
	URL    string `json:"url,omitempty"`
	Method string `json:"method,omitempty"`
	Status int    `json:"status,omitempty"`
	Body   string `json:"body"`
}

const (
	maxHTMLScanBytesHydrateGo = 2 * 1024 * 1024
	maxStatePIBytesHydrateGo  = 1_048_576
)

var (
	unsafeObjectKeysHydrateGo = map[string]bool{
		"__proto__":   true,
		"constructor": true,
		"prototype":   true,
	}

	skipWalkKeysHydrateGo = map[string]bool{
		"buildid":          true,
		"scriptloader":     true,
		"__n_ssg":          true,
		"__n_ssp":          true,
		"assetprefix":      true,
		"runtimeconfig":    true,
		"stylesheet":       true,
		"css":              true,
		"svg":              true,
		"icon":             true,
		"webpack":          true,
		"chunks":           true,
		"polyfillfiles":    true,
		"lowpriorityfiles": true,
		"ampfirstpages":    true,
	}

	inertiaSkipPropKeysHydrateGo = map[string]bool{
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

	devalueWrapperTagsHydrateGo = map[string]bool{
		"Reactive":        true,
		"ShallowReactive": true,
		"Ref":             true,
		"ShallowRef":      true,
		"Object":          true,
	}

	devalueEmptyTagsHydrateGo = map[string]bool{
		"EmptyRef":        true,
		"EmptyShallowRef": true,
		"Undefined":       true,
		"NaN":             true,
		"Infinity":        true,
		"-Infinity":       true,
		"-0":              true,
		"RegExp":          true,
	}

	devalueStringTagsHydrateGo = map[string]bool{
		"Date":   true,
		"URL":    true,
		"BigInt": true,
	}

	richProseKeysHydrateGo = map[string]bool{
		"content":          true,
		"body":             true,
		"markdown":         true,
		"mdx":              true,
		"articlebody":      true,
		"descriptionhtml":  true,
		"descriptionplain": true,
		"jobdescription":   true,
		"responsibilities": true,
		"qualifications":   true,
		"requirements":     true,
		"summary":          true,
		"overview":         true,
		"about":            true,
		"bio":              true,
		"details":          true,
		"text":             true,
		"rendered":         true,
		"body_html":        true,
		"html":             true,
	}

	recordTitleKeysHydrateGo = []string{
		"title", "name", "headline", "jobTitle", "role", "position",
		"question", "subject", "package", "repo", "full_name", "model", "label",
	}

	recordURLKeysHydrateGo = []string{
		"url", "href", "permalink", "canonicalUrl", "applyUrl", "jobUrl",
		"absolute_url", "hostedUrl", "html_url", "link", "path", "slug",
	}

	recordMetaKeysHydrateGo = []string{
		"summary", "description", "excerpt", "snippet", "answer",
		"location", "locationName", "city", "workplaceType",
		"price", "salary", "compensation",
		"date", "publishedAt", "published_at", "createdAt", "created_at",
		"updatedAt", "updated_at", "postedAt",
		"company", "organization", "department", "team", "category",
		"type", "status", "author", "version", "downloads", "stars", "stargazers_count",
	}

	reNavContainerKeyHydrateGo = newLazyRegexp(`(?i)^(?:nav|navigation|navbar|menu|menus|menuitems|header|footer|breadcrumbs?|social|sociallinks|locales?|languages?|tabs|routes|icons?|themes?|shortcuts)$`)
	reRecordBonusKeyHydrateGo  = newLazyRegexp(`(?i)^(?:items|results|records|jobs|postings|posts|articles|products|hits|nodes|edges|entries|listings|packages|models|datasets|events|questions|threads|topics|rows)$`)
	reUUIDPrefixHydrateGo      = newLazyRegexp(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-`)
	reSlugLikeURLHydrateGo     = newLazyRegexp(`(?i)^[a-z0-9][a-z0-9/_-]{2,120}$`)
	reRelPathSlugHydrateGo     = newLazyRegexp(`(?i)^[a-z0-9][a-z0-9/_.-]{1,120}$`)
	reRichProseKeySubHydrateGo = newLazyRegexp(`(?i)description|content|markdown|body|overview|article|post`)
	reHydrateHTMLTagHydrateGo  = newLazyRegexp(`(?i)<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|a)\b`)
	reInertiaHTMLTagHydrateGo  = newLazyRegexp(`(?i)<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|em|a|table|blockquote)\b`)
	reAnyAlphaTagHydrateGo     = newLazyRegexp(`(?i)<[a-z]`)
)

// ScanJSONStringLiteralAt scans a double-quoted JSON string literal starting at `src[openQuoteIdx] == '"'`
// up to `maxEnd` in linear O(N) time and returns `(decoded, nextIdx, ok)` where `nextIdx` is always the
// scan stop offset so callers can advance past malformed or unclosed string literals without quadratic rescanning.
func ScanJSONStringLiteralAt(src string, openQuoteIdx, maxEnd int) (decoded string, nextIdx int, ok bool) {
	limit := len(src)
	if maxEnd > 0 && maxEnd < limit {
		limit = maxEnd
	}
	if openQuoteIdx < 0 || openQuoteIdx >= limit || src[openQuoteIdx] != '"' {
		return "", openQuoteIdx + 1, false
	}
	i := openQuoteIdx + 1
	for i < limit {
		ch := src[i]
		if ch == '"' {
			rawLiteral := src[openQuoteIdx : i+1]
			var out string
			if err := json.Unmarshal([]byte(rawLiteral), &out); err != nil {
				return "", i + 1, false
			}
			return out, i + 1, true
		}
		if ch == '\\' {
			i += 2
			continue
		}
		if ch < 0x20 {
			return "", i + 1, false
		}
		i++
	}
	return "", limit, false
}

// ExtractBalancedJSONAt extracts a balanced `{...}` or `[...]` JSON slice starting at or after `startIdx`
// (skipping leading whitespace and `=`) within `maxScanChars` bytes in linear O(N) time.
func ExtractBalancedJSONAt(src string, startIdx, maxScanChars int) (rawJSON string, endIdx int, ok bool) {
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
	inString := false
	for i := start; i < limit; i++ {
		ch := src[i]
		if inString {
			if ch == '\\' {
				i++
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			continue
		}
		if ch == openByte {
			depth++
		} else if ch == closeByte {
			depth--
			if depth == 0 {
				return src[start : i+1], i + 1, true
			}
		}
	}
	return "", 0, false
}

// IsNuxtDevalueFlatArray detects whether a parsed JSON value is a Nuxt 3/4 `devalue` flat index-pointer array.
func IsNuxtDevalueFlatArray(parsed any) bool {
	arr, ok := parsed.([]any)
	if !ok || len(arr) < 2 {
		return false
	}
	switch root := arr[0].(type) {
	case []any:
		if len(root) == 2 {
			tag, okTag := root[0].(string)
			_, okIdx := jsonIntHydrateGo(root[1])
			if okTag && okIdx && devalueWrapperTagsHydrateGo[tag] {
				return true
			}
		}
	case map[string]any:
		if len(root) == 0 {
			return false
		}
		for _, v := range root {
			idx, okIdx := jsonIntHydrateGo(v)
			if !okIdx || idx < -8 || idx >= len(arr) {
				return false
			}
		}
		return true
	}
	return false
}

// DereferenceNuxtDevaluePayload safely dereferences a Nuxt 3/4 `devalue` flat slot table into a
// bounded (`maxNodes`, `maxDepth = 12`), cycle-free plain Go tree while blocking prototype-pollution keys.
func DereferenceNuxtDevaluePayload(flat []any, maxNodes int) any {
	if len(flat) == 0 {
		return nil
	}
	if maxNodes <= 0 {
		maxNodes = 2_000
	}
	const maxDepth = 12
	memo := make(map[int]any)
	activeStack := make(map[int]bool)
	allocatedNodes := 0

	isSlotIndex := func(v any) (int, bool) {
		idx, ok := jsonIntHydrateGo(v)
		if !ok || idx < 0 || idx >= len(flat) {
			return 0, false
		}
		return idx, true
	}

	var derefSlot func(idx, depth int) any
	derefSlot = func(idx, depth int) any {
		if idx < 0 || idx >= len(flat) || depth > maxDepth || allocatedNodes >= maxNodes {
			return nil
		}
		if cached, exists := memo[idx]; exists {
			return cached
		}
		if activeStack[idx] {
			return nil // Cycle breaker
		}

		raw := flat[idx]
		if raw == nil {
			return nil
		}
		switch typedRaw := raw.(type) {
		case []any:
			activeStack[idx] = true
			allocatedNodes++
			var result any
			tag := ""
			if len(typedRaw) > 0 {
				tag, _ = typedRaw[0].(string)
			}
			switch {
			case tag != "" && devalueWrapperTagsHydrateGo[tag]:
				if len(typedRaw) > 1 {
					if slotIdx, ok := isSlotIndex(typedRaw[1]); ok {
						result = derefSlot(slotIdx, depth+1)
					}
				}
			case tag != "" && devalueEmptyTagsHydrateGo[tag]:
				result = nil
			case tag != "" && devalueStringTagsHydrateGo[tag]:
				if len(typedRaw) > 1 {
					if s, ok := typedRaw[1].(string); ok {
						result = s
					} else if slotIdx, ok := isSlotIndex(typedRaw[1]); ok {
						result = derefSlot(slotIdx, depth+1)
					}
				}
			case tag == "Set":
				end := len(typedRaw)
				if end > 251 {
					end = 251
				}
				items := make([]any, 0, end-1)
				for i := 1; i < end; i++ {
					if allocatedNodes >= maxNodes {
						break
					}
					if slotIdx, ok := isSlotIndex(typedRaw[i]); ok {
						items = append(items, derefSlot(slotIdx, depth+1))
					} else {
						items = append(items, typedRaw[i])
					}
				}
				result = items
			case tag == "Map":
				obj := make(map[string]any)
				for i := 1; i+1 < len(typedRaw) && i < 201; i += 2 {
					if allocatedNodes >= maxNodes {
						break
					}
					var kVal any = typedRaw[i]
					if slotIdx, ok := isSlotIndex(typedRaw[i]); ok {
						kVal = derefSlot(slotIdx, depth+1)
					}
					kStr, okK := scalarStringOrNumberSchemaGo(kVal)
					if !okK || kStr == "" || unsafeObjectKeysHydrateGo[kStr] {
						continue
					}
					var vVal any = typedRaw[i+1]
					if slotIdx, ok := isSlotIndex(typedRaw[i+1]); ok {
						vVal = derefSlot(slotIdx, depth+1)
					}
					obj[kStr] = vVal
				}
				result = obj
			default:
				allIndices := len(typedRaw) > 0
				for _, x := range typedRaw {
					n, okN := jsonIntHydrateGo(x)
					if !okN || n < -8 || n >= len(flat) {
						allIndices = false
						break
					}
				}
				lim := len(typedRaw)
				if lim > 300 {
					lim = 300
				}
				outArr := make([]any, 0, lim)
				for i := 0; i < lim; i++ {
					if allocatedNodes >= maxNodes {
						break
					}
					el := typedRaw[i]
					if allIndices {
						if slotIdx, ok := isSlotIndex(el); ok {
							outArr = append(outArr, derefSlot(slotIdx, depth+1))
						} else {
							outArr = append(outArr, nil)
						}
					} else {
						outArr = append(outArr, el)
					}
				}
				result = outArr
			}
			delete(activeStack, idx)
			memo[idx] = result
			return result

		case map[string]any:
			activeStack[idx] = true
			allocatedNodes++
			outObj := make(map[string]any)
			keys := sortedMapKeysSchemaGo(typedRaw)
			if len(keys) > 200 {
				keys = keys[:200]
			}
			for _, k := range keys {
				if allocatedNodes >= maxNodes {
					break
				}
				if unsafeObjectKeysHydrateGo[k] || skipWalkKeysHydrateGo[strings.ToLower(k)] {
					continue
				}
				v := typedRaw[k]
				if slotIdx, ok := isSlotIndex(v); ok {
					outObj[k] = derefSlot(slotIdx, depth+1)
				} else if negIdx, okNeg := jsonIntHydrateGo(v); okNeg && negIdx < 0 {
					// devalue negative sentinels (-1 = undefined, -2 = NaN, etc.)
					continue
				} else {
					outObj[k] = v
				}
			}
			delete(activeStack, idx)
			memo[idx] = outObj
			return outObj

		default:
			return raw
		}
	}

	return derefSlot(0, 0)
}

// DistilledRecordsResult holds structured records, GFM Markdown table, and pagination metadata distilled from a JSON tree.
type DistilledRecordsResult struct {
	Records    []map[string]any `json:"records"`
	Markdown   string           `json:"markdown"`
	Returned   int              `json:"returned"`
	Total      *int             `json:"total,omitempty"`
	Truncated  bool             `json:"truncated,omitempty"`
	NextCursor string           `json:"nextCursor,omitempty"`
}

// DistillStructuredRecordsFull walks an arbitrary JSON state or XHR payload tree (`maxVisited = 2_500`, `maxDepth = 12`)
// and returns the full DistilledRecordsResult (records + GFM Markdown + pagination metadata), or nil when none matches.
func DistillStructuredRecordsFull(root any, baseURL string, maxRecords int) *DistilledRecordsResult {
	res := distillRecordsWithMetaHydrateGo(root, baseURL, maxRecords)
	if res == nil || len(res.records) == 0 {
		return nil
	}
	out := &DistilledRecordsResult{
		Records:    res.records,
		Markdown:   res.markdown,
		Returned:   res.returned,
		Truncated:  res.truncated,
		NextCursor: res.nextCursor,
	}
	if res.hasTotal {
		t := res.total
		out.Total = &t
	}
	return out
}

// DistillStructuredRecordsFromJSONTree walks an arbitrary JSON state or XHR payload tree
// (`maxVisited = 2_500`, `maxDepth = 12`) to extract the highest-confidence homogeneous data record array
// (`>= 3` items, capped at `maxRecords`), rejecting nav/menu chrome and returning `nil` when none matches.
func DistillStructuredRecordsFromJSONTree(root any, baseURL string, maxRecords int) []map[string]any {
	res := distillRecordsWithMetaHydrateGo(root, baseURL, maxRecords)
	if res == nil || len(res.records) == 0 {
		return nil
	}
	return res.records
}

// ExtractNextRSCFlight extracts prose and structured records from Next.js App Router RSC Flight streams
// (`self.__next_f.push([1, "..."])`), including `$` Flight chunk reference resolution, in linear O(N) time.
func ExtractNextRSCFlight(rawHTML, baseURL string, htmlToMD func(frag, base string) (string, []string)) *HydratedFrameworkStateResult {
	if rawHTML == "" || !strings.Contains(rawHTML, "__next_f.push") {
		return nil
	}
	boundedHTML := sliceUTF8CleanBytesSchemaGo(rawHTML, maxHTMLScanBytesHydrateGo)
	if !strings.Contains(boundedHTML, "__next_f.push") {
		return nil
	}

	var rscChunks []string
	totalRSCChars := 0
	searchPos := 0
	const marker = "__next_f.push("

	for searchPos < len(boundedHTML) && len(rscChunks) < 300 && totalRSCChars < 1_500_000 {
		rel := strings.Index(boundedHTML[searchPos:], marker)
		if rel < 0 {
			break
		}
		idx := searchPos + rel
		p := idx + len(marker)
		for p < len(boundedHTML) && (boundedHTML[p] <= 32 || boundedHTML[p] == '[') {
			p++
		}
		if p < len(boundedHTML) && boundedHTML[p] >= '0' && boundedHTML[p] <= '2' {
			p++
			for p < len(boundedHTML) && boundedHTML[p] <= 32 {
				p++
			}
			if p < len(boundedHTML) && boundedHTML[p] == ',' {
				p++
				for p < len(boundedHTML) && boundedHTML[p] <= 32 {
					p++
				}
				if p < len(boundedHTML) && boundedHTML[p] == '"' {
					maxEnd := p + 1 + 1_000_000
					if maxEnd > len(boundedHTML) {
						maxEnd = len(boundedHTML)
					}
					decoded, nextIdx, ok := ScanJSONStringLiteralAt(boundedHTML, p, maxEnd)
					if ok {
						searchPos = nextIdx
						if decoded != "" {
							rscChunks = append(rscChunks, decoded)
							totalRSCChars += len(decoded)
						}
						continue
					}
					if nextIdx > idx+len(marker) {
						searchPos = nextIdx
						continue
					}
				}
			}
		}
		searchPos = idx + len(marker)
	}

	if len(rscChunks) == 0 {
		return nil
	}

	rscTitle := extractHTMLTitleLinearHydrateGo(boundedHTML)
	combinedRSC := strings.Join(rscChunks, "")
	var rscBlocks []string
	seenRSC := make(map[string]bool)

	addProseCandidate := func(rawStr string, minWords int) {
		pre := strings.TrimSpace(StripInvisibleSchemaChars(rawStr))
		if len(pre) < 80 {
			return
		}
		head80 := pre
		if len(head80) > 80 {
			head80 = head80[:80]
		}
		if !containsWhitespaceHydrateGo(head80) {
			return
		}
		lowerPre := strings.ToLower(pre[:minIntHydrateGo(len(pre), 16)])
		if strings.HasPrefix(lowerPre, "http://") || strings.HasPrefix(lowerPre, "https://") || strings.HasPrefix(lowerPre, "/_next/") {
			return
		}
		hasHTML := strings.IndexByte(pre, '<') >= 0 && reHydrateHTMLTagHydrateGo.MatchString(pre)
		var converted string
		if hasHTML {
			converted = convertHTMLFragmentHydrateGo(pre, baseURL, htmlToMD)
		} else {
			converted = pre
		}
		converted = neutralizeAllUnsafeMarkdownLinksLinearGo(StripInvisibleSchemaChars(converted))
		converted = escapeDangerousAngleBracketsSchemaGo(converted)
		wc := countWordsSchemaGo(converted)
		if wc >= minWords && !seenRSC[converted] {
			seenRSC[converted] = true
			rscBlocks = append(rscBlocks, converted)
		}
	}

	var piDecodedChunks []string
	piDecodedChars := 0
	sawRSCUnicodeTag := HasRawOrEncodedUnicodeTag(combinedRSC)
	recordPILeaf := func(s string) {
		dec := s
		if strings.IndexByte(s, '&') >= 0 {
			dec = decodeBasicEntitiesSchemaGo(s)
		}
		if !sawRSCUnicodeTag && HasRawOrEncodedUnicodeTag(dec) {
			sawRSCUnicodeTag = true
		}
		if piDecodedChars < maxStatePIBytesHydrateGo && dec != "" {
			slice := sliceUTF8CleanBytesSchemaGo(dec, maxStatePIBytesHydrateGo-piDecodedChars)
			if slice != "" {
				piDecodedChunks = append(piDecodedChunks, slice)
				piDecodedChars += len(slice)
			}
		}
	}

	// Single-pass O(N) escape-aware character state machine over `combinedRSC` (`HIGH-1` & `HIGH-3`).
	stringLiteralsDecoded := 0
	inRSCStr := false
	rscStrStart := -1
	for i := 0; i < len(combinedRSC); i++ {
		ch := combinedRSC[i]
		if !inRSCStr {
			if ch == '\\' {
				i++
				continue
			}
			if ch == '"' {
				inRSCStr = true
				rscStrStart = i
			}
			continue
		}
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inRSCStr = false
			litLen := i + 1 - rscStrStart
			if litLen >= 10 && litLen <= 250_002 && stringLiteralsDecoded < 30_000 {
				rawLiteral := combinedRSC[rscStrStart : i+1]
				if litLen >= 82 || strings.IndexByte(rawLiteral, '\\') >= 0 || strings.IndexByte(rawLiteral, '&') >= 0 {
					stringLiteralsDecoded++
					var unescaped string
					if err := json.Unmarshal([]byte(rawLiteral), &unescaped); err == nil {
						recordPILeaf(unescaped)
						if len(unescaped) >= 80 {
							addProseCandidate(unescaped, 25)
						}
					}
				}
			}
		}
	}

	// Line-by-line scan for `<id>:T<hex>,<prose>`, `<id>:"..."`, and `<id>:{...}` / `<id>:[...]` chunks with `$` reference map.
	flightChunksByID := make(map[string]any)
	var flightChunkOrder []string
	var parsedFlightObjects []any

	lineStart := 0
	linesScanned := 0
	for lineStart < len(combinedRSC) && linesScanned < 3_000 {
		nlRel := strings.IndexByte(combinedRSC[lineStart:], '\n')
		lineEnd := len(combinedRSC)
		if nlRel >= 0 {
			lineEnd = lineStart + nlRel
		}
		line := strings.TrimSpace(combinedRSC[lineStart:lineEnd])
		if nlRel >= 0 {
			lineStart = lineEnd + 1
		} else {
			lineStart = len(combinedRSC)
		}
		linesScanned++
		if line == "" {
			continue
		}

		chunkID := ""
		payload := line
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx > 0 && colonIdx <= 12 && isFlightChunkIDHydrateGo(line[:colonIdx]) {
			chunkID = line[:colonIdx]
			payload = line[colonIdx+1:]
		}

		if strings.HasPrefix(payload, "T") || strings.HasPrefix(payload, "t") {
			commaIdx := strings.IndexByte(payload, ',')
			if commaIdx > 1 && commaIdx <= 10 {
				tBody := payload[commaIdx+1:]
				if chunkID != "" {
					flightChunksByID[chunkID] = tBody
				}
				recordPILeaf(tBody)
				addProseCandidate(tBody, 30)
				continue
			}
		}

		if chunkID != "" && len(payload) >= 2 && payload[0] == '"' && len(payload) <= 250_002 {
			var strChunk string
			if err := json.Unmarshal([]byte(payload), &strChunk); err == nil {
				flightChunksByID[chunkID] = strChunk
				if len(strChunk) >= 80 {
					addProseCandidate(strChunk, 25)
				}
				continue
			}
		}

		// Strip leading RSC Flight type prefixes like `I[...]` or `HL[...]` only when pure JSON starts at `[` or `{`.
		if len(parsedFlightObjects) < 120 && len(payload) >= 2 && len(payload) <= 512_000 && (payload[0] == '[' || payload[0] == '{') {
			var parsedLineObj any
			if err := json.Unmarshal([]byte(payload), &parsedLineObj); err == nil && parsedLineObj != nil {
				if chunkID != "" {
					flightChunksByID[chunkID] = parsedLineObj
					flightChunkOrder = append(flightChunkOrder, chunkID)
				}
				if len(payload) >= 40 || chunkID != "" {
					parsedFlightObjects = append(parsedFlightObjects, parsedLineObj)
				}
				continue
			}
		}
		if len(line) >= 80 && strings.IndexByte(line, '<') >= 0 && reHydrateHTMLTagHydrateGo.MatchString(line) {
			recordPILeaf(line)
			addProseCandidate(line, 25)
		}
	}

	// Resolve `$` Flight chunk references (`"$1a"`, `"$L1a"`, `"$@1a"`) cycle-safely across `flightChunksByID`.
	resolvedFlightObjects := parsedFlightObjects
	if len(flightChunksByID) > 0 && len(parsedFlightObjects) > 0 {
		resolvedFlightObjects = resolveFlightReferencesHydrateGo(parsedFlightObjects, flightChunksByID, 2_500)
		// Surface prose strings exposed via `$` chunk resolution.
		walkFlightProseStringsHydrateGo(resolvedFlightObjects, func(s string) {
			if len(s) >= 80 {
				addProseCandidate(s, 25)
			}
		})
	}
	_ = flightChunkOrder

	// Walk parsed Flight JSON objects to ensure nested/escaped string leaves are decoded for PI inspection.
	flightPIVisited := 0
	var walkFlightPI func(val any, depth int)
	walkFlightPI = func(val any, depth int) {
		if val == nil || depth > 18 || flightPIVisited > 100_000 {
			return
		}
		switch v := val.(type) {
		case string:
			if v == "" {
				return
			}
			flightPIVisited++
			recordPILeaf(v)
		case []any:
			if len(v) == 0 {
				return
			}
			flightPIVisited++
			for _, el := range v {
				if flightPIVisited > 100_000 {
					break
				}
				switch el.(type) {
				case string, []any, map[string]any:
					walkFlightPI(el, depth+1)
				}
			}
		case map[string]any:
			if len(v) == 0 {
				return
			}
			flightPIVisited++
			for _, k := range sortedMapKeysSchemaGo(v) {
				if unsafeObjectKeysHydrateGo[k] || skipWalkKeysHydrateGo[strings.ToLower(k)] {
					continue
				}
				if flightPIVisited > 100_000 {
					break
				}
				child := v[k]
				switch child.(type) {
				case string, []any, map[string]any:
					walkFlightPI(child, depth+1)
				}
			}
		}
	}
	for _, fo := range parsedFlightObjects {
		walkFlightPI(fo, 0)
	}

	var distilledRecords *distilledRecordsResultHydrateGo
	if len(resolvedFlightObjects) > 0 {
		distilledRecords = distillRecordsWithMetaHydrateGo(resolvedFlightObjects, baseURL, 250)
	}

	proseJoined := strings.TrimSpace(strings.Join(rscBlocks, "\n\n"))
	proseWords := countWordsSchemaGo(proseJoined)

	if proseWords < 25 && distilledRecords == nil {
		return nil
	}

	var bodyParts []string
	if proseWords >= 25 {
		bodyParts = append(bodyParts, proseJoined)
	}
	if distilledRecords != nil {
		bodyParts = append(bodyParts, distilledRecords.markdown)
	}
	combinedBody := strings.TrimSpace(strings.Join(bodyParts, "\n\n"))
	finalMD := combinedBody
	if rscTitle != "" && !strings.HasPrefix(combinedBody, "# ") {
		finalMD = "# " + rscTitle + "\n\n" + combinedBody
	}

	var piParts []string
	piParts = append(piParts, sliceUTF8CleanBytesSchemaGo(combinedRSC, 524_288))
	piParts = append(piParts, piDecodedChunks...)
	if sawRSCUnicodeTag {
		piParts = append(piParts, "\U000E0069")
	}

	out := &HydratedFrameworkStateResult{
		Title:                       rscTitle,
		Markdown:                    finalMD,
		Framework:                   "nextjs-rsc",
		RawDecodedStringsForPICheck: strings.Join(piParts, "\n"),
	}
	if distilledRecords != nil {
		out.Records = distilledRecords.records
		out.Returned = distilledRecords.returned
		if distilledRecords.hasTotal {
			out.Total = distilledRecords.total
		}
		out.Truncated = distilledRecords.truncated
		out.NextCursor = distilledRecords.nextCursor
	}
	return out
}

// ExtractFromParsedStateTree walks a parsed framework state tree (Next.js, Nuxt, Remix, Angular, Wix,
// Squarespace, Substack, Gatsby, Inertia) to extract rich prose sections and/or homogeneous `records[]`.
func ExtractFromParsedStateTree(root any, framework, baseURL string, htmlToMD func(frag, base string) (string, []string), rawSourceHint string, hasUnicodeTag bool) *HydratedFrameworkStateResult {
	if root == nil {
		return nil
	}
	switch root.(type) {
	case map[string]any, []any:
	default:
		return nil
	}

	rootTarget := root
	switch framework {
	case "nuxt":
		if IsNuxtDevalueFlatArray(root) {
			if arr, ok := root.([]any); ok {
				rootTarget = DereferenceNuxtDevaluePayload(arr, 2_000)
			}
		}
	case "nextjs":
		if m, ok := root.(map[string]any); ok {
			if props, okP := m["props"].(map[string]any); okP && props["pageProps"] != nil {
				rootTarget = props["pageProps"]
			}
		}
	case "gatsby":
		if m, ok := root.(map[string]any); ok && m["result"] != nil {
			rootTarget = m["result"]
		}
	case "inertia":
		if m, ok := root.(map[string]any); ok {
			if props, okP := m["props"].(map[string]any); okP && len(props) > 0 {
				rootTarget = props
			}
		}
	}

	switch rootTarget.(type) {
	case map[string]any, []any:
	default:
		return nil
	}

	bestTitle := ""
	bestTitleDepth := 999
	trimmedHint := strings.TrimSpace(rawSourceHint)
	if trimmedHint != "" {
		if !hasUnicodeTag && HasRawOrEncodedUnicodeTag(trimmedHint) {
			hasUnicodeTag = true
		}
		if len(trimmedHint) <= 300 && !strings.HasPrefix(trimmedHint, "{") && !strings.HasPrefix(trimmedHint, "[") {
			bestTitle = SanitizeSchemaPlainField(trimmedHint, 200)
			bestTitleDepth = -1
		}
	}

	bestDescription := ""
	var richSections []string
	seenBlocks := make(map[string]bool)
	var rawPIStrings []string
	rawPILen := 0
	sawStateUnicodeTag := hasUnicodeTag
	piVisited := 0

	var collectStatePILeaves func(node any, depth int)
	collectStatePILeaves = func(node any, depth int) {
		if node == nil || depth > 20 || piVisited > 100_000 {
			return
		}
		switch v := node.(type) {
		case string:
			trimmed := strings.TrimSpace(v)
			if trimmed == "" {
				return
			}
			piVisited++
			decodedForPI := trimmed
			if strings.IndexByte(trimmed, '&') >= 0 {
				decodedForPI = decodeBasicEntitiesSchemaGo(trimmed)
			}
			if !sawStateUnicodeTag && HasRawOrEncodedUnicodeTag(decodedForPI) {
				sawStateUnicodeTag = true
			}
			if rawPILen < maxStatePIBytesHydrateGo {
				chunk := sliceUTF8CleanBytesSchemaGo(decodedForPI, maxStatePIBytesHydrateGo-rawPILen)
				if chunk != "" {
					rawPIStrings = append(rawPIStrings, chunk)
					rawPILen += len(chunk)
				}
			}
		case []any:
			if len(v) == 0 {
				return
			}
			piVisited++
			for _, item := range v {
				if piVisited > 100_000 {
					break
				}
				switch item.(type) {
				case string, []any, map[string]any:
					collectStatePILeaves(item, depth+1)
				}
			}
		case map[string]any:
			if len(v) == 0 {
				return
			}
			piVisited++
			for _, k := range sortedMapKeysSchemaGo(v) {
				if unsafeObjectKeysHydrateGo[k] || skipWalkKeysHydrateGo[strings.ToLower(k)] {
					continue
				}
				if piVisited > 100_000 {
					break
				}
				child := v[k]
				switch child.(type) {
				case string, []any, map[string]any:
					collectStatePILeaves(child, depth+1)
				}
			}
		}
	}
	collectStatePILeaves(rootTarget, 0)
	if sawStateUnicodeTag {
		rawPIStrings = append(rawPIStrings, "\U000E0069")
	}

	visited := 0
	var walkProse func(node any, depth int, keyHint string)
	walkProse = func(node any, depth int, keyHint string) {
		if node == nil || depth > 11 || visited > 2_000 {
			return
		}
		visited++

		switch v := node.(type) {
		case string:
			rawTrimmed := strings.TrimSpace(v)
			if rawTrimmed == "" {
				return
			}
			lowerKey := strings.ToLower(keyHint)
			if (bestTitle == "" || depth < bestTitleDepth) &&
				(lowerKey == "title" || lowerKey == "jobtitle" || lowerKey == "headline" || lowerKey == "pagetitle") &&
				len(rawTrimmed) >= 4 && len(rawTrimmed) <= 180 &&
				!reAnyAlphaTagHydrateGo.MatchString(rawTrimmed) {
				bestTitle = SanitizeSchemaPlainField(rawTrimmed, 180)
				bestTitleDepth = depth
				return
			}
			if bestDescription == "" &&
				(lowerKey == "description" || lowerKey == "shortdescription" || lowerKey == "excerpt" || lowerKey == "subtitle") &&
				len(rawTrimmed) >= 40 && len(rawTrimmed) <= 400 &&
				!reAnyAlphaTagHydrateGo.MatchString(rawTrimmed) {
				bestDescription = SanitizeSchemaPlainField(rawTrimmed, 400)
			}

			isRichKey := richProseKeysHydrateGo[lowerKey] || reRichProseKeySubHydrateGo.MatchString(lowerKey)
			if !isRichKey || len(rawTrimmed) < 120 {
				return
			}
			head100 := rawTrimmed
			if len(head100) > 100 {
				head100 = head100[:100]
			}
			if !containsWhitespaceHydrateGo(head100) {
				return
			}

			preClean := StripInvisibleSchemaChars(rawTrimmed)
			hasHTML := strings.IndexByte(preClean, '<') >= 0 && reHydrateHTMLTagHydrateGo.MatchString(preClean)
			var converted string
			if hasHTML {
				converted = convertHTMLFragmentHydrateGo(preClean, baseURL, htmlToMD)
			} else {
				converted = preClean
				if strings.IndexByte(converted, '&') >= 0 {
					// Pre-escape `<` before entity decoding so `&lt;script&gt;` vs literal `<` never confuse downstream prose!
					converted = preEscapeLtDecodeEntitiesHydrateGo(converted)
				}
			}
			converted = StripInvisibleSchemaChars(converted)
			converted = neutralizeAllUnsafeMarkdownLinksLinearGo(converted)
			converted = escapeDangerousAngleBracketsSchemaGo(converted)

			wc := countWordsSchemaGo(converted)
			if wc >= 25 && !seenBlocks[converted] {
				seenBlocks[converted] = true
				richSections = append(richSections, converted)
			}

		case []any:
			lim := len(v)
			if lim > 80 {
				lim = 80
			}
			for i := 0; i < lim; i++ {
				walkProse(v[i], depth+1, keyHint)
			}

		case map[string]any:
			for _, k := range sortedMapKeysSchemaGo(v) {
				if unsafeObjectKeysHydrateGo[k] || skipWalkKeysHydrateGo[strings.ToLower(k)] {
					continue
				}
				walkProse(v[k], depth+1, k)
			}
		}
	}

	walkProse(rootTarget, 0, "")
	distilledRecords := distillRecordsWithMetaHydrateGo(rootTarget, baseURL, 250)

	proseJoined := strings.TrimSpace(strings.Join(richSections, "\n\n"))
	proseWords := countWordsSchemaGo(proseJoined)

	if proseWords < 35 && distilledRecords == nil {
		return nil
	}

	var sections []string
	if proseWords >= 35 {
		sections = append(sections, proseJoined)
	}
	if distilledRecords != nil {
		sections = append(sections, distilledRecords.markdown)
	}
	bodyJoined := strings.TrimSpace(strings.Join(sections, "\n\n"))
	finalMD := bodyJoined
	if bestTitle != "" && !hasLeadingMarkdownH1HydrateGo(bodyJoined) {
		finalMD = "# " + bestTitle + "\n\n" + bodyJoined
	}

	out := &HydratedFrameworkStateResult{
		Title:       bestTitle,
		Description: bestDescription,
		Markdown:    finalMD,
		Framework:   framework,
	}
	if distilledRecords != nil {
		out.Records = distilledRecords.records
		out.Returned = distilledRecords.returned
		structured := map[string]any{
			"source":   "hydration:" + framework,
			"returned": distilledRecords.returned,
		}
		if distilledRecords.hasTotal {
			out.Total = distilledRecords.total
			structured["total"] = distilledRecords.total
		}
		out.Truncated = distilledRecords.truncated
		out.NextCursor = distilledRecords.nextCursor
		out.Structured = structured
	}
	if len(rawPIStrings) > 0 {
		out.RawDecodedStringsForPICheck = strings.Join(rawPIStrings, "\n")
	}
	return out
}

// RecoverSSRHydrationContent recovers rich prose and/or structured `records[]` from embedded SSR/SPA state containers:
// `__NEXT_DATA__`, `__NUXT_DATA__` (including Nuxt 3/4 `devalue`), Next App Router RSC `__next_f`, Inertia `data-page`
// (with `<` pre-escaping before entity decode), Angular `ng-state`, Remix `__remixContext`, Apollo `__APOLLO_STATE__`,
// Wix `wix-viewer-model`, Squarespace `SQUARESPACE_CONTEXT`, and Substack `window._preloads`.
func RecoverSSRHydrationContent(rawHTML, baseURL string, htmlToMD func(frag, base string) (string, []string)) *HydratedFrameworkStateResult {
	if rawHTML == "" {
		return nil
	}
	boundedHTML := sliceUTF8CleanBytesSchemaGo(rawHTML, maxHTMLScanBytesHydrateGo)
	hasScript := strings.Contains(boundedHTML, "<script") || strings.Contains(boundedHTML, "<SCRIPT") || indexFoldASCIIExtract(boundedHTML, "<script") >= 0
	hasInertia := strings.Contains(boundedHTML, "data-page=")
	if !hasScript && !hasInertia {
		return nil
	}

	docTitle := extractHTMLTitleLinearHydrateGo(boundedHTML)

	if hasScript {
		rawJSON := ""
		framework := ""

		scanScriptBlocksLinearSchemaGo(boundedHTML, maxHTMLScanBytesHydrateGo, func(attrStr, inner string) bool {
			if rawJSON != "" {
				return false
			}
			trimmedInner := strings.TrimSpace(inner)
			if trimmedInner == "" {
				return true
			}
			idVal := extractScriptIDAttrHydrateGo(attrStr)
			switch {
			case idVal == "__NEXT_DATA__":
				rawJSON = trimmedInner
				framework = "nextjs"
			case idVal == "__NUXT_DATA__":
				rawJSON = trimmedInner
				framework = "nuxt"
			case idVal == "ng-state":
				rawJSON = trimmedInner
				framework = "angular"
			case idVal == "wix-viewer-model":
				rawJSON = trimmedInner
				framework = "wix"
			case strings.Contains(trimmedInner, "__remixContext"):
				idx := strings.Index(trimmedInner, "__remixContext")
				if balanced, _, ok := ExtractBalancedJSONAt(trimmedInner, idx+len("__remixContext"), 1_500_000); ok {
					rawJSON = balanced
					framework = "remix"
				}
			case strings.Contains(trimmedInner, "__APOLLO_STATE__"):
				idx := strings.Index(trimmedInner, "__APOLLO_STATE__")
				if balanced, _, ok := ExtractBalancedJSONAt(trimmedInner, idx+len("__APOLLO_STATE__"), 1_500_000); ok {
					rawJSON = balanced
					framework = "apollo"
				}
			case strings.Contains(trimmedInner, "SQUARESPACE_CONTEXT"):
				idx := strings.Index(trimmedInner, "SQUARESPACE_CONTEXT")
				if balanced, _, ok := ExtractBalancedJSONAt(trimmedInner, idx+len("SQUARESPACE_CONTEXT"), 1_500_000); ok {
					rawJSON = balanced
					framework = "squarespace"
				}
			case strings.Contains(trimmedInner, "window._preloads"):
				idx := strings.Index(trimmedInner, "window._preloads")
				if parseRel := strings.Index(trimmedInner[idx:], "JSON.parse("); parseRel >= 0 {
					afterParse := idx + parseRel + len("JSON.parse(")
					if qRel := strings.IndexByte(trimmedInner[afterParse:], '"'); qRel >= 0 {
						qStart := afterParse + qRel
						maxEnd := qStart + 1 + 1_500_000
						if maxEnd > len(trimmedInner) {
							maxEnd = len(trimmedInner)
						}
						if innerStr, _, ok := ScanJSONStringLiteralAt(trimmedInner, qStart, maxEnd); ok && strings.TrimSpace(innerStr) != "" {
							rawJSON = strings.TrimSpace(innerStr)
							framework = "substack"
						}
					}
				}
			}
			return rawJSON == ""
		})

		if rawJSON == "" && strings.Contains(boundedHTML, "__next_f.push") {
			if rsc := ExtractNextRSCFlight(boundedHTML, baseURL, htmlToMD); rsc != nil {
				return rsc
			}
		}

		if rawJSON != "" && len(rawJSON) <= maxHTMLScanBytesHydrateGo {
			var parsed any
			if err := json.Unmarshal([]byte(rawJSON), &parsed); err == nil && parsed != nil {
				rawHasUnicodeTag := HasRawOrEncodedUnicodeTag(rawJSON)
				if res := ExtractFromParsedStateTree(parsed, framework, baseURL, htmlToMD, docTitle, rawHasUnicodeTag); res != nil {
					return res
				}
			}
		}
	}

	if hasInertia {
		if inertiaRes := extractInertiaHydrationHydrateGo(boundedHTML, baseURL, htmlToMD, docTitle); inertiaRes != nil {
			return inertiaRes
		}
	}

	return nil
}

// DistillCapturedJSONResponses distills same-origin `200 OK` `application/json` XHR/Fetch responses captured
// by Chromium CDP rendering into sanitized `records[]`, GFM Markdown, `structured` metadata, and decoded PI strings.
func DistillCapturedJSONResponses(inputs []CapturedJSONPayloadInput, baseURL string, htmlToMD func(frag, base string) (string, []string)) *HydratedFrameworkStateResult {
	_ = htmlToMD
	if len(inputs) == 0 || strings.TrimSpace(baseURL) == "" {
		return nil
	}
	expectedOrigin, okOrigin := originOfPublicHTTPSHydrateGo(baseURL)
	if !okOrigin {
		return nil
	}

	var piChunks []string
	piBytes := 0
	sawCapturedUnicodeTag := false
	var bestDistilled *distilledRecordsResultHydrateGo
	bestSourceURL := ""

	limit := len(inputs)
	if limit > 6 {
		limit = 6
	}
	for i := 0; i < limit; i++ {
		entry := inputs[i]
		respURL := strings.TrimSpace(entry.URL)
		bodyStr := strings.TrimSpace(entry.Body)
		status := entry.Status
		if status == 0 {
			status = 200
		}
		if respURL == "" || bodyStr == "" || len(bodyStr) > 512*1024 || status != 200 {
			continue
		}

		// Defense-in-depth: strictly verify `respURL` is a public `https://` URL on the exact same origin as `baseURL`.
		validURL := SanitizeSchemaHTTPSURL(respURL, "")
		if validURL == "" {
			continue
		}
		respOrigin, okResp := originOfPublicHTTPSHydrateGo(validURL)
		if !okResp || respOrigin != expectedOrigin {
			continue
		}

		if !sawCapturedUnicodeTag && HasRawOrEncodedUnicodeTag(bodyStr) {
			sawCapturedUnicodeTag = true
		}

		var parsed any
		if err := json.Unmarshal([]byte(bodyStr), &parsed); err != nil || parsed == nil {
			continue
		}

		// Per-entry node budget skipping primitives/empty containers (`NEW-HIGH-1`).
		entryVisited := 0
		var collectPILeaves func(val any, depth int)
		collectPILeaves = func(val any, depth int) {
			if val == nil || depth > 20 || entryVisited > 100_000 {
				return
			}
			switch v := val.(type) {
			case string:
				if v == "" {
					return
				}
				entryVisited++
				dec := v
				if strings.IndexByte(v, '&') >= 0 {
					dec = decodeBasicEntitiesSchemaGo(v)
				}
				if !sawCapturedUnicodeTag && HasRawOrEncodedUnicodeTag(dec) {
					sawCapturedUnicodeTag = true
				}
				if piBytes < maxStatePIBytesHydrateGo {
					slice := sliceUTF8CleanBytesSchemaGo(dec, maxStatePIBytesHydrateGo-piBytes)
					if slice != "" {
						piChunks = append(piChunks, slice)
						piBytes += len(slice)
					}
				}
			case []any:
				if len(v) == 0 {
					return
				}
				entryVisited++
				for _, el := range v {
					if entryVisited > 100_000 {
						break
					}
					switch el.(type) {
					case string, []any, map[string]any:
						collectPILeaves(el, depth+1)
					}
				}
			case map[string]any:
				if len(v) == 0 {
					return
				}
				entryVisited++
				for _, k := range sortedMapKeysSchemaGo(v) {
					if unsafeObjectKeysHydrateGo[k] || skipWalkKeysHydrateGo[strings.ToLower(k)] {
						continue
					}
					if entryVisited > 100_000 {
						break
					}
					child := v[k]
					switch child.(type) {
					case string, []any, map[string]any:
						collectPILeaves(child, depth+1)
					}
				}
			}
		}
		collectPILeaves(parsed, 0)

		cand := distillRecordsWithMetaHydrateGo(parsed, baseURL, 250)
		if cand != nil && (bestDistilled == nil || len(cand.records) > len(bestDistilled.records)) {
			bestDistilled = cand
			bestSourceURL = validURL
		}
	}

	if sawCapturedUnicodeTag {
		piChunks = append(piChunks, "\U000E0069")
	}
	if bestDistilled == nil && len(piChunks) == 0 {
		return nil
	}

	out := &HydratedFrameworkStateResult{
		Framework:                   "cdp-xhr-json",
		RawDecodedStringsForPICheck: strings.Join(piChunks, "\n"),
	}
	if bestDistilled != nil {
		out.Records = bestDistilled.records
		out.Markdown = bestDistilled.markdown
		out.Returned = bestDistilled.returned
		structured := map[string]any{
			"source":   "cdp-xhr-json",
			"returned": bestDistilled.returned,
		}
		if bestSourceURL != "" {
			structured["endpoint"] = bestSourceURL
		}
		if bestDistilled.hasTotal {
			out.Total = bestDistilled.total
			structured["total"] = bestDistilled.total
		}
		out.Truncated = bestDistilled.truncated
		out.NextCursor = bestDistilled.nextCursor
		out.Structured = structured
	}
	return out
}

// --- Unexported Hydration & Record Distillation Helpers (all suffixed with HydrateGo) ---

type distilledRecordsResultHydrateGo struct {
	records    []map[string]any
	markdown   string
	returned   int
	total      int
	hasTotal   bool
	truncated  bool
	nextCursor string
}

type scoredRecordCandidateHydrateGo struct {
	score     int
	items     []map[string]any
	parentObj map[string]any
	keyHint   string
}

func distillRecordsWithMetaHydrateGo(root any, baseURL string, maxRecords int) *distilledRecordsResultHydrateGo {
	if root == nil {
		return nil
	}
	switch root.(type) {
	case map[string]any, []any:
	default:
		return nil
	}
	if maxRecords <= 0 {
		maxRecords = 250
	}
	if maxRecords > 500 {
		maxRecords = 500
	}

	visited := 0
	var best *scoredRecordCandidateHydrateGo

	evaluateArray := func(arr []any, parentObj map[string]any, keyHint string) {
		if len(arr) < 3 || len(arr) > 500 {
			return
		}
		if reNavContainerKeyHydrateGo.MatchString(keyHint) {
			return
		}

		sampleCount := len(arr)
		if sampleCount > 25 {
			sampleCount = 25
		}
		var unwrappedSample []map[string]any
		for i := 0; i < sampleCount; i++ {
			if u := unwrapRelayNodeHydrateGo(arr[i]); u != nil {
				unwrappedSample = append(unwrappedSample, u)
			}
		}
		minRequired := int(math.Ceil(float64(sampleCount) * 0.8))
		if len(unwrappedSample) < minRequired {
			return
		}

		validTitleCount := 0
		urlCount := 0
		richMetaCount := 0
		totalTitleLen := 0
		maxKeysSeen := 0

		for _, item := range unwrappedSample {
			safeKeyCount := 0
			for k := range item {
				if !unsafeObjectKeysHydrateGo[k] {
					safeKeyCount++
				}
			}
			if safeKeyCount > maxKeysSeen {
				maxKeysSeen = safeKeyCount
			}
			if safeKeyCount < 2 {
				continue
			}

			rawTitle := readCaseInsensitiveScalarHydrateGo(item, recordTitleKeysHydrateGo)
			cleanTitle := SanitizeSchemaPlainField(rawTitle, 240)
			lowerTitle := strings.ToLower(cleanTitle)
			if len(cleanTitle) >= 2 &&
				len(cleanTitle) <= 220 &&
				!strings.HasPrefix(lowerTitle, "http://") &&
				!strings.HasPrefix(lowerTitle, "https://") &&
				!reUUIDPrefixHydrateGo.MatchString(cleanTitle) {
				validTitleCount++
				totalTitleLen += len(cleanTitle)
			}

			rawURL := readCaseInsensitiveScalarHydrateGo(item, recordURLKeysHydrateGo)
			if rawURL != "" && (strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "/") || reSlugLikeURLHydrateGo.MatchString(rawURL)) {
				urlCount++
			}

			rawMeta := readCaseInsensitiveScalarHydrateGo(item, recordMetaKeysHydrateGo)
			if rawMeta != "" && rawMeta != rawTitle {
				richMetaCount++
			}
		}

		titleRatio := float64(validTitleCount) / float64(len(unwrappedSample))
		maxAnchorMeta := urlCount
		if richMetaCount > maxAnchorMeta {
			maxAnchorMeta = richMetaCount
		}
		anchorOrMetaRatio := float64(maxAnchorMeta) / float64(len(unwrappedSample))
		if titleRatio < 0.8 || anchorOrMetaRatio < 0.6 {
			return
		}

		avgTitleLen := 0.0
		if validTitleCount > 0 {
			avgTitleLen = float64(totalTitleLen) / float64(validTitleCount)
		}
		// Anti-Nav-Menu Guard: reject short `{ label, href }` link lists with zero metadata!
		if len(arr) <= 10 && richMetaCount == 0 && (maxKeysSeen <= 3 || avgTitleLen < 22) {
			return
		}
		if richMetaCount == 0 && avgTitleLen < 14 {
			return
		}

		bonus := 0
		if reRecordBonusKeyHydrateGo.MatchString(keyHint) {
			bonus = 25
		}
		cappedLen := len(arr)
		if cappedLen > 100 {
			cappedLen = 100
		}
		score := cappedLen*2 + richMetaCount*4 + urlCount*2 + bonus
		if best == nil || score > best.score {
			take := len(arr)
			if take > maxRecords {
				take = maxRecords
			}
			allUnwrapped := make([]map[string]any, 0, take)
			for i := 0; i < take; i++ {
				if u := unwrapRelayNodeHydrateGo(arr[i]); u != nil {
					allUnwrapped = append(allUnwrapped, u)
				}
			}
			best = &scoredRecordCandidateHydrateGo{
				score:     score,
				items:     allUnwrapped,
				parentObj: parentObj,
				keyHint:   keyHint,
			}
		}
	}

	var walk func(node any, parentObj map[string]any, keyHint string, depth int)
	walk = func(node any, parentObj map[string]any, keyHint string, depth int) {
		if node == nil || depth > 12 || visited > 2_500 {
			return
		}
		visited++

		switch typed := node.(type) {
		case []any:
			evaluateArray(typed, parentObj, keyHint)
			lim := len(typed)
			if lim > 30 {
				lim = 30
			}
			for i := 0; i < lim; i++ {
				switch typed[i].(type) {
				case []any, map[string]any:
					walk(typed[i], nil, keyHint, depth+1)
				}
			}
		case map[string]any:
			for _, k := range sortedMapKeysSchemaGo(typed) {
				if unsafeObjectKeysHydrateGo[k] || skipWalkKeysHydrateGo[strings.ToLower(k)] {
					continue
				}
				v := typed[k]
				switch v.(type) {
				case []any, map[string]any:
					walk(v, typed, k, depth+1)
				}
			}
		}
	}

	walk(root, nil, "", 0)
	if best == nil {
		return nil
	}

	var records []map[string]any
	var tableRows [][]string
	hasLocationCol := false
	hasPriceOrDateCol := false
	hasSummaryCol := false

	for _, item := range best.items {
		title := SanitizeSchemaPlainField(readCaseInsensitiveScalarHydrateGo(item, recordTitleKeysHydrateGo), 240)
		if title == "" {
			continue
		}

		rawURLCandidate := readCaseInsensitiveScalarHydrateGo(item, recordURLKeysHydrateGo)
		safeURL := resolveCandidateRecordURLHydrateGo(rawURLCandidate, baseURL)
		if safeURL == "" && rawURLCandidate != "" && baseURL != "" && strings.Contains(rawURLCandidate, "/") && reRelPathSlugHydrateGo.MatchString(rawURLCandidate) {
			safeURL = resolveCandidateRecordURLHydrateGo("/"+rawURLCandidate, baseURL)
		}

		location := SanitizeSchemaPlainField(readCaseInsensitiveScalarHydrateGo(item, []string{"location", "locationName", "city", "workplaceType"}), 140)
		price := SanitizeSchemaPlainField(readCaseInsensitiveScalarHydrateGo(item, []string{"price", "salary", "compensation"}), 80)
		date := SanitizeSchemaPlainField(readCaseInsensitiveScalarHydrateGo(item, []string{"publishedAt", "published_at", "date", "postedAt", "createdAt", "created_at", "updatedAt"}), 64)
		companyOrAuthor := SanitizeSchemaPlainField(readCaseInsensitiveScalarHydrateGo(item, []string{"company", "organization", "author", "department", "category"}), 120)
		summaryRaw := SanitizeSchemaPlainField(readCaseInsensitiveScalarHydrateGo(item, []string{"summary", "description", "excerpt", "snippet", "answer"}), 320)
		summary := ""
		if summaryRaw != title {
			summary = summaryRaw
		}
		idVal := SanitizeSchemaPlainField(readCaseInsensitiveScalarHydrateGo(item, []string{"id", "jobId", "reqId", "sku", "version"}), 80)

		outRec := map[string]any{
			"title": title,
		}
		if safeURL != "" {
			outRec["url"] = safeURL
		}
		if companyOrAuthor != "" {
			outRec["meta"] = companyOrAuthor
		}
		if location != "" {
			outRec["location"] = location
			hasLocationCol = true
		}
		if price != "" {
			outRec["price"] = price
		}
		if date != "" {
			outRec["date"] = date
		}
		if price != "" || date != "" || companyOrAuthor != "" {
			hasPriceOrDateCol = true
		}
		if summary != "" {
			outRec["summary"] = summary
			hasSummaryCol = true
		}
		if idVal != "" {
			outRec["id"] = idVal
		}
		records = append(records, outRec)

		safeLink := formatSafeMarkdownLinkSchemaGo(title, safeURL)
		var infoBits []string
		if companyOrAuthor != "" {
			infoBits = append(infoBits, companyOrAuthor)
		}
		if price != "" {
			infoBits = append(infoBits, price)
		}
		if date != "" {
			infoBits = append(infoBits, date)
		}
		locCell := location
		if locCell == "" {
			locCell = "-"
		}
		infoCell := "-"
		if len(infoBits) > 0 {
			infoCell = strings.Join(infoBits, " · ")
		}
		sumCell := summary
		if sumCell == "" {
			sumCell = "-"
		}
		tableRows = append(tableRows, []string{safeLink, locCell, infoCell, sumCell})
	}

	if len(records) < 3 {
		return nil
	}

	total := 0
	hasTotal := false
	nextCursor := ""
	truncated := false
	if best.parentObj != nil {
		p := best.parentObj
		var pagSub map[string]any
		if m, ok := p["pagination"].(map[string]any); ok {
			pagSub = m
		} else if m, ok := p["pageInfo"].(map[string]any); ok {
			pagSub = m
		} else if m, ok := p["meta"].(map[string]any); ok {
			pagSub = m
		}

		for _, src := range []map[string]any{p, pagSub} {
			if src == nil {
				continue
			}
			for _, tk := range []string{"total", "totalCount", "total_count", "totalHits", "nbHits", "totalResults", "count", "found"} {
				if tv, ok := finiteNumberSchemaGo(src[tk]); ok {
					iv := int(math.Floor(tv))
					if iv >= len(records) && iv <= 10_000_000 {
						total = iv
						hasTotal = true
						break
					}
				}
			}
			for _, ck := range []string{"nextCursor", "next_cursor", "endCursor", "nextPageToken"} {
				if cs, ok := src[ck].(string); ok {
					trimmedCS := strings.TrimSpace(cs)
					if trimmedCS != "" && len(cs) <= 256 {
						nextCursor = SanitizeSchemaPlainField(cs, 256)
						break
					}
				}
			}
			if b, ok := src["hasNextPage"].(bool); ok && b {
				truncated = true
			}
			if b, ok := src["hasMore"].(bool); ok && b {
				truncated = true
			}
		}
		if hasTotal && total > len(records) {
			truncated = true
		}
	}

	colIndices := []int{0}
	headers := []string{"Item"}
	if hasLocationCol {
		colIndices = append(colIndices, 1)
		headers = append(headers, "Location")
	}
	if hasPriceOrDateCol {
		colIndices = append(colIndices, 2)
		headers = append(headers, "Info")
	}
	if hasSummaryCol {
		colIndices = append(colIndices, 3)
		headers = append(headers, "Summary")
	}
	if len(colIndices) == 1 {
		headers = append(headers, "Details")
		colIndices = append(colIndices, 3)
	}

	projectedRows := make([][]string, len(tableRows))
	for rIdx, row := range tableRows {
		proj := make([]string, len(colIndices))
		for cIdx, srcCol := range colIndices {
			if srcCol < len(row) && row[srcCol] != "" {
				proj[cIdx] = row[srcCol]
			} else {
				proj[cIdx] = "-"
			}
		}
		projectedRows[rIdx] = proj
	}
	md := formatGFMTableSchemaGo(headers, projectedRows)
	if truncated {
		totalNote := strconv.Itoa(len(records))
		if hasTotal {
			totalNote = fmt.Sprintf("%d of %d", len(records), total)
		}
		if nextCursor != "" {
			md += fmt.Sprintf("\n\n*Showing %s records (nextCursor: `%s`).*", totalNote, nextCursor)
		} else {
			md += fmt.Sprintf("\n\n*Showing %s records (list truncated).*", totalNote)
		}
	}

	return &distilledRecordsResultHydrateGo{
		records:    records,
		markdown:   md,
		returned:   len(records),
		total:      total,
		hasTotal:   hasTotal,
		truncated:  truncated,
		nextCursor: nextCursor,
	}
}

func unwrapRelayNodeHydrateGo(item any) map[string]any {
	obj, ok := item.(map[string]any)
	if !ok {
		return nil
	}
	if len(obj) <= 3 {
		if nodeMap, okN := obj["node"].(map[string]any); okN {
			return nodeMap
		}
	}
	return obj
}

func readCaseInsensitiveScalarHydrateGo(obj map[string]any, candidateKeys []string) string {
	for _, key := range candidateKeys {
		if val, exists := obj[key]; exists {
			if s := extractNestedScalarHydrateGo(val); s != "" {
				return s
			}
		}
	}
	sortedKeys := sortedMapKeysSchemaGo(obj)
	for _, want := range candidateKeys {
		for _, k := range sortedKeys {
			if strings.EqualFold(k, want) {
				if s := extractNestedScalarHydrateGo(obj[k]); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func extractNestedScalarHydrateGo(val any) string {
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case json.Number:
		return v.String()
	case map[string]any:
		for _, sub := range []string{"rendered", "name", "title", "label", "text", "value", "url", "href", "slug"} {
			switch sv := v[sub].(type) {
			case string:
				if t := strings.TrimSpace(sv); t != "" {
					return t
				}
			case float64:
				if !math.IsNaN(sv) && !math.IsInf(sv, 0) {
					return strconv.FormatFloat(sv, 'f', -1, 64)
				}
			case json.Number:
				if s := sv.String(); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func resolveCandidateRecordURLHydrateGo(rawVal, baseURL string) string {
	if rawVal == "" {
		return ""
	}
	trimmed := strings.TrimSpace(StripInvisibleSchemaChars(rawVal))
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || hasDisallowedURLSchemePrefixSchemaGo(trimmed) {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		return SanitizeSchemaHTTPSURL(trimmed, baseURL)
	}
	if strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "//") && baseURL != "" {
		return SanitizeSchemaHTTPSURL(trimmed, baseURL)
	}
	return ""
}

// --- Next.js RSC `$` Reference Dereferencing Helpers ---

func isFlightChunkIDHydrateGo(s string) bool {
	if s == "" || len(s) > 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
			return false
		}
	}
	return true
}

func parseFlightDollarRefHydrateGo(s string, table map[string]any) (string, bool) {
	if len(s) < 2 || len(s) > 16 || s[0] != '$' {
		return "", false
	}
	if s[1] == '$' {
		return "", false // `$$...` escaped literal `$` in React Flight protocol
	}
	rest := s[1:]
	if len(rest) > 1 && (rest[0] == 'L' || rest[0] == '@' || rest[0] == 'S') {
		rest = rest[1:]
	}
	if !isFlightChunkIDHydrateGo(rest) {
		return "", false
	}
	_, exists := table[rest]
	return rest, exists
}

func resolveFlightReferencesHydrateGo(objs []any, table map[string]any, maxNodes int) []any {
	allocated := 0
	active := make(map[string]bool)

	var resolveNode func(val any, depth int) any
	resolveNode = func(val any, depth int) any {
		if val == nil || depth > 14 || allocated >= maxNodes {
			return val
		}
		switch v := val.(type) {
		case string:
			if refID, ok := parseFlightDollarRefHydrateGo(v, table); ok {
				if active[refID] {
					return nil
				}
				active[refID] = true
				allocated++
				resolved := resolveNode(table[refID], depth+1)
				delete(active, refID)
				return resolved
			}
			if strings.HasPrefix(v, "$$") {
				return v[1:]
			}
			return v
		case []any:
			if len(v) == 0 {
				return v
			}
			allocated++
			lim := len(v)
			if lim > 300 {
				lim = 300
			}
			out := make([]any, 0, lim)
			for i := 0; i < lim; i++ {
				if allocated >= maxNodes {
					out = append(out, v[i])
					continue
				}
				out = append(out, resolveNode(v[i], depth+1))
			}
			return out
		case map[string]any:
			if len(v) == 0 {
				return v
			}
			allocated++
			out := make(map[string]any, len(v))
			for _, k := range sortedMapKeysSchemaGo(v) {
				if unsafeObjectKeysHydrateGo[k] || skipWalkKeysHydrateGo[strings.ToLower(k)] {
					continue
				}
				if allocated >= maxNodes {
					out[k] = v[k]
					continue
				}
				out[k] = resolveNode(v[k], depth+1)
			}
			return out
		default:
			return val
		}
	}

	out := make([]any, 0, len(objs))
	for _, o := range objs {
		out = append(out, resolveNode(o, 0))
	}
	return out
}

func walkFlightProseStringsHydrateGo(objs []any, onString func(string)) {
	visited := 0
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if v == nil || depth > 14 || visited > 2_000 {
			return
		}
		visited++
		switch t := v.(type) {
		case string:
			onString(t)
		case []any:
			lim := len(t)
			if lim > 80 {
				lim = 80
			}
			for i := 0; i < lim; i++ {
				walk(t[i], depth+1)
			}
		case map[string]any:
			for _, k := range sortedMapKeysSchemaGo(t) {
				if unsafeObjectKeysHydrateGo[k] || skipWalkKeysHydrateGo[strings.ToLower(k)] {
					continue
				}
				walk(t[k], depth+1)
			}
		}
	}
	for _, o := range objs {
		walk(o, 0)
	}
}

// --- Inertia `data-page` Hydration with `<` Pre-Escaping Before Entity Decode ---

func extractInertiaHydrationHydrateGo(boundedHTML, baseURL string, htmlToMD func(frag, base string) (string, []string), docTitle string) *HydratedFrameworkStateResult {
	rawAttr, ok := extractDataPageAttrLinearHydrateGo(boundedHTML, 524_288)
	if !ok || rawAttr == "" || len(rawAttr) > 524_288 {
		return nil
	}
	rawHasUnicodeTag := HasRawOrEncodedUnicodeTag(rawAttr)

	// CRITICAL SECURITY INVARIANT: Pre-escape any literal `<` in the raw `data-page` attribute to `&amp;lt;`
	// BEFORE HTML entity decoding so literal `<script>` / `<img...>` inside single-quoted `data-page='...'`
	// decodes to `&lt;script>` rather than raw `<script>`, while legitimate HTML-encoded `&lt;p&gt;` in
	// `data-page="{&quot;body&quot;:&quot;&lt;p&gt;...&lt;/p&gt;&quot;}"` decodes once to `<p>...</p>`.
	guardedAttr := rawAttr
	if strings.IndexByte(rawAttr, '<') >= 0 {
		guardedAttr = strings.ReplaceAll(rawAttr, "<", "&amp;lt;")
	}
	decodedJSON := decodeBasicEntitiesSchemaGo(guardedAttr)
	var parsed any
	if err := json.Unmarshal([]byte(decodedJSON), &parsed); err != nil || parsed == nil {
		return nil
	}
	inertiaObj, isObj := parsed.(map[string]any)
	if !isObj {
		return nil
	}

	// 1. Try rich prose (>= 35 words) / homogeneous records (>= 3 items) extraction first.
	if stateRes := ExtractFromParsedStateTree(inertiaObj, "inertia", baseURL, htmlToMD, docTitle, rawHasUnicodeTag); stateRes != nil {
		return stateRes
	}

	// 2. Otherwise render structured Inertia `{ component, props }` summary (`formatInertiaPagePropsToMarkdown` parity).
	return formatInertiaPagePropsHydrateGo(inertiaObj, baseURL, htmlToMD, rawHasUnicodeTag)
}

func extractDataPageAttrLinearHydrateGo(src string, maxScanBytes int) (string, bool) {
	capped := sliceUTF8CleanBytesSchemaGo(src, maxScanBytes)
	dead := &htmlDeadStateSchemaGo{}
	pos := strings.IndexByte(capped, '<')
	for pos >= 0 && pos < len(capped) {
		if dead.hasGtCache && dead.nextGtPos == -1 {
			break
		}
		if pos+2 > len(capped) {
			break
		}
		first := capped[pos+1]
		if first == '/' || first == '!' || first == '?' || !isASCIIAlphaSchemaGo(first) {
			rel := strings.IndexByte(capped[pos+1:], '<')
			if rel < 0 {
				break
			}
			pos = pos + 1 + rel
			continue
		}
		p := pos + 2
		for p < len(capped) && !isHTMLTagBoundaryByteSchemaGo(capped[p]) {
			p++
		}
		if p >= len(capped) {
			break
		}
		openEnd := findTagOpenEndQuoteAwareSchemaGo(capped, p, dead)
		if openEnd < 0 {
			break
		}
		attrChunk := capped[p:openEnd]
		if strings.Contains(attrChunk, "data-page") || indexFoldASCIIExtract(attrChunk, "data-page") >= 0 {
			if val, found := extractNamedHTMLAttrHydrateGo(attrChunk, "data-page"); found && val != "" {
				return val, true
			}
		}
		if openEnd+1 >= len(capped) {
			break
		}
		rel := strings.IndexByte(capped[openEnd+1:], '<')
		if rel < 0 {
			break
		}
		pos = openEnd + 1 + rel
	}
	return "", false
}

func preEscapeLtDecodeEntitiesHydrateGo(s string) string {
	if s == "" {
		return ""
	}
	clean := StripInvisibleSchemaChars(s)
	if strings.IndexByte(clean, '<') >= 0 {
		clean = strings.ReplaceAll(clean, "<", "&lt;")
	}
	decoded := decodeMarkdownEntitiesPreservingLtGo(clean)
	return StripInvisibleSchemaChars(decoded)
}

func preEscapeUntrustedInlineHydrateGo(val any, maxLen int) string {
	rawStr, ok := scalarStringOrNumberSchemaGo(val)
	if !ok {
		if b, isB := val.(bool); isB {
			if b {
				rawStr = "true"
			} else {
				rawStr = "false"
			}
		} else {
			return ""
		}
	}
	cleaned := StripInvisibleSchemaChars(rawStr)
	if strings.TrimSpace(cleaned) == "" {
		return ""
	}
	// Pre-escape `<` to `&lt;` BEFORE `decodeMarkdownEntitiesPreservingLtGo`!
	if strings.IndexByte(cleaned, '<') >= 0 {
		cleaned = strings.ReplaceAll(cleaned, "<", "&lt;")
	}
	decoded := StripInvisibleSchemaChars(decodeMarkdownEntitiesPreservingLtGo(cleaned))
	safe := neutralizeAllUnsafeMarkdownLinksLinearGo(decoded)
	safe = strings.ReplaceAll(safe, "\r", " ")
	safe = strings.ReplaceAll(safe, "\n", " ")
	safe = strings.ReplaceAll(safe, "<", "&lt;")
	safe = strings.Join(strings.Fields(safe), " ")
	if maxLen > 0 && utf16UnitsLenSchemaGo(safe) > maxLen {
		safe = strings.TrimSpace(sliceRunesMax(safe, maxLen))
	}
	return safe
}

func formatInertiaPagePropsHydrateGo(inertiaObj map[string]any, baseURL string, htmlToMD func(frag, base string) (string, []string), rawHasUnicodeTag bool) *HydratedFrameworkStateResult {
	rawComp, _ := inertiaObj["component"].(string)
	if strings.TrimSpace(rawComp) == "" {
		return nil
	}
	compClean := preEscapeUntrustedInlineHydrateGo(rawComp, 200)
	compClean = strings.ReplaceAll(compClean, "`", " ")
	compClean = strings.TrimSpace(compClean)
	if compClean == "" {
		return nil
	}

	rawProps, _ := inertiaObj["props"].(map[string]any)
	if len(rawProps) == 0 {
		return nil
	}

	// Collect PI string leaves across `inertiaObj`.
	var piChunks []string
	piBytes := 0
	sawUnicode := rawHasUnicodeTag
	piVisited := 0
	var collectPI func(val any, depth int)
	collectPI = func(val any, depth int) {
		if val == nil || depth > 18 || piVisited > 100_000 {
			return
		}
		switch v := val.(type) {
		case string:
			if v == "" {
				return
			}
			piVisited++
			dec := v
			if strings.IndexByte(v, '&') >= 0 {
				dec = decodeBasicEntitiesSchemaGo(v)
			}
			if !sawUnicode && HasRawOrEncodedUnicodeTag(dec) {
				sawUnicode = true
			}
			if piBytes < maxStatePIBytesHydrateGo {
				sl := sliceUTF8CleanBytesSchemaGo(dec, maxStatePIBytesHydrateGo-piBytes)
				if sl != "" {
					piChunks = append(piChunks, sl)
					piBytes += len(sl)
				}
			}
		case []any:
			if len(v) == 0 {
				return
			}
			piVisited++
			for _, el := range v {
				collectPI(el, depth+1)
			}
		case map[string]any:
			if len(v) == 0 {
				return
			}
			piVisited++
			for _, k := range sortedMapKeysSchemaGo(v) {
				if unsafeObjectKeysHydrateGo[k] {
					continue
				}
				collectPI(v[k], depth+1)
			}
		}
	}
	collectPI(inertiaObj, 0)
	if sawUnicode {
		piChunks = append(piChunks, "\U000E0069")
	}

	bestTitle := ""
	bestDescription := ""
	visited := 0

	escapeKeyHeading := func(val string) string {
		s := preEscapeUntrustedInlineHydrateGo(val, 120)
		s = strings.TrimLeft(s, "# \t")
		var sb strings.Builder
		sb.Grow(len(s))
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '*', '_', '`', '[', ']', '|':
				continue
			default:
				sb.WriteByte(s[i])
			}
		}
		return strings.TrimSpace(sb.String())
	}

	escapeCell := func(val any) string {
		s := preEscapeUntrustedInlineHydrateGo(val, 160)
		if s == "" {
			return "-"
		}
		return strings.ReplaceAll(s, "|", `\|`)
	}

	convertRichString := func(raw string) string {
		cleaned := strings.TrimSpace(StripInvisibleSchemaChars(raw))
		if cleaned == "" {
			return ""
		}
		if strings.IndexByte(cleaned, '<') >= 0 && reInertiaHTMLTagHydrateGo.MatchString(cleaned) {
			converted := convertHTMLFragmentHydrateGo(cleaned, baseURL, htmlToMD)
			converted = strings.TrimSpace(StripInvisibleSchemaChars(converted))
			converted = neutralizeAllUnsafeMarkdownLinksLinearGo(converted)
			return strings.ReplaceAll(converted, "<", "&lt;")
		}
		decoded := preEscapeLtDecodeEntitiesHydrateGo(cleaned)
		safe := neutralizeAllUnsafeMarkdownLinksLinearGo(decoded)
		return strings.ReplaceAll(safe, "<", "&lt;")
	}

	var renderObjectFields func(obj map[string]any, depth int) []string
	renderObjectFields = func(obj map[string]any, depth int) []string {
		if depth > 3 || visited > 400 {
			return nil
		}
		var bullets []string
		var subBlocks []string
		for _, k := range sortedMapKeysSchemaGo(obj) {
			visited++
			if visited > 400 {
				break
			}
			v := obj[k]
			lower := strings.ToLower(k)
			if unsafeObjectKeysHydrateGo[k] || inertiaSkipPropKeysHydrateGo[lower] || v == nil || v == "" {
				continue
			}
			if lower == "auth" {
				if authMap, okA := v.(map[string]any); okA && authMap["user"] == nil {
					continue
				}
			}
			safeKey := escapeKeyHeading(k)
			if safeKey == "" {
				safeKey = "field"
			}

			switch tv := v.(type) {
			case string:
				clean := strings.TrimSpace(StripInvisibleSchemaChars(tv))
				if clean == "" {
					continue
				}
				safeScalar := preEscapeUntrustedInlineHydrateGo(clean, 300)
				if bestTitle == "" && (lower == "title" || lower == "pagetitle" || lower == "headline" || lower == "name") && len(clean) <= 180 {
					bestTitle = preEscapeUntrustedInlineHydrateGo(clean, 180)
				}
				if bestDescription == "" && (lower == "description" || lower == "summary" || lower == "excerpt") && len(clean) >= 20 && len(clean) <= 400 && !reAnyAlphaTagHydrateGo.MatchString(clean) {
					bestDescription = preEscapeUntrustedInlineHydrateGo(clean, 400)
				}
				isProse := len(clean) >= 80 || lower == "body" || lower == "content" || lower == "markdown" || lower == "html" || lower == "descriptionhtml"
				if isProse && containsWhitespaceHydrateGo(clean) {
					if rich := convertRichString(clean); rich != "" {
						subBlocks = append(subBlocks, rich)
					}
				} else if safeScalar != "" {
					bullets = append(bullets, fmt.Sprintf("- **%s**: %s", safeKey, safeScalar))
				}

			case float64, int, int64, json.Number, bool:
				if sv := preEscapeUntrustedInlineHydrateGo(tv, 120); sv != "" {
					bullets = append(bullets, fmt.Sprintf("- **%s**: %s", safeKey, sv))
				}

			case []any:
				if len(tv) == 0 {
					continue
				}
				lim := len(tv)
				if lim > 40 {
					lim = 40
				}
				slice := tv[:lim]
				allScalars := true
				allObjects := true
				for _, it := range slice {
					switch it.(type) {
					case string, float64, int, int64, json.Number, bool:
						allObjects = false
					case map[string]any:
						allScalars = false
					default:
						allScalars = false
						allObjects = false
					}
				}
				if allScalars {
					var parts []string
					for _, it := range slice {
						if s := preEscapeUntrustedInlineHydrateGo(it, 160); s != "" {
							parts = append(parts, s)
						}
					}
					if len(parts) > 0 {
						bullets = append(bullets, fmt.Sprintf("- **%s**: %s", safeKey, strings.Join(parts, ", ")))
					}
				} else if allObjects {
					firstRow := slice[0].(map[string]any)
					var cols []string
					for _, ck := range sortedMapKeysSchemaGo(firstRow) {
						if unsafeObjectKeysHydrateGo[ck] {
							continue
						}
						switch firstRow[ck].(type) {
						case string, float64, int, int64, json.Number, bool:
							cols = append(cols, ck)
						}
						if len(cols) >= 6 {
							break
						}
					}
					if len(cols) >= 2 {
						headCells := make([]string, len(cols))
						sepCells := make([]string, len(cols))
						for i, c := range cols {
							headCells[i] = escapeCell(c)
							sepCells[i] = "---"
						}
						tLines := make([]string, 0, len(slice)+2)
						tLines = append(tLines, "| "+strings.Join(headCells, " | ")+" |")
						tLines = append(tLines, "| "+strings.Join(sepCells, " | ")+" |")
						for _, it := range slice {
							rm := it.(map[string]any)
							rowCells := make([]string, len(cols))
							for i, c := range cols {
								rowCells[i] = escapeCell(rm[c])
							}
							tLines = append(tLines, "| "+strings.Join(rowCells, " | ")+" |")
						}
						subBlocks = append(subBlocks, "### "+safeKey+"\n\n"+strings.Join(tLines, "\n"))
					} else {
						var itemLines []string
						for _, it := range slice {
							rm := it.(map[string]any)
							label := preEscapeUntrustedInlineHydrateGo(firstNonNilSchemaGo(rm["title"], rm["name"], rm["label"], rm["id"]), 160)
							rawDesc := ""
							if bs, okB := rm["body"].(string); okB {
								rawDesc = convertRichString(bs)
							} else if ds, okD := rm["description"].(string); okD {
								rawDesc = convertRichString(ds)
							}
							desc := strings.Join(strings.Fields(rawDesc), " ")
							if label != "" && desc != "" {
								itemLines = append(itemLines, fmt.Sprintf("- **%s**: %s", label, sliceRunesMax(desc, 400)))
							} else if label != "" {
								itemLines = append(itemLines, "- "+label)
							}
						}
						if len(itemLines) > 0 {
							subBlocks = append(subBlocks, "### "+safeKey+"\n\n"+strings.Join(itemLines, "\n"))
						}
					}
				}

			case map[string]any:
				if depth < 2 {
					nestedParts := renderObjectFields(tv, depth+1)
					if len(nestedParts) > 0 {
						hPrefix := "###"
						if depth == 0 {
							hPrefix = "##"
						}
						subBlocks = append(subBlocks, hPrefix+" "+safeKey+"\n\n"+strings.Join(nestedParts, "\n\n"))
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

	headingTitle := bestTitle
	if headingTitle == "" {
		headingTitle = strings.ReplaceAll(compClean, "/", " — ")
	}
	headingTitle = strings.Join(strings.Fields(headingTitle), " ")

	sections := []string{
		"# " + headingTitle,
		fmt.Sprintf("- **Inertia Component**: `%s`", compClean),
	}
	sections = append(sections, propSections...)

	distilled := distillRecordsWithMetaHydrateGo(rawProps, baseURL, 250)
	out := &HydratedFrameworkStateResult{
		Title:       bestTitle,
		Description: bestDescription,
		Markdown:    strings.TrimSpace(strings.Join(sections, "\n\n")),
		Framework:   "inertia",
	}
	if distilled != nil {
		out.Records = distilled.records
		out.Returned = distilled.returned
		if distilled.hasTotal {
			out.Total = distilled.total
		}
		out.Truncated = distilled.truncated
		out.NextCursor = distilled.nextCursor
	}
	if len(piChunks) > 0 {
		out.RawDecodedStringsForPICheck = strings.Join(piChunks, "\n")
	}
	return out
}

// --- Shared Small Hydration Utilities ---

func jsonIntHydrateGo(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n {
			return 0, false
		}
		if n > 1e9 || n < -1e9 {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

func convertHTMLFragmentHydrateGo(frag, baseURL string, htmlToMD func(frag, base string) (string, []string)) string {
	if htmlToMD != nil {
		md, _ := htmlToMD(frag, baseURL)
		return strings.TrimSpace(md)
	}
	var baseU *url.URL
	if baseURL != "" {
		baseU, _ = url.Parse(baseURL)
	}
	return strings.TrimSpace(htmlFragmentToMarkdown(frag, baseU))
}

func extractHTMLTitleLinearHydrateGo(boundedHTML string) string {
	headWin := sliceUTF8CleanBytesSchemaGo(boundedHTML, 65_536)
	lower := asciiLowerExtractString(headWin)
	openIdx := strings.Index(lower, "<title")
	if openIdx < 0 {
		return ""
	}
	afterName := openIdx + len("<title")
	if afterName >= len(headWin) || !isHTMLTagBoundaryByteSchemaGo(headWin[afterName]) {
		return ""
	}
	openEnd := findTagOpenEndQuoteAwareSchemaGo(headWin, afterName, nil)
	if openEnd < 0 || headWin[openEnd-1] == '/' {
		return ""
	}
	closeIdx := findNextValidCloseTagSchemaGo(lower, headWin, "</title", openEnd+1)
	if closeIdx < 0 || closeIdx-(openEnd+1) > 4096 {
		return ""
	}
	return SanitizeSchemaPlainField(headWin[openEnd+1:closeIdx], 300)
}

func extractScriptIDAttrHydrateGo(attrStr string) string {
	val, ok := extractNamedHTMLAttrHydrateGo(attrStr, "id")
	if !ok {
		return ""
	}
	return strings.TrimSpace(val)
}

func extractNamedHTMLAttrHydrateGo(attrStr, targetNameLower string) (string, bool) {
	n := len(attrStr)
	i := 0
	for i < n {
		for i < n && isHTMLAttrSpaceSchemaGo(attrStr[i]) {
			i++
		}
		if i >= n {
			break
		}
		if attrStr[i] == '/' || attrStr[i] == '>' {
			i++
			continue
		}
		nameStart := i
		for i < n && !isHTMLAttrSpaceSchemaGo(attrStr[i]) && attrStr[i] != '=' && attrStr[i] != '/' && attrStr[i] != '>' && attrStr[i] != '"' && attrStr[i] != '\'' {
			i++
		}
		if i == nameStart {
			i++
			continue
		}
		name := attrStr[nameStart:i]
		for i < n && isHTMLAttrSpaceSchemaGo(attrStr[i]) {
			i++
		}
		if i >= n || attrStr[i] != '=' {
			if strings.EqualFold(name, targetNameLower) {
				return "", true
			}
			continue
		}
		i++
		for i < n && isHTMLAttrSpaceSchemaGo(attrStr[i]) {
			i++
		}
		if i >= n {
			break
		}
		var val string
		if attrStr[i] == '"' || attrStr[i] == '\'' {
			q := attrStr[i]
			i++
			valStart := i
			for i < n && attrStr[i] != q {
				i++
			}
			if i >= n {
				return "", false
			}
			val = attrStr[valStart:i]
			i++
		} else {
			valStart := i
			for i < n && !isHTMLAttrSpaceSchemaGo(attrStr[i]) && attrStr[i] != '"' && attrStr[i] != '\'' && attrStr[i] != '>' {
				i++
			}
			val = attrStr[valStart:i]
		}
		if strings.EqualFold(name, targetNameLower) {
			return val, true
		}
	}
	return "", false
}

func originOfPublicHTTPSHydrateGo(rawURL string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", false
	}
	if _, ok := normalizeAndValidatePublicHTTPSURLSchemaGo(u, ""); !ok {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	return "https://" + host, true
}

func containsWhitespaceHydrateGo(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			return true
		}
	}
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		if r == '\u00A0' || r == '\u2000' || r == '\u3000' {
			return true
		}
		i += w
	}
	return false
}

func hasLeadingMarkdownH1HydrateGo(s string) bool {
	if !strings.HasPrefix(s, "#") || len(s) < 2 {
		return false
	}
	return s[1] == ' ' || s[1] == '\t'
}

func minIntHydrateGo(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = sort.Strings
