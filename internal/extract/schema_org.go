package extract

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// UniversalSchemaOrgResult holds structured metadata, records, and synthesized Markdown
// extracted from `<script type="application/ld+json">` blocks (`schema-org.ts` parity).
type UniversalSchemaOrgResult struct {
	ExtractorID         string           `json:"extractorId,omitempty"`
	PrimaryType         string           `json:"primaryType,omitempty"`
	SchemaType          string           `json:"schemaType,omitempty"`
	Title               string           `json:"title,omitempty"`
	Description         string           `json:"description,omitempty"`
	Author              string           `json:"author,omitempty"`
	PublishedTime       string           `json:"publishedTime,omitempty"`
	ModifiedTime        string           `json:"modifiedTime,omitempty"`
	SiteName            string           `json:"siteName,omitempty"`
	Markdown            string           `json:"markdown,omitempty"`
	HeaderMarkdown      string           `json:"headerMarkdown,omitempty"`
	Structured          map[string]any   `json:"structured,omitempty"`
	Records             []map[string]any `json:"records,omitempty"`
	Returned            int              `json:"returned,omitempty"`
	Total               int              `json:"total,omitempty"`
	Truncated           bool             `json:"truncated,omitempty"`
	NextCursor          string           `json:"nextCursor,omitempty"`
	RawJSONLDForPICheck string           `json:"rawJsonLdForPiCheck,omitempty"`
}

const (
	maxHTMLScanBytesSchemaGo = 2 * 1024 * 1024
	maxPISchemaCharsSchemaGo = 1_572_864
)

var (
	reUnicodeTagJSONEscapeSchemaGo = regexp.MustCompile(`(?i)\\u(?:db40\\{1,16}udc[0-7][0-9a-f]|\{[ \t]{0,4}0{0,8}e00[0-7][0-9a-f][ \t]{0,4}\})`)
	reUnicodeTagHTMLEntitySchemaGo = regexp.MustCompile(`&(?:amp;|#0{0,6}38;?|#[xX]0{0,6}26;?){0,4}#(?:[xX]0{0,8}[eE]00[0-7][0-9a-fA-F]|0{0,8}917(?:50[4-9]|5[1-9]\d|6[0-2]\d|63[01]));?`)
	reRichHTMLTagProbeSchemaGo     = regexp.MustCompile(`(?i)<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|em|code|pre|blockquote|table|a)\b`)
	reSchemaTypeIdentSchemaGo      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{1,63}$`)

	articleTypesSchemaGo = map[string]bool{
		"article":          true,
		"newsarticle":      true,
		"blogposting":      true,
		"techarticle":      true,
		"scholarlyarticle": true,
		"report":           true,
		"liveblogposting":  true,
	}

	eventTypesSchemaGo = map[string]bool{
		"event":            true,
		"businessevent":    true,
		"educationevent":   true,
		"musicevent":       true,
		"socialevent":      true,
		"sportsevent":      true,
		"publicationevent": true,
		"hackathonevent":   true,
	}

	softwareTypesSchemaGo = map[string]bool{
		"softwareapplication": true,
		"webapplication":      true,
		"mobileapplication":   true,
		"videogame":           true,
	}

	localBusinessTypesSchemaGo = map[string]bool{
		"localbusiness":      true,
		"restaurant":         true,
		"store":              true,
		"medicalbusiness":    true,
		"lodgingbusiness":    true,
		"automotivebusiness": true,
		"financialservice":   true,
	}

	organizationTypesSchemaGo = map[string]bool{
		"organization":            true,
		"corporation":             true,
		"ngo":                     true,
		"educationalorganization": true,
		"governmentorganization":  true,
	}

	disallowedHostSuffixesSchemaGo = []string{
		".localhost",
		".local",
		".internal",
		".arpa",
		".intranet",
		".corp",
		".lan",
		".nip.io",
		".sslip.io",
		".xip.io",
		".localtest.me",
		".lvh.me",
		".vcap.me",
		".traefik.me",
		".1u.ms",
		".rebind.network",
	}

	disallowedExactHostsSchemaGo = map[string]bool{
		"localhost":                  true,
		"nip.io":                     true,
		"sslip.io":                   true,
		"xip.io":                     true,
		"localtest.me":               true,
		"lvh.me":                     true,
		"vcap.me":                    true,
		"traefik.me":                 true,
		"1u.ms":                      true,
		"rebind.network":             true,
		"metadata.goog":              true,
		"metadata.google.internal":   true,
		"instance-data.ec2.internal": true,
	}
)

// HasRawOrEncodedUnicodeTag detects literal, JSON-escaped (`\udb40\udc69`, `\u{e0069}`), or
// HTML-entity-encoded (`&#xE0069;`, `&#917609;`, `&amp;#xE0069;`) Unicode Tag smuggling (`U+E0000..U+E007F`)
// in linear O(N) time with zero tree-node budget (`NEW-HIGH-1`).
func HasRawOrEncodedUnicodeTag(raw string) bool {
	if raw == "" {
		return false
	}
	// UTF-8 encoding of U+E0000..U+E007F starts with \xF3\xA0\x80..\xF3\xA0\x81.
	if strings.Contains(raw, "\xf3\xa0") {
		for i := 0; i < len(raw); {
			r, w := utf8.DecodeRuneInString(raw[i:])
			if r >= 0xE0000 && r <= 0xE007F {
				return true
			}
			i += w
		}
	}
	if strings.IndexByte(raw, '\\') >= 0 {
		for _, needle := range []string{"db40", "e00"} {
			pos := 0
			for pos < len(raw) {
				rel := indexFoldASCIIExtract(raw[pos:], needle)
				if rel < 0 {
					break
				}
				hit := pos + rel
				wStart := hit - 32
				if wStart < 0 {
					wStart = 0
				}
				wEnd := hit + 32
				if wEnd > len(raw) {
					wEnd = len(raw)
				}
				if reUnicodeTagJSONEscapeSchemaGo.MatchString(raw[wStart:wEnd]) {
					return true
				}
				pos = hit + len(needle)
			}
		}
	}
	if strings.IndexByte(raw, '&') >= 0 && strings.IndexByte(raw, '#') >= 0 {
		pos := 0
		for pos < len(raw) {
			rel := strings.IndexByte(raw[pos:], '#')
			if rel < 0 {
				break
			}
			hit := pos + rel
			// Skip contiguous `#000038;` / `#x000026;` ampersand entity chains if followed immediately by `#`, or inspect window around terminal `#`.
			wStart := hit - 64
			if wStart < 0 {
				wStart = 0
			}
			wEnd := hit + 32
			if wEnd > len(raw) {
				wEnd = len(raw)
			}
			if reUnicodeTagHTMLEntitySchemaGo.MatchString(raw[wStart:wEnd]) {
				return true
			}
			pos = hit + 1
		}
	}
	return false
}

// DecodeBasicEntities decodes basic named HTML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`, `&apos;`, `&nbsp;`)
// and valid Unicode scalar numeric character references (`1..0x10FFFF` excluding surrogates), leaving invalid/NUL numeric entities intact.
func DecodeBasicEntities(s string) string {
	return decodeBasicEntitiesSchemaGo(s)
}

// IsJSONLDScriptAttr matches `<script type="application/ld+json">` attribute strings (quoted or unquoted,
// with optional MIME parameters such as `;charset=utf-8`) in linear O(N) time (`HIGH-3`).
func IsJSONLDScriptAttr(attrStr string) bool {
	if attrStr == "" || indexFoldASCIIExtract(attrStr, "ld+json") < 0 {
		return false
	}
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
			// Skip stray quote or delimiter safely.
			i++
			continue
		}
		attrName := attrStr[nameStart:i]
		for i < n && isHTMLAttrSpaceSchemaGo(attrStr[i]) {
			i++
		}
		if i >= n || attrStr[i] != '=' {
			continue
		}
		i++ // consume '='
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
				// Unclosed quote cannot form valid quoted type="application/ld+json"
				return false
			}
			val = attrStr[valStart:i]
			i++ // consume closing quote
		} else {
			valStart := i
			for i < n && !isHTMLAttrSpaceSchemaGo(attrStr[i]) && attrStr[i] != '"' && attrStr[i] != '\'' && attrStr[i] != '>' {
				i++
			}
			val = strings.TrimSuffix(attrStr[valStart:i], "/")
			// If unquoted value terminated on a quote or non-boundary other than space/'/'/'>'/EOF, reject.
			if i < n && attrStr[i] != '/' && attrStr[i] != '>' && !isHTMLAttrSpaceSchemaGo(attrStr[i]) {
				if strings.EqualFold(attrName, "type") {
					return false
				}
			}
		}
		if strings.EqualFold(attrName, "type") {
			trimmedVal := trimASCIIWhitespaceSchemaGo(val)
			mime := trimmedVal
			if semi := strings.IndexByte(trimmedVal, ';'); semi >= 0 {
				mime = trimASCIIWhitespaceSchemaGo(trimmedVal[:semi])
			}
			if strings.EqualFold(mime, "application/ld+json") {
				return true
			}
		}
	}
	return false
}

// ExtractJSONLDObjects extracts flattened JSON-LD objects (including `@graph` entries) from
// `<script type="application/ld+json">` blocks in linear O(N) time (`H1`).
func ExtractJSONLDObjects(rawHTML string, maxEntities int) []map[string]any {
	if rawHTML == "" || indexFoldASCIIExtract(rawHTML, "ld+json") < 0 {
		return []map[string]any{}
	}
	capCount := maxEntities
	if capCount <= 0 {
		capCount = 100
	}
	if capCount > 250 {
		capCount = 250
	}
	results := make([]map[string]any, 0, 8)
	var pushItem func(item any, depth int)
	pushItem = func(item any, depth int) {
		if item == nil || depth > 16 || len(results) >= capCount {
			return
		}
		switch v := item.(type) {
		case []any:
			for _, el := range v {
				if len(results) >= capCount {
					break
				}
				pushItem(el, depth+1)
			}
		case map[string]any:
			results = append(results, v)
			if graph, ok := v["@graph"].([]any); ok {
				for _, g := range graph {
					if len(results) >= capCount {
						break
					}
					pushItem(g, depth+1)
				}
			}
		}
	}

	scanScriptBlocksLinearSchemaGo(rawHTML, maxHTMLScanBytesSchemaGo, func(attrStr, inner string) bool {
		if len(results) >= capCount {
			return false
		}
		if !IsJSONLDScriptAttr(attrStr) {
			return true
		}
		raw := strings.TrimSpace(inner)
		if raw == "" || len(raw) > maxHTMLScanBytesSchemaGo {
			return true
		}
		parsed := parseJSONValueSchemaGo(raw)
		if parsed == nil && strings.IndexByte(raw, '&') >= 0 {
			parsed = parseJSONValueSchemaGo(decodeBasicEntitiesSchemaGo(raw))
		}
		pushItem(parsed, 0)
		return len(results) < capCount
	})

	return results
}

// StripInvisibleSchemaChars strips ANSI CSI sequences, ASCII/C1 control codes, soft hyphens,
// zero-width characters, Bidi overrides, line/paragraph separators, Unicode Tags (`U+E0000..U+E007F`),
// and variation selectors (`U+E0100..U+E01EF`).
func StripInvisibleSchemaChars(s string) string {
	if s == "" {
		return ""
	}
	// Fast pure-printable-ASCII path.
	pureASCII := true
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !((b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t') {
			pureASCII = false
			break
		}
	}
	if pureASCII {
		return s
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	var sb strings.Builder
	sb.Grow(len(s))
	n := len(s)
	for i := 0; i < n; {
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
		if (r >= 0x007F && r <= 0x009F) ||
			r == 0x00AD || r == 0x061C || r == 0x180E ||
			(r >= 0x200B && r <= 0x200F) ||
			(r >= 0x2028 && r <= 0x202F) ||
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

// SanitizeSchemaPlainField sanitizes a single-line Schema.org / hydration metadata scalar,
// stripping invisible characters before and after HTML entity decoding, stripping HTML tags,
// neutralizing unsafe Markdown links, and escaping `<` and `>`.
func SanitizeSchemaPlainField(raw any, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 512
	}
	str, ok := scalarStringOrNumberSchemaGo(raw)
	if !ok || str == "" {
		return ""
	}
	pre := StripInvisibleSchemaChars(str)
	tagStripped := stripHTMLTagsQuoteAwareSchemaGo(pre, " ", maxHTMLScanBytesSchemaGo)
	decoded := tagStripped
	if strings.IndexByte(tagStripped, '&') >= 0 {
		decoded = decodeBasicEntitiesSchemaGo(tagStripped)
	}
	// Strip again after entity decoding so `&#xE0069;` / `&#x202E;` never survive.
	clean := collapseWhitespaceSchemaGo(StripInvisibleSchemaChars(decoded))
	if clean == "" {
		return ""
	}
	clean = neutralizeAllUnsafeMarkdownLinksLinearGo(clean)
	clean = strings.ReplaceAll(clean, "<", "&lt;")
	clean = strings.ReplaceAll(clean, ">", "&gt;")
	if utf16UnitsLenSchemaGo(clean) > maxLen {
		clean = strings.TrimSpace(sliceRunesMax(clean, maxLen))
	}
	return clean
}

// SanitizeSchemaRichMarkdown converts HTML or plain Schema.org body text into sanitized Markdown.
func SanitizeSchemaRichMarkdown(raw any, baseURL string, htmlToMD func(frag, base string) (string, []string), maxChars int) string {
	if maxChars <= 0 {
		maxChars = 32_000
	}
	rawStr, ok := raw.(string)
	if !ok || rawStr == "" {
		return ""
	}
	pre := strings.TrimSpace(StripInvisibleSchemaChars(rawStr))
	if pre == "" {
		return ""
	}
	hasHTML := strings.IndexByte(pre, '<') >= 0 && reRichHTMLTagProbeSchemaGo.MatchString(pre)
	var md string
	if hasHTML {
		if htmlToMD != nil {
			md, _ = htmlToMD(pre, baseURL)
		} else {
			var baseU *url.URL
			if baseURL != "" {
				baseU, _ = url.Parse(baseURL)
			}
			md = htmlFragmentToMarkdown(pre, baseU)
		}
	} else {
		md = decodeBasicEntitiesSchemaGo(stripHTMLTagsQuoteAwareSchemaGo(pre, " ", maxHTMLScanBytesSchemaGo))
	}
	md = StripInvisibleSchemaChars(md)
	md = neutralizeAllUnsafeMarkdownLinksLinearGo(md)
	md = escapeDangerousAngleBracketsSchemaGo(md)
	md = collapseBlankLinesMarkdownSchemaGo(md)
	if utf16UnitsLenSchemaGo(md) > maxChars {
		md = strings.TrimSpace(sliceRunesMax(md, maxChars))
	}
	return md
}

// PercentEncodeUnsafeRecordURLChars percent-encodes characters that can break Markdown link syntax
// or inject raw tags (`(`, `)`, `[`, `]`, `<`, `>`, `\`, and ASCII whitespace).
func PercentEncodeUnsafeRecordURLChars(urlStr string) string {
	needsEncode := false
	for i := 0; i < len(urlStr); i++ {
		switch urlStr[i] {
		case '(', ')', '[', ']', '<', '>', '\\', ' ', '\t', '\r', '\n':
			needsEncode = true
		}
		if needsEncode {
			break
		}
	}
	if !needsEncode {
		return urlStr
	}
	var sb strings.Builder
	sb.Grow(len(urlStr) + 16)
	for i := 0; i < len(urlStr); i++ {
		switch urlStr[i] {
		case '(':
			sb.WriteString("%28")
		case ')':
			sb.WriteString("%29")
		case '[':
			sb.WriteString("%5B")
		case ']':
			sb.WriteString("%5D")
		case '<':
			sb.WriteString("%3C")
		case '>':
			sb.WriteString("%3E")
		case '\\':
			sb.WriteString("%5C")
		case ' ':
			sb.WriteString("%20")
		case '\t':
			sb.WriteString("%09")
		case '\r':
			sb.WriteString("%0D")
		case '\n':
			sb.WriteString("%0A")
		default:
			sb.WriteByte(urlStr[i])
		}
	}
	return sb.String()
}

// SanitizeSchemaHTTPSURL resolves `raw` against `baseURL`, enforces public `https://` on port 443
// without credentials or private/loopback/rebinding hosts, and percent-encodes unsafe Markdown link characters.
func SanitizeSchemaHTTPSURL(raw any, baseURL string) string {
	rawStr, ok := raw.(string)
	if !ok {
		return ""
	}
	cleaned := strings.TrimSpace(StripInvisibleSchemaChars(rawStr))
	if cleaned == "" || hasDisallowedURLSchemePrefixSchemaGo(cleaned) {
		return ""
	}
	if strings.HasPrefix(cleaned, "\\") || hasBackslashInAuthoritySchemaGo(cleaned) {
		return ""
	}
	// Pre-encode interior spaces/tabs so `url.Parse` matches WHATWG URL resolution on spaces in paths/queries.
	preEncoded := preEncodeWhitespaceForURLParseSchemaGo(cleaned)
	var resolved *url.URL
	if baseURL != "" {
		baseParsed, err := url.Parse(strings.TrimSpace(baseURL))
		if err != nil || baseParsed.Scheme == "" || baseParsed.Host == "" {
			u, err2 := url.Parse(preEncoded)
			if err2 != nil {
				return ""
			}
			resolved = u
		} else {
			ref, err2 := url.Parse(preEncoded)
			if err2 != nil {
				return ""
			}
			resolved = baseParsed.ResolveReference(ref)
		}
	} else {
		u, err := url.Parse(preEncoded)
		if err != nil {
			return ""
		}
		resolved = u
	}
	checked, ok := normalizeAndValidatePublicHTTPSURLSchemaGo(resolved, "")
	if !ok {
		return ""
	}
	return PercentEncodeUnsafeRecordURLChars(checked)
}

// ExtractUniversalSchemaOrg extracts rich Schema.org JSON-LD entities from HTML in linear O(N) time.
// Skips `JobPosting`, standalone `Product`, and `BreadcrumbList` so specialized extractors remain authoritative,
// and never emits `records: []` on empty/unmatched trees.
func ExtractUniversalSchemaOrg(rawHTML, baseURL string, htmlToMD func(frag, base string) (string, []string)) *UniversalSchemaOrgResult {
	if rawHTML == "" || indexFoldASCIIExtract(rawHTML, "ld+json") < 0 {
		return nil
	}
	entities := ExtractJSONLDObjects(rawHTML, 100)
	if len(entities) == 0 {
		return nil
	}

	var fallbackItemList *UniversalSchemaOrgResult
	var fallbackDomain *UniversalSchemaOrgResult
	var fallbackArticle *UniversalSchemaOrgResult
	var fallbackOrg *UniversalSchemaOrgResult

	var matched *UniversalSchemaOrgResult

	for _, entity := range entities {
		types := normalizeSchemaTypesSchemaGo(entity["@type"])
		if len(types) == 0 {
			continue
		}
		lowerSet := make(map[string]bool, len(types))
		for _, t := range types {
			lowerSet[strings.ToLower(t)] = true
		}
		if lowerSet["jobposting"] || lowerSet["product"] || lowerSet["breadcrumblist"] {
			continue
		}

		if lowerSet["qapage"] {
			if qa := extractQAOrForumThreadSchemaGo(entity, "QAPage", baseURL, htmlToMD); qa != nil {
				matched = qa
				break
			}
		}
		if lowerSet["discussionforumposting"] {
			if forum := extractQAOrForumThreadSchemaGo(entity, "DiscussionForumPosting", baseURL, htmlToMD); forum != nil {
				matched = forum
				break
			}
		}
		if lowerSet["faqpage"] {
			if faq := extractFAQPageSchemaGo(entity, baseURL, htmlToMD); faq != nil {
				matched = faq
				break
			}
		}
		if lowerSet["howto"] {
			if ht := extractHowToSchemaGo(entity, baseURL, htmlToMD); ht != nil {
				matched = ht
				break
			}
		}

		if fallbackItemList == nil && (lowerSet["itemlist"] || lowerSet["collectionpage"] || lowerSet["searchresultspage"]) {
			matchedType := "ItemList"
			for _, t := range types {
				lt := strings.ToLower(t)
				if lt == "itemlist" || lt == "collectionpage" || lt == "searchresultspage" {
					matchedType = t
					break
				}
			}
			fallbackItemList = extractItemListSchemaGo(entity, matchedType, baseURL)
		}

		if fallbackDomain == nil {
			if evType := findMatchingSchemaTypeSchemaGo(types, eventTypesSchemaGo); evType != "" {
				fallbackDomain = extractDomainEntitySchemaGo(entity, evType, "event", baseURL)
			}
			if fallbackDomain == nil {
				if swType := findMatchingSchemaTypeSchemaGo(types, softwareTypesSchemaGo); swType != "" {
					fallbackDomain = extractDomainEntitySchemaGo(entity, swType, "software", baseURL)
				}
			}
			if fallbackDomain == nil && lowerSet["dataset"] {
				fallbackDomain = extractDomainEntitySchemaGo(entity, "Dataset", "dataset", baseURL)
			}
			if fallbackDomain == nil && lowerSet["recipe"] {
				fallbackDomain = extractDomainEntitySchemaGo(entity, "Recipe", "recipe", baseURL)
			}
			if fallbackDomain == nil && lowerSet["course"] {
				fallbackDomain = extractDomainEntitySchemaGo(entity, "Course", "course", baseURL)
			}
			if fallbackDomain == nil && lowerSet["videoobject"] {
				fallbackDomain = extractDomainEntitySchemaGo(entity, "VideoObject", "video", baseURL)
			}
			if fallbackDomain == nil {
				if lbType := findMatchingSchemaTypeSchemaGo(types, localBusinessTypesSchemaGo); lbType != "" {
					fallbackDomain = extractDomainEntitySchemaGo(entity, lbType, "localbusiness", baseURL)
				}
			}
		}

		if fallbackArticle == nil {
			if artType := findMatchingSchemaTypeSchemaGo(types, articleTypesSchemaGo); artType != "" {
				fallbackArticle = extractArticleSchemaGo(entity, artType, baseURL, htmlToMD)
			}
		}

		if fallbackOrg == nil {
			if orgType := findMatchingSchemaTypeSchemaGo(types, organizationTypesSchemaGo); orgType != "" {
				fallbackOrg = extractDomainEntitySchemaGo(entity, orgType, "organization", baseURL)
			}
		}
	}

	if matched == nil {
		switch {
		case fallbackItemList != nil:
			matched = fallbackItemList
		case fallbackDomain != nil:
			matched = fallbackDomain
		case fallbackArticle != nil:
			matched = fallbackArticle
		case fallbackOrg != nil:
			matched = fallbackOrg
		}
	}
	if matched == nil {
		return nil
	}
	if matched.ExtractorID == "" {
		matched.ExtractorID = "schema-org"
	}
	if matched.PrimaryType == "" {
		matched.PrimaryType = matched.SchemaType
	}
	if matched.SchemaType == "" {
		matched.SchemaType = matched.PrimaryType
	}
	if matched.Total > matched.Returned && matched.Returned > 0 {
		matched.Truncated = true
	}
	matched.RawJSONLDForPICheck = InspectRawSchemaOrgJSONLD(rawHTML)
	return matched
}

// InspectRawSchemaOrgJSONLD walks all `<script type="application/ld+json">` string leaves up to depth 20
// and 1.5 MiB for prompt-injection screening (`checkPromptInjection: true`), preserving smuggled Unicode Tags (`HIGH-3`).
func InspectRawSchemaOrgJSONLD(rawHTML string) string {
	if rawHTML == "" || indexFoldASCIIExtract(rawHTML, "ld+json") < 0 {
		return ""
	}
	var chunks []string
	totalChars := 0
	sawUnicodeTag := false
	totalVisited := 0

	scanScriptBlocksLinearSchemaGo(rawHTML, maxHTMLScanBytesSchemaGo, func(attrStr, inner string) bool {
		if !IsJSONLDScriptAttr(attrStr) {
			return true
		}
		raw := strings.TrimSpace(inner)
		if raw == "" || len(raw) > maxHTMLScanBytesSchemaGo {
			return true
		}
		if !sawUnicodeTag && HasRawOrEncodedUnicodeTag(raw) {
			sawUnicodeTag = true
		}
		parsed := parseJSONValueSchemaGo(raw)
		if parsed == nil && strings.IndexByte(raw, '&') >= 0 {
			parsed = parseJSONValueSchemaGo(decodeBasicEntitiesSchemaGo(raw))
		}
		scriptVisited := 0

		var walkStrings func(val any, depth int)
		walkStrings = func(val any, depth int) {
			if val == nil || depth > 20 || scriptVisited > 100_000 || totalVisited > 250_000 {
				return
			}
			switch v := val.(type) {
			case string:
				if v == "" {
					return
				}
				scriptVisited++
				totalVisited++
				decoded := v
				if strings.IndexByte(v, '&') >= 0 {
					decoded = decodeBasicEntitiesSchemaGo(v)
				}
				if !sawUnicodeTag && HasRawOrEncodedUnicodeTag(decoded) {
					sawUnicodeTag = true
				}
				if totalChars < maxPISchemaCharsSchemaGo {
					rem := maxPISchemaCharsSchemaGo - totalChars
					slice := sliceUTF8CleanBytesSchemaGo(decoded, rem)
					if slice != "" {
						chunks = append(chunks, slice)
						totalChars += len(slice)
					}
				}
			case []any:
				if len(v) == 0 {
					return // Never charge budget for empty arrays (`[[],[],...]`, `NEW-HIGH-1`)
				}
				scriptVisited++
				totalVisited++
				for _, item := range v {
					if scriptVisited > 100_000 || totalVisited > 250_000 {
						break
					}
					switch item.(type) {
					case string, []any, map[string]any:
						walkStrings(item, depth+1)
					}
				}
			case map[string]any:
				if len(v) == 0 {
					return // Never charge budget for empty `{}`
				}
				scriptVisited++
				totalVisited++
				keys := sortedMapKeysSchemaGo(v)
				for _, k := range keys {
					if scriptVisited > 100_000 || totalVisited > 250_000 {
						break
					}
					child := v[k]
					switch child.(type) {
					case string, []any, map[string]any:
						walkStrings(child, depth+1)
					}
				}
			}
		}

		walkStrings(parsed, 0)
		return true
	})

	if sawUnicodeTag {
		chunks = append(chunks, "\U000E0069")
	}
	return strings.Join(chunks, "\n")
}

// --- Unexported Schema.org extractors & linear HTML/URL helpers (all suffixed with SchemaGo) ---

func findMatchingSchemaTypeSchemaGo(types []string, allowedLower map[string]bool) string {
	for _, t := range types {
		if allowedLower[strings.ToLower(t)] {
			return t
		}
	}
	return ""
}

func normalizeSchemaTypesSchemaGo(rawType any) []string {
	var out []string
	pushOne := func(v any) {
		s, ok := v.(string)
		if !ok {
			return
		}
		trimmed := strings.TrimSpace(s)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "https://schema.org/") {
			trimmed = strings.TrimSpace(trimmed[len("https://schema.org/"):])
		} else if strings.HasPrefix(lower, "http://schema.org/") {
			trimmed = strings.TrimSpace(trimmed[len("http://schema.org/"):])
		}
		if trimmed != "" && reSchemaTypeIdentSchemaGo.MatchString(trimmed) {
			out = append(out, trimmed)
		}
	}
	if arr, ok := rawType.([]any); ok {
		limit := len(arr)
		if limit > 8 {
			limit = 8
		}
		for i := 0; i < limit; i++ {
			pushOne(arr[i])
		}
	} else {
		pushOne(rawType)
	}
	return out
}

func extractAuthorNameSchemaGo(rawAuthor any) string {
	if rawAuthor == nil {
		return ""
	}
	switch a := rawAuthor.(type) {
	case string:
		return SanitizeSchemaPlainField(a, 180)
	case []any:
		limit := len(a)
		if limit > 5 {
			limit = 5
		}
		var names []string
		for i := 0; i < limit; i++ {
			if n := extractAuthorNameSchemaGo(a[i]); n != "" {
				names = append(names, n)
			}
		}
		return strings.Join(names, ", ")
	case map[string]any:
		cand := a["name"]
		if cand == nil {
			cand = a["alternateName"]
		}
		return SanitizeSchemaPlainField(cand, 180)
	default:
		return ""
	}
}

func extractPublisherNameSchemaGo(rawPub any) string {
	if rawPub == nil {
		return ""
	}
	switch p := rawPub.(type) {
	case string:
		return SanitizeSchemaPlainField(p, 180)
	case map[string]any:
		return SanitizeSchemaPlainField(p["name"], 180)
	default:
		return ""
	}
}

func formatSafeMarkdownLinkSchemaGo(label, safeHTTPSURL string) string {
	safeLabel := strings.ReplaceAll(label, `\`, `\\`)
	safeLabel = strings.ReplaceAll(safeLabel, "[", `\[`)
	safeLabel = strings.ReplaceAll(safeLabel, "]", `\]`)
	if safeHTTPSURL == "" {
		return safeLabel
	}
	escapedURL := PercentEncodeUnsafeRecordURLChars(safeHTTPSURL)
	return "[" + safeLabel + "](" + escapedURL + ")"
}

func firstNonNilSchemaGo(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

func extractFAQPageSchemaGo(obj map[string]any, baseURL string, htmlToMD func(frag, base string) (string, []string)) *UniversalSchemaOrgResult {
	rawMain := firstNonNilSchemaGo(obj["mainEntity"], obj["hasPart"])
	var items []any
	switch m := rawMain.(type) {
	case []any:
		items = m
	case map[string]any:
		items = []any{m}
	}
	if len(items) == 0 {
		return nil
	}

	limit := len(items)
	if limit > 100 {
		limit = 100
	}
	var records []map[string]any
	var sections []string

	for i := 0; i < limit; i++ {
		qObj, ok := items[i].(map[string]any)
		if !ok {
			continue
		}
		question := SanitizeSchemaPlainField(firstNonNilSchemaGo(qObj["name"], qObj["headline"], qObj["text"]), 400)
		ansRaw := qObj["acceptedAnswer"]
		if ansRaw == nil {
			if sArr, isArr := qObj["suggestedAnswer"].([]any); isArr && len(sArr) > 0 {
				ansRaw = sArr[0]
			} else {
				ansRaw = qObj["suggestedAnswer"]
			}
		}
		ansObj, _ := ansRaw.(map[string]any)
		var ansSource any
		if ansObj != nil {
			ansSource = firstNonNilSchemaGo(ansObj["text"], ansObj["articleBody"])
		}
		if ansSource == nil {
			ansSource = qObj["answer"]
		}
		answerMD := SanitizeSchemaRichMarkdown(ansSource, baseURL, htmlToMD, 4_000)
		answerPlain := SanitizeSchemaPlainField(ansSource, 2_000)
		if question == "" || answerMD == "" || answerPlain == "" {
			continue
		}

		var urlSource any = qObj["url"]
		if urlSource == nil && ansObj != nil {
			urlSource = ansObj["url"]
		}
		safeURL := SanitizeSchemaHTTPSURL(urlSource, baseURL)
		rec := map[string]any{
			"question": question,
			"answer":   answerPlain,
		}
		if safeURL != "" {
			rec["url"] = safeURL
		}
		records = append(records, rec)
		sections = append(sections, "## "+question+"\n\n"+answerMD)
	}

	if len(records) == 0 {
		return nil
	}
	title := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["name"], obj["headline"]), 300)
	description := SanitizeSchemaPlainField(obj["description"], 1_000)
	var mdParts []string
	if title != "" {
		mdParts = append(mdParts, "# "+title)
	}
	mdParts = append(mdParts, sections...)

	structured := map[string]any{
		"schemaType":    "FAQPage",
		"questionCount": len(records),
	}
	if title != "" {
		structured["title"] = title
	}

	return &UniversalSchemaOrgResult{
		ExtractorID: "schema-org",
		PrimaryType: "FAQPage",
		SchemaType:  "FAQPage",
		Title:       title,
		Description: description,
		Markdown:    strings.Join(mdParts, "\n\n"),
		Structured:  structured,
		Records:     records,
		Returned:    len(records),
		Total:       len(records),
	}
}

func extractQAOrForumThreadSchemaGo(obj map[string]any, schemaType, baseURL string, htmlToMD func(frag, base string) (string, []string)) *UniversalSchemaOrgResult {
	mainObj := obj
	if schemaType == "QAPage" {
		if me, ok := obj["mainEntity"].(map[string]any); ok {
			mainObj = me
		}
	}

	title := SanitizeSchemaPlainField(firstNonNilSchemaGo(mainObj["headline"], mainObj["name"], obj["name"], obj["headline"]), 350)
	opBody := SanitizeSchemaRichMarkdown(firstNonNilSchemaGo(mainObj["text"], mainObj["articleBody"], mainObj["description"]), baseURL, htmlToMD, 16_000)
	opAuthor := extractAuthorNameSchemaGo(firstNonNilSchemaGo(mainObj["author"], obj["author"]))
	publishedTime := SanitizeSchemaPlainField(firstNonNilSchemaGo(mainObj["datePublished"], obj["datePublished"]), 64)
	modifiedTime := SanitizeSchemaPlainField(firstNonNilSchemaGo(mainObj["dateModified"], obj["dateModified"]), 64)

	var records []map[string]any
	var replySections []string

	pushReply := func(rawReply any, accepted bool) {
		if len(records) >= 100 {
			return
		}
		r, ok := rawReply.(map[string]any)
		if !ok {
			return
		}
		txtSource := firstNonNilSchemaGo(r["text"], r["articleBody"], r["description"])
		textMD := SanitizeSchemaRichMarkdown(txtSource, baseURL, htmlToMD, 8_000)
		textPlain := SanitizeSchemaPlainField(txtSource, 2_000)
		if textMD == "" || textPlain == "" {
			return
		}
		author := extractAuthorNameSchemaGo(r["author"])
		created := SanitizeSchemaPlainField(firstNonNilSchemaGo(r["datePublished"], r["dateCreated"]), 64)
		upvotes, hasUpvotes := finiteNumberSchemaGo(r["upvoteCount"])
		safeURL := SanitizeSchemaHTTPSURL(r["url"], baseURL)

		role := "reply"
		if accepted {
			role = "accepted_answer"
		}
		rec := map[string]any{
			"role": role,
			"text": textPlain,
		}
		if author != "" {
			rec["author"] = author
		}
		if created != "" {
			rec["publishedAt"] = created
		}
		if hasUpvotes {
			if math.Trunc(upvotes) == upvotes {
				rec["upvoteCount"] = int64(upvotes)
			} else {
				rec["upvoteCount"] = upvotes
			}
		}
		if safeURL != "" {
			rec["url"] = safeURL
		}
		records = append(records, rec)

		var metaParts []string
		if accepted {
			metaParts = append(metaParts, "**Accepted Answer**")
		} else {
			metaParts = append(metaParts, "**Reply**")
		}
		if author != "" {
			metaParts = append(metaParts, "by "+author)
		}
		if created != "" {
			metaParts = append(metaParts, "("+created+")")
		}
		if hasUpvotes {
			metaParts = append(metaParts, fmt.Sprintf("· %v upvotes", rec["upvoteCount"]))
		}
		replySections = append(replySections, "### "+strings.Join(metaParts, " ")+"\n\n"+textMD)
	}

	if mainObj["acceptedAnswer"] != nil {
		pushReply(mainObj["acceptedAnswer"], true)
	}
	if sArr, ok := mainObj["suggestedAnswer"].([]any); ok {
		lim := len(sArr)
		if lim > 50 {
			lim = 50
		}
		for i := 0; i < lim; i++ {
			pushReply(sArr[i], false)
		}
	} else if mainObj["suggestedAnswer"] != nil {
		pushReply(mainObj["suggestedAnswer"], false)
	}

	rawComments := firstNonNilSchemaGo(mainObj["comment"], obj["comment"])
	if cArr, ok := rawComments.([]any); ok {
		lim := len(cArr)
		if lim > 80 {
			lim = 80
		}
		for i := 0; i < lim; i++ {
			pushReply(cArr[i], false)
		}
	} else if rawComments != nil {
		pushReply(rawComments, false)
	}

	if title == "" && opBody == "" && len(records) == 0 {
		return nil
	}
	if opBody == "" && len(records) == 0 {
		return nil
	}

	var opMetaBits []string
	if opAuthor != "" {
		opMetaBits = append(opMetaBits, "**Author**: "+opAuthor)
	}
	if publishedTime != "" {
		opMetaBits = append(opMetaBits, "**Posted**: "+publishedTime)
	}
	opMeta := strings.Join(opMetaBits, " · ")

	var mdParts []string
	if title != "" {
		mdParts = append(mdParts, "# "+title)
	}
	if opMeta != "" {
		mdParts = append(mdParts, opMeta)
	}
	if opBody != "" {
		mdParts = append(mdParts, opBody)
	}
	if len(replySections) > 0 {
		mdParts = append(mdParts, "## Replies")
		mdParts = append(mdParts, replySections...)
	}

	structured := map[string]any{
		"schemaType": schemaType,
		"replyCount": len(records),
	}
	if title != "" {
		structured["title"] = title
	}
	if opAuthor != "" {
		structured["author"] = opAuthor
	}
	if publishedTime != "" {
		structured["datePublished"] = publishedTime
	}

	out := &UniversalSchemaOrgResult{
		ExtractorID:   "schema-org",
		PrimaryType:   schemaType,
		SchemaType:    schemaType,
		Title:         title,
		Author:        opAuthor,
		PublishedTime: publishedTime,
		ModifiedTime:  modifiedTime,
		Markdown:      strings.Join(mdParts, "\n\n"),
		Structured:    structured,
	}
	if len(records) > 0 {
		out.Records = records
		out.Returned = len(records)
		out.Total = len(records)
	}
	return out
}

func extractHowToSchemaGo(obj map[string]any, baseURL string, htmlToMD func(frag, base string) (string, []string)) *UniversalSchemaOrgResult {
	title := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["name"], obj["headline"]), 350)
	description := SanitizeSchemaPlainField(obj["description"], 1_200)
	totalTime := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["totalTime"], obj["performTime"]), 60)

	collectNamedList := func(raw any) []string {
		arr, ok := raw.([]any)
		if !ok {
			if m, isM := raw.(map[string]any); isM {
				arr = []any{m}
			} else if s, isS := raw.(string); isS {
				arr = []any{s}
			}
		}
		var out []string
		for i := 0; i < len(arr) && len(out) < 40; i++ {
			switch el := arr[i].(type) {
			case string:
				if v := SanitizeSchemaPlainField(el, 180); v != "" {
					out = append(out, v)
				}
			case map[string]any:
				if v := SanitizeSchemaPlainField(firstNonNilSchemaGo(el["name"], el["text"]), 180); v != "" {
					out = append(out, v)
				}
			}
		}
		return out
	}

	supplies := collectNamedList(obj["supply"])
	tools := collectNamedList(obj["tool"])

	var stepRecords []map[string]any
	var stepLines []string
	var pushStep func(rawStep any)
	pushStep = func(rawStep any) {
		if len(stepRecords) >= 100 || rawStep == nil {
			return
		}
		switch st := rawStep.(type) {
		case string:
			txt := SanitizeSchemaPlainField(st, 1_500)
			if txt == "" {
				return
			}
			pos := len(stepRecords) + 1
			stepRecords = append(stepRecords, map[string]any{
				"position": pos,
				"text":     txt,
			})
			stepLines = append(stepLines, fmt.Sprintf("%d. %s", pos, txt))
		case []any:
			for _, sub := range st {
				pushStep(sub)
			}
		case map[string]any:
			if subItems, ok := st["itemListElement"].([]any); ok && len(subItems) > 0 {
				// HowToSection containing nested HowToSteps, or HowToStep with HowToDirections.
				hasSubStep := false
				for _, sub := range subItems {
					if sm, isM := sub.(map[string]any); isM {
						if sm["text"] != nil || sm["itemListElement"] != nil {
							hasSubStep = true
							break
						}
					}
				}
				if hasSubStep && st["text"] == nil {
					for _, sub := range subItems {
						pushStep(sub)
					}
					return
				}
			}
			stepName := SanitizeSchemaPlainField(st["name"], 240)
			stepBody := SanitizeSchemaRichMarkdown(firstNonNilSchemaGo(st["text"], st["description"]), baseURL, htmlToMD, 4_000)
			stepPlain := SanitizeSchemaPlainField(firstNonNilSchemaGo(st["text"], st["description"], st["name"]), 1_500)
			if stepPlain == "" && stepName == "" {
				return
			}
			pos := len(stepRecords) + 1
			safeURL := SanitizeSchemaHTTPSURL(st["url"], baseURL)
			rec := map[string]any{
				"position": pos,
			}
			if stepName != "" {
				rec["title"] = stepName
			}
			if stepPlain != "" {
				rec["text"] = stepPlain
			}
			if safeURL != "" {
				rec["url"] = safeURL
			}
			stepRecords = append(stepRecords, rec)
			body := stepBody
			if body == "" {
				body = stepPlain
			}
			if stepName != "" && stepName != stepPlain {
				stepLines = append(stepLines, fmt.Sprintf("%d. **%s** — %s", pos, stepName, strings.ReplaceAll(body, "\n", " ")))
			} else {
				stepLines = append(stepLines, fmt.Sprintf("%d. %s", pos, strings.ReplaceAll(body, "\n", " ")))
			}
		}
	}

	pushStep(firstNonNilSchemaGo(obj["step"], obj["steps"]))

	if title == "" && len(stepRecords) == 0 {
		return nil
	}
	if len(stepRecords) == 0 && description == "" {
		return nil
	}

	var bullets []string
	structured := map[string]any{
		"schemaType": "HowTo",
	}
	if title != "" {
		structured["name"] = title
	}
	if description != "" {
		structured["description"] = description
	}
	if totalTime != "" {
		structured["totalTime"] = totalTime
		bullets = append(bullets, "- **Total Time**: "+totalTime)
	}
	if len(supplies) > 0 {
		structured["supply"] = supplies
		bullets = append(bullets, "- **Supplies**: "+strings.Join(supplies, ", "))
	}
	if len(tools) > 0 {
		structured["tool"] = tools
		bullets = append(bullets, "- **Tools**: "+strings.Join(tools, ", "))
	}
	if len(stepRecords) > 0 {
		structured["stepCount"] = len(stepRecords)
	}

	headerMD := strings.Join(bullets, "\n")
	var mdBlocks []string
	if title != "" {
		mdBlocks = append(mdBlocks, "# "+title)
	}
	if headerMD != "" {
		mdBlocks = append(mdBlocks, headerMD)
	}
	if description != "" {
		mdBlocks = append(mdBlocks, description)
	}
	if len(stepLines) > 0 {
		mdBlocks = append(mdBlocks, "## Steps\n\n"+strings.Join(stepLines, "\n"))
	}

	out := &UniversalSchemaOrgResult{
		ExtractorID:    "schema-org",
		PrimaryType:    "HowTo",
		SchemaType:     "HowTo",
		Title:          title,
		Description:    description,
		HeaderMarkdown: headerMD,
		Markdown:       strings.Join(mdBlocks, "\n\n"),
		Structured:     structured,
	}
	if len(stepRecords) > 0 {
		out.Records = stepRecords
		out.Returned = len(stepRecords)
		out.Total = len(stepRecords)
	}
	return out
}

func extractItemListSchemaGo(obj map[string]any, schemaType, baseURL string) *UniversalSchemaOrgResult {
	var listContainer map[string]any
	if _, ok := obj["itemListElement"].([]any); ok {
		listContainer = obj
	} else if me, ok := obj["mainEntity"].(map[string]any); ok {
		if _, ok2 := me["itemListElement"].([]any); ok2 {
			listContainer = me
		}
	}
	if listContainer == nil {
		return nil
	}
	rawElements, ok := listContainer["itemListElement"].([]any)
	if !ok || len(rawElements) == 0 {
		return nil
	}

	limit := len(rawElements)
	if limit > 250 {
		limit = 250
	}

	var records []map[string]any
	var tableRows [][]string
	anySummaryOrPrice := false

	for i := 0; i < limit; i++ {
		rawEl := rawElements[i]
		if rawEl == nil {
			continue
		}
		if s, isStr := rawEl.(string); isStr {
			if asURL := SanitizeSchemaHTTPSURL(s, baseURL); asURL != "" {
				posStr := strconv.Itoa(i + 1)
				records = append(records, map[string]any{
					"position": i + 1,
					"url":      asURL,
				})
				tableRows = append(tableRows, []string{posStr, asURL, "-"})
			}
			continue
		}
		elObj, isMap := rawEl.(map[string]any)
		if !isMap {
			continue
		}
		inner := elObj
		if itemMap, okItem := elObj["item"].(map[string]any); okItem {
			inner = itemMap
		}
		var itemStringFallback any
		if itemStr, okStr := elObj["item"].(string); okStr {
			itemStringFallback = itemStr
		}
		itemURL := SanitizeSchemaHTTPSURL(firstNonNilSchemaGo(inner["url"], inner["@id"], elObj["url"], itemStringFallback), baseURL)
		name := SanitizeSchemaPlainField(firstNonNilSchemaGo(inner["name"], inner["headline"], elObj["name"]), 240)
		if name == "" && itemURL == "" {
			continue
		}

		desc := SanitizeSchemaPlainField(firstNonNilSchemaGo(inner["description"], elObj["description"]), 300)
		var offers map[string]any
		if oMap, okO := inner["offers"].(map[string]any); okO {
			offers = oMap
		} else if oArr, okA := inner["offers"].([]any); okA && len(oArr) > 0 {
			offers, _ = oArr[0].(map[string]any)
		}
		rawPrice := ""
		rawCurrency := ""
		if offers != nil {
			rawPrice = SanitizeSchemaPlainField(firstNonNilSchemaGo(offers["price"], offers["lowPrice"]), 40)
			rawCurrency = SanitizeSchemaPlainField(offers["priceCurrency"], 12)
		}
		priceStr := ""
		if rawPrice != "" {
			if rawCurrency != "" {
				priceStr = rawPrice + " " + rawCurrency
			} else {
				priceStr = rawPrice
			}
		}
		if desc != "" || priceStr != "" {
			anySummaryOrPrice = true
		}

		pos := len(records) + 1
		if pNum, hasP := finiteNumberSchemaGo(elObj["position"]); hasP && pNum > 0 {
			pos = int(math.Floor(pNum))
		}
		rec := map[string]any{
			"position": pos,
		}
		if name != "" {
			rec["title"] = name
		}
		if itemURL != "" {
			rec["url"] = itemURL
		}
		if priceStr != "" {
			rec["price"] = priceStr
		}
		if desc != "" {
			rec["summary"] = desc
		}
		records = append(records, rec)

		linkCell := "-"
		if name != "" {
			linkCell = formatSafeMarkdownLinkSchemaGo(name, itemURL)
		} else if itemURL != "" {
			linkCell = itemURL
		}
		var detailBits []string
		if priceStr != "" {
			detailBits = append(detailBits, priceStr)
		}
		if desc != "" {
			detailBits = append(detailBits, desc)
		}
		detailCell := "-"
		if len(detailBits) > 0 {
			detailCell = strings.Join(detailBits, " — ")
		}
		tableRows = append(tableRows, []string{strconv.Itoa(pos), linkCell, detailCell})
	}

	if len(records) < 2 {
		return nil
	}
	lowerST := strings.ToLower(schemaType)
	isExplicitList := strings.Contains(lowerST, "itemlist") || strings.Contains(lowerST, "collectionpage") || strings.Contains(lowerST, "searchresultspage")
	if len(records) <= 3 && !anySummaryOrPrice && !isExplicitList {
		return nil
	}

	title := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["name"], obj["headline"], listContainer["name"]), 300)
	description := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["description"], listContainer["description"]), 1_000)

	total := len(records)
	if declTotal, okT := finiteNumberSchemaGo(firstNonNilSchemaGo(listContainer["numberOfItems"], obj["numberOfItems"])); okT && int(math.Floor(declTotal)) >= len(records) {
		total = int(math.Floor(declTotal))
	}

	var headers []string
	var compactRows [][]string
	if anySummaryOrPrice {
		headers = []string{"#", "Item", "Details"}
		compactRows = tableRows
	} else {
		headers = []string{"#", "Item"}
		compactRows = make([][]string, len(tableRows))
		for i, r := range tableRows {
			compactRows[i] = []string{r[0], r[1]}
		}
	}
	tableMD := formatGFMTableSchemaGo(headers, compactRows)
	var mdParts []string
	if title != "" {
		mdParts = append(mdParts, "# "+title)
	}
	if description != "" {
		mdParts = append(mdParts, description)
	}
	if tableMD != "" {
		mdParts = append(mdParts, tableMD)
	}

	structured := map[string]any{
		"schemaType": schemaType,
		"returned":   len(records),
		"total":      total,
	}
	if title != "" {
		structured["title"] = title
	}

	return &UniversalSchemaOrgResult{
		ExtractorID: "schema-org",
		PrimaryType: schemaType,
		SchemaType:  schemaType,
		Title:       title,
		Description: description,
		Markdown:    strings.Join(mdParts, "\n\n"),
		Structured:  structured,
		Records:     records,
		Returned:    len(records),
		Total:       total,
		Truncated:   total > len(records),
	}
}

func extractArticleSchemaGo(obj map[string]any, schemaType, baseURL string, htmlToMD func(frag, base string) (string, []string)) *UniversalSchemaOrgResult {
	title := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["headline"], obj["name"]), 350)
	description := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["description"], obj["abstract"]), 1_200)
	author := extractAuthorNameSchemaGo(obj["author"])
	siteName := extractPublisherNameSchemaGo(obj["publisher"])
	publishedTime := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["datePublished"], obj["dateCreated"]), 64)
	modifiedTime := SanitizeSchemaPlainField(obj["dateModified"], 64)
	section := SanitizeSchemaPlainField(obj["articleSection"], 120)
	bodyMD := SanitizeSchemaRichMarkdown(firstNonNilSchemaGo(obj["articleBody"], obj["text"]), baseURL, htmlToMD, 64_000)
	bodyWords := countWordsSchemaGo(bodyMD)

	if title == "" && bodyWords < 25 {
		return nil
	}

	var metaBits []string
	if author != "" {
		metaBits = append(metaBits, "**Author**: "+author)
	}
	if siteName != "" {
		metaBits = append(metaBits, "**Publisher**: "+siteName)
	}
	if publishedTime != "" {
		metaBits = append(metaBits, "**Published**: "+publishedTime)
	}
	if section != "" {
		metaBits = append(metaBits, "**Section**: "+section)
	}
	headerMD := strings.Join(metaBits, " · ")

	fullMD := ""
	if bodyWords >= 30 {
		var parts []string
		if title != "" {
			parts = append(parts, "# "+title)
		}
		if headerMD != "" {
			parts = append(parts, headerMD)
		}
		parts = append(parts, bodyMD)
		fullMD = strings.Join(parts, "\n\n")
	}

	structured := map[string]any{
		"schemaType": schemaType,
	}
	if title != "" {
		structured["headline"] = title
	}
	if description != "" {
		structured["description"] = description
	}
	if author != "" {
		structured["author"] = author
	}
	if siteName != "" {
		structured["publisher"] = siteName
	}
	if publishedTime != "" {
		structured["datePublished"] = publishedTime
	}
	if modifiedTime != "" {
		structured["dateModified"] = modifiedTime
	}
	if section != "" {
		structured["articleSection"] = section
	}
	if bodyWords > 0 {
		structured["wordCount"] = bodyWords
	}

	return &UniversalSchemaOrgResult{
		ExtractorID:    "schema-org",
		PrimaryType:    schemaType,
		SchemaType:     schemaType,
		Title:          title,
		Description:    description,
		Author:         author,
		PublishedTime:  publishedTime,
		ModifiedTime:   modifiedTime,
		SiteName:       siteName,
		Markdown:       fullMD,
		HeaderMarkdown: headerMD,
		Structured:     structured,
	}
}

func extractDomainEntitySchemaGo(obj map[string]any, schemaType, kind, baseURL string) *UniversalSchemaOrgResult {
	title := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["name"], obj["headline"]), 350)
	if title == "" {
		return nil
	}
	description := SanitizeSchemaPlainField(obj["description"], 1_500)
	safeURL := SanitizeSchemaHTTPSURL(obj["url"], baseURL)

	structured := map[string]any{
		"schemaType": schemaType,
		"name":       title,
	}
	if description != "" {
		structured["description"] = description
	}
	if safeURL != "" {
		structured["url"] = safeURL
	}

	var bullets []string
	var publishedTime string
	var author string

	switch kind {
	case "event":
		startDate := SanitizeSchemaPlainField(obj["startDate"], 80)
		endDate := SanitizeSchemaPlainField(obj["endDate"], 80)
		status := stripSchemaOrgURLPrefixSchemaGo(SanitizeSchemaPlainField(obj["eventStatus"], 80))
		attendance := stripSchemaOrgURLPrefixSchemaGo(SanitizeSchemaPlainField(obj["eventAttendanceMode"], 80))
		var locSource any
		if locObj, ok := obj["location"].(map[string]any); ok {
			locSource = locObj["name"]
		} else if _, ok := obj["location"].(string); ok {
			locSource = obj["location"]
		}
		locName := SanitizeSchemaPlainField(locSource, 180)
		organizer := extractPublisherNameSchemaGo(obj["organizer"])
		if startDate != "" {
			structured["startDate"] = startDate
			bullets = append(bullets, "- **Start**: "+startDate)
		}
		if endDate != "" {
			structured["endDate"] = endDate
			bullets = append(bullets, "- **End**: "+endDate)
		}
		if locName != "" {
			structured["location"] = locName
			bullets = append(bullets, "- **Location**: "+locName)
		}
		if attendance != "" {
			structured["attendanceMode"] = attendance
			bullets = append(bullets, "- **Mode**: "+attendance)
		}
		if status != "" {
			structured["eventStatus"] = status
		}
		if organizer != "" {
			structured["organizer"] = organizer
			bullets = append(bullets, "- **Organizer**: "+organizer)
		}

	case "software":
		appCat := SanitizeSchemaPlainField(obj["applicationCategory"], 120)
		osStr := SanitizeSchemaPlainField(obj["operatingSystem"], 160)
		version := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["softwareVersion"], obj["version"]), 80)
		ratingValue := ""
		ratingCount := ""
		if ratingObj, ok := obj["aggregateRating"].(map[string]any); ok {
			ratingValue = SanitizeSchemaPlainField(ratingObj["ratingValue"], 20)
			ratingCount = SanitizeSchemaPlainField(firstNonNilSchemaGo(ratingObj["ratingCount"], ratingObj["reviewCount"]), 24)
		}
		if appCat != "" {
			structured["applicationCategory"] = appCat
			bullets = append(bullets, "- **Category**: "+appCat)
		}
		if osStr != "" {
			structured["operatingSystem"] = osStr
			bullets = append(bullets, "- **Operating System**: "+osStr)
		}
		if version != "" {
			structured["softwareVersion"] = version
			bullets = append(bullets, "- **Version**: "+version)
		}
		if ratingValue != "" {
			structured["ratingValue"] = ratingValue
			if ratingCount != "" {
				structured["ratingCount"] = ratingCount
				bullets = append(bullets, fmt.Sprintf("- **Rating**: %s (%s reviews)", ratingValue, ratingCount))
			} else {
				bullets = append(bullets, "- **Rating**: "+ratingValue)
			}
		}

	case "dataset":
		creator := extractAuthorNameSchemaGo(firstNonNilSchemaGo(obj["creator"], obj["author"]))
		var licSource any = obj["license"]
		if licObj, ok := obj["license"].(map[string]any); ok {
			licSource = licObj["name"]
		}
		license := SanitizeSchemaPlainField(licSource, 200)
		temporal := SanitizeSchemaPlainField(obj["temporalCoverage"], 120)
		identifier := SanitizeSchemaPlainField(obj["identifier"], 160)
		if creator != "" {
			structured["creator"] = creator
			author = creator
			bullets = append(bullets, "- **Creator**: "+creator)
		}
		if license != "" {
			structured["license"] = license
			bullets = append(bullets, "- **License**: "+license)
		}
		if temporal != "" {
			structured["temporalCoverage"] = temporal
			bullets = append(bullets, "- **Coverage**: "+temporal)
		}
		if identifier != "" {
			structured["identifier"] = identifier
		}

	case "recipe":
		prepTime := SanitizeSchemaPlainField(obj["prepTime"], 40)
		cookTime := SanitizeSchemaPlainField(obj["cookTime"], 40)
		totalTime := SanitizeSchemaPlainField(obj["totalTime"], 40)
		yieldRaw := obj["recipeYield"]
		if yArr, ok := yieldRaw.([]any); ok && len(yArr) > 0 {
			yieldRaw = yArr[0]
		}
		recipeYield := SanitizeSchemaPlainField(yieldRaw, 80)
		var ingredients []string
		if ingArr, ok := obj["recipeIngredient"].([]any); ok {
			lim := len(ingArr)
			if lim > 60 {
				lim = 60
			}
			for i := 0; i < lim; i++ {
				if v := SanitizeSchemaPlainField(ingArr[i], 200); v != "" {
					ingredients = append(ingredients, v)
				}
			}
		}
		if totalTime != "" || prepTime != "" || cookTime != "" {
			var tBits []string
			if prepTime != "" {
				tBits = append(tBits, "prep "+prepTime)
			}
			if cookTime != "" {
				tBits = append(tBits, "cook "+cookTime)
			}
			if totalTime != "" {
				tBits = append(tBits, "total "+totalTime)
			}
			tStr := strings.Join(tBits, ", ")
			structured["timing"] = tStr
			bullets = append(bullets, "- **Time**: "+tStr)
		}
		if recipeYield != "" {
			structured["recipeYield"] = recipeYield
			bullets = append(bullets, "- **Yield**: "+recipeYield)
		}
		if len(ingredients) > 0 {
			structured["recipeIngredient"] = ingredients
		}

	case "course":
		provider := extractPublisherNameSchemaGo(firstNonNilSchemaGo(obj["provider"], obj["creator"]))
		courseCode := SanitizeSchemaPlainField(obj["courseCode"], 80)
		eduLevel := SanitizeSchemaPlainField(obj["educationalLevel"], 120)
		lang := SanitizeSchemaPlainField(obj["inLanguage"], 40)
		if provider != "" {
			structured["provider"] = provider
			bullets = append(bullets, "- **Provider**: "+provider)
		}
		if courseCode != "" {
			structured["courseCode"] = courseCode
			bullets = append(bullets, "- **Course Code**: "+courseCode)
		}
		if eduLevel != "" {
			structured["educationalLevel"] = eduLevel
			bullets = append(bullets, "- **Level**: "+eduLevel)
		}
		if lang != "" {
			structured["inLanguage"] = lang
		}

	case "video":
		uploadDate := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["uploadDate"], obj["datePublished"]), 64)
		duration := SanitizeSchemaPlainField(obj["duration"], 40)
		creator := extractAuthorNameSchemaGo(firstNonNilSchemaGo(obj["author"], obj["creator"]))
		embedURL := SanitizeSchemaHTTPSURL(firstNonNilSchemaGo(obj["embedUrl"], obj["contentUrl"]), baseURL)
		if uploadDate != "" {
			publishedTime = uploadDate
			structured["uploadDate"] = uploadDate
			bullets = append(bullets, "- **Uploaded**: "+uploadDate)
		}
		if duration != "" {
			structured["duration"] = duration
			bullets = append(bullets, "- **Duration**: "+duration)
		}
		if creator != "" {
			author = creator
			structured["author"] = creator
			bullets = append(bullets, "- **Creator**: "+creator)
		}
		if embedURL != "" {
			structured["embedUrl"] = embedURL
		}

	case "localbusiness":
		tel := SanitizeSchemaPlainField(obj["telephone"], 60)
		priceRange := SanitizeSchemaPlainField(obj["priceRange"], 30)
		addrStr := formatPostalAddressSchemaGo(obj["address"])
		if tel == "" && addrStr == "" {
			return nil
		}
		if addrStr != "" {
			structured["address"] = addrStr
			bullets = append(bullets, "- **Address**: "+addrStr)
		}
		if tel != "" {
			structured["telephone"] = tel
			bullets = append(bullets, "- **Phone**: "+tel)
		}
		if priceRange != "" {
			structured["priceRange"] = priceRange
		}

	case "organization":
		tel := SanitizeSchemaPlainField(obj["telephone"], 60)
		founding := SanitizeSchemaPlainField(obj["foundingDate"], 40)
		addrStr := formatPostalAddressSchemaGo(obj["address"])
		// Require rich Organization facts so bare publisher stubs inside @graph never create noise.
		if addrStr == "" && tel == "" && founding == "" && len(description) < 40 {
			return nil
		}
		if addrStr != "" {
			structured["address"] = addrStr
			bullets = append(bullets, "- **Address**: "+addrStr)
		}
		if tel != "" {
			structured["telephone"] = tel
			bullets = append(bullets, "- **Phone**: "+tel)
		}
		if founding != "" {
			structured["foundingDate"] = founding
			bullets = append(bullets, "- **Founded**: "+founding)
		}
	}

	if len(bullets) == 0 && description == "" {
		return nil
	}
	headerMD := strings.Join(bullets, "\n")
	var mdBlocks []string
	mdBlocks = append(mdBlocks, "# "+title)
	if headerMD != "" {
		mdBlocks = append(mdBlocks, headerMD)
	}
	if description != "" {
		mdBlocks = append(mdBlocks, description)
	}

	return &UniversalSchemaOrgResult{
		ExtractorID:    "schema-org",
		PrimaryType:    schemaType,
		SchemaType:     schemaType,
		Title:          title,
		Description:    description,
		Author:         author,
		PublishedTime:  publishedTime,
		HeaderMarkdown: headerMD,
		Markdown:       strings.Join(mdBlocks, "\n\n"),
		Structured:     structured,
	}
}

func formatPostalAddressSchemaGo(rawAddr any) string {
	if addrObj, ok := rawAddr.(map[string]any); ok {
		keys := []string{"streetAddress", "addressLocality", "addressRegion", "postalCode", "addressCountry"}
		var parts []string
		for _, k := range keys {
			if v := SanitizeSchemaPlainField(addrObj[k], 80); v != "" {
				parts = append(parts, v)
			}
		}
		return strings.Join(parts, ", ")
	}
	return SanitizeSchemaPlainField(rawAddr, 200)
}

func stripSchemaOrgURLPrefixSchemaGo(s string) string {
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "https://schema.org/") {
		return s[len("https://schema.org/"):]
	}
	if strings.HasPrefix(lower, "http://schema.org/") {
		return s[len("http://schema.org/"):]
	}
	return s
}

func scalarStringOrNumberSchemaGo(raw any) (string, bool) {
	switch v := raw.(type) {
	case string:
		return v, true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return "", false
		}
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case json.Number:
		return v.String(), true
	default:
		return "", false
	}
}

func finiteNumberSchemaGo(raw any) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, !math.IsNaN(v) && !math.IsInf(v, 0)
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}

func parseJSONValueSchemaGo(raw string) any {
	trimmed := strings.TrimPrefix(raw, "\uFEFF")
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return nil
	}
	return v
}

func sortedMapKeysSchemaGo(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func countWordsSchemaGo(s string) int {
	count := 0
	inWord := false
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		isWordRune := unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '\'' || r == '-'
		if isWordRune {
			if !inWord {
				count++
				inWord = true
			}
		} else {
			inWord = false
		}
		i += w
	}
	return count
}

func utf16UnitsLenSchemaGo(s string) int {
	if len(s) == 0 {
		return 0
	}
	units := 0
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		if r > 0xFFFF {
			units += 2
		} else {
			units++
		}
		i += w
	}
	return units
}

func sliceUTF8CleanBytesSchemaGo(s string, maxBytes int) string {
	if maxBytes <= 0 || s == "" {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func collapseWhitespaceSchemaGo(s string) string {
	if s == "" {
		return ""
	}
	return strings.Join(strings.Fields(s), " ")
}

func collapseBlankLinesMarkdownSchemaGo(s string) string {
	norm := strings.ReplaceAll(s, "\r\n", "\n")
	norm = strings.ReplaceAll(norm, "\r", "\n")
	var sb strings.Builder
	sb.Grow(len(norm))
	nlRun := 0
	for i := 0; i < len(norm); i++ {
		if norm[i] == '\n' {
			nlRun++
			if nlRun <= 2 {
				sb.WriteByte('\n')
			}
			continue
		}
		nlRun = 0
		sb.WriteByte(norm[i])
	}
	return strings.TrimSpace(sb.String())
}

// escapeDangerousAngleBracketsSchemaGo matches `/<(?=[ \t]*(?:javascript|vbscript|data|file|blob|\/?[a-zA-Z!]))/gi`
// in linear O(N) time without regex lookahead.
func escapeDangerousAngleBracketsSchemaGo(s string) string {
	if strings.IndexByte(s, '<') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 16)
	n := len(s)
	for i := 0; i < n; i++ {
		if s[i] != '<' {
			sb.WriteByte(s[i])
			continue
		}
		p := i + 1
		for p < n && (s[p] == ' ' || s[p] == '\t') {
			p++
		}
		dangerous := false
		if p < n {
			c := s[p]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '!' {
				dangerous = true
			} else if c == '/' && p+1 < n {
				c2 := s[p+1]
				if (c2 >= 'a' && c2 <= 'z') || (c2 >= 'A' && c2 <= 'Z') || c2 == '!' {
					dangerous = true
				}
			}
		}
		if dangerous {
			sb.WriteString("&lt;")
		} else {
			sb.WriteByte('<')
		}
	}
	return sb.String()
}

// decodeBasicEntitiesSchemaGo matches `decodeBasicEntities` in `hub/src/extractors/utils.ts` 1:1.
func decodeBasicEntitiesSchemaGo(s string) string {
	if strings.IndexByte(s, '&') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	n := len(s)
	for i := 0; i < n; {
		if s[i] != '&' {
			sb.WriteByte(s[i])
			i++
			continue
		}
		semiRel := strings.IndexByte(s[i+1:], ';')
		if semiRel < 0 || semiRel > 14 {
			sb.WriteByte('&')
			i++
			continue
		}
		ent := s[i+1 : i+1+semiRel]
		nextIdx := i + 1 + semiRel + 1
		if len(ent) >= 2 && ent[0] == '#' {
			if ent[1] == 'x' || ent[1] == 'X' {
				if hexStr := ent[2:]; len(hexStr) > 0 {
					if cp, err := strconv.ParseUint(hexStr, 16, 32); err == nil && cp > 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF) {
						sb.WriteRune(rune(cp))
						i = nextIdx
						continue
					}
				}
			} else {
				if decStr := ent[1:]; len(decStr) > 0 {
					if cp, err := strconv.ParseUint(decStr, 10, 32); err == nil && cp > 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF) {
						sb.WriteRune(rune(cp))
						i = nextIdx
						continue
					}
				}
			}
		} else {
			switch strings.ToLower(ent) {
			case "nbsp":
				sb.WriteByte(' ')
				i = nextIdx
				continue
			case "amp":
				sb.WriteByte('&')
				i = nextIdx
				continue
			case "lt":
				sb.WriteByte('<')
				i = nextIdx
				continue
			case "gt":
				sb.WriteByte('>')
				i = nextIdx
				continue
			case "quot":
				sb.WriteByte('"')
				i = nextIdx
				continue
			case "apos":
				sb.WriteByte('\'')
				i = nextIdx
				continue
			}
		}
		sb.WriteByte('&')
		i++
	}
	return sb.String()
}

func escapeGFMCellSchemaGo(val string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 180
	}
	s := strings.ReplaceAll(val, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "-"
	}
	if utf8.RuneCountInString(s) > maxLen {
		return sliceRunesMax(s, maxLen-1) + "…"
	}
	return s
}

func formatGFMTableSchemaGo(headers []string, rows [][]string) string {
	if len(headers) == 0 || len(rows) == 0 {
		return ""
	}
	headCells := make([]string, len(headers))
	sepCells := make([]string, len(headers))
	for i, h := range headers {
		headCells[i] = escapeGFMCellSchemaGo(h, 80)
		sepCells[i] = "---"
	}
	lines := make([]string, 0, len(rows)+2)
	lines = append(lines, "| "+strings.Join(headCells, " | ")+" |")
	lines = append(lines, "| "+strings.Join(sepCells, " | ")+" |")
	for _, r := range rows {
		cells := make([]string, len(headers))
		for i := range headers {
			cellVal := ""
			if i < len(r) {
				cellVal = r[i]
			}
			cells[i] = escapeGFMCellSchemaGo(cellVal, 180)
		}
		lines = append(lines, "| "+strings.Join(cells, " | ")+" |")
	}
	return strings.Join(lines, "\n")
}

// --- Linear HTML Tag & Script Scanners (O(N) with 3-state dead-path memoization) ---

type htmlDeadStateSchemaGo struct {
	mask       []uint8
	nextGtPos  int
	hasGtCache bool
}

func isHTMLTagBoundaryByteSchemaGo(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r' || b == '/' || b == '>'
}

func isHTMLAttrSpaceSchemaGo(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func trimASCIIWhitespaceSchemaGo(s string) string {
	start := 0
	end := len(s)
	for start < end && isHTMLAttrSpaceSchemaGo(s[start]) {
		start++
	}
	for end > start && isHTMLAttrSpaceSchemaGo(s[end-1]) {
		end--
	}
	return s[start:end]
}

func markDeadTagScanPathSchemaGo(src string, fromIdx, stopIdx int, mask []uint8) {
	state := uint8(0) // 0 = unquoted, 1 = ", 2 = '
	for i := fromIdx; i < stopIdx; i++ {
		bit := uint8(1) << state
		if (mask[i] & bit) != 0 {
			break
		}
		mask[i] |= bit
		ch := src[i]
		if state == 1 {
			if ch == '"' {
				state = 0
			}
		} else if state == 2 {
			if ch == '\'' {
				state = 0
			}
		} else if ch == '"' {
			state = 1
		} else if ch == '\'' {
			state = 2
		}
	}
}

func findTagOpenEndQuoteAwareSchemaGo(src string, fromIdx int, dead *htmlDeadStateSchemaGo) int {
	if dead != nil && dead.hasGtCache && dead.nextGtPos == -1 {
		return -1
	}
	if dead != nil && (!dead.hasGtCache || dead.nextGtPos < fromIdx) {
		rel := strings.IndexByte(src[fromIdx:], '>')
		if rel < 0 {
			dead.hasGtCache = true
			dead.nextGtPos = -1
			return -1
		}
		dead.hasGtCache = true
		dead.nextGtPos = fromIdx + rel
	} else if dead == nil && strings.IndexByte(src[fromIdx:], '>') < 0 {
		return -1
	}

	if dead != nil && dead.mask != nil && fromIdx < len(dead.mask) && (dead.mask[fromIdx]&1) != 0 {
		return -1
	}

	state := uint8(0)
	for i := fromIdx; i < len(src); i++ {
		if dead != nil && dead.mask != nil && (dead.mask[i]&(uint8(1)<<state)) != 0 {
			markDeadTagScanPathSchemaGo(src, fromIdx, i, dead.mask)
			return -1
		}
		ch := src[i]
		if state == 1 {
			if ch == '"' {
				state = 0
			}
		} else if state == 2 {
			if ch == '\'' {
				state = 0
			}
		} else if ch == '"' {
			state = 1
		} else if ch == '\'' {
			state = 2
		} else if ch == '>' {
			return i
		}
	}
	if dead != nil {
		if dead.mask == nil {
			dead.mask = make([]uint8, len(src))
		}
		markDeadTagScanPathSchemaGo(src, fromIdx, len(src), dead.mask)
	}
	return -1
}

func findNextValidCloseTagSchemaGo(lower, src, closeNeedle string, fromIdx int) int {
	if fromIdx >= len(lower) {
		return -1
	}
	rel := strings.Index(lower[fromIdx:], closeNeedle)
	for rel >= 0 {
		closePos := fromIdx + rel
		afterCloseName := closePos + len(closeNeedle)
		if afterCloseName < len(src) && isHTMLTagBoundaryByteSchemaGo(src[afterCloseName]) {
			return closePos
		}
		fromIdx = afterCloseName
		if fromIdx >= len(lower) {
			break
		}
		rel = strings.Index(lower[fromIdx:], closeNeedle)
	}
	return -1
}

// scanScriptBlocksLinearSchemaGo scans `<script ...>...</script>` blocks in guaranteed O(N) time.
func scanScriptBlocksLinearSchemaGo(rawHTML string, maxBytes int, onScript func(attrStr, inner string) bool) {
	if rawHTML == "" {
		return
	}
	src := sliceUTF8CleanBytesSchemaGo(rawHTML, maxBytes)
	if strings.IndexByte(src, 0) >= 0 {
		src = strings.ReplaceAll(src, "\x00", "")
	}
	lower := asciiLowerExtractString(src)
	const openNeedle = "<script"
	const closeNeedle = "</script"

	firstHit := strings.Index(lower, openNeedle)
	if firstHit < 0 {
		return
	}
	dead := &htmlDeadStateSchemaGo{}
	cachedClosePos := -2

	for firstHit >= 0 && firstHit < len(src) {
		afterNameIdx := firstHit + len(openNeedle)
		if afterNameIdx >= len(src) || !isHTMLTagBoundaryByteSchemaGo(src[afterNameIdx]) {
			rel := strings.Index(lower[afterNameIdx:], openNeedle)
			if rel < 0 {
				break
			}
			firstHit = afterNameIdx + rel
			continue
		}
		openEnd := findTagOpenEndQuoteAwareSchemaGo(src, afterNameIdx, dead)
		if openEnd < 0 {
			break
		}
		attrStr := src[afterNameIdx:openEnd]
		if src[openEnd-1] == '/' {
			if !onScript(attrStr[:len(attrStr)-1], "") {
				return
			}
			cursor := openEnd + 1
			rel := strings.Index(lower[cursor:], openNeedle)
			if rel < 0 {
				break
			}
			firstHit = cursor + rel
			continue
		}
		if cachedClosePos != -1 && cachedClosePos < openEnd+1 {
			cachedClosePos = findNextValidCloseTagSchemaGo(lower, src, closeNeedle, openEnd+1)
		}
		if cachedClosePos < 0 {
			break
		}
		closeEndRel := strings.IndexByte(src[cachedClosePos+len(closeNeedle):], '>')
		if closeEndRel < 0 {
			break
		}
		closeEnd := cachedClosePos + len(closeNeedle) + closeEndRel
		inner := src[openEnd+1 : cachedClosePos]
		if !onScript(attrStr, inner) {
			return
		}
		cursor := closeEnd + 1
		if cursor >= len(lower) {
			break
		}
		rel := strings.Index(lower[cursor:], openNeedle)
		if rel < 0 {
			break
		}
		firstHit = cursor + rel
	}
}

// stripHTMLTagsQuoteAwareSchemaGo strips HTML tags, comments, declarations, and CDATA in linear O(N) time.
func stripHTMLTagsQuoteAwareSchemaGo(rawHTML, replacement string, maxBytes int) string {
	src := sliceUTF8CleanBytesSchemaGo(rawHTML, maxBytes)
	if strings.IndexByte(src, '<') < 0 {
		return src
	}
	dead := &htmlDeadStateSchemaGo{}
	var sb strings.Builder
	sb.Grow(len(src))
	cursor := 0
	n := len(src)
	pos := strings.IndexByte(src, '<')
	noCommentCloseFrom := -1
	noCDATACloseFrom := -1

	for pos >= 0 && pos < n {
		if dead.hasGtCache && dead.nextGtPos == -1 {
			break
		}
		tagEnd := tryFindHTMLTagEndSchemaGo(src, pos, dead, &noCommentCloseFrom, &noCDATACloseFrom)
		if tagEnd < 0 {
			if pos+1 >= n {
				break
			}
			rel := strings.IndexByte(src[pos+1:], '<')
			if rel < 0 {
				break
			}
			pos = pos + 1 + rel
			continue
		}
		if pos > cursor {
			sb.WriteString(src[cursor:pos])
		}
		sb.WriteString(replacement)
		cursor = tagEnd
		if cursor >= n {
			break
		}
		rel := strings.IndexByte(src[cursor:], '<')
		if rel < 0 {
			break
		}
		pos = cursor + rel
	}
	if cursor == 0 {
		return src
	}
	if cursor < n {
		sb.WriteString(src[cursor:])
	}
	return sb.String()
}

func tryFindHTMLTagEndSchemaGo(src string, ltIdx int, dead *htmlDeadStateSchemaGo, noCommentCloseFrom, noCDATACloseFrom *int) int {
	n := len(src)
	if ltIdx+2 > n {
		return -1
	}
	p := ltIdx + 1
	first := src[p]
	isClosing := false

	if first == '/' {
		isClosing = true
		p++
		if p >= n || !isASCIIAlphaSchemaGo(src[p]) {
			return -1
		}
	} else if first == '!' || first == '?' {
		p++
		if p >= n {
			return -1
		}
		declNext := src[p]
		if first == '!' && declNext == '-' && p+1 < n && src[p+1] == '-' {
			bodyStart := ltIdx + 4
			if bodyStart < n && src[bodyStart] == '>' {
				return bodyStart + 1
			}
			if bodyStart+1 < n && src[bodyStart] == '-' && src[bodyStart+1] == '>' {
				return bodyStart + 2
			}
			if *noCommentCloseFrom >= 0 && bodyStart >= *noCommentCloseFrom {
				return -1
			}
			stdRel := strings.Index(src[bodyStart:], "-->")
			bangRel := strings.Index(src[bodyStart:], "--!>")
			if stdRel < 0 && bangRel < 0 {
				if *noCommentCloseFrom < 0 || bodyStart < *noCommentCloseFrom {
					*noCommentCloseFrom = bodyStart
				}
				return -1
			}
			if stdRel >= 0 && (bangRel < 0 || stdRel <= bangRel) {
				return bodyStart + stdRel + 3
			}
			return bodyStart + bangRel + 4
		}
		if first == '!' && declNext == '[' && strings.HasPrefix(src[p:], "[CDATA[") {
			afterCDATA := p + 7
			if *noCDATACloseFrom >= 0 && afterCDATA >= *noCDATACloseFrom {
				return -1
			}
			rel := strings.Index(src[afterCDATA:], "]]>")
			if rel < 0 {
				if *noCDATACloseFrom < 0 || afterCDATA < *noCDATACloseFrom {
					*noCDATACloseFrom = afterCDATA
				}
				return -1
			}
			return afterCDATA + rel + 3
		}
		if !isASCIIAlphaSchemaGo(declNext) {
			return -1
		}
	} else if !isASCIIAlphaSchemaGo(first) {
		return -1
	}

	p++
	for p < n && !isHTMLTagBoundaryByteSchemaGo(src[p]) {
		p++
	}
	if p >= n {
		return -1
	}
	var openEnd int
	if isClosing {
		rel := strings.IndexByte(src[p:], '>')
		if rel < 0 {
			dead.hasGtCache = true
			dead.nextGtPos = -1
			return -1
		}
		openEnd = p + rel
	} else {
		openEnd = findTagOpenEndQuoteAwareSchemaGo(src, p, dead)
		if openEnd < 0 {
			return -1
		}
	}
	return openEnd + 1
}

func isASCIIAlphaSchemaGo(b byte) bool {
	lower := b | 0x20
	return lower >= 'a' && lower <= 'z'
}

// --- Public HTTPS URL Validation Helpers (SSRF / Port / Credentials / Rebinding Guards) ---

func hasDisallowedURLSchemePrefixSchemaGo(s string) bool {
	colon := strings.IndexByte(s, ':')
	if colon <= 0 {
		return false
	}
	scheme := strings.ToLower(strings.TrimSpace(s[:colon]))
	switch scheme {
	case "javascript", "vbscript", "data", "file", "blob", "mailto", "tel", "ftp", "ws", "wss":
		return true
	default:
		return false
	}
}

func hasBackslashInAuthoritySchemaGo(s string) bool {
	if strings.IndexByte(s, '\\') < 0 {
		return false
	}
	// Reject backslashes anywhere before `?` or `#` if `://` or `//` is present.
	end := len(s)
	if q := strings.IndexByte(s, '?'); q >= 0 && q < end {
		end = q
	}
	if h := strings.IndexByte(s, '#'); h >= 0 && h < end {
		end = h
	}
	prefix := s[:end]
	if idx := strings.Index(prefix, "://"); idx >= 0 {
		rest := prefix[idx+3:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			rest = rest[:slash]
		}
		return strings.IndexByte(rest, '\\') >= 0
	}
	if strings.HasPrefix(prefix, "//") {
		return true
	}
	return false
}

func preEncodeWhitespaceForURLParseSchemaGo(s string) string {
	hasWS := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' {
			hasWS = true
			break
		}
	}
	if !hasWS {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
			sb.WriteString("%20")
		case '\t':
			sb.WriteString("%09")
		case '\r':
			sb.WriteString("%0D")
		case '\n':
			sb.WriteString("%0A")
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

func isSafePublicHostnameWithSelfSchemaGo(rawHost, selfHost string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(rawHost))
	if trimmed == "" || strings.Contains(trimmed, "..") {
		return false
	}
	host := strings.TrimSuffix(trimmed, ".")
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for i := 0; i < len(host); i++ {
		b := host[i]
		if b <= 0x20 || b == 0x7F || b == ':' || b == '[' || b == ']' || b == '\\' || b == '/' {
			return false
		}
	}
	if net.ParseIP(host) != nil || !isSafePublicHostnameGo(host) {
		return false
	}
	if disallowedExactHostsSchemaGo[host] {
		return false
	}
	for _, suf := range disallowedHostSuffixesSchemaGo {
		if strings.HasSuffix(host, suf) {
			return false
		}
	}
	canonSelf := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(selfHost)), ".")
	if canonSelf != "" && host == canonSelf {
		return false
	}
	labels := strings.Split(host, ".")
	for _, lbl := range labels {
		if lbl == "" || strings.HasPrefix(lbl, "-") || strings.HasSuffix(lbl, "-") {
			return false
		}
	}
	tld := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return false
	}
	if len(tld) > 2 && tld[0] == '0' && (tld[1] == 'x' || tld[1] == 'X') {
		allHex := true
		for i := 2; i < len(tld); i++ {
			c := tld[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		if allHex {
			return false
		}
	}
	return true
}

func normalizeAndValidatePublicHTTPSURLSchemaGo(u *url.URL, selfHost string) (string, bool) {
	if u == nil || strings.ToLower(u.Scheme) != "https" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	if port := u.Port(); port != "" && port != "443" {
		return "", false
	}
	rawHost := u.Hostname()
	if !isSafePublicHostnameWithSelfSchemaGo(rawHost, selfHost) {
		return "", false
	}
	clone := *u
	clone.Scheme = "https"
	clone.Host = strings.TrimSuffix(strings.ToLower(rawHost), ".")
	if clone.Path == "" {
		clone.Path = "/"
	}
	return clone.String(), true
}
