package extract

import (
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"strings"
)

// CMSAutoTwinFormatted holds formatted Markdown, structured metadata, optional records,
// and prompt-injection screening text from WordPress REST or Gatsby `page-data.json` twins (`cms-twins.ts` parity).
type CMSAutoTwinFormatted struct {
	ExtractorID                 string           `json:"extractorId,omitempty"`
	TwinURL                     string           `json:"twinUrl,omitempty"`
	Title                       string           `json:"title,omitempty"`
	Description                 string           `json:"description,omitempty"`
	PublishedTime               string           `json:"publishedTime,omitempty"`
	ModifiedTime                string           `json:"modifiedTime,omitempty"`
	Markdown                    string           `json:"markdown"`
	Structured                  map[string]any   `json:"structured,omitempty"`
	Records                     []map[string]any `json:"records,omitempty"`
	Returned                    int              `json:"returned,omitempty"`
	Total                       int              `json:"total,omitempty"`
	Truncated                   bool             `json:"truncated,omitempty"`
	NextCursor                  string           `json:"nextCursor,omitempty"`
	RawDecodedStringsForPICheck string           `json:"rawDecodedStringsForPiCheck"`
}

const (
	maxWordPressHeadScanBytesCMSGo = 96_000
	maxWordPressJSONBytesCMSGo     = 4 * 1024 * 1024
	maxGatsbyJSONBytesCMSGo        = 2 * 1024 * 1024
	maxCMSPICharsCMSGo             = 1_572_864
)

var (
	reWPRestPostPathCMSGo   = regexp.MustCompile(`^/wp-json/wp/v2/(?:posts|pages)/[1-9][0-9]{0,11}/?$`)
	reHrefAmpersandEntCMSGo = regexp.MustCompile(`(?i)&(?:amp|#0*38|#x0*26);`)
)

// DiscoverWordPressRestTwinURL linearly scans `<head>` (`<= 96 KiB`) for WordPress's canonical per-post/page
// REST JSON `<link rel="alternate" type="application/json">` tag, enforcing strict same-origin `https://` port 443,
// `/wp-json/wp/v2/(posts|pages)/<digits>` path format, and SSRF-safe public hostname validation.
func DiscoverWordPressRestTwinURL(rawHTML, pageFinalURL, selfHost string) string {
	if rawHTML == "" || !strings.Contains(rawHTML, "wp-json/wp/v2/") {
		return ""
	}
	base, err := url.Parse(strings.TrimSpace(pageFinalURL))
	if err != nil || strings.ToLower(base.Scheme) != "https" || base.User != nil {
		return ""
	}
	if port := base.Port(); port != "" && port != "443" {
		return ""
	}
	if !isSafePublicHostnameWithSelfSchemaGo(base.Hostname(), selfHost) {
		return ""
	}
	baseHost := strings.TrimSuffix(strings.ToLower(base.Hostname()), ".")

	src := sliceUTF8CleanBytesSchemaGo(rawHTML, maxWordPressHeadScanBytesCMSGo)
	dead := &htmlDeadStateSchemaGo{}
	pos := strings.IndexByte(src, '<')

	for pos >= 0 && pos < len(src) {
		if dead.hasGtCache && dead.nextGtPos == -1 {
			break
		}
		if pos+2 > len(src) {
			break
		}
		first := src[pos+1]
		if first == '/' || first == '!' || first == '?' || !isASCIIAlphaSchemaGo(first) {
			rel := strings.IndexByte(src[pos+1:], '<')
			if rel < 0 {
				break
			}
			pos = pos + 1 + rel
			continue
		}
		p := pos + 2
		for p < len(src) && !isHTMLTagBoundaryByteSchemaGo(src[p]) {
			p++
		}
		if p >= len(src) {
			break
		}
		tagName := src[pos+1 : p]
		openEnd := findTagOpenEndQuoteAwareSchemaGo(src, p, dead)
		if openEnd < 0 {
			break
		}
		if strings.EqualFold(tagName, "link") {
			attrChunk := strings.TrimSuffix(src[p:openEnd], "/")
			if matched := matchWordPressLinkAttrsCMSGo(attrChunk, base, baseHost, selfHost); matched != "" {
				return matched
			}
		}
		if openEnd+1 >= len(src) {
			break
		}
		rel := strings.IndexByte(src[openEnd+1:], '<')
		if rel < 0 {
			break
		}
		pos = openEnd + 1 + rel
	}
	return ""
}

// ResolveGatsbyPageDataTwinURL builds Gatsby's static `/page-data/<pathname>/page-data.json` URL
// for thin `id="___gatsby"` shells while rejecting dot-traversal, encoded slashes, credentials, and SSRF hosts.
func ResolveGatsbyPageDataTwinURL(rawHTML, pageFinalURL, selfHost string) string {
	if rawHTML == "" || !strings.Contains(rawHTML, `id="___gatsby"`) {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(pageFinalURL))
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.User != nil {
		return ""
	}
	if port := u.Port(); port != "" && port != "443" {
		return ""
	}
	if !isSafePublicHostnameWithSelfSchemaGo(u.Hostname(), selfHost) {
		return ""
	}

	// Use `EscapedPath()` so `%2f` / `%2e` stay encoded and are rejected by `isGatsbySlugSegmentCMSGo` (`..%2fsecret` -> "").
	escapedPath := u.EscapedPath()
	if strings.HasPrefix(escapedPath, "/page-data/") {
		return ""
	}
	rawParts := strings.Split(escapedPath, "/")
	var rawSegs []string
	for _, p := range rawParts {
		if p != "" {
			rawSegs = append(rawSegs, p)
		}
	}
	if len(rawSegs) > 16 {
		return ""
	}
	for _, seg := range rawSegs {
		if seg == "." || seg == ".." || len(seg) > 120 || !isGatsbySlugSegmentCMSGo(seg) {
			return ""
		}
	}
	slugPath := "index"
	if len(rawSegs) > 0 {
		slugPath = strings.Join(rawSegs, "/")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	twinU := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/page-data/" + slugPath + "/page-data.json",
	}
	checked, ok := normalizeAndValidatePublicHTTPSURLSchemaGo(twinU, selfHost)
	if !ok {
		return ""
	}
	return checked
}

// FormatWordPressRestPostJSON converts a WordPress REST `/wp-json/wp/v2/(posts|pages)/<id>` JSON payload
// into sanitized Markdown, metadata, and decoded prompt-injection inspection text.
func FormatWordPressRestPostJSON(rawJSON, baseURL string, htmlToMD func(frag, base string) (string, []string)) *CMSAutoTwinFormatted {
	if rawJSON == "" || len(rawJSON) > maxWordPressJSONBytesCMSGo {
		return nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(rawJSON, "\uFEFF")), &parsed); err != nil || parsed == nil {
		return nil
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return nil
	}

	titleObj, _ := obj["title"].(map[string]any)
	contentObj, _ := obj["content"].(map[string]any)
	excerptObj, _ := obj["excerpt"].(map[string]any)

	if contentObj != nil {
		if prot, isBool := contentObj["protected"].(bool); isBool && prot {
			return nil
		}
	}

	rawTitleHTML := ""
	if titleObj != nil {
		rawTitleHTML, _ = titleObj["rendered"].(string)
	}
	rawContentHTML := ""
	if contentObj != nil {
		rawContentHTML, _ = contentObj["rendered"].(string)
	}
	rawExcerptHTML := ""
	if excerptObj != nil {
		rawExcerptHTML, _ = excerptObj["rendered"].(string)
	}
	if strings.TrimSpace(rawContentHTML) == "" {
		return nil
	}

	title := SanitizeSchemaPlainField(rawTitleHTML, 350)
	description := SanitizeSchemaPlainField(rawExcerptHTML, 1_000)
	bodyMD := SanitizeSchemaRichMarkdown(rawContentHTML, baseURL, htmlToMD, 128_000)
	wordCount := countWordsSchemaGo(bodyMD)
	if wordCount < 25 {
		return nil
	}

	publishedTime := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["date_gmt"], obj["date"]), 64)
	modifiedTime := SanitizeSchemaPlainField(firstNonNilSchemaGo(obj["modified_gmt"], obj["modified"]), 64)
	slug := SanitizeSchemaPlainField(obj["slug"], 160)
	wpType := SanitizeSchemaPlainField(obj["type"], 40)
	if wpType == "" {
		wpType = "post"
	}

	md := bodyMD
	if title != "" && !strings.HasPrefix(bodyMD, "# ") {
		md = "# " + title + "\n\n" + bodyMD
	}

	wpHasUnicodeTag := HasRawOrEncodedUnicodeTag(rawJSON) ||
		HasRawOrEncodedUnicodeTag(rawTitleHTML) ||
		HasRawOrEncodedUnicodeTag(rawExcerptHTML) ||
		HasRawOrEncodedUnicodeTag(rawContentHTML)

	var piParts []string
	for _, s := range []string{rawTitleHTML, rawExcerptHTML, rawContentHTML} {
		if s == "" {
			continue
		}
		if strings.IndexByte(s, '&') >= 0 {
			piParts = append(piParts, decodeBasicEntitiesSchemaGo(s))
		} else {
			piParts = append(piParts, s)
		}
	}
	rawForPI := sliceUTF8CleanBytesSchemaGo(strings.Join(piParts, "\n"), maxCMSPICharsCMSGo)
	if wpHasUnicodeTag && !strings.Contains(rawForPI, "\U000E0069") {
		if rawForPI == "" {
			rawForPI = "\U000E0069"
		} else {
			rawForPI = sliceUTF8CleanBytesSchemaGo(rawForPI, maxCMSPICharsCMSGo-8) + "\n\U000E0069"
		}
	}

	structured := map[string]any{
		"source":    "wordpress-rest",
		"postType":  wpType,
		"wordCount": wordCount,
	}
	if idNum, hasID := finiteNumberSchemaGo(obj["id"]); hasID {
		if math.Trunc(idNum) == idNum {
			structured["id"] = int64(idNum)
		} else {
			structured["id"] = idNum
		}
	}
	if slug != "" {
		structured["slug"] = slug
	}
	if publishedTime != "" {
		structured["datePublished"] = publishedTime
	}
	if modifiedTime != "" {
		structured["dateModified"] = modifiedTime
	}

	return &CMSAutoTwinFormatted{
		ExtractorID:                 "wordpress-rest",
		Title:                       title,
		Description:                 description,
		PublishedTime:               publishedTime,
		ModifiedTime:                modifiedTime,
		Markdown:                    md,
		Structured:                  structured,
		RawDecodedStringsForPICheck: rawForPI,
	}
}

// FormatGatsbyPageDataJSON converts a Gatsby static `/page-data/.../page-data.json` payload
// into sanitized Markdown, optional structured `records[]`, metadata, and decoded PI inspection text.
func FormatGatsbyPageDataJSON(rawJSON, baseURL string, htmlToMD func(frag, base string) (string, []string)) *CMSAutoTwinFormatted {
	trimmed := strings.TrimSpace(strings.TrimPrefix(rawJSON, "\uFEFF"))
	if trimmed == "" || len(trimmed) > maxGatsbyJSONBytesCMSGo {
		return nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil || parsed == nil {
		return nil
	}
	parsedObj, ok := parsed.(map[string]any)
	if !ok {
		return nil
	}
	target := any(parsedObj)
	if resVal, hasRes := parsedObj["result"]; hasRes && resVal != nil {
		target = resVal
	}

	gatsbyHasUnicodeTag := HasRawOrEncodedUnicodeTag(rawJSON)
	hydrated := ExtractFromParsedStateTree(target, "gatsby", baseURL, htmlToMD, "", gatsbyHasUnicodeTag)
	if hydrated == nil {
		return nil
	}

	rawPI := hydrated.RawDecodedStringsForPICheck
	if rawPI == "" {
		rawPI = sliceUTF8CleanBytesSchemaGo(rawJSON, maxCMSPICharsCMSGo)
		if gatsbyHasUnicodeTag && !strings.Contains(rawPI, "\U000E0069") {
			rawPI = sliceUTF8CleanBytesSchemaGo(rawPI, maxCMSPICharsCMSGo-8) + "\n\U000E0069"
		}
	}

	structured := hydrated.Structured
	if structured == nil {
		structured = map[string]any{
			"source": "gatsby-page-data",
		}
	}

	return &CMSAutoTwinFormatted{
		ExtractorID:                 "gatsby-page-data",
		Title:                       hydrated.Title,
		Description:                 hydrated.Description,
		Markdown:                    hydrated.Markdown,
		Structured:                  structured,
		Records:                     hydrated.Records,
		Returned:                    hydrated.Returned,
		Total:                       hydrated.Total,
		Truncated:                   hydrated.Truncated,
		NextCursor:                  hydrated.NextCursor,
		RawDecodedStringsForPICheck: rawPI,
	}
}

// --- Unexported CMS Auto-Twin Helpers (all suffixed with CMSGo) ---

func matchWordPressLinkAttrsCMSGo(attrChunk string, base *url.URL, baseHost, selfHost string) string {
	relVal, _ := extractNamedHTMLAttrHydrateGo(attrChunk, "rel")
	typeVal, _ := extractNamedHTMLAttrHydrateGo(attrChunk, "type")
	hrefVal, _ := extractNamedHTMLAttrHydrateGo(attrChunk, "href")
	if relVal == "" || typeVal == "" || hrefVal == "" {
		return ""
	}

	hasAlternate := false
	for _, tok := range strings.Fields(strings.ToLower(relVal)) {
		if tok == "alternate" {
			hasAlternate = true
			break
		}
	}
	if !hasAlternate {
		return ""
	}

	mime := strings.ToLower(typeVal)
	if semi := strings.IndexByte(mime, ';'); semi >= 0 {
		mime = mime[:semi]
	}
	if strings.TrimSpace(mime) != "application/json" {
		return ""
	}

	rawHref := strings.TrimSpace(reHrefAmpersandEntCMSGo.ReplaceAllString(hrefVal, "&"))
	if rawHref == "" || strings.IndexByte(rawHref, '#') >= 0 || hasBackslashInAuthoritySchemaGo(rawHref) || strings.HasPrefix(rawHref, "\\") {
		return ""
	}

	ref, err := url.Parse(rawHref)
	if err != nil {
		return ""
	}
	cand := base.ResolveReference(ref)
	if strings.ToLower(cand.Scheme) != "https" || cand.User != nil || cand.Fragment != "" {
		return ""
	}
	if port := cand.Port(); port != "" && port != "443" {
		return ""
	}
	if strings.TrimSuffix(strings.ToLower(cand.Hostname()), ".") != baseHost {
		return ""
	}
	escapedPath := cand.EscapedPath()
	if !reWPRestPostPathCMSGo.MatchString(escapedPath) {
		return ""
	}
	cand.RawQuery = ""
	cand.ForceQuery = false
	checked, ok := normalizeAndValidatePublicHTTPSURLSchemaGo(cand, selfHost)
	if !ok {
		return ""
	}
	return checked
}

func isGatsbySlugSegmentCMSGo(seg string) bool {
	if seg == "" {
		return false
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '~' || c == '-') {
			return false
		}
	}
	return true
}
