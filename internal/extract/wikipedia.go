package extract

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// DefaultWikipediaMaxAgeMs is the default 24-hour cache freshness window for Wikipedia articles.
	DefaultWikipediaMaxAgeMs = 24 * 60 * 60_000
	// DefaultWikipediaHourlyArticleLimit is the polite single-article ceiling per caller per Wikimedia host per hour.
	DefaultWikipediaHourlyArticleLimit = 200

	maxMediaWikiMarkdownBytesWikiGo = 2 * 1024 * 1024
	wikimediaEnterpriseURLWikiGo    = "https://enterprise.wikimedia.com/"
	wikimediaDumpsURLWikiGo         = "https://dumps.wikimedia.org/"
)

// ParsedWikipediaArticle holds the normalized canonical components of a Wikipedia article URL.
type ParsedWikipediaArticle struct {
	CanonicalURL     string `json:"canonicalUrl"`
	Host             string `json:"host"`
	Lang             string `json:"lang"`
	Title            string `json:"title"`
	EncodedTitle     string `json:"encodedTitle"`
	SectionAnchor    string `json:"sectionAnchor,omitempty"`
	CanonicalTitle   string `json:"canonicalTitle,omitempty"`
	UnderscoredTitle string `json:"underscoredTitle,omitempty"`
}

var (
	wikipediaLangReWikiGo               = regexp.MustCompile(`(?i)^[a-z]{2,12}(?:-[a-z0-9]{1,12}){0,2}$`)
	reQueryDisallowedWikiGo             = regexp.MustCompile(`(?i)[?&](?:diff|veaction)=`)
	rePositiveNumericIDWikiGo           = regexp.MustCompile(`^0*([1-9][0-9]{0,14})$`)
	rePercentDotOnlyWikiGo              = regexp.MustCompile(`(?i)^(?:%2e|\.)+$`)
	reGuessDisallowedWikiGo             = regexp.MustCompile(`(?i)(?:^|\s)(?:site:|filetype:|intitle:|inurl:|OR\b|AND\b|NOT\b|-)|\bhttps?://|["*?]`)
	reGuessUpperOrPunctWikiGo           = regexp.MustCompile(`[A-Z0-9/.+-]`)
	reGuessAllUpperDigitWikiGo          = regexp.MustCompile(`^[A-Z0-9]+$`)
	reJumpToContentWikiGo               = regexp.MustCompile(`(?i)^\[(?:Jump to content|Zum Inhalt springen|Aller au contenu)\]\(#[^)]*\)$`)
	reWikidataStandaloneWikiGo          = regexp.MustCompile(`(?i)^\[[^\]]{1,64}\]\(https?://(?:www\.)?wikidata\.org/wiki/Special:EntityPage/[^)]*\)$`)
	reFromWikipediaWikiGo               = regexp.MustCompile(`(?i)^(?:From Wikipedia, the free encyclopedia|Aus Wikipedia, der freien Enzyklopädie|Un article de Wikipédia, l'encyclopédie libre\.?)$`)
	reLanguageCountWikiGo               = regexp.MustCompile(`(?i)^\d{1,4}[ \t]+(?:languages|language|Sprachen|langues|idiomas|lingue)$`)
	reFlaggedRevsWikiGo                 = regexp.MustCompile(`(?i)^(?:\*{1,2})?(?:Checked|Gesichtet|Vérifié|Revisado)(?:\*{1,2})?$`)
	reWikidataEntityURLWikiGo           = regexp.MustCompile(`(?i)^https?://(?:www\.)?wikidata\.org/wiki/Special:EntityPage/`)
	reActionEditURLWikiGo               = regexp.MustCompile(`(?i)[?&]action=edit`)
	reCiteURLWikiGo                     = regexp.MustCompile(`(?i)(?:^#cite_(?:note|ref)|Wikipedia:(?:Citation_needed|Please_clarify|Disputed_statement))`)
	reCiteLabelWikiGo                   = regexp.MustCompile(`(?is)^(?:\d{1,4}|[a-z]|(?:note|nb|lower-alpha|upper-alpha)[ \t]*\d{1,3}|citation needed|clarification needed|when\?|who\?|dubious.{0,48})$`)
	reEditMarkerInnerWikiGo             = regexp.MustCompile(`(?i)^(?:edit|Bearbeiten(?:[ \t]*\|[ \t]*Quelltext bearbeiten)?|modifier(?:[ \t]*\|[ \t]*modifier le code)?|editar|citation needed|clarification needed|when\?|who\?|dubious[ \t]*[–-][ \t]*discuss)$`)
	reFnBacklinkWikiGo                  = regexp.MustCompile(`(?i)^\[\^[a-z0-9]{1,32}\][ \t]*`)
	nonEditionWikipediaSubdomainsWikiGo = map[string]bool{
		"www":        true,
		"m":          true,
		"zero":       true,
		"wap":        true,
		"mobile":     true,
		"login":      true,
		"auth":       true,
		"donate":     true,
		"thankyou":   true,
		"nostalgia":  true,
		"ten":        true,
		"test":       true,
		"test2":      true,
		"outreach":   true,
		"wikimania":  true,
		"foundation": true,
		"species":    true,
		"commons":    true,
		"meta":       true,
		"incubator":  true,
		"quality":    true,
		"strategy":   true,
		"usability":  true,
		"wg-en":      true,
	}
	disallowedWikipediaNamespacesWikiGo = map[string]bool{
		"special":                true,
		"talk":                   true,
		"user":                   true,
		"user_talk":              true,
		"wikipedia":              true,
		"wikipedia_talk":         true,
		"project":                true,
		"project_talk":           true,
		"file":                   true,
		"file_talk":              true,
		"image":                  true,
		"image_talk":             true,
		"media":                  true,
		"mediawiki":              true,
		"mediawiki_talk":         true,
		"template":               true,
		"template_talk":          true,
		"help":                   true,
		"help_talk":              true,
		"category":               true,
		"category_talk":          true,
		"portal":                 true,
		"portal_talk":            true,
		"draft":                  true,
		"draft_talk":             true,
		"timedtext":              true,
		"timedtext_talk":         true,
		"module":                 true,
		"module_talk":            true,
		"book":                   true,
		"book_talk":              true,
		"gadget":                 true,
		"gadget_talk":            true,
		"gadget_definition":      true,
		"topic":                  true,
		"spezial":                true,
		"diskussion":             true,
		"benutzer":               true,
		"benutzerin":             true,
		"benutzer_diskussion":    true,
		"datei":                  true,
		"datei_diskussion":       true,
		"vorlage":                true,
		"hilfe":                  true,
		"kategorie":              true,
		"spécial":                true,
		"discussion":             true,
		"utilisateur":            true,
		"utilisatrice":           true,
		"discussion_utilisateur": true,
		"fichier":                true,
		"modèle":                 true,
		"aide":                   true,
		"catégorie":              true,
		"portail":                true,
		"projet":                 true,
		"sujet":                  true,
		"especial":               true,
		"discusión":              true,
		"usuario":                true,
		"usuaria":                true,
		"usuario_discusión":      true,
		"archivo":                true,
		"plantilla":              true,
		"ayuda":                  true,
		"categoría":              true,
		"speciale":               true,
		"discussione":            true,
		"utente":                 true,
		"discussioni_utente":     true,
		"aiuto":                  true,
		"categoria":              true,
		"progetto":               true,
		"usuário":                true,
		"usuária":                true,
		"ficheiro":               true,
		"predefinição":           true,
		"ajuda":                  true,
		"特別":                     true,
		"ノート":                    true,
		"利用者":                    true,
		"ファイル":                   true,
		"служебная":              true,
		"обсуждение":             true,
		"участник":               true,
		"файл":                   true,
		"шаблон":                 true,
		"категория":              true,
	}
	stopLowerWordsWikiGo = map[string]bool{
		"of":   true,
		"the":  true,
		"in":   true,
		"on":   true,
		"and":  true,
		"for":  true,
		"to":   true,
		"a":    true,
		"an":   true,
		"by":   true,
		"at":   true,
		"from": true,
		"with": true,
	}
)

func hasSubdomainWikiGo(host, suffix string) bool {
	return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
}

// IsWikipediaHost reports whether rawHost is wikipedia.org or a subdomain of wikipedia.org.
func IsWikipediaHost(rawHost string) bool {
	h := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	return h == "wikipedia.org" || hasSubdomainWikiGo(h, ".wikipedia.org")
}

// IsWikimediaHost reports whether rawHost belongs to Wikipedia or a sister Wikimedia project domain.
func IsWikimediaHost(rawHost string) bool {
	h := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if h == "" {
		return false
	}
	return IsWikipediaHost(h) ||
		h == "wikimedia.org" || hasSubdomainWikiGo(h, ".wikimedia.org") ||
		h == "wiktionary.org" || hasSubdomainWikiGo(h, ".wiktionary.org") ||
		h == "wikibooks.org" || hasSubdomainWikiGo(h, ".wikibooks.org") ||
		h == "wikiquote.org" || hasSubdomainWikiGo(h, ".wikiquote.org") ||
		h == "wikisource.org" || hasSubdomainWikiGo(h, ".wikisource.org") ||
		h == "wikiversity.org" || hasSubdomainWikiGo(h, ".wikiversity.org") ||
		h == "wikivoyage.org" || hasSubdomainWikiGo(h, ".wikivoyage.org") ||
		h == "wikidata.org" || hasSubdomainWikiGo(h, ".wikidata.org") ||
		h == "mediawiki.org" || hasSubdomainWikiGo(h, ".mediawiki.org")
}

// ExtractWikipediaLangFromHost extracts the canonical language edition code from `<lang>.wikipedia.org`
// or `<lang>.m.wikipedia.org`, returning `""` for non-edition hosts (`www`, `meta`, `commons`, etc.).
func ExtractWikipediaLangFromHost(rawHost string) string {
	h := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if !hasSubdomainWikiGo(h, ".wikipedia.org") {
		return ""
	}
	sub := h[:len(h)-len(".wikipedia.org")]
	cleanSub := sub
	if strings.HasSuffix(sub, ".m") {
		cleanSub = sub[:len(sub)-2]
	}
	if cleanSub == "" || nonEditionWikipediaSubdomainsWikiGo[cleanSub] || !wikipediaLangReWikiGo.MatchString(cleanSub) {
		return ""
	}
	return cleanSub
}

// NormalizeWikipediaLang validates and normalizes a Wikipedia language code, returning fallback (default "en") when invalid.
func NormalizeWikipediaLang(rawLang, fallback string) string {
	if fallback == "" {
		fallback = "en"
	}
	clean := strings.ToLower(strings.TrimSpace(rawLang))
	if clean != "" && !nonEditionWikipediaSubdomainsWikiGo[clean] && wikipediaLangReWikiGo.MatchString(clean) {
		return clean
	}
	return fallback
}

func safeDecodeWikiSegmentWikiGo(seg string) string {
	if strings.IndexByte(seg, '%') < 0 {
		return seg
	}
	decoded, err := url.PathUnescape(seg)
	if err != nil || !utf8.ValidString(decoded) {
		return seg
	}
	return decoded
}

func hasUnsafeWikiTitlePathSegmentsWikiGo(rawOrDecoded string) bool {
	parts := strings.Split(rawOrDecoded, "/")
	for _, part := range parts {
		clean := strings.TrimSpace(part)
		if clean == "" || clean == "." || clean == ".." {
			return true
		}
		if rePercentDotOnlyWikiGo.MatchString(clean) {
			return true
		}
	}
	return false
}

func collapseSpacesToUnderscoreWikiGo(s string, collapseUnderscores bool) string {
	var b strings.Builder
	b.Grow(len(s))
	lastUnderscore := false
	inSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !inSpace {
				if !collapseUnderscores || !lastUnderscore {
					b.WriteByte('_')
					lastUnderscore = true
				}
				inSpace = true
			}
			continue
		}
		inSpace = false
		if r == '_' {
			if collapseUnderscores && lastUnderscore {
				continue
			}
			b.WriteByte('_')
			lastUnderscore = true
			continue
		}
		lastUnderscore = false
		b.WriteRune(r)
	}
	return b.String()
}

func collapseWikiTitleSpacesWikiGo(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for _, r := range s {
		if r == '_' || unicode.IsSpace(r) {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func upperFirstRuneWikiGo(s string) string {
	if s == "" {
		return ""
	}
	r, width := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && width <= 1 {
		return s
	}
	return strings.ToUpper(string(r)) + s[width:]
}

func isWikiPathUnescapedByteWikiGo(c byte) bool {
	if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
		return true
	}
	switch c {
	case '-', '_', '.', '!', '~', '*', '\'', '(', ')', ':', ',':
		return true
	}
	return false
}

func encodeWikiSegmentPartWikiGo(part string) string {
	const hexUpper = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(part) + 8)
	for i := 0; i < len(part); i++ {
		c := part[i]
		if isWikiPathUnescapedByteWikiGo(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&0x0F])
		}
	}
	return b.String()
}

func encodeCanonicalWikiTitlePathWikiGo(decodedTitle string) string {
	trimmed := strings.TrimSpace(decodedTitle)
	underscored := collapseSpacesToUnderscoreWikiGo(trimmed, true)
	if underscored == "" || strings.HasPrefix(underscored, ":") || hasUnsafeWikiTitlePathSegmentsWikiGo(underscored) {
		return ""
	}
	titled := upperFirstRuneWikiGo(underscored)
	segments := strings.Split(titled, "/")
	for i, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return ""
		}
		segments[i] = encodeWikiSegmentPartWikiGo(seg)
	}
	return strings.Join(segments, "/")
}

// IsDisallowedWikipediaTitle reports whether decodedTitle is empty, contains unsafe path segments,
// or targets a non-article MediaWiki namespace (`Special:`, `Talk:`, `User:`, `Wikipedia:`, `File:`, localized equivalents, etc.).
func IsDisallowedWikipediaTitle(decodedTitle string) bool {
	rawTrimmed := strings.TrimSpace(decodedTitle)
	if rawTrimmed == "" || strings.HasPrefix(rawTrimmed, ":") || hasUnsafeWikiTitlePathSegmentsWikiGo(rawTrimmed) {
		return true
	}
	trimmed := strings.TrimLeft(collapseSpacesToUnderscoreWikiGo(rawTrimmed, false), "_")
	if trimmed == "" || strings.HasPrefix(trimmed, ":") {
		return true
	}
	colonIdx := strings.IndexByte(trimmed, ':')
	if colonIdx <= 0 {
		return false
	}
	prefix := strings.ToLower(strings.TrimRight(trimmed[:colonIdx], "_"))
	if prefix == "" {
		return true
	}
	if disallowedWikipediaNamespacesWikiGo[prefix] {
		return true
	}
	if strings.HasSuffix(prefix, "_talk") || strings.HasSuffix(prefix, "_diskussion") || strings.HasSuffix(prefix, "_discusión") {
		return true
	}
	return false
}

type queryPairWikiGo struct {
	key string
	val string
}

type rawWikiURLPartsWikiGo struct {
	scheme        string
	hostname      string
	pathname      string
	rawSearch     string
	queryPairs    []queryPairWikiGo
	sectionAnchor string
}

func decodeFormComponentWikiGo(raw string) string {
	replaced := strings.ReplaceAll(raw, "+", " ")
	if strings.IndexByte(replaced, '%') < 0 {
		return replaced
	}
	var out strings.Builder
	out.Grow(len(replaced))
	for i := 0; i < len(replaced); i++ {
		if replaced[i] == '%' && i+2 < len(replaced) {
			hi := hexValWikiGo(replaced[i+1])
			lo := hexValWikiGo(replaced[i+2])
			if hi >= 0 && lo >= 0 {
				out.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		out.WriteByte(replaced[i])
	}
	s := out.String()
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

func hexValWikiGo(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

func parseRawWikiURLPartsWikiGo(rawURL string) *rawWikiURLPartsWikiGo {
	s := strings.TrimSpace(rawURL)
	if s == "" {
		return nil
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7F {
			return nil
		}
	}

	var scheme, rest string
	if len(s) > 8 && strings.EqualFold(s[:8], "https://") {
		scheme = "https"
		rest = s[8:]
	} else if len(s) > 7 && strings.EqualFold(s[:7], "http://") {
		scheme = "http"
		rest = s[7:]
	} else {
		return nil
	}

	var rawFragment string
	if hashIdx := strings.IndexByte(rest, '#'); hashIdx >= 0 {
		rawFragment = rest[hashIdx+1:]
		rest = rest[:hashIdx]
	}

	var rawSearch string
	if qIdx := strings.IndexByte(rest, '?'); qIdx >= 0 {
		qPart := rest[qIdx+1:]
		if qPart != "" {
			rawSearch = "?" + qPart
		}
		rest = rest[:qIdx]
	}

	var authority, pathname string
	if slashIdx := strings.IndexByte(rest, '/'); slashIdx >= 0 {
		authority = rest[:slashIdx]
		pathname = rest[slashIdx:]
	} else {
		authority = rest
		pathname = "/"
	}

	if authority == "" || strings.ContainsAny(authority, "@\\") {
		return nil
	}
	if colonIdx := strings.IndexByte(authority, ':'); colonIdx >= 0 {
		port := authority[colonIdx+1:]
		authority = authority[:colonIdx]
		if !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
			return nil
		}
	}
	if authority == "" {
		return nil
	}

	var pairs []queryPairWikiGo
	if len(rawSearch) > 1 {
		for _, seg := range strings.Split(rawSearch[1:], "&") {
			if seg == "" {
				continue
			}
			var k, v string
			if eq := strings.IndexByte(seg, '='); eq >= 0 {
				k = decodeFormComponentWikiGo(seg[:eq])
				v = decodeFormComponentWikiGo(seg[eq+1:])
			} else {
				k = decodeFormComponentWikiGo(seg)
			}
			pairs = append(pairs, queryPairWikiGo{key: k, val: v})
		}
	}

	anchor := ""
	if rawFragment != "" {
		anchor = strings.TrimSpace(safeDecodeWikiSegmentWikiGo(rawFragment))
	}

	return &rawWikiURLPartsWikiGo{
		scheme:        scheme,
		hostname:      authority,
		pathname:      pathname,
		rawSearch:     rawSearch,
		queryPairs:    pairs,
		sectionAnchor: anchor,
	}
}

func getAllQueryParamsWikiGo(pairs []queryPairWikiGo, key string) []string {
	var out []string
	for _, p := range pairs {
		if p.key == key {
			out = append(out, p.val)
		}
	}
	return out
}

func lastQueryParamWikiGo(pairs []queryPairWikiGo, key string) (string, bool) {
	vals := getAllQueryParamsWikiGo(pairs, key)
	if len(vals) == 0 {
		return "", false
	}
	return vals[len(vals)-1], true
}

func parsePositiveWikiNumericIDWikiGo(raw string) string {
	m := rePositiveNumericIDWikiGo.FindStringSubmatch(strings.TrimSpace(raw))
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// ParseWikipediaArticleURL parses and canonicalizes a Wikipedia article URL (`https://<lang>.wikipedia.org/wiki/<Title>`,
// mobile `<lang>.m.wikipedia.org`, and `/w/index.php?title=` or `?oldid=`/`?curid=`), returning nil for non-Wikipedia URLs,
// credentials, `/w/api.php`, `/w/rest.php`, non-view/render actions, diffs, traversal paths, or disallowed namespaces.
func ParseWikipediaArticleURL(rawURL string) *ParsedWikipediaArticle {
	u := parseRawWikiURLPartsWikiGo(rawURL)
	if u == nil {
		return nil
	}
	lang := ExtractWikipediaLangFromHost(u.hostname)
	if lang == "" {
		return nil
	}
	host := lang + ".wikipedia.org"

	if u.rawSearch != "" {
		if reQueryDisallowedWikiGo.MatchString(u.rawSearch) {
			return nil
		}
		for _, rawAct := range getAllQueryParamsWikiGo(u.queryPairs, "action") {
			act := strings.ToLower(strings.TrimSpace(rawAct))
			if act != "" && act != "view" && act != "render" {
				return nil
			}
		}
	}

	var rawTitleCandidate string
	isWikiPath := strings.HasPrefix(u.pathname, "/wiki/") && len(u.pathname) > len("/wiki/")
	isIndexScriptPath := u.pathname == "/" ||
		u.pathname == "/w" ||
		u.pathname == "/w/" ||
		u.pathname == "/w/index.php" ||
		u.pathname == "/index.php"

	if isWikiPath {
		rawSlug := strings.TrimRight(u.pathname[len("/wiki/"):], "/")
		if rawSlug == "" || hasUnsafeWikiTitlePathSegmentsWikiGo(rawSlug) {
			return nil
		}
		rawDecodedSlug := safeDecodeWikiSegmentWikiGo(rawSlug)
		if rawDecodedSlug == "" || hasUnsafeWikiTitlePathSegmentsWikiGo(rawDecodedSlug) {
			return nil
		}
		rawTitleCandidate = rawDecodedSlug
		for _, qt := range getAllQueryParamsWikiGo(u.queryPairs, "title") {
			cleanQt := collapseWikiTitleSpacesWikiGo(qt)
			if cleanQt == "" || hasUnsafeWikiTitlePathSegmentsWikiGo(qt) || IsDisallowedWikipediaTitle(cleanQt) {
				return nil
			}
		}
	} else if isIndexScriptPath && u.rawSearch != "" {
		for _, qt := range getAllQueryParamsWikiGo(u.queryPairs, "title") {
			cleanQt := collapseWikiTitleSpacesWikiGo(qt)
			if cleanQt != "" && (hasUnsafeWikiTitlePathSegmentsWikiGo(qt) || IsDisallowedWikipediaTitle(cleanQt)) {
				return nil
			}
		}
		queryTitle, hasTitle := lastQueryParamWikiGo(u.queryPairs, "title")
		if hasTitle && strings.TrimSpace(queryTitle) != "" {
			if hasUnsafeWikiTitlePathSegmentsWikiGo(queryTitle) {
				return nil
			}
			rawTitleCandidate = queryTitle
		} else {
			rawOld, _ := lastQueryParamWikiGo(u.queryPairs, "oldid")
			rawCur, _ := lastQueryParamWikiGo(u.queryPairs, "curid")
			oldNum := parsePositiveWikiNumericIDWikiGo(rawOld)
			curNum := parsePositiveWikiNumericIDWikiGo(rawCur)
			resolvedID := oldNum
			paramName := "oldid"
			if resolvedID == "" {
				resolvedID = curNum
				paramName = "curid"
			}
			if resolvedID != "" {
				revTitle := "Revision " + resolvedID
				underTitle := "Revision_" + resolvedID
				return &ParsedWikipediaArticle{
					CanonicalURL:     "https://" + host + "/w/index.php?" + paramName + "=" + resolvedID,
					Host:             host,
					Lang:             lang,
					Title:            revTitle,
					EncodedTitle:     underTitle,
					SectionAnchor:    u.sectionAnchor,
					CanonicalTitle:   revTitle,
					UnderscoredTitle: underTitle,
				}
			}
			return nil
		}
	} else {
		return nil
	}

	decoded := collapseWikiTitleSpacesWikiGo(rawTitleCandidate)
	if decoded == "" || IsDisallowedWikipediaTitle(decoded) {
		return nil
	}
	encodedSlug := encodeCanonicalWikiTitlePathWikiGo(decoded)
	if encodedSlug == "" {
		return nil
	}
	canonicalURL := "https://" + host + "/wiki/" + encodedSlug
	parsedCheck, err := url.Parse(canonicalURL)
	if err != nil || parsedCheck.EscapedPath() != "/wiki/"+encodedSlug {
		return nil
	}
	canonicalTitle := upperFirstRuneWikiGo(decoded)
	underscoredTitle := strings.ReplaceAll(canonicalTitle, " ", "_")
	return &ParsedWikipediaArticle{
		CanonicalURL:     canonicalURL,
		Host:             host,
		Lang:             lang,
		Title:            canonicalTitle,
		EncodedTitle:     encodedSlug,
		SectionAnchor:    u.sectionAnchor,
		CanonicalTitle:   canonicalTitle,
		UnderscoredTitle: underscoredTitle,
	}
}

var reWikiTitleSuffixWikiGo = regexp.MustCompile(`(?i)\s+[–—-]\s+(?:Wikipedia|Wikipédia|Wikipedie|Wikipédia,.*|Wikipedia,.*)$`)

// ResolveWikipediaCanonicalFinalURL resolves the canonical `https://<lang>.wikipedia.org/wiki/<Title>` URL
// from requestedURL and responseFinalURL.
func ResolveWikipediaCanonicalFinalURL(requestedURL, responseFinalURL string) string {
	return ResolveWikipediaCanonicalFinalURLFull(requestedURL, responseFinalURL, "", "")
}

// ResolveWikipediaCanonicalFinalURLFull resolves the canonical Wikipedia article URL from requestedURL,
// storedFinalURL, cached title, and cached Markdown H1 (upgrading `oldid`/`curid` or redirect hits to canonical `/wiki/<Title>`).
func ResolveWikipediaCanonicalFinalURLFull(requestedURL, storedFinalURL, title, markdown string) string {
	reqTrim := strings.TrimSpace(requestedURL)
	finTrim := strings.TrimSpace(storedFinalURL)
	if finTrim != "" && finTrim != reqTrim {
		if parsedFin := ParseWikipediaArticleURL(finTrim); parsedFin != nil {
			return parsedFin.CanonicalURL
		}
		return finTrim
	}
	reqWiki := ParseWikipediaArticleURL(reqTrim)
	if reqWiki == nil {
		if finTrim != "" {
			return finTrim
		}
		return reqTrim
	}
	if t := strings.TrimSpace(title); t != "" {
		stripped := strings.TrimSpace(reWikiTitleSuffixWikiGo.ReplaceAllString(t, ""))
		if stripped != "" && !IsDisallowedWikipediaTitle(stripped) {
			if slug := encodeCanonicalWikiTitlePathWikiGo(stripped); slug != "" {
				if cand := ParseWikipediaArticleURL("https://" + reqWiki.Host + "/wiki/" + slug); cand != nil {
					return cand.CanonicalURL
				}
			}
		}
	}
	if strings.HasPrefix(markdown, "# ") {
		h1 := markdown[2:]
		if nl := strings.IndexByte(h1, '\n'); nl >= 0 {
			h1 = h1[:nl]
		}
		h1 = strings.TrimSpace(h1)
		if h1 != "" && !strings.Contains(h1, "[") && !IsDisallowedWikipediaTitle(h1) {
			if slug := encodeCanonicalWikiTitlePathWikiGo(h1); slug != "" {
				if cand := ParseWikipediaArticleURL("https://" + reqWiki.Host + "/wiki/" + slug); cand != nil {
					return cand.CanonicalURL
				}
			}
		}
	}
	if finTrim != "" {
		return finTrim
	}
	return reqTrim
}

func utf16LenWikiGo(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// BuildWikipediaDirectTitleGuessURL builds a direct-title guess URL (`https://<lang>.wikipedia.org/wiki/<Title>`)
// only when rawQuery looks like a concise article title (`<= 6` words, `<= 120` chars, no search operators or disallowed namespaces).
func BuildWikipediaDirectTitleGuessURL(rawQuery, lang string) string {
	q := strings.TrimSpace(rawQuery)
	if q == "" || utf16LenWikiGo(q) > 120 {
		return ""
	}
	if reGuessDisallowedWikiGo.MatchString(q) {
		return ""
	}
	words := strings.Fields(q)
	if len(words) == 0 || len(words) > 6 {
		return ""
	}
	if IsDisallowedWikipediaTitle(q) {
		return ""
	}
	safeLang := NormalizeWikipediaLang(lang, "en")

	casedWords := make([]string, len(words))
	for idx, w := range words {
		_, firstWidth := utf8.DecodeRuneInString(w)
		rest := w[firstWidth:]
		if reGuessUpperOrPunctWikiGo.MatchString(rest) || reGuessAllUpperDigitWikiGo.MatchString(w) {
			if idx == 0 {
				casedWords[idx] = upperFirstRuneWikiGo(w)
			} else {
				casedWords[idx] = w
			}
			continue
		}
		low := strings.ToLower(w)
		if idx > 0 && stopLowerWordsWikiGo[low] {
			casedWords[idx] = low
		} else {
			casedWords[idx] = upperFirstRuneWikiGo(low)
		}
	}

	encoded := encodeCanonicalWikiTitlePathWikiGo(strings.Join(casedWords, " "))
	if encoded == "" {
		return ""
	}
	candidate := "https://" + safeLang + ".wikipedia.org/wiki/" + encoded
	if parsed := ParseWikipediaArticleURL(candidate); parsed != nil {
		return parsed.CanonicalURL
	}
	return ""
}

// BuildWikimediaRobotsSuggestion returns an actionable RFC 9309-compliant guidance message when a caller hits
// robots-disallowed Wikimedia search or API paths.
func BuildWikimediaRobotsSuggestion(rawHost string) string {
	h := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	lang := ExtractWikipediaLangFromHost(h)
	if lang == "" {
		lang = "en"
	}
	wikiHost := lang + ".wikipedia.org"
	return "Wikipedia search and API paths are robots-disallowed. Use `search` with `site:" + wikiHost + "` (or `wikipedia: true`), " +
		"or fetch `https://" + wikiHost + "/wiki/<Title>` directly. For bulk or structured corpus access, use Wikimedia Enterprise " +
		"(" + wikimediaEnterpriseURLWikiGo + ") or Wikimedia Dumps (" + wikimediaDumpsURLWikiGo + ")."
}

func capUTF8BytesWikiGo(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

func parseFenceLineWikiGo(ln string) (fenceChar byte, fenceLen int, rest string, ok bool) {
	i := 0
	for i < len(ln) && i < 3 && (ln[i] == ' ' || ln[i] == '\t') {
		i++
	}
	if i >= len(ln) || (ln[i] != '`' && ln[i] != '~') {
		return 0, 0, "", false
	}
	ch := ln[i]
	start := i
	for i < len(ln) && ln[i] == ch {
		i++
	}
	if i-start < 3 {
		return 0, 0, "", false
	}
	tail := strings.TrimSuffix(ln[i:], "\r")
	return ch, i - start, tail, true
}

func isHorizontalSpacesOnlyWikiGo(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			return false
		}
	}
	return true
}

func stripMediaWikiInlineLinksLinearWikiGo(ln string) string {
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
		relMid := strings.Index(ln[searchPos:], "](")
		if relMid < 0 {
			break
		}
		mid := searchPos + relMid

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
				linkURL := ln[mid+2 : endParen]
				isWikidataSitelink := !hasDoubleOpen && reWikidataEntityURLWikiGo.MatchString(linkURL)
				isActionEdit := reActionEditURLWikiGo.MatchString(linkURL)
				isCiteLink := reCiteURLWikiGo.MatchString(linkURL) && reCiteLabelWikiGo.MatchString(label)

				if isWikidataSitelink || isActionEdit || isCiteLink {
					cutStart := openStart
					if isWikidataSitelink || isActionEdit {
						for cutStart > lastEmit && (ln[cutStart-1] == ' ' || ln[cutStart-1] == '\t') {
							cutStart--
						}
					}
					if lastEmit == 0 {
						out.Grow(n)
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

func isWordByteWikiGo(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func hasFoldWordPrefixWikiGo(s, prefixLower string) bool {
	if len(s) < len(prefixLower) {
		return false
	}
	for i := 0; i < len(prefixLower); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		if c != prefixLower[i] {
			return false
		}
	}
	return len(s) == len(prefixLower) || !isWordByteWikiGo(s[len(prefixLower)])
}

func isFooterCutLineWikiGo(trimmed string) bool {
	if len(trimmed) < 5 {
		return false
	}
	s := trimmed
	if s[0] == '#' {
		if len(s) < 7 || s[1] != '#' {
			return false
		}
		k := 2
		for k < len(s) && s[k] == '#' {
			k++
		}
		if k >= len(s) || (s[k] != ' ' && s[k] != '\t') {
			return false
		}
		for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
			k++
		}
		s = s[k:]
	}
	if len(s) < 5 {
		return false
	}
	switch s[0] | 0x20 {
	case 'n':
		return hasFoldWordPrefixWikiGo(s, "navigation menu") || hasFoldWordPrefixWikiGo(s, "namespaces")
	case 'v':
		return hasFoldWordPrefixWikiGo(s, "views")
	case 'p':
		return hasFoldWordPrefixWikiGo(s, "personal tools")
	default:
		return false
	}
}

func isFootMarkerInnerWikiGo(inner string) bool {
	n := len(inner)
	if n == 0 || n > 12 {
		return false
	}
	c0 := inner[0]
	if c0 >= '0' && c0 <= '9' {
		if n > 4 {
			return false
		}
		for i := 1; i < n; i++ {
			if inner[i] < '0' || inner[i] > '9' {
				return false
			}
		}
		return true
	}
	if (c0 | 0x20) != 'n' {
		return false
	}
	k := 0
	if n >= 5 && strings.EqualFold(inner[:4], "note") {
		k = 4
	} else if n >= 3 && strings.EqualFold(inner[:2], "nb") {
		k = 2
	} else {
		return false
	}
	for k < n && (inner[k] == ' ' || inner[k] == '\t') {
		k++
	}
	digits := n - k
	if digits < 1 || digits > 3 {
		return false
	}
	for i := k; i < n; i++ {
		if inner[i] < '0' || inner[i] > '9' {
			return false
		}
	}
	return true
}

func isEditMarkerInnerFastWikiGo(inner string) bool {
	n := len(inner)
	if n < 4 || n > 44 {
		return false
	}
	switch inner[0] | 0x20 {
	case 'e':
		return strings.EqualFold(inner, "edit") || strings.EqualFold(inner, "editar")
	case 'c':
		return strings.EqualFold(inner, "citation needed") || strings.EqualFold(inner, "clarification needed")
	case 'w':
		return strings.EqualFold(inner, "when?") || strings.EqualFold(inner, "who?")
	case 'b', 'm', 'd':
		return reEditMarkerInnerWikiGo.MatchString(inner)
	default:
		return false
	}
}

func isChromeStandaloneLineWikiGo(trimmed string, lineIdx int) bool {
	n := len(trimmed)
	if n == 0 || n > 200 || trimmed[0] == '|' {
		return false
	}
	c0 := trimmed[0]
	if c0 == '[' {
		if n >= 2 && trimmed[n-1] == ']' && isHorizontalSpacesOnlyWikiGo(trimmed[1:n-1]) {
			return true
		}
		if trimmed[n-1] == ')' {
			if strings.Contains(trimmed, "wikidata.org/wiki/Special:EntityPage/") && reWikidataStandaloneWikiGo.MatchString(trimmed) {
				return true
			}
			if strings.Contains(trimmed, "(#") && reJumpToContentWikiGo.MatchString(trimmed) {
				return true
			}
		}
		return false
	}
	if c0 >= '0' && c0 <= '9' {
		return n <= 24 && reLanguageCountWikiGo.MatchString(trimmed)
	}
	switch c0 | 0x20 {
	case 'e':
		return strings.EqualFold(trimmed, "edit links") || strings.EqualFold(trimmed, "editar enlaces")
	case 'l':
		return strings.EqualFold(trimmed, "links bearbeiten")
	case 'm':
		return strings.EqualFold(trimmed, "modifier les liens") || strings.EqualFold(trimmed, "modifica link") || strings.EqualFold(trimmed, "move to sidebar")
	case 't':
		return strings.EqualFold(trimmed, "toggle the table of contents")
	case 'h':
		return strings.EqualFold(trimmed, "hide")
	case 'f':
		return strings.EqualFold(trimmed, "from wikipedia, the free encyclopedia")
	case 'a':
		return n <= 64 && reFromWikipediaWikiGo.MatchString(trimmed)
	case 'u':
		return n <= 64 && reFromWikipediaWikiGo.MatchString(trimmed)
	}
	if lineIdx < 40 && n <= 16 && (c0 == '*' || (c0|0x20) == 'c' || (c0|0x20) == 'g' || (c0|0x20) == 'v' || (c0|0x20) == 'r') {
		return reFlaggedRevsWikiGo.MatchString(trimmed)
	}
	return false
}

func stripBracketMarkersSinglePassWikiGo(ln string) string {
	// Single linear pass handling:
	//  - `[ \t]*\[[ \t]*\](?![(:])` (strips preceding spaces/tabs)
	//  - `[ \t]*\[<edit/citation marker>\](?![(:])` (strips preceding spaces/tabs)
	//  - `\[<footnote number>\](?![(:])` (preserves preceding whitespace)
	if strings.IndexByte(ln, '[') < 0 || strings.IndexByte(ln, ']') < 0 {
		return ln
	}
	var out strings.Builder
	lastEmit := 0
	pos := 0
	n := len(ln)

	for pos < n {
		relOpen := strings.IndexByte(ln[pos:], '[')
		if relOpen < 0 {
			break
		}
		openIdx := pos + relOpen
		scanEnd := openIdx + 80
		if scanEnd > n {
			scanEnd = n
		}
		closeIdx := -1
		nestedOpen := -1
		for k := openIdx + 1; k < scanEnd; k++ {
			if ln[k] == '[' {
				nestedOpen = k
				break
			}
			if ln[k] == ']' {
				closeIdx = k
				break
			}
		}
		if nestedOpen >= 0 {
			pos = nestedOpen
			continue
		}
		if closeIdx < 0 {
			pos = openIdx + 1
			continue
		}
		if closeIdx+1 < n && (ln[closeIdx+1] == '(' || ln[closeIdx+1] == ':') {
			pos = closeIdx + 1
			continue
		}

		inner := ln[openIdx+1 : closeIdx]
		stripPrecedingWS := false
		matched := false
		if isHorizontalSpacesOnlyWikiGo(inner) {
			matched = true
			stripPrecedingWS = true
		} else if isFootMarkerInnerWikiGo(inner) {
			matched = true
		} else if isEditMarkerInnerFastWikiGo(inner) {
			matched = true
			stripPrecedingWS = true
		}

		if matched {
			cutStart := openIdx
			if stripPrecedingWS {
				for cutStart > lastEmit && (ln[cutStart-1] == ' ' || ln[cutStart-1] == '\t') {
					cutStart--
				}
			}
			if lastEmit == 0 {
				out.Grow(n)
			}
			out.WriteString(ln[lastEmit:cutStart])
			lastEmit = closeIdx + 1
			pos = closeIdx + 1
			continue
		}
		pos = closeIdx + 1
	}

	if lastEmit == 0 {
		return ln
	}
	out.WriteString(ln[lastEmit:])
	return out.String()
}

// CleanMediaWikiMarkdown performs fence-aware linear O(N) cleanup of MediaWiki Markdown (`< 5ms` on 2 MiB),
// stripping `[ ]` checkboxes, `"Edit links"`, Wikidata sitelinks, `[1][2]` footnote markers, `[edit]` links,
// Vector 2022 UI chrome, reference back-link letter chains, and trailing navigation menus while preserving tables and code fences.
func CleanMediaWikiMarkdown(rawMD string) string {
	bounded := capUTF8BytesWikiGo(rawMD, maxMediaWikiMarkdownBytesWikiGo)
	var out strings.Builder
	out.Grow(len(bounded))

	inFence := false
	var fenceChar byte
	fenceLen := 0
	hasEmitted := false
	pendingBlankLines := 0
	lineIdx := 0

	emitLine := func(ln string) {
		if !inFence && strings.TrimSpace(ln) == "" {
			if hasEmitted {
				pendingBlankLines++
			}
			return
		}
		if hasEmitted {
			if pendingBlankLines > 0 {
				out.WriteString("\n\n")
				pendingBlankLines = 0
			} else {
				out.WriteByte('\n')
			}
		}
		out.WriteString(ln)
		hasEmitted = true
	}

	cursor := 0
	n := len(bounded)
	for cursor <= n {
		var ln string
		relNL := strings.IndexByte(bounded[cursor:], '\n')
		if relNL < 0 {
			ln = bounded[cursor:]
			cursor = n + 1
		} else {
			ln = bounded[cursor : cursor+relNL]
			cursor += relNL + 1
		}
		i := lineIdx
		lineIdx++

		if fc, fl, rest, isFence := parseFenceLineWikiGo(ln); isFence {
			if !inFence {
				if !(fc == '`' && strings.IndexByte(rest, '`') >= 0) {
					emitLine(ln)
					inFence = true
					fenceChar = fc
					fenceLen = fl
					continue
				}
			} else if fc == fenceChar && fl >= fenceLen && isHorizontalSpacesOnlyWikiGo(rest) {
				inFence = false
				fenceChar = 0
				fenceLen = 0
				emitLine(ln)
				continue
			}
		}
		if inFence {
			if hasEmitted {
				for pendingBlankLines > 0 {
					out.WriteByte('\n')
					pendingBlankLines--
				}
				out.WriteByte('\n')
			}
			out.WriteString(ln)
			hasEmitted = true
			continue
		}

		trimmed := strings.TrimSpace(ln)
		if isFooterCutLineWikiGo(trimmed) {
			break
		}

		if isChromeStandaloneLineWikiGo(trimmed, i) {
			continue
		}

		if strings.IndexByte(ln, '[') >= 0 && strings.IndexByte(ln, ']') >= 0 {
			ln = stripMediaWikiInlineLinksLinearWikiGo(ln)
			ln = stripBracketMarkersSinglePassWikiGo(ln)
		}

		if len(ln) > 0 {
			// Fast check for `^` backlink lines before allocating TrimSpace
			firstNonWS := 0
			for firstNonWS < len(ln) && (ln[firstNonWS] == ' ' || ln[firstNonWS] == '\t') {
				firstNonWS++
			}
			if firstNonWS < len(ln) && ln[firstNonWS] == '^' {
				caretIdx := firstNonWS
				p := caretIdx + 1
				for p < len(ln) && (ln[p] == ' ' || ln[p] == '\t') {
					p++
				}
				if p > caretIdx+1 {
					restAfterCaret := ln[p:]
					if loc := reFnBacklinkWikiGo.FindStringIndex(restAfterCaret); loc != nil {
						ln = "^ " + restAfterCaret[loc[1]:]
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
		}

		if len(trimmed) > 0 && strings.TrimSpace(ln) == "" {
			continue
		}

		emitLine(ln)
	}

	return strings.TrimSpace(out.String())
}
