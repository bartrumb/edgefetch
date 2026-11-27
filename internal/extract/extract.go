package extract

import (
	"html"
	"math"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
)

// ImageInfo describes an image discovered on a page.
type ImageInfo struct {
	URL string `json:"url"`
	Alt string `json:"alt,omitempty"`
}

// BrandingProfile summarizes visual brand identity signals extracted from HTML/CSS (`formats: ["branding"]`).
type BrandingProfile struct {
	Title        string   `json:"title,omitempty"`
	Description  string   `json:"description,omitempty"`
	CanonicalURL string   `json:"canonicalUrl,omitempty"`
	Favicon      string   `json:"favicon,omitempty"`
	Logo         string   `json:"logo,omitempty"`
	OGImage      string   `json:"ogImage,omitempty"`
	ThemeColor   string   `json:"themeColor,omitempty"`
	Colors       []string `json:"colors,omitempty"`
	Fonts        []string `json:"fonts,omitempty"`
}

// PageExtraction holds the structured outputs extracted from an HTML document.
type PageExtraction struct {
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Favicon     string           `json:"favicon,omitempty"`
	Markdown    string           `json:"markdown,omitempty"`
	Text        string           `json:"text,omitempty"`
	Links       []string         `json:"links,omitempty"`
	Images      []ImageInfo      `json:"images,omitempty"`
	Branding    *BrandingProfile `json:"branding,omitempty"`
}

// ExtractOptions configures HTML extraction.
type ExtractOptions struct {
	BaseURL         string
	OnlyMainContent bool
	IncludeLinks    bool
	IncludeImages   bool
	IncludeBranding bool
	RedactPII       bool
	Query           string
	MaxChars        int
}

var (
	reHTMLComment = newLazyRegexp(`(?is)<!--.*?-->`)
	reDropBlocks  = []*lazyRegexp{
		newLazyRegexp(`(?is)<head\b[^>]*>.*?</head>`),
		newLazyRegexp(`(?is)<script\b[^>]*>.*?</script>`),
		newLazyRegexp(`(?is)<style\b[^>]*>.*?</style>`),
		newLazyRegexp(`(?is)<noscript\b[^>]*>.*?</noscript>`),
		newLazyRegexp(`(?is)<template\b[^>]*>.*?</template>`),
		newLazyRegexp(`(?is)<svg\b[^>]*>.*?</svg>`),
		newLazyRegexp(`(?is)<canvas\b[^>]*>.*?</canvas>`),
		newLazyRegexp(`(?is)<iframe\b[^>]*>.*?</iframe>`),
	}
	reChromeBlocks = []*lazyRegexp{
		newLazyRegexp(`(?is)<nav\b[^>]*>.*?</nav>`),
		newLazyRegexp(`(?is)<footer\b[^>]*>.*?</footer>`),
		newLazyRegexp(`(?is)<aside\b[^>]*>.*?</aside>`),
	}
	reHeaderBlock  = newLazyRegexp(`(?is)<header\b[^>]*>.*?</header>`)
	reMainBlock    = newLazyRegexp(`(?is)<main\b[^>]*>(.*?)</main>`)
	reArticleBlock = newLazyRegexp(`(?is)<article\b[^>]*>(.*?)</article>`)
	reTitleTag     = newLazyRegexp(`(?is)<title\b[^>]*>(.*?)</title>`)
	reMetaTag      = newLazyRegexp(`(?is)<meta\b[^>]*>`)
	reLinkTag      = newLazyRegexp(`(?is)<link\b[^>]*>`)
	reStyleContent = newLazyRegexp(`(?is)<style\b[^>]*>(.*?)</style>`)
	reAttrPair     = newLazyRegexp(`(?is)([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)

	reAnchor    = newLazyRegexp(`(?is)<a\b([^>]*)>(.*?)</a>`)
	reImgTag    = newLazyRegexp(`(?is)<img\b([^>]*)>`)
	rePreCode   = newLazyRegexp(`(?is)<pre\b([^>]*)>\s*(?:<code\b([^>]*)>)?(.*?)(?:</code>)?\s*</pre>`)
	reCodeLang  = newLazyRegexp(`(?i)(?:\b(?:language|lang)-|\bdata-(?:language|lang)=["']?)([a-z0-9_+#-]+)\b`)
	reEcLine    = newLazyRegexp(`(?is)<div\b[^>]*\bec-line\b[^>]*>`)
	reInlineCd  = newLazyRegexp(`(?is)<code\b[^>]*>(.*?)</code>`)
	reHeading   = newLazyRegexp(`(?is)<h([1-6])\b[^>]*>(.*?)</h[1-6]>`)
	reStrong    = newLazyRegexp(`(?is)<strong\b[^>]*>(.*?)</strong>|<b\b[^>]*>(.*?)</b>`)
	reEm        = newLazyRegexp(`(?is)<em\b[^>]*>(.*?)</em>|<i\b[^>]*>(.*?)</i>`)
	reListItem  = newLazyRegexp(`(?is)<li\b[^>]*>(.*?)</li>`)
	reBlockquot = newLazyRegexp(`(?is)<blockquote\b[^>]*>(.*?)</blockquote>`)
	reTable     = newLazyRegexp(`(?is)<table\b[^>]*>(.*?)</table>`)
	reTableRow  = newLazyRegexp(`(?is)<tr\b[^>]*>(.*?)</tr>`)
	reTableCell = newLazyRegexp(`(?is)<t([hd])\b[^>]*>(.*?)</t[hd]>`)
	reBlockEnd  = newLazyRegexp(`(?is)</(p|div|section|article|main|ul|ol|dl|dd|dt|figure|figcaption|tr|header)>`)
	reBrHr      = newLazyRegexp(`(?is)<(br|hr)\b[^>]*/?>`)
	reAnyTag    = newLazyRegexp(`(?s)<[^>]+>`)
	reMultiLine = newLazyRegexp(`\n{3,}`)
	reSpaceRun  = newLazyRegexp(`[ \t]{2,}`)
	reDupLink   = newLazyRegexp(`(\[[^\]]+\]\((https?://[^)\s]+)\))[ \t]*\((https?://[^)\s]+)\)`)
	reDupInLink = newLazyRegexp(`\[([^\[\]\n]+?)[ \t]*\((https?://[^)\s]+)\)\]\((https?://[^)\s]+)\)`)

	reHexColor   = newLazyRegexp(`#[0-9a-fA-F]{6}\b`)
	reFontFamily = newLazyRegexp(`(?i)font-family\s*:\s*([^;}{]+)`)
	reGoogleFont = newLazyRegexp(`(?i)fonts\.googleapis\.com/css2?\?family=([^&"'\s>]+)`)

	reEmail = newLazyRegexp(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	reSSN   = newLazyRegexp(`\b\d{3}-\d{2}-\d{4}\b`)
	rePhone = newLazyRegexp(`(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\b\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b|\+\d{1,3}[-.\s]\d{2,4}[-.\s]\d{3,4}[-.\s]\d{3,4}\b`)
	reCard  = newLazyRegexp(`\b(?:\d[ -]*?){13,19}\b`)

	reSPAShell = newLazyRegexp(`(?i)<div[^>]+id=["']?(root|app|__next|__nuxt)["']?[^>]*>\s*</div>`)
)

// DetectRenderedChallenge checks whether an HTML payload (HTTP or headless browser) is gated by a bot/CAPTCHA challenge.
// Delegates to `classify.ClassifyWAF` (`R2` & `R3`) so all 4 anti-false-positive guardrails (visible word-count veto,
// Schema.org JSON-LD veto, `<pre>`/`<code>` immunity, and `<nav>` landmark veto) protect rendered pages too.
func DetectRenderedChallenge(rawHTML string) string {
	if waf := classify.ClassifyWAF(200, nil, []byte(rawHTML)); waf != nil {
		return waf.Summary
	}
	return ""
}

// NeedsBrowserRender heuristics detect empty client-side SPA shells (`<div id="root"></div>` + script bundles with
// almost zero SSR body text) so `renderMode: "auto"` only launches Chromium when static HTTP/2 lacks content.
func NeedsBrowserRender(rawHTML string) bool {
	if strings.TrimSpace(rawHTML) == "" {
		return false
	}
	text := PlainText(rawHTML)
	if len(text) >= 240 {
		return false
	}
	lower := strings.ToLower(rawHTML)
	hasScript := strings.Contains(lower, "<script")
	if !hasScript {
		return false
	}
	if reSPAShell.MatchString(rawHTML) {
		return true
	}
	return len(text) < 80 && (strings.Contains(lower, "type=\"module\"") || strings.Contains(lower, "/_next/static/") || strings.Contains(lower, "vite"))
}

// ExtractHTML parses rawHTML into clean Markdown, plain text, links, images, and optional branding profile.
func ExtractHTML(rawHTML string, opts ExtractOptions) PageExtraction {
	var base *url.URL
	if opts.BaseURL != "" {
		base, _ = url.Parse(opts.BaseURL)
	}

	meta := scanHeadMetadata(rawHTML, base)
	out := PageExtraction{
		Title:       meta.Title,
		Description: meta.Description,
		Favicon:     meta.Favicon,
	}

	if opts.IncludeBranding {
		b := meta
		b.Colors, b.Fonts = extractStyleSignals(rawHTML)
		out.Branding = &b
	}

	work := reHTMLComment.ReplaceAllString(rawHTML, "")
	if opts.OnlyMainContent {
		if m := reMainBlock.FindStringSubmatch(work); len(m) == 2 && len(PlainText(m[1])) >= 32 {
			work = m[1]
		} else if m := reArticleBlock.FindStringSubmatch(work); len(m) == 2 && len(PlainText(m[1])) >= 32 {
			work = m[1]
		} else {
			for _, rx := range reChromeBlocks {
				work = rx.ReplaceAllString(work, "")
			}
			work = reHeaderBlock.ReplaceAllString(work, "")
		}
	}
	for _, rx := range reDropBlocks {
		work = rx.ReplaceAllString(work, "")
	}

	if opts.IncludeLinks {
		out.Links = extractLinks(work, base)
	}
	if opts.IncludeImages {
		out.Images = extractImages(work, base)
	}

	md := htmlFragmentToMarkdown(work, base)
	if out.Title != "" && !strings.HasPrefix(md, "# ") {
		md = "# " + out.Title + "\n\n" + md
	}
	md = strings.TrimSpace(md)
	txt := markdownToPlainText(md)

	if strings.TrimSpace(opts.Query) != "" {
		limit := opts.MaxChars
		if limit <= 0 {
			limit = 16_000
		}
		md = RerankPassages(md, opts.Query, limit)
		txt = markdownToPlainText(md)
	}

	if opts.RedactPII {
		md = RedactPII(md)
		txt = RedactPII(txt)
	}
	if opts.MaxChars > 0 {
		if len(md) > opts.MaxChars {
			md = md[:opts.MaxChars]
		}
		if len(txt) > opts.MaxChars {
			txt = txt[:opts.MaxChars]
		}
	}

	out.Markdown = md
	out.Text = txt
	return out
}

// PlainText strips scripts/styles/tags from HTML and collapses whitespace.
func PlainText(rawHTML string) string {
	clean := reHTMLComment.ReplaceAllString(rawHTML, " ")
	for _, rx := range reDropBlocks {
		clean = rx.ReplaceAllString(clean, " ")
	}
	clean = reAnyTag.ReplaceAllString(clean, " ")
	clean = html.UnescapeString(clean)
	return strings.Join(strings.Fields(clean), " ")
}

func htmlFragmentToMarkdown(fragment string, base *url.URL) string {
	s := fragment

	// 1. Convert fenced <pre><code> and inline <code> blocks first so inner generics (`Promise<void>`, `#include <stdio.h>`)
	// and newlines are never stripped as HTML tags during subsequent passes.
	type placeholder struct {
		token string
		value string
	}
	var stash []placeholder
	s = rePreCode.ReplaceAllStringFunc(s, func(match string) string {
		sub := rePreCode.FindStringSubmatch(match)
		lang := ""
		inner := ""
		if len(sub) >= 4 {
			if lm := reCodeLang.FindStringSubmatch(sub[2] + " " + sub[1]); len(lm) == 2 {
				lang = strings.ToLower(lm[1])
			}
			inner = sub[3]
		}
		if strings.Contains(inner, "ec-line") && reEcLine.MatchString(inner) {
			noNewlines := strings.NewReplacer("\r\n", "", "\n", "").Replace(inner)
			inner = reEcLine.ReplaceAllString(noNewlines, "\n")
		}
		inner = reAnyTag.ReplaceAllString(inner, "")
		inner = strings.Trim(html.UnescapeString(inner), "\r\n")
		fence := "```"
		for strings.Contains(inner, fence) {
			fence += "`"
		}
		tok := "\x00CODEBLOCK_" + itoa(len(stash)) + "\x00"
		stash = append(stash, placeholder{token: tok, value: "\n\n" + fence + lang + "\n" + inner + "\n" + fence + "\n\n"})
		return tok
	})

	s = reInlineCd.ReplaceAllStringFunc(s, func(m string) string {
		sub := reInlineCd.FindStringSubmatch(m)
		if len(sub) < 2 {
			return ""
		}
		txt := cleanInline(sub[1])
		if txt == "" {
			return ""
		}
		tok := "\x00INLINECODE_" + itoa(len(stash)) + "\x00"
		stash = append(stash, placeholder{token: tok, value: formatInlineCodeSpan(txt)})
		return tok
	})

	// 2. Convert HTML <table> blocks into GFM Markdown tables (`| Col | Col |`).
	s = reTable.ReplaceAllStringFunc(s, func(tbl string) string {
		rows := reTableRow.FindAllStringSubmatch(tbl, -1)
		if len(rows) == 0 {
			return tbl
		}
		var grid [][]string
		maxCols := 0
		for _, r := range rows {
			cells := reTableCell.FindAllStringSubmatch(r[1], -1)
			if len(cells) == 0 {
				continue
			}
			row := make([]string, 0, len(cells))
			for _, c := range cells {
				txt := cleanInline(c[2])
				txt = strings.ReplaceAll(txt, "|", `\|`)
				row = append(row, txt)
			}
			if len(row) > maxCols {
				maxCols = len(row)
			}
			grid = append(grid, row)
		}
		if len(grid) == 0 || maxCols == 0 {
			return ""
		}
		var b strings.Builder
		b.WriteString("\n\n")
		for rIdx, row := range grid {
			for len(row) < maxCols {
				row = append(row, "")
			}
			b.WriteString("| ")
			b.WriteString(strings.Join(row, " | "))
			b.WriteString(" |\n")
			if rIdx == 0 {
				sep := make([]string, maxCols)
				for i := range sep {
					sep[i] = "---"
				}
				b.WriteString("| ")
				b.WriteString(strings.Join(sep, " | "))
				b.WriteString(" |\n")
			}
		}
		b.WriteString("\n")
		tok := "\x00TABLE_" + itoa(len(stash)) + "\x00"
		stash = append(stash, placeholder{token: tok, value: b.String()})
		return tok
	})

	// 3. Images, links, headings, emphasis, lists, blockquotes.

	stashURL := func(u string) string {
		tok := "\x00URL_" + itoa(len(stash)) + "\x00"
		stash = append(stash, placeholder{token: tok, value: u})
		return tok
	}

	s = reImgTag.ReplaceAllStringFunc(s, func(m string) string {
		attrs := parseAttrs(m)
		src := resolveHref(firstAttr(attrs, "src", "data-src"), base)
		if src == "" || strings.HasPrefix(src, "data:") {
			return ""
		}
		alt := strings.TrimSpace(html.UnescapeString(attrs["alt"]))
		return "![" + alt + "](" + stashURL(src) + ")"
	})

	s = reAnchor.ReplaceAllStringFunc(s, func(m string) string {
		sub := reAnchor.FindStringSubmatch(m)
		if len(sub) < 3 {
			return ""
		}
		attrs := parseAttrs(sub[1])
		href := resolveHref(attrs["href"], base)
		label := cleanInline(sub[2])
		if label == "" {
			return ""
		}
		if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "#") {
			return label
		}
		return "[" + label + "](" + stashURL(href) + ")"
	})

	s = reHeading.ReplaceAllStringFunc(s, func(m string) string {
		sub := reHeading.FindStringSubmatch(m)
		if len(sub) < 3 {
			return ""
		}
		level := int(sub[1][0] - '0')
		txt := cleanInline(sub[2])
		if txt == "" {
			return ""
		}
		return "\n\n" + strings.Repeat("#", level) + " " + txt + "\n\n"
	})

	s = reStrong.ReplaceAllStringFunc(s, func(m string) string {
		sub := reStrong.FindStringSubmatch(m)
		if len(sub) < 3 {
			return ""
		}
		inner := sub[1]
		if inner == "" {
			inner = sub[2]
		}
		txt := cleanInline(inner)
		if txt == "" {
			return ""
		}
		return "**" + txt + "**"
	})

	s = reEm.ReplaceAllStringFunc(s, func(m string) string {
		sub := reEm.FindStringSubmatch(m)
		if len(sub) < 3 {
			return ""
		}
		inner := sub[1]
		if inner == "" {
			inner = sub[2]
		}
		txt := cleanInline(inner)
		if txt == "" {
			return ""
		}
		return "*" + txt + "*"
	})

	s = reBlockquot.ReplaceAllStringFunc(s, func(m string) string {
		sub := reBlockquot.FindStringSubmatch(m)
		if len(sub) < 2 {
			return ""
		}
		txt := cleanInline(sub[1])
		if txt == "" {
			return ""
		}
		return "\n\n> " + txt + "\n\n"
	})

	s = reListItem.ReplaceAllStringFunc(s, func(m string) string {
		sub := reListItem.FindStringSubmatch(m)
		if len(sub) < 2 {
			return ""
		}
		txt := cleanInline(sub[1])
		if txt == "" {
			return ""
		}
		return "\n- " + txt
	})

	s = reBrHr.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(strings.ToLower(m), "<hr") {
			return "\n\n---\n\n"
		}
		return "\n"
	})
	s = reBlockEnd.ReplaceAllString(s, "\n\n")
	s = reAnyTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)

	lines := strings.Split(s, "\n")
	for i, line := range lines {
		line = strings.ReplaceAll(line, "\r", "")
		line = reSpaceRun.ReplaceAllString(strings.TrimSpace(line), " ")
		lines[i] = line
	}
	s = strings.Join(lines, "\n")
	for i := len(stash) - 1; i >= 0; i-- {
		s = strings.ReplaceAll(s, stash[i].token, stash[i].value)
	}
	s = reDupLink.ReplaceAllStringFunc(s, func(m string) string {
		sub := reDupLink.FindStringSubmatch(m)
		if len(sub) == 4 && sub[2] == sub[3] {
			return sub[1]
		}
		return m
	})
	s = reDupInLink.ReplaceAllStringFunc(s, func(m string) string {
		sub := reDupInLink.FindStringSubmatch(m)
		if len(sub) == 4 && sub[2] == sub[3] {
			return "[" + strings.TrimSpace(sub[1]) + "](" + sub[2] + ")"
		}
		return m
	})
	s = reMultiLine.ReplaceAllString(s, "\n\n")
	s = reInvisibleSmuggling.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

func formatInlineCodeSpan(txt string) string {
	maxRun := 0
	cur := 0
	for i := 0; i < len(txt); i++ {
		if txt[i] == '`' {
			cur++
			if cur > maxRun {
				maxRun = cur
			}
		} else {
			cur = 0
		}
	}
	delim := strings.Repeat("`", maxRun+1)
	if strings.HasPrefix(txt, "`") || strings.HasSuffix(txt, "`") {
		return delim + " " + txt + " " + delim
	}
	return delim + txt + delim
}

func markdownToPlainText(md string) string {
	var out []string
	for _, line := range strings.Split(md, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "```") || l == "---" {
			continue
		}
		l = strings.TrimLeft(l, "#>- ")
		out = append(out, l)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// RerankPassages splits long Markdown or PDF text into semantic paragraphs/sections and selects the top chunks matching
// `query` via BM25-style term scoring + exact-phrase boost while preserving original document reading order.
func RerankPassages(doc, query string, maxChars int) string {
	query = strings.TrimSpace(query)
	if query == "" || len(doc) == 0 {
		return doc
	}
	if maxChars <= 0 {
		maxChars = 12_000
	}
	terms := tokenize(query)
	if len(terms) == 0 {
		if len(doc) > maxChars {
			return doc[:maxChars]
		}
		return doc
	}

	rawBlocks := strings.Split(doc, "\n\n")
	type chunk struct {
		idx   int
		text  string
		score float64
	}
	var chunks []chunk
	currentHeading := ""
	for _, b := range rawBlocks {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		if strings.HasPrefix(b, "#") && !strings.Contains(b, "\n") {
			currentHeading = b
			continue
		}
		full := b
		if currentHeading != "" {
			full = currentHeading + "\n" + b
			currentHeading = ""
		}
		chunks = append(chunks, chunk{idx: len(chunks), text: full})
	}
	if len(chunks) <= 1 {
		if len(doc) > maxChars {
			return doc[:maxChars]
		}
		return doc
	}

	df := make(map[string]int, len(terms))
	chunkFreqs := make([]map[string]int, len(chunks))
	totalWords := 0
	for i, c := range chunks {
		words := tokenize(c.text)
		totalWords += len(words)
		freq := make(map[string]int)
		for _, w := range words {
			freq[w]++
		}
		chunkFreqs[i] = freq
		for _, t := range terms {
			if freq[t] > 0 {
				df[t]++
			}
		}
	}
	avgLen := math.Max(1.0, float64(totalWords)/float64(len(chunks)))
	nDocs := float64(len(chunks))
	lowerQuery := strings.ToLower(query)

	for i := range chunks {
		freq := chunkFreqs[i]
		docLen := 0
		for _, c := range freq {
			docLen += c
		}
		var score float64
		for _, t := range terms {
			tf := float64(freq[t])
			if tf == 0 {
				continue
			}
			idf := math.Log(1.0 + (nDocs-float64(df[t])+0.5)/(float64(df[t])+0.5))
			num := tf * 2.2
			den := tf + 1.2*(1.0-0.75+0.75*(float64(docLen)/avgLen))
			score += idf * (num / den)
		}
		if len(lowerQuery) >= 4 && strings.Contains(strings.ToLower(chunks[i].text), lowerQuery) {
			score += 3.0
		}
		chunks[i].score = score
	}

	sorted := append([]chunk(nil), chunks...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].score != sorted[j].score {
			return sorted[i].score > sorted[j].score
		}
		return sorted[i].idx < sorted[j].idx
	})

	var selected []chunk
	used := 0
	for _, c := range sorted {
		if c.score <= 0 && len(selected) > 0 {
			break
		}
		if used+len(c.text)+2 > maxChars && len(selected) > 0 {
			continue
		}
		selected = append(selected, c)
		used += len(c.text) + 2
		if used >= maxChars {
			break
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].idx < selected[j].idx })

	parts := make([]string, len(selected))
	for i, c := range selected {
		parts[i] = c.text
	}
	return strings.Join(parts, "\n\n")
}

// RedactPII replaces email addresses, SSNs, phone numbers, and Luhn-valid payment card numbers with `[REDACTED_*]`.
func RedactPII(s string) string {
	s = reEmail.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = reSSN.ReplaceAllString(s, "[REDACTED_SSN]")
	s = reCard.ReplaceAllStringFunc(s, func(candidate string) string {
		if isLuhnCard(candidate) {
			return "[REDACTED_CARD]"
		}
		return candidate
	})
	s = rePhone.ReplaceAllString(s, "[REDACTED_PHONE]")
	return s
}

func isLuhnCard(raw string) bool {
	var digits []int
	for i := 0; i < len(raw); i++ {
		if raw[i] >= '0' && raw[i] <= '9' {
			digits = append(digits, int(raw[i]-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() >= 2 {
			w := cur.String()
			if !isStopWord(w) {
				out = append(out, w)
			}
		}
		cur.Reset()
	}
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func isStopWord(w string) bool {
	switch w {
	case "the", "and", "for", "with", "that", "this", "from", "are", "was", "were", "have", "has", "had", "not", "but", "what", "how", "when", "where", "who", "which", "into", "your", "about":
		return true
	}
	return false
}

func extractTitle(rawHTML string) string {
	m := reTitleTag.FindStringSubmatch(rawHTML)
	if len(m) < 2 {
		return ""
	}
	return cleanInline(m[1])
}

func scanHeadMetadata(rawHTML string, base *url.URL) BrandingProfile {
	var p BrandingProfile
	p.Title = extractTitle(rawHTML)

	for _, tag := range reMetaTag.FindAllString(rawHTML, 80) {
		attrs := parseAttrs(tag)
		name := strings.ToLower(firstAttr(attrs, "name", "property"))
		content := strings.TrimSpace(html.UnescapeString(attrs["content"]))
		if content == "" {
			continue
		}
		switch name {
		case "description":
			if p.Description == "" {
				p.Description = content
			}
		case "og:description":
			if p.Description == "" {
				p.Description = content
			}
		case "og:title":
			if p.Title == "" {
				p.Title = content
			}
		case "og:image", "twitter:image":
			if p.OGImage == "" {
				p.OGImage = resolveHref(content, base)
			}
		case "theme-color":
			if p.ThemeColor == "" {
				p.ThemeColor = content
			}
		}
	}

	baseStr := ""
	if base != nil {
		baseStr = base.String()
	}
	faviconRank := 2
	for _, tag := range reLinkTag.FindAllString(rawHTML, 60) {
		attrs := parseAttrs(tag)
		rel := strings.ToLower(attrs["rel"])
		if strings.Contains(rel, "icon") && faviconRank > 0 {
			if iconHref := resolveFaviconHrefFullDocGo(attrs["href"], baseStr); iconHref != "" {
				if rank := faviconRelRankFullDocGo(rel); rank < faviconRank {
					p.Favicon = iconHref
					faviconRank = rank
				}
			}
		}
		href := resolveHref(attrs["href"], base)
		if href == "" {
			continue
		}
		if strings.Contains(rel, "canonical") && p.CanonicalURL == "" {
			p.CanonicalURL = href
		}
	}
	if p.Favicon == "" && base != nil && base.Scheme == "https" && base.Host != "" {
		p.Favicon = (&url.URL{Scheme: "https", Host: base.Host, Path: "/favicon.ico"}).String()
	}

	for _, img := range reImgTag.FindAllString(rawHTML, 40) {
		attrs := parseAttrs(img)
		combined := strings.ToLower(attrs["alt"] + " " + attrs["class"] + " " + attrs["id"] + " " + attrs["src"])
		if strings.Contains(combined, "logo") {
			if src := resolveHref(firstAttr(attrs, "src", "data-src"), base); src != "" && !strings.HasPrefix(src, "data:") {
				p.Logo = src
				break
			}
		}
	}
	return p
}

func extractStyleSignals(rawHTML string) (colors, fonts []string) {
	lowHTML := asciiLowerExtractString(rawHTML)
	hasStyle := strings.Contains(lowHTML, "</style")
	hasGoogleFont := strings.Contains(lowHTML, "fonts.googleapis.com")
	if !hasStyle && !hasGoogleFont {
		return nil, nil
	}
	seenColor := make(map[string]bool)
	var styleBuf strings.Builder
	if hasStyle {
		for _, m := range reStyleContent.FindAllStringSubmatch(rawHTML, 25) {
			if len(m) >= 2 {
				styleBuf.WriteString(m[1])
				styleBuf.WriteByte('\n')
			}
		}
	}
	styleText := styleBuf.String()
	for _, c := range reHexColor.FindAllString(styleText, 60) {
		lc := strings.ToLower(c)
		if lc == "#ffffff" || lc == "#000000" {
			continue
		}
		if !seenColor[lc] {
			seenColor[lc] = true
			colors = append(colors, lc)
			if len(colors) >= 8 {
				break
			}
		}
	}

	seenFont := make(map[string]bool)
	addFont := func(raw string) {
		f := strings.Trim(strings.TrimSpace(raw), `"'`)
		if f == "" || len(f) > 48 {
			return
		}
		lf := strings.ToLower(f)
		switch lf {
		case "sans-serif", "serif", "monospace", "inherit", "initial", "system-ui", "-apple-system", "blinkmacsystemfont":
			return
		}
		if !seenFont[lf] && len(fonts) < 6 {
			seenFont[lf] = true
			fonts = append(fonts, f)
		}
	}
	if hasGoogleFont {
		for _, gm := range reGoogleFont.FindAllStringSubmatch(rawHTML, 10) {
			if len(gm) >= 2 {
				name := strings.Split(gm[1], ":")[0]
				addFont(strings.ReplaceAll(name, "+", " "))
			}
		}
	}
	for _, fm := range reFontFamily.FindAllStringSubmatch(styleText, 25) {
		if len(fm) >= 2 {
			for _, part := range strings.Split(fm[1], ",") {
				addFont(part)
			}
		}
	}
	return colors, fonts
}

func extractLinks(work string, base *url.URL) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range reAnchor.FindAllStringSubmatch(work, 500) {
		if len(m) < 2 {
			continue
		}
		attrs := parseAttrs(m[1])
		u := resolveHTTPSLink(attrs["href"], base)
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
			if len(out) >= 250 {
				break
			}
		}
	}
	return out
}

func extractImages(work string, base *url.URL) []ImageInfo {
	seen := make(map[string]bool)
	var out []ImageInfo
	for _, m := range reImgTag.FindAllString(work, 150) {
		attrs := parseAttrs(m)
		src := resolveHTTPSLink(firstAttr(attrs, "src", "data-src"), base)
		if src == "" || seen[src] {
			continue
		}
		seen[src] = true
		alt := strings.TrimSpace(html.UnescapeString(attrs["alt"]))
		out = append(out, ImageInfo{URL: src, Alt: alt})
		if len(out) >= 60 {
			break
		}
	}
	return out
}

func cleanInline(s string) string {
	s = reAnyTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

func parseAttrs(tag string) map[string]string {
	out := make(map[string]string)
	for _, m := range reAttrPair.FindAllStringSubmatch(tag, 20) {
		key := strings.ToLower(m[1])
		val := m[2]
		if val == "" {
			val = m[3]
		}
		if val == "" {
			val = m[4]
		}
		if _, exists := out[key]; !exists {
			out[key] = val
		}
	}
	return out
}

func firstAttr(attrs map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(attrs[k]); v != "" {
			return v
		}
	}
	return ""
}

var reHrefAmpEntity = newLazyRegexp(`(?i)&(?:amp|#0*38|#x0*26);`)
var reInvisibleSmuggling = newLazyRegexp(`[\x{E0000}-\x{E007F}\x{202A}-\x{202E}\x{2066}-\x{2069}]`)

// unescapeHrefAmpOnly safely replaces only `&amp;` / `&#38;` / `&#x26;` inside URLs.
// Calling `html.UnescapeString` on raw hrefs corrupts semicolon-less query params like
// `&currentTime=` (`&curren` -> `¤tTime=`), `&section=` (`&sect` -> `§ion=`), and `&region=` (`&reg` -> `®ion=`).
func unescapeHrefAmpOnly(raw string) string {
	if !strings.Contains(raw, "&") {
		return strings.TrimSpace(raw)
	}
	return strings.TrimSpace(reHrefAmpEntity.ReplaceAllString(raw, "&"))
}

func resolveHref(raw string, base *url.URL) string {
	raw = unescapeHrefAmpOnly(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	return u.String()
}

func resolveHTTPSLink(raw string, base *url.URL) string {
	resolved := resolveHref(raw, base)
	if resolved == "" {
		return ""
	}
	u, err := url.Parse(resolved)
	if err != nil || (u.Scheme != "https" && (base == nil || u.Scheme != base.Scheme)) || u.Host == "" {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
