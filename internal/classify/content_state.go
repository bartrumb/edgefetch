package classify

import (
	"html"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const maxHTMLScanCharsCSGo = 2 * 1024 * 1024

// WAFChallengeInput provides HTTP response metadata, HTML, and extracted text/Markdown to ClassifyWAFAndChallengeFull.
type WAFChallengeInput struct {
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers,omitempty"`
	RawHTML     string            `json:"rawHtml,omitempty"`
	URL         string            `json:"url,omitempty"`
	Title       string            `json:"title,omitempty"`
	VisibleText string            `json:"visibleText,omitempty"`
	Markdown    string            `json:"markdown,omitempty"`
}

// IframeScanResult reports external or ATS/widget iframes discovered in an HTML document.
type IframeScanResult struct {
	HasExternalIframe bool     `json:"hasExternalIframe"`
	IsIcims           bool     `json:"isIcims,omitempty"`
	WidgetHosts       []string `json:"widgetHosts,omitempty"`
	IframeSrcs        []string `json:"iframeSrcs,omitempty"`
}

// ContentStateInput provides full context for ClassifyContentStateFull.
type ContentStateInput struct {
	Status       int    `json:"status"`
	URL          string `json:"url,omitempty"`
	FinalURL     string `json:"finalUrl,omitempty"`
	Title        string `json:"title,omitempty"`
	Markdown     string `json:"markdown"`
	RawHTML      string `json:"rawHtml,omitempty"`
	ValidThrough string `json:"validThrough,omitempty"`
	Rendered     bool   `json:"rendered,omitempty"`
	NowMs        int64  `json:"nowMs,omitempty"`
}

// ContentStateResult describes the semantic availability state of a scraped 2xx page (`R4`).
type ContentStateResult struct {
	State      string  `json:"state"`
	Reason     string  `json:"reason,omitempty"`
	Confidence float64 `json:"confidence"`
}

// BlockedRefinement holds normalized machine-readable block reasons and caller guidance (`waf.ts:refineBlockedInfo`).
type BlockedRefinement struct {
	Reason       string `json:"reason,omitempty"`
	Host         string `json:"host,omitempty"`
	Category     string `json:"category,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
	Retryable    bool   `json:"retryable"`
	RetryAfterMs int64  `json:"retryAfterMs,omitempty"`
	Message      string `json:"message,omitempty"`
	Suggestion   string `json:"suggestion,omitempty"`
}

var (
	reWordTokensCSGo                = newLazyRegexp(`[\p{L}\p{N}_'-]+`)
	reNamedEntitiesCSGo             = newLazyRegexp(`(?i)&[a-z0-9#]+;`)
	reRichSchemaInnerCSGo           = newLazyRegexp(`(?is)"@type"\s*:\s*(?:\[[^\]]{0,400})?["'](?:Article|TechArticle|NewsArticle|BlogPosting|ScholarlyArticle|JobPosting|Product|SoftwareSourceCode|FAQPage|APIReference)["']`)
	reJSONLDAttrCSGo                = newLazyRegexp(`(?i)\btype\s*=\s*["']application/ld\+json["']`)
	reDataScriptAttrCSGo            = newLazyRegexp(`(?i)\b(?:type\s*=\s*["']application/(?:ld\+)?json["']|id\s*=\s*["']__(?:NEXT|NUXT)_DATA__["'])`)
	reScriptBlocksCSGo              = newLazyRegexp(`(?is)<script\b([^>]*)>(.*?)</script>`)
	reVisibleDropBlocksCSGo         = newLazyRegexp(`(?is)<(?:pre|code|blockquote|textarea|svg|style|script)\b[^>]*>.*?</(?:pre|code|blockquote|textarea|svg|style|script)>`)
	reScrubDomBlocksCSGo            = newLazyRegexp(`(?is)<(?:pre|code|blockquote|textarea|svg|style)\b[^>]*>.*?</(?:pre|code|blockquote|textarea|svg|style)>`)
	reProseLeakBlocksCSGo           = newLazyRegexp(`(?is)<(?:script|style|noscript|template)\b[^>]*>.*?</(?:script|style|noscript|template)>`)
	reVisibleHTMLDropCSGo           = newLazyRegexp(`(?is)<(?:script|style|noscript|template|svg)\b[^>]*>.*?</(?:script|style|noscript|template|svg)>`)
	reH1BlockCSGo                   = newLazyRegexp(`(?is)<h1\b[^>]*>(.*?)</h1>`)
	reMarkdownH1CSGo                = newLazyRegexp(`^(?:\s*\r?\n)*[ \t]{0,3}#{1,2}[ \t]+([^\r\n]{1,200})`)
	reCloudflareTitleFullCSGo       = newLazyRegexp(`(?i)^(?:just a moment\.{0,3}|attention required!\s*\|\s*cloudflare|ddos-guard|checking your browser)$`)
	reGenericChallengeTitleFullCSGo = newLazyRegexp(`(?i)^(?:verify you are human|human verification|pardon our interruption|access to this page has been denied|bot verification|security check|vercel security checkpoint)$`)
	reAkamaiRefFullCSGo             = newLazyRegexp(`(?i)reference\s*#18\.[0-9a-f]{4,}\.[0-9]{6,}`)

	reNonContentIframeHostCSGo = newLazyRegexp(`(?i)(?:googletagmanager\.com|doubleclick\.net|googlesyndication\.com|google-analytics\.com|facebook\.com/tr|challenges\.cloudflare\.com|recaptcha|hcaptcha|captcha-delivery\.com|_incapsula_resource|js\.stripe\.com|newrelic\.com|demdex\.net)`)
	reIframeSkipSchemeCSGo     = newLazyRegexp(`(?i)^(?:about:blank|javascript:|data:)`)
	reIframeSrcValidCSGo       = newLazyRegexp(`(?i)^(?:https?://|//|/[A-Za-z0-9_.-])`)
	reHiddenStyleCSGo          = newLazyRegexp(`(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden)`)
	reHiddenBoolAttrCSGo       = newLazyRegexp(`(?i)(?:^|\s)hidden(?:\s*=\s*(?:""|''|"true"|'true'|"hidden"|'hidden'|true|hidden))?(?:\s|$)`)
	reSimpleTagAttrCSGo        = newLazyRegexp(`([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+)))?`)
	reWidgetSameHostHintCSGo   = newLazyRegexp(`(?i)(?:icims|in_iframe|embed|widget|greenhouse|lever|ashby|workday|smartrecruiters|bamboohr|workable|recruitee|jobvite|taleo)`)

	reClosedPostingCSGo    = newLazyRegexp(`(?i)\b(?:this\s+(?:job|position|role|posting)\s+(?:is\s+no\s+longer|has\s+been\s+(?:filled|closed))|no\s+longer\s+accepting\s+applications|position\s+has\s+been\s+filled|job\s+is\s+no\s+longer\s+(?:open|available|active)|sorry,\s*this\s+job\s+(?:opening\s+)?is\s+closed)\b`)
	reSoft404H1CSGo        = newLazyRegexp(`(?m)^#\s+([^\n]+)`)
	reNotFoundHeadingCSGo  = newLazyRegexp(`(?i)\b(?:404\b|page\s+not\s+found|job\s+not\s+found|post(?:ing)?\s+not\s+found|couldn['’]t\s+find\s+(?:that|this)\s+page|page\s+doesn['’]t\s+exist)\b`)
	reNotFoundBodyCSGo     = newLazyRegexp(`(?i)\b(?:the\s+page\s+you\s+(?:requested|are\s+looking\s+for)\s+(?:could\s+not\s+be\s+found|does\s+not\s+exist)|error\s+404|we\s+can['’]t\s+seem\s+to\s+find\s+the\s+page)\b`)
	reLoginGateHeadingCSGo = newLazyRegexp(`(?i)^(?:sign\s+in|log\s*in|authentication\s+required|members\s+only)(?:\s+to\s+\S+|\s*[-|–]\s*.*)?$`)
	// Present-tense site maintenance notice. The subject must be the site/service itself (or "we"), so news about a
	// bridge or road "down for maintenance" and how-to maintenance articles do not match; future-tense notices
	// ("will undergo maintenance on Saturday") never match because a present-tense verb is required.
	reMaintenanceStatusCSGo = newLazyRegexp(`(?i)(?:\b(?:(?:this|our|the)\s+)?(?:site|website|web\s+site|page|service|store|shop|app|application|server|platform|portal)\s+(?:is|are)|\bwe['’]re|\bwe\s+are)\s+(?:currently\s+)?(?:(?:down\s+for|undergoing|under)\s+(?:some\s+)?(?:scheduled\s+|planned\s+)?maintenance\b|temporarily\s+unavailable\b)|\bbe\s+right\s+back\b`)
	reMaintenanceRetryCSGo  = newLazyRegexp(`(?i)\b(?:check\s+back|try\s+again|back\s+(?:soon|shortly|online)|return\s+shortly)\b`)
	reLoginGateCopyCSGo     = newLazyRegexp(`(?i)\b(?:sign\s+in\s+to\s+(?:view|read|continue|access)|log\s+in\s+to\s+(?:view|read|continue|access)|please\s+(?:sign|log)\s+in\s+to\s+continue|create\s+a\s+free\s+account\s+to\s+continue\s+reading)\b`)

	reDNSNotFoundCSGo            = newLazyRegexp(`(?i)\b(?:enotfound|nxdomain|dns_not_found|eai_noname)\b|no such host|name or service not known|nodename nor servname provided|domain does not exist`)
	reSchemeDowngradeCSGo        = newLazyRegexp(`(?is)(?:scheme_downgrade|https?-to-http|scheme\s+downgrade|(?:disallowed_url|redirect).{0,140}?(?:only\s+https://|scheme\s+must\s+be\s+https|to\s+http://))`)
	reSSRFBlockedCSGo            = newLazyRegexp(`(?is)\b(?:blocked_ssrf|ssrf)\b|forbidden\s+redirect\s+target.{0,80}?internal|non-public(?:\s+ip|\s+peer|\s+address)?|metadata\s+(?:ip|endpoint|address|service)|private\s+(?:ip|network|address)|loopback\s+(?:ip|address)|link-local\s+(?:ip|address)|disallowed_url|resolved\s+to\s+(?:a\s+)?(?:private|loopback|link-local|reserved|non-public|internal)`)
	reRobotsUnreachableCSGo      = newLazyRegexp(`(?is)robots\.txt.{0,180}?(?:unreachable|timed out|returned http (?:5\d\d|429)|budget exhausted|redirect failed|unexpected http)`)
	reContentSignalCSGo          = newLazyRegexp(`(?i)content-signal|ai-input\s*=\s*no`)
	reDisallowsPathInRobotsCSGo  = newLazyRegexp(`(?i)disallows\s+this\s+path\s+in\s+robots\.txt`)
	reAggregatorSugCSGo          = newLazyRegexp(`(?i)aggregator|go\s+directly\s+to\s+the\s+employer|board\s+instead\s+of\s+job\s+boards`)
	reBlockedAggregatorHostCSGo  = newLazyRegexp(`(?i)(?:^|\.)(?:linkedin\.com|indeed\.com|dice\.com|startup\.jobs|glassdoor\.com|ziprecruiter\.com)$`)
	reSmartRecruitersAPIHostCSGo = newLazyRegexp(`(?i)^api\.smartrecruiters\.com$`)
	rePyPIJSONPathCSGo           = newLazyRegexp(`(?i)/json/?$`)
)

func capStringBytesUTF8CSGo(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

func readHeaderCaseInsensitiveCSGo(headers map[string]string, name string) string {
	if len(headers) == 0 {
		return ""
	}
	if v, ok := headers[name]; ok {
		return strings.TrimSpace(v)
	}
	target := strings.ToLower(name)
	if v, ok := headers[target]; ok {
		return strings.TrimSpace(v)
	}
	for k, v := range headers {
		if strings.EqualFold(k, target) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func stripTagsQuoteAwareCSGo(s string, maxBytes int) string {
	bounded := capStringBytesUTF8CSGo(s, maxBytes)
	if strings.IndexByte(bounded, '<') < 0 {
		return bounded
	}
	var out strings.Builder
	out.Grow(len(bounded))
	i := 0
	n := len(bounded)
	for i < n {
		relLt := strings.IndexByte(bounded[i:], '<')
		if relLt < 0 {
			out.WriteString(bounded[i:])
			break
		}
		lt := i + relLt
		out.WriteString(bounded[i:lt])
		if lt+1 >= n {
			out.WriteByte('<')
			break
		}
		c1 := bounded[lt+1]
		isTagStart := (c1 >= 'a' && c1 <= 'z') || (c1 >= 'A' && c1 <= 'Z') || c1 == '/' || c1 == '!' || c1 == '?'
		if !isTagStart {
			out.WriteByte('<')
			i = lt + 1
			continue
		}
		cur := lt + 1
		var quote byte
		closed := false
		for cur < n {
			ch := bounded[cur]
			if quote != 0 {
				if ch == quote {
					quote = 0
				}
			} else if ch == '"' || ch == '\'' {
				if c1 != '/' {
					quote = ch
				}
			} else if ch == '>' {
				closed = true
				cur++
				break
			}
			cur++
		}
		if !closed {
			out.WriteString(bounded[lt:])
			break
		}
		out.WriteByte(' ')
		i = cur
	}
	return out.String()
}

func countWordsFromHTMLCSGo(htmlFragment string) int {
	plain := stripTagsQuoteAwareCSGo(htmlFragment, 98_304)
	plain = html.UnescapeString(plain)
	plain = reNamedEntitiesCSGo.ReplaceAllString(plain, " ")
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return 0
	}
	return len(reWordTokensCSGo.FindAllStringIndex(plain, -1))
}

func countWordsFromTextCSGo(text string) int {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0
	}
	return len(reWordTokensCSGo.FindAllStringIndex(trimmed, -1))
}

func hasRichSchemaJSONLDCSGo(sample string) bool {
	if !strings.Contains(sample, "ld+json") && !strings.Contains(sample, "LD+JSON") {
		return false
	}
	matches := reScriptBlocksCSGo.FindAllStringSubmatch(sample, 16)
	for _, m := range matches {
		if len(m) == 3 && reJSONLDAttrCSGo.MatchString(m[1]) {
			inner := capStringBytesUTF8CSGo(m[2], 24_000)
			if reRichSchemaInnerCSGo.MatchString(inner) {
				return true
			}
		}
	}
	return false
}

func stripMarkdownFencesAndBlockquotesCSGo(text string) string {
	if !strings.Contains(text, "```") && !strings.Contains(text, "~~~") && strings.IndexByte(text, '>') < 0 {
		return text
	}
	lines := strings.Split(text, "\n")
	kept := make([]string, 0, len(lines))
	var fenceChar byte
	fenceLen := 0
	for _, line := range lines {
		i := 0
		for i < len(line) && i < 3 && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		trimmedStart := line[i:]
		if fenceChar == 0 {
			if len(trimmedStart) >= 3 && (trimmedStart[0] == '`' || trimmedStart[0] == '~') {
				fc := trimmedStart[0]
				k := 0
				for k < len(trimmedStart) && trimmedStart[k] == fc {
					k++
				}
				if k >= 3 && !(fc == '`' && strings.IndexByte(trimmedStart[k:], '`') >= 0) {
					fenceChar = fc
					fenceLen = k
					continue
				}
			}
			if strings.HasPrefix(trimmedStart, ">") {
				continue
			}
			kept = append(kept, line)
		} else {
			if len(trimmedStart) >= fenceLen && trimmedStart[0] == fenceChar {
				k := 0
				for k < len(trimmedStart) && trimmedStart[k] == fenceChar {
					k++
				}
				rest := strings.TrimRight(trimmedStart[k:], " \t\r")
				if k >= fenceLen && rest == "" {
					fenceChar = 0
					fenceLen = 0
				}
			}
		}
	}
	return strings.Join(kept, "\n")
}

func stripMarkdownFencesOnlyCSGo(text string) string {
	if !strings.Contains(text, "```") && !strings.Contains(text, "~~~") {
		return text
	}
	lines := strings.Split(text, "\n")
	kept := make([]string, 0, len(lines))
	var fenceChar byte
	fenceLen := 0
	for _, line := range lines {
		i := 0
		for i < len(line) && i < 3 && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		trimmedStart := line[i:]
		if fenceChar == 0 {
			if len(trimmedStart) >= 3 && (trimmedStart[0] == '`' || trimmedStart[0] == '~') {
				fc := trimmedStart[0]
				k := 0
				for k < len(trimmedStart) && trimmedStart[k] == fc {
					k++
				}
				if k >= 3 && !(fc == '`' && strings.IndexByte(trimmedStart[k:], '`') >= 0) {
					fenceChar = fc
					fenceLen = k
					continue
				}
			}
			kept = append(kept, line)
		} else {
			if len(trimmedStart) >= fenceLen && trimmedStart[0] == fenceChar {
				k := 0
				for k < len(trimmedStart) && trimmedStart[k] == fenceChar {
					k++
				}
				rest := strings.TrimRight(trimmedStart[k:], " \t\r")
				if k >= fenceLen && rest == "" {
					fenceChar = 0
					fenceLen = 0
				}
			}
		}
	}
	return strings.Join(kept, "\n")
}

// ClassifyWAFAndChallengeFull evaluates HTTP status, headers, raw HTML, Markdown, and visible text against the full
// 10-vendor WAF & Challenge Signature Catalog (`cloudflare`, `akamai`, `datadome`, `perimeterx`, `aws-waf`, `imperva`,
// `vercel`, `fastly`, `kasada`, `generic`) while enforcing all 4 Anti-False-Positive Guardrails (`R2` & `R3`).
func ClassifyWAFAndChallengeFull(in WAFChallengeInput) *WAFMatch {
	status := in.Status

	// --- Layer 1: Authoritative HTTP Response Headers ---
	if cfMit := strings.ToLower(readHeaderCaseInsensitiveCSGo(in.Headers, "cf-mitigated")); cfMit != "" {
		category := "challenge"
		if cfMit == "block" {
			category = "waf_block"
		} else if cfMit == "rate_limit" {
			category = "rate_limit"
		}
		return &WAFMatch{
			Vendor:     "cloudflare",
			Category:   category,
			Confidence: 1.0,
			Signals:    []string{"header:cf-mitigated=" + cfMit},
			Summary:    "Cloudflare " + category + " (cf-mitigated)",
		}
	}

	if amzWaf := strings.ToLower(readHeaderCaseInsensitiveCSGo(in.Headers, "x-amzn-waf-action")); amzWaf == "challenge" || amzWaf == "captcha" || amzWaf == "block" {
		category := "challenge"
		if amzWaf == "block" {
			category = "waf_block"
		}
		return &WAFMatch{
			Vendor:     "aws-waf",
			Category:   category,
			Confidence: 1.0,
			Signals:    []string{"header:x-amzn-waf-action=" + amzWaf},
			Summary:    "AWS WAF " + amzWaf + " (x-amzn-waf-action)",
		}
	}

	if vercelMit := strings.ToLower(readHeaderCaseInsensitiveCSGo(in.Headers, "x-vercel-mitigated")); vercelMit != "" {
		category := "challenge"
		if vercelMit == "deny" || vercelMit == "block" {
			category = "waf_block"
		} else if vercelMit == "rate_limit" {
			category = "rate_limit"
		}
		return &WAFMatch{
			Vendor:     "vercel",
			Category:   category,
			Confidence: 1.0,
			Signals:    []string{"header:x-vercel-mitigated=" + vercelMit},
			Summary:    "Vercel Firewall mitigation (" + vercelMit + ")",
		}
	}

	ddHdr := strings.ToLower(readHeaderCaseInsensitiveCSGo(in.Headers, "x-datadome"))
	ddB := readHeaderCaseInsensitiveCSGo(in.Headers, "x-dd-b")
	if (status == 403 || status == 401 || status == 429) && (ddHdr == "protected" || ddB != "") {
		return &WAFMatch{
			Vendor:     "datadome",
			Category:   "challenge",
			Confidence: 1.0,
			Signals:    []string{"header:x-datadome"},
			Summary:    "DataDome anti-bot interstitial",
		}
	}

	if kasadaHdr := readHeaderCaseInsensitiveCSGo(in.Headers, "x-kpsdk-ct"); kasadaHdr != "" && (status == 429 || status == 403) {
		return &WAFMatch{
			Vendor:     "kasada",
			Category:   "challenge",
			Confidence: 1.0,
			Signals:    []string{"header:x-kpsdk-ct"},
			Summary:    "Kasada anti-bot challenge",
		}
	}

	if readHeaderCaseInsensitiveCSGo(in.Headers, "x-px-blocked") == "1" {
		return &WAFMatch{
			Vendor:     "perimeterx",
			Category:   "challenge",
			Confidence: 1.0,
			Signals:    []string{"header:x-px-blocked=1"},
			Summary:    "PerimeterX / HUMAN block interstitial",
		}
	}

	rawBody := in.RawHTML
	if rawBody == "" {
		if in.Markdown != "" {
			rawBody = in.Markdown
		} else if in.VisibleText != "" {
			rawBody = in.VisibleText
		}
	}
	if rawBody == "" && strings.TrimSpace(in.Title) == "" {
		return nil
	}
	if status >= 200 && status < 300 && len(rawBody) > 49_152 {
		return nil
	}

	sample := capStringBytesUTF8CSGo(rawBody, 98_304)
	noComments := reWafHTMLComments.ReplaceAllString(sample, " ")
	visibleClean := reVisibleDropBlocksCSGo.ReplaceAllString(noComments, " ")
	visibleWords := countWordsFromHTMLCSGo(visibleClean)
	if in.RawHTML == "" && in.VisibleText != "" {
		if vw := countWordsFromTextCSGo(in.VisibleText); vw > visibleWords {
			visibleWords = vw
		}
	}

	// --- Layer 2 & Layer 4: Structural Content Veto & Payload Geometry Check on 200 OK ---
	if status >= 200 && status < 300 {
		if visibleWords >= 120 {
			return nil
		}
		if hasRichSchemaJSONLDCSGo(sample) {
			return nil
		}
		for _, mm := range reWafMainOrArticle.FindAllStringSubmatch(visibleClean, 4) {
			if len(mm) == 2 && countWordsFromHTMLCSGo(mm[1]) >= 250 {
				return nil
			}
		}
		if len(reWafSubheadings.FindAllStringIndex(visibleClean, 3)) >= 2 && visibleWords >= 100 {
			return nil
		}
		for _, nm := range reWafNavBlock.FindAllStringSubmatch(noComments, 4) {
			if len(nm) == 2 && visibleWords >= 120 && len(reWafNavAnchor.FindAllStringIndex(nm[1], 5)) >= 4 {
				return nil
			}
		}
	}

	// --- Layer 3: Strip <pre>, <code>, <blockquote>, JSON-LD, hydration JSON, Markdown fences, & blockquotes ---
	noDataScripts := reScriptBlocksCSGo.ReplaceAllStringFunc(noComments, func(full string) string {
		sub := reScriptBlocksCSGo.FindStringSubmatch(full)
		if len(sub) >= 2 && reDataScriptAttrCSGo.MatchString(sub[1]) {
			return " "
		}
		return full
	})
	scrubbedDom := reScrubDomBlocksCSGo.ReplaceAllString(noDataScripts, " ")
	scrubbed := stripMarkdownFencesAndBlockquotesCSGo(scrubbedDom)
	scrubbedLower := strings.ToLower(scrubbed)

	title := extractRawTitle(scrubbed)
	if title == "" && strings.TrimSpace(in.Title) != "" {
		title = strings.TrimSpace(in.Title)
	}

	headingTitle := ""
	if title == "" && visibleWords < 80 {
		if hm := reH1BlockCSGo.FindStringSubmatch(scrubbed); len(hm) == 2 {
			headingTitle = strings.Join(strings.Fields(html.UnescapeString(stripTagsQuoteAwareCSGo(hm[1], 1024))), " ")
		}
		if headingTitle == "" {
			if mdm := reMarkdownH1CSGo.FindStringSubmatch(scrubbed); len(mdm) == 2 {
				headingTitle = strings.TrimSpace(strings.TrimRight(mdm[1], " \t#*"))
			}
		}
	}
	effectiveTitle := title
	if effectiveTitle == "" {
		effectiveTitle = headingTitle
	}

	serverHdr := strings.ToLower(readHeaderCaseInsensitiveCSGo(in.Headers, "server"))
	setCookie := strings.ToLower(readHeaderCaseInsensitiveCSGo(in.Headers, "set-cookie"))
	isGenericChallengeTitle := effectiveTitle != "" && reGenericChallengeTitleFullCSGo.MatchString(effectiveTitle)
	hasCloudflareProseSignals := strings.Contains(scrubbedLower, "enable javascript and cookies to continue") ||
		strings.Contains(scrubbedLower, "needs to review the security of your connection") ||
		strings.Contains(scrubbedLower, "verify you are human") ||
		strings.Contains(scrubbedLower, "why do i have to complete a captcha") ||
		strings.Contains(scrubbedLower, "performance & security by cloudflare") ||
		strings.Contains(scrubbedLower, "checking if the site connection is secure")

	// 1. Cloudflare
	if (title != "" && reCloudflareTitleFullCSGo.MatchString(title)) ||
		(visibleWords < 80 && effectiveTitle != "" && reCloudflareTitleFullCSGo.MatchString(effectiveTitle) && (hasCloudflareProseSignals || visibleWords < 25)) ||
		(visibleWords < 60 &&
			(strings.Contains(scrubbedLower, "enable javascript and cookies to continue") ||
				(strings.Contains(scrubbedLower, "just a moment") && hasCloudflareProseSignals) ||
				(strings.Contains(scrubbedLower, "verify you are human") && strings.Contains(scrubbedLower, "needs to review the security of your connection")) ||
				(strings.Contains(scrubbedLower, "attention required") &&
					strings.Contains(scrubbedLower, "cloudflare") &&
					(strings.Contains(scrubbedLower, "security check") || strings.Contains(scrubbedLower, "captcha"))))) ||
		(strings.Contains(scrubbedLower, "_cf_chl_opt") && strings.Contains(scrubbedLower, "/cdn-cgi/challenge-platform/")) ||
		(visibleWords < 80 && strings.Contains(scrubbedLower, "challenges.cloudflare.com/turnstile") && isGenericChallengeTitle) {
		sig := "prose:cloudflare-challenge"
		if title != "" {
			sig = "dom:cloudflare-challenge"
		}
		return &WAFMatch{
			Vendor:     "cloudflare",
			Category:   "challenge",
			Confidence: 0.95,
			Signals:    []string{sig},
			Summary:    "Cloudflare anti-bot challenge page",
		}
	}

	// 2. DataDome
	if strings.Contains(scrubbedLower, "geo.captcha-delivery.com") ||
		strings.Contains(scrubbedLower, "ct.captcha-delivery.com") ||
		(visibleWords < 60 && strings.Contains(scrubbedLower, "please enable js and disable any ad blocker")) {
		return &WAFMatch{
			Vendor:     "datadome",
			Category:   "challenge",
			Confidence: 0.96,
			Signals:    []string{"dom:captcha-delivery.com"},
			Summary:    "DataDome CAPTCHA interstitial",
		}
	}

	// 3. PerimeterX / HUMAN
	if (strings.Contains(scrubbedLower, "px-captcha") &&
		(strings.Contains(scrubbedLower, "_pxappid") || strings.Contains(scrubbedLower, "perimeterx") || strings.Contains(setCookie, "_pxhd="))) ||
		(strings.Contains(scrubbedLower, `"appid":"px`) && strings.Contains(scrubbedLower, `"blockscript"`)) {
		return &WAFMatch{
			Vendor:     "perimeterx",
			Category:   "challenge",
			Confidence: 0.95,
			Signals:    []string{"dom:px-captcha"},
			Summary:    "PerimeterX / HUMAN anti-bot challenge",
		}
	}

	// 4. Akamai Bot Manager
	if (strings.Contains(serverHdr, "akamaighost") || strings.Contains(serverHdr, "akamai") || strings.Contains(setCookie, "_abck=") || strings.Contains(scrubbedLower, "edgesuite.net")) &&
		(reAkamaiRefFullCSGo.MatchString(scrubbed) || (status == 403 && strings.Contains(scrubbedLower, "edgesuite.net"))) {
		return &WAFMatch{
			Vendor:     "akamai",
			Category:   "waf_block",
			Confidence: 0.95,
			Signals:    []string{"dom:akamai-reference-18"},
			Summary:    "Akamai Bot Manager access denied (Reference #18)",
		}
	}

	// 5. AWS WAF
	if strings.Contains(scrubbedLower, "awswafintegration") ||
		strings.Contains(scrubbedLower, "aws-waf-token") ||
		strings.Contains(scrubbedLower, "awswaf-captcha") {
		return &WAFMatch{
			Vendor:     "aws-waf",
			Category:   "challenge",
			Confidence: 0.94,
			Signals:    []string{"dom:awswaf-captcha"},
			Summary:    "AWS WAF CAPTCHA interstitial",
		}
	}

	// 6. Imperva / Incapsula
	if strings.Contains(scrubbedLower, "/_incapsula_resource") ||
		(strings.Contains(setCookie, "visid_incap_") && strings.Contains(scrubbedLower, "incapsula incident id")) {
		return &WAFMatch{
			Vendor:     "imperva",
			Category:   "challenge",
			Confidence: 0.96,
			Signals:    []string{"dom:_incapsula_resource"},
			Summary:    "Imperva Incapsula security interstitial",
		}
	}

	// 7. Fastly WAF 403
	if status == 403 &&
		(strings.Contains(serverHdr, "fastly") || readHeaderCaseInsensitiveCSGo(in.Headers, "x-served-by") != "") &&
		!strings.Contains(scrubbedLower, "fastly error: unknown domain") &&
		strings.Contains(scrubbedLower, "request blocked") &&
		visibleWords < 80 {
		return &WAFMatch{
			Vendor:     "fastly",
			Category:   "waf_block",
			Confidence: 0.88,
			Signals:    []string{"dom:fastly-403-block"},
			Summary:    "Fastly WAF 403 block page",
		}
	}

	// 8. Vercel Security Checkpoint & Generic interstitial shells (< 80 visible words)
	if visibleWords < 80 {
		if strings.Contains(scrubbedLower, "vercel security checkpoint") ||
			((strings.Contains(scrubbedLower, "we're verifying your browser") || strings.Contains(scrubbedLower, "we are verifying your browser")) &&
				strings.Contains(scrubbedLower, "vercel")) {
			return &WAFMatch{
				Vendor:     "vercel",
				Category:   "challenge",
				Confidence: 0.94,
				Signals:    []string{"prose:vercel-security-checkpoint"},
				Summary:    "Vercel Security Checkpoint challenge page",
			}
		}
		if isGenericChallengeTitle &&
			(strings.Contains(scrubbedLower, "g-recaptcha") ||
				strings.Contains(scrubbedLower, "h-captcha") ||
				strings.Contains(scrubbedLower, "cf-turnstile") ||
				strings.Contains(scrubbedLower, "complete the security check") ||
				strings.Contains(scrubbedLower, "why do i have to complete a captcha")) {
			return &WAFMatch{
				Vendor:     "generic",
				Category:   "challenge",
				Confidence: 0.88,
				Signals:    []string{"title:" + effectiveTitle},
				Summary:    "anti-bot challenge page (" + effectiveTitle + ")",
			}
		}
		if strings.Contains(scrubbedLower, "checking your browser before accessing ") ||
			strings.Contains(scrubbedLower, "please wait while we check your browser") ||
			(strings.Contains(scrubbedLower, "making sure you're not a bot") && strings.Contains(scrubbedLower, "anubis")) {
			return &WAFMatch{
				Vendor:     "generic",
				Category:   "challenge",
				Confidence: 0.90,
				Signals:    []string{"dom:js-pow-interstitial"},
				Summary:    "JavaScript / proof-of-work anti-bot interstitial",
			}
		}
	}

	return nil
}

func readSimpleTagAttrCSGo(attrChunk, targetKeyLower string) string {
	matches := reSimpleTagAttrCSGo.FindAllStringSubmatch(attrChunk, 32)
	for _, m := range matches {
		if len(m) >= 5 && strings.EqualFold(m[1], targetKeyLower) {
			if m[2] != "" {
				return strings.TrimSpace(m[2])
			}
			if m[3] != "" {
				return strings.TrimSpace(m[3])
			}
			return strings.TrimSpace(m[4])
		}
	}
	return ""
}

func scanOpenTagsLinearCSGo(rawHTML, targetTagLower string, maxBytes int, onTag func(attrs string) bool) {
	src := capStringBytesUTF8CSGo(rawHTML, maxBytes)
	n := len(src)
	tLen := len(targetTagLower)
	pos := 0
	for pos < n {
		relLt := strings.IndexByte(src[pos:], '<')
		if relLt < 0 {
			break
		}
		lt := pos + relLt
		if lt+1+tLen >= n {
			break
		}
		if src[lt+1] == '!' && lt+3 < n && src[lt+2] == '-' && src[lt+3] == '-' {
			relEnd := strings.Index(src[lt+4:], "-->")
			if relEnd < 0 {
				break
			}
			pos = lt + 4 + relEnd + 3
			continue
		}
		match := true
		for k := 0; k < tLen; k++ {
			if (src[lt+1+k] | 0x20) != targetTagLower[k] {
				match = false
				break
			}
		}
		after := src[lt+1+tLen]
		isBoundary := after == ' ' || after == '\t' || after == '\n' || after == '\r' || after == '\f' || after == '/' || after == '>'
		if !match || !isBoundary {
			pos = lt + 1
			continue
		}

		cur := lt + 1 + tLen
		var quote byte
		openEnd := -1
		for cur < n {
			ch := src[cur]
			if quote != 0 {
				if ch == quote {
					quote = 0
				}
			} else if ch == '"' || ch == '\'' {
				quote = ch
			} else if ch == '>' {
				openEnd = cur
				break
			}
			cur++
		}
		if openEnd < 0 {
			break
		}
		attrEnd := openEnd
		if attrEnd > lt+1+tLen && src[attrEnd-1] == '/' {
			attrEnd--
		}
		attrs := src[lt+1+tLen : attrEnd]
		if !onTag(attrs) {
			return
		}
		pos = openEnd + 1
	}
}

func scanIframesInternalCSGo(rawHTML, pageURL string, anyRelativeShell bool) (IframeScanResult, bool) {
	if rawHTML == "" || !strings.Contains(strings.ToLower(capStringBytesUTF8CSGo(rawHTML, maxHTMLScanCharsCSGo)), "<iframe") {
		return IframeScanResult{}, false
	}

	var baseURL *url.URL
	pageHost := ""
	if strings.TrimSpace(pageURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(pageURL)); err == nil && u.Hostname() != "" {
			baseURL = u
			pageHost = strings.ToLower(u.Hostname())
		}
	}

	var res IframeScanResult
	isIcims := false
	seenHosts := make(map[string]bool)
	seenSrcs := make(map[string]bool)

	addHost := func(h string) {
		lh := strings.ToLower(strings.TrimSpace(h))
		if lh != "" && !seenHosts[lh] {
			seenHosts[lh] = true
			res.WidgetHosts = append(res.WidgetHosts, lh)
		}
	}
	addSrc := func(s string) {
		if s != "" && !seenSrcs[s] {
			seenSrcs[s] = true
			res.IframeSrcs = append(res.IframeSrcs, s)
		}
	}

	scanOpenTagsLinearCSGo(rawHTML, "iframe", maxHTMLScanCharsCSGo, func(attrs string) bool {
		id := readSimpleTagAttrCSGo(attrs, "id")
		name := readSimpleTagAttrCSGo(attrs, "name")
		cls := readSimpleTagAttrCSGo(attrs, "class")
		src := html.UnescapeString(readSimpleTagAttrCSGo(attrs, "src"))
		if src == "" {
			src = html.UnescapeString(readSimpleTagAttrCSGo(attrs, "data-src"))
		}
		style := readSimpleTagAttrCSGo(attrs, "style")
		width := readSimpleTagAttrCSGo(attrs, "width")
		height := readSimpleTagAttrCSGo(attrs, "height")
		ariaHidden := readSimpleTagAttrCSGo(attrs, "aria-hidden")

		if strings.EqualFold(ariaHidden, "true") {
			return true
		}
		if width == "0" || width == "1" || height == "0" || height == "1" {
			return true
		}
		if style != "" && reHiddenStyleCSGo.MatchString(style) {
			return true
		}
		if reHiddenBoolAttrCSGo.MatchString(attrs) {
			return true
		}

		combinedMeta := strings.ToLower(id + " " + name + " " + cls + " " + src)
		if strings.Contains(combinedMeta, "icims") {
			res.HasExternalIframe = true
			isIcims = true
			if src != "" {
				resolvedSrc := src
				iframeHost := ""
				if parsedSrc, err := url.Parse(src); err == nil {
					if baseURL != nil {
						resolved := baseURL.ResolveReference(parsedSrc)
						resolvedSrc = resolved.String()
						iframeHost = strings.ToLower(resolved.Hostname())
					} else {
						iframeHost = strings.ToLower(parsedSrc.Hostname())
					}
				}
				addSrc(resolvedSrc)
				if iframeHost != "" {
					addHost(iframeHost)
				} else {
					addHost("icims.com")
				}
			} else {
				addHost("icims.com")
			}
			return true
		}

		if src == "" || reIframeSkipSchemeCSGo.MatchString(src) {
			return true
		}
		if reNonContentIframeHostCSGo.MatchString(src) {
			return true
		}
		if !reIframeSrcValidCSGo.MatchString(src) {
			return true
		}

		resolvedSrc := src
		iframeHost := ""
		if strings.HasPrefix(src, "//") {
			if u, err := url.Parse("https:" + src); err == nil {
				resolvedSrc = u.String()
				iframeHost = strings.ToLower(u.Hostname())
			}
		} else if parsedSrc, err := url.Parse(src); err == nil {
			if parsedSrc.IsAbs() {
				iframeHost = strings.ToLower(parsedSrc.Hostname())
			} else if baseURL != nil {
				resolved := baseURL.ResolveReference(parsedSrc)
				resolvedSrc = resolved.String()
				iframeHost = strings.ToLower(resolved.Hostname())
			}
		}

		if iframeHost != "" && reNonContentIframeHostCSGo.MatchString(iframeHost) {
			return true
		}

		isExternal := (iframeHost != "" && (pageHost == "" || iframeHost != pageHost))
		isWidget := reWidgetSameHostHintCSGo.MatchString(combinedMeta)
		isRelativeNoPage := pageHost == "" && strings.HasPrefix(src, "/")

		if isExternal || isWidget || isRelativeNoPage || anyRelativeShell {
			res.HasExternalIframe = true
			addSrc(resolvedSrc)
			if iframeHost != "" {
				addHost(iframeHost)
			}
		}
		return true
	})

	return res, isIcims
}

// HasExternalOrWidgetIframe linearly scans rawHTML for visible external or ATS/widget `<iframe>` elements,
// ignoring hidden tracking pixels, tag managers, and CAPTCHA widgets.
func HasExternalOrWidgetIframe(rawHTML, pageURL string) IframeScanResult {
	res, isIcims := scanIframesInternalCSGo(rawHTML, pageURL, true)
	res.IsIcims = isIcims
	return res
}

var (
	reGHJobPathCSGo    = newLazyRegexp(`(?i)/jobs/(\d+)`)
	reBoardJobUUIDCSGo = newLazyRegexp(`(?i)^/[^/]+/([0-9a-f]{8}-[0-9a-f-]{27})\b`)
)

// ClassifyContentStateFull evaluates ContentStateInput with full ATS silent-redirect, validThrough expiry, and rendered-iframe awareness.
func ClassifyContentStateFull(in ContentStateInput) ContentStateResult {
	status := in.Status
	if status == 0 {
		status = 200
	}
	nowMs := in.NowMs
	if nowMs <= 0 {
		nowMs = time.Now().UnixMilli()
	}
	checkURLStr := strings.TrimSpace(in.FinalURL)
	if checkURLStr == "" {
		checkURLStr = strings.TrimSpace(in.URL)
	}
	if checkURLStr != "" {
		if finU, err := url.Parse(checkURLStr); err == nil {
			origU := finU
			if strings.TrimSpace(in.URL) != "" {
				if parsedOrig, oErr := url.Parse(strings.TrimSpace(in.URL)); oErr == nil {
					origU = parsedOrig
				}
			}
			finHost := strings.ToLower(finU.Hostname())
			origHost := strings.ToLower(origU.Hostname())
			isGhFin := finHost == "boards.greenhouse.io" || finHost == "job-boards.greenhouse.io" || finHost == "eu-boards.greenhouse.io" || finHost == "job-boards.eu.greenhouse.io"
			isGhOrig := origHost == "boards.greenhouse.io" || origHost == "job-boards.greenhouse.io" || origHost == "eu-boards.greenhouse.io" || origHost == "job-boards.eu.greenhouse.io"
			if (isGhFin || isGhOrig) && finU.Query().Get("error") == "true" {
				return ContentStateResult{State: "closed_posting", Reason: "Greenhouse redirected closed posting to ?error=true.", Confidence: 0.98}
			}
			origToken := ""
			if isGhOrig {
				if m := reGHJobPathCSGo.FindStringSubmatch(origU.Path); len(m) == 2 {
					origToken = m[1]
				}
			}
			if origToken == "" {
				origToken = origU.Query().Get("gh_jid")
			}
			if origToken == "" && (origHost == "jobs.lever.co" || origHost == "jobs.eu.lever.co" || origHost == "jobs.ashbyhq.com") {
				if m := reBoardJobUUIDCSGo.FindStringSubmatch(origU.Path); len(m) == 2 {
					origToken = m[1]
				}
			}
			if origToken != "" && in.FinalURL != "" && in.FinalURL != in.URL {
				finCombined := strings.ToLower(finU.Path)
				if finU.RawQuery != "" {
					finCombined += "?" + strings.ToLower(finU.RawQuery)
				}
				if !strings.Contains(finCombined, strings.ToLower(origToken)) {
					return ContentStateResult{
						State:      "closed_posting",
						Reason:     "ATS job posting redirected away from its job ID to a generic careers/board index (role closed).",
						Confidence: 0.96,
					}
				}
			}
		}
	}

	if vt := strings.TrimSpace(in.ValidThrough); vt != "" {
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
			if parsed, err := time.Parse(layout, vt); err == nil {
				if parsed.UnixMilli() < nowMs-86_400_000 {
					short := vt
					if len(short) > 10 {
						short = short[:10]
					}
					return ContentStateResult{
						State:      "closed_posting",
						Reason:     "JobPosting validThrough expired (" + short + ")",
						Confidence: 0.95,
					}
				}
				break
			}
		}
	}

	rawForShell := in.RawHTML
	if in.Rendered {
		// When already rendered in Chromium, keep password input detection but skip unrendered empty_shell classification
		res := ClassifyContentState(status, rawForShell, in.Markdown, checkURLStr, in.Title)
		if res.State == "empty_shell" {
			return ContentStateResult{State: "active", Confidence: 1.0}
		}
		return res
	}
	return ClassifyContentState(status, rawForShell, in.Markdown, checkURLStr, in.Title)
}

func hasPasswordInputLinearCSGo(cleanVisibleHTML string) bool {
	if cleanVisibleHTML == "" || (!strings.Contains(cleanVisibleHTML, "password") && !strings.Contains(cleanVisibleHTML, "PASSWORD") && !strings.Contains(strings.ToLower(cleanVisibleHTML), "password")) {
		return false
	}
	found := false
	scanOpenTagsLinearCSGo(cleanVisibleHTML, "input", maxHTMLScanCharsCSGo, func(attrs string) bool {
		if strings.EqualFold(readSimpleTagAttrCSGo(attrs, "type"), "password") {
			found = true
			return false
		}
		return true
	})
	return found
}

// ClassifyContentState classifies a response into `"active"`, `"closed_posting"`, `"soft_404"`, `"temporarily_unavailable"`,
// `"login_wall"`, or `"empty_shell"`
// while applying word-count and structural vetoes so technical articles discussing HTTP 404 or authentication stay `"active"`.
func ClassifyContentState(status int, rawHTML, markdown, finalURL, title string) ContentStateResult {
	if status == 0 {
		status = 200
	}

	// 0. Deterministic ATS silent-redirect dead-link trap (e.g. Greenhouse `?error=true`)
	if strings.TrimSpace(finalURL) != "" {
		if finU, err := url.Parse(strings.TrimSpace(finalURL)); err == nil {
			finHost := strings.ToLower(finU.Hostname())
			isGhFinHost := finHost == "boards.greenhouse.io" ||
				finHost == "job-boards.greenhouse.io" ||
				finHost == "eu-boards.greenhouse.io" ||
				finHost == "job-boards.eu.greenhouse.io"
			if isGhFinHost && finU.Query().Get("error") == "true" {
				return ContentStateResult{
					State:      "closed_posting",
					Reason:     "Greenhouse redirected closed posting to ?error=true.",
					Confidence: 0.98,
				}
			}
		}
	}

	boundedMD := capStringBytesUTF8CSGo(markdown, maxHTMLScanCharsCSGo)
	withoutFences := stripMarkdownFencesOnlyCSGo(boundedMD)
	if strings.Contains(withoutFences, "</") {
		withoutFences = reProseLeakBlocksCSGo.ReplaceAllString(withoutFences, " ")
	}
	proseOnly := strings.TrimSpace(withoutFences)
	words := countWordsFromTextCSGo(proseOnly)

	cleanVisibleHTML := ""
	needVisibleHTML := rawHTML != "" && (strings.TrimSpace(title) == "" || words < 110)
	if needVisibleHTML {
		boundedRaw := capStringBytesUTF8CSGo(rawHTML, maxHTMLScanCharsCSGo)
		lowRaw := strings.ToLower(boundedRaw)
		if strings.Contains(lowRaw, "</script") ||
			strings.Contains(lowRaw, "</style") ||
			strings.Contains(lowRaw, "</noscript") ||
			strings.Contains(lowRaw, "</template") ||
			strings.Contains(lowRaw, "</svg") {
			cleanVisibleHTML = reVisibleHTMLDropCSGo.ReplaceAllString(boundedRaw, " ")
		} else {
			cleanVisibleHTML = boundedRaw
		}
	}
	if strings.TrimSpace(title) == "" && cleanVisibleHTML != "" {
		title = extractRawTitle(cleanVisibleHTML)
	}

	topProse := capStringBytesUTF8CSGo(proseOnly, 900)
	topSlice := title + "\n" + topProse

	// 1. Closed / expired job posting check
	if words < 350 && reClosedPostingCSGo.MatchString(topSlice) {
		return ContentStateResult{
			State:      "closed_posting",
			Reason:     "Page indicates the job posting is closed or no longer accepting applications.",
			Confidence: 0.92,
		}
	}

	// 2. Soft-404 check (HTTP 2xx with compact < 120-word body & 404/not-found title/H1 or < 60-word not-found body)
	if status >= 200 && status < 300 && words < 120 {
		h1Text := ""
		if m := reSoft404H1CSGo.FindStringSubmatch(proseOnly); len(m) == 2 {
			h1Text = m[1]
		}
		headingText := strings.TrimSpace(title + " " + h1Text)
		isNotFoundHeading := headingText != "" && reNotFoundHeadingCSGo.MatchString(headingText)
		isNotFoundBody := proseOnly != "" && reNotFoundBodyCSGo.MatchString(proseOnly)
		if isNotFoundHeading || (words < 60 && isNotFoundBody) {
			return ContentStateResult{
				State:      "soft_404",
				Reason:     "HTTP 200 response contains a Page Not Found (soft-404) body.",
				Confidence: 0.90,
			}
		}
	}

	// 2b. Temporary maintenance page (HTTP 2xx, < 250 words, present-tense site maintenance notice AND a retry
	// phrase, and no Article/Product/JobPosting-class JSON-LD).
	if status >= 200 && status < 300 && words < 250 {
		scan := title + "\n" + capStringBytesUTF8CSGo(proseOnly, 8_000)
		if words == 0 && cleanVisibleHTML != "" {
			scan += "\n" + stripTagsQuoteAwareCSGo(capStringBytesUTF8CSGo(cleanVisibleHTML, 64_000), 64_000)
		}
		if reMaintenanceStatusCSGo.MatchString(scan) && reMaintenanceRetryCSGo.MatchString(scan) &&
			!hasRichSchemaJSONLDCSGo(capStringBytesUTF8CSGo(rawHTML, maxHTMLScanCharsCSGo)) {
			return ContentStateResult{
				State:      "temporarily_unavailable",
				Reason:     "HTTP 2xx response is a temporary maintenance / unavailable notice; retry later.",
				Confidence: 0.85,
			}
		}
	}

	// 3. Login-wall check (thin body < 110 words gated by sign-in prompt or password input outside scripts/templates)
	if words < 110 {
		hasPasswordInput := hasPasswordInputLinearCSGo(cleanVisibleHTML)
		trimmedTitle := strings.TrimSpace(title)
		hasLoginGateHeading := trimmedTitle != "" && reLoginGateHeadingCSGo.MatchString(trimmedTitle)
		hasLoginGateCopy := reLoginGateCopyCSGo.MatchString(topSlice)
		if hasLoginGateCopy || (hasPasswordInput && (hasLoginGateHeading || words < 65)) {
			return ContentStateResult{
				State:      "login_wall",
				Reason:     "Content is gated behind an authentication / sign-in wall.",
				Confidence: 0.90,
			}
		}
	}

	// 4. Unrendered thin `<iframe>` shell check (< 50 extracted words on HTTP 2xx)
	if status >= 200 && status < 300 && words < 50 && rawHTML != "" {
		iframeShell, isIcims := scanIframesInternalCSGo(rawHTML, finalURL, true)
		if iframeShell.HasExternalIframe {
			reason := "Unrendered HTML shell (< 50 words) wrapping an external or widget <iframe>."
			if isIcims {
				reason = "Unrendered iCIMS ATS iframe shell (#icims_content_iframe) with < 50 words of outer chrome."
			}
			return ContentStateResult{
				State:      "empty_shell",
				Reason:     reason,
				Confidence: 0.88,
			}
		}
	}

	return ContentStateResult{
		State:      "active",
		Confidence: 1.0,
	}
}

// IsEligibleForWaybackFallback reports whether a failed origin fetch is strictly eligible for Internet Archive
// (`Wayback CDX`) link-rot recovery: ONLY `5xx` or network/DNS unreachability (`status == 0`) on unauthenticated
// `GET`/`HEAD` requests — NEVER on `robots.txt`, challenges/WAF, SSRF, `401`, `402`, `403`, `404`, `410`, `429`, or `451`.
func IsEligibleForWaybackFallback(status int, outcome, wafCategory, urlStr, method string, hasAuthHeaders bool) bool {
	if hasAuthHeaders {
		return false
	}
	if strings.TrimSpace(wafCategory) != "" {
		return false
	}
	m := strings.ToUpper(strings.TrimSpace(method))
	if m != "" && m != "GET" && m != "HEAD" {
		return false
	}
	if strings.TrimSpace(urlStr) != "" {
		u, err := url.Parse(strings.TrimSpace(urlStr))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			return false
		}
		h := strings.ToLower(u.Hostname())
		if h == "localhost" || strings.HasSuffix(h, ".local") || h == "archive.org" || h == "web.archive.org" {
			return false
		}
	}

	out := strings.ToLower(strings.TrimSpace(outcome))
	switch out {
	case "ok",
		"challenge",
		"blocked",
		"blocked_ssrf",
		"ssrf",
		"scheme_downgrade",
		"robots_disallowed",
		"robots",
		"robots_unreachable",
		"content_signal_disallowed",
		"content-signal",
		"payment_required",
		"rate_limited",
		"not_found",
		"gone",
		"use_bulk_channel":
		return false
	}
	if strings.Contains(out, "robots") ||
		strings.Contains(out, "challenge") ||
		strings.Contains(out, "cf-mitigated") ||
		strings.Contains(out, "content-signal") ||
		strings.Contains(out, "ai-input=no") ||
		strings.Contains(out, "ssrf") ||
		strings.Contains(out, "non-public ip") {
		return false
	}

	switch status {
	case 401, 402, 403, 404, 410, 429, 451:
		return false
	}
	return status == 0 || (status >= 500 && status <= 599)
}

func isWikimediaHostCSGo(host string) bool {
	suffixes := []string{
		"wikipedia.org",
		"wikimedia.org",
		"wiktionary.org",
		"wikibooks.org",
		"wikiquote.org",
		"wikisource.org",
		"wikiversity.org",
		"wikivoyage.org",
		"wikidata.org",
		"mediawiki.org",
	}
	for _, sfx := range suffixes {
		if host == sfx || (strings.HasSuffix(host, "."+sfx) && len(host) > len(sfx)+1) {
			return true
		}
	}
	return false
}

func extractWikiLangCSGo(host string) string {
	if !strings.HasSuffix(host, ".wikipedia.org") || len(host) <= len(".wikipedia.org") {
		return "en"
	}
	sub := strings.TrimSuffix(host, ".wikipedia.org")
	sub = strings.TrimSuffix(sub, ".m")
	if sub == "" || sub == "www" || sub == "m" || sub == "meta" || sub == "commons" || sub == "foundation" {
		return "en"
	}
	return sub
}

func buildDefaultBlockedSuggestionCSGo(host, pathname, reason string) string {
	if reason == "robots" && isWikimediaHostCSGo(host) {
		lang := extractWikiLangCSGo(host)
		wikiHost := lang + ".wikipedia.org"
		return "Wikipedia search and API paths are robots-disallowed. Use `search` with `site:" + wikiHost + "` (or `wikipedia: true`), " +
			"or fetch `https://" + wikiHost + "/wiki/<Title>` directly. For bulk or structured corpus access, use Wikimedia Enterprise " +
			"(https://enterprise.wikimedia.com/) or Wikimedia Dumps (https://dumps.wikimedia.org/)."
	}
	if reSmartRecruitersAPIHostCSGo.MatchString(host) {
		return "api.smartrecruiters.com disallows automated access in robots.txt. Scrape the public HTML posting on `https://jobs.smartrecruiters.com/{Company}/{JobId}` instead (it embeds structured schema.org JobPosting metadata)."
	}
	if host == "icims.com" || strings.HasSuffix(host, ".icims.com") {
		return host + " is the employer's iCIMS ATS portal. Try rendering with browser / ?in_iframe=1 or check if the employer mirrors openings on its main careers site."
	}
	if reBlockedAggregatorHostCSGo.MatchString(host) {
		how := "requests with an anti-bot challenge"
		if reason == "robots" {
			how = "crawlers via robots.txt"
		}
		return host + " blocks automated " + how + ". Run `jobs` or `search` with `site:job-boards.greenhouse.io OR site:jobs.ashbyhq.com OR site:jobs.lever.co OR site:myworkdayjobs.com \"<company> <role>\"` (or `builtin.com`) to read the employer's official posting directly."
	}
	if host == "pypi.org" && rePyPIJSONPathCSGo.MatchString(pathname) {
		return "pypi.org disallows /pypi/*/json in robots.txt; scrape https://pypi.org/project/<package>/ instead."
	}
	if host == "openstreetmap.org" || strings.HasSuffix(host, ".openstreetmap.org") {
		return "openstreetmap.org disallows /node/, /way/, /relation/, and /api/ in robots.txt to protect community servers. Query Nominatim, the Overpass API, or bulk Planet.osm extracts instead."
	}
	if host == "npr.org" || strings.HasSuffix(host, ".npr.org") {
		how := "bot protection"
		if reason == "robots" {
			how = "robots.txt"
		}
		return host + " blocks automated HTML scraping via " + how + ". Fetch NPR's official public RSS feeds instead: `https://feeds.npr.org/1001/rss.xml` (News), `https://feeds.npr.org/1003/rss.xml` (US), or `https://feeds.npr.org/1004/rss.xml` (World)."
	}
	if host == "bbc.com" || strings.HasSuffix(host, ".bbc.com") || host == "bbc.co.uk" || strings.HasSuffix(host, ".bbc.co.uk") {
		how := "bot protection"
		if reason == "robots" {
			how = "robots.txt"
		}
		return host + " restricts automated HTML scraping via " + how + ". Fetch BBC News's official public RSS feed instead: `https://feeds.bbci.co.uk/news/rss.xml` (or `https://feeds.bbci.co.uk/news/world/rss.xml`)."
	}
	if host == "apnews.com" || strings.HasSuffix(host, ".apnews.com") || host == "reuters.com" || strings.HasSuffix(host, ".reuters.com") {
		how := "anti-bot challenge"
		if reason == "robots" {
			how = "robots.txt"
		}
		return host + " blocks automated HTML scraping via " + how + ". Call `search` with `topic: \"news\"` or scrape official broadcaster RSS feeds (`https://www.cbsnews.com/latest/rss/main`, `https://feeds.nbcnews.com/nbcnews/public/news`, `https://feeds.npr.org/1001/rss.xml`, `https://feeds.bbci.co.uk/news/rss.xml`)."
	}
	labelHost := host
	if labelHost == "" {
		labelHost = "origin"
	}
	if reason == "robots" {
		return labelHost + " disallows this path in robots.txt."
	}
	return labelHost + " blocked automated access with an anti-bot challenge. Do not retry or attempt to bypass; check for an official API, RSS feed, or public dataset instead."
}

// RefineBlockedInfo normalizes block metadata across SSRF, HTTPS->HTTP scheme downgrades, RFC 9309 §2.3.1.4
// `robots_unreachable`, non-challenge HTTP 429 rate limits, iCIMS ATS portals, robots disallows, and WAF challenges.
func RefineBlockedInfo(urlStr string, status int, outcome string, waf *WAFMatch, existingSuggestion string) BlockedRefinement {
	host := ""
	pathname := ""
	if strings.TrimSpace(urlStr) != "" {
		if u, err := url.Parse(strings.TrimSpace(urlStr)); err == nil {
			host = strings.TrimRight(strings.ToLower(u.Hostname()), ".")
			pathname = u.Path
		}
	}

	outStr := strings.ToLower(strings.TrimSpace(outcome))
	sugStr := strings.TrimSpace(existingSuggestion)
	diag := outStr + " " + sugStr

	if outStr == "dns_not_found" || reDNSNotFoundCSGo.MatchString(diag) {
		return BlockedRefinement{}
	}

	if outStr == "scheme_downgrade" || reSchemeDowngradeCSGo.MatchString(diag) {
		return BlockedRefinement{
			Reason:    "scheme_downgrade",
			Host:      host,
			Retryable: false,
			Message:   "HTTPS-to-HTTP scheme downgrade redirect was blocked.",
		}
	}

	if outStr == "blocked_ssrf" || outStr == "ssrf" || reSSRFBlockedCSGo.MatchString(diag) {
		return BlockedRefinement{
			Reason:    "ssrf",
			Host:      host,
			Retryable: false,
			Message:   "Target or redirect resolved to a non-public/metadata IP address and was blocked.",
		}
	}

	if strings.HasPrefix(outStr, "robots_unreachable") ||
		strings.HasPrefix(strings.ToLower(sugStr), "robots_unreachable") ||
		((outStr == "stop" || outStr == "robots_unreachable" || outStr == "error") && reRobotsUnreachableCSGo.MatchString(diag)) {
		labelHost := host
		if labelHost == "" {
			labelHost = "origin"
		}
		return BlockedRefinement{
			Reason:     "robots_unreachable",
			Host:       labelHost,
			Retryable:  true,
			Suggestion: labelHost + "'s /robots.txt timed out or returned 5xx (disallow assumed temporarily per RFC 9309 §2.3.1.4). Retry shortly.",
		}
	}

	if status == 402 || outStr == "payment_required" {
		labelHost := host
		if labelHost == "" {
			labelHost = "This origin"
		}
		sug := sugStr
		if sug == "" {
			sug = labelHost + " returned HTTP 402 Payment Required. EdgeFetch never pays automatically; inform the user or select a free public source."
		}
		return BlockedRefinement{
			Reason:     "payment_required",
			Host:       host,
			Retryable:  false,
			Suggestion: sug,
		}
	}

	if outStr == "content_signal_disallowed" || outStr == "content-signal" || reContentSignalCSGo.MatchString(diag) {
		labelHost := host
		if labelHost == "" {
			labelHost = "This host"
		}
		sug := sugStr
		if sug == "" {
			sug = labelHost + " declares `Content-Signal: ai-input=no` in robots.txt, opting out of agent input retrieval. Respect the publisher's preference and use an official API or opted-in source instead."
		}
		return BlockedRefinement{
			Reason:     "content-signal",
			Host:       host,
			Retryable:  false,
			Suggestion: sug,
		}
	}

	if (status == 429 || outStr == "rate_limited") && outStr != "challenge" && (waf == nil || waf.Category == "rate_limit") {
		labelHost := host
		if labelHost == "" {
			labelHost = "origin"
		}
		sug := sugStr
		if sug == "" || reDisallowsPathInRobotsCSGo.MatchString(sug) {
			sug = labelHost + " returned HTTP 429 Too Many Requests. Wait out the cooldown window before retrying."
		}
		vend := ""
		if waf != nil {
			vend = waf.Vendor
		}
		return BlockedRefinement{
			Reason:     "rate_limited",
			Host:       labelHost,
			Category:   "rate_limit",
			Vendor:     vend,
			Retryable:  true,
			Suggestion: sug,
		}
	}

	if host == "icims.com" || strings.HasSuffix(host, ".icims.com") {
		isRobots := outStr == "robots_disallowed" || outStr == "robots" || strings.Contains(strings.ToLower(sugStr), "robots.txt")
		isChallenge := waf != nil || outStr == "challenge"
		if isRobots || isChallenge || sugStr != "" {
			reason := "challenge"
			if isRobots {
				reason = "robots"
			}
			sug := sugStr
			if sug == "" || reAggregatorSugCSGo.MatchString(sug) {
				sug = host + " is the employer's iCIMS ATS portal. Try rendering with browser / ?in_iframe=1 or check if the employer mirrors openings on its main careers site."
			}
			vend := ""
			cat := ""
			if waf != nil {
				vend = waf.Vendor
				cat = waf.Category
			}
			return BlockedRefinement{
				Reason:     reason,
				Host:       host,
				Vendor:     vend,
				Category:   cat,
				Retryable:  false,
				Suggestion: sug,
			}
		}
	}

	isRobots := outStr == "robots_disallowed" || outStr == "robots" || strings.Contains(strings.ToLower(sugStr), "robots.txt")
	if isRobots {
		sug := sugStr
		if sug == "" {
			sug = buildDefaultBlockedSuggestionCSGo(host, pathname, "robots")
		}
		return BlockedRefinement{
			Reason:     "robots",
			Host:       host,
			Retryable:  false,
			Suggestion: sug,
		}
	}

	if waf != nil || outStr == "challenge" {
		sug := sugStr
		if sug == "" {
			sug = buildDefaultBlockedSuggestionCSGo(host, pathname, "challenge")
		}
		vend := ""
		cat := "challenge"
		if waf != nil {
			vend = waf.Vendor
			cat = waf.Category
		}
		return BlockedRefinement{
			Reason:     "challenge",
			Host:       host,
			Vendor:     vend,
			Category:   cat,
			Retryable:  false,
			Suggestion: sug,
		}
	}

	if sugStr != "" {
		return BlockedRefinement{
			Reason:     outStr,
			Host:       host,
			Retryable:  false,
			Suggestion: sugStr,
		}
	}

	return BlockedRefinement{}
}

// RefineBlockedMapInput mirrors `waf.ts:refineBlockedInfo` parameters for exact Hub parity.
type RefineBlockedMapInput struct {
	URL         string         `json:"url"`
	Outcome     string         `json:"outcome,omitempty"`
	Problem     string         `json:"problem,omitempty"`
	Status      int            `json:"status,omitempty"`
	RetryAfter  string         `json:"retryAfter,omitempty"`
	BaseBlocked map[string]any `json:"baseBlocked,omitempty"`
	NowMs       int64          `json:"nowMs,omitempty"`
}

// RefineBlockedInfoMap post-processes `baseBlocked` map metadata with exact Hub parity (`dns_not_found` -> nil,
// `scheme_downgrade`, `ssrf`, `robots_unreachable`, `rate_limited` + `retryAfterMs`, and `icims.com` ATS guidance).
func RefineBlockedInfoMap(in RefineBlockedMapInput) map[string]any {
	nowMs := in.NowMs
	if nowMs <= 0 {
		nowMs = time.Now().UnixMilli()
	}
	host := ""
	if strings.TrimSpace(in.URL) != "" {
		if u, err := url.Parse(strings.TrimSpace(in.URL)); err == nil {
			host = strings.TrimRight(strings.ToLower(u.Hostname()), ".")
		}
	}
	outStr := strings.ToLower(strings.TrimSpace(in.Outcome))
	probStr := strings.TrimSpace(in.Problem)

	if outStr == "dns_not_found" || reDNSNotFoundCSGo.MatchString(probStr) {
		return nil
	}

	baseReason, _ := in.BaseBlocked["reason"].(string)
	if outStr == "scheme_downgrade" || (outStr == "blocked" && baseReason == "scheme_downgrade") || reSchemeDowngradeCSGo.MatchString(probStr) {
		return map[string]any{
			"reason":    "scheme_downgrade",
			"retryable": false,
			"message":   "HTTPS-to-HTTP scheme downgrade redirect was blocked.",
		}
	}

	if outStr == "blocked_ssrf" || (outStr == "blocked" && baseReason == "ssrf") || reSSRFBlockedCSGo.MatchString(probStr) {
		return map[string]any{
			"reason":    "ssrf",
			"retryable": false,
			"message":   "Target or redirect resolved to a non-public/metadata IP address and was blocked.",
		}
	}

	if strings.HasPrefix(strings.ToLower(probStr), "robots_unreachable") ||
		((outStr == "stop" || outStr == "robots_unreachable" || outStr == "error") && reRobotsUnreachableCSGo.MatchString(probStr)) {
		labelHost := host
		if labelHost == "" {
			labelHost = "origin"
		}
		return map[string]any{
			"reason":     "robots_unreachable",
			"host":       labelHost,
			"suggestion": labelHost + "'s /robots.txt timed out or returned 5xx (disallow assumed temporarily per RFC 9309 §2.3.1.4). Retry shortly.",
		}
	}

	var retryAfterMs *int64
	if ra := strings.TrimSpace(in.RetryAfter); ra != "" {
		allDigits := true
		for i := 0; i < len(ra); i++ {
			if ra[i] < '0' || ra[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			if secs, err := strconv.ParseInt(ra, 10, 64); err == nil && secs >= 0 {
				ms := secs * 1000
				retryAfterMs = &ms
			}
		} else {
			for _, layout := range []string{time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC} {
				if parsedDate, err := time.Parse(layout, ra); err == nil {
					delta := parsedDate.UnixMilli() - nowMs
					if delta < 0 {
						delta = 0
					}
					retryAfterMs = &delta
					break
				}
			}
		}
	}

	if (in.Status == 429 || outStr == "rate_limited") && outStr != "challenge" && baseReason != "challenge" {
		labelHost := host
		if labelHost == "" {
			if bh, ok := in.BaseBlocked["host"].(string); ok && bh != "" {
				labelHost = bh
			} else {
				labelHost = "origin"
			}
		}
		out := make(map[string]any, len(in.BaseBlocked)+4)
		for k, v := range in.BaseBlocked {
			out[k] = v
		}
		out["reason"] = "rate_limited"
		out["host"] = labelHost
		if retryAfterMs != nil {
			out["retryAfterMs"] = *retryAfterMs
		}
		baseSug, _ := in.BaseBlocked["suggestion"].(string)
		if baseSug != "" && !reDisallowsPathInRobotsCSGo.MatchString(baseSug) {
			out["suggestion"] = baseSug
		} else {
			raNote := ""
			if retryAfterMs != nil {
				secs := (*retryAfterMs + 999) / 1000
				raNote = " (Retry-After: " + strconv.FormatInt(secs, 10) + "s)"
			}
			out["suggestion"] = labelHost + " returned HTTP 429 Too Many Requests" + raNote + ". Wait out the cooldown window before retrying."
		}
		return out
	}

	if in.BaseBlocked != nil && (host == "icims.com" || strings.HasSuffix(host, ".icims.com")) {
		sug, _ := in.BaseBlocked["suggestion"].(string)
		cat, _ := in.BaseBlocked["category"].(string)
		if reAggregatorSugCSGo.MatchString(sug) || cat == "aggregator" {
			cp := make(map[string]any, len(in.BaseBlocked))
			for k, v := range in.BaseBlocked {
				if k != "category" {
					cp[k] = v
				}
			}
			cp["suggestion"] = host + " is the employer's iCIMS ATS portal. Try rendering with browser / ?in_iframe=1 or check if the employer mirrors openings on its main careers site."
			return cp
		}
	}

	return in.BaseBlocked
}
