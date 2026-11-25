package classify

import (
	"html"
	"strings"
)

// WAFMatch describes a detected Web Application Firewall (WAF) or anti-bot challenge interstitial (`R2` & `R3`).
// EdgeFetch strictly halts on challenges and WAF blocks — never solving, clicking through, or bypassing them.
type WAFMatch struct {
	Vendor     string   `json:"vendor"`            // "cloudflare", "akamai", "datadome", "perimeterx", "aws-waf", "imperva", "vercel", "fastly", "kasada", "generic"
	Category   string   `json:"category"`          // "challenge" | "waf_block" | "rate_limit"
	Confidence float64  `json:"confidence"`        // 0.0 .. 1.0 (1.0 = authoritative HTTP header)
	Signals    []string `json:"signals,omitempty"` // Matched header/DOM indicators
	Summary    string   `json:"summary,omitempty"` // Human-readable diagnostic summary
}

var (
	reWafScriptDataStrip = newLazyRegexp(`(?is)<script\b[^>]*(?:type\s*=\s*["']application/(?:ld\+)?json["']|id\s*=\s*["']__(?:NEXT|NUXT)_DATA__["'])[^>]*>.*?</script>`)
	reWafCodeQuoteStrip  = newLazyRegexp(`(?is)<(?:pre|code|blockquote|textarea|svg|style)\b[^>]*>.*?</(?:pre|code|blockquote|textarea|svg|style)>`)
	reWafAllScriptsStrip = newLazyRegexp(`(?is)<script\b[^>]*>.*?</script>`)
	reWafHTMLComments    = newLazyRegexp(`(?is)<!--.*?-->`)
	reWafAnyTag          = newLazyRegexp(`(?s)<[^>]+>`)
	reWafTitle           = newLazyRegexp(`(?is)<title\b[^>]*>(.*?)</title>`)
	reWafMainOrArticle   = newLazyRegexp(`(?is)<(?:main|article)\b[^>]*>(.*?)</(?:main|article)>`)
	reWafSubheadings     = newLazyRegexp(`(?is)<h[23]\b[^>]*>.*?</h[23]>`)
	reWafNavBlock        = newLazyRegexp(`(?is)<nav\b[^>]*>(.*?)</nav>`)
	reWafNavAnchor       = newLazyRegexp(`(?is)<a\b[^>]*\bhref\s*=`)
	reWafSchemaRichType  = newLazyRegexp(`(?is)<script\b[^>]*type\s*=\s*["']application/ld\+json["'][^>]*>[^<]*"@type"\s*:\s*(?:\[[^\]]*)?["'](?:Article|TechArticle|NewsArticle|BlogPosting|ScholarlyArticle|JobPosting|Product|SoftwareSourceCode|FAQPage|APIReference)["']`)

	reCloudflareTitle = newLazyRegexp(`(?i)^\s*(?:just a moment\.{0,3}|attention required!\s*\|\s*cloudflare|ddos-guard|checking your browser)\s*$`)
	reGenericTitle    = newLazyRegexp(`(?i)^\s*(?:verify you are human|human verification|pardon our interruption|access to this page has been denied|bot verification|security check)\s*$`)
	reAkamaiRef       = newLazyRegexp(`(?i)reference\s*#18\.[0-9a-f]{4,}\.[0-9]{6,}`)
)

func countPlainWords(s string) int {
	plain := html.UnescapeString(reWafAnyTag.ReplaceAllString(s, " "))
	return len(strings.Fields(plain))
}

func extractRawTitle(raw string) string {
	m := reWafTitle.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(reWafAnyTag.ReplaceAllString(m[1], " ")))
}

// hasStructuralContentVeto implements Anti-False-Positive Guardrails #2 & #4 (`R3`):
// On HTTP 2xx responses, real content pages (with >= 250 words in <main>/<article>/body, >= 2 <h2>/<h3> headings,
// rich Schema.org Article/JobPosting/Product JSON-LD, or <nav> with >= 4 links + >= 120 words) NEVER false-positive
// as challenges even if they embed a footer reCAPTCHA/hCaptcha or discuss WAFs/Turnstile in prose!
func hasStructuralContentVeto(status int, rawHTML string) (veto bool, visibleWords int) {
	noComments := reWafHTMLComments.ReplaceAllString(rawHTML, " ")
	visibleClean := reWafAllScriptsStrip.ReplaceAllString(reWafCodeQuoteStrip.ReplaceAllString(noComments, " "), " ")
	visibleWords = countPlainWords(visibleClean)

	if status < 200 || status >= 300 {
		return false, visibleWords
	}

	if reWafSchemaRichType.MatchString(rawHTML) {
		return true, visibleWords
	}
	if mainMatch := reWafMainOrArticle.FindStringSubmatch(visibleClean); len(mainMatch) == 2 {
		if countPlainWords(mainMatch[1]) >= 250 {
			return true, visibleWords
		}
	}
	if visibleWords >= 250 {
		return true, visibleWords
	}
	if len(reWafSubheadings.FindAllStringIndex(visibleClean, 3)) >= 2 && visibleWords >= 100 {
		return true, visibleWords
	}
	for _, nm := range reWafNavBlock.FindAllStringSubmatch(noComments, 4) {
		if len(nm) == 2 && len(reWafNavAnchor.FindAllStringIndex(nm[1], 5)) >= 4 && visibleWords >= 120 {
			return true, visibleWords
		}
	}
	return false, visibleWords
}

// ClassifyWAF evaluates response status, HTTP headers, and HTML/JSON body against the 7-vendor WAF & Challenge
// Signature Catalog (`R2`) while enforcing all 4 Anti-False-Positive Guardrails (`R3`).
func ClassifyWAF(status int, header map[string][]string, body []byte) *WAFMatch {
	// --- Layer 1: Authoritative HTTP Response Headers (100% confidence regardless of body length) ---
	if header != nil {
		if rawCf := headerGet(header, "cf-mitigated"); rawCf != "" {
			cfMit := strings.ToLower(strings.TrimSpace(rawCf))
			if cfMit == "" {
				cfMit = "challenge"
			}
			cat := "challenge"
			if cfMit == "block" {
				cat = "waf_block"
			}
			return &WAFMatch{
				Vendor:     "cloudflare",
				Category:   cat,
				Confidence: 1.0,
				Signals:    []string{"header:cf-mitigated=" + cfMit},
				Summary:    "Cloudflare " + cat + " (cf-mitigated)",
			}
		}
		if amzAct := strings.ToLower(strings.TrimSpace(headerGet(header, "x-amzn-waf-action"))); amzAct == "challenge" || amzAct == "captcha" || amzAct == "block" {
			cat := "challenge"
			if amzAct == "block" {
				cat = "waf_block"
			}
			return &WAFMatch{
				Vendor:     "aws-waf",
				Category:   cat,
				Confidence: 1.0,
				Signals:    []string{"header:x-amzn-waf-action=" + amzAct},
				Summary:    "AWS WAF " + amzAct + " (x-amzn-waf-action)",
			}
		}
		if vMit := strings.ToLower(strings.TrimSpace(headerGet(header, "x-vercel-mitigated"))); vMit != "" {
			cat := "challenge"
			if vMit == "deny" || vMit == "block" {
				cat = "waf_block"
			}
			return &WAFMatch{
				Vendor:     "vercel",
				Category:   cat,
				Confidence: 1.0,
				Signals:    []string{"header:x-vercel-mitigated=" + vMit},
				Summary:    "Vercel Firewall mitigation (" + vMit + ")",
			}
		}
		ddHdr := strings.ToLower(strings.TrimSpace(headerGet(header, "x-datadome")))
		ddB := strings.TrimSpace(headerGet(header, "x-dd-b"))
		if (status == 403 || status == 401 || status == 429) && (ddHdr == "protected" || ddB != "") {
			return &WAFMatch{
				Vendor:     "datadome",
				Category:   "challenge",
				Confidence: 1.0,
				Signals:    []string{"header:x-datadome"},
				Summary:    "DataDome anti-bot interstitial",
			}
		}
		if strings.TrimSpace(headerGet(header, "x-kpsdk-ct")) != "" && (status == 429 || status == 403) {
			return &WAFMatch{
				Vendor:     "kasada",
				Category:   "challenge",
				Confidence: 1.0,
				Signals:    []string{"header:x-kpsdk-ct"},
				Summary:    "Kasada anti-bot challenge",
			}
		}
		if strings.TrimSpace(headerGet(header, "x-px-blocked")) == "1" {
			return &WAFMatch{
				Vendor:     "perimeterx",
				Category:   "challenge",
				Confidence: 1.0,
				Signals:    []string{"header:x-px-blocked=1"},
				Summary:    "PerimeterX / HUMAN block interstitial",
			}
		}
	}

	if len(body) == 0 {
		return nil
	}
	// Cap body inspection to 96 KiB — real interstitials are compact shells, never multi-megabyte documents.
	if status >= 200 && status < 300 && len(body) > 49_152 {
		return nil
	}
	sample := body
	if len(sample) > 98_304 {
		sample = sample[:98_304]
	}
	rawStr := string(sample)

	// --- Layer 2 & Layer 4: Structural Content Veto & Payload Shape Check on 200 OK ---
	vetoed, visibleWords := hasStructuralContentVeto(status, rawStr)
	if vetoed {
		return nil
	}
	if status >= 200 && status < 300 && visibleWords >= 120 {
		return nil
	}

	// --- Layer 3: Strip <pre>, <code>, <blockquote>, JSON-LD, and SSR hydration JSON before body pattern matching ---
	scrubbed := reWafCodeQuoteStrip.ReplaceAllString(reWafScriptDataStrip.ReplaceAllString(rawStr, " "), " ")
	scrubbedLower := strings.ToLower(scrubbed)
	title := extractRawTitle(scrubbed)
	serverHdr := ""
	setCookie := ""
	if header != nil {
		serverHdr = strings.ToLower(headerGet(header, "server"))
		setCookie = strings.ToLower(strings.Join(headerValues(header, "set-cookie"), "; "))
	}

	// 1. Cloudflare interstitial body
	if reCloudflareTitle.MatchString(title) ||
		(strings.Contains(scrubbedLower, "_cf_chl_opt") && strings.Contains(scrubbedLower, "/cdn-cgi/challenge-platform/")) ||
		(visibleWords < 80 && strings.Contains(scrubbedLower, "challenges.cloudflare.com/turnstile") && reGenericTitle.MatchString(title)) {
		return &WAFMatch{
			Vendor:     "cloudflare",
			Category:   "challenge",
			Confidence: 0.95,
			Signals:    []string{"dom:cloudflare-challenge"},
			Summary:    "Cloudflare anti-bot challenge page",
		}
	}

	// 2. DataDome interstitial
	if strings.Contains(scrubbedLower, "geo.captcha-delivery.com") || strings.Contains(scrubbedLower, "ct.captcha-delivery.com") {
		return &WAFMatch{
			Vendor:     "datadome",
			Category:   "challenge",
			Confidence: 0.96,
			Signals:    []string{"dom:captcha-delivery.com"},
			Summary:    "DataDome CAPTCHA interstitial",
		}
	}

	// 3. PerimeterX / HUMAN Security
	if (strings.Contains(scrubbedLower, "px-captcha") && (strings.Contains(scrubbedLower, "_pxappid") || strings.Contains(scrubbedLower, "perimeterx") || strings.Contains(setCookie, "_pxhd="))) ||
		(strings.Contains(scrubbedLower, `"appid":"px`) && strings.Contains(scrubbedLower, `"blockscript"`)) {
		return &WAFMatch{
			Vendor:     "perimeterx",
			Category:   "challenge",
			Confidence: 0.95,
			Signals:    []string{"dom:px-captcha"},
			Summary:    "PerimeterX / HUMAN anti-bot challenge",
		}
	}

	// 4. Akamai Bot Manager (`AkamaiGHost` + `Reference #18.` or `_abck` interstitial)
	if (strings.Contains(serverHdr, "akamaighost") || strings.Contains(serverHdr, "akamai") || strings.Contains(setCookie, "_abck=")) &&
		(reAkamaiRef.MatchString(scrubbed) || (status == 403 && strings.Contains(scrubbedLower, "edgesuite.net"))) {
		return &WAFMatch{
			Vendor:     "akamai",
			Category:   "waf_block",
			Confidence: 0.95,
			Signals:    []string{"dom:akamai-reference-18"},
			Summary:    "Akamai Bot Manager access denied (Reference #18)",
		}
	}

	// 5. AWS WAF CAPTCHA / Challenge body
	if strings.Contains(scrubbedLower, "awswafintegration") || strings.Contains(scrubbedLower, "aws-waf-token") || strings.Contains(scrubbedLower, "awswaf-captcha") {
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

	// 7. Fastly WAF 403 block page
	if status == 403 && (strings.Contains(serverHdr, "fastly") || (header != nil && headerGet(header, "x-served-by") != "")) &&
		!strings.Contains(scrubbedLower, "fastly error: unknown domain") &&
		strings.Contains(scrubbedLower, "request blocked") && visibleWords < 80 {
		return &WAFMatch{
			Vendor:     "fastly",
			Category:   "waf_block",
			Confidence: 0.88,
			Signals:    []string{"dom:fastly-403-block"},
			Summary:    "Fastly WAF 403 block page",
		}
	}

	// 8. Generic interstitial shell (`<title>Verify you are human</title>`, NCBI JS check, or Anubis PoW gate on < 80-word shell)
	if visibleWords < 80 {
		if reGenericTitle.MatchString(title) &&
			(strings.Contains(scrubbedLower, "g-recaptcha") || strings.Contains(scrubbedLower, "h-captcha") || strings.Contains(scrubbedLower, "cf-turnstile")) {
			return &WAFMatch{
				Vendor:     "generic",
				Category:   "challenge",
				Confidence: 0.88,
				Signals:    []string{"title:" + title},
				Summary:    "anti-bot challenge page (" + title + ")",
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
