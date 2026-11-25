package extract

import (
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	// FrameworkDetectWindowChars bounds framework/platform detection to the first 64 KiB (65,536 UTF-16 code units).
	FrameworkDetectWindowChars = 65_536

	defaultInertiaMaxScanCharsFWGo = 524_288
	maxInertiaPayloadCharsFWGo     = 262_144
)

// SafeResponseHeaderAllowlist lists response headers safe for framework/platform detection without leaking secrets like set-cookie.
var SafeResponseHeaderAllowlist = []string{
	"server",
	"powered-by",
	"x-powered-by",
	"x-generator",
	"x-shopid",
	"x-shopify-stage",
	"x-wix-request-id",
	"x-drupal-cache",
	"x-drupal-dynamic-cache",
	"x-nextjs-cache",
	"x-remix-response",
	"x-vercel-id",
	"x-nf-request-id",
	"x-github-request-id",
	"x-hs-hub-id",
	"x-typo3-parsetime",
	"cf-ray",
	"cf-cache-status",
	"cf-mitigated",
	"via",
	"vary",
	"link",
	"x-robots-tag",
	"content-signal",
	"x-markdown-tokens",
	"cache-control",
}

// BrowserFrameworkGlobals captures optional client-side framework globals observed during CDP browser rendering.
type BrowserFrameworkGlobals struct {
	Next        bool `json:"next,omitempty"`
	Nuxt        bool `json:"nuxt,omitempty"`
	Remix       bool `json:"remix,omitempty"`
	ReactRouter bool `json:"reactRouter,omitempty"`
	SvelteKit   bool `json:"sveltekit,omitempty"`
	Angular     bool `json:"angular,omitempty"`
	Qwik        bool `json:"qwik,omitempty"`
	Solid       bool `json:"solid,omitempty"`
	Shopify     bool `json:"shopify,omitempty"`
	WP          bool `json:"wp,omitempty"`
	Webflow     bool `json:"webflow,omitempty"`
	Squarespace bool `json:"squarespace,omitempty"`
	Wix         bool `json:"wix,omitempty"`
}

// DetectedSiteStack summarizes the detected CMS/commerce/docs platform and frontend framework for a response.
type DetectedSiteStack struct {
	Source       string   `json:"source"`
	Platform     string   `json:"platform,omitempty"`
	Framework    string   `json:"framework,omitempty"`
	Generators   []string `json:"generators"`
	Signals      []string `json:"signals"`
	ContentFlags []string `json:"contentFlags,omitempty"`
}

// DetectSiteFrameworkParams configures bounded 64 KiB framework and platform detection.
type DetectSiteFrameworkParams struct {
	URL           string                   `json:"url,omitempty"`
	Body          string                   `json:"body,omitempty"`
	ContentSource string                   `json:"contentSource,omitempty"`
	Headers       map[string]string        `json:"headers,omitempty"`
	Globals       *BrowserFrameworkGlobals `json:"globals,omitempty"`
}

var (
	reEntityQuotFWGo = newLazyRegexp(`(?i)&quot;`)
	reEntityAposFWGo = newLazyRegexp(`(?i)&apos;`)
	reEntityLtFWGo   = newLazyRegexp(`(?i)&lt;`)
	reEntityGtFWGo   = newLazyRegexp(`(?i)&gt;`)
	reEntityAmpFWGo  = newLazyRegexp(`(?i)&amp;`)
)

func isAsciiWsFWGo(c byte) bool {
	return c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0c || c == 0x0d
}

func isAttrNameCharFWGo(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == ':'
}

func decodeBasicHTMLEntitiesFWGo(s string) string {
	if strings.IndexByte(s, '&') < 0 {
		return s
	}
	out := reEntityQuotFWGo.ReplaceAllString(s, `"`)
	out = strings.ReplaceAll(out, "&#34;", `"`)
	out = reEntityAposFWGo.ReplaceAllString(out, `'`)
	out = strings.ReplaceAll(out, "&#39;", `'`)
	out = reEntityLtFWGo.ReplaceAllString(out, `<`)
	out = reEntityGtFWGo.ReplaceAllString(out, `>`)
	out = reEntityAmpFWGo.ReplaceAllString(out, `&`)
	return out
}

func sliceUTF16WindowFWGo(s string, maxUnits int) string {
	if maxUnits <= 0 || s == "" {
		return ""
	}
	if len(s) <= maxUnits {
		return s
	}
	units := 0
	for idx, r := range s {
		step := 1
		if r >= 0x10000 {
			step = 2
		}
		if units+step > maxUnits {
			return s[:idx]
		}
		units += step
	}
	return s
}

func capUTF16UnitsFWGo(s string, maxUnits int) string {
	return sliceUTF16WindowFWGo(s, maxUnits)
}

// ScanGeneratorMetaTags linearly scans `<meta ...>` tags inside the first maxChars (default 65,536) and returns
// every `<meta name="generator">` content value in document order, regardless of quote style, case, or attribute order.
func ScanGeneratorMetaTags(htmlStr string, maxChars int) []string {
	if maxChars <= 0 {
		maxChars = FrameworkDetectWindowChars
	}
	win := sliceUTF16WindowFWGo(htmlStr, maxChars)
	limit := len(win)
	generators := []string{}
	pos := 0

	for pos < limit {
		relLt := strings.IndexByte(win[pos:], '<')
		if relLt < 0 {
			break
		}
		lt := pos + relLt
		if lt+5 >= limit {
			break
		}

		c1 := win[lt+1] | 0x20
		c2 := win[lt+2] | 0x20
		c3 := win[lt+3] | 0x20
		c4 := win[lt+4] | 0x20
		c5 := win[lt+5]
		if c1 != 'm' || c2 != 'e' || c3 != 't' || c4 != 'a' || !(isAsciiWsFWGo(c5) || c5 == '/' || c5 == '>') {
			pos = lt + 1
			continue
		}

		cur := lt + 5
		metaName := ""
		metaContent := ""
		closed := false

		for cur < limit {
			for cur < limit && (isAsciiWsFWGo(win[cur]) || win[cur] == '/') {
				cur++
			}
			if cur >= limit {
				break
			}
			if win[cur] == '>' {
				closed = true
				cur++
				break
			}

			nameStart := cur
			for cur < limit && isAttrNameCharFWGo(win[cur]) {
				cur++
			}
			if cur == nameStart {
				cur++
				continue
			}
			attrName := strings.ToLower(win[nameStart:cur])

			for cur < limit && isAsciiWsFWGo(win[cur]) {
				cur++
			}
			attrVal := ""
			if cur < limit && win[cur] == '=' {
				cur++
				for cur < limit && isAsciiWsFWGo(win[cur]) {
					cur++
				}
				if cur < limit {
					q := win[cur]
					if q == '"' || q == '\'' {
						cur++
						valStart := cur
						relClose := strings.IndexByte(win[cur:], q)
						if relClose < 0 {
							cur = limit
							break
						}
						closeQ := cur + relClose
						attrVal = win[valStart:closeQ]
						cur = closeQ + 1
					} else {
						valStart := cur
						for cur < limit && !isAsciiWsFWGo(win[cur]) && win[cur] != '>' {
							cur++
						}
						valEnd := cur
						if valEnd > valStart && win[valEnd-1] == '/' && cur < limit && win[cur] == '>' {
							valEnd--
						}
						attrVal = win[valStart:valEnd]
					}
				}
			}

			if attrName == "name" {
				metaName = strings.ToLower(strings.TrimSpace(attrVal))
			} else if attrName == "content" {
				metaContent = strings.TrimSpace(decodeBasicHTMLEntitiesFWGo(attrVal))
			}
		}

		if closed && metaName == "generator" && metaContent != "" {
			generators = append(generators, capUTF16UnitsFWGo(metaContent, 160))
			if len(generators) >= 8 {
				break
			}
		}
		if cur > lt {
			pos = cur
		} else {
			pos = lt + 1
		}
	}

	return generators
}

// FilterSafeResponseHeaders filters rawHeaders down to SafeResponseHeaderAllowlist (case-insensitively),
// trimming values to 512 chars and returning nil when no allowlisted headers are present.
func FilterSafeResponseHeaders(rawHeaders map[string]string) map[string]string {
	if len(rawHeaders) == 0 {
		return nil
	}
	var lowerMap map[string]string
	for k, v := range rawHeaders {
		lk := strings.ToLower(k)
		if lk != k {
			if lowerMap == nil {
				lowerMap = make(map[string]string, len(rawHeaders))
			}
			if _, exists := lowerMap[lk]; !exists {
				lowerMap[lk] = v
			}
		}
	}

	out := make(map[string]string)
	for _, key := range SafeResponseHeaderAllowlist {
		val, ok := rawHeaders[key]
		if !ok && lowerMap != nil {
			val, ok = lowerMap[key]
		}
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(val)
		if trimmed != "" {
			out[key] = capUTF16UnitsFWGo(trimmed, 512)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DetectSiteFramework detects the site platform and frontend framework from bounded 64 KiB HTML or origin-markdown text,
// allowlisted response headers, hostname suffixes, and optional CDP browser globals.
func DetectSiteFramework(p DetectSiteFrameworkParams) DetectedSiteStack {
	win := sliceUTF16WindowFWGo(p.Body, FrameworkDetectWindowChars)
	signals := []string{}
	var contentFlags []string
	var platform string
	var framework string

	host := ""
	if p.URL != "" {
		if parsedURL, err := url.Parse(p.URL); err == nil {
			host = strings.ToLower(parsedURL.Hostname())
		}
	}

	safeHeaders := FilterSafeResponseHeaders(p.Headers)
	poweredBy := strings.ToLower(safeHeaders["powered-by"] + " " + safeHeaders["x-powered-by"])
	xGen := strings.ToLower(safeHeaders["x-generator"])
	linkHdr := strings.ToLower(safeHeaders["link"])

	// 1. Header signals
	if safeHeaders["x-shopid"] != "" || safeHeaders["x-shopify-stage"] != "" || strings.Contains(poweredBy, "shopify") {
		platform = "shopify"
		signals = append(signals, "header:shopify")
	} else if safeHeaders["x-wix-request-id"] != "" {
		platform = "wix"
		signals = append(signals, "header:x-wix-request-id")
	} else if safeHeaders["x-drupal-cache"] != "" || safeHeaders["x-drupal-dynamic-cache"] != "" || strings.HasPrefix(xGen, "drupal") {
		platform = "drupal"
		signals = append(signals, "header:drupal")
	} else if strings.Contains(linkHdr, "https://api.w.org/") {
		platform = "wordpress"
		signals = append(signals, "header:api.w.org")
	} else if strings.Contains(poweredBy, "craft cms") {
		platform = "craft-cms"
		signals = append(signals, "header:craft-cms")
	} else if safeHeaders["x-typo3-parsetime"] != "" {
		platform = "typo3"
		signals = append(signals, "header:typo3")
	}
	if strings.Contains(linkHdr, `rel="ucp"`) || strings.Contains(linkHdr, "/.well-known/ucp") {
		contentFlags = append(contentFlags, "ucp")
	}
	if strings.Contains(poweredBy, "next.js") || safeHeaders["x-nextjs-cache"] != "" {
		framework = "nextjs"
		signals = append(signals, "header:nextjs")
	} else if safeHeaders["x-remix-response"] != "" {
		framework = "remix"
		signals = append(signals, "header:remix")
	}

	// 2. Hostname suffix signals
	if platform == "" && host != "" {
		switch {
		case strings.HasSuffix(host, ".myshopify.com"):
			platform = "shopify"
			signals = append(signals, "host:myshopify.com")
		case strings.HasSuffix(host, ".notion.site"):
			platform = "notion"
			signals = append(signals, "host:notion.site")
		case strings.HasSuffix(host, ".godaddysites.com"):
			platform = "godaddy-builder"
			signals = append(signals, "host:godaddysites.com")
		case strings.HasSuffix(host, ".jimdosite.com"):
			platform = "jimdo"
			signals = append(signals, "host:jimdosite.com")
		case strings.HasSuffix(host, ".bigcartel.com"):
			platform = "big-cartel"
			signals = append(signals, "host:bigcartel.com")
		case strings.HasSuffix(host, ".square.site"):
			platform = "square-online"
			signals = append(signals, "host:square.site")
		case strings.HasSuffix(host, ".mybigcommerce.com"):
			platform = "bigcommerce"
			signals = append(signals, "host:mybigcommerce.com")
		case strings.HasSuffix(host, ".mykajabi.com"):
			platform = "kajabi"
			signals = append(signals, "host:mykajabi.com")
		case strings.HasSuffix(host, ".teachable.com"):
			platform = "teachable"
			signals = append(signals, "host:teachable.com")
		case strings.HasSuffix(host, ".thinkific.com"):
			platform = "thinkific"
			signals = append(signals, "host:thinkific.com")
		case strings.HasSuffix(host, ".blogspot.com"):
			platform = "blogger"
			signals = append(signals, "host:blogspot.com")
		case strings.HasSuffix(host, ".framer.website"):
			platform = "framer"
			signals = append(signals, "host:framer.website")
		case strings.HasSuffix(host, ".my.site.com"):
			platform = "salesforce-experience-cloud"
			signals = append(signals, "host:my.site.com")
		}
	}

	// 3. Origin-negotiated Markdown path
	if p.ContentSource == "origin-markdown" {
		if strings.Contains(win, "built and hosted on [Mintlify]") ||
			strings.Contains(win, "mintlify.com") ||
			(strings.Contains(win, "> ## Documentation Index") && (strings.Contains(win, "## Agent Instructions") || strings.Contains(win, "?ask="))) {
			if platform == "" {
				platform = "mintlify"
			}
			signals = append(signals, "md:mintlify")
		} else if strings.Contains(win, "This documentation is published with GitBook.") {
			if platform == "" {
				platform = "gitbook"
			}
			signals = append(signals, "md:gitbook")
		} else if strings.Contains(win, "agentTools:") && strings.Contains(win, "projectIndex:") {
			if platform == "" {
				platform = "readme"
			}
			signals = append(signals, "md:readme-frontmatter")
		} else if strings.Contains(win, "cdn11.bigcommerce.com/s-") {
			if platform == "" {
				platform = "bigcommerce"
			}
			signals = append(signals, "md:bigcommerce-cdn")
		} else if strings.Contains(win, "/fileadmin/") && (strings.Contains(win, "/extension-storage/_processed_/") || strings.Contains(win, "cHash=")) {
			if platform == "" {
				platform = "typo3"
			}
			signals = append(signals, "md:typo3-paths")
		}
		if framework == "" && strings.Contains(win, "/_astro/") {
			framework = "astro"
			signals = append(signals, "md:astro-assets")
		} else if framework == "" && strings.Contains(win, "/_next/") {
			framework = "nextjs"
			signals = append(signals, "md:nextjs-assets")
		}
		if strings.Contains(win, "Documentation Index") && strings.Contains(win, "/llms.txt") {
			contentFlags = append(contentFlags, "llms-index")
		}
		if strings.Contains(win, "## Agent Instructions") || strings.Contains(win, "?ask=<question>&goal=") {
			contentFlags = append(contentFlags, "agent-instructions")
		}
		return DetectedSiteStack{
			Source:       "origin-markdown",
			Platform:     platform,
			Framework:    framework,
			Generators:   []string{},
			Signals:      signals,
			ContentFlags: contentFlags,
		}
	}

	if win == "" {
		return DetectedSiteStack{
			Source:       "headers-only",
			Platform:     platform,
			Framework:    framework,
			Generators:   []string{},
			Signals:      signals,
			ContentFlags: contentFlags,
		}
	}

	// 4. HTML `<meta name="generator">` multi-tag scan (first 64 KiB)
	generators := ScanGeneratorMetaTags(win, FrameworkDetectWindowChars)
	for _, gen := range generators {
		g := strings.ToLower(gen)
		switch {
		case strings.HasPrefix(g, "starlight "):
			if platform == "" {
				platform = "starlight"
			}
			if framework == "" {
				framework = "astro"
			}
			signals = append(signals, "generator:starlight")
		case strings.HasPrefix(g, "astro "):
			if framework == "" {
				framework = "astro"
			}
			signals = append(signals, "generator:astro")
		case strings.HasPrefix(g, "hugo "):
			if framework == "" {
				framework = "hugo"
			}
			signals = append(signals, "generator:hugo")
		case strings.HasPrefix(g, "docusaurus"):
			if platform == "" {
				platform = "docusaurus"
			}
			if framework == "" {
				framework = "react"
			}
			signals = append(signals, "generator:docusaurus")
		case strings.HasPrefix(g, "vitepress"):
			if platform == "" {
				platform = "vitepress"
			}
			if framework == "" {
				framework = "vue"
			}
			signals = append(signals, "generator:vitepress")
		case strings.HasPrefix(g, "vuepress"):
			if platform == "" {
				platform = "vuepress"
			}
			if framework == "" {
				framework = "vue"
			}
			signals = append(signals, "generator:vuepress")
		case strings.HasPrefix(g, "hexo "):
			if framework == "" {
				framework = "hexo"
			}
			signals = append(signals, "generator:hexo")
		case strings.HasPrefix(g, "antora "):
			if platform == "" {
				platform = "antora"
			}
			signals = append(signals, "generator:antora")
		case strings.HasPrefix(g, "mkdocs-"):
			if strings.Contains(g, "mkdocs-material") {
				platform = "mkdocs-material"
			} else {
				platform = "mkdocs"
			}
			signals = append(signals, "generator:mkdocs")
		case strings.HasPrefix(g, "jekyll "):
			if framework == "" {
				framework = "jekyll"
			}
			signals = append(signals, "generator:jekyll")
		case strings.HasPrefix(g, "eleventy"):
			if framework == "" {
				framework = "eleventy"
			}
			signals = append(signals, "generator:eleventy")
		case strings.HasPrefix(g, "next.js"):
			if framework == "" {
				framework = "nextjs"
			}
			signals = append(signals, "generator:nextjs")
		case strings.HasPrefix(g, "gatsby"):
			if framework == "" {
				framework = "gatsby"
			}
			signals = append(signals, "generator:gatsby")
		case strings.Contains(g, "woocommerce"):
			if platform == "" || platform == "wordpress" {
				platform = "woocommerce"
			}
			if framework == "" {
				framework = "wordpress"
			}
			signals = append(signals, "generator:woocommerce")
		case strings.HasPrefix(g, "wordpress"):
			if platform == "" {
				platform = "wordpress"
			}
			signals = append(signals, "generator:wordpress")
		case strings.HasPrefix(g, "drupal"):
			if platform == "" {
				platform = "drupal"
			}
			signals = append(signals, "generator:drupal")
		case strings.HasPrefix(g, "joomla!"):
			if platform == "" {
				platform = "joomla"
			}
			signals = append(signals, "generator:joomla")
		case strings.HasPrefix(g, "ghost "):
			if platform == "" {
				platform = "ghost"
			}
			signals = append(signals, "generator:ghost")
		case g == "webflow" || strings.HasPrefix(g, "webflow "):
			if platform == "" {
				platform = "webflow"
			}
			signals = append(signals, "generator:webflow")
		case strings.HasPrefix(g, "wix.com website builder"):
			if platform == "" {
				platform = "wix"
			}
			signals = append(signals, "generator:wix")
		case g == "blogger":
			if platform == "" {
				platform = "blogger"
			}
			signals = append(signals, "generator:blogger")
		case g == "big cartel":
			if platform == "" {
				platform = "big-cartel"
			}
			signals = append(signals, "generator:big-cartel")
		case g == "square online":
			if platform == "" {
				platform = "square-online"
			}
			signals = append(signals, "generator:square-online")
		case g == "mystmd":
			if platform == "" {
				platform = "mystmd"
			}
			signals = append(signals, "generator:mystmd")
		case strings.HasPrefix(g, "starfield technologies; go daddy"):
			if platform == "" {
				platform = "godaddy-builder"
			}
			signals = append(signals, "generator:godaddy-builder")
		case strings.HasPrefix(g, "jimdo"):
			if platform == "" {
				platform = "jimdo"
			}
			signals = append(signals, "generator:jimdo")
		}
	}

	// 5. Verified structural HTML literals in the first 64 KiB
	if (platform == "" || platform == "wordpress") &&
		(strings.Contains(win, "/wp-content/plugins/woocommerce/") || (strings.Contains(win, "/wp-content/") && strings.Contains(win, "woocommerce"))) {
		platform = "woocommerce"
		if framework == "" {
			framework = "wordpress"
		}
		signals = append(signals, "html:woocommerce")
	}
	if platform == "" {
		switch {
		case strings.Contains(win, "shopify.exit_interstitial") ||
			strings.Contains(win, "Shopify.shop =") ||
			strings.Contains(win, "shopify-digital-wallet") ||
			(strings.Contains(win, "cdn.shopify.com/s/files/") && strings.Contains(win, "Shopify")):
			platform = "shopify"
			signals = append(signals, "html:shopify")
		case strings.Contains(win, "/wp-content/plugins/woocommerce/") || (strings.Contains(win, "/wp-content/") && strings.Contains(win, "woocommerce")):
			platform = "woocommerce"
			signals = append(signals, "html:woocommerce")
		case strings.Contains(win, "/wp-content/") && strings.Contains(win, "/wp-includes/"):
			platform = "wordpress"
			signals = append(signals, "html:wp-content+wp-includes")
		case strings.Contains(win, "<!-- This is Squarespace. -->") || strings.Contains(win, "Static.SQUARESPACE_CONTEXT"):
			platform = "squarespace"
			signals = append(signals, "html:squarespace")
		case strings.Contains(win, `id="wix-viewer-model"`) || strings.Contains(win, `id='wix-viewer-model'`):
			platform = "wix"
			signals = append(signals, "html:wix-viewer-model")
		case strings.Contains(win, "data-wf-site=") || strings.Contains(win, "<!-- This site was created in Webflow."):
			platform = "webflow"
			signals = append(signals, "html:webflow")
		case strings.Contains(win, "data-notion-html="):
			platform = "notion"
			signals = append(signals, "html:notion")
		case strings.Contains(win, `id="gh-members-styles"`) || strings.Contains(win, "data-ghost="):
			platform = "ghost"
			signals = append(signals, "html:ghost")
		case strings.Contains(win, "data-drupal-link-system-path="):
			platform = "drupal"
			signals = append(signals, "html:drupal")
		case strings.Contains(win, `class="joomla-script-options`):
			platform = "joomla"
			signals = append(signals, "html:joomla")
		case strings.Contains(win, `xmlns:b='http://www.google.com/2005/gml/b'`) || strings.Contains(win, `xmlns:b="http://www.google.com/2005/gml/b"`):
			platform = "blogger"
			signals = append(signals, "html:blogger")
		case strings.Contains(win, "<!-- Served from Big Cartel Storefront -->"):
			platform = "big-cartel"
			signals = append(signals, "html:big-cartel")
		case strings.Contains(win, `data-role="square-online-featureflags"`):
			platform = "square-online"
			signals = append(signals, "html:square-online")
		case strings.Contains(win, "catalog/view/theme/") && strings.Contains(win, "route="):
			platform = "opencart"
			signals = append(signals, "html:opencart")
		case strings.Contains(win, "window.Thinkific"):
			platform = "thinkific"
			signals = append(signals, "html:thinkific")
		case strings.Contains(win, "teachablecdn.com") && strings.Contains(win, "/l/_next/"):
			platform = "teachable"
			signals = append(signals, "html:teachable")
		case strings.Contains(win, "cdn.podia.com/assets/storefront"):
			platform = "podia"
			signals = append(signals, "html:podia")
		case strings.Contains(win, "window.bubble_session_uid"):
			platform = "bubble"
			signals = append(signals, "html:bubble")
		case strings.Contains(win, "window.dmAPI") && strings.Contains(win, "cdn-website.com"):
			platform = "duda"
			signals = append(signals, "html:duda")
		case strings.Contains(win, "substackcdn.com/bundle/static/") || strings.Contains(win, "window._preloads"):
			platform = "substack"
			signals = append(signals, "html:substack")
		case strings.Contains(win, `id="__docusaurus"`):
			platform = "docusaurus"
			signals = append(signals, "html:docusaurus")
		case strings.Contains(win, `class="VPContent`) || strings.Contains(win, "vitepress-theme-appearance"):
			platform = "vitepress"
			signals = append(signals, "html:vitepress")
		case strings.Contains(win, "data-md-component="):
			platform = "mkdocs-material"
			signals = append(signals, "html:mkdocs-material")
		case strings.Contains(win, "window.$docsify"):
			platform = "docsify"
			signals = append(signals, "html:docsify")
		case strings.Contains(win, "swagger-ui-bundle.js") && strings.Contains(win, `id="swagger-ui"`):
			platform = "swagger-ui"
			signals = append(signals, "html:swagger-ui")
		case strings.Contains(win, "sb-manager/") && strings.Contains(win, "STORYBOOK_"):
			platform = "storybook"
			signals = append(signals, "html:storybook")
		}
	}

	if framework == "" {
		switch {
		case strings.Contains(win, "data-next-head="):
			framework = "nextjs-pages"
			signals = append(signals, "html:data-next-head")
		case strings.Contains(win, "/_next/static/immutable/") || strings.Contains(win, `data-precedence="next"`) || strings.Contains(win, "self.__next_f.push("):
			framework = "nextjs-app"
			signals = append(signals, "html:nextjs-app")
		case strings.Contains(win, `id="__NEXT_DATA__"`) || strings.Contains(win, "/_next/static/"):
			framework = "nextjs"
			signals = append(signals, "html:nextjs")
		case strings.Contains(win, "/_nuxt/") || strings.Contains(win, `id="__NUXT_DATA__"`):
			framework = "nuxt"
			signals = append(signals, "html:nuxt")
		case strings.Contains(win, "/_app/immutable/") || strings.Contains(win, "data-sveltekit-"):
			framework = "sveltekit"
			signals = append(signals, "html:sveltekit")
		case strings.Contains(win, "/_astro/") || strings.Contains(win, "data-astro-cid-"):
			framework = "astro"
			signals = append(signals, "html:astro")
		case strings.Contains(win, "q:container="):
			framework = "qwik"
			signals = append(signals, "html:qwik")
		case strings.Contains(win, "data-hk=") && strings.Contains(win, "_$HY"):
			framework = "solid"
			signals = append(signals, "html:solid")
		case strings.Contains(win, `data-page="{&quot;component&quot;`) || strings.Contains(win, `data-page='{"component"`):
			framework = "inertia"
			signals = append(signals, "html:inertia-data-page")
		case strings.Contains(win, "livewireautofill") || strings.Contains(win, "wire:snapshot="):
			framework = "livewire"
			signals = append(signals, "html:livewire")
		case strings.Contains(win, `id="blazor-error-ui"`) || strings.Contains(win, "_framework/blazor."):
			framework = "blazor"
			signals = append(signals, "html:blazor")
		case strings.Contains(win, `ng-version="`) || strings.Contains(win, `id="ng-state"`):
			framework = "angular"
			signals = append(signals, "html:angular")
		case strings.Contains(win, "ng-app="):
			framework = "angularjs"
			signals = append(signals, "html:angularjs")
		case strings.Contains(win, `/config/environment"`):
			framework = "ember"
			signals = append(signals, "html:ember")
		case strings.Contains(win, `id="___gatsby"`):
			framework = "gatsby"
			signals = append(signals, "html:gatsby")
		case strings.Contains(win, "/assets/manifest-") && strings.Contains(win, "entry.client-"):
			framework = "react-router-v7"
			signals = append(signals, "html:react-router-v7")
		case strings.Contains(win, "window.__remixContext"):
			framework = "remix"
			signals = append(signals, "html:remix")
		case strings.Contains(win, "hx-get=") || strings.Contains(win, "hx-post=") || strings.Contains(win, "hx-boost="):
			framework = "htmx"
			signals = append(signals, "html:htmx")
		case strings.Contains(win, "x-data="):
			framework = "alpine"
			signals = append(signals, "html:alpine")
		}
	}

	if strings.HasPrefix(framework, "nextjs") && platform == "" && strings.Contains(win, "--nextra-primary-hue") {
		platform = "nextra"
		signals = append(signals, "html:nextra")
	}

	// 6. Browser globals (only present when rendered via CDP)
	if g := p.Globals; g != nil {
		if platform == "" {
			switch {
			case g.Shopify:
				platform = "shopify"
				signals = append(signals, "global:Shopify")
			case g.WP:
				platform = "wordpress"
				signals = append(signals, "global:wp")
			case g.Squarespace:
				platform = "squarespace"
				signals = append(signals, "global:Squarespace")
			case g.Webflow:
				platform = "webflow"
				signals = append(signals, "global:Webflow")
			case g.Wix:
				platform = "wix"
				signals = append(signals, "global:wix")
			}
		}
		if framework == "" {
			switch {
			case g.Next:
				framework = "nextjs"
				signals = append(signals, "global:__NEXT_DATA__")
			case g.Nuxt:
				framework = "nuxt"
				signals = append(signals, "global:__NUXT__")
			case g.Remix:
				framework = "remix"
				signals = append(signals, "global:__remixContext")
			case g.ReactRouter:
				framework = "react-router"
				signals = append(signals, "global:__reactRouterContext")
			case g.Angular:
				framework = "angular"
				signals = append(signals, "global:ng")
			}
		}
	}

	return DetectedSiteStack{
		Source:       "html",
		Platform:     platform,
		Framework:    framework,
		Generators:   generators,
		Signals:      signals,
		ContentFlags: contentFlags,
	}
}

func capBytesValidUTF8FWGo(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	end := maxChars
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

// ExtractInertiaPageProps linearly extracts Inertia.js `data-page="{&quot;component&quot;:...}"` serialized page props
// within maxScanChars (default 512 KiB), returning nil when absent, malformed, or missing a string `component`.
func ExtractInertiaPageProps(rawHTML string, maxScanChars int) map[string]any {
	if maxScanChars <= 0 {
		maxScanChars = defaultInertiaMaxScanCharsFWGo
	}
	slice := sliceUTF16WindowFWGo(capBytesValidUTF8FWGo(rawHTML, maxScanChars*4), maxScanChars)
	dqIdx := strings.Index(slice, `data-page="{&quot;component&quot;`)
	sqIdx := -1
	if dqIdx < 0 {
		sqIdx = strings.Index(slice, `data-page='{"component"`)
	}
	if dqIdx < 0 && sqIdx < 0 {
		return nil
	}

	isDouble := dqIdx >= 0
	baseIdx := sqIdx
	quoteByte := byte('\'')
	if isDouble {
		baseIdx = dqIdx
		quoteByte = '"'
	}
	startVal := baseIdx + len("data-page=") + 1
	if startVal >= len(slice) {
		return nil
	}
	relClose := strings.IndexByte(slice[startVal:], quoteByte)
	if relClose < 0 || relClose > maxInertiaPayloadCharsFWGo {
		return nil
	}

	decoded := decodeBasicHTMLEntitiesFWGo(slice[startVal : startVal+relClose])
	var parsed map[string]any
	if err := json.Unmarshal([]byte(decoded), &parsed); err != nil || parsed == nil {
		return nil
	}
	if _, ok := parsed["component"].(string); !ok {
		return nil
	}
	return parsed
}
