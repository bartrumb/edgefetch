package extract

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxHTMLScanCharsFullDocGo = 2 * 1024 * 1024 // 2 MiB linear HTML scan ceiling (matches TS MAX_HTML_SCAN_CHARS)

// FullExtractOptions configures full-fidelity HTML document extraction and Markdown finalization.
type FullExtractOptions struct {
	BaseURL             string   `json:"baseUrl,omitempty"`
	OnlyMainContent     bool     `json:"onlyMainContent,omitempty"`
	IncludeImages       bool     `json:"includeImages,omitempty"`
	IncludeTags         []string `json:"includeTags,omitempty"`
	ExcludeTags         []string `json:"excludeTags,omitempty"`
	MaxChars            int      `json:"maxChars,omitempty"`
	Offset              int      `json:"offset,omitempty"`
	RedactPII           bool     `json:"redactPii,omitempty"`
	AllowPdfPageMarkers bool     `json:"allowPdfPageMarkers,omitempty"`
	IsPDF               bool     `json:"isPdf,omitempty"`
	PreserveOriginMD    bool     `json:"preserveOriginMarkdown,omitempty"`
	IsFragment          bool     `json:"isFragment,omitempty"`
}

// ExtractedDocumentFull holds the full-fidelity Markdown, metadata, links, images, branding,
// structured JSON-LD entities, and pagination state extracted from an HTML document.
type ExtractedDocumentFull struct {
	Title                string           `json:"title,omitempty"`
	Description          string           `json:"description,omitempty"`
	Author               string           `json:"author,omitempty"`
	PublishedTime        string           `json:"publishedTime,omitempty"`
	ModifiedTime         string           `json:"modifiedTime,omitempty"`
	SiteName             string           `json:"siteName,omitempty"`
	WordCount            int              `json:"wordCount,omitempty"`
	Language             string           `json:"language,omitempty"`
	Favicon              string           `json:"favicon,omitempty"`
	OGImage              string           `json:"ogImage,omitempty"`
	CanonicalURL         string           `json:"canonicalUrl,omitempty"`
	MarkdownAlternateURL string           `json:"markdownAlternateUrl,omitempty"`
	RobotsMeta           string           `json:"robotsMeta,omitempty"`
	ExtractorID          string           `json:"extractorId,omitempty"`
	Records              []map[string]any `json:"records,omitempty"`
	Total                *int             `json:"total,omitempty"`
	Returned             *int             `json:"returned,omitempty"`
	NextCursor           string           `json:"nextCursor,omitempty"`
	InertiaHydrated      bool             `json:"inertiaHydrated,omitempty"`
	Markdown             string           `json:"markdown"`
	RawSanitizedMarkdown string           `json:"rawSanitizedMarkdown,omitempty"`
	Text                 string           `json:"text,omitempty"`
	Links                []string         `json:"links"`
	Images               []ImageInfo      `json:"images"`
	Branding             BrandingProfile  `json:"branding"`
	StructuredData       []map[string]any `json:"structuredData,omitempty"`
	TotalChars           int              `json:"totalChars"`
	ReturnedChars        int              `json:"returnedChars"`
	Truncated            bool             `json:"truncated,omitempty"`
	NextOffset           *int             `json:"nextOffset,omitempty"`
}

var (
	urlOnlyTagAttrsFullDocGo = map[string]bool{
		"href": true, "src": true, "srcset": true,
		"data-src": true, "data-srcset": true, "data-lazy-src": true, "data-lazy-srcset": true,
		"data-original": true, "action": true, "poster": true,
	}

	codeLangAliasesFullDocGo = map[string]string{
		"javascript":    "js",
		"mjs":           "js",
		"cjs":           "js",
		"typescript":    "ts",
		"py":            "python",
		"py3":           "python",
		"python3":       "python",
		"pycon":         "python",
		"pycon3":        "python",
		"default":       "python",
		"rs":            "rust",
		"golang":        "go",
		"sh":            "bash",
		"shell":         "bash",
		"shell-session": "bash",
		"zsh":           "bash",
		"console":       "bash",
		"terminal":      "bash",
		"doscon":        "cmd",
		"objc":          "objectivec",
		"yml":           "yaml",
		"md":            "markdown",
		"cs":            "csharp",
		"c++":           "cpp",
		"plaintext":     "",
		"plain":         "",
		"text":          "",
		"txt":           "",
		"none":          "",
		"nohighlight":   "",
		"output":        "",
	}

	voidHTMLTagsFullDocGo = map[string]bool{
		"area": true, "base": true, "br": true, "col": true, "embed": true,
		"hr": true, "img": true, "input": true, "link": true, "meta": true,
		"param": true, "source": true, "track": true, "wbr": true,
	}

	alwaysHiddenOrChromeClassesFullDocGo = map[string]bool{
		"sr-only":                               true,
		"visually-hidden":                       true,
		"screenreader-only":                     true,
		"hideme":                                true,
		"unitheader-banner":                     true,
		"js-comment-minimize":                   true,
		"js-comment-hide-button":                true,
		"js-suggestion-button-placeholder":      true,
		"js-clipboard-copy":                     true,
		"zeroclipboard-container":               true,
		"doc-anchor":                            true,
		"documentation-idlink":                  true,
		"documentation-examplebuttonscontainer": true,
		"documentation-exampleerror":            true,
		"headerlink":                            true,
		"pilcrow":                               true,
		"mw-editsection":                        true,
		"mw-editsection-bracket":                true,
		"mw-editsection-divider":                true,
		"sphinxsidebar":                         true,
		"katex-html":                            true,
		"mwe-math-fallback-image-inline":        true,
		"mwe-math-fallback-image-display":       true,
		"lnt":                                   true,
		"line-numbers-rows":                     true,
		"line-numbers-wrapper":                  true,
		"hljs-ln-numbers":                       true,
		"swiper-slide-duplicate":                true,
		"slick-cloned":                          true,
		"splide__slide--clone":                  true,
		"flickity-cloned":                       true,
		"glide__slide--clone":                   true,
		"owl-cloned":                            true,
	}

	nonContentRolesFullDocGo = map[string]bool{
		"navigation": true, "search": true, "banner": true, "contentinfo": true,
		"dialog": true, "alertdialog": true, "menu": true, "menubar": true, "toolbar": true,
	}

	pdfCompoundPrefixesFullDocGo = map[string]bool{
		"self": true, "multi": true, "cross": true, "non": true, "well": true,
		"high": true, "low": true, "long": true, "short": true, "full": true,
		"part": true, "real": true, "end": true, "one": true, "two": true,
		"three": true, "four": true, "five": true, "six": true, "ten": true,
		"all": true, "auto": true, "co": true, "over": true, "under": true,
		"hyper": true, "micro": true, "macro": true, "zero": true, "open": true,
		"closed": true, "right": true, "hand": true, "rule": true, "role": true,
		"user": true, "site": true, "host": true, "edge": true, "cloud": true,
	}

	blockCloseTagsFullDocGo = map[string]bool{
		"p": true, "div": true, "section": true, "article": true, "main": true,
		"ul": true, "ol": true, "dl": true, "dd": true, "dt": true,
		"figure": true, "figcaption": true, "tr": true, "header": true, "details": true,
	}

	spaceCloseTagsFullDocGo = map[string]bool{
		"span": true, "button": true, "label": true, "time": true, "td": true, "th": true,
	}

	reURLAmpOnlyFullDocGo        = regexp.MustCompile(`(?i)&(?:amp|#0*38|#x0*26);`)
	reBracketCiteNumFullDocGo    = regexp.MustCompile(`\[\s+(\d{1,4})\s*\]`)
	reAuthorByPrefixFullDocGo    = regexp.MustCompile(`(?i)^by\s+`)
	reAuthorURLFullDocGo         = regexp.MustCompile(`(?i)\(?\s*https?://\S+\s*\)?`)
	reAuthorAndFullDocGo         = regexp.MustCompile(`(?i),?\s+and\s+`)
	reAuthorTrailDashFullDocGo   = regexp.MustCompile(`\s*[-–—|]\s*$`)
	reSimpleSelectorFullDocGo    = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9:-]*)?(?:#([a-zA-Z0-9_:-]+))?(?:\.([a-zA-Z0-9_:-]+))?$`)
	reLangIdentFullDocGo         = regexp.MustCompile(`^[a-z0-9_+#-]{1,20}$`)
	reClassLang1FullDocGo        = regexp.MustCompile(`(?i)\b(?:highlight-source-|language-|lang-|highlight-|syntax-|code-|brush:\s*)([a-zA-Z0-9_+#-]+)`)
	reClassLang2FullDocGo        = regexp.MustCompile(`(?i)\b([a-zA-Z0-9_+#-]+)-(?:code|snippet)\b`)
	reClassLang3FullDocGo        = regexp.MustCompile(`(?i)\bhljs\s+([a-zA-Z0-9_+#-]+)\b`)
	reClassRustFullDocGo         = regexp.MustCompile(`(?i)\brust(?:-example-rendered)?\b`)
	reClassGoDocFullDocGo        = regexp.MustCompile(`\bDocumentation-exampleCode\b`)
	reHeadingEditFullDocGo       = regexp.MustCompile(`(?i)\s*\[\s*(?:edit|edit\s+source)(?:\s*\|\s*(?:edit|edit\s+source))?\s*\]\s*$`)
	reHeadingAddedInFullDocGo    = regexp.MustCompile(`(?i)\s+¶\s+(added in\s+\S+)$`)
	reHeadingPilcrowLnkFullDocGo = regexp.MustCompile(`\s*\[[§¶#]\]\([^)]*\)\s*$`)
	reHeadingTrailSymFullDocGo   = regexp.MustCompile(`\s+[§¶#]+$`)
	rePlaceholderMetaFullDocGo   = regexp.MustCompile(`(?i)^(?:loading(?:\.{0,3})?|untitled|please wait(?:\.{0,3})?)$`)
	rePlaceholderHashFullDocGo   = regexp.MustCompile(`^#[a-zA-Z_$][\w$]*(?:\.[\w$]+)+$`)
	reResponsiveShowFullDocGo    = regexp.MustCompile(`(?i)\b(?:d-(?:sm|md|lg|xl|xxl)-(?:block|flex|inline|inline-block|grid|table)|(?:sm|md|lg|xl|2xl):(?:block|flex|inline|inline-block|grid|table))\b`)
	reStyleHiddenFullDocGo       = regexp.MustCompile(`(?i)(?:^|;)\s*(?:display\s*:\s*none\b|visibility\s*:\s*hidden\b|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|font-size\s*:\s*0(?:px|em|rem|%|pt)?\s*(?:;|$))`)
	reWikiDisplayStyleFullDocGo  = regexp.MustCompile(`(?s)^\{\\displaystyle\s+(.*)\}$`)
	reCommentCompanionFullDocGo  = regexp.MustCompile(`(?is)<!--[\s\S]{0,600}?\bavailable as Markdown at\s+(/[A-Za-z0-9._~!$&'()*+,;=:@/%-]+\.md|https://[A-Za-z0-9._~!$&'()*+,;=:@/%-]+\.md)\b[\s\S]{0,600}?-->`)
	reYouTubeEmbedFullDocGo      = regexp.MustCompile(`(?i)(?:youtube\.com|youtube-nocookie\.com)/embed/([A-Za-z0-9_-]{6,20})`)
	reTwitterDirectFullDocGo     = regexp.MustCompile(`(?i)(?:twitter\.com|x\.com)/([A-Za-z0-9_]+)/status/(\d+)`)
	reTwitterWidgetFullDocGo     = regexp.MustCompile(`(?i)platform\.twitter\.com/embed/Tweet\.html\?[^"']*?\bid=(\d+)`)
	reBogusCommentFullDocGo      = regexp.MustCompile(`(?s)<\?[\s\S]{0,400}?\?>|<\?>`)
	reFeedbackFormFullDocGo      = regexp.MustCompile(`(?i)was this (?:page )?helpful|did this help|page feedback`)
	reChromeButtonFullDocGo      = regexp.MustCompile(`(?i)^(?:menu|open menu|close menu|toggle (?:menu|navigation|sidebar|theme|color mode)|on this page|table of contents|copy(?:\s+(?:for llm|as markdown|page|code|link|markdown|item path|path|url|to clipboard|head branch name to clipboard))?|copied!?|view (?:as )?markdown|open in (?:chatgpt|claude|cursor|v0|perplexity|scira)|ask ai(?:\s+about\s+this\s+page)?|yes|no|skip|submit feedback|give feedback|report an issue|back to top|dark mode|light mode|see all|hide|hide comment|show more|show less|share|format|run|search(?:\.{0,3}|\s+(?:docs|documentation))?(?:\s*(?:⌘\s*k|ctrl(?:\s*\+\s*|\s+)?k|/))?)$`)
	reLazyPlaceholderFullDocGo   = regexp.MustCompile(`(?i)(?:^|[/_-])placeholder(?:[-_]{1,2}[a-z0-9_-]+)?\.(?:png|gif|svg|webp|jpe?g|avif)(?:$|[?#])`)
	reTinyOrAvatarFullDocGo      = regexp.MustCompile(`(?i)\b(?:avatar|gravatar|author[-_]?photo|author[-_]?image|1x1|pixel|spacer)\b`)
	reTinyOrBadgeImgFullDocGo    = regexp.MustCompile(`(?i)\b(?:avatar|gravatar|author[-_]?photo|author[-_]?image|1x1|pixel|spacer|badge)\b`)
	reQueryDimFullDocGo          = regexp.MustCompile(`(?i)[?&](?:w|width|h|height)=(\d{1,4})\b`)
	reClutterAttrFullDocGo       = regexp.MustCompile(`(?i)\b(?:sidebar|related|popular|trending|recommended|most-read|more-stories|toc|table-of-contents|breadcrumb|pagination|pager|tag-cloud|tags-list|categories|social|share|widget|footer-links)\b`)
	reSphinxPreFullDocGo         = regexp.MustCompile(`(?is)<div\b([^>]{1,350})>\s*<div\b([^>]{1,350})>\s*<pre\b`)
	reSphinxOuterLangFullDocGo   = regexp.MustCompile(`(?i)\bhighlight-([a-zA-Z0-9_+#-]+)\b`)
	reVitePressPreFullDocGo      = regexp.MustCompile(`(?is)<div\b([^>]{1,500})>(\s*(?:<button\b[^>]{0,240}>[^<]{0,40}</button>\s*)?(?:<span\b[^>]{0,240}>[^<]{0,40}</span>\s*)?)<pre\b`)
	reVitePressLangFullDocGo     = regexp.MustCompile(`(?i)\b(?:language|lang|highlight-source)-([a-zA-Z0-9_+#-]+)\b`)
	reShortBtnFullDocGo          = regexp.MustCompile(`(?is)<button\b[^>]*>[^<]*</button>`)
	reShortLangSpanFullDocGo     = regexp.MustCompile(`(?is)<span\b[^>]*\blang\b[^>]*>[^<]*</span>`)
	reSupFootnoteRefFullDocGo    = regexp.MustCompile(`(?is)<sup\b([^>]{1,300})>\s*<a\b([^>]{1,300})>[\s\S]{0,60}?</a>\s*</sup>`)
	reFootnoteBackrefFullDocGo   = regexp.MustCompile(`(?is)<a\b[^>]*(?:footnote-backref|#fnref|#user-content-fnref)[^>]*>[\s\S]*?</a>`)
	reCalloutTitleElemFullDocGo  = regexp.MustCompile(`(?is)<(p|div)\b[^>]{0,600}\b(?:markdown-alert-title|admonition-title|callout-title|starlight-aside__title|custom-block-title)\b[^>]{0,600}>([\s\S]{0,600}?)</(?:p|div)>`)
	reCalloutClassTypeFullDocGo  = regexp.MustCompile(`(?i)\b(?:markdown-alert-([a-z]+)|theme-admonition-([a-z]+)|starlight-aside--([a-z]+)|(note|tip|info|warning|caution|danger|important))\b`)
	reAdjacentAnchorsFullDocGo   = regexp.MustCompile(`(?i)(</a>)(<a\b)`)
	reAdjacentCodeFullDocGo      = regexp.MustCompile(`(?i)(</code>)(<code\b)`)
	reAlnumBeforeAnchorFullDocGo = regexp.MustCompile(`([A-Za-z0-9])(<a\b)`)
	reSummarySeeAllFullDocGo     = regexp.MustCompile(`(?i)\s+(?:see all(?:\s+hide)?|show more(?:\s+show less)?)$`)
	reDtStarSpaceFullDocGo       = regexp.MustCompile(`\*([^*\n]+)\*([A-Za-z0-9_` + "`" + `])`)
	reDtStarPlainFullDocGo       = regexp.MustCompile(`\*([^*\n]+)\*`)
	reBlockInsideInlineFullDocGo = regexp.MustCompile(`(?i)<(?:li|ul|ol|table|blockquote|pre)\b`)
	reListBlockContentFullDocGo  = regexp.MustCompile("(?m)```|~~~|@@(?:EFFENCE|EFCODE)_\\d+@@|^\\s*(?:#{1,6}\\s|\\|\\s|>\\s)")
	reSentinelEffenceFullDocGo   = regexp.MustCompile(`@@EFFENCE_(\d+)@@`)
	reSentinelEfcodeFullDocGo    = regexp.MustCompile(`@@EFCODE_(\d+)@@`)
	reSentinelEfinlineFullDocGo  = regexp.MustCompile("`@@EFINLINE_(\\d+)@@`")
	reSentinelHnCodeFullDocGo    = regexp.MustCompile(`@@HNCODE_(\d+)@@`)
	reTaskLineNormFullDocGo      = regexp.MustCompile(`^(\s*-\s+)\[\s*([xX])\s*\]`)
	reListIndentLineFullDocGo    = regexp.MustCompile(`^( {2}| {4}| {6})(-\s+\S[\s\S]*)$`)
	reTrailPilcrowLinkFullDocGo  = regexp.MustCompile(`[ \t]*\[¶\]\([^)]*\)[ \t]*$`)
	reTrailPilcrowRawFullDocGo   = regexp.MustCompile(`[ \t]+¶$`)
	reBoilerplateLineFullDocGo   = regexp.MustCompile(`(?i)^(?:was this (?:page )?helpful\??|yes\s*no|copy page(?:\s*copy page)*|back to top(?:\s*was this page helpful\??\s*yes\s*no)?|what could we improve on this page\?\s*submit feedback\s*skip|thanks for your feedback!?|edit this page.*|##\s+repository navigation|click to (?:show|hide) internal directories\.)$`)
	reMdnLangHeaderFullDocGo     = regexp.MustCompile("(?i)(^|\\n\\n)(js|javascript|ts|typescript|jsx|tsx|html|css|scss|json|bash|sh|shell|python|py|rust|go|sql|yaml|toml|xml|http|wasm)[ \\t]*\\n+```([a-z0-9_+#-]*)[ \\t]*\\n")
	reHelpImproveMdnFullDocGo    = regexp.MustCompile(`(?is)\n+##[ \t]+Help improve MDN\b[\s\S]{0,600}$`)
	reAnyH1LineFullDocGo         = regexp.MustCompile(`(?m)^#[ \t]+\S`)
	reGitHubIssueURLFullDocGo    = regexp.MustCompile(`(?i)^https?://github\.com/[^/]+/[^/]+/(?:issues|pull)/\d+`)
	reGitHubDupH2FullDocGo       = regexp.MustCompile(`(?i)(^#\s+[^\n]+\n+(?:(?:Open|Closed|Merged|Draft)\n+[\s\S]{0,400}?\n+)?)##\s+[^\n]+#\d+\s+[^\n]+\n+`)
	reArxivAbsURLFullDocGo       = regexp.MustCompile(`(?i)^https?://(?:export\.)?arxiv\.org/abs/`)
	reArxivBreadcrumbFullDocGo   = regexp.MustCompile(`^#\s+[^\n]+>\s+[^\n]+\n+`)
	reArxivTitlePrefixFullDocGo  = regexp.MustCompile(`(?m)^#\s+Title:\s+`)
	reArxivFooterFullDocGo       = regexp.MustCompile(`(?is)\n###\s+(?:Current browse context|Bibliographic and Citation Tools|Code, Data and Media Associated with this Article|Demos|Recommenders and Search Tools|arXivLabs:)\b[\s\S]*$`)
	reRedactedLinkGuardFullDocGo = regexp.MustCompile(`(\[REDACTED_(?:EMAIL|SSN|PHONE|CARD)\][ \t]*)([([:])`)
	rePDFBoilerplateFullDocGo    = regexp.MustCompile(`(?i)\b(?:hereby grants permission|proper attribution|all rights reserved|copyright\s+(?:©|\(c\)|\d{4})|published as a conference paper|under review as a conference paper|proceedings of the|preprint\.\s+under review|journalistic or\s+scholarly works)\b`)
	rePDFSkipTitleLineFullDocGo  = regexp.MustCompile(`(?i)^(?:page\s+\d+|\d+|https?://|table of contents|arxiv:\s*\d)`)
	rePDFAllCapsLineFullDocGo    = regexp.MustCompile(`^[A-Z][A-Z\s&.'-]{3,80}$`)
	reSchemaFenceOnlyFullDocGo   = regexp.MustCompile("(?i)^`{3,}json[ \\t]*\\r?\\n(?:\\{\\s*\"@context\"\\s*:\\s*\"https?://schema\\.org\"[^\\r\\n]{80,}\\r?\\n)+\\s*`{3,}$")
	reRfcPageFooterFullDocGo     = regexp.MustCompile(`(?i)\[Page\s+\d+\]$`)
	reRfcRunningHeaderFullDocGo  = regexp.MustCompile(`(?i)\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}$`)
	reRfcSectionHeadingFullDocGo = regexp.MustCompile(`^(\d+(?:\.\d+){0,3})\.\s+([A-Z][^\r\n]{1,90})$`)
	reMwChromeFooterFullDocGo    = regexp.MustCompile(`(?i)^(?:##+[ \t]+)?(?:Navigation menu|Namespaces|Views|Personal tools)\b`)
	reMwDropLine1FullDocGo       = regexp.MustCompile(`(?i)^(?:\[[ \t]*\]|Edit links|Links bearbeiten|Modifier les liens|Editar enlaces|Modifica link|Toggle the table of contents|Move to sidebar|hide)$`)
	reMwDropJumpFullDocGo        = regexp.MustCompile(`(?i)^\[(?:Jump to content|Zum Inhalt springen|Aller au contenu)\]\(#[^)]*\)$`)
	reMwDropWikidataFullDocGo    = regexp.MustCompile(`(?i)^\[[^\]]{1,64}\]\(https?://(?:www\.)?wikidata\.org/wiki/Special:EntityPage/[^)]*\)$`)
	reMwDropTaglineFullDocGo     = regexp.MustCompile(`(?i)^(?:From Wikipedia, the free encyclopedia|Aus Wikipedia, der freien Enzyklopädie|Un article de Wikipédia, l'encyclopédie libre\.?)$`)
	reMwDropLangCountFullDocGo   = regexp.MustCompile(`(?i)^\d{1,4}[ \t]+(?:languages|language|Sprachen|langues|idiomas|lingue)$`)
	reMwDropCheckedFullDocGo     = regexp.MustCompile(`(?i)^(?:\*{1,2})?(?:Checked|Gesichtet|Vérifié|Revisado)(?:\*{1,2})?$`)
	reMwCiteLabelFullDocGo       = regexp.MustCompile(`(?is)^(?:\d{1,4}|[a-z]|(?:note|nb|lower-alpha|upper-alpha)[ \t]*\d{1,3}|citation needed|clarification needed|when\?|who\?|dubious[\s\S]{0,48})$`)
	reMwEditOrCiteTokenFullDocGo = regexp.MustCompile(`(?i)^(?:edit|Bearbeiten(?:[ \t]*\|[ \t]*Quelltext bearbeiten)?|modifier(?:[ \t]*\|[ \t]*modifier le code)?|editar|citation needed|clarification needed|when\?|who\?|dubious[ \t]*[–-][ \t]*discuss)$`)
	reMwNumBracketTokenFullDocGo = regexp.MustCompile(`(?i)^(?:\d{1,4}|(?:note|nb)[ \t]*\d{1,3})$`)
	reStackExHostFullDocGo       = regexp.MustCompile(`(?i)^(?:www\.)?(?:stackoverflow\.com|serverfault\.com|superuser\.com|askubuntu\.com|mathoverflow\.net|stackapps\.com|[a-z0-9.-]+\.stackexchange\.com)$`)
)

type scannedTagFullDocGo struct {
	index         int
	end           int
	tagNameLower  string
	rawTag        string
	attrs         string
	isClosing     bool
	isSelfClosing bool
	isDeclaration bool
}

type scannerDeadStateFullDocGo struct {
	noCloseDbl         bool
	noCloseSgl         bool
	noCommentCloseFrom int
	noCdataCloseFrom   int
	nextGtPos          int // 0 = unknown, -1 = none left, >0 = index
}

func truncateUTF8SafeFullDocGo(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	floor := maxBytes - 3
	if floor < 0 {
		floor = 0
	}
	for cut > floor && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func isTagNameBoundaryByteFullDocGo(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r' || b == '/' || b == '>'
}

func tryParseTagAtFullDocGo(src string, pos int, dead *scannerDeadStateFullDocGo, allowDeclarations bool) (scannedTagFullDocGo, bool) {
	n := len(src)
	if pos+1 >= n || src[pos] != '<' {
		return scannedTagFullDocGo{}, false
	}
	p := pos + 1
	c1 := src[p]
	if c1 == '!' || c1 == '?' {
		if !allowDeclarations {
			return scannedTagFullDocGo{}, false
		}
		if c1 == '!' && p+2 < n && src[p+1] == '-' && src[p+2] == '-' {
			if dead.noCommentCloseFrom > 0 && pos >= dead.noCommentCloseFrom {
				return scannedTagFullDocGo{}, false
			}
			rel := strings.Index(src[p+3:], "-->")
			if rel < 0 {
				dead.noCommentCloseFrom = pos
				return scannedTagFullDocGo{}, false
			}
			end := p + 3 + rel + 3
			return scannedTagFullDocGo{
				index: pos, end: end, tagNameLower: "!comment",
				rawTag: src[pos:end], isDeclaration: true,
			}, true
		}
		if c1 == '!' && p+7 < n && strings.HasPrefix(src[p+1:], "[CDATA[") {
			if dead.noCdataCloseFrom > 0 && pos >= dead.noCdataCloseFrom {
				return scannedTagFullDocGo{}, false
			}
			rel := strings.Index(src[p+8:], "]]>")
			if rel < 0 {
				dead.noCdataCloseFrom = pos
				return scannedTagFullDocGo{}, false
			}
			end := p + 8 + rel + 3
			return scannedTagFullDocGo{
				index: pos, end: end, tagNameLower: "!cdata",
				rawTag: src[pos:end], isDeclaration: true,
			}, true
		}
		relGt := strings.IndexByte(src[p+1:], '>')
		if relGt < 0 {
			dead.nextGtPos = -1
			return scannedTagFullDocGo{}, false
		}
		end := p + 1 + relGt + 1
		return scannedTagFullDocGo{
			index: pos, end: end, tagNameLower: "!decl",
			rawTag: src[pos:end], isDeclaration: true,
		}, true
	}

	isClosing := false
	if c1 == '/' {
		isClosing = true
		p++
	}
	if p >= n || !((src[p] >= 'a' && src[p] <= 'z') || (src[p] >= 'A' && src[p] <= 'Z')) {
		return scannedTagFullDocGo{}, false
	}
	nameStart := p
	for p < n {
		ch := src[p]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == ':' || ch == '_' {
			p++
		} else {
			break
		}
	}
	if p < n && !isTagNameBoundaryByteFullDocGo(src[p]) {
		return scannedTagFullDocGo{}, false
	}
	nameLower := asciiLowerExtractString(src[nameStart:p])
	attrStart := p

	if isClosing {
		relGt := strings.IndexByte(src[p:], '>')
		if relGt < 0 {
			dead.nextGtPos = -1
			return scannedTagFullDocGo{}, false
		}
		gtIdx := p + relGt
		return scannedTagFullDocGo{
			index:        pos,
			end:          gtIdx + 1,
			tagNameLower: nameLower,
			rawTag:       src[pos : gtIdx+1],
			attrs:        src[attrStart:gtIdx],
			isClosing:    true,
		}, true
	}

	for {
		j := p
		var quote byte
		for j < n {
			c := src[j]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
			} else {
				if c == '"' && !dead.noCloseDbl {
					quote = '"'
				} else if c == '\'' && !dead.noCloseSgl {
					quote = '\''
				} else if c == '>' {
					break
				}
			}
			j++
		}
		if j < n && src[j] == '>' {
			attrEnd := j
			selfClosing := false
			if attrEnd > attrStart && src[attrEnd-1] == '/' {
				selfClosing = true
				attrEnd--
			}
			return scannedTagFullDocGo{
				index:         pos,
				end:           j + 1,
				tagNameLower:  nameLower,
				rawTag:        src[pos : j+1],
				attrs:         src[attrStart:attrEnd],
				isSelfClosing: selfClosing,
			}, true
		}
		if quote == '"' {
			dead.noCloseDbl = true
			continue
		}
		if quote == '\'' {
			dead.noCloseSgl = true
			continue
		}
		dead.nextGtPos = -1
		return scannedTagFullDocGo{}, false
	}
}

func scanHTMLTagsLinearFullDocGo(rawHTML string, onTag func(scannedTagFullDocGo) bool, maxChars int, allowDeclarations bool) {
	if maxChars <= 0 {
		maxChars = maxHTMLScanCharsFullDocGo
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, maxChars)
	var dead scannerDeadStateFullDocGo
	rel := strings.IndexByte(src, '<')
	if rel < 0 {
		return
	}
	pos := rel
	for pos >= 0 && pos < len(src) {
		if dead.nextGtPos == -1 {
			break
		}
		parsed, ok := tryParseTagAtFullDocGo(src, pos, &dead, allowDeclarations)
		if !ok {
			if dead.nextGtPos == -1 {
				break
			}
			nextRel := strings.IndexByte(src[pos+1:], '<')
			if nextRel < 0 {
				break
			}
			pos = pos + 1 + nextRel
			continue
		}
		if !onTag(parsed) {
			break
		}
		if parsed.end >= len(src) {
			break
		}
		nextRel := strings.IndexByte(src[parsed.end:], '<')
		if nextRel < 0 {
			break
		}
		pos = parsed.end + nextRel
	}
}

func guardSplitTagReassemblyOnChunksFullDocGo(chunks []string, nextSuffix string, deferSet map[string]bool) []string {
	if nextSuffix == "" || len(chunks) == 0 {
		return chunks
	}
	idx := len(chunks) - 1
	for idx >= 0 && len(chunks[idx]) == 0 {
		idx--
	}
	if idx < 0 {
		return chunks
	}
	tail := chunks[idx]
	minScan := len(tail) - 64
	if minScan < 0 {
		minScan = 0
	}
	ltPos := -1
	for i := len(tail) - 1; i >= minScan; i-- {
		ch := tail[i]
		if ch == '>' || ch == '"' || ch == '\'' || ch == '=' || isASCIIWhitespaceByte(ch) || ch == '\v' || ch == '\f' {
			return chunks
		}
		if ch == '<' {
			ltPos = i
			break
		}
	}
	if ltPos < 0 {
		return chunks
	}
	if len(deferSet) > 0 {
		sufLim := len(nextSuffix)
		if sufLim > 24 {
			sufLim = 24
		}
		combined := asciiLowerExtractString(strings.ReplaceAll(tail[ltPos+1:]+nextSuffix[:sufLim], "\x00", ""))
		checkStart := 0
		if strings.HasPrefix(combined, "/") {
			checkStart = 1
		}
		for target := range deferSet {
			if len(combined) > checkStart+len(target) && strings.HasPrefix(combined[checkStart:], target) {
				if isTagNameBoundaryByteFullDocGo(combined[checkStart+len(target)]) {
					return chunks
				}
			}
		}
	}
	chunks[idx] = tail[:ltPos] + "&lt;" + tail[ltPos+1:]
	return chunks
}

func replaceHTMLTagsQuoteAwareLinearFullDocGo(rawHTML string, replacer func(scannedTagFullDocGo) string, maxChars int, allowDeclarations bool) string {
	if maxChars <= 0 {
		maxChars = maxHTMLScanCharsFullDocGo
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, maxChars)
	if strings.IndexByte(src, '<') < 0 {
		return src
	}
	var out []string
	cursor := 0
	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		if tag.index > cursor {
			out = append(out, src[cursor:tag.index])
		}
		rep := replacer(tag)
		if rep == "" && tag.end < len(src) {
			endSuf := tag.end + 24
			if endSuf > len(src) {
				endSuf = len(src)
			}
			out = guardSplitTagReassemblyOnChunksFullDocGo(out, src[tag.end:endSuf], nil)
		} else if rep != "" {
			out = append(out, rep)
		}
		cursor = tag.end
		return true
	}, maxChars, allowDeclarations)
	if cursor == 0 {
		return src
	}
	if cursor < len(src) {
		out = append(out, src[cursor:])
	}
	return strings.Join(out, "")
}

func stripHTMLTagsQuoteAwareLinearFullDocGo(rawHTML, replacement string, maxChars int) string {
	return replaceHTMLTagsQuoteAwareLinearFullDocGo(rawHTML, func(scannedTagFullDocGo) string {
		return replacement
	}, maxChars, true)
}

func replaceHTMLOpenTagsLinearFullDocGo(rawHTML string, tagNamesLower []string, replacer func(scannedTagFullDocGo) string, maxChars int) string {
	if maxChars <= 0 {
		maxChars = maxHTMLScanCharsFullDocGo
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, maxChars)
	if strings.IndexByte(src, '<') < 0 {
		return src
	}
	targetSet := make(map[string]bool, len(tagNamesLower))
	for _, t := range tagNamesLower {
		targetSet[t] = true
	}
	var out []string
	cursor := 0
	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		if tag.isClosing || tag.isDeclaration || !targetSet[tag.tagNameLower] {
			return true
		}
		if tag.index > cursor {
			out = append(out, src[cursor:tag.index])
		}
		rep := replacer(tag)
		if rep == "" && tag.end < len(src) {
			endSuf := tag.end + 24
			if endSuf > len(src) {
				endSuf = len(src)
			}
			out = guardSplitTagReassemblyOnChunksFullDocGo(out, src[tag.end:endSuf], nil)
		} else if rep != "" {
			out = append(out, rep)
		}
		cursor = tag.end
		return true
	}, maxChars, false)
	if cursor == 0 {
		return src
	}
	if cursor < len(src) {
		out = append(out, src[cursor:])
	}
	return strings.Join(out, "")
}

func replacePairedHTMLElementsLinearFullDocGo(
	rawHTML string,
	tagNamesLower []string,
	replacer func(fullMatch, tagNameLower, attrs, innerHTML string) string,
	maxChars, maxInnerChars int,
) string {
	if maxChars <= 0 {
		maxChars = maxHTMLScanCharsFullDocGo
	}
	if maxInnerChars <= 0 {
		maxInnerChars = maxHTMLScanCharsFullDocGo
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, maxChars)
	if strings.IndexByte(src, '<') < 0 {
		return src
	}
	lower := asciiLowerExtractString(src)
	targetSet := make(map[string]bool, len(tagNamesLower))
	hasAny := false
	for _, t := range tagNamesLower {
		targetSet[t] = true
		if !hasAny && strings.Contains(lower, "<"+t) && (strings.Contains(lower, "</"+t) || strings.Contains(lower, "/>")) {
			hasAny = true
		}
	}
	if !hasAny {
		return src
	}

	var dead scannerDeadStateFullDocGo
	cachedClose := make(map[string]int, len(tagNamesLower))
	for _, t := range tagNamesLower {
		cachedClose[t] = -2
	}

	var out []string
	cursor := 0
	rel := strings.IndexByte(src, '<')
	pos := rel

	for pos >= 0 && pos < len(src) {
		parsed, ok := tryParseTagAtFullDocGo(src, pos, &dead, false)
		if !ok {
			if dead.nextGtPos == -1 {
				break
			}
			nextRel := strings.IndexByte(src[pos+1:], '<')
			if nextRel < 0 {
				break
			}
			pos = pos + 1 + nextRel
			continue
		}
		if parsed.isClosing || parsed.isDeclaration || !targetSet[parsed.tagNameLower] {
			if parsed.end >= len(src) {
				break
			}
			nextRel := strings.IndexByte(src[parsed.end:], '<')
			if nextRel < 0 {
				break
			}
			pos = parsed.end + nextRel
			continue
		}
		if parsed.isSelfClosing {
			if parsed.index > cursor {
				out = append(out, src[cursor:parsed.index])
			}
			rep := replacer(parsed.rawTag, parsed.tagNameLower, parsed.attrs, "")
			if rep == "" && parsed.end < len(src) {
				endSuf := parsed.end + 24
				if endSuf > len(src) {
					endSuf = len(src)
				}
				out = guardSplitTagReassemblyOnChunksFullDocGo(out, src[parsed.end:endSuf], nil)
			} else if rep != "" {
				out = append(out, rep)
			}
			cursor = parsed.end
			if cursor >= len(src) {
				break
			}
			nextRel := strings.IndexByte(src[cursor:], '<')
			if nextRel < 0 {
				break
			}
			pos = cursor + nextRel
			continue
		}

		tag := parsed.tagNameLower
		closePos := cachedClose[tag]
		if closePos != -1 && closePos < parsed.end {
			closePos = findNextValidCloseTagGo(lower, src, "</"+tag, parsed.end)
			cachedClose[tag] = closePos
		}
		if closePos < 0 {
			delete(targetSet, tag)
			if len(targetSet) == 0 {
				break
			}
		}
		if closePos < 0 || closePos-parsed.end > maxInnerChars {
			if parsed.end >= len(src) {
				break
			}
			nextRel := strings.IndexByte(src[parsed.end:], '<')
			if nextRel < 0 {
				break
			}
			pos = parsed.end + nextRel
			continue
		}
		closeEndRel := strings.IndexByte(src[closePos+2+len(tag):], '>')
		if closeEndRel < 0 {
			cachedClose[tag] = -1
			if parsed.end >= len(src) {
				break
			}
			nextRel := strings.IndexByte(src[parsed.end:], '<')
			if nextRel < 0 {
				break
			}
			pos = parsed.end + nextRel
			continue
		}
		closeEnd := closePos + 2 + len(tag) + closeEndRel
		if parsed.index > cursor {
			out = append(out, src[cursor:parsed.index])
		}
		inner := src[parsed.end:closePos]
		rep := replacer(src[parsed.index:closeEnd+1], tag, parsed.attrs, inner)
		if rep == "" && closeEnd+1 < len(src) {
			endSuf := closeEnd + 25
			if endSuf > len(src) {
				endSuf = len(src)
			}
			out = guardSplitTagReassemblyOnChunksFullDocGo(out, src[closeEnd+1:endSuf], nil)
		} else if rep != "" {
			out = append(out, rep)
		}
		cursor = closeEnd + 1
		if cursor >= len(src) {
			break
		}
		nextRel := strings.IndexByte(src[cursor:], '<')
		if nextRel < 0 {
			break
		}
		pos = cursor + nextRel
	}

	if cursor == 0 {
		return src
	}
	if cursor < len(src) {
		out = append(out, src[cursor:])
	}
	return strings.Join(out, "")
}

func replaceHTMLTagBlocksLinearFullDocGo(rawHTML, tagLower string, replacer func(full, attrs, inner string) string, maxChars int) string {
	return replacePairedHTMLElementsLinearFullDocGo(rawHTML, []string{tagLower}, func(full, _, attrs, inner string) string {
		return replacer(full, attrs, inner)
	}, maxChars, maxChars)
}

func stripHTMLTagsLinearFullDocGo(rawHTML string, tagNamesLower []string, replacement string, maxChars int) string {
	if maxChars <= 0 {
		maxChars = maxHTMLScanCharsFullDocGo
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, maxChars)
	if strings.IndexByte(src, '<') < 0 {
		return src
	}
	lower := asciiLowerExtractString(src)
	targetSet := make(map[string]bool, len(tagNamesLower))
	hasAny := false
	for _, t := range tagNamesLower {
		targetSet[t] = true
		if !hasAny && strings.Contains(lower, "<"+t) {
			hasAny = true
		}
	}
	if !hasAny {
		return src
	}

	// Balanced O(N) stripping so nested `<nav><nav>...</nav></nav>` or `<aside>...<aside>...</aside>...</aside>` strips outer cleanly.
	var out []string
	lastKeepIdx := 0
	skipTag := ""
	skipDepth := 0
	skipStartIdx := 0

	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		tName := tag.tagNameLower
		isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tName] || tag.isSelfClosing)
		if skipDepth > 0 {
			if tName == skipTag {
				if tag.isClosing {
					skipDepth--
					if skipDepth == 0 {
						if replacement == "" && tag.end < len(src) {
							endSuf := tag.end + 24
							if endSuf > len(src) {
								endSuf = len(src)
							}
							out = guardSplitTagReassemblyOnChunksFullDocGo(out, src[tag.end:endSuf], targetSet)
						} else if replacement != "" {
							out = append(out, replacement)
						}
						lastKeepIdx = tag.end
					}
				} else if !isSelf {
					skipDepth++
				}
			}
			return true
		}
		if targetSet[tName] {
			if tag.isClosing {
				out = append(out, src[lastKeepIdx:tag.index])
				if replacement == "" && tag.end < len(src) {
					endSuf := tag.end + 24
					if endSuf > len(src) {
						endSuf = len(src)
					}
					out = guardSplitTagReassemblyOnChunksFullDocGo(out, src[tag.end:endSuf], targetSet)
				} else if replacement != "" {
					out = append(out, replacement)
				}
				lastKeepIdx = tag.end
				return true
			}
			out = append(out, src[lastKeepIdx:tag.index])
			if isSelf {
				if replacement != "" {
					out = append(out, replacement)
				}
				lastKeepIdx = tag.end
			} else {
				skipTag = tName
				skipDepth = 1
				skipStartIdx = tag.index
				if (tName == "script" || tName == "style" || tName == "head" || tName == "noscript" || tName == "template" || tName == "svg" || tName == "iframe") &&
					findNextValidCloseTagGo(lower, src, "</"+tName, tag.end) < 0 {
					return false
				}
			}
		}
		return true
	}, maxChars, false)

	if len(out) == 0 && skipDepth == 0 {
		return src
	}
	if skipDepth > 0 {
		if skipTag == "script" || skipTag == "style" || skipTag == "head" || skipTag == "noscript" || skipTag == "template" || skipTag == "svg" || skipTag == "iframe" {
			// Drop unclosed raw-text/dangerous blocks cleanly.
		} else {
			out = append(out, src[skipStartIdx:])
		}
	} else if lastKeepIdx < len(src) {
		out = append(out, src[lastKeepIdx:])
	}
	return strings.Join(out, "")
}

func stripHTMLCommentsLinearFullDocGo(rawHTML string, maxChars int) string {
	if maxChars <= 0 {
		maxChars = maxHTMLScanCharsFullDocGo
	}
	src := truncateUTF8SafeFullDocGo(rawHTML, maxChars)
	if !strings.Contains(src, "<!--") {
		return src
	}
	return stripHtmlCommentsLinearGo(src, false)
}

func unescapeURLAttrAmpOnlyFullDocGo(raw string) string {
	if strings.IndexByte(raw, '&') < 0 {
		return raw
	}
	return reURLAmpOnlyFullDocGo.ReplaceAllString(raw, "&")
}

func parseTagAttrsFullDocGo(tag string) map[string]string {
	if len(tag) > 65536 {
		tag = tag[:65536]
	}
	rawAttrs := parseHTMLTagAttrsGo(tag)
	if len(rawAttrs) == 0 {
		return rawAttrs
	}
	out := make(map[string]string, len(rawAttrs))
	for k, v := range rawAttrs {
		if urlOnlyTagAttrsFullDocGo[k] {
			out[k] = unescapeURLAttrAmpOnlyFullDocGo(v)
		} else {
			out[k] = DecodeHTMLEntities(v)
		}
	}
	return out
}

func resolveHTTPSHrefFullDocGo(rawHref, baseURL string, preserveHash bool) string {
	res := resolveInlineHTMLHrefGo(rawHref, baseURL, preserveHash)
	if res == "" {
		return ""
	}
	if u, err := url.Parse(res); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Path == "" && u.RawQuery == "" && u.Fragment == "" {
		u.Path = "/"
		return encodeUnsafeHrefCharsGo(u.String())
	}
	return res
}

func resolveSafeMarkdownHrefOrRelativeFullDocGo(rawHref, baseURL string, preserveHash bool) string {
	if abs := resolveHTTPSHrefFullDocGo(rawHref, baseURL, preserveHash); abs != "" {
		return abs
	}
	if baseURL != "" || rawHref == "" {
		return ""
	}
	trimmedRaw := strings.TrimSpace(rawHref)
	if trimmedRaw == "" {
		return ""
	}
	decoded := strings.TrimSpace(DecodeHTMLEntities(trimmedRaw))
	if decoded == "" ||
		strings.HasPrefix(decoded, "#") ||
		strings.HasPrefix(decoded, "//") ||
		strings.HasPrefix(decoded, `/\`) ||
		strings.ContainsAny(decoded, " \t\r\n<>()`\"'") ||
		isDisallowedMarkdownLinkDestinationGo(trimmedRaw) ||
		isDisallowedMarkdownLinkDestinationGo(decoded) {
		return ""
	}
	colonIdx := strings.IndexByte(decoded, ':')
	slashIdx := strings.IndexByte(decoded, '/')
	if colonIdx > 0 && (slashIdx < 0 || colonIdx < slashIdx) {
		return ""
	}
	return decoded
}

func isPunctClusterByteFullDocGo(b byte) bool {
	switch b {
	case ',', '.', ';', ':', '!', '?', ')', ']', '}':
		return true
	}
	return false
}

func collapseTagBoundaryPunctuationFullDocGo(s string) string {
	if s == "" {
		return s
	}
	// 1) Collapse spaces before `[,.;:!?)\]}]` when NOT preceded by `[` and when followed by whitespace, EOS, or `[,.;:!?)\]}]`.
	if strings.IndexByte(s, ' ') >= 0 {
		var sb strings.Builder
		sb.Grow(len(s))
		i := 0
		n := len(s)
		for i < n {
			if s[i] == ' ' && (i == 0 || s[i-1] != '[') {
				j := i
				for j < n && s[j] == ' ' {
					j++
				}
				if j < n && isPunctClusterByteFullDocGo(s[j]) {
					after := j + 1
					if after >= n || isASCIIWhitespaceByte(s[after]) || isPunctClusterByteFullDocGo(s[after]) {
						sb.WriteByte(s[j])
						i = after
						continue
					}
				}
			}
			sb.WriteByte(s[i])
			i++
		}
		s = sb.String()
	}

	// 2) Collapse spaces before apostrophe contractions (`'s`, `'t`, `'re`, `'ve`, `'ll`, `'d`, `'m` and curly `’`).
	if strings.IndexByte(s, ' ') >= 0 && (strings.IndexByte(s, '\'') >= 0 || strings.Contains(s, "\u2019")) {
		var sb strings.Builder
		sb.Grow(len(s))
		i := 0
		n := len(s)
		for i < n {
			if s[i] == ' ' {
				j := i
				for j < n && s[j] == ' ' {
					j++
				}
				aposLen := 0
				if j < n && s[j] == '\'' {
					aposLen = 1
				} else if j+3 <= n && s[j:j+3] == "\u2019" {
					aposLen = 3
				}
				if aposLen > 0 {
					tail := s[j+aposLen:]
					sufLen := matchContractionSuffixFullDocGo(tail)
					if sufLen > 0 {
						sb.WriteString(s[j : j+aposLen+sufLen])
						i = j + aposLen + sufLen
						continue
					}
				}
			}
			sb.WriteByte(s[i])
			i++
		}
		s = sb.String()
	}

	// 3) Collapse `( +` before non-whitespace, non-`)`
	if strings.Contains(s, "( ") {
		var sb strings.Builder
		sb.Grow(len(s))
		i := 0
		n := len(s)
		for i < n {
			if s[i] == '(' && i+1 < n && s[i+1] == ' ' {
				j := i + 1
				for j < n && s[j] == ' ' {
					j++
				}
				if j < n && !isASCIIWhitespaceByte(s[j]) && s[j] != ')' {
					sb.WriteByte('(')
					i = j
					continue
				}
			}
			sb.WriteByte(s[i])
			i++
		}
		s = sb.String()
	}

	// 4) Collapse `[\s+(\d{1,4})\s*]` -> `[$1]`
	if strings.Contains(s, "[ ") || strings.Contains(s, "[\t") || strings.Contains(s, "[\n") {
		s = reBracketCiteNumFullDocGo.ReplaceAllString(s, "[$1]")
	}
	return s
}

func matchContractionSuffixFullDocGo(tail string) int {
	if len(tail) == 0 {
		return 0
	}
	isWordEnd := func(idx int) bool {
		if idx >= len(tail) {
			return true
		}
		r, _ := utf8.DecodeRuneInString(tail[idx:])
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
	}
	if len(tail) >= 2 {
		two := asciiLowerExtractString(tail[:2])
		if (two == "re" || two == "ve" || two == "ll") && isWordEnd(2) {
			return 2
		}
	}
	one := asciiLowerExtractByte(tail[0])
	if (one == 's' || one == 't' || one == 'd' || one == 'm') && isWordEnd(1) {
		return 1
	}
	return 0
}

func cleanInlineHTMLFullDocGo(fragment string) string {
	if fragment == "" {
		return ""
	}
	stripped := replaceHTMLTagsQuoteAwareLinearFullDocGo(fragment, func(t scannedTagFullDocGo) string {
		if !t.isClosing && t.tagNameLower == "wbr" {
			return ""
		}
		return " "
	}, maxHTMLScanCharsFullDocGo, true)
	decoded := stripInvisibleSmugglingCharsGo(DecodeHTMLEntities(stripped))
	joined := strings.Join(strings.Fields(decoded), " ")
	return collapseTagBoundaryPunctuationFullDocGo(joined)
}

func isLazyPlaceholderImageURLFullDocGo(urlStr string) bool {
	trimmed := strings.TrimSpace(urlStr)
	if trimmed == "" || strings.HasPrefix(asciiLowerExtractString(trimmed[:minInt(len(trimmed), 6)]), "data:") {
		return true
	}
	return reLazyPlaceholderFullDocGo.MatchString(trimmed)
}

func isTinyOrAvatarImageURLFullDocGo(urlStr, alt string) bool {
	if isLazyPlaceholderImageURLFullDocGo(urlStr) {
		return true
	}
	if reTinyOrAvatarFullDocGo.MatchString(alt + " " + urlStr) {
		return true
	}
	for _, m := range reQueryDimFullDocGo.FindAllStringSubmatch(urlStr, 8) {
		if len(m) >= 2 {
			if dim, err := strconv.Atoi(m[1]); err == nil && dim > 0 && dim <= 4 {
				return true
			}
		}
	}
	return false
}

func isDecorativeOrTinyImageFullDocGo(attrs map[string]string, resolvedSrc string) bool {
	if w, err := strconv.Atoi(strings.TrimSpace(attrs["width"])); err == nil && w > 0 && w < 100 {
		return true
	}
	if h, err := strconv.Atoi(strings.TrimSpace(attrs["height"])); err == nil && h > 0 && h < 100 {
		return true
	}
	hay := attrs["alt"] + " " + attrs["class"] + " " + attrs["id"] + " " + resolvedSrc
	return reTinyOrBadgeImgFullDocGo.MatchString(hay) || isLazyPlaceholderImageURLFullDocGo(resolvedSrc)
}

func convertAnchorInnerWithBadgeImagesFullDocGo(inner, baseURL string, includeImages bool) string {
	withoutEm := inner
	lowInner := asciiLowerExtractString(inner)
	if strings.Contains(lowInner, "<em") || strings.Contains(lowInner, "<i") ||
		strings.Contains(lowInner, "<strong") || strings.Contains(lowInner, "<b") ||
		strings.Contains(lowInner, "<u") || strings.Contains(lowInner, "<mark") {
		withoutEm = replaceHTMLTagsQuoteAwareLinearFullDocGo(inner, func(t scannedTagFullDocGo) string {
			switch t.tagNameLower {
			case "em", "i", "strong", "b", "u", "mark":
				return ""
			}
			return t.rawTag
		}, 8192, false)
	}
	if !includeImages || !strings.Contains(asciiLowerExtractString(withoutEm), "<img") {
		return cleanInlineHTMLFullDocGo(withoutEm)
	}
	withImgs := replaceHTMLOpenTagsLinearFullDocGo(withoutEm, []string{"img"}, func(tag scannedTagFullDocGo) string {
		if hasInlineEventHandlerAttrGo(tag.attrs) {
			return ""
		}
		attrs := parseTagAttrsFullDocGo(tag.attrs)
		srcCand := attrs["src"]
		if srcCand == "" {
			srcCand = attrs["data-src"]
		}
		resolvedSrc := resolveSafeMarkdownHrefOrRelativeFullDocGo(srcCand, baseURL, false)
		alt := strings.NewReplacer("[", "", "]", "").Replace(cleanInlineHTMLFullDocGo(attrs["alt"]))
		if resolvedSrc == "" || isTinyOrAvatarImageURLFullDocGo(resolvedSrc, alt) {
			return ""
		}
		return " ![" + alt + "](" + resolvedSrc + ") "
	}, 8192)
	return cleanInlineHTMLFullDocGo(withImgs)
}

// SanitizeScrapedMetadataField sanitizes single-line metadata fields (`Title`, `Description`, `Author`, `SiteName`),
// stripping invisible smuggling characters, collapsing newlines/tabs, neutralizing unsafe Markdown links, and escaping `<` -> `&lt;`.
func SanitizeScrapedMetadataField(raw string, maxLen int) string {
	if raw == "" {
		return ""
	}
	if maxLen <= 0 {
		maxLen = 2000
	}
	bounded := truncateUTF8SafeFullDocGo(raw, maxLen*4)
	clean := SanitizeScrapedMeta(bounded)
	if clean == "" {
		return ""
	}
	if utf8.RuneCountInString(clean) > maxLen {
		clean = sliceRunesMax(clean, maxLen)
		clean = strings.TrimSpace(clean)
		clean = SanitizeScrapedMeta(clean)
	}
	if len(clean) > maxLen {
		clean = strings.TrimSpace(truncateUTF8SafeFullDocGo(clean, maxLen))
		clean = SanitizeScrapedMeta(clean)
	}
	return clean
}

// SanitizeScrapedTimestampField sanitizes ISO/human timestamp metadata fields, neutralizing Markdown/HTML syntax.
func SanitizeScrapedTimestampField(raw string, maxLen int) string {
	if raw == "" {
		return ""
	}
	if maxLen <= 0 {
		maxLen = 128
	}
	s := stripInvisibleSmugglingCharsGo(raw)
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if r <= 0x1F || (r >= 0x7F && r <= 0x9F) || r == '\u2028' || r == '\u2029' {
			sb.WriteByte(' ')
		} else {
			sb.WriteRune(r)
		}
	}
	s = strings.Join(strings.Fields(sb.String()), " ")
	if s == "" {
		return ""
	}
	if len(s) > maxLen {
		s = strings.TrimSpace(truncateUTF8SafeFullDocGo(s, maxLen))
	}
	if strings.Contains(s, "](") || strings.Contains(s, "]:") || strings.Contains(s, "//") {
		s = neutralizeAllUnsafeMarkdownLinksLinearGo(s)
	}
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
	)
	return replacer.Replace(s)
}

func normalizeFenceLangFullDocGo(raw string) string {
	if raw == "" {
		return ""
	}
	clean := strings.ToLower(strings.TrimSpace(raw))
	clean = strings.TrimPrefix(clean, "language-")
	clean = strings.TrimPrefix(clean, "lang-")
	if clean == "" || !reLangIdentFullDocGo.MatchString(clean) {
		return ""
	}
	if alias, exists := codeLangAliasesFullDocGo[clean]; exists {
		return alias
	}
	return clean
}

func inferCodeFenceLangFullDocGo(preAttrStr, codeAttrStr string) string {
	preAttrs := parseTagAttrsFullDocGo(preAttrStr)
	codeAttrs := parseTagAttrsFullDocGo(codeAttrStr)
	for _, cand := range []string{
		codeAttrs["data-language"],
		codeAttrs["data-lang"],
		codeAttrs["data-wrapper-lang"],
		preAttrs["data-language"],
		preAttrs["data-lang"],
		preAttrs["data-wrapper-lang"],
		codeAttrs["lang"],
		preAttrs["lang"],
	} {
		if norm := normalizeFenceLangFullDocGo(cand); norm != "" {
			return norm
		}
	}
	cCls := codeAttrs["class"]
	if len(cCls) > 512 {
		cCls = cCls[:512]
	}
	pCls := preAttrs["class"]
	if len(pCls) > 512 {
		pCls = pCls[:512]
	}
	classes := cCls + " " + pCls
	for _, rx := range []*regexp.Regexp{reClassLang1FullDocGo, reClassLang2FullDocGo, reClassLang3FullDocGo} {
		if m := rx.FindStringSubmatch(classes); len(m) >= 2 {
			if norm := normalizeFenceLangFullDocGo(m[1]); norm != "" {
				return norm
			}
		}
	}
	if reClassRustFullDocGo.MatchString(classes) {
		return "rust"
	}
	if reClassGoDocFullDocGo.MatchString(classes) {
		return "go"
	}
	return ""
}

func cleanHeadingPermalinksFullDocGo(headingText string) string {
	s := headingText
	if strings.HasPrefix(s, "§") {
		s = strings.TrimLeft(s[len("§"):], " \t")
	}
	s = reHeadingEditFullDocGo.ReplaceAllString(s, "")
	s = reHeadingAddedInFullDocGo.ReplaceAllString(s, " ($1)")
	s = reHeadingPilcrowLnkFullDocGo.ReplaceAllString(s, "")
	s = reHeadingTrailSymFullDocGo.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

// RedactPIIMarkdownSafe redacts email, SSN, phone, and Luhn-valid payment cards while escaping adjacent
// Markdown link delimiters (`[REDACTED_EMAIL]\(javascript:...)`) so redaction never synthesizes links.
func RedactPIIMarkdownSafe(text string) string {
	return redactPIIMarkdownSafeFullDocGo(text)
}

func redactPIIMarkdownSafeFullDocGo(text string) string {
	if text == "" {
		return text
	}
	out := RedactPII(text)
	if strings.Contains(out, "[REDACTED_") {
		out = reRedactedLinkGuardFullDocGo.ReplaceAllString(out, `$1\$2`)
	}
	return out
}

func isPlaceholderMetaValueFullDocGo(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return true
	}
	if rePlaceholderMetaFullDocGo.MatchString(s) {
		return true
	}
	if strings.ContainsAny(s, "{}") || rePlaceholderHashFullDocGo.MatchString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func cleanAuthorMetaStringFullDocGo(raw string) string {
	s := reAuthorByPrefixFullDocGo.ReplaceAllString(raw, "")
	s = reAuthorURLFullDocGo.ReplaceAllString(s, "")
	s = reAuthorAndFullDocGo.ReplaceAllString(s, ", ")
	s = reAuthorTrailDashFullDocGo.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(s), " ")
}

func countTextWordsFullDocGo(text string) int {
	n := len(text)
	if n == 0 {
		return 0
	}
	words := 0
	inWord := false
	i := 0
	for i < n {
		b := text[i]
		if b < 0x80 {
			isW := (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '\'' || b == '-'
			if isW {
				if !inWord {
					words++
					inWord = true
				}
			} else {
				inWord = false
			}
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(text[i:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '\'' || r == '-' {
			if !inWord {
				words++
				inWord = true
			}
		} else {
			inWord = false
		}
		i += w
	}
	return words
}

func collapseHorizontalSpaceRunFullDocGo(s string) string {
	if !strings.Contains(s, "  ") && strings.IndexByte(s, '\t') < 0 && strings.IndexByte(s, '\r') < 0 && strings.IndexByte(s, '\f') < 0 && strings.IndexByte(s, '\v') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	prevSpace := false
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == ' ' || b == '\t' || b == '\r' || b == '\f' || b == '\v' {
			if !prevSpace {
				sb.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		sb.WriteByte(b)
	}
	return sb.String()
}

// ExtractLargestURLFromSrcset selects the highest-resolution candidate URL from an HTML `srcset` attribute (`1200w`, `2x`, etc.),
// preserving commas inside CDN transform paths (e.g. Cloudinary `w_800,q_auto`) that lack post-comma whitespace.
func ExtractLargestURLFromSrcset(srcset string) string {
	s := strings.TrimSpace(srcset)
	if s == "" {
		return ""
	}
	// Split strictly on `,` followed by >=1 whitespace char + non-whitespace so commas inside URLs survive.
	var entries []string
	start := 0
	n := len(s)
	for i := 0; i < n; i++ {
		if s[i] == ',' {
			j := i + 1
			for j < n && isASCIIWhitespaceByte(s[j]) {
				j++
			}
			if j > i+1 && j < n {
				entries = append(entries, s[start:i])
				start = j
				i = j - 1
			}
		}
	}
	entries = append(entries, s[start:])

	bestURL := ""
	bestScore := -1.0
	for _, rawEntry := range entries {
		fields := strings.Fields(strings.TrimSpace(rawEntry))
		if len(fields) == 0 {
			continue
		}
		cand := strings.TrimSpace(strings.TrimRight(fields[0], ","))
		if cand == "" || strings.HasPrefix(asciiLowerExtractString(cand[:minInt(len(cand), 6)]), "data:") {
			continue
		}
		score := 100.0
		if len(fields) >= 2 {
			desc := asciiLowerExtractString(strings.TrimRight(fields[1], ","))
			if len(desc) >= 2 && (desc[len(desc)-1] == 'w' || desc[len(desc)-1] == 'x') {
				unit := desc[len(desc)-1]
				if num, err := strconv.ParseFloat(desc[:len(desc)-1], 64); err == nil && num > 0 {
					if unit == 'w' {
						score = num
					} else {
						score = num * 1000.0
					}
				}
			}
		}
		if score >= bestScore {
			bestScore = score
			bestURL = cand
		}
	}
	return bestURL
}

func flattenJsonLdEntitiesFullDocGo(rawHTML string) []map[string]any {
	var entities []map[string]any
	var visit func(node any, depth int)
	visit = func(node any, depth int) {
		if node == nil || depth > 6 {
			return
		}
		switch v := node.(type) {
		case []any:
			for _, item := range v {
				visit(item, depth+1)
			}
		case map[string]any:
			entities = append(entities, v)
			if graph, ok := v["@graph"].([]any); ok {
				visit(graph, depth+1)
			}
		}
	}
	if strings.Contains(asciiLowerExtractString(rawHTML), "ld+json") {
		replaceHTMLTagBlocksLinearFullDocGo(rawHTML, "script", func(_, attrStr, inner string) string {
			attrs := parseTagAttrsFullDocGo(attrStr)
			if strings.EqualFold(strings.TrimSpace(attrs["type"]), "application/ld+json") {
				var parsed any
				if err := json.Unmarshal([]byte(strings.TrimSpace(inner)), &parsed); err == nil {
					visit(parsed, 0)
				}
			}
			return ""
		}, maxHTMLScanCharsFullDocGo)
	}
	return entities
}

type schemaMetaResultFullDocGo struct {
	author        string
	publishedTime string
	modifiedTime  string
	siteName      string
	articleBody   string
}

func extractSchemaMetadataAndBodyFullDocGo(entities []map[string]any) schemaMetaResultFullDocGo {
	var res schemaMetaResultFullDocGo
	var extractAuthors func(raw any) []string
	extractAuthors = func(raw any) []string {
		switch v := raw.(type) {
		case string:
			c := cleanAuthorMetaStringFullDocGo(v)
			if c != "" && !isPlaceholderMetaValueFullDocGo(c) {
				return []string{c}
			}
		case []any:
			var out []string
			for _, item := range v {
				out = append(out, extractAuthors(item)...)
			}
			return out
		case map[string]any:
			if name, ok := v["name"].(string); ok {
				c := cleanAuthorMetaStringFullDocGo(name)
				if c != "" && !isPlaceholderMetaValueFullDocGo(c) {
					return []string{c}
				}
			}
		}
		return nil
	}

	for _, ent := range entities {
		if res.author == "" && ent["author"] != nil {
			rawNames := extractAuthors(ent["author"])
			seen := make(map[string]bool)
			var uniq []string
			for _, nm := range rawNames {
				if !seen[nm] {
					seen[nm] = true
					uniq = append(uniq, nm)
					if len(uniq) >= 8 {
						break
					}
				}
			}
			if len(uniq) > 0 {
				res.author = strings.Join(uniq, ", ")
			}
		}
		if res.publishedTime == "" {
			if dp, ok := ent["datePublished"].(string); ok && !isPlaceholderMetaValueFullDocGo(dp) {
				res.publishedTime = strings.TrimSpace(dp)
			}
		}
		if res.modifiedTime == "" {
			if dm, ok := ent["dateModified"].(string); ok && !isPlaceholderMetaValueFullDocGo(dm) {
				res.modifiedTime = strings.TrimSpace(dm)
			}
		}
		if res.siteName == "" {
			cand := ""
			if pub, ok := ent["publisher"].(map[string]any); ok {
				if pn, ok := pub["name"].(string); ok {
					cand = pn
				}
			}
			if cand == "" {
				tStr := strings.ToLower(jsonScalarToString(ent["@type"]))
				if tStr == "website" {
					if nm, ok := ent["name"].(string); ok {
						cand = nm
					}
				}
			}
			if cand != "" && !isPlaceholderMetaValueFullDocGo(cand) {
				res.siteName = strings.TrimSpace(cand)
			}
		}
		bodyCand := ""
		if ab, ok := ent["articleBody"].(string); ok {
			bodyCand = strings.TrimSpace(ab)
		} else if tx, ok := ent["text"].(string); ok {
			tLower := strings.ToLower(jsonScalarToString(ent["@type"]))
			if strings.Contains(tLower, "article") || strings.Contains(tLower, "posting") ||
				strings.Contains(tLower, "question") || strings.Contains(tLower, "answer") {
				bodyCand = strings.TrimSpace(tx)
			}
		}
		if bodyCand != "" && len(bodyCand) > len(res.articleBody) {
			res.articleBody = bodyCand
		}
	}
	return res
}

type parsedSimpleSelectorFullDocGo struct {
	tag string
	id  string
	cls string
}

func parseSimpleSelectorListFullDocGo(rawSelectors []string) []parsedSimpleSelectorFullDocGo {
	if len(rawSelectors) == 0 {
		return nil
	}
	limit := len(rawSelectors)
	if limit > 25 {
		limit = 25
	}
	var out []parsedSimpleSelectorFullDocGo
	for _, raw := range rawSelectors[:limit] {
		s := strings.TrimSpace(raw)
		if s == "" || len(s) > 80 {
			continue
		}
		m := reSimpleSelectorFullDocGo.FindStringSubmatch(s)
		if len(m) < 4 || (m[1] == "" && m[2] == "" && m[3] == "") {
			continue
		}
		out = append(out, parsedSimpleSelectorFullDocGo{
			tag: strings.ToLower(m[1]),
			id:  strings.ToLower(m[2]),
			cls: strings.ToLower(m[3]),
		})
	}
	return out
}

func tagMatchesSimpleSelectorsFullDocGo(tagLower, attrStr string, selectors []parsedSimpleSelectorFullDocGo) bool {
	if len(selectors) == 0 {
		return false
	}
	var parsedAttrs map[string]string
	var classSet map[string]bool
	for _, sel := range selectors {
		if sel.tag != "" && sel.tag != tagLower {
			continue
		}
		if sel.id != "" || sel.cls != "" {
			if parsedAttrs == nil {
				parsedAttrs = parseTagAttrsFullDocGo(attrStr)
			}
			if sel.id != "" && strings.ToLower(strings.TrimSpace(parsedAttrs["id"])) != sel.id {
				continue
			}
			if sel.cls != "" {
				if classSet == nil {
					classSet = make(map[string]bool)
					for _, tok := range strings.Fields(strings.ToLower(parsedAttrs["class"])) {
						classSet[tok] = true
					}
				}
				if !classSet[sel.cls] {
					continue
				}
			}
		}
		return true
	}
	return false
}

func applyIncludeAndExcludeTagSelectorsFullDocGo(rawHTML string, includeTags, excludeTags []string) string {
	out := truncateUTF8SafeFullDocGo(rawHTML, maxHTMLScanCharsFullDocGo)
	parsedInclude := parseSimpleSelectorListFullDocGo(includeTags)
	if len(parsedInclude) > 0 {
		type spanRange struct{ start, end int }
		var matched []spanRange
		matchTag := ""
		matchDepth := 0
		matchStart := 0
		src := out
		scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
			tLower := tag.tagNameLower
			isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tLower] || tag.isSelfClosing)
			if matchDepth > 0 {
				if tLower == matchTag {
					if tag.isClosing {
						matchDepth--
						if matchDepth == 0 {
							matched = append(matched, spanRange{matchStart, tag.end})
						}
					} else if !isSelf {
						matchDepth++
					}
				}
				return true
			}
			if !tag.isClosing && tagMatchesSimpleSelectorsFullDocGo(tLower, tag.attrs, parsedInclude) {
				if isSelf {
					matched = append(matched, spanRange{tag.index, tag.end})
				} else {
					matchTag = tLower
					matchDepth = 1
					matchStart = tag.index
				}
			}
			return true
		}, maxHTMLScanCharsFullDocGo, false)
		if matchDepth > 0 {
			matched = append(matched, spanRange{matchStart, len(src)})
		}
		if len(matched) > 0 {
			parts := make([]string, len(matched))
			for i, r := range matched {
				parts[i] = src[r.start:r.end]
			}
			out = strings.Join(parts, "\n\n")
		}
	}

	parsedExclude := parseSimpleSelectorListFullDocGo(excludeTags)
	if len(parsedExclude) > 0 {
		var chunks []string
		lastKeepIdx := 0
		skipTag := ""
		skipDepth := 0
		skipStartIdx := 0
		src := out
		scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
			tLower := tag.tagNameLower
			isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tLower] || tag.isSelfClosing)
			if skipDepth > 0 {
				if tLower == skipTag {
					if tag.isClosing {
						skipDepth--
						if skipDepth == 0 {
							lastKeepIdx = tag.end
						}
					} else if !isSelf {
						skipDepth++
					}
				}
				return true
			}
			if !tag.isClosing && tagMatchesSimpleSelectorsFullDocGo(tLower, tag.attrs, parsedExclude) {
				chunks = append(chunks, src[lastKeepIdx:tag.index])
				if isSelf {
					lastKeepIdx = tag.end
				} else {
					skipTag = tLower
					skipDepth = 1
					skipStartIdx = tag.index
				}
			}
			return true
		}, maxHTMLScanCharsFullDocGo, false)
		if len(chunks) > 0 || skipDepth > 0 {
			if skipDepth > 0 {
				chunks = append(chunks, src[skipStartIdx:])
			} else if lastKeepIdx < len(src) {
				chunks = append(chunks, src[lastKeepIdx:])
			}
			out = strings.Join(chunks, "")
		}
	}
	return out
}

func extractBalancedRoleMainHTMLFullDocGo(rawHTML string) (string, bool) {
	targetTag := ""
	contentStart := -1
	depth := 0
	var matched string
	found := false

	scanHTMLTagsLinearFullDocGo(rawHTML, func(tag scannedTagFullDocGo) bool {
		if tag.tagNameLower != "div" && tag.tagNameLower != "section" {
			return true
		}
		if targetTag == "" {
			if tag.isClosing || tag.isSelfClosing {
				return true
			}
			attrs := parseTagAttrsFullDocGo(tag.attrs)
			if strings.EqualFold(strings.TrimSpace(attrs["role"]), "main") {
				targetTag = tag.tagNameLower
				contentStart = tag.end
				depth = 1
			}
			return true
		}
		if tag.tagNameLower != targetTag {
			return true
		}
		if tag.isClosing {
			depth--
			if depth == 0 {
				matched = rawHTML[contentStart:tag.index]
				found = true
				return false
			}
		} else if !tag.isSelfClosing {
			depth++
		}
		return true
	}, maxHTMLScanCharsFullDocGo, false)
	return matched, found
}

func shouldStripSubtreeOpenTagFullDocGo(tagLower, attrStr string) bool {
	if attrStr == "" || tagLower == "html" || tagLower == "body" || tagLower == "main" || tagLower == "article" {
		return false
	}
	lowAttr := asciiLowerExtractString(attrStr)
	if !strings.Contains(lowAttr, "hidden") && !strings.Contains(lowAttr, "style") &&
		!strings.Contains(lowAttr, "role") && !strings.Contains(lowAttr, "class") && !strings.Contains(lowAttr, "aria-hidden") {
		return false
	}
	attrs := parseTagAttrsFullDocGo(attrStr)
	if hv, hasHidden := attrs["hidden"]; hasHidden {
		hvLower := strings.ToLower(strings.TrimSpace(hv))
		if hvLower != "false" && hvLower != "0" {
			return true
		}
	}
	if styleVal := attrs["style"]; styleVal != "" {
		if !strings.Contains(lowAttr, "mwe-math") && !strings.Contains(lowAttr, "katex-mathml") && !strings.Contains(lowAttr, "mjx-assistive") {
			if reStyleHiddenFullDocGo.MatchString(styleVal) || isHiddenInlineStyleGo(styleVal) {
				return true
			}
		}
	}
	if roleVal := strings.ToLower(strings.TrimSpace(attrs["role"])); nonContentRolesFullDocGo[roleVal] {
		return true
	}
	if (tagLower == "span" || tagLower == "i" || tagLower == "bdi") && strings.EqualFold(strings.TrimSpace(attrs["aria-hidden"]), "true") {
		return true
	}
	if classVal := strings.TrimSpace(attrs["class"]); classVal != "" {
		tokens := strings.Fields(strings.ToLower(classVal))
		hasDNoneOrTw := false
		for _, tok := range tokens {
			if alwaysHiddenOrChromeClassesFullDocGo[tok] {
				return true
			}
			if tok == "d-none" || tok == "tw-hidden" {
				hasDNoneOrTw = true
			}
		}
		if hasDNoneOrTw && !reResponsiveShowFullDocGo.MatchString(classVal) {
			return true
		}
	}
	return false
}

func stripHiddenAndChromeSubtreesFullDocGo(rawHTML string) string {
	src := truncateUTF8SafeFullDocGo(rawHTML, maxHTMLScanCharsFullDocGo)
	var chunks []string
	lastKeepIdx := 0
	skipTag := ""
	skipDepth := 0
	skipStartIdx := 0

	scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
		tLower := tag.tagNameLower
		isSelf := !tag.isClosing && (voidHTMLTagsFullDocGo[tLower] || tag.isSelfClosing)
		if skipDepth > 0 {
			if tLower == skipTag {
				if tag.isClosing {
					skipDepth--
					if skipDepth == 0 {
						lastKeepIdx = tag.end
					}
				} else if !isSelf {
					skipDepth++
				}
			}
			return true
		}
		if !tag.isClosing && shouldStripSubtreeOpenTagFullDocGo(tLower, tag.attrs) {
			chunks = append(chunks, src[lastKeepIdx:tag.index])
			if isSelf {
				lastKeepIdx = tag.end
			} else {
				skipTag = tLower
				skipDepth = 1
				skipStartIdx = tag.index
			}
		}
		return true
	}, maxHTMLScanCharsFullDocGo, false)

	if len(chunks) == 0 && skipDepth == 0 {
		return src
	}
	if skipDepth > 0 {
		chunks = append(chunks, src[skipStartIdx:])
	} else if lastKeepIdx < len(src) {
		chunks = append(chunks, src[lastKeepIdx:])
	}
	return strings.Join(chunks, "")
}

type substackPreloadFullDocGo struct {
	title         string
	subtitle      string
	author        string
	publishedTime string
	bodyHTML      string
}

func extractSubstackPreloadDataFullDocGo(rawHTML string) *substackPreloadFullDocGo {
	if !strings.Contains(rawHTML, "preloads-json") && !(strings.Contains(rawHTML, "window._preloads") && strings.Contains(rawHTML, "body_html")) {
		return nil
	}
	readFromData := func(data any) *substackPreloadFullDocGo {
		d, ok := data.(map[string]any)
		if !ok {
			return nil
		}
		var post map[string]any
		if p, ok := d["post"].(map[string]any); ok {
			post = p
		} else if fd, ok := d["feedData"].(map[string]any); ok {
			if ip, ok := fd["initialPost"].(map[string]any); ok {
				post, _ = ip["post"].(map[string]any)
			}
		}
		if post == nil {
			return nil
		}
		bodyHTML, _ := post["body_html"].(string)
		bodyHTML = strings.TrimSpace(bodyHTML)
		title, _ := post["title"].(string)
		title = strings.TrimSpace(title)
		subtitle, _ := post["subtitle"].(string)
		subtitle = strings.TrimSpace(subtitle)
		pubTime, _ := post["post_date"].(string)
		pubTime = strings.TrimSpace(pubTime)
		author := ""
		if bylines, ok := post["publishedBylines"].([]any); ok && len(bylines) > 0 {
			if b0, ok := bylines[0].(map[string]any); ok {
				if nm, ok := b0["name"].(string); ok {
					author = strings.TrimSpace(nm)
				}
			}
		}
		if bodyHTML == "" && title == "" {
			return nil
		}
		return &substackPreloadFullDocGo{
			title:         title,
			subtitle:      subtitle,
			author:        author,
			publishedTime: pubTime,
			bodyHTML:      bodyHTML,
		}
	}

	if strings.Contains(rawHTML, "preloads-json") {
		preloadStr := ""
		replaceHTMLTagBlocksLinearFullDocGo(rawHTML, "script", func(_, attrStr, inner string) string {
			if preloadStr == "" && strings.EqualFold(parseTagAttrsFullDocGo(attrStr)["id"], "preloads-json") {
				preloadStr = inner
			}
			return ""
		}, maxHTMLScanCharsFullDocGo)
		if preloadStr != "" {
			var parsed any
			if err := json.Unmarshal([]byte(preloadStr), &parsed); err == nil {
				if res := readFromData(parsed); res != nil {
					return res
				}
			}
		}
	}

	if markerIdx := strings.Index(rawHTML, "window._preloads"); markerIdx >= 0 {
		const parsePrefix = `JSON.parse("`
		relParse := strings.Index(rawHTML[markerIdx:], parsePrefix)
		if relParse >= 0 && relParse < 200 {
			start := markerIdx + relParse + len(parsePrefix)
			maxEnd := start + 1_500_000
			if maxEnd > len(rawHTML) {
				maxEnd = len(rawHTML)
			}
			i := start
			for i < maxEnd {
				if rawHTML[i] == '\\' {
					i += 2
				} else if rawHTML[i] == '"' {
					break
				} else {
					i++
				}
			}
			if i < maxEnd {
				var jsonStr string
				if err := json.Unmarshal([]byte(`"`+rawHTML[start:i]+`"`), &jsonStr); err == nil {
					var parsed any
					if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
						if res := readFromData(parsed); res != nil {
							return res
						}
					}
				}
			}
		}
	}
	return nil
}

func hasClassTokenFullDocGo(attrStr, tokenLower string) bool {
	cls := strings.ToLower(parseTagAttrsFullDocGo(attrStr)["class"])
	if cls == "" {
		return false
	}
	for _, tok := range strings.Fields(cls) {
		if tok == tokenLower {
			return true
		}
	}
	return false
}

func findFirstClassSubtreeLinearFullDocGo(rawHTML string, tagNames []string, classTokenLower string) (inner string, endIdx int, ok bool) {
	tagSet := make(map[string]bool, len(tagNames))
	for _, t := range tagNames {
		tagSet[t] = true
	}
	matchTag := ""
	depth := 0
	innerStart := -1
	scanHTMLTagsLinearFullDocGo(rawHTML, func(tag scannedTagFullDocGo) bool {
		if !tagSet[tag.tagNameLower] {
			return true
		}
		if matchTag == "" {
			if tag.isClosing || tag.isSelfClosing {
				return true
			}
			if hasClassTokenFullDocGo(tag.attrs, classTokenLower) {
				matchTag = tag.tagNameLower
				depth = 1
				innerStart = tag.end
			}
			return true
		}
		if tag.tagNameLower != matchTag {
			return true
		}
		if tag.isClosing {
			depth--
			if depth == 0 {
				inner = rawHTML[innerStart:tag.index]
				endIdx = tag.end
				ok = true
				return false
			}
		} else if !tag.isSelfClosing {
			depth++
		}
		return true
	}, maxHTMLScanCharsFullDocGo, false)
	return inner, endIdx, ok
}

func findFirstAnchorInFragmentFullDocGo(frag string) (href, text string, ok bool) {
	replacePairedHTMLElementsLinearFullDocGo(frag, []string{"a"}, func(_, _, attrStr, inner string) string {
		if !ok {
			attrs := parseTagAttrsFullDocGo(attrStr)
			href = attrs["href"]
			text = cleanInlineHTMLFullDocGo(inner)
			ok = true
		}
		return ""
	}, 24000, 4000)
	return href, text, ok
}

func findHNAuthorInFragmentFullDocGo(frag string) string {
	author := ""
	replacePairedHTMLElementsLinearFullDocGo(frag, []string{"a"}, func(_, _, attrStr, inner string) string {
		if author == "" {
			attrs := parseTagAttrsFullDocGo(attrStr)
			href := attrs["href"]
			if strings.HasPrefix(href, "user?id=") || hasClassTokenFullDocGo(attrStr, "hnuser") {
				if c := cleanInlineHTMLFullDocGo(inner); c != "" {
					author = c
				}
			}
		}
		return ""
	}, 32000, 1000)
	return author
}

func findSpanAttrInFragmentFullDocGo(frag, classTokenLower, attrNameLower string) string {
	val := ""
	scanHTMLTagsLinearFullDocGo(frag, func(tag scannedTagFullDocGo) bool {
		if !tag.isClosing && tag.tagNameLower == "span" && hasClassTokenFullDocGo(tag.attrs, classTokenLower) {
			val = parseTagAttrsFullDocGo(tag.attrs)[attrNameLower]
			return false
		}
		return true
	}, 32000, false)
	return val
}

func hnFragmentToMarkdownFullDocGo(fragHTML, baseURL string) string {
	var codeBlocks []string
	s := fragHTML
	if strings.Contains(fragHTML, "reply") {
		s = replacePairedHTMLElementsLinearFullDocGo(fragHTML, []string{"div"}, func(full, _, attrStr, _ string) string {
			if hasClassTokenFullDocGo(attrStr, "reply") {
				return ""
			}
			return full
		}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
	}
	s = replacePairedHTMLElementsLinearFullDocGo(s, []string{"pre"}, func(_, _, _, inner string) string {
		clean := strings.TrimRight(DecodeHTMLEntities(stripHTMLTagsQuoteAwareLinearFullDocGo(inner, "", maxHTMLScanCharsFullDocGo)), " \t\r\n")
		idx := len(codeBlocks)
		codeBlocks = append(codeBlocks, "\n\n"+MakeSafeCodeFence(clean, "", false)+"\n\n")
		return "@@HNCODE_" + strconv.Itoa(idx) + "@@"
	}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
	s = replacePairedHTMLElementsLinearFullDocGo(s, []string{"code"}, func(_, _, _, c string) string {
		span := formatInlineCodeSpanGo(cleanInlineHTMLFullDocGo(c))
		if span == "" {
			return ""
		}
		idx := len(codeBlocks)
		codeBlocks = append(codeBlocks, span)
		return "@@HNCODE_" + strconv.Itoa(idx) + "@@"
	}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
	s = replacePairedHTMLElementsLinearFullDocGo(s, []string{"a"}, func(_, _, attrStr, inner string) string {
		attrs := parseTagAttrsFullDocGo(attrStr)
		href := resolveHTTPSHrefFullDocGo(attrs["href"], baseURL, true)
		label := cleanInlineHTMLFullDocGo(inner)
		if label == "" {
			return href
		}
		if href != "" {
			dupSuf := " (" + href + ")"
			if len(label) > len(dupSuf) && strings.HasSuffix(label, dupSuf) {
				if stripped := strings.TrimSpace(label[:len(label)-len(dupSuf)]); stripped != "" {
					label = stripped
				}
			}
			return "[" + label + "](" + href + ")"
		}
		return label
	}, maxHTMLScanCharsFullDocGo, 16384)
	s = replacePairedHTMLElementsLinearFullDocGo(s, []string{"i", "em"}, func(_, _, _, inner string) string {
		t := cleanInlineHTMLFullDocGo(inner)
		if t == "" {
			return ""
		}
		return "*" + t + "*"
	}, maxHTMLScanCharsFullDocGo, 16384)
	s = replaceHTMLOpenTagsLinearFullDocGo(s, []string{"p", "br"}, func(t scannedTagFullDocGo) string {
		if t.tagNameLower == "p" {
			return "\n\n"
		}
		return "\n"
	}, maxHTMLScanCharsFullDocGo)
	s = stripHTMLTagsQuoteAwareLinearFullDocGo(s, "", maxHTMLScanCharsFullDocGo)
	s = DecodeHTMLEntities(s)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = reSpaceRun.ReplaceAllString(strings.TrimSpace(l), " ")
	}
	s = collapseExcessBlankLinesGo(strings.TrimSpace(strings.Join(lines, "\n")))
	return reSentinelHnCodeFullDocGo.ReplaceAllStringFunc(s, func(m string) string {
		sub := reSentinelHnCodeFullDocGo.FindStringSubmatch(m)
		if len(sub) >= 2 {
			if idx, err := strconv.Atoi(sub[1]); err == nil && idx >= 0 && idx < len(codeBlocks) {
				return codeBlocks[idx]
			}
		}
		return ""
	})
}

type hnExtractedResultFullDocGo struct {
	title         string
	author        string
	publishedTime string
	markdown      string
	links         []string
}

func extractHNCommentsFromHTMLFullDocGo(afterHeaderHTML, hnBase string) []string {
	if !strings.Contains(afterHeaderHTML, "comtr") {
		return nil
	}
	type comRow struct {
		attrs map[string]string
		inner string
	}
	var comRows []comRow
	comDepth := 0
	comInnerStart := -1
	var comAttrs map[string]string
	scanHTMLTagsLinearFullDocGo(afterHeaderHTML, func(tag scannedTagFullDocGo) bool {
		if tag.tagNameLower != "tr" {
			return true
		}
		if comDepth == 0 {
			if !tag.isClosing && !tag.isSelfClosing && hasClassTokenFullDocGo(tag.attrs, "comtr") {
				parsed := parseTagAttrsFullDocGo(tag.attrs)
				if !hasClassTokenFullDocGo(tag.attrs, "noshow") {
					comDepth = 1
					comInnerStart = tag.end
					comAttrs = parsed
				}
			}
			return true
		}
		if tag.isClosing {
			comDepth--
			if comDepth == 0 {
				if tag.index-comInnerStart <= 32000 {
					comRows = append(comRows, comRow{attrs: comAttrs, inner: afterHeaderHTML[comInnerStart:tag.index]})
					if len(comRows) >= 120 {
						return false
					}
				}
			}
		} else if !tag.isSelfClosing {
			comDepth++
		}
		return true
	}, maxHTMLScanCharsFullDocGo, false)

	var commentItems []string
	seenIDs := make(map[string]bool)
	for _, cr := range comRows {
		cid := cr.attrs["id"]
		if cid != "" {
			if seenIDs[cid] {
				continue
			}
			seenIDs[cid] = true
		}
		rowHTML := cr.inner
		px := 0
		if strings.Contains(rowHTML, "ind") {
			if indInner, _, ok := findFirstClassSubtreeLinearFullDocGo(rowHTML, []string{"td"}, "ind"); ok {
				scanHTMLTagsLinearFullDocGo(indInner, func(t scannedTagFullDocGo) bool {
					if !t.isClosing && t.tagNameLower == "img" {
						if w, err := strconv.Atoi(strings.TrimSpace(parseTagAttrsFullDocGo(t.attrs)["width"])); err == nil {
							px = w
						}
						return false
					}
					return true
				}, 1024, false)
			}
		}
		depth := (px + 20) / 40
		if depth < 0 {
			depth = 0
		} else if depth > 5 {
			depth = 5
		}
		cAuthor := findHNAuthorInFragmentFullDocGo(rowHTML)
		if cAuthor == "" {
			cAuthor = "[deleted]"
		}
		cDate := ""
		if strings.Contains(rowHTML, "age") {
			ageTitle := findSpanAttrInFragmentFullDocGo(rowHTML, "age", "title")
			cDate = strings.Split(ageTitle, "T")[0]
		}
		if !strings.Contains(rowHTML, "commtext") {
			continue
		}
		commInner, _, ok := findFirstClassSubtreeLinearFullDocGo(rowHTML, []string{"div", "span"}, "commtext")
		if !ok || commInner == "" {
			continue
		}
		cBody := hnFragmentToMarkdownFullDocGo(commInner, hnBase)
		if cBody == "" || cBody == "[dead]" || cBody == "[flagged]" {
			continue
		}
		indent := strings.Repeat("  ", depth)
		bodyLines := strings.Split(cBody, "\n")
		for idx := 1; idx < len(bodyLines); idx++ {
			if bodyLines[idx] != "" {
				bodyLines[idx] = indent + "  " + bodyLines[idx]
			}
		}
		header := "**" + cAuthor + "**"
		if cDate != "" {
			header += " *(" + cDate + ")*"
		}
		commentItems = append(commentItems, indent+"- "+header+": "+strings.Join(bodyLines, "\n"))
	}
	return commentItems
}

func extractHackerNewsMarkdownFullDocGo(rawHTML, baseURL string) *hnExtractedResultFullDocGo {
	boundedHTML := truncateUTF8SafeFullDocGo(rawHTML, maxHTMLScanCharsFullDocGo)
	isHNHost := false
	if baseURL != "" {
		if u, err := url.Parse(baseURL); err == nil {
			h := strings.ToLower(u.Hostname())
			isHNHost = h == "news.ycombinator.com" || h == "www.news.ycombinator.com"
		}
	}
	if !isHNHost {
		if !strings.Contains(boundedHTML, "hnmain") && !strings.Contains(boundedHTML, "HNMAIN") {
			return nil
		}
		hasHNMain := false
		scanHTMLTagsLinearFullDocGo(boundedHTML, func(tag scannedTagFullDocGo) bool {
			if !tag.isClosing && tag.tagNameLower == "table" && strings.EqualFold(parseTagAttrsFullDocGo(tag.attrs)["id"], "hnmain") {
				hasHNMain = true
				return false
			}
			return true
		}, maxHTMLScanCharsFullDocGo, false)
		if !hasHNMain {
			return nil
		}
	}

	hnBase := baseURL
	if hnBase == "" {
		hnBase = "https://news.ycombinator.com/"
	}
	var links []string
	seenLinks := make(map[string]bool)
	addLink := func(rawHref string) string {
		r := resolveHTTPSHrefFullDocGo(rawHref, hnBase, false)
		if r != "" && !seenLinks[r] && len(links) < 250 {
			seenLinks[r] = true
			links = append(links, r)
		}
		return r
	}

	// 1. `<table class="fatitem">` item thread page
	if strings.Contains(boundedHTML, "fatitem") {
		if fat, fatEnd, ok := findFirstClassSubtreeLinearFullDocGo(boundedHTML, []string{"table"}, "fatitem"); ok && len(fat) > 0 && len(fat) <= 120000 {
			var titleHref, titleText string
			hasTitleLink := false
			if strings.Contains(fat, "titleline") {
				if tlInner, _, tlOk := findFirstClassSubtreeLinearFullDocGo(fat, []string{"span"}, "titleline"); tlOk {
					titleHref, titleText, hasTitleLink = findFirstAnchorInFragmentFullDocGo(tlInner)
				}
			}
			var onStoryHref, onStoryText string
			hasOnStory := false
			if strings.Contains(fat, "onstory") {
				if osInner, _, osOk := findFirstClassSubtreeLinearFullDocGo(fat, []string{"span"}, "onstory"); osOk {
					onStoryHref, onStoryText, hasOnStory = findFirstAnchorInFragmentFullDocGo(osInner)
				}
			}
			author := findHNAuthorInFragmentFullDocGo(fat)
			rawAgeTitle := ""
			if strings.Contains(fat, "age") {
				rawAgeTitle = findSpanAttrInFragmentFullDocGo(fat, "age", "title")
			}
			rawISO := strings.TrimSpace(strings.Split(rawAgeTitle, " ")[0])
			dateShort := strings.Split(rawISO, "T")[0]
			score := ""
			if strings.Contains(fat, "score") {
				if scInner, _, scOk := findFirstClassSubtreeLinearFullDocGo(fat, []string{"span"}, "score"); scOk {
					score = cleanInlineHTMLFullDocGo(scInner)
				}
			}

			var sections []string
			outTitle := ""
			if hasTitleLink {
				storyURL := addLink(titleHref)
				outTitle = titleText
				if storyURL != "" {
					sections = append(sections, "# ["+outTitle+"]("+storyURL+")")
				} else {
					sections = append(sections, "# "+outTitle)
				}
				var metaBits []string
				if score != "" {
					metaBits = append(metaBits, score)
				}
				if author != "" {
					metaBits = append(metaBits, "by "+author)
				}
				if dateShort != "" {
					metaBits = append(metaBits, dateShort)
				}
				if len(metaBits) > 0 {
					sections = append(sections, "*"+strings.Join(metaBits, " · ")+"*")
				}
				if strings.Contains(fat, "toptext") {
					if topInner, _, topOk := findFirstClassSubtreeLinearFullDocGo(fat, []string{"div"}, "toptext"); topOk && topInner != "" {
						if topMD := hnFragmentToMarkdownFullDocGo(topInner, hnBase); topMD != "" {
							sections = append(sections, topMD)
						}
					}
				}
			} else {
				storyTitle := "Hacker News Thread"
				if hasOnStory && onStoryText != "" {
					storyTitle = onStoryText
				}
				storyHref := ""
				if hasOnStory {
					storyHref = addLink(onStoryHref)
				}
				outTitle = storyTitle
				sections = append(sections, "# "+storyTitle)
				var metaBits []string
				if author != "" {
					metaBits = append(metaBits, "Comment by **"+author+"**")
				}
				if dateShort != "" {
					metaBits = append(metaBits, dateShort)
				}
				if storyHref != "" {
					metaBits = append(metaBits, "on ["+storyTitle+"]("+storyHref+")")
				}
				if len(metaBits) > 0 {
					sections = append(sections, strings.Join(metaBits, " · "))
				}
				if strings.Contains(fat, "commtext") {
					if commInner, _, cmOk := findFirstClassSubtreeLinearFullDocGo(fat, []string{"div", "span"}, "commtext"); cmOk && commInner != "" {
						if bodyMD := hnFragmentToMarkdownFullDocGo(commInner, hnBase); bodyMD != "" {
							sections = append(sections, bodyMD)
						}
					}
				}
			}

			commentItems := extractHNCommentsFromHTMLFullDocGo(boundedHTML[fatEnd:], hnBase)
			if len(commentItems) > 0 {
				sections = append(sections, "## Comments\n\n"+strings.Join(commentItems, "\n\n"))
			}
			md := strings.TrimSpace(strings.Join(sections, "\n\n"))
			if len(md) >= 24 {
				return &hnExtractedResultFullDocGo{
					title: outTitle, author: author, publishedTime: rawISO, markdown: md, links: links,
				}
			}
		}
	}

	// 2. Direct `<table id="hnmain">` `<tr class="athing submission">` + `<tr class="athing comtr">` thread OR story listing page
	if strings.Contains(boundedHTML, "athing") {
		type trItem struct {
			attrs  string
			inner  string
			endIdx int
		}
		var trList []trItem
		trDepth := 0
		trStart := -1
		trAttrStr := ""
		scanHTMLTagsLinearFullDocGo(boundedHTML, func(tag scannedTagFullDocGo) bool {
			if tag.tagNameLower != "tr" {
				return true
			}
			if trDepth == 0 {
				if !tag.isClosing && !tag.isSelfClosing {
					trDepth = 1
					trStart = tag.end
					trAttrStr = tag.attrs
				}
				return true
			}
			if tag.isClosing {
				trDepth--
				if trDepth == 0 {
					if tag.index-trStart <= 16000 {
						trList = append(trList, trItem{attrs: trAttrStr, inner: boundedHTML[trStart:tag.index], endIdx: tag.end})
						if len(trList) >= 300 {
							return false
						}
					}
				}
			} else if !tag.isSelfClosing {
				trDepth++
			}
			return true
		}, maxHTMLScanCharsFullDocGo, false)

		// Check single submission + comment tree layout (e.g. `bench/run-bench.mjs` HN fixture)
		if strings.Contains(boundedHTML, "comtr") && len(trList) >= 2 &&
			hasClassTokenFullDocGo(trList[0].attrs, "athing") && !hasClassTokenFullDocGo(trList[0].attrs, "comtr") &&
			!hasClassTokenFullDocGo(trList[1].attrs, "athing") {
			if tlInner, _, tlOk := findFirstClassSubtreeLinearFullDocGo(trList[0].inner, []string{"span"}, "titleline"); tlOk {
				if tHref, tText, aOk := findFirstAnchorInFragmentFullDocGo(tlInner); aOk && tText != "" {
					storyURL := addLink(tHref)
					subHTML := trList[1].inner
					author := findHNAuthorInFragmentFullDocGo(subHTML)
					rawAge := ""
					if strings.Contains(subHTML, "age") {
						rawAge = findSpanAttrInFragmentFullDocGo(subHTML, "age", "title")
					}
					rawISO := strings.TrimSpace(strings.Split(rawAge, " ")[0])
					dateShort := strings.Split(rawISO, "T")[0]
					score := ""
					if strings.Contains(subHTML, "score") {
						if scInner, _, scOk := findFirstClassSubtreeLinearFullDocGo(subHTML, []string{"span"}, "score"); scOk {
							score = cleanInlineHTMLFullDocGo(scInner)
						}
					}
					var sections []string
					if storyURL != "" {
						sections = append(sections, "# ["+tText+"]("+storyURL+")")
					} else {
						sections = append(sections, "# "+tText)
					}
					var metaBits []string
					if score != "" {
						metaBits = append(metaBits, score)
					}
					if author != "" {
						metaBits = append(metaBits, "by "+author)
					}
					if dateShort != "" {
						metaBits = append(metaBits, dateShort)
					}
					if len(metaBits) > 0 {
						sections = append(sections, "*"+strings.Join(metaBits, " · ")+"*")
					}
					commentItems := extractHNCommentsFromHTMLFullDocGo(boundedHTML[trList[1].endIdx:], hnBase)
					if len(commentItems) > 0 {
						sections = append(sections, "## Comments\n\n"+strings.Join(commentItems, "\n\n"))
						return &hnExtractedResultFullDocGo{
							title: tText, author: author, publishedTime: rawISO,
							markdown: strings.Join(sections, "\n\n"), links: links,
						}
					}
				}
			}
		}

		// HN listing page (`news`, `newest`, `ask`, `show`)
		var listingItems []string
		for idx := 0; idx < len(trList); idx++ {
			curTr := trList[idx]
			if !hasClassTokenFullDocGo(curTr.attrs, "athing") || hasClassTokenFullDocGo(curTr.attrs, "comtr") {
				continue
			}
			if idx+1 >= len(trList) || hasClassTokenFullDocGo(trList[idx+1].attrs, "athing") {
				continue
			}
			nextTr := trList[idx+1]
			rowAttrs := parseTagAttrsFullDocGo(curTr.attrs)
			id := rowAttrs["id"]
			var tHref, tText string
			hasAnchor := false
			if strings.Contains(curTr.inner, "titleline") {
				if tlInner, _, tlOk := findFirstClassSubtreeLinearFullDocGo(curTr.inner, []string{"span"}, "titleline"); tlOk {
					tHref, tText, hasAnchor = findFirstAnchorInFragmentFullDocGo(tlInner)
				}
			}
			if !hasAnchor || tText == "" {
				continue
			}
			storyHref := addLink(tHref)
			siteStr := ""
			if strings.Contains(curTr.inner, "sitestr") {
				if sInner, _, sOk := findFirstClassSubtreeLinearFullDocGo(curTr.inner, []string{"span"}, "sitestr"); sOk {
					siteStr = cleanInlineHTMLFullDocGo(sInner)
				}
			}
			subHTML := nextTr.inner
			pts := ""
			if strings.Contains(subHTML, "score") {
				if scInner, _, scOk := findFirstClassSubtreeLinearFullDocGo(subHTML, []string{"span"}, "score"); scOk {
					pts = cleanInlineHTMLFullDocGo(scInner)
				}
			}
			byUser := findHNAuthorInFragmentFullDocGo(subHTML)
			lastAnchorText := ""
			replacePairedHTMLElementsLinearFullDocGo(subHTML, []string{"a"}, func(_, _, _, aInner string) string {
				lastAnchorText = cleanInlineHTMLFullDocGo(aInner)
				return ""
			}, 8000, 500)
			commentsPart := ""
			lowLast := strings.ToLower(lastAnchorText)
			if id != "" && (strings.Contains(lowLast, "comment") || strings.Contains(lowLast, "discuss")) {
				cLink := addLink("https://news.ycombinator.com/item?id=" + id)
				commentsPart = "[" + lastAnchorText + "](" + cLink + ")"
			}
			var metaParts []string
			if pts != "" {
				metaParts = append(metaParts, pts)
			}
			if byUser != "" {
				metaParts = append(metaParts, "by "+byUser)
			}
			if commentsPart != "" {
				metaParts = append(metaParts, commentsPart)
			}
			meta := strings.Join(metaParts, " · ")
			head := "**" + tText + "**"
			if storyHref != "" {
				head = "**[" + tText + "](" + storyHref + ")**"
			}
			line := strconv.Itoa(len(listingItems)+1) + ". " + head
			if siteStr != "" {
				line += " *(" + siteStr + ")*"
			}
			if meta != "" {
				line += " — " + meta
			}
			listingItems = append(listingItems, line)
			idx++
			if len(listingItems) >= 60 {
				break
			}
		}
		if len(listingItems) >= 2 {
			return &hnExtractedResultFullDocGo{
				title:    "Hacker News",
				markdown: "# Hacker News\n\n" + strings.Join(listingItems, "\n"),
				links:    links,
			}
		}
	}
	return nil
}

func normalizeLatexSourceFullDocGo(rawTex string) string {
	tex := strings.TrimSpace(DecodeHTMLEntities(rawTex))
	if m := reWikiDisplayStyleFullDocGo.FindStringSubmatch(tex); len(m) >= 2 {
		tex = strings.TrimSpace(m[1])
	}
	return tex
}

func mapCalloutTypeToGFMFullDocGo(rawType string) string {
	switch strings.ToLower(strings.TrimSpace(rawType)) {
	case "tip", "hint", "success":
		return "TIP"
	case "important":
		return "IMPORTANT"
	case "warning", "warn", "attention":
		return "WARNING"
	case "caution", "danger", "error", "bug", "failure":
		return "CAUTION"
	default:
		return "NOTE"
	}
}

func convertCalloutsLinearFullDocGo(rawHTML string, stashInline func(string) string) string {
	low := asciiLowerExtractString(rawHTML)
	if !strings.Contains(low, "markdown-alert-") &&
		!strings.Contains(low, "admonition") &&
		!strings.Contains(low, "starlight-aside--") &&
		!strings.Contains(low, "data-callout") &&
		!strings.Contains(low, "custom-block") {
		return rawHTML
	}

	var chunks []string
	lastIdx := 0
	matchTag := ""
	matchAttr := ""
	innerStart := 0
	depth := 0

	scanHTMLTagsLinearFullDocGo(rawHTML, func(tag scannedTagFullDocGo) bool {
		if tag.tagNameLower != "div" && tag.tagNameLower != "aside" {
			return true
		}
		if depth == 0 {
			if tag.isClosing || tag.isSelfClosing {
				return true
			}
			lowAttr := asciiLowerExtractString(tag.attrs)
			if !strings.Contains(lowAttr, "markdown-alert-") &&
				!strings.Contains(lowAttr, "admonition") &&
				!strings.Contains(lowAttr, "starlight-aside--") &&
				!strings.Contains(lowAttr, "data-callout") &&
				!strings.Contains(lowAttr, "custom-block") {
				return true
			}
			attrs := parseTagAttrsFullDocGo(tag.attrs)
			cls := strings.ToLower(attrs["class"])
			isCallout := attrs["data-callout"] != "" ||
				strings.Contains(cls, "markdown-alert-") ||
				strings.Contains(cls, "admonition") ||
				strings.Contains(cls, "starlight-aside--") ||
				hasClassTokenFullDocGo(tag.attrs, "custom-block")
			if !isCallout {
				return true
			}
			matchTag = tag.tagNameLower
			matchAttr = tag.attrs
			innerStart = tag.end
			chunks = append(chunks, rawHTML[lastIdx:tag.index])
			lastIdx = tag.index
			depth = 1
			return true
		}
		if tag.tagNameLower != matchTag {
			return true
		}
		if tag.isClosing {
			depth--
			if depth == 0 {
				inner := rawHTML[innerStart:tag.index]
				if len(inner) <= 12000 {
					attrs := parseTagAttrsFullDocGo(matchAttr)
					cls := strings.ToLower(attrs["class"])
					rawType := attrs["data-callout"]
					if rawType == "" {
						if m := reCalloutClassTypeFullDocGo.FindStringSubmatch(cls); len(m) >= 5 {
							for _, grp := range m[1:5] {
								if grp != "" {
									rawType = grp
									break
								}
							}
						}
					}
					if rawType == "" {
						rawType = "note"
					}
					gfmType := mapCalloutTypeToGFMFullDocGo(rawType)
					customTitle := ""
					bodyWithoutTitle := reCalloutTitleElemFullDocGo.ReplaceAllStringFunc(inner, func(tm string) string {
						sub := reCalloutTitleElemFullDocGo.FindStringSubmatch(tm)
						if len(sub) >= 3 {
							cand := cleanInlineHTMLFullDocGo(sub[2])
							if cand != "" && !strings.EqualFold(cand, rawType) && !strings.EqualFold(cand, gfmType) {
								customTitle = cand
							}
						}
						return ""
					})
					withCode := bodyWithoutTitle
					if stashInline != nil && strings.Contains(asciiLowerExtractString(withCode), "<code") {
						withCode = replacePairedHTMLElementsLinearFullDocGo(withCode, []string{"code"}, func(_, _, _, cInner string) string {
							return stashInline(formatInlineCodeSpanGo(cleanInlineHTMLFullDocGo(cInner)))
						}, 12000, 4000)
					}
					bodyText := cleanInlineHTMLFullDocGo(withCode)
					if bodyText != "" {
						titleSuffix := ""
						if customTitle != "" {
							titleSuffix = " " + customTitle
						}
						chunks = append(chunks, "\n\n> [!"+gfmType+"]"+titleSuffix+"\n> "+bodyText+"\n\n")
						lastIdx = tag.end
						return true
					}
				}
				chunks = append(chunks, rawHTML[lastIdx:tag.end])
				lastIdx = tag.end
			}
		} else if !tag.isSelfClosing {
			depth++
		}
		return true
	}, maxHTMLScanCharsFullDocGo, false)

	if len(chunks) == 0 {
		return rawHTML
	}
	if lastIdx < len(rawHTML) {
		chunks = append(chunks, rawHTML[lastIdx:])
	}
	return strings.Join(chunks, "")
}

func standardizeElementsInHTMLFullDocGo(rawHTML string, stashCode func(string) string, stashInline func(string) string) string {
	out := rawHTML
	lowOut := asciiLowerExtractString(out)

	// 1. Strip pure line-number gutter cells in 2-column code tables, then unwrap 1x1 `<pre>` layout tables.
	if strings.Contains(lowOut, "lntd") || strings.Contains(lowOut, "gutter") ||
		strings.Contains(lowOut, "hljs-ln-numbers") || strings.Contains(lowOut, "blob-num") {
		out = replacePairedHTMLElementsLinearFullDocGo(out, []string{"td"}, func(full, _, attrStr, inner string) string {
			if !hasClassTokenFullDocGo(attrStr, "lntd") &&
				!hasClassTokenFullDocGo(attrStr, "gutter") &&
				!hasClassTokenFullDocGo(attrStr, "hljs-ln-numbers") &&
				!hasClassTokenFullDocGo(attrStr, "blob-num") {
				return full
			}
			plain := strings.TrimSpace(stripHTMLTagsQuoteAwareLinearFullDocGo(inner, "", 12000))
			if plain == "" {
				return full
			}
			for i := 0; i < len(plain); i++ {
				c := plain[i]
				if !((c >= '0' && c <= '9') || isASCIIWhitespaceByte(c)) {
					return full
				}
			}
			return ""
		}, maxHTMLScanCharsFullDocGo, 12000)

		out = replacePairedHTMLElementsLinearFullDocGo(out, []string{"table"}, func(full, _, _, inner string) string {
			if !strings.Contains(asciiLowerExtractString(inner), "<pre") {
				return full
			}
			strippedLayout := strings.TrimSpace(replaceHTMLTagsQuoteAwareLinearFullDocGo(inner, func(t scannedTagFullDocGo) string {
				if t.tagNameLower == "tbody" || t.tagNameLower == "tr" || t.tagNameLower == "td" {
					return ""
				}
				return t.rawTag
			}, 65536, false))
			lowLayout := asciiLowerExtractString(strippedLayout)
			if strings.HasPrefix(lowLayout, "<pre") && strings.HasSuffix(lowLayout, "</pre>") {
				return "\n\n" + strippedLayout + "\n\n"
			}
			return full
		}, maxHTMLScanCharsFullDocGo, 65536)
	}

	// 2. Propagate Sphinx / ReadTheDocs two-level `<div class="highlight-{lang}"><div class="highlight"><pre>`.
	if strings.Contains(out, "highlight-") {
		out = reSphinxPreFullDocGo.ReplaceAllStringFunc(out, func(full string) string {
			sub := reSphinxPreFullDocGo.FindStringSubmatch(full)
			if len(sub) < 3 || !hasClassTokenFullDocGo(sub[2], "highlight") {
				return full
			}
			lm := reSphinxOuterLangFullDocGo.FindStringSubmatch(sub[1])
			if len(lm) < 2 || strings.HasPrefix(strings.ToLower(lm[1]), "source-") {
				return full
			}
			norm := normalizeFenceLangFullDocGo(lm[1])
			if norm == "" {
				return full
			}
			return "<div" + sub[1] + "><div" + sub[2] + `><pre data-wrapper-lang="` + norm + `"`
		})
	}

	// 3. Convert GitHub / Sphinx `<div class="highlight ..."><pre>...</pre></div>` linearly.
	if strings.Contains(asciiLowerExtractString(out), "highlight") {
		src := out
		lowerSrc := asciiLowerExtractString(src)
		var chunks []string
		lastCopied := 0
		scanHTMLTagsLinearFullDocGo(src, func(tag scannedTagFullDocGo) bool {
			if tag.index < lastCopied || tag.isClosing || tag.isSelfClosing || tag.tagNameLower != "div" {
				return true
			}
			if !strings.Contains(asciiLowerExtractString(tag.attrs), "highlight") || !hasClassTokenFullDocGo(tag.attrs, "highlight") {
				return true
			}
			divAttrs := parseTagAttrsFullDocGo(tag.attrs)
			afterDiv := tag.end
			for afterDiv < len(src) && isASCIIWhitespaceByte(src[afterDiv]) {
				afterDiv++
			}
			if afterDiv+4 > len(src) || lowerSrc[afterDiv:afterDiv+4] != "<pre" ||
				(afterDiv+4 < len(src) && !isTagNameBoundaryByteFullDocGo(src[afterDiv+4])) {
				return true
			}
			relGt := strings.IndexByte(src[afterDiv+4:], '>')
			if relGt < 0 || relGt > 800 {
				return true
			}
			preOpenGt := afterDiv + 4 + relGt
			preAttrStr := src[afterDiv+4 : preOpenGt]
			relClose := strings.Index(lowerSrc[preOpenGt+1:], "</pre>")
			if relClose < 0 || relClose > 100000 {
				return true
			}
			preCloseIdx := preOpenGt + 1 + relClose
			afterPre := preCloseIdx + 6
			for afterPre < len(src) && isASCIIWhitespaceByte(src[afterPre]) {
				afterPre++
			}
			if afterPre+6 > len(src) || lowerSrc[afterPre:afterPre+6] != "</div>" {
				return true
			}
			preInner := src[preOpenGt+1 : preCloseIdx]
			lang := inferCodeFenceLangFullDocGo(tag.attrs, preAttrStr)
			rawClip := divAttrs["data-snippet-clipboard-copy-content"]
			var codeText string
			if strings.TrimSpace(rawClip) != "" {
				codeText = rawClip
			} else {
				codeText = DecodeHTMLEntities(stripHTMLTagsQuoteAwareLinearFullDocGo(preInner, "", 100000))
			}
			block := "\n\n" + MakeSafeCodeFence(strings.TrimSpace(codeText), lang, false) + "\n\n"
			chunks = append(chunks, src[lastCopied:tag.index])
			if stashCode != nil {
				chunks = append(chunks, stashCode(block))
			} else {
				chunks = append(chunks, block)
			}
			lastCopied = afterPre + 6
			return true
		}, maxHTMLScanCharsFullDocGo, false)
		if len(chunks) > 0 {
			chunks = append(chunks, src[lastCopied:])
			out = strings.Join(chunks, "")
		}
	}

	// 4. GFM task-list checkboxes (`<input type="checkbox" checked>`).
	if strings.Contains(asciiLowerExtractString(out), "<input") {
		out = replaceHTMLOpenTagsLinearFullDocGo(out, []string{"input"}, func(tag scannedTagFullDocGo) string {
			attrs := parseTagAttrsFullDocGo(tag.attrs)
			if !strings.EqualFold(strings.TrimSpace(attrs["type"]), "checkbox") {
				return tag.rawTag
			}
			_, hasChecked := attrs["checked"]
			checkedVal := strings.ToLower(strings.TrimSpace(attrs["checked"]))
			if hasChecked && checkedVal != "false" && checkedVal != "0" {
				return "@@EFTASKX@@ "
			}
			return "@@EFTASKO@@ "
		}, maxHTMLScanCharsFullDocGo)
	}

	// 5. HTML footnotes (`<sup id="fnref:1"><a href="#fn:1">1</a></sup>` + `<section id="footnotes"><ol>...</ol></section>`).
	lowFn := asciiLowerExtractString(out)
	if strings.Contains(lowFn, "fnref") || strings.Contains(lowFn, "footnote") {
		out = reSupFootnoteRefFullDocGo.ReplaceAllStringFunc(out, func(full string) string {
			sub := reSupFootnoteRefFullDocGo.FindStringSubmatch(full)
			if len(sub) < 3 {
				return full
			}
			sa := parseTagAttrsFullDocGo(sub[1])
			aa := parseTagAttrsFullDocGo(sub[2])
			rawHref := strings.TrimSpace(aa["href"])
			rawID := ""
			for _, pfx := range []string{"#fn:", "#user-content-fn-", "#footnote-"} {
				if strings.HasPrefix(strings.ToLower(rawHref), pfx) {
					rawID = rawHref[len(pfx):]
					break
				}
			}
			if rawID == "" {
				supID := strings.TrimSpace(sa["id"])
				for _, pfx := range []string{"fnref:", "user-content-fnref-"} {
					if strings.HasPrefix(strings.ToLower(supID), pfx) {
						rawID = supID[len(pfx):]
						break
					}
				}
			}
			if rawID == "" {
				return full
			}
			if dashIdx := strings.LastIndexByte(rawID, '-'); dashIdx > 0 {
				allDigits := true
				for i := dashIdx + 1; i < len(rawID); i++ {
					if rawID[i] < '0' || rawID[i] > '9' {
						allDigits = false
						break
					}
				}
				if allDigits {
					rawID = rawID[:dashIdx]
				}
			}
			var cleanID strings.Builder
			for i := 0; i < len(rawID); i++ {
				c := rawID[i]
				if isASCIIAlnumExtract(c) || c == '_' || c == '-' {
					cleanID.WriteByte(c)
				}
			}
			if cleanID.Len() == 0 {
				return full
			}
			return "[^" + cleanID.String() + "]"
		})

		out = replacePairedHTMLElementsLinearFullDocGo(out, []string{"section", "div"}, func(full, _, attrStr, inner string) string {
			attrs := parseTagAttrsFullDocGo(attrStr)
			hay := strings.ToLower(attrs["id"] + " " + attrs["class"])
			if !strings.Contains(hay, "footnote") || !strings.Contains(asciiLowerExtractString(inner), "<ol") {
				return full
			}
			var defs []string
			replacePairedHTMLElementsLinearFullDocGo(inner, []string{"li"}, func(_, _, liAttrs, liInner string) string {
				la := parseTagAttrsFullDocGo(liAttrs)
				liID := strings.TrimSpace(la["id"])
				rawID := ""
				for _, pfx := range []string{"fn:", "user-content-fn-", "footnote-"} {
					if strings.HasPrefix(strings.ToLower(liID), pfx) {
						rawID = liID[len(pfx):]
						break
					}
				}
				var cleanID strings.Builder
				for i := 0; i < len(rawID); i++ {
					c := rawID[i]
					if isASCIIAlnumExtract(c) || c == '_' || c == '-' {
						cleanID.WriteByte(c)
					}
				}
				idStr := cleanID.String()
				if idStr == "" {
					idStr = strconv.Itoa(len(defs) + 1)
				}
				withoutBackref := reFootnoteBackrefFullDocGo.ReplaceAllString(liInner, "")
				cleanedLi := strings.TrimRight(cleanInlineHTMLFullDocGo(withoutBackref), " \t\u21a9\uFE0E")
				if cleanedLi != "" {
					defs = append(defs, "[^"+idStr+"]: "+cleanedLi)
				}
				return ""
			}, 40000, 4000)
			if len(defs) > 0 {
				return "\n\n" + strings.Join(defs, "\n") + "\n\n"
			}
			return full
		}, maxHTMLScanCharsFullDocGo, 45000)
	}

	// 6. Propagate VitePress / Docusaurus / Prism wrapper `<div class="... language-ts ...">` onto `<pre>`.
	if reVitePressLangFullDocGo.MatchString(out) {
		out = reVitePressPreFullDocGo.ReplaceAllStringFunc(out, func(full string) string {
			sub := reVitePressPreFullDocGo.FindStringSubmatch(full)
			if len(sub) < 3 {
				return full
			}
			lm := reVitePressLangFullDocGo.FindStringSubmatch(sub[1])
			if len(lm) < 2 {
				return full
			}
			cleanedMid := reShortBtnFullDocGo.ReplaceAllString(sub[2], "")
			cleanedMid = reShortLangSpanFullDocGo.ReplaceAllString(cleanedMid, "")
			return "<div" + sub[1] + ">" + cleanedMid + `<pre data-wrapper-lang="` + lm[1] + `"`
		})
	}

	// 7. Strip MediaWiki visual math fallback `<img>` tags.
	if strings.Contains(out, "mwe-math-fallback-image") {
		out = replaceHTMLOpenTagsLinearFullDocGo(out, []string{"img"}, func(tag scannedTagFullDocGo) string {
			if strings.Contains(tag.attrs, "mwe-math-fallback-image") {
				return ""
			}
			return tag.rawTag
		}, maxHTMLScanCharsFullDocGo)
	}

	// 8. Mark `<math>` inside `.katex-display` or `.MathJax_Display` as block display.
	lowMathDisp := asciiLowerExtractString(out)
	if strings.Contains(lowMathDisp, "katex-display") || strings.Contains(lowMathDisp, "mathjax_display") {
		out = replacePairedHTMLElementsLinearFullDocGo(out, []string{"span", "div"}, func(full, _, attrStr, _ string) string {
			if !hasClassTokenFullDocGo(attrStr, "katex-display") && !hasClassTokenFullDocGo(attrStr, "mathjax_display") {
				return full
			}
			lowFull := asciiLowerExtractString(full)
			mIdx := strings.Index(lowFull, "<math")
			if mIdx < 0 || (mIdx+5 < len(full) && !isTagNameBoundaryByteFullDocGo(full[mIdx+5])) {
				return full
			}
			return full[:mIdx] + `<math data-ef-display="block"` + full[mIdx+5:]
		}, maxHTMLScanCharsFullDocGo, 16000)
	}

	// 9. Convert `<math>` (KaTeX `<annotation encoding="application/x-tex">`, MathML `alttext`, or Parsoid `data-mw`) to LaTeX.
	if strings.Contains(asciiLowerExtractString(out), "<math") {
		out = replacePairedHTMLElementsLinearFullDocGo(out, []string{"math"}, func(full, _, attrStr, inner string) string {
			attrs := parseTagAttrsFullDocGo(attrStr)
			annotTex := ""
			hasAnnot := false
			replacePairedHTMLElementsLinearFullDocGo(inner, []string{"annotation"}, func(_, _, aAttr, aInner string) string {
				if !hasAnnot {
					aParsed := parseTagAttrsFullDocGo(aAttr)
					if strings.EqualFold(strings.TrimSpace(aParsed["encoding"]), "application/x-tex") {
						annotTex = aInner
						hasAnnot = true
					}
				}
				return ""
			}, 24000, 24000)
			mwExtSrc := ""
			if dm := attrs["data-mw"]; dm != "" && strings.Contains(dm, "extsrc") {
				var parsedMw struct {
					Body struct {
						ExtSrc string `json:"extsrc"`
					} `json:"body"`
				}
				if err := json.Unmarshal([]byte(dm), &parsedMw); err == nil {
					mwExtSrc = parsedMw.Body.ExtSrc
				}
			}
			rawTex := annotTex
			if !hasAnnot {
				for _, cand := range []string{attrs["alttext"], attrs["data-latex"], mwExtSrc} {
					if cand != "" {
						rawTex = cand
						break
					}
				}
			}
			if rawTex == "" {
				return full
			}
			tex := normalizeLatexSourceFullDocGo(rawTex)
			if tex == "" {
				return full
			}
			isBlock := attrs["display"] == "block" || attrs["data-ef-display"] == "block" || strings.Contains(tex, "\n")
			if isBlock {
				return "\n\n$$\n" + tex + "\n$$\n\n"
			}
			return "$" + strings.Join(strings.Fields(tex), " ") + "$"
		}, maxHTMLScanCharsFullDocGo, 24000)
	}

	// 10. Convert MathJax `<mjx-container data-latex="...">`.
	if strings.Contains(asciiLowerExtractString(out), "<mjx-container") {
		out = replacePairedHTMLElementsLinearFullDocGo(out, []string{"mjx-container"}, func(full, _, attrStr, _ string) string {
			attrs := parseTagAttrsFullDocGo(attrStr)
			rawTex := attrs["data-latex"]
			if rawTex == "" {
				rawTex = attrs["data-math"]
			}
			if rawTex == "" {
				return full
			}
			tex := normalizeLatexSourceFullDocGo(rawTex)
			if tex == "" {
				return full
			}
			isBlock := attrs["display"] == "true" || attrs["display"] == "block"
			if isBlock {
				return "\n\n$$\n" + tex + "\n$$\n\n"
			}
			return "$" + strings.Join(strings.Fields(tex), " ") + "$"
		}, maxHTMLScanCharsFullDocGo, 12000)
	}

	// 11. Convert VitePress, Docusaurus, Starlight, Obsidian, and GitHub callouts (`> [!WARNING]`, `> [!NOTE]`, `> [!TIP]`).
	out = convertCalloutsLinearFullDocGo(out, stashInline)

	// 12. Upgrade `<picture><source srcset="..."><img></picture>` to highest-resolution image candidate.
	if strings.Contains(asciiLowerExtractString(out), "<picture") {
		out = replacePairedHTMLElementsLinearFullDocGo(out, []string{"picture"}, func(full, _, _, inner string) string {
			bestSrc := ""
			scanHTMLTagsLinearFullDocGo(inner, func(tag scannedTagFullDocGo) bool {
				if !tag.isClosing && tag.tagNameLower == "source" {
					sAttrs := parseTagAttrsFullDocGo(tag.attrs)
					srcsetVal := sAttrs["srcset"]
					if srcsetVal == "" {
						srcsetVal = sAttrs["data-srcset"]
					}
					if cand := ExtractLargestURLFromSrcset(srcsetVal); cand != "" {
						bestSrc = cand
						return false
					}
				}
				return true
			}, 8000, false)
			if bestSrc == "" {
				return full
			}
			replacedImg := false
			return replaceHTMLOpenTagsLinearFullDocGo(inner, []string{"img"}, func(imgTag scannedTagFullDocGo) string {
				if replacedImg {
					return imgTag.rawTag
				}
				replacedImg = true
				imgAttrs := parseTagAttrsFullDocGo(imgTag.attrs)
				if imgAttrs["src"] != "" && !isLazyPlaceholderImageURLFullDocGo(imgAttrs["src"]) {
					return imgTag.rawTag
				}
				safeSrc := strings.ReplaceAll(bestSrc, `"`, "%22")
				return `<img src="` + safeSrc + `" ` + imgTag.attrs + `>`
			}, 8000)
		}, maxHTMLScanCharsFullDocGo, 8000)
	}

	return out
}

func pruneHighLinkDensityBlocksFullDocGo(rawHTML string) string {
	beforeWords := countTextWordsFullDocGo(stripHTMLTagsQuoteAwareLinearFullDocGo(rawHTML, " ", maxHTMLScanCharsFullDocGo))
	if beforeWords < 140 {
		return rawHTML
	}
	candidate := replacePairedHTMLElementsLinearFullDocGo(rawHTML, []string{"div", "section", "ul"}, func(full, tag, attrStr, inner string) string {
		lowInner := asciiLowerExtractString(inner)
		if strings.Contains(lowInner, "<pre") || strings.Contains(lowInner, "<code") ||
			strings.Contains(lowInner, "<table") || strings.Contains(lowInner, "<h1") ||
			strings.Contains(lowInner, "<article") || strings.Contains(lowInner, "<figure") ||
			strings.Contains(lowInner, "<math") || strings.Contains(lowInner, "<"+tag) {
			return full
		}
		type aPair struct{ attrs, inner string }
		var anchors []aPair
		replacePairedHTMLElementsLinearFullDocGo(inner, []string{"a"}, func(_, _, aAttrs, aInner string) string {
			anchors = append(anchors, aPair{aAttrs, aInner})
			return ""
		}, 12000, 4000)
		if len(anchors) < 5 {
			return full
		}
		totalText := cleanInlineHTMLFullDocGo(inner)
		words := countTextWordsFullDocGo(totalText)
		if words == 0 || words >= 95 {
			return full
		}
		anchorTextLen := 0
		hashOnly := 0
		for _, am := range anchors {
			aAttrs := parseTagAttrsFullDocGo(am.attrs)
			if strings.HasPrefix(strings.TrimSpace(aAttrs["href"]), "#") {
				hashOnly++
			}
			anchorTextLen += len(cleanInlineHTMLFullDocGo(am.inner))
		}
		denom := len(totalText)
		if denom < 1 {
			denom = 1
		}
		if float64(anchorTextLen)/float64(denom) < 0.8 {
			return full
		}
		isSamePageToc := hashOnly >= 4 && hashOnly == len(anchors)
		attrs := parseTagAttrsFullDocGo(attrStr)
		hasClutter := reClutterAttrFullDocGo.MatchString(attrs["class"] + " " + attrs["id"])
		if isSamePageToc || (hasClutter && tag != "article") {
			return ""
		}
		return full
	}, maxHTMLScanCharsFullDocGo, 12000)

	if candidate == rawHTML {
		return rawHTML
	}
	afterWords := countTextWordsFullDocGo(stripHTMLTagsQuoteAwareLinearFullDocGo(candidate, " ", maxHTMLScanCharsFullDocGo))
	if float64(afterWords) >= float64(beforeWords)*0.55 {
		return candidate
	}
	return rawHTML
}

func cleanGitHubIssueOrPRMarkdownFullDocGo(md string) string {
	out := reGitHubDupH2FullDocGo.ReplaceAllString(md, "$1")
	low := asciiLowerExtractString(out)
	if idx := strings.Index(low, "[sign up for free](https://github.com/join"); idx >= 0 {
		out = out[:idx]
	}
	low2 := asciiLowerExtractString(out)
	if idx := strings.Index(low2, "\n### reviewers"); idx >= 0 {
		out = out[:idx]
	}
	return strings.TrimSpace(out)
}

func cleanArxivAbstractMarkdownFullDocGo(md string) string {
	out := reArxivBreadcrumbFullDocGo.ReplaceAllString(md, "")
	out = reArxivTitlePrefixFullDocGo.ReplaceAllString(out, "# ")
	out = reArxivFooterFullDocGo.ReplaceAllString(out, "")
	return strings.TrimSpace(out)
}

func extractBalancedDivAtFullDocGo(src string, openStart int) (string, bool) {
	depth := 0
	innerStart := -1
	var inner string
	found := false
	scanHTMLTagsLinearFullDocGo(src[openStart:], func(tag scannedTagFullDocGo) bool {
		if tag.tagNameLower != "div" {
			return true
		}
		if !tag.isClosing && !tag.isSelfClosing {
			depth++
			if depth == 1 {
				innerStart = tag.end
			}
			return true
		}
		if tag.isClosing && depth > 0 {
			depth--
			if depth == 0 {
				inner = src[openStart+innerStart : openStart+tag.index]
				found = true
				return false
			}
		}
		return true
	}, maxHTMLScanCharsFullDocGo, false)
	return inner, found
}

func extractStackExchangeHTMLFullDocGo(rawHTML, baseURL string, includeImages bool) (title, md string, ok bool) {
	cleanHTML := stripHTMLTagsLinearFullDocGo(rawHTML, []string{"script", "style", "noscript", "svg"}, "", maxHTMLScanCharsFullDocGo)
	qHeaderIdx := -1
	qOpenIdx := -1
	qOpenAttrs := ""
	type ansOpen struct {
		idx   int
		attrs string
	}
	var ansOpens []ansOpen

	scanHTMLTagsLinearFullDocGo(cleanHTML, func(tag scannedTagFullDocGo) bool {
		if tag.isClosing || tag.isSelfClosing || tag.tagNameLower != "div" {
			return true
		}
		attrs := parseTagAttrsFullDocGo(tag.attrs)
		id := strings.TrimSpace(attrs["id"])
		lowID := strings.ToLower(id)
		if lowID == "question-header" && qHeaderIdx < 0 {
			qHeaderIdx = tag.index
		} else if lowID == "question" && qOpenIdx < 0 {
			qOpenIdx = tag.index
			qOpenAttrs = tag.attrs
		} else if strings.HasPrefix(lowID, "answer-") && len(ansOpens) < 12 {
			allDigits := len(lowID) > 7
			for i := 7; i < len(lowID); i++ {
				if lowID[i] < '0' || lowID[i] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				ansOpens = append(ansOpens, ansOpen{idx: tag.index, attrs: tag.attrs})
			}
		}
		return true
	}, maxHTMLScanCharsFullDocGo, false)

	if qOpenIdx < 0 {
		return "", "", false
	}
	h1Source := cleanHTML
	if qHeaderIdx >= 0 {
		if qhInner, qhOk := extractBalancedDivAtFullDocGo(cleanHTML, qHeaderIdx); qhOk {
			h1Source = qhInner
		}
	}
	rawH1 := ""
	replacePairedHTMLElementsLinearFullDocGo(h1Source, []string{"h1"}, func(_, _, _, hInner string) string {
		if rawH1 == "" {
			rawH1 = cleanInlineHTMLFullDocGo(hInner)
		}
		return ""
	}, 65536, 4096)
	rawH1 = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(rawH1, "[duplicate]"), "[closed]"))
	if rawH1 == "" {
		return "", "", false
	}
	qInner, qOk := extractBalancedDivAtFullDocGo(cleanHTML, qOpenIdx)
	if !qOk {
		return "", "", false
	}

	extractPostBody := func(block string) string {
		bodyIdx := -1
		scanHTMLTagsLinearFullDocGo(block, func(t scannedTagFullDocGo) bool {
			if !t.isClosing && !t.isSelfClosing && t.tagNameLower == "div" {
				if hasClassTokenFullDocGo(t.attrs, "s-prose") ||
					hasClassTokenFullDocGo(t.attrs, "js-post-body") ||
					hasClassTokenFullDocGo(t.attrs, "post-text") {
					bodyIdx = t.index
					return false
				}
			}
			return true
		}, len(block), false)
		if bodyIdx < 0 {
			return ""
		}
		inner, bOk := extractBalancedDivAtFullDocGo(block, bodyIdx)
		if !bOk || strings.TrimSpace(inner) == "" {
			return ""
		}
		sub := ExtractHTMLDocumentFull(inner, FullExtractOptions{
			BaseURL:         baseURL,
			OnlyMainContent: false,
			IncludeImages:   includeImages,
		})
		return strings.TrimSpace(sub.Markdown)
	}

	extractComments := func(block string) []string {
		var out []string
		replacePairedHTMLElementsLinearFullDocGo(block, []string{"span"}, func(_, _, attrStr, sInner string) string {
			if len(out) < 6 && hasClassTokenFullDocGo(attrStr, "comment-copy") {
				if txt := cleanInlineHTMLFullDocGo(sInner); txt != "" {
					out = append(out, "> - *Comment*: "+txt)
				}
			}
			return ""
		}, len(block), 4096)
		return out
	}

	qMd := extractPostBody(qInner)
	if qMd == "" {
		return "", "", false
	}
	qScore := strings.TrimSpace(parseTagAttrsFullDocGo(qOpenAttrs)["data-score"])
	if qScore == "" {
		if vcInner, _, vcOk := findFirstClassSubtreeLinearFullDocGo(qInner, []string{"div"}, "js-vote-count"); vcOk {
			qScore = cleanInlineHTMLFullDocGo(vcInner)
		}
	}
	var tags []string
	seenTags := make(map[string]bool)
	replacePairedHTMLElementsLinearFullDocGo(qInner, []string{"a"}, func(_, _, attrStr, aInner string) string {
		if len(tags) < 8 && hasClassTokenFullDocGo(attrStr, "post-tag") {
			if t := cleanInlineHTMLFullDocGo(aInner); t != "" && !seenTags[t] {
				seenTags[t] = true
				tags = append(tags, "`"+t+"`")
			}
		}
		return ""
	}, len(qInner), 512)

	sections := []string{"# " + rawH1}
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
	if qComs := extractComments(qInner); len(qComs) > 0 {
		sections = append(sections, strings.Join(qComs, "\n"))
	}

	type seAns struct {
		accepted bool
		score    int
		md       string
		comments []string
	}
	var answers []seAns
	for _, ao := range ansOpens {
		aInner, aOk := extractBalancedDivAtFullDocGo(cleanHTML, ao.idx)
		if !aOk {
			continue
		}
		headCheck := aInner
		if len(headCheck) > 2000 {
			headCheck = headCheck[:2000]
		}
		accepted := hasClassTokenFullDocGo(ao.attrs, "accepted-answer") ||
			hasClassTokenFullDocGo(ao.attrs, "js-accepted-answer") ||
			strings.Contains(asciiLowerExtractString(headCheck), "js-accepted-answer-indicator")
		scoreRaw := strings.TrimSpace(parseTagAttrsFullDocGo(ao.attrs)["data-score"])
		if scoreRaw == "" {
			if vcInner, _, vcOk := findFirstClassSubtreeLinearFullDocGo(aInner, []string{"div"}, "js-vote-count"); vcOk {
				scoreRaw = cleanInlineHTMLFullDocGo(vcInner)
			}
		}
		score, _ := strconv.Atoi(scoreRaw)
		aMd := extractPostBody(aInner)
		if aMd == "" {
			continue
		}
		answers = append(answers, seAns{accepted: accepted, score: score, md: aMd, comments: extractComments(aInner)})
	}

	sort.SliceStable(answers, func(i, j int) bool {
		if answers[i].accepted != answers[j].accepted {
			return answers[i].accepted
		}
		return answers[i].score > answers[j].score
	})
	limit := len(answers)
	if limit > 8 {
		limit = 8
	}
	for i := 0; i < limit; i++ {
		a := answers[i]
		var heading string
		if a.accepted {
			heading = "## \u2705 Accepted Answer (Score: " + strconv.Itoa(a.score) + ")"
		} else {
			heading = "## Answer " + strconv.Itoa(i+1) + " (Score: " + strconv.Itoa(a.score) + ")"
		}
		sections = append(sections, heading+"\n\n"+a.md)
		if len(a.comments) > 0 {
			sections = append(sections, strings.Join(a.comments, "\n"))
		}
	}
	return rawH1, strings.Join(sections, "\n\n"), true
}

func extractIETFRfcFullDocGo(rawHTML, currentMD, docTitle string) (string, bool) {
	var preBlocks []string
	if strings.Contains(asciiLowerExtractString(rawHTML), "newpage") {
		replacePairedHTMLElementsLinearFullDocGo(rawHTML, []string{"pre"}, func(_, _, attrStr, inner string) string {
			if len(preBlocks) < 400 && hasClassTokenFullDocGo(attrStr, "newpage") {
				preBlocks = append(preBlocks, DecodeHTMLEntities(stripHTMLTagsQuoteAwareLinearFullDocGo(inner, "", 65536)))
			}
			return ""
		}, maxHTMLScanCharsFullDocGo, 65536)
	}
	sourceText := currentMD
	if len(preBlocks) > 0 {
		sourceText = strings.Join(preBlocks, "\n")
	}
	if len(strings.TrimSpace(sourceText)) < 80 {
		return "", false
	}
	norm := strings.ReplaceAll(strings.ReplaceAll(sourceText, "\r\n", "\n"), "\f", "\n")
	var cleanedLines []string
	for _, rawLine := range strings.Split(norm, "\n") {
		rTrim := strings.TrimRight(rawLine, " \t\r")
		if reRfcPageFooterFullDocGo.MatchString(rTrim) {
			continue
		}
		fullTrim := strings.TrimLeft(rTrim, " \t")
		if strings.HasPrefix(fullTrim, "RFC ") && strings.Contains(fullTrim, "  ") && reRfcRunningHeaderFullDocGo.MatchString(fullTrim) {
			continue
		}
		if rawLine == fullTrim {
			if m := reRfcSectionHeadingFullDocGo.FindStringSubmatch(fullTrim); len(m) >= 3 {
				depth := strings.Count(m[1], ".") + 2
				if depth > 4 {
					depth = 4
				}
				cleanedLines = append(cleanedLines, "\n"+strings.Repeat("#", depth)+" "+m[1]+". "+m[2]+"\n")
				continue
			}
		}
		cleanedLines = append(cleanedLines, rawLine)
	}
	md := strings.TrimSpace(collapseExcessBlankLinesGo(strings.Join(cleanedLines, "\n")))
	if docTitle != "" && !strings.HasPrefix(md, "# ") {
		md = "# " + docTitle + "\n\n" + md
	}
	return md, true
}

func stripMediaWikiInlineLinksLinearFullDocGo(ln string) string {
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
		rel := strings.Index(ln[searchPos:], "](")
		if rel < 0 {
			break
		}
		mid := searchPos + rel
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
			if ln[b] == '[' {
				openBr = b
				break
			}
			if ln[b] == ']' {
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
				uStr := ln[mid+2 : endParen]
				lowU := asciiLowerExtractString(uStr)
				isWikidata := !hasDoubleOpen && (strings.HasPrefix(lowU, "https://www.wikidata.org/wiki/special:entitypage/") || strings.HasPrefix(lowU, "https://wikidata.org/wiki/special:entitypage/"))
				isActionEdit := strings.Contains(lowU, "?action=edit") || strings.Contains(lowU, "&action=edit")
				isCiteLink := (strings.HasPrefix(lowU, "#cite_note") || strings.HasPrefix(lowU, "#cite_ref") ||
					strings.Contains(lowU, "wikipedia:citation_needed") || strings.Contains(lowU, "wikipedia:please_clarify") ||
					strings.Contains(lowU, "wikipedia:disputed_statement")) && reMwCiteLabelFullDocGo.MatchString(label)
				if isWikidata || isActionEdit || isCiteLink {
					cutStart := openStart
					if isWikidata || isActionEdit {
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

func stripMediaWikiBracketMarkersLinearFullDocGo(ln string) string {
	if strings.IndexByte(ln, '[') < 0 || strings.IndexByte(ln, ']') < 0 {
		return ln
	}
	var sb strings.Builder
	sb.Grow(len(ln))
	lastEmit := 0
	i := 0
	n := len(ln)
	for i < n {
		if ln[i] != '[' {
			i++
			continue
		}
		closeRel := strings.IndexByte(ln[i+1:], ']')
		if closeRel < 0 {
			break
		}
		closeIdx := i + 1 + closeRel
		if closeIdx-i > 80 {
			i++
			continue
		}
		after := closeIdx + 1
		// Never touch Markdown links `[label](url)` or reference definitions `[id]: url`!
		if after < n && (ln[after] == '(' || ln[after] == ':') {
			i = after
			continue
		}
		inner := ln[i+1 : closeIdx]
		isBlank := isBlankASCIILineGo(inner)
		isEditOrCite := !isBlank && reMwEditOrCiteTokenFullDocGo.MatchString(inner)
		isNumCite := !isBlank && !isEditOrCite && reMwNumBracketTokenFullDocGo.MatchString(inner)
		if isBlank || isEditOrCite || isNumCite {
			cutStart := i
			if isBlank || isEditOrCite {
				for cutStart > lastEmit && (ln[cutStart-1] == ' ' || ln[cutStart-1] == '\t') {
					cutStart--
				}
			}
			sb.WriteString(ln[lastEmit:cutStart])
			lastEmit = after
			i = after
			continue
		}
		i++
	}
	if lastEmit == 0 {
		return ln
	}
	sb.WriteString(ln[lastEmit:])
	return sb.String()
}

func cleanMediaWikiMarkdownFullDocGo(rawMD string) string {
	bounded := truncateUTF8SafeFullDocGo(rawMD, maxHTMLScanCharsFullDocGo)
	lines := strings.Split(bounded, "\n")
	out := make([]string, 0, len(lines))
	inFence := false
	var fenceChar byte
	fenceLen := 0

	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if fp, rest, ok := parseFenceHeaderPrefixGo(ln); ok {
			leadSp := 0
			for leadSp < len(fp) && (fp[leadSp] == ' ' || fp[leadSp] == '\t') {
				leadSp++
			}
			ticks := fp[leadSp:]
			if leadSp <= 3 && len(ticks) >= 3 {
				if !inFence {
					if !(ticks[0] == '`' && strings.IndexByte(rest, '`') >= 0) {
						inFence = true
						fenceChar = ticks[0]
						fenceLen = len(ticks)
						out = append(out, ln)
						continue
					}
				} else if ticks[0] == fenceChar && len(ticks) >= fenceLen && isBlankASCIILineGo(rest) {
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
		if reMwChromeFooterFullDocGo.MatchString(trimmed) {
			break
		}
		if !strings.HasPrefix(trimmed, "|") {
			if reMwDropLine1FullDocGo.MatchString(trimmed) ||
				reMwDropJumpFullDocGo.MatchString(trimmed) ||
				reMwDropWikidataFullDocGo.MatchString(trimmed) ||
				reMwDropTaglineFullDocGo.MatchString(trimmed) ||
				reMwDropLangCountFullDocGo.MatchString(trimmed) ||
				(i < 40 && reMwDropCheckedFullDocGo.MatchString(trimmed)) {
				continue
			}
		}
		if strings.IndexByte(ln, '[') >= 0 && strings.IndexByte(ln, ']') >= 0 {
			ln = stripMediaWikiInlineLinksLinearFullDocGo(ln)
			ln = stripMediaWikiBracketMarkersLinearFullDocGo(ln)
		}
		if trimmed != "" && strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, ln)
	}
	return strings.TrimSpace(collapseExcessBlankLinesGo(strings.Join(out, "\n")))
}

// ExtractHTMLDocumentFull extracts clean GFM Markdown, metadata, links, images, branding,
// structured JSON-LD data, and optional paginated slices from raw HTML without external DOM dependencies.
func ExtractHTMLDocumentFull(rawHTML string, opts FullExtractOptions) ExtractedDocumentFull {
	baseURL := strings.TrimSpace(opts.BaseURL)
	onlyMainContent := opts.OnlyMainContent
	includeImages := opts.IncludeImages
	includeTags := opts.IncludeTags
	excludeTags := opts.ExcludeTags
	redactPII := opts.RedactPII

	boundedRawHTML := truncateUTF8SafeFullDocGo(rawHTML, maxHTMLScanCharsFullDocGo)
	if strings.IndexByte(boundedRawHTML, 0) >= 0 {
		boundedRawHTML = strings.ReplaceAll(boundedRawHTML, "\x00", "")
	}
	if strings.Contains(boundedRawHTML, "@@EF") {
		boundedRawHTML = strings.ReplaceAll(boundedRawHTML, "@@EF", "")
	}
	if strings.Contains(boundedRawHTML, "@@HNCODE_") {
		boundedRawHTML = strings.ReplaceAll(boundedRawHTML, "@@HNCODE_", "")
	}

	var jsonLdEntities []map[string]any
	schemaMeta := extractSchemaMetadataAndBodyFullDocGo(nil)
	title := ""
	var (
		language             string
		description          string
		author               string
		publishedTime        string
		modifiedTime         string
		siteName             string
		ogImage              string
		themeColor           string
		firstDatetimeAttr    string
		canonicalURL         string
		markdownAlternateURL string
		robotsMeta           string
		favicon              string
		logo                 string
		citationAuthors      []string
		colors               []string
		fonts                []string
	)

	hasClosedTag := strings.IndexByte(boundedRawHTML, '<') >= 0 && strings.IndexByte(boundedRawHTML, '>') >= 0

	if !opts.IsFragment && hasClosedTag {
		if indexFoldASCIIExtract(boundedRawHTML, "ld+json") >= 0 {
			jsonLdEntities = flattenJsonLdEntitiesFullDocGo(boundedRawHTML)
			schemaMeta = extractSchemaMetadataAndBodyFullDocGo(jsonLdEntities)
		}

		rawDocTitle := ""
		hasDocTitle := false
		replacePairedHTMLElementsLinearFullDocGo(boundedRawHTML, []string{"title"}, func(_, _, _, inner string) string {
			if !hasDocTitle {
				rawDocTitle = cleanInlineHTMLFullDocGo(inner)
				hasDocTitle = true
			}
			return ""
		}, maxHTMLScanCharsFullDocGo, 4096)

		if rawDocTitle != "" && !isPlaceholderMetaValueFullDocGo(rawDocTitle) {
			title = rawDocTitle
		}

		lowBounded := asciiLowerExtractString(boundedRawHTML)
		if strings.Contains(lowBounded, "<html") || strings.Contains(lowBounded, "<meta") ||
			strings.Contains(lowBounded, "<link") || strings.Contains(lowBounded, "<time") ||
			strings.Contains(lowBounded, "<relative-time") || strings.Contains(lowBounded, "<img") {
			scanHTMLTagsLinearFullDocGo(boundedRawHTML, func(tag scannedTagFullDocGo) bool {
				if tag.isClosing || tag.isDeclaration {
					return true
				}
				switch tag.tagNameLower {
				case "html":
					if language == "" {
						language = strings.TrimSpace(parseTagAttrsFullDocGo(tag.attrs)["lang"])
					}
				case "meta":
					attrs := parseTagAttrsFullDocGo(tag.attrs)
					key := attrs["name"]
					if key == "" {
						key = attrs["property"]
					}
					key = strings.ToLower(strings.TrimSpace(key))
					content := strings.TrimSpace(attrs["content"])
					if content == "" || isPlaceholderMetaValueFullDocGo(content) {
						return true
					}
					switch key {
					case "description", "og:description":
						if description == "" {
							description = content
						}
					case "og:title":
						if title == "" {
							title = content
						}
					case "og:image", "twitter:image":
						if ogImage == "" {
							ogImage = resolveHTTPSHrefFullDocGo(content, baseURL, false)
						}
					case "theme-color":
						if themeColor == "" {
							themeColor = content
						}
					case "og:site_name", "application-name":
						if siteName == "" {
							siteName = content
						}
					case "robots", "googlebot":
						if robotsMeta == "" {
							robotsMeta = content
						}
					case "author", "article:author", "sailthru.author", "byl":
						lowC := asciiLowerExtractString(content[:minInt(len(content), 8)])
						if author == "" && !strings.HasPrefix(lowC, "http://") && !strings.HasPrefix(lowC, "https://") {
							if cleaned := cleanAuthorMetaStringFullDocGo(content); cleaned != "" && !isPlaceholderMetaValueFullDocGo(cleaned) {
								author = cleaned
							}
						}
					case "citation_author", "dc.creator":
						if len(citationAuthors) < 10 {
							if cleaned := cleanAuthorMetaStringFullDocGo(content); cleaned != "" {
								citationAuthors = append(citationAuthors, cleaned)
							}
						}
					case "article:published_time", "date", "pubdate", "publishdate",
						"citation_publication_date", "citation_date", "citation_online_date",
						"dc.date", "dc.date.issued", "dcterms.created", "dcterms.issued":
						if publishedTime == "" {
							publishedTime = content
						}
					case "article:modified_time", "og:updated_time":
						if modifiedTime == "" {
							modifiedTime = content
						}
					}
				case "link":
					attrs := parseTagAttrsFullDocGo(tag.attrs)
					rel := strings.ToLower(attrs["rel"])
					mimeType := strings.ToLower(attrs["type"])
					href := resolveHTTPSHrefFullDocGo(attrs["href"], baseURL, false)
					if href == "" {
						return true
					}
					if strings.Contains(rel, "canonical") && canonicalURL == "" {
						canonicalURL = href
					}
					if strings.Contains(rel, "icon") && favicon == "" {
						favicon = href
					}
					if strings.Contains(rel, "alternate") &&
						(strings.Contains(mimeType, "text/markdown") || strings.Contains(mimeType, "application/markdown")) &&
						markdownAlternateURL == "" {
						markdownAlternateURL = href
					}
				case "time", "relative-time":
					if firstDatetimeAttr == "" {
						if dt := strings.TrimSpace(parseTagAttrsFullDocGo(tag.attrs)["datetime"]); dt != "" {
							firstDatetimeAttr = dt
						}
					}
				case "img":
					if logo == "" {
						attrs := parseTagAttrsFullDocGo(tag.attrs)
						hay := strings.ToLower(attrs["alt"] + " " + attrs["class"] + " " + attrs["id"] + " " + attrs["src"])
						if strings.Contains(hay, "logo") {
							srcCand := attrs["src"]
							if srcCand == "" {
								srcCand = attrs["data-src"]
							}
							logo = resolveHTTPSHrefFullDocGo(srcCand, baseURL, false)
						}
					}
				}
				return true
			}, maxHTMLScanCharsFullDocGo, false)
		}

		if author == "" && len(citationAuthors) > 0 {
			seen := make(map[string]bool)
			var uniq []string
			for _, ca := range citationAuthors {
				if !seen[ca] {
					seen[ca] = true
					uniq = append(uniq, ca)
				}
			}
			author = strings.Join(uniq, ", ")
		}
		if author == "" {
			author = schemaMeta.author
		}
		if publishedTime == "" {
			publishedTime = schemaMeta.publishedTime
		}
		if publishedTime == "" {
			publishedTime = firstDatetimeAttr
		}
		if modifiedTime == "" {
			modifiedTime = schemaMeta.modifiedTime
		}
		if siteName == "" {
			siteName = schemaMeta.siteName
		}
		if favicon == "" && baseURL != "" {
			if bu, err := url.Parse(baseURL); err == nil && (bu.Scheme == "https" || bu.Scheme == "http") && bu.Host != "" {
				favicon = bu.Scheme + "://" + bu.Host + "/favicon.ico"
			}
		}

		colors, fonts = extractStyleSignals(boundedRawHTML)

		if markdownAlternateURL == "" && strings.Contains(boundedRawHTML, "available as Markdown at") {
			if m := reCommentCompanionFullDocGo.FindStringSubmatch(boundedRawHTML); len(m) >= 2 {
				markdownAlternateURL = resolveHTTPSHrefFullDocGo(m[1], baseURL, false)
			}
		}
	}

	hasDefaultHTMLScoping := !opts.IsFragment && onlyMainContent && len(includeTags) == 0 && len(excludeTags) == 0
	var ytMeta *YouTubeWatchMeta
	var substackPreload *substackPreloadFullDocGo
	var hnExtracted *hnExtractedResultFullDocGo

	if hasDefaultHTMLScoping && hasClosedTag {
		ytMeta = ExtractYouTubeWatchMetadataFromHTML(boundedRawHTML, baseURL)
		substackPreload = extractSubstackPreloadDataFullDocGo(boundedRawHTML)
		if substackPreload != nil {
			if substackPreload.title != "" {
				title = substackPreload.title
			}
			if substackPreload.subtitle != "" && description == "" {
				description = substackPreload.subtitle
			}
			if substackPreload.author != "" && author == "" {
				author = substackPreload.author
			}
			if substackPreload.publishedTime != "" && publishedTime == "" {
				publishedTime = substackPreload.publishedTime
			}
		}
		hnExtracted = extractHackerNewsMarkdownFullDocGo(boundedRawHTML, baseURL)
		if hnExtracted != nil {
			if hnExtracted.title != "" {
				title = hnExtracted.title
			}
			if hnExtracted.author != "" && author == "" {
				author = hnExtracted.author
			}
			if hnExtracted.publishedTime != "" && publishedTime == "" {
				publishedTime = hnExtracted.publishedTime
			}
		}
	}

	var noscriptChunks []string
	var withoutCommentsAndScripts string
	if !hasClosedTag {
		withoutCommentsAndScripts = stripHTMLCommentsLinearFullDocGo(boundedRawHTML, maxHTMLScanCharsFullDocGo)
	} else {
		// Promote `<noscript><img ...></noscript>` and capture `<noscript>` SSR prose fallbacks (>=35 words).
		withPromotedNoscript := replaceHTMLTagBlocksLinearFullDocGo(boundedRawHTML, "noscript", func(_, _, inner string) string {
			trimmedInner := strings.TrimSpace(inner)
			singleImg := false
			scanHTMLTagsLinearFullDocGo(trimmedInner, func(tag scannedTagFullDocGo) bool {
				if tag.index == 0 && tag.end == len(trimmedInner) && !tag.isClosing && tag.tagNameLower == "img" {
					singleImg = true
				}
				return false
			}, 4096, false)
			if singleImg {
				return trimmedInner
			}
			if countTextWordsFullDocGo(stripHTMLTagsQuoteAwareLinearFullDocGo(trimmedInner, " ", maxHTMLScanCharsFullDocGo)) >= 35 {
				noscriptChunks = append(noscriptChunks, trimmedInner)
			}
			return ""
		}, maxHTMLScanCharsFullDocGo)

		// Convert YouTube & X/Twitter `<iframe>` embeds into clean Markdown links before stripping `<iframe>`.
		withEmbedLinks := replaceHTMLTagBlocksLinearFullDocGo(withPromotedNoscript, "iframe", func(_, attrStr, _ string) string {
			attrs := parseTagAttrsFullDocGo(attrStr)
			src := attrs["src"]
			if src == "" {
				src = attrs["data-src"]
			}
			if src == "" {
				return ""
			}
			if yt := reYouTubeEmbedFullDocGo.FindStringSubmatch(src); len(yt) >= 2 {
				return "\n\n[Embedded YouTube Video](https://www.youtube.com/watch?v=" + yt[1] + ")\n\n"
			}
			if xd := reTwitterDirectFullDocGo.FindStringSubmatch(src); len(xd) >= 3 {
				return "\n\n[Embedded Post](https://x.com/" + xd[1] + "/status/" + xd[2] + ")\n\n"
			}
			if xe := reTwitterWidgetFullDocGo.FindStringSubmatch(src); len(xe) >= 2 {
				return "\n\n[Embedded Post](https://x.com/i/status/" + xe[1] + ")\n\n"
			}
			return ""
		}, maxHTMLScanCharsFullDocGo)

		// Preserve MathJax `<script type="math/tex">` equations before stripping `<script>` tags.
		withMathScripts := withEmbedLinks
		if indexFoldASCIIExtract(withEmbedLinks, "math/tex") >= 0 {
			withMathScripts = replaceHTMLTagBlocksLinearFullDocGo(withEmbedLinks, "script", func(_, attrStr, inner string) string {
				lowAttr := asciiLowerExtractString(attrStr)
				if !strings.Contains(lowAttr, "math/tex") {
					return ""
				}
				tex := normalizeLatexSourceFullDocGo(inner)
				if tex == "" {
					return ""
				}
				if strings.Contains(lowAttr, "mode=display") || strings.Contains(lowAttr, "mode = display") {
					return "\n\n$$\n" + tex + "\n$$\n\n"
				}
				return "$" + strings.Join(strings.Fields(tex), " ") + "$"
			}, maxHTMLScanCharsFullDocGo)
		}

		withoutComments := stripHTMLCommentsLinearFullDocGo(withMathScripts, maxHTMLScanCharsFullDocGo)
		if strings.Contains(withoutComments, "<?") {
			withoutComments = reBogusCommentFullDocGo.ReplaceAllString(withoutComments, "")
		}
		withoutSvg := stripHTMLTagsLinearFullDocGo(withoutComments, []string{"svg"}, " ", maxHTMLScanCharsFullDocGo)
		withoutCommentsAndScripts = stripHTMLTagsLinearFullDocGo(withoutSvg, []string{
			"head", "noscript", "template", "canvas", "iframe",
			"include-fragment", "details-dialog", "details-menu", "tool-tip", "clipboard-copy",
			"script", "style",
		}, "", maxHTMLScanCharsFullDocGo)
	}
	work := withoutCommentsAndScripts

	primaryH1Text := ""
	if onlyMainContent && len(includeTags) == 0 && strings.Contains(asciiLowerExtractString(work), "<h1") {
		h1ScanSrc := stripHTMLTagsLinearFullDocGo(work, []string{"nav", "footer", "aside", "dialog", "menu"}, "", maxHTMLScanCharsFullDocGo)
		replacePairedHTMLElementsLinearFullDocGo(h1ScanSrc, []string{"h1"}, func(_, _, _, hInner string) string {
			if primaryH1Text == "" {
				strippedChrome := replacePairedHTMLElementsLinearFullDocGo(hInner, []string{"span", "a"}, func(sf, st, sa, si string) string {
					if st == "span" && (hasClassTokenFullDocGo(sa, "mw-editsection") || hasClassTokenFullDocGo(sa, "mw-editsection-bracket") || hasClassTokenFullDocGo(sa, "mw-editsection-divider")) {
						return ""
					}
					if st == "a" {
						lowA := asciiLowerExtractString(sa)
						if strings.Contains(lowA, "action=edit") || hasClassTokenFullDocGo(sa, "pilcrow") || hasClassTokenFullDocGo(sa, "headerlink") || hasClassTokenFullDocGo(sa, "doc-anchor") {
							return ""
						}
						lbl := cleanInlineHTMLFullDocGo(si)
						if lbl == "¶" || lbl == "§" || lbl == "#" {
							return ""
						}
					}
					return sf
				}, 2048, 2048)
				if cleaned := cleanHeadingPermalinksFullDocGo(cleanInlineHTMLFullDocGo(strippedChrome)); cleaned != "" {
					primaryH1Text = cleaned
				}
			}
			return ""
		}, maxHTMLScanCharsFullDocGo, 2048)
	}

	extractedMarkdownBodyOnly := false
	workHasClosedTag := strings.IndexByte(work, '<') >= 0 && strings.IndexByte(work, '>') >= 0
	if !workHasClosedTag {
		// Fast path for plain text or unclosed-tag fragments (`work` contains zero closed HTML tags).
	} else if len(includeTags) > 0 {
		work = applyIncludeAndExcludeTagSelectorsFullDocGo(work, includeTags, excludeTags)
	} else if onlyMainContent {
		work = stripHTMLTagsLinearFullDocGo(work, []string{"nav", "footer", "aside", "dialog", "menu"}, "", maxHTMLScanCharsFullDocGo)
		substackMarkup := ""
		if strings.Contains(work, "markup") {
			substackMarkup = applyIncludeAndExcludeTagSelectorsFullDocGo(work, []string{".markup"}, nil)
		}
		var mdBodyParts []string
		var articleParts []string
		replacePairedHTMLElementsLinearFullDocGo(work, []string{"article"}, func(_, _, aAttrs, aInner string) string {
			articleParts = append(articleParts, aInner)
			if hasClassTokenFullDocGo(aAttrs, "markdown-body") {
				mdBodyParts = append(mdBodyParts, aInner)
			}
			return ""
		}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
		joinedMdBody := strings.Join(mdBodyParts, "\n\n<hr/>\n\n")

		firstMainEnd := -1
		lastMainCloseIdx := -1
		scanHTMLTagsLinearFullDocGo(work, func(tag scannedTagFullDocGo) bool {
			if tag.tagNameLower != "main" {
				return true
			}
			if !tag.isClosing && !tag.isSelfClosing && firstMainEnd < 0 {
				firstMainEnd = tag.end
			} else if tag.isClosing && firstMainEnd >= 0 {
				lastMainCloseIdx = tag.index
			}
			return true
		}, maxHTMLScanCharsFullDocGo, false)
		mainInner := ""
		if firstMainEnd >= 0 && lastMainCloseIdx > firstMainEnd {
			mainInner = work[firstMainEnd:lastMainCloseIdx]
		}

		isGitHubIssueOrPR := baseURL != "" && reGitHubIssueURLFullDocGo.MatchString(baseURL)
		lowWork := asciiLowerExtractString(work)
		if !isGitHubIssueOrPR && len(strings.TrimSpace(joinedMdBody)) >= 32 {
			work = joinedMdBody
			extractedMarkdownBodyOnly = true
		} else if (strings.Contains(lowWork, "body markup") || strings.Contains(lowWork, "markup body")) && len(strings.TrimSpace(substackMarkup)) >= 64 {
			work = substackMarkup
			extractedMarkdownBodyOnly = true
		} else if substackPreload != nil && substackPreload.bodyHTML != "" && (mainInner == "" || countTextWordsFullDocGo(stripHTMLTagsQuoteAwareLinearFullDocGo(mainInner, " ", maxHTMLScanCharsFullDocGo)) < 40) {
			work = substackPreload.bodyHTML
			extractedMarkdownBodyOnly = true
		} else if len(strings.TrimSpace(mainInner)) >= 32 {
			work = mainInner
		} else if joinedArticles := strings.Join(articleParts, "\n\n"); len(strings.TrimSpace(joinedArticles)) >= 32 {
			work = joinedArticles
		} else if roleMain, rmOk := extractBalancedRoleMainHTMLFullDocGo(work); rmOk && len(strings.TrimSpace(roleMain)) >= 32 {
			work = roleMain
		} else {
			work = stripHTMLTagsLinearFullDocGo(work, []string{"header"}, "", maxHTMLScanCharsFullDocGo)
		}

		if len(excludeTags) > 0 {
			work = applyIncludeAndExcludeTagSelectorsFullDocGo(work, nil, excludeTags)
		}

		work = stripHTMLTagsLinearFullDocGo(stripHiddenAndChromeSubtreesFullDocGo(work), []string{"nav", "footer", "aside"}, "", maxHTMLScanCharsFullDocGo)
		work = replacePairedHTMLElementsLinearFullDocGo(work, []string{"span", "a", "label", "ul", "form", "button", "details"}, func(full, tag, attrStr, inner string) string {
			switch tag {
			case "span":
				if hasClassTokenFullDocGo(attrStr, "mw-editsection") || hasClassTokenFullDocGo(attrStr, "mw-editsection-bracket") || hasClassTokenFullDocGo(attrStr, "mw-editsection-divider") {
					return ""
				}
			case "a":
				anchorLabel := cleanInlineHTMLFullDocGo(inner)
				lowA := asciiLowerExtractString(attrStr)
				if strings.Contains(lowA, "action=edit") ||
					hasClassTokenFullDocGo(attrStr, "pilcrow") ||
					hasClassTokenFullDocGo(attrStr, "headerlink") ||
					hasClassTokenFullDocGo(attrStr, "doc-anchor") ||
					anchorLabel == "¶" ||
					anchorLabel == "[¶]" ||
					strings.Contains(lowA, "https://www.wikidata.org/wiki/special:entitypage/") {
					return ""
				}
			case "label":
				if hasClassTokenFullDocGo(attrStr, "p-lang-btn-label") {
					return ""
				}
			case "ul":
				if strings.Count(asciiLowerExtractString(inner), "interlanguage-link") >= 3 {
					return ""
				}
			case "form":
				if reFeedbackFormFullDocGo.MatchString(inner) {
					return ""
				}
			case "button":
				btnTxt := cleanInlineHTMLFullDocGo(inner)
				if reChromeButtonFullDocGo.MatchString(btnTxt) {
					return ""
				}
			case "details":
				linkCount := strings.Count(asciiLowerExtractString(inner), "<a")
				if linkCount >= 4 {
					proseNoLinks := cleanInlineHTMLFullDocGo(replacePairedHTMLElementsLinearFullDocGo(inner, []string{"a"}, func(_, _, _, _ string) string {
						return " "
					}, 16384, 4096))
					if len(proseNoLinks) < 120 {
						return ""
					}
				}
			}
			return full
		}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
		work = pruneHighLinkDensityBlocksFullDocGo(work)
	} else if len(excludeTags) > 0 {
		work = applyIncludeAndExcludeTagSelectorsFullDocGo(work, nil, excludeTags)
	}

	if !onlyMainContent || len(includeTags) > 0 {
		if opts.IsFragment {
			work = stripHiddenAndChromeSubtreesFullDocGo(work)
		}
		work = replacePairedHTMLElementsLinearFullDocGo(work, []string{"span", "a", "button"}, func(full, tag, attrStr, inner string) string {
			if tag == "span" && (hasClassTokenFullDocGo(attrStr, "mw-editsection") || hasClassTokenFullDocGo(attrStr, "mw-editsection-bracket") || hasClassTokenFullDocGo(attrStr, "mw-editsection-divider")) {
				return ""
			}
			if tag == "a" {
				lbl := cleanInlineHTMLFullDocGo(inner)
				lowA := asciiLowerExtractString(attrStr)
				if strings.Contains(lowA, "action=edit") || hasClassTokenFullDocGo(attrStr, "pilcrow") ||
					hasClassTokenFullDocGo(attrStr, "headerlink") || hasClassTokenFullDocGo(attrStr, "doc-anchor") ||
					lbl == "¶" || lbl == "[¶]" {
					return ""
				}
			}
			if tag == "button" && opts.IsFragment && reChromeButtonFullDocGo.MatchString(cleanInlineHTMLFullDocGo(inner)) {
				return ""
			}
			return full
		}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
	}

	var codeStash []string
	var links []string
	images := make([]ImageInfo, 0)
	var md string

	if !workHasClosedTag {
		md = work
	} else {
		stashCode := func(renderedCodeMD string) string {
			idx := len(codeStash)
			codeStash = append(codeStash, renderedCodeMD)
			return "@@EFCODE_" + strconv.Itoa(idx) + "@@"
		}
		stashFence := func(fenceMD string) string {
			idx := len(codeStash)
			codeStash = append(codeStash, strings.TrimSpace(fenceMD))
			return "\n\n@@EFFENCE_" + strconv.Itoa(idx) + "@@\n\n"
		}
		stashInline := func(spanMD string) string {
			if spanMD == "" {
				return ""
			}
			idx := len(codeStash)
			codeStash = append(codeStash, spanMD)
			return "`@@EFINLINE_" + strconv.Itoa(idx) + "@@`"
		}

		work = standardizeElementsInHTMLFullDocGo(work, stashCode, stashInline)

		collectAnchorLinks := func(htmlSource string) []string {
			outLinks := make([]string, 0)
			seen := make(map[string]bool)
			replacePairedHTMLElementsLinearFullDocGo(htmlSource, []string{"a"}, func(_, _, attrStr, _ string) string {
				if len(outLinks) >= 250 {
					return ""
				}
				attrs := parseTagAttrsFullDocGo(attrStr)
				if resolved := resolveHTTPSHrefFullDocGo(attrs["href"], baseURL, false); resolved != "" && !seen[resolved] {
					seen[resolved] = true
					outLinks = append(outLinks, resolved)
				}
				return ""
			}, maxHTMLScanCharsFullDocGo, 16384)
			return outLinks
		}

		links = collectAnchorLinks(work)
		if (len(links) == 0 || extractedMarkdownBodyOnly) && onlyMainContent {
			seenLinkSet := make(map[string]bool, len(links))
			for _, l := range links {
				seenLinkSet[l] = true
			}
			for _, l := range collectAnchorLinks(withoutCommentsAndScripts) {
				if !seenLinkSet[l] {
					seenLinkSet[l] = true
					links = append(links, l)
					if len(links) >= 250 {
						break
					}
				}
			}
		}

		seenImages := make(map[string]bool)
		if includeImages {
			scanHTMLTagsLinearFullDocGo(work, func(tag scannedTagFullDocGo) bool {
				if tag.isClosing || tag.tagNameLower != "img" {
					return true
				}
				attrs := parseTagAttrsFullDocGo(tag.attrs)
				primarySrc := ""
				if attrs["src"] != "" && !isLazyPlaceholderImageURLFullDocGo(attrs["src"]) {
					primarySrc = attrs["src"]
				}
				bestCand := primarySrc
				for _, fallback := range []string{
					attrs["data-src"],
					attrs["data-lazy-src"],
					attrs["data-original"],
					ExtractLargestURLFromSrcset(firstNonEmptyFullDocGo(attrs["srcset"], attrs["data-srcset"], attrs["data-lazy-srcset"])),
					attrs["src"],
				} {
					if bestCand != "" {
						break
					}
					bestCand = fallback
				}
				src := resolveHTTPSHrefFullDocGo(bestCand, baseURL, false)
				if src != "" && !seenImages[src] && !isDecorativeOrTinyImageFullDocGo(attrs, src) {
					seenImages[src] = true
					images = append(images, ImageInfo{URL: src, Alt: strings.TrimSpace(attrs["alt"])})
					if len(images) >= 60 {
						return false
					}
				}
				return true
			}, maxHTMLScanCharsFullDocGo, false)
		}

		formatTableCellMarkdown := func(cellHTML string) string {
			withInline := reAdjacentAnchorsFullDocGo.ReplaceAllString(cellHTML, "$1 $2")
			withInline = replaceHTMLOpenTagsLinearFullDocGo(withInline, []string{"br"}, func(scannedTagFullDocGo) string {
				return " / "
			}, 16384)
			withInline = replacePairedHTMLElementsLinearFullDocGo(withInline, []string{"code"}, func(_, _, _, c string) string {
				return stashInline(formatInlineCodeSpanGo(cleanInlineHTMLFullDocGo(c)))
			}, 16384, 8192)
			withInline = replacePairedHTMLElementsLinearFullDocGo(withInline, []string{"a"}, func(_, _, attrStr, inner string) string {
				attrs := parseTagAttrsFullDocGo(attrStr)
				href := resolveHTTPSHrefFullDocGo(attrs["href"], baseURL, true)
				label := convertAnchorInnerWithBadgeImagesFullDocGo(inner, baseURL, includeImages)
				if label == "" {
					return " "
				}
				if href != "" {
					dupSuf := " (" + href + ")"
					if len(label) > len(dupSuf) && strings.HasSuffix(label, dupSuf) {
						if stripped := strings.TrimSpace(label[:len(label)-len(dupSuf)]); stripped != "" {
							label = stripped
						}
					}
					return "[" + label + "](" + href + ")"
				}
				return label
			}, 16384, 8192)
			withInline = replacePairedHTMLElementsLinearFullDocGo(withInline, []string{"strong", "b"}, func(_, _, _, inner string) string {
				txt := cleanInlineHTMLFullDocGo(inner)
				if txt == "" {
					return " "
				}
				return "**" + txt + "**"
			}, 16384, 8192)
			withInline = replacePairedHTMLElementsLinearFullDocGo(withInline, []string{"em", "i"}, func(_, _, _, inner string) string {
				txt := cleanInlineHTMLFullDocGo(inner)
				if txt == "" {
					return " "
				}
				return "*" + txt + "*"
			}, 16384, 8192)
			return strings.ReplaceAll(cleanInlineHTMLFullDocGo(withInline), "|", `\|`)
		}

		md = replaceHTMLOpenTagsLinearFullDocGo(work, []string{"wbr"}, func(scannedTagFullDocGo) string { return "" }, maxHTMLScanCharsFullDocGo)
		md = reAdjacentAnchorsFullDocGo.ReplaceAllString(md, "$1 $2")
		md = reAdjacentCodeFullDocGo.ReplaceAllString(md, "$1 $2")
		md = reAlnumBeforeAnchorFullDocGo.ReplaceAllString(md, "$1 $2")

		// Strip Expressive Code empty header figcaptions.
		if strings.Contains(asciiLowerExtractString(md), "<figcaption") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"figcaption"}, func(full, _, attrStr, inner string) string {
				if !hasClassTokenFullDocGo(attrStr, "header") || len(inner) > 600 {
					return full
				}
				lowIn := asciiLowerExtractString(inner)
				if strings.Contains(lowIn, "title") && strings.Contains(lowIn, "sr-only") {
					withoutSr := replacePairedHTMLElementsLinearFullDocGo(inner, []string{"span"}, func(sf, _, sAttr, _ string) string {
						if hasClassTokenFullDocGo(sAttr, "sr-only") {
							return ""
						}
						return sf
					}, 600, 600)
					if cleanInlineHTMLFullDocGo(withoutSr) == "" {
						return ""
					}
				}
				return full
			}, maxHTMLScanCharsFullDocGo, 600)
		}

		// `<pre>` blocks (optionally wrapping `<code ...>...</code>`)
		if strings.Contains(asciiLowerExtractString(md), "<pre") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"pre"}, func(_, _, preAttrs, preInner string) string {
				codeAttrs := ""
				rawCodeHTML := preInner
				trimmedPre := strings.TrimSpace(preInner)
				lowTrimmed := asciiLowerExtractString(trimmedPre)
				if strings.HasPrefix(lowTrimmed, "<code") && strings.HasSuffix(lowTrimmed, "</code>") {
					replacePairedHTMLElementsLinearFullDocGo(trimmedPre, []string{"code"}, func(_, _, cAttrs, cInner string) string {
						if codeAttrs == "" {
							codeAttrs = cAttrs
							rawCodeHTML = cInner
						}
						return ""
					}, len(trimmedPre), len(trimmedPre))
				}
				lang := inferCodeFenceLangFullDocGo(preAttrs, codeAttrs)
				withEcLines := rawCodeHTML
				if strings.Contains(rawCodeHTML, "ec-line") {
					noNL := strings.NewReplacer("\r\n", "", "\n", "").Replace(rawCodeHTML)
					withEcLines = replaceHTMLOpenTagsLinearFullDocGo(noNL, []string{"div"}, func(t scannedTagFullDocGo) string {
						if hasClassTokenFullDocGo(t.attrs, "ec-line") {
							return "\n"
						}
						return t.rawTag
					}, maxHTMLScanCharsFullDocGo)
				}
				decodedCode := strings.TrimSpace(DecodeHTMLEntities(stripHTMLTagsQuoteAwareLinearFullDocGo(withEcLines, "", maxHTMLScanCharsFullDocGo)))
				return stashFence(MakeSafeCodeFence(decodedCode, lang, false))
			}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
		}

		// `<figure>` with `<img>` and optional `<figcaption>`
		if strings.Contains(asciiLowerExtractString(md), "<figure") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"figure"}, func(full, _, _, figInner string) string {
				if strings.Contains(asciiLowerExtractString(figInner), "<figure") {
					return full
				}
				withoutCap := stripHTMLTagsLinearFullDocGo(figInner, []string{"figcaption"}, "", 8000)
				lowNoCap := asciiLowerExtractString(withoutCap)
				if strings.Contains(lowNoCap, "<pre") || strings.Contains(lowNoCap, "<table") || strings.Contains(lowNoCap, "<p") {
					return full
				}
				var ia map[string]string
				scanHTMLTagsLinearFullDocGo(figInner, func(t scannedTagFullDocGo) bool {
					if !t.isClosing && t.tagNameLower == "img" {
						ia = parseTagAttrsFullDocGo(t.attrs)
						return false
					}
					return true
				}, 8000, false)
				if ia == nil {
					return full
				}
				primary := ""
				if ia["src"] != "" && !isLazyPlaceholderImageURLFullDocGo(ia["src"]) {
					primary = ia["src"]
				}
				bestSrc := firstNonEmptyFullDocGo(
					primary,
					ia["data-src"],
					ExtractLargestURLFromSrcset(firstNonEmptyFullDocGo(ia["srcset"], ia["data-srcset"])),
					ia["src"],
				)
				resolvedSrc := resolveHTTPSHrefFullDocGo(bestSrc, baseURL, false)
				if resolvedSrc == "" || isDecorativeOrTinyImageFullDocGo(ia, resolvedSrc) {
					return full
				}
				alt := cleanInlineHTMLFullDocGo(ia["alt"])
				capText := ""
				replacePairedHTMLElementsLinearFullDocGo(figInner, []string{"figcaption"}, func(_, _, _, cInner string) string {
					if capText == "" {
						capText = cleanInlineHTMLFullDocGo(cInner)
					}
					return ""
				}, 8000, 1200)
				if !includeImages {
					if capText != "" {
						return "\n\n*" + capText + "*\n\n"
					}
					return ""
				}
				if capText != "" && capText != alt {
					return "\n\n![" + alt + "](" + resolvedSrc + ")\n\n*" + capText + "*\n\n"
				}
				return "\n\n![" + alt + "](" + resolvedSrc + ")\n\n"
			}, maxHTMLScanCharsFullDocGo, 8000)
		}

		// GFM `<table>` conversion
		if strings.Contains(asciiLowerExtractString(md), "<table") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"table"}, func(full, _, _, tbl string) string {
				if strings.Contains(asciiLowerExtractString(tbl), "<table") {
					return full
				}
				var rows [][]string
				replacePairedHTMLElementsLinearFullDocGo(tbl, []string{"tr"}, func(_, _, _, rInner string) string {
					var cells []string
					replacePairedHTMLElementsLinearFullDocGo(rInner, []string{"th", "td"}, func(_, _, _, cInner string) string {
						cells = append(cells, formatTableCellMarkdown(cInner))
						return ""
					}, 65536, 16384)
					hasNonEmpty := false
					for _, c := range cells {
						if c != "" {
							hasNonEmpty = true
							break
						}
					}
					if hasNonEmpty {
						rows = append(rows, cells)
					}
					return ""
				}, maxHTMLScanCharsFullDocGo, 65536)
				if len(rows) == 0 {
					return ""
				}
				cols := 0
				for _, r := range rows {
					if len(r) > cols {
						cols = len(r)
					}
				}
				if cols == 0 {
					return ""
				}
				padRow := func(r []string) string {
					padded := make([]string, cols)
					copy(padded, r)
					return "| " + strings.Join(padded, " | ") + " |"
				}
				sepCells := make([]string, cols)
				for i := range sepCells {
					sepCells[i] = "---"
				}
				outLines := make([]string, 0, len(rows)+1)
				outLines = append(outLines, padRow(rows[0]))
				outLines = append(outLines, "| "+strings.Join(sepCells, " | ")+" |")
				for _, r := range rows[1:] {
					outLines = append(outLines, padRow(r))
				}
				return "\n\n" + strings.Join(outLines, "\n") + "\n\n"
			}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
		}

		// Inline `<code>` and `<kbd>`
		if lowMd := asciiLowerExtractString(md); strings.Contains(lowMd, "<code") || strings.Contains(lowMd, "<kbd") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"code", "kbd"}, func(_, _, _, c string) string {
				return stashInline(formatInlineCodeSpanGo(cleanInlineHTMLFullDocGo(c)))
			}, maxHTMLScanCharsFullDocGo, maxHTMLScanCharsFullDocGo)
		}

		// Links wrapping headings (`<a href="..."><h2>Title</h2></a>`)
		if lowMd := asciiLowerExtractString(md); strings.Contains(lowMd, "<a") && strings.Contains(lowMd, "<h") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"a"}, func(full, _, attrStr, inner string) string {
				trimmed := strings.TrimSpace(inner)
				if len(trimmed) < 7 || trimmed[0] != '<' || (trimmed[1] != 'h' && trimmed[1] != 'H') || trimmed[2] < '1' || trimmed[2] > '6' {
					return full
				}
				lvl := 0
				hInnerMatched := ""
				replacePairedHTMLElementsLinearFullDocGo(trimmed, []string{"h1", "h2", "h3", "h4", "h5", "h6"}, func(hf, ht, _, hInner string) string {
					if lvl == 0 && len(hf) == len(trimmed) {
						lvl = int(ht[1] - '0')
						hInnerMatched = hInner
					}
					return ""
				}, len(trimmed), len(trimmed))
				if lvl == 0 {
					return full
				}
				attrs := parseTagAttrsFullDocGo(attrStr)
				href := resolveHTTPSHrefFullDocGo(attrs["href"], baseURL, true)
				txt := cleanHeadingPermalinksFullDocGo(cleanInlineHTMLFullDocGo(hInnerMatched))
				if txt == "" {
					return ""
				}
				hashes := strings.Repeat("#", lvl)
				if href != "" {
					return "\n\n" + hashes + " [" + txt + "](" + href + ")\n\n"
				}
				return "\n\n" + hashes + " " + txt + "\n\n"
			}, maxHTMLScanCharsFullDocGo, 8192)
		}

		// Headings `<h1>`..`<h6>`
		if strings.Contains(asciiLowerExtractString(md), "<h") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"h1", "h2", "h3", "h4", "h5", "h6"}, func(_, tag, _, inner string) string {
				txt := cleanHeadingPermalinksFullDocGo(cleanInlineHTMLFullDocGo(inner))
				if txt == "" {
					return ""
				}
				lvl := int(tag[1] - '0')
				return "\n\n" + strings.Repeat("#", lvl) + " " + txt + "\n\n"
			}, maxHTMLScanCharsFullDocGo, 8192)
		}

		// `<summary>`
		if strings.Contains(asciiLowerExtractString(md), "<summary") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"summary"}, func(_, _, _, inner string) string {
				cleaned := reSummarySeeAllFullDocGo.ReplaceAllString(cleanInlineHTMLFullDocGo(inner), "")
				txt := cleanHeadingPermalinksFullDocGo(cleaned)
				if txt == "" {
					return ""
				}
				if strings.HasPrefix(txt, "#") {
					return "\n\n" + txt + "\n\n"
				}
				return "\n\n**" + txt + "**\n\n"
			}, maxHTMLScanCharsFullDocGo, 4096)
		}

		// Inline links, strikethrough, mark, bold, italic, `<dt>`, `<blockquote>`
		md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"a"}, func(full, _, attrStr, inner string) string {
			if reBlockInsideInlineFullDocGo.MatchString(inner) {
				return full
			}
			attrs := parseTagAttrsFullDocGo(attrStr)
			href := resolveHTTPSHrefFullDocGo(attrs["href"], baseURL, true)
			label := convertAnchorInnerWithBadgeImagesFullDocGo(inner, baseURL, includeImages)
			if label == "" {
				return " "
			}
			if href != "" {
				dupSuf := " (" + href + ")"
				if len(label) > len(dupSuf) && strings.HasSuffix(label, dupSuf) {
					if stripped := strings.TrimSpace(label[:len(label)-len(dupSuf)]); stripped != "" {
						label = stripped
					}
				}
				return "[" + label + "](" + href + ")"
			}
			return label
		}, maxHTMLScanCharsFullDocGo, 16384)

		md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"del", "s", "strike"}, func(full, _, _, inner string) string {
			if reBlockInsideInlineFullDocGo.MatchString(inner) {
				return full
			}
			txt := cleanInlineHTMLFullDocGo(inner)
			if txt == "" {
				return ""
			}
			return "~~" + txt + "~~"
		}, maxHTMLScanCharsFullDocGo, 8192)

		md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"mark"}, func(full, _, _, inner string) string {
			if reBlockInsideInlineFullDocGo.MatchString(inner) {
				return full
			}
			txt := cleanInlineHTMLFullDocGo(inner)
			if txt == "" {
				return ""
			}
			return "==" + txt + "=="
		}, maxHTMLScanCharsFullDocGo, 8192)

		md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"strong", "b"}, func(full, _, _, inner string) string {
			if reBlockInsideInlineFullDocGo.MatchString(inner) {
				return full
			}
			txt := cleanInlineHTMLFullDocGo(inner)
			if txt == "" {
				return " "
			}
			return "**" + txt + "**"
		}, maxHTMLScanCharsFullDocGo, 8192)

		md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"em", "i"}, func(full, _, _, inner string) string {
			if reBlockInsideInlineFullDocGo.MatchString(inner) {
				return full
			}
			txt := cleanInlineHTMLFullDocGo(inner)
			if txt == "" {
				return " "
			}
			return "*" + txt + "*"
		}, maxHTMLScanCharsFullDocGo, 8192)

		if strings.Contains(asciiLowerExtractString(md), "<dt") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"dt"}, func(_, _, _, inner string) string {
				compactSpans := replaceHTMLTagsQuoteAwareLinearFullDocGo(inner, func(t scannedTagFullDocGo) string {
					if t.tagNameLower == "span" {
						return ""
					}
					return t.rawTag
				}, 2000, false)
				compactSpans = reDtStarSpaceFullDocGo.ReplaceAllString(compactSpans, "$1 $2")
				compactSpans = reDtStarPlainFullDocGo.ReplaceAllString(compactSpans, "$1")
				term := cleanHeadingPermalinksFullDocGo(cleanInlineHTMLFullDocGo(compactSpans))
				if term == "" {
					return ""
				}
				term = strings.TrimPrefix(strings.TrimSuffix(term, "**"), "**")
				return "\n\n**" + term + "**\n\n"
			}, maxHTMLScanCharsFullDocGo, 1800)
		}

		if strings.Contains(asciiLowerExtractString(md), "<blockquote") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"blockquote"}, func(_, _, _, inner string) string {
				txt := cleanInlineHTMLFullDocGo(inner)
				if txt == "" {
					return ""
				}
				return "\n\n> " + txt + "\n\n"
			}, maxHTMLScanCharsFullDocGo, 16384)
		}

		// Standalone `<img>` tags when `IncludeImages` is enabled
		if includeImages && strings.Contains(asciiLowerExtractString(md), "<img") {
			md = replaceHTMLOpenTagsLinearFullDocGo(md, []string{"img"}, func(tag scannedTagFullDocGo) string {
				if hasInlineEventHandlerAttrGo(tag.attrs) {
					return ""
				}
				attrs := parseTagAttrsFullDocGo(tag.attrs)
				primary := ""
				if attrs["src"] != "" && !isLazyPlaceholderImageURLFullDocGo(attrs["src"]) {
					primary = attrs["src"]
				}
				bestSrc := firstNonEmptyFullDocGo(
					primary,
					attrs["data-src"],
					ExtractLargestURLFromSrcset(firstNonEmptyFullDocGo(attrs["srcset"], attrs["data-srcset"])),
					attrs["src"],
				)
				resolvedSrc := resolveHTTPSHrefFullDocGo(bestSrc, baseURL, false)
				if resolvedSrc == "" || isDecorativeOrTinyImageFullDocGo(attrs, resolvedSrc) {
					return ""
				}
				alt := strings.NewReplacer("[", "", "]", "").Replace(cleanInlineHTMLFullDocGo(attrs["alt"]))
				return "\n\n![" + alt + "](" + resolvedSrc + ")\n\n"
			}, maxHTMLScanCharsFullDocGo)
		}

		// `<ul>`/`<ol>`/`<li>` single O(N) stack pass
		if strings.Contains(asciiLowerExtractString(md), "<li") {
			listSrc := md
			var listOut []string
			listDepth := 0
			type liFrame struct {
				depth   int
				emitted bool
			}
			var liStack []liFrame
			lastListIdx := 0

			flushListSeg := func(seg string) {
				if seg == "" {
					return
				}
				if len(liStack) == 0 {
					listOut = append(listOut, seg)
					return
				}
				active := &liStack[len(liStack)-1]
				indentLvl := active.depth - 1
				if indentLvl < 0 {
					indentLvl = 0
				} else if indentLvl > 3 {
					indentLvl = 3
				}
				indent := strings.Repeat("  ", indentLvl)
				if reListBlockContentFullDocGo.MatchString(seg) {
					parts := SplitMarkdownByCodeFences(seg)
					for idx := range parts {
						if idx%2 == 0 {
							parts[idx] = stripHTMLTagsQuoteAwareLinearFullDocGo(parts[idx], " ", maxHTMLScanCharsFullDocGo)
						}
					}
					cleanedBlock := strings.TrimSpace(strings.Join(parts, ""))
					if cleanedBlock == "" {
						return
					}
					if !active.emitted {
						listOut = append(listOut, "\n"+indent+"- "+cleanedBlock)
						active.emitted = true
					} else {
						listOut = append(listOut, "\n\n"+cleanedBlock)
					}
					return
				}
				txt := cleanInlineHTMLFullDocGo(seg)
				if txt == "" {
					return
				}
				if !active.emitted {
					listOut = append(listOut, "\n"+indent+"- "+txt)
					active.emitted = true
				} else {
					listOut = append(listOut, " "+txt)
				}
			}

			scanHTMLTagsLinearFullDocGo(listSrc, func(tag scannedTagFullDocGo) bool {
				t := tag.tagNameLower
				if t != "ul" && t != "ol" && t != "li" {
					return true
				}
				flushListSeg(listSrc[lastListIdx:tag.index])
				lastListIdx = tag.end
				if !tag.isClosing && (t == "ul" || t == "ol") {
					listDepth++
				} else if tag.isClosing && (t == "ul" || t == "ol") {
					for len(liStack) > 0 && liStack[len(liStack)-1].depth >= listDepth {
						liStack = liStack[:len(liStack)-1]
					}
					if listDepth > 0 {
						listDepth--
					}
					if listDepth == 0 {
						listOut = append(listOut, "\n\n")
					}
				} else if !tag.isClosing && t == "li" {
					targetDepth := listDepth
					if targetDepth < 1 {
						targetDepth = 1
					}
					for len(liStack) > 0 && liStack[len(liStack)-1].depth >= targetDepth {
						liStack = liStack[:len(liStack)-1]
					}
					liStack = append(liStack, liFrame{depth: targetDepth, emitted: false})
				} else if tag.isClosing && t == "li" {
					if len(liStack) > 0 {
						liStack = liStack[:len(liStack)-1]
					}
				}
				return true
			}, maxHTMLScanCharsFullDocGo, false)
			flushListSeg(listSrc[lastListIdx:])
			md = strings.Join(listOut, "")
		}

		if strings.Contains(asciiLowerExtractString(md), "<a") {
			md = replacePairedHTMLElementsLinearFullDocGo(md, []string{"a"}, func(_, _, attrStr, inner string) string {
				attrs := parseTagAttrsFullDocGo(attrStr)
				href := resolveHTTPSHrefFullDocGo(attrs["href"], baseURL, true)
				label := convertAnchorInnerWithBadgeImagesFullDocGo(inner, baseURL, includeImages)
				if label == "" {
					return ""
				}
				if href != "" {
					dupSuf := " (" + href + ")"
					if len(label) > len(dupSuf) && strings.HasSuffix(label, dupSuf) {
						if stripped := strings.TrimSpace(label[:len(label)-len(dupSuf)]); stripped != "" {
							label = stripped
						}
					}
					return "[" + label + "](" + href + ")"
				}
				return label
			}, maxHTMLScanCharsFullDocGo, 16384)
		}

		md = replaceHTMLTagsQuoteAwareLinearFullDocGo(md, func(tag scannedTagFullDocGo) string {
			if !tag.isClosing && tag.tagNameLower == "hr" {
				return "\n\n---\n\n"
			}
			if !tag.isClosing && tag.tagNameLower == "br" {
				return "\n"
			}
			if tag.isClosing && blockCloseTagsFullDocGo[tag.tagNameLower] {
				return "\n\n"
			}
			if tag.isClosing && spaceCloseTagsFullDocGo[tag.tagNameLower] {
				return " "
			}
			return ""
		}, maxHTMLScanCharsFullDocGo, true)
	} // end if workHasClosedTag

	if strings.Contains(md, "@@EFTASK") {
		md = strings.ReplaceAll(md, "@@EFTASKX@@", "[x]")
		md = strings.ReplaceAll(md, "@@EFTASKO@@", "[ ]")
	}
	if len(codeStash) > 0 {
		md = reSentinelEffenceFullDocGo.ReplaceAllStringFunc(md, func(m string) string {
			sub := reSentinelEffenceFullDocGo.FindStringSubmatch(m)
			if len(sub) >= 2 {
				if idx, err := strconv.Atoi(sub[1]); err == nil && idx >= 0 && idx < len(codeStash) {
					return codeStash[idx]
				}
			}
			return ""
		})
		md = reSentinelEfcodeFullDocGo.ReplaceAllStringFunc(md, func(m string) string {
			sub := reSentinelEfcodeFullDocGo.FindStringSubmatch(m)
			if len(sub) >= 2 {
				if idx, err := strconv.Atoi(sub[1]); err == nil && idx >= 0 && idx < len(codeStash) {
					return codeStash[idx]
				}
			}
			return ""
		})
	}

	mdParts := SplitMarkdownByCodeFences(md)
	for idx, part := range mdParts {
		if idx%2 == 1 {
			continue
		}
		decodedPart := decodeMarkdownEntitiesPreservingLtGo(part)
		withCleanLinks := sanitizeAndResolveMarkdownProseLinksLinearGo(decodedPart, baseURL)
		if !includeImages {
			withCleanLinks = stripMarkdownImagesLinearFullDocGo(withCleanLinks)
		}
		var keptLines []string
		for _, line := range strings.Split(withCleanLinks, "\n") {
			normTask := line
			if len(line) >= 5 {
				tl := strings.TrimLeft(line, " \t")
				if strings.HasPrefix(tl, "-") && strings.IndexByte(tl, '[') >= 0 {
					normTask = reTaskLineNormFullDocGo.ReplaceAllString(line, "$1[x]")
				}
			}
			var cleanedLine string
			if len(normTask) >= 4 && normTask[0] == ' ' && normTask[1] == ' ' {
				if li := reListIndentLineFullDocGo.FindStringSubmatch(normTask); len(li) >= 3 {
					cleanedLine = li[1] + collapseTagBoundaryPunctuationFullDocGo(collapseHorizontalSpaceRunFullDocGo(strings.TrimSpace(li[2])))
				}
			}
			if cleanedLine == "" {
				cleanedLine = collapseTagBoundaryPunctuationFullDocGo(collapseHorizontalSpaceRunFullDocGo(strings.TrimSpace(normTask)))
				if strings.Contains(cleanedLine, "¶") {
					cleanedLine = reTrailPilcrowLinkFullDocGo.ReplaceAllString(cleanedLine, "")
					cleanedLine = reTrailPilcrowRawFullDocGo.ReplaceAllString(cleanedLine, "")
				}
			}
			if len(cleanedLine) <= 220 && cleanedLine != "" && reBoilerplateLineFullDocGo.MatchString(cleanedLine) {
				continue
			}
			keptLines = append(keptLines, cleanedLine)
		}
		mdParts[idx] = collapseExcessBlankLinesGo(strings.Join(keptLines, "\n"))
	}
	md = strings.Join(mdParts, "")
	if len(codeStash) > 0 {
		md = reSentinelEfinlineFullDocGo.ReplaceAllStringFunc(md, func(m string) string {
			sub := reSentinelEfinlineFullDocGo.FindStringSubmatch(m)
			if len(sub) >= 2 {
				if idx, err := strconv.Atoi(sub[1]); err == nil && idx >= 0 && idx < len(codeStash) {
					return codeStash[idx]
				}
			}
			return ""
		})
	}
	if strings.Contains(md, "```") {
		md = reMdnLangHeaderFullDocGo.ReplaceAllStringFunc(md, func(m string) string {
			sub := reMdnLangHeaderFullDocGo.FindStringSubmatch(m)
			if len(sub) < 4 {
				return m
			}
			lang := strings.TrimSpace(sub[3])
			if lang == "" {
				lang = normalizeFenceLangFullDocGo(sub[2])
			}
			return sub[1] + "```" + lang + "\n"
		})
	}
	tailStart := len(md) - 800
	if tailStart < 0 {
		tailStart = 0
	}
	if strings.Contains(asciiLowerExtractString(md[tailStart:]), "help improve mdn") {
		md = reHelpImproveMdnFullDocGo.ReplaceAllString(md, "")
	}
	md = strings.TrimSpace(collapseExcessBlankLinesGo(md))

	if primaryH1Text != "" && onlyMainContent && len(includeTags) == 0 && ytMeta == nil && hnExtracted == nil && md != "" && !reAnyH1LineFullDocGo.MatchString(md) {
		md = "# " + primaryH1Text + "\n\n" + md
	}

	extractorID := ""
	inertiaHydrated := false
	var siteRecords []map[string]any
	var siteTotal *int
	var siteReturned *int
	var siteTruncated *bool
	var siteNextCursor string
	if ytMeta != nil {
		if ytMeta.Title != "" {
			title = ytMeta.Title
		}
		if ytMeta.Description != "" {
			description = truncateUTF8SafeFullDocGo(ytMeta.Description, 320)
		}
		md = ytMeta.Markdown
	} else if hnExtracted != nil {
		md = hnExtracted.markdown
		if len(hnExtracted.links) > 0 {
			seen := make(map[string]bool, len(hnExtracted.links))
			merged := append([]string(nil), hnExtracted.links...)
			for _, l := range merged {
				seen[l] = true
			}
			for _, l := range links {
				if !seen[l] && len(merged) < 250 {
					seen[l] = true
					merged = append(merged, l)
				}
			}
			links = merged
		}
	} else if hasDefaultHTMLScoping && hasClosedTag {
		var parsedBase *url.URL
		hostLower := ""
		if baseURL != "" {
			parsedBase, _ = url.Parse(baseURL)
			if parsedBase != nil {
				hostLower = strings.ToLower(parsedBase.Hostname())
			}
		}
		if baseURL != "" && reGitHubIssueURLFullDocGo.MatchString(baseURL) {
			md = cleanGitHubIssueOrPRMarkdownFullDocGo(md)
		} else if siteRes, siteOk := ApplyDeclarativeHTMLExtractor(boundedRawHTML, baseURL, md, func(frag, fragBase string) (string, []string) {
			sub := ExtractHTMLDocumentFull(frag, FullExtractOptions{
				BaseURL:         fragBase,
				OnlyMainContent: false,
				IncludeImages:   includeImages,
			})
			return sub.Markdown, sub.Links
		}); siteOk && siteRes != nil {
			extractorID = siteRes.ExtractorID
			md = siteRes.Markdown
			if siteRes.Title != "" {
				title = siteRes.Title
			}
			if siteRes.Description != "" && description == "" {
				description = siteRes.Description
			}
			if siteRes.Author != "" && author == "" {
				author = siteRes.Author
			}
			if siteRes.PublishedTime != "" && publishedTime == "" {
				publishedTime = siteRes.PublishedTime
			}
			if len(siteRes.Links) > 0 {
				merged := make([]string, 0, len(siteRes.Links)+len(links))
				seen := make(map[string]bool, len(siteRes.Links))
				for _, l := range siteRes.Links {
					if !seen[l] && len(merged) < 250 {
						seen[l] = true
						merged = append(merged, l)
					}
				}
				for _, l := range links {
					if !seen[l] && len(merged) < 250 {
						seen[l] = true
						merged = append(merged, l)
					}
				}
				links = merged
			}
			siteRecords = siteRes.Records
			siteTotal = siteRes.Total
			siteReturned = siteRes.Returned
			siteTruncated = siteRes.Truncated
			siteNextCursor = siteRes.NextCursor
		} else if (reStackExHostFullDocGo.MatchString(hostLower) || (strings.Contains(boundedRawHTML, `id="question"`) && strings.Contains(boundedRawHTML, `id="question-header"`))) &&
			(parsedBase == nil || strings.HasPrefix(parsedBase.Path, "/questions/") || strings.HasPrefix(parsedBase.Path, "/q/")) {
			if seTitle, seMD, seOk := extractStackExchangeHTMLFullDocGo(boundedRawHTML, baseURL, includeImages); seOk {
				title = seTitle
				md = seMD
				extractorID = "stackexchange-qa"
			}
		} else if hostLower == "rfc-editor.org" || hostLower == "www.rfc-editor.org" || hostLower == "datatracker.ietf.org" ||
			(strings.Contains(boundedRawHTML, `class="newpage"`) && strings.Contains(boundedRawHTML, "[Page ")) {
			if rfcMD, rfcOk := extractIETFRfcFullDocGo(boundedRawHTML, md, title); rfcOk {
				md = rfcMD
				extractorID = "ietf-rfc"
			}
		} else if strings.HasSuffix(hostLower, ".wikipedia.org") || hostLower == "wiki.archlinux.org" ||
			strings.Contains(asciiLowerExtractString(boundedRawHTML[:minInt(len(boundedRawHTML), 4000)]), `content="mediawiki`) ||
			strings.Contains(asciiLowerExtractString(boundedRawHTML[:minInt(len(boundedRawHTML), 4000)]), `content='mediawiki`) {
			if wikiMD := cleanMediaWikiMarkdownFullDocGo(md); wikiMD != "" {
				md = wikiMD
				extractorID = "mediawiki"
			}
		} else if baseURL != "" && reArxivAbsURLFullDocGo.MatchString(baseURL) {
			md = cleanArxivAbstractMarkdownFullDocGo(md)
		}

		// Schema.org `articleBody` & `<noscript>` SSR rescue when DOM yielded <30 words
		mdWords := countTextWordsFullDocGo(md)
		if mdWords < 30 && schemaMeta.articleBody != "" {
			schemaWords := countTextWordsFullDocGo(schemaMeta.articleBody)
			minReq := mdWords * 2
			if minReq < 40 {
				minReq = 40
			}
			if schemaWords > minReq {
				var cleanSchemaMD string
				if strings.IndexByte(schemaMeta.articleBody, '<') >= 0 {
					cleanSchemaMD = cleanInlineHTMLFullDocGo(schemaMeta.articleBody)
				} else {
					cleanSchemaMD = strings.TrimSpace(DecodeHTMLEntities(schemaMeta.articleBody))
				}
				if cleanSchemaMD != "" {
					if title != "" && !strings.HasPrefix(cleanSchemaMD, "# ") {
						md = "# " + title + "\n\n" + cleanSchemaMD
					} else {
						md = cleanSchemaMD
					}
				}
			}
		} else if mdWords < 25 && len(noscriptChunks) > 0 {
			rescued := ExtractHTMLDocumentFull(strings.Join(noscriptChunks, "\n\n"), FullExtractOptions{
				BaseURL:         baseURL,
				OnlyMainContent: false,
				IncludeImages:   includeImages,
			})
			minReq := mdWords * 2
			if minReq < 35 {
				minReq = 35
			}
			if countTextWordsFullDocGo(rescued.Markdown) > minReq {
				md = rescued.Markdown
				if len(links) == 0 && len(rescued.Links) > 0 {
					links = rescued.Links
				}
			}
		}

		// Inertia.js SSR `data-page` hydration unlock when prose <50 words
		if countTextWordsFullDocGo(md) < 50 &&
			(strings.Contains(boundedRawHTML, `data-page="{&quot;component&quot;`) || strings.Contains(boundedRawHTML, `data-page='{"component"`)) {
			if inertiaBytes, inOk := extractInertiaDataPageBytesGo(boundedRawHTML); inOk {
				var inertiaProps map[string]any
				if err := json.Unmarshal(inertiaBytes, &inertiaProps); err == nil {
					if inertiaDoc := FormatInertiaPagePropsToMarkdown(inertiaProps, baseURL); inertiaDoc != nil && strings.TrimSpace(inertiaDoc.Markdown) != "" {
						md = inertiaDoc.Markdown
						if inertiaDoc.Title != "" && title == "" {
							title = inertiaDoc.Title
						}
						if inertiaDoc.Description != "" && description == "" {
							description = inertiaDoc.Description
						}
						inertiaHydrated = true
					}
				}
			}
		}
	}

	var plainText string
	if !opts.IsFragment {
		switch {
		case ytMeta != nil:
			plainText = ytMeta.Markdown
		case hnExtracted != nil:
			plainText = hnExtracted.markdown
		case inertiaHydrated:
			plainText = md
		default:
			plainText = cleanInlineHTMLFullDocGo(work)
		}
	}

	if redactPII {
		md = redactPIIMarkdownSafeFullDocGo(md)
		plainText = redactPIIMarkdownSafeFullDocGo(plainText)
	}

	rawSanitizedMD := SanitizeMarkdownWithOptions(md, baseURL, opts.AllowPdfPageMarkers)
	plainText = stripInvisibleSmugglingCharsGo(plainText)

	if redactPII {
		title = redactPIIMarkdownSafeFullDocGo(title)
		description = redactPIIMarkdownSafeFullDocGo(description)
		author = redactPIIMarkdownSafeFullDocGo(author)
		siteName = redactPIIMarkdownSafeFullDocGo(siteName)
	}
	title = SanitizeScrapedMetadataField(title, 512)
	description = SanitizeScrapedMetadataField(description, 2000)
	author = SanitizeScrapedMetadataField(author, 256)
	siteName = SanitizeScrapedMetadataField(siteName, 256)
	robotsMeta = SanitizeScrapedMetadataField(robotsMeta, 256)
	publishedTime = SanitizeScrapedTimestampField(publishedTime, 128)
	modifiedTime = SanitizeScrapedTimestampField(modifiedTime, 128)

	finalMD := rawSanitizedMD
	totalChars := len(rawSanitizedMD)
	returnedChars := totalChars
	truncated := false
	var nextOffset *int
	if opts.Offset > 0 || opts.MaxChars > 0 {
		finalMD, totalChars, returnedChars, truncated, nextOffset = sliceMarkdownWithOffsetAndMaxCharsFullDocGo(
			rawSanitizedMD, opts.Offset, opts.MaxChars, opts.AllowPdfPageMarkers,
		)
	}
	wordCount := countTextWordsFullDocGo(finalMD)
	if links == nil {
		links = []string{}
	}
	if images == nil {
		images = []ImageInfo{}
	}

	branding := BrandingProfile{
		Title:        title,
		Description:  description,
		CanonicalURL: canonicalURL,
		Favicon:      favicon,
		Logo:         logo,
		OGImage:      ogImage,
		ThemeColor:   themeColor,
		Colors:       colors,
		Fonts:        fonts,
	}

	if siteTruncated != nil && *siteTruncated {
		truncated = true
	}
	return ExtractedDocumentFull{
		Title:                title,
		Description:          description,
		Author:               author,
		PublishedTime:        publishedTime,
		ModifiedTime:         modifiedTime,
		SiteName:             siteName,
		WordCount:            wordCount,
		Language:             language,
		Favicon:              favicon,
		OGImage:              ogImage,
		CanonicalURL:         canonicalURL,
		MarkdownAlternateURL: markdownAlternateURL,
		RobotsMeta:           robotsMeta,
		ExtractorID:          extractorID,
		Records:              siteRecords,
		Total:                siteTotal,
		Returned:             siteReturned,
		NextCursor:           siteNextCursor,
		InertiaHydrated:      inertiaHydrated,
		Markdown:             finalMD,
		RawSanitizedMarkdown: rawSanitizedMD,
		Text:                 plainText,
		Links:                links,
		Images:               images,
		Branding:             branding,
		StructuredData:       jsonLdEntities,
		TotalChars:           totalChars,
		ReturnedChars:        returnedChars,
		Truncated:            truncated,
		NextOffset:           nextOffset,
	}
}

func firstNonEmptyFullDocGo(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func stripMarkdownImagesLinearFullDocGo(prose string) string {
	if !strings.Contains(prose, "![") {
		return prose
	}
	lines := strings.Split(prose, "\n")
	changed := false
	for li, line := range lines {
		if !strings.Contains(line, "![") {
			continue
		}
		cursors := newMdLineCursorsGo()
		var out strings.Builder
		lastIdx := 0
		i := 0
		for i < len(line) {
			ch := line[i]
			if ch == '`' && !isBackslashEscapedAt(line, i) {
				tEnd, sEnd := scanCodeSpanEndLinearGo(line, i, cursors)
				if sEnd > 0 {
					i = sEnd
				} else {
					i = tEnd
				}
				continue
			}
			if ch == '!' && !isBackslashEscapedAt(line, i) {
				if tok := tryParseMarkdownLinkOrImageAtGo(line, i, cursors, false); tok != nil && tok.isImage {
					out.WriteString(line[lastIdx:i])
					i = tok.end
					lastIdx = i
					changed = true
					continue
				}
			}
			i++
		}
		if lastIdx > 0 {
			out.WriteString(line[lastIdx:])
			lines[li] = out.String()
		}
	}
	if !changed {
		return prose
	}
	return strings.Join(lines, "\n")
}

func dehyphenatePDFProseFullDocGo(part string) string {
	if !strings.Contains(part, "-\n") && !strings.Contains(part, "-\r\n") {
		return part
	}
	var sb strings.Builder
	sb.Grow(len(part))
	lastCopy := 0
	i := 0
	n := len(part)
	for i < n {
		if part[i] != '-' {
			i++
			continue
		}
		nlStart := i + 1
		nlEnd := -1
		if nlStart < n && part[nlStart] == '\n' {
			nlEnd = nlStart + 1
		} else if nlStart+1 < n && part[nlStart] == '\r' && part[nlStart+1] == '\n' {
			nlEnd = nlStart + 2
		}
		if nlEnd < 0 {
			i++
			continue
		}
		// Walk backward 1..64 ASCII alnum chars and verify preceding byte is NOT ASCII alnum.
		lStart := i
		for lStart > lastCopy && i-lStart < 64 && isASCIIAlnumExtract(part[lStart-1]) {
			lStart--
		}
		leftLen := i - lStart
		if leftLen < 1 || (lStart > 0 && isASCIIAlnumExtract(part[lStart-1])) {
			i = nlEnd
			continue
		}
		rStart := nlEnd
		for rStart < n && rStart-nlEnd < 32 && (part[rStart] == ' ' || part[rStart] == '\t') {
			rStart++
		}
		rEnd := rStart
		for rEnd < n && rEnd-rStart < 64 && isASCIIAlphaExtract(part[rEnd]) {
			rEnd++
		}
		if rEnd == rStart {
			i = nlEnd
			continue
		}
		left := part[lStart:i]
		right := part[rStart:rEnd]
		keepHyphen := (left[len(left)-1] >= '0' && left[len(left)-1] <= '9') ||
			(right[0] >= 'A' && right[0] <= 'Z') ||
			pdfCompoundPrefixesFullDocGo[strings.ToLower(left)]
		sb.WriteString(part[lastCopy:lStart])
		if keepHyphen {
			sb.WriteString(left + "-" + right)
		} else {
			sb.WriteString(left + right)
		}
		lastCopy = rEnd
		i = rEnd
	}
	if lastCopy == 0 {
		return part
	}
	sb.WriteString(part[lastCopy:])
	return sb.String()
}

// CleanPDFMarkdown normalizes Poppler / OCR PDF layout whitespace (column-alignment spaces and line-wrap hyphenations)
// while leaving fenced code blocks untouched.
func CleanPDFMarkdown(md string) string {
	if md == "" {
		return md
	}
	bounded := truncateUTF8SafeFullDocGo(md, maxHTMLScanCharsFullDocGo)
	parts := SplitMarkdownByCodeFences(bounded)
	for idx, part := range parts {
		if idx%2 == 1 {
			continue
		}
		dehyph := dehyphenatePDFProseFullDocGo(part)
		lines := strings.Split(dehyph, "\n")
		for li, line := range lines {
			trimmedStart := strings.TrimLeft(line, " \t")
			if strings.HasPrefix(trimmedStart, "|") {
				lines[li] = strings.TrimRight(line, " \t\r")
			} else {
				lines[li] = reSpaceRun.ReplaceAllString(strings.TrimSpace(line), " ")
			}
		}
		parts[idx] = collapseExcessBlankLinesGo(strings.Join(lines, "\n"))
	}
	return strings.TrimSpace(strings.Join(parts, ""))
}

// ExtractPDFTitle derives a clean document title from extracted PDF Markdown, skipping copyright/conference boilerplate
// and falling back to the URL filename when needed.
func ExtractPDFTitle(md, urlStr string) string {
	head := strings.ReplaceAll(truncateUTF8SafeFullDocGo(md, 2400), "\r\n", "\n")
	var paragraphs []string
	for _, rawP := range strings.Split(head, "\n\n") {
		p := strings.TrimSpace(rawP)
		if p != "" {
			paragraphs = append(paragraphs, p)
			if len(paragraphs) >= 6 {
				break
			}
		}
	}
	var candidateParagraphs []string
	for _, p := range paragraphs {
		if !rePDFBoilerplateFullDocGo.MatchString(p) {
			candidateParagraphs = append(candidateParagraphs, p)
		}
	}
	scanSource := candidateParagraphs
	if len(scanSource) == 0 {
		scanSource = paragraphs
	}
	var scanLines []string
	for _, p := range scanSource {
		scanLines = append(scanLines, strings.Split(p, "\n")...)
	}
	limit := len(scanLines)
	if limit > 14 {
		limit = 14
	}
	for _, rawLine := range scanLines[:limit] {
		line := strings.TrimLeft(rawLine, "#")
		line = strings.Join(strings.Fields(line), " ")
		if len(line) < 3 || len(line) > 120 {
			continue
		}
		if rePDFSkipTitleLineFullDocGo.MatchString(line) {
			continue
		}
		hasLower := false
		for i := 0; i < len(line); i++ {
			if line[i] >= 'a' && line[i] <= 'z' {
				hasLower = true
				break
			}
		}
		if !hasLower && rePDFAllCapsLineFullDocGo.MatchString(line) {
			words := strings.Fields(strings.ToLower(line))
			for wi, w := range words {
				if len(w) > 0 && w[0] >= 'a' && w[0] <= 'z' {
					words[wi] = strings.ToUpper(w[:1]) + w[1:]
				}
			}
			return strings.Join(words, " ")
		}
		return line
	}
	if urlStr != "" {
		if u, err := url.Parse(urlStr); err == nil {
			segs := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(segs) > 0 && segs[len(segs)-1] != "" {
				lastSeg := segs[len(segs)-1]
				if dec, err := url.PathUnescape(lastSeg); err == nil {
					lastSeg = dec
				}
				if strings.HasSuffix(strings.ToLower(lastSeg), ".pdf") {
					lastSeg = lastSeg[:len(lastSeg)-4]
				}
				cleaned := strings.NewReplacer("-", " ", "_", " ").Replace(lastSeg)
				cleaned = strings.Join(strings.Fields(cleaned), " ")
				if cleaned != "" {
					return cleaned
				}
			}
		}
	}
	return ""
}

func sanitizeFrontmatterFieldTextFullDocGo(raw string) string {
	s := raw
	if strings.Contains(s, "<!--") {
		s = stripHTMLCommentsLinearFullDocGo(s, 4096)
	}
	if strings.IndexByte(s, '<') >= 0 {
		s = stripHTMLTagsLinearFullDocGo(s, []string{"script", "style", "iframe", "svg", "noscript", "template"}, " ", 4096)
	}
	if strings.IndexByte(s, '<') >= 0 {
		s = stripHTMLTagsQuoteAwareLinearFullDocGo(s, " ", 4096)
	}
	decoded := strings.Join(strings.Fields(stripInvisibleSmugglingCharsGo(DecodeHTMLEntities(s))), " ")
	return SanitizeScrapedMetadataField(decoded, 2000)
}

// ParseMarkdownFrontmatter parses and strips a leading YAML `---` frontmatter block (up to 4 KiB),
// returning sanitized `title`, `description`, and remaining `body`.
func ParseMarkdownFrontmatter(md string) (title, description, body string) {
	if !strings.HasPrefix(md, "---") {
		return "", "", md
	}
	headRaw := truncateUTF8SafeFullDocGo(md, 4300)
	head := strings.ReplaceAll(headRaw, "\r\n", "\n")
	if !strings.HasPrefix(head, "---\n") {
		return "", "", md
	}
	closeRel := strings.Index(head[4:], "\n---")
	if closeRel < 0 {
		return "", "", md
	}
	closeIdx := 4 + closeRel
	if closeIdx > 4004 {
		return "", "", md
	}
	afterClose := closeIdx + 4
	if afterClose < len(head) && head[afterClose] != '\n' {
		return "", "", md
	}

	fmBlock := head[4:closeIdx]
	hasYamlKV := false
	for _, line := range strings.Split(fmBlock, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		colonIdx := strings.IndexByte(trimmedLine, ':')
		if colonIdx <= 0 || colonIdx > 64 {
			continue
		}
		rawKey := strings.TrimRight(trimmedLine[:colonIdx], " \t")
		if rawKey == "" {
			continue
		}
		validKey := true
		for i := 0; i < len(rawKey); i++ {
			c := rawKey[i]
			if !(isASCIIAlnumExtract(c) || c == '_' || c == '-') {
				validKey = false
				break
			}
		}
		if !validKey {
			continue
		}
		hasYamlKV = true
		k := strings.ToLower(rawKey)
		v := strings.TrimSpace(trimmedLine[colonIdx+1:])
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = strings.TrimSpace(v[1 : len(v)-1])
		}
		if k == "title" && v != "" && title == "" {
			title = sanitizeFrontmatterFieldTextFullDocGo(v)
		} else if k == "description" && v != "" && description == "" {
			description = sanitizeFrontmatterFieldTextFullDocGo(v)
		}
	}
	if !hasYamlKV {
		return "", "", md
	}

	// Advance past matching `---` + following blank lines in original `md` (supporting both `\n` and `\r\n`).
	pos := 3
	if pos < len(md) && md[pos] == '\r' {
		pos++
	}
	if pos < len(md) && md[pos] == '\n' {
		pos++
	}
	for pos < len(md) {
		nlRel := strings.IndexByte(md[pos:], '\n')
		var lineEnd, nextLine int
		if nlRel < 0 {
			lineEnd = len(md)
			nextLine = len(md)
		} else {
			lineEnd = pos + nlRel
			nextLine = lineEnd + 1
		}
		lineContent := strings.TrimSuffix(md[pos:lineEnd], "\r")
		if lineContent == "---" {
			pos = nextLine
			for pos < len(md) {
				if md[pos] == '\n' {
					pos++
				} else if pos+1 < len(md) && md[pos] == '\r' && md[pos+1] == '\n' {
					pos += 2
				} else {
					break
				}
			}
			return title, description, md[pos:]
		}
		pos = nextLine
	}
	return title, description, md
}

// ExtractMarkdownLinksAndImages scans non-fenced Markdown prose in O(N) time and returns resolved
// HTTP/HTTPS links (up to 250) and non-decorative images (up to 60).
func ExtractMarkdownLinksAndImages(md, baseURL string) (links []string, images []ImageInfo) {
	bounded := truncateUTF8SafeFullDocGo(md, maxHTMLScanCharsFullDocGo)
	_, _, fmBody := ParseMarkdownFrontmatter(bounded)
	parts := SplitMarkdownByCodeFences(fmBody)
	var proseSegs []string
	for idx, p := range parts {
		if idx%2 == 0 {
			proseSegs = append(proseSegs, p)
		}
	}
	proseOnly := strings.Join(proseSegs, "\n")

	links = make([]string, 0)
	seenLinks := make(map[string]bool)
	images = make([]ImageInfo, 0)
	seenImages := make(map[string]bool)

	var collectFromLine func(line string)
	collectFromLine = func(line string) {
		if !strings.Contains(line, "](") && strings.IndexByte(line, '<') < 0 {
			return
		}
		cursors := newMdLineCursorsGo()
		nextGt := -1
		noGtLeft := false
		i := 0
		for i < len(line) {
			if len(links) >= 250 && len(images) >= 60 {
				break
			}
			ch := line[i]
			if ch == '`' {
				if isBackslashEscapedAt(line, i) {
					i++
					continue
				}
				tEnd, sEnd := scanCodeSpanEndLinearGo(line, i, cursors)
				if sEnd > 0 {
					i = sEnd
				} else {
					i = tEnd
				}
				continue
			}
			if ch == '<' && !noGtLeft && len(links) < 250 {
				if nextGt <= i {
					rel := strings.IndexByte(line[i+1:], '>')
					if rel < 0 {
						noGtLeft = true
					} else {
						nextGt = i + 1 + rel
					}
				}
				if !noGtLeft && nextGt > i+8 && nextGt-i <= 2048 {
					autoCand := line[i+1 : nextGt]
					if isValidHttpAutolinkGo(autoCand) {
						if resolved := resolveHTTPSHrefFullDocGo(autoCand, baseURL, false); resolved != "" && !seenLinks[resolved] {
							seenLinks[resolved] = true
							links = append(links, resolved)
						}
						i = nextGt + 1
						continue
					}
				}
			}
			if (ch == '!' || ch == '[') && !isBackslashEscapedAt(line, i) {
				if tok := tryParseMarkdownLinkOrImageAtGo(line, i, cursors, true); tok != nil {
					rawHref := strings.TrimSpace(tok.rawURL)
					if tok.isImage {
						if len(images) < 60 && rawHref != "" && !isDisallowedMarkdownLinkDestinationGo(rawHref) {
							alt := strings.TrimSpace(tok.rawLabel)
							if resolved := resolveHTTPSHrefFullDocGo(rawHref, baseURL, false); resolved != "" && !seenImages[resolved] && !isTinyOrAvatarImageURLFullDocGo(resolved, alt) {
								seenImages[resolved] = true
								images = append(images, ImageInfo{URL: resolved, Alt: alt})
							}
						}
					} else {
						if strings.Contains(tok.rawLabel, "![") && len(images) < 60 {
							collectFromLine(tok.rawLabel)
						}
						if len(links) < 250 && rawHref != "" && !strings.HasPrefix(rawHref, "#") && !isDisallowedMarkdownLinkDestinationGo(rawHref) {
							if resolved := resolveHTTPSHrefFullDocGo(rawHref, baseURL, false); resolved != "" && !seenLinks[resolved] {
								seenLinks[resolved] = true
								links = append(links, resolved)
							}
						}
					}
					i = tok.end
					continue
				}
			}
			i++
		}
	}

	for _, rawLine := range strings.Split(strings.ReplaceAll(proseOnly, "\r\n", "\n"), "\n") {
		if len(links) >= 250 && len(images) >= 60 {
			break
		}
		collectFromLine(rawLine)
	}
	return links, images
}

// ExtractMarkdownLinksImagesAndMeta extracts resolved links, optional images, and frontmatter/H1 title + description.
func ExtractMarkdownLinksImagesAndMeta(md, baseURL string, includeImages bool) (links []string, images []ImageInfo, title, description string) {
	bounded := truncateUTF8SafeFullDocGo(md, maxHTMLScanCharsFullDocGo)
	fmTitle, fmDesc, fmBody := ParseMarkdownFrontmatter(bounded)
	title = fmTitle
	description = fmDesc
	links, images = ExtractMarkdownLinksAndImages(bounded, baseURL)
	if !includeImages {
		images = []ImageInfo{}
	}
	if title == "" {
		proseSegs := SplitMarkdownByCodeFences(fmBody)
		for idx, seg := range proseSegs {
			if idx%2 != 0 {
				continue
			}
			for _, rawLine := range strings.Split(strings.ReplaceAll(seg, "\r\n", "\n"), "\n") {
				trimmed := strings.TrimSpace(rawLine)
				if trimmed == "" || strings.HasPrefix(trimmed, ">") {
					continue
				}
				if strings.HasPrefix(trimmed, "# ") || strings.HasPrefix(trimmed, "#\t") {
					h1Raw := strings.TrimSpace(trimmed[1:])
					cleanH1 := sanitizeFrontmatterFieldTextFullDocGo(stripMarkdownLinksToLabelsLinearFmtGo(h1Raw))
					if cleanH1 != "" {
						title = cleanH1
						break
					}
				}
			}
			if title != "" {
				break
			}
		}
	}
	return links, images, title, description
}

// CollapseAnimatedCounterTickers dedupes animated slot/ticker counter clones
// (`"382,831,172 3 8 2, 8 3 1, 1 7 2"` -> `"382,831,172"`) in linear O(N) time.
func CollapseAnimatedCounterTickers(prose string) string {
	hasComma := strings.IndexByte(prose, ',') >= 0
	if !hasComma {
		run := 0
		has4Digits := false
		for i := 0; i < len(prose); i++ {
			if prose[i] >= '0' && prose[i] <= '9' {
				run++
				if run >= 4 {
					has4Digits = true
					break
				}
			} else {
				run = 0
			}
		}
		if !has4Digits {
			return prose
		}
	}

	var out strings.Builder
	lastCopy := 0
	i := 0
	n := len(prose)

	stepTickerWS := func(idx int) (int, bool) {
		if idx >= n {
			return 0, false
		}
		if prose[idx] == ' ' || prose[idx] == '\t' {
			return 1, true
		}
		if idx+1 < n && prose[idx] == 0xC2 && prose[idx+1] == 0xA0 { // UTF-8 NBSP (\u00a0)
			return 2, true
		}
		return 0, false
	}

	for i < n {
		c := prose[i]
		var prev byte
		if i > 0 {
			prev = prose[i-1]
		}
		if c >= '0' && c <= '9' && !((prev >= '0' && prev <= '9') || prev == ',') {
			j := i
			var digits strings.Builder
			commas := 0
			for j < n {
				ch := prose[j]
				if ch >= '0' && ch <= '9' {
					digits.WriteByte(ch)
					j++
				} else if ch == ',' && j > i && j+1 < n && prose[j+1] >= '0' && prose[j+1] <= '9' {
					commas++
					j++
				} else {
					break
				}
			}
			dStr := digits.String()
			if (commas >= 1 || len(dStr) >= 4) && len(dStr) >= 4 && j < n {
				keepEnd := j
				for keepEnd < n && (prose[keepEnd] == '*' || prose[keepEnd] == '_') {
					keepEnd++
				}
				k := keepEnd
				leadNL := 0
				for k < n {
					if w, ok := stepTickerWS(k); ok {
						k += w
					} else if prose[k] == '\n' && leadNL < 2 {
						leadNL++
						k++
					} else {
						break
					}
				}
				if k > keepEnd {
					var tDigits strings.Builder
					tSpaces := 0
					m := k
					lastAcceptedEnd := k
					for m < n && tDigits.Len() < len(dStr) {
						mc := prose[m]
						if mc >= '0' && mc <= '9' {
							tDigits.WriteByte(mc)
							m++
							lastAcceptedEnd = m
						} else if mc == ',' {
							m++
						} else if w, ok := stepTickerWS(m); ok {
							tSpaces++
							m += w
						} else if mc == '\n' {
							tSpaces++
							m++
						} else {
							break
						}
					}
					var nextAfter byte
					if lastAcceptedEnd < n {
						nextAfter = prose[lastAcceptedEnd]
					}
					minReqSpaces := 2
					if commas == 0 {
						minReqSpaces = len(dStr) - 1
						if minReqSpaces < 3 {
							minReqSpaces = 3
						}
					}
					if tDigits.String() == dStr && tSpaces >= minReqSpaces && !(nextAfter >= '0' && nextAfter <= '9') {
						out.WriteString(prose[lastCopy:keepEnd])
						lastCopy = lastAcceptedEnd
						i = lastAcceptedEnd
						continue
					}
				}
			}
			if j > i {
				i = j
			} else {
				i++
			}
			continue
		}
		i++
	}
	if lastCopy == 0 {
		return prose
	}
	out.WriteString(prose[lastCopy:])
	return out.String()
}

func closeUnclosedInlineCodeInFinalProseFullDocGo(lastProse string) (string, bool) {
	if strings.IndexByte(lastProse, '`') < 0 {
		return lastProse, false
	}
	// Scan only the final blank-line-delimited paragraph.
	tailStart := 0
	lines := strings.Split(lastProse, "\n")
	curOffset := 0
	for _, ln := range lines {
		if isBlankASCIILineGo(ln) {
			tailStart = curOffset + len(ln) + 1
		}
		curOffset += len(ln) + 1
	}
	if tailStart > len(lastProse) {
		tailStart = len(lastProse)
	}
	tailPara := lastProse[tailStart:]
	hasBS := strings.IndexByte(tailPara, '\\') >= 0
	p := 0
	openTickLen := 0
	for p < len(tailPara) {
		rel := strings.IndexByte(tailPara[p:], '`')
		if rel < 0 {
			break
		}
		p += rel
		if hasBS && isBackslashEscapedAt(tailPara, p) {
			p++
			continue
		}
		tEnd := p + 1
		for tEnd < len(tailPara) && tailPara[tEnd] == '`' {
			tEnd++
		}
		want := tEnd - p
		q := tEnd
		matchedEnd := -1
		for q < len(tailPara) {
			hitRel := strings.IndexByte(tailPara[q:], '`')
			if hitRel < 0 {
				break
			}
			hit := q + hitRel
			rEnd := hit + 1
			for rEnd < len(tailPara) && tailPara[rEnd] == '`' {
				rEnd++
			}
			if rEnd-hit == want {
				matchedEnd = rEnd
				break
			}
			q = rEnd
		}
		if matchedEnd < 0 {
			openTickLen = want
			break
		}
		p = matchedEnd
	}
	if openTickLen == 0 {
		return lastProse, false
	}
	trimmedRight := strings.TrimRight(lastProse, " \t\r\n")
	trailingWS := lastProse[len(trimmedRight):]
	pad := ""
	if strings.HasSuffix(trimmedRight, "`") {
		pad = " "
	}
	return trimmedRight + pad + strings.Repeat("`", openTickLen) + trailingWS, true
}

func sanitizeMarkdownPageSliceFullDocGo(fullMD string, safeOffset int, rawSlice string, allowPdfPageMarkers bool) string {
	if rawSlice == "" {
		return ""
	}
	reconstructed := rawSlice
	forceLeadingNL := false

	if safeOffset > 0 && len(fullMD) > 0 {
		clamped := safeOffset
		if clamped > len(fullMD) {
			clamped = len(fullMD)
		}
		state := mdFenceRecognizerStateGo{prevLineWasASCIIBlank: true}
		pos := 0
		for pos <= clamped && pos <= len(fullMD) {
			nlRel := strings.IndexByte(fullMD[pos:], '\n')
			lineEnd := len(fullMD)
			nextPos := len(fullMD) + 1
			if nlRel >= 0 {
				lineEnd = pos + nlRel
				nextPos = lineEnd + 1
			}
			rawLine := strings.TrimSuffix(fullMD[pos:lineEnd], "\r")
			containsOffset := clamped >= pos && clamped <= lineEnd
			if !containsOffset {
				stepCanonicalMarkdownFenceLineGo(rawLine, &state, true)
				pos = nextPos
				continue
			}
			wasInFence := state.inFence
			prevCh := state.fenceChar
			prevEff := state.effectiveFenceLen
			if state.fenceLen > prevEff {
				prevEff = state.fenceLen
			}
			stepRes := stepCanonicalMarkdownFenceLineGo(rawLine, &state, true)
			firstNL := strings.IndexByte(reconstructed, '\n')
			if stepRes.kind == fenceStepOpenTrustedGo && clamped > pos {
				forceLeadingNL = true
				eff := state.effectiveFenceLen
				if state.fenceLen > eff {
					eff = state.fenceLen
				}
				fenceStr := strings.Repeat(string(state.fenceChar), eff)
				if firstNL >= 0 {
					reconstructed = fenceStr + stepRes.openedInfo + "\n" + reconstructed[firstNL+1:]
				} else {
					reconstructed = fenceStr + "\n" + fenceStr
				}
			} else if wasInFence && stepRes.kind == fenceStepInTrustedGo {
				forceLeadingNL = true
				fenceStr := strings.Repeat(string(prevCh), prevEff)
				reconstructed = fenceStr + "\n" + reconstructed
			} else if stepRes.kind == fenceStepCloseTrustedGo {
				forceLeadingNL = true
				head := reconstructed
				tail := ""
				if firstNL >= 0 {
					head = reconstructed[:firstNL]
					tail = reconstructed[firstNL:]
				}
				var esc strings.Builder
				for i := 0; i < len(head); i++ {
					if head[i] == '`' || head[i] == '~' {
						esc.WriteByte('\\')
					}
					esc.WriteByte(head[i])
				}
				reconstructed = esc.String() + tail
			}
			break
		}
	}

	_, segs := recognizeAndHardenMarkdownFencesGo(reconstructed, true)
	if len(segs) > 0 && (len(segs)-1)%2 == 0 {
		if closedLast, changed := closeUnclosedInlineCodeInFinalProseFullDocGo(segs[len(segs)-1]); changed {
			segs[len(segs)-1] = closedLast
			_, segs = recognizeAndHardenMarkdownFencesGo(strings.Join(segs, ""), true)
		}
	}

	for idx, seg := range segs {
		if idx%2 == 1 {
			segs[idx] = cleanCodeFenceSegmentGo(seg)
			continue
		}
		p := stripInvisibleSmugglingCharsGo(seg)
		p = escapeGfmTaskListCheckboxesLinearGo(p)
		p = neutralizeAllUnsafeMarkdownLinksLinearGo(p)
		p = escapeAllResidualLtInProseLinearGo(p, allowPdfPageMarkers)
		p = escapePostStripProseFencesGo(p)
		segs[idx] = p
	}
	finalOut := strings.Join(segs, "")
	if strings.Contains(finalOut, "```") || strings.Contains(finalOut, "~~~") {
		_, reSegs := recognizeAndHardenMarkdownFencesGo(finalOut, true)
		for idx, seg := range reSegs {
			if idx%2 == 1 {
				reSegs[idx] = cleanCodeFenceSegmentGo(seg)
				continue
			}
			p := stripInvisibleSmugglingCharsGo(seg)
			p = neutralizeAllUnsafeMarkdownLinksLinearGo(p)
			p = escapeAllResidualLtInProseLinearGo(p, allowPdfPageMarkers)
			p = escapePostStripProseFencesGo(p)
			reSegs[idx] = p
		}
		finalOut = strings.Join(reSegs, "")
	}
	if safeOffset > 0 && forceLeadingNL && !strings.HasPrefix(finalOut, "\n\n") {
		if strings.HasPrefix(finalOut, "\n") {
			return "\n" + finalOut
		}
		return "\n\n" + finalOut
	}
	return finalOut
}

func sliceMarkdownWithOffsetAndMaxCharsFullDocGo(
	fullMD string,
	offset int,
	maxChars int,
	allowPdfPageMarkers bool,
) (finalMD string, totalChars, returnedChars int, truncated bool, nextOffset *int) {
	totalChars = len(fullMD)
	safeOffset := offset
	if safeOffset < 0 {
		safeOffset = 0
	}
	if safeOffset > totalChars {
		safeOffset = totalChars
	}
	// Align offset to valid UTF-8 rune boundary.
	for safeOffset > 0 && safeOffset < totalChars && (fullMD[safeOffset]&0xC0) == 0x80 {
		safeOffset--
	}

	windowSrc := fullMD[safeOffset:]
	if maxChars > 0 && len(windowSrc) > maxChars {
		cut := maxChars
		for cut > 0 && cut < len(windowSrc) && (windowSrc[cut]&0xC0) == 0x80 {
			cut--
		}
		minCut := int(float64(maxChars) * 0.6)
		if paraBreak := strings.LastIndex(windowSrc[:cut], "\n\n"); paraBreak >= minCut {
			cut = paraBreak
		} else if lineBreak := strings.LastIndexByte(windowSrc[:cut], '\n'); lineBreak >= minCut {
			cut = lineBreak
		} else if spaceBreak := strings.LastIndexByte(windowSrc[:cut], ' '); spaceBreak >= minCut {
			cut = spaceBreak
		}
		rawSliced := strings.TrimRight(windowSrc[:cut], " \t\r\n")
		step := len(rawSliced)
		if step == 0 {
			step = cut
		}
		nextOff := safeOffset + step
		if nextOff > totalChars {
			nextOff = totalChars
		}
		closed := sanitizeMarkdownPageSliceFullDocGo(fullMD, safeOffset, rawSliced, allowPdfPageMarkers)
		return closed, totalChars, len(closed), true, &nextOff
	}

	if safeOffset > 0 {
		cleanSlice := sanitizeMarkdownPageSliceFullDocGo(fullMD, safeOffset, windowSrc, allowPdfPageMarkers)
		return cleanSlice, totalChars, len(cleanSlice), false, nil
	}
	return windowSrc, totalChars, len(windowSrc), false, nil
}

// FinalizeScrapedMarkdown strips frontmatter, sanitizes inline HTML and unsafe Markdown links, collapses animated
// counter tickers, optionally normalizes PDF layout whitespace, and applies offset/maxChars pagination with
// automatic code-fence / code-span closure.
func FinalizeScrapedMarkdown(md, baseURL string, opts FullExtractOptions) (finalMD string, totalChars, returnedChars int, truncated bool, nextOffset *int) {
	effectiveBase := strings.TrimSpace(baseURL)
	if effectiveBase == "" {
		effectiveBase = strings.TrimSpace(opts.BaseURL)
	}
	bounded := truncateUTF8SafeFullDocGo(md, maxSanitizeMarkdownScanBytes)
	body := bounded
	if !opts.IsPDF {
		_, _, body = ParseMarkdownFrontmatter(bounded)
	}
	bodyTrimmed := strings.TrimSpace(body)
	if bodyTrimmed == "" {
		return "", 0, 0, false, nil
	}

	if opts.PreserveOriginMD && strings.Contains(bodyTrimmed, "schema.org") {
		parts := SplitMarkdownByCodeFences(bodyTrimmed)
		for idx, part := range parts {
			if idx%2 == 1 && len(part) < 32768 && strings.Contains(part, "schema.org") {
				if reSchemaFenceOnlyFullDocGo.MatchString(strings.TrimSpace(part)) {
					parts[idx] = ""
				}
			}
		}
		bodyTrimmed = strings.Join(parts, "")
	}

	sanitized := SanitizeMarkdownWithOptions(bodyTrimmed, effectiveBase, opts.AllowPdfPageMarkers)
	if !opts.PreserveOriginMD && !opts.IsPDF {
		parts := SplitMarkdownByCodeFences(sanitized)
		for idx, seg := range parts {
			if idx%2 == 0 {
				parts[idx] = CollapseAnimatedCounterTickers(seg)
			}
		}
		sanitized = strings.Join(parts, "")
	}
	if opts.IsPDF {
		sanitized = CleanPDFMarkdown(sanitized)
	}
	if !opts.IncludeImages && strings.Contains(sanitized, "![") {
		parts := SplitMarkdownByCodeFences(sanitized)
		for idx, seg := range parts {
			if idx%2 == 0 {
				parts[idx] = stripMarkdownImagesLinearFullDocGo(seg)
			}
		}
		sanitized = strings.Join(parts, "")
	}
	if opts.RedactPII {
		sanitized = redactPIIMarkdownSafeFullDocGo(sanitized)
	}
	sanitized = SanitizeMarkdownWithOptions(sanitized, effectiveBase, opts.AllowPdfPageMarkers)
	sanitized = trimASCIIWhitespaceLinearGo(collapseExcessBlankLinesGo(sanitized))
	return sliceMarkdownWithOffsetAndMaxCharsFullDocGo(sanitized, opts.Offset, opts.MaxChars, opts.AllowPdfPageMarkers)
}
