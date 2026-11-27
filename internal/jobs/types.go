// Package jobs implements EdgeFetch's pure-CPU job & ATS intelligence engine:
// compensation & workplace normalization, Schema.org JobPosting JSON-LD extraction,
// EEO/AI boilerplate classification, JSON record chunking, 18+ ATS board/posting
// adapters & auto-discovery, company/domain anti-spoofing filters, redirect loss
// diagnostics, HTTP 402 / x402 payment-term sanitization, and ethical blocked hints.
//
// Zero net/http or crypto/tls imports are permitted in WASM-compiled files so
// edgefetch-core.wasm stays well within Cloudflare Workers' bundle budget.
package jobs

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// PayPeriod enumerates normalized compensation intervals.
type PayPeriod string

const (
	PayPeriodYear  PayPeriod = "year"
	PayPeriodMonth PayPeriod = "month"
	PayPeriodWeek  PayPeriod = "week"
	PayPeriodDay   PayPeriod = "day"
	PayPeriodHour  PayPeriod = "hour"
)

// PayBasis classifies compensation as base salary, OTE, or total target cash/comp.
type PayBasis string

const (
	PayBasisBase  PayBasis = "base"
	PayBasisOTE   PayBasis = "ote"
	PayBasisTotal PayBasis = "total"
)

// WorkplaceType classifies remote, hybrid, onsite, or unknown work arrangements.
type WorkplaceType string

const (
	WorkplaceRemote  WorkplaceType = "remote"
	WorkplaceHybrid  WorkplaceType = "hybrid"
	WorkplaceOnsite  WorkplaceType = "onsite"
	WorkplaceUnknown WorkplaceType = "unknown"
)

// ATSBoardStatus classifies an ATS board probe into 6 deterministic outcomes.
type ATSBoardStatus string

const (
	BoardStatusOK              ATSBoardStatus = "ok"
	BoardStatusEmptyBoard      ATSBoardStatus = "empty_board"
	BoardStatusWrongSlug       ATSBoardStatus = "wrong_slug"
	BoardStatusBlockedOrDown   ATSBoardStatus = "blocked_or_down"
	BoardStatusNotFound        ATSBoardStatus = "not_found"
	BoardStatusBudgetExhausted ATSBoardStatus = "budget_exhausted"
)

// VerifiedPostingStatus enumerates saved-posting batch verification states.
type VerifiedPostingStatus string

const (
	PostingStatusLive      VerifiedPostingStatus = "live"
	PostingStatusClosed    VerifiedPostingStatus = "closed"
	PostingStatusBoardGone VerifiedPostingStatus = "board_gone"
	PostingStatusUnknown   VerifiedPostingStatus = "unknown"
)

// DiscoveredATSBoard describes an ATS job board discovered from a company domain or HTML page.
type DiscoveredATSBoard struct {
	Domain         string         `json:"domain,omitempty"`
	Platform       string         `json:"platform"`
	Slug           string         `json:"slug"`
	BoardURL       string         `json:"boardUrl"`
	DiscoveredFrom string         `json:"discoveredFrom"`
	BoardStatus    ATSBoardStatus `json:"boardStatus,omitempty"`
	Tried          []string       `json:"tried,omitempty"`
	Total          *int           `json:"total,omitempty"`
	Returned       *int           `json:"returned,omitempty"`
	Truncated      *bool          `json:"truncated,omitempty"`
	NextCursor     string         `json:"nextCursor,omitempty"`
}

// NormalizedPay holds standardized compensation bounds, currency, period, and basis.
type NormalizedPay struct {
	Min      *float64  `json:"min"`
	Max      *float64  `json:"max"`
	Currency string    `json:"currency"`
	Period   PayPeriod `json:"period"`
	Interval string    `json:"interval,omitempty"`
	Basis    PayBasis  `json:"basis"`
	Raw      string    `json:"raw,omitempty"`
}

// StructuredJobPosting holds single-posting metadata extracted from JSON-LD or ATS APIs.
type StructuredJobPosting struct {
	Title              string         `json:"title"`
	HiringOrganization string         `json:"hiringOrganization,omitempty"`
	JobLocation        []string       `json:"jobLocation,omitempty"`
	JobLocationType    string         `json:"jobLocationType,omitempty"`
	WorkplaceType      WorkplaceType  `json:"workplaceType"`
	BaseSalary         *NormalizedPay `json:"baseSalary"`
	Pay                *NormalizedPay `json:"pay"`
	DatePosted         string         `json:"datePosted,omitempty"`
	ValidThrough       string         `json:"validThrough,omitempty"`
	EmploymentType     string         `json:"employmentType,omitempty"`
	URL                string         `json:"url,omitempty"`
	ApplyURL           string         `json:"applyUrl,omitempty"`
	Source             string         `json:"source,omitempty"`
}

// StructuredJobRecord represents a normalized job listing row across ATS boards and feeds.
type StructuredJobRecord struct {
	Title          string         `json:"title"`
	Company        string         `json:"company"`
	URL            string         `json:"url"`
	ApplyURL       string         `json:"applyUrl"`
	WorkplaceType  WorkplaceType  `json:"workplaceType"`
	Locations      []string       `json:"locations"`
	Pay            *NormalizedPay `json:"pay"`
	PayUnknown     bool           `json:"payUnknown,omitempty"`
	MatchedOn      string         `json:"matchedOn,omitempty"`
	PostedAt       *string        `json:"postedAt"`
	PostedLabel    string         `json:"postedLabel,omitempty"`
	Source         string         `json:"source"`
	EmploymentType string         `json:"employmentType,omitempty"`
	Snippet        string         `json:"snippet,omitempty"`
}

// X402ExtraMetadata holds allowlisted depth-1 x402 token metadata.
type X402ExtraMetadata struct {
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Decimals *int   `json:"decimals,omitempty"`
}

// X402PaymentTerms holds sanitized HTTP 402 / x402 / L402 payment requirements.
type X402PaymentTerms struct {
	X402Version       *int               `json:"x402Version,omitempty"`
	AcceptsCount      *int               `json:"acceptsCount,omitempty"`
	Scheme            string             `json:"scheme,omitempty"`
	Price             string             `json:"price,omitempty"`
	Amount            string             `json:"amount,omitempty"`
	MaxAmountRequired string             `json:"maxAmountRequired,omitempty"`
	Asset             string             `json:"asset,omitempty"`
	Currency          string             `json:"currency,omitempty"`
	Network           string             `json:"network,omitempty"`
	PayTo             string             `json:"payTo,omitempty"`
	Resource          string             `json:"resource,omitempty"`
	Description       string             `json:"description,omitempty"`
	Invoice           string             `json:"invoice,omitempty"`
	Macaroon          string             `json:"macaroon,omitempty"`
	Extra             *X402ExtraMetadata `json:"extra,omitempty"`
}

// IsEmpty reports whether X402PaymentTerms carries zero populated fields.
func (t X402PaymentTerms) IsEmpty() bool {
	return t.X402Version == nil &&
		t.AcceptsCount == nil &&
		t.Scheme == "" &&
		t.Price == "" &&
		t.Amount == "" &&
		t.MaxAmountRequired == "" &&
		t.Asset == "" &&
		t.Currency == "" &&
		t.Network == "" &&
		t.PayTo == "" &&
		t.Resource == "" &&
		t.Description == "" &&
		t.Invoice == "" &&
		t.Macaroon == "" &&
		t.Extra == nil
}

// X402ParseResult pairs the formatted human price summary (if valid) with sanitized X402PaymentTerms.
type X402ParseResult struct {
	Price string           `json:"price,omitempty"`
	Terms X402PaymentTerms `json:"terms"`
}

// BlockedSuggestion provides an ethical alternative when a URL is blocked by robots.txt, Content-Signal, WAF, or HTTP 402.
type BlockedSuggestion struct {
	Reason     string            `json:"reason"`
	Host       string            `json:"host,omitempty"`
	Signal     string            `json:"signal,omitempty"`
	Price      string            `json:"price,omitempty"`
	Terms      *X402PaymentTerms `json:"terms,omitempty"`
	Suggestion string            `json:"suggestion"`
}

// RedirectAnalysis describes material URL redirects and potential dropped filter parameters.
type RedirectAnalysis struct {
	Redirected       bool   `json:"redirected"`
	RedirectNote     string `json:"redirectNote,omitempty"`
	FiltersMayBeLost bool   `json:"filtersMayBeLost,omitempty"`
}

// HTMLToMDFunc converts an HTML fragment into GitHub-Flavored Markdown and extracted links.
type HTMLToMDFunc func(htmlFrag, baseURL string) (markdown string, links []string)

// DefaultHTMLToMD converts an HTML fragment to Markdown using extract.ExtractHTMLDocumentFull.
func DefaultHTMLToMD(frag, base string) (string, []string) {
	if base == "" {
		base = "https://example.com"
	}
	doc := extract.ExtractHTMLDocumentFull("<!doctype html><html><body>"+frag+"</body></html>", extract.FullExtractOptions{
		BaseURL:         base,
		OnlyMainContent: false,
		IncludeImages:   true,
		IsFragment:      true,
	})
	return doc.Markdown, doc.Links
}

// ATSFormattedResult holds the formatted Markdown and structured records produced by an ATS adapter.
type ATSFormattedResult struct {
	Title         string                `json:"title"`
	Description   string                `json:"description,omitempty"`
	PublishedTime string                `json:"publishedTime,omitempty"`
	Markdown      string                `json:"markdown"`
	Links         []string              `json:"links,omitempty"`
	JobPosting    *StructuredJobPosting `json:"jobPosting,omitempty"`
	Jobs          []StructuredJobRecord `json:"jobs,omitempty"`
	Total         *int                  `json:"total,omitempty"`
	Returned      *int                  `json:"returned,omitempty"`
	Truncated     *bool                 `json:"truncated,omitempty"`
	NextCursor    string                `json:"nextCursor,omitempty"`
}

// ATSPreFetchSpec describes how to fetch and format an ATS API twin before scraping HTML.
type ATSPreFetchSpec struct {
	ID          string `json:"id"`
	FetchURL    string `json:"fetchUrl"`
	Method      string `json:"method"`
	RequestBody string `json:"requestBody,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Kind        string `json:"kind"`
	Accept      string `json:"accept"`

	// Internal parsed route metadata used by FormatATSResponse.
	host       string
	org        string
	site       string
	jobID      string
	reqOffset  int
	searchText string
	// serverPaged: the API already applied reqOffset (skip/limit), so the formatter must not slice again and can
	// only infer "more remain" from a full page (Lever does not report a total).
	serverPaged bool
}

// Format parses rawBody into an ATSFormattedResult using htmlToMD (defaulting to DefaultHTMLToMD when nil).
func (s *ATSPreFetchSpec) Format(rawBody, origURL string, htmlToMD HTMLToMDFunc) *ATSFormattedResult {
	if s == nil {
		return nil
	}
	return s.formatWithNow(rawBody, origURL, htmlToMD, time.Now())
}

// PublicJobFeedSpec identifies a robots.txt-allowed public remote job feed.
type PublicJobFeedSpec struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// PublicJobFeeds lists the keyless robots.txt-allowed remote job feeds integrated into jobs.
var PublicJobFeeds = []PublicJobFeedSpec{
	{ID: "weworkremotely", URL: "https://weworkremotely.com/remote-jobs.rss"},
	{ID: "himalayas", URL: "https://himalayas.app/jobs/api?limit=50"},
	{ID: "workingnomads", URL: "https://www.workingnomads.com/api/exposed_jobs/"},
}

var (
	reANSICSIJobs     = newLazyRegexp(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	reMultiSpacesJobs = newLazyRegexp(`\s+`)
	reHexEntityJobs   = newLazyRegexp(`(?i)&#x([0-9a-f]+);`)
	reDecEntityJobs   = newLazyRegexp(`&#(\d+);`)
	namedEntityRepl   = strings.NewReplacer(
		"&nbsp;", " ", "&NBSP;", " ",
		"&amp;", "&", "&AMP;", "&",
		"&lt;", "<", "&LT;", "<",
		"&gt;", ">", "&GT;", ">",
		"&quot;", `"`, "&QUOT;", `"`,
		"&#39;", "'",
		"&apos;", "'", "&APOS;", "'",
		"&dollar;", "$", "&DOLLAR;", "$",
		"&pound;", "£", "&POUND;", "£",
		"&euro;", "€", "&EURO;", "€",
		"&ndash;", "–", "&NDASH;", "–",
		"&mdash;", "—", "&MDASH;", "—",
		"&minus;", "-", "&MINUS;", "-",
	)
)

// DecodeEntitiesBasic decodes common named HTML entities and valid scalar numeric character references.
func DecodeEntitiesBasic(s string) string {
	if s == "" || strings.IndexByte(s, '&') < 0 {
		return s
	}
	out := decodeNamedEntitiesCaseInsensitive(s)
	if strings.Contains(out, "&#") {
		out = reHexEntityJobs.ReplaceAllStringFunc(out, func(m string) string {
			hexStr := m[3 : len(m)-1]
			cp, err := strconv.ParseUint(hexStr, 16, 32)
			if err != nil || cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
				return m
			}
			return string(rune(cp))
		})
		out = reDecEntityJobs.ReplaceAllStringFunc(out, func(m string) string {
			decStr := m[2 : len(m)-1]
			cp, err := strconv.ParseUint(decStr, 10, 32)
			if err != nil || cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
				return m
			}
			return string(rune(cp))
		})
	}
	return out
}

func decodeNamedEntitiesCaseInsensitive(s string) string {
	// Fast path via replacer, then handle any mixed-case entity names like `&Nbsp;`.
	s = namedEntityRepl.Replace(s)
	if strings.IndexByte(s, '&') < 0 {
		return s
	}
	var sb strings.Builder
	i := 0
	for i < len(s) {
		amp := strings.IndexByte(s[i:], '&')
		if amp < 0 {
			sb.WriteString(s[i:])
			break
		}
		amp += i
		sb.WriteString(s[i:amp])
		semi := strings.IndexByte(s[amp:], ';')
		if semi > 1 && semi <= 10 {
			tok := strings.ToLower(s[amp : amp+semi+1])
			var rep string
			switch tok {
			case "&nbsp;":
				rep = " "
			case "&amp;":
				rep = "&"
			case "&lt;":
				rep = "<"
			case "&gt;":
				rep = ">"
			case "&quot;":
				rep = `"`
			case "&apos;":
				rep = "'"
			case "&dollar;":
				rep = "$"
			case "&pound;":
				rep = "£"
			case "&euro;":
				rep = "€"
			case "&ndash;":
				rep = "–"
			case "&mdash;":
				rep = "—"
			case "&minus;":
				rep = "-"
			}
			if rep != "" {
				sb.WriteString(rep)
				i = amp + semi + 1
				continue
			}
		}
		sb.WriteByte('&')
		i = amp + 1
	}
	return sb.String()
}

func isInvisibleJobRune(r rune) bool {
	if r <= 0x08 || r == 0x0B || r == 0x0C || (r >= 0x0E && r <= 0x1F) || (r >= 0x7F && r <= 0x9F) {
		return true
	}
	if r == 0x00AD || r == 0x061C || r == 0x180E || r == 0xFEFF {
		return true
	}
	if (r >= 0x200B && r <= 0x200F) || (r >= 0x2028 && r <= 0x202F) || (r >= 0x2060 && r <= 0x206F) {
		return true
	}
	if (r >= 0xE0000 && r <= 0xE007F) || (r >= 0xE0100 && r <= 0xE01EF) {
		return true
	}
	return false
}

// StripInvisibleJobChars strips ANSI CSI sequences, Unicode Tags (U+E0000..U+E007F),
// Variation Selectors Supplement (U+E0100..U+E01EF), BiDi overrides/isolates, zero-width chars, and C0/C1 controls.
func StripInvisibleJobChars(s string) string {
	if s == "" {
		return ""
	}
	if strings.IndexByte(s, '\x1b') >= 0 {
		s = reANSICSIJobs.ReplaceAllString(s, "")
	}
	needsFilter := false
	for _, r := range s {
		if isInvisibleJobRune(r) {
			needsFilter = true
			break
		}
	}
	if !needsFilter {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if !isInvisibleJobRune(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// StripHTMLTagsQuoteAware strips HTML comments, CDATA wrappers, and quote-aware HTML tags in linear O(N) time.
func StripHTMLTagsQuoteAware(src, replacement string) string {
	if src == "" || strings.IndexByte(src, '<') < 0 {
		return src
	}
	n := len(src)
	var sb strings.Builder
	sb.Grow(n)
	var deadMask []uint8
	nextGtPos := -2
	i := 0
	for i < n {
		lt := strings.IndexByte(src[i:], '<')
		if lt < 0 {
			sb.WriteString(src[i:])
			break
		}
		lt += i
		sb.WriteString(src[i:lt])
		if lt+1 >= n {
			sb.WriteByte('<')
			break
		}
		// HTML comment <!-- ... -->
		if lt+3 < n && src[lt+1] == '!' && src[lt+2] == '-' && src[lt+3] == '-' {
			end := findHTMLCommentEndLinear(src, lt)
			if end > lt {
				sb.WriteString(replacement)
				i = end
				continue
			}
			sb.WriteByte('<')
			i = lt + 1
			continue
		}
		// CDATA <![CDATA[ ... ]]>
		if lt+8 < n && strings.EqualFold(src[lt:lt+9], "<![cdata[") {
			closeIdx := strings.Index(src[lt+9:], "]]>")
			if closeIdx >= 0 {
				sb.WriteString(src[lt+9 : lt+9+closeIdx])
				i = lt + 9 + closeIdx + 3
				continue
			}
		}
		c1 := src[lt+1]
		isTagStart := isASCIIAlphaByte(c1) || c1 == '!' || c1 == '?' || (c1 == '/' && lt+2 < n && isASCIIAlphaByte(src[lt+2]))
		if !isTagStart {
			sb.WriteByte('<')
			i = lt + 1
			continue
		}
		gt := findQuoteAwareTagEnd(src, lt+1, &nextGtPos, &deadMask)
		if gt < 0 {
			sb.WriteByte('<')
			i = lt + 1
			continue
		}
		sb.WriteString(replacement)
		i = gt + 1
	}
	return sb.String()
}

func isASCIIAlphaByte(b byte) bool {
	low := b | 32
	return low >= 'a' && low <= 'z'
}

func findHTMLCommentEndLinear(src string, lt int) int {
	bodyStart := lt + 4
	if bodyStart < len(src) && src[bodyStart] == '>' {
		return bodyStart + 1
	}
	if bodyStart+1 < len(src) && src[bodyStart] == '-' && src[bodyStart+1] == '>' {
		return bodyStart + 2
	}
	std := strings.Index(src[bodyStart:], "-->")
	bang := strings.Index(src[bodyStart:], "--!>")
	if std < 0 && bang < 0 {
		return -1
	}
	if std >= 0 && (bang < 0 || std <= bang) {
		return bodyStart + std + 3
	}
	return bodyStart + bang + 4
}

func findQuoteAwareTagEnd(src string, fromIdx int, nextGtPos *int, deadMask *[]uint8) int {
	if *nextGtPos == -1 {
		return -1
	}
	if *nextGtPos < fromIdx {
		gt := strings.IndexByte(src[fromIdx:], '>')
		if gt < 0 {
			*nextGtPos = -1
			return -1
		}
		*nextGtPos = fromIdx + gt
	}
	mask := *deadMask
	if mask != nil && fromIdx < len(mask) && (mask[fromIdx]&1) != 0 {
		return -1
	}
	state := uint8(0)
	for i := fromIdx; i < len(src); i++ {
		if mask != nil && (mask[i]&(1<<state)) != 0 {
			markDeadPath(src, fromIdx, i, mask)
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
	if mask == nil {
		mask = make([]uint8, len(src))
		*deadMask = mask
	}
	markDeadPath(src, fromIdx, len(src), mask)
	return -1
}

func markDeadPath(src string, fromIdx, stopIdx int, mask []uint8) {
	state := uint8(0)
	for i := fromIdx; i < stopIdx; i++ {
		bit := uint8(1) << state
		if (mask[i] & bit) != 0 {
			break
		}
		mask[i] |= bit
		ch := src[i]
		if state == 1 && ch == '"' {
			state = 0
		} else if state == 2 && ch == '\'' {
			state = 0
		} else if state == 0 && ch == '"' {
			state = 1
		} else if state == 0 && ch == '\'' {
			state = 2
		}
	}
}

// StripTagsPlain removes invisible chars, strips HTML tags, decodes entities, re-strips smuggled invisible chars, and collapses whitespace.
func StripTagsPlain(s string) string {
	if s == "" {
		return ""
	}
	pre := StripInvisibleJobChars(s)
	tagStripped := StripHTMLTagsQuoteAware(pre, " ")
	decoded := DecodeEntitiesBasic(tagStripped)
	clean := StripInvisibleJobChars(decoded)
	return strings.TrimSpace(reMultiSpacesJobs.ReplaceAllString(clean, " "))
}

// SanitizeJobFieldPlain sanitizes plain metadata fields, neutralizing unsafe Markdown links and escaping residual angle brackets.
func SanitizeJobFieldPlain(raw string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 512
	}
	plain := StripTagsPlain(raw)
	if plain == "" {
		return ""
	}
	clean := extract.NeutralizeAllUnsafeMarkdownLinks(plain)
	clean = strings.ReplaceAll(clean, "<", "&lt;")
	clean = strings.ReplaceAll(clean, ">", "&gt;")
	clean = sliceUTF16Max(clean, maxLen)
	return strings.TrimSpace(clean)
}

// SanitizeISOCurrencyCode validates a 3-letter ASCII ISO currency code or returns fallback.
func SanitizeISOCurrencyCode(raw string, fallback string) string {
	if fallback == "" {
		fallback = "USD"
	}
	trimmed := strings.ToUpper(strings.TrimSpace(StripInvisibleJobChars(raw)))
	if len(trimmed) == 3 && trimmed[0] >= 'A' && trimmed[0] <= 'Z' && trimmed[1] >= 'A' && trimmed[1] <= 'Z' && trimmed[2] >= 'A' && trimmed[2] <= 'Z' {
		return trimmed
	}
	return fallback
}

// SafeJSONParse unmarshals JSON after stripping any leading UTF-8 BOM, returning nil on error.
func SafeJSONParse(raw string) any {
	trimmed := strings.TrimPrefix(raw, "\ufeff")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return nil
	}
	var out any
	dec := json.NewDecoder(strings.NewReader(trimmed))
	if err := dec.Decode(&out); err != nil {
		return nil
	}
	return out
}

// MarshalNoEscape serializes v to compact JSON without HTML-escaping `<`, `>`, or `&`.
func MarshalNoEscape(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimRight(buf.String(), "\n")
}

// EncodeURIComponent matches JavaScript encodeURIComponent (preserving A-Z a-z 0-9 - _ . ! ~ * ' ( )).
func EncodeURIComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '!' || b == '~' || b == '*' || b == '\'' || b == '(' || b == ')' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hex[b>>4])
			sb.WriteByte(hex[b&0x0F])
		}
	}
	return sb.String()
}

// DecodeURIComponent matches JavaScript decodeURIComponent (percent-only unescaping + strict UTF-8 check).
func DecodeURIComponent(s string) (string, bool) {
	if strings.IndexByte(s, '%') < 0 {
		return s, utf8.ValidString(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) {
				return "", false
			}
			hi, ok1 := fromHexByte(s[i+1])
			lo, ok2 := fromHexByte(s[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			out = append(out, (hi<<4)|lo)
			i += 2
		} else {
			out = append(out, s[i])
		}
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

func fromHexByte(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	default:
		return 0, false
	}
}

func parseStrictURL(raw string) (*url.URL, bool) {
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n\t ") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.ContainsAny(trimmed, "\x00\r\n\t") {
			return nil, false
		}
		raw = trimmed
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, false
	}
	if p := u.Port(); p != "" {
		pn, err := strconv.Atoi(p)
		if err != nil || pn < 1 || pn > 65535 {
			return nil, false
		}
	}
	if colon := strings.LastIndexByte(u.Host, ':'); colon >= 0 && !strings.HasSuffix(u.Host, "]") {
		portPart := u.Host[colon+1:]
		if portPart != "" {
			pn, err := strconv.Atoi(portPart)
			if err != nil || pn < 1 || pn > 65535 {
				return nil, false
			}
		}
	}
	return u, true
}

func sliceUTF16Max(s string, maxUnits int) string {
	if maxUnits <= 0 || s == "" {
		return ""
	}
	if len(s) <= maxUnits {
		return s
	}
	units := 0
	for idx, r := range s {
		w := 1
		if r >= 0x10000 {
			w = 2
		}
		if units+w > maxUnits {
			return s[:idx]
		}
		units += w
	}
	return s
}

func intPtr(v int) *int       { return &v }
func boolPtr(v bool) *bool    { return &v }
func strPtr(v string) *string { return &v }
