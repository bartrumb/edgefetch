package catalog

import (
	"bytes"
	"encoding/json"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

var (
	reDangerousInlineLinkScheme = newLazyRegexp(`(?i)\]\(\s*(?:javascript|vbscript|data|file|blob):[^)]*\)`)
	reCloseBracketSpaceParen    = newLazyRegexp(`\]\s*\(`)
	reCloseBracketSpaceOpen     = newLazyRegexp(`\]\s*\[`)
	reCloseBracketSpaceColon    = newLazyRegexp(`\]\s*:`)
	reNumericOrHexTLD           = newLazyRegexp(`(?i)^(?:\d+|0x[0-9a-f]+)$`)
	reISOCurrency3              = newLazyRegexp(`^[A-Z]{3}$`)
	reMarkdownImgTag            = newLazyRegexp(`!\[([^\]]*)\]\(([^)\r\n]+)\)`)

	disallowedHostSuffixes = []string{
		".localhost",
		".localhost.localdomain",
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

	disallowedExactHosts = map[string]bool{
		"localhost":                  true,
		"localhost.localdomain":      true,
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

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func strPtrAlways(s string) *string {
	return &s
}

func stripANSICSI(s string) string {
	if !strings.Contains(s, "\x1b[") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	n := len(s)
	for i := 0; i < n; {
		if s[i] == 0x1b && i+1 < n && s[i+1] == '[' {
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
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

func isCommerceInvisibleRune(r rune) bool {
	return (r >= 0x0000 && r <= 0x0008) ||
		r == 0x000B || r == 0x000C ||
		(r >= 0x000E && r <= 0x001F) ||
		r == 0x007F || r == 0x00AD || r == 0x061C || r == 0x180E ||
		(r >= 0x200B && r <= 0x200F) ||
		(r >= 0x202A && r <= 0x202E) ||
		(r >= 0x2060 && r <= 0x206F) ||
		r == 0xFEFF ||
		(r >= 0xE0000 && r <= 0xE01EF)
}

func isTimestampControlOrInvisibleRune(r rune) bool {
	return (r >= 0x0000 && r <= 0x001F) ||
		(r >= 0x007F && r <= 0x009F) ||
		r == 0x00AD || r == 0x061C || r == 0x180E ||
		(r >= 0x200B && r <= 0x200F) ||
		(r >= 0x2028 && r <= 0x202E) ||
		(r >= 0x2060 && r <= 0x206F) ||
		r == 0xFEFF ||
		(r >= 0xE0000 && r <= 0xE01EF)
}

func sliceUTF16Safe(s string, maxUnits int) string {
	if maxUnits <= 0 || s == "" {
		return ""
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

func escapeUnescapedChar(s string, target byte) string {
	if strings.IndexByte(s, target) < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		if s[i] == target {
			bs := 0
			for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 0 {
				sb.WriteByte('\\')
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// FormatMarkdownLinkCommerce safely formats `[label](url)` by escaping brackets/angle-brackets
// and odd trailing backslashes in `label`, and percent-encoding unsafe URL delimiters in `rawURL`.
func FormatMarkdownLinkCommerce(label, rawURL string) string {
	safeLabel := extract.StripInvisibleSchemaChars(label)
	safeLabel = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ", "<", "&lt;", ">", "&gt;").Replace(safeLabel)
	safeLabel = strings.TrimSpace(safeLabel)
	if strings.Contains(safeLabel, "](") {
		safeLabel = reCloseBracketSpaceParen.ReplaceAllString(safeLabel, `\] \(`)
	}
	safeLabel = escapeUnescapedChar(safeLabel, '[')
	safeLabel = escapeUnescapedChar(safeLabel, ']')
	bs := 0
	for i := len(safeLabel) - 1; i >= 0 && safeLabel[i] == '\\'; i-- {
		bs++
	}
	if bs%2 == 1 {
		safeLabel += `\`
	}
	trimmedURL := strings.TrimSpace(rawURL)
	if trimmedURL == "" {
		return safeLabel
	}
	dest := extract.PercentEncodeUnsafeRecordURLChars(trimmedURL)
	if safeLabel == "" {
		safeLabel = dest
	}
	return "[" + safeLabel + "](" + dest + ")"
}

// SanitizeCommerceField sanitizes untrusted e-commerce text fields (`title`, `vendor`, `productType`,
// `tags`, `options`, `variants[].title`, `sku`) non-destructively so product characters (`<`, `>`, `&`,
// `[`, `]`, `*`, `_`, `#`, `~`, “ ` “, `|`) are preserved via escaping while HTML tags, entity smuggling,
// phishing links, emphasis breakouts, and ATX headings are impossible.
func SanitizeCommerceField(raw any, maxLen int) string {
	rawStr, ok := raw.(string)
	if !ok || rawStr == "" {
		return ""
	}
	if maxLen <= 0 {
		maxLen = 400
	}
	if !utf8.ValidString(rawStr) {
		rawStr = strings.ToValidUTF8(rawStr, "\uFFFD")
	}
	s := stripANSICSI(rawStr)

	var flat strings.Builder
	flat.Grow(len(s))
	prevSpace := true
	for _, r := range s {
		if isCommerceInvisibleRune(r) {
			continue
		}
		if r == '\r' || r == '\n' || r == '\t' || r == 0x0085 || r == 0x2028 || r == 0x2029 || unicode.IsSpace(r) {
			if !prevSpace {
				flat.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		flat.WriteRune(r)
	}
	s = strings.TrimSpace(flat.String())
	if s == "" {
		return ""
	}
	if extract.UTF16Len(s) > maxLen {
		s = strings.TrimSpace(sliceUTF16Safe(s, maxLen))
		if s == "" {
			return ""
		}
	}

	if strings.IndexByte(s, '&') >= 0 {
		s = strings.ReplaceAll(s, "&", "&amp;")
	}
	if strings.IndexByte(s, '<') >= 0 {
		s = strings.ReplaceAll(s, "<", "&lt;")
	}
	if strings.IndexByte(s, '>') >= 0 {
		s = strings.ReplaceAll(s, ">", "&gt;")
	}
	if strings.Contains(s, "](") {
		s = reDangerousInlineLinkScheme.ReplaceAllString(s, "](#)")
	}
	if strings.IndexByte(s, '[') >= 0 || strings.IndexByte(s, ']') >= 0 {
		s = reCloseBracketSpaceParen.ReplaceAllString(s, `\] \(`)
		s = reCloseBracketSpaceOpen.ReplaceAllString(s, `\] \[`)
		s = reCloseBracketSpaceColon.ReplaceAllString(s, `\]:`)
		s = escapeUnescapedChar(s, '[')
		s = escapeUnescapedChar(s, ']')
	}
	for _, ch := range []byte{'*', '_', '~', '`', '#'} {
		s = escapeUnescapedChar(s, ch)
	}
	return s
}

// SanitizeCommerceTimestamp sanitizes commerce timestamps (`publishedAt`, `updatedAt`) by collapsing
// control/line-break characters and escaping HTML/Markdown-unsafe characters.
func SanitizeCommerceTimestamp(raw any, maxLen int) *string {
	rawStr, ok := raw.(string)
	if !ok || rawStr == "" {
		return nil
	}
	if maxLen <= 0 {
		maxLen = 96
	}
	if !utf8.ValidString(rawStr) {
		rawStr = strings.ToValidUTF8(rawStr, "\uFFFD")
	}
	s := stripANSICSI(rawStr)

	var flat strings.Builder
	flat.Grow(len(s))
	prevSpace := true
	for _, r := range s {
		if isTimestampControlOrInvisibleRune(r) || unicode.IsSpace(r) {
			if !prevSpace {
				flat.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		flat.WriteRune(r)
	}
	s = strings.TrimSpace(flat.String())
	if s == "" {
		return nil
	}
	if extract.UTF16Len(s) > maxLen {
		s = strings.TrimSpace(sliceUTF16Safe(s, maxLen))
		if s == "" {
			return nil
		}
	}
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"*", `\*`,
		"_", `\_`,
		"#", `\#`,
		"`", "\\`",
		"|", "&#124;",
	)
	out := r.Replace(s)
	if out == "" {
		return nil
	}
	return &out
}

func sanitizeCommerceSKU(raw any) *string {
	s, ok := raw.(string)
	if !ok || s == "" {
		return nil
	}
	clean := SanitizeCommerceField(s, 160)
	if clean == "" {
		return nil
	}
	return &clean
}

func formatCommerceSKUDisplay(sku *string, escapePipesForProse bool) string {
	if sku == nil || *sku == "" {
		return "`-`"
	}
	prepared := *sku
	if escapePipesForProse {
		prepared = escapeUnescapedChar(prepared, '|')
	}
	if !strings.ContainsAny(prepared, `\&|`) {
		return "`" + prepared + "`"
	}
	return prepared
}

// IsSafePublicHostname validates that rawHost is a public internet DNS name and NOT an IP literal,
// numeric/hex IPv4 obfuscation, loopback/LAN/metadata name, wildcard DNS-rebinding domain, bare public
// suffix, or recursive self-hub hostname.
func IsSafePublicHostname(rawHost, selfHost string) bool {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c <= 0x20 || c >= 0x7f || c == ':' || c == '[' || c == ']' || c == '\\' || c == '/' || c == '%' {
			return false
		}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	if disallowedExactHosts[host] {
		return false
	}
	for _, suf := range disallowedHostSuffixes {
		if strings.HasSuffix(host, suf) {
			return false
		}
	}
	canonicalSelf := strings.TrimRight(strings.ToLower(strings.TrimSpace(selfHost)), ".")
	if canonicalSelf != "" && host == canonicalSelf {
		return false
	}
	labels := strings.Split(host, ".")
	pureLDH := true
	for _, lbl := range labels {
		if lbl == "" || len(lbl) > 63 || lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			ch := lbl[i]
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				pureLDH = false
			}
		}
	}
	tld := labels[len(labels)-1]
	if reNumericOrHexTLD.MatchString(tld) {
		return false
	}
	if pureLDH && extract.IsPublicOrPrivateSuffix(host) {
		return false
	}
	return true
}

func canonicalizeParsedHTTPSURL(u *url.URL) string {
	cloned := *u
	cloned.Scheme = "https"
	hostLow := strings.ToLower(cloned.Hostname())
	cloned.Host = hostLow
	if cloned.Path == "" {
		cloned.Path = "/"
	}
	return cloned.String()
}

// NormalizePublicCommerceImageURL validates and normalizes a commerce image/asset URL to a strictly
// public `https://` URL on port 443 without credentials, IP literals, or private/local hosts.
func NormalizePublicCommerceImageURL(raw any) string {
	rawStr, ok := raw.(string)
	if !ok {
		return ""
	}
	s := strings.TrimSpace(rawStr)
	if s == "" || len(s) > 2048 || strings.IndexByte(s, '\\') >= 0 {
		return ""
	}
	for _, r := range s {
		if r <= 0x20 || (r >= 0x7f && r <= 0x9f) {
			return ""
		}
	}
	candidate := s
	if strings.HasPrefix(s, "//") {
		if strings.HasPrefix(s, "///") {
			return ""
		}
		candidate = "https:" + s
	} else if len(s) < 8 || !strings.EqualFold(s[:8], "https://") {
		return ""
	}
	u, err := url.Parse(candidate)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil {
		return ""
	}
	if port := u.Port(); port != "" && port != "443" {
		return ""
	}
	if !IsSafePublicHostname(u.Hostname(), "") {
		return ""
	}
	return canonicalizeParsedHTTPSURL(u)
}

func stripNonPublicMarkdownImages(md string) string {
	if md == "" || !strings.Contains(md, "![") {
		return md
	}
	return reMarkdownImgTag.ReplaceAllStringFunc(md, func(full string) string {
		sub := reMarkdownImgTag.FindStringSubmatch(full)
		if len(sub) < 3 {
			return full
		}
		trimmed := strings.TrimSpace(sub[2])
		var rawDest string
		if strings.HasPrefix(trimmed, "<") {
			if gt := strings.IndexByte(trimmed, '>'); gt > 0 {
				rawDest = strings.TrimSpace(trimmed[1:gt])
			} else {
				rawDest = strings.TrimSpace(trimmed[1:])
			}
		} else if fields := strings.Fields(trimmed); len(fields) > 0 {
			rawDest = fields[0]
		}
		if NormalizePublicCommerceImageURL(rawDest) != "" {
			return full
		}
		return ""
	})
}

// ConvertCommerceHTMLFragmentToMD converts an HTML description fragment into sanitized Markdown
// using Go's full HTML extractor (`extract.ExtractHTMLDocumentFull`) with images enabled.
func ConvertCommerceHTMLFragmentToMD(frag, baseURL string) string {
	if strings.TrimSpace(frag) == "" {
		return ""
	}
	doc := extract.ExtractHTMLDocumentFull("<!doctype html><html><body>"+frag+"</body></html>", extract.FullExtractOptions{
		BaseURL:         baseURL,
		OnlyMainContent: false,
		IncludeImages:   true,
	})
	return strings.TrimSpace(doc.Markdown)
}

// StripTagsInlineCommerce strips HTML tags linearly, decodes basic entities, collapses whitespace,
// and escapes any residual `<` characters.
func StripTagsInlineCommerce(rawHTML string) string {
	if rawHTML == "" {
		return ""
	}
	src := rawHTML
	if len(src) > 2*1024*1024 {
		src = src[:2*1024*1024]
	}
	var sb strings.Builder
	sb.Grow(len(src))
	inTag := false
	var quote byte
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if !inTag {
			if ch == '<' && i+1 < len(src) {
				next := src[i+1]
				if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') || next == '/' || next == '!' || next == '?' {
					inTag = true
					quote = 0
					sb.WriteByte(' ')
					continue
				}
			}
			sb.WriteByte(ch)
		} else {
			if quote != 0 {
				if ch == quote {
					quote = 0
				}
			} else if ch == '"' || ch == '\'' {
				quote = ch
			} else if ch == '>' {
				inTag = false
			}
		}
	}
	decoded := extract.DecodeBasicEntities(sb.String())
	collapsed := strings.Join(strings.Fields(decoded), " ")
	return extract.EscapeAllResidualLtInProse(collapsed, false)
}

// SafeDecodeURIComponent decodes percent-escapes strictly (like JS `decodeURIComponent`,
// without treating `+` as space) and rejects invalid UTF-8 byte sequences.
func SafeDecodeURIComponent(raw string) (string, bool) {
	if strings.IndexByte(raw, '%') < 0 {
		if !utf8.ValidString(raw) {
			return "", false
		}
		return raw, true
	}
	dec, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(dec) {
		return "", false
	}
	return dec, true
}

// EncodeURIComponent matches JavaScript's `encodeURIComponent` (unreserved: A-Z a-z 0-9 - _ . ! ~ * ' ( )).
func EncodeURIComponent(s string) string {
	const hexUpper = "0123456789ABCDEF"
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '!' || b == '~' || b == '*' || b == '\'' || b == '(' || b == ')' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hexUpper[b>>4])
			sb.WriteByte(hexUpper[b&0x0f])
		}
	}
	return sb.String()
}

func escapeGFMCell(val string, maxLen int) string {
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
	if extract.UTF16Len(s) > maxLen {
		return sliceUTF16Safe(s, maxLen-1) + "…"
	}
	return s
}

// FormatGFMTable formats headers and string rows into a GitHub-Flavored Markdown table.
func FormatGFMTable(headers []string, rows [][]string) string {
	if len(headers) == 0 || len(rows) == 0 {
		return ""
	}
	headCells := make([]string, len(headers))
	sepCells := make([]string, len(headers))
	for i, h := range headers {
		headCells[i] = escapeGFMCell(h, 80)
		sepCells[i] = "---"
	}
	lines := make([]string, 0, len(rows)+2)
	lines = append(lines, "| "+strings.Join(headCells, " | ")+" |")
	lines = append(lines, "| "+strings.Join(sepCells, " | ")+" |")
	for _, r := range rows {
		cells := make([]string, len(headers))
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			cells[i] = escapeGFMCell(v, 180)
		}
		lines = append(lines, "| "+strings.Join(cells, " | ")+" |")
	}
	return strings.Join(lines, "\n")
}

func parseJSONValueCommerce(raw string) (any, bool) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if trimmed == "" {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, false
	}
	return val, true
}

func parseJSONObjectCommerce(raw string) (map[string]any, bool) {
	val, ok := parseJSONValueCommerce(raw)
	if !ok || val == nil {
		return nil, false
	}
	obj, isObj := val.(map[string]any)
	return obj, isObj
}

func jsonScalarToStringCommerce(v any) string {
	switch tv := v.(type) {
	case nil:
		return ""
	case string:
		return tv
	case json.Number:
		return tv.String()
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return ""
		}
		if tv == math.Trunc(tv) && math.Abs(tv) < 1e15 {
			return strconv.FormatInt(int64(tv), 10)
		}
		return strconv.FormatFloat(tv, 'f', -1, 64)
	case int:
		return strconv.Itoa(tv)
	case int64:
		return strconv.FormatInt(tv, 10)
	case bool:
		if tv {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func isRawJSONNumberCommerce(v any) bool {
	switch v.(type) {
	case json.Number, float64, int, int64:
		return true
	default:
		return false
	}
}

func jsonNumberToFloatCommerce(v any) (float64, bool) {
	switch tv := v.(type) {
	case json.Number:
		f, err := tv.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case float64:
		return tv, !math.IsNaN(tv) && !math.IsInf(tv, 0)
	case int:
		return float64(tv), true
	case int64:
		return float64(tv), true
	default:
		return 0, false
	}
}

func readHeaderCaseInsensitive(headers map[string]string, target string) string {
	if len(headers) == 0 {
		return ""
	}
	if v, ok := headers[target]; ok {
		return strings.TrimSpace(v)
	}
	low := strings.ToLower(target)
	if v, ok := headers[low]; ok {
		return strings.TrimSpace(v)
	}
	for k, v := range headers {
		if strings.ToLower(k) == low {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func readHeaderInt(headers map[string]string, key string) (int, bool) {
	val := readHeaderCaseInsensitive(headers, key)
	if val == "" {
		return 0, false
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func cleanOriginString(originStr string) string {
	if u, err := url.Parse(strings.TrimSpace(originStr)); err == nil && u.Scheme != "" && u.Host != "" {
		return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	}
	return strings.TrimRight(originStr, "/")
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
