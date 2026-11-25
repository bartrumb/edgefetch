package mcpfed

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

var (
	ansiCSISequenceRe       = newLazyRegexp(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	slugifyPrefixStripRe    = newLazyRegexp(`(?i)^(?:io\.github\.[^/]+/|io\.modelcontextprotocol\.[^/]+/|@[a-z0-9._-]+/)`)
	slugifyNonSlugRunRe     = newLazyRegexp(`[^a-z0-9_-]+`)
	slugifyMultiSepRe       = newLazyRegexp(`[_-]{2,}`)
	strictConnectorDomainRe = newLazyRegexp(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	dottedIPv4DigitsRe      = newLazyRegexp(`^\d+(?:\.\d+){3}$`)
	reservedInternalTLDRe   = newLazyRegexp(`(?i)\.(?:local|localhost|internal|intranet|corp|home|lan|arpa|onion)$`)
	numericOrHexTLDRe       = newLazyRegexp(`(?i)^(?:\d+|0x[0-9a-f]+)$`)
)

var disallowedHostSuffixes = []string{
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

var disallowedExactHosts = map[string]bool{
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

// SafeHTTPSURLResult holds the outcome of IsSafePublicHTTPSURL.
type SafeHTTPSURLResult struct {
	OK         bool   `json:"ok"`
	Normalized string `json:"normalized,omitempty"`
	Origin     string `json:"origin,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	Pathname   string `json:"pathname,omitempty"`
	Search     string `json:"search,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func decodeUTF8Rune(s string) (rune, int) {
	return utf8.DecodeRuneInString(s)
}

func isMCPSmugglingRune(r rune) bool {
	if r <= 0x0008 || r == 0x000B || r == 0x000C || (r >= 0x000E && r <= 0x001F) || r == 0x007F {
		return true
	}
	if r == 0x00AD || r == 0x061C || r == 0x180E || r == 0xFEFF {
		return true
	}
	if (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2060 && r <= 0x206F) {
		return true
	}
	if (r >= 0xE0000 && r <= 0xE007F) || (r >= 0xE0100 && r <= 0xE01EF) {
		return true
	}
	return false
}

// StripMCPSmugglingChars strips invisible Unicode Tag/Variation Selector smuggling, Bidi controls,
// zero-width characters, ANSI CSI sequences, and raw ASCII C0/DEL control bytes.
func StripMCPSmugglingChars(s string) string {
	if s == "" {
		return ""
	}
	needsClean := false
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b < 0x20 && b != '\r' && b != '\n' && b != '\t') || b >= 0x7F {
			needsClean = true
			break
		}
	}
	if !needsClean {
		return s
	}
	work := s
	if strings.IndexByte(work, 0x1b) >= 0 {
		work = ansiCSISequenceRe.ReplaceAllString(work, "")
	}
	var sb strings.Builder
	sb.Grow(len(work))
	for i := 0; i < len(work); {
		b := work[i]
		if b < 0x80 {
			if isMCPSmugglingRune(rune(b)) {
				i++
				continue
			}
			sb.WriteByte(b)
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(work[i:])
		if isMCPSmugglingRune(r) {
			i += w
			continue
		}
		sb.WriteString(work[i : i+w])
		i += w
	}
	return sb.String()
}

func isNonPublicIPv4Octets(a, b, c, d int) bool {
	_ = d
	if a == 0 || a == 10 || a == 127 || a >= 224 {
		return true
	}
	if a == 100 && b >= 64 && b <= 127 {
		return true
	}
	if a == 169 && b == 254 {
		return true
	}
	if a == 172 && b >= 16 && b <= 31 {
		return true
	}
	if a == 192 && b == 168 {
		return true
	}
	if a == 192 && b == 0 && (c == 0 || c == 2) {
		return true
	}
	if a == 192 && b == 88 && c == 99 {
		return true
	}
	if a == 198 && (b == 18 || b == 19) {
		return true
	}
	if a == 198 && b == 51 && c == 100 {
		return true
	}
	if a == 203 && b == 0 && c == 113 {
		return true
	}
	return false
}

func classifyIPLiteralHost(rawHost string) string {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") || strings.Contains(host, ":") {
		inner := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if inner == "::" || inner == "::1" ||
			strings.HasPrefix(inner, "fe8") || strings.HasPrefix(inner, "fe9") ||
			strings.HasPrefix(inner, "fea") || strings.HasPrefix(inner, "feb") ||
			strings.HasPrefix(inner, "fc") || strings.HasPrefix(inner, "fd") ||
			strings.HasPrefix(inner, "ff") ||
			strings.HasPrefix(inner, "2001:db8:") || strings.HasPrefix(inner, "100::") {
			return "private_ip"
		}
		if strings.HasPrefix(inner, "::ffff:") {
			rest := inner[len("::ffff:"):]
			if parts := strings.Split(rest, "."); len(parts) == 4 {
				a, e1 := strconv.Atoi(parts[0])
				b, e2 := strconv.Atoi(parts[1])
				c, e3 := strconv.Atoi(parts[2])
				d, e4 := strconv.Atoi(parts[3])
				if e1 == nil && e2 == nil && e3 == nil && e4 == nil && a <= 255 && b <= 255 && c <= 255 && d <= 255 {
					if isNonPublicIPv4Octets(a, b, c, d) {
						return "private_ip"
					}
					return "public_ip"
				}
			}
			if parts := strings.Split(rest, ":"); len(parts) == 2 && len(parts[0]) <= 4 && len(parts[1]) <= 4 {
				hi, e1 := strconv.ParseUint(parts[0], 16, 16)
				lo, e2 := strconv.ParseUint(parts[1], 16, 16)
				if e1 == nil && e2 == nil {
					if isNonPublicIPv4Octets(int((hi>>8)&0xff), int(hi&0xff), int((lo>>8)&0xff), int(lo&0xff)) {
						return "private_ip"
					}
					return "public_ip"
				}
			}
		}
		return "public_ip"
	}
	if parts := strings.Split(host, "."); len(parts) == 4 && dottedIPv4DigitsRe.MatchString(host) {
		a, e1 := strconv.Atoi(parts[0])
		b, e2 := strconv.Atoi(parts[1])
		c, e3 := strconv.Atoi(parts[2])
		d, e4 := strconv.Atoi(parts[3])
		if e1 == nil && e2 == nil && e3 == nil && e4 == nil && a <= 255 && b <= 255 && c <= 255 && d <= 255 {
			if isNonPublicIPv4Octets(a, b, c, d) {
				return "private_ip"
			}
			return "public_ip"
		}
		return "private_ip"
	}
	labels := strings.Split(host, ".")
	tld := labels[len(labels)-1]
	if numericOrHexTLDRe.MatchString(tld) {
		return "private_ip"
	}
	return ""
}

// IsSafePublicHostname validates that rawHost is a public DNS name (no IP literals, loopback/LAN/metadata, rebinding, or self-hub).
func IsSafePublicHostname(rawHost, selfHost string) bool {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for i := 0; i < len(host); i++ {
		b := host[i]
		if b <= 0x20 || b >= 0x7f || b == ':' || b == '[' || b == ']' || b == '%' || b == '/' || b == '\\' {
			return false
		}
	}
	if disallowedExactHosts[host] {
		return false
	}
	for _, suffix := range disallowedHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	canonicalSelf := strings.TrimRight(strings.ToLower(strings.TrimSpace(selfHost)), ".")
	if canonicalSelf != "" && host == canonicalSelf {
		return false
	}
	labels := strings.Split(host, ".")
	for _, lbl := range labels {
		if lbl == "" || len(lbl) > 63 || lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	return !numericOrHexTLDRe.MatchString(tld)
}

func resolveWHATWGPath(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}
	if !strings.HasPrefix(escapedPath, "/") {
		escapedPath = "/" + escapedPath
	}
	if !strings.Contains(escapedPath, "/.") {
		return escapedPath
	}
	trailingSlash := strings.HasSuffix(escapedPath, "/") || strings.HasSuffix(escapedPath, "/.") || strings.HasSuffix(escapedPath, "/..")
	parts := strings.Split(escapedPath, "/")
	stack := make([]string, 0, len(parts))
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		stack = append(stack, seg)
	}
	resolved := "/" + strings.Join(stack, "/")
	if trailingSlash && resolved != "/" {
		resolved += "/"
	}
	return resolved
}

// IsSafePublicHTTPSURL validates that rawURL is a safe public https:// URL on port 443 with no credentials or fragments.
func IsSafePublicHTTPSURL(rawURL, selfHost string) SafeHTTPSURLResult {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return SafeHTTPSURLResult{OK: false, Reason: "URL must be a non-empty https:// string"}
	}
	if containsCRorLForNUL(trimmed) {
		return SafeHTTPSURLResult{OK: false, Reason: "URL contains control characters"}
	}
	normalizedSlashes := strings.ReplaceAll(trimmed, "\\", "/")
	u, err := url.Parse(normalizedSlashes)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return SafeHTTPSURLResult{OK: false, Reason: "invalid URL: " + rawURL}
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return SafeHTTPSURLResult{OK: false, Reason: "only https:// URLs are permitted"}
	}
	if !strings.HasPrefix(strings.ToLower(normalizedSlashes), "https://") {
		return SafeHTTPSURLResult{OK: false, Reason: "invalid URL: " + rawURL}
	}
	if u.User != nil {
		_, hasPass := u.User.Password()
		if u.User.Username() != "" || hasPass {
			return SafeHTTPSURLResult{OK: false, Reason: "URLs with embedded credentials are not permitted"}
		}
	}
	if strings.Contains(u.Host, "@") {
		return SafeHTTPSURLResult{OK: false, Reason: "URLs with embedded credentials are not permitted"}
	}

	var rawHostname, portStr string
	if strings.HasPrefix(u.Host, "[") {
		endBracket := strings.IndexByte(u.Host, ']')
		if endBracket < 0 {
			return SafeHTTPSURLResult{OK: false, Reason: "invalid URL: " + rawURL}
		}
		rawHostname = u.Host[:endBracket+1]
		rem := u.Host[endBracket+1:]
		if strings.HasPrefix(rem, ":") {
			portStr = rem[1:]
		} else if rem != "" {
			return SafeHTTPSURLResult{OK: false, Reason: "invalid URL: " + rawURL}
		}
	} else if colon := strings.IndexByte(u.Host, ':'); colon >= 0 {
		if strings.IndexByte(u.Host[colon+1:], ':') >= 0 {
			return SafeHTTPSURLResult{OK: false, Reason: "invalid URL: " + rawURL}
		}
		rawHostname = u.Host[:colon]
		portStr = u.Host[colon+1:]
	} else {
		rawHostname = u.Host
	}

	if portStr != "" && portStr != "443" {
		for i := 0; i < len(portStr); i++ {
			if portStr[i] < '0' || portStr[i] > '9' {
				return SafeHTTPSURLResult{OK: false, Reason: "invalid URL: " + rawURL}
			}
		}
		return SafeHTTPSURLResult{OK: false, Reason: "only port 443 is permitted"}
	}

	hostLower := strings.ToLower(rawHostname)
	if !IsSafePublicHostname(hostLower, selfHost) {
		ipKind := classifyIPLiteralHost(hostLower)
		if ipKind == "public_ip" {
			return SafeHTTPSURLResult{
				OK:     false,
				Reason: fmt.Sprintf("IP address literals are not allowed (%s); provide a public DNS hostname.", hostLower),
			}
		}
		if ipKind == "private_ip" {
			return SafeHTTPSURLResult{
				OK:     false,
				Reason: fmt.Sprintf("disallowed non-public IP address (%s): private, loopback, and metadata IPs are blocked", hostLower),
			}
		}
		return SafeHTTPSURLResult{OK: false, Reason: "disallowed hostname: " + hostLower}
	}

	if u.Fragment != "" {
		return SafeHTTPSURLResult{OK: false, Reason: "URL fragments (#) are not permitted on MCP endpoints"}
	}
	if strings.HasSuffix(hostLower, ".") {
		return SafeHTTPSURLResult{OK: false, Reason: "Trailing-dot FQDN hostnames are not permitted on MCP endpoints"}
	}

	origin := "https://" + hostLower
	pathname := resolveWHATWGPath(u.EscapedPath())
	search := ""
	if u.RawQuery != "" {
		search = "?" + u.RawQuery
	}
	normalized := origin + pathname
	if u.RawQuery != "" {
		normalized += "?" + u.RawQuery
	} else if u.ForceQuery {
		normalized += "?"
	}
	if strings.HasSuffix(normalizedSlashes, "#") && u.Fragment == "" {
		normalized += "#"
	}

	return SafeHTTPSURLResult{
		OK:         true,
		Normalized: normalized,
		Origin:     origin,
		Hostname:   hostLower,
		Pathname:   pathname,
		Search:     search,
	}
}

// SanitizeManifestString strips smuggling runes and redacts prompt-injection directives in third-party registry manifests.
func SanitizeManifestString(raw string, maxLen int) string {
	if raw == "" {
		return ""
	}
	if maxLen <= 0 {
		maxLen = 600
	}
	stripped := strings.TrimSpace(whitespaceRunRe.ReplaceAllString(StripMCPSmugglingChars(raw), " "))
	if stripped == "" {
		return ""
	}
	bounded, _ := sliceUTF16(stripped, maxLen)
	if detectPromptInjForMCP(bounded).Detected {
		return "[redacted: untrusted manifest instruction blocked]"
	}
	return bounded
}

// SlugifyMCPServerName converts a registry server name (including reverse-DNS / @scope prefixes) into a safe slug.
func SlugifyMCPServerName(rawName string) string {
	cleaned := strings.ToLower(StripMCPSmugglingChars(rawName))
	cleaned = slugifyPrefixStripRe.ReplaceAllString(cleaned, "")
	cleaned = slugifyNonSlugRunRe.ReplaceAllString(cleaned, "-")
	cleaned = slugifyMultiSepRe.ReplaceAllString(cleaned, "-")
	cleaned = strings.Trim(cleaned, "_-")
	if cleaned == "" {
		cleaned = "mcp-server"
	}
	if len(cleaned) > 48 {
		cleaned = cleaned[:48]
	}
	cleaned = strings.Trim(cleaned, "_-")
	if cleaned == "" {
		return "mcp-server"
	}
	return cleaned
}

// IsSharedHostingHostname delegates to extract.HasPrivateSharedHostingSuffix for PSL PRIVATE DOMAINS isolation.
func IsSharedHostingHostname(hostname string) bool {
	clean := strings.TrimRight(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if clean == "" {
		return false
	}
	return extract.HasPrivateSharedHostingSuffix(clean)
}

// ExtractRegistrableDomain returns the eTLD+1 registrable domain (or "" when unregistrable / bare suffix / IP).
func ExtractRegistrableDomain(hostname string) string {
	clean := strings.TrimRight(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if clean == "" || !strictConnectorDomainRe.MatchString(clean) || dottedIPv4DigitsRe.MatchString(clean) {
		return ""
	}
	return extract.GetRegistrableDomain(clean)
}

// ValidateConnectorDomains validates operator-supplied connector domains against PSL suffixes, shared-hosting sibling tenants, and origin matching.
func ValidateConnectorDomains(rawDomains json.RawMessage, remoteOrigin string, allowUnrelatedDomains bool) ([]string, bool, string) {
	trimmedRaw := strings.TrimSpace(string(rawDomains))
	if trimmedRaw == "" || trimmedRaw == "null" {
		return []string{}, true, ""
	}
	var rawArr []json.RawMessage
	if err := json.Unmarshal(rawDomains, &rawArr); err != nil {
		return nil, false, "domains must be an array of domain strings"
	}

	uOrigin, err := url.Parse(strings.TrimSpace(remoteOrigin))
	if err != nil || uOrigin.Hostname() == "" {
		return nil, false, "Invalid remoteOrigin for domain validation"
	}
	remoteHost := strings.TrimRight(strings.ToLower(uOrigin.Hostname()), ".")
	remoteBase := extract.GetRegistrableDomain(remoteHost)
	remoteIsSharedHosting := extract.HasPrivateSharedHostingSuffix(remoteHost)

	limit := min(len(rawArr), 16)
	out := make([]string, 0, limit)
	seen := make(map[string]bool, limit)

	for i := 0; i < limit; i++ {
		var rawStr string
		if err := json.Unmarshal(rawArr[i], &rawStr); err != nil || strings.TrimSpace(string(rawArr[i])) == "null" {
			return nil, false, "Each domain entry must be a string"
		}
		trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rawStr)), "www.")
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "*") || strings.Contains(trimmed, "/") || strings.Contains(trimmed, ":") || strings.HasSuffix(trimmed, ".") {
			return nil, false, fmt.Sprintf("Wildcard or malformed domain %q is not permitted", rawStr)
		}
		if len(trimmed) > 128 || !strictConnectorDomainRe.MatchString(trimmed) {
			return nil, false, fmt.Sprintf("Invalid domain syntax %q", rawStr)
		}
		if reservedInternalTLDRe.MatchString(trimmed) {
			return nil, false, fmt.Sprintf("Internal or reserved domain %q is not permitted", trimmed)
		}
		if extract.IsPublicOrPrivateSuffix(trimmed) {
			return nil, false, fmt.Sprintf("Shared hosting or public suffix %q cannot be claimed as a connector domain", trimmed)
		}
		candBase := extract.GetRegistrableDomain(trimmed)
		if candBase == "" {
			return nil, false, fmt.Sprintf("Unregistrable domain %q", trimmed)
		}
		if !allowUnrelatedDomains {
			if remoteIsSharedHosting || extract.HasPrivateSharedHostingSuffix(trimmed) {
				exactOrChild := candBase == remoteBase &&
					(trimmed == remoteHost || strings.HasSuffix(trimmed, "."+remoteHost) || strings.HasSuffix(remoteHost, "."+trimmed))
				if !exactOrChild {
					return nil, false, fmt.Sprintf("Shared-hosting domain %q does not match exact connector host %q.", trimmed, remoteHost)
				}
			} else {
				sameHostOrSub := trimmed == remoteHost || strings.HasSuffix(remoteHost, "."+trimmed) || strings.HasSuffix(trimmed, "."+remoteHost)
				sameRegistrable := remoteBase != "" && candBase == remoteBase
				if !sameHostOrSub && !sameRegistrable {
					return nil, false, fmt.Sprintf(
						"Domain %q does not match connector origin %q. Enable routeScrapeDomains / autoRouteScrape explicitly to claim external domains.",
						trimmed, remoteHost,
					)
				}
			}
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			out = append(out, trimmed)
		}
	}
	return out, true, ""
}

// InferAssociatedDomains enforces Security Invariant H1: never infer foreign domains from untrusted manifests.
func InferAssociatedDomains() []string {
	return []string{}
}
