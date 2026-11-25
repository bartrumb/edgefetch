package agentloop

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
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

var (
	reEncodedPathBypass = newLazyRegexp(`(?i)%2e|%2f|%5c|%3b|%3f|%23`)
	reNumericOrHexLabel = newLazyRegexp(`(?i)^(?:\d+|0x[0-9a-f]+)$`)
)

// PublicURLCheckResult reports validation of a public HTTPS target URL.
type PublicURLCheckResult struct {
	OK         bool   `json:"ok"`
	Normalized string `json:"normalized,omitempty"`
	Error      string `json:"error,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Message    string `json:"message,omitempty"`
}

func trimTrailingSlashes(s string) string {
	end := len(s)
	for end > 0 && s[end-1] == '/' {
		end--
	}
	return s[:end]
}

func normalizeOperatorBaseURLPreservingQuery(raw string) string {
	qIdx := strings.IndexByte(raw, '?')
	if qIdx < 0 {
		return trimTrailingSlashes(raw)
	}
	return trimTrailingSlashes(raw[:qIdx]) + raw[qIdx:]
}

func stripBaseURLQuery(raw string) string {
	qIdx := strings.IndexByte(raw, '?')
	if qIdx >= 0 {
		return trimTrailingSlashes(raw[:qIdx])
	}
	return trimTrailingSlashes(raw)
}

// AppendEndpointToBaseURL appends an endpoint path to baseUrl while preserving any operator query string.
func AppendEndpointToBaseURL(baseURL, suffixPath, alreadyEndsWith string) string {
	qIdx := strings.IndexByte(baseURL, '?')
	pathPart := trimTrailingSlashes(baseURL)
	queryPart := ""
	if qIdx >= 0 {
		pathPart = trimTrailingSlashes(baseURL[:qIdx])
		queryPart = baseURL[qIdx:]
	}
	if alreadyEndsWith != "" && strings.HasSuffix(pathPart, alreadyEndsWith) {
		return pathPart + queryPart
	}
	return pathPart + suffixPath + queryPart
}

func safeDecodeURIComponent(s string) (string, bool) {
	if !strings.ContainsRune(s, '%') {
		return s, true
	}
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) {
				return "", false
			}
			hi, ok1 := hexNibble(s[i+1])
			lo, ok2 := hexNibble(s[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			buf = append(buf, (hi<<4)|lo)
			i += 2
		} else {
			buf = append(buf, s[i])
		}
	}
	if !utf8.Valid(buf) {
		return "", false
	}
	return string(buf), true
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func isPrintableCleanBaseURLASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '\\' || c == '?' || c == '#' || c == ';' {
			return false
		}
	}
	return true
}

type parsedHTTPURL struct {
	scheme        string
	originLower   string
	hostname      string
	explicitPort  string
	effectivePort string
	escapedPath   string
}

func parseStrictHTTPURL(raw string) (*parsedHTTPURL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" {
		return nil, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, false
	}
	if u.User != nil {
		return nil, false
	}
	hostPort := u.Host
	if hostPort == "" || strings.ContainsAny(hostPort, " \t\r\n/\\?#") {
		return nil, false
	}
	var hostPart, portPart string
	if strings.HasPrefix(hostPort, "[") {
		closeIdx := strings.IndexByte(hostPort, ']')
		if closeIdx <= 1 {
			return nil, false
		}
		inner := hostPort[1:closeIdx]
		if strings.ContainsRune(inner, '%') {
			return nil, false
		}
		addr, addrErr := netip.ParseAddr(inner)
		if addrErr != nil || !addr.Is6() {
			return nil, false
		}
		hostPart = "[" + strings.ToLower(addr.String()) + "]"
		rest := hostPort[closeIdx+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return nil, false
			}
			portPart = rest[1:]
		}
	} else {
		if strings.ContainsAny(hostPort, "[]") {
			return nil, false
		}
		colonIdx := strings.IndexByte(hostPort, ':')
		if colonIdx >= 0 {
			if strings.IndexByte(hostPort[colonIdx+1:], ':') >= 0 {
				return nil, false
			}
			hostPart = strings.ToLower(hostPort[:colonIdx])
			portPart = hostPort[colonIdx+1:]
		} else {
			hostPart = strings.ToLower(hostPort)
		}
	}
	if hostPart == "" {
		return nil, false
	}
	defaultPort := "80"
	if scheme == "https" {
		defaultPort = "443"
	}
	effectivePort := defaultPort
	explicitPort := ""
	if portPart != "" {
		n, pErr := strconv.Atoi(portPart)
		if pErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != portPart {
			return nil, false
		}
		effectivePort = portPart
		if portPart != defaultPort {
			explicitPort = portPart
		}
	}
	originLower := scheme + "://" + hostPart
	if explicitPort != "" {
		originLower += ":" + explicitPort
	}
	escPath := u.EscapedPath()
	if escPath == "" {
		escPath = "/"
	}
	return &parsedHTTPURL{
		scheme:        scheme,
		originLower:   originLower,
		hostname:      hostPart,
		explicitPort:  explicitPort,
		effectivePort: effectivePort,
		escapedPath:   escPath,
	}, true
}

// ValidateCleanHTTPBaseURL validates an untrusted or operator HTTP(S) LLM baseUrl against traversal,
// double-encoding, credentials, query/fragment smuggling, and empty segments.
func ValidateCleanHTTPBaseURL(rawURL string) (normalized string, parsed *parsedHTTPURL, errMsg string, ok bool) {
	if rawURL == "" || len(rawURL) > 2048 {
		return "", nil, "baseUrl must be a non-empty URL <= 2048 chars", false
	}
	if !isPrintableCleanBaseURLASCII(rawURL) {
		return "", nil, "baseUrl must contain only printable ASCII without whitespace, semicolons, query strings, fragments, or backslashes", false
	}
	lowerPrefix := strings.ToLower(rawURL[:min(len(rawURL), 9)])
	schemeIdx := -1
	if strings.HasPrefix(lowerPrefix, "https://") && len(rawURL) > 8 && rawURL[8] != '/' {
		schemeIdx = 5
	} else if strings.HasPrefix(lowerPrefix, "http://") && len(rawURL) > 7 && rawURL[7] != '/' {
		schemeIdx = 4
	}
	if schemeIdx < 0 {
		return "", nil, "baseUrl must start with https:// or http:// followed by a valid authority", false
	}

	decoded := rawURL
	for round := 0; round < 5; round++ {
		if reEncodedPathBypass.MatchString(decoded) {
			return "", nil, "baseUrl must not contain percent-encoded path separators, semicolons, or dot segments", false
		}
		if !strings.ContainsRune(decoded, '%') {
			break
		}
		if round == 4 {
			return "", nil, "baseUrl must not contain deeply nested percent-encoding", false
		}
		next, decOK := safeDecodeURIComponent(decoded)
		if !decOK {
			return "", nil, "baseUrl contains malformed percent-encoding", false
		}
		if !isPrintableCleanBaseURLASCII(next) {
			return "", nil, "baseUrl contains disallowed percent-encoded characters", false
		}
		if next == decoded {
			break
		}
		decoded = next
	}

	afterScheme := rawURL[schemeIdx+3:]
	if strings.Contains(strings.TrimSuffix(afterScheme, "/"), "//") {
		return "", nil, `baseUrl path must not contain empty "//" segments`, false
	}

	trimmed := trimTrailingSlashes(rawURL)
	if strings.Contains(trimmed, "@") {
		return "", nil, "baseUrl must not contain embedded credentials", false
	}
	u, parseOK := parseStrictHTTPURL(trimmed)
	if !parseOK {
		return "", nil, "malformed URL", false
	}
	if strings.HasSuffix(u.hostname, ".") {
		return "", nil, "baseUrl hostname must not have a trailing dot", false
	}

	for _, candStr := range []string{trimmed, trimTrailingSlashes(decoded)} {
		scEnd := strings.Index(candStr, "://")
		rawPath := "/"
		if scEnd >= 0 {
			if pSlash := strings.IndexByte(candStr[scEnd+3:], '/'); pSlash >= 0 {
				rawPath = candStr[scEnd+3+pSlash:]
			}
		}
		for _, seg := range strings.Split(rawPath, "/") {
			if seg != "" && strings.Trim(seg, ".") == "" {
				return "", nil, `baseUrl must not contain "." or ".." path traversal segments`, false
			}
		}
	}

	return u.originLower + trimTrailingSlashes(u.escapedPath), u, "", true
}

// MatchesTrustedBaseURLPrefix checks whether candidateURL is on the exact same origin and path-prefix as trustedURL.
func MatchesTrustedBaseURLPrefix(candidateURLStr, trustedURLStr string) bool {
	if candidateURLStr == "" || trustedURLStr == "" {
		return false
	}
	if strings.HasPrefix(candidateURLStr, "workers-ai://") || strings.HasPrefix(trustedURLStr, "workers-ai://") {
		return candidateURLStr == trustedURLStr
	}
	_, cand, _, ok1 := ValidateCleanHTTPBaseURL(candidateURLStr)
	_, trust, _, ok2 := ValidateCleanHTTPBaseURL(trustedURLStr)
	if !ok1 || !ok2 || cand.originLower != trust.originLower {
		return false
	}
	candPath := trimTrailingSlashes(cand.escapedPath)
	if candPath == "" {
		candPath = "/"
	}
	trustPath := trimTrailingSlashes(trust.escapedPath)
	if trustPath == "" || trustPath == "/" {
		return true
	}
	return candPath == trustPath || strings.HasPrefix(candPath, trustPath+"/")
}

func isNonPublicIPv4Octets(a, b, c, _ byte) bool {
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
	return a == 203 && b == 0 && c == 113
}

func classifyIPLiteralHost(rawHost string) string {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") || strings.ContainsRune(host, ':') {
		inner := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		addr, err := netip.ParseAddr(inner)
		if err != nil {
			return "private_ip"
		}
		if addr.Is4In6() {
			v4 := addr.Unmap().As4()
			if isNonPublicIPv4Octets(v4[0], v4[1], v4[2], v4[3]) {
				return "private_ip"
			}
			return "public_ip"
		}
		s := strings.ToLower(addr.String())
		if addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
			addr.IsMulticast() || addr.IsPrivate() || strings.HasPrefix(s, "2001:db8:") || strings.HasPrefix(s, "100::") {
			return "private_ip"
		}
		return "public_ip"
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
		v4 := addr.As4()
		if isNonPublicIPv4Octets(v4[0], v4[1], v4[2], v4[3]) {
			return "private_ip"
		}
		return "public_ip"
	}
	labels := strings.Split(host, ".")
	if reNumericOrHexLabel.MatchString(labels[len(labels)-1]) {
		return "private_ip"
	}
	return ""
}

func isSafePublicHostname(rawHost, selfHost string) bool {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(rawHost)), ".")
	if host == "" || len(host) > 253 || !strings.ContainsRune(host, '.') {
		return false
	}
	for i := 0; i < len(host); i++ {
		if host[i] <= 0x20 || host[i] == ':' || host[i] == '[' || host[i] == ']' {
			return false
		}
	}
	if disallowedExactHosts[host] {
		return false
	}
	for _, suf := range disallowedHostSuffixes {
		if strings.HasSuffix(host, suf) {
			return false
		}
	}
	canonSelf := strings.TrimRight(strings.ToLower(strings.TrimSpace(selfHost)), ".")
	if canonSelf != "" && host == canonSelf {
		return false
	}
	labels := strings.Split(host, ".")
	for _, lbl := range labels {
		if lbl == "" || strings.HasPrefix(lbl, "-") || strings.HasSuffix(lbl, "-") {
			return false
		}
	}
	return !reNumericOrHexLabel.MatchString(labels[len(labels)-1])
}

// ValidatePublicHTTPSTargetURL validates that raw is a public https:// URL on port 443.
func ValidatePublicHTTPSTargetURL(raw, selfHost string) PublicURLCheckResult {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return PublicURLCheckResult{OK: false, Error: "invalid_url", Reason: "invalid_url", Message: "url must be a non-empty https:// string"}
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return PublicURLCheckResult{OK: false, Error: "invalid_url", Reason: "invalid_url", Message: "invalid URL: " + raw}
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return PublicURLCheckResult{OK: false, Error: "invalid_url", Reason: "scheme_not_allowed", Message: "only https:// URLs are permitted"}
	}
	if u.User != nil {
		return PublicURLCheckResult{OK: false, Error: "invalid_url", Reason: "credentials_not_allowed", Message: "URLs with embedded credentials are not permitted"}
	}
	parsed, ok := parseStrictHTTPURL(trimmed)
	if !ok {
		return PublicURLCheckResult{OK: false, Error: "invalid_url", Reason: "invalid_url", Message: "invalid URL: " + raw}
	}
	if parsed.explicitPort != "" {
		return PublicURLCheckResult{OK: false, Error: "invalid_url", Reason: "port_not_allowed", Message: "only port 443 is permitted"}
	}
	if !isSafePublicHostname(parsed.hostname, selfHost) {
		switch classifyIPLiteralHost(parsed.hostname) {
		case "public_ip":
			return PublicURLCheckResult{
				OK: false, Error: "invalid_url", Reason: "ip_literal_not_allowed",
				Message: fmt.Sprintf("IP address literals are not allowed (%s); provide a public DNS hostname.", parsed.hostname),
			}
		case "private_ip":
			return PublicURLCheckResult{
				OK: false, Error: "invalid_url", Reason: "ssrf",
				Message: fmt.Sprintf("disallowed non-public IP address (%s): private, loopback, and metadata IPs are blocked", parsed.hostname),
			}
		default:
			return PublicURLCheckResult{OK: false, Error: "invalid_url", Reason: "ssrf", Message: "disallowed hostname: " + parsed.hostname}
		}
	}
	u.Scheme = "https"
	u.Host = parsed.hostname
	if u.Path == "" {
		u.Path = "/"
	}
	return PublicURLCheckResult{OK: true, Normalized: u.String()}
}

func isOfflineHost(urlStr string) bool {
	if strings.HasPrefix(urlStr, "workers-ai://") {
		return false
	}
	var h string
	if parsed, ok := parseStrictHTTPURL(stripBaseURLQuery(urlStr)); ok {
		h = parsed.hostname
	} else if u, err := url.Parse(urlStr); err == nil {
		h = strings.ToLower(u.Hostname())
	}
	return h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]" ||
		h == "host.docker.internal" || h == "ollama" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal")
}
