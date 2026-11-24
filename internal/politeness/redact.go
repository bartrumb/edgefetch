package politeness

import (
	"net/url"
	"strings"
)

type urlSepKind uint8

const (
	urlSepNone urlSepKind = iota
	urlSepPlain
	urlSepJSONSlash
	urlSepPctEncoded
	urlSepProtoRel
	urlSepMailto
)

func asciiLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func hasPrefixFoldASCII(s, lowerPrefix string) bool {
	if len(s) < len(lowerPrefix) {
		return false
	}
	for i := 0; i < len(lowerPrefix); i++ {
		if asciiLowerByte(s[i]) != lowerPrefix[i] {
			return false
		}
	}
	return true
}

func isHostStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '['
}

func isProtoRelBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '"', '\'', '=', '(', '[', '{', '<', ',', ';', '|':
		return true
	default:
		return false
	}
}

func hasEncodedBoundaryBefore(s string, i int) bool {
	if i < 3 || s[i-3] != '%' {
		return false
	}
	sub := s[i-3 : i]
	return hasPrefixFoldASCII(sub, "%22") || hasPrefixFoldASCII(sub, "%27") ||
		hasPrefixFoldASCII(sub, "%20") || hasPrefixFoldASCII(sub, "%09") ||
		hasPrefixFoldASCII(sub, "%0a") || hasPrefixFoldASCII(sub, "%0d") ||
		hasPrefixFoldASCII(sub, "%3c") || hasPrefixFoldASCII(sub, "%28") ||
		hasPrefixFoldASCII(sub, "%3d")
}

func matchURLSchemeAt(s string, i int) (sep urlSepKind, afterSep int) {
	if i < 0 || i >= len(s) {
		return urlSepNone, 0
	}
	if s[i] == '/' {
		if i+2 < len(s) && s[i+1] == '/' && isHostStartByte(s[i+2]) &&
			(i == 0 || isProtoRelBoundary(s[i-1]) || hasEncodedBoundaryBefore(s, i)) {
			// Verify authority after // looks like a real host ([ipv6], localhost, user@..., or domain with dot), not a plain //comment.
			rest := s[i+2:]
			endAuth := len(rest)
			for k := 0; k < len(rest); k++ {
				c := rest[k]
				if c == '/' || c == '?' || c == '#' || c == ';' || c <= ' ' || c == '"' || c == '\'' || c == ')' || c == '>' || c == '%' {
					endAuth = k
					break
				}
			}
			auth := rest[:endAuth]
			if strings.HasPrefix(rest, "[") || strings.IndexByte(auth, '.') > 0 || strings.IndexByte(auth, '@') > 0 || hasPrefixFoldASCII(auth, "localhost") {
				return urlSepProtoRel, i + 2
			}
		}
		return urlSepNone, 0
	}
	c0 := asciiLowerByte(s[i])
	switch c0 {
	case 'h', 'w', 'f', 's', 'r', 'p', 'm', 'a', 'g', 'l', 'n':
	default:
		return urlSepNone, 0
	}
	// Avoid matching inside a longer identifier like "myhttp://", except percent-encoded quotes/spaces like "%22https://".
	if i > 0 && !hasEncodedBoundaryBefore(s, i) {
		prev := asciiLowerByte(s[i-1])
		if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') {
			return urlSepNone, 0
		}
	}
	rem := s[i:]
	schemeLen := 0
	switch c0 {
	case 'h':
		if hasPrefixFoldASCII(rem, "https") {
			schemeLen = 5
		} else if hasPrefixFoldASCII(rem, "http") {
			schemeLen = 4
		}
	case 'w':
		if hasPrefixFoldASCII(rem, "wss") {
			schemeLen = 3
		} else if hasPrefixFoldASCII(rem, "ws") {
			schemeLen = 2
		}
	case 'f':
		if hasPrefixFoldASCII(rem, "ftps") {
			schemeLen = 4
		} else if hasPrefixFoldASCII(rem, "ftp") {
			schemeLen = 3
		} else if hasPrefixFoldASCII(rem, "file") {
			schemeLen = 4
		}
	case 's':
		if hasPrefixFoldASCII(rem, "socks5h") {
			schemeLen = 7
		} else if hasPrefixFoldASCII(rem, "socks5") {
			schemeLen = 6
		} else if hasPrefixFoldASCII(rem, "sftp") {
			schemeLen = 4
		} else if hasPrefixFoldASCII(rem, "ssh") {
			schemeLen = 3
		} else if hasPrefixFoldASCII(rem, "s3") {
			schemeLen = 2
		}
	case 'g':
		if hasPrefixFoldASCII(rem, "gs") {
			schemeLen = 2
		}
	case 'r':
		if hasPrefixFoldASCII(rem, "rediss") {
			schemeLen = 6
		} else if hasPrefixFoldASCII(rem, "redis") {
			schemeLen = 5
		}
	case 'p':
		if hasPrefixFoldASCII(rem, "postgresql") {
			schemeLen = 10
		} else if hasPrefixFoldASCII(rem, "postgres") {
			schemeLen = 8
		}
	case 'm':
		if hasPrefixFoldASCII(rem, "mailto:") {
			if len(rem) > 7 && rem[7] > ' ' {
				return urlSepMailto, i + 7
			}
			return urlSepNone, 0
		}
		if hasPrefixFoldASCII(rem, "mongodb+srv") {
			schemeLen = 11
		} else if hasPrefixFoldASCII(rem, "mongodb") {
			schemeLen = 7
		} else if hasPrefixFoldASCII(rem, "mysql") {
			schemeLen = 5
		}
	case 'a':
		if hasPrefixFoldASCII(rem, "amqps") {
			schemeLen = 5
		} else if hasPrefixFoldASCII(rem, "amqp") {
			schemeLen = 4
		}
	case 'l':
		if hasPrefixFoldASCII(rem, "ldaps") {
			schemeLen = 5
		} else if hasPrefixFoldASCII(rem, "ldap") {
			schemeLen = 4
		}
	case 'n':
		if hasPrefixFoldASCII(rem, "nats") {
			schemeLen = 4
		}
	}
	if schemeLen == 0 {
		return urlSepNone, 0
	}
	tail := rem[schemeLen:]
	switch {
	case strings.HasPrefix(tail, "://"):
		return urlSepPlain, i + schemeLen + 3
	case strings.HasPrefix(tail, `:\/\/`):
		return urlSepJSONSlash, i + schemeLen + 5
	case hasPrefixFoldASCII(tail, "%3a%2f%2f"):
		return urlSepPctEncoded, i + schemeLen + 9
	default:
		return urlSepNone, 0
	}
}

func countPrecedingBackslashes(s string, pos int) int {
	n := 0
	for pos > 0 && s[pos-1] == '\\' {
		n++
		pos--
	}
	return n
}

func isAllDigitsASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

var sensitivePathActionSegments = map[string]bool{
	"reset":       true,
	"verify":      true,
	"confirm":     true,
	"magic":       true,
	"token":       true,
	"invite":      true,
	"activate":    true,
	"unsubscribe": true,
	"secret":      true,
	"secrets":     true,
	"apikey":      true,
	"api-key":     true,
	"api_key":     true,
	"webhook":     true,
	"webhooks":    true,
}

func scrubPathMatrixAndResetTokens(pathPart string) string {
	if pathPart == "" {
		return ""
	}
	needsWork := strings.IndexByte(pathPart, ';') >= 0
	if !needsWork {
		lp := strings.ToLower(pathPart)
		if strings.Contains(lp, "/secret") {
			needsWork = true
		} else {
			for k := range sensitivePathActionSegments {
				if strings.Contains(lp, "/"+k+"/") {
					needsWork = true
					break
				}
			}
		}
	}
	if !needsWork {
		return pathPart
	}
	segs := strings.Split(pathPart, "/")
	redactNext := false
	for idx, seg := range segs {
		if semi := strings.IndexByte(seg, ';'); semi >= 0 {
			seg = seg[:semi]
			segs[idx] = seg
		}
		if seg == "" {
			continue
		}
		lowSeg := strings.ToLower(seg)
		if redactNext {
			segs[idx] = "[REDACTED]"
			redactNext = false
			continue
		}
		if lowSeg == "secret" || lowSeg == "secrets" {
			segs[idx] = "[REDACTED]"
			redactNext = idx+1 < len(segs) && segs[idx+1] != ""
			continue
		}
		if sensitivePathActionSegments[lowSeg] {
			redactNext = true
		}
	}
	return strings.Join(segs, "/")
}

func cutEarliestFold(s string, markers ...string) string {
	cutAt := len(s)
	for _, m := range markers {
		for i := 0; i+len(m) <= cutAt; i++ {
			if hasPrefixFoldASCII(s[i:], m) {
				cutAt = i
				break
			}
		}
	}
	return s[:cutAt]
}

func stripAuthUserinfo(auth string) string {
	if at := strings.LastIndexByte(auth, '@'); at >= 0 {
		return auth[at+1:]
	}
	lastPctAtEnd := -1
	for i := 0; i+3 <= len(auth); i++ {
		if hasPrefixFoldASCII(auth[i:], "%40") {
			lastPctAtEnd = i + 3
		}
	}
	if lastPctAtEnd >= 0 {
		return auth[lastPctAtEnd:]
	}
	return auth
}

func scrubMatchedURL(raw string, kind urlSepKind) string {
	if raw == "" {
		return ""
	}
	if kind == urlSepMailto {
		raw = cutEarliestFold(raw, "?", "#", "%3f", "%23")
		return raw
	}
	if kind == urlSepPctEncoded {
		raw = cutEarliestFold(raw, "?", "#", "%3f", "%23", "%3b")
		sepIdx := -1
		for i := 0; i+9 <= len(raw); i++ {
			if hasPrefixFoldASCII(raw[i:], "%3a%2f%2f") {
				sepIdx = i + 9
				break
			}
		}
		if sepIdx >= 0 {
			rest := raw[sepIdx:]
			slashIdx := len(rest)
			for i := 0; i < len(rest); i++ {
				if rest[i] == '/' || hasPrefixFoldASCII(rest[i:], "%2f") {
					slashIdx = i
					break
				}
			}
			auth := stripAuthUserinfo(rest[:slashIdx])
			pathPart := rest[slashIdx:]
			raw = raw[:sepIdx] + auth + pathPart
		}
		return raw
	}

	if kind == urlSepJSONSlash {
		raw = cutEarliestFold(raw, "#", "?", `\u003f`, `\u0023`)
		if idx := strings.Index(raw, `:\/\/`); idx >= 0 {
			rest := raw[idx+5:]
			slash := strings.Index(rest, `\/`)
			auth := rest
			pathPart := ""
			if slash >= 0 {
				auth = rest[:slash]
				pathPart = rest[slash:]
			}
			if semi := strings.IndexByte(pathPart, ';'); semi >= 0 {
				pathPart = pathPart[:semi]
			}
			auth = stripAuthUserinfo(auth)
			raw = raw[:idx+5] + auth + pathPart
		}
		return raw
	}

	// Plain `scheme://...` or protocol-relative `//...`:
	// Before stripping `?`/`#`, check if `?`/`#`/`/` is actually inside unescaped userinfo (`user:pa?ss@host/p` or `user:pa/ss@host/p`).
	sepEnd := -1
	if kind == urlSepProtoRel && strings.HasPrefix(raw, "//") {
		sepEnd = 2
	} else if idx := strings.Index(raw, "://"); idx >= 0 {
		sepEnd = idx + 3
	}
	if sepEnd >= 0 {
		rest := raw[sepEnd:]
		delim := strings.IndexAny(rest, "/?#")
		head := rest
		if delim >= 0 {
			head = rest[:delim]
		}
		if strings.IndexByte(head, '@') < 0 && !strings.HasPrefix(head, "[") {
			if colon := strings.IndexByte(head, ':'); colon >= 0 && !isAllDigitsASCII(head[colon+1:]) {
				if lastAt := strings.LastIndexByte(rest, '@'); lastAt >= 0 {
					raw = raw[:sepEnd] + rest[lastAt+1:]
				}
			} else if pctColon := indexFoldASCII(head, "%3a"); pctColon >= 0 {
				if lastAt := strings.LastIndexByte(rest, '@'); lastAt >= 0 {
					raw = raw[:sepEnd] + rest[lastAt+1:]
				}
			}
		}
	}

	if idx := strings.IndexByte(raw, '#'); idx >= 0 {
		raw = raw[:idx]
	}
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		raw = raw[:idx]
	}
	raw = cutEarliestFold(raw, `\u003f`, `\u0023`, "%3f", "%23")

	if sepEnd >= 0 && sepEnd <= len(raw) {
		isFileScheme := sepEnd >= 7 && hasPrefixFoldASCII(raw[:sepEnd], "file://")
		rest := raw[sepEnd:]
		slash := strings.IndexByte(rest, '/')
		auth := rest
		pathPart := ""
		if slash >= 0 {
			auth = rest[:slash]
			pathPart = rest[slash:]
		}
		auth = stripAuthUserinfo(auth)
		if isFileScheme {
			if pathPart != "" && pathPart != "/" {
				pathPart = "/[REDACTED]"
			}
		} else {
			pathPart = scrubPathMatrixAndResetTokens(pathPart)
		}
		raw = raw[:sepEnd] + auth + pathPart
	}
	return raw
}

func indexFoldASCII(s, lowerNeedle string) int {
	for i := 0; i+len(lowerNeedle) <= len(s); i++ {
		if hasPrefixFoldASCII(s[i:], lowerNeedle) {
			return i
		}
	}
	return -1
}

func isKnownStandardScheme(lowerScheme string) bool {
	switch lowerScheme {
	case "http", "https", "ws", "wss", "ftp", "ftps", "sftp", "socks5", "socks5h",
		"redis", "rediss", "postgres", "postgresql", "mailto", "file", "blob", "about", "data":
		return true
	default:
		return false
	}
}

func scrubSchemelessAuthorityAndPath(raw string) string {
	// Strip `#fragment` and `?query` after handling any unescaped `user:pass@host/path` prefix.
	slashOrQuery := strings.IndexAny(raw, "/?#")
	head := raw
	if slashOrQuery >= 0 {
		head = raw[:slashOrQuery]
	}
	if at := strings.LastIndexByte(head, '@'); at >= 0 {
		raw = raw[at+1:]
	} else if colon := strings.IndexByte(head, ':'); colon >= 0 && !isAllDigitsASCII(head[colon+1:]) {
		if lastAt := strings.LastIndexByte(raw, '@'); lastAt >= 0 {
			raw = raw[lastAt+1:]
		}
	} else if pctAt := indexFoldASCII(head, "%40"); pctAt >= 0 {
		raw = raw[pctAt+3:]
	}
	if idx := strings.IndexByte(raw, '#'); idx >= 0 {
		raw = raw[:idx]
	}
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		raw = raw[:idx]
	}
	if slash := strings.IndexByte(raw, '/'); slash >= 0 {
		if semi := strings.IndexByte(raw[:slash], ';'); semi >= 0 {
			raw = raw[:semi] + scrubPathMatrixAndResetTokens(raw[slash:])
		} else {
			raw = raw[:slash] + scrubPathMatrixAndResetTokens(raw[slash:])
		}
	} else if semi := strings.IndexByte(raw, ';'); semi >= 0 {
		raw = raw[:semi]
	}
	return raw
}

// SanitizeURL strips `user:pass@` credentials (including schemeless `user:secret@host/path` and `%40`-encoded userinfo),
// query parameters (`?...`), `#fragments`, matrix parameters (`;...`), and sensitive action path tokens (`/reset/<token>`)
// from `raw` for safe structured logging and OpenTelemetry `url.full` attributes.
func SanitizeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "//") {
		return scrubMatchedURL(trimmed, urlSepProtoRel)
	}
	if kind, _ := matchURLSchemeAt(trimmed, 0); kind != urlSepNone {
		scrubbed := scrubMatchedURL(trimmed, kind)
		if kind == urlSepPlain && !hasPrefixFoldASCII(scrubbed, "file://") {
			if u, err := url.Parse(scrubbed); err == nil && u.Scheme != "" {
				u.User = nil
				u.RawQuery = ""
				u.ForceQuery = false
				u.Fragment = ""
				u.RawFragment = ""
				u.Path = scrubPathMatrixAndResetTokens(u.Path)
				u.RawPath = ""
				return u.String()
			}
		}
		return scrubbed
	}
	// Schemeless `user:secret@example.com/path` or `example.com/path?token=x`:
	// Note that `url.Parse("user:secret@example.com/path")` misparses `"user"` as `u.Scheme` and `"secret@..."` as `u.Opaque`!
	if !strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil && u.Scheme != "" && isKnownStandardScheme(strings.ToLower(u.Scheme)) {
			u.User = nil
			u.RawQuery = ""
			u.ForceQuery = false
			u.Fragment = ""
			u.RawFragment = ""
			u.Path = scrubPathMatrixAndResetTokens(u.Path)
			u.RawPath = ""
			return u.String()
		}
		return scrubSchemelessAuthorityAndPath(trimmed)
	}
	return scrubMatchedURL(trimmed, urlSepPlain)
}

func looksLikeSecretTokenValue(tok string) bool {
	if len(tok) < 6 {
		return false
	}
	hasDigit := false
	hasUpper := false
	hasSym := false
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c == '-' || c == '_' || c == '.' || c == '/' || c == '+' || c == '=':
			hasSym = true
		}
	}
	return hasDigit || (hasUpper && hasSym) || len(tok) >= 20
}

const unquotedQueryStopChars = " \t\r\n<>')]}%\xc2\xe2"
const bareURLStopChars = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f \"'<>)]}\\%\xc2\xe2"

func findUnquotedURLEnd(s string, start int, kind urlSepKind) int {
	sawQuery := false
	j := start
	for j < len(s) {
		if sawQuery && kind != urlSepPctEncoded && kind != urlSepJSONSlash {
			if rel := strings.IndexAny(s[j:], unquotedQueryStopChars); rel >= 0 {
				j += rel
			} else {
				j = len(s)
				break
			}
		}
		c := s[j]
		if c == '?' || c == '#' || c == ';' {
			sawQuery = true
			j++
			continue
		}
		if kind == urlSepPctEncoded && (hasPrefixFoldASCII(s[j:], "%3f") || hasPrefixFoldASCII(s[j:], "%23") || hasPrefixFoldASCII(s[j:], "%3b")) {
			sawQuery = true
			j += 3
			continue
		}
		if c == '\r' || c == '\n' || c == '<' || c == '>' || c == '\'' || c == ')' || c == ']' || c == '}' {
			// Allow ']' inside an IPv6 host literal (`scheme://[::1]:8080/...`) or malformed userinfo before '@'.
			if c == ']' && !sawQuery {
				if openBr := strings.LastIndexByte(s[start:j], '['); openBr >= 0 && strings.IndexByte(s[start+openBr:j], '/') < 0 {
					j++
					continue
				}
			}
			break
		}
		if hasPrefixFoldASCII(s[j:], "%22") || hasPrefixFoldASCII(s[j:], "%27") || hasPrefixFoldASCII(s[j:], "%3e") {
			// If URL was delimited by %22/%27/%3c or %22 is followed by whitespace/colon, terminate before the encoded quote.
			if (start >= 5 && hasEncodedBoundaryBefore(s, start-2)) ||
				j+3 >= len(s) || s[j+3] == ':' || s[j+3] == ' ' || s[j+3] == ',' || s[j+3] == ';' || s[j+3] == ')' {
				break
			}
		}
		// Unicode NEL (C2 85) and LS/PS (E2 80 A8 / E2 80 A9) terminate unquoted tokens.
		if c == 0xc2 && j+1 < len(s) && s[j+1] == 0x85 {
			break
		}
		if c == 0xe2 && j+2 < len(s) && s[j+1] == 0x80 && (s[j+2] == 0xa8 || s[j+2] == 0xa9) {
			break
		}
		if kind == urlSepJSONSlash && c == '\\' && j+1 < len(s) && s[j+1] == '/' {
			j += 2
			continue
		}
		if !sawQuery && (c == '"' || c == '\\') {
			break
		}
		if c == ' ' || c == '\t' {
			if sawQuery {
				k := j + 1
				for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
					k++
				}
				tokEnd := k
				for tokEnd < len(s) && s[tokEnd] != ' ' && s[tokEnd] != '\t' && s[tokEnd] != '\r' && s[tokEnd] != '\n' {
					tokEnd++
				}
				tok := s[k:tokEnd]
				if tok != "" {
					if nextKind, _ := matchURLSchemeAt(s, k); nextKind == urlSepNone && !strings.Contains(tok, "://") &&
						(strings.IndexByte(tok, '=') >= 0 || strings.IndexByte(tok, '&') >= 0) {
						j = tokEnd
						continue
					}
				}
			}
			break
		}
		j++
	}
	// Trim trailing sentence punctuation (e.g. `,` or `;` in `http://[::1]:8080/p?k=SECRET, http://...`).
	for j > start {
		last := s[j-1]
		if last == ',' || last == '.' || last == ';' {
			j--
			continue
		}
		break
	}
	return j
}

func isValidBareDomainHost(h string) bool {
	if len(h) < 4 {
		return false
	}
	if strings.IndexByte(h, '.') < 0 {
		return strings.EqualFold(h, "localhost")
	}
	// Check IPv4 literal a.b.c.d
	if len(h) >= 7 && len(h) <= 15 && h[0] >= '0' && h[0] <= '9' {
		endIP, _, ok := matchIPPortToken(h+":80", 0)
		if ok && endIP == len(h)+3 {
			return true
		}
	}
	lastDot := -1
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c == '.' {
			if i == 0 || i == len(h)-1 || h[i-1] == '.' || h[i-1] == '-' || h[i+1] == '-' {
				return false
			}
			lastDot = i
			continue
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	if lastDot <= 0 {
		return false
	}
	tld := h[lastDot+1:]
	if len(tld) < 2 {
		return false
	}
	if hasPrefixFoldASCII(tld, "xn--") {
		return len(tld) > 4
	}
	for i := 0; i < len(tld); i++ {
		c := tld[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

func tryMatchBareHostURLAt(s string, i int) (endIdx int, scrubbed string, scanSkipTo int, ok bool) {
	if i > 0 && isSchemelessPrevBlocked(s[i-1]) && !hasEncodedBoundaryBefore(s, i) {
		return 0, "", i + 1, false
	}
	c0 := s[i]
	if !((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || (c0 >= '0' && c0 <= '9') || c0 == '[') {
		return 0, "", i + 1, false
	}
	n := len(s)
	hostEnd := i
	if c0 == '[' {
		p := i + 1
		for p < n && s[p] != ']' && p-i <= 64 {
			c := s[p]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.' || c == '%') {
				return 0, "", p, false
			}
			p++
		}
		if p >= n || p <= i+2 || s[p] != ']' || strings.IndexByte(s[i+1:p], ':') < 0 {
			return 0, "", p, false
		}
		hostEnd = p + 1
	} else {
		for hostEnd < n {
			c := s[hostEnd]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
				hostEnd++
				continue
			}
			break
		}
		if !isValidBareDomainHost(s[i:hostEnd]) {
			return 0, "", hostEnd, false
		}
	}

	hasPort := false
	afterAuth := hostEnd
	if afterAuth < n && s[afterAuth] == ':' {
		pStart := afterAuth + 1
		pEnd := pStart
		var portVal int
		for pEnd < n && s[pEnd] >= '0' && s[pEnd] <= '9' && pEnd-pStart < 5 {
			portVal = portVal*10 + int(s[pEnd]-'0')
			pEnd++
		}
		if pEnd == pStart || portVal < 1 || portVal > 65535 {
			return 0, "", hostEnd, false
		}
		hasPort = true
		afterAuth = pEnd
	} else if c0 == '[' {
		// Bare [::1] without :port is only treated as a URL when immediately followed by /path
		if afterAuth >= n || s[afterAuth] != '/' {
			return 0, "", hostEnd, false
		}
	}

	if afterAuth >= n {
		return 0, "", afterAuth, false
	}
	nextCh := s[afterAuth]
	if nextCh != '/' && !(hasPort && (nextCh == '?' || nextCh == '#' || nextCh == ';')) {
		return 0, "", afterAuth, false
	}

	// Scan remainder of bare URL up to whitespace / quote / bracket / paren / %22 using SIMD IndexAny
	j := afterAuth
	for j < n {
		rel := strings.IndexAny(s[j:], bareURLStopChars)
		if rel < 0 {
			j = n
			break
		}
		j += rel
		c := s[j]
		if c == '%' {
			if hasPrefixFoldASCII(s[j:], "%22") || hasPrefixFoldASCII(s[j:], "%27") || hasPrefixFoldASCII(s[j:], "%3e") {
				break
			}
			j++
			continue
		}
		if c == 0xc2 {
			if j+1 < n && s[j+1] == 0x85 {
				break
			}
			j++
			continue
		}
		if c == 0xe2 {
			if j+2 < n && s[j+1] == 0x80 && (s[j+2] == 0xa8 || s[j+2] == 0xa9) {
				break
			}
			j++
			continue
		}
		break
	}
	for j > afterAuth && (s[j-1] == ',' || s[j-1] == '.' || s[j-1] == ';') {
		j--
	}
	if j <= afterAuth {
		return 0, "", afterAuth, false
	}

	authStr := s[i:afterAuth]
	tail := s[afterAuth:j]
	if hasPort || c0 == '[' {
		// Bare `host.tld:8443/secret` or `[::1]:8080/secret?tok=1`: scrub path + query + fragment completely.
		if strings.HasPrefix(tail, "/") && len(tail) > 1 {
			return j, authStr + "/[REDACTED]", j, true
		}
		return j, authStr, j, true
	}

	// Domain without :port (`host.tld/path?key=1#tok=2`): scrub query, fragment, matrix params, and sensitive segments.
	cleanTail := tail
	if idx := strings.IndexByte(cleanTail, '#'); idx >= 0 {
		cleanTail = cleanTail[:idx]
	}
	if idx := strings.IndexByte(cleanTail, '?'); idx >= 0 {
		cleanTail = cleanTail[:idx]
	}
	cleanTail = cutEarliestFold(cleanTail, `\u003f`, `\u0023`, "%3f", "%23")
	cleanTail = scrubPathMatrixAndResetTokens(cleanTail)
	if cleanTail == tail {
		return 0, "", j, false
	}
	return j, authStr + cleanTail, j, true
}

func isHostTokenBytes(h string) bool {
	if len(h) < 3 {
		return false
	}
	if strings.HasPrefix(h, "[") {
		closeBr := strings.IndexByte(h, ']')
		return closeBr > 1
	}
	dot := strings.IndexByte(h, '.')
	if dot <= 0 || dot == len(h)-1 {
		if !hasPrefixFoldASCII(h, "localhost") {
			return false
		}
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

func isSchemelessPrevBlocked(prev byte) bool {
	return (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') ||
		prev == '/' || prev == ':' || prev == '@' || prev == '.' || prev == '_' || prev == '-'
}

const schemelessTermChars = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f \"'<>),{}\\`|"

func clampAtUTF8LineBreak(s string, from, end int) int {
	// Fast SIMD scan via strings.IndexByte so 1 MiB pure-ASCII inputs pay O(1) calls (zero per-byte -race/-coverprofile overhead).
	for k := from; k < end; {
		relC2 := strings.IndexByte(s[k:end], 0xc2)
		relE2 := strings.IndexByte(s[k:end], 0xe2)
		if relC2 < 0 && relE2 < 0 {
			return end
		}
		nextRel := relC2
		if nextRel < 0 || (relE2 >= 0 && relE2 < nextRel) {
			nextRel = relE2
		}
		pos := k + nextRel
		if s[pos] == 0xc2 {
			if pos+1 < end && s[pos+1] == 0x85 {
				return pos
			}
		} else if pos+2 < end && s[pos+1] == 0x80 && (s[pos+2] == 0xa8 || s[pos+2] == 0xa9) {
			return pos
		}
		k = pos + 1
	}
	return end
}

func clampSchemelessOuterBracketAndPunct(s string, lastAt, tokEnd int) int {
	k := lastAt + 1
	// Allow a single IPv6 bracketed host literal immediately following `@` (`@[::1]:8080/...`).
	if k < tokEnd && s[k] == '[' {
		k++
		for k < tokEnd && s[k] != ']' {
			k++
		}
		if k < tokEnd && s[k] == ']' {
			k++
		}
	}
	// Any subsequent `]` is an enclosing bracket delimiter (`[user:secret@example.com]:443` or `[user:secret@[::1]]:443`).
	for ; k < tokEnd; k++ {
		if s[k] == ']' {
			tokEnd = k
			break
		}
	}
	for tokEnd > lastAt+1 && (s[tokEnd-1] == ';' || s[tokEnd-1] == ',') {
		tokEnd--
	}
	return tokEnd
}

type schemelessSpanCache struct {
	tokEnd            int
	lastAt            int
	lastColonBeforeAt int
	hostValid         bool
	hasPathOrQuery    bool
	afterChanged      bool
	canMatchAny       bool
	cleanAfter        string
}

func (sc *schemelessSpanCache) refresh(s string, from int) {
	tokEnd := len(s)
	if rel := strings.IndexAny(s[from:], schemelessTermChars); rel >= 0 {
		tokEnd = from + rel
	}
	tokEnd = clampAtUTF8LineBreak(s, from, tokEnd)
	lastAt := -1
	if relAt := strings.LastIndexByte(s[from:tokEnd], '@'); relAt >= 0 {
		lastAt = from + relAt
	}
	if lastAt > from {
		tokEnd = clampSchemelessOuterBracketAndPunct(s, lastAt, tokEnd)
	}
	sc.tokEnd = tokEnd
	sc.lastAt = lastAt
	sc.lastColonBeforeAt = -1
	sc.hostValid = false
	sc.hasPathOrQuery = false
	sc.afterChanged = false
	sc.canMatchAny = false
	sc.cleanAfter = ""

	if lastAt <= from {
		return
	}
	afterAt := s[lastAt+1 : tokEnd]
	slashOrQ := strings.IndexAny(afterAt, "/?#")
	hostPart := afterAt
	if slashOrQ >= 0 {
		hostPart = afterAt[:slashOrQ]
	}
	if semi := strings.IndexByte(hostPart, ';'); semi >= 0 {
		if strings.IndexByte(hostPart[semi+1:], '=') < 0 {
			tokEnd = lastAt + 1 + semi
			sc.tokEnd = tokEnd
			afterAt = s[lastAt+1 : tokEnd]
			slashOrQ = -1
			hostPart = afterAt
		} else {
			hostPart = hostPart[:semi]
		}
	}
	if !isHostTokenBytes(hostPart) {
		return
	}
	sc.hostValid = true
	sc.hasPathOrQuery = slashOrQ >= 0
	sc.cleanAfter = scrubSchemelessAuthorityAndPath(afterAt)
	sc.afterChanged = sc.cleanAfter != afterAt

	lastColon := -1
	if relCol := strings.LastIndexByte(s[from:lastAt], ':'); relCol >= 0 {
		lastColon = from + relCol
	}
	pctFloor := from
	if lastColon >= pctFloor {
		pctFloor = lastColon + 1
	}
	for pctFloor+3 <= lastAt {
		relPct := strings.IndexByte(s[pctFloor:lastAt], '%')
		if relPct < 0 {
			break
		}
		pos := pctFloor + relPct
		if pos+3 <= lastAt && hasPrefixFoldASCII(s[pos:], "%3a") {
			lastColon = pos
			pctFloor = pos + 3
		} else {
			pctFloor = pos + 1
		}
	}
	sc.lastColonBeforeAt = lastColon
	sc.canMatchAny = lastColon >= from || (sc.hasPathOrQuery && sc.afterChanged)
}

func (sc *schemelessSpanCache) matchAt(s string, i int) (endIdx int, scrubbed string, ok bool) {
	// Match schemeless `user:secret@host.tld[/path][?query][#frag]` at word/quote boundary in O(1) amortized time.
	if i > 0 && isSchemelessPrevBlocked(s[i-1]) {
		return 0, "", false
	}
	if i >= sc.tokEnd {
		sc.refresh(s, i)
	}
	if !sc.canMatchAny || sc.lastAt <= i || !sc.hostValid {
		return 0, "", false
	}
	hasColon := sc.lastColonBeforeAt >= i
	if !hasColon && !sc.hasPathOrQuery {
		return 0, "", false
	}
	if !hasColon {
		if !sc.afterChanged {
			return 0, "", false
		}
		// Preserve `user@host/path` when no password is present, while still stripping `?query`, `#frag`, `;matrix`, `/reset/<tok>`.
		return sc.tokEnd, s[i:sc.lastAt] + "@" + sc.cleanAfter, true
	}
	return sc.tokEnd, sc.cleanAfter, true
}

func isIPPortTerminator(b byte) bool {
	switch b {
	case ':', ' ', '\t', '\r', '\n', ',', ';', ')', '"', '\'', '-', '>':
		return true
	default:
		return false
	}
}

func matchIPPortToken(s string, start int) (endIdx int, port string, ok bool) {
	if start < 0 || start >= len(s) {
		return 0, "", false
	}
	j := start
	if s[j] == '[' {
		j++
		bodyStart := j
		for j < len(s) && s[j] != ']' {
			c := s[j]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == ':' || c == '.' || c == '%' || c == '-' || c == '_') {
				return 0, "", false
			}
			j++
		}
		if j >= len(s) || j == bodyStart || s[j] != ']' {
			return 0, "", false
		}
		j++
	} else {
		for oct := 0; oct < 4; oct++ {
			if oct > 0 {
				if j >= len(s) || s[j] != '.' {
					return 0, "", false
				}
				j++
			}
			val := 0
			digits := 0
			for j < len(s) && s[j] >= '0' && s[j] <= '9' && digits < 3 {
				val = val*10 + int(s[j]-'0')
				digits++
				j++
			}
			if digits == 0 || val > 255 {
				return 0, "", false
			}
		}
	}
	if j >= len(s) || s[j] != ':' {
		return 0, "", false
	}
	j++
	portStart := j
	for j < len(s) && s[j] >= '0' && s[j] <= '9' && j-portStart < 5 {
		j++
	}
	if j == portStart {
		return 0, "", false
	}
	if j < len(s) && !isIPPortTerminator(s[j]) {
		return 0, "", false
	}
	return j, s[portStart:j], true
}

func tryMatchDNSResolverAddr(s string, i int, seenLookup bool) (addrStart, addrEnd int, ok bool) {
	c0 := asciiLowerByte(s[i])
	// Pattern 1: `lookup <host> on <ip>:<port>` (or standalone ` on <ip>:53`)
	if c0 == 'o' && i > 0 && s[i-1] == ' ' && hasPrefixFoldASCII(s[i:], "on ") {
		endIdx, port, matched := matchIPPortToken(s, i+3)
		if matched && (seenLookup || port == "53" || port == "5353") {
			return i + 3, endIdx, true
		}
		return 0, 0, false
	}
	// Pattern 2: `(dial|read|write) udp[46]? (<src>->)?<ip>:<port>` or `dial tcp[46]? (<src>->)?<ip>:53`
	if (c0 == 'd' || c0 == 'r' || c0 == 'w') &&
		(i == 0 || !((asciiLowerByte(s[i-1]) >= 'a' && asciiLowerByte(s[i-1]) <= 'z') || (s[i-1] >= '0' && s[i-1] <= '9'))) {
		verbLen := 0
		isTCP := false
		switch {
		case hasPrefixFoldASCII(s[i:], "dial udp"):
			verbLen = 8
		case hasPrefixFoldASCII(s[i:], "read udp"):
			verbLen = 8
		case hasPrefixFoldASCII(s[i:], "write udp"):
			verbLen = 9
		case hasPrefixFoldASCII(s[i:], "dial tcp"):
			verbLen = 8
			isTCP = true
		}
		if verbLen > 0 {
			p := i + verbLen
			if p < len(s) && (s[p] == '4' || s[p] == '6') {
				p++
			}
			if p < len(s) && s[p] == ' ' {
				p++
				end1, port1, m1 := matchIPPortToken(s, p)
				if m1 {
					finalEnd := end1
					finalPort := port1
					if end1+2 < len(s) && s[end1] == '-' && s[end1+1] == '>' {
						if end2, port2, m2 := matchIPPortToken(s, end1+2); m2 {
							finalEnd = end2
							finalPort = port2
						}
					}
					if (!isTCP && seenLookup) || finalPort == "53" || finalPort == "5353" {
						return p, finalEnd, true
					}
				}
			}
		}
	}
	return 0, 0, false
}

// RedactEmbeddedURLs scrubs query strings (`?...`), `#fragments`, matrix parameters (`;...`), `user:pass@` credentials
// (both schemed and schemeless), reset path tokens, and inline bearer/basic/token/api_key secrets from URLs embedded
// inside error, log, or OpenTelemetry span strings in a single linear O(N) pass.
func RedactEmbeddedURLs(s string) string {
	if s == "" {
		return ""
	}
	hasColon := strings.IndexByte(s, ':') >= 0
	hasSlash := strings.IndexByte(s, '/') >= 0
	hasPct := strings.IndexByte(s, '%') >= 0
	hasAt := strings.IndexByte(s, '@') >= 0
	hasDotOrBracket := strings.IndexByte(s, '.') >= 0 || strings.IndexByte(s, '[') >= 0
	hasResolver := hasColon && hasDotOrBracket
	hasScheme := hasPct ||
		strings.Contains(s, "//") ||
		((hasColon || hasSlash) && strings.IndexByte(s, '\\') >= 0) ||
		(hasColon && strings.ContainsAny(s, "mM") && (strings.Contains(s, "mailto:") || strings.ContainsAny(s, "MAILTO")))
	hasBare := (hasColon || hasSlash) &&
		(hasDotOrBracket || strings.Contains(s, "localhost") || strings.ContainsAny(s, "LOCALHOST"))
	hasSecretKw := (hasColon || strings.IndexByte(s, ' ') >= 0 || strings.IndexByte(s, '\t') >= 0 || strings.IndexByte(s, '=') >= 0) &&
		(strings.Contains(s, "bearer") ||
			strings.Contains(s, "basic") ||
			strings.Contains(s, "token") ||
			strings.Contains(s, "api_key") ||
			strings.Contains(s, "apikey") ||
			(strings.ContainsAny(s, "BTA") && strings.ContainsAny(s, "eEiIoO")))
	if !hasResolver && !hasScheme && !hasAt && !hasBare && !hasSecretKw {
		return s
	}

	var out strings.Builder
	var spanCache schemelessSpanCache
	copiedUpTo := 0
	bareSkipUntil := 0
	seenLookup := false
	i := 0
	for i < len(s) {
		if s[i] <= ' ' {
			i++
			continue
		}
		if hasResolver {
			if asciiLowerByte(s[i]) == 'l' &&
				(i == 0 || !((asciiLowerByte(s[i-1]) >= 'a' && asciiLowerByte(s[i-1]) <= 'z') || (s[i-1] >= '0' && s[i-1] <= '9'))) &&
				hasPrefixFoldASCII(s[i:], "lookup ") {
				seenLookup = true
			}
			if addrStart, addrEnd, matched := tryMatchDNSResolverAddr(s, i, seenLookup); matched {
				if out.Cap() == 0 {
					out.Grow(len(s) + 16)
				}
				out.WriteString(s[copiedUpTo:addrStart])
				out.WriteString("[redacted-resolver]:53")
				copiedUpTo = addrEnd
				i = addrEnd
				continue
			}
		}
		if hasScheme {
			kind, afterSep := matchURLSchemeAt(s, i)
			if kind != urlSepNone {
				endIdx := afterSep
				quotePos := i - 1
				if i >= 5 && hasPrefixFoldASCII(s[i-5:i], "blob:") {
					quotePos = i - 6
				}
				if quotePos >= 0 && s[quotePos] == '"' {
					openBS := countPrecedingBackslashes(s, quotePos)
					if openBS%2 == 0 && openBS > 0 {
						// Even number of preceding backslashes (`\\"https://...`) escapes the backslashes, NOT the quote!
						openBS = 0
					}
					// Power-of-two modulus for recursive %q / JSON quote escaping (`openBS` in {0, 1, 3, 7, ...}).
					step := (openBS + 1) * 2
					foundClose := false
					for searchFrom := afterSep; searchFrom < len(s); {
						relQ := strings.IndexByte(s[searchFrom:], '"')
						if relQ < 0 {
							break
						}
						j := searchFrom + relQ
						bs := countPrecedingBackslashes(s, j)
						if (openBS == 0 && bs%2 == 0) || (openBS > 0 && bs >= openBS && bs%step == openBS) {
							endIdx = j - openBS
							foundClose = true
							break
						}
						searchFrom = j + 1
					}
					if !foundClose {
						endIdx = len(s)
					}
				} else if quotePos >= 0 && s[quotePos] == '\'' {
					foundClose := false
					for searchFrom := afterSep; searchFrom < len(s); {
						relQ := strings.IndexByte(s[searchFrom:], '\'')
						if relQ < 0 {
							break
						}
						j := searchFrom + relQ
						if countPrecedingBackslashes(s, j)%2 == 0 {
							endIdx = j
							foundClose = true
							break
						}
						searchFrom = j + 1
					}
					if !foundClose {
						endIdx = len(s)
					}
				} else if i >= 3 && (hasPrefixFoldASCII(s[i-3:i], "%22") || hasPrefixFoldASCII(s[i-3:i], "%27")) {
					closeTag := strings.ToLower(s[i-3 : i])
					foundClose := false
					for j := afterSep; j+3 <= len(s); j++ {
						if hasPrefixFoldASCII(s[j:], closeTag) {
							endIdx = j
							foundClose = true
							break
						}
						if s[j] == '\r' || s[j] == '\n' {
							endIdx = j
							foundClose = true
							break
						}
					}
					if !foundClose {
						endIdx = findUnquotedURLEnd(s, afterSep, kind)
					}
				} else {
					endIdx = findUnquotedURLEnd(s, afterSep, kind)
				}

				if endIdx < afterSep {
					endIdx = afterSep
				}
				scrubbed := scrubMatchedURL(s[i:endIdx], kind)
				if scrubbed != s[i:endIdx] || out.Cap() > 0 {
					if out.Cap() == 0 {
						out.Grow(i - copiedUpTo + len(scrubbed) + (len(s) - endIdx))
					}
					out.WriteString(s[copiedUpTo:i])
					out.WriteString(scrubbed)
					copiedUpTo = endIdx
				}
				i = endIdx
				continue
			}
		}

		// Schemeless `user:secret@host/path` or `user@host/path?token=...`
		if hasAt {
			if endIdx, scrubbed, ok := spanCache.matchAt(s, i); ok {
				if out.Cap() == 0 {
					out.Grow(len(s))
				}
				out.WriteString(s[copiedUpTo:i])
				out.WriteString(scrubbed)
				copiedUpTo = endIdx
				i = endIdx
				continue
			}
			if !hasColon && !hasSlash && !hasPct && !hasSecretKw && i < spanCache.tokEnd && !spanCache.canMatchAny {
				i = spanCache.tokEnd
				continue
			}
		}

		// Bare `host.tld:8443/secret`, `[::1]:8080/secret?tok=1`, or `host.tld/path?key=...#tok=...`
		if hasBare && i >= bareSkipUntil {
			endIdx, scrubbed, skipTo, matched := tryMatchBareHostURLAt(s, i)
			if matched {
				if out.Cap() == 0 {
					out.Grow(len(s))
				}
				out.WriteString(s[copiedUpTo:i])
				out.WriteString(scrubbed)
				copiedUpTo = endIdx
				bareSkipUntil = endIdx
				i = endIdx
				continue
			}
			if skipTo > bareSkipUntil {
				bareSkipUntil = skipTo
			}
		}

		// Redact inline "Bearer <secret>", "Basic <secret>", "token=<secret>", "api_key=<secret>", "apikey=<secret>" fragments outside URLs.
		if hasSecretKw {
			c0 := asciiLowerByte(s[i])
			if (c0 == 't' || c0 == 'b' || c0 == 'a') && (i == 0 || !((asciiLowerByte(s[i-1]) >= 'a' && asciiLowerByte(s[i-1]) <= 'z') || (s[i-1] >= '0' && s[i-1] <= '9'))) {
				kwLen := 0
				switch {
				case hasPrefixFoldASCII(s[i:], "bearer"):
					kwLen = 6
				case hasPrefixFoldASCII(s[i:], "basic"):
					kwLen = 5
				case hasPrefixFoldASCII(s[i:], "token"):
					kwLen = 5
				case hasPrefixFoldASCII(s[i:], "api_key"):
					kwLen = 7
				case hasPrefixFoldASCII(s[i:], "apikey"):
					kwLen = 6
				}
				if kwLen > 0 && i+kwLen < len(s) && (s[i+kwLen] == ' ' || s[i+kwLen] == '\t' || s[i+kwLen] == '=' || s[i+kwLen] == ':') {
					valStart := i + kwLen + 1
					for valStart < len(s) && (s[valStart] == ' ' || s[valStart] == '\t') {
						valStart++
					}
					valEnd := valStart
					for valEnd < len(s) && s[valEnd] != ' ' && s[valEnd] != '\t' && s[valEnd] != '\r' && s[valEnd] != '\n' &&
						s[valEnd] != '"' && s[valEnd] != '\'' && s[valEnd] != ',' && s[valEnd] != ';' && s[valEnd] != ')' &&
						s[valEnd] != ']' && s[valEnd] != '}' && s[valEnd] != '\\' && s[valEnd] != '`' && s[valEnd] != '|' {
						if s[valEnd] == 0xc2 && valEnd+1 < len(s) && s[valEnd+1] == 0x85 {
							break
						}
						if s[valEnd] == 0xe2 && valEnd+2 < len(s) && s[valEnd+1] == 0x80 && (s[valEnd+2] == 0xa8 || s[valEnd+2] == 0xa9) {
							break
						}
						valEnd++
					}
					if looksLikeSecretTokenValue(s[valStart:valEnd]) {
						if out.Cap() == 0 {
							out.Grow(len(s))
						}
						out.WriteString(s[copiedUpTo:valStart])
						out.WriteString("[REDACTED]")
						copiedUpTo = valEnd
						i = valEnd
						continue
					}
				}
			}
		}
		i++
		if !hasAt && !hasPct {
			for i < bareSkipUntil {
				prev := s[i-1]
				cur := s[i]
				if ((prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9')) &&
					((cur >= 'a' && cur <= 'z') || (cur >= 'A' && cur <= 'Z') || (cur >= '0' && cur <= '9')) {
					i++
					continue
				}
				break
			}
		}
	}
	if copiedUpTo == 0 {
		return s
	}
	out.WriteString(s[copiedUpTo:])
	return out.String()
}
