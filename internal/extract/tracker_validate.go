package extract

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

const (
	MinEasyPrivacyListBytes      = 200 * 1024
	MaxEasyPrivacyListBytes      = 10 * 1024 * 1024
	MinEasyPrivacyHostCount      = 5_000
	MaxEasyPrivacyHostCount      = 200_000
	MaxEasyPrivacyHostDeltaRatio = 0.2
)

var (
	reEasyPrivacyTitleHeader   = newLazyRegexp(`(?i)^!\s*Title\s*:\s*EasyPrivacy(?:\b|$)`)
	reEasyPrivacyVersionHeader = newLazyRegexp(`(?i)^!\s*Version\s*:`)
	reEasyPrivacyLastModHeader = newLazyRegexp(`(?i)^!\s*Last\s+modified\s*:`)
	reEasyPrivacyVersionVal    = newLazyRegexp(`^[A-Za-z0-9._-]{1,64}$`)

	easyPrivacyNeverBlockSuffixes = map[string]bool{
		// Bot-challenge & WAF hosts
		"challenges.cloudflare.com": true,
		"datadome.co":               true,
		"captcha-delivery.com":      true,
		"perimeterx.net":            true,
		"px-cdn.net":                true,
		"px-cloud.net":              true,
		"pxchk.net":                 true,
		"humansecurity.com":         true,
		"hsprotect.net":             true,
		"akamaihd.net":              true,
		"akamaized.net":             true,
		"akstat.io":                 true,
		"go-mpulse.net":             true,
		"arkoselabs.com":            true,
		"funcaptcha.com":            true,
		"recaptcha.net":             true,
		"google.com":                true,
		"gstatic.com":               true,
		"hcaptcha.com":              true,
		// Feature-flag / A-B SDKs
		"launchdarkly.com":  true,
		"optimizely.com":    true,
		"statsig.com":       true,
		"statsigapi.net":    true,
		"featureassets.org": true,
		"split.io":          true,
		"growthbook.io":     true,
	}
)

// ValidatedEasyPrivacyResult holds the result of ParseAndValidateEasyPrivacyGo.
type ValidatedEasyPrivacyResult struct {
	OK                 bool    `json:"ok"`
	Reason             string  `json:"reason,omitempty"`
	Version            string  `json:"version,omitempty"`
	HeaderLastModified *string `json:"headerLastModified"`
	RawParsedHostCount int     `json:"rawParsedHostCount,omitempty"`
	JoinedHosts        string  `json:"joinedHosts,omitempty"`
}

// NormalizeTrackerHostCandidate normalizes a candidate domain host per RFC 1123 (rejecting IPv4 literals and numeric-only TLDs).
func NormalizeTrackerHostCandidate(raw string) (string, bool) {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if clean == "" || len(clean) > 253 || strings.HasPrefix(clean, ".") || strings.HasSuffix(clean, ".") || !strings.Contains(clean, ".") {
		return "", false
	}
	labels := strings.Split(clean, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", false
			}
		}
	}
	tld := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", false
	}
	return clean, true
}

func trackerHostMatchesSuffixSet(host string, set map[string]bool) bool {
	if len(set) == 0 || host == "" {
		return false
	}
	for cur := host; ; {
		if set[cur] {
			return true
		}
		dot := strings.IndexByte(cur, '.')
		if dot < 0 {
			return false
		}
		cur = cur[dot+1:]
	}
}

// ParseAndValidateEasyPrivacyGo parses and validates an EasyPrivacy list in a single native Go pass.
func ParseAndValidateEasyPrivacyGo(rawText string, byteLength int, previousHostCount int, extraNeverBlockHosts []string) ValidatedEasyPrivacyResult {
	if byteLength < MinEasyPrivacyListBytes {
		return ValidatedEasyPrivacyResult{OK: false, Reason: fmt.Sprintf("list too small (%d < %d bytes)", byteLength, MinEasyPrivacyListBytes)}
	}
	if byteLength > MaxEasyPrivacyListBytes {
		return ValidatedEasyPrivacyResult{OK: false, Reason: fmt.Sprintf("list exceeds maximum size (%d > %d bytes)", byteLength, MaxEasyPrivacyListBytes)}
	}

	headEnd := min(512, len(rawText))
	headSample := strings.ToLower(strings.TrimLeft(rawText[:headEnd], " \t\r\n"))
	if strings.HasPrefix(headSample, "<!doctype") || strings.HasPrefix(headSample, "<html") || strings.HasPrefix(headSample, "<head") {
		return ValidatedEasyPrivacyResult{OK: false, Reason: "HTML document received instead of EasyPrivacy text list"}
	}

	extraAllowSet := make(map[string]bool, len(extraNeverBlockHosts))
	for _, h := range extraNeverBlockHosts {
		if clean, ok := NormalizeTrackerHostCandidate(h); ok {
			extraAllowSet[clean] = true
		}
	}

	sawEasyPrivacyTitle := false
	version := ""
	var headerLastModified *string
	nonEmptyHeaderLinesSeen := 0

	skippedAllowSet := make(map[string]struct{}, 64)
	survivingSet := make(map[string]struct{}, 48_000)

	totalLen := len(rawText)
	for lineStart := 0; lineStart <= totalLen; {
		nlRel := strings.IndexByte(rawText[lineStart:], '\n')
		lineEnd := totalLen
		if nlRel >= 0 {
			lineEnd = lineStart + nlRel
		}
		endTrim := lineEnd
		if endTrim > lineStart && rawText[endTrim-1] == '\r' {
			endTrim--
		}
		line := strings.TrimSpace(rawText[lineStart:endTrim])
		lineStart = lineEnd + 1

		if line != "" {
			if nonEmptyHeaderLinesSeen < 30 && (line[0] == '!' || line[0] == '[') {
				nonEmptyHeaderLinesSeen++
				if reEasyPrivacyTitleHeader.MatchString(line) {
					if colon := strings.IndexByte(line, ':'); colon >= 0 {
						titleVal := strings.TrimSpace(line[colon+1:])
						if titleVal == "EasyPrivacy" || strings.HasPrefix(titleVal, "EasyPrivacy ") {
							sawEasyPrivacyTitle = true
						}
					}
				} else if version == "" && reEasyPrivacyVersionHeader.MatchString(line) {
					if colon := strings.IndexByte(line, ':'); colon >= 0 {
						verVal := strings.TrimSpace(line[colon+1:])
						if reEasyPrivacyVersionVal.MatchString(verVal) {
							version = verVal
						}
					}
				} else if headerLastModified == nil && reEasyPrivacyLastModHeader.MatchString(line) {
					if colon := strings.IndexByte(line, ':'); colon >= 0 {
						lmVal := strings.TrimSpace(line[colon+1:])
						if lmVal != "" && len(lmVal) <= 128 {
							lmCopy := lmVal
							headerLastModified = &lmCopy
						}
					}
				}
			} else if len(line) >= 6 && line[0] == '|' && line[1] == '|' && line[len(line)-1] == '^' {
				rawBody := strings.ToLower(line[2 : len(line)-1])
				pureChars := true
				for i := 0; i < len(rawBody); i++ {
					c := rawBody[i]
					if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
						pureChars = false
						break
					}
				}
				if pureChars {
					if host, ok := NormalizeTrackerHostCandidate(rawBody); ok && !IsPublicOrPrivateSuffix(host) {
						if trackerHostMatchesSuffixSet(host, easyPrivacyNeverBlockSuffixes) || trackerHostMatchesSuffixSet(host, extraAllowSet) {
							skippedAllowSet[host] = struct{}{}
						} else {
							survivingSet[host] = struct{}{}
						}
					}
				}
			}
		}
		if nlRel < 0 {
			break
		}
	}

	if !sawEasyPrivacyTitle {
		return ValidatedEasyPrivacyResult{OK: false, Reason: `missing required "! Title: EasyPrivacy" header`}
	}
	if version == "" {
		return ValidatedEasyPrivacyResult{OK: false, Reason: `missing required "! Version:" header`}
	}

	survivingCount := len(survivingSet)
	rawParsedHostCount := survivingCount + len(skippedAllowSet)
	if rawParsedHostCount < MinEasyPrivacyHostCount || survivingCount < MinEasyPrivacyHostCount {
		return ValidatedEasyPrivacyResult{
			OK:     false,
			Reason: fmt.Sprintf("parsed host count (%d) below minimum (%d)", survivingCount, MinEasyPrivacyHostCount),
		}
	}
	if rawParsedHostCount > MaxEasyPrivacyHostCount || survivingCount > MaxEasyPrivacyHostCount {
		return ValidatedEasyPrivacyResult{
			OK:     false,
			Reason: fmt.Sprintf("parsed host count (%d) exceeds maximum (%d)", survivingCount, MaxEasyPrivacyHostCount),
		}
	}

	if previousHostCount > 0 {
		deltaRatio := math.Abs(float64(survivingCount-previousHostCount)) / float64(previousHostCount)
		if deltaRatio > MaxEasyPrivacyHostDeltaRatio {
			return ValidatedEasyPrivacyResult{
				OK:     false,
				Reason: fmt.Sprintf("parsed host count (%d) differs from previous good list (%d) by %.1f%% (> 20%%)", survivingCount, previousHostCount, deltaRatio*100),
			}
		}
	}

	hosts := make([]string, 0, survivingCount)
	for h := range survivingSet {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	return ValidatedEasyPrivacyResult{
		OK:                 true,
		Version:            version,
		HeaderLastModified: headerLastModified,
		RawParsedHostCount: rawParsedHostCount,
		JoinedHosts:        strings.Join(hosts, "\n"),
	}
}
