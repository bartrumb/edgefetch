package jobs

import (
	"encoding/base64"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	reRedirectFilterPath  = regexp.MustCompile(`(?i)/(?:role|roles|search|category|department|team|location|tag|filter|q)\b`)
	reRedirectGenericPath = regexp.MustCompile(`(?i)^/(?:jobs?|careers?|remote|openings?)?$`)

	reBase64HeaderCand     = regexp.MustCompile(`^[A-Za-z0-9+/_=-]{8,}$`)
	reTestnetNetwork       = regexp.MustCompile(`(?i)(?:sepolia|goerli|holesky|testnet|devnet|mumbai|amoy|fuji)`)
	reDeceptive402Token    = regexp.MustCompile(`(?i)(?:\b(?:gratis|free|trial|complimentary|paid|prepaid|waived|comped|zero|refunded|settled|included|authorized|authorised|allowed|bypass|exempt|sponsored|covered|ok|go|yes)\b|free|gratis|complimentary|ok2fetch|oktofetch|freetrial|nocost|nofee|nocharge|prepaid|already[-_.: ]*paid|fr33|f2ee)`)
	reX402InjectionProse   = regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override|system[ \t]+prompt|assistant[ \t]*:|pre-?authori[sz]ed|already[ \t]+settled|fetch_url|bearer[ \t]+token|rm[ \t]+-rf|instructions?)\b`)
	reZeroValue402Price    = regexp.MustCompile(`^[$€£]?\s*0+(?:\.0+)?(?:\b|\s|$)`)
	reANSICSIorOSCX402     = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?`)
	reX402DisallowedURLInl = regexp.MustCompile(`(?i)\b(?:https?|ftp|javascript|vbscript|data|file|blob):[^\s)]*`)
	reX402SchemePrefix     = regexp.MustCompile(`(?i)^(?:https?|ftp|javascript|vbscript|data|file|blob):`)
	reX402IdentScheme      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	reX402IdentNetwork     = regexp.MustCompile(`^[A-Za-z0-9:._-]{1,48}$`)
	reX402IdentPayTo       = regexp.MustCompile(`^[A-Za-z0-9:._@-]{1,128}$`)
	reX402IdentInvoice     = regexp.MustCompile(`^[A-Za-z0-9+/=_.:-]{1,512}$`)
	reX402IdentMacaroon    = regexp.MustCompile(`^[A-Za-z0-9+/=_."':-]{1,512}$`)
	reX402HexContract      = regexp.MustCompile(`^0x[A-Za-z0-9]{4,64}$`)
	reX402SolanaMint       = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)
	reX402StandalonePrice  = regexp.MustCompile(`^\$?\d{1,12}(?:\.\d{1,8})?(?: [A-Z0-9]{2,10})?$`)
	reX402PriceNumPart     = regexp.MustCompile(`^\$?(\d{1,12}(?:\.\d{1,8})?)`)
	reX402PriceTailCur     = regexp.MustCompile(` [A-Z0-9]{2,10}$`)
	reX402CurCode          = regexp.MustCompile(`^[A-Z0-9]{2,10}$`)
	reX402Digits1to30      = regexp.MustCompile(`^\d{1,30}$`)
	reX402AuthScheme       = regexp.MustCompile(`(?i)^(?:x402|l402|lsat)$`)

	reContentSignalProb = regexp.MustCompile(`(?i)content-signal|ai-input\s*=\s*no`)
	reDNSNotFoundProb   = regexp.MustCompile(`(?i)\b(?:enotfound|nxdomain|dns_not_found|eai_noname)\b|no such host|name or service not known|nodename nor servname provided|domain does not exist`)
	reRobotsProb        = regexp.MustCompile(`(?i)robots\.txt`)
	reChallengeProb     = regexp.MustCompile(`(?i)challenge|cf-mitigated|turnstile|captcha|verify you are human`)
	reChallenge403Prob  = regexp.MustCompile(`(?i)cloudflare|bot|forbidden`)
	reBlockedJobBoards  = regexp.MustCompile(`(?i)(?:^|\.)(?:linkedin\.com|indeed\.com|dice\.com|icims\.com|startup\.jobs|glassdoor\.com|ziprecruiter\.com)$`)
	rePyPIJSONPath      = regexp.MustCompile(`(?i)/json/?$`)

	knownMainnetUSDCContracts = map[string][]string{
		"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913":   {"base", "base-mainnet", "eip155:8453"},
		"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48":   {"ethereum", "eth", "mainnet", "eip155:1"},
		"0x3c499c542cef5e3811e1192ce70d8cc03d5c3359":   {"polygon", "matic", "eip155:137"},
		"0x2791bca1f2de4661ed88a30c99a7a9449aa84174":   {"polygon", "matic", "eip155:137"},
		"0xaf88d065e77c8cc2239327c5edb3a432268e5831":   {"arbitrum", "arbitrum-one", "eip155:42161"},
		"0xff970a61a04b1ca14834a43f5de4533ebddb5cc8":   {"arbitrum", "arbitrum-one", "eip155:42161"},
		"0x0b2c639c533813f4aa9d7837caf62653d097ff85":   {"optimism", "op-mainnet", "eip155:10"},
		"0x7f5c764cbc14f9669b88837ca1490cca17c31607":   {"optimism", "op-mainnet", "eip155:10"},
		"0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e":   {"avalanche", "avax", "eip155:43114"},
		"epjfwdd5aufqssqem2qn1xzybapc8g4weggkzwytdt1v": {"solana", "solana-mainnet"},
	}

	knownMainnetUSDCNetworks = func() map[string]bool {
		m := make(map[string]bool)
		for _, nets := range knownMainnetUSDCContracts {
			for _, n := range nets {
				m[n] = true
			}
		}
		return m
	}()

	allowedX402OnchainAssets = map[string]bool{
		"USDC": true, "USDC.e": true, "USDT": true, "DAI": true, "PYUSD": true,
		"EURC": true, "USDP": true, "FRAX": true, "LUSD": true, "WETH": true,
		"ETH": true, "WBTC": true, "BTC": true, "SAT": true, "SATS": true, "SOL": true,
	}

	allowedX402FiatCurrencies = map[string]bool{
		"USD": true, "EUR": true, "GBP": true, "CAD": true, "AUD": true,
		"JPY": true, "CHF": true, "NZD": true, "SGD": true, "HKD": true,
	}

	x402ForbiddenKeys = map[string]bool{
		"__proto__": true, "constructor": true, "prototype": true,
	}
)

// AnalyzeURLRedirect flags material URL redirects and warns when role/search/query filters may have been dropped.
func AnalyzeURLRedirect(requestedURL, finalURL string) RedirectAnalysis {
	if requestedURL == "" || finalURL == "" {
		return RedirectAnalysis{Redirected: false}
	}
	reqU, ok1 := parseStrictURL(requestedURL)
	finU, ok2 := parseStrictURL(finalURL)
	if !ok1 || !ok2 {
		return RedirectAnalysis{Redirected: false}
	}
	normHost := func(h string) string {
		low := strings.ToLower(h)
		low = strings.TrimPrefix(low, "www.")
		return strings.TrimRight(low, ".")
	}
	normPath := func(p string) string {
		if p == "" {
			return "/"
		}
		if len(p) > 1 {
			trimmed := strings.TrimRight(p, "/")
			if trimmed == "" {
				return "/"
			}
			return trimmed
		}
		return "/"
	}

	sameHost := normHost(reqU.Hostname()) == normHost(finU.Hostname())
	reqPath := normPath(reqU.EscapedPath())
	finPath := normPath(finU.EscapedPath())
	reqSearch := ""
	if reqU.RawQuery != "" {
		reqSearch = "?" + reqU.RawQuery
	}
	finSearch := ""
	if finU.RawQuery != "" {
		finSearch = "?" + finU.RawQuery
	}

	if sameHost && strings.EqualFold(reqPath, finPath) && reqSearch == finSearch {
		return RedirectAnalysis{Redirected: false}
	}

	reqDepth := countNonEmptySegments(reqPath)
	finDepth := countNonEmptySegments(finPath)
	reqHasQuery := len(reqU.Query()) > 0
	finHasQuery := len(finU.Query()) > 0

	hadFilterSignals := reqHasQuery || reRedirectFilterPath.MatchString(reqPath)
	collapsedToGeneric := finDepth < reqDepth ||
		(reqHasQuery && !finHasQuery) ||
		reRedirectGenericPath.MatchString(finPath)
	filtersMayBeLost := hadFilterSignals && collapsedToGeneric

	fromLabel := canonicalWhatwgURLString(reqU)
	toLabel := canonicalWhatwgURLString(finU)
	if sameHost {
		fromLabel = reqPath + reqSearch
		toLabel = finPath + finSearch
	}

	note := fmt.Sprintf("Redirected from %s to %s.", fromLabel, toLabel)
	if filtersMayBeLost {
		note = fmt.Sprintf("Redirected from %s to %s; role or search filters from the original URL may have been lost.", fromLabel, toLabel)
	}
	return RedirectAnalysis{
		Redirected:       true,
		RedirectNote:     note,
		FiltersMayBeLost: filtersMayBeLost,
	}
}

func canonicalWhatwgURLString(u *url.URL) string {
	copied := *u
	copied.Scheme = strings.ToLower(copied.Scheme)
	copied.Host = strings.ToLower(copied.Host)
	if copied.Path == "" && (copied.Scheme == "http" || copied.Scheme == "https") {
		copied.Path = "/"
	}
	return copied.String()
}

func countNonEmptySegments(p string) int {
	n := 0
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			n++
		}
	}
	return n
}

func readPaymentHeader(headers map[string]string, name string) string {
	if len(headers) == 0 {
		return ""
	}
	if v, ok := headers[name]; ok {
		return strings.TrimSpace(v)
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func tryDecodePaymentHeaderJSON(raw string) map[string]any {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 65_536 {
		return nil
	}
	if strings.HasPrefix(trimmed, "{") {
		if m, ok := SafeJSONParse(trimmed).(map[string]any); ok {
			return m
		}
	}
	if reBase64HeaderCand.MatchString(trimmed) {
		norm := strings.NewReplacer("-", "+", "_", "/").Replace(trimmed)
		if rem := len(norm) % 4; rem != 0 {
			norm += strings.Repeat("=", 4-rem)
		}
		if decodedBytes, err := base64.StdEncoding.DecodeString(norm); err == nil {
			decoded := strings.ToValidUTF8(string(decodedBytes), "\uFFFD")
			if m, ok := SafeJSONParse(decoded).(map[string]any); ok {
				return m
			}
		}
	}
	return nil
}

func hasOwnPropMap(obj map[string]any, key string) bool {
	if x402ForbiddenKeys[key] || obj == nil {
		return false
	}
	_, ok := obj[key]
	return ok
}

func sanitizeX402String(raw any, maxLen int) string {
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	cleaned := reANSICSIorOSCX402.ReplaceAllString(s, "")
	var sb strings.Builder
	sb.Grow(len(cleaned))
	prevSpace := false
	for _, r := range cleaned {
		// Strip zero-width, variation selectors, Hangul fillers, Unicode Tags, BiDi controls.
		if r == 0x00AD || r == 0x034F || r == 0x061C || r == 0x115F || r == 0x1160 || r == 0x180E ||
			(r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2060 && r <= 0x206F) ||
			r == 0x3164 || (r >= 0xFE00 && r <= 0xFE0F) || r == 0xFEFF || r == 0xFFA0 ||
			(r >= 0xE0000 && r <= 0xE01EF) {
			continue
		}
		// Normalize C0/C1 controls and Unicode spaces to ASCII ' '.
		if r <= 0x1F || (r >= 0x7F && r <= 0x9F) || r == 0x00A0 || r == 0x1680 ||
			(r >= 0x2000 && r <= 0x200A) || r == 0x2028 || r == 0x2029 || r == 0x202F ||
			r == 0x205F || r == 0x3000 || r == ' ' || r == '\t' {
			if !prevSpace && sb.Len() > 0 {
				sb.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		sb.WriteRune(r)
		prevSpace = false
	}
	res := strings.TrimSpace(sb.String())
	if res == "" {
		return ""
	}
	return sliceUTF16Max(res, maxLen)
}

func sanitizeX402PlainField(raw any, maxLen int, strictIdentifier bool) string {
	base := sanitizeX402String(raw, 2_048)
	if base == "" {
		return ""
	}
	var out strings.Builder
	out.Grow(len(base))
	i := 0
	for i < len(base) {
		ch := base[i]
		if ch == '<' {
			gt := strings.IndexByte(base[i+1:], '>')
			if gt >= 0 {
				i = i + 1 + gt + 1
			} else {
				i++
			}
			continue
		}
		if ch == '!' && i+1 < len(base) && base[i+1] == '[' {
			closeBr := strings.IndexByte(base[i+2:], ']')
			if closeBr >= 0 {
				closeBr += i + 2
				if closeBr+1 < len(base) && base[closeBr+1] == '(' {
					p := closeBr + 2
					depth := 1
					for p < len(base) && depth > 0 {
						pc := base[p]
						if pc == '\\' && p+1 < len(base) {
							p += 2
							continue
						}
						if pc == ' ' && depth == 1 {
							break
						}
						if pc == '(' {
							depth++
						} else if pc == ')' {
							depth--
						}
						p++
					}
					i = p
					continue
				}
			}
			i += 2
			continue
		}
		if ch == '[' {
			closeBr := strings.IndexByte(base[i+1:], ']')
			if closeBr >= 0 {
				closeBr += i + 1
				label := base[i+1 : closeBr]
				if closeBr+1 < len(base) && base[closeBr+1] == '(' {
					p := closeBr + 2
					depth := 1
					for p < len(base) && depth > 0 {
						pc := base[p]
						if pc == '\\' && p+1 < len(base) {
							p += 2
							continue
						}
						if pc == ' ' && depth == 1 {
							break
						}
						if pc == '(' {
							depth++
						} else if pc == ')' {
							depth--
						}
						p++
					}
					out.WriteString(label)
					i = p
					continue
				}
				if closeBr+1 < len(base) && base[closeBr+1] == '[' {
					refClose := strings.IndexByte(base[closeBr+2:], ']')
					if refClose >= 0 {
						out.WriteString(label)
						i = closeBr + 2 + refClose + 1
						continue
					}
				}
			}
			i++
			continue
		}
		if ch == ']' || ch == '>' || ch == '`' {
			i++
			continue
		}
		if strictIdentifier && (ch == '(' || ch == ')') {
			i++
			continue
		}
		_, w := utf8.DecodeRuneInString(base[i:])
		if w <= 0 {
			w = 1
		}
		out.WriteString(base[i : i+w])
		i += w
	}

	withoutURLs := reX402DisallowedURLInl.ReplaceAllString(out.String(), "")
	withoutURLs = strings.TrimSpace(reMultiSpacesJobs.ReplaceAllString(withoutURLs, " "))
	if withoutURLs == "" || reX402InjectionProse.MatchString(withoutURLs) {
		return ""
	}
	return strings.TrimSpace(sliceUTF16Max(withoutURLs, maxLen))
}

func sanitizeX402Identifier(raw any, re *regexp.Regexp, maxLen int) string {
	s := sanitizeX402String(raw, maxLen+8)
	if s == "" || len(s) > maxLen {
		return ""
	}
	if reX402SchemePrefix.MatchString(s) {
		return ""
	}
	if !re.MatchString(s) || reX402InjectionProse.MatchString(s) {
		return ""
	}
	return s
}

func isPrintableASCIINoSpace(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

func isSafeX402AssetLabel(rawLabel string) bool {
	if !isPrintableASCIINoSpace(rawLabel) {
		return false
	}
	if reDeceptive402Token.MatchString(rawLabel) || reX402InjectionProse.MatchString(rawLabel) {
		return false
	}
	if reX402HexContract.MatchString(rawLabel) || reX402SolanaMint.MatchString(rawLabel) {
		return true
	}
	if rawLabel == "USDC.e" {
		return true
	}
	return allowedX402OnchainAssets[strings.ToUpper(rawLabel)] && !strings.Contains(rawLabel, ".")
}

func isSafeX402CurrencyLabel(rawLabel string) bool {
	if isSafeX402AssetLabel(rawLabel) {
		return true
	}
	return allowedX402FiatCurrencies[strings.ToUpper(rawLabel)]
}

func isKnownUSDCAsset(assetRaw, network string) bool {
	trimmed := strings.TrimSpace(assetRaw)
	if !isPrintableASCIINoSpace(trimmed) {
		return false
	}
	if network != "" && reTestnetNetwork.MatchString(network) {
		return false
	}
	if strings.EqualFold(trimmed, "USDC") {
		return network == "" || knownMainnetUSDCNetworks[strings.ToLower(strings.TrimSpace(network))]
	}
	chains, ok := knownMainnetUSDCContracts[strings.ToLower(trimmed)]
	if !ok {
		return false
	}
	if network == "" {
		return true
	}
	normNet := strings.ToLower(strings.TrimSpace(network))
	for _, c := range chains {
		if c == normNet {
			return true
		}
	}
	return false
}

func sanitizeX402HTTPSResource(raw any, expectedHost string) string {
	s := sanitizeX402String(raw, 512)
	if s == "" || !strings.HasPrefix(strings.ToLower(s), "https://") || strings.ContainsAny(s, " \t\r\n<>[]`") || reX402InjectionProse.MatchString(s) {
		return ""
	}
	u, ok := parseStrictURL(s)
	if !ok || !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Hostname() == "" {
		return ""
	}
	if expectedHost != "" {
		expHost := expectedHost
		if eu, okEu := parseStrictURL(expectedHost); okEu && eu.Hostname() != "" {
			expHost = eu.Hostname()
		}
		if !strings.EqualFold(u.Hostname(), expHost) {
			return ""
		}
	}
	if strings.HasPrefix(s, "https://") {
		return s
	}
	return canonicalWhatwgURLString(u)
}

func canonicalUnsignedDigits(digits string) string {
	trimmed := strings.TrimLeft(digits, "0")
	if trimmed == "" {
		return "0"
	}
	return trimmed
}

func compareCanonicalDigits(a, b string) int {
	ca, cb := canonicalUnsignedDigits(a), canonicalUnsignedDigits(b)
	if len(ca) != len(cb) {
		if len(ca) > len(cb) {
			return 1
		}
		return -1
	}
	return strings.Compare(ca, cb)
}

func normalizeX402AtomicAmount(raw any) (string, bool) {
	switch v := raw.(type) {
	case float64:
		// JS Number.isSafeInteger(v) && v >= 0 (`0 .. 2^53 - 1`)
		const maxSafeInt = 9007199254740991.0
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > maxSafeInt || math.Trunc(v) != v {
			return "", false
		}
		return strconv.FormatInt(int64(v), 10), true
	case string:
		for _, r := range v {
			if r <= 0x1F || (r >= 0x7F && r <= 0x9F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
				return "", false
			}
		}
		s := strings.TrimSpace(v)
		if !reX402Digits1to30.MatchString(s) {
			return "", false
		}
		return canonicalUnsignedDigits(s), true
	default:
		return "", false
	}
}

func formatAtomicAmountDecimalString(atomicDigits string, decimals int) string {
	canonical := canonicalUnsignedDigits(atomicDigits)
	if decimals <= 0 {
		return canonical
	}
	padded := canonical
	if len(padded) < decimals+1 {
		padded = strings.Repeat("0", decimals+1-len(padded)) + padded
	}
	splitIdx := len(padded) - decimals
	whole := padded[:splitIdx]
	frac := strings.TrimRight(padded[splitIdx:], "0")
	if frac != "" {
		return whole + "." + frac
	}
	return whole
}

func hasX402StandalonePriceUnsafeRune(s string) bool {
	for _, r := range s {
		if r <= 0x1F || (r >= 0x7F && r <= 0x9F) || r == 0x00A0 || r == 0x1680 ||
			(r >= 0x2000 && r <= 0x200F) || (r >= 0x2028 && r <= 0x202F) ||
			(r >= 0x205F && r <= 0x206F) || r == 0x3000 || r == 0xFEFF {
			return true
		}
	}
	return false
}

func validateX402StandalonePrice(raw any, fallbackCurrency string) string {
	var s string
	switch v := raw.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v > 999_999_999_999 {
			return ""
		}
		formatted := strconv.FormatFloat(v, 'f', -1, 64)
		if strings.ContainsAny(formatted, "eE") {
			return ""
		}
		s = formatted
	case string:
		if hasX402StandalonePriceUnsafeRune(v) ||
			reDeceptive402Token.MatchString(v) ||
			reX402InjectionProse.MatchString(v) ||
			reZeroValue402Price.MatchString(strings.TrimSpace(v)) {
			return ""
		}
		s = strings.Join(strings.Fields(strings.TrimSpace(v)), " ")
	default:
		return ""
	}
	if !reX402StandalonePrice.MatchString(s) || reDeceptive402Token.MatchString(s) || reZeroValue402Price.MatchString(s) {
		return ""
	}
	numMatch := reX402PriceNumPart.FindStringSubmatch(s)
	if len(numMatch) < 2 {
		return ""
	}
	numVal, err := strconv.ParseFloat(numMatch[1], 64)
	if err != nil || !(numVal > 0) {
		return ""
	}
	if strings.HasPrefix(s, "$") || reX402PriceTailCur.MatchString(s) {
		return s
	}
	if fallbackCurrency != "" && (reDeceptive402Token.MatchString(fallbackCurrency) || !isSafeX402AssetLabel(fallbackCurrency)) {
		return ""
	}
	curRaw := strings.ToUpper(strings.TrimSpace(fallbackCurrency))
	if curRaw == "" {
		curRaw = "USD"
	}
	cur := "USD"
	if reX402CurCode.MatchString(curRaw) && !reDeceptive402Token.MatchString(curRaw) {
		cur = curRaw
	}
	if cur == "USD" {
		return "$" + s
	}
	return "$" + s + " " + cur
}

func formatX402PriceString(terms X402PaymentTerms, sawDeceptiveCurrency, rawUntrustedAssetPresent bool) string {
	assetRaw := strings.TrimSpace(terms.Asset)
	currencyRaw := strings.TrimSpace(terms.Currency)
	networkRaw := strings.TrimSpace(terms.Network)

	isUSDC := isKnownUSDCAsset(assetRaw, networkRaw) ||
		(assetRaw == "" && !rawUntrustedAssetPresent && isKnownUSDCAsset(currencyRaw, networkRaw))

	rawLabel := assetRaw
	if isUSDC {
		rawLabel = "USDC"
	} else if rawLabel == "" && !rawUntrustedAssetPresent {
		rawLabel = currencyRaw
	}
	assetLabel := ""
	if isUSDC {
		assetLabel = "USDC"
	} else if isSafeX402AssetLabel(rawLabel) {
		assetLabel = rawLabel
	}

	normMax, hasMax := "", false
	if terms.MaxAmountRequired != "" {
		normMax, hasMax = normalizeX402AtomicAmount(terms.MaxAmountRequired)
	}
	normAmt, hasAmt := "", false
	if terms.Amount != "" {
		normAmt, hasAmt = normalizeX402AtomicAmount(terms.Amount)
	}

	maxPos := hasMax && normMax != "0"
	amtPos := hasAmt && normAmt != "0"
	validAmt, hasValidAmt := "", false
	switch {
	case maxPos && amtPos:
		hasValidAmt = true
		if compareCanonicalDigits(normMax, normAmt) >= 0 {
			validAmt = normMax
		} else {
			validAmt = normAmt
		}
	case maxPos:
		validAmt, hasValidAmt = normMax, true
	case amtPos:
		validAmt, hasValidAmt = normAmt, true
	case hasMax:
		validAmt, hasValidAmt = normMax, true
	case hasAmt:
		validAmt, hasValidAmt = normAmt, true
	}

	if hasValidAmt {
		if validAmt == "0" {
			return ""
		}
		if isUSDC {
			return "$" + formatAtomicAmountDecimalString(validAmt, 6) + " USDC"
		}
		if assetLabel != "" {
			return fmt.Sprintf("%s atomic units (%s)", validAmt, assetLabel)
		}
		return validAmt + " atomic units"
	}

	if sawDeceptiveCurrency {
		return ""
	}
	fb := currencyRaw
	if fb == "" {
		fb = assetLabel
	}
	return validateX402StandalonePrice(terms.Price, fb)
}

func isAuthTokenByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

func parseWWWAuthenticateLinear(rawWWWAuth string) (scheme string, pairs [][2]string) {
	s := rawWWWAuth
	if len(s) > 8_192 {
		s = s[:8_192]
	}
	n := len(s)
	i := 0
	for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
		i++
	}
	schemeStart := i
	for i < n && isAuthTokenByte(s[i]) {
		i++
	}
	if i > schemeStart {
		probe := i
		for probe < n && (s[probe] == ' ' || s[probe] == '\t') {
			probe++
		}
		if probe >= n || s[probe] != '=' {
			cand := s[schemeStart:i]
			if reX402AuthScheme.MatchString(cand) {
				if strings.EqualFold(cand, "lsat") {
					scheme = "L402"
				} else {
					scheme = cand
				}
			}
		} else {
			i = schemeStart
		}
	}

	for i < n {
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' || s[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		kStart := i
		for i < n && isAuthTokenByte(s[i]) {
			i++
		}
		if i == kStart {
			for i < n && s[i] != ' ' && s[i] != '\t' && s[i] != ',' {
				i++
			}
			continue
		}
		key := strings.ToLower(s[kStart:i])
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n || s[i] != '=' {
			continue
		}
		i++
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		var val string
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			i++
			var sb strings.Builder
			for i < n {
				ch := s[i]
				if ch == q {
					i++
					break
				}
				if ch == '\\' && q == '"' && i+1 < n {
					sb.WriteByte(s[i+1])
					i += 2
					continue
				}
				sb.WriteByte(ch)
				i++
			}
			val = sb.String()
		} else {
			vStart := i
			for i < n && s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n' && s[i] != ',' {
				i++
			}
			val = s[vStart:i]
		}
		if val != "" {
			pairs = append(pairs, [2]string{key, val})
		}
	}
	return scheme, pairs
}
