package jobs

import (
	"fmt"
	"math"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

func mergeHigherAtomicAmount(existing, incoming string, hasIncoming bool) string {
	if !hasIncoming {
		return existing
	}
	if existing == "" {
		return incoming
	}
	if compareCanonicalDigits(incoming, existing) > 0 {
		return incoming
	}
	return existing
}

// ParseX402PaymentTerms parses HTTP 402 Payment Required headers and JSON bodies into strictly sanitized X402ParseResult.
func ParseX402PaymentTerms(status int, headers map[string]string, rawBody, expectedHost string) *X402ParseResult {
	if status != 402 {
		return nil
	}

	var terms X402PaymentTerms
	var rawCandidatePrice any
	hasCandidatePrice := false
	sawDeceptiveCurrency := false
	sawRawAssetField := false

	payHdr := readPaymentHeader(headers, "payment-required")
	if payHdr == "" {
		payHdr = readPaymentHeader(headers, "x-payment-required")
	}
	wwwAuth := readPaymentHeader(headers, "www-authenticate")

	pickBestAcceptEntry := func(accepts []any) map[string]any {
		var bestObj map[string]any
		bestAmt := ""
		hasBestAmt := false
		limit := min(len(accepts), 32)
		for i := 0; i < limit; i++ {
			obj, ok := accepts[i].(map[string]any)
			if !ok || obj == nil {
				continue
			}
			if bestObj == nil {
				bestObj = obj
			}
			var mAmt, aAmt string
			var okM, okA bool
			if hasOwnPropMap(obj, "maxAmountRequired") {
				mAmt, okM = normalizeX402AtomicAmount(obj["maxAmountRequired"])
			}
			if hasOwnPropMap(obj, "amount") {
				aAmt, okA = normalizeX402AtomicAmount(obj["amount"])
			}
			topAmt, hasTop := "", false
			if okM && okA {
				hasTop = true
				if compareCanonicalDigits(mAmt, aAmt) >= 0 {
					topAmt = mAmt
				} else {
					topAmt = aAmt
				}
			} else if okM {
				topAmt, hasTop = mAmt, true
			} else if okA {
				topAmt, hasTop = aAmt, true
			}
			if hasTop && (!hasBestAmt || compareCanonicalDigits(topAmt, bestAmt) > 0) {
				bestAmt = topAmt
				hasBestAmt = true
				bestObj = obj
			}
		}
		return bestObj
	}

	applyRequirementObj := func(root map[string]any) {
		if hasOwnPropMap(root, "x402Version") {
			if vf, ok := root["x402Version"].(float64); ok && math.Trunc(vf) == vf && vf >= 1 && vf <= 10 {
				terms.X402Version = intPtr(int(vf))
			}
		}
		var accepts []any
		if hasOwnPropMap(root, "accepts") {
			accepts, _ = root["accepts"].([]any)
		}
		var chosenAccept map[string]any
		if len(accepts) > 0 {
			chosenAccept = pickBestAcceptEntry(accepts)
		}
		if len(accepts) > 1 {
			terms.AcceptsCount = intPtr(min(len(accepts), 32))
		}
		primary := root
		if chosenAccept != nil {
			primary = chosenAccept
		}

		readOwn := func(k string) any {
			if hasOwnPropMap(primary, k) && primary[k] != nil {
				return primary[k]
			}
			if chosenAccept != nil && hasOwnPropMap(root, k) && root[k] != nil {
				return root[k]
			}
			return nil
		}

		scheme := sanitizeX402Identifier(readOwn("scheme"), reX402IdentScheme, 32)
		rawAssetVal := readOwn("asset")
		if rawAssetVal != nil && strings.TrimSpace(fmt.Sprint(rawAssetVal)) != "" {
			sawRawAssetField = true
		}
		assetRaw := sanitizeX402String(rawAssetVal, 128)
		currency := sanitizeX402String(readOwn("currency"), 64)
		network := sanitizeX402Identifier(readOwn("network"), reX402IdentNetwork, 48)
		payToCand := readOwn("payTo")
		if payToCand == nil {
			payToCand = readOwn("recipient")
		}
		payTo := sanitizeX402Identifier(payToCand, reX402IdentPayTo, 128)
		resource := sanitizeX402HTTPSResource(readOwn("resource"), expectedHost)
		rawDescVal := readOwn("description")
		if _, ok := rawDescVal.(string); ok {
			if reDeceptive402Token.MatchString(sanitizeX402String(rawDescVal, 512)) {
				sawDeceptiveCurrency = true
			}
		}
		description := sanitizeX402PlainField(rawDescVal, 140, false)
		amount, okAmt := normalizeX402AtomicAmount(readOwn("amount"))
		maxAmt, okMax := normalizeX402AtomicAmount(readOwn("maxAmountRequired"))
		if candPrice := readOwn("price"); candPrice != nil {
			rawCandidatePrice = candPrice
			hasCandidatePrice = true
		}

		if scheme != "" {
			terms.Scheme = scheme
		}
		terms.Amount = mergeHigherAtomicAmount(terms.Amount, amount, okAmt)
		terms.MaxAmountRequired = mergeHigherAtomicAmount(terms.MaxAmountRequired, maxAmt, okMax)

		effectiveNet := terms.Network
		if network != "" {
			effectiveNet = network
			terms.Network = network
		}
		if assetRaw != "" {
			if reDeceptive402Token.MatchString(assetRaw) {
				sawDeceptiveCurrency = true
			} else if isKnownUSDCAsset(assetRaw, effectiveNet) {
				terms.Asset = "USDC"
			} else if isSafeX402AssetLabel(assetRaw) {
				terms.Asset = assetRaw
			} else {
				sawDeceptiveCurrency = true
			}
		}
		if currency != "" {
			if reDeceptive402Token.MatchString(currency) {
				sawDeceptiveCurrency = true
			} else if isSafeX402AssetLabel(currency) {
				terms.Currency = currency
			} else {
				sawDeceptiveCurrency = true
			}
		}
		if payTo != "" {
			terms.PayTo = payTo
		}
		if resource != "" {
			terms.Resource = resource
		}
		if description != "" {
			if reDeceptive402Token.MatchString(description) {
				sawDeceptiveCurrency = true
			} else {
				terms.Description = description
			}
		}

		if hasOwnPropMap(primary, "extra") {
			if eo, ok := primary["extra"].(map[string]any); ok && eo != nil {
				var safeExtra X402ExtraMetadata
				hasExtra := false
				if hasOwnPropMap(eo, "name") {
					if extraName := sanitizeX402PlainField(eo["name"], 80, false); extraName != "" && !reDeceptive402Token.MatchString(extraName) {
						safeExtra.Name = extraName
						hasExtra = true
					}
				}
				if hasOwnPropMap(eo, "version") {
					if extraVer := sanitizeX402Identifier(eo["version"], reX402IdentScheme, 32); extraVer != "" {
						safeExtra.Version = extraVer
						hasExtra = true
					}
				}
				curCand := currency
				if curCand == "" {
					curCand = terms.Currency
				}
				effectiveIsUSDC := isKnownUSDCAsset(assetRaw, effectiveNet) ||
					(!sawRawAssetField && isKnownUSDCAsset(curCand, effectiveNet))
				if hasOwnPropMap(eo, "decimals") {
					if decNum, isNum := eo["decimals"].(float64); isNum {
						if effectiveIsUSDC {
							safeExtra.Decimals = intPtr(6)
							hasExtra = true
						} else if decNum == 0 {
							safeExtra.Decimals = intPtr(0)
							hasExtra = true
						}
					}
				}
				if hasExtra {
					terms.Extra = &safeExtra
				}
			}
		}
	}

	if payHdr != "" {
		if hdrObj := tryDecodePaymentHeaderJSON(payHdr); hdrObj != nil {
			applyRequirementObj(hdrObj)
		}
	}
	if rawBody != "" && len(rawBody) <= 65_536 && strings.HasPrefix(strings.TrimSpace(rawBody), "{") {
		if bodyObj, ok := SafeJSONParse(rawBody).(map[string]any); ok && bodyObj != nil {
			applyRequirementObj(bodyObj)
		}
	}
	if wwwAuth != "" {
		authScheme, authPairs := parseWWWAuthenticateLinear(wwwAuth)
		if authScheme != "" && terms.Scheme == "" {
			if sc := sanitizeX402Identifier(authScheme, reX402IdentScheme, 32); sc != "" {
				terms.Scheme = sc
			}
		}
		for _, kv := range authPairs {
			k, rawV := kv[0], kv[1]
			switch k {
			case "price":
				if !hasCandidatePrice {
					rawCandidatePrice = rawV
					hasCandidatePrice = true
				}
			case "amount":
				a, ok := normalizeX402AtomicAmount(rawV)
				terms.Amount = mergeHigherAtomicAmount(terms.Amount, a, ok)
			case "maxamountrequired":
				m, ok := normalizeX402AtomicAmount(rawV)
				terms.MaxAmountRequired = mergeHigherAtomicAmount(terms.MaxAmountRequired, m, ok)
			case "asset":
				if terms.Asset == "" {
					sawRawAssetField = true
					if as := sanitizeX402String(rawV, 128); as != "" {
						if reDeceptive402Token.MatchString(as) {
							sawDeceptiveCurrency = true
						} else if isKnownUSDCAsset(as, terms.Network) {
							terms.Asset = "USDC"
						} else if isSafeX402AssetLabel(as) {
							terms.Asset = as
						} else {
							sawDeceptiveCurrency = true
						}
					}
				}
			case "currency":
				if terms.Currency == "" {
					if cu := sanitizeX402String(rawV, 64); cu != "" {
						if reDeceptive402Token.MatchString(cu) {
							sawDeceptiveCurrency = true
						} else if isSafeX402CurrencyLabel(cu) {
							terms.Currency = cu
						} else {
							sawDeceptiveCurrency = true
						}
					}
				}
			case "network":
				if terms.Network == "" {
					if nw := sanitizeX402Identifier(rawV, reX402IdentNetwork, 48); nw != "" {
						terms.Network = nw
					}
				}
			case "payto", "recipient":
				if terms.PayTo == "" {
					if pt := sanitizeX402Identifier(rawV, reX402IdentPayTo, 128); pt != "" {
						terms.PayTo = pt
					}
				}
			case "resource":
				if terms.Resource == "" {
					if rs := sanitizeX402HTTPSResource(rawV, expectedHost); rs != "" {
						terms.Resource = rs
					}
				}
			case "description":
				if terms.Description == "" {
					if reDeceptive402Token.MatchString(sanitizeX402String(rawV, 512)) {
						sawDeceptiveCurrency = true
					}
					if ds := sanitizeX402PlainField(rawV, 140, false); ds != "" {
						if reDeceptive402Token.MatchString(ds) {
							sawDeceptiveCurrency = true
						} else {
							terms.Description = ds
						}
					}
				}
			case "invoice":
				if inv := sanitizeX402Identifier(rawV, reX402IdentInvoice, 512); inv != "" {
					terms.Invoice = inv
				}
			case "macaroon":
				if !strings.Contains(rawV, "://") {
					if mac := sanitizeX402Identifier(rawV, reX402IdentMacaroon, 512); mac != "" {
						terms.Macaroon = mac
					}
				}
			}
		}
	}

	fbCur := terms.Currency
	if fbCur == "" {
		fbCur = terms.Asset
	}
	validStandalone := ""
	if hasCandidatePrice {
		rawCandStr, isStr := rawCandidatePrice.(string)
		trimmedCand := strings.TrimSpace(rawCandStr)
		if !(sawDeceptiveCurrency && isStr && !strings.HasPrefix(trimmedCand, "$") && !reX402PriceTailCur.MatchString(trimmedCand)) {
			validStandalone = validateX402StandalonePrice(rawCandidatePrice, fbCur)
		}
	}
	if validStandalone != "" {
		terms.Price = validStandalone
	}

	formattedPrice := formatX402PriceString(terms, sawDeceptiveCurrency, sawRawAssetField)
	terms.Price = formattedPrice

	return &X402ParseResult{
		Price: formattedPrice,
		Terms: terms,
	}
}

// BuildBlockedInfo builds an ethical blocked diagnostic & alternative suggestion without ever bypassing blocks or paying automatically.
func BuildBlockedInfo(urlStr, outcome, problem string, status int, headers map[string]string, rawBody string) *BlockedSuggestion {
	outStr := strings.ToLower(outcome)
	probStr := problem

	host := ""
	pathname := ""
	if u, ok := parseStrictURL(urlStr); ok {
		host = strings.ToLower(u.Hostname())
		pathname = u.EscapedPath()
		if pathname == "" {
			pathname = "/"
		}
	}

	// G3: HTTP 402 Payment Required / x402
	if status == 402 || outStr == "payment_required" {
		parsedPayment := ParseX402PaymentTerms(402, headers, rawBody, host)
		price := ""
		var termsPtr *X402PaymentTerms
		if parsedPayment != nil {
			price = parsedPayment.Price
			if !parsedPayment.Terms.IsEmpty() {
				tCopy := parsedPayment.Terms
				termsPtr = &tCopy
			}
		}
		originLabel := host
		if originLabel == "" {
			originLabel = "This origin"
		}
		suggestion := fmt.Sprintf("%s returned HTTP 402 Payment Required. EdgeFetch never pays automatically; inform the user or select a free public source.", originLabel)
		if price != "" {
			suggestion = fmt.Sprintf("%s requires payment (%s) via HTTP 402 / x402 for this resource. EdgeFetch never pays automatically; surface the price to the user or select a free public source.", originLabel, price)
		}
		return &BlockedSuggestion{
			Reason:     "payment_required",
			Host:       host,
			Price:      price,
			Terms:      termsPtr,
			Suggestion: suggestion,
		}
	}

	// G2: Cloudflare Content Signals (`Content-Signal: ai-input=no`)
	if outStr == "content_signal_disallowed" || reContentSignalProb.MatchString(probStr) {
		hostLabel := host
		if hostLabel == "" {
			hostLabel = "This host"
		}
		return &BlockedSuggestion{
			Reason:     "content-signal",
			Host:       host,
			Signal:     "ai-input=no",
			Suggestion: fmt.Sprintf("%s declares `Content-Signal: ai-input=no` in robots.txt, opting out of agent input retrieval. Respect the publisher's preference and use an official API or opted-in source instead.", hostLabel),
		}
	}

	if outStr == "dns_not_found" || reDNSNotFoundProb.MatchString(probStr) {
		return nil
	}

	isRobots := reRobotsProb.MatchString(probStr) || outStr == "robots_disallowed"
	isChallenge := outStr == "challenge" ||
		reChallengeProb.MatchString(probStr) ||
		(status == 403 && reChallenge403Prob.MatchString(probStr))

	if !isRobots && !isChallenge {
		return nil
	}

	reason := "challenge"
	if isRobots {
		reason = "robots"
	}

	if reason == "robots" && extract.IsWikimediaHost(host) {
		return &BlockedSuggestion{
			Reason:     "robots",
			Host:       host,
			Suggestion: extract.BuildWikimediaRobotsSuggestion(host),
		}
	}

	if strings.Contains(host, "api.smartrecruiters.com") {
		return &BlockedSuggestion{
			Reason:     reason,
			Host:       host,
			Suggestion: "api.smartrecruiters.com disallows automated access in robots.txt. Scrape the public HTML posting on `https://jobs.smartrecruiters.com/{Company}/{JobId}` instead (it embeds structured schema.org JobPosting metadata).",
		}
	}

	if reBlockedJobBoards.MatchString(host) {
		via := "requests with an anti-bot challenge"
		if reason == "robots" {
			via = "crawlers via robots.txt"
		}
		return &BlockedSuggestion{
			Reason: reason,
			Host:   host,
			Suggestion: fmt.Sprintf("%s blocks automated %s. ", host, via) +
				"Run `jobs` or `search` with `site:job-boards.greenhouse.io OR site:jobs.ashbyhq.com OR site:jobs.lever.co OR site:myworkdayjobs.com \"<company> <role>\"` (or `builtin.com`) to read the employer's official posting directly.",
		}
	}

	if host == "pypi.org" && rePyPIJSONPath.MatchString(pathname) {
		return &BlockedSuggestion{
			Reason:     reason,
			Host:       host,
			Suggestion: "pypi.org disallows /pypi/*/json in robots.txt; scrape https://pypi.org/project/<package>/ instead.",
		}
	}

	if host == "openstreetmap.org" || strings.HasSuffix(host, ".openstreetmap.org") {
		return &BlockedSuggestion{
			Reason:     reason,
			Host:       host,
			Suggestion: "openstreetmap.org disallows /node/, /way/, /relation/, and /api/ in robots.txt to protect community servers. Query Nominatim, the Overpass API, or bulk Planet.osm extracts instead.",
		}
	}

	if host == "npr.org" || strings.HasSuffix(host, ".npr.org") {
		via := "bot protection"
		if reason == "robots" {
			via = "robots.txt"
		}
		return &BlockedSuggestion{
			Reason:     reason,
			Host:       host,
			Suggestion: fmt.Sprintf("%s blocks automated HTML scraping via %s. Fetch NPR's official public RSS feeds instead: `https://feeds.npr.org/1001/rss.xml` (News), `https://feeds.npr.org/1003/rss.xml` (US), or `https://feeds.npr.org/1004/rss.xml` (World).", host, via),
		}
	}

	if host == "bbc.com" || strings.HasSuffix(host, ".bbc.com") || host == "bbc.co.uk" || strings.HasSuffix(host, ".bbc.co.uk") {
		via := "bot protection"
		if reason == "robots" {
			via = "robots.txt"
		}
		return &BlockedSuggestion{
			Reason:     reason,
			Host:       host,
			Suggestion: fmt.Sprintf("%s restricts automated HTML scraping via %s. Fetch BBC News's official public RSS feed instead: `https://feeds.bbci.co.uk/news/rss.xml` (or `https://feeds.bbci.co.uk/news/world/rss.xml`).", host, via),
		}
	}

	if host == "apnews.com" || strings.HasSuffix(host, ".apnews.com") || host == "reuters.com" || strings.HasSuffix(host, ".reuters.com") {
		via := "anti-bot challenge"
		if reason == "robots" {
			via = "robots.txt"
		}
		return &BlockedSuggestion{
			Reason:     reason,
			Host:       host,
			Suggestion: fmt.Sprintf("%s blocks automated HTML scraping via %s. Call `search` with `topic: \"news\"` or scrape official broadcaster RSS feeds (`https://www.cbsnews.com/latest/rss/main`, `https://feeds.nbcnews.com/nbcnews/public/news`, `https://feeds.npr.org/1001/rss.xml`, `https://feeds.bbci.co.uk/news/rss.xml`).", host, via),
		}
	}

	hostLabel := host
	if hostLabel == "" {
		hostLabel = "This host"
	}
	if reason == "robots" {
		return &BlockedSuggestion{
			Reason:     reason,
			Host:       host,
			Suggestion: fmt.Sprintf("%s disallows this path in robots.txt. Use `search` for official documentation, public API endpoints, or search snippets instead.", hostLabel),
		}
	}
	return &BlockedSuggestion{
		Reason:     reason,
		Host:       host,
		Suggestion: fmt.Sprintf("%s returned an anti-bot challenge. Do not retry this URL; use `search` to find an official mirror, package registry, or primary source.", hostLabel),
	}
}
