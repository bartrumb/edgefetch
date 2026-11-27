package extract

import (
	"net/url"
	"strconv"
	"strings"
)

var (
	reMicrodataProductTypeSliceGo  = newLazyRegexp(`(?i)^(?:https?://schema\.org/|schema:)?(?:Product|ProductGroup|IndividualProduct|ProductModel|SomeProducts)$`)
	reMicrodataBrandTypeSliceGo    = newLazyRegexp(`(?i)(?:^|\s)(?:https?://schema\.org/|schema:)?(?:Brand|Organization)(?:\s|$)`)
	reMicrodataOfferTypeSliceGo    = newLazyRegexp(`(?i)(?:^|\s)(?:https?://schema\.org/|schema:)?(?:Offer|AggregateOffer)(?:\s|$)`)
	reMicrodataRatingTypeSliceGo   = newLazyRegexp(`(?i)(?:^|\s)(?:https?://schema\.org/|schema:)?AggregateRating(?:\s|$)`)
	reMicrodataImageTypeSliceGo    = newLazyRegexp(`(?i)(?:^|\s)(?:https?://schema\.org/|schema:)?ImageObject(?:\s|$)`)
	reCurrencyCodeWordSliceGo      = newLazyRegexp(`(?i)\b(USD|EUR|GBP|CAD|AUD|CHF|JPY|CNY|SEK|NOK|DKK|PLN|NZD|INR)\b`)
	reParenSuffixSliceGo           = newLazyRegexp(`\s*\([^)]{1,40}\)\s*$`)
	reNonProductLdTypeSliceGo      = newLazyRegexp(`(?i)^(?:schema:)?(?:JobPosting|Article|NewsArticle|BlogPosting|TechArticle|ScholarlyArticle|QAPage|FAQPage|DiscussionForumPosting|HowTo|Recipe|Event|Person|Course|Dataset)$`)
	reSkipProductImageNameSliceGo  = newLazyRegexp(`(?i)(?:logo|icon|favicon|avatar|badge|spinner|placeholder|1x1|pixel|spacer)`)
	reAlnumDigitCodeSliceGo        = newLazyRegexp(`[0-9]`)
	reCurrencyPrefixedPriceHintGo  = newLazyRegexp(`(?i)(?:[$£€¥₹]\s*\d|\b(?:USD|EUR|GBP|CAD|AUD)\s+\d|\d+(?:[.,]\d{2})\s*[€£])`)
	reStrictCurrencySpanSliceGo    = newLazyRegexp(`^(?:(?:US|CA|AU)?[$£€¥₹]\s*\d[\d,]*(?:[.,]\d{1,2})?|(?:USD|EUR|GBP|CAD|AUD)\s+\d[\d,]*(?:[.,]\d{1,2})?|\d[\d,]*(?:[.,]\d{1,2})\s*(?:€|£|USD|EUR|GBP))$`)
)

// resolveStructuredProductURLSliceGo resolves a product URL candidate against finalURL while blocking
// unsafe schemes (`javascript:`, `data:`, `vbscript:`, `file:`, `mailto:`, etc.), backslashes, credentials,
// non-standard ports, and loopback/private/SSRF hostnames. Falls back to finalURL on invalid inputs.
func resolveStructuredProductURLSliceGo(rawURL, finalURL string) string {
	cleaned := strings.TrimSpace(StripInvisibleSchemaChars(rawURL))
	if cleaned == "" {
		return finalURL
	}
	if strings.HasPrefix(cleaned, `\`) || hasBackslashInAuthoritySchemaGo(cleaned) {
		return finalURL
	}
	// Check unsafe schemes (including HTML entity / whitespace obfuscated schemes) before url.Parse.
	// Protocol-relative `//` is handled explicitly below because IsDisallowedMarkdownLinkDestination rejects all `//`.
	if !strings.HasPrefix(cleaned, "//") && IsDisallowedMarkdownLinkDestination(cleaned) {
		return finalURL
	}

	var baseParsed *url.URL
	if strings.TrimSpace(finalURL) != "" {
		if bp, err := url.Parse(preEncodeWhitespaceForURLParseSchemaGo(strings.TrimSpace(finalURL))); err == nil {
			bpScheme := asciiLowerSliceGo(bp.Scheme)
			if (bpScheme == "https" || bpScheme == "http") && bp.Hostname() != "" {
				bp.Scheme = bpScheme
				baseParsed = bp
			}
		}
	}

	var resolved *url.URL
	if strings.HasPrefix(cleaned, "//") {
		if len(cleaned) <= 2 || cleaned[2] == '/' || cleaned[2] == '\\' {
			return finalURL
		}
		candidate := preEncodeWhitespaceForURLParseSchemaGo(cleaned)
		if baseParsed != nil {
			ref, err := url.Parse(candidate)
			if err != nil {
				return finalURL
			}
			resolved = baseParsed.ResolveReference(ref)
		} else {
			u, err := url.Parse("https:" + candidate)
			if err != nil {
				return finalURL
			}
			resolved = u
		}
	} else {
		preEncoded := preEncodeWhitespaceForURLParseSchemaGo(cleaned)
		ref, err := url.Parse(preEncoded)
		if err != nil {
			return finalURL
		}
		if ref.IsAbs() {
			resolved = ref
		} else if baseParsed != nil {
			resolved = baseParsed.ResolveReference(ref)
		} else {
			return finalURL
		}
	}

	if resolved == nil {
		return finalURL
	}
	scheme := asciiLowerSliceGo(resolved.Scheme)
	if scheme != "https" && scheme != "http" {
		return finalURL
	}
	resolved.Scheme = scheme
	if resolved.User != nil {
		return finalURL
	}
	port := resolved.Port()
	if port != "" && port != "80" && port != "443" {
		return finalURL
	}
	hostname := asciiLowerSliceGo(resolved.Hostname())
	if !isSafePublicHostnameSliceGo(hostname) {
		return finalURL
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") || port == "" {
		resolved.Host = hostname
	} else {
		resolved.Host = hostname + ":" + port
	}
	if resolved.Path == "" {
		resolved.Path = "/"
	}
	return PercentEncodeUnsafeRecordURLChars(resolved.String())
}

// parseNumericPriceSpanSliceGo parses standard (`$1,299.00`) and European comma-decimal (`€199,99`, `1.299,00 €`) prices.
func parseNumericPriceSpanSliceGo(raw string) (float64, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	var span strings.Builder
	started := false
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if (c >= '0' && c <= '9') || (started && (c == '.' || c == ',')) {
			span.WriteByte(c)
			started = true
		} else if started {
			break
		}
	}
	s := span.String()
	if s == "" {
		return 0, false
	}
	// Trim any trailing '.' or ',' from the span.
	s = strings.TrimRight(s, ".,")
	if s == "" {
		return 0, false
	}
	lastComma := strings.LastIndexByte(s, ',')
	lastDot := strings.LastIndexByte(s, '.')
	var normalized string
	if lastComma > lastDot {
		afterComma := s[lastComma+1:]
		if len(afterComma) == 1 || len(afterComma) == 2 {
			// European decimal comma (e.g. "199,99" or "1.299,00").
			normalized = strings.ReplaceAll(s[:lastComma], ".", "") + "." + afterComma
		} else {
			// Thousands separator comma (e.g. "1,299").
			normalized = strings.ReplaceAll(s, ",", "")
		}
	} else {
		// Dot decimal or integer; strip grouping commas.
		normalized = strings.ReplaceAll(s, ",", "")
	}
	f, err := strconv.ParseFloat(normalized, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

func inferPriceCurrencySliceGo(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if m := reCurrencyCodeWordSliceGo.FindStringSubmatch(trimmed); len(m) >= 2 {
		return strings.ToUpper(m[1])
	}
	upper := strings.ToUpper(trimmed)
	switch {
	case strings.Contains(upper, "US$"):
		return "USD"
	case strings.Contains(upper, "CA$"), strings.Contains(upper, "C$"):
		return "CAD"
	case strings.Contains(upper, "AU$"), strings.Contains(upper, "A$"):
		return "AUD"
	case strings.Contains(trimmed, "£"):
		return "GBP"
	case strings.Contains(trimmed, "€"):
		return "EUR"
	}
	return ""
}

func normalizeAvailabilitySliceGo(raw string) string {
	s := strings.TrimSpace(reSchemaOrgPrefixSliceGo.ReplaceAllString(strings.TrimSpace(raw), ""))
	if s == "" {
		return ""
	}
	low := asciiLowerSliceGo(strings.Join(strings.Fields(s), " "))
	switch {
	case strings.Contains(low, "not in stock"), strings.Contains(low, "not-in-stock"), strings.Contains(low, "not instock"),
		strings.Contains(low, "not available"), strings.Contains(low, "no longer available"),
		strings.Contains(low, "out of stock"), strings.Contains(low, "outofstock"), strings.Contains(low, "sold out"), strings.Contains(low, "unavailable"):
		return "OutOfStock"
	case strings.Contains(low, "preorder"), strings.Contains(low, "pre-order"):
		return "PreOrder"
	case strings.Contains(low, "backorder"), strings.Contains(low, "back-order"):
		return "BackOrder"
	case strings.Contains(low, "in stock"), strings.Contains(low, "instock"), low == "available":
		return "InStock"
	default:
		return SanitizePlainMetadataText(s, 80)
	}
}

func firstNonEmptySliceGo(vals ...string) string {
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func appendUniqueImageSliceGo(dst []string, rawImg, finalURL string) []string {
	norm := normalizePublicProductImageURLSliceGo(rawImg, finalURL)
	if norm == "" {
		return dst
	}
	for _, existing := range dst {
		if existing == norm {
			return dst
		}
	}
	return append(dst, norm)
}

func hasItemTypeTokenSliceGo(el *domNodeDOM, re *lazyRegexp) bool {
	if el == nil || el.attribs == nil {
		return false
	}
	raw, ok := el.attribs["itemtype"]
	if !ok || strings.TrimSpace(raw) == "" {
		return false
	}
	for _, tok := range strings.Fields(raw) {
		if re.MatchString(tok) {
			return true
		}
	}
	return false
}

func hasAttribDOM(el *domNodeDOM, name string) bool {
	if el == nil || el.attribs == nil {
		return false
	}
	_, ok := el.attribs[name]
	return ok
}

func microdataPropValueSliceGo(el *domNodeDOM, prop string, budget *visitBudgetDOM) string {
	if el == nil {
		return ""
	}
	switch prop {
	case "url", "image", "availability", "itemcondition":
		switch el.name {
		case "a", "area", "link":
			if v := strings.TrimSpace(el.attribs["href"]); v != "" {
				return v
			}
		case "img", "source":
			if v := firstNonEmptySliceGo(el.attribs["src"], el.attribs["data-src"]); v != "" {
				return v
			}
		}
		if v := strings.TrimSpace(el.attribs["content"]); v != "" {
			return v
		}
		return extractCleanNodeTextDOM(el, budget)
	default:
		if v := strings.TrimSpace(el.attribs["content"]); v != "" {
			return v
		}
		if el.name == "data" || el.name == "meter" || el.name == "input" {
			if v := strings.TrimSpace(el.attribs["value"]); v != "" {
				return v
			}
		}
		if el.name == "time" {
			if v := strings.TrimSpace(el.attribs["datetime"]); v != "" {
				return v
			}
		}
		return extractCleanNodeTextDOM(el, budget)
	}
}

func collectScopedMicrodataProps(root *domNodeDOM, budget *visitBudgetDOM, onProp func(prop string, el *domNodeDOM, isScope bool)) {
	if root == nil || budget == nil {
		return
	}
	var walk func(node *domNodeDOM, isRoot bool)
	walk = func(node *domNodeDOM, isRoot bool) {
		if node == nil || budget.remaining <= 0 {
			return
		}
		budget.remaining--
		if node.kind == nodeElementDOM && !isRoot {
			rawProp := strings.TrimSpace(node.attribs["itemprop"])
			isScope := hasAttribDOM(node, "itemscope")
			if rawProp != "" {
				for _, tok := range strings.Fields(asciiLowerSliceGo(rawProp)) {
					onProp(tok, node, isScope)
				}
			}
			// Scope isolation: never descend past a nested itemscope so Brand.name / Offer.name / Review don't leak.
			if isScope {
				return
			}
		}
		for _, ch := range node.children {
			if ch.kind == nodeElementDOM {
				walk(ch, false)
			}
		}
	}
	walk(root, true)
}

func parseMicrodataOfferScope(offerNode *domNodeDOM, budget *visitBudgetDOM) map[string]any {
	offer := make(map[string]any)
	collectScopedMicrodataProps(offerNode, budget, func(prop string, el *domNodeDOM, isScope bool) {
		if isScope {
			if prop == "pricespecification" {
				nested := parseMicrodataOfferScope(el, budget)
				for _, k := range []string{"price", "lowPrice", "priceCurrency"} {
					if offer[k] == nil && nested[k] != nil {
						offer[k] = nested[k]
					}
				}
			}
			return
		}
		val := microdataPropValueSliceGo(el, prop, budget)
		if val == "" {
			return
		}
		switch prop {
		case "name":
			if offer["name"] == nil {
				offer["name"] = val
			}
		case "sku":
			if offer["sku"] == nil {
				offer["sku"] = val
			}
		case "mpn":
			if offer["mpn"] == nil {
				offer["mpn"] = val
			}
		case "price":
			if offer["price"] == nil {
				offer["price"] = val
			}
		case "lowprice":
			if offer["lowPrice"] == nil {
				offer["lowPrice"] = val
			}
		case "pricecurrency":
			if offer["priceCurrency"] == nil {
				offer["priceCurrency"] = val
			}
		case "availability":
			if offer["availability"] == nil {
				offer["availability"] = val
			}
		case "url":
			if offer["url"] == nil {
				offer["url"] = val
			}
		}
	})
	return offer
}

// ExtractMicrodataProduct extracts Schema.org Product Microdata (`itemscope`/`itemtype`/`itemprop`)
// from HTML, returning nil when no valid Product microdata scope is present.
func ExtractMicrodataProduct(rawBody, finalURL, fallbackTitle, fallbackDescription string) map[string]any {
	return extractMicrodataProductSliceGo(rawBody, finalURL, fallbackTitle, fallbackDescription)
}

func extractMicrodataProductSliceGo(rawBody, finalURL, fallbackTitle, fallbackDescription string) map[string]any {
	if indexFoldASCIIExtract(rawBody, "itemscope") < 0 ||
		indexFoldASCIIExtract(rawBody, "itemtype") < 0 ||
		indexFoldASCIIExtract(rawBody, "schema.org") < 0 {
		return nil
	}
	doc := ParseHTMLDoc(rawBody, maxHTMLScanBytesSliceGo)
	if doc == nil || doc.node == nil || doc.budget == nil {
		return nil
	}

	var productRoot *domNodeDOM
	walkSubtreeElementsDOM(doc.node, doc.budget, func(el *domNodeDOM) walkDirectiveDOM {
		if hasAttribDOM(el, "itemscope") && hasItemTypeTokenSliceGo(el, reMicrodataProductTypeSliceGo) {
			productRoot = el
			return walkStopDOM
		}
		return walkContinueDOM
	})
	if productRoot == nil {
		return nil
	}

	var (
		microName, microDesc, microURL, microBrand string
		microSKU, microMPN, microProductID         string
		microGTIN13, microGTIN14, microGTIN12      string
		microGTIN8, microGTIN, microEAN, microUPC  string
		directPrice, directLowPrice, directCurr    string
		directAvail                                string
		ratingVal, reviewCount, ratingCount        string
		rawImages                                  []string
		offerList                                  []map[string]any
	)

	collectScopedMicrodataProps(productRoot, doc.budget, func(prop string, el *domNodeDOM, isScope bool) {
		if isScope {
			switch prop {
			case "brand", "manufacturer":
				if microBrand == "" {
					var nestedBrand string
					collectScopedMicrodataProps(el, doc.budget, func(np string, nel *domNodeDOM, nScope bool) {
						if !nScope && np == "name" && nestedBrand == "" {
							nestedBrand = microdataPropValueSliceGo(nel, np, doc.budget)
						}
					})
					microBrand = firstNonEmptySliceGo(nestedBrand, extractCleanNodeTextDOM(el, doc.budget))
				}
			case "offers", "offer":
				if len(offerList) < 30 && (hasItemTypeTokenSliceGo(el, reMicrodataOfferTypeSliceGo) || !hasAttribDOM(el, "itemtype")) {
					om := parseMicrodataOfferScope(el, doc.budget)
					if len(om) > 0 {
						offerList = append(offerList, om)
					}
				}
			case "aggregaterating":
				if hasItemTypeTokenSliceGo(el, reMicrodataRatingTypeSliceGo) || !hasAttribDOM(el, "itemtype") {
					collectScopedMicrodataProps(el, doc.budget, func(np string, nel *domNodeDOM, nScope bool) {
						if nScope {
							return
						}
						nv := microdataPropValueSliceGo(nel, np, doc.budget)
						switch np {
						case "ratingvalue":
							if ratingVal == "" {
								ratingVal = nv
							}
						case "reviewcount":
							if reviewCount == "" {
								reviewCount = nv
							}
						case "ratingcount":
							if ratingCount == "" {
								ratingCount = nv
							}
						}
					})
				}
			case "image":
				if hasItemTypeTokenSliceGo(el, reMicrodataImageTypeSliceGo) || !hasAttribDOM(el, "itemtype") {
					collectScopedMicrodataProps(el, doc.budget, func(np string, nel *domNodeDOM, nScope bool) {
						if !nScope && (np == "url" || np == "contenturl") {
							if nv := microdataPropValueSliceGo(nel, "image", doc.budget); nv != "" {
								rawImages = append(rawImages, nv)
							}
						}
					})
				}
			default:
				if (prop == "brand" || prop == "manufacturer") && hasItemTypeTokenSliceGo(el, reMicrodataBrandTypeSliceGo) {
					// Already handled above.
				}
			}
			return
		}

		val := microdataPropValueSliceGo(el, prop, doc.budget)
		if val == "" {
			return
		}
		switch prop {
		case "name":
			if microName == "" {
				microName = val
			}
		case "description":
			if microDesc == "" {
				microDesc = val
			}
		case "url":
			if microURL == "" {
				microURL = val
			}
		case "brand", "manufacturer":
			if microBrand == "" {
				microBrand = val
			}
		case "sku":
			if microSKU == "" {
				microSKU = val
			}
		case "mpn":
			if microMPN == "" {
				microMPN = val
			}
		case "productid":
			if microProductID == "" {
				microProductID = val
			}
		case "gtin13":
			if microGTIN13 == "" {
				microGTIN13 = val
			}
		case "gtin14":
			if microGTIN14 == "" {
				microGTIN14 = val
			}
		case "gtin12":
			if microGTIN12 == "" {
				microGTIN12 = val
			}
		case "gtin8":
			if microGTIN8 == "" {
				microGTIN8 = val
			}
		case "gtin":
			if microGTIN == "" {
				microGTIN = val
			}
		case "ean":
			if microEAN == "" {
				microEAN = val
			}
		case "upc":
			if microUPC == "" {
				microUPC = val
			}
		case "price":
			if directPrice == "" {
				directPrice = val
			}
		case "lowprice":
			if directLowPrice == "" {
				directLowPrice = val
			}
		case "pricecurrency":
			if directCurr == "" {
				directCurr = val
			}
		case "availability":
			if directAvail == "" {
				directAvail = val
			}
		case "image":
			rawImages = append(rawImages, val)
		case "ratingvalue":
			if ratingVal == "" {
				ratingVal = val
			}
		case "reviewcount":
			if reviewCount == "" {
				reviewCount = val
			}
		case "ratingcount":
			if ratingCount == "" {
				ratingCount = val
			}
		}
	})

	var primaryOffer map[string]any
	if len(offerList) > 0 {
		primaryOffer = offerList[0]
	}

	var rawPrice any
	if primaryOffer != nil {
		if p, ok := primaryOffer["price"]; ok && p != nil {
			rawPrice = p
		} else if lp, ok := primaryOffer["lowPrice"]; ok && lp != nil {
			rawPrice = lp
		}
	}
	if rawPrice == nil {
		if directPrice != "" {
			rawPrice = directPrice
		} else if directLowPrice != "" {
			rawPrice = directLowPrice
		}
	}
	price, hasPrice := parsePriceValueSliceGo(rawPrice)

	currency := ""
	if primaryOffer != nil {
		if c, ok := primaryOffer["priceCurrency"].(string); ok {
			currency = strings.TrimSpace(c)
		}
	}
	if currency == "" {
		currency = strings.TrimSpace(directCurr)
	}
	if currency == "" && rawPrice != nil {
		if s, ok := rawPrice.(string); ok {
			currency = inferPriceCurrencySliceGo(s)
		}
	}

	availability := ""
	if primaryOffer != nil {
		if a, ok := primaryOffer["availability"].(string); ok {
			availability = normalizeAvailabilitySliceGo(a)
		}
	}
	if availability == "" && directAvail != "" {
		availability = normalizeAvailabilitySliceGo(directAvail)
	}

	var images []string
	for _, ri := range rawImages {
		images = appendUniqueImageSliceGo(images, ri, finalURL)
	}
	if len(images) == 0 {
		if ogImg := matchMetaContentSliceGo(rawBody, []string{"og:image"}); ogImg != "" {
			images = appendUniqueImageSliceGo(images, ogImg, finalURL)
		}
	}

	title := SanitizePlainMetadataText(firstNonEmptySliceGo(microName, fallbackTitle), 400)
	desc := SanitizePlainMetadataText(firstNonEmptySliceGo(microDesc, fallbackDescription), 1200)
	brand := SanitizePlainMetadataText(microBrand, 240)
	offerSKU := ""
	offerMPN := ""
	if primaryOffer != nil {
		if s, ok := primaryOffer["sku"].(string); ok {
			offerSKU = s
		}
		if m, ok := primaryOffer["mpn"].(string); ok {
			offerMPN = m
		}
	}
	mpn := SanitizePlainMetadataText(firstNonEmptySliceGo(microMPN, offerMPN), 160)
	sku := SanitizePlainMetadataText(firstNonEmptySliceGo(microSKU, offerSKU, mpn, microProductID), 160)
	gtin := SanitizePlainMetadataText(firstNonEmptySliceGo(microGTIN13, microGTIN14, microGTIN12, microGTIN8, microGTIN, microEAN, microUPC), 64)

	if title == "" || (!hasPrice && sku == "" && mpn == "" && gtin == "" && brand == "" && availability == "" && len(images) == 0 && len(offerList) == 0) {
		return nil
	}

	resolvedURL := resolveStructuredProductURLSliceGo(microURL, finalURL)
	out := map[string]any{
		"url":   resolvedURL,
		"title": title,
	}
	if desc != "" {
		out["description"] = desc
	}
	if brand != "" {
		out["brand"] = brand
	}
	if sku != "" {
		out["sku"] = sku
	}
	if mpn != "" {
		out["mpn"] = mpn
	}
	if gtin != "" {
		out["gtin"] = gtin
	}
	if hasPrice {
		out["price"] = price
	}
	if currency != "" {
		out["currency"] = SanitizePlainMetadataText(currency, 16)
	}
	if availability != "" {
		out["availability"] = availability
	}
	if len(images) > 0 {
		out["images"] = images
	}
	if ratingVal != "" {
		out["rating"] = jsNumberOrRawSliceGo(ratingVal)
	}
	rcSrc := firstNonEmptySliceGo(reviewCount, ratingCount)
	if rcSrc != "" {
		out["reviewCount"] = jsNumberOrRawSliceGo(rcSrc)
	}
	if len(offerList) > 1 {
		capOffers := minIntSliceGo(len(offerList), 30)
		variants := make([]map[string]any, 0, capOffers)
		for _, o := range offerList[:capOffers] {
			vm := make(map[string]any)
			if vn, ok := o["name"].(string); ok {
				if cleanVN := SanitizePlainMetadataText(vn, 240); cleanVN != "" {
					vm["name"] = cleanVN
				}
			}
			if vs, ok := o["sku"].(string); ok {
				if cleanVS := SanitizePlainMetadataText(vs, 160); cleanVS != "" {
					vm["sku"] = cleanVS
				}
			}
			if vp, ok := o["price"]; ok && vp != nil {
				if parsedVP, okVP := parseVariantPriceValueSliceGo(vp); okVP {
					vm["price"] = parsedVP
				}
			} else if vlp, ok := o["lowPrice"]; ok && vlp != nil {
				if parsedVP, okVP := parseVariantPriceValueSliceGo(vlp); okVP {
					vm["price"] = parsedVP
				}
			}
			if vc, ok := o["priceCurrency"].(string); ok && vc != "" {
				vm["currency"] = SanitizePlainMetadataText(vc, 16)
			}
			if va, ok := o["availability"].(string); ok && va != "" {
				if normVA := normalizeAvailabilitySliceGo(va); normVA != "" {
					vm["availability"] = normVA
				}
			}
			variants = append(variants, vm)
		}
		out["variants"] = variants
	}
	return out
}

func isInsideChromeAncestorsDOM(el *domNodeDOM) bool {
	for cur := el.parent; cur != nil; cur = cur.parent {
		if cur.kind != nodeElementDOM {
			continue
		}
		switch cur.name {
		case "nav", "header", "footer", "aside":
			return true
		}
	}
	return false
}

func normalizeSpecKeySliceGo(rawKey string) (normKey string, baseKey string) {
	k := asciiLowerSliceGo(strings.Join(strings.Fields(rawKey), " "))
	k = strings.TrimRight(k, ": \t")
	base := strings.TrimSpace(reParenSuffixSliceGo.ReplaceAllString(k, ""))
	return k, base
}

func toCamelSpecKeySliceGo(baseKey string) string {
	fields := strings.FieldsFunc(baseKey, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	if len(fields) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fields[0])
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if f == "" {
			continue
		}
		if f[0] >= 'a' && f[0] <= 'z' {
			sb.WriteByte(f[0] - ('a' - 'A'))
			sb.WriteString(f[1:])
		} else {
			sb.WriteString(f)
		}
	}
	return sb.String()
}

func looksLikePartCodeSliceGo(val string) bool {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" || len(trimmed) > 64 {
		return false
	}
	if !reAlnumDigitCodeSliceGo.MatchString(trimmed) {
		return false
	}
	if len(strings.Fields(trimmed)) > 3 {
		return false
	}
	if strings.Contains(trimmed, ". ") || strings.ContainsAny(trimmed, ";!?") {
		return false
	}
	return true
}

func extractSpecTableProductSliceGo(rawBody, finalURL, fallbackTitle, fallbackDescription string, jsonLdList []map[string]any) map[string]any {
	if indexFoldASCIIExtract(rawBody, "<table") < 0 &&
		indexFoldASCIIExtract(rawBody, "<dl") < 0 &&
		indexFoldASCIIExtract(rawBody, "price") < 0 &&
		!reCurrencyPrefixedPriceHintGo.MatchString(rawBody) {
		return nil
	}

	// False-positive veto 1: non-product og:type.
	ogType := asciiLowerSliceGo(strings.TrimSpace(matchMetaContentSliceGo(rawBody, []string{"og:type"})))
	if ogType == "article" || ogType == "newsarticle" || ogType == "blogposting" || ogType == "profile" ||
		strings.HasPrefix(ogType, "article.") || strings.HasPrefix(ogType, "video.") || strings.HasPrefix(ogType, "music.") {
		return nil
	}

	// False-positive veto 2: non-product JSON-LD primary entity.
	for _, obj := range jsonLdList {
		switch tv := obj["@type"].(type) {
		case string:
			if reNonProductLdTypeSliceGo.MatchString(strings.TrimSpace(tv)) {
				return nil
			}
		case []any:
			for _, elem := range tv {
				if s, ok := elem.(string); ok && reNonProductLdTypeSliceGo.MatchString(strings.TrimSpace(s)) {
					return nil
				}
			}
		}
	}

	// False-positive veto 3: MediaWiki / Docs / Forum HTML markers.
	if indexFoldASCIIExtract(rawBody, "mw-parser-output") >= 0 ||
		indexFoldASCIIExtract(rawBody, "mw-content-text") >= 0 ||
		indexFoldASCIIExtract(rawBody, `content="mediawiki`) >= 0 ||
		indexFoldASCIIExtract(rawBody, "markdown-body") >= 0 ||
		indexFoldASCIIExtract(rawBody, "rst-content") >= 0 ||
		indexFoldASCIIExtract(rawBody, "theme-doc-markdown") >= 0 ||
		indexFoldASCIIExtract(rawBody, "message--post") >= 0 {
		return nil
	}

	doc := ParseHTMLDoc(rawBody, maxHTMLScanBytesSliceGo)
	if doc == nil || doc.node == nil || doc.budget == nil {
		return nil
	}

	// Additional DOM veto for Wikipedia table.infobox.
	hasInfobox := false
	walkSubtreeElementsDOM(doc.node, doc.budget, func(el *domNodeDOM) walkDirectiveDOM {
		if el.name == "table" && el.attribs != nil && hasClassTokenDOM(el.attribs["class"], "infobox") {
			hasInfobox = true
			return walkStopDOM
		}
		return walkContinueDOM
	})
	if hasInfobox {
		return nil
	}

	// Collect 2-column spec tables and <dl> pairs outside <nav>/<header>/<footer>/<aside>.
	type kvPair struct {
		key string
		val string
	}
	var pairs []kvPair

	tables := doc.Select("table", 30)
	for _, tbl := range tables {
		if isInsideChromeAncestorsDOM(tbl.node) {
			continue
		}
		rows := tbl.TableRows()
		twoColCount := 0
		multiColCount := 0
		tablePairs := make([]kvPair, 0, len(rows))
		for _, row := range rows {
			if len(row) == 2 {
				k := strings.TrimSpace(row[0])
				v := strings.TrimSpace(row[1])
				if len(k) >= 1 && len(k) <= 80 && len(v) >= 1 && len(v) <= 300 {
					twoColCount++
					tablePairs = append(tablePairs, kvPair{key: k, val: v})
				}
			} else if len(row) >= 3 {
				multiColCount++
			}
		}
		if twoColCount >= 2 && multiColCount <= twoColCount {
			pairs = append(pairs, tablePairs...)
		}
	}

	dls := doc.Select("dl", 30)
	for _, dl := range dls {
		if isInsideChromeAncestorsDOM(dl.node) {
			continue
		}
		pendingKey := ""
		walkSubtreeElementsDOM(dl.node, doc.budget, func(el *domNodeDOM) walkDirectiveDOM {
			switch el.name {
			case "dt":
				pendingKey = strings.TrimSpace(extractCleanNodeTextDOM(el, doc.budget))
				return walkSkipDOM
			case "dd":
				if pendingKey != "" {
					val := strings.TrimSpace(extractCleanNodeTextDOM(el, doc.budget))
					if len(pendingKey) <= 80 && len(val) >= 1 && len(val) <= 300 {
						pairs = append(pairs, kvPair{key: pendingKey, val: val})
					}
					pendingKey = ""
				}
				return walkSkipDOM
			}
			return walkContinueDOM
		})
	}

	// Collect <li>Key: Value</li> spec pairs outside chrome ancestors for non-table/non-<dl> product pages.
	for _, li := range doc.Select("li", 60) {
		if isInsideChromeAncestorsDOM(li.node) {
			continue
		}
		txt := strings.TrimSpace(extractCleanNodeTextDOM(li.node, doc.budget))
		if len(txt) < 4 || len(txt) > 200 {
			continue
		}
		colonIdx := strings.IndexByte(txt, ':')
		if colonIdx <= 0 || colonIdx >= 80 || colonIdx+1 >= len(txt) {
			continue
		}
		k := strings.TrimSpace(txt[:colonIdx])
		v := strings.TrimSpace(txt[colonIdx+1:])
		if len(k) >= 1 && len(k) <= 80 && len(v) >= 1 && len(v) <= 160 {
			pairs = append(pairs, kvPair{key: k, val: v})
		}
	}

	var (
		sku, mpn, modelCode, gtin, brand, productType string
		availability                                  string
		primaryPriceRaw, secondaryPriceRaw            string
		hasPrimaryPrice                               bool
		recognizedSpecCount, hardwareSpecCount        int
		specs                                         = make(map[string]string)
	)

	for _, kv := range pairs {
		normKey, baseKey := normalizeSpecKeySliceGo(kv.key)
		if normKey == "" {
			continue
		}
		// Job-posting table veto.
		switch baseKey {
		case "salary", "compensation", "employment type", "job type", "qualifications", "apply now":
			return nil
		}

		val := SanitizePlainMetadataText(kv.val, 300)
		if val == "" {
			continue
		}

		switch normKey {
		case "sku", "product code", "item code":
			if sku == "" {
				sku = SanitizePlainMetadataText(val, 160)
				recognizedSpecCount++
			}
		case "mpn", "part number", "part no", "part no.", "part #", "manufacturer part number",
			"article number", "article no", "article no.", "item number", "item no", "item #", "catalog number":
			if mpn == "" {
				mpn = SanitizePlainMetadataText(val, 160)
				recognizedSpecCount++
			}
		case "code":
			if looksLikePartCodeSliceGo(val) {
				if sku == "" {
					sku = SanitizePlainMetadataText(val, 160)
				}
				if mpn == "" {
					mpn = SanitizePlainMetadataText(val, 160)
				}
				recognizedSpecCount++
			}
		case "model", "model number", "model no":
			if modelCode == "" {
				modelCode = SanitizePlainMetadataText(val, 160)
			}
			recognizedSpecCount++
			hardwareSpecCount++
			if camel := toCamelSpecKeySliceGo(baseKey); camel != "" {
				specs[camel] = val
			}
		case "upc", "ean", "ean-13", "ean13", "gtin", "gtin-13", "gtin-12", "gtin-8", "gtin-14", "barcode", "isbn", "isbn-10", "isbn-13":
			if gtin == "" {
				gtin = SanitizePlainMetadataText(val, 64)
				recognizedSpecCount++
			}
			if camel := toCamelSpecKeySliceGo(baseKey); camel != "" {
				specs[camel] = val
			}
		case "price", "price (excl. tax)", "price (incl. tax)", "unit price", "sale price", "our price":
			if !hasPrimaryPrice {
				primaryPriceRaw = val
				hasPrimaryPrice = true
				recognizedSpecCount++
			}
		case "list price", "msrp", "rrp", "retail price":
			if secondaryPriceRaw == "" {
				secondaryPriceRaw = val
				recognizedSpecCount++
			}
		case "availability", "stock", "stock status", "in stock":
			if availability == "" {
				availability = normalizeAvailabilitySliceGo(val)
				recognizedSpecCount++
			}
		case "brand", "manufacturer", "vendor", "make", "publisher":
			if brand == "" {
				brand = SanitizePlainMetadataText(val, 240)
				recognizedSpecCount++
			}
		case "product type":
			if productType == "" {
				productType = SanitizePlainMetadataText(val, 160)
			}
			recognizedSpecCount++
			if camel := toCamelSpecKeySliceGo(baseKey); camel != "" {
				specs[camel] = val
			}
		case "tax", "number of reviews":
			recognizedSpecCount++
			if camel := toCamelSpecKeySliceGo(baseKey); camel != "" {
				specs[camel] = val
			}
		default:
			switch baseKey {
			case "rated voltage", "voltage", "rated power", "power", "max torque", "torque",
				"efficiency", "weight", "dimensions", "operating temperature", "ip rating",
				"protection grade", "communication", "protocol", "wheel size", "gear ratio",
				"reduction ratio", "mounting", "cable length", "connector", "noise grade",
				"certifications", "battery", "capacity", "frame", "fork", "drivetrain", "brakes":
				recognizedSpecCount++
				hardwareSpecCount++
				if camel := toCamelSpecKeySliceGo(baseKey); camel != "" {
					specs[camel] = val
				}
			}
		}
	}

	if mpn == "" && modelCode != "" {
		mpn = modelCode
	}
	if sku == "" && mpn != "" {
		sku = mpn
	}

	// Semantic price & availability selectors when not already found in spec table.
	priceCandidateRaw := primaryPriceRaw
	if priceCandidateRaw == "" {
		priceCandidateRaw = secondaryPriceRaw
	}
	if priceCandidateRaw == "" {
		for _, sel := range []string{".price_color", ".product-price", ".product_price", ".woocommerce-Price-amount", "p.price", "span.price", "[data-price]", ".amount", ".money", ".cost"} {
			hits := doc.Select(sel, 6)
			for _, hit := range hits {
				if isInsideChromeAncestorsDOM(hit.node) {
					continue
				}
				txt := strings.TrimSpace(hit.AttrOrEmpty("data-price"))
				if txt == "" {
					txt = strings.TrimSpace(hit.Text())
				}
				if txt != "" && len(txt) <= 40 {
					if f, ok := parseNumericPriceSpanSliceGo(txt); ok && f > 0 {
						priceCandidateRaw = txt
						break
					}
				}
			}
			if priceCandidateRaw != "" {
				break
			}
		}
	}
	if priceCandidateRaw == "" {
		walkSubtreeElementsDOM(doc.node, doc.budget, func(el *domNodeDOM) walkDirectiveDOM {
			if priceCandidateRaw != "" {
				return walkStopDOM
			}
			if isInsideChromeAncestorsDOM(el) {
				return walkSkipDOM
			}
			switch el.name {
			case "p", "span", "div", "strong", "b", "em", "li", "dd":
				hasChildElem := false
				for _, ch := range el.children {
					if ch.kind == nodeElementDOM {
						hasChildElem = true
						break
					}
				}
				if !hasChildElem {
					txt := strings.TrimSpace(extractCleanNodeTextDOM(el, doc.budget))
					if len(txt) >= 2 && len(txt) <= 32 && reStrictCurrencySpanSliceGo.MatchString(txt) {
						if f, ok := parseNumericPriceSpanSliceGo(txt); ok && f > 0 {
							priceCandidateRaw = txt
							return walkStopDOM
						}
					}
				}
			}
			return walkContinueDOM
		})
	}

	var parsedPrice any
	hasNumericPrice := false
	if priceCandidateRaw != "" {
		if f, ok := parseNumericPriceSpanSliceGo(priceCandidateRaw); ok && f > 0 {
			parsedPrice = f
			hasNumericPrice = true
		}
	}
	currency := ""
	if hasNumericPrice {
		currency = inferPriceCurrencySliceGo(priceCandidateRaw)
	}

	if availability == "" {
		for _, sel := range []string{".instock", ".out-of-stock", ".availability", ".stock-status"} {
			hits := doc.Select(sel, 4)
			for _, hit := range hits {
				if isInsideChromeAncestorsDOM(hit.node) {
					continue
				}
				if txt := strings.TrimSpace(hit.Text()); txt != "" && len(txt) <= 80 {
					normAv := normalizeAvailabilitySliceGo(txt)
					if normAv == "InStock" || normAv == "OutOfStock" || normAv == "PreOrder" || normAv == "BackOrder" {
						availability = normAv
						break
					}
				}
			}
			if availability != "" {
				break
			}
		}
	}

	h1Text := ""
	if h1 := doc.First("h1"); h1 != nil && !isInsideChromeAncestorsDOM(h1.node) {
		h1Text = h1.Text()
	}
	ogTitle := matchMetaContentSliceGo(rawBody, []string{"og:title"})
	title := SanitizePlainMetadataText(firstNonEmptySliceGo(h1Text, ogTitle, fallbackTitle), 400)
	if title == "" {
		return nil
	}

	// Anti-false-positive activation gate.
	hasIdentifier := sku != "" || gtin != "" || mpn != ""
	activated := (hasNumericPrice && (hasIdentifier || brand != "" || availability != "" || productType != "" || recognizedSpecCount >= 2)) ||
		(hasIdentifier && recognizedSpecCount >= 2) ||
		(hardwareSpecCount >= 3)
	if !activated {
		return nil
	}

	descSrc := ""
	for _, sel := range []string{"#product_description + p", ".product_description", ".product-description"} {
		if node := doc.First(sel); node != nil && !isInsideChromeAncestorsDOM(node.node) {
			if txt := strings.TrimSpace(node.Text()); txt != "" {
				descSrc = txt
				break
			}
		}
	}
	desc := SanitizePlainMetadataText(firstNonEmptySliceGo(descSrc, fallbackDescription), 1200)

	var images []string
	for _, sel := range []string{"#product_gallery img", ".product_page img", ".product-gallery img", ".item.active img", "main img", "article img"} {
		for _, img := range doc.Select(sel, 8) {
			if isInsideChromeAncestorsDOM(img.node) {
				continue
			}
			src := firstNonEmptySliceGo(img.AttrOrEmpty("src"), img.AttrOrEmpty("data-src"))
			if src == "" || reSkipProductImageNameSliceGo.MatchString(src) {
				continue
			}
			if img.AttrOrEmpty("width") == "1" || img.AttrOrEmpty("height") == "1" {
				continue
			}
			images = appendUniqueImageSliceGo(images, src, finalURL)
			if len(images) >= 5 {
				break
			}
		}
		if len(images) > 0 {
			break
		}
	}
	if len(images) == 0 {
		if ogImg := matchMetaContentSliceGo(rawBody, []string{"og:image"}); ogImg != "" {
			images = appendUniqueImageSliceGo(images, ogImg, finalURL)
		}
	}

	productURL := finalURL
	var mdProdRoot *domNodeDOM
	walkSubtreeElementsDOM(doc.node, doc.budget, func(el *domNodeDOM) walkDirectiveDOM {
		if hasAttribDOM(el, "itemscope") && hasItemTypeTokenSliceGo(el, reMicrodataProductTypeSliceGo) {
			mdProdRoot = el
			return walkStopDOM
		}
		return walkContinueDOM
	})
	if mdProdRoot != nil {
		collectScopedMicrodataProps(mdProdRoot, doc.budget, func(prop string, el *domNodeDOM, isScope bool) {
			if !isScope && prop == "url" && productURL == finalURL {
				if cand := microdataPropValueSliceGo(el, prop, doc.budget); cand != "" {
					productURL = resolveStructuredProductURLSliceGo(cand, finalURL)
				}
			}
		})
	}

	out := map[string]any{
		"url":   productURL,
		"title": title,
	}
	if desc != "" {
		out["description"] = desc
	}
	if brand != "" {
		out["brand"] = brand
	}
	if sku != "" {
		out["sku"] = sku
	}
	if mpn != "" {
		out["mpn"] = mpn
	}
	if gtin != "" {
		out["gtin"] = gtin
	}
	if hasNumericPrice {
		out["price"] = parsedPrice
	}
	if currency != "" {
		out["currency"] = currency
	}
	if availability != "" {
		out["availability"] = availability
	}
	if len(images) > 0 {
		out["images"] = images
	}
	if len(specs) > 0 {
		out["specs"] = specs
	}
	return out
}
