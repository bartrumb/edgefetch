package catalog

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
)

var (
	reWooProductTwinPath = newLazyRegexp(`(?i)^(?:/[a-z]{2}(?:-[a-z]{2})?)?/product/([a-z0-9._~%-]+)/?$`)
	reWooSinglePath      = newLazyRegexp(`(?i)/product/[^/]+`)
	reLeadingMarkdownH1  = newLazyRegexp(`^#\s+[^\n]+\n+`)
	reNonAlnumSlug       = newLazyRegexp(`[^a-z0-9]+`)
)

// IsWooCommerceHTMLOrHeaders detects WooCommerce storefronts from Link headers or HTML markers.
func IsWooCommerceHTMLOrHeaders(rawHTML string, headers map[string]string) bool {
	if len(headers) > 0 {
		if linkHdr := readHeaderCaseInsensitive(headers, "link"); strings.Contains(linkHdr, "/wp-json/wc/") {
			return true
		}
	}
	if rawHTML == "" {
		return false
	}
	slice := rawHTML
	if len(slice) > 100_000 {
		slice = slice[:100_000]
	}
	return strings.Contains(slice, "woocommerce-page") ||
		strings.Contains(slice, "woocommerce-loop-product") ||
		strings.Contains(slice, "woocommerce-products-header") ||
		strings.Contains(slice, "wc-block-grid") ||
		strings.Contains(slice, "wc-blocks") ||
		strings.Contains(slice, "/plugins/woocommerce/") ||
		strings.Contains(slice, "WooCommerce") ||
		strings.Contains(slice, "wc_add_to_cart_params") ||
		strings.Contains(slice, "/wp-json/wc/store/")
}

// WooCommerceProductTwinURL holds the resolved WooCommerce Store API v1 twin URL for a product page.
type WooCommerceProductTwinURL struct {
	Slug        string `json:"slug"`
	StoreAPIURL string `json:"storeApiUrl"`
}

func parseHTTPSHostAndRawPath(productURL string) (host string, rawPath string, ok bool) {
	s := strings.TrimSpace(productURL)
	if len(s) <= len("https://") || !strings.EqualFold(s[:8], "https://") || strings.IndexByte(s, '\\') >= 0 {
		return "", "", false
	}
	u, err := url.Parse(s)
	if err == nil {
		if !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Host == "" {
			return "", "", false
		}
		if port := u.Port(); port != "" && port != "443" {
			return "", "", false
		}
		rawHost := strings.ToLower(u.Hostname())
		if rawHost == "" || strings.HasSuffix(rawHost, ".") || !strings.Contains(rawHost, ".") || !IsSafePublicHostname(rawHost, "") {
			return "", "", false
		}
		rp := u.EscapedPath()
		if rp == "" {
			rp = u.Path
		}
		return rawHost, rp, true
	}
	// Fallback when pathname contains malformed percent-escapes (e.g. `%E0%A4%A`) accepted by WHATWG `new URL`.
	rest := s[8:]
	endAuth := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' || rest[i] == '?' || rest[i] == '#' {
			endAuth = i
			break
		}
	}
	auth := rest[:endAuth]
	if auth == "" || strings.ContainsAny(auth, "@ \t\r\n\\") {
		return "", "", false
	}
	uHost, errH := url.Parse("https://" + auth)
	if errH != nil || uHost.User != nil || uHost.Host == "" {
		return "", "", false
	}
	if port := uHost.Port(); port != "" && port != "443" {
		return "", "", false
	}
	rawHost := strings.ToLower(uHost.Hostname())
	if rawHost == "" || strings.HasSuffix(rawHost, ".") || !strings.Contains(rawHost, ".") || !IsSafePublicHostname(rawHost, "") {
		return "", "", false
	}
	tail := rest[endAuth:]
	if idx := strings.IndexAny(tail, "?#"); idx >= 0 {
		tail = tail[:idx]
	}
	if tail == "" {
		tail = "/"
	}
	return rawHost, tail, true
}

// ResolveCustomDomainWooCommerceProductTwinURL upgrades `/product/<slug>/` URLs to `/wp-json/wc/store/v1/products?slug=<slug>`.
func ResolveCustomDomainWooCommerceProductTwinURL(productURL string) *WooCommerceProductTwinURL {
	host, rawPath, ok := parseHTTPSHostAndRawPath(productURL)
	if !ok {
		return nil
	}
	m := reWooProductTwinPath.FindStringSubmatch(rawPath)
	if len(m) != 2 || m[1] == "" {
		return nil
	}
	slug := m[1]
	if dec, ok := SafeDecodeURIComponent(m[1]); ok {
		slug = dec
	}
	slug = strings.TrimSpace(slug)
	if slug == "" || len(slug) > 160 || strings.Contains(slug, "/") {
		return nil
	}
	origin := "https://" + host
	return &WooCommerceProductTwinURL{
		Slug:        slug,
		StoreAPIURL: origin + "/wp-json/wc/store/v1/products?slug=" + EncodeURIComponent(slug),
	}
}

// WooCommerceCatalogTwinURL holds the resolved Store API v1 list endpoint for a custom-domain
// `/product-category/<slug>/` or `/shop/` URL.
type WooCommerceCatalogTwinURL struct {
	Kind        string `json:"kind"`
	Slug        string `json:"slug,omitempty"`
	StoreAPIURL string `json:"storeApiUrl"`
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

// ResolveCustomDomainWooCommerceCatalogTwinURL upgrades `/product-category/.../<slug>/` and `/shop/` URLs
// to `/wp-json/wc/store/v1/products?category=<slug>&per_page=50` or `?per_page=50`.
func ResolveCustomDomainWooCommerceCatalogTwinURL(pageURL string) *WooCommerceCatalogTwinURL {
	host, rawPath, ok := parseHTTPSHostAndRawPath(pageURL)
	if !ok {
		return nil
	}
	var segs []string
	for _, seg := range strings.Split(rawPath, "/") {
		if seg != "" {
			segs = append(segs, seg)
		}
	}
	if len(segs) > 0 && reCatalogLocaleSeg.MatchString(segs[0]) {
		segs = segs[1:]
	}
	if len(segs) == 0 {
		return nil
	}

	pageNum := ""
	if len(segs) >= 3 && strings.EqualFold(segs[len(segs)-2], "page") && isAllDigitsASCII(segs[len(segs)-1]) {
		pageNum = segs[len(segs)-1]
		segs = segs[:len(segs)-2]
	}

	origin := "https://" + host
	pageSuffix := ""
	if pageNum != "" && pageNum != "1" {
		pageSuffix = "&page=" + pageNum
	}

	if len(segs) >= 2 && strings.EqualFold(segs[0], "product-category") {
		rawSlug := segs[len(segs)-1]
		slug := rawSlug
		if dec, okDec := SafeDecodeURIComponent(rawSlug); okDec {
			slug = dec
		}
		slug = strings.TrimSpace(slug)
		if slug == "" || len(slug) > 160 || strings.Contains(slug, "/") {
			return nil
		}
		return &WooCommerceCatalogTwinURL{
			Kind:        "category",
			Slug:        slug,
			StoreAPIURL: origin + "/wp-json/wc/store/v1/products?category=" + EncodeURIComponent(slug) + "&per_page=50" + pageSuffix,
		}
	}

	if len(segs) == 1 && strings.EqualFold(segs[0], "shop") {
		return &WooCommerceCatalogTwinURL{
			Kind:        "shop",
			StoreAPIURL: origin + "/wp-json/wc/store/v1/products?per_page=50" + pageSuffix,
		}
	}
	return nil
}

func scaleMinorUnitPrice(raw any, minorUnit int) *float64 {
	if raw == nil || raw == "" {
		return nil
	}
	var n float64
	hasN := false
	if f, ok := jsonNumberToFloatCommerce(raw); ok {
		n = f
		hasN = true
	} else if s, okS := raw.(string); okS {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			if f, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				n = f
				hasN = true
			}
		}
	}
	if !hasN || n < 0 {
		return nil
	}
	if minorUnit < 0 {
		minorUnit = 0
	} else if minorUnit > 8 {
		minorUnit = 8
	}
	factor := math.Pow10(minorUnit)
	scaled := math.Round(n) / factor
	return &scaled
}

// WooNormalizeOptions configures NormalizeWooCommerceProductRecord.
type WooNormalizeOptions struct {
	Fields      string `json:"fields,omitempty"`
	MaxImages   int    `json:"maxImages,omitempty"`
	MaxVariants int    `json:"maxVariants,omitempty"`
}

// NormalizeWooCommerceProductRecord normalizes a WooCommerce Store API v1 product object into a CatalogRecord.
func NormalizeWooCommerceProductRecord(rawProd map[string]any, originStr string, opts *WooNormalizeOptions) *CatalogRecord {
	if rawProd == nil {
		return nil
	}
	rawName := jsonScalarToStringCommerce(rawProd["name"])
	if rawName == "" {
		rawName = jsonScalarToStringCommerce(rawProd["title"])
	}
	title := SanitizeCommerceField(rawName, 400)
	if title == "" {
		return nil
	}

	maxImages := DefaultMaxImagesPerProduct
	maxVariants := DefaultMaxVariantsPerProduct
	if opts != nil {
		maxImages = clampProductBound(opts.MaxImages, DefaultMaxImagesPerProduct)
		maxVariants = clampProductBound(opts.MaxVariants, DefaultMaxVariantsPerProduct)
	}
	cleanOrigin := cleanOriginString(originStr)

	productID := jsonScalarToStringCommerce(rawProd["id"])
	handle := productID
	if slug, ok := rawProd["slug"].(string); ok && strings.TrimSpace(slug) != "" {
		handle = strings.TrimSpace(slug)
	}
	prodURL := NormalizePublicCommerceImageURL(rawProd["permalink"])
	if prodURL == "" {
		prodURL = cleanOrigin + "/product/" + EncodeURIComponent(handle) + "/"
	}

	prices, _ := rawProd["prices"].(map[string]any)
	minorUnit := 2
	if prices != nil {
		if mu, ok := jsonNumberToFloatCommerce(prices["currency_minor_unit"]); ok && isRawJSONNumberCommerce(prices["currency_minor_unit"]) && mu == math.Trunc(mu) && mu >= 0 && mu <= 8 {
			minorUnit = int(mu)
		}
	}
	var currency *string
	if prices != nil {
		if curRaw, ok := prices["currency_code"].(string); ok {
			curUp := strings.ToUpper(strings.TrimSpace(curRaw))
			if reISOCurrency3.MatchString(curUp) {
				currency = &curUp
			}
		}
	}

	var rawBasePrice, rawRegPrice any
	if prices != nil {
		rawBasePrice = prices["price"]
		if rawBasePrice == nil {
			rawBasePrice = prices["sale_price"]
		}
		rawRegPrice = prices["regular_price"]
	}
	basePrice := scaleMinorUnitPrice(rawBasePrice, minorUnit)
	regPrice := scaleMinorUnitPrice(rawRegPrice, minorUnit)
	var compareAt *float64
	if regPrice != nil && basePrice != nil && *regPrice > *basePrice {
		compareAt = regPrice
	}

	var vendor *string
	if brands, ok := rawProd["brands"].([]any); ok && len(brands) > 0 {
		if b0, ok0 := brands[0].(map[string]any); ok0 {
			if bName, okS := b0["name"].(string); okS && strings.TrimSpace(bName) != "" {
				vendor = strPtrOrNil(SanitizeCommerceField(bName, 200))
			}
		}
	}

	var productType *string
	if cats, ok := rawProd["categories"].([]any); ok && len(cats) > 0 {
		if c0, ok0 := cats[0].(map[string]any); ok0 {
			if cName, okS := c0["name"].(string); okS {
				productType = strPtrOrNil(SanitizeCommerceField(cName, 200))
			}
		}
	}
	if productType == nil {
		if tStr, ok := rawProd["type"].(string); ok {
			productType = strPtrOrNil(SanitizeCommerceField(tStr, 200))
		}
	}

	tags := make([]string, 0)
	if rawTags, ok := rawProd["tags"].([]any); ok {
		if len(rawTags) > 100 {
			rawTags = rawTags[:100]
		}
		for _, tAny := range rawTags {
			if tm, okM := tAny.(map[string]any); okM {
				if ct := SanitizeCommerceField(jsonScalarToStringCommerce(tm["name"]), 120); ct != "" {
					tags = append(tags, ct)
				}
			}
		}
	}

	images := make([]string, 0)
	if rawImgs, ok := rawProd["images"].([]any); ok {
		seen := make(map[string]bool)
		for _, imgAny := range rawImgs {
			if im, okM := imgAny.(map[string]any); okM {
				cand := im["src"]
				if cand == nil {
					cand = im["url"]
				}
				src := NormalizePublicCommerceImageURL(cand)
				if src != "" && !seen[src] {
					seen[src] = true
					images = append(images, src)
					if len(images) >= maxImages {
						break
					}
				}
			}
		}
	}

	options := make([]CatalogOption, 0)
	if rawAttrs, ok := rawProd["attributes"].([]any); ok {
		if len(rawAttrs) > 50 {
			rawAttrs = rawAttrs[:50]
		}
		for _, aAny := range rawAttrs {
			am, okM := aAny.(map[string]any)
			if !okM {
				continue
			}
			aName := SanitizeCommerceField(jsonScalarToStringCommerce(am["name"]), 120)
			terms := make([]string, 0)
			if rawTerms, okT := am["terms"].([]any); okT {
				if len(rawTerms) > 100 {
					rawTerms = rawTerms[:100]
				}
				for _, trAny := range rawTerms {
					if trm, okTM := trAny.(map[string]any); okTM {
						if tv := SanitizeCommerceField(jsonScalarToStringCommerce(trm["name"]), 120); tv != "" {
							terms = append(terms, tv)
						}
					}
				}
			}
			if aName != "" {
				options = append(options, CatalogOption{Name: aName, Values: terms})
			}
		}
	}

	topSKU := sanitizeCommerceSKU(rawProd["sku"])
	var topAvailable *bool
	if b, ok := rawProd["is_in_stock"].(bool); ok {
		bv := b
		topAvailable = &bv
	}
	var primaryImg *string
	if len(images) > 0 {
		first := images[0]
		primaryImg = &first
	}

	var variants []CatalogVariantRecord
	if rawVars, ok := rawProd["variations"].([]any); ok && len(rawVars) > 0 {
		if len(rawVars) > maxVariants {
			rawVars = rawVars[:maxVariants]
		}
		variants = make([]CatalogVariantRecord, 0, len(rawVars))
		for _, vrAny := range rawVars {
			vr, okM := vrAny.(map[string]any)
			if !okM {
				continue
			}
			vID := jsonScalarToStringCommerce(vr["id"])
			vAttrs := make([]string, 0)
			if aArr, okA := vr["attributes"].([]any); okA {
				for _, atAny := range aArr {
					if atm, okAM := atAny.(map[string]any); okAM {
						if cv := SanitizeCommerceField(jsonScalarToStringCommerce(atm["value"]), 120); cv != "" {
							vAttrs = append(vAttrs, cv)
						}
					}
				}
			}
			vSKU := sanitizeCommerceSKU(vr["sku"])
			if vSKU == nil {
				vSKU = topSKU
			}
			var vTitle *string
			if len(vAttrs) > 0 {
				joined := strings.Join(vAttrs, " / ")
				vTitle = &joined
			}
			vAvail := topAvailable
			if b, okB := vr["is_in_stock"].(bool); okB {
				bv := b
				vAvail = &bv
			}
			variants = append(variants, CatalogVariantRecord{
				VariantID: vID,
				SKU:       vSKU,
				Title:     vTitle,
				Options:   vAttrs,
				Price:     basePrice,
				CompareAt: compareAt,
				Currency:  currency,
				Available: vAvail,
				Image:     primaryImg,
			})
		}
	} else {
		variants = []CatalogVariantRecord{
			{
				VariantID: productID,
				SKU:       topSKU,
				Options:   []string{},
				Price:     basePrice,
				CompareAt: compareAt,
				Currency:  currency,
				Available: topAvailable,
				Image:     primaryImg,
			},
		}
	}

	descHTML := jsonScalarToStringCommerce(rawProd["description"])
	if descHTML == "" {
		descHTML = jsonScalarToStringCommerce(rawProd["short_description"])
	}
	descText := StripTagsInlineCommerce(descHTML)

	pubCand := rawProd["date_created_gmt"]
	if pubCand == nil {
		pubCand = rawProd["date_created"]
	}
	if pubCand == nil {
		pubCand = rawProd["published_at"]
	}
	updCand := rawProd["date_modified_gmt"]
	if updCand == nil {
		updCand = rawProd["date_modified"]
	}
	if updCand == nil {
		updCand = rawProd["updated_at"]
	}
	publishedAt := SanitizeCommerceTimestamp(pubCand, 96)
	updatedAt := SanitizeCommerceTimestamp(updCand, 96)
	lean := opts != nil && opts.Fields == "lean"

	rec := &CatalogRecord{
		Platform:    "woocommerce",
		Origin:      cleanOrigin,
		ProductID:   productID,
		Handle:      handle,
		URL:         prodURL,
		Title:       title,
		Vendor:      vendor,
		ProductType: productType,
		Tags:        tags,
		PublishedAt: publishedAt,
		UpdatedAt:   updatedAt,
		Options:     options,
		Variants:    variants,
	}
	if !lean {
		rec.DescriptionText = strPtrAlways(descText)
		imgsCopy := images
		rec.Images = &imgsCopy
	}
	return rec
}

func formatWooMoneyCell(amount *float64, currency *string) string {
	if amount == nil {
		return "-"
	}
	cur := "USD"
	if currency != nil && *currency != "" {
		cur = *currency
	}
	return fmt.Sprintf("%s %.2f", cur, *amount)
}

func formatWooStockCell(avail *bool) string {
	if avail == nil {
		return "-"
	}
	if *avail {
		return "In Stock"
	}
	return "Out of Stock"
}

// WooEnrichParams configures EnrichWooCommerceProductFromStoreAPI.
type WooEnrichParams struct {
	RawJSON        string `json:"rawJson"`
	ProductURL     string `json:"productUrl"`
	Slug           string `json:"slug"`
	FallbackBodyMD string `json:"fallbackBodyMd,omitempty"`
}

// EnrichWooCommerceProductFromStoreAPI formats a WooCommerce Store API v1 response into a TwinFormattedDoc.
func EnrichWooCommerceProductFromStoreAPI(params WooEnrichParams) *TwinFormattedDoc {
	parsed, ok := parseJSONValueCommerce(params.RawJSON)
	if !ok || parsed == nil {
		return nil
	}
	var candidates []map[string]any
	switch tv := parsed.(type) {
	case []any:
		for _, el := range tv {
			if m, okM := el.(map[string]any); okM {
				candidates = append(candidates, m)
			}
		}
	case map[string]any:
		candidates = []map[string]any{tv}
	}
	if len(candidates) == 0 {
		return nil
	}
	targetSlug := strings.ToLower(params.Slug)
	var matched map[string]any
	for _, c := range candidates {
		if sl, okS := c["slug"].(string); okS && strings.ToLower(strings.TrimSpace(sl)) == targetSlug {
			matched = c
			break
		}
	}
	if matched == nil && len(candidates) == 1 {
		matched = candidates[0]
	}
	if matched == nil {
		return nil
	}
	rec := NormalizeWooCommerceProductRecord(matched, params.ProductURL, nil)
	if rec == nil {
		return nil
	}

	descHTML, _ := matched["description"].(string)
	apiBodyMD := ""
	if descHTML != "" {
		apiBodyMD = strings.TrimSpace(stripNonPublicMarkdownImages(ConvertCommerceHTMLFragmentToMD(descHTML, params.ProductURL)))
	}
	cleanedFallback := strings.TrimSpace(stripNonPublicMarkdownImages(reLeadingMarkdownH1.ReplaceAllString(params.FallbackBodyMD, "")))
	bodyMD := apiBodyMD
	if len(apiBodyMD) < 80 && cleanedFallback != "" {
		bodyMD = cleanedFallback
	}

	var metaLines []string
	if rec.Vendor != nil && *rec.Vendor != "" {
		metaLines = append(metaLines, "- **Brand / Vendor**: "+*rec.Vendor)
	}
	if rec.ProductType != nil && *rec.ProductType != "" {
		metaLines = append(metaLines, "- **Category**: "+*rec.ProductType)
	}
	if len(rec.Tags) > 0 {
		metaLines = append(metaLines, "- **Tags**: "+strings.Join(rec.Tags, ", "))
	}

	rows := make([][]string, 0, len(rec.Variants))
	for _, v := range rec.Variants {
		vt := rec.Title
		if v.Title != nil && *v.Title != "" {
			vt = *v.Title
		}
		rows = append(rows, []string{
			vt,
			formatCommerceSKUDisplay(v.SKU, false),
			formatWooMoneyCell(v.Price, v.Currency),
			formatWooMoneyCell(v.CompareAt, v.Currency),
			formatWooStockCell(v.Available),
		})
	}

	sections := []string{"# " + rec.Title}
	if len(metaLines) > 0 {
		sections = append(sections, strings.Join(metaLines, "\n"))
	}
	sections = append(sections, "## Variants & Pricing\n\n"+FormatGFMTable([]string{"Variant", "SKU", "Price", "Compare At", "Stock"}, rows))
	if bodyMD != "" {
		sections = append(sections, "## Product Details\n\n"+bodyMD)
	}

	doc := &TwinFormattedDoc{
		Title:    rec.Title,
		Markdown: strings.Join(sections, "\n\n"),
		Links:    []string{rec.URL},
		Records:  []CatalogRecord{*rec},
	}
	if rec.DescriptionText != nil && *rec.DescriptionText != "" {
		doc.Description = sliceUTF16Safe(*rec.DescriptionText, 260)
	}
	if rec.Vendor != nil && *rec.Vendor != "" {
		doc.Author = *rec.Vendor
	}
	if rec.PublishedAt != nil && *rec.PublishedAt != "" {
		doc.PublishedTime = *rec.PublishedAt
	}
	return doc
}

// FormatWCStoreAPIListTwin formats a `/wp-json/wc/store/v1/products` list response into a TwinFormattedDoc.
func FormatWCStoreAPIListTwin(rawBody, origURL string) *TwinFormattedDoc {
	return FormatWCStoreAPIListTwinWithOptions(rawBody, origURL, "")
}

// FormatWCStoreAPIListTwinWithOptions formats a `/wp-json/wc/store/v1/products` list response into a TwinFormattedDoc,
// reading `per_page`, `page`, and `NextURL` base from `twinURL` when provided (so custom-domain HTML URLs get accurate pagination).
func FormatWCStoreAPIListTwinWithOptions(rawBody, origURL, twinURL string) *TwinFormattedDoc {
	parsed, ok := parseJSONValueCommerce(rawBody)
	if !ok {
		return nil
	}
	arr, isArr := parsed.([]any)
	if !isArr {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(origURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	queryURL := u
	if strings.TrimSpace(twinURL) != "" {
		if tu, errT := url.Parse(strings.TrimSpace(twinURL)); errT == nil && tu.Scheme != "" && tu.Host != "" {
			queryURL = tu
		}
	}
	q := queryURL.Query()
	page := 1
	if p, errP := strconv.Atoi(q.Get("page")); errP == nil && p > 1 {
		page = p
	}
	perPage := 100
	if pp, errPP := strconv.Atoi(q.Get("per_page")); errPP == nil && pp >= 1 {
		perPage = pp
	}

	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	records := make([]CatalogRecord, 0, len(arr))
	for _, itemAny := range arr {
		if item, okM := itemAny.(map[string]any); okM {
			if norm := NormalizeWooCommerceProductRecord(item, origin, nil); norm != nil {
				records = append(records, *norm)
			}
		}
	}
	if tTwin := strings.TrimSpace(twinURL); tTwin != "" && tTwin != strings.TrimSpace(origURL) && len(records) == 0 {
		// Fail open cleanly to HTML when custom-domain Store API category/shop returns an empty array.
		return nil
	}

	returned := len(records)
	hasMore := returned > 0 && returned >= perPage
	nextURL := ""
	if hasMore {
		nextU := *queryURL
		nq := nextU.Query()
		nq.Set("page", strconv.Itoa(page+1))
		nextU.RawQuery = nq.Encode()
		nextURL = nextU.String()
	}

	title := fmt.Sprintf("%s — WooCommerce Catalog (Page %d, %d products)", strings.ToLower(u.Hostname()), page, returned)
	rowCap := len(records)
	if rowCap > 120 {
		rowCap = 120
	}
	links := make([]string, 0, rowCap)
	rows := make([][]string, 0, rowCap)
	for i := 0; i < rowCap; i++ {
		r := records[i]
		links = append(links, r.URL)
		var v0 *CatalogVariantRecord
		if len(r.Variants) > 0 {
			v0 = &r.Variants[0]
		}
		var sku *string
		var price *float64
		var cur *string
		var avail *bool
		if v0 != nil {
			sku = v0.SKU
			price = v0.Price
			cur = v0.Currency
			avail = v0.Available
		}
		catCell := "-"
		if r.ProductType != nil && *r.ProductType != "" {
			catCell = *r.ProductType
		}
		rows = append(rows, []string{
			FormatMarkdownLinkCommerce(r.Title, r.URL),
			formatCommerceSKUDisplay(sku, false),
			catCell,
			formatWooMoneyCell(price, cur),
			formatWooStockCell(avail),
		})
	}
	tableMD := "No products returned on this page."
	if len(rows) > 0 {
		tableMD = FormatGFMTable([]string{"Product", "SKU", "Category", "Price", "Stock"}, rows)
	}
	return &TwinFormattedDoc{
		Title:    title,
		Markdown: "# " + title + "\n\n" + tableMD,
		Links:    links,
		Records:  records,
		Pagination: &PaginationInfo{
			Page:     page,
			Returned: returned,
			Limit:    perPage,
			HasMore:  hasMore,
			NextURL:  nextURL,
		},
	}
}

// FormatWCStoreAPIProductTwin formats a single `/wp-json/wc/store/v1/products/<id>` object into a TwinFormattedDoc.
func FormatWCStoreAPIProductTwin(rawBody, origURL string) *TwinFormattedDoc {
	obj, ok := parseJSONObjectCommerce(rawBody)
	if !ok {
		return nil
	}
	rec := NormalizeWooCommerceProductRecord(obj, origURL, nil)
	if rec == nil {
		return nil
	}
	descHTML, _ := obj["description"].(string)
	bodyMD := ""
	if descHTML != "" {
		bodyMD = strings.TrimSpace(stripNonPublicMarkdownImages(ConvertCommerceHTMLFragmentToMD(descHTML, origURL)))
	}
	rows := make([][]string, 0, len(rec.Variants))
	for _, v := range rec.Variants {
		vt := rec.Title
		if v.Title != nil && *v.Title != "" {
			vt = *v.Title
		}
		rows = append(rows, []string{
			vt,
			formatCommerceSKUDisplay(v.SKU, false),
			formatWooMoneyCell(v.Price, v.Currency),
			formatWooStockCell(v.Available),
		})
	}
	sections := []string{
		"# " + rec.Title,
		FormatGFMTable([]string{"Variant", "SKU", "Price", "Stock"}, rows),
	}
	if bodyMD != "" {
		sections = append(sections, "## Description\n\n"+bodyMD)
	}
	doc := &TwinFormattedDoc{
		Title:    rec.Title,
		Markdown: strings.Join(sections, "\n\n"),
		Links:    []string{rec.URL},
		Records:  []CatalogRecord{*rec},
	}
	if rec.DescriptionText != nil && *rec.DescriptionText != "" {
		doc.Description = sliceUTF16Safe(*rec.DescriptionText, 260)
	}
	if rec.Vendor != nil && *rec.Vendor != "" {
		doc.Author = *rec.Vendor
	}
	if rec.PublishedAt != nil && *rec.PublishedAt != "" {
		doc.PublishedTime = *rec.PublishedAt
	}
	return doc
}
