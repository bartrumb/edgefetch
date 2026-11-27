package catalog

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

var (
	reShopifyPoweredBy     = newLazyRegexp(`(?i)\bshopify\b`)
	reMyShopifyDomain      = newLazyRegexp(`(?i)[a-z0-9-]\.myshopify\.com\b`)
	reShopifyShopAssign    = newLazyRegexp(`Shopify\.shop\s*=`)
	reShopifyActiveCurr    = newLazyRegexp(`Shopify\.currency\s*=\s*\{[^}]{0,240}?"active"\s*:\s*"([A-Z]{3})"`)
	reShopifyJSONLDCurr    = newLazyRegexp(`(?i)"priceCurrency"\s*:\s*"([A-Z]{3})"`)
	reShopifyHandleSafe    = newLazyRegexp(`^[A-Za-z0-9_-]{1,160}$`)
	reShopifyDefaultTitle  = newLazyRegexp(`(?i)^default(?:\s+title)?$`)
	reShopifyCollectionURL = newLazyRegexp(`(?i)^/collections/([^/]+)/products\.json$`)
	reShopifyColPath       = newLazyRegexp(`(?i)^/collections/([A-Za-z0-9_-]+)`)
	reShopifyProductPath   = newLazyRegexp(`(?i)/products/[^/]+`)
	reShopifyDatePrefix    = newLazyRegexp(`^\d{4}-\d{2}-\d{2}`)
	reShopifyAvailTrue     = newLazyRegexp(`(?i)InStock|PreOrder|BackOrder|OnlineOnly`)
	reShopifyAvailFalse    = newLazyRegexp(`(?i)OutOfStock|SoldOut|Discontinued`)
	reShopifyPreorder      = newLazyRegexp(`(?i)PreOrder|BackOrder`)
	reCatalogLocaleSeg     = newLazyRegexp(`(?i)^[a-z]{2}(?:-[a-z]{2})?$`)
)

// IsShopifyHTMLOrHeaders detects Shopify storefronts from HTTP response headers or HTML markers.
func IsShopifyHTMLOrHeaders(rawHTML string, headers map[string]string) bool {
	if len(headers) > 0 {
		if readHeaderCaseInsensitive(headers, "x-shopid") != "" ||
			readHeaderCaseInsensitive(headers, "x-shopify-stage") != "" ||
			readHeaderCaseInsensitive(headers, "x-sorting-hat-shopid") != "" {
			return true
		}
		powered := readHeaderCaseInsensitive(headers, "powered-by")
		if powered == "" {
			powered = readHeaderCaseInsensitive(headers, "x-powered-by")
		}
		if powered != "" && reShopifyPoweredBy.MatchString(powered) {
			return true
		}
	}
	if rawHTML == "" {
		return false
	}
	headSlice := rawHTML
	if len(headSlice) > 120_000 {
		headSlice = headSlice[:120_000]
	}
	return reMyShopifyDomain.MatchString(headSlice) ||
		strings.Contains(headSlice, "cdn.shopify.com") ||
		reShopifyShopAssign.MatchString(headSlice) ||
		strings.Contains(headSlice, "shopify-digital-wallet") ||
		strings.Contains(headSlice, "ShopifyAnalytics") ||
		strings.Contains(headSlice, "shopify-section")
}

// ExtractShopifyCurrencyFromHTML extracts a 3-letter ISO currency code from Shopify HTML globals, OpenGraph meta, or JSON-LD.
func ExtractShopifyCurrencyFromHTML(rawHTML string) string {
	if rawHTML == "" {
		return ""
	}
	slice := rawHTML
	if len(slice) > 120_000 {
		slice = slice[:120_000]
	}
	if m := reShopifyActiveCurr.FindStringSubmatch(slice); len(m) == 2 {
		return strings.ToUpper(m[1])
	}
	doc := extract.ParseHTMLDoc(slice, 80_000)
	for _, prop := range []string{"og:price:currency", "product:price:currency"} {
		if metaNode := doc.First(`meta[property="` + prop + `"]`); metaNode != nil {
			cand := strings.ToUpper(strings.TrimSpace(metaNode.AttrOrEmpty("content")))
			if reISOCurrency3.MatchString(cand) {
				return cand
			}
		}
		if metaNode := doc.First(`meta[name="` + prop + `"]`); metaNode != nil {
			cand := strings.ToUpper(strings.TrimSpace(metaNode.AttrOrEmpty("content")))
			if reISOCurrency3.MatchString(cand) {
				return cand
			}
		}
	}
	if m := reShopifyJSONLDCurr.FindStringSubmatch(slice); len(m) == 2 {
		return strings.ToUpper(m[1])
	}
	return ""
}

// ShopifyProductTwinURLs holds resolved `.json` and `.js` twin URLs for a custom-domain Shopify product page.
type ShopifyProductTwinURLs struct {
	JSONURL string `json:"jsonUrl"`
	JSURL   string `json:"jsUrl"`
	Handle  string `json:"handle"`
}

// ResolveCustomDomainShopifyProductTwinURL resolves `/products/<handle>` URLs to `.json` and `.js` twin endpoints.
func ResolveCustomDomainShopifyProductTwinURL(productURL string) *ShopifyProductTwinURLs {
	host, rawPath, ok := parseHTTPSHostAndRawPath(productURL)
	if !ok {
		return nil
	}
	var nonEmpty []string
	for _, seg := range strings.Split(rawPath, "/") {
		if seg != "" {
			nonEmpty = append(nonEmpty, seg)
		}
	}
	prodIdx := -1
	for i, seg := range nonEmpty {
		if seg == "products" {
			prodIdx = i
			break
		}
	}
	if prodIdx < 0 || prodIdx+1 >= len(nonEmpty) {
		return nil
	}
	rawSeg, ok := SafeDecodeURIComponent(nonEmpty[prodIdx+1])
	if !ok || rawSeg == "" {
		return nil
	}
	handle := rawSeg
	lowH := strings.ToLower(handle)
	if strings.HasSuffix(lowH, ".json") {
		handle = handle[:len(handle)-5]
	} else if strings.HasSuffix(lowH, ".js") {
		handle = handle[:len(handle)-3]
	}
	if !reShopifyHandleSafe.MatchString(handle) {
		return nil
	}
	origin := "https://" + host
	enc := EncodeURIComponent(handle)
	return &ShopifyProductTwinURLs{
		JSONURL: origin + "/products/" + enc + ".json",
		JSURL:   origin + "/products/" + enc + ".js",
		Handle:  handle,
	}
}

// ShopifyCollectionTwinURL holds the resolved `/collections/<handle>/products.json?limit=50` twin URL.
type ShopifyCollectionTwinURL struct {
	JSONURL string `json:"jsonUrl"`
	Handle  string `json:"handle"`
}

// ResolveCustomDomainShopifyCollectionTwinURL resolves `/collections/<handle>` URLs (with optional leading locale)
// to `/collections/<handle>/products.json?limit=50`, rejecting product sub-routes (`/collections/<col>/products/<prod>`).
func ResolveCustomDomainShopifyCollectionTwinURL(pageURL string) *ShopifyCollectionTwinURL {
	host, rawPath, ok := parseHTTPSHostAndRawPath(pageURL)
	if !ok {
		return nil
	}
	var nonEmpty []string
	for _, seg := range strings.Split(rawPath, "/") {
		if seg != "" {
			nonEmpty = append(nonEmpty, seg)
		}
	}
	if len(nonEmpty) > 0 && reCatalogLocaleSeg.MatchString(nonEmpty[0]) {
		nonEmpty = nonEmpty[1:]
	}
	// Match /collections/<handle> or /collections/<handle>/products (without product handle).
	if len(nonEmpty) < 2 || len(nonEmpty) > 3 || !strings.EqualFold(nonEmpty[0], "collections") {
		return nil
	}
	if len(nonEmpty) == 3 && !strings.EqualFold(nonEmpty[2], "products") {
		return nil
	}
	rawSeg, okDec := SafeDecodeURIComponent(nonEmpty[1])
	if !okDec || rawSeg == "" {
		return nil
	}
	if strings.HasSuffix(strings.ToLower(rawSeg), ".json") || strings.HasSuffix(strings.ToLower(rawSeg), ".js") {
		return nil
	}
	if !reShopifyHandleSafe.MatchString(rawSeg) {
		return nil
	}
	origin := "https://" + host
	enc := EncodeURIComponent(rawSeg)
	return &ShopifyCollectionTwinURL{
		JSONURL: origin + "/collections/" + enc + "/products.json?limit=50",
		Handle:  rawSeg,
	}
}

func parseShopifyMoney(raw any, isAjaxJS bool) (*float64, bool) {
	if raw == nil || raw == "" {
		return nil, false
	}
	if isRawJSONNumberCommerce(raw) {
		f, ok := jsonNumberToFloatCommerce(raw)
		if !ok || f < 0 {
			return nil, false
		}
		val := f
		if isAjaxJS {
			val = math.Round(f) / 100.0
		}
		return &val, true
	}
	if s, isStr := raw.(string); isStr {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			return nil, false
		}
		if isAjaxJS {
			allDigits := true
			for i := 0; i < len(trimmed); i++ {
				if trimmed[i] < '0' || trimmed[i] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				cents, err := strconv.ParseFloat(trimmed, 64)
				if err == nil && !math.IsNaN(cents) && !math.IsInf(cents, 0) {
					v := math.Round(cents) / 100.0
					return &v, true
				}
				return nil, false
			}
		}
		f, err := strconv.ParseFloat(strings.ReplaceAll(trimmed, ",", ""), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return nil, false
		}
		return &f, true
	}
	return nil, false
}

func cleanVariantTitle(rawTitle any) *string {
	cleaned := SanitizeCommerceField(rawTitle, 240)
	if cleaned == "" || reShopifyDefaultTitle.MatchString(cleaned) {
		return nil
	}
	return &cleaned
}

// ShopifyNormalizeOptions configures NormalizeShopifyProductRecord.
type ShopifyNormalizeOptions struct {
	Currency         string                    `json:"currency,omitempty"`
	Fields           string                    `json:"fields,omitempty"`
	IsAjaxJS         *bool                     `json:"isAjaxJs,omitempty"`
	AjaxVariantsByID map[string]map[string]any `json:"ajaxVariantsById,omitempty"`
	MaxImages        int                       `json:"maxImages,omitempty"`
	MaxVariants      int                       `json:"maxVariants,omitempty"`
}

func clampProductBound(v, def int) int {
	if v <= 0 {
		v = def
	}
	if v < 1 {
		return 1
	}
	if v > 250 {
		return 250
	}
	return v
}

// NormalizeShopifyProductRecord normalizes a raw Shopify product JSON object into a neutral CatalogRecord.
func NormalizeShopifyProductRecord(rawProd map[string]any, originStr string, opts *ShopifyNormalizeOptions) *CatalogRecord {
	if rawProd == nil {
		return nil
	}
	title := SanitizeCommerceField(rawProd["title"], 400)
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

	isAjaxJS := false
	if opts != nil && opts.IsAjaxJS != nil {
		isAjaxJS = *opts.IsAjaxJS
	} else {
		isAjaxJS = isRawJSONNumberCommerce(rawProd["price"])
		if !isAjaxJS {
			if rawVars, ok := rawProd["variants"].([]any); ok && len(rawVars) > 0 {
				if v0, ok0 := rawVars[0].(map[string]any); ok0 && isRawJSONNumberCommerce(v0["price"]) {
					isAjaxJS = true
				}
			}
		}
	}

	productID := jsonScalarToStringCommerce(rawProd["id"])
	handle := ""
	if h, ok := rawProd["handle"].(string); ok {
		handle = strings.TrimSpace(h)
	}
	prodURL := cleanOrigin
	if handle != "" {
		prodURL = cleanOrigin + "/products/" + EncodeURIComponent(handle)
	}

	vendor := strPtrOrNil(SanitizeCommerceField(rawProd["vendor"], 200))
	rawType, _ := rawProd["product_type"].(string)
	if rawType == "" {
		rawType, _ = rawProd["type"].(string)
	}
	productType := strPtrOrNil(SanitizeCommerceField(rawType, 200))

	tags := make([]string, 0)
	switch tv := rawProd["tags"].(type) {
	case []any:
		for _, el := range tv {
			if c := SanitizeCommerceField(jsonScalarToStringCommerce(el), 120); c != "" {
				tags = append(tags, c)
			}
		}
	case string:
		for _, tok := range strings.Split(tv, ",") {
			if c := SanitizeCommerceField(tok, 120); c != "" {
				tags = append(tags, c)
			}
		}
	}

	imageByID := make(map[string]string)
	imageByVariantID := make(map[string]string)
	allImageURLs := make([]string, 0)
	seenImageURLs := make(map[string]bool)
	if rawImages, ok := rawProd["images"].([]any); ok {
		for _, img := range rawImages {
			switch iv := img.(type) {
			case string:
				u := NormalizePublicCommerceImageURL(iv)
				if u != "" && !seenImageURLs[u] && len(allImageURLs) < maxImages {
					seenImageURLs[u] = true
					allImageURLs = append(allImageURLs, u)
				}
			case map[string]any:
				cand := iv["src"]
				if cand == nil {
					cand = iv["url"]
				}
				u := NormalizePublicCommerceImageURL(cand)
				if u == "" {
					continue
				}
				if !seenImageURLs[u] && len(allImageURLs) < maxImages {
					seenImageURLs[u] = true
					allImageURLs = append(allImageURLs, u)
				}
				if idStr := jsonScalarToStringCommerce(iv["id"]); idStr != "" && len(imageByID) < maxImages*4 {
					imageByID[idStr] = u
				}
				if vIDs, okV := iv["variant_ids"].([]any); okV {
					for _, vid := range vIDs {
						if vidStr := jsonScalarToStringCommerce(vid); vidStr != "" && len(imageByVariantID) < maxVariants*4 {
							imageByVariantID[vidStr] = u
						}
					}
				}
			}
			if len(allImageURLs) >= maxImages && len(imageByID) >= maxImages*4 {
				break
			}
		}
	}

	options := make([]CatalogOption, 0)
	if rawOpts, ok := rawProd["options"].([]any); ok {
		for _, opt := range rawOpts {
			switch ov := opt.(type) {
			case string:
				cleanOpt := SanitizeCommerceField(ov, 120)
				if cleanOpt != "" && !strings.EqualFold(cleanOpt, "title") {
					options = append(options, CatalogOption{Name: cleanOpt, Values: []string{}})
				}
			case map[string]any:
				oName := SanitizeCommerceField(ov["name"], 120)
				vals := make([]string, 0)
				if vArr, okA := ov["values"].([]any); okA {
					for _, rv := range vArr {
						cv := SanitizeCommerceField(jsonScalarToStringCommerce(rv), 120)
						if cv != "" && !strings.EqualFold(cv, "default title") {
							vals = append(vals, cv)
						}
					}
				}
				if oName != "" && !(strings.EqualFold(oName, "title") && len(vals) == 0) {
					options = append(options, CatalogOption{Name: oName, Values: vals})
				}
			}
		}
	}

	var currencyPtr *string
	if opts != nil {
		curUp := strings.ToUpper(strings.TrimSpace(opts.Currency))
		if reISOCurrency3.MatchString(curUp) {
			currencyPtr = &curUp
		}
	}

	variants := make([]CatalogVariantRecord, 0)
	if rawVars, ok := rawProd["variants"].([]any); ok {
		if len(rawVars) > maxVariants {
			rawVars = rawVars[:maxVariants]
		}
		for _, rvAny := range rawVars {
			rv, okM := rvAny.(map[string]any)
			if !okM {
				continue
			}
			variantID := jsonScalarToStringCommerce(rv["id"])
			var ajaxV map[string]any
			if variantID != "" && opts != nil && opts.AjaxVariantsByID != nil {
				ajaxV = opts.AjaxVariantsByID[variantID]
			}
			merged := rv
			if ajaxV != nil {
				merged = make(map[string]any, len(ajaxV)+len(rv))
				for k, v := range ajaxV {
					merged[k] = v
				}
				for k, v := range rv {
					if v != nil {
						merged[k] = v
					}
				}
			}

			sku := sanitizeCommerceSKU(merged["sku"])
			barcode := sanitizeCommerceSKU(merged["barcode"])
			vTitle := cleanVariantTitle(merged["title"])

			optValues := make([]string, 0)
			if oArr, okO := merged["options"].([]any); okO {
				for _, o := range oArr {
					co := SanitizeCommerceField(jsonScalarToStringCommerce(o), 120)
					if co != "" && !strings.EqualFold(co, "default title") {
						optValues = append(optValues, co)
					}
				}
			} else {
				for _, okKey := range []string{"option1", "option2", "option3"} {
					co := SanitizeCommerceField(merged[okKey], 120)
					if co != "" && !strings.EqualFold(co, "default title") {
						optValues = append(optValues, co)
					}
				}
			}

			price, _ := parseShopifyMoney(merged["price"], isAjaxJS)
			var compareAt *float64
			if rawComp, okC := parseShopifyMoney(merged["compare_at_price"], isAjaxJS); okC && rawComp != nil && *rawComp > 0 {
				compareAt = rawComp
			}

			var available *bool
			if b, isB := merged["available"].(bool); isB {
				bv := b
				available = &bv
			} else if ajaxV != nil {
				if b, isB := ajaxV["available"].(bool); isB {
					bv := b
					available = &bv
				}
			}

			var invPolicy *string
			if pol, isS := merged["inventory_policy"].(string); isS && (pol == "continue" || pol == "deny") {
				pv := pol
				invPolicy = &pv
			}

			var invQty *int
			if qf, okQ := jsonNumberToFloatCommerce(merged["inventory_quantity"]); okQ && isRawJSONNumberCommerce(merged["inventory_quantity"]) {
				qi := int(math.Trunc(qf))
				invQty = &qi
			}

			var grams *int
			if gf, okG := jsonNumberToFloatCommerce(merged["grams"]); okG && isRawJSONNumberCommerce(merged["grams"]) {
				gi := int(math.Round(gf))
				grams = &gi
			}

			var imgStr string
			switch fi := merged["featured_image"].(type) {
			case string:
				imgStr = NormalizePublicCommerceImageURL(fi)
			case map[string]any:
				cand := fi["src"]
				if cand == nil {
					cand = fi["url"]
				}
				imgStr = NormalizePublicCommerceImageURL(cand)
			}
			if imgStr == "" {
				if imgID := jsonScalarToStringCommerce(merged["image_id"]); imgID != "" {
					imgStr = imageByID[imgID]
				}
			}
			if imgStr == "" && variantID != "" {
				imgStr = imageByVariantID[variantID]
			}

			var curCopy *string
			if currencyPtr != nil {
				c := *currencyPtr
				curCopy = &c
			}

			variants = append(variants, CatalogVariantRecord{
				VariantID:         variantID,
				SKU:               sku,
				Barcode:           barcode,
				Title:             vTitle,
				Options:           optValues,
				Price:             price,
				CompareAt:         compareAt,
				Currency:          curCopy,
				Available:         available,
				InventoryPolicy:   invPolicy,
				InventoryQuantity: invQty,
				Grams:             grams,
				Image:             strPtrOrNil(imgStr),
			})
		}
	}

	bodyHTML, _ := rawProd["body_html"].(string)
	if bodyHTML == "" {
		bodyHTML, _ = rawProd["description"].(string)
	}
	descText := StripTagsInlineCommerce(bodyHTML)
	publishedAt := SanitizeCommerceTimestamp(rawProd["published_at"], 96)
	updatedAt := SanitizeCommerceTimestamp(rawProd["updated_at"], 96)
	lean := opts != nil && opts.Fields == "lean"

	rec := &CatalogRecord{
		Platform:    "shopify",
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
		imgsCopy := allImageURLs
		rec.Images = &imgsCopy
	}
	return rec
}

func formatMoneyDisplay(amount *float64, currency *string) string {
	if amount == nil || math.IsNaN(*amount) || math.IsInf(*amount, 0) {
		return "-"
	}
	fixed := fmt.Sprintf("%.2f", *amount)
	cur := ""
	if currency != nil {
		cur = *currency
	}
	if cur == "" || cur == "USD" {
		return "$" + fixed
	}
	return cur + " " + fixed
}

func formatVariantAvailability(v CatalogVariantRecord) string {
	if v.Available == nil {
		return "-"
	}
	if !*v.Available {
		return "Out of Stock"
	}
	if v.InventoryPolicy != nil && *v.InventoryPolicy == "continue" && v.InventoryQuantity != nil && *v.InventoryQuantity <= 0 {
		return "Backorder / Preorder"
	}
	return "Available"
}

// ShopifyEnrichParams configures EnrichShopifyProductFromJSON.
type ShopifyEnrichParams struct {
	RawJSON    string `json:"rawJson"`
	ProductURL string `json:"productUrl"`
	Currency   string `json:"currency,omitempty"`
	IsAjaxJS   *bool  `json:"isAjaxJs,omitempty"`
	AjaxJSBody string `json:"ajaxJsBody,omitempty"`
}

// EnrichShopifyProductFromJSON formats a single-product Shopify `.json` or `.js` payload into a TwinFormattedDoc.
func EnrichShopifyProductFromJSON(params ShopifyEnrichParams) *TwinFormattedDoc {
	data, ok := parseJSONObjectCommerce(params.RawJSON)
	if !ok {
		return nil
	}
	prod := data
	if sub, okSub := data["product"].(map[string]any); okSub {
		prod = sub
	}
	rawTitle, isStr := prod["title"].(string)
	if !isStr || strings.TrimSpace(rawTitle) == "" {
		return nil
	}

	var ajaxVariantsByID map[string]map[string]any
	if params.AjaxJSBody != "" {
		if ajaxObj, okA := parseJSONObjectCommerce(params.AjaxJSBody); okA {
			if arr, okV := ajaxObj["variants"].([]any); okV {
				ajaxVariantsByID = make(map[string]map[string]any, len(arr))
				for _, avAny := range arr {
					if av, okM := avAny.(map[string]any); okM && av["id"] != nil {
						ajaxVariantsByID[jsonScalarToStringCommerce(av["id"])] = av
					}
				}
			}
		}
	}

	record := NormalizeShopifyProductRecord(prod, params.ProductURL, &ShopifyNormalizeOptions{
		Currency:         params.Currency,
		IsAjaxJS:         params.IsAjaxJS,
		AjaxVariantsByID: ajaxVariantsByID,
	})
	if record == nil {
		return nil
	}

	bodyHTML, _ := prod["body_html"].(string)
	if bodyHTML == "" {
		bodyHTML, _ = prod["description"].(string)
	}
	rawBodyMD := ConvertCommerceHTMLFragmentToMD(bodyHTML, params.ProductURL)
	bodyMD := strings.TrimSpace(stripNonPublicMarkdownImages(rawBodyMD))

	rowCap := len(record.Variants)
	if rowCap > 60 {
		rowCap = 60
	}
	rows := make([][]string, 0, rowCap)
	for i := 0; i < rowCap; i++ {
		v := record.Variants[i]
		vt := record.Title
		if v.Title != nil && *v.Title != "" {
			vt = *v.Title
		}
		compCell := "-"
		if v.CompareAt != nil {
			compCell = formatMoneyDisplay(v.CompareAt, v.Currency)
		}
		rows = append(rows, []string{
			vt,
			formatCommerceSKUDisplay(v.SKU, false),
			formatMoneyDisplay(v.Price, v.Currency),
			compCell,
			formatVariantAvailability(v),
		})
	}

	activeCur := ""
	if len(record.Variants) > 0 && record.Variants[0].Currency != nil {
		activeCur = *record.Variants[0].Currency
	} else if params.Currency != "" {
		activeCur = params.Currency
	}
	var bullets []string
	if record.Vendor != nil && *record.Vendor != "" {
		bullets = append(bullets, "- **Brand / Vendor**: "+*record.Vendor)
	}
	if record.ProductType != nil && *record.ProductType != "" {
		bullets = append(bullets, "- **Product Type**: "+*record.ProductType)
	}
	if len(record.Tags) > 0 {
		bullets = append(bullets, "- **Tags**: "+strings.Join(record.Tags, ", "))
	}
	if activeCur != "" {
		bullets = append(bullets, "- **Currency**: "+activeCur)
	}

	sections := []string{"# " + record.Title}
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	if len(rows) > 0 {
		sections = append(sections, "## Variants & Pricing\n\n"+FormatGFMTable([]string{"Variant", "SKU", "Price", "Compare At", "Availability"}, rows))
	}
	if bodyMD != "" {
		sections = append(sections, "## Product Details\n\n"+bodyMD)
	}

	doc := &TwinFormattedDoc{
		Title:    record.Title,
		Markdown: strings.Join(sections, "\n\n"),
		Links:    []string{record.URL},
		Records:  []CatalogRecord{*record},
	}
	if record.DescriptionText != nil && *record.DescriptionText != "" {
		doc.Description = sliceUTF16Safe(*record.DescriptionText, 260)
	}
	if record.Vendor != nil && *record.Vendor != "" {
		doc.Author = *record.Vendor
	}
	if record.PublishedAt != nil && *record.PublishedAt != "" {
		doc.PublishedTime = *record.PublishedAt
	}
	return doc
}
