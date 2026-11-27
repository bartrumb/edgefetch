package catalog

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

var (
	reSFCCSitePattern      = newLazyRegexp(`Sites-([A-Za-z0-9_-]{2,64})-Site`)
	reSFCCVariationURL     = newLazyRegexp(`(?i)(?:(?:https?:)?//[^\s"'<>]+)?/on/demandware\.store/Sites-[A-Za-z0-9_-]+-Site/[A-Za-z0-9_-]+/Product-Variation\?[^\s"'<>]*pid=[^\s"'<>&]+[^\s"'<>]*`)
	reSFCCDataPID          = newLazyRegexp(`(?i)data-pid=["']([A-Za-z0-9_.-]{1,100})["']`)
	reSFCCSiteLocalePath   = newLazyRegexp(`(?i)(?:(?:https?:)?//([^\s"'<>/?#]+)[^\s"'<>?#]*)?/on/demandware\.store/(Sites-[A-Za-z0-9_-]+-Site)/([A-Za-z0-9_-]+)/`)
	reSFCCSpecKeywordCheck = newLazyRegexp(`(?i)\b(?:frame|fork|stack|reach|wheelbase|head\s*tube|seat\s*tube|weight|motor|battery|drivetrain|brakes|wheels|tires|geometry|size|spec|dimensions|material|sku|model)\b`)
)

// SFCCTwinURL holds the resolved same-origin SFCC `Product-Variation` JSON endpoint.
type SFCCTwinURL struct {
	VariationURL string `json:"variationUrl"`
	PID          string `json:"pid"`
}

// SFCCSpecTable represents an extracted HTML specification or geometry table.
type SFCCSpecTable struct {
	Heading string
	Headers []string
	Rows    [][]string
}

// IsSFCCDemandwareHTMLOrHeaders detects Salesforce Commerce Cloud (Demandware) storefronts
// strictly via structural HTTP headers and HTML/URL markers (never via hardcoded brand lists).
func IsSFCCDemandwareHTMLOrHeaders(rawHTML string, headers map[string]string) bool {
	if len(headers) > 0 {
		if readHeaderCaseInsensitive(headers, "x-dw-request-base-id") != "" {
			return true
		}
		for k := range headers {
			if strings.HasPrefix(strings.ToLower(k), "x-dw-") {
				return true
			}
		}
	}
	if rawHTML == "" {
		return false
	}
	slice := rawHTML
	if len(slice) > 150_000 {
		slice = slice[:150_000]
	}
	return strings.Contains(slice, "on/demandware.static") ||
		strings.Contains(slice, "/demandware.static/") ||
		strings.Contains(slice, "on/demandware.store") ||
		strings.Contains(slice, "/demandware.store/") ||
		strings.Contains(slice, "Product-Variation") ||
		strings.Contains(slice, "dwvar_") ||
		strings.Contains(slice, "dw.ac") ||
		(strings.Contains(slice, "Sites-") && reSFCCSitePattern.MatchString(slice))
}

// ResolveSFCCProductVariationTwinURL discovers or constructs a strictly same-origin `https://`
// SFCC `Product-Variation` JSON twin URL from HTML markers (`Product-Variation` URL or `Sites-*-Site` + `data-pid`).
func ResolveSFCCProductVariationTwinURL(pageURL, rawHTML string) *SFCCTwinURL {
	baseU, ok := IsSafeHTTPSStoreURL(pageURL, "")
	if !ok || baseU == nil || rawHTML == "" {
		return nil
	}
	baseHost := strings.ToLower(baseU.Hostname())
	scan := rawHTML
	if len(scan) > 512*1024 {
		scan = scan[:512*1024]
	}

	for _, m := range reSFCCVariationURL.FindAllString(scan, 16) {
		cleaned := strings.ReplaceAll(m, "&amp;", "&")
		ref, err := url.Parse(cleaned)
		if err != nil {
			continue
		}
		resolved := baseU.ResolveReference(ref)
		if resolved != nil && strings.EqualFold(resolved.Scheme, "https") &&
			strings.EqualFold(resolved.Hostname(), baseHost) &&
			IsSafePublicHostname(resolved.Hostname(), "") &&
			resolved.User == nil && (resolved.Port() == "" || resolved.Port() == "443") {
			pid := strings.TrimSpace(resolved.Query().Get("pid"))
			if pid != "" {
				resolved.Fragment = ""
				return &SFCCTwinURL{
					VariationURL: resolved.String(),
					PID:          pid,
				}
			}
		}
	}

	// Construct from discovered same-origin or relative Sites-<Site>-Site/<locale> and data-pid if both appear.
	if pidMatch := reSFCCDataPID.FindStringSubmatch(scan); len(pidMatch) == 2 {
		pid := strings.TrimSpace(pidMatch[1])
		if pid != "" {
			for _, siteMatch := range reSFCCSiteLocalePath.FindAllStringSubmatch(scan, 16) {
				if len(siteMatch) != 4 {
					continue
				}
				matchHost := strings.ToLower(strings.TrimSpace(siteMatch[1]))
				if matchHost != "" && matchHost != baseHost && matchHost != baseHost+":443" {
					continue
				}
				siteID := siteMatch[2]
				locale := siteMatch[3]
				return &SFCCTwinURL{
					VariationURL: fmt.Sprintf("https://%s/on/demandware.store/%s/%s/Product-Variation?pid=%s", baseHost, siteID, locale, EncodeURIComponent(pid)),
					PID:          pid,
				}
			}
		}
	}
	return nil
}

// ExtractSFCCGeometryAndSpecTables extracts product specification and geometry `<table>` and `<dl>` structures.
func ExtractSFCCGeometryAndSpecTables(doc *extract.HTMLDoc) []SFCCSpecTable {
	if doc == nil {
		return nil
	}
	var out []SFCCSpecTable
	for idx, tbl := range doc.Select("table", 16) {
		cls := strings.ToLower(tbl.AttrOrEmpty("class") + " " + tbl.AttrOrEmpty("id"))
		isNamedSpec := strings.Contains(cls, "spec") || strings.Contains(cls, "geometry") ||
			strings.Contains(cls, "dimension") || strings.Contains(cls, "attribute") || strings.Contains(cls, "tech")
		rows := tbl.Select("tr", 80)
		if len(rows) == 0 {
			continue
		}
		var headers []string
		var bodyRows [][]string
		for rIdx, tr := range rows {
			ths := tr.Select("th", 20)
			tds := tr.Select("td", 20)
			if rIdx == 0 && len(ths) >= 2 && len(tds) == 0 {
				for _, th := range ths {
					headers = append(headers, SanitizeCommerceField(th.Text(), 120))
				}
				continue
			}
			var cells []string
			for _, th := range ths {
				cells = append(cells, SanitizeCommerceField(th.Text(), 160))
			}
			for _, td := range tds {
				cells = append(cells, SanitizeCommerceField(td.Text(), 160))
			}
			if len(cells) >= 2 {
				bodyRows = append(bodyRows, cells)
			}
		}
		if len(bodyRows) == 0 {
			continue
		}
		if len(headers) == 0 {
			colCount := len(bodyRows[0])
			if colCount == 2 {
				headers = []string{"Attribute", "Value"}
			} else {
				for c := 0; c < colCount; c++ {
					headers = append(headers, fmt.Sprintf("Col %d", c+1))
				}
			}
		}
		// Require either named spec/geometry table or spec keyword match in text
		sampleText := strings.Join(headers, " ")
		if len(bodyRows) > 0 {
			sampleText += " " + strings.Join(bodyRows[0], " ")
		}
		if !isNamedSpec && !reSFCCSpecKeywordCheck.MatchString(sampleText) {
			continue
		}
		heading := "Specifications & Geometry"
		if strings.Contains(cls, "geometry") {
			heading = "Geometry"
		} else if idx > 0 {
			heading = fmt.Sprintf("Specifications (%d)", idx+1)
		}
		out = append(out, SFCCSpecTable{
			Heading: heading,
			Headers: headers,
			Rows:    bodyRows,
		})
	}
	return out
}

// FormatSFCCProductVariationJSON parses an SFCC `Product-Variation` JSON payload, merges any HTML
// geometry/spec tables from `fallbackHTML`, and emits normalized `CatalogRecord` + GFM tables.
func FormatSFCCProductVariationJSON(rawBody, origURL, fallbackHTML, _ string) *TwinFormattedDoc {
	obj, ok := parseJSONObjectCommerce(rawBody)
	if !ok || obj == nil {
		return nil
	}
	prodObj, okP := obj["product"].(map[string]any)
	if !okP {
		prodObj = obj
	}
	title := SanitizeCommerceField(prodObj["productName"], 400)
	if title == "" {
		title = SanitizeCommerceField(prodObj["name"], 400)
	}
	if title == "" {
		return nil
	}

	u, err := url.Parse(strings.TrimSpace(origURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	pid := jsonScalarToStringCommerce(prodObj["id"])
	if pid == "" {
		pid = jsonScalarToStringCommerce(prodObj["masterID"])
	}
	brand := SanitizeCommerceField(prodObj["brand"], 200)
	skuPtr := sanitizeCommerceSKU(firstNonEmptyCommerce(jsonScalarToStringCommerce(prodObj["manufacturerSKU"]), pid))

	var price *float64
	var compareAt *float64
	var cur *string
	if prObj, okPr := prodObj["price"].(map[string]any); okPr {
		if sales, okS := prObj["sales"].(map[string]any); okS {
			if f, okF := jsonNumberToFloatCommerce(sales["value"]); okF && f >= 0 {
				price = &f
			}
			if c, okC := sales["currency"].(string); okC {
				cu := strings.ToUpper(strings.TrimSpace(c))
				if reISOCurrency3.MatchString(cu) {
					cur = &cu
				}
			}
		}
		if list, okL := prObj["list"].(map[string]any); okL {
			if f, okF := jsonNumberToFloatCommerce(list["value"]); okF && price != nil && f > *price {
				compareAt = &f
			}
		}
	}

	avail := parseSFCCAvailability(prodObj)

	imgs := make([]string, 0)
	seenImgs := make(map[string]bool)
	if imgsObj, okI := prodObj["images"].(map[string]any); okI {
		for _, sizeKey := range []string{"hiRes", "large", "medium"} {
			if arr, okA := imgsObj[sizeKey].([]any); okA {
				for _, imAny := range arr {
					if im, okM := imAny.(map[string]any); okM {
						cand := jsonScalarToStringCommerce(im["absURL"])
						if cand == "" {
							cand = jsonScalarToStringCommerce(im["url"])
						}
						if safeU := resolveSafeSameOriginOrPublicHTTPS(cand, u); safeU != "" && !seenImgs[safeU] {
							seenImgs[safeU] = true
							imgs = append(imgs, safeU)
						}
					}
				}
			}
		}
	}

	options := make([]CatalogOption, 0)
	selectedOpts := make([]string, 0)
	if vAttrs, okVA := prodObj["variationAttributes"].([]any); okVA {
		for _, vaAny := range vAttrs {
			va, okM := vaAny.(map[string]any)
			if !okM {
				continue
			}
			attrName := SanitizeCommerceField(firstNonEmptyCommerce(jsonScalarToStringCommerce(va["displayName"]), jsonScalarToStringCommerce(va["attributeId"])), 120)
			vals := make([]string, 0)
			if vArr, okArr := va["values"].([]any); okArr {
				for _, vAny := range vArr {
					if vm, okVM := vAny.(map[string]any); okVM {
						dv := SanitizeCommerceField(firstNonEmptyCommerce(jsonScalarToStringCommerce(vm["displayValue"]), jsonScalarToStringCommerce(vm["value"])), 120)
						if dv != "" {
							vals = append(vals, dv)
							if sel, okSel := vm["selected"].(bool); okSel && sel {
								selectedOpts = append(selectedOpts, dv)
							}
						}
					}
				}
			}
			if attrName != "" && len(vals) > 0 {
				options = append(options, CatalogOption{Name: attrName, Values: vals})
			}
		}
	}

	var vTitle *string
	if len(selectedOpts) > 0 {
		joined := strings.Join(selectedOpts, " / ")
		vTitle = &joined
	}
	var primaryImg *string
	if len(imgs) > 0 {
		u0 := imgs[0]
		primaryImg = &u0
	}

	descHTML := firstNonEmptyCommerce(jsonScalarToStringCommerce(prodObj["longDescription"]), jsonScalarToStringCommerce(prodObj["shortDescription"]))
	bodyMD := ""
	if descHTML != "" {
		bodyMD = strings.TrimSpace(stripNonPublicMarkdownImages(ConvertCommerceHTMLFragmentToMD(descHTML, origURL)))
	}

	rec := CatalogRecord{
		Platform:        "sfcc",
		Origin:          origin,
		ProductID:       pid,
		Handle:          pid,
		URL:             u.String(),
		Title:           title,
		Vendor:          strPtrOrNil(brand),
		Tags:            []string{},
		DescriptionText: strPtrAlways(StripTagsInlineCommerce(descHTML)),
		Images:          &imgs,
		Options:         options,
		Variants: []CatalogVariantRecord{
			{
				VariantID: pid,
				SKU:       skuPtr,
				Title:     vTitle,
				Options:   selectedOpts,
				Price:     price,
				CompareAt: compareAt,
				Currency:  cur,
				Available: avail,
				Image:     primaryImg,
			},
		},
	}

	var bullets []string
	if brand != "" {
		bullets = append(bullets, "- **Brand**: "+brand)
	}
	if skuPtr != nil {
		bullets = append(bullets, "- **SKU**: "+formatCommerceSKUDisplay(skuPtr, true))
	}
	if price != nil {
		bullets = append(bullets, "- **Price**: "+formatGenericMoneyDisplay(price, cur))
	}
	if avail != nil {
		if *avail {
			bullets = append(bullets, "- **Availability**: In Stock")
		} else {
			bullets = append(bullets, "- **Availability**: Out of Stock")
		}
	}
	for _, opt := range options {
		bullets = append(bullets, fmt.Sprintf("- **%s**: %s", opt.Name, strings.Join(opt.Values, ", ")))
	}

	sections := []string{"# " + title}
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	varRowName := title
	if vTitle != nil {
		varRowName = *vTitle
	}
	stockCell := "-"
	if avail != nil {
		if *avail {
			stockCell = "In Stock"
		} else {
			stockCell = "Out of Stock"
		}
	}
	sections = append(sections, "## Variants & Pricing\n\n"+FormatGFMTable(
		[]string{"Variant", "SKU", "Price", "Stock"},
		[][]string{{varRowName, formatCommerceSKUDisplay(skuPtr, false), formatGenericMoneyDisplay(price, cur), stockCell}},
	))

	if fallbackHTML != "" {
		doc := extract.ParseHTMLDoc(fallbackHTML, 2*1024*1024)
		for _, tbl := range ExtractSFCCGeometryAndSpecTables(doc) {
			sections = append(sections, "## "+tbl.Heading+"\n\n"+FormatGFMTable(tbl.Headers, tbl.Rows))
		}
	}
	if bodyMD != "" {
		sections = append(sections, "## Product Details\n\n"+bodyMD)
	}

	return &TwinFormattedDoc{
		Title:       title,
		Author:      brand,
		Description: sliceUTF16Safe(*rec.DescriptionText, 260),
		Markdown:    strings.Join(sections, "\n\n"),
		Links:       []string{u.String()},
		Records:     []CatalogRecord{rec},
	}
}

func parseSFCCAvailabilityText(raw string) (bool, bool) {
	low := strings.ToLower(strings.Join(strings.Fields(raw), " "))
	if low == "" {
		return false, false
	}
	for _, neg := range []string{
		"not in stock", "not-in-stock", "not instock", "not available",
		"no longer available", "out of stock", "out-of-stock", "outofstock",
		"sold out", "unavailable",
	} {
		if strings.Contains(low, neg) {
			return false, true
		}
	}
	if strings.Contains(low, "in stock") || strings.Contains(low, "instock") || low == "available" {
		return true, true
	}
	return false, false
}

func parseSFCCAvailability(prodObj map[string]any) *bool {
	if prodObj == nil {
		return nil
	}
	if b, okB := prodObj["available"].(bool); okB {
		bv := b
		return &bv
	}
	if avRaw, hasAv := prodObj["availability"]; hasAv && avRaw != nil {
		switch av := avRaw.(type) {
		case bool:
			bv := av
			return &bv
		case string:
			if b, ok := parseSFCCAvailabilityText(av); ok {
				bv := b
				return &bv
			}
		case map[string]any:
			if b, okB := av["inStock"].(bool); okB {
				bv := b
				return &bv
			}
			if s, okS := av["inStock"].(string); okS {
				ts := strings.TrimSpace(s)
				if strings.EqualFold(ts, "true") {
					bv := true
					return &bv
				}
				if strings.EqualFold(ts, "false") {
					bv := false
					return &bv
				}
			}
			if b, okB := av["available"].(bool); okB {
				bv := b
				return &bv
			}
			if ats, okA := jsonNumberToFloatCommerce(av["ats"]); okA {
				bv := ats > 0
				return &bv
			}
			if msgs, okM := av["messages"].([]any); okM {
				for _, mAny := range msgs {
					if b, ok := parseSFCCAvailabilityText(jsonScalarToStringCommerce(mAny)); ok {
						bv := b
						return &bv
					}
				}
			}
			if msg := jsonScalarToStringCommerce(av["message"]); msg != "" {
				if b, ok := parseSFCCAvailabilityText(msg); ok {
					bv := b
					return &bv
				}
			}
		}
	}
	if b, okB := prodObj["readyToOrder"].(bool); okB {
		bv := b
		return &bv
	}
	return nil
}

// ExtractSFCCProductHTML extracts SFCC product JSON-LD, `data-pid`, variation options, and
// geometry/specification HTML tables as a zero-network fail-open fallback.
func ExtractSFCCProductHTML(rawURL, rawHTML, _ string, extractorID string) *PostFetchSiteResult {
	if extractorID == "" {
		extractorID = "sfcc-demandware"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !IsSFCCDemandwareHTMLOrHeaders(rawHTML, nil) {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	doc := extract.ParseHTMLDoc(rawHTML, 2*1024*1024)

	prodLD := firstJSONLDProductCommerce(rawHTML)
	specTables := ExtractSFCCGeometryAndSpecTables(doc)

	pid := ""
	if pidNode := doc.First("[data-pid]"); pidNode != nil {
		pid = strings.TrimSpace(pidNode.AttrOrEmpty("data-pid"))
	}
	title := ""
	if prodLD != nil {
		title = SanitizeCommerceField(prodLD["name"], 400)
	}
	if title == "" {
		title = SanitizeCommerceField(doc.Text("h1.product-name, h1.pdp-title, h1"), 400)
	}
	if title == "" || (prodLD == nil && pid == "" && len(specTables) == 0) {
		return nil
	}

	brand := ""
	if prodLD != nil {
		switch b := prodLD["brand"].(type) {
		case string:
			brand = SanitizeCommerceField(b, 200)
		case map[string]any:
			brand = SanitizeCommerceField(b["name"], 200)
		}
	}
	var skuPtr *string
	if prodLD != nil {
		skuPtr = sanitizeCommerceSKU(prodLD["sku"])
	}
	if skuPtr == nil && pid != "" {
		skuPtr = sanitizeCommerceSKU(pid)
	}
	var price *float64
	var cur *string
	var avail *bool
	offers := extractJSONLDOffersList(prodLD)
	if len(offers) > 0 {
		price, cur, avail = parseJSONLDPriceOffer(offers[0])
	}
	if price == nil {
		pText := doc.Text(".prices .sales .value, .price .sales, .product-price")
		price, cur = parseCommercePriceAndCurrency(pText)
	}

	options := make([]CatalogOption, 0)
	for _, attrBox := range doc.Select("[data-attr]", 16) {
		aName := SanitizeCommerceField(attrBox.AttrOrEmpty("data-attr"), 120)
		vals := make([]string, 0)
		for _, vEl := range attrBox.Select("[data-attr-value], option", 40) {
			vt := SanitizeCommerceField(firstNonEmptyCommerce(vEl.Text(), vEl.AttrOrEmpty("data-attr-value")), 120)
			if vt != "" && !strings.EqualFold(vt, "select") {
				vals = append(vals, vt)
			}
		}
		if aName != "" && len(vals) > 0 {
			options = append(options, CatalogOption{Name: aName, Values: vals})
		}
	}

	desc := ""
	if prodLD != nil {
		desc = SanitizeCommerceField(StripTagsInlineCommerce(jsonScalarToStringCommerce(prodLD["description"])), 1200)
	}
	prodID := firstNonEmptyCommerce(pid, jsonScalarToStringCommerce(prodLD["sku"]), title)
	rec := CatalogRecord{
		Platform:        "sfcc",
		Origin:          origin,
		ProductID:       prodID,
		Handle:          prodID,
		URL:             u.String(),
		Title:           title,
		Vendor:          strPtrOrNil(brand),
		Tags:            []string{},
		DescriptionText: strPtrAlways(desc),
		Options:         options,
		Variants: []CatalogVariantRecord{
			{
				VariantID: prodID,
				SKU:       skuPtr,
				Options:   []string{},
				Price:     price,
				Currency:  cur,
				Available: avail,
			},
		},
	}

	var bullets []string
	if brand != "" {
		bullets = append(bullets, "- **Brand**: "+brand)
	}
	if skuPtr != nil {
		bullets = append(bullets, "- **SKU**: "+formatCommerceSKUDisplay(skuPtr, true))
	}
	if price != nil {
		bullets = append(bullets, "- **Price**: "+formatGenericMoneyDisplay(price, cur))
	}
	for _, opt := range options {
		bullets = append(bullets, fmt.Sprintf("- **%s**: %s", opt.Name, strings.Join(opt.Values, ", ")))
	}

	sections := []string{"# " + title}
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	for _, tbl := range specTables {
		sections = append(sections, "## "+tbl.Heading+"\n\n"+FormatGFMTable(tbl.Headers, tbl.Rows))
	}
	if desc != "" {
		sections = append(sections, "## Description\n\n"+desc)
	}
	return &PostFetchSiteResult{
		ExtractorID: extractorID,
		Title:       title,
		Author:      brand,
		Description: sliceUTF16Safe(desc, 260),
		Markdown:    strings.Join(sections, "\n\n"),
		Links:       []string{u.String()},
		Records:     []CatalogRecord{rec},
	}
}
