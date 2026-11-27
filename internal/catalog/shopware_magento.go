package catalog

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

var (
	reMagentoProductID      = newLazyRegexp(`(?i)(?:data-product-id|"productId"|"entity_id")\s*[:=]\s*["']?(\d{1,12})["']?`)
	reMagentoFormProductID1 = newLazyRegexp(`(?i)<input\b[^>]*\bname\s*=\s*["']product["'][^>]*\bvalue\s*=\s*["'](\d{1,12})["']`)
	reMagentoFormProductID2 = newLazyRegexp(`(?i)<input\b[^>]*\bvalue\s*=\s*["'](\d{1,12})["'][^>]*\bname\s*=\s*["']product["']`)
	reMagentoDigitsOnly     = newLazyRegexp(`^\d{1,12}$`)
)

// IsMagento2HTMLOrHeaders detects Magento 2 storefronts strictly via structural HTTP headers or HTML markers.
func IsMagento2HTMLOrHeaders(rawHTML string, headers map[string]string) bool {
	if len(headers) > 0 {
		if readHeaderCaseInsensitive(headers, "x-magento-vary") != "" ||
			readHeaderCaseInsensitive(headers, "x-magento-tags") != "" ||
			readHeaderCaseInsensitive(headers, "x-magento-cache-debug") != "" {
			return true
		}
	}
	if rawHTML == "" {
		return false
	}
	slice := rawHTML
	if len(slice) > 150_000 {
		slice = slice[:150_000]
	}
	return strings.Contains(slice, "text/x-magento-init") ||
		strings.Contains(slice, `data-role="swatch-options"`) ||
		strings.Contains(slice, `data-role='swatch-options'`) ||
		strings.Contains(slice, "Magento_Swatches") ||
		strings.Contains(slice, "Magento_Catalog") ||
		strings.Contains(slice, "mage/cookies") ||
		strings.Contains(slice, "mage/apply/main")
}

// IsShopware6HTMLOrHeaders detects Shopware 6 storefronts strictly via structural HTTP headers or HTML markers.
func IsShopware6HTMLOrHeaders(rawHTML string, headers map[string]string) bool {
	if len(headers) > 0 {
		if readHeaderCaseInsensitive(headers, "sw-context-token") != "" ||
			readHeaderCaseInsensitive(headers, "sw-in-app-url") != "" {
			return true
		}
	}
	if rawHTML == "" {
		return false
	}
	slice := rawHTML
	if len(slice) > 150_000 {
		slice = slice[:150_000]
	}
	return strings.Contains(slice, "sw-product-detail") ||
		strings.Contains(slice, "product-detail-properties-table") ||
		strings.Contains(slice, "product-detail-configurator") ||
		strings.Contains(slice, "frontend.detail.page") ||
		strings.Contains(slice, "/bundles/storefront/")
}

func extractMagentoInitSwatchConfig(rawHTML string) map[string]any {
	pos := 0
	for i := 0; i < 40 && pos < len(rawHTML); i++ {
		idx := strings.Index(rawHTML[pos:], "text/x-magento-init")
		if idx < 0 {
			break
		}
		tagPos := pos + idx
		gtRel := strings.IndexByte(rawHTML[tagPos:], '>')
		if gtRel < 0 {
			break
		}
		bodyStart := tagPos + gtRel + 1
		endRel := strings.Index(strings.ToLower(rawHTML[bodyStart:]), "</script>")
		if endRel < 0 {
			break
		}
		body := strings.TrimSpace(rawHTML[bodyStart : bodyStart+endRel])
		pos = bodyStart + endRel + 9
		if body == "" {
			continue
		}
		obj, ok := parseJSONObjectCommerce(body)
		if !ok {
			continue
		}
		for _, selVal := range obj {
			selMap, okM := selVal.(map[string]any)
			if !okM {
				continue
			}
			for _, modKey := range []string{"Magento_Swatches/js/swatch-renderer", "Magento_ConfigurableProduct/js/configurable"} {
				if modObj, okMod := selMap[modKey].(map[string]any); okMod {
					if jc, okJC := modObj["jsonConfig"].(map[string]any); okJC {
						return jc
					}
					if sc, okSC := modObj["spConfig"].(map[string]any); okSC {
						return sc
					}
				}
			}
		}
	}
	// Fallback: inline spConfig / jsonConfig literal in script
	for _, marker := range []string{`"jsonConfig":`, `"spConfig":`, `spConfig =`, `jsonConfig =`} {
		idx := strings.Index(rawHTML, marker)
		if idx < 0 || idx > 512_000 {
			continue
		}
		tail := rawHTML[idx+len(marker):]
		braceRel := strings.IndexByte(tail, '{')
		if braceRel < 0 || braceRel > 32 {
			continue
		}
		rawJSON, _, ok := extract.ExtractBalancedJSONAt(tail, braceRel, 256*1024)
		if !ok {
			continue
		}
		if obj, okO := parseJSONObjectCommerce(rawJSON); okO && obj["attributes"] != nil {
			return obj
		}
	}
	return nil
}

func extractSpecTableRowsBySelector(doc *extract.HTMLDoc, sel string) [][]string {
	var rows [][]string
	if doc == nil {
		return nil
	}
	tbl := doc.First(sel)
	if tbl == nil {
		return nil
	}
	for _, tr := range tbl.Select("tr", 80) {
		th := tr.First("th")
		tds := tr.Select("td", 4)
		var k, v string
		if th != nil && len(tds) >= 1 {
			k = SanitizeCommerceField(strings.TrimRight(strings.TrimSpace(th.Text()), ":"), 120)
			v = SanitizeCommerceField(tds[0].Text(), 240)
		} else if len(tds) >= 2 {
			k = SanitizeCommerceField(strings.TrimRight(strings.TrimSpace(tds[0].Text()), ":"), 120)
			v = SanitizeCommerceField(tds[1].Text(), 240)
		}
		if k != "" && v != "" {
			rows = append(rows, []string{k, v})
		}
	}
	return rows
}

// ExtractMagento2ProductHTML extracts Magento 2 `text/x-magento-init` swatch/configurable JSON,
// `#product-attribute-specs-table`, and JSON-LD into normalized `CatalogRecord` + GFM tables.
func ExtractMagento2ProductHTML(rawURL, rawHTML, _ string, extractorID string) *PostFetchSiteResult {
	if extractorID == "" {
		extractorID = "shopware-magento"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !IsMagento2HTMLOrHeaders(rawHTML, nil) {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	doc := extract.ParseHTMLDoc(rawHTML, 2*1024*1024)

	prodLD := firstJSONLDProductCommerce(rawHTML)
	jc := extractMagentoInitSwatchConfig(rawHTML)
	specRows := extractSpecTableRowsBySelector(doc, "#product-attribute-specs-table, table.additional-attributes")

	title := ""
	if prodLD != nil {
		title = SanitizeCommerceField(prodLD["name"], 400)
	}
	if title == "" {
		title = SanitizeCommerceField(doc.Text("h1.page-title span, h1.page-title, h1"), 400)
	}
	if title == "" {
		return nil
	}

	topSKU := (*string)(nil)
	if prodLD != nil {
		topSKU = sanitizeCommerceSKU(prodLD["sku"])
	}
	if topSKU == nil {
		topSKU = sanitizeCommerceSKU(doc.Text(".product.attribute.sku .value, [itemprop='sku']"))
	}

	var basePrice *float64
	var baseCur *string
	var baseAvail *bool
	offers := extractJSONLDOffersList(prodLD)
	if len(offers) > 0 {
		basePrice, baseCur, baseAvail = parseJSONLDPriceOffer(offers[0])
	}
	if basePrice == nil {
		p2, c2 := parseCommercePriceAndCurrency(doc.Text(".product-info-price .price-wrapper .price, .product-info-price .price"))
		basePrice = p2
		if baseCur == nil {
			baseCur = c2
		}
	}

	options := make([]CatalogOption, 0)
	variants := make([]CatalogVariantRecord, 0)

	if jc != nil {
		if baseCur == nil {
			fmtStr := jsonScalarToStringCommerce(jc["currencyFormat"])
			if fmtStr == "" {
				if pf, okPF := jc["priceFormat"].(map[string]any); okPF {
					fmtStr = jsonScalarToStringCommerce(pf["pattern"])
				}
			}
			if fmtStr != "" {
				_, curFromFmt := parseCommercePriceAndCurrency(fmtStr)
				if curFromFmt != nil {
					baseCur = curFromFmt
				}
			}
		}
		if basePrice == nil {
			if pr, okP := jc["prices"].(map[string]any); okP {
				if fp, okFP := pr["finalPrice"].(map[string]any); okFP {
					if fv, okFV := jsonNumberToFloatCommerce(fp["amount"]); okFV && fv >= 0 {
						basePrice = &fv
					}
				}
			}
		}

		// Build attrId -> valId -> label lookup and collect options[].products[] child mappings
		valLabelByAttrVal := make(map[string]map[string]string)
		optLabelsByChildID := make(map[string][]string)
		seenChild := make(map[string]bool)
		seenAttrForChild := make(map[string]map[string]bool)
		attrOrder := make([]string, 0)
		if attrsMap, okA := jc["attributes"].(map[string]any); okA {
			for aID := range attrsMap {
				attrOrder = append(attrOrder, aID)
			}
			sort.Strings(attrOrder)
			for _, aID := range attrOrder {
				am, okM := attrsMap[aID].(map[string]any)
				if !okM {
					continue
				}
				aLabel := SanitizeCommerceField(firstNonEmptyCommerce(jsonScalarToStringCommerce(am["label"]), jsonScalarToStringCommerce(am["code"])), 120)
				valLabelByAttrVal[aID] = make(map[string]string)
				optVals := make([]string, 0)
				if optsArr, okO := am["options"].([]any); okO {
					for _, ovAny := range optsArr {
						if om, okOM := ovAny.(map[string]any); okOM {
							vID := jsonScalarToStringCommerce(om["id"])
							vLbl := SanitizeCommerceField(jsonScalarToStringCommerce(om["label"]), 120)
							if vID != "" && vLbl != "" {
								valLabelByAttrVal[aID][vID] = vLbl
								optVals = append(optVals, vLbl)
							}
							if prods, okP := om["products"].([]any); okP {
								for _, pAny := range prods {
									cid := strings.TrimSpace(jsonScalarToStringCommerce(pAny))
									if cid == "" {
										continue
									}
									seenChild[cid] = true
									if vLbl != "" {
										if seenAttrForChild[cid] == nil {
											seenAttrForChild[cid] = make(map[string]bool)
										}
										if !seenAttrForChild[cid][aID] {
											seenAttrForChild[cid][aID] = true
											optLabelsByChildID[cid] = append(optLabelsByChildID[cid], vLbl)
										}
									}
								}
							}
						}
					}
				}
				if aLabel != "" && len(optVals) > 0 {
					options = append(options, CatalogOption{Name: aLabel, Values: optVals})
				}
			}
		}

		skuMap, _ := jc["sku"].(map[string]any)
		optPrices, _ := jc["optionPrices"].(map[string]any)
		imgMap, _ := jc["images"].(map[string]any)

		buildMagentoVariant := func(cid string, optLabels []string) CatalogVariantRecord {
			var vTitle *string
			if len(optLabels) > 0 {
				joined := strings.Join(optLabels, " / ")
				vTitle = &joined
			}
			vSKU := topSKU
			if skuMap != nil {
				if s := sanitizeCommerceSKU(skuMap[cid]); s != nil {
					vSKU = s
				}
			}
			vPrice := basePrice
			var vCompare *float64
			if optPrices != nil {
				if pm, okPM := optPrices[cid].(map[string]any); okPM {
					if fp, okFP := pm["finalPrice"].(map[string]any); okFP {
						if fv, okFV := jsonNumberToFloatCommerce(fp["amount"]); okFV && fv >= 0 {
							vPrice = &fv
						}
					}
					if op, okOP := pm["oldPrice"].(map[string]any); okOP {
						if ov, okOV := jsonNumberToFloatCommerce(op["amount"]); okOV && vPrice != nil && ov > *vPrice {
							vCompare = &ov
						}
					}
				}
			}
			var vImg *string
			if imgMap != nil {
				if arr, okArr := imgMap[cid].([]any); okArr && len(arr) > 0 {
					if im0, okIm := arr[0].(map[string]any); okIm {
						cand := firstNonEmptyCommerce(jsonScalarToStringCommerce(im0["full"]), jsonScalarToStringCommerce(im0["img"]))
						if safeU := resolveSafeSameOriginOrPublicHTTPS(cand, u); safeU != "" {
							vImg = &safeU
						}
					}
				}
			}
			return CatalogVariantRecord{
				VariantID: cid,
				SKU:       vSKU,
				Title:     vTitle,
				Options:   optLabels,
				Price:     vPrice,
				CompareAt: vCompare,
				Currency:  baseCur,
				Available: baseAvail,
				Image:     vImg,
			}
		}

		if idxMap, okIdx := jc["index"].(map[string]any); okIdx && len(idxMap) > 0 {
			childIDs := make([]string, 0, len(idxMap))
			for cid := range idxMap {
				childIDs = append(childIDs, cid)
			}
			sort.Strings(childIDs)
			if len(childIDs) > DefaultMaxVariantsPerProduct {
				childIDs = childIDs[:DefaultMaxVariantsPerProduct]
			}
			for _, cid := range childIDs {
				combo, _ := idxMap[cid].(map[string]any)
				optLabels := make([]string, 0, len(attrOrder))
				for _, aID := range attrOrder {
					valID := jsonScalarToStringCommerce(combo[aID])
					if lbl := valLabelByAttrVal[aID][valID]; lbl != "" {
						optLabels = append(optLabels, lbl)
					}
				}
				variants = append(variants, buildMagentoVariant(cid, optLabels))
			}
		} else {
			childIDs := make([]string, 0)
			if len(seenChild) > 0 {
				for cid := range seenChild {
					childIDs = append(childIDs, cid)
				}
			} else {
				seenFallback := make(map[string]bool)
				for cid := range skuMap {
					if cid != "" && !seenFallback[cid] {
						seenFallback[cid] = true
						childIDs = append(childIDs, cid)
					}
				}
				for cid := range optPrices {
					if cid != "" && !seenFallback[cid] {
						seenFallback[cid] = true
						childIDs = append(childIDs, cid)
					}
				}
			}
			sort.Strings(childIDs)
			if len(childIDs) > DefaultMaxVariantsPerProduct {
				childIDs = childIDs[:DefaultMaxVariantsPerProduct]
			}
			for _, cid := range childIDs {
				optLabels := append([]string(nil), optLabelsByChildID[cid]...)
				variants = append(variants, buildMagentoVariant(cid, optLabels))
			}
		}
	}

	if len(variants) == 0 && (basePrice != nil || topSKU != nil || len(specRows) > 0) {
		variants = append(variants, CatalogVariantRecord{
			VariantID: firstNonEmptyCommerce(jsonScalarToStringCommerce(prodLD["sku"]), "1"),
			SKU:       topSKU,
			Options:   []string{},
			Price:     basePrice,
			Currency:  baseCur,
			Available: baseAvail,
		})
	}
	if len(variants) == 0 && len(specRows) == 0 {
		return nil
	}

	desc := ""
	if prodLD != nil {
		desc = SanitizeCommerceField(StripTagsInlineCommerce(jsonScalarToStringCommerce(prodLD["description"])), 1200)
	}
	prodID := ""
	if m := reMagentoProductID.FindStringSubmatch(rawHTML); len(m) == 2 {
		prodID = m[1]
	}
	if prodID == "" && topSKU != nil {
		prodID = *topSKU
	}
	if prodID == "" {
		prodID = strings.Trim(u.Path, "/")
	}

	rec := CatalogRecord{
		Platform:        "magento2",
		Origin:          origin,
		ProductID:       prodID,
		Handle:          strings.Trim(u.Path, "/"),
		URL:             u.String(),
		Title:           title,
		Tags:            []string{},
		DescriptionText: strPtrAlways(desc),
		Options:         options,
		Variants:        variants,
	}

	var sections []string
	sections = append(sections, "# "+title)
	if len(variants) > 0 {
		vRows := make([][]string, 0, len(variants))
		for i, v := range variants {
			if i >= 60 {
				break
			}
			vt := title
			if v.Title != nil && *v.Title != "" {
				vt = *v.Title
			}
			vRows = append(vRows, []string{
				vt,
				formatCommerceSKUDisplay(v.SKU, false),
				formatGenericMoneyDisplay(v.Price, v.Currency),
			})
		}
		sections = append(sections, "## Variants & Pricing\n\n"+FormatGFMTable([]string{"Variant", "SKU", "Price"}, vRows))
	}
	if len(specRows) > 0 {
		sections = append(sections, "## Specifications\n\n"+FormatGFMTable([]string{"Attribute", "Value"}, specRows))
	}
	if desc != "" {
		sections = append(sections, "## Description\n\n"+desc)
	}
	return &PostFetchSiteResult{
		ExtractorID: extractorID,
		Title:       title,
		Description: sliceUTF16Safe(desc, 260),
		Markdown:    strings.Join(sections, "\n\n"),
		Links:       []string{u.String()},
		Records:     []CatalogRecord{rec},
	}
}

// ResolveMagento2RenderInfoTwinURL builds a bounded same-origin `/rest/V1/products-render-info`
// URL for Magento 2 product pages (strictly `pageSize=1`, never unfiltered catalog dumps).
func ResolveMagento2RenderInfoTwinURL(pageURL, rawHTML string) string {
	u, ok := IsSafeHTTPSStoreURL(pageURL, "")
	if !ok || u == nil || !IsMagento2HTMLOrHeaders(rawHTML, nil) {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	pid := ""
	if m := reMagentoProductID.FindStringSubmatch(rawHTML); len(m) == 2 && m[1] != "" {
		pid = m[1]
	} else if m := reMagentoFormProductID1.FindStringSubmatch(rawHTML); len(m) == 2 && m[1] != "" {
		pid = m[1]
	} else if m := reMagentoFormProductID2.FindStringSubmatch(rawHTML); len(m) == 2 && m[1] != "" {
		pid = m[1]
	} else if jc := extractMagentoInitSwatchConfig(rawHTML); jc != nil {
		var cands []string
		if idxMap, okIdx := jc["index"].(map[string]any); okIdx {
			for cid := range idxMap {
				if reMagentoDigitsOnly.MatchString(cid) {
					cands = append(cands, cid)
				}
			}
		}
		if len(cands) == 0 {
			if attrsMap, okA := jc["attributes"].(map[string]any); okA {
				for _, amAny := range attrsMap {
					if am, okM := amAny.(map[string]any); okM {
						if opts, okO := am["options"].([]any); okO {
							for _, ovAny := range opts {
								if om, okOM := ovAny.(map[string]any); okOM {
									if prods, okP := om["products"].([]any); okP {
										for _, pAny := range prods {
											cid := strings.TrimSpace(jsonScalarToStringCommerce(pAny))
											if reMagentoDigitsOnly.MatchString(cid) {
												cands = append(cands, cid)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if len(cands) == 0 {
			if skuMap, okS := jc["sku"].(map[string]any); okS {
				for cid := range skuMap {
					if reMagentoDigitsOnly.MatchString(cid) {
						cands = append(cands, cid)
					}
				}
			}
		}
		if len(cands) > 0 {
			sort.Strings(cands)
			pid = cands[0]
		}
	}
	if pid != "" {
		return fmt.Sprintf(
			"https://%s/rest/V1/products-render-info?searchCriteria[filterGroups][0][filters][0][field]=entity_id&searchCriteria[filterGroups][0][filters][0][value]=%s&searchCriteria[pageSize]=1&storeId=0&currencyCode=USD",
			host, EncodeURIComponent(pid),
		)
	}
	return ""
}

// FormatMagento2RenderInfoJSON parses Magento 2 `/rest/V1/products-render-info` JSON (failing open on
// 401/403/404 error objects or empty `items[]`) and merges optional HTML spec tables.
func FormatMagento2RenderInfoJSON(rawBody, origURL, fallbackHTML string) *TwinFormattedDoc {
	obj, ok := parseJSONObjectCommerce(rawBody)
	if !ok || obj == nil {
		return nil
	}
	items, okArr := obj["items"].([]any)
	if !okArr || len(items) == 0 {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(origURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)

	records := make([]CatalogRecord, 0, len(items))
	rows := make([][]string, 0, len(items))
	links := make([]string, 0, len(items))

	for idx, itAny := range items {
		if idx >= 20 {
			break
		}
		it, okM := itAny.(map[string]any)
		if !okM {
			continue
		}
		title := SanitizeCommerceField(it["name"], 400)
		if title == "" {
			continue
		}
		pid := jsonScalarToStringCommerce(it["id"])
		skuPtr := sanitizeCommerceSKU(it["sku"])
		itemURL := resolveSafeSameOriginOrPublicHTTPS(jsonScalarToStringCommerce(it["url"]), u)
		if itemURL == "" {
			itemURL = u.String()
		}
		links = append(links, itemURL)

		var price *float64
		var compareAt *float64
		var cur *string
		if cStr, okC := it["currency_code"].(string); okC {
			cu := strings.ToUpper(strings.TrimSpace(cStr))
			if reISOCurrency3.MatchString(cu) {
				cur = &cu
			}
		}
		if pi, okPI := it["price_info"].(map[string]any); okPI {
			if fp, okF := jsonNumberToFloatCommerce(pi["final_price"]); okF && fp >= 0 {
				price = &fp
			}
			if rp, okR := jsonNumberToFloatCommerce(pi["regular_price"]); okR && price != nil && rp > *price {
				compareAt = &rp
			}
		}
		var avail *bool
		if salStr, okS := it["is_salable"].(string); okS {
			b := salStr == "1" || strings.EqualFold(salStr, "true")
			avail = &b
		} else if b, okB := it["is_salable"].(bool); okB {
			bv := b
			avail = &bv
		}
		imgs := make([]string, 0)
		if rawImgs, okI := it["images"].([]any); okI {
			for _, imAny := range rawImgs {
				if im, okIM := imAny.(map[string]any); okIM {
					if su := resolveSafeSameOriginOrPublicHTTPS(jsonScalarToStringCommerce(im["url"]), u); su != "" {
						imgs = append(imgs, su)
					}
				}
			}
		}
		var pImg *string
		if len(imgs) > 0 {
			u0 := imgs[0]
			pImg = &u0
		}

		records = append(records, CatalogRecord{
			Platform:  "magento2",
			Origin:    origin,
			ProductID: pid,
			Handle:    pid,
			URL:       itemURL,
			Title:     title,
			Tags:      []string{},
			Images:    &imgs,
			Options:   []CatalogOption{},
			Variants: []CatalogVariantRecord{
				{
					VariantID: pid,
					SKU:       skuPtr,
					Options:   []string{},
					Price:     price,
					CompareAt: compareAt,
					Currency:  cur,
					Available: avail,
					Image:     pImg,
				},
			},
		})
		rows = append(rows, []string{
			FormatMarkdownLinkCommerce(title, itemURL),
			formatCommerceSKUDisplay(skuPtr, false),
			formatGenericMoneyDisplay(price, cur),
		})
	}

	if len(records) == 0 {
		return nil
	}
	sections := []string{
		"# " + records[0].Title,
		"## Variants & Pricing\n\n" + FormatGFMTable([]string{"Product", "SKU", "Price"}, rows),
	}
	if fallbackHTML != "" {
		doc := extract.ParseHTMLDoc(fallbackHTML, 2*1024*1024)
		if specRows := extractSpecTableRowsBySelector(doc, "#product-attribute-specs-table, table.additional-attributes"); len(specRows) > 0 {
			sections = append(sections, "## Specifications\n\n"+FormatGFMTable([]string{"Attribute", "Value"}, specRows))
		}
	}
	return &TwinFormattedDoc{
		Title:    records[0].Title,
		Markdown: strings.Join(sections, "\n\n"),
		Links:    links,
		Records:  records,
	}
}

// ExtractShopware6ProductHTML extracts Shopware 6 (`sw-product-detail`, `.product-detail-properties-table`,
// configurator options, and JSON-LD) into normalized `CatalogRecord` + GFM tables.
func ExtractShopware6ProductHTML(rawURL, rawHTML, _ string, extractorID string) *PostFetchSiteResult {
	if extractorID == "" {
		extractorID = "shopware-magento"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !IsShopware6HTMLOrHeaders(rawHTML, nil) {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	doc := extract.ParseHTMLDoc(rawHTML, 2*1024*1024)

	prodLD := firstJSONLDProductCommerce(rawHTML)
	title := ""
	if prodLD != nil {
		title = SanitizeCommerceField(prodLD["name"], 400)
	}
	if title == "" {
		title = SanitizeCommerceField(doc.Text("h1.product-detail-name, h1"), 400)
	}
	if title == "" {
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
	if brand == "" {
		brand = SanitizeCommerceField(doc.Text(".product-detail-manufacturer-link"), 200)
	}

	skuPtr := (*string)(nil)
	if prodLD != nil {
		skuPtr = sanitizeCommerceSKU(prodLD["sku"])
	}
	if skuPtr == nil {
		skuPtr = sanitizeCommerceSKU(doc.Text(".product-detail-ordernumber"))
	}

	var price *float64
	var cur *string
	var avail *bool
	offers := extractJSONLDOffersList(prodLD)
	if len(offers) > 0 {
		price, cur, avail = parseJSONLDPriceOffer(offers[0])
	}
	if price == nil {
		price, cur = parseCommercePriceAndCurrency(doc.Text(".product-detail-price"))
	}

	options := make([]CatalogOption, 0)
	for _, grp := range doc.Select(".product-detail-configurator-group", 16) {
		gName := SanitizeCommerceField(grp.Text(".product-detail-configurator-group-title"), 120)
		vals := make([]string, 0)
		for _, opt := range grp.Select(".product-detail-configurator-option-label, option", 40) {
			vt := SanitizeCommerceField(opt.Text(), 120)
			if vt != "" {
				vals = append(vals, vt)
			}
		}
		if gName != "" && len(vals) > 0 {
			options = append(options, CatalogOption{Name: gName, Values: vals})
		}
	}

	specRows := extractSpecTableRowsBySelector(doc, "table.product-detail-properties-table, .product-detail-properties-table")

	descHTML := ""
	if rawDesc, ok := extract.ExtractFirstRawElementOrBoundedHTML(rawHTML,
		extract.RawElementSelector{Class: "product-detail-description-text"},
	); ok {
		descHTML = rawDesc
	}
	bodyMD := ""
	if strings.TrimSpace(descHTML) != "" {
		bodyMD = strings.TrimSpace(stripNonPublicMarkdownImages(ConvertCommerceHTMLFragmentToMD(descHTML, rawURL)))
	} else if prodLD != nil {
		if ds, okD := prodLD["description"].(string); okD {
			bodyMD = SanitizeCommerceField(StripTagsInlineCommerce(ds), 1200)
		}
	}

	if price == nil && skuPtr == nil && len(specRows) == 0 && len(options) == 0 && bodyMD == "" {
		return nil
	}

	prodID := strings.Trim(u.Path, "/")
	if skuPtr != nil {
		prodID = *skuPtr
	}
	rec := CatalogRecord{
		Platform:        "shopware6",
		Origin:          origin,
		ProductID:       prodID,
		Handle:          strings.Trim(u.Path, "/"),
		URL:             u.String(),
		Title:           title,
		Vendor:          strPtrOrNil(brand),
		Tags:            []string{},
		DescriptionText: strPtrAlways(bodyMD),
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
	if len(specRows) > 0 {
		sections = append(sections, "## Specifications\n\n"+FormatGFMTable([]string{"Property", "Value"}, specRows))
	}
	if bodyMD != "" {
		sections = append(sections, "## Product Details\n\n"+bodyMD)
	}
	return &PostFetchSiteResult{
		ExtractorID: extractorID,
		Title:       title,
		Author:      brand,
		Description: sliceUTF16Safe(bodyMD, 260),
		Markdown:    strings.Join(sections, "\n\n"),
		Links:       []string{u.String()},
		Records:     []CatalogRecord{rec},
	}
}

// ExtractShopwareOrMagentoHTML dispatches post-fetch HTML extraction to Magento 2 or Shopware 6
// strictly based on structural markers.
func ExtractShopwareOrMagentoHTML(rawURL, rawHTML, currentMD, extractorID string) *PostFetchSiteResult {
	if IsMagento2HTMLOrHeaders(rawHTML, nil) {
		if res := ExtractMagento2ProductHTML(rawURL, rawHTML, currentMD, extractorID); res != nil {
			return res
		}
	}
	if IsShopware6HTMLOrHeaders(rawHTML, nil) {
		if res := ExtractShopware6ProductHTML(rawURL, rawHTML, currentMD, extractorID); res != nil {
			return res
		}
	}
	return nil
}
