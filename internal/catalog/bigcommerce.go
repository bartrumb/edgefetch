package catalog

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// IsBigCommerceHTMLOrHeaders detects BigCommerce Stencil storefronts structurally
// from response headers or HTML markers.
func IsBigCommerceHTMLOrHeaders(rawHTML string, headers map[string]string) bool {
	if len(headers) > 0 {
		if readHeaderCaseInsensitive(headers, "x-bc-storefront-type") != "" ||
			readHeaderCaseInsensitive(headers, "x-bc-cache-status") != "" ||
			readHeaderCaseInsensitive(headers, "x-bc-customer-group-id") != "" {
			return true
		}
	}
	if rawHTML == "" {
		return false
	}
	slice := rawHTML
	if len(slice) > 120_000 {
		slice = slice[:120_000]
	}
	return strings.Contains(slice, "cdn11.bigcommerce.com/s-") ||
		strings.Contains(slice, "bigcommerce.com/s-") ||
		strings.Contains(slice, "window.BCData") ||
		strings.Contains(slice, "var BCData") ||
		strings.Contains(slice, "data-cart-item-add") ||
		strings.Contains(slice, "data-product-attributes") ||
		strings.Contains(slice, "mybigcommerce.com") ||
		strings.Contains(slice, "productView-info")
}

func extractBigCommerceBCData(rawHTML string) map[string]any {
	scan := rawHTML
	if len(scan) > 512_000 {
		scan = scan[:512_000]
	}
	var fallbackObj map[string]any
	for _, marker := range []string{"window.BCData", "var BCData", "BCData ="} {
		searchFrom := 0
		for iter := 0; iter < 32 && searchFrom < len(scan); iter++ {
			rel := strings.Index(scan[searchFrom:], marker)
			if rel < 0 {
				break
			}
			searchFrom += rel + len(marker)
			if searchFrom >= len(scan) {
				break
			}
			tail := scan[searchFrom:]
			braceRel := strings.IndexByte(tail, '{')
			if braceRel < 0 || braceRel > 64 {
				continue
			}
			rawJSON, _, ok := extract.ExtractBalancedJSONAt(tail, braceRel, 128*1024)
			if !ok {
				continue
			}
			parsed, okP := parseJSONObjectCommerce(rawJSON)
			if !okP || len(parsed) == 0 {
				continue
			}
			if parsed["product_attributes"] != nil {
				return parsed
			}
			if fallbackObj == nil {
				fallbackObj = parsed
			}
		}
	}
	return fallbackObj
}

// ExtractBigCommerceHTML extracts BigCommerce Stencil product details (`BCData`, JSON-LD, Microdata,
// `form[data-cart-item-add]` options, `<dl class="productView-info">` specs) or category grid cards.
func ExtractBigCommerceHTML(rawURL, rawHTML, _ string, extractorID string) *PostFetchSiteResult {
	if extractorID == "" {
		extractorID = "bigcommerce-store"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !IsBigCommerceHTMLOrHeaders(rawHTML, nil) {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	doc := extract.ParseHTMLDoc(rawHTML, 2*1024*1024)

	bcData := extractBigCommerceBCData(rawHTML)
	prodLD := firstJSONLDProductCommerce(rawHTML)
	microProd := extract.ExtractMicrodataProduct(rawHTML, rawURL, "", "")
	microProdNode := doc.First(`[itemscope][itemtype*="schema.org/Product" i]`)

	// Extract <dl class="productView-info"> key-value pairs.
	specRows := make([][]string, 0)
	var dlSKU, dlUPC, dlMPN string
	for _, dl := range doc.Select("dl.productView-info, .productView-info", 4) {
		dts := dl.Select("dt", 40)
		dds := dl.Select("dd", 40)
		n := len(dts)
		if len(dds) < n {
			n = len(dds)
		}
		for i := 0; i < n; i++ {
			k := SanitizeCommerceField(strings.TrimRight(strings.TrimSpace(dts[i].Text()), ":"), 120)
			v := SanitizeCommerceField(strings.TrimSpace(dds[i].Text()), 240)
			if k == "" || v == "" {
				continue
			}
			specRows = append(specRows, []string{k, v})
			lowK := strings.ToLower(k)
			if lowK == "sku" && dlSKU == "" {
				dlSKU = v
			} else if lowK == "upc" && dlUPC == "" {
				dlUPC = v
			} else if lowK == "mpn" && dlMPN == "" {
				dlMPN = v
			}
		}
	}

	// Single Product Path
	title := SanitizeCommerceField(doc.Text("h1.productView-title"), 400)
	if title == "" && prodLD != nil {
		title = SanitizeCommerceField(prodLD["name"], 400)
	}
	if title == "" && microProd != nil {
		title = SanitizeCommerceField(microProd["title"], 400)
	}
	if title == "" && microProdNode != nil {
		title = SanitizeCommerceField(microProdNode.Text(`[itemprop="name"]`), 400)
	}
	hasProductGrid := doc.First(".productGrid .card, ul.productGrid li.product, article.card[data-entity-id]") != nil
	hasMicrodataProduct := microProd != nil || microProdNode != nil
	isProductView := doc.First("form[data-cart-item-add]") != nil ||
		doc.First(".productView") != nil ||
		prodLD != nil ||
		(bcData != nil && bcData["product_attributes"] != nil) ||
		(hasMicrodataProduct && !hasProductGrid)

	if isProductView && title != "" {
		brand := SanitizeCommerceField(doc.Text(".productView-brand a, .productView-brand"), 200)
		if brand == "" && prodLD != nil {
			switch b := prodLD["brand"].(type) {
			case string:
				brand = SanitizeCommerceField(b, 200)
			case map[string]any:
				brand = SanitizeCommerceField(b["name"], 200)
			}
		}
		if brand == "" && microProd != nil {
			brand = SanitizeCommerceField(microProd["brand"], 200)
		}
		if brand == "" && microProdNode != nil {
			brand = SanitizeCommerceField(microProdNode.Text(`[itemprop="brand"] [itemprop="name"], [itemprop="brand"]`), 200)
		}

		var skuPtr *string
		var barcodePtr *string
		var price *float64
		var compareAt *float64
		var cur *string
		var avail *bool
		var invQty *int
		imgs := make([]string, 0)

		if bcData != nil {
			if pa, okPA := bcData["product_attributes"].(map[string]any); okPA {
				skuPtr = sanitizeCommerceSKU(pa["sku"])
				barcodePtr = sanitizeCommerceSKU(firstNonEmptyCommerce(jsonScalarToStringCommerce(pa["upc"]), jsonScalarToStringCommerce(pa["mpn"])))
				if b, okB := pa["instock"].(bool); okB {
					bv := b
					avail = &bv
				} else if b, okB := pa["purchasable"].(bool); okB {
					bv := b
					avail = &bv
				}
				if stF, okS := jsonNumberToFloatCommerce(pa["stock"]); okS {
					si := int(stF)
					invQty = &si
				}
				if prObj, okPr := pa["price"].(map[string]any); okPr {
					wt, _ := prObj["without_tax"].(map[string]any)
					if wt == nil {
						wt, _ = prObj["with_tax"].(map[string]any)
					}
					if wt != nil {
						if fv, okF := jsonNumberToFloatCommerce(wt["value"]); okF && fv >= 0 {
							price = &fv
						}
						if cStr, okC := wt["currency"].(string); okC {
							cu := strings.ToUpper(strings.TrimSpace(cStr))
							if reISOCurrency3.MatchString(cu) {
								cur = &cu
							}
						}
					}
					if rrp, okR := prObj["rrp_without_tax"].(map[string]any); okR {
						if rv, okRV := jsonNumberToFloatCommerce(rrp["value"]); okRV && price != nil && rv > *price {
							compareAt = &rv
						}
					}
				}
				if imgObj, okI := pa["image"].(map[string]any); okI {
					if rawD, okD := imgObj["data"].(string); okD {
						cand := strings.ReplaceAll(rawD, "{:size}", "1280x1280")
						if safeU := resolveSafeSameOriginOrPublicHTTPS(cand, u); safeU != "" {
							imgs = append(imgs, safeU)
						}
					}
				}
			}
		}

		if skuPtr == nil && prodLD != nil {
			skuPtr = sanitizeCommerceSKU(prodLD["sku"])
		}
		if skuPtr == nil && microProd != nil {
			skuPtr = sanitizeCommerceSKU(microProd["sku"])
		}
		if skuPtr == nil && dlSKU != "" {
			skuPtr = sanitizeCommerceSKU(dlSKU)
		}
		if barcodePtr == nil && dlUPC != "" {
			barcodePtr = sanitizeCommerceSKU(dlUPC)
		} else if barcodePtr == nil && dlMPN != "" {
			barcodePtr = sanitizeCommerceSKU(dlMPN)
		}
		if barcodePtr == nil && microProd != nil {
			barcodePtr = sanitizeCommerceSKU(firstNonEmptyCommerce(jsonScalarToStringCommerce(microProd["gtin"]), jsonScalarToStringCommerce(microProd["mpn"])))
		}

		offers := extractJSONLDOffersList(prodLD)
		if len(offers) > 0 && (price == nil || avail == nil) {
			ldP, ldC, ldA := parseJSONLDPriceOffer(offers[0])
			if price == nil {
				price = ldP
			}
			if cur == nil {
				cur = ldC
			}
			if avail == nil {
				avail = ldA
			}
		}
		if microProd != nil {
			if price == nil {
				if mp, okMP := jsonNumberToFloatCommerce(microProd["price"]); okMP && mp >= 0 {
					price = &mp
				}
			}
			if cur == nil {
				if mc, okMC := microProd["currency"].(string); okMC {
					cu := strings.ToUpper(strings.TrimSpace(mc))
					if reISOCurrency3.MatchString(cu) {
						cur = &cu
					}
				}
			}
			if avail == nil {
				if ma, okMA := microProd["availability"].(string); okMA {
					switch ma {
					case "InStock", "PreOrder", "BackOrder", "OnlineOnly", "LimitedAvailability", "InStoreOnly":
						bv := true
						avail = &bv
					case "OutOfStock", "Discontinued", "SoldOut":
						bv := false
						avail = &bv
					}
				}
			}
			if len(imgs) == 0 {
				if mImgs, okMI := microProd["images"].([]string); okMI {
					for _, im := range mImgs {
						if safeU := resolveSafeSameOriginOrPublicHTTPS(im, u); safeU != "" {
							imgs = append(imgs, safeU)
						}
					}
				}
			}
		}
		if price == nil {
			pText := doc.Text(".productView-price .price--withoutTax, .productView-price .price")
			p2, c2 := parseCommercePriceAndCurrency(pText)
			price = p2
			if cur == nil {
				cur = c2
			}
		}

		// Extract Stencil form[data-cart-item-add] options
		options := make([]CatalogOption, 0)
		if cartForm := doc.First("form[data-cart-item-add]"); cartForm != nil {
			var emittedContainers []*extract.HTMLNode
			for _, field := range cartForm.Select("[data-product-attribute], [data-product-option-change], .form-field, fieldset", 24) {
				if _, isOptChange := field.Attr("data-product-option-change"); isOptChange && field.First("[data-product-attribute], .form-field, fieldset") != nil {
					continue
				}
				if len(field.Select("[data-product-attribute], fieldset", 2)) >= 2 {
					continue
				}
				isNestedInEmitted := false
				for _, prev := range emittedContainers {
					if field.IsDescendantOf(prev) {
						isNestedInEmitted = true
						break
					}
				}
				if isNestedInEmitted {
					continue
				}
				allLabels := field.Select("label", 40)
				radioInputs := field.Select(`input[type="radio"], input[type="checkbox"]`, 40)
				radioForIDs := make(map[string]bool)
				for _, inp := range radioInputs {
					if id := strings.TrimSpace(inp.AttrOrEmpty("id")); id != "" {
						radioForIDs[id] = true
					}
				}
				isOptionLabel := func(cand *extract.HTMLNode) bool {
					clsPad := " " + strings.ToLower(strings.TrimSpace(cand.AttrOrEmpty("class"))) + " "
					if strings.Contains(clsPad, " form-option ") ||
						strings.Contains(clsPad, " form-radio-label ") ||
						strings.Contains(clsPad, " form-checkbox-label ") ||
						strings.Contains(clsPad, " form-radio ") ||
						strings.Contains(clsPad, " form-checkbox ") {
						return true
					}
					if cand.First("input") != nil {
						return true
					}
					if forAttr := strings.TrimSpace(cand.AttrOrEmpty("for")); forAttr != "" && radioForIDs[forAttr] {
						return true
					}
					return false
				}
				usedLabelIdx := -1
				rawLbl := ""
				if len(radioInputs) > 0 {
					rawLbl = strings.TrimSpace(field.Text("legend"))
				}
				if rawLbl == "" {
					for li, cand := range allLabels {
						clsPad := " " + strings.ToLower(strings.TrimSpace(cand.AttrOrEmpty("class"))) + " "
						if !strings.Contains(clsPad, " form-label ") || isOptionLabel(cand) {
							continue
						}
						if t := strings.TrimSpace(cand.Text()); t != "" {
							rawLbl = t
							usedLabelIdx = li
							break
						}
					}
				}
				if strings.TrimSpace(rawLbl) == "" {
					rawLbl = field.Text("legend")
				}
				if strings.TrimSpace(rawLbl) == "" {
					for li, cand := range allLabels {
						if isOptionLabel(cand) {
							continue
						}
						if t := strings.TrimSpace(cand.Text()); t != "" {
							rawLbl = t
							usedLabelIdx = li
							break
						}
					}
				}
				if strings.TrimSpace(rawLbl) == "" {
					if sel := field.First("select"); sel != nil {
						rawLbl = firstNonEmptyCommerce(sel.AttrOrEmpty("aria-label"), sel.AttrOrEmpty("title"))
					}
				}
				lbl := SanitizeCommerceField(strings.TrimSuffix(strings.TrimSpace(rawLbl), ":"), 120)
				if lbl == "" {
					continue
				}
				vals := make([]string, 0)
				seenV := make(map[string]bool)
				for _, opt := range field.Select("select option", 40) {
					if val, hasVal := opt.Attr("value"); hasVal && strings.TrimSpace(val) == "" {
						continue
					}
					vt := SanitizeCommerceField(opt.Text(), 120)
					if vt != "" && !seenV[vt] {
						seenV[vt] = true
						vals = append(vals, vt)
					}
				}
				for _, rlbl := range field.Select("label.form-option, label.form-radio-label", 40) {
					rawOpt := firstNonEmptyCommerce(
						rlbl.Text(),
						rlbl.AttrOrEmpty("title"),
						rlbl.AttrOrEmpty("aria-label"),
						rlbl.AttrOf("span", "title"),
						rlbl.AttrOf("span", "aria-label"),
					)
					vt := SanitizeCommerceField(rawOpt, 120)
					if vt != "" && !seenV[vt] {
						seenV[vt] = true
						vals = append(vals, vt)
					}
				}
				if len(vals) == 0 {
					radioByID := make(map[string]*extract.HTMLNode, len(radioInputs))
					for _, inp := range radioInputs {
						if id := strings.TrimSpace(inp.AttrOrEmpty("id")); id != "" {
							radioByID[id] = inp
						}
					}
					matchedInputs := make(map[any]bool, len(radioInputs))
					usedForLabels := make(map[any]bool, len(allLabels))
					for li, rlbl := range allLabels {
						if li == usedLabelIdx {
							continue
						}
						forAttr := strings.TrimSpace(rlbl.AttrOrEmpty("for"))
						wrapped := rlbl.Select(`input[type="radio"], input[type="checkbox"]`, 4)
						if len(wrapped) == 0 && (forAttr == "" || !radioForIDs[forAttr]) {
							continue
						}
						rawOpt := firstNonEmptyCommerce(
							rlbl.Text(),
							rlbl.AttrOrEmpty("title"),
							rlbl.AttrOrEmpty("aria-label"),
							rlbl.AttrOf("span", "title"),
							rlbl.AttrOf("span", "aria-label"),
						)
						vt := SanitizeCommerceField(rawOpt, 120)
						if vt != "" && !seenV[vt] {
							seenV[vt] = true
							vals = append(vals, vt)
						}
						if lKey := rlbl.NodeKey(); lKey != nil {
							usedForLabels[lKey] = true
						}
						for _, winp := range wrapped {
							if wKey := winp.NodeKey(); wKey != nil {
								matchedInputs[wKey] = true
							}
						}
						if forAttr != "" {
							if targetInp := radioByID[forAttr]; targetInp != nil {
								if tKey := targetInp.NodeKey(); tKey != nil {
									matchedInputs[tKey] = true
								}
							}
						}
					}
					if len(vals) < len(radioInputs) {
						for _, inp := range radioInputs {
							iKey := inp.NodeKey()
							if iKey != nil && matchedInputs[iKey] {
								continue
							}
							rawOpt := firstNonEmptyCommerce(inp.AttrOrEmpty("data-label"), inp.AttrOrEmpty("aria-label"), inp.AttrOrEmpty("title"))
							vt := SanitizeCommerceField(rawOpt, 120)
							if vt != "" {
								if iKey != nil {
									matchedInputs[iKey] = true
								}
								if !seenV[vt] {
									seenV[vt] = true
									vals = append(vals, vt)
								}
							}
						}
					}
					if len(vals) < len(radioInputs) && len(radioInputs) > 0 && strings.TrimSpace(field.Text("legend")) != "" {
						orderedNodes := field.Select(`label, input[type="radio"], input[type="checkbox"]`, 120)
						waitingForLabel := false
						for _, node := range orderedNodes {
							nKey := node.NodeKey()
							if node.Tag() == "input" {
								if nKey != nil && matchedInputs[nKey] {
									waitingForLabel = false
								} else {
									waitingForLabel = true
								}
								continue
							}
							if !waitingForLabel || (nKey != nil && usedForLabels[nKey]) {
								continue
							}
							if forAttr := strings.TrimSpace(node.AttrOrEmpty("for")); forAttr != "" {
								continue
							}
							vt := SanitizeCommerceField(node.Text(), 120)
							if vt != "" && !seenV[vt] {
								seenV[vt] = true
								vals = append(vals, vt)
								waitingForLabel = false
							}
						}
					}
				}
				if len(vals) > 0 {
					options = append(options, CatalogOption{Name: lbl, Values: vals})
					emittedContainers = append(emittedContainers, field)
				}
			}
			if len(options) == 0 {
				formLabels := cartForm.Select("label", 40)
				for _, sel := range cartForm.Select(`select[name^="attribute"]`, 16) {
					selID := strings.TrimSpace(sel.AttrOrEmpty("id"))
					rawLbl := ""
					if selID != "" {
						for _, fl := range formLabels {
							if strings.TrimSpace(fl.AttrOrEmpty("for")) == selID {
								rawLbl = fl.Text()
								break
							}
						}
					}
					if strings.TrimSpace(rawLbl) == "" {
						rawLbl = firstNonEmptyCommerce(sel.AttrOrEmpty("aria-label"), sel.AttrOrEmpty("title"))
					}
					lbl := SanitizeCommerceField(strings.TrimSuffix(strings.TrimSpace(rawLbl), ":"), 120)
					if lbl == "" {
						continue
					}
					vals := make([]string, 0)
					seenV := make(map[string]bool)
					for _, opt := range sel.Select("option", 40) {
						if val, hasVal := opt.Attr("value"); hasVal && strings.TrimSpace(val) == "" {
							continue
						}
						vt := SanitizeCommerceField(opt.Text(), 120)
						if vt != "" && !seenV[vt] {
							seenV[vt] = true
							vals = append(vals, vt)
						}
					}
					if len(vals) > 0 {
						options = append(options, CatalogOption{Name: lbl, Values: vals})
					}
				}
			}
		}

		prodID := ""
		if pidInput := doc.First(`form[data-cart-item-add] input[name="product_id"]`); pidInput != nil {
			prodID = strings.TrimSpace(pidInput.AttrOrEmpty("value"))
		}
		if prodID == "" && skuPtr != nil {
			prodID = *skuPtr
		}
		if prodID == "" {
			prodID = strings.Trim(u.Path, "/")
		}

		var descHTML string
		if rawDesc, ok := extract.ExtractFirstRawElementOrBoundedHTML(rawHTML,
			extract.RawElementSelector{ID: "tab-description"},
			extract.RawElementSelector{Class: "productview-description"},
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
		if bodyMD == "" && microProd != nil {
			if ms := jsonScalarToStringCommerce(microProd["description"]); ms != "" {
				bodyMD = SanitizeCommerceField(StripTagsInlineCommerce(ms), 1200)
			}
		}

		var primaryImg *string
		if len(imgs) > 0 {
			u0 := imgs[0]
			primaryImg = &u0
		}

		rec := CatalogRecord{
			Platform:        "bigcommerce",
			Origin:          origin,
			ProductID:       prodID,
			Handle:          strings.Trim(u.Path, "/"),
			URL:             u.String(),
			Title:           title,
			Vendor:          strPtrOrNil(brand),
			Tags:            []string{},
			DescriptionText: strPtrAlways(bodyMD),
			Images:          &imgs,
			Options:         options,
			Variants: []CatalogVariantRecord{
				{
					VariantID:         prodID,
					SKU:               skuPtr,
					Barcode:           barcodePtr,
					Options:           []string{},
					Price:             price,
					CompareAt:         compareAt,
					Currency:          cur,
					Available:         avail,
					InventoryQuantity: invQty,
					Image:             primaryImg,
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
		if len(specRows) > 0 {
			sections = append(sections, "## Specifications\n\n"+FormatGFMTable([]string{"Attribute", "Value"}, specRows))
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

	// Category / Search Grid Path
	cards := doc.Select(".productGrid .card, ul.productGrid li.product, article.card[data-entity-id]", 60)
	if len(cards) == 0 {
		return nil
	}
	records := make([]CatalogRecord, 0, len(cards))
	rows := make([][]string, 0, len(cards))
	links := make([]string, 0, len(cards))
	for idx, card := range cards {
		cTitle := SanitizeCommerceField(card.Text(".card-title a, .card-title, h4, h3"), 300)
		if cTitle == "" {
			continue
		}
		href := ""
		if a := card.First(".card-title a[href], a[href]"); a != nil {
			href = a.AttrOrEmpty("href")
		}
		itemURL := resolveSafeSameOriginOrPublicHTTPS(href, u)
		if itemURL == "" {
			itemURL = u.String()
		} else {
			links = append(links, itemURL)
		}
		skuPtr := sanitizeCommerceSKU(card.AttrOrEmpty("data-sku"))
		priceText := card.Text(".price--withoutTax, .price")
		price, cur := parseCommercePriceAndCurrency(priceText)
		pid := firstNonEmptyCommerce(card.AttrOrEmpty("data-entity-id"), card.AttrOrEmpty("data-product-id"), strconv.Itoa(idx+1))
		records = append(records, CatalogRecord{
			Platform:  "bigcommerce",
			Origin:    origin,
			ProductID: pid,
			Handle:    pid,
			URL:       itemURL,
			Title:     cTitle,
			Tags:      []string{},
			Options:   []CatalogOption{},
			Variants: []CatalogVariantRecord{
				{VariantID: pid, SKU: skuPtr, Options: []string{}, Price: price, Currency: cur},
			},
		})
		rows = append(rows, []string{
			FormatMarkdownLinkCommerce(cTitle, itemURL),
			formatCommerceSKUDisplay(skuPtr, false),
			formatGenericMoneyDisplay(price, cur),
		})
	}
	if len(records) == 0 {
		return nil
	}
	pageTitle := SanitizeCommerceField(doc.Text("h1.page-heading, h1"), 300)
	if pageTitle == "" {
		pageTitle = fmt.Sprintf("%s — BigCommerce Catalog (%d products)", strings.ToLower(u.Hostname()), len(records))
	}
	return &PostFetchSiteResult{
		ExtractorID: extractorID,
		Title:       pageTitle,
		Markdown:    "# " + pageTitle + "\n\n" + FormatGFMTable([]string{"Product", "SKU", "Price"}, rows),
		Links:       links,
		Records:     records,
	}
}

type bcSitemapIndexXML struct {
	Sitemaps []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
	} `xml:"sitemap"`
}

type bcURLSetXML struct {
	URLs []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
		Images  []struct {
			Loc string `xml:"loc"`
		} `xml:"image"`
	} `xml:"url"`
}

// FormatBigCommerceXMLSitemap parses BigCommerce `/xmlsitemap.php` (`<sitemapindex>` or `<urlset>`)
// into a GFM table, validated `Links`, and `CatalogRecord[]`. Fails open (`nil`) on non-XML responses.
func FormatBigCommerceXMLSitemap(rawBody, origURL string) *TwinFormattedDoc {
	trimmed := strings.TrimSpace(strings.TrimPrefix(rawBody, "\ufeff"))
	if trimmed == "" || (!strings.Contains(trimmed, "<urlset") && !strings.Contains(trimmed, "<sitemapindex")) {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(origURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	host := strings.ToLower(u.Hostname())

	if strings.Contains(trimmed, "<sitemapindex") {
		var idx bcSitemapIndexXML
		if err := xml.Unmarshal([]byte(trimmed), &idx); err != nil || len(idx.Sitemaps) == 0 {
			return nil
		}
		capItems := len(idx.Sitemaps)
		if capItems > 500 {
			capItems = 500
		}
		rows := make([][]string, 0, capItems)
		links := make([]string, 0, capItems)
		for i := 0; i < capItems; i++ {
			sm := idx.Sitemaps[i]
			loc := NormalizePublicCommerceImageURL(sm.Loc)
			if loc == "" {
				continue
			}
			links = append(links, loc)
			lm := "-"
			if ts := SanitizeCommerceTimestamp(sm.LastMod, 40); ts != nil {
				lm = *ts
			}
			safeLoc := extract.PercentEncodeUnsafeRecordURLChars(loc)
			rows = append(rows, []string{FormatMarkdownLinkCommerce(safeLoc, loc), lm})
		}
		if len(rows) == 0 {
			return nil
		}
		title := fmt.Sprintf("%s — BigCommerce XML Sitemap Index (%d sitemaps)", host, len(rows))
		return &TwinFormattedDoc{
			Title:    title,
			Markdown: "# " + title + "\n\n" + FormatGFMTable([]string{"Sitemap URL", "Last Modified"}, rows),
			Links:    links,
		}
	}

	var us bcURLSetXML
	if err := xml.Unmarshal([]byte(trimmed), &us); err != nil || len(us.URLs) == 0 {
		return nil
	}
	capItems := len(us.URLs)
	if capItems > 500 {
		capItems = 500
	}
	rows := make([][]string, 0, capItems)
	links := make([]string, 0, capItems)
	records := make([]CatalogRecord, 0, capItems)
	for i := 0; i < capItems; i++ {
		entry := us.URLs[i]
		loc := NormalizePublicCommerceImageURL(entry.Loc)
		if loc == "" {
			continue
		}
		links = append(links, loc)
		lmPtr := SanitizeCommerceTimestamp(entry.LastMod, 40)
		lm := "-"
		if lmPtr != nil {
			lm = *lmPtr
		}
		imgURL := ""
		if len(entry.Images) > 0 {
			imgURL = NormalizePublicCommerceImageURL(entry.Images[0].Loc)
		}
		imgCell := "-"
		imgs := []string{}
		if imgURL != "" {
			imgCell = extract.PercentEncodeUnsafeRecordURLChars(imgURL)
			imgs = []string{imgURL}
		}
		parsedLoc, _ := url.Parse(loc)
		handle := ""
		if parsedLoc != nil {
			handle = strings.Trim(parsedLoc.Path, "/")
		}
		safeLoc := extract.PercentEncodeUnsafeRecordURLChars(loc)
		rows = append(rows, []string{FormatMarkdownLinkCommerce(safeLoc, loc), lm, imgCell})
		records = append(records, CatalogRecord{
			Platform:  "bigcommerce",
			Origin:    origin,
			ProductID: handle,
			Handle:    handle,
			URL:       loc,
			Title:     handle,
			Tags:      []string{},
			UpdatedAt: lmPtr,
			Images:    &imgs,
			Options:   []CatalogOption{},
			Variants:  []CatalogVariantRecord{},
		})
	}
	if len(rows) == 0 {
		return nil
	}
	title := fmt.Sprintf("%s — BigCommerce XML Sitemap (%d URLs)", host, len(rows))
	return &TwinFormattedDoc{
		Title:    title,
		Markdown: "# " + title + "\n\n" + FormatGFMTable([]string{"URL", "Last Modified", "Image"}, rows),
		Links:    links,
		Records:  records,
	}
}
