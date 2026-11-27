package catalog

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// ShopifyFeedFormatOptions configures FormatShopifyProductsFeedTwin.
type ShopifyFeedFormatOptions struct {
	TwinURL  string `json:"twinUrl,omitempty"`
	Currency string `json:"currency,omitempty"`
}

// FormatShopifyProductsFeedTwin formats a `/products.json` or `/collections/<h>/products.json` feed page.
func FormatShopifyProductsFeedTwin(rawBody, origURL string, opts ...ShopifyFeedFormatOptions) *TwinFormattedDoc {
	data, ok := parseJSONObjectCommerce(rawBody)
	if !ok {
		return nil
	}
	rawProducts, isArr := data["products"].([]any)
	if !isArr {
		return nil
	}
	var fmtOpt ShopifyFeedFormatOptions
	if len(opts) > 0 {
		fmtOpt = opts[0]
	}
	u, err := url.Parse(strings.TrimSpace(origURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	queryURL := u
	if strings.TrimSpace(fmtOpt.TwinURL) != "" {
		if tu, errT := url.Parse(strings.TrimSpace(fmtOpt.TwinURL)); errT == nil && tu.Scheme != "" && tu.Host != "" {
			queryURL = tu
		}
	}
	q := queryURL.Query()
	page := 1
	if p, errP := strconv.Atoi(q.Get("page")); errP == nil && p > 1 {
		page = p
	}
	limit := 30
	if l, errL := strconv.Atoi(q.Get("limit")); errL == nil && l > 0 {
		if l > 250 {
			limit = 250
		} else {
			limit = l
		}
	}

	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	var normOpts *ShopifyNormalizeOptions
	if strings.TrimSpace(fmtOpt.Currency) != "" {
		normOpts = &ShopifyNormalizeOptions{Currency: fmtOpt.Currency}
	}
	records := make([]CatalogRecord, 0, len(rawProducts))
	for _, rpAny := range rawProducts {
		if rp, okM := rpAny.(map[string]any); okM {
			if norm := NormalizeShopifyProductRecord(rp, origin, normOpts); norm != nil {
				records = append(records, *norm)
			}
		}
	}

	if tTwin := strings.TrimSpace(fmtOpt.TwinURL); tTwin != "" &&
		!strings.EqualFold(tTwin, strings.TrimSpace(origURL)) &&
		!strings.HasSuffix(strings.ToLower(u.Path), ".json") &&
		len(records) == 0 {
		// Fail open cleanly to origin collection HTML when a pre-fetch collection twin returns products: [].
		return nil
	}

	returned := len(records)
	hasMore := returned > 0 && returned >= limit
	nextURL := ""
	if hasMore {
		nextU := *queryURL
		nq := nextU.Query()
		nq.Set("page", strconv.Itoa(page+1))
		if !nq.Has("limit") {
			nq.Set("limit", strconv.Itoa(limit))
		}
		nextU.RawQuery = nq.Encode()
		nextURL = nextU.String()
	}

	host := strings.ToLower(u.Hostname())
	scopeLabel := host
	rawPath := queryURL.EscapedPath()
	if rawPath == "" {
		rawPath = queryURL.Path
	}
	if colMatch := reShopifyCollectionURL.FindStringSubmatch(rawPath); len(colMatch) == 2 {
		if decCol, okDec := SafeDecodeURIComponent(colMatch[1]); okDec && decCol != "" {
			scopeLabel = fmt.Sprintf("%s (%s)", host, decCol)
		}
	} else if colMatch := reShopifyColPath.FindStringSubmatch(u.EscapedPath()); len(colMatch) == 2 {
		if decCol, okDec := SafeDecodeURIComponent(colMatch[1]); okDec && decCol != "" {
			scopeLabel = fmt.Sprintf("%s (%s)", host, decCol)
		}
	}
	totalVariants := 0
	for _, r := range records {
		totalVariants += len(r.Variants)
	}
	title := fmt.Sprintf("%s — Shopify Catalog Inventory (Page %d, %d products)", scopeLabel, page, returned)

	moreLine := "- **Has More Pages**: No"
	if hasMore {
		moreLine = "- **Has More Pages**: Yes (" + FormatMarkdownLinkCommerce(fmt.Sprintf("Page %d", page+1), nextURL) + ")"
	}
	summaryBullets := strings.Join([]string{
		"- **Store Origin**: " + origin,
		fmt.Sprintf("- **Page**: %d (%d products, %d variants)", page, returned, totalVariants),
		moreLine,
	}, "\n")

	rowCap := len(records)
	if rowCap > 120 {
		rowCap = 120
	}
	links := make([]string, 0, rowCap)
	rows := make([][]string, 0, rowCap)
	for i := 0; i < rowCap; i++ {
		r := records[i]
		links = append(links, r.URL)
		var minP, maxP *float64
		availCount := 0
		anyKnownAvail := false
		var skuSamples []string
		seenSKU := make(map[string]bool)
		for _, v := range r.Variants {
			if v.SKU != nil && *v.SKU != "" && !seenSKU[*v.SKU] && len(skuSamples) < 3 {
				seenSKU[*v.SKU] = true
				skuSamples = append(skuSamples, formatCommerceSKUDisplay(v.SKU, false))
			}
			if v.Price != nil {
				pv := *v.Price
				if minP == nil || pv < *minP {
					cp := pv
					minP = &cp
				}
				if maxP == nil || pv > *maxP {
					cp := pv
					maxP = &cp
				}
			}
			if v.Available != nil {
				anyKnownAvail = true
				if *v.Available {
					availCount++
				}
			}
		}
		skuCell := "-"
		if len(skuSamples) > 0 {
			skuCell = strings.Join(skuSamples, ", ")
		}
		priceCell := "-"
		if minP != nil && maxP != nil {
			var c0 *string
			if len(r.Variants) > 0 {
				c0 = r.Variants[0].Currency
			}
			if *minP == *maxP {
				priceCell = formatMoneyDisplay(minP, c0)
			} else {
				priceCell = formatMoneyDisplay(minP, c0) + "–" + formatMoneyDisplay(maxP, c0)
			}
		}
		availCell := fmt.Sprintf("%d variants", len(r.Variants))
		if anyKnownAvail {
			availCell = fmt.Sprintf("%d/%d in stock", availCount, len(r.Variants))
		}
		updatedDisplay := "-"
		if r.UpdatedAt != nil && *r.UpdatedAt != "" {
			if dm := reShopifyDatePrefix.FindString(*r.UpdatedAt); dm != "" {
				updatedDisplay = dm
			} else {
				updatedDisplay = *r.UpdatedAt
			}
		}
		vendorCell := "-"
		if r.Vendor != nil && *r.Vendor != "" {
			vendorCell = *r.Vendor
		}
		typeCell := "-"
		if r.ProductType != nil && *r.ProductType != "" {
			typeCell = *r.ProductType
		}
		rows = append(rows, []string{
			FormatMarkdownLinkCommerce(r.Title, r.URL),
			vendorCell,
			typeCell,
			skuCell,
			strconv.Itoa(len(r.Variants)),
			priceCell,
			availCell,
			updatedDisplay,
		})
	}

	tableSection := "No products returned on this page."
	if len(rows) > 0 {
		tableSection = FormatGFMTable([]string{"Product", "Vendor", "Type", "SKU", "Variants", "Price", "Stock", "Updated"}, rows)
	}
	return &TwinFormattedDoc{
		Title:    title,
		Markdown: strings.Join([]string{"# " + title, summaryBullets, tableSection}, "\n\n"),
		Links:    links,
		Records:  records,
		Pagination: &PaginationInfo{
			Page:     page,
			Returned: returned,
			Limit:    limit,
			HasMore:  hasMore,
			NextURL:  nextURL,
		},
	}
}

func extractEmbeddedShopifyProductJSON(rawHTML string) string {
	doc := extract.ParseHTMLDoc(rawHTML, 2*1024*1024)
	for _, sc := range doc.Select("script", 40) {
		t := strings.ToLower(strings.TrimSpace(sc.AttrOrEmpty("type")))
		if t != "" && t != "application/json" && t != "text/json" {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(sc.AttrOrEmpty("id")))
		_, hasDataProdJSON := sc.Attr("data-product-json")
		_, hasDataProd := sc.Attr("data-product")
		if !hasDataProdJSON && !hasDataProd && !strings.HasPrefix(id, "productjson") {
			continue
		}
		cand := strings.TrimSpace(sc.HTML())
		if parsed, ok := parseJSONObjectCommerce(cand); ok {
			if _, okT := parsed["title"].(string); okT {
				return cand
			}
			if sub, okSub := parsed["product"].(map[string]any); okSub {
				if _, okT := sub["title"].(string); okT {
					return cand
				}
			}
		}
	}

	metaMarker := strings.Index(rawHTML, "var meta = {")
	if metaMarker != -1 && metaMarker < 200_000 {
		if braceRel := strings.IndexByte(rawHTML[metaMarker:], '{'); braceRel >= 0 {
			startBrace := metaMarker + braceRel
			lowTail := strings.ToLower(rawHTML[startBrace:])
			if endRel := strings.Index(lowTail, "</script>"); endRel > 0 && endRel < 200_000 {
				block := rawHTML[startBrace : startBrace+endRel]
				if semiIdx := strings.Index(block, "};"); semiIdx >= 0 {
					if parsed, ok := parseJSONObjectCommerce(block[:semiIdx+1]); ok {
						if p, okP := parsed["product"].(map[string]any); okP && p["id"] != nil {
							if vars, okV := p["variants"].([]any); okV && len(vars) > 0 {
								inferredTitle, _ := p["title"].(string)
								if inferredTitle == "" {
									if fv, okFV := vars[0].(map[string]any); okFV {
										if nm, okNm := fv["name"].(string); okNm {
											inferredTitle = strings.TrimSpace(strings.Split(nm, " - ")[0])
										}
									}
								}
								if inferredTitle != "" {
									clone := make(map[string]any, len(p)+1)
									for k, v := range p {
										clone[k] = v
									}
									clone["title"] = inferredTitle
									if jb, err := marshalNoEscape(clone); err == nil {
										return string(jb)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return ""
}

// ExtractShopifyProductHTML extracts product records and Markdown from a live Shopify product HTML document.
func ExtractShopifyProductHTML(rawURL, rawHTML, _ string, extractorID string) *PostFetchSiteResult {
	if extractorID == "" {
		extractorID = "shopify"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !reShopifyProductPath.MatchString(u.Path) || !IsShopifyHTMLOrHeaders(rawHTML, nil) {
		return nil
	}
	currency := ExtractShopifyCurrencyFromHTML(rawHTML)
	if embedded := extractEmbeddedShopifyProductJSON(rawHTML); embedded != "" {
		if fromEmb := EnrichShopifyProductFromJSON(ShopifyEnrichParams{
			RawJSON:    embedded,
			ProductURL: u.String(),
			Currency:   currency,
		}); fromEmb != nil {
			return &PostFetchSiteResult{
				ExtractorID:   extractorID,
				Title:         fromEmb.Title,
				Description:   fromEmb.Description,
				Author:        fromEmb.Author,
				PublishedTime: fromEmb.PublishedTime,
				Markdown:      fromEmb.Markdown,
				Links:         fromEmb.Links,
				Records:       fromEmb.Records,
			}
		}
	}

	ldObjects := extract.ExtractJSONLDObjects(rawHTML, 100)
	var prodLD map[string]any
	for _, o := range ldObjects {
		if strings.Contains(strings.ToLower(fmt.Sprint(o["@type"])), "product") {
			prodLD = o
			break
		}
	}
	rawName, okName := prodLD["name"].(string)
	if prodLD == nil || !okName {
		return nil
	}
	title := SanitizeCommerceField(rawName, 400)
	if title == "" {
		return nil
	}
	brand := ""
	switch b := prodLD["brand"].(type) {
	case string:
		brand = SanitizeCommerceField(b, 200)
	case map[string]any:
		brand = SanitizeCommerceField(b["name"], 200)
	}
	desc := ""
	if dStr, okD := prodLD["description"].(string); okD {
		desc = SanitizeCommerceField(StripTagsInlineCommerce(dStr), 1200)
	}

	rawOffers := prodLD["hasVariant"]
	if rawOffers == nil {
		rawOffers = prodLD["offers"]
	}
	var offersList []map[string]any
	switch ov := rawOffers.(type) {
	case []any:
		for _, el := range ov {
			if m, okM := el.(map[string]any); okM {
				offersList = append(offersList, m)
			}
		}
	case map[string]any:
		offersList = []map[string]any{ov}
	}

	handle := ""
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	for i, p := range parts {
		if p == "products" && i+1 < len(parts) {
			if dec, okD := SafeDecodeURIComponent(parts[i+1]); okD {
				handle = dec
			}
			break
		}
	}

	if len(offersList) > 60 {
		offersList = offersList[:60]
	}
	variants := make([]CatalogVariantRecord, 0, len(offersList))
	rows := make([][]string, 0, len(offersList))
	for i, off := range offersList {
		subOffer := off
		if arr, okA := off["offers"].([]any); okA && len(arr) > 0 {
			if m0, ok0 := arr[0].(map[string]any); ok0 {
				subOffer = m0
			}
		} else if m0, ok0 := off["offers"].(map[string]any); ok0 {
			subOffer = m0
		}
		rawVName, _ := off["name"].(string)
		rawVName = strings.TrimSpace(rawVName)
		var vTitle *string
		if rawVName != "" && SanitizeCommerceField(rawVName, 240) != title {
			vTitle = cleanVariantTitle(rawVName)
		}
		skuCand := off["sku"]
		if skuCand == nil {
			skuCand = subOffer["sku"]
		}
		sku := sanitizeCommerceSKU(skuCand)
		var barcodeCand any
		for _, bk := range []string{"gtin13", "gtin12", "gtin"} {
			if off[bk] != nil {
				barcodeCand = off[bk]
				break
			}
		}
		if barcodeCand == nil {
			barcodeCand = subOffer["gtin13"]
			if barcodeCand == nil {
				barcodeCand = subOffer["gtin12"]
			}
		}
		barcode := sanitizeCommerceSKU(barcodeCand)

		rawPrice := subOffer["price"]
		if rawPrice == nil {
			rawPrice = subOffer["lowPrice"]
		}
		var price *float64
		if f, okF := jsonNumberToFloatCommerce(rawPrice); okF {
			price = &f
		} else if sP, okS := rawPrice.(string); okS {
			if f, errP := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(sP), ",", ""), 64); errP == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				price = &f
			}
		}
		curRaw, _ := subOffer["priceCurrency"].(string)
		curRaw = strings.ToUpper(strings.TrimSpace(curRaw))
		vCur := currency
		if reISOCurrency3.MatchString(curRaw) {
			vCur = curRaw
		}

		availRaw := jsonScalarToStringCommerce(subOffer["availability"])
		var available *bool
		if reShopifyAvailTrue.MatchString(availRaw) {
			t := true
			available = &t
		} else if reShopifyAvailFalse.MatchString(availRaw) {
			f := false
			available = &f
		}
		var invPol *string
		if reShopifyPreorder.MatchString(availRaw) {
			c := "continue"
			invPol = &c
		}
		imgRaw := off["image"]
		if arr, okA := imgRaw.([]any); okA && len(arr) > 0 {
			imgRaw = arr[0]
		}
		if mI, okM := imgRaw.(map[string]any); okM {
			imgRaw = mI["url"]
		}
		img := strPtrOrNil(NormalizePublicCommerceImageURL(imgRaw))

		vID := jsonScalarToStringCommerce(off["@id"])
		if vID == "" && sku != nil {
			vID = *sku
		}
		if vID == "" {
			vID = strconv.Itoa(i + 1)
		}
		vOpts := []string{}
		if vTitle != nil {
			vOpts = []string{*vTitle}
		}
		variants = append(variants, CatalogVariantRecord{
			VariantID:       vID,
			SKU:             sku,
			Barcode:         barcode,
			Title:           vTitle,
			Options:         vOpts,
			Price:           price,
			Currency:        strPtrOrNil(vCur),
			Available:       available,
			InventoryPolicy: invPol,
			Image:           img,
		})

		statusText := "-"
		if available != nil {
			if *available {
				if invPol != nil && *invPol == "continue" {
					statusText = "Backorder / Preorder"
				} else {
					statusText = "In Stock"
				}
			} else {
				statusText = "Out of Stock"
			}
		} else if availRaw != "" {
			segs := strings.Split(availRaw, "/")
			if last := segs[len(segs)-1]; last != "" {
				statusText = last
			}
		}
		dispTitle := title
		if vTitle != nil {
			dispTitle = *vTitle
		}
		skuCell := "-"
		if sku != nil {
			skuCell = formatCommerceSKUDisplay(sku, false)
		}
		priceCell := "-"
		if price != nil {
			c := vCur
			if c == "" {
				c = "USD"
			}
			priceCell = fmt.Sprintf("%s %.2f", c, *price)
		}
		rows = append(rows, []string{dispTitle, skuCell, priceCell, statusText})
	}

	pubCand := prodLD["releaseDate"]
	if pubCand == nil {
		pubCand = prodLD["datePublished"]
	}
	publishedAt := SanitizeCommerceTimestamp(pubCand, 96)
	updatedAt := SanitizeCommerceTimestamp(prodLD["dateModified"], 96)
	prodID := jsonScalarToStringCommerce(prodLD["productID"])
	if prodID == "" {
		prodID = jsonScalarToStringCommerce(prodLD["sku"])
	}
	if prodID == "" {
		prodID = handle
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	emptyImgs := []string{}
	record := CatalogRecord{
		Platform:        "shopify",
		Origin:          origin,
		ProductID:       prodID,
		Handle:          handle,
		URL:             u.String(),
		Title:           title,
		Vendor:          strPtrOrNil(brand),
		ProductType:     strPtrOrNil(SanitizeCommerceField(prodLD["category"], 200)),
		Tags:            []string{},
		DescriptionText: strPtrAlways(desc),
		PublishedAt:     publishedAt,
		UpdatedAt:       updatedAt,
		Images:          &emptyImgs,
		Options:         []CatalogOption{},
		Variants:        variants,
	}

	var bullets []string
	if brand != "" {
		bullets = append(bullets, "- **Brand**: "+brand)
	}
	if topSKU := sanitizeCommerceSKU(prodLD["sku"]); topSKU != nil {
		bullets = append(bullets, "- **SKU**: "+formatCommerceSKUDisplay(topSKU, true))
	}
	sections := []string{"# " + title}
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	if len(rows) > 0 {
		sections = append(sections, "## Pricing & Availability\n\n"+FormatGFMTable([]string{"Variant", "SKU", "Price", "Status"}, rows))
	}
	if desc != "" {
		sections = append(sections, "## Description\n\n"+desc)
	}
	res := &PostFetchSiteResult{
		ExtractorID: extractorID,
		Title:       title,
		Author:      brand,
		Markdown:    strings.Join(sections, "\n\n"),
		Records:     []CatalogRecord{record},
	}
	if desc != "" {
		res.Description = sliceUTF16Safe(desc, 260)
	}
	return res
}

func shopifyCatalogFirstPage(cfg DeclarativeCatalogConfig, originURLStr, collection string) string {
	perPage := cfg.PerPage
	if perPage <= 0 {
		perPage = 250
	} else if perPage > 250 {
		perPage = 250
	}
	firstTpl := cfg.FirstPageTemplate
	if firstTpl == "" {
		firstTpl = fmt.Sprintf("{origin}/products.json?limit=%d&page=1", perPage)
	}
	colTpl := cfg.CollectionPageTemplate
	if colTpl == "" {
		colTpl = fmt.Sprintf("{origin}/collections/{collection}/products.json?limit=%d&page=1", perPage)
	}
	origin := cleanOriginString(originURLStr)
	col := strings.TrimSpace(collection)
	if col == "" {
		if u, err := url.Parse(originURLStr); err == nil {
			if m := reShopifyColPath.FindStringSubmatch(u.Path); len(m) == 2 {
				col = m[1]
			}
		}
	}
	if col != "" && reShopifyHandleSafe.MatchString(col) {
		out := strings.ReplaceAll(colTpl, "{origin}", origin)
		return strings.ReplaceAll(out, "{collection}", EncodeURIComponent(col))
	}
	return strings.ReplaceAll(firstTpl, "{origin}", origin)
}

func shopifyCatalogParsePage(cfg DeclarativeCatalogConfig, body, originStr, fields string) ([]CatalogRecord, bool, error) {
	parsed, ok := parseJSONObjectCommerce(body)
	if !ok {
		return nil, false, errors.New("non_json_or_invalid_shopify_catalog")
	}
	rawProducts, isArr := parsed["products"].([]any)
	if !isArr {
		return nil, false, errors.New("non_json_or_invalid_shopify_catalog")
	}
	maxImgs := clampProductBound(cfg.MaxImagesPerProduct, DefaultMaxImagesPerProduct)
	maxVars := clampProductBound(cfg.MaxVariantsPerProduct, DefaultMaxVariantsPerProduct)
	origin := cleanOriginString(originStr)
	records := make([]CatalogRecord, 0, len(rawProducts))
	for _, rpAny := range rawProducts {
		if rp, okM := rpAny.(map[string]any); okM {
			if norm := NormalizeShopifyProductRecord(rp, origin, &ShopifyNormalizeOptions{
				Fields:      fields,
				MaxImages:   maxImgs,
				MaxVariants: maxVars,
			}); norm != nil {
				records = append(records, *norm)
			}
		}
	}
	return records, len(rawProducts) == 0, nil
}

func shopifyCatalogNextPage(cfg DeclarativeCatalogConfig, prevURL, body string, pageIndex int) string {
	parsed, ok := parseJSONObjectCommerce(body)
	if !ok {
		return ""
	}
	prods, isArr := parsed["products"].([]any)
	if !isArr || len(prods) == 0 {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(prevURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	perPage := cfg.PerPage
	if perPage <= 0 || perPage > 250 {
		perPage = 250
	}
	q := u.Query()
	curPage := pageIndex + 1
	if curPage < 1 {
		curPage = 1
	}
	if pStr := q.Get("page"); pStr != "" {
		if p, errP := strconv.Atoi(pStr); errP == nil && p >= 1 {
			curPage = p
		} else {
			curPage = 1
		}
	}
	rq := setQueryParamPreservingOrder(u.RawQuery, "page", strconv.Itoa(curPage+1))
	if !q.Has("limit") {
		rq = setQueryParamPreservingOrder(rq, "limit", strconv.Itoa(perPage))
	}
	u.RawQuery = rq
	return u.String()
}
