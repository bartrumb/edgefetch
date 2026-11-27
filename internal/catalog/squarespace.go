package catalog

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// IsSquarespaceCommerceHTMLOrHeaders detects Squarespace Commerce storefronts structurally
// from HTTP headers or bounded HTML markers (never matching non-commerce Squarespace blogs).
func IsSquarespaceCommerceHTMLOrHeaders(rawHTML string, headers map[string]string) bool {
	hasPlatform := false
	if len(headers) > 0 {
		if srv := strings.ToLower(readHeaderCaseInsensitive(headers, "server")); strings.Contains(srv, "squarespace") {
			hasPlatform = true
		}
		if readHeaderCaseInsensitive(headers, "x-sqsp-request-id") != "" {
			hasPlatform = true
		}
	}
	if rawHTML == "" {
		return false
	}
	slice := rawHTML
	if len(slice) > 120_000 {
		slice = slice[:120_000]
	}
	if !hasPlatform {
		hasPlatform = strings.Contains(slice, "Static.SQUARESPACE_CONTEXT") ||
			strings.Contains(slice, "<!-- This is Squarespace. -->") ||
			strings.Contains(slice, "squarespace-cdn.com") ||
			strings.Contains(slice, "assets.squarespace.com") ||
			strings.Contains(slice, "static1.squarespace.com")
	}
	if !hasPlatform {
		return false
	}
	return strings.Contains(slice, "ProductList") ||
		strings.Contains(slice, "product-item") ||
		strings.Contains(slice, "ProductItem") ||
		strings.Contains(slice, "sqs-add-to-cart") ||
		strings.Contains(slice, "sqs-product") ||
		strings.Contains(slice, "data-item-id") ||
		strings.Contains(slice, "storePageId") ||
		strings.Contains(slice, `"productType"`) ||
		strings.Contains(slice, "products-flex-container")
}

// ResolveSquarespaceCommerceTwinURL appends `?format=json-pretty` on safe public HTTPS URLs
// unless `format=json` / `format=json-pretty` is already present.
func ResolveSquarespaceCommerceTwinURL(rawURL string) string {
	u, ok := IsSafeHTTPSStoreURL(rawURL, "")
	if !ok || u == nil {
		return ""
	}
	q := u.Query()
	curFmt := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if curFmt == "json-pretty" || curFmt == "json" {
		return ""
	}
	u.RawQuery = setQueryParamPreservingOrder(u.RawQuery, "format", "json-pretty")
	return u.String()
}

func parseSquarespaceMoney(raw map[string]any, fallbackCents any) (*float64, *string) {
	if raw != nil {
		var cur *string
		if c, ok := raw["currency"].(string); ok {
			cu := strings.ToUpper(strings.TrimSpace(c))
			if reISOCurrency3.MatchString(cu) {
				cur = &cu
			}
		}
		if val := raw["value"]; val != nil {
			if f, ok := jsonNumberToFloatCommerce(val); ok && f >= 0 {
				return &f, cur
			}
			if s, ok := val.(string); ok {
				if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 {
					return &f, cur
				}
			}
		}
		if cents := raw["decimalValue"]; cents != nil {
			if s, ok := cents.(string); ok {
				if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 {
					return &f, cur
				}
			}
		}
	}
	if fallbackCents != nil {
		if f, ok := jsonNumberToFloatCommerce(fallbackCents); ok && f >= 0 {
			scaled := math.Round(f) / 100.0
			return &scaled, nil
		}
	}
	return nil, nil
}

func sanitizeSquarespaceTimestamp(raw any) *string {
	if raw == nil {
		return nil
	}
	if f, ok := jsonNumberToFloatCommerce(raw); ok && f > 1e11 {
		ts := time.UnixMilli(int64(f)).UTC().Format(time.RFC3339)
		return &ts
	}
	return SanitizeCommerceTimestamp(raw, 96)
}

func normalizeSquarespaceItemRecord(rawItem map[string]any, origin string, pageURL *url.URL) (*CatalogRecord, bool) {
	if rawItem == nil {
		return nil, false
	}
	sc, _ := rawItem["structuredContent"].(map[string]any)
	rawVars, hasVars := []any(nil), false
	if sc != nil {
		rawVars, hasVars = sc["variants"].([]any)
	}
	if sc == nil && rawItem["variants"] == nil && rawItem["priceMoney"] == nil && rawItem["price"] == nil {
		return nil, false
	}

	title := SanitizeCommerceField(rawItem["title"], 400)
	if title == "" {
		return nil, false
	}
	prodID := jsonScalarToStringCommerce(rawItem["id"])
	handle := strings.TrimSpace(jsonScalarToStringCommerce(rawItem["urlId"]))
	if handle == "" {
		handle = prodID
	}

	itemURL := origin
	if fu, ok := rawItem["fullUrl"].(string); ok && strings.TrimSpace(fu) != "" {
		if resolved := resolveSafeSameOriginOrPublicHTTPS(fu, pageURL); resolved != "" {
			itemURL = resolved
		}
	} else if handle != "" {
		itemURL = origin + "/" + EncodeURIComponent(handle)
	}

	var productType *string
	if cats, ok := rawItem["categories"].([]any); ok && len(cats) > 0 {
		if c0 := SanitizeCommerceField(jsonScalarToStringCommerce(cats[0]), 200); c0 != "" {
			productType = &c0
		}
	}
	tags := make([]string, 0)
	if rawTags, ok := rawItem["tags"].([]any); ok {
		for _, t := range rawTags {
			if ct := SanitizeCommerceField(jsonScalarToStringCommerce(t), 120); ct != "" {
				tags = append(tags, ct)
			}
		}
	}

	imgs := make([]string, 0)
	seenImgs := make(map[string]bool)
	addImg := func(raw any) {
		if u := NormalizePublicCommerceImageURL(raw); u != "" && !seenImgs[u] && len(imgs) < DefaultMaxImagesPerProduct {
			seenImgs[u] = true
			imgs = append(imgs, u)
		}
	}
	addImg(rawItem["assetUrl"])
	if gallery, ok := rawItem["items"].([]any); ok {
		for _, g := range gallery {
			if gm, okM := g.(map[string]any); okM {
				addImg(gm["assetUrl"])
			}
		}
	}

	optMap := make(map[string][]string)
	optOrder := make([]string, 0)
	variants := make([]CatalogVariantRecord, 0)

	if hasVars && len(rawVars) > 0 {
		if len(rawVars) > DefaultMaxVariantsPerProduct {
			rawVars = rawVars[:DefaultMaxVariantsPerProduct]
		}
		for idx, rvAny := range rawVars {
			rv, okM := rvAny.(map[string]any)
			if !okM {
				continue
			}
			vID := jsonScalarToStringCommerce(rv["id"])
			if vID == "" {
				vID = strconv.Itoa(idx + 1)
			}
			vSKU := sanitizeCommerceSKU(rv["sku"])
			pm, _ := rv["priceMoney"].(map[string]any)
			price, cur := parseSquarespaceMoney(pm, rv["price"])

			var compareAt *float64
			onSale, _ := rv["onSale"].(bool)
			if onSale {
				spm, _ := rv["salePriceMoney"].(map[string]any)
				saleP, saleCur := parseSquarespaceMoney(spm, rv["salePrice"])
				if saleP != nil {
					if price != nil && *price > *saleP {
						compareAt = price
					}
					price = saleP
					if cur == nil {
						cur = saleCur
					}
				}
			}

			var avail *bool
			var invQty *int
			if st, okS := rv["stock"].(map[string]any); okS {
				if unl, okU := st["unlimited"].(bool); okU && unl {
					t := true
					avail = &t
				} else if qf, okQ := jsonNumberToFloatCommerce(st["quantity"]); okQ {
					qi := int(math.Trunc(qf))
					invQty = &qi
					b := qi > 0
					avail = &b
				}
			}

			optVals := make([]string, 0)
			if attrs, okA := rv["attributes"].(map[string]any); okA && len(attrs) > 0 {
				keys := make([]string, 0, len(attrs))
				for k := range attrs {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					ck := SanitizeCommerceField(k, 120)
					cv := SanitizeCommerceField(jsonScalarToStringCommerce(attrs[k]), 120)
					if ck != "" && cv != "" {
						optVals = append(optVals, cv)
						if _, exists := optMap[ck]; !exists {
							optOrder = append(optOrder, ck)
						}
						found := false
						for _, ex := range optMap[ck] {
							if ex == cv {
								found = true
								break
							}
						}
						if !found {
							optMap[ck] = append(optMap[ck], cv)
						}
					}
				}
			}

			var vTitle *string
			if len(optVals) > 0 {
				joined := strings.Join(optVals, " / ")
				vTitle = &joined
			}

			var vImg *string
			if mi, okMI := rv["mainImage"].(map[string]any); okMI {
				if u := NormalizePublicCommerceImageURL(mi["assetUrl"]); u != "" {
					vImg = &u
					addImg(u)
				}
			}
			if vImg == nil && len(imgs) > 0 {
				u0 := imgs[0]
				vImg = &u0
			}

			variants = append(variants, CatalogVariantRecord{
				VariantID:         vID,
				SKU:               vSKU,
				Title:             vTitle,
				Options:           optVals,
				Price:             price,
				CompareAt:         compareAt,
				Currency:          cur,
				Available:         avail,
				InventoryQuantity: invQty,
				Image:             vImg,
			})
		}
	} else if sc != nil {
		pm, _ := sc["priceMoney"].(map[string]any)
		price, cur := parseSquarespaceMoney(pm, sc["price"])
		var compareAt *float64
		if onSale, _ := sc["onSale"].(bool); onSale {
			spm, _ := sc["salePriceMoney"].(map[string]any)
			if sp, scCur := parseSquarespaceMoney(spm, sc["salePrice"]); sp != nil {
				if price != nil && *price > *sp {
					compareAt = price
				}
				price = sp
				if cur == nil {
					cur = scCur
				}
			}
		}
		var avail *bool
		var invQty *int
		if st, okS := sc["stock"].(map[string]any); okS {
			if unl, okU := st["unlimited"].(bool); okU && unl {
				t := true
				avail = &t
			} else if qf, okQ := jsonNumberToFloatCommerce(st["quantity"]); okQ {
				qi := int(math.Trunc(qf))
				invQty = &qi
				b := qi > 0
				avail = &b
			}
		}
		vSKU := sanitizeCommerceSKU(sc["sku"])
		var vImg *string
		if len(imgs) > 0 {
			u0 := imgs[0]
			vImg = &u0
		}
		if price != nil || vSKU != nil || avail != nil {
			variants = append(variants, CatalogVariantRecord{
				VariantID:         prodID,
				SKU:               vSKU,
				Options:           []string{},
				Price:             price,
				CompareAt:         compareAt,
				Currency:          cur,
				Available:         avail,
				InventoryQuantity: invQty,
				Image:             vImg,
			})
		}
	}

	if len(variants) == 0 {
		return nil, false
	}

	options := make([]CatalogOption, 0, len(optOrder))
	for _, k := range optOrder {
		options = append(options, CatalogOption{Name: k, Values: optMap[k]})
	}

	bodyHTML, _ := rawItem["body"].(string)
	if bodyHTML == "" {
		bodyHTML, _ = rawItem["excerpt"].(string)
	}
	descText := StripTagsInlineCommerce(bodyHTML)

	rec := &CatalogRecord{
		Platform:        "squarespace",
		Origin:          origin,
		ProductID:       prodID,
		Handle:          handle,
		URL:             itemURL,
		Title:           title,
		ProductType:     productType,
		Tags:            tags,
		DescriptionText: strPtrAlways(descText),
		PublishedAt:     sanitizeSquarespaceTimestamp(rawItem["publishOn"]),
		UpdatedAt:       sanitizeSquarespaceTimestamp(rawItem["updatedOn"]),
		Images:          &imgs,
		Options:         options,
		Variants:        variants,
	}
	return rec, true
}

// FormatSquarespaceCommerceJSON formats Squarespace `?format=json-pretty` single-product or collection JSON
// into a GFM table + normalized `CatalogRecord[]`.
func FormatSquarespaceCommerceJSON(rawBody, origURL string) *TwinFormattedDoc {
	obj, ok := parseJSONObjectCommerce(rawBody)
	if !ok || obj == nil {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(origURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)

	if itemObj, okItem := obj["item"].(map[string]any); okItem {
		rec, okRec := normalizeSquarespaceItemRecord(itemObj, origin, u)
		if !okRec || rec == nil {
			return nil
		}
		rows := make([][]string, 0, len(rec.Variants))
		for _, v := range rec.Variants {
			vt := rec.Title
			if v.Title != nil && *v.Title != "" {
				vt = *v.Title
			}
			saleCell := "-"
			priceCell := formatGenericMoneyDisplay(v.Price, v.Currency)
			if v.CompareAt != nil {
				saleCell = priceCell
				priceCell = formatGenericMoneyDisplay(v.CompareAt, v.Currency)
			}
			stockCell := "-"
			if v.Available != nil {
				if *v.Available {
					stockCell = "In Stock"
				} else {
					stockCell = "Out of Stock"
				}
			}
			rows = append(rows, []string{
				vt,
				formatCommerceSKUDisplay(v.SKU, false),
				priceCell,
				saleCell,
				stockCell,
			})
		}

		bodyHTML, _ := itemObj["body"].(string)
		bodyMD := strings.TrimSpace(stripNonPublicMarkdownImages(ConvertCommerceHTMLFragmentToMD(bodyHTML, origURL)))
		sections := []string{"# " + rec.Title}
		if rec.ProductType != nil && *rec.ProductType != "" {
			sections = append(sections, "- **Category**: "+*rec.ProductType)
		}
		sections = append(sections, "## Variants & Pricing\n\n"+FormatGFMTable([]string{"Variant", "SKU", "Price", "Sale Price", "Stock"}, rows))
		if bodyMD != "" {
			sections = append(sections, "## Product Details\n\n"+bodyMD)
		}
		return &TwinFormattedDoc{
			Title:       rec.Title,
			Description: sliceUTF16Safe(*rec.DescriptionText, 260),
			Markdown:    strings.Join(sections, "\n\n"),
			Links:       []string{rec.URL},
			Records:     []CatalogRecord{*rec},
		}
	}

	rawItems, okArr := obj["items"].([]any)
	if !okArr || len(rawItems) == 0 {
		return nil
	}
	records := make([]CatalogRecord, 0, len(rawItems))
	for _, itAny := range rawItems {
		if it, okM := itAny.(map[string]any); okM {
			if rec, okR := normalizeSquarespaceItemRecord(it, origin, u); okR && rec != nil {
				records = append(records, *rec)
			}
		}
	}
	if len(records) == 0 {
		return nil
	}

	colTitle := ""
	if col, okCol := obj["collection"].(map[string]any); okCol {
		colTitle = SanitizeCommerceField(col["title"], 300)
	}
	if colTitle == "" {
		colTitle = fmt.Sprintf("%s — Squarespace Store Catalog (%d products)", strings.ToLower(u.Hostname()), len(records))
	}

	rowCap := len(records)
	if rowCap > 120 {
		rowCap = 120
	}
	rows := make([][]string, 0, rowCap)
	links := make([]string, 0, rowCap)
	for i := 0; i < rowCap; i++ {
		r := records[i]
		links = append(links, r.URL)
		var sku *string
		var price *float64
		var cur *string
		var avail *bool
		if len(r.Variants) > 0 {
			v0 := r.Variants[0]
			sku = v0.SKU
			price = v0.Price
			cur = v0.Currency
			avail = v0.Available
		}
		stockCell := "-"
		if avail != nil {
			if *avail {
				stockCell = "In Stock"
			} else {
				stockCell = "Out of Stock"
			}
		}
		catCell := "-"
		if r.ProductType != nil && *r.ProductType != "" {
			catCell = *r.ProductType
		}
		rows = append(rows, []string{
			FormatMarkdownLinkCommerce(r.Title, r.URL),
			formatCommerceSKUDisplay(sku, false),
			formatGenericMoneyDisplay(price, cur),
			stockCell,
			catCell,
		})
	}
	tableMD := FormatGFMTable([]string{"Product", "SKU", "Price", "Stock", "Category"}, rows)
	return &TwinFormattedDoc{
		Title:    colTitle,
		Markdown: "# " + colTitle + "\n\n" + tableMD,
		Links:    links,
		Records:  records,
	}
}

// ExtractSquarespaceCommerceHTML provides a zero-network HTML/JSON-LD fallback when `?format=json-pretty`
// is disallowed by `robots.txt` or returns 403/404.
func ExtractSquarespaceCommerceHTML(rawURL, rawHTML, _ string, extractorID string) *PostFetchSiteResult {
	if extractorID == "" {
		extractorID = "squarespace-commerce"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !IsSquarespaceCommerceHTMLOrHeaders(rawHTML, nil) {
		return nil
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	doc := extract.ParseHTMLDoc(rawHTML, 2*1024*1024)

	if prodLD := firstJSONLDProductCommerce(rawHTML); prodLD != nil {
		title := SanitizeCommerceField(prodLD["name"], 400)
		if title != "" {
			offers := extractJSONLDOffersList(prodLD)
			var price *float64
			var cur *string
			var avail *bool
			if len(offers) > 0 {
				price, cur, avail = parseJSONLDPriceOffer(offers[0])
			}
			skuPtr := sanitizeCommerceSKU(prodLD["sku"])
			desc := SanitizeCommerceField(StripTagsInlineCommerce(jsonScalarToStringCommerce(prodLD["description"])), 1200)
			if price != nil || skuPtr != nil || desc != "" {
				rec := CatalogRecord{
					Platform:        "squarespace",
					Origin:          origin,
					ProductID:       firstNonEmptyCommerce(jsonScalarToStringCommerce(prodLD["sku"]), title),
					Handle:          strings.Trim(u.Path, "/"),
					URL:             u.String(),
					Title:           title,
					Tags:            []string{},
					DescriptionText: strPtrAlways(desc),
					Options:         []CatalogOption{},
					Variants: []CatalogVariantRecord{
						{
							VariantID: "1",
							SKU:       skuPtr,
							Options:   []string{},
							Price:     price,
							Currency:  cur,
							Available: avail,
						},
					},
				}
				rows := [][]string{{
					title,
					formatCommerceSKUDisplay(skuPtr, false),
					formatGenericMoneyDisplay(price, cur),
				}}
				sections := []string{"# " + title, FormatGFMTable([]string{"Product", "SKU", "Price"}, rows)}
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
		}
	}

	cards := doc.Select(".ProductList-item, .product-item, .grid-item", 60)
	if len(cards) == 0 {
		return nil
	}
	records := make([]CatalogRecord, 0, len(cards))
	rows := make([][]string, 0, len(cards))
	links := make([]string, 0, len(cards))
	for idx, card := range cards {
		name := SanitizeCommerceField(card.Text(".ProductList-title, .grid-title, .product-title, h2, h3"), 300)
		if name == "" {
			continue
		}
		href := ""
		if a := card.First("a[href]"); a != nil {
			href = a.AttrOrEmpty("href")
		}
		itemURL := resolveSafeSameOriginOrPublicHTTPS(href, u)
		if itemURL == "" {
			itemURL = u.String()
		} else {
			links = append(links, itemURL)
		}
		priceText := card.Text(".product-price, .sqs-money-native, .ProductList-price")
		price, cur := parseCommercePriceAndCurrency(priceText)
		pid := strings.TrimSpace(card.AttrOrEmpty("data-item-id"))
		if pid == "" {
			pid = strconv.Itoa(idx + 1)
		}
		records = append(records, CatalogRecord{
			Platform:  "squarespace",
			Origin:    origin,
			ProductID: pid,
			Handle:    pid,
			URL:       itemURL,
			Title:     name,
			Tags:      []string{},
			Options:   []CatalogOption{},
			Variants: []CatalogVariantRecord{
				{VariantID: pid, Options: []string{}, Price: price, Currency: cur},
			},
		})
		rows = append(rows, []string{FormatMarkdownLinkCommerce(name, itemURL), formatGenericMoneyDisplay(price, cur)})
	}
	if len(records) == 0 {
		return nil
	}
	title := SanitizeCommerceField(doc.Text("h1"), 300)
	if title == "" {
		title = fmt.Sprintf("%s — Squarespace Store", strings.ToLower(u.Hostname()))
	}
	return &PostFetchSiteResult{
		ExtractorID: extractorID,
		Title:       title,
		Markdown:    "# " + title + "\n\n" + FormatGFMTable([]string{"Product", "Price"}, rows),
		Links:       links,
		Records:     records,
	}
}

func firstNonEmptyCommerce(vals ...string) string {
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}
