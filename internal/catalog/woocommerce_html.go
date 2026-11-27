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

// ExtractWooCommerceProductHTML extracts product records and Markdown from a live WooCommerce product HTML document.
func ExtractWooCommerceProductHTML(rawURL, rawHTML, _ string, extractorID string) *PostFetchSiteResult {
	if extractorID == "" {
		extractorID = "woocommerce"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !IsWooCommerceHTMLOrHeaders(rawHTML, nil) {
		return nil
	}
	doc := extract.ParseHTMLDoc(rawHTML, 2*1024*1024)
	bodyNode := doc.First("body")
	hasSingleClass := false
	if bodyNode != nil {
		for _, tok := range strings.Fields(strings.ToLower(bodyNode.AttrOrEmpty("class"))) {
			if tok == "single-product" {
				hasSingleClass = true
				break
			}
		}
	}
	if !hasSingleClass && !reWooSinglePath.MatchString(u.Path) {
		return nil
	}

	ldObjects := extract.ExtractJSONLDObjects(rawHTML, 100)
	var prodLD map[string]any
	for _, o := range ldObjects {
		if strings.Contains(strings.ToLower(fmt.Sprint(o["@type"])), "product") {
			prodLD = o
			break
		}
	}
	rawTitle := ""
	if prodLD != nil {
		if nm, ok := prodLD["name"].(string); ok && strings.TrimSpace(nm) != "" {
			rawTitle = strings.TrimSpace(nm)
		}
	}
	if rawTitle == "" {
		if h1 := doc.First("h1.product_title"); h1 != nil {
			rawTitle = strings.TrimSpace(h1.Text())
		}
	}
	title := SanitizeCommerceField(rawTitle, 400)
	if title == "" {
		return nil
	}

	rawSKU := ""
	if prodLD != nil {
		if sk, ok := prodLD["sku"].(string); ok && strings.TrimSpace(sk) != "" {
			rawSKU = strings.TrimSpace(sk)
		}
	}
	if rawSKU == "" {
		if sp := doc.First("span.sku"); sp != nil {
			rawSKU = strings.TrimSpace(sp.Text())
		}
	}
	skuPtr := sanitizeCommerceSKU(rawSKU)
	skuStr := ""
	if skuPtr != nil {
		skuStr = *skuPtr
	}

	var offer map[string]any
	if prodLD != nil {
		switch ov := prodLD["offers"].(type) {
		case []any:
			if len(ov) > 0 {
				offer, _ = ov[0].(map[string]any)
			}
		case map[string]any:
			offer = ov
		}
	}
	var price *float64
	if offer != nil {
		if f, ok := jsonNumberToFloatCommerce(offer["price"]); ok {
			price = &f
		} else if sP, okS := offer["price"].(string); okS {
			if f, errP := strconv.ParseFloat(strings.TrimSpace(sP), 64); errP == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				price = &f
			}
		}
	}
	var currency *string
	if offer != nil {
		if cStr, ok := offer["priceCurrency"].(string); ok {
			cUp := strings.ToUpper(strings.TrimSpace(cStr))
			if reISOCurrency3.MatchString(cUp) {
				currency = &cUp
			}
		}
	}
	var available *bool
	if offer != nil {
		availRaw := strings.ToLower(jsonScalarToStringCommerce(offer["availability"]))
		if strings.Contains(availRaw, "instock") {
			t := true
			available = &t
		} else if strings.Contains(availRaw, "outofstock") {
			f := false
			available = &f
		}
	}
	desc := ""
	if prodLD != nil {
		if dStr, ok := prodLD["description"].(string); ok {
			desc = SanitizeCommerceField(StripTagsInlineCommerce(dStr), 1200)
		}
	}
	if price == nil && skuStr == "" && desc == "" {
		return nil
	}

	var ldImgRaw any
	if prodLD != nil {
		ldImgRaw = prodLD["image"]
		if arr, okA := ldImgRaw.([]any); okA && len(arr) > 0 {
			ldImgRaw = arr[0]
		}
		if mI, okM := ldImgRaw.(map[string]any); okM {
			ldImgRaw = mI["url"]
		}
	}
	safeImg := strPtrOrNil(NormalizePublicCommerceImageURL(ldImgRaw))
	imgs := []string{}
	if safeImg != nil {
		imgs = []string{*safeImg}
	}

	var pubCand, updCand any
	if prodLD != nil {
		pubCand = prodLD["releaseDate"]
		if pubCand == nil {
			pubCand = prodLD["datePublished"]
		}
		updCand = prodLD["dateModified"]
	}
	publishedAt := SanitizeCommerceTimestamp(pubCand, 96)
	updatedAt := SanitizeCommerceTimestamp(updCand, 96)

	var nonEmpty []string
	for _, seg := range strings.Split(u.Path, "/") {
		if seg != "" {
			nonEmpty = append(nonEmpty, seg)
		}
	}
	handle := ""
	if len(nonEmpty) > 0 {
		handle = nonEmpty[len(nonEmpty)-1]
	} else {
		handle = reNonAlnumSlug.ReplaceAllString(strings.ToLower(title), "-")
	}
	prodID := skuStr
	if prodID == "" {
		prodID = handle
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	rec := CatalogRecord{
		Platform:        "woocommerce",
		Origin:          origin,
		ProductID:       prodID,
		Handle:          handle,
		URL:             u.String(),
		Title:           title,
		Tags:            []string{},
		DescriptionText: strPtrAlways(desc),
		PublishedAt:     publishedAt,
		UpdatedAt:       updatedAt,
		Images:          &imgs,
		Options:         []CatalogOption{},
		Variants: []CatalogVariantRecord{
			{
				VariantID: prodID,
				SKU:       skuPtr,
				Options:   []string{},
				Price:     price,
				Currency:  currency,
				Available: available,
				Image:     safeImg,
			},
		},
	}

	var bullets []string
	if skuPtr != nil {
		bullets = append(bullets, "- **SKU**: "+formatCommerceSKUDisplay(skuPtr, true))
	}
	if price != nil {
		cur := "USD"
		if currency != nil {
			cur = *currency
		}
		bullets = append(bullets, fmt.Sprintf("- **Price**: %s %.2f", cur, *price))
	}
	if available != nil {
		if *available {
			bullets = append(bullets, "- **Availability**: In Stock")
		} else {
			bullets = append(bullets, "- **Availability**: Out of Stock")
		}
	}
	var sections []string
	sections = append(sections, "# "+title)
	if len(bullets) > 0 {
		sections = append(sections, strings.Join(bullets, "\n"))
	}
	if desc != "" {
		sections = append(sections, "## Description\n\n"+desc)
	}
	res := &PostFetchSiteResult{
		ExtractorID: extractorID,
		Title:       title,
		Markdown:    strings.Join(sections, "\n\n"),
		Links:       []string{u.String()},
		Records:     []CatalogRecord{rec},
	}
	if desc != "" {
		res.Description = sliceUTF16Safe(desc, 260)
	}
	return res
}

// ExtractWooCommerceCatalogHTML extracts a product list from WooCommerce `/product-category/` or `/shop/` HTML
// as a fail-open fallback when the Store API is unavailable or disallowed by robots.txt.
func ExtractWooCommerceCatalogHTML(rawURL, rawHTML, _ string, extractorID string) *PostFetchSiteResult {
	if extractorID == "" {
		extractorID = "woocommerce"
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if !IsWooCommerceHTMLOrHeaders(rawHTML, nil) {
		return nil
	}
	doc := extract.ParseHTMLDoc(rawHTML, 2*1024*1024)
	bodyNode := doc.First("body")
	bodyCls := ""
	if bodyNode != nil {
		bodyCls = " " + strings.ToLower(bodyNode.AttrOrEmpty("class")) + " "
	}
	lowPath := strings.ToLower(u.Path)
	isCatalogPage := strings.Contains(bodyCls, " tax-product_cat ") ||
		strings.Contains(bodyCls, " post-type-archive-product ") ||
		strings.Contains(lowPath, "/product-category/") ||
		strings.HasSuffix(strings.TrimRight(lowPath, "/"), "/shop")
	if !isCatalogPage {
		return nil
	}

	cards := doc.Select("ul.products li.product, .wc-block-grid__product, .products .product", 60)
	if len(cards) == 0 {
		return nil
	}

	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	records := make([]CatalogRecord, 0, len(cards))
	rows := make([][]string, 0, len(cards))
	links := make([]string, 0, len(cards))
	seenURLs := make(map[string]bool)

	for idx, card := range cards {
		rawTitle := ""
		for _, sel := range []string{".woocommerce-loop-product__title", ".wc-block-grid__product-title", "h2", "h3", ".product-title"} {
			if n := card.First(sel); n != nil {
				if t := strings.TrimSpace(n.Text()); t != "" {
					rawTitle = t
					break
				}
			}
		}
		prodTitle := SanitizeCommerceField(rawTitle, 300)
		if prodTitle == "" {
			continue
		}

		prodHref := ""
		if a := card.First("a[href]"); a != nil {
			prodHref = strings.TrimSpace(a.AttrOrEmpty("href"))
		}
		prodURL := resolveSafeSameOriginOrPublicHTTPS(prodHref, u)
		if prodURL == "" {
			prodURL = u.String()
		} else if !seenURLs[prodURL] {
			seenURLs[prodURL] = true
			links = append(links, prodURL)
		}

		skuRaw := ""
		if btn := card.First("[data-product_sku]"); btn != nil {
			skuRaw = btn.AttrOrEmpty("data-product_sku")
		}
		skuPtr := sanitizeCommerceSKU(skuRaw)

		priceText := ""
		for _, psel := range []string{".price ins .amount", ".price .amount", ".wc-block-grid__product-price .amount", ".price", ".wc-block-grid__product-price"} {
			if pn := card.First(psel); pn != nil {
				if pt := strings.TrimSpace(pn.Text()); pt != "" {
					priceText = pt
					break
				}
			}
		}
		price, cur := parseCommercePriceAndCurrency(priceText)

		imgURL := ""
		if im := card.First("img"); im != nil {
			cand := strings.TrimSpace(im.AttrOrEmpty("src"))
			if cand == "" || strings.HasPrefix(strings.ToLower(cand), "data:") {
				cand = strings.TrimSpace(im.AttrOrEmpty("data-src"))
			}
			imgURL = resolveSafeSameOriginOrPublicHTTPS(cand, u)
		}
		imgs := []string{}
		var imgPtr *string
		if imgURL != "" {
			imgs = []string{imgURL}
			imgPtr = &imgURL
		}

		handle := reNonAlnumSlug.ReplaceAllString(strings.ToLower(prodTitle), "-")
		handle = strings.Trim(handle, "-")
		if handle == "" {
			handle = fmt.Sprintf("item-%d", idx+1)
		}
		pid := handle
		if pidNode := card.First("[data-product_id]"); pidNode != nil {
			if v := strings.TrimSpace(pidNode.AttrOrEmpty("data-product_id")); v != "" {
				pid = v
			}
		}
		records = append(records, CatalogRecord{
			Platform:  "woocommerce",
			Origin:    origin,
			ProductID: pid,
			Handle:    handle,
			URL:       prodURL,
			Title:     prodTitle,
			Tags:      []string{},
			Images:    &imgs,
			Options:   []CatalogOption{},
			Variants: []CatalogVariantRecord{
				{
					VariantID: pid,
					SKU:       skuPtr,
					Options:   []string{},
					Price:     price,
					Currency:  cur,
					Image:     imgPtr,
				},
			},
		})
		rows = append(rows, []string{
			FormatMarkdownLinkCommerce(prodTitle, prodURL),
			formatCommerceSKUDisplay(skuPtr, false),
			formatWooMoneyCell(price, cur),
		})
	}

	if len(records) == 0 {
		return nil
	}

	pageTitle := SanitizeCommerceField(doc.Text("h1.woocommerce-products-header__title"), 300)
	if pageTitle == "" {
		pageTitle = SanitizeCommerceField(doc.Text("h1"), 300)
	}
	if pageTitle == "" {
		pageTitle = fmt.Sprintf("%s — WooCommerce Catalog", strings.ToLower(u.Hostname()))
	}

	tableMD := FormatGFMTable([]string{"Product", "SKU", "Price"}, rows)
	return &PostFetchSiteResult{
		ExtractorID: extractorID,
		Title:       pageTitle,
		Markdown:    fmt.Sprintf("# %s\n\n%s", pageTitle, tableMD),
		Links:       links,
		Records:     records,
	}
}

func wooCatalogFirstPage(cfg DeclarativeCatalogConfig, originURLStr, collection string) string {
	perPage := cfg.PerPage
	if perPage <= 0 || perPage > 100 {
		perPage = 100
	}
	firstTpl := cfg.FirstPageTemplate
	if firstTpl == "" {
		firstTpl = fmt.Sprintf("{origin}/wp-json/wc/store/v1/products?per_page=%d&page=1", perPage)
	}
	origin := cleanOriginString(originURLStr)
	base := strings.ReplaceAll(firstTpl, "{origin}", origin)
	if col := strings.TrimSpace(collection); col != "" {
		return base + "&category=" + EncodeURIComponent(col)
	}
	return base
}

func wooCatalogParsePage(cfg DeclarativeCatalogConfig, body, originStr, fields string, headers map[string]string) ([]CatalogRecord, bool, error) {
	parsed, ok := parseJSONValueCommerce(body)
	if !ok {
		return nil, false, errors.New("non_json_or_invalid_woocommerce_catalog")
	}
	items, isArr := parsed.([]any)
	if !isArr {
		return nil, false, errors.New("non_json_or_invalid_woocommerce_catalog")
	}
	perPage := cfg.PerPage
	if perPage <= 0 || perPage > 100 {
		perPage = 100
	}
	maxImgs := clampProductBound(cfg.MaxImagesPerProduct, DefaultMaxImagesPerProduct)
	maxVars := clampProductBound(cfg.MaxVariantsPerProduct, DefaultMaxVariantsPerProduct)
	origin := cleanOriginString(originStr)
	records := make([]CatalogRecord, 0, len(items))
	for _, itAny := range items {
		if it, okM := itAny.(map[string]any); okM {
			if norm := NormalizeWooCommerceProductRecord(it, origin, &WooNormalizeOptions{
				Fields:      fields,
				MaxImages:   maxImgs,
				MaxVariants: maxVars,
			}); norm != nil {
				records = append(records, *norm)
			}
		}
	}
	totalPages, hasTP := readHeaderInt(headers, "x-wp-totalpages")
	done := len(items) == 0 || len(items) < perPage || (hasTP && totalPages <= 1)
	return records, done, nil
}

func setQueryParamPreservingOrder(rawQuery, key, val string) string {
	encPair := url.QueryEscape(key) + "=" + url.QueryEscape(val)
	if rawQuery == "" {
		return encPair
	}
	parts := strings.Split(rawQuery, "&")
	out := make([]string, 0, len(parts)+1)
	replaced := false
	for _, seg := range parts {
		if seg == "" {
			continue
		}
		k := seg
		if eq := strings.IndexByte(seg, '='); eq >= 0 {
			k = seg[:eq]
		}
		if unesc, err := url.QueryUnescape(k); err == nil {
			k = unesc
		}
		if k == key {
			if !replaced {
				out = append(out, encPair)
				replaced = true
			}
			continue
		}
		out = append(out, seg)
	}
	if !replaced {
		out = append(out, encPair)
	}
	return strings.Join(out, "&")
}

func wooCatalogNextPage(cfg DeclarativeCatalogConfig, prevURL, body string, pageIndex int, headers map[string]string) string {
	parsed, ok := parseJSONValueCommerce(body)
	if !ok {
		return ""
	}
	items, isArr := parsed.([]any)
	if !isArr || len(items) == 0 {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(prevURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	perPage := cfg.PerPage
	if perPage <= 0 || perPage > 100 {
		perPage = 100
	}
	q := u.Query()
	pp := perPage
	if ppStr := q.Get("per_page"); ppStr != "" {
		if v, errPP := strconv.Atoi(ppStr); errPP == nil && v >= 1 {
			pp = v
		}
	}
	if len(items) < pp {
		return ""
	}
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
	if totalPages, hasTP := readHeaderInt(headers, "x-wp-totalpages"); hasTP && curPage >= totalPages {
		return ""
	}
	u.RawQuery = setQueryParamPreservingOrder(u.RawQuery, "page", strconv.Itoa(curPage+1))
	return u.String()
}

// ValidateDeclarativeCatalogConfig validates platform allowlist and normalizes pauseMs/pageCap bounds.
func ValidateDeclarativeCatalogConfig(cfg DeclarativeCatalogConfig) (DeclarativeCatalogConfig, error) {
	plat := strings.ToLower(strings.TrimSpace(cfg.Platform))
	if !ValidCatalogPlatforms[plat] {
		return cfg, fmt.Errorf("unsupported declarative catalog platform %q (expected \"shopify\" or \"woocommerce\")", cfg.Platform)
	}
	cfg.Platform = plat
	if cfg.PauseMs <= 0 {
		cfg.PauseMs = 2000
	}
	if cfg.PauseMs < 250 {
		cfg.PauseMs = 250
	}
	if cfg.PageCap <= 0 {
		cfg.PageCap = 200
	} else if cfg.PageCap > 1000 {
		cfg.PageCap = 1000
	}
	return cfg, nil
}

// CatalogSpecFirstPage builds the first pagination URL for a validated DeclarativeCatalogConfig.
func CatalogSpecFirstPage(cfg DeclarativeCatalogConfig, originURLStr, collection string) (string, error) {
	valid, err := ValidateDeclarativeCatalogConfig(cfg)
	if err != nil {
		return "", err
	}
	if valid.Platform == "shopify" {
		return shopifyCatalogFirstPage(valid, originURLStr, collection), nil
	}
	return wooCatalogFirstPage(valid, originURLStr, collection), nil
}

// CatalogSpecParsePage parses a raw JSON catalog page for Shopify or WooCommerce.
func CatalogSpecParsePage(cfg DeclarativeCatalogConfig, body, originStr, fields string, headers map[string]string) ([]CatalogRecord, bool, error) {
	valid, err := ValidateDeclarativeCatalogConfig(cfg)
	if err != nil {
		return nil, false, err
	}
	if valid.Platform == "shopify" {
		return shopifyCatalogParsePage(valid, body, originStr, fields)
	}
	return wooCatalogParsePage(valid, body, originStr, fields, headers)
}

// CatalogSpecNextPage resolves the next page URL (or `""` when pagination is finished) for Shopify or WooCommerce.
func CatalogSpecNextPage(cfg DeclarativeCatalogConfig, prevURL, body string, pageIndex int, headers map[string]string) (string, error) {
	valid, err := ValidateDeclarativeCatalogConfig(cfg)
	if err != nil {
		return "", err
	}
	if valid.Platform == "shopify" {
		return shopifyCatalogNextPage(valid, prevURL, body, pageIndex), nil
	}
	return wooCatalogNextPage(valid, prevURL, body, pageIndex, headers), nil
}
