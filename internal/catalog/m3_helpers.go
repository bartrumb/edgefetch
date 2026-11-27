package catalog

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

var (
	reM3CurrencyCodeWord = newLazyRegexp(`(?i)\b(USD|EUR|GBP|CAD|AUD|CHF|JPY|CNY|SEK|NOK|DKK|PLN|NZD|INR)\b`)
)

func init() {
	extract.RegisterExternalHTMLMode("squarespace_html", func(rawHTML, baseURL, currentMD, extractorID string) *extract.DeclarativePostFetchResult {
		return postFetchResultToExtract(ExtractSquarespaceCommerceHTML(baseURL, rawHTML, currentMD, extractorID))
	})
	extract.RegisterExternalHTMLMode("bigcommerce_html", func(rawHTML, baseURL, currentMD, extractorID string) *extract.DeclarativePostFetchResult {
		return postFetchResultToExtract(ExtractBigCommerceHTML(baseURL, rawHTML, currentMD, extractorID))
	})
	extract.RegisterExternalHTMLMode("sfcc_html", func(rawHTML, baseURL, currentMD, extractorID string) *extract.DeclarativePostFetchResult {
		return postFetchResultToExtract(ExtractSFCCProductHTML(baseURL, rawHTML, currentMD, extractorID))
	})
	extract.RegisterExternalHTMLMode("shopware_magento_html", func(rawHTML, baseURL, currentMD, extractorID string) *extract.DeclarativePostFetchResult {
		return postFetchResultToExtract(ExtractShopwareOrMagentoHTML(baseURL, rawHTML, currentMD, extractorID))
	})

	extract.RegisterExternalCommerceMode("squarespace_json", func(rawBytes []byte, origURL string) (*extract.DeclarativeFormattedDoc, bool) {
		doc := FormatSquarespaceCommerceJSON(string(rawBytes), origURL)
		return twinDocToExtract(doc), doc != nil
	})
	extract.RegisterExternalCommerceMode("bigcommerce_sitemap", func(rawBytes []byte, origURL string) (*extract.DeclarativeFormattedDoc, bool) {
		doc := FormatBigCommerceXMLSitemap(string(rawBytes), origURL)
		return twinDocToExtract(doc), doc != nil
	})
	extract.RegisterExternalCommerceMode("sfcc_variation", func(rawBytes []byte, origURL string) (*extract.DeclarativeFormattedDoc, bool) {
		doc := FormatSFCCProductVariationJSON(string(rawBytes), origURL, "", "")
		return twinDocToExtract(doc), doc != nil
	})
	extract.RegisterExternalCommerceMode("magento2_render_info", func(rawBytes []byte, origURL string) (*extract.DeclarativeFormattedDoc, bool) {
		doc := FormatMagento2RenderInfoJSON(string(rawBytes), origURL, "")
		return twinDocToExtract(doc), doc != nil
	})
}

func catalogRecordsToMaps(recs []CatalogRecord) []map[string]any {
	if len(recs) == 0 {
		return nil
	}
	b, err := json.Marshal(recs)
	if err != nil {
		return nil
	}
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

func postFetchResultToExtract(res *PostFetchSiteResult) *extract.DeclarativePostFetchResult {
	if res == nil {
		return nil
	}
	return &extract.DeclarativePostFetchResult{
		ExtractorID:   res.ExtractorID,
		Title:         res.Title,
		Description:   res.Description,
		Author:        res.Author,
		PublishedTime: res.PublishedTime,
		Markdown:      res.Markdown,
		Links:         res.Links,
		Records:       catalogRecordsToMaps(res.Records),
	}
}

func twinDocToExtract(doc *TwinFormattedDoc) *extract.DeclarativeFormattedDoc {
	if doc == nil {
		return nil
	}
	return &extract.DeclarativeFormattedDoc{
		Title:         doc.Title,
		Description:   doc.Description,
		Author:        doc.Author,
		PublishedTime: doc.PublishedTime,
		Markdown:      doc.Markdown,
		Links:         doc.Links,
		Records:       catalogRecordsToMaps(doc.Records),
	}
}

func resolveSafeSameOriginOrPublicHTTPS(raw string, base *url.URL) string {
	tr := strings.TrimSpace(raw)
	if tr == "" || strings.IndexByte(tr, '\\') >= 0 {
		return ""
	}
	low := strings.ToLower(tr)
	if strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") ||
		strings.HasPrefix(low, "vbscript:") || strings.HasPrefix(low, "mailto:") || strings.HasPrefix(low, "tel:") {
		return ""
	}
	if strings.HasPrefix(tr, "//") {
		if strings.HasPrefix(tr, "///") {
			return ""
		}
		return NormalizePublicCommerceImageURL(tr)
	}
	ref, err := url.Parse(tr)
	if err != nil {
		return ""
	}
	if ref.IsAbs() {
		return NormalizePublicCommerceImageURL(tr)
	}
	if base == nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	if resolved == nil {
		return ""
	}
	return NormalizePublicCommerceImageURL(resolved.String())
}

func parseCommercePriceAndCurrency(raw string) (*float64, *string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	var cur string
	if m := reM3CurrencyCodeWord.FindStringSubmatch(trimmed); len(m) >= 2 {
		cur = strings.ToUpper(m[1])
	} else {
		up := strings.ToUpper(trimmed)
		switch {
		case strings.Contains(up, "US$"):
			cur = "USD"
		case strings.Contains(up, "CA$"), strings.Contains(up, "C$"):
			cur = "CAD"
		case strings.Contains(up, "AU$"), strings.Contains(up, "A$"):
			cur = "AUD"
		case strings.Contains(trimmed, "£"):
			cur = "GBP"
		case strings.Contains(trimmed, "€"):
			cur = "EUR"
		case strings.Contains(trimmed, "$"):
			cur = "USD"
		}
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
	s := strings.TrimRight(span.String(), ".,")
	if s == "" {
		return nil, strPtrOrNil(cur)
	}
	lastComma := strings.LastIndexByte(s, ',')
	lastDot := strings.LastIndexByte(s, '.')
	normalized := s
	if lastComma > lastDot {
		afterComma := s[lastComma+1:]
		if len(afterComma) == 1 || len(afterComma) == 2 {
			normalized = strings.ReplaceAll(s[:lastComma], ".", "") + "." + afterComma
		} else {
			normalized = strings.ReplaceAll(s, ",", "")
		}
	} else {
		normalized = strings.ReplaceAll(s, ",", "")
	}
	f, err := strconv.ParseFloat(normalized, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return nil, strPtrOrNil(cur)
	}
	return &f, strPtrOrNil(cur)
}

func firstJSONLDProductCommerce(rawHTML string) map[string]any {
	objs := extract.ExtractJSONLDObjects(rawHTML, 100)
	for _, o := range objs {
		tStr := strings.ToLower(fmt.Sprint(o["@type"]))
		if strings.Contains(tStr, "product") {
			return o
		}
	}
	return nil
}

func extractJSONLDOffersList(prodLD map[string]any) []map[string]any {
	if prodLD == nil {
		return nil
	}
	rawOffers := prodLD["hasVariant"]
	if rawOffers == nil {
		rawOffers = prodLD["offers"]
	}
	var out []map[string]any
	switch ov := rawOffers.(type) {
	case []any:
		for _, el := range ov {
			if m, ok := el.(map[string]any); ok {
				out = append(out, m)
			}
		}
	case map[string]any:
		if subArr, ok := ov["offers"].([]any); ok && len(subArr) > 0 {
			for _, el := range subArr {
				if m, okM := el.(map[string]any); okM {
					out = append(out, m)
				}
			}
		} else {
			out = append(out, ov)
		}
	}
	return out
}

func formatGenericMoneyDisplay(amount *float64, currency *string) string {
	if amount == nil || math.IsNaN(*amount) || math.IsInf(*amount, 0) {
		return "-"
	}
	cur := "USD"
	if currency != nil && *currency != "" {
		cur = *currency
	}
	return fmt.Sprintf("%s %.2f", cur, *amount)
}

func parseJSONLDPriceOffer(off map[string]any) (price *float64, currency *string, avail *bool) {
	if off == nil {
		return nil, nil, nil
	}
	sub := off
	if arr, ok := off["offers"].([]any); ok && len(arr) > 0 {
		if m0, ok0 := arr[0].(map[string]any); ok0 {
			sub = m0
		}
	} else if m0, ok := off["offers"].(map[string]any); ok {
		sub = m0
	}
	rawP := sub["price"]
	if rawP == nil {
		rawP = sub["lowPrice"]
	}
	if f, ok := jsonNumberToFloatCommerce(rawP); ok && f >= 0 {
		price = &f
	} else if s, okS := rawP.(string); okS {
		p2, c2 := parseCommercePriceAndCurrency(s)
		price = p2
		currency = c2
	}
	if curRaw, ok := sub["priceCurrency"].(string); ok {
		cu := strings.ToUpper(strings.TrimSpace(curRaw))
		if reISOCurrency3.MatchString(cu) {
			currency = &cu
		}
	}
	avStr := strings.ToLower(jsonScalarToStringCommerce(sub["availability"]))
	if strings.Contains(avStr, "outofstock") || strings.Contains(avStr, "soldout") || strings.Contains(avStr, "discontinued") {
		f := false
		avail = &f
	} else if strings.Contains(avStr, "instock") || strings.Contains(avStr, "preorder") || strings.Contains(avStr, "backorder") || strings.Contains(avStr, "onlineonly") {
		t := true
		avail = &t
	}
	return price, currency, avail
}
