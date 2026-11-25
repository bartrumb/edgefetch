package catalog

import (
	"strconv"
	"strings"
)

// CatalogRecordFilter specifies query, attribute, price, availability, and pagination filters over CatalogRecord slices.
type CatalogRecordFilter struct {
	Platform         string   `json:"platform,omitempty"`
	Offset           int      `json:"offset,omitempty"`
	Cursor           string   `json:"cursor,omitempty"`
	Limit            int      `json:"limit,omitempty"`
	Vendors          []string `json:"vendors,omitempty"`
	ProductTypes     []string `json:"productTypes,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	AvailableOnly    bool     `json:"availableOnly,omitempty"`
	InStockOnly      bool     `json:"inStockOnly,omitempty"`
	MinPrice         *float64 `json:"minPrice,omitempty"`
	MaxPrice         *float64 `json:"maxPrice,omitempty"`
	Query            string   `json:"query,omitempty"`
	Fields           string   `json:"fields,omitempty"`
	FallbackCurrency string   `json:"fallbackCurrency,omitempty"`
}

// CatalogFilterOutput holds paginated, filtered, and optionally lean-projected catalog records.
type CatalogFilterOutput struct {
	TotalProducts        int                 `json:"totalProducts"`
	MatchedProducts      int                 `json:"matchedProducts"`
	Offset               int                 `json:"offset"`
	Limit                int                 `json:"limit"`
	Returned             int                 `json:"returned"`
	HasMore              bool                `json:"hasMore"`
	NeedsShopifyCurrency bool                `json:"needsShopifyCurrency,omitempty"`
	FullRecords          []CatalogRecord     `json:"fullRecords,omitempty"`
	LeanRecords          []LeanCatalogRecord `json:"leanRecords,omitempty"`
}

// FilterCatalogRecords filters, slices, backfills currency, and projects (`full` or `lean`) normalized catalog records.
func FilterCatalogRecords(records []CatalogRecord, f CatalogRecordFilter) CatalogFilterOutput {
	offset := f.Offset
	if offset <= 0 && f.Cursor != "" {
		if parsedOff, err := strconv.Atoi(strings.TrimSpace(f.Cursor)); err == nil && parsedOff > 0 {
			offset = parsedOff
		}
	}
	if offset < 0 {
		offset = 0
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 250 {
		limit = 250
	}

	normList := func(in []string) []string {
		var out []string
		for _, s := range in {
			if t := strings.ToLower(strings.TrimSpace(s)); t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	vendorFilters := normList(f.Vendors)
	typeFilters := normList(f.ProductTypes)
	tagFilters := normList(f.Tags)
	queryLow := strings.ToLower(strings.TrimSpace(f.Query))
	availOnly := f.AvailableOnly || f.InStockOnly

	matched := make([]CatalogRecord, 0, len(records))
	for _, r := range records {
		if len(vendorFilters) > 0 {
			rv := ""
			if r.Vendor != nil {
				rv = strings.ToLower(*r.Vendor)
			}
			hit := false
			for _, vf := range vendorFilters {
				if rv == vf || strings.Contains(rv, vf) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		if len(typeFilters) > 0 {
			rt := ""
			if r.ProductType != nil {
				rt = strings.ToLower(*r.ProductType)
			}
			hit := false
			for _, tf := range typeFilters {
				if rt == tf || strings.Contains(rt, tf) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		if len(tagFilters) > 0 {
			hit := false
			for _, tf := range tagFilters {
				for _, rt := range r.Tags {
					rtLow := strings.ToLower(rt)
					if rtLow == tf || strings.Contains(rtLow, tf) {
						hit = true
						break
					}
				}
				if hit {
					break
				}
			}
			if !hit {
				continue
			}
		}
		if availOnly {
			hasAvail := false
			for _, v := range r.Variants {
				if v.Available != nil && *v.Available {
					hasAvail = true
					break
				}
			}
			if !hasAvail {
				continue
			}
		}
		if f.MinPrice != nil || f.MaxPrice != nil {
			priceOK := false
			for _, v := range r.Variants {
				if v.Price == nil {
					continue
				}
				if f.MinPrice != nil && *v.Price < *f.MinPrice {
					continue
				}
				if f.MaxPrice != nil && *v.Price > *f.MaxPrice {
					continue
				}
				priceOK = true
				break
			}
			if !priceOK {
				continue
			}
		}
		if queryLow != "" {
			var sb strings.Builder
			sb.WriteString(strings.ToLower(r.Title))
			sb.WriteByte(' ')
			sb.WriteString(strings.ToLower(r.Handle))
			if r.Vendor != nil {
				sb.WriteByte(' ')
				sb.WriteString(strings.ToLower(*r.Vendor))
			}
			if r.ProductType != nil {
				sb.WriteByte(' ')
				sb.WriteString(strings.ToLower(*r.ProductType))
			}
			for _, t := range r.Tags {
				sb.WriteByte(' ')
				sb.WriteString(strings.ToLower(t))
			}
			for _, v := range r.Variants {
				if v.SKU != nil {
					sb.WriteByte(' ')
					sb.WriteString(strings.ToLower(*v.SKU))
				}
				if v.Title != nil {
					sb.WriteByte(' ')
					sb.WriteString(strings.ToLower(*v.Title))
				}
			}
			if !strings.Contains(sb.String(), queryLow) {
				continue
			}
		}
		matched = append(matched, r)
	}

	var sliced []CatalogRecord
	if offset < len(matched) {
		end := offset + limit
		if end > len(matched) {
			end = len(matched)
		}
		sliced = make([]CatalogRecord, end-offset)
		for i := range sliced {
			src := matched[offset+i]
			varsCopy := make([]CatalogVariantRecord, len(src.Variants))
			copy(varsCopy, src.Variants)
			src.Variants = varsCopy
			sliced[i] = src
		}
	} else {
		sliced = []CatalogRecord{}
	}

	needsCurrency := false
	if f.FallbackCurrency != "" {
		sliced = ApplyShopifyCurrencyBackfill(sliced, f.FallbackCurrency)
	} else if f.Platform == "shopify" {
		for _, rec := range sliced {
			for _, v := range rec.Variants {
				if v.Currency == nil || *v.Currency == "" {
					needsCurrency = true
					break
				}
			}
			if needsCurrency {
				break
			}
		}
	}

	out := CatalogFilterOutput{
		TotalProducts:        len(records),
		MatchedProducts:      len(matched),
		Offset:               offset,
		Limit:                limit,
		Returned:             len(sliced),
		HasMore:              offset+len(sliced) < len(matched),
		NeedsShopifyCurrency: needsCurrency,
	}
	if f.Fields == "lean" && !needsCurrency {
		lean := make([]LeanCatalogRecord, len(sliced))
		for i, r := range sliced {
			lean[i] = ProjectLeanCatalogRecord(r)
		}
		out.LeanRecords = lean
	} else {
		out.FullRecords = sliced
	}
	return out
}
