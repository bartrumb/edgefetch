package catalog

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// ProjectLeanCatalogRecord projects a full CatalogRecord down to compact product-level summary fields (`fields: "lean"`),
// omitting `tags`, `options`, `images`, `descriptionText`, and `variants[]`.
func ProjectLeanCatalogRecord(rec CatalogRecord) LeanCatalogRecord {
	var minP, maxP *float64
	var currency *string
	available := false
	var fallbackVariantImg *string

	for _, v := range rec.Variants {
		if v.Price != nil && !math.IsNaN(*v.Price) && !math.IsInf(*v.Price, 0) {
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
		if currency == nil && v.Currency != nil && *v.Currency != "" {
			cp := *v.Currency
			currency = &cp
		}
		if v.Available != nil && *v.Available {
			available = true
		}
		if fallbackVariantImg == nil && v.Image != nil && *v.Image != "" {
			cp := *v.Image
			fallbackVariantImg = &cp
		}
	}

	var primaryImg *string
	if rec.Images != nil && len(*rec.Images) > 0 && (*rec.Images)[0] != "" {
		first := (*rec.Images)[0]
		primaryImg = &first
	} else {
		primaryImg = fallbackVariantImg
	}

	return LeanCatalogRecord{
		Platform:     rec.Platform,
		Origin:       rec.Origin,
		ProductID:    rec.ProductID,
		Handle:       rec.Handle,
		URL:          rec.URL,
		Title:        rec.Title,
		Vendor:       rec.Vendor,
		ProductType:  rec.ProductType,
		Available:    available,
		PriceMin:     minP,
		PriceMax:     maxP,
		Currency:     currency,
		Image:        primaryImg,
		VariantCount: len(rec.Variants),
		PublishedAt:  rec.PublishedAt,
		UpdatedAt:    rec.UpdatedAt,
	}
}

// fnv1a64HexUTF16 computes the deterministic 64-bit dual-FNV-1a hex digest over UTF-16 code units,
// preserving 100% upgrade compatibility with persisted D1 `catalog_runs.hashes_json` rows.
func fnv1a64HexUTF16(input string) string {
	var h1 uint32 = 0x811c9dc5
	var h2 uint32 = 0xc9dc5118
	u16Idx := 0
	for _, r := range input {
		if r < 0x10000 {
			c := uint32(r)
			h1 ^= c
			h1 *= 0x01000193
			h2 ^= c ^ uint32(u16Idx&0xff)
			h2 *= 0x01000193
			u16Idx++
		} else {
			sub := r - 0x10000
			hi := uint32(0xd800 + (sub >> 10))
			lo := uint32(0xdc00 + (sub & 0x3ff))
			h1 ^= hi
			h1 *= 0x01000193
			h2 ^= hi ^ uint32(u16Idx&0xff)
			h2 *= 0x01000193
			u16Idx++

			h1 ^= lo
			h1 *= 0x01000193
			h2 ^= lo ^ uint32(u16Idx&0xff)
			h2 *= 0x01000193
			u16Idx++
		}
	}
	return fmt.Sprintf("%08x%08x", h1, h2)
}

type canonicalVariantHashPayload struct {
	VariantID       string   `json:"variantId"`
	SKU             *string  `json:"sku"`
	Barcode         *string  `json:"barcode"`
	Title           *string  `json:"title"`
	Options         []string `json:"options"`
	Price           *float64 `json:"price"`
	CompareAt       *float64 `json:"compareAt"`
	Currency        *string  `json:"currency"`
	Available       *bool    `json:"available"`
	InventoryPolicy *string  `json:"inventoryPolicy"`
	Grams           *int     `json:"grams"`
	Image           *string  `json:"image"`
}

// ComputeCatalogVariantHash computes a deterministic content hash for a single variant.
func ComputeCatalogVariantHash(v CatalogVariantRecord) string {
	opts := v.Options
	if opts == nil {
		opts = []string{}
	}
	payload := canonicalVariantHashPayload{
		VariantID:       v.VariantID,
		SKU:             v.SKU,
		Barcode:         v.Barcode,
		Title:           v.Title,
		Options:         opts,
		Price:           v.Price,
		CompareAt:       v.CompareAt,
		Currency:        v.Currency,
		Available:       v.Available,
		InventoryPolicy: v.InventoryPolicy,
		Grams:           v.Grams,
		Image:           v.Image,
	}
	raw, _ := marshalNoEscape(payload)
	return fnv1a64HexUTF16(string(raw))
}

type canonicalProductHashPayload struct {
	ProductID   string          `json:"productId"`
	Handle      string          `json:"handle"`
	Title       string          `json:"title"`
	Vendor      *string         `json:"vendor"`
	ProductType *string         `json:"productType"`
	Tags        []string        `json:"tags"`
	Options     []CatalogOption `json:"options"`
	Variants    []string        `json:"variants"`
}

// ComputeCatalogProductHash computes a deterministic content hash for a CatalogRecord,
// explicitly ignoring `updatedAt` and `publishedAt` so inventory timestamp bumps do not cause false `changed` diffs.
func ComputeCatalogProductHash(rec CatalogRecord) string {
	sortedVariantHashes := make([]string, len(rec.Variants))
	for i, v := range rec.Variants {
		sortedVariantHashes[i] = v.VariantID + ":" + ComputeCatalogVariantHash(v)
	}
	sort.Strings(sortedVariantHashes)

	sortedTags := make([]string, len(rec.Tags))
	copy(sortedTags, rec.Tags)
	sort.Strings(sortedTags)

	opts := rec.Options
	if opts == nil {
		opts = []CatalogOption{}
	}
	for i := range opts {
		if opts[i].Values == nil {
			opts[i].Values = []string{}
		}
	}

	payload := canonicalProductHashPayload{
		ProductID:   rec.ProductID,
		Handle:      rec.Handle,
		Title:       rec.Title,
		Vendor:      rec.Vendor,
		ProductType: rec.ProductType,
		Tags:        sortedTags,
		Options:     opts,
		Variants:    sortedVariantHashes,
	}
	raw, _ := marshalNoEscape(payload)
	return fnv1a64HexUTF16(string(raw))
}

// BuildSnapshotHashBundle constructs product-level and variant-level hash maps for a catalog snapshot.
func BuildSnapshotHashBundle(records []CatalogRecord) SnapshotHashBundle {
	products := make(map[string]string, len(records))
	variants := make(map[string]string, len(records)*2)
	for _, r := range records {
		pKey := r.ProductID
		if pKey == "" {
			pKey = r.Handle
		}
		if pKey == "" {
			continue
		}
		products[pKey] = ComputeCatalogProductHash(r)
		for _, v := range r.Variants {
			vSub := v.VariantID
			if vSub == "" && v.SKU != nil && *v.SKU != "" {
				vSub = *v.SKU
			}
			if vSub == "" && v.Title != nil && *v.Title != "" {
				vSub = *v.Title
			}
			if vSub == "" {
				vSub = "0"
			}
			variants[pKey+"::"+vSub] = ComputeCatalogVariantHash(v)
		}
	}
	return SnapshotHashBundle{
		Products: products,
		Variants: variants,
	}
}

// ComputeCatalogSnapshotDiff computes added, removed, and changed counts at both product and variant granularity.
func ComputeCatalogSnapshotDiff(prev, curr SnapshotHashBundle) CatalogSnapshotDiff {
	added, removed, changed := 0, 0, 0
	for k, h := range curr.Products {
		prevH, exists := prev.Products[k]
		if !exists {
			added++
		} else if prevH != h {
			changed++
		}
	}
	for k := range prev.Products {
		if _, exists := curr.Products[k]; !exists {
			removed++
		}
	}

	vAdded, vRemoved, vChanged := 0, 0, 0
	for vk, vh := range curr.Variants {
		prevVh, exists := prev.Variants[vk]
		if !exists {
			vAdded++
		} else if prevVh != vh {
			vChanged++
		}
	}
	for vk := range prev.Variants {
		if _, exists := curr.Variants[vk]; !exists {
			vRemoved++
		}
	}

	return CatalogSnapshotDiff{
		Added:   added,
		Removed: removed,
		Changed: changed,
		VariantDiff: &CatalogVariantDiffCounts{
			Added:   vAdded,
			Removed: vRemoved,
			Changed: vChanged,
		},
	}
}

func recordPriceSignature(r CatalogRecord) string {
	parts := make([]string, len(r.Variants))
	for i, v := range r.Variants {
		p := "nil"
		if v.Price != nil {
			p = fmt.Sprintf("%.4f", *v.Price)
		}
		c := "nil"
		if v.CompareAt != nil {
			c = fmt.Sprintf("%.4f", *v.CompareAt)
		}
		cur := ""
		if v.Currency != nil {
			cur = *v.Currency
		}
		parts[i] = fmt.Sprintf("%s:%s:%s:%s", v.VariantID, p, c, cur)
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func recordAvailabilitySignature(r CatalogRecord) string {
	parts := make([]string, len(r.Variants))
	for i, v := range r.Variants {
		a := "nil"
		if v.Available != nil {
			if *v.Available {
				a = "true"
			} else {
				a = "false"
			}
		}
		parts[i] = v.VariantID + ":" + a
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// EvaluateShrinkGuard checks whether the current snapshot dropped strictly below 50% (`>50%` drop)
// of the previous trusted complete snapshot (`currCount < prevCount * 0.5`).
func EvaluateShrinkGuard(prevProductsCount, currProductsCount int) (warning string, previousProducts int, shrunk bool) {
	if prevProductsCount > 0 && currProductsCount*2 < prevProductsCount {
		return "shrink", prevProductsCount, true
	}
	return "", 0, false
}

// ComputeDetailedCatalogSnapshotDiff computes full product/variant diff breakdowns including
// priceChanged, availabilityChanged, unchanged, and `>50%` shrink guard detection.
func ComputeDetailedCatalogSnapshotDiff(prevRecords, currRecords []CatalogRecord) DetailedCatalogSnapshotDiff {
	prevBundle := BuildSnapshotHashBundle(prevRecords)
	currBundle := BuildSnapshotHashBundle(currRecords)
	base := ComputeCatalogSnapshotDiff(prevBundle, currBundle)

	prevByKey := make(map[string]CatalogRecord, len(prevRecords))
	for _, r := range prevRecords {
		k := r.ProductID
		if k == "" {
			k = r.Handle
		}
		if k != "" {
			prevByKey[k] = r
		}
	}

	priceChanged, availChanged, unchanged := 0, 0, 0
	for _, curr := range currRecords {
		k := curr.ProductID
		if k == "" {
			k = curr.Handle
		}
		if k == "" {
			continue
		}
		prevRec, existed := prevByKey[k]
		if !existed {
			continue
		}
		if prevBundle.Products[k] == currBundle.Products[k] {
			unchanged++
			continue
		}
		if recordPriceSignature(prevRec) != recordPriceSignature(curr) {
			priceChanged++
		}
		if recordAvailabilitySignature(prevRec) != recordAvailabilitySignature(curr) {
			availChanged++
		}
	}

	_, prevCount, shrunk := EvaluateShrinkGuard(len(prevRecords), len(currRecords))
	out := DetailedCatalogSnapshotDiff{
		Added:               base.Added,
		Removed:             base.Removed,
		Changed:             base.Changed,
		PriceChanged:        priceChanged,
		AvailabilityChanged: availChanged,
		Unchanged:           unchanged,
		ShrunkOver50Pct:     shrunk,
	}
	if base.VariantDiff != nil {
		out.VariantDiff = *base.VariantDiff
	}
	if shrunk {
		out.PreviousProducts = prevCount
	}
	return out
}

// ApproxUTF8Bytes returns the UTF-8 byte length of s.
func ApproxUTF8Bytes(s string) int {
	return len(s)
}

// ApproxHashBundleBytes estimates the in-memory footprint in bytes of a SnapshotHashBundle.
func ApproxHashBundleBytes(hashes *SnapshotHashBundle) int {
	if hashes == nil {
		return 0
	}
	total := 64
	for k, v := range hashes.Products {
		total += len(k) + len(v) + 48
	}
	for vk, vv := range hashes.Variants {
		total += len(vk) + len(vv) + 48
	}
	return total
}

// ClampCatalogRecord bounds description length, image/variant/tag/option counts, and serialized JSON size (`<= 64 KiB`).
func ClampCatalogRecord(rec CatalogRecord) (CatalogRecord, int) {
	clamped := rec
	if clamped.DescriptionText != nil && len(*clamped.DescriptionText) > 60_000 {
		s := sliceUTF16Safe(*clamped.DescriptionText, 60_000)
		clamped.DescriptionText = &s
	}
	emptyImgs := []string{}
	if clamped.Images != nil {
		imgs := *clamped.Images
		if len(imgs) > DefaultMaxImagesPerProduct {
			imgs = imgs[:DefaultMaxImagesPerProduct]
		}
		cp := make([]string, len(imgs))
		copy(cp, imgs)
		clamped.Images = &cp
	} else {
		clamped.Images = &emptyImgs
	}
	if len(clamped.Variants) > DefaultMaxVariantsPerProduct {
		clamped.Variants = clamped.Variants[:DefaultMaxVariantsPerProduct]
	} else if clamped.Variants == nil {
		clamped.Variants = []CatalogVariantRecord{}
	}
	if len(clamped.Tags) > 128 {
		clamped.Tags = clamped.Tags[:128]
	} else if clamped.Tags == nil {
		clamped.Tags = []string{}
	}
	if len(clamped.Options) > 32 {
		clamped.Options = clamped.Options[:32]
	} else if clamped.Options == nil {
		clamped.Options = []CatalogOption{}
	}

	rawJSON, _ := marshalNoEscape(clamped)
	byteLen := len(rawJSON)
	if byteLen > MaxRecordSerializedBytes {
		if clamped.DescriptionText != nil && len(*clamped.DescriptionText) > 0 {
			keep := len(*clamped.DescriptionText) - (byteLen - MaxRecordSerializedBytes)
			if keep < 0 {
				keep = 0
			}
			if keep > 4096 {
				keep = 4096
			}
			s := sliceUTF16Safe(*clamped.DescriptionText, keep)
			clamped.DescriptionText = &s
			rawJSON, _ = marshalNoEscape(clamped)
			byteLen = len(rawJSON)
		}
		if byteLen > MaxRecordSerializedBytes && len(clamped.Variants) > 32 {
			clamped.Variants = clamped.Variants[:32]
			if clamped.Images != nil && len(*clamped.Images) > 32 {
				imgs := (*clamped.Images)[:32]
				clamped.Images = &imgs
			}
			rawJSON, _ = marshalNoEscape(clamped)
			byteLen = len(rawJSON)
		}
	}
	return clamped, byteLen
}

// SerializeRecordsNDJSON serializes a slice of CatalogRecord values into newline-delimited JSON.
func SerializeRecordsNDJSON(records []CatalogRecord) string {
	if len(records) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, r := range records {
		if b, err := marshalNoEscape(r); err == nil {
			sb.Write(b)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// ParseRecordsNDJSON parses newline-delimited JSON CatalogRecord lines, skipping malformed lines
// and estimating the in-memory LRU cache footprint.
func ParseRecordsNDJSON(ndjson string) ([]CatalogRecord, int) {
	records := make([]CatalogRecord, 0)
	approxBytes := 64
	for _, line := range strings.Split(ndjson, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var rec CatalogRecord
		if err := json.Unmarshal([]byte(trimmed), &rec); err != nil {
			continue
		}
		records = append(records, rec)
		vOverhead := 64
		if len(rec.Variants) > 0 {
			vOverhead = len(rec.Variants) * 64
		}
		approxBytes += len(trimmed) + vOverhead
	}
	return records, approxBytes
}

// DecompressGzipBounded gunzips raw bytes with a hard decompressed ceiling (`maxBytes`),
// immediately aborting if decompressed output exceeds `maxBytes`.
func DecompressGzipBounded(raw []byte, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxR2DecompressedBytes
	}
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		out, err := io.ReadAll(io.LimitReader(gr, int64(maxBytes)+1))
		if err != nil {
			return nil, err
		}
		if len(out) > maxBytes {
			return nil, fmt.Errorf("catalog artifact exceeds %d bytes limit", maxBytes)
		}
		return out, nil
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("catalog artifact exceeds %d bytes limit", maxBytes)
	}
	return raw, nil
}
