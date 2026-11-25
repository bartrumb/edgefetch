package catalog

import "encoding/json"

const (
	DefaultMaxImagesPerProduct   = 250
	DefaultMaxVariantsPerProduct = 250

	MaxCatalogInMemoryBytes          = 16 * 1024 * 1024
	MaxGlobalCatalogBytes            = 32 * 1024 * 1024
	MaxPerUserCatalogBytes           = 8 * 1024 * 1024
	MaxCachedCatalogRuns             = 16
	MaxCachedCatalogRunsPerUser      = 4
	MaxConcurrentCatalogPerPrincipal = 2
	MaxConcurrentCatalogGlobal       = 8
	MaxConcurrentCatalogNonOwner     = 6
	MaxConcurrentR2Reloads           = 2
	MaxCatalogTotalSleepMs           = 120_000
	MaxCatalogWallMs                 = 120_000
	MaxR2DecompressedBytes           = 32 * 1024 * 1024
	MaxR2CacheableArtifactBytes      = 8 * 1024 * 1024
	MaxVariantsPerCatalogRun         = 50_000
	MaxRecordSerializedBytes         = 64 * 1024
	MaxCompactHistoryRuns            = 256
	MaxCompactHistoryRunsPerUser     = 32
)

// ValidCatalogPlatforms is the strict allowlist of declarative catalog platforms.
var ValidCatalogPlatforms = map[string]bool{
	"shopify":     true,
	"woocommerce": true,
}

// CatalogOption represents a normalized product option definition (e.g. Size, Color).
type CatalogOption struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// CatalogVariantRecord represents a normalized SKU/variant within a CatalogRecord.
type CatalogVariantRecord struct {
	VariantID         string   `json:"variantId"`
	SKU               *string  `json:"sku"`
	Barcode           *string  `json:"barcode,omitempty"`
	Title             *string  `json:"title"`
	Options           []string `json:"options"`
	Price             *float64 `json:"price"`
	CompareAt         *float64 `json:"compareAt"`
	Currency          *string  `json:"currency"`
	Available         *bool    `json:"available"`
	InventoryPolicy   *string  `json:"inventoryPolicy,omitempty"`
	InventoryQuantity *int     `json:"inventoryQuantity,omitempty"`
	Grams             *int     `json:"grams"`
	Image             *string  `json:"image"`
}

// UnmarshalJSON accepts both canonical CatalogVariantRecord fields and legacy/loose
// caller fields (`id` -> VariantID, `compareAtPrice` -> CompareAt) so hashing never fails.
func (v *CatalogVariantRecord) UnmarshalJSON(data []byte) error {
	type alias CatalogVariantRecord
	var aux struct {
		alias
		LegacyID         json.RawMessage `json:"id"`
		LegacyCompareAtP *float64        `json:"compareAtPrice"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*v = CatalogVariantRecord(aux.alias)
	if v.VariantID == "" && len(aux.LegacyID) > 0 && string(aux.LegacyID) != "null" {
		var s string
		if err := json.Unmarshal(aux.LegacyID, &s); err == nil {
			v.VariantID = s
		} else {
			v.VariantID = string(aux.LegacyID)
		}
	}
	if v.CompareAt == nil && aux.LegacyCompareAtP != nil {
		v.CompareAt = aux.LegacyCompareAtP
	}
	return nil
}

// CatalogRecord represents a platform-neutral normalized e-commerce product record.
// Note: DescriptionText and Images use pointers so `"lean"` mode omits them (`nil`)
// while `"full"` mode always serializes `""` and `[]` (`non-nil`).
type CatalogRecord struct {
	Platform        string                 `json:"platform"`
	Origin          string                 `json:"origin"`
	ProductID       string                 `json:"productId"`
	Handle          string                 `json:"handle"`
	URL             string                 `json:"url"`
	Title           string                 `json:"title"`
	Vendor          *string                `json:"vendor"`
	ProductType     *string                `json:"productType"`
	Tags            []string               `json:"tags"`
	DescriptionText *string                `json:"descriptionText,omitempty"`
	PublishedAt     *string                `json:"publishedAt"`
	UpdatedAt       *string                `json:"updatedAt"`
	Images          *[]string              `json:"images,omitempty"`
	Options         []CatalogOption        `json:"options"`
	Variants        []CatalogVariantRecord `json:"variants"`
}

// UnmarshalJSON accepts both canonical CatalogRecord JSON and partial records (e.g. `id` fallback).
func (r *CatalogRecord) UnmarshalJSON(data []byte) error {
	type alias CatalogRecord
	var aux struct {
		alias
		LegacyID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*r = CatalogRecord(aux.alias)
	if r.ProductID == "" && len(aux.LegacyID) > 0 && string(aux.LegacyID) != "null" {
		var s string
		if err := json.Unmarshal(aux.LegacyID, &s); err == nil {
			r.ProductID = s
		} else {
			r.ProductID = string(aux.LegacyID)
		}
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
	if r.Options == nil {
		r.Options = []CatalogOption{}
	}
	if r.Variants == nil {
		r.Variants = []CatalogVariantRecord{}
	}
	return nil
}

// LeanCatalogRecord is the compact product-level summary emitted when `fields: "lean"`.
type LeanCatalogRecord struct {
	Platform     string   `json:"platform"`
	Origin       string   `json:"origin"`
	ProductID    string   `json:"productId"`
	Handle       string   `json:"handle"`
	URL          string   `json:"url"`
	Title        string   `json:"title"`
	Vendor       *string  `json:"vendor"`
	ProductType  *string  `json:"productType"`
	Available    bool     `json:"available"`
	PriceMin     *float64 `json:"priceMin"`
	PriceMax     *float64 `json:"priceMax"`
	Currency     *string  `json:"currency"`
	Image        *string  `json:"image"`
	VariantCount int      `json:"variantCount"`
	PublishedAt  *string  `json:"publishedAt"`
	UpdatedAt    *string  `json:"updatedAt"`
}

// DeclarativeCatalogConfig configures polite full-store catalog pagination for Shopify or WooCommerce.
type DeclarativeCatalogConfig struct {
	Platform               string `json:"platform"`
	PauseMs                int    `json:"pauseMs"`
	PageCap                int    `json:"pageCap"`
	FirstPageTemplate      string `json:"firstPageTemplate,omitempty"`
	CollectionPageTemplate string `json:"collectionPageTemplate,omitempty"`
	PerPage                int    `json:"perPage,omitempty"`
	MaxVariantsPerProduct  int    `json:"maxVariantsPerProduct,omitempty"`
	MaxImagesPerProduct    int    `json:"maxImagesPerProduct,omitempty"`
}

// PaginationInfo describes feed-level page metadata for twin formatters.
type PaginationInfo struct {
	Page     int    `json:"page"`
	Returned int    `json:"returned"`
	Limit    int    `json:"limit,omitempty"`
	HasMore  bool   `json:"hasMore"`
	NextURL  string `json:"nextUrl,omitempty"`
}

// TwinFormattedDoc holds a formatted Markdown twin document and normalized commerce records.
type TwinFormattedDoc struct {
	Title         string          `json:"title"`
	Description   string          `json:"description,omitempty"`
	Author        string          `json:"author,omitempty"`
	PublishedTime string          `json:"publishedTime,omitempty"`
	Markdown      string          `json:"markdown"`
	Links         []string        `json:"links,omitempty"`
	Records       []CatalogRecord `json:"records,omitempty"`
	Pagination    *PaginationInfo `json:"pagination,omitempty"`
}

// PostFetchSiteResult holds structured post-fetch HTML commerce extraction output.
type PostFetchSiteResult struct {
	ExtractorID   string          `json:"extractorId"`
	Title         string          `json:"title,omitempty"`
	Description   string          `json:"description,omitempty"`
	Author        string          `json:"author,omitempty"`
	PublishedTime string          `json:"publishedTime,omitempty"`
	Markdown      string          `json:"markdown"`
	Links         []string        `json:"links,omitempty"`
	Records       []CatalogRecord `json:"records,omitempty"`
}

// CatalogRunStatus enumerates lifecycle states of a catalog pull.
type CatalogRunStatus string

const (
	StatusRunning     CatalogRunStatus = "running"
	StatusCoolingDown CatalogRunStatus = "cooling_down"
	StatusComplete    CatalogRunStatus = "complete"
	StatusPartial     CatalogRunStatus = "partial"
	StatusChallenged  CatalogRunStatus = "challenged"
)

// CatalogVariantDiffCounts holds variant-level snapshot diff counters.
type CatalogVariantDiffCounts struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Changed int `json:"changed"`
}

// CatalogSnapshotDiff holds product-level and variant-level snapshot diff counters.
type CatalogSnapshotDiff struct {
	Added       int                       `json:"added"`
	Removed     int                       `json:"removed"`
	Changed     int                       `json:"changed"`
	VariantDiff *CatalogVariantDiffCounts `json:"variantDiff,omitempty"`
}

// DetailedCatalogSnapshotDiff extends CatalogSnapshotDiff with price/availability breakdown and shrink guard.
type DetailedCatalogSnapshotDiff struct {
	Added               int                      `json:"added"`
	Removed             int                      `json:"removed"`
	Changed             int                      `json:"changed"`
	PriceChanged        int                      `json:"priceChanged"`
	AvailabilityChanged int                      `json:"availabilityChanged"`
	Unchanged           int                      `json:"unchanged"`
	VariantDiff         CatalogVariantDiffCounts `json:"variantDiff"`
	ShrunkOver50Pct     bool                     `json:"shrunkOver50Pct"`
	PreviousProducts    int                      `json:"previousProducts,omitempty"`
}

// CatalogUCPMetadata describes advertised Universal Commerce Protocol (UCP) endpoints in robots.txt.
type CatalogUCPMetadata struct {
	Advertised bool   `json:"advertised"`
	Endpoint   string `json:"endpoint"`
}

// SnapshotHashBundle maps product IDs and `productId::variantId` keys to deterministic FNV-1a 64-bit hashes.
type SnapshotHashBundle struct {
	Products map[string]string `json:"products"`
	Variants map[string]string `json:"variants"`
}

// CatalogStatusSummary summarizes the status, counts, and diff of a catalog run.
type CatalogStatusSummary struct {
	OK               bool                 `json:"ok"`
	CatalogID        string               `json:"catalogId"`
	Status           CatalogRunStatus     `json:"status"`
	Platform         string               `json:"platform"`
	Origin           string               `json:"origin"`
	Collection       string               `json:"collection,omitempty"`
	Fields           string               `json:"fields,omitempty"`
	Products         int                  `json:"products"`
	Variants         int                  `json:"variants"`
	Pages            int                  `json:"pages"`
	PagesRead        int                  `json:"pagesRead"`
	PauseMs          int                  `json:"pauseMs"`
	DurationMs       int64                `json:"durationMs"`
	Truncated        bool                 `json:"truncated,omitempty"`
	Reason           string               `json:"reason,omitempty"`
	ResumeAt         string               `json:"resumeAt,omitempty"`
	Warning          string               `json:"warning,omitempty"`
	PreviousProducts *int                 `json:"previousProducts,omitempty"`
	ArtifactID       string               `json:"artifactId,omitempty"`
	Diff             *CatalogSnapshotDiff `json:"diff"`
	UCP              *CatalogUCPMetadata  `json:"ucp,omitempty"`
	Blocked          any                  `json:"blocked,omitempty"`
	CreatedAt        string               `json:"createdAt"`
	UpdatedAt        string               `json:"updatedAt"`
}
