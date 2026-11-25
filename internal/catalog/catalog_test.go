package catalog

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSnapshotHashingDiffShrinkLeanAndUCP(t *testing.T) {
	p10 := 10.0
	p20 := 20.0
	p25 := 25.0
	usd := "USD"
	tr := true
	fl := false
	t1 := "2026-01-01T00:00:00Z"
	t2 := "2026-11-25T99:99:99Z"
	imgs := []string{"https://cdn.example.com/p1.jpg"}

	rec1 := CatalogRecord{
		Platform:  "shopify",
		Origin:    "https://shop.example.com",
		ProductID: "1",
		Handle:    "item-1",
		URL:       "https://shop.example.com/products/item-1",
		Title:     "Item 1",
		Tags:      []string{"gear", "outdoor"},
		UpdatedAt: &t1,
		Images:    &imgs,
		Options:   []CatalogOption{},
		Variants: []CatalogVariantRecord{
			{VariantID: "10", Price: &p10, Currency: &usd, Available: &tr, Options: []string{}},
			{VariantID: "11", Price: &p20, Currency: &usd, Available: &fl, Options: []string{}},
		},
	}

	lean := ProjectLeanCatalogRecord(rec1)
	if !lean.Available || lean.PriceMin == nil || *lean.PriceMin != 10.0 || lean.PriceMax == nil || *lean.PriceMax != 20.0 || lean.VariantCount != 2 {
		t.Fatalf("unexpected lean projection: %+v", lean)
	}

	// Bumping UpdatedAt & reordering Tags MUST produce identical product hash!
	rec1Bumped := rec1
	rec1Bumped.UpdatedAt = &t2
	rec1Bumped.Tags = []string{"outdoor", "gear"}
	if ComputeCatalogProductHash(rec1) != ComputeCatalogProductHash(rec1Bumped) {
		t.Fatal("product hash must ignore updatedAt bumps and tag order")
	}

	rec2 := CatalogRecord{
		Platform:  "shopify",
		Origin:    "https://shop.example.com",
		ProductID: "2",
		Handle:    "item-2",
		Title:     "Item 2",
		Variants:  []CatalogVariantRecord{{VariantID: "20", Price: &p20, Currency: &usd, Available: &tr}},
	}
	rec3 := CatalogRecord{
		Platform:  "shopify",
		Origin:    "https://shop.example.com",
		ProductID: "3",
		Handle:    "item-3",
		Title:     "Item 3",
		Variants:  []CatalogVariantRecord{{VariantID: "30", Price: &p10, Currency: &usd, Available: &tr}},
	}
	rec4 := CatalogRecord{
		Platform:  "shopify",
		Origin:    "https://shop.example.com",
		ProductID: "4",
		Handle:    "item-4",
		Title:     "Item 4",
		Variants:  []CatalogVariantRecord{{VariantID: "40", Price: &p10, Currency: &usd, Available: &tr}},
	}

	prevSnap := []CatalogRecord{rec1, rec2, rec3, rec4}
	rec2PriceChanged := rec2
	rec2PriceChanged.Variants = []CatalogVariantRecord{{VariantID: "20", Price: &p25, Currency: &usd, Available: &fl}}
	rec5Added := CatalogRecord{
		Platform:  "shopify",
		Origin:    "https://shop.example.com",
		ProductID: "5",
		Handle:    "item-5",
		Title:     "Item 5",
		Variants:  []CatalogVariantRecord{{VariantID: "50", Price: &p10, Currency: &usd, Available: &tr}},
	}
	currSnap := []CatalogRecord{rec1Bumped, rec2PriceChanged, rec3, rec5Added} // 4 removed, 5 added, 2 price+avail changed, 1 & 3 unchanged

	detailed := ComputeDetailedCatalogSnapshotDiff(prevSnap, currSnap)
	if detailed.Added != 1 || detailed.Removed != 1 || detailed.Changed != 1 || detailed.PriceChanged != 1 || detailed.AvailabilityChanged != 1 || detailed.Unchanged != 2 || detailed.ShrunkOver50Pct {
		t.Fatalf("unexpected detailed diff: %+v", detailed)
	}

	shrunkDiff := ComputeDetailedCatalogSnapshotDiff(prevSnap, []CatalogRecord{rec1})
	if !shrunkDiff.ShrunkOver50Pct || shrunkDiff.PreviousProducts != 4 {
		t.Fatalf("expected >50%% shrink guard to trip on 4 -> 1 drop, got %+v", shrunkDiff)
	}

	ucp := DiscoverUCPEndpointFromRobots("https://shop.example.com", "User-agent: *\nAllow: /\n# /.well-known/ucp\n")
	if ucp == nil || !ucp.Advertised || ucp.Endpoint != "https://shop.example.com/.well-known/ucp" {
		t.Fatalf("unexpected UCP discovery: %+v", ucp)
	}
	if DiscoverUCPEndpointFromRobots("not-a-valid-origin", "/.well-known/ucp") != nil {
		t.Fatal("expected invalid origin rejected in DiscoverUCPEndpointFromRobots")
	}

	if _, ok := IsSafeHTTPSStoreURL("https://shop.example.com.", ""); ok {
		t.Fatal("expected trailing-dot store hostname rejected")
	}
	if _, ok := IsSafeHTTPSStoreURL("https://hub.example.com/", "hub.example.com"); ok {
		t.Fatal("expected selfHost store URL rejected")
	}
	if u, ok := IsSafeHTTPSStoreURL("https://shop.example.com/collections/shoes", "hub.example.com"); !ok || u == nil {
		t.Fatal("expected valid store URL accepted")
	}
}

func TestPageEvaluationNonStorefrontWAFAndFiltering(t *testing.T) {
	// 1. Non-storefront SPA HTML on `auto`: Probe 1 (Shopify 404) -> fallback_wc; Probe 2 (Woo 200 SPA HTML) -> unsupported_storefront!
	step1 := EvaluateCatalogPageResponse(CatalogPageEvalInput{
		CurrentURL:           "https://shop-spa.example.com/products.json?limit=250&page=1",
		OriginWithCollection: "https://shop-spa.example.com",
		Platform:             "shopify",
		Fields:               "lean",
		PagesRead:            0,
		Status:               404,
		Outcome:              "ok",
		Headers:              map[string]string{"content-type": "text/html"},
	}, "<!doctype html><html><body>Not Found</body></html>")
	if step1.Action != "fallback_wc" || !strings.Contains(step1.NextURL, "/wp-json/wc/store/v1/products") {
		t.Fatalf("expected fallback_wc on Shopify 404, got %+v", step1)
	}

	step2 := EvaluateCatalogPageResponse(CatalogPageEvalInput{
		CurrentURL:              step1.NextURL,
		OriginWithCollection:    "https://shop-spa.example.com",
		Platform:                "woocommerce",
		Fields:                  "lean",
		PagesRead:               0,
		TriedAutoFallbackToWC:   true,
		AutoFallbackFromShopify: true,
		Status:                  200,
		Outcome:                 "ok",
		Headers:                 map[string]string{"content-type": "text/html; charset=utf-8"},
	}, "<!doctype html><html><head><title>SHOP</title></head><body><shop-app unresolved>SHOP</shop-app></body></html>")
	if step2.Action != "halt" || !step2.UnsupportedStore || step2.StopReason != "unsupported_storefront" || step2.Challenged {
		t.Fatalf("expected non-storefront SPA to halt cleanly as unsupported_storefront, got %+v", step2)
	}

	// 2. WAF interstitial HTML (`/_Incapsula_Resource`) MUST immediately halt as `challenged` without falling back to WooCommerce!
	wafStep := EvaluateCatalogPageResponse(CatalogPageEvalInput{
		CurrentURL:           "https://protected.example.com/products.json?limit=250&page=1",
		OriginWithCollection: "https://protected.example.com",
		Platform:             "shopify",
		Fields:               "full",
		PagesRead:            0,
		Status:               200,
		Outcome:              "ok",
		Headers:              map[string]string{"content-type": "text/html"},
	}, `<!doctype html><html><body><iframe src="/_Incapsula_Resource?SWJIYLWA=1"></iframe></body></html>`)
	if wafStep.Action != "halt" || !wafStep.Challenged {
		t.Fatalf("expected WAF HTML interstitial to halt as challenged, got %+v", wafStep)
	}

	// 3. Valid JSON containing word "Turnstile" MUST NOT false-positive as challenge!
	okHardware := EvaluateCatalogPageResponse(CatalogPageEvalInput{
		CurrentURL:           "https://hardware.example.com/products.json?limit=250&page=1",
		OriginWithCollection: "https://hardware.example.com",
		Platform:             "shopify",
		Fields:               "full",
		PagesRead:            0,
		CatalogCfg:           DeclarativeCatalogConfig{Platform: "shopify", PauseMs: 2000, PageCap: 10},
		Status:               200,
		Outcome:              "ok",
		Headers:              map[string]string{"content-type": "application/json"},
	}, `{"products":[{"id":1,"handle":"gate","title":"Turnstile gate hardware","tags":["challenge-platform"],"variants":[]}]}`)
	if okHardware.Action != "parsed" || len(okHardware.Items) != 1 {
		t.Fatalf("expected valid Turnstile JSON product to parse cleanly, got %+v", okHardware)
	}

	// 4. FilterCatalogRecords (`vendor`, `productTypes`, `tags`, `inStockOnly`, `minPrice`, `maxPrice`, `query`, `cursor`, `fallbackCurrency`, `lean`)
	vA := "Alpine"
	vB := "Beta"
	tBag := "Bags"
	p50 := 50.0
	p120 := 120.0
	tr := true
	fl := false
	sku1 := "ALP-100"
	recs := []CatalogRecord{
		{
			Platform:    "shopify",
			Origin:      "https://shop.example.com",
			ProductID:   "1",
			Handle:      "alpine-pack",
			Title:       "Alpine Summit Pack",
			Vendor:      &vA,
			ProductType: &tBag,
			Tags:        []string{"ultralight", "waterproof"},
			Variants:    []CatalogVariantRecord{{VariantID: "10", SKU: &sku1, Price: &p120, Available: &tr}},
		},
		{
			Platform:    "shopify",
			Origin:      "https://shop.example.com",
			ProductID:   "2",
			Handle:      "beta-pouch",
			Title:       "Beta Day Pouch",
			Vendor:      &vB,
			ProductType: &tBag,
			Tags:        []string{"casual"},
			Variants:    []CatalogVariantRecord{{VariantID: "20", Price: &p50, Available: &fl}},
		},
	}
	minP := 100.0
	maxP := 150.0
	filtered := FilterCatalogRecords(recs, CatalogRecordFilter{
		Platform:         "shopify",
		Vendors:          []string{"alpine"},
		ProductTypes:     []string{"bags"},
		Tags:             []string{"waterproof"},
		InStockOnly:      true,
		MinPrice:         &minP,
		MaxPrice:         &maxP,
		Query:            "alp-100",
		Fields:           "lean",
		FallbackCurrency: "EUR",
	})
	if filtered.MatchedProducts != 1 || len(filtered.LeanRecords) != 1 || filtered.LeanRecords[0].Currency == nil || *filtered.LeanRecords[0].Currency != "EUR" {
		t.Fatalf("unexpected FilterCatalogRecords output: %+v", filtered)
	}
}

func TestCatalogStoreBoundedLRUConcurrencyAndSingleflightGzip(t *testing.T) {
	store := NewCatalogStore()

	// 1. Non-owner pool (`<= 6`) reserves 2 slots for `owner` (`<= 8` global)
	var releases []func()
	for i := 0; i < 6; i++ {
		tenant := ResolveCatalogTenantBucket(fmt.Sprintf("member_%d", i/2), "", "", "member")
		rel, ok := store.AcquireConcurrencySlot(tenant)
		if !ok {
			t.Fatalf("expected member slot %d to succeed", i)
		}
		releases = append(releases, rel)
	}
	// 7th non-owner must be rejected even though global count is 6 < 8!
	if _, ok := store.AcquireConcurrencySlot(ResolveCatalogTenantBucket("member_extra", "", "", "member")); ok {
		t.Fatal("expected 7th non-owner rejected so 2 slots stay reserved for owner")
	}
	// Owner still acquires its reserved slot!
	ownerRel, ok := store.AcquireConcurrencySlot(ResolveCatalogTenantBucket("owner", "", "", "owner"))
	if !ok {
		t.Fatal("expected owner to acquire reserved slot")
	}
	ownerRel()
	for _, rel := range releases {
		rel()
	}

	// 2. Singleflight coalescing + `<= 2` gunzip reload semaphore
	p9 := 9.99
	tr := true
	sampleNDJSON := SerializeRecordsNDJSON([]CatalogRecord{
		{
			Platform:  "shopify",
			Origin:    "https://gz.example.com",
			ProductID: "1",
			Handle:    "gz-1",
			Title:     "Gzip Item",
			Variants:  []CatalogVariantRecord{{VariantID: "10", Price: &p9, Available: &tr}},
		},
	})
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write([]byte(sampleNDJSON))
	_ = gw.Close()
	gzBytes := gzBuf.Bytes()

	var loaderCalls atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs, err := store.ReloadRecordsCoalesced(context.Background(), "catalog/cat_sf.ndjson.gz", func(context.Context) ([]byte, error) {
				loaderCalls.Add(1)
				time.Sleep(15 * time.Millisecond)
				return gzBytes, nil
			})
			if err != nil || len(recs) != 1 {
				t.Errorf("unexpected coalesced reload result: %v, len=%d", err, len(recs))
			}
		}()
	}
	wg.Wait()
	if loaderCalls.Load() != 1 {
		t.Fatalf("expected 16 concurrent cold reads coalesced onto 1 loader call, got %d", loaderCalls.Load())
	}

	// 10 distinct cold artifacts loaded concurrently must never exceed MaxConcurrentR2Reloads (2)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		artKey := fmt.Sprintf("catalog/cat_multi_%d.ndjson.gz", i)
		go func(k string) {
			defer wg.Done()
			_, err := store.ReloadRecordsCoalesced(context.Background(), k, func(context.Context) ([]byte, error) {
				time.Sleep(10 * time.Millisecond)
				return gzBytes, nil
			})
			if err != nil {
				t.Errorf("reload %s failed: %v", k, err)
			}
		}(artKey)
	}
	wg.Wait()
	stats := store.MemoryStats()
	if stats.PeakReloadsSeen > MaxConcurrentR2Reloads {
		t.Fatalf("expected peak concurrent reloads <= %d, got %d", MaxConcurrentR2Reloads, stats.PeakReloadsSeen)
	}
	if stats.TotalBytes > MaxGlobalCatalogBytes {
		t.Fatalf("expected total bytes <= %d, got %d", MaxGlobalCatalogBytes, stats.TotalBytes)
	}

	now := time.Now()
	store.SetCachedOriginCurrency("https://shop.example.com", "GBP", 10*time.Minute, now)
	if cur, ok := store.GetCachedOriginCurrency("https://shop.example.com", now.Add(5*time.Minute)); !ok || cur != "GBP" {
		t.Fatalf("expected cached origin currency GBP, got %q (ok=%v)", cur, ok)
	}
	if _, ok := store.GetCachedOriginCurrency("https://shop.example.com", now.Add(15*time.Minute)); ok {
		t.Fatal("expected expired origin currency entry evicted")
	}
}
