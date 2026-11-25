package main

import (
	"bytes"
	"encoding/json"

	"github.com/bartrumb/edgefetch/v2/internal/catalog"
)

func init() {
	phase2CatalogRPC = handlePhase2CatalogRPC
	phase2CatalogRawRPC = handlePhase2CatalogRawRPC
}

func handlePhase2CatalogRawRPC(op string, meta json.RawMessage, rawStr string) (any, bool, error) {
	switch op {
	case "commerce_is_shopify_html":
		var m struct {
			Headers map[string]string `json:"headers"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{"ok": catalog.IsShopifyHTMLOrHeaders(rawStr, m.Headers)}, true, nil

	case "commerce_extract_shopify_currency":
		cur := catalog.ExtractShopifyCurrencyFromHTML(rawStr)
		if cur == "" {
			return map[string]any{"currency": nil}, true, nil
		}
		return map[string]any{"currency": cur}, true, nil

	case "commerce_enrich_shopify_json":
		var m struct {
			ProductURL string `json:"productUrl"`
			Currency   string `json:"currency"`
			IsAjaxJS   *bool  `json:"isAjaxJs"`
			AjaxJSBody string `json:"ajaxJsBody"`
		}
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &m); err != nil {
				return nil, true, err
			}
		}
		doc := catalog.EnrichShopifyProductFromJSON(catalog.ShopifyEnrichParams{
			RawJSON:    rawStr,
			ProductURL: m.ProductURL,
			Currency:   m.Currency,
			IsAjaxJS:   m.IsAjaxJS,
			AjaxJSBody: m.AjaxJSBody,
		})
		return map[string]any{"doc": doc}, true, nil

	case "commerce_format_shopify_feed":
		var m struct {
			OrigURL string `json:"origUrl"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{"doc": catalog.FormatShopifyProductsFeedTwin(rawStr, m.OrigURL)}, true, nil

	case "commerce_extract_shopify_html":
		var m struct {
			URL             string `json:"url"`
			CurrentMarkdown string `json:"currentMarkdown"`
			ExtractorID     string `json:"extractorId"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{
			"result": catalog.ExtractShopifyProductHTML(m.URL, rawStr, m.CurrentMarkdown, m.ExtractorID),
		}, true, nil

	case "commerce_is_woocommerce_html":
		var m struct {
			Headers map[string]string `json:"headers"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{"ok": catalog.IsWooCommerceHTMLOrHeaders(rawStr, m.Headers)}, true, nil

	case "commerce_enrich_woocommerce_json":
		var m struct {
			ProductURL     string `json:"productUrl"`
			Slug           string `json:"slug"`
			FallbackBodyMD string `json:"fallbackBodyMd"`
		}
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &m); err != nil {
				return nil, true, err
			}
		}
		doc := catalog.EnrichWooCommerceProductFromStoreAPI(catalog.WooEnrichParams{
			RawJSON:        rawStr,
			ProductURL:     m.ProductURL,
			Slug:           m.Slug,
			FallbackBodyMD: m.FallbackBodyMD,
		})
		return map[string]any{"doc": doc}, true, nil

	case "commerce_format_wc_list":
		var m struct {
			OrigURL string `json:"origUrl"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{"doc": catalog.FormatWCStoreAPIListTwin(rawStr, m.OrigURL)}, true, nil

	case "commerce_format_wc_product":
		var m struct {
			OrigURL string `json:"origUrl"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{"doc": catalog.FormatWCStoreAPIProductTwin(rawStr, m.OrigURL)}, true, nil

	case "commerce_extract_woocommerce_html":
		var m struct {
			URL             string `json:"url"`
			CurrentMarkdown string `json:"currentMarkdown"`
			ExtractorID     string `json:"extractorId"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{
			"result": catalog.ExtractWooCommerceProductHTML(m.URL, rawStr, m.CurrentMarkdown, m.ExtractorID),
		}, true, nil

	case "commerce_spec_parse_page":
		var m struct {
			Config  catalog.DeclarativeCatalogConfig `json:"config"`
			Origin  string                           `json:"origin"`
			Fields  string                           `json:"fields"`
			Headers map[string]string                `json:"headers"`
		}
		if err := json.Unmarshal(meta, &m); err != nil {
			return nil, true, err
		}
		records, done, err := catalog.CatalogSpecParsePage(m.Config, rawStr, m.Origin, m.Fields, m.Headers)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, true, nil
		}
		return map[string]any{"ok": true, "records": records, "done": done}, true, nil

	case "commerce_spec_next_page":
		var m struct {
			Config    catalog.DeclarativeCatalogConfig `json:"config"`
			URL       string                           `json:"url"`
			PageIndex int                              `json:"pageIndex"`
			Headers   map[string]string                `json:"headers"`
		}
		if err := json.Unmarshal(meta, &m); err != nil {
			return nil, true, err
		}
		nextURL, err := catalog.CatalogSpecNextPage(m.Config, m.URL, rawStr, m.PageIndex, m.Headers)
		if err != nil || nextURL == "" {
			return map[string]any{"nextUrl": nil}, true, nil
		}
		return map[string]any{"nextUrl": nextURL}, true, nil

	case "catalog_discover_ucp":
		var m struct {
			Origin string `json:"origin"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{"ucp": catalog.DiscoverUCPEndpointFromRobots(m.Origin, rawStr)}, true, nil

	case "catalog_evaluate_page":
		var in catalog.CatalogPageEvalInput
		if err := json.Unmarshal(meta, &in); err != nil {
			return nil, true, err
		}
		return catalog.EvaluateCatalogPageResponse(in, rawStr), true, nil

	case "catalog_parse_currency_probe":
		cur := catalog.ParseShopifyCurrencyProbe(rawStr)
		if cur == "" {
			return map[string]any{"currency": nil}, true, nil
		}
		return map[string]any{"currency": cur}, true, nil

	case "catalog_parse_ndjson":
		recs, approxBytes := catalog.ParseRecordsNDJSON(rawStr)
		return map[string]any{"records": recs, "bytes": approxBytes}, true, nil

	default:
		return nil, false, nil
	}
}

func handlePhase2CatalogRPC(op string, payload json.RawMessage) (any, bool, error) {
	switch op {
	case "commerce_sanitize_field":
		var p struct {
			Raw    any `json:"raw"`
			MaxLen int `json:"maxLen"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": catalog.SanitizeCommerceField(p.Raw, p.MaxLen)}, true, nil

	case "commerce_sanitize_timestamp":
		var p struct {
			Raw    any `json:"raw"`
			MaxLen int `json:"maxLen"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": catalog.SanitizeCommerceTimestamp(p.Raw, p.MaxLen)}, true, nil

	case "commerce_normalize_image_url":
		var p struct {
			Raw any `json:"raw"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		u := catalog.NormalizePublicCommerceImageURL(p.Raw)
		if u == "" {
			return map[string]any{"url": nil}, true, nil
		}
		return map[string]any{"url": u}, true, nil

	case "commerce_resolve_shopify_twin":
		var p struct {
			ProductURL string `json:"productUrl"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"twin": catalog.ResolveCustomDomainShopifyProductTwinURL(p.ProductURL)}, true, nil

	case "commerce_normalize_shopify_record":
		var p struct {
			RawProd map[string]any                   `json:"rawProd"`
			Origin  string                           `json:"origin"`
			Opts    *catalog.ShopifyNormalizeOptions `json:"opts"`
		}
		dec := json.NewDecoder(bytes.NewReader(payload))
		dec.UseNumber()
		if err := dec.Decode(&p); err != nil {
			return nil, true, err
		}
		return map[string]any{"record": catalog.NormalizeShopifyProductRecord(p.RawProd, p.Origin, p.Opts)}, true, nil

	case "commerce_resolve_woocommerce_twin":
		var p struct {
			ProductURL string `json:"productUrl"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"twin": catalog.ResolveCustomDomainWooCommerceProductTwinURL(p.ProductURL)}, true, nil

	case "commerce_normalize_woocommerce_record":
		var p struct {
			RawProd map[string]any               `json:"rawProd"`
			Origin  string                       `json:"origin"`
			Opts    *catalog.WooNormalizeOptions `json:"opts"`
		}
		dec := json.NewDecoder(bytes.NewReader(payload))
		dec.UseNumber()
		if err := dec.Decode(&p); err != nil {
			return nil, true, err
		}
		return map[string]any{"record": catalog.NormalizeWooCommerceProductRecord(p.RawProd, p.Origin, p.Opts)}, true, nil

	case "commerce_spec_first_page":
		var p struct {
			Config     catalog.DeclarativeCatalogConfig `json:"config"`
			Origin     string                           `json:"origin"`
			Collection string                           `json:"collection"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		firstURL, err := catalog.CatalogSpecFirstPage(p.Config, p.Origin, p.Collection)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, true, nil
		}
		return map[string]any{"ok": true, "url": firstURL}, true, nil

	case "catalog_project_lean":
		var p struct {
			Record catalog.CatalogRecord `json:"record"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"lean": catalog.ProjectLeanCatalogRecord(p.Record)}, true, nil

	case "catalog_variant_hash":
		var p struct {
			Variant catalog.CatalogVariantRecord `json:"variant"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"hash": catalog.ComputeCatalogVariantHash(p.Variant)}, true, nil

	case "catalog_product_hash":
		var p struct {
			Record catalog.CatalogRecord `json:"record"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"hash": catalog.ComputeCatalogProductHash(p.Record)}, true, nil

	case "catalog_snapshot_diff":
		var p struct {
			Prev catalog.SnapshotHashBundle `json:"prev"`
			Curr catalog.SnapshotHashBundle `json:"curr"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"diff": catalog.ComputeCatalogSnapshotDiff(p.Prev, p.Curr)}, true, nil

	case "catalog_approx_hash_bytes":
		var p struct {
			Hashes *catalog.SnapshotHashBundle `json:"hashes"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"bytes": catalog.ApproxHashBundleBytes(p.Hashes)}, true, nil

	case "catalog_validate_store_url":
		var p struct {
			URL      string `json:"url"`
			SelfHost string `json:"selfHost"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		u, ok := catalog.IsSafeHTTPSStoreURL(p.URL, p.SelfHost)
		if !ok || u == nil {
			return map[string]any{"ok": false}, true, nil
		}
		return map[string]any{"ok": true, "normalized": u.String()}, true, nil

	case "catalog_resolve_tenant":
		var p struct {
			CleanUserID  string `json:"cleanUserId"`
			Principal    string `json:"principal"`
			ActiveUserID string `json:"activeUserId"`
			ActiveRole   string `json:"activeRole"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return catalog.ResolveCatalogTenantBucket(p.CleanUserID, p.Principal, p.ActiveUserID, p.ActiveRole), true, nil

	case "catalog_init_pull":
		var req catalog.CatalogInitRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, true, err
		}
		plan, valErr := catalog.InitCatalogPullPlan(req)
		if valErr != nil {
			return map[string]any{"ok": false, "error": valErr.ErrorCode, "message": valErr.Message}, true, nil
		}
		return map[string]any{"ok": true, "plan": plan}, true, nil

	case "catalog_finalize_pull":
		var p struct {
			Records          []catalog.CatalogRecord     `json:"records"`
			DetectedCurrency string                      `json:"detectedCurrency"`
			PrevProducts     *int                        `json:"prevProducts"`
			PrevHashes       *catalog.SnapshotHashBundle `json:"prevHashes"`
			IsComplete       bool                        `json:"isComplete"`
			BuildNDJSON      bool                        `json:"buildNdjson"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		recs := p.Records
		if p.DetectedCurrency != "" {
			recs = catalog.ApplyShopifyCurrencyBackfill(recs, p.DetectedCurrency)
		}
		totalVariants := 0
		for _, r := range recs {
			totalVariants += len(r.Variants)
		}
		currHashes := catalog.BuildSnapshotHashBundle(recs)
		hashesBytes := catalog.ApproxHashBundleBytes(&currHashes)

		var warning string
		var previousProducts *int
		var diff *catalog.CatalogSnapshotDiff
		if p.PrevProducts != nil {
			if w, prevCnt, shrunk := catalog.EvaluateShrinkGuard(*p.PrevProducts, len(recs)); shrunk {
				warning = w
				previousProducts = &prevCnt
			}
		}
		if p.PrevHashes != nil && p.IsComplete {
			d := catalog.ComputeCatalogSnapshotDiff(*p.PrevHashes, currHashes)
			diff = &d
		}
		ndjson := ""
		if p.BuildNDJSON && len(recs) > 0 {
			ndjson = catalog.SerializeRecordsNDJSON(recs)
		}
		out := map[string]any{
			"records":       recs,
			"totalVariants": totalVariants,
			"hashes":        currHashes,
			"hashesBytes":   hashesBytes,
			"diff":          diff,
			"ndjson":        ndjson,
		}
		if warning != "" {
			out["warning"] = warning
			out["previousProducts"] = previousProducts
		}
		return out, true, nil

	case "catalog_filter_records":
		var p struct {
			Records []catalog.CatalogRecord     `json:"records"`
			Filter  catalog.CatalogRecordFilter `json:"filter"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return catalog.FilterCatalogRecords(p.Records, p.Filter), true, nil

	default:
		return nil, false, nil
	}
}
