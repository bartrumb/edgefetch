package hub

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/catalog"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/jobs"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

// HandleJobs serves `POST /v1/jobs`.
func (h *RouteHandler) HandleJobs(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, status := h.ExecuteJobs(r.Context(), payload, r.Header, p.EffectiveOwnerID())
	writeJSON(w, status, out)
}

// ExecuteJobs discovers ATS boards/feeds, parses Greenhouse/Lever/Ashby/JSON-LD postings, and filters/ranks results.
func (h *RouteHandler) ExecuteJobs(ctx context.Context, payload map[string]any, hdr http.Header, ownerID string) (map[string]any, int) {
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.jobs", 1, nil)
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	query := strings.TrimSpace(strField(payload["query"]))
	company := strings.TrimSpace(strField(payload["company"]))
	var seedURLs []string
	addSeed := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			s = "https://" + s
		}
		seedURLs = append(seedURLs, s)
	}
	addSeed(strField(payload["url"]))
	addSeed(strField(payload["domain"]))
	for _, u := range stringSliceField(payload["urls"]) {
		addSeed(u)
	}
	for _, d := range stringSliceField(payload["domains"]) {
		addSeed(d)
	}
	if len(seedURLs) > 0 {
		span.SetAttribute("url.full", otel.SanitizeURL(seedURLs[0]))
	}
	if strings.EqualFold(strings.TrimSpace(strField(payload["mode"])), "verify") || boolField(payload["verify"]) {
		out, st := h.executeJobsVerify(ctx, span, seedURLs, payload, hdr, ownerID)
		statusOut = st
		return out, st
	}
	limit := intField(payload["limit"], 20, 1, 100)

	var collected []jobs.StructuredJobRecord
	var discoveredBoards []jobs.DiscoveredATSBoard
	var singlePosting *jobs.StructuredJobPosting
	adapterID := ""

	fetchJobsURL := func(targetURL string) (crawl.Result, string, bool) {
		u, err := url.Parse(strings.TrimSpace(targetURL))
		if err != nil || h.allowURL(u) != nil || h.deps.DispatchFetch == nil {
			return crawl.Result{}, "", false
		}
		if spec := jobs.ResolveATSPreFetchSpec(targetURL); spec != nil {
			if fu, fErr := url.Parse(spec.FetchURL); fErr == nil && h.allowURL(fu) == nil {
				rep, _, _, dErr := h.deps.DispatchFetch(ctx, crawl.FetchCall{
					MaxSeconds: 30, Options: crawl.Options{Concurrency: 1, IncludeBody: true, RespectRobots: crawl.Bool(true)},
					Requests: []crawl.Request{{ID: "ats-1", URL: spec.FetchURL, Kind: classify.Kind(spec.Kind), Accept: spec.Accept}},
				}, strField(payload["target"]), strField(payload["site"]), hdr)
				if dErr == nil && len(rep.Results) > 0 && rep.Results[0].Status == http.StatusOK {
					bodyStr := decodeReplyBodyString(rep.Results[0])
					if fmtRes := jobs.FormatATSResponse(targetURL, bodyStr, targetURL, jobs.DefaultHTMLToMD, time.Now()); fmtRes != nil {
						adapterID = firstNonEmpty(adapterID, strings.Split(spec.ID, "-")[0])
						collected = append(collected, fmtRes.Jobs...)
						if fmtRes.JobPosting != nil {
							singlePosting = fmtRes.JobPosting
						}
						return rep.Results[0], bodyStr, true
					}
				}
			}
		}
		rep, _, _, dErr := h.deps.DispatchFetch(ctx, crawl.FetchCall{
			MaxSeconds: 30, Options: crawl.Options{Concurrency: 1, IncludeBody: true, RespectRobots: crawl.Bool(true)},
			Requests: []crawl.Request{{ID: "jobs-html-1", URL: targetURL, Kind: classify.KindScrape, Formats: []string{"markdown", "links"}}},
		}, strField(payload["target"]), strField(payload["site"]), hdr)
		if dErr != nil || len(rep.Results) == 0 {
			return crawl.Result{}, "", false
		}
		return rep.Results[0], decodeReplyBodyString(rep.Results[0]), false
	}

	if len(seedURLs) > 0 {
		for idx, rawURL := range seedURLs {
			if idx >= 10 {
				break
			}
			if pu, uErr := url.Parse(rawURL); uErr != nil || pu.Host == "" || h.allowURL(pu) != nil {
				if len(seedURLs) == 1 {
					statusOut = http.StatusBadRequest
					return map[string]any{"ok": false, "error": "bad_url"}, statusOut
				}
				continue
			}
			res, bodyStr, matchedATS := fetchJobsURL(rawURL)
			if !matchedATS && bodyStr != "" {
				boards := jobs.DiscoverATSBoardsFromHTML(jobs.DiscoverBoardsParams{
					RawHTML: bodyStr, Links: res.Links, FinalURL: firstNonEmpty(res.FinalURL, rawURL), SourceURL: rawURL,
				})
				discoveredBoards = append(discoveredBoards, boards...)
				for i := 0; i < len(boards) && i < 3; i++ {
					if _, _, okB := fetchJobsURL(boards[i].BoardURL); okB && adapterID == "" {
						adapterID = boards[i].Platform
					}
				}
				if jp := jobs.ExtractJobPostingJSONLD(bodyStr, firstNonEmpty(res.FinalURL, rawURL), res.Markdown); jp != nil {
					singlePosting = jp
					if len(collected) == 0 && jp.Title != "" {
						collected = append(collected, jobs.StructuredJobRecord{
							Title: jp.Title, Company: firstNonEmpty(jp.HiringOrganization, company, hostOfURL(rawURL)),
							URL: firstNonEmpty(jp.URL, rawURL), ApplyURL: firstNonEmpty(jp.ApplyURL, rawURL),
							WorkplaceType: jp.WorkplaceType, Locations: jp.JobLocation, Pay: jp.Pay, Source: "jsonld",
						})
					}
				}
			}
		}
	} else if company != "" {
		slug := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(company), " ", ""))
		for _, cand := range []string{"https://boards.greenhouse.io/" + slug, "https://jobs.lever.co/" + slug, "https://jobs.ashbyhq.com/" + slug} {
			if _, _, okB := fetchJobsURL(cand); okB {
				break
			}
		}
	}

	if adapterID != "" {
		span.SetAttribute("edgefetch.adapter_id", adapterID)
	}
	var wantRemote *bool
	if v, ok := payload["remoteOnly"].(bool); ok {
		wantRemote = &v
	} else if v, ok := payload["remote"].(bool); ok {
		wantRemote = &v
	}
	var minBase *float64
	if f, ok := floatField(firstNonEmptyAny(payload["minSalary"], payload["minBase"])); ok && f > 0 {
		minBase = &f
	}
	ranked := jobs.FilterAndRankJobs(jobs.FilterAndRankParams{
		Collected: collected, Query: query, WantRemote: wantRemote,
		GeoLocationsFilter: stringSliceField(payload["locations"]), MinBase: minBase, Limit: limit,
	})
	_ = ownerID
	return map[string]any{
		"ok": true, "query": query, "total": ranked.MatchedTotal, "returned": len(ranked.FinalJobs),
		"jobs": ranked.FinalJobs, "boards": discoveredBoards, "adapterId": adapterID, "singlePost": singlePosting,
	}, http.StatusOK
}

func firstNonEmptyAny(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

// HandleCatalog serves `POST /v1/catalog`.
func (h *RouteHandler) HandleCatalog(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, status := h.ExecuteCatalog(r.Context(), payload, r.Header, p)
	writeJSON(w, status, out)
}

// ExecuteCatalog runs Shopify / WooCommerce storefront catalog extraction, snapshot hashing, and diffing.
func (h *RouteHandler) ExecuteCatalog(ctx context.Context, payload map[string]any, hdr http.Header, p AuthPrincipal) (map[string]any, int) {
	rawURL := strings.TrimSpace(strField(payload["url"]))
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.catalog", 1, map[string]any{"url.full": otel.SanitizeURL(rawURL)})
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	if existID := strings.TrimSpace(strField(payload["catalogId"])); existID != "" {
		return h.getCatalogStatusMap(existID, p)
	}
	if pu, err := url.Parse(rawURL); err != nil || pu.Host == "" || h.allowURL(pu) != nil {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "invalid_url"}, statusOut
	}
	var maxPagesPtr, pauseMsPtr *int
	if mp := intField(payload["maxPages"], 0, 0, 250); mp > 0 {
		maxPagesPtr = &mp
	}
	if pm := intField(payload["pauseMs"], 0, 0, 30000); pm > 0 {
		pauseMsPtr = &pm
	}
	plan, valErr := catalog.InitCatalogPullPlan(catalog.CatalogInitRequest{
		URL: rawURL, Platform: strField(payload["platform"]), Collection: strField(payload["collection"]),
		Fields: strField(payload["fields"]), MaxPages: maxPagesPtr, PauseMs: pauseMsPtr,
	})
	if valErr != nil {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": valErr.ErrorCode, "message": valErr.Message}, statusOut
	}
	tenant := catalog.ResolveCatalogTenantBucket(p.EffectiveOwnerID(), p.Kind, p.UserID, p.Role)
	release, okSlot := h.catSt.AcquireConcurrencySlot(tenant)
	if !okSlot {
		statusOut = http.StatusTooManyRequests
		return map[string]any{"ok": false, "error": "catalog_concurrency_exceeded"}, statusOut
	}
	defer release()
	if h.deps.DispatchFetch == nil {
		statusOut = http.StatusServiceUnavailable
		return map[string]any{"ok": false, "error": "hub_unavailable"}, statusOut
	}

	started := time.Now()
	catID := catalog.GenerateCatalogID()
	platform := plan.InitialPlatform
	curURL := plan.FirstPageURL
	pagesRead := 0
	triedWC := platform == "woocommerce" || (plan.RawPlatform != "" && plan.RawPlatform != "auto")
	autoFromShop := false
	var records []catalog.CatalogRecord
	seenKeys := map[string]bool{}
	runStatus := catalog.StatusComplete
	stopReason := ""
	shopCfg := catalog.DeclarativeCatalogConfig{Platform: "shopify", PauseMs: 2000, PageCap: plan.MaxPages}
	wooCfg := catalog.DeclarativeCatalogConfig{Platform: "woocommerce", PauseMs: 1000, PageCap: plan.MaxPages}

	for curURL != "" && pagesRead < plan.MaxPages {
		if cu, cErr := url.Parse(curURL); cErr != nil || h.allowURL(cu) != nil {
			runStatus, stopReason = catalog.StatusPartial, "bad_page_url"
			break
		}
		rep, _, _, dErr := h.deps.DispatchFetch(ctx, crawl.FetchCall{
			MaxSeconds: 30, Options: crawl.Options{Concurrency: 1, IncludeBody: true, RespectRobots: crawl.Bool(true)},
			Requests: []crawl.Request{{ID: fmt.Sprintf("cat-%d", pagesRead+1), URL: curURL, Kind: classify.KindJSON, Accept: "application/json"}},
		}, strField(payload["target"]), strField(payload["site"]), hdr)
		if dErr != nil || len(rep.Results) == 0 {
			runStatus, stopReason = catalog.StatusPartial, "fetch_failed"
			break
		}
		r0 := rep.Results[0]
		activeCfg := shopCfg
		if platform == "woocommerce" {
			activeCfg = wooCfg
		}
		ev := catalog.EvaluateCatalogPageResponse(catalog.CatalogPageEvalInput{
			CurrentURL: curURL, OriginWithCollection: plan.OriginWithCollection, Collection: plan.Collection,
			Platform: platform, Fields: plan.Fields, PagesRead: pagesRead,
			TriedAutoFallbackToWC: triedWC, AutoFallbackFromShopify: autoFromShop,
			CatalogCfg: activeCfg, WooCatalogCfg: wooCfg,
			Status: r0.Status, Outcome: string(r0.Outcome), Problem: r0.Problem,
			Headers: lowerHeadersMap(r0.ResponseHeaders), FinalURL: r0.FinalURL, NowMs: time.Now().UnixMilli(),
		}, decodeReplyBodyString(r0))
		if ev.Action == "fallback_wc" {
			platform, triedWC, autoFromShop, curURL = "woocommerce", true, true, ev.NextURL
			continue
		}
		if ev.Action != "parsed" {
			stopReason = ev.StopReason
			if ev.Challenged {
				runStatus = catalog.StatusChallenged
			} else {
				runStatus = catalog.StatusPartial
			}
			break
		}
		pagesRead++
		for _, item := range ev.Items {
			if !seenKeys[item.Key] {
				seenKeys[item.Key] = true
				records = append(records, item.Record)
			}
		}
		if ev.Done || ev.NextURL == "" {
			break
		}
		curURL = ev.NextURL
	}

	variantsTotal := 0
	for _, r := range records {
		variantsTotal += len(r.Variants)
	}
	hashes := catalog.BuildSnapshotHashBundle(records)
	var diffPtr *catalog.CatalogSnapshotDiff
	var prevProdsPtr *int
	var warnStr string
	if prevCount, prevHashes, hasPrev := h.catSt.FindPreviousCompleteBaseline(tenant.OwnerKey, plan.Origin, plan.Collection, catID); hasPrev && prevHashes != nil {
		d := catalog.ComputeCatalogSnapshotDiff(*prevHashes, hashes)
		diffPtr, prevProdsPtr = &d, &prevCount
		warnStr, _, _ = catalog.EvaluateShrinkGuard(prevCount, len(records))
	}
	nowISO := time.Now().UTC().Format(time.RFC3339)
	summary := catalog.CatalogStatusSummary{
		OK: runStatus == catalog.StatusComplete || len(records) > 0, CatalogID: catID, Status: runStatus, Platform: platform,
		Origin: plan.Origin, Collection: plan.Collection, Fields: plan.Fields, Products: len(records), Variants: variantsTotal,
		Pages: pagesRead, PagesRead: pagesRead, PauseMs: plan.EffectivePauseMs, DurationMs: time.Since(started).Milliseconds(),
		Reason: stopReason, Warning: warnStr, PreviousProducts: prevProdsPtr, Diff: diffPtr, CreatedAt: nowISO, UpdatedAt: nowISO,
	}
	h.catSt.RememberRun(catalog.StoredCatalogRun{UserID: tenant.OwnerKey, Summary: summary, Hashes: &hashes, Records: records, HasRecords: true})
	span.SetAttribute("edgefetch.adapter_id", platform)

	filt := catalog.FilterCatalogRecords(records, catalog.CatalogRecordFilter{
		Platform: platform, Fields: plan.Fields, Limit: intField(payload["limit"], 50, 1, 250),
	})
	out := structToMap(summary)
	if plan.Fields == "lean" {
		out["records"] = filt.LeanRecords
	} else {
		out["records"] = filt.FullRecords
	}
	return out, http.StatusOK
}

// HandleCatalogStatus serves `GET /v1/catalog/:id`.
func (h *RouteHandler) HandleCatalogStatus(w http.ResponseWriter, r *http.Request, catalogID string) {
	p, ok := h.requireScope(w, r, "crawl:read")
	if !ok {
		return
	}
	_, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, "edgefetch.catalog", 1, map[string]any{"edgefetch.op": "status"})
	defer span.End(true, "")
	out, status := h.getCatalogStatusMap(catalogID, p)
	writeJSON(w, status, out)
}

func (h *RouteHandler) getCatalogStatusMap(catalogID string, p AuthPrincipal) (map[string]any, int) {
	if !catalog.IsValidCatalogID(catalogID) {
		return map[string]any{"ok": false, "error": "invalid_catalog_id"}, http.StatusBadRequest
	}
	tenant := catalog.ResolveCatalogTenantBucket(p.EffectiveOwnerID(), p.Kind, p.UserID, p.Role)
	run, ok := h.catSt.GetRun(catalogID, tenant.OwnerKey)
	if !ok {
		return map[string]any{"ok": false, "error": "catalog_not_found"}, http.StatusNotFound
	}
	return structToMap(run.Summary), http.StatusOK
}

// HandleCatalogRecords serves `GET /v1/catalog/:id/records`.
func (h *RouteHandler) HandleCatalogRecords(w http.ResponseWriter, r *http.Request, catalogID string) {
	p, ok := h.requireScope(w, r, "crawl:read")
	if !ok {
		return
	}
	_, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, "edgefetch.catalog", 1, map[string]any{"edgefetch.op": "records"})
	defer span.End(true, "")
	if !catalog.IsValidCatalogID(catalogID) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_catalog_id"})
		return
	}
	tenant := catalog.ResolveCatalogTenantBucket(p.EffectiveOwnerID(), p.Kind, p.UserID, p.Role)
	run, found := h.catSt.GetRun(catalogID, tenant.OwnerKey)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "catalog_not_found"})
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	fields := firstNonEmpty(q.Get("fields"), run.Summary.Fields, "full")
	filt := catalog.FilterCatalogRecords(run.Records, catalog.CatalogRecordFilter{
		Platform: run.Summary.Platform, Offset: offset, Limit: limit, Vendors: q["vendor"], ProductTypes: q["productType"],
		AvailableOnly: q.Get("availableOnly") == "true" || q.Get("availableOnly") == "1", Query: firstNonEmpty(q.Get("query"), q.Get("q")), Fields: fields,
	})
	var recs any = filt.FullRecords
	if fields == "lean" {
		recs = filt.LeanRecords
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "catalogId": catalogID, "platform": run.Summary.Platform, "totalProducts": filt.TotalProducts,
		"matchedProducts": filt.MatchedProducts, "offset": filt.Offset, "limit": filt.Limit, "returned": filt.Returned, "hasMore": filt.HasMore, "records": recs,
	})
}

// HandleBatchScrape serves `POST /v1/batch/scrape`.
func (h *RouteHandler) HandleBatchScrape(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, status := h.ExecuteBatchScrape(r.Context(), payload, r.Header, p.EffectiveOwnerID(), h.publicOriginOf(r))
	writeJSON(w, status, out)
}

func (h *RouteHandler) ExecuteBatchScrape(ctx context.Context, payload map[string]any, hdr http.Header, ownerID, origin string) (map[string]any, int) {
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.batch_scrape", 1, nil)
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	urls := stringSliceField(payload["urls"])
	if len(urls) == 0 || len(urls) > 50 {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "invalid_urls"}, statusOut
	}
	id := "batch_" + randomHex(10)
	now := time.Now().UnixMilli()
	var data, errs []map[string]any
	for _, u := range urls {
		scOut, _, st := h.ExecuteScrape(ctx, ScrapeRequest{URL: u, MaxChars: intField(payload["maxChars"], 0, 0, 1<<20), skipRouteSpan: true}, hdr, ownerID)
		delete(scOut, "_etag")
		if okVal, _ := scOut["ok"].(bool); st == http.StatusOK && okVal {
			data = append(data, scOut)
		} else {
			errs = append(errs, map[string]any{"url": u, "status": st, "error": firstNonEmpty(strField(scOut["problem"]), strField(scOut["error"]))})
		}
	}
	h.putJob(ctx, AsyncJobRecord{Kind: "batch", ID: id, OwnerID: ownerID, Status: "completed", Total: len(urls), Completed: len(data), Data: data, Errors: errs, CreatedAtMs: now, UpdatedAtMs: time.Now().UnixMilli()})
	return map[string]any{"ok": true, "id": id, "status": "completed", "total": len(urls), "completed": len(data), "url": origin + "/v1/batch/scrape/" + id, "data": data, "errors": errs}, http.StatusOK
}

func (h *RouteHandler) HandleBatchScrapeByID(w http.ResponseWriter, r *http.Request, id string) {
	h.handleAsyncJobByID(w, r, "batch", "edgefetch.batch_scrape", id)
}

func (h *RouteHandler) HandleCrawlParamsPreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireScope(w, r, "crawl:read"); !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, status := h.previewCrawlParams(payload)
	writeJSON(w, status, out)
}

func (h *RouteHandler) previewCrawlParams(payload map[string]any) (map[string]any, int) {
	pu, err := url.Parse(strings.TrimSpace(strField(payload["url"])))
	if err != nil || pu.Host == "" || h.allowURL(pu) != nil {
		return map[string]any{"ok": false, "error": "invalid_url"}, http.StatusBadRequest
	}
	return map[string]any{"ok": true, "url": pu.String(), "limit": intField(payload["limit"], 10, 1, 100), "maxDepth": intField(payload["maxDepth"], 2, 0, 6), "sameHost": payload["allowExternalLinks"] != true, "prompt": strField(payload["prompt"])}, http.StatusOK
}

func (h *RouteHandler) HandleCrawl(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, status := h.ExecuteCrawl(r.Context(), payload, r.Header, p.EffectiveOwnerID(), h.publicOriginOf(r))
	writeJSON(w, status, out)
}

func (h *RouteHandler) ExecuteCrawl(ctx context.Context, payload map[string]any, hdr http.Header, ownerID, origin string) (map[string]any, int) {
	rawURL := strings.TrimSpace(strField(payload["url"]))
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.crawl", 1, map[string]any{"url.full": otel.SanitizeURL(rawURL)})
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	rootU, err := url.Parse(rawURL)
	if err != nil || rootU.Host == "" || h.allowURL(rootU) != nil {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "invalid_url"}, statusOut
	}
	limit := intField(payload["limit"], 10, 1, 50)
	maxDepth := intField(payload["maxDepth"], 2, 0, 5)
	colID := strField(payload["collectionId"])

	type qItem struct {
		u     string
		depth int
	}
	queue := []qItem{{u: rootU.String(), depth: 0}}
	visited := map[string]bool{rootU.String(): true}
	var pages, errs []map[string]any

	for len(queue) > 0 && len(pages) < limit {
		cur := queue[0]
		queue = queue[1:]
		scOut, _, st := h.ExecuteScrape(ctx, ScrapeRequest{URL: cur.u, skipRouteSpan: true}, hdr, ownerID)
		delete(scOut, "_etag")
		if okVal, _ := scOut["ok"].(bool); st != http.StatusOK || !okVal {
			errs = append(errs, map[string]any{"url": cur.u, "status": st, "error": firstNonEmpty(strField(scOut["problem"]), strField(scOut["error"]))})
			continue
		}
		pages = append(pages, scOut)
		if colID != "" {
			h.ingestCollectionDoc(ctx, CollectionDocInput{
				CollectionID: colID, OwnerID: ownerID, Visibility: "public", DocumentID: "crawl:" + sha256HexStr(cur.u)[:24], PageID: sha256HexStr(cur.u)[:24],
				URL: cur.u, Title: firstNonEmpty(strField(scOut["title"]), cur.u), Markdown: strField(scOut["markdown"]), FetchedAtMs: time.Now().UnixMilli(),
			})
		}
		if cur.depth >= maxDepth {
			continue
		}
		for _, lnk := range stringSliceField(scOut["links"]) {
			if lu, lErr := url.Parse(lnk); lErr == nil && strings.EqualFold(lu.Hostname(), rootU.Hostname()) && h.allowURL(lu) == nil {
				lu.Fragment = ""
				norm := lu.String()
				if !visited[norm] && len(visited) < limit*4 {
					visited[norm] = true
					queue = append(queue, qItem{u: norm, depth: cur.depth + 1})
				}
			}
		}
	}
	id := "crawl_" + randomHex(10)
	h.putJob(ctx, AsyncJobRecord{Kind: "crawl", ID: id, OwnerID: ownerID, Status: "completed", Total: len(pages), Completed: len(pages), CollectionID: colID, Data: pages, Errors: errs, CreatedAtMs: time.Now().UnixMilli(), UpdatedAtMs: time.Now().UnixMilli()})
	return map[string]any{"ok": true, "id": id, "crawlId": id, "status": "completed", "total": len(pages), "completed": len(pages), "collectionId": colID, "url": origin + "/v1/crawl/" + id, "data": pages}, http.StatusOK
}

func (h *RouteHandler) HandleCrawlByID(w http.ResponseWriter, r *http.Request, id string) {
	h.handleAsyncJobByID(w, r, "crawl", "edgefetch.crawl", id)
}

func (h *RouteHandler) handleAsyncJobByID(w http.ResponseWriter, r *http.Request, kind, spanName, id string) {
	_, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, spanName, 1, nil)
	defer span.End(true, "")
	if r.Method == http.MethodGet {
		p, ok := h.requireScope(w, r, "crawl:read")
		if !ok {
			return
		}
		rec, found := h.getJob(r.Context(), kind, id, p.EffectiveOwnerID())
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": kind + "_not_found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": rec.ID, "status": rec.Status, "total": rec.Total, "completed": rec.Completed, "collectionId": rec.CollectionID, "data": rec.Data, "errors": rec.Errors})
		return
	}
	if r.Method == http.MethodDelete {
		p, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		okCancel := h.cancelJob(r.Context(), kind, id, p.EffectiveOwnerID())
		st := http.StatusOK
		if !okCancel {
			st = http.StatusNotFound
		}
		writeJSON(w, st, map[string]any{"ok": okCancel, "id": id, "status": "cancelled"})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
}
