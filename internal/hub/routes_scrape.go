package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/jobs"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

const (
	maxScrapeBodyBytes    = 1 << 20   // 1 MiB
	maxIngestTabBodyBytes = 4_000_000 // 4 MB (`T2-A6`: 4_200_000 -> 413)
)

// ScrapeRequest models `POST /v1/scrape` parameters.
type ScrapeRequest struct {
	URL             string                   `json:"url"`
	Formats         []any                    `json:"formats,omitempty"`
	OnlyMainContent *bool                    `json:"onlyMainContent,omitempty"`
	RenderMode      string                   `json:"renderMode,omitempty"`
	WaitFor         int                      `json:"waitFor,omitempty"`
	WaitForMs       int                      `json:"waitForMs,omitempty"`
	Mobile          bool                     `json:"mobile,omitempty"`
	Actions         []browser.InteractAction `json:"actions,omitempty"`
	Query           string                   `json:"query,omitempty"`
	MaxChars        int                      `json:"maxChars,omitempty"`
	MaxAge          int64                    `json:"maxAge,omitempty"`
	MaxAgeMs        *int64                   `json:"maxAgeMs,omitempty"`
	SpaFallback     any                      `json:"spaFallback,omitempty"`
	Target          string                   `json:"target,omitempty"`
	Site            string                   `json:"site,omitempty"`
	Visibility      string                   `json:"visibility,omitempty"`

	skipRouteSpan bool
	interactSpec  *crawl.InteractSpec
}

func (h *RouteHandler) requireScope(w http.ResponseWriter, r *http.Request, scope string) (AuthPrincipal, bool) {
	p := h.principalOf(r)
	if !p.Authenticated {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return p, false
	}
	if !p.HasScope(scope) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=\"insufficient_scope\", scope=%q", scope))
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "insufficient_scope", "required": scope})
		return p, false
	}
	return p, true
}

// HandleScrape serves `POST /v1/scrape`.
func (h *RouteHandler) HandleScrape(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	buf, tooLarge, err := ReadBoundedBody(w, r, maxScrapeBodyBytes)
	if tooLarge {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "payload_too_large"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	var req ScrapeRequest
	if err := json.Unmarshal(buf, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	body, via, status := h.ExecuteScrape(r.Context(), req, r.Header, p.EffectiveOwnerID())
	if via != "" {
		w.Header().Set("X-Crawler-Via", via)
	}
	if etag, ok := body["_etag"].(string); ok && etag != "" {
		w.Header().Set("ETag", etag)
		delete(body, "_etag")
	}
	if status == http.StatusNotModified {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, status, body)
}

// ExecuteScrape performs a single-URL scrape with cache, twin pre-fetch, raw HTML extraction, Content-Signal/x402 gates, SPA fallback, and artifact slicing.
func (h *RouteHandler) ExecuteScrape(ctx context.Context, req ScrapeRequest, hdr http.Header, ownerID string) (map[string]any, string, int) {
	started := time.Now()
	u := strings.TrimSpace(req.URL)
	var span *otel.ActiveSpan
	if !req.skipRouteSpan {
		ctx, span, _ = otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.scrape", 1, map[string]any{
			"url.full": otel.SanitizeURL(u),
		})
	}
	statusOut := http.StatusOK
	errMsg := ""
	defer func() {
		if span != nil {
			span.SetAttribute("http.response.status_code", statusOut)
			span.End(statusOut >= 200 && statusOut < 400, errMsg)
		}
	}()

	if u == "" {
		statusOut = http.StatusBadRequest
		errMsg = "missing_url"
		return map[string]any{"ok": false, "error": "missing_url", "message": "url is required"}, "hub", statusOut
	}
	parsedURL, uErr := url.Parse(u)
	if uErr != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || h.allowURL(parsedURL) != nil {
		statusOut = http.StatusBadRequest
		errMsg = "bad_url"
		return map[string]any{"ok": false, "error": "bad_url"}, "hub", statusOut
	}

	var maxAgeMs int64
	if req.MaxAgeMs != nil {
		maxAgeMs = *req.MaxAgeMs
	} else if req.MaxAge > 0 {
		maxAgeMs = req.MaxAge
	}
	if maxAgeMs > 0 {
		ifNoneMatch := ""
		if hdr != nil {
			ifNoneMatch = strings.TrimSpace(hdr.Get("If-None-Match"))
		}
		if hit, cStatus, cVia := h.checkScrapeCache(ctx, u, ownerID, maxAgeMs, ifNoneMatch); cStatus != 0 {
			statusOut = cStatus
			return hit, cVia, cStatus
		}
	}

	var revalPayload map[string]any
	var revalETag string
	if req.MaxAgeMs != nil && *req.MaxAgeMs == 0 {
		revalPayload, revalETag = h.peekScrapeCacheForRevalidation(ctx, u, ownerID)
	}

	formats, wantScreenshot := normalizeScrapeFormats(req.Formats)
	kind := classify.KindScrape
	interactSpec := req.interactSpec
	if interactSpec == nil && len(req.Actions) > 0 {
		interactSpec = &crawl.InteractSpec{Actions: req.Actions}
	}
	if interactSpec != nil {
		kind = classify.KindRender
	} else if req.RenderMode == "always" || wantScreenshot || req.Mobile {
		kind = classify.KindRender
	}

	if kind == classify.KindScrape && revalETag == "" {
		if twinOut, twinVia, twinOK := h.tryPreFetchTwin(ctx, u, req, hdr, ownerID); twinOK {
			if span != nil {
				span.SetAttribute("edgefetch.adapter_id", fmt.Sprint(twinOut["extractorId"]))
				span.SetAttribute("crawler.outcome", "ok")
			}
			return twinOut, twinVia, http.StatusOK
		}
	}

	if h.deps.DispatchFetch == nil {
		statusOut = http.StatusServiceUnavailable
		errMsg = "dispatch_not_configured"
		return map[string]any{"ok": false, "error": "hub_unavailable"}, "hub", statusOut
	}

	waitMs := req.WaitForMs
	if waitMs <= 0 && req.WaitFor > 0 {
		waitMs = req.WaitFor
	}
	onlyMain := true
	if req.OnlyMainContent != nil {
		onlyMain = *req.OnlyMainContent
	}
	call := crawl.FetchCall{
		MaxSeconds: 45,
		Options:    crawl.Options{Concurrency: 1, IncludeBody: true, RespectRobots: crawl.Bool(true), DiscoverLlms: crawl.Bool(true)},
		Requests: []crawl.Request{{
			ID: "scrape-1", URL: u, Kind: kind, Formats: formats, OnlyMainContent: crawl.Bool(onlyMain), IfNoneMatch: revalETag,
			DiscoverLlms: crawl.Bool(true), Query: req.Query, RenderMode: req.RenderMode, WaitForMs: waitMs, Mobile: req.Mobile, Interact: interactSpec,
		}},
	}

	reply, via, dStatus, err := h.deps.DispatchFetch(ctx, call, req.Target, req.Site, hdr)
	if err != nil {
		statusOut = firstPositiveStatus(dStatus, http.StatusServiceUnavailable)
		errMsg = err.Error()
		return map[string]any{"ok": false, "error": "hub_unavailable", "message": err.Error()}, via, statusOut
	}
	if len(reply.Results) == 0 {
		statusOut = http.StatusBadGateway
		errMsg = "empty_reply"
		return map[string]any{"ok": false, "error": "empty_reply"}, via, statusOut
	}
	res := reply.Results[0]
	if res.Status == http.StatusNotModified && revalPayload != nil {
		cp := cloneMap(revalPayload)
		delete(cp, "_originEtag")
		cp["ok"] = true
		cp["cached"] = true
		cp["revalidated"] = true
		cp["status"] = http.StatusOK
		cp["via"] = "cache:r2-d1"
		return cp, "cache:r2-d1", http.StatusOK
	}
	rawBody := decodeReplyBodyString(res)

	if hasContentSignalDisallowed(res) {
		statusOut = http.StatusUnavailableForLegalReasons
		errMsg = "content_signal_disallowed"
		if span != nil {
			span.SetAttribute("crawler.outcome", "content_signal_disallowed")
		}
		return map[string]any{
			"ok": false, "url": u, "status": http.StatusUnavailableForLegalReasons,
			"outcome": "content_signal_disallowed", "blockedReason": "content-signal",
			"blocked": map[string]any{"reason": "content-signal", "retryable": false},
		}, via, statusOut
	}

	if res.Status == http.StatusPaymentRequired || res.Outcome == "payment_required" {
		statusOut = http.StatusPaymentRequired
		errMsg = "payment_required"
		if span != nil {
			span.SetAttribute("crawler.outcome", "payment_required")
		}
		blockedObj := map[string]any{"reason": "payment_required", "retryable": false, "terms": map[string]any{}}
		hdrMap := mergeLowerHeaders(res.ResponseHeaders, res.PaymentHeaders)
		if parsed := jobs.ParseX402PaymentTerms(http.StatusPaymentRequired, hdrMap, rawBody, hostOfURL(u)); parsed != nil {
			blockedObj["terms"] = parsed.Terms
			if parsed.Price != "" {
				blockedObj["price"] = parsed.Price
			}
		}
		return map[string]any{
			"ok": false, "url": u, "status": http.StatusPaymentRequired,
			"outcome": "payment_required", "blockedReason": "payment_required", "blocked": blockedObj,
		}, via, statusOut
	}

	out, finalVia := h.buildExtractedScrapeOutput(ctx, u, res, rawBody, via, onlyMain, req, hdr, ownerID)
	if h.deps.RecordHostTelemetry != nil {
		h.deps.RecordHostTelemetry(ctx, HostTelemetryEvent{
			Host: hostOfURL(u), URL: u, Status: res.Status, Outcome: string(res.Outcome),
			Via: finalVia, AdapterID: fmt.Sprint(out["extractorId"]), DurationMs: time.Since(started).Milliseconds(), TimestampMs: time.Now().UnixMilli(),
		})
	}
	if res.Outcome == classify.OutcomeChallenge {
		statusOut = res.Status
		if statusOut < 400 {
			statusOut = http.StatusForbidden
		}
		errMsg = firstNonEmpty(res.Problem, "challenge")
	}
	if span != nil {
		span.SetAttribute("crawler.outcome", fmt.Sprint(out["outcome"]))
	}
	return out, finalVia, statusOut
}

func (h *RouteHandler) tryPreFetchTwin(ctx context.Context, u string, req ScrapeRequest, hdr http.Header, ownerID string) (map[string]any, string, bool) {
	if h.deps.DispatchFetch == nil {
		return nil, "", false
	}
	var twinID, fetchURL, accept string
	var twinKind classify.Kind
	var formatFn func(rawBody, finalURL string) (title, desc, author, pub, md string, links []string, ok bool)

	if twin, ok := extract.ResolveDeclarativeTwin(u); ok {
		twinID = firstNonEmpty(twin.ID, twin.AdapterID)
		fetchURL, accept, twinKind = twin.FetchURL, twin.Accept, twin.Kind
		formatFn = func(rawBody, finalURL string) (string, string, string, string, string, []string, bool) {
			if !twin.ValidateRedirectTarget(finalURL) {
				return "", "", "", "", "", nil, false
			}
			doc, ok := twin.Format(rawBody)
			if !ok || doc == nil || strings.TrimSpace(doc.Markdown) == "" {
				return "", "", "", "", "", nil, false
			}
			return doc.Title, doc.Description, doc.Author, doc.PublishedTime, doc.Markdown, doc.Links, true
		}
	} else if wiki := extract.ParseWikipediaArticleURL(u); wiki != nil {
		twinID = "wikipedia"
		fetchURL = "https://" + wiki.Host + "/api/rest_v1/page/summary/" + wiki.EncodedTitle
		accept, twinKind = "application/json", classify.KindJSON
		formatFn = func(rawBody, finalURL string) (string, string, string, string, string, []string, bool) {
			fu, fErr := url.Parse(finalURL)
			if fErr != nil || fu.Scheme != "https" || !strings.EqualFold(fu.Hostname(), wiki.Host) {
				return "", "", "", "", "", nil, false
			}
			var sum struct {
				Title       string `json:"title"`
				Description string `json:"description"`
				Extract     string `json:"extract"`
			}
			if json.Unmarshal([]byte(rawBody), &sum) != nil || strings.TrimSpace(sum.Extract) == "" {
				return "", "", "", "", "", nil, false
			}
			return sum.Title, sum.Description, "", "", "# " + sum.Title + "\n\n" + extract.CleanMediaWikiMarkdown(sum.Extract), []string{wiki.CanonicalURL}, true
		}
	}
	if twinID == "" || fetchURL == "" {
		return nil, "", false
	}
	if tu, err := url.Parse(fetchURL); err != nil || h.allowURL(tu) != nil {
		return nil, "", false
	}

	twinCtx, twinSpan, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.hub.twin", 1, map[string]any{
		"edgefetch.twin.candidate": twinID,
		"url.full":                 otel.SanitizeURL(fetchURL),
	})
	rep, via, _, dErr := h.deps.DispatchFetch(twinCtx, crawl.FetchCall{
		MaxSeconds: 30, Options: crawl.Options{Concurrency: 1, IncludeBody: true, MaxBytes: 8 << 20, RespectRobots: crawl.Bool(true)},
		Requests: []crawl.Request{{ID: "twin-1", URL: fetchURL, Kind: twinKind, Accept: accept}},
	}, req.Target, req.Site, hdr)
	if dErr != nil || len(rep.Results) == 0 {
		twinSpan.SetAttribute("edgefetch.twin.hit", false)
		twinSpan.End(false, "twin_fetch_failed")
		return nil, "", false
	}
	tRes := rep.Results[0]
	finalURL := firstNonEmpty(tRes.FinalURL, fetchURL)
	if fu, fErr := url.Parse(finalURL); fErr != nil || h.allowURL(fu) != nil || tRes.Status != http.StatusOK || tRes.Outcome != classify.OutcomeOK {
		twinSpan.SetAttribute("edgefetch.twin.hit", false)
		twinSpan.End(false, "twin_non_200")
		return nil, "", false
	}
	title, desc, author, pub, rawMD, links, fmtOK := formatFn(decodeReplyBodyString(tRes), finalURL)
	cleanMD := strings.TrimSpace(extract.SanitizeScrapedMarkdown(rawMD))
	if !fmtOK || cleanMD == "" {
		twinSpan.SetAttribute("edgefetch.twin.hit", false)
		twinSpan.End(false, "twin_format_failed")
		return nil, "", false
	}

	twinSpan.SetAttribute("edgefetch.adapter_id", twinID)
	twinSpan.SetAttribute("edgefetch.twin.hit", true)
	twinSpan.SetAttribute("crawler.via", via)
	twinSpan.End(true, "")

	cleanTitle := extract.SanitizeScrapedMeta(title)
	cleanDesc := extract.SanitizeScrapedMeta(desc)
	out := map[string]any{
		"ok": true, "cached": false, "url": u, "finalUrl": finalURL, "via": via, "status": http.StatusOK, "outcome": classify.OutcomeOK,
		"extractorId": twinID, "contentSource": "twin:" + twinID,
		"title": cleanTitle, "description": cleanDesc, "markdown": cleanMD, "text": cleanMD,
		"links": nonNilStrings(links), "metadata": map[string]any{"title": cleanTitle, "description": cleanDesc, "sourceURL": u},
		"rendered": false, "timing": tRes.Timing,
	}
	if author != "" {
		out["author"] = extract.SanitizeScrapedMeta(author)
	}
	if pub != "" {
		out["publishedTime"] = extract.SanitizeScrapedMeta(pub)
	}
	originETag := firstNonEmpty(tRes.ETag, lowerHeadersMap(tRes.ResponseHeaders)["etag"])
	h.applyScrapePagingAndCache(ctx, out, cleanMD, req, u, ownerID, originETag)
	return out, via, true
}

func (h *RouteHandler) buildExtractedScrapeOutput(
	ctx context.Context, u string, res crawl.Result, rawBody, via string, onlyMain bool, req ScrapeRequest, hdr http.Header, ownerID string,
) (map[string]any, string) {
	finalURL := firstNonEmpty(res.FinalURL, res.URL, u)
	md := extract.SanitizeScrapedMarkdown(res.Markdown)
	txt := extract.SanitizeScrapedMarkdown(res.Text)
	title := extract.SanitizeScrapedMeta(res.Title)
	desc := extract.SanitizeScrapedMeta(res.Description)
	links := res.Links
	images := res.Images
	meta := map[string]any{"sourceURL": u}
	var hydrationOut, schemaOrgOut, frameworkOut any
	extractorID := ""
	renderedVia := ""

	if rawBody != "" {
		frameworkOut = extract.DetectSiteFramework(extract.DetectSiteFrameworkParams{
			URL: finalURL, Headers: lowerHeadersMap(res.ResponseHeaders), Body: rawBody,
		})
		htmlToMD := func(frag, base string) (string, []string) {
			ex := extract.ExtractHTMLDocumentFull(frag, extract.FullExtractOptions{BaseURL: base, OnlyMainContent: false})
			return ex.Markdown, ex.Links
		}
		if hyd := extract.RecoverSSRHydrationContent(rawBody, finalURL, htmlToMD); hyd != nil {
			hydrationOut = hyd
		}
		if so := extract.ExtractUniversalSchemaOrg(rawBody, finalURL, htmlToMD); so != nil && (so.PrimaryType != "" || len(so.Records) > 0 || len(so.Structured) > 0) {
			schemaOrgOut = so
		}
		if md == "" {
			if wpURL := extract.DiscoverWordPressRestTwinURL(rawBody, finalURL, ""); wpURL != "" {
				if cmsMD, cmsTitle, ok := h.tryFetchCMSTwin(ctx, wpURL, finalURL, htmlToMD, req, hdr, "wordpress-rest"); ok {
					md, txt, title, extractorID = cmsMD, cmsMD, firstNonEmpty(cmsTitle, title), "wordpress-rest"
				}
			}
		}
		if md == "" {
			doc := extract.ExtractHTMLDocumentFull(rawBody, extract.FullExtractOptions{
				BaseURL: finalURL, OnlyMainContent: onlyMain, IncludeImages: true,
			})
			md = extract.SanitizeScrapedMarkdown(doc.Markdown)
			if md == "" && hydrationOut != nil {
				if hyd, ok := hydrationOut.(*extract.HydratedFrameworkStateResult); ok && strings.TrimSpace(hyd.Markdown) != "" {
					md = extract.SanitizeScrapedMarkdown(hyd.Markdown)
				}
			}
			if md == "" && doc.Title == "" && !strings.Contains(rawBody, "<") {
				md = extract.SanitizeScrapedMarkdown(rawBody)
			}
			txt = firstNonEmpty(extract.SanitizeScrapedMarkdown(doc.Text), md)
			title = firstNonEmpty(title, extract.SanitizeScrapedMeta(doc.Title))
			desc = firstNonEmpty(desc, extract.SanitizeScrapedMeta(doc.Description))
			if len(links) == 0 {
				links = doc.Links
			}
			if len(images) == 0 {
				images = doc.Images
			}
			if doc.Language != "" {
				meta["language"] = doc.Language
			}
			if doc.CanonicalURL != "" {
				meta["canonicalUrl"] = doc.CanonicalURL
			}
			if doc.ExtractorID != "" {
				extractorID = doc.ExtractorID
			}
		}
	}

	if spaPref, useSPA := h.shouldUseSpaFallback(req, res, rawBody, md); useSPA {
		if fbMD, fbTitle, fbProvider, ok := h.callExternalSpaFallback(ctx, u, spaPref); ok {
			md, txt, via, renderedVia = fbMD, fbMD, "spa-fallback:"+fbProvider, fbProvider
			if fbTitle != "" {
				title = fbTitle
			}
		}
	}

	meta["title"] = title
	if desc != "" {
		meta["description"] = desc
	}
	out := map[string]any{
		"ok":     res.Outcome == classify.OutcomeOK || (res.Status >= 200 && res.Status < 300 && md != ""),
		"cached": false, "url": u, "finalUrl": finalURL, "via": via, "status": res.Status, "outcome": res.Outcome, "problem": res.Problem,
		"title": title, "description": desc, "markdown": md, "text": txt,
		"links": nonNilStrings(links), "images": images, "metadata": meta,
		"rendered": res.Rendered || renderedVia != "", "timing": res.Timing,
	}
	if renderedVia != "" {
		out["renderedVia"] = renderedVia
	}
	if extractorID != "" {
		out["extractorId"] = extractorID
	}
	if res.ContentSource != "" && out["contentSource"] == nil {
		out["contentSource"] = res.ContentSource
	}
	if hydrationOut != nil {
		out["hydration"] = hydrationOut
	}
	if schemaOrgOut != nil {
		out["schemaOrg"] = schemaOrgOut
	}
	if frameworkOut != nil {
		out["framework"] = frameworkOut
	}
	if len(res.ActionResults) > 0 {
		out["actionResults"] = res.ActionResults
	}
	if res.BlockedReason != "" {
		out["blockedReason"] = res.BlockedReason
		out["blocked"] = map[string]any{"reason": res.BlockedReason, "retryable": false}
	}
	originETag := firstNonEmpty(res.ETag, lowerHeadersMap(res.ResponseHeaders)["etag"])
	h.applyScrapePagingAndCache(ctx, out, md, req, u, ownerID, originETag)
	return out, via
}

func (h *RouteHandler) tryFetchCMSTwin(ctx context.Context, twinURL, baseURL string, htmlToMD func(string, string) (string, []string), req ScrapeRequest, hdr http.Header, twinID string) (string, string, bool) {
	if tu, err := url.Parse(twinURL); err != nil || h.allowURL(tu) != nil || h.deps.DispatchFetch == nil {
		return "", "", false
	}
	tCtx, tSpan, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.hub.twin", 1, map[string]any{
		"edgefetch.twin.candidate": twinID, "url.full": otel.SanitizeURL(twinURL),
	})
	rep, _, _, dErr := h.deps.DispatchFetch(tCtx, crawl.FetchCall{
		MaxSeconds: 20, Options: crawl.Options{Concurrency: 1, IncludeBody: true, RespectRobots: crawl.Bool(true)},
		Requests: []crawl.Request{{ID: "cms-1", URL: twinURL, Kind: classify.KindJSON, Accept: "application/json"}},
	}, req.Target, req.Site, hdr)
	if dErr != nil || len(rep.Results) == 0 || rep.Results[0].Status != http.StatusOK {
		tSpan.SetAttribute("edgefetch.twin.hit", false)
		tSpan.End(false, "cms_twin_miss")
		return "", "", false
	}
	doc := extract.FormatWordPressRestPostJSON(decodeReplyBodyString(rep.Results[0]), baseURL, htmlToMD)
	if doc == nil || strings.TrimSpace(doc.Markdown) == "" {
		tSpan.SetAttribute("edgefetch.twin.hit", false)
		tSpan.End(false, "cms_format_failed")
		return "", "", false
	}
	tSpan.SetAttribute("edgefetch.adapter_id", twinID)
	tSpan.SetAttribute("edgefetch.twin.hit", true)
	tSpan.End(true, "")
	return extract.SanitizeScrapedMarkdown(doc.Markdown), extract.SanitizeScrapedMeta(doc.Title), true
}
