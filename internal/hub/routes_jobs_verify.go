package hub

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/jobs"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

func (h *RouteHandler) executeJobsVerify(
	ctx context.Context, span *otel.ActiveSpan, seedURLs []string, payload map[string]any, hdr http.Header, ownerID string,
) (map[string]any, int) {
	if len(seedURLs) == 0 {
		return map[string]any{"ok": false, "error": "missing_urls", "message": "urls must contain at least 1 URL for mode=verify"}, http.StatusBadRequest
	}
	results := make([]map[string]any, 0, min(len(seedURLs), 20))
	boardsChecked := map[string]bool{}
	adapterID := ""

	for idx, rawURL := range seedURLs {
		if idx >= 20 {
			break
		}
		pu, uErr := url.Parse(rawURL)
		if uErr != nil || pu.Host == "" || h.allowURL(pu) != nil {
			results = append(results, map[string]any{"url": rawURL, "status": "unknown", "reason": "bad_url"})
			continue
		}
		ident := jobs.ParseATSPostingIdentity(rawURL)
		if ident != nil {
			boardsChecked[ident.Platform+":"+strings.ToLower(ident.Slug)] = true
			if adapterID == "" {
				adapterID = ident.Platform
			}
		}

		scOut, _, st := h.ExecuteScrape(ctx, ScrapeRequest{
			URL: rawURL, RenderMode: "auto", Target: strField(payload["target"]), Site: strField(payload["site"]),
			skipRouteSpan: true,
		}, hdr, ownerID)
		finalU := firstNonEmpty(strField(scOut["finalUrl"]), rawURL)
		title := strField(scOut["title"])
		md := strField(scOut["markdown"])
		cState := classify.ClassifyContentState(st, "", md, finalU, title).State

		item := map[string]any{"url": rawURL}
		if ident != nil {
			item["platform"] = ident.Platform
			item["slug"] = ident.Slug
		}
		switch {
		case st == http.StatusNotFound || st == http.StatusGone ||
			scOut["status"] == http.StatusNotFound || scOut["status"] == http.StatusGone ||
			cState == "closed_posting" || cState == "soft_404":
			item["status"] = "closed"
		case cState == "temporarily_unavailable":
			// A maintenance page says nothing about the posting itself; report unknown so callers retry later.
			item["status"] = "unknown"
			item["reason"] = "temporarily_unavailable"
		case st == http.StatusOK && boolField(scOut["ok"]) && cState != "empty_shell":
			item["status"] = "live"
			if title != "" {
				item["title"] = title
			}
			if extID := strField(scOut["extractorId"]); extID != "" && adapterID == "" {
				adapterID = extID
			}
		default:
			item["status"] = "unknown"
			item["reason"] = firstNonEmpty(strField(scOut["problem"]), strField(scOut["error"]), "fetch_failed")
		}
		results = append(results, item)
	}

	if span != nil {
		span.SetAttribute("edgefetch.jobs.mode", "verify")
		span.SetAttribute("edgefetch.jobs.jobs_returned", len(results))
		if adapterID != "" {
			span.SetAttribute("edgefetch.adapter_id", adapterID)
		}
	}
	return map[string]any{
		"ok":            true,
		"mode":          "verify",
		"boardsFetched": len(boardsChecked),
		"checked":       len(results),
		"results":       results,
	}, http.StatusOK
}
