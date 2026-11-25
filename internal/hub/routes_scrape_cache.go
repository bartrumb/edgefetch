package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

func (h *RouteHandler) checkScrapeCache(ctx context.Context, u, ownerID string, maxAgeMs int64, ifNoneMatch string) (map[string]any, int, string) {
	emitHit := func(payload map[string]any, etag string) (map[string]any, int, string) {
		_, cSpan, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "cache:r2-d1", 1, map[string]any{"url.full": otel.SanitizeURL(u)})
		cSpan.End(true, "")
		cp := cloneMap(payload)
		delete(cp, "_originEtag")
		cp["cached"] = true
		cp["via"] = "cache:r2-d1"
		if etag != "" {
			cp["_etag"] = etag
		}
		return cp, http.StatusOK, "cache:r2-d1"
	}
	if h.deps.LookupScrapeCache != nil {
		lu, err := h.deps.LookupScrapeCache(ctx, u, ownerID, maxAgeMs, ifNoneMatch)
		if err == nil {
			if lu.NotModified {
				return map[string]any{"_etag": lu.ETag}, http.StatusNotModified, "cache:r2-d1"
			}
			if lu.Hit && lu.Payload != nil {
				return emitHit(lu.Payload, lu.ETag)
			}
		}
		return nil, 0, ""
	}
	h.mem.mu.RLock()
	ent, ok := h.mem.scrapeCache[ownerID+"|"+u]
	h.mem.mu.RUnlock()
	if !ok || time.Now().UnixMilli()-ent.StoredAtMs > maxAgeMs {
		return nil, 0, ""
	}
	if ifNoneMatch != "" && ent.ETag != "" && ifNoneMatch == ent.ETag {
		return map[string]any{"_etag": ent.ETag}, http.StatusNotModified, "cache:r2-d1"
	}
	return emitHit(ent.Payload, ent.ETag)
}

func (h *RouteHandler) peekScrapeCacheForRevalidation(ctx context.Context, u, ownerID string) (map[string]any, string) {
	const sevenDaysMs = int64(7 * 24 * 3600 * 1000)
	if h.deps.LookupScrapeCache != nil {
		lu, err := h.deps.LookupScrapeCache(ctx, u, ownerID, sevenDaysMs, "")
		if err == nil && lu.Hit && lu.Payload != nil {
			originETag := firstNonEmpty(strField(lu.Payload["_originEtag"]), lu.ETag)
			return lu.Payload, originETag
		}
		return nil, ""
	}
	h.mem.mu.RLock()
	ent, ok := h.mem.scrapeCache[ownerID+"|"+u]
	h.mem.mu.RUnlock()
	if !ok || ent.Payload == nil {
		return nil, ""
	}
	return ent.Payload, firstNonEmpty(strField(ent.Payload["_originEtag"]), ent.ETag)
}

func parseSpaFallbackPref(raw any) (mode string, explicit bool) {
	switch v := raw.(type) {
	case nil:
		return "", false
	case bool:
		if v {
			return "auto", true
		}
		return "off", true
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		switch s {
		case "", "auto", "true", "1":
			return "auto", s != ""
		case "off", "false", "0", "none":
			return "off", true
		case "crawl4ai", "firecrawl":
			return s, true
		default:
			return "auto", true
		}
	default:
		return "auto", false
	}
}

func (h *RouteHandler) shouldUseSpaFallback(req ScrapeRequest, res crawl.Result, rawHTML, md string) (string, bool) {
	c4 := strings.TrimSpace(h.getenv("CRAWL4AI_API_URL"))
	fc := strings.TrimSpace(h.getenv("FIRECRAWL_API_URL"))
	if c4 == "" && fc == "" {
		return "", false
	}
	if res.BlockedReason != "" || res.Outcome == classify.OutcomeChallenge || res.Outcome == classify.OutcomeStop ||
		strings.Contains(string(res.Outcome), "robots") || res.Status >= 400 {
		return "", false
	}
	pref, explicit := parseSpaFallbackPref(req.SpaFallback)
	if pref == "off" {
		return "", false
	}
	if !explicit && strings.TrimSpace(md) != "" && !extract.NeedsBrowserRender(rawHTML) {
		return "", false
	}
	return pref, true
}

func (h *RouteHandler) callExternalSpaFallback(ctx context.Context, targetURL, pref string) (string, string, string, bool) {
	c4 := strings.TrimRight(strings.TrimSpace(h.getenv("CRAWL4AI_API_URL")), "/")
	fc := strings.TrimRight(strings.TrimSpace(h.getenv("FIRECRAWL_API_URL")), "/")
	provider, endpoint, token := "crawl4ai", c4+"/crawl", strings.TrimSpace(h.getenv("CRAWL4AI_API_TOKEN"))
	reqBody := map[string]any{"urls": []string{targetURL}, "priority": 5}
	if (pref == "firecrawl" && fc != "") || c4 == "" {
		if fc == "" {
			return "", "", "", false
		}
		provider, endpoint, token = "firecrawl", fc+"/v1/scrape", strings.TrimSpace(h.getenv("FIRECRAWL_API_KEY"))
		reqBody = map[string]any{"url": targetURL, "formats": []string{"markdown"}}
	}
	sCtx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.spa_fallback", 3, map[string]any{
		"edgefetch.spa_fallback.provider": provider, "url.full": otel.SanitizeURL(endpoint),
	})
	rawJSON, _ := json.Marshal(reqBody)
	httpReq, err := http.NewRequestWithContext(sCtx, http.MethodPost, endpoint, bytes.NewReader(rawJSON))
	if err != nil {
		span.End(false, err.Error())
		return "", "", "", false
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.opCli.Do(httpReq)
	if err != nil {
		span.End(false, err.Error())
		return "", "", "", false
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		span.End(false, fmt.Sprintf("status_%d", resp.StatusCode))
		return "", "", "", false
	}
	var parsed map[string]any
	_ = json.Unmarshal(b, &parsed)
	md, title := extractSpaFallbackMarkdown(parsed)
	md = strings.TrimSpace(extract.SanitizeScrapedMarkdown(md))
	if md == "" {
		span.End(false, "empty_markdown")
		return "", "", "", false
	}
	span.End(true, "")
	return md, extract.SanitizeScrapedMeta(title), provider, true
}

func (h *RouteHandler) applyScrapePagingAndCache(ctx context.Context, out map[string]any, fullMD string, req ScrapeRequest, u, ownerID, originETag string) {
	workMD := fullMD
	if req.Query != "" && workMD != "" {
		workMD = extract.RerankPassages(workMD, req.Query, req.MaxChars)
	}
	totalLen := len(workMD)
	if req.MaxChars > 0 && totalLen > req.MaxChars {
		artID := h.persistArtifact(ctx, fullMD, ownerID, firstNonEmpty(req.Visibility, "public"))
		cut := req.MaxChars
		for cut > 0 && !utf8.RuneStart(workMD[cut]) {
			cut--
		}
		truncMD := workMD[:cut]
		out["markdown"] = truncMD
		out["markdownArtifactId"] = artID
		out["truncated"] = true
		out["totalChars"] = totalLen
		out["nextOffset"] = len(truncMD)
	} else {
		out["markdown"] = workMD
	}
	if okVal, _ := out["ok"].(bool); okVal {
		etag := `"` + sha256HexStr(workMD)[:24] + `"`
		out["_etag"] = etag
		cachedCopy := cloneMap(out)
		delete(cachedCopy, "_etag")
		if originETag != "" {
			cachedCopy["_originEtag"] = originETag
		}
		entry := ScrapeCacheEntry{URL: u, OwnerID: ownerID, Visibility: firstNonEmpty(req.Visibility, "public"), ETag: etag, Payload: cachedCopy, StoredAtMs: time.Now().UnixMilli()}
		if h.deps.StoreScrapeCache != nil {
			_ = h.deps.StoreScrapeCache(ctx, entry)
		} else {
			h.mem.mu.Lock()
			h.mem.scrapeCache[ownerID+"|"+u] = entry
			h.mem.mu.Unlock()
		}
	}
}

func mergeLowerHeaders(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[strings.ToLower(strings.TrimSpace(k))] = v
		}
	}
	return out
}

func lowerHeadersMap(in map[string]string) map[string]string { return mergeLowerHeaders(in) }
func strField(v any) string                                  { s, _ := v.(string); return s }
func boolField(v any) bool                                   { b, _ := v.(bool); return b }

func floatField(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func intField(v any, def, minV, maxV int) int {
	f, ok := floatField(v)
	if !ok {
		return def
	}
	return max(minV, min(maxV, int(f)))
}

func stringSliceField(v any) []string {
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, it := range arr {
			if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}
