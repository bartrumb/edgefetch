package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ExtractTavilyBodyAPIKey inspects a raw JSON request body for Tavily's `"api_key"` field so
// `ServeHTTP` authentication middleware can validate Tavily SDK callers without `Authorization` headers.
func ExtractTavilyBodyAPIKey(rawBody []byte) string {
	trimmed := strings.TrimSpace(string(rawBody))
	if !strings.HasPrefix(trimmed, "{") {
		return ""
	}
	var obj struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(rawBody, &obj); err != nil {
		return ""
	}
	tok := strings.TrimSpace(obj.APIKey)
	if strings.ContainsAny(tok, " \t\r\n") {
		return ""
	}
	return tok
}

// HandleCompat routes Firecrawl v2 (`/v2/*`, `/compat/firecrawl/v2/*`) and Tavily (`/compat/tavily/*`) requests.
func (h *RouteHandler) HandleCompat(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/compat/tavily/"):
		h.handleTavilyCompat(w, r, strings.TrimPrefix(p, "/compat/tavily"))
		return true
	case strings.HasPrefix(p, "/compat/firecrawl/v2/"):
		h.handleFirecrawlV2Compat(w, r, strings.TrimPrefix(p, "/compat/firecrawl/v2"))
		return true
	case strings.HasPrefix(p, "/v2/"):
		h.handleFirecrawlV2Compat(w, r, strings.TrimPrefix(p, "/v2"))
		return true
	default:
		return false
	}
}

func (h *RouteHandler) handleFirecrawlV2Compat(w http.ResponseWriter, r *http.Request, subPath string) {
	switch {
	case subPath == "/scrape" && r.Method == http.MethodPost:
		pr, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		payload, okBody := readCompatJSON(w, r)
		if !okBody {
			return
		}
		var req ScrapeRequest
		b, _ := json.Marshal(payload)
		_ = json.Unmarshal(b, &req)
		out, via, status := h.ExecuteScrape(r.Context(), req, r.Header, pr.EffectiveOwnerID())
		if via != "" {
			w.Header().Set("X-Crawler-Via", via)
		}
		delete(out, "_etag")
		if okVal, _ := out["ok"].(bool); status != http.StatusOK || !okVal {
			writeJSON(w, status, map[string]any{
				"success": false,
				"error":   firstNonEmpty(strField(out["problem"]), strField(out["error"]), "scrape_failed"),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": out})

	case subPath == "/map" && r.Method == http.MethodPost:
		if _, ok := h.requireScope(w, r, "crawl:fetch"); !ok {
			return
		}
		payload, okBody := readCompatJSON(w, r)
		if !okBody {
			return
		}
		out, via, status := h.ExecuteMap(r.Context(), payload, r.Header)
		if via != "" {
			w.Header().Set("X-Crawler-Via", via)
		}
		if okVal, _ := out["ok"].(bool); status != http.StatusOK || !okVal {
			writeJSON(w, status, map[string]any{"success": false, "error": firstNonEmpty(strField(out["error"]), "map_failed")})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "links": out["links"]})

	case subPath == "/crawl/params-preview" && r.Method == http.MethodPost:
		if _, ok := h.requireScope(w, r, "crawl:read"); !ok {
			return
		}
		payload, okBody := readCompatJSON(w, r)
		if !okBody {
			return
		}
		out, status := h.previewCrawlParams(payload)
		if status >= 400 {
			writeJSON(w, status, map[string]any{"success": false, "error": firstNonEmpty(strField(out["error"]), "bad_request")})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": out})

	case subPath == "/crawl" && r.Method == http.MethodPost:
		pr, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		payload, okBody := readCompatJSON(w, r)
		if !okBody {
			return
		}
		out, status := h.ExecuteCrawl(r.Context(), payload, r.Header, pr.EffectiveOwnerID(), h.publicOriginOf(r))
		if status >= 400 {
			writeJSON(w, status, map[string]any{"success": false, "error": firstNonEmpty(strField(out["error"]), "crawl_failed")})
			return
		}
		id := strField(out["id"])
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"id":      id,
			"url":     h.publicOriginOf(r) + "/v2/crawl/" + id,
		})

	case strings.HasPrefix(subPath, "/crawl/"):
		id := strings.TrimPrefix(subPath, "/crawl/")
		h.handleFirecrawlAsyncJob(w, r, "crawl", id)

	case subPath == "/batch/scrape" && r.Method == http.MethodPost:
		pr, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		payload, okBody := readCompatJSON(w, r)
		if !okBody {
			return
		}
		out, status := h.ExecuteBatchScrape(r.Context(), payload, r.Header, pr.EffectiveOwnerID(), h.publicOriginOf(r))
		if status >= 400 {
			writeJSON(w, status, map[string]any{"success": false, "error": firstNonEmpty(strField(out["error"]), "batch_failed")})
			return
		}
		id := strField(out["id"])
		writeJSON(w, http.StatusOK, map[string]any{
			"success":     true,
			"id":          id,
			"url":         h.publicOriginOf(r) + "/v2/batch/scrape/" + id,
			"invalidURLs": []string{},
		})

	case strings.HasPrefix(subPath, "/batch/scrape/"):
		id := strings.TrimPrefix(subPath, "/batch/scrape/")
		h.handleFirecrawlAsyncJob(w, r, "batch", id)

	case subPath == "/search" && r.Method == http.MethodPost:
		pr, ok := h.requireScope(w, r, "crawl:read")
		if !ok {
			return
		}
		payload, okBody := readCompatJSON(w, r)
		if !okBody {
			return
		}
		out, status := h.ExecuteSearch(r.Context(), payload, r.Header, pr.EffectiveOwnerID())
		if status >= 400 {
			writeJSON(w, status, map[string]any{"success": false, "error": firstNonEmpty(strField(out["error"]), "search_failed")})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"data":    map[string]any{"web": out["results"]},
		})

	case subPath == "/extract" && r.Method == http.MethodPost:
		pr, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		payload, okBody := readCompatJSON(w, r)
		if !okBody {
			return
		}
		out, status := h.ExecuteExtract(r.Context(), payload, r.Header, pr.EffectiveOwnerID())
		if status >= 400 {
			writeJSON(w, status, map[string]any{"success": false, "error": firstNonEmpty(strField(out["error"]), "extract_failed")})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": out["data"], "results": out["results"]})

	case subPath == "/agent" && r.Method == http.MethodPost:
		pr, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		payload, okBody := readCompatJSON(w, r)
		if !okBody {
			return
		}
		out, status := h.ExecuteAgent(r.Context(), payload, r.Header, pr, nil)
		if status >= 400 {
			writeJSON(w, status, map[string]any{"success": false, "error": firstNonEmpty(strField(out["error"]), "agent_failed")})
			return
		}
		out["success"] = true
		writeJSON(w, http.StatusOK, out)

	case strings.HasPrefix(subPath, "/agent/") && strings.HasSuffix(subPath, "/trace") && r.Method == http.MethodGet:
		id := strings.TrimSuffix(strings.TrimPrefix(subPath, "/agent/"), "/trace")
		h.HandleAgentTrace(w, r, id)

	case strings.HasPrefix(subPath, "/agent/"):
		id := strings.TrimPrefix(subPath, "/agent/")
		h.HandleAgentByID(w, r, id)

	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": "not_found"})
	}
}

func (h *RouteHandler) handleFirecrawlAsyncJob(w http.ResponseWriter, r *http.Request, kind, id string) {
	if r.Method == http.MethodGet {
		pr, ok := h.requireScope(w, r, "crawl:read")
		if !ok {
			return
		}
		rec, found := h.getJob(r.Context(), kind, id, pr.EffectiveOwnerID())
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": kind + "_not_found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"success":   true,
			"id":        rec.ID,
			"status":    rec.Status,
			"total":     rec.Total,
			"completed": rec.Completed,
			"data":      rec.Data,
			"errors":    rec.Errors,
		})
		return
	}
	if r.Method == http.MethodDelete {
		pr, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		if !h.cancelJob(r.Context(), kind, id, pr.EffectiveOwnerID()) {
			writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": kind + "_not_found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "status": "cancelled"})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "method_not_allowed"})
}

func (h *RouteHandler) handleTavilyCompat(w http.ResponseWriter, r *http.Request, subPath string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"detail": map[string]any{"error": "method_not_allowed"}})
		return
	}
	started := time.Now()
	payload, okBody := readCompatJSON(w, r)
	if !okBody {
		return
	}
	delete(payload, "api_key")

	switch subPath {
	case "/search":
		pr, ok := h.requireScope(w, r, "crawl:read")
		if !ok {
			return
		}
		q := strings.TrimSpace(strField(payload["query"]))
		maxRes := intField(payload["max_results"], 5, 1, 20)
		incRaw := payload["include_raw_content"] == true || strField(payload["include_raw_content"]) == "markdown"
		out, status := h.ExecuteSearch(r.Context(), map[string]any{
			"query":  q,
			"limit":  maxRes,
			"scrape": incRaw,
		}, r.Header, pr.EffectiveOwnerID())
		if status >= 400 {
			writeJSON(w, status, map[string]any{"detail": map[string]any{"error": firstNonEmpty(strField(out["error"]), "search_failed")}})
			return
		}
		rawHits, _ := out["results"].([]WebSearchHit)
		results := make([]map[string]any, 0, len(rawHits))
		for i, hit := range rawHits {
			score := hit.Score
			if score <= 0 {
				score = float64(len(rawHits)-i) / float64(max(1, len(rawHits)))
			}
			item := map[string]any{
				"title":   hit.Title,
				"url":     hit.URL,
				"content": firstNonEmpty(hit.Snippet, hit.Description, hit.Markdown),
				"score":   score,
			}
			if incRaw {
				item["raw_content"] = hit.Markdown
			}
			results = append(results, item)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"query":         q,
			"results":       results,
			"response_time": time.Since(started).Seconds(),
		})

	case "/extract":
		pr, ok := h.requireScope(w, r, "crawl:fetch")
		if !ok {
			return
		}
		urls := stringSliceField(payload["urls"])
		if len(urls) == 0 {
			if single := strings.TrimSpace(strField(payload["urls"])); single != "" {
				urls = []string{single}
			} else if u := strings.TrimSpace(strField(payload["url"])); u != "" {
				urls = []string{u}
			}
		}
		if len(urls) == 0 || len(urls) > 20 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"detail": map[string]any{"error": "urls must contain 1..20 URLs"}})
			return
		}
		results := make([]map[string]any, 0, len(urls))
		failed := make([]map[string]any, 0)
		for _, u := range urls {
			scOut, _, st := h.ExecuteScrape(r.Context(), ScrapeRequest{URL: u}, r.Header, pr.EffectiveOwnerID())
			if okVal, _ := scOut["ok"].(bool); st == http.StatusOK && okVal {
				results = append(results, map[string]any{
					"url":         u,
					"raw_content": strField(scOut["markdown"]),
				})
			} else {
				failed = append(failed, map[string]any{
					"url":   u,
					"error": firstNonEmpty(strField(scOut["problem"]), strField(scOut["error"]), fmt.Sprintf("status_%d", st)),
				})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"results":        results,
			"failed_results": failed,
			"response_time":  time.Since(started).Seconds(),
		})

	case "/map":
		if _, ok := h.requireScope(w, r, "crawl:fetch"); !ok {
			return
		}
		baseURL := firstNonEmpty(strField(payload["url"]), strField(payload["base_url"]))
		out, _, status := h.ExecuteMap(r.Context(), map[string]any{
			"url":   baseURL,
			"limit": intField(payload["limit"], 100, 1, 500),
		}, r.Header)
		if status >= 400 {
			writeJSON(w, status, map[string]any{"detail": map[string]any{"error": firstNonEmpty(strField(out["error"]), "map_failed")}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"base_url":      out["url"],
			"results":       out["links"],
			"response_time": time.Since(started).Seconds(),
		})

	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"detail": map[string]any{"error": "not_found"}})
	}
}

func readCompatJSON(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	buf, tooLarge, err := ReadBoundedBody(w, r, maxScrapeBodyBytes)
	if tooLarge {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"success": false, "error": "payload_too_large"})
		return nil, false
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "bad_json"})
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(buf, &m); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "bad_json"})
		return nil, false
	}
	return m, true
}
