package hub

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agentloop"
	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

// HandleExtract serves `POST /v1/extract`.
func (h *RouteHandler) HandleExtract(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, status := h.ExecuteExtract(r.Context(), payload, r.Header, p.EffectiveOwnerID())
	writeJSON(w, status, out)
}

// ExecuteExtract scrapes 1..10 URLs and runs BYO-LLM or deterministic structured extraction.
func (h *RouteHandler) ExecuteExtract(ctx context.Context, payload map[string]any, hdr http.Header, ownerID string) (map[string]any, int) {
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.extract", 1, nil)
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	urls := stringSliceField(payload["urls"])
	if len(urls) == 0 {
		if single, ok := payload["url"].(string); ok && strings.TrimSpace(single) != "" {
			urls = []string{strings.TrimSpace(single)}
		}
	}
	if len(urls) == 0 || len(urls) > 10 {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "invalid_urls", "message": "urls must contain 1 to 10 URLs"}, statusOut
	}
	prompt, _ := payload["prompt"].(string)
	schema, _ := payload["schema"].(map[string]any)
	colID := strings.TrimSpace(strField(payload["collectionId"]))
	llmCfgOut := agentloop.ResolveLLMConfig(agentloop.ResolveLLMConfigInput{
		Env:        h.llmEnvConfig(),
		RequestLLM: rawJSONField(payload["llm"]),
	})

	items := make([]map[string]any, 0, len(urls))
	var combinedMD strings.Builder
	var firstTitle string
	for _, rawU := range urls {
		scOut, _, scSt := h.ExecuteScrape(ctx, ScrapeRequest{URL: rawU, skipRouteSpan: true}, hdr, ownerID)
		md := strField(scOut["markdown"])
		title := strField(scOut["title"])
		desc := strField(scOut["description"])
		if firstTitle == "" {
			firstTitle = title
		}
		if colID != "" && md != "" {
			h.ingestCollectionDoc(ctx, CollectionDocInput{
				CollectionID: colID, OwnerID: ownerID, Visibility: firstNonEmpty(strField(payload["visibility"]), "public"),
				DocumentID: "extract:" + sha256HexStr(ownerID + ":" + rawU)[:24], PageID: sha256HexStr(ownerID + ":" + rawU)[:24],
				URL: rawU, Title: firstNonEmpty(title, rawU), Description: desc, Markdown: md, FetchedAtMs: time.Now().UnixMilli(),
			})
		}
		combinedMD.WriteString("## " + rawU + "\n" + md + "\n\n")
		doc := extract.ExtractedDocumentFull{Title: title, Description: desc, Markdown: md}
		detData, matched, unfilled := extract.ExtractStructuredJSONFromPageWithDiagnostics("", doc, schema, prompt)
		if scOut["schemaOrg"] != nil && len(detData) == 0 {
			detData["schemaOrg"] = scOut["schemaOrg"]
		}
		items = append(items, map[string]any{"url": rawU, "status": scSt, "data": detData, "matchedFields": matched, "unfilledFields": unfilled})
	}

	firstMap, _ := items[0]["data"].(map[string]any)
	var finalData any = firstMap
	mode := "deterministic"
	if llmCfgOut.OK && llmCfgOut.Config != nil {
		if llmData, viaLLM := agentloop.ExtractJSONWithOptionalLLM(
			ctx, combinedMD.String(), firstTitle, urls[0], prompt, schema, firstMap, llmCfgOut.Config, h.llmTransportFor(ctx, *llmCfgOut.Config),
		); viaLLM && llmData != nil {
			finalData = llmData
			mode = "llm"
		}
	}
	return map[string]any{"ok": true, "mode": mode, "data": finalData, "results": items}, http.StatusOK
}

// HandleMap serves `POST /v1/map`.
func (h *RouteHandler) HandleMap(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireScope(w, r, "crawl:fetch"); !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, via, status := h.ExecuteMap(r.Context(), payload, r.Header)
	if via != "" {
		w.Header().Set("X-Crawler-Via", via)
	}
	writeJSON(w, status, out)
}

// ExecuteMap discovers URLs from `/llms.txt`, `/sitemap.xml`, and page links.
func (h *RouteHandler) ExecuteMap(ctx context.Context, payload map[string]any, hdr http.Header) (map[string]any, string, int) {
	rawU := strings.TrimSpace(strField(payload["url"]))
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.map", 1, map[string]any{"url.full": otel.SanitizeURL(rawU)})
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	pu, err := url.Parse(rawU)
	if err != nil || pu.Host == "" || h.allowURL(pu) != nil {
		statusOut = http.StatusBadRequest
		return map[string]any{"ok": false, "error": "invalid_url"}, "hub", statusOut
	}
	limit := intField(payload["limit"], 100, 1, 500)
	searchFilter := strings.ToLower(strings.TrimSpace(strField(payload["search"])))
	origin := pu.Scheme + "://" + pu.Host
	if h.deps.DispatchFetch == nil {
		statusOut = http.StatusServiceUnavailable
		return map[string]any{"ok": false, "error": "hub_unavailable"}, "hub", statusOut
	}
	rep, via, dSt, dErr := h.deps.DispatchFetch(ctx, crawl.FetchCall{
		MaxSeconds: 30, Options: crawl.Options{Concurrency: 2, IncludeBody: true, RespectRobots: crawl.Bool(true)},
		Requests: []crawl.Request{
			{ID: "llms", URL: origin + "/llms.txt", Kind: classify.KindText, Accept: "text/plain"},
			{ID: "sitemap", URL: origin + "/sitemap.xml", Kind: classify.KindText, Accept: "application/xml"},
			{ID: "home", URL: pu.String(), Kind: classify.KindScrape, Formats: []string{"links"}},
		},
	}, strField(payload["target"]), strField(payload["site"]), hdr)
	if dErr != nil {
		statusOut = firstPositiveStatus(dSt, http.StatusServiceUnavailable)
		return map[string]any{"ok": false, "error": dErr.Error()}, via, statusOut
	}
	seen := map[string]bool{}
	links := make([]string, 0, 16)
	add := func(c string) {
		c = strings.TrimSpace(c)
		if c == "" || len(links) >= limit || seen[c] {
			return
		}
		if cu, e := url.Parse(c); e != nil || h.allowURL(cu) != nil {
			return
		}
		if searchFilter != "" && !strings.Contains(strings.ToLower(c), searchFilter) {
			return
		}
		seen[c] = true
		links = append(links, c)
	}
	for _, it := range rep.Results {
		bodyStr := decodeReplyBodyString(it)
		for _, l := range it.Links {
			add(l)
		}
		for _, m := range reHubSitemapLoc.FindAllStringSubmatch(bodyStr, 500) {
			if len(m) > 1 {
				add(m[1])
			}
		}
		for _, m := range reHubMdURL.FindAllStringSubmatch(bodyStr, 500) {
			if len(m) > 1 {
				add(m[1])
			}
		}
		if strings.Contains(bodyStr, "<") {
			doc := extract.ExtractHTMLDocumentFull(bodyStr, extract.FullExtractOptions{BaseURL: origin})
			for _, l := range doc.Links {
				add(l)
			}
		}
	}
	return map[string]any{"ok": true, "url": origin, "total": len(links), "links": links}, via, http.StatusOK
}

// HandleInteract serves `POST /v1/interact`.
func (h *RouteHandler) HandleInteract(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	payload, okBody := readV1JSON(w, r)
	if !okBody {
		return
	}
	out, via, status := h.ExecuteInteract(r.Context(), payload, r.Header, p.EffectiveOwnerID())
	if via != "" {
		w.Header().Set("X-Crawler-Via", via)
	}
	writeJSON(w, status, out)
}

// ExecuteInteract validates browser availability (`T2-A4`), HMAC-binds `sessionId`, and runs interactive browser actions.
func (h *RouteHandler) ExecuteInteract(ctx context.Context, payload map[string]any, hdr http.Header, ownerID string) (map[string]any, string, int) {
	var actions []browser.InteractAction
	if rawActs, ok := payload["actions"]; ok {
		b, _ := json.Marshal(rawActs)
		_ = json.Unmarshal(b, &actions)
	}
	rawSess := strings.TrimSpace(strField(payload["sessionId"]))
	sessHash := ""
	if rawSess != "" {
		sessHash = sha256HexStr(rawSess)[:16]
	}
	ctx, span, _ := otel.StartChildSpan(ctx, h.deps.OtelExporter, "edgefetch.interact", 1, map[string]any{
		"edgefetch.interact.action_count": len(actions),
		"edgefetch.interact.session_hash": sessHash,
	})
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	if !h.hasBrowser() {
		statusOut = http.StatusServiceUnavailable
		return map[string]any{
			"ok":      false,
			"error":   "browser_unavailable",
			"message": "No browser-capable worker node connected",
		}, "hub", statusOut
	}

	sessionID, okSess := h.verifyOrMintInteractSession(rawSess, ownerID)
	if !okSess {
		statusOut = http.StatusForbidden
		return map[string]any{"ok": false, "error": "invalid_session", "message": "Invalid or unauthorized sessionId"}, "hub", statusOut
	}
	span.SetAttribute("edgefetch.interact.session_hash", sha256HexStr(sessionID)[:16])

	closeReq := boolField(payload["close"]) || boolField(payload["closeSession"])
	keepReq := boolField(payload["keepSession"])
	rawURL := strings.TrimSpace(strField(payload["url"]))
	if rawURL == "" && rawSess != "" {
		h.mem.mu.RLock()
		rawURL = h.mem.interactSessions[sessionID]
		h.mem.mu.RUnlock()
	}
	if rawURL != "" {
		h.mem.mu.Lock()
		if closeReq {
			delete(h.mem.interactSessions, sessionID)
		} else {
			h.mem.interactSessions[sessionID] = rawURL
		}
		h.mem.mu.Unlock()
	}
	if closeReq && rawURL == "" {
		return map[string]any{"ok": true, "sessionId": sessionID, "closed": true}, "hub", http.StatusOK
	}
	scOut, via, st := h.ExecuteScrape(ctx, ScrapeRequest{
		URL: rawURL, RenderMode: "always", Actions: actions, Target: strField(payload["target"]), Site: strField(payload["site"]),
		skipRouteSpan: true,
		interactSpec: &crawl.InteractSpec{
			SessionID:    sessionID,
			KeepSession:  keepReq && !closeReq,
			CloseSession: closeReq,
			Actions:      actions,
		},
	}, hdr, ownerID)
	statusOut = st
	scOut["sessionId"] = sessionID
	scOut["closed"] = closeReq
	return scOut, via, st
}

func (h *RouteHandler) verifyOrMintInteractSession(rawSess, ownerID string) (string, bool) {
	sign := func(id string) string {
		mac := hmac.New(sha256.New, []byte(h.sessionSecret()))
		_, _ = mac.Write([]byte(ownerID + ":" + id))
		return hex.EncodeToString(mac.Sum(nil))[:32]
	}
	if rawSess == "" {
		id := randomHex(12)
		return "efi_" + id + "." + sign(id), true
	}
	if !strings.HasPrefix(rawSess, "efi_") {
		return "", false
	}
	id, gotMAC, ok := strings.Cut(strings.TrimPrefix(rawSess, "efi_"), ".")
	if !ok || id == "" || gotMAC == "" {
		return "", false
	}
	return rawSess, constantTimeEquals(gotMAC, sign(id))
}

// HandleIngestTab serves `OPTIONS / POST /v1/ingest-tab` (`T2-A6`).
func (h *RouteHandler) HandleIngestTab(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key, Traceparent")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p, ok := h.requireScope(w, r, "crawl:fetch")
	if !ok {
		return
	}
	ctx, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, "edgefetch.ingest_tab", 1, nil)
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	buf, tooLarge, err := ReadBoundedBody(w, r, maxIngestTabBodyBytes)
	if tooLarge {
		statusOut = http.StatusRequestEntityTooLarge
		writeJSON(w, statusOut, map[string]any{"ok": false, "error": "payload_too_large"})
		return
	}
	if err != nil {
		statusOut = http.StatusBadRequest
		writeJSON(w, statusOut, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	var clip struct {
		URL             string `json:"url"`
		Title           string `json:"title"`
		HTML            string `json:"html"`
		Markdown        string `json:"markdown"`
		CollectionID    string `json:"collectionId"`
		OnlyMainContent *bool  `json:"onlyMainContent"`
		Visibility      string `json:"visibility"`
	}
	if json.Unmarshal(buf, &clip) != nil {
		statusOut = http.StatusBadRequest
		writeJSON(w, statusOut, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	pu, uErr := url.Parse(strings.TrimSpace(clip.URL))
	if uErr != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
		statusOut = http.StatusBadRequest
		writeJSON(w, statusOut, map[string]any{"ok": false, "error": "invalid_url"})
		return
	}
	pu.Fragment = ""
	cleanURL := pu.String()
	span.SetAttribute("url.full", otel.SanitizeURL(cleanURL))

	md := strings.TrimSpace(extract.SanitizeScrapedMarkdown(clip.Markdown))
	title := strings.TrimSpace(extract.SanitizeScrapedMeta(clip.Title))
	if md == "" && strings.TrimSpace(clip.HTML) != "" {
		onlyMain := clip.OnlyMainContent == nil || *clip.OnlyMainContent
		doc := extract.ExtractHTMLDocumentFull(clip.HTML, extract.FullExtractOptions{BaseURL: cleanURL, OnlyMainContent: onlyMain})
		md = strings.TrimSpace(extract.SanitizeScrapedMarkdown(doc.Markdown))
		if title == "" {
			title = extract.SanitizeScrapedMeta(doc.Title)
		}
	}
	if md == "" {
		statusOut = http.StatusBadRequest
		writeJSON(w, statusOut, map[string]any{"ok": false, "error": "empty_content"})
		return
	}
	colID := firstNonEmpty(clip.CollectionID, "browser-clips")
	vis := firstNonEmpty(clip.Visibility, "public")
	ownerID := p.EffectiveOwnerID()
	artID := h.persistArtifact(ctx, md, ownerID, vis)
	chunks := h.ingestCollectionDoc(ctx, CollectionDocInput{
		CollectionID: colID, OwnerID: ownerID, Visibility: vis,
		DocumentID: "clip:" + artID[:32], PageID: sha256HexStr(ownerID + ":" + cleanURL)[:32],
		URL: cleanURL, Title: firstNonEmpty(title, cleanURL), Markdown: md, FetchedAtMs: time.Now().UnixMilli(),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "url": cleanURL, "title": firstNonEmpty(title, cleanURL),
		"collectionId": colID, "indexedChunks": chunks, "contentSha256": artID, "markdown": md,
	})
}

// HandleCollectionSearch serves `GET / POST /v1/collections/:id/search`.
func (h *RouteHandler) HandleCollectionSearch(w http.ResponseWriter, r *http.Request, collectionID string) {
	p, ok := h.requireScope(w, r, "crawl:read")
	if !ok {
		return
	}
	ctx, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, "edgefetch.collection_search", 1, map[string]any{"edgefetch.collection_id": collectionID})
	defer span.End(true, "")

	query := firstNonEmpty(r.URL.Query().Get("q"), r.URL.Query().Get("query"))
	limit := intField(r.URL.Query().Get("limit"), 10, 1, 100)
	if r.Method == http.MethodPost {
		buf, tooLarge, err := ReadBoundedBody(w, r, maxScrapeBodyBytes)
		if tooLarge {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "payload_too_large"})
			return
		}
		if err == nil && len(buf) > 0 {
			var body map[string]any
			if json.Unmarshal(buf, &body) == nil {
				query = firstNonEmpty(strField(body["query"]), strField(body["q"]), query)
				limit = intField(body["limit"], limit, 1, 100)
			}
		}
	}
	hits := h.searchCollectionDocs(ctx, firstNonEmpty(collectionID, "default"), query, p.EffectiveOwnerID(), limit)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "collectionId": collectionID, "query": query, "hits": hits})
}

func (h *RouteHandler) ingestCollectionDoc(ctx context.Context, doc CollectionDocInput) int {
	if h.deps.IngestCollectionPage != nil {
		if n, err := h.deps.IngestCollectionPage(ctx, doc); err == nil {
			return n
		}
	}
	h.mem.mu.Lock()
	key := doc.OwnerID + ":" + doc.CollectionID
	existing := h.mem.collections[key]
	replaced := false
	for i := range existing {
		if existing[i].URL == doc.URL {
			existing[i] = doc
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, doc)
	}
	h.mem.collections[key] = existing
	h.mem.mu.Unlock()
	return max(1, (len(doc.Markdown)+1023)/1024)
}

func (h *RouteHandler) searchCollectionDocs(ctx context.Context, collectionID, query, ownerID string, limit int) []CollectionSearchHit {
	if h.deps.SearchCollection != nil {
		if hits, err := h.deps.SearchCollection(ctx, collectionID, query, ownerID, limit); err == nil {
			if hits == nil {
				return []CollectionSearchHit{}
			}
			return hits
		}
	}
	qLow := strings.ToLower(strings.TrimSpace(query))
	tokens := strings.Fields(qLow)
	h.mem.mu.RLock()
	docs := append([]CollectionDocInput(nil), h.mem.collections[ownerID+":"+collectionID]...)
	if ownerID != "owner" && len(docs) == 0 {
		docs = append(docs, h.mem.collections["owner:"+collectionID]...)
	}
	h.mem.mu.RUnlock()

	hits := make([]CollectionSearchHit, 0, min(limit, len(docs)))
	for _, d := range docs {
		hay := strings.ToLower(d.Title + "\n" + d.Markdown)
		score := 0.0
		if qLow == "" {
			score = 1.0
		} else {
			for _, tok := range tokens {
				if strings.Contains(hay, tok) {
					score += 1.0
				}
			}
		}
		if score <= 0 {
			continue
		}
		snip := d.Markdown
		if len(snip) > 280 {
			snip = snip[:280]
		}
		hits = append(hits, CollectionSearchHit{
			CollectionID: collectionID, DocumentID: d.DocumentID, PageID: d.PageID,
			URL: d.URL, Title: d.Title, Snippet: snip, Score: score,
		})
		if len(hits) >= limit {
			break
		}
	}
	return hits
}

func readV1JSON(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	buf, tooLarge, err := ReadBoundedBody(w, r, maxScrapeBodyBytes)
	if tooLarge {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "payload_too_large"})
		return nil, false
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(buf, &m); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return nil, false
	}
	return m, true
}

func normalizeScrapeFormats(raw []any) ([]string, bool) {
	var out []string
	wantShot := false
	for _, f := range raw {
		switch v := f.(type) {
		case string:
			if v == "screenshot" {
				wantShot = true
			}
			out = append(out, v)
		case map[string]any:
			if t, ok := v["type"].(string); ok && t != "" {
				if t == "screenshot" {
					wantShot = true
				}
				out = append(out, t)
			}
		}
	}
	if len(out) == 0 {
		out = []string{"markdown", "links"}
	}
	return out, wantShot
}

func firstPositiveStatus(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return http.StatusInternalServerError
}

func cloneMap(in map[string]any) map[string]any {
	b, _ := json.Marshal(in)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func structToMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func extractSpaFallbackMarkdown(parsed map[string]any) (string, string) {
	if parsed == nil {
		return "", ""
	}
	if results, ok := parsed["results"].([]any); ok && len(results) > 0 {
		if r0, ok := results[0].(map[string]any); ok {
			if mdObj, ok := r0["markdown"].(map[string]any); ok {
				return firstNonEmpty(strField(mdObj["fit_markdown"]), strField(mdObj["raw_markdown"])), strField(r0["title"])
			}
			return strField(r0["markdown"]), strField(r0["title"])
		}
	}
	if data, ok := parsed["data"].(map[string]any); ok {
		meta, _ := data["metadata"].(map[string]any)
		return strField(data["markdown"]), strField(meta["title"])
	}
	return strField(parsed["markdown"]), strField(parsed["title"])
}
