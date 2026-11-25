package hubstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

const rrfK = 60.0

// ErrInvalidSearchQuery indicates an empty or oversized search query.
var ErrInvalidSearchQuery = errors.New("hubstore: search query must be 1..500 characters")

var trackingQueryParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true, "utm_term": true,
	"utm_content": true, "utm_id": true, "gclid": true, "fbclid": true,
	"msclkid": true, "mc_cid": true, "mc_eid": true, "_hsenc": true, "_hsmi": true,
}

var highlightReplacer = strings.NewReplacer(
	"<b>", "", "</b>", "", "<B>", "", "</B>", "",
	"<em>", "", "</em>", "", "<EM>", "", "</EM>", "",
	"<strong>", "", "</strong>", "",
)

// SearchConfig holds external provider credentials, local BM25 collection index, HTTP client, and OTLP exporter.
type SearchConfig struct {
	SearxngURL           string
	SerperAPIKey         string
	BraveAPIKey          string
	TavilyAPIKey         string
	CollectionIndex      *CollectionIndex
	CollectionStorageKey string
	OperatorClient       *http.Client
	OtelExporter         *otel.Exporter
}

// SearchParams configures a federated RRF search invocation.
type SearchParams struct {
	Query      string   `json:"query"`
	Limit      int      `json:"limit"`
	Sources    []string `json:"sources,omitempty"`
	Providers  []string `json:"providers,omitempty"`
	Collection string   `json:"collection,omitempty"`
	Category   string   `json:"category,omitempty"`
	TimeRange  string   `json:"timeRange,omitempty"`
	Country    string   `json:"country,omitempty"`
	Language   string   `json:"language,omitempty"`
}

type rawProviderHit struct {
	url     string
	title   string
	snippet string
}

// CanonicalizeSearchURL normalizes a search result URL, stripping fragments and tracking query parameters.
func CanonicalizeSearchURL(rawURL string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	u.Fragment = ""
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if port := u.Port(); port != "" && !((u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80")) {
		u.Host = host + ":" + port
	} else {
		u.Host = host
	}
	if u.RawQuery != "" {
		q := u.Query()
		changed := false
		for k := range q {
			if lk := strings.ToLower(k); trackingQueryParams[lk] || strings.HasPrefix(lk, "utm_") {
				q.Del(k)
				changed = true
			}
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	if len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimRight(u.Path, "/")
	}
	return u.String(), true
}

func sanitizeProviderField(s string) string {
	return extract.SanitizeScrapedMeta(highlightReplacer.Replace(s))
}

func normalizeTimeRangeCode(tr string) (std, serper, brave string) {
	switch strings.ToLower(strings.TrimSpace(tr)) {
	case "day", "d":
		return "day", "qdr:d", "pd"
	case "week", "w":
		return "week", "qdr:w", "pw"
	case "month", "m":
		return "month", "qdr:m", "pm"
	case "year", "y":
		return "year", "qdr:y", "py"
	default:
		return "", "", ""
	}
}

func doTracedProviderRequest(
	ctx context.Context,
	exp *otel.Exporter,
	client *http.Client,
	provider, method, reqURL string,
	headers map[string]string,
	bodyBytes []byte,
	parseFn func([]byte) ([]rawProviderHit, error),
) ([]rawProviderHit, error) {
	spanCtx, span, _ := otel.StartChildSpan(ctx, exp, "edgefetch.search."+provider, 3, map[string]any{
		"search.provider":     provider,
		"http.request.method": method,
		"url.full":            otel.SanitizeURL(reqURL),
	})
	reqCtx, cancel := context.WithTimeout(spanCtx, 12*time.Second)
	defer cancel()

	var body io.Reader
	if len(bodyBytes) > 0 {
		body = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, reqURL, body)
	if err != nil {
		span.End(false, provider+"_request_build_error")
		return nil, fmt.Errorf("%s: request build error", provider)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		span.End(false, provider+"_transport_error")
		return nil, fmt.Errorf("%s: transport error", provider)
	}
	defer func() { _ = resp.Body.Close() }()

	span.SetAttribute("http.response.status_code", resp.StatusCode)
	rawResp, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if readErr != nil {
		span.End(false, provider+"_read_error")
		return nil, fmt.Errorf("%s: read error", provider)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fmt.Sprintf("%s_http_%d", provider, resp.StatusCode)
		span.End(false, msg)
		return nil, errors.New(msg)
	}
	hits, parseErr := parseFn(rawResp)
	if parseErr != nil {
		span.End(false, provider+"_parse_error")
		return nil, fmt.Errorf("%s: parse error", provider)
	}
	span.SetAttribute("search.result_count", len(hits))
	span.End(true, "")
	return hits, nil
}

func appendCanonicalHit(dst []rawProviderHit, rawURL, rawTitle, rawSnippet string) []rawProviderHit {
	if canon, ok := CanonicalizeSearchURL(rawURL); ok {
		dst = append(dst, rawProviderHit{
			url:     canon,
			title:   sanitizeProviderField(rawTitle),
			snippet: sanitizeProviderField(rawSnippet),
		})
	}
	return dst
}

func callSearXNG(ctx context.Context, cfg SearchConfig, client *http.Client, p SearchParams, limit int) ([]rawProviderHit, error) {
	base, err := url.Parse(strings.TrimSpace(cfg.SearxngURL))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" {
		return nil, errors.New("searxng_invalid_url")
	}
	u := base.ResolveReference(&url.URL{Path: strings.TrimRight(base.Path, "/") + "/search"})
	q := u.Query()
	q.Set("format", "json")
	q.Set("q", p.Query)
	if p.Category != "" {
		q.Set("categories", p.Category)
	}
	if std, _, _ := normalizeTimeRangeCode(p.TimeRange); std != "" {
		q.Set("time_range", std)
	}
	if p.Language != "" {
		q.Set("language", p.Language)
	}
	u.RawQuery = q.Encode()

	return doTracedProviderRequest(ctx, cfg.OtelExporter, client, "searxng", http.MethodGet, u.String(), nil, nil, func(raw []byte) ([]rawProviderHit, error) {
		var parsed struct {
			Results []struct {
				URL     string `json:"url"`
				Title   string `json:"title"`
				Content string `json:"content"`
			} `json:"results"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, err
		}
		var out []rawProviderHit
		for i, r := range parsed.Results {
			if i >= limit*2 {
				break
			}
			out = appendCanonicalHit(out, r.URL, r.Title, r.Content)
		}
		return out, nil
	})
}

func callSerper(ctx context.Context, cfg SearchConfig, client *http.Client, p SearchParams) ([]rawProviderHit, error) {
	payload := map[string]any{"q": p.Query, "num": 10}
	if _, tbs, _ := normalizeTimeRangeCode(p.TimeRange); tbs != "" {
		payload["tbs"] = tbs
	}
	if p.Country != "" {
		payload["gl"] = strings.ToLower(strings.TrimSpace(p.Country))
	}
	if p.Language != "" {
		payload["hl"] = strings.ToLower(strings.TrimSpace(p.Language))
	}
	bodyBytes, _ := json.Marshal(payload)
	headers := map[string]string{"Content-Type": "application/json", "X-API-Key": strings.TrimSpace(cfg.SerperAPIKey)}
	return doTracedProviderRequest(ctx, cfg.OtelExporter, client, "serper", http.MethodPost, "https://google.serper.dev/search", headers, bodyBytes, func(raw []byte) ([]rawProviderHit, error) {
		var parsed struct {
			KnowledgeGraph *struct {
				Title       string `json:"title"`
				Website     string `json:"website"`
				Description string `json:"description"`
			} `json:"knowledgeGraph"`
			Organic []struct {
				Link    string `json:"link"`
				Title   string `json:"title"`
				Snippet string `json:"snippet"`
			} `json:"organic"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, err
		}
		var out []rawProviderHit
		if kg := parsed.KnowledgeGraph; kg != nil && kg.Website != "" {
			out = appendCanonicalHit(out, kg.Website, kg.Title, kg.Description)
		}
		for _, r := range parsed.Organic {
			out = appendCanonicalHit(out, r.Link, r.Title, r.Snippet)
		}
		return out, nil
	})
}

func callBrave(ctx context.Context, cfg SearchConfig, client *http.Client, p SearchParams, limit int) ([]rawProviderHit, error) {
	u, _ := url.Parse("https://api.search.brave.com/res/v1/web/search")
	q := u.Query()
	q.Set("q", p.Query)
	q.Set("count", strconv.Itoa(min(20, max(1, limit))))
	if _, _, fr := normalizeTimeRangeCode(p.TimeRange); fr != "" {
		q.Set("freshness", fr)
	}
	if p.Country != "" {
		q.Set("country", strings.ToUpper(strings.TrimSpace(p.Country)))
	}
	if p.Language != "" {
		q.Set("search_lang", strings.ToLower(strings.TrimSpace(p.Language)))
	}
	u.RawQuery = q.Encode()
	headers := map[string]string{"X-Subscription-Token": strings.TrimSpace(cfg.BraveAPIKey)}
	return doTracedProviderRequest(ctx, cfg.OtelExporter, client, "brave", http.MethodGet, u.String(), headers, nil, func(raw []byte) ([]rawProviderHit, error) {
		var parsed struct {
			Web struct {
				Results []struct {
					URL         string `json:"url"`
					Title       string `json:"title"`
					Description string `json:"description"`
				} `json:"results"`
			} `json:"web"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, err
		}
		var out []rawProviderHit
		for _, r := range parsed.Web.Results {
			out = appendCanonicalHit(out, r.URL, r.Title, r.Description)
		}
		return out, nil
	})
}

func callTavily(ctx context.Context, cfg SearchConfig, client *http.Client, p SearchParams, limit int) ([]rawProviderHit, error) {
	payload := map[string]any{"query": p.Query, "max_results": min(10, max(1, limit)), "search_depth": "basic"}
	if std, _, _ := normalizeTimeRangeCode(p.TimeRange); std != "" {
		payload["time_range"] = std
	}
	bodyBytes, _ := json.Marshal(payload)
	headers := map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + strings.TrimSpace(cfg.TavilyAPIKey)}
	return doTracedProviderRequest(ctx, cfg.OtelExporter, client, "tavily", http.MethodPost, "https://api.tavily.com/search", headers, bodyBytes, func(raw []byte) ([]rawProviderHit, error) {
		var parsed struct {
			Results []struct {
				URL     string `json:"url"`
				Title   string `json:"title"`
				Content string `json:"content"`
			} `json:"results"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, err
		}
		var out []rawProviderHit
		for _, r := range parsed.Results {
			out = appendCanonicalHit(out, r.URL, r.Title, r.Content)
		}
		return out, nil
	})
}

func resolveEnabledProviders(p SearchParams) (allowCollections, allowSearxng, allowSerper, allowBrave, allowTavily bool) {
	filter := make(map[string]bool)
	for _, s := range append(slices.Clone(p.Sources), p.Providers...) {
		if clean := strings.ToLower(strings.TrimSpace(s)); clean != "" {
			filter[clean] = true
		}
	}
	if len(filter) == 0 {
		return true, true, true, true, true
	}
	anyWeb := filter["web"] || filter["all"]
	return filter["collections"] || filter["collection"] || filter["local"] || filter["fts"],
		anyWeb || filter["searxng"],
		anyWeb || filter["serper"],
		anyWeb || filter["brave"],
		anyWeb || filter["tavily"]
}

// ExecuteWebSearch queries local BM25 collections and configured external search APIs, fusing results via RRF (`k=60`).
func ExecuteWebSearch(ctx context.Context, cfg SearchConfig, p SearchParams) (map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p.Query = strings.TrimSpace(p.Query)
	if p.Query == "" || len(p.Query) > 500 {
		return nil, ErrInvalidSearchQuery
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 10
	} else if limit > 50 {
		limit = 50
	}
	client := cfg.OperatorClient
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}

	allowColl, allowSearxng, allowSerper, allowBrave, allowTavily := resolveEnabledProviders(p)

	type providerBatch struct {
		hits []rawProviderHit
		used bool
	}
	var mu sync.Mutex
	byProvider := make(map[string]providerBatch)

	if allowColl && cfg.CollectionIndex != nil {
		storageKey := strings.TrimSpace(cfg.CollectionStorageKey)
		if storageKey == "" {
			storageKey = strings.TrimSpace(p.Collection)
		}
		if storageKey == "" {
			storageKey = "default"
		}
		collHits := cfg.CollectionIndex.Search(storageKey, p.Query, limit*2, "")
		seenURL := make(map[string]bool, len(collHits))
		var items []rawProviderHit
		for _, h := range collHits {
			if canon, ok := CanonicalizeSearchURL(h.URL); ok && !seenURL[canon] {
				seenURL[canon] = true
				items = append(items, rawProviderHit{
					url: canon, title: sanitizeProviderField(h.Title), snippet: sanitizeProviderField(h.Snippet),
				})
			}
		}
		if len(items) > 0 || p.Collection != "" {
			byProvider["collections"] = providerBatch{hits: items, used: true}
		}
	}

	var wg sync.WaitGroup
	launch := func(name string, fn func() ([]rawProviderHit, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hits, err := fn()
			mu.Lock()
			byProvider[name] = providerBatch{hits: hits, used: err == nil}
			mu.Unlock()
		}()
	}
	if allowSearxng && strings.TrimSpace(cfg.SearxngURL) != "" {
		launch("searxng", func() ([]rawProviderHit, error) { return callSearXNG(ctx, cfg, client, p, limit) })
	}
	if allowSerper && strings.TrimSpace(cfg.SerperAPIKey) != "" {
		launch("serper", func() ([]rawProviderHit, error) { return callSerper(ctx, cfg, client, p) })
	}
	if allowBrave && strings.TrimSpace(cfg.BraveAPIKey) != "" {
		launch("brave", func() ([]rawProviderHit, error) { return callBrave(ctx, cfg, client, p, limit) })
	}
	if allowTavily && strings.TrimSpace(cfg.TavilyAPIKey) != "" {
		launch("tavily", func() ([]rawProviderHit, error) { return callTavily(ctx, cfg, client, p, limit) })
	}
	wg.Wait()

	type fusedEntry struct {
		url, title, snippet string
		rrfScore            float64
		providers           []string
	}
	order := []string{"collections", "searxng", "serper", "brave", "tavily"}
	providersUsed := make([]string, 0, len(order))
	fusedMap := make(map[string]*fusedEntry)

	for _, provName := range order {
		batch, ok := byProvider[provName]
		if !ok || !batch.used {
			continue
		}
		providersUsed = append(providersUsed, provName)
		seenInProv := make(map[string]bool, len(batch.hits))
		rank := 0
		for _, item := range batch.hits {
			if seenInProv[item.url] {
				continue
			}
			seenInProv[item.url] = true
			addScore := 1.0 / (rrfK + float64(rank+1))
			rank++
			if existing, exists := fusedMap[item.url]; exists {
				existing.rrfScore += addScore
				if !slices.Contains(existing.providers, provName) {
					existing.providers = append(existing.providers, provName)
				}
				if existing.title == "" && item.title != "" {
					existing.title = item.title
				}
				if existing.snippet == "" && item.snippet != "" {
					existing.snippet = item.snippet
				}
			} else {
				title := item.title
				if title == "" {
					title = extractURLHostname(item.url)
				}
				fusedMap[item.url] = &fusedEntry{
					url: item.url, title: title, snippet: item.snippet,
					rrfScore: addScore, providers: []string{provName},
				}
			}
		}
	}

	ranked := make([]*fusedEntry, 0, len(fusedMap))
	for _, fe := range fusedMap {
		ranked = append(ranked, fe)
	}
	slices.SortFunc(ranked, func(a, b *fusedEntry) int {
		if a.rrfScore != b.rrfScore {
			if b.rrfScore > a.rrfScore {
				return 1
			}
			return -1
		}
		return strings.Compare(a.url, b.url)
	})
	ranked = ranked[:min(len(ranked), limit)]

	maxRRF := 1.0
	if len(ranked) > 0 && ranked[0].rrfScore > 0 {
		maxRRF = ranked[0].rrfScore
	}
	results := make([]map[string]any, len(ranked))
	for i, r := range ranked {
		normScore := math.Round(math.Min(1.0, (r.rrfScore/maxRRF)*0.95)*10000) / 10000
		results[i] = map[string]any{
			"url": r.url, "title": r.title, "description": r.snippet, "content": r.snippet,
			"snippet": r.snippet, "score": normScore, "rrfScore": math.Round(r.rrfScore*1e6) / 1e6,
			"provider": r.providers[0], "providers": r.providers,
		}
	}
	return map[string]any{
		"ok": true, "query": p.Query, "providersUsed": providersUsed,
		"total": len(results), "results": results, "web": results,
	}, nil
}
