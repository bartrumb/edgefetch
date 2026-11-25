package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agentloop"
	"github.com/bartrumb/edgefetch/v2/internal/catalog"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

type ScrapeCacheLookup struct {
	Hit         bool           `json:"hit"`
	NotModified bool           `json:"notModified"`
	ETag        string         `json:"etag,omitempty"`
	Payload     map[string]any `json:"payload,omitempty"`
}

type ScrapeCacheEntry struct {
	URL        string         `json:"url"`
	OwnerID    string         `json:"ownerId,omitempty"`
	Visibility string         `json:"visibility,omitempty"`
	ETag       string         `json:"etag,omitempty"`
	Payload    map[string]any `json:"payload"`
	StoredAtMs int64          `json:"storedAtMs"`
}

type ArtifactSliceRequest struct {
	ArtifactID string `json:"artifactId"`
	OwnerID    string `json:"ownerId,omitempty"`
	Visibility string `json:"visibility,omitempty"`
	Retention  string `json:"retention,omitempty"`
	Format     string `json:"format,omitempty"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
}

type ArtifactSlicePage struct {
	ArtifactID    string `json:"artifactId"`
	Content       string `json:"content"`
	Format        string `json:"format"`
	TotalChars    int    `json:"totalChars"`
	ReturnedChars int    `json:"returnedChars"`
	Offset        int    `json:"offset"`
	Truncated     bool   `json:"truncated"`
	NextOffset    *int   `json:"nextOffset,omitempty"`
}

type HostTelemetryEvent struct {
	Host        string `json:"host"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Outcome     string `json:"outcome"`
	Via         string `json:"via"`
	AdapterID   string `json:"adapterId,omitempty"`
	DurationMs  int64  `json:"durationMs"`
	TimestampMs int64  `json:"timestampMs"`
}

type AsyncJobRecord struct {
	Kind         string           `json:"kind"`
	ID           string           `json:"id"`
	OwnerID      string           `json:"ownerId"`
	Status       string           `json:"status"`
	Total        int              `json:"total"`
	Completed    int              `json:"completed"`
	CollectionID string           `json:"collectionId,omitempty"`
	Data         []map[string]any `json:"data,omitempty"`
	Errors       []map[string]any `json:"errors,omitempty"`
	Payload      map[string]any   `json:"payload,omitempty"`
	CreatedAtMs  int64            `json:"createdAtMs"`
	UpdatedAtMs  int64            `json:"updatedAtMs"`
}

type CollectionDocInput struct {
	CollectionID string `json:"collectionId"`
	OwnerID      string `json:"ownerId"`
	Visibility   string `json:"visibility"`
	DocumentID   string `json:"documentId"`
	PageID       string `json:"pageId"`
	URL          string `json:"url"`
	Title        string `json:"title"`
	Description  string `json:"description,omitempty"`
	Markdown     string `json:"markdown"`
	FetchedAtMs  int64  `json:"fetchedAtMs"`
}

type CollectionSearchHit struct {
	CollectionID string  `json:"collectionId"`
	DocumentID   string  `json:"documentId,omitempty"`
	PageID       string  `json:"pageId,omitempty"`
	URL          string  `json:"url"`
	Title        string  `json:"title"`
	Snippet      string  `json:"snippet"`
	Score        float64 `json:"score"`
}

type WebSearchRequest struct {
	Query      string   `json:"query"`
	Limit      int      `json:"limit"`
	Collection string   `json:"collection,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Scrape     bool     `json:"scrape,omitempty"`
	MaxChars   int      `json:"maxChars,omitempty"`
	OwnerID    string   `json:"ownerId,omitempty"`
	Visibility string   `json:"visibility,omitempty"`
}

type WebSearchHit struct {
	Title       string  `json:"title"`
	URL         string  `json:"url"`
	Description string  `json:"description,omitempty"`
	Snippet     string  `json:"snippet,omitempty"`
	Markdown    string  `json:"markdown,omitempty"`
	Score       float64 `json:"score,omitempty"`
}

type WebSearchResponse struct {
	Provider string         `json:"provider"`
	Query    string         `json:"query"`
	Results  []WebSearchHit `json:"results"`
}

type ConnectedMcpConfig struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	EndpointURL    string            `json:"endpointUrl"`
	Transport      string            `json:"transport"`
	AuthType       string            `json:"authType"`
	Enabled        bool              `json:"enabled"`
	DomainPatterns []string          `json:"domainPatterns,omitempty"`
	Description    string            `json:"description,omitempty"`
	ToolsCache     []map[string]any  `json:"toolsCache,omitempty"`
	SealedAuth     string            `json:"sealedAuth,omitempty"`
	PlainHeaders   map[string]string `json:"plainHeaders,omitempty"`
	UpdatedAtMs    int64             `json:"updatedAtMs,omitempty"`
}

// RouteDeps decouples `/v1/*`, `/v2/*`, `/compat/*`, and `/mcp` handlers from storage/auth concrete types.
type RouteDeps struct {
	DispatchFetch        func(ctx context.Context, call crawl.FetchCall, target, site string, hdr http.Header) (reply crawl.FetchReply, via string, status int, err error)
	HasBrowserCapability func() bool
	AllowURL             func(*url.URL) error
	OperatorClient       *http.Client
	OtelExporter         *otel.Exporter
	Getenv               func(string) string
	RobotsBypassHosts    []string
	SessionSecret        string
	PublicOrigin         string
	VaultMasterKey       string
	ListAgents           func() map[string]any
	Capabilities         func() map[string]any

	LookupScrapeCache       func(ctx context.Context, rawURL, ownerID string, maxAgeMs int64, ifNoneMatch string) (ScrapeCacheLookup, error)
	StoreScrapeCache        func(ctx context.Context, entry ScrapeCacheEntry) error
	PersistMarkdownArtifact func(ctx context.Context, markdown, ownerID, visibility string) (artifactID string, err error)
	ReadArtifactPage        func(ctx context.Context, req ArtifactSliceRequest) (*ArtifactSlicePage, int, string, error)
	RecordHostTelemetry     func(ctx context.Context, ev HostTelemetryEvent)
	ListHosts               func(ctx context.Context, limit int) ([]map[string]any, error)
	ListHostGaps            func(ctx context.Context, limit int) ([]map[string]any, error)
	PutAsyncJob             func(ctx context.Context, rec AsyncJobRecord) error
	GetAsyncJob             func(ctx context.Context, kind, id, ownerID string) (*AsyncJobRecord, bool)
	CancelAsyncJob          func(ctx context.Context, kind, id, ownerID string) bool
	IngestCollectionPage    func(ctx context.Context, doc CollectionDocInput) (indexedChunks int, err error)
	SearchCollection        func(ctx context.Context, collectionID, query, ownerID string, limit int) ([]CollectionSearchHit, error)
	ExecuteWebSearch        func(ctx context.Context, req WebSearchRequest) (*WebSearchResponse, error)
	CatalogStore            *catalog.CatalogStore
	ListConnectedMcp        func(ctx context.Context, ownerID string) ([]ConnectedMcpConfig, error)
}

type MemoryRouteStore struct {
	mu               sync.RWMutex
	scrapeCache      map[string]ScrapeCacheEntry
	artifacts        map[string]string
	jobs             map[string]AsyncJobRecord
	collections      map[string][]CollectionDocInput
	interactSessions map[string]string
}

func NewMemoryRouteStore() *MemoryRouteStore {
	return &MemoryRouteStore{
		scrapeCache:      make(map[string]ScrapeCacheEntry),
		artifacts:        make(map[string]string),
		jobs:             make(map[string]AsyncJobRecord),
		collections:      make(map[string][]CollectionDocInput),
		interactSessions: make(map[string]string),
	}
}

type RouteHandler struct {
	deps  RouteDeps
	mem   *MemoryRouteStore
	catSt *catalog.CatalogStore
	opCli *http.Client
}

func NewRouteHandler(deps RouteDeps) *RouteHandler {
	catSt := deps.CatalogStore
	if catSt == nil {
		catSt = catalog.NewCatalogStore()
	}
	opCli := deps.OperatorClient
	if opCli == nil {
		opCli = &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &RouteHandler{deps: deps, mem: NewMemoryRouteStore(), catSt: catSt, opCli: opCli}
}

func NewServerRouteDeps(s *Server) RouteDeps {
	return RouteDeps{
		DispatchFetch: s.DispatchOrFallback,
		HasBrowserCapability: func() bool {
			s.mu.Lock()
			for _, sess := range s.agents {
				if sess.hasCapability("browser-v1") {
					s.mu.Unlock()
					return true
				}
			}
			s.mu.Unlock()
			hasAgentAuth := s.cfg.AgentToken != "" || len(s.cfg.AgentTokens) > 0
			if !hasAgentAuth && s.cfg.FallbackCrawler != nil {
				for _, c := range s.cfg.FallbackCrawler.Capabilities() {
					if c == "browser-v1" {
						return true
					}
				}
			}
			return false
		},
		AllowURL:      s.allow,
		OtelExporter:  s.cfg.OtelExporter,
		Getenv:        os.Getenv,
		SessionSecret: s.cfg.CallerToken,
		ListAgents:    s.ListAgents,
		CatalogStore:  catalog.NewCatalogStore(),
	}
}

func (h *RouteHandler) allowURL(u *url.URL) error {
	if h.deps.AllowURL != nil {
		return h.deps.AllowURL(u)
	}
	return crawl.PublicHTTPS(u)
}

func (h *RouteHandler) getenv(key string) string {
	if h.deps.Getenv != nil {
		return h.deps.Getenv(key)
	}
	return ""
}

func (h *RouteHandler) llmEnvConfig() agentloop.LLMEnvConfig {
	return agentloop.LLMEnvConfig{
		EdgeFetchLLMProvider:        h.getenv("EDGEFETCH_LLM_PROVIDER"),
		EdgeFetchLLMBaseURL:         firstNonEmpty(h.getenv("EDGEFETCH_LLM_BASE_URL"), h.getenv("LLM_BASE_URL")),
		EdgeFetchLLMAPIKey:          h.getenv("EDGEFETCH_LLM_API_KEY"),
		EdgeFetchLLMModel:           firstNonEmpty(h.getenv("EDGEFETCH_LLM_MODEL"), h.getenv("LLM_MODEL")),
		EdgeFetchAllowLocalOverride: h.getenv("EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE"),
		OllamaHost:                  h.getenv("OLLAMA_HOST"),
		OpenAIAPIKey:                h.getenv("OPENAI_API_KEY"),
		OpenRouterAPIKey:            h.getenv("OPENROUTER_API_KEY"),
		AnthropicAPIKey:             h.getenv("ANTHROPIC_API_KEY"),
		GeminiAPIKey:                h.getenv("GEMINI_API_KEY"),
	}
}

func rawJSONField(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func (h *RouteHandler) hasBrowser() bool {
	return h.deps.HasBrowserCapability != nil && h.deps.HasBrowserCapability()
}

func (h *RouteHandler) principalOf(r *http.Request) AuthPrincipal {
	p := PrincipalFromContext(r.Context())
	if p.Authenticated {
		return p
	}
	return AuthPrincipal{Authenticated: true, Kind: "owner", UserID: "owner", Role: "owner", Scopes: []string{"crawl:read", "crawl:fetch", "mcp:call"}, IsOwner: true}
}

func (h *RouteHandler) sessionSecret() string {
	return firstNonEmpty(h.deps.SessionSecret, h.getenv("EDGEFETCH_SESSION_SECRET"), h.getenv("EDGEFETCH_CALLER_TOKEN"), "edgefetch-ephemeral-session-key")
}

func (h *RouteHandler) publicOriginOf(r *http.Request) string {
	if orig := firstNonEmpty(h.deps.PublicOrigin, h.getenv("EDGEFETCH_PUBLIC_ORIGIN")); orig != "" {
		return strings.TrimRight(orig, "/")
	}
	if r == nil {
		return "http://127.0.0.1"
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := firstNonEmpty(r.Host, "127.0.0.1")
	return scheme + "://" + host
}

func (h *RouteHandler) listAgents() map[string]any {
	if h.deps.ListAgents != nil {
		return h.deps.ListAgents()
	}
	return map[string]any{"connected": 0, "agents": []AgentInfo{}}
}

func sha256HexStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (h *RouteHandler) persistArtifact(ctx context.Context, md, ownerID, visibility string) string {
	if h.deps.PersistMarkdownArtifact != nil {
		if id, err := h.deps.PersistMarkdownArtifact(ctx, md, ownerID, visibility); err == nil && id != "" {
			return id
		}
	}
	id := sha256HexStr(md)
	h.mem.mu.Lock()
	h.mem.artifacts[id] = md
	h.mem.mu.Unlock()
	return id
}

func (h *RouteHandler) readArtifact(ctx context.Context, req ArtifactSliceRequest) (*ArtifactSlicePage, int, string) {
	if h.deps.ReadArtifactPage != nil {
		pg, st, code, _ := h.deps.ReadArtifactPage(ctx, req)
		return pg, st, code
	}
	h.mem.mu.RLock()
	md, ok := h.mem.artifacts[strings.ToLower(strings.TrimSpace(req.ArtifactID))]
	h.mem.mu.RUnlock()
	if !ok {
		return nil, http.StatusNotFound, "artifact_not_found"
	}
	off := max(0, min(req.Offset, len(md)))
	lim := req.Limit
	if lim <= 0 {
		lim = 32768
	}
	end := off + lim
	truncated := false
	var next *int
	if end < len(md) {
		truncated = true
		n := end
		next = &n
	} else {
		end = len(md)
	}
	s := md[off:end]
	return &ArtifactSlicePage{ArtifactID: req.ArtifactID, Content: s, Format: firstNonEmpty(req.Format, "markdown"), TotalChars: len(md), ReturnedChars: len(s), Offset: off, Truncated: truncated, NextOffset: next}, http.StatusOK, ""
}

func (h *RouteHandler) putJob(ctx context.Context, rec AsyncJobRecord) {
	if h.deps.PutAsyncJob != nil {
		_ = h.deps.PutAsyncJob(ctx, rec)
		return
	}
	h.mem.mu.Lock()
	h.mem.jobs[rec.Kind+":"+rec.ID] = rec
	h.mem.mu.Unlock()
}

func (h *RouteHandler) getJob(ctx context.Context, kind, id, ownerID string) (*AsyncJobRecord, bool) {
	if h.deps.GetAsyncJob != nil {
		return h.deps.GetAsyncJob(ctx, kind, id, ownerID)
	}
	h.mem.mu.RLock()
	rec, ok := h.mem.jobs[kind+":"+id]
	h.mem.mu.RUnlock()
	if !ok || (rec.OwnerID != "" && ownerID != "" && ownerID != "owner" && rec.OwnerID != ownerID) {
		return nil, false
	}
	cp := rec
	return &cp, true
}

func (h *RouteHandler) cancelJob(ctx context.Context, kind, id, ownerID string) bool {
	if h.deps.CancelAsyncJob != nil {
		return h.deps.CancelAsyncJob(ctx, kind, id, ownerID)
	}
	h.mem.mu.Lock()
	defer h.mem.mu.Unlock()
	k := kind + ":" + id
	rec, ok := h.mem.jobs[k]
	if !ok || (rec.OwnerID != "" && ownerID != "" && ownerID != "owner" && rec.OwnerID != ownerID) {
		return false
	}
	rec.Status = "cancelled"
	rec.UpdatedAtMs = time.Now().UnixMilli()
	h.mem.jobs[k] = rec
	return true
}

func (h *RouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.TryServeRoute(w, r) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found"})
	}
}

// HandleArtifactByID serves `GET /v1/artifacts/:id` with checkpoint-safe slice paging and tenant isolation.
func (h *RouteHandler) HandleArtifactByID(w http.ResponseWriter, r *http.Request, artifactID string) {
	p, ok := h.requireScope(w, r, "crawl:read")
	if !ok {
		return
	}
	_, span, _ := otel.StartChildSpan(r.Context(), h.deps.OtelExporter, "edgefetch.artifacts", 1, nil)
	statusOut := http.StatusOK
	defer func() { span.End(statusOut < 400, "") }()

	q := r.URL.Query()
	offset, _ := strconv.Atoi(strings.TrimSpace(q.Get("offset")))
	limit, _ := strconv.Atoi(strings.TrimSpace(firstNonEmpty(q.Get("maxChars"), q.Get("limit"))))
	vis := "public"
	if !p.IsOwner && p.EffectiveOwnerID() != "owner" {
		vis = "private"
	}
	pg, st, errCode := h.readArtifact(r.Context(), ArtifactSliceRequest{
		ArtifactID: strings.TrimSpace(artifactID),
		OwnerID:    p.EffectiveOwnerID(),
		Visibility: vis,
		Format:     strings.TrimSpace(q.Get("format")),
		Offset:     offset,
		Limit:      limit,
	})
	statusOut = st
	if st != http.StatusOK || pg == nil {
		if errCode == "" {
			errCode = "not_found"
		}
		writeJSON(w, st, map[string]any{"ok": false, "error": errCode})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"id":            pg.ArtifactID,
		"artifactId":    pg.ArtifactID,
		"content":       pg.Content,
		"markdown":      pg.Content,
		"format":        pg.Format,
		"offset":        pg.Offset,
		"totalChars":    pg.TotalChars,
		"returnedChars": pg.ReturnedChars,
		"truncated":     pg.Truncated,
		"hasMore":       pg.Truncated,
		"nextOffset":    pg.NextOffset,
	})
}

func (h *RouteHandler) TryServeRoute(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == "/mcp":
		h.HandleMCP(w, r)
	case h.HandleCompat(w, r):
	case p == "/v1/scrape" && r.Method == http.MethodPost:
		h.HandleScrape(w, r)
	case p == "/v1/extract" && r.Method == http.MethodPost:
		h.HandleExtract(w, r)
	case p == "/v1/map" && r.Method == http.MethodPost:
		h.HandleMap(w, r)
	case p == "/v1/interact" && r.Method == http.MethodPost:
		h.HandleInteract(w, r)
	case p == "/v1/ingest-tab" && (r.Method == http.MethodPost || r.Method == http.MethodOptions):
		h.HandleIngestTab(w, r)
	case strings.HasPrefix(p, "/v1/collections/") && strings.HasSuffix(p, "/search") && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		h.HandleCollectionSearch(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/v1/collections/"), "/search"))
	case p == "/v1/search" && r.Method == http.MethodPost:
		h.HandleSearch(w, r)
	case p == "/v1/hosts" && r.Method == http.MethodGet:
		h.HandleHosts(w, r, false)
	case p == "/v1/hosts/gaps" && r.Method == http.MethodGet:
		h.HandleHosts(w, r, true)
	case p == "/v1/jobs" && r.Method == http.MethodPost:
		h.HandleJobs(w, r)
	case p == "/v1/catalog" && r.Method == http.MethodPost:
		h.HandleCatalog(w, r)
	case strings.HasPrefix(p, "/v1/catalog/") && strings.HasSuffix(p, "/records") && r.Method == http.MethodGet:
		h.HandleCatalogRecords(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/v1/catalog/"), "/records"))
	case strings.HasPrefix(p, "/v1/catalog/") && r.Method == http.MethodGet:
		h.HandleCatalogStatus(w, r, strings.TrimPrefix(p, "/v1/catalog/"))
	case p == "/v1/batch/scrape" && r.Method == http.MethodPost:
		h.HandleBatchScrape(w, r)
	case strings.HasPrefix(p, "/v1/batch/scrape/"):
		h.HandleBatchScrapeByID(w, r, strings.TrimPrefix(p, "/v1/batch/scrape/"))
	case p == "/v1/crawl/params-preview" && r.Method == http.MethodPost:
		h.HandleCrawlParamsPreview(w, r)
	case p == "/v1/crawl" && r.Method == http.MethodPost:
		h.HandleCrawl(w, r)
	case strings.HasPrefix(p, "/v1/crawl/"):
		h.HandleCrawlByID(w, r, strings.TrimPrefix(p, "/v1/crawl/"))
	case p == "/v1/agent" && r.Method == http.MethodPost:
		h.HandleAgent(w, r)
	case strings.HasPrefix(p, "/v1/agent/") && strings.HasSuffix(p, "/trace") && r.Method == http.MethodGet:
		h.HandleAgentTrace(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/v1/agent/"), "/trace"))
	case strings.HasPrefix(p, "/v1/agent/"):
		h.HandleAgentByID(w, r, strings.TrimPrefix(p, "/v1/agent/"))
	case strings.HasPrefix(p, "/v1/artifacts/") && r.Method == http.MethodGet:
		h.HandleArtifactByID(w, r, strings.TrimPrefix(p, "/v1/artifacts/"))
	case p == "/v1/mcp/registry" && r.Method == http.MethodGet:
		h.HandleMCPRegistry(w, r)
	case p == "/v1/mcp/query" && r.Method == http.MethodPost:
		h.HandleMCPQuery(w, r)
	default:
		return false
	}
	return true
}

func decodeReplyBodyString(res crawl.Result) string {
	if b, err := res.DecodeBody(); err == nil && len(b) > 0 {
		return string(b)
	}
	return res.Body
}

func hasContentSignalDisallowed(res crawl.Result) bool {
	if res.Outcome == classify.Outcome("content_signal_disallowed") || res.BlockedReason == "content-signal" || res.BlockedReason == "content_signal_disallowed" {
		return true
	}
	probLower := strings.ToLower(res.Problem)
	if strings.Contains(probLower, "content-signal") || strings.Contains(probLower, "ai-input=no") {
		return true
	}
	for k, v := range res.ResponseHeaders {
		if strings.EqualFold(k, "content-signal") && strings.Contains(strings.ToLower(v), "ai-input=no") {
			return true
		}
	}
	return false
}
