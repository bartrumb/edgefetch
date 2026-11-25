package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/catalog"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/hub/hubauth"
	"github.com/bartrumb/edgefetch/v2/internal/hub/hubstore"
)

func (s *Server) initSubsystems() {
	getenv := s.cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	dataDir := strings.TrimSpace(s.cfg.DataDir)
	if dataDir == "" && s.cfg.Getenv != nil {
		dataDir = strings.TrimSpace(s.cfg.Getenv("EDGEFETCH_DATA_DIR"))
	}

	opClient := s.cfg.OperatorClient
	if opClient == nil {
		opClient = &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}

	store, err := hubstore.NewStore(dataDir, s.maxBlobCap)
	if err != nil {
		store, _ = hubstore.NewStore("", s.maxBlobCap)
	}
	s.store = store

	colIdx, err := hubstore.NewCollectionIndex(dataDir)
	if err != nil {
		colIdx, _ = hubstore.NewCollectionIndex("")
	}
	s.colIndex = colIdx

	pubOrig := strings.TrimSpace(s.cfg.PublicOrigin)
	if pubOrig == "" {
		pubOrig = hubauth.ResolveConfiguredPublicOrigin(getenv)
	}
	s.configuredOrigin = pubOrig

	tm, tmErr := hubstore.NewTrackerManager(hubstore.TrackerConfig{
		Store:        store,
		Client:       opClient,
		PublicOrigin: pubOrig,
		Getenv:       getenv,
		OnUpdate:     s.broadcastTrackerList,
	})
	if tmErr == nil && tm != nil {
		s.trackerMgr = tm
		bgCtx, cancel := context.WithCancel(context.Background())
		s.bgCancel = cancel
		tm.StartBackground(bgCtx)
	}

	mcpTok := strings.TrimSpace(s.cfg.McpToken)
	if mcpTok == "" && s.cfg.Getenv != nil {
		mcpTok = strings.TrimSpace(getenv("MCP_TOKEN"))
	}
	sessSec := firstNonEmpty(s.cfg.SessionSecret, getenv("SESSION_SECRET"), getenv("EDGEFETCH_SESSION_SECRET"))
	vaultKey := firstNonEmpty(s.cfg.VaultMasterKey, getenv("VAULT_MASTER_KEY"), getenv("EDGEFETCH_VAULT_MASTER_KEY"))
	redirAllow := s.cfg.RedirectAllowlist
	if len(redirAllow) == 0 {
		redirAllow = hubauth.ParseRedirectAllowlist(getenv("OAUTH_REDIRECT_ALLOWLIST"))
	}
	ghCfg := s.cfg.GitHub
	if ghCfg.ClientID == "" {
		ghCfg = hubauth.GitHubConfig{
			ClientID:     strings.TrimSpace(getenv("GITHUB_CLIENT_ID")),
			ClientSecret: strings.TrimSpace(getenv("GITHUB_CLIENT_SECRET")),
			OwnerID:      strings.TrimSpace(getenv("GITHUB_OWNER_ID")),
			OwnerLogin:   strings.TrimSpace(getenv("GITHUB_OWNER_LOGIN")),
			SignupMode:   strings.TrimSpace(getenv("SIGNUP_MODE")),
			AllowedUsers: strings.TrimSpace(getenv("GITHUB_ALLOWED_USERS")),
		}
	}

	authMgr, aErr := hubauth.NewManager(hubauth.Config{
		DataDir:             dataDir,
		ServiceName:         "EdgeFetch Hub",
		McpSlug:             "edgefetch",
		HubVersion:          agent.Version,
		CallerToken:         s.cfg.CallerToken,
		McpToken:            mcpTok,
		SessionSecret:       sessSec,
		VaultMasterKey:      vaultKey,
		PublicOrigin:        pubOrig,
		AllowedLoopbackPort: s.cfg.AllowedLoopbackPort,
		TrustProxy:          s.cfg.TrustProxy,
		TrustFly:            s.cfg.TrustFly,
		DisableUpdateCheck:  s.cfg.DisableUpdateCheck || strings.EqualFold(strings.TrimSpace(getenv("EDGEFETCH_DISABLE_UPDATE_CHECK")), "1") || strings.EqualFold(strings.TrimSpace(getenv("EDGEFETCH_DISABLE_UPDATE_CHECK")), "true"),
		RedirectAllowlist:   redirAllow,
		GitHub:              ghCfg,
		Getenv:              getenv,
		HTTPClient:          opClient,
		OtelExporter:        s.cfg.OtelExporter,
		Callbacks: hubauth.Callbacks{
			GetAdminState:     s.buildAdminState,
			ExecuteAdminFetch: s.executeAdminFetch,
			ClearAffinities:   s.clearAffinities,
			ClearEvents: func(context.Context) error {
				if s.store != nil {
					s.store.ClearEvents()
				}
				return nil
			},
			OnTelemetryToggle: func(enabled bool) {
				if s.cfg.OtelExporter != nil {
					s.cfg.OtelExporter.SetRuntimeDevTelemetry(enabled)
				}
			},
		},
	})
	if aErr == nil {
		s.authMgr = authMgr
	}

	bypass := s.cfg.RobotsBypassHosts
	if len(bypass) == 0 {
		bypass = splitCSV(firstNonEmpty(getenv("EDGEFETCH_ROBOTS_BYPASS_HOSTS"), getenv("ROBOTS_BYPASS_HOSTS")))
	}

	deps := NewServerRouteDeps(s)
	deps.OperatorClient = opClient
	deps.Getenv = getenv
	deps.RobotsBypassHosts = bypass
	deps.SessionSecret = firstNonEmpty(sessSec, s.cfg.CallerToken)
	deps.PublicOrigin = pubOrig
	deps.VaultMasterKey = vaultKey
	deps.Capabilities = s.capabilitiesPayload
	deps.CatalogStore = catalog.NewCatalogStore()

	if s.store != nil {
		deps.LookupScrapeCache = func(_ context.Context, rawURL, ownerID string, maxAgeMs int64, ifNoneMatch string) (ScrapeCacheLookup, error) {
			key := ownerID + "|" + rawURL
			payload, etag, notMod, hit := s.store.GetScrapeCache(key, maxAgeMs, ifNoneMatch)
			return ScrapeCacheLookup{Hit: hit, NotModified: notMod, ETag: etag, Payload: payload}, nil
		}
		deps.StoreScrapeCache = func(_ context.Context, entry ScrapeCacheEntry) error {
			owner := firstNonEmpty(entry.OwnerID, "owner")
			etag := s.store.PutScrapeCache(owner+"|"+entry.URL, entry.Payload)
			if entry.Payload != nil {
				entry.Payload["_etag"] = etag
			}
			return nil
		}
		deps.PersistMarkdownArtifact = func(_ context.Context, md, ownerID, visibility string) (string, error) {
			isPriv := visibility == "private" || (ownerID != "" && ownerID != "owner")
			id, _, _, err := s.store.PersistMarkdownArtifact(firstNonEmpty(ownerID, "owner"), "", "", md, isPriv)
			return id, err
		}
		deps.ReadArtifactPage = func(_ context.Context, req ArtifactSliceRequest) (*ArtifactSlicePage, int, string, error) {
			isOwner := req.OwnerID == "" || req.OwnerID == "owner"
			pg, st, code := s.store.ReadArtifactPage(firstNonEmpty(req.OwnerID, "owner"), isOwner, req.ArtifactID, req.Offset, req.Limit)
			if st != http.StatusOK || pg == nil {
				return nil, st, code, nil
			}
			content, _ := pg["content"].(string)
			totalChars, _ := pg["totalChars"].(int)
			hasMore, _ := pg["hasMore"].(bool)
			offVal, _ := pg["offset"].(int)
			var nextPtr *int
			if hasMore {
				if nxt, ok := pg["nextOffset"].(int); ok {
					n := nxt
					nextPtr = &n
				}
			}
			return &ArtifactSlicePage{
				ArtifactID:    req.ArtifactID,
				Content:       content,
				Format:        firstNonEmpty(req.Format, "markdown"),
				TotalChars:    totalChars,
				ReturnedChars: len(content),
				Offset:        offVal,
				Truncated:     hasMore,
				NextOffset:    nextPtr,
			}, http.StatusOK, "", nil
		}
		deps.RecordHostTelemetry = func(_ context.Context, ev HostTelemetryEvent) {
			s.store.RecordHostTelemetry(ev.Host, ev.Outcome, ev.Status, "", "", ev.AdapterID, ev.DurationMs)
		}
		deps.ListHosts = func(_ context.Context, limit int) ([]map[string]any, error) {
			return s.store.ListHosts(limit), nil
		}
		deps.ListHostGaps = func(_ context.Context, limit int) ([]map[string]any, error) {
			return s.store.ListHostGaps(limit), nil
		}
		deps.PutAsyncJob = func(_ context.Context, rec AsyncJobRecord) error {
			b, _ := json.Marshal(rec)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			s.store.PutJob(rec.Kind, rec.ID, firstNonEmpty(rec.OwnerID, "owner"), m)
			return nil
		}
		deps.GetAsyncJob = func(_ context.Context, kind, id, ownerID string) (*AsyncJobRecord, bool) {
			isOwner := ownerID == "" || ownerID == "owner"
			m, ok := s.store.GetJob(kind, id, firstNonEmpty(ownerID, "owner"), isOwner)
			if !ok {
				return nil, false
			}
			b, _ := json.Marshal(m)
			var rec AsyncJobRecord
			if json.Unmarshal(b, &rec) != nil {
				return nil, false
			}
			return &rec, true
		}
		deps.CancelAsyncJob = func(_ context.Context, kind, id, ownerID string) bool {
			isOwner := ownerID == "" || ownerID == "owner"
			_, ok := s.store.DeleteOrCancelJob(kind, id, firstNonEmpty(ownerID, "owner"), isOwner)
			return ok
		}
	}

	if s.colIndex != nil {
		deps.IngestCollectionPage = func(_ context.Context, doc CollectionDocInput) (int, error) {
			isOwner := doc.OwnerID == "" || doc.OwnerID == "owner"
			stKey, disp := hubstore.ResolveCollectionKey(doc.OwnerID, isOwner, doc.CollectionID)
			n, _ := s.colIndex.ReplacePageChunks(stKey, disp, doc.URL, doc.Title, doc.Markdown)
			return n, nil
		}
		deps.SearchCollection = func(_ context.Context, collectionID, query, ownerID string, limit int) ([]CollectionSearchHit, error) {
			isOwner := ownerID == "" || ownerID == "owner"
			stKey, disp := hubstore.ResolveCollectionKey(ownerID, isOwner, collectionID)
			hits := s.colIndex.Search(stKey, query, limit, "")
			out := make([]CollectionSearchHit, 0, len(hits))
			for _, h := range hits {
				out = append(out, CollectionSearchHit{
					CollectionID: disp,
					URL:          h.URL,
					Title:        h.Title,
					Snippet:      h.Snippet,
					Score:        h.Score,
				})
			}
			return out, nil
		}
		deps.ExecuteWebSearch = func(ctx context.Context, req WebSearchRequest) (*WebSearchResponse, error) {
			isOwner := req.OwnerID == "" || req.OwnerID == "owner"
			stKey, _ := hubstore.ResolveCollectionKey(req.OwnerID, isOwner, firstNonEmpty(req.Collection, "default"))
			rawRes, err := hubstore.ExecuteWebSearch(ctx, hubstore.SearchConfig{
				SearxngURL:           getenv("SEARXNG_URL"),
				SerperAPIKey:         getenv("SERPER_API_KEY"),
				BraveAPIKey:          getenv("BRAVE_API_KEY"),
				TavilyAPIKey:         getenv("TAVILY_API_KEY"),
				CollectionIndex:      s.colIndex,
				CollectionStorageKey: stKey,
				OperatorClient:       opClient,
				OtelExporter:         s.cfg.OtelExporter,
			}, hubstore.SearchParams{
				Query:      req.Query,
				Limit:      req.Limit,
				Sources:    req.Sources,
				Collection: req.Collection,
			})
			if err != nil {
				return nil, err
			}
			var hits []WebSearchHit
			if b, mErr := json.Marshal(rawRes["results"]); mErr == nil {
				_ = json.Unmarshal(b, &hits)
			}
			prov := "collections"
			if pu, ok := rawRes["providersUsed"].([]string); ok && len(pu) > 0 {
				prov = strings.Join(pu, ",")
			}
			return &WebSearchResponse{Provider: prov, Query: req.Query, Results: hits}, nil
		}
	}

	if s.authMgr != nil {
		deps.ListConnectedMcp = func(_ context.Context, ownerID string) ([]ConnectedMcpConfig, error) {
			srvList, err := s.authMgr.ListDecryptedMcpServers(ownerID)
			if err != nil {
				return nil, err
			}
			out := make([]ConnectedMcpConfig, 0, len(srvList))
			for _, srv := range srvList {
				hdrs := make(map[string]string, len(srv.Headers))
				for k, v := range srv.Headers {
					hdrs[k] = v
				}
				if srv.OAuth != nil && srv.OAuth.AccessToken != "" {
					hdrs["Authorization"] = "Bearer " + srv.OAuth.AccessToken
				}
				var toolsCache []map[string]any
				if b, mErr := json.Marshal(srv.Tools); mErr == nil {
					_ = json.Unmarshal(b, &toolsCache)
				}
				out = append(out, ConnectedMcpConfig{
					ID:             srv.ID,
					Name:           srv.Name,
					EndpointURL:    srv.RemoteURL,
					Transport:      srv.Transport,
					AuthType:       srv.AuthType,
					Enabled:        true,
					DomainPatterns: srv.Domains,
					ToolsCache:     toolsCache,
					PlainHeaders:   hdrs,
				})
			}
			return out, nil
		}
	}

	s.routes = NewRouteHandler(deps)
}

func (s *Server) capabilitiesPayload() map[string]any {
	trackerStatus := map[string]any{"available": false, "reason": "not_loaded"}
	trackerAvail := false
	if s.trackerMgr != nil {
		st := s.trackerMgr.Status()
		trackerStatus = st
		trackerAvail, _ = st["available"].(bool)
	}
	return map[string]any{
		"ok":      true,
		"runtime": "go-hub",
		"version": agent.Version,
		"capabilities": map[string]bool{
			"fetch":           true,
			"scrape":          true,
			"extract":         true,
			"map":             true,
			"crawl":           true,
			"interact":        true,
			"search":          true,
			"jobs":            true,
			"catalog":         true,
			"agent":           true,
			"extractors":      true,
			"mcp":             true,
			"oauth":           true,
			"artifacts":       true,
			"localFallback":   s.cfg.FallbackCrawler != nil,
			"trackerBlocking": trackerAvail,
		},
		"trackerBlocking": trackerStatus,
	}
}

func (s *Server) sendTrackerListToSession(ctx context.Context, sess *agentSession) {
	if s.trackerMgr == nil || sess == nil || sess.conn == nil {
		return
	}
	ver, hosts := s.trackerMgr.CurrentList()
	if ver == "" || len(hosts) == 0 {
		return
	}
	frames := hubstore.BuildTrackerListFrames(ver, hosts)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, fr := range frames {
		if sess.conn.Write(wctx, websocket.MessageText, fr) != nil {
			return
		}
	}
}

func (s *Server) broadcastTrackerList(ver string, hosts []string) {
	if ver == "" || len(hosts) == 0 {
		return
	}
	frames := hubstore.BuildTrackerListFrames(ver, hosts)
	s.mu.Lock()
	sessions := make([]*agentSession, 0, len(s.agents))
	for _, sess := range s.agents {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		go func(target *agentSession) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, fr := range frames {
				if target.conn.Write(ctx, websocket.MessageText, fr) != nil {
					return
				}
			}
		}(sess)
	}
}

func (s *Server) buildAdminState(_ context.Context) (hubauth.AdminHubState, error) {
	fleet := s.ListAgents()
	agentsList, _ := fleet["agents"].([]AgentInfo)
	vers := make([]hubauth.FleetAgentVersion, 0, len(agentsList))
	for _, a := range agentsList {
		vers = append(vers, hubauth.FleetAgentVersion{SiteID: a.SiteID, Version: a.Version})
	}
	now := time.Now()
	s.mu.Lock()
	affList := make([]map[string]any, 0, len(s.affinities))
	for host, aff := range s.affinities {
		if now.Before(aff.expiresAt) {
			affList = append(affList, map[string]any{"host": host, "siteId": aff.siteID, "expiresAt": aff.expiresAt.UnixMilli()})
		}
	}
	s.mu.Unlock()
	var tracker any
	if s.trackerMgr != nil {
		tracker = s.trackerMgr.Status()
	}
	var events any = []any{}
	if s.store != nil {
		events = s.store.ListEvents(100)
	}
	connCount, _ := fleet["connected"].(int)
	ipsCount, _ := fleet["distinctPublicIps"].(int)
	return hubauth.AdminHubState{
		Connected:         connCount,
		DistinctPublicIPs: ipsCount,
		Agents:            vers,
		AgentsRaw:         agentsList,
		Affinities:        affList,
		TrackerList:       tracker,
		Events:            events,
	}, nil
}

func (s *Server) executeAdminFetch(ctx context.Context, req hubauth.AdminFetchRequest) (int, string, []byte, error) {
	kind := classify.Kind(strings.TrimSpace(req.Kind))
	if kind == "" {
		kind = classify.KindScrape
	}
	call := crawl.FetchCall{
		MaxSeconds: 45,
		Options: crawl.Options{
			Concurrency:   1,
			PauseMs:       req.PauseMs,
			PauseJitterMs: req.PauseJitterMs,
			IncludeBody:   req.IncludeBody,
			RespectRobots: crawl.Bool(req.RespectRobots || !IsRobotBypassedHost(req.URL, s.routes.deps.RobotsBypassHosts)),
		},
		Requests: []crawl.Request{{ID: "admin-1", URL: strings.TrimSpace(req.URL), Kind: kind}},
	}
	if code, msg, ok := crawl.ValidateCall(call, s.allow); !ok {
		b, _ := json.Marshal(map[string]string{"error": code, "message": msg})
		return http.StatusBadRequest, "hub", b, nil
	}
	rep, via, st, err := s.DispatchOrFallback(ctx, call, req.Target, req.Site, nil)
	if err != nil {
		b, _ := json.Marshal(map[string]string{"error": "hub_unavailable", "message": err.Error()})
		return st, via, b, nil
	}
	b, _ := json.Marshal(rep)
	return http.StatusOK, via, b, nil
}

func (s *Server) clearAffinities(_ context.Context, siteID string) error {
	targetSite := strings.TrimSpace(siteID)
	s.mu.Lock()
	if targetSite == "" {
		s.affinities = make(map[string]affinityEntry)
	} else {
		for h, aff := range s.affinities {
			if aff.siteID == targetSite {
				delete(s.affinities, h)
			}
		}
	}
	s.mu.Unlock()
	return nil
}

func extractAgentSubprotocolToken(r *http.Request) (token string, wantsAgentSubproto bool) {
	for _, rawHdr := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, item := range strings.Split(rawHdr, ",") {
			p := strings.TrimSpace(item)
			if p == "edgefetch-agent" {
				wantsAgentSubproto = true
				continue
			}
			if strings.HasPrefix(p, "edgefetch-v1.") && token == "" {
				enc := strings.TrimPrefix(p, "edgefetch-v1.")
				if dec, err := base64.RawURLEncoding.DecodeString(enc); err == nil && len(dec) > 0 {
					token = string(dec)
				}
			}
		}
	}
	return token, wantsAgentSubproto
}

// executeScrape preserves direct internal test compatibility (`hub_coverage_test.go`) by delegating to `RouteHandler.ExecuteScrape`.
func (s *Server) executeScrape(ctx context.Context, p ScrapeRequest, hdr http.Header) (map[string]any, string, int) {
	if _, ok := s.routes.deps.OtelExporter, true; ok && s.routes != nil {
		out, via, st := s.routes.ExecuteScrape(ctx, p, hdr, "owner")
		if errStr := fmt.Sprint(out["error"]); errStr == "empty_reply" && st != http.StatusBadGateway {
			st = http.StatusBadGateway
		}
		return out, via, st
	}
	return map[string]any{"ok": false, "error": "hub_unavailable"}, "hub", http.StatusServiceUnavailable
}
