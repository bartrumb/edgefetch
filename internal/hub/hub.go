package hub

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

const (
	maxAgentFrameBytes    = 1 << 20  // 1 MiB WebSocket control frame cap
	maxGzipReplyBytes     = 20 << 20 // 20 MiB compressed reply cap
	maxDecodedReplyBytes  = 32 << 20 // 32 MiB uncompressed reply cap
	maxArtifactStoreBytes = 64 << 20 // 64 MiB bounded in-memory artifact ring
	defaultCooldownDur    = 15 * time.Second
	stickyAffinityTTL     = 10 * time.Minute
)

var (
	reSiteID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	reJobID  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Config configures a self-hosted Go Hub controller instance.
type Config struct {
	CallerToken       string
	AgentToken        string
	AgentTokens       map[string]string
	PeerURLs          []string
	PeerToken         string
	PeerHTTPClient    *http.Client
	FallbackCrawler   *crawl.Crawler
	Allow             func(*url.URL) error
	Logger            *slog.Logger
	DispatchTimeout   time.Duration
	MaxArtifactMemory int
}

type agentSession struct {
	siteID       string
	arch         string
	version      string
	publicIP     string
	capabilities []string
	connectedAt  time.Time
	conn         *websocket.Conn

	mu        sync.Mutex
	busy      bool
	lastJobAt time.Time
	jobsOK    int64
	jobsErr   int64
	replaced  bool
}

func (s *agentSession) hasCapability(want string) bool {
	for _, c := range s.capabilities {
		if strings.EqualFold(strings.TrimSpace(c), want) {
			return true
		}
	}
	return false
}

type pendingJob struct {
	jobID     string
	jobNonce  string
	siteID    string
	session   *agentSession
	doneCh    chan jobOutcome
	createdAt time.Time
}

type jobOutcome struct {
	reply crawl.FetchReply
	raw   string
	err   error
}

type storedBlob struct {
	sha256        string
	contentSHA256 string
	gzBytes       []byte
	storedAt      time.Time
}

type affinityEntry struct {
	siteID    string
	expiresAt time.Time
}

// AgentInfo summarizes a connected worker node in `GET /agents` and MCP `list_agents`.
type AgentInfo struct {
	SiteID       string   `json:"siteId"`
	Arch         string   `json:"arch"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities"`
	Busy         bool     `json:"busy"`
	ConnectedAt  int64    `json:"connectedAt"`
	LastJobAt    int64    `json:"lastJobAt,omitempty"`
	JobsOK       int64    `json:"jobsOk"`
	JobsErr      int64    `json:"jobsErr"`
}

// Server coordinates connected Go edge workers and serves `/fetch`, `/v1/scrape`, and `/mcp`.
type Server struct {
	cfg    Config
	log    *slog.Logger
	allow  func(*url.URL) error
	closed atomic.Bool

	mu         sync.Mutex
	agents     map[string]*agentSession
	pending    map[string]*pendingJob
	cooldowns  map[string]time.Time // "<siteID>|<host>" -> expiresAt
	affinities map[string]affinityEntry
	blobs      map[string]storedBlob
	blobOrder  []string
	blobBytes  int
	maxBlobCap int
}

// ParseAgentTokensJSON parses `EDGEFETCH_AGENT_TOKENS` (`{"site-1":"<token>"}`) and enforces >= 24-char secrets.
func ParseAgentTokensJSON(raw string) (map[string]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, fmt.Errorf("invalid EDGEFETCH_AGENT_TOKENS JSON: %w", err)
	}
	out := make(map[string]string, len(parsed))
	for k, v := range parsed {
		site := strings.ToLower(strings.TrimSpace(k))
		tok := strings.TrimSpace(v)
		if !reSiteID.MatchString(site) {
			return nil, fmt.Errorf("invalid site_id %q in EDGEFETCH_AGENT_TOKENS", k)
		}
		if len(tok) < agent.MinTokenLength {
			return nil, fmt.Errorf("token for site %q must be at least %d characters", site, agent.MinTokenLength)
		}
		out[site] = tok
	}
	return out, nil
}

// NewServer constructs a ready-to-serve Go Hub `http.Handler`.
func NewServer(cfg Config) *Server {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	allow := cfg.Allow
	if allow == nil {
		allow = crawl.PublicHTTPS
	}
	if cfg.DispatchTimeout <= 0 {
		cfg.DispatchTimeout = 60 * time.Second
	}
	maxCap := cfg.MaxArtifactMemory
	if maxCap <= 0 {
		maxCap = maxArtifactStoreBytes
	}
	return &Server{
		cfg:        cfg,
		log:        log,
		allow:      allow,
		agents:     make(map[string]*agentSession),
		pending:    make(map[string]*pendingJob),
		cooldowns:  make(map[string]time.Time),
		affinities: make(map[string]affinityEntry),
		blobs:      make(map[string]storedBlob),
		maxBlobCap: maxCap,
	}
}

// Close disconnects any active agent WebSockets cleanly during server shutdown.
func (s *Server) Close() error {
	s.closed.Store(true)
	s.mu.Lock()
	sessions := make([]*agentSession, 0, len(s.agents))
	for _, sess := range s.agents {
		sessions = append(sessions, sess)
	}
	s.agents = make(map[string]*agentSession)
	s.mu.Unlock()

	for _, sess := range sessions {
		_ = sess.conn.Close(websocket.StatusGoingAway, "hub_shutdown")
	}
	return nil
}

// ServeHTTP routes control-plane (`/agent/*`) and caller-plane (`/health`, `/agents`, `/fetch`, `/v1/*`, `/mcp`) requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case (r.URL.Path == "/health" || r.URL.Path == "/healthz") && r.Method == http.MethodGet:
		s.mu.Lock()
		n := len(s.agents)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "hub", "version": agent.Version, "connectedAgents": n})
		return

	case r.URL.Path == "/agent/ws":
		s.handleAgentWS(w, r)
		return

	case strings.HasPrefix(r.URL.Path, "/agent/artifacts/") && r.Method == http.MethodPut:
		s.handleAgentArtifactPut(w, r)
		return

	case r.URL.Path == "/agent/reply" && r.Method == http.MethodPost:
		s.handleAgentReply(w, r)
		return
	}

	if !s.isCallerAuthorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "valid Bearer or x-api-key token required"})
		return
	}

	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet && strings.TrimSpace(s.cfg.CallerToken) == "":
		s.serveDesktopLaunchpad(w, r)

	case r.URL.Path == "/agents" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.ListAgents())

	case r.URL.Path == "/v1/capabilities" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"runtime": "go-hub",
			"version": agent.Version,
			"capabilities": map[string]bool{
				"fetch":         true,
				"scrape":        true,
				"mcp":           true,
				"artifacts":     true,
				"localFallback": s.cfg.FallbackCrawler != nil,
			},
		})

	case r.URL.Path == "/fetch" && r.Method == http.MethodPost:
		s.handleCallerFetch(w, r)

	case r.URL.Path == "/v1/scrape" && r.Method == http.MethodPost:
		s.handleCallerScrape(w, r)

	case (r.URL.Path == "/v2/scrape" || r.URL.Path == "/compat/firecrawl/v2/scrape") && r.Method == http.MethodPost:
		s.handleFirecrawlV2Scrape(w, r)

	case (r.URL.Path == "/v1/map" || r.URL.Path == "/v2/map" || r.URL.Path == "/compat/firecrawl/v2/map") && r.Method == http.MethodPost:
		s.handleCallerMap(w, r, strings.HasPrefix(r.URL.Path, "/v2/") || strings.HasPrefix(r.URL.Path, "/compat/"))

	case r.URL.Path == "/mcp":
		s.handleMCP(w, r)

	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func (s *Server) isCallerAuthorized(r *http.Request) bool {
	want := strings.TrimSpace(s.cfg.CallerToken)
	if want == "" {
		return true
	}
	got := extractCallerToken(r)
	if got == "" {
		return false
	}
	return constantTimeEquals(got, want)
}

func (s *Server) authorizeAgent(r *http.Request) (string, bool) {
	tok := extractBearer(r)
	if tok == "" {
		return "", false
	}
	hdrSite := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Agent-Site")))
	mappedSites := make(map[string]bool, len(s.cfg.AgentTokens))

	if len(s.cfg.AgentTokens) > 0 {
		matchedSite := ""
		for site, secret := range s.cfg.AgentTokens {
			mappedSites[site] = true
			if len(secret) >= agent.MinTokenLength && constantTimeEquals(tok, secret) {
				matchedSite = site
			}
		}
		if matchedSite != "" && (hdrSite == "" || hdrSite == matchedSite) {
			return matchedSite, true
		}
	}

	shared := strings.TrimSpace(s.cfg.AgentToken)
	if len(shared) >= agent.MinTokenLength && constantTimeEquals(tok, shared) {
		if reSiteID.MatchString(hdrSite) && !mappedSites[hdrSite] {
			return hdrSite, true
		}
	}
	return "", false
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	siteID, ok := s.authorizeAgent(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(maxAgentFrameBytes)

	caps := splitCSV(r.Header.Get("X-Agent-Capabilities"))
	pubIP := clientIPOf(r)
	sess := &agentSession{
		siteID:       siteID,
		arch:         firstNonEmpty(r.Header.Get("X-Agent-Arch"), "unknown"),
		version:      strings.TrimSpace(r.Header.Get("X-Agent-Version")),
		publicIP:     pubIP,
		capabilities: caps,
		connectedAt:  time.Now(),
		conn:         conn,
	}

	s.mu.Lock()
	old := s.agents[siteID]
	if old != nil {
		old.mu.Lock()
		old.replaced = true
		old.mu.Unlock()
	}
	s.agents[siteID] = sess
	s.mu.Unlock()

	if old != nil {
		_ = old.conn.Close(websocket.StatusPolicyViolation, "replaced_by_newer_session")
	}

	helloBytes, _ := json.Marshal(map[string]string{"type": "hello", "siteId": siteID})
	_ = conn.Write(r.Context(), websocket.MessageText, helloBytes)
	s.log.Info("hub_agent_connected", slog.String("site", siteID), slog.String("arch", sess.arch), slog.String("version", sess.version))

	defer func() {
		s.mu.Lock()
		if s.agents[siteID] == sess {
			delete(s.agents, siteID)
		}
		for jid, pj := range s.pending {
			if pj.session == sess {
				delete(s.pending, jid)
				select {
				case pj.doneCh <- jobOutcome{err: errors.New("agent_disconnected")}:
				default:
				}
			}
		}
		s.mu.Unlock()
		_ = conn.CloseNow()
	}()

	for {
		_, data, readErr := conn.Read(r.Context())
		if readErr != nil {
			return
		}
		text := strings.TrimSpace(string(data))
		if text == "ping" {
			_ = conn.Write(r.Context(), websocket.MessageText, []byte("pong"))
			continue
		}
		var hello struct {
			Type         string   `json:"type"`
			Version      string   `json:"version"`
			Arch         string   `json:"arch"`
			Capabilities []string `json:"capabilities"`
		}
		if json.Unmarshal(data, &hello) == nil && hello.Type == "agent_hello" {
			sess.mu.Lock()
			if hello.Version != "" {
				sess.version = hello.Version
			}
			if hello.Arch != "" {
				sess.arch = hello.Arch
			}
			if len(hello.Capabilities) > 0 {
				sess.capabilities = hello.Capabilities
			}
			sess.mu.Unlock()
		}
	}
}

func (s *Server) handleAgentArtifactPut(w http.ResponseWriter, r *http.Request) {
	siteID, ok := s.authorizeAgent(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	blobSHA := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/agent/artifacts/")))
	jobID := strings.TrimSpace(r.Header.Get("X-Job-Id"))
	jobNonce := strings.TrimSpace(r.Header.Get("X-Job-Nonce"))
	contentSHA := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Content-Sha256")))
	if !reSHA256.MatchString(blobSHA) || !reJobID.MatchString(jobID) || !reJobID.MatchString(jobNonce) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_artifact_headers"})
		return
	}
	if !s.verifyPendingJob(jobID, jobNonce, siteID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_job"})
		return
	}

	gzBytes, err := io.ReadAll(io.LimitReader(r.Body, crawl.MaxMaxBytes+1024))
	if err != nil || len(gzBytes) > crawl.MaxMaxBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "artifact_too_large"})
		return
	}
	sum := sha256.Sum256(gzBytes)
	if hex.EncodeToString(sum[:]) != blobSHA {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "blob_sha256_mismatch"})
		return
	}

	s.storeBlob(storedBlob{
		sha256:        blobSHA,
		contentSHA256: contentSHA,
		gzBytes:       gzBytes,
		storedAt:      time.Now(),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "blobSha256": blobSHA})
}

func (s *Server) storeBlob(b storedBlob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.blobs[b.sha256]; exists {
		return
	}
	for s.blobBytes+len(b.gzBytes) > s.maxBlobCap && len(s.blobOrder) > 0 {
		evict := s.blobOrder[0]
		s.blobOrder = s.blobOrder[1:]
		if old, ok := s.blobs[evict]; ok {
			s.blobBytes -= len(old.gzBytes)
			delete(s.blobs, evict)
		}
	}
	if len(b.gzBytes) <= s.maxBlobCap {
		s.blobs[b.sha256] = b
		s.blobOrder = append(s.blobOrder, b.sha256)
		s.blobBytes += len(b.gzBytes)
	}
}

func (s *Server) hydrateArtifacts(reply *crawl.FetchReply) {
	for i := range reply.Results {
		res := &reply.Results[i]
		if res.Body != "" || res.Artifact == nil || res.Artifact.BlobSHA256 == "" {
			continue
		}
		s.mu.Lock()
		bl, ok := s.blobs[res.Artifact.BlobSHA256]
		s.mu.Unlock()
		if !ok {
			continue
		}
		zr, err := gzip.NewReader(bytes.NewReader(bl.gzBytes))
		if err != nil {
			continue
		}
		raw, rErr := io.ReadAll(io.LimitReader(zr, crawl.MaxMaxBytes+1))
		_ = zr.Close()
		if rErr == nil && len(raw) <= crawl.MaxMaxBytes {
			res.Body = string(raw)
		}
	}
}

func (s *Server) handleAgentReply(w http.ResponseWriter, r *http.Request) {
	siteID, ok := s.authorizeAgent(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	jobID := strings.TrimSpace(r.Header.Get("X-Job-Id"))
	jobNonce := strings.TrimSpace(r.Header.Get("X-Job-Nonce"))
	if !reJobID.MatchString(jobID) || !reJobID.MatchString(jobNonce) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_job_headers"})
		return
	}
	if !s.verifyPendingJob(jobID, jobNonce, siteID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_job"})
		return
	}

	var reader io.Reader = io.LimitReader(r.Body, maxGzipReplyBytes+1)
	rawCompressed, err := io.ReadAll(reader)
	if err != nil || len(rawCompressed) > maxGzipReplyBytes {
		s.completePending(jobID, jobNonce, siteID, jobOutcome{err: errors.New("reply_too_large")})
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "too_large"})
		return
	}

	decoded := rawCompressed
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		zr, gzErr := gzip.NewReader(bytes.NewReader(rawCompressed))
		if gzErr != nil {
			s.completePending(jobID, jobNonce, siteID, jobOutcome{err: gzErr})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_gzip"})
			return
		}
		decBytes, rErr := io.ReadAll(io.LimitReader(zr, maxDecodedReplyBytes+1))
		_ = zr.Close()
		if rErr != nil || len(decBytes) > maxDecodedReplyBytes {
			s.completePending(jobID, jobNonce, siteID, jobOutcome{err: errors.New("decompressed_too_large")})
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "too_large"})
			return
		}
		decoded = decBytes
	}

	var reply crawl.FetchReply
	if err := json.Unmarshal(decoded, &reply); err != nil {
		s.completePending(jobID, jobNonce, siteID, jobOutcome{err: err})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_reply_json"})
		return
	}

	s.completePending(jobID, jobNonce, siteID, jobOutcome{reply: reply, raw: string(decoded)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) verifyPendingJob(jobID, jobNonce, siteID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	pj, ok := s.pending[jobID]
	if !ok || pj.siteID != siteID {
		return false
	}
	return constantTimeEquals(jobNonce, pj.jobNonce)
}

func (s *Server) completePending(jobID, jobNonce, siteID string, out jobOutcome) {
	s.mu.Lock()
	pj, ok := s.pending[jobID]
	if ok && pj.siteID == siteID && constantTimeEquals(jobNonce, pj.jobNonce) {
		delete(s.pending, jobID)
	} else {
		pj = nil
	}
	s.mu.Unlock()
	if pj == nil {
		return
	}

	pj.session.mu.Lock()
	pj.session.busy = false
	pj.session.lastJobAt = time.Now()
	if out.err != nil {
		pj.session.jobsErr++
	} else {
		pj.session.jobsOK++
	}
	pj.session.mu.Unlock()

	if out.err == nil {
		now := time.Now()
		s.mu.Lock()
		for _, r := range out.reply.Results {
			h := hostOfURL(r.URL)
			if h == "" {
				continue
			}
			if r.Outcome == classify.OutcomeStop || r.Outcome == classify.OutcomeChallenge {
				cd := defaultCooldownDur
				if r.RetryAfterMs > 0 {
					cd = time.Duration(r.RetryAfterMs) * time.Millisecond
				}
				s.cooldowns[siteID+"|"+h] = now.Add(cd)
				if aff, hasAff := s.affinities[h]; hasAff && aff.siteID == siteID {
					delete(s.affinities, h)
				}
			} else if r.Outcome == classify.OutcomeOK {
				s.affinities[h] = affinityEntry{siteID: siteID, expiresAt: now.Add(stickyAffinityTTL)}
			}
		}
		s.mu.Unlock()
	}

	select {
	case pj.doneCh <- out:
	default:
	}
}

// ListAgents returns fleet status across all currently connected WebSocket workers.
func (s *Server) ListAgents() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]AgentInfo, 0, len(s.agents))
	ips := make(map[string]bool)
	for _, sess := range s.agents {
		sess.mu.Lock()
		info := AgentInfo{
			SiteID:       sess.siteID,
			Arch:         sess.arch,
			Version:      sess.version,
			Capabilities: append([]string(nil), sess.capabilities...),
			Busy:         sess.busy,
			ConnectedAt:  sess.connectedAt.UnixMilli(),
			JobsOK:       sess.jobsOK,
			JobsErr:      sess.jobsErr,
		}
		if !sess.lastJobAt.IsZero() {
			info.LastJobAt = sess.lastJobAt.UnixMilli()
		}
		if sess.publicIP != "" {
			ips[sess.publicIP] = true
		}
		sess.mu.Unlock()
		list = append(list, info)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].SiteID < list[j].SiteID })
	return map[string]any{
		"connected":         len(list),
		"distinctPublicIps": len(ips),
		"agents":            list,
	}
}

// DispatchOrFallback routes `call` to a connected WebSocket agent (failing over on 429/disconnect), or falls back to
// the Hub's in-process `FallbackCrawler` when `target` is `"auto"` or `"container"`.
func (s *Server) DispatchOrFallback(
	ctx context.Context,
	call crawl.FetchCall,
	target, preferredSite string,
	traceHdr http.Header,
) (reply crawl.FetchReply, via string, status int, err error) {
	if target == "" {
		target = "auto"
	}
	tc := otel.ExtractOrNew(traceHdr)
	traceMap := map[string]string{
		"traceparent":  otel.FormatTraceparent(tc),
		"x-trace-id":   tc.TraceID,
		"x-span-id":    tc.SpanID,
		"x-request-id": firstNonEmpty(traceHdr.Get("x-request-id"), tc.SpanID),
	}

	needsBrowser := false
	primaryHost := ""
	for _, rq := range call.Requests {
		if primaryHost == "" {
			primaryHost = hostOfURL(rq.URL)
		}
		if rq.Kind == classify.KindRender || rq.RenderMode == "always" || rq.Interact != nil {
			needsBrowser = true
		}
	}

	alreadyHopped := traceHdr != nil && strings.TrimSpace(traceHdr.Get("X-EdgeFetch-Peer-Hop")) != ""
	var lastAgentReply *crawl.FetchReply
	var lastAgentVia string

	triedSites := make(map[string]bool)
	if target == "auto" || target == "agent" {
		for attempt := 0; attempt < 3; attempt++ {
			sess := s.pickAgent(primaryHost, preferredSite, needsBrowser, triedSites)
			if sess == nil {
				break
			}
			triedSites[sess.siteID] = true
			rep, dispErr := s.dispatchToSession(ctx, sess, call, traceMap)
			if dispErr != nil {
				if preferredSite != "" {
					break
				}
				continue
			}
			if call.Options.IncludeBody {
				s.hydrateArtifacts(&rep)
			}
			// If agent hit HTTP 429/403 stop and another peer exists, fail over automatically!
			if replyHitStopOrChallenge(rep) && preferredSite == "" {
				if s.pickAgent(primaryHost, "", needsBrowser, triedSites) != nil {
					continue
				}
				if !alreadyHopped && len(s.cfg.PeerURLs) > 0 {
					repCopy := rep
					lastAgentReply = &repCopy
					lastAgentVia = "agent:" + sess.siteID
					break
				}
			}
			return rep, "agent:" + sess.siteID, http.StatusOK, nil
		}
		if target == "agent" && lastAgentReply == nil {
			return crawl.FetchReply{}, "hub", http.StatusServiceUnavailable, errors.New("no matching healthy remote agents available")
		}
	}

	// Tailscale / WireGuard Peer-to-Peer Egress Handoff (`EDGEFETCH_PEERS`):
	// When local agents hit 429/challenge (or before local fallback if local fallback hits 429), forward 1 hop to healthy peers.
	if lastAgentReply != nil && !alreadyHopped && len(s.cfg.PeerURLs) > 0 {
		if peerRep, peerVia, ok := s.tryPeerHandoff(ctx, call, primaryHost, traceMap); ok {
			return peerRep, peerVia, http.StatusOK, nil
		}
		return *lastAgentReply, lastAgentVia, http.StatusOK, nil
	}

	if s.cfg.FallbackCrawler == nil {
		if !alreadyHopped && len(s.cfg.PeerURLs) > 0 {
			if peerRep, peerVia, ok := s.tryPeerHandoff(ctx, call, primaryHost, traceMap); ok {
				return peerRep, peerVia, http.StatusOK, nil
			}
		}
		return crawl.FetchReply{}, "hub", http.StatusServiceUnavailable, errors.New("no remote agents connected and local fallback crawler disabled")
	}
	rep := crawl.ExecuteCallWithTrace(ctx, s.cfg.FallbackCrawler, call, traceHdr, crawl.CallLogger(s.log, traceHdr), nil)
	if replyHitStopOrChallenge(rep) && !alreadyHopped && len(s.cfg.PeerURLs) > 0 {
		if peerRep, peerVia, ok := s.tryPeerHandoff(ctx, call, primaryHost, traceMap); ok {
			return peerRep, peerVia, http.StatusOK, nil
		}
	}
	return rep, "local-hub", http.StatusOK, nil
}

func replyHitStopOrChallenge(rep crawl.FetchReply) bool {
	for _, r := range rep.Results {
		if r.Outcome == classify.OutcomeStop || r.Outcome == classify.OutcomeChallenge || r.Outcome == classify.OutcomeNotTried {
			return true
		}
	}
	return false
}

func (s *Server) tryPeerHandoff(ctx context.Context, call crawl.FetchCall, primaryHost string, traceMap map[string]string) (crawl.FetchReply, string, bool) {
	client := s.cfg.PeerHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	peerTok := firstNonEmpty(s.cfg.PeerToken, s.cfg.CallerToken)
	bodyBytes, err := json.Marshal(call)
	if err != nil {
		return crawl.FetchReply{}, "", false
	}

	now := time.Now()
	for _, rawPeer := range s.cfg.PeerURLs {
		base := strings.TrimRight(strings.TrimSpace(rawPeer), "/")
		if base == "" {
			continue
		}
		cdKey := "peer:" + base + "|" + primaryHost
		s.mu.Lock()
		exp, cooled := s.cooldowns[cdKey]
		if cooled && now.Before(exp) {
			s.mu.Unlock()
			continue
		}
		if cooled {
			delete(s.cooldowns, cdKey)
		}
		s.mu.Unlock()

		req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, base+"/fetch", bytes.NewReader(bodyBytes))
		if rErr != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-EdgeFetch-Peer-Hop", "1")
		if peerTok != "" {
			req.Header.Set("Authorization", "Bearer "+peerTok)
		}
		for hk, hv := range traceMap {
			if hv != "" {
				req.Header.Set(hk, hv)
			}
		}

		resp, dErr := client.Do(req)
		if dErr != nil {
			continue
		}
		var peerReply crawl.FetchReply
		decErr := json.NewDecoder(io.LimitReader(resp.Body, maxDecodedReplyBytes)).Decode(&peerReply)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decErr != nil {
			continue
		}
		if replyHitStopOrChallenge(peerReply) {
			cd := defaultCooldownDur
			for _, r := range peerReply.Results {
				if r.RetryAfterMs > 0 {
					cd = time.Duration(r.RetryAfterMs) * time.Millisecond
					break
				}
			}
			s.mu.Lock()
			s.cooldowns[cdKey] = time.Now().Add(cd)
			s.mu.Unlock()
			continue
		}
		peerHost := base
		if pu, pErr := url.Parse(base); pErr == nil && pu.Host != "" {
			peerHost = pu.Host
		}
		return peerReply, "peer:" + peerHost, true
	}
	return crawl.FetchReply{}, "", false
}

func (s *Server) pickAgent(host, preferredSite string, needsBrowser bool, exclude map[string]bool) *agentSession {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	isEligible := func(sess *agentSession) bool {
		if sess == nil || exclude[sess.siteID] {
			return false
		}
		if preferredSite != "" && sess.siteID != preferredSite {
			return false
		}
		if host != "" {
			if exp, cooled := s.cooldowns[sess.siteID+"|"+host]; cooled {
				if now.Before(exp) {
					return false
				}
				delete(s.cooldowns, sess.siteID+"|"+host)
			}
		}
		sess.mu.Lock()
		busy := sess.busy
		hasBr := !needsBrowser || sess.hasCapability("browser-v1")
		sess.mu.Unlock()
		return !busy && hasBr
	}

	if preferredSite == "" && host != "" {
		if aff, ok := s.affinities[host]; ok {
			if now.Before(aff.expiresAt) {
				if sess := s.agents[aff.siteID]; isEligible(sess) {
					sess.mu.Lock()
					sess.busy = true
					sess.mu.Unlock()
					return sess
				}
			} else {
				delete(s.affinities, host)
			}
		}
	}

	var best *agentSession
	var bestLast time.Time
	for _, sess := range s.agents {
		if !isEligible(sess) {
			continue
		}
		sess.mu.Lock()
		lj := sess.lastJobAt
		sess.mu.Unlock()
		if best == nil || lj.Before(bestLast) {
			best = sess
			bestLast = lj
		}
	}
	if best != nil {
		best.mu.Lock()
		best.busy = true
		best.mu.Unlock()
	}
	return best
}

func (s *Server) dispatchToSession(ctx context.Context, sess *agentSession, call crawl.FetchCall, traceMap map[string]string) (crawl.FetchReply, error) {
	jobID := "job_" + randomHex(10)
	jobNonce := randomHex(16)
	pj := &pendingJob{
		jobID:     jobID,
		jobNonce:  jobNonce,
		siteID:    sess.siteID,
		session:   sess,
		doneCh:    make(chan jobOutcome, 1),
		createdAt: time.Now(),
	}

	s.mu.Lock()
	s.pending[jobID] = pj
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if _, still := s.pending[jobID]; still {
			delete(s.pending, jobID)
			sess.mu.Lock()
			sess.busy = false
			sess.mu.Unlock()
		}
		s.mu.Unlock()
	}()

	env := map[string]any{
		"type":     "dispatch",
		"jobId":    jobID,
		"jobNonce": jobNonce,
		"trace":    traceMap,
		"call":     call,
	}
	if call.Options.IncludeBody {
		env["artifacts"] = map[string]any{
			"mode":            "r2",
			"retention":       "transient",
			"maxContentBytes": crawl.MaxMaxBytes,
		}
	}
	frame, err := json.Marshal(env)
	if err != nil {
		return crawl.FetchReply{}, err
	}

	timeout := s.cfg.DispatchTimeout
	if call.MaxSeconds > 0 {
		if d := time.Duration(call.MaxSeconds+5) * time.Second; d < timeout {
			timeout = d
		}
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if werr := sess.conn.Write(dctx, websocket.MessageText, frame); werr != nil {
		return crawl.FetchReply{}, werr
	}

	select {
	case out := <-pj.doneCh:
		return out.reply, out.err
	case <-dctx.Done():
		return crawl.FetchReply{}, dctx.Err()
	}
}

func (s *Server) handleCallerFetch(w http.ResponseWriter, r *http.Request) {
	target := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("target")))
	if target != "" && target != "auto" && target != "agent" && target != "container" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_target"})
		return
	}
	site := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("site")))
	if site != "" && !reSiteID.MatchString(site) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_site"})
		return
	}

	var call crawl.FetchCall
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, crawl.MaxCallBodyBytes))
	if err := dec.Decode(&call); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json", "message": err.Error()})
		return
	}
	if code, msg, ok := crawl.ValidateCall(call, s.allow); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "message": msg})
		return
	}

	reply, via, status, err := s.DispatchOrFallback(r.Context(), call, target, site, r.Header)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": "hub_unavailable", "message": err.Error()})
		return
	}
	w.Header().Set("X-Crawler-Via", via)
	writeJSON(w, http.StatusOK, reply)
}

type scrapePayload struct {
	URL             string   `json:"url"`
	Formats         []string `json:"formats,omitempty"`
	OnlyMainContent *bool    `json:"onlyMainContent,omitempty"`
	RenderMode      string   `json:"renderMode,omitempty"`
	Query           string   `json:"query,omitempty"`
	MaxChars        int      `json:"maxChars,omitempty"`
	Target          string   `json:"target,omitempty"`
	Site            string   `json:"site,omitempty"`
}

func (s *Server) executeScrape(ctx context.Context, p scrapePayload, hdr http.Header) (map[string]any, string, int) {
	u := strings.TrimSpace(p.URL)
	if u == "" {
		return map[string]any{"ok": false, "error": "missing_url"}, "hub", http.StatusBadRequest
	}
	parsedURL, uErr := url.Parse(u)
	if uErr != nil || s.allow(parsedURL) != nil {
		return map[string]any{"ok": false, "error": "bad_url", "message": "only public https:// URLs are permitted"}, "hub", http.StatusBadRequest
	}
	formats := p.Formats
	if len(formats) == 0 {
		formats = []string{"markdown", "links"}
	}
	kind := classify.KindScrape
	if p.RenderMode == "always" {
		kind = classify.KindRender
	}
	onlyMain := true
	if p.OnlyMainContent != nil {
		onlyMain = *p.OnlyMainContent
	}
	call := crawl.FetchCall{
		MaxSeconds: 45,
		Options: crawl.Options{
			Concurrency:   1,
			RespectRobots: crawl.Bool(true),
			DiscoverLlms:  crawl.Bool(true),
		},
		Requests: []crawl.Request{
			{
				ID:              "scrape-1",
				URL:             u,
				Kind:            kind,
				Formats:         formats,
				OnlyMainContent: crawl.Bool(onlyMain),
				DiscoverLlms:    crawl.Bool(true),
				Query:           p.Query,
				RenderMode:      p.RenderMode,
			},
		},
	}

	reply, via, status, err := s.DispatchOrFallback(ctx, call, p.Target, p.Site, hdr)
	if err != nil {
		return map[string]any{"ok": false, "error": "hub_unavailable", "message": err.Error()}, via, status
	}
	if len(reply.Results) == 0 {
		return map[string]any{"ok": false, "error": "empty_reply"}, via, http.StatusBadGateway
	}
	res := reply.Results[0]
	md := res.Markdown
	if p.MaxChars > 0 && len(md) > p.MaxChars {
		md = md[:p.MaxChars]
	}
	return map[string]any{
		"ok":          res.Outcome == classify.OutcomeOK,
		"url":         res.URL,
		"finalUrl":    res.FinalURL,
		"via":         via,
		"status":      res.Status,
		"outcome":     res.Outcome,
		"problem":     res.Problem,
		"title":       res.Title,
		"description": res.Description,
		"markdown":    md,
		"text":        res.Text,
		"links":       res.Links,
		"images":      res.Images,
		"llms":        res.Llms,
		"rendered":    res.Rendered,
		"timing":      res.Timing,
	}, via, http.StatusOK
}

func (s *Server) handleCallerScrape(w http.ResponseWriter, r *http.Request) {
	var p scrapePayload
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, crawl.MaxCallBodyBytes))
	if err := dec.Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json", "message": err.Error()})
		return
	}
	body, via, status := s.executeScrape(r.Context(), p, r.Header)
	w.Header().Set("X-Crawler-Via", via)
	writeJSON(w, status, body)
}

func (s *Server) handleFirecrawlV2Scrape(w http.ResponseWriter, r *http.Request) {
	var p scrapePayload
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, crawl.MaxCallBodyBytes))
	if err := dec.Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "bad_json", "message": err.Error()})
		return
	}
	body, via, status := s.executeScrape(r.Context(), p, r.Header)
	w.Header().Set("X-Crawler-Via", via)
	okVal, _ := body["ok"].(bool)
	if status != http.StatusOK || !okVal {
		writeJSON(w, status, map[string]any{"success": false, "error": firstNonEmpty(fmt.Sprint(body["problem"]), fmt.Sprint(body["error"]))})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": body})
}

var (
	reHubSitemapLoc = regexp.MustCompile(`(?i)<loc>\s*(https?://[^<\s]+)\s*</loc>`)
	reHubMdURL      = regexp.MustCompile(`\]\((https?://[^)\s]+)\)`)
)

func (s *Server) handleCallerMap(w http.ResponseWriter, r *http.Request, v2Envelope bool) {
	var mp struct {
		URL    string `json:"url"`
		Search string `json:"search"`
		Limit  int    `json:"limit"`
		Target string `json:"target"`
		Site   string `json:"site"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, crawl.MaxCallBodyBytes))
	if err := dec.Decode(&mp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "success": false, "error": "bad_json"})
		return
	}
	parsedURL, uErr := url.Parse(strings.TrimSpace(mp.URL))
	if uErr != nil || s.allow(parsedURL) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "success": false, "error": "invalid_url"})
		return
	}
	if mp.Limit <= 0 || mp.Limit > 500 {
		mp.Limit = 100
	}
	origin := parsedURL.Scheme + "://" + parsedURL.Host
	call := crawl.FetchCall{
		MaxSeconds: 30,
		Options:    crawl.Options{Concurrency: 2, IncludeBody: true, RespectRobots: crawl.Bool(true)},
		Requests: []crawl.Request{
			{ID: "llms", URL: origin + "/llms.txt", Kind: classify.KindText},
			{ID: "sitemap", URL: origin + "/sitemap.xml", Kind: classify.KindText},
			{ID: "home", URL: parsedURL.String(), Kind: classify.KindScrape, Formats: []string{"links"}},
		},
	}
	rep, via, status, err := s.DispatchOrFallback(r.Context(), call, mp.Target, mp.Site, r.Header)
	if err != nil {
		writeJSON(w, status, map[string]any{"ok": false, "success": false, "error": err.Error()})
		return
	}
	seen := map[string]struct{}{}
	var links []string
	filterLower := strings.ToLower(strings.TrimSpace(mp.Search))
	addCand := func(cand string) {
		cand = strings.TrimSpace(cand)
		if (!strings.HasPrefix(cand, "https://") && !strings.HasPrefix(cand, "http://")) || len(links) >= mp.Limit {
			return
		}
		if cu, cErr := url.Parse(cand); cErr != nil || s.allow(cu) != nil {
			return
		}
		if filterLower != "" && !strings.Contains(strings.ToLower(cand), filterLower) {
			return
		}
		if _, exists := seen[cand]; !exists {
			seen[cand] = struct{}{}
			links = append(links, cand)
		}
	}
	for _, item := range rep.Results {
		for _, l := range item.Links {
			addCand(l)
		}
		for _, m := range reHubSitemapLoc.FindAllStringSubmatch(item.Body, 500) {
			if len(m) > 1 {
				addCand(m[1])
			}
		}
		for _, m := range reHubMdURL.FindAllStringSubmatch(item.Body, 500) {
			if len(m) > 1 {
				addCand(m[1])
			}
		}
	}
	w.Header().Set("X-Crawler-Via", via)
	if v2Envelope {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "links": links})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "url": origin, "total": len(links), "links": links})
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete || r.Method == http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	var rpc struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	if err := dec.Decode(&rpc); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      nil,
			"error":   map[string]any{"code": -32700, "message": "Parse error"},
		})
		return
	}

	switch rpc.Method {
	case "notifications/initialized", "notifications/cancelled":
		w.WriteHeader(http.StatusAccepted)
		return

	case "ping":
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": rpc.ID, "result": map[string]any{}})
		return

	case "initialize":
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result": map[string]any{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "edgefetch-go-hub", "version": agent.Version},
			},
		})
		return

	case "tools/list":
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result": map[string]any{
				"tools": []map[string]any{
					{
						"name":        "list_agents",
						"description": "List connected EdgeFetch Go worker nodes and capabilities.",
						"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
					},
					{
						"name":        "scrape",
						"description": "Scrape a public HTTPS URL to clean Markdown via connected Go nodes or local Hub fallback.",
						"inputSchema": map[string]any{
							"type":     "object",
							"required": []string{"url"},
							"properties": map[string]any{
								"url":        map[string]any{"type": "string"},
								"query":      map[string]any{"type": "string"},
								"maxChars":   map[string]any{"type": "integer"},
								"renderMode": map[string]any{"type": "string", "enum": []string{"off", "auto", "always"}},
								"target":     map[string]any{"type": "string", "enum": []string{"auto", "agent", "container"}},
								"site":       map[string]any{"type": "string"},
							},
						},
					},
					{
						"name":        "fetch_url",
						"description": "Fetch one HTTPS URL with raw status, httptrace timing, and classification outcome.",
						"inputSchema": map[string]any{
							"type":     "object",
							"required": []string{"url"},
							"properties": map[string]any{
								"url":    map[string]any{"type": "string"},
								"kind":   map[string]any{"type": "string"},
								"target": map[string]any{"type": "string"},
							},
						},
					},
				},
			},
		})
		return

	case "tools/call":
		var callParams struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(rpc.Params, &callParams); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"error":   map[string]any{"code": -32602, "message": "Invalid params"},
			})
			return
		}
		switch callParams.Name {
		case "list_agents":
			txt, _ := json.MarshalIndent(s.ListAgents(), "", "  ")
			writeJSON(w, http.StatusOK, mcpTextResult(rpc.ID, string(txt), false))
			return
		case "scrape":
			var sp scrapePayload
			_ = json.Unmarshal(callParams.Arguments, &sp)
			out, _, status := s.executeScrape(r.Context(), sp, r.Header)
			txt, _ := json.MarshalIndent(out, "", "  ")
			isErr := status >= 400 || out["ok"] == false
			writeJSON(w, http.StatusOK, mcpTextResult(rpc.ID, string(txt), isErr))
			return
		case "fetch_url":
			var fp struct {
				URL    string `json:"url"`
				Kind   string `json:"kind"`
				Target string `json:"target"`
			}
			_ = json.Unmarshal(callParams.Arguments, &fp)
			k := classify.Kind(fp.Kind)
			if k == "" {
				k = classify.KindScrape
			}
			fc := crawl.FetchCall{
				MaxSeconds: 45,
				Options:    crawl.Options{IncludeBody: true, RespectRobots: crawl.Bool(true)},
				Requests:   []crawl.Request{{ID: "mcp-1", URL: strings.TrimSpace(fp.URL), Kind: k}},
			}
			if code, msg, ok := crawl.ValidateCall(fc, s.allow); !ok {
				writeJSON(w, http.StatusOK, mcpTextResult(rpc.ID, code+": "+msg, true))
				return
			}
			rep, via, _, err := s.DispatchOrFallback(r.Context(), fc, fp.Target, "", r.Header)
			if err != nil {
				writeJSON(w, http.StatusOK, mcpTextResult(rpc.ID, err.Error(), true))
				return
			}
			txt, _ := json.MarshalIndent(map[string]any{"via": via, "reply": rep}, "", "  ")
			writeJSON(w, http.StatusOK, mcpTextResult(rpc.ID, string(txt), false))
			return
		default:
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"error":   map[string]any{"code": -32601, "message": "Unknown tool: " + callParams.Name},
			})
			return
		}

	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"error":   map[string]any{"code": -32601, "message": "Method not found"},
		})
	}
}

func mcpTextResult(id any, text string, isError bool) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"isError": isError,
			"content": []map[string]any{
				{"type": "text", "text": text},
			},
		},
	}
}

func extractBearer(r *http.Request) string {
	val := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(val) < 8 || !strings.EqualFold(val[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(val[7:])
}

func extractCallerToken(r *http.Request) string {
	if b := extractBearer(r); b != "" {
		return b
	}
	apiKey := strings.TrimSpace(r.Header.Get("X-Api-Key"))
	if apiKey != "" && !strings.ContainsAny(apiKey, " \t\r\n") {
		return apiKey
	}
	return ""
}

func constantTimeEquals(a, b string) bool {
	da := sha256.Sum256([]byte(a))
	db := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
}

func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

func clientIPOf(r *http.Request) string {
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		return cf
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return strconv.Itoa(len(r.RemoteAddr))
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if c := strings.TrimSpace(p); c != "" {
			out = append(out, c)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) serveDesktopLaunchpad(w http.ResponseWriter, r *http.Request) {
	origin := "http://" + r.Host
	mcpURL := origin + "/mcp"
	vscodeLink := "vscode:mcp/install?%7B%22name%22%3A%22edgefetch%22%2C%22type%22%3A%22http%22%2C%22url%22%3A%22" + url.QueryEscape(mcpURL) + "%22%7D"
	cursorCfgB64 := "eyJ1cmwiOiI" // dynamic in JS below for exact host port
	_ = cursorCfgB64
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EdgeFetch %s — Local Desktop MCP Launchpad</title>
  <style>
    :root { color-scheme: dark; }
    body { font: 14px/1.55 system-ui, -apple-system, sans-serif; margin: 0; background: #0b1120; color: #e2e8f0; padding: 28px 16px; }
    main { max-width: 860px; margin: 0 auto; display: grid; gap: 18px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; }
    h1 { margin: 0 0 6px; font-size: 1.3rem; color: #f8fafc; }
    h2 { margin: 0 0 10px; font-size: 1rem; color: #f8fafc; }
    p { margin: 0; color: #94a3b8; }
    .btns { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
    a.btn, button { font: inherit; font-weight: 600; font-size: 0.85rem; text-decoration: none; padding: 8px 14px; border-radius: 8px; border: 1px solid #3b82f6; background: #2563eb; color: #fff; cursor: pointer; }
    a.btn.alt { background: #0f172a; border-color: #475569; color: #38bdf8; }
    input[type="url"] { width: 100%%; box-sizing: border-box; padding: 9px 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font: inherit; }
    pre { background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 12px; overflow: auto; max-height: 360px; color: #7dd3fc; font-size: 0.82rem; margin: 10px 0 0; }
  </style>
</head>
<body>
  <main>
    <section class="card">
      <h1>EdgeFetch v%s — Local Desktop MCP Running</h1>
      <p>Listening strictly on loopback (<code>%s</code>) with HTTP/2 + SSRF-proxied OS Browser JS rendering.</p>
      <div class="btns">
        <a class="btn" id="cursor-btn" href="#">+ Install in Cursor</a>
        <a class="btn" href="%s">+ Install in VS Code</a>
        <a class="btn alt" href="/v1/capabilities" target="_blank">View Capabilities JSON</a>
      </div>
      <pre>claude mcp add --transport http edgefetch %s
# Or zero-daemon stdio mode (Claude Desktop / Cursor / Windsurf):
edgefetch install-mcp</pre>
    </section>
    <section class="card">
      <h2>Live Local Scrape Tester</h2>
      <form id="f" style="display:grid;grid-template-columns:1fr auto;gap:10px">
        <input id="u" type="url" required value="https://example.com" placeholder="https://...">
        <button type="submit" id="b">Scrape to Markdown</button>
      </form>
      <pre id="out">Click "Scrape to Markdown" to test your local node...</pre>
    </section>
  </main>
  <script>
    const mcpUrl = %q;
    document.getElementById('cursor-btn').href = 'cursor://anysphere.cursor-deeplink/mcp/install?name=edgefetch&config=' + encodeURIComponent(btoa(JSON.stringify({ url: mcpUrl })));
    document.getElementById('f').addEventListener('submit', async (e) => {
      e.preventDefault();
      const b = document.getElementById('b');
      b.disabled = true; b.textContent = 'Scraping...';
      try {
        const r = await fetch('/v1/scrape', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: document.getElementById('u').value }) });
        const j = await r.json();
        document.getElementById('out').textContent = j.markdown || JSON.stringify(j, null, 2);
      } finally { b.disabled = false; b.textContent = 'Scrape to Markdown'; }
    });
  </script>
</body>
</html>`, agent.Version, agent.Version, origin, vscodeLink, mcpURL, mcpURL)
}
