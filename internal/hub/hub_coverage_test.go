package hub

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/coder/websocket"

	"github.com/bartrumb/edgefetch/v2/internal/botauth"
	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
)

type hubRTFunc func(*http.Request) (*http.Response, error)

func (f hubRTFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func makeTestGzip(t *testing.T, data []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	b := buf.Bytes()
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:])
}

func TestHubHelpersAndConfigDefaults(t *testing.T) {
	if toks, err := ParseAgentTokensJSON("   "); err != nil || toks != nil {
		t.Fatalf("expected nil, nil for blank tokens JSON, got %v, %v", toks, err)
	}
	if _, err := ParseAgentTokensJSON("{bad"); err == nil {
		t.Fatal("expected malformed tokens JSON error")
	}
	if _, err := ParseAgentTokensJSON(`{"Bad Site!":"012345678901234567890123"}`); err == nil || !strings.Contains(err.Error(), "invalid site_id") {
		t.Fatalf("expected invalid site_id error, got %v", err)
	}
	if _, err := ParseAgentTokensJSON(`{"site-1":"short"}`); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("expected short token error, got %v", err)
	}

	sDef := NewServer(Config{})
	if sDef.maxBlobCap != maxArtifactStoreBytes || cap(sDef.callSem) != maxConcurrentCalls || sDef.cfg.DispatchTimeout != 60*time.Second {
		t.Fatalf("unexpected NewServer defaults: blobCap=%d sem=%d timeout=%v", sDef.maxBlobCap, cap(sDef.callSem), sDef.cfg.DispatchTimeout)
	}
	sCust := NewServer(Config{
		Logger:             slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DispatchTimeout:    5 * time.Second,
		MaxArtifactMemory:  1024,
		MaxConcurrentCalls: 2,
	})
	if sCust.maxBlobCap != 1024 || cap(sCust.callSem) != 2 || sCust.cfg.DispatchTimeout != 5*time.Second {
		t.Fatalf("unexpected custom NewServer config: blobCap=%d sem=%d timeout=%v", sCust.maxBlobCap, cap(sCust.callSem), sCust.cfg.DispatchTimeout)
	}

	if got := hostOfURL("://bad-url"); got != "" {
		t.Fatalf("expected empty hostOfURL for bad url, got %q", got)
	}
	if got := splitCSV("   "); got != nil {
		t.Fatalf("expected nil splitCSV for whitespace, got %v", got)
	}
	if got := splitCSV("a, , b"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected splitCSV: %v", got)
	}

	reqAPI := httptest.NewRequest(http.MethodGet, "/", nil)
	reqAPI.Header.Set("X-Api-Key", "valid-api-key")
	if got := extractCallerToken(reqAPI); got != "valid-api-key" {
		t.Fatalf("expected X-Api-Key token, got %q", got)
	}
	reqBadAPI := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBadAPI.Header.Set("X-Api-Key", "has space")
	if got := extractCallerToken(reqBadAPI); got != "" {
		t.Fatalf("expected whitespace X-Api-Key rejected, got %q", got)
	}

	reqCF := httptest.NewRequest(http.MethodGet, "/", nil)
	reqCF.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := clientIPOf(reqCF); got != "203.0.113.9" {
		t.Fatalf("expected CF-Connecting-IP, got %q", got)
	}
	reqXFF := httptest.NewRequest(http.MethodGet, "/", nil)
	reqXFF.Header.Set("X-Forwarded-For", "198.51.100.1, 10.0.0.1")
	if got := clientIPOf(reqXFF); got != "198.51.100.1" {
		t.Fatalf("expected X-Forwarded-For first IP, got %q", got)
	}
	reqRawAddr := httptest.NewRequest(http.MethodGet, "/", nil)
	reqRawAddr.RemoteAddr = "unparsed-addr"
	if got := clientIPOf(reqRawAddr); got != "13" {
		t.Fatalf("expected len(RemoteAddr) fallback \"13\", got %q", got)
	}

	if got := requestFullURL(nil); got != "" {
		t.Fatalf("expected empty requestFullURL(nil), got %q", got)
	}
	if got := requestFullURL(&http.Request{}); got != "" {
		t.Fatalf("expected empty requestFullURL with nil URL, got %q", got)
	}
	reqTLS := httptest.NewRequest(http.MethodGet, "/v1/scrape?q=1", nil)
	reqTLS.TLS = &tls.ConnectionState{}
	reqTLS.Host = "hub.example.com"
	if got := requestFullURL(reqTLS); got != "https://hub.example.com/v1/scrape?q=1" {
		t.Fatalf("expected https requestFullURL, got %q", got)
	}
	reqNoHost := httptest.NewRequest(http.MethodGet, "/only-path", nil)
	reqNoHost.Host = ""
	if got := requestFullURL(reqNoHost); got != "/only-path" {
		t.Fatalf("expected path-only requestFullURL, got %q", got)
	}

	rec := httptest.NewRecorder()
	sw := &statusResponseWriter{ResponseWriter: rec}
	if sw.Unwrap() != rec {
		t.Fatal("statusResponseWriter.Unwrap did not return inner ResponseWriter")
	}
}

func TestHubBotTransparencyAndLaunchpad(t *testing.T) {
	kp, err := botauth.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signer, err := botauth.NewSigner(kp.PrivateKeySeedB64URL, "https://hub.example/.well-known/http-message-signatures-directory")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	s := NewServer(Config{
		BotSigner: signer,
		BotPublicJWKs: []botauth.PublicJWK{
			{Kid: ""},
			signer.PublicJWK(),
			{Kty: "OKP", Crv: "Ed25519", Kid: "extra-kid-1", X: "AAAA"},
		},
		UserAgent:           "CustomBot/1.0",
		BotContactURL:       "https://ops.example/bot",
		AllowedLoopbackPort: "8787",
	})
	defer s.Close()

	// Directory GET & HEAD with BotSigner != nil (max-age=240, HEAD writes no body)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		req := httptest.NewRequest(method, "http://127.0.0.1:8787/.well-known/http-message-signatures-directory", nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Cache-Control"), "max-age=240") {
			t.Fatalf("%s directory failed: code=%d cc=%q", method, rec.Code, rec.Header().Get("Cache-Control"))
		}
		if method == http.MethodHead && rec.Body.Len() != 0 {
			t.Fatalf("expected empty body for HEAD directory, got %q", rec.Body.String())
		}
		if method == http.MethodGet && !strings.Contains(rec.Body.String(), "extra-kid-1") {
			t.Fatalf("expected extra-kid-1 in directory body: %s", rec.Body.String())
		}
	}

	// Directory without BotSigner (max-age=3600)
	sNoSig := NewServer(Config{})
	defer sNoSig.Close()
	recNoSig := httptest.NewRecorder()
	sNoSig.ServeHTTP(recNoSig, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/.well-known/http-message-signatures-directory", nil))
	if recNoSig.Code != http.StatusOK || !strings.Contains(recNoSig.Header().Get("Cache-Control"), "max-age=3600") {
		t.Fatalf("unsigned directory failed: code=%d cc=%q", recNoSig.Code, recNoSig.Header().Get("Cache-Control"))
	}

	// /.well-known/edgefetch-bot.json with X-Forwarded-Proto: https and r.Host == "" fallback to r.URL.Host
	reqBot := httptest.NewRequest(http.MethodGet, "https://bot.example/.well-known/edgefetch-bot.json", nil)
	reqBot.Host = ""
	reqBot.Header.Set("X-Forwarded-Proto", "https")
	recBot := httptest.NewRecorder()
	s.ServeHTTP(recBot, reqBot)
	if recBot.Code != http.StatusOK || !strings.Contains(recBot.Body.String(), `"https://bot.example/.well-known/http-message-signatures-directory"`) || !strings.Contains(recBot.Body.String(), `"CustomBot/1.0"`) {
		t.Fatalf("unexpected edgefetch-bot.json response (%d): %s", recBot.Code, recBot.Body.String())
	}

	// Tokenless Desktop Launchpad via ServeHTTP (writes without explicit WriteHeader) + /healthz + /v1/capabilities + /v1/extractors
	reqHome := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/", nil)
	reqHome.Host = "127.0.0.1:8787"
	recHome := httptest.NewRecorder()
	s.ServeHTTP(recHome, reqHome)
	if recHome.Code != http.StatusOK || !strings.Contains(recHome.Body.String(), "Local Desktop MCP Launchpad") {
		t.Fatalf("unexpected launchpad response (%d): %s", recHome.Code, recHome.Body.String())
	}

	// Direct white-box call with empty r.Host -> defaults to 127.0.0.1:8787
	recEmptyHost := httptest.NewRecorder()
	reqEmptyHost := httptest.NewRequest(http.MethodGet, "/", nil)
	reqEmptyHost.Host = ""
	s.serveDesktopLaunchpad(recEmptyHost, reqEmptyHost)
	if !strings.Contains(recEmptyHost.Body.String(), "http://127.0.0.1:8787/mcp") {
		t.Fatalf("expected default 127.0.0.1:8787 in launchpad: %s", recEmptyHost.Body.String())
	}

	for _, path := range []string{"/healthz", "/v1/capabilities", "/v1/extractors"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787"+path, nil)
		req.Host = "127.0.0.1:8787"
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestHubTokenlessLoopbackEdgeCases(t *testing.T) {
	sAnyPort := NewServer(Config{})
	defer sAnyPort.Close()

	// Empty Host -> 403
	reqNoHost := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	reqNoHost.Host = ""
	rec := httptest.NewRecorder()
	sAnyPort.ServeHTTP(rec, reqNoHost)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for empty Host, got %d", rec.Code)
	}

	// Bare Host: localhost without port when AllowedLoopbackPort == "" -> 200
	reqBare := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	reqBare.Host = "localhost"
	recBare := httptest.NewRecorder()
	sAnyPort.ServeHTTP(recBare, reqBare)
	if recBare.Code != http.StatusOK {
		t.Fatalf("expected 200 for bare localhost without port pin, got %d: %s", recBare.Code, recBare.Body.String())
	}

	// Port-pinned server
	sPinned := NewServer(Config{AllowedLoopbackPort: "8787"})
	defer sPinned.Close()

	reqWrongPort := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	reqWrongPort.Host = "localhost"
	recWrongPort := httptest.NewRecorder()
	sPinned.ServeHTTP(recWrongPort, reqWrongPort)
	if recWrongPort.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for Host port mismatch, got %d", recWrongPort.Code)
	}

	reqBadOriginScheme := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	reqBadOriginScheme.Host = "127.0.0.1:8787"
	reqBadOriginScheme.Header.Set("Origin", "ftp://127.0.0.1:8787")
	recBadOriginScheme := httptest.NewRecorder()
	sPinned.ServeHTTP(recBadOriginScheme, reqBadOriginScheme)
	if recBadOriginScheme.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for bad Origin scheme, got %d", recBadOriginScheme.Code)
	}

	reqBadOriginPort := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	reqBadOriginPort.Host = "127.0.0.1:8787"
	reqBadOriginPort.Header.Set("Origin", "http://127.0.0.1:9999")
	recBadOriginPort := httptest.NewRecorder()
	sPinned.ServeHTTP(recBadOriginPort, reqBadOriginPort)
	if recBadOriginPort.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for Origin port mismatch, got %d", recBadOriginPort.Code)
	}

	// PUT/DELETE without application/json -> 415
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/mcp", nil)
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Origin", "http://127.0.0.1:8787")
		rec := httptest.NewRecorder()
		sPinned.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415 for %s without json content-type, got %d", method, rec.Code)
		}
	}
}

func TestHubAuthorizeAgentPerSiteAndIsolation(t *testing.T) {
	const (
		tokSiteA  = "site-a-secret-token-0123456789"
		tokShared = "shared-agent-token-01234567890"
		callerTok = "caller-secret-token-0123456789"
	)
	s := NewServer(Config{
		CallerToken: callerTok,
		AgentToken:  tokShared,
		AgentTokens: map[string]string{
			"site-a":     tokSiteA,
			"short-site": "too-short",
		},
	})
	defer s.Close()

	makeAuthReq := func(tok, site string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/agent/ws", nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		if site != "" {
			r.Header.Set("X-Agent-Site", site)
		}
		return r
	}

	if site, ok := s.authorizeAgent(makeAuthReq("", "site-a")); ok || site != "" {
		t.Fatal("expected empty bearer rejected")
	}
	if site, ok := s.authorizeAgent(makeAuthReq(tokSiteA, "")); !ok || site != "site-a" {
		t.Fatalf("expected site-a without X-Agent-Site allowed, got %q %v", site, ok)
	}
	if site, ok := s.authorizeAgent(makeAuthReq(tokSiteA, "site-a")); !ok || site != "site-a" {
		t.Fatalf("expected site-a matching X-Agent-Site allowed, got %q %v", site, ok)
	}
	if _, ok := s.authorizeAgent(makeAuthReq(tokSiteA, "site-b")); ok {
		t.Fatal("expected site-a token with mismatched X-Agent-Site rejected")
	}
	if _, ok := s.authorizeAgent(makeAuthReq("too-short", "short-site")); ok {
		t.Fatal("expected short per-site token rejected")
	}
	if _, ok := s.authorizeAgent(makeAuthReq(tokShared, "site-a")); ok {
		t.Fatal("expected shared token rejected for mapped site-a")
	}
	if _, ok := s.authorizeAgent(makeAuthReq(tokShared, "BAD!")); ok {
		t.Fatal("expected shared token rejected for invalid site ID")
	}
	if site, ok := s.authorizeAgent(makeAuthReq(tokShared, "site-free")); !ok || site != "site-free" {
		t.Fatalf("expected shared token allowed for unmapped site-free, got %q %v", site, ok)
	}
}

func TestHubAgentWSLifecycleErrorsPingReplaceAndDisconnect(t *testing.T) {
	const agentTok = "agent-ws-secret-token-0123456789"
	const callerTok = "caller-ws-secret-token-012345678"
	s := NewServer(Config{
		CallerToken:     callerTok,
		AgentToken:      agentTok,
		DispatchTimeout: 2 * time.Second,
	})
	defer s.Close()
	srv := httptest.NewServer(s)
	defer srv.Close()

	// POST /agent/ws -> 405
	reqPost := httptest.NewRequest(http.MethodPost, "/agent/ws", nil)
	recPost := httptest.NewRecorder()
	s.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /agent/ws, got %d", recPost.Code)
	}

	// GET /agent/ws unauthenticated -> 401
	recUnauth := httptest.NewRecorder()
	s.ServeHTTP(recUnauth, httptest.NewRequest(http.MethodGet, "/agent/ws", nil))
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /agent/ws, got %d", recUnauth.Code)
	}

	// GET /agent/ws authenticated plain HTTP -> websocket.Accept error
	reqPlain := httptest.NewRequest(http.MethodGet, "/agent/ws", nil)
	reqPlain.Header.Set("Authorization", "Bearer "+agentTok)
	reqPlain.Header.Set("X-Agent-Site", "site-dup")
	recPlain := httptest.NewRecorder()
	s.ServeHTTP(recPlain, reqPlain)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect Agent 1 (site-dup), verify hello, ping/pong, agent_hello update.
	c1, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":        {"Bearer " + agentTok},
			"X-Agent-Site":         {"site-dup"},
			"X-Agent-Capabilities": {"http2"},
		},
	})
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	defer c1.CloseNow()
	if _, _, err := c1.Read(ctx); err != nil { // initial hello
		t.Fatalf("c1 read hello: %v", err)
	}
	if err := c1.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatalf("c1 write ping: %v", err)
	}
	_, pong, err := c1.Read(ctx)
	if err != nil || string(pong) != "pong" {
		t.Fatalf("expected pong, got %q (err=%v)", pong, err)
	}
	if err := c1.Write(ctx, websocket.MessageText, []byte(`{"type":"agent_hello","version":"2.7.1","arch":"amd64","capabilities":["browser-v1"]}`)); err != nil {
		t.Fatalf("c1 write agent_hello: %v", err)
	}

	c1Closed := make(chan error, 1)
	go func() {
		_, _, rErr := c1.Read(ctx)
		c1Closed <- rErr
	}()

	// Connect Agent 2 with same site-dup -> replaces c1!
	c2, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": {"Bearer " + agentTok},
			"X-Agent-Site":  {"site-dup"},
		},
	})
	if err != nil {
		t.Fatalf("dial c2: %v", err)
	}
	if _, _, err := c2.Read(ctx); err != nil {
		t.Fatalf("c2 read hello: %v", err)
	}
	// c1 should receive PolicyViolation close
	if rErr := <-c1Closed; rErr == nil {
		t.Fatal("expected replaced c1 to be closed")
	}

	// Also connect site-a to test ListAgents sorting with >=2 agents
	cA, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": {"Bearer " + agentTok},
			"X-Agent-Site":  {"site-a"},
		},
	})
	if err != nil {
		t.Fatalf("dial cA: %v", err)
	}
	defer cA.CloseNow()
	if _, _, err := cA.Read(ctx); err != nil {
		t.Fatalf("cA read hello: %v", err)
	}
	// Wait briefly for agent registration
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		la := s.ListAgents()
		if la["connected"].(int) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	agentsMap := s.ListAgents()
	agentsSlice := agentsMap["agents"].([]AgentInfo)
	if len(agentsSlice) != 2 || agentsSlice[0].SiteID != "site-a" || agentsSlice[1].SiteID != "site-dup" {
		t.Fatalf("unexpected sorted ListAgents: %+v", agentsSlice)
	}

	// Dispatch job to site-dup, read dispatch frame on c2, then close c2 abruptly -> pending job canceled with agent_disconnected
	errCh := make(chan error, 1)
	go func() {
		_, _, _, dErr := s.DispatchOrFallback(ctx, crawl.FetchCall{
			MaxSeconds: 5,
			Requests:   []crawl.Request{{ID: "r1", URL: "https://example.com/", Kind: classify.KindScrape}},
		}, "agent", "site-dup", nil)
		errCh <- dErr
	}()
	if _, _, err := c2.Read(ctx); err != nil {
		t.Fatalf("c2 read dispatch: %v", err)
	}
	_ = c2.CloseNow()
	select {
	case dErr := <-errCh:
		if dErr == nil {
			t.Fatal("expected DispatchOrFallback error after agent disconnect")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for agent_disconnected failure")
	}
}

func TestHubArtifactPutEvictionHydrationAndReplyErrors(t *testing.T) {
	const agentTok = "agent-art-secret-token-01234567"
	s := NewServer(Config{
		AgentToken:        agentTok,
		MaxArtifactMemory: 128,
	})
	defer s.Close()

	authHeader := "Bearer " + agentTok
	validSHA := strings.Repeat("a", 64)

	// 1. PUT /agent/artifacts/* error paths
	recUnauth := httptest.NewRecorder()
	s.ServeHTTP(recUnauth, httptest.NewRequest(http.MethodPut, "/agent/artifacts/"+validSHA, strings.NewReader("x")))
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recUnauth.Code)
	}

	reqBadHdr := httptest.NewRequest(http.MethodPut, "/agent/artifacts/bad-sha", strings.NewReader("x"))
	reqBadHdr.Header.Set("Authorization", authHeader)
	reqBadHdr.Header.Set("X-Agent-Site", "site-1")
	recBadHdr := httptest.NewRecorder()
	s.ServeHTTP(recBadHdr, reqBadHdr)
	if recBadHdr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad_artifact_headers, got %d", recBadHdr.Code)
	}

	reqNoJob := httptest.NewRequest(http.MethodPut, "/agent/artifacts/"+validSHA, strings.NewReader("x"))
	reqNoJob.Header.Set("Authorization", authHeader)
	reqNoJob.Header.Set("X-Agent-Site", "site-1")
	reqNoJob.Header.Set("X-Job-Id", "job_missing")
	reqNoJob.Header.Set("X-Job-Nonce", "nonce123")
	recNoJob := httptest.NewRecorder()
	s.ServeHTTP(recNoJob, reqNoJob)
	if recNoJob.Code != http.StatusNotFound {
		t.Fatalf("expected 404 unknown job, got %d", recNoJob.Code)
	}

	// Seed a pendingJob directly to hit uploading (409), uploadsCount (429), uploadedBlobs==nil init, too-large body (413), sha mismatch (400), and valid upload
	pj := &pendingJob{
		jobID:    "job_art1",
		jobNonce: "nonce_art1",
		siteID:   "site-1",
		requests: []crawl.Request{{ID: "r1", URL: "https://example.com/", Kind: classify.KindScrape}},
		doneCh:   make(chan jobOutcome, 1),
	}
	s.mu.Lock()
	s.pending[pj.jobID] = pj
	s.mu.Unlock()

	// 409 Conflict when uploading == true
	pj.uploading = true
	if _, code := s.acquirePendingJobArtifactSlot(pj.jobID, pj.jobNonce, pj.siteID); code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict, got %d", code)
	}
	pj.uploading = false

	// 429 TooManyRequests when uploadsCount >= maxJobArtifactUploads
	pj.uploadsCount = maxJobArtifactUploads
	if _, code := s.acquirePendingJobArtifactSlot(pj.jobID, pj.jobNonce, pj.siteID); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 TooManyRequests, got %d", code)
	}
	pj.uploadsCount = 0

	// Body read error / > MaxMaxBytes -> 413 artifact_too_large
	reqTooLarge := httptest.NewRequest(http.MethodPut, "/agent/artifacts/"+validSHA, iotest.ErrReader(errors.New("body read fail")))
	reqTooLarge.Header.Set("Authorization", authHeader)
	reqTooLarge.Header.Set("X-Agent-Site", "site-1")
	reqTooLarge.Header.Set("X-Job-Id", pj.jobID)
	reqTooLarge.Header.Set("X-Job-Nonce", pj.jobNonce)
	recTooLarge := httptest.NewRecorder()
	s.ServeHTTP(recTooLarge, reqTooLarge)
	if recTooLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 artifact_too_large, got %d", recTooLarge.Code)
	}

	// SHA mismatch -> 400 blob_sha256_mismatch
	reqMismatch := httptest.NewRequest(http.MethodPut, "/agent/artifacts/"+validSHA, strings.NewReader("payload"))
	reqMismatch.Header.Set("Authorization", authHeader)
	reqMismatch.Header.Set("X-Agent-Site", "site-1")
	reqMismatch.Header.Set("X-Job-Id", pj.jobID)
	reqMismatch.Header.Set("X-Job-Nonce", pj.jobNonce)
	recMismatch := httptest.NewRecorder()
	s.ServeHTTP(recMismatch, reqMismatch)
	if recMismatch.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 blob_sha256_mismatch, got %d", recMismatch.Code)
	}

	// Valid upload initializes nil pj.uploadedBlobs
	gzValid, shaValid := makeTestGzip(t, []byte("hello-artifact"))
	reqOK := httptest.NewRequest(http.MethodPut, "/agent/artifacts/"+shaValid, bytes.NewReader(gzValid))
	reqOK.Header.Set("Authorization", authHeader)
	reqOK.Header.Set("X-Agent-Site", "site-1")
	reqOK.Header.Set("X-Job-Id", pj.jobID)
	reqOK.Header.Set("X-Job-Nonce", pj.jobNonce)
	recOK := httptest.NewRecorder()
	s.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 artifact upload, got %d: %s", recOK.Code, recOK.Body.String())
	}

	// 2. storeBlob duplicate, FIFO eviction, oversized blob (> maxBlobCap), and hydrateArtifacts edge cases
	s.storeBlob(storedBlob{sha256: shaValid, gzBytes: gzValid}) // duplicate early return
	b1 := bytes.Repeat([]byte("1"), 64)
	h1 := sha256.Sum256(b1)
	s1 := hex.EncodeToString(h1[:])
	b2 := bytes.Repeat([]byte("2"), 64)
	h2 := sha256.Sum256(b2)
	s2 := hex.EncodeToString(h2[:])
	b3 := bytes.Repeat([]byte("3"), 64)
	h3 := sha256.Sum256(b3)
	s3 := hex.EncodeToString(h3[:])
	s.storeBlob(storedBlob{sha256: s1, gzBytes: b1})
	s.storeBlob(storedBlob{sha256: s2, gzBytes: b2})
	s.storeBlob(storedBlob{sha256: s3, gzBytes: b3})                   // evicts shaValid & s1
	s.storeBlob(storedBlob{sha256: "big", gzBytes: make([]byte, 200)}) // > maxBlobCap (128), skipped

	// Corrupt gzip and truncated gzip blobs
	notGzip := []byte("not-gzip-bytes")
	ngSum := sha256.Sum256(notGzip)
	ngSHA := hex.EncodeToString(ngSum[:])
	s.storeBlob(storedBlob{sha256: ngSHA, gzBytes: notGzip})

	gzTruncSource, _ := makeTestGzip(t, []byte("truncated-gzip-stream"))
	gzTrunc := gzTruncSource[:len(gzTruncSource)-4]
	trSum := sha256.Sum256(gzTrunc)
	trSHA := hex.EncodeToString(trSum[:])
	s.storeBlob(storedBlob{sha256: trSHA, gzBytes: gzTrunc})

	// Valid small gzip blob fitting within 128-byte cap
	gzSmall, smallSHA := makeTestGzip(t, []byte("ok"))
	s.storeBlob(storedBlob{sha256: smallSHA, gzBytes: gzSmall})

	rep := crawl.FetchReply{
		Results: []crawl.Result{
			{Body: "already-set", Artifact: &crawl.ArtifactRef{BlobSHA256: smallSHA}},
			{Artifact: &crawl.ArtifactRef{BlobSHA256: s1}},       // evicted -> !ok
			{Artifact: &crawl.ArtifactRef{BlobSHA256: ngSHA}},    // gzip.NewReader error
			{Artifact: &crawl.ArtifactRef{BlobSHA256: trSHA}},    // truncated gzip read error
			{Artifact: &crawl.ArtifactRef{BlobSHA256: smallSHA}}, // hydrated!
		},
	}
	s.hydrateArtifacts(&rep)
	if rep.Results[1].Body != "" || rep.Results[2].Body != "" || rep.Results[3].Body != "" || rep.Results[4].Body != "ok" {
		t.Fatalf("unexpected hydrateArtifacts results: %+v", rep.Results)
	}

	// 3. POST /agent/reply error branches
	recRepUnauth := httptest.NewRecorder()
	s.ServeHTTP(recRepUnauth, httptest.NewRequest(http.MethodPost, "/agent/reply", strings.NewReader("{}")))
	if recRepUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 reply, got %d", recRepUnauth.Code)
	}

	reqBadJobHdr := httptest.NewRequest(http.MethodPost, "/agent/reply", strings.NewReader("{}"))
	reqBadJobHdr.Header.Set("Authorization", authHeader)
	reqBadJobHdr.Header.Set("X-Agent-Site", "site-1")
	recBadJobHdr := httptest.NewRecorder()
	s.ServeHTTP(recBadJobHdr, reqBadJobHdr)
	if recBadJobHdr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad_job_headers, got %d", recBadJobHdr.Code)
	}

	seedJob := func(id string) *pendingJob {
		j := &pendingJob{
			jobID:    id,
			jobNonce: "nonce_" + id,
			siteID:   "site-1",
			requests: []crawl.Request{{ID: "r1", URL: "https://example.com/", Kind: classify.KindScrape}},
			doneCh:   make(chan jobOutcome, 1),
		}
		s.mu.Lock()
		s.pending[j.jobID] = j
		s.mu.Unlock()
		return j
	}
	postReply := func(j *pendingJob, body io.Reader, ce string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/agent/reply", body)
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("X-Agent-Site", j.siteID)
		req.Header.Set("X-Job-Id", j.jobID)
		req.Header.Set("X-Job-Nonce", j.jobNonce)
		if ce != "" {
			req.Header.Set("Content-Encoding", ce)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	jErrRead := seedJob("job_rerr")
	if rec := postReply(jErrRead, iotest.ErrReader(errors.New("too big")), ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 too_large, got %d", rec.Code)
	}

	jBadGz := seedJob("job_bgz")
	if rec := postReply(jBadGz, strings.NewReader("not-gzip"), "gzip"); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad_gzip, got %d", rec.Code)
	}

	// Compressed > maxDecodedReplyBytes (32 MiB + 1 byte of zeros)
	var bigBuf bytes.Buffer
	zwBig := gzip.NewWriter(&bigBuf)
	zeros := make([]byte, 1<<20)
	for i := 0; i < 33; i++ {
		_, _ = zwBig.Write(zeros)
	}
	_ = zwBig.Close()
	jBigGz := seedJob("job_biggz")
	if rec := postReply(jBigGz, bytes.NewReader(bigBuf.Bytes()), "gzip"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 decompressed too_large, got %d", rec.Code)
	}

	jBadJSON := seedJob("job_bjson")
	if rec := postReply(jBadJSON, strings.NewReader("{bad"), ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad_reply_json, got %d", rec.Code)
	}

	jMismatch := seedJob("job_mis")
	if rec := postReply(jMismatch, strings.NewReader(`{"results":[]}`), ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 mismatched_result_count, got %d", rec.Code)
	}

	// RetryAfterMs > 120000 clamped to 120000 and unauthorized artifact stripped
	jClamp := seedJob("job_clamp")
	if rec := postReply(jClamp, strings.NewReader(`{"results":[{"id":"wrong","url":"https://evil.example","outcome":"ok","retryAfterMs":999999,"artifact":{"blobSha256":"`+strings.Repeat("b", 64)+`"}}]}`), ""); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 clamp reply, got %d: %s", rec.Code, rec.Body.String())
	}
	outClamp := <-jClamp.doneCh
	if outClamp.reply.Results[0].RetryAfterMs != 120_000 || outClamp.reply.Results[0].Artifact != nil {
		t.Fatalf("expected clamped RetryAfterMs and stripped unauthorized artifact: %+v", outClamp.reply.Results[0])
	}

	// 4. completePending edge cases: missing job, session jobsErr++, invalid URL, OutcomeStop cooldown clearing affinity, full doneCh
	s.completePending("no_such_job", "n", "site-1", jobOutcome{})

	sess := &agentSession{siteID: "site-1", busy: true}
	jErr := &pendingJob{jobID: "job_cp_err", jobNonce: "ncp", siteID: "site-1", session: sess, doneCh: make(chan jobOutcome, 1)}
	s.mu.Lock()
	s.pending[jErr.jobID] = jErr
	s.affinities["bad-cd.example"] = affinityEntry{siteID: "site-1", expiresAt: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	s.completePending(jErr.jobID, jErr.jobNonce, "site-1", jobOutcome{err: errors.New("boom")})
	if sess.jobsErr != 1 || sess.busy {
		t.Fatalf("expected jobsErr=1 and busy=false, got jobsErr=%d busy=%v", sess.jobsErr, sess.busy)
	}

	jStop := &pendingJob{jobID: "job_cp_stop", jobNonce: "ncps", siteID: "site-1", doneCh: make(chan jobOutcome, 1)}
	jStop.doneCh <- jobOutcome{} // pre-fill doneCh to exercise `default:` non-blocking send
	s.mu.Lock()
	s.pending[jStop.jobID] = jStop
	s.mu.Unlock()
	s.completePending(jStop.jobID, jStop.jobNonce, "site-1", jobOutcome{
		reply: crawl.FetchReply{
			Results: []crawl.Result{
				{URL: "://bad-url", Outcome: classify.OutcomeOK},
				{URL: "https://bad-cd.example/p", Outcome: classify.OutcomeStop, RetryAfterMs: 500},
			},
		},
	})
	s.mu.Lock()
	_, affStill := s.affinities["bad-cd.example"]
	_, cdSet := s.cooldowns["site-1|bad-cd.example"]
	s.mu.Unlock()
	if affStill || !cdSet {
		t.Fatalf("expected affinity cleared and cooldown set on OutcomeStop (affStill=%v cdSet=%v)", affStill, cdSet)
	}
}

func TestHubCallerConcurrencyGate503(t *testing.T) {
	inFlight := make(chan struct{})
	release := make(chan struct{})
	rt := hubRTFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/robots.txt") {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		select {
		case inFlight <- struct{}{}:
		default:
		}
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader("<p>ok</p>"))}, nil
	})
	c := crawl.NewCrawler(rt, func(*url.URL) error { return nil }, crawl.DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	defer c.Close()

	s := NewServer(Config{
		CallerToken:        "caller-sem-token-0123456789012",
		FallbackCrawler:    c,
		Allow:              func(*url.URL) error { return nil },
		MaxConcurrentCalls: 1,
	})
	defer s.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	rec1 := httptest.NewRecorder()
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/v1/scrape", strings.NewReader(`{"url":"https://example.com/slow"}`))
		req.Header.Set("Authorization", "Bearer caller-sem-token-0123456789012")
		s.ServeHTTP(rec1, req)
	}()

	<-inFlight
	req2 := httptest.NewRequest(http.MethodPost, "/v1/scrape", strings.NewReader(`{"url":"https://example.com/fast"}`))
	req2.Header.Set("Authorization", "Bearer caller-sem-token-0123456789012")
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusServiceUnavailable || !strings.Contains(rec2.Body.String(), "server_busy") {
		t.Fatalf("expected 503 server_busy, got %d: %s", rec2.Code, rec2.Body.String())
	}

	close(release)
	wg.Wait()
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", rec1.Code)
	}
}

func TestHubPickAgentCapabilitiesLRUStickyAndCooldowns(t *testing.T) {
	s := NewServer(Config{})
	defer func() {
		s.mu.Lock()
		s.agents = map[string]*agentSession{}
		s.mu.Unlock()
		_ = s.Close()
	}()

	now := time.Now()
	s.mu.Lock()
	s.agents["site-http"] = &agentSession{siteID: "site-http", capabilities: []string{"http2"}, lastJobAt: now.Add(-10 * time.Minute)}
	s.agents["site-br-old"] = &agentSession{siteID: "site-br-old", capabilities: []string{"BROWSER-V1"}, lastJobAt: now.Add(-5 * time.Minute)}
	s.agents["site-br-new"] = &agentSession{siteID: "site-br-new", capabilities: []string{"browser-v1"}, lastJobAt: now.Add(-1 * time.Minute)}
	s.cooldowns["site-br-old|cool.example"] = now.Add(-time.Second) // expired -> deleted
	s.cooldowns["site-br-new|cool.example"] = now.Add(time.Minute)  // active -> skipped
	s.affinities["sticky.example"] = affinityEntry{siteID: "site-br-new", expiresAt: now.Add(time.Minute)}
	s.affinities["expired.example"] = affinityEntry{siteID: "site-http", expiresAt: now.Add(-time.Second)}
	s.mu.Unlock()

	// Render request on cool.example: site-http lacks browser-v1, site-br-new cooled down, site-br-old expired cooldown cleaned & picked!
	picked := s.pickAgent("cool.example", "", true, map[string]bool{})
	if picked == nil || picked.siteID != "site-br-old" {
		t.Fatalf("expected site-br-old picked, got %+v", picked)
	}
	picked.mu.Lock()
	picked.busy = false
	picked.mu.Unlock()

	// LRU picks site-br-old over site-br-new for render on fresh.example
	lru := s.pickAgent("fresh.example", "", true, map[string]bool{})
	if lru == nil || lru.siteID != "site-br-old" {
		t.Fatalf("expected LRU site-br-old, got %+v", lru)
	}
	lru.mu.Lock()
	lru.busy = false
	lru.mu.Unlock()

	// Sticky affinity picks site-br-new for sticky.example
	sticky := s.pickAgent("sticky.example", "", false, map[string]bool{})
	if sticky == nil || sticky.siteID != "site-br-new" {
		t.Fatalf("expected sticky site-br-new, got %+v", sticky)
	}
	sticky.mu.Lock()
	sticky.busy = false
	sticky.mu.Unlock()

	// Expired affinity cleaned up when preferredSite == ""
	expPicked := s.pickAgent("expired.example", "", false, map[string]bool{})
	if expPicked == nil {
		t.Fatal("expected agent picked for expired.example")
	}
	expPicked.mu.Lock()
	expPicked.busy = false
	expPicked.mu.Unlock()

	// preferredSite skips mismatches
	pref := s.pickAgent("expired.example", "site-br-old", false, map[string]bool{})
	if pref == nil || pref.siteID != "site-br-old" {
		t.Fatalf("expected preferredSite site-br-old, got %+v", pref)
	}
	s.mu.Lock()
	_, expiredLeft := s.affinities["expired.example"]
	_, expiredCDLeft := s.cooldowns["site-br-old|cool.example"]
	s.mu.Unlock()
	if expiredLeft || expiredCDLeft {
		t.Fatalf("expected expired affinity and cooldown deleted (aff=%v cd=%v)", expiredLeft, expiredCDLeft)
	}
}

func TestHubAgentFailoverPeerHandoffAndTimeouts(t *testing.T) {
	const agentTok = "agent-failover-token-012345678"
	const callerTok = "caller-failover-token-01234567"

	// 1. Peer servers: redirect peer, HTTP 500 peer, OutcomeStop peer, and healthy peer
	redirectPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example/", http.StatusFound)
	}))
	defer redirectPeer.Close()

	err500Peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer err500Peer.Close()

	stopPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, crawl.FetchReply{
			Results: []crawl.Result{{ID: "r1", URL: "https://ex.example/", Outcome: classify.OutcomeStop, RetryAfterMs: 500}},
		})
	}))
	defer stopPeer.Close()

	var peerAccepts atomic.Bool
	healthyPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !peerAccepts.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, crawl.FetchReply{
			Results: []crawl.Result{{ID: "r1", URL: "https://ex.example/", Status: 200, Outcome: classify.OutcomeOK, Markdown: "from-peer", ContentSource: "llms.txt"}},
		})
	}))
	defer healthyPeer.Close()

	// Closed listener to hit client.Do error
	closedPeer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedPeerURL := closedPeer.URL
	closedPeer.Close()

	s := NewServer(Config{
		CallerToken:     callerTok,
		AgentToken:      agentTok,
		DispatchTimeout: 300 * time.Millisecond,
		PeerURLs: []string{
			"",
			"://bad-url",
			"http://non-loopback.example:8787",
			closedPeerURL,
			redirectPeer.URL,
			err500Peer.URL,
			stopPeer.URL,
			healthyPeer.URL,
		},
	})
	defer s.Close()
	srv := httptest.NewServer(s)
	defer srv.Close()

	// No agents + FallbackCrawler==nil + peer healthy -> returns peer:<host>
	peerAccepts.Store(true)
	rep, via, status, err := s.DispatchOrFallback(context.Background(), crawl.FetchCall{
		MaxSeconds: 1,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "auto", "", nil)
	if err != nil || status != http.StatusOK || !strings.HasPrefix(via, "peer:") || len(rep.Results) != 1 {
		t.Fatalf("expected peer handoff success, got via=%q status=%d err=%v", via, status, err)
	}

	// Active peer cooldown on stopPeer + failing healthyPeer -> 503 when FallbackCrawler == nil
	peerAccepts.Store(false)
	_, _, status, err = s.DispatchOrFallback(context.Background(), crawl.FetchCall{
		MaxSeconds: 1,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "auto", "", nil)
	if err == nil || status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no fallback and peers fail, got status=%d err=%v", status, err)
	}

	// Wait for stopPeer 500ms cooldown to expire so expired peer cooldown deletion runs next
	time.Sleep(550 * time.Millisecond)
	peerAccepts.Store(true)
	_, viaCooldownExpired, _, errCooldownExpired := s.DispatchOrFallback(context.Background(), crawl.FetchCall{
		MaxSeconds: 1,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "auto", "", nil)
	if errCooldownExpired != nil || !strings.HasPrefix(viaCooldownExpired, "peer:") {
		t.Fatalf("expected expired peer cooldown cleanup & peer success, got via=%q err=%v", viaCooldownExpired, errCooldownExpired)
	}

	// Connect 2 agents over WS: agent-1 returns OutcomeChallenge -> fails over to agent-2!
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialAgent := func(site string, handler func(jobID, jobNonce string)) *websocket.Conn {
		c, _, dErr := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": {"Bearer " + agentTok}, "X-Agent-Site": {site}},
		})
		if dErr != nil {
			t.Fatalf("dial %s: %v", site, dErr)
		}
		if _, _, rErr := c.Read(ctx); rErr != nil { // hello
			t.Fatalf("read hello %s: %v", site, rErr)
		}
		go func() {
			for {
				_, data, rErr := c.Read(ctx)
				if rErr != nil {
					return
				}
				var msg struct {
					Type     string `json:"type"`
					JobID    string `json:"jobId"`
					JobNonce string `json:"jobNonce"`
				}
				if json.Unmarshal(data, &msg) == nil && msg.Type == "dispatch" {
					handler(msg.JobID, msg.JobNonce)
				}
			}
		}()
		return c
	}
	sendAgentReply := func(site, jobID, jobNonce string, rep crawl.FetchReply) {
		b, _ := json.Marshal(rep)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/agent/reply", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+agentTok)
		req.Header.Set("X-Agent-Site", site)
		req.Header.Set("X-Job-Id", jobID)
		req.Header.Set("X-Job-Nonce", jobNonce)
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
	}

	var mode atomic.Int32 // 0: challenge->ok failover, 1: stop->peer, 2: stop->lastAgentReply, 3: timeout
	c1 := dialAgent("site-1", func(jid, jn string) {
		switch mode.Load() {
		case 0:
			sendAgentReply("site-1", jid, jn, crawl.FetchReply{Results: []crawl.Result{{ID: "r1", URL: "https://ex.example/", Outcome: classify.OutcomeChallenge}}})
		case 1, 2:
			sendAgentReply("site-1", jid, jn, crawl.FetchReply{Results: []crawl.Result{{ID: "r1", URL: "https://ex.example/", Outcome: classify.OutcomeStop}}})
		case 3:
			// do not reply -> dispatchToSession times out!
		}
	})
	defer c1.CloseNow()

	c2 := dialAgent("site-2", func(jid, jn string) {
		switch mode.Load() {
		case 0:
			sendAgentReply("site-2", jid, jn, crawl.FetchReply{Results: []crawl.Result{{ID: "r1", URL: "https://ex.example/", Status: 200, Outcome: classify.OutcomeOK, Markdown: "failover-ok"}}})
		case 1, 2:
			sendAgentReply("site-2", jid, jn, crawl.FetchReply{Results: []crawl.Result{{ID: "r1", URL: "https://ex.example/", Outcome: classify.OutcomeStop}}})
		}
	})
	defer c2.CloseNow()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s.ListAgents()["connected"].(int) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Case 0: site-1 returns Challenge -> automatic failover to site-2
	rep0, via0, _, err0 := s.DispatchOrFallback(ctx, crawl.FetchCall{
		MaxSeconds: 5,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "auto", "", nil)
	if err0 != nil || len(rep0.Results) != 1 || rep0.Results[0].Markdown != "failover-ok" {
		t.Fatalf("expected failover to second agent, got via=%q rep=%+v err=%v", via0, rep0, err0)
	}

	// Clear cooldowns for next case
	s.mu.Lock()
	s.cooldowns = map[string]time.Time{}
	s.mu.Unlock()

	// Case 1: both agents return Stop, healthyPeer succeeds -> peer:<host>
	mode.Store(1)
	peerAccepts.Store(true)
	_, via1, _, err1 := s.DispatchOrFallback(ctx, crawl.FetchCall{
		MaxSeconds: 5,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "auto", "", nil)
	if err1 != nil || !strings.HasPrefix(via1, "peer:") {
		t.Fatalf("expected peer handoff after agent stop, got via=%q err=%v", via1, err1)
	}

	// Case 2: agents return Stop, peer fails -> returns *lastAgentReply
	s.mu.Lock()
	s.cooldowns = map[string]time.Time{}
	s.mu.Unlock()
	mode.Store(2)
	peerAccepts.Store(false)
	rep2, via2, _, err2 := s.DispatchOrFallback(ctx, crawl.FetchCall{
		MaxSeconds: 5,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "auto", "", nil)
	if err2 != nil || !strings.HasPrefix(via2, "agent:") || rep2.Results[0].Outcome != classify.OutcomeStop {
		t.Fatalf("expected lastAgentReply fallback, got via=%q rep=%+v err=%v", via2, rep2, err2)
	}

	// Case 3: dispatchToSession timeout & write failure (closed c2 + preferredSite)
	_ = c2.CloseNow()
	mode.Store(3)
	s.mu.Lock()
	s.cooldowns = map[string]time.Time{}
	// Make site-1 idle & hit DispatchTimeout (80ms)
	if sess1 := s.agents["site-1"]; sess1 != nil {
		sess1.mu.Lock()
		sess1.busy = false
		sess1.mu.Unlock()
	}
	s.mu.Unlock()

	_, _, _, errTimeout := s.DispatchOrFallback(ctx, crawl.FetchCall{
		MaxSeconds: 1,
		Options:    crawl.Options{IncludeBody: true},
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "agent", "site-1", nil)
	if errTimeout == nil {
		t.Fatal("expected dispatch timeout error")
	}

	// Direct dispatchToSession write error on closed conn + non-preferred DispatchOrFallback write error
	closedSess := &agentSession{siteID: "site-closed", conn: c2}
	if _, wErr := s.dispatchToSession(ctx, closedSess, crawl.FetchCall{
		MaxSeconds: 1,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, nil); wErr == nil {
		t.Fatal("expected dispatchToSession write error on closed conn")
	}
	s.mu.Lock()
	s.agents["site-closed"] = closedSess
	s.cooldowns = map[string]time.Time{}
	s.mu.Unlock()
	mode.Store(0)
	_, _, _, errWriteNonPref := s.DispatchOrFallback(ctx, crawl.FetchCall{
		MaxSeconds: 5,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "agent", "", nil)
	_ = errWriteNonPref
	s.mu.Lock()
	delete(s.agents, "site-closed")
	s.mu.Unlock()
	s.mu.Lock()
	if sess2 := s.agents["site-2"]; sess2 != nil {
		sess2.mu.Lock()
		sess2.busy = false
		sess2.mu.Unlock()
	}
	s.mu.Unlock()
	_, _, _, errWritePref := s.DispatchOrFallback(ctx, crawl.FetchCall{
		MaxSeconds: 1,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "agent", "site-2", nil)
	if errWritePref == nil {
		t.Fatal("expected write error on closed preferred agent")
	}

	// Local fallback hits Stop -> tryPeerHandoff succeeds
	stopRT := hubRTFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/robots.txt") {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader("429"))}, nil
	})
	fbStop := crawl.NewCrawler(stopRT, func(*url.URL) error { return nil }, crawl.DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	fbStop.Sleep = func(context.Context, time.Duration) error { return nil }
	defer fbStop.Close()

	sFB := NewServer(Config{
		FallbackCrawler: fbStop,
		Allow:           func(*url.URL) error { return nil },
		PeerURLs:        []string{healthyPeer.URL},
	})
	defer sFB.Close()
	peerAccepts.Store(true)
	_, viaFB, _, errFB := sFB.DispatchOrFallback(ctx, crawl.FetchCall{
		MaxSeconds: 1,
		Requests:   []crawl.Request{{ID: "r1", URL: "https://ex.example/", Kind: classify.KindScrape}},
	}, "container", "", nil)
	if errFB != nil || !strings.HasPrefix(viaFB, "peer:") {
		t.Fatalf("expected local fallback Stop to hand off to peer, got via=%q err=%v", viaFB, errFB)
	}
}

func TestHubCallerFetchScrapeAndMapCoverage(t *testing.T) {
	const callerTok = "caller-endpoints-token-0123456"

	// Mock origin serving dev.to twin JSON, /llms.txt, /sitemap.xml, HTML, and 404
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/api/articles/gopher/writing-fuzz-tests":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"title": "Writing Fuzz Tests",
				"description": "Deep guide to Go fuzzing.",
				"published_timestamp": "2026-01-01T00:00:00Z",
				"user": {"name": "Gopher"},
				"body_markdown": "Alpha fuzz paragraph.\n\nSecond fuzz paragraph with detail and héllo 世界!"
			}`))
		case "/api/articles/gopher/utf8-twin":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"title": "T",
				"user": {"name": "Gopher"},
				"body_markdown": "éééééééééééééééééééé"
			}`))
		case "/llms.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("# Docs\n- [Guide](https://docs.example.com/guide)\n- [Blocked](http://127.0.0.1/blocked)\n- [Mail](mailto:bad@example.com)\n"))
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<urlset><url><loc>https://docs.example.com/api</loc></url><url><loc>https://docs.example.com/api</loc></url></urlset>`))
		case "/not-found":
			w.WriteHeader(http.StatusNotFound)
		case "/utf8":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><body><main><p>Héllo 世界 from EdgeFetch!</p><a href="https://docs.example.com/blog">Blog</a></main></body></html>`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><body><main><a href="https://docs.example.com/blog">Blog</a></main></body></html>`))
		}
	}))
	defer origin.Close()

	originAddr := origin.Listener.Addr().String()
	tlsCfg := origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsCfg.ServerName = "example.com"
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}
	allowHTTPSOnly := func(u *url.URL) error {
		if u.Scheme != "https" || u.Hostname() == "127.0.0.1" {
			return errors.New("disallowed")
		}
		return nil
	}
	crawler := crawl.NewCrawler(tr, allowHTTPSOnly, crawl.DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	crawler.Sleep = func(context.Context, time.Duration) error { return nil }
	defer crawler.Close()

	s := NewServer(Config{
		CallerToken:     callerTok,
		FallbackCrawler: crawler,
		Allow:           allowHTTPSOnly,
	})
	defer s.Close()

	doAuthPost := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+callerTok)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	// POST /fetch errors
	if rec := doAuthPost("/fetch?target=bogus", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad_target, got %d", rec.Code)
	}
	if rec := doAuthPost("/fetch?site=BAD!", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad_site, got %d", rec.Code)
	}
	if rec := doAuthPost("/fetch", `{bad`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad_json, got %d", rec.Code)
	}
	if rec := doAuthPost("/fetch", `{"requests":[]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 empty requests, got %d", rec.Code)
	}

	// executeScrape direct call without TraceContext in ctx + missing/bad URL
	if _, _, st := s.executeScrape(context.Background(), scrapePayload{}, nil); st != http.StatusBadRequest {
		t.Fatalf("expected 400 missing_url, got %d", st)
	}
	if _, _, st := s.executeScrape(context.Background(), scrapePayload{URL: "http://127.0.0.1/"}, nil); st != http.StatusBadRequest {
		t.Fatalf("expected 400 bad_url, got %d", st)
	}

	// Scrape formats (string + object screenshot), actions, waitFor, onlyMainContent=false
	_, _, _ = s.executeScrape(context.Background(), scrapePayload{
		URL:             "https://docs.example.com/utf8",
		Formats:         []any{"screenshot", map[string]any{"type": "screenshot"}},
		OnlyMainContent: crawl.Bool(false),
		WaitFor:         10,
		Actions:         []browser.InteractAction{{Type: "wait", WaitMs: 1}},
	}, nil)
	// Standard KindScrape with multi-byte UTF-8 maxChars=2 (cuts mid-'é')
	outScrape, _, stScrape := s.executeScrape(context.Background(), scrapePayload{
		URL:      "https://docs.example.com/utf8",
		MaxChars: 2,
	}, nil)
	if stScrape != http.StatusOK || len(outScrape["markdown"].(string)) > 2 {
		t.Fatalf("unexpected executeScrape with maxChars: status=%d out=%+v", stScrape, outScrape)
	}
	// RenderMode="always" without Actions
	_, _, _ = s.executeScrape(context.Background(), scrapePayload{
		URL:        "https://docs.example.com/utf8",
		RenderMode: "always",
	}, nil)

	// Twin hit with query + maxChars AND without query + mid-rune UTF-8 maxChars (hits !utf8.RuneStart for odd/even byte alignments)
	if rec := doAuthPost("/v1/scrape", `{"url":"https://dev.to/gopher/writing-fuzz-tests","query":"fuzz","maxChars":80}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"twin:dev-to"`) || !strings.Contains(rec.Body.String(), `"author":"Gopher"`) {
		t.Fatalf("expected twin hit with query (%d): %s", rec.Code, rec.Body.String())
	}
	for _, mc := range []string{"15", "16"} {
		if rec := doAuthPost("/v1/scrape", `{"url":"https://dev.to/gopher/utf8-twin","maxChars":`+mc+`}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"twin:dev-to"`) {
			t.Fatalf("expected twin hit with utf-8 maxChars=%s (%d): %s", mc, rec.Code, rec.Body.String())
		}
	}

	// Twin DispatchOrFallback error + scrape DispatchOrFallback error (target="agent" with no agents)
	if rec := doAuthPost("/v1/scrape", `{"url":"https://dev.to/gopher/writing-fuzz-tests","target":"agent"}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when target=agent has no agents, got %d: %s", rec.Code, rec.Body.String())
	}

	// Empty reply & ContentSource from mock peer
	emptyPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "/cs") {
			writeJSON(w, http.StatusOK, crawl.FetchReply{Results: []crawl.Result{{ID: "scrape-1", URL: "https://docs.example.com/cs", Status: 200, Outcome: classify.OutcomeOK, ContentSource: "llms.txt"}}})
			return
		}
		writeJSON(w, http.StatusOK, crawl.FetchReply{Results: []crawl.Result{}})
	}))
	defer emptyPeer.Close()
	sPeerOnly := NewServer(Config{Allow: allowHTTPSOnly, PeerURLs: []string{emptyPeer.URL}})
	defer sPeerOnly.Close()

	if _, _, st := sPeerOnly.executeScrape(context.Background(), scrapePayload{URL: "https://docs.example.com/"}, nil); st != http.StatusBadGateway {
		t.Fatalf("expected 502 empty_reply, got %d", st)
	}
	outCS, _, stCS := sPeerOnly.executeScrape(context.Background(), scrapePayload{URL: "https://docs.example.com/cs"}, nil)
	if stCS != http.StatusOK || outCS["contentSource"] != "llms.txt" {
		t.Fatalf("expected contentSource=llms.txt, got st=%d out=%+v", stCS, outCS)
	}

	// /v2/scrape & /compat/firecrawl/v2/scrape error & ok branches
	if rec := doAuthPost("/v2/scrape", `{bad`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on /v2/scrape bad JSON, got %d", rec.Code)
	}
	if rec := doAuthPost("/compat/firecrawl/v2/scrape", `{}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"success":false`) {
		t.Fatalf("expected 400 success=false on /v2/scrape missing url, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doAuthPost("/v2/scrape", `{"url":"https://docs.example.com/not-found"}`); !strings.Contains(rec.Body.String(), `"success":false`) {
		t.Fatalf("expected success=false on 404 origin: %s", rec.Body.String())
	}

	// /v1/map, /v2/map, /compat/firecrawl/v2/map
	if rec := doAuthPost("/v1/map", `{bad`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 map bad_json, got %d", rec.Code)
	}
	if rec := doAuthPost("/v1/map", `{"url":"http://127.0.0.1/"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 map invalid_url, got %d", rec.Code)
	}
	if rec := doAuthPost("/v1/map", `{"url":"https://docs.example.com/","target":"agent"}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 map target=agent with no agents, got %d", rec.Code)
	}
	recMapV1 := doAuthPost("/v1/map", `{"url":"https://docs.example.com/","limit":0,"search":"api"}`)
	if recMapV1.Code != http.StatusOK || !strings.Contains(recMapV1.Body.String(), `"https://docs.example.com/api"`) || strings.Contains(recMapV1.Body.String(), "guide") {
		t.Fatalf("unexpected /v1/map filtered output (%d): %s", recMapV1.Code, recMapV1.Body.String())
	}
	recMapV2 := doAuthPost("/compat/firecrawl/v2/map", `{"url":"https://docs.example.com/","limit":2}`)
	if recMapV2.Code != http.StatusOK || !strings.Contains(recMapV2.Body.String(), `"success":true`) {
		t.Fatalf("unexpected /compat/firecrawl/v2/map output (%d): %s", recMapV2.Code, recMapV2.Body.String())
	}
}

func TestHubMCPMethodsAndErrorBranches(t *testing.T) {
	const callerTok = "caller-mcp-secret-token-012345"

	rt := hubRTFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/robots.txt"):
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		case strings.HasSuffix(r.URL.Path, "/404"):
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		default:
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader("<main><p>MCP OK</p></main>"))}, nil
		}
	})
	crawler := crawl.NewCrawler(rt, func(*url.URL) error { return nil }, crawl.DefaultUserAgent, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	crawler.Sleep = func(context.Context, time.Duration) error { return nil }
	defer crawler.Close()

	// Peer returning OutcomeGone with empty Problem to exercise "scrape failed" fallback in MCP scrape
	stopEmptyProblemPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, crawl.FetchReply{Results: []crawl.Result{{ID: "scrape-1", URL: "https://ex.example/gone", Outcome: classify.OutcomeGone}}})
	}))
	defer stopEmptyProblemPeer.Close()

	s := NewServer(Config{
		CallerToken:     callerTok,
		FallbackCrawler: crawler,
		Allow: func(u *url.URL) error {
			if u.Scheme != "https" {
				return errors.New("https only")
			}
			return nil
		},
	})
	defer s.Close()

	doMCP := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+callerTok)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		if rec := doMCP(m, ""); rec.Code != http.StatusMethodNotAllowed || rec.Body.Len() != 0 {
			t.Fatalf("expected 405 empty body for %s /mcp, got %d %q", m, rec.Code, rec.Body.String())
		}
	}
	if rec := doMCP(http.MethodPut, ""); rec.Code != http.StatusMethodNotAllowed || !strings.Contains(rec.Body.String(), "method_not_allowed") {
		t.Fatalf("expected 405 JSON for PUT /mcp, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doMCP(http.MethodPost, `{bad`); !strings.Contains(rec.Body.String(), "-32700") {
		t.Fatalf("expected -32700 parse error: %s", rec.Body.String())
	}
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for notification, got %d", rec.Code)
	}
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"result":{}`) {
		t.Fatalf("expected ping {}, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`); !strings.Contains(rec.Body.String(), "-32601") {
		t.Fatalf("expected -32601 Method not found: %s", rec.Body.String())
	}
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":123}`); !strings.Contains(rec.Body.String(), "-32602") {
		t.Fatalf("expected -32602 Invalid params: %s", rec.Body.String())
	}

	// MCP scrape errors: 404 (problem != "") and missing URL (out["error"])
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"https://ex.example/404"}}}`); !strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Fatalf("expected isError:true for 404 scrape: %s", rec.Body.String())
	}
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"scrape","arguments":{}}}`); !strings.Contains(rec.Body.String(), "missing_url") {
		t.Fatalf("expected missing_url error: %s", rec.Body.String())
	}

	// Peer-only server for "scrape failed" (OutcomeStop with empty problem)
	sPeer := NewServer(Config{
		CallerToken: callerTok,
		Allow:       func(*url.URL) error { return nil },
		PeerURLs:    []string{stopEmptyProblemPeer.URL},
	})
	defer sPeer.Close()
	reqStop := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"https://ex.example/stop"}}}`))
	reqStop.Header.Set("Authorization", "Bearer "+callerTok)
	recStop := httptest.NewRecorder()
	sPeer.ServeHTTP(recStop, reqStop)
	if !strings.Contains(recStop.Body.String(), `"isError":true`) {
		t.Fatalf("expected isError:true for stop empty problem: %s", recStop.Body.String())
	}

	// MCP fetch_url: invalid URL, target="agent" no agents, valid kind="scrape"
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"http://insecure.example/"}}}`); !strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Fatalf("expected ValidateCall error on fetch_url: %s", rec.Body.String())
	}
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://ex.example/ok","target":"agent"}}}`); !strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Fatalf("expected DispatchOrFallback error on fetch_url target=agent: %s", rec.Body.String())
	}
	if rec := doMCP(http.MethodPost, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://ex.example/ok","kind":"scrape"}}}`); !strings.Contains(rec.Body.String(), `"isError":false`) {
		t.Fatalf("expected fetch_url success: %s", rec.Body.String())
	}
}
