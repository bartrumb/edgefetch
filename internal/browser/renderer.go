package browser

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

// ErrChallengeDetected is returned when a rendered DOM contains a CAPTCHA or anti-bot challenge;
// EdgeFetch halts immediately and never attempts to solve, click through, or wait out challenges.
var ErrChallengeDetected = errors.New("anti-bot challenge detected in rendered DOM")

const (
	defaultRenderSettleMs = 900
	maxRenderSettleMs     = 15_000
	sessionIdleTTL        = 3 * time.Minute
	browserIdleTTL        = 3 * time.Minute
	maxActiveSessions     = 8
	maxRenderedDOMChars   = 16 << 20 // 16 MiB cap in JS prevents >24 MiB CDP frames from dropping shared connection
)

// InteractAction describes a single deterministic browser interaction step (`firecrawl_interact` & `/scrape` inline `actions` parity).
type InteractAction struct {
	Type         string `json:"type"`                   // "click", "fill", "type", "write", "press", "wait", "scroll", "select", "navigate", "screenshot", "scrape", "executeJavascript", "pdf"
	Selector     string `json:"selector,omitempty"`     // CSS selector for click/fill/type/select/scroll/wait
	All          bool   `json:"all,omitempty"`          // Click every element matching Selector when true
	Value        string `json:"value,omitempty"`        // Input value for fill/type/select/write
	Text         string `json:"text,omitempty"`         // Alias for Value on write/type
	Key          string `json:"key,omitempty"`          // Key name for press (e.g. "Enter", "Tab", "Escape")
	Direction    string `json:"direction,omitempty"`    // "down" (default) or "up" for scroll
	Script       string `json:"script,omitempty"`       // JS snippet for executeJavascript
	FullPage     bool   `json:"fullPage,omitempty"`     // Full-page capture for screenshot action
	URL          string `json:"url,omitempty"`          // HTTPS target for navigate
	WaitMs       int    `json:"waitMs,omitempty"`       // Milliseconds to pause after or during "wait"
	Milliseconds int    `json:"milliseconds,omitempty"` // Firecrawl alias for WaitMs
}

// ActionScrapeSnapshot records a mid-sequence DOM snapshot captured by a `{ "type": "scrape" }` action.
type ActionScrapeSnapshot struct {
	URL  string `json:"url"`
	HTML string `json:"html"`
}

// ActionJSReturn records the return value of an `{ "type": "executeJavascript" }` action.
type ActionJSReturn struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// Task describes a browser render or interaction request.
type Task struct {
	URL                string
	UserAgent          string
	AcceptLanguage     string
	Headers            map[string]string
	Mobile             bool
	ViewportWidth      int
	ViewportHeight     int
	WaitForMs          int
	WaitSelector       string
	Screenshot         bool
	ScreenshotFullPage bool
	ScreenshotQuality  int
	Actions            []InteractAction
	SessionID          string // Optional existing session to resume
	KeepSession        bool   // Retain tab open for follow-up `interact` calls
	CloseSession       bool   // Close `SessionID` immediately after or without running actions
}

// Output holds the rendered DOM, HTTP metadata, screenshot, action outputs, and optional session handle.
type Output struct {
	Status            int
	Headers           http.Header
	FinalURL          string
	HTML              string
	ScreenshotBase64  string
	ActionScreenshots []string
	ActionScrapes     []ActionScrapeSnapshot
	JavascriptReturns []ActionJSReturn
	PDFBase64         string
	SessionID         string
}

type retainedSession struct {
	mu               sync.Mutex
	id               string
	browserContextID string
	targetID         string
	cdpSessionID     string
	initialHost      string
	lastCheckedURL   string
	hasExtraHeaders  bool
	lastUsed         time.Time
	lastStatus       int
	lastHeaders      http.Header
}

func (s *retainedSession) getLastCheckedURL() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCheckedURL
}

func (s *retainedSession) setLastCheckedURL(u string) {
	if s == nil || u == "" {
		return
	}
	s.mu.Lock()
	s.lastCheckedURL = u
	s.mu.Unlock()
}

func (s *retainedSession) setResponseMeta(status int, hdrs http.Header) {
	s.mu.Lock()
	if status > 0 {
		s.lastStatus = status
		s.lastHeaders = hdrs
	}
	s.mu.Unlock()
}

func (s *retainedSession) snapshotResponseMeta() (int, http.Header) {
	s.mu.Lock()
	st := s.lastStatus
	hdrs := s.lastHeaders.Clone()
	s.mu.Unlock()
	return st, hdrs
}

// FindChromeBinary locates an installed headless Chromium/Chrome/Edge/Brave executable across Linux, macOS, and Windows,
// enabling a ~8 MB desktop binary download to render JavaScript (`browser-v1` + `interact-v1`) using pre-installed OS browsers.
func FindChromeBinary() string {
	if custom := strings.TrimSpace(os.Getenv("EDGEFETCH_CHROME_BIN")); custom != "" {
		if p, err := exec.LookPath(custom); err == nil {
			return p
		}
		if st, err := os.Stat(custom); err == nil && !st.IsDir() {
			return custom
		}
	}
	for _, candidate := range []string{
		"chromium-browser",
		"chromium",
		"google-chrome-stable",
		"google-chrome",
		"msedge",
		"brave-browser",
		"brave",
	} {
		if p, err := exec.LookPath(candidate); err == nil {
			return p
		}
	}

	switch runtime.GOOS {
	case "windows":
		var roots []string
		for _, envKey := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if dir := strings.TrimSpace(os.Getenv(envKey)); dir != "" {
				roots = append(roots, dir)
			}
		}
		relPaths := []string{
			filepath.Join("Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join("Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join("BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			filepath.Join("Chromium", "Application", "chrome.exe"),
		}
		for _, r := range roots {
			for _, rel := range relPaths {
				cand := filepath.Join(r, rel)
				if st, err := os.Stat(cand); err == nil && !st.IsDir() {
					return cand
				}
			}
		}
	case "darwin":
		home, _ := os.UserHomeDir()
		appRoots := []string{"/Applications"}
		if home != "" {
			appRoots = append(appRoots, filepath.Join(home, "Applications"))
		}
		appBins := []string{
			"Google Chrome.app/Contents/MacOS/Google Chrome",
			"Chromium.app/Contents/MacOS/Chromium",
			"Brave Browser.app/Contents/MacOS/Brave Browser",
			"Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		}
		for _, r := range appRoots {
			for _, rel := range appBins {
				cand := filepath.Join(r, rel)
				if st, err := os.Stat(cand); err == nil && !st.IsDir() {
					return cand
				}
			}
		}
	}
	return ""
}

// Renderer manages a shared headless Chromium process + SSRF-safe loopback CONNECT proxy.
type Renderer struct {
	chromeBin   string
	allow       func(*url.URL) error
	CheckRobots func(ctx context.Context, rawURL string) error
	userAgent   string
	log         *slog.Logger
	sem         chan struct{}

	// Optional hook allowing unit tests to attach a mock CDP WebSocket URL without spawning OS Chromium.
	dialOverrideWS string

	mu          sync.Mutex
	proxy       *SSRFProxy
	cmd         *exec.Cmd
	userDataDir string
	cdp         *cdpConn
	sessions    map[string]*retainedSession
	activeRuns  int
	lastUsedAt  time.Time
	closed      bool
}

// NewRenderer constructs a Renderer bounded to `maxConcurrent` simultaneous tabs (default 2).
func NewRenderer(chromeBin string, allow func(*url.URL) error, userAgent string, maxConcurrent int, log *slog.Logger) *Renderer {
	if maxConcurrent <= 0 {
		maxConcurrent = 2
	}
	if maxConcurrent > 4 {
		maxConcurrent = 4
	}
	if chromeBin == "" {
		chromeBin = FindChromeBinary()
	}
	r := &Renderer{
		chromeBin: chromeBin,
		allow:     allow,
		userAgent: userAgent,
		log:       log,
		sem:       make(chan struct{}, maxConcurrent),
		sessions:  make(map[string]*retainedSession),
	}
	return r
}

// NewMockRenderer creates a Renderer backed by an in-memory/loopback CDP WebSocket URL for deterministic unit tests.
func NewMockRenderer(wsURL string, allow func(*url.URL) error, userAgent string) *Renderer {
	r := NewRenderer("", allow, userAgent, 2, nil)
	r.dialOverrideWS = wsURL
	return r
}

// Available reports whether a headless browser binary (or test override) is available.
func (r *Renderer) Available() bool {
	return r != nil && (r.chromeBin != "" || r.dialOverrideWS != "")
}

// CloseSession terminates a retained `interact` browser session immediately (`interact_stop`).
func (r *Renderer) CloseSession(ctx context.Context, sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false
	}
	r.mu.Lock()
	sess, ok := r.sessions[sessionID]
	if ok {
		delete(r.sessions, sessionID)
	}
	cdp := r.cdp
	r.mu.Unlock()
	if !ok {
		return false
	}
	if cdp != nil && !cdp.isClosed() {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = cdp.call(cctx, "", "Target.closeTarget", map[string]any{"targetId": sess.targetID}, nil)
		_ = cdp.call(cctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": sess.browserContextID}, nil)
		cancel()
	}
	return true
}

// Execute runs a stateless page render or stateful multi-step `interact` turn inside an isolated incognito context.
func (r *Renderer) Execute(ctx context.Context, task Task) (out Output, retErr error) {
	if task.CloseSession && task.URL == "" && len(task.Actions) == 0 {
		_ = r.CloseSession(ctx, task.SessionID)
		return Output{SessionID: task.SessionID, Status: http.StatusOK}, nil
	}
	if !r.Available() {
		return Output{}, ErrBrowserUnavailable
	}

	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return Output{}, ctx.Err()
	}

	r.mu.Lock()
	r.activeRuns++
	r.lastUsedAt = time.Now()
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if r.activeRuns > 0 {
			r.activeRuns--
		}
		r.lastUsedAt = time.Now()
		r.mu.Unlock()
	}()

	cdp, err := r.ensureBrowser(ctx)
	if err != nil {
		return Output{}, err
	}
	r.reapExpiredSessions(ctx, cdp)

	var (
		sess    *retainedSession
		resumed bool
	)
	if task.SessionID != "" {
		r.mu.Lock()
		if existing, ok := r.sessions[task.SessionID]; ok {
			existing.lastUsed = time.Now()
			sess = existing
			resumed = true
		}
		r.mu.Unlock()
		// Reject unknown caller-supplied session IDs rather than accepting attacker-chosen handles.
		if !resumed {
			return Output{}, fmt.Errorf("unknown or expired browser session %q", task.SessionID)
		}
	}

	if sess == nil {
		var bcOut struct {
			BrowserContextID string `json:"browserContextId"`
		}
		if err := cdp.call(ctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": !task.KeepSession}, &bcOut); err != nil {
			return Output{}, fmt.Errorf("create browser context: %w", err)
		}

		vpWidth := task.ViewportWidth
		vpHeight := task.ViewportHeight
		if vpWidth <= 0 {
			if task.Mobile {
				vpWidth = 390
			} else {
				vpWidth = 1366
			}
		}
		if vpHeight <= 0 {
			if task.Mobile {
				vpHeight = 844
			} else {
				vpHeight = 900
			}
		}

		var tgtOut struct {
			TargetID string `json:"targetId"`
		}
		if err := cdp.call(ctx, "", "Target.createTarget", map[string]any{
			"url":              "about:blank",
			"browserContextId": bcOut.BrowserContextID,
			"width":            vpWidth,
			"height":           vpHeight,
		}, &tgtOut); err != nil {
			_ = cdp.call(context.Background(), "", "Target.disposeBrowserContext", map[string]any{"browserContextId": bcOut.BrowserContextID}, nil)
			return Output{}, fmt.Errorf("create target: %w", err)
		}

		var attOut struct {
			SessionID string `json:"sessionId"`
		}
		if err := cdp.call(ctx, "", "Target.attachToTarget", map[string]any{
			"targetId": tgtOut.TargetID,
			"flatten":  true,
		}, &attOut); err != nil {
			_ = cdp.call(context.Background(), "", "Target.closeTarget", map[string]any{"targetId": tgtOut.TargetID}, nil)
			_ = cdp.call(context.Background(), "", "Target.disposeBrowserContext", map[string]any{"browserContextId": bcOut.BrowserContextID}, nil)
			return Output{}, fmt.Errorf("attach target: %w", err)
		}

		sid := randomSessionID()
		initHost := ""
		if task.URL != "" {
			if parsedInit, pErr := url.Parse(task.URL); pErr == nil {
				initHost = strings.ToLower(parsedInit.Hostname())
			}
		}
		sess = &retainedSession{
			id:               sid,
			browserContextID: bcOut.BrowserContextID,
			targetID:         tgtOut.TargetID,
			cdpSessionID:     attOut.SessionID,
			initialHost:      initHost,
			hasExtraHeaders:  len(task.Headers) > 0,
			lastUsed:         time.Now(),
			lastStatus:       http.StatusOK,
			lastHeaders:      make(http.Header),
		}

		_ = cdp.call(ctx, sess.cdpSessionID, "Page.enable", nil, nil)
		_ = cdp.call(ctx, sess.cdpSessionID, "Network.enable", nil, nil)
		_ = cdp.call(ctx, sess.cdpSessionID, "Runtime.enable", nil, nil)

		if task.Mobile || task.ViewportWidth > 0 || task.ViewportHeight > 0 {
			scale := 1.0
			if task.Mobile {
				scale = 2.0
			}
			_ = cdp.call(ctx, sess.cdpSessionID, "Emulation.setDeviceMetricsOverride", map[string]any{
				"width":             vpWidth,
				"height":            vpHeight,
				"deviceScaleFactor": scale,
				"mobile":            task.Mobile,
			}, nil)
		}

		ua := strings.TrimSpace(task.UserAgent)
		if ua == "" {
			ua = r.userAgent
		}
		acceptLang := strings.TrimSpace(task.AcceptLanguage)
		if acceptLang == "" {
			acceptLang = "en-US,en;q=0.9"
		}
		if ua != "" {
			_ = cdp.call(ctx, sess.cdpSessionID, "Network.setUserAgentOverride", map[string]any{
				"userAgent":      ua,
				"acceptLanguage": acceptLang,
			}, nil)
		}
		if len(task.Headers) > 0 {
			_ = cdp.call(ctx, sess.cdpSessionID, "Network.setExtraHTTPHeaders", map[string]any{
				"headers": task.Headers,
			}, nil)
		}
	}

	cleanupOnExit := !task.KeepSession || task.CloseSession
	defer func() {
		if retErr != nil && !resumed {
			cleanupOnExit = true
		}
		if cleanupOnExit {
			r.mu.Lock()
			delete(r.sessions, sess.id)
			r.mu.Unlock()
			cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = cdp.call(cctx, "", "Target.closeTarget", map[string]any{"targetId": sess.targetID}, nil)
			_ = cdp.call(cctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": sess.browserContextID}, nil)
			cancel()
		} else {
			r.mu.Lock()
			if len(r.sessions) >= maxActiveSessions {
				r.evictOldestSessionLocked(cdp)
			}
			sess.lastUsed = time.Now()
			r.sessions[sess.id] = sess
			r.mu.Unlock()
		}
	}()

	events, unsub := cdp.subscribe()
	defer unsub()

	if task.URL != "" {
		u, err := url.Parse(task.URL)
		if err != nil {
			return Output{}, err
		}
		if r.allow != nil {
			if err := r.allow(u); err != nil {
				return Output{}, err
			}
		}
		if r.CheckRobots != nil {
			if err := r.CheckRobots(ctx, u.String()); err != nil {
				return Output{}, err
			}
		}
		sess.setLastCheckedURL(u.String())
		status, hdrs, err := navigateAndWait(ctx, cdp, sess, events, task.URL, task.WaitForMs, task.WaitSelector)
		clearExtraHTTPHeaders(ctx, cdp, sess)
		if err != nil {
			return Output{}, err
		}
		sess.setResponseMeta(status, hdrs)
		if preHTML, preURL, rErr := readDocumentHTML(ctx, cdp, sess.cdpSessionID); rErr == nil {
			if vErr := r.validateFinalURL(ctx, sess, preURL, task.URL); vErr != nil {
				return Output{}, vErr
			}
			if why := extract.DetectRenderedChallenge(preHTML); why != "" {
				st, hClone := sess.snapshotResponseMeta()
				return Output{Status: st, Headers: hClone}, fmt.Errorf("%w: %s", ErrChallengeDetected, why)
			}
		}
	}

	var (
		actionScreenshots []string
		actionScrapes     []ActionScrapeSnapshot
		jsReturns         []ActionJSReturn
		pdfBase64         string
	)
	for i, act := range task.Actions {
		if err := r.runAction(ctx, cdp, sess, events, act, &actionScreenshots, &actionScrapes, &jsReturns, &pdfBase64); err != nil {
			return Output{}, fmt.Errorf("interact action %d (%s): %w", i, act.Type, err)
		}
	}

	htmlStr, finalURL, err := readDocumentHTML(ctx, cdp, sess.cdpSessionID)
	if err != nil {
		return Output{}, err
	}
	if vErr := r.validateFinalURL(ctx, sess, finalURL, task.URL); vErr != nil {
		return Output{}, vErr
	}
	for i := range actionScrapes {
		if vErr := r.validateFinalURL(ctx, sess, actionScrapes[i].URL, task.URL); vErr != nil {
			return Output{}, vErr
		}
	}
	st, hClone := sess.snapshotResponseMeta()
	if why := extract.DetectRenderedChallenge(htmlStr); why != "" {
		return Output{Status: st, Headers: hClone, FinalURL: finalURL}, fmt.Errorf("%w: %s", ErrChallengeDetected, why)
	}

	var shotB64 string
	if task.Screenshot {
		var shot struct {
			Data string `json:"data"`
		}
		shotFormat := "png"
		shotParams := map[string]any{"format": shotFormat}
		if task.ScreenshotQuality > 0 && task.ScreenshotQuality < 100 {
			shotParams["format"] = "jpeg"
			shotParams["quality"] = task.ScreenshotQuality
		}
		if task.ScreenshotFullPage {
			shotParams["captureBeyondViewport"] = true
		}
		if sErr := cdp.call(ctx, sess.cdpSessionID, "Page.captureScreenshot", shotParams, &shot); sErr == nil {
			shotB64 = shot.Data
		}
	}

	out = Output{
		Status:            st,
		Headers:           hClone,
		FinalURL:          finalURL,
		HTML:              htmlStr,
		ScreenshotBase64:  shotB64,
		ActionScreenshots: actionScreenshots,
		ActionScrapes:     actionScrapes,
		JavascriptReturns: jsReturns,
		PDFBase64:         pdfBase64,
	}
	if task.KeepSession && !task.CloseSession {
		out.SessionID = sess.id
	}
	return out, nil
}

func clearExtraHTTPHeaders(ctx context.Context, cdp *cdpConn, sess *retainedSession) {
	if sess == nil {
		return
	}
	sess.mu.Lock()
	if !sess.hasExtraHeaders {
		sess.mu.Unlock()
		return
	}
	sess.hasExtraHeaders = false
	cdpSID := sess.cdpSessionID
	sess.mu.Unlock()

	cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if ctx != nil && ctx.Err() == nil {
		cancel()
		cctx, cancel = context.WithTimeout(ctx, 2*time.Second)
	}
	_ = cdp.call(cctx, cdpSID, "Network.setExtraHTTPHeaders", map[string]any{"headers": map[string]string{}}, nil)
	cancel()
}

func navigateAndWait(
	ctx context.Context,
	cdp *cdpConn,
	sess *retainedSession,
	events <-chan cdpEvent,
	targetURL string,
	waitForMs int,
	waitSelector string,
) (int, http.Header, error) {
	sessionID := ""
	if sess != nil {
		sessionID = sess.cdpSessionID
	}
	var navOut struct {
		FrameID   string `json:"frameId"`
		ErrorText string `json:"errorText,omitempty"`
	}
	if err := cdp.call(ctx, sessionID, "Page.navigate", map[string]any{"url": targetURL}, &navOut); err != nil {
		return 0, nil, err
	}
	if navOut.ErrorText != "" {
		return 0, nil, fmt.Errorf("navigation failed: %s", navOut.ErrorText)
	}

	status := 0
	hdrs := make(http.Header)
	hdrs.Set("Content-Type", "text/html; charset=utf-8")
	inFlight := make(map[string]time.Time)

	handleNetEvent := func(ev cdpEvent) (loadFired bool) {
		if ev.SessionID != sessionID {
			return false
		}
		switch ev.Method {
		case "Network.requestWillBeSent":
			var rw struct {
				RequestID string `json:"requestId"`
				Type      string `json:"type"`
				Request   struct {
					URL string `json:"url"`
				} `json:"request"`
			}
			if json.Unmarshal(ev.Params, &rw) == nil {
				if sess != nil && sess.initialHost != "" && rw.Request.URL != "" {
					if reqU, uErr := url.Parse(rw.Request.URL); uErr == nil && reqU.Hostname() != "" && !strings.EqualFold(reqU.Hostname(), sess.initialHost) {
						clearExtraHTTPHeaders(ctx, cdp, sess)
					}
				}
				if rw.RequestID != "" {
					// Track SPA data & code requests; ignore long-lived streaming/beacon types (WebSocket, EventSource, Media, Ping).
					switch rw.Type {
					case "Document", "XHR", "Fetch", "Script":
						inFlight[rw.RequestID] = time.Now()
					}
				}
			}
		case "Network.loadingFinished", "Network.loadingFailed":
			var lf struct {
				RequestID string `json:"requestId"`
			}
			if json.Unmarshal(ev.Params, &lf) == nil && lf.RequestID != "" {
				delete(inFlight, lf.RequestID)
			}
		case "Network.responseReceived":
			var rr struct {
				RequestID string `json:"requestId"`
				Type      string `json:"type"`
				FrameID   string `json:"frameId"`
				Response  struct {
					Status  int               `json:"status"`
					Headers map[string]string `json:"headers"`
				} `json:"response"`
			}
			if json.Unmarshal(ev.Params, &rr) == nil {
				if rr.Type == "Document" && (navOut.FrameID == "" || rr.FrameID == navOut.FrameID) && rr.Response.Status > 0 {
					status = rr.Response.Status
					for k, v := range rr.Response.Headers {
						hdrs.Set(k, v)
					}
				}
			}
		case "Page.loadEventFired":
			return true
		}
		return false
	}

	loadWait := time.NewTimer(15 * time.Second)
	defer loadWait.Stop()
	loaded := false
	for !loaded {
		select {
		case ev := <-events:
			if handleNetEvent(ev) {
				loaded = true
			}
		case <-cdp.closeCh:
			return 0, nil, cdp.crashError("during Page.navigate")
		case <-loadWait.C:
			loaded = true
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
	}

	if waitSelector != "" {
		_ = waitForCSSSelector(ctx, cdp, sessionID, waitSelector, 8*time.Second)
	}

	// SPA Network-Idle + Lazy-Scroll + DOM Mutation Quiescence:
	// Trigger IntersectionObserver / lazy-loaded SPA sections and wait for active XHR/Fetch calls to drain.
	explicitWait := waitForMs > 0
	settle := waitForMs
	if settle <= 0 {
		settle = defaultRenderSettleMs
	}
	if settle > maxRenderSettleMs {
		settle = maxRenderSettleMs
	}

	maxIdleBudget := time.Duration(settle) * time.Millisecond
	if maxIdleBudget < 3500*time.Millisecond {
		maxIdleBudget = 3500 * time.Millisecond
	}
	quietWindow := 400 * time.Millisecond
	if explicitWait && time.Duration(settle)*time.Millisecond < quietWindow {
		quietWindow = time.Duration(settle) * time.Millisecond
	}

	idleDeadline := time.Now().Add(maxIdleBudget)
	minFloor := time.Now().Add(time.Duration(settle) * time.Millisecond)
	if !explicitWait {
		minFloor = time.Now().Add(350 * time.Millisecond)
	}
	idleSince := time.Time{}
	if len(inFlight) == 0 {
		idleSince = time.Now()
	}

	pollTick := time.NewTicker(50 * time.Millisecond)
	for {
		now := time.Now()
		for id, started := range inFlight {
			if now.Sub(started) > 8*time.Second {
				delete(inFlight, id)
			}
		}
		if len(inFlight) == 0 {
			if idleSince.IsZero() {
				idleSince = now
			}
			if !now.Before(minFloor) && now.Sub(idleSince) >= quietWindow {
				break
			}
		} else {
			idleSince = time.Time{}
		}
		if !now.Before(idleDeadline) {
			break
		}
		select {
		case ev := <-events:
			_ = handleNetEvent(ev)
			if len(inFlight) > 0 {
				idleSince = time.Time{}
			}
		case <-pollTick.C:
		case <-cdp.closeCh:
			pollTick.Stop()
			return 0, nil, cdp.crashError("during SPA network-idle wait")
		case <-ctx.Done():
			pollTick.Stop()
			return 0, nil, ctx.Err()
		}
	}
	pollTick.Stop()

	// Trigger lazy IntersectionObserver cards and wait briefly for client-side DOM hydration mutations to settle.
	if !explicitWait || waitForMs >= 250 {
		_ = waitForSPADOMQuiescence(ctx, cdp, sessionID)
	}

	if status == 0 {
		status = http.StatusOK
	}
	return status, hdrs, nil
}

func waitForCSSSelector(ctx context.Context, cdp *cdpConn, sessionID, selector string, maxWait time.Duration) error {
	selJSON, _ := json.Marshal(selector)
	expr := fmt.Sprintf(`Boolean(document.querySelector(%s))`, string(selJSON))
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		ok, err := evalBool(ctx, cdp, sessionID, expr)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		t := time.NewTimer(150 * time.Millisecond)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
	return fmt.Errorf("selector %q did not appear within %s", selector, maxWait)
}

func (r *Renderer) runAction(
	ctx context.Context,
	cdp *cdpConn,
	sess *retainedSession,
	events <-chan cdpEvent,
	act InteractAction,
	actionScreenshots *[]string,
	actionScrapes *[]ActionScrapeSnapshot,
	jsReturns *[]ActionJSReturn,
	pdfBase64 *string,
) error {
	kind := strings.ToLower(strings.TrimSpace(act.Type))
	selJSON, _ := json.Marshal(act.Selector)
	effectiveVal := act.Value
	if effectiveVal == "" && act.Text != "" {
		effectiveVal = act.Text
	}
	valJSON, _ := json.Marshal(effectiveVal)
	effectiveWaitMs := act.WaitMs
	if effectiveWaitMs <= 0 && act.Milliseconds > 0 {
		effectiveWaitMs = act.Milliseconds
	}

	switch kind {
	case "wait":
		ms := effectiveWaitMs
		if ms <= 0 {
			ms = 500
		}
		if ms > maxRenderSettleMs {
			ms = maxRenderSettleMs
		}
		if act.Selector != "" {
			return waitForCSSSelector(ctx, cdp, sess.cdpSessionID, act.Selector, time.Duration(ms)*time.Millisecond)
		}
		t := time.NewTimer(time.Duration(ms) * time.Millisecond)
		defer t.Stop()
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}

	case "navigate":
		u, err := url.Parse(strings.TrimSpace(act.URL))
		if err != nil {
			return err
		}
		if r.allow != nil {
			if err := r.allow(u); err != nil {
				return err
			}
		}
		if r.CheckRobots != nil {
			if err := r.CheckRobots(ctx, u.String()); err != nil {
				return err
			}
		}
		sess.setLastCheckedURL(u.String())
		if sess.initialHost == "" || !strings.EqualFold(u.Hostname(), sess.initialHost) {
			clearExtraHTTPHeaders(ctx, cdp, sess)
		}
		st, hdrs, err := navigateAndWait(ctx, cdp, sess, events, u.String(), effectiveWaitMs, act.Selector)
		clearExtraHTTPHeaders(ctx, cdp, sess)
		if err != nil {
			return err
		}
		sess.setResponseMeta(st, hdrs)
		return nil

	case "click":
		if strings.TrimSpace(act.Selector) == "" {
			return errors.New("click action requires selector")
		}
		var js string
		if act.All {
			js = fmt.Sprintf(`(() => {
				const els = document.querySelectorAll(%s);
				if (!els || els.length === 0) return "selector_not_found";
				els.forEach((el) => { try { el.scrollIntoView({ block: "center" }); el.click(); } catch {} });
				return "ok";
			})()`, string(selJSON))
		} else {
			js = fmt.Sprintf(`(() => {
				const el = document.querySelector(%s);
				if (!el) return "selector_not_found";
				el.scrollIntoView({ block: "center" });
				el.click();
				return "ok";
			})()`, string(selJSON))
		}
		res, err := evalString(ctx, cdp, sess.cdpSessionID, js)
		if err != nil {
			return err
		}
		if res != "ok" {
			return fmt.Errorf("click %s: %s", act.Selector, res)
		}

	case "write":
		if effectiveVal != "" {
			if err := cdp.call(ctx, sess.cdpSessionID, "Input.insertText", map[string]any{"text": effectiveVal}, nil); err != nil {
				return err
			}
		}

	case "fill", "type", "select":
		if strings.TrimSpace(act.Selector) == "" {
			return fmt.Errorf("%s action requires selector", kind)
		}
		js := fmt.Sprintf(`(() => {
			const el = document.querySelector(%s);
			if (!el) return "selector_not_found";
			el.focus();
			const val = %s;
			const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
			if (setter) setter.call(el, val); else el.value = val;
			el.dispatchEvent(new Event("input", { bubbles: true }));
			el.dispatchEvent(new Event("change", { bubbles: true }));
			return "ok";
		})()`, string(selJSON), string(valJSON))
		res, err := evalString(ctx, cdp, sess.cdpSessionID, js)
		if err != nil {
			return err
		}
		if res != "ok" {
			return fmt.Errorf("%s %s: %s", kind, act.Selector, res)
		}

	case "press":
		key := strings.TrimSpace(act.Key)
		if key == "" {
			key = "Enter"
		}
		_ = cdp.call(ctx, sess.cdpSessionID, "Input.dispatchKeyEvent", map[string]any{"type": "keyDown", "key": key}, nil)
		_ = cdp.call(ctx, sess.cdpSessionID, "Input.dispatchKeyEvent", map[string]any{"type": "keyUp", "key": key}, nil)

	case "scroll":
		dirSign := 1
		if strings.EqualFold(strings.TrimSpace(act.Direction), "up") {
			dirSign = -1
		}
		if strings.TrimSpace(act.Selector) != "" {
			_, _ = evalString(ctx, cdp, sess.cdpSessionID, fmt.Sprintf(`(() => { document.querySelector(%s)?.scrollIntoView({ behavior: "instant", block: "center" }); return "ok"; })()`, string(selJSON)))
		} else {
			_, _ = evalString(ctx, cdp, sess.cdpSessionID, fmt.Sprintf(`(() => { window.scrollBy(0, %d * (window.innerHeight || 800)); return "ok"; })()`, dirSign))
		}

	case "screenshot":
		var shot struct {
			Data string `json:"data"`
		}
		shotParams := map[string]any{"format": "png"}
		if act.FullPage {
			shotParams["captureBeyondViewport"] = true
		}
		if err := cdp.call(ctx, sess.cdpSessionID, "Page.captureScreenshot", shotParams, &shot); err != nil {
			return err
		}
		if shot.Data != "" && actionScreenshots != nil {
			*actionScreenshots = append(*actionScreenshots, shot.Data)
		}

	case "scrape":
		snapHTML, snapURL, err := readDocumentHTML(ctx, cdp, sess.cdpSessionID)
		if err != nil {
			return err
		}
		if actionScrapes != nil {
			*actionScrapes = append(*actionScrapes, ActionScrapeSnapshot{URL: snapURL, HTML: snapHTML})
		}

	case "executejavascript":
		script := strings.TrimSpace(act.Script)
		if script == "" {
			script = strings.TrimSpace(effectiveVal)
		}
		if script == "" {
			return errors.New("executeJavascript action requires script")
		}
		var evalRes struct {
			Result struct {
				Type  string `json:"type"`
				Value any    `json:"value"`
			} `json:"result"`
			ExceptionDetails *struct {
				Text string `json:"text"`
			} `json:"exceptionDetails,omitempty"`
		}
		if err := cdp.call(ctx, sess.cdpSessionID, "Runtime.evaluate", map[string]any{
			"expression":    script,
			"returnByValue": true,
			"awaitPromise":  true,
		}, &evalRes); err != nil {
			return err
		}
		if evalRes.ExceptionDetails != nil {
			return fmt.Errorf("js exception: %s", evalRes.ExceptionDetails.Text)
		}
		if jsReturns != nil {
			*jsReturns = append(*jsReturns, ActionJSReturn{Type: evalRes.Result.Type, Value: evalRes.Result.Value})
		}

	case "pdf":
		var pdfOut struct {
			Data string `json:"data"`
		}
		if err := cdp.call(ctx, sess.cdpSessionID, "Page.printToPDF", map[string]any{"printBackground": true}, &pdfOut); err != nil {
			return err
		}
		if pdfBase64 != nil && pdfOut.Data != "" {
			*pdfBase64 = pdfOut.Data
		}

	default:
		return fmt.Errorf("unsupported interact action type %q", act.Type)
	}

	pause := effectiveWaitMs
	if pause <= 0 {
		pause = 250
	}
	if pause > 5_000 {
		pause = 5_000
	}
	t := time.NewTimer(time.Duration(pause) * time.Millisecond)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitForSPADOMQuiescence(ctx context.Context, cdp *cdpConn, sessionID string) error {
	js := `new Promise((resolve) => {
		try {
			const h = window.innerHeight || 800;
			window.scrollTo(0, h);
			setTimeout(() => { try { window.scrollTo(0, h * 2); } catch {} }, 80);
			setTimeout(() => { try { window.scrollTo(0, 0); } catch {} }, 160);
			const wordCount = () => ((document.body && document.body.innerText) || "").trim().split(/\s+/).filter(Boolean).length;
			const isPlaceholder = () => /^(loading|please wait|just a moment)\b/i.test(((document.body && document.body.innerText) || "").trim());
			let lastMut = Date.now();
			const start = lastMut;
			const obs = new MutationObserver(() => { lastMut = Date.now(); });
			if (document.documentElement) {
				obs.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
			}
			const check = () => {
				const now = Date.now();
				const elapsed = now - start;
				const quiet = now - lastMut;
				const words = wordCount();
				if (elapsed >= 2400 || (words >= 45 && !isPlaceholder() && quiet >= 260 && elapsed >= 180) || (quiet >= 600 && elapsed >= 220)) {
					obs.disconnect();
					resolve(true);
					return;
				}
				setTimeout(check, 90);
			};
			setTimeout(check, 180);
		} catch {
			resolve(true);
		}
	})`
	var res struct {
		Result struct {
			Value bool `json:"value"`
		} `json:"result"`
	}
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return cdp.call(qctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    js,
		"returnByValue": true,
		"awaitPromise":  true,
	}, &res)
}

func readDocumentHTML(ctx context.Context, cdp *cdpConn, sessionID string) (htmlStr, finalURL string, err error) {
	// Serialize full DOM including open Web Component shadowRoot trees (`getHTML({ serializableShadowRoots: true })`
	// or light-DOM shadow flattening fallback) so Shadow-DOM SPAs (Lit, Stencil, LWC, Shoelace) extract cleanly.
	expr := `(() => {
		const root = document.documentElement;
		if (!root) return JSON.stringify({ url: String(location.href || ""), html: "" });
		let html = "";
		try {
			let hasShadow = false;
			const walkCheck = (el) => {
				if (hasShadow || !el) return;
				if (el.shadowRoot) { hasShadow = true; return; }
				for (let c = el.firstElementChild; c; c = c.nextElementSibling) walkCheck(c);
			};
			walkCheck(root);
			if (!hasShadow) {
				html = root.outerHTML;
			} else {
				const cloneWithShadow = (node) => {
					if (node.nodeType === Node.TEXT_NODE) return document.createTextNode(node.nodeValue || "");
					if (node.nodeType !== Node.ELEMENT_NODE) return null;
					const tag = node.tagName.toLowerCase();
					if (tag === "script" || tag === "style") return node.cloneNode(true);
					const copy = node.cloneNode(false);
					if (tag === "details") copy.setAttribute("open", "");
					if (node.shadowRoot) {
						const wrapper = document.createElement("div");
						wrapper.setAttribute("data-shadow-root", "open");
						for (const sc of node.shadowRoot.childNodes) {
							const c = cloneWithShadow(sc);
							if (c) wrapper.appendChild(c);
						}
						copy.appendChild(wrapper);
					}
					for (const ch of node.childNodes) {
						const c = cloneWithShadow(ch);
						if (c) copy.appendChild(c);
					}
					return copy;
				};
				const cloned = cloneWithShadow(root);
				html = cloned ? cloned.outerHTML : root.outerHTML;
			}
		} catch {
			html = root.outerHTML;
		}
		if (html && html.length > 16777216) {
			return JSON.stringify({ url: String(location.href || ""), html: "", oversized: html.length });
		}
		return JSON.stringify({ url: String(location.href || ""), html });
	})()`
	raw, err := evalString(ctx, cdp, sessionID, expr)
	if err != nil {
		return "", "", err
	}
	var payload struct {
		URL       string `json:"url"`
		HTML      string `json:"html"`
		Oversized int    `json:"oversized,omitempty"`
	}
	if uErr := json.Unmarshal([]byte(raw), &payload); uErr != nil {
		return raw, "", nil
	}
	if payload.Oversized > 0 || len(payload.HTML) > maxRenderedDOMChars {
		return "", payload.URL, fmt.Errorf("rendered DOM exceeds %d byte safety cap", maxRenderedDOMChars)
	}
	return payload.HTML, payload.URL, nil
}

func (r *Renderer) validateFinalURL(ctx context.Context, sess *retainedSession, finalURL, initialURL string) error {
	trimmed := strings.TrimSpace(finalURL)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "chrome-error://") {
		return errors.New("browser navigation blocked or failed (chrome-error)")
	}
	if strings.EqualFold(trimmed, "about:blank") {
		if initialURL != "" {
			return errors.New("browser remained on about:blank after navigation")
		}
		return nil
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("invalid rendered final URL: %w", err)
	}
	if r.allow != nil {
		if err := r.allow(u); err != nil {
			return fmt.Errorf("rendered final URL blocked by SSRF policy (%s): %w", u.Redacted(), err)
		}
	}
	prevChecked := sess.getLastCheckedURL()
	if r.CheckRobots != nil && trimmed != initialURL && trimmed != prevChecked {
		if err := r.CheckRobots(ctx, u.String()); err != nil {
			return fmt.Errorf("rendered final URL disallowed by robots.txt: %w", err)
		}
		sess.setLastCheckedURL(u.String())
	}
	return nil
}

func buildSanitizedChildEnv(userDir string) []string {
	tmpDir := os.TempDir()
	allowKeys := []string{
		"PATH",
		"LANG",
		"LC_ALL",
		"FONTCONFIG_PATH",
		"FONTCONFIG_FILE",
		"TZ",
		"SYSTEMROOT",
		"SystemRoot",
		"WINDIR",
		"windir",
		"COMSPEC",
		"ComSpec",
		"PATHEXT",
		"PROGRAMFILES",
		"ProgramFiles",
		"PROGRAMFILES(X86)",
		"ProgramFiles(x86)",
		"LOCALAPPDATA",
		"LocalAppData",
		"APPDATA",
		"USERPROFILE",
	}
	seen := make(map[string]bool, len(allowKeys)+4)
	env := make([]string, 0, len(allowKeys)+4)
	for _, k := range allowKeys {
		upper := strings.ToUpper(k)
		if seen[upper] {
			continue
		}
		if v := os.Getenv(k); v != "" {
			seen[upper] = true
			env = append(env, k+"="+v)
		}
	}
	if !seen["PATH"] {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	home := userDir
	if home == "" {
		home = tmpDir
	}
	env = append(env,
		"HOME="+home,
		"TMPDIR="+tmpDir,
		"TEMP="+tmpDir,
		"TMP="+tmpDir,
	)
	return env
}

func evalString(ctx context.Context, cdp *cdpConn, sessionID, expr string) (string, error) {
	var res struct {
		Result struct {
			Type  string `json:"type"`
			Value any    `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails,omitempty"`
	}
	if err := cdp.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": true,
		"awaitPromise":  true,
	}, &res); err != nil {
		return "", err
	}
	if res.ExceptionDetails != nil {
		return "", errors.New("js exception: " + res.ExceptionDetails.Text)
	}
	if s, ok := res.Result.Value.(string); ok {
		return s, nil
	}
	b, _ := json.Marshal(res.Result.Value)
	return string(b), nil
}

func evalBool(ctx context.Context, cdp *cdpConn, sessionID, expr string) (bool, error) {
	var res struct {
		Result struct {
			Value bool `json:"value"`
		} `json:"result"`
	}
	if err := cdp.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": true,
	}, &res); err != nil {
		return false, err
	}
	return res.Result.Value, nil
}

func buildChromiumLaunchArgs(proxyAddr, userDir string) []string {
	args := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-setuid-sandbox",
		"--disable-gpu-sandbox",
		"--disable-dev-shm-usage",
		"--disable-crash-reporter",
		"--disable-breakpad",
		"--disable-extensions",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-translate",
		"--disable-default-apps",
		"--disable-quic",
		"--disable-features=TranslateUI",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--enforce-webrtc-ip-permission-check",
		"--autoplay-policy=user-gesture-required",
		"--mute-audio",
		"--no-first-run",
		"--no-default-browser-check",
		"--hide-scrollbars",
		"--remote-debugging-address=127.0.0.1",
		"--remote-debugging-port=0",
		"--proxy-server=http://" + proxyAddr,
		"--proxy-bypass-list=<-loopback>",
		"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
		"--user-data-dir=" + userDir,
	}
	if runtime.GOOS == "linux" {
		args = append(args,
			"--use-gl=angle",
			"--use-angle=swiftshader",
			"--enable-unsafe-swiftshader",
			"--ignore-gpu-blocklist",
		)
	} else {
		args = append(args, "--disable-gpu")
	}
	args = append(args, "about:blank")
	return args
}

func (r *Renderer) ensureBrowser(ctx context.Context) (*cdpConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("renderer closed")
	}
	if r.cdp != nil && !r.cdp.isClosed() {
		return r.cdp, nil
	}
	r.shutdownLocked()

	if r.dialOverrideWS != "" {
		conn, err := dialCDP(ctx, r.dialOverrideWS)
		if err != nil {
			return nil, err
		}
		r.cdp = conn
		return conn, nil
	}

	proxy, err := NewSSRFProxy(r.allow, nil)
	if err != nil {
		return nil, err
	}
	userDir, err := os.MkdirTemp("", "edgefetch-chrome-*")
	if err != nil {
		_ = proxy.Close()
		return nil, err
	}

	args := buildChromiumLaunchArgs(proxy.Addr(), userDir)

	cmd := exec.Command(r.chromeBin, args...)
	cmd.Env = buildSanitizedChildEnv(userDir)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = proxy.Close()
		_ = os.RemoveAll(userDir)
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = proxy.Close()
		_ = os.RemoveAll(userDir)
		return nil, fmt.Errorf("start chromium: %w", err)
	}

	var (
		connHolder   atomic.Pointer[cdpConn]
		earlyCrashMu sync.Mutex
		earlyCrash   string
	)
	wsCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		reason := ""
		for sc.Scan() {
			line := sc.Text()
			if idx := strings.Index(line, "ws://127.0.0.1:"); idx >= 0 {
				wsCh <- strings.TrimSpace(line[idx:])
				// Continue draining stderr and capture any post-startup FATAL/crash line for CDP error reporting.
				// If sc.Scan() stops early on a line >64 KiB, drain the remainder via io.Copy so Chromium never blocks!
				for sc.Scan() {
					txt := sc.Text()
					if c := connHolder.Load(); c != nil {
						c.setCrashReason(txt)
					} else {
						earlyCrashMu.Lock()
						earlyCrash = startupReason(earlyCrash, txt)
						earlyCrashMu.Unlock()
					}
				}
				_, _ = io.Copy(io.Discard, stderr)
				return
			}
			reason = startupReason(reason, line)
		}
		_, _ = io.Copy(io.Discard, stderr)
		msg := "chromium exited before advertising DevTools ws://127.0.0.1 endpoint"
		if reason != "" {
			msg += ": " + reason
		}
		errCh <- errors.New(msg)
	}()

	var wsURL string
	startTimer := time.NewTimer(15 * time.Second)
	defer startTimer.Stop()
	select {
	case wsURL = <-wsCh:
	case e := <-errCh:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = proxy.Close()
		_ = os.RemoveAll(userDir)
		return nil, e
	case <-startTimer.C:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = proxy.Close()
		_ = os.RemoveAll(userDir)
		return nil, errors.New("timed out waiting for chromium DevTools endpoint")
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = proxy.Close()
		_ = os.RemoveAll(userDir)
		return nil, ctx.Err()
	}

	conn, err := dialCDP(ctx, wsURL)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = proxy.Close()
		_ = os.RemoveAll(userDir)
		return nil, fmt.Errorf("dial chromium cdp: %w", err)
	}
	earlyCrashMu.Lock()
	if earlyCrash != "" {
		conn.setCrashReason(earlyCrash)
	}
	earlyCrashMu.Unlock()
	connHolder.Store(conn)

	r.proxy = proxy
	r.cmd = cmd
	r.userDataDir = userDir
	r.cdp = conn
	r.lastUsedAt = time.Now()
	if r.log != nil {
		r.log.Info("browser_started", slog.String("bin", r.chromeBin), slog.String("proxy", proxy.Addr()))
	}
	go r.idleReaperLoop(conn)
	return conn, nil
}

func (r *Renderer) idleReaperLoop(target *cdpConn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-target.closeCh:
			return
		case <-ticker.C:
			r.mu.Lock()
			if r.closed || r.cdp != target {
				r.mu.Unlock()
				return
			}
			now := time.Now()
			for id, s := range r.sessions {
				if now.Sub(s.lastUsed) > sessionIdleTTL {
					delete(r.sessions, id)
				}
			}
			if r.activeRuns == 0 && len(r.sessions) == 0 && now.Sub(r.lastUsedAt) >= browserIdleTTL {
				if r.log != nil {
					r.log.Info("browser_idle_shutdown", slog.Duration("idle", now.Sub(r.lastUsedAt)))
				}
				r.shutdownLocked()
				r.mu.Unlock()
				return
			}
			r.mu.Unlock()
		}
	}
}

func (r *Renderer) reapExpiredSessions(ctx context.Context, cdp *cdpConn) {
	now := time.Now()
	var expired []*retainedSession
	r.mu.Lock()
	for id, s := range r.sessions {
		if now.Sub(s.lastUsed) > sessionIdleTTL {
			expired = append(expired, s)
			delete(r.sessions, id)
		}
	}
	r.mu.Unlock()
	for _, s := range expired {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_ = cdp.call(cctx, "", "Target.closeTarget", map[string]any{"targetId": s.targetID}, nil)
		_ = cdp.call(cctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": s.browserContextID}, nil)
		cancel()
	}
}

func (r *Renderer) evictOldestSessionLocked(cdp *cdpConn) {
	var oldest *retainedSession
	for _, s := range r.sessions {
		if oldest == nil || s.lastUsed.Before(oldest.lastUsed) {
			oldest = s
		}
	}
	if oldest != nil {
		delete(r.sessions, oldest.id)
		go func(s *retainedSession) {
			cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = cdp.call(cctx, "", "Target.closeTarget", map[string]any{"targetId": s.targetID}, nil)
			_ = cdp.call(cctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": s.browserContextID}, nil)
			cancel()
		}(oldest)
	}
}

func (r *Renderer) shutdownLocked() {
	r.sessions = make(map[string]*retainedSession)
	if r.cdp != nil {
		_ = r.cdp.close()
		r.cdp = nil
	}
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
		_ = r.cmd.Wait()
		r.cmd = nil
	}
	if r.proxy != nil {
		_ = r.proxy.Close()
		r.proxy = nil
	}
	if r.userDataDir != "" {
		_ = os.RemoveAll(r.userDataDir)
		r.userDataDir = ""
	}
}

// Close terminates any active Chromium subprocess, loopback SSRF proxy, and temporary profile directory.
func (r *Renderer) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.shutdownLocked()
	return nil
}

func randomSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "efsess_" + hex.EncodeToString(b[:])
}

// startupReason keeps the most useful stderr line from a Chromium that failed to start: its last FATAL line, else its
// last line. Chromium logs many harmless errors (no D-Bus, no Vulkan) first, so a FATAL line wins once seen.
func startupReason(current, line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return current
	}
	if len(line) > 300 {
		line = line[:300]
	}
	if strings.Contains(line, ":FATAL:") {
		return line
	}
	if strings.Contains(current, ":FATAL:") {
		return current
	}
	return line
}
