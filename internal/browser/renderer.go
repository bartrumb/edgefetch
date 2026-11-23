package browser

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

// ErrChallengeDetected is returned when a rendered DOM contains a CAPTCHA or anti-bot challenge;
// EdgeFetch halts immediately and never attempts to solve, click through, or wait out challenges.
var ErrChallengeDetected = errors.New("anti-bot challenge detected in rendered DOM")

const (
	defaultRenderSettleMs  = 900
	maxRenderSettleMs      = 15_000
	sessionIdleTTL         = 3 * time.Minute
	browserIdleTTL         = 3 * time.Minute
	maxActiveSessions      = 8
	maxRenderedDOMChars    = 16 << 20 // 16 MiB cap in JS prevents >24 MiB CDP frames from dropping shared connection
	maxSessionFrameEntries = 256      // hard cap on per-session frame maps (frameOrigins, childFrames, frameTainted)
	maxSessionNetEntries   = 512      // hard cap on per-session network/request provenance maps
)

var (
	idleReaperInterval       = 30 * time.Second
	navLoadTimeout           = 15 * time.Second
	actionNavWatchWindow     = 400 * time.Millisecond
	actionNavLoadTimeout     = 10 * time.Second
	enterSubmitFallbackDelay = 50 * time.Millisecond
	staleInFlightTTL         = 8 * time.Second
	minIdleBudget            = 3500 * time.Millisecond
	readProcFile             = os.ReadFile
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

// ActionResult records per-step outcome diagnostics for browser `interact` actions.
type ActionResult struct {
	Index      int    `json:"index"`
	Type       string `json:"type"`
	Status     string `json:"status"` // "ok" or "no_effect"
	URLChanged bool   `json:"urlChanged"`
	DOMChanged bool   `json:"domChanged"`
	FinalURL   string `json:"finalUrl,omitempty"`
	Warning    string `json:"warning,omitempty"`
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
	ActionResults     []ActionResult
	PDFBase64         string
	SessionID         string
}

type fetchHeaderEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type retainedSession struct {
	mu                    sync.Mutex
	id                    string
	browserContextID      string
	targetID              string
	cdpSessionID          string
	mainFrameID           string
	frameOrigins          map[string]string // frameId -> canonical committed origin (bounded <= 256; evicted on detach & cleared on main commit)
	childFrames           map[string]string // frameId -> parentFrameId (non-empty for every child/grandchild frame; bounded <= 256)
	frameTainted          map[string]bool   // frameId -> true once tainted (reset ONLY when new top-level document commits on mainFrameID)
	taintedNetReqs        map[string]bool   // Network.RequestId -> true when documentURL/initiator is non-bound (blob:, data:, about:, cross-origin)
	reqLoaderIDs          map[string]string // Network.RequestId -> loaderId from Network.requestWillBeSent
	scriptInitiatedReqs   map[string]bool   // Network.RequestId -> true when initiated by script/non-harness context
	sawUninjectedSubdoc   bool              // true once any non-harness Document load or child frame occurred
	hasCommittedDoc       bool              // true once a document committed on mainFrameID (or session was resumed from an earlier step)
	committedLoaderID     string            // loaderId of the currently committed top-level document on mainFrameID
	committedDocURL       string            // canonical fragment-stripped URL of the currently committed top-level document
	staleStepDocURLs      map[string]bool   // retired committedDocURLs from prior session steps (blocks late pagehide/unload beacons)
	reqDocURLs            map[string]string // Network.RequestId -> fragment-stripped documentURL from Network.requestWillBeSent
	pendingNavLoaderID    string            // loaderId of the in-flight harness Page.navigate before commit
	pendingStepHeaders    map[string]string // staged next-step headers promoted to extraHeaders ONLY when Page.frameNavigated commits
	pendingNavCrossOrigin bool              // true if the in-flight harness navigation took a cross-origin redirect before commit
	awaitingHarnessDocNav bool              // true ONLY between expectHarnessNavigation and that single top-level Document requestPaused
	awaitingHarnessCommit bool              // true ONLY between expectHarnessNavigation and that single top-level Page.frameNavigated commit
	harnessNavURL         string            // URL the harness passed to Page.navigate and has not yet seen paused
	navChainReqID         string            // Fetch requestId of the harness navigation (follows same-origin HTTP 3xx redirects)
	injectedReqs          map[string]bool   // Fetch requestIds that received the task headers (redirect-chain provenance)
	initialOrigin         string
	redirectedCrossOrigin bool
	lastCheckedURL        string
	hasExtraHeaders       bool
	extraHeaders          map[string]string
	fetchEnabled          bool
	stopFetchOnce         sync.Once
	stopFetchCh           chan struct{}
	lastUsed              time.Time
	lastStatus            int
	lastHeaders           http.Header
}

func canonicalURLOrigin(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "https" && scheme != "http" {
		return ""
	}
	host := politeness.CanonicalHost(u.Hostname())
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(u.Port())
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	} else {
		pNum, pErr := strconv.Atoi(port)
		if pErr != nil || pNum < 1 || pNum > 65535 {
			return ""
		}
		port = strconv.Itoa(pNum)
	}
	return scheme + "://" + host + ":" + port
}

func (s *retainedSession) stopFetch() {
	if s == nil {
		return
	}
	s.mu.Lock()
	ch := s.stopFetchCh
	s.mu.Unlock()
	if ch != nil {
		s.stopFetchOnce.Do(func() {
			close(ch)
		})
	}
}

func mergeCDPRequestHeaders(existing map[string]any, extra map[string]string) []fetchHeaderEntry {
	overrideLower := make(map[string]bool, len(extra))
	extraKeys := make([]string, 0, len(extra))
	for k := range extra {
		tk := strings.TrimSpace(k)
		if tk == "" {
			continue
		}
		overrideLower[strings.ToLower(tk)] = true
		extraKeys = append(extraKeys, k)
	}
	sort.Strings(extraKeys)

	existingKeys := make([]string, 0, len(existing))
	for k := range existing {
		if overrideLower[strings.ToLower(strings.TrimSpace(k))] {
			continue
		}
		existingKeys = append(existingKeys, k)
	}
	sort.Strings(existingKeys)

	out := make([]fetchHeaderEntry, 0, len(existingKeys)+len(extraKeys))
	for _, k := range existingKeys {
		v, ok := existing[k]
		if !ok || v == nil {
			continue
		}
		if sv, isStr := v.(string); isStr {
			out = append(out, fetchHeaderEntry{Name: k, Value: sv})
		} else {
			out = append(out, fetchHeaderEntry{Name: k, Value: fmt.Sprint(v)})
		}
	}
	for _, k := range extraKeys {
		out = append(out, fetchHeaderEntry{Name: strings.TrimSpace(k), Value: extra[k]})
	}
	return out
}

func stripURLFragment(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return s
}

func (s *retainedSession) enableOriginScopedHeaders(ctx context.Context, cdp *cdpConn, hdrs map[string]string, stageUntilNavCommit ...bool) error {
	if s == nil || len(hdrs) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(hdrs))
	for k, v := range hdrs {
		if tk := strings.TrimSpace(k); tk != "" {
			cloned[tk] = v
		}
	}
	if len(cloned) == 0 {
		return nil
	}

	s.mu.Lock()
	if len(stageUntilNavCommit) > 0 && stageUntilNavCommit[0] && s.hasCommittedDoc {
		s.pendingStepHeaders = cloned
	} else {
		s.extraHeaders = cloned
		s.pendingStepHeaders = nil
	}
	s.hasExtraHeaders = true
	needEnable := !s.fetchEnabled
	if needEnable {
		s.fetchEnabled = true
		s.stopFetchCh = make(chan struct{})
	}
	stopCh := s.stopFetchCh
	cdpSID := s.cdpSessionID
	s.mu.Unlock()

	if !needEnable {
		return nil
	}

	fetchEvents, fetchUnsub := cdp.subscribe()
	go func() {
		defer fetchUnsub()
		for {
			select {
			case <-stopCh:
				return
			case <-cdp.closeCh:
				return
			case ev := <-fetchEvents:
				if ev.SessionID != cdpSID {
					continue
				}
				switch ev.Method {
				case "Page.frameAttached":
					s.noteFrameAttached(ev.Params)
				case "Page.frameNavigated":
					s.noteFrameNavigated(ev.Params)
				case "Page.frameDetached":
					s.noteFrameDetached(ev.Params)
				case "Page.downloadWillBegin":
					s.noteDownloadWillBegin(ev.Params)
				case "Network.requestWillBeSent":
					s.noteNetworkRequestWillBeSent(ev.Params)
				case "Network.responseReceived":
					s.noteNetworkResponseReceived(ev.Params)
				case "Network.loadingFailed":
					s.noteNetworkLoadingFailed(ev.Params)
				case "Fetch.requestPaused":
					s.handleRequestPaused(cdp, ev.Params)
				}
			}
		}
	}()

	if err := cdp.call(ctx, cdpSID, "Fetch.enable", map[string]any{
		"patterns": []map[string]any{{"urlPattern": "*"}},
	}, nil); err != nil {
		s.stopFetch()
		return fmt.Errorf("enable origin-scoped Fetch interception: %w", err)
	}
	s.seedFrameTree(ctx, cdp)
	return nil
}

// hasPositiveSameOriginProof requires at least one of Origin or Referer to be explicitly present and match initOrigin,
// and rejects immediately if either Origin or Referer is "null" or belongs to any other origin.
// Note: Sec-Fetch-* headers are intentionally NOT consulted because CDP Fetch.requestPaused fires before
// Chromium's network service populates Fetch Metadata headers.
func hasPositiveSameOriginProof(hdrs map[string]any, initOrigin string) bool {
	if initOrigin == "" || len(hdrs) == 0 {
		return false
	}
	proven := false
	for k, rawV := range hdrs {
		if rawV == nil {
			continue
		}
		val := strings.TrimSpace(fmt.Sprint(rawV))
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "origin", "referer":
			if val == "" {
				continue
			}
			if strings.EqualFold(val, "null") || canonicalURLOrigin(val) != initOrigin {
				return false
			}
			proven = true
		}
	}
	return proven
}

func sameNavigationURL(a, b string) bool {
	strip := func(s string) string {
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		return s
	}
	a, b = strip(a), strip(b)
	if a == b {
		return true
	}
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil || canonicalURLOrigin(a) == "" || canonicalURLOrigin(a) != canonicalURLOrigin(b) {
		return false
	}
	pa, pb := ua.Path, ub.Path
	if pa == "" {
		pa = "/"
	}
	if pb == "" {
		pb = "/"
	}
	return pa == pb && ua.Query().Encode() == ub.Query().Encode()
}

func hasNonEmptyRefererHeader(hdrs map[string]any) bool {
	for k, rawV := range hdrs {
		if rawV == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "referer") && strings.TrimSpace(fmt.Sprint(rawV)) != "" {
			return true
		}
	}
	return false
}

func (s *retainedSession) setFrameOriginLocked(frameID, origin string) {
	if frameID == "" {
		return
	}
	if s.frameOrigins == nil {
		s.frameOrigins = make(map[string]string)
	}
	if _, exists := s.frameOrigins[frameID]; !exists && len(s.frameOrigins) >= maxSessionFrameEntries {
		for k := range s.frameOrigins {
			if k != s.mainFrameID {
				delete(s.frameOrigins, k)
				break
			}
		}
	}
	s.frameOrigins[frameID] = origin
}

func (s *retainedSession) setChildFrameLocked(frameID, parentID string) {
	if frameID == "" || parentID == "" {
		return
	}
	if s.childFrames == nil {
		s.childFrames = make(map[string]string)
	}
	if _, exists := s.childFrames[frameID]; !exists && len(s.childFrames) >= maxSessionFrameEntries {
		for k := range s.childFrames {
			if k != s.mainFrameID {
				delete(s.childFrames, k)
				break
			}
		}
	}
	s.childFrames[frameID] = parentID
}

func (s *retainedSession) setFrameTaintedLocked(frameID string, tainted bool) {
	if frameID == "" {
		return
	}
	if s.frameTainted == nil {
		s.frameTainted = make(map[string]bool)
	}
	if _, exists := s.frameTainted[frameID]; !exists && len(s.frameTainted) >= maxSessionFrameEntries {
		for k := range s.frameTainted {
			if k != s.mainFrameID {
				delete(s.frameTainted, k)
				break
			}
		}
	}
	s.frameTainted[frameID] = tainted
}

func (s *retainedSession) lookupReqLoaderLocked(netID, reqID string) string {
	if len(s.reqLoaderIDs) == 0 {
		return ""
	}
	if netID != "" {
		if l := s.reqLoaderIDs[netID]; l != "" {
			return l
		}
	}
	if reqID != "" {
		return s.reqLoaderIDs[reqID]
	}
	return ""
}

// noteFrameAttached marks every child frame (srcdoc, blob:, data:, about:blank, same-origin or cross-origin iframe)
// tainted on attach and propagates parent frame taint to descendants.
func (s *retainedSession) noteFrameAttached(rawParams json.RawMessage) {
	var ev struct {
		FrameID       string `json:"frameId"`
		ParentFrameID string `json:"parentFrameId"`
	}
	if json.Unmarshal(rawParams, &ev) != nil || ev.FrameID == "" {
		return
	}
	s.mu.Lock()
	if ev.ParentFrameID != "" {
		s.setChildFrameLocked(ev.FrameID, ev.ParentFrameID)
		// Inherit parent taint and unconditionally taint all child frames (including non-network srcdoc/about:blank/blob:/data:).
		s.setFrameTaintedLocked(ev.FrameID, true)
		s.sawUninjectedSubdoc = true
	} else if s.frameTainted[ev.ParentFrameID] {
		s.setFrameTaintedLocked(ev.FrameID, true)
	}
	s.mu.Unlock()
}

// noteFrameNavigated updates per-frame origins and resets/sets taint ONLY when a frame actually commits a document (Page.frameNavigated).
func (s *retainedSession) noteFrameNavigated(rawParams json.RawMessage) {
	var ev struct {
		Frame struct {
			ID             string `json:"id"`
			ParentID       string `json:"parentId"`
			LoaderID       string `json:"loaderId"`
			URL            string `json:"url"`
			SecurityOrigin string `json:"securityOrigin"`
		} `json:"frame"`
	}
	if json.Unmarshal(rawParams, &ev) != nil || ev.Frame.ID == "" {
		return
	}
	urlOrigin := canonicalURLOrigin(ev.Frame.URL)
	secOrigin := canonicalURLOrigin(ev.Frame.SecurityOrigin)
	s.mu.Lock()
	if ev.Frame.ParentID != "" {
		s.setChildFrameLocked(ev.Frame.ID, ev.Frame.ParentID)
		s.setFrameOriginLocked(ev.Frame.ID, urlOrigin)
		s.setFrameTaintedLocked(ev.Frame.ID, true)
		s.sawUninjectedSubdoc = true
		s.mu.Unlock()
		return
	}
	s.mainFrameID = ev.Frame.ID
	if s.committedDocURL != "" {
		newClean := stripURLFragment(ev.Frame.URL)
		if newClean != "" && !sameNavigationURL(s.committedDocURL, newClean) {
			if s.staleStepDocURLs == nil || len(s.staleStepDocURLs) >= 64 {
				s.staleStepDocURLs = make(map[string]bool)
			}
			s.staleStepDocURLs[s.committedDocURL] = true
		}
	}
	s.hasCommittedDoc = true
	s.committedLoaderID = ev.Frame.LoaderID
	s.committedDocURL = stripURLFragment(ev.Frame.URL)
	if s.committedDocURL != "" && s.staleStepDocURLs != nil {
		delete(s.staleStepDocURLs, s.committedDocURL)
	}
	// Clear old child frames and reset frameOrigins to the newly committed top-level frame so frame maps stay O(active frames).
	s.childFrames = make(map[string]string)
	s.frameOrigins = map[string]string{ev.Frame.ID: urlOrigin}

	loaderOK := s.pendingNavLoaderID == "" || ev.Frame.LoaderID == "" || ev.Frame.LoaderID == s.pendingNavLoaderID
	// Top-level main frame commit: untainted ONLY when committing the single expected harness Page.navigate to initialOrigin
	// with zero cross-origin redirect hops (taints immediately on cross-origin redirect, blob:, data:, about:blank, BFCache, reload, or meta refresh).
	if s.awaitingHarnessCommit && !s.pendingNavCrossOrigin && loaderOK && s.initialOrigin != "" &&
		urlOrigin == s.initialOrigin && (secOrigin == "" || secOrigin == s.initialOrigin) {
		if s.pendingStepHeaders != nil {
			s.extraHeaders = s.pendingStepHeaders
			s.pendingStepHeaders = nil
		}
		s.awaitingHarnessCommit = false
		s.awaitingHarnessDocNav = false
		s.pendingNavLoaderID = ""
		s.redirectedCrossOrigin = false
		s.sawUninjectedSubdoc = false
		s.frameTainted = map[string]bool{ev.Frame.ID: false}
	} else {
		s.pendingStepHeaders = nil
		s.awaitingHarnessCommit = false
		s.awaitingHarnessDocNav = false
		s.pendingNavLoaderID = ""
		s.redirectedCrossOrigin = true
		s.sawUninjectedSubdoc = true
		s.frameTainted = map[string]bool{ev.Frame.ID: true}
	}
	s.mu.Unlock()
}

func (s *retainedSession) noteFrameDetached(rawParams json.RawMessage) {
	var ev struct {
		FrameID string `json:"frameId"`
	}
	if json.Unmarshal(rawParams, &ev) != nil || ev.FrameID == "" {
		return
	}
	s.mu.Lock()
	delete(s.frameOrigins, ev.FrameID)
	delete(s.childFrames, ev.FrameID)
	if ev.FrameID == s.mainFrameID {
		// Keep detached mainFrameID marked tainted so late unload/keepalive requests on mainFrameID are blocked.
		s.setFrameTaintedLocked(ev.FrameID, true)
	} else {
		// Non-mainFrameID frames are already rejected by `paused.FrameID != s.mainFrameID`, so evict cleanly to bound memory.
		delete(s.frameTainted, ev.FrameID)
	}
	s.mu.Unlock()
}

func (s *retainedSession) noteDownloadWillBegin(rawParams json.RawMessage) {
	var ev struct {
		FrameID string `json:"frameId"`
	}
	if json.Unmarshal(rawParams, &ev) != nil {
		return
	}
	s.mu.Lock()
	s.sawUninjectedSubdoc = true
	if ev.FrameID != "" {
		s.setFrameTaintedLocked(ev.FrameID, true)
	}
	if ev.FrameID == "" || ev.FrameID == s.mainFrameID {
		s.awaitingHarnessCommit = false
		s.pendingNavCrossOrigin = true
		s.redirectedCrossOrigin = true
		if s.mainFrameID != "" {
			s.setFrameTaintedLocked(s.mainFrameID, true)
		}
	}
	s.mu.Unlock()
}

func (s *retainedSession) noteNetworkRequestWillBeSent(rawParams json.RawMessage) {
	var ev struct {
		RequestID   string `json:"requestId"`
		LoaderID    string `json:"loaderId"`
		Type        string `json:"type"`
		DocumentURL string `json:"documentURL"`
		Initiator   struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"initiator"`
	}
	if json.Unmarshal(rawParams, &ev) != nil || ev.RequestID == "" {
		return
	}
	s.mu.Lock()
	if ev.LoaderID != "" {
		if s.reqLoaderIDs == nil || len(s.reqLoaderIDs) >= maxSessionNetEntries {
			s.reqLoaderIDs = make(map[string]string)
		}
		s.reqLoaderIDs[ev.RequestID] = ev.LoaderID
	}
	if ev.DocumentURL != "" {
		if s.reqDocURLs == nil || len(s.reqDocURLs) >= maxSessionNetEntries {
			s.reqDocURLs = make(map[string]string)
		}
		s.reqDocURLs[ev.RequestID] = stripURLFragment(ev.DocumentURL)
	}
	if strings.EqualFold(ev.Initiator.Type, "script") || strings.TrimSpace(ev.Initiator.URL) != "" {
		if s.scriptInitiatedReqs == nil || len(s.scriptInitiatedReqs) >= maxSessionNetEntries {
			s.scriptInitiatedReqs = make(map[string]bool)
		}
		s.scriptInitiatedReqs[ev.RequestID] = true
	}
	initOrigin := s.initialOrigin
	if initOrigin != "" {
		badDoc := ev.DocumentURL != "" && canonicalURLOrigin(ev.DocumentURL) != initOrigin
		badInit := ev.Initiator.URL != "" && canonicalURLOrigin(ev.Initiator.URL) != initOrigin
		if badDoc || badInit {
			if s.taintedNetReqs == nil || len(s.taintedNetReqs) >= maxSessionNetEntries {
				s.taintedNetReqs = make(map[string]bool)
			}
			s.taintedNetReqs[ev.RequestID] = true
		}
	}
	s.mu.Unlock()
}

func (s *retainedSession) noteNetworkResponseReceived(rawParams json.RawMessage) {
	var ev struct {
		RequestID string `json:"requestId"`
		Type      string `json:"type"`
		FrameID   string `json:"frameId"`
		Response  struct {
			Status  int               `json:"status"`
			Headers map[string]string `json:"headers"`
		} `json:"response"`
	}
	if json.Unmarshal(rawParams, &ev) != nil || !strings.EqualFold(ev.Type, "Document") {
		return
	}
	isAttachment := false
	for k, v := range ev.Response.Headers {
		if strings.EqualFold(strings.TrimSpace(k), "content-disposition") &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "attachment") {
			isAttachment = true
			break
		}
	}
	if ev.Response.Status != http.StatusNoContent && ev.Response.Status != http.StatusResetContent && !isAttachment {
		return
	}
	s.mu.Lock()
	s.sawUninjectedSubdoc = true
	if ev.FrameID != "" {
		s.setFrameTaintedLocked(ev.FrameID, true)
	}
	if ev.FrameID == "" || ev.FrameID == s.mainFrameID {
		s.awaitingHarnessCommit = false
		s.pendingNavCrossOrigin = true
		s.redirectedCrossOrigin = true
		if s.mainFrameID != "" {
			s.setFrameTaintedLocked(s.mainFrameID, true)
		}
	}
	s.mu.Unlock()
}

func (s *retainedSession) noteNetworkLoadingFailed(rawParams json.RawMessage) {
	var ev struct {
		RequestID string `json:"requestId"`
	}
	if json.Unmarshal(rawParams, &ev) != nil || ev.RequestID == "" {
		return
	}
	s.mu.Lock()
	if s.navChainReqID != "" && ev.RequestID == s.navChainReqID {
		s.awaitingHarnessCommit = false
		s.pendingNavCrossOrigin = true
		s.redirectedCrossOrigin = true
		if s.mainFrameID != "" {
			s.setFrameTaintedLocked(s.mainFrameID, true)
		}
	}
	s.mu.Unlock()
}

func (s *retainedSession) seedFrameTree(ctx context.Context, cdp *cdpConn) {
	type node struct {
		Frame struct {
			ID       string `json:"id"`
			ParentID string `json:"parentId"`
			LoaderID string `json:"loaderId"`
			URL      string `json:"url"`
		} `json:"frame"`
		ChildFrames []json.RawMessage `json:"childFrames"`
	}
	var out struct {
		FrameTree json.RawMessage `json:"frameTree"`
	}
	if cdp.call(ctx, s.cdpSessionID, "Page.getFrameTree", nil, &out) != nil || len(out.FrameTree) == 0 {
		return
	}
	var walk func(raw json.RawMessage, parentID string, isRoot bool)
	walk = func(raw json.RawMessage, parentID string, isRoot bool) {
		var n node
		if json.Unmarshal(raw, &n) != nil || n.Frame.ID == "" {
			return
		}
		fOrigin := canonicalURLOrigin(n.Frame.URL)
		s.mu.Lock()
		if isRoot {
			if s.mainFrameID == "" {
				s.mainFrameID = n.Frame.ID
			}
			if n.Frame.URL != "" && !strings.EqualFold(n.Frame.URL, "about:blank") {
				s.hasCommittedDoc = true
				if s.committedDocURL == "" {
					s.committedDocURL = stripURLFragment(n.Frame.URL)
				}
				if s.committedLoaderID == "" && n.Frame.LoaderID != "" {
					s.committedLoaderID = n.Frame.LoaderID
				}
				s.setFrameOriginLocked(n.Frame.ID, fOrigin)
				if fOrigin != s.initialOrigin {
					s.setFrameTaintedLocked(n.Frame.ID, true)
				}
			}
		} else {
			effParent := n.Frame.ParentID
			if effParent == "" {
				effParent = parentID
			}
			s.setChildFrameLocked(n.Frame.ID, effParent)
			s.setFrameOriginLocked(n.Frame.ID, fOrigin)
			s.setFrameTaintedLocked(n.Frame.ID, true)
		}
		s.mu.Unlock()
		for _, c := range n.ChildFrames {
			walk(c, n.Frame.ID, false)
		}
	}
	walk(out.FrameTree, "", true)
}

func (s *retainedSession) expectHarnessNavigation(targetURL string) {
	if s == nil {
		return
	}
	targetOrigin := canonicalURLOrigin(targetURL)
	s.mu.Lock()
	// IMPORTANT: Never clear s.frameTainted or s.redirectedCrossOrigin here when a step begins;
	// taint is cleared ONLY in noteFrameNavigated once the new top-level document actually commits!
	if s.committedDocURL != "" && targetURL != "" && !sameNavigationURL(s.committedDocURL, targetURL) {
		if s.staleStepDocURLs == nil || len(s.staleStepDocURLs) >= 64 {
			s.staleStepDocURLs = make(map[string]bool)
		}
		s.staleStepDocURLs[s.committedDocURL] = true
	}
	s.pendingNavLoaderID = ""
	s.navChainReqID = ""
	if s.initialOrigin != "" && targetOrigin == s.initialOrigin {
		s.harnessNavURL = targetURL
		s.awaitingHarnessDocNav = true
		s.awaitingHarnessCommit = true
		s.pendingNavCrossOrigin = false
	} else {
		s.harnessNavURL = ""
		s.awaitingHarnessDocNav = false
		s.awaitingHarnessCommit = false
		s.pendingNavCrossOrigin = true
		s.redirectedCrossOrigin = true
	}
	s.mu.Unlock()
}

func (s *retainedSession) clearExpectedHarnessNavigation() {
	if s == nil {
		return
	}
	s.mu.Lock()
	uncommittedOnExisting := s.awaitingHarnessCommit && s.hasCommittedDoc
	s.harnessNavURL = ""
	s.awaitingHarnessDocNav = false
	s.awaitingHarnessCommit = false
	s.pendingNavLoaderID = ""
	if uncommittedOnExisting {
		s.redirectedCrossOrigin = true
		if s.mainFrameID != "" {
			s.setFrameTaintedLocked(s.mainFrameID, true)
		}
	}
	s.mu.Unlock()
}

func (s *retainedSession) handleRequestPaused(cdp *cdpConn, rawParams json.RawMessage) {
	var paused struct {
		RequestID           string `json:"requestId"`
		NetworkID           string `json:"networkId"`
		FrameID             string `json:"frameId"`
		ResourceType        string `json:"resourceType"`
		RedirectStatusCode  int    `json:"redirectStatusCode"`
		RedirectedRequestID string `json:"redirectedRequestId"`
		Initiator           *struct {
			Type string `json:"type,omitempty"`
			URL  string `json:"url,omitempty"`
		} `json:"initiator,omitempty"`
		Request struct {
			URL     string         `json:"url"`
			Method  string         `json:"method"`
			Headers map[string]any `json:"headers"`
		} `json:"request"`
	}
	if json.Unmarshal(rawParams, &paused) != nil || paused.RequestID == "" {
		return
	}

	reqOrigin := ""
	if paused.Request.URL != "" {
		reqOrigin = canonicalURLOrigin(paused.Request.URL)
	}

	s.mu.Lock()
	cdpSID := s.cdpSessionID
	initOrigin := s.initialOrigin
	extra := s.extraHeaders
	pendingExtra := s.pendingStepHeaders

	isDocReq := strings.EqualFold(paused.ResourceType, "Document")
	isChildFrame := paused.FrameID != "" && (s.childFrames[paused.FrameID] != "" || (s.mainFrameID != "" && paused.FrameID != s.mainFrameID))
	if isChildFrame {
		s.setFrameTaintedLocked(paused.FrameID, true)
	}
	isMainDoc := (isDocReq || paused.ResourceType == "") && !isChildFrame &&
		(s.mainFrameID == "" || paused.FrameID == "" || paused.FrameID == s.mainFrameID)

	sameOriginReq := initOrigin != "" && reqOrigin != "" && reqOrigin == initOrigin
	// A redirect hop is only as trustworthy as the hop before it: bound -> third party -> bound never gets headers.
	chainOK := paused.RedirectedRequestID == "" || s.injectedReqs[paused.RedirectedRequestID]

	isScriptInit := (paused.Initiator != nil && (strings.EqualFold(paused.Initiator.Type, "script") || strings.TrimSpace(paused.Initiator.URL) != "")) ||
		(paused.NetworkID != "" && s.scriptInitiatedReqs[paused.NetworkID]) ||
		(paused.RequestID != "" && s.scriptInitiatedReqs[paused.RequestID])
	reqLoader := s.lookupReqLoaderLocked(paused.NetworkID, paused.RequestID)

	// Only the single top-level Document request initiated by Go's Page.navigate (plus its direct same-origin 3xx redirect chain) is a harnessHop.
	// Taint from any prior page is NOT reset here; it is reset ONLY when Page.frameNavigated commits the new document!
	harnessHop := false
	if isMainDoc {
		switch {
		case s.awaitingHarnessDocNav && paused.RedirectedRequestID == "" && s.harnessNavURL != "" &&
			sameNavigationURL(paused.Request.URL, s.harnessNavURL) && !isScriptInit &&
			!(s.hasCommittedDoc && hasNonEmptyRefererHeader(paused.Request.Headers)):
			harnessHop = true
			s.awaitingHarnessDocNav = false
			s.harnessNavURL = ""
			if s.mainFrameID == "" && paused.FrameID != "" {
				s.mainFrameID = paused.FrameID
			}
			if reqLoader != "" {
				s.pendingNavLoaderID = reqLoader
			}
		case paused.RedirectedRequestID != "" && paused.RedirectedRequestID == s.navChainReqID:
			if chainOK && sameOriginReq && !s.pendingNavCrossOrigin {
				harnessHop = true
			} else {
				s.pendingNavCrossOrigin = true
				s.redirectedCrossOrigin = true
			}
		}
		if harnessHop {
			s.navChainReqID = paused.RequestID
		}
	}

	// Any non-harness Document load (form submit, reload, history nav, meta refresh, JS location.href, subframe Document,
	// or cross-origin redirect of the harness navigation) receives ZERO caller headers and immediately taints its frame
	// (and taints the entire tab if on the main frame).
	if isDocReq && !harnessHop && initOrigin != "" {
		s.sawUninjectedSubdoc = true
		if paused.FrameID != "" {
			s.setFrameTaintedLocked(paused.FrameID, true)
		}
		if !isChildFrame {
			if paused.RedirectedRequestID != "" && paused.RedirectedRequestID == s.navChainReqID {
				s.pendingNavCrossOrigin = true
			}
			s.redirectedCrossOrigin = true
			if s.mainFrameID != "" {
				s.setFrameTaintedLocked(s.mainFrameID, true)
			}
		}
	}

	netTainted := (paused.NetworkID != "" && s.taintedNetReqs[paused.NetworkID]) ||
		(paused.RequestID != "" && s.taintedNetReqs[paused.RequestID])
	if paused.Initiator != nil && strings.TrimSpace(paused.Initiator.URL) != "" {
		if canonicalURLOrigin(paused.Initiator.URL) != initOrigin {
			netTainted = true
		}
	}

	// While a new navigation step is in flight before Page.frameNavigated commits on mainFrameID, block ALL non-harnessHop
	// requests from the still-alive previous document (and also reject any request carrying a stale previous loaderId or retired step URL).
	preCommitOldDoc := s.hasCommittedDoc && s.awaitingHarnessCommit
	staleLoader := s.committedLoaderID != "" && reqLoader != "" && reqLoader != s.committedLoaderID
	stalePrevStepDoc := false
	if len(s.staleStepDocURLs) > 0 {
		isRetiredURL := func(u string) bool {
			clean := stripURLFragment(u)
			if clean == "" {
				return false
			}
			if s.committedDocURL != "" && sameNavigationURL(clean, s.committedDocURL) {
				return false
			}
			if s.staleStepDocURLs[clean] {
				return true
			}
			for prevU := range s.staleStepDocURLs {
				if sameNavigationURL(clean, prevU) {
					return true
				}
			}
			return false
		}
		for hk, hv := range paused.Request.Headers {
			if hv != nil && strings.EqualFold(strings.TrimSpace(hk), "referer") {
				if isRetiredURL(fmt.Sprint(hv)) {
					stalePrevStepDoc = true
				}
				break
			}
		}
		if !stalePrevStepDoc && paused.Initiator != nil && paused.Initiator.URL != "" && isRetiredURL(paused.Initiator.URL) {
			stalePrevStepDoc = true
		}
		if !stalePrevStepDoc && paused.NetworkID != "" && isRetiredURL(s.reqDocURLs[paused.NetworkID]) {
			stalePrevStepDoc = true
		}
		if !stalePrevStepDoc && paused.RequestID != "" && isRetiredURL(s.reqDocURLs[paused.RequestID]) {
			stalePrevStepDoc = true
		}
	}
	badCommittedOrigin := s.hasCommittedDoc && !s.awaitingHarnessCommit && paused.FrameID != "" &&
		s.frameOrigins[paused.FrameID] != "" && s.frameOrigins[paused.FrameID] != initOrigin

	tabTainted := s.redirectedCrossOrigin
	frameUntrusted := paused.FrameID == "" || isChildFrame || s.frameTainted[paused.FrameID] ||
		(s.mainFrameID != "" && paused.FrameID != s.mainFrameID)
	isPingOrBeacon := strings.EqualFold(paused.ResourceType, "Ping") || strings.EqualFold(paused.ResourceType, "CSPViolationReport")

	allowInject := false
	switch {
	case !sameOriginReq:
		allowInject = false
	case harnessHop:
		allowInject = !s.pendingNavCrossOrigin && !netTainted
		if pendingExtra != nil {
			extra = pendingExtra
		}
	case isDocReq:
		allowInject = false
	default:
		// Subresources: require committed target document (never pre-commit or retired previous page), matching loaderId,
		// untainted tab & frame, non-Ping, redirect-chain provenance, and positive Origin/Referer proof.
		allowInject = !preCommitOldDoc && !staleLoader && !stalePrevStepDoc && !badCommittedOrigin &&
			!tabTainted && !frameUntrusted && !netTainted && !isPingOrBeacon && chainOK &&
			hasPositiveSameOriginProof(paused.Request.Headers, initOrigin)
	}

	if allowInject && len(extra) > 0 {
		if s.injectedReqs == nil || len(s.injectedReqs) >= maxSessionNetEntries {
			s.injectedReqs = make(map[string]bool)
		}
		s.injectedReqs[paused.RequestID] = true
	}
	s.mu.Unlock()

	params := map[string]any{"requestId": paused.RequestID}
	if allowInject && len(extra) > 0 {
		params["headers"] = mergeCDPRequestHeaders(paused.Request.Headers, extra)
	}
	go func() {
		cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = cdp.call(cctx, cdpSID, "Fetch.continueRequest", params, nil)
	}()
}

func (s *retainedSession) getLastCheckedURL() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCheckedURL
}

func (s *retainedSession) getMainFrameID() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mainFrameID
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
	var snapFallback string
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
			if runtime.GOOS == "linux" && isLinuxSnapWrapper(p) {
				if snapFallback == "" {
					snapFallback = p
				}
				continue
			}
			return p
		}
	}
	if snapFallback != "" {
		return snapFallback
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
	chromeBin      string
	allow          func(*url.URL) error
	CheckRobots    func(ctx context.Context, rawURL string) error
	userAgent      string
	log            *slog.Logger
	sem            chan struct{}
	requireSandbox bool
	allowNoSandbox bool

	// Optional hooks allowing unit/E2E tests to attach a mock CDP WebSocket URL or custom proxy dialer.
	dialOverrideWS string
	proxyDial      func(ctx context.Context, network, addr string) (net.Conn, error)
	extraFlags     []string

	probeOnce        sync.Once
	mu               sync.Mutex
	proxy            *SSRFProxy
	cmd              *exec.Cmd
	userDataDir      string
	cdp              *cdpConn
	sessions         map[string]*retainedSession
	activeRuns       int
	taintedByHeaders bool
	sandboxFallback  bool
	disabledByPolicy bool
	sandboxState     string
	browserVersion   string
	lastUsedAt       time.Time
	closed           bool
	otelExp          *otel.Exporter
}

func isSandboxRequiredByEnv() bool {
	v := strings.TrimSpace(os.Getenv("EDGEFETCH_REQUIRE_BROWSER_SANDBOX"))
	return v == "1" || strings.EqualFold(v, "true")
}

func isNoSandboxAllowedByEnv() bool {
	v := strings.TrimSpace(os.Getenv("EDGEFETCH_ALLOW_NO_SANDBOX"))
	return v == "1" || strings.EqualFold(v, "true")
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
	initialSandbox := ""
	if chromeBin != "" {
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			initialSandbox = "on"
		} else {
			initialSandbox = "unknown"
		}
	}
	r := &Renderer{
		chromeBin:      chromeBin,
		allow:          allow,
		userAgent:      userAgent,
		log:            log,
		sem:            make(chan struct{}, maxConcurrent),
		requireSandbox: isSandboxRequiredByEnv(),
		allowNoSandbox: isNoSandboxAllowedByEnv(),
		sessions:       make(map[string]*retainedSession),
		sandboxState:   initialSandbox,
	}
	return r
}

// NewMockRenderer creates a Renderer backed by an in-memory/loopback CDP WebSocket URL for deterministic unit tests.
func NewMockRenderer(wsURL string, allow func(*url.URL) error, userAgent string) *Renderer {
	r := NewRenderer("", allow, userAgent, 2, nil)
	r.dialOverrideWS = wsURL
	return r
}

// Available reports whether a headless browser binary (or test override) is available and permitted by sandbox policy.
func (r *Renderer) Available() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	disabled := r.disabledByPolicy
	r.mu.Unlock()
	return !disabled && (r.chromeBin != "" || r.dialOverrideWS != "")
}

// SetAllowNoSandbox configures whether Chromium may fall back to `--no-sandbox` when the host OS or
// Home Assistant OS AppArmor/seccomp profile blocks unprivileged user namespaces (`CLONE_NEWUSER`).
// Ignored when EDGEFETCH_REQUIRE_BROWSER_SANDBOX is set.
func (r *Renderer) SetAllowNoSandbox(allow bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.allowNoSandbox = allow || isNoSandboxAllowedByEnv()
	if r.allowNoSandbox && !r.requireSandbox {
		r.disabledByPolicy = false
	}
	r.mu.Unlock()
}

// SetOtelExporter attaches an optional non-blocking OpenTelemetry OTLP/HTTP span exporter.
func (r *Renderer) SetOtelExporter(exp *otel.Exporter) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.otelExp = exp
	r.mu.Unlock()
}

func (r *Renderer) otelExporter() *otel.Exporter {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	exp := r.otelExp
	r.mu.Unlock()
	return exp
}

// BrowserInfo returns the detected Chromium product version and OS process sandbox state ("on", "off", or "unknown").
func (r *Renderer) BrowserInfo() (version string, sandbox string) {
	if r == nil {
		return "", ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.browserVersion, r.sandboxState
}

// ProbeStartup pre-populates r.browserVersion via `<chromeBin> --version` and probes OS sandbox support on Linux.
// When EDGEFETCH_REQUIRE_BROWSER_SANDBOX is set and the OS sandbox is "off", Available() becomes false.
func (r *Renderer) ProbeStartup(ctx context.Context) {
	if r == nil || r.chromeBin == "" || r.dialOverrideWS != "" || ctx.Err() != nil {
		return
	}
	r.probeOnce.Do(func() {
		vctx, vcancel := context.WithTimeout(ctx, 3*time.Second)
		vcmd := exec.CommandContext(vctx, r.chromeBin, "--version")
		vcmd.Env = buildSanitizedChildEnv("")
		if out, err := vcmd.Output(); err == nil {
			line := strings.TrimSpace(string(out))
			if nl := strings.IndexByte(line, '\n'); nl >= 0 {
				line = strings.TrimSpace(line[:nl])
			}
			if line != "" {
				r.mu.Lock()
				if r.browserVersion == "" {
					r.browserVersion = line
				}
				r.mu.Unlock()
			}
		}
		vcancel()

		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			r.mu.Lock()
			r.sandboxState = "on"
			r.mu.Unlock()
			return
		}
		if runtime.GOOS == "linux" {
			pctx, pcancel := context.WithTimeout(ctx, 4*time.Second)
			_, _ = r.ensureBrowser(pctx)
			pcancel()
			r.mu.Lock()
			if (r.requireSandbox || !r.allowNoSandbox) && r.sandboxState == "off" {
				r.disabledByPolicy = true
			}
			r.mu.Unlock()
		}
	})
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
	sess.stopFetch()
	if cdp != nil && !cdp.isClosed() {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = cdp.call(cctx, "", "Target.closeTarget", map[string]any{"targetId": sess.targetID}, nil)
		_ = cdp.call(cctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": sess.browserContextID}, nil)
		cancel()
	}
	r.mu.Lock()
	if r.taintedByHeaders && r.activeRuns == 0 && len(r.sessions) == 0 {
		r.shutdownLocked()
	}
	r.mu.Unlock()
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

	exp := r.otelExporter()
	if tc, hasTrace := otel.TraceContextFromContext(ctx); exp != nil && hasTrace && tc.Sampled {
		renderStart := time.Now()
		defer func() {
			errMsg := ""
			if retErr != nil {
				errMsg = otel.RedactEmbeddedURLs(retErr.Error())
			}
			exp.Record(otel.Span{
				TraceID:      tc.TraceID,
				SpanID:       otel.RandomHex(8),
				ParentSpanID: tc.SpanID,
				Name:         "edgefetch.browser.render",
				Kind:         1, // INTERNAL
				Start:        renderStart,
				End:          time.Now(),
				StatusOK:     retErr == nil,
				ErrorMessage: errMsg,
				Attributes: map[string]any{
					"url.full":                otel.SanitizeURL(task.URL),
					"browser.status":          out.Status,
					"browser.rendered_bytes":  len(out.HTML),
					"browser.actions_count":   len(task.Actions),
					"browser.session_resumed": task.SessionID != "",
					"browser.screenshot":      task.Screenshot,
				},
			})
		}()
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
		if len(task.Headers) > 0 {
			r.taintedByHeaders = true
		}
		if r.activeRuns > 0 {
			r.activeRuns--
		}
		r.lastUsedAt = time.Now()
		if r.taintedByHeaders && r.activeRuns == 0 && len(r.sessions) == 0 {
			r.shutdownLocked()
		}
		r.mu.Unlock()
	}()

	cdp, err := r.ensureBrowser(ctx)
	if err != nil {
		return Output{}, err
	}
	if len(task.Headers) > 0 {
		r.mu.Lock()
		r.taintedByHeaders = true
		r.mu.Unlock()
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
		sess.mu.Lock()
		if sess.lastCheckedURL != "" {
			sess.hasCommittedDoc = true
		}
		sess.mu.Unlock()
		navTarget := task.URL
		if navTarget == "" {
			for _, a := range task.Actions {
				if strings.EqualFold(strings.TrimSpace(a.Type), "navigate") {
					navTarget = strings.TrimSpace(a.URL)
					break
				}
			}
		}
		if len(task.Headers) > 0 {
			if navTarget != "" {
				upOrigin := canonicalURLOrigin(navTarget)
				if upOrigin == "" {
					return Output{}, errors.New("cannot scope request headers: navigation target has no canonical http(s) origin")
				}
				sess.mu.Lock()
				prevOrigin := sess.initialOrigin
				sess.initialOrigin = upOrigin
				if prevOrigin != upOrigin {
					sess.injectedReqs = nil
					sess.navChainReqID = ""
					if prevOrigin != "" {
						// Mark the currently loaded previous-origin document tainted until the new navigation commits.
						sess.redirectedCrossOrigin = true
						if sess.mainFrameID != "" {
							sess.setFrameTaintedLocked(sess.mainFrameID, true)
						}
					}
				}
				sess.mu.Unlock()
			} else {
				sess.mu.Lock()
				hasInit := sess.initialOrigin != ""
				sess.mu.Unlock()
				if !hasInit {
					return Output{}, errors.New("cannot scope request headers: session has no canonical http(s) origin")
				}
			}
			if err := sess.enableOriginScopedHeaders(ctx, cdp, task.Headers, navTarget != ""); err != nil {
				return Output{}, err
			}
		} else if navTarget != "" {
			navOrigin := canonicalURLOrigin(navTarget)
			sess.mu.Lock()
			if sess.initialOrigin != "" && navOrigin != sess.initialOrigin {
				sess.redirectedCrossOrigin = true
			}
			sess.mu.Unlock()
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
		initOrigin := ""
		if task.URL != "" {
			initOrigin = canonicalURLOrigin(task.URL)
		} else {
			for _, a := range task.Actions {
				if strings.EqualFold(strings.TrimSpace(a.Type), "navigate") {
					initOrigin = canonicalURLOrigin(a.URL)
					break
				}
			}
		}
		if len(task.Headers) > 0 && initOrigin == "" {
			_ = cdp.call(context.Background(), "", "Target.closeTarget", map[string]any{"targetId": tgtOut.TargetID}, nil)
			_ = cdp.call(context.Background(), "", "Target.disposeBrowserContext", map[string]any{"browserContextId": bcOut.BrowserContextID}, nil)
			return Output{}, errors.New("cannot scope request headers: navigation target has no canonical http(s) origin")
		}
		sess = &retainedSession{
			id:               sid,
			browserContextID: bcOut.BrowserContextID,
			targetID:         tgtOut.TargetID,
			cdpSessionID:     attOut.SessionID,
			initialOrigin:    initOrigin,
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
			if err := sess.enableOriginScopedHeaders(ctx, cdp, task.Headers); err != nil {
				_ = cdp.call(context.Background(), "", "Target.closeTarget", map[string]any{"targetId": sess.targetID}, nil)
				_ = cdp.call(context.Background(), "", "Target.disposeBrowserContext", map[string]any{"browserContextId": sess.browserContextID}, nil)
				return Output{}, err
			}
		}
	}

	cleanupOnExit := !task.KeepSession || task.CloseSession
	defer func() {
		if retErr != nil && !resumed {
			cleanupOnExit = true
		}
		if cleanupOnExit {
			sess.stopFetch()
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
		actionResults     []ActionResult
		pdfBase64         string
	)
	if len(task.Actions) > 0 {
		actionResults = make([]ActionResult, 0, len(task.Actions))
	}
	for i, act := range task.Actions {
		ar, err := r.runActionStep(ctx, cdp, sess, events, i, act, &actionScreenshots, &actionScrapes, &jsReturns, &pdfBase64)
		if err != nil {
			stErr, hErr := sess.snapshotResponseMeta()
			return Output{Status: stErr, Headers: hErr, ActionResults: actionResults}, fmt.Errorf("interact action %d (%s): %w", i, act.Type, err)
		}
		actionResults = append(actionResults, ar)
	}

	htmlStr, finalURL, err := readDocumentHTML(ctx, cdp, sess.cdpSessionID)
	if err != nil {
		return Output{ActionResults: actionResults}, err
	}
	if vErr := r.validateFinalURL(ctx, sess, finalURL, task.URL); vErr != nil {
		return Output{ActionResults: actionResults}, vErr
	}
	for i := range actionScrapes {
		if vErr := r.validateFinalURL(ctx, sess, actionScrapes[i].URL, task.URL); vErr != nil {
			return Output{ActionResults: actionResults}, vErr
		}
	}
	st, hClone := sess.snapshotResponseMeta()
	if why := extract.DetectRenderedChallenge(htmlStr); why != "" {
		return Output{Status: st, Headers: hClone, FinalURL: finalURL, ActionResults: actionResults}, fmt.Errorf("%w: %s", ErrChallengeDetected, why)
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
		ActionResults:     actionResults,
		PDFBase64:         pdfBase64,
	}
	if task.KeepSession && !task.CloseSession {
		out.SessionID = sess.id
	}
	return out, nil
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
		LoaderID  string `json:"loaderId,omitempty"`
		ErrorText string `json:"errorText,omitempty"`
	}
	sess.expectHarnessNavigation(targetURL)
	defer sess.clearExpectedHarnessNavigation()
	if err := cdp.call(ctx, sessionID, "Page.navigate", map[string]any{"url": targetURL}, &navOut); err != nil {
		return 0, nil, err
	}
	if sess != nil && (navOut.FrameID != "" || navOut.LoaderID != "") {
		sess.mu.Lock()
		if sess.mainFrameID == "" && navOut.FrameID != "" {
			sess.mainFrameID = navOut.FrameID
		}
		if sess.awaitingHarnessCommit && sess.pendingNavLoaderID == "" && navOut.LoaderID != "" {
			sess.pendingNavLoaderID = navOut.LoaderID
		}
		sess.mu.Unlock()
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
			}
			if json.Unmarshal(ev.Params, &rw) == nil && rw.RequestID != "" {
				// Track SPA data & code requests; ignore long-lived streaming/beacon types (WebSocket, EventSource, Media, Ping).
				switch rw.Type {
				case "Document", "XHR", "Fetch", "Script":
					inFlight[rw.RequestID] = time.Now()
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

	loadWait := time.NewTimer(navLoadTimeout)
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
	if maxIdleBudget < minIdleBudget {
		maxIdleBudget = minIdleBudget
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
			if now.Sub(started) > staleInFlightTTL {
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

type cdpKeySpec struct {
	key  string
	code string
	text string
	vk   int
}

func resolveCDPKeySpec(raw string) cdpKeySpec {
	if raw == " " {
		return cdpKeySpec{key: " ", code: "Space", text: " ", vk: 32}
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return cdpKeySpec{key: "Enter", code: "Enter", text: "\r", vk: 13}
	}
	switch strings.ToLower(trimmed) {
	case "enter", "return", "numpadenter":
		return cdpKeySpec{key: "Enter", code: "Enter", text: "\r", vk: 13}
	case "tab":
		return cdpKeySpec{key: "Tab", code: "Tab", vk: 9}
	case "escape", "esc":
		return cdpKeySpec{key: "Escape", code: "Escape", vk: 27}
	case "backspace":
		return cdpKeySpec{key: "Backspace", code: "Backspace", vk: 8}
	case "delete":
		return cdpKeySpec{key: "Delete", code: "Delete", vk: 46}
	case "space", "spacebar":
		return cdpKeySpec{key: " ", code: "Space", text: " ", vk: 32}
	case "arrowdown":
		return cdpKeySpec{key: "ArrowDown", code: "ArrowDown", vk: 40}
	case "arrowup":
		return cdpKeySpec{key: "ArrowUp", code: "ArrowUp", vk: 38}
	case "arrowleft":
		return cdpKeySpec{key: "ArrowLeft", code: "ArrowLeft", vk: 37}
	case "arrowright":
		return cdpKeySpec{key: "ArrowRight", code: "ArrowRight", vk: 39}
	case "home":
		return cdpKeySpec{key: "Home", code: "Home", vk: 36}
	case "end":
		return cdpKeySpec{key: "End", code: "End", vk: 35}
	case "pageup":
		return cdpKeySpec{key: "PageUp", code: "PageUp", vk: 33}
	case "pagedown":
		return cdpKeySpec{key: "PageDown", code: "PageDown", vk: 34}
	}
	if len(trimmed) == 1 && trimmed[0] >= 0x20 && trimmed[0] <= 0x7e {
		ch := trimmed[0]
		switch {
		case ch >= 'a' && ch <= 'z':
			upper := ch - 'a' + 'A'
			return cdpKeySpec{key: trimmed, code: "Key" + string(upper), text: trimmed, vk: int(upper)}
		case ch >= 'A' && ch <= 'Z':
			return cdpKeySpec{key: trimmed, code: "Key" + trimmed, text: trimmed, vk: int(ch)}
		case ch >= '0' && ch <= '9':
			return cdpKeySpec{key: trimmed, code: "Digit" + trimmed, text: trimmed, vk: int(ch)}
		default:
			return cdpKeySpec{key: trimmed, code: trimmed, text: trimmed, vk: int(ch)}
		}
	}
	return cdpKeySpec{key: trimmed, code: trimmed}
}

type actionDOMSnapshot struct {
	url    string
	digest string
	ok     bool
}

func captureActionDOMState(ctx context.Context, cdp *cdpConn, sessionID string) actionDOMSnapshot {
	if cdp == nil || ctx.Err() != nil {
		return actionDOMSnapshot{}
	}
	const expr = `(() => {
		const u = String(location.href || "");
		const title = String(document.title || "");
		const bodyText = String((document.body && document.body.innerText) || "");
		let h = 2166136261;
		for (let i = 0; i < bodyText.length; i++) {
			h ^= bodyText.charCodeAt(i);
			h = Math.imul(h, 16777619);
		}
		const els = document.body ? document.body.getElementsByTagName("*").length : 0;
		const controls = document.querySelectorAll ? document.querySelectorAll("input,textarea,select,[open],[aria-expanded]") : [];
		for (let i = 0; i < controls.length && i < 64; i++) {
			const c = controls[i];
			const v = (c.type === "checkbox" || c.type === "radio")
				? String(Boolean(c.checked))
				: String((c.value !== undefined ? c.value : "") + "|" + (c.getAttribute ? (c.getAttribute("aria-expanded") || "") : "") + "|" + Boolean(c.open));
			for (let j = 0; j < v.length; j++) {
				h ^= v.charCodeAt(j);
				h = Math.imul(h, 16777619);
			}
		}
		return JSON.stringify({
			url: u,
			digest: bodyText.length + ":" + title + ":" + els + ":" + (h >>> 0)
		});
	})()`
	raw, err := evalString(ctx, cdp, sessionID, expr)
	if err != nil || len(raw) == 0 || raw[0] != '{' {
		return actionDOMSnapshot{}
	}
	var payload struct {
		URL    string `json:"url"`
		Digest string `json:"digest"`
		HTML   string `json:"html"`
	}
	if json.Unmarshal([]byte(raw), &payload) != nil {
		return actionDOMSnapshot{}
	}
	dig := payload.Digest
	if dig == "" && payload.HTML != "" {
		dig = strconv.Itoa(len(payload.HTML)) + ":" + payload.HTML
	}
	if dig == "" && payload.URL == "" {
		return actionDOMSnapshot{}
	}
	return actionDOMSnapshot{url: payload.URL, digest: dig, ok: true}
}

type actionNavTracker struct {
	sessionID        string
	sess             *retainedSession
	navStarted       bool
	sameDocNav       bool
	loadFired        bool
	docStatus        int
	docHeaders       http.Header
	inFlight         map[string]time.Time
	requestedDocURLs []string
}

func newActionNavTracker(sess *retainedSession) *actionNavTracker {
	sid := ""
	if sess != nil {
		sid = sess.cdpSessionID
	}
	return &actionNavTracker{
		sessionID:  sid,
		sess:       sess,
		docHeaders: make(http.Header),
		inFlight:   make(map[string]time.Time),
	}
}

func (t *actionNavTracker) isMainFrame(frameID string) bool {
	if frameID == "" || t.sess == nil {
		return true
	}
	mf := t.sess.getMainFrameID()
	return mf == "" || frameID == mf
}

func (t *actionNavTracker) handleEvent(ev cdpEvent) {
	if ev.SessionID != t.sessionID {
		return
	}
	switch ev.Method {
	case "Page.frameStartedLoading":
		var f struct {
			FrameID string `json:"frameId"`
		}
		if json.Unmarshal(ev.Params, &f) == nil && t.isMainFrame(f.FrameID) {
			t.navStarted = true
		}
	case "Page.navigatedWithinDocument":
		var f struct {
			FrameID string `json:"frameId"`
			URL     string `json:"url"`
		}
		if json.Unmarshal(ev.Params, &f) == nil && t.isMainFrame(f.FrameID) {
			t.sameDocNav = true
			if f.URL != "" {
				t.requestedDocURLs = append(t.requestedDocURLs, f.URL)
			}
		}
	case "Page.frameNavigated":
		var fn struct {
			Frame struct {
				ID       string `json:"id"`
				ParentID string `json:"parentId"`
				URL      string `json:"url"`
			} `json:"frame"`
		}
		if json.Unmarshal(ev.Params, &fn) == nil && (fn.Frame.ParentID == "" || (fn.Frame.ID != "" && t.isMainFrame(fn.Frame.ID))) {
			if t.sess != nil && fn.Frame.ParentID == "" && fn.Frame.ID != "" {
				t.sess.mu.Lock()
				t.sess.mainFrameID = fn.Frame.ID
				t.sess.mu.Unlock()
			}
			t.navStarted = true
			if fn.Frame.URL != "" {
				t.requestedDocURLs = append(t.requestedDocURLs, fn.Frame.URL)
			}
		}
	case "Page.loadEventFired":
		t.loadFired = true
	case "Network.requestWillBeSent":
		var rw struct {
			RequestID string `json:"requestId"`
			FrameID   string `json:"frameId"`
			Type      string `json:"type"`
			Request   struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		if json.Unmarshal(ev.Params, &rw) == nil {
			if rw.RequestID != "" {
				switch rw.Type {
				case "Document", "XHR", "Fetch", "Script":
					t.inFlight[rw.RequestID] = time.Now()
				}
			}
			if rw.Type == "Document" && t.isMainFrame(rw.FrameID) && rw.Request.URL != "" {
				t.requestedDocURLs = append(t.requestedDocURLs, rw.Request.URL)
			}
		}
	case "Network.loadingFinished", "Network.loadingFailed":
		var lf struct {
			RequestID string `json:"requestId"`
		}
		if json.Unmarshal(ev.Params, &lf) == nil && lf.RequestID != "" {
			delete(t.inFlight, lf.RequestID)
		}
	case "Network.responseReceived":
		var rr struct {
			Type     string `json:"type"`
			FrameID  string `json:"frameId"`
			Response struct {
				Status  int               `json:"status"`
				Headers map[string]string `json:"headers"`
			} `json:"response"`
		}
		if json.Unmarshal(ev.Params, &rr) == nil {
			if rr.Type == "Document" && t.isMainFrame(rr.FrameID) && rr.Response.Status > 0 {
				t.docStatus = rr.Response.Status
				for k, v := range rr.Response.Headers {
					t.docHeaders.Set(k, v)
				}
			}
		}
	}
}

func (r *Renderer) checkPendingNavURLs(ctx context.Context, cdp *cdpConn, sess *retainedSession, tracker *actionNavTracker, checked *int) error {
	for *checked < len(tracker.requestedDocURLs) {
		cand := strings.TrimSpace(tracker.requestedDocURLs[*checked])
		*checked++
		if cand == "" || strings.EqualFold(cand, "about:blank") || strings.HasPrefix(strings.ToLower(cand), "chrome-error://") {
			continue
		}
		u, err := url.Parse(cand)
		if err != nil {
			continue
		}
		if r.allow != nil {
			if aErr := r.allow(u); aErr != nil {
				_ = cdp.call(ctx, tracker.sessionID, "Page.stopLoading", nil, nil)
				return fmt.Errorf("rendered final URL blocked by SSRF policy (%s): %w", politeness.SanitizeURL(u.String()), aErr)
			}
		}
		prevChecked := sess.getLastCheckedURL()
		if r.CheckRobots != nil && u.String() != prevChecked {
			if rErr := r.CheckRobots(ctx, u.String()); rErr != nil {
				_ = cdp.call(ctx, tracker.sessionID, "Page.stopLoading", nil, nil)
				return fmt.Errorf("rendered final URL disallowed by robots.txt: %w", rErr)
			}
			sess.setLastCheckedURL(u.String())
		}
	}
	return nil
}

func waitForActionDOMQuiescence(ctx context.Context, cdp *cdpConn, sessionID string) {
	const js = `new Promise((resolve) => {
		try {
			let lastMut = Date.now();
			const start = lastMut;
			const obs = new MutationObserver(() => { lastMut = Date.now(); });
			if (document.documentElement) {
				obs.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
			}
			const check = () => {
				const now = Date.now();
				if (now - start >= 600 || (now - lastMut >= 160 && now - start >= 120)) {
					obs.disconnect();
					resolve(true);
					return;
				}
				setTimeout(check, 50);
			};
			setTimeout(check, 80);
		} catch {
			resolve(true);
		}
	})`
	var out struct {
		Result struct {
			Value bool `json:"value"`
		} `json:"result"`
	}
	qctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_ = cdp.call(qctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    js,
		"returnByValue": true,
		"awaitPromise":  true,
	}, &out)
}

func (r *Renderer) watchActionEventsWindow(
	ctx context.Context,
	cdp *cdpConn,
	sess *retainedSession,
	events <-chan cdpEvent,
	tracker *actionNavTracker,
	checkedIdx *int,
	window time.Duration,
) error {
	if events == nil || window <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(window)
	defer timer.Stop()
	for !tracker.navStarted && !tracker.sameDocNav {
		select {
		case ev := <-events:
			tracker.handleEvent(ev)
			if err := r.checkPendingNavURLs(ctx, cdp, sess, tracker, checkedIdx); err != nil {
				return err
			}
		case <-timer.C:
			return nil
		case <-cdp.closeCh:
			return cdp.crashError("during interact navigation watch")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *Renderer) finishActionNavigationIfStarted(
	ctx context.Context,
	cdp *cdpConn,
	sess *retainedSession,
	events <-chan cdpEvent,
	tracker *actionNavTracker,
	checkedIdx *int,
) error {
	if events == nil {
		return nil
	}
	if err := r.checkPendingNavURLs(ctx, cdp, sess, tracker, checkedIdx); err != nil {
		return err
	}
	if tracker.navStarted {
		loadTimer := time.NewTimer(actionNavLoadTimeout)
		for !tracker.loadFired {
			select {
			case ev := <-events:
				tracker.handleEvent(ev)
				if err := r.checkPendingNavURLs(ctx, cdp, sess, tracker, checkedIdx); err != nil {
					loadTimer.Stop()
					return err
				}
			case <-loadTimer.C:
				tracker.loadFired = true
			case <-cdp.closeCh:
				loadTimer.Stop()
				return cdp.crashError("during interact Page.loadEventFired wait")
			case <-ctx.Done():
				loadTimer.Stop()
				return ctx.Err()
			}
		}
		loadTimer.Stop()

		// Brief post-load network quiescence (bounded to 1.2s, 200ms quiet window).
		idleDeadline := time.Now().Add(1200 * time.Millisecond)
		idleSince := time.Time{}
		if len(tracker.inFlight) == 0 {
			idleSince = time.Now()
		}
		tick := time.NewTicker(40 * time.Millisecond)
		for {
			now := time.Now()
			for id, started := range tracker.inFlight {
				if now.Sub(started) > staleInFlightTTL {
					delete(tracker.inFlight, id)
				}
			}
			if len(tracker.inFlight) == 0 {
				if idleSince.IsZero() {
					idleSince = now
				}
				if now.Sub(idleSince) >= 200*time.Millisecond {
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
				tracker.handleEvent(ev)
				if err := r.checkPendingNavURLs(ctx, cdp, sess, tracker, checkedIdx); err != nil {
					tick.Stop()
					return err
				}
				if len(tracker.inFlight) > 0 {
					idleSince = time.Time{}
				}
			case <-tick.C:
			case <-cdp.closeCh:
				tick.Stop()
				return cdp.crashError("during interact network quiescence")
			case <-ctx.Done():
				tick.Stop()
				return ctx.Err()
			}
		}
		tick.Stop()
		waitForActionDOMQuiescence(ctx, cdp, tracker.sessionID)
		if tracker.docStatus > 0 {
			sess.setResponseMeta(tracker.docStatus, tracker.docHeaders)
		}
		return nil
	}
	if tracker.sameDocNav {
		waitForActionDOMQuiescence(ctx, cdp, tracker.sessionID)
	}
	return nil
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
	_, err := r.runActionStep(ctx, cdp, sess, events, 0, act, actionScreenshots, actionScrapes, jsReturns, pdfBase64)
	return err
}

func (r *Renderer) runActionStep(
	ctx context.Context,
	cdp *cdpConn,
	sess *retainedSession,
	events <-chan cdpEvent,
	index int,
	act InteractAction,
	actionScreenshots *[]string,
	actionScrapes *[]ActionScrapeSnapshot,
	jsReturns *[]ActionJSReturn,
	pdfBase64 *string,
) (ActionResult, error) {
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

	var beforeSnap actionDOMSnapshot
	if kind == "click" || kind == "press" {
		beforeSnap = captureActionDOMState(ctx, cdp, sess.cdpSessionID)
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
			if err := waitForCSSSelector(ctx, cdp, sess.cdpSessionID, act.Selector, time.Duration(ms)*time.Millisecond); err != nil {
				return ActionResult{}, err
			}
			return ActionResult{Index: index, Type: kind, Status: "ok", DOMChanged: true}, nil
		}
		t := time.NewTimer(time.Duration(ms) * time.Millisecond)
		defer t.Stop()
		select {
		case <-t.C:
			return ActionResult{Index: index, Type: kind, Status: "ok"}, nil
		case <-ctx.Done():
			return ActionResult{}, ctx.Err()
		}

	case "navigate":
		prevURL := sess.getLastCheckedURL()
		u, err := url.Parse(strings.TrimSpace(act.URL))
		if err != nil {
			return ActionResult{}, err
		}
		if r.allow != nil {
			if err := r.allow(u); err != nil {
				return ActionResult{}, err
			}
		}
		if r.CheckRobots != nil {
			if err := r.CheckRobots(ctx, u.String()); err != nil {
				return ActionResult{}, err
			}
		}
		sess.setLastCheckedURL(u.String())
		navOrigin := canonicalURLOrigin(u.String())
		sess.mu.Lock()
		if sess.initialOrigin == "" {
			sess.initialOrigin = navOrigin
		}
		if sess.initialOrigin != "" && navOrigin != sess.initialOrigin {
			sess.redirectedCrossOrigin = true
		}
		sess.mu.Unlock()
		st, hdrs, err := navigateAndWait(ctx, cdp, sess, events, u.String(), effectiveWaitMs, act.Selector)
		if err != nil {
			return ActionResult{}, err
		}
		sess.setResponseMeta(st, hdrs)
		return ActionResult{
			Index:      index,
			Type:       kind,
			Status:     "ok",
			URLChanged: u.String() != prevURL,
			DOMChanged: true,
			FinalURL:   u.String(),
		}, nil

	case "click":
		if strings.TrimSpace(act.Selector) == "" {
			return ActionResult{}, errors.New("click action requires selector")
		}
		tracker := newActionNavTracker(sess)
		checkedIdx := 0
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
			return ActionResult{}, err
		}
		if res != "ok" {
			return ActionResult{}, fmt.Errorf("click %s: %s", act.Selector, res)
		}
		if err := r.watchActionEventsWindow(ctx, cdp, sess, events, tracker, &checkedIdx, actionNavWatchWindow); err != nil {
			return ActionResult{}, err
		}
		if err := r.finishActionNavigationIfStarted(ctx, cdp, sess, events, tracker, &checkedIdx); err != nil {
			return ActionResult{}, err
		}

	case "write":
		if effectiveVal != "" {
			if err := cdp.call(ctx, sess.cdpSessionID, "Input.insertText", map[string]any{"text": effectiveVal}, nil); err != nil {
				return ActionResult{}, err
			}
		}

	case "fill", "type", "select":
		if strings.TrimSpace(act.Selector) == "" {
			return ActionResult{}, fmt.Errorf("%s action requires selector", kind)
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
			return ActionResult{}, err
		}
		if res != "ok" {
			return ActionResult{}, fmt.Errorf("%s %s: %s", kind, act.Selector, res)
		}

	case "press":
		spec := resolveCDPKeySpec(act.Key)
		tracker := newActionNavTracker(sess)
		checkedIdx := 0
		if strings.TrimSpace(act.Selector) != "" {
			_, _ = evalString(ctx, cdp, sess.cdpSessionID, fmt.Sprintf(`(() => { document.querySelector(%s)?.focus(); return "ok"; })()`, string(selJSON)))
		}
		if spec.key == "Enter" && ctx.Err() == nil {
			_, _ = evalString(ctx, cdp, sess.cdpSessionID, `(() => {
				window.__efEnterDefaultPrevented = false;
				window.__efEnterBeforeHref = String(location.href || "");
				const mark = (e) => { if (e && e.defaultPrevented) window.__efEnterDefaultPrevented = true; };
				window.addEventListener("keydown", mark, { once: true });
				window.addEventListener("keypress", mark, { once: true });
				return "ok";
			})()`)
		}
		downType := "keyDown"
		if spec.text != "" {
			downType = "rawKeyDown"
		}
		downParams := map[string]any{"type": downType, "key": spec.key}
		if spec.code != "" {
			downParams["code"] = spec.code
		}
		if spec.vk > 0 {
			downParams["windowsVirtualKeyCode"] = spec.vk
			downParams["nativeVirtualKeyCode"] = spec.vk
		}
		_ = cdp.call(ctx, sess.cdpSessionID, "Input.dispatchKeyEvent", downParams, nil)
		if spec.text != "" {
			charParams := map[string]any{
				"type":           "char",
				"key":            spec.key,
				"text":           spec.text,
				"unmodifiedText": spec.text,
			}
			if spec.code != "" {
				charParams["code"] = spec.code
			}
			if spec.vk > 0 {
				charParams["windowsVirtualKeyCode"] = spec.vk
				charParams["nativeVirtualKeyCode"] = spec.vk
			}
			_ = cdp.call(ctx, sess.cdpSessionID, "Input.dispatchKeyEvent", charParams, nil)
		}
		upParams := map[string]any{"type": "keyUp", "key": spec.key}
		if spec.code != "" {
			upParams["code"] = spec.code
		}
		if spec.vk > 0 {
			upParams["windowsVirtualKeyCode"] = spec.vk
			upParams["nativeVirtualKeyCode"] = spec.vk
		}
		_ = cdp.call(ctx, sess.cdpSessionID, "Input.dispatchKeyEvent", upParams, nil)

		remWatch := actionNavWatchWindow
		if spec.key == "Enter" && events != nil {
			firstSlice := enterSubmitFallbackDelay
			if firstSlice > remWatch {
				firstSlice = remWatch
			}
			if err := r.watchActionEventsWindow(ctx, cdp, sess, events, tracker, &checkedIdx, firstSlice); err != nil {
				return ActionResult{}, err
			}
			remWatch -= firstSlice
			if !tracker.navStarted && !tracker.sameDocNav && ctx.Err() == nil {
				_, _ = evalString(ctx, cdp, sess.cdpSessionID, `(() => {
					if (window.__efEnterDefaultPrevented) return "prevented";
					if (window.__efEnterBeforeHref && String(location.href || "") !== window.__efEnterBeforeHref) return "navigating";
					const el = document.activeElement;
					if (!el || !el.tagName) return "no_active";
					const tag = el.tagName.toUpperCase();
					if (tag !== "INPUT" && tag !== "SELECT" && tag !== "BUTTON") return "not_control";
					if (tag === "BUTTON" && el.type && el.type.toLowerCase() !== "submit") return "non_submit_btn";
					if (tag === "INPUT") {
						const it = (el.type || "text").toLowerCase();
						if (it === "button" || it === "reset" || it === "checkbox" || it === "radio" || it === "file") return "non_submit_input";
					}
					const form = el.form || (el.closest ? el.closest("form") : null);
					if (!form) return "no_form";
					if (typeof form.requestSubmit === "function") {
						form.requestSubmit();
					} else {
						form.submit();
					}
					return "submitted";
				})()`)
			}
		}
		if remWatch > 0 {
			if err := r.watchActionEventsWindow(ctx, cdp, sess, events, tracker, &checkedIdx, remWatch); err != nil {
				return ActionResult{}, err
			}
		}
		if err := r.finishActionNavigationIfStarted(ctx, cdp, sess, events, tracker, &checkedIdx); err != nil {
			return ActionResult{}, err
		}

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
			return ActionResult{}, err
		}
		if shot.Data != "" && actionScreenshots != nil {
			*actionScreenshots = append(*actionScreenshots, shot.Data)
		}

	case "scrape":
		snapHTML, snapURL, err := readDocumentHTML(ctx, cdp, sess.cdpSessionID)
		if err != nil {
			return ActionResult{}, err
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
			return ActionResult{}, errors.New("executeJavascript action requires script")
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
			return ActionResult{}, err
		}
		if evalRes.ExceptionDetails != nil {
			return ActionResult{}, fmt.Errorf("js exception: %s", evalRes.ExceptionDetails.Text)
		}
		if jsReturns != nil {
			*jsReturns = append(*jsReturns, ActionJSReturn{Type: evalRes.Result.Type, Value: evalRes.Result.Value})
		}

	case "pdf":
		var pdfOut struct {
			Data string `json:"data"`
		}
		if err := cdp.call(ctx, sess.cdpSessionID, "Page.printToPDF", map[string]any{"printBackground": true}, &pdfOut); err != nil {
			return ActionResult{}, err
		}
		if pdfBase64 != nil && pdfOut.Data != "" {
			*pdfBase64 = pdfOut.Data
		}

	default:
		return ActionResult{}, fmt.Errorf("unsupported interact action type %q", act.Type)
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
	case <-ctx.Done():
		return ActionResult{}, ctx.Err()
	}

	resDiag := ActionResult{
		Index:  index,
		Type:   kind,
		Status: "ok",
	}
	switch kind {
	case "fill", "type", "select":
		resDiag.DOMChanged = true
	case "write":
		resDiag.DOMChanged = effectiveVal != ""
	case "click", "press":
		afterSnap := captureActionDOMState(ctx, cdp, sess.cdpSessionID)
		if afterSnap.ok {
			if afterSnap.url != "" {
				resDiag.FinalURL = afterSnap.url
			}
			if beforeSnap.ok {
				resDiag.URLChanged = afterSnap.url != beforeSnap.url
				resDiag.DOMChanged = afterSnap.digest != beforeSnap.digest
				if resDiag.URLChanged && afterSnap.url != "" {
					if vErr := r.validateFinalURL(ctx, sess, afterSnap.url, beforeSnap.url); vErr != nil {
						return ActionResult{}, vErr
					}
				}
				if !resDiag.URLChanged && !resDiag.DOMChanged {
					resDiag.Status = "no_effect"
					resDiag.Warning = "action completed without changing URL or visible DOM"
				}
			} else {
				resDiag.DOMChanged = true
			}
		} else {
			resDiag.DOMChanged = true
		}
	}
	return resDiag, nil
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
	return buildChromiumLaunchArgsWithSandbox(proxyAddr, userDir, true)
}

func buildChromiumLaunchArgsWithSandbox(proxyAddr, userDir string, useSandbox bool) []string {
	proxyFlag := "--proxy-server=http://" + proxyAddr
	profileFlag := "--user-data-dir=" + userDir
	args := []string{
		"--headless=new",
	}
	if !useSandbox {
		args = append(args,
			"--no-sandbox",
			"--disable-setuid-sandbox",
			"--disable-gpu-sandbox",
		)
	}
	args = append(args,
		"--disable-dev-shm-usage",
		"--disable-crash-reporter",
		"--disable-breakpad",
		"--disable-extensions",
		"--disable-component-extensions-with-background-pages",
		"--disable-background-networking",
		"--disable-domain-reliability",
		"--disable-client-side-phishing-detection",
		"--disable-sync",
		"--disable-translate",
		"--disable-default-apps",
		"--disable-quic",
		"--media-router=0",
		"--disable-features=TranslateUI,MediaRouter,DialMediaRouteProvider,CastMediaRouteProvider,CastStreamingWin,GlobalMediaControls,NetworkTimeServiceQuerying,OptimizationHints",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--enforce-webrtc-ip-permission-check",
		"--autoplay-policy=user-gesture-required",
		"--mute-audio",
		"--no-first-run",
		"--no-default-browser-check",
		"--hide-scrollbars",
		proxyFlag,
		"--proxy-bypass-list=<-loopback>",
		"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
		profileFlag,
	)
	// R6 Zero-TCP Pipe Transport: Use inherited OS pipes (FD 3 / FD 4) on Linux, macOS, and Windows so neither Go nor
	// Chromium ever opens a listening TCP DevTools socket (eliminating loopback /json/version and bridge races).
	args = append(args, "--remote-debugging-pipe")
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

func isSandboxStartupFailureText(s string) bool {
	lower := strings.ToLower(s)
	for _, phrase := range []string{
		"no usable sandbox",
		"without --no-sandbox is not supported",
		"failed to move to new namespace",
		"setuid sandbox is not running as root",
		"suid sandbox helper binary was found, but is not configured correctly",
		"namespace sandbox failed",
	} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	if !strings.Contains(lower, ":fatal:") {
		return false
	}
	// Require EPERM/EACCES on :fatal: lines so transient EMFILE ("Too many open files") or ENOMEM in credentials.cc
	// never permanently latches r.sandboxFallback = true (--no-sandbox).
	if !strings.Contains(lower, "operation not permitted") && !strings.Contains(lower, "permission denied") {
		return false
	}
	for _, marker := range []string{
		"zygote_host_impl_linux",
		"sandbox_linux",
		"sandbox_host_linux",
		"credentials.cc",
		"setuid sandbox",
		"namespace sandbox",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isLinuxSnapWrapper(binPath string) bool {
	if strings.Contains(binPath, "/snap/") {
		return true
	}
	if resolved, err := filepath.EvalSymlinks(binPath); err == nil && strings.Contains(resolved, "/snap/") {
		return true
	}
	st, err := os.Stat(binPath)
	if err != nil || st.IsDir() || st.Size() > 8192 {
		return false
	}
	raw, err := os.ReadFile(binPath)
	if err != nil {
		return false
	}
	s := string(raw)
	return strings.HasPrefix(s, "#!") && (strings.Contains(s, "snap run ") || strings.Contains(s, "/snap/bin/"))
}

func isLinuxProcessZombieOrDead(pid int) bool {
	if runtime.GOOS != "linux" || pid <= 0 {
		return false
	}
	raw, err := readProcFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	rparen := bytes.LastIndexByte(raw, ')')
	if rparen < 0 || rparen+2 >= len(raw) {
		return false
	}
	rest := strings.Fields(string(raw[rparen+1:]))
	return len(rest) > 0 && (rest[0] == "Z" || rest[0] == "X" || rest[0] == "x")
}

func isSandboxStartupFailure(err error) bool {
	if err == nil {
		return false
	}
	return isSandboxStartupFailureText(err.Error())
}

func linuxSandboxBlockedByHostPolicy() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if attr, err := readProcFile("/proc/self/attr/current"); err == nil {
		attrLower := strings.ToLower(strings.TrimSpace(string(attr)))
		if strings.Contains(attrLower, "edgefetch_fat") ||
			strings.HasPrefix(attrLower, "edgefetch ") ||
			strings.Contains(attrLower, "_edgefetch ") ||
			strings.HasSuffix(attrLower, "_edgefetch") ||
			attrLower == "edgefetch" {
			return true
		}
	}
	if cloneVal, err := readProcFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(cloneVal)) == "0" {
			return true
		}
	}
	return false
}

func (r *Renderer) launchAndDialPipeLocked(ctx context.Context, userDir string, args []string, startupWait time.Duration) (*exec.Cmd, string, *cdpConn, error) {
	cmd, toChromeWrite, fromChromeRead, stderr, err := startBrowserPipeProcess(r.chromeBin, args, buildSanitizedChildEnv(userDir))
	if err != nil {
		_ = os.RemoveAll(userDir)
		return nil, "", nil, err
	}

	var (
		connHolder     atomic.Pointer[cdpConn]
		earlyCrashMu   sync.Mutex
		earlyCrash     string
		closePipesOnce sync.Once
	)
	closePipes := func() {
		closePipesOnce.Do(func() {
			_ = toChromeWrite.Close()
			_ = fromChromeRead.Close()
			_ = stderr.Close()
		})
	}
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			txt := sc.Text()
			if c := connHolder.Load(); c != nil {
				c.setCrashReason(txt)
			} else {
				earlyCrashMu.Lock()
				earlyCrash = startupReason(earlyCrash, txt)
				earlyCrashMu.Unlock()
				if strings.Contains(txt, ":FATAL:") || isSandboxStartupFailureText(txt) {
					_ = toChromeWrite.Close()
					_ = fromChromeRead.Close()
				}
			}
		}
		_, _ = io.Copy(io.Discard, stderr)
	}()

	var teardownOnce sync.Once
	conn := newPipeCDPConn(toChromeWrite, fromChromeRead, func() {
		teardownOnce.Do(func() {
			_ = toChromeWrite.Close()
			_ = fromChromeRead.Close()
			select {
			case <-stderrDone:
			case <-time.After(250 * time.Millisecond):
			}
			closePipes()
			if c := connHolder.Load(); c != nil {
				earlyCrashMu.Lock()
				ec := earlyCrash
				earlyCrashMu.Unlock()
				if ec != "" {
					c.setCrashReason(ec)
				}
			}
		})
	})

	probeCtx, probeCancel := context.WithTimeout(ctx, startupWait)
	probeDone := make(chan struct{})
	var probeWG sync.WaitGroup
	if cmd.Process != nil {
		pid := cmd.Process.Pid
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-probeDone:
					return
				case <-probeCtx.Done():
					return
				case <-ticker.C:
					if isLinuxProcessZombieOrDead(pid) {
						_ = conn.close()
						return
					}
				}
			}
		}()
	}
	var verOut struct {
		Product string `json:"product"`
	}
	probeErr := conn.call(probeCtx, "", "Browser.getVersion", nil, &verOut)
	close(probeDone)
	probeCancel()
	probeWG.Wait()
	if probeErr != nil {
		_ = conn.close()
		closePipes()
		killBrowserProcessGroup(cmd)
		_ = os.RemoveAll(userDir)
		if ctx.Err() != nil {
			return nil, "", nil, ctx.Err()
		}
		select {
		case <-stderrDone:
		case <-time.After(250 * time.Millisecond):
		}
		earlyCrashMu.Lock()
		reason := earlyCrash
		earlyCrashMu.Unlock()
		if errors.Is(probeErr, context.DeadlineExceeded) && reason == "" {
			return nil, "", nil, errors.New("timed out waiting for chromium DevTools endpoint")
		}
		msg := "chromium exited before advertising DevTools pipe endpoint"
		if reason != "" {
			msg += ": " + reason
		} else {
			msg += ": " + probeErr.Error()
		}
		return nil, "", nil, errors.New(msg)
	}
	if prod := strings.TrimSpace(verOut.Product); prod != "" {
		r.browserVersion = prod
	}
	_ = os.Remove(filepath.Join(userDir, "DevToolsActivePort"))
	earlyCrashMu.Lock()
	if earlyCrash != "" {
		conn.setCrashReason(earlyCrash)
	}
	earlyCrashMu.Unlock()
	connHolder.Store(conn)
	return cmd, userDir, conn, nil
}

func (r *Renderer) launchAndDialLocked(ctx context.Context, proxyAddr string, useSandbox bool, startupWait time.Duration) (*exec.Cmd, string, *cdpConn, error) {
	userDir, err := os.MkdirTemp("", "edgefetch-chrome-*")
	if err != nil {
		return nil, "", nil, err
	}
	if err := hardenUserDataDir(userDir); err != nil {
		_ = os.RemoveAll(userDir)
		return nil, "", nil, err
	}

	args := buildChromiumLaunchArgsWithSandbox(proxyAddr, userDir, useSandbox)
	if len(r.extraFlags) > 0 {
		// Insert test-only flags before the trailing "about:blank" positional argument.
		tail := args[len(args)-1]
		args = append(append([]string(nil), args[:len(args)-1]...), r.extraFlags...)
		args = append(args, tail)
	}
	return r.launchAndDialPipeLocked(ctx, userDir, args, startupWait)
}

func (r *Renderer) canFallbackToNoSandboxLocked() bool {
	return !r.requireSandbox && r.allowNoSandbox
}

func (r *Renderer) ensureBrowser(ctx context.Context) (*cdpConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("renderer closed")
	}
	if r.disabledByPolicy {
		return nil, ErrBrowserUnavailable
	}
	if r.cdp != nil && !r.cdp.isClosed() {
		if !(r.taintedByHeaders && r.activeRuns <= 1 && len(r.sessions) == 0) {
			return r.cdp, nil
		}
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

	useSandbox := true
	if runtime.GOOS == "linux" {
		if !r.sandboxFallback && linuxSandboxBlockedByHostPolicy() {
			if !r.canFallbackToNoSandboxLocked() {
				r.sandboxState = "off"
				r.disabledByPolicy = true
				if r.log != nil {
					r.log.Warn("browser_sandbox_disabled",
						slog.String("bin", r.chromeBin),
						slog.String("reason", "host MAC/userns policy blocks the Chromium sandbox; enable allow_no_sandbox_browser: true in Home Assistant add-on Configuration, mount deploy/seccomp/chromium-sandbox.json, or set EDGEFETCH_ALLOW_NO_SANDBOX=1"))
				}
				if r.requireSandbox {
					return nil, errors.New("chromium OS sandbox unavailable under host MAC/userns policy and EDGEFETCH_REQUIRE_BROWSER_SANDBOX is set")
				}
				return nil, errors.New("chromium OS sandbox unavailable under host MAC/userns policy (enable allow_no_sandbox_browser: true on Home Assistant OS, configure deploy/seccomp/chromium-sandbox.json, or set EDGEFETCH_ALLOW_NO_SANDBOX=1)")
			}
			r.sandboxFallback = true
			r.sandboxState = "off"
			if r.log != nil {
				r.log.Warn("browser_sandbox_fallback",
					slog.String("bin", r.chromeBin),
					slog.String("reason", "host MAC/userns policy blocks the Chromium sandbox (pre-check; EDGEFETCH_ALLOW_NO_SANDBOX=1)"))
			}
		}
		useSandbox = !r.sandboxFallback
	}

	proxy, err := NewSSRFProxy(r.allow, r.proxyDial)
	if err != nil {
		return nil, err
	}

	waitBudget := 25 * time.Second
	firstAttemptWait := waitBudget
	if useSandbox && runtime.GOOS == "linux" {
		if dl, ok := ctx.Deadline(); ok {
			if half := time.Until(dl) / 2; half > 2*time.Second && half < firstAttemptWait {
				firstAttemptWait = half
			}
		}
	}
	cmd, userDir, conn, launchErr := r.launchAndDialLocked(ctx, proxy.Addr(), useSandbox, firstAttemptWait)
	if launchErr != nil && runtime.GOOS == "linux" && useSandbox && ctx.Err() == nil &&
		(isSandboxStartupFailure(launchErr) || (r.canFallbackToNoSandboxLocked() && strings.Contains(launchErr.Error(), "before advertising DevTools"))) {
		if !r.canFallbackToNoSandboxLocked() {
			r.sandboxState = "off"
			r.disabledByPolicy = true
			_ = proxy.Close()
			if r.log != nil {
				r.log.Warn("browser_sandbox_disabled",
					slog.String("bin", r.chromeBin),
					slog.String("reason", launchErr.Error()))
			}
			if r.requireSandbox {
				return nil, fmt.Errorf("chromium OS sandbox failed and EDGEFETCH_REQUIRE_BROWSER_SANDBOX is set: %w", launchErr)
			}
			return nil, fmt.Errorf("chromium OS sandbox failed (configure deploy/seccomp/chromium-sandbox.json or set EDGEFETCH_ALLOW_NO_SANDBOX=1): %w", launchErr)
		}
		r.sandboxFallback = true
		r.sandboxState = "off"
		if r.log != nil {
			r.log.Warn("browser_sandbox_fallback",
				slog.String("bin", r.chromeBin),
				slog.String("reason", launchErr.Error()))
		}
		useSandbox = false
		cmd, userDir, conn, launchErr = r.launchAndDialLocked(ctx, proxy.Addr(), false, waitBudget)
	}
	if launchErr != nil {
		_ = proxy.Close()
		return nil, launchErr
	}

	if useSandbox {
		r.sandboxState = "on"
	} else {
		r.sandboxState = "off"
	}

	var verOut struct {
		Product string `json:"product"`
	}
	vctx, vcancel := context.WithTimeout(ctx, 2*time.Second)
	if vErr := conn.call(vctx, "", "Browser.getVersion", nil, &verOut); vErr == nil {
		if prod := strings.TrimSpace(verOut.Product); prod != "" {
			r.browserVersion = prod
		}
	}
	vcancel()

	r.proxy = proxy
	r.cmd = cmd
	r.userDataDir = userDir
	r.cdp = conn
	r.lastUsedAt = time.Now()
	if r.log != nil {
		r.log.Info("browser_started",
			slog.String("bin", r.chromeBin),
			slog.String("proxy", proxy.Addr()),
			slog.String("sandbox", r.sandboxState),
			slog.String("version", r.browserVersion))
	}
	go r.idleReaperLoop(conn)
	return conn, nil
}

func (r *Renderer) idleReaperLoop(target *cdpConn) {
	ticker := time.NewTicker(idleReaperInterval)
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
					s.stopFetch()
					delete(r.sessions, id)
				}
			}
			if r.activeRuns == 0 && len(r.sessions) == 0 && (r.taintedByHeaders || now.Sub(r.lastUsedAt) >= browserIdleTTL) {
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
		s.stopFetch()
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
		oldest.stopFetch()
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
	for _, s := range r.sessions {
		s.stopFetch()
	}
	r.sessions = make(map[string]*retainedSession)
	r.taintedByHeaders = false
	if r.cdp != nil {
		_ = r.cdp.close()
		r.cdp = nil
	}
	if r.cmd != nil {
		killBrowserProcessGroup(r.cmd)
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
	if strings.Contains(line, ":FATAL:") || isSandboxStartupFailureText(line) {
		return line
	}
	if strings.Contains(current, ":FATAL:") || isSandboxStartupFailureText(current) {
		return current
	}
	return line
}
