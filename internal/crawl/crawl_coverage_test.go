package crawl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/botauth"
	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
	"github.com/bartrumb/edgefetch/v2/internal/politeness"
	"github.com/coder/websocket"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type errReader struct {
	prefix []byte
	sent   bool
	err    error
}

func (e *errReader) Read(p []byte) (int, error) {
	if !e.sent && len(e.prefix) > 0 {
		e.sent = true
		n := copy(p, e.prefix)
		if n < len(e.prefix) {
			e.prefix = e.prefix[n:]
			e.sent = false
		}
		return n, nil
	}
	return 0, e.err
}

func (e *errReader) Close() error { return nil }

func makeMinimalValidPDF(text string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	o1 := b.Len()
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	o2 := b.Len()
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	o3 := b.Len()
	b.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n")
	o4 := b.Len()
	b.WriteString("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
	stream := fmt.Sprintf("BT /F1 12 Tf 72 720 Td (%s) Tj ET\n", text)
	o5 := b.Len()
	fmt.Fprintf(&b, "5 0 obj\n<< /Length %d >>\nstream\n%sendstream\nendobj\n", len(stream), stream)
	xref := b.Len()
	b.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for _, off := range []int{o1, o2, o3, o4, o5} {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return b.Bytes()
}

func TestCrawlHelpersNormalizationCapabilitiesAndCheckRobots(t *testing.T) {
	// DecodeBody empty.
	if b, err := (Result{}).DecodeBody(); err != nil || b != nil {
		t.Fatalf("expected nil,nil from empty DecodeBody, got %v %v", b, err)
	}

	// Options.Normalize out-of-range clamps.
	normLow := (Options{
		PauseMs:       -1,
		PauseJitterMs: -5,
		GapMs:         -10,
		Concurrency:   -1,
		TimeoutMs:     0,
		MaxBytes:      0,
		MaxTotalBytes: 0,
		Retries:       -2,
	}).Normalize()
	if normLow.PauseMs != DefaultPauseMs || normLow.PauseJitterMs != 0 || normLow.GapMs != 0 ||
		normLow.Concurrency != 1 || normLow.TimeoutMs != DefaultTimeoutMs ||
		normLow.MaxBytes != DefaultMaxBytes || normLow.MaxTotalBytes != DefaultMaxTotalBytes || normLow.Retries != 0 {
		t.Fatalf("unexpected low Normalize: %+v", normLow)
	}
	normHigh := (Options{
		PauseMs:       5000,
		PauseJitterMs: MaxPauseJitterMs + 100,
		GapMs:         100,
		Concurrency:   MaxConcurrency + 10,
		TimeoutMs:     MaxTimeoutMs + 1000,
		MaxBytes:      MaxMaxBytes + 1000,
		MaxTotalBytes: MaxMaxTotalBytes + 1000,
		Retries:       MaxRetries + 5,
	}).Normalize()
	if normHigh.PauseJitterMs != MaxPauseJitterMs || normHigh.Concurrency != MaxConcurrency ||
		normHigh.TimeoutMs != MaxTimeoutMs || normHigh.MaxBytes != MaxMaxBytes ||
		normHigh.MaxTotalBytes != MaxMaxTotalBytes || normHigh.Retries != MaxRetries {
		t.Fatalf("unexpected high Normalize: %+v", normHigh)
	}

	// ValidateUserAgent empty & >256.
	if err := ValidateUserAgent("   "); err == nil {
		t.Fatal("expected error for blank UA")
	}
	if err := ValidateUserAgent(strings.Repeat("a", 257)); err == nil {
		t.Fatal("expected error for >256 UA")
	}

	// NewCrawler defaults (nil allow, blank UA, Jitter, CheckRobots closure).
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cDefault := NewCrawler(nil, nil, "  ", silentLog)
	defer cDefault.Close()
	if cDefault.userAgent != DefaultUserAgent {
		t.Fatalf("expected DefaultUserAgent, got %q", cDefault.userAgent)
	}
	httpU, _ := url.Parse("http://example.com/")
	if err := cDefault.allow(httpU); err == nil {
		t.Fatal("expected default PublicHTTPS allow to reject http://")
	}
	if cDefault.Jitter(0) != 0 {
		t.Fatal("expected Jitter(0) == 0")
	}
	if j := cDefault.Jitter(10 * time.Millisecond); j < 0 || j > 10*time.Millisecond {
		t.Fatalf("Jitter out of range: %v", j)
	}

	// Nil receiver guards for Close, BrowserInfo, AllowsRobotsBypass, hostStateFor lazy init.
	if err := ((*Crawler)(nil)).Close(); err != nil {
		t.Fatal(err)
	}
	if err := (&Crawler{}).Close(); err != nil {
		t.Fatal(err)
	}
	if v, sb := ((*Crawler)(nil)).BrowserInfo(); v != "" || sb != "" {
		t.Fatal("expected empty BrowserInfo on nil crawler")
	}
	if ((*Crawler)(nil)).AllowsRobotsBypass("a.com") || cDefault.AllowsRobotsBypass("  .") {
		t.Fatal("expected AllowsRobotsBypass false")
	}
	if hs := (&Crawler{Now: time.Now}).hostStateFor("a.test"); hs == nil {
		t.Fatal("expected lazy hostStateFor init")
	}

	// Capabilities: bare, with MockRenderer + BotSigner, and with mock pdftotext in PATH.
	if caps := (&Crawler{}).Capabilities(); len(caps) != 1 || caps[0] != "artifacts-v1" {
		t.Fatalf("expected [artifacts-v1], got %v", caps)
	}
	kp, err := botauth.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := botauth.NewSigner(kp.PrivateKeySeedB64URL, "https://bot.example.com/dir")
	if err != nil {
		t.Fatal(err)
	}
	cCaps, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /priv\nAllow: /\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	robChecker := cCaps.renderer.CheckRobots
	cCaps.SetRenderer(browser.NewMockRenderer("ws://127.0.0.1:1", nil, DefaultUserAgent))
	cCaps.SetBotSigner(signer)
	if v, sb := cCaps.BrowserInfo(); v != "" || sb != "" {
		t.Logf("BrowserInfo=%q %q", v, sb)
	}
	pdfBinDir := t.TempDir()
	pdfScript := filepath.Join(pdfBinDir, "pdftotext")
	if err := os.WriteFile(pdfScript, []byte("#!/bin/sh\necho 'poppler extracted text'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pdfBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	capsStr := strings.Join(cCaps.Capabilities(), ",")
	if !strings.Contains(capsStr, "artifacts-v1") || !strings.Contains(capsStr, "browser-v1") || !strings.Contains(capsStr, "pdf-v1") || !strings.Contains(capsStr, "bot-auth-v1") {
		t.Fatalf("expected all 4 capabilities, got %q", capsStr)
	}

	// Test r.CheckRobots closure wired in NewCrawler (Acquire err, disallowed, allowed).
	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	hsCheck := cCaps.hostStateFor("rob.test")
	_ = hsCheck.Acquire(context.Background())
	if err := robChecker(cancelledCtx, "http://rob.test/ok"); err == nil {
		hsCheck.Release()
		t.Fatal("expected Acquire error on cancelled ctx in CheckRobots")
	}
	hsCheck.Release()
	if err := robChecker(context.Background(), "http://rob.test/priv"); err == nil {
		t.Fatal("expected disallow error from CheckRobots")
	}
	if err := robChecker(context.Background(), "http://rob.test/public"); err != nil {
		t.Fatalf("expected allow nil from CheckRobots, got %v", err)
	}

	// SleepCtx, waitGlobalGap, bumpGlobalThrottle, notTried, rateLimitedCooldownResult, hostOf, isPermanentFetchError, extractSafeResponseHeaders, backoff.
	if err := SleepCtx(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := SleepCtx(cancelledCtx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Canceled from SleepCtx, got %v", err)
	}

	fixedNow := time.Unix(1700000000, 0)
	var gapSleeps []time.Duration
	cGap := &Crawler{
		Now:   func() time.Time { return fixedNow },
		Sleep: func(_ context.Context, d time.Duration) error { gapSleeps = append(gapSleeps, d); return nil },
		Jitter: func(d time.Duration) time.Duration {
			return d / 2
		},
	}
	cGap.bumpGlobalThrottle(0)
	cGap.bumpGlobalThrottle(10 * time.Second)
	cGap.bumpGlobalThrottle(2 * time.Second) // smaller does not shrink globalNext
	if !cGap.globalNext.Equal(fixedNow.Add(10 * time.Second)) {
		t.Fatalf("unexpected globalNext: %v", cGap.globalNext)
	}
	cGap.globalNext = time.Time{}
	_ = cGap.waitGlobalGap(context.Background(), 0)
	_ = cGap.waitGlobalGap(context.Background(), 50*time.Millisecond)
	_ = cGap.waitGlobalGap(context.Background(), 50*time.Millisecond)
	if len(gapSleeps) != 1 || gapSleeps[0] != 50*time.Millisecond {
		t.Fatalf("expected [50ms] gap sleeps, got %v", gapSleeps)
	}
	cGap.backoff(context.Background(), 5)
	if gapSleeps[1] != 2500*time.Millisecond+(7500*time.Millisecond)/2 {
		t.Fatalf("expected backoff attempt 5 clamped to 10s base, got %v", gapSleeps[1])
	}

	if nt := notTried(Request{ID: "a"}, "why"); nt.Kind != classify.KindPage || nt.Outcome != classify.OutcomeNotTried {
		t.Fatalf("unexpected notTried: %+v", nt)
	}
	if rl := rateLimitedCooldownResult(Request{ID: "a"}, 500); rl.Kind != classify.KindPage || rl.Status != 429 || rl.Outcome != classify.OutcomeStop {
		t.Fatalf("unexpected rateLimitedCooldownResult: %+v", rl)
	}
	if got := hostOf("://bad"); got != "://bad" {
		t.Fatalf("expected hostOf(\"://bad\") == \"://bad\", got %q", got)
	}
	if got := hostOf("/relative/path"); got != "" {
		t.Fatalf("expected hostOf(\"/relative/path\") == \"\", got %q", got)
	}
	if isPermanentFetchError(nil) {
		t.Fatal("isPermanentFetchError(nil) should be false")
	}
	if extractSafeResponseHeaders(nil) != nil {
		t.Fatal("extractSafeResponseHeaders(nil) should be nil")
	}
	if got := extractSafeResponseHeaders(http.Header{"Server": {"   "}}); got != nil {
		t.Fatalf("expected nil for whitespace-only header, got %v", got)
	}
	truncHdr := extractSafeResponseHeaders(http.Header{"Link": {strings.Repeat("a", 510) + "€€"}})
	if len(truncHdr["link"]) != 510 {
		t.Fatalf("expected UTF-8 rune-boundary truncation at 510 bytes, got %d", len(truncHdr["link"]))
	}

	// resolveMaxStreamingPDFBytes env clamps & MaxBytes > MaxStreamingPDFBytes.
	t.Setenv("EDGEFETCH_MAX_PDF_BYTES", "100")
	if got := resolveMaxStreamingPDFBytes(Options{}); got != 1024 {
		t.Fatalf("expected 1024 clamp, got %d", got)
	}
	t.Setenv("EDGEFETCH_MAX_PDF_BYTES", "999999999")
	if got := resolveMaxStreamingPDFBytes(Options{}); got != 256<<20 {
		t.Fatalf("expected 256<<20 clamp, got %d", got)
	}
	t.Setenv("EDGEFETCH_MAX_PDF_BYTES", "")
	if got := resolveMaxStreamingPDFBytes(Options{MaxBytes: 100 << 20}); got != MaxStreamingPDFBytes {
		t.Fatalf("expected MaxStreamingPDFBytes, got %d", got)
	}
}

func TestCrawlRunWithSinkRedirectsRenderAndErrorPaths(t *testing.T) {
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))

	// 1. RunWithSink ctx.Done() in dispatch loop with remMs > 0 + same-host stopped == "crawl cancelled" with remMs > 0 + sink != nil.
	var c1 *Crawler
	c1, _ = newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	now1 := time.Unix(1700000000, 0)
	c1.Now = func() time.Time { return now1 }
	ctx1, cancel1 := context.WithCancel(context.Background())
	c1.Sleep = func(_ context.Context, d time.Duration) error {
		if d > 0 {
			c1.hostStateFor("h1.test").NoteRateLimit(now1, 10*time.Second)
			cancel1()
			return context.Canceled
		}
		return nil
	}
	c1.hostStateFor("h2.test").NoteRateLimit(now1, 10*time.Second)

	var sinkCalls atomic.Int32
	res1 := c1.RunWithSink(ctx1, []Request{
		{ID: "1", URL: "http://h1.test/one", Kind: classify.KindPage},
		{ID: "2", URL: "http://h1.test/two", Kind: classify.KindPage},
		{ID: "3", URL: "http://h1.test/three", Kind: classify.KindPage},
		{ID: "4", URL: "http://h2.test/queued", Kind: classify.KindPage},
	}, Options{Concurrency: 1, PauseMs: 10, RespectRobots: Bool(false)}, silentLog, func(i int, r Result) Result {
		sinkCalls.Add(1)
		r.Body = ""
		return r
	})
	if sinkCalls.Load() == 0 || res1[2].Outcome != classify.OutcomeStop || res1[3].Outcome != classify.OutcomeStop {
		t.Fatalf("expected 429 cooldown stop results on cancelled batch, got %+v", res1)
	}

	// 1b. Deterministic RunWithSink ctx.Done() with remMs == 0: host 1 holds sem inside sink until host 2 hits ctx.Done().
	var (
		cDet          *Crawler
		detCancelling atomic.Bool
		detHost2Done  = make(chan struct{})
		detHost2Once  sync.Once
	)
	cDet, _ = newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>det</html>"))
	}))
	detNow := time.Unix(1700000100, 0)
	cDet.Now = func() time.Time {
		if detCancelling.Load() {
			detHost2Once.Do(func() { close(detHost2Done) })
		}
		return detNow
	}
	detCtx, detCancel := context.WithCancel(context.Background())
	resDet := cDet.RunWithSink(detCtx, []Request{
		{ID: "d1", URL: "http://det1.test/one", Kind: classify.KindPage},
		{ID: "d2", URL: "http://det2.test/two", Kind: classify.KindPage},
	}, Options{Concurrency: 1, RespectRobots: Bool(false)}, silentLog, func(i int, r Result) Result {
		if i == 0 {
			detCancelling.Store(true)
			detCancel()
			select {
			case <-detHost2Done:
			case <-time.After(2 * time.Second):
			}
		}
		return r
	})
	if len(resDet) != 2 || resDet[0].Outcome != classify.OutcomeOK ||
		resDet[1].Outcome != classify.OutcomeNotTried || resDet[1].Problem != "crawl cancelled" {
		t.Fatalf("expected deterministic crawl cancelled notTried on host 2 with remMs==0, got %+v", resDet)
	}

	// 2. runRequestWithRedirects pre-flight KindRender branches:
	//    - origReq.Kind == ""
	//    - resumed/close-session Interact with empty URL
	//    - Acquire fail (remMs > 0 and == 0)
	//    - CheckCircuit open (5 transient errors)
	//    - CrawlDelay + PauseJitterMs + WaitDelay + c.Sleep fail (remMs > 0 and == 0) + waitGlobalGap fail (remMs > 0 and == 0)
	//    - distressed robots (500 on /robots.txt -> OutcomeStop)
	c2, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			switch r.Host {
			case "cd.test":
				_, _ = w.Write([]byte("User-agent: *\nCrawl-delay: 2\n"))
			case "rob500.test":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	var cdpSawFetchEnable atomic.Bool
	cdpRenderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			_, raw, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var req struct {
				ID        int64  `json:"id"`
				SessionID string `json:"sessionId"`
				Method    string `json:"method"`
			}
			if json.Unmarshal(raw, &req) != nil {
				continue
			}
			if req.Method == "Fetch.enable" {
				cdpSawFetchEnable.Store(true)
			}
			send := func(v any) {
				b, _ := json.Marshal(v)
				_ = conn.Write(r.Context(), websocket.MessageText, b)
			}
			switch req.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-1"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-1"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-1"}})
			case "Page.navigate":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f1"}})
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Runtime.evaluate":
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": `{"url":"https://cd.test/p","html":"<html><body>ok</body></html>"}`}}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpRenderSrv.Close()
	c2.SetRenderer(browser.NewMockRenderer("ws://"+strings.TrimPrefix(cdpRenderSrv.URL, "http://"), nil, DefaultUserAgent))

	// origReq.Kind == ""
	rEmptyKind, _ := c2.runRequestWithRedirects(context.Background(), Request{ID: "ek", URL: "http://ok.test/1"}, Options{}.Normalize(), false, time.Millisecond, 0, 0, silentLog)
	if rEmptyKind.Kind != classify.KindPage {
		t.Fatalf("expected default KindPage, got %+v", rEmptyKind)
	}

	// CloseSession Interact with empty URL.
	resClose := c2.Run(context.Background(), []Request{{
		ID:       "cs",
		Kind:     classify.KindRender,
		Interact: &InteractSpec{SessionID: "s-none", CloseSession: true},
	}}, Options{RespectRobots: Bool(true)})
	if resClose[0].Outcome != classify.OutcomeOK {
		t.Fatalf("expected CloseSession ok, got %+v", resClose[0])
	}

	// KindRender Acquire fail (remMs == 0 and remMs > 0).
	hsAcq := c2.hostStateFor("acq.test")
	_ = hsAcq.Acquire(context.Background())
	cCancel, cancelAcq := context.WithCancel(context.Background())
	cancelAcq()
	rAcq0, _ := c2.runRequestWithRedirects(cCancel, Request{ID: "a0", URL: "http://acq.test/1", Kind: classify.KindRender}, Options{}.Normalize(), false, time.Millisecond, 0, 0, silentLog)
	hsAcq.NoteRateLimit(c2.Now(), 5*time.Second)
	rAcqRem, _ := c2.runRequestWithRedirects(cCancel, Request{ID: "a1", URL: "http://acq.test/1", Kind: classify.KindRender}, Options{}.Normalize(), false, time.Millisecond, 0, 0, silentLog)
	hsAcq.Release()
	if rAcq0.Outcome != classify.OutcomeNotTried || rAcqRem.Outcome != classify.OutcomeStop {
		t.Fatalf("unexpected Acquire fail outcomes: %+v / %+v", rAcq0, rAcqRem)
	}

	// KindRender CheckCircuit open.
	hsCirc := c2.hostStateFor("circ.test")
	for i := 0; i < 6; i++ {
		hsCirc.RecordOutcome(c2.Now(), 0, 0, 502, false, true)
	}
	rCirc, _ := c2.runRequestWithRedirects(context.Background(), Request{ID: "c", URL: "http://circ.test/1", Kind: classify.KindRender}, Options{}.Normalize(), false, time.Millisecond, 0, 0, silentLog)
	if rCirc.Outcome != classify.OutcomeError {
		t.Fatalf("expected circuit open error, got %+v", rCirc)
	}

	// KindRender CrawlDelay + PauseJitterMs + WaitDelay + c.Sleep fail & waitGlobalGap fail (with/without NoteRateLimit).
	resCD := c2.Run(context.Background(), []Request{
		{ID: "cd1", URL: "http://cd.test/1", Kind: classify.KindRender},
		{ID: "cd2", URL: "http://cd.test/2", Kind: classify.KindRender},
	}, Options{PauseMs: 1, PauseJitterMs: 50, GapMs: 10})
	if len(resCD) != 2 || resCD[0].Outcome != classify.OutcomeOK || resCD[1].Outcome != classify.OutcomeOK {
		t.Fatalf("expected 2 OK results for cd.test crawl delay run, got %+v", resCD)
	}

	// Sleep failure on KindRender host wait (remMs == 0 and remMs > 0) and on waitGlobalGap.
	c2.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	c2.hostStateFor("slp.test").RecordOutcome(c2.Now(), 5*time.Second, 0, 200, false, false)
	rSlp0, _ := c2.runRequestWithRedirects(context.Background(), Request{ID: "s0", URL: "http://slp.test/1", Kind: classify.KindRender}, Options{}.Normalize(), true, time.Millisecond, 0, 0, silentLog)
	c2.hostStateFor("slp.test").NoteRateLimit(c2.Now(), 5*time.Second)
	rSlpRem, _ := c2.runRequestWithRedirects(context.Background(), Request{ID: "sr", URL: "http://slp.test/2", Kind: classify.KindRender}, Options{}.Normalize(), true, time.Millisecond, 0, 0, silentLog)
	if rSlp0.Outcome != classify.OutcomeNotTried || rSlpRem.Outcome != classify.OutcomeStop {
		t.Fatalf("unexpected KindRender sleep fail outcomes: %+v / %+v", rSlp0, rSlpRem)
	}

	c2.Sleep = func(_ context.Context, d time.Duration) error {
		if d > 0 {
			return context.Canceled
		}
		return nil
	}
	c2.globalNext = c2.Now().Add(time.Second)
	rGap0, _ := c2.runRequestWithRedirects(context.Background(), Request{ID: "g0", URL: "http://gap0.test/1", Kind: classify.KindRender}, Options{}.Normalize(), false, 0, 0, 20*time.Millisecond, silentLog)
	c2.hostStateFor("gapr.test").NoteRateLimit(c2.Now(), 5*time.Second)
	c2.globalNext = c2.Now().Add(time.Second)
	rGapRem, _ := c2.runRequestWithRedirects(context.Background(), Request{ID: "gr", URL: "http://gapr.test/1", Kind: classify.KindRender}, Options{}.Normalize(), false, 0, 0, 20*time.Millisecond, silentLog)
	if rGap0.Outcome != classify.OutcomeNotTried || rGapRem.Outcome != classify.OutcomeStop {
		t.Fatalf("unexpected KindRender gap fail outcomes: %+v / %+v", rGap0, rGapRem)
	}
	c2.Sleep = func(context.Context, time.Duration) error { return nil }
	c2.globalNext = time.Time{}

	// Distressed robots on KindRender -> OutcomeStop.
	rRobStop := c2.Run(context.Background(), []Request{{ID: "rs", URL: "http://rob500.test/p", Kind: classify.KindRender}}, Options{PauseMs: 1})
	if rRobStop[0].Outcome != classify.OutcomeStop {
		t.Fatalf("expected OutcomeStop on 500 /robots.txt for KindRender, got %+v", rRobStop[0])
	}

	// 3. HTTP loop edge cases: invalid URL parse, hop>0 c.allow reject, Acquire fail remMs==0, CheckCircuit open,
	//    WaitDelay > waitDur, Sleep fail (remMs==0 & >0), waitGlobalGap fail (remMs==0 & >0),
	//    hop==MaxRedirects (>5 redirects), invalid redirect Location, anyBotSigned across redirect, gap>0 + 429 Retry-After: 30,
	//    renderMode: "auto" cross-origin redirect stripping Headers & copying ResponseHeaders!
	var (
		cAuto       *Crawler
		redirTarget string
	)
	cAuto, _ = newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/to-blocked":
			http.Redirect(w, r, "http://127.0.0.1/bad", http.StatusFound)
		case "/bad-loc":
			w.Header().Set("Location", "http://[::1]:bad")
			w.WriteHeader(http.StatusFound)
		case "/loop":
			hopN, _ := strconv.Atoi(r.URL.Query().Get("n"))
			http.Redirect(w, r, fmt.Sprintf("/loop?n=%d", hopN+1), http.StatusFound)
		case "/bot-hop0":
			cAuto.SetBotSigner(nil)
			http.Redirect(w, r, "/bot-hop1", http.StatusFound)
		case "/bot-hop1":
			_, _ = w.Write([]byte("<html>signed-on-hop0</html>"))
		case "/429-ra":
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		case "/auto-redir":
			http.Redirect(w, r, redirTarget, http.StatusFound)
		case "/spa":
			w.Header().Set("Server", "edge")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>`))
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	redirTarget = "http://b.test/spa"
	cAuto.allow = func(u *url.URL) error {
		if u.Hostname() == "127.0.0.1" {
			return errors.New("loopback blocked")
		}
		return nil
	}
	cAuto.SetRenderer(browser.NewMockRenderer("ws://"+strings.TrimPrefix(cdpRenderSrv.URL, "http://"), nil, DefaultUserAgent))

	// url.Parse failure.
	rParse, _ := cAuto.runRequestWithRedirects(context.Background(), Request{ID: "p", URL: "http://[::1]:bad", Kind: classify.KindPage}, Options{RespectRobots: Bool(false)}.Normalize(), false, time.Millisecond, 0, 0, silentLog)
	if rParse.Outcome != classify.OutcomeError {
		t.Fatalf("expected parse err, got %+v", rParse)
	}
	// hop>0 allow rejection.
	rHopAllow := cAuto.Run(context.Background(), []Request{{ID: "ha", URL: "http://a.test/to-blocked", Kind: classify.KindPage}}, Options{PauseMs: 1})
	if rHopAllow[0].Outcome != classify.OutcomeError || !strings.Contains(rHopAllow[0].Problem, "loopback blocked") {
		t.Fatalf("expected redirect allow err, got %+v", rHopAllow[0])
	}
	// >5 redirects & invalid redirect Location.
	rMore5 := cAuto.Run(context.Background(), []Request{{ID: "m5", URL: "http://a.test/loop?n=0", Kind: classify.KindPage}}, Options{PauseMs: 1})
	if !strings.Contains(rMore5[0].Problem, "more than 5 redirects") {
		t.Fatalf("expected >5 redirects error, got %+v", rMore5[0])
	}
	rBadLoc := cAuto.Run(context.Background(), []Request{{ID: "bl", URL: "http://a.test/bad-loc", Kind: classify.KindPage}}, Options{PauseMs: 1})
	if rBadLoc[0].Outcome != classify.OutcomeError || !strings.Contains(rBadLoc[0].Problem, "Location") {
		t.Fatalf("expected invalid redirect Location error, got %+v", rBadLoc[0])
	}

	// anyBotSigned across redirect.
	kp2, _ := botauth.GenerateKeyPair()
	signer2, _ := botauth.NewSigner(kp2.PrivateKeySeedB64URL, "https://bot.example.com/dir")
	cAuto.SetBotSigner(signer2)
	rBotRedir := cAuto.Run(context.Background(), []Request{{ID: "br", URL: "http://bot.test/bot-hop0", Kind: classify.KindPage}}, Options{PauseMs: 1})
	if !rBotRedir[0].botAuthSigned {
		t.Fatalf("expected botAuthSigned preserved across redirect, got %+v", rBotRedir[0])
	}

	// renderMode: "auto" cross-origin redirect strips X-Test before CDP and copies ResponseHeaders.
	cdpSawFetchEnable.Store(false)
	rAuto := cAuto.Run(context.Background(), []Request{{
		ID:         "auto",
		URL:        "http://a.test/auto-redir",
		Kind:       classify.KindScrape,
		RenderMode: "auto",
		Headers:    map[string]string{"X-Test": "1"},
	}}, Options{PauseMs: 1})
	if !rAuto[0].Rendered || rAuto[0].ResponseHeaders["server"] != "edge" {
		t.Fatalf("expected auto render with copied ResponseHeaders, got %+v", rAuto[0])
	}
	if cdpSawFetchEnable.Load() {
		t.Fatal("expected cross-origin renderMode=auto redirect to strip X-Test before CDP (Fetch.enable must not be called)")
	}

	// gap>0 + 429 Retry-After: 30 -> bumpGlobalThrottle.
	r429 := cAuto.Run(context.Background(), []Request{{ID: "ra", URL: "http://ra.test/429-ra", Kind: classify.KindPage}}, Options{PauseMs: 1, GapMs: 25})
	if r429[0].Status != 429 {
		t.Fatalf("expected 429 status, got %+v", r429[0])
	}

	// HTTP loop Acquire fail remMs==0, CheckCircuit open (5 502s), WaitDelay > waitDur, Sleep fail & waitGlobalGap fail.
	hsHAcq := cAuto.hostStateFor("hacq.test")
	_ = hsHAcq.Acquire(context.Background())
	rHAcq0, _ := cAuto.runRequestWithRedirects(cCancel, Request{ID: "ha0", URL: "http://hacq.test/1", Kind: classify.KindPage}, Options{RespectRobots: Bool(false)}.Normalize(), false, time.Millisecond, 0, 0, silentLog)
	hsHAcq.Release()
	if rHAcq0.Outcome != classify.OutcomeNotTried {
		t.Fatalf("expected HTTP Acquire notTried, got %+v", rHAcq0)
	}

	for i := 0; i < 6; i++ {
		_ = cAuto.Run(context.Background(), []Request{{ID: "502", URL: "http://fail502.test/502", Kind: classify.KindPage}}, Options{PauseMs: 1, Retries: 0})
	}
	rCircOpen := cAuto.Run(context.Background(), []Request{{ID: "co", URL: "http://fail502.test/502", Kind: classify.KindPage}}, Options{PauseMs: 1, Retries: 0})
	if !strings.Contains(rCircOpen[0].Problem, "circuit") {
		t.Fatalf("expected circuit open, got %+v", rCircOpen[0])
	}

	cAuto.hostStateFor("wd.test").RecordOutcome(cAuto.Now(), 5*time.Second, 0, 200, false, false)
	cAuto.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	rHSlp0, _ := cAuto.runRequestWithRedirects(context.Background(), Request{ID: "hs0", URL: "http://wd.test/1", Kind: classify.KindPage}, Options{RespectRobots: Bool(false)}.Normalize(), true, time.Millisecond, 0, 0, silentLog)
	cAuto.hostStateFor("wd.test").NoteRateLimit(cAuto.Now(), 5*time.Second)
	rHSlpRem, _ := cAuto.runRequestWithRedirects(context.Background(), Request{ID: "hsr", URL: "http://wd.test/1", Kind: classify.KindPage}, Options{RespectRobots: Bool(false)}.Normalize(), true, time.Millisecond, 0, 0, silentLog)
	if rHSlp0.Outcome != classify.OutcomeNotTried || rHSlpRem.Outcome != classify.OutcomeStop {
		t.Fatalf("expected HTTP sleep fail outcomes, got %+v / %+v", rHSlp0, rHSlpRem)
	}
	cAuto.Sleep = func(_ context.Context, d time.Duration) error {
		if d > 0 {
			return context.Canceled
		}
		return nil
	}
	cAuto.globalNext = cAuto.Now().Add(time.Second)
	rHGap0, _ := cAuto.runRequestWithRedirects(context.Background(), Request{ID: "hg0", URL: "http://hgap0.test/1", Kind: classify.KindPage}, Options{RespectRobots: Bool(false)}.Normalize(), false, 0, 0, 20*time.Millisecond, silentLog)
	cAuto.hostStateFor("hgapr.test").NoteRateLimit(cAuto.Now(), 5*time.Second)
	cAuto.globalNext = cAuto.Now().Add(time.Second)
	rHGapRem, _ := cAuto.runRequestWithRedirects(context.Background(), Request{ID: "hgr", URL: "http://hgapr.test/1", Kind: classify.KindPage}, Options{RespectRobots: Bool(false)}.Normalize(), false, 0, 0, 20*time.Millisecond, silentLog)
	if rHGap0.Outcome != classify.OutcomeNotTried || rHGapRem.Outcome != classify.OutcomeStop {
		t.Fatalf("expected HTTP gap fail outcomes, got %+v / %+v", rHGap0, rHGapRem)
	}
}

func TestCrawlFetchSingleHopPDFStreamDNSAndRobotsEdges(t *testing.T) {
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))

	// 1. Real DNS+TLS httptrace + POST default ContentType + If-Modified-Since 304 + TLS permanent error.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/post":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "bad post", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("post-ok"))
		case "/ims":
			if r.Header.Get("If-Modified-Since") != "" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		default:
			_, _ = w.Write([]byte("<html><body>hello</body></html>"))
		}
	}))
	defer tlsSrv.Close()
	_, port, _ := net.SplitHostPort(tlsSrv.Listener.Addr().String())
	localhostBase := "https://localhost:" + port

	baseTLS := tlsSrv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	baseTLS.ServerName = "example.com"
	trTrust := &http.Transport{
		TLSClientConfig: baseTLS,
	}
	cTLS := NewCrawler(trTrust, func(*url.URL) error { return nil }, DefaultUserAgent, silentLog)
	cTLS.SetRobotsBypassHosts([]string{"localhost"})
	cTLS.Sleep = func(context.Context, time.Duration) error { return nil }

	resTrace := cTLS.Run(context.Background(), []Request{
		{ID: "dns", URL: localhostBase + "/hello", Kind: classify.KindPage},
		{ID: "post", URL: localhostBase + "/post", Method: "POST", RequestBody: `{}`},
		{ID: "ims", URL: localhostBase + "/ims", Kind: classify.KindPage, IfModifiedSince: "Wed, 21 Oct 2015 07:28:00 GMT"},
	}, Options{RespectRobots: Bool(false), PauseMs: 1})
	if resTrace[0].Outcome != classify.OutcomeOK || resTrace[1].Outcome != classify.OutcomeOK || resTrace[2].Status != http.StatusNotModified {
		t.Fatalf("unexpected TLS/DNS/POST/IMS results: %+v", resTrace)
	}

	// Untrusted TLS server -> x509 permanent error not retried (Attempts == 1).
	cUntrusted := NewCrawler(&http.Transport{}, func(*url.URL) error { return nil }, DefaultUserAgent, silentLog)
	cUntrusted.SetRobotsBypassHosts([]string{"127.0.0.1"})
	cUntrusted.Sleep = func(context.Context, time.Duration) error { return nil }
	resUntrusted := cUntrusted.Run(context.Background(), []Request{{ID: "tls-err", URL: tlsSrv.URL + "/hello", Kind: classify.KindPage}}, Options{RespectRobots: Bool(false), Retries: 2})
	if resUntrusted[0].Attempts != 1 || resUntrusted[0].Outcome != classify.OutcomeError {
		t.Fatalf("expected permanent TLS error in 1 attempt, got %+v", resUntrusted[0])
	}

	// 2. fetchSingleHop: empty Kind, invalid Kind, transient fetchErr retry, 429 Strike 2 (ra==0), truncated+cf-mitigated, invalid URL NewRequestWithContext.
	var dropAttempt atomic.Int32
	var strike429 atomic.Int32
	cHop, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/drop1":
			if dropAttempt.Add(1) == 1 {
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, err := hj.Hijack()
					if err == nil {
						_ = conn.Close()
						return
					}
				}
			}
			_, _ = w.Write([]byte("recovered"))
		case "/strike429":
			if strike429.Add(1) <= 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>third-time-ok</html>"))
		case "/cf-trunc":
			w.Header().Set("Cf-Mitigated", "managed")
			_, _ = w.Write([]byte(strings.Repeat("x", 200)))
		}
	}))
	if resBadKind, _, _ := cHop.fetchSingleHop(context.Background(), Request{ID: "bk", Kind: "invalid_kind"}, Options{}); resBadKind.Outcome != classify.OutcomeError {
		t.Fatalf("expected invalid Kind error, got %+v", resBadKind)
	}
	resEmptyHop, _, _ := cHop.fetchSingleHop(context.Background(), Request{ID: "ek", URL: "http://h.test/drop1"}, Options{Retries: 1}.Normalize())
	if resEmptyHop.Outcome != classify.OutcomeOK || resEmptyHop.Attempts != 2 {
		t.Fatalf("expected transient fetchErr recovery on attempt 2, got %+v", resEmptyHop)
	}
	res429, _, _ := cHop.fetchSingleHop(context.Background(), Request{ID: "429", URL: "http://h.test/strike429", Kind: classify.KindPage}, Options{}.Normalize())
	if res429.Outcome != classify.OutcomeOK || res429.Attempts != 3 {
		t.Fatalf("expected 3-strikes 429 recovery on attempt 3, got %+v", res429)
	}
	resCF, _, _ := cHop.fetchSingleHop(context.Background(), Request{ID: "cf", URL: "http://h.test/cf-trunc", Kind: classify.KindPage}, Options{MaxBytes: 50}.Normalize())
	if resCF.Outcome != classify.OutcomeChallenge {
		t.Fatalf("expected OutcomeChallenge on truncated+cf-mitigated, got %+v", resCF)
	}
	if _, _, _, _, _, _, _, _, err := cHop.onceWithPDFStream(context.Background(), Request{URL: "http://\x7f"}, "text/html", Options{}.Normalize()); err == nil {
		t.Fatal("expected NewRequestWithContext error")
	}

	// 3. Streaming PDF paths (corrupt PDF on KindScrape vs KindPDF, valid PDF with Query+RedactPII+Formats[text]+poppler, Content-Length > pdfMax, prefix/copy/tail errors, remBytes < 1).
	validPDF := makeMinimalValidPDF("Battery replacement guide contact user@example.com for support.")
	badPDF := []byte("%PDF-1.7\n%%EOF\n")
	cPDF, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		switch r.URL.Path {
		case "/bad.pdf":
			_, _ = w.Write(badPDF)
		case "/good.pdf":
			_, _ = w.Write(validPDF)
		case "/bigcl.pdf":
			padded := append(append([]byte{}, validPDF...), bytes.Repeat([]byte(" "), 10000)...)
			w.Header().Set("Content-Length", strconv.Itoa(len(padded)))
			_, _ = w.Write(padded)
		case "/big.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(strings.Repeat("H", 2048)))
		case "/stream-chunked.pdf":
			w.Header().Set("Content-Type", "application/pdf")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte("A"), 1024)...))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			_, _ = w.Write([]byte("tail"))
		}
	}))
	resBadScrape, _, _ := cPDF.fetchSingleHop(context.Background(), Request{ID: "bs", URL: "http://pdf.test/bad.pdf", Kind: classify.KindScrape}, Options{}.Normalize())
	resBadPDF, _, _ := cPDF.fetchSingleHop(context.Background(), Request{ID: "bp", URL: "http://pdf.test/bad.pdf", Kind: classify.KindPDF}, Options{}.Normalize())
	if resBadScrape.Outcome != classify.OutcomeError || resBadPDF.Outcome != classify.OutcomeOK || resBadPDF.Problem == "" {
		t.Fatalf("unexpected corrupt PDF outcomes: scrape=%+v pdf=%+v", resBadScrape, resBadPDF)
	}

	// Mock pdftotext in PATH for usedPoppler on streaming PDF + IncludeBody.
	popDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(popDir, "pdftotext"), []byte("#!/bin/sh\necho 'Battery guide contact user@example.com'\n"), 0o755)
	t.Setenv("PATH", popDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	resGoodPDF, _, _ := cPDF.fetchSingleHop(context.Background(), Request{
		ID:        "gp",
		URL:       "http://pdf.test/good.pdf",
		Kind:      classify.KindScrape,
		Query:     "Battery",
		RedactPII: true,
		Formats:   []string{"text"},
	}, Options{IncludeBody: true}.Normalize())
	if resGoodPDF.PDFEngine != "poppler-pdftotext" || resGoodPDF.Text == "" || resGoodPDF.Body == "" {
		t.Fatalf("expected poppler-pdftotext streaming PDF extraction, got %+v", resGoodPDF)
	}

	// Content-Length > pdfMax early cut-off.
	t.Setenv("EDGEFETCH_MAX_PDF_BYTES", "2048")
	resBigCL, _, _ := cPDF.fetchSingleHop(context.Background(), Request{ID: "bcl", URL: "http://pdf.test/bigcl.pdf", Kind: classify.KindPDF}, Options{}.Normalize())
	if !resBigCL.Truncated {
		t.Fatalf("expected Content-Length > pdfMax truncation, got %+v", resBigCL)
	}
	t.Setenv("EDGEFETCH_MAX_PDF_BYTES", "")

	// remBytes < 1 when Options.MaxBytes < len(prefix) on non-PDF KindScrape.
	resRemLT1, _, _ := cPDF.fetchSingleHop(context.Background(), Request{ID: "rem", URL: "http://pdf.test/big.html", Kind: classify.KindScrape}, Options{MaxBytes: 100}.Normalize())
	if !resRemLT1.Truncated {
		t.Fatalf("expected truncated when MaxBytes < 1024 prefix, got %+v", resRemLT1)
	}

	// remLimit < 1 in onceWithPDFStream when EDGEFETCH_MAX_PDF_BYTES is unset, Options.MaxBytes=100, and chunked PDF >= 1024 bytes.
	t.Setenv("EDGEFETCH_MAX_PDF_BYTES", "")
	resPDFRemLT1, _, _ := cPDF.fetchSingleHop(context.Background(), Request{ID: "pdf-rem", URL: "http://pdf.test/stream-chunked.pdf", Kind: classify.KindScrape}, Options{MaxBytes: 100}.Normalize())
	if !resPDFRemLT1.Truncated || resPDFRemLT1.Outcome != classify.OutcomeError {
		t.Fatalf("expected truncated OutcomeError for chunked PDF with MaxBytes=100, got %+v", resPDFRemLT1)
	}

	// Custom RoundTripper errors in onceWithPDFStream: prefix ReadAll err, io.CopyBuffer err after PDF prefix, tail ReadAll err.
	for _, tc := range []struct {
		name string
		kind classify.Kind
		ct   string
		body io.ReadCloser
	}{
		{"prefix_err", classify.KindScrape, "application/pdf", &errReader{err: io.ErrUnexpectedEOF}},
		{"copy_err", classify.KindScrape, "application/pdf", &errReader{prefix: append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte("A"), 1500)...), err: io.ErrUnexpectedEOF}},
		{"tail_err", classify.KindPage, "text/html", &errReader{prefix: []byte("<html>"), err: io.ErrUnexpectedEOF}},
	} {
		cRT := NewCrawler(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": {tc.ct}},
				Body:       tc.body,
			}, nil
		}), func(*url.URL) error { return nil }, DefaultUserAgent, silentLog)
		if _, _, _, _, _, _, _, _, err := cRT.onceWithPDFStream(context.Background(), Request{URL: "https://rt.test/x", Kind: tc.kind}, "*/*", Options{}.Normalize()); err == nil {
			t.Fatalf("%s: expected read error", tc.name)
		}
	}

	// 4. parseRobotsCacheTTL, checkRobots, fetchRobots edge cases.
	if got := parseRobotsCacheTTL(http.Header{"Cache-Control": {`max-age="120"`}}); got != 120*time.Second {
		t.Fatalf("expected 120s for quoted max-age, got %v", got)
	}
	if got := parseRobotsCacheTTL(http.Header{"Cache-Control": {"max-age=999999"}}); got != politeness.RobotsCacheTTL {
		t.Fatalf("expected RobotsCacheTTL clamp, got %v", got)
	}
	if got := parseRobotsCacheTTL(http.Header{"Cache-Control": {"max-age=99999999999999999999999"}}); got != politeness.RobotsCacheTTL {
		t.Fatalf("expected RobotsCacheTTL on overflow, got %v", got)
	}

	cRob := NewCrawler(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	}), func(u *url.URL) error {
		if u.Hostname() == "deny.test" {
			return errors.New("denied")
		}
		return nil
	}, DefaultUserAgent, silentLog)
	hsR := cRob.hostStateFor("r.test")
	if ok, _, _, _ := cRob.checkRobots(context.Background(), hsR, "://bad"); ok {
		t.Fatal("expected url.Parse failure in checkRobots")
	}
	cCancel, cancelRob := context.WithCancel(context.Background())
	cancelRob()
	if ok, dist, _, _ := cRob.checkRobots(cCancel, hsR, "https://r.test/a"); ok || !dist {
		t.Fatal("expected pre-cancelled checkRobots distressed")
	}
	hsR.SetRobots(cRob.Now(), &politeness.RobotsEntry{Distressed: true, Reason: "", ExpiresAt: cRob.Now().Add(time.Minute)}, 0)
	if _, _, _, msg := cRob.checkRobots(context.Background(), hsR, "https://r.test/a"); !strings.Contains(msg, "robots_unreachable:") {
		t.Fatalf("expected default robots_unreachable msg, got %q", msg)
	}
	hsR.SetRobots(cRob.Now(), &politeness.RobotsEntry{Distressed: true, Reason: "503", ExpiresAt: cRob.Now().Add(time.Minute)}, 0)
	if _, _, _, msg := cRob.checkRobots(context.Background(), hsR, "https://r.test/a"); msg != "robots_unreachable: 503" {
		t.Fatalf("expected prefixed msg, got %q", msg)
	}

	// fetchRobots: cancelled ctx, hop-0 allow fail, NewRequest fail, Do timeout.
	if ent, _ := cRob.fetchRobots(cCancel, &url.URL{Scheme: "https", Host: "r.test"}); !ent.Distressed {
		t.Fatal("expected distressed on cancelled fetchRobots")
	}
	if ent, _ := cRob.fetchRobots(context.Background(), &url.URL{Scheme: "https", Host: "deny.test"}); !ent.Distressed {
		t.Fatal("expected distressed on allow fail")
	}
	if ent, _ := cRob.fetchRobots(context.Background(), &url.URL{Scheme: "https", Host: "bad\x7f"}); !ent.Distressed {
		t.Fatal("expected distressed on NewRequest fail")
	}
	if ent, _ := cRob.fetchRobots(context.Background(), &url.URL{Scheme: "https", Host: "timeout.test"}); !ent.Distressed || !strings.Contains(ent.Reason, "timed out") {
		t.Fatalf("expected timeout distressed reason, got %+v", ent)
	}

	// fetchRobots HTTP status branches via httptest: 302 missing Location, 302 bad Location, 300 status, >1 MiB zero-newline body.
	cRobHTTP, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "noloc.test":
			w.WriteHeader(http.StatusFound)
		case "badloc.test":
			w.Header().Set("Location", "://bad")
			w.WriteHeader(http.StatusFound)
		case "s300.test":
			w.WriteHeader(http.StatusMultipleChoices)
		case "hugeline.test":
			_, _ = w.Write(bytes.Repeat([]byte("a"), politeness.RobotsMaxBytes+16))
		}
	}))
	for _, h := range []string{"noloc.test", "badloc.test", "s300.test"} {
		if ent, _ := cRobHTTP.fetchRobots(context.Background(), &url.URL{Scheme: "http", Host: h}); !ent.Distressed {
			t.Fatalf("%s: expected distressed robots entry, got %+v", h, ent)
		}
	}
	if ent, _ := cRobHTTP.fetchRobots(context.Background(), &url.URL{Scheme: "http", Host: "hugeline.test"}); ent.Distressed {
		t.Fatalf("expected non-distressed empty parse on >1MiB single-line robots.txt, got %+v", ent)
	}
}

func TestCrawlLLMsScrapeAndServerHandlers(t *testing.T) {
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))

	// 1. ValidateCustomHeaders >16 headers & >2048 bytes.
	manyHdrs := map[string]string{}
	for i := 0; i < 17; i++ {
		manyHdrs[fmt.Sprintf("X-H-%d", i)] = "v"
	}
	if err := ValidateCustomHeaders(manyHdrs); err == nil {
		t.Fatal("expected too many headers error")
	}
	bigHdrs := map[string]string{
		"X-Big-1": strings.Repeat("a", 1100),
		"X-Big-2": strings.Repeat("b", 1100),
	}
	if err := ValidateCustomHeaders(bigHdrs); err == nil {
		t.Fatal("expected headers exceed 2048 bytes error")
	}

	// 2. llmsCache expiry & eviction at 512.
	lc := newLlmsCache()
	baseT := time.Unix(1700000000, 0)
	lc.set("exp.test", nil, baseT.Add(time.Minute))
	if _, ok := lc.get("exp.test", baseT.Add(2*time.Minute)); ok {
		t.Fatal("expected expired llmsCache entry removed")
	}
	for i := 0; i < maxCachedLlmsHosts+5; i++ {
		lc.set(fmt.Sprintf("h%d.test", i), nil, baseT.Add(time.Hour))
	}
	if len(lc.entries) != maxCachedLlmsHosts {
		t.Fatalf("expected llmsCache capped at %d, got %d", maxCachedLlmsHosts, len(lc.entries))
	}

	// 3. shouldDiscoverLlms, runAuxiliaryFetch, discoverHostLlms, tryFetchCompanionMarkdown, enrichResult.
	if shouldDiscoverLlms(Request{Kind: classify.KindScrape}, Options{DiscoverLlms: Bool(false)}) {
		t.Fatal("expected opts.DiscoverLlms=false honored")
	}

	validPDF := makeMinimalValidPDF("Battery repair guide email test@example.com.")
	llmsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/llms.txt":
			_, _ = w.Write([]byte("# Docs\n> Site summary\n- [404 Md](https://docs.test/missing.md): missing\n- [Short](https://docs.test/short.md): short\n- [Soft404](https://docs.test/soft404.md): html\n- [Blocked](http://127.0.0.1/bad.md): blocked\n"))
		case "/missing.md":
			w.WriteHeader(http.StatusNotFound)
		case "/short.md":
			_, _ = w.Write([]byte("short"))
		case "/soft404.md":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<!doctype html><html><body>Not found page padding text here</body></html>"))
		case "/guide.md":
			w.Header().Set("Content-Type", "text/markdown")
			_, _ = w.Write([]byte("# Battery Guide\nThis battery repair manual explains contact support@example.com in detail so it exceeds twenty four characters easily. " + strings.Repeat("More battery details. ", 15) + "\n"))
		case "/guide":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Guide</title><meta name="theme-color" content="#123456"></head><body><main><h1>Guide</h1><img src="/a.png" alt="pic"><p>Body text</p></main></body></html>`))
		case "/plain":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Battery info contact plain@example.com."))
		case "/bin":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte{0x01, 0x02, 0x03})
		case "/mem.pdf":
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write(validPDF)
		case "/badmem.pdf":
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte("%PDF-1.7\n%%EOF\n"))
		}
	}))
	defer llmsSrv.Close()
	llmsAddr := llmsSrv.Listener.Addr().String()
	llmsTLS := llmsSrv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	llmsTLS.InsecureSkipVerify = true
	cLlms := NewCrawler(&http.Transport{
		TLSClientConfig: llmsTLS,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, llmsAddr)
		},
	}, func(u *url.URL) error {
		if u.Hostname() == "127.0.0.1" {
			return errors.New("blocked")
		}
		return nil
	}, DefaultUserAgent, silentLog)
	cLlms.Sleep = func(context.Context, time.Duration) error { return nil }
	defer cLlms.Close()

	if _, _, ok := cLlms.runAuxiliaryFetch(context.Background(), "://bad", "text/markdown", 1024, Options{}.Normalize()); ok {
		t.Fatal("expected invalid URL in runAuxiliaryFetch false")
	}
	if _, _, ok := cLlms.runAuxiliaryFetch(context.Background(), "http://127.0.0.1/bad.md", "text/markdown", 1024, Options{}.Normalize()); ok {
		t.Fatal("expected blocked URL in runAuxiliaryFetch false")
	}
	if cLlms.discoverHostLlms(context.Background(), "ftp://x", Options{}.Normalize()) != nil {
		t.Fatal("expected nil discoverHostLlms for ftp://")
	}
	if cLlms.discoverHostLlms(context.Background(), "https://docs.test/llms.txt", Options{}.Normalize()) != nil {
		t.Fatal("expected nil discoverHostLlms for /llms.txt itself")
	}
	if _, ok := cLlms.tryFetchCompanionMarkdown(context.Background(), "", Options{}.Normalize()); ok {
		t.Fatal("expected false for empty mdURL")
	}
	for _, p := range []string{"/missing.md", "/short.md", "/soft404.md"} {
		if _, ok := cLlms.tryFetchCompanionMarkdown(context.Background(), "https://docs.test"+p, Options{}.Normalize()); ok {
			t.Fatalf("expected false for companion %s", p)
		}
	}

	// Put mock pdftotext in PATH so in-memory PDF extraction in enrichResult covers usedPoppler (while failing on tiny badmem.pdf).
	popDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(popDir, "pdftotext"), []byte("#!/bin/sh\nif [ \"$(wc -c)\" -lt 50 ]; then exit 1; fi\necho 'Battery repair guide contact test@example.com'\n"), 0o755)
	t.Setenv("PATH", popDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// enrichResult: KindScrape with OnlyMainContent=false, Formats=[markdown, text, links, images, branding, base64], Query, RedactPII, CandidateCompanionMarkdownURL fallback.
	resRich := cLlms.Run(context.Background(), []Request{
		{
			ID:              "guide",
			URL:             "https://docs.test/guide",
			Kind:            classify.KindScrape,
			OnlyMainContent: Bool(false),
			Formats:         []string{"markdown", "text", "links", "images", "branding", "base64"},
			Query:           "battery",
			RedactPII:       true,
		},
		{
			ID:        "plain",
			URL:       "https://docs.test/plain",
			Kind:      classify.KindText,
			Accept:    "text/plain",
			Formats:   []string{"text"},
			Query:     "Battery",
			RedactPII: true,
		},
		{
			ID:   "bin",
			URL:  "https://docs.test/bin",
			Kind: classify.KindBinary,
		},
		{
			ID:        "mempdf",
			URL:       "https://docs.test/mem.pdf",
			Kind:      classify.KindPDF,
			Formats:   []string{"markdown", "text", "base64"}, // base64 disables streaming -> hits in-memory isPDF in enrichResult!
			Query:     "Battery",
			RedactPII: true,
		},
		{
			ID:      "badmempdf",
			URL:     "https://docs.test/badmem.pdf",
			Kind:    classify.KindPDF,
			Formats: []string{"markdown", "base64"},
		},
	}, Options{PauseMs: 1})
	if !resRich[0].Llms.UsedCompanionMd || resRich[0].Text == "" || len(resRich[0].Images) == 0 || resRich[0].Branding == nil || resRich[0].BodyBase64 == "" {
		t.Fatalf("expected rich guide enrichment, got %+v", resRich[0])
	}
	if resRich[1].Text == "" || resRich[2].SHA256 == "" || resRich[2].BodyBase64 == "" {
		t.Fatalf("unexpected plain/bin results: %+v / %+v", resRich[1], resRich[2])
	}
	if resRich[3].PDFEngine == "" || resRich[3].Text == "" || resRich[4].Problem == "" {
		t.Fatalf("unexpected in-memory PDF results: %+v / %+v", resRich[3], resRich[4])
	}

	// 4. runBrowserStep error/edge paths via MockRenderer + custom CDP WS.
	var (
		cdpModeMu sync.Mutex
		cdpMode   string
	)
	cdpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			_, raw, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var req struct {
				ID        int64  `json:"id"`
				SessionID string `json:"sessionId"`
				Method    string `json:"method"`
			}
			if json.Unmarshal(raw, &req) != nil {
				continue
			}
			send := func(v any) {
				b, _ := json.Marshal(v)
				_ = conn.Write(r.Context(), websocket.MessageText, b)
			}
			cdpModeMu.Lock()
			m := cdpMode
			cdpModeMu.Unlock()
			switch req.Method {
			case "Target.createBrowserContext":
				send(map[string]any{"id": req.ID, "result": map[string]any{"browserContextId": "bc-b"}})
			case "Target.createTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"targetId": "tgt-b"}})
			case "Target.attachToTarget":
				send(map[string]any{"id": req.ID, "result": map[string]any{"sessionId": "s-b"}})
			case "Page.navigate":
				if m == "err" {
					send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "error": map[string]any{"code": -1, "message": "nav fail"}})
					continue
				}
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"frameId": "f1"}})
				send(map[string]any{"sessionId": req.SessionID, "method": "Page.loadEventFired", "params": map[string]any{}})
			case "Runtime.evaluate":
				u, h := "https://b.test/ok", "<html><body><main>ok</main></body></html>"
				switch m {
				case "challenge":
					h = `<html><head><title>Just a moment...</title></head><body><div class="cf-turnstile"></div></body></html>`
				case "blocked_final":
					u = "http://127.0.0.1/secret"
				case "huge":
					h = strings.Repeat("Z", 128)
				case "empty":
					h = ""
				}
				docJSON, _ := json.Marshal(map[string]string{"url": u, "html": h})
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{"result": map[string]any{"type": "string", "value": string(docJSON)}}})
			default:
				send(map[string]any{"id": req.ID, "sessionId": req.SessionID, "result": map[string]any{}})
			}
		}
	}))
	defer cdpSrv.Close()

	cBr := NewCrawler(http.DefaultTransport, func(u *url.URL) error {
		if u.Hostname() == "127.0.0.1" {
			return errors.New("loopback blocked")
		}
		return nil
	}, DefaultUserAgent, silentLog)
	cBr.SetRenderer(nil)
	if rUnavail := cBr.runBrowserStep(context.Background(), Request{ID: "u", URL: "https://b.test/"}, Options{TimeoutMs: 5000, MaxBytes: 4096}, time.Now()); rUnavail.Outcome != classify.OutcomeError {
		t.Fatalf("expected ErrBrowserUnavailable, got %+v", rUnavail)
	}

	cBr.SetRenderer(browser.NewMockRenderer("ws://"+strings.TrimPrefix(cdpSrv.URL, "http://"), nil, DefaultUserAgent))
	rInteract := cBr.runBrowserStep(context.Background(), Request{
		ID:       "int",
		URL:      "https://b.test/",
		Kind:     classify.KindRender,
		Interact: &InteractSpec{KeepSession: true, Actions: []browser.InteractAction{{Type: "wait", WaitMs: 1}}},
	}, Options{TimeoutMs: 5000, MaxBytes: 4096, IncludeBody: true}, time.Now())
	if rInteract.Outcome != classify.OutcomeOK || rInteract.Body == "" || rInteract.SessionID == "" {
		t.Fatalf("expected Interact runBrowserStep ok with body & SessionID, got %+v", rInteract)
	}

	for _, tc := range []struct {
		mode string
		url  string
		want classify.Outcome
		maxB int
	}{
		{"challenge", "", classify.OutcomeChallenge, 4096},
		{"err", "https://b.test/", classify.OutcomeError, 4096},
		{"blocked_final", "", classify.OutcomeError, 4096},
		{"huge", "", classify.OutcomeError, 32},
		{"empty", "", classify.OutcomeOK, 4096},
	} {
		cdpModeMu.Lock()
		cdpMode = tc.mode
		cdpModeMu.Unlock()
		req := Request{ID: tc.mode, URL: tc.url, Kind: classify.KindRender}
		if tc.url == "" {
			req.Interact = &InteractSpec{Actions: []browser.InteractAction{{Type: "wait", WaitMs: 1}}}
		}
		got := cBr.runBrowserStep(context.Background(), req, Options{TimeoutMs: 5000, MaxBytes: tc.maxB}, time.Now())
		if got.Outcome != tc.want {
			t.Fatalf("mode %s: expected outcome %s, got %+v", tc.mode, tc.want, got)
		}
	}

	// 5. server.go: PublicHTTPS space host, WithAllowedHosts, WithBlockedHost, normalizeHostRule,
	//    ValidateCall, ValidateCallWithCrawler, ExecuteCall, ExecuteCallWithSink, ExecuteCallWithTrace (MaxSeconds>Max, empty traceSpanID),
	//    NewAuthenticatedHandler (405/401/bad_json), CallLogger.
	spaceURL := &url.URL{Scheme: "https", Host: "foo bar.com", Path: "/"}
	if err := PublicHTTPS(spaceURL); err == nil {
		t.Fatal("expected PublicHTTPS to reject hostname with space")
	}
	if WithAllowedHosts(PublicHTTPS, []string{"", "*", "[]", "none"}) == nil {
		t.Fatal("expected base returned for empty allowed hosts")
	}
	allowSub := WithAllowedHosts(PublicHTTPS, []string{"https://sub.example.com/path"})
	otherU, _ := url.Parse("https://other.example.com/")
	if err := allowSub(otherU); err == nil {
		t.Fatal("expected allowSub to reject other.example.com")
	}
	httpOtherU, _ := url.Parse("http://sub.example.com/")
	if err := allowSub(httpOtherU); err == nil {
		t.Fatal("expected base(u) error on http://")
	}
	if WithBlockedHost(PublicHTTPS, "none") == nil {
		t.Fatal("expected base returned for 'none'")
	}
	if err := WithBlockedHost(PublicHTTPS, "hub.example.com")(httpOtherU); err == nil {
		t.Fatal("expected base(u) error in WithBlockedHost")
	}

	if _, _, ok := ValidateCall(FetchCall{}, PublicHTTPS); ok {
		t.Fatal("expected ValidateCall to fail on 0 requests")
	}
	if _, _, ok := ValidateCallWithCrawler(nil, FetchCall{Requests: []Request{{ID: "1", URL: "https://a.example.com/", Kind: "bad_kind"}}}, PublicHTTPS); ok {
		t.Fatal("expected bad_kind")
	}
	if code, _, ok := ValidateCallWithCrawler(nil, FetchCall{
		Requests: []Request{{ID: "1", Kind: classify.KindRender, Interact: &InteractSpec{SessionID: "s1"}}},
		Options:  Options{RespectRobots: Bool(false)},
	}, PublicHTTPS); ok || code != "robots_required" {
		t.Fatalf("expected robots_required for resumed interact, got %s %v", code, ok)
	}
	if _, _, ok := ValidateCallWithCrawler(nil, FetchCall{
		Requests: []Request{{
			ID:       "1",
			Kind:     classify.KindRender,
			Interact: &InteractSpec{SessionID: "s1", Actions: []browser.InteractAction{{Type: "navigate", URL: "http://bad.example.com/"}}},
		}},
	}, PublicHTTPS); ok {
		t.Fatal("expected bad_url for interact navigate action")
	}
	if _, _, ok := ValidateCallWithCrawler(nil, FetchCall{
		Requests: []Request{{
			ID:       "1",
			Kind:     classify.KindRender,
			Interact: &InteractSpec{SessionID: "s1", Actions: []browser.InteractAction{{Type: "navigate", URL: "https://good.example.com/"}}},
		}},
	}, PublicHTTPS); !ok {
		t.Fatal("expected valid resumed interact with valid navigate action")
	}

	// ExecuteCall, ExecuteCallWithSink, ExecuteCallWithTrace (MaxSeconds > MaxMaxSeconds + OutcomeNotTried fallback span timings).
	cSrv, _ := newTestCrawler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/402" {
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	otelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer otelSrv.Close()
	exp := otel.NewExporterFromEnv(func(k string) string {
		if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
			return otelSrv.URL
		}
		return ""
	}, "crawl-cov", "2.7.0", otelSrv.Client().Transport)
	cSrv.SetOtelExporter(exp)
	defer cSrv.Close()

	rep402 := ExecuteCall(context.Background(), cSrv, FetchCall{
		MaxSeconds: 9999,
		Requests: []Request{
			{ID: "1", URL: "http://s.test/402", Kind: classify.KindPage},
			{ID: "2", URL: "http://s.test/after402", Kind: classify.KindPage},
		},
	}, silentLog)
	if len(rep402.Results) != 2 || rep402.Results[0].Status != http.StatusPaymentRequired ||
		rep402.Results[0].Outcome != classify.OutcomePaymentRequired || rep402.Results[1].Outcome != classify.OutcomeNotTried {
		t.Fatalf("expected 402 payment_required followed by not_tried, got %+v", rep402.Results)
	}
	repOK := ExecuteCallWithSink(context.Background(), cSrv, FetchCall{
		Requests: []Request{{ID: "1", URL: "http://s.test/ok", Kind: classify.KindPage}},
	}, silentLog, nil)
	if len(repOK.Results) != 1 || repOK.Results[0].Status != http.StatusOK || repOK.Results[0].Outcome != classify.OutcomeOK {
		t.Fatalf("expected single 200 OK result from ExecuteCallWithSink, got %+v", repOK.Results)
	}

	// NewAuthenticatedHandler 405 / 401 ("Bearer   ") / 400 bad_json.
	hAuth := NewAuthenticatedHandler(cSrv, PublicHTTPS, "secret-token")
	for _, tc := range []struct {
		method, path, auth, body string
		want                     int
	}{
		{http.MethodPost, "/healthz", "", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/fetch", "", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/fetch", "Bearer    ", `{}`, http.StatusUnauthorized},
		{http.MethodPost, "/fetch", "Bearer secret-token", `{"unknownField":1}`, http.StatusBadRequest},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		rec := httptest.NewRecorder()
		hAuth.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s: expected %d, got %d", tc.method, tc.path, tc.want, rec.Code)
		}
	}

	// CallLogger trace headers & traceparent fallback.
	var logOut bytes.Buffer
	baseL := slog.New(slog.NewJSONHandler(&logOut, nil))
	hExplicit := http.Header{}
	hExplicit.Set("x-trace-id", "trace-123")
	hExplicit.Set("x-span-id", "span-456")
	hExplicit.Set("x-request-id", "ray-789")
	CallLogger(baseL, hExplicit).Info("explicit")
	hTP := http.Header{}
	hTP.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	CallLogger(baseL, hTP).Info("tp")
	if !strings.Contains(logOut.String(), "trace-123") || !strings.Contains(logOut.String(), "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("expected trace fields in CallLogger output, got %s", logOut.String())
	}
}
