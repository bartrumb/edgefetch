// Package crawl implements a bounded-concurrency, polite HTTP/2 fetcher with net/http/httptrace phase telemetry,
// positive dwell jitter, conditional GETs (ETag / If-Modified-Since), and strict memory/SSRF guardrails.
package crawl

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/internal/browser"
	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/extract"
	"github.com/bartrumb/edgefetch/internal/politeness"
)

// DefaultUserAgent is sent when no custom User-Agent is configured. Always identify crawlers honestly.
const DefaultUserAgent = "EdgeFetch/2.0 (+https://github.com/bartrumb/edgefetch)"

// InteractSpec configures stateful or single-turn headless Chromium interaction (`firecrawl_interact` parity).
type InteractSpec struct {
	SessionID    string                   `json:"sessionId,omitempty"`
	KeepSession  bool                     `json:"keepSession,omitempty"`
	CloseSession bool                     `json:"closeSession,omitempty"`
	Actions      []browser.InteractAction `json:"actions,omitempty"`
}

// Request describes a single URL to fetch within a batch.
type Request struct {
	ID                 string            `json:"id"`
	URL                string            `json:"url"`
	Kind               classify.Kind     `json:"kind"`
	Accept             string            `json:"accept,omitempty"`
	IfNoneMatch        string            `json:"ifNoneMatch,omitempty"`
	IfModifiedSince    string            `json:"ifModifiedSince,omitempty"`
	Formats            []string          `json:"formats,omitempty"`
	OnlyMainContent    *bool             `json:"onlyMainContent,omitempty"`
	DiscoverLlms       *bool             `json:"discoverLlms,omitempty"`
	PreferLlmsMarkdown *bool             `json:"preferLlmsMarkdown,omitempty"`
	RedactPII          bool              `json:"redactPii,omitempty"`
	Query              string            `json:"query,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	RenderMode         string            `json:"renderMode,omitempty"` // "off" (default), "auto", "always"
	WaitForMs          int               `json:"waitForMs,omitempty"`
	WaitSelector       string            `json:"waitSelector,omitempty"`
	MaxPages           int               `json:"maxPages,omitempty"`
	Interact           *InteractSpec     `json:"interact,omitempty"`
}

// Timing records where a single HTTP attempt spent wall-clock milliseconds via Go's `net/http/httptrace` hooks.
// When `Reused == true` (warm HTTP/2 or keep-alive socket), `DNSMs`, `ConnectMs`, and `TLSMs` are `0`.
type Timing struct {
	DNSMs      int64  `json:"dnsMs"`
	ConnectMs  int64  `json:"connectMs"`
	TLSMs      int64  `json:"tlsMs"`
	TTFBMs     int64  `json:"ttfbMs"`
	Reused     bool   `json:"reused"`
	RemoteAddr string `json:"remoteAddr,omitempty"`
	Proto      string `json:"proto,omitempty"`
}

// ArtifactRef references a gzipped response body uploaded directly to R2 (`PUT /agent/artifacts/<blobSha256>`) so
// large page bodies never pass through the `AgentHubDO` Durable Object or accumulate in batch RAM.
type ArtifactRef struct {
	BlobSHA256    string `json:"blobSha256"`
	ContentSHA256 string `json:"contentSha256"`
	ContentBytes  int    `json:"contentBytes"`
	StoredBytes   int    `json:"storedBytes"`
	Encoding      string `json:"encoding"`
	Retention     string `json:"retention"`
}

// Result reports the outcome, headers of interest, phase timings, and optional body or R2 artifact of one `Request`.
type Result struct {
	ID               string                   `json:"id"`
	URL              string                   `json:"url"`
	Kind             classify.Kind            `json:"kind"`
	Outcome          classify.Outcome         `json:"outcome"`
	Problem          string                   `json:"problem,omitempty"`
	Status           int                      `json:"status"`
	ContentType      string                   `json:"contentType,omitempty"`
	CfMitigated      string                   `json:"cfMitigated,omitempty"`
	ETag             string                   `json:"etag,omitempty"`
	LastModified     string                   `json:"lastModified,omitempty"`
	RetryAfter       string                   `json:"retryAfter,omitempty"`
	RetryAfterMs     int64                    `json:"retryAfterMs,omitempty"`
	Bytes            int                      `json:"bytes"`
	Truncated        bool                     `json:"truncated,omitempty"`
	BodyOmitted      bool                     `json:"bodyOmitted,omitempty"`
	Attempts         int                      `json:"attempts"`
	DurationMs       int64                    `json:"durationMs"`
	Timing           Timing                   `json:"timing"`
	Body             string                   `json:"body,omitempty"`
	BodyEncoding     string                   `json:"bodyEncoding,omitempty"`
	Artifact         *ArtifactRef             `json:"artifact,omitempty"`
	ArtifactError    string                   `json:"artifactError,omitempty"`
	FinalURL         string                   `json:"finalUrl,omitempty"`
	Title            string                   `json:"title,omitempty"`
	Description      string                   `json:"description,omitempty"`
	Favicon          string                   `json:"favicon,omitempty"`
	Markdown         string                   `json:"markdown,omitempty"`
	Text             string                   `json:"text,omitempty"`
	Links            []string                 `json:"links,omitempty"`
	Images           []extract.ImageInfo      `json:"images,omitempty"`
	Branding         *extract.BrandingProfile `json:"branding,omitempty"`
	Llms             *extract.LlmsDiscovery   `json:"llms,omitempty"`
	Rendered         bool                     `json:"rendered,omitempty"`
	SessionID        string                   `json:"sessionId,omitempty"`
	ScreenshotBase64 string                   `json:"screenshotBase64,omitempty"`
	PDFEngine        string                   `json:"pdfEngine,omitempty"`
	SHA256           string                   `json:"sha256,omitempty"`
	BodyBase64       string                   `json:"bodyBase64,omitempty"`
}

// DecodeBody returns the exact raw response bytes for `r.Body`, decoding `"base64"` payloads losslessly when the origin
// response contained non-UTF-8 bytes.
func (r Result) DecodeBody() ([]byte, error) {
	if r.Body == "" {
		return nil, nil
	}
	if r.BodyEncoding == "base64" {
		return base64.StdEncoding.DecodeString(r.Body)
	}
	return []byte(r.Body), nil
}

// Bool returns a pointer to v for configuring optional tri-state boolean fields on Options.
func Bool(v bool) *bool { return &v }

// Options bounds a crawl batch. Zero values take safe defaults in Normalize() (including RespectRobots = true).
type Options struct {
	PauseMs       int   `json:"pauseMs"`
	PauseJitterMs int   `json:"pauseJitterMs,omitempty"`
	GapMs         int   `json:"gapMs"`
	Concurrency   int   `json:"concurrency"`
	TimeoutMs     int   `json:"timeoutMs"`
	MaxBytes      int   `json:"maxBytes"`
	MaxTotalBytes int   `json:"maxTotalBytes,omitempty"`
	Retries       int   `json:"retries"`
	IncludeBody   bool  `json:"includeBody"`
	DiscoverLlms  *bool `json:"discoverLlms,omitempty"`
	RespectRobots *bool `json:"respectRobots,omitempty"`
	// Robots is accepted as a wire alias for RespectRobots. When both are omitted, Normalize() defaults to true.
	Robots *bool `json:"robots,omitempty"`
}

const (
	DefaultPauseMs       = 2000
	MaxPauseJitterMs     = 30_000
	DefaultTimeoutMs     = 30_000
	MaxTimeoutMs         = 120_000
	DefaultMaxBytes      = 8 << 20
	MaxMaxBytes          = 16 << 20
	MaxStreamingPDFBytes = 256 << 20 // 256 MiB disk-streamed PDF ceiling on Fat nodes (zero 100 MiB heap spike)
	DefaultMaxTotalBytes = 16 << 20  // 16 MiB batch body ceiling stays safely below Hub's 20 MiB reply cap & 128 MiB GOMEMLIMIT
	MaxMaxTotalBytes     = 18 << 20
	MaxConcurrency       = 4
	MaxRetries           = 3
	MaxRedirects         = 5
)

// RobotsEnabled reports whether /robots.txt enforcement is active (defaulting to true when unset).
func (o Options) RobotsEnabled() bool {
	if o.RespectRobots != nil {
		return *o.RespectRobots
	}
	if o.Robots != nil {
		return *o.Robots
	}
	return true
}

// Normalize clamps out-of-range or zero fields on a value copy of Options.
func (o Options) Normalize() Options {
	enabled := o.RobotsEnabled()
	o.RespectRobots = Bool(enabled)
	o.Robots = nil
	if o.PauseMs <= 0 {
		o.PauseMs = DefaultPauseMs
	}
	if o.PauseJitterMs < 0 {
		o.PauseJitterMs = 0
	}
	if o.PauseJitterMs > MaxPauseJitterMs {
		o.PauseJitterMs = MaxPauseJitterMs
	}
	if o.GapMs < 0 {
		o.GapMs = 0
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 1
	}
	if o.Concurrency > MaxConcurrency {
		o.Concurrency = MaxConcurrency
	}
	if o.TimeoutMs <= 0 {
		o.TimeoutMs = DefaultTimeoutMs
	}
	if o.TimeoutMs > MaxTimeoutMs {
		o.TimeoutMs = MaxTimeoutMs
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxBytes > MaxMaxBytes {
		o.MaxBytes = MaxMaxBytes
	}
	if o.MaxTotalBytes <= 0 {
		o.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if o.MaxTotalBytes > MaxMaxTotalBytes {
		o.MaxTotalBytes = MaxMaxTotalBytes
	}
	if o.Retries < 0 {
		o.Retries = 0
	}
	if o.Retries > MaxRetries {
		o.Retries = MaxRetries
	}
	return o
}

// ValidateUserAgent ensures a configured `User-Agent` is non-empty printable ASCII with zero CR/LF header-injection bytes.
func ValidateUserAgent(ua string) error {
	ua = strings.TrimSpace(ua)
	if len(ua) == 0 || len(ua) > 256 {
		return fmt.Errorf("user_agent must be 1..256 characters (got %d)", len(ua))
	}
	for i := 0; i < len(ua); i++ {
		b := ua[i]
		if b < 0x20 || b > 0x7E {
			return fmt.Errorf("user_agent contains non-printable ASCII byte 0x%02x", b)
		}
	}
	return nil
}

// Crawler executes polite, rate-limited HTTP GET batches.
// Never copy a `Crawler` value after creation (`sync.Mutex` fields must stay at a fixed address).
type Crawler struct {
	client    *http.Client
	allow     func(*url.URL) error
	userAgent string
	log       *slog.Logger

	// Injectable clock/sleep/jitter hooks make multi-second pacing tests run in < 1 ms without mocking frameworks.
	Sleep  func(ctx context.Context, d time.Duration) error
	Now    func() time.Time
	Jitter func(d time.Duration) time.Duration

	hostsMu           sync.Mutex
	hosts             *politeness.Registry
	llms              *llmsCache
	renderer          *browser.Renderer
	robotsBypassHosts []string
	globalMu          sync.Mutex
	globalNext        time.Time
}

// NewCrawler constructs a `Crawler` whose HTTP redirects are handled hop-by-hop (re-checking URL rules, per-host locks,
// pacing, and `/robots.txt` on every redirect hop).
func NewCrawler(transport http.RoundTripper, allow func(*url.URL) error, userAgent string, log *slog.Logger) *Crawler {
	if strings.TrimSpace(userAgent) == "" {
		userAgent = DefaultUserAgent
	}
	if allow == nil {
		allow = PublicHTTPS
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var rngMu sync.Mutex
	c := &Crawler{
		client:    client,
		allow:     allow,
		userAgent: userAgent,
		log:       log,
		Sleep:     SleepCtx,
		Now:       time.Now,
		hosts:     politeness.NewRegistry(),
		Jitter: func(d time.Duration) time.Duration {
			if d <= 0 {
				return 0
			}
			rngMu.Lock()
			defer rngMu.Unlock()
			return time.Duration(rng.Int63n(int64(d) + 1))
		},
	}
	r := browser.NewRenderer("", allow, userAgent, 2, log)
	r.CheckRobots = func(ctx context.Context, rawURL string) error {
		host := hostOf(rawURL)
		if !c.shouldCheckRobots(host, Options{}) {
			return nil
		}
		hs := c.hostStateFor(host)
		if err := hs.Acquire(ctx); err != nil {
			return err
		}
		defer hs.Release()
		allowed, _, reason := c.checkRobots(ctx, hs, rawURL)
		if !allowed {
			return errors.New(reason)
		}
		return nil
	}
	c.renderer = r
	return c
}

// SetRenderer replaces the browser renderer (used by unit tests with mock CDP WebSockets).
func (c *Crawler) SetRenderer(r *browser.Renderer) {
	c.renderer = r
}

// Close shuts down any running headless Chromium subprocess and loopback SSRF proxy.
func (c *Crawler) Close() error {
	if c == nil || c.renderer == nil {
		return nil
	}
	return c.renderer.Close()
}

// Capabilities returns the runtime feature tokens advertised in `X-Agent-Capabilities` (`artifacts-v1`, plus
// `browser-v1` when Chromium is present and `pdf-v1` when Poppler `pdftotext` is installed).
func (c *Crawler) Capabilities() []string {
	caps := []string{"artifacts-v1"}
	if c != nil && c.renderer != nil && c.renderer.Available() {
		caps = append(caps, "browser-v1")
	}
	if extract.HasPDFToText() {
		caps = append(caps, "pdf-v1")
	}
	return caps
}

// SetRobotsBypassHosts configures the owner-controlled host allowlist permitted to set `respectRobots: false`.
// By default this list is empty, meaning `/robots.txt` is always enforced even if a caller sends `respectRobots: false`.
func (c *Crawler) SetRobotsBypassHosts(hosts []string) {
	clean := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		if h := normalizeHostRule(raw); h != "" {
			clean = append(clean, h)
		}
	}
	c.hostsMu.Lock()
	c.robotsBypassHosts = clean
	c.hostsMu.Unlock()
}

// AllowsRobotsBypass reports whether `host` matches the owner's explicit `robots_bypass_hosts` allowlist.
func (c *Crawler) AllowsRobotsBypass(host string) bool {
	if c == nil {
		return false
	}
	h := politeness.CanonicalHost(host)
	if h == "" {
		return false
	}
	c.hostsMu.Lock()
	allowedList := c.robotsBypassHosts
	c.hostsMu.Unlock()
	for _, allowed := range allowedList {
		if h == allowed || strings.HasSuffix(h, "."+allowed) {
			return true
		}
	}
	return false
}

func (c *Crawler) shouldCheckRobots(host string, opts Options) bool {
	if opts.RobotsEnabled() {
		return true
	}
	return !c.AllowsRobotsBypass(host)
}

// Logger exposes the crawler's base structured logger.
func (c *Crawler) Logger() *slog.Logger {
	return c.log
}

func (c *Crawler) hostStateFor(host string) *politeness.HostState {
	c.hostsMu.Lock()
	if c.hosts == nil {
		c.hosts = politeness.NewRegistry()
	}
	reg := c.hosts
	c.hostsMu.Unlock()
	return reg.Get(host, c.Now())
}

func (c *Crawler) waitGlobalGap(ctx context.Context, gap time.Duration) error {
	if gap <= 0 {
		return ctx.Err()
	}
	c.globalMu.Lock()
	now := c.Now()
	start := c.globalNext
	if start.Before(now) {
		start = now
	}
	c.globalNext = start.Add(gap)
	c.globalMu.Unlock()
	return c.Sleep(ctx, start.Sub(now))
}

func (c *Crawler) bumpGlobalThrottle(d time.Duration) {
	if d <= 0 {
		return
	}
	c.globalMu.Lock()
	if until := c.Now().Add(d); until.After(c.globalNext) {
		c.globalNext = until
	}
	c.globalMu.Unlock()
}

// SleepCtx pauses for `d` or returns early when `ctx` cancels, freeing the underlying timer immediately via `defer t.Stop()`.
func SleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ResultSink transforms an individual `Result` as soon as its fetch completes (for example, uploading its body to R2
// and releasing `res.Body` from memory before the next URL in the batch runs).
type ResultSink func(idx int, res Result) Result

// Run executes `reqs` with `c.log` and returns results in exact input order.
func (c *Crawler) Run(ctx context.Context, reqs []Request, opts Options) []Result {
	return c.RunLogged(ctx, reqs, opts, c.log)
}

// RunLogged executes `reqs` using a request-scoped structured logger (carrying distributed trace IDs).
func (c *Crawler) RunLogged(ctx context.Context, reqs []Request, opts Options, log *slog.Logger) []Result {
	return c.RunWithSink(ctx, reqs, opts, log, nil)
}

// RunWithSink executes `reqs` and invokes optional `sink(i, res)` immediately as each fetch finishes so streaming
// artifact uploaders can free `res.Body` before subsequent URLs execute.
func (c *Crawler) RunWithSink(ctx context.Context, reqs []Request, opts Options, log *slog.Logger, sink ResultSink) []Result {
	opts = opts.Normalize()
	results := make([]Result, len(reqs))

	order := []string{}
	byHost := map[string][]int{}
	for i, r := range reqs {
		h := hostOf(r.URL)
		if _, seen := byHost[h]; !seen {
			order = append(order, h)
		}
		byHost[h] = append(byHost[h], i)
	}

	gap := time.Duration(opts.GapMs) * time.Millisecond
	minPause := time.Duration(opts.PauseMs) * time.Millisecond
	maxJitter := time.Duration(opts.PauseJitterMs) * time.Millisecond
	sem := make(chan struct{}, opts.Concurrency)
	var retainedBodyBytes atomic.Int64
	var wg sync.WaitGroup

	for _, h := range order {
		idx := byHost[h]
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			for _, i := range idx {
				results[i] = notTried(reqs[i], "crawl cancelled")
			}
			continue
		}

		wg.Add(1)
		go func(host string, idx []int) {
			defer wg.Done()
			defer func() { <-sem }()

			stopped := ""
			for n, i := range idx {
				r := reqs[i]
				if stopped != "" {
					results[i] = notTried(r, stopped)
					continue
				}
				res, cancelled := c.runRequestWithRedirects(ctx, r, opts, n > 0, minPause, maxJitter, gap, log)
				if sink != nil {
					res = sink(i, res)
				}
				if opts.IncludeBody && len(res.Body) > 0 {
					encodedLen := int64(len(res.Body))
					for {
						cur := retainedBodyBytes.Load()
						if cur+encodedLen > int64(opts.MaxTotalBytes) {
							res.Body = ""
							res.BodyEncoding = ""
							res.Truncated = true
							res.BodyOmitted = true
							if res.Problem == "" {
								res.Problem = fmt.Sprintf("batch total body budget (%d bytes) exceeded", opts.MaxTotalBytes)
							}
							break
						}
						if retainedBodyBytes.CompareAndSwap(cur, cur+encodedLen) {
							break
						}
					}
				}
				results[i] = res
				if cancelled {
					stopped = "crawl cancelled"
					continue
				}
				if classify.StopsHost(r.Kind, res.Outcome) {
					stopped = fmt.Sprintf("host stopped after %s on %s", res.Outcome, r.URL)
				}
			}
		}(h, idx)
	}
	wg.Wait()
	return results
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func (c *Crawler) runRequestWithRedirects(
	ctx context.Context,
	origReq Request,
	opts Options,
	paceInitialHop bool,
	minPause, maxJitter, gap time.Duration,
	log *slog.Logger,
) (Result, bool) {
	if err := ValidateCustomHeaders(origReq.Headers); err != nil {
		return Result{ID: origReq.ID, URL: origReq.URL, Kind: origReq.Kind, Outcome: classify.OutcomeError, Problem: err.Error()}, false
	}
	started := c.Now()

	// Resumed or session-closing `interact` turn (`origReq.URL == ""` with `origReq.Interact.SessionID != ""`).
	if origReq.Interact != nil && strings.TrimSpace(origReq.URL) == "" {
		res := c.runBrowserStep(ctx, origReq, opts, started)
		c.logResult(ctx, log, origReq, res)
		return res, false
	}

	// Explicit headless browser render (`KindRender`, `renderMode: "always"`, or `Interact != nil`):
	// Enforce per-host pacing AND check `/robots.txt` BEFORE launching/navigating Chromium!
	if origReq.Kind == classify.KindRender || strings.EqualFold(origReq.RenderMode, "always") || origReq.Interact != nil {
		curHost := hostOf(origReq.URL)
		hs := c.hostStateFor(curHost)
		if err := hs.Acquire(ctx); err != nil {
			return notTried(origReq, "crawl cancelled"), true
		}
		if why := hs.CheckCircuit(c.Now(), curHost); why != "" {
			hs.Release()
			return Result{ID: origReq.ID, URL: origReq.URL, Kind: origReq.Kind, Outcome: classify.OutcomeError, Problem: why}, false
		}
		var waitDur time.Duration
		if paceInitialHop {
			waitDur = minPause
			if cd := hs.CrawlDelay(c.Now()); cd > waitDur {
				waitDur = cd
			}
			if maxJitter > 0 {
				waitDur += c.Jitter(maxJitter)
			}
			if rem := hs.WaitDelay(c.Now()); rem > waitDur {
				waitDur = rem
			}
		} else {
			waitDur = hs.WaitDelay(c.Now())
		}
		if waitDur > 0 {
			if err := c.Sleep(ctx, waitDur); err != nil {
				hs.Release()
				return notTried(origReq, "crawl cancelled"), true
			}
		}
		if err := c.waitGlobalGap(ctx, gap); err != nil {
			hs.Release()
			return notTried(origReq, "crawl cancelled"), true
		}
		if c.shouldCheckRobots(curHost, opts) {
			if allowed, distressed, reason := c.checkRobots(ctx, hs, origReq.URL); !allowed {
				hs.Release()
				outcome := classify.OutcomeError
				if distressed {
					outcome = classify.OutcomeStop
				}
				return Result{
					ID:         origReq.ID,
					URL:        origReq.URL,
					Kind:       origReq.Kind,
					Outcome:    outcome,
					Problem:    reason,
					DurationMs: c.Now().Sub(started).Milliseconds(),
				}, false
			}
		}
		nextFloor := minPause
		if maxJitter > 0 {
			nextFloor += c.Jitter(maxJitter)
		}
		hs.RecordOutcome(c.Now(), nextFloor, 0, http.StatusOK, false, false)
		hs.Release()

		res := c.runBrowserStep(ctx, origReq, opts, started)
		c.logResult(ctx, log, origReq, res)
		return res, false
	}
	curURLStr := origReq.URL
	prevHost := ""
	totalAttempts := 0

	for hop := 0; hop <= MaxRedirects; hop++ {
		parsedCur, err := url.Parse(curURLStr)
		if err != nil {
			return Result{ID: origReq.ID, URL: origReq.URL, Kind: origReq.Kind, Outcome: classify.OutcomeError, Problem: err.Error()}, false
		}
		if hop > 0 && c.allow != nil {
			if err := c.allow(parsedCur); err != nil {
				return Result{ID: origReq.ID, URL: origReq.URL, Kind: origReq.Kind, Outcome: classify.OutcomeError, Problem: err.Error()}, false
			}
		}

		curHost := hostOf(curURLStr)
		hs := c.hostStateFor(curHost)
		if err := hs.Acquire(ctx); err != nil {
			return notTried(origReq, "crawl cancelled"), true
		}

		if why := hs.CheckCircuit(c.Now(), curHost); why != "" {
			hs.Release()
			return Result{ID: origReq.ID, URL: origReq.URL, Kind: origReq.Kind, Outcome: classify.OutcomeError, Problem: why}, false
		}

		var waitDur time.Duration
		if (hop == 0 && paceInitialHop) || (hop > 0 && curHost == prevHost) {
			waitDur = minPause
			if cd := hs.CrawlDelay(c.Now()); cd > waitDur {
				waitDur = cd
			}
			if maxJitter > 0 {
				waitDur += c.Jitter(maxJitter)
			}
			if rem := hs.WaitDelay(c.Now()); rem > waitDur {
				waitDur = rem
			}
		} else {
			waitDur = hs.WaitDelay(c.Now())
		}
		if waitDur > 0 {
			if err := c.Sleep(ctx, waitDur); err != nil {
				hs.Release()
				return notTried(origReq, "crawl cancelled"), true
			}
		}
		prevHost = curHost

		if err := c.waitGlobalGap(ctx, gap); err != nil {
			hs.Release()
			return notTried(origReq, "crawl cancelled"), true
		}

		if c.shouldCheckRobots(curHost, opts) {
			if allowed, distressed, reason := c.checkRobots(ctx, hs, curURLStr); !allowed {
				hs.Release()
				outcome := classify.OutcomeError
				if distressed {
					outcome = classify.OutcomeStop
				} else if origReq.Kind == classify.KindPage || origReq.Kind == classify.KindText {
					outcome = classify.OutcomeSkip
				}
				return Result{
					ID:         origReq.ID,
					URL:        origReq.URL,
					Kind:       origReq.Kind,
					Outcome:    outcome,
					Problem:    reason,
					Attempts:   totalAttempts,
					DurationMs: c.Now().Sub(started).Milliseconds(),
				}, false
			}
		}

		hopReq := origReq
		hopReq.URL = curURLStr
		if hop > 0 {
			hopReq.IfNoneMatch = ""
			hopReq.IfModifiedSince = ""
		}
		res, loc, rawBody := c.fetchSingleHop(ctx, hopReq, opts)
		totalAttempts += res.Attempts
		res.ID = origReq.ID
		res.URL = origReq.URL
		if hop > 0 && !isRedirectStatus(res.Status) {
			res.FinalURL = curURLStr
		}
		res.Attempts = totalAttempts

		retryAfter := time.Duration(res.RetryAfterMs) * time.Millisecond
		nextFloor := minPause
		if maxJitter > 0 {
			nextFloor += c.Jitter(maxJitter)
		}
		throttled := res.Status == http.StatusTooManyRequests || res.Status == http.StatusServiceUnavailable || res.Outcome == classify.OutcomeChallenge
		transientDead := (res.Status == 0 && res.Outcome == classify.OutcomeError) || retriableStatus(res.Status)
		hs.RecordOutcome(c.Now(), nextFloor, retryAfter, res.Status, throttled, transientDead)
		hs.Release()

		if gap > 0 && (res.Outcome == classify.OutcomeChallenge || res.Status == http.StatusTooManyRequests) {
			cool := politeness.DefaultThrottlePause
			if retryAfter > cool {
				cool = retryAfter
			}
			c.bumpGlobalThrottle(cool)
		}

		if isRedirectStatus(res.Status) && loc != "" && res.CfMitigated == "" {
			if hop == MaxRedirects {
				res.Outcome = classify.OutcomeError
				res.Problem = fmt.Sprintf("more than %d redirects", MaxRedirects)
				res.Body = ""
				res.DurationMs = c.Now().Sub(started).Milliseconds()
				c.logResult(ctx, log, origReq, res)
				return res, false
			}
			locURL, lErr := url.Parse(loc)
			if lErr != nil {
				res.Outcome = classify.OutcomeError
				res.Problem = "invalid redirect Location: " + lErr.Error()
				res.Body = ""
				res.DurationMs = c.Now().Sub(started).Milliseconds()
				c.logResult(ctx, log, origReq, res)
				return res, false
			}
			curURLStr = parsedCur.ResolveReference(locURL).String()
			continue
		}

		if strings.EqualFold(origReq.RenderMode, "auto") &&
			res.Outcome == classify.OutcomeOK &&
			c.renderer != nil &&
			c.renderer.Available() &&
			extract.NeedsBrowserRender(string(rawBody)) {
			targetForRender := res.FinalURL
			if targetForRender == "" {
				targetForRender = origReq.URL
			}
			upReq := origReq
			upReq.URL = targetForRender
			renderedRes := c.runBrowserStep(ctx, upReq, opts, started)
			if renderedRes.Outcome == classify.OutcomeOK || renderedRes.Outcome == classify.OutcomeChallenge {
				renderedRes.ID = origReq.ID
				renderedRes.URL = origReq.URL
				c.logResult(ctx, log, origReq, renderedRes)
				return renderedRes, false
			}
		}

		c.enrichResult(ctx, origReq, opts, rawBody, &res)
		res.DurationMs = c.Now().Sub(started).Milliseconds()
		c.logResult(ctx, log, origReq, res)
		return res, false
	}

	return Result{ID: origReq.ID, URL: origReq.URL, Kind: origReq.Kind, Outcome: classify.OutcomeError, Problem: "redirect loop"}, false
}

func notTried(r Request, why string) Result {
	return Result{ID: r.ID, URL: r.URL, Kind: r.Kind, Outcome: classify.OutcomeNotTried, Problem: why}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return politeness.CanonicalHost(raw)
	}
	if h := politeness.CanonicalHost(u.Hostname()); h != "" {
		return h
	}
	return politeness.CanonicalHost(u.Host)
}

func retriableStatus(status int) bool {
	return status == 500 || status == 502 || status == 504
}

func isPermanentFetchError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, politeness.ErrNonPublicPeer) {
		return true
	}
	var certVerErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certInv x509.CertificateInvalidError
	if errors.As(err, &certVerErr) || errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &certInv) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "refusing connection to non-public IP") || strings.Contains(msg, "unsupported protocol scheme")
}

type streamedPDFResult struct {
	rawBytes    int
	sha256Hex   string
	text        string
	usedPoppler bool
	err         error
}

func (c *Crawler) fetchSingleHop(ctx context.Context, r Request, opts Options) (Result, string, []byte) {
	res := Result{ID: r.ID, URL: r.URL, Kind: r.Kind}
	accept, err := classify.AcceptFor(r.Kind, r.Accept)
	if err != nil {
		res.Outcome, res.Problem = classify.OutcomeError, err.Error()
		return res, "", nil
	}

	var redirectLoc string
	var finalBody []byte
	for attempt := 1; ; attempt++ {
		res.Attempts = attempt
		status, header, body, truncated, maxLimitUsed, pdfStream, timing, fetchErr := c.onceWithPDFStream(ctx, r, accept, opts)
		res.Timing = timing
		if fetchErr != nil {
			if ctx.Err() != nil {
				res.Outcome, res.Problem = classify.OutcomeError, ctx.Err().Error()
				break
			}
			if !isPermanentFetchError(fetchErr) && attempt <= opts.Retries {
				c.backoff(ctx, attempt)
				continue
			}
			res.Outcome, res.Problem = classify.OutcomeError, fetchErr.Error()
			break
		}
		if retriableStatus(status) && header.Get("cf-mitigated") == "" && attempt <= opts.Retries {
			c.backoff(ctx, attempt)
			continue
		}

		res.Status = status
		res.Bytes = len(body)
		res.Truncated = truncated
		res.ContentType = header.Get("content-type")
		res.CfMitigated = header.Get("cf-mitigated")
		res.ETag = header.Get("etag")
		res.LastModified = header.Get("last-modified")
		res.RetryAfter = header.Get("retry-after")
		redirectLoc = strings.TrimSpace(header.Get("location"))
		if ra := politeness.ParseRetryAfter(res.RetryAfter, c.Now()); ra > 0 {
			res.RetryAfterMs = ra.Milliseconds()
		}

		if isRedirectStatus(status) && redirectLoc != "" && res.CfMitigated == "" {
			break
		}

		if truncated {
			res.Outcome, res.Problem = classify.OutcomeError, fmt.Sprintf("body over %d bytes", maxLimitUsed)
			if header.Get("cf-mitigated") != "" {
				res.Outcome, res.Problem = classify.Classify(r.Kind, status, header, nil)
			}
		} else if pdfStream != nil {
			res.Bytes = pdfStream.rawBytes
			res.SHA256 = pdfStream.sha256Hex
			if pdfStream.err != nil {
				if r.Kind == classify.KindScrape {
					res.Outcome, res.Problem = classify.OutcomeError, pdfStream.err.Error()
				} else {
					res.Outcome, res.Problem = classify.OutcomeOK, pdfStream.err.Error()
				}
			} else {
				pdfTxt := pdfStream.text
				if r.Query != "" {
					pdfTxt = extract.RerankPassages(pdfTxt, r.Query, 24_000)
				}
				if r.RedactPII {
					pdfTxt = extract.RedactPII(pdfTxt)
				}
				res.Outcome, res.Problem = classify.OutcomeOK, ""
				res.Markdown = pdfTxt
				if hasFormat(r.Formats, "text") {
					res.Text = pdfTxt
				}
				res.PDFEngine = "pure-go"
				if pdfStream.usedPoppler {
					res.PDFEngine = "poppler-pdftotext"
				}
				if opts.IncludeBody {
					res.Body = pdfTxt
					res.BodyEncoding = "utf-8"
					res.ContentType = "text/markdown; charset=utf-8"
				}
			}
		} else if status == http.StatusNotModified && (r.IfNoneMatch != "" || r.IfModifiedSince != "") && res.CfMitigated == "" {
			res.Outcome, res.Problem = classify.OutcomeOK, ""
		} else {
			res.Outcome, res.Problem = classify.Classify(r.Kind, status, header, body)
		}
		finalBody = body
		if pdfStream == nil && opts.IncludeBody {
			if utf8.Valid(body) {
				res.Body = string(body)
				res.BodyEncoding = "utf-8"
			} else {
				res.Body = base64.StdEncoding.EncodeToString(body)
				res.BodyEncoding = "base64"
			}
		}
		break
	}
	return res, redirectLoc, finalBody
}

func (c *Crawler) logResult(ctx context.Context, log *slog.Logger, r Request, res Result) {
	level := slog.LevelInfo
	switch res.Outcome {
	case classify.OutcomeChallenge, classify.OutcomeStop:
		level = slog.LevelWarn
	case classify.OutcomeError:
		level = slog.LevelError
	}
	log.Log(ctx, level, "fetch",
		slog.String("store", r.ID), slog.String("url", r.URL), slog.String("kind", string(r.Kind)),
		slog.Int("status", res.Status), slog.String("outcome", string(res.Outcome)), slog.String("problem", res.Problem),
		slog.Int("attempts", res.Attempts), slog.Int64("duration_ms", res.DurationMs), slog.Int("bytes", res.Bytes),
		slog.Bool("truncated", res.Truncated),
		slog.Int64("dns_ms", res.Timing.DNSMs), slog.Int64("connect_ms", res.Timing.ConnectMs), slog.Int64("tls_ms", res.Timing.TLSMs),
		slog.Int64("ttfb_ms", res.Timing.TTFBMs), slog.Bool("conn_reused", res.Timing.Reused),
		slog.String("remote_addr", res.Timing.RemoteAddr), slog.String("proto", res.Timing.Proto))
}

func (c *Crawler) backoff(ctx context.Context, attempt int) {
	d := time.Second << (attempt - 1)
	if d > 10*time.Second {
		d = 10 * time.Second
	}
	floor := d / 4
	_ = c.Sleep(ctx, floor+c.Jitter(d-floor))
}

func ms(from, to time.Time) int64 {
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return 0
	}
	return to.Sub(from).Milliseconds()
}

func (c *Crawler) onceWithPDFStream(ctx context.Context, r Request, accept string, opts Options) (int, http.Header, []byte, bool, int, *streamedPDFResult, Timing, error) {
	var tm Timing
	var dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, wrote, firstByte time.Time
	var mu sync.Mutex
	at := func(t *time.Time, first bool) {
		mu.Lock()
		defer mu.Unlock()
		if !first || t.IsZero() {
			*t = time.Now()
		}
	}
	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { at(&dnsStart, true) },
		DNSDone:              func(httptrace.DNSDoneInfo) { at(&dnsDone, false) },
		ConnectStart:         func(string, string) { at(&connStart, true) },
		ConnectDone:          func(string, string, error) { at(&connDone, false) },
		TLSHandshakeStart:    func() { at(&tlsStart, true) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { at(&tlsDone, false) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { at(&wrote, false) },
		GotFirstResponseByte: func() { at(&firstByte, true) },
		GotConn: func(info httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			tm.Reused = info.Reused
			if info.Conn != nil {
				tm.RemoteAddr = info.Conn.RemoteAddr().String()
			}
		},
	}
	phases := func() {
		mu.Lock()
		defer mu.Unlock()
		tm.DNSMs, tm.ConnectMs, tm.TLSMs, tm.TTFBMs = ms(dnsStart, dnsDone), ms(connStart, connDone), ms(tlsStart, tlsDone), ms(wrote, firstByte)
	}

	timeoutDur := time.Duration(opts.TimeoutMs) * time.Millisecond
	if (r.Kind == classify.KindScrape || r.Kind == classify.KindPDF) && timeoutDur < 95*time.Second {
		if u, uErr := url.Parse(r.URL); uErr == nil && strings.HasSuffix(strings.ToLower(u.Path), ".pdf") {
			timeoutDur = 95 * time.Second
		}
	}
	actx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), timeoutDur)
	defer cancel()

	req, err := http.NewRequestWithContext(actx, http.MethodGet, r.URL, nil)
	if err != nil {
		return 0, nil, nil, false, opts.MaxBytes, nil, tm, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	for k, v := range r.Headers {
		req.Header.Set(strings.TrimSpace(k), v)
	}
	if r.IfNoneMatch != "" {
		req.Header.Set("If-None-Match", r.IfNoneMatch)
	}
	if r.IfModifiedSince != "" {
		req.Header.Set("If-Modified-Since", r.IfModifiedSince)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		phases()
		return 0, nil, nil, false, opts.MaxBytes, nil, tm, err
	}
	defer resp.Body.Close()
	tm.Proto = resp.Proto

	// Stream PDFs up to 256 MiB directly to an ephemeral `/tmp` file when extracting Markdown/text (`KindScrape` / `KindPDF`),
	// avoiding 100+ MiB heap spikes on service manuals while seeking the PDF `xref` trailer on disk via Poppler `pdftotext`.
	canStreamPDF := (r.Kind == classify.KindScrape || r.Kind == classify.KindPDF) &&
		!hasFormat(r.Formats, "base64") &&
		resp.StatusCode >= 200 && resp.StatusCode <= 299 &&
		resp.Header.Get("cf-mitigated") == ""

	var prefix []byte
	if canStreamPDF {
		var pErr error
		prefix, pErr = io.ReadAll(io.LimitReader(resp.Body, 1024))
		if pErr != nil {
			phases()
			return 0, nil, nil, false, opts.MaxBytes, nil, tm, pErr
		}
		ctLower := strings.ToLower(resp.Header.Get("content-type"))
		if strings.Contains(ctLower, "application/pdf") || extract.IsPDFBytes(prefix) {
			if tmpFile, tmpErr := os.CreateTemp("", "edgefetch-pdf-*.pdf"); tmpErr == nil {
				tmpPath := tmpFile.Name()
				defer func() {
					_ = tmpFile.Close()
					_ = os.Remove(tmpPath)
				}()
				hasher := sha256.New()
				mw := io.MultiWriter(tmpFile, hasher)
				var totalWritten int64
				if len(prefix) > 0 {
					n, wErr := mw.Write(prefix)
					totalWritten += int64(n)
					if wErr != nil {
						phases()
						return 0, nil, nil, false, MaxStreamingPDFBytes, nil, tm, wErr
					}
				}
				remLimit := int64(MaxStreamingPDFBytes) - totalWritten + 1
				copyBuf := make([]byte, 32*1024)
				copied, cErr := io.CopyBuffer(mw, io.LimitReader(resp.Body, remLimit), copyBuf)
				totalWritten += copied
				phases()
				if cErr != nil {
					return 0, nil, nil, false, MaxStreamingPDFBytes, nil, tm, cErr
				}
				if totalWritten > MaxStreamingPDFBytes {
					return resp.StatusCode, resp.Header, nil, true, MaxStreamingPDFBytes, nil, tm, nil
				}
				_ = tmpFile.Close()
				sum := hasher.Sum(nil)
				txt, usedPoppler, extErr := extract.ExtractPDFFileText(actx, tmpPath, r.MaxPages)
				return resp.StatusCode, resp.Header, nil, false, MaxStreamingPDFBytes, &streamedPDFResult{
					rawBytes:    int(totalWritten),
					sha256Hex:   hex.EncodeToString(sum),
					text:        txt,
					usedPoppler: usedPoppler,
					err:         extErr,
				}, tm, nil
			}
		}
	}

	// Read `MaxBytes + 1` bytes so normal responses hit `EOF` cleanly (returning the HTTP/2 or keep-alive socket to the
	// pool for reuse) while oversized streams are detected and cut off without unbounded memory allocation.
	remBytes := int64(opts.MaxBytes) - int64(len(prefix)) + 1
	if remBytes < 1 {
		remBytes = 1
	}
	tail, err := io.ReadAll(io.LimitReader(resp.Body, remBytes))
	phases()
	if err != nil {
		return 0, nil, nil, false, opts.MaxBytes, nil, tm, err
	}
	limited := tail
	if len(prefix) > 0 {
		limited = make([]byte, 0, len(prefix)+len(tail))
		limited = append(limited, prefix...)
		limited = append(limited, tail...)
	}
	truncated := len(limited) > opts.MaxBytes
	if truncated {
		limited = limited[:opts.MaxBytes]
	}
	return resp.StatusCode, resp.Header, limited, truncated, opts.MaxBytes, nil, tm, nil
}

func (c *Crawler) checkRobots(ctx context.Context, hs *politeness.HostState, rawURL string) (allowed, distressed bool, reason string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, false, err.Error()
	}
	now := c.Now()
	entry := hs.CachedRobots(now)
	if entry == nil {
		var pause time.Duration
		entry, pause = c.fetchRobots(ctx, u)
		hs.SetRobots(c.Now(), entry, pause)
	}
	if entry.Distressed {
		msg := entry.Reason
		if msg == "" {
			msg = "robots.txt unreachable (disallow assumed per RFC 9309)"
		}
		return false, true, msg
	}
	if !entry.Allowed(u.RequestURI()) {
		return false, false, "robots.txt disallowed " + u.Path
	}
	return true, false, ""
}

// fetchRobots implements RFC 9309 §2.3.1 (following up to MaxRedirects validated redirects, e.g. apex -> www):
//   - 3xx (up to MaxRedirects hops): validate Location via `c.allow` and follow.
//   - 2xx: parse rules and cache for RobotsCacheTTL (24 h).
//   - 4xx except 429 (e.g. 404, 403, 410): "unavailable" -> allow all for RobotsCacheTTL (24 h).
//   - Network/timeout error, body read error, 429, or 5xx: "unreachable" -> disallow all for RobotsDistressTTL (5 m).
func (c *Crawler) fetchRobots(ctx context.Context, target *url.URL) (*politeness.RobotsEntry, time.Duration) {
	curURL := &url.URL{Scheme: target.Scheme, Host: target.Host, Path: "/robots.txt"}
	rctx, cancel := context.WithTimeout(ctx, politeness.RobotsTimeout)
	defer cancel()

	for hop := 0; hop <= MaxRedirects; hop++ {
		if c.allow != nil {
			if err := c.allow(curURL); err != nil {
				return &politeness.RobotsEntry{
					Distressed: true,
					Reason:     "robots.txt disallowed redirect target: " + err.Error(),
					ExpiresAt:  c.Now().Add(politeness.RobotsDistressTTL),
				}, politeness.DefaultThrottlePause
			}
		}

		req, err := http.NewRequestWithContext(rctx, http.MethodGet, curURL.String(), nil)
		if err != nil {
			return &politeness.RobotsEntry{
				Distressed: true,
				Reason:     "robots.txt request invalid: " + err.Error(),
				ExpiresAt:  c.Now().Add(politeness.RobotsDistressTTL),
			}, politeness.DefaultThrottlePause
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "text/plain,*/*;q=0.8")

		resp, err := c.client.Do(req)
		if err != nil {
			return &politeness.RobotsEntry{
				Distressed: true,
				Reason:     "robots.txt unreachable (disallow assumed per RFC 9309): " + err.Error(),
				ExpiresAt:  c.Now().Add(politeness.RobotsDistressTTL),
			}, politeness.DefaultThrottlePause
		}

		now := c.Now()
		if isRedirectStatus(resp.StatusCode) {
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if loc == "" {
				return &politeness.RobotsEntry{
					Distressed: true,
					Reason:     fmt.Sprintf("robots.txt redirect HTTP %d missing Location", resp.StatusCode),
					ExpiresAt:  now.Add(politeness.RobotsDistressTTL),
				}, politeness.DefaultThrottlePause
			}
			if hop == MaxRedirects {
				return &politeness.RobotsEntry{
					Distressed: true,
					Reason:     fmt.Sprintf("robots.txt exceeded %d redirects", MaxRedirects),
					ExpiresAt:  now.Add(politeness.RobotsDistressTTL),
				}, politeness.DefaultThrottlePause
			}
			locURL, parseErr := url.Parse(loc)
			if parseErr != nil {
				return &politeness.RobotsEntry{
					Distressed: true,
					Reason:     "robots.txt invalid redirect Location: " + parseErr.Error(),
					ExpiresAt:  now.Add(politeness.RobotsDistressTTL),
				}, politeness.DefaultThrottlePause
			}
			curURL = curURL.ResolveReference(locURL)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			pause := politeness.ParseRetryAfter(resp.Header.Get("Retry-After"), now)
			if pause < politeness.DefaultThrottlePause {
				pause = politeness.DefaultThrottlePause
			}
			_ = resp.Body.Close()
			return &politeness.RobotsEntry{
				Distressed: true,
				Reason:     fmt.Sprintf("robots.txt returned HTTP %d (disallow assumed per RFC 9309)", resp.StatusCode),
				ExpiresAt:  now.Add(politeness.RobotsDistressTTL),
			}, pause
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			_ = resp.Body.Close()
			return &politeness.RobotsEntry{ExpiresAt: now.Add(politeness.RobotsCacheTTL)}, 0
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return &politeness.RobotsEntry{
				Distressed: true,
				Reason:     fmt.Sprintf("robots.txt returned unexpected HTTP %d", resp.StatusCode),
				ExpiresAt:  now.Add(politeness.RobotsDistressTTL),
			}, politeness.DefaultThrottlePause
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, politeness.RobotsMaxBytes))
		_ = resp.Body.Close()
		if err != nil {
			return &politeness.RobotsEntry{
				Distressed: true,
				Reason:     "robots.txt read failed (disallow assumed per RFC 9309): " + err.Error(),
				ExpiresAt:  now.Add(politeness.RobotsDistressTTL),
			}, politeness.DefaultThrottlePause
		}

		uaProduct := strings.ToLower(c.userAgent)
		if slash := strings.IndexByte(uaProduct, '/'); slash > 0 {
			uaProduct = uaProduct[:slash]
		}
		return politeness.ParseRobotsTxt(string(raw), uaProduct, now.Add(politeness.RobotsCacheTTL)), 0
	}

	return &politeness.RobotsEntry{
		Distressed: true,
		Reason:     fmt.Sprintf("robots.txt exceeded %d redirects", MaxRedirects),
		ExpiresAt:  c.Now().Add(politeness.RobotsDistressTTL),
	}, politeness.DefaultThrottlePause
}

// Summary aggregates outcome and status-code histograms across a `FetchReply`.
type Summary struct {
	Total     int            `json:"total"`
	ByOutcome map[string]int `json:"byOutcome"`
	ByStatus  map[string]int `json:"byStatus"`
}

// Summarize computes `Summary` counts over `results`.
func Summarize(results []Result) Summary {
	s := Summary{
		Total:     len(results),
		ByOutcome: make(map[string]int),
		ByStatus:  make(map[string]int),
	}
	for _, r := range results {
		s.ByOutcome[string(r.Outcome)]++
		s.ByStatus[fmt.Sprintf("%d", r.Status)]++
	}
	return s
}
