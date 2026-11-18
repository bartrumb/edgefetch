// Package crawl implements a bounded-concurrency, polite HTTP/2 fetcher with `net/http/httptrace` phase telemetry,
// positive dwell jitter, conditional GETs (`ETag` / `If-Modified-Since`), and strict memory/SSRF guardrails.
//
// For Go learners reading this package:
//   - Compare `func (o Options) Normalize() Options` (a VALUE receiver that sanitizes a local struct copy without
//     mutating the caller) vs. `func (c *Crawler) Run(...)` (a POINTER receiver required whenever a struct embeds
//     `sync.Mutex` or shares mutable state across goroutines).
//   - Notice how `RunLogged` writes concurrently into `results := make([]Result, len(reqs))` WITHOUT a mutex on
//     `results`: because requests are partitioned by hostname and each index `i` belongs to exactly one goroutine,
//     disjoint index writes (`results[i] = res`) are 100% data-race free under `go test -race`.
package crawl

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/politeness"
)

// DefaultUserAgent is sent when no custom User-Agent is configured. Always identify crawlers honestly.
const DefaultUserAgent = "EdgeFetch/1.0 (+https://github.com/bartrumb/edgefetch)"

// Request describes a single URL to fetch within a batch.
type Request struct {
	ID              string        `json:"id"`
	URL             string        `json:"url"`
	Kind            classify.Kind `json:"kind"`
	Accept          string        `json:"accept,omitempty"`
	IfNoneMatch     string        `json:"ifNoneMatch,omitempty"`
	IfModifiedSince string        `json:"ifModifiedSince,omitempty"`
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

// Result reports the outcome, headers of interest, phase timings, and optional body of one `Request`.
type Result struct {
	ID           string           `json:"id"`
	URL          string           `json:"url"`
	Kind         classify.Kind    `json:"kind"`
	Outcome      classify.Outcome `json:"outcome"`
	Problem      string           `json:"problem,omitempty"`
	Status       int              `json:"status"`
	ContentType  string           `json:"contentType,omitempty"`
	CfMitigated  string           `json:"cfMitigated,omitempty"`
	ETag         string           `json:"etag,omitempty"`
	LastModified string           `json:"lastModified,omitempty"`
	RetryAfter   string           `json:"retryAfter,omitempty"`
	RetryAfterMs int64            `json:"retryAfterMs,omitempty"`
	Bytes        int              `json:"bytes"`
	Truncated    bool             `json:"truncated,omitempty"`
	Attempts     int              `json:"attempts"`
	DurationMs   int64            `json:"durationMs"`
	Timing       Timing           `json:"timing"`
	Body         string           `json:"body,omitempty"`
}

// Options bounds a crawl batch. Zero values take safe defaults in `Normalize()`.
type Options struct {
	PauseMs       int  `json:"pauseMs"`
	PauseJitterMs int  `json:"pauseJitterMs,omitempty"`
	GapMs         int  `json:"gapMs"`
	Concurrency   int  `json:"concurrency"`
	TimeoutMs     int  `json:"timeoutMs"`
	MaxBytes      int  `json:"maxBytes"`
	Retries       int  `json:"retries"`
	IncludeBody   bool `json:"includeBody"`
	RespectRobots bool `json:"respectRobots,omitempty"`
}

const (
	DefaultPauseMs   = 2000
	MaxPauseJitterMs = 30_000
	DefaultTimeoutMs = 30_000
	DefaultMaxBytes  = 8 << 20
	MaxMaxBytes      = 16 << 20
	MaxConcurrency   = 4
	MaxRetries       = 3
)

// Normalize clamps out-of-range or zero fields on a value copy of `Options`.
func (o Options) Normalize() Options {
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
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxBytes > MaxMaxBytes {
		o.MaxBytes = MaxMaxBytes
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
	userAgent string
	log       *slog.Logger

	// Injectable clock/sleep/jitter hooks make multi-second pacing tests run in < 1 ms without mocking frameworks.
	Sleep  func(ctx context.Context, d time.Duration) error
	Now    func() time.Time
	Jitter func(d time.Duration) time.Duration

	hostsMu    sync.Mutex
	hosts      *politeness.Registry
	globalMu   sync.Mutex
	globalNext time.Time
}

// NewCrawler constructs a `Crawler` whose HTTP redirects are validated against the same `allow` rule as initial URLs.
func NewCrawler(transport http.RoundTripper, allow func(*url.URL) error, userAgent string, log *slog.Logger) *Crawler {
	if strings.TrimSpace(userAgent) == "" {
		userAgent = DefaultUserAgent
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("more than 5 redirects")
			}
			return allow(req.URL)
		},
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var rngMu sync.Mutex
	return &Crawler{
		client:    client,
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

// Run executes `reqs` with `c.log` and returns results in exact input order.
func (c *Crawler) Run(ctx context.Context, reqs []Request, opts Options) []Result {
	return c.RunLogged(ctx, reqs, opts, c.log)
}

// RunLogged executes `reqs` using a request-scoped structured logger (carrying distributed trace IDs).
func (c *Crawler) RunLogged(ctx context.Context, reqs []Request, opts Options, log *slog.Logger) []Result {
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

			hs := c.hostStateFor(host)
			if err := hs.Acquire(ctx); err != nil {
				for _, i := range idx {
					results[i] = notTried(reqs[i], "crawl cancelled")
				}
				return
			}
			defer hs.Release()

			stopped := ""
			for n, i := range idx {
				r := reqs[i]
				if stopped != "" {
					results[i] = notTried(r, stopped)
					continue
				}
				if why := hs.CheckCircuit(c.Now(), host); why != "" {
					res := Result{ID: r.ID, URL: r.URL, Kind: r.Kind, Outcome: classify.OutcomeError, Problem: why}
					results[i] = res
					if classify.StopsHost(r.Kind, res.Outcome) {
						stopped = fmt.Sprintf("host stopped after %s on %s", res.Outcome, r.URL)
					}
					continue
				}

				if n == 0 {
					if d := hs.WaitDelay(c.Now()); d > 0 {
						if err := c.Sleep(ctx, d); err != nil {
							results[i] = notTried(r, "crawl cancelled")
							stopped = "crawl cancelled"
							continue
						}
					}
				} else {
					pause := minPause
					if cd := hs.CrawlDelay(c.Now()); cd > pause {
						pause = cd
					}
					if maxJitter > 0 {
						pause += c.Jitter(maxJitter)
					}
					if err := c.Sleep(ctx, pause); err != nil {
						results[i] = notTried(r, "crawl cancelled")
						stopped = "crawl cancelled"
						continue
					}
				}

				if err := c.waitGlobalGap(ctx, gap); err != nil {
					results[i] = notTried(r, "crawl cancelled")
					stopped = "crawl cancelled"
					continue
				}

				if opts.RespectRobots {
					if allowed, reason := c.checkRobots(ctx, hs, r.URL); !allowed {
						outcome := classify.OutcomeError
						if strings.HasPrefix(reason, "robots.txt returned") {
							outcome = classify.OutcomeStop
						} else if r.Kind == classify.KindPage || r.Kind == classify.KindText {
							outcome = classify.OutcomeSkip
						}
						res := Result{ID: r.ID, URL: r.URL, Kind: r.Kind, Outcome: outcome, Problem: reason}
						results[i] = res
						if classify.StopsHost(r.Kind, res.Outcome) {
							stopped = fmt.Sprintf("host stopped after %s on %s", res.Outcome, r.URL)
						}
						continue
					}
				}

				res := c.fetch(ctx, r, opts, log)
				results[i] = res
				retryAfter := time.Duration(res.RetryAfterMs) * time.Millisecond
				nextFloor := minPause
				if maxJitter > 0 {
					nextFloor += c.Jitter(maxJitter)
				}
				throttled := res.Status == http.StatusTooManyRequests || res.Status == http.StatusServiceUnavailable || res.Outcome == classify.OutcomeChallenge
				transientDead := (res.Status == 0 && res.Outcome == classify.OutcomeError) || retriableStatus(res.Status)
				hs.RecordOutcome(c.Now(), nextFloor, retryAfter, res.Status, throttled, transientDead)

				if gap > 0 && (res.Outcome == classify.OutcomeChallenge || res.Status == http.StatusTooManyRequests) {
					cool := politeness.DefaultThrottlePause
					if retryAfter > cool {
						cool = retryAfter
					}
					c.bumpGlobalThrottle(cool)
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

func notTried(r Request, why string) Result {
	return Result{ID: r.ID, URL: r.URL, Kind: r.Kind, Outcome: classify.OutcomeNotTried, Problem: why}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

func retriableStatus(status int) bool {
	return status == 500 || status == 502 || status == 504
}

func (c *Crawler) fetch(ctx context.Context, r Request, opts Options, log *slog.Logger) Result {
	started := c.Now()
	res := Result{ID: r.ID, URL: r.URL, Kind: r.Kind}
	accept, err := classify.AcceptFor(r.Kind, r.Accept)
	if err != nil {
		res.Outcome, res.Problem = classify.OutcomeError, err.Error()
		return res
	}

	for attempt := 1; ; attempt++ {
		res.Attempts = attempt
		status, header, body, truncated, timing, fetchErr := c.once(ctx, r, accept, opts)
		res.Timing = timing
		if fetchErr != nil {
			if ctx.Err() != nil {
				res.Outcome, res.Problem = classify.OutcomeError, ctx.Err().Error()
				break
			}
			if attempt <= opts.Retries {
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
		if ra := politeness.ParseRetryAfter(res.RetryAfter, c.Now()); ra > 0 {
			res.RetryAfterMs = ra.Milliseconds()
		}

		if truncated {
			res.Outcome, res.Problem = classify.OutcomeError, fmt.Sprintf("body over %d bytes", opts.MaxBytes)
			if header.Get("cf-mitigated") != "" {
				res.Outcome, res.Problem = classify.Classify(r.Kind, status, header, nil)
			}
		} else if status == http.StatusNotModified && (r.IfNoneMatch != "" || r.IfModifiedSince != "") && res.CfMitigated == "" {
			res.Outcome, res.Problem = classify.OutcomeOK, ""
		} else {
			res.Outcome, res.Problem = classify.Classify(r.Kind, status, header, body)
		}
		if opts.IncludeBody {
			res.Body = string(body)
		}
		break
	}
	res.DurationMs = c.Now().Sub(started).Milliseconds()

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
	return res
}

func (c *Crawler) backoff(ctx context.Context, attempt int) {
	d := time.Second << (attempt - 1)
	if d > 10*time.Second {
		d = 10 * time.Second
	}
	_ = c.Sleep(ctx, c.Jitter(d))
}

func ms(from, to time.Time) int64 {
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return 0
	}
	return to.Sub(from).Milliseconds()
}

func (c *Crawler) once(ctx context.Context, r Request, accept string, opts Options) (int, http.Header, []byte, bool, Timing, error) {
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

	actx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), time.Duration(opts.TimeoutMs)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(actx, http.MethodGet, r.URL, nil)
	if err != nil {
		return 0, nil, nil, false, tm, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if r.IfNoneMatch != "" {
		req.Header.Set("If-None-Match", r.IfNoneMatch)
	}
	if r.IfModifiedSince != "" {
		req.Header.Set("If-Modified-Since", r.IfModifiedSince)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		phases()
		return 0, nil, nil, false, tm, err
	}
	defer resp.Body.Close()
	tm.Proto = resp.Proto

	// Read `MaxBytes + 1` bytes so normal responses hit `EOF` cleanly (returning the HTTP/2 or keep-alive socket to the
	// pool for reuse) while oversized streams are detected and cut off without unbounded memory allocation.
	limited, err := io.ReadAll(io.LimitReader(resp.Body, int64(opts.MaxBytes)+1))
	phases()
	if err != nil {
		return 0, nil, nil, false, tm, err
	}
	truncated := len(limited) > opts.MaxBytes
	if truncated {
		limited = limited[:opts.MaxBytes]
	}
	return resp.StatusCode, resp.Header, limited, truncated, tm, nil
}

func (c *Crawler) checkRobots(ctx context.Context, hs *politeness.HostState, rawURL string) (bool, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, err.Error()
	}
	now := c.Now()
	entry := hs.CachedRobots(now)
	if entry == nil {
		entry = c.fetchRobots(ctx, u)
		distress := time.Duration(0)
		if entry.Distressed {
			distress = politeness.DefaultThrottlePause
		}
		hs.SetRobots(c.Now(), entry, distress)
	}
	if entry.Distressed {
		return false, "robots.txt returned 5xx (host paused)"
	}
	if !entry.Allowed(u.RequestURI()) {
		return false, "robots.txt disallowed " + u.Path
	}
	return true, ""
}

func (c *Crawler) fetchRobots(ctx context.Context, target *url.URL) *politeness.RobotsEntry {
	robotsURL := (&url.URL{Scheme: target.Scheme, Host: target.Host, Path: "/robots.txt"}).String()
	rctx, cancel := context.WithTimeout(ctx, politeness.RobotsTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return &politeness.RobotsEntry{ExpiresAt: c.Now().Add(politeness.RobotsDistressTTL)}
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/plain,*/*;q=0.8")

	resp, err := c.client.Do(req)
	if err != nil {
		return &politeness.RobotsEntry{ExpiresAt: c.Now().Add(politeness.RobotsDistressTTL)}
	}
	defer resp.Body.Close()

	now := c.Now()
	if resp.StatusCode >= 500 {
		return &politeness.RobotsEntry{Distressed: true, ExpiresAt: now.Add(politeness.RobotsDistressTTL)}
	}
	if resp.StatusCode != http.StatusOK {
		return &politeness.RobotsEntry{ExpiresAt: now.Add(politeness.RobotsCacheTTL)}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, politeness.RobotsMaxBytes))
	if err != nil {
		return &politeness.RobotsEntry{ExpiresAt: now.Add(politeness.RobotsDistressTTL)}
	}

	// Extract the primary User-Agent product token (e.g. `"EdgeFetch/1.0 ..."` -> `"edgefetch"`) for RFC 9309 matching.
	uaProduct := strings.ToLower(c.userAgent)
	if slash := strings.IndexByte(uaProduct, '/'); slash > 0 {
		uaProduct = uaProduct[:slash]
	}
	return politeness.ParseRobotsTxt(string(raw), uaProduct, now.Add(politeness.RobotsCacheTTL))
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
