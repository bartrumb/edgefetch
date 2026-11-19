package crawl

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/extract"
	"github.com/bartrumb/edgefetch/internal/politeness"
)

const (
	maxCustomHeaders      = 16
	maxCustomHeadersBytes = 2048
	llmsCacheTTL          = 1 * time.Hour
	maxCachedLlmsHosts    = 512
	llmsMaxBytes          = 512 << 10 // 512 KiB ceiling on /llms.txt index files
)

var validHeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,64}$`)

// ValidateCustomHeaders enforces strict header-injection and hop-by-hop/auth header guards on caller-supplied headers.
// Safe domain headers pass; `Host`, `Authorization`, `Cookie`, `Proxy-*`, `CF-*`, `X-Forwarded-*`, and control bytes fail closed.
func ValidateCustomHeaders(hdrs map[string]string) error {
	if len(hdrs) == 0 {
		return nil
	}
	if len(hdrs) > maxCustomHeaders {
		return fmt.Errorf("too many custom headers (%d > %d)", len(hdrs), maxCustomHeaders)
	}
	totalBytes := 0
	for k, v := range hdrs {
		name := strings.TrimSpace(k)
		if !validHeaderNameRe.MatchString(name) {
			return fmt.Errorf("invalid header name %q", k)
		}
		lower := strings.ToLower(name)
		if isForbiddenCustomHeader(lower) {
			return fmt.Errorf("header %q is not permitted", name)
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] > 0x7E {
				return fmt.Errorf("header %q contains non-printable ASCII byte 0x%02x", name, v[i])
			}
		}
		totalBytes += len(name) + len(v)
		if totalBytes > maxCustomHeadersBytes {
			return fmt.Errorf("custom headers exceed %d bytes", maxCustomHeadersBytes)
		}
	}
	return nil
}

func isForbiddenCustomHeader(lower string) bool {
	switch lower {
	case "host", "user-agent", "authorization", "cookie", "cookie2", "set-cookie",
		"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
		"te", "trailer", "transfer-encoding", "upgrade", "content-length", "via", "forwarded":
		return true
	}
	return strings.HasPrefix(lower, "proxy-") ||
		strings.HasPrefix(lower, "sec-") ||
		strings.HasPrefix(lower, "cf-") ||
		strings.HasPrefix(lower, "x-forwarded-") ||
		strings.HasPrefix(lower, "x-real-ip")
}

type cachedLlmsEntry struct {
	doc       *extract.LlmsDocument // nil when host returned 404 or non-llms content
	expiresAt time.Time
}

type llmsCache struct {
	mu      sync.Mutex
	entries map[string]cachedLlmsEntry
}

func newLlmsCache() *llmsCache {
	return &llmsCache{entries: make(map[string]cachedLlmsEntry)}
}

func (lc *llmsCache) get(host string, now time.Time) (cachedLlmsEntry, bool) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	e, ok := lc.entries[host]
	if !ok {
		return cachedLlmsEntry{}, false
	}
	if !now.Before(e.expiresAt) {
		delete(lc.entries, host)
		return cachedLlmsEntry{}, false
	}
	return e, true
}

func (lc *llmsCache) set(host string, doc *extract.LlmsDocument, expiresAt time.Time) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if len(lc.entries) >= maxCachedLlmsHosts {
		for k := range lc.entries {
			delete(lc.entries, k)
			break
		}
	}
	lc.entries[host] = cachedLlmsEntry{doc: doc, expiresAt: expiresAt}
}

func hasFormat(formats []string, want string) bool {
	for _, f := range formats {
		if strings.EqualFold(strings.TrimSpace(f), want) {
			return true
		}
	}
	return false
}

func shouldDiscoverLlms(r Request, opts Options) bool {
	if r.DiscoverLlms != nil {
		return *r.DiscoverLlms
	}
	if opts.DiscoverLlms != nil {
		return *opts.DiscoverLlms
	}
	return r.Kind == classify.KindScrape
}

// runAuxiliaryFetch executes a polite secondary GET (`/llms.txt` or `<url>.md`) through `runRequestWithRedirects` so
// URL policy (`c.allow`), per-host locks, per-host pacing, `robots.txt`, and manual redirect hops are strictly enforced.
func (c *Crawler) runAuxiliaryFetch(ctx context.Context, targetURL, accept string, maxBytes int, opts Options) (Result, []byte, bool) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return Result{}, nil, false
	}
	if c.allow != nil {
		if err := c.allow(parsed); err != nil {
			return Result{}, nil, false
		}
	}
	auxOpts := opts
	auxOpts.IncludeBody = true
	if maxBytes > 0 && maxBytes < auxOpts.MaxBytes {
		auxOpts.MaxBytes = maxBytes
	}
	if auxOpts.TimeoutMs > 8_000 {
		auxOpts.TimeoutMs = 8_000
	}
	auxOpts.Retries = 0

	minPause := time.Duration(opts.PauseMs) * time.Millisecond
	maxJitter := time.Duration(opts.PauseJitterMs) * time.Millisecond
	gap := time.Duration(opts.GapMs) * time.Millisecond
	silentLog := slog.New(slog.NewTextHandler(io.Discard, nil))

	res, cancelled := c.runRequestWithRedirects(
		ctx,
		Request{
			ID:     "aux",
			URL:    targetURL,
			Kind:   classify.KindText,
			Accept: accept,
		},
		auxOpts,
		true,
		minPause,
		maxJitter,
		gap,
		silentLog,
	)
	if cancelled || res.Outcome != classify.OutcomeOK || res.Status < 200 || res.Status >= 300 {
		return res, nil, false
	}
	raw, err := res.DecodeBody()
	if err != nil {
		return res, nil, false
	}
	return res, raw, true
}

func (c *Crawler) discoverHostLlms(ctx context.Context, pageURL string, opts Options) *extract.LlmsDiscovery {
	u, err := url.Parse(pageURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil
	}
	lp := strings.ToLower(u.Path)
	if lp == "/llms.txt" || lp == "/llms-full.txt" || lp == "/.well-known/llms.txt" {
		return nil
	}

	host := politeness.CanonicalHost(u.Hostname())
	now := c.Now()
	c.hostsMu.Lock()
	if c.llms == nil {
		c.llms = newLlmsCache()
	}
	lc := c.llms
	c.hostsMu.Unlock()

	entry, cached := lc.get(host, now)
	if !cached {
		doc := c.fetchLlmsIndex(ctx, u, opts)
		lc.set(host, doc, c.Now().Add(llmsCacheTTL))
		entry = cachedLlmsEntry{doc: doc}
	}
	if entry.doc == nil {
		return &extract.LlmsDiscovery{Found: false}
	}

	matched, companionURL, related := entry.doc.MatchPage(pageURL)
	return &extract.LlmsDiscovery{
		Found:          true,
		LlmsTxtURL:     entry.doc.SourceURL,
		LlmsFullTxtURL: entry.doc.FullTxtURL,
		CompanionMdURL: companionURL,
		SiteTitle:      entry.doc.Title,
		SiteSummary:    entry.doc.Summary,
		MatchedEntry:   matched,
		RelatedLinks:   related,
	}
}

func (c *Crawler) fetchLlmsIndex(ctx context.Context, target *url.URL, opts Options) *extract.LlmsDocument {
	for _, candidatePath := range []string{"/llms.txt", "/.well-known/llms.txt"} {
		llmsURL := (&url.URL{Scheme: target.Scheme, Host: target.Host, Path: candidatePath}).String()
		_, raw, ok := c.runAuxiliaryFetch(ctx, llmsURL, "text/markdown", llmsMaxBytes, opts)
		if !ok {
			continue
		}
		if doc, valid := extract.ParseLlmsTxt(string(raw), llmsURL); valid {
			return doc
		}
	}
	return nil
}

func (c *Crawler) tryFetchCompanionMarkdown(ctx context.Context, mdURL string, opts Options) (string, bool) {
	if mdURL == "" {
		return "", false
	}
	res, raw, ok := c.runAuxiliaryFetch(ctx, mdURL, "text/markdown", opts.MaxBytes, opts)
	if !ok || res.Status != 200 {
		return "", false
	}
	ct := strings.ToLower(res.ContentType)
	text := strings.TrimSpace(string(raw))
	if len(text) < 24 {
		return "", false
	}
	prefixLen := len(text)
	if prefixLen > 256 {
		prefixLen = 256
	}
	lowerPrefix := strings.ToLower(text[:prefixLen])
	if strings.Contains(ct, "text/html") || strings.HasPrefix(lowerPrefix, "<!doctype") || strings.HasPrefix(lowerPrefix, "<html") {
		return "", false
	}
	return text, true
}

func (c *Crawler) enrichResult(ctx context.Context, r Request, opts Options, rawBody []byte, res *Result) {
	wantMarkdown := hasFormat(r.Formats, "markdown") || r.Kind == classify.KindScrape
	wantText := hasFormat(r.Formats, "text")
	wantLinks := hasFormat(r.Formats, "links")
	wantImages := hasFormat(r.Formats, "images")
	wantBranding := hasFormat(r.Formats, "branding")
	wantRawHTML := hasFormat(r.Formats, "rawHtml") || hasFormat(r.Formats, "html")
	onlyMain := true
	if r.OnlyMainContent != nil {
		onlyMain = *r.OnlyMainContent
	}

	if shouldDiscoverLlms(r, opts) && res.Outcome == classify.OutcomeOK {
		targetForLlms := res.FinalURL
		if targetForLlms == "" {
			targetForLlms = r.URL
		}
		disc := c.discoverHostLlms(ctx, targetForLlms, opts)
		if disc != nil {
			preferMd := r.PreferLlmsMarkdown == nil || *r.PreferLlmsMarkdown
			candidate := disc.CompanionMdURL
			if candidate == "" && preferMd && disc.Found {
				candidate = extract.CandidateCompanionMarkdownURL(targetForLlms)
			}
			if preferMd && candidate != "" {
				if mdBody, ok := c.tryFetchCompanionMarkdown(ctx, candidate, opts); ok {
					disc.CompanionMdURL = candidate
					disc.UsedCompanionMd = true
					if r.Query != "" {
						mdBody = extract.RerankPassages(mdBody, r.Query, 24_000)
					}
					if r.RedactPII {
						mdBody = extract.RedactPII(mdBody)
					}
					res.Markdown = mdBody
				}
			}
			res.Llms = disc
		}
	}

	if res.Outcome != classify.OutcomeOK || len(rawBody) == 0 {
		return
	}

	ct := strings.ToLower(res.ContentType)
	isMarkdownOrPlain := strings.Contains(ct, "text/markdown") || strings.Contains(ct, "text/plain")
	if isMarkdownOrPlain && (wantMarkdown || wantText) {
		txt := string(rawBody)
		if r.Query != "" {
			txt = extract.RerankPassages(txt, r.Query, 24_000)
		}
		if r.RedactPII {
			txt = extract.RedactPII(txt)
		}
		if wantMarkdown && res.Markdown == "" {
			res.Markdown = txt
		}
		if wantText {
			res.Text = txt
		}
		if !opts.IncludeBody && !wantRawHTML {
			res.Body = ""
			res.BodyEncoding = ""
		}
		return
	}

	isHTML := strings.Contains(ct, "html") || r.Kind == classify.KindPage || r.Kind == classify.KindScrape || r.Kind == classify.KindCatalog
	if isHTML && (wantMarkdown || wantText || wantLinks || wantImages || wantBranding) {
		baseURL := res.FinalURL
		if baseURL == "" {
			baseURL = r.URL
		}
		ext := extract.ExtractHTML(string(rawBody), extract.ExtractOptions{
			BaseURL:         baseURL,
			OnlyMainContent: onlyMain,
			IncludeLinks:    wantLinks,
			IncludeImages:   wantImages,
			IncludeBranding: wantBranding,
			RedactPII:       r.RedactPII,
			Query:           r.Query,
		})
		res.Title = ext.Title
		res.Description = ext.Description
		res.Favicon = ext.Favicon
		if wantMarkdown && res.Markdown == "" {
			res.Markdown = ext.Markdown
		}
		if wantText {
			res.Text = ext.Text
		}
		if wantLinks {
			res.Links = ext.Links
		}
		if wantImages {
			res.Images = ext.Images
		}
		if wantBranding {
			res.Branding = ext.Branding
		}
		if !opts.IncludeBody && !wantRawHTML {
			res.Body = ""
			res.BodyEncoding = ""
		}
	}
}
