package crawl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/jobs"
	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

// isOpenAPIOrNotebookJSON reports whether raw is a JSON object with a top-level `openapi`, `swagger` or `nbformat`
// key (the documents the Hub formats as API specs / notebooks instead of record chunks). It streams top-level
// tokens and skips nested values without building the document.
func isOpenAPIOrNotebookJSON(raw string) bool {
	trimmed := strings.TrimLeft(raw, " \t\r\n\ufeff")
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return false
		}
		key, _ := keyTok.(string)
		switch key {
		case "openapi", "swagger", "nbformat":
			return true
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return false
		}
	}
	return false
}

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
		if !validHeaderNameRe.MatchString(k) {
			return fmt.Errorf("invalid header name %q", k)
		}
		lower := strings.ToLower(k)
		if isForbiddenCustomHeader(lower) {
			return fmt.Errorf("header %q is not permitted", k)
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] > 0x7E {
				return fmt.Errorf("header %q contains non-printable ASCII byte 0x%02x", k, v[i])
			}
		}
		totalBytes += len(k) + len(v)
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
		"te", "trailer", "transfer-encoding", "upgrade", "content-length", "via", "forwarded",
		"signature", "signature-input", "signature-agent":
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
	return r.Kind == classify.KindScrape || r.Kind == classify.KindRender
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
	wantMarkdown := hasFormat(r.Formats, "markdown") || r.Kind == classify.KindScrape || r.Kind == classify.KindRender || r.Kind == classify.KindPDF
	wantText := hasFormat(r.Formats, "text")
	wantLinks := hasFormat(r.Formats, "links")
	wantImages := hasFormat(r.Formats, "images")
	wantBranding := hasFormat(r.Formats, "branding")
	wantBase64 := hasFormat(r.Formats, "base64") || hasFormat(r.Formats, "rawBase64") || r.Kind == classify.KindBinary
	wantRawHTML := hasFormat(r.Formats, "rawHtml") || hasFormat(r.Formats, "html")
	onlyMain := true
	if r.OnlyMainContent != nil {
		onlyMain = *r.OnlyMainContent
	}

	if res.Outcome == classify.OutcomeOK && len(rawBody) > 0 {
		sum := sha256.Sum256(rawBody)
		if wantBase64 || r.Kind == classify.KindPDF {
			res.SHA256 = hex.EncodeToString(sum[:])
		}
		if wantBase64 {
			res.BodyBase64 = base64.StdEncoding.EncodeToString(rawBody)
		}
	}

	ct := strings.ToLower(res.ContentType)
	isOriginMarkdown := strings.Contains(ct, "text/markdown") || strings.Contains(ct, "text/x-markdown")

	if res.PDFEngine == "" && shouldDiscoverLlms(r, opts) && res.Outcome == classify.OutcomeOK && r.URL != "" {
		targetForLlms := res.FinalURL
		if targetForLlms == "" {
			targetForLlms = r.URL
		}
		disc := c.discoverHostLlms(ctx, targetForLlms, opts)
		if disc != nil {
			preferMd := !isOriginMarkdown && (r.PreferLlmsMarkdown == nil || *r.PreferLlmsMarkdown)
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

	isPDF := r.Kind == classify.KindPDF || strings.Contains(ct, "application/pdf") || extract.IsPDFBytes(rawBody)
	if isPDF && (wantMarkdown || wantText) {
		pdfTxt, usedPoppler, err := extract.ExtractPDFText(ctx, rawBody, r.MaxPages)
		if err == nil {
			if r.Query != "" {
				pdfTxt = extract.RerankPassages(pdfTxt, r.Query, 24_000)
			}
			if r.RedactPII {
				pdfTxt = extract.RedactPII(pdfTxt)
			}
			if wantMarkdown {
				res.Markdown = pdfTxt
			}
			if wantText {
				res.Text = pdfTxt
			}
			res.PDFEngine = "pure-go"
			if usedPoppler {
				res.PDFEngine = "poppler-pdftotext"
			}
		} else if r.Kind == classify.KindPDF {
			res.Problem = err.Error()
		}
		if !opts.IncludeBody && !wantRawHTML {
			res.Body = ""
			res.BodyEncoding = ""
		}
		return
	}

	if isOriginMarkdown {
		res.ContentSource = "origin-markdown"
	}

	// Step 2: When the caller sets `opts.MaxInlineBodyBytes` (e.g. Hub's 4 MiB WASM input budget) and `rawBody`
	// exceeds that inline limit, run full native Go extraction in OS memory here on the Go node so the Worker
	// isolate never receives or parses the >4 MiB raw body (while R2 sink still uploads the raw artifact!).
	if opts.MaxInlineBodyBytes > 0 && len(rawBody) > opts.MaxInlineBodyBytes && !wantBase64 {
		c.offloadOverBudgetDocumentOnNode(r, opts, rawBody, onlyMain, wantMarkdown, wantText, wantLinks, wantImages, wantBranding, isOriginMarkdown, res)
		return
	}

	isMarkdownOrPlain := isOriginMarkdown || strings.Contains(ct, "text/plain")
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

	isHTML := strings.Contains(ct, "html") || r.Kind == classify.KindPage || r.Kind == classify.KindRender || r.Kind == classify.KindScrape || r.Kind == classify.KindCatalog
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

func looksLikeHTMLPrefix(raw string) bool {
	trimmed := strings.TrimLeft(raw, " \t\r\n")
	if len(trimmed) > 256 {
		trimmed = trimmed[:256]
	}
	low := strings.ToLower(trimmed)
	return strings.HasPrefix(low, "<!doctype html") ||
		strings.HasPrefix(low, "<html") ||
		strings.Contains(low, "<head") ||
		strings.Contains(low, "<body") ||
		strings.Contains(low, "<main") ||
		strings.Contains(low, "<article")
}

func (c *Crawler) offloadOverBudgetDocumentOnNode(
	r Request,
	opts Options,
	rawBody []byte,
	onlyMain, wantMarkdown, wantText, wantLinks, wantImages, wantBranding, isOriginMarkdown bool,
	res *Result,
) {
	if !utf8.Valid(rawBody) {
		return
	}
	rawStr := string(rawBody)
	baseURL := res.FinalURL
	if baseURL == "" {
		baseURL = r.URL
	}
	ct := strings.ToLower(res.ContentType)

	// `ExtractedOnNode` is set only once a formatter actually matched (inside applyNodeMd). An unformattable body
	// (e.g. a >4 MiB `<urlset>` sitemap, which no node formatter handles) must not claim node extraction, or the Hub
	// would accept an empty result as a successful scrape.
	applyNodeMd := func(md, text string) {
		res.ExtractedOnNode = true
		// Tag scoping is honoured: the HTML branch passes IncludeTags/ExcludeTags to the extractor, and the non-HTML
		// formatters (JSON, feeds, CSV, ...) are unaffected by tags on the edge path too.
		if len(r.IncludeTags) > 0 || len(r.ExcludeTags) > 0 {
			res.ContentScopingApplied = true
		}
		if r.Query != "" && md != "" {
			md = extract.RerankPassages(md, r.Query, 24_000)
			if text != "" {
				text = md
			}
		}
		if r.RedactPII {
			if md != "" {
				md = extract.RedactPII(md)
			}
			if text != "" {
				text = extract.RedactPII(text)
			}
		}
		// Never truncate Markdown mid-document/mid-fence before the Hub's authoritative sanitizer pass!
		// If the extracted Markdown itself exceeds `opts.MaxInlineBodyBytes`, omit it cleanly and set
		// `MarkdownOverBudget = true` so the Hub returns a clear warning with the stored R2 artifact.
		if opts.MaxInlineBodyBytes > 0 && len(md) > opts.MaxInlineBodyBytes {
			res.Markdown = ""
			res.Text = ""
			res.MarkdownOverBudget = true
			return
		}
		if wantMarkdown && res.Markdown == "" {
			res.Markdown = md
		}
		if wantText {
			if text != "" && (opts.MaxInlineBodyBytes <= 0 || len(text) <= opts.MaxInlineBodyBytes) {
				res.Text = text
			} else if res.Markdown != "" {
				res.Text = res.Markdown
			}
		}
	}

	if isOriginMarkdown {
		applyNodeMd(rawStr, rawStr)
		return
	}

	isHTML := !isOriginMarkdown && (strings.Contains(ct, "html") || looksLikeHTMLPrefix(rawStr))
	if isHTML {
		full := extract.ExtractHTMLDocumentFull(rawStr, extract.FullExtractOptions{
			BaseURL:         baseURL,
			OnlyMainContent: onlyMain,
			IncludeImages:   wantImages,
			RedactPII:       r.RedactPII,
			MaxScanChars:    16 << 20,
			IncludeTags:     r.IncludeTags,
			ExcludeTags:     r.ExcludeTags,
		})
		res.Title = full.Title
		res.Description = full.Description
		res.Favicon = full.Favicon
		res.ExtractorID = full.ExtractorID
		if len(full.Records) > 0 {
			res.Records = full.Records
		}
		if wantLinks && len(full.Links) > 0 {
			res.Links = full.Links
		}
		if wantImages && len(full.Images) > 0 {
			res.Images = full.Images
		}
		if wantBranding {
			bCopy := full.Branding
			res.Branding = &bCopy
		}
		applyNodeMd(full.Markdown, full.Text)
		return
	}

	if doc, ok := extract.FormatDeclarativeTwinByURL(baseURL, rawStr, baseURL); ok && doc != nil && strings.TrimSpace(doc.Markdown) != "" {
		res.Title = doc.Title
		res.Description = doc.Description
		if wantLinks && len(doc.Links) > 0 {
			res.Links = doc.Links
		}
		if len(doc.Records) > 0 {
			res.Records = doc.Records
		}
		applyNodeMd(doc.Markdown, doc.Markdown)
		return
	}
	if feedDoc, feedLinks := extract.FormatFeedXMLToMarkdown(rawStr, baseURL); feedDoc != nil && strings.TrimSpace(feedDoc.Markdown) != "" {
		res.Title = feedDoc.Title
		res.Description = feedDoc.Description
		if wantLinks && len(feedLinks) > 0 {
			res.Links = feedLinks
		}
		applyNodeMd(feedDoc.Markdown, feedDoc.Markdown)
		return
	}
	if vcDoc := extract.FormatVCardToMarkdown(rawStr); vcDoc != nil && strings.TrimSpace(vcDoc.Markdown) != "" {
		res.Title = vcDoc.Title
		applyNodeMd(vcDoc.Markdown, vcDoc.Markdown)
		return
	}
	if icsDoc := extract.FormatICalendarToMarkdown(rawStr); icsDoc != nil && strings.TrimSpace(icsDoc.Markdown) != "" {
		res.Title = icsDoc.Title
		applyNodeMd(icsDoc.Markdown, icsDoc.Markdown)
		return
	}
	// `jsonFilter`: same per-record chunker + filter the Hub runs at the edge (`chunkJsonRecords` ->
	// `jobs_chunk_json_records`), so an over-budget JSON record array honors the filter instead of returning every
	// record. OpenAPI / notebook documents keep their dedicated formatter (the edge skips record chunking for them).
	structuredJSON := isOpenAPIOrNotebookJSON(rawStr)
	if structuredJSON {
		// The generic JSON formatter only previews documents over its 2 MiB DOM cap (a WASM-memory limit). The node
		// runs in OS memory, so over-budget OpenAPI specs / notebooks get their dedicated formatters in full.
		doc := extract.FormatJupyterNotebookToMarkdown(rawStr, baseURL)
		if doc == nil || strings.TrimSpace(doc.Markdown) == "" {
			doc = extract.FormatOpenAPISpecToMarkdown(rawStr, baseURL)
		}
		if doc != nil && strings.TrimSpace(doc.Markdown) != "" {
			res.Title = doc.Title
			res.Description = doc.Description
			applyNodeMd(doc.Markdown, "")
			return
		}
	}
	if r.JSONFilter != "" && !structuredJSON {
		if chunked := jobs.ChunkJSONRecords(jobs.ChunkJSONRecordsParams{
			RawBody:     rawStr,
			ContentType: res.ContentType,
			URL:         baseURL,
			JSONFilter:  r.JSONFilter,
		}); chunked != nil {
			res.Title = chunked.Title
			md := chunked.Markdown
			if strings.TrimSpace(md) == "" {
				md = fmt.Sprintf("No records matched jsonFilter (0 of %d records).", chunked.TotalRecords)
			}
			applyNodeMd(md, md)
			return
		}
	}
	if jsonDoc := extract.TryParseJSONPayloadForScrape(rawStr, baseURL); jsonDoc != nil && strings.TrimSpace(jsonDoc.Markdown) != "" {
		res.Title = jsonDoc.Title
		res.Description = jsonDoc.Description
		applyNodeMd(jsonDoc.Markdown, "")
		return
	}
	if csvDoc := extract.FormatDelimitedTableToMarkdown(rawStr, res.ContentType, baseURL); csvDoc != nil && strings.TrimSpace(csvDoc.Markdown) != "" {
		res.Title = csvDoc.Title
		applyNodeMd(csvDoc.Markdown, "")
		return
	}
	if patchDoc := extract.FormatGitPatchToMarkdown(rawStr, baseURL); patchDoc != nil && strings.TrimSpace(patchDoc.Markdown) != "" {
		res.Title = patchDoc.Title
		applyNodeMd(patchDoc.Markdown, "")
		return
	}
	if srcDoc := extract.FormatSourceCodeURLToMarkdown(rawStr, baseURL, res.ContentType); srcDoc != nil && strings.TrimSpace(srcDoc.Markdown) != "" {
		res.Title = srcDoc.Title
		applyNodeMd(srcDoc.Markdown, "")
		return
	}
	if strings.Contains(ct, "text/plain") {
		applyNodeMd(rawStr, rawStr)
	}
}

func (c *Crawler) runBrowserStep(ctx context.Context, r Request, opts Options, started time.Time) Result {
	res := Result{
		ID:       r.ID,
		URL:      r.URL,
		Kind:     r.Kind,
		Attempts: 1,
	}
	if c.renderer == nil || !c.renderer.Available() {
		res.Outcome = classify.OutcomeError
		res.Problem = browser.ErrBrowserUnavailable.Error()
		res.DurationMs = c.Now().Sub(started).Milliseconds()
		return res
	}

	rctx, cancel := context.WithTimeout(ctx, time.Duration(opts.TimeoutMs)*time.Millisecond)
	defer cancel()

	task := browser.Task{
		URL:                r.URL,
		UserAgent:          c.userAgent,
		AcceptLanguage:     r.AcceptLanguage,
		Headers:            r.Headers,
		Mobile:             r.Mobile,
		ViewportWidth:      r.ViewportWidth,
		ViewportHeight:     r.ViewportHeight,
		WaitForMs:          r.WaitForMs,
		WaitSelector:       r.WaitSelector,
		Screenshot:         hasFormat(r.Formats, "screenshot"),
		ScreenshotFullPage: r.ScreenshotFullPage,
		ScreenshotQuality:  r.ScreenshotQuality,
		BlockTrackers:      r.BlockTrackers,
	}
	if r.Interact != nil {
		task.SessionID = r.Interact.SessionID
		task.KeepSession = r.Interact.KeepSession
		task.CloseSession = r.Interact.CloseSession
		task.Actions = r.Interact.Actions
	}

	out, err := c.renderer.Execute(rctx, task)
	blockedCount := out.BlockedTrackers
	res.BlockedTrackers = &blockedCount
	if err != nil {
		res.Status = out.Status
		res.SessionID = out.SessionID
		res.ActionResults = out.ActionResults
		switch {
		case errors.Is(err, browser.ErrChallengeDetected):
			res.FinalURL = out.FinalURL
			res.Outcome = classify.OutcomeChallenge
			res.WAF = classify.ClassifyWAF(http.StatusOK, out.Headers, []byte(out.HTML))
			res.Problem = RedactEmbeddedURLs(err.Error())
		case isSSRFBlockError(err):
			res.Status = 0
			res.Outcome = classify.OutcomeBlockedSSRF
			res.BlockedReason = "ssrf"
			res.Problem = "blocked by SSRF policy: non-public target address"
		case isDNSNotFoundError(err) || strings.Contains(strings.ToUpper(err.Error()), "ERR_NAME_NOT_RESOLVED"):
			res.Status = 0
			res.Outcome = classify.OutcomeDNSNotFound
			res.Problem = "domain does not exist (DNS NXDOMAIN)"
		default:
			res.Outcome = classify.OutcomeError
			res.Problem = RedactEmbeddedURLs(err.Error())
		}
		res.DurationMs = c.Now().Sub(started).Milliseconds()
		return res
	}

	if out.FinalURL != "" && c.allow != nil {
		if finalParsed, pErr := url.Parse(out.FinalURL); pErr != nil {
			res.Outcome = classify.OutcomeError
			res.Problem = "invalid rendered finalUrl"
			res.DurationMs = c.Now().Sub(started).Milliseconds()
			return res
		} else if aErr := c.allow(finalParsed); aErr != nil {
			res.Outcome = classify.OutcomeBlockedSSRF
			res.BlockedReason = "ssrf"
			res.Problem = ssrfProblemFromAllowErr(aErr)
			res.DurationMs = c.Now().Sub(started).Milliseconds()
			return res
		}
	}

	rawBody := []byte(out.HTML)
	if len(rawBody) > opts.MaxBytes {
		res.Status = out.Status
		res.Bytes = opts.MaxBytes
		res.Truncated = true
		res.Outcome = classify.OutcomeError
		res.Problem = fmt.Sprintf("rendered DOM over %d bytes", opts.MaxBytes)
		res.DurationMs = c.Now().Sub(started).Milliseconds()
		return res
	}

	res.Status = out.Status
	if res.Status == 0 {
		res.Status = http.StatusOK
	}
	res.Bytes = len(rawBody)
	if len(rawBody) > 0 {
		res.ContentType = "text/html; charset=utf-8"
	} else {
		res.ContentType = out.Headers.Get("content-type")
		if res.ContentType == "" {
			res.ContentType = "text/html; charset=utf-8"
		}
	}
	res.FinalURL = out.FinalURL
	res.Rendered = true
	res.SessionID = out.SessionID
	res.ScreenshotBase64 = out.ScreenshotBase64
	res.ActionScreenshots = out.ActionScreenshots
	res.ActionScrapes = out.ActionScrapes
	res.JavascriptReturns = out.JavascriptReturns
	res.ActionResults = out.ActionResults
	res.CapturedJSON = out.CapturedJSON
	res.PDFBase64 = out.PDFBase64
	res.WAF = classify.ClassifyWAF(res.Status, out.Headers, rawBody)
	res.Outcome, res.Problem = classify.Classify(classify.KindRender, res.Status, out.Headers, rawBody)

	if opts.IncludeBody && len(rawBody) > 0 {
		if utf8.Valid(rawBody) {
			res.Body = string(rawBody)
			res.BodyEncoding = "utf-8"
		} else {
			res.Body = base64.StdEncoding.EncodeToString(rawBody)
			res.BodyEncoding = "base64"
		}
	}
	c.enrichResult(ctx, r, opts, rawBody, &res)
	res.DurationMs = c.Now().Sub(started).Milliseconds()
	return res
}
