package classify

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Kind identifies what resource shape the caller expects from a URL.
type Kind string

const (
	KindFeed    Kind = "feed"    // Structured JSON product feed (`{"products": [...]}`)
	KindJSON    Kind = "json"    // Any valid 2xx JSON document
	KindPage    Kind = "page"    // Individual HTML or Markdown document (`text/markdown` / `text/html`, 404/410 -> `gone`)
	KindText    Kind = "text"    // Auxiliary HTML, Markdown, or XML document (e.g., sitemap or llms.txt)
	KindCatalog Kind = "catalog" // Full-catalog HTML page where non-2xx fails the host batch
	KindScrape  Kind = "scrape"  // Universal smart scrape (HTML, Markdown, PDF, JSON, or XML -> Markdown + metadata)
	KindRender  Kind = "render"  // Headless Chromium JS-rendered HTML document (`edgefetch_fat`)
	KindPDF     Kind = "pdf"     // PDF document (`%PDF-` extracted via poppler `pdftotext` or pure-Go fallback)
	KindBinary  Kind = "binary"  // Binary resource returned as `bodyBase64` + `sha256`
)

// Outcome describes how the crawler and caller should act on an HTTP response.
type Outcome string

const (
	OutcomeOK              Outcome = "ok"
	OutcomeChallenge       Outcome = "challenge"        // Edge anti-bot challenge (`cf-mitigated`) — never retried
	OutcomeStop            Outcome = "stop"             // Origin answered 403, 429, or 503 — halt remaining URLs for this host
	OutcomePaymentRequired Outcome = "payment_required" // Origin answered HTTP 402 (e.g. x402 / Monetization Gateway) — halt host, never auto-pay
	OutcomeGone            Outcome = "gone"             // Document answered 404 or 410
	OutcomeSkip            Outcome = "skip"             // Non-200 or non-HTML/Markdown page that can be skipped without failing the host
	OutcomeError           Outcome = "error"            // Feed/transport failure
	OutcomeNotTried        Outcome = "not_tried"        // Left unsent because an earlier request stopped the host or timed out
)

// Classify evaluates status code, response headers, and body bytes to determine `(Outcome, problem)`.
//
// Note that Go `switch` cases do NOT fall through unless `fallthrough` is written explicitly, and multiple values
// can share one `case 403, 429, 503:` branch cleanly.
func Classify(kind Kind, status int, header http.Header, body []byte) (Outcome, string) {
	if waf := ClassifyWAF(status, header, body); waf != nil {
		return OutcomeChallenge, waf.Summary
	}
	if status == http.StatusPaymentRequired {
		return OutcomePaymentRequired, "http 402 payment required"
	}
	ok := status >= 200 && status <= 299

	switch kind {
	case KindText:
		switch status {
		case 403, 429, 503:
			return OutcomeStop, fmt.Sprintf("HTTP %d", status)
		}
		if !ok {
			return OutcomeSkip, ""
		}
		return OutcomeOK, ""

	case KindCatalog:
		if !ok {
			return OutcomeError, fmt.Sprintf("HTTP %d", status)
		}
		return OutcomeOK, ""

	case KindPage:
		switch status {
		case 403, 429, 503:
			return OutcomeStop, fmt.Sprintf("HTTP %d", status)
		case 404, 410:
			return OutcomeGone, ""
		}
		ctLower := strings.ToLower(header.Get("content-type"))
		isPageDoc := strings.Contains(ctLower, "text/html") ||
			strings.Contains(ctLower, "text/markdown") ||
			strings.Contains(ctLower, "text/x-markdown")
		if !ok || !isPageDoc {
			return OutcomeSkip, ""
		}
		return OutcomeOK, ""

	case KindJSON:
		if !ok {
			return OutcomeError, fmt.Sprintf("HTTP %d", status)
		}
		if !json.Valid(body) {
			return OutcomeError, invalidJSONMessage(header)
		}
		return OutcomeOK, ""

	case KindScrape, KindRender:
		switch status {
		case 403, 429, 503:
			return OutcomeStop, fmt.Sprintf("HTTP %d", status)
		case 404, 410:
			return OutcomeGone, fmt.Sprintf("HTTP %d", status)
		}
		if !ok {
			return OutcomeError, fmt.Sprintf("HTTP %d", status)
		}
		return OutcomeOK, ""

	case KindPDF:
		switch status {
		case 403, 429, 503:
			return OutcomeStop, fmt.Sprintf("HTTP %d", status)
		case 404, 410:
			return OutcomeGone, fmt.Sprintf("HTTP %d", status)
		}
		if !ok {
			return OutcomeError, fmt.Sprintf("HTTP %d", status)
		}
		ct := strings.ToLower(header.Get("content-type"))
		prefix := body
		if len(prefix) > 1024 {
			prefix = prefix[:1024]
		}
		if !strings.Contains(ct, "pdf") && !strings.Contains(string(prefix), "%PDF-") {
			return OutcomeError, fmt.Sprintf("not a PDF (%s)", ct)
		}
		return OutcomeOK, ""

	case KindBinary:
		switch status {
		case 403, 429, 503:
			return OutcomeStop, fmt.Sprintf("HTTP %d", status)
		case 404, 410:
			return OutcomeGone, fmt.Sprintf("HTTP %d", status)
		}
		if !ok {
			return OutcomeError, fmt.Sprintf("HTTP %d", status)
		}
		return OutcomeOK, ""
	}

	// Default (`KindFeed`): HTTP 2xx JSON object containing a top-level `"products"` array.
	if !ok {
		return OutcomeError, fmt.Sprintf("HTTP %d", status)
	}

	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return OutcomeError, invalidJSONMessage(header)
	}
	obj, isObj := parsed.(map[string]any)
	if !isObj {
		if parsed == nil {
			return OutcomeError, "feed is JSON null"
		}
		return OutcomeError, "no products array"
	}
	if _, isArr := obj["products"].([]any); !isArr {
		return OutcomeError, "no products array"
	}
	return OutcomeOK, ""
}

func invalidJSONMessage(header http.Header) string {
	ct := header.Get("content-type")
	if ct == "" {
		ct = "null"
	}
	return fmt.Sprintf("not JSON (%s)", ct)
}

// StopsHost reports whether `outcome` on `kind` should leave remaining queued URLs for the same host `not_tried`.
func StopsHost(kind Kind, o Outcome) bool {
	switch o {
	case OutcomeChallenge, OutcomeStop, OutcomePaymentRequired:
		return true
	case OutcomeError:
		return kind == KindFeed || kind == KindJSON || kind == KindCatalog
	}
	return false
}

// DefaultAgentPageAccept negotiates Markdown for Agents first (`G1`), falling back cleanly to HTML.
const DefaultAgentPageAccept = "text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.8, */*;q=0.7"

// AcceptFor validates `(kind, requestedAccept)` and returns the outbound `Accept` header value.
func AcceptFor(kind Kind, requested string) (string, error) {
	switch kind {
	case KindFeed, KindJSON:
		return "application/json", nil
	case KindPage:
		return DefaultAgentPageAccept, nil
	case KindCatalog:
		return "text/html", nil
	case KindRender:
		return "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", nil
	case KindScrape:
		if requested != "" {
			return requested, nil
		}
		return DefaultAgentPageAccept, nil
	case KindPDF:
		return "application/pdf,*/*;q=0.8", nil
	case KindBinary:
		if requested != "" {
			return requested, nil
		}
		return "*/*", nil
	case KindText:
		switch requested {
		case "text/html", "text/markdown", "text/x-markdown", "application/xml", "text/xml", "application/rss+xml", "application/atom+xml", "application/json", "text/calendar", "text/plain":
			return requested, nil
		}
		return "", fmt.Errorf("unsupported KindText accept %q", requested)
	case "":
		return "", errors.New("missing kind")
	}
	return "", fmt.Errorf("unknown kind %q", kind)
}
