// Package classify categorizes HTTP responses into deterministic crawl outcomes (ok, challenge, stop, gone,
// skip, error, not_tried) before upstream parsers inspect response bodies.
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
	KindPage    Kind = "page"    // Individual HTML document (`text/html`, 404/410 -> `gone`)
	KindText    Kind = "text"    // Auxiliary HTML or XML document (e.g., sitemap or collection)
	KindCatalog Kind = "catalog" // Full-catalog HTML page where non-2xx fails the host batch
)

// Outcome describes how the crawler and caller should act on an HTTP response.
type Outcome string

const (
	OutcomeOK        Outcome = "ok"
	OutcomeChallenge Outcome = "challenge" // Edge anti-bot challenge (`cf-mitigated`) — never retried
	OutcomeStop      Outcome = "stop"      // Origin answered 403, 429, or 503 — halt remaining URLs for this host
	OutcomeGone      Outcome = "gone"      // Document answered 404 or 410
	OutcomeSkip      Outcome = "skip"      // Non-200 or non-HTML page that can be skipped without failing the host
	OutcomeError     Outcome = "error"     // Feed/transport failure
	OutcomeNotTried  Outcome = "not_tried" // Left unsent because an earlier request stopped the host or timed out
)

// Classify evaluates status code, response headers, and body bytes to determine `(Outcome, problem)`.
//
// Note that Go `switch` cases do NOT fall through unless `fallthrough` is written explicitly, and multiple values
// can share one `case 403, 429, 503:` branch cleanly.
func Classify(kind Kind, status int, header http.Header, body []byte) (Outcome, string) {
	if header.Get("cf-mitigated") != "" {
		return OutcomeChallenge, "Cloudflare challenge (cf-mitigated)"
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
		if !ok || !strings.Contains(header.Get("content-type"), "text/html") {
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
	case OutcomeChallenge, OutcomeStop:
		return true
	case OutcomeError:
		return kind == KindFeed || kind == KindJSON || kind == KindCatalog
	}
	return false
}

// AcceptFor validates `(kind, requestedAccept)` and returns the outbound `Accept` header value.
func AcceptFor(kind Kind, requested string) (string, error) {
	switch kind {
	case KindFeed, KindJSON:
		return "application/json", nil
	case KindPage, KindCatalog:
		return "text/html", nil
	case KindText:
		switch requested {
		case "text/html", "application/xml", "text/xml", "application/rss+xml", "application/atom+xml", "application/json", "text/calendar", "text/plain":
			return requested, nil
		}
		return "", fmt.Errorf("unsupported KindText accept %q", requested)
	case "":
		return "", errors.New("missing kind")
	}
	return "", fmt.Errorf("unknown kind %q", kind)
}
