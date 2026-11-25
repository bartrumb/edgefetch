package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// DefaultDevTelemetryURL is the opt-in EdgeFetch structural error collector endpoint.
// Never contacted unless `EDGEFETCH_DEV_TELEMETRY=1` AND `DO_NOT_TRACK` is not truthy.
const DefaultDevTelemetryURL = "https://telemetry.edgefetch.dev/v1/dev-errors"

var (
	reSafeVersion    = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,32}$`)
	reSafeTokenShort = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	reSafeMode       = regexp.MustCompile(`^[a-z0-9_,-]{1,32}$`)
	reSafeSpanName   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,96}$`)
	reSafeAdapterID  = regexp.MustCompile(`^[A-Za-z0-9._:-]{0,64}$`)
	reSafeWafVendor  = regexp.MustCompile(`^[a-z0-9_-]{0,32}$`)
	reSafeErrorClass = regexp.MustCompile(`^[a-z0-9_:-]{1,64}$`)
)

// DevErrorReport contains ONLY structural, zero-PII error fields matching `telemetry.edgefetch.dev`'s strict allowlist.
// ZERO URLs, ZERO hostnames, ZERO paths, ZERO query strings, ZERO HTML/Markdown bodies, ZERO raw error messages, ZERO headers.
type DevErrorReport struct {
	SchemaVersion int    `json:"schemaVersion"`
	Version       string `json:"version"`
	Runtime       string `json:"runtime"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Mode          string `json:"mode"`
	SpanName      string `json:"spanName"`
	AdapterID     string `json:"adapterId"`
	WAFVendor     string `json:"wafVendor"`
	HTTPStatus    int    `json:"httpStatus"`
	ErrorClass    string `json:"errorClass"`
}

// IsDoNotTrack returns true when `DO_NOT_TRACK` is set to a truthy value (`1`, `true`, `yes`, `on`).
func IsDoNotTrack(raw string) bool {
	return isTruthyEnv(raw)
}

// IsDevTelemetryEnabled enforces the strict unattended-OFF & `DO_NOT_TRACK=1` hard-override invariant:
//   - Always `false` if `getenv == nil` or `DO_NOT_TRACK=1` (even when `EDGEFETCH_DEV_TELEMETRY=1`).
//   - Only `true` when `EDGEFETCH_DEV_TELEMETRY` is explicitly truthy (`1`, `true`, `yes`, `on`).
func IsDevTelemetryEnabled(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	if IsDoNotTrack(getenv("DO_NOT_TRACK")) {
		return false
	}
	return isTruthyEnv(getenv("EDGEFETCH_DEV_TELEMETRY"))
}

// ResolveDevTelemetryURL returns the active collector URL when opt-in telemetry is enabled, or `""` when disabled.
func ResolveDevTelemetryURL(getenv func(string) string) string {
	if !IsDevTelemetryEnabled(getenv) {
		return ""
	}
	custom := strings.TrimSpace(getenv("EDGEFETCH_DEV_TELEMETRY_URL"))
	if custom == "" {
		custom = strings.TrimSpace(getenv("EDGEFETCH_DEV_TELEMETRY_ENDPOINT"))
	}
	if custom == "" {
		return DefaultDevTelemetryURL
	}
	trimmed := strings.TrimRight(custom, "/")
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/dev-errors"
	}
	return u.String()
}

func inferModeFromServiceName(serviceName string) string {
	lower := strings.ToLower(strings.TrimSpace(serviceName))
	switch {
	case strings.HasPrefix(lower, "edgefetch-agent"):
		return "agent"
	case strings.Contains(lower, "mcp"):
		return "mcp"
	case strings.Contains(lower, "desktop"):
		return "desktop"
	case strings.Contains(lower, "serve") && !strings.Contains(lower, "server"):
		return "serve"
	case strings.Contains(lower, "hub"):
		return "hub"
	case strings.Contains(lower, "cli"):
		return "cli"
	default:
		return "server"
	}
}

func sanitizeStructuralToken(raw string, maxLen int, allowUpper bool) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !allowUpper {
		s = strings.ToLower(s)
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") || strings.Contains(lower, "://") {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < maxLen; i++ {
		c := s[i]
		isLower := c >= 'a' && c <= 'z'
		isUpper := allowUpper && c >= 'A' && c <= 'Z'
		isDigit := c >= '0' && c <= '9'
		if isLower || isUpper || isDigit || c == '_' || c == '-' || c == '.' || c == ':' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func attrString(attrs map[string]any, keys ...string) string {
	if len(attrs) == 0 {
		return ""
	}
	for _, k := range keys {
		if v, ok := attrs[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func attrInt(attrs map[string]any, keys ...string) int {
	if len(attrs) == 0 {
		return 0
	}
	for _, k := range keys {
		v, ok := attrs[k]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				return parsed
			}
		}
	}
	return 0
}

// ClassifyErrorClass maps span outcomes, HTTP status codes, WAF vendors, and error categories to a closed set of
// structural tokens — never echoing raw user URLs, hostnames, paths, or arbitrary exception strings.
func ClassifyErrorClass(httpStatus int, outcome, wafVendor, errMsg string) string {
	outLower := strings.ToLower(strings.TrimSpace(outcome))
	wafLower := strings.ToLower(strings.TrimSpace(wafVendor))
	msgLower := strings.ToLower(strings.TrimSpace(errMsg))

	switch outLower {
	case "challenge":
		return "waf_challenge"
	case "rate_limited":
		return "rate_limited"
	case "payment_required":
		return "payment_required"
	case "blocked_ssrf":
		return "ssrf_blocked"
	case "dns_not_found":
		return "dns_error"
	case "blocked":
		if strings.Contains(msgLower, "robots") {
			return "robots_disallowed"
		}
		return "waf_block"
	}

	if wafLower != "" {
		if httpStatus == 429 {
			return "rate_limited"
		}
		return "waf_challenge"
	}

	switch {
	case strings.Contains(msgLower, "robots"):
		return "robots_disallowed"
	case strings.Contains(msgLower, "non-public") || strings.Contains(msgLower, "ssrf") || strings.Contains(msgLower, "refusing dial"):
		return "ssrf_blocked"
	case strings.Contains(msgLower, "deadline exceeded") || strings.Contains(msgLower, "timeout") || strings.Contains(msgLower, "timed out"):
		return "timeout"
	case strings.Contains(msgLower, "tls") || strings.Contains(msgLower, "x509") || strings.Contains(msgLower, "certificate"):
		return "tls_error"
	case strings.Contains(msgLower, "no such host") || strings.Contains(msgLower, "dns"):
		return "dns_error"
	case strings.Contains(msgLower, "connection refused") || strings.Contains(msgLower, "connection reset") || strings.Contains(msgLower, "dial"):
		return "connect_error"
	case strings.Contains(msgLower, "browser") || strings.Contains(msgLower, "chromium") || strings.Contains(msgLower, "cdp"):
		return "browser_error"
	case strings.Contains(msgLower, "adapter") || strings.Contains(msgLower, "extractor"):
		return "adapter_error"
	}

	switch {
	case httpStatus == 401:
		return "http_401"
	case httpStatus == 402:
		return "payment_required"
	case httpStatus == 403:
		return "http_403"
	case httpStatus == 404:
		return "http_404"
	case httpStatus == 429:
		return "rate_limited"
	case httpStatus >= 400 && httpStatus < 500:
		return "http_4xx"
	case httpStatus >= 500 && httpStatus < 600:
		return "http_5xx"
	default:
		return "internal_error"
	}
}

// ValidateDevErrorReport verifies that `r` conforms strictly to the collector schema and contains zero URLs or PII.
func ValidateDevErrorReport(r DevErrorReport) error {
	if r.SchemaVersion != 1 {
		return errors.New("invalid schemaVersion")
	}
	if r.Runtime != "go" && r.Runtime != "workers" && r.Runtime != "node" && r.Runtime != "deno" {
		return errors.New("invalid runtime")
	}
	if !reSafeVersion.MatchString(r.Version) {
		return errors.New("invalid version")
	}
	if !reSafeTokenShort.MatchString(r.OS) || !reSafeTokenShort.MatchString(r.Arch) {
		return errors.New("invalid os/arch")
	}
	if !reSafeMode.MatchString(r.Mode) {
		return errors.New("invalid mode")
	}
	if !reSafeSpanName.MatchString(r.SpanName) {
		return errors.New("invalid spanName")
	}
	if !reSafeAdapterID.MatchString(r.AdapterID) {
		return errors.New("invalid adapterId")
	}
	if !reSafeWafVendor.MatchString(r.WAFVendor) {
		return errors.New("invalid wafVendor")
	}
	if r.HTTPStatus < 0 || r.HTTPStatus > 599 {
		return errors.New("invalid httpStatus")
	}
	if !reSafeErrorClass.MatchString(r.ErrorClass) {
		return errors.New("invalid errorClass")
	}
	for _, s := range []string{r.Version, r.Runtime, r.OS, r.Arch, r.Mode, r.SpanName, r.AdapterID, r.WAFVendor, r.ErrorClass} {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") || strings.Contains(lower, "://") {
			return errors.New("URL substring forbidden in telemetry report")
		}
	}
	return nil
}

// ScrubSpanToDevErrorReport converts a failed (`!StatusOK` or WAF-blocked) `Span` into a strictly allowlisted `DevErrorReport`.
// Healthy (`StatusOK == true` without WAF failure) spans return `(_, false)`.
func ScrubSpanToDevErrorReport(s Span, serviceName, serviceVersion string) (DevErrorReport, bool) {
	wafVendor := sanitizeStructuralToken(attrString(s.Attributes, "edgefetch.waf.vendor", "waf.vendor"), 32, false)
	outcome := attrString(s.Attributes, "crawler.outcome", "edgefetch.outcome")
	isWafOrFailure := !s.StatusOK || wafVendor != "" || outcome == "challenge" || outcome == "rate_limited" || outcome == "error"
	if !isWafOrFailure {
		return DevErrorReport{}, false
	}

	ver := strings.TrimPrefix(strings.TrimSpace(serviceVersion), "v")
	if ver == "" || !reSafeVersion.MatchString(ver) {
		ver = "unknown"
	}
	osName := sanitizeStructuralToken(runtime.GOOS, 24, false)
	if osName == "" {
		osName = "unknown"
	}
	archName := sanitizeStructuralToken(runtime.GOARCH, 24, false)
	if archName == "" {
		archName = "unknown"
	}
	mode := sanitizeStructuralToken(inferModeFromServiceName(serviceName), 32, false)
	if mode == "" {
		mode = "server"
	}
	spanName := sanitizeStructuralToken(s.Name, 96, true)
	if spanName == "" {
		spanName = "edgefetch.span"
	}
	adapterID := sanitizeStructuralToken(attrString(s.Attributes, "edgefetch.adapter_id", "adapter.id"), 64, true)
	status := attrInt(s.Attributes, "http.response.status_code", "http.status_code")
	if status < 0 || status > 599 {
		status = 0
	}
	errClass := ClassifyErrorClass(status, outcome, wafVendor, s.ErrorMessage)

	rep := DevErrorReport{
		SchemaVersion: 1,
		Version:       ver,
		Runtime:       "go",
		OS:            osName,
		Arch:          archName,
		Mode:          mode,
		SpanName:      spanName,
		AdapterID:     adapterID,
		WAFVendor:     wafVendor,
		HTTPStatus:    status,
		ErrorClass:    errClass,
	}
	if ValidateDevErrorReport(rep) != nil {
		return DevErrorReport{}, false
	}
	return rep, true
}

func (e *Exporter) sendDevErrorBatch(ctx context.Context, spans []Span) {
	if e == nil || e.client == nil {
		return
	}
	if e.getenv != nil && IsDoNotTrack(e.getenv("DO_NOT_TRACK")) {
		return
	}
	rtOpt := e.runtimeDevOptIn.Load()
	if rtOpt < 0 {
		return
	}
	targetURL := e.devTelemetryURL
	if targetURL == "" && rtOpt > 0 {
		targetURL = DefaultDevTelemetryURL
		if e.getenv != nil {
			if c := strings.TrimSpace(e.getenv("EDGEFETCH_DEV_TELEMETRY_URL")); c != "" {
				targetURL = c
			}
		}
	}
	if targetURL == "" {
		return
	}
	seen := make(map[string]struct{}, len(spans))
	events := make([]DevErrorReport, 0, 4)
	for _, s := range spans {
		rep, ok := ScrubSpanToDevErrorReport(s, e.serviceName, e.serviceVersion)
		if !ok {
			continue
		}
		dedupKey := rep.SpanName + "|" + rep.AdapterID + "|" + rep.WAFVendor + "|" + strconv.Itoa(rep.HTTPStatus) + "|" + rep.ErrorClass
		if _, dup := seen[dedupKey]; dup {
			continue
		}
		seen[dedupKey] = struct{}{}
		events = append(events, rep)
		if len(events) >= 16 {
			break
		}
	}
	if len(events) == 0 {
		return
	}

	var payload any
	if len(events) == 1 {
		payload = events[0]
	} else {
		payload = map[string]any{"events": events}
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil || len(bodyBytes) > 8192 {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	_ = resp.Body.Close()
}
