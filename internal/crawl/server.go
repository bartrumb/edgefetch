package crawl

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/politeness"
)

const (
	MaxRequestsPerCall = 400
	MaxCallBodyBytes   = 1 << 20 // 1 MiB request payload ceiling
	DefaultMaxSeconds  = 600
	MaxMaxSeconds      = 1800
)

// FetchCall is the wire payload accepted by `POST /fetch` and WebSocket `dispatch`.
type FetchCall struct {
	Requests   []Request `json:"requests"`
	Options    Options   `json:"options"`
	MaxSeconds int       `json:"maxSeconds"`
}

// FetchReply is the wire payload returned by `POST /fetch` and uploaded to `POST /agent/reply`.
type FetchReply struct {
	Results    []Result `json:"results"`
	Summary    Summary  `json:"summary"`
	DurationMs int64    `json:"durationMs"`
}

// PublicHTTPS enforces the baseline SSRF URL invariant: https on port 443 with a multi-label DNS hostname (never an
// IP literal, localhost, or credentialed user:pass@ URL). Paired with politeness.RejectNonPublicPeer at dial time.
func PublicHTTPS(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("only https URLs: %s", u.Redacted())
	}
	if u.User != nil {
		return errors.New("URL with user info")
	}
	if p := u.Port(); p != "" && p != "443" {
		return fmt.Errorf("port %s not allowed", p)
	}
	host := politeness.CanonicalHost(u.Hostname())
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") {
		return fmt.Errorf("host %q not allowed", host)
	}
	return nil
}

// WithAllowedHosts restricts base to exact or subdomain matches of hosts when hosts contains non-empty entries.
func WithAllowedHosts(base func(*url.URL) error, hosts []string) func(*url.URL) error {
	clean := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		h := normalizeHostRule(raw)
		if h != "" {
			clean = append(clean, h)
		}
	}
	if len(clean) == 0 {
		return base
	}
	return func(u *url.URL) error {
		if err := base(u); err != nil {
			return err
		}
		host := politeness.CanonicalHost(u.Hostname())
		for _, allowed := range clean {
			if host == allowed || strings.HasSuffix(host, "."+allowed) {
				return nil
			}
		}
		return fmt.Errorf("host %q is not in allowed_hosts", host)
	}
}

// WithBlockedHost wraps base so an outbound agent can never be instructed to recursively fetch its own coordination hub.
func WithBlockedHost(base func(*url.URL) error, blockedHost string) func(*url.URL) error {
	blocked := normalizeHostRule(blockedHost)
	if blocked == "" {
		return base
	}
	return func(u *url.URL) error {
		if err := base(u); err != nil {
			return err
		}
		if politeness.CanonicalHost(u.Hostname()) == blocked {
			return fmt.Errorf("refusing recursive fetch of coordination hub %q", blocked)
		}
		return nil
	}
}

func normalizeHostRule(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	// Ignore empty placeholders like `[]` or `*` entered into Home Assistant UI list fields.
	if h == "" || h == "[]" || h == "*" || h == "none" {
		return ""
	}
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil {
			h = strings.ToLower(u.Hostname())
		}
	}
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimPrefix(h, ".")
	h = strings.TrimSuffix(h, ".")
	return h
}

// ValidateCall checks batch bounds, `Accept` kinds, URL rules, and default `robots.txt` enforcement before network IO.
func ValidateCall(call FetchCall, allow func(*url.URL) error) (code, msg string, ok bool) {
	return ValidateCallWithCrawler(nil, call, allow)
}

// ValidateCallWithCrawler validates `call`, rejecting `respectRobots: false` unless every target host is explicitly
// allowlisted on `c` via `SetRobotsBypassHosts` (off by default).
func ValidateCallWithCrawler(c *Crawler, call FetchCall, allow func(*url.URL) error) (code, msg string, ok bool) {
	if len(call.Requests) == 0 || len(call.Requests) > MaxRequestsPerCall {
		return "bad_requests", fmt.Sprintf("send 1 to %d requests", MaxRequestsPerCall), false
	}
	robotsDisabled := !call.Options.RobotsEnabled()
	for i, req := range call.Requests {
		if _, err := classify.AcceptFor(req.Kind, req.Accept); err != nil {
			return "bad_kind", fmt.Sprintf("request %d: %v", i, err), false
		}
		u, err := url.Parse(req.URL)
		if err == nil {
			err = allow(u)
		}
		if err != nil {
			return "bad_url", fmt.Sprintf("request %d: %v", i, err), false
		}
		if robotsDisabled && !c.AllowsRobotsBypass(u.Hostname()) {
			return "robots_required", fmt.Sprintf("request %d: disabling robots.txt is not permitted for host %q", i, politeness.CanonicalHost(u.Hostname())), false
		}
	}
	return "", "", true
}

// ExecuteCall enforces `MaxSeconds`, runs `c.RunLogged`, and logs batch summary metrics.
func ExecuteCall(ctx context.Context, c *Crawler, call FetchCall, log *slog.Logger) FetchReply {
	secs := call.MaxSeconds
	if secs <= 0 {
		secs = DefaultMaxSeconds
	}
	if secs > MaxMaxSeconds {
		secs = MaxMaxSeconds
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second)
	defer cancel()

	started := time.Now()
	results := c.RunLogged(cctx, call.Requests, call.Options, log)
	reply := FetchReply{
		Results:    results,
		Summary:    Summarize(results),
		DurationMs: time.Since(started).Milliseconds(),
	}
	log.Info("call",
		slog.Int("requests", len(call.Requests)), slog.Int64("duration_ms", reply.DurationMs),
		slog.Any("by_outcome", reply.Summary.ByOutcome), slog.Any("by_status", reply.Summary.ByStatus))
	return reply
}

// NewHandler constructs an unauthenticated HTTP router (/healthz, /fetch) for loopback or isolated container bridges.
func NewHandler(c *Crawler, allow func(*url.URL) error) http.Handler {
	return NewAuthenticatedHandler(c, allow, "")
}

// NewAuthenticatedHandler constructs the HTTP router (/healthz, /fetch) for server mode.
// When bearerToken is non-empty, POST /fetch requires a constant-time verified Authorization: Bearer <token> header.
func NewAuthenticatedHandler(c *Crawler, allow func(*url.URL) error, bearerToken string) http.Handler {
	mux := http.NewServeMux()
	wantAuth := strings.TrimSpace(bearerToken) != ""
	wantDigest := sha256.Sum256([]byte(strings.TrimSpace(bearerToken)))

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeHTTPError(w, http.StatusMethodNotAllowed, "method", "GET only")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeHTTPError(w, http.StatusMethodNotAllowed, "method", "POST only")
			return
		}
		if wantAuth {
			got, ok := parseBearerHeader(r.Header.Get("Authorization"))
			gotDigest := sha256.Sum256([]byte(got))
			if !ok || subtle.ConstantTimeCompare(gotDigest[:], wantDigest[:]) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeHTTPError(w, http.StatusUnauthorized, "unauthorized", "valid Bearer token required")
				return
			}
		}
		var call FetchCall
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxCallBodyBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&call); err != nil {
			writeHTTPError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if code, msg, ok := ValidateCallWithCrawler(c, call, allow); !ok {
			writeHTTPError(w, http.StatusBadRequest, code, msg)
			return
		}
		reply := ExecuteCall(r.Context(), c, call, CallLogger(c.Logger(), r.Header))
		writeJSON(w, http.StatusOK, reply)
	})
	return mux
}

func parseBearerHeader(val string) (string, bool) {
	if len(val) < 8 || !strings.EqualFold(val[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(val[7:])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHTTPError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

var traceHeaderFields = []struct{ header, field string }{
	{"x-trace-id", "trace_id"},
	{"x-span-id", "parent_span_id"},
	{"x-request-id", "ray_id"},
}

var validTraceToken = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// CallLogger attaches sanitized distributed trace identifiers onto `base` (blocking log-injection control characters).
func CallLogger(base *slog.Logger, h http.Header) *slog.Logger {
	var attrs []any
	for _, t := range traceHeaderFields {
		if v := h.Get(t.header); validTraceToken.MatchString(v) {
			attrs = append(attrs, slog.String(t.field, v))
		}
	}
	return base.With(attrs...)
}
