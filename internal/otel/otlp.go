package otel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

var reTraceparent = regexp.MustCompile(`^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-([0-9a-fA-F]{2})$`)

const (
	zeroTraceID = "00000000000000000000000000000000"
	zeroSpanID  = "0000000000000000"
)

// TraceContext holds W3C Trace Context identifiers (`00-<TraceID>-<SpanID>-<Flags>`).
type TraceContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Sampled      bool
}

// RandomHex generates `byteLen` CSPRNG bytes encoded as lowercase hex.
func RandomHex(byteLen int) string {
	buf := make([]byte, byteLen)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// ParseTraceparent parses an incoming W3C `traceparent` header and mints a fresh child `SpanID`.
func ParseTraceparent(raw string) (TraceContext, bool) {
	m := reTraceparent.FindStringSubmatch(strings.TrimSpace(raw))
	if len(m) != 4 {
		return TraceContext{}, false
	}
	traceID := strings.ToLower(m[1])
	parentSpanID := strings.ToLower(m[2])
	if traceID == zeroTraceID || parentSpanID == zeroSpanID {
		return TraceContext{}, false
	}
	flags, err := strconv.ParseUint(m[3], 16, 8)
	if err != nil {
		return TraceContext{}, false
	}
	return TraceContext{
		TraceID:      traceID,
		SpanID:       RandomHex(8),
		ParentSpanID: parentSpanID,
		Sampled:      (flags & 0x01) == 0x01,
	}, true
}

// FormatTraceparent formats `tc` as a W3C `traceparent` header value.
func FormatTraceparent(tc TraceContext) string {
	flag := "00"
	if tc.Sampled {
		flag = "01"
	}
	traceID := tc.TraceID
	if len(traceID) != 32 {
		traceID = RandomHex(16)
	}
	spanID := tc.SpanID
	if len(spanID) != 16 {
		spanID = RandomHex(8)
	}
	return "00-" + traceID + "-" + spanID + "-" + flag
}

// ExtractOrNew inspects `traceparent` (or fallback `X-Trace-Id` / `X-Span-Id`) on `h`, creating a new root
// trace when absent.
func ExtractOrNew(h http.Header) TraceContext {
	if h != nil {
		if tc, ok := ParseTraceparent(h.Get("traceparent")); ok {
			return tc
		}
		rawTrace := strings.ToLower(strings.TrimSpace(h.Get("x-trace-id")))
		if len(rawTrace) == 32 && isHex(rawTrace) && rawTrace != zeroTraceID {
			parent := strings.ToLower(strings.TrimSpace(h.Get("x-span-id")))
			if len(parent) != 16 || !isHex(parent) || parent == zeroSpanID {
				parent = ""
			}
			return TraceContext{
				TraceID:      rawTrace,
				SpanID:       RandomHex(8),
				ParentSpanID: parent,
				Sampled:      true,
			}
		}
	}
	return TraceContext{
		TraceID: RandomHex(16),
		SpanID:  RandomHex(8),
		Sampled: true,
	}
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isValidTraceID(id string) bool {
	return len(id) == 32 && isHex(id) && id != zeroTraceID
}

func isValidSpanID(id string) bool {
	return len(id) == 16 && isHex(id) && id != zeroSpanID
}

type traceContextKey struct{}

// WithTraceContext attaches `tc` onto `ctx` (using `context.Background()` when `ctx == nil`).
func WithTraceContext(ctx context.Context, tc TraceContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceContextKey{}, tc)
}

// TraceContextFromContext retrieves a valid `TraceContext` attached by `WithTraceContext`.
func TraceContextFromContext(ctx context.Context) (TraceContext, bool) {
	if ctx == nil {
		return TraceContext{}, false
	}
	tc, ok := ctx.Value(traceContextKey{}).(TraceContext)
	if !ok {
		return TraceContext{}, false
	}
	tc.TraceID = strings.ToLower(strings.TrimSpace(tc.TraceID))
	tc.SpanID = strings.ToLower(strings.TrimSpace(tc.SpanID))
	tc.ParentSpanID = strings.ToLower(strings.TrimSpace(tc.ParentSpanID))
	if !isValidTraceID(tc.TraceID) || !isValidSpanID(tc.SpanID) {
		return TraceContext{}, false
	}
	return tc, true
}

// Child derives a child `TraceContext` preserving `TraceID` and `Sampled` while linking `ParentSpanID` to `tc.SpanID`.
func (tc TraceContext) Child() TraceContext {
	traceID := strings.ToLower(strings.TrimSpace(tc.TraceID))
	if !isValidTraceID(traceID) {
		traceID = RandomHex(16)
	}
	parentSpanID := strings.ToLower(strings.TrimSpace(tc.SpanID))
	if !isValidSpanID(parentSpanID) {
		parentSpanID = ""
	}
	return TraceContext{
		TraceID:      traceID,
		SpanID:       RandomHex(8),
		ParentSpanID: parentSpanID,
		Sampled:      tc.Sampled,
	}
}

// InjectHeaders writes W3C `traceparent` and EdgeFetch correlation headers (`X-Trace-Id`, `X-Span-Id`, `X-Request-Id`) onto `dst`.
func InjectHeaders(dst http.Header, tc TraceContext, requestID string) {
	if dst == nil {
		return
	}
	if !isValidTraceID(strings.ToLower(strings.TrimSpace(tc.TraceID))) {
		tc.TraceID = RandomHex(16)
	} else {
		tc.TraceID = strings.ToLower(strings.TrimSpace(tc.TraceID))
	}
	if !isValidSpanID(strings.ToLower(strings.TrimSpace(tc.SpanID))) {
		tc.SpanID = RandomHex(8)
	} else {
		tc.SpanID = strings.ToLower(strings.TrimSpace(tc.SpanID))
	}
	dst.Set("Traceparent", FormatTraceparent(tc))
	dst.Set("X-Trace-Id", tc.TraceID)
	dst.Set("X-Span-Id", tc.SpanID)
	if reqID := strings.TrimSpace(requestID); reqID != "" {
		dst.Set("X-Request-Id", reqID)
	} else if strings.TrimSpace(dst.Get("X-Request-Id")) == "" {
		dst.Set("X-Request-Id", tc.SpanID)
	}
}

// SanitizeURL strips `user:pass@` credentials (including schemeless userinfo), query parameters, `#fragments`,
// matrix parameters, and reset path tokens from `raw` for safe OTLP logging (`politeness.SanitizeURL` parity).
func SanitizeURL(raw string) string {
	return politeness.SanitizeURL(raw)
}

func scrubRawURL(raw string) string {
	return politeness.SanitizeURL(raw)
}

// RedactEmbeddedURLs delegates directly to `politeness.RedactEmbeddedURLs` so OTLP span error strings have 100%
// redaction parity across `http://`, `https://`, `ws://`, `wss://`, `ftp://`, schemeless userinfo, percent-encoded
// credentials, JSON-escaped slashes, query strings, `#fragments`, and inline Bearer/Basic/token secrets.
func RedactEmbeddedURLs(s string) string {
	return politeness.RedactEmbeddedURLs(s)
}

// ActiveSpan tracks an in-flight OTLP span and exports it once on `End`.
type ActiveSpan struct {
	mu    sync.Mutex
	exp   *Exporter
	tc    TraceContext
	name  string
	kind  int
	start time.Time
	attrs map[string]any
	ended bool
}

// StartSpan begins an `ActiveSpan` using `tc`'s exact `TraceID`/`SpanID`/`ParentSpanID` (preserving `Sampled`).
func StartSpan(exp *Exporter, tc TraceContext, name string, kind int, attrs map[string]any) *ActiveSpan {
	if !isValidTraceID(strings.ToLower(strings.TrimSpace(tc.TraceID))) {
		tc.TraceID = RandomHex(16)
	} else {
		tc.TraceID = strings.ToLower(strings.TrimSpace(tc.TraceID))
	}
	if !isValidSpanID(strings.ToLower(strings.TrimSpace(tc.SpanID))) {
		tc.SpanID = RandomHex(8)
	} else {
		tc.SpanID = strings.ToLower(strings.TrimSpace(tc.SpanID))
	}
	var cloned map[string]any
	if len(attrs) > 0 {
		cloned = make(map[string]any, len(attrs))
		for k, v := range attrs {
			cloned[k] = v
		}
	}
	return &ActiveSpan{
		exp:   exp,
		tc:    tc,
		name:  name,
		kind:  kind,
		start: time.Now(),
		attrs: cloned,
	}
}

// StartChildSpan derives a child `TraceContext` from `ctx` (or mints a fresh root when absent), attaches it to the
// returned `context.Context` even when `exp == nil` or `!Sampled`, and starts an `ActiveSpan`.
func StartChildSpan(ctx context.Context, exp *Exporter, name string, kind int, attrs map[string]any) (context.Context, *ActiveSpan, TraceContext) {
	var child TraceContext
	if parentTC, ok := TraceContextFromContext(ctx); ok {
		child = parentTC.Child()
	} else {
		child = ExtractOrNew(nil)
	}
	span := StartSpan(exp, child, name, kind, attrs)
	return WithTraceContext(ctx, child), span, child
}

// SetAttribute attaches or updates an attribute on an active span prior to `End`.
func (a *ActiveSpan) SetAttribute(k string, v any) {
	if a == nil || k == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ended {
		return
	}
	if a.attrs == nil {
		a.attrs = make(map[string]any)
	}
	a.attrs[k] = v
}

// Suppress marks the span ended without exporting it (used to prevent unauthenticated 401/pre-auth scanner traffic
// from amplifying OTLP collector billing while preserving response W3C trace correlation headers).
func (a *ActiveSpan) Suppress() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.ended = true
	a.mu.Unlock()
}

// End finishes the span once and records it to the exporter when non-nil and sampled.
func (a *ActiveSpan) End(statusOK bool, errMsg string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.ended {
		a.mu.Unlock()
		return
	}
	a.ended = true
	exp := a.exp
	tc := a.tc
	name := a.name
	kind := a.kind
	start := a.start
	var attrs map[string]any
	if len(a.attrs) > 0 {
		attrs = make(map[string]any, len(a.attrs))
		for k, v := range a.attrs {
			attrs[k] = v
		}
	}
	a.mu.Unlock()

	if exp == nil || !tc.Sampled {
		return
	}
	exp.Record(Span{
		TraceID:      tc.TraceID,
		SpanID:       tc.SpanID,
		ParentSpanID: tc.ParentSpanID,
		Name:         name,
		Kind:         kind,
		Start:        start,
		End:          time.Now(),
		StatusOK:     statusOK,
		ErrorMessage: RedactEmbeddedURLs(errMsg),
		Attributes:   attrs,
	})
}

// Span represents one OpenTelemetry trace span ready for OTLP/HTTP JSON export.
type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Name         string
	Kind         int // 1=INTERNAL, 2=SERVER, 3=CLIENT
	Start        time.Time
	End          time.Time
	StatusOK     bool
	ErrorMessage string
	Attributes   map[string]any
}

// ResolveTracesURL normalizes `OTEL_EXPORTER_OTLP_ENDPOINT` onto its `/v1/traces` HTTP URL.
func ResolveTracesURL(endpoint string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/traces"
	} else if !strings.HasSuffix(u.Path, "/v1/traces") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/traces"
	}
	return u.String()
}

// ParseHeaders parses standard `OTEL_EXPORTER_OTLP_HEADERS` (`k1=v1,k2=v2`, supporting URL-encoded values).
func ParseHeaders(raw string) map[string]string {
	out := make(map[string]string)
	if strings.TrimSpace(raw) == "" {
		return out
	}
	for _, item := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || strings.ContainsAny(k, "\r\n\x00") || strings.ContainsAny(v, "\r\n\x00") {
			continue
		}
		if dec, err := url.PathUnescape(v); err == nil {
			v = dec
		}
		out[k] = v
	}
	return out
}

// Exporter batches and flushes OTLP/HTTP JSON spans asynchronously off the crawl critical path.
type Exporter struct {
	tracesURL       string
	devTelemetryURL string
	stdoutOut       io.Writer
	stdoutMu        sync.Mutex
	headers         map[string]string
	serviceName     string
	serviceVersion  string
	client          *http.Client
	tickInterval    time.Duration

	ch              chan Span
	stopCh          chan struct{}
	wg              sync.WaitGroup
	once            sync.Once
	getenv          func(string) string
	runtimeDevOptIn atomic.Int32
}

func isTruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// NewExporterFromEnv returns a live `*Exporter` when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured (or when
// `EDGEFETCH_OTEL_STDOUT=1` / `OTEL_EXPORTER_OTLP_ENDPOINT=stdout` is set for local issue debugging), or `nil` when unset.
func NewExporterFromEnv(getenv func(string) string, defaultService, version string, transport http.RoundTripper) *Exporter {
	return newExporterFromEnv(getenv, defaultService, version, transport, os.Stderr, time.Second)
}

// NewStandbyDevTelemetryExporter constructs an idle `*Exporter` for Hub mode when no OTLP endpoint or env telemetry
// flag is set at startup, so `/admin` runtime opt-in (`SetRuntimeDevTelemetry(true)`) works live without restart while
// incurring zero channel/network work while idle (`DO_NOT_TRACK=1` still returns `nil`).
func NewStandbyDevTelemetryExporter(getenv func(string) string, defaultService, version string, transport http.RoundTripper) *Exporter {
	if getenv != nil && IsDoNotTrack(getenv("DO_NOT_TRACK")) {
		return nil
	}
	svc := defaultService
	if getenv != nil {
		if s := strings.TrimSpace(getenv("OTEL_SERVICE_NAME")); s != "" {
			svc = s
		}
	}
	if svc == "" {
		svc = "edgefetch-go-hub"
	}
	if version == "" {
		version = "2.8.11"
	}
	e := &Exporter{
		serviceName:    svc,
		serviceVersion: version,
		client:         &http.Client{Transport: transport, Timeout: 5 * time.Second},
		tickInterval:   time.Second,
		ch:             make(chan Span, 256),
		stopCh:         make(chan struct{}),
		getenv:         getenv,
	}
	e.wg.Add(1)
	go e.loop()
	return e
}

func newExporterFromEnv(
	getenv func(string) string,
	defaultService, version string,
	transport http.RoundTripper,
	stderrOut io.Writer,
	tickInterval time.Duration,
) *Exporter {
	if getenv == nil {
		return nil
	}
	rawEndpoint := strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	wantStdout := isTruthyEnv(getenv("EDGEFETCH_OTEL_STDOUT")) || strings.EqualFold(rawEndpoint, "stdout") || strings.EqualFold(rawEndpoint, "stderr")
	tracesURL := ""
	if !strings.EqualFold(rawEndpoint, "stdout") && !strings.EqualFold(rawEndpoint, "stderr") {
		tracesURL = ResolveTracesURL(rawEndpoint)
	}
	devTelURL := ResolveDevTelemetryURL(getenv)
	if tracesURL == "" && !wantStdout && devTelURL == "" {
		return nil
	}
	svc := strings.TrimSpace(getenv("OTEL_SERVICE_NAME"))
	if svc == "" {
		svc = defaultService
	}
	if svc == "" {
		svc = "edgefetch-go"
	}
	if version == "" {
		version = "2.8.11"
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	var stdoutWriter io.Writer
	if wantStdout {
		stdoutWriter = stderrOut
	}
	if tickInterval <= 0 {
		tickInterval = time.Second
	}
	if rawDelay := strings.TrimSpace(getenv("OTEL_BSP_SCHEDULE_DELAY")); rawDelay != "" {
		if ms, err := strconv.Atoi(rawDelay); err == nil && ms >= 10 && ms <= 60_000 {
			tickInterval = time.Duration(ms) * time.Millisecond
		}
	}
	e := &Exporter{
		tracesURL:       tracesURL,
		devTelemetryURL: devTelURL,
		stdoutOut:       stdoutWriter,
		headers:         ParseHeaders(getenv("OTEL_EXPORTER_OTLP_HEADERS")),
		serviceName:     svc,
		serviceVersion:  version,
		client:          client,
		tickInterval:    tickInterval,
		ch:              make(chan Span, 256),
		stopCh:          make(chan struct{}),
		getenv:          getenv,
	}
	e.wg.Add(1)
	go e.loop()
	return e
}

// SetRuntimeDevTelemetry updates the runtime structural dev-telemetry toggle (`DO_NOT_TRACK=1` always overrides to off).
func (e *Exporter) SetRuntimeDevTelemetry(enabled bool) {
	if e == nil {
		return
	}
	if enabled {
		e.runtimeDevOptIn.Store(1)
	} else {
		e.runtimeDevOptIn.Store(-1)
	}
}

// Record enqueues `s` without blocking; drops silently if the collector queue is full or exporter is idle.
func (e *Exporter) Record(s Span) {
	if e == nil || len(s.TraceID) != 32 {
		return
	}
	if e.tracesURL == "" && e.stdoutOut == nil && e.devTelemetryURL == "" && e.runtimeDevOptIn.Load() <= 0 {
		return
	}
	if len(s.SpanID) != 16 {
		s.SpanID = RandomHex(8)
	}
	select {
	case e.ch <- s:
	default:
	}
}

// Shutdown flushes queued spans up to `ctx` deadline and stops the background worker.
func (e *Exporter) Shutdown(ctx context.Context) {
	if e == nil {
		return
	}
	e.once.Do(func() {
		close(e.stopCh)
	})
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Close flushes pending spans with a bounded 3-second timeout and stops the exporter (nil-safe).
func (e *Exporter) Close() error {
	if e == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	e.Shutdown(ctx)
	return nil
}

func (e *Exporter) loop() {
	defer e.wg.Done()
	interval := e.tickInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	batch := make([]Span, 0, 64)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		cp := make([]Span, len(batch))
		copy(cp, batch)
		batch = batch[:0]
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		_ = e.sendBatch(ctx, cp)
		cancel()
	}

	for {
		select {
		case s := <-e.ch:
			batch = append(batch, s)
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-e.stopCh:
			for {
				select {
				case s := <-e.ch:
					batch = append(batch, s)
					if len(batch) >= 64 {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (e *Exporter) sendBatch(ctx context.Context, spans []Span) error {
	e.sendDevErrorBatch(ctx, spans)
	bodyBytes, err := BuildOTLPJSON(e.serviceName, e.serviceVersion, spans)
	if err != nil {
		return err
	}
	if e.stdoutOut != nil {
		e.stdoutMu.Lock()
		_, _ = e.stdoutOut.Write(append(bodyBytes, '\n'))
		e.stdoutMu.Unlock()
	}
	if e.tracesURL == "" || e.client == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tracesURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return nil
}

// BuildOTLPJSON serializes `spans` into a standard OpenTelemetry OTLP/HTTP JSON `ExportTraceServiceRequest`.
func BuildOTLPJSON(serviceName, serviceVersion string, spans []Span) ([]byte, error) {
	otlpSpans := make([]map[string]any, 0, len(spans))
	for _, s := range spans {
		attrs := make([]map[string]any, 0, len(s.Attributes))
		for k, v := range s.Attributes {
			if attr, ok := toOTLPAttr(k, v); ok {
				attrs = append(attrs, attr)
			}
		}
		end := s.End
		if end.Before(s.Start) {
			end = s.Start
		}
		kind := s.Kind
		if kind <= 0 {
			kind = 1
		}
		statusObj := map[string]any{"code": 1}
		if !s.StatusOK {
			statusObj["code"] = 2
			if s.ErrorMessage != "" {
				msg := s.ErrorMessage
				if len(msg) > 256 {
					msg = msg[:256]
				}
				statusObj["message"] = msg
			}
		}
		item := map[string]any{
			"traceId":           s.TraceID,
			"spanId":            s.SpanID,
			"name":              s.Name,
			"kind":              kind,
			"startTimeUnixNano": strconv.FormatInt(s.Start.UnixNano(), 10),
			"endTimeUnixNano":   strconv.FormatInt(end.UnixNano(), 10),
			"attributes":        attrs,
			"status":            statusObj,
		}
		if s.ParentSpanID != "" {
			item["parentSpanId"] = s.ParentSpanID
		}
		otlpSpans = append(otlpSpans, item)
	}

	payload := map[string]any{
		"resourceSpans": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{
						{"key": "service.name", "value": map[string]any{"stringValue": serviceName}},
						{"key": "service.version", "value": map[string]any{"stringValue": serviceVersion}},
						{"key": "telemetry.sdk.name", "value": map[string]any{"stringValue": "edgefetch-go-otlp"}},
					},
				},
				"scopeSpans": []map[string]any{
					{
						"scope": map[string]any{"name": "edgefetch.go", "version": serviceVersion},
						"spans": otlpSpans,
					},
				},
			},
		},
	}
	return json.Marshal(payload)
}

func toOTLPAttr(key string, val any) (map[string]any, bool) {
	switch v := val.(type) {
	case string:
		return map[string]any{"key": key, "value": map[string]any{"stringValue": v}}, true
	case bool:
		return map[string]any{"key": key, "value": map[string]any{"boolValue": v}}, true
	case int:
		return map[string]any{"key": key, "value": map[string]any{"intValue": strconv.Itoa(v)}}, true
	case int64:
		return map[string]any{"key": key, "value": map[string]any{"intValue": strconv.FormatInt(v, 10)}}, true
	case float64:
		return map[string]any{"key": key, "value": map[string]any{"doubleValue": v}}, true
	default:
		return nil, false
	}
}
