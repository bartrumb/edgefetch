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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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
	tracesURL      string
	headers        map[string]string
	serviceName    string
	serviceVersion string
	client         *http.Client

	ch     chan Span
	stopCh chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
}

// NewExporterFromEnv returns a live `*Exporter` when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured, or `nil` when unset.
func NewExporterFromEnv(getenv func(string) string, defaultService, version string, transport http.RoundTripper) *Exporter {
	if getenv == nil {
		return nil
	}
	tracesURL := ResolveTracesURL(getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracesURL == "" {
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
		version = "2.4.1"
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	e := &Exporter{
		tracesURL:      tracesURL,
		headers:        ParseHeaders(getenv("OTEL_EXPORTER_OTLP_HEADERS")),
		serviceName:    svc,
		serviceVersion: version,
		client:         client,
		ch:             make(chan Span, 256),
		stopCh:         make(chan struct{}),
	}
	e.wg.Add(1)
	go e.loop()
	return e
}

// Record enqueues `s` without blocking; drops silently if the collector queue is full.
func (e *Exporter) Record(s Span) {
	if e == nil || len(s.TraceID) != 32 {
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

func (e *Exporter) loop() {
	defer e.wg.Done()
	ticker := time.NewTicker(time.Second)
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
	bodyBytes, err := BuildOTLPJSON(e.serviceName, e.serviceVersion, spans)
	if err != nil {
		return err
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
