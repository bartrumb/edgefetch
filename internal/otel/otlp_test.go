package otel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

func TestTraceparentParseFormatAndExtract(t *testing.T) {
	tc, ok := ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if !ok {
		t.Fatal("expected valid traceparent")
	}
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || tc.ParentSpanID != "00f067aa0ba902b7" || !tc.Sampled || len(tc.SpanID) != 16 {
		t.Fatalf("unexpected TraceContext: %+v", tc)
	}
	if _, ok := ParseTraceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01"); ok {
		t.Fatal("all-zero traceId must be rejected per W3C spec")
	}

	hdr := http.Header{}
	hdr.Set("traceparent", FormatTraceparent(tc))
	extracted := ExtractOrNew(hdr)
	if extracted.TraceID != tc.TraceID || extracted.ParentSpanID != tc.SpanID {
		t.Fatalf("ExtractOrNew failed to link parent span: %+v", extracted)
	}
}

func TestExporterAsyncBatchFlushAndShutdown(t *testing.T) {
	var received atomic.Int32
	var lastAuth, lastBody string

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		lastAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		lastBody = string(b)
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	exp := NewExporterFromEnv(func(k string) string {
		switch k {
		case "OTEL_EXPORTER_OTLP_ENDPOINT":
			return collector.URL
		case "OTEL_EXPORTER_OTLP_HEADERS":
			return "Authorization=Bearer%20secret_otlp_key"
		case "OTEL_SERVICE_NAME":
			return "edgefetch-agent-test"
		default:
			return ""
		}
	}, "edgefetch-go", "2.1.0", collector.Client().Transport)
	if exp == nil {
		t.Fatal("expected non-nil Exporter")
	}

	now := time.Now()
	exp.Record(Span{
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:       "1122334455667788",
		ParentSpanID: "00f067aa0ba902b7",
		Name:         "edgefetch.go.fetch",
		Kind:         3,
		Start:        now.Add(-45 * time.Millisecond),
		End:          now,
		StatusOK:     true,
		Attributes: map[string]any{
			"net.ttfb_ms":     int64(32),
			"net.conn_reused": true,
			"crawler.outcome": "ok",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	exp.Shutdown(ctx)

	if received.Load() != 1 {
		t.Fatalf("expected 1 OTLP batch POST, got %d", received.Load())
	}
	if lastAuth != "Bearer secret_otlp_key" {
		t.Fatalf("unexpected Authorization header: %q", lastAuth)
	}
	if !strings.Contains(lastBody, `"edgefetch-agent-test"`) || !strings.Contains(lastBody, `"4bf92f3577b34da6a3ce929d0e0e4736"`) {
		t.Fatalf("unexpected OTLP JSON payload: %s", lastBody)
	}
}

func TestSanitizeURLAndRedactEmbeddedURLs(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"https://user:pass@api.example.com/v1/items?api_key=SECRET#frag", "https://api.example.com/v1/items"},
		{"http://127.0.0.1:8787/v1/scrape?token=abc#sec", "http://127.0.0.1:8787/v1/scrape"},
		{"/v1/scrape?secret=xyz#top", "/v1/scrape"},
		{"https://u:p@[bad/p?tok=1#f", "https://[bad/p"},
	}
	for _, tc := range cases {
		if got := SanitizeURL(tc.in); got != tc.want {
			t.Fatalf("SanitizeURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	errStr := `Get "https://user:pass@api.example.com/p?api_key=SECRET_KEY#frag": dial tcp timeout https://other.example/x?tok=999`
	redacted := RedactEmbeddedURLs(errStr)
	if strings.Contains(redacted, "SECRET_KEY") || strings.Contains(redacted, "user:pass") || strings.Contains(redacted, "frag") || strings.Contains(redacted, "tok=999") {
		t.Fatalf("SECURITY: RedactEmbeddedURLs leaked secrets: %q", redacted)
	}
	if !strings.Contains(redacted, "https://api.example.com/p") || !strings.Contains(redacted, "https://other.example/x") {
		t.Fatalf("expected scrubbed origins/paths preserved: %q", redacted)
	}
}

func TestContextChildInjectAndActiveSpan(t *testing.T) {
	var nilCtx context.Context
	if _, ok := TraceContextFromContext(nilCtx); ok {
		t.Fatal("expected nil ctx to have no TraceContext")
	}
	if _, ok := TraceContextFromContext(WithTraceContext(context.Background(), TraceContext{TraceID: "bad", SpanID: "bad"})); ok {
		t.Fatal("expected invalid TraceContext rejected")
	}

	var received atomic.Int32
	var lastBody string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lastBody = string(b)
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	exp := NewExporterFromEnv(func(k string) string {
		if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
			return collector.URL
		}
		return ""
	}, "edgefetch-otel-test", "1.0.0", collector.Client().Transport)
	if exp == nil {
		t.Fatal("expected non-nil Exporter")
	}

	root := TraceContext{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "1122334455667788", Sampled: true}
	ctx := WithTraceContext(context.Background(), root)
	gotRoot, ok := TraceContextFromContext(ctx)
	if !ok || gotRoot.TraceID != root.TraceID || gotRoot.SpanID != root.SpanID {
		t.Fatalf("round-trip TraceContext failed: %+v ok=%v", gotRoot, ok)
	}

	rootSpan := StartSpan(exp, root, "edgefetch.root", 2, map[string]any{"url.full": "https://example.com"})
	childCtx, childSpan, childTC := StartChildSpan(ctx, exp, "edgefetch.child", 1, map[string]any{"k": 1})
	if childTC.TraceID != root.TraceID || childTC.ParentSpanID != root.SpanID || childTC.SpanID == root.SpanID {
		t.Fatalf("unexpected child TraceContext: %+v", childTC)
	}
	if gotChild, ok := TraceContextFromContext(childCtx); !ok || gotChild.SpanID != childTC.SpanID {
		t.Fatalf("expected child TraceContext on returned context: %+v", gotChild)
	}

	hdr := http.Header{}
	InjectHeaders(hdr, childTC, "")
	if hdr.Get("X-Trace-Id") != root.TraceID || hdr.Get("X-Span-Id") != childTC.SpanID || hdr.Get("X-Request-Id") != childTC.SpanID || hdr.Get("Traceparent") != FormatTraceparent(childTC) {
		t.Fatalf("unexpected injected headers: %+v", hdr)
	}

	childSpan.SetAttribute("extra", "val")
	childSpan.End(false, `Get "https://host.example/p?secret=LEAK123#frag": fail`)
	childSpan.End(true, "") // idempotent second End must be ignored
	rootSpan.End(true, "")

	// Unsampled TraceContext still propagates through context.Context while exporting 0 spans.
	unsampledCtx := WithTraceContext(context.Background(), TraceContext{
		TraceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SpanID:  "bbbbbbbbbbbbbbbb",
		Sampled: false,
	})
	uNext, uSpan, uTC := StartChildSpan(unsampledCtx, exp, "edgefetch.unsampled", 1, nil)
	if uTC.Sampled || uTC.ParentSpanID != "bbbbbbbbbbbbbbbb" {
		t.Fatalf("expected unsampled child linked to parent: %+v", uTC)
	}
	if gotU, ok := TraceContextFromContext(uNext); !ok || gotU.SpanID != uTC.SpanID {
		t.Fatalf("expected unsampled TraceContext propagated: %+v", gotU)
	}
	uSpan.End(true, "")

	// Nil exporter & nil span must not panic.
	var nilExp *Exporter
	if err := nilExp.Close(); err != nil {
		t.Fatalf("nil Exporter.Close error: %v", err)
	}
	_, nilSpan, nilTC := StartChildSpan(context.Background(), nil, "edgefetch.noexp", 1, nil)
	if !nilTC.Sampled || len(nilTC.TraceID) != 32 {
		t.Fatalf("expected fresh TraceContext even when exp == nil: %+v", nilTC)
	}
	nilSpan.SetAttribute("a", 1)
	nilSpan.End(true, "")

	if err := exp.Close(); err != nil {
		t.Fatalf("exp.Close failed: %v", err)
	}
	if received.Load() != 1 {
		t.Fatalf("expected 1 OTLP flush, got %d", received.Load())
	}
	if strings.Contains(lastBody, "LEAK123") || strings.Contains(lastBody, "edgefetch.unsampled") {
		t.Fatalf("unexpected secret or unsampled span in OTLP payload: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"edgefetch.root"`) || !strings.Contains(lastBody, `"edgefetch.child"`) {
		t.Fatalf("expected root and child spans in OTLP payload: %s", lastBody)
	}
}

func TestExtractOrNewHeaderFallbacks(t *testing.T) {
	h := http.Header{}
	h.Set("X-Trace-Id", "4bf92f3577b34da6a3ce929d0e0e4736")
	h.Set("X-Span-Id", "not-valid-span")
	tc := ExtractOrNew(h)
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || tc.ParentSpanID != "" || !tc.Sampled {
		t.Fatalf("unexpected ExtractOrNew fallback: %+v", tc)
	}
	h.Set("X-Span-Id", "00f067aa0ba902b7")
	tc2 := ExtractOrNew(h)
	if tc2.ParentSpanID != "00f067aa0ba902b7" {
		t.Fatalf("expected valid X-Span-Id preserved: %+v", tc2)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestOtelHeaderHelpersRedactionAndBuildEdges(t *testing.T) {
	// ParseTraceparent edge cases: malformed, zero span ID, uppercase hex, unsampled "00"
	if _, ok := ParseTraceparent("bad-header"); ok {
		t.Fatal("expected malformed traceparent rejected")
	}
	if _, ok := ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"); ok {
		t.Fatal("expected all-zero parentSpanId rejected")
	}
	tcUnsampled, ok := ParseTraceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-00")
	if !ok || tcUnsampled.Sampled || tcUnsampled.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || tcUnsampled.ParentSpanID != "00f067aa0ba902b7" {
		t.Fatalf("unexpected uppercase unsampled ParseTraceparent: %+v ok=%v", tcUnsampled, ok)
	}
	if got := FormatTraceparent(TraceContext{TraceID: "short", SpanID: "short", Sampled: false}); !strings.HasPrefix(got, "00-") || !strings.HasSuffix(got, "-00") || len(got) != 55 {
		t.Fatalf("FormatTraceparent fallback unexpected: %q", got)
	}

	// ExtractOrNew: zero/non-hex X-Trace-Id, zero X-Span-Id
	hZero := http.Header{}
	hZero.Set("X-Trace-Id", "00000000000000000000000000000000")
	if tc := ExtractOrNew(hZero); tc.TraceID == zeroTraceID || len(tc.TraceID) != 32 {
		t.Fatalf("expected fresh traceId for zero X-Trace-Id: %+v", tc)
	}
	hNonHex := http.Header{}
	hNonHex.Set("X-Trace-Id", strings.Repeat("g", 32))
	if tc := ExtractOrNew(hNonHex); !isValidTraceID(tc.TraceID) || tc.TraceID == strings.Repeat("g", 32) {
		t.Fatalf("expected fresh traceId for non-hex X-Trace-Id: %+v", tc)
	}
	hZeroSpan := http.Header{}
	hZeroSpan.Set("X-Trace-Id", "4bf92f3577b34da6a3ce929d0e0e4736")
	hZeroSpan.Set("X-Span-Id", "0000000000000000")
	if tc := ExtractOrNew(hZeroSpan); tc.ParentSpanID != "" {
		t.Fatalf("expected zero X-Span-Id ignored: %+v", tc)
	}

	// WithTraceContext(nil, ...) and TraceContextFromContext non-struct / non-hex
	var nilCtx context.Context
	nilWrapped := WithTraceContext(nilCtx, tcUnsampled)
	if got, ok := TraceContextFromContext(nilWrapped); !ok || got.TraceID != tcUnsampled.TraceID {
		t.Fatalf("WithTraceContext(nil) failed: %+v ok=%v", got, ok)
	}
	if _, ok := TraceContextFromContext(context.WithValue(context.Background(), traceContextKey{}, "wrong-type")); ok {
		t.Fatal("expected non-TraceContext value rejected")
	}

	// Child() with invalid TraceID / SpanID
	badChild := (TraceContext{TraceID: "bad", SpanID: "bad", Sampled: true}).Child()
	if !isValidTraceID(badChild.TraceID) || badChild.ParentSpanID != "" || !badChild.Sampled {
		t.Fatalf("unexpected invalid Child() fallback: %+v", badChild)
	}

	// InjectHeaders: nil header, invalid IDs, explicit requestID, pre-existing X-Request-Id
	InjectHeaders(nil, badChild, "req-1")
	hdr := http.Header{}
	hdr.Set("X-Request-Id", "existing-req")
	InjectHeaders(hdr, TraceContext{TraceID: "bad", SpanID: "bad"}, "")
	if hdr.Get("X-Request-Id") != "existing-req" || !isValidTraceID(hdr.Get("X-Trace-Id")) || !isValidSpanID(hdr.Get("X-Span-Id")) {
		t.Fatalf("unexpected InjectHeaders with existing request ID: %+v", hdr)
	}
	InjectHeaders(hdr, tcUnsampled, "req-override")
	if hdr.Get("X-Request-Id") != "req-override" {
		t.Fatalf("expected explicit requestID override, got %q", hdr.Get("X-Request-Id"))
	}

	// scrubRawURL / RedactEmbeddedURLs edge cases
	if got := scrubRawURL("https://user:pass@host.example"); got != "https://host.example" {
		t.Fatalf("scrubRawURL without path slash = %q", got)
	}
	if got := RedactEmbeddedURLs(""); got != "" {
		t.Fatalf("expected empty RedactEmbeddedURLs, got %q", got)
	}
	if got := RedactEmbeddedURLs("plain error without urls"); got != "plain error without urls" {
		t.Fatalf("expected passthrough RedactEmbeddedURLs, got %q", got)
	}
	if got := RedactEmbeddedURLs(`bad quote "https://u:p@example.com/a\z?secret=1#f"`); strings.Contains(got, "secret=1") || strings.Contains(got, "u:p@") {
		t.Fatalf("expected quoted invalid-escape URL scrubbed, got %q", got)
	}

	// StartSpan with invalid IDs, SetAttribute / End nil and post-End edges
	sInvalid := StartSpan(nil, TraceContext{TraceID: "bad", SpanID: "bad"}, "n", 1, nil)
	if !isValidTraceID(sInvalid.tc.TraceID) || !isValidSpanID(sInvalid.tc.SpanID) {
		t.Fatalf("StartSpan did not normalize invalid IDs: %+v", sInvalid.tc)
	}
	var nilSpan *ActiveSpan
	nilSpan.SetAttribute("k", "v")
	nilSpan.End(true, "")
	sInvalid.SetAttribute("", "ignored")
	sInvalid.End(true, "")
	sInvalid.SetAttribute("after-end", "ignored")

	// ResolveTracesURL & ParseHeaders
	urlCases := [][2]string{
		{"", ""},
		{"   ", ""},
		{"://bad", ""},
		{"ftp://otel.example.com", ""},
		{"https:///nohost", ""},
		{"https://otel.example.com", "https://otel.example.com/v1/traces"},
		{"https://otel.example.com/collector", "https://otel.example.com/collector/v1/traces"},
		{"https://otel.example.com/custom/v1/traces", "https://otel.example.com/custom/v1/traces"},
	}
	for _, tc := range urlCases {
		if got := ResolveTracesURL(tc[0]); got != tc[1] {
			t.Fatalf("ResolveTracesURL(%q) = %q, want %q", tc[0], got, tc[1])
		}
	}
	hdrs := ParseHeaders("noequals,=emptykey,bad\nkey=val,k=bad\rval,k2=ok%20val,k3=%ZZ")
	if len(hdrs) != 2 || hdrs["k2"] != "ok val" || hdrs["k3"] != "%ZZ" {
		t.Fatalf("unexpected ParseHeaders result: %+v", hdrs)
	}
	if emptyHdrs := ParseHeaders("   "); len(emptyHdrs) != 0 {
		t.Fatalf("expected empty headers map, got %+v", emptyHdrs)
	}

	// BuildOTLPJSON edge cases: End < Start, kind <= 0, >256 error truncation, StatusOK=false empty msg, float64, unknown attr type, NaN error
	now := time.Now()
	rawJSON, err := BuildOTLPJSON("svc", "1.0", []Span{{
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:       "1122334455667788",
		Name:         "edge",
		Kind:         0,
		Start:        now,
		End:          now.Add(-time.Second),
		StatusOK:     false,
		ErrorMessage: strings.Repeat("x", 300),
		Attributes: map[string]any{
			"i":       42,
			"f":       3.5,
			"ignored": struct{}{},
		},
	}, {
		TraceID:  "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:   "2233445566778899",
		Name:     "empty-err",
		Kind:     2,
		Start:    now,
		End:      now,
		StatusOK: false,
	}})
	if err != nil {
		t.Fatalf("BuildOTLPJSON failed: %v", err)
	}
	if !strings.Contains(string(rawJSON), `"doubleValue":3.5`) || strings.Contains(string(rawJSON), strings.Repeat("x", 260)) {
		t.Fatalf("unexpected BuildOTLPJSON output: %s", rawJSON)
	}
	if _, err := BuildOTLPJSON("svc", "1.0", []Span{{
		TraceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:     "1122334455667788",
		Name:       "nan",
		Start:      now,
		End:        now,
		Attributes: map[string]any{"badFloat": math.NaN()},
	}}); err == nil {
		t.Fatal("expected BuildOTLPJSON to fail on math.NaN()")
	}
}

func TestExporterEnvVariantsTickerBatchDrainAndErrors(t *testing.T) {
	// 1. Nil getenv and unset env return nil Exporter.
	if got := NewExporterFromEnv(nil, "svc", "1.0", nil); got != nil {
		t.Fatal("expected nil Exporter for nil getenv")
	}
	if got := NewExporterFromEnv(func(string) string { return "" }, "", "", nil); got != nil {
		t.Fatal("expected nil Exporter when endpoint/stdout unset")
	}

	// 2. Stdout/stderr exporter with default service name & version, fast ticker flush (race-free buffer).
	var stderrBuf bytes.Buffer
	var bufMu sync.Mutex
	safeWriter := writerFunc(func(p []byte) (int, error) {
		bufMu.Lock()
		defer bufMu.Unlock()
		return stderrBuf.Write(p)
	})
	stdExp := newExporterFromEnv(func(k string) string {
		if k == "EDGEFETCH_OTEL_STDOUT" {
			return "1"
		}
		return ""
	}, "", "", nil, safeWriter, 5*time.Millisecond)
	if stdExp == nil || stdExp.serviceName != "edgefetch-go" || stdExp.serviceVersion != "2.7.4" {
		t.Fatalf("unexpected default service/version on stdout exporter: %+v", stdExp)
	}

	// Cover loop() default tickInterval <= 0 branch directly
	defTickExp := &Exporter{
		ch:     make(chan Span, 1),
		stopCh: make(chan struct{}),
	}
	defTickExp.wg.Add(1)
	go defTickExp.loop()
	defTickExp.Shutdown(context.Background())

	// Record nil & invalid spans (ignored) + valid span without SpanID (auto-minted) -> flushed by ticker!
	var nilExp *Exporter
	nilExp.Record(Span{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736"})
	nilExp.Shutdown(context.Background())
	stdExp.Record(Span{TraceID: "short"})
	stdExp.Record(Span{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		Name:    "ticker-span",
		Start:   time.Now(),
		End:     time.Now(),
	})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		bufMu.Lock()
		n := stderrBuf.Len()
		bufMu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Let an empty tick fire too before Shutdown
	time.Sleep(10 * time.Millisecond)
	stdExp.Shutdown(context.Background())
	bufMu.Lock()
	gotOut := stderrBuf.String()
	bufMu.Unlock()
	if !strings.Contains(gotOut, `"ticker-span"`) {
		t.Fatalf("expected ticker-flushed span on stderrOut, got %q", gotOut)
	}

	// 3. Batch >= 64 flush in main loop, blocking RoundTripper -> channel-full drop + Shutdown ctx timeout + stopCh drain >= 64, cleanly unblocked.
	inFlight := make(chan struct{}, 4)
	release := make(chan struct{})
	var reqCount atomic.Int32
	blockOnce := atomic.Bool{}
	blockOnce.Store(true)
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		reqCount.Add(1)
		if blockOnce.CompareAndSwap(true, false) {
			inFlight <- struct{}{}
			<-release
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	exp := newExporterFromEnv(func(k string) string {
		if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
			return "http://127.0.0.1:4318"
		}
		return ""
	}, "batch-svc", "1.0", rt, io.Discard, 0) // tickInterval<=0 defaults to 1s
	if exp == nil {
		t.Fatal("expected batch exporter")
	}

	// Send 64 spans to trigger len(batch)>=64 flush in main loop -> blocks in rt.
	for i := 0; i < 64; i++ {
		exp.Record(Span{
			TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			SpanID:  "1122334455667788",
			Name:    "batch-main",
			Start:   time.Now(),
			End:     time.Now(),
		})
	}
	<-inFlight

	// While worker is blocked inside sendBatch, overfill ch (cap 256) to cover default drop AND stopCh drain >= 64.
	for i := 0; i < 300; i++ {
		exp.Record(Span{
			TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			SpanID:  "1122334455667788",
			Name:    "batch-drain",
			Start:   time.Now(),
			End:     time.Now(),
		})
	}

	// Trigger Shutdown with short deadline to cover `case <-ctx.Done():`
	shortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	exp.Shutdown(shortCtx)
	cancel()

	// Unblock RoundTripper and await full wg drain cleanly (zero goroutine leaks).
	close(release)
	exp.Shutdown(context.Background())
	if reqCount.Load() < 5 {
		t.Fatalf("expected >=5 batch flushes (1 main + 4 drain), got %d", reqCount.Load())
	}

	// 4. Direct sendBatch error branches: NaN BuildOTLPJSON error, invalid URL NewRequestWithContext error, transport Do error.
	if err := exp.sendBatch(context.Background(), []Span{{
		TraceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:     "1122334455667788",
		Name:       "nan",
		Start:      time.Now(),
		End:        time.Now(),
		Attributes: map[string]any{"x": math.NaN()},
	}}); err == nil {
		t.Fatal("expected sendBatch NaN error")
	}
	badURLExp := &Exporter{
		tracesURL: "http://[::1]:namedport/v1/traces",
		client:    &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unreachable") })},
	}
	if err := badURLExp.sendBatch(context.Background(), []Span{{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "1122334455667788",
		Name:    "bad-url",
	}}); err == nil {
		t.Fatal("expected sendBatch NewRequestWithContext error")
	}
	errExp := &Exporter{
		tracesURL: "http://127.0.0.1:4318/v1/traces",
		client:    &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial refused") })},
	}
	if err := errExp.sendBatch(context.Background(), []Span{{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "1122334455667788",
		Name:    "do-err",
	}}); err == nil || !strings.Contains(err.Error(), "dial refused") {
		t.Fatalf("expected client.Do error, got %v", err)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

func TestR7OtelAndPolitenessRedactionParity(t *testing.T) {
	urlInputs := []string{
		"",
		"   ",
		"https://user:SECRET_PASS@api.example.com/v1/items?api_key=SECRET_Q#SECRET_FRAG",
		"ws://user:SECRET_WS@hub.example.com:8443/agent/ws?token=SECRET_TOK#SECRET_F",
		"wss://admin:SECRET_WSS@hub.example.com/ws;jsessionid=SECRET_MAT/sub",
		"https://user:p/a/s/s@api.example.com/v1/data?sig=SECRET_SIG",
		"user:SECRET_SCHEMELESS@api.example.com/path?tok=SECRET_Q",
		"https://auth.example.com/reset/SECRET_RESET_TOKEN_999",
	}
	for _, raw := range urlInputs {
		gotOtel := SanitizeURL(raw)
		gotPol := politeness.SanitizeURL(raw)
		if gotOtel != gotPol {
			t.Fatalf("SanitizeURL parity mismatch for %q: otel=%q politeness=%q", raw, gotOtel, gotPol)
		}
		if strings.Contains(gotOtel, "SECRET_") {
			t.Fatalf("SECURITY: SanitizeURL(%q) leaked secret: %q", raw, gotOtel)
		}
	}

	embeddedInputs := []string{
		`dial wss://agent:SECRET-1@hub.example.com/ws?token=SECRET-2#SECRET-3 failed`,
		`ws://u:SECRET-4@127.0.0.1:9000/cdp?key=SECRET-5`,
		`json error {"url":"https:\/\/u:SECRET-6@api.example.com\/v1?api_key=SECRET-7#SECRET-8"}`,
		`encoded https%3A%2F%2Fu%3ASECRET-9%40api.example.com%2Fp%3Ftoken%3DSECRET-10`,
		`schemeless dial user:SECRET-11@internal.example.com:5432/db?password=SECRET-12`,
		`slash-in-pass https://admin:SEC/RET-13@api.example.com/v1/ok`,
		`matrix https://api.example.com/items;sid=SECRET-14/list and Authorization: Bearer SECRET-15 and Basic SECRET-16`,
		`ftp://u:SECRET-17@files.example.com/pub?k=SECRET-18 mailto:ops@example.com?token=SECRET-19#SECRET-22 //u:SECRET-20@cdn.example.com/x?q=SECRET-21`,
	}
	for i, raw := range embeddedInputs {
		gotOtel := RedactEmbeddedURLs(raw)
		gotPol := politeness.RedactEmbeddedURLs(raw)
		if gotOtel != gotPol {
			t.Fatalf("RedactEmbeddedURLs parity mismatch #%d:\n  otel=%q\n  pol =%q", i+1, gotOtel, gotPol)
		}
		if strings.Contains(gotOtel, "SECRET-") {
			t.Fatalf("SECURITY: OTel RedactEmbeddedURLs #%d leaked secret:\n  in =%s\n  out=%s", i+1, raw, gotOtel)
		}
	}
}
