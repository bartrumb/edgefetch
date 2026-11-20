package otel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
