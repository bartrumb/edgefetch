package otel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDevTelemetryDefaultOffDoNotTrackOverrideAndZeroUrlScrubbing(t *testing.T) {
	// 1. Unattended default (`EDGEFETCH_DEV_TELEMETRY` unset / "0" / "false") MUST be strictly OFF.
	for _, val := range []string{"", "0", "false", "no", "off"} {
		getenv := func(k string) string {
			if k == "EDGEFETCH_DEV_TELEMETRY" {
				return val
			}
			return ""
		}
		if IsDevTelemetryEnabled(getenv) {
			t.Fatalf("SECURITY: expected IsDevTelemetryEnabled=false when EDGEFETCH_DEV_TELEMETRY=%q", val)
		}
		if got := NewExporterFromEnv(getenv, "edgefetch-agent-1", "2.7.0", nil); got != nil {
			_ = got.Close()
			t.Fatalf("SECURITY: expected nil Exporter when EDGEFETCH_DEV_TELEMETRY=%q", val)
		}
	}

	// 2. `DO_NOT_TRACK=1` MUST hard-disable telemetry even when `EDGEFETCH_DEV_TELEMETRY=1`!
	var dntHits atomic.Int32
	dntCollector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dntHits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer dntCollector.Close()

	for _, dntVal := range []string{"1", "true", "yes", "on"} {
		dntEnv := func(k string) string {
			switch k {
			case "EDGEFETCH_DEV_TELEMETRY":
				return "1"
			case "DO_NOT_TRACK":
				return dntVal
			case "EDGEFETCH_DEV_TELEMETRY_URL":
				return dntCollector.URL + "/v1/dev-errors"
			default:
				return ""
			}
		}
		if IsDevTelemetryEnabled(dntEnv) {
			t.Fatalf("SECURITY: DO_NOT_TRACK=%q failed to override EDGEFETCH_DEV_TELEMETRY=1", dntVal)
		}
		if exp := NewExporterFromEnv(dntEnv, "edgefetch-agent-1", "2.7.0", dntCollector.Client().Transport); exp != nil {
			_ = exp.Close()
			t.Fatalf("SECURITY: expected nil Exporter under DO_NOT_TRACK=%q", dntVal)
		}
	}
	if dntHits.Load() != 0 {
		t.Fatalf("SECURITY: expected 0 collector hits under DO_NOT_TRACK=1, got %d", dntHits.Load())
	}

	// 3. Opt-in (`EDGEFETCH_DEV_TELEMETRY=1`, `DO_NOT_TRACK=0`) exports ONLY status=ERROR / WAF spans with ZERO URLs/PII!
	var (
		mu          sync.Mutex
		rawPayloads []string
		received    []DevErrorReport
	)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/dev-errors" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var single DevErrorReport
		mu.Lock()
		rawPayloads = append(rawPayloads, string(b))
		if err := json.Unmarshal(b, &single); err == nil && single.SchemaVersion == 1 {
			received = append(received, single)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer collector.Close()

	optInEnv := func(k string) string {
		switch k {
		case "EDGEFETCH_DEV_TELEMETRY":
			return "1"
		case "DO_NOT_TRACK":
			return "0"
		case "EDGEFETCH_DEV_TELEMETRY_URL":
			return collector.URL
		default:
			return ""
		}
	}
	exp := NewExporterFromEnv(optInEnv, "edgefetch-agent-node1", "2.7.0", collector.Client().Transport)
	if exp == nil {
		t.Fatal("expected non-nil Exporter when EDGEFETCH_DEV_TELEMETRY=1 and DO_NOT_TRACK=0")
	}

	now := time.Now()
	// Healthy span MUST NOT be exported to dev-errors!
	exp.Record(Span{
		TraceID:  "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:   "1111111111111111",
		Name:     "edgefetch.go.fetch.scrape",
		Kind:     3,
		Start:    now,
		End:      now,
		StatusOK: true,
		Attributes: map[string]any{
			"url.full":                  "https://secret-corp.internal.example/private/doc?token=SUPER_SECRET_1",
			"http.response.status_code": 200,
			"crawler.outcome":           "ok",
		},
	})

	// Error / WAF span containing sensitive URLs, hostnames, paths, query secrets, and headers MUST be scrubbed to structural allowlist!
	exp.Record(Span{
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:       "2222222222222222",
		Name:         "edgefetch.go.fetch.scrape",
		Kind:         3,
		Start:        now,
		End:          now,
		StatusOK:     false,
		ErrorMessage: `Get "https://admin:hunter2@secret-corp.internal.example/private/board?api_key=SUPER_SECRET_2#frag": Cloudflare challenge`,
		Attributes: map[string]any{
			"url.full":                  "https://secret-corp.internal.example/private/board?api_key=SUPER_SECRET_2",
			"http.response.status_code": 403,
			"crawler.outcome":           "challenge",
			"edgefetch.adapter_id":      "greenhouse",
			"edgefetch.waf.vendor":      "cloudflare",
			"authorization":             "Bearer TOP_SECRET_BEARER_TOKEN",
			"markdown.preview":          "# Confidential Internal Document",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	exp.Shutdown(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || len(rawPayloads) != 1 {
		t.Fatalf("expected strictly 1 scrubbed error report (healthy span dropped), got %d (%v)", len(received), rawPayloads)
	}
	raw := rawPayloads[0]
	for _, forbidden := range []string{
		"http://",
		"https://",
		"secret-corp",
		"internal.example",
		"/private",
		"SUPER_SECRET",
		"TOP_SECRET",
		"hunter2",
		"Confidential",
		"url.full",
		"authorization",
	} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("SECURITY: forbidden PII/URL substring %q leaked in dev error telemetry payload: %s", forbidden, raw)
		}
	}

	// Verify exact 11 keys on serialized JSON object
	var genericObj map[string]any
	if err := json.Unmarshal([]byte(raw), &genericObj); err != nil {
		t.Fatalf("unmarshal generic map: %v", err)
	}
	if len(genericObj) != 11 {
		t.Fatalf("expected strictly 11 allowlisted keys, got %d: %v", len(genericObj), genericObj)
	}

	got := received[0]
	if got.SchemaVersion != 1 || got.Version != "2.7.0" || got.Runtime != "go" || got.Mode != "agent" ||
		got.SpanName != "edgefetch.go.fetch.scrape" || got.AdapterID != "greenhouse" ||
		got.WAFVendor != "cloudflare" || got.HTTPStatus != 403 || got.ErrorClass != "waf_challenge" {
		t.Fatalf("unexpected scrubbed DevErrorReport: %+v", got)
	}
}
