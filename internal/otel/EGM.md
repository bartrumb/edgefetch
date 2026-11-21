# otel

## Overview
Package `otel` implements zero-dependency W3C Trace Context (`traceparent`) propagation and an asynchronous, non-blocking OpenTelemetry OTLP/HTTP JSON span exporter (`POST <OTEL_EXPORTER_OTLP_ENDPOINT>/v1/traces` or local stderr debug output).

## Interface
- `[otlp.go:TraceContext]`: `type TraceContext struct { TraceID, SpanID, ParentSpanID string; Sampled bool }`.
- `[otlp.go:RandomHex]`: `func RandomHex(byteLen int) string` — encodes `byteLen` CSPRNG bytes as lowercase hex.
- `[otlp.go:ParseTraceparent]`: `func ParseTraceparent(raw string) (TraceContext, bool)` — parses W3C `00-<32hex>-<16hex>-<2hex>` and mints a fresh child `SpanID`.
- `[otlp.go:FormatTraceparent]`: `func FormatTraceparent(tc TraceContext) string` — formats `00-<TraceID>-<SpanID>-<01|00>`.
- `[otlp.go:ExtractOrNew]`: `func ExtractOrNew(h http.Header) TraceContext` — extracts `traceparent`, falls back to `X-Trace-Id` / `X-Span-Id`, or mints a sampled root trace.
- `[otlp.go:Span]`: `type Span struct { TraceID, SpanID, ParentSpanID, Name string; Kind int; Start, End time.Time; StatusOK bool; ErrorMessage string; Attributes map[string]any }`.
- `[otlp.go:ResolveTracesURL]`: `func ResolveTracesURL(endpoint string) string` — normalizes an `http`/`https` OTLP endpoint to `/v1/traces`.
- `[otlp.go:ParseHeaders]`: `func ParseHeaders(raw string) map[string]string` — parses comma-separated `k=v` entries from `OTEL_EXPORTER_OTLP_HEADERS`.
- `[otlp.go:Exporter]`, `[otlp.go:NewExporterFromEnv]`: `func NewExporterFromEnv(getenv func(string) string, defaultService, version string, transport http.RoundTripper) *Exporter` — configures exporter from `OTEL_EXPORTER_OTLP_ENDPOINT`, `EDGEFETCH_OTEL_STDOUT`, `OTEL_SERVICE_NAME`, and `OTEL_EXPORTER_OTLP_HEADERS` (returns `nil` when disabled).
- `[otlp.go:Exporter.Record]`, `[otlp.go:Exporter.Shutdown]`: Non-blocking span enqueue and graceful drain (`nil`-receiver safe).
- `[otlp.go:BuildOTLPJSON]`: `func BuildOTLPJSON(serviceName, serviceVersion string, spans []Span) ([]byte, error)` — marshals an OTLP/HTTP JSON `ExportTraceServiceRequest` payload.

## Invariants
- `[otlp.go:ParseTraceparent]`, `[otlp.go:reTraceparent]`: Accepts only version `00` with non-zero 32-hex `TraceID` and 16-hex `ParentSpanID`, lowercasing IDs and setting `Sampled = (flags & 0x01) == 0x01`.
- `[otlp.go:ExtractOrNew]`: Fallback `X-Trace-Id` must be 32 non-zero lowercase hex chars (`X-Span-Id` coerced to `""` unless 16 non-zero lowercase hex chars); otherwise mints a fresh sampled root `TraceContext`.
- `[otlp.go:ResolveTracesURL]`, `[otlp.go:ParseHeaders]`: `ResolveTracesURL` rejects non-`http`/`https` or hostless URLs; `ParseHeaders` skips entries containing `\r`, `\n`, or `\x00` before `url.PathUnescape`.
- `[otlp.go:Exporter.Record]`, `[otlp.go:Exporter.loop]`: `Record` drops silently (never blocking callers) if `e == nil`, `len(s.TraceID) != 32`, or the 256-span buffer channel is full; `loop` flushes at `64` spans or `1s` intervals with a `4s` per-batch timeout.
- `[otlp.go:BuildOTLPJSON]`, `[otlp.go:toOTLPAttr]`: Clamps `End` to `Start` if earlier, truncates `ErrorMessage` to `256` bytes, formats nanosecond timestamps and `int`/`int64` `intValue` fields as decimal strings, and drops attribute types outside `string`, `bool`, `int`, `int64`, and `float64`.

## Side Effects
- `[otlp.go:RandomHex]`: Reads cryptographic entropy via `crypto/rand.Read`.
- `[otlp.go:NewExporterFromEnv]`, `[otlp.go:Exporter.Shutdown]`: Reads `OTEL_*` / `EDGEFETCH_OTEL_STDOUT` via `getenv`, starts a background `loop` goroutine with a `1s` `time.Ticker`, and closes `stopCh` once on `Shutdown`.
- `[otlp.go:Exporter.sendBatch]`: Writes newline-delimited OTLP JSON batches to `os.Stderr` in stdout/stderr mode and issues outbound `POST <tracesURL>` HTTP requests via `e.client.Do`.

## Verification
- Run: `go test ./internal/otel`
