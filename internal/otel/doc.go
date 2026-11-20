// Package otel implements W3C Trace Context (`traceparent`) propagation and a non-blocking, zero-dependency
// OpenTelemetry OTLP/HTTP JSON span exporter (`POST <OTEL_EXPORTER_OTLP_ENDPOINT>/v1/traces`).
//
// Configured via standard OpenTelemetry environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT`,
// `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`), allowing Go server, agent, and self-hosted hub nodes
// to stream child HTTP/2 + `httptrace` spans directly to Grafana Tempo, Jaeger, Honeycomb, Axiom, SigNoz,
// or any OpenTelemetry Collector without adding external SDK dependencies to `go.mod`.
package otel
