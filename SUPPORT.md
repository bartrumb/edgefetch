# Support & Sanitized OpenTelemetry Trace Guide

Need help deploying EdgeFetch, debugging an extraction edge case, or contributing a new public-API adapter? Here is where to go and how to share diagnostics safely.

## Where to Get Help

- **Questions, Setup Help & Architecture Q&A:** Open a thread in [GitHub Discussions](https://github.com/bartrumb/edgefetch/discussions).
- **Reproducible Bugs & Extraction Regressions:** Open a [Bug Report Issue](https://github.com/bartrumb/edgefetch/issues/new?template=bug_report.yml).
- **New Public Provider / ATS Adapter Requests:** Open an [Extractor / Adapter Request](https://github.com/bartrumb/edgefetch/issues/new?template=adapter_request.yml) or see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security Vulnerabilities (SSRF, Auth, Sandbox):** **Never open a public issue.** Report privately via [GitHub Security Advisories](https://github.com/bartrumb/edgefetch/security/advisories/new) (see [SECURITY.md](SECURITY.md)).

---

## Attaching Sanitized OpenTelemetry Traces to Bug Reports

EdgeFetch speaks vendor-agnostic W3C `traceparent` + OTLP/HTTP JSON natively across both the Go worker/CLI (`internal/otel`) and the TypeScript Hub (`hub/src/otel.ts`) with zero heavy SDK dependencies.

### 1. One-Command CLI Diagnostic Bundle (`edgefetch bug-report`)

Run `edgefetch bug-report` on your desktop, Proxmox LXC, or Docker container:

```bash
# HTTP/2 + SSR extraction trace:
edgefetch bug-report https://example.com/docs/page

# Force Headless Chromium render trace:
edgefetch bug-report --render https://example.com/spa-page

# Inside a running Docker worker container:
docker exec ef-agent /edgefetch bug-report https://example.com/docs/page
```

**What `edgefetch bug-report` guarantees:**
- **Zero leaked secrets:** Never prints `CALLER_TOKEN`, `EDGEFETCH_AGENT_TOKEN`, `EDGEFETCH_HUB_URL`, or API keys (records only `set (redacted)` vs `unset`).
- **URL query & credential scrubbing:** Automatically strips `user:pass@`, `?query=...`, and `#fragment` from URLs before serializing spans.
- **Full OTLP/JSON span breakdown:** Captures `dnsMs`, `connectMs`, `tlsMs`, `ttfbMs`, `robotsMs`, `durationMs`, HTTP protocol (`h2` / `http/1.1`), WAF vendor classification, and Markdown character count inside a collapsible GitHub Markdown `<details>` block.

### 2. Streaming OTLP Spans to Stderr Locally (`EDGEFETCH_OTEL_STDOUT=1`)

If you don't run Grafana Tempo, Jaeger, or Honeycomb locally, set `EDGEFETCH_OTEL_STDOUT=1` (or `OTEL_EXPORTER_OTLP_ENDPOINT=stdout`) to emit OTLP/JSON span batches directly to `stderr`:

```bash
EDGEFETCH_OTEL_STDOUT=1 edgefetch scrape https://example.com/docs/page
```

### 3. Capturing `/v1/agent` Multi-Step Traces from a Hub

Every autonomous `/v1/agent` run records a redacted step-by-step tool trace (`llm.apiKey` and URL query strings are stripped before storage):

```bash
curl -fsSL -H "Authorization: Bearer $CALLER_TOKEN" \
  "https://your-hub.example.com/v1/agent/<agt_id>/trace" | jq .
```

### 4. Exporting to Grafana Tempo, Jaeger, Honeycomb, or Cloudflare

Configure standard OpenTelemetry environment variables on either the Hub or Go nodes:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT="https://otel.example.com"
OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer%20<your-otlp-ingest-token>"
OTEL_SERVICE_NAME="edgefetch-prod"
```

> **Reminder:** Never paste raw `OTEL_EXPORTER_OTLP_HEADERS`, `CALLER_TOKEN`, `AGENT_TOKEN`, or `BOT_SIGNING_PRIVATE_KEY` values into a public GitHub issue.
