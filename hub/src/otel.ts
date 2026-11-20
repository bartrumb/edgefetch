/**
 * Vendor-agnostic OpenTelemetry OTLP/HTTP JSON trace exporter + W3C Trace Context (`traceparent`) propagation.
 *
 * Works identically on Cloudflare Workers (`ctx.waitUntil`), Deno Deploy, Node.js 22+, Bun, Fly.io, Railway, and Render
 * with zero external dependencies. Compatible out-of-the-box with Grafana Tempo, Jaeger (`:4318`), Honeycomb, Axiom,
 * SigNoz, Datadog OTLP ingest, and OpenTelemetry Collector (`POST <endpoint>/v1/traces`).
 *
 * Standard environment variables:
 *   - `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `https://api.honeycomb.io` or `http://otel-collector:4318`)
 *   - `OTEL_EXPORTER_OTLP_HEADERS`  (e.g. `Authorization=Bearer tok,x-honeycomb-team=key`)
 *   - `OTEL_SERVICE_NAME`           (default: `edgefetch-hub`)
 */

export interface TraceContext {
  traceId: string; // 32 lowercase hex chars (16 bytes)
  spanId: string; // 16 lowercase hex chars (8 bytes)
  parentSpanId?: string;
  sampled: boolean;
}

export interface OtlpSpanInput {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind?: 1 | 2 | 3; // 1=INTERNAL, 2=SERVER, 3=CLIENT
  startTimeMs: number;
  endTimeMs: number;
  statusOk?: boolean;
  errorMessage?: string;
  attributes?: Record<string, string | number | boolean | undefined>;
}

export interface OtelEnvConfig {
  OTEL_EXPORTER_OTLP_ENDPOINT?: string;
  OTEL_EXPORTER_OTLP_HEADERS?: string;
  OTEL_SERVICE_NAME?: string;
}

const TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i;
const ALL_ZERO_32 = '0'.repeat(32);
const ALL_ZERO_16 = '0'.repeat(16);

export function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] as number).toString(16).padStart(2, '0');
  }
  return out;
}

/** Parses an incoming W3C `traceparent` header (`00-<traceId>-<spanId>-<flags>`). */
export function parseTraceparent(headerValue: string | null | undefined): TraceContext | null {
  if (!headerValue) return null;
  const m = TRACEPARENT_RE.exec(headerValue.trim());
  if (!m) return null;
  const traceId = (m[1] as string).toLowerCase();
  const parentSpanId = (m[2] as string).toLowerCase();
  const flags = parseInt(m[3] as string, 16);
  if (traceId === ALL_ZERO_32 || parentSpanId === ALL_ZERO_16) return null;
  return {
    traceId,
    spanId: randomHex(8),
    parentSpanId,
    sampled: (flags & 0x01) === 0x01,
  };
}

/** Formats a W3C `traceparent` header string. */
export function formatTraceparent(ctx: { traceId: string; spanId: string; sampled?: boolean }): string {
  return `00-${ctx.traceId}-${ctx.spanId}-${ctx.sampled === false ? '00' : '01'}`;
}

/** Extracts W3C `traceparent` from `request` or starts a new root trace context, returning propagation headers for Go workers. */
export function createRequestTraceContext(request: Request): {
  context: TraceContext;
  headers: Record<string, string>;
} {
  const parsed = parseTraceparent(request.headers.get('traceparent'));
  const context: TraceContext = parsed ?? {
    traceId: randomHex(16),
    spanId: randomHex(8),
    sampled: true,
  };
  const ray = request.headers.get('cf-ray') ?? request.headers.get('x-request-id') ?? context.spanId;
  return {
    context,
    headers: {
      traceparent: formatTraceparent(context),
      'x-trace-id': context.traceId,
      'x-span-id': context.spanId,
      'x-request-id': ray,
    },
  };
}

/** Parses standard `OTEL_EXPORTER_OTLP_HEADERS` (`key1=val1,key2=val2` with URL-encoded value support). */
export function parseOtlpHeaders(raw?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw || !raw.trim()) return out;
  for (const entry of raw.split(',')) {
    const eq = entry.indexOf('=');
    if (eq <= 0) continue;
    const key = entry.slice(0, eq).trim();
    const rawVal = entry.slice(eq + 1).trim();
    if (!key || /[\r\n\0]/.test(key) || /[\r\n\0]/.test(rawVal)) continue;
    try {
      out[key] = decodeURIComponent(rawVal);
    } catch {
      out[key] = rawVal;
    }
  }
  return out;
}

/** Normalizes `OTEL_EXPORTER_OTLP_ENDPOINT` to its `/v1/traces` HTTP endpoint. */
export function resolveOtlpTracesUrl(endpoint?: string): string | null {
  const trimmed = (endpoint ?? '').trim().replace(/\/+$/, '');
  if (!trimmed) return null;
  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  if (!u.pathname || u.pathname === '/') {
    u.pathname = '/v1/traces';
  } else if (!u.pathname.endsWith('/v1/traces')) {
    u.pathname = `${u.pathname.replace(/\/+$/, '')}/v1/traces`;
  }
  return u.toString();
}

function toOtlpAttribute(key: string, value: string | number | boolean) {
  if (typeof value === 'boolean') {
    return { key, value: { boolValue: value } };
  }
  if (typeof value === 'number') {
    if (Number.isInteger(value)) {
      return { key, value: { intValue: String(value) } };
    }
    return { key, value: { doubleValue: value } };
  }
  return { key, value: { stringValue: value } };
}

/** Builds a standard OTLP/HTTP JSON `ExportTraceServiceRequest` payload (`application/json`). */
export function buildOtlpTracePayload(params: {
  serviceName?: string;
  serviceVersion?: string;
  spans: OtlpSpanInput[];
}): Record<string, unknown> {
  const serviceName = params.serviceName?.trim() || 'edgefetch-hub';
  const serviceVersion = params.serviceVersion?.trim() || '2.5.1';
  return {
    resourceSpans: [
      {
        resource: {
          attributes: [
            toOtlpAttribute('service.name', serviceName),
            toOtlpAttribute('service.version', serviceVersion),
            toOtlpAttribute('telemetry.sdk.name', 'edgefetch-otlp'),
          ],
        },
        scopeSpans: [
          {
            scope: { name: 'edgefetch.tracer', version: serviceVersion },
            spans: params.spans.map((s) => {
              const attrs: Array<Record<string, unknown>> = [];
              for (const [k, v] of Object.entries(s.attributes ?? {})) {
                if (v !== undefined) attrs.push(toOtlpAttribute(k, v));
              }
              return {
                traceId: s.traceId,
                spanId: s.spanId,
                ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
                name: s.name,
                kind: s.kind ?? 2,
                startTimeUnixNano: `${BigInt(Math.max(0, Math.floor(s.startTimeMs))) * 1_000_000n}`,
                endTimeUnixNano: `${BigInt(Math.max(s.startTimeMs, Math.floor(s.endTimeMs))) * 1_000_000n}`,
                attributes: attrs,
                status:
                  s.statusOk === false
                    ? { code: 2, ...(s.errorMessage ? { message: s.errorMessage.slice(0, 256) } : {}) }
                    : { code: 1 },
              };
            }),
          },
        ],
      },
    ],
  };
}

/** Extracts child OTLP spans from a Go `FetchReply` JSON body so non-OTLP Go nodes still appear in Hub waterfalls. */
export function buildCrawlChildSpans(params: {
  traceId: string;
  parentSpanId: string;
  via: string;
  endTimeMs: number;
  replyText: string;
}): OtlpSpanInput[] {
  const out: OtlpSpanInput[] = [];
  try {
    const parsed = JSON.parse(params.replyText) as {
      results?: Array<{
        id?: string;
        url?: string;
        kind?: string;
        status?: number;
        outcome?: string;
        durationMs?: number;
        rendered?: boolean;
        timing?: {
          dnsMs?: number;
          connectMs?: number;
          tlsMs?: number;
          ttfbMs?: number;
          reused?: boolean;
          proto?: string;
        };
      }>;
    };
    for (const r of (parsed.results ?? []).slice(0, 32)) {
      const dur = Math.max(1, Number(r.durationMs ?? r.timing?.ttfbMs ?? 1));
      let safeUrl = r.url ?? '';
      try {
        const u = new URL(safeUrl);
        safeUrl = `${u.origin}${u.pathname}`;
      } catch {
        // leave as-is
      }
      out.push({
        traceId: params.traceId,
        spanId: randomHex(8),
        parentSpanId: params.parentSpanId,
        name: `edgefetch.fetch.${r.kind ?? 'page'}`,
        kind: 3,
        startTimeMs: Math.max(0, params.endTimeMs - dur),
        endTimeMs: params.endTimeMs,
        statusOk: r.outcome === 'ok' || r.outcome === 'gone' || r.outcome === 'skip',
        attributes: {
          'url.full': safeUrl,
          'http.response.status_code': r.status ?? 0,
          'crawler.via': params.via,
          'crawler.outcome': r.outcome ?? 'unknown',
          'crawler.rendered': Boolean(r.rendered),
          'net.dns_ms': r.timing?.dnsMs ?? 0,
          'net.connect_ms': r.timing?.connectMs ?? 0,
          'net.tls_ms': r.timing?.tlsMs ?? 0,
          'net.ttfb_ms': r.timing?.ttfbMs ?? 0,
          'net.conn_reused': Boolean(r.timing?.reused),
          ...(r.timing?.proto ? { 'network.protocol.name': r.timing.proto } : {}),
        },
      });
    }
  } catch {
    // ignore malformed reply payloads
  }
  return out;
}

/** Sends buffered OTLP spans asynchronously; never throws so collector outages cannot affect caller traffic. */
export async function flushOtlpSpans(params: {
  env: OtelEnvConfig;
  spans: OtlpSpanInput[];
  fetchFn?: typeof fetch;
}): Promise<boolean> {
  if (params.spans.length === 0) return false;
  const tracesUrl = resolveOtlpTracesUrl(params.env.OTEL_EXPORTER_OTLP_ENDPOINT);
  if (!tracesUrl) return false;

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...parseOtlpHeaders(params.env.OTEL_EXPORTER_OTLP_HEADERS),
  };
  const payload = buildOtlpTracePayload({
    serviceName: params.env.OTEL_SERVICE_NAME,
    spans: params.spans,
  });
  const doFetch = params.fetchFn ?? fetch;
  try {
    const res = await doFetch(tracesUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(4_000),
    });
    await res.body?.cancel().catch(() => undefined);
    return res.ok;
  } catch {
    return false;
  }
}
