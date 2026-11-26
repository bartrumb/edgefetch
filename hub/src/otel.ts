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

// @ts-ignore: `hub/tsconfig.json` uses `@cloudflare/workers-types` without `@types/node`
import { AsyncLocalStorage } from 'node:async_hooks';
import { flushDevErrorTelemetry, type DevTelemetryEnvConfig } from './dev-telemetry';

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

export type OtlpSpanRecord = OtlpSpanInput;
export type SpanAttributes = Record<string, string | number | boolean | undefined>;

export interface OtelEnvConfig extends DevTelemetryEnvConfig {
  OTEL_EXPORTER_OTLP_ENDPOINT?: string;
  OTEL_EXPORTER_OTLP_HEADERS?: string;
  OTEL_SERVICE_NAME?: string;
}

interface AsyncLocalStorageLike<T> {
  getStore(): T | undefined;
  run<R>(store: T, callback: (...args: unknown[]) => R, ...args: unknown[]): R;
}

export interface SpanStartOptions {
  kind?: 1 | 2 | 3;
  attributes?: SpanAttributes;
  startTimeMs?: number;
}

export interface ActiveSpanHandle {
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly name: string;
  readonly sampled: boolean;
  setAttribute(key: string, value: string | number | boolean | undefined): void;
  setAttributes(attrs: SpanAttributes): void;
  setStatus(ok: boolean, errorMessage?: string): void;
  end(endTimeMs?: number): void;
}

const TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i;
const ALL_ZERO_32 = '0'.repeat(32);
const ALL_ZERO_16 = '0'.repeat(16);
const SAFE_REQUEST_ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const RFC_HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;
const FORBIDDEN_OTLP_HEADER_NAMES = new Set([
  '__proto__',
  'constructor',
  'prototype',
  'host',
  ':authority',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'upgrade',
  'te',
  'trailer',
  'proxy-connection',
]);

export const MAX_INFLIGHT_OTLP_EXPORTS = 32;
export const MAX_SECURITY_AUDIT_INFLIGHT_OTLP = 24;
export const MAX_PUBLIC_UNAUTH_INFLIGHT_OTLP = 8;
export const UNAUTH_OTLP_EXPORT_CAPACITY = 30;
export const SECURITY_AUDIT_OTLP_CAPACITY = 120;
const UNAUTH_OTLP_WINDOW_MS = 60_000;

let inflightOtlpExports = 0;
let inflightSecurityAuditOtlp = 0;
let inflightPublicUnauthOtlp = 0;
let unauthOtlpTokens = UNAUTH_OTLP_EXPORT_CAPACITY;
let unauthOtlpLastRefillMs = Date.now();
let securityAuditOtlpTokens = SECURITY_AUDIT_OTLP_CAPACITY;
let securityAuditOtlpLastRefillMs = Date.now();

export function resetOtlpExportLimitersForTests(): void {
  unauthOtlpTokens = UNAUTH_OTLP_EXPORT_CAPACITY;
  unauthOtlpLastRefillMs = Date.now();
  securityAuditOtlpTokens = SECURITY_AUDIT_OTLP_CAPACITY;
  securityAuditOtlpLastRefillMs = Date.now();
}

function consumeUnauthOtlpBudget(nowMs = Date.now()): boolean {
  const elapsed = Math.max(0, nowMs - unauthOtlpLastRefillMs);
  const refillPerMs = UNAUTH_OTLP_EXPORT_CAPACITY / UNAUTH_OTLP_WINDOW_MS;
  unauthOtlpTokens = Math.min(UNAUTH_OTLP_EXPORT_CAPACITY, unauthOtlpTokens + elapsed * refillPerMs);
  unauthOtlpLastRefillMs = nowMs;
  if (unauthOtlpTokens < 1) return false;
  unauthOtlpTokens -= 1;
  return true;
}

function consumeSecurityAuditOtlpBudget(nowMs = Date.now()): boolean {
  const elapsed = Math.max(0, nowMs - securityAuditOtlpLastRefillMs);
  const refillPerMs = SECURITY_AUDIT_OTLP_CAPACITY / UNAUTH_OTLP_WINDOW_MS;
  securityAuditOtlpTokens = Math.min(
    SECURITY_AUDIT_OTLP_CAPACITY,
    securityAuditOtlpTokens + elapsed * refillPerMs,
  );
  securityAuditOtlpLastRefillMs = nowMs;
  if (securityAuditOtlpTokens < 1) return false;
  securityAuditOtlpTokens -= 1;
  return true;
}

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
  if (!headerValue || headerValue.length > 256) return null;
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

function sanitizeInboundRequestId(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed || !SAFE_REQUEST_ID_RE.test(trimmed)) return null;
  return trimmed;
}

function hasHeaderValue(headers: Headers | undefined, name: string): boolean {
  if (!headers || typeof headers.get !== 'function') return false;
  const val = headers.get(name);
  return typeof val === 'string' && val.trim().length > 0;
}

function isNonSuppressibleAuditRequest(request: Request): boolean {
  if (hasHeaderValue(request.headers, 'x-agent-token')) {
    return true;
  }
  try {
    const pathname = new URL(request.url).pathname;
    if (
      pathname === '/admin' ||
      pathname.startsWith('/admin/') ||
      pathname.startsWith('/oauth/') ||
      pathname === '/mcp' ||
      pathname.startsWith('/mcp/') ||
      pathname.startsWith('/agent/')
    ) {
      return true;
    }
  } catch {
    // ignore malformed URLs in synthetic unit-test Request stubs
  }
  return false;
}

function isNonSuppressibleAuditSpanName(name: string): boolean {
  return (
    name.startsWith('edgefetch.admin.') ||
    name.startsWith('edgefetch.oauth.') ||
    name === 'edgefetch.mcp.tool' ||
    name === 'edgefetch.mcp_query' ||
    name === 'edgefetch.mcp_registry' ||
    name.startsWith('edgefetch.agent.')
  );
}

/** Extracts W3C `traceparent` from `request` or starts a new root trace context, returning propagation headers for Go workers. */
export function createRequestTraceContext(request: Request): {
  context: TraceContext;
  headers: Record<string, string>;
} {
  const parsed = parseTraceparent(request.headers?.get?.('traceparent'));
  const forceSampled = isNonSuppressibleAuditRequest(request);
  const context: TraceContext = parsed
    ? {
        ...parsed,
        sampled: parsed.sampled || forceSampled,
      }
    : {
        traceId: randomHex(16),
        spanId: randomHex(8),
        sampled: true,
      };
  const ray =
    sanitizeInboundRequestId(request.headers?.get?.('cf-ray')) ??
    sanitizeInboundRequestId(request.headers?.get?.('x-request-id')) ??
    context.spanId;
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
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  if (!raw || !raw.trim()) return { ...out };
  for (const entry of raw.split(',')) {
    const eq = entry.indexOf('=');
    if (eq <= 0) continue;
    const key = entry.slice(0, eq).trim();
    const rawVal = entry.slice(eq + 1).trim();
    if (!key || !RFC_HEADER_NAME_RE.test(key)) continue;
    if (FORBIDDEN_OTLP_HEADER_NAMES.has(key.toLowerCase())) continue;
    if (/[\r\n\0]/.test(key) || /[\r\n\0]/.test(rawVal)) continue;
    let decoded = rawVal;
    try {
      decoded = decodeURIComponent(rawVal);
    } catch {
      decoded = rawVal;
    }
    if (/[\r\n\0]/.test(decoded)) continue;
    out[key] = decoded;
  }
  return { ...out };
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
  if (u.username || u.password || u.hash) return null;
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
  const serviceVersion = params.serviceVersion?.trim() || '2.8.6';
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
              const safeStartMs = Number.isFinite(s.startTimeMs) ? Math.max(0, Math.floor(s.startTimeMs)) : 0;
              const safeEndMs = Number.isFinite(s.endTimeMs)
                ? Math.max(safeStartMs, Math.floor(s.endTimeMs))
                : safeStartMs;
              return {
                traceId: s.traceId,
                spanId: s.spanId,
                ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
                name: s.name.slice(0, 128),
                kind: s.kind ?? 2,
                startTimeUnixNano: `${BigInt(safeStartMs) * 1_000_000n}`,
                endTimeUnixNano: `${BigInt(safeEndMs) * 1_000_000n}`,
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

const SENSITIVE_ATTR_KEY_RE =
  /(?:token|secret|password|authorization|cookie|api[_.-]?key|credential|private[_.-]?key|bearer|csrf|sealed|verifier|session[_.-]?id)/i;
const URL_ATTR_KEY_RE = /^(?:url\.full|http\.url|url|target\.url|origin\.url)$/i;

function scrubFreeTextUrlsAndSecrets(raw: string): string {
  const bounded = raw.length > 4096 ? raw.slice(0, 4096) : raw;
  const withScrubbedUrls = bounded.replace(
    /(?:blob:)?(?:https?|wss?|ftps?):(?:\/\/|\\\/\\\/)[^\s"'<>)\]}]+/gi,
    (match) => {
      const hadEscapedSlashes = match.includes('\\/');
      const unescaped = hadEscapedSlashes ? match.replace(/\\\//g, '/') : match;
      const cleaned = sanitizeUrlForSpan(unescaped);
      return hadEscapedSlashes ? cleaned.replace(/\//g, '\\/') : cleaned;
    },
  );
  const withScrubbedSchemeless = withScrubbedUrls.replace(
    /(^|[\s"'([{,;])([A-Za-z0-9_.+-]{1,64}):([^\s/@"'<>()[\]{};,\\]{1,256})@(\[[0-9a-fA-F:]+\]|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|localhost)(?::\d{1,5})?/g,
    (_m, pre: string, _user: string, _pass: string, host: string) => `${pre}[redacted]@${host}`,
  );
  return withScrubbedSchemeless
    .replace(/\bBearer(?:[ \t]+|[ \t]*:[ \t]*)\S+/gi, 'Bearer [redacted]')
    .replace(/\bBasic(?:[ \t]+|[ \t]*:[ \t]*)\S+/gi, 'Basic [redacted]')
    .replace(/\b(?:efc|efa|efr)_[A-Za-z0-9_-]{8,}\b/g, '[redacted]')
    .replace(
      /(\b[a-z0-9_.-]{0,32}(?:api[_.-]?key|access[_.-]?token|refresh[_.-]?token|client[_.-]?secret|token|secret|password|passwd|pwd|signature|sig|code)[ \t]*[:=][ \t]*["']?)([^\s&"'`,;)\]}]+)/gi,
      '$1[redacted]',
    );
}

function redactInlineSecrets(raw: string): string {
  return scrubFreeTextUrlsAndSecrets(raw);
}

/** Strips URL query strings, fragments, userinfo, and inline secrets from span error messages. */
export function sanitizeErrorMessageForSpan(errOrMsg: unknown, fallback = ''): string {
  const raw =
    errOrMsg instanceof Error
      ? errOrMsg.message
      : typeof errOrMsg === 'string'
        ? errOrMsg
        : errOrMsg === undefined || errOrMsg === null
          ? ''
          : String(errOrMsg);
  const trimmed = raw.trim();
  if (!trimmed) return redactInlineSecrets(fallback).slice(0, 256);
  return scrubFreeTextUrlsAndSecrets(trimmed).slice(0, 256);
}

/** Strips query strings, fragments, and embedded credentials from URLs before attaching to spans. */
export function sanitizeUrlForSpan(rawUrl: string): string {
  const trimmed = rawUrl.trim().replace(/\\\//g, '/');
  if (!trimmed) return '';
  if (trimmed.toLowerCase().startsWith('blob:')) {
    const inner = sanitizeUrlForSpan(trimmed.slice(5));
    return (inner ? `blob:${inner}` : 'blob:').slice(0, 512);
  }
  try {
    const u = new URL(trimmed);
    if (u.protocol && u.host) {
      return `${u.protocol}//${u.host}${u.pathname}`.slice(0, 512);
    }
    if (u.origin && u.origin !== 'null') {
      return `${u.origin}${u.pathname}`.slice(0, 512);
    }
  } catch {
    // Fallback for malformed URLs below
  }
  return trimmed
    .replace(/:\/\/[^/?#\s]+@/g, '://')
    .replace(/[?#].*$/, '')
    .replace(
      /(\b[a-z0-9_.-]{0,32}(?:api[_.-]?key|access[_.-]?token|refresh[_.-]?token|client[_.-]?secret|token|secret|password|passwd|pwd|signature|sig|code)[ \t]*[:=][ \t]*["']?)([^\s&"'`,;)\]}]+)/gi,
      '$1[redacted]',
    )
    .slice(0, 512);
}

/** Sanitizes span attributes by redacting secret keys/values and stripping URL query/userinfo. */
export function sanitizeSpanAttributes(attrs?: SpanAttributes): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  if (!attrs) return out;
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined) continue;
    if (typeof value === 'string') {
      if (SENSITIVE_ATTR_KEY_RE.test(key)) {
        out[key] = '[redacted]';
      } else if (URL_ATTR_KEY_RE.test(key)) {
        out[key] = sanitizeUrlForSpan(value).slice(0, 512);
      } else {
        out[key] = redactInlineSecrets(value).slice(0, 512);
      }
    } else if (typeof value === 'number') {
      if (Number.isFinite(value)) out[key] = value;
    } else if (typeof value === 'boolean') {
      out[key] = value;
    }
  }
  return out;
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
  const safeEndMs = Number.isFinite(params.endTimeMs) ? Math.max(0, Math.floor(params.endTimeMs)) : Date.now();
  try {
    const parsed = JSON.parse(params.replyText) as {
      results?: Array<{
        id?: string;
        url?: string;
        kind?: unknown;
        status?: unknown;
        outcome?: unknown;
        durationMs?: unknown;
        rendered?: boolean;
        blockedTrackers?: unknown;
        waf?: { vendor?: unknown };
        timing?: {
          dnsMs?: unknown;
          connectMs?: unknown;
          tlsMs?: unknown;
          ttfbMs?: unknown;
          reused?: boolean;
          proto?: unknown;
        };
      }>;
    };
    for (const r of (parsed.results ?? []).slice(0, 32)) {
      const rawDur = Number(r.durationMs ?? r.timing?.ttfbMs ?? 1);
      const dur = Number.isFinite(rawDur) ? Math.max(1, Math.min(86_400_000, Math.floor(rawDur))) : 1;
      const safeKind =
        typeof r.kind === 'string' && /^[a-z0-9_-]{1,24}$/i.test(r.kind.trim()) ? r.kind.trim().toLowerCase() : 'page';
      const rawStatus = Number(r.status);
      const safeStatus = Number.isFinite(rawStatus) ? Math.max(0, Math.min(999, Math.floor(rawStatus))) : 0;
      const safeOutcome = typeof r.outcome === 'string' ? r.outcome : 'unknown';
      const safeUrl = sanitizeUrlForSpan(typeof r.url === 'string' ? r.url : '');
      const dnsMs = Number(r.timing?.dnsMs);
      const connectMs = Number(r.timing?.connectMs);
      const tlsMs = Number(r.timing?.tlsMs);
      const ttfbMs = Number(r.timing?.ttfbMs);
      out.push({
        traceId: params.traceId,
        spanId: randomHex(8),
        parentSpanId: params.parentSpanId,
        name: `edgefetch.fetch.${safeKind}`,
        kind: 3,
        startTimeMs: Math.max(0, safeEndMs - dur),
        endTimeMs: safeEndMs,
        statusOk:
          safeOutcome === 'ok' ||
          safeOutcome === 'gone' ||
          safeOutcome === 'not_found' ||
          safeOutcome === 'skip' ||
          (safeStatus === 404 && !r.waf?.vendor),
        attributes: sanitizeSpanAttributes({
          'url.full': safeUrl,
          'http.response.status_code': safeStatus,
          'crawler.via': params.via,
          'crawler.outcome': safeOutcome,
          'crawler.rendered': Boolean(r.rendered),
          ...(typeof r.blockedTrackers === 'number' && Number.isFinite(r.blockedTrackers)
            ? { 'browser.blocked_trackers': Math.max(0, Math.floor(r.blockedTrackers)) }
            : {}),
          ...(typeof r.waf?.vendor === 'string' && r.waf.vendor ? { 'edgefetch.waf.vendor': r.waf.vendor } : {}),
          'net.dns_ms': Number.isFinite(dnsMs) ? Math.max(0, Math.floor(dnsMs)) : 0,
          'net.connect_ms': Number.isFinite(connectMs) ? Math.max(0, Math.floor(connectMs)) : 0,
          'net.tls_ms': Number.isFinite(tlsMs) ? Math.max(0, Math.floor(tlsMs)) : 0,
          'net.ttfb_ms': Number.isFinite(ttfbMs) ? Math.max(0, Math.floor(ttfbMs)) : 0,
          'net.conn_reused': Boolean(r.timing?.reused),
          ...(typeof r.timing?.proto === 'string' && r.timing.proto ? { 'network.protocol.name': r.timing.proto } : {}),
        }),
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
  priority?: 'authenticated' | 'security_audit' | 'public_unauth';
}): Promise<boolean> {
  if (params.spans.length === 0) return false;
  const tracesUrl = resolveOtlpTracesUrl(params.env.OTEL_EXPORTER_OTLP_ENDPOINT);
  if (!tracesUrl) return false;
  const priority = params.priority ?? 'authenticated';
  if (inflightOtlpExports >= MAX_INFLIGHT_OTLP_EXPORTS) return false;
  if (priority === 'public_unauth' && inflightPublicUnauthOtlp >= MAX_PUBLIC_UNAUTH_INFLIGHT_OTLP) {
    return false;
  }
  if (
    priority === 'security_audit' &&
    inflightSecurityAuditOtlp + inflightPublicUnauthOtlp >= MAX_SECURITY_AUDIT_INFLIGHT_OTLP
  ) {
    return false;
  }

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...parseOtlpHeaders(params.env.OTEL_EXPORTER_OTLP_HEADERS),
  };
  const payload = buildOtlpTracePayload({
    serviceName: params.env.OTEL_SERVICE_NAME,
    spans: params.spans,
  });
  const doFetch = params.fetchFn ?? fetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => {
    ctrl.abort(new DOMException('OTLP export timed out', 'TimeoutError'));
  }, 4_000);
  (timer as { unref?: () => void }).unref?.();
  inflightOtlpExports++;
  if (priority === 'public_unauth') inflightPublicUnauthOtlp++;
  else if (priority === 'security_audit') inflightSecurityAuditOtlp++;
  try {
    const res = await doFetch(tracesUrl, {
      method: 'POST',
      redirect: 'manual',
      headers,
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    await res.body?.cancel().catch(() => undefined);
    return res.ok;
  } catch {
    return false;
  } finally {
    inflightOtlpExports = Math.max(0, inflightOtlpExports - 1);
    if (priority === 'public_unauth') inflightPublicUnauthOtlp = Math.max(0, inflightPublicUnauthOtlp - 1);
    else if (priority === 'security_audit') inflightSecurityAuditOtlp = Math.max(0, inflightSecurityAuditOtlp - 1);
    clearTimeout(timer);
  }
}

const PROTECTED_ROUTE_SPAN_NAMES: ReadonlySet<string> = new Set([
  'edgefetch.scrape',
  'edgefetch.batch_scrape',
  'edgefetch.ingest_tab',
  'edgefetch.extract',
  'edgefetch.search',
  'edgefetch.collection_search',
  'edgefetch.jobs',
  'edgefetch.catalog',
  'edgefetch.map',
  'edgefetch.crawl',
  'edgefetch.interact',
  'edgefetch.agent',
  'edgefetch.agents',
  'edgefetch.fetch',
  'edgefetch.capabilities',
  'edgefetch.extractors',
  'edgefetch.mcp_registry',
  'edgefetch.mcp_query',
  'edgefetch.hosts',
  'edgefetch.artifacts',
  'edgefetch.mcp.tool',
  'edgefetch.dispatch',
]);

function classifyBatchAuthStatus(
  batch: OtlpSpanInput[],
  explicitAuthenticated: boolean,
): 'authenticated' | 'security_audit' | 'unauth_rejected' | 'public_unauth' {
  if (explicitAuthenticated) return 'authenticated';
  const serverHttpSpan = batch.find((s) => s.name === 'edgefetch.http' && s.kind === 2);
  if (!serverHttpSpan) {
    // Non-HTTP background / direct unit-test tracer spans are caller-controlled programmatic traces
    return 'authenticated';
  }
  const httpStatus = Number(serverHttpSpan.attributes?.['http.response.status_code'] ?? 0);
  const hasAuthenticatedWork = batch.some(
    (s) =>
      s.kind === 3 ||
      s.name === 'edgefetch.dispatch' ||
      s.name.startsWith('edgefetch.fetch.') ||
      s.name === 'edgefetch.mcp.tool' ||
      s.name.startsWith('edgefetch.agent.') ||
      s.attributes?.['admin.outcome'] === 'authenticated' ||
      s.attributes?.['admin.outcome'] === 'logged_out' ||
      (s.name.startsWith('edgefetch.admin.') &&
        s.name !== 'edgefetch.admin.login' &&
        s.name !== 'edgefetch.admin.github_login' &&
        s.name !== 'edgefetch.admin.github_callback' &&
        httpStatus !== 401 &&
        s.attributes?.['admin.outcome'] !== 'unauthorized') ||
      (s.name === 'edgefetch.oauth.authorize' && s.attributes?.['oauth.outcome'] === 'approved') ||
      ((s.name === 'edgefetch.oauth.token' ||
        s.name === 'edgefetch.oauth.refresh' ||
        s.name === 'edgefetch.oauth.revoke') &&
        ((httpStatus >= 200 && httpStatus < 300) || s.attributes?.['oauth.outcome'] === 'replay_detected')) ||
      (httpStatus !== 401 && httpStatus !== 403 && PROTECTED_ROUTE_SPAN_NAMES.has(s.name)),
  );
  if (hasAuthenticatedWork) return 'authenticated';
  const hasAdminAuthenticated =
    httpStatus >= 200 &&
    httpStatus < 400 &&
    typeof serverHttpSpan.attributes?.['url.path'] === 'string' &&
    (serverHttpSpan.attributes['url.path'].startsWith('/admin/api/') ||
      serverHttpSpan.attributes['url.path'].startsWith('/admin/mcp/'));
  if (hasAdminAuthenticated) return 'authenticated';

  // Isolate `/admin/*` and `/oauth/*` security audit spans onto a dedicated security-audit budget so public
  // discovery traffic (`/openapi.json`, `/.well-known/*`, `/health`, `401` floods) can NEVER drain audit exports!
  const hasSecurityAuditSpan = batch.some(
    (s) => s.name.startsWith('edgefetch.admin.') || s.name.startsWith('edgefetch.oauth.'),
  );
  if (hasSecurityAuditSpan) {
    return 'security_audit';
  }
  if (httpStatus === 401 || httpStatus === 403) {
    return 'unauth_rejected';
  }
  return 'public_unauth';
}

interface RequestTracerState {
  rootContext: TraceContext;
  requestId: string;
  spans: OtlpSpanInput[];
  openSpans: Set<ActiveSpanHandle>;
  suppressed: boolean;
  authenticated: boolean;
  rootSpanClaimed: boolean;
}

function createRequestTracerStorage(): AsyncLocalStorageLike<RequestTracer> {
  try {
    if (typeof AsyncLocalStorage === 'function') {
      return new (AsyncLocalStorage as new <T>() => AsyncLocalStorageLike<T>)<RequestTracer>();
    }
  } catch {
    // fallback below when node:async_hooks is unavailable
  }
  let currentStore: RequestTracer | undefined;
  return {
    getStore: () => currentStore,
    run: <R>(store: RequestTracer, callback: (...args: unknown[]) => R, ...args: unknown[]): R => {
      const prev = currentStore;
      currentStore = store;
      try {
        return callback(...args);
      } finally {
        currentStore = prev;
      }
    },
  };
}

const requestTracerStorage = createRequestTracerStorage();

const inProcessVerifiedRequests = new WeakSet<Request>();

/**
 * Marks a Web `Request` instance in-process (never via an inbound HTTP header!) as having passed front-end
 * cryptographic credential verification in `portable-server.ts`.
 */
export function markRequestVerifiedInProcess(request: Request): void {
  inProcessVerifiedRequests.add(request);
}

export function isRequestVerifiedInProcess(request: Request): boolean {
  return inProcessVerifiedRequests.has(request);
}

export class RequestTracer {
  private readonly state: RequestTracerState;
  private readonly currentSpanId: string;
  private readonly currentSpan?: ActiveSpanHandle;

  private constructor(state: RequestTracerState, currentSpanId: string, currentSpan?: ActiveSpanHandle) {
    this.state = state;
    this.currentSpanId = currentSpanId;
    this.currentSpan = currentSpan;
  }

  /**
   * True when this tracer is the root view (no span entered) of the same request as `other`. Used so an explicitly
   * passed root tracer does not shadow the child span that is active in AsyncLocalStorage for that same request.
   */
  isRootViewOf(other: RequestTracer): boolean {
    return this.currentSpan === undefined && this.state === other.state;
  }

  static fromRequest(
    request: Request,
    opts?: { suppress?: boolean; suppressWhenUnsampledHealth?: boolean; authenticated?: boolean },
  ): RequestTracer {
    const { context, headers } = createRequestTraceContext(request);
    let suppress = Boolean(opts?.suppress);
    const methodUpper = request.method.toUpperCase();
    if (!suppress && opts?.suppressWhenUnsampledHealth && (methodUpper === 'GET' || methodUpper === 'HEAD')) {
      try {
        const pathname = new URL(request.url).pathname;
        if (pathname === '/health' || pathname === '/readyz') suppress = true;
      } catch {
        // ignore invalid URL
      }
    }
    const preVerified = Boolean(opts?.authenticated) || isRequestVerifiedInProcess(request);
    return new RequestTracer(
      {
        rootContext: context,
        requestId: headers['x-request-id'] ?? context.spanId,
        spans: [],
        openSpans: new Set<ActiveSpanHandle>(),
        suppressed: suppress,
        authenticated: preVerified,
        rootSpanClaimed: false,
      },
      context.spanId,
    );
  }

  static fromContext(
    context: TraceContext,
    requestId?: string,
    opts?: { suppress?: boolean; authenticated?: boolean },
  ): RequestTracer {
    const parentHandle: ActiveSpanHandle = {
      traceId: context.traceId,
      spanId: context.spanId,
      ...(context.parentSpanId ? { parentSpanId: context.parentSpanId } : {}),
      name: 'context',
      sampled: context.sampled,
      setAttribute() {},
      setAttributes() {},
      setStatus() {},
      end() {},
    };
    return new RequestTracer(
      {
        rootContext: { ...context },
        requestId: sanitizeInboundRequestId(requestId) ?? context.spanId,
        spans: [],
        openSpans: new Set<ActiveSpanHandle>(),
        suppressed: Boolean(opts?.suppress),
        authenticated: opts?.authenticated ?? true,
        rootSpanClaimed: true,
      },
      context.spanId,
      parentHandle,
    );
  }

  get traceId(): string {
    return this.state.rootContext.traceId;
  }

  get rootSpanId(): string {
    return this.state.rootContext.spanId;
  }

  get spanId(): string {
    return this.currentSpanId;
  }

  get sampled(): boolean {
    return this.state.rootContext.sampled;
  }

  get requestId(): string {
    return this.state.requestId;
  }

  get suppressed(): boolean {
    return this.state.suppressed;
  }

  get authenticated(): boolean {
    return this.state.authenticated;
  }

  markAuthenticated(authenticated = true): void {
    this.state.authenticated = authenticated;
  }

  get context(): TraceContext {
    return {
      traceId: this.traceId,
      spanId: this.currentSpanId,
      ...(this.currentSpan?.parentSpanId
        ? { parentSpanId: this.currentSpan.parentSpanId }
        : this.state.rootContext.parentSpanId
          ? { parentSpanId: this.state.rootContext.parentSpanId }
          : {}),
      sampled: this.sampled,
    };
  }

  setSuppressed(suppressed: boolean): void {
    this.state.suppressed = suppressed;
  }

  run<T>(fn: () => T): T {
    return requestTracerStorage.run(this, fn);
  }

  startSpan(name: string, opts?: SpanStartOptions): ActiveSpanHandle {
    if (isNonSuppressibleAuditSpanName(name)) {
      this.state.rootContext.sampled = true;
    }
    const claimRoot = this.currentSpan === undefined && !this.state.rootSpanClaimed;
    if (claimRoot) {
      this.state.rootSpanClaimed = true;
    }
    const spanId = claimRoot ? this.state.rootContext.spanId : randomHex(8);
    const parentSpanId =
      this.currentSpan !== undefined
        ? this.currentSpan.spanId
        : this.state.rootContext.parentSpanId;
    const rawStart = opts?.startTimeMs ?? Date.now();
    const startTimeMs = Number.isFinite(rawStart) ? rawStart : Date.now();
    const kind = opts?.kind ?? 1;
    const attributes: Record<string, string | number | boolean> = sanitizeSpanAttributes(opts?.attributes);
    let statusOk = true;
    let errorMessage: string | undefined;
    let ended = false;
    const state = this.state;

    const handle: ActiveSpanHandle = {
      traceId: state.rootContext.traceId,
      spanId,
      ...(parentSpanId ? { parentSpanId } : {}),
      name,
      get sampled() {
        return state.rootContext.sampled;
      },
      setAttribute(key, value) {
        if (ended) return;
        if (key === 'admin.outcome' || key === 'oauth.outcome') {
          state.rootContext.sampled = true;
        }
        const sanitized = sanitizeSpanAttributes({ [key]: value });
        Object.assign(attributes, sanitized);
      },
      setAttributes(attrs) {
        if (ended) return;
        if ('admin.outcome' in attrs || 'oauth.outcome' in attrs) {
          state.rootContext.sampled = true;
        }
        Object.assign(attributes, sanitizeSpanAttributes(attrs));
      },
      setStatus(ok, errMsg) {
        if (ended) return;
        statusOk = ok;
        if (!ok && errMsg) {
          const safeMsg = sanitizeErrorMessageForSpan(errMsg);
          errorMessage = safeMsg || undefined;
        } else if (ok) {
          errorMessage = undefined;
        }
      },
      end(endTimeMs = Date.now()) {
        if (ended) return;
        ended = true;
        state.openSpans.delete(handle);
        if (state.suppressed || !state.rootContext.sampled) return;
        const safeEnd = Number.isFinite(endTimeMs) ? Math.max(startTimeMs, endTimeMs) : startTimeMs;
        state.spans.push({
          traceId: state.rootContext.traceId,
          spanId,
          ...(parentSpanId ? { parentSpanId } : {}),
          name,
          kind,
          startTimeMs,
          endTimeMs: safeEnd,
          statusOk,
          ...(errorMessage ? { errorMessage } : {}),
          attributes,
        });
      },
    };
    state.openSpans.add(handle);
    return handle;
  }

  async withSpan<T>(
    name: string,
    optsOrFn: SpanStartOptions | undefined | ((span: ActiveSpanHandle, tracer: RequestTracer) => Promise<T> | T),
    maybeFn?: (span: ActiveSpanHandle, tracer: RequestTracer) => Promise<T> | T,
  ): Promise<T> {
    const opts = typeof optsOrFn === 'function' ? undefined : optsOrFn;
    const fn = typeof optsOrFn === 'function' ? optsOrFn : maybeFn!;
    const span = this.startSpan(name, opts);
    const childTracer = new RequestTracer(this.state, span.spanId, span);
    try {
      return await requestTracerStorage.run(childTracer, () => fn(span, childTracer));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      span.setStatus(false, msg);
      throw err;
    } finally {
      span.end();
    }
  }

  setAttribute(key: string, value: string | number | boolean | undefined): void {
    if (this.currentSpan) {
      this.currentSpan.setAttribute(key, value);
    }
  }

  recordSpans(spans: OtlpSpanInput[]): void {
    if (this.state.suppressed || !this.sampled || spans.length === 0) return;
    for (const s of spans) {
      this.state.spans.push({
        ...s,
        traceId: s.traceId || this.traceId,
        attributes: sanitizeSpanAttributes(s.attributes),
      });
    }
  }

  getTraceHeaders(): Record<string, string> {
    return {
      traceparent: formatTraceparent({
        traceId: this.traceId,
        spanId: this.currentSpanId,
        sampled: this.sampled,
      }),
      'x-trace-id': this.traceId,
      'x-span-id': this.currentSpanId,
      'x-request-id': this.requestId,
    };
  }

  getRootTraceHeaders(): Record<string, string> {
    return {
      'x-trace-id': this.traceId,
      traceparent: formatTraceparent({
        traceId: this.traceId,
        spanId: this.rootSpanId,
        sampled: this.sampled,
      }),
    };
  }

  bindPromise<T>(promise: Promise<T>): Promise<T> {
    return this.run(() => promise);
  }

  bindCallback<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
    return (...args: A) => this.run(() => fn(...args));
  }

  getRecordedSpans(): OtlpSpanInput[] {
    return [...this.state.spans];
  }

  async flush(params: {
    env: OtelEnvConfig & { SAFE_FETCH?: typeof fetch; SAFE_PUBLIC_FETCH?: typeof fetch };
    fetchFn?: typeof fetch;
    devTelemetrySetting?: string | boolean | null;
    ctx?: { waitUntil?: (p: Promise<unknown>) => void };
  }): Promise<boolean> {
    const batch = this.state.spans.splice(0, this.state.spans.length);
    if (batch.length === 0 || this.state.suppressed || !this.sampled) {
      return false;
    }

    const authClass = classifyBatchAuthStatus(batch, this.state.authenticated);
    // Never emit outbound OTLP or Dev-Telemetry network POSTs on unauthenticated `401`/`403` gate rejections!
    if (authClass === 'unauth_rejected') {
      return false;
    }
    const allowOtlp =
      authClass === 'authenticated'
        ? true
        : authClass === 'security_audit'
          ? consumeSecurityAuditOtlpBudget()
          : consumeUnauthOtlpBudget();
    const allowDevTelemetry = authClass === 'authenticated';

    const doFlush = Promise.all([
      allowOtlp
        ? flushOtlpSpans({
            env: params.env,
            spans: batch,
            priority: authClass,
            ...(params.fetchFn ?? params.env.SAFE_FETCH ? { fetchFn: params.fetchFn ?? params.env.SAFE_FETCH } : {}),
          })
        : Promise.resolve(false),
      allowDevTelemetry
        ? flushDevErrorTelemetry({
            env: params.env,
            spans: batch,
            dbSettingValue: params.devTelemetrySetting,
            ...(params.fetchFn ?? params.env.SAFE_PUBLIC_FETCH ?? params.env.SAFE_FETCH
              ? { fetchFn: params.fetchFn ?? params.env.SAFE_PUBLIC_FETCH ?? params.env.SAFE_FETCH }
              : {}),
          })
        : Promise.resolve(false),
    ]).then(([otlpOk, devTelOk]) => otlpOk || devTelOk);
    if (params.ctx?.waitUntil) {
      params.ctx.waitUntil(doFlush);
      return true;
    }
    return await doFlush;
  }
}

export function getActiveRequestTracer(explicit?: RequestTracer | TraceContext): RequestTracer | null {
  if (explicit instanceof RequestTracer) {
    // A root tracer handed in explicitly (e.g. bound before `withRouteSpan`) would otherwise win over the span that is
    // actually active for this request, turning `setActiveSpanAttribute` into a no-op on the root.
    const activeForSameRequest = requestTracerStorage.getStore();
    if (activeForSameRequest && activeForSameRequest !== explicit && explicit.isRootViewOf(activeForSameRequest)) {
      return activeForSameRequest;
    }
    return explicit;
  }
  const fromAls = requestTracerStorage.getStore();
  if (fromAls) return fromAls;
  if (explicit) return RequestTracer.fromContext(explicit);
  return null;
}

export function setActiveSpanAttribute(
  key: string,
  value: string | number | boolean | undefined,
  explicit?: RequestTracer | TraceContext,
): void {
  const tracer = getActiveRequestTracer(explicit);
  tracer?.setAttribute(key, value);
}

/** Attaches `x-trace-id` and `traceparent` headers to any HTTP Response safely (preserving `101` WebSocket upgrades and immutable redirects). */
export function injectTraceHeaders(response: Response, trace: RequestTracer | TraceContext): Response {
  const traceId = trace.traceId;
  const spanId = trace instanceof RequestTracer ? trace.rootSpanId : trace.spanId;
  const sampled = trace.sampled;
  const traceparent = formatTraceparent({ traceId, spanId, sampled });
  const isWebSocketUpgrade =
    response.status === 101 ||
    ('webSocket' in response && Boolean((response as { webSocket?: unknown }).webSocket));

  if (isWebSocketUpgrade) {
    try {
      response.headers.set('x-trace-id', traceId);
      response.headers.set('traceparent', traceparent);
    } catch {
      // Never reconstruct a 101 WebSocket response
    }
    return response;
  }

  try {
    response.headers.set('x-trace-id', traceId);
    response.headers.set('traceparent', traceparent);
    return response;
  } catch {
    const headers = new Headers(response.headers);
    headers.set('x-trace-id', traceId);
    headers.set('traceparent', traceparent);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }
}
