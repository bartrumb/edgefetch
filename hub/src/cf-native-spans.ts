/**
 * Cloudflare Workers native tracing sink for EdgeFetch's request tracer spans.
 *
 * Only `edgefetch.dispatch` used `tracing.enterSpan` directly, so every other EdgeFetch span (search providers,
 * search cache, agent router, MCP federation, ...) reached Cloudflare only if an OTLP endpoint was configured. This
 * sink re-emits each flushed span as a native span. Native spans start when emitted, so the real timing is carried
 * as `edgefetch.span.start_ms` / `edgefetch.span.duration_ms` attributes (query those, not the native duration).
 * Disable with `EDGEFETCH_CF_NATIVE_SPANS=off`.
 */
import { tracing } from 'cloudflare:workers';

import type { NativeSpanSink, OtlpSpanInput } from './otel';

const MAX_ATTRIBUTES = 64;

type NativeSpan = { setAttribute(key: string, value: unknown): void };
type EnterSpan = <T>(name: string, fn: (span: NativeSpan) => T) => T;

export function nativeSpanAttributes(span: OtlpSpanInput): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {
    'edgefetch.span.start_ms': span.startTimeMs,
    'edgefetch.span.duration_ms': Math.max(0, span.endTimeMs - span.startTimeMs),
    'edgefetch.span.status': span.statusOk === false ? 'error' : 'ok',
    'edgefetch.trace_id': span.traceId,
    'edgefetch.span_id': span.spanId,
  };
  if (span.parentSpanId) out['edgefetch.parent_span_id'] = span.parentSpanId;
  if (span.errorMessage) out['edgefetch.span.error'] = span.errorMessage;
  let added = 0;
  for (const [k, v] of Object.entries(span.attributes ?? {})) {
    if (v === undefined || k in out) continue;
    if (added++ >= MAX_ATTRIBUTES) break;
    out[k] = v;
  }
  return out;
}

export function cloudflareNativeSpanSink(env: { EDGEFETCH_CF_NATIVE_SPANS?: string }): NativeSpanSink | undefined {
  if ((env.EDGEFETCH_CF_NATIVE_SPANS ?? '').trim().toLowerCase() === 'off') return undefined;
  const enter = (tracing as unknown as { enterSpan?: EnterSpan }).enterSpan;
  if (typeof enter !== 'function') return undefined;
  return (span) => {
    enter.call(tracing, span.name || 'edgefetch.span', (native: NativeSpan) => {
      for (const [k, v] of Object.entries(nativeSpanAttributes(span))) native.setAttribute(k, v);
    });
  };
}
