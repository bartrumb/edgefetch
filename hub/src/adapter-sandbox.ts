/**
 * Zero-Secret / Zero-Network Bulkhead & Optional Dynamic Worker Isolate Runner for Site Adapters (`hub/src/adapter-sandbox.ts`).
 *
 * Security Invariants (Kitesurf Lesson #1):
 *  1. Contributed adapters (`hub/src/extractors/providers/**`) receive ONLY frozen plain-data inputs (`url`, `rawHtml`/`rawBody`,
 *     pure HTML-to-Markdown helper) — NEVER `env`, Hub secrets (`CALLER_TOKEN`, `AGENT_TOKENS`, LLM keys), D1/R2 bindings, or `fetch`.
 *  2. During synchronous adapter execution, global outbound `fetch` is temporarily poisoned (`AdapterNetworkForbiddenError`)
 *     so a buggy or malicious contributed adapter attempting `globalThis.fetch(...)` fails closed immediately with zero network egress!
 *  3. When an optional Cloudflare Dynamic Worker Loader binding (`env.ADAPTER_ISOLATE_LOADER`) is configured on Workers Paid,
 *     untrusted external adapter scripts can be executed inside a disposable `LOADER.load(...)` V8 isolate with `globalOutbound: null`
 *     and empty `env: {}`.
 */

export class AdapterNetworkForbiddenError extends Error {
  constructor() {
    super('Adapter bulkhead violation: network fetch is forbidden inside site adapters');
    this.name = 'AdapterNetworkForbiddenError';
  }
}

export interface DynamicWorkerLoaderLike {
  load(spec: {
    compatibilityDate: string;
    mainModule: string;
    modules: Record<string, string>;
    env?: Record<string, never>;
    globalOutbound?: null;
  }): {
    fetch(input: string | Request, init?: RequestInit): Promise<Response>;
  };
}

export const MAX_ADAPTER_ISOLATE_OUTPUT_BYTES = 4 * 1024 * 1024; // 4 MiB ceiling on dynamic Worker isolate outputs

function deepFreezePlainData<T>(val: T, depth = 0): T {
  if (val === null || typeof val !== 'object' || depth > 6) return val;
  if (Object.isFrozen(val)) return val;
  if (Array.isArray(val)) {
    const copy = val.map((item) => deepFreezePlainData(item, depth + 1));
    return Object.freeze(copy) as unknown as T;
  }
  const proto = Object.getPrototypeOf(val);
  if (proto !== Object.prototype && proto !== null) {
    return val;
  }
  const clone: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
    clone[k] = deepFreezePlainData(v, depth + 1);
  }
  return Object.freeze(clone) as T;
}

async function readIsolateJsonCapped(res: Response, maxBytes = MAX_ADAPTER_ISOLATE_OUTPUT_BYTES): Promise<unknown> {
  if (!res.body) return null;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value && value.byteLength > 0) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel('Adapter isolate output exceeds byte cap').catch(() => undefined);
        throw new Error(`Adapter isolate output exceeds ${maxBytes} bytes limit`);
      }
      chunks.push(value);
    }
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(merged));
}

/**
 * Executes a synchronous site-adapter hook (`extractHtml` or `formatTwin`) inside a zero-network, frozen-input bulkhead
 * with wall-clock timing telemetry. Temporarily replaces `globalThis.fetch` and `globalThis.WebSocket` for the duration of
 * the synchronous turn so contributed adapter code cannot initiate covert network requests.
 */
export function runAdapterSyncInBulkhead<TInput extends object, TResult>(
  adapterId: string,
  fn: (input: Readonly<TInput>) => TResult,
  input: TInput,
  maxBudgetMs = 250,
): { ok: true; value: TResult; durationMs: number; overBudget: boolean } | { ok: false; error: string; durationMs: number } {
  const frozenInput = deepFreezePlainData(input);
  const origFetch = globalThis.fetch;
  const origWebSocket = (globalThis as { WebSocket?: unknown }).WebSocket;
  const started = Date.now();
  let fetchDescriptorRestorable = true;
  let wsDescriptorRestorable = true;
  try {
    globalThis.fetch = (() => {
      throw new AdapterNetworkForbiddenError();
    }) as typeof fetch;
  } catch {
    fetchDescriptorRestorable = false;
  }
  try {
    if (origWebSocket !== undefined) {
      (globalThis as { WebSocket?: unknown }).WebSocket = function ForbiddenAdapterWebSocket() {
        throw new AdapterNetworkForbiddenError();
      };
    }
  } catch {
    wsDescriptorRestorable = false;
  }

  try {
    const value = fn(frozenInput);
    if (
      value !== null &&
      (typeof value === 'object' || typeof value === 'function') &&
      typeof (value as { then?: unknown }).then === 'function'
    ) {
      const durationMs = Date.now() - started;
      return {
        ok: false,
        error: `adapter[${adapterId}] failed: synchronous bulkhead forbids async/Promise return values`,
        durationMs,
      };
    }
    const durationMs = Date.now() - started;
    return {
      ok: true,
      value,
      durationMs,
      overBudget: durationMs > maxBudgetMs,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: `adapter[${adapterId}] failed: ${msg.slice(0, 240)}`,
      durationMs,
    };
  } finally {
    if (fetchDescriptorRestorable) {
      try {
        globalThis.fetch = origFetch;
      } catch {
        // Ignore if runtime freezes globalThis.fetch
      }
    }
    if (wsDescriptorRestorable && origWebSocket !== undefined) {
      try {
        (globalThis as { WebSocket?: unknown }).WebSocket = origWebSocket;
      } catch {
        // Ignore if runtime freezes globalThis.WebSocket
      }
    }
  }
}

/**
 * Optional Cloudflare Dynamic Worker isolate runner (`worker_loaders`): runs a self-contained ES module transform inside
 * a throwaway V8 isolate with `env: {}` and `globalOutbound: null` (zero secrets, zero network).
 */
export async function runUntrustedAdapterInDynamicWorker<TInput, TOutput>(params: {
  loader: DynamicWorkerLoaderLike;
  adapterModuleSource: string;
  input: TInput;
  timeoutMs?: number;
}): Promise<{ ok: true; output: TOutput } | { ok: false; error: string }> {
  const harnessSource = `
import adapter from './adapter.mjs';
export default {
  async fetch(request) {
    const payload = await request.json();
    const fn = typeof adapter === 'function' ? adapter : adapter?.transform;
    if (typeof fn !== 'function') {
      return Response.json({ ok: false, error: 'missing adapter transform' }, { status: 400 });
    }
    const output = await fn(Object.freeze(payload));
    return Response.json({ ok: true, output });
  }
};
`;
  try {
    const isolate = params.loader.load({
      compatibilityDate: '2026-01-01',
      mainModule: 'entry.mjs',
      modules: {
        'entry.mjs': harnessSource,
        'adapter.mjs': params.adapterModuleSource,
      },
      env: {},
      globalOutbound: null,
    });
    const res = await isolate.fetch('https://adapter-isolate.internal/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(params.input),
      signal: AbortSignal.timeout(Math.max(50, Math.min(2_000, params.timeoutMs ?? 500))),
    });
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      return { ok: false, error: `isolate HTTP ${res.status}` };
    }
    const body = (await readIsolateJsonCapped(res)) as { ok?: boolean; output?: TOutput; error?: string };
    return body?.ok ? { ok: true, output: body.output as TOutput } : { ok: false, error: body?.error ?? 'isolate error' };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
