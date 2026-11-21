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

/**
 * Executes a synchronous site-adapter hook (`extractHtml` or `formatTwin`) inside a zero-network, frozen-input bulkhead
 * with wall-clock timing telemetry. Temporarily replaces `globalThis.fetch` for the duration of the synchronous turn so
 * contributed adapter code cannot initiate covert network requests even if it references `globalThis.fetch`.
 */
export function runAdapterSyncInBulkhead<TInput extends object, TResult>(
  adapterId: string,
  fn: (input: Readonly<TInput>) => TResult,
  input: TInput,
  maxBudgetMs = 250,
): { ok: true; value: TResult; durationMs: number; overBudget: boolean } | { ok: false; error: string; durationMs: number } {
  const frozenInput = Object.freeze({ ...input });
  const origFetch = globalThis.fetch;
  const started = Date.now();
  let fetchDescriptorRestorable = true;
  try {
    globalThis.fetch = (() => {
      throw new AdapterNetworkForbiddenError();
    }) as typeof fetch;
  } catch {
    fetchDescriptorRestorable = false;
  }

  try {
    const value = fn(frozenInput);
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
      return { ok: false, error: `isolate HTTP ${res.status}` };
    }
    const body = (await res.json()) as { ok?: boolean; output?: TOutput; error?: string };
    return body?.ok ? { ok: true, output: body.output as TOutput } : { ok: false, error: body?.error ?? 'isolate error' };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
