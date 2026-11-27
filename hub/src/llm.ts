/**
 * Vendor-neutral BYO-LLM engine (`hub/src/llm.ts`) delegating all pure-CPU config resolution,
 * C1/M1 origin + path-prefix API key isolation, SSRF validation, URL/header log redaction,
 * provider wire request/response codecs, `<think>`/`<tool_call>` parsing, extractive summaries,
 * and JSON Schema validation to Go (`internal/agentloop` via `edgefetch-core.wasm`).
 *
 * Retains thin async `fetch` (`redirect: 'manual'`, 4 MiB streamed response cap), Cloudflare
 * `Workers AI` binding execution, and zero-secret OpenTelemetry span instrumentation.
 */

import {
  getActiveRequestTracer,
  sanitizeErrorMessageForSpan,
  sanitizeUrlForSpan,
  type ActiveSpanHandle,
  type RequestTracer,
  type SpanAttributes,
  type TraceContext,
} from './otel';
import { callCoreWasm, callCoreWasmRaw } from './wasm-bridge';

const MAX_LLM_RESPONSE_BYTES = 4 * 1024 * 1024; // 4 MiB ceiling on LLM API JSON responses (H5)

export type LlmProvider =
  | 'openai'
  | 'ollama'
  | 'lmstudio'
  | 'vllm'
  | 'openrouter'
  | 'anthropic'
  | 'gemini'
  | 'workers-ai';

export interface LlmEnvBindings {
  EDGEFETCH_LLM_PROVIDER?: string;
  EDGEFETCH_LLM_BASE_URL?: string;
  EDGEFETCH_LLM_API_KEY?: string;
  EDGEFETCH_LLM_MODEL?: string;
  EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE?: string;
  OLLAMA_HOST?: string;
  OPENAI_API_KEY?: string;
  OPENROUTER_API_KEY?: string;
  ANTHROPIC_API_KEY?: string;
  GEMINI_API_KEY?: string;
  SAFE_FETCH?: typeof fetch;
  SAFE_PUBLIC_FETCH?: typeof fetch;
  AI?: {
    run: (model: string, inputs: Record<string, unknown>) => Promise<unknown>;
    /** Cloudflare Web Search API on the Workers AI binding (used by `web-search.ts`). */
    websearch?: (opts: Record<string, unknown>) => Promise<Response>;
  };
}

export interface ResolvedLlmConfig {
  provider: LlmProvider;
  baseUrl: string;
  apiKey?: string;
  model: string;
  isOfflineLocal: boolean;
  safeFetch?: typeof fetch;
  workersAi?: LlmEnvBindings['AI'];
}

export interface LlmToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface LlmToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export type LlmMessage =
  | { role: 'system'; content: string }
  | { role: 'user'; content: string }
  | { role: 'assistant'; content: string; toolCalls?: LlmToolCall[] }
  | { role: 'tool'; toolCallId: string; name: string; content: string };

export interface LlmChatCompletionResult {
  ok: boolean;
  content: string;
  toolCalls: LlmToolCall[];
  usage?: {
    promptTokens?: number;
    completionTokens?: number;
    totalTokens?: number;
  };
  error?: string;
}

async function readResponseTextCapped(res: Response, maxBytes = MAX_LLM_RESPONSE_BYTES): Promise<string> {
  const cl = res.headers.get('content-length');
  if (cl !== null && cl.trim() !== '') {
    const n = Number(cl);
    if (Number.isFinite(n) && n > maxBytes) {
      await res.body?.cancel().catch(() => undefined);
      throw new Error(`LLM response Content-Length (${n}) exceeds ${maxBytes} byte limit`);
    }
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value && value.byteLength > 0) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel('LLM response too large').catch(() => undefined);
        throw new Error(`LLM response body exceeds ${maxBytes} byte limit`);
      }
      chunks.push(value);
    }
  }
  if (chunks.length === 0) return '';
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    joined.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(joined);
}

export function redactLlmUrlForLog(rawUrl: string): string {
  if (!rawUrl || rawUrl.startsWith('workers-ai://')) return rawUrl;
  return callCoreWasm<{ out: string }>('llm_redact_url', { url: rawUrl }).out;
}

export function redactLlmConfigForLog(
  cfg: (ResolvedLlmConfig & { endpoint?: string; headers?: unknown }) | null,
): Record<string, unknown> | undefined {
  if (!cfg) return undefined;
  let headersMap: Record<string, string> | undefined;
  let hasHeaders = false;
  if (cfg.headers && typeof cfg.headers === 'object') {
    if (typeof (cfg.headers as Headers).forEach === 'function') {
      headersMap = {};
      hasHeaders = true;
      (cfg.headers as Headers).forEach((v, k) => {
        headersMap![k] = v;
      });
    } else if (!Array.isArray(cfg.headers)) {
      headersMap = {};
      hasHeaders = true;
      for (const [k, v] of Object.entries(cfg.headers as Record<string, unknown>)) {
        if (v !== undefined && v !== null) headersMap[k] = String(v);
      }
    }
  }
  return callCoreWasm<{ out?: Record<string, unknown> }>('llm_redact_config', {
    config: {
      provider: cfg.provider,
      baseUrl: cfg.baseUrl,
      ...(typeof cfg.endpoint === 'string' ? { endpoint: cfg.endpoint } : {}),
      ...(hasHeaders ? { headers: headersMap, hasHeaders: true } : {}),
      ...(cfg.apiKey ? { apiKey: cfg.apiKey } : {}),
      model: cfg.model,
      isOfflineLocal: Boolean(cfg.isOfflineLocal),
    },
  }).out;
}

function normalizeRequestLlmForWire(raw: unknown): unknown {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return typeof raw === 'function' || typeof raw === 'symbol' ? 'invalid' : raw;
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (v === undefined) continue;
    out[k] = typeof v === 'function' || typeof v === 'symbol' ? null : v;
  }
  return out;
}

export function resolveLlmConfig(params: {
  env: LlmEnvBindings;
  requestLlm?: unknown;
  selfHost?: string;
}): { ok: true; config: ResolvedLlmConfig | null } | { ok: false; error: string; message: string } {
  const { env, requestLlm, selfHost } = params;
  const wasmRes = callCoreWasm<
    | {
        ok: true;
        config: {
          provider: LlmProvider;
          baseUrl: string;
          apiKey?: string;
          model: string;
          isOfflineLocal: boolean;
          useSafePublicFetch?: boolean;
        } | null;
      }
    | { ok: false; error: string; message: string }
  >('llm_resolve_config', {
    env: {
      EDGEFETCH_LLM_PROVIDER: env.EDGEFETCH_LLM_PROVIDER,
      EDGEFETCH_LLM_BASE_URL: env.EDGEFETCH_LLM_BASE_URL,
      EDGEFETCH_LLM_API_KEY: env.EDGEFETCH_LLM_API_KEY,
      EDGEFETCH_LLM_MODEL: env.EDGEFETCH_LLM_MODEL,
      EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE: env.EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE,
      OLLAMA_HOST: env.OLLAMA_HOST,
      OPENAI_API_KEY: env.OPENAI_API_KEY,
      OPENROUTER_API_KEY: env.OPENROUTER_API_KEY,
      ANTHROPIC_API_KEY: env.ANTHROPIC_API_KEY,
      GEMINI_API_KEY: env.GEMINI_API_KEY,
      hasWorkersAi: Boolean(env.AI),
    },
    ...(requestLlm !== undefined && requestLlm !== null ? { requestLlm: normalizeRequestLlmForWire(requestLlm) } : {}),
    ...(selfHost ? { selfHost } : {}),
  });

  if (!wasmRes.ok) {
    return { ok: false, error: wasmRes.error, message: wasmRes.message };
  }
  if (!wasmRes.config) {
    return { ok: true, config: null };
  }
  const resolvedSafeFetch = wasmRes.config.useSafePublicFetch ? (env.SAFE_PUBLIC_FETCH ?? env.SAFE_FETCH) : env.SAFE_FETCH;
  return {
    ok: true,
    config: {
      provider: wasmRes.config.provider,
      baseUrl: wasmRes.config.baseUrl,
      ...(wasmRes.config.apiKey ? { apiKey: wasmRes.config.apiKey } : {}),
      model: wasmRes.config.model,
      isOfflineLocal: wasmRes.config.isOfflineLocal,
      ...(resolvedSafeFetch ? { safeFetch: resolvedSafeFetch } : {}),
      ...(env.AI ? { workersAi: env.AI } : {}),
    },
  };
}

export function parseLooseJsonObject(raw: string): Record<string, unknown> | null {
  if (!raw) return null;
  return callCoreWasmRaw<{ object: Record<string, unknown> | null }>('llm_parse_loose_json', null, raw).object ?? null;
}

export async function completeLlmTurn(params: {
  config: ResolvedLlmConfig;
  messages: LlmMessage[];
  tools?: LlmToolDefinition[];
  jsonMode?: boolean;
  temperature?: number;
  maxTokens?: number;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
  tracer?: RequestTracer | TraceContext;
  traceAttributes?: SpanAttributes;
}): Promise<LlmChatCompletionResult> {
  const {
    config,
    messages,
    tools = [],
    jsonMode = false,
    temperature = 0.1,
    maxTokens = 2048,
    timeoutMs = 45_000,
  } = params;
  const fetchFn = params.fetchFn ?? config.safeFetch ?? fetch;
  const allowedToolNames = tools.map((t) => t.name);
  const activeTracer = getActiveRequestTracer(params.tracer);

  const reqSpec = callCoreWasm<{
    kind: 'http' | 'workers-ai';
    endpoint: string;
    headers?: Record<string, string>;
    body?: string;
    workersAiInput?: Record<string, unknown>;
  }>('llm_build_request', {
    config: {
      provider: config.provider,
      baseUrl: config.baseUrl,
      ...(config.apiKey ? { apiKey: config.apiKey } : {}),
      model: config.model,
      isOfflineLocal: Boolean(config.isOfflineLocal),
    },
    messages,
    tools,
    jsonMode,
    temperature,
    maxTokens,
  });

  const runTurn = async (span?: ActiveSpanHandle): Promise<LlmChatCompletionResult> => {
    if (config.provider === 'workers-ai' && config.workersAi) {
      span?.setAttribute('url.full', 'workers-ai://binding');
      try {
        const rawOut = await config.workersAi.run(config.model, reqSpec.workersAiInput ?? {});
        return callCoreWasm<LlmChatCompletionResult>('llm_parse_workers_ai', {
          rawOut: rawOut && typeof rawOut === 'object' && !Array.isArray(rawOut) ? rawOut : {},
          allowedToolNames,
        });
      } catch (err) {
        return { ok: false, content: '', toolCalls: [], error: err instanceof Error ? err.message : String(err) };
      }
    }

    span?.setAttribute('url.full', sanitizeUrlForSpan(reqSpec.endpoint));
    span?.setAttribute('http.request.method', 'POST');
    try {
      const res = await fetchFn(reqSpec.endpoint, {
        method: 'POST',
        headers: reqSpec.headers ?? { 'content-type': 'application/json' },
        body: reqSpec.body ?? '{}',
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
      span?.setAttribute('http.response.status_code', res.status);
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => undefined);
        return callCoreWasmRaw<LlmChatCompletionResult>(
          'llm_parse_response',
          { provider: config.provider, status: res.status, allowedToolNames },
          '',
        );
      }
      const rawText = await readResponseTextCapped(res);
      return callCoreWasmRaw<LlmChatCompletionResult>(
        'llm_parse_response',
        { provider: config.provider, status: res.status, allowedToolNames },
        rawText,
      );
    } catch (err) {
      return { ok: false, content: '', toolCalls: [], error: err instanceof Error ? err.message : String(err) };
    }
  };

  if (!activeTracer) {
    return runTurn();
  }
  return activeTracer.withSpan(
    'edgefetch.llm.turn',
    {
      kind: 3,
      attributes: {
        'gen_ai.system': config.provider,
        'gen_ai.request.model': config.model,
        'edgefetch.llm.is_offline_local': Boolean(config.isOfflineLocal),
        ...(params.traceAttributes ?? {}),
      },
    },
    async (span) => {
      const out = await runTurn(span);
      span.setAttribute('edgefetch.llm.tool_call_count', out.toolCalls.length);
      span.setAttribute('edgefetch.llm.has_text', Boolean(out.content));
      if (out.usage) {
        if (out.usage.promptTokens !== undefined) span.setAttribute('gen_ai.usage.input_tokens', out.usage.promptTokens);
        if (out.usage.completionTokens !== undefined) span.setAttribute('gen_ai.usage.output_tokens', out.usage.completionTokens);
        if (out.usage.totalTokens !== undefined) span.setAttribute('gen_ai.usage.total_tokens', out.usage.totalTokens);
      }
      if (!out.ok) {
        span.setStatus(false, sanitizeErrorMessageForSpan(out.error, 'llm_error'));
      }
      return out;
    },
  );
}

export function buildDeterministicSummary(markdown: string, title?: string): string {
  return callCoreWasmRaw<{ summary: string }>('llm_deterministic_summary', { title: title ?? '' }, markdown).summary;
}

export async function summarizeMarkdownWithOptionalLlm(params: {
  markdown: string;
  title?: string;
  llmConfig: ResolvedLlmConfig | null;
  fetchFn?: typeof fetch;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ summary: string; viaLlm: boolean }> {
  const { markdown, title, llmConfig, fetchFn, tracer } = params;
  if (llmConfig && markdown.trim().length > 0) {
    const { messages } = callCoreWasm<{ messages: LlmMessage[] }>('llm_build_prompts', {
      mode: 'summarize',
      markdown: markdown.slice(0, 16_000),
      title: title ?? '',
    });
    const res = await completeLlmTurn({
      config: llmConfig,
      messages,
      maxTokens: 380,
      temperature: 0.1,
      timeoutMs: 25_000,
      ...(fetchFn ? { fetchFn } : {}),
      ...(tracer ? { tracer } : {}),
    });
    if (res.ok && res.content.trim().length >= 20) {
      return { summary: res.content.trim(), viaLlm: true };
    }
  }
  return { summary: buildDeterministicSummary(markdown, title), viaLlm: false };
}

export async function extractJsonWithOptionalLlm(params: {
  markdown: string;
  title?: string;
  url: string;
  prompt?: string;
  schema?: Record<string, unknown>;
  heuristicFallback: Record<string, unknown>;
  llmConfig: ResolvedLlmConfig | null;
  fetchFn?: typeof fetch;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ data: Record<string, unknown>; viaLlm: boolean }> {
  const { markdown, title, url, prompt, schema, heuristicFallback, llmConfig, fetchFn, tracer } = params;
  if (!llmConfig || !markdown.trim()) {
    return { data: heuristicFallback, viaLlm: false };
  }
  const { messages } = callCoreWasm<{ messages: LlmMessage[] }>('llm_build_prompts', {
    mode: 'extract_json',
    markdown: markdown.slice(0, 24_000),
    title: title ?? '',
    url,
    prompt: prompt ?? '',
    ...(schema ? { schema } : {}),
  });
  const res = await completeLlmTurn({
    config: llmConfig,
    messages,
    jsonMode: true,
    maxTokens: 1_800,
    temperature: 0,
    timeoutMs: 30_000,
    ...(fetchFn ? { fetchFn } : {}),
    ...(tracer ? { tracer } : {}),
  });
  if (res.ok) {
    const parsed = parseLooseJsonObject(res.content);
    if (parsed && Object.keys(parsed).length > 0) {
      return { data: { ...heuristicFallback, ...parsed }, viaLlm: true };
    }
  }
  return { data: heuristicFallback, viaLlm: false };
}

export function validateDataAgainstJsonSchema(
  data: unknown,
  schema?: Record<string, unknown>,
): { valid: boolean; partialValid: boolean; errors: string[] } {
  const validSchema = schema && typeof schema === 'object' && !Array.isArray(schema) ? schema : undefined;
  if (!validSchema && data !== null && data !== undefined && typeof data !== 'object') {
    return { valid: true, partialValid: true, errors: [] };
  }
  return callCoreWasm<{ valid: boolean; partialValid: boolean; errors: string[] }>('llm_validate_schema', {
    hasData: data !== undefined,
    ...(data !== undefined ? { data } : {}),
    ...(validSchema ? { schema: validSchema } : {}),
  });
}
