/**
 * Federated "One MCP" Execution Engine & Domain-First Router (`hub/src/mcp-federation.ts`).
 *
 * Thin Cloudflare `safe-fetch` / concurrency / OAuth-refresh orchestrator delegating all untrusted envelope
 * construction, Markdown/HTML/link/prompt-injection scrubbing, bounded recursive JSON sanitization, JSON Schema
 * allowlist rebuilding, SSE JSON-RPC matching, and domain routing to Go WASM (`internal/mcpfed`).
 */

import { isJsonDepthWithinLimit, isSafePublicHttpsUrl } from './mcp-registry';
import {
  buildMaskedAuthSummary,
  filterSafeCachedMcpTools,
  isCachedMcpToolPermitted,
  isSafeMcpIdentifier,
  isValidMcpConnectorSlug,
  parseAllowedMcpTools,
  sealVaultCredentials,
  toPublicMcpServerSummary,
  unsealVaultCredentials,
  type CachedMcpToolSchema,
  type McpVaultStore,
  type PublicMcpServerSummary,
  type StoredMcpServerRow,
  type VaultSecretPayload,
} from './mcp-vault';
import { getActiveCallerAuthContext } from './oauth';
import { callCoreWasm, callCoreWasmRaw } from './wasm-bridge';

export const MAX_REMOTE_MCP_RESPONSE_BYTES = 4 * 1024 * 1024;
export const MAX_MCP_CONTENT_BLOCKS = 64;
export const MAX_MCP_BLOCK_TEXT_CHARS = 64 * 1024;
export const MAX_MCP_LINK_LABEL_CHARS = 512;
export const MAX_MCP_LINK_TARGET_CHARS = 2048;
export const MAX_MCP_TOOL_SCHEMA_BYTES = 16 * 1024;
export const REMOTE_MCP_TIMEOUT_MS = 25_000;
export const MAX_CONCURRENT_MCP_CALLS_PER_USER = 8;
export const MAX_STRUCTURED_SANITIZE_DEPTH = 12;
export const MAX_STRUCTURED_CONTAINER_ENTRIES = 256;
export const MAX_STRUCTURED_NODE_BUDGET = 2_048;
export const MAX_STRUCTURED_STRING_CHARS = 16 * 1024;
export const MAX_MCP_RPC_ERROR_DATA_BYTES = 4 * 1024;
export const MAX_MCP_RPC_ERROR_DATA_DEPTH = 4;
export const MAX_MCP_RPC_ERROR_DATA_ENTRIES = 16;
export const MAX_MCP_RPC_ERROR_DATA_NODES = 64;
export const MAX_MCP_RPC_ERROR_DATA_STRING_CHARS = 512;

const MAX_OAUTH_REFRESH_BYTES = 256 * 1024;
const OAUTH_REFRESH_TIMEOUT_MS = 15_000;
const DOWNSTREAM_PROTOCOL_VERSION = '2025-03-26';
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const activeFederatedCallsByUser = new Map<string, number>();

export function neutralizeUntrustedMcpBoundaryTags(input: string): string {
  if (!input || !/untrusted_/i.test(input)) return input;
  return callCoreWasm<{ out: string }>('mcp_fed_neutralize_boundary_tags', { input }).out;
}

export function formatFenceSafeUntrustedMcpEnvelope(params: {
  tag?: 'untrusted_mcp_output' | 'untrusted_mcp_tool_output';
  attributes?: Record<string, string | undefined>;
  content: string;
  maxChars?: number;
}): string {
  return callCoreWasm<{ out: string }>('mcp_fed_format_envelope', {
    tag: params.tag ?? 'untrusted_mcp_output',
    attributes: params.attributes ?? {},
    content: params.content ?? '',
    maxChars: typeof params.maxChars === 'number' && params.maxChars > 0 ? params.maxChars : 0,
  }).out;
}

export function sanitizeMcpMarkdownOutput(
  rawMarkdown: string,
  baseUrl?: string,
  maxChars = MAX_REMOTE_MCP_RESPONSE_BYTES,
): string {
  if (!rawMarkdown) return '';
  return callCoreWasmRaw<{ out: string }>(
    'mcp_fed_sanitize_markdown',
    { baseUrl: baseUrl ?? '', maxChars },
    rawMarkdown,
  ).out;
}

export interface SanitizedTextResult {
  text: string;
  detected: boolean;
  scrubbed: boolean;
  triggers: string[];
}

export function sanitizeRemoteMcpText(raw: string, maxChars = MAX_REMOTE_MCP_RESPONSE_BYTES): SanitizedTextResult {
  if (!raw) return { text: '', detected: false, scrubbed: false, triggers: [] };
  return callCoreWasmRaw<SanitizedTextResult>('mcp_fed_sanitize_remote_text', { maxChars }, raw);
}

/**
 * Early-aborting O(maxBytes) JSON serializer + Go WASM size estimator with cycle detection.
 */
export function measureJsonSizeCapped(rawValue: unknown, maxBytes: number): number {
  let acc = 0;
  const seen = new WeakSet<object>();
  const chunks: string[] = [];

  const emit = (node: unknown): void => {
    if (acc > maxBytes) return;
    if (node === null || node === undefined) {
      acc += 4;
      chunks.push('null');
      return;
    }
    const t = typeof node;
    if (t === 'boolean') {
      const s = (node as boolean) ? 'true' : 'false';
      acc += s.length;
      chunks.push(s);
      return;
    }
    if (t === 'number') {
      const s = Number.isFinite(node as number) ? String(node) : 'null';
      acc += String(node).length;
      chunks.push(s);
      return;
    }
    if (t === 'bigint') {
      const s = String(node);
      acc += s.length;
      chunks.push(JSON.stringify({ '\u0000ef_bigint': s }));
      return;
    }
    if (t === 'string') {
      acc += (node as string).length + 2;
      if (acc > maxBytes) return;
      chunks.push(JSON.stringify(node));
      return;
    }
    if (t !== 'object') {
      acc += 4;
      chunks.push('null');
      return;
    }
    const obj = node as object;
    if (seen.has(obj)) {
      acc = maxBytes + 1;
      return;
    }
    seen.add(obj);
    try {
      if (Array.isArray(obj)) {
        acc += 2;
        chunks.push('[');
        for (let i = 0; i < obj.length; i++) {
          if (i > 0) {
            acc += 1;
            chunks.push(',');
          }
          emit(obj[i]);
          if (acc > maxBytes) return;
        }
        chunks.push(']');
        return;
      }
      acc += 2;
      chunks.push('{');
      let first = true;
      for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        if (!first) {
          acc += 1;
          chunks.push(',');
        }
        first = false;
        acc += k.length + 3;
        if (acc > maxBytes) return;
        chunks.push(JSON.stringify(k), ':');
        emit(v);
        if (acc > maxBytes) return;
      }
      chunks.push('}');
    } finally {
      seen.delete(obj);
    }
  };

  emit(rawValue);
  if (acc > maxBytes) return acc;
  return callCoreWasmRaw<{ size: number }>('mcp_fed_measure_json_size', { maxBytes }, chunks.join('')).size;
}

export interface SanitizedConnectorTextResult {
  text: string;
  sanitized: boolean;
  fullySanitized: boolean;
  truncated: boolean;
  detected: boolean;
  scrubbed: boolean;
  triggers: string[];
}

export interface SanitizedConnectorStructuredResult {
  value: unknown;
  sanitized: boolean;
  fullySanitized: boolean;
  truncated: boolean;
  detected: boolean;
  scrubbed: boolean;
  triggers: string[];
}

export function sanitizeConnectorText(
  raw: string,
  maxChars = MAX_STRUCTURED_STRING_CHARS,
  baseUrl?: string,
  redactSecret?: VaultSecretPayload | null,
): SanitizedConnectorTextResult {
  if (typeof raw !== 'string') {
    return { text: '', sanitized: false, fullySanitized: false, truncated: false, detected: false, scrubbed: false, triggers: [] };
  }
  if (!raw) {
    return { text: '', sanitized: true, fullySanitized: true, truncated: false, detected: false, scrubbed: false, triggers: [] };
  }
  if (!Number.isFinite(maxChars) || maxChars <= 0) {
    return { text: '', sanitized: false, fullySanitized: false, truncated: true, detected: false, scrubbed: false, triggers: [] };
  }
  try {
    return callCoreWasmRaw<SanitizedConnectorTextResult>(
      'mcp_fed_sanitize_connector_text',
      {
        maxChars: Math.floor(maxChars),
        baseUrl: baseUrl ?? '',
        applyRedact: redactSecret !== undefined,
        redactSecret: redactSecret ?? null,
      },
      raw,
    );
  } catch {
    return {
      text: '[sanitization_failed]',
      sanitized: false,
      fullySanitized: false,
      truncated: true,
      detected: false,
      scrubbed: true,
      triggers: [],
    };
  }
}

function serializeWithSentinelsForWasm(rawValue: unknown): string {
  const replacer = (_k: string, v: unknown): unknown => {
    if (typeof v === 'function' || typeof v === 'symbol') return { '\u0000ef_nonjson': 1 };
    if (typeof v === 'bigint') return { '\u0000ef_bigint': String(v) };
    return v;
  };
  try {
    return JSON.stringify(rawValue, replacer) ?? 'null';
  } catch {
    const ancestors = new WeakSet<object>();
    const breakCycles = (node: unknown): unknown => {
      if (typeof node === 'function' || typeof node === 'symbol') return { '\u0000ef_nonjson': 1 };
      if (typeof node === 'bigint') return { '\u0000ef_bigint': String(node) };
      if (!node || typeof node !== 'object') return node;
      if (ancestors.has(node)) return { '\u0000ef_cycle': 1 };
      ancestors.add(node);
      try {
        if (Array.isArray(node)) return node.map(breakCycles);
        const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
        for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
          out[k] = breakCycles(v);
        }
        return out;
      } finally {
        ancestors.delete(node);
      }
    };
    return JSON.stringify(breakCycles(rawValue)) ?? 'null';
  }
}

export function sanitizeConnectorStructuredValue(
  rawValue: unknown,
  opts?: {
    baseUrl?: string;
    redactSecret?: VaultSecretPayload | null;
    maxDepth?: number;
    maxEntriesPerContainer?: number;
    maxNodeBudget?: number;
    maxStringChars?: number;
    maxTotalChars?: number;
  },
): SanitizedConnectorStructuredResult {
  if (rawValue === undefined) {
    return {
      value: undefined,
      sanitized: true,
      fullySanitized: true,
      truncated: false,
      detected: false,
      scrubbed: false,
      triggers: [],
    };
  }
  const serialized = serializeWithSentinelsForWasm(rawValue);
  return callCoreWasmRaw<SanitizedConnectorStructuredResult>(
    'mcp_fed_sanitize_structured',
    {
      baseUrl: opts?.baseUrl ?? '',
      applyRedact: opts?.redactSecret !== undefined,
      redactSecret: opts?.redactSecret ?? null,
      maxDepth: opts?.maxDepth ?? MAX_STRUCTURED_SANITIZE_DEPTH,
      maxEntriesPerContainer: opts?.maxEntriesPerContainer ?? MAX_STRUCTURED_CONTAINER_ENTRIES,
      maxNodeBudget: opts?.maxNodeBudget ?? MAX_STRUCTURED_NODE_BUDGET,
      maxStringChars: opts?.maxStringChars ?? MAX_STRUCTURED_STRING_CHARS,
      ...(opts?.maxTotalChars !== undefined ? { maxTotalChars: opts.maxTotalChars } : {}),
    },
    serialized,
  );
}

export function rebuildSafeMcpInputSchema(
  rawNode: unknown,
  depth = 0,
): { schema: Record<string, unknown>; scrubbed: boolean } {
  return callCoreWasm<{ schema: Record<string, unknown>; scrubbed: boolean }>('mcp_fed_rebuild_schema', {
    rawNode: rawNode && typeof rawNode === 'object' && !Array.isArray(rawNode) ? rawNode : null,
    depth,
  });
}

export function sanitizeRemoteMcpToolDefs(rawTools: unknown): {
  tools: CachedMcpToolSchema[];
  promptInjectionScrubbed: boolean;
  oversizedRejected?: boolean;
} {
  if (!Array.isArray(rawTools)) return { tools: [], promptInjectionScrubbed: false };
  let serialized: string;
  try {
    serialized = JSON.stringify(rawTools);
  } catch {
    return { tools: [], promptInjectionScrubbed: false, oversizedRejected: true };
  }
  if (serialized.length > MAX_MCP_TOOL_SCHEMA_BYTES) {
    return { tools: [], promptInjectionScrubbed: false, oversizedRejected: true };
  }
  return callCoreWasmRaw<{
    tools: CachedMcpToolSchema[];
    promptInjectionScrubbed: boolean;
    oversizedRejected?: boolean;
  }>('mcp_fed_sanitize_tool_defs', {}, serialized);
}

async function readBoundedBytes(
  resp: Response,
  maxBytes: number,
): Promise<{ ok: true; text: string; byteLength: number } | { ok: false; error: 'too_large' | 'read_error' }> {
  const cl = resp.headers.get('content-length');
  if (cl !== null && cl.trim() !== '') {
    const n = Number(cl);
    if (!Number.isFinite(n) || n < 0 || n > maxBytes) {
      await resp.body?.cancel().catch(() => undefined);
      return { ok: false, error: 'too_large' };
    }
  }
  if (!resp.body) return { ok: true, text: '', byteLength: 0 };
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel('downstream MCP response exceeded 4 MiB').catch(() => undefined);
          return { ok: false, error: 'too_large' };
        }
        chunks.push(value);
      }
    }
  } catch {
    await reader.cancel().catch(() => undefined);
    return { ok: false, error: 'read_error' };
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  return {
    ok: true,
    text: new TextDecoder('utf-8', { fatal: false }).decode(merged),
    byteLength: total,
  };
}

export function parseSseJsonRpcResponse(
  sseText: string,
  expectedId?: string | number,
): Record<string, unknown> | null {
  if (!sseText) return null;
  return callCoreWasmRaw<{ rpc: Record<string, unknown> | null }>(
    'mcp_fed_parse_sse_rpc',
    expectedId !== undefined ? { expectedId } : {},
    sseText,
  ).rpc;
}

async function refreshDownstreamOAuthIfNeeded(params: {
  server: StoredMcpServerRow;
  secret: VaultSecretPayload;
  forceRefresh?: boolean;
  vaultMasterKey: string | undefined;
  vaultStore: McpVaultStore;
  fetchFn: typeof fetch;
  selfHost?: string;
  now?: number;
  deadlineAt?: number;
}): Promise<{ ok: true; secret: VaultSecretPayload; refreshed: boolean } | { ok: false; error: string }> {
  const { server, secret, forceRefresh = false } = params;
  if (secret.kind !== 'oauth2' || !secret.oauth) {
    return { ok: true, secret, refreshed: false };
  }
  const now = params.now ?? Date.now();
  const isExpiringSoon = typeof secret.oauth.expiresAt === 'number' && secret.oauth.expiresAt <= now + 60_000;
  if (!forceRefresh && !isExpiringSoon) {
    return { ok: true, secret, refreshed: false };
  }
  if (!secret.oauth.refreshToken) {
    return forceRefresh
      ? { ok: false, error: 'Downstream OAuth access token expired and no refresh_token is available' }
      : { ok: true, secret, refreshed: false };
  }

  const epCheck = callCoreWasm<{ ok: boolean; normalizedUrl?: string; message?: string }>(
    'mcp_vault_oauth_validate_token_ep',
    {
      tokenEndpoint: secret.oauth.tokenEndpoint,
      expectedIssuer: secret.oauth.issuer ?? '',
      confirmedAuthOrigin: secret.oauth.confirmedAuthOrigin ?? '',
      remoteOrigin: server.remoteOrigin,
      selfHost: params.selfHost ?? '',
    },
  );
  if (!epCheck.ok || !epCheck.normalizedUrl) {
    return { ok: false, error: `Unsafe OAuth token_endpoint: ${epCheck.message ?? 'origin mismatch'}` };
  }

  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: secret.oauth.refreshToken,
    client_id: secret.oauth.clientId,
  });
  if (secret.oauth.clientSecret) form.set('client_secret', secret.oauth.clientSecret);
  if (secret.oauth.resource) form.set('resource', secret.oauth.resource);

  const remBudgetMs = params.deadlineAt !== undefined ? params.deadlineAt - Date.now() : OAUTH_REFRESH_TIMEOUT_MS;
  if (remBudgetMs <= 50) {
    return { ok: false, error: 'Downstream OAuth refresh timed out (exchange budget exhausted)' };
  }

  let resp: Response;
  const fetchFn = params.fetchFn;
  try {
    resp = await fetchFn(epCheck.normalizedUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: form.toString(),
      redirect: 'manual',
      signal: AbortSignal.timeout(Math.min(OAUTH_REFRESH_TIMEOUT_MS, Math.max(250, remBudgetMs))),
    });
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'OAuth token refresh network error' };
  }

  if (resp.status >= 300 && resp.status < 400) {
    await resp.body?.cancel().catch(() => undefined);
    return { ok: false, error: `Blocked redirect HTTP ${resp.status} during OAuth token refresh` };
  }

  const bodyRead = await readBoundedBytes(resp, MAX_OAUTH_REFRESH_BYTES);
  if (!bodyRead.ok || resp.status !== 200) {
    return { ok: false, error: `Downstream OAuth refresh failed (HTTP ${resp.status})` };
  }
  if (!isJsonDepthWithinLimit(bodyRead.text, 32)) {
    return { ok: false, error: 'Malformed JSON nesting from downstream OAuth token refresh' };
  }

  let parsedTokenJson: unknown;
  try {
    parsedTokenJson = JSON.parse(bodyRead.text);
  } catch {
    return { ok: false, error: 'Malformed JSON from downstream OAuth token refresh' };
  }
  if (!parsedTokenJson || typeof parsedTokenJson !== 'object' || Array.isArray(parsedTokenJson)) {
    return { ok: false, error: 'Malformed JSON object from downstream OAuth token refresh' };
  }
  const tokenJson = parsedTokenJson as Record<string, unknown>;

  const nextAccess = typeof tokenJson.access_token === 'string' ? tokenJson.access_token.trim() : '';
  if (!nextAccess || /[\x00-\x08\x0a-\x1f\x7f]/.test(nextAccess)) {
    return { ok: false, error: 'Downstream OAuth refresh response missing valid access_token' };
  }
  const nextRefresh =
    typeof tokenJson.refresh_token === 'string' &&
    tokenJson.refresh_token.trim() &&
    !/[\x00-\x08\x0a-\x1f\x7f]/.test(tokenJson.refresh_token)
      ? tokenJson.refresh_token.trim()
      : secret.oauth.refreshToken;
  const expiresIn = Number(tokenJson.expires_in);
  const nextExpiresAt =
    Number.isFinite(expiresIn) && expiresIn > 0 ? now + Math.floor(expiresIn * 1_000) : secret.oauth.expiresAt;

  const updatedSecret: VaultSecretPayload = {
    kind: 'oauth2',
    pinnedOrigin: server.remoteOrigin,
    pinnedUrl: server.remoteUrl,
    oauth: {
      ...secret.oauth,
      accessToken: nextAccess,
      ...(nextRefresh ? { refreshToken: nextRefresh } : {}),
      ...(nextExpiresAt ? { expiresAt: nextExpiresAt } : {}),
    },
  };

  const reSealed = await sealVaultCredentials({
    vaultMasterKey: params.vaultMasterKey,
    userId: server.userId,
    remoteOrigin: server.remoteOrigin,
    id: server.id,
    slug: server.slug,
    authType: server.authType,
    payload: updatedSecret,
  });
  if (reSealed.ok) {
    const latestServer = (await params.vaultStore.getServer(server.userId, server.id)) ?? server;
    await params.vaultStore.upsertServer({
      ...latestServer,
      encryptedCredentials: reSealed.ciphertext,
      secretVersion: reSealed.secretVersion,
      authSummary: buildMaskedAuthSummary(updatedSecret),
      updatedAt: now,
    });
  }

  return { ok: true, secret: updatedSecret, refreshed: true };
}

interface ExchangeBudgetState {
  deadlineAt: number;
  remainingBytes: number;
}

async function sendSingleRemoteJsonRpc(params: {
  remoteUrl: string;
  pinnedOrigin: string;
  secret: VaultSecretPayload | null;
  rpcBody: Record<string, unknown>;
  sessionId?: string;
  fetchFn: typeof fetch;
  selfHost?: string;
  timeoutMs?: number;
  budget?: ExchangeBudgetState;
  sanitizeCallOpts?: {
    allowSessionRetry: boolean;
    serverSlug: string;
    serverName: string;
    remoteOrigin: string;
    toolName: string;
    sanitizeBaseUrl: string;
    tokenRefreshed: boolean;
  };
}): Promise<
  | {
      ok: true;
      status: number;
      rpc: Record<string, unknown> | null;
      needsSessionInit?: boolean;
      sanitizedCall?: QueryMcpCallOutput;
      sessionId?: string;
    }
  | { ok: false; status: number; error: string; message: string; isUnauthorized?: boolean }
> {
  const baseTimeoutMs = Math.min(REMOTE_MCP_TIMEOUT_MS, Math.max(250, params.timeoutMs ?? REMOTE_MCP_TIMEOUT_MS));
  const deadlineAt = params.budget?.deadlineAt ?? Date.now() + baseTimeoutMs;
  let curUrl = params.remoteUrl;

  for (let hop = 0; hop <= 1; hop++) {
    const remainingMs = deadlineAt - Date.now();
    if (remainingMs <= 25) {
      return { ok: false, status: 504, error: 'remote_mcp_timeout', message: 'Remote MCP exchange timed out' };
    }
    const check = isSafePublicHttpsUrl(curUrl, params.selfHost);
    if (!check.ok) {
      return { ok: false, status: 400, error: 'unsafe_remote_mcp_url', message: check.reason };
    }
    if (check.origin !== params.pinnedOrigin.toLowerCase()) {
      return {
        ok: false,
        status: 502,
        error: 'remote_mcp_redirect_blocked',
        message: `Blocked cross-origin redirect from ${params.pinnedOrigin} to ${check.origin}`,
      };
    }

    const hdrsRes = callCoreWasm<{ ok: boolean; headers?: Record<string, string>; error?: string }>(
      'mcp_fed_build_outbound_headers',
      {
        secret: params.secret,
        targetOrigin: check.origin,
        sessionId: params.sessionId ?? '',
      },
    );
    if (!hdrsRes.ok || !hdrsRes.headers) {
      return { ok: false, status: 502, error: 'origin_pin_violation', message: hdrsRes.error ?? 'Origin pin violation' };
    }

    let resp: Response;
    const fetchFn = params.fetchFn;
    try {
      resp = await fetchFn(check.normalized, {
        method: 'POST',
        headers: new Headers(hdrsRes.headers),
        body: JSON.stringify(params.rpcBody),
        redirect: 'manual',
        signal: AbortSignal.timeout(Math.min(baseTimeoutMs, Math.max(50, remainingMs))),
      });
    } catch (err) {
      const rawMsg = err instanceof Error ? err.message : String(err);
      const isTimeout = /timeout|aborted/i.test(rawMsg);
      return {
        ok: false,
        status: isTimeout ? 504 : 502,
        error: isTimeout ? 'remote_mcp_timeout' : 'remote_mcp_unreachable',
        message: sanitizeConnectorText(rawMsg, 240, params.pinnedOrigin, params.secret).text || 'Remote MCP request failed',
      };
    }

    if (resp.status >= 300 && resp.status < 400) {
      const loc = resp.headers.get('location')?.trim();
      await resp.body?.cancel().catch(() => undefined);
      if (!loc || hop >= 1 || (resp.status !== 307 && resp.status !== 308)) {
        return {
          ok: false,
          status: 502,
          error: 'remote_mcp_redirect_blocked',
          message: `Blocked HTTP ${resp.status} redirect from remote MCP endpoint`,
        };
      }
      let nextUrl: URL;
      try {
        nextUrl = new URL(loc, check.url);
      } catch {
        return { ok: false, status: 502, error: 'remote_mcp_redirect_blocked', message: 'Invalid redirect Location header' };
      }
      const nextCheck = isSafePublicHttpsUrl(nextUrl.toString(), params.selfHost);
      if (!nextCheck.ok || nextCheck.origin !== params.pinnedOrigin.toLowerCase()) {
        return {
          ok: false,
          status: 502,
          error: 'remote_mcp_redirect_blocked',
          message: 'Blocked cross-origin or non-public redirect from remote MCP endpoint',
        };
      }
      curUrl = nextCheck.normalized;
      continue;
    }

    if (resp.status === 401) {
      await resp.body?.cancel().catch(() => undefined);
      return {
        ok: false,
        status: 401,
        error: 'remote_mcp_unauthorized',
        message: 'Remote MCP server rejected credentials (HTTP 401 Unauthorized)',
        isUnauthorized: true,
      };
    }

    const sessionHdr = resp.headers.get('mcp-session-id')?.trim() || params.sessionId;
    if (resp.status === 202 || resp.status === 204) {
      await resp.body?.cancel().catch(() => undefined);
      return { ok: true, status: resp.status, rpc: null, ...(sessionHdr ? { sessionId: sessionHdr } : {}) };
    }

    const maxBytesThisStep = params.budget ? Math.max(1, params.budget.remainingBytes) : MAX_REMOTE_MCP_RESPONSE_BYTES;
    const bodyRead = await readBoundedBytes(resp, maxBytesThisStep);
    if (!bodyRead.ok) {
      return {
        ok: false,
        status: 502,
        error: bodyRead.error === 'too_large' ? 'remote_mcp_response_too_large' : 'remote_mcp_read_error',
        message:
          bodyRead.error === 'too_large'
            ? 'Downstream MCP response exceeded 4 MiB exchange byte budget'
            : 'Failed reading downstream MCP response stream',
      };
    }
    if (params.budget) {
      params.budget.remainingBytes = Math.max(0, params.budget.remainingBytes - bodyRead.byteLength);
    }

    const expectedId = params.rpcBody.id as string | number | undefined;
    if (params.sanitizeCallOpts) {
      const combined = callCoreWasmRaw<{
        found: boolean;
        depthExceeded?: boolean;
        needsSessionInit?: boolean;
        status?: number;
        body?: Record<string, unknown>;
      }>(
        'mcp_fed_parse_and_sanitize_call_result',
        {
          contentType: resp.headers.get('content-type') ?? '',
          ...(expectedId !== undefined ? { expectedId } : {}),
          allowSessionRetry: params.sanitizeCallOpts.allowSessionRetry,
          serverSlug: params.sanitizeCallOpts.serverSlug,
          serverName: params.sanitizeCallOpts.serverName,
          remoteOrigin: params.sanitizeCallOpts.remoteOrigin,
          toolName: params.sanitizeCallOpts.toolName,
          sanitizeBaseUrl: params.sanitizeCallOpts.sanitizeBaseUrl,
          selfHost: params.selfHost ?? '',
          tokenRefreshed: params.sanitizeCallOpts.tokenRefreshed,
          activeSecret: params.secret ?? null,
        },
        bodyRead.text,
      );
      if (combined.depthExceeded) {
        return {
          ok: false,
          status: 502,
          error: 'remote_mcp_invalid_jsonrpc',
          message: 'Remote MCP JSON response exceeded maximum nesting depth',
        };
      }
      if (!resp.ok && !combined.found) {
        return {
          ok: false,
          status: 502,
          error: 'remote_mcp_http_error',
          message: `Remote MCP server returned HTTP ${resp.status}`,
        };
      }
      if (!combined.found) {
        return {
          ok: false,
          status: 502,
          error: 'remote_mcp_invalid_jsonrpc',
          message: 'Remote MCP server did not return a valid JSON-RPC 2.0 response matching request id',
        };
      }
      if (combined.needsSessionInit) {
        return {
          ok: true,
          status: resp.status,
          rpc: null,
          needsSessionInit: true,
          ...(sessionHdr ? { sessionId: sessionHdr } : {}),
        };
      }
      return {
        ok: true,
        status: resp.status,
        rpc: null,
        sanitizedCall: { status: combined.status ?? 200, body: combined.body ?? {} },
        ...(sessionHdr ? { sessionId: sessionHdr } : {}),
      };
    }

    const parsedRpc = callCoreWasmRaw<{
      found: boolean;
      depthExceeded: boolean;
      rpc?: Record<string, unknown>;
    }>(
      'mcp_fed_parse_remote_rpc',
      {
        contentType: resp.headers.get('content-type') ?? '',
        ...(expectedId !== undefined ? { expectedId } : {}),
      },
      bodyRead.text,
    );

    if (parsedRpc.depthExceeded) {
      return {
        ok: false,
        status: 502,
        error: 'remote_mcp_invalid_jsonrpc',
        message: 'Remote MCP JSON response exceeded maximum nesting depth',
      };
    }
    if (!resp.ok && !parsedRpc.found) {
      return {
        ok: false,
        status: 502,
        error: 'remote_mcp_http_error',
        message: `Remote MCP server returned HTTP ${resp.status}`,
      };
    }
    if (!parsedRpc.found || !parsedRpc.rpc) {
      return {
        ok: false,
        status: 502,
        error: 'remote_mcp_invalid_jsonrpc',
        message: 'Remote MCP server did not return a valid JSON-RPC 2.0 response matching request id',
      };
    }

    return {
      ok: true,
      status: resp.status,
      rpc: parsedRpc.rpc,
      ...(sessionHdr ? { sessionId: sessionHdr } : {}),
    };
  }

  return { ok: false, status: 502, error: 'remote_mcp_redirect_blocked', message: 'Redirect limit reached' };
}

export async function testAndListRemoteMcpTools(params: {
  remoteUrl: string;
  secret: VaultSecretPayload | null;
  fetchFn?: typeof fetch;
  selfHost?: string;
  timeoutMs?: number;
}): Promise<
  | {
      ok: true;
      tools: CachedMcpToolSchema[];
      serverInfo?: { name?: string; version?: string };
      promptInjectionScrubbed: boolean;
    }
  | {
      ok: false;
      status: number;
      error: string;
      message: string;
      isUnauthorized?: boolean;
    }
> {
  const urlCheck = isSafePublicHttpsUrl(params.remoteUrl, params.selfHost);
  if (!urlCheck.ok) {
    return { ok: false, status: 400, error: 'invalid_remote_url', message: urlCheck.reason };
  }
  const fetchFn = params.fetchFn ?? fetch;
  const totalTimeoutMs = Math.min(REMOTE_MCP_TIMEOUT_MS, Math.max(500, params.timeoutMs ?? REMOTE_MCP_TIMEOUT_MS));
  const exchangeBudget: ExchangeBudgetState = {
    deadlineAt: Date.now() + totalTimeoutMs,
    remainingBytes: MAX_REMOTE_MCP_RESPONSE_BYTES,
  };

  const initRes = await sendSingleRemoteJsonRpc({
    remoteUrl: urlCheck.normalized,
    pinnedOrigin: urlCheck.origin,
    secret: params.secret,
    rpcBody: {
      jsonrpc: '2.0',
      id: 'ef-init-1',
      method: 'initialize',
      params: {
        protocolVersion: DOWNSTREAM_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'edgefetch-hub', version: '2.8.13' },
      },
    },
    fetchFn,
    selfHost: params.selfHost,
    timeoutMs: totalTimeoutMs,
    budget: exchangeBudget,
  });

  if (!initRes.ok) return initRes;
  if (initRes.rpc?.error) {
    const initErrObj = initRes.rpc.error as { message?: unknown };
    return {
      ok: false,
      status: 502,
      error: 'remote_mcp_rpc_error',
      message: sanitizeConnectorText(String(initErrObj?.message ?? 'initialize failed'), 240, urlCheck.origin, params.secret).text,
    };
  }
  const sessionId = initRes.sessionId;
  const initResult =
    initRes.rpc?.result && typeof initRes.rpc.result === 'object' ? (initRes.rpc.result as Record<string, unknown>) : null;
  const rawSrvInfo =
    initResult?.serverInfo && typeof initResult.serverInfo === 'object'
      ? (initResult.serverInfo as Record<string, unknown>)
      : undefined;

  if (sessionId) {
    await sendSingleRemoteJsonRpc({
      remoteUrl: urlCheck.normalized,
      pinnedOrigin: urlCheck.origin,
      secret: params.secret,
      rpcBody: { jsonrpc: '2.0', method: 'notifications/initialized' },
      sessionId,
      fetchFn,
      selfHost: params.selfHost,
      timeoutMs: Math.min(5_000, totalTimeoutMs),
      budget: exchangeBudget,
    }).catch(() => undefined);
  }

  const listRes = await sendSingleRemoteJsonRpc({
    remoteUrl: urlCheck.normalized,
    pinnedOrigin: urlCheck.origin,
    secret: params.secret,
    rpcBody: { jsonrpc: '2.0', id: 'ef-tools-1', method: 'tools/list', params: {} },
    ...(sessionId ? { sessionId } : {}),
    fetchFn,
    selfHost: params.selfHost,
    timeoutMs: totalTimeoutMs,
    budget: exchangeBudget,
  });

  if (!listRes.ok) return listRes;
  if (listRes.rpc?.error) {
    const errObj = listRes.rpc.error as { message?: unknown };
    return {
      ok: false,
      status: 502,
      error: 'remote_mcp_rpc_error',
      message: sanitizeConnectorText(String(errObj?.message ?? 'tools/list failed'), 240, urlCheck.origin, params.secret).text,
    };
  }

  const resultObj =
    listRes.rpc?.result && typeof listRes.rpc.result === 'object' ? (listRes.rpc.result as Record<string, unknown>) : {};
  const { tools, promptInjectionScrubbed, oversizedRejected } = sanitizeRemoteMcpToolDefs(resultObj.tools);
  if (oversizedRejected) {
    return {
      ok: false,
      status: 502,
      error: 'remote_mcp_schema_too_large',
      message: `Downstream tools/list schema exceeded ${MAX_MCP_TOOL_SCHEMA_BYTES} byte maximum`,
    };
  }

  return {
    ok: true,
    tools,
    ...(rawSrvInfo
      ? {
          serverInfo: {
            ...(typeof rawSrvInfo.name === 'string'
              ? { name: sanitizeConnectorText(rawSrvInfo.name, 120, urlCheck.origin, params.secret).text }
              : {}),
            ...(typeof rawSrvInfo.version === 'string'
              ? { version: sanitizeConnectorText(rawSrvInfo.version, 48, urlCheck.origin, params.secret).text }
              : {}),
          },
        }
      : {}),
    promptInjectionScrubbed,
  };
}

export interface QueryMcpCallInput {
  action?: 'list_connected' | 'list_tools' | 'call_tool';
  server?: string;
  tool?: string;
  arguments?: Record<string, unknown>;
  refresh?: boolean;
  allowedMcpTools?: readonly string[];
}

export interface QueryMcpCallOutput {
  status: number;
  body: Record<string, unknown>;
}

export function extractMarkdownFromQueryMcpBody(body: Record<string, unknown>): string {
  if (!body || typeof body !== 'object') return '';
  return callCoreWasm<{ markdown: string }>('mcp_fed_extract_markdown', { body }).markdown;
}

async function resolveDecryptedServerSecret(params: {
  server: StoredMcpServerRow;
  vaultMasterKey: string | undefined;
  vaultStore?: McpVaultStore;
  now?: number;
}): Promise<{ ok: true; secret: VaultSecretPayload | null } | { ok: false; status: number; error: string; message: string }> {
  if (!params.server.encryptedCredentials || params.server.authType === 'none') {
    return { ok: true, secret: { kind: 'none', pinnedOrigin: params.server.remoteOrigin } };
  }
  const previousCiphertext = params.server.encryptedCredentials;
  const unsealed = await unsealVaultCredentials({
    vaultMasterKey: params.vaultMasterKey,
    userId: params.server.userId,
    remoteOrigin: params.server.remoteOrigin,
    remoteUrl: params.server.remoteUrl,
    id: params.server.id,
    slug: params.server.slug,
    authType: params.server.authType,
    secretVersion: params.server.secretVersion ?? 1,
    ciphertext: previousCiphertext,
  });
  if (!unsealed.ok) {
    return {
      ok: false,
      status: unsealed.error === 'vault_master_key_unconfigured' ? 503 : 500,
      error: unsealed.error,
      message: unsealed.message,
    };
  }
  if (unsealed.resealedCiphertext && params.vaultStore) {
    const rotatedAt = params.now ?? Date.now();
    const nextSecretVer = unsealed.resealedSecretVersion ?? 2;
    if (typeof params.vaultStore.resealServerSecret === 'function') {
      const resealedOk = await params.vaultStore.resealServerSecret({
        id: params.server.id,
        userId: params.server.userId,
        expectedEncryptedCredentials: previousCiphertext,
        encryptedCredentials: unsealed.resealedCiphertext,
        secretVersion: nextSecretVer,
        updatedAt: rotatedAt,
      });
      if (resealedOk) {
        params.server.encryptedCredentials = unsealed.resealedCiphertext;
        params.server.secretVersion = nextSecretVer;
        params.server.updatedAt = rotatedAt;
      }
    } else {
      const current = await params.vaultStore.getServer(params.server.userId, params.server.id);
      if (current && current.encryptedCredentials === previousCiphertext && (current.secretVersion ?? 1) <= nextSecretVer) {
        await params.vaultStore.upsertServer({
          ...current,
          encryptedCredentials: unsealed.resealedCiphertext,
          secretVersion: nextSecretVer,
          updatedAt: rotatedAt,
        });
        params.server.encryptedCredentials = unsealed.resealedCiphertext;
        params.server.secretVersion = nextSecretVer;
        params.server.updatedAt = rotatedAt;
      }
    }
  }
  return { ok: true, secret: unsealed.payload };
}

export async function executeFederatedMcpQuery(params: {
  userId: string;
  input: QueryMcpCallInput;
  allowedMcpTools?: ReadonlyArray<string> | ReadonlySet<string>;
  baseUrlOverride?: string;
  vaultStore: McpVaultStore;
  vaultMasterKey: string | undefined;
  fetchFn?: typeof fetch;
  selfHost?: string;
  timeoutMs?: number;
  now?: number;
}): Promise<QueryMcpCallOutput> {
  const action = params.input.action ?? 'list_connected';
  const fetchFn = params.fetchFn ?? fetch;
  const now = params.now ?? Date.now();
  const userKey = params.userId.trim() || 'owner';

  const parsedParamAllowed = parseAllowedMcpTools(params.allowedMcpTools);
  if (!parsedParamAllowed.ok) {
    return {
      status: 400,
      body: {
        ok: false,
        visibility: 'private',
        error: parsedParamAllowed.error,
        message: parsedParamAllowed.message,
        sanitized: true,
        fullySanitized: true,
      },
    };
  }
  const parsedInputAllowed = parseAllowedMcpTools(params.input.allowedMcpTools);
  if (!parsedInputAllowed.ok) {
    return {
      status: 400,
      body: {
        ok: false,
        visibility: 'private',
        error: parsedInputAllowed.error,
        message: parsedInputAllowed.message,
        sanitized: true,
        fullySanitized: true,
      },
    };
  }
  const effectiveAllowedTools = new Set<string>([...parsedParamAllowed.allowed, ...parsedInputAllowed.allowed]);

  if (action === 'list_connected') {
    const rows = await params.vaultStore.listServers(params.userId);
    const summaries: PublicMcpServerSummary[] = rows.map(toPublicMcpServerSummary);
    const rawServers = summaries.map((s) => ({
      slug: s.slug,
      name: s.name,
      remoteUrl: s.remoteUrl,
      transport: s.transport,
      authType: s.authType,
      authSummary: s.authSummary,
      domains: s.domains,
      autoRouteScrape: s.autoRouteScrape,
      toolCount: s.toolCount,
      enabled: s.enabled,
      lastVerifiedAt: s.lastVerifiedAt,
    }));
    const serversSan = sanitizeConnectorStructuredValue(rawServers);
    return {
      status: 200,
      body: {
        ok: true,
        action: 'list_connected',
        visibility: 'private',
        userId: params.userId,
        count: summaries.length,
        sanitized: serversSan.sanitized,
        fullySanitized: serversSan.fullySanitized,
        servers: serversSan.value,
      },
    };
  }

  const serverRef = typeof params.input.server === 'string' ? params.input.server.trim() : '';
  if (!serverRef) {
    return {
      status: 400,
      body: {
        ok: false,
        visibility: 'private',
        error: 'missing_server',
        message: 'server id or slug is required for list_tools and call_tool',
        sanitized: true,
        fullySanitized: true,
      },
    };
  }

  const serverRow = await params.vaultStore.getServer(params.userId, serverRef);
  const serverRefNorm = serverRef.toLowerCase();
  if (!serverRow || (serverRow.id.toLowerCase() !== serverRefNorm && serverRow.slug.toLowerCase() !== serverRefNorm)) {
    const refSan = sanitizeConnectorText(serverRef, 80);
    return {
      status: 404,
      body: {
        ok: false,
        visibility: 'private',
        error: 'mcp_server_not_connected',
        message: `No connected MCP server matching "${refSan.text}" found for current user`,
        sanitized: refSan.sanitized,
        fullySanitized: refSan.fullySanitized,
      },
    };
  }
  if (!isValidMcpConnectorSlug(serverRow.slug)) {
    return {
      status: 400,
      body: {
        ok: false,
        visibility: 'private',
        error: 'invalid_server_slug',
        message: 'Connected MCP server has an invalid slug ("__" and unsafe characters are forbidden)',
        sanitized: true,
        fullySanitized: true,
      },
    };
  }
  if (!serverRow.enabled) {
    return {
      status: 409,
      body: {
        ok: false,
        visibility: 'private',
        error: 'mcp_server_disabled',
        message: `Connected MCP server "${serverRow.slug}" is currently disabled`,
        sanitized: true,
        fullySanitized: true,
      },
    };
  }

  const urlCheck = isSafePublicHttpsUrl(serverRow.remoteUrl, params.selfHost);
  if (!urlCheck.ok || urlCheck.origin !== serverRow.remoteOrigin.toLowerCase()) {
    return {
      status: 400,
      body: {
        ok: false,
        visibility: 'private',
        error: 'unsafe_remote_mcp_url',
        message: urlCheck.ok ? 'Remote URL origin does not match pinned vault origin' : urlCheck.reason,
        sanitized: true,
        fullySanitized: true,
      },
    };
  }

  if (action === 'list_tools' && !params.input.refresh && serverRow.cachedTools.length > 0) {
    const safeCached = filterSafeCachedMcpTools(serverRow.cachedTools);
    const cachedSan = sanitizeConnectorStructuredValue(safeCached, { baseUrl: serverRow.remoteOrigin });
    return {
      status: 200,
      body: {
        ok: true,
        action: 'list_tools',
        visibility: 'private',
        cached: true,
        server: serverRow.slug,
        domains: serverRow.domains,
        count: safeCached.length,
        sanitized: cachedSan.sanitized,
        fullySanitized: cachedSan.fullySanitized,
        tools: cachedSan.value,
      },
    };
  }

  if (action !== 'list_tools' && action !== 'call_tool') {
    return {
      status: 400,
      body: {
        ok: false,
        visibility: 'private',
        error: 'invalid_action',
        message: 'action must be one of "list_connected", "list_tools", or "call_tool"',
      },
    };
  }

  const inFlightForUser = activeFederatedCallsByUser.get(userKey) ?? 0;
  if (inFlightForUser >= MAX_CONCURRENT_MCP_CALLS_PER_USER) {
    return {
      status: 429,
      body: {
        ok: false,
        visibility: 'private',
        error: 'too_many_concurrent_mcp_queries',
        message: `Too many concurrent federated MCP requests (${MAX_CONCURRENT_MCP_CALLS_PER_USER} max per user).`,
      },
    };
  }
  activeFederatedCallsByUser.set(userKey, inFlightForUser + 1);

  const totalExchangeTimeoutMs = Math.min(REMOTE_MCP_TIMEOUT_MS, Math.max(500, params.timeoutMs ?? REMOTE_MCP_TIMEOUT_MS));
  const exchangeBudget: ExchangeBudgetState = {
    deadlineAt: Date.now() + totalExchangeTimeoutMs,
    remainingBytes: MAX_REMOTE_MCP_RESPONSE_BYTES,
  };

  try {
    if (action === 'list_tools') {
      const dec = await resolveDecryptedServerSecret({
        server: serverRow,
        vaultMasterKey: params.vaultMasterKey,
        vaultStore: params.vaultStore,
        now,
      });
      if (!dec.ok) {
        return { status: dec.status, body: { ok: false, visibility: 'private', error: dec.error, message: dec.message } };
      }
      let activeSecret = dec.secret;
      if (activeSecret?.kind === 'oauth2') {
        const preRef = await refreshDownstreamOAuthIfNeeded({
          server: serverRow,
          secret: activeSecret,
          vaultMasterKey: params.vaultMasterKey,
          vaultStore: params.vaultStore,
          fetchFn,
          selfHost: params.selfHost,
          now,
          deadlineAt: exchangeBudget.deadlineAt,
        });
        if (preRef.ok) activeSecret = preRef.secret;
      }

      let listed = await testAndListRemoteMcpTools({
        remoteUrl: urlCheck.normalized,
        secret: activeSecret,
        fetchFn,
        selfHost: params.selfHost,
        timeoutMs: Math.max(250, exchangeBudget.deadlineAt - Date.now()),
      });
      if (!listed.ok && listed.isUnauthorized && activeSecret?.kind === 'oauth2' && activeSecret.oauth?.refreshToken) {
        const rotated = await refreshDownstreamOAuthIfNeeded({
          server: serverRow,
          secret: activeSecret,
          forceRefresh: true,
          vaultMasterKey: params.vaultMasterKey,
          vaultStore: params.vaultStore,
          fetchFn,
          selfHost: params.selfHost,
          now,
          deadlineAt: exchangeBudget.deadlineAt,
        });
        if (rotated.ok) {
          listed = await testAndListRemoteMcpTools({
            remoteUrl: urlCheck.normalized,
            secret: rotated.secret,
            fetchFn,
            selfHost: params.selfHost,
            timeoutMs: Math.max(250, exchangeBudget.deadlineAt - Date.now()),
          });
        }
      }

      if (!listed.ok) {
        const listErrSan = sanitizeConnectorText(listed.message, 240, serverRow.remoteOrigin, activeSecret);
        await params.vaultStore.upsertServer({ ...serverRow, lastError: listErrSan.text, updatedAt: now });
        return {
          status: listed.status,
          body: {
            ok: false,
            visibility: 'private',
            server: serverRow.slug,
            error: listed.error,
            message: listErrSan.text,
            sanitized: listErrSan.sanitized,
            fullySanitized: listErrSan.fullySanitized,
          },
        };
      }

      const latestRow = (await params.vaultStore.getServer(params.userId, serverRow.slug)) ?? serverRow;
      const liveToolsSan = sanitizeConnectorStructuredValue(listed.tools, {
        baseUrl: serverRow.remoteOrigin,
        redactSecret: activeSecret,
      });
      await params.vaultStore.upsertServer({
        ...latestRow,
        cachedTools: listed.tools,
        toolCount: listed.tools.length,
        lastVerifiedAt: now,
        lastError: null,
        updatedAt: now,
      });

      return {
        status: 200,
        body: {
          ok: true,
          action: 'list_tools',
          visibility: 'private',
          cached: false,
          server: serverRow.slug,
          domains: serverRow.domains,
          count: listed.tools.length,
          sanitized: liveToolsSan.sanitized,
          fullySanitized: liveToolsSan.fullySanitized,
          tools: liveToolsSan.value,
          ...(listed.promptInjectionScrubbed || liveToolsSan.detected ? { promptInjectionScrubbed: true } : {}),
        },
      };
    }

    const toolName = typeof params.input.tool === 'string' ? params.input.tool.trim() : '';
    if (!toolName || !isSafeMcpIdentifier(toolName) || FORBIDDEN_PROTO_KEYS.has(toolName)) {
      return {
        status: 400,
        body: {
          ok: false,
          visibility: 'private',
          error: 'missing_tool',
          message: 'Valid tool name (without "__") is required when action="call_tool"',
          sanitized: true,
          fullySanitized: true,
        },
      };
    }

    const safeCachedTools = filterSafeCachedMcpTools(serverRow.cachedTools);
    const cachedTool = safeCachedTools.find((t) => t.name === toolName);
    if (!cachedTool || !isCachedMcpToolPermitted(serverRow.slug, cachedTool, effectiveAllowedTools)) {
      return {
        status: 403,
        body: {
          ok: false,
          visibility: 'private',
          server: serverRow.slug,
          tool: toolName,
          error: 'mcp_tool_not_permitted',
          message: !cachedTool
            ? `Tool "${toolName}" is not in cached tools for connector "${serverRow.slug}". Run list_tools first.`
            : `Tool "${serverRow.slug}/${toolName}" requires readOnlyHint=true and destructiveHint!=true unless explicitly allow-listed via allowedMcpTools as "${serverRow.slug}/${toolName}".`,
          sanitized: true,
          fullySanitized: true,
        },
      };
    }

    const toolArgs =
      params.input.arguments && typeof params.input.arguments === 'object' && !Array.isArray(params.input.arguments)
        ? params.input.arguments
        : {};

    const dec = await resolveDecryptedServerSecret({
      server: serverRow,
      vaultMasterKey: params.vaultMasterKey,
      vaultStore: params.vaultStore,
      now,
    });
    if (!dec.ok) {
      return { status: dec.status, body: { ok: false, visibility: 'private', error: dec.error, message: dec.message } };
    }

    let activeSecret = dec.secret;
    let tokenRefreshed = false;
    if (activeSecret?.kind === 'oauth2') {
      const preRef = await refreshDownstreamOAuthIfNeeded({
        server: serverRow,
        secret: activeSecret,
        vaultMasterKey: params.vaultMasterKey,
        vaultStore: params.vaultStore,
        fetchFn,
        selfHost: params.selfHost,
        now,
        deadlineAt: exchangeBudget.deadlineAt,
      });
      if (!preRef.ok && typeof activeSecret.oauth?.expiresAt === 'number' && activeSecret.oauth.expiresAt <= now) {
        const refErrSan = sanitizeConnectorText(preRef.error, 240, serverRow.remoteOrigin, activeSecret);
        return {
          status: 502,
          body: {
            ok: false,
            visibility: 'private',
            server: serverRow.slug,
            error: 'oauth_refresh_failed',
            message: refErrSan.text,
            sanitized: refErrSan.sanitized,
            fullySanitized: refErrSan.fullySanitized,
          },
        };
      }
      if (preRef.ok) {
        activeSecret = preRef.secret;
        tokenRefreshed = preRef.refreshed;
      }
    }

    const sanitizeBaseUrl = params.baseUrlOverride ?? serverRow.remoteOrigin;
    const invokeToolsCall = async (secretToUse: VaultSecretPayload | null, refreshedFlag: boolean) => {
      const callBody = {
        jsonrpc: '2.0',
        id: `ef-call-${Date.now()}`,
        method: 'tools/call',
        params: { name: toolName, arguments: toolArgs },
      };
      const baseSanitizeOpts = {
        serverSlug: serverRow.slug,
        serverName: serverRow.name,
        remoteOrigin: serverRow.remoteOrigin,
        toolName,
        sanitizeBaseUrl,
        tokenRefreshed: refreshedFlag,
      };
      const direct = await sendSingleRemoteJsonRpc({
        remoteUrl: urlCheck.normalized,
        pinnedOrigin: urlCheck.origin,
        secret: secretToUse,
        rpcBody: callBody,
        fetchFn,
        selfHost: params.selfHost,
        timeoutMs: totalExchangeTimeoutMs,
        budget: exchangeBudget,
        sanitizeCallOpts: { ...baseSanitizeOpts, allowSessionRetry: true },
      });
      if (direct.ok && direct.needsSessionInit) {
        const initStep = await sendSingleRemoteJsonRpc({
          remoteUrl: urlCheck.normalized,
          pinnedOrigin: urlCheck.origin,
          secret: secretToUse,
          rpcBody: {
            jsonrpc: '2.0',
            id: 'ef-session-init',
            method: 'initialize',
            params: {
              protocolVersion: DOWNSTREAM_PROTOCOL_VERSION,
              capabilities: {},
              clientInfo: { name: 'edgefetch-hub', version: '2.8.13' },
            },
          },
          fetchFn,
          selfHost: params.selfHost,
          timeoutMs: totalExchangeTimeoutMs,
          budget: exchangeBudget,
        });
        if (initStep.ok && initStep.sessionId) {
          return await sendSingleRemoteJsonRpc({
            remoteUrl: urlCheck.normalized,
            pinnedOrigin: urlCheck.origin,
            secret: secretToUse,
            rpcBody: callBody,
            sessionId: initStep.sessionId,
            fetchFn,
            selfHost: params.selfHost,
            timeoutMs: totalExchangeTimeoutMs,
            budget: exchangeBudget,
            sanitizeCallOpts: { ...baseSanitizeOpts, allowSessionRetry: false },
          });
        }
      }
      return direct;
    };

    let callRes = await invokeToolsCall(activeSecret, tokenRefreshed);
    if (!callRes.ok && callRes.isUnauthorized && activeSecret?.kind === 'oauth2' && activeSecret.oauth?.refreshToken) {
      const rotated = await refreshDownstreamOAuthIfNeeded({
        server: serverRow,
        secret: activeSecret,
        forceRefresh: true,
        vaultMasterKey: params.vaultMasterKey,
        vaultStore: params.vaultStore,
        fetchFn,
        selfHost: params.selfHost,
        now,
        deadlineAt: exchangeBudget.deadlineAt,
      });
      if (rotated.ok) {
        activeSecret = rotated.secret;
        tokenRefreshed = true;
        callRes = await invokeToolsCall(activeSecret, tokenRefreshed);
      }
    }

    if (!callRes.ok) {
      const netErrSan = sanitizeConnectorText(callRes.message, 400, serverRow.remoteOrigin, activeSecret);
      return {
        status: callRes.status,
        body: {
          ok: false,
          visibility: 'private',
          server: serverRow.slug,
          tool: toolName,
          error: callRes.error,
          message: netErrSan.text,
          sanitized: netErrSan.sanitized,
          fullySanitized: netErrSan.fullySanitized,
        },
      };
    }

    if (callRes.sanitizedCall) {
      return callRes.sanitizedCall;
    }
    return callCoreWasmRaw<QueryMcpCallOutput>(
      'mcp_fed_sanitize_call_result',
      {
        serverSlug: serverRow.slug,
        serverName: serverRow.name,
        remoteOrigin: serverRow.remoteOrigin,
        toolName,
        sanitizeBaseUrl,
        selfHost: params.selfHost ?? '',
        tokenRefreshed,
        activeSecret: activeSecret ?? null,
      },
      JSON.stringify(callRes.rpc ?? {}),
    );
  } finally {
    const cur = activeFederatedCallsByUser.get(userKey) ?? 0;
    if (cur <= 1) activeFederatedCallsByUser.delete(userKey);
    else activeFederatedCallsByUser.set(userKey, cur - 1);
  }
}

export interface MatchedConnectedMcp {
  server: PublicMcpServerSummary;
  matchedDomains: string[];
  score: number;
}

export function matchConnectedMcpsForContext(params: {
  servers: readonly StoredMcpServerRow[];
  query?: string;
  urls?: readonly string[];
}): MatchedConnectedMcp[] {
  if (!params.servers || params.servers.length === 0) return [];
  return callCoreWasm<{ matches: MatchedConnectedMcp[] }>('mcp_fed_match_context', {
    servers: params.servers,
    query: params.query ?? '',
    urls: params.urls ?? [],
  }).matches;
}

export async function tryScrapeViaConnectedMcp(params: {
  userId: string;
  targetUrl: string;
  query?: string;
  preferMcp?: boolean;
  allowedServerIds?: ReadonlySet<string>;
  allowedMcpTools?: ReadonlyArray<string> | ReadonlySet<string>;
  requireExplicitReadOnlyHint?: boolean;
  vaultStore: McpVaultStore;
  vaultMasterKey: string | undefined;
  fetchFn?: typeof fetch;
  selfHost?: string;
}): Promise<{ status: number; via: string; body: Record<string, unknown> } | null> {
  const activeAuth = getActiveCallerAuthContext();
  if (activeAuth && activeAuth.principal.startsWith('oauth:') && !activeAuth.scopes.includes('mcp:call')) {
    return null;
  }

  const parsedAllowed = parseAllowedMcpTools(params.allowedMcpTools);
  if (!parsedAllowed.ok) {
    return null;
  }
  const allowedToolSet = parsedAllowed.allowed;

  const targetCheck = isSafePublicHttpsUrl(params.targetUrl, params.selfHost);
  if (!targetCheck.ok) {
    return null;
  }

  const allRows = await params.vaultStore.listServers(params.userId);
  if (allRows.length === 0) return null;

  const { plan } = callCoreWasm<{
    plan: {
      matched: boolean;
      normalizedTarget?: string;
      safeForwardUrl?: string;
      serverSlug?: string;
      toolName?: string;
      toolArguments?: Record<string, unknown>;
    };
  }>('mcp_fed_select_scrape_tool', {
    servers: allRows,
    targetUrl: targetCheck.normalized,
    query: params.query ?? '',
    preferMcp: params.preferMcp === true,
    hasAllowedServerIds: Boolean(params.allowedServerIds),
    allowedServerIds: params.allowedServerIds ? [...params.allowedServerIds] : [],
    allowedTools: [...allowedToolSet],
    requireExplicitReadOnlyHint: params.requireExplicitReadOnlyHint !== false,
    selfHost: params.selfHost ?? '',
  });

  if (!plan.matched || !plan.serverSlug || !plan.toolName || !plan.safeForwardUrl || !plan.normalizedTarget) {
    return null;
  }

  const out = await executeFederatedMcpQuery({
    userId: params.userId,
    input: {
      action: 'call_tool',
      server: plan.serverSlug,
      tool: plan.toolName,
      arguments: plan.toolArguments ?? {},
    },
    allowedMcpTools: allowedToolSet,
    baseUrlOverride: plan.safeForwardUrl,
    vaultStore: params.vaultStore,
    vaultMasterKey: params.vaultMasterKey,
    fetchFn: params.fetchFn,
    selfHost: params.selfHost,
  });

  if (out.status !== 200 || !out.body.ok) {
    return null;
  }
  const safeMarkdown = extractMarkdownFromQueryMcpBody(out.body);
  if (!safeMarkdown.trim()) {
    return null;
  }

  const prevPi = (out.body.promptInjection as { detected?: boolean; scrubbed?: boolean; triggers?: string[] } | undefined) ?? {};
  const wasSanitized = out.body.sanitized === true;
  const wasFullySanitized = Boolean(wasSanitized && out.body.fullySanitized !== false);

  return {
    status: 200,
    via: `mcp:${plan.serverSlug}`,
    body: {
      ok: true,
      cached: false,
      visibility: 'private',
      url: plan.normalizedTarget,
      finalUrl: plan.normalizedTarget,
      status: 200,
      via: `mcp:${plan.serverSlug}`,
      extractorId: `mcp:${plan.serverSlug}:${plan.toolName}`,
      markdown: safeMarkdown,
      sanitized: wasSanitized,
      fullySanitized: wasFullySanitized,
      promptInjection: {
        detected: Boolean(prevPi.detected),
        scrubbed: Boolean(prevPi.scrubbed),
        triggers: Array.isArray(prevPi.triggers) ? prevPi.triggers : [],
      },
      metadata: {
        title: `${plan.serverSlug} — ${plan.toolName}`,
        sourceMcpServer: plan.serverSlug,
        sourceMcpTool: plan.toolName,
        visibility: 'private',
      },
    },
  };
}
