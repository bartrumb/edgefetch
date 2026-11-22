/**
 * Federated "One MCP" Execution Engine & Domain-First Router (`hub/src/mcp-federation.ts`).
 *
 * Security Guardrails:
 *  1. SSRF & Origin Pinning: Every remote MCP endpoint URL passes `isSafePublicHttpsUrl` (`https://`, port 443,
 *     public DNS + dial-time `SAFE_PUBLIC_FETCH`, `redirect: 'manual'`). Decrypted `Authorization` and custom secret
 *     headers are strictly pinned to `(scheme, host, port)` (`secret.pinnedOrigin === remoteOrigin`); cross-origin
 *     redirects are hard-blocked before any credential leaves the origin.
 *  2. Untrusted Output Budgets & Prompt-Injection Scrubbing: Responses are capped at `<= 4 MiB` and `<= 25s`,
 *     parsed across both `application/json` and `text/event-stream` (Streamable HTTP SSE), stripped of invisible
 *     Unicode Tag (`U+E0000..U+E007F`) and Bidi control chars, and scrubbed via `detectPromptInjection`.
 *  3. Automatic OAuth 2.1 Refresh: Expired downstream OAuth tokens with a `refresh_token` are transparently rotated
 *     and re-sealed into `user_mcp_servers` with a fresh `AES-256-GCM` salt + IV.
 *  4. Private Cache Partitioning: Every federated result carries `visibility: 'private'` and is strictly isolated
 *     by `user_id` — NEVER written to shared R2/D1 caches.
 */

import { isSafePublicHttpsUrl, stripMcpSmugglingChars } from './mcp-registry';
import {
  buildMaskedAuthSummary,
  sealVaultCredentials,
  toPublicMcpServerSummary,
  unsealVaultCredentials,
  type CachedMcpToolSchema,
  type McpVaultStore,
  type PublicMcpServerSummary,
  type StoredMcpServerRow,
  type VaultSecretPayload,
} from './mcp-vault';
import { detectPromptInjection } from './scrape-advanced';

export const MAX_REMOTE_MCP_RESPONSE_BYTES = 4 * 1024 * 1024; // 4 MiB hard ceiling on downstream MCP responses
export const REMOTE_MCP_TIMEOUT_MS = 25_000; // 25s hard timeout on downstream MCP calls
const MAX_OAUTH_REFRESH_BYTES = 256 * 1024;
const OAUTH_REFRESH_TIMEOUT_MS = 15_000;
const DOWNSTREAM_PROTOCOL_VERSION = '2025-03-26';

export interface SanitizedTextResult {
  text: string;
  detected: boolean;
  scrubbed: boolean;
  triggers: string[];
}

/**
 * Strips invisible Unicode Tag / Bidi smuggling characters and scrubs indirect prompt-injection instructions
 * using `detectPromptInjection`, guaranteeing `detectPromptInjection(output.text).detected === false`.
 */
export function sanitizeRemoteMcpText(raw: string, maxChars = MAX_REMOTE_MCP_RESPONSE_BYTES): SanitizedTextResult {
  if (!raw) return { text: '', detected: false, scrubbed: false, triggers: [] };
  const boundedRaw = raw.length > maxChars ? raw.slice(0, maxChars) : raw;

  // 1. Scan BEFORE stripping Unicode Tags so `unicode_tag_ascii_smuggling` (`U+E0000..U+E007F`) is flagged!
  const preScan = detectPromptInjection({
    markdown: boundedRaw,
    ...(boundedRaw.includes('<') ? { rawHtml: boundedRaw } : {}),
  });

  const stripped = stripMcpSmugglingChars(boundedRaw);
  const postStripScan = detectPromptInjection({
    markdown: stripped,
    ...(stripped.includes('<') ? { rawHtml: stripped } : {}),
  });

  const allTriggers = [...new Set([...preScan.triggers, ...postStripScan.triggers])];
  if (!preScan.detected && !postStripScan.detected) {
    return { text: stripped, detected: false, scrubbed: false, triggers: [] };
  }

  // If ONLY `unicode_tag_ascii_smuggling` triggered and stripping neutralized it cleanly, verify `postStripScan.detected === false`
  if (!postStripScan.detected) {
    return { text: stripped, detected: true, scrubbed: true, triggers: allTriggers };
  }

  // Scrub offending lines while preserving benign surrounding structured data when possible
  const lines = stripped.split(/\r?\n/);
  const scrubbedLines = lines.map((line) => {
    if (!line.trim()) return line;
    const lineCheck = detectPromptInjection({
      markdown: line,
      ...(line.includes('<') ? { rawHtml: line } : {}),
    });
    if (lineCheck.detected || /<\s*[a-z][^>]*\bstyle\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)/i.test(line)) {
      return `[SCRUBBED: prompt injection blocked (${lineCheck.triggers.join(', ') || allTriggers.join(', ')})]`;
    }
    return line;
  });

  let candidate = scrubbedLines.join('\n');
  // Re-verify full block to defeat multi-line split prompt injections!
  const verifyScan = detectPromptInjection({
    markdown: candidate,
    ...(candidate.includes('<') ? { rawHtml: candidate } : {}),
  });
  if (verifyScan.detected) {
    const mergedTriggers = [...new Set([...allTriggers, ...verifyScan.triggers])];
    candidate = `[SCRUBBED: prompt injection blocked (${mergedTriggers.join(', ')})]`;
    return { text: candidate, detected: true, scrubbed: true, triggers: mergedTriggers };
  }

  return { text: candidate, detected: true, scrubbed: true, triggers: allTriggers };
}

export function sanitizeRemoteMcpToolDefs(rawTools: unknown): {
  tools: CachedMcpToolSchema[];
  promptInjectionScrubbed: boolean;
} {
  if (!Array.isArray(rawTools)) return { tools: [], promptInjectionScrubbed: false };
  const tools: CachedMcpToolSchema[] = [];
  let promptInjectionScrubbed = false;

  for (const item of rawTools.slice(0, 128)) {
    if (!item || typeof item !== 'object') continue;
    const t = item as Record<string, unknown>;
    const rawName = typeof t.name === 'string' ? stripMcpSmugglingChars(t.name).trim() : '';
    if (!rawName || !/^[A-Za-z0-9_.:-]{1,96}$/.test(rawName)) continue;

    const titleSan = typeof t.title === 'string' ? sanitizeRemoteMcpText(t.title, 160) : null;
    const descSan = typeof t.description === 'string' ? sanitizeRemoteMcpText(t.description, 800) : null;
    if (titleSan?.detected || descSan?.detected) promptInjectionScrubbed = true;

    const rawSchema =
      t.inputSchema && typeof t.inputSchema === 'object' && !Array.isArray(t.inputSchema)
        ? (t.inputSchema as Record<string, unknown>)
        : { type: 'object', properties: {} };
    const schemaStr = JSON.stringify(rawSchema);
    const schemaSan = sanitizeRemoteMcpText(schemaStr.slice(0, 16_384), 16_384);
    let safeSchema: Record<string, unknown> = { type: 'object', properties: {} };
    if (!schemaSan.detected) {
      safeSchema = rawSchema;
    } else {
      promptInjectionScrubbed = true;
    }

    const annotations =
      t.annotations && typeof t.annotations === 'object' ? (t.annotations as Record<string, unknown>) : null;
    const readOnlyHint =
      typeof annotations?.readOnlyHint === 'boolean' ? annotations.readOnlyHint : undefined;

    tools.push({
      name: rawName,
      ...(titleSan?.text ? { title: titleSan.text } : {}),
      ...(descSan?.text ? { description: descSan.text } : {}),
      inputSchema: safeSchema,
      ...(readOnlyHint !== undefined ? { readOnlyHint } : {}),
    });
  }

  return { tools, promptInjectionScrubbed };
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

/**
 * Parses a Streamable HTTP `text/event-stream` SSE payload and extracts the JSON-RPC 2.0 response matching `expectedId`.
 */
export function parseSseJsonRpcResponse(
  sseText: string,
  expectedId?: string | number,
): Record<string, unknown> | null {
  const normalized = sseText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const blocks = normalized.split('\n\n');
  let fallbackResponse: Record<string, unknown> | null = null;

  for (const block of blocks) {
    if (!block.trim()) continue;
    const dataLines: string[] = [];
    for (const line of block.split('\n')) {
      if (line.startsWith(':')) continue;
      if (line.startsWith('data:')) {
        const after = line.slice(5);
        dataLines.push(after.startsWith(' ') ? after.slice(1) : after);
      }
    }
    if (dataLines.length === 0) continue;
    const rawData = dataLines.join('\n').trim();
    if (!rawData || rawData === '[DONE]') continue;
    try {
      const parsed = JSON.parse(rawData);
      const candidates = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of candidates) {
        if (!item || typeof item !== 'object') continue;
        const msg = item as Record<string, unknown>;
        if ('result' in msg || 'error' in msg) {
          if (expectedId !== undefined && msg.id === expectedId) {
            return msg;
          }
          fallbackResponse = msg;
        }
      }
    } catch {
      // ignore non-JSON SSE events (e.g. endpoint discovery strings)
    }
  }

  return fallbackResponse;
}

function buildPinnedOutboundHeaders(
  secret: VaultSecretPayload | null,
  targetOrigin: string,
  sessionId?: string,
): { ok: true; headers: Headers } | { ok: false; error: string } {
  const headers = new Headers({
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'user-agent': 'EdgeFetch-MCP-Federation/2.7',
    'mcp-protocol-version': DOWNSTREAM_PROTOCOL_VERSION,
  });
  if (sessionId && /^[\x21-\x7e]{1,256}$/.test(sessionId)) {
    headers.set('mcp-session-id', sessionId);
  }
  if (!secret || secret.kind === 'none') {
    return { ok: true, headers };
  }
  // Strict origin pinning: NEVER attach decrypted credentials unless `(scheme, host, port)` matches `secret.pinnedOrigin`!
  if (secret.pinnedOrigin.toLowerCase() !== targetOrigin.toLowerCase()) {
    return { ok: false, error: 'Refusing to attach vault credentials: target origin does not match pinnedOrigin' };
  }
  if (secret.kind === 'oauth2' && secret.oauth?.accessToken) {
    headers.set('authorization', `Bearer ${secret.oauth.accessToken}`);
  } else if (secret.kind === 'headers' && secret.headers) {
    for (const [k, v] of Object.entries(secret.headers)) {
      if (!/[\r\n\0]/.test(k) && !/[\r\n\0]/.test(v)) {
        headers.set(k, v);
      }
    }
  }
  return { ok: true, headers };
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
}): Promise<{ ok: true; secret: VaultSecretPayload; refreshed: boolean } | { ok: false; error: string }> {
  const { server, secret, forceRefresh = false } = params;
  if (secret.kind !== 'oauth2' || !secret.oauth) {
    return { ok: true, secret, refreshed: false };
  }
  const now = params.now ?? Date.now();
  const isExpiringSoon =
    typeof secret.oauth.expiresAt === 'number' && secret.oauth.expiresAt <= now + 60_000;
  if (!forceRefresh && !isExpiringSoon) {
    return { ok: true, secret, refreshed: false };
  }
  if (!secret.oauth.refreshToken) {
    if (forceRefresh) {
      return { ok: false, error: 'Downstream OAuth access token expired and no refresh_token is available' };
    }
    return { ok: true, secret, refreshed: false };
  }

  const tokenEpCheck = isSafePublicHttpsUrl(secret.oauth.tokenEndpoint, params.selfHost);
  if (!tokenEpCheck.ok) {
    return { ok: false, error: `Unsafe OAuth token_endpoint: ${tokenEpCheck.reason}` };
  }

  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: secret.oauth.refreshToken,
    client_id: secret.oauth.clientId,
  });
  if (secret.oauth.clientSecret) {
    form.set('client_secret', secret.oauth.clientSecret);
  }

  let resp: Response;
  try {
    resp = await params.fetchFn(tokenEpCheck.normalized, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: form.toString(),
      redirect: 'manual',
      signal: AbortSignal.timeout(OAUTH_REFRESH_TIMEOUT_MS),
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

  let tokenJson: Record<string, unknown>;
  try {
    tokenJson = JSON.parse(bodyRead.text) as Record<string, unknown>;
  } catch {
    return { ok: false, error: 'Malformed JSON from downstream OAuth token refresh' };
  }

  const nextAccess = typeof tokenJson.access_token === 'string' ? tokenJson.access_token.trim() : '';
  if (!nextAccess || /[\r\n\0]/.test(nextAccess)) {
    return { ok: false, error: 'Downstream OAuth refresh response missing valid access_token' };
  }
  const nextRefresh =
    typeof tokenJson.refresh_token === 'string' && tokenJson.refresh_token.trim() && !/[\r\n\0]/.test(tokenJson.refresh_token)
      ? tokenJson.refresh_token.trim()
      : secret.oauth.refreshToken;
  const expiresIn = Number(tokenJson.expires_in);
  const nextExpiresAt =
    Number.isFinite(expiresIn) && expiresIn > 0 ? now + Math.floor(expiresIn * 1_000) : secret.oauth.expiresAt;

  const updatedSecret: VaultSecretPayload = {
    kind: 'oauth2',
    pinnedOrigin: server.remoteOrigin,
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
    payload: updatedSecret,
  });
  if (reSealed.ok) {
    await params.vaultStore.upsertServer({
      ...server,
      encryptedCredentials: reSealed.ciphertext,
      authSummary: buildMaskedAuthSummary(updatedSecret),
      updatedAt: now,
    });
  }

  return { ok: true, secret: updatedSecret, refreshed: true };
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
}): Promise<
  | { ok: true; status: number; rpc: Record<string, unknown> | null; sessionId?: string }
  | { ok: false; status: number; error: string; message: string; isUnauthorized?: boolean }
> {
  const timeoutMs = Math.min(REMOTE_MCP_TIMEOUT_MS, Math.max(1_000, params.timeoutMs ?? REMOTE_MCP_TIMEOUT_MS));
  let curUrl = params.remoteUrl;

  for (let hop = 0; hop <= 1; hop++) {
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

    const hdrsRes = buildPinnedOutboundHeaders(params.secret, check.origin, params.sessionId);
    if (!hdrsRes.ok) {
      return { ok: false, status: 502, error: 'origin_pin_violation', message: hdrsRes.error };
    }

    let resp: Response;
    try {
      resp = await params.fetchFn(check.normalized, {
        method: 'POST',
        headers: hdrsRes.headers,
        body: JSON.stringify(params.rpcBody),
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const isTimeout = /timeout|aborted/i.test(msg);
      return {
        ok: false,
        status: isTimeout ? 504 : 502,
        error: isTimeout ? 'remote_mcp_timeout' : 'remote_mcp_unreachable',
        message: sanitizeRemoteMcpText(msg, 240).text || 'Remote MCP request failed',
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

    const bodyRead = await readBoundedBytes(resp, MAX_REMOTE_MCP_RESPONSE_BYTES);
    if (!bodyRead.ok) {
      return {
        ok: false,
        status: 502,
        error: bodyRead.error === 'too_large' ? 'remote_mcp_response_too_large' : 'remote_mcp_read_error',
        message:
          bodyRead.error === 'too_large'
            ? 'Downstream MCP response exceeded 4 MiB byte budget'
            : 'Failed reading downstream MCP response stream',
      };
    }

    const ct = (resp.headers.get('content-type') ?? '').toLowerCase();
    const expectedId = params.rpcBody.id as string | number | undefined;
    let rpcObj: Record<string, unknown> | null = null;
    if (ct.includes('text/event-stream')) {
      rpcObj = parseSseJsonRpcResponse(bodyRead.text, expectedId);
    } else if (bodyRead.text.trim()) {
      try {
        const parsed = JSON.parse(bodyRead.text);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          rpcObj = parsed as Record<string, unknown>;
        } else if (Array.isArray(parsed) && parsed[0] && typeof parsed[0] === 'object') {
          rpcObj = parsed[0] as Record<string, unknown>;
        }
      } catch {
        // Fallback: try SSE parser if server omitted text/event-stream header
        rpcObj = parseSseJsonRpcResponse(bodyRead.text, expectedId);
      }
    }

    if (!resp.ok && !rpcObj) {
      return {
        ok: false,
        status: 502,
        error: 'remote_mcp_http_error',
        message: `Remote MCP server returned HTTP ${resp.status}`,
      };
    }
    if (!rpcObj) {
      return {
        ok: false,
        status: 502,
        error: 'remote_mcp_invalid_jsonrpc',
        message: 'Remote MCP server did not return a valid JSON-RPC 2.0 response',
      };
    }

    return {
      ok: true,
      status: resp.status,
      rpc: rpcObj,
      ...(sessionHdr ? { sessionId: sessionHdr } : {}),
    };
  }

  return { ok: false, status: 502, error: 'remote_mcp_redirect_blocked', message: 'Redirect limit reached' };
}

/**
 * Executes live `initialize` + `tools/list` against a remote MCP server (used by `/admin` "Test Connection" and `list_tools` refresh).
 */
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
        clientInfo: { name: 'edgefetch-hub', version: '2.7.0' },
      },
    },
    fetchFn,
    selfHost: params.selfHost,
    timeoutMs: params.timeoutMs,
  });

  if (!initRes.ok) return initRes;
  const sessionId = initRes.sessionId;
  const initResult =
    initRes.rpc?.result && typeof initRes.rpc.result === 'object'
      ? (initRes.rpc.result as Record<string, unknown>)
      : null;
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
      timeoutMs: 5_000,
    }).catch(() => undefined);
  }

  const listRes = await sendSingleRemoteJsonRpc({
    remoteUrl: urlCheck.normalized,
    pinnedOrigin: urlCheck.origin,
    secret: params.secret,
    rpcBody: {
      jsonrpc: '2.0',
      id: 'ef-tools-1',
      method: 'tools/list',
      params: {},
    },
    ...(sessionId ? { sessionId } : {}),
    fetchFn,
    selfHost: params.selfHost,
    timeoutMs: params.timeoutMs,
  });

  if (!listRes.ok) return listRes;
  if (listRes.rpc?.error) {
    const errObj = listRes.rpc.error as { message?: unknown };
    return {
      ok: false,
      status: 502,
      error: 'remote_mcp_rpc_error',
      message: sanitizeRemoteMcpText(String(errObj?.message ?? 'tools/list failed'), 240).text,
    };
  }

  const resultObj =
    listRes.rpc?.result && typeof listRes.rpc.result === 'object'
      ? (listRes.rpc.result as Record<string, unknown>)
      : {};
  const { tools, promptInjectionScrubbed } = sanitizeRemoteMcpToolDefs(resultObj.tools);

  return {
    ok: true,
    tools,
    ...(rawSrvInfo
      ? {
          serverInfo: {
            ...(typeof rawSrvInfo.name === 'string' ? { name: sanitizeRemoteMcpText(rawSrvInfo.name, 120).text } : {}),
            ...(typeof rawSrvInfo.version === 'string' ? { version: sanitizeRemoteMcpText(rawSrvInfo.version, 48).text } : {}),
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
}

export interface QueryMcpCallOutput {
  status: number;
  body: Record<string, unknown>;
}

async function resolveDecryptedServerSecret(params: {
  server: StoredMcpServerRow;
  vaultMasterKey: string | undefined;
}): Promise<{ ok: true; secret: VaultSecretPayload | null } | { ok: false; status: number; error: string; message: string }> {
  if (!params.server.encryptedCredentials || params.server.authType === 'none') {
    return { ok: true, secret: { kind: 'none', pinnedOrigin: params.server.remoteOrigin } };
  }
  const unsealed = await unsealVaultCredentials({
    vaultMasterKey: params.vaultMasterKey,
    userId: params.server.userId,
    remoteOrigin: params.server.remoteOrigin,
    ciphertext: params.server.encryptedCredentials,
  });
  if (!unsealed.ok) {
    return {
      ok: false,
      status: unsealed.error === 'vault_master_key_unconfigured' ? 503 : 500,
      error: unsealed.error,
      message: unsealed.message,
    };
  }
  return { ok: true, secret: unsealed.payload };
}

/**
 * Executes MCP `query_mcp` (`list_connected` | `list_tools` | `call_tool`) strictly isolated to `userId`.
 */
export async function executeFederatedMcpQuery(params: {
  userId: string;
  input: QueryMcpCallInput;
  vaultStore: McpVaultStore;
  vaultMasterKey: string | undefined;
  fetchFn?: typeof fetch;
  selfHost?: string;
  now?: number;
}): Promise<QueryMcpCallOutput> {
  const action = params.input.action ?? 'list_connected';
  const fetchFn = params.fetchFn ?? fetch;
  const now = params.now ?? Date.now();

  if (action === 'list_connected') {
    const rows = await params.vaultStore.listServers(params.userId);
    const summaries: PublicMcpServerSummary[] = rows.map(toPublicMcpServerSummary);
    return {
      status: 200,
      body: {
        ok: true,
        action: 'list_connected',
        visibility: 'private',
        userId: params.userId,
        count: summaries.length,
        servers: summaries.map((s) => ({
          slug: s.slug,
          name: s.name,
          remoteUrl: s.remoteUrl,
          transport: s.transport,
          authType: s.authType,
          authSummary: s.authSummary,
          domains: s.domains,
          toolCount: s.toolCount,
          enabled: s.enabled,
          lastVerifiedAt: s.lastVerifiedAt,
        })),
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
        message: 'server slug or domain is required for list_tools and call_tool',
      },
    };
  }

  const serverRow = await params.vaultStore.getServer(params.userId, serverRef);
  if (!serverRow) {
    return {
      status: 404,
      body: {
        ok: false,
        visibility: 'private',
        error: 'mcp_server_not_connected',
        message: `No connected MCP server matching "${serverRef}" found for current user`,
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
      },
    };
  }

  if (action === 'list_tools') {
    if (!params.input.refresh && serverRow.cachedTools.length > 0) {
      return {
        status: 200,
        body: {
          ok: true,
          action: 'list_tools',
          visibility: 'private',
          cached: true,
          server: serverRow.slug,
          domains: serverRow.domains,
          count: serverRow.cachedTools.length,
          tools: serverRow.cachedTools,
        },
      };
    }

    const dec = await resolveDecryptedServerSecret({ server: serverRow, vaultMasterKey: params.vaultMasterKey });
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
      });
      if (preRef.ok) activeSecret = preRef.secret;
    }

    let listed = await testAndListRemoteMcpTools({
      remoteUrl: urlCheck.normalized,
      secret: activeSecret,
      fetchFn,
      selfHost: params.selfHost,
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
      });
      if (rotated.ok) {
        listed = await testAndListRemoteMcpTools({
          remoteUrl: urlCheck.normalized,
          secret: rotated.secret,
          fetchFn,
          selfHost: params.selfHost,
        });
      }
    }

    if (!listed.ok) {
      await params.vaultStore.upsertServer({
        ...serverRow,
        lastError: listed.message.slice(0, 240),
        updatedAt: now,
      });
      return {
        status: listed.status,
        body: {
          ok: false,
          visibility: 'private',
          server: serverRow.slug,
          error: listed.error,
          message: listed.message,
        },
      };
    }

    const latestRow = (await params.vaultStore.getServer(params.userId, serverRow.slug)) ?? serverRow;
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
        tools: listed.tools,
        ...(listed.promptInjectionScrubbed ? { promptInjectionScrubbed: true } : {}),
      },
    };
  }

  if (action !== 'call_tool') {
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

  const toolName = typeof params.input.tool === 'string' ? params.input.tool.trim() : '';
  if (!toolName || !/^[A-Za-z0-9_.:-]{1,96}$/.test(toolName)) {
    return {
      status: 400,
      body: {
        ok: false,
        visibility: 'private',
        error: 'missing_tool',
        message: 'Valid tool name is required when action="call_tool"',
      },
    };
  }

  const toolArgs =
    params.input.arguments && typeof params.input.arguments === 'object' && !Array.isArray(params.input.arguments)
      ? params.input.arguments
      : {};

  const dec = await resolveDecryptedServerSecret({ server: serverRow, vaultMasterKey: params.vaultMasterKey });
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
    });
    if (!preRef.ok && typeof activeSecret.oauth?.expiresAt === 'number' && activeSecret.oauth.expiresAt <= now) {
      return {
        status: 502,
        body: { ok: false, visibility: 'private', server: serverRow.slug, error: 'oauth_refresh_failed', message: preRef.error },
      };
    }
    if (preRef.ok) {
      activeSecret = preRef.secret;
      tokenRefreshed = preRef.refreshed;
    }
  }

  const invokeToolsCall = async (secretToUse: VaultSecretPayload | null) => {
    const callBody = {
      jsonrpc: '2.0',
      id: `ef-call-${Date.now()}`,
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: toolArgs,
      },
    };
    const direct = await sendSingleRemoteJsonRpc({
      remoteUrl: urlCheck.normalized,
      pinnedOrigin: urlCheck.origin,
      secret: secretToUse,
      rpcBody: callBody,
      fetchFn,
      selfHost: params.selfHost,
    });
    if (
      direct.ok &&
      direct.rpc?.error &&
      /not\s+initialized|session/i.test(String((direct.rpc.error as { message?: unknown }).message ?? ''))
    ) {
      // Stateful Streamable HTTP fallback: run `initialize` first to acquire `Mcp-Session-Id`
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
            clientInfo: { name: 'edgefetch-hub', version: '2.7.0' },
          },
        },
        fetchFn,
        selfHost: params.selfHost,
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
        });
      }
    }
    return direct;
  };

  let callRes = await invokeToolsCall(activeSecret);
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
    });
    if (rotated.ok) {
      activeSecret = rotated.secret;
      tokenRefreshed = true;
      callRes = await invokeToolsCall(activeSecret);
    }
  }

  if (!callRes.ok) {
    return {
      status: callRes.status,
      body: {
        ok: false,
        visibility: 'private',
        server: serverRow.slug,
        tool: toolName,
        error: callRes.error,
        message: callRes.message,
      },
    };
  }

  if (callRes.rpc?.error) {
    const rpcErr = callRes.rpc.error as { code?: unknown; message?: unknown };
    return {
      status: 502,
      body: {
        ok: false,
        visibility: 'private',
        server: serverRow.slug,
        tool: toolName,
        error: 'remote_mcp_tool_error',
        code: typeof rpcErr.code === 'number' ? rpcErr.code : -32000,
        message: sanitizeRemoteMcpText(String(rpcErr.message ?? 'Remote MCP tool call returned an error'), 400).text,
      },
    };
  }

  const rawResult =
    callRes.rpc?.result && typeof callRes.rpc.result === 'object'
      ? (callRes.rpc.result as Record<string, unknown>)
      : {};
  const rawContent = Array.isArray(rawResult.content) ? rawResult.content : [];
  const sanitizedContent: Array<Record<string, unknown>> = [];
  const textParts: string[] = [];
  let anyDetected = false;
  let anyScrubbed = false;
  const triggerSet = new Set<string>();

  for (const item of rawContent.slice(0, 64)) {
    if (!item || typeof item !== 'object') continue;
    const block = item as Record<string, unknown>;
    const bType = typeof block.type === 'string' ? block.type : 'text';
    if (typeof block.text === 'string') {
      const san = sanitizeRemoteMcpText(block.text);
      if (san.detected) anyDetected = true;
      if (san.scrubbed) anyScrubbed = true;
      for (const tr of san.triggers) triggerSet.add(tr);
      sanitizedContent.push({ type: bType, text: san.text });
      textParts.push(san.text);
    } else if (block.resource && typeof block.resource === 'object') {
      const resObj = block.resource as Record<string, unknown>;
      const resText = typeof resObj.text === 'string' ? sanitizeRemoteMcpText(resObj.text) : null;
      if (resText) {
        if (resText.detected) anyDetected = true;
        if (resText.scrubbed) anyScrubbed = true;
        for (const tr of resText.triggers) triggerSet.add(tr);
        textParts.push(resText.text);
      }
      sanitizedContent.push({
        type: 'resource',
        resource: {
          ...(typeof resObj.uri === 'string' ? { uri: sanitizeRemoteMcpText(resObj.uri, 512).text } : {}),
          ...(typeof resObj.mimeType === 'string' ? { mimeType: sanitizeRemoteMcpText(resObj.mimeType, 120).text } : {}),
          ...(resText ? { text: resText.text } : {}),
        },
      });
    }
  }

  let sanitizedStructured: unknown;
  if (rawResult.structuredContent !== undefined) {
    const serialized = JSON.stringify(rawResult.structuredContent);
    const sanStruct = sanitizeRemoteMcpText(serialized);
    if (sanStruct.detected) {
      anyDetected = true;
      anyScrubbed = sanStruct.scrubbed;
      for (const tr of sanStruct.triggers) triggerSet.add(tr);
      sanitizedStructured = sanStruct.text;
    } else {
      try {
        sanitizedStructured = JSON.parse(sanStruct.text);
      } catch {
        sanitizedStructured = sanStruct.text;
      }
    }
    if (textParts.length === 0) {
      textParts.push(typeof sanitizedStructured === 'string' ? sanitizedStructured : JSON.stringify(sanitizedStructured, null, 2));
    }
  }

  const markdown = textParts.join('\n\n');
  const isRemoteError = Boolean(rawResult.isError);

  return {
    status: isRemoteError ? 502 : 200,
    body: {
      ok: !isRemoteError,
      action: 'call_tool',
      visibility: 'private',
      via: `mcp:${serverRow.slug}`,
      server: serverRow.slug,
      serverName: serverRow.name,
      remoteOrigin: serverRow.remoteOrigin,
      tool: toolName,
      isError: isRemoteError,
      ...(tokenRefreshed ? { tokenRefreshed: true } : {}),
      sanitized: true,
      promptInjection: {
        detected: anyDetected,
        scrubbed: anyScrubbed,
        triggers: [...triggerSet],
      },
      markdown,
      content: sanitizedContent,
      ...(sanitizedStructured !== undefined ? { structuredContent: sanitizedStructured } : {}),
    },
  };
}

export interface MatchedConnectedMcp {
  server: PublicMcpServerSummary;
  matchedDomains: string[];
  score: number;
}

/**
 * Ranks a user's enabled connected MCP servers against `/v1/agent` or `scrape` target URLs and query text.
 */
export function matchConnectedMcpsForContext(params: {
  servers: readonly StoredMcpServerRow[];
  query?: string;
  urls?: readonly string[];
}): MatchedConnectedMcp[] {
  const qLower = (params.query ?? '').toLowerCase();
  const urlHosts = new Set<string>();
  for (const rawU of params.urls ?? []) {
    try {
      const h = new URL(rawU).hostname.toLowerCase().replace(/^www\./, '');
      if (h) urlHosts.add(h);
    } catch {
      // ignore
    }
  }
  // Also extract inline `https://...` hostnames from natural-language query
  for (const m of qLower.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) {
    const h = m[1]!.toLowerCase().replace(/^www\./, '');
    if (h) urlHosts.add(h);
  }

  const out: MatchedConnectedMcp[] = [];
  for (const row of params.servers) {
    if (!row.enabled) continue;
    let score = 0;
    const matchedDomains: string[] = [];

    for (const dom of row.domains) {
      const cleanDom = dom.toLowerCase().replace(/^\*\./, '').replace(/^www\./, '');
      if (!cleanDom) continue;
      for (const uh of urlHosts) {
        if (uh === cleanDom || uh.endsWith(`.${cleanDom}`)) {
          score += 40;
          if (!matchedDomains.includes(cleanDom)) matchedDomains.push(cleanDom);
        }
      }
      if (qLower.includes(cleanDom)) {
        score += 25;
        if (!matchedDomains.includes(cleanDom)) matchedDomains.push(cleanDom);
      }
    }

    const slugClean = row.slug.toLowerCase();
    const nameClean = row.name.toLowerCase();
    if (slugClean.length >= 3 && qLower.includes(slugClean)) score += 20;
    else if (nameClean.length >= 3 && qLower.includes(nameClean)) score += 16;

    if (score > 0) {
      out.push({
        server: toPublicMcpServerSummary(row),
        matchedDomains,
        score,
      });
    }
  }

  out.sort((a, b) => b.score - a.score || a.server.slug.localeCompare(b.server.slug));
  return out;
}

/**
 * Selects a read-oriented URL tool on a matching connected MCP when `scrape` targets a domain with an active MCP connector.
 * Returns `null` when no URL-capable read tool exists so `scrape` falls back seamlessly to YAML twins -> Go scraping.
 */
export async function tryScrapeViaConnectedMcp(params: {
  userId: string;
  targetUrl: string;
  query?: string;
  vaultStore: McpVaultStore;
  vaultMasterKey: string | undefined;
  fetchFn?: typeof fetch;
  selfHost?: string;
}): Promise<{ status: number; via: string; body: Record<string, unknown> } | null> {
  const rows = await params.vaultStore.listServers(params.userId);
  if (rows.length === 0) return null;

  const matches = matchConnectedMcpsForContext({
    servers: rows,
    urls: [params.targetUrl],
  });
  const top = matches[0];
  if (!top || top.matchedDomains.length === 0) return null;

  // Look for a safe read-only / fetch / page / retrieve tool accepting `url` or `uri`
  const candidateTool = top.server.tools.find((t) => {
    if (t.readOnlyHint === false) return false;
    const isReadName = /^(?:get|fetch|read|retrieve|resolve|view|inspect|page|search)/i.test(t.name) || t.readOnlyHint === true;
    if (!isReadName) return false;
    const props =
      t.inputSchema?.properties && typeof t.inputSchema.properties === 'object'
        ? (t.inputSchema.properties as Record<string, unknown>)
        : {};
    return 'url' in props || 'uri' in props;
  });
  if (!candidateTool) return null;

  const props = (candidateTool.inputSchema.properties ?? {}) as Record<string, unknown>;
  const toolArgs: Record<string, unknown> = 'url' in props ? { url: params.targetUrl } : { uri: params.targetUrl };
  if (params.query && 'query' in props) {
    toolArgs.query = params.query;
  }

  const out = await executeFederatedMcpQuery({
    userId: params.userId,
    input: {
      action: 'call_tool',
      server: top.server.slug,
      tool: candidateTool.name,
      arguments: toolArgs,
    },
    vaultStore: params.vaultStore,
    vaultMasterKey: params.vaultMasterKey,
    fetchFn: params.fetchFn,
    selfHost: params.selfHost,
  });

  if (out.status !== 200 || !out.body.ok || typeof out.body.markdown !== 'string' || !out.body.markdown.trim()) {
    return null;
  }

  return {
    status: 200,
    via: `mcp:${top.server.slug}`,
    body: {
      ok: true,
      cached: false,
      visibility: 'private',
      url: params.targetUrl,
      finalUrl: params.targetUrl,
      status: 200,
      via: `mcp:${top.server.slug}`,
      extractorId: `mcp:${top.server.slug}:${candidateTool.name}`,
      markdown: out.body.markdown,
      sanitized: true,
      promptInjection: out.body.promptInjection,
      metadata: {
        title: `${top.server.name} — ${candidateTool.name}`,
        sourceMcpServer: top.server.slug,
        sourceMcpTool: candidateTool.name,
        visibility: 'private',
      },
    },
  };
}
