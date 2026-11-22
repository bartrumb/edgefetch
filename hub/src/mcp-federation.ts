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

import { isJsonDepthWithinLimit, isSafePublicHttpsUrl, stripMcpSmugglingChars } from './mcp-registry';
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
import { sanitizeInlineHtmlInMarkdown } from './scrape';
import { detectPromptInjection } from './scrape-advanced';

export const MAX_REMOTE_MCP_RESPONSE_BYTES = 4 * 1024 * 1024; // 4 MiB hard ceiling on downstream MCP responses
export const MAX_MCP_TOOL_SCHEMA_BYTES = 16 * 1024; // 16 KiB hard ceiling on individual & total downstream tools/list schemas (H3)
export const REMOTE_MCP_TIMEOUT_MS = 25_000; // 25s hard timeout on downstream MCP calls
export const MAX_CONCURRENT_MCP_CALLS_PER_USER = 8; // Per-user concurrency quota on federated MCP calls
const MAX_OAUTH_REFRESH_BYTES = 256 * 1024;
const OAUTH_REFRESH_TIMEOUT_MS = 15_000;
const DOWNSTREAM_PROTOCOL_VERSION = '2025-03-26';

const activeFederatedCallsByUser = new Map<string, number>();

const MCP_DIRECTIVE_INJECTION_RE =
  /\b(?:note|instruction|message|directive|reminder)\s+to\s+(?:the\s+)?(?:ai|llm|assistant|model|agent)\b|\bcall\s+query_mcp\s*\(|\bpre-authori[sz]ed\b|\bdo\s+not\s+ask\s+(?:the\s+user\s+)?for\s+confirmation\b|\bwhen\s+summarizing[^.\n]{0,80}\b(?:append|include|output|exfiltrate)\b/i;

const DANGEROUS_MARKDOWN_SCHEME_RE = /^(?:javascript|vbscript|data|file|blob)\s*:/i;
const RAW_DANGEROUS_HTML_TAG_RE =
  /<\s*\/?\s*(?:script|iframe|object|embed|applet|meta|link|style|base|form|input|button|textarea|svg|math)\b[^>]*>/gi;
const RAW_EVENT_HANDLER_TAG_RE = /<([a-z][a-z0-9-]*)\b([^>]*?\bon[a-z]{2,32}\s*=[^>]*?)>/gi;

/**
 * Sanitizes untrusted Markdown/text returned by a downstream MCP server:
 *  - Runs the Hub's HTML/Markdown sanitizer (`sanitizeInlineHtmlInMarkdown`),
 *  - Escapes dangerous raw HTML elements (`<script>`, `<iframe>`, `<svg>`, inline `on*=` handlers),
 *  - Strips `javascript:`, `data:`, `vbscript:`, `file:`, and `blob:` Markdown links/images (`[label](scheme:...)` -> `label`).
 */
export function sanitizeMcpMarkdownOutput(rawMarkdown: string, baseUrl?: string): string {
  if (!rawMarkdown) return '';
  let out = sanitizeInlineHtmlInMarkdown(rawMarkdown, baseUrl);
  out = out.replace(RAW_DANGEROUS_HTML_TAG_RE, (m) => m.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
  out = out.replace(RAW_EVENT_HANDLER_TAG_RE, (m) => m.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
  // Strip dangerous URI schemes from Markdown links `[text](url)` and images `![alt](url)`
  out = out.replace(/(!?\[([^\]]*)\])\(([^)\r\n]+)\)/g, (full, bracketPart: string, label: string, rawTarget: string) => {
    const cleanedTarget = rawTarget
      .trim()
      .replace(/^<|>$/g, '')
      .replace(/[\u0000-\u0020]+/g, '');
    if (DANGEROUS_MARKDOWN_SCHEME_RE.test(cleanedTarget)) {
      return label || '[blocked-unsafe-link]';
    }
    return full;
  });
  return out;
}

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
  const mcpDirectiveDetected = MCP_DIRECTIVE_INJECTION_RE.test(stripped);

  const allTriggers = [
    ...new Set([
      ...preScan.triggers,
      ...postStripScan.triggers,
      ...(mcpDirectiveDetected ? ['mcp_assistant_directive_smuggling'] : []),
    ]),
  ];
  if (!preScan.detected && !postStripScan.detected && !mcpDirectiveDetected) {
    return { text: stripped, detected: false, scrubbed: false, triggers: [] };
  }

  // If ONLY `unicode_tag_ascii_smuggling` triggered and stripping neutralized it cleanly, verify `postStripScan.detected === false`
  if (!postStripScan.detected && !mcpDirectiveDetected) {
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
    const lineDirective = MCP_DIRECTIVE_INJECTION_RE.test(line);
    if (
      lineCheck.detected ||
      lineDirective ||
      /<\s*[a-z][^>]*\bstyle\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)/i.test(line)
    ) {
      const reasons = [
        ...lineCheck.triggers,
        ...(lineDirective ? ['mcp_assistant_directive_smuggling'] : []),
      ];
      return `[SCRUBBED: prompt injection blocked (${reasons.join(', ') || allTriggers.join(', ')})]`;
    }
    return line;
  });

  let candidate = scrubbedLines.join('\n');
  // Re-verify full block to defeat multi-line split prompt injections!
  const verifyScan = detectPromptInjection({
    markdown: candidate,
    ...(candidate.includes('<') ? { rawHtml: candidate } : {}),
  });
  if (verifyScan.detected || MCP_DIRECTIVE_INJECTION_RE.test(candidate)) {
    const mergedTriggers = [...new Set([...allTriggers, ...verifyScan.triggers])];
    candidate = `[SCRUBBED: prompt injection blocked (${mergedTriggers.join(', ')})]`;
    return { text: candidate, detected: true, scrubbed: true, triggers: mergedTriggers };
  }

  return { text: candidate, detected: true, scrubbed: true, triggers: allTriggers };
}

const ALLOWED_JSON_SCHEMA_TYPES = new Set(['object', 'string', 'number', 'integer', 'boolean', 'array', 'null']);
const SAFE_SCHEMA_PROP_KEY_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).byteLength;
}

/**
 * Rebuilds a downstream MCP tool `inputSchema` using a strict recursive allow-list walker (H3):
 *  - Drops ALL unknown JSON Schema keywords (`$defs`, `$comment`, `examples`, `default` objects, `$ref`, arbitrary keys).
 *  - Bounds nesting depth (`<= 6`), property count (`<= 32`), enum count (`<= 32`), and identifier key syntax (`/^[A-Za-z0-9_.-]{1,64}$/`).
 *  - Scrubs/rejects any `description` (`<= 240` chars) that triggers `stripMcpSmugglingChars` or `detectPromptInjection`.
 */
export function rebuildSafeMcpInputSchema(
  rawNode: unknown,
  depth = 0,
): { schema: Record<string, unknown>; scrubbed: boolean } {
  if (!rawNode || typeof rawNode !== 'object' || Array.isArray(rawNode) || depth > 6) {
    return { schema: depth === 0 ? { type: 'object', properties: {} } : {}, scrubbed: false };
  }
  const src = rawNode as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  let scrubbed = false;

  const ALLOWED_SCHEMA_KEYWORDS = new Set([
    'type',
    'properties',
    'required',
    'description',
    'enum',
    'items',
    'minimum',
    'maximum',
    'minLength',
    'maxLength',
    'additionalProperties',
  ]);
  for (const k of Object.keys(src)) {
    if (k !== '$schema' && !ALLOWED_SCHEMA_KEYWORDS.has(k)) {
      // Unknown keyword (`$defs`, `$comment`, `examples`, `default`, etc.) dropped
      if (typeof src[k] === 'string' || typeof src[k] === 'object') {
        const sCheck = sanitizeRemoteMcpText(JSON.stringify(src[k]).slice(0, 4_096), 4_096);
        if (sCheck.detected) scrubbed = true;
      }
    }
  }

  if (typeof src.type === 'string' && ALLOWED_JSON_SCHEMA_TYPES.has(src.type)) {
    out.type = src.type;
  } else if (Array.isArray(src.type)) {
    const validTypes = src.type.filter((t): t is string => typeof t === 'string' && ALLOWED_JSON_SCHEMA_TYPES.has(t)).slice(0, 4);
    if (validTypes.length > 0) out.type = validTypes;
  } else if (depth === 0) {
    out.type = 'object';
  }

  if (typeof src.description === 'string') {
    const descClean = stripMcpSmugglingChars(src.description).replace(/\s+/g, ' ').trim().slice(0, 240);
    if (descClean) {
      const descCheck = sanitizeRemoteMcpText(descClean, 240);
      if (descCheck.detected) {
        scrubbed = true;
      } else {
        out.description = descCheck.text;
      }
    }
  }

  let validPropKeys: Set<string> | null = null;
  if (src.properties && typeof src.properties === 'object' && !Array.isArray(src.properties)) {
    const rebuiltProps: Record<string, unknown> = {};
    validPropKeys = new Set<string>();
    for (const [rawKey, rawVal] of Object.entries(src.properties as Record<string, unknown>).slice(0, 32)) {
      const cleanKey = stripMcpSmugglingChars(rawKey).trim();
      if (!SAFE_SCHEMA_PROP_KEY_RE.test(cleanKey) || FORBIDDEN_PROTO_KEYS.has(cleanKey)) {
        scrubbed = true;
        continue;
      }
      const keyInj = sanitizeRemoteMcpText(cleanKey, 64);
      if (keyInj.detected) {
        scrubbed = true;
        continue;
      }
      const child = rebuildSafeMcpInputSchema(rawVal, depth + 1);
      if (child.scrubbed) scrubbed = true;
      rebuiltProps[cleanKey] = child.schema;
      validPropKeys.add(cleanKey);
    }
    out.properties = rebuiltProps;
  } else if (out.type === 'object' && depth === 0) {
    out.properties = {};
  }

  if (Array.isArray(src.required)) {
    const reqOut: string[] = [];
    for (const r of src.required.slice(0, 32)) {
      if (typeof r === 'string' && SAFE_SCHEMA_PROP_KEY_RE.test(r) && (!validPropKeys || validPropKeys.has(r))) {
        if (!reqOut.includes(r)) reqOut.push(r);
      }
    }
    if (reqOut.length > 0) out.required = reqOut;
  }

  if (Array.isArray(src.enum)) {
    const enumOut: Array<string | number | boolean | null> = [];
    for (const ev of src.enum.slice(0, 32)) {
      if (typeof ev === 'string') {
        const cleanEv = stripMcpSmugglingChars(ev).slice(0, 120);
        const evCheck = sanitizeRemoteMcpText(cleanEv, 120);
        if (evCheck.detected) {
          scrubbed = true;
          continue;
        }
        enumOut.push(cleanEv);
      } else if (typeof ev === 'number' && Number.isFinite(ev)) {
        enumOut.push(ev);
      } else if (typeof ev === 'boolean' || ev === null) {
        enumOut.push(ev);
      }
    }
    if (enumOut.length > 0) out.enum = enumOut;
  }

  if (src.items && typeof src.items === 'object' && !Array.isArray(src.items)) {
    const itemChild = rebuildSafeMcpInputSchema(src.items, depth + 1);
    if (itemChild.scrubbed) scrubbed = true;
    out.items = itemChild.schema;
  }

  if (typeof src.minimum === 'number' && Number.isFinite(src.minimum)) out.minimum = src.minimum;
  if (typeof src.maximum === 'number' && Number.isFinite(src.maximum)) out.maximum = src.maximum;
  if (typeof src.minLength === 'number' && Number.isInteger(src.minLength) && src.minLength >= 0 && src.minLength <= 1_048_576) {
    out.minLength = src.minLength;
  }
  if (typeof src.maxLength === 'number' && Number.isInteger(src.maxLength) && src.maxLength >= 0 && src.maxLength <= 1_048_576) {
    out.maxLength = src.maxLength;
  }
  if (typeof src.additionalProperties === 'boolean') {
    out.additionalProperties = src.additionalProperties;
  }

  return { schema: out, scrubbed };
}

export function sanitizeRemoteMcpToolDefs(rawTools: unknown): {
  tools: CachedMcpToolSchema[];
  promptInjectionScrubbed: boolean;
  oversizedRejected?: boolean;
} {
  if (!Array.isArray(rawTools)) return { tools: [], promptInjectionScrubbed: false };

  // H3: Reject any downstream `tools/list` whose total serialized payload exceeds 16 KiB BEFORE truncating or storing!
  let totalRawBytes = 2;
  try {
    totalRawBytes = utf8ByteLength(JSON.stringify(rawTools));
  } catch {
    return { tools: [], promptInjectionScrubbed: false, oversizedRejected: true };
  }
  if (totalRawBytes > MAX_MCP_TOOL_SCHEMA_BYTES) {
    return { tools: [], promptInjectionScrubbed: false, oversizedRejected: true };
  }

  const tools: CachedMcpToolSchema[] = [];
  let promptInjectionScrubbed = false;

  for (const item of rawTools.slice(0, 64)) {
    if (!item || typeof item !== 'object') continue;
    const t = item as Record<string, unknown>;
    if (utf8ByteLength(JSON.stringify(t)) > MAX_MCP_TOOL_SCHEMA_BYTES) {
      return { tools: [], promptInjectionScrubbed: false, oversizedRejected: true };
    }
    const rawName = typeof t.name === 'string' ? stripMcpSmugglingChars(t.name).trim() : '';
    if (!rawName || !/^[A-Za-z0-9_.:-]{1,64}$/.test(rawName)) continue;

    const titleSan = typeof t.title === 'string' ? sanitizeRemoteMcpText(t.title, 120) : null;
    const descSan = typeof t.description === 'string' ? sanitizeRemoteMcpText(t.description, 240) : null;
    if (titleSan?.detected || descSan?.detected) promptInjectionScrubbed = true;

    const rebuilt = rebuildSafeMcpInputSchema(t.inputSchema, 0);
    if (rebuilt.scrubbed) promptInjectionScrubbed = true;

    const annotations =
      t.annotations && typeof t.annotations === 'object' ? (t.annotations as Record<string, unknown>) : null;
    const readOnlyHint =
      typeof annotations?.readOnlyHint === 'boolean'
        ? annotations.readOnlyHint
        : typeof t.readOnlyHint === 'boolean'
          ? t.readOnlyHint
          : undefined;
    const destructiveHint =
      typeof annotations?.destructiveHint === 'boolean'
        ? annotations.destructiveHint
        : typeof t.destructiveHint === 'boolean'
          ? t.destructiveHint
          : undefined;

    tools.push({
      name: rawName,
      ...(titleSan && !titleSan.detected && titleSan.text ? { title: titleSan.text } : {}),
      ...(descSan && !descSan.detected && descSan.text ? { description: descSan.text } : {}),
      inputSchema: rebuilt.schema,
      ...(readOnlyHint !== undefined ? { readOnlyHint } : {}),
      ...(destructiveHint !== undefined ? { destructiveHint } : {}),
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
    if (!isJsonDepthWithinLimit(rawData, 32)) continue;
    try {
      const parsed = JSON.parse(rawData);
      const candidates = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of candidates) {
        if (!item || typeof item !== 'object') continue;
        const msg = item as Record<string, unknown>;
        if ('result' in msg || 'error' in msg) {
          if (expectedId !== undefined) {
            if (msg.id === expectedId) return msg;
            continue;
          }
          fallbackResponse = msg;
        }
      }
    } catch {
      // ignore non-JSON SSE events (e.g. endpoint discovery strings)
    }
  }

  return expectedId !== undefined ? null : fallbackResponse;
}

function redactVaultSecretsFromText(raw: string, secret: VaultSecretPayload | null): string {
  if (!raw) return raw;
  let out = raw.replace(/\bBearer\s+[^\s"',;)]+/gi, 'Bearer [REDACTED]');
  if (!secret) return out;
  const sensitiveValues: string[] = [];
  if (secret.headers) {
    for (const v of Object.values(secret.headers)) {
      const trimmed = v.trim();
      if (trimmed.length >= 4) sensitiveValues.push(trimmed);
      const strippedBearer = trimmed.replace(/^Bearer\s+/i, '').trim();
      if (strippedBearer.length >= 4) sensitiveValues.push(strippedBearer);
    }
  }
  if (secret.oauth) {
    for (const tok of [secret.oauth.accessToken, secret.oauth.refreshToken, secret.oauth.clientSecret]) {
      if (typeof tok === 'string' && tok.trim().length >= 4) sensitiveValues.push(tok.trim());
    }
  }
  for (const val of sensitiveValues) {
    if (out.includes(val)) {
      out = out.split(val).join('[REDACTED]');
    }
  }
  return out;
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
  deadlineAt?: number;
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
  if (secret.oauth.issuer) {
    const issCheck = isSafePublicHttpsUrl(secret.oauth.issuer, params.selfHost);
    if (!issCheck.ok || tokenEpCheck.origin !== issCheck.origin) {
      return { ok: false, error: 'Unsafe OAuth token_endpoint: origin mismatch with recorded issuer' };
    }
  }

  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: secret.oauth.refreshToken,
    client_id: secret.oauth.clientId,
  });
  if (secret.oauth.clientSecret) {
    form.set('client_secret', secret.oauth.clientSecret);
  }
  if (secret.oauth.resource) {
    form.set('resource', secret.oauth.resource);
  }

  const remBudgetMs = params.deadlineAt !== undefined ? params.deadlineAt - Date.now() : OAUTH_REFRESH_TIMEOUT_MS;
  if (remBudgetMs <= 50) {
    return { ok: false, error: 'Downstream OAuth refresh timed out (exchange budget exhausted)' };
  }
  const effectiveRefreshTimeoutMs = Math.min(OAUTH_REFRESH_TIMEOUT_MS, Math.max(250, remBudgetMs));

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
      signal: AbortSignal.timeout(effectiveRefreshTimeoutMs),
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
    if (!isJsonDepthWithinLimit(bodyRead.text, 32)) {
      return { ok: false, error: 'Malformed JSON nesting from downstream OAuth token refresh' };
    }
    tokenJson = JSON.parse(bodyRead.text) as Record<string, unknown>;
  } catch {
    return { ok: false, error: 'Malformed JSON from downstream OAuth token refresh' };
  }

  const nextAccess = typeof tokenJson.access_token === 'string' ? tokenJson.access_token.trim() : '';
  if (!nextAccess || /[\x00-\x08\x0a-\x1f\x7f]/.test(nextAccess)) {
    return { ok: false, error: 'Downstream OAuth refresh response missing valid access_token' };
  }
  const nextRefresh =
    typeof tokenJson.refresh_token === 'string' && tokenJson.refresh_token.trim() && !/[\x00-\x08\x0a-\x1f\x7f]/.test(tokenJson.refresh_token)
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
}): Promise<
  | { ok: true; status: number; rpc: Record<string, unknown> | null; sessionId?: string }
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
        signal: AbortSignal.timeout(Math.min(baseTimeoutMs, Math.max(50, remainingMs))),
      });
    } catch (err) {
      const msg = redactVaultSecretsFromText(err instanceof Error ? err.message : String(err), params.secret);
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

    const ct = (resp.headers.get('content-type') ?? '').toLowerCase();
    const expectedId = params.rpcBody.id as string | number | undefined;
    let rpcObj: Record<string, unknown> | null = null;
    if (ct.includes('text/event-stream')) {
      rpcObj = parseSseJsonRpcResponse(bodyRead.text, expectedId);
    } else if (bodyRead.text.trim()) {
      const trimmedBody = bodyRead.text.trim();
      if (!isJsonDepthWithinLimit(trimmedBody, 32)) {
        return {
          ok: false,
          status: 502,
          error: 'remote_mcp_invalid_jsonrpc',
          message: 'Remote MCP JSON response exceeded maximum nesting depth',
        };
      }
      try {
        const parsed = JSON.parse(trimmedBody);
        const candidates = Array.isArray(parsed) ? parsed : [parsed];
        for (const cand of candidates) {
          if (!cand || typeof cand !== 'object' || Array.isArray(cand)) continue;
          const msg = cand as Record<string, unknown>;
          if (!('result' in msg) && !('error' in msg)) continue;
          if (expectedId !== undefined) {
            if (msg.id === expectedId) {
              rpcObj = msg;
              break;
            }
          } else {
            rpcObj = msg;
            break;
          }
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
        message: 'Remote MCP server did not return a valid JSON-RPC 2.0 response matching request id',
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
        clientInfo: { name: 'edgefetch-hub', version: '2.7.2' },
      },
    },
    fetchFn,
    selfHost: params.selfHost,
    timeoutMs: totalTimeoutMs,
    budget: exchangeBudget,
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
      timeoutMs: Math.min(5_000, totalTimeoutMs),
      budget: exchangeBudget,
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
    timeoutMs: totalTimeoutMs,
    budget: exchangeBudget,
  });

  if (!listRes.ok) return listRes;
  if (listRes.rpc?.error) {
    const errObj = listRes.rpc.error as { message?: unknown };
    const redactedErr = redactVaultSecretsFromText(String(errObj?.message ?? 'tools/list failed'), params.secret);
    return {
      ok: false,
      status: 502,
      error: 'remote_mcp_rpc_error',
      message: sanitizeRemoteMcpText(redactedErr, 240).text,
    };
  }

  const resultObj =
    listRes.rpc?.result && typeof listRes.rpc.result === 'object'
      ? (listRes.rpc.result as Record<string, unknown>)
      : {};
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
    remoteUrl: params.server.remoteUrl,
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
  timeoutMs?: number;
  now?: number;
}): Promise<QueryMcpCallOutput> {
  const action = params.input.action ?? 'list_connected';
  const fetchFn = params.fetchFn ?? fetch;
  const now = params.now ?? Date.now();
  const userKey = params.userId.trim() || 'owner';

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
          autoRouteScrape: s.autoRouteScrape,
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

  if (action === 'list_tools' && !params.input.refresh && serverRow.cachedTools.length > 0) {
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

  // Enforce per-user concurrent federated MCP call quota (`8`) so slow/hanging remotes cannot exhaust Worker sockets!
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
          deadlineAt: exchangeBudget.deadlineAt,
        });
        if (preRef.ok) activeSecret = preRef.secret;
      }

      const remMs1 = Math.max(250, exchangeBudget.deadlineAt - Date.now());
      let listed = await testAndListRemoteMcpTools({
        remoteUrl: urlCheck.normalized,
        secret: activeSecret,
        fetchFn,
        selfHost: params.selfHost,
        timeoutMs: remMs1,
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
          const remMs2 = Math.max(250, exchangeBudget.deadlineAt - Date.now());
          listed = await testAndListRemoteMcpTools({
            remoteUrl: urlCheck.normalized,
            secret: rotated.secret,
            fetchFn,
            selfHost: params.selfHost,
            timeoutMs: remMs2,
          });
        }
      }

      if (!listed.ok) {
        const safeLastErr = redactVaultSecretsFromText(listed.message, activeSecret).slice(0, 240);
        await params.vaultStore.upsertServer({
          ...serverRow,
          lastError: safeLastErr,
          updatedAt: now,
        });
        return {
          status: listed.status,
          body: {
            ok: false,
            visibility: 'private',
            server: serverRow.slug,
            error: listed.error,
            message: safeLastErr,
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

    const toolName = typeof params.input.tool === 'string' ? params.input.tool.trim() : '';
    if (!toolName || !/^[A-Za-z0-9_.:-]{1,64}$/.test(toolName)) {
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
        deadlineAt: exchangeBudget.deadlineAt,
      });
      if (!preRef.ok && typeof activeSecret.oauth?.expiresAt === 'number' && activeSecret.oauth.expiresAt <= now) {
        return {
          status: 502,
          body: {
            ok: false,
            visibility: 'private',
            server: serverRow.slug,
            error: 'oauth_refresh_failed',
            message: redactVaultSecretsFromText(preRef.error, activeSecret),
          },
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
        timeoutMs: totalExchangeTimeoutMs,
        budget: exchangeBudget,
      });
      if (
        direct.ok &&
        direct.rpc?.error &&
        /not\s+initialized|session/i.test(String((direct.rpc.error as { message?: unknown }).message ?? ''))
      ) {
        // Stateful Streamable HTTP fallback: run `initialize` first to acquire `Mcp-Session-Id` within the SAME exchange budget!
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
              clientInfo: { name: 'edgefetch-hub', version: '2.7.2' },
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
        deadlineAt: exchangeBudget.deadlineAt,
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
          message: redactVaultSecretsFromText(callRes.message, activeSecret),
        },
      };
    }

    if (callRes.rpc?.error) {
      const rpcErr = callRes.rpc.error as { code?: unknown; message?: unknown };
      const redactedRpcMsg = redactVaultSecretsFromText(
        String(rpcErr.message ?? 'Remote MCP tool call returned an error'),
        activeSecret,
      );
      return {
        status: 502,
        body: {
          ok: false,
          visibility: 'private',
          server: serverRow.slug,
          tool: toolName,
          error: 'remote_mcp_tool_error',
          code: typeof rpcErr.code === 'number' ? rpcErr.code : -32000,
          message: sanitizeRemoteMcpText(redactedRpcMsg, 400).text,
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

    // Strict allowlist on `content[].type` (`'text'` and `'resource'` text only — drops executable/binary/unknown types)!
    for (const item of rawContent.slice(0, 64)) {
      if (!item || typeof item !== 'object') continue;
      const block = item as Record<string, unknown>;
      const bType = typeof block.type === 'string' ? block.type.trim().toLowerCase() : '';
      if (bType === 'text' && typeof block.text === 'string') {
        const san = sanitizeRemoteMcpText(block.text);
        if (san.detected) anyDetected = true;
        if (san.scrubbed) anyScrubbed = true;
        for (const tr of san.triggers) triggerSet.add(tr);
        const safeText = sanitizeMcpMarkdownOutput(san.text, serverRow.remoteOrigin);
        sanitizedContent.push({ type: 'text', text: safeText });
        textParts.push(safeText);
      } else if (bType === 'resource' && block.resource && typeof block.resource === 'object') {
        const resObj = block.resource as Record<string, unknown>;
        if (typeof resObj.text !== 'string') {
          // Drop binary `blob` resources and empty non-text resource envelopes!
          continue;
        }
        const resText = sanitizeRemoteMcpText(resObj.text);
        if (resText.detected) anyDetected = true;
        if (resText.scrubbed) anyScrubbed = true;
        for (const tr of resText.triggers) triggerSet.add(tr);
        const safeResText = sanitizeMcpMarkdownOutput(resText.text, serverRow.remoteOrigin);
        textParts.push(safeResText);

        let safeResourceUri: string | undefined;
        if (typeof resObj.uri === 'string') {
          const uriCheck = isSafePublicHttpsUrl(resObj.uri, params.selfHost);
          if (uriCheck.ok) safeResourceUri = uriCheck.normalized;
        }
        const rawMime = typeof resObj.mimeType === 'string' ? resObj.mimeType.trim().toLowerCase() : '';
        const safeMime =
          /^(?:text\/(?:plain|markdown|csv|xml)|application\/(?:json|ld\+json))(?:\s*;.*)?$/.test(rawMime)
            ? rawMime.slice(0, 80)
            : undefined;
        sanitizedContent.push({
          type: 'resource',
          resource: {
            ...(safeResourceUri ? { uri: safeResourceUri } : {}),
            ...(safeMime ? { mimeType: safeMime } : {}),
            text: safeResText,
          },
        });
      }
    }

    let sanitizedStructured: unknown;
    if (rawResult.structuredContent !== undefined) {
      const serialized = JSON.stringify(rawResult.structuredContent);
      if (isJsonDepthWithinLimit(serialized, 32)) {
        const sanStruct = sanitizeRemoteMcpText(serialized);
        if (sanStruct.detected) {
          anyDetected = true;
          anyScrubbed = sanStruct.scrubbed;
          for (const tr of sanStruct.triggers) triggerSet.add(tr);
          sanitizedStructured = sanitizeMcpMarkdownOutput(sanStruct.text, serverRow.remoteOrigin);
        } else {
          try {
            sanitizedStructured = JSON.parse(sanStruct.text);
          } catch {
            sanitizedStructured = sanitizeMcpMarkdownOutput(sanStruct.text, serverRow.remoteOrigin);
          }
        }
        if (textParts.length === 0) {
          const fallbackStr =
            typeof sanitizedStructured === 'string'
              ? sanitizedStructured
              : sanitizeMcpMarkdownOutput(JSON.stringify(sanitizedStructured, null, 2), serverRow.remoteOrigin);
          textParts.push(fallbackStr);
        }
      }
    }

    const markdown = sanitizeMcpMarkdownOutput(textParts.join('\n\n'), serverRow.remoteOrigin);
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

const SENSITIVE_QUERY_PARAM_RE =
  /^(?:token|access_token|id_token|refresh_token|api[_.-]?key|key|secret|password|passwd|pwd|sig|signature|x-amz-signature|x-goog-signature|code|session|session_id|jwt|auth)$/i;

function sanitizeTargetUrlForMcpForwarding(validatedUrl: URL): string {
  const clone = new URL(validatedUrl.toString());
  clone.username = '';
  clone.password = '';
  clone.hash = '';
  for (const k of [...clone.searchParams.keys()]) {
    if (SENSITIVE_QUERY_PARAM_RE.test(k.trim())) {
      clone.searchParams.delete(k);
    }
  }
  return clone.toString();
}

/**
 * Selects a read-oriented URL tool on a matching connected MCP when `scrape` targets a domain with an active MCP connector.
 * Security Invariants (H1):
 *  - Strictly OPT-IN: runs ONLY when `preferMcp === true` on the scrape request OR `row.autoRouteScrape === true` on the connector!
 *  - Validates `targetUrl` through `isSafePublicHttpsUrl` BEFORE matching or forwarding to any MCP server.
 *  - Strips query credentials and NEVER forwards caller `headers` or `cookies` to the MCP server.
 *  - Sanitizes all returned Markdown via `sanitizeMcpMarkdownOutput` + `sanitizeRemoteMcpText`.
 */
export async function tryScrapeViaConnectedMcp(params: {
  userId: string;
  targetUrl: string;
  query?: string;
  preferMcp?: boolean;
  vaultStore: McpVaultStore;
  vaultMasterKey: string | undefined;
  fetchFn?: typeof fetch;
  selfHost?: string;
}): Promise<{ status: number; via: string; body: Record<string, unknown> } | null> {
  // 1. Validate `https://` public target URL BEFORE routing to any MCP server!
  const targetCheck = isSafePublicHttpsUrl(params.targetUrl, params.selfHost);
  if (!targetCheck.ok) {
    return null;
  }

  const allRows = await params.vaultStore.listServers(params.userId);
  if (allRows.length === 0) return null;

  // 2. Strictly OPT-IN routing (`preferMcp === true` OR explicit `autoRouteScrape === true` on the vault connector)!
  const eligibleRows = allRows.filter((r) => r.enabled && (params.preferMcp === true || r.autoRouteScrape === true));
  if (eligibleRows.length === 0) return null;

  const safeForwardUrl = sanitizeTargetUrlForMcpForwarding(targetCheck.url);
  const matches = matchConnectedMcpsForContext({
    servers: eligibleRows,
    urls: [safeForwardUrl],
  });
  const top = matches[0];
  if (!top || top.matchedDomains.length === 0) return null;

  // 3. Select ONLY a non-destructive read-oriented tool accepting `url` or `uri`
  const candidateTool = top.server.tools.find((t) => {
    if (t.readOnlyHint === false || t.destructiveHint === true) return false;
    const isReadName = /^(?:get|fetch|read|retrieve|resolve|view|inspect|page|search)(?:[_.:-]|$|[A-Z])/i.test(t.name) || t.readOnlyHint === true;
    if (!isReadName) return false;
    const props =
      t.inputSchema?.properties && typeof t.inputSchema.properties === 'object'
        ? (t.inputSchema.properties as Record<string, unknown>)
        : {};
    return 'url' in props || 'uri' in props;
  });
  if (!candidateTool) return null;

  const props = (candidateTool.inputSchema.properties ?? {}) as Record<string, unknown>;
  const toolArgs: Record<string, unknown> = 'url' in props ? { url: safeForwardUrl } : { uri: safeForwardUrl };
  if (params.query && 'query' in props) {
    toolArgs.query = params.query.slice(0, 500);
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

  const reSanitized = sanitizeRemoteMcpText(out.body.markdown);
  const safeMarkdown = sanitizeMcpMarkdownOutput(reSanitized.text, safeForwardUrl);
  const prevPi = (out.body.promptInjection as { detected?: boolean; scrubbed?: boolean; triggers?: string[] } | undefined) ?? {};
  const mergedTriggers = [...new Set([...(prevPi.triggers ?? []), ...reSanitized.triggers])];

  return {
    status: 200,
    via: `mcp:${top.server.slug}`,
    body: {
      ok: true,
      cached: false,
      visibility: 'private',
      url: targetCheck.normalized,
      finalUrl: targetCheck.normalized,
      status: 200,
      via: `mcp:${top.server.slug}`,
      extractorId: `mcp:${top.server.slug}:${candidateTool.name}`,
      markdown: safeMarkdown,
      sanitized: true,
      promptInjection: {
        detected: Boolean(prevPi.detected || reSanitized.detected),
        scrubbed: Boolean(prevPi.scrubbed || reSanitized.scrubbed),
        triggers: mergedTriggers,
      },
      metadata: {
        title: `${top.server.slug} — ${candidateTool.name}`,
        sourceMcpServer: top.server.slug,
        sourceMcpTool: candidateTool.name,
        visibility: 'private',
      },
    },
  };
}
