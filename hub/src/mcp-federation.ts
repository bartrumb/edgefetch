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
  filterSafeCachedMcpTools,
  isCachedMcpToolPermitted,
  isSafeMcpIdentifier,
  isValidMcpConnectorSlug,
  parseAllowedMcpTools,
  SAFE_MCP_IDENTIFIER_RE,
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
import { sanitizeInlineHtmlInMarkdown } from './scrape';
import { detectPromptInjection } from './scrape-advanced';

export const MAX_REMOTE_MCP_RESPONSE_BYTES = 4 * 1024 * 1024; // 4 MiB hard ceiling on downstream MCP responses
export const MAX_MCP_CONTENT_BLOCKS = 64; // Hard cap on content blocks per downstream MCP response (H3)
export const MAX_MCP_BLOCK_TEXT_CHARS = 64 * 1024; // 64 KiB per-block raw text cap BEFORE sanitizing (H3)
export const MAX_MCP_LINK_LABEL_CHARS = 512;
export const MAX_MCP_LINK_TARGET_CHARS = 2048;
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

/**
 * Neutralizes any `<untrusted_...` / `</untrusted_...` XML boundary tags inside untrusted connector text
 * so an adversarial response can never close or spoof an `<untrusted_mcp_output>` / `<untrusted_mcp_tool_output>` wrapper.
 */
export function neutralizeUntrustedMcpBoundaryTags(input: string): string {
  if (!input || !/untrusted_/i.test(input)) return input;
  return input.replace(/<(\s*\/?\s*untrusted_[a-z0-9_-]*)/gi, '&lt;$1');
}

/**
 * Wraps untrusted downstream MCP text in a fence-safe + boundary-tag-safe envelope:
 *  1. Escapes any `<untrusted_mcp...` or `</untrusted_mcp...` tags inside `content`,
 *  2. Dynamically selects a backtick fence strictly longer than any contiguous `` ` `` run in `content` (`maxRun + 1`, min 3),
 *     preventing triple-backtick ```` ``` ```` or XML closing-tag breakouts.
 */
export function formatFenceSafeUntrustedMcpEnvelope(params: {
  tag?: 'untrusted_mcp_output' | 'untrusted_mcp_tool_output';
  attributes?: Record<string, string | undefined>;
  content: string;
  maxChars?: number;
}): string {
  const tag = params.tag === 'untrusted_mcp_tool_output' ? 'untrusted_mcp_tool_output' : 'untrusted_mcp_output';
  const raw = params.content ?? '';
  const sliced =
    typeof params.maxChars === 'number' && params.maxChars > 0 && raw.length > params.maxChars
      ? raw.slice(0, params.maxChars)
      : raw;
  const safeBody = neutralizeUntrustedMcpBoundaryTags(sliced);
  let maxBacktickRun = 0;
  let curRun = 0;
  for (let i = 0; i < safeBody.length; i++) {
    if (safeBody.charCodeAt(i) === 96 /* ` */) {
      curRun++;
      if (curRun > maxBacktickRun) maxBacktickRun = curRun;
    } else {
      curRun = 0;
    }
  }
  const fence = '`'.repeat(Math.max(3, maxBacktickRun + 1));
  const attrParts: string[] = [];
  if (params.attributes) {
    for (const [k, v] of Object.entries(params.attributes)) {
      if (!v || !/^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$/.test(k)) continue;
      const safeVal = String(v).replace(/["&<>\r\n\0`]/g, '');
      attrParts.push(`${k}="${safeVal}"`);
    }
  }
  const attrStr = attrParts.length > 0 ? ` ${attrParts.join(' ')}` : '';
  return `<${tag}${attrStr}>\n${fence}text\n${safeBody}\n${fence}\n</${tag}>`;
}

/**
 * Pure O(N) zero-backtracking scanner that strips dangerous URI schemes (`javascript:`, `vbscript:`, `data:`, `file:`, `blob:`)
 * from Markdown `[label](target)` and `![label](target)` links (`label <= 512` chars, `target <= 2048` chars).
 */
function stripDangerousMarkdownLinksLinear(input: string): string {
  if (!input.includes('](') || !input.includes(')') || !input.includes(':')) return input;
  const n = input.length;
  let out = '';
  let emitFrom = 0;
  let openBracket = -1;
  let noCloseParenBefore = -1;

  for (let i = 0; i < n; i++) {
    const ch = input.charCodeAt(i);
    if (ch === 10 /* \n */ || ch === 13 /* \r */) {
      openBracket = -1;
      continue;
    }
    if (ch === 91 /* [ */) {
      openBracket = i;
      continue;
    }
    if (ch === 93 /* ] */ && openBracket >= 0) {
      const labelLen = i - openBracket - 1;
      if (labelLen <= MAX_MCP_LINK_LABEL_CHARS && i + 1 < n && input.charCodeAt(i + 1) === 40 /* ( */) {
        const parenStart = i + 2;
        if (parenStart >= noCloseParenBefore) {
          const maxEnd = Math.min(n, parenStart + MAX_MCP_LINK_TARGET_CHARS);
          let closeParen = -1;
          let scanPos = parenStart;
          for (; scanPos < maxEnd; scanPos++) {
            const tc = input.charCodeAt(scanPos);
            if (tc === 10 || tc === 13) break;
            if (tc === 41 /* ) */) {
              closeParen = scanPos;
              break;
            }
          }
          if (closeParen >= 0) {
            const rawTarget = input.slice(parenStart, closeParen);
            const cleanedTarget = rawTarget
              .trim()
              .replace(/^<|>$/g, '')
              .replace(/[\u0000-\u0020]+/g, '');
            if (DANGEROUS_MARKDOWN_SCHEME_RE.test(cleanedTarget)) {
              const linkStart =
                openBracket > 0 && input.charCodeAt(openBracket - 1) === 33 /* ! */
                  ? openBracket - 1
                  : openBracket;
              const label = input.slice(openBracket + 1, i);
              out += input.slice(emitFrom, linkStart) + (label || '[blocked-unsafe-link]');
              emitFrom = closeParen + 1;
            }
            i = closeParen;
            openBracket = -1;
            continue;
          }
          noCloseParenBefore = scanPos;
        }
      }
      openBracket = -1;
    }
  }
  if (emitFrom === 0) return input;
  return out + input.slice(emitFrom);
}

function hasHiddenInlineStyleLinear(line: string): boolean {
  if (!line.includes('<') || !/style/i.test(line)) return false;
  let pos = 0;
  while (pos < line.length) {
    const lt = line.indexOf('<', pos);
    if (lt < 0) return false;
    const gt = line.indexOf('>', lt + 1);
    const tagSlice = gt >= 0 ? line.slice(lt, Math.min(gt + 1, lt + 2_048)) : line.slice(lt, lt + 2_048);
    if (/\bstyle\s*=/i.test(tagSlice) && /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)/i.test(tagSlice)) {
      return true;
    }
    if (gt < 0) return false;
    pos = gt + 1;
  }
  return false;
}

/**
 * Sanitizes untrusted Markdown/text returned by a downstream MCP server:
 *  - Bounds input BEFORE sanitizing,
 *  - Runs the Hub's HTML/Markdown sanitizer (`sanitizeInlineHtmlInMarkdown`),
 *  - Neutralizes `<untrusted_mcp...` boundary tags,
 *  - Strips `javascript:`, `data:`, `vbscript:`, `file:`, and `blob:` Markdown links/images in strictly linear O(N) time.
 */
export function sanitizeMcpMarkdownOutput(rawMarkdown: string, baseUrl?: string, maxChars = MAX_REMOTE_MCP_RESPONSE_BYTES): string {
  if (!rawMarkdown) return '';
  const bounded = rawMarkdown.length > maxChars ? rawMarkdown.slice(0, maxChars) : rawMarkdown;
  let out = sanitizeInlineHtmlInMarkdown(bounded, baseUrl);
  out = neutralizeUntrustedMcpBoundaryTags(out);
  out = stripDangerousMarkdownLinksLinear(out);
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
  const postStripScan =
    stripped === boundedRaw
      ? preScan
      : detectPromptInjection({
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
  if (lines.length === 1) {
    return { text: '[SCRUBBED: prompt injection blocked]', detected: true, scrubbed: true, triggers: allTriggers };
  }
  const scrubbedLines = lines.map((line) => {
    if (!line.trim()) return line;
    const lineCheck = detectPromptInjection({
      markdown: line,
      ...(line.includes('<') ? { rawHtml: line } : {}),
    });
    const lineDirective = MCP_DIRECTIVE_INJECTION_RE.test(line);
    if (lineCheck.detected || lineDirective || hasHiddenInlineStyleLinear(line)) {
      return '[SCRUBBED: prompt injection blocked]';
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
    candidate = '[SCRUBBED: prompt injection blocked]';
    return { text: candidate, detected: true, scrubbed: true, triggers: mergedTriggers };
  }

  return { text: candidate, detected: true, scrubbed: true, triggers: allTriggers };
}

export const MAX_STRUCTURED_SANITIZE_DEPTH = 12;
export const MAX_STRUCTURED_CONTAINER_ENTRIES = 256;
export const MAX_STRUCTURED_NODE_BUDGET = 2_048;
export const MAX_STRUCTURED_STRING_CHARS = 16 * 1024; // 16 KiB per string leaf
export const MAX_MCP_RPC_ERROR_DATA_BYTES = 4 * 1024; // 4 KiB hard ceiling on JSON-RPC error.data
export const MAX_MCP_RPC_ERROR_DATA_DEPTH = 4;
export const MAX_MCP_RPC_ERROR_DATA_ENTRIES = 16;
export const MAX_MCP_RPC_ERROR_DATA_NODES = 64;
export const MAX_MCP_RPC_ERROR_DATA_STRING_CHARS = 512;

/**
 * Early-aborting O(maxBytes) serialized JSON size estimator with cycle detection.
 * Stops traversing immediately as soon as the estimated serialized byte/char size exceeds `maxBytes`,
 * preventing multi-megabyte `structuredContent` or `error.data` trees from burning CPU in `JSON.stringify`
 * or recursive sanitization before hitting the size budget.
 */
export function measureJsonSizeCapped(rawValue: unknown, maxBytes: number): number {
  let acc = 0;
  const seen = new WeakSet<object>();

  const visit = (node: unknown): void => {
    if (acc > maxBytes) return;
    if (node === null || node === undefined) {
      acc += 4;
      return;
    }
    const t = typeof node;
    if (t === 'boolean') {
      acc += (node as boolean) ? 4 : 5;
      return;
    }
    if (t === 'number' || t === 'bigint') {
      acc += String(node).length;
      return;
    }
    if (t === 'string') {
      acc += (node as string).length + 2;
      return;
    }
    if (t !== 'object') {
      acc += 4;
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
        for (let i = 0; i < obj.length; i++) {
          if (i > 0) acc += 1;
          visit(obj[i]);
          if (acc > maxBytes) return;
        }
        return;
      }
      acc += 2;
      let first = true;
      for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        if (!first) acc += 1;
        first = false;
        acc += k.length + 3;
        if (acc > maxBytes) return;
        visit(v);
        if (acc > maxBytes) return;
      }
    } finally {
      seen.delete(obj);
    }
  };

  visit(rawValue);
  return acc;
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

/**
 * Runs the complete connector text sanitization pipeline (`redactVaultSecretsFromText` -> `sanitizeRemoteMcpText`
 * control-char/Bidi/Unicode-Tag/prompt-injection scrubber -> `sanitizeMcpMarkdownOutput` HTML/boundary-tag/link sanitizer)
 * on a single untrusted string, setting `sanitized` dynamically from actual pipeline completion and post-verification.
 */
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
    const redacted = redactSecret !== undefined ? redactVaultSecretsFromText(raw, redactSecret) : raw;
    const truncated = redacted.length > maxChars;
    const bounded = truncated ? redacted.slice(0, maxChars) : redacted;
    const piRes = sanitizeRemoteMcpText(bounded, maxChars);
    const safeMd = sanitizeMcpMarkdownOutput(piRes.text, baseUrl, maxChars);
    const postVerify = detectPromptInjection({
      markdown: safeMd,
      ...(safeMd.includes('<') ? { rawHtml: safeMd } : {}),
    });
    const completedCleanly = !postVerify.detected && !MCP_DIRECTIVE_INJECTION_RE.test(safeMd);
    return {
      text: safeMd,
      sanitized: completedCleanly,
      fullySanitized: completedCleanly && !truncated,
      truncated,
      detected: piRes.detected || postVerify.detected,
      scrubbed: piRes.scrubbed || safeMd !== bounded || redacted !== raw,
      triggers: postVerify.triggers.length > 0 ? [...new Set([...piRes.triggers, ...postVerify.triggers])] : piRes.triggers,
    };
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

/**
 * Bounded recursive sanitizer for arbitrary connector JSON values (`structuredContent`, JSON-RPC `error.data`,
 * `discover_mcps` manifests, and `query_mcp` tool/server metadata):
 *  - Runs the full Markdown + dangerous-link + inline-HTML + control-char + prompt-injection sanitizer on EVERY
 *    string leaf AND object key!
 *  - Caps depth (`<= 12`), keys/items per container (`<= 256`), total visited nodes (`<= 2048`), string leaf length (`<= 16 KiB`),
 *    and optional cumulative `maxTotalChars`.
 *  - Replaces excess depth/node/entry/char subtrees with `"[truncated]"` and sets `fullySanitized = false`.
 */
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
  const maxDepth = opts?.maxDepth ?? MAX_STRUCTURED_SANITIZE_DEPTH;
  const maxEntries = opts?.maxEntriesPerContainer ?? MAX_STRUCTURED_CONTAINER_ENTRIES;
  const maxNodes = opts?.maxNodeBudget ?? MAX_STRUCTURED_NODE_BUDGET;
  const maxStringChars = opts?.maxStringChars ?? MAX_STRUCTURED_STRING_CHARS;
  const maxTotalChars = opts?.maxTotalChars;
  const baseUrl = opts?.baseUrl;
  const redactSecret = opts?.redactSecret;

  let visitedNodes = 0;
  let totalProcessedChars = 0;
  let allLeavesSanitized = true;
  let truncated = false;
  let anyDetected = false;
  let anyScrubbed = false;
  const triggerSet = new Set<string>();
  const activeAncestors = new WeakSet<object>();

  const walk = (node: unknown, depth: number): unknown => {
    visitedNodes++;
    if (
      visitedNodes > maxNodes ||
      depth > maxDepth ||
      (maxTotalChars !== undefined && totalProcessedChars > maxTotalChars)
    ) {
      truncated = true;
      return '[truncated]';
    }
    if (node === null || node === undefined || typeof node === 'boolean') {
      return node;
    }
    if (typeof node === 'number') {
      return Number.isFinite(node) ? node : null;
    }
    if (typeof node === 'bigint') {
      const s = sanitizeConnectorText(String(node), 128, baseUrl, redactSecret);
      totalProcessedChars += s.text.length;
      if (!s.sanitized) allLeavesSanitized = false;
      if (s.truncated) truncated = true;
      return s.text;
    }
    if (typeof node === 'string') {
      const remChars =
        maxTotalChars !== undefined ? Math.max(0, maxTotalChars - totalProcessedChars) : maxStringChars;
      if (maxTotalChars !== undefined && remChars === 0 && node.length > 0) {
        truncated = true;
        return '[truncated]';
      }
      const leafBudget = Math.min(maxStringChars, remChars);
      const s = sanitizeConnectorText(node, leafBudget, baseUrl, redactSecret);
      totalProcessedChars += s.text.length;
      if (!s.sanitized) allLeavesSanitized = false;
      if (s.truncated) truncated = true;
      if (s.detected) anyDetected = true;
      if (s.scrubbed) anyScrubbed = true;
      for (const tr of s.triggers) triggerSet.add(tr);
      return s.text;
    }
    if (typeof node !== 'object') {
      allLeavesSanitized = false;
      return null;
    }
    if (activeAncestors.has(node)) {
      truncated = true;
      return '[truncated]';
    }
    activeAncestors.add(node);
    try {
      if (Array.isArray(node)) {
        const outArr: unknown[] = [];
        const sliceLen = Math.min(node.length, maxEntries);
        for (let i = 0; i < sliceLen; i++) {
          if (visitedNodes >= maxNodes || (maxTotalChars !== undefined && totalProcessedChars >= maxTotalChars)) {
            outArr.push('[truncated]');
            truncated = true;
            return outArr;
          }
          outArr.push(walk(node[i], depth + 1));
        }
        if (node.length > maxEntries) {
          outArr.push('[truncated]');
          truncated = true;
        }
        return outArr;
      }

      const entries = Object.entries(node as Record<string, unknown>);
      const outObj: Record<string, unknown> = {};
      let emitted = 0;
      for (let i = 0; i < entries.length; i++) {
        const [rawK, rawV] = entries[i]!;
        if (rawK === '__proto__' || rawK === 'constructor' || rawK === 'prototype') {
          anyScrubbed = true;
          continue;
        }
        if (
          emitted >= maxEntries ||
          visitedNodes >= maxNodes ||
          (maxTotalChars !== undefined && totalProcessedChars >= maxTotalChars)
        ) {
          outObj.__truncated__ = '[truncated]';
          truncated = true;
          break;
        }
        const keySan = sanitizeConnectorText(rawK, 256, baseUrl, redactSecret);
        totalProcessedChars += keySan.text.length;
        if (!keySan.sanitized) allLeavesSanitized = false;
        if (keySan.truncated) truncated = true;
        if (keySan.detected) anyDetected = true;
        if (keySan.scrubbed) anyScrubbed = true;
        for (const tr of keySan.triggers) triggerSet.add(tr);
        const safeKey =
          keySan.text && keySan.text !== '__proto__' && keySan.text !== 'constructor' && keySan.text !== 'prototype'
            ? keySan.text
            : `key_${emitted}`;
        const childVal = walk(rawV, depth + 1);
        if (childVal !== undefined) {
          outObj[safeKey] = childVal;
        }
        emitted++;
      }
      return outObj;
    } finally {
      activeAncestors.delete(node);
    }
  };

  const sanitizedVal = walk(rawValue, 0);
  const didSanitize = visitedNodes > 0 && allLeavesSanitized;
  return {
    value: sanitizedVal,
    sanitized: didSanitize,
    fullySanitized: didSanitize && !truncated,
    truncated,
    detected: anyDetected,
    scrubbed: anyScrubbed,
    triggers: [...triggerSet],
  };
}

const ALLOWED_JSON_SCHEMA_TYPES = new Set(['object', 'string', 'number', 'integer', 'boolean', 'array', 'null']);
const SAFE_SCHEMA_PROP_KEY_RE = SAFE_MCP_IDENTIFIER_RE;
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
        out.description = sanitizeMcpMarkdownOutput(descCheck.text, undefined, 240);
      }
    }
  }

  let validPropKeys: Set<string> | null = null;
  if (src.properties && typeof src.properties === 'object' && !Array.isArray(src.properties)) {
    const rebuiltProps: Record<string, unknown> = {};
    validPropKeys = new Set<string>();
    for (const [rawKey, rawVal] of Object.entries(src.properties as Record<string, unknown>).slice(0, 32)) {
      const cleanKey = stripMcpSmugglingChars(rawKey).trim();
      if (!isSafeMcpIdentifier(cleanKey) || FORBIDDEN_PROTO_KEYS.has(cleanKey)) {
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
      if (typeof r === 'string' && isSafeMcpIdentifier(r) && (!validPropKeys || validPropKeys.has(r))) {
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
    if (!isSafeMcpIdentifier(rawName) || FORBIDDEN_PROTO_KEYS.has(rawName)) {
      promptInjectionScrubbed = true;
      continue;
    }
    const nameInj = sanitizeRemoteMcpText(rawName, 64);
    if (nameInj.detected) {
      promptInjectionScrubbed = true;
      continue;
    }

    const titleSan = typeof t.title === 'string' ? sanitizeConnectorText(t.title, 120) : null;
    const descSan = typeof t.description === 'string' ? sanitizeConnectorText(t.description, 240) : null;
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

  const allowedAuthOrigin = secret.oauth.confirmedAuthOrigin
    ? secret.oauth.confirmedAuthOrigin.trim().toLowerCase()
    : server.remoteOrigin.toLowerCase();
  const tokenEpCheck = isSafePublicHttpsUrl(secret.oauth.tokenEndpoint, params.selfHost);
  if (!tokenEpCheck.ok) {
    return { ok: false, error: `Unsafe OAuth token_endpoint: ${tokenEpCheck.reason}` };
  }
  if (tokenEpCheck.origin !== allowedAuthOrigin) {
    return {
      ok: false,
      error: `Unsafe OAuth token_endpoint: cross-origin authorization server ${tokenEpCheck.origin} is not confirmed for ${server.remoteOrigin}`,
    };
  }
  if (secret.oauth.issuer) {
    const issCheck = isSafePublicHttpsUrl(secret.oauth.issuer, params.selfHost);
    if (!issCheck.ok || issCheck.origin !== allowedAuthOrigin || tokenEpCheck.origin !== issCheck.origin) {
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
        message: sanitizeConnectorText(msg, 240, params.pinnedOrigin, params.secret).text || 'Remote MCP request failed',
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
        clientInfo: { name: 'edgefetch-hub', version: '2.7.8' },
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
    const initErrSan = sanitizeConnectorText(
      String(initErrObj?.message ?? 'initialize failed'),
      240,
      urlCheck.origin,
      params.secret,
    );
    return {
      ok: false,
      status: 502,
      error: 'remote_mcp_rpc_error',
      message: initErrSan.text,
    };
  }
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
    const errSan = sanitizeConnectorText(String(errObj?.message ?? 'tools/list failed'), 240, urlCheck.origin, params.secret);
    return {
      ok: false,
      status: 502,
      error: 'remote_mcp_rpc_error',
      message: errSan.text,
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

/**
 * Extracts joined Markdown/text from an `executeFederatedMcpQuery` response `body` (`content[]` text/resource blocks,
 * with fallback to `structuredContent` or legacy `markdown`).
 */
export function extractMarkdownFromQueryMcpBody(body: Record<string, unknown>): string {
  if (typeof body.markdown === 'string' && body.markdown) {
    return body.markdown;
  }
  if (Array.isArray(body.content) && body.content.length > 0) {
    const parts: string[] = [];
    for (const rawBlock of body.content) {
      if (!rawBlock || typeof rawBlock !== 'object') continue;
      const block = rawBlock as Record<string, unknown>;
      if (block.type === 'text' && typeof block.text === 'string' && block.text) {
        parts.push(block.text);
      } else if (block.type === 'resource' && block.resource && typeof block.resource === 'object') {
        const r = block.resource as Record<string, unknown>;
        if (typeof r.text === 'string' && r.text) {
          parts.push(r.text);
        }
      }
    }
    if (parts.length > 0) {
      return parts.join('\n\n');
    }
  }
  if (body.structuredContent !== undefined) {
    return typeof body.structuredContent === 'string'
      ? body.structuredContent
      : (JSON.stringify(body.structuredContent, null, 2) ?? '');
  }
  return '';
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

/**
 * Executes MCP `query_mcp` (`list_connected` | `list_tools` | `call_tool`) strictly isolated to `userId`.
 */
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
  const effectiveAllowedTools = new Set<string>([
    ...parsedParamAllowed.allowed,
    ...parsedInputAllowed.allowed,
  ]);

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

  // S6: Resolve strictly by exact connector `id` or exact `slug` (never by domain, origin, or suffix).
  const serverRow = await params.vaultStore.getServer(params.userId, serverRef);
  const serverRefNorm = serverRef.toLowerCase();
  if (
    !serverRow ||
    (serverRow.id.toLowerCase() !== serverRefNorm && serverRow.slug.toLowerCase() !== serverRefNorm)
  ) {
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
        const listErrSan = sanitizeConnectorText(listed.message, 240, serverRow.remoteOrigin, activeSecret);
        await params.vaultStore.upsertServer({
          ...serverRow,
          lastError: listErrSan.text,
          updatedAt: now,
        });
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

    // S6: Enforce cached tool + readOnlyHint/destructiveHint gate (matching `/v1/agent`):
    // tool MUST exist in `cachedTools`, and MUST have `readOnlyHint === true && destructiveHint !== true`
    // unless explicitly allow-listed for this request in exact `${serverRow.slug}/${toolName}` format!
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
              clientInfo: { name: 'edgefetch-hub', version: '2.7.8' },
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

    const sanitizeBaseUrl = params.baseUrlOverride ?? serverRow.remoteOrigin;

    if (callRes.rpc?.error) {
      const rpcErr = callRes.rpc.error as { code?: unknown; message?: unknown; data?: unknown };
      const msgSan = sanitizeConnectorText(
        String(rpcErr.message ?? 'Remote MCP tool call returned an error'),
        400,
        sanitizeBaseUrl,
        activeSecret,
      );
      let dataSan: SanitizedConnectorStructuredResult | undefined;
      if (rpcErr.data !== undefined) {
        if (typeof rpcErr.data === 'string') {
          const strSan = sanitizeConnectorText(
            rpcErr.data,
            MAX_MCP_RPC_ERROR_DATA_STRING_CHARS,
            sanitizeBaseUrl,
            activeSecret,
          );
          dataSan = {
            value: strSan.text,
            sanitized: strSan.sanitized,
            fullySanitized: strSan.fullySanitized,
            truncated: strSan.truncated,
            detected: strSan.detected,
            scrubbed: strSan.scrubbed,
            triggers: strSan.triggers,
          };
        } else if (measureJsonSizeCapped(rpcErr.data, MAX_MCP_RPC_ERROR_DATA_BYTES) > MAX_MCP_RPC_ERROR_DATA_BYTES) {
          dataSan = {
            value: '[truncated]',
            sanitized: true,
            fullySanitized: false,
            truncated: true,
            detected: false,
            scrubbed: true,
            triggers: [],
          };
        } else {
          const candSan = sanitizeConnectorStructuredValue(rpcErr.data, {
            baseUrl: sanitizeBaseUrl,
            redactSecret: activeSecret,
            maxDepth: MAX_MCP_RPC_ERROR_DATA_DEPTH,
            maxEntriesPerContainer: MAX_MCP_RPC_ERROR_DATA_ENTRIES,
            maxNodeBudget: MAX_MCP_RPC_ERROR_DATA_NODES,
            maxStringChars: MAX_MCP_RPC_ERROR_DATA_STRING_CHARS,
            maxTotalChars: MAX_MCP_RPC_ERROR_DATA_BYTES,
          });
          let serErrData = '';
          try {
            serErrData = JSON.stringify(candSan.value) ?? '';
          } catch {
            serErrData = '';
          }
          if (!serErrData || serErrData.length > MAX_MCP_RPC_ERROR_DATA_BYTES) {
            dataSan = {
              value: '[truncated]',
              sanitized: candSan.sanitized,
              fullySanitized: false,
              truncated: true,
              detected: candSan.detected,
              scrubbed: true,
              triggers: candSan.triggers,
            };
          } else {
            dataSan = candSan;
          }
        }
      }
      const errTriggers = [...new Set([...msgSan.triggers, ...(dataSan?.triggers ?? [])])];
      return {
        status: 502,
        body: {
          ok: false,
          visibility: 'private',
          server: serverRow.slug,
          tool: toolName,
          error: 'remote_mcp_tool_error',
          code: typeof rpcErr.code === 'number' ? rpcErr.code : -32000,
          message: msgSan.text,
          ...(dataSan !== undefined ? { data: dataSan.value } : {}),
          sanitized: Boolean(msgSan.sanitized && (dataSan ? dataSan.sanitized : true)),
          fullySanitized: Boolean(msgSan.fullySanitized && (dataSan ? dataSan.fullySanitized : true)),
          promptInjection: {
            detected: Boolean(msgSan.detected || dataSan?.detected),
            scrubbed: Boolean(msgSan.scrubbed || dataSan?.scrubbed),
            triggers: errTriggers,
          },
        },
      };
    }

    const rawResult =
      callRes.rpc?.result && typeof callRes.rpc.result === 'object'
        ? (callRes.rpc.result as Record<string, unknown>)
        : {};
    const rawContent = Array.isArray(rawResult.content) ? rawResult.content : [];
    const sanitizedContent: Array<Record<string, unknown>> = [];
    let anyDetected = false;
    let anyScrubbed = false;
    let contentBlocksAllSanitized = true;
    let fullySanitized = rawContent.length <= MAX_MCP_CONTENT_BLOCKS;
    let droppedContentBlocks = 0;
    const triggerSet = new Set<string>();

    // Strict allowlist on `content[].type` (`'text'` and `'resource'` text only — drops executable/binary/unknown types)!
    // H3: Cap max content blocks (<= 64), cap per-block raw text BEFORE sanitizing (<= 64 KiB), and bound total text budget (<= 4 MiB).
    let remainingTextBudget = MAX_REMOTE_MCP_RESPONSE_BYTES;
    for (const item of rawContent.slice(0, MAX_MCP_CONTENT_BLOCKS)) {
      if (remainingTextBudget <= 0) {
        fullySanitized = false;
        break;
      }
      if (!item || typeof item !== 'object') {
        droppedContentBlocks++;
        continue;
      }
      const block = item as Record<string, unknown>;
      const bType = typeof block.type === 'string' ? block.type.trim().toLowerCase() : '';
      if (bType === 'text' && typeof block.text === 'string') {
        const blockBudget = Math.min(MAX_MCP_BLOCK_TEXT_CHARS, remainingTextBudget);
        if (block.text.length > blockBudget) fullySanitized = false;
        const rawBlockSlice = block.text.length > blockBudget ? block.text.slice(0, blockBudget) : block.text;
        remainingTextBudget -= rawBlockSlice.length;
        const san = sanitizeConnectorText(rawBlockSlice, blockBudget, sanitizeBaseUrl, activeSecret);
        if (!san.sanitized) contentBlocksAllSanitized = false;
        if (!san.fullySanitized) fullySanitized = false;
        if (san.detected) anyDetected = true;
        if (san.scrubbed) anyScrubbed = true;
        for (const tr of san.triggers) triggerSet.add(tr);
        sanitizedContent.push({ type: 'text', text: san.text });
      } else if (bType === 'resource' && block.resource && typeof block.resource === 'object') {
        const resObj = block.resource as Record<string, unknown>;
        if (typeof resObj.text !== 'string') {
          // Drop binary `blob` resources and empty non-text resource envelopes!
          droppedContentBlocks++;
          continue;
        }
        const blockBudget = Math.min(MAX_MCP_BLOCK_TEXT_CHARS, remainingTextBudget);
        if (resObj.text.length > blockBudget) fullySanitized = false;
        const rawResSlice = resObj.text.length > blockBudget ? resObj.text.slice(0, blockBudget) : resObj.text;
        remainingTextBudget -= rawResSlice.length;
        const resText = sanitizeConnectorText(rawResSlice, blockBudget, sanitizeBaseUrl, activeSecret);
        if (!resText.sanitized) contentBlocksAllSanitized = false;
        if (!resText.fullySanitized) fullySanitized = false;
        if (resText.detected) anyDetected = true;
        if (resText.scrubbed) anyScrubbed = true;
        for (const tr of resText.triggers) triggerSet.add(tr);

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
            text: resText.text,
          },
        });
      } else {
        droppedContentBlocks++;
      }
    }

    let sanitizedStructured: unknown;
    let structuredAllSanitized = true;
    if (rawResult.structuredContent !== undefined) {
      const structBudget = Math.min(MAX_MCP_BLOCK_TEXT_CHARS, Math.max(0, remainingTextBudget));
      // M10-1: Check estimated serialized size budget BEFORE running `sanitizeConnectorStructuredValue`!
      if (structBudget <= 0 || measureJsonSizeCapped(rawResult.structuredContent, structBudget) > structBudget) {
        sanitizedStructured = '[truncated]';
        fullySanitized = false;
        remainingTextBudget = Math.max(0, remainingTextBudget - 11);
      } else {
        const structRes = sanitizeConnectorStructuredValue(rawResult.structuredContent, {
          baseUrl: sanitizeBaseUrl,
          redactSecret: activeSecret,
          maxTotalChars: structBudget,
        });
        structuredAllSanitized = structRes.sanitized;
        if (!structRes.fullySanitized) fullySanitized = false;
        if (structRes.detected) anyDetected = true;
        if (structRes.scrubbed) anyScrubbed = true;
        for (const tr of structRes.triggers) triggerSet.add(tr);

        let serializedSanitized = '';
        try {
          serializedSanitized = JSON.stringify(structRes.value) ?? '';
        } catch {
          serializedSanitized = '';
          structuredAllSanitized = false;
        }
        if (serializedSanitized.length > structBudget) {
          sanitizedStructured = '[truncated]';
          fullySanitized = false;
          remainingTextBudget = Math.max(0, remainingTextBudget - 11);
        } else {
          sanitizedStructured = structRes.value;
          remainingTextBudget = Math.max(0, remainingTextBudget - serializedSanitized.length);
        }
      }
    }

    const srvNameSan = sanitizeConnectorText(serverRow.name, 120, sanitizeBaseUrl, activeSecret);
    if (!srvNameSan.sanitized) contentBlocksAllSanitized = false;
    const isRemoteError = Boolean(rawResult.isError);
    const dynamicallySanitized = Boolean(contentBlocksAllSanitized && structuredAllSanitized);

    // M10-4: Return `content` (and `structuredContent` when present) without duplicating identical text into `markdown`.
    return {
      status: isRemoteError ? 502 : 200,
      body: {
        ok: !isRemoteError,
        action: 'call_tool',
        visibility: 'private',
        via: `mcp:${serverRow.slug}`,
        server: serverRow.slug,
        serverName: srvNameSan.text,
        remoteOrigin: serverRow.remoteOrigin,
        tool: toolName,
        isError: isRemoteError,
        ...(tokenRefreshed ? { tokenRefreshed: true } : {}),
        ...(droppedContentBlocks > 0 ? { droppedContentBlocks } : {}),
        sanitized: dynamicallySanitized,
        fullySanitized: Boolean(dynamicallySanitized && fullySanitized),
        promptInjection: {
          detected: anyDetected,
          scrubbed: anyScrubbed,
          triggers: [...triggerSet],
        },
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
  const qLower = (params.query ?? '').slice(0, 4_096).toLowerCase();
  const urlHosts = new Set<string>();
  for (const rawU of params.urls ?? []) {
    try {
      const h = new URL(rawU).hostname.toLowerCase().replace(/^www\./, '');
      if (h) urlHosts.add(h);
    } catch {
      // ignore
    }
  }
  // Extract inline `https://...` hostnames linearly from bounded query tokens (zero regex backtracking)
  for (const rawTok of qLower.split(/[\s<>()"'[\]{},;]+/)) {
    if (!rawTok.startsWith('http://') && !rawTok.startsWith('https://')) continue;
    try {
      const h = new URL(rawTok).hostname.toLowerCase().replace(/^www\./, '');
      if (h) urlHosts.add(h);
    } catch {
      // ignore
    }
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
  allowedServerIds?: ReadonlySet<string>;
  allowedMcpTools?: ReadonlyArray<string> | ReadonlySet<string>;
  requireExplicitReadOnlyHint?: boolean;
  vaultStore: McpVaultStore;
  vaultMasterKey: string | undefined;
  fetchFn?: typeof fetch;
  selfHost?: string;
}): Promise<{ status: number; via: string; body: Record<string, unknown> } | null> {
  // 0. Enforce `mcp:call` scope whenever an OAuth caller is in active context!
  const activeAuth = getActiveCallerAuthContext();
  if (activeAuth && activeAuth.principal.startsWith('oauth:') && !activeAuth.scopes.includes('mcp:call')) {
    return null;
  }

  const parsedAllowed = parseAllowedMcpTools(params.allowedMcpTools);
  if (!parsedAllowed.ok) {
    return null;
  }
  const allowedToolSet = parsedAllowed.allowed;

  // 1. Validate `https://` public target URL BEFORE routing to any MCP server!
  const targetCheck = isSafePublicHttpsUrl(params.targetUrl, params.selfHost);
  if (!targetCheck.ok) {
    return null;
  }

  const allRows = await params.vaultStore.listServers(params.userId);
  if (allRows.length === 0) return null;

  // 2. Strictly OPT-IN routing (`preferMcp === true` OR explicit `autoRouteScrape === true` on the vault connector,
  //    plus strict `allowedServerIds` filtering when called from `/v1/agent`)!
  const eligibleRows = allRows.filter(
    (r) =>
      r.enabled &&
      isValidMcpConnectorSlug(r.slug) &&
      (!params.allowedServerIds || params.allowedServerIds.has(r.id)) &&
      (params.preferMcp === true || r.autoRouteScrape === true),
  );
  if (eligibleRows.length === 0) return null;

  const safeForwardUrl = sanitizeTargetUrlForMcpForwarding(targetCheck.url);
  const matches = matchConnectedMcpsForContext({
    servers: eligibleRows,
    urls: [safeForwardUrl],
  });
  const top = matches[0];
  if (!top || top.matchedDomains.length === 0) return null;

  // 3. S6: Enforce `readOnlyHint === true && destructiveHint !== true` by default (unless explicitly allow-listed in `allowedMcpTools`)
  const requireReadOnly = params.requireExplicitReadOnlyHint !== false;
  const topSlugLower = top.server.slug.toLowerCase();
  const candidateTool = filterSafeCachedMcpTools(top.server.tools).find((t) => {
    if (!isSafeMcpIdentifier(t.name) || FORBIDDEN_PROTO_KEYS.has(t.name)) return false;
    const explicitlyAllowed = allowedToolSet.has(`${topSlugLower}/${t.name}`);
    if (!explicitlyAllowed) {
      if (requireReadOnly && t.readOnlyHint !== true) return false;
      if (t.readOnlyHint === false || t.destructiveHint === true) return false;
    }
    const isReadName =
      explicitlyAllowed ||
      /^(?:get|fetch|read|retrieve|resolve|view|inspect|page|search)(?:[_.-]|$|[A-Z])/i.test(t.name) ||
      t.readOnlyHint === true;
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

  // M10-3 & P3-4: Sanitize once inside `executeFederatedMcpQuery` using `safeForwardUrl` as `baseUrlOverride`,
  // and propagate actual `sanitized` / `fullySanitized` / `promptInjection` results without double-sanitizing.
  const out = await executeFederatedMcpQuery({
    userId: params.userId,
    input: {
      action: 'call_tool',
      server: top.server.slug,
      tool: candidateTool.name,
      arguments: toolArgs,
    },
    allowedMcpTools: allowedToolSet,
    baseUrlOverride: safeForwardUrl,
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
      sanitized: wasSanitized,
      fullySanitized: wasFullySanitized,
      promptInjection: {
        detected: Boolean(prevPi.detected),
        scrubbed: Boolean(prevPi.scrubbed),
        triggers: Array.isArray(prevPi.triggers) ? prevPi.triggers : [],
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
