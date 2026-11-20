/**
 * Linear-time HTML scanners, ReDoS-proof regex validation, bounded request-body streaming,
 * and IPv6 `/64` rate-limit key canonicalization (`hub/src/safe-input.ts`).
 */

export const MAX_HTML_SCAN_CHARS = 2 * 1024 * 1024; // 2 MiB ceiling on regex/DOM scan inputs (M4)

const utf8Decoder = new TextDecoder();

/**
 * Streams `request.body` up to `maxBytes` UTF-8 bytes (`M6`), aborting immediately as soon as
 * `Content-Length` or cumulative chunk bytes exceed `maxBytes` — never buffering unbounded payloads in RAM.
 */
export async function readBodyTextCapped(
  request: Request,
  maxBytes: number,
): Promise<{ ok: true; text: string; byteLength: number } | { ok: false; error: 'too_large' | 'read_error' }> {
  const clHeader = request.headers.get('content-length');
  if (clHeader !== null && clHeader.trim() !== '') {
    const cl = Number(clHeader);
    if (!Number.isFinite(cl) || cl < 0 || cl > maxBytes) {
      await request.body?.cancel().catch(() => undefined);
      return { ok: false, error: 'too_large' };
    }
  }
  if (!request.body) {
    return { ok: true, text: '', byteLength: 0 };
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel('body exceeds maxBytes').catch(() => undefined);
          return { ok: false, error: 'too_large' };
        }
        chunks.push(value);
      }
    }
  } catch {
    await reader.cancel().catch(() => undefined);
    return { ok: false, error: 'read_error' };
  }

  if (chunks.length === 0) return { ok: true, text: '', byteLength: 0 };
  if (chunks.length === 1) {
    return { ok: true, text: utf8Decoder.decode(chunks[0]!), byteLength: total };
  }
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    joined.set(c, off);
    off += c.byteLength;
  }
  return { ok: true, text: utf8Decoder.decode(joined), byteLength: total };
}

function isTagNameBoundary(ch: number): boolean {
  // space, tab, CR, LF, '/', '>'
  return ch === 32 || ch === 9 || ch === 13 || ch === 10 || ch === 47 || ch === 62;
}

function findTagOpenEndQuoteAware(src: string, fromIdx: number): number {
  let quote = 0;
  for (let i = fromIdx; i < src.length; i++) {
    const ch = src.charCodeAt(i);
    if (quote !== 0) {
      if (ch === quote) quote = 0;
    } else if (ch === 34 || ch === 39) {
      quote = ch;
    } else if (ch === 62 /* '>' */) {
      return i;
    }
  }
  return -1;
}

/**
 * Pure `indexOf` O(N) HTML comment stripper (`<!-- ... -->`) with zero regex backtracking (`M4`).
 */
export function stripHtmlCommentsLinear(rawHtml: string, maxChars = MAX_HTML_SCAN_CHARS): string {
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  let pos = src.indexOf('<!--');
  if (pos < 0) return src;
  const out: string[] = [];
  let cursor = 0;
  while (pos >= 0) {
    out.push(src.slice(cursor, pos));
    const closeIdx = src.indexOf('-->', pos + 4);
    if (closeIdx < 0) {
      cursor = src.length;
      break;
    }
    cursor = closeIdx + 3;
    pos = src.indexOf('<!--', cursor);
  }
  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
}

/**
 * Pure `indexOf` O(N) HTML element replacer/stripper for a single tag (`<noscript>`, `<iframe>`, `<script>`).
 * Prevents quadratic `O(N^2)` backtracking when an adversarial HTML document contains 20,000+ unclosed `<noscript>` tags (`M4`)!
 */
export function replaceHtmlTagBlocksLinear(
  rawHtml: string,
  tagNameLower: string,
  replacer: (fullMatch: string, attrStr: string, innerHtml: string) => string,
  maxChars = MAX_HTML_SCAN_CHARS,
): string {
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  const lower = src.toLowerCase();
  const openNeedle = `<${tagNameLower}`;
  const closeNeedle = `</${tagNameLower}`;
  let searchFrom = 0;
  let firstHit = lower.indexOf(openNeedle, searchFrom);
  if (firstHit < 0) return src;

  const out: string[] = [];
  let cursor = 0;
  let noCloseTagsRemain = false;

  while (firstHit >= 0) {
    const afterNameIdx = firstHit + openNeedle.length;
    if (afterNameIdx >= src.length || !isTagNameBoundary(src.charCodeAt(afterNameIdx))) {
      firstHit = lower.indexOf(openNeedle, afterNameIdx);
      continue;
    }
    const openEnd = findTagOpenEndQuoteAware(src, afterNameIdx);
    if (openEnd < 0) {
      // Unclosed `<tag ...` at EOF: drop unclosed tag tail safely in O(1) without scanning again.
      out.push(src.slice(cursor, firstHit));
      cursor = src.length;
      break;
    }
    out.push(src.slice(cursor, firstHit));
    const attrStr = src.slice(afterNameIdx, openEnd);
    if (src.charCodeAt(openEnd - 1) === 47 /* self-closing '/>' */) {
      out.push(replacer(src.slice(firstHit, openEnd + 1), attrStr.slice(0, -1), ''));
      cursor = openEnd + 1;
      firstHit = lower.indexOf(openNeedle, cursor);
      continue;
    }

    // Locate matching `</tag>` in lowercased view; once `closePos < 0` occurs ONCE, zero `</tag>` tokens exist
    // anywhere in the remainder of the document (`noCloseTagsRemain = true`), guaranteeing strict O(N) time!
    let closePos = noCloseTagsRemain ? -1 : lower.indexOf(closeNeedle, openEnd + 1);
    while (closePos >= 0) {
      const afterCloseName = closePos + closeNeedle.length;
      if (afterCloseName < src.length && isTagNameBoundary(src.charCodeAt(afterCloseName))) {
        break;
      }
      closePos = lower.indexOf(closeNeedle, afterCloseName);
    }

    if (closePos < 0) {
      noCloseTagsRemain = true;
      if (tagNameLower === 'script' || tagNameLower === 'style') {
        cursor = src.length;
        break;
      }
      cursor = openEnd + 1;
      firstHit = lower.indexOf(openNeedle, cursor);
      continue;
    }

    const closeEnd = src.indexOf('>', closePos + closeNeedle.length);
    if (closeEnd < 0) {
      cursor = src.length;
      break;
    }
    const inner = src.slice(openEnd + 1, closePos);
    out.push(replacer(src.slice(firstHit, closeEnd + 1), attrStr, inner));
    cursor = closeEnd + 1;
    firstHit = lower.indexOf(openNeedle, cursor);
  }

  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
}

/**
 * Strips all blocks for a list of HTML tags (`script`, `style`, `noscript`, `template`, `svg`, etc.) in guaranteed O(N) time (`M4`).
 */
export function stripHtmlTagsLinear(
  rawHtml: string,
  tagNamesLower: readonly string[],
  replacement = '',
  maxChars = MAX_HTML_SCAN_CHARS,
): string {
  let cur = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  for (const tag of tagNamesLower) {
    cur = replaceHtmlTagBlocksLinear(cur, tag, () => replacement, maxChars);
  }
  return cur;
}

/** Escapes all ECMAScript RegExp metacharacters in an untrusted literal string (`M5`). */
export function escapeRegexLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Validates and compiles a caller-supplied regular expression (`M5`), rejecting:
 *  - Patterns > 160 chars
 *  - Backreferences (`\1`..`\9`, `\k<...>`) and lookbehinds (`(?<=`, `(?<!`)
 *  - ANY quantified group whose interior itself contains a quantifier (`+`, `*`, `{`) or alternation (`|`),
 *    regardless of nesting depth — blocking `((a+))+$`, `([a-z]+)*$`, `(a|aa)+$`, and `(a+){2,}`!
 */
export function compileSafeUserRegex(pattern: string, flags = ''): RegExp | null {
  if (!pattern || pattern.length > 160) return null;
  if (/\\[1-9]|\\k<|\(\?<[=!]/i.test(pattern)) return null;

  interface GroupState {
    hasQuantifier: boolean;
    hasAlternation: boolean;
  }
  const stack: GroupState[] = [];
  let inCharClass = false;

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === '\\') {
      i++; // skip escaped char
      continue;
    }
    if (inCharClass) {
      if (ch === ']') inCharClass = false;
      continue;
    }
    if (ch === '[') {
      inCharClass = true;
      continue;
    }
    if (ch === '(') {
      stack.push({ hasQuantifier: false, hasAlternation: false });
      continue;
    }
    if (ch === '|') {
      if (stack.length > 0) stack[stack.length - 1]!.hasAlternation = true;
      continue;
    }
    if (ch === ')') {
      const closed = stack.pop();
      if (!closed) return null; // unbalanced ')'
      const next = pattern[i + 1] ?? '';
      const groupIsQuantified = next === '+' || next === '*' || next === '?' || next === '{';
      if (groupIsQuantified && (closed.hasQuantifier || closed.hasAlternation)) {
        return null;
      }
      if (stack.length > 0) {
        if (closed.hasQuantifier || groupIsQuantified) {
          stack[stack.length - 1]!.hasQuantifier = true;
        }
        if (closed.hasAlternation) {
          stack[stack.length - 1]!.hasAlternation = true;
        }
      }
      continue;
    }
    if (ch === '+' || ch === '*' || ch === '{') {
      // Reject adjacent stacked quantifiers like `a++` or `a*{1,5}`
      const next = pattern[i + 1] ?? '';
      if (ch !== '{' && (next === '+' || next === '*' || next === '{')) return null;
      if (stack.length > 0) {
        stack[stack.length - 1]!.hasQuantifier = true;
      }
    }
  }
  if (stack.length > 0 || inCharClass) return null;

  try {
    return new RegExp(pattern, flags);
  } catch {
    return null;
  }
}

/**
 * Canonicalizes a client IP for brute-force lockout / rate-limiting (`H4` & `Low`):
 *  - Strips IPv4-mapped IPv6 prefix (`::ffff:192.0.2.1` -> `192.0.2.1`).
 *  - Collapses IPv6 addresses to their `/64` subnet prefix (`2001:0db8:0001:0002::/64`) so an attacker rotating
 *    host addresses inside one `/64` allocation shares one lockout bucket.
 */
export function normalizeClientRateLimitIp(rawIp: string | null | undefined): string {
  let clean = (rawIp ?? '').split(',')[0]?.trim().toLowerCase() ?? '';
  if (!clean) return 'local';
  if (clean.startsWith('[') && clean.includes(']')) {
    clean = clean.slice(1, clean.indexOf(']'));
  }
  if (clean.startsWith('::ffff:')) {
    const v4 = clean.slice('::ffff:'.length);
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v4)) return v4;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(clean)) {
    return clean;
  }
  if (clean === '::1') return '127.0.0.1';
  if (clean.includes(':')) {
    const zoneIdx = clean.indexOf('%');
    const noZone = zoneIdx >= 0 ? clean.slice(0, zoneIdx) : clean;
    const expanded = expandIpv6Hextets(noZone);
    if (expanded) {
      return `${expanded.slice(0, 4).join(':')}::/64`;
    }
  }
  return clean.slice(0, 45);
}

function expandIpv6Hextets(addr: string): string[] | null {
  const parts = addr.split('::');
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if ((parts.length === 1 && missing !== 0) || missing < 0) return null;
  const full = [...left, ...Array<string>(parts.length === 2 ? missing : 0).fill('0'), ...right];
  if (full.length !== 8) return null;
  const padded: string[] = [];
  for (const h of full) {
    if (!/^[0-9a-f]{1,4}$/i.test(h)) return null;
    padded.push(h.toLowerCase().padStart(4, '0'));
  }
  return padded;
}
