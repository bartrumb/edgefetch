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
  const MAX_CLEAN_DRAIN_BYTES = 2 * 1024 * 1024;
  const clHeader = request.headers.get('content-length');
  if (clHeader !== null && clHeader.trim() !== '') {
    const cl = Number(clHeader);
    if (!Number.isFinite(cl) || cl < 0 || cl > maxBytes) {
      // Drain small over-limit bodies (`<= 2 MiB`) with zero buffering so HTTP/1.1 clients on Windows loopback never
      // hit TCP `ECONNRESET` while reading the `413` response; for larger uploads, return immediately (`O(1)`).
      if (Number.isFinite(cl) && cl > 0 && cl <= MAX_CLEAN_DRAIN_BYTES && request.body) {
        const r = request.body.getReader();
        let drained = 0;
        try {
          for (;;) {
            const { done, value } = await r.read();
            if (done) break;
            drained += value?.byteLength ?? 0;
            if (drained > MAX_CLEAN_DRAIN_BYTES) break;
          }
        } catch {
          // ignore
        } finally {
          r.releaseLock();
        }
      }
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

/**
 * ASCII-only lowercasing (`A-Z` -> `a-z`) that strictly preserves UTF-16 `.length` and 1:1 code-unit offsets on 100%
 * of inputs (`M3` — prevents `'İ'.toLowerCase()` -> `'i\u0307'` length expansion from shifting slice indices!).
 */
export function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) | 32));
}

export function isTagNameBoundary(ch: number): boolean {
  // space (0x20), tab (0x09), LF (0x0A), FF (0x0C), CR (0x0D), '/' (0x2F), '>' (0x3E) (`M3`)
  return ch === 32 || ch === 9 || ch === 10 || ch === 12 || ch === 13 || ch === 47 || ch === 62;
}

function isAsciiAlpha(ch: number): boolean {
  const lower = ch | 32;
  return lower >= 97 && lower <= 122;
}

function isTagNameChar(ch: number): boolean {
  const lower = ch | 32;
  return (lower >= 97 && lower <= 122) || (ch >= 48 && ch <= 57) || ch === 45 /* '-' */ || ch === 58 /* ':' */;
}

function markDeadTagScanPath(src: string, fromIdx: number, stopIdx: number, deadMask: Uint8Array): void {
  let state = 0; // 0 = unquoted, 1 = ", 2 = '
  for (let i = fromIdx; i < stopIdx; i++) {
    const bit = 1 << state;
    if ((deadMask[i]! & bit) !== 0) break;
    deadMask[i]! |= bit;
    const ch = src.charCodeAt(i);
    if (state === 1) {
      if (ch === 34) state = 0;
    } else if (state === 2) {
      if (ch === 39) state = 0;
    } else if (ch === 34) {
      state = 1;
    } else if (ch === 39) {
      state = 2;
    }
  }
}

/**
 * Quote-aware scan for closing `>` starting at `fromIdx` (`H1`).
 * When `deadRef` is provided, lazily allocates a 3-state `(unquoted, ", ')` memoization bitmask on the first
 * unclosed-tag failure so 24,000+ unclosed `<a href="` or `<span style="` tags run in guaranteed **O(N)** total time!
 */
export function findTagOpenEndQuoteAware(
  src: string,
  fromIdx: number,
  deadRef?: { mask?: Uint8Array },
): number {
  const existingMask = deadRef?.mask;
  if (existingMask && fromIdx < existingMask.length && (existingMask[fromIdx]! & 1) !== 0) {
    return -1;
  }
  let state = 0; // 0 = unquoted, 1 = ", 2 = '
  for (let i = fromIdx; i < src.length; i++) {
    if (existingMask && (existingMask[i]! & (1 << state)) !== 0) {
      markDeadTagScanPath(src, fromIdx, i, existingMask);
      return -1;
    }
    const ch = src.charCodeAt(i);
    if (state === 1) {
      if (ch === 34) state = 0;
    } else if (state === 2) {
      if (ch === 39) state = 0;
    } else if (ch === 34) {
      state = 1;
    } else if (ch === 39) {
      state = 2;
    } else if (ch === 62 /* '>' */) {
      return i;
    }
  }
  if (deadRef) {
    if (!deadRef.mask) deadRef.mask = new Uint8Array(src.length);
    markDeadTagScanPath(src, fromIdx, src.length, deadRef.mask);
  }
  return -1;
}

export interface ScannedHtmlTag {
  index: number;
  end: number; // exclusive index right after '>'
  rawTag: string;
  tagNameLower: string; // e.g. 'div', 'a', '!doctype', '?xml'
  isClosing: boolean;
  isSelfClosing: boolean;
  isDeclaration: boolean;
  attrs: string;
}

function tryParseTagAt(
  src: string,
  ltIdx: number,
  deadRef: { mask?: Uint8Array },
  allowDeclarations: boolean,
): ScannedHtmlTag | null {
  const len = src.length;
  if (ltIdx + 2 > len) return null;
  let p = ltIdx + 1;
  const first = src.charCodeAt(p);
  let isClosing = false;
  let isDeclaration = false;

  if (first === 47 /* '/' */) {
    isClosing = true;
    p++;
    if (p >= len || !isAsciiAlpha(src.charCodeAt(p))) return null;
  } else if (allowDeclarations && (first === 33 /* '!' */ || first === 63 /* '?' */)) {
    isDeclaration = true;
    p++;
    if (p >= len) return null;
    // Handle `<!-- ... -->` or `<![CDATA[ ... ]]>` or `<!DOCTYPE ...>` / `<?xml ...>`
    const declNext = src.charCodeAt(p);
    if (first === 33 && declNext === 45 && p + 1 < len && src.charCodeAt(p + 1) === 45) {
      const commentEnd = src.indexOf('-->', p + 2);
      if (commentEnd < 0) return null;
      const end = commentEnd + 3;
      return {
        index: ltIdx,
        end,
        rawTag: src.slice(ltIdx, end),
        tagNameLower: '!--',
        isClosing: false,
        isSelfClosing: true,
        isDeclaration: true,
        attrs: src.slice(p + 2, commentEnd),
      };
    }
    if (first === 33 && src.startsWith('[CDATA[', p)) {
      const cdataEnd = src.indexOf(']]>', p + 7);
      if (cdataEnd < 0) return null;
      const end = cdataEnd + 3;
      return {
        index: ltIdx,
        end,
        rawTag: src.slice(ltIdx, end),
        tagNameLower: '![cdata[',
        isClosing: false,
        isSelfClosing: true,
        isDeclaration: true,
        attrs: src.slice(p + 7, cdataEnd),
      };
    }
    if (!isAsciiAlpha(declNext)) return null;
  } else if (!isAsciiAlpha(first)) {
    return null;
  }

  const nameStart = isDeclaration ? ltIdx + 1 : p;
  p++;
  while (p < len && isTagNameChar(src.charCodeAt(p))) p++;
  if (p >= len || !isTagNameBoundary(src.charCodeAt(p))) return null;

  const openEnd = findTagOpenEndQuoteAware(src, p, deadRef);
  if (openEnd < 0) return null;

  const tagNameLower = asciiLower(src.slice(nameStart, p));
  const rawAttrs = src.slice(p, openEnd);
  const isSelfClosing = !isClosing && (isDeclaration || src.charCodeAt(openEnd - 1) === 47 /* '/' */);
  const attrs = !isClosing && !isDeclaration && isSelfClosing ? rawAttrs.slice(0, -1) : rawAttrs;
  return {
    index: ltIdx,
    end: openEnd + 1,
    rawTag: src.slice(ltIdx, openEnd + 1),
    tagNameLower,
    isClosing,
    isSelfClosing,
    isDeclaration,
    attrs,
  };
}

/**
 * General O(N) quote-aware HTML tag scanner (`H1`).
 * Never rescans unclosed `<tag ...` suffixes thanks to 3-state quote dead-path memoization.
 */
export function scanHtmlTagsLinear(
  rawHtml: string,
  onTag: (tag: ScannedHtmlTag) => void | boolean,
  maxChars = MAX_HTML_SCAN_CHARS,
  allowDeclarations = false,
): void {
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  const deadRef: { mask?: Uint8Array } = {};
  let pos = src.indexOf('<');
  while (pos >= 0 && pos < src.length) {
    const parsed = tryParseTagAt(src, pos, deadRef, allowDeclarations);
    if (!parsed) {
      // Fast bailout: if `deadRef.mask` just proved no unquoted `>` exists from a state-0 index, check if ANY `>` remains at all!
      if (deadRef.mask && src.indexOf('>', pos + 1) < 0) break;
      pos = src.indexOf('<', pos + 1);
      continue;
    }
    const cont = onTag(parsed);
    if (cont === false) break;
    pos = src.indexOf('<', parsed.end);
  }
}

/**
 * Linear O(N) quote-aware HTML tag replacer (`H1`).
 */
export function replaceHtmlTagsQuoteAwareLinear(
  rawHtml: string,
  replacer: (tag: ScannedHtmlTag) => string,
  maxChars = MAX_HTML_SCAN_CHARS,
  allowDeclarations = true,
): string {
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  if (src.indexOf('<') < 0) return src;
  const out: string[] = [];
  let cursor = 0;
  scanHtmlTagsLinear(
    src,
    (tag) => {
      if (tag.index > cursor) out.push(src.slice(cursor, tag.index));
      out.push(replacer(tag));
      cursor = tag.end;
    },
    maxChars,
    allowDeclarations,
  );
  if (cursor === 0) return src;
  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
}

/**
 * Linear O(N) drop-in replacement for `HTML_TAG_QUOTE_AWARE_RE` and `/<[^>]+>/g` (`H1`).
 */
export function stripHtmlTagsQuoteAwareLinear(
  rawHtml: string,
  replacement = '',
  maxChars = MAX_HTML_SCAN_CHARS,
): string {
  return replaceHtmlTagsQuoteAwareLinear(rawHtml, () => replacement, maxChars, true);
}

/**
 * Linear O(N) replacer for specific open/void tags (`<img>`, `<input>`, `<meta>`, `<link>`, `<br>`, `<hr>`, `<wbr>`).
 */
export function replaceHtmlOpenTagsLinear(
  rawHtml: string,
  tagNamesLower: ReadonlySet<string> | readonly string[],
  replacer: (tag: ScannedHtmlTag) => string,
  maxChars = MAX_HTML_SCAN_CHARS,
): string {
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  if (src.indexOf('<') < 0) return src;
  const targetSet = tagNamesLower instanceof Set ? tagNamesLower : new Set(tagNamesLower);
  const out: string[] = [];
  let cursor = 0;
  scanHtmlTagsLinear(
    src,
    (tag) => {
      if (tag.isClosing || tag.isDeclaration || !targetSet.has(tag.tagNameLower)) return;
      if (tag.index > cursor) out.push(src.slice(cursor, tag.index));
      out.push(replacer(tag));
      cursor = tag.end;
    },
    maxChars,
    false,
  );
  if (cursor === 0) return src;
  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
}

function findNextValidCloseTag(lower: string, src: string, closeNeedle: string, fromIdx: number): number {
  let closePos = lower.indexOf(closeNeedle, fromIdx);
  while (closePos >= 0) {
    const afterCloseName = closePos + closeNeedle.length;
    if (afterCloseName < src.length && isTagNameBoundary(src.charCodeAt(afterCloseName))) {
      return closePos;
    }
    closePos = lower.indexOf(closeNeedle, afterCloseName);
  }
  return -1;
}

/**
 * Linear O(N) paired-element replacer (`<a>...</a>`, `<pre>...</pre>`, `<h1..h6>`, `<math>`, `<figcaption>`, etc.).
 * Uses BOTH 3-state quote dead-path memoization AND monotonic per-tag close-position caching so unclosed tags,
 * unclosed quotes, `'<a><a>'.repeat(12000)`, and `maxInnerChars`-bounded elements run in guaranteed O(N) time (`H1`).
 */
export function replacePairedHtmlElementsLinear(
  rawHtml: string,
  tagNamesLower: readonly string[],
  replacer: (fullMatch: string, tagNameLower: string, attrs: string, innerHtml: string) => string,
  options?: { maxChars?: number; maxInnerChars?: number },
): string {
  const maxChars = options?.maxChars ?? MAX_HTML_SCAN_CHARS;
  const maxInnerChars = options?.maxInnerChars ?? MAX_HTML_SCAN_CHARS;
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  if (src.indexOf('<') < 0) return src;
  const lower = asciiLower(src);
  const targetSet = new Set(tagNamesLower);
  let hasAny = false;
  for (const t of targetSet) {
    if (lower.indexOf(`<${t}`) >= 0) {
      hasAny = true;
      break;
    }
  }
  if (!hasAny) return src;

  const deadRef: { mask?: Uint8Array } = {};
  // Monotonic cached close tag index per tag name (`-2` = uninitialized, `-1` = none left anywhere in `src`)
  const cachedCloseByTag = new Map<string, number>();
  for (const t of targetSet) cachedCloseByTag.set(t, -2);

  const out: string[] = [];
  let cursor = 0;
  let pos = src.indexOf('<');

  while (pos >= 0 && pos < src.length) {
    const parsed = tryParseTagAt(src, pos, deadRef, false);
    if (!parsed) {
      if (deadRef.mask && src.indexOf('>', pos + 1) < 0) break;
      pos = src.indexOf('<', pos + 1);
      continue;
    }
    if (parsed.isClosing || parsed.isDeclaration || !targetSet.has(parsed.tagNameLower)) {
      pos = src.indexOf('<', parsed.end);
      continue;
    }
    if (parsed.isSelfClosing) {
      if (parsed.index > cursor) out.push(src.slice(cursor, parsed.index));
      out.push(replacer(parsed.rawTag, parsed.tagNameLower, parsed.attrs, ''));
      cursor = parsed.end;
      pos = src.indexOf('<', cursor);
      continue;
    }

    const tag = parsed.tagNameLower;
    let closePos = cachedCloseByTag.get(tag) ?? -2;
    if (closePos !== -1 && closePos < parsed.end) {
      closePos = findNextValidCloseTag(lower, src, `</${tag}`, parsed.end);
      cachedCloseByTag.set(tag, closePos);
    }
    if (closePos < 0) {
      pos = src.indexOf('<', parsed.end);
      continue;
    }
    if (closePos - parsed.end > maxInnerChars) {
      pos = src.indexOf('<', parsed.end);
      continue;
    }
    const closeEnd = findTagOpenEndQuoteAware(src, closePos + 2 + tag.length, deadRef);
    if (closeEnd < 0) {
      cachedCloseByTag.set(tag, -1);
      pos = src.indexOf('<', parsed.end);
      continue;
    }
    if (parsed.index > cursor) out.push(src.slice(cursor, parsed.index));
    const inner = src.slice(parsed.end, closePos);
    out.push(replacer(src.slice(parsed.index, closeEnd + 1), tag, parsed.attrs, inner));
    cursor = closeEnd + 1;
    pos = src.indexOf('<', cursor);
  }

  if (cursor === 0) return src;
  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
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
 * Prevents quadratic `O(N^2)` backtracking when an adversarial HTML document contains 20,000+ unclosed `<noscript>` tags (`M4`),
 * and uses `asciiLower` + form-feed boundary (`M3`).
 */
export function replaceHtmlTagBlocksLinear(
  rawHtml: string,
  tagNameLower: string,
  replacer: (fullMatch: string, attrStr: string, innerHtml: string) => string,
  maxChars = MAX_HTML_SCAN_CHARS,
): string {
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  const lower = asciiLower(src);
  const openNeedle = `<${tagNameLower}`;
  const closeNeedle = `</${tagNameLower}`;
  let firstHit = lower.indexOf(openNeedle, 0);
  if (firstHit < 0) return src;

  const deadRef: { mask?: Uint8Array } = {};
  const out: string[] = [];
  let cursor = 0;
  let cachedClosePos = -2;

  while (firstHit >= 0) {
    const afterNameIdx = firstHit + openNeedle.length;
    if (afterNameIdx >= src.length || !isTagNameBoundary(src.charCodeAt(afterNameIdx))) {
      firstHit = lower.indexOf(openNeedle, afterNameIdx);
      continue;
    }
    const openEnd = findTagOpenEndQuoteAware(src, afterNameIdx, deadRef);
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

    if (cachedClosePos !== -1 && cachedClosePos < openEnd + 1) {
      cachedClosePos = findNextValidCloseTag(lower, src, closeNeedle, openEnd + 1);
    }

    if (cachedClosePos < 0) {
      if (tagNameLower === 'script' || tagNameLower === 'style') {
        cursor = src.length;
        break;
      }
      cursor = openEnd + 1;
      firstHit = lower.indexOf(openNeedle, cursor);
      continue;
    }

    const closeEnd = findTagOpenEndQuoteAware(src, cachedClosePos + closeNeedle.length, deadRef);
    if (closeEnd < 0) {
      cursor = src.length;
      break;
    }
    const inner = src.slice(openEnd + 1, cachedClosePos);
    out.push(replacer(src.slice(firstHit, closeEnd + 1), attrStr, inner));
    cursor = closeEnd + 1;
    firstHit = lower.indexOf(openNeedle, cursor);
  }

  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
}

/**
 * Strips all blocks for a list of HTML tags (`script`, `style`, `noscript`, `template`, `svg`, etc.) in guaranteed O(N) time (`M4` & `M3`).
 * Re-runs `script`/`style` once if stripping nested tags (`<scr<canvas></canvas>ipt>`) reassembled an executable tag.
 */
export function stripHtmlTagsLinear(
  rawHtml: string,
  tagNamesLower: readonly string[],
  replacement = '',
  maxChars = MAX_HTML_SCAN_CHARS,
): string {
  let cur = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  let wantsScript = false;
  let wantsStyle = false;
  for (const tag of tagNamesLower) {
    if (tag === 'script') wantsScript = true;
    if (tag === 'style') wantsStyle = true;
    cur = replaceHtmlTagBlocksLinear(cur, tag, () => replacement, maxChars);
  }
  if (wantsScript || wantsStyle) {
    for (let pass = 0; pass < 2; pass++) {
      const lower = asciiLower(cur);
      const hitScript = wantsScript && lower.indexOf('<script') >= 0;
      const hitStyle = wantsStyle && lower.indexOf('<style') >= 0;
      if (!hitScript && !hitStyle) break;
      if (hitScript) cur = replaceHtmlTagBlocksLinear(cur, 'script', () => replacement, maxChars);
      if (hitStyle) cur = replaceHtmlTagBlocksLinear(cur, 'style', () => replacement, maxChars);
    }
  }
  return cur;
}

/** Escapes all ECMAScript RegExp metacharacters in an untrusted literal string (`M5`). */
export function escapeRegexLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Validates and compiles a caller-supplied regular expression (`M4` / `M5`), rejecting:
 *  - Patterns > 160 chars
 *  - Backreferences (`\1`..`\9`, `\k<...>`) and lookbehinds (`(?<=`, `(?<!`)
 *  - ANY parenthesized group `(...)` followed by a quantifier (`+`, `*`, `?`, `{`) if the group body contains ANY
 *    quantifier (`?`, `*`, `+`, `{`), ANY alternation (`|`), OR can match the empty string (`minLen === 0`) —
 *    blocking `(a?a?)+$`, `(aa?)+$`, `([\w-]?[\w-]?)+#`, `(a\b?a?)+$`, `((a+))+$`, and `(a|aa)+$`!
 *  - Patterns with more than 1 unbounded quantifier (`*`, `+`, `{n,}`) anywhere in the pattern — blocking
 *    polynomial `a*a*a*a*b`, `\w*\w*\w*\w*#`, and `(?=(a+))a*b`!
 *  - Excessive bounded quantifiers / alternations (`> 10` total quantifiers or `> 10` alternations, or `{n,m}` > 32).
 */
export function compileSafeUserRegex(pattern: string, flags = ''): RegExp | null {
  if (!pattern || pattern.length > 160) return null;
  if (/\\[1-9]|\\k<|\(\?<[=!]/i.test(pattern)) return null;

  interface GroupFrame {
    isLookaround: boolean;
    hasQuantifier: boolean;
    hasAlternation: boolean;
    branchMinLen: number;
    minBranchLen: number;
    lastAtomMinLen: number;
    canQuantifyLastAtom: boolean;
  }

  const makeFrame = (isLookaround: boolean): GroupFrame => ({
    isLookaround,
    hasQuantifier: false,
    hasAlternation: false,
    branchMinLen: 0,
    minBranchLen: Number.POSITIVE_INFINITY,
    lastAtomMinLen: 0,
    canQuantifyLastAtom: false,
  });

  const stack: GroupFrame[] = [makeFrame(false)];
  let inCharClass = false;
  let unboundedQuantifiers = 0;
  let totalQuantifiers = 0;
  let totalAlternations = 0;

  const pushAtom = (minLen: number) => {
    const top = stack[stack.length - 1]!;
    top.branchMinLen += minLen;
    top.lastAtomMinLen = minLen;
    top.canQuantifyLastAtom = true;
  };

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === '\\') {
      if (i + 1 >= pattern.length) return null;
      const esc = pattern[i + 1]!;
      i++;
      if (!inCharClass) {
        // Word-boundary assertions `\b` / `\B` are zero-width (`minLen = 0`); other escapes match >= 1 char.
        if (esc === 'b' || esc === 'B') {
          const top = stack[stack.length - 1]!;
          top.lastAtomMinLen = 0;
          top.canQuantifyLastAtom = true;
        } else {
          pushAtom(1);
        }
      }
      continue;
    }
    if (inCharClass) {
      if (ch === ']') {
        inCharClass = false;
        pushAtom(1);
      }
      continue;
    }
    if (ch === '[') {
      inCharClass = true;
      continue;
    }
    if (ch === '^' || ch === '$') {
      const top = stack[stack.length - 1]!;
      top.lastAtomMinLen = 0;
      top.canQuantifyLastAtom = true;
      continue;
    }
    if (ch === '(') {
      const next = pattern[i + 1] ?? '';
      if (next === '?') {
        const mod = pattern[i + 2] ?? '';
        if (mod === ':' || mod === '=' || mod === '!') {
          stack.push(makeFrame(mod === '=' || mod === '!'));
          i += 2;
          continue;
        }
        if (mod === '<') {
          const closeAngle = pattern.indexOf('>', i + 3);
          if (closeAngle < 0) return null;
          const name = pattern.slice(i + 3, closeAngle);
          if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) return null;
          stack.push(makeFrame(false));
          i = closeAngle;
          continue;
        }
        return null;
      }
      stack.push(makeFrame(false));
      continue;
    }
    if (ch === '|') {
      totalAlternations++;
      if (totalAlternations > 10) return null;
      const top = stack[stack.length - 1]!;
      top.hasAlternation = true;
      top.minBranchLen = Math.min(top.minBranchLen, top.branchMinLen);
      top.branchMinLen = 0;
      top.lastAtomMinLen = 0;
      top.canQuantifyLastAtom = false;
      continue;
    }
    if (ch === ')') {
      if (stack.length <= 1) return null; // unbalanced ')'
      const closed = stack.pop()!;
      const groupMinLen = closed.isLookaround ? 0 : Math.min(closed.minBranchLen, closed.branchMinLen);
      const next = pattern[i + 1] ?? '';
      const groupIsQuantified = next === '+' || next === '*' || next === '?' || next === '{';
      if (groupIsQuantified) {
        if (closed.isLookaround || closed.hasQuantifier || closed.hasAlternation || groupMinLen === 0) {
          return null;
        }
      }
      const parent = stack[stack.length - 1]!;
      if (closed.hasQuantifier) parent.hasQuantifier = true;
      if (closed.hasAlternation) parent.hasAlternation = true;
      parent.branchMinLen += groupMinLen;
      parent.lastAtomMinLen = groupMinLen;
      parent.canQuantifyLastAtom = !closed.isLookaround;
      continue;
    }
    if (ch === '+' || ch === '*' || ch === '?') {
      const top = stack[stack.length - 1]!;
      if (!top.canQuantifyLastAtom) return null;
      totalQuantifiers++;
      if (totalQuantifiers > 10) return null;
      if (ch === '+' || ch === '*') {
        unboundedQuantifiers++;
        if (unboundedQuantifiers > 1) return null;
      }
      if (ch === '*' || ch === '?') {
        top.branchMinLen -= top.lastAtomMinLen;
        top.lastAtomMinLen = 0;
      }
      top.hasQuantifier = true;
      top.canQuantifyLastAtom = false;
      // Optional lazy modifier (`*?`, `+?`, `??`)
      if (pattern[i + 1] === '?') {
        i++;
      }
      const after = pattern[i + 1] ?? '';
      if (after === '+' || after === '*' || after === '?' || after === '{') return null;
      continue;
    }
    if (ch === '{') {
      const braceMatch = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(i));
      if (!braceMatch) {
        // Non-quantifier literal `{`
        pushAtom(1);
        continue;
      }
      const top = stack[stack.length - 1]!;
      if (!top.canQuantifyLastAtom) return null;
      const minRep = Number(braceMatch[1]);
      const rawMax = braceMatch[2];
      if (!Number.isFinite(minRep) || minRep > 32) return null;
      totalQuantifiers++;
      if (totalQuantifiers > 10) return null;
      if (rawMax === '') {
        unboundedQuantifiers++;
        if (unboundedQuantifiers > 1) return null;
      } else if (rawMax !== undefined) {
        const maxRep = Number(rawMax);
        if (!Number.isFinite(maxRep) || maxRep < minRep || maxRep > 32) return null;
      }
      // Adjust minimum branch length from 1x atom to `minRep`x atom
      top.branchMinLen += (minRep - 1) * top.lastAtomMinLen;
      if (minRep === 0) top.lastAtomMinLen = 0;
      top.hasQuantifier = true;
      top.canQuantifyLastAtom = false;
      i += braceMatch[0].length - 1;
      if (pattern[i + 1] === '?') {
        i++;
      }
      const after = pattern[i + 1] ?? '';
      if (after === '+' || after === '*' || after === '?' || after === '{') return null;
      continue;
    }
    pushAtom(1);
  }
  if (stack.length !== 1 || inCharClass) return null;

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
