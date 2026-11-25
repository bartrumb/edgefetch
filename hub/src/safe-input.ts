/**
 * Linear-time HTML scanners, ReDoS-proof regex validation, bounded request-body streaming,
 * and IPv6 `/64` rate-limit key canonicalization (`hub/src/safe-input.ts`).
 */

import { compileWasmRe2, type WasmRe2Compiled } from './wasm-bridge';

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
 * Decodes a URI component without throwing an uncaught `URIError` on malformed percent-encoding (`%zz`, `%E0%A4%A`).
 */
export function safeDecodeURIComponent(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/**
 * ASCII-only lowercasing (`A-Z` -> `a-z`) that strictly preserves UTF-16 `.length` and 1:1 code-unit offsets on 100%
 * of inputs (`M3` — prevents `'İ'.toLowerCase()` -> `'i\u0307'` length expansion from shifting slice indices!).
 */
export function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) | 32));
}

export function isTagNameBoundary(ch: number): boolean {
  // space (0x20), tab (0x09), LF (0x0A), VT (0x0B), FF (0x0C), CR (0x0D), '/' (0x2F), '>' (0x3E) (`M3` & `R3-H2`)
  return ch === 32 || ch === 9 || ch === 10 || ch === 11 || ch === 12 || ch === 13 || ch === 47 || ch === 62;
}

function isAsciiAlpha(ch: number): boolean {
  const lower = ch | 32;
  return lower >= 97 && lower <= 122;
}

export interface ScannerDeadState {
  mask?: Uint8Array;
  noCommentCloseFrom?: number;
  noCdataCloseFrom?: number;
  nextStdCommentClose?: number;
  nextBangCommentClose?: number;
  nextCdataClose?: number;
  nextGtPos?: number;
  nextNameBoundary?: number;
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
  deadRef?: ScannerDeadState,
): number {
  if (deadRef?.nextGtPos === -1) return -1;
  if (deadRef && (deadRef.nextGtPos === undefined || deadRef.nextGtPos < fromIdx)) {
    const gt = src.indexOf('>', fromIdx);
    deadRef.nextGtPos = gt;
    if (gt < 0) return -1;
  } else if (!deadRef && src.indexOf('>', fromIdx) < 0) {
    return -1;
  }
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

/**
 * Finds the exclusive end index (right after `>`) of an HTML5 comment starting with `<!--` at `ltIdx` (`R3-H1`).
 * Handles WHATWG HTML5 abrupt comments (`<!-->`, `<!--->`), bang-closed comments (`--!>`), and standard `-->`
 * with monotonic + dead-path memoization so `'<!--'.repeat(70_000)` runs in guaranteed **O(N)** (`< 5ms`) time!
 */
function findHtmlCommentCloseEnd(src: string, ltIdx: number, deadRef: ScannerDeadState): number {
  const bodyStart = ltIdx + 4;
  const len = src.length;
  if (bodyStart < len && src.charCodeAt(bodyStart) === 62 /* '>' */) {
    return bodyStart + 1;
  }
  if (bodyStart + 1 < len && src.charCodeAt(bodyStart) === 45 /* '-' */ && src.charCodeAt(bodyStart + 1) === 62 /* '>' */) {
    return bodyStart + 2;
  }
  if (deadRef.noCommentCloseFrom !== undefined && bodyStart >= deadRef.noCommentCloseFrom) {
    return -1;
  }
  let stdIdx = deadRef.nextStdCommentClose ?? -2;
  if (stdIdx !== -1 && stdIdx < bodyStart) {
    stdIdx = src.indexOf('-->', bodyStart);
    deadRef.nextStdCommentClose = stdIdx;
  }
  let bangIdx = deadRef.nextBangCommentClose ?? -2;
  if (bangIdx !== -1 && bangIdx < bodyStart) {
    bangIdx = src.indexOf('--!>', bodyStart);
    deadRef.nextBangCommentClose = bangIdx;
  }
  if (stdIdx < 0 && bangIdx < 0) {
    if (deadRef.noCommentCloseFrom === undefined || bodyStart < deadRef.noCommentCloseFrom) {
      deadRef.noCommentCloseFrom = bodyStart;
    }
    return -1;
  }
  if (stdIdx >= 0 && (bangIdx < 0 || stdIdx <= bangIdx)) {
    return stdIdx + 3;
  }
  return bangIdx + 4;
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
  deadRef: ScannerDeadState,
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
    // Handle `<!-- ... -->` / `<!-->` / `<!--->` / `--!>` or `<![CDATA[ ... ]]>` or `<!DOCTYPE ...>` / `<?xml ...>`
    const declNext = src.charCodeAt(p);
    if (first === 33 && declNext === 45 && p + 1 < len && src.charCodeAt(p + 1) === 45) {
      const end = findHtmlCommentCloseEnd(src, ltIdx, deadRef);
      if (end < 0) return null;
      const bodyStart = ltIdx + 4;
      const innerEnd = end <= bodyStart + 2 ? bodyStart : src.charCodeAt(end - 2) === 33 /* '!' */ ? end - 4 : end - 3;
      return {
        index: ltIdx,
        end,
        rawTag: src.slice(ltIdx, end),
        tagNameLower: '!--',
        isClosing: false,
        isSelfClosing: true,
        isDeclaration: true,
        attrs: innerEnd > bodyStart ? src.slice(bodyStart, innerEnd) : '',
      };
    }
    if (first === 33 && declNext === 91 /* '[' */ && src.startsWith('[CDATA[', p)) {
      const afterCdata = p + 7;
      if (deadRef.noCdataCloseFrom !== undefined && afterCdata >= deadRef.noCdataCloseFrom) {
        return null;
      }
      let cdataEnd = deadRef.nextCdataClose ?? -2;
      if (cdataEnd !== -1 && cdataEnd < afterCdata) {
        cdataEnd = src.indexOf(']]>', afterCdata);
        deadRef.nextCdataClose = cdataEnd;
      }
      if (cdataEnd < 0) {
        if (deadRef.noCdataCloseFrom === undefined || afterCdata < deadRef.noCdataCloseFrom) {
          deadRef.noCdataCloseFrom = afterCdata;
        }
        return null;
      }
      const end = cdataEnd + 3;
      return {
        index: ltIdx,
        end,
        rawTag: src.slice(ltIdx, end),
        tagNameLower: '![cdata[',
        isClosing: false,
        isSelfClosing: true,
        isDeclaration: true,
        attrs: src.slice(afterCdata, cdataEnd),
      };
    }
    if (!isAsciiAlpha(declNext)) return null;
  } else if (!isAsciiAlpha(first)) {
    return null;
  }

  const nameStart = isDeclaration ? ltIdx + 1 : p;
  p++;
  // HTML5 Tag Name state (`R3-H2` & `R4-H1`): once `<` + ASCII alpha opens a tag, ALL characters up to a tag-name boundary
  // (`\t`, `\n`, `\v`, `\f`, `\r`, `' '`, `'/'`, `'>'`) belong to this single tag name, with monotonic boundary caching so `'<x'.repeat(8000)` runs in O(N).
  let nameEnd = deadRef.nextNameBoundary ?? -2;
  if (nameEnd !== -1 && nameEnd < p) {
    let q = p;
    while (q < len && !isTagNameBoundary(src.charCodeAt(q))) q++;
    nameEnd = q < len ? q : -1;
    deadRef.nextNameBoundary = nameEnd;
  }
  if (nameEnd === -1) return null;
  p = nameEnd;

  // HTML5 End Tag state (`R3-H2`): closing tags `</tag ...>` close at the FIRST `>` without parsing quoted attributes!
  const openEnd = isClosing ? src.indexOf('>', p) : findTagOpenEndQuoteAware(src, p, deadRef);
  if (openEnd < 0) {
    if (isClosing) deadRef.nextGtPos = -1;
    return null;
  }

  const rawName = src.slice(nameStart, p);
  const cleanName = rawName.indexOf('\u0000') >= 0 ? rawName.replace(/\u0000/g, '') : rawName;
  const tagNameLower = asciiLower(cleanName);
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
 * Prevents split-tag reassembly (`R3-H2`: `<<form></form>img src=x onerror=alert(1)>` or `<im<form></form>g ...>`)
 * whenever a tag/element/comment is deleted with an empty string `''`. If the accumulated output ends with an
 * unclosed `<` tag-open prefix (`<`, `</`, `<!`, `<?`, or `<tagchars` with no `>`/whitespace/quote), escapes that
 * trailing `<` to `&lt;` unless `deferReassemblySet` contains the resulting tag name (so nested `<scr<style></style>ipt>`
 * inside `stripHtmlTagsLinear` still collapses and strips the outer `<script>...</script>` block completely!).
 */
function guardSplitTagReassemblyOnEmptyRemoval(
  out: string[],
  nextSuffix: string,
  deferReassemblySet?: ReadonlySet<string>,
): void {
  if (!nextSuffix) return;
  let chunkIdx = out.length - 1;
  while (chunkIdx >= 0 && out[chunkIdx]!.length === 0) chunkIdx--;
  if (chunkIdx < 0) return;
  const tail = out[chunkIdx]!;
  const minScan = Math.max(0, tail.length - 64);
  let ltPos = -1;
  for (let i = tail.length - 1; i >= minScan; i--) {
    const ch = tail.charCodeAt(i);
    if (ch === 62 /* '>' */ || ch === 34 /* '"' */ || ch === 39 /* "'" */ || ch === 61 /* '=' */) {
      return;
    }
    if (ch === 32 || ch === 9 || ch === 10 || ch === 11 || ch === 12 || ch === 13) {
      return;
    }
    if (ch === 60 /* '<' */) {
      ltPos = i;
      break;
    }
  }
  if (ltPos < 0) return;

  if (deferReassemblySet && deferReassemblySet.size > 0) {
    const prefixAfterLt = tail.slice(ltPos + 1);
    const combined = asciiLower((prefixAfterLt + nextSuffix.slice(0, 24)).replace(/\u0000/g, ''));
    const checkStart = combined.startsWith('/') ? 1 : 0;
    for (const target of deferReassemblySet) {
      if (combined.startsWith(target, checkStart)) {
        const afterIdx = checkStart + target.length;
        if (afterIdx < combined.length && isTagNameBoundary(combined.charCodeAt(afterIdx))) {
          return;
        }
      }
    }
  }

  out[chunkIdx] = `${tail.slice(0, ltPos)}&lt;${tail.slice(ltPos + 1)}`;
}

/**
 * General O(N) quote-aware HTML tag scanner (`H1` & `R3-H1`).
 * Never rescans unclosed `<tag ...`, `<!--`, or `<![CDATA[` suffixes thanks to dead-path memoization.
 */
export function scanHtmlTagsLinear(
  rawHtml: string,
  onTag: (tag: ScannedHtmlTag) => void | boolean,
  maxChars = MAX_HTML_SCAN_CHARS,
  allowDeclarations = false,
): void {
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  const deadRef: ScannerDeadState = {};
  let pos = src.indexOf('<');
  while (pos >= 0 && pos < src.length) {
    if (deadRef.nextGtPos === -1) break;
    const parsed = tryParseTagAt(src, pos, deadRef, allowDeclarations);
    if (!parsed) {
      if (deadRef.mask || deadRef.noCommentCloseFrom !== undefined || deadRef.noCdataCloseFrom !== undefined || deadRef.nextGtPos === -1) {
        if (deadRef.nextGtPos === undefined || (deadRef.nextGtPos !== -1 && deadRef.nextGtPos <= pos)) {
          deadRef.nextGtPos = src.indexOf('>', pos + 1);
        }
        if (deadRef.nextGtPos < 0) break;
      }
      if (allowDeclarations && pos + 3 < src.length && src.charCodeAt(pos + 1) === 33) {
        if (src.charCodeAt(pos + 2) === 45 && src.charCodeAt(pos + 3) === 45) {
          pos = src.indexOf('<', pos + 4);
          continue;
        }
        if (src.charCodeAt(pos + 2) === 91 && src.startsWith('[CDATA[', pos + 2)) {
          pos = src.indexOf('<', pos + 9);
          continue;
        }
      }
      pos = src.indexOf('<', pos + 1);
      continue;
    }
    const cont = onTag(parsed);
    if (cont === false) break;
    pos = src.indexOf('<', parsed.end);
  }
}

/**
 * Linear O(N) quote-aware HTML tag replacer (`H1` & `R3-H2`).
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
      const rep = replacer(tag);
      if (rep === '' && tag.end < src.length) {
        guardSplitTagReassemblyOnEmptyRemoval(out, src.slice(tag.end, tag.end + 24));
      } else {
        out.push(rep);
      }
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
      const rep = replacer(tag);
      if (rep === '' && tag.end < src.length) {
        guardSplitTagReassemblyOnEmptyRemoval(out, src.slice(tag.end, tag.end + 24));
      } else {
        out.push(rep);
      }
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
 * unclosed quotes, `'<a><a>'.repeat(12000)`, and `maxInnerChars`-bounded elements run in guaranteed O(N) time (`H1` & `R3-H2`).
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

  const deadRef: ScannerDeadState = {};
  // Monotonic cached close tag index per tag name (`-2` = uninitialized, `-1` = none left anywhere in `src`)
  const cachedCloseByTag = new Map<string, number>();
  for (const t of targetSet) cachedCloseByTag.set(t, -2);

  const out: string[] = [];
  let cursor = 0;
  let pos = src.indexOf('<');

  while (pos >= 0 && pos < src.length) {
    const parsed = tryParseTagAt(src, pos, deadRef, false);
    if (!parsed) {
      if (deadRef.mask || deadRef.nextGtPos === -1) {
        if (deadRef.nextGtPos === undefined || (deadRef.nextGtPos !== -1 && deadRef.nextGtPos <= pos)) {
          deadRef.nextGtPos = src.indexOf('>', pos + 1);
        }
        if (deadRef.nextGtPos < 0) break;
      }
      pos = src.indexOf('<', pos + 1);
      continue;
    }
    if (parsed.isClosing || parsed.isDeclaration || !targetSet.has(parsed.tagNameLower)) {
      pos = src.indexOf('<', parsed.end);
      continue;
    }
    if (parsed.isSelfClosing) {
      if (parsed.index > cursor) out.push(src.slice(cursor, parsed.index));
      const rep = replacer(parsed.rawTag, parsed.tagNameLower, parsed.attrs, '');
      if (rep === '' && parsed.end < src.length) {
        guardSplitTagReassemblyOnEmptyRemoval(out, src.slice(parsed.end, parsed.end + 24));
      } else {
        out.push(rep);
      }
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
    // HTML5 End Tag state (`R3-H2`): closing tags close at the FIRST `>`, never swallowing quoted attributes across later elements!
    const closeEnd = src.indexOf('>', closePos + 2 + tag.length);
    if (closeEnd < 0) {
      cachedCloseByTag.set(tag, -1);
      pos = src.indexOf('<', parsed.end);
      continue;
    }
    if (parsed.index > cursor) out.push(src.slice(cursor, parsed.index));
    const inner = src.slice(parsed.end, closePos);
    const rep = replacer(src.slice(parsed.index, closeEnd + 1), tag, parsed.attrs, inner);
    if (rep === '' && closeEnd + 1 < src.length) {
      guardSplitTagReassemblyOnEmptyRemoval(out, src.slice(closeEnd + 1, closeEnd + 25));
    } else {
      out.push(rep);
    }
    cursor = closeEnd + 1;
    pos = src.indexOf('<', cursor);
  }

  if (cursor === 0) return src;
  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
}

const DANGEROUS_BLOCK_TAG_SET: ReadonlySet<string> = new Set([
  'script',
  'style',
  'noscript',
  'template',
  'iframe',
  'svg',
  'object',
  'embed',
]);

/**
 * Pure `indexOf` O(N) HTML comment stripper (`<!-- ... -->`, `<!-->`, `<!--->`, `--!>`) with dead-path memoization
 * (`M4` & `R3-H1`) and without swallowing the rest of the document on unterminated `<!--` tokens.
 */
export function stripHtmlCommentsLinear(rawHtml: string, maxChars = MAX_HTML_SCAN_CHARS): string {
  const src = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  let pos = src.indexOf('<!--');
  if (pos < 0) return src;
  const deadRef: ScannerDeadState = {};
  const out: string[] = [];
  let cursor = 0;
  while (pos >= 0) {
    const closeEnd = findHtmlCommentCloseEnd(src, pos, deadRef);
    if (closeEnd < 0) {
      // Unterminated `<!--`: no `-->` or `--!>` exists anywhere after `pos + 4`. Jump directly to any abrupt `<!-->` / `<!--->` if present!
      const abrupt1 = src.indexOf('<!-->', pos + 4);
      const abrupt2 = src.indexOf('<!--->', pos + 4);
      if (abrupt1 < 0 && abrupt2 < 0) break;
      pos = abrupt1 >= 0 && (abrupt2 < 0 || abrupt1 <= abrupt2) ? abrupt1 : abrupt2;
      continue;
    }
    if (pos > cursor) out.push(src.slice(cursor, pos));
    if (closeEnd < src.length) {
      guardSplitTagReassemblyOnEmptyRemoval(out, src.slice(closeEnd, closeEnd + 24), DANGEROUS_BLOCK_TAG_SET);
    }
    cursor = closeEnd;
    pos = src.indexOf('<!--', cursor);
  }
  if (cursor === 0) return src;
  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
}

const STRAY_NUL_PRESERVING_EF_SENTINEL_RE =
  /\u0000(?!EF[A-Z]{2,12}\d{0,7}\u0000)(?<!\u0000EF[A-Z]{2,12}\d{0,7}\u0000)/g;

function stripStrayNulsPreservingEfSentinels(s: string): string {
  return s.indexOf('\u0000') >= 0 ? s.replace(STRAY_NUL_PRESERVING_EF_SENTINEL_RE, '') : s;
}

/**
 * Pure `indexOf` O(N) HTML element replacer/stripper for a single tag (`<noscript>`, `<iframe>`, `<script>`).
 * Prevents quadratic `O(N^2)` backtracking when an adversarial HTML document contains 20,000+ unclosed `<noscript>` tags (`M4`),
 * uses `asciiLower` + vertical-tab/form-feed boundaries, strips NULs (preserving internal `EF...` stash sentinels, `R4-M7`), and prevents split-tag `<img` reassembly (`R3-H2`).
 */
export function replaceHtmlTagBlocksLinear(
  rawHtml: string,
  tagNameLower: string,
  replacer: (fullMatch: string, attrStr: string, innerHtml: string) => string,
  maxChars = MAX_HTML_SCAN_CHARS,
  deferReassemblySet?: ReadonlySet<string>,
): string {
  const capped = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  const src = stripStrayNulsPreservingEfSentinels(capped);
  const lower = asciiLower(src);
  const openNeedle = `<${tagNameLower}`;
  const closeNeedle = `</${tagNameLower}`;
  let firstHit = lower.indexOf(openNeedle, 0);
  if (firstHit < 0) return src;

  const deadRef: ScannerDeadState = {};
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
    if (firstHit > cursor) out.push(src.slice(cursor, firstHit));
    const attrStr = src.slice(afterNameIdx, openEnd);
    if (src.charCodeAt(openEnd - 1) === 47 /* self-closing '/>' */) {
      const rep = replacer(src.slice(firstHit, openEnd + 1), attrStr.slice(0, -1), '');
      if (rep === '' && openEnd + 1 < src.length) {
        guardSplitTagReassemblyOnEmptyRemoval(out, src.slice(openEnd + 1, openEnd + 25), deferReassemblySet);
      } else {
        out.push(rep);
      }
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

    // HTML5 End Tag state (`R3-H2`): closing tags close at the FIRST `>`, not quote-parsed attributes.
    const closeEnd = src.indexOf('>', cachedClosePos + closeNeedle.length);
    if (closeEnd < 0) {
      cursor = src.length;
      break;
    }
    const inner = src.slice(openEnd + 1, cachedClosePos);
    const rep = replacer(src.slice(firstHit, closeEnd + 1), attrStr, inner);
    if (rep === '' && closeEnd + 1 < src.length) {
      guardSplitTagReassemblyOnEmptyRemoval(out, src.slice(closeEnd + 1, closeEnd + 25), deferReassemblySet);
    } else {
      out.push(rep);
    }
    cursor = closeEnd + 1;
    firstHit = lower.indexOf(openNeedle, cursor);
  }

  if (cursor < src.length) out.push(src.slice(cursor));
  return out.join('');
}

/**
 * Strips all blocks for a list of HTML tags (`script`, `style`, `noscript`, `template`, `svg`, etc.) in guaranteed O(N) time (`M4`, `M3`, `R3-H2`).
 * Strips NUL bytes, prevents split-tag `<img` reassembly on non-target tags, and iterates to fixed point on reassembled target tags (`<sc<st...`).
 */
export function stripHtmlTagsLinear(
  rawHtml: string,
  tagNamesLower: readonly string[],
  replacement = '',
  maxChars = MAX_HTML_SCAN_CHARS,
): string {
  const capped = rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  let cur = stripStrayNulsPreservingEfSentinels(capped);
  if (cur.indexOf('<') < 0 || tagNamesLower.length === 0) return cur;
  const targetSet = new Set(tagNamesLower.map((t) => asciiLower(t)));
  const deferSet = replacement === '' ? targetSet : undefined;
  const initialLower = asciiLower(cur);
  let changedAny = false;

  for (const tag of targetSet) {
    if (initialLower.indexOf(`<${tag}`) < 0) continue;
    const next = replaceHtmlTagBlocksLinear(cur, tag, () => replacement, maxChars, deferSet);
    if (next !== cur) {
      cur = next;
      changedAny = true;
    }
  }

  if (changedAny && replacement === '' && targetSet.size > 0) {
    for (let pass = 0; pass < 8; pass++) {
      const prevLen = cur.length;
      const lower = asciiLower(cur);
      let matchedAny = false;
      for (const tag of targetSet) {
        if (lower.indexOf(`<${tag}`) >= 0) {
          matchedAny = true;
          cur = replaceHtmlTagBlocksLinear(cur, tag, () => replacement, maxChars, deferSet);
        }
      }
      if (!matchedAny || cur.length === prevLen) break;
    }
  }
  return cur;
}

/**
 * Linear O(N) CommonMark-aware sanitizer (`R3-H2`) that escapes any residual `<` followed by `[A-Za-z/!?]`
 * outside fenced code blocks (` ``` ` / ` ~~~ `) and closed inline backtick code spans (`` `...` ``) as `&lt;`.
 */
export function escapeResidualHtmlTagsOutsideCode(
  markdown: string,
  maxChars = MAX_HTML_SCAN_CHARS,
): string {
  if (!markdown || markdown.indexOf('<') < 0) return markdown;
  const src = markdown.length > maxChars ? markdown.slice(0, maxChars) : markdown;
  const len = src.length;
  const out: string[] = [];
  let cursor = 0;
  let i = 0;
  let atLineStart = true;

  // Monotonic per-backtick-run-length cursors (`<= 32` chars) so 200k unclosed backticks run in guaranteed O(N) time!
  const cachedTickPos = new Map<number, number>();
  const scannedTickTo = new Map<number, number>();
  let nextParaBreak = -2;

  const isCodeSpanBreakingLineAt = (lineStart: number): boolean => {
    let p = lineStart;
    while (p < len && (src.charCodeAt(p) === 32 || src.charCodeAt(p) === 9)) p++;
    if (p >= len || src.charCodeAt(p) === 10 || src.charCodeAt(p) === 13) return true; // blank line
    const leadSpaces = p - lineStart;
    const c = src.charCodeAt(p);
    // Blockquote, ATX heading, code fence (`<= 3` spaces)
    if (leadSpaces <= 3) {
      if (c === 62 /* '>' */) return true;
      if (c === 35 /* '#' */) {
        let h = p;
        while (h < len && src.charCodeAt(h) === 35 && h - p < 7) h++;
        if (h - p <= 6 && (h >= len || src.charCodeAt(h) === 32 || src.charCodeAt(h) === 9 || src.charCodeAt(h) === 10 || src.charCodeAt(h) === 13)) {
          return true;
        }
      }
      if (c === 96 /* '`' */ || c === 126 /* '~' */) {
        let f = p + 1;
        while (f < len && src.charCodeAt(f) === c) f++;
        if (f - p >= 3) return true;
      }
      // Setext underline (`===` / `---`) or thematic break (`***`, `---`, `___`)
      if (c === 61 /* '=' */ || c === 45 /* '-' */ || c === 42 /* '*' */ || c === 95 /* '_' */) {
        let q = p;
        let sameCount = 0;
        let onlyMarkerAndWs = true;
        while (q < len && src.charCodeAt(q) !== 10 && src.charCodeAt(q) !== 13) {
          const qc = src.charCodeAt(q);
          if (qc === c) sameCount++;
          else if ((c === 61 || qc !== 32) && qc !== 9) {
            onlyMarkerAndWs = false;
            break;
          }
          q++;
        }
        if (onlyMarkerAndWs && ((c === 61 || c === 45) ? sameCount >= 1 : sameCount >= 3)) {
          return true;
        }
      }
    }
    // Unordered (`- `, `* `, `+ `) or ordered (`1. `, `1) `) list item
    if (c === 45 /* '-' */ || c === 42 /* '*' */ || c === 43 /* '+' */) {
      if (p + 1 < len && (src.charCodeAt(p + 1) === 32 || src.charCodeAt(p + 1) === 9)) return true;
    } else if (c >= 48 && c <= 57) {
      let d = p + 1;
      while (d < len && d - p < 9 && src.charCodeAt(d) >= 48 && src.charCodeAt(d) <= 57) d++;
      if (d < len && (src.charCodeAt(d) === 46 /* '.' */ || src.charCodeAt(d) === 41 /* ')' */)) {
        if (d + 1 < len && (src.charCodeAt(d + 1) === 32 || src.charCodeAt(d + 1) === 9)) return true;
      }
    }
    return false;
  };

  const findParaBreakFrom = (fromIdx: number): number => {
    if (nextParaBreak !== -1 && nextParaBreak < fromIdx) {
      let search = fromIdx;
      nextParaBreak = -1;
      while (search < len) {
        const nl = src.indexOf('\n', search);
        if (nl < 0) break;
        if (nl + 1 < len && isCodeSpanBreakingLineAt(nl + 1)) {
          nextParaBreak = nl;
          break;
        }
        search = nl + 1;
      }
    }
    return nextParaBreak;
  };

  const findClosingBacktickRun = (tickLen: number, fromIdx: number): number => {
    if (tickLen > 32) return -1;
    let pos = cachedTickPos.get(tickLen) ?? -2;
    while (pos !== -1 && pos < fromIdx) {
      let search = Math.max(fromIdx, scannedTickTo.get(tickLen) ?? 0);
      pos = -1;
      while (search < len) {
        const hit = src.indexOf('`', search);
        if (hit < 0) {
          scannedTickTo.set(tickLen, len);
          break;
        }
        let end = hit + 1;
        while (end < len && src.charCodeAt(end) === 96 /* '`' */) end++;
        const runLen = end - hit;
        scannedTickTo.set(tickLen, end);
        if (runLen === tickLen && (hit === 0 || src.charCodeAt(hit - 1) !== 96)) {
          pos = hit;
          break;
        }
        search = end;
      }
      cachedTickPos.set(tickLen, pos);
    }
    return pos;
  };

  while (i < len) {
    if (atLineStart) {
      let indent = 0;
      while (indent < 3 && i + indent < len && src.charCodeAt(i + indent) === 32) indent++;
      const fPos = i + indent;
      const fCh = fPos < len ? src.charCodeAt(fPos) : 0;
      if ((fCh === 96 /* '`' */ || fCh === 126 /* '~' */) && (fPos >= len || src.charCodeAt(fPos) !== 32)) {
        let fEnd = fPos + 1;
        while (fEnd < len && src.charCodeAt(fEnd) === fCh) fEnd++;
        const fenceLen = fEnd - fPos;
        if (fenceLen >= 3) {
          const lineEnd = src.indexOf('\n', fEnd);
          const infoEnd = lineEnd < 0 ? len : lineEnd;
          // In CommonMark, backtick fence info strings cannot contain backticks
          const validFenceOpen = fCh === 126 || src.slice(fEnd, infoEnd).indexOf('`') < 0;
          if (validFenceOpen && lineEnd >= 0) {
            let scanLine = lineEnd + 1;
            let closedEnd = -1;
            let dedentedAmbiguous = false;
            while (scanLine < len) {
              const nextNl = src.indexOf('\n', scanLine);
              const lEnd = nextNl < 0 ? len : nextNl;
              let wsCols = 0;
              let wsPos = scanLine;
              while (wsPos < lEnd && src.charCodeAt(wsPos) === 32) {
                wsCols++;
                wsPos++;
              }
              const isBlankLine = wsPos === lEnd || (wsPos + 1 === lEnd && src.charCodeAt(wsPos) === 13);
              if (!isBlankLine && indent > 0 && wsCols < indent) {
                // Indented fence followed by dedented line may close container fence in nested CommonMark contexts; fail closed!
                dedentedAmbiguous = true;
                break;
              }
              if (wsCols <= 3) {
                let cPos = scanLine + wsCols;
                let cTicks = 0;
                while (cPos < lEnd && src.charCodeAt(cPos) === fCh) {
                  cTicks++;
                  cPos++;
                }
                if (cTicks >= fenceLen) {
                  while (
                    cPos < lEnd &&
                    (src.charCodeAt(cPos) === 32 || src.charCodeAt(cPos) === 9 || src.charCodeAt(cPos) === 13)
                  ) {
                    cPos++;
                  }
                  if (cPos === lEnd) {
                    closedEnd = nextNl < 0 ? len : nextNl + 1;
                    break;
                  }
                }
              }
              if (nextNl < 0) break;
              scanLine = nextNl + 1;
            }
            if (!dedentedAmbiguous && closedEnd >= 0) {
              i = closedEnd;
              atLineStart = true;
              continue;
            }
          }
        }
      }
      atLineStart = false;
    }

    const ch = src.charCodeAt(i);
    if (ch === 10 /* '\n' */) {
      atLineStart = true;
      i++;
      continue;
    }
    if (ch === 96 /* '`' */) {
      let bs = 0;
      let bp = i - 1;
      while (bp >= 0 && src.charCodeAt(bp) === 92 /* '\\' */) {
        bs++;
        bp--;
      }
      if ((bs & 1) === 1) {
        i++;
        continue;
      }
      let tEnd = i + 1;
      while (tEnd < len && src.charCodeAt(tEnd) === 96) tEnd++;
      const tickLen = tEnd - i;
      const closeHit = findClosingBacktickRun(tickLen, tEnd);
      if (closeHit >= tEnd) {
        const paraBreak = findParaBreakFrom(tEnd);
        if (paraBreak < 0 || closeHit < paraBreak) {
          i = closeHit + tickLen;
          continue;
        }
      }
      i = tEnd;
      continue;
    }
    if (ch === 60 /* '<' */ && i + 1 < len) {
      const next = src.charCodeAt(i + 1);
      if (isAsciiAlpha(next) || next === 47 /* '/' */ || next === 33 /* '!' */ || next === 63 /* '?' */) {
        if (i > cursor) out.push(src.slice(cursor, i));
        out.push('&lt;');
        cursor = i + 1;
      }
    }
    i++;
  }

  if (cursor === 0 && markdown.length <= maxChars) return markdown;
  if (cursor < len) out.push(src.slice(cursor));
  if (markdown.length > maxChars) {
    // Also escape any `<` in the tail beyond `maxChars` without code-span tracking so >2MiB markdown never passes raw `<tag`
    out.push(markdown.slice(maxChars).replace(/<(?=[A-Za-z/!?])/g, '&lt;'));
  }
  return out.join('');
}

/** Escapes all ECMAScript RegExp metacharacters in an untrusted literal string (`M5`). */
export function escapeRegexLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

interface RegexCharset {
  lo: bigint; // ASCII 0..63
  hi: bigint; // ASCII 64..127
  nonAscii: boolean;
}

const CS_MASK64 = (1n << 64n) - 1n;
const EMPTY_CHARSET: RegexCharset = { lo: 0n, hi: 0n, nonAscii: false };
const ALL_CHARSET: RegexCharset = { lo: CS_MASK64, hi: CS_MASK64, nonAscii: true };

function csUnion(a: RegexCharset, b: RegexCharset): RegexCharset {
  return { lo: a.lo | b.lo, hi: a.hi | b.hi, nonAscii: a.nonAscii || b.nonAscii };
}

function csDisjoint(a: RegexCharset, b: RegexCharset): boolean {
  return (a.lo & b.lo) === 0n && (a.hi & b.hi) === 0n && !(a.nonAscii && b.nonAscii);
}

function csSingleBit(code: number): RegexCharset {
  if (code < 0 || code >= 128) return { lo: 0n, hi: 0n, nonAscii: true };
  if (code < 64) return { lo: 1n << BigInt(code), hi: 0n, nonAscii: false };
  return { lo: 0n, hi: 1n << BigInt(code - 64), nonAscii: false };
}

function csFromChar(code: number, ignoreCase: boolean, unicodeMode: boolean): RegexCharset {
  if (code >= 128) {
    // Under `/iu`, `\u017f` ('ſ') and `\u212a` ('K') fold to ASCII 's' and 'k'
    if (ignoreCase && unicodeMode && (code === 0x017f || code === 0x212a)) {
      return ALL_CHARSET;
    }
    return { lo: 0n, hi: 0n, nonAscii: true };
  }
  let cs = csSingleBit(code);
  if (ignoreCase) {
    const lower = code | 32;
    if (lower >= 97 && lower <= 122) {
      cs = csUnion(cs, csSingleBit(code ^ 32));
    }
  }
  return cs;
}

function csRange(fromCode: number, toCode: number, ignoreCase: boolean, unicodeMode: boolean): RegexCharset {
  let acc = EMPTY_CHARSET;
  const hiBound = Math.min(toCode, 127);
  for (let c = Math.max(0, fromCode); c <= hiBound; c++) {
    acc = csUnion(acc, csFromChar(c, ignoreCase, unicodeMode));
  }
  if (toCode >= 128) {
    acc = csUnion(acc, csFromChar(toCode, ignoreCase, unicodeMode));
    acc = { lo: acc.lo, hi: acc.hi, nonAscii: true };
  }
  return acc;
}

const CS_DIGITS = csRange(48, 57, false, false);
const CS_NOT_DIGITS: RegexCharset = { lo: (~CS_DIGITS.lo) & CS_MASK64, hi: (~CS_DIGITS.hi) & CS_MASK64, nonAscii: true };
const CS_WORD_ASCII = csUnion(
  csUnion(csRange(65, 90, false, false), csRange(97, 122, false, false)),
  csUnion(CS_DIGITS, csSingleBit(95 /* '_' */)),
);
const CS_SPACE_ASCII: RegexCharset = {
  lo: (1n << 9n) | (1n << 10n) | (1n << 11n) | (1n << 12n) | (1n << 13n) | (1n << 32n),
  hi: 0n,
  nonAscii: true,
};
const CS_NOT_SPACE: RegexCharset = {
  lo: (~CS_SPACE_ASCII.lo) & CS_MASK64,
  hi: CS_MASK64,
  nonAscii: true,
};

type RegexNode =
  | { kind: 'anchor'; isCaret: boolean; isDollar: boolean }
  | { kind: 'atom'; cs: RegexCharset; isLiteral: boolean }
  | {
      kind: 'group';
      groupKind: 'normal' | 'pos_lookahead' | 'neg_lookahead';
      branches: RegexItem[][];
      hasQuantifier: boolean;
      hasLookaround: boolean;
      hasUnbounded: boolean;
      minLen: number;
      maxLen: number;
      firstCs: RegexCharset;
      allCs: RegexCharset;
    };

interface RegexItem {
  node: RegexNode;
  quantified: boolean;
  min: number;
  max: number; // Number.POSITIVE_INFINITY for unbounded
  minLen: number;
  maxLen: number;
  firstCs: RegexCharset;
  allCs: RegexCharset;
}

const MAX_LINEAR_REGEX_LEN = 512;
const MAX_LINEAR_REGEX_SUBJECT_LEN = 32_768;
const MAX_USER_REGEX_LEN = 256;
const MAX_USER_REGEX_SUBJECT_LEN = 2048;
const MAX_RE2_LRU_ENTRIES = 512;

const JS_SPACE_RE2_RANGES =
  '\\t\\n\\v\\f\\r \\x{00a0}\\x{1680}\\x{2000}-\\x{200a}\\x{2028}\\x{2029}\\x{202f}\\x{205f}\\x{3000}\\x{feff}';
const JS_NOT_SPACE_RE2_RANGES =
  '\\x00-\\x08\\x0e-\\x1f\\x21-\\x{009f}\\x{00a1}-\\x{167f}\\x{1681}-\\x{1fff}\\x{200b}-\\x{2027}\\x{202a}-\\x{202e}\\x{2030}-\\x{205e}\\x{2060}-\\x{2fff}\\x{3001}-\\x{fefe}\\x{ff00}-\\x{10ffff}';

const re2InstanceLru = new Map<string, WasmRe2Compiled | null>();
const linearRegexLru = new Map<string, RegExp | null>();
const safeUserRegexLru = new Map<string, RegExp | null>();
const safeUnionMatcherLru = new Map<string, ((subject: string) => boolean) | null>();

function lruGet<V>(map: Map<string, V>, key: string): { hit: true; value: V } | { hit: false } {
  if (!map.has(key)) return { hit: false };
  const val = map.get(key) as V;
  map.delete(key);
  map.set(key, val);
  return { hit: true, value: val };
}

function lruSet<V>(map: Map<string, V>, key: string, value: V, maxEntries = MAX_RE2_LRU_ENTRIES): void {
  if (map.has(key)) map.delete(key);
  else if (map.size >= maxEntries) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.set(key, value);
}

function isHexChar(ch: string): boolean {
  return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
}

function translateJsEscapesBase(data: string): string {
  if (data.length === 0) return '(?:)';
  let result = '';
  let inCharClass = false;
  let i = 0;
  const size = data.length;
  while (i < size) {
    const ch = data[i]!;
    if (ch === '\\') {
      if (i + 1 >= size) return `${result}\\`;
      const esc = data[i + 1]!;
      if (esc === '\\') {
        result += '\\\\';
        i += 2;
        continue;
      }
      if (esc === 'c') {
        if (i + 2 < size) {
          const code = data.charCodeAt(i + 2);
          if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
            const val = code % 32;
            result += `\\x${val.toString(16).padStart(2, '0').toUpperCase()}`;
            i += 3;
            continue;
          }
        }
        result += 'c';
        i += 2;
        continue;
      }
      if (esc === 'u') {
        if (i + 2 < size && data[i + 2] === '{') {
          let j = i + 3;
          let hasHex = false;
          let closed = false;
          while (j < size) {
            const hc = data[j]!;
            if (hc === '}') {
              closed = true;
              break;
            }
            if (!isHexChar(hc)) break;
            hasHex = true;
            j++;
          }
          if (closed && hasHex) {
            result += '\\x';
            i += 2;
            continue;
          }
        } else if (
          i + 5 < size &&
          isHexChar(data[i + 2]!) &&
          isHexChar(data[i + 3]!) &&
          isHexChar(data[i + 4]!) &&
          isHexChar(data[i + 5]!)
        ) {
          result += `\\x{${data.slice(i + 2, i + 6)}}`;
          i += 6;
          continue;
        }
        result += 'u';
        i += 2;
        continue;
      }
      if (esc === 'x') {
        let validHex = false;
        if (i + 2 < size && data[i + 2] === '{') {
          let j = i + 3;
          let hasHex = false;
          while (j < size && isHexChar(data[j]!)) {
            hasHex = true;
            j++;
          }
          if (hasHex && j < size && data[j] === '}') validHex = true;
        } else if (i + 3 < size && isHexChar(data[i + 2]!) && isHexChar(data[i + 3]!)) {
          validHex = true;
        }
        result += validHex ? '\\x' : 'x';
        i += 2;
        continue;
      }
      if ('nrtfvadDsSwWbBpPAzQE01234567'.includes(esc)) {
        result += `\\${esc}`;
        i += 2;
        continue;
      }
      const cp = data.codePointAt(i + 1)!;
      const symSize = cp > 0xffff ? 2 : 1;
      if ((cp >= 48 && cp <= 57) || (cp >= 65 && cp <= 90) || (cp >= 97 && cp <= 122)) {
        result += data.slice(i + 1, i + 1 + symSize);
      } else {
        result += `\\${data.slice(i + 1, i + 1 + symSize)}`;
      }
      i += 1 + symSize;
      continue;
    }
    if (ch === '[') {
      if (!inCharClass && data[i + 1] === ']') {
        result += '[^\\x00-\\x{10FFFF}]';
        i += 2;
        continue;
      }
      if (!inCharClass && data[i + 1] === '^' && data[i + 2] === ']') {
        result += '[\\x00-\\x{10FFFF}]';
        i += 3;
        continue;
      }
      inCharClass = true;
    } else if (ch === ']') {
      inCharClass = false;
    } else if (!inCharClass && ch === '(' && data[i + 1] === '?' && data[i + 2] === '<') {
      if (i + 3 < size && !'=!)>'.includes(data[i + 3]!)) {
        result += '(?P<';
        i += 3;
        continue;
      }
    }
    const cp = data.codePointAt(i)!;
    const symSize = cp > 0xffff ? 2 : 1;
    result += data.slice(i, i + symSize);
    i += symSize;
  }
  return result;
}

function translateJsPatternForRe2(effectivePattern: string, seenFlags: ReadonlySet<string>): string | null {
  const dotAll = seenFlags.has('s');
  const unicodeMode = seenFlags.has('u');
  // Reject JS lookaheads upfront before delegating to Go RE2 (`(?=...)`, `(?!...)`)
  for (let k = 0; k + 2 < effectivePattern.length; k++) {
    if (effectivePattern[k] === '\\') {
      k++;
      continue;
    }
    if (effectivePattern[k] === '(' && effectivePattern[k + 1] === '?' && (effectivePattern[k + 2] === '=' || effectivePattern[k + 2] === '!')) {
      return null;
    }
  }
  const base = translateJsEscapesBase(effectivePattern).replace(/\\0(?![0-7])/g, '\\x00');
  let out = '';
  let inClass = false;
  let classStart = -1;
  let i = 0;
  const len = base.length;

  while (i < len) {
    const c = base[i]!;
    if (c === '\\') {
      if (i + 1 >= len) return null;
      const next = base[i + 1]!;
      if (next === 's') {
        out += inClass ? JS_SPACE_RE2_RANGES : `[${JS_SPACE_RE2_RANGES}]`;
        i += 2;
        continue;
      }
      if (next === 'S') {
        out += inClass ? JS_NOT_SPACE_RE2_RANGES : `[^${JS_SPACE_RE2_RANGES}]`;
        i += 2;
        continue;
      }
      if (next === 'A' || next === 'z' || next === 'Q' || next === 'E') {
        if (unicodeMode) return null;
        out += next;
        i += 2;
        continue;
      }
      if ((next === 'p' || next === 'P') && base[i + 2] === '{') {
        if (!unicodeMode) {
          // Without `/u`, `\p{L}` in JS is literal `p{L}` (`{L}` is literal `{L}`)
          out += next;
          i += 2;
          continue;
        }
        const closeBrace = base.indexOf('}', i + 3);
        if (closeBrace > i + 2) {
          out += base.slice(i, closeBrace + 1);
          i += closeBrace - i + 1;
          continue;
        }
      }
      if (next === 'x' && base[i + 2] === '{') {
        const closeBrace = base.indexOf('}', i + 3);
        if (closeBrace > i + 2) {
          out += base.slice(i, closeBrace + 1);
          i = closeBrace + 1;
          continue;
        }
      }
      out += base.slice(i, i + 2);
      i += 2;
      continue;
    }

    if (!inClass) {
      if (c === '[') {
        inClass = true;
        classStart = i;
        out += '[';
        i++;
        continue;
      }
      if (c === '.' && !dotAll) {
        out += '[^\\r\\n\\x{2028}\\x{2029}]';
        i++;
        continue;
      }
      out += c;
      i++;
      continue;
    }

    const isInitialCloseBracket =
      i === classStart + 1 || (i === classStart + 2 && base[classStart + 1] === '^');
    if (c === ']' && !isInitialCloseBracket) {
      inClass = false;
      classStart = -1;
      out += ']';
      i++;
      continue;
    }
    if (c === '[' && base[i + 1] === ':') {
      out += '[\\:';
      i += 2;
      continue;
    }
    out += c;
    i++;
  }

  return inClass ? null : out;
}

function extractMandatoryLiteralHint(effectivePattern: string, ignoreCase: boolean): string {
  // Sound fast-path prefilter: extract longest unquantified top-level literal run when there is NO top-level `|` alternation.
  let parenDepth = 0;
  let inClass = false;
  let classStart = -1;
  let best = '';
  let cur = '';

  const commitCur = () => {
    if (cur.length >= 2 && cur.length > best.length) {
      if (!ignoreCase || !/[A-Za-z]/.test(cur)) {
        best = cur;
      }
    }
    cur = '';
  };

  const isFollowedByQuantifier = (afterIdx: number): boolean => {
    if (afterIdx >= effectivePattern.length) return false;
    const qc = effectivePattern[afterIdx]!;
    if (qc === '*' || qc === '?' || qc === '+') return true;
    if (qc === '{' && /^\{\d+(?:,\d*)?\}/.test(effectivePattern.slice(afterIdx))) return true;
    return false;
  };

  for (let i = 0; i < effectivePattern.length; i++) {
    const c = effectivePattern[i]!;
    if (inClass) {
      if (c === '\\') {
        i++;
        continue;
      }
      const initial = i === classStart + 1 || (i === classStart + 2 && effectivePattern[classStart + 1] === '^');
      if (c === ']' && !initial) {
        inClass = false;
      }
      continue;
    }
    if (c === '[') {
      commitCur();
      inClass = true;
      classStart = i;
      continue;
    }
    if (c === '(') {
      commitCur();
      parenDepth++;
      continue;
    }
    if (c === ')') {
      commitCur();
      if (parenDepth > 0) parenDepth--;
      continue;
    }
    if (parenDepth > 0) continue;
    if (c === '|') return ''; // top-level alternation -> no mandatory global literal

    if (c === '\\') {
      if (i + 1 >= effectivePattern.length) break;
      const esc = effectivePattern[i + 1]!;
      i++;
      if ('/.:=-_~@#%'.includes(esc) && !isFollowedByQuantifier(i + 1)) {
        cur += esc;
      } else {
        commitCur();
      }
      continue;
    }

    if ('^$.*+?{}[]()\\'.includes(c)) {
      commitCur();
      continue;
    }

    const code = c.charCodeAt(0);
    if (code >= 32 && code < 127 && !isFollowedByQuantifier(i + 1)) {
      if (!ignoreCase || (code < 65 || (code > 90 && code < 97) || code > 122)) {
        cur += c;
      } else {
        commitCur();
      }
    } else {
      commitCur();
    }
  }
  commitCur();
  return best;
}

function hasExcessiveBoundedRepetition(pattern: string, maxExpandedUnits = 256): boolean {
  let inClass = false;
  let classStart = -1;
  const groupCostStack: number[] = [0];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '\\') {
      i++;
      continue;
    }
    if (inClass) {
      const initial = i === classStart + 1 || (i === classStart + 2 && pattern[classStart + 1] === '^');
      if (c === ']' && !initial) inClass = false;
      continue;
    }
    if (c === '[') {
      inClass = true;
      classStart = i;
      groupCostStack[groupCostStack.length - 1]! += 1;
      continue;
    }
    if (c === '(') {
      groupCostStack.push(0);
      continue;
    }
    if (c === ')') {
      const innerCost = Math.max(1, groupCostStack.length > 1 ? groupCostStack.pop()! : 1);
      const bm = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(i + 1));
      if (bm) {
        const minN = Number(bm[1]);
        const maxN = bm[2] === undefined ? minN : bm[2] === '' ? minN : Number(bm[2]);
        if (minN > 64 || maxN > 64) return true;
        const prod = innerCost * Math.max(1, maxN);
        if (prod > maxExpandedUnits) return true;
        groupCostStack[groupCostStack.length - 1]! += prod;
        i += bm[0].length;
      } else {
        groupCostStack[groupCostStack.length - 1]! += innerCost;
      }
      if (groupCostStack[groupCostStack.length - 1]! > maxExpandedUnits) return true;
      continue;
    }
    if (c === '{') {
      const bm = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(i));
      if (bm) {
        const minN = Number(bm[1]);
        const maxN = bm[2] === undefined ? minN : bm[2] === '' ? minN : Number(bm[2]);
        if (minN > 64 || maxN > 64) return true;
        groupCostStack[groupCostStack.length - 1]! += Math.max(1, maxN);
        if (groupCostStack[groupCostStack.length - 1]! > maxExpandedUnits) return true;
        i += bm[0].length - 1;
        continue;
      }
    }
  }
  return false;
}

function buildRe2RegExp(
  rawSource: string,
  effectivePattern: string,
  seenFlags: ReadonlySet<string>,
  maxSubjectLen: number,
): RegExp | null {
  if (seenFlags.has('y')) return null;
  const ignoreCase = seenFlags.has('i');
  let re2Prefix = '';
  if (ignoreCase) re2Prefix += 'i';
  if (seenFlags.has('m')) re2Prefix += 'm';
  if (seenFlags.has('s')) re2Prefix += 's';

  const canonicalFlags = ['d', 'g', 'i', 'm', 's', 'u', 'y'].filter((f) => seenFlags.has(f)).join('');
  const re2CacheKey = `${effectivePattern}\u0000${canonicalFlags}\u0000${maxSubjectLen}`;

  try {
    let compiled: WasmRe2Compiled | null;
    const cachedRe2 = lruGet(re2InstanceLru, re2CacheKey);
    if (cachedRe2.hit) {
      compiled = cachedRe2.value;
    } else {
      const translated = translateJsPatternForRe2(effectivePattern, seenFlags);
      if (translated === null) {
        lruSet(re2InstanceLru, re2CacheKey, null);
        return null;
      }
      const fullRe2 = re2Prefix ? `(?${re2Prefix})${translated}` : translated;
      compiled = compileWasmRe2(fullRe2);
      lruSet(re2InstanceLru, re2CacheKey, compiled);
    }
    if (!compiled) return null;
    const literalHint = extractMandatoryLiteralHint(effectivePattern, ignoreCase);
    let lastSubj = '\u0000__UNSET__';
    let lastRes = false;

    const regExpLike = {
      source: rawSource,
      flags: canonicalFlags,
      global: seenFlags.has('g'),
      ignoreCase,
      multiline: seenFlags.has('m'),
      dotAll: seenFlags.has('s'),
      unicode: seenFlags.has('u'),
      sticky: false,
      hasIndices: seenFlags.has('d'),
      lastIndex: 0,
      test(subject: string): boolean {
        if (typeof subject !== 'string' || subject.length > maxSubjectLen) return false;
        if (subject === lastSubj) return lastRes;
        if (literalHint && subject.indexOf(literalHint) < 0) {
          lastSubj = subject;
          lastRes = false;
          return false;
        }
        const ok = compiled.test(subject);
        lastSubj = subject;
        lastRes = ok;
        return ok;
      },
      exec(subject: string): RegExpExecArray | null {
        if (typeof subject !== 'string' || subject.length > maxSubjectLen) return null;
        if (literalHint && subject.indexOf(literalHint) < 0) return null;
        return compiled.exec(subject) as RegExpExecArray | null;
      },
      toString(): string {
        return `/${rawSource}/${canonicalFlags}`;
      },
    };
    return regExpLike as unknown as RegExp;
  } catch {
    return null;
  }
}

/**
 * Compiles a regular expression up to `512` chars using Google's `RE2JS` DFA/NFA engine (`O(N)` worst-case time,
 * `subject.length <= 32_768`, LRU-cached across calls, never invoking V8's backtracking `RegExp`).
 */
export function compileLinearRegex(pattern: string, flags = ''): RegExp | null {
  if (typeof pattern !== 'string' || !pattern || pattern.length > MAX_LINEAR_REGEX_LEN) return null;
  if (typeof flags !== 'string' || flags.length > 8) return null;

  const cacheKey = `${pattern}\u0000${flags}`;
  const cached = lruGet(linearRegexLru, cacheKey);
  if (cached.hit) return cached.value;

  if (/\\[1-9]|\\k<|\(\?<[=!]/i.test(pattern) || hasExcessiveBoundedRepetition(pattern, 256)) {
    lruSet(linearRegexLru, cacheKey, null);
    return null;
  }

  let effectivePattern = pattern;
  let effectiveFlags = flags;
  if (effectivePattern.startsWith('(?i)')) {
    effectivePattern = effectivePattern.slice(4);
    if (!effectivePattern) {
      lruSet(linearRegexLru, cacheKey, null);
      return null;
    }
    if (!effectiveFlags.includes('i')) effectiveFlags += 'i';
  }

  const seenFlags = new Set<string>();
  for (const f of effectiveFlags) {
    if (!'dgimsuy'.includes(f) || seenFlags.has(f)) {
      lruSet(linearRegexLru, cacheKey, null);
      return null;
    }
    seenFlags.add(f);
  }

  const built = buildRe2RegExp(pattern, effectivePattern, seenFlags, MAX_LINEAR_REGEX_SUBJECT_LEN);
  lruSet(linearRegexLru, cacheKey, built);
  return built;
}

/**
 * Compiles an array of already-validated safe crawl regex patterns into a single `RE2JS` union DFA
 * so `includePaths` / `excludePaths` evaluate 20+ patterns per URL in a single `O(N)` DFA pass (`M10`).
 */
export function compileSafeUserRegexUnion(
  patterns: readonly string[],
  maxSubjectLen = MAX_USER_REGEX_SUBJECT_LEN,
): ((subject: string) => boolean) | null {
  if (patterns.length === 0) return () => false;
  if (patterns.length === 1) {
    const single = compileSafeUserRegex(patterns[0]!);
    if (!single) return null;
    return (subject: string) => single.test(subject);
  }
  const cacheKey = `${maxSubjectLen}\u0000${patterns.join('\u0000')}`;
  const cached = lruGet(safeUnionMatcherLru, cacheKey);
  if (cached.hit) return cached.value;

  const branches: string[] = [];
  for (const raw of patterns) {
    if (!compileSafeUserRegex(raw)) {
      lruSet(safeUnionMatcherLru, cacheKey, null, 128);
      return null;
    }
    let eff = raw;
    const seen = new Set<string>();
    if (eff.startsWith('(?i)')) {
      eff = eff.slice(4);
      seen.add('i');
    }
    const translated = translateJsPatternForRe2(eff, seen);
    if (translated === null) {
      lruSet(safeUnionMatcherLru, cacheKey, null, 128);
      return null;
    }
    branches.push(seen.has('i') ? `(?i:${translated})` : `(?:${translated})`);
  }

  try {
    const unionRe2 = compileWasmRe2(`(?:${branches.join('|')})`);
    if (!unionRe2) throw new Error('union compile failed');
    const matcherFn = (subject: string): boolean => {
      if (typeof subject !== 'string' || subject.length > maxSubjectLen) return false;
      return unionRe2.test(subject);
    };
    lruSet(safeUnionMatcherLru, cacheKey, matcherFn, 128);
    return matcherFn;
  } catch {
    const fallbackRefs = patterns.map((p) => compileSafeUserRegex(p)).filter((r): r is RegExp => r !== null);
    if (fallbackRefs.length !== patterns.length) {
      lruSet(safeUnionMatcherLru, cacheKey, null, 128);
      return null;
    }
    const fallbackFn = (subject: string): boolean => fallbackRefs.some((r) => r.test(subject));
    lruSet(safeUnionMatcherLru, cacheKey, fallbackFn, 128);
    return fallbackFn;
  }
}

// Validates and compiles a caller-supplied regular expression (`M4`, `M5`, `R3-H3`) via structural AST precheck +
// `RE2JS` linear-time Thompson NFA execution (`O(N)` guarantee, zero V8 backtracking `RegExp`), supporting leading `(?i)`
// and disjoint-delimiter multi-segment patterns (`^/[^/]+/[^/]+$`, `/[a-z]+/[a-z]+/`, `/release-notes/v\d+\.\d+\.\d+`,
// `.*/blog/.*`, `^/blog/.*/comments/.*$`, `^/a/(b|c)?$`) while rejecting:
//  - Patterns > 256 chars, invalid/duplicate flags, `v` unicodeSets flag, backreferences, and lookbehinds
//  - Star-height >= 2 (groups repeated `>= 2` times containing inner quantifiers, alternations, lookarounds, or `minLen === 0`)
//  - Bounded-quantifier & alternation towers (`a{0,32}` x 3+, `a*a?a?a?`, `(aa){1,32}` x 5, lookahead towers) via `branchProduct > 64`
//  - Overlapping multi-wildcard polynomial patterns (`a*a*b`, `.*.*.*`, `\d+\d+\d+$`, `.*.{0,32}{4}X`).
export function compileSafeUserRegex(pattern: string, flags = ''): RegExp | null {
  if (typeof pattern !== 'string' || !pattern || pattern.length > MAX_USER_REGEX_LEN) return null;
  if (typeof flags !== 'string' || flags.length > 8) return null;
  const cacheKey = `${pattern}\u0000${flags}`;
  const cached = lruGet(safeUserRegexLru, cacheKey);
  if (cached.hit) return cached.value;
  const built = compileSafeUserRegexUncached(pattern, flags);
  lruSet(safeUserRegexLru, cacheKey, built);
  return built;
}

function compileSafeUserRegexUncached(pattern: string, flags = ''): RegExp | null {
  if (typeof pattern !== 'string' || !pattern || pattern.length > MAX_USER_REGEX_LEN) return null;
  if (typeof flags !== 'string' || flags.length > 8) return null;

  let effectivePattern = pattern;
  let effectiveFlags = flags;
  if (effectivePattern.startsWith('(?i)')) {
    effectivePattern = effectivePattern.slice(4);
    if (!effectivePattern) return null;
    if (!effectiveFlags.includes('i')) effectiveFlags += 'i';
  }

  // Validate RegExp flags (`v` disallowed to keep character-class grammar unambiguous)
  const seenFlags = new Set<string>();
  for (const f of effectiveFlags) {
    if (!'dgimsuy'.includes(f) || seenFlags.has(f)) return null;
    seenFlags.add(f);
  }

  if (/\\[1-9]|\\k<|\(\?<[=!]/i.test(effectivePattern)) return null;

  const ignoreCase = seenFlags.has('i');
  const unicodeMode = seenFlags.has('u');
  const dotAll = seenFlags.has('s');
  const multiline = seenFlags.has('m');

  const wordCs: RegexCharset = ignoreCase && unicodeMode ? { ...CS_WORD_ASCII, nonAscii: true } : CS_WORD_ASCII;
  const notWordCs: RegexCharset =
    ignoreCase && unicodeMode
      ? ALL_CHARSET
      : { lo: (~CS_WORD_ASCII.lo) & CS_MASK64, hi: (~CS_WORD_ASCII.hi) & CS_MASK64, nonAscii: true };
  const dotCs: RegexCharset = dotAll
    ? ALL_CHARSET
    : { lo: CS_MASK64 & ~((1n << 10n) | (1n << 13n)), hi: CS_MASK64, nonAscii: true };

  let totalQuantifiers = 0;
  let totalAlternations = 0;
  let pos = 0;
  const len = effectivePattern.length;

  const parseEscapeOutsideOrInside = (inClass: boolean): { ok: true; isAssertion?: boolean; cs: RegexCharset; isLiteral: boolean } | { ok: false } => {
    // Assumes `effectivePattern[pos] === '\\'`
    pos++;
    if (pos >= len) return { ok: false };
    const esc = effectivePattern[pos]!;
    pos++;
    if (!inClass && (esc === 'b' || esc === 'B')) {
      return { ok: true, isAssertion: true, cs: EMPTY_CHARSET, isLiteral: false };
    }
    if (esc === 'd') return { ok: true, cs: CS_DIGITS, isLiteral: false };
    if (esc === 'D') return { ok: true, cs: CS_NOT_DIGITS, isLiteral: false };
    if (esc === 'w') return { ok: true, cs: wordCs, isLiteral: false };
    if (esc === 'W') return { ok: true, cs: notWordCs, isLiteral: false };
    if (esc === 's') return { ok: true, cs: CS_SPACE_ASCII, isLiteral: false };
    if (esc === 'S') return { ok: true, cs: CS_NOT_SPACE, isLiteral: false };
    if (esc === 't') return { ok: true, cs: csSingleBit(9), isLiteral: true };
    if (esc === 'n') return { ok: true, cs: csSingleBit(10), isLiteral: true };
    if (esc === 'v') return { ok: true, cs: csSingleBit(11), isLiteral: true };
    if (esc === 'f') return { ok: true, cs: csSingleBit(12), isLiteral: true };
    if (esc === 'r') return { ok: true, cs: csSingleBit(13), isLiteral: true };
    if (esc === '0') return { ok: true, cs: csSingleBit(0), isLiteral: true };
    if (esc === 'x') {
      const hex = effectivePattern.slice(pos, pos + 2);
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        pos += 2;
        return { ok: true, cs: csFromChar(parseInt(hex, 16), ignoreCase, unicodeMode), isLiteral: true };
      }
      return { ok: true, cs: csFromChar(120 /* 'x' */, ignoreCase, unicodeMode), isLiteral: true };
    }
    if (esc === 'u') {
      if (effectivePattern[pos] === '{') {
        const closeBrace = effectivePattern.indexOf('}', pos + 1);
        if (closeBrace > pos + 1) {
          const hex = effectivePattern.slice(pos + 1, closeBrace);
          if (/^[0-9A-Fa-f]{1,6}$/.test(hex)) {
            const cp = parseInt(hex, 16);
            if (cp <= 0x10ffff) {
              pos = closeBrace + 1;
              return { ok: true, cs: csFromChar(cp, ignoreCase, unicodeMode), isLiteral: true };
            }
          }
        }
      } else {
        const hex = effectivePattern.slice(pos, pos + 4);
        if (/^[0-9A-Fa-f]{4}$/.test(hex)) {
          pos += 4;
          return { ok: true, cs: csFromChar(parseInt(hex, 16), ignoreCase, unicodeMode), isLiteral: true };
        }
      }
      return { ok: true, cs: csFromChar(117 /* 'u' */, ignoreCase, unicodeMode), isLiteral: true };
    }
    if ((esc === 'p' || esc === 'P') && effectivePattern[pos] === '{') {
      const closeBrace = effectivePattern.indexOf('}', pos + 1);
      if (closeBrace < 0) return { ok: false };
      if (unicodeMode) {
        pos = closeBrace + 1;
        return { ok: true, cs: ALL_CHARSET, isLiteral: false };
      }
      // Without `/u`, `\p` is literal `'p'` and `{...}` is parsed next in main loop
      return { ok: true, cs: csFromChar(esc.charCodeAt(0), ignoreCase, unicodeMode), isLiteral: true };
    }
    if (esc === 'c') {
      if (pos < len && isAsciiAlpha(effectivePattern.charCodeAt(pos))) {
        const ctrl = effectivePattern.charCodeAt(pos) & 31;
        pos++;
        return { ok: true, cs: csSingleBit(ctrl), isLiteral: true };
      }
      return { ok: true, cs: ALL_CHARSET, isLiteral: false };
    }
    return { ok: true, cs: csFromChar(esc.charCodeAt(0), ignoreCase, unicodeMode), isLiteral: true };
  };

  const parseCharClass = (): RegexCharset | null => {
    // Assumes `effectivePattern[pos] === '['`
    pos++;
    if (pos >= len) return null;
    let negated = false;
    if (effectivePattern[pos] === '^') {
      negated = true;
      pos++;
    }
    let acc = EMPTY_CHARSET;
    let hasComplexInsideNegated = false;

    const readClassElem = (): { kind: 'char'; code: number; cs: RegexCharset } | { kind: 'set'; cs: RegexCharset } | null => {
      if (pos >= len) return null;
      const c = effectivePattern[pos]!;
      if (c === '\\') {
        const save = pos;
        const escRes = parseEscapeOutsideOrInside(true);
        if (!escRes.ok) return null;
        const rawEsc = effectivePattern[save + 1]!;
        if ('dDwWsSpP'.includes(rawEsc)) {
          if (negated && 'DWS'.includes(rawEsc) || rawEsc === 'p' || rawEsc === 'P') {
            hasComplexInsideNegated = true;
          }
          return { kind: 'set', cs: escRes.cs };
        }
        if (rawEsc === 't') return { kind: 'char', code: 9, cs: escRes.cs };
        if (rawEsc === 'n') return { kind: 'char', code: 10, cs: escRes.cs };
        if (rawEsc === 'v') return { kind: 'char', code: 11, cs: escRes.cs };
        if (rawEsc === 'f') return { kind: 'char', code: 12, cs: escRes.cs };
        if (rawEsc === 'r') return { kind: 'char', code: 13, cs: escRes.cs };
        if (rawEsc === '0') return { kind: 'char', code: 0, cs: escRes.cs };
        if (rawEsc !== 'x' && rawEsc !== 'u' && rawEsc !== 'c') {
          return { kind: 'char', code: rawEsc.charCodeAt(0), cs: escRes.cs };
        }
        hasComplexInsideNegated = negated;
        return { kind: 'set', cs: escRes.cs };
      }
      const cp = effectivePattern.codePointAt(pos)!;
      pos += cp > 0xffff ? 2 : 1;
      return { kind: 'char', code: cp, cs: csFromChar(cp, ignoreCase, unicodeMode) };
    };

    while (pos < len && effectivePattern[pos] !== ']') {
      const first = readClassElem();
      if (!first) return null;
      if (pos + 1 < len && effectivePattern[pos] === '-' && effectivePattern[pos + 1] !== ']') {
        pos++; // consume '-'
        const second = readClassElem();
        if (!second) return null;
        if (first.kind === 'char' && second.kind === 'char') {
          if (first.code > second.code) return null;
          if (negated && (first.code >= 128 || second.code >= 128)) hasComplexInsideNegated = true;
          acc = csUnion(acc, csRange(first.code, second.code, ignoreCase, unicodeMode));
        } else {
          hasComplexInsideNegated = true;
          acc = ALL_CHARSET;
        }
      } else {
        if (negated && first.kind === 'char' && first.code >= 128) hasComplexInsideNegated = true;
        acc = csUnion(acc, first.cs);
      }
    }
    if (pos >= len || effectivePattern[pos] !== ']') return null;
    pos++; // consume ']'

    if (!negated) return acc;
    if (hasComplexInsideNegated) return ALL_CHARSET;
    return {
      lo: (~acc.lo) & CS_MASK64,
      hi: (~acc.hi) & CS_MASK64,
      nonAscii: true,
    };
  };

  const computeSeqSummary = (items: RegexItem[]) => {
    let minLen = 0;
    let maxLen = 0;
    let firstCs = EMPTY_CHARSET;
    let allCs = EMPTY_CHARSET;
    let canStillBeFirst = true;
    let hasQuantifier = false;
    let hasLookaround = false;
    let hasUnbounded = false;

    for (const it of items) {
      if (it.quantified) hasQuantifier = true;
      if (it.max === Number.POSITIVE_INFINITY) hasUnbounded = true;
      if (it.node.kind === 'group') {
        if (it.node.groupKind !== 'normal') {
          hasLookaround = true;
          if (it.node.hasQuantifier) hasQuantifier = true;
          if (it.node.hasUnbounded) hasUnbounded = true;
          continue;
        }
        if (it.node.hasQuantifier) hasQuantifier = true;
        if (it.node.hasLookaround) hasLookaround = true;
        if (it.node.hasUnbounded) hasUnbounded = true;
      }
      if (it.node.kind === 'anchor') continue;

      if (canStillBeFirst) {
        firstCs = csUnion(firstCs, it.firstCs);
        if (it.minLen > 0) canStillBeFirst = false;
      }
      allCs = csUnion(allCs, it.allCs);
      minLen += it.minLen;
      maxLen = maxLen === Number.POSITIVE_INFINITY || it.maxLen === Number.POSITIVE_INFINITY
        ? Number.POSITIVE_INFINITY
        : maxLen + it.maxLen;
    }

    return { minLen, maxLen, firstCs, allCs, hasQuantifier, hasLookaround, hasUnbounded };
  };

  const parseBranches = (depth: number, stopAtParen: boolean): RegexItem[][] | null => {
    if (depth > 16) return null;
    const branches: RegexItem[][] = [];
    let current: RegexItem[] = [];

    while (pos < len) {
      const ch = effectivePattern[pos]!;
      if (ch === ')') {
        if (!stopAtParen) return null;
        break;
      }
      if (ch === '|') {
        totalAlternations++;
        if (totalAlternations > 10) return null;
        branches.push(current);
        current = [];
        pos++;
        continue;
      }

      let node: RegexNode | null = null;
      if (ch === '^' || ch === '$') {
        pos++;
        node = { kind: 'anchor', isCaret: ch === '^', isDollar: ch === '$' };
      } else if (ch === '\\') {
        const escRes = parseEscapeOutsideOrInside(false);
        if (!escRes.ok) return null;
        if (escRes.isAssertion) {
          node = { kind: 'anchor', isCaret: false, isDollar: false };
        } else {
          node = { kind: 'atom', cs: escRes.cs, isLiteral: escRes.isLiteral };
        }
      } else if (ch === '[') {
        const cls = parseCharClass();
        if (!cls) return null;
        node = { kind: 'atom', cs: cls, isLiteral: false };
      } else if (ch === '.') {
        pos++;
        node = { kind: 'atom', cs: dotCs, isLiteral: false };
      } else if (ch === '(') {
        pos++;
        let groupKind: 'normal' | 'pos_lookahead' | 'neg_lookahead' = 'normal';
        if (effectivePattern[pos] === '?') {
          const mod = effectivePattern[pos + 1] ?? '';
          if (mod === ':') {
            pos += 2;
          } else if (mod === '=') {
            groupKind = 'pos_lookahead';
            pos += 2;
          } else if (mod === '!') {
            groupKind = 'neg_lookahead';
            pos += 2;
          } else if (mod === '<') {
            const closeAngle = effectivePattern.indexOf('>', pos + 2);
            if (closeAngle < 0) return null;
            const name = effectivePattern.slice(pos + 2, closeAngle);
            if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) return null;
            pos = closeAngle + 1;
          } else {
            return null;
          }
        }
        const innerBranches = parseBranches(depth + 1, true);
        if (!innerBranches || pos >= len || effectivePattern[pos] !== ')') return null;
        pos++; // consume ')'

        let minLen = Number.POSITIVE_INFINITY;
        let maxLen = 0;
        let firstCs = EMPTY_CHARSET;
        let allCs = EMPTY_CHARSET;
        let hasQuantifier = false;
        let hasLookaround = groupKind !== 'normal';
        let hasUnbounded = false;

        for (const br of innerBranches) {
          const sum = computeSeqSummary(br);
          minLen = Math.min(minLen, sum.minLen);
          maxLen = Math.max(maxLen, sum.maxLen);
          firstCs = csUnion(firstCs, sum.firstCs);
          allCs = csUnion(allCs, sum.allCs);
          if (sum.hasQuantifier) hasQuantifier = true;
          if (sum.hasLookaround) hasLookaround = true;
          if (sum.hasUnbounded) hasUnbounded = true;
        }
        if (groupKind !== 'normal') {
          minLen = 0;
          maxLen = 0;
          firstCs = EMPTY_CHARSET;
          allCs = EMPTY_CHARSET;
        }
        node = {
          kind: 'group',
          groupKind,
          branches: innerBranches,
          hasQuantifier,
          hasLookaround,
          hasUnbounded,
          minLen,
          maxLen,
          firstCs,
          allCs,
        };
      } else if (ch === '+' || ch === '*' || ch === '?') {
        return null; // unquantifiable position
      } else if (ch === '{') {
        if (/^\{\d+(?:,\d*)?\}/.test(effectivePattern.slice(pos))) {
          return null; // quantifier with nothing to quantify
        }
        pos++;
        node = { kind: 'atom', cs: csFromChar(123 /* '{' */, ignoreCase, unicodeMode), isLiteral: true };
      } else {
        const cp = effectivePattern.codePointAt(pos)!;
        pos += cp > 0xffff ? 2 : 1;
        node = { kind: 'atom', cs: csFromChar(cp, ignoreCase, unicodeMode), isLiteral: true };
      }

      // Optional trailing quantifier on `node`
      let quantified = false;
      let minRep = 1;
      let maxRep = 1;
      if (pos < len) {
        const qch = effectivePattern[pos]!;
        if (qch === '+' || qch === '*' || qch === '?') {
          quantified = true;
          minRep = qch === '+' ? 1 : 0;
          maxRep = qch === '?' ? 1 : Number.POSITIVE_INFINITY;
          pos++;
        } else if (qch === '{') {
          const bm = /^\{(\d+)(?:,(\d*))?\}/.exec(effectivePattern.slice(pos));
          if (bm) {
            quantified = true;
            minRep = Number(bm[1]);
            const rawMax = bm[2];
            if (!Number.isFinite(minRep) || minRep > 32) return null;
            if (rawMax === undefined) {
              maxRep = minRep;
            } else if (rawMax === '') {
              maxRep = Number.POSITIVE_INFINITY;
            } else {
              maxRep = Number(rawMax);
              if (!Number.isFinite(maxRep) || maxRep < minRep || maxRep > 32) return null;
            }
            pos += bm[0].length;
          }
        }
      }

      if (quantified) {
        totalQuantifiers++;
        if (totalQuantifiers > 10) return null;
        // Disallow zero-repetition `{0}` / `{0,0}` tricks and quantified anchors/lookarounds
        if (maxRep === 0) return null;
        if (node.kind === 'anchor') {
          if (minRep === 0) return null; // `(a^?)+`, `(a\B?a?)+`
        }
        if (node.kind === 'group') {
          if (node.groupKind !== 'normal') return null; // `(?=a)+`, `(?=a)?`
          if (maxRep >= 2) {
            if (node.hasQuantifier || node.branches.length > 1 || node.hasLookaround || node.minLen === 0) {
              return null;
            }
          }
        }
        // Optional lazy modifier (`*?`, `+?`, `??`, `{1,3}?`)
        if (effectivePattern[pos] === '?') {
          pos++;
        }
        const afterQ = effectivePattern[pos] ?? '';
        if (afterQ === '+' || afterQ === '*' || afterQ === '?' || /^\{\d+(?:,\d*)?\}/.test(effectivePattern.slice(pos))) {
          return null; // chained quantifiers `a**`, `a+?+`, `a{1,2}{1,2}`, `a{1,3}??`
        }
      }

      const baseMin = node.kind === 'atom' ? 1 : node.kind === 'group' ? node.minLen : 0;
      const baseMax = node.kind === 'atom' ? 1 : node.kind === 'group' ? node.maxLen : 0;
      const baseFirst = node.kind === 'atom' ? node.cs : node.kind === 'group' ? node.firstCs : EMPTY_CHARSET;
      const baseAll = node.kind === 'atom' ? node.cs : node.kind === 'group' ? node.allCs : EMPTY_CHARSET;

      current.push({
        node,
        quantified,
        min: minRep,
        max: maxRep,
        minLen: baseMin * minRep,
        maxLen:
          baseMax === 0
            ? 0
            : maxRep === Number.POSITIVE_INFINITY || baseMax === Number.POSITIVE_INFINITY
              ? Number.POSITIVE_INFINITY
              : baseMax * maxRep,
        firstCs: baseFirst,
        allCs: baseAll,
      });
    }

    branches.push(current);
    return branches;
  };

  const rootBranches = parseBranches(0, false);
  if (!rootBranches || pos !== len) return null;

  // Flatten unquantified (or `{1}`/`{1,1}`) single-branch normal groups so `(a{0,32})(a{0,32})` === `a{0,32}a{0,32}`
  const flattenSeq = (items: RegexItem[]): RegexItem[] => {
    const out: RegexItem[] = [];
    for (const it of items) {
      if (it.node.kind === 'group' && it.node.groupKind === 'normal' && it.node.branches.length === 1 && it.min === 1 && it.max === 1) {
        out.push(...flattenSeq(it.node.branches[0]!));
      } else {
        out.push(it);
      }
    }
    return out;
  };

  let globalUnclosedUnbounded = 0;

  const analyzeSeq = (
    rawItems: RegexItem[],
    isTopLevel: boolean,
    tailIsPatternEnd = false,
  ): { ok: true; branchProduct: number } | { ok: false } => {
    const items = flattenSeq(rawItems);
    const isStartAnchored =
      isTopLevel &&
      !multiline &&
      items.length > 0 &&
      items[0]!.node.kind === 'anchor' &&
      items[0]!.node.isCaret;

    let activeUnionCs = EMPTY_CHARSET;
    let chainVarCount = 0;
    let branchProduct = 1;
    let hasUnclosedUnbounded = false;
    let mandatoryLiteralsSinceUnbounded = 0;

    for (let idx = 0; idx < items.length; idx++) {
      const it = items[idx]!;
      if (it.node.kind === 'anchor') continue;

      if (it.node.kind === 'group' && it.node.groupKind !== 'normal') {
        for (const br of it.node.branches) {
          const sub = analyzeSeq(br, false);
          if (!sub.ok) return { ok: false };
        }
        if (it.node.hasUnbounded) {
          if (hasUnclosedUnbounded || globalUnclosedUnbounded >= 1) return { ok: false };
          hasUnclosedUnbounded = true;
          globalUnclosedUnbounded++;
          mandatoryLiteralsSinceUnbounded = 0;
          branchProduct *= 32;
          if (branchProduct > 64) return { ok: false };
          chainVarCount++;
          activeUnionCs = ALL_CHARSET;
        }
        continue;
      }

      // Disjoint mandatory character barrier check (`^/[^/]+/[^/]+$`, `/[a-z]+/[a-z]+/`, `/release-notes/v\d+\.\d+\.\d+`)
      if (chainVarCount === 1 && it.minLen >= 1 && csDisjoint(it.firstCs, activeUnionCs)) {
        activeUnionCs = EMPTY_CHARSET;
        chainVarCount = 0;
        branchProduct = 1;
        hasUnclosedUnbounded = false;
      }

      // Optional single-branch group starting with a mandatory disjoint delimiter (`^/items/\d+(\?.*)?$`, `^/[a-z]{2}(-[A-Z]{2})?/`)
      if (
        it.node.kind === 'group' &&
        it.node.groupKind === 'normal' &&
        it.node.branches.length === 1 &&
        it.min === 0 &&
        it.max === 1
      ) {
        let nextIdx = idx + 1;
        while (nextIdx < items.length && items[nextIdx]!.node.kind === 'anchor') nextIdx++;
        const nextItem = nextIdx < items.length ? items[nextIdx]! : null;
        const followerIsBarrier = nextItem
          ? nextItem.minLen >= 1 && csDisjoint(nextItem.firstCs, activeUnionCs) && csDisjoint(nextItem.firstCs, it.allCs)
          : tailIsPatternEnd;
        const innerFlat = flattenSeq(it.node.branches[0]!);
        const firstReal = innerFlat.find((x) => x.node.kind !== 'anchor');
        if (
          followerIsBarrier &&
          firstReal &&
          firstReal.minLen >= 1 &&
          chainVarCount <= 1 &&
          csDisjoint(firstReal.firstCs, activeUnionCs)
        ) {
          activeUnionCs = EMPTY_CHARSET;
          chainVarCount = 0;
          branchProduct = 1;
          hasUnclosedUnbounded = false;
        }
        const sub = analyzeSeq(innerFlat, false, idx === items.length - 1 && tailIsPatternEnd);
        if (!sub.ok) return { ok: false };
        if (it.node.hasUnbounded) {
          if (hasUnclosedUnbounded) return { ok: false };
          hasUnclosedUnbounded = true;
          mandatoryLiteralsSinceUnbounded = 0;
        }
        const factor = Math.max(2, sub.branchProduct + 1);
        branchProduct *= factor;
        if (branchProduct > 64) return { ok: false };
        chainVarCount++;
        activeUnionCs = csUnion(activeUnionCs, it.allCs);
        continue;
      }

      // Validate inner branches of any group
      let maxInnerProduct = 1;
      let allBranchesDisjointFixed = false;
      if (it.node.kind === 'group' && it.node.groupKind === 'normal') {
        let unionFirst = EMPTY_CHARSET;
        let pairwiseDisjoint = it.node.branches.length > 1;
        let sameFixedLen: number | null = null;

        for (const br of it.node.branches) {
          const sub = analyzeSeq(br, false);
          if (!sub.ok) return { ok: false };
          if (sub.branchProduct > maxInnerProduct) maxInnerProduct = sub.branchProduct;
          const sum = computeSeqSummary(br);
          if (sum.minLen < 1 || sum.minLen !== sum.maxLen || !csDisjoint(sum.firstCs, unionFirst)) {
            pairwiseDisjoint = false;
          } else if (sameFixedLen === null) {
            sameFixedLen = sum.minLen;
          } else if (sameFixedLen !== sum.minLen) {
            pairwiseDisjoint = false;
          }
          unionFirst = csUnion(unionFirst, sum.firstCs);
        }
        allBranchesDisjointFixed = pairwiseDisjoint;
        if (it.node.branches.length > 1 && it.node.hasUnbounded && it.max !== Number.POSITIVE_INFINITY) {
          if (hasUnclosedUnbounded) return { ok: false };
          hasUnclosedUnbounded = true;
          mandatoryLiteralsSinceUnbounded = 0;
        }
      }

      if (it.min < it.max) {
        // Variable-length item (`?`, `*`, `+`, `{n,}`, `{n,m}`)
        if (it.max === Number.POSITIVE_INFINITY) {
          if (hasUnclosedUnbounded) {
            globalUnclosedUnbounded++;
            if (globalUnclosedUnbounded > 2 || mandatoryLiteralsSinceUnbounded < 2) {
              return { ok: false };
            }
            const restItems = items.slice(idx + 1);
            const isTrailingAtEnd = restItems.length === 0 && tailIsPatternEnd;
            if (!isStartAnchored && !isTrailingAtEnd) {
              return { ok: false };
            }
            // Safe 2nd wildcard separated by >= 2 mandatory literal chars (`^/blog/.*/comments/.*$` or `.*/blog/.*`)
            branchProduct = 1;
          } else {
            if (globalUnclosedUnbounded === 0) globalUnclosedUnbounded = 1;
          }
          hasUnclosedUnbounded = true;
          mandatoryLiteralsSinceUnbounded = 0;
        }

        const repFactor = it.max === Number.POSITIVE_INFINITY ? 32 : it.max - it.min + 1;
        const groupAltFactor =
          it.node.kind === 'group' && it.node.branches.length > 1 && !allBranchesDisjointFixed
            ? it.node.branches.length
            : 1;
        branchProduct *= repFactor * groupAltFactor * maxInnerProduct;
        if (branchProduct > 64) return { ok: false };
        chainVarCount++;
        activeUnionCs = csUnion(activeUnionCs, it.allCs);
      } else if (it.node.kind === 'group' && it.node.groupKind === 'normal') {
        const altFactor =
          it.node.branches.length > 1 && !allBranchesDisjointFixed ? it.node.branches.length : 1;
        const combined = altFactor * maxInnerProduct;
        if (combined > 1) {
          for (let r = 0; r < it.min; r++) {
            branchProduct *= combined;
            if (branchProduct > 64) return { ok: false };
          }
          chainVarCount++;
          activeUnionCs = csUnion(activeUnionCs, it.allCs);
        } else {
          if (chainVarCount > 0) activeUnionCs = csUnion(activeUnionCs, it.allCs);
        }
      } else {
        // Fixed mandatory atom (`min === max >= 1`)
        if (it.node.kind === 'atom' && it.node.isLiteral) {
          mandatoryLiteralsSinceUnbounded += it.min;
        }
        if (chainVarCount > 0) {
          activeUnionCs = csUnion(activeUnionCs, it.allCs);
        }
      }
    }

    return { ok: true, branchProduct };
  };

  for (const br of rootBranches) {
    const res = analyzeSeq(br, rootBranches.length === 1, true);
    if (!res.ok) return null;
  }

  return buildRe2RegExp(pattern, effectivePattern, seenFlags, MAX_USER_REGEX_SUBJECT_LEN);
}

function parseStrictIpv4Canonical(s: string): string | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const octets: number[] = [];
  for (let i = 1; i <= 4; i++) {
    const n = Number(m[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    octets.push(n);
  }
  return `${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}`;
}

/**
 * Canonicalizes a client IP for brute-force lockout / rate-limiting (`H4`, `R3-M4`, & `Low`):
 *  - Strips `:port` from IPv4 (`1.2.3.4:12345` -> `1.2.3.4`) and bracketed IPv6 (`[::1]:12345` -> `::1`).
 *  - Strips IPv4-mapped IPv6 prefix in both dotted-quad (`::ffff:192.0.2.1`) and hex (`::ffff:c000:0201`) forms.
 *  - Collapses IPv6 addresses to their `/64` subnet prefix (`2001:0db8:0001:0002::/64`) so an attacker rotating
 *    host addresses inside one `/64` allocation shares one lockout bucket.
 */
export function normalizeClientRateLimitIp(rawIp: string | null | undefined): string {
  let clean = (rawIp ?? '').split(',')[0]?.trim().toLowerCase() ?? '';
  if (!clean) return 'local';
  if (clean.startsWith('[') && clean.includes(']')) {
    clean = clean.slice(1, clean.indexOf(']'));
  } else {
    const v4PortMatch = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(clean);
    if (v4PortMatch) {
      clean = v4PortMatch[1]!;
    }
  }
  if (clean.startsWith('::ffff:')) {
    const v4 = parseStrictIpv4Canonical(clean.slice('::ffff:'.length));
    if (v4) return v4;
  }
  const directV4 = parseStrictIpv4Canonical(clean);
  if (directV4) return directV4;

  if (clean === '::1') return '127.0.0.1';
  if (clean.includes(':')) {
    const zoneIdx = clean.indexOf('%');
    const noZone = zoneIdx >= 0 ? clean.slice(0, zoneIdx) : clean;
    const expanded = expandIpv6Hextets(noZone);
    if (expanded) {
      // Check canonical IPv4-mapped IPv6 (`0000:0000:0000:0000:0000:ffff:XXYY:ZZWW`) and `::1`
      const isZeros0to4 =
        expanded[0] === '0000' &&
        expanded[1] === '0000' &&
        expanded[2] === '0000' &&
        expanded[3] === '0000' &&
        expanded[4] === '0000';
      if (isZeros0to4 && expanded[5] === '0000' && expanded[6] === '0000' && expanded[7] === '0001') {
        return '127.0.0.1';
      }
      if (isZeros0to4 && expanded[5] === 'ffff') {
        const hi = parseInt(expanded[6]!, 16);
        const lo = parseInt(expanded[7]!, 16);
        return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
      }
      return `${expanded.slice(0, 4).join(':')}::/64`;
    }
  }
  return clean.slice(0, 45);
}

function expandIpv6Hextets(addr: string): string[] | null {
  let clean = addr;
  const lastColon = clean.lastIndexOf(':');
  if (lastColon >= 0 && clean.slice(lastColon + 1).includes('.')) {
    const v4 = parseStrictIpv4Canonical(clean.slice(lastColon + 1));
    if (!v4) return null;
    const oct = v4.split('.').map(Number);
    const hi = ((oct[0]! << 8) | oct[1]!).toString(16);
    const lo = ((oct[2]! << 8) | oct[3]!).toString(16);
    clean = `${clean.slice(0, lastColon)}:${hi}:${lo}`;
  }
  const parts = clean.split('::');
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
