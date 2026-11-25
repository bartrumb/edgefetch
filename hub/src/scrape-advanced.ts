/**
 * Advanced `/v1/scrape` & `/v2/scrape` capabilities (`hub/src/scrape-advanced.ts`).
 *
 * Pure-CPU CommonMark fence recognition/hardening, checkpoint slice paging, prompt-injection detection,
 * unsafe link neutralization, selector attribute extraction, and Schema.org/OG product extraction
 * execute in Go (`internal/extract/sanitize_slice.go` & `prompt_injection.go`) via `edgefetch-core.wasm`.
 */

import { validatePublicHttpsTargetUrl } from './overflow';
import {
  callCoreWasm,
  callCoreWasmRaw,
  callCoreWasmRawPair,
  callCoreWasmRawString,
  MAX_WASM_INPUT_BYTES,
} from './wasm-bridge';

export const MAX_SANITIZER_WASM_UTF8_BYTES = MAX_WASM_INPUT_BYTES - 16_384;
const SANITIZER_CUT_ENCODER = new TextEncoder();
let sanitizerScratchBuf: Uint8Array | null = null;

/**
 * Cuts an oversized Markdown input to `maxUtf8Bytes` (default ~3.98 MiB < `MAX_WASM_INPUT_BYTES`)
 * at a line break (`\n`) when available (or at a surrogate-safe UTF-16 code-point boundary on single-line inputs)
 * so Go's WASM sanitizer sees the entire remaining prefix as one coherent document (never chunked across fences).
 */
export function cutMarkdownToSanitizerBudget(
  raw: string,
  maxUtf8Bytes = MAX_SANITIZER_WASM_UTF8_BYTES,
): { text: string; cut: boolean } {
  if (!raw) return { text: '', cut: false };
  if (raw.length * 3 <= maxUtf8Bytes) {
    return { text: raw, cut: false };
  }
  let candidateChars = Math.min(raw.length, maxUtf8Bytes);
  if (candidateChars < raw.length && candidateChars > 0) {
    const tailUnit = raw.charCodeAt(candidateChars - 1);
    if (tailUnit >= 0xd800 && tailUnit <= 0xdbff) {
      candidateChars--;
    }
  }
  // Fast ASCII check: if `raw.length <= maxUtf8Bytes` and all code units < 0x80, 1 char === 1 UTF-8 byte (`0` copy!).
  if (raw.length <= maxUtf8Bytes) {
    let allAscii = true;
    for (let i = 0; i < raw.length; i++) {
      if (raw.charCodeAt(i) >= 0x80) {
        allAscii = false;
        break;
      }
    }
    if (allAscii) return { text: raw, cut: false };
  } else {
    // Check if prefix `0..candidateChars` is pure ASCII so e.g. `'['.repeat(7_000_000)` cuts in < 2ms without allocating 4 MiB!
    let prefixAscii = true;
    for (let i = 0; i < candidateChars; i++) {
      if (raw.charCodeAt(i) >= 0x80) {
        prefixAscii = false;
        break;
      }
    }
    if (prefixAscii) {
      let cutPos = candidateChars;
      const nl = raw.lastIndexOf('\n', cutPos - 1);
      if (nl > 0) {
        cutPos = nl;
      }
      return { text: raw.slice(0, cutPos), cut: true };
    }
  }

  if (!sanitizerScratchBuf || sanitizerScratchBuf.byteLength < maxUtf8Bytes) {
    sanitizerScratchBuf = new Uint8Array(maxUtf8Bytes);
  }
  const prefixSlice = candidateChars === raw.length ? raw : raw.slice(0, candidateChars);
  const encRes = SANITIZER_CUT_ENCODER.encodeInto(prefixSlice, sanitizerScratchBuf.subarray(0, maxUtf8Bytes));
  if (candidateChars === raw.length && encRes.read === raw.length) {
    return { text: raw, cut: false };
  }
  let cutPos = encRes.read;
  const nl = raw.lastIndexOf('\n', cutPos - 1);
  if (nl > 0) {
    cutPos = nl;
  } else if (cutPos > 0) {
    const prev = raw.charCodeAt(cutPos - 1);
    if (prev >= 0xd800 && prev <= 0xdbff) cutPos--;
  }
  return { text: raw.slice(0, cutPos), cut: true };
}

/** Invisible / format characters (below U+200B) that the fallback strips: soft hyphen, CGJ, ALM, Mongolian VS. */
function isFallbackStrippedLowInvisible(c: number): boolean {
  return c === 0x00ad || c === 0x034f || c === 0x061c || (c >= 0x180b && c <= 0x180f);
}

/**
 * Pure-TS linear O(N) emergency fallback when WASM sanitization fails for any reason.
 * Escapes every `&`, `<` and `>` as HTML entities (so a later entity decode cannot revive a tag),
 * strips control/invisible smuggling characters, unwraps simple
 * `[label](dest)` / `![alt](dest)` link/image syntax to plain visible text, and escapes any remaining
 * `[` / `]` so zero HTML tags, autolinks, links, or images can ever reach a caller unsanitized.
 */
export function escapeMarkdownFallbackLinear(
  raw: string,
  maxChars = MAX_SANITIZER_WASM_UTF8_BYTES,
): string {
  if (!raw) return '';
  let limit = Math.min(raw.length, maxChars);
  if (limit < raw.length) {
    const nl = raw.lastIndexOf('\n', limit - 1);
    if (nl > 0 && (limit - nl <= 262_144 || nl >= (limit >>> 1))) {
      limit = nl;
    } else if (limit > 0) {
      const prev = raw.charCodeAt(limit - 1);
      if (prev >= 0xd800 && prev <= 0xdbff) limit--;
    }
  }

  const chunks: string[] = [];
  // End of the furthest failed `](...)` paren scan. A later `[` whose paren region starts before this point is
  // escaped instead of rescanned, which keeps the whole pass linear (e.g. `'[](('.repeat(1e6)`). Escaping is
  // always the safe outcome; it only forgoes link unwrapping in that rare overlap.
  let parenScanFailedUntil = -1;
  let i = 0;
  while (i < limit) {
    const c = raw.charCodeAt(i);
    // Strip ASCII control chars except TAB (9), LF (10), CR (13)
    if ((c < 0x20 && c !== 9 && c !== 10 && c !== 13) || c === 0x7f) {
      i++;
      continue;
    }
    // Strip zero-width, Bidi override, variation-selector & other invisible smuggling characters
    if (
      isFallbackStrippedLowInvisible(c) ||
      (c >= 0x200b && c <= 0x200f) ||
      (c >= 0x202a && c <= 0x202e) ||
      (c >= 0x2060 && c <= 0x2069) ||
      (c >= 0xfe00 && c <= 0xfe0f) ||
      c === 0xfeff
    ) {
      i++;
      continue;
    }
    // Strip Astral Plane 14 Unicode Tag characters (U+E0000..U+E007F, high surrogate 0xDB40)
    if (c === 0xdb40 && i + 1 < limit) {
      const lo = raw.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdc7f) {
        i += 2;
        continue;
      }
    }
    if (c === 0x3c /* < */) {
      chunks.push('&lt;');
      i++;
      continue;
    }
    if (c === 0x3e /* > */) {
      chunks.push('&gt;');
      i++;
      continue;
    }
    if (c === 0x26 /* & */) {
      chunks.push('&amp;');
      i++;
      continue;
    }
    // Unwrap `![alt](dest)` or `[label](dest)` within a bounded 512-char window; otherwise escape `[` / `]`.
    if ((c === 0x21 /* ! */ && i + 1 < limit && raw.charCodeAt(i + 1) === 0x5b) || c === 0x5b /* [ */) {
      const bracketOpen = c === 0x21 ? i + 1 : i;
      const scanCap = Math.min(limit, bracketOpen + 512);
      let closeBracket = -1;
      for (let k = bracketOpen + 1; k < scanCap; k++) {
        const kc = raw.charCodeAt(k);
        if (kc === 0x5b || kc === 0x0a || kc === 0x0d) break;
        if (kc === 0x5d /* ] */) {
          closeBracket = k;
          break;
        }
      }
      if (
        closeBracket > bracketOpen &&
        closeBracket + 1 < limit &&
        raw.charCodeAt(closeBracket + 1) === 0x28 /* ( */ &&
        closeBracket + 2 >= parenScanFailedUntil
      ) {
        const parenCap = Math.min(limit, closeBracket + 2 + 2_048);
        let depth = 1;
        let p = closeBracket + 2;
        while (p < parenCap && depth > 0) {
          const pc = raw.charCodeAt(p);
          if (pc === 0x0a || pc === 0x0d) break;
          if (pc === 0x28) depth++;
          else if (pc === 0x29) depth--;
          p++;
        }
        if (depth === 0) {
          const rawLabel = raw.slice(bracketOpen + 1, closeBracket);
          if (rawLabel) {
            chunks.push(escapeMarkdownFallbackLinear(rawLabel, rawLabel.length));
          }
          i = p;
          continue;
        }
        parenScanFailedUntil = p;
      }
      if (c === 0x21) {
        chunks.push('!&#91;');
        i += 2;
      } else {
        chunks.push('&#91;');
        i++;
      }
      continue;
    }
    if (c === 0x5d /* ] */) {
      chunks.push('&#93;');
      i++;
      continue;
    }
    // Fast span copy for safe plain characters
    const runStart = i;
    i++;
    while (i < limit) {
      const nc = raw.charCodeAt(i);
      if (
        nc < 0x20 ||
        nc === 0x7f ||
        nc === 0x3c ||
        nc === 0x3e ||
        nc === 0x26 ||
        nc === 0x21 ||
        isFallbackStrippedLowInvisible(nc) ||
        nc === 0x5b ||
        nc === 0x5d ||
        nc >= 0x200b
      ) {
        break;
      }
      i++;
    }
    chunks.push(raw.slice(runStart, i));
  }
  return chunks.join('');
}

export function isAsciiWhitespaceCode(c: number): boolean {
  return c === 32 || c === 9 || c === 10 || c === 13;
}

export function isAsciiSpaceOrTabOnly(s: string, start = 0, end = s.length): boolean {
  for (let i = start; i < end; i++) {
    const c = s.charCodeAt(i);
    if (c !== 32 && c !== 9) return false;
  }
  return true;
}

export function trimAsciiWhitespaceLinear(s: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && isAsciiWhitespaceCode(s.charCodeAt(start))) start++;
  while (end > start && isAsciiWhitespaceCode(s.charCodeAt(end - 1))) end--;
  return start === 0 && end === s.length ? s : s.slice(start, end);
}

export function trimTrailingAsciiWhitespaceLinear(s: string): string {
  let end = s.length;
  while (end > 0 && isAsciiWhitespaceCode(s.charCodeAt(end - 1))) end--;
  return end === s.length ? s : s.slice(0, end);
}

export function isDisallowedMarkdownLinkDestination(rawHref: string): boolean {
  if (!rawHref) return false;
  if (rawHref.length > 8_192) return true;
  return callCoreWasm<{ disallowed: boolean }>('is_disallowed_link', { href: String(rawHref) }).disallowed;
}

export function neutralizeAllUnsafeMarkdownLinksLinear(prose: string): string {
  if (!prose) return '';
  const { text: bounded } = cutMarkdownToSanitizerBudget(String(prose));
  return callCoreWasmRawString('neutralize_unsafe_links', null, bounded);
}

export function escapeGfmTaskListCheckboxesLinear(prose: string): string {
  if (!prose || !prose.includes('[')) return prose;
  const { text: bounded } = cutMarkdownToSanitizerBudget(prose);
  return callCoreWasmRawString('escape_task_checkboxes', null, bounded);
}

export function escapeAllResidualLtInProseLinear(prose: string, allowPdfPageMarkers = false): string {
  if (!prose || !prose.includes('<')) return prose;
  const { text: bounded } = cutMarkdownToSanitizerBudget(prose);
  return callCoreWasmRawString('escape_residual_lt', { allowPdfPageMarkers }, bounded);
}

export function stripInvisibleSmugglingChars(s: string): string {
  if (!s) return '';
  const { text: bounded } = cutMarkdownToSanitizerBudget(s);
  return callCoreWasmRawString('strip_invisible', null, bounded);
}

export function cleanFenceInfoStringLinear(rawInfo: string): string {
  if (!rawInfo) return '';
  return callCoreWasm<{ out: string }>('clean_fence_info', { info: rawInfo }).out;
}

export interface MarkdownFenceRecognizerState {
  inFence: boolean;
  fenceChar: string;
  fenceLen: number;
  fenceIndent: number;
  fenceInfo: string;
  fenceRiskyContainer: boolean;
  prevLineWasBlank: boolean;
  inParagraph: boolean;
  lastListMarkerIndent: number;
  lastListItemContentCol: number;
}

export function createMarkdownFenceRecognizerState(): MarkdownFenceRecognizerState {
  return {
    inFence: false,
    fenceChar: '',
    fenceLen: 0,
    fenceIndent: 0,
    fenceInfo: '',
    fenceRiskyContainer: false,
    prevLineWasBlank: true,
    inParagraph: false,
    lastListMarkerIndent: -1,
    lastListItemContentCol: -1,
  };
}

export interface ReopenedMarkdownFence {
  fenceChar: string;
  fenceLen: number;
  info: string;
}

export interface RecognizeMarkdownFencesOptions {
  harden?: boolean;
  preserveCrLf?: boolean;
  initialReopenedFence?: ReopenedMarkdownFence | null;
  initialState?: MarkdownFenceRecognizerState;
  skipLeadingSeparatorEmptyLine?: boolean;
}

export function recognizeAndHardenMarkdownFences(
  rawMd: string,
  options?: RecognizeMarkdownFencesOptions,
): { hardened: string; segments: string[] } {
  if (!rawMd) return { hardened: '', segments: [''] };
  const rawOut = callCoreWasmRawString(
    'recognize_fences',
    {
      harden: Boolean(options?.harden),
      preserveCrLf: Boolean(options?.preserveCrLf),
      ...(options?.initialReopenedFence ? { initialReopenedFence: options.initialReopenedFence } : {}),
      ...(options?.initialState ? { initialState: options.initialState } : {}),
      skipLeadingSeparatorEmptyLine: Boolean(options?.skipLeadingSeparatorEmptyLine),
    },
    rawMd,
  );
  const nulIdx = rawOut.indexOf('\0');
  if (nulIdx < 0) return { hardened: rawOut, segments: [rawOut] };
  const header = rawOut.slice(0, nulIdx);
  if (header === 'J') {
    const parsed = JSON.parse(rawOut.slice(nulIdx + 1)) as { hardened?: string; segments?: string[] };
    return { hardened: parsed.hardened ?? '', segments: parsed.segments ?? [''] };
  }
  const hardened = rawOut.slice(nulIdx + 1);
  if (!header) return { hardened, segments: [hardened] };
  const parts = header.split(',');
  const segments = new Array<string>(parts.length);
  let cur = 0;
  for (let i = 0; i < parts.length; i++) {
    const len = Number(parts[i]);
    segments[i] = hardened.slice(cur, cur + len);
    cur += len;
  }
  return { hardened, segments };
}

export interface MarkdownSliceCheckpoint {
  pos?: number;
  utf16Pos?: number;
  offset?: number;
  state?: MarkdownFenceRecognizerState;
  activeFence?: ReopenedMarkdownFence | null;
  inFence?: boolean;
  fenceChar?: string;
  fenceLen?: number;
  effectiveFenceLen?: number;
  fenceIndent?: number;
  activeListIndent?: number;
  listIndents?: number[];
  prevLineWasParagraph?: boolean;
  prevLineWasAsciiBlank?: boolean;
  possiblyInList?: boolean;
  escapedUntrusted?: { ch: string; len: number; needBlockquote: boolean } | null;
}

export function computeMarkdownSliceCheckpoints(rawFullMd: string, stepChars = 16_384): MarkdownSliceCheckpoint[] {
  if (!rawFullMd) return [];
  return (
    callCoreWasmRaw<{ checkpoints: MarkdownSliceCheckpoint[] | null }>(
      'slice_checkpoints',
      { stepChars },
      rawFullMd,
    ).checkpoints ?? []
  );
}

export function sanitizeMarkdownPageSlice(
  fullMd: string,
  safeOffset: number,
  sliceInput: string,
  allowPdfPageMarkers = false,
  precomputedCheckpoints?: readonly MarkdownSliceCheckpoint[],
): string {
  if (!sliceInput) return '';
  const fullStr = String(fullMd ?? '');
  const clampedOffset = Math.max(0, Math.floor(safeOffset));

  // O(window) fast path: when offset === 0, prefix scanning is unused (`< 0.5ms` instead of copying 1 MiB+ fullMd).
  if (clampedOffset === 0) {
    return callCoreWasm<{ out: string }>('sanitize_slice', {
      fullMd: '',
      safeOffset: 0,
      sliceInput: String(sliceInput),
      allowPdfPageMarkers: Boolean(allowPdfPageMarkers),
    }).out;
  }

  // O(window) checkpointed prefix window (`<= ~16 KiB` instead of copying 1 MiB+ fullMd across WASM JSON).
  if (
    precomputedCheckpoints &&
    precomputedCheckpoints.length > 0 &&
    typeof precomputedCheckpoints[0]?.utf16Pos === 'number'
  ) {
    let lo = 0;
    let hi = precomputedCheckpoints.length - 1;
    let bestIdx = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const u16 = precomputedCheckpoints[mid]?.utf16Pos;
      if (typeof u16 === 'number' && u16 < clampedOffset) {
        bestIdx = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    const nlIdx = fullStr.indexOf('\n', clampedOffset);
    const windowEnd = nlIdx >= 0 ? nlIdx + 1 : fullStr.length;
    if (bestIdx >= 0) {
      const cp = precomputedCheckpoints[bestIdx]!;
      const winStart = cp.utf16Pos!;
      const windowMd = fullStr.slice(winStart, windowEnd);
      const relOffset = clampedOffset - winStart;
      const relCp: MarkdownSliceCheckpoint = { ...cp, pos: 0, utf16Pos: 0 };
      return callCoreWasm<{ out: string }>('sanitize_slice', {
        fullMd: windowMd,
        safeOffset: relOffset,
        sliceInput: String(sliceInput),
        allowPdfPageMarkers: Boolean(allowPdfPageMarkers),
        checkpoints: [relCp],
      }).out;
    }
    // Offset precedes the first checkpoint (`< 16 KiB`), and `fullStr` is clean (`utf16Pos` tracked).
    const headWindow = fullStr.slice(0, windowEnd);
    return callCoreWasm<{ out: string }>('sanitize_slice', {
      fullMd: headWindow,
      safeOffset: clampedOffset,
      sliceInput: String(sliceInput),
      allowPdfPageMarkers: Boolean(allowPdfPageMarkers),
    }).out;
  }

  return callCoreWasm<{ out: string }>('sanitize_slice', {
    fullMd: fullStr,
    safeOffset: clampedOffset,
    sliceInput: String(sliceInput),
    allowPdfPageMarkers: Boolean(allowPdfPageMarkers),
    ...(precomputedCheckpoints && precomputedCheckpoints.length > 0 ? { checkpoints: precomputedCheckpoints } : {}),
  }).out;
}

export function sanitizeFullMarkdownDocumentForArtifact(fullMd: string): string {
  if (!fullMd) return '';
  const { text: boundedMd } = cutMarkdownToSanitizerBudget(fullMd);
  try {
    return callCoreWasmRawString('full_artifact_markdown', null, boundedMd);
  } catch {
    return escapeMarkdownFallbackLinear(boundedMd);
  }
}

export function stripMarkdownTableDividerLinesLinear(s: string): string {
  if (!s || !s.includes('-')) return s;
  return callCoreWasmRawString('strip_table_dividers', null, s);
}

/** UTF-8 byte length of `s`, counting stops early once it exceeds `cap` (returns a value > cap). */
const ALL_ASCII_RE = /^[\x00-\x7f]*$/;
function utf8ByteLenUpTo(s: string, cap: number): number {
  if (s.length > cap) return s.length; // every UTF-16 code unit is >= 1 UTF-8 byte
  if (ALL_ASCII_RE.test(s)) return s.length; // native scan; avoids a JS loop on the common ASCII case
  let bytes = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const lo = s.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        bytes += 4;
        i++;
      } else bytes += 3;
    } else bytes += 3;
    if (bytes > cap) return bytes;
  }
  return bytes;
}

export function detectPromptInjection(params: {
  markdown: string;
  rawHtml?: string;
}): {
  detected: boolean;
  triggers: string[];
} {
  const md = String(params.markdown ?? '');
  const html = String(params.rawHtml ?? '');
  const PI_MAX_SCAN_CHARS = 8 * 1024 * 1024;
  // The WASM budget is in UTF-8 bytes. One UTF-16 code unit is at most 3 UTF-8 bytes, so a window of
  // `PI_WASM_BYTES / 3` chars always fits, even for all-CJK pages (a 2M-char CJK window would be ~6 MB).
  const PI_WASM_BYTES = MAX_WASM_INPUT_BYTES - 65_536;
  const PI_WINDOW_CHARS = Math.floor(PI_WASM_BYTES / 3);
  const PI_OVERLAP_CHARS = 16_384;
  const boundedMd = md.length > PI_MAX_SCAN_CHARS ? md.slice(0, PI_MAX_SCAN_CHARS) : md;
  const boundedHtml = html.length > PI_MAX_SCAN_CHARS ? html.slice(0, PI_MAX_SCAN_CHARS) : html;

  if (
    boundedMd.length <= 2 * 1024 * 1024 &&
    boundedHtml.length <= 1024 * 1024 &&
    utf8ByteLenUpTo(boundedMd, PI_WASM_BYTES) + utf8ByteLenUpTo(boundedHtml, PI_WASM_BYTES) <= PI_WASM_BYTES
  ) {
    const res =
      boundedHtml.length === 0
        ? callCoreWasmRaw<{ detected: boolean; triggers?: string[] }>('detect_prompt_injection', null, boundedMd)
        : callCoreWasmRawPair<{ detected: boolean; triggers?: string[] }>('detect_prompt_injection', boundedMd, boundedHtml);
    return {
      detected: Boolean(res.detected),
      triggers: res.triggers ?? [],
    };
  }

  const triggerSet = new Set<string>();
  const scanWindowed = (src: string, isHtml: boolean) => {
    for (let pos = 0; pos < src.length; pos += PI_WINDOW_CHARS - PI_OVERLAP_CHARS) {
      let end = Math.min(src.length, pos + PI_WINDOW_CHARS);
      if (end < src.length) {
        const code = src.charCodeAt(end - 1);
        if (code >= 0xd800 && code <= 0xdbff) end++;
      }
      const chunk = src.slice(pos, end);
      const r = isHtml
        ? callCoreWasmRawPair<{ detected: boolean; triggers?: string[] }>('detect_prompt_injection', '', chunk)
        : callCoreWasmRaw<{ detected: boolean; triggers?: string[] }>('detect_prompt_injection', null, chunk);
      if (r.triggers) {
        for (const t of r.triggers) triggerSet.add(t);
      }
      if (end >= src.length) break;
    }
  };
  if (boundedMd.length > 0) scanWindowed(boundedMd, false);
  if (boundedHtml.length > 0) scanWindowed(boundedHtml, true);
  const triggers = [...triggerSet];
  return {
    detected: triggers.length > 0,
    triggers,
  };
}

export function extractHtmlAttributesBySelectors(
  rawHtml: string,
  selectors: Array<{ selector: string; attribute: string }>,
): { items: Array<{ selector: string; attribute: string; values: string[] }> } {
  if (!rawHtml || !Array.isArray(selectors) || selectors.length === 0) {
    return { items: [] };
  }
  const cleanSelectors = selectors
    .slice(0, 25)
    .filter(
      (s): s is { selector: string; attribute: string } =>
        Boolean(s && typeof s === 'object' && typeof s.selector === 'string' && typeof s.attribute === 'string'),
    );
  if (cleanSelectors.length === 0) {
    return { items: [] };
  }
  const res = callCoreWasmRaw<{ items?: Array<{ selector: string; attribute: string; values?: string[] }> }>(
    'extract_html_attributes',
    { selectors: cleanSelectors },
    rawHtml,
  );
  return {
    items: (res.items ?? []).map((it) => ({
      selector: it.selector,
      attribute: it.attribute,
      values: it.values ?? [],
    })),
  };
}

export function sanitizePlainMetadataText(raw: string | undefined, maxLen = 2_000): string | undefined {
  if (!raw || typeof raw !== 'string') return undefined;
  const out = callCoreWasm<{ out: string }>('sanitize_meta', { text: raw, maxLen }).out;
  return out || undefined;
}

export function extractStructuredProduct(params: {
  rawBody: string;
  finalUrl: string;
  fallbackTitle?: string;
  fallbackDescription?: string;
}): Record<string, unknown> | null {
  if (!params.rawBody) return null;
  const res = callCoreWasmRaw<{ product: Record<string, unknown> | null }>(
    'extract_structured_product',
    {
      finalUrl: params.finalUrl,
      fallbackTitle: params.fallbackTitle ?? '',
      fallbackDescription: params.fallbackDescription ?? '',
    },
    params.rawBody,
  );
  return res.product ?? null;
}

const SUPPORTED_INLINE_ACTIONS = new Set([
  'wait',
  'click',
  'write',
  'fill',
  'type',
  'select',
  'press',
  'scroll',
  'navigate',
  'screenshot',
  'scrape',
  'executejavascript',
  'pdf',
]);

export function normalizeInlineBrowserActions(
  rawActions: unknown,
  selfHost?: string,
  maxItems = 50,
): { ok: true; actions: Array<Record<string, unknown>> } | { ok: false; message: string } {
  if (!Array.isArray(rawActions) || rawActions.length === 0) {
    return { ok: true, actions: [] };
  }
  if (rawActions.length > maxItems) {
    return { ok: false, message: `maximum ${maxItems} browser actions permitted per request` };
  }

  const out: Array<Record<string, unknown>> = [];
  for (const rawAct of rawActions) {
    if (!rawAct || typeof rawAct !== 'object' || Array.isArray(rawAct)) continue;
    const a = rawAct as Record<string, unknown>;
    const rawType = typeof a.type === 'string' ? a.type.trim() : '';
    const lowerType = rawType.toLowerCase();
    if (!SUPPORTED_INLINE_ACTIONS.has(lowerType)) {
      return { ok: false, message: `unsupported action type: ${rawType}` };
    }
    if (lowerType === 'navigate') {
      const navCheck = validatePublicHttpsTargetUrl(a.url, selfHost);
      if (!navCheck.ok) {
        return { ok: false, message: `navigate action: ${navCheck.message}` };
      }
    }
    const rawMs =
      typeof a.waitMs === 'number' && Number.isFinite(a.waitMs)
        ? a.waitMs
        : typeof a.milliseconds === 'number' && Number.isFinite(a.milliseconds)
          ? a.milliseconds
          : undefined;
    const explicitWaitMs = rawMs !== undefined ? Math.min(15_000, Math.max(0, Math.floor(rawMs))) : undefined;
    const keyVal = typeof a.key === 'string' ? a.key.slice(0, 40) : undefined;
    const textVal =
      typeof a.value === 'string'
        ? a.value.slice(0, 4096)
        : typeof a.text === 'string'
          ? a.text.slice(0, 4096)
          : undefined;
    const effectiveWaitMs =
      explicitWaitMs !== undefined
        ? explicitWaitMs
        : lowerType === 'click'
          ? 1_000
          : lowerType === 'press' && (!keyVal || /^(?:enter|return)$/i.test(keyVal))
            ? 800
            : undefined;

    out.push({
      type: lowerType === 'executejavascript' ? 'executeJavascript' : lowerType,
      ...(typeof a.selector === 'string' ? { selector: a.selector.slice(0, 240) } : {}),
      ...(a.all === true ? { all: true } : {}),
      ...(textVal !== undefined ? { value: textVal, text: textVal } : {}),
      ...(keyVal !== undefined ? { key: keyVal } : {}),
      ...(typeof a.direction === 'string' && /^(?:up|down)$/i.test(a.direction.trim())
        ? { direction: a.direction.trim().toLowerCase() }
        : {}),
      ...(typeof a.script === 'string' ? { script: a.script.slice(0, 16_384) } : {}),
      ...(a.fullPage === true ? { fullPage: true } : {}),
      ...(typeof a.url === 'string' ? { url: a.url.trim() } : {}),
      ...(effectiveWaitMs !== undefined ? { waitMs: effectiveWaitMs } : {}),
    });
  }
  return { ok: true, actions: out };
}

export function parsePdfParserOptions(rawParsers: unknown): {
  skipPdfParsing: boolean;
  ocrModeOverride?: 'off' | 'auto' | 'always';
  maxPagesOverride?: number;
  includePagesArray: boolean;
  includePageMarkers: boolean;
} {
  if (!Array.isArray(rawParsers)) {
    return { skipPdfParsing: false, includePagesArray: false, includePageMarkers: false };
  }
  if (rawParsers.length === 0) {
    return { skipPdfParsing: true, includePagesArray: false, includePageMarkers: false };
  }
  let ocrModeOverride: 'off' | 'auto' | 'always' | undefined;
  let maxPagesOverride: number | undefined;
  let includePagesArray = false;
  let includePageMarkers = false;
  let sawPdfParser = false;

  for (const p of rawParsers) {
    if (p === 'pdf') {
      sawPdfParser = true;
    } else if (p && typeof p === 'object' && !Array.isArray(p)) {
      const po = p as Record<string, unknown>;
      if (po.type === 'pdf') {
        sawPdfParser = true;
        if (po.mode === 'fast') ocrModeOverride = 'off';
        else if (po.mode === 'ocr') ocrModeOverride = 'always';
        else if (po.mode === 'auto') ocrModeOverride = 'auto';
        if (typeof po.maxPages === 'number' && Number.isFinite(po.maxPages)) {
          maxPagesOverride = Math.min(500, Math.max(1, Math.floor(po.maxPages)));
        }
        if (po.pages === true) includePagesArray = true;
        if (po.pageMarkers === true) includePageMarkers = true;
      }
    }
  }
  return {
    skipPdfParsing: !sawPdfParser && rawParsers.length > 0 && !rawParsers.includes('image'),
    ...(ocrModeOverride ? { ocrModeOverride } : {}),
    ...(maxPagesOverride ? { maxPagesOverride } : {}),
    includePagesArray,
    includePageMarkers,
  };
}

export function splitPdfPagesAndMarkers(
  rawPdfMarkdown: string,
  includePageMarkers: boolean,
): { pages: string[]; markedMarkdown: string } {
  if (!rawPdfMarkdown) return { pages: [], markedMarkdown: '' };
  const rawPages = rawPdfMarkdown.includes('\f')
    ? rawPdfMarkdown
        .split('\f')
        .map((p) => p.trim())
        .filter(Boolean)
    : [rawPdfMarkdown.trim()];
  if (!includePageMarkers) {
    return { pages: rawPages, markedMarkdown: rawPdfMarkdown };
  }
  const marked = rawPages.map((p, idx) => `<!-- page ${idx + 1} -->\n\n${p}`).join('\n\n');
  return { pages: rawPages, markedMarkdown: marked };
}

export function encodeBodyToRawBase64(item: Record<string, unknown>): string | undefined {
  if (typeof item.bodyBase64 === 'string' && item.bodyBase64.length > 0) {
    return item.bodyBase64;
  }
  if (typeof item.body === 'string' && item.body.length > 0) {
    if (item.bodyEncoding === 'base64') {
      return item.body;
    }
    const bytes = new TextEncoder().encode(item.body);
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }
  return undefined;
}
