/**
 * Advanced `/v1/scrape` & `/v2/scrape` capabilities (`hub/src/scrape-advanced.ts`).
 *
 * Pure-CPU CommonMark fence recognition/hardening, checkpoint slice paging, prompt-injection detection,
 * unsafe link neutralization, selector attribute extraction, and Schema.org/OG product extraction
 * execute in Go (`internal/extract/sanitize_slice.go` & `prompt_injection.go`) via `edgefetch-core.wasm`.
 */

import { validatePublicHttpsTargetUrl } from './overflow';
import { callCoreWasm, callCoreWasmRawPair, callCoreWasmRawString } from './wasm-bridge';

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
  return callCoreWasmRawString('neutralize_unsafe_links', null, String(prose));
}

export function escapeGfmTaskListCheckboxesLinear(prose: string): string {
  if (!prose || !prose.includes('[')) return prose;
  return callCoreWasm<{ out: string }>('escape_task_checkboxes', { prose }).out;
}

export function escapeAllResidualLtInProseLinear(prose: string, allowPdfPageMarkers = false): string {
  if (!prose || !prose.includes('<')) return prose;
  return callCoreWasm<{ out: string }>('escape_residual_lt', { prose, allowPdfPageMarkers }).out;
}

export function stripInvisibleSmugglingChars(s: string): string {
  if (!s) return '';
  return callCoreWasm<{ out: string }>('strip_invisible', { text: s }).out;
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
  const res = callCoreWasm<{ hardened: string; segments: string[] }>('recognize_fences', {
    md: rawMd,
    harden: Boolean(options?.harden),
    preserveCrLf: Boolean(options?.preserveCrLf),
    ...(options?.initialReopenedFence ? { initialReopenedFence: options.initialReopenedFence } : {}),
    ...(options?.initialState ? { initialState: options.initialState } : {}),
    skipLeadingSeparatorEmptyLine: Boolean(options?.skipLeadingSeparatorEmptyLine),
  });
  return { hardened: res.hardened ?? '', segments: res.segments ?? [''] };
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
    callCoreWasm<{ checkpoints: MarkdownSliceCheckpoint[] | null }>('slice_checkpoints', {
      fullMd: rawFullMd,
      stepChars,
    }).checkpoints ?? []
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
  return callCoreWasmRawString('full_artifact_markdown', null, fullMd);
}

export function stripMarkdownTableDividerLinesLinear(s: string): string {
  if (!s || !s.includes('-')) return s;
  return callCoreWasm<{ out: string }>('strip_table_dividers', { text: s }).out;
}

export function detectPromptInjection(params: {
  markdown: string;
  rawHtml?: string;
}): {
  detected: boolean;
  triggers: string[];
} {
  const res = callCoreWasmRawPair<{ detected: boolean; triggers?: string[] }>(
    'detect_prompt_injection',
    String(params.markdown ?? ''),
    String(params.rawHtml ?? ''),
  );
  return {
    detected: Boolean(res.detected),
    triggers: res.triggers ?? [],
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
  const res = callCoreWasm<{ items?: Array<{ selector: string; attribute: string; values?: string[] }> }>(
    'extract_html_attributes',
    { rawHtml, selectors: cleanSelectors },
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
  const res = callCoreWasm<{ product: Record<string, unknown> | null }>('extract_structured_product', {
    rawBody: params.rawBody,
    finalUrl: params.finalUrl,
    fallbackTitle: params.fallbackTitle ?? '',
    fallbackDescription: params.fallbackDescription ?? '',
  });
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
