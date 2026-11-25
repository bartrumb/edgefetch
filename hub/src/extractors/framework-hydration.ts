/**
 * SSR Framework State Hydration Bridge (`hub/src/extractors/framework-hydration.ts`) — delegates to Go `internal/extract/hydration.go` via `edgefetch-core.wasm`.
 */

import { callCoreWasm, callCoreWasmRaw } from '../wasm-bridge';
import type { HtmlFragmentConverter } from './types';

export interface HydratedFrameworkStateResult {
  title?: string;
  description?: string;
  markdown: string;
  framework: string;
  records?: Array<Record<string, unknown>>;
  structured?: Record<string, unknown>;
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
  rawDecodedStringsForPiCheck?: string;
}

export interface CapturedJsonPayloadInput {
  url?: string;
  method?: string;
  status?: number;
  body: string;
}

export function scanJsonStringLiteralAt(
  src: string,
  openQuoteIdx: number,
  maxEnd = src.length,
): { decoded: string; nextIdx: number } | null {
  if (openQuoteIdx < 0 || openQuoteIdx >= src.length || src.charCodeAt(openQuoteIdx) !== 34) return null;
  const cap = Math.min(src.length, maxEnd);
  let i = openQuoteIdx + 1;
  while (i < cap) {
    const ch = src.charCodeAt(i);
    if (ch === 92) {
      i += 2;
      continue;
    }
    if (ch === 34) {
      try {
        return { decoded: JSON.parse(src.slice(openQuoteIdx, i + 1)) as string, nextIdx: i + 1 };
      } catch {
        return null;
      }
    }
    i++;
  }
  return null;
}

export function extractBalancedJsonAtLinear(
  src: string,
  startIdx: number,
  maxScanChars = 524_288,
): { rawJson: string; endIdx: number } | null {
  const endCap = Math.min(src.length, startIdx + maxScanChars);
  if (startIdx < 0 || startIdx >= endCap) return null;
  const open = src.charCodeAt(startIdx);
  if (open !== 123 && open !== 91) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = startIdx; i < endCap; i++) {
    const c = src.charCodeAt(i);
    if (inStr) {
      if (esc) esc = false;
      else if (c === 92) esc = true;
      else if (c === 34) inStr = false;
      continue;
    }
    if (c === 34) inStr = true;
    else if (c === 123 || c === 91) depth++;
    else if (c === 125 || c === 93) {
      depth--;
      if (depth === 0) return { rawJson: src.slice(startIdx, i + 1), endIdx: i + 1 };
      if (depth < 0) return null;
    }
  }
  return null;
}

export function isNuxtDevalueFlatArray(parsed: unknown): parsed is unknown[] {
  if (!Array.isArray(parsed) || parsed.length < 2) return false;
  const res = callCoreWasm<{ ok: boolean }>('deref_nuxt_devalue', { flat: parsed, maxNodes: 8 });
  return Boolean(res.ok);
}

export function dereferenceNuxtDevaluePayload(flat: unknown[], maxNodes = 4_000): unknown {
  const res = callCoreWasm<{ ok: boolean; value?: unknown }>('deref_nuxt_devalue', { flat, maxNodes });
  return res.ok ? res.value : null;
}

export function distillStructuredRecordsFromJsonTree(
  root: unknown,
  baseUrl?: string,
  maxRecords = 200,
): {
  records: Array<Record<string, unknown>>;
  markdown: string;
  returned: number;
  total?: number;
  truncated?: boolean;
  nextCursor?: string;
} | null {
  if (!root || typeof root !== 'object') return null;
  return (
    callCoreWasm<{
      result: {
        records: Array<Record<string, unknown>>;
        markdown: string;
        returned: number;
        total?: number;
        truncated?: boolean;
        nextCursor?: string;
      } | null;
    }>('distill_json_records', {
      root,
      baseUrl: baseUrl ?? '',
      maxRecords,
    }).result ?? null
  );
}

export function extractNextRscFlightLinear(
  rawHtml: string,
  baseUrl?: string,
  _htmlToMd?: HtmlFragmentConverter,
): HydratedFrameworkStateResult | null {
  return callCoreWasmRaw<{ result: HydratedFrameworkStateResult | null }>(
    'extract_next_rsc',
    { baseUrl: baseUrl ?? '' },
    String(rawHtml ?? ''),
  ).result;
}

export function extractFromParsedStateTree(
  root: unknown,
  framework: string,
  baseUrl?: string,
  _htmlToMd?: HtmlFragmentConverter,
  rawSourceHint?: string,
  hasUnicodeTag = false,
): HydratedFrameworkStateResult | null {
  return callCoreWasm<{ result: HydratedFrameworkStateResult | null }>('extract_state_tree', {
    root,
    framework,
    baseUrl: baseUrl ?? '',
    rawSourceHint: rawSourceHint ?? '',
    hasUnicodeTag,
  }).result;
}

export function recoverSsrHydrationContent(
  rawHtml: string,
  baseUrl?: string,
  _htmlToMd?: HtmlFragmentConverter,
): HydratedFrameworkStateResult | null {
  return callCoreWasmRaw<{ result: HydratedFrameworkStateResult | null }>(
    'recover_ssr_hydration',
    { baseUrl: baseUrl ?? '' },
    String(rawHtml ?? ''),
  ).result;
}

export function distillCapturedJsonResponses(
  inputs: readonly CapturedJsonPayloadInput[],
  baseUrl?: string,
  _htmlToMd?: HtmlFragmentConverter,
): HydratedFrameworkStateResult | null {
  return callCoreWasm<{ result: HydratedFrameworkStateResult | null }>('distill_captured_json', {
    inputs,
    baseUrl: baseUrl ?? '',
  }).result;
}
