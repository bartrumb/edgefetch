/**
 * Schema.org JSON-LD Bridge (`hub/src/extractors/schema-org.ts`) — delegates to Go `internal/extract/schema_org.go` via `edgefetch-core.wasm`.
 */

import { callCoreWasm, callCoreWasmRaw } from '../wasm-bridge';
import type { HtmlFragmentConverter } from './types';

export interface UniversalSchemaOrgResult {
  extractorId?: string;
  primaryType?: string;
  schemaType?: string;
  title?: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  modifiedTime?: string;
  siteName?: string;
  markdown?: string;
  headerMarkdown?: string;
  structured?: Record<string, unknown>;
  records?: Array<Record<string, unknown>>;
  returned?: number;
  total?: number;
  truncated?: boolean;
  nextCursor?: string;
  rawJsonLdForPiCheck?: string;
}

export function stripInvisibleSchemaChars(s: string): string {
  return callCoreWasm<{ out: string }>('strip_invisible', { text: String(s ?? '') }).out;
}

export function sanitizeSchemaPlainField(raw: unknown, maxLen = 512): string {
  return callCoreWasm<{ out: string }>('sanitize_schema_plain', { raw, maxLen }).out;
}

export function sanitizeSchemaRichMarkdown(
  raw: unknown,
  baseUrl?: string,
  _htmlToMd?: HtmlFragmentConverter,
  maxChars = 65_536,
): string {
  return callCoreWasm<{ out: string }>('sanitize_schema_rich_md', {
    raw,
    baseUrl: baseUrl ?? '',
    maxChars,
  }).out;
}

export function percentEncodeUnsafeRecordUrlChars(urlStr: string): string {
  return String(urlStr ?? '')
    .replace(/\(/g, '%28')
    .replace(/\)/g, '%29')
    .replace(/\[/g, '%5B')
    .replace(/\]/g, '%5D')
    .replace(/</g, '%3C')
    .replace(/>/g, '%3E')
    .replace(/\\/g, '%5C')
    .replace(/\s+/g, '%20');
}

export function sanitizeSchemaHttpsUrl(raw: unknown, baseUrl?: string): string | undefined {
  const out = callCoreWasm<{ out: string }>('sanitize_schema_url', { raw, baseUrl: baseUrl ?? '' }).out;
  return out || undefined;
}

export function extractUniversalSchemaOrg(
  rawHtml: string,
  baseUrl?: string,
  _htmlToMd?: HtmlFragmentConverter,
): UniversalSchemaOrgResult | null {
  const s = String(rawHtml ?? '');
  if (!s || !/ld\+json/i.test(s)) return null;
  return callCoreWasmRaw<{ result: UniversalSchemaOrgResult | null }>(
    'extract_schema_org',
    { baseUrl: baseUrl ?? '' },
    s,
  ).result;
}

export function inspectRawSchemaOrgJsonLdLinear(rawHtml: string): string {
  const s = String(rawHtml ?? '');
  if (!s || !/ld\+json/i.test(s)) return '';
  return callCoreWasmRaw<{ out: string }>('inspect_raw_schema_org', null, s).out;
}
