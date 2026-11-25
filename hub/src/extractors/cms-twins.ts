/**
 * CMS Auto-Twins Bridge (`hub/src/extractors/cms-twins.ts`) — delegates URL discovery & JSON formatting to Go `internal/extract/cms_twins.go` via `edgefetch-core.wasm`.
 */

import { callCoreWasmRaw } from '../wasm-bridge';
import type { HtmlFragmentConverter } from './types';

export interface CmsAutoTwinResult {
  extractorId: 'wordpress-rest' | 'gatsby-page-data';
  twinUrl: string;
  title?: string;
  description?: string;
  publishedTime?: string;
  modifiedTime?: string;
  markdown: string;
  structured?: Record<string, unknown>;
  records?: Array<Record<string, unknown>>;
  returned?: number;
  total?: number;
  truncated?: boolean;
  nextCursor?: string;
  rawDecodedStringsForPiCheck: string;
}

export function discoverWordPressRestTwinUrlLinear(
  rawHtml: string,
  pageFinalUrl: string,
  selfHost?: string,
): string | null {
  const s = String(rawHtml ?? '');
  if (!s) return null;
  const url = callCoreWasmRaw<{ url: string }>(
    'cms_discover_wp',
    {
      pageFinalUrl: String(pageFinalUrl ?? ''),
      selfHost: selfHost ?? '',
    },
    s,
  ).url;
  return url || null;
}

export function resolveGatsbyPageDataTwinUrl(
  rawHtml: string,
  pageFinalUrl: string,
  selfHost?: string,
): string | null {
  const s = String(rawHtml ?? '');
  if (!s) return null;
  const url = callCoreWasmRaw<{ url: string }>(
    'cms_resolve_gatsby',
    {
      pageFinalUrl: String(pageFinalUrl ?? ''),
      selfHost: selfHost ?? '',
    },
    s,
  ).url;
  return url || null;
}

export function formatWordPressRestPostJson(
  rawJson: string,
  baseUrl: string,
  _htmlToMd?: HtmlFragmentConverter,
): Omit<CmsAutoTwinResult, 'extractorId' | 'twinUrl'> | null {
  const s = String(rawJson ?? '');
  if (!s) return null;
  return callCoreWasmRaw<{ result: Omit<CmsAutoTwinResult, 'extractorId' | 'twinUrl'> | null }>(
    'cms_format_wp',
    { baseUrl: String(baseUrl ?? '') },
    s,
  ).result;
}

export async function tryFetchCmsAutoTwin(params: {
  rawHtml: string;
  finalUrl: string;
  currentWordCount: number;
  selfHost?: string;
  htmlToMd: HtmlFragmentConverter;
  fetchSameOriginJson: (twinUrl: string, tag: string) => Promise<string>;
}): Promise<CmsAutoTwinResult | null> {
  const { rawHtml, finalUrl, currentWordCount, selfHost, fetchSameOriginJson } = params;

  if (currentWordCount < 120) {
    const wpUrl = discoverWordPressRestTwinUrlLinear(rawHtml, finalUrl, selfHost);
    if (wpUrl) {
      try {
        const rawJson = await fetchSameOriginJson(wpUrl, 'wp-rest-json');
        if (rawJson.trim()) {
          const formatted = formatWordPressRestPostJson(rawJson, finalUrl);
          if (formatted) {
            const newWords = (formatted.markdown.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
            if (newWords > currentWordCount && newWords >= 30) {
              return { extractorId: 'wordpress-rest', twinUrl: wpUrl, ...formatted };
            }
          }
        }
      } catch {
        // Keep standard HTML extraction when /wp-json is disallowed or unavailable
      }
    }
  }

  if (currentWordCount < 60) {
    const gatsbyUrl = resolveGatsbyPageDataTwinUrl(rawHtml, finalUrl, selfHost);
    if (gatsbyUrl) {
      try {
        const rawJson = await fetchSameOriginJson(gatsbyUrl, 'gatsby-page-data');
        if (rawJson.trim() && rawJson.length <= 2 * 1024 * 1024) {
          const hydrated = callCoreWasmRaw<{ result: Omit<CmsAutoTwinResult, 'extractorId' | 'twinUrl'> | null }>(
            'cms_format_gatsby',
            { baseUrl: finalUrl },
            rawJson,
          ).result;
          if (hydrated) {
            const newWords = (hydrated.markdown.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
            if (newWords > currentWordCount * 2 || Boolean(hydrated.records && hydrated.records.length >= 3)) {
              return {
                extractorId: 'gatsby-page-data',
                twinUrl: gatsbyUrl,
                ...hydrated,
              };
            }
          }
        }
      } catch {
        // Keep standard HTML extraction when page-data.json is absent or blocked
      }
    }
  }

  return null;
}
