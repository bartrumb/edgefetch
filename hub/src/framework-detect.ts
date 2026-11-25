/**
 * Web Framework & Platform Detector Bridge (`hub/src/framework-detect.ts`) — delegates to Go `internal/extract/framework_detect.go` via `edgefetch-core.wasm`.
 */

import { callCoreWasm } from './wasm-bridge';

export const FRAMEWORK_DETECT_WINDOW_CHARS = 65_536;

export const SAFE_RESPONSE_HEADER_ALLOWLIST: readonly string[] = [
  'server',
  'powered-by',
  'x-powered-by',
  'x-generator',
  'x-shopid',
  'x-shopify-stage',
  'x-wix-request-id',
  'x-drupal-cache',
  'x-drupal-dynamic-cache',
  'x-nextjs-cache',
  'x-remix-response',
  'x-vercel-id',
  'x-nf-request-id',
  'x-github-request-id',
  'x-hs-hub-id',
  'x-typo3-parsetime',
  'cf-ray',
  'cf-cache-status',
  'cf-mitigated',
  'via',
  'vary',
  'link',
  'x-robots-tag',
  'content-signal',
  'x-markdown-tokens',
  'cache-control',
] as const;

export interface BrowserFrameworkGlobals {
  next?: boolean;
  nuxt?: boolean;
  remix?: boolean;
  reactRouter?: boolean;
  sveltekit?: boolean;
  angular?: boolean;
  qwik?: boolean;
  solid?: boolean;
  shopify?: boolean;
  wp?: boolean;
  webflow?: boolean;
  squarespace?: boolean;
  wix?: boolean;
}

export interface DetectedSiteStack {
  source: 'html' | 'origin-markdown' | 'headers-only';
  platform?: string;
  framework?: string;
  generators: string[];
  signals: string[];
  contentFlags?: string[];
}

export function filterSafeResponseHeaders(
  rawHeaders: Record<string, string | undefined> | Headers | undefined,
): Record<string, string> | undefined {
  if (!rawHeaders) return undefined;
  const out: Record<string, string> = {};
  let count = 0;
  for (const key of SAFE_RESPONSE_HEADER_ALLOWLIST) {
    const val =
      typeof (rawHeaders as Headers).get === 'function'
        ? (rawHeaders as Headers).get(key)
        : (rawHeaders as Record<string, string | undefined>)[key] ??
          (rawHeaders as Record<string, string | undefined>)[key.toLowerCase()];
    if (typeof val === 'string' && val.trim()) {
      out[key] = val.trim().slice(0, 512);
      count++;
    }
  }
  return count > 0 ? out : undefined;
}

export function scanGeneratorMetaTagsLinear(html: string, maxChars = FRAMEWORK_DETECT_WINDOW_CHARS): string[] {
  return (
    callCoreWasm<{ generators: string[] | null }>('scan_generator_metas', {
      html: String(html ?? ''),
      maxChars,
    }).generators ?? []
  );
}

export function detectSiteFrameworkLinear(params: {
  url?: string;
  body?: string;
  contentSource?: 'html' | 'origin-markdown';
  headers?: Record<string, string | undefined> | Headers;
  globals?: BrowserFrameworkGlobals;
}): DetectedSiteStack {
  const safeHeaders = filterSafeResponseHeaders(params.headers);
  const res = callCoreWasm<{ result: DetectedSiteStack }>('detect_framework', {
    url: params.url ?? '',
    body: params.body !== undefined ? params.body.slice(0, FRAMEWORK_DETECT_WINDOW_CHARS) : '',
    contentSource: params.contentSource ?? '',
    ...(safeHeaders ? { headers: safeHeaders } : {}),
    ...(params.globals ? { globals: params.globals } : {}),
  }).result;
  return {
    ...res,
    generators: res.generators ?? [],
    signals: res.signals ?? [],
  };
}

export function extractInertiaPagePropsLinear(rawHtml: string, maxScanChars = 524_288): Record<string, unknown> | null {
  return callCoreWasm<{ props: Record<string, unknown> | null }>('extract_inertia_props', {
    rawHtml: String(rawHtml ?? ''),
    maxScanChars,
  }).props;
}
