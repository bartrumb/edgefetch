/**
 * WAF & Challenge Signature Catalog (`R2`), 4-Layer Anti-False-Positive Engine (`R3`),
 * `contentState` Soft-404 / Closed-Role / Login-Wall Classifier (`R4`),
 * SSR Hydration State Recovery (`__NEXT_DATA__`, `__NUXT_DATA__`, Remix, Apollo — `R6`),
 * and Opt-In Internet Archive Wayback CDX Link-Rot Fallback (`R8`).
 *
 * Pure-CPU classification delegates to Go (`internal/classify/content_state.go`) via `edgefetch-core.wasm`.
 */

import { validatePublicHttpsTargetUrl } from './overflow';
import { callCoreWasm, callCoreWasmRaw } from './wasm-bridge';

export {
  recoverSsrHydrationContent,
  type HydratedFrameworkStateResult,
} from './extractors/framework-hydration';

export type WafVendor =
  | 'cloudflare'
  | 'akamai'
  | 'datadome'
  | 'perimeterx'
  | 'aws-waf'
  | 'imperva'
  | 'vercel'
  | 'fastly'
  | 'kasada'
  | 'generic';

export type WafCategory = 'challenge' | 'waf_block' | 'rate_limit';

export interface WafClassification {
  vendor: WafVendor;
  category: WafCategory;
  confidence: number;
  signals: string[];
  summary: string;
}

// `temporarily_unavailable` is a transient state (maintenance / "try again later" pages): never cached or indexed as
// content, retry later. Classified in Go (`internal/classify`), surfaced here via WASM.
export type ContentState =
  | 'active'
  | 'closed_posting'
  | 'soft_404'
  | 'login_wall'
  | 'empty_shell'
  | 'temporarily_unavailable';

export interface ContentStateResult {
  state: ContentState;
  reason?: string;
}

export type HtmlFragmentConverter = (html: string, baseUrl?: string) => { markdown: string; links: string[] };

function headersToRecord(headers: Headers | Record<string, string | undefined> | undefined): Record<string, string> {
  if (!headers) return {};
  const out: Record<string, string> = {};
  if (typeof (headers as Headers).forEach === 'function') {
    (headers as Headers).forEach((val, key) => {
      out[key] = val;
    });
    return out;
  }
  for (const [k, v] of Object.entries(headers as Record<string, string | undefined>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

const MAX_WAF_HTML_SCAN_CHARS = 2 * 1024 * 1024;
const MAX_CONTENT_STATE_MD_SCAN_CHARS = 131_072;

function sliceSurrogateSafe(raw: string, maxChars: number): string {
  if (raw.length <= maxChars) return raw;
  let end = maxChars;
  if (end > 0) {
    const tail = raw.charCodeAt(end - 1);
    if (tail >= 0xd800 && tail <= 0xdbff) end--;
  }
  return raw.slice(0, end);
}

export function classifyWafAndChallenge(params: {
  status: number;
  headers?: Headers | Record<string, string | undefined>;
  rawBody?: string;
}): WafClassification | null {
  const res = callCoreWasmRaw<{ match: WafClassification | null }>(
    'classify_waf',
    {
      status: params.status,
      headers: headersToRecord(params.headers),
    },
    sliceSurrogateSafe(String(params.rawBody ?? ''), MAX_WAF_HTML_SCAN_CHARS),
  );
  return res.match ?? null;
}

export function hasExternalOrWidgetIframeLinear(rawHtml: string): {
  found: boolean;
  iframeSrc?: string;
  isIcims?: boolean;
} {
  if (!rawHtml) return { found: false };
  const res = callCoreWasmRaw<{
    result: { hasExternalIframe: boolean; isIcims?: boolean; iframeSrcs?: string[] };
  }>('scan_iframes', { pageUrl: '' }, sliceSurrogateSafe(String(rawHtml), MAX_WAF_HTML_SCAN_CHARS)).result;
  return {
    found: Boolean(res?.hasExternalIframe),
    ...(res?.iframeSrcs?.[0] ? { iframeSrc: res.iframeSrcs[0] } : {}),
    ...(res?.isIcims ? { isIcims: true } : {}),
  };
}

export function classifyContentState(params: {
  status?: number;
  url?: string;
  finalUrl?: string;
  title?: string;
  markdown: string;
  rawHtml?: string;
  validThrough?: string;
  rendered?: boolean;
  nowMs?: number;
}): ContentStateResult {
  const res = callCoreWasmRaw<{ result: { state: ContentState; reason?: string } }>(
    'classify_content_state',
    {
      status: params.status ?? 200,
      url: params.url ?? '',
      finalUrl: params.finalUrl ?? '',
      title: sliceSurrogateSafe(String(params.title ?? ''), 2_048),
      markdown: sliceSurrogateSafe(String(params.markdown ?? ''), MAX_CONTENT_STATE_MD_SCAN_CHARS),
      validThrough: params.validThrough ?? '',
      rendered: Boolean(params.rendered),
      nowMs: params.nowMs ?? Date.now(),
    },
    sliceSurrogateSafe(params.rawHtml ?? '', MAX_WAF_HTML_SCAN_CHARS),
  ).result;
  return {
    state: res.state,
    ...(res.reason ? { reason: res.reason } : {}),
  };
}

export function isEligibleForWaybackFallback(params: {
  outcome?: unknown;
  status?: unknown;
  problem?: unknown;
  waf?: WafClassification | null;
}): boolean {
  if (params.waf) return false;
  return callCoreWasm<{ eligible: boolean }>('eligible_wayback', {
    status: typeof params.status === 'number' ? params.status : 0,
    outcome: typeof params.outcome === 'string' ? params.outcome : '',
    problem: typeof params.problem === 'string' ? params.problem : '',
    wafCategory: '',
  }).eligible;
}

export async function tryFetchWaybackSnapshot(params: {
  url: string;
  target: 'auto' | 'agent' | 'container';
  site?: string;
  source: string;
  artifactRetention?: 'transient' | 'stored' | 'off';
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: 'transient' | 'stored' | 'off',
    hydrateInline?: boolean,
  ) => Promise<{ status: number; via: string; bodyText: string }>;
}): Promise<{ snapshotUrl: string; timestamp: string; rawBody: string; contentType: string; via: string } | null> {
  const availApiUrl = `https://archive.org/wayback/available?url=${encodeURIComponent(params.url)}`;
  try {
    const cdxRes = await params.executeHubFetch(
      params.target,
      JSON.stringify({
        maxSeconds: 20,
        options: { includeBody: true, respectRobots: true },
        requests: [{ id: 'wb-avail-1', url: availApiUrl, kind: 'json', accept: 'application/json' }],
      }),
      params.site,
      `${params.source}:wayback-cdx`,
      'off',
      true,
    );
    if (cdxRes.status !== 200) return null;
    const cdxParsed = JSON.parse(cdxRes.bodyText) as { results?: Array<Record<string, unknown>> };
    const cdxItem = cdxParsed.results?.[0];
    if (cdxItem?.outcome !== 'ok' || typeof cdxItem.body !== 'string') return null;
    const rawCdxFinal =
      typeof cdxItem?.finalUrl === 'string' && cdxItem.finalUrl.trim()
        ? cdxItem.finalUrl.trim()
        : '';
    if (rawCdxFinal) {
      const checkedCdx = validatePublicHttpsTargetUrl(rawCdxFinal);
      if (!checkedCdx.ok) return null;
      const cdxHost = checkedCdx.url.hostname.toLowerCase().replace(/\.$/, '');
      if (cdxHost !== 'archive.org' && cdxHost !== 'web.archive.org') return null;
    }

    const avail = JSON.parse(cdxItem.body) as {
      archived_snapshots?: {
        closest?: { available?: boolean; url?: string; timestamp?: string; status?: string };
      };
    };
    const closest = avail.archived_snapshots?.closest;
    if (!closest?.available || typeof closest.url !== 'string' || !closest.timestamp) return null;
    if (closest.status && closest.status !== '200') return null;

    const checkedClosest = validatePublicHttpsTargetUrl(closest.url.replace(/^http:\/\//i, 'https://'));
    if (!checkedClosest.ok) return null;
    const snapParsed = checkedClosest.url;
    if (snapParsed.hostname.toLowerCase().replace(/\.$/, '') !== 'web.archive.org') return null;
    snapParsed.pathname = snapParsed.pathname.replace(/^\/web\/(\d{14})(?:[a-z_]*)\//, '/web/$1id_/');
    const cleanSnapUrl = snapParsed.toString();

    const snapRes = await params.executeHubFetch(
      params.target,
      JSON.stringify({
        maxSeconds: 30,
        options: { includeBody: true, respectRobots: true },
        requests: [{ id: 'wb-snap-1', url: cleanSnapUrl, kind: 'scrape', formats: ['markdown'] }],
      }),
      params.site,
      `${params.source}:wayback-snap`,
      params.artifactRetention ?? 'transient',
      true,
    );
    if (snapRes.status !== 200) return null;
    const snapReply = JSON.parse(snapRes.bodyText) as { results?: Array<Record<string, unknown>> };
    const snapItem = snapReply.results?.[0];
    const rawSnapFinal =
      typeof snapItem?.finalUrl === 'string' && snapItem.finalUrl.trim()
        ? snapItem.finalUrl.trim()
        : typeof snapItem?.url === 'string' && snapItem.url.trim()
          ? snapItem.url.trim()
          : '';
    if (rawSnapFinal) {
      const checkedFinal = validatePublicHttpsTargetUrl(rawSnapFinal);
      if (!checkedFinal.ok) return null;
      const finalHost = checkedFinal.url.hostname.toLowerCase().replace(/\.$/, '');
      if (finalHost !== 'web.archive.org' && finalHost !== 'archive.org') return null;
    }
    const snapBody = typeof snapItem?.body === 'string' && snapItem.bodyEncoding !== 'base64' ? snapItem.body : '';
    if (snapItem?.outcome !== 'ok' || !snapBody.trim()) return null;

    return {
      snapshotUrl: closest.url.replace(/^http:\/\//i, 'https://'),
      timestamp: closest.timestamp,
      rawBody: snapBody,
      contentType: typeof snapItem.contentType === 'string' ? snapItem.contentType : 'text/html',
      via: snapRes.via,
    };
  } catch {
    return null;
  }
}

export function refineBlockedInfo(params: {
  url: string;
  outcome?: unknown;
  problem?: unknown;
  status?: unknown;
  retryAfter?: unknown;
  baseBlocked: unknown;
  nowMs?: number;
}): Record<string, unknown> | undefined {
  const baseBlocked =
    params.baseBlocked && typeof params.baseBlocked === 'object' && !Array.isArray(params.baseBlocked)
      ? (params.baseBlocked as Record<string, unknown>)
      : undefined;
  let retryAfterStr = '';
  if (typeof params.retryAfter === 'string' && params.retryAfter.trim()) {
    const trimmed = params.retryAfter.trim();
    if (/^\d+$/.test(trimmed)) {
      retryAfterStr = trimmed;
    } else {
      const parsedDate = Date.parse(trimmed);
      if (Number.isFinite(parsedDate)) {
        const now = params.nowMs ?? Date.now();
        retryAfterStr = String(Math.max(0, Math.floor((parsedDate - now) / 1000)));
      }
    }
  }
  const res = callCoreWasm<{ result: Record<string, unknown> | null }>('refine_blocked_map', {
    url: String(params.url ?? ''),
    outcome: typeof params.outcome === 'string' ? params.outcome : '',
    problem: typeof params.problem === 'string' ? params.problem : '',
    status: typeof params.status === 'number' ? params.status : 0,
    retryAfter: retryAfterStr,
    ...(baseBlocked ? { baseBlocked } : {}),
    nowMs: params.nowMs ?? Date.now(),
  });
  if (res.result && typeof params.retryAfter === 'string' && !/^\d+$/.test(params.retryAfter.trim())) {
    const parsedDate = Date.parse(params.retryAfter.trim());
    if (Number.isFinite(parsedDate) && res.result.reason === 'rate_limited') {
      const exactMs = Math.max(0, parsedDate - (params.nowMs ?? Date.now()));
      res.result.retryAfterMs = exactMs;
    }
  }
  return res.result ?? undefined;
}
