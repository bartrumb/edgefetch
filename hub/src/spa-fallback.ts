/**
 * Ethical Heavy-SPA Fallback Connector (`Crawl4AI` Self-Hosted/Cloud & `Firecrawl` Cloud/Self-Hosted).
 *
 * Architectural & Ethical Contract:
 *  1. EdgeFetch ALWAYS runs its own fast ethical path first (`robots.txt` -> HTTP/2 -> ATS/Site twins -> Next.js RSC /
 *     `__NEXT_DATA__` / Nuxt SSR hydration -> local `browser-v1` CDP Chromium with `networkidle` + Shadow DOM).
 *  2. External SPA providers (`CRAWL4AI_API_URL` and/or `FIRECRAWL_API_URL` + `FIRECRAWL_API_KEY`) are invoked ONLY when:
 *      - Local EdgeFetch nodes lack a browser (`fat_agent_required`), timed out / crashed (`status === 0` / `5xx`), OR
 *        yielded an unhydrated thin `<script>` SPA shell (`< 50` words on `200 OK`), AND
 *      - The target URL is strictly eligible: **NEVER** on `robots.txt` disallows, **NEVER** on `401`/`403`/`404`/`410`/`429`,
 *        **NEVER** on WAF / CAPTCHA / anti-bot challenges, and **NEVER** on login walls!
 *  3. If local nodes never reached `/robots.txt` (e.g. `503 fat_agent_required` when only Lite nodes are connected),
 *     `tryExternalSpaFallback` fetches and enforces `/robots.txt` first before calling Crawl4AI or Firecrawl.
 */

import { fetchOverflowRobots, isRobotsAllowed } from './overflow';
import { classifyWafAndChallenge, type ContentState, type WafClassification } from './waf';

export type SpaFallbackProvider = 'crawl4ai' | 'firecrawl';
export type SpaFallbackMode = 'auto' | 'off' | 'crawl4ai' | 'firecrawl';

export interface SpaFallbackEnv {
  /** Self-hosted or cloud Crawl4AI base URL (e.g. `http://crawl4ai:11235` or `https://crawl4ai.example.com`). */
  CRAWL4AI_API_URL?: string;
  /** Optional Bearer token for authenticated Crawl4AI deployments. */
  CRAWL4AI_API_TOKEN?: string;
  /** Optional custom or self-hosted Firecrawl base URL (defaults to `https://api.firecrawl.dev` when `FIRECRAWL_API_KEY` is set). */
  FIRECRAWL_API_URL?: string;
  /** Firecrawl API key (`fc-...`; optional when pointing `FIRECRAWL_API_URL` at an unauthenticated self-hosted instance). */
  FIRECRAWL_API_KEY?: string;
  /** Comma-separated provider priority order (default: `"crawl4ai,firecrawl"` so `$0` self-hosted Crawl4AI runs first). */
  SPA_FALLBACK_ORDER?: string;
  /** Optional custom fetch override for deterministic unit testing. */
  SPA_FALLBACK_FETCH?: typeof fetch;
  SAFE_FETCH?: typeof fetch;
  SAFE_PUBLIC_FETCH?: typeof fetch;
  USER_AGENT?: string;
}

export interface SpaFallbackSuccess {
  ok: true;
  provider: SpaFallbackProvider;
  via: `fallback:${SpaFallbackProvider}`;
  finalUrl: string;
  status: number;
  markdown: string;
  html?: string;
  title?: string;
  description?: string;
  links?: string[];
}

export function listConfiguredSpaFallbacks(env: SpaFallbackEnv): SpaFallbackProvider[] {
  const hasCrawl4Ai = Boolean(env.CRAWL4AI_API_URL?.trim());
  const hasFirecrawl = Boolean(env.FIRECRAWL_API_URL?.trim() || env.FIRECRAWL_API_KEY?.trim());
  if (!hasCrawl4Ai && !hasFirecrawl) return [];

  const rawOrder = (env.SPA_FALLBACK_ORDER ?? 'crawl4ai,firecrawl')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s): s is SpaFallbackProvider => s === 'crawl4ai' || s === 'firecrawl');
  const order: SpaFallbackProvider[] = rawOrder.length > 0 ? [...new Set(rawOrder)] : ['crawl4ai', 'firecrawl'];

  return order.filter((p) => (p === 'crawl4ai' ? hasCrawl4Ai : hasFirecrawl));
}

export function normalizeSpaFallbackMode(raw: unknown): SpaFallbackMode {
  if (raw === 'off' || raw === false) return 'off';
  if (raw === 'crawl4ai') return 'crawl4ai';
  if (raw === 'firecrawl') return 'firecrawl';
  return 'auto';
}

/**
 * Enforces EdgeFetch's strict ethical gate before delegating any URL to Crawl4AI or Firecrawl:
 * NEVER delegates on `robots.txt` blocks, `401`/`403`/`404`/`410`/`429`, WAF/CAPTCHA challenges, or login walls.
 */
export function isEligibleForExternalSpaFallback(params: {
  mode?: SpaFallbackMode;
  outcome?: unknown;
  status?: unknown;
  errorCode?: unknown;
  problem?: string;
  waf?: WafClassification | null;
  contentState?: ContentState;
  isThinSpa200?: boolean;
}): boolean {
  const { mode = 'auto', outcome, status, errorCode, problem = '', waf, contentState, isThinSpa200 = false } = params;
  if (mode === 'off') return false;
  if (waf) return false;
  if (outcome === 'challenge' || outcome === 'gone' || outcome === 'skip') return false;
  if (/robots\.txt|disallowed|ssrf|non-public|challenge|captcha|turnstile|unauthorized|forbidden/i.test(problem)) {
    return false;
  }
  if (contentState && contentState !== 'active') return false;

  const code = typeof status === 'number' ? status : 0;
  if (code === 401 || code === 403 || code === 404 || code === 410 || code === 429) {
    return false;
  }

  // Case 1: Hub had no `browser-v1` Fat agent connected (`503 fat_agent_required`).
  if (errorCode === 'fat_agent_required') return true;

  // Case 2: Local node / Chromium timed out, ran out of RAM on a heavy SPA bundle (`status === 0`), or hit `502`/`503`/`504`.
  if (outcome === 'error' && (code === 0 || code === 500 || code === 502 || code === 503 || code === 504)) {
    return true;
  }

  // Case 3: Origin returned `200 OK` HTML with `<script>` tags and zero WAF/robots blocks, yet remained a thin SPA shell (`< 50` words).
  if (isThinSpa200 && code >= 200 && code < 300) {
    return true;
  }

  return false;
}

async function verifyRobotsBeforeExternalFallback(
  targetUrl: string,
  userAgent: string,
  fetchFn: typeof fetch,
  selfHost = '',
): Promise<boolean> {
  try {
    const u = new URL(targetUrl);
    if (u.protocol !== 'https:') return false;
    const parsed = await fetchOverflowRobots(u.origin, userAgent, fetchFn, Date.now() + 8_000, selfHost);
    const pathAndQuery = `${u.pathname || '/'}${u.search || ''}`;
    return isRobotsAllowed(parsed, pathAndQuery);
  } catch {
    return false;
  }
}

async function callCrawl4AiProvider(params: {
  url: string;
  baseUrl: string;
  token?: string;
  waitSelector?: string;
  noCache?: boolean;
  fetchFn: typeof fetch;
}): Promise<SpaFallbackSuccess | null> {
  const base = params.baseUrl.trim().replace(/\/+$/, '');
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json',
  };
  if (params.token?.trim()) {
    headers.authorization = `Bearer ${params.token.trim()}`;
  }

  const res = await params.fetchFn(`${base}/crawl`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      urls: [params.url],
      browser_config: {
        type: 'BrowserConfig',
        params: { headless: true },
      },
      crawler_config: {
        type: 'CrawlerRunConfig',
        params: {
          cache_mode: params.noCache ? 'bypass' : 'enabled',
          check_robots_txt: true,
          magic: false,
          ...(params.waitSelector ? { wait_for: `css:${params.waitSelector}` } : {}),
        },
      },
    }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!res.ok) return null;

  const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!data) return null;
  const first = Array.isArray(data.results)
    ? (data.results[0] as Record<string, unknown> | undefined)
    : (data.result as Record<string, unknown> | undefined) ?? data;
  if (!first || first.success === false) return null;

  const statusCode = typeof first.status_code === 'number' ? first.status_code : 200;
  const html = typeof first.html === 'string' ? first.html : typeof first.cleaned_html === 'string' ? first.cleaned_html : undefined;
  if (classifyWafAndChallenge({ status: statusCode, rawBody: html ?? '' })) {
    return null;
  }

  let markdown = '';
  const mdField = first.markdown;
  if (typeof mdField === 'string') {
    markdown = mdField.trim();
  } else if (mdField && typeof mdField === 'object') {
    const mdObj = mdField as Record<string, unknown>;
    markdown = String(mdObj.fit_markdown || mdObj.raw_markdown || mdObj.markdown_with_citations || '').trim();
  }
  if (!markdown && first.markdown_v2 && typeof first.markdown_v2 === 'object') {
    const v2 = first.markdown_v2 as Record<string, unknown>;
    markdown = String(v2.fit_markdown || v2.raw_markdown || '').trim();
  }
  if (!markdown) return null;

  const meta = first.metadata && typeof first.metadata === 'object' ? (first.metadata as Record<string, unknown>) : {};
  const finalUrl = typeof first.redirected_url === 'string' && first.redirected_url ? first.redirected_url : typeof first.url === 'string' && first.url ? first.url : params.url;
  const linksObj = first.links && typeof first.links === 'object' ? (first.links as { internal?: Array<{ href?: string }>; external?: Array<{ href?: string }> }) : undefined;
  const links = linksObj
    ? [...(linksObj.internal ?? []), ...(linksObj.external ?? [])]
        .map((l) => (typeof l?.href === 'string' ? l.href : ''))
        .filter((href) => href.startsWith('https://'))
    : undefined;

  return {
    ok: true,
    provider: 'crawl4ai',
    via: 'fallback:crawl4ai',
    finalUrl,
    status: statusCode,
    markdown,
    ...(html ? { html } : {}),
    ...(typeof meta.title === 'string' && meta.title.trim() ? { title: meta.title.trim() } : {}),
    ...(typeof meta.description === 'string' && meta.description.trim() ? { description: meta.description.trim() } : {}),
    ...(links && links.length > 0 ? { links } : {}),
  };
}

async function callFirecrawlProvider(params: {
  url: string;
  baseUrl?: string;
  apiKey?: string;
  onlyMainContent?: boolean;
  waitForMs?: number;
  noCache?: boolean;
  fetchFn: typeof fetch;
}): Promise<SpaFallbackSuccess | null> {
  const base = (params.baseUrl?.trim() || 'https://api.firecrawl.dev').replace(/\/+$/, '');
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json',
  };
  if (params.apiKey?.trim()) {
    headers.authorization = `Bearer ${params.apiKey.trim()}`;
  }

  const endpoint = /\/v[12]$/i.test(base) ? `${base}/scrape` : `${base}/v1/scrape`;
  const res = await params.fetchFn(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      url: params.url,
      formats: ['markdown'],
      onlyMainContent: params.onlyMainContent ?? true,
      ...(params.waitForMs && params.waitForMs > 0 ? { waitFor: Math.min(15_000, params.waitForMs) } : {}),
      ...(params.noCache ? { maxAge: 0 } : {}),
    }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!res.ok) return null;

  const json = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!json || json.success === false) return null;
  const data = (json.data && typeof json.data === 'object' ? (json.data as Record<string, unknown>) : json);
  const meta = data.metadata && typeof data.metadata === 'object' ? (data.metadata as Record<string, unknown>) : {};
  const statusCode = typeof meta.statusCode === 'number' ? meta.statusCode : 200;
  if (statusCode === 401 || statusCode === 403 || statusCode === 429) return null;

  const markdown = typeof data.markdown === 'string' ? data.markdown.trim() : '';
  const html = typeof data.html === 'string' ? data.html : typeof data.rawHtml === 'string' ? data.rawHtml : undefined;
  if (!markdown) return null;
  if (classifyWafAndChallenge({ status: statusCode, rawBody: html ?? markdown })) {
    return null;
  }

  const finalUrl =
    typeof meta.sourceURL === 'string' && meta.sourceURL
      ? meta.sourceURL
      : typeof meta.url === 'string' && meta.url
        ? meta.url
        : params.url;
  const links = Array.isArray(data.links) ? data.links.filter((l): l is string => typeof l === 'string' && l.startsWith('https://')) : undefined;

  return {
    ok: true,
    provider: 'firecrawl',
    via: 'fallback:firecrawl',
    finalUrl,
    status: statusCode,
    markdown,
    ...(html ? { html } : {}),
    ...(typeof meta.title === 'string' && meta.title.trim() ? { title: meta.title.trim() } : {}),
    ...(typeof meta.description === 'string' && meta.description.trim() ? { description: meta.description.trim() } : {}),
    ...(links && links.length > 0 ? { links } : {}),
  };
}

export async function tryExternalSpaFallback(params: {
  url: string;
  env: SpaFallbackEnv;
  mode?: SpaFallbackMode;
  robotsAlreadyVerified: boolean;
  onlyMainContent?: boolean;
  waitForMs?: number;
  waitSelector?: string;
  noCache?: boolean;
}): Promise<SpaFallbackSuccess | null> {
  const mode = params.mode ?? 'auto';
  if (mode === 'off') return null;

  const configured = listConfiguredSpaFallbacks(params.env);
  const candidates = mode === 'auto' ? configured : configured.filter((p) => p === mode);
  if (candidates.length === 0) return null;

  const fetchFn = params.env.SPA_FALLBACK_FETCH ?? params.env.SAFE_FETCH ?? fetch;
  const robotsFetchFn = params.env.SPA_FALLBACK_FETCH ?? params.env.SAFE_PUBLIC_FETCH ?? fetchFn;
  const ua = params.env.USER_AGENT?.trim() || 'EdgeFetch/2.5 (bot@edgefetch.dev)';

  if (!params.robotsAlreadyVerified) {
    const allowed = await verifyRobotsBeforeExternalFallback(params.url, ua, robotsFetchFn);
    if (!allowed) return null;
  }

  for (const provider of candidates) {
    try {
      if (provider === 'crawl4ai' && params.env.CRAWL4AI_API_URL?.trim()) {
        const out = await callCrawl4AiProvider({
          url: params.url,
          baseUrl: params.env.CRAWL4AI_API_URL,
          token: params.env.CRAWL4AI_API_TOKEN,
          waitSelector: params.waitSelector,
          noCache: params.noCache,
          fetchFn,
        });
        if (out && out.markdown.trim().length > 0) return out;
      } else if (provider === 'firecrawl' && (params.env.FIRECRAWL_API_URL?.trim() || params.env.FIRECRAWL_API_KEY?.trim())) {
        const out = await callFirecrawlProvider({
          url: params.url,
          baseUrl: params.env.FIRECRAWL_API_URL,
          apiKey: params.env.FIRECRAWL_API_KEY,
          onlyMainContent: params.onlyMainContent,
          waitForMs: params.waitForMs,
          noCache: params.noCache,
          fetchFn,
        });
        if (out && out.markdown.trim().length > 0) return out;
      }
    } catch {
      // Fail over to next configured SPA provider cleanly if first is unreachable.
    }
  }
  return null;
}
