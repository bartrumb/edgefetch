/**
 * Site URL discovery (`POST /v1/map`), async site `crawl` (`POST /v1/crawl`, `GET/DELETE /v1/crawl/:id`, `CrawlWorkflow`),
 * signed HMAC-SHA256 webhook delivery, and Markdown change-tracking diffs (`PR V2-2`).
 */

import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { extractHtmlDocument, parseLlmsTxt, SCRAPE_PIPELINE_VERSION } from './scrape';
import { COLLECTION_ID_RE } from './search-index';
import { r2DerivedKey, type ArtifactRetention, type OptionalStorageBindings } from './storage';

export type HubFetchExecutor = (
  target: 'auto' | 'agent' | 'container',
  body: string,
  site?: string,
  source?: string,
  artifactRetention?: ArtifactRetention | 'off',
  hydrateInline?: boolean,
  collectionId?: string,
) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;

function isSafeDomainHost(hostname: string, selfHost?: string): boolean {
  const h = hostname.toLowerCase().replace(/\.+$/, '');
  if (!h || !h.includes('.') || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) {
    return false;
  }
  if (/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(h) || h.includes(':')) {
    return false;
  }
  if (selfHost && h === selfHost.toLowerCase().replace(/\.+$/, '')) {
    return false;
  }
  return true;
}

function validatePublicHttpsUrl(raw: unknown, selfHost?: string): { ok: true; url: URL } | { ok: false; message: string } {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { ok: false, message: 'url must be a non-empty https:// string' };
  }
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return { ok: false, message: `invalid URL: ${raw}` };
  }
  if (u.protocol !== 'https:' || (u.port && u.port !== '443') || u.username || u.password) {
    return { ok: false, message: 'only public https:// URLs on port 443 without credentials are permitted' };
  }
  if (!isSafeDomainHost(u.hostname, selfHost)) {
    return { ok: false, message: `disallowed hostname: ${u.hostname}` };
  }
  u.hash = '';
  return { ok: true, url: u };
}

function matchesHostScope(candidateHost: string, rootHost: string, allowSubdomains: boolean): boolean {
  const ch = candidateHost.toLowerCase().replace(/\.+$/, '');
  const rh = rootHost.toLowerCase().replace(/\.+$/, '');
  if (ch === rh) return true;
  const bareRoot = rh.startsWith('www.') ? rh.slice(4) : rh;
  if (ch === `www.${bareRoot}` || ch === bareRoot) return true;
  return allowSubdomains && ch.endsWith(`.${bareRoot}`);
}

/** Extracts `Sitemap:` URLs declared inside a `/robots.txt` file. */
export function extractRobotsSitemaps(robotsText: string, origin: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const rawLine of robotsText.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    const m = /^sitemap\s*:\s*(\S+)$/i.exec(line);
    if (!m?.[1]) continue;
    try {
      const u = new URL(m[1], origin);
      if (u.protocol === 'https:' && !seen.has(u.toString())) {
        seen.add(u.toString());
        out.push(u.toString());
        if (out.length >= 10) break;
      }
    } catch {
      // ignore malformed sitemap directive
    }
  }
  return out;
}

/** Parses XML `<sitemapindex>` and `<urlset>` `<loc>` entries. */
export function parseSitemapXml(xmlText: string): { isIndex: boolean; locs: string[] } {
  const isIndex = /<\s*sitemapindex\b/i.test(xmlText);
  const locs: string[] = [];
  const seen = new Set<string>();
  const locRe = /<\s*loc\b[^>]*>([\s\S]*?)<\/\s*loc\s*>/gi;
  let m: RegExpExecArray | null;
  while ((m = locRe.exec(xmlText)) !== null) {
    const raw = m[1]!
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
      .replace(/&amp;/g, '&')
      .trim();
    if (!raw || seen.has(raw)) continue;
    try {
      const u = new URL(raw);
      if (u.protocol === 'https:') {
        u.hash = '';
        const clean = u.toString();
        if (!seen.has(clean)) {
          seen.add(clean);
          locs.push(clean);
          if (locs.length >= 5_000) break;
        }
      }
    } catch {
      // ignore invalid URL
    }
  }
  return { isIndex, locs };
}

async function decodeXmlOrGzipBody(bodyStr: string, bodyEncoding?: string, urlHint = ''): Promise<string> {
  if (!bodyStr) return '';
  const looksGzip = bodyEncoding === 'base64' || urlHint.toLowerCase().endsWith('.gz');
  if (!looksGzip) return bodyStr;
  try {
    const binStr = atob(bodyStr);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
    if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
      const ab = await new Response(stream).arrayBuffer();
      return new TextDecoder('utf-8', { fatal: false }).decode(ab.slice(0, 4 << 20));
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return bodyStr;
  }
}

export interface MapRequestPayload {
  url?: unknown;
  search?: unknown;
  limit?: unknown;
  includeSubdomains?: unknown;
  ignoreSitemap?: unknown;
  target?: unknown;
  site?: unknown;
}

/**
 * Executes `POST /v1/map` + MCP `map`: discovers URLs across `/robots.txt` `Sitemap:`, `/sitemap.xml` (including
 * `<sitemapindex>` + `.xml.gz`), `/llms.txt`, and root homepage `<a href>` links politely through `executeHubFetch`.
 */
export async function executeMapCall(params: {
  payload: MapRequestPayload;
  executeHubFetch: HubFetchExecutor;
  selfHost?: string;
  source?: string;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, executeHubFetch, selfHost, source = 'map' } = params;
  const check = validatePublicHttpsUrl(payload.url, selfHost);
  if (!check.ok) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: check.message } };
  }
  const rootUrl = check.url;
  const origin = rootUrl.origin;
  const rootHost = rootUrl.hostname;
  const includeSubdomains = Boolean(payload.includeSubdomains);
  const ignoreSitemap = Boolean(payload.ignoreSitemap);
  const searchFilter = typeof payload.search === 'string' ? payload.search.trim().toLowerCase() : '';
  const limit =
    typeof payload.limit === 'number' && Number.isFinite(payload.limit)
      ? Math.min(5_000, Math.max(1, Math.floor(payload.limit)))
      : 500;
  const target: 'auto' | 'agent' | 'container' =
    payload.target === 'agent' || payload.target === 'container' ? payload.target : 'auto';
  const site = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim() : undefined;

  const seedRequests: Array<Record<string, unknown>> = [
    { id: 'home', url: rootUrl.toString(), kind: 'page' },
    { id: 'llms', url: `${origin}/llms.txt`, kind: 'text', accept: 'text/markdown' },
  ];
  if (!ignoreSitemap) {
    seedRequests.push(
      { id: 'robots', url: `${origin}/robots.txt`, kind: 'text', accept: 'text/plain' },
      { id: 'sitemap', url: `${origin}/sitemap.xml`, kind: 'text', accept: 'application/xml' },
    );
  }

  const seedRes = await executeHubFetch(
    target,
    JSON.stringify({
      maxSeconds: 45,
      options: { includeBody: true, respectRobots: true, pauseMs: 400 },
      requests: seedRequests,
    }),
    site,
    source,
    'transient',
    true,
  );
  if (seedRes.status !== 200) {
    return { status: seedRes.status, via: seedRes.via, body: { ok: false, error: 'map_fetch_failed' } };
  }

  const parsed = JSON.parse(seedRes.bodyText) as { results?: Array<Record<string, unknown>> };
  const byId = new Map<string, Record<string, unknown>>();
  for (const r of parsed.results ?? []) {
    if (typeof r.id === 'string') byId.set(r.id, r);
  }

  const discovered = new Map<string, { url: string; title?: string; source: string }>();
  const addUrl = (rawCandidate: string, src: string, title?: string) => {
    try {
      const u = new URL(rawCandidate, origin);
      if (u.protocol !== 'https:' || (u.port && u.port !== '443')) return;
      if (!matchesHostScope(u.hostname, rootHost, includeSubdomains)) return;
      u.hash = '';
      const clean = u.toString();
      if (!discovered.has(clean)) {
        discovered.set(clean, { url: clean, ...(title ? { title } : {}), source: src });
      }
    } catch {
      // ignore
    }
  };
  addUrl(rootUrl.toString(), 'seed');

  const homeItem = byId.get('home');
  if (homeItem?.outcome === 'ok' && typeof homeItem.body === 'string') {
    const ext = extractHtmlDocument(homeItem.body, { baseUrl: rootUrl.toString(), onlyMainContent: false });
    for (const l of ext.links) addUrl(l, 'homepage');
  }

  const llmsItem = byId.get('llms');
  if (llmsItem?.outcome === 'ok' && typeof llmsItem.body === 'string') {
    const llmsDoc = parseLlmsTxt(llmsItem.body, `${origin}/llms.txt`);
    if (llmsDoc) {
      for (const l of llmsDoc.links) addUrl(l.url, 'llms.txt', l.title);
    }
  }

  if (!ignoreSitemap) {
    const childSitemaps = new Set<string>();
    const robotsItem = byId.get('robots');
    if (robotsItem?.outcome === 'ok' && typeof robotsItem.body === 'string') {
      for (const sm of extractRobotsSitemaps(robotsItem.body, origin)) {
        if (sm !== `${origin}/sitemap.xml`) childSitemaps.add(sm);
      }
    }

    const smItem = byId.get('sitemap');
    if (smItem?.outcome === 'ok' && typeof smItem.body === 'string') {
      const xml = await decodeXmlOrGzipBody(smItem.body, smItem.bodyEncoding as string | undefined, `${origin}/sitemap.xml`);
      const parsedSm = parseSitemapXml(xml);
      if (parsedSm.isIndex) {
        for (const loc of parsedSm.locs.slice(0, 5)) childSitemaps.add(loc);
      } else {
        for (const loc of parsedSm.locs) addUrl(loc, 'sitemap');
      }
    }

    const toFetchSitemaps = [...childSitemaps]
      .filter((u) => {
        try {
          return matchesHostScope(new URL(u).hostname, rootHost, true);
        } catch {
          return false;
        }
      })
      .slice(0, 4);

    if (toFetchSitemaps.length > 0 && discovered.size < limit) {
      const subRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: { includeBody: true, respectRobots: true, pauseMs: 400 },
          requests: toFetchSitemaps.map((u, idx) => ({
            id: `csm-${idx}`,
            url: u,
            kind: 'text',
            accept: 'application/xml',
          })),
        }),
        site,
        `${source}:child-sitemaps`,
        'transient',
        true,
      );
      if (subRes.status === 200) {
        const subParsed = JSON.parse(subRes.bodyText) as { results?: Array<Record<string, unknown>> };
        for (const sr of subParsed.results ?? []) {
          if (sr.outcome === 'ok' && typeof sr.body === 'string') {
            const xml = await decodeXmlOrGzipBody(sr.body, sr.bodyEncoding as string | undefined, String(sr.url ?? ''));
            const p = parseSitemapXml(xml);
            if (!p.isIndex) {
              for (const loc of p.locs) addUrl(loc, 'sitemap');
            }
          }
        }
      }
    }
  }

  let items = [...discovered.values()];
  if (searchFilter) {
    const terms = searchFilter.split(/\s+/).filter(Boolean);
    items = items
      .map((entry) => {
        const hay = `${entry.url} ${entry.title ?? ''}`.toLowerCase();
        let hits = 0;
        for (const t of terms) if (hay.includes(t)) hits++;
        return { entry, hits };
      })
      .filter((x) => x.hits > 0)
      .sort((a, b) => b.hits - a.hits || a.entry.url.localeCompare(b.entry.url))
      .map((x) => x.entry);
  } else {
    items.sort((a, b) => a.url.localeCompare(b.url));
  }

  const sliced = items.slice(0, limit);
  return {
    status: 200,
    via: seedRes.via,
    body: {
      ok: true,
      url: rootUrl.toString(),
      total: sliced.length,
      links: sliced.map((x) => x.url),
      entries: sliced,
    },
  };
}

/** Computes a compact line-level Markdown diff for `formats: ["changes"]` change tracking (`Addition 8`). */
export function computeMarkdownChanges(prevMarkdown: string | null, nextMarkdown: string): {
  status: 'new' | 'same' | 'changed';
  addedCount: number;
  removedCount: number;
  diffPreview: string;
} {
  if (prevMarkdown === null) {
    return { status: 'new', addedCount: nextMarkdown.split('\n').length, removedCount: 0, diffPreview: '' };
  }
  const prevClean = prevMarkdown.replace(/\r\n/g, '\n').trim();
  const nextClean = nextMarkdown.replace(/\r\n/g, '\n').trim();
  if (prevClean === nextClean) {
    return { status: 'same', addedCount: 0, removedCount: 0, diffPreview: '' };
  }

  const prevSet = new Set(prevClean.split('\n').map((l) => l.trim()).filter(Boolean));
  const nextSet = new Set(nextClean.split('\n').map((l) => l.trim()).filter(Boolean));
  const added = [...nextSet].filter((l) => !prevSet.has(l));
  const removed = [...prevSet].filter((l) => !nextSet.has(l));
  const previewLines = [
    ...removed.slice(0, 15).map((l) => `- ${l}`),
    ...added.slice(0, 15).map((l) => `+ ${l}`),
  ];
  return {
    status: 'changed',
    addedCount: added.length,
    removedCount: removed.length,
    diffPreview: previewLines.join('\n').slice(0, 4_000),
  };
}

export interface WebhookConfig {
  url: string;
  secret?: string;
  events?: Array<'crawl.started' | 'crawl.page' | 'crawl.completed' | 'crawl.failed'>;
  metadata?: Record<string, unknown>;
}

export async function signWebhookPayload(secret: string, timestampSec: number, rawJson: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(`${timestampSec}.${rawJson}`));
  return [...new Uint8Array(sigBuf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Delivers an SSRF-validated, HMAC-SHA256 signed webhook event (`X-EdgeFetch-Signature: sha256=<hex>`). */
export async function deliverSignedWebhook(params: {
  webhook: WebhookConfig;
  defaultSecret?: string;
  event: 'crawl.started' | 'crawl.page' | 'crawl.completed' | 'crawl.failed';
  crawlId: string;
  data: Record<string, unknown>;
  selfHost?: string;
  fetchFn?: typeof fetch;
}): Promise<{ delivered: boolean; status?: number }> {
  const { webhook, defaultSecret, event, crawlId, data, selfHost, fetchFn = fetch } = params;
  if (Array.isArray(webhook.events) && webhook.events.length > 0 && !webhook.events.includes(event)) {
    return { delivered: false };
  }
  const urlCheck = validatePublicHttpsUrl(webhook.url, selfHost);
  if (!urlCheck.ok) {
    return { delivered: false };
  }

  const tsSec = Math.floor(Date.now() / 1000);
  const bodyJson = JSON.stringify({
    event,
    crawlId,
    timestamp: tsSec,
    ...(webhook.metadata ? { metadata: webhook.metadata } : {}),
    data,
  });

  const signingSecret = (webhook.secret ?? defaultSecret ?? '').trim();
  const headers = new Headers({
    'content-type': 'application/json',
    'user-agent': 'EdgeFetch-Webhook/2.0',
    'x-edgefetch-event': event,
    'x-edgefetch-timestamp': String(tsSec),
  });
  if (signingSecret) {
    const sigHex = await signWebhookPayload(signingSecret, tsSec, bodyJson);
    headers.set('x-edgefetch-signature', `sha256=${sigHex}`);
  }

  try {
    const res = await fetchFn(urlCheck.url.toString(), {
      method: 'POST',
      headers,
      body: bodyJson,
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    await res.body?.cancel().catch(() => undefined);
    return { delivered: res.status >= 200 && res.status < 300, status: res.status };
  } catch {
    return { delivered: false };
  }
}

export interface CrawlJobOptions {
  limit: number;
  maxDepth: number;
  allowSubdomains: boolean;
  includePaths: string[];
  excludePaths: string[];
  collectionId?: string;
  renderMode?: 'off' | 'auto' | 'always';
  webhook?: WebhookConfig;
  target: 'auto' | 'agent' | 'container';
  site?: string;
}

export interface CrawlWorkflowParams {
  crawlId: string;
  rootUrl: string;
  selfHost?: string;
}

function pathAllowed(pathname: string, includePaths: string[], excludePaths: string[]): boolean {
  for (const ex of excludePaths) {
    if (pathname.startsWith(ex)) return false;
  }
  if (includePaths.length === 0) return true;
  return includePaths.some((inc) => pathname.startsWith(inc));
}

export async function createCrawlJob(params: {
  payload: Record<string, unknown>;
  metaDb?: D1Database;
  selfHost?: string;
  now?: number;
}): Promise<
  | { ok: true; crawlId: string; rootUrl: string; options: CrawlJobOptions }
  | { ok: false; status: number; error: string; message: string }
> {
  const { payload, metaDb, selfHost, now = Date.now() } = params;
  if (!metaDb) {
    return { ok: false, status: 503, error: 'tracking_not_configured', message: 'Async crawl requires META D1 binding' };
  }
  const urlCheck = validatePublicHttpsUrl(payload.url, selfHost);
  if (!urlCheck.ok) {
    return { ok: false, status: 400, error: 'invalid_url', message: urlCheck.message };
  }

  let webhook: WebhookConfig | undefined;
  if (payload.webhook && typeof payload.webhook === 'object') {
    const w = payload.webhook as Record<string, unknown>;
    const whCheck = validatePublicHttpsUrl(w.url, selfHost);
    if (!whCheck.ok) {
      return { ok: false, status: 400, error: 'invalid_webhook_url', message: whCheck.message };
    }
    const allowedEvents = ['crawl.started', 'crawl.page', 'crawl.completed', 'crawl.failed'] as const;
    const evs = Array.isArray(w.events)
      ? w.events.filter((e): e is (typeof allowedEvents)[number] => allowedEvents.includes(e as never))
      : undefined;
    webhook = {
      url: whCheck.url.toString(),
      ...(typeof w.secret === 'string' && w.secret.trim() ? { secret: w.secret.trim() } : {}),
      ...(evs && evs.length > 0 ? { events: evs } : {}),
      ...(w.metadata && typeof w.metadata === 'object' ? { metadata: w.metadata as Record<string, unknown> } : {}),
    };
  }

  const crawlId = `crw_${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}`;
  const rawColl = typeof payload.collectionId === 'string' ? payload.collectionId.trim() : crawlId;
  const options: CrawlJobOptions = {
    limit: typeof payload.limit === 'number' && Number.isFinite(payload.limit) ? Math.min(200, Math.max(1, Math.floor(payload.limit))) : 25,
    maxDepth:
      typeof payload.maxDepth === 'number' && Number.isFinite(payload.maxDepth)
        ? Math.min(5, Math.max(0, Math.floor(payload.maxDepth)))
        : 2,
    allowSubdomains: Boolean(payload.allowSubdomains),
    includePaths: Array.isArray(payload.includePaths)
      ? payload.includePaths.filter((p): p is string => typeof p === 'string' && p.startsWith('/')).slice(0, 20)
      : [],
    excludePaths: Array.isArray(payload.excludePaths)
      ? payload.excludePaths.filter((p): p is string => typeof p === 'string' && p.startsWith('/')).slice(0, 20)
      : [],
    ...(COLLECTION_ID_RE.test(rawColl) ? { collectionId: rawColl } : {}),
    ...(payload.renderMode === 'auto' || payload.renderMode === 'always' || payload.renderMode === 'off'
      ? { renderMode: payload.renderMode }
      : {}),
    ...(webhook ? { webhook } : {}),
    target: payload.target === 'agent' || payload.target === 'container' ? payload.target : 'auto',
    ...(typeof payload.site === 'string' && payload.site.trim() ? { site: payload.site.trim() } : {}),
  };

  // Store options JSON WITHOUT raw caller webhook secrets in plaintext if a secret was provided (redact or keep in workflow).
  const storedOptions = {
    ...options,
    ...(options.webhook ? { webhook: { ...options.webhook, ...(options.webhook.secret ? { secret: undefined, hasSecret: true } : {}) } } : {}),
  };

  await metaDb
    .prepare(
      `INSERT INTO crawls (id, root_url, status, options_json, discovered_count, fetched_count, failed_count, created_at, updated_at)
       VALUES (?, ?, 'queued', ?, 1, 0, 0, ?, ?)`,
    )
    .bind(crawlId, urlCheck.url.toString(), JSON.stringify(storedOptions), now, now)
    .run();

  return { ok: true, crawlId, rootUrl: urlCheck.url.toString(), options };
}

export async function executeCrawlJob(params: {
  crawlId: string;
  rootUrl: string;
  options: CrawlJobOptions;
  env: OptionalStorageBindings & { WEBHOOK_SECRET?: string };
  executeHubFetch: HubFetchExecutor;
  selfHost?: string;
  webhookFetchFn?: typeof fetch;
}): Promise<{ status: 'completed' | 'cancelled' | 'failed'; fetchedCount: number; failedCount: number; discoveredCount: number }> {
  const { crawlId, rootUrl, options, env, executeHubFetch, selfHost, webhookFetchFn } = params;
  const metaDb = env.META!;
  const rootParsed = new URL(rootUrl);

  const isCancelled = async (): Promise<boolean> => {
    const row = await metaDb.prepare('SELECT status FROM crawls WHERE id = ? LIMIT 1').bind(crawlId).first<{ status: string }>();
    return row?.status === 'cancelled';
  };

  if (await isCancelled()) {
    return { status: 'cancelled', fetchedCount: 0, failedCount: 0, discoveredCount: 1 };
  }

  await metaDb
    .prepare("UPDATE crawls SET status = 'running', updated_at = ? WHERE id = ? AND status != 'cancelled'")
    .bind(Date.now(), crawlId)
    .run();

  if (options.webhook) {
    await deliverSignedWebhook({
      webhook: options.webhook,
      defaultSecret: env.WEBHOOK_SECRET,
      event: 'crawl.started',
      crawlId,
      data: { rootUrl, limit: options.limit, maxDepth: options.maxDepth },
      selfHost,
      ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
    });
  }

  const visited = new Set<string>([rootUrl]);
  let frontier: string[] = [rootUrl];
  let fetchedCount = 0;
  let failedCount = 0;

  try {
    for (let depth = 0; depth <= options.maxDepth && frontier.length > 0 && fetchedCount + failedCount < options.limit; depth++) {
      if (await isCancelled()) {
        return { status: 'cancelled', fetchedCount, failedCount, discoveredCount: visited.size };
      }

      const remainingBudget = options.limit - (fetchedCount + failedCount);
      const wave = frontier.slice(0, Math.min(remainingBudget, 15));
      const nextFrontier: string[] = [];

      const retention: ArtifactRetention | undefined = env.ARTIFACTS ? 'stored' : undefined;
      const call = {
        maxSeconds: 60,
        options: { includeBody: true, respectRobots: true, discoverLlms: depth === 0 },
        requests: wave.map((u, idx) => ({
          id: `c-${depth}-${idx}`,
          url: u,
          kind: options.renderMode === 'always' ? 'render' : 'scrape',
          formats: ['markdown', 'links'],
          onlyMainContent: true,
          ...(options.renderMode ? { renderMode: options.renderMode } : {}),
        })),
      };

      const fetchOut = await executeHubFetch(
        options.target,
        JSON.stringify(call),
        options.site,
        `crawl:${crawlId}`,
        retention,
        true,
        options.collectionId,
      );

      if (fetchOut.status !== 200) {
        failedCount += wave.length;
        break;
      }

      const parsed = JSON.parse(fetchOut.bodyText) as { results?: Array<Record<string, unknown>> };
      for (const item of parsed.results ?? []) {
        const itemUrl = typeof item.url === 'string' ? item.url : '';
        if (item.outcome === 'ok') {
          fetchedCount++;
          const rawHtml = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
          const ext = rawHtml ? extractHtmlDocument(rawHtml, { baseUrl: itemUrl, onlyMainContent: true }) : undefined;
          const md = (typeof item.markdown === 'string' && item.markdown) || ext?.markdown || '';
          const links = Array.isArray(item.links) ? (item.links as string[]) : (ext?.links ?? []);

          if (options.webhook) {
            await deliverSignedWebhook({
              webhook: options.webhook,
              defaultSecret: env.WEBHOOK_SECRET,
              event: 'crawl.page',
              crawlId,
              data: {
                url: itemUrl,
                status: item.status ?? 200,
                title: (typeof item.title === 'string' && item.title) || ext?.title,
                markdownPreview: md.slice(0, 2_000),
              },
              selfHost,
              ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
            });
          }

          if (depth < options.maxDepth) {
            for (const lnk of links) {
              if (visited.size >= options.limit * 3) break;
              try {
                const lu = new URL(lnk, itemUrl);
                if (lu.protocol !== 'https:' || (lu.port && lu.port !== '443')) continue;
                if (!matchesHostScope(lu.hostname, rootParsed.hostname, options.allowSubdomains)) continue;
                if (!pathAllowed(lu.pathname, options.includePaths, options.excludePaths)) continue;
                lu.hash = '';
                const clean = lu.toString();
                if (!visited.has(clean)) {
                  visited.add(clean);
                  nextFrontier.push(clean);
                }
              } catch {
                // ignore
              }
            }
          }
        } else {
          failedCount++;
        }
      }

      // Link crawl_id onto fetches rows for this URL wave so GET /v1/crawl/:id returns page results cleanly.
      if (wave.length > 0) {
        const placeholders = wave.map(() => '?').join(', ');
        await metaDb
          .prepare(
            `UPDATE fetches
             SET crawl_id = ?
             WHERE crawl_id IS NULL
               AND page_id IN (SELECT id FROM pages WHERE url IN (${placeholders}))
               AND fetched_at >= ?`,
          )
          .bind(crawlId, ...wave, Date.now() - 120_000)
          .run()
          .catch(() => undefined);
      }

      await metaDb
        .prepare(
          `UPDATE crawls
           SET discovered_count = ?, fetched_count = ?, failed_count = ?, updated_at = ?
           WHERE id = ?`,
        )
        .bind(visited.size, fetchedCount, failedCount, Date.now(), crawlId)
        .run();

      frontier = nextFrontier;
    }

    if (await isCancelled()) {
      return { status: 'cancelled', fetchedCount, failedCount, discoveredCount: visited.size };
    }

    const doneNow = Date.now();
    await metaDb
      .prepare(
        `UPDATE crawls
         SET status = 'completed', discovered_count = ?, fetched_count = ?, failed_count = ?, updated_at = ?, finished_at = ?
         WHERE id = ? AND status != 'cancelled'`,
      )
      .bind(visited.size, fetchedCount, failedCount, doneNow, doneNow, crawlId)
      .run();

    if (options.webhook) {
      await deliverSignedWebhook({
        webhook: options.webhook,
        defaultSecret: env.WEBHOOK_SECRET,
        event: 'crawl.completed',
        crawlId,
        data: { rootUrl, discoveredCount: visited.size, fetchedCount, failedCount, collectionId: options.collectionId },
        selfHost,
        ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
      });
    }

    return { status: 'completed', fetchedCount, failedCount, discoveredCount: visited.size };
  } catch (e) {
    const failNow = Date.now();
    await metaDb
      .prepare("UPDATE crawls SET status = 'failed', updated_at = ?, finished_at = ? WHERE id = ?")
      .bind(failNow, failNow, crawlId)
      .run()
      .catch(() => undefined);
    if (options.webhook) {
      await deliverSignedWebhook({
        webhook: options.webhook,
        defaultSecret: env.WEBHOOK_SECRET,
        event: 'crawl.failed',
        crawlId,
        data: { rootUrl, error: e instanceof Error ? e.message : String(e) },
        selfHost,
        ...(webhookFetchFn ? { fetchFn: webhookFetchFn } : {}),
      });
    }
    return { status: 'failed', fetchedCount, failedCount, discoveredCount: visited.size };
  }
}

export async function getCrawlJobStatus(params: {
  crawlId: string;
  metaDb?: D1Database;
  bucket?: R2Bucket;
  offset?: number;
  limit?: number;
}): Promise<{ ok: true; crawl: Record<string, unknown> } | { ok: false; status: number; error: string }> {
  const { crawlId, metaDb, bucket, offset = 0, limit = 25 } = params;
  if (!metaDb) return { ok: false, status: 503, error: 'tracking_not_configured' };

  const row = await metaDb
    .prepare(
      `SELECT id, root_url, status, options_json, discovered_count, fetched_count, failed_count, created_at, updated_at, finished_at
       FROM crawls WHERE id = ? LIMIT 1`,
    )
    .bind(crawlId)
    .first<{
      id: string;
      root_url: string;
      status: string;
      options_json: string;
      discovered_count: number;
      fetched_count: number;
      failed_count: number;
      created_at: number;
      updated_at: number;
      finished_at: number | null;
    }>();
  if (!row) return { ok: false, status: 404, error: 'crawl_not_found' };

  const safeOffset = Math.max(0, Math.floor(offset));
  const safeLimit = Math.min(50, Math.max(1, Math.floor(limit)));
  const pageRows = (
    await metaDb
      .prepare(
        `SELECT p.url, f.status, f.outcome, f.content_sha256, f.blob_sha256, f.fetched_at, d.title
         FROM fetches f
         JOIN pages p ON p.id = f.page_id
         LEFT JOIN documents d ON d.content_sha256 = f.content_sha256 AND d.format = 'markdown' AND d.pipeline_version = ?
         WHERE f.crawl_id = ?
         ORDER BY f.fetched_at ASC
         LIMIT ? OFFSET ?`,
      )
      .bind(SCRAPE_PIPELINE_VERSION, crawlId, safeLimit, safeOffset)
      .all<{
        url: string;
        status: number;
        outcome: string;
        content_sha256: string | null;
        blob_sha256: string | null;
        fetched_at: number;
        title: string | null;
      }>()
  ).results;

  const data: Array<Record<string, unknown>> = [];
  for (const pr of pageRows ?? []) {
    let markdown: string | undefined;
    if (bucket && pr.content_sha256) {
      const mdObj = await bucket.get(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', pr.content_sha256));
      if (mdObj) markdown = await mdObj.text();
    }
    data.push({
      url: pr.url,
      status: pr.status,
      outcome: pr.outcome,
      ...(pr.title ? { title: pr.title } : {}),
      ...(pr.blob_sha256 ? { artifactId: pr.blob_sha256 } : {}),
      ...(markdown !== undefined ? { markdown } : {}),
      fetchedAt: pr.fetched_at,
    });
  }

  let parsedOpts: Record<string, unknown> = {};
  try {
    parsedOpts = JSON.parse(row.options_json) as Record<string, unknown>;
  } catch {
    // ignore
  }

  return {
    ok: true,
    crawl: {
      id: row.id,
      rootUrl: row.root_url,
      status: row.status,
      collectionId: parsedOpts.collectionId,
      discoveredCount: row.discovered_count,
      fetchedCount: row.fetched_count,
      failedCount: row.failed_count,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      finishedAt: row.finished_at,
      offset: safeOffset,
      limit: safeLimit,
      hasMore: safeOffset + data.length < row.fetched_count + row.failed_count,
      nextOffset: safeOffset + data.length < row.fetched_count + row.failed_count ? safeOffset + data.length : null,
      data,
    },
  };
}

export async function cancelCrawlJob(crawlId: string, metaDb?: D1Database): Promise<{ ok: boolean; status: number }> {
  if (!metaDb) return { ok: false, status: 503 };
  const now = Date.now();
  const res = await metaDb
    .prepare(
      `UPDATE crawls
       SET status = 'cancelled', updated_at = ?, finished_at = COALESCE(finished_at, ?)
       WHERE id = ? AND status IN ('queued', 'running')`,
    )
    .bind(now, now, crawlId)
    .run();
  if ((res.meta?.changes ?? 0) === 0) {
    const exists = await metaDb.prepare('SELECT status FROM crawls WHERE id = ? LIMIT 1').bind(crawlId).first<{ status: string }>();
    if (!exists) return { ok: false, status: 404 };
  }
  return { ok: true, status: 200 };
}

export class CrawlWorkflow extends WorkflowEntrypoint<OptionalStorageBindings, CrawlWorkflowParams> {
  override async run(event: WorkflowEvent<CrawlWorkflowParams>, step: WorkflowStep): Promise<{ crawlId: string; status: string }> {
    const status = await step.do('check-crawl-record', async () => {
      if (!this.env.META) return 'unconfigured';
      const row = await this.env.META
        .prepare('SELECT status FROM crawls WHERE id = ? LIMIT 1')
        .bind(event.payload.crawlId)
        .first<{ status: string }>();
      return row?.status ?? 'missing';
    });
    return { crawlId: event.payload.crawlId, status };
  }
}
