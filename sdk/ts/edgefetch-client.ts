/**
 * Zero-dependency TypeScript client SDK for EdgeFetch v2.1 (`sdk/ts/edgefetch-client.ts`).
 * Runs unmodified in Cloudflare Workers, Node.js >= 20, Deno, Bun, and browsers using standard `fetch`.
 */

export type ScrapeFormat =
  | 'markdown'
  | 'text'
  | 'summary'
  | 'product'
  | 'rawBase64'
  | 'html'
  | 'rawHtml'
  | 'links'
  | 'images'
  | 'branding'
  | 'llmsTxt'
  | 'screenshot'
  | 'changes'
  | 'changeTracking'
  | { type: 'json'; prompt?: string; schema?: Record<string, unknown> }
  | { type: 'attributes'; selectors: Array<{ selector: string; attribute: string }> }
  | { type: 'screenshot'; fullPage?: boolean; quality?: number; viewport?: { width?: number; height?: number } }
  | { type: 'changeTracking'; modes?: Array<'git-diff' | 'json'>; tag?: string };

export interface EdgeFetchRequestOptions {
  /** Optional W3C `traceparent` header overriding the client default for this request (`''` suppresses header). */
  traceparent?: string;
}

export interface EdgeFetchClientOptions {
  /** Single Hub URL (e.g. `https://edgefetch.example.com`). */
  baseUrl?: string;
  /** Ordered list of Hub URLs for active-standby HA failover (e.g. `[cloudflareHub, tailscaleGoHub]`). */
  baseUrls?: string[];
  token: string;
  /** Allow cleartext `http://` Hub URLs for non-loopback hosts (default `false`; `127.0.0.1` / `localhost` / `[::1]` are always allowed). */
  allowInsecureHttp?: boolean;
  fetchFn?: typeof fetch;
  /** Optional default W3C `traceparent` header forwarded on every request unless overridden per call. */
  traceparent?: string;
}

export interface ScrapeParams {
  url: string;
  formats?: ScrapeFormat[];
  onlyMainContent?: boolean;
  includeTags?: string[];
  excludeTags?: string[];
  discoverLlmsTxt?: boolean;
  maxAgeMs?: number;
  noCache?: boolean;
  ephemeral?: boolean;
  maxChars?: number;
  ocr?: boolean;
  renderMode?: 'off' | 'auto' | 'always' | 'browser';
  waitForMs?: number;
  waitSelector?: string;
  maxPages?: number;
  redactPii?: boolean;
  query?: string;
  jsonFilter?: string;
  collectionId?: string;
  waybackFallback?: boolean;
  spaFallback?: 'auto' | 'off' | 'crawl4ai' | 'firecrawl';
  target?: 'auto' | 'agent' | 'container';
  site?: string;
}

export interface ExtractParams {
  urls: string[];
  query?: string;
  jsonFilter?: string;
  renderMode?: 'off' | 'auto' | 'always' | 'browser';
  mode?: 'chunks' | 'full';
  chunksPerSource?: number;
  maxChars?: number;
  maxAgeMs?: number;
  noCache?: boolean;
  ephemeral?: boolean;
  ocr?: boolean;
  redactPii?: boolean;
  collectionId?: string;
  waybackFallback?: boolean;
  spaFallback?: 'auto' | 'off' | 'crawl4ai' | 'firecrawl';
  target?: 'auto' | 'agent' | 'container';
  site?: string;
}

export interface MapParams {
  url: string;
  search?: string;
  limit?: number;
  includeSubdomains?: boolean;
  includeOutsidePath?: boolean;
  ignoreSitemap?: boolean;
}

export interface CrawlParams {
  url: string;
  limit?: number;
  maxDepth?: number;
  allowSubdomains?: boolean;
  includePaths?: string[];
  excludePaths?: string[];
  collectionId?: string;
  renderMode?: 'off' | 'auto' | 'always';
  webhook?: {
    url: string;
    secret?: string;
    events?: Array<'crawl.started' | 'crawl.page' | 'crawl.completed' | 'crawl.failed'>;
    metadata?: Record<string, unknown>;
  };
}

export interface SearchParams {
  query: string;
  max_results?: number;
  include_domains?: string[];
  exclude_domains?: string[];
  time_range?: 'day' | 'week' | 'month' | 'year';
  max_age_ms?: number;
  include_answer?: boolean;
  include_raw_content?: boolean;
  chunks_per_source?: number;
  collections?: string[];
}

export interface InteractAction {
  type: 'click' | 'fill' | 'type' | 'press' | 'wait' | 'scroll' | 'select' | 'navigate';
  selector?: string;
  value?: string;
  key?: string;
  url?: string;
  waitMs?: number;
}

export interface InteractParams {
  url?: string;
  sessionId?: string;
  keepSession?: boolean;
  closeSession?: boolean;
  transcript?: boolean;
  actions?: InteractAction[];
  formats?: Array<'markdown' | 'html' | 'screenshot'>;
  waitForMs?: number;
  waitSelector?: string;
  site?: string;
}

export class EdgeFetchError extends Error {
  public readonly status: number;
  public readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'EdgeFetchError';
    this.status = status;
    this.code = code;
  }
}

const TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i;
const ALL_ZERO_32 = '0'.repeat(32);
const ALL_ZERO_16 = '0'.repeat(16);

type HeaderLike = Headers | Record<string, unknown> | null | undefined;

function sanitizeTraceparentHeader(raw?: string): string | undefined {
  if (raw === undefined) return undefined;
  if (/[\r\n\0]/.test(raw)) {
    throw new Error('Invalid traceparent header: contains forbidden CR, LF, or NUL character');
  }
  const trimmed = raw.trim();
  return trimmed || undefined;
}

function readHeader(headers: HeaderLike, name: string): string | null {
  if (!headers || typeof headers !== 'object') return null;
  if (typeof (headers as Headers).get === 'function') {
    const val = (headers as Headers).get(name);
    const cleaned = typeof val === 'string' ? val.trim() : '';
    return cleaned || null;
  }
  const target = name.toLowerCase();
  for (const [key, val] of Object.entries(headers)) {
    if (key.toLowerCase() === target && typeof val === 'string') {
      const cleaned = val.trim();
      return cleaned || null;
    }
  }
  return null;
}

function extractTraceIdFromTraceparent(headerValue: string | null): string | null {
  if (!headerValue) return null;
  const match = TRACEPARENT_RE.exec(headerValue.trim());
  if (!match) return null;
  const traceId = match[1]!.toLowerCase();
  const spanId = match[2]!.toLowerCase();
  if (traceId === ALL_ZERO_32 || spanId === ALL_ZERO_16) return null;
  return traceId;
}

function isLoopbackHostname(hostname: string): boolean {
  const clean = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');
  return clean === '127.0.0.1' || clean === 'localhost' || clean === '::1';
}

function validateHubOrigin(raw: string, allowInsecureHttp: boolean): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`Invalid EdgeFetch Hub baseUrl "${raw}": expected https:// origin`);
  }
  const proto = parsed.protocol.toLowerCase();
  if (proto !== 'https:' && proto !== 'http:') {
    throw new Error(`Unsupported EdgeFetch Hub protocol "${parsed.protocol}" in "${raw}": expected https://`);
  }
  if (proto === 'http:' && !allowInsecureHttp && !isLoopbackHostname(parsed.hostname)) {
    throw new Error(
      `Refusing cleartext http:// Hub URL "${raw}" for non-loopback host "${parsed.hostname}" (use https:// or set allowInsecureHttp: true)`,
    );
  }
  return raw;
}

export class EdgeFetchClient {
  private readonly baseUrls: string[];
  private readonly token: string;
  private readonly fetchFn: typeof fetch;
  private readonly defaultTraceparent: string | undefined;
  public lastTraceId: string | null = null;
  public lastTraceparent: string | null = null;

  constructor(options: EdgeFetchClientOptions) {
    const urls = [
      ...(options.baseUrls ?? []),
      ...(options.baseUrl ? [options.baseUrl] : []),
    ]
      .map((u) => u.trim().replace(/\/+$/, ''))
      .filter(Boolean);
    if (urls.length === 0) {
      throw new Error('EdgeFetchClient requires baseUrl or non-empty baseUrls');
    }
    const allowInsecure = options.allowInsecureHttp === true;
    this.baseUrls = [...new Set(urls)].map((u) => validateHubOrigin(u, allowInsecure));
    this.token = options.token;
    this.fetchFn = options.fetchFn ?? fetch;
    this.defaultTraceparent = sanitizeTraceparentHeader(options.traceparent);
  }

  private captureTraceHeaders(headers: HeaderLike): void {
    const rawTraceparent = readHeader(headers, 'traceparent');
    const rawTraceId = readHeader(headers, 'x-trace-id');
    this.lastTraceparent = rawTraceparent;
    this.lastTraceId = rawTraceId ?? extractTraceIdFromTraceparent(rawTraceparent);
  }

  private async requestJson<T>(
    method: string,
    path: string,
    body?: unknown,
    requestOptions?: EdgeFetchRequestOptions,
  ): Promise<T> {
    let lastError: unknown;
    const serializedBody = body !== undefined ? JSON.stringify(body) : undefined;
    const traceparent =
      requestOptions?.traceparent !== undefined
        ? sanitizeTraceparentHeader(requestOptions.traceparent)
        : this.defaultTraceparent;

    for (let idx = 0; idx < this.baseUrls.length; idx++) {
      this.lastTraceId = null;
      this.lastTraceparent = null;
      const origin = this.baseUrls[idx]!;
      let res: Response;
      try {
        res = await this.fetchFn(`${origin}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.token}`,
            accept: 'application/json',
            ...(traceparent ? { traceparent } : {}),
            ...(serializedBody !== undefined ? { 'content-type': 'application/json' } : {}),
          },
          ...(serializedBody !== undefined ? { body: serializedBody } : {}),
        });
      } catch (networkErr) {
        lastError = networkErr;
        continue;
      }

      this.captureTraceHeaders(res.headers as HeaderLike);
      const rawJson: unknown = await res.json().catch(() => ({}));
      if (!res.ok) {
        const json = rawJson !== null && typeof rawJson === 'object' ? (rawJson as Record<string, unknown>) : {};
        const efErr = new EdgeFetchError(
          res.status,
          typeof json.error === 'string' ? json.error : `http_${res.status}`,
          typeof json.message === 'string' ? json.message : `EdgeFetch HTTP ${res.status}`,
        );
        // Fail over to next standby controller on 502 / 503 / 504 gateway/hub unavailability.
        if (res.status === 502 || res.status === 503 || res.status === 504) {
          lastError = efErr;
          continue;
        }
        throw efErr;
      }
      return rawJson as T;
    }

    throw lastError instanceof Error ? lastError : new Error('All EdgeFetch Hub endpoints failed');
  }

  capabilities(requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('GET', '/v1/capabilities', undefined, requestOptions);
  }

  hosts(limit = 100, requestOptions?: EdgeFetchRequestOptions): Promise<{ ok: boolean; hosts: Array<Record<string, unknown>> }> {
    return this.requestJson(
      'GET',
      `/v1/hosts?limit=${Math.max(1, Math.min(500, Math.floor(limit)))}`,
      undefined,
      requestOptions,
    );
  }

  extractors(category?: string, requestOptions?: EdgeFetchRequestOptions): Promise<{
    ok: boolean;
    total: number;
    categories: Record<string, number>;
    extractors: Array<Record<string, unknown>>;
  }> {
    const qs = category ? `?category=${encodeURIComponent(category)}` : '';
    return this.requestJson('GET', `/v1/extractors${qs}`, undefined, requestOptions);
  }

  scrape(params: ScrapeParams, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/scrape', params, requestOptions);
  }

  extract(params: ExtractParams, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/extract', params, requestOptions);
  }

  map(params: MapParams, requestOptions?: EdgeFetchRequestOptions): Promise<{ ok: boolean; url: string; total: number; links: string[]; entries: unknown[] }> {
    return this.requestJson('POST', '/v1/map', params, requestOptions);
  }

  crawl(params: CrawlParams, requestOptions?: EdgeFetchRequestOptions): Promise<{ ok: boolean; id: string; status: string; collectionId?: string; url: string }> {
    return this.requestJson('POST', '/v1/crawl', params, requestOptions);
  }

  getCrawl(crawlId: string, offset = 0, limit = 25, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('GET', `/v1/crawl/${encodeURIComponent(crawlId)}?offset=${offset}&limit=${limit}`, undefined, requestOptions);
  }

  cancelCrawl(crawlId: string, requestOptions?: EdgeFetchRequestOptions): Promise<{ ok: boolean; id: string; status: string }> {
    return this.requestJson('DELETE', `/v1/crawl/${encodeURIComponent(crawlId)}`, undefined, requestOptions);
  }

  search(params: SearchParams, requestOptions?: EdgeFetchRequestOptions): Promise<{ ok: boolean; query: string; results: Array<Record<string, unknown>> }> {
    return this.requestJson('POST', '/v1/search', params, requestOptions);
  }

  jobs(params: {
    query?: string;
    company?: string;
    domains?: string[];
    remote?: boolean;
    locations?: string[];
    minBase?: number;
    postedWithinDays?: number;
    limit?: number;
    includeBuiltIn?: boolean;
    exclude?: Array<{ company?: string; title?: string; url?: string }>;
  }, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/jobs', params, requestOptions);
  }

  interact(params: InteractParams, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/interact', params, requestOptions);
  }

  batchScrape(params: { urls: string[]; sync?: boolean; [key: string]: unknown }, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/batch/scrape', params, requestOptions);
  }

  getBatchScrape(batchId: string, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('GET', `/v1/batch/scrape/${encodeURIComponent(batchId)}`, undefined, requestOptions);
  }

  cancelBatchScrape(batchId: string, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('DELETE', `/v1/batch/scrape/${encodeURIComponent(batchId)}`, undefined, requestOptions);
  }

  previewCrawlParams(params: { url: string; prompt: string }, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/crawl/params-preview', params, requestOptions);
  }

  agent(params: {
    prompt: string;
    urls?: string[];
    strictConstrainToURLs?: boolean;
    schema?: Record<string, unknown>;
    effort?: 'low' | 'medium' | 'high';
    maxSteps?: number;
    maxPages?: number;
    threadId?: string;
    zeroDataRetention?: boolean;
    async?: boolean;
    safe?: boolean;
    location?: { country?: string; languages?: string[] };
    llm?: { provider?: string; baseUrl?: string; model?: string; apiKey?: string };
  }, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/agent', params, requestOptions);
  }

  getAgent(agentId: string, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('GET', `/v1/agent/${encodeURIComponent(agentId)}`, undefined, requestOptions);
  }

  getAgentTrace(agentId: string, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('GET', `/v1/agent/${encodeURIComponent(agentId)}/trace`, undefined, requestOptions);
  }

  cancelAgent(agentId: string, requestOptions?: EdgeFetchRequestOptions): Promise<Record<string, unknown>> {
    return this.requestJson('DELETE', `/v1/agent/${encodeURIComponent(agentId)}`, undefined, requestOptions);
  }

  readArtifact(
    blobSha256: string,
    offset = 0,
    limit = 65_536,
    format: 'raw' | 'markdown' = 'raw',
    requestOptions?: EdgeFetchRequestOptions,
  ): Promise<Record<string, unknown>> {
    return this.requestJson(
      'GET',
      `/v1/artifacts/${encodeURIComponent(blobSha256)}?format=${format === 'markdown' ? 'markdown' : 'json'}&offset=${offset}&limit=${limit}`,
      undefined,
      requestOptions,
    );
  }
}
