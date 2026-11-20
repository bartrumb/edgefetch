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

export interface EdgeFetchClientOptions {
  /** Single Hub URL (e.g. `https://edgefetch.example.com`). */
  baseUrl?: string;
  /** Ordered list of Hub URLs for active-standby HA failover (e.g. `[cloudflareHub, tailscaleGoHub]`). */
  baseUrls?: string[];
  token: string;
  /** Allow cleartext `http://` Hub URLs for non-loopback hosts (default `false`; `127.0.0.1` / `localhost` / `[::1]` are always allowed). */
  allowInsecureHttp?: boolean;
  fetchFn?: typeof fetch;
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
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'EdgeFetchError';
  }
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
  }

  private async requestJson<T>(method: string, path: string, body?: unknown): Promise<T> {
    let lastError: unknown;
    const serializedBody = body !== undefined ? JSON.stringify(body) : undefined;

    for (let idx = 0; idx < this.baseUrls.length; idx++) {
      const origin = this.baseUrls[idx]!;
      const hasMore = idx + 1 < this.baseUrls.length;
      let res: Response;
      try {
        res = await this.fetchFn(`${origin}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.token}`,
            accept: 'application/json',
            ...(serializedBody !== undefined ? { 'content-type': 'application/json' } : {}),
          },
          ...(serializedBody !== undefined ? { body: serializedBody } : {}),
        });
      } catch (networkErr) {
        lastError = networkErr;
        if (hasMore) continue;
        throw networkErr;
      }

      const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      if (!res.ok) {
        const efErr = new EdgeFetchError(
          res.status,
          typeof json.error === 'string' ? json.error : `http_${res.status}`,
          typeof json.message === 'string' ? json.message : `EdgeFetch HTTP ${res.status}`,
        );
        // Fail over to next standby controller on 502 / 503 / 504 gateway/hub unavailability.
        if (hasMore && (res.status === 502 || res.status === 503 || res.status === 504)) {
          lastError = efErr;
          continue;
        }
        throw efErr;
      }
      return json as T;
    }

    throw lastError instanceof Error ? lastError : new Error('All EdgeFetch Hub endpoints failed');
  }

  capabilities(): Promise<Record<string, unknown>> {
    return this.requestJson('GET', '/v1/capabilities');
  }

  hosts(limit = 100): Promise<{ ok: boolean; hosts: Array<Record<string, unknown>> }> {
    return this.requestJson('GET', `/v1/hosts?limit=${Math.max(1, Math.min(500, Math.floor(limit)))}`);
  }

  extractors(category?: string): Promise<{
    ok: boolean;
    total: number;
    categories: Record<string, number>;
    extractors: Array<Record<string, unknown>>;
  }> {
    const qs = category ? `?category=${encodeURIComponent(category)}` : '';
    return this.requestJson('GET', `/v1/extractors${qs}`);
  }

  scrape(params: ScrapeParams): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/scrape', params);
  }

  extract(params: ExtractParams): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/extract', params);
  }

  map(params: MapParams): Promise<{ ok: boolean; url: string; total: number; links: string[]; entries: unknown[] }> {
    return this.requestJson('POST', '/v1/map', params);
  }

  crawl(params: CrawlParams): Promise<{ ok: boolean; id: string; status: string; collectionId?: string; url: string }> {
    return this.requestJson('POST', '/v1/crawl', params);
  }

  getCrawl(crawlId: string, offset = 0, limit = 25): Promise<Record<string, unknown>> {
    return this.requestJson('GET', `/v1/crawl/${encodeURIComponent(crawlId)}?offset=${offset}&limit=${limit}`);
  }

  cancelCrawl(crawlId: string): Promise<{ ok: boolean; id: string; status: string }> {
    return this.requestJson('DELETE', `/v1/crawl/${encodeURIComponent(crawlId)}`);
  }

  search(params: SearchParams): Promise<{ ok: boolean; query: string; results: Array<Record<string, unknown>> }> {
    return this.requestJson('POST', '/v1/search', params);
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
  }): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/jobs', params);
  }

  interact(params: InteractParams): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/interact', params);
  }

  batchScrape(params: { urls: string[]; sync?: boolean; [key: string]: unknown }): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/batch/scrape', params);
  }

  getBatchScrape(batchId: string): Promise<Record<string, unknown>> {
    return this.requestJson('GET', `/v1/batch/scrape/${encodeURIComponent(batchId)}`);
  }

  cancelBatchScrape(batchId: string): Promise<Record<string, unknown>> {
    return this.requestJson('DELETE', `/v1/batch/scrape/${encodeURIComponent(batchId)}`);
  }

  previewCrawlParams(params: { url: string; prompt: string }): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/crawl/params-preview', params);
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
  }): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/agent', params);
  }

  getAgent(agentId: string): Promise<Record<string, unknown>> {
    return this.requestJson('GET', `/v1/agent/${encodeURIComponent(agentId)}`);
  }

  getAgentTrace(agentId: string): Promise<Record<string, unknown>> {
    return this.requestJson('GET', `/v1/agent/${encodeURIComponent(agentId)}/trace`);
  }

  cancelAgent(agentId: string): Promise<Record<string, unknown>> {
    return this.requestJson('DELETE', `/v1/agent/${encodeURIComponent(agentId)}`);
  }

  readArtifact(blobSha256: string, offset = 0, limit = 65_536, format: 'raw' | 'markdown' = 'raw'): Promise<Record<string, unknown>> {
    return this.requestJson(
      'GET',
      `/v1/artifacts/${encodeURIComponent(blobSha256)}?format=${format === 'markdown' ? 'markdown' : 'json'}&offset=${offset}&limit=${limit}`,
    );
  }
}
