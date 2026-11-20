/**
 * Zero-dependency TypeScript client SDK for EdgeFetch v2.1 (`sdk/ts/edgefetch-client.ts`).
 * Runs unmodified in Cloudflare Workers, Node.js >= 20, Deno, Bun, and browsers using standard `fetch`.
 */

export type ScrapeFormat =
  | 'markdown'
  | 'text'
  | 'html'
  | 'rawHtml'
  | 'links'
  | 'images'
  | 'branding'
  | 'llmsTxt'
  | 'screenshot'
  | 'changes'
  | { type: 'json'; schema: Record<string, unknown> };

export interface EdgeFetchClientOptions {
  /** Single Hub URL (e.g. `https://edgefetch.example.com`). */
  baseUrl?: string;
  /** Ordered list of Hub URLs for active-standby HA failover (e.g. `[cloudflareHub, tailscaleGoHub]`). */
  baseUrls?: string[];
  token: string;
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
  renderMode?: 'off' | 'auto' | 'always';
  waitForMs?: number;
  waitSelector?: string;
  maxPages?: number;
  redactPii?: boolean;
  query?: string;
  collectionId?: string;
  target?: 'auto' | 'agent' | 'container';
  site?: string;
}

export interface ExtractParams {
  urls: string[];
  query?: string;
  mode?: 'chunks' | 'full';
  chunksPerSource?: number;
  maxChars?: number;
  maxAgeMs?: number;
  noCache?: boolean;
  ephemeral?: boolean;
  ocr?: boolean;
  redactPii?: boolean;
  collectionId?: string;
  target?: 'auto' | 'agent' | 'container';
  site?: string;
}

export interface MapParams {
  url: string;
  search?: string;
  limit?: number;
  includeSubdomains?: boolean;
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
    this.baseUrls = [...new Set(urls)];
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

  interact(params: InteractParams): Promise<Record<string, unknown>> {
    return this.requestJson('POST', '/v1/interact', params);
  }

  readArtifact(blobSha256: string, offset = 0, limit = 65_536, format: 'raw' | 'markdown' = 'raw'): Promise<Record<string, unknown>> {
    return this.requestJson(
      'GET',
      `/v1/artifacts/${encodeURIComponent(blobSha256)}?format=${format === 'markdown' ? 'markdown' : 'json'}&offset=${offset}&limit=${limit}`,
    );
  }
}
