/**
 * Canonical zero-drift OpenAPI 3.1.0 specification generator and `GET /openapi.json` route handler.
 *
 * - Shares JSON Schema 2020-12 tool payloads directly with `hub/src/mcp.ts` (`MCP_TOOL_SCHEMAS`) so MCP `tools/list`
 *   and REST `/v1/*` request schemas can never drift.
 * - Zero external npm dependencies; runs identically on Cloudflare Workers, Node.js 22+ Portable Hub, and Deno.
 * - Strictly sanitizes `origin` (`https:` or loopback `http:` only, falling back to `https://edgefetch.dev`) to prevent
 *   `Host` header poisoning of `servers[].url` and OAuth 2.1 endpoint URLs.
 */

import { buildCanonicalMcpToolSchemas, MCP_TOOL_SCHEMAS, TEXT_ACCEPTS } from './mcp';

export const DEFAULT_OPENAPI_ORIGIN = 'https://edgefetch.dev';
export const DEFAULT_OPENAPI_VERSION = '2.8.1';

export interface BuildOpenApiOptions {
  origin?: string;
  version?: string;
}

function isLoopbackHostname(hostname: string): boolean {
  const h = hostname.trim().toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '[::1]' || h === '::1';
}

/**
 * Validates `origin` strictly via `new URL(origin).origin`, allowing only `https:` or loopback `http:` origins
 * (`127.0.0.1`, `localhost`, `[::1]`) and falling back to `https://edgefetch.dev` when malformed or untrusted.
 */
export function sanitizeOpenApiOrigin(rawOrigin?: string): string {
  if (typeof rawOrigin !== 'string' || !rawOrigin.trim()) {
    return DEFAULT_OPENAPI_ORIGIN;
  }
  try {
    const parsed = new URL(rawOrigin.trim());
    if (parsed.username || parsed.password || parsed.origin === 'null') {
      return DEFAULT_OPENAPI_ORIGIN;
    }
    if (parsed.protocol === 'https:') {
      return parsed.origin;
    }
    if (parsed.protocol === 'http:' && isLoopbackHostname(parsed.hostname)) {
      return parsed.origin;
    }
    return DEFAULT_OPENAPI_ORIGIN;
  } catch {
    return DEFAULT_OPENAPI_ORIGIN;
  }
}

function resolveOpenApiContentType(acceptHeader: string | null): string {
  const accept = (acceptHeader ?? '').toLowerCase();
  const openapiIdx = accept.indexOf('application/openapi+json');
  if (openapiIdx >= 0) {
    const jsonIdx = accept.indexOf('application/json');
    if (jsonIdx < 0 || openapiIdx < jsonIdx) {
      return 'application/openapi+json; charset=utf-8';
    }
  }
  return 'application/json; charset=utf-8';
}

function authReadSecurity() {
  return [{ bearerAuth: [] }, { oauth2Pkce: ['crawl:read'] }];
}

function authFetchSecurity() {
  return [{ bearerAuth: [] }, { oauth2Pkce: ['crawl:fetch'] }];
}

function authMcpQuerySecurity() {
  return [{ bearerAuth: [] }, { oauth2Pkce: ['crawl:read', 'mcp:call'] }];
}

function jsonContent(schemaRefOrObj: Record<string, unknown>) {
  return {
    'application/json': {
      schema: schemaRefOrObj,
    },
  };
}

function schemaRef(name: string): Record<string, string> {
  return { $ref: `#/components/schemas/${name}` };
}

function standardAuthErrorResponses() {
  return {
    '400': {
      description: 'Malformed JSON body or invalid request parameters.',
      content: jsonContent(schemaRef('ErrorResponse')),
    },
    '401': {
      description: 'Missing or invalid Bearer token / OAuth 2.1 access token.',
      headers: {
        'WWW-Authenticate': {
          description: 'RFC 9728 OAuth 2.1 Protected Resource challenge header.',
          schema: { type: 'string' },
        },
      },
      content: jsonContent(schemaRef('ErrorResponse')),
    },
    '403': {
      description: 'Insufficient OAuth 2.1 scope (`crawl:read`, `crawl:fetch`, or `mcp:call`) or policy block.',
      content: jsonContent(schemaRef('ErrorResponse')),
    },
  };
}

/**
 * Builds the deterministic OpenAPI `3.1.0` specification document for EdgeFetch Hub.
 */
export function buildOpenApiSpec(options: BuildOpenApiOptions = {}): Record<string, unknown> {
  const safeOrigin = sanitizeOpenApiOrigin(options.origin);
  const version = (options.version ?? DEFAULT_OPENAPI_VERSION).trim() || DEFAULT_OPENAPI_VERSION;

  const mcpTools = buildCanonicalMcpToolSchemas();
  const mcpToolSchemaEntries: Record<string, Record<string, unknown>> = {};
  for (const tool of mcpTools) {
    const pascal = tool.name
      .split('_')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join('');
    mcpToolSchemaEntries[`McpTool_${pascal}Input`] = {
      title: `${tool.annotations.title} (MCP ${tool.name})`,
      description: tool.description,
      ...tool.inputSchema,
    };
  }

  const scrapeProps = MCP_TOOL_SCHEMAS.scrape!.properties;
  const crawlProps = MCP_TOOL_SCHEMAS.crawl!.properties;
  const agentProps = MCP_TOOL_SCHEMAS.agent!.properties;
  const collectionSearchProps = MCP_TOOL_SCHEMAS.search_collection!.properties;

  return {
    openapi: '3.1.0',
    jsonSchemaDialect: 'https://spec.openapis.org/oas/3.1/dialect/base',
    info: {
      title: 'EdgeFetch Hub API',
      summary: 'Self-hosted web scraping, search, browser automation, and MCP coordinator for AI agents.',
      version,
      description:
        'EdgeFetch Hub coordinates polite outbound-only Go worker nodes (HTTP/2, Headless Chromium, Poppler PDF/OCR, and 49+ keyless site adapters) with strict RFC 9309 robots.txt and Content-Signal compliance, D1 FTS5 hybrid search, R2 content-addressed artifacts, self-hosted OAuth 2.1 PKCE, and Streamable HTTP Model Context Protocol (`POST /mcp`).',
      contact: {
        name: 'EdgeFetch',
        url: 'https://edgefetch.dev',
      },
      license: {
        name: 'FSL-1.1-MIT (Hub) / MIT (Worker, SDKs & Adapters)',
        url: 'https://github.com/bartrumb/edgefetch/blob/main/README.md#license--trademarks',
      },
    },
    servers: [
      {
        url: safeOrigin,
        description:
          safeOrigin === DEFAULT_OPENAPI_ORIGIN
            ? 'EdgeFetch Canonical Specification Origin (replace with your self-hosted Hub URL)'
            : 'EdgeFetch Hub Instance',
      },
    ],
    tags: [
      {
        name: 'Discovery',
        description: 'Health checks, OpenAPI 3.1.0 schema, RFC 9421 Web Bot Auth directory, and OAuth 2.1 metadata.',
      },
      {
        name: 'System',
        description: 'Hub capabilities, keyless site adapters, per-host health telemetry, stored artifacts, and worker fleet.',
      },
      {
        name: 'Scraping & Extraction',
        description: 'Polite URL-to-Markdown scraping, multi-URL batch scraping, BM25 passage extraction, and tab clipping.',
      },
      {
        name: 'Browser Automation',
        description: 'Sandboxed Headless Chromium interaction with dial-time SSRF isolation and session persistence.',
      },
      {
        name: 'Crawl & Map',
        description: 'Fast sitemap/llms.txt URL discovery and asynchronous breadth-first site crawling.',
      },
      {
        name: 'Search & Collections',
        description: 'Edge-first web search waterfall (Serper/Tavily/Brave/SearXNG) and private D1 FTS5 collection search.',
      },
      {
        name: 'Vertical Intelligence',
        description: 'Normalized multi-ATS job search/verification and polite full-store Shopify/WooCommerce catalog diffing.',
      },
      {
        name: 'Autonomous Agent',
        description: 'Multi-step web research and structured JSON extraction powered by BYO-LLM or local Ollama.',
      },
      {
        name: 'Coordinator & MCP',
        description: 'Low-level multi-URL coordinator dispatch (`POST /fetch`) and Streamable HTTP MCP (`POST /mcp`).',
      },
      {
        name: 'Compatibility',
        description: 'Drop-in Firecrawl v2 (`/v2/*`) compatibility endpoints for unmodified third-party SDKs.',
      },
    ],
    paths: {
      '/health': {
        get: {
          tags: ['Discovery'],
          operationId: 'getHealth',
          summary: 'Check Hub liveness',
          description: 'Returns HTTP 200 `{ "ok": true }` without authentication for uptime monitors and container health checks.',
          security: [],
          responses: {
            '200': {
              description: 'Hub is healthy.',
              content: jsonContent(schemaRef('HealthResponse')),
            },
          },
        },
      },
      '/openapi.json': {
        get: {
          tags: ['Discovery'],
          operationId: 'getOpenApiSpec',
          summary: 'Fetch OpenAPI 3.1.0 specification',
          description:
            'Returns this OpenAPI 3.1.0 document with permissive CORS (`Access-Control-Allow-Origin: *`) for 1-click import into ChatGPT Actions, OpenWebUI, Dify, n8n, Postman, and Scalar.',
          security: [],
          responses: {
            '200': {
              description: 'OpenAPI 3.1.0 JSON document.',
              content: {
                'application/json': { schema: { type: 'object' } },
                'application/openapi+json': { schema: { type: 'object' } },
              },
            },
          },
        },
      },
      '/.well-known/edgefetch-bot.json': {
        get: {
          tags: ['Discovery'],
          operationId: 'getBotManifest',
          summary: 'Get machine-readable bot transparency manifest',
          description:
            'Declares EdgeFetch User-Agent, strict RFC 9309 robots.txt and Content-Signal (`ai-input`) policies, anti-bot challenge halt guarantee, and RFC 9421 Web Bot Auth key directory link.',
          security: [],
          responses: {
            '200': {
              description: 'Bot transparency manifest.',
              content: jsonContent(schemaRef('BotManifestResponse')),
            },
          },
        },
      },
      '/.well-known/http-message-signatures-directory': {
        get: {
          tags: ['Discovery'],
          operationId: 'getBotSignaturesDirectory',
          summary: 'Get RFC 9421 Web Bot Auth Ed25519 JWKS directory',
          description:
            'Serves public Ed25519 signing keys (`application/http-message-signatures-directory+json`) with cryptographic self-signatures for origin verification.',
          security: [],
          responses: {
            '200': {
              description: 'RFC 9421 HTTP Message Signatures JWKS directory.',
              content: {
                'application/http-message-signatures-directory+json': {
                  schema: schemaRef('BotKeyDirectoryResponse'),
                },
              },
            },
          },
        },
      },
      '/.well-known/oauth-protected-resource': {
        get: {
          tags: ['Discovery'],
          operationId: 'getOAuthProtectedResource',
          summary: 'Get RFC 9728 OAuth 2.1 Protected Resource metadata',
          description: 'Advertises protected MCP resource URI, authorization server issuer, and supported scopes (`crawl:read`, `crawl:fetch`, `mcp:call`).',
          security: [],
          responses: {
            '200': {
              description: 'OAuth 2.1 Protected Resource metadata.',
              content: jsonContent(schemaRef('OAuthProtectedResourceMetadata')),
            },
          },
        },
      },
      '/.well-known/oauth-authorization-server': {
        get: {
          tags: ['Discovery'],
          operationId: 'getOAuthAuthorizationServer',
          summary: 'Get RFC 8414 OAuth 2.1 Authorization Server metadata',
          description:
            'Advertises `/oauth/authorize`, `/oauth/token`, `/oauth/register` (RFC 7591 Dynamic Client Registration), `/oauth/revoke`, and mandatory `S256` PKCE support (with optional multi-user Sign in with GitHub).',
          security: [],
          responses: {
            '200': {
              description: 'OAuth 2.1 Authorization Server metadata.',
              content: jsonContent(schemaRef('OAuthAuthorizationServerMetadata')),
            },
          },
        },
      },
      '/admin/auth/github': {
        get: {
          tags: ['Discovery'],
          operationId: 'startGitHubOAuthLogin',
          summary: 'Start Sign in with GitHub OAuth 2.0 + PKCE S256 login',
          description:
            'Initiates an `oauth4webapi` OAuth 2.0 + PKCE (`S256`) + sealed `state` cookie redirect to GitHub (`https://github.com/login/oauth/authorize`) for `/admin` and `/oauth/authorize` multi-user authentication.',
          security: [],
          parameters: [
            {
              name: 'return_to',
              in: 'query',
              required: false,
              description: 'Optional relative Hub path (`/admin` or `/oauth/authorize?...`) to return to after sign-in.',
              schema: { type: 'string' },
            },
          ],
          responses: {
            '302': {
              description: 'Redirect to GitHub OAuth 2.0 authorization endpoint.',
            },
            '503': {
              description: 'GitHub OAuth (`GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`) is not configured on this Hub.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
          },
        },
      },
      '/admin/auth/github/callback': {
        get: {
          tags: ['Discovery'],
          operationId: 'completeGitHubOAuthCallback',
          summary: 'Complete Sign in with GitHub OAuth 2.0 callback',
          description:
            'Validates OAuth `state` + PKCE `S256`, verifies `SIGNUP_MODE` (`invite_only` default) + `GITHUB_ALLOWED_USERS` (`login` or `@org`) + `GITHUB_OWNER_LOGIN`, and issues an `HS256` `jose` session JWT cookie.',
          security: [],
          parameters: [
            { name: 'code', in: 'query', required: false, schema: { type: 'string' } },
            { name: 'state', in: 'query', required: false, schema: { type: 'string' } },
          ],
          responses: {
            '302': { description: 'Authenticated session cookie issued; redirecting back to Hub UI.' },
            '400': { description: 'Missing/invalid state cookie or OAuth callback error.' },
            '403': { description: 'GitHub account is not authorized under `SIGNUP_MODE` / `GITHUB_ALLOWED_USERS`.' },
          },
        },
      },
      '/v1/capabilities': {
        get: {
          tags: ['System'],
          operationId: 'getCapabilities',
          summary: 'Inspect Hub storage, search, OCR, and LLM bindings',
          description: 'Reports configured Hub bindings (`ARTIFACTS` R2, `META` D1, `SEARCH` D1 FTS5, `INGEST` Workflow, SERP providers, and BYO-LLM readiness).',
          security: authReadSecurity(),
          responses: {
            '200': {
              description: 'Hub capability report.',
              content: jsonContent(schemaRef('CapabilitiesResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/extractors': {
        get: {
          tags: ['System'],
          operationId: 'listExtractors',
          summary: 'List built-in keyless site and API adapters',
          description:
            'Lists EdgeFetch’s 49+ built-in keyless site adapters (SEC EDGAR, Ashby/Greenhouse/Lever/Workday ATS, arXiv, OpenAlex, PubChem, NVD CVEs, npm, PyPI, Crates, Shopify, etc.).',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'category',
              in: 'query',
              required: false,
              description: 'Optional adapter category filter.',
              schema: {
                type: 'string',
                enum: ['jobs', 'finance', 'public-records', 'research-health', 'developer', 'genai', 'commerce-social'],
              },
            },
          ],
          responses: {
            '200': {
              description: 'Registered keyless site adapters.',
              content: jsonContent(schemaRef('ExtractorsResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/hosts': {
        get: {
          tags: ['System'],
          operationId: 'listHostHealth',
          summary: 'List per-host politeness, EWMA TTFB, and 429 health metrics',
          description: 'Returns per-origin EWMA latency, recommended polite pause intervals, HTTP 429 streaks, and detected WAF vendors.',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'limit',
              in: 'query',
              required: false,
              description: 'Maximum host health records to return (1..500, default 100).',
              schema: { type: 'integer', minimum: 1, maximum: 500, default: 100 },
            },
          ],
          responses: {
            '200': {
              description: 'Per-host telemetry records.',
              content: jsonContent(schemaRef('HostsHealthResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/hosts/gaps': {
        get: {
          tags: ['System'],
          operationId: 'listHostAdapterGaps',
          summary: 'Rank origin hosts by headless browser fallback time and non-OK fetch rate',
          description:
            'Queries `META` D1 `fetches` telemetry (`auto-render-1` / `ext-auto-*` browser renders and non-OK outcomes) over the requested window and cross-references each host against `listRegisteredAdapters()` to prioritize declarative YAML adapter authoring.',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'days',
              in: 'query',
              required: false,
              description: 'Lookback window in days (`1..90`, default `7`).',
              schema: { type: 'integer', minimum: 1, maximum: 90, default: 7 },
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              description: 'Maximum ranked hosts to return (`1..100`, default `25`).',
              schema: { type: 'integer', minimum: 1, maximum: 100, default: 25 },
            },
            {
              name: 'unadapted',
              in: 'query',
              required: false,
              description: 'When `true`, omit hosts already covered by a registered adapter.',
              schema: { type: 'boolean', default: false },
            },
          ],
          responses: {
            '200': {
              description: 'Ranked host gap telemetry and scaffold commands.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/artifacts/{blobSha256}': {
        get: {
          tags: ['System'],
          operationId: 'getArtifact',
          summary: 'Read or page a stored artifact from R2',
          description:
            'Streams or pages a content-addressed R2 artifact (`64`-char hex `blobSha256` or `md:<sha256>` derived Markdown) using character `offset` and `limit`.',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'blobSha256',
              in: 'path',
              required: true,
              description: '64-character lowercase hex SHA-256 (`blobSha256`) or `md:<sha256>` derived Markdown ID.',
              schema: { type: 'string' },
            },
            {
              name: 'format',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['raw', 'markdown'] },
            },
            {
              name: 'retention',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['transient', 'stored'] },
            },
            {
              name: 'visibility',
              in: 'query',
              required: false,
              description: 'Set to `private` to read strictly from the authenticated user’s `private/<userId>/...` R2 namespace.',
              schema: { type: 'string', enum: ['public', 'private'] },
            },
            {
              name: 'offset',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 0, default: 0 },
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 1, maximum: 1048576, default: 65536 },
            },
          ],
          responses: {
            '200': {
              description: 'Artifact slice or raw stream.',
              content: {
                'application/json': { schema: schemaRef('ArtifactPageResponse') },
                'text/markdown': { schema: { type: 'string' } },
                'application/octet-stream': { schema: { type: 'string', format: 'binary' } },
              },
            },
            '404': {
              description: 'Artifact not found or expired.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/scrape': {
        post: {
          tags: ['Scraping & Extraction'],
          operationId: 'scrapeUrl',
          summary: 'Scrape a public HTTPS URL to clean Markdown, JSON, or metadata',
          description:
            'Scrapes one public `https://` URL politely through connected worker nodes, automatically upgrading to keyless API adapters, companion `/llms.txt` `.md` docs, Poppler/Tesseract PDF extraction, `.ipynb` / OpenAPI converters, or Headless Chromium rendering when needed.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('ScrapeRequest')),
          },
          responses: {
            '200': {
              description: 'Scrape result with Markdown, metadata, links, and provenance.',
              content: jsonContent(schemaRef('ScrapeResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/batch/scrape': {
        post: {
          tags: ['Scraping & Extraction'],
          operationId: 'createBatchScrape',
          summary: 'Start or execute a multi-URL batch scrape job',
          description: 'Scrapes 1..100 public `https://` URLs with per-host pacing, returning either an async batch ID or inline `data` when `sync: true`.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('BatchScrapeRequest')),
          },
          responses: {
            '200': {
              description: 'Completed synchronous batch scrape.',
              content: jsonContent(schemaRef('BatchScrapeStatusResponse')),
            },
            '202': {
              description: 'Accepted asynchronous batch scrape job.',
              content: jsonContent(schemaRef('BatchScrapeStatusResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/batch/scrape/{batchId}': {
        get: {
          tags: ['Scraping & Extraction'],
          operationId: 'getBatchScrape',
          summary: 'Get batch scrape job status and results',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'batchId',
              in: 'path',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Batch scrape job status and collected documents.',
              content: jsonContent(schemaRef('BatchScrapeStatusResponse')),
            },
            '404': {
              description: 'Batch job not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
        delete: {
          tags: ['Scraping & Extraction'],
          operationId: 'cancelBatchScrape',
          summary: 'Cancel a running batch scrape job',
          security: authFetchSecurity(),
          parameters: [
            {
              name: 'batchId',
              in: 'path',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Batch scrape cancelled.',
              content: jsonContent(schemaRef('CancelJobResponse')),
            },
            '404': {
              description: 'Batch job not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/extract': {
        post: {
          tags: ['Scraping & Extraction'],
          operationId: 'extractUrls',
          summary: 'Extract BM25-ranked passages across 1..20 URLs',
          description:
            'Fetches up to 20 public `https://` URLs politely, converts each to verified Markdown, and returns the top BM25 query-ranked chunks per source.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('ExtractRequest')),
          },
          responses: {
            '200': {
              description: 'Ranked passages and extraction metadata per URL.',
              content: jsonContent(schemaRef('ExtractResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/interact': {
        post: {
          tags: ['Browser Automation'],
          operationId: 'interactBrowser',
          summary: 'Drive a sandboxed Headless Chromium session',
          description:
            'Executes browser actions (`click`, `fill`, `type`, `press`, `wait`, `scroll`, `select`, `navigate`) inside an incognito Chromium context on a `browser-v1` worker node with dial-time SSRF isolation and automatic halt on anti-bot challenges.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('InteractRequest')),
          },
          responses: {
            '200': {
              description: 'Browser session output (Markdown, HTML, screenshot, or transcript) and optional `sessionId`.',
              content: jsonContent(schemaRef('InteractResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/map': {
        post: {
          tags: ['Crawl & Map'],
          operationId: 'mapSiteUrls',
          summary: 'Discover URLs on a domain via sitemaps, /llms.txt, and links',
          description:
            'Rapidly maps a site’s URLs using `robots.txt` `Sitemap:` directives, `sitemap.xml` / `.xml.gz`, `/llms.txt`, and homepage links with optional keyword ranking.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('MapRequest')),
          },
          responses: {
            '200': {
              description: 'Discovered URL list.',
              content: jsonContent(schemaRef('MapResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/crawl/params-preview': {
        post: {
          tags: ['Crawl & Map'],
          operationId: 'previewCrawlParams',
          summary: 'Synthesize crawl path filters and depth from natural language',
          description: 'Deterministically converts a natural-language crawl instruction (`prompt`) and root `url` into `includePaths`, `excludePaths`, `maxDepth`, and `limit`.',
          security: authReadSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('CrawlParamsPreviewRequest')),
          },
          responses: {
            '200': {
              description: 'Suggested crawl parameters.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/crawl': {
        post: {
          tags: ['Crawl & Map'],
          operationId: 'createCrawl',
          summary: 'Start a polite breadth-first site crawl',
          description:
            'Starts an asynchronous (or `sync: true`) multi-page crawl enforcing `robots.txt`, path filters, per-host pacing, optional D1 FTS5 indexing (`collectionId`), and HMAC-SHA256 webhook delivery.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('CrawlRequest')),
          },
          responses: {
            '200': {
              description: 'Completed synchronous crawl job.',
              content: jsonContent(schemaRef('CrawlCreateResponse')),
            },
            '202': {
              description: 'Queued asynchronous crawl job.',
              content: jsonContent(schemaRef('CrawlCreateResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/crawl/{crawlId}': {
        get: {
          tags: ['Crawl & Map'],
          operationId: 'getCrawl',
          summary: 'Poll crawl job progress and paged results',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'crawlId',
              in: 'path',
              required: true,
              description: 'Crawl job identifier (`crw_...`).',
              schema: { type: 'string' },
            },
            {
              name: 'offset',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 0, default: 0 },
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 1, maximum: 200, default: 25 },
            },
          ],
          responses: {
            '200': {
              description: 'Crawl status and crawled pages.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            '404': {
              description: 'Crawl job not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
        delete: {
          tags: ['Crawl & Map'],
          operationId: 'cancelCrawl',
          summary: 'Cancel an active crawl job',
          security: authFetchSecurity(),
          parameters: [
            {
              name: 'crawlId',
              in: 'path',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Crawl cancelled.',
              content: jsonContent(schemaRef('CancelJobResponse')),
            },
            '404': {
              description: 'Crawl job not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/search': {
        post: {
          tags: ['Search & Collections'],
          operationId: 'searchWeb',
          summary: 'Search the web and private D1 FTS5 collections',
          description:
            'Runs EdgeFetch’s edge-first search waterfall across private `SEARCH` D1 FTS5 collections, `$0` `site:` edge-map discovery, 24h SERP cache, and configured Serper / SearXNG / Tavily / Brave providers, with optional live page chunking.',
          security: authReadSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('SearchRequest')),
          },
          responses: {
            '200': {
              description: 'Ranked web and collection search results.',
              content: jsonContent(schemaRef('SearchResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/collections/{collectionId}/search': {
        get: {
          tags: ['Search & Collections'],
          operationId: 'searchCollectionGet',
          summary: 'Query an indexed D1 FTS5 collection via GET',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'collectionId',
              in: 'path',
              required: true,
              description: 'Collection identifier (e.g. `default` or `crw_...`).',
              schema: { type: 'string' },
            },
            {
              name: 'q',
              in: 'query',
              required: false,
              description: 'Keyword search query (`query` is also accepted).',
              schema: { type: 'string' },
            },
            {
              name: 'query',
              in: 'query',
              required: false,
              description: 'Alias for `q`.',
              schema: { type: 'string' },
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 1, maximum: 50, default: 10 },
            },
          ],
          responses: {
            '200': {
              description: 'BM25-ranked FTS5 hits.',
              content: jsonContent(schemaRef('CollectionSearchResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
        post: {
          tags: ['Search & Collections'],
          operationId: 'searchCollectionPost',
          summary: 'Query an indexed D1 FTS5 collection via POST',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'collectionId',
              in: 'path',
              required: true,
              description: 'Collection identifier (e.g. `default` or `crw_...`).',
              schema: { type: 'string' },
            },
          ],
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('CollectionSearchRequest')),
          },
          responses: {
            '200': {
              description: 'BM25-ranked FTS5 hits.',
              content: jsonContent(schemaRef('CollectionSearchResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/ingest-tab': {
        post: {
          tags: ['Scraping & Extraction'],
          operationId: 'ingestBrowserTab',
          summary: 'Clip and index an authenticated user browser tab into D1 FTS5',
          description:
            'Accepts HTML or Markdown captured directly by a user-initiated browser extension clip (up to 4 MiB), converts main content to clean Markdown, and indexes chunks into `collectionId`.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('IngestTabRequest')),
          },
          responses: {
            '200': {
              description: 'Cleaned Markdown and indexed chunk count.',
              content: jsonContent(schemaRef('IngestTabResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/jobs': {
        post: {
          tags: ['Vertical Intelligence'],
          operationId: 'searchOrVerifyJobs',
          summary: 'Search or batch-verify structured ATS job postings',
          description:
            'Searches official ATS boards (Greenhouse, Ashby, Lever, Workday CXS, Workable, Gem, Rippling, SmartRecruiters, company domain auto-discovery, and Built In) with normalized compensation (`base` vs `ote`), OR batch-verifies saved job URLs (`mode: "verify"`).',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('JobsRequest')),
          },
          responses: {
            '200': {
              description: 'Normalized job postings or batch verification statuses.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/catalog': {
        post: {
          tags: ['Vertical Intelligence'],
          operationId: 'extractOrDiffCatalog',
          summary: 'Extract and diff a Shopify or WooCommerce storefront catalog',
          description:
            'Politely extracts full product and variant inventory from Shopify (`/products.json`) or WooCommerce Store API sequentially with `robots.txt` + `Content-Signal` enforcement, shrink guards, and variant-level price/stock diffs.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('CatalogRequest')),
          },
          responses: {
            '200': {
              description: 'Catalog snapshot, diff summary, and paged product records.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            '202': {
              description: 'Queued asynchronous catalog extraction (`sync: false`).',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/catalog/{catalogId}': {
        get: {
          tags: ['Vertical Intelligence'],
          operationId: 'getCatalogStatus',
          summary: 'Get catalog extraction status and snapshot diff summary',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'catalogId',
              in: 'path',
              required: true,
              description: 'Catalog run ID (`cat_...`).',
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Catalog run metadata and snapshot diff summary.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            '404': {
              description: 'Catalog run not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/catalog/{catalogId}/records': {
        get: {
          tags: ['Vertical Intelligence'],
          operationId: 'getCatalogRecords',
          summary: 'Page and filter normalized products from a catalog run',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'catalogId',
              in: 'path',
              required: true,
              description: 'Catalog run ID (`cat_...`).',
              schema: { type: 'string' },
            },
            {
              name: 'offset',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 0, default: 0 },
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              schema: { type: 'integer', minimum: 1, maximum: 250, default: 50 },
            },
            {
              name: 'vendor',
              in: 'query',
              required: false,
              description: 'Filter by vendor/brand (repeatable).',
              schema: { type: 'string' },
            },
            {
              name: 'productType',
              in: 'query',
              required: false,
              description: 'Filter by productType (repeatable).',
              schema: { type: 'string' },
            },
            {
              name: 'availableOnly',
              in: 'query',
              required: false,
              schema: { type: 'boolean' },
            },
            {
              name: 'query',
              in: 'query',
              required: false,
              description: 'Keyword filter across title, handle, vendor, tags, and SKUs.',
              schema: { type: 'string' },
            },
            {
              name: 'q',
              in: 'query',
              required: false,
              description: 'Short alias for `query` keyword filter.',
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Filtered catalog product records.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            '404': {
              description: 'Catalog run not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/agent': {
        post: {
          tags: ['Autonomous Agent'],
          operationId: 'runAgent',
          summary: 'Run autonomous multi-step web research and structured JSON extraction',
          description:
            'Executes a multi-step research loop with BYO-LLM (OpenAI, Anthropic, Gemini, OpenRouter, Workers AI, or local Ollama/vLLM), routing across all 49+ keyless site adapters with optional JSON Schema validation, SSE streaming (`Accept: text/event-stream`), and Zero Data Retention.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('AgentRequest')),
          },
          responses: {
            '200': {
              description: 'Completed agent research output (or `text/event-stream` when requested).',
              content: {
                'application/json': { schema: schemaRef('GenericOkResponse') },
                'text/event-stream': { schema: { type: 'string' } },
              },
            },
            '202': {
              description: 'Accepted asynchronous agent run (`agt_...`).',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/agent/{agentId}': {
        get: {
          tags: ['Autonomous Agent'],
          operationId: 'getAgentRun',
          summary: 'Get autonomous agent run status and output',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'agentId',
              in: 'path',
              required: true,
              description: 'Agent run ID (`agt_...`).',
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Agent run status, citations, and structured output.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            '404': {
              description: 'Agent run not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
        delete: {
          tags: ['Autonomous Agent'],
          operationId: 'cancelAgentRun',
          summary: 'Cancel a running autonomous agent task',
          security: authFetchSecurity(),
          parameters: [
            {
              name: 'agentId',
              in: 'path',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Agent run cancelled.',
              content: jsonContent(schemaRef('CancelJobResponse')),
            },
            '404': {
              description: 'Agent run not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/agent/{agentId}/trace': {
        get: {
          tags: ['Autonomous Agent'],
          operationId: 'getAgentTrace',
          summary: 'Get step-by-step execution trace spans for an agent run',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'agentId',
              in: 'path',
              required: true,
              description: 'Agent run ID (`agt_...`).',
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Ordered execution trace spans.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            '404': {
              description: 'Agent run not found.',
              content: jsonContent(schemaRef('ErrorResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/mcp/registry': {
        get: {
          tags: ['Coordinator & MCP'],
          operationId: 'discoverMcpRegistry',
          summary: 'Search Official MCP Registry and Glama MCP Directory',
          description:
            'Queries both `registry.modelcontextprotocol.io` and `glama.ai` via `SAFE_PUBLIC_FETCH`, fusing server manifests, remote Streamable HTTP/SSE endpoints, required auth headers, and associated web domains.',
          security: authReadSecurity(),
          parameters: [
            {
              name: 'q',
              in: 'query',
              required: false,
              description: 'Search keyword, service name, or domain.',
              schema: { type: 'string' },
            },
            {
              name: 'query',
              in: 'query',
              required: false,
              description: 'Alias for `q`.',
              schema: { type: 'string' },
            },
            {
              name: 'remoteOnly',
              in: 'query',
              required: false,
              description: 'When `true`, return only servers advertising remote `streamable-http` or `sse` endpoints.',
              schema: { type: 'boolean', default: false },
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              description: 'Maximum registry entries to return (`1..50`, default `20`).',
              schema: { type: 'integer', minimum: 1, maximum: 50, default: 20 },
            },
          ],
          responses: {
            '200': {
              description: 'Normalized dual-source MCP registry search results.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v1/mcp/query': {
        post: {
          tags: ['Coordinator & MCP'],
          operationId: 'queryConnectedMcp',
          summary: 'List or invoke tools on a user-connected federated MCP server',
          description:
            'Executes `list_connected`, `list_tools`, or `call_tool` over Streamable HTTP / SSE against a user-isolated `AES-256-GCM` vault connector, auto-refreshing OAuth 2.1 tokens and scrubbing indirect prompt injections (`visibility: "private"`). Requires OAuth scope `mcp:call` (or `CALLER_TOKEN` / `MCP_TOKEN`) when `action` is `"call_tool"`.',
          security: authMcpQuerySecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('McpTool_QueryMcpInput')),
          },
          responses: {
            '200': {
              description: 'Sanitized private federated MCP result.',
              content: jsonContent(schemaRef('GenericOkResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/agents': {
        get: {
          tags: ['System'],
          operationId: 'listAgents',
          summary: 'List connected outbound worker nodes',
          description:
            'Lists connected Go worker nodes (`siteId`, CPU architecture, version, `LITE` vs `FAT` browser/PDF capabilities, and job counters). Requires `CALLER_TOKEN`.',
          security: [{ bearerAuth: [] }],
          responses: {
            '200': {
              description: 'Connected worker fleet summary.',
              content: jsonContent(schemaRef('AgentsListResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/fetch': {
        post: {
          tags: ['Coordinator & MCP'],
          operationId: 'dispatchFetch',
          summary: 'Dispatch a coordinated low-level fetch batch',
          description:
            'Dispatches 1..N structured fetch requests across connected remote Go worker nodes with LRU load balancing, host-affinity pinning, `429` cooldown failover, `robots.txt` validation, and optional R2 artifact hydration. Requires `CALLER_TOKEN`.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: 'target',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['auto', 'agent', 'container'], default: 'auto' },
            },
            {
              name: 'site',
              in: 'query',
              required: false,
              description: 'Optional worker `siteId` pin when `target=agent`.',
              schema: { type: 'string' },
            },
            {
              name: 'artifacts',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['transient', 'stored', 'off'] },
            },
            {
              name: 'hydrate',
              in: 'query',
              required: false,
              description: 'Hydrate R2 artifact bodies inline (default `true`).',
              schema: { type: 'boolean', default: true },
            },
          ],
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('CoordinatorFetchCall')),
          },
          responses: {
            '200': {
              description: 'Coordinator batch fetch reply with per-URL status, timing, and classification outcome.',
              content: jsonContent(schemaRef('CoordinatorFetchReply')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/mcp': {
        post: {
          tags: ['Coordinator & MCP'],
          operationId: 'handleMcpJsonRpc',
          summary: 'Streamable HTTP Model Context Protocol (MCP) JSON-RPC endpoint',
          description:
            'Stateless Streamable HTTP MCP endpoint supporting protocol versions `2026-07-28` through `2024-11-05` (`initialize`, `tools/list`, `tools/call`, `server/discover`, `ping`) across all 17 canonical EdgeFetch tools.',
          security: [{ bearerAuth: [] }, { oauth2Pkce: ['crawl:read', 'crawl:fetch', 'mcp:call'] }],
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('McpJsonRpcRequest')),
          },
          responses: {
            '200': {
              description: 'JSON-RPC 2.0 response envelope.',
              content: jsonContent(schemaRef('McpJsonRpcResponse')),
            },
            '202': {
              description: 'Accepted JSON-RPC notification.',
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v2/scrape': {
        post: {
          tags: ['Compatibility'],
          operationId: 'compatV2Scrape',
          summary: 'Firecrawl v2 compatible single-URL scrape',
          description: 'Drop-in Firecrawl v2 `POST /v2/scrape` compatibility endpoint returning `{ "success": true, "data": ... }`.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('ScrapeRequest')),
          },
          responses: {
            '200': {
              description: 'Firecrawl v2 compatible scrape envelope.',
              content: jsonContent(schemaRef('CompatSuccessResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v2/crawl': {
        post: {
          tags: ['Compatibility'],
          operationId: 'compatV2Crawl',
          summary: 'Firecrawl v2 compatible site crawl',
          description: 'Drop-in Firecrawl v2 `POST /v2/crawl` compatibility endpoint.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('CrawlRequest')),
          },
          responses: {
            '200': {
              description: 'Firecrawl v2 compatible crawl job creation envelope.',
              content: jsonContent(schemaRef('CompatSuccessResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v2/map': {
        post: {
          tags: ['Compatibility'],
          operationId: 'compatV2Map',
          summary: 'Firecrawl v2 compatible site URL map',
          description: 'Drop-in Firecrawl v2 `POST /v2/map` compatibility endpoint.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('MapRequest')),
          },
          responses: {
            '200': {
              description: 'Firecrawl v2 compatible map envelope.',
              content: jsonContent(schemaRef('CompatSuccessResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v2/search': {
        post: {
          tags: ['Compatibility'],
          operationId: 'compatV2Search',
          summary: 'Firecrawl v2 compatible web search',
          description: 'Drop-in Firecrawl v2 `POST /v2/search` compatibility endpoint.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('SearchRequest')),
          },
          responses: {
            '200': {
              description: 'Firecrawl v2 compatible search envelope.',
              content: jsonContent(schemaRef('CompatSuccessResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v2/extract': {
        post: {
          tags: ['Compatibility'],
          operationId: 'compatV2Extract',
          summary: 'Firecrawl v2 compatible multi-URL passage extraction',
          description: 'Drop-in Firecrawl v2 `POST /v2/extract` compatibility endpoint.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('ExtractRequest')),
          },
          responses: {
            '200': {
              description: 'Firecrawl v2 compatible extract envelope.',
              content: jsonContent(schemaRef('CompatSuccessResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
      '/v2/agent': {
        post: {
          tags: ['Compatibility'],
          operationId: 'compatV2Agent',
          summary: 'Firecrawl v2 compatible autonomous research agent',
          description: 'Drop-in Firecrawl v2 `POST /v2/agent` compatibility endpoint.',
          security: authFetchSecurity(),
          requestBody: {
            required: true,
            content: jsonContent(schemaRef('AgentRequest')),
          },
          responses: {
            '200': {
              description: 'Firecrawl v2 compatible agent response.',
              content: jsonContent(schemaRef('CompatSuccessResponse')),
            },
            '202': {
              description: 'Accepted asynchronous Firecrawl v2 agent job.',
              content: jsonContent(schemaRef('CompatSuccessResponse')),
            },
            ...standardAuthErrorResponses(),
          },
        },
      },
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          description:
            'Authenticate with `Authorization: Bearer <token>` using your Hub `CALLER_TOKEN`, scoped `MCP_TOKEN`, or an OAuth 2.1 access token (`X-API-Key` is also accepted).',
        },
        oauth2Pkce: {
          type: 'oauth2',
          description:
            'Self-hosted OAuth 2.1 Authorization Code flow with mandatory `S256` PKCE (`code_challenge_method=S256`) and RFC 7591 Dynamic Client Registration (`POST /oauth/register`).',
          flows: {
            authorizationCode: {
              authorizationUrl: `${safeOrigin}/oauth/authorize`,
              tokenUrl: `${safeOrigin}/oauth/token`,
              refreshUrl: `${safeOrigin}/oauth/token`,
              scopes: {
                'crawl:read':
                  'Read capabilities, keyless site adapters, host health, connected worker status, stored R2 artifacts, and search indexes.',
                'crawl:fetch':
                  'Execute polite outbound scrapes, crawls, URL maps, browser interactions, job/catalog extractions, and autonomous agent runs.',
                'mcp:call':
                  'Invoke tools (`action: "call_tool"`) on user-connected federated MCP servers via `POST /v1/mcp/query` or MCP `query_mcp`.',
              },
            },
          },
        },
      },
      schemas: {
        // Canonical zero-drift schemas shared directly with `hub/src/mcp.ts` (`MCP_TOOL_SCHEMAS`)
        ScrapeRequest: MCP_TOOL_SCHEMAS.scrape!,
        ExtractRequest: MCP_TOOL_SCHEMAS.extract!,
        InteractRequest: MCP_TOOL_SCHEMAS.interact!,
        MapRequest: MCP_TOOL_SCHEMAS.map!,
        SearchRequest: MCP_TOOL_SCHEMAS.search!,
        JobsRequest: MCP_TOOL_SCHEMAS.jobs!,
        CatalogRequest: MCP_TOOL_SCHEMAS.catalog!,
        BatchScrapeRequest: {
          type: 'object',
          properties: {
            urls: {
              type: 'array',
              items: { type: 'string' },
              minItems: 1,
              maxItems: 100,
              description: '1..100 public https:// URLs to scrape.',
            },
            ignoreInvalidURLs: {
              type: 'boolean',
              default: false,
              description: 'Skip invalid URLs instead of rejecting the batch with HTTP 400.',
            },
            sync: {
              type: 'boolean',
              default: false,
              description: 'Wait for completion and return scraped `data` inline.',
            },
            formats: scrapeProps.formats!,
            renderMode: scrapeProps.renderMode!,
            onlyMainContent: scrapeProps.onlyMainContent!,
            maxAgeMs: scrapeProps.maxAgeMs!,
            redactPii: scrapeProps.redactPii!,
            target: scrapeProps.target!,
            site: scrapeProps.site!,
          },
          required: ['urls'],
          additionalProperties: true,
        },
        CrawlParamsPreviewRequest: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'Root public https:// URL to crawl.' },
            prompt: {
              type: 'string',
              description: 'Natural-language crawl goal (e.g. "only /docs and /api, skip /blog, max 50 pages depth 2").',
            },
          },
          required: ['url'],
          additionalProperties: false,
        },
        CrawlRequest: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'Root public https:// URL to start crawling.' },
            limit: crawlProps.limit!,
            maxDepth: crawlProps.maxDepth!,
            allowSubdomains: crawlProps.allowSubdomains!,
            includePaths: crawlProps.includePaths!,
            excludePaths: crawlProps.excludePaths!,
            collectionId: crawlProps.collectionId!,
            sync: {
              type: 'boolean',
              default: false,
              description: 'Wait for crawl completion before returning HTTP 200.',
            },
            webhook: {
              type: 'object',
              description: 'Optional HTTPS webhook signed with `WEBHOOK_SECRET` (HMAC-SHA256).',
              properties: {
                url: { type: 'string', description: 'Public https:// webhook receiver URL.' },
                events: {
                  type: 'array',
                  items: { type: 'string', enum: ['started', 'page', 'completed', 'failed'] },
                },
                headers: {
                  type: 'object',
                  additionalProperties: { type: 'string' },
                },
              },
              required: ['url'],
            },
          },
          required: ['url'],
          additionalProperties: true,
        },
        CollectionSearchRequest: {
          type: 'object',
          properties: {
            query: collectionSearchProps.query!,
            q: { type: 'string', description: 'Alias for `query`.' },
            limit: collectionSearchProps.limit!,
          },
          additionalProperties: false,
        },
        IngestTabRequest: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'Source http(s) URL of the clipped browser tab.' },
            title: { type: 'string', description: 'Optional page title override.' },
            html: { type: 'string', description: 'Captured DOM HTML (up to 4 MiB).' },
            markdown: { type: 'string', description: 'Pre-extracted Markdown when HTML is omitted.' },
            collectionId: { type: 'string', default: 'default', description: 'Target SEARCH D1 FTS5 collection ID.' },
            visibility: {
              type: 'string',
              enum: ['public', 'private'],
              description: 'Artifact & FTS5 collection isolation (`private` namespaces R2 & FTS5 under the authenticated `userId`).',
            },
            onlyMainContent: { type: 'boolean', default: true },
          },
          required: ['url'],
          additionalProperties: false,
        },
        AgentRequest: {
          type: 'object',
          properties: {
            prompt: agentProps.prompt!,
            urls: agentProps.urls!,
            strictConstrainToURLs: agentProps.strictConstrainToURLs!,
            schema: agentProps.schema!,
            effort: agentProps.effort!,
            maxSteps: agentProps.maxSteps!,
            maxPages: agentProps.maxPages!,
            threadId: agentProps.threadId!,
            zeroDataRetention: agentProps.zeroDataRetention!,
            safe: agentProps.safe!,
            location: agentProps.location!,
            llm: agentProps.llm!,
            async: { type: 'boolean', description: 'Run asynchronously and return `202` with `id` (`agt_...`).' },
            stream: { type: 'boolean', description: 'Stream real-time Server-Sent Events (`text/event-stream`).' },
          },
          required: ['prompt'],
          additionalProperties: true,
        },
        CoordinatorFetchCall: {
          type: 'object',
          properties: {
            maxSeconds: { type: 'integer', minimum: 1, maximum: 120, default: 30 },
            options: {
              type: 'object',
              properties: {
                concurrency: { type: 'integer', minimum: 1, maximum: 8 },
                pauseMs: { type: 'integer', minimum: 0, maximum: 30000 },
                pauseJitterMs: { type: 'integer', minimum: 0, maximum: 15000 },
                respectRobots: { type: 'boolean', default: true },
                includeBody: { type: 'boolean', default: true },
                maxBytes: { type: 'integer', minimum: 256, maximum: 16777216 },
                artifactRetention: { type: 'string', enum: ['transient', 'stored', 'off'] },
                collectionId: { type: 'string' },
              },
            },
            requests: {
              type: 'array',
              minItems: 1,
              items: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  url: { type: 'string' },
                  kind: {
                    type: 'string',
                    enum: ['page', 'text', 'json', 'feed', 'catalog', 'scrape', 'render', 'pdf', 'binary'],
                  },
                  accept: { type: 'string', enum: [...TEXT_ACCEPTS] },
                  ifNoneMatch: { type: 'string' },
                  ifModifiedSince: { type: 'string' },
                },
                required: ['id', 'url'],
              },
            },
          },
          required: ['requests'],
        },
        CoordinatorFetchReply: {
          type: 'object',
          properties: {
            summary: { type: 'object' },
            results: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  url: { type: 'string' },
                  finalUrl: { type: 'string' },
                  status: { type: 'integer' },
                  outcome: { type: 'string' },
                  problem: { type: 'string' },
                  contentType: { type: 'string' },
                  body: { type: 'string' },
                  timing: { type: 'object' },
                  artifact: { type: 'object' },
                },
              },
            },
          },
        },
        McpJsonRpcRequest: {
          type: 'object',
          properties: {
            jsonrpc: { type: 'string', const: '2.0' },
            id: { type: ['string', 'integer', 'null'] },
            method: {
              type: 'string',
              description: 'MCP method (`initialize`, `tools/list`, `tools/call`, `server/discover`, `ping`).',
            },
            params: {
              type: 'object',
              description: 'Method parameters (for `tools/call`, `{ name, arguments }` matching one of the `McpTool_*Input` schemas).',
            },
          },
          required: ['jsonrpc', 'method'],
        },
        McpJsonRpcResponse: {
          type: 'object',
          properties: {
            jsonrpc: { type: 'string', const: '2.0' },
            id: { type: ['string', 'integer', 'null'] },
            result: { type: 'object' },
            error: {
              type: 'object',
              properties: {
                code: { type: 'integer' },
                message: { type: 'string' },
                data: {},
              },
            },
          },
          required: ['jsonrpc'],
        },
        HealthResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean', const: true },
          },
          required: ['ok'],
        },
        BotManifestResponse: {
          type: 'object',
          properties: {
            bot: { type: 'string' },
            version: { type: 'string' },
            category: { type: 'string' },
            userAgent: { type: 'string' },
            operatorContact: { type: 'string' },
            policies: { type: 'object' },
            webBotAuth: { type: 'object' },
          },
        },
        BotKeyDirectoryResponse: {
          type: 'object',
          properties: {
            keys: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  kty: { type: 'string', const: 'OKP' },
                  crv: { type: 'string', const: 'Ed25519' },
                  kid: { type: 'string' },
                  x: { type: 'string' },
                  nbf: { type: 'integer' },
                  exp: { type: 'integer' },
                },
                required: ['kty', 'crv', 'kid', 'x', 'nbf'],
              },
            },
          },
          required: ['keys'],
        },
        OAuthProtectedResourceMetadata: {
          type: 'object',
          properties: {
            resource: { type: 'string' },
            authorization_servers: { type: 'array', items: { type: 'string' } },
            bearer_methods_supported: { type: 'array', items: { type: 'string' } },
            scopes_supported: { type: 'array', items: { type: 'string' } },
            resource_name: { type: 'string' },
          },
        },
        OAuthAuthorizationServerMetadata: {
          type: 'object',
          properties: {
            issuer: { type: 'string' },
            authorization_endpoint: { type: 'string' },
            token_endpoint: { type: 'string' },
            registration_endpoint: { type: 'string' },
            revocation_endpoint: { type: 'string' },
            response_types_supported: { type: 'array', items: { type: 'string' } },
            grant_types_supported: { type: 'array', items: { type: 'string' } },
            code_challenge_methods_supported: { type: 'array', items: { type: 'string' } },
            scopes_supported: { type: 'array', items: { type: 'string' } },
          },
        },
        CapabilitiesResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            version: { type: 'string' },
            storage: { type: 'object' },
            search: { type: 'object' },
          },
        },
        ExtractorsResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            total: { type: 'integer' },
            categories: { type: 'object', additionalProperties: { type: 'integer' } },
            extractors: { type: 'array', items: { type: 'object' } },
          },
        },
        HostsHealthResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            hosts: { type: 'array', items: { type: 'object' } },
          },
        },
        ArtifactPageResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            blobSha256: { type: 'string' },
            content: { type: 'string' },
            offset: { type: 'integer' },
            nextOffset: { type: ['integer', 'null'] },
            hasMore: { type: 'boolean' },
            totalChars: { type: 'integer' },
          },
        },
        ScrapeResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            cached: { type: 'boolean' },
            url: { type: 'string' },
            finalUrl: { type: 'string' },
            status: { type: 'integer' },
            via: { type: 'string' },
            rendered: { type: 'boolean' },
            title: { type: 'string' },
            description: { type: 'string' },
            wordCount: { type: 'integer' },
            favicon: { type: 'string' },
            contentType: { type: 'string' },
            markdown: { type: 'string' },
            json: { type: 'object' },
            jsonExtractionMode: { type: 'string', enum: ['heuristic', 'llm'] },
            warnings: { type: 'array', items: { type: 'string' } },
            links: { type: 'array', items: { type: 'string' } },
            metadata: { type: 'object' },
            blocked: { type: ['object', 'null'] },
          },
        },
        BatchScrapeStatusResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            id: { type: 'string' },
            status: { type: 'string' },
            total: { type: 'integer' },
            completed: { type: 'integer' },
            url: { type: 'string' },
            data: { type: 'array', items: { type: 'object' } },
          },
        },
        ExtractResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            results: { type: 'array', items: { type: 'object' } },
            failedResults: { type: 'array', items: { type: 'object' } },
          },
        },
        InteractResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            sessionId: { type: 'string' },
            url: { type: 'string' },
            finalUrl: { type: 'string' },
            rendered: { type: 'boolean' },
            actions: { type: 'array', items: { type: 'object' } },
            warnings: { type: 'array', items: { type: 'string' } },
            markdown: { type: 'string' },
            truncated: { type: 'boolean' },
            offset: { type: 'integer' },
            totalChars: { type: 'integer' },
            remainingChars: { type: 'integer' },
            nextOffset: { type: ['integer', 'null'] },
            screenshotBase64: { type: 'string' },
            screenshotArtifactId: { type: 'string' },
            screenshotMimeType: { type: 'string' },
            screenshotBytes: { type: 'integer' },
            metadata: { type: 'object' },
          },
        },
        MapResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            url: { type: 'string' },
            total: { type: 'integer' },
            links: { type: 'array', items: { type: 'string' } },
          },
        },
        CrawlCreateResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            id: { type: 'string' },
            status: { type: 'string' },
            collectionId: { type: 'string' },
            url: { type: 'string' },
          },
        },
        SearchResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            query: { type: 'string' },
            results: { type: 'array', items: { type: 'object' } },
          },
        },
        CollectionSearchResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            collectionId: { type: 'string' },
            query: { type: 'string' },
            hits: { type: 'array', items: { type: 'object' } },
          },
        },
        IngestTabResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            url: { type: 'string' },
            collectionId: { type: 'string' },
            indexedChunks: { type: 'integer' },
            contentSha256: { type: 'string' },
            markdown: { type: 'string' },
          },
        },
        AgentsListResponse: {
          type: 'object',
          properties: {
            connected: { type: 'integer' },
            distinctPublicIps: { type: 'integer' },
            trackerListVersion: { type: ['string', 'null'] },
            agents: { type: 'array', items: { type: 'object' } },
          },
        },
        CancelJobResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            id: { type: 'string' },
            status: { type: 'string', const: 'cancelled' },
          },
        },
        CompatSuccessResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {},
          },
          required: ['success'],
        },
        GenericOkResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
          },
          additionalProperties: true,
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            error: { type: 'string' },
            message: { type: 'string' },
          },
          required: ['error'],
        },
        ...mcpToolSchemaEntries,
      },
    },
  };
}

/**
 * Handles `GET /openapi.json`, `HEAD /openapi.json`, and `OPTIONS /openapi.json` with permissive CORS and
 * `X-Content-Type-Options: nosniff` so browser API explorers and LLM tool importers can load the spec cross-origin.
 */
export function handleOpenApiRoute(
  request: Request,
  url: URL,
  version = DEFAULT_OPENAPI_VERSION,
): Response | null {
  if (url.pathname !== '/openapi.json') {
    return null;
  }

  const corsHeaders: Record<string, string> = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, HEAD, OPTIONS',
    'access-control-allow-headers': 'Accept, Authorization, Content-Type',
    'x-content-type-options': 'nosniff',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        ...corsHeaders,
        'cache-control': 'public, max-age=86400',
      },
    });
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return Response.json(
      { error: 'method_not_allowed' },
      {
        status: 405,
        headers: {
          ...corsHeaders,
          allow: 'GET, HEAD, OPTIONS',
          'cache-control': 'no-store',
        },
      },
    );
  }

  const spec = buildOpenApiSpec({ origin: url.origin, version });
  const body = `${JSON.stringify(spec, null, 2)}\n`;
  const contentType = resolveOpenApiContentType(request.headers.get('accept'));

  return new Response(request.method === 'HEAD' ? null : body, {
    status: 200,
    headers: {
      ...corsHeaders,
      'content-type': contentType,
      'cache-control': 'public, max-age=300',
      vary: 'Accept',
    },
  });
}
