/**
 * Stateless Streamable HTTP Model Context Protocol (MCP) server (`POST /mcp`, `GET /mcp`, `DELETE /mcp`, `OPTIONS /mcp`).
 *
 * - Dual-era MCP server speaking both modern `2026-07-28` (`server/discover`, per-request `_meta`, `Mcp-Method`/`Mcp-Name`
 *   validation, `resultType`, `CacheableResult`) and legacy `2025-11-25` / `2025-06-18` / `2025-03-26` / `2024-11-05`
 *   with zero external runtime dependencies.
 * - Authenticates via self-hosted OAuth 2.1 (`authorizeMcpRequest`, returning RFC 9728 `401 + WWW-Authenticate` and
 *   RFC 6750 `403 insufficient_scope` step-up challenges) OR direct `Bearer` / `x-api-key` token.
 * - Enforces `Origin` validation against DNS-rebinding / cross-origin attacks and per-tool OAuth scopes
 *   (`crawl:read` vs `crawl:fetch`).
 */
import { redactUrlForLog, sanitizeDetails, type ActivityStore, type HubEventInput } from './activity-log';
import type { AffinityPin, AgentAttachment, FetchTarget } from './agent-hub';
import { SITE_ID_PATTERN } from './auth';
import { analyzeUrlRedirect, buildBlockedInfo } from './jobs';
import { authorizeMcpRequest, isTrustedMcpBrowserOrigin, type OAuthStore } from './oauth';
import { validatePublicHttpsTargetUrl } from './overflow';
import { classifyWafAndChallenge } from './waf';

const SUPPORTED_PROTOCOL_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'] as const;
const LEGACY_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'] as const;
const DEFAULT_PROTOCOL_VERSION = '2025-03-26';
const MCP_INSTRUCTIONS =
  'Use search for web & crawled-collection discovery (Serper/Tavily/Brave/SearXNG waterfall + edge-map + SEARCH D1), jobs for one-call structured ATS job search across Greenhouse/Ashby/Lever/Workday/SmartRecruiters/Built In, scrape / extract for clean Markdown, Jupyter .ipynb, OpenAPI, & PDFs (with optional PDF OCR and companion .md discovery), map / crawl for site discovery, interact for headless Chromium sessions & YouTube transcripts, read_artifact for large stored docs, and list_agents for fleet status.';
const MAX_MCP_REQUEST_BYTES = 256 * 1024;
const MAX_BODY_PREVIEW_CHARS = 64 * 1024;
const DEFAULT_MCP_SCRAPE_MAX_CHARS = 100_000;
const DEFAULT_BATCH_PREVIEW_CHARS = 3 * 1024;
const MAX_BATCH_URLS = 25;

/** The Accept values a `kind: "text"` request may carry: the set both Go crawlers (container and agents) accept. */
export const TEXT_ACCEPTS = [
  'text/html',
  'application/xml',
  'text/xml',
  'application/rss+xml',
  'application/atom+xml',
  'application/json',
  'text/calendar',
  'text/plain',
] as const;

/**
 * The Accept for a text request that named none, from the URL's file type. Both Go crawlers refuse a text request
 * without one (`bad_kind`), and the MCP tools used to send none.
 */
const RAW_TEXT_FILE_EXT_RE =
  /\.(txt|md|markdown|mdx|vcf|vcard|csv|tsv|yaml|yml|toml|patch|diff|py|rs|go|ts|tsx|js|jsx|mjs|cjs|rb|java|kt|swift|c|h|cpp|hpp|cs|php|sh|bash|zsh|ps1|sql|proto|graphql|gql|lua|zig|tf|hcl|nix|prisma|css|scss|ini|conf|env)$/;

export function defaultTextAccept(url: string): (typeof TEXT_ACCEPTS)[number] {
  let host = '';
  let pathname = '';
  try {
    const parsed = new URL(url);
    host = parsed.hostname.toLowerCase();
    pathname = parsed.pathname.toLowerCase();
  } catch {
    return 'text/html';
  }
  if (/\.(xml|xml\.gz)$/.test(pathname) || pathname.includes('sitemap')) return 'application/xml';
  if (/\.(rss)$/.test(pathname) || /\/(rss|feed)\/?$/.test(pathname)) return 'application/rss+xml';
  if (/\.(atom)$/.test(pathname) || /\/atom\/?$/.test(pathname)) return 'application/atom+xml';
  if (/\.(json|webmanifest|jsonl|ndjson|ipynb)$/.test(pathname)) return 'application/json';
  if (/\.ics$/.test(pathname)) return 'text/calendar';
  if (
    RAW_TEXT_FILE_EXT_RE.test(pathname) ||
    /\/(?:dockerfile|makefile)$/.test(pathname) ||
    host === 'raw.githubusercontent.com' ||
    host === 'gist.githubusercontent.com' ||
    pathname.includes('/-/raw/')
  ) {
    return 'text/plain';
  }
  return 'text/html';
}

/** Infers the best crawl `kind` (`page` | `text` | `json`) from a URL path/host when caller omits `kind`. */
export function inferKindForUrl(url: string): 'page' | 'text' | 'json' {
  let host = '';
  let pathname = '';
  try {
    const parsed = new URL(url);
    host = parsed.hostname.toLowerCase();
    pathname = parsed.pathname.toLowerCase();
  } catch {
    return 'page';
  }
  if (
    /\.(json|webmanifest|jsonl|ndjson|ipynb)$/.test(pathname) ||
    pathname.startsWith('/.well-known/') ||
    host === 'registry.npmjs.org' ||
    host === 'api.github.com' ||
    (host === 'pypi.org' && /\/json\/?$/.test(pathname))
  ) {
    return 'json';
  }
  if (
    /\.(xml|xml\.gz|rss|atom|ics)$/.test(pathname) ||
    RAW_TEXT_FILE_EXT_RE.test(pathname) ||
    /\/(?:dockerfile|makefile)$/.test(pathname) ||
    /\/(rss|feed|atom)\/?$/.test(pathname) ||
    pathname.includes('sitemap') ||
    host === 'raw.githubusercontent.com' ||
    host === 'gist.githubusercontent.com' ||
    pathname.includes('/-/raw/')
  ) {
    return 'text';
  }
  return 'page';
}

/** The Accept to send with one request, or an error for one the crawlers would refuse. */
export function textAcceptFor(kind: string, url: string, requested: unknown): { ok: true; accept?: string } | { ok: false; error: string } {
  if (kind !== 'text') return { ok: true };
  if (requested === undefined || requested === null || requested === '') return { ok: true, accept: defaultTextAccept(url) };
  if (typeof requested === 'string' && (TEXT_ACCEPTS as readonly string[]).includes(requested)) return { ok: true, accept: requested };
  return { ok: false, error: `accept must be one of ${TEXT_ACCEPTS.join(', ')}` };
}

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

export interface McpExecuteFetchResult {
  status: number;
  via: string;
  bodyText: string;
  stageTimingsMs?: Record<string, number>;
}

export interface McpServerDeps {
  serverName: string;
  serverVersion: string;
  ownerSecret?: string;
  mcpToken?: string;
  oauthStore: OAuthStore;
  activity?: ActivityStore;
  allowedTargets: FetchTarget[];
  defaultTarget: FetchTarget;
  listFleet: () => Promise<{
    connected: number;
    agents: AgentAttachment[];
    affinities: AffinityPin[];
  }>;
  executeFetch: (params: {
    target: FetchTarget;
    site?: string;
    body: string;
    principal?: string;
  }) => Promise<McpExecuteFetchResult>;
  readArtifact?: (params: {
    blobSha256: string;
    retention?: 'transient' | 'stored';
    format?: 'raw' | 'markdown';
    offset?: number;
    limit?: number;
  }) => Promise<{ ok: true; page: Record<string, unknown> } | { ok: false; status: number; error: string; message?: string }>;
  executeScrape?: (params: {
    args: Record<string, unknown>;
    principal?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeExtract?: (params: {
    args: Record<string, unknown>;
    principal?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeInteract?: (params: {
    args: Record<string, unknown>;
    principal?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeMap?: (params: {
    args: Record<string, unknown>;
    principal?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeCrawl?: (params: {
    args: Record<string, unknown>;
    principal?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeSearch?: (params: {
    args: Record<string, unknown>;
    principal?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeJobs?: (params: {
    args: Record<string, unknown>;
    principal?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeAgent?: (params: {
    args: Record<string, unknown>;
    principal?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  findExtractors?: (params: {
    query: string;
    category?: string;
    limit?: number;
  }) => Array<Record<string, unknown>>;
  searchCollection?: (params: {
    collectionId: string;
    query: string;
    limit?: number;
  }) => Promise<{ ok: true; hits: Array<Record<string, unknown>> } | { ok: false; status: number; error: string }>;
  scheduleBackground?: (promise: Promise<unknown>) => void;
  allowedOrigins?: readonly string[];
  selfHost?: string;
}

function isAllowedMcpOrigin(
  originHeader: string | null,
  selfOrigin: string,
  extraAllowedHosts: readonly string[] = [],
): boolean {
  return isTrustedMcpBrowserOrigin(originHeader, selfOrigin, extraAllowedHosts);
}

function mcpCorsHeaders(
  request: Request,
  selfOrigin: string,
  extraAllowedHosts: readonly string[] = [],
): Record<string, string> {
  const originHeader = request.headers.get('origin');
  if (!originHeader || !isAllowedMcpOrigin(originHeader, selfOrigin, extraAllowedHosts)) return {};
  return {
    'access-control-allow-origin': originHeader,
    'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
    'access-control-allow-headers':
      'authorization, x-api-key, content-type, accept, mcp-protocol-version, mcp-method, mcp-name, mcp-session-id',
    'access-control-expose-headers': 'www-authenticate, mcp-protocol-version, mcp-session-id',
    vary: 'Origin',
  };
}

function jsonRpcError(id: string | number | null, code: number, message: string, data?: unknown) {
  return {
    jsonrpc: '2.0',
    id,
    error: data !== undefined ? { code, message, data } : { code, message },
  };
}

function jsonRpcResult(id: string | number | null, result: unknown) {
  return { jsonrpc: '2.0', id, result };
}

/** Decodes MCP Streamable HTTP `=?base64?...?=` header sentinel values (SEP-2243). */
function decodeMcpHeaderValue(raw: string): { ok: true; value: string } | { ok: false } {
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c !== 0x09 && (c < 0x20 || c > 0x7e)) return { ok: false };
  }
  if (raw.startsWith('=?base64?') && raw.endsWith('?=')) {
    const b64 = raw.slice('=?base64?'.length, -2);
    try {
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return { ok: true, value: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
    } catch {
      return { ok: false };
    }
  }
  return { ok: true, value: raw };
}

function requiredScopeForTool(toolName: string): 'crawl:read' | 'crawl:fetch' | null {
  if (
    toolName === 'list_agents' ||
    toolName === 'read_artifact' ||
    toolName === 'search' ||
    toolName === 'search_collection' ||
    toolName === 'find_extractors'
  ) {
    return 'crawl:read';
  }
  if (
    toolName === 'fetch_url' ||
    toolName === 'fetch_batch' ||
    toolName === 'scrape' ||
    toolName === 'extract' ||
    toolName === 'interact' ||
    toolName === 'map' ||
    toolName === 'crawl' ||
    toolName === 'jobs' ||
    toolName === 'agent'
  ) {
    return 'crawl:fetch';
  }
  return null;
}

function hasRequiredToolScope(scopes: string[], needed: 'crawl:read' | 'crawl:fetch' | null): boolean {
  if (!needed) return true;
  if (needed === 'crawl:read') return scopes.includes('crawl:read') || scopes.includes('crawl:fetch');
  return scopes.includes('crawl:fetch');
}

function validatePublicHttpsUrl(raw: unknown, selfHost?: string): { ok: true; url: string } | { ok: false; error: string } {
  const res = validatePublicHttpsTargetUrl(raw, selfHost);
  return res.ok ? { ok: true, url: res.normalized } : { ok: false, error: res.message };
}

/**
 * Strips private/residential HAOS WAN IPs (`publicIp`) and internal LAN socket tuples in `lastError` before returning
 * `list_agents` over the public `/mcp` surface (preserving private origin shielding while keeping `/admin` diagnostics).
 */
export function sanitizeFleetForMcp(fleet: {
  connected: number;
  agents: AgentAttachment[];
  affinities: AffinityPin[];
}): {
  connected: number;
  agents: Array<Omit<AgentAttachment, 'publicIp'> & Record<string, unknown>>;
  affinities: Array<{ siteId: string; expiresAt: number }>;
  activeCooldownCount: number;
} {
  const safeAffinities = (fleet.affinities ?? []).map(({ siteId, expiresAt }) => ({ siteId, expiresAt }));
  return {
    connected: fleet.connected,
    agents: (fleet.agents ?? []).map((agent) => {
      const {
        publicIp: _omitPublicIp,
        remoteAddr: _omitRemoteAddr,
        ip: _omitIp,
        ...rest
      } = agent as unknown as Record<string, unknown>;
      if (typeof rest.lastError === 'string' && rest.lastError) {
        rest.lastError = rest.lastError
          .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, '[redacted-ip]')
          .replace(/\[[0-9a-fA-F:]+\](?::\d+)?/g, '[redacted-ip]');
      }
      return rest as Omit<AgentAttachment, 'publicIp'> & Record<string, unknown>;
    }),
    affinities: safeAffinities,
    activeCooldownCount: safeAffinities.length,
  };
}

function buildToolDefinitions(deps: McpServerDeps) {
  const { allowedTargets, defaultTarget } = deps;
  const allTools = [
    {
      name: 'list_agents',
      description:
        'List connected Home Assistant OS / EdgeFetch standby crawler agents (LITE vs FAT browser/PDF tiers), CPU architectures, job counters, and active host-affinity pins.',
      annotations: {
        title: 'List Connected Crawler Agents',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
    },
    {
      name: 'fetch_url',
      description:
        'Fetch a public HTTPS URL politely through the EdgeFetch coordinator (enforcing robots.txt, per-host rate limits, SSRF blocks, and returning DNS/TLS/TTFB phase timings plus response content).',
      annotations: {
        title: 'Fetch Public HTTPS URL',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Public https:// URL to fetch (port 443).' },
          kind: {
            type: 'string',
            enum: ['feed', 'json', 'page', 'text'],
            description:
              'Optional response kind ("page" for HTML, "text" for sitemaps/XML/RSS/Markdown/plain text, "json" for JSON APIs, "feed" for Shopify /products.json). Omit to auto-detect from URL.',
          },
          accept: {
            type: 'string',
            enum: [...TEXT_ACCEPTS],
            description: 'For kind "text" only. Default: picked from the URL (.xml or sitemap = application/xml, .txt/.md = text/plain, /rss = application/rss+xml, else text/html).',
          },
          target: {
            type: 'string',
            enum: allowedTargets,
            default: defaultTarget,
            description:
              'Execution tier ("auto" = load-balance across remote HAOS nodes and reach out via Cloudflare only on 429, "agent", or "container").',
          },
          site: {
            type: 'string',
            description: 'Optional standby site ID to pin (e.g. "site-arm64", "site-x86", "site-win-vm").',
          },
          respectRobots: { type: 'boolean', default: true, description: 'Respect /robots.txt Allow/Disallow and Crawl-delay.' },
          robots: { type: 'boolean', description: 'Deprecated alias for respectRobots.' },
          includeBody: { type: 'boolean', default: true, description: 'Include response body preview in tool output.' },
          maxBytes: {
            type: 'integer',
            minimum: 256,
            maximum: 16777216,
            description:
              'Maximum inline preview size in chars/bytes (256..16777216). Full untruncated body is always stored in R2 and readable via read_artifact.',
          },
          ifNoneMatch: { type: 'string', description: 'Optional ETag for conditional 304 Not Modified checks.' },
          ifModifiedSince: { type: 'string', description: 'Optional Last-Modified timestamp for conditional 304 checks.' },
        },
        required: ['url'],
        additionalProperties: false,
      },
    },
    {
      name: 'fetch_batch',
      description:
        'Politely fetch up to 25 public HTTPS URLs in one coordinated batch with per-host serialization, positive dwell jitter, robots.txt checks, and phase timing.',
      annotations: {
        title: 'Batch Fetch Public HTTPS URLs',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          urls: {
            type: 'array',
            items: { type: 'string' },
            minItems: 1,
            maxItems: MAX_BATCH_URLS,
            description: '1 to 25 public https:// URLs to fetch.',
          },
          kind: {
            type: 'string',
            enum: ['feed', 'json', 'page', 'text'],
            description: 'Optional kind applied to every URL; omit to auto-detect per URL (HTML -> "page", RSS/XML/Markdown/txt -> "text", .json -> "json").',
          },
          accept: {
            type: 'string',
            enum: [...TEXT_ACCEPTS],
            description: 'For kind "text" only; applies to every URL. Default: picked from each URL.',
          },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional standby site ID when target="agent".' },
          pauseMs: { type: 'integer', minimum: 0, maximum: 30000, default: 1000, description: 'Minimum per-host pause in ms.' },
          pauseJitterMs: { type: 'integer', minimum: 0, maximum: 15000, default: 500, description: 'Random positive jitter added to pauseMs.' },
          respectRobots: { type: 'boolean', default: true },
          robots: { type: 'boolean', description: 'Deprecated alias for respectRobots.' },
          includeBody: { type: 'boolean', default: false, description: 'Set true to include truncated body previews per URL.' },
          previewBytes: {
            type: 'integer',
            minimum: 256,
            maximum: 65536,
            default: DEFAULT_BATCH_PREVIEW_CHARS,
            description: 'Max inline body preview chars per URL when includeBody=true (default 3072; full body stays in R2 via read_artifact).',
          },
        },
        required: ['urls'],
        additionalProperties: false,
      },
    },
    {
      name: 'scrape',
      description:
        'Scrape a public HTTPS URL into clean main-content Markdown, metadata, links, images, branding, changes diff, and /llms.txt + companion .md discovery (with verified META D1 + R2 maxAgeMs caching and optional Chromium rendering).',
      annotations: {
        title: 'Scrape URL to Markdown & Metadata',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Public https:// URL to scrape.' },
          formats: {
            type: 'array',
            items: {
              anyOf: [
                {
                  type: 'string',
                  enum: [
                    'markdown',
                    'text',
                    'summary',
                    'product',
                    'rawBase64',
                    'html',
                    'rawHtml',
                    'links',
                    'images',
                    'branding',
                    'llmsTxt',
                    'screenshot',
                    'changes',
                    'changeTracking',
                  ],
                },
                {
                  type: 'object',
                  properties: {
                    type: { type: 'string', enum: ['json', 'attributes', 'screenshot', 'changeTracking'] },
                    prompt: { type: 'string', description: 'Optional extraction instruction when type="json".' },
                    schema: { type: 'object', description: 'Optional JSON Schema object when type="json".' },
                    selectors: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          selector: { type: 'string' },
                          attribute: { type: 'string' },
                        },
                        required: ['selector', 'attribute'],
                      },
                    },
                    fullPage: { type: 'boolean' },
                    quality: { type: 'integer', minimum: 1, maximum: 100 },
                    modes: { type: 'array', items: { type: 'string' } },
                    tag: { type: 'string' },
                  },
                  required: ['type'],
                },
              ],
            },
            default: ['markdown'],
            description: 'Desired output formats (string format names or { type: "json", schema } for structured extraction).',
          },
          renderMode: {
            type: 'string',
            enum: ['off', 'auto', 'always', 'browser'],
            default: 'auto',
            description: '"auto" (default) automatically switches thin/SPA pages to headless Chromium on edgefetch_fat nodes; "always" or "browser" forces Chromium.',
          },
          waitForMs: { type: 'integer', minimum: 0, maximum: 15000, description: 'Extra JS settle wait in ms when rendering.' },
          waitSelector: { type: 'string', description: 'Optional CSS selector to wait for when rendering.' },
          maxPages: { type: 'integer', minimum: 1, maximum: 500, description: 'Max PDF pages to extract via Poppler pdftotext / PyMuPDF + Tesseract OCR.' },
          ocr: {
            type: 'string',
            enum: ['auto', 'always', 'off'],
            default: 'auto',
            description: 'PDF OCR mode via PyMuPDF + Tesseract 5.5.0: "auto" OCRs scanned/image-only PDFs; "always" forces OCR on image-based tables.',
          },
          onlyMainContent: { type: 'boolean', default: true, description: 'Strip nav/footer/aside chrome and isolate main/article content.' },
          includeTags: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional HTML tag/ID/class selectors (e.g. ["article", "#content", ".post-body"]) to keep exclusively.',
          },
          excludeTags: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional HTML tag/ID/class selectors (e.g. [".comments", "#cookie-banner", "aside"]) to remove before Markdown conversion.',
          },
          includeImages: {
            type: 'boolean',
            default: true,
            description: 'Include content images >=100px (set false to strip all images and inline ![...] tags).',
          },
          maxChars: {
            type: 'integer',
            minimum: 500,
            maximum: 500000,
            description:
              'Optional max Markdown character limit (default 100000 on MCP; truncates cleanly at paragraph/word boundary and returns markdownArtifactId + nextOffset for lossless paging via read_artifact).',
          },
          discoverLlmsTxt: { type: 'boolean', default: true, description: 'Check /llms.txt and upgrade to companion .md when available.' },
          maxAgeMs: { type: 'integer', minimum: 0, default: 0, description: 'Serve cached verified Markdown if fetched within maxAgeMs.' },
          redactPii: { type: 'boolean', default: false, description: 'Redact emails, phone numbers, and SSNs.' },
          checkPromptInjection: {
            type: 'boolean',
            default: false,
            description: '$0 prompt-injection guard: fails fast with 403 SCRAPE_PROMPT_INJECTION_DETECTED when malicious override directives are found.',
          },
          mobile: { type: 'boolean', default: false, description: 'Emulate 390x844 mobile viewport in headless browser.' },
          location: {
            type: 'object',
            properties: {
              country: { type: 'string' },
              languages: { type: 'array', items: { type: 'string' } },
            },
          },
          actions: {
            type: 'array',
            maxItems: 50,
            description: 'Optional inline browser actions (wait, click, write, fill, press, scroll, screenshot, scrape, executeJavascript, pdf).',
            items: { type: 'object' },
          },
          parsers: {
            type: 'array',
            description: 'Optional PDF/image parser controls (e.g. [{ type: "pdf", mode: "auto", pages: true, pageMarkers: true }] or [] for raw base64).',
            items: { anyOf: [{ type: 'string' }, { type: 'object' }] },
          },
          query: { type: 'string', description: 'Optional focus query to rerank relevant passages.' },
          jsonFilter: {
            type: 'string',
            description: 'Optional record filter for JSON array responses (e.g. `title~"Forward Deployed"` or `id=abc123`), emitting 1 chunk per record.',
          },
          collectionId: { type: 'string', description: 'Optional FTS5 collection ID to index the verified Markdown into.' },
          waybackFallback: {
            type: 'boolean',
            default: false,
            description:
              'Opt-in Internet Archive Wayback fallback strictly on 5xx or network-unreachable link rot (never used on robots.txt, 401/403/429, or anti-bot challenges).',
          },
          spaFallback: {
            type: 'string',
            enum: ['auto', 'off', 'crawl4ai', 'firecrawl'],
            default: 'auto',
            description:
              'When CRAWL4AI_API_URL or FIRECRAWL_API_URL/KEY is configured on the Hub, ethically falls back on heavy/unhydrated SPAs or missing local browser nodes (never used on robots.txt, 403/429, or challenges).',
          },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional standby site ID when target="agent".' },
        },
        required: ['url'],
        additionalProperties: false,
      },
    },
    {
      name: 'extract',
      description:
        'Extract clean Markdown and BM25 query-ranked chunks across 1..20 public HTTPS URLs in one polite batch (with optional verified maxAgeMs cache and FTS5 collection indexing).',
      annotations: {
        title: 'Extract Focused Passages from URLs',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          urls: {
            type: 'array',
            items: { type: 'string' },
            minItems: 1,
            maxItems: 20,
            description: '1..20 public https:// URLs to extract from.',
          },
          query: { type: 'string', description: 'Focus query used to BM25-rank the top chunks per source.' },
          jsonFilter: {
            type: 'string',
            description: 'Optional record filter for JSON array responses (e.g. `title~"Forward Deployed"` or `id=abc123`), emitting 1 chunk per record.',
          },
          renderMode: {
            type: 'string',
            enum: ['off', 'auto', 'always', 'browser'],
            default: 'auto',
            description: '"auto" (default) upgrades thin scripted pages to headless Chromium; "always" or "browser" forces Chromium.',
          },
          chunksPerSource: { type: 'integer', minimum: 1, maximum: 10, default: 3, description: 'Max chunks returned per URL.' },
          maxAgeMs: { type: 'integer', minimum: 0, default: 0, description: 'Serve cached verified Markdown if fetched within maxAgeMs.' },
          redactPii: { type: 'boolean', default: false, description: 'Redact emails, phone numbers, and SSNs.' },
          collectionId: { type: 'string', description: 'Optional FTS5 collection ID to index extracted pages into.' },
          waybackFallback: {
            type: 'boolean',
            default: false,
            description:
              'Opt-in Internet Archive Wayback fallback strictly on 5xx or network-unreachable link rot (never used on robots.txt, 401/403/429, or anti-bot challenges).',
          },
          spaFallback: {
            type: 'string',
            enum: ['auto', 'off', 'crawl4ai', 'firecrawl'],
            default: 'auto',
            description:
              'When CRAWL4AI_API_URL or FIRECRAWL_API_URL/KEY is configured on the Hub, ethically falls back on heavy/unhydrated SPAs or missing local browser nodes (never used on robots.txt, 403/429, or challenges).',
          },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional standby site ID when target="agent".' },
        },
        required: ['urls'],
        additionalProperties: false,
      },
    },
    {
      name: 'map',
      description:
        'Discover URLs on a site rapidly and politely via robots.txt Sitemap:, sitemap.xml / .xml.gz, /llms.txt, and homepage links, with optional search filter.',
      annotations: {
        title: 'Map Site URLs',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Root public https:// URL of the site.' },
          search: { type: 'string', description: 'Optional keyword filter to rank/filter matching URLs.' },
          limit: { type: 'integer', minimum: 1, maximum: 5000, default: 500 },
          includeSubdomains: { type: 'boolean', default: false },
          includeOutsidePath: {
            type: 'boolean',
            default: false,
            description: 'When false (default), restricts discovered URLs to the root URL path prefix when url has a subpath.',
          },
          ignoreSitemap: { type: 'boolean', default: false },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional standby site ID when target="agent".' },
        },
        required: ['url'],
        additionalProperties: false,
      },
    },
    {
      name: 'crawl',
      description:
        'Start an async multi-page breadth-first site crawl (with robots.txt, includePaths/excludePaths, SEARCH D1 FTS5 indexing, and HMAC webhooks), OR pass crawlId to poll status / cancel.',
      annotations: {
        title: 'Async Site Crawl (Start / Status / Cancel)',
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Root public https:// URL to start crawling (omit when checking/cancelling crawlId).' },
          crawlId: { type: 'string', description: 'Existing crawl ID (`crw_...`) to check status or cancel.' },
          cancel: { type: 'boolean', default: false, description: 'Set true with crawlId to cancel a running crawl.' },
          limit: { type: 'integer', minimum: 1, maximum: 200, default: 25 },
          maxDepth: { type: 'integer', minimum: 0, maximum: 5, default: 2 },
          allowSubdomains: { type: 'boolean', default: false },
          includePaths: { type: 'array', items: { type: 'string' } },
          excludePaths: { type: 'array', items: { type: 'string' } },
          collectionId: { type: 'string', description: 'Optional SEARCH D1 collection ID to index crawled pages into.' },
          offset: { type: 'integer', minimum: 0, default: 0, description: 'Result offset when polling crawlId.' },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'search',
      description:
        'Edge-first web & collection search: queries private SEARCH D1 FTS5 + HAOS edge-map (/llms.txt & sitemap.xml on site: queries) + 24h SERP cache + Serper (Google) waterfall (calling SearXNG/Brave only on <3 hits), with optional live HAOS page extraction.',
      annotations: {
        title: 'Search Web & Crawled Collections',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Search query (1..500 chars). Supports site:domain.com for $0 HAOS edge-map discovery.' },
          max_results: { type: 'integer', minimum: 1, maximum: 20, default: 5 },
          maxResults: { type: 'integer', minimum: 1, maximum: 20, description: 'Alias for max_results.' },
          limit: { type: 'integer', minimum: 1, maximum: 20, description: 'Alias for max_results.' },
          mode: {
            type: 'string',
            enum: ['waterfall', 'rrf', 'serper'],
            default: 'waterfall',
            description: '"waterfall" (default) runs Serper alone first and calls SearXNG/Brave only if Serper returns <3 hits; "serper" skips Brave completely; "rrf" fuses active providers in parallel.',
          },
          providers: {
            type: 'array',
            items: { type: 'string', enum: ['serper', 'brave', 'searxng', 'tavily'] },
            description: 'Optional explicit provider allowlist (e.g. ["serper"] or ["serper", "searxng"] to never call Brave).',
          },
          include_domains: { type: 'array', items: { type: 'string' } },
          includeDomains: { type: 'array', items: { type: 'string' }, description: 'Alias for include_domains.' },
          exclude_domains: { type: 'array', items: { type: 'string' } },
          excludeDomains: { type: 'array', items: { type: 'string' }, description: 'Alias for exclude_domains.' },
          time_range: { type: 'string', enum: ['day', 'week', 'month', 'year'] },
          timeRange: { type: 'string', enum: ['day', 'week', 'month', 'year'], description: 'Alias for time_range.' },
          max_age_ms: { type: 'integer', minimum: 0, description: 'SERP cache max age in ms (default 86400000 = 24h; 0 bypasses cache).' },
          maxAgeMs: { type: 'integer', minimum: 0, description: 'Alias for max_age_ms.' },
          include_raw_content: { type: 'boolean', default: false, description: 'Fetch & chunk top results politely via EdgeFetch HAOS agents.' },
          includeRawContent: { type: 'boolean', description: 'Alias for include_raw_content.' },
          chunks_per_source: { type: 'integer', minimum: 1, maximum: 10, default: 3 },
          chunksPerSource: { type: 'integer', minimum: 1, maximum: 10, description: 'Alias for chunks_per_source.' },
          collections: { type: 'array', items: { type: 'string' }, description: 'Optional private SEARCH D1 collection IDs to fuse.' },
          collectionId: { type: 'string', description: 'Optional single private SEARCH D1 collection ID to fuse.' },
        },
        required: ['query'],
        additionalProperties: false,
      },
    },
    {
      name: 'search_collection',
      description:
        'Search a private SEARCH D1 FTS5 collection populated by crawl, scrape, or extract (e.g. collectionId="default" or a crawlId `crw_...`) with BM25 ranking and snippets.',
      annotations: {
        title: 'Search Indexed Collection (D1 FTS5)',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        type: 'object',
        properties: {
          collectionId: {
            type: 'string',
            default: 'default',
            description: 'Target collection ID (`default` or a custom / `crw_...` collectionId).',
          },
          query: { type: 'string', description: 'Keyword search query matched safely against FTS5 chunks.' },
          limit: { type: 'integer', minimum: 1, maximum: 50, default: 10 },
        },
        required: ['query'],
        additionalProperties: false,
      },
    },
    {
      name: 'interact',
      description:
        'Drive a sandboxed headless Chromium session on an edgefetch_fat (browser-v1) node (click, fill, press, scroll, wait, PNG screenshots) with SSRF CONNECT isolation, robots.txt pre-checks, and automatic stop on anti-bot challenges.',
      annotations: {
        title: 'Interact with Page in Sandboxed Headless Browser',
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Initial public https:// URL (omit when resuming/closing sessionId).' },
          sessionId: { type: 'string', description: 'Composite sessionId returned from a prior interact call with keepSession=true.' },
          keepSession: { type: 'boolean', default: false, description: 'Keep the incognito browser tab open for follow-up interact calls.' },
          closeSession: { type: 'boolean', default: false, description: 'Close the retained browser session after this turn.' },
          actions: {
            type: 'array',
            maxItems: 25,
            items: {
              type: 'object',
              properties: {
                type: { type: 'string', enum: ['click', 'fill', 'type', 'press', 'wait', 'scroll', 'select', 'navigate'] },
                selector: { type: 'string' },
                value: { type: 'string' },
                key: { type: 'string' },
                url: { type: 'string' },
                waitMs: { type: 'integer', minimum: 0, maximum: 15000 },
              },
              required: ['type'],
              additionalProperties: false,
            },
          },
          formats: {
            type: 'array',
            items: { type: 'string', enum: ['markdown', 'html', 'rawHtml', 'screenshot', 'transcript'] },
            default: ['markdown'],
          },
          waitForMs: { type: 'integer', minimum: 0, maximum: 15000 },
          waitSelector: { type: 'string' },
          site: { type: 'string', description: 'Optional specific edgefetch_fat site ID.' },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'read_artifact',
      description:
        'Read a slice of a stored R2 artifact by artifactId (64-char hex blobSha256 for raw fetch bodies, or md:<sha256> / format="markdown" for derived scrape Markdown) using character offset + limit paging.',
      annotations: {
        title: 'Read Paged Crawl Artifact',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        type: 'object',
        properties: {
          artifactId: {
            type: 'string',
            description: '64-character hex blobSha256 (from fetch_url/fetch_batch/scrape) OR md:<sha256> (markdownArtifactId from scrape).',
          },
          format: {
            type: 'string',
            enum: ['raw', 'markdown'],
            description: 'Optional slice format ("raw" default for blobSha256; "markdown" reads derived clean Markdown when available).',
          },
          retention: { type: 'string', enum: ['transient', 'stored'], description: 'Optional retention tier hint.' },
          offset: { type: 'integer', minimum: 0, default: 0, description: 'Character offset to start reading from.' },
          limit: { type: 'integer', minimum: 1, maximum: 262144, default: 65536, description: 'Max characters to return in this page.' },
        },
        required: ['artifactId'],
        additionalProperties: false,
      },
    },
    {
      name: 'jobs',
      description:
        'One-call structured job search across official ATS boards (Greenhouse US/EU, Ashby, Lever US/EU, Workday CXS, Workable, Gem, Rippling, SmartRecruiters, company-domain -> ATS auto-discovery, and optional Built In): standardizes pay ({ min, max, currency, period, basis: "base"|"ote"|"total" }), workplaceType, and locations, deduplicates by (company, title), and filters by remote, locations, minBase, postedWithinDays, and exclude.',
      annotations: {
        title: 'Search & Extract Structured Job Postings',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Role or keyword query (e.g. "Forward Deployed Engineer", "Solutions Architect").' },
          company: { type: 'string', description: 'Optional company name or ATS org filter.' },
          domains: {
            type: 'array',
            items: { type: 'string' },
            maxItems: 10,
            description:
              'Optional company domains (e.g. ["cloudflare.com", "stripe.com"]) to probe /careers and /jobs for automatic ATS board discovery across 16+ ATS platforms.',
          },
          remote: { type: 'boolean', description: 'When true, keep only remote-eligible roles.' },
          locations: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional location substrings to match (e.g. ["United States", "Remote", "New York"]).',
          },
          minBase: {
            type: 'number',
            minimum: 0,
            description: 'Minimum annual base salary floor (ignores total-target-cash / OTE unless basis === "base").',
          },
          postedWithinDays: { type: 'integer', minimum: 1, maximum: 365, description: 'Filter postings published within N days.' },
          limit: { type: 'integer', minimum: 1, maximum: 50, default: 20 },
          includeBuiltIn: { type: 'boolean', default: true, description: 'Also check Built In remote job search.' },
          exclude: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                company: { type: 'string' },
                title: { type: 'string' },
                url: { type: 'string' },
              },
              additionalProperties: false,
            },
            description: 'Optional list of already-applied roles to exclude.',
          },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional standby site ID when target="agent".' },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'find_extractors',
      description:
        'On-demand dynamic search across EdgeFetch’s 49+ keyless built-in site/API adapters (SEC EDGAR, YC, Polymarket, Ashby/Greenhouse/Lever/Workday/Workable/Gem/Rippling ATS, arXiv, OpenAlex, DOI/Crossref, ClinicalTrials, openFDA, PubChem, Socrata, CKAN, ArcGIS, Legistar, USAspending, NIST NVD CVEs, npm, PyPI, Crates, Shopify, etc.) without context bloat.',
      annotations: {
        title: 'Search Built-In Keyless Site Adapters',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Provider name, domain, or data topic (e.g. "SEC 10-K", "CVE", "clinical trials").' },
          category: {
            type: 'string',
            enum: ['jobs', 'finance', 'public-records', 'research-health', 'developer', 'genai', 'commerce-social'],
          },
          limit: { type: 'integer', minimum: 1, maximum: 50, default: 10 },
        },
        required: ['query'],
        additionalProperties: false,
      },
    },
    {
      name: 'agent',
      description:
        'Autonomous multi-step web research & structured JSON extraction agent: works with offline local LLMs (Ollama, LM Studio, vLLM) or online BYO-LLM (OpenAI, Anthropic, Gemini, OpenRouter, Workers AI), dynamically routing across all 49+ keyless adapters with zero 3-source cap and $0 Zero Data Retention.',
      annotations: {
        title: 'Autonomous Research & Structured Data Agent',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          prompt: { type: 'string', description: 'Natural-language goal or research question (URLs optional).' },
          agentId: { type: 'string', description: 'Existing agt_... ID to poll status, fetch trace, or cancel.' },
          trace: { type: 'boolean', default: false, description: 'Return ordered execution spans when polling agentId.' },
          cancel: { type: 'boolean', default: false, description: 'Cancel a running agentId.' },
          urls: { type: 'array', items: { type: 'string' }, description: 'Optional seed public https:// URLs.' },
          strictConstrainToURLs: { type: 'boolean', default: false, description: 'Restrict navigation strictly to seed urls.' },
          schema: { type: 'object', description: 'Optional JSON Schema for structured output validation.' },
          effort: { type: 'string', enum: ['low', 'medium', 'high'], default: 'medium' },
          maxSteps: { type: 'integer', minimum: 1, maximum: 20 },
          maxPages: { type: 'integer', minimum: 1, maximum: 40 },
          threadId: { type: 'string', description: 'Optional prior agt_... threadId for multi-turn continuation.' },
          zeroDataRetention: { type: 'boolean', default: false, description: '$0 native Zero Data Retention (skips D1/R2 persistence).' },
          safe: { type: 'boolean', default: false },
          location: {
            type: 'object',
            properties: {
              country: { type: 'string' },
              languages: { type: 'array', items: { type: 'string' } },
            },
          },
          llm: {
            type: 'object',
            description: 'Optional BYO-LLM override (e.g. { provider: "ollama"|"openai"|"anthropic"|"gemini", model, baseUrl }).',
            properties: {
              provider: { type: 'string' },
              baseUrl: { type: 'string' },
              model: { type: 'string' },
              apiKey: { type: 'string' },
            },
          },
        },
        additionalProperties: false,
      },
    },
  ];
  return allTools
    .filter((t) => {
      if (t.name === 'scrape') return Boolean(deps.executeScrape);
      if (t.name === 'extract') return Boolean(deps.executeExtract);
      if (t.name === 'map') return Boolean(deps.executeMap);
      if (t.name === 'crawl') return Boolean(deps.executeCrawl);
      if (t.name === 'search') return Boolean(deps.executeSearch);
      if (t.name === 'search_collection') return Boolean(deps.searchCollection);
      if (t.name === 'interact') return Boolean(deps.executeInteract);
      if (t.name === 'read_artifact') return Boolean(deps.readArtifact);
      if (t.name === 'jobs') return Boolean(deps.executeJobs);
      if (t.name === 'find_extractors') return Boolean(deps.findExtractors);
      if (t.name === 'agent') return Boolean(deps.executeAgent);
      return true;
    })
    .map((t) => ({ ...t, title: t.annotations.title }));
}

export function truncateResultBodies(
  parsed: Record<string, unknown>,
  inlineMaxChars = MAX_BODY_PREVIEW_CHARS,
  autoInferredKind = false,
): Record<string, unknown> {
  if (!Array.isArray(parsed.results)) return parsed;
  let promotedTruncatedErrors = 0;
  let promotedAutoKindSkips = 0;
  const results = parsed.results.map((item) => {
    if (!item || typeof item !== 'object') return item;
    const copy = { ...(item as Record<string, unknown>) };
    const art = copy.artifact as { blobSha256?: string; retention?: string } | undefined;
    if (art?.blobSha256) {
      copy.artifactId = art.blobSha256;
    }

    // Finding #3: HTTP 2xx body size truncation is a truncated success (`outcome: "ok", truncated: true`), not an error.
    if (
      copy.truncated === true &&
      copy.outcome === 'error' &&
      typeof copy.status === 'number' &&
      copy.status >= 200 &&
      copy.status < 300
    ) {
      copy.outcome = 'ok';
      delete copy.problem;
      promotedTruncatedErrors++;
    }

    // When caller omitted `kind` (`autoInferredKind === true`) and an extensionless URL returned HTTP 2xx with a valid
    // JSON/XML/text/Markdown/vCard/CSV payload and body, promote `kind="page"` skip to `ok` instead of failing the caller.
    if (
      autoInferredKind &&
      copy.outcome === 'skip' &&
      typeof copy.status === 'number' &&
      copy.status >= 200 &&
      copy.status < 300 &&
      ((typeof copy.body === 'string' && copy.body.length > 0) || Boolean(art?.blobSha256)) &&
      typeof copy.contentType === 'string' &&
      /^(?:text\/|application\/(?:[a-z0-9.+-]*\+)?(?:json|xml|rss|atom|yaml|csv|javascript)|application\/x-ndjson)/i.test(
        copy.contentType.trim(),
      )
    ) {
      copy.outcome = 'ok';
      delete copy.problem;
      promotedAutoKindSkips++;
    }

    // Finding #5: Always explain why a response was skipped (e.g. non-HTML content-type on `kind: "page"`).
    if (copy.outcome === 'skip' && (!copy.problem || String(copy.problem).trim() === '')) {
      if (typeof copy.status === 'number' && copy.status >= 200 && copy.status < 300) {
        copy.problem = `non-HTML content-type "${String(copy.contentType || 'unknown')}" skipped for kind="page" (omit kind to auto-detect, or set kind="text" / "json")`;
      } else {
        copy.problem = `HTTP ${String(copy.status ?? 0)} skipped`;
      }
    }

    // P9 & P10: Flag material URL redirects (`redirected`, `filtersMayBeLost`) and attach structured `blocked` hints!
    if (typeof copy.url === 'string' && typeof copy.finalUrl === 'string' && copy.finalUrl) {
      const redir = analyzeUrlRedirect(copy.url, copy.finalUrl);
      if (redir.redirected) {
        copy.redirected = true;
        if (redir.redirectNote) copy.redirectNote = redir.redirectNote;
        if (redir.filtersMayBeLost) copy.filtersMayBeLost = true;
      }
    }
    if (copy.outcome !== 'ok' && typeof copy.url === 'string') {
      if (!copy.waf && typeof copy.status === 'number') {
        const inferredWaf = classifyWafAndChallenge({
          status: copy.status,
          ...(typeof copy.body === 'string' && (!copy.bodyEncoding || copy.bodyEncoding === 'utf-8') ? { rawBody: copy.body } : {}),
        });
        if (inferredWaf) copy.waf = inferredWaf;
      }
      const blocked = buildBlockedInfo(copy.url, copy.outcome, copy.problem, copy.status);
      if (blocked) copy.blocked = blocked;
    }

    if (typeof copy.body === 'string' && copy.body.length > inlineMaxChars) {
      const totalChars = copy.body.length;
      copy.body = copy.body.slice(0, inlineMaxChars);
      copy.truncated = true;
      copy.offset = 0;
      copy.nextOffset = inlineMaxChars;
      copy.hasMore = true;
      copy.bodyOriginalChars = totalChars;
      copy.bodyPreviewTruncated = true;
    } else if (copy.bodyOmitted === true && art?.blobSha256) {
      copy.offset = 0;
      copy.nextOffset = 0;
      copy.hasMore = true;
    }
    return copy;
  });

  if ((promotedTruncatedErrors > 0 || promotedAutoKindSkips > 0) && parsed.summary && typeof parsed.summary === 'object') {
    const sumCopy = { ...(parsed.summary as Record<string, unknown>) };
    if (sumCopy.byOutcome && typeof sumCopy.byOutcome === 'object') {
      const byOut = { ...(sumCopy.byOutcome as Record<string, number>) };
      byOut.ok = (byOut.ok ?? 0) + promotedTruncatedErrors + promotedAutoKindSkips;
      if (promotedTruncatedErrors > 0) {
        byOut.error = Math.max(0, (byOut.error ?? 0) - promotedTruncatedErrors);
        if (byOut.error === 0) delete byOut.error;
      }
      if (promotedAutoKindSkips > 0) {
        byOut.skip = Math.max(0, (byOut.skip ?? 0) - promotedAutoKindSkips);
        if (byOut.skip === 0) delete byOut.skip;
      }
      sumCopy.byOutcome = byOut;
    }
    return { ...parsed, summary: sumCopy, results };
  }

  return { ...parsed, results };
}

async function handleToolCallInner(
  name: string,
  args: Record<string, unknown>,
  scopes: string[],
  principal: string,
  deps: McpServerDeps,
): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
  if (name === 'list_agents') {
    if (!scopes.includes('crawl:read') && !scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:read is required.' }], isError: true };
    }
    try {
      const fleet = sanitizeFleetForMcp(await deps.listFleet());
      return {
        content: [{ type: 'text', text: JSON.stringify(fleet, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: 'hub_unavailable', message: e instanceof Error ? e.message : 'Coordinator temporarily unavailable' }) }],
        isError: true,
      };
    }
  }

  if (name === 'fetch_url' || name === 'fetch_batch') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }

    const rawTarget = (typeof args.target === 'string' ? args.target.trim().toLowerCase() : deps.defaultTarget) as FetchTarget;
    if (!deps.allowedTargets.includes(rawTarget)) {
      return {
        content: [{ type: 'text', text: `Unsupported target '${rawTarget}' (allowed: ${deps.allowedTargets.join(', ')})` }],
        isError: true,
      };
    }

    const rawSite = typeof args.site === 'string' ? args.site.trim().toLowerCase() : undefined;
    if (rawSite && !SITE_ID_PATTERN.test(rawSite)) {
      return { content: [{ type: 'text', text: `Invalid site ID '${rawSite}'` }], isError: true };
    }

    if (args.respectRobots === false || args.robots === false) {
      return { content: [{ type: 'text', text: 'Disabling robots.txt via MCP is not permitted.' }], isError: true };
    }
    const explicitKind =
      args.kind === 'feed' || args.kind === 'json' || args.kind === 'text' || args.kind === 'page' ? args.kind : undefined;
    const respectRobots = true;
    const includeBody = typeof args.includeBody === 'boolean' ? args.includeBody : name === 'fetch_url';

    if (
      (typeof args.ifNoneMatch === 'string' && /[\r\n\0]/.test(args.ifNoneMatch)) ||
      (typeof args.ifModifiedSince === 'string' && /[\r\n\0]/.test(args.ifModifiedSince))
    ) {
      return { content: [{ type: 'text', text: 'Invalid control characters in conditional header.' }], isError: true };
    }

    let requests: Array<Record<string, unknown>>;
    if (name === 'fetch_url') {
      const check = validatePublicHttpsUrl(args.url, deps.selfHost);
      if (!check.ok) return { content: [{ type: 'text', text: check.error }], isError: true };
      const kind = explicitKind ?? inferKindForUrl(check.url);
      const accept = textAcceptFor(kind, check.url, args.accept);
      if (!accept.ok) return { content: [{ type: 'text', text: accept.error }], isError: true };
      requests = [
        {
          id: 'mcp-1',
          url: check.url,
          kind,
          ...(accept.accept ? { accept: accept.accept } : {}),
          ...(typeof args.ifNoneMatch === 'string' && args.ifNoneMatch ? { ifNoneMatch: args.ifNoneMatch } : {}),
          ...(typeof args.ifModifiedSince === 'string' && args.ifModifiedSince ? { ifModifiedSince: args.ifModifiedSince } : {}),
        },
      ];
    } else {
      if (!Array.isArray(args.urls) || args.urls.length === 0 || args.urls.length > MAX_BATCH_URLS) {
        return { content: [{ type: 'text', text: `urls must contain 1 to ${MAX_BATCH_URLS} HTTPS URLs` }], isError: true };
      }
      requests = [];
      for (let i = 0; i < args.urls.length; i++) {
        const check = validatePublicHttpsUrl(args.urls[i], deps.selfHost);
        if (!check.ok) return { content: [{ type: 'text', text: `urls[${i}]: ${check.error}` }], isError: true };
        const kind = explicitKind ?? inferKindForUrl(check.url);
        const accept = textAcceptFor(kind, check.url, args.accept);
        if (!accept.ok) return { content: [{ type: 'text', text: accept.error }], isError: true };
        requests.push({ id: `mcp-${i + 1}`, url: check.url, kind, ...(accept.accept ? { accept: accept.accept } : {}) });
      }
    }

    // Finding #4 & #6: Never truncate the R2 artifact upload when a caller passes a small `maxBytes` preview cap!
    // Only forward `options.maxBytes` to the Go agent when the caller asks to RAISE Go's 8 MiB ceiling (up to 16 MiB).
    const requestedMaxBytes =
      typeof args.maxBytes === 'number' && Number.isFinite(args.maxBytes) ? Math.floor(args.maxBytes) : undefined;
    const inlineMaxChars =
      name === 'fetch_batch'
        ? typeof args.previewBytes === 'number' && Number.isFinite(args.previewBytes)
          ? Math.min(MAX_BODY_PREVIEW_CHARS, Math.max(256, Math.floor(args.previewBytes)))
          : DEFAULT_BATCH_PREVIEW_CHARS
        : requestedMaxBytes !== undefined
          ? Math.min(MAX_BODY_PREVIEW_CHARS, Math.max(256, requestedMaxBytes))
          : MAX_BODY_PREVIEW_CHARS;

    const callPayload = {
      maxSeconds: 60,
      options: {
        includeBody,
        respectRobots,
        ...(name === 'fetch_batch' ? { concurrency: 4 } : {}),
        ...(requestedMaxBytes !== undefined && requestedMaxBytes > 8 * 1024 * 1024
          ? { maxBytes: Math.min(16 << 20, requestedMaxBytes) }
          : {}),
        ...(typeof args.pauseMs === 'number' ? { pauseMs: Math.min(30_000, Math.max(0, Math.floor(args.pauseMs))) } : {}),
        ...(typeof args.pauseJitterMs === 'number'
          ? { pauseJitterMs: Math.min(15_000, Math.max(0, Math.floor(args.pauseJitterMs))) }
          : {}),
      },
      requests,
    };

    let res: McpExecuteFetchResult;
    try {
      res = await deps.executeFetch({
        target: rawTarget,
        ...(rawSite ? { site: rawSite } : {}),
        body: JSON.stringify(callPayload),
        principal,
      });
    } catch (e) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'hub_unavailable',
              message: e instanceof Error ? e.message : 'Coordinator temporarily unavailable',
            }),
          },
        ],
        isError: true,
      };
    }

    let formatted: unknown = res.bodyText;
    try {
      const parsed = JSON.parse(res.bodyText) as Record<string, unknown>;
      formatted = {
        via: res.via,
        httpStatus: res.status,
        ...(res.stageTimingsMs ? { stageTimingsMs: res.stageTimingsMs } : {}),
        ...truncateResultBodies(parsed, inlineMaxChars, explicitKind === undefined),
      };
    } catch {
      formatted = {
        via: res.via,
        httpStatus: res.status,
        ...(res.stageTimingsMs ? { stageTimingsMs: res.stageTimingsMs } : {}),
        raw: res.bodyText.slice(0, inlineMaxChars),
      };
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(formatted, null, 2) }],
      ...(res.status >= 400 ? { isError: true } : {}),
    };
  }

  if (name === 'read_artifact') {
    if (!scopes.includes('crawl:read') && !scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:read is required.' }], isError: true };
    }
    if (!deps.readArtifact) {
      return { content: [{ type: 'text', text: 'R2 artifact storage is not configured on this hub.' }], isError: true };
    }
    const blobSha256 = typeof args.artifactId === 'string' ? args.artifactId.trim().toLowerCase() : '';
    const retention = args.retention === 'stored' ? 'stored' : args.retention === 'transient' ? 'transient' : undefined;
    const format = args.format === 'markdown' ? 'markdown' : args.format === 'raw' ? 'raw' : undefined;
    const offset = typeof args.offset === 'number' ? Math.max(0, Math.floor(args.offset)) : 0;
    const limit = typeof args.limit === 'number' ? Math.min(262_144, Math.max(1, Math.floor(args.limit))) : MAX_BODY_PREVIEW_CHARS;
    const out = await deps.readArtifact({
      blobSha256,
      ...(retention ? { retention } : {}),
      ...(format ? { format } : {}),
      offset,
      limit,
    });
    if (!out.ok) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: out.error, status: out.status, ...(out.message ? { message: out.message } : {}) }),
          },
        ],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: JSON.stringify(out.page, null, 2) }] };
  }

  if (name === 'scrape') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }
    if (!deps.executeScrape) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'scrape_not_configured' }) }], isError: true };
    }
    const scrapeArgs =
      args.maxChars === undefined ? { ...args, defaultMaxChars: DEFAULT_MCP_SCRAPE_MAX_CHARS } : args;
    const res = await deps.executeScrape({ args: scrapeArgs, principal });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status !== 200 ? { isError: true } : {}),
    };
  }

  if (name === 'extract') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }
    if (!deps.executeExtract) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'extract_not_configured' }) }], isError: true };
    }
    const res = await deps.executeExtract({ args, principal });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status !== 200 ? { isError: true } : {}),
    };
  }

  if (name === 'search_collection') {
    if (!scopes.includes('crawl:read') && !scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:read is required.' }], isError: true };
    }
    if (!deps.searchCollection) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'search_not_configured' }) }], isError: true };
    }
    const collectionId = typeof args.collectionId === 'string' && args.collectionId.trim() ? args.collectionId.trim() : 'default';
    const query = typeof args.query === 'string' ? args.query : '';
    const limit = typeof args.limit === 'number' && Number.isFinite(args.limit) ? args.limit : 10;
    const res = await deps.searchCollection({ collectionId, query, limit });
    if (!res.ok) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: res.error }) }], isError: true };
    }
    return {
      content: [{ type: 'text', text: JSON.stringify({ collectionId, query, hits: res.hits }, null, 2) }],
    };
  }

  if (name === 'interact') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }
    if (!deps.executeInteract) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'interact_not_configured' }) }], isError: true };
    }
    const res = await deps.executeInteract({ args, principal });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status !== 200 ? { isError: true } : {}),
    };
  }

  if (name === 'map') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }
    if (!deps.executeMap) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'map_not_configured' }) }], isError: true };
    }
    const res = await deps.executeMap({ args, principal });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status !== 200 ? { isError: true } : {}),
    };
  }

  if (name === 'crawl') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }
    if (!deps.executeCrawl) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'crawl_not_configured' }) }], isError: true };
    }
    const res = await deps.executeCrawl({ args, principal });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status >= 400 ? { isError: true } : {}),
    };
  }

  if (name === 'search') {
    if (!scopes.includes('crawl:read') && !scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:read is required.' }], isError: true };
    }
    if (!deps.executeSearch) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'search_not_configured' }) }], isError: true };
    }
    const res = await deps.executeSearch({ args, principal });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status !== 200 ? { isError: true } : {}),
    };
  }

  if (name === 'jobs') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }
    if (!deps.executeJobs) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'jobs_not_configured' }) }], isError: true };
    }
    const res = await deps.executeJobs({ args, principal });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status !== 200 ? { isError: true } : {}),
    };
  }

  if (name === 'find_extractors') {
    if (!scopes.includes('crawl:read') && !scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:read is required.' }], isError: true };
    }
    if (!deps.findExtractors) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'extractors_not_configured' }) }], isError: true };
    }
    const q = typeof args.query === 'string' ? args.query : '';
    const cat = typeof args.category === 'string' ? args.category : undefined;
    const lim = typeof args.limit === 'number' ? args.limit : 10;
    const matches = deps.findExtractors({ query: q, ...(cat ? { category: cat } : {}), limit: lim });
    return {
      content: [{ type: 'text', text: JSON.stringify({ ok: true, count: matches.length, matches }, null, 2) }],
    };
  }

  if (name === 'agent') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }
    if (!deps.executeAgent) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'agent_not_configured' }) }], isError: true };
    }
    const res = await deps.executeAgent({ args, principal });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status >= 400 ? { isError: true } : {}),
    };
  }

  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}

async function handleToolCall(
  name: string,
  args: Record<string, unknown>,
  scopes: string[],
  principal: string,
  deps: McpServerDeps,
): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
  try {
    return await handleToolCallInner(name, args, scopes, principal, deps);
  } catch (err) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            ok: false,
            error: 'tool_execution_error',
            message: err instanceof Error ? err.message : 'Unexpected tool execution failure',
          }),
        },
      ],
      isError: true,
    };
  }
}

async function dispatchRpcMessage(
  msg: JsonRpcRequest,
  scopes: string[],
  principal: string,
  userAgent: string,
  deps: McpServerDeps,
  isModern = false,
): Promise<{ body: Record<string, unknown>; status?: number } | null> {
  const isNotification = msg.id === undefined;
  const id = msg.id ?? null;

  if (msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return { body: jsonRpcError(id, -32600, 'Invalid JSON-RPC 2.0 request') };
  }

  if (isNotification || msg.method.startsWith('notifications/')) {
    return null;
  }

  const startedAt = Date.now();
  const authType = principal === 'owner_token' || principal === 'mcp_token' ? ('bearer_token' as const) : ('oauth' as const);
  const methodLabel =
    msg.method === 'tools/call' && typeof msg.params?.name === 'string'
      ? `tools/call:${msg.params.name}`
      : msg.method;

  const runActivity = (p: void | Promise<unknown> | undefined): Promise<void> => {
    if (!p || typeof (p as Promise<unknown>).then !== 'function') return Promise.resolve();
    const safe = (p as Promise<unknown>).catch(() => undefined).then(() => undefined);
    if (deps.scheduleBackground) {
      deps.scheduleBackground(safe);
      return Promise.resolve();
    }
    return safe;
  };

  const finishMcpTurn = async (event?: HubEventInput): Promise<void> => {
    if (!deps.activity) return;
    if (deps.activity.recordMcpTurn) {
      await runActivity(
        deps.activity.recordMcpTurn({
          principal,
          authType,
          userAgent,
          method: methodLabel,
          now: startedAt,
          ...(event ? { event } : {}),
        }),
      );
      return;
    }
    await runActivity(
      deps.activity.recordMcpCall({
        principal,
        authType,
        userAgent,
        method: methodLabel,
        now: startedAt,
      }),
    );
    if (event) {
      await runActivity(deps.activity.recordEvent(event));
    }
  };

  const modernMeta = isModern
    ? {
        resultType: 'complete' as const,
        _meta: {
          'io.modelcontextprotocol/serverInfo': { name: deps.serverName, version: deps.serverVersion },
        },
      }
    : {};

  switch (msg.method) {
    case 'server/discover': {
      await finishMcpTurn();
      return {
        body: jsonRpcResult(id, {
          resultType: 'complete',
          supportedVersions: [...SUPPORTED_PROTOCOL_VERSIONS],
          capabilities: { tools: { listChanged: false } },
          _meta: {
            'io.modelcontextprotocol/serverInfo': { name: deps.serverName, version: deps.serverVersion },
          },
          instructions: MCP_INSTRUCTIONS,
          ttlMs: 3_600_000,
          cacheScope: 'private',
        }),
      };
    }
    case 'initialize': {
      const clientProto = typeof msg.params?.protocolVersion === 'string' ? msg.params.protocolVersion : '';
      const clientInfo = (msg.params?.clientInfo ?? {}) as { name?: string; version?: string };
      const protocolVersion = (LEGACY_PROTOCOL_VERSIONS as readonly string[]).includes(clientProto)
        ? clientProto
        : DEFAULT_PROTOCOL_VERSION;
      await finishMcpTurn({
        level: 'info',
        category: 'mcp',
        event: 'mcp_initialize',
        summary: `MCP initialize from ${principal} (${clientInfo.name ?? userAgent}, proto ${protocolVersion})`,
        details: sanitizeDetails({ principal, authType, clientName: clientInfo.name ?? '', protocolVersion, userAgent }),
      });
      return {
        body: jsonRpcResult(id, {
          protocolVersion,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: deps.serverName, version: deps.serverVersion },
          instructions: MCP_INSTRUCTIONS,
        }),
      };
    }
    case 'ping':
    case 'logging/setLevel':
      await finishMcpTurn();
      return { body: jsonRpcResult(id, { ...modernMeta }) };
    case 'resources/list':
      await finishMcpTurn();
      return { body: jsonRpcResult(id, { ...modernMeta, resources: [] }) };
    case 'resources/templates/list':
      await finishMcpTurn();
      return { body: jsonRpcResult(id, { ...modernMeta, resourceTemplates: [] }) };
    case 'prompts/list':
      await finishMcpTurn();
      return { body: jsonRpcResult(id, { ...modernMeta, prompts: [] }) };
    case 'tools/list':
      await finishMcpTurn({
        level: 'info',
        category: 'mcp',
        event: 'mcp_tools_list',
        summary: `MCP tools/list queried by ${principal}`,
        details: { principal, authType, userAgent },
      });
      return {
        body: jsonRpcResult(id, {
          ...modernMeta,
          tools: buildToolDefinitions(deps),
          ...(isModern ? { ttlMs: 300_000, cacheScope: 'private' as const } : {}),
        }),
      };
    case 'tools/call': {
      const toolName = typeof msg.params?.name === 'string' ? msg.params.name : '';
      const rawArgs =
        msg.params?.arguments && typeof msg.params.arguments === 'object' && !Array.isArray(msg.params.arguments)
          ? (msg.params.arguments as Record<string, unknown>)
          : {};
      if (!toolName) {
        await finishMcpTurn();
        return { body: jsonRpcError(id, -32602, 'Missing tool name') };
      }
      const out = await handleToolCall(toolName, rawArgs, scopes, principal, deps);
      const safeLogArgs: Record<string, unknown> = {};
      if (typeof rawArgs.url === 'string') safeLogArgs.url = redactUrlForLog(rawArgs.url);
      if (Array.isArray(rawArgs.urls)) {
        safeLogArgs.urlCount = rawArgs.urls.length;
        safeLogArgs.urls = rawArgs.urls.slice(0, 5).map((u) => (typeof u === 'string' ? redactUrlForLog(u) : ''));
      }
      if (typeof rawArgs.kind === 'string') safeLogArgs.kind = rawArgs.kind;
      if (typeof rawArgs.target === 'string') safeLogArgs.target = rawArgs.target;
      if (typeof rawArgs.site === 'string') safeLogArgs.site = rawArgs.site;
      await finishMcpTurn({
        level: out.isError ? 'warn' : 'info',
        category: 'mcp',
        event: 'mcp_tool_call',
        summary: `MCP ${toolName} called by ${principal} (${Date.now() - startedAt}ms)`,
        details: sanitizeDetails({ principal, authType, toolName, args: safeLogArgs, durationMs: Date.now() - startedAt, isError: Boolean(out.isError) }),
      });
      return { body: jsonRpcResult(id, { ...modernMeta, ...out }) };
    }
    default:
      await finishMcpTurn();
      return {
        body: jsonRpcError(id, -32601, `Method not found: ${msg.method}`),
        ...(isModern ? { status: 404 } : {}),
      };
  }
}

/**
 * Validates MCP `2026-07-28` Streamable HTTP request metadata & header-body consistency (`SEP-2243` & `SEP-2575`)
 * when a modern request is detected, while allowing legacy (`<= 2025-11-25`) requests to pass unchanged.
 */
function validateRequestEra(
  request: Request,
  msg: JsonRpcRequest,
):
  | { ok: true; isModern: boolean; negotiatedVersion: string }
  | { ok: false; status: number; body: Record<string, unknown> } {
  const id = msg.id ?? null;
  const meta =
    msg.params && typeof msg.params._meta === 'object' && msg.params._meta !== null && !Array.isArray(msg.params._meta)
      ? (msg.params._meta as Record<string, unknown>)
      : null;
  const metaVersion = typeof meta?.['io.modelcontextprotocol/protocolVersion'] === 'string'
    ? (meta['io.modelcontextprotocol/protocolVersion'] as string)
    : null;
  const headerVersion = request.headers.get('mcp-protocol-version');

  const isLegacyHeader = headerVersion !== null && (LEGACY_PROTOCOL_VERSIONS as readonly string[]).includes(headerVersion);
  const entersModernValidation =
    metaVersion !== null ||
    msg.method === 'server/discover' ||
    (headerVersion !== null && !isLegacyHeader && msg.method !== 'initialize');

  if (!entersModernValidation) {
    return {
      ok: true,
      isModern: false,
      negotiatedVersion: isLegacyHeader ? headerVersion! : DEFAULT_PROTOCOL_VERSION,
    };
  }

  // `server/discover` without `_meta` or headers may still be probed leniently if neither is supplied,
  // but if HTTP headers/meta ARE supplied on HTTP transport, enforce SEP-2243 consistency.
  const effectiveVersion = metaVersion ?? headerVersion ?? '2026-07-28';
  if (metaVersion !== null || headerVersion !== null) {
    if (!headerVersion || (metaVersion !== null && headerVersion !== metaVersion)) {
      return {
        ok: false,
        status: 400,
        body: jsonRpcError(id, -32020, 'Header mismatch: MCP-Protocol-Version header must be present and match _meta protocolVersion'),
      };
    }
  }

  if (!(SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(effectiveVersion)) {
    return {
      ok: false,
      status: 400,
      body: jsonRpcError(id, -32022, 'Unsupported protocol version', {
        supported: [...SUPPORTED_PROTOCOL_VERSIONS],
        requested: effectiveVersion,
      }),
    };
  }

  const isModern = effectiveVersion === '2026-07-28';
  if (isModern && (metaVersion !== null || headerVersion === '2026-07-28')) {
    const mcpMethod = request.headers.get('mcp-method');
    if (!mcpMethod || mcpMethod !== msg.method) {
      return {
        ok: false,
        status: 400,
        body: jsonRpcError(id, -32020, `Header mismatch: Mcp-Method header must match body method '${msg.method ?? ''}'`),
      };
    }
    if (msg.method === 'tools/call') {
      const rawMcpName = request.headers.get('mcp-name');
      const bodyName = typeof msg.params?.name === 'string' ? msg.params.name : '';
      if (!rawMcpName) {
        return {
          ok: false,
          status: 400,
          body: jsonRpcError(id, -32020, 'Header mismatch: Mcp-Name header is required for tools/call'),
        };
      }
      const decoded = decodeMcpHeaderValue(rawMcpName);
      if (!decoded.ok || decoded.value !== bodyName) {
        return {
          ok: false,
          status: 400,
          body: jsonRpcError(id, -32020, 'Header mismatch: Mcp-Name header does not match params.name'),
        };
      }
    }
  }

  return { ok: true, isModern, negotiatedVersion: effectiveVersion };
}

export async function handleMcpRequest(request: Request, url: URL, deps: McpServerDeps): Promise<Response> {
  const origin = url.origin;
  const resolvedDeps: McpServerDeps = deps.selfHost ? deps : { ...deps, selfHost: url.hostname };
  if (!isAllowedMcpOrigin(request.headers.get('origin'), origin, resolvedDeps.allowedOrigins)) {
    return Response.json({ error: 'forbidden_origin' }, { status: 403 });
  }

  const cors = mcpCorsHeaders(request, origin, resolvedDeps.allowedOrigins);
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  const auth = await authorizeMcpRequest({
    request,
    origin,
    ownerSecret: resolvedDeps.ownerSecret,
    mcpToken: resolvedDeps.mcpToken,
    store: resolvedDeps.oauthStore,
  });
  if (!auth.ok) {
    return Response.json(
      { error: 'unauthorized', message: 'OAuth 2.1 or Bearer token required' },
      {
        status: auth.status,
        headers: {
          'cache-control': 'no-store',
          'www-authenticate': auth.wwwAuthenticate,
          ...cors,
        },
      },
    );
  }

  if (request.method === 'DELETE') {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method === 'GET') {
    // Per MCP Streamable HTTP stateless specification: return 405 when standalone GET SSE is unused.
    return new Response(null, { status: 405, headers: { allow: 'POST, DELETE, OPTIONS', ...cors } });
  }
  if (request.method !== 'POST') {
    return Response.json({ error: 'method_not_allowed' }, { status: 405, headers: cors });
  }

  const rawText = await request.text();
  if (rawText.length > MAX_MCP_REQUEST_BYTES) {
    return Response.json(jsonRpcError(null, -32600, 'MCP payload exceeds 256 KiB'), { status: 413, headers: cors });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return Response.json(jsonRpcError(null, -32700, 'Parse error'), { status: 400, headers: cors });
  }

  const userAgent = request.headers.get('user-agent') ?? 'mcp-client';

  if (Array.isArray(parsed)) {
    if (parsed.length === 0 || parsed.length > 20) {
      return Response.json(jsonRpcError(null, -32600, 'Invalid batch length'), { status: 400, headers: cors });
    }
    const replies: Array<Record<string, unknown>> = [];
    for (const item of parsed) {
      const out = await dispatchRpcMessage((item ?? {}) as JsonRpcRequest, auth.scopes, auth.principal, userAgent, resolvedDeps, false);
      if (out) replies.push(out.body);
    }
    if (replies.length === 0) return new Response(null, { status: 202, headers: cors });
    return Response.json(replies, {
      status: 200,
      headers: { 'cache-control': 'no-store', 'mcp-protocol-version': DEFAULT_PROTOCOL_VERSION, ...cors },
    });
  }

  const msg = (parsed ?? {}) as JsonRpcRequest;
  const era = validateRequestEra(request, msg);
  if (!era.ok) {
    return Response.json(era.body, {
      status: era.status,
      headers: { 'cache-control': 'no-store', ...cors },
    });
  }

  // RFC 6750 §3.1 + MCP 2026-07-28 Step-Up Authorization: challenge insufficient OAuth scopes with 403 + WWW-Authenticate.
  if (msg.method === 'tools/call' && typeof msg.params?.name === 'string') {
    const needed = requiredScopeForTool(msg.params.name);
    if (!hasRequiredToolScope(auth.scopes, needed) && needed) {
      const wwwAuth = `Bearer error="insufficient_scope", scope="${needed}", resource_metadata="${origin}/.well-known/oauth-protected-resource", error_description="OAuth scope ${needed} is required for ${msg.params.name}"`;
      return Response.json(jsonRpcError(msg.id ?? null, -32001, `Insufficient OAuth scope: ${needed} is required.`), {
        status: 403,
        headers: {
          'cache-control': 'no-store',
          'www-authenticate': wwwAuth,
          ...cors,
        },
      });
    }
  }

  const single = await dispatchRpcMessage(msg, auth.scopes, auth.principal, userAgent, resolvedDeps, era.isModern);
  if (!single) {
    return new Response(null, { status: 202, headers: cors });
  }
  return Response.json(single.body, {
    status: single.status ?? 200,
    headers: { 'cache-control': 'no-store', 'mcp-protocol-version': era.negotiatedVersion, ...cors },
  });
}
