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
import { filterSafeResponseHeaders } from './framework-detect';
import { analyzeUrlRedirect, buildBlockedInfo } from './jobs';
import { authorizeMcpRequest, isTrustedMcpBrowserOrigin, type OAuthStore } from './oauth';
import { formatFenceSafeUntrustedMcpEnvelope, sanitizeConnectorStructuredValue } from './mcp-federation';
import { parseAllowedMcpTools, resolveCallerUserId } from './mcp-vault';
import { getActiveRequestTracer, type RequestTracer } from './otel';
import {
  DNS_NOT_FOUND_MESSAGE,
  isDnsNotFoundError,
  isSchemeDowngradeError,
  isSsrfBlockedError,
  SCHEME_DOWNGRADE_BLOCKED_INFO,
  scrubResolverIpFromError,
  SSRF_BLOCKED_INFO,
  validatePublicHttpsTargetUrl,
  type TargetUrlRejectionReason,
} from './overflow';
import { readBodyTextCapped } from './safe-input';
import { classifyWafAndChallenge, refineBlockedInfo } from './waf';
import { checkAndRecordWikipediaArticleQuota, parseWikipediaArticleUrl } from './wikipedia';

const SUPPORTED_PROTOCOL_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'] as const;
const LEGACY_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'] as const;
const DEFAULT_PROTOCOL_VERSION = '2025-03-26';
const MCP_INSTRUCTIONS =
  'Choose the right tool for the task: (1) Use scrape to read a single web page, article, documentation page, PDF, or RSS/Atom feed as clean Markdown with metadata. (2) Use extract to retrieve query-ranked passages across 1 to 20 URLs at once. (3) Use search for open-web, news (topic="news"), and indexed collection discovery. (4) Use interact when a page requires live browser actions (click, fill, press, scroll, screenshots, or video transcripts). (5) Use fetch_url or fetch_batch ONLY for raw unparsed HTTP bytes and response headers on JSON/XML APIs or raw text files — never for HTML articles or web pages. (6) Use map to list a site\'s URLs, crawl for multi-page site indexing, search_collection to query saved collections, read_artifact to page through large stored outputs, jobs for structured job-board search and verification, catalog for full Shopify/WooCommerce product catalogs, find_extractors to look up built-in site/API adapters, agent for multi-step LLM-guided research and semantic JSON-Schema extraction, discover_mcps / query_mcp for federated MCP servers, and list_agents for crawler node health.';
const MAX_MCP_REQUEST_BYTES = 256 * 1024;
const MAX_BODY_PREVIEW_CHARS = 64 * 1024;
const DEFAULT_MCP_SCRAPE_MAX_CHARS = 100_000;
const DEFAULT_BATCH_PREVIEW_CHARS = 3 * 1024;
const MAX_BATCH_URLS = 25;

/** The Accept values a `kind: "text"` or `kind: "page"` request may carry. */
export const TEXT_ACCEPTS = [
  'text/html',
  'text/markdown',
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
  if (/\.(rss)$/.test(pathname) || /\/(?:rss|feed|feeds)(?:\/|$)/.test(pathname)) return 'application/rss+xml';
  if (/\.(atom)$/.test(pathname) || /\/atom(?:\/|$)/.test(pathname)) return 'application/atom+xml';
  if (/\.(json|webmanifest|jsonl|ndjson|ipynb)$/.test(pathname) || /(?:^|\/)api(?:\/|$)/.test(pathname)) return 'application/json';
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
    /\.(xml|xml\.gz|rss|atom|ics)$/.test(pathname) ||
    RAW_TEXT_FILE_EXT_RE.test(pathname) ||
    /\/(?:dockerfile|makefile)$/.test(pathname) ||
    /\/(?:rss|feed|feeds|atom)(?:\/|$)/.test(pathname) ||
    pathname.includes('sitemap')
  ) {
    return 'text';
  }
  if (
    /\.(json|webmanifest|jsonl|ndjson|ipynb)$/.test(pathname) ||
    pathname.startsWith('/.well-known/') ||
    (!/\.(?:html?|xhtml|php|asp|aspx)$/.test(pathname) && /(?:^|\/)api(?:\/|$)/.test(pathname)) ||
    host === 'registry.npmjs.org' ||
    host === 'api.github.com' ||
    (host === 'pypi.org' && /\/json\/?$/.test(pathname))
  ) {
    return 'json';
  }
  if (
    host === 'raw.githubusercontent.com' ||
    host === 'gist.githubusercontent.com' ||
    pathname.includes('/-/raw/')
  ) {
    return 'text';
  }
  return 'page';
}

export const inferRequestKind = inferKindForUrl;

/** The Accept to send with one request, or an error for one the crawlers would refuse. */
export function textAcceptFor(kind: string, url: string, requested: unknown): { ok: true; accept?: string } | { ok: false; error: string } {
  if (kind === 'text') {
    if (requested === undefined || requested === null || requested === '') return { ok: true, accept: defaultTextAccept(url) };
    if (typeof requested === 'string' && (TEXT_ACCEPTS as readonly string[]).includes(requested)) return { ok: true, accept: requested };
    return { ok: false, error: `accept must be one of ${TEXT_ACCEPTS.join(', ')}` };
  }
  if (kind === 'page') {
    if (requested === undefined || requested === null || requested === '') return { ok: true };
    if (typeof requested === 'string' && (TEXT_ACCEPTS as readonly string[]).includes(requested)) return { ok: true, accept: requested };
    return { ok: false, error: `accept must be one of ${TEXT_ACCEPTS.join(', ')}` };
  }
  return { ok: true };
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
    /** false: store artifacts but don't hydrate bodies back from R2 into the reply (caller set includeBody: false). */
    hydrateInline?: boolean;
  }) => Promise<McpExecuteFetchResult>;
  readArtifact?: (params: {
    blobSha256: string;
    retention?: 'transient' | 'stored';
    format?: 'raw' | 'markdown';
    visibility?: 'public' | 'private';
    offset?: number;
    limit?: number;
    userId?: string;
  }) => Promise<{ ok: true; page: Record<string, unknown> } | { ok: false; status: number; via?: string; error: string; message?: string }>;
  executeScrape?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeExtract?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeInteract?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeMap?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeCrawl?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeSearch?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeJobs?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeCatalog?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeAgent?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  discoverMcps?: (params: {
    query?: string;
    remoteOnly?: boolean;
    limit?: number;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeQueryMcp?: (params: {
    args: Record<string, unknown>;
    principal?: string;
    userId?: string;
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
    userId?: string;
  }) => Promise<{ ok: true; hits: Array<Record<string, unknown>> } | { ok: false; status: number; error: string }>;
  scheduleBackground?: (promise: Promise<unknown>) => void;
  tracer?: RequestTracer;
  allowedOrigins?: readonly string[];
  selfHost?: string;
}

export type McpHandlerOptions = McpServerDeps;

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
    toolName === 'find_extractors' ||
    toolName === 'discover_mcps' ||
    toolName === 'query_mcp'
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
    toolName === 'catalog' ||
    toolName === 'agent'
  ) {
    return 'crawl:fetch';
  }
  return null;
}

function hasRequiredToolScope(scopes: string[], needed: 'crawl:read' | 'crawl:fetch' | null): boolean {
  if (!needed) return true;
  if (needed === 'crawl:read') {
    return scopes.includes('crawl:read') || scopes.includes('crawl:fetch') || scopes.includes('mcp:call');
  }
  return scopes.includes('crawl:fetch');
}

function validatePublicHttpsUrl(
  raw: unknown,
  selfHost?: string,
): { ok: true; url: string } | { ok: false; reason: TargetUrlRejectionReason; error: string } {
  const res = validatePublicHttpsTargetUrl(raw, selfHost);
  return res.ok ? { ok: true, url: res.normalized } : { ok: false, reason: res.reason, error: res.message };
}

/**
 * Strips private/residential HAOS WAN IPs (`publicIp`) and internal LAN socket tuples in `lastError` before returning
 * `list_agents` over the public `/mcp` surface (preserving private origin shielding while keeping `/admin` diagnostics).
 */
export function sanitizeFleetForMcp(fleet: {
  connected: number;
  trackerListVersion?: string | null;
  agents: AgentAttachment[];
  affinities: AffinityPin[];
}): {
  connected: number;
  trackerListVersion: string | null;
  agents: Array<Omit<AgentAttachment, 'publicIp'> & Record<string, unknown>>;
  affinities: Array<{ siteId: string; expiresAt: number }>;
  activeCooldownCount: number;
} {
  const safeAffinities = (fleet.affinities ?? []).map(({ siteId, expiresAt }) => ({ siteId, expiresAt }));
  return {
    connected: fleet.connected,
    trackerListVersion: typeof fleet.trackerListVersion === 'string' ? fleet.trackerListVersion : null,
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
      if (
        rest.browserSandbox === 'off' &&
        Array.isArray(rest.capabilities) &&
        rest.capabilities.includes('browser-v1')
      ) {
        rest.browserConfinement = 'container-mac+loopback-proxy';
      }
      return rest as Omit<AgentAttachment, 'publicIp'> & Record<string, unknown>;
    }),
    affinities: safeAffinities,
    activeCooldownCount: safeAffinities.length,
  };
}

export const DEFAULT_ALLOWED_TARGETS: readonly FetchTarget[] = ['auto', 'agent', 'container'];

export interface CanonicalMcpToolSchema {
  type: 'object';
  properties: Record<string, Record<string, unknown>>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface CanonicalMcpToolDefinition {
  name: string;
  description: string;
  annotations: {
    title: string;
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
  inputSchema: CanonicalMcpToolSchema;
}

/**
 * Canonical single-source-of-truth definitions for all 17 EdgeFetch MCP tools.
 * Shared directly by `POST /mcp` (`tools/list`) and `GET /openapi.json` (`hub/src/openapi.ts`) so schemas never drift.
 */
export function buildCanonicalMcpToolSchemas(options?: {
  allowedTargets?: readonly FetchTarget[];
  defaultTarget?: FetchTarget;
}): CanonicalMcpToolDefinition[] {
  const allowedTargets = [...(options?.allowedTargets ?? DEFAULT_ALLOWED_TARGETS)];
  const defaultTarget = options?.defaultTarget ?? 'auto';
  return [
    {
      name: 'list_agents',
      description:
        'Returns connected crawler worker nodes, their capabilities (HTTP vs headless browser and PDF support), CPU architectures, job counts, and active host routing pins.',
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
        'Fetches a single public HTTPS URL and returns raw, unparsed HTTP body bytes, status code, safe response headers, and timing. Use this ONLY for JSON/XML APIs, raw data files, or HTTP header inspection — NEVER for HTML web pages or articles (use scrape for 1 page or extract for multiple pages instead).',
      annotations: {
        title: 'Low-Level Raw HTTP Fetch (APIs/XML/Headers — Use scrape for Web Pages)',
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
              'Optional response kind ("json" for JSON APIs, "text" for XML/RSS/Markdown/plain text, "feed" for product JSON feeds, "page" for raw HTML). Omit to auto-detect from URL.',
          },
          accept: {
            type: 'string',
            enum: [...TEXT_ACCEPTS],
            description:
              'Optional Accept header media type override (defaults automatically based on the URL when omitted).',
          },
          target: {
            type: 'string',
            enum: allowedTargets,
            default: defaultTarget,
            description:
              'Execution route ("auto" uses connected crawler nodes first with automatic overflow, "agent" forces a connected node, "container" forces cloud overflow).',
          },
          site: {
            type: 'string',
            description: 'Optional worker site ID to pin when target="agent".',
          },
          respectRobots: { type: 'boolean', default: true, description: 'Respect /robots.txt Allow, Disallow, and Crawl-delay rules.' },
          robots: { type: 'boolean', description: 'Deprecated alias for respectRobots.' },
          includeBody: { type: 'boolean', default: true, description: 'Include the response body preview in tool output.' },
          maxBytes: {
            type: 'integer',
            minimum: 256,
            maximum: 16777216,
            description:
              'Maximum inline preview size in characters/bytes (256..16777216). Larger bodies return an artifactId readable via read_artifact.',
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
        'Fetches 1 to 25 public HTTPS URLs in one polite batch and returns per-URL HTTP status, outcome ("ok", "not_found" for 404, "gone" for 410, "dns_not_found", "blocked", or "rate_limited"), headers, and optional raw body previews. Use this for batch API/feed/status checks; prefer extract when you want clean readable passages from web pages.',
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
            description: 'Optional kind applied to every URL; omit to auto-detect per URL.',
          },
          accept: {
            type: 'string',
            enum: [...TEXT_ACCEPTS],
            description: 'Optional Accept media type for text requests; omit to infer per URL.',
          },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional worker site ID when target="agent".' },
          pauseMs: { type: 'integer', minimum: 0, maximum: 30000, default: 1000, description: 'Minimum per-host pause in milliseconds.' },
          pauseJitterMs: { type: 'integer', minimum: 0, maximum: 15000, default: 500, description: 'Random positive jitter in milliseconds added to pauseMs.' },
          respectRobots: { type: 'boolean', default: true },
          robots: { type: 'boolean', description: 'Deprecated alias for respectRobots.' },
          includeBody: {
            type: 'boolean',
            default: false,
            description:
              'Set true to include truncated raw body previews per URL. Either way each successful result carries an artifactId for read_artifact.',
          },
          previewBytes: {
            type: 'integer',
            minimum: 256,
            maximum: 65536,
            default: DEFAULT_BATCH_PREVIEW_CHARS,
            description: 'Maximum inline body preview characters per URL when includeBody=true (default 3072; full body can be paged via read_artifact).',
          },
        },
        required: ['urls'],
        additionalProperties: false,
      },
    },
    {
      name: 'scrape',
      description:
        'Reads a single public HTTPS web page, PDF, RSS/Atom feed, OpenAPI spec, or Jupyter notebook and returns clean main-content Markdown plus structured metadata (title, wordCount, favicon, canonicalUrl, contentType, links, and images). Prefer scrape for reading 1 URL, extract for query-focused passages across multiple URLs, and interact when clicking or typing in a browser is required.',
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
                    prompt: { type: 'string', description: 'Optional extraction instruction when type="json" (requires an LLM provider).' },
                    schema: {
                      type: 'object',
                      description:
                        'Optional JSON Schema object when type="json". Without an LLM configured, schema extraction is structural/heuristic (matching JSON-LD, headings, definition lists, and key-value lines, setting unmatched fields to null); use the agent tool for semantic LLM extraction.',
                    },
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
            description:
              'Desired output formats (e.g. ["markdown", "links"] or [{ type: "json", schema }]). Note: keyless { type: "json", schema } extraction is structural/heuristic; prefer agent for semantic extraction.',
          },
          renderMode: {
            type: 'string',
            enum: ['off', 'auto', 'always', 'browser'],
            default: 'auto',
            description:
              '"auto" (default) fetches static HTML first and only launches a headless browser on thin JavaScript-driven pages; "off" never uses a browser; "always" or "browser" forces headless browser rendering.',
          },
          waitForMs: { type: 'integer', minimum: 0, maximum: 15000, description: 'Extra JavaScript settle wait in milliseconds when rendering in a browser.' },
          waitSelector: { type: 'string', description: 'Optional CSS selector to wait for when rendering in a browser.' },
          maxPages: { type: 'integer', minimum: 1, maximum: 500, description: 'Maximum PDF pages to extract.' },
          ocr: {
            type: 'string',
            enum: ['auto', 'always', 'off'],
            default: 'auto',
            description: 'PDF OCR mode: "auto" runs OCR only on scanned/image-only PDFs; "always" forces OCR; "off" disables OCR.',
          },
          onlyMainContent: { type: 'boolean', default: true, description: 'Strip navigation, footer, and sidebar chrome to keep primary article content.' },
          includeTags: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional HTML tag, #id, or .class selectors (e.g. ["article", "#content"]) to keep exclusively. Heading-only matches automatically expand to include their section prose.',
          },
          excludeTags: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional HTML tag, #id, or .class selectors (e.g. [".comments", "aside"]) to remove before Markdown conversion.',
          },
          includeImages: {
            type: 'boolean',
            default: true,
            description: 'Include content images >=100px (set false to omit inline image links).',
          },
          maxChars: {
            type: 'integer',
            minimum: 500,
            maximum: 500000,
            description:
              'Maximum Markdown characters returned inline (default 100000 on MCP; truncates cleanly and returns markdownArtifactId + nextOffset for paging via read_artifact).',
          },
          discoverLlmsTxt: { type: 'boolean', default: true, description: 'Check /llms.txt and prefer publisher-provided companion .md files when available.' },
          preferOriginMarkdown: {
            type: 'boolean',
            default: true,
            description: 'Set false to request text/html instead of text/markdown from servers that negotiate Markdown directly.',
          },
          maxAgeMs: { type: 'integer', minimum: 0, default: 0, description: 'Return a cached scrape result if fetched with the same options within maxAgeMs milliseconds.' },
          redactPii: { type: 'boolean', default: false, description: 'Redact email addresses, phone numbers, and US SSNs from extracted text.' },
          checkPromptInjection: {
            type: 'boolean',
            default: false,
            description: 'When true, rejects pages containing prompt-injection override directives with HTTP 403.',
          },
          mobile: { type: 'boolean', default: false, description: 'Emulate a 390x844 mobile viewport in headless browser mode.' },
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
            description: 'Optional browser actions to run before scraping (wait, click, write, fill, press, scroll, screenshot, scrape, executeJavascript, pdf).',
            items: { type: 'object' },
          },
          parsers: {
            type: 'array',
            description: 'Optional PDF parser controls (e.g. [{ type: "pdf", mode: "auto", pages: true, pageMarkers: true }] or [] for raw base64).',
            items: { anyOf: [{ type: 'string' }, { type: 'object' }] },
          },
          query: { type: 'string', description: 'Optional focus query to surface only the most relevant passages.' },
          jsonFilter: {
            type: 'string',
            description: 'Optional filter for JSON array responses (e.g. `title~"Engineer"` or `id=abc123`), emitting one chunk per matching record.',
          },
          collectionId: { type: 'string', description: 'Optional collection ID to index the extracted Markdown into for search_collection.' },
          visibility: {
            type: 'string',
            enum: ['public', 'private'],
            default: 'public',
            description: 'Cache and storage visibility ("private" isolates cached content to the current authenticated user).',
          },
          waybackFallback: {
            type: 'boolean',
            default: false,
            description:
              'Opt-in Internet Archive Wayback Machine fallback strictly on 5xx errors or unreachable hosts (never used on robots.txt blocks, 401/403/429, or bot challenges).',
          },
          spaFallback: {
            type: 'string',
            enum: ['auto', 'off', 'crawl4ai', 'firecrawl'],
            default: 'auto',
            description:
              'Optional external SPA renderer fallback when configured on the server (never used on robots.txt blocks, 403/429, or bot challenges).',
          },
          blockTrackers: {
            type: 'boolean',
            default: true,
            description:
              'Abort third-party tracking subresources during headless Chromium renders using the Hub EasyPrivacy host list (default true when loaded; set false to disable for this request only).',
          },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional worker site ID when target="agent".' },
        },
        required: ['url'],
        additionalProperties: false,
      },
    },
    {
      name: 'extract',
      description:
        'Extracts clean, query-ranked Markdown passages across 1 to 20 public HTTPS URLs in one batch. Returns top matching chunks per URL (or noRelevantMatch: true with empty chunks when zero query terms appear on a page). Prefer extract for multi-URL question answering and scrape for reading one full page.',
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
            description: '1 to 20 public https:// URLs to extract passages from.',
          },
          query: {
            type: 'string',
            description:
              'Keyword or question used to rank the most relevant passages per URL (heuristic BM25 keyword ranking; returns noRelevantMatch: true when zero query terms match).',
          },
          jsonFilter: {
            type: 'string',
            description: 'Optional filter for JSON array responses (e.g. `title~"Engineer"` or `id=abc123`), emitting one chunk per matching record.',
          },
          renderMode: {
            type: 'string',
            enum: ['off', 'auto', 'always', 'browser'],
            default: 'auto',
            description: '"auto" (default) renders thin JavaScript-driven pages in a headless browser; "off" disables browser rendering; "always" forces it.',
          },
          chunksPerSource: { type: 'integer', minimum: 1, maximum: 10, default: 3, description: 'Maximum ranked chunks returned per URL.' },
          includeRawContent: {
            type: 'boolean',
            default: false,
            description: 'Set true to also include combined Markdown in rawContent on each result (omitted by default to avoid duplicating chunk text).',
          },
          maxAgeMs: { type: 'integer', minimum: 0, default: 0, description: 'Reuse cached Markdown if fetched within maxAgeMs milliseconds.' },
          redactPii: { type: 'boolean', default: false, description: 'Redact email addresses, phone numbers, and US SSNs.' },
          collectionId: { type: 'string', description: 'Optional collection ID to index extracted pages into for search_collection.' },
          visibility: {
            type: 'string',
            enum: ['public', 'private'],
            default: 'public',
            description: 'Cache and index isolation mode ("private" isolates data to the authenticated user).',
          },
          waybackFallback: {
            type: 'boolean',
            default: false,
            description:
              'Opt-in Internet Archive Wayback Machine fallback strictly on 5xx errors or unreachable hosts (never used on robots.txt blocks, 401/403/429, or bot challenges).',
          },
          spaFallback: {
            type: 'string',
            enum: ['auto', 'off', 'crawl4ai', 'firecrawl'],
            default: 'auto',
            description:
              'Optional external SPA renderer fallback when configured on the server (never used on robots.txt blocks, 403/429, or bot challenges).',
          },
          blockTrackers: {
            type: 'boolean',
            default: true,
            description:
              'Abort third-party tracking subresources during headless Chromium renders using the Hub EasyPrivacy host list (default true when loaded; set false to disable for this request only).',
          },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional worker site ID when target="agent".' },
        },
        required: ['urls'],
        additionalProperties: false,
      },
    },
    {
      name: 'map',
      description:
        'Discovers public URLs on a website using sitemaps, /llms.txt, and homepage links, returning a filtered list of links without scraping every page.',
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
          url: { type: 'string', description: 'Root public https:// URL of the site to map.' },
          search: { type: 'string', description: 'Optional keyword filter to rank and narrow discovered URLs.' },
          limit: { type: 'integer', minimum: 1, maximum: 5000, default: 500 },
          includeSubdomains: { type: 'boolean', default: false },
          includeOutsidePath: {
            type: 'boolean',
            default: false,
            description: 'When false (default), restricts discovered URLs to the root URL path prefix when url includes a subpath.',
          },
          ignoreSitemap: { type: 'boolean', default: false },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional worker site ID when target="agent".' },
        },
        required: ['url'],
        additionalProperties: false,
      },
    },
    {
      name: 'crawl',
      description:
        'Crawls multiple pages of a website breadth-first (respecting robots.txt and path filters) and indexes them into a searchable collection. Small crawls (limit <= 5) wait up to 25 seconds to return completed pages directly; larger or background crawls return a crawlId that you can poll or cancel by calling crawl with { crawlId }.',
      annotations: {
        title: 'Site Crawl (Run / Poll Status / Cancel)',
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Root public https:// URL to start crawling (omit when polling or cancelling an existing crawlId).' },
          crawlId: { type: 'string', description: 'Existing crawl ID (`crw_...`) to poll progress/results or cancel.' },
          cancel: { type: 'boolean', default: false, description: 'Set true with crawlId to cancel a running crawl.' },
          async: { type: 'boolean', description: 'Set true to run in the background immediately and return crawlId even when limit <= 5.' },
          limit: { type: 'integer', minimum: 1, maximum: 200, default: 25, description: 'Maximum pages to crawl (1..200).' },
          maxDepth: { type: 'integer', minimum: 0, maximum: 5, default: 2, description: 'Maximum link hop depth from the root URL.' },
          allowSubdomains: { type: 'boolean', default: false },
          includePaths: { type: 'array', items: { type: 'string' }, description: 'Optional path prefixes or regexes to include.' },
          excludePaths: { type: 'array', items: { type: 'string' }, description: 'Optional path prefixes or regexes to skip.' },
          collectionId: { type: 'string', description: 'Optional collection ID to index crawled pages into for search_collection.' },
          offset: { type: 'integer', minimum: 0, default: 0, description: 'Result offset when polling an existing crawlId.' },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'search',
      description:
        'Searches the web, news headlines (topic="news"), and optional indexed collections, returning ranked results with titles, URLs, snippets, and optional extracted page chunks when includeRawContent is true.',
      annotations: {
        title: 'Search Web & News',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description:
              'Search query (1..500 characters). Supports site:domain.com filtering (including site:<lang>.wikipedia.org or wikipedia=true for robots-compliant Wikipedia article discovery).',
          },
          maxResults: { type: 'integer', minimum: 1, maximum: 20, default: 5, description: 'Maximum search results to return (1..20).' },
          timeRange: { type: 'string', enum: ['day', 'week', 'month', 'year'], description: 'Optional recency filter.' },
          includeDomains: { type: 'array', items: { type: 'string' }, description: 'Restrict results to these domains.' },
          excludeDomains: { type: 'array', items: { type: 'string' }, description: 'Exclude results from these domains.' },
          includeRawContent: {
            type: 'boolean',
            default: false,
            description: 'When true, fetches the top result URLs and attaches ranked Markdown chunks.',
          },
          chunksPerSource: {
            type: 'integer',
            minimum: 1,
            maximum: 10,
            default: 3,
            description: 'Maximum Markdown chunks attached per result when includeRawContent is true.',
          },
          mode: {
            type: 'string',
            enum: ['waterfall', 'rrf', 'serper'],
            default: 'waterfall',
            description:
              'Provider strategy: "waterfall" (default) queries the primary search provider first and falls back only when results are sparse; "rrf" queries configured providers in parallel; "serper" uses only Serper.',
          },
          providers: {
            type: 'array',
            items: { type: 'string', enum: ['serper', 'brave', 'searxng', 'tavily'] },
            description: 'Optional allowlist of search providers to use.',
          },
          collectionId: { type: 'string', description: 'Optional indexed collection ID to merge into search results.' },
          noCache: { type: 'boolean', default: false, description: 'Set true to bypass cached search results and fetch fresh results.' },
        },
        required: ['query'],
        additionalProperties: true,
      },
    },
    {
      name: 'search_collection',
      description:
        'Searches pages previously indexed into a collection by scrape, extract, or crawl, returning BM25 relevance-scored chunks (with compact query excerpts on long passages and empty hits when no terms match).',
      annotations: {
        title: 'Search Indexed Collection',
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
            description: 'Target collection ID (e.g. "default" or a crawl ID `crw_...`).',
          },
          query: { type: 'string', description: 'Keyword query to match against indexed document chunks.' },
          limit: { type: 'integer', minimum: 1, maximum: 50, default: 10, description: 'Maximum matching chunks to return (1..50).' },
        },
        required: ['query'],
        additionalProperties: false,
      },
    },
    {
      name: 'interact',
      description:
        'Opens a page in a sandboxed headless browser and executes interactive steps (click, fill, type, press, select, scroll, wait, navigate), returning rendered Markdown, per-action URL/DOM change telemetry, warnings when clicks have no effect, optional screenshots, and a sessionId when keepSession is true.',
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
          url: { type: 'string', description: 'Initial public https:// URL (omit when resuming or closing an existing sessionId).' },
          sessionId: { type: 'string', description: 'Session token returned from a prior interact call with keepSession=true.' },
          keepSession: { type: 'boolean', default: false, description: 'Keep the isolated browser tab open for follow-up interact calls.' },
          closeSession: { type: 'boolean', default: false, description: 'Close an open browser session after this call.' },
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
          waitForMs: { type: 'integer', minimum: 0, maximum: 15000, description: 'Milliseconds to wait for page state to settle.' },
          waitSelector: { type: 'string', description: 'Optional CSS selector to wait for before extracting output.' },
          maxChars: {
            type: 'integer',
            minimum: 100,
            maximum: 500000,
            description: 'Maximum Markdown characters to return in this call (returns totalChars, remainingChars, and nextOffset when truncated).',
          },
          offset: {
            type: 'integer',
            minimum: 0,
            default: 0,
            description: 'Character offset into the rendered Markdown for paging large pages.',
          },
          blockTrackers: {
            type: 'boolean',
            default: true,
            description:
              'Abort third-party tracking subresources during headless Chromium renders using the Hub EasyPrivacy host list (default true when loaded; set false to disable for this request only).',
          },
          site: { type: 'string', description: 'Optional browser-capable worker site ID.' },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'read_artifact',
      description:
        'Reads a character slice of a stored response artifact by artifactId (either a 64-character hex SHA-256 from fetch_url/fetch_batch/scrape, or an `md:<sha256>` markdownArtifactId from scrape) using offset and limit paging.',
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
            description: '64-character hex SHA-256 artifact ID (from fetch_url/fetch_batch/scrape) OR `md:<sha256>` (markdownArtifactId from scrape).',
          },
          format: {
            type: 'string',
            enum: ['raw', 'markdown'],
            description: 'Optional output format ("raw" default for raw artifacts; "markdown" reads derived clean Markdown when available).',
          },
          retention: { type: 'string', enum: ['transient', 'stored'], description: 'Optional retention tier hint.' },
          offset: { type: 'integer', minimum: 0, default: 0, description: 'Character offset to start reading from.' },
          limit: { type: 'integer', minimum: 1, maximum: 262144, default: 65536, description: 'Maximum characters to return in this page.' },
        },
        required: ['artifactId'],
        additionalProperties: false,
      },
    },
    {
      name: 'jobs',
      description:
        'Searches official company job boards (Greenhouse, Ashby, Lever, Workday, Workable, Gem, Rippling, SmartRecruiters, company-domain career page discovery, and Built In) or batch-verifies saved job URLs, returning normalized compensation, workplaceType, locations, and posting status.',
      annotations: {
        title: 'Search & Verify Structured Job Postings',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Role or keyword query (e.g. "Forward Deployed Engineer", "Solutions Architect").' },
          company: { type: 'string', description: 'Optional company name or job-board organization slug.' },
          domains: {
            type: 'array',
            items: { type: 'string' },
            maxItems: 10,
            description:
              'Optional company domains (e.g. ["cloudflare.com", "stripe.com"]) to probe /careers and /jobs for official job-board discovery.',
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
            description: 'Minimum annual base salary filter.',
          },
          minBaseMode: {
            type: 'string',
            enum: ['floor', 'ceiling', 'overlap'],
            default: 'floor',
            description: 'How minBase compares against salary ranges: "floor" (pay.min >= minBase) or "overlap" / "ceiling" (pay.max >= minBase).',
          },
          strictPay: {
            type: 'boolean',
            default: false,
            description: 'When true and minBase is set, exclude postings that do not list compensation.',
          },
          postedWithinDays: { type: 'integer', minimum: 1, maximum: 365, description: 'Keep postings published within the last N days.' },
          limit: { type: 'integer', minimum: 1, maximum: 50, default: 20 },
          offset: {
            type: 'integer',
            minimum: 0,
            default: 0,
            description: 'Board pagination offset for paging large job boards (e.g. pass 100 after reading 0..99).',
          },
          cursor: {
            type: 'string',
            description: 'Pagination cursor returned in nextCursor from a previous truncated jobs response.',
          },
          includeBuiltIn: { type: 'boolean', default: true, description: 'Include Built In job listings (disabled automatically when company or domains is set).' },
          includePublicFeeds: {
            type: 'boolean',
            default: false,
            description: 'Opt in to public remote job feeds (We Work Remotely, Himalayas, Working Nomads).',
          },
          mode: {
            type: 'string',
            enum: ['search', 'verify'],
            description: 'Execution mode ("search" default, or "verify" to batch-check whether saved job URLs are still live).',
          },
          verify: {
            type: 'array',
            items: { type: 'string' },
            maxItems: 50,
            description: 'Saved https:// job posting URLs to batch-verify ("live" | "closed" | "board_gone" | "unknown").',
          },
          urls: {
            type: 'array',
            items: { type: 'string' },
            maxItems: 50,
            description: 'Alias for verify when mode="verify".',
          },
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
            description: 'Optional list of roles to exclude from results.',
          },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional worker site ID when target="agent".' },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'find_extractors',
      description:
        'Searches built-in keyless site and public-data adapters (such as SEC EDGAR, arXiv, OpenAlex, ClinicalTrials, openFDA, NIST NVD CVEs, npm, PyPI, Crates, job boards, and Shopify) and returns matching adapter URL patterns and capabilities.',
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
      name: 'catalog',
      description:
        'Extracts normalized product, variant, pricing, SKU, and availability records from a public Shopify or WooCommerce storefront (respecting robots.txt and rate limits), or pages and filters an existing catalog snapshot by catalogId.',
      annotations: {
        title: 'Extract & Diff Full Storefront Catalog',
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Public https:// storefront or collection URL (omit when paging an existing catalogId).' },
          catalogId: { type: 'string', description: 'Existing catalog run ID (`cat_...`) to poll status or page/filter product records.' },
          platform: {
            type: 'string',
            enum: ['auto', 'shopify', 'woocommerce'],
            default: 'auto',
            description: 'Storefront platform ("auto" detects Shopify vs WooCommerce).',
          },
          collection: { type: 'string', description: 'Optional collection or category slug.' },
          fields: {
            type: 'string',
            enum: ['full', 'lean'],
            default: 'full',
            description: '"full" includes descriptions and images; "lean" returns compact pricing, SKU, and availability fields.',
          },
          maxPages: { type: 'integer', minimum: 1, maximum: 200, description: 'Maximum catalog pages to fetch sequentially.' },
          pauseMs: { type: 'integer', minimum: 500, maximum: 30000, description: 'Polite pause between sequential pages in milliseconds.' },
          sync: { type: 'boolean', default: true, description: 'Set false to run in the background and poll with catalogId.' },
          offset: { type: 'integer', minimum: 0, description: 'Record offset when paging an existing catalogId.' },
          limit: { type: 'integer', minimum: 1, maximum: 250, description: 'Maximum records to return when paging an existing catalogId (default 50).' },
          vendor: {
            anyOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
            description: 'Optional vendor/brand filter when paging catalogId records.',
          },
          productType: {
            anyOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
            description: 'Optional productType filter when paging catalogId records.',
          },
          availableOnly: { type: 'boolean', description: 'When true, keep only products with at least one in-stock variant.' },
          query: { type: 'string', description: 'Optional keyword filter across title, handle, vendor, tags, and SKUs when paging catalogId.' },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional worker site ID when target="agent".' },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'agent',
      description:
        'Runs a multi-step LLM-guided web research and semantic JSON-Schema extraction agent using either a configured server LLM or a caller-supplied BYO-LLM (OpenAI, Anthropic, Gemini, OpenRouter, Ollama, or Workers AI), returning synthesized answers or schema-validated JSON.',
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
          prompt: { type: 'string', description: 'Natural-language research question or extraction goal.' },
          agentId: { type: 'string', description: 'Existing `agt_...` run ID to poll status, fetch trace spans, or cancel.' },
          trace: { type: 'boolean', default: false, description: 'Return execution trace spans when polling agentId.' },
          cancel: { type: 'boolean', default: false, description: 'Cancel a running agentId.' },
          urls: { type: 'array', items: { type: 'string' }, description: 'Optional starting public https:// URLs.' },
          strictConstrainToURLs: { type: 'boolean', default: false, description: 'Restrict navigation strictly to the provided seed urls.' },
          schema: { type: 'object', description: 'Optional JSON Schema for semantic structured output validation.' },
          effort: { type: 'string', enum: ['low', 'medium', 'high'], default: 'medium' },
          maxSteps: { type: 'integer', minimum: 1, maximum: 20 },
          maxPages: { type: 'integer', minimum: 1, maximum: 40 },
          threadId: { type: 'string', description: 'Optional prior `agt_...` threadId for multi-turn follow-up.' },
          zeroDataRetention: { type: 'boolean', default: false, description: 'When true, skips persisting run history or cached artifacts.' },
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
            description: 'Optional BYO-LLM configuration (e.g. { provider: "openai"|"anthropic"|"gemini"|"ollama", model, baseUrl, apiKey }).',
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
    {
      name: 'discover_mcps',
      description:
        'Searches the Official Model Context Protocol Registry and Glama directory to find remote and local MCP servers, returning endpoint URLs, authentication requirements, and associated domains.',
      annotations: {
        title: 'Discover MCP Servers (Official Registry + Glama)',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: 'Search keyword, service name, or domain (e.g. "linear", "notion", "github", "sentry", "stripe").',
          },
          remoteOnly: {
            type: 'boolean',
            default: false,
            description: 'When true, return only servers offering remote HTTP or SSE endpoints.',
          },
          limit: {
            type: 'integer',
            minimum: 1,
            maximum: 50,
            default: 20,
            description: 'Maximum registry entries to return (1..50).',
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'query_mcp',
      description:
        'Lists your connected downstream MCP servers, inspects their available tool schemas on demand, or invokes a tool on a connected downstream MCP server.',
      annotations: {
        title: 'Query Connected Federated MCP Server',
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
      inputSchema: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['list_connected', 'list_tools', 'call_tool'],
            default: 'list_connected',
            description:
              '"list_connected" lists connected MCP servers; "list_tools" inspects tools on a server; "call_tool" executes a tool on a server.',
          },
          server: {
            type: 'string',
            description: 'Connected MCP server id or slug (required for "list_tools" and "call_tool").',
          },
          tool: {
            type: 'string',
            description: 'Downstream MCP tool name to execute (required when action="call_tool").',
          },
          arguments: {
            type: 'object',
            description: 'JSON object arguments passed to the downstream MCP tool when action="call_tool".',
          },
          allowedMcpTools: {
            type: 'array',
            items: { type: 'string' },
            description:
              'Optional per-request allow-list of non-read-only cached downstream tools in exact "<slug>/<tool>" format.',
          },
          refresh: {
            type: 'boolean',
            default: false,
            description: 'When true on action="list_tools", fetches fresh tool definitions from the remote MCP server.',
          },
        },
        additionalProperties: false,
      },
    },
  ];
}

export const MCP_TOOL_SCHEMAS: Readonly<Record<string, CanonicalMcpToolSchema>> = Object.freeze(
  Object.fromEntries(buildCanonicalMcpToolSchemas().map((tool) => [tool.name, tool.inputSchema])),
);

function buildToolDefinitions(deps: McpServerDeps) {
  const allTools = buildCanonicalMcpToolSchemas({
    allowedTargets: deps.allowedTargets,
    defaultTarget: deps.defaultTarget,
  });
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
      if (t.name === 'catalog') return Boolean(deps.executeCatalog);
      if (t.name === 'find_extractors') return Boolean(deps.findExtractors);
      if (t.name === 'agent') return Boolean(deps.executeAgent);
      if (t.name === 'discover_mcps') return Boolean(deps.discoverMcps);
      if (t.name === 'query_mcp') return Boolean(deps.executeQueryMcp);
      return true;
    })
    .map((t) => ({ ...t, title: t.annotations.title }));
}

/** Removes inline body fields from a fetch result (for `includeBody: false`), keeping `artifactId` and metadata. */
export function stripInlineBodyFields(item: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...item };
  for (const key of ['body', 'bodyEncoding', 'bodyOriginalChars', 'bodyPreviewTruncated', 'bodyBase64', 'rawBody']) {
    delete copy[key];
  }
  return copy;
}

export function truncateResultBodies(
  parsed: Record<string, unknown>,
  inlineMaxChars = MAX_BODY_PREVIEW_CHARS,
  autoInferredKind = false,
): Record<string, unknown> {
  if (!Array.isArray(parsed.results)) return parsed;
  const outcomeDeltas = new Map<string, number>();
  const recordOutcomeShift = (fromOutcome: unknown, toOutcome: string) => {
    const prev = typeof fromOutcome === 'string' && fromOutcome ? fromOutcome : 'error';
    if (prev === toOutcome) return;
    outcomeDeltas.set(prev, (outcomeDeltas.get(prev) ?? 0) - 1);
    outcomeDeltas.set(toOutcome, (outcomeDeltas.get(toOutcome) ?? 0) + 1);
  };
  const results = parsed.results.map((item) => {
    if (!item || typeof item !== 'object') return item;
    const copy = { ...(item as Record<string, unknown>) };
    const origOutcome = copy.outcome;
    if (typeof copy.problem === 'string') {
      copy.problem = scrubResolverIpFromError(copy.problem);
    }
    if (copy.headers !== undefined) {
      const safeHdrs =
        copy.headers && typeof copy.headers === 'object' && !Array.isArray(copy.headers)
          ? filterSafeResponseHeaders(copy.headers as Record<string, string | undefined>)
          : undefined;
      if (safeHdrs) {
        copy.headers = safeHdrs;
      } else {
        delete copy.headers;
      }
    }
    const art = copy.artifact as { blobSha256?: string; retention?: string } | undefined;
    if (art?.blobSha256) {
      copy.artifactId = art.blobSha256;
    }

    // Normalize HTTP 404 to `not_found` while keeping HTTP 410 as `gone`.
    if (copy.status === 404 && (copy.outcome === 'gone' || copy.outcome === 'error')) {
      copy.outcome = 'not_found';
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
    }

    // When caller omitted `kind` (`autoInferredKind === true` or `copy.kindAuto === true`) and an extensionless URL returned HTTP 2xx with a valid
    // JSON/XML/RSS/Atom/text/Markdown/vCard/CSV payload and body, promote `kind="page"`/`"json"`/`"text"` skip to `ok` instead of failing the caller.
    if (
      (autoInferredKind || copy.kindAuto === true) &&
      copy.outcome === 'skip' &&
      typeof copy.status === 'number' &&
      copy.status >= 200 &&
      copy.status < 300 &&
      ((typeof copy.body === 'string' && copy.body.length > 0) || Boolean(art?.blobSha256)) &&
      typeof copy.contentType === 'string' &&
      /^(?:text\/|application\/(?:[a-z0-9.+-]*\+)?(?:json|xml)|application\/(?:xhtml\+xml|rss\+xml|atom\+xml|yaml|x-yaml|csv|javascript|x-ndjson))(?:[;\s]|$)/i.test(
        copy.contentType.trim(),
      )
    ) {
      copy.outcome = 'ok';
      delete copy.problem;
    }

    // An auto-detected `kind: "page"` request that actually returned JSON (e.g. an extensionless ATS API such as
    // `/posting-api/job-board/<org>`) is reported as `kind: "json"`. Only the response label changes: the request was
    // fetched as a page on purpose, since guessing `json` up front would turn HTML on api.* hosts into `skip`.
    if (
      (autoInferredKind || copy.kindAuto === true) &&
      copy.kind === 'page' &&
      copy.outcome === 'ok' &&
      typeof copy.contentType === 'string' &&
      /^application\/(?:[a-z0-9.+-]*\+)?json(?:[;\s]|$)/i.test(copy.contentType.trim())
    ) {
      copy.kind = 'json';
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
    const isSyntheticRedir403 =
      copy.status === 403 &&
      typeof copy.body === 'string' &&
      copy.body.length <= 512 &&
      /^\s*forbidden redirect target:/i.test(copy.body);
    if (copy.outcome !== 'ok' && isDnsNotFoundError(copy.outcome, copy.problem)) {
      copy.outcome = 'dns_not_found';
      copy.error = 'dns_not_found';
      copy.retryable = false;
      copy.message = DNS_NOT_FOUND_MESSAGE;
      copy.problem = typeof copy.problem === 'string' && copy.problem ? copy.problem : DNS_NOT_FOUND_MESSAGE;
      delete copy.blocked;
      delete copy.body;
    } else if (copy.outcome !== 'ok' && isSchemeDowngradeError(copy.outcome, copy.problem, copy.blockedReason)) {
      copy.outcome = 'blocked';
      copy.blockedReason = 'scheme_downgrade';
      copy.blocked = { ...SCHEME_DOWNGRADE_BLOCKED_INFO };
      copy.problem = SCHEME_DOWNGRADE_BLOCKED_INFO.message;
      delete copy.body;
      delete copy.artifact;
      delete copy.artifactId;
    } else if (isSyntheticRedir403 || (copy.outcome !== 'ok' && isSsrfBlockedError(copy.outcome, copy.problem, copy.blockedReason))) {
      copy.outcome = 'blocked';
      copy.status = 0;
      copy.blockedReason = 'ssrf';
      copy.blocked = { ...SSRF_BLOCKED_INFO };
      copy.problem = SSRF_BLOCKED_INFO.message;
      delete copy.body;
      delete copy.artifact;
      delete copy.artifactId;
    } else if (copy.outcome !== 'ok' && typeof copy.url === 'string') {
      if (!copy.waf && typeof copy.status === 'number' && copy.status !== 402 && copy.outcome !== 'payment_required') {
        const inferredWaf = classifyWafAndChallenge({
          status: copy.status,
          ...(typeof copy.body === 'string' && (!copy.bodyEncoding || copy.bodyEncoding === 'utf-8') ? { rawBody: copy.body } : {}),
        });
        if (inferredWaf) copy.waf = inferredWaf;
      }
      if ((copy.status === 429 || copy.outcome === 'rate_limited') && copy.outcome !== 'challenge' && !copy.waf) {
        copy.rateLimited = true;
      }
      const baseBlocked = buildBlockedInfo(copy.url, copy.outcome, copy.problem, copy.status, {
        headers:
          copy.paymentHeaders && typeof copy.paymentHeaders === 'object' && !Array.isArray(copy.paymentHeaders)
            ? (copy.paymentHeaders as Record<string, string | undefined>)
            : undefined,
        rawBody: typeof copy.body === 'string' && (!copy.bodyEncoding || copy.bodyEncoding === 'utf-8') ? copy.body : undefined,
      }) as Record<string, unknown> | null;
      const blocked = refineBlockedInfo({
        url: copy.url,
        outcome: copy.outcome,
        problem: copy.problem,
        status: copy.status,
        retryAfter: copy.retryAfter,
        baseBlocked,
      });
      if (blocked) copy.blocked = blocked;
      if (typeof copy.body === 'string' && copy.body.includes('cf-footer-ip')) {
        copy.body = copy.body.replace(/(<span\b[^>]*\bid=["']?cf-footer-ip["']?[^>]*>)[^<]{1,80}(<\/span>)/gi, '$1[redacted]$2');
      }
    }
    if (typeof copy.outcome === 'string' && copy.outcome !== origOutcome) {
      recordOutcomeShift(origOutcome, copy.outcome);
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

  if (outcomeDeltas.size > 0 && parsed.summary && typeof parsed.summary === 'object') {
    const sumCopy = { ...(parsed.summary as Record<string, unknown>) };
    if (sumCopy.byOutcome && typeof sumCopy.byOutcome === 'object') {
      const byOut = { ...(sumCopy.byOutcome as Record<string, number>) };
      for (const [outKey, delta] of outcomeDeltas.entries()) {
        if (delta === 0) continue;
        const nextVal = Math.max(0, (byOut[outKey] ?? 0) + delta);
        if (nextVal === 0) delete byOut[outKey];
        else byOut[outKey] = nextVal;
      }
      sumCopy.byOutcome = byOut;
    }
    return { ...parsed, summary: sumCopy, results };
  }

  return { ...parsed, results };
}

function compactMcpScreenshotBody(body: Record<string, unknown>): Record<string, unknown> {
  if (typeof body.screenshotArtifactId !== 'string' || !body.screenshotArtifactId) {
    return body;
  }
  const copy: Record<string, unknown> = { ...body };
  delete copy.screenshotBase64;
  delete copy.screenshot;
  if (!copy.screenshotNote) {
    copy.screenshotNote =
      'PNG screenshot stored as an R2 artifact; call read_artifact({ artifactId: screenshotArtifactId, format: "raw" }) on demand.';
  }
  return copy;
}

async function handleToolCallInner(
  name: string,
  args: Record<string, unknown>,
  scopes: string[],
  principal: string,
  deps: McpServerDeps,
  userId = 'owner',
): Promise<{ content: Array<{ type: 'text'; text: string }>; structuredContent?: Record<string, unknown>; isError?: boolean }> {
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
    const preBlockedByIndex = new Map<number, Record<string, unknown>>();
    if (name === 'fetch_url') {
      const check = validatePublicHttpsUrl(args.url, deps.selfHost);
      if (!check.ok) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ok: false,
                  outcome: 'blocked',
                  error: check.reason,
                  retryable: false,
                  message: check.error,
                  blocked: {
                    reason: check.reason,
                    retryable: false,
                    message: check.error,
                  },
                },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }
      const kind = explicitKind ?? inferKindForUrl(check.url);
      const accept = textAcceptFor(kind, check.url, args.accept);
      if (!accept.ok) return { content: [{ type: 'text', text: accept.error }], isError: true };
      const singleWikiArt = parseWikipediaArticleUrl(check.url);
      if (singleWikiArt) {
        const wikiQuota = checkAndRecordWikipediaArticleQuota({
          callerKey: userId || principal,
          host: singleWikiArt.host,
        });
        if (!wikiQuota.allowed) {
          return {
            content: [{ type: 'text', text: JSON.stringify(wikiQuota.block, null, 2) }],
            isError: true,
          };
        }
      }
      requests = [
        {
          id: 'mcp-1',
          url: check.url,
          kind,
          ...(explicitKind === undefined ? { kindAuto: true } : {}),
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
        const rawEntry = args.urls[i];
        const entryObj = rawEntry && typeof rawEntry === 'object' && !Array.isArray(rawEntry) ? (rawEntry as Record<string, unknown>) : null;
        const rawUrlVal = entryObj ? entryObj.url : rawEntry;
        const itemExplicitKind =
          entryObj && (entryObj.kind === 'feed' || entryObj.kind === 'json' || entryObj.kind === 'text' || entryObj.kind === 'page')
            ? entryObj.kind
            : explicitKind;
        const check = validatePublicHttpsUrl(rawUrlVal, deps.selfHost);
        if (!check.ok) {
          preBlockedByIndex.set(i, {
            id: `mcp-${i + 1}`,
            url: typeof rawUrlVal === 'string' ? rawUrlVal : String(rawUrlVal ?? ''),
            status: 0,
            outcome: 'blocked',
            blockedReason: check.reason,
            error: check.reason,
            retryable: false,
            message: check.error,
            problem: check.error,
            blocked: {
              reason: check.reason,
              retryable: false,
              message: check.error,
            },
          });
          continue;
        }
        const kind = itemExplicitKind ?? inferKindForUrl(check.url);
        const accept = textAcceptFor(kind, check.url, entryObj?.accept ?? args.accept);
        if (!accept.ok) return { content: [{ type: 'text', text: accept.error }], isError: true };
        const wikiArt = parseWikipediaArticleUrl(check.url);
        if (wikiArt) {
          const wikiQuota = checkAndRecordWikipediaArticleQuota({
            callerKey: userId || principal,
            host: wikiArt.host,
          });
          if (!wikiQuota.allowed) {
            preBlockedByIndex.set(i, {
              id: `mcp-${i + 1}`,
              url: check.url,
              status: 429,
              ...wikiQuota.block,
            });
            continue;
          }
        }
        requests.push({
          id: `mcp-${i + 1}`,
          url: check.url,
          kind,
          ...(itemExplicitKind === undefined ? { kindAuto: true } : {}),
          ...(accept.accept ? { accept: accept.accept } : {}),
        });
      }
    }

    const requestedPauseMs =
      typeof args.pauseMs === 'number' && Number.isFinite(args.pauseMs)
        ? Math.min(30_000, Math.max(0, Math.floor(args.pauseMs)))
        : undefined;
    const effectivePauseMs = requestedPauseMs !== undefined ? Math.max(2_000, requestedPauseMs) : undefined;
    const pacingEchoFields =
      effectivePauseMs !== undefined
        ? {
            effectivePauseMs,
            ...(requestedPauseMs! < effectivePauseMs
              ? { politenessFloorNote: `Requested pauseMs (${requestedPauseMs}ms) was clamped to the per-host politeness floor (${effectivePauseMs}ms; edge nodes may also apply their configured site floor).` }
              : {}),
          }
        : {};

    if (name === 'fetch_batch' && requests.length === 0 && preBlockedByIndex.size > 0) {
      const onlyBlocked = [...preBlockedByIndex.entries()]
        .sort((a, b) => a[0] - b[0])
        .map(([, v]) => v);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                via: 'policy',
                httpStatus: 200,
                ...pacingEchoFields,
                results: onlyBlocked,
                summary: { total: onlyBlocked.length, byOutcome: { blocked: onlyBlocked.length } },
              },
              null,
              2,
            ),
          },
        ],
      };
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

    // `includeBody: false` means "don't return bodies inline", not "don't keep them": the fetcher (Go node R2 sink and
    // the hub dispatch artifact policy) only stores an artifact when bodies are requested, so always request them and
    // instead skip inline R2 hydration and strip the body fields from the response. Results keep `artifactId` for
    // `read_artifact`, exactly as `fetch_url` does.
    const callPayload = {
      maxSeconds: 60,
      options: {
        includeBody: true,
        respectRobots,
        ...(name === 'fetch_batch' ? { concurrency: 4 } : {}),
        ...(requestedMaxBytes !== undefined && requestedMaxBytes > 8 * 1024 * 1024
          ? { maxBytes: Math.min(16 << 20, requestedMaxBytes) }
          : {}),
        ...(requestedPauseMs !== undefined ? { pauseMs: requestedPauseMs } : {}),
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
        ...(includeBody ? {} : { hydrateInline: false }),
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
    let singleDnsOrSsrfErr = false;
    try {
      const parsed = JSON.parse(res.bodyText) as Record<string, unknown>;
      const truncatedObj = truncateResultBodies(parsed, inlineMaxChars, explicitKind === undefined);
      if (!includeBody && Array.isArray(truncatedObj.results)) {
        truncatedObj.results = truncatedObj.results.map((item) => (item && typeof item === 'object' ? stripInlineBodyFields(item) : item));
      }
      if (name === 'fetch_batch' && preBlockedByIndex.size > 0 && Array.isArray(truncatedObj.results)) {
        const fetchedById = new Map<string, Record<string, unknown>>();
        for (const item of truncatedObj.results) {
          if (item && typeof item === 'object' && typeof (item as Record<string, unknown>).id === 'string') {
            fetchedById.set((item as Record<string, unknown>).id as string, item as Record<string, unknown>);
          }
        }
        const totalBatchLen = Array.isArray(args.urls) ? args.urls.length : truncatedObj.results.length + preBlockedByIndex.size;
        const mergedResults: Array<Record<string, unknown>> = [];
        for (let i = 0; i < totalBatchLen; i++) {
          const preBlocked = preBlockedByIndex.get(i);
          if (preBlocked) {
            mergedResults.push(preBlocked);
          } else {
            const found = fetchedById.get(`mcp-${i + 1}`);
            if (found) mergedResults.push(found);
          }
        }
        truncatedObj.results = mergedResults;
        const prevSum =
          truncatedObj.summary && typeof truncatedObj.summary === 'object'
            ? { ...(truncatedObj.summary as Record<string, unknown>) }
            : {};
        const prevByOut =
          prevSum.byOutcome && typeof prevSum.byOutcome === 'object'
            ? { ...(prevSum.byOutcome as Record<string, number>) }
            : {};
        prevByOut.blocked = (prevByOut.blocked ?? 0) + preBlockedByIndex.size;
        prevSum.total = mergedResults.length;
        prevSum.byOutcome = prevByOut;
        truncatedObj.summary = prevSum;
      }
      const firstItem =
        name === 'fetch_url' && Array.isArray(truncatedObj.results) && truncatedObj.results.length === 1
          ? (truncatedObj.results[0] as Record<string, unknown> | undefined)
          : undefined;
      const topDnsFields =
        firstItem?.outcome === 'dns_not_found'
          ? {
              ok: false,
              error: 'dns_not_found',
              retryable: false,
              message: DNS_NOT_FOUND_MESSAGE,
            }
          : firstItem?.outcome === 'blocked' && firstItem.blocked
            ? {
                ok: false,
                outcome: 'blocked',
                blocked: firstItem.blocked,
              }
            : firstItem?.outcome === 'skip' && firstItem.blocked
              ? {
                  blocked: firstItem.blocked,
                }
              : {};
      if (firstItem?.outcome === 'dns_not_found' || firstItem?.outcome === 'blocked') {
        singleDnsOrSsrfErr = true;
      }
      formatted = {
        ...topDnsFields,
        via: res.via,
        httpStatus: firstItem?.outcome === 'dns_not_found' ? 502 : res.status,
        ...pacingEchoFields,
        ...(res.stageTimingsMs ? { stageTimingsMs: res.stageTimingsMs } : {}),
        ...truncatedObj,
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
      ...(res.status >= 400 || singleDnsOrSsrfErr ? { isError: true } : {}),
    };
  }

  if (name === 'read_artifact') {
    if (!scopes.includes('crawl:read') && !scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:read is required.' }], isError: true };
    }
    if (!deps.readArtifact) {
      return { content: [{ type: 'text', text: 'Artifact storage is not configured on this hub.' }], isError: true };
    }
    const rawIdArg =
      typeof args.artifactId === 'string' && args.artifactId.trim()
        ? args.artifactId
        : typeof args.blobSha256 === 'string'
          ? args.blobSha256
          : '';
    const blobSha256 = rawIdArg.trim().toLowerCase();
    const retention = args.retention === 'stored' ? 'stored' : args.retention === 'transient' ? 'transient' : undefined;
    const format = args.format === 'markdown' ? 'markdown' : args.format === 'raw' ? 'raw' : undefined;
    const visibility = args.visibility === 'private' ? 'private' : args.visibility === 'public' ? 'public' : undefined;
    const offset = typeof args.offset === 'number' ? Math.max(0, Math.floor(args.offset)) : 0;
    const limit = typeof args.limit === 'number' ? Math.min(262_144, Math.max(1, Math.floor(args.limit))) : MAX_BODY_PREVIEW_CHARS;
    const out = await deps.readArtifact({
      blobSha256,
      ...(retention ? { retention } : {}),
      ...(format ? { format } : {}),
      ...(visibility ? { visibility } : {}),
      offset,
      limit,
      userId,
    });
    if (!out.ok) {
      const isMissing =
        out.error === 'artifact_not_found' ||
        out.error === 'artifact_expired' ||
        out.status === 404 ||
        out.status === 410;
      const errBody = isMissing
        ? {
            ok: false,
            status: 404,
            via: 'hub',
            error: 'artifact_not_found',
            message: 'Artifact was not found or has expired.',
          }
        : {
            ok: false,
            status: out.status,
            via: 'hub',
            error: out.error,
            ...(out.message ? { message: out.message } : {}),
          };
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(errBody, null, 2),
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
    const res = await deps.executeScrape({ args: scrapeArgs, principal, userId });
    return {
      content: [{ type: 'text', text: JSON.stringify(compactMcpScreenshotBody(res.body), null, 2) }],
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
    const res = await deps.executeExtract({ args, principal, userId });
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
    const res = await deps.searchCollection({ collectionId, query, limit, userId });
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
    const res = await deps.executeInteract({ args, principal, userId });
    return {
      content: [{ type: 'text', text: JSON.stringify(compactMcpScreenshotBody(res.body), null, 2) }],
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
    const res = await deps.executeMap({ args, principal, userId });
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
    const res = await deps.executeCrawl({ args, principal, userId });
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
    const res = await deps.executeSearch({ args, principal, userId });
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
    const res = await deps.executeJobs({ args, principal, userId });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status !== 200 ? { isError: true } : {}),
    };
  }

  if (name === 'catalog') {
    if (!scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:fetch is required.' }], isError: true };
    }
    if (!deps.executeCatalog) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'catalog_not_configured' }) }], isError: true };
    }
    const res = await deps.executeCatalog({ args, principal, userId });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status >= 400 ? { isError: true } : {}),
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
    const res = await deps.executeAgent({ args, principal, userId });
    return {
      content: [{ type: 'text', text: JSON.stringify(res.body, null, 2) }],
      ...(res.status >= 400 ? { isError: true } : {}),
    };
  }

  if (name === 'discover_mcps') {
    if (!scopes.includes('crawl:read') && !scopes.includes('crawl:fetch')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:read is required.' }], isError: true };
    }
    if (!deps.discoverMcps) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'registry_not_configured' }) }], isError: true };
    }
    const query = typeof args.query === 'string' ? args.query : undefined;
    const remoteOnly = typeof args.remoteOnly === 'boolean' ? args.remoteOnly : false;
    const limit = typeof args.limit === 'number' && Number.isFinite(args.limit) ? args.limit : 20;
    const res = await deps.discoverMcps({ ...(query !== undefined ? { query } : {}), remoteOnly, limit });
    const upstreamUnsanitized = res.body.sanitized === false;
    const upstreamFullySanitized = res.body.fullySanitized !== false;
    const san = sanitizeConnectorStructuredValue(res.body);
    const sanObj =
      san.value && typeof san.value === 'object' && !Array.isArray(san.value)
        ? (san.value as Record<string, unknown>)
        : { data: san.value };
    const isSanitized = Boolean(!upstreamUnsanitized && san.sanitized);
    const isFullySanitized = Boolean(isSanitized && upstreamFullySanitized && san.fullySanitized);
    const payloadOut: Record<string, unknown> = {
      ...sanObj,
      sanitized: isSanitized,
      fullySanitized: isFullySanitized,
      promptInjection: {
        detected: san.detected,
        scrubbed: san.scrubbed,
        triggers: san.triggers,
      },
    };
    const wrappedText = formatFenceSafeUntrustedMcpEnvelope({
      tag: 'untrusted_mcp_output',
      attributes: { tool: 'discover_mcps' },
      content: JSON.stringify(payloadOut, null, 2),
    });
    return {
      content: [{ type: 'text', text: wrappedText }],
      structuredContent: payloadOut,
      ...(res.status >= 400 ? { isError: true } : {}),
    };
  }

  if (name === 'query_mcp') {
    const action = typeof args.action === 'string' ? args.action : 'list_connected';
    if (action === 'call_tool' || action === 'list_tools') {
      if (!scopes.includes('mcp:call')) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ok: false,
                  error: 'insufficient_scope',
                  message: `OAuth scope mcp:call is required for action="${action}"`,
                },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }
    } else if (!scopes.includes('crawl:read') && !scopes.includes('crawl:fetch') && !scopes.includes('mcp:call')) {
      return { content: [{ type: 'text', text: 'Insufficient OAuth scope: crawl:read is required.' }], isError: true };
    }
    if (!deps.executeQueryMcp) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'mcp_federation_not_configured' }) }], isError: true };
    }
    const parsedAllowed = parseAllowedMcpTools(args.allowedMcpTools);
    if (!parsedAllowed.ok) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: false,
                error: parsedAllowed.error,
                message: parsedAllowed.message,
              },
              null,
              2,
            ),
          },
        ],
        isError: true,
      };
    }
    const res = await deps.executeQueryMcp({ args, principal, userId });
    const prevPi =
      res.body.promptInjection && typeof res.body.promptInjection === 'object'
        ? (res.body.promptInjection as { detected?: boolean; scrubbed?: boolean; triggers?: unknown })
        : undefined;
    const prevTriggers = Array.isArray(prevPi?.triggers)
      ? prevPi!.triggers.filter((t): t is string => typeof t === 'string')
      : [];

    // M10-3: `executeFederatedMcpQuery` already sanitizes all connector output fields once and sets `res.body.sanitized`.
    // Only run `sanitizeConnectorStructuredValue` when a custom/mock `executeQueryMcp` returned an unsanitized body.
    let payloadOut: Record<string, unknown>;
    if (typeof res.body.sanitized === 'boolean') {
      const isSanitized = res.body.sanitized === true;
      const isFullySanitized = Boolean(isSanitized && res.body.fullySanitized !== false);
      payloadOut = {
        ...res.body,
        sanitized: isSanitized,
        fullySanitized: isFullySanitized,
        promptInjection: {
          detected: Boolean(prevPi?.detected),
          scrubbed: Boolean(prevPi?.scrubbed),
          triggers: prevTriggers,
        },
      };
    } else {
      const san = sanitizeConnectorStructuredValue(res.body);
      const sanObj =
        san.value && typeof san.value === 'object' && !Array.isArray(san.value)
          ? (san.value as Record<string, unknown>)
          : { data: san.value };
      const isSanitized = san.sanitized;
      const isFullySanitized = Boolean(isSanitized && san.fullySanitized);
      const mergedTriggers = [...new Set([...prevTriggers, ...san.triggers])];
      payloadOut = {
        ...sanObj,
        sanitized: isSanitized,
        fullySanitized: isFullySanitized,
        promptInjection: {
          detected: Boolean(prevPi?.detected || san.detected),
          scrubbed: Boolean(prevPi?.scrubbed || san.scrubbed),
          triggers: mergedTriggers,
        },
      };
    }
    const safeActionAttr = /^[a-z_]{1,24}$/i.test(action) ? action : undefined;
    const safeServerAttr =
      typeof payloadOut.server === 'string' && /^[a-z0-9_-]{1,48}$/i.test(payloadOut.server)
        ? payloadOut.server
        : undefined;
    const wrappedText = formatFenceSafeUntrustedMcpEnvelope({
      tag: 'untrusted_mcp_output',
      attributes: {
        tool: 'query_mcp',
        ...(safeActionAttr ? { action: safeActionAttr } : {}),
        ...(safeServerAttr ? { server: safeServerAttr } : {}),
      },
      content: JSON.stringify(payloadOut, null, 2),
    });
    return {
      content: [{ type: 'text', text: wrappedText }],
      structuredContent: payloadOut,
      ...(res.status >= 400 || payloadOut.isError === true ? { isError: true } : {}),
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
  userId = 'owner',
): Promise<{ content: Array<{ type: 'text'; text: string }>; structuredContent?: Record<string, unknown>; isError?: boolean }> {
  try {
    return await handleToolCallInner(name, args, scopes, principal, deps, userId);
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
  userId = 'owner',
): Promise<{ body: Record<string, unknown>; status?: number; sseLeading?: Array<Record<string, unknown>> } | null> {
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
          ttlMs: 60_000,
          cacheScope: 'private',
        }),
      };
    }
    case 'subscriptions/listen': {
      // MCP 2026-07-28 change-notification stream. The hub's tool list is fixed per deployed version (it never changes
      // while a client is connected) and it advertises `listChanged: false`, so it honors no notification types: it
      // acknowledges with an empty `notifications` set, then ends the subscription gracefully with a `complete` result
      // (spec "Graceful Closure"), which tells the client not to reconnect. Before this, the method was unknown and
      // 2026-07-28 clients retried it with backoff on every connect (HTTP 404 bursts).
      await finishMcpTurn();
      const subscriptionMeta = { 'io.modelcontextprotocol/subscriptionId': id };
      return {
        sseLeading: [
          {
            jsonrpc: '2.0',
            method: 'notifications/subscriptions/acknowledged',
            params: { _meta: subscriptionMeta, notifications: {} },
          },
        ],
        body: jsonRpcResult(id, { resultType: 'complete', _meta: subscriptionMeta }),
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
      const activeTracer = deps.tracer ?? getActiveRequestTracer();
      const invokeTool = () => handleToolCall(toolName, rawArgs, scopes, principal, deps, userId);
      const out = activeTracer
        ? await activeTracer.withSpan(
            'edgefetch.mcp.tool',
            {
              kind: 1,
              attributes: {
                'rpc.system': 'jsonrpc',
                'rpc.method': 'tools/call',
                'mcp.tool.name': toolName,
                'mcp.auth.type': authType,
                'mcp.principal': principal,
                'mcp.protocol_version': isModern ? '2026-07-28' : DEFAULT_PROTOCOL_VERSION,
              },
            },
            async (span) => {
              const res = await invokeTool();
              const isErr = Boolean(res.isError);
              span.setAttribute('mcp.is_error', isErr);
              const firstTxt = Array.isArray(res.content) && typeof res.content[0]?.text === 'string' ? res.content[0].text : '';
              if (firstTxt.startsWith('{') && firstTxt.length <= 65_536) {
                try {
                  const parsedToolOut = JSON.parse(firstTxt) as Record<string, unknown>;
                  if (typeof parsedToolOut.status === 'number' && Number.isFinite(parsedToolOut.status)) {
                    span.setAttribute('http.response.status_code', Math.floor(parsedToolOut.status));
                  }
                  const outLabel =
                    typeof parsedToolOut.outcome === 'string'
                      ? parsedToolOut.outcome
                      : typeof parsedToolOut.error === 'string'
                        ? parsedToolOut.error
                        : undefined;
                  if (outLabel) span.setAttribute('edgefetch.outcome', outLabel.slice(0, 64));
                } catch {
                  // ignore non-JSON tool payloads
                }
              }
              if (isErr) span.setStatus(false, 'mcp_tool_error');
              return res;
            },
          )
        : await invokeTool();
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
        level: 'info',
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

/**
 * True for an MCP Streamable HTTP request sent to the site root instead of `/mcp`: a JSON POST (JSON-RPC), a GET that
 * only asks for an SSE stream, or a DELETE that ends an MCP session. Clients configured with the bare origin discover
 * OAuth via `/.well-known/*` (and the root resource already normalizes to `/mcp`), then send every MCP call to `/`.
 * Answering those with 401 made clients refresh tokens in a loop until `/oauth/token` rate-limited them, so the hub
 * serves them as `/mcp`. Browser GETs (HTML) and other root requests are unaffected.
 */
export function isMcpRootRequest(request: Request, url: URL): boolean {
  if (url.pathname !== '/') return false;
  const method = request.method.toUpperCase();
  if (method === 'POST') {
    return /^application\/json(?:\s*;|$)/i.test((request.headers.get('content-type') ?? '').trim());
  }
  if (method === 'GET') {
    const accept = (request.headers.get('accept') ?? '').toLowerCase();
    return accept.includes('text/event-stream') && !accept.includes('text/html');
  }
  if (method === 'DELETE') return request.headers.has('mcp-session-id');
  return false;
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

  const cappedBody = await readBodyTextCapped(request, Math.min(MAX_MCP_REQUEST_BYTES, MAX_MCP_REQUEST_BYTES));
  if (!cappedBody.ok) {
    if (cappedBody.error === 'too_large') {
      return Response.json(jsonRpcError(null, -32600, 'MCP payload exceeds 256 KiB'), { status: 413, headers: cors });
    }
    return Response.json(jsonRpcError(null, -32700, 'Parse error'), { status: 400, headers: cors });
  }
  const rawText = cappedBody.text;

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return Response.json(jsonRpcError(null, -32700, 'Parse error'), { status: 400, headers: cors });
  }

  const userAgent = request.headers.get('user-agent') ?? 'mcp-client';
  const callerUserId = resolveCallerUserId(auth as { userId?: string; principal?: string });

  if (Array.isArray(parsed)) {
    if (parsed.length === 0 || parsed.length > 20) {
      return Response.json(jsonRpcError(null, -32600, 'Invalid batch length'), { status: 400, headers: cors });
    }
    const replies: Array<Record<string, unknown>> = [];
    for (const item of parsed) {
      const out = await dispatchRpcMessage(
        (item ?? {}) as JsonRpcRequest,
        auth.scopes,
        auth.principal,
        userAgent,
        resolvedDeps,
        false,
        callerUserId,
      );
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

  const single = await dispatchRpcMessage(msg, auth.scopes, auth.principal, userAgent, resolvedDeps, era.isModern, callerUserId);
  if (!single) {
    return new Response(null, { status: 202, headers: cors });
  }
  if (single.sseLeading) {
    // SSE response stream: the leading notifications (e.g. `notifications/subscriptions/acknowledged`), then the final
    // JSON-RPC response, which ends the stream.
    const events = [...single.sseLeading, single.body].map((m) => `event: message\ndata: ${JSON.stringify(m)}\n\n`).join('');
    return new Response(events, {
      status: 200,
      headers: {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-store',
        'x-accel-buffering': 'no',
        'mcp-protocol-version': era.negotiatedVersion,
        ...cors,
      },
    });
  }
  return Response.json(single.body, {
    status: single.status ?? 200,
    headers: { 'cache-control': 'no-store', 'mcp-protocol-version': era.negotiatedVersion, ...cors },
  });
}
