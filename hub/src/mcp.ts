/**
 * Stateless Streamable HTTP Model Context Protocol (MCP) server (`POST /mcp`, `GET /mcp`, `DELETE /mcp`, `OPTIONS /mcp`).
 *
 * - Speaks MCP JSON-RPC 2.0 across `2025-11-25`, `2025-06-18`, `2025-03-26`, and `2024-11-05` with zero external
 *   runtime dependencies.
 * - Authenticates via self-hosted OAuth 2.1 (`authorizeMcpRequest`, returning RFC 9728 `401 + WWW-Authenticate` for
 *   one-command `claude mcp add --transport http ...` discovery) OR direct `Bearer <CALLER_TOKEN>`.
 * - Enforces `Origin` validation against DNS-rebinding / cross-origin attacks and per-tool OAuth scopes
 *   (`crawl:read` vs `crawl:fetch`).
 */
import type { ActivityStore } from './activity-log';
import type { AffinityPin, AgentAttachment, FetchTarget } from './agent-hub';
import { SITE_ID_PATTERN } from './auth';
import { authorizeMcpRequest, type OAuthStore } from './oauth';

const SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'] as const;
const DEFAULT_PROTOCOL_VERSION = '2025-03-26';
const MAX_MCP_REQUEST_BYTES = 256 * 1024;
const MAX_BODY_PREVIEW_CHARS = 64 * 1024;
const MAX_BATCH_URLS = 25;

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
}

export interface McpServerDeps {
  serverName: string;
  serverVersion: string;
  ownerSecret?: string;
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
}

function isAllowedMcpOrigin(originHeader: string | null, selfOrigin: string): boolean {
  if (!originHeader) return true;
  try {
    const u = new URL(originHeader);
    const h = u.hostname.toLowerCase();
    const selfHost = new URL(selfOrigin).hostname.toLowerCase();
    return (
      h === 'localhost' ||
      h === '127.0.0.1' ||
      h === '[::1]' ||
      h === '::1' ||
      h === 'claude.ai' ||
      h.endsWith('.claude.ai') ||
      h === selfHost
    );
  } catch {
    return false;
  }
}

function mcpCorsHeaders(request: Request, selfOrigin: string): Record<string, string> {
  const originHeader = request.headers.get('origin');
  if (!originHeader || !isAllowedMcpOrigin(originHeader, selfOrigin)) return {};
  return {
    'access-control-allow-origin': originHeader,
    'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
    'access-control-allow-headers': 'authorization, content-type, accept, mcp-protocol-version, mcp-session-id',
    'access-control-expose-headers': 'www-authenticate, mcp-protocol-version, mcp-session-id',
    vary: 'Origin',
  };
}

function jsonRpcError(id: string | number | null, code: number, message: string) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function jsonRpcResult(id: string | number | null, result: unknown) {
  return { jsonrpc: '2.0', id, result };
}

function validatePublicHttpsUrl(raw: unknown): { ok: true; url: string } | { ok: false; error: string } {
  if (typeof raw !== 'string' || !raw.trim()) return { ok: false, error: 'url must be a non-empty https:// string' };
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return { ok: false, error: `invalid URL: ${raw}` };
  }
  if (u.protocol !== 'https:') return { ok: false, error: 'only https:// URLs are permitted' };
  if (u.username || u.password) return { ok: false, error: 'URLs with embedded credentials are not permitted' };
  if (u.port && u.port !== '443') return { ok: false, error: 'only port 443 is permitted' };
  if (!u.hostname.includes('.') || u.hostname.toLowerCase() === 'localhost') {
    return { ok: false, error: `disallowed hostname: ${u.hostname}` };
  }
  return { ok: true, url: u.toString() };
}

function buildToolDefinitions(allowedTargets: FetchTarget[], defaultTarget: FetchTarget) {
  return [
    {
      name: 'list_agents',
      description:
        'List connected Home Assistant OS / EdgeFetch standby crawler agents, CPU architectures (amd64/arm64), job counters, and active 15-minute SQLite domain-affinity pins.',
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
            enum: ['feed', 'page'],
            default: 'page',
            description: '"feed" for JSON APIs/feeds (Accept: application/json) or "page" for HTML documents.',
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
          robots: { type: 'boolean', default: true, description: 'Respect /robots.txt Allow/Disallow and Crawl-delay.' },
          includeBody: { type: 'boolean', default: true, description: 'Include response body preview in tool output.' },
          maxBytes: { type: 'integer', minimum: 1024, maximum: 16777216, description: 'Maximum response body bytes (up to 16 MiB).' },
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
          kind: { type: 'string', enum: ['feed', 'page'], default: 'page' },
          target: { type: 'string', enum: allowedTargets, default: defaultTarget },
          site: { type: 'string', description: 'Optional standby site ID when target="agent".' },
          pauseMs: { type: 'integer', minimum: 0, maximum: 30000, default: 1000, description: 'Minimum per-host pause in ms.' },
          pauseJitterMs: { type: 'integer', minimum: 0, maximum: 15000, default: 500, description: 'Random positive jitter added to pauseMs.' },
          robots: { type: 'boolean', default: true },
          includeBody: { type: 'boolean', default: false, description: 'Set true to include truncated body previews per URL.' },
        },
        required: ['urls'],
        additionalProperties: false,
      },
    },
  ];
}

function truncateResultBodies(parsed: Record<string, unknown>): Record<string, unknown> {
  if (!Array.isArray(parsed.results)) return parsed;
  const results = parsed.results.map((item) => {
    if (!item || typeof item !== 'object') return item;
    const copy = { ...(item as Record<string, unknown>) };
    if (typeof copy.body === 'string' && copy.body.length > MAX_BODY_PREVIEW_CHARS) {
      copy.bodyPreviewTruncated = true;
      copy.bodyOriginalChars = copy.body.length;
      copy.body = copy.body.slice(0, MAX_BODY_PREVIEW_CHARS);
    }
    return copy;
  });
  return { ...parsed, results };
}

async function handleToolCall(
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
    const fleet = await deps.listFleet();
    return {
      content: [{ type: 'text', text: JSON.stringify(fleet, null, 2) }],
    };
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

    const kind = args.kind === 'feed' ? 'feed' : 'page';
    const robots = typeof args.robots === 'boolean' ? args.robots : true;
    const includeBody = typeof args.includeBody === 'boolean' ? args.includeBody : name === 'fetch_url';

    let requests: Array<Record<string, unknown>>;
    if (name === 'fetch_url') {
      const check = validatePublicHttpsUrl(args.url);
      if (!check.ok) return { content: [{ type: 'text', text: check.error }], isError: true };
      requests = [
        {
          id: 'mcp-1',
          url: check.url,
          kind,
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
        const check = validatePublicHttpsUrl(args.urls[i]);
        if (!check.ok) return { content: [{ type: 'text', text: `urls[${i}]: ${check.error}` }], isError: true };
        requests.push({ id: `mcp-${i + 1}`, url: check.url, kind });
      }
    }

    const callPayload = {
      maxSeconds: 60,
      options: {
        includeBody,
        robots,
        ...(typeof args.maxBytes === 'number' ? { maxBytes: Math.min(16 << 20, Math.max(1024, Math.floor(args.maxBytes))) } : {}),
        ...(typeof args.pauseMs === 'number' ? { pauseMs: Math.min(30_000, Math.max(0, Math.floor(args.pauseMs))) } : {}),
        ...(typeof args.pauseJitterMs === 'number'
          ? { pauseJitterMs: Math.min(15_000, Math.max(0, Math.floor(args.pauseJitterMs))) }
          : {}),
      },
      requests,
    };

    const res = await deps.executeFetch({
      target: rawTarget,
      ...(rawSite ? { site: rawSite } : {}),
      body: JSON.stringify(callPayload),
      principal,
    });

    let formatted: unknown = res.bodyText;
    try {
      const parsed = JSON.parse(res.bodyText) as Record<string, unknown>;
      formatted = { via: res.via, httpStatus: res.status, ...truncateResultBodies(parsed) };
    } catch {
      formatted = { via: res.via, httpStatus: res.status, raw: res.bodyText.slice(0, MAX_BODY_PREVIEW_CHARS) };
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(formatted, null, 2) }],
      ...(res.status >= 400 ? { isError: true } : {}),
    };
  }

  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}

async function dispatchRpcMessage(
  msg: JsonRpcRequest,
  scopes: string[],
  principal: string,
  userAgent: string,
  deps: McpServerDeps,
): Promise<Record<string, unknown> | null> {
  const isNotification = msg.id === undefined;
  const id = msg.id ?? null;

  if (msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return jsonRpcError(id, -32600, 'Invalid JSON-RPC 2.0 request');
  }

  if (isNotification || msg.method.startsWith('notifications/')) {
    return null;
  }

  const startedAt = Date.now();
  const authType = principal === 'owner_token' ? ('bearer_token' as const) : ('oauth' as const);
  const methodLabel =
    msg.method === 'tools/call' && typeof msg.params?.name === 'string'
      ? `tools/call:${msg.params.name}`
      : msg.method;

  await deps.activity?.recordMcpCall({
    principal,
    authType,
    userAgent,
    method: methodLabel,
    now: startedAt,
  });

  switch (msg.method) {
    case 'initialize': {
      const clientProto = typeof msg.params?.protocolVersion === 'string' ? msg.params.protocolVersion : '';
      const clientInfo = (msg.params?.clientInfo ?? {}) as { name?: string; version?: string };
      const protocolVersion = (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(clientProto)
        ? clientProto
        : DEFAULT_PROTOCOL_VERSION;
      await deps.activity?.recordEvent({
        level: 'info',
        category: 'mcp',
        event: 'mcp_initialize',
        summary: `MCP initialize from ${principal} (${clientInfo.name ?? userAgent}, proto ${protocolVersion})`,
        details: { principal, authType, clientInfo, protocolVersion, userAgent },
      });
      return jsonRpcResult(id, {
        protocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: deps.serverName, version: deps.serverVersion },
        instructions:
          'Use list_agents to inspect connected Home Assistant OS standby crawlers and 429 cooldowns, and fetch_url / fetch_batch to fetch public HTTPS feeds or pages politely.',
      });
    }
    case 'ping':
      return jsonRpcResult(id, {});
    case 'tools/list':
      await deps.activity?.recordEvent({
        level: 'info',
        category: 'mcp',
        event: 'mcp_tools_list',
        summary: `MCP tools/list queried by ${principal}`,
        details: { principal, authType, userAgent },
      });
      return jsonRpcResult(id, { tools: buildToolDefinitions(deps.allowedTargets, deps.defaultTarget) });
    case 'tools/call': {
      const toolName = typeof msg.params?.name === 'string' ? msg.params.name : '';
      const rawArgs =
        msg.params?.arguments && typeof msg.params.arguments === 'object' && !Array.isArray(msg.params.arguments)
          ? (msg.params.arguments as Record<string, unknown>)
          : {};
      if (!toolName) return jsonRpcError(id, -32602, 'Missing tool name');
      const out = await handleToolCall(toolName, rawArgs, scopes, principal, deps);
      await deps.activity?.recordEvent({
        level: out.isError ? 'warn' : 'info',
        category: 'mcp',
        event: 'mcp_tool_call',
        summary: `MCP ${toolName} called by ${principal} (${Date.now() - startedAt}ms)`,
        details: { principal, authType, toolName, args: rawArgs, durationMs: Date.now() - startedAt, isError: Boolean(out.isError) },
      });
      return jsonRpcResult(id, out);
    }
    default:
      return jsonRpcError(id, -32601, `Method not found: ${msg.method}`);
  }
}

export async function handleMcpRequest(request: Request, url: URL, deps: McpServerDeps): Promise<Response> {
  const origin = url.origin;
  if (!isAllowedMcpOrigin(request.headers.get('origin'), origin)) {
    return Response.json({ error: 'forbidden_origin' }, { status: 403 });
  }

  const cors = mcpCorsHeaders(request, origin);
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  const auth = await authorizeMcpRequest({
    request,
    origin,
    ownerSecret: deps.ownerSecret,
    store: deps.oauthStore,
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
    // Per MCP Streamable HTTP stateless specification (§2.1.2): return 405 when standalone server-push SSE is unused.
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
      const out = await dispatchRpcMessage((item ?? {}) as JsonRpcRequest, auth.scopes, auth.principal, userAgent, deps);
      if (out) replies.push(out);
    }
    if (replies.length === 0) return new Response(null, { status: 202, headers: cors });
    return Response.json(replies, {
      status: 200,
      headers: { 'cache-control': 'no-store', 'mcp-protocol-version': DEFAULT_PROTOCOL_VERSION, ...cors },
    });
  }

  const single = await dispatchRpcMessage((parsed ?? {}) as JsonRpcRequest, auth.scopes, auth.principal, userAgent, deps);
  if (!single) {
    return new Response(null, { status: 202, headers: cors });
  }
  return Response.json(single, {
    status: 200,
    headers: { 'cache-control': 'no-store', 'mcp-protocol-version': DEFAULT_PROTOCOL_VERSION, ...cors },
  });
}
