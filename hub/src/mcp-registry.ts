/**
 * Dual-Source Model Context Protocol (MCP) Server Discovery (`hub/src/mcp-registry.ts`).
 *
 * Thin Cloudflare fetch/TTL-cache wrapper over Go `internal/mcpfed` (`edgefetch-core.wasm`):
 *  1. Official Model Context Protocol Registry (`https://registry.modelcontextprotocol.io/v0/servers`)
 *  2. Glama MCP Directory (`https://glama.ai/api/mcp/v1/servers`)
 */

import { callCoreWasm, callCoreWasmRaw } from './wasm-bridge';

/**
 * Strips invisible Unicode Tag smuggling (`U+E0000`–`U+E007F`), Variation Selectors Supplement (`U+E0100`–`U+E01EF`),
 * Bidi overrides/isolates, zero-width / soft-hyphen characters, ANSI CSI sequences, and raw ASCII C0/DEL control bytes.
 */
export function stripMcpSmugglingChars(s: string): string {
  if (!s || !/[^\x20-\x7e\r\n\t]/.test(s)) return s;
  return callCoreWasm<{ out: string }>('mcp_reg_strip_smuggling', { text: s }).out;
}

export const OFFICIAL_MCP_REGISTRY_URL = 'https://registry.modelcontextprotocol.io/v0/servers';
export const GLAMA_MCP_REGISTRY_URL = 'https://glama.ai/api/mcp/v1/servers';

const REGISTRY_TIMEOUT_MS = 10_000;
const MAX_REGISTRY_RESPONSE_BYTES = 2 * 1024 * 1024; // 2 MiB cap per upstream registry JSON payload
const REGISTRY_CACHE_TTL_MS = 5 * 60_000; // 5m TTL for healthy dual-source responses
const REGISTRY_PARTIAL_CACHE_TTL_MS = 15_000; // 15s short TTL when one upstream degraded
const MAX_REGISTRY_CACHE_ENTRIES = 128;

export interface McpRemoteHeaderSpec {
  name: string;
  description?: string;
  isRequired: boolean;
  isSecret: boolean;
  default?: string;
  placeholder?: string;
}

export interface McpRemoteEndpointSpec {
  type: 'streamable-http' | 'sse';
  url: string;
  headers: McpRemoteHeaderSpec[];
}

export interface McpEnvVarSpec {
  name: string;
  description?: string;
  isRequired: boolean;
  isSecret: boolean;
  default?: string;
}

export interface McpPackageSpec {
  registryType?: string;
  identifier: string;
  version?: string;
  transport?: string;
  environmentVariables: McpEnvVarSpec[];
}

export interface NormalizedMcpRegistryEntry {
  id: string;
  slug: string;
  name: string;
  title: string;
  description: string;
  version?: string;
  websiteUrl?: string;
  repositoryUrl?: string;
  sources: Array<'official-registry' | 'glama' | 'first-party'>;
  hasRemote: boolean;
  remotes: McpRemoteEndpointSpec[];
  packages: McpPackageSpec[];
  domains: string[];
}

export interface DiscoverMcpsResult {
  ok: boolean;
  status: number;
  query: string;
  remoteOnly: boolean;
  partial: boolean;
  cached: boolean;
  count: number;
  servers: NormalizedMcpRegistryEntry[];
  sourceStatus: {
    officialRegistry: 'ok' | 'error';
    glama: 'ok' | 'error';
  };
  warnings?: string[];
  error?: string;
}

/**
 * Validates that `rawUrl` is a safe public `https://` URL on port `443` with no credentials, no fragment,
 * and no loopback/private/DNS-rebinding/self-hub hostname.
 */
export function isSafePublicHttpsUrl(
  rawUrl: unknown,
  selfHost?: string,
): { ok: true; url: URL; normalized: string; origin: string } | { ok: false; reason: string } {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { ok: false, reason: 'URL must be a non-empty https:// string' };
  }
  const trimmed = rawUrl.trim();
  if (/[\r\n\0]/.test(trimmed)) {
    return { ok: false, reason: 'URL contains control characters' };
  }
  let candidate = trimmed;
  if (/[^\x20-\x7e]/.test(candidate)) {
    try {
      candidate = new URL(candidate).toString();
    } catch {
      return { ok: false, reason: `invalid URL: ${rawUrl}` };
    }
  }
  const res = callCoreWasm<{
    ok: boolean;
    normalized?: string;
    origin?: string;
    reason?: string;
  }>('mcp_reg_check_https_url', { rawUrl: candidate, selfHost: selfHost ?? '' });
  if (!res.ok || !res.normalized || !res.origin) {
    return { ok: false, reason: res.reason ?? `invalid URL: ${rawUrl}` };
  }
  return {
    ok: true,
    url: new URL(res.normalized),
    normalized: res.normalized,
    origin: res.origin,
  };
}

export function isJsonDepthWithinLimit(rawJson: string, maxDepth = 32): boolean {
  if (!rawJson) return true;
  return callCoreWasmRaw<{ withinLimit: boolean }>('mcp_reg_json_depth', { maxDepth }, rawJson).withinLimit;
}

export function slugifyMcpServerName(rawName: string): string {
  return callCoreWasm<{ slug: string }>('mcp_reg_slugify', { rawName: String(rawName ?? '') }).slug;
}

export function isSharedHostingHostname(hostname: string): boolean {
  if (!hostname || typeof hostname !== 'string') return false;
  return callCoreWasm<{ shared: boolean }>('mcp_reg_is_shared_hosting', { hostname }).shared;
}

export function extractRegistrableDomain(hostname: string): string | null {
  if (!hostname || typeof hostname !== 'string') return null;
  const dom = callCoreWasm<{ domain: string }>('mcp_reg_registrable_domain', { hostname }).domain;
  return dom || null;
}

export function validateConnectorDomains(
  rawDomains: unknown,
  remoteOrigin: string,
  allowUnrelatedDomains = false,
): { ok: true; domains: string[] } | { ok: false; error: string } {
  if (rawDomains === undefined || rawDomains === null) {
    return { ok: true, domains: [] };
  }
  if (!Array.isArray(rawDomains)) {
    return { ok: false, error: 'domains must be an array of domain strings' };
  }
  for (const item of rawDomains.slice(0, 16)) {
    if (typeof item !== 'string') {
      return { ok: false, error: 'Each domain entry must be a string' };
    }
  }
  const res = callCoreWasm<{ ok: boolean; domains?: string[]; error?: string }>('mcp_reg_validate_domains', {
    rawDomains,
    remoteOrigin: String(remoteOrigin ?? ''),
    allowUnrelatedDomains: Boolean(allowUnrelatedDomains),
  });
  if (!res.ok) {
    return { ok: false, error: res.error ?? 'Invalid connector domains' };
  }
  return { ok: true, domains: res.domains ?? [] };
}

export function inferAssociatedDomains(_params: {
  name: string;
  title?: string;
  websiteUrl?: string;
  remotes?: ReadonlyArray<{ url: string }>;
}): string[] {
  return callCoreWasm<{ domains: string[] }>('mcp_reg_infer_domains', {}).domains;
}

export function parseOfficialRegistryPayload(payload: unknown, selfHost?: string): NormalizedMcpRegistryEntry[] {
  return callCoreWasmRaw<{ entries: NormalizedMcpRegistryEntry[] }>(
    'mcp_reg_parse_official',
    { selfHost: selfHost ?? '' },
    JSON.stringify(payload ?? null),
  ).entries;
}

export function parseGlamaRegistryPayload(payload: unknown, selfHost?: string): NormalizedMcpRegistryEntry[] {
  return callCoreWasmRaw<{ entries: NormalizedMcpRegistryEntry[] }>(
    'mcp_reg_parse_glama',
    { selfHost: selfHost ?? '' },
    JSON.stringify(payload ?? null),
  ).entries;
}

export function fuseRegistryEntries(
  officialEntries: readonly NormalizedMcpRegistryEntry[],
  glamaEntries: readonly NormalizedMcpRegistryEntry[],
  /** When set, matching first-party presets (e.g. Google's hosted Maps MCP) are prepended (Go `internal/mcpfed`). */
  query?: string,
): NormalizedMcpRegistryEntry[] {
  return callCoreWasm<{ entries: NormalizedMcpRegistryEntry[] }>('mcp_reg_fuse', {
    official: officialEntries,
    glama: glamaEntries,
    ...(query ? { query } : {}),
  }).entries;
}

async function readRegistryTextBounded(resp: Response, maxBytes: number): Promise<string> {
  const cl = resp.headers.get('content-length');
  if (cl !== null && cl.trim() !== '') {
    const n = Number(cl);
    if (!Number.isFinite(n) || n < 0 || n > maxBytes) {
      await resp.body?.cancel().catch(() => undefined);
      throw new Error(`Registry response exceeded ${maxBytes} bytes`);
    }
  }
  if (!resp.body) return 'null';
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel('exceeded maxBytes').catch(() => undefined);
          throw new Error(`Registry response exceeded ${maxBytes} bytes`);
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  const trimmed = new TextDecoder('utf-8', { fatal: false }).decode(merged).trim();
  if (!trimmed) return 'null';
  if (!isJsonDepthWithinLimit(trimmed, 32)) {
    throw new Error('Registry JSON nesting depth exceeded limit');
  }
  JSON.parse(trimmed);
  return trimmed;
}

const registryCache = new Map<string, { expiresAt: number; result: DiscoverMcpsResult }>();

export function resetMcpRegistryCacheForTests(): void {
  registryCache.clear();
}

export async function discoverMcps(params: {
  query?: string;
  remoteOnly?: boolean;
  limit?: number;
  fetchFn?: typeof fetch;
  selfHost?: string;
  bypassCache?: boolean;
  now?: number;
}): Promise<DiscoverMcpsResult> {
  const q = callCoreWasm<{ out: string }>('mcp_reg_sanitize_manifest_str', {
    raw: typeof params.query === 'string' ? params.query : '',
    maxLen: 120,
  }).out;
  const remoteOnly = Boolean(params.remoteOnly);
  const limit =
    typeof params.limit === 'number' && Number.isFinite(params.limit)
      ? Math.max(1, Math.min(50, Math.floor(params.limit)))
      : 20;
  const now = params.now ?? Date.now();
  const selfHostKey = (params.selfHost ?? '').trim().toLowerCase();
  const cacheKey = `${selfHostKey}|${q.toLowerCase()}|${remoteOnly ? '1' : '0'}|${limit}`;

  if (!params.bypassCache) {
    const hit = registryCache.get(cacheKey);
    if (hit && hit.expiresAt > now) {
      return { ...hit.result, cached: true };
    }
    if (hit) registryCache.delete(cacheKey);
  }

  const fetchFn = params.fetchFn ?? fetch;
  const upstreamLimit = Math.min(50, Math.max(limit, remoteOnly ? limit * 2 : limit));

  const officialUrl = new URL(OFFICIAL_MCP_REGISTRY_URL);
  if (q) officialUrl.searchParams.set('search', q);
  officialUrl.searchParams.set('limit', String(upstreamLimit));

  const glamaUrl = new URL(GLAMA_MCP_REGISTRY_URL);
  glamaUrl.searchParams.set('query', q);
  glamaUrl.searchParams.set('first', String(upstreamLimit));

  const fetchSource = async (targetUrl: string): Promise<string> => {
    const check = isSafePublicHttpsUrl(targetUrl, params.selfHost);
    if (!check.ok) throw new Error(check.reason);
    const resp = await fetchFn(check.normalized, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'user-agent': 'EdgeFetch-MCP-Registry/2.7 (+https://edgefetch.dev)',
      },
      redirect: 'manual',
      signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS),
    });
    if (resp.status >= 300 && resp.status < 400) {
      await resp.body?.cancel().catch(() => undefined);
      throw new Error(`Unexpected HTTP ${resp.status} redirect from registry`);
    }
    if (!resp.ok) {
      await resp.body?.cancel().catch(() => undefined);
      throw new Error(`HTTP ${resp.status}`);
    }
    return await readRegistryTextBounded(resp, MAX_REGISTRY_RESPONSE_BYTES);
  };

  const [officialOutcome, glamaOutcome] = await Promise.allSettled([
    fetchSource(officialUrl.toString()),
    fetchSource(glamaUrl.toString()),
  ]);

  const warnings: string[] = [];
  let officialEntries: NormalizedMcpRegistryEntry[] = [];
  let glamaEntries: NormalizedMcpRegistryEntry[] = [];

  if (officialOutcome.status === 'fulfilled') {
    try {
      officialEntries = callCoreWasmRaw<{ entries: NormalizedMcpRegistryEntry[] }>(
        'mcp_reg_parse_official',
        { selfHost: params.selfHost ?? '' },
        officialOutcome.value,
      ).entries;
    } catch (err) {
      warnings.push(`Official MCP Registry parse error: ${err instanceof Error ? err.message : String(err)}`);
    }
  } else {
    warnings.push(
      `Official MCP Registry unavailable: ${officialOutcome.reason instanceof Error ? officialOutcome.reason.message : String(officialOutcome.reason)}`,
    );
  }

  if (glamaOutcome.status === 'fulfilled') {
    try {
      glamaEntries = callCoreWasmRaw<{ entries: NormalizedMcpRegistryEntry[] }>(
        'mcp_reg_parse_glama',
        { selfHost: params.selfHost ?? '' },
        glamaOutcome.value,
      ).entries;
    } catch (err) {
      warnings.push(`Glama MCP Directory parse error: ${err instanceof Error ? err.message : String(err)}`);
    }
  } else {
    warnings.push(
      `Glama MCP Directory unavailable: ${glamaOutcome.reason instanceof Error ? glamaOutcome.reason.message : String(glamaOutcome.reason)}`,
    );
  }

  const officialOk = officialOutcome.status === 'fulfilled';
  const glamaOk = glamaOutcome.status === 'fulfilled';

  if (!officialOk && !glamaOk) {
    return {
      ok: false,
      status: 502,
      query: q,
      remoteOnly,
      partial: false,
      cached: false,
      count: 0,
      servers: [],
      sourceStatus: { officialRegistry: 'error', glama: 'error' },
      warnings,
      error: 'registry_unavailable',
    };
  }

  let fused = fuseRegistryEntries(officialEntries, glamaEntries, q);
  if (remoteOnly) {
    fused = fused.filter((s) => s.hasRemote);
  }
  const sliced = fused.slice(0, limit);
  const partial = !officialOk || !glamaOk;

  const result: DiscoverMcpsResult = {
    ok: true,
    status: 200,
    query: q,
    remoteOnly,
    partial,
    cached: false,
    count: sliced.length,
    servers: sliced,
    sourceStatus: {
      officialRegistry: officialOk ? 'ok' : 'error',
      glama: glamaOk ? 'ok' : 'error',
    },
    ...(warnings.length > 0 ? { warnings } : {}),
  };

  const ttl = partial ? REGISTRY_PARTIAL_CACHE_TTL_MS : REGISTRY_CACHE_TTL_MS;
  registryCache.delete(cacheKey);
  registryCache.set(cacheKey, { expiresAt: now + ttl, result });
  while (registryCache.size > MAX_REGISTRY_CACHE_ENTRIES) {
    const oldest = registryCache.keys().next().value;
    if (oldest === undefined) break;
    registryCache.delete(oldest);
  }

  return result;
}
