/**
 * Dual-Source Model Context Protocol (MCP) Server Discovery (`hub/src/mcp-registry.ts`).
 *
 * Queries both:
 *  1. Official Model Context Protocol Registry (`https://registry.modelcontextprotocol.io/v0/servers`)
 *  2. Glama MCP Directory (`https://glama.ai/api/mcp/v1/servers`)
 *
 * Security & Reliability Invariants:
 *  - All outbound requests use `SAFE_PUBLIC_FETCH` with `redirect: 'manual'`, `<= 10s` timeout, and `<= 2 MiB` streamed body cap.
 *  - Every advertised `remotes[].url` is validated through `isSafePublicHttpsUrl` (`https://` on port 443, public DNS only);
 *    unsafe or private-network URLs in third-party manifests are stripped before reaching `/admin` or `discover_mcps`.
 *  - Every manifest string (`title`, `description`, header descriptions) passes through invisible Unicode Tag/Bidi stripping
 *    and `detectPromptInjection` scrubbing.
 *  - Graceful partial-source fallback: if either upstream returns `429` / `5xx` / timeout, results from the healthy
 *    upstream are still returned with `partial: true` and `sourceStatus` diagnostics.
 */

import { validatePublicHttpsTargetUrl } from './overflow';
import { getRegistrableDomain, hasPrivateSharedHostingSuffix, isPublicOrPrivateSuffix } from './psl';
import { detectPromptInjection } from './scrape-advanced';

/**
 * Strips invisible Unicode Tag smuggling (`U+E0000`–`U+E007F`), Variation Selectors Supplement (`U+E0100`–`U+E01EF`),
 * Bidi overrides/isolates, zero-width / soft-hyphen characters, ANSI CSI sequences, and raw ASCII C0/DEL control bytes.
 */
export function stripMcpSmugglingChars(s: string): string {
  if (!s || !/[^\x20-\x7e\r\n\t]/.test(s)) return s;
  return s
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu,
      '',
    );
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
  sources: Array<'official-registry' | 'glama'>;
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
  const baseCheck = validatePublicHttpsTargetUrl(trimmed, selfHost);
  if (!baseCheck.ok) {
    return { ok: false, reason: baseCheck.message };
  }
  if (baseCheck.url.hash) {
    return { ok: false, reason: 'URL fragments (#) are not permitted on MCP endpoints' };
  }
  if (baseCheck.url.hostname.endsWith('.')) {
    return { ok: false, reason: 'Trailing-dot FQDN hostnames are not permitted on MCP endpoints' };
  }
  return {
    ok: true,
    url: baseCheck.url,
    normalized: baseCheck.normalized,
    origin: baseCheck.url.origin.toLowerCase(),
  };
}

export function isJsonDepthWithinLimit(rawJson: string, maxDepth = 32): boolean {
  let depth = 0;
  let inStr = false;
  let escaped = false;
  for (let i = 0; i < rawJson.length; i++) {
    const ch = rawJson.charCodeAt(i);
    if (inStr) {
      if (escaped) {
        escaped = false;
      } else if (ch === 92 /* '\\' */) {
        escaped = true;
      } else if (ch === 34 /* '"' */) {
        inStr = false;
      }
      continue;
    }
    if (ch === 34 /* '"' */) {
      inStr = true;
    } else if (ch === 91 /* '[' */ || ch === 123 /* '{' */) {
      depth++;
      if (depth > maxDepth) return false;
    } else if (ch === 93 /* ']' */ || ch === 125 /* '}' */) {
      if (depth > 0) depth--;
    }
  }
  return true;
}

function sanitizeManifestString(raw: unknown, maxLen = 600): string {
  if (typeof raw !== 'string') return '';
  const stripped = stripMcpSmugglingChars(raw).replace(/\s+/g, ' ').trim();
  if (!stripped) return '';
  const bounded = stripped.slice(0, maxLen);
  const pi = detectPromptInjection({
    markdown: bounded,
    ...(bounded.includes('<') ? { rawHtml: bounded } : {}),
  });
  if (pi.detected) {
    return '[redacted: untrusted manifest instruction blocked]';
  }
  return bounded;
}

export function slugifyMcpServerName(rawName: string): string {
  const cleaned = stripMcpSmugglingChars(rawName)
    .toLowerCase()
    .replace(/^(?:io\.github\.[^/]+\/|io\.modelcontextprotocol\.[^/]+\/|@[a-z0-9._-]+\/)/i, '')
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/[_-]{2,}/g, '-')
    .replace(/^[_-]+|[_-]+$/g, '');
  return (cleaned || 'mcp-server').slice(0, 48).replace(/^[_-]+|[_-]+$/g, '') || 'mcp-server';
}

export function isSharedHostingHostname(hostname: string): boolean {
  const clean = hostname.trim().toLowerCase().replace(/\.+$/, '');
  if (!clean) return false;
  return hasPrivateSharedHostingSuffix(clean);
}

const STRICT_CONNECTOR_DOMAIN_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export function extractRegistrableDomain(hostname: string): string | null {
  const clean = hostname.trim().toLowerCase().replace(/\.+$/, '');
  if (!clean || !STRICT_CONNECTOR_DOMAIN_RE.test(clean)) return null;
  if (/^\d+(?:\.\d+){3}$/.test(clean)) return null;
  return getRegistrableDomain(clean);
}

/**
 * Validates operator/user-supplied `domains` on a vault MCP connector:
 *  - Rejects wildcards (`*.example.com`), bare public/private suffixes (`co.uk`, `github.io`, `supabase.co`), IPs, and reserved/internal TLDs.
 *  - Rejects unrelated third-party domains (and sibling shared-hosting tenants!) unless `allowUnrelatedDomains === true`.
 */
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
  let remoteHost = '';
  try {
    remoteHost = new URL(remoteOrigin).hostname.toLowerCase().replace(/\.+$/, '');
  } catch {
    return { ok: false, error: 'Invalid remoteOrigin for domain validation' };
  }
  const remoteBase = getRegistrableDomain(remoteHost);
  const remoteIsSharedHosting = hasPrivateSharedHostingSuffix(remoteHost);
  const out: string[] = [];
  const seen = new Set<string>();

  for (const raw of rawDomains.slice(0, 16)) {
    if (typeof raw !== 'string') {
      return { ok: false, error: 'Each domain entry must be a string' };
    }
    const trimmed = raw.trim().toLowerCase().replace(/^www\./, '');
    if (!trimmed) continue;
    if (trimmed.includes('*') || trimmed.includes('/') || trimmed.includes(':') || trimmed.endsWith('.')) {
      return { ok: false, error: `Wildcard or malformed domain "${raw}" is not permitted` };
    }
    if (trimmed.length > 128 || !STRICT_CONNECTOR_DOMAIN_RE.test(trimmed)) {
      return { ok: false, error: `Invalid domain syntax "${raw}"` };
    }
    if (/\.(?:local|localhost|internal|intranet|corp|home|lan|arpa|onion)$/i.test(trimmed)) {
      return { ok: false, error: `Internal or reserved domain "${trimmed}" is not permitted` };
    }
    if (isPublicOrPrivateSuffix(trimmed)) {
      return { ok: false, error: `Shared hosting or public suffix "${trimmed}" cannot be claimed as a connector domain` };
    }
    const candBase = getRegistrableDomain(trimmed);
    if (!candBase) {
      return { ok: false, error: `Unregistrable domain "${trimmed}"` };
    }
    if (!allowUnrelatedDomains) {
      if (remoteIsSharedHosting || hasPrivateSharedHostingSuffix(trimmed)) {
        const exactOrChildHost =
          candBase === remoteBase &&
          (trimmed === remoteHost || trimmed.endsWith(`.${remoteHost}`) || remoteHost.endsWith(`.${trimmed}`));
        if (!exactOrChildHost) {
          return {
            ok: false,
            error: `Shared-hosting domain "${trimmed}" does not match exact connector host "${remoteHost}".`,
          };
        }
      } else {
        const sameHostOrSub = trimmed === remoteHost || remoteHost.endsWith(`.${trimmed}`) || trimmed.endsWith(`.${remoteHost}`);
        const sameRegistrable = Boolean(remoteBase && candBase === remoteBase);
        if (!sameHostOrSub && !sameRegistrable) {
          return {
            ok: false,
            error: `Domain "${trimmed}" does not match connector origin "${remoteHost}". Enable routeScrapeDomains / autoRouteScrape explicitly to claim external domains.`,
          };
        }
      }
    }
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      out.push(trimmed);
    }
  }
  return { ok: true, domains: out };
}

/**
 * Security Invariant (H1): Never infer third-party domains (`github.com`, `notion.so`, `linear.app`, etc.) from
 * untrusted server names, descriptions, reverse-DNS namespaces, or `websiteUrl`. Always defaults strictly to `[]`.
 */
export function inferAssociatedDomains(_params: {
  name: string;
  title?: string;
  websiteUrl?: string;
  remotes?: ReadonlyArray<{ url: string }>;
}): string[] {
  return [];
}

async function readJsonBounded(resp: Response, maxBytes: number): Promise<unknown> {
  const cl = resp.headers.get('content-length');
  if (cl !== null && cl.trim() !== '') {
    const n = Number(cl);
    if (!Number.isFinite(n) || n < 0 || n > maxBytes) {
      await resp.body?.cancel().catch(() => undefined);
      throw new Error(`Registry response exceeded ${maxBytes} bytes`);
    }
  }
  if (!resp.body) return null;
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
  const text = new TextDecoder('utf-8', { fatal: false }).decode(merged);
  const trimmed = text.trim();
  if (!trimmed) return null;
  if (!isJsonDepthWithinLimit(trimmed, 32)) {
    throw new Error('Registry JSON nesting depth exceeded limit');
  }
  return JSON.parse(trimmed);
}

const FORBIDDEN_MANIFEST_HEADER_NAMES = new Set([
  'cookie',
  'set-cookie',
  'host',
  ':authority',
  ':method',
  ':path',
  ':scheme',
  'origin',
  'referer',
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'cf-connecting-ip',
  'true-client-ip',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'upgrade',
  'te',
  'proxy-authorization',
  'mcp-session-id',
]);

function parseHeadersArray(rawHeaders: unknown): McpRemoteHeaderSpec[] {
  if (!Array.isArray(rawHeaders)) return [];
  const out: McpRemoteHeaderSpec[] = [];
  const seenNames = new Set<string>();
  for (const item of rawHeaders.slice(0, 20)) {
    if (!item || typeof item !== 'object') continue;
    const h = item as Record<string, unknown>;
    const rawName = typeof h.name === 'string' ? h.name.trim() : '';
    if (!rawName || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(rawName)) continue;
    const lower = rawName.toLowerCase();
    if (FORBIDDEN_MANIFEST_HEADER_NAMES.has(lower) || seenNames.has(lower)) continue;
    seenNames.add(lower);
    const inferredSecret =
      Boolean(h.isSecret ?? h.secret) ||
      lower === 'authorization' ||
      lower.includes('key') ||
      lower.includes('token') ||
      lower.includes('secret') ||
      lower.includes('auth');
    const desc = sanitizeManifestString(h.description, 240);
    const defVal = typeof h.default === 'string' ? sanitizeManifestString(h.default, 120) : undefined;
    const placeholder =
      typeof h.placeholder === 'string'
        ? sanitizeManifestString(h.placeholder, 120)
        : typeof h.value === 'string' && h.value.includes('{')
          ? sanitizeManifestString(h.value, 120)
          : lower === 'authorization'
            ? 'Bearer <token>'
            : undefined;
    out.push({
      name: rawName,
      ...(desc ? { description: desc } : {}),
      isRequired: Boolean(h.isRequired ?? h.required ?? true),
      isSecret: inferredSecret,
      ...(defVal && !inferredSecret ? { default: defVal } : {}),
      ...(placeholder ? { placeholder } : {}),
    });
  }
  return out;
}

function parseEnvVarsArray(rawEnvVars: unknown): McpEnvVarSpec[] {
  if (!Array.isArray(rawEnvVars)) return [];
  const out: McpEnvVarSpec[] = [];
  for (const item of rawEnvVars.slice(0, 25)) {
    if (typeof item === 'string' && /^[A-Z0-9_]{1,80}$/i.test(item.trim())) {
      const n = item.trim();
      out.push({
        name: n,
        isRequired: true,
        isSecret: /KEY|TOKEN|SECRET|PASSWORD|AUTH|PAT/i.test(n),
      });
      continue;
    }
    if (!item || typeof item !== 'object') continue;
    const ev = item as Record<string, unknown>;
    const name = typeof ev.name === 'string' ? ev.name.trim() : '';
    if (!name || !/^[A-Za-z0-9_]{1,80}$/.test(name)) continue;
    const desc = sanitizeManifestString(ev.description, 240);
    const isSecret = Boolean(ev.isSecret ?? ev.secret) || /KEY|TOKEN|SECRET|PASSWORD|AUTH|PAT/i.test(name);
    const defVal = typeof ev.default === 'string' && !isSecret ? sanitizeManifestString(ev.default, 120) : undefined;
    out.push({
      name,
      ...(desc ? { description: desc } : {}),
      isRequired: Boolean(ev.isRequired ?? ev.required ?? false),
      isSecret,
      ...(defVal ? { default: defVal } : {}),
    });
  }
  return out;
}

function parseRemotesArray(rawRemotes: unknown, selfHost?: string): McpRemoteEndpointSpec[] {
  if (!Array.isArray(rawRemotes)) return [];
  const out: McpRemoteEndpointSpec[] = [];
  const seenUrls = new Set<string>();
  for (const item of rawRemotes.slice(0, 10)) {
    if (!item || typeof item !== 'object') continue;
    const r = item as Record<string, unknown>;
    const rawType = String(r.type ?? r.transportType ?? r.transport ?? 'streamable-http')
      .trim()
      .toLowerCase();
    const type: 'streamable-http' | 'sse' | null =
      rawType === 'streamable-http' || rawType === 'http' || rawType === 'streamable_http'
        ? 'streamable-http'
        : rawType === 'sse'
          ? 'sse'
          : null;
    if (!type) continue;
    const urlCheck = isSafePublicHttpsUrl(r.url, selfHost);
    if (!urlCheck.ok) continue;
    if (seenUrls.has(urlCheck.normalized)) continue;
    seenUrls.add(urlCheck.normalized);
    out.push({
      type,
      url: urlCheck.normalized,
      headers: parseHeadersArray(r.headers),
    });
  }
  return out;
}

function parsePackagesArray(rawPackages: unknown): McpPackageSpec[] {
  if (!Array.isArray(rawPackages)) return [];
  const out: McpPackageSpec[] = [];
  for (const item of rawPackages.slice(0, 10)) {
    if (!item || typeof item !== 'object') continue;
    const p = item as Record<string, unknown>;
    const identifier = sanitizeManifestString(p.identifier ?? p.name, 160);
    if (!identifier) continue;
    const regType = sanitizeManifestString(p.registryType ?? p.registry_name, 40);
    const version = sanitizeManifestString(p.version, 48);
    const transportObj = p.transport && typeof p.transport === 'object' ? (p.transport as Record<string, unknown>) : null;
    const transport = sanitizeManifestString(transportObj?.type ?? p.transport, 40);
    out.push({
      ...(regType ? { registryType: regType } : {}),
      identifier,
      ...(version ? { version } : {}),
      ...(transport ? { transport } : {}),
      environmentVariables: parseEnvVarsArray(p.environmentVariables ?? p.environment_variables),
    });
  }
  return out;
}

export function parseOfficialRegistryPayload(payload: unknown, selfHost?: string): NormalizedMcpRegistryEntry[] {
  const list = Array.isArray(payload)
    ? payload
    : payload && typeof payload === 'object' && Array.isArray((payload as { servers?: unknown[] }).servers)
      ? (payload as { servers: unknown[] }).servers
      : [];

  const entries: NormalizedMcpRegistryEntry[] = [];
  for (const rawItem of list.slice(0, 250)) {
    if (!rawItem || typeof rawItem !== 'object') continue;
    const wrapper = rawItem as Record<string, unknown>;
    const srv =
      wrapper.server && typeof wrapper.server === 'object' && !Array.isArray(wrapper.server)
        ? (wrapper.server as Record<string, unknown>)
        : wrapper;

    const name = sanitizeManifestString(srv.name, 160);
    if (!name) continue;
    const title = sanitizeManifestString(srv.title, 140) || name;
    const description = sanitizeManifestString(srv.description, 600);
    const version = sanitizeManifestString(srv.version, 48) || undefined;

    const webCheck = isSafePublicHttpsUrl(srv.websiteUrl ?? srv.homepage, selfHost);
    const websiteUrl = webCheck.ok ? webCheck.normalized : undefined;

    const repoRaw =
      typeof srv.repository === 'string'
        ? srv.repository
        : srv.repository && typeof srv.repository === 'object'
          ? (srv.repository as { url?: unknown }).url
          : undefined;
    const repoCheck = isSafePublicHttpsUrl(repoRaw, selfHost);
    const repositoryUrl = repoCheck.ok ? repoCheck.normalized : undefined;

    const remotes = parseRemotesArray(srv.remotes, selfHost);
    const packages = parsePackagesArray(srv.packages);
    // H1: Never trust third-party domain claims (`srv.domains`) or heuristic domain inference on untrusted registry manifests!
    const domains: string[] = [];

    entries.push({
      id: name,
      slug: slugifyMcpServerName(name),
      name,
      title,
      description,
      ...(version ? { version } : {}),
      ...(websiteUrl ? { websiteUrl } : {}),
      ...(repositoryUrl ? { repositoryUrl } : {}),
      sources: ['official-registry'],
      hasRemote: remotes.length > 0,
      remotes,
      packages,
      domains,
    });
  }
  return entries;
}

export function parseGlamaRegistryPayload(payload: unknown, selfHost?: string): NormalizedMcpRegistryEntry[] {
  const list = Array.isArray(payload)
    ? payload
    : payload && typeof payload === 'object' && Array.isArray((payload as { servers?: unknown[] }).servers)
      ? (payload as { servers: unknown[] }).servers
      : [];

  const entries: NormalizedMcpRegistryEntry[] = [];
  for (const rawItem of list.slice(0, 250)) {
    if (!rawItem || typeof rawItem !== 'object') continue;
    const srv = rawItem as Record<string, unknown>;
    const namespace = sanitizeManifestString(srv.namespace, 80);
    const baseName = sanitizeManifestString(srv.slug ?? srv.name ?? srv.id, 120);
    if (!baseName) continue;
    const fullName = namespace && !baseName.includes('/') ? `${namespace}/${baseName}` : baseName;
    const title = sanitizeManifestString(srv.name ?? srv.title, 140) || fullName;
    const description = sanitizeManifestString(srv.description, 600);
    const version = sanitizeManifestString(srv.version, 48) || undefined;

    const repoRaw =
      typeof srv.repository === 'string'
        ? srv.repository
        : srv.repository && typeof srv.repository === 'object'
          ? (srv.repository as { url?: unknown }).url
          : undefined;
    const repoCheck = isSafePublicHttpsUrl(repoRaw, selfHost);
    const repositoryUrl = repoCheck.ok ? repoCheck.normalized : undefined;

    const webCheck = isSafePublicHttpsUrl(srv.homepage ?? srv.websiteUrl ?? srv.url, selfHost);
    const websiteUrl =
      webCheck.ok && !webCheck.url.hostname.toLowerCase().endsWith('glama.ai') ? webCheck.normalized : undefined;

    const remotes = parseRemotesArray(srv.remotes, selfHost);
    // Glama entries may also expose `remoteUrl` / `sseUrl` / `httpUrl` / `endpoints`
    for (const [field, rType] of [
      ['remoteUrl', 'streamable-http'],
      ['httpUrl', 'streamable-http'],
      ['streamableHttpUrl', 'streamable-http'],
      ['sseUrl', 'sse'],
    ] as const) {
      if (srv[field]) {
        const c = isSafePublicHttpsUrl(srv[field], selfHost);
        if (c.ok && !remotes.some((r) => r.url === c.normalized)) {
          remotes.push({ type: rType, url: c.normalized, headers: parseHeadersArray(srv.headers) });
        }
      }
    }
    if (Array.isArray(srv.endpoints)) {
      for (const ep of parseRemotesArray(srv.endpoints, selfHost)) {
        if (!remotes.some((r) => r.url === ep.url)) remotes.push(ep);
      }
    }

    // Parse Glama `environmentVariablesJsonSchema` (`{ properties: { API_KEY: { description } }, required: [...] }`)
    const envVars: McpEnvVarSpec[] = parseEnvVarsArray(srv.environmentVariables);
    const envSchema =
      srv.environmentVariablesJsonSchema && typeof srv.environmentVariablesJsonSchema === 'object'
        ? (srv.environmentVariablesJsonSchema as { properties?: Record<string, unknown>; required?: unknown[] })
        : null;
    if (envSchema?.properties && typeof envSchema.properties === 'object') {
      const reqSet = new Set(Array.isArray(envSchema.required) ? envSchema.required.map(String) : []);
      for (const [k, v] of Object.entries(envSchema.properties).slice(0, 20)) {
        if (!/^[A-Za-z0-9_]{1,80}$/.test(k) || envVars.some((e) => e.name === k)) continue;
        const propObj = v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
        const desc = sanitizeManifestString(propObj.description, 240);
        envVars.push({
          name: k,
          ...(desc ? { description: desc } : {}),
          isRequired: reqSet.has(k),
          isSecret: /KEY|TOKEN|SECRET|PASSWORD|AUTH|PAT/i.test(k),
        });
      }
    }

    const packages = parsePackagesArray(srv.packages);
    if (packages.length === 0 && envVars.length > 0) {
      packages.push({
        identifier: fullName,
        environmentVariables: envVars,
      });
    }

    const domains = inferAssociatedDomains({
      name: fullName,
      title,
      ...(websiteUrl ? { websiteUrl } : {}),
      remotes,
    });

    entries.push({
      id: fullName,
      slug: slugifyMcpServerName(fullName),
      name: fullName,
      title,
      description,
      ...(version ? { version } : {}),
      ...(websiteUrl ? { websiteUrl } : {}),
      ...(repositoryUrl ? { repositoryUrl } : {}),
      sources: ['glama'],
      hasRemote: remotes.length > 0,
      remotes,
      packages,
      domains,
    });
  }
  return entries;
}

function canonicalDedupeKeys(entry: NormalizedMcpRegistryEntry): string[] {
  const keys: string[] = [];
  if (entry.repositoryUrl) {
    keys.push(
      `repo:${entry.repositoryUrl
        .toLowerCase()
        .replace(/\.git$/i, '')
        .replace(/\/+$/, '')}`,
    );
  }
  for (const r of entry.remotes) {
    keys.push(`remote:${r.url.toLowerCase().replace(/\/+$/, '')}`);
  }
  keys.push(`slug:${entry.slug}`);
  return keys;
}

export function fuseRegistryEntries(
  officialEntries: readonly NormalizedMcpRegistryEntry[],
  glamaEntries: readonly NormalizedMcpRegistryEntry[],
): NormalizedMcpRegistryEntry[] {
  const merged: NormalizedMcpRegistryEntry[] = [];
  const keyToIndex = new Map<string, number>();

  const upsert = (entry: NormalizedMcpRegistryEntry) => {
    const keys = canonicalDedupeKeys(entry);
    let existingIdx: number | undefined;
    for (const k of keys) {
      const hit = keyToIndex.get(k);
      if (hit !== undefined) {
        existingIdx = hit;
        break;
      }
    }
    if (existingIdx === undefined) {
      const idx = merged.length;
      merged.push({
        ...entry,
        sources: [...entry.sources],
        remotes: [...entry.remotes],
        packages: [...entry.packages],
        domains: [...entry.domains],
      });
      for (const k of keys) keyToIndex.set(k, idx);
      return;
    }

    const target = merged[existingIdx]!;
    for (const src of entry.sources) {
      if (!target.sources.includes(src)) target.sources.push(src);
    }
    if (!target.description && entry.description) target.description = entry.description;
    if (!target.version && entry.version) target.version = entry.version;
    if (!target.websiteUrl && entry.websiteUrl) target.websiteUrl = entry.websiteUrl;
    if (!target.repositoryUrl && entry.repositoryUrl) target.repositoryUrl = entry.repositoryUrl;

    for (const rem of entry.remotes) {
      const existingRem = target.remotes.find((r) => r.url.toLowerCase() === rem.url.toLowerCase());
      if (!existingRem) {
        target.remotes.push(rem);
      } else if (existingRem.headers.length === 0 && rem.headers.length > 0) {
        existingRem.headers = rem.headers;
      }
    }
    target.hasRemote = target.remotes.length > 0;

    if (target.packages.length === 0 && entry.packages.length > 0) {
      target.packages.push(...entry.packages);
    }
    for (const d of entry.domains) {
      if (!target.domains.includes(d)) target.domains.push(d);
    }
    for (const k of keys) keyToIndex.set(k, existingIdx);
  };

  for (const e of officialEntries) upsert(e);
  for (const e of glamaEntries) upsert(e);

  // Rank servers with `streamable-http` remotes highest, then `sse` remotes, then multi-source verified entries.
  merged.sort((a, b) => {
    const aStreamHttp = a.remotes.some((r) => r.type === 'streamable-http') ? 2 : a.hasRemote ? 1 : 0;
    const bStreamHttp = b.remotes.some((r) => r.type === 'streamable-http') ? 2 : b.hasRemote ? 1 : 0;
    if (bStreamHttp !== aStreamHttp) return bStreamHttp - aStreamHttp;
    if (b.sources.length !== a.sources.length) return b.sources.length - a.sources.length;
    return a.name.localeCompare(b.name);
  });

  return merged;
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
  const q = sanitizeManifestString(params.query ?? '', 120);
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

  const fetchSource = async (targetUrl: string): Promise<unknown> => {
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
    return await readJsonBounded(resp, MAX_REGISTRY_RESPONSE_BYTES);
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
      officialEntries = parseOfficialRegistryPayload(officialOutcome.value, params.selfHost);
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
      glamaEntries = parseGlamaRegistryPayload(glamaOutcome.value, params.selfHost);
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

  let fused = fuseRegistryEntries(officialEntries, glamaEntries);
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
