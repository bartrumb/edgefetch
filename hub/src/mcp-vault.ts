/**
 * Per-User `AES-256-GCM` Downstream MCP Credential Vault & OAuth 2.1 PKCE Connector (`hub/src/mcp-vault.ts`).
 *
 * Thin Cloudflare SQLite/Memory persistence & OAuth HTTP wrapper delegating all HKDF-SHA256 + AES-256-GCM AEAD,
 * v2 5-field AAD binding, P6/M8 downgrade prevention, PKCE state sealing, and RFC 9728/8414 validation to Go WASM (`internal/mcpfed`).
 */

import {
  isJsonDepthWithinLimit,
  isSafePublicHttpsUrl,
  stripMcpSmugglingChars,
  validateConnectorDomains,
} from './mcp-registry';
import type { SqlStorageLike } from './oauth';
import { callCoreWasm } from './wasm-bridge';

export type { SqlStorageLike };

export const SAFE_MCP_IDENTIFIER_RE = /^[A-Za-z0-9_.-]{1,64}$/;
export const PROMPT_INJECTION_MCP_ID_RE =
  /(?:^|[_.-])(?:ignore|disregard|override|bypass|exfiltrate|jailbreak|forget)(?:[_.-]|$|[A-Z])|system[_.-]?(?:prompt|instruction|message|override)|developer[_.-]?(?:prompt|instruction|message)|prompt[_.-]?injection/i;
export const SAFE_MCP_CONNECTOR_SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;

export function isSafeMcpIdentifier(raw: string): boolean {
  if (!raw || typeof raw !== 'string') return false;
  return callCoreWasm<{ ok: boolean }>('mcp_vault_is_safe_id', { raw }).ok;
}

export function isValidMcpConnectorSlug(raw: string): boolean {
  if (!raw || typeof raw !== 'string') return false;
  return callCoreWasm<{ ok: boolean }>('mcp_vault_is_valid_slug', { raw }).ok;
}

export function normalizeMcpConnectorSlug(rawName: string): string {
  return callCoreWasm<{ slug: string }>('mcp_vault_normalize_slug', { rawName: String(rawName ?? '') }).slug;
}

export function parseAllowedMcpTools(
  raw: unknown,
): { ok: true; allowed: Set<string> } | { ok: false; error: 'invalid_allowed_mcp_tools'; message: string } {
  if (raw === undefined || raw === null) {
    return { ok: true, allowed: new Set() };
  }
  const items: unknown[] | null = raw instanceof Set ? [...raw] : Array.isArray(raw) ? raw : null;
  if (!items) {
    return {
      ok: false,
      error: 'invalid_allowed_mcp_tools',
      message: 'allowedMcpTools must be an array of exact "<slug>/<tool>" strings.',
    };
  }
  for (const entry of items) {
    if (typeof entry !== 'string') {
      return {
        ok: false,
        error: 'invalid_allowed_mcp_tools',
        message: 'Every allowedMcpTools entry must be a "<slug>/<tool>" string.',
      };
    }
  }
  const res = callCoreWasm<{ ok: boolean; allowed?: string[]; message?: string }>('mcp_vault_parse_allowed_tools', {
    raw: items,
  });
  if (!res.ok) {
    return {
      ok: false,
      error: 'invalid_allowed_mcp_tools',
      message: res.message ?? 'Invalid allowedMcpTools',
    };
  }
  return { ok: true, allowed: new Set(res.allowed ?? []) };
}

export function isCachedMcpToolPermitted(
  serverSlug: string,
  tool: CachedMcpToolSchema,
  allowedMcpTools?: ReadonlySet<string>,
): boolean {
  return callCoreWasm<{ permitted: boolean }>('mcp_vault_is_tool_permitted', {
    serverSlug: String(serverSlug ?? ''),
    tool,
    allowed: allowedMcpTools ? [...allowedMcpTools] : [],
  }).permitted;
}

export const MCP_OAUTH_STATE_TTL_MS = 10 * 60_000;
export const MCP_OAUTH_BIND_COOKIE = '__Host-ef_mcp_oauth_bind';
export const MCP_OAUTH_BIND_COOKIE_DEV = 'ef_mcp_oauth_bind';
const MAX_OAUTH_META_BYTES = 256 * 1024;
const OAUTH_META_TIMEOUT_MS = 10_000;
const MAX_VAULT_SERVERS_PER_USER = 64;
const MAX_PENDING_OAUTH_STATES_PER_USER = 16;

export interface CachedMcpToolSchema {
  name: string;
  title?: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
}

export interface VaultSecretPayload {
  kind: 'headers' | 'oauth2' | 'none';
  pinnedOrigin: string;
  pinnedUrl?: string;
  purpose?: 'user_mcp_servers:credentials';
  serverId?: string;
  slug?: string;
  authType?: 'oauth2' | 'headers' | 'none';
  headers?: Record<string, string>;
  oauth?: {
    accessToken: string;
    refreshToken?: string;
    tokenType?: string;
    expiresAt?: number;
    scope?: string;
    issuer?: string;
    resource?: string;
    tokenEndpoint: string;
    confirmedAuthOrigin?: string;
    clientId: string;
    clientSecret?: string;
  };
}

export interface MaskedAuthSummary {
  authMode: 'oauth2' | 'bearer' | 'headers' | 'none';
  headerNames: string[];
  maskedBadge: string;
  hasRefreshToken?: boolean;
  tokenExpiresAt?: number;
}

export interface StoredMcpServerRow {
  id: string;
  userId: string;
  slug: string;
  name: string;
  remoteUrl: string;
  remoteOrigin: string;
  transport: 'streamable-http' | 'sse';
  authType: 'oauth2' | 'headers' | 'none';
  encryptedCredentials: string | null;
  secretVersion?: number;
  authSummary: MaskedAuthSummary;
  domains: string[];
  autoRouteScrape?: boolean;
  cachedTools: CachedMcpToolSchema[];
  toolCount: number;
  enabled: boolean;
  lastVerifiedAt: number | null;
  lastError: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface PublicMcpServerSummary {
  id: string;
  userId: string;
  slug: string;
  name: string;
  remoteUrl: string;
  remoteOrigin: string;
  transport: 'streamable-http' | 'sse';
  authType: 'oauth2' | 'headers' | 'none';
  authSummary: MaskedAuthSummary;
  domains: string[];
  autoRouteScrape: boolean;
  tools: CachedMcpToolSchema[];
  toolCount: number;
  enabled: boolean;
  lastVerifiedAt: number | null;
  lastError: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface PendingMcpOAuthStateRow {
  stateHash: string;
  userId: string;
  slug: string;
  name: string;
  remoteUrl: string;
  remoteOrigin: string;
  transport: 'streamable-http' | 'sse';
  domains: string[];
  autoRouteScrape?: boolean;
  confirmedAuthOrigin?: string;
  encryptedPkceBlob: string;
  expiresAt: number;
}

export interface McpVaultStore {
  listServers(userId: string): Promise<StoredMcpServerRow[]> | StoredMcpServerRow[];
  getServer(userId: string, slugOrId: string): Promise<StoredMcpServerRow | null> | StoredMcpServerRow | null;
  upsertServer(row: StoredMcpServerRow): Promise<void> | void;
  resealServerSecret?(params: {
    id: string;
    userId: string;
    expectedEncryptedCredentials?: string;
    encryptedCredentials: string;
    secretVersion: number;
    updatedAt: number;
  }): Promise<boolean> | boolean;
  deleteServer(userId: string, slug: string): Promise<boolean> | boolean;
  putOAuthState(row: PendingMcpOAuthStateRow): Promise<void> | void;
  consumeOAuthState(
    stateHash: string,
    userId: string,
    now: number,
  ): Promise<PendingMcpOAuthStateRow | null> | PendingMcpOAuthStateRow | null;
}

export const MCP_VAULT_SQLITE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS user_mcp_servers (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT 'owner',
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    remote_url TEXT NOT NULL,
    remote_origin TEXT NOT NULL,
    transport TEXT NOT NULL DEFAULT 'streamable-http',
    auth_type TEXT NOT NULL DEFAULT 'headers',
    encrypted_credentials TEXT,
    secret_version INTEGER NOT NULL DEFAULT 1,
    auth_summary_json TEXT NOT NULL DEFAULT '{}',
    domains_json TEXT NOT NULL DEFAULT '[]',
    auto_route_scrape INTEGER NOT NULL DEFAULT 0,
    cached_tools_json TEXT NOT NULL DEFAULT '[]',
    tool_count INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_verified_at INTEGER,
    last_error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (user_id, slug)
  );
  CREATE INDEX IF NOT EXISTS idx_user_mcp_servers_user ON user_mcp_servers(user_id);
  CREATE TABLE IF NOT EXISTS mcp_oauth_states (
    state_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT 'owner',
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    remote_url TEXT NOT NULL,
    remote_origin TEXT NOT NULL,
    transport TEXT NOT NULL,
    domains_json TEXT NOT NULL,
    auto_route_scrape INTEGER NOT NULL DEFAULT 0,
    confirmed_auth_origin TEXT,
    encrypted_pkce_blob TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`;

export function resolveCallerUserId(auth?: { userId?: string; principal?: string } | null): string {
  const rawUserId = typeof auth?.userId === 'string' ? auth.userId : '';
  const rawPrincipal = typeof auth?.principal === 'string' ? auth.principal : '';
  return callCoreWasm<{ userId: string }>('mcp_vault_resolve_user_id', {
    userId: rawUserId,
    principal: rawPrincipal,
  }).userId;
}

export function toPublicMcpServerSummary(row: StoredMcpServerRow): PublicMcpServerSummary {
  return callCoreWasm<{ summary: PublicMcpServerSummary }>('mcp_vault_public_summary', { row }).summary;
}

export function validateVaultMasterKey(
  vaultMasterKey: string | undefined,
): { ok: true; key: string } | { ok: false; status: 503; error: 'vault_master_key_unconfigured'; message: string } {
  const res = callCoreWasm<{
    ok: boolean;
    key?: string;
    message?: string;
  }>('mcp_vault_validate_master_key', { vaultMasterKey: vaultMasterKey ?? '' });
  if (!res.ok || !res.key) {
    return {
      ok: false,
      status: 503,
      error: 'vault_master_key_unconfigured',
      message: res.message ?? 'VAULT_MASTER_KEY unconfigured',
    };
  }
  return { ok: true, key: res.key };
}

const vaultTextEncoder = new TextEncoder();
const vaultTextDecoder = new TextDecoder();

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(raw: string): Uint8Array {
  const b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

async function deriveVaultAesGcmKey(cleanMasterKey: string, salt: Uint8Array, hkdfInfo: string): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    vaultTextEncoder.encode(cleanMasterKey),
    { name: 'HKDF' },
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      info: vaultTextEncoder.encode(hkdfInfo),
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function sha256Base64UrlHost(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', vaultTextEncoder.encode(input));
  return bytesToBase64Url(new Uint8Array(digest));
}

async function computeOAuthBindHmacHost(cleanMasterKey: string, userId: string, state: string, sessionCsrf: string): Promise<string> {
  const { macKey, macMessage } = callCoreWasm<{ macKey: string; macMessage: string }>('mcp_vault_prepare_oauth_bind', {
    vaultMasterKey: cleanMasterKey,
    userId,
    state,
    sessionCsrf,
  });
  const key = await crypto.subtle.importKey(
    'raw',
    vaultTextEncoder.encode(macKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, vaultTextEncoder.encode(macMessage));
  return bytesToBase64Url(new Uint8Array(sig));
}

async function verifyOAuthBindHmacHost(
  presented: string,
  cleanMasterKey: string,
  userId: string,
  state: string,
  sessionCsrf: string,
): Promise<boolean> {
  if (!presented || !/^[A-Za-z0-9_-]{43}$/.test(presented)) return false;
  const { macKey, macMessage } = callCoreWasm<{ macKey: string; macMessage: string }>('mcp_vault_prepare_oauth_bind', {
    vaultMasterKey: cleanMasterKey,
    userId,
    state,
    sessionCsrf,
  });
  const key = await crypto.subtle.importKey(
    'raw',
    vaultTextEncoder.encode(macKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const sigBytes = base64UrlToBytes(presented);
  return crypto.subtle.verify('HMAC', key, sigBytes as BufferSource, vaultTextEncoder.encode(macMessage));
}

export async function sealVaultCredentials(params: {
  vaultMasterKey: string | undefined;
  userId: string;
  remoteOrigin: string;
  id?: string;
  serverId?: string;
  slug?: string;
  authType?: 'oauth2' | 'headers' | 'none' | string;
  payload: VaultSecretPayload;
}): Promise<
  | { ok: true; ciphertext: string; secretVersion: number }
  | {
      ok: false;
      status: 400 | 503;
      error: 'vault_master_key_unconfigured' | 'invalid_slug';
      message: string;
    }
> {
  const prep = callCoreWasm<{
    ok: boolean;
    cleanKey?: string;
    hkdfInfo?: string;
    aad?: string;
    plaintext?: string;
    envelopeVersion?: string;
    secretVersion?: number;
    status?: 400 | 503;
    error?: 'vault_master_key_unconfigured' | 'invalid_slug';
    message?: string;
  }>('mcp_vault_prepare_seal', {
    vaultMasterKey: params.vaultMasterKey ?? '',
    userId: params.userId,
    remoteOrigin: params.remoteOrigin,
    ...(params.id !== undefined ? { id: params.id } : {}),
    ...(params.serverId !== undefined ? { serverId: params.serverId } : {}),
    ...(params.slug !== undefined ? { slug: params.slug } : {}),
    ...(params.authType !== undefined ? { authType: params.authType } : {}),
    payload: params.payload,
  });
  if (!prep.ok || !prep.cleanKey || !prep.hkdfInfo || prep.aad === undefined || prep.plaintext === undefined) {
    return {
      ok: false,
      status: prep.status ?? 503,
      error: prep.error ?? 'vault_master_key_unconfigured',
      message: prep.message ?? 'Vault encryption failed',
    };
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveVaultAesGcmKey(prep.cleanKey, salt, prep.hkdfInfo);
  const encryptedBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: vaultTextEncoder.encode(prep.aad) },
    aesKey,
    vaultTextEncoder.encode(prep.plaintext),
  );
  return {
    ok: true,
    ciphertext: `${prep.envelopeVersion ?? 'v2'}.${bytesToBase64Url(salt)}.${bytesToBase64Url(iv)}.${bytesToBase64Url(new Uint8Array(encryptedBuf))}`,
    secretVersion: prep.secretVersion ?? 1,
  };
}

export async function unsealVaultCredentials(params: {
  vaultMasterKey: string | undefined;
  userId: string;
  remoteOrigin: string;
  remoteUrl?: string;
  id?: string;
  serverId?: string;
  slug?: string;
  authType?: 'oauth2' | 'headers' | 'none' | string;
  secretVersion?: number;
  ciphertext: string;
}): Promise<
  | { ok: true; payload: VaultSecretPayload; resealedCiphertext?: string; resealedSecretVersion?: number }
  | { ok: false; error: 'vault_master_key_unconfigured' | 'vault_decryption_failed'; message: string }
> {
  if (!params.ciphertext || typeof params.ciphertext !== 'string') {
    return { ok: false, error: 'vault_decryption_failed', message: 'Malformed vault ciphertext envelope' };
  }
  const wireReq = {
    vaultMasterKey: params.vaultMasterKey ?? '',
    userId: params.userId,
    remoteOrigin: params.remoteOrigin,
    ...(params.remoteUrl ? { remoteUrl: params.remoteUrl } : {}),
    ...(params.id !== undefined ? { id: params.id } : {}),
    ...(params.serverId !== undefined ? { serverId: params.serverId } : {}),
    ...(params.slug !== undefined ? { slug: params.slug } : {}),
    ...(params.authType !== undefined ? { authType: params.authType } : {}),
    ...(typeof params.secretVersion === 'number' ? { secretVersion: params.secretVersion } : {}),
    ciphertext: params.ciphertext,
  };
  const prep = callCoreWasm<{
    ok: boolean;
    cleanKey?: string;
    saltB64?: string;
    ivB64?: string;
    ctB64?: string;
    attempts?: Array<{ hkdfInfo: string; aad: string; shouldReseal: boolean; failMessage: string }>;
    error?: 'vault_master_key_unconfigured' | 'vault_decryption_failed';
    message?: string;
  }>('mcp_vault_prepare_unseal', wireReq);
  if (!prep.ok || !prep.cleanKey || !prep.saltB64 || !prep.ivB64 || !prep.ctB64 || !prep.attempts?.length) {
    return {
      ok: false,
      error: prep.error ?? 'vault_decryption_failed',
      message: prep.message ?? 'Vault decryption failed',
    };
  }
  const salt = base64UrlToBytes(prep.saltB64);
  const iv = base64UrlToBytes(prep.ivB64);
  const ct = base64UrlToBytes(prep.ctB64);

  let plainText: string | null = null;
  let shouldReseal = false;
  let lastFailMsg = 'AES-256-GCM authentication failed';
  for (const att of prep.attempts) {
    lastFailMsg = att.failMessage;
    try {
      const aesKey = await deriveVaultAesGcmKey(prep.cleanKey, salt, att.hkdfInfo);
      const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as BufferSource, additionalData: vaultTextEncoder.encode(att.aad) },
        aesKey,
        ct as BufferSource,
      );
      plainText = new TextDecoder('utf-8', { fatal: true }).decode(plainBuf);
      shouldReseal = att.shouldReseal;
      break;
    } catch {
      // try next downgrade-allowed attempt
    }
  }
  if (plainText === null) {
    return { ok: false, error: 'vault_decryption_failed', message: lastFailMsg };
  }

  const verified = callCoreWasm<{
    ok: boolean;
    payload?: VaultSecretPayload;
    needsReseal?: boolean;
    error?: 'vault_master_key_unconfigured' | 'vault_decryption_failed';
    message?: string;
  }>('mcp_vault_verify_unseal', {
    ...wireReq,
    plaintext: plainText,
    attemptShouldReseal: shouldReseal,
  });
  if (!verified.ok || !verified.payload) {
    return {
      ok: false,
      error: verified.error ?? 'vault_decryption_failed',
      message: verified.message ?? 'Vault decryption failed',
    };
  }
  if (verified.needsReseal) {
    const resealed = await sealVaultCredentials({
      vaultMasterKey: prep.cleanKey,
      userId: params.userId,
      remoteOrigin: params.remoteOrigin,
      ...(params.id !== undefined ? { id: params.id } : {}),
      ...(params.serverId !== undefined ? { serverId: params.serverId } : {}),
      ...(params.slug !== undefined ? { slug: params.slug } : {}),
      ...(params.authType !== undefined ? { authType: params.authType } : {}),
      payload: verified.payload,
    });
    if (resealed.ok) {
      return {
        ok: true,
        payload: verified.payload,
        resealedCiphertext: resealed.ciphertext,
        resealedSecretVersion: resealed.secretVersion,
      };
    }
  }
  return { ok: true, payload: verified.payload };
}

export function sanitizeSecretHeadersInput(params: {
  bearerToken?: unknown;
  headers?: unknown;
}): { ok: true; headers: Record<string, string> } | { ok: false; error: string } {
  const hasHeaders = params.headers !== undefined && params.headers !== null;
  if (hasHeaders) {
    if (typeof params.headers !== 'object' || Array.isArray(params.headers)) {
      return { ok: false, error: 'headers must be a JSON object mapping header names to string values' };
    }
    for (const [k, v] of Object.entries(params.headers as Record<string, unknown>)) {
      if (v !== undefined && v !== null && typeof v !== 'string') {
        return { ok: false, error: `Header "${k}" value must be a string` };
      }
    }
  }
  const res = callCoreWasm<{ ok: boolean; headers?: Record<string, string>; error?: string }>(
    'mcp_vault_sanitize_headers',
    {
      ...(typeof params.bearerToken === 'string' ? { bearerToken: params.bearerToken } : {}),
      headers: hasHeaders ? params.headers : null,
      hasHeaders,
    },
  );
  if (!res.ok) {
    return { ok: false, error: res.error ?? 'Invalid custom headers' };
  }
  return { ok: true, headers: res.headers ?? {} };
}

export function buildMaskedAuthSummary(payload: VaultSecretPayload): MaskedAuthSummary {
  return callCoreWasm<{ summary: MaskedAuthSummary }>('mcp_vault_masked_auth_summary', { payload }).summary;
}

export function filterSafeCachedMcpTools(rawTools: unknown): CachedMcpToolSchema[] {
  if (!Array.isArray(rawTools)) return [];
  return callCoreWasm<{ tools: CachedMcpToolSchema[] }>('mcp_vault_filter_cached_tools', {
    tools: rawTools.slice(0, 64),
  }).tools;
}

function parseStoredRow(r: Record<string, unknown>): StoredMcpServerRow {
  let authSummary: MaskedAuthSummary = { authMode: 'none', headerNames: [], maskedBadge: 'Configured' };
  let domains: string[] = [];
  let cachedTools: CachedMcpToolSchema[] = [];
  try {
    if (typeof r.auth_summary_json === 'string' && r.auth_summary_json) {
      authSummary = JSON.parse(r.auth_summary_json) as MaskedAuthSummary;
    }
  } catch {
    // ignore
  }
  try {
    if (typeof r.domains_json === 'string' && r.domains_json) {
      const parsed = JSON.parse(r.domains_json);
      if (Array.isArray(parsed)) domains = parsed.filter((x): x is string => typeof x === 'string');
    }
  } catch {
    // ignore
  }
  try {
    if (typeof r.cached_tools_json === 'string' && r.cached_tools_json) {
      cachedTools = filterSafeCachedMcpTools(JSON.parse(r.cached_tools_json));
    }
  } catch {
    // ignore
  }
  const rawTransport = String(r.transport ?? 'streamable-http');
  const rawAuthType = String(r.auth_type ?? 'headers');
  const rawSecretVer = Number(r.secret_version ?? 1);
  return {
    id: String(r.id),
    userId: String(r.user_id ?? 'owner'),
    slug: String(r.slug),
    name: String(r.name),
    remoteUrl: String(r.remote_url),
    remoteOrigin: String(r.remote_origin),
    transport: rawTransport === 'sse' ? 'sse' : 'streamable-http',
    authType: rawAuthType === 'oauth2' ? 'oauth2' : rawAuthType === 'none' ? 'none' : 'headers',
    encryptedCredentials: typeof r.encrypted_credentials === 'string' && r.encrypted_credentials ? r.encrypted_credentials : null,
    secretVersion: Number.isInteger(rawSecretVer) && rawSecretVer >= 1 ? rawSecretVer : 1,
    authSummary,
    domains,
    autoRouteScrape: Number(r.auto_route_scrape ?? 0) !== 0,
    cachedTools,
    toolCount: Number(r.tool_count ?? cachedTools.length),
    enabled: Number(r.enabled ?? 1) !== 0,
    lastVerifiedAt: typeof r.last_verified_at === 'number' ? r.last_verified_at : null,
    lastError: typeof r.last_error === 'string' && r.last_error ? r.last_error : null,
    createdAt: Number(r.created_at ?? 0),
    updatedAt: Number(r.updated_at ?? 0),
  };
}

export function createSqliteMcpVaultStore(sql: SqlStorageLike): McpVaultStore {
  let initialized = false;
  const ensureTables = () => {
    if (initialized) return;
    sql.exec(
      `CREATE TABLE IF NOT EXISTS user_mcp_servers (
         id TEXT PRIMARY KEY,
         user_id TEXT NOT NULL DEFAULT 'owner',
         slug TEXT NOT NULL,
         name TEXT NOT NULL,
         remote_url TEXT NOT NULL,
         remote_origin TEXT NOT NULL,
         transport TEXT NOT NULL DEFAULT 'streamable-http',
         auth_type TEXT NOT NULL DEFAULT 'headers',
         secret_version INTEGER NOT NULL DEFAULT 1,
         encrypted_credentials TEXT,
         auth_summary_json TEXT NOT NULL DEFAULT '{}',
         domains_json TEXT NOT NULL DEFAULT '[]',
         auto_route_scrape INTEGER NOT NULL DEFAULT 0,
         cached_tools_json TEXT NOT NULL DEFAULT '[]',
         tool_count INTEGER NOT NULL DEFAULT 0,
         enabled INTEGER NOT NULL DEFAULT 1,
         last_verified_at INTEGER,
         last_error TEXT,
         created_at INTEGER NOT NULL,
         updated_at INTEGER NOT NULL,
         UNIQUE (user_id, slug)
       )`,
    );
    sql.exec('CREATE INDEX IF NOT EXISTS idx_user_mcp_servers_user ON user_mcp_servers(user_id)');
    try {
      sql.exec('ALTER TABLE user_mcp_servers ADD COLUMN auto_route_scrape INTEGER NOT NULL DEFAULT 0');
    } catch {
      // Column already exists
    }
    try {
      sql.exec('ALTER TABLE user_mcp_servers ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1');
    } catch {
      // Column already exists
    }
    sql.exec(
      `CREATE TABLE IF NOT EXISTS mcp_oauth_states (
         state_hash TEXT PRIMARY KEY,
         user_id TEXT NOT NULL DEFAULT 'owner',
         slug TEXT NOT NULL,
         name TEXT NOT NULL,
         remote_url TEXT NOT NULL,
         remote_origin TEXT NOT NULL,
         transport TEXT NOT NULL,
         domains_json TEXT NOT NULL,
         auto_route_scrape INTEGER NOT NULL DEFAULT 0,
         confirmed_auth_origin TEXT,
         encrypted_pkce_blob TEXT NOT NULL,
         expires_at INTEGER NOT NULL
       )`,
    );
    try {
      sql.exec('ALTER TABLE mcp_oauth_states ADD COLUMN auto_route_scrape INTEGER NOT NULL DEFAULT 0');
    } catch {
      // Column already exists
    }
    try {
      sql.exec('ALTER TABLE mcp_oauth_states ADD COLUMN confirmed_auth_origin TEXT');
    } catch {
      // Column already exists
    }
    initialized = true;
  };

  return {
    listServers(userId) {
      ensureTables();
      const uid = userId.trim() || 'owner';
      return sql
        .exec<Record<string, unknown>>('SELECT * FROM user_mcp_servers WHERE user_id = ? ORDER BY updated_at DESC', uid)
        .toArray()
        .map(parseStoredRow);
    },
    getServer(userId, slugOrId) {
      ensureTables();
      const uid = userId.trim() || 'owner';
      const needle = slugOrId.trim().toLowerCase();
      if (!needle || needle.includes('__')) return null;
      const direct = sql
        .exec<Record<string, unknown>>(
          'SELECT * FROM user_mcp_servers WHERE user_id = ? AND (LOWER(slug) = ? OR LOWER(id) = ?) LIMIT 1',
          uid,
          needle,
          needle,
        )
        .toArray()[0];
      return direct ? parseStoredRow(direct) : null;
    },
    upsertServer(row) {
      ensureTables();
      const uid = row.userId.trim() || 'owner';
      const cleanSlug = row.slug.trim().toLowerCase();
      if (!isValidMcpConnectorSlug(cleanSlug)) {
        throw new Error(`Invalid MCP connector slug "${row.slug}": must match /^[a-z0-9][a-z0-9_-]{0,47}$/ without "__"`);
      }
      const safeTools = filterSafeCachedMcpTools(row.cachedTools);
      const safeToolCount = Array.isArray(row.cachedTools) && row.cachedTools.length > 0 ? safeTools.length : row.toolCount;
      const secretVersion =
        typeof row.secretVersion === 'number' && Number.isInteger(row.secretVersion) && row.secretVersion >= 1
          ? row.secretVersion
          : 1;
      sql.exec(
        `DELETE FROM user_mcp_servers
         WHERE user_id = ? AND slug != ? AND id IN (
           SELECT id FROM user_mcp_servers WHERE user_id = ? ORDER BY updated_at DESC LIMIT -1 OFFSET ?
         )`,
        uid,
        cleanSlug,
        uid,
        MAX_VAULT_SERVERS_PER_USER - 1,
      );
      sql.exec(
        `INSERT INTO user_mcp_servers (
           id, user_id, slug, name, remote_url, remote_origin, transport, auth_type,
           encrypted_credentials, secret_version, auth_summary_json, domains_json, auto_route_scrape, cached_tools_json,
           tool_count, enabled, last_verified_at, last_error, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, slug) DO UPDATE SET
           name = excluded.name,
           remote_url = excluded.remote_url,
           remote_origin = excluded.remote_origin,
           transport = excluded.transport,
           auth_type = excluded.auth_type,
           encrypted_credentials = excluded.encrypted_credentials,
           secret_version = excluded.secret_version,
           auth_summary_json = excluded.auth_summary_json,
           domains_json = excluded.domains_json,
           auto_route_scrape = excluded.auto_route_scrape,
           cached_tools_json = excluded.cached_tools_json,
           tool_count = excluded.tool_count,
           enabled = excluded.enabled,
           last_verified_at = excluded.last_verified_at,
           last_error = excluded.last_error,
           updated_at = excluded.updated_at`,
        row.id,
        uid,
        cleanSlug,
        row.name,
        row.remoteUrl,
        row.remoteOrigin,
        row.transport,
        row.authType,
        row.encryptedCredentials,
        secretVersion,
        JSON.stringify(row.authSummary),
        JSON.stringify(row.domains),
        row.autoRouteScrape ? 1 : 0,
        JSON.stringify(safeTools),
        safeToolCount,
        row.enabled ? 1 : 0,
        row.lastVerifiedAt,
        row.lastError,
        row.createdAt,
        row.updatedAt,
      );
    },
    resealServerSecret(p) {
      ensureTables();
      const uid = p.userId.trim() || 'owner';
      if (!p.expectedEncryptedCredentials || typeof p.expectedEncryptedCredentials !== 'string') {
        return false;
      }
      const updated = sql
        .exec<{ id: string }>(
          `UPDATE user_mcp_servers
              SET encrypted_credentials = ?,
                  secret_version = ?,
                  updated_at = ?
            WHERE user_id = ? AND id = ? AND encrypted_credentials = ? AND secret_version <= ?
            RETURNING id`,
          p.encryptedCredentials,
          p.secretVersion,
          p.updatedAt,
          uid,
          p.id,
          p.expectedEncryptedCredentials,
          p.secretVersion,
        )
        .toArray();
      return updated.length > 0;
    },
    deleteServer(userId, slug) {
      ensureTables();
      const uid = userId.trim() || 'owner';
      const cleanSlug = slug.trim().toLowerCase();
      const existing = sql
        .exec<{ id: string }>('SELECT id FROM user_mcp_servers WHERE user_id = ? AND slug = ? LIMIT 1', uid, cleanSlug)
        .toArray()[0];
      if (!existing) return false;
      sql.exec('DELETE FROM user_mcp_servers WHERE user_id = ? AND slug = ?', uid, cleanSlug);
      return true;
    },
    putOAuthState(row) {
      ensureTables();
      const uid = row.userId.trim() || 'owner';
      sql.exec('DELETE FROM mcp_oauth_states WHERE expires_at <= ?', row.expiresAt - MCP_OAUTH_STATE_TTL_MS);
      sql.exec(
        `DELETE FROM mcp_oauth_states
         WHERE user_id = ? AND state_hash IN (
           SELECT state_hash FROM mcp_oauth_states WHERE user_id = ? ORDER BY expires_at DESC LIMIT -1 OFFSET ?
         )`,
        uid,
        uid,
        MAX_PENDING_OAUTH_STATES_PER_USER - 1,
      );
      sql.exec(
        `INSERT OR REPLACE INTO mcp_oauth_states (
           state_hash, user_id, slug, name, remote_url, remote_origin, transport, domains_json, auto_route_scrape, confirmed_auth_origin, encrypted_pkce_blob, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        row.stateHash,
        uid,
        row.slug,
        row.name,
        row.remoteUrl,
        row.remoteOrigin,
        row.transport,
        JSON.stringify(row.domains),
        row.autoRouteScrape ? 1 : 0,
        row.confirmedAuthOrigin ?? null,
        row.encryptedPkceBlob,
        row.expiresAt,
      );
    },
    consumeOAuthState(stateHash, userId, now) {
      ensureTables();
      const uid = userId.trim() || 'owner';
      const rows = sql
        .exec<Record<string, unknown>>(
          'SELECT * FROM mcp_oauth_states WHERE state_hash = ? AND user_id = ? LIMIT 1',
          stateHash,
          uid,
        )
        .toArray();
      sql.exec('DELETE FROM mcp_oauth_states WHERE (state_hash = ? AND user_id = ?) OR expires_at <= ?', stateHash, uid, now);
      const r = rows[0];
      if (!r || Number(r.expires_at ?? 0) <= now) return null;
      let domains: string[] = [];
      try {
        const parsed = JSON.parse(String(r.domains_json ?? '[]'));
        if (Array.isArray(parsed)) domains = parsed.filter((x): x is string => typeof x === 'string');
      } catch {
        // ignore
      }
      return {
        stateHash: String(r.state_hash),
        userId: String(r.user_id ?? 'owner'),
        slug: String(r.slug),
        name: String(r.name),
        remoteUrl: String(r.remote_url),
        remoteOrigin: String(r.remote_origin),
        transport: String(r.transport) === 'sse' ? 'sse' : 'streamable-http',
        domains,
        autoRouteScrape: Number(r.auto_route_scrape ?? 0) !== 0,
        ...(typeof r.confirmed_auth_origin === 'string' && r.confirmed_auth_origin
          ? { confirmedAuthOrigin: r.confirmed_auth_origin }
          : {}),
        encryptedPkceBlob: String(r.encrypted_pkce_blob),
        expiresAt: Number(r.expires_at),
      };
    },
  };
}

export function createMemoryMcpVaultStore(): McpVaultStore {
  const servers = new Map<string, StoredMcpServerRow>();
  const states = new Map<string, PendingMcpOAuthStateRow>();
  const keyOf = (u: string, s: string) => `${u.trim() || 'owner'}|${s.trim().toLowerCase()}`;

  return {
    listServers(userId) {
      const uid = userId.trim() || 'owner';
      return [...servers.values()]
        .filter((s) => s.userId === uid)
        .sort((a, b) => b.updatedAt - a.updatedAt)
        .map((s) => structuredClone(s));
    },
    getServer(userId, slugOrId) {
      const uid = userId.trim() || 'owner';
      const needle = slugOrId.trim().toLowerCase();
      if (!needle || needle.includes('__')) return null;
      const direct = servers.get(keyOf(uid, needle));
      if (direct) return structuredClone(direct);
      for (const s of servers.values()) {
        if (s.userId === uid && (s.slug.toLowerCase() === needle || s.id.toLowerCase() === needle)) {
          return structuredClone(s);
        }
      }
      return null;
    },
    upsertServer(row) {
      const uid = row.userId.trim() || 'owner';
      const cleanSlug = row.slug.trim().toLowerCase();
      if (!isValidMcpConnectorSlug(cleanSlug)) {
        throw new Error(`Invalid MCP connector slug "${row.slug}": must match /^[a-z0-9][a-z0-9_-]{0,47}$/ without "__"`);
      }
      const safeTools = filterSafeCachedMcpTools(row.cachedTools);
      const safeToolCount = Array.isArray(row.cachedTools) && row.cachedTools.length > 0 ? safeTools.length : row.toolCount;
      const secretVersion =
        typeof row.secretVersion === 'number' && Number.isInteger(row.secretVersion) && row.secretVersion >= 1
          ? row.secretVersion
          : 1;
      const userRows = [...servers.entries()].filter(([, v]) => v.userId === uid && v.slug.toLowerCase() !== cleanSlug);
      if (userRows.length >= MAX_VAULT_SERVERS_PER_USER) {
        userRows.sort((a, b) => a[1].updatedAt - b[1].updatedAt);
        for (let i = 0; i <= userRows.length - MAX_VAULT_SERVERS_PER_USER; i++) {
          servers.delete(userRows[i]![0]);
        }
      }
      servers.set(
        keyOf(uid, cleanSlug),
        structuredClone({ ...row, slug: cleanSlug, userId: uid, secretVersion, cachedTools: safeTools, toolCount: safeToolCount }),
      );
    },
    resealServerSecret(p) {
      const uid = p.userId.trim() || 'owner';
      if (!p.expectedEncryptedCredentials || typeof p.expectedEncryptedCredentials !== 'string') {
        return false;
      }
      for (const [k, s] of servers.entries()) {
        if (
          s.id === p.id &&
          s.userId === uid &&
          s.encryptedCredentials === p.expectedEncryptedCredentials &&
          (s.secretVersion ?? 1) <= p.secretVersion
        ) {
          servers.set(k, {
            ...s,
            encryptedCredentials: p.encryptedCredentials,
            secretVersion: p.secretVersion,
            updatedAt: p.updatedAt,
          });
          return true;
        }
      }
      return false;
    },
    deleteServer(userId, slug) {
      return servers.delete(keyOf(userId, slug));
    },
    putOAuthState(row) {
      const uid = row.userId.trim() || 'owner';
      const approxNow = row.expiresAt - MCP_OAUTH_STATE_TTL_MS;
      for (const [k, v] of states.entries()) {
        if (v.expiresAt <= approxNow) states.delete(k);
      }
      const userStates = [...states.entries()].filter(([, v]) => v.userId === uid);
      if (userStates.length >= MAX_PENDING_OAUTH_STATES_PER_USER) {
        userStates.sort((a, b) => a[1].expiresAt - b[1].expiresAt);
        for (let i = 0; i <= userStates.length - MAX_PENDING_OAUTH_STATES_PER_USER; i++) {
          states.delete(userStates[i]![0]);
        }
      }
      states.set(row.stateHash, structuredClone({ ...row, userId: uid }));
    },
    consumeOAuthState(stateHash, userId, now) {
      const uid = userId.trim() || 'owner';
      for (const [k, v] of states.entries()) {
        if (v.expiresAt <= now) states.delete(k);
      }
      const hit = states.get(stateHash);
      if (!hit || hit.userId !== uid) return null;
      states.delete(stateHash);
      if (hit.expiresAt <= now) return null;
      return structuredClone(hit);
    },
  };
}

async function fetchJsonSafeBounded(
  targetUrl: string,
  fetchFn: typeof fetch,
  selfHost: string | undefined,
  init?: RequestInit,
): Promise<{ status: number; headers: Headers; json: Record<string, unknown> | null }> {
  const check = isSafePublicHttpsUrl(targetUrl, selfHost);
  if (!check.ok) throw new Error(check.reason);
  const resp = await fetchFn(check.normalized, {
    ...init,
    redirect: 'manual',
    signal: init?.signal ?? AbortSignal.timeout(OAUTH_META_TIMEOUT_MS),
  });
  if (resp.status >= 300 && resp.status < 400) {
    await resp.body?.cancel().catch(() => undefined);
    throw new Error(`Disallowed redirect HTTP ${resp.status} from ${check.url.hostname}`);
  }
  const cl = resp.headers.get('content-length');
  if (cl !== null && cl.trim() !== '') {
    const n = Number(cl);
    if (!Number.isFinite(n) || n < 0 || n > MAX_OAUTH_META_BYTES) {
      await resp.body?.cancel().catch(() => undefined);
      throw new Error('OAuth metadata response exceeded 256 KiB');
    }
  }
  if (!resp.body) return { status: resp.status, headers: resp.headers, json: null };
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > MAX_OAUTH_META_BYTES) {
          await reader.cancel().catch(() => undefined);
          throw new Error('OAuth metadata response exceeded 256 KiB');
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
  let json: Record<string, unknown> | null = null;
  try {
    const parsed = trimmed && isJsonDepthWithinLimit(trimmed, 32) ? JSON.parse(trimmed) : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      json = parsed as Record<string, unknown>;
    }
  } catch {
    json = null;
  }
  return { status: resp.status, headers: resp.headers, json };
}

export interface DiscoveredRemoteOAuthMetadata {
  supported: boolean;
  requiresAuthOriginConfirmation?: boolean;
  error?: 'cross_origin_auth_confirmation_required';
  authOrigin?: string;
  connectorOrigin?: string;
  resource?: string;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  registrationEndpoint?: string;
  scopesSupported?: string[];
  codeChallengeMethods?: string[];
}

export async function probeRemoteMcpOAuthMetadata(params: {
  remoteUrl: string;
  confirmedAuthOrigin?: string;
  fetchFn?: typeof fetch;
  selfHost?: string;
}): Promise<DiscoveredRemoteOAuthMetadata> {
  const { plan } = callCoreWasm<{
    plan: {
      ok: boolean;
      normalizedRemote?: string;
      connectorOrigin?: string;
      confirmedOrigin?: string;
      prCandidates?: string[];
      fallbackCandidates?: string[];
    };
  }>('mcp_vault_oauth_prepare_probe', {
    remoteUrl: params.remoteUrl,
    confirmedAuthOrigin: params.confirmedAuthOrigin ?? '',
    selfHost: params.selfHost ?? '',
  });
  if (!plan.ok || !plan.normalizedRemote || !plan.connectorOrigin) {
    return { supported: false };
  }

  const fetchFn = params.fetchFn ?? fetch;
  let resourceUri = plan.normalizedRemote;
  let authIssuerUrl = plan.connectorOrigin;
  let allowedAuthOrigin = plan.connectorOrigin;
  let asCandidates = plan.fallbackCandidates ?? [];
  let prScopes: string[] = [];

  for (const cand of plan.prCandidates ?? []) {
    try {
      const pr = await fetchJsonSafeBounded(cand, fetchFn, params.selfHost, {
        method: 'GET',
        headers: { accept: 'application/json' },
      });
      if (pr.status === 200) {
        if (!pr.json) return { supported: false };
        const { result } = callCoreWasm<{
          result: {
            valid: boolean;
            requiresAuthOriginConfirmation?: boolean;
            error?: 'cross_origin_auth_confirmation_required';
            authOrigin?: string;
            connectorOrigin?: string;
            resourceUri?: string;
            authIssuerUrl?: string;
            allowedAuthOrigin?: string;
            asCandidates?: string[];
            scopesSupported?: string[];
          };
        }>('mcp_vault_oauth_validate_prm', {
          prm: pr.json,
          remoteUrl: plan.normalizedRemote,
          confirmedAuthOrigin: params.confirmedAuthOrigin ?? '',
          selfHost: params.selfHost ?? '',
        });
        if (!result.valid) {
          if (result.requiresAuthOriginConfirmation && result.error) {
            return {
              supported: false,
              requiresAuthOriginConfirmation: true,
              error: result.error,
              ...(result.authOrigin ? { authOrigin: result.authOrigin } : {}),
              ...(result.connectorOrigin ? { connectorOrigin: result.connectorOrigin } : {}),
            };
          }
          return { supported: false };
        }
        resourceUri = result.resourceUri ?? resourceUri;
        authIssuerUrl = result.authIssuerUrl ?? authIssuerUrl;
        allowedAuthOrigin = result.allowedAuthOrigin ?? allowedAuthOrigin;
        asCandidates = result.asCandidates ?? asCandidates;
        prScopes = result.scopesSupported ?? [];
        break;
      }
    } catch {
      // continue to fallback on 404/network error before 200 PRM
    }
  }

  for (const asUrl of asCandidates) {
    try {
      const asRes = await fetchJsonSafeBounded(asUrl, fetchFn, params.selfHost, {
        method: 'GET',
        headers: { accept: 'application/json' },
      });
      if (asRes.status === 200 && asRes.json) {
        const { meta, abort } = callCoreWasm<{ meta: DiscoveredRemoteOAuthMetadata; abort: boolean }>(
          'mcp_vault_oauth_validate_asm',
          {
            asm: asRes.json,
            expectedIssuerUrl: authIssuerUrl,
            allowedAuthOrigin,
            connectorOrigin: plan.connectorOrigin,
            resourceUri,
            prScopes,
            selfHost: params.selfHost ?? '',
          },
        );
        if (meta.supported) return meta;
        if (abort) return { supported: false };
      }
    } catch {
      // try next candidate
    }
  }

  return { supported: false };
}

export async function startDownstreamMcpOAuth(params: {
  userId: string;
  sessionCsrf: string;
  hubOrigin: string;
  remoteUrl: string;
  confirmedAuthOrigin?: string;
  slug?: string;
  name?: string;
  transport?: 'streamable-http' | 'sse';
  domains?: string[];
  autoRouteScrape?: boolean;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
  vaultMasterKey: string | undefined;
  vaultStore: McpVaultStore;
  fetchFn?: typeof fetch;
  selfHost?: string;
  now?: number;
}): Promise<
  | {
      ok: true;
      authorizationUrl: string;
      bindCookieValue: string;
      slug: string;
    }
  | {
      ok: false;
      status: number;
      error: string;
      message: string;
      authOrigin?: string;
      connectorOrigin?: string;
    }
> {
  const keyCheck = validateVaultMasterKey(params.vaultMasterKey);
  if (!keyCheck.ok) return keyCheck;

  const urlCheck = isSafePublicHttpsUrl(params.remoteUrl, params.selfHost);
  if (!urlCheck.ok) {
    return { ok: false, status: 400, error: 'invalid_remote_url', message: urlCheck.reason };
  }

  const probePlan = callCoreWasm<{ plan: { ok: boolean; reason?: string; confirmedOrigin?: string } }>(
    'mcp_vault_oauth_prepare_probe',
    {
      remoteUrl: urlCheck.normalized,
      confirmedAuthOrigin: params.confirmedAuthOrigin ?? '',
      selfHost: params.selfHost ?? '',
    },
  ).plan;
  if (!probePlan.ok) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_confirmed_auth_origin',
      message: probePlan.reason ?? 'Invalid confirmedAuthOrigin',
    };
  }

  const cleanName = stripMcpSmugglingChars(params.name ?? '').trim().slice(0, 120) || urlCheck.url.hostname;
  let slug: string;
  if (typeof params.slug === 'string' && params.slug.trim()) {
    const rawExplicitSlug = params.slug.trim().toLowerCase();
    if (params.slug.includes('__') || !isValidMcpConnectorSlug(rawExplicitSlug)) {
      return {
        ok: false,
        status: 400,
        error: 'invalid_slug',
        message: 'Connector slug must be 1..48 lowercase [a-z0-9_-] characters and must not contain "__".',
      };
    }
    slug = rawExplicitSlug;
  } else {
    slug = normalizeMcpConnectorSlug(cleanName);
  }

  const autoRouteScrape = params.autoRouteScrape === true;
  const domValidation = validateConnectorDomains(params.domains, urlCheck.origin, autoRouteScrape);
  if (!domValidation.ok) {
    return { ok: false, status: 400, error: 'invalid_domains', message: domValidation.error };
  }

  const fetchFn = params.fetchFn ?? fetch;
  const meta = await probeRemoteMcpOAuthMetadata({
    remoteUrl: urlCheck.normalized,
    ...(probePlan.confirmedOrigin ? { confirmedAuthOrigin: probePlan.confirmedOrigin } : {}),
    fetchFn,
    selfHost: params.selfHost,
  });
  if (meta.error === 'cross_origin_auth_confirmation_required' && meta.authOrigin) {
    return {
      ok: false,
      status: 409,
      error: 'cross_origin_auth_confirmation_required',
      authOrigin: meta.authOrigin,
      connectorOrigin: meta.connectorOrigin ?? urlCheck.origin,
      message: `Remote MCP server (${urlCheck.origin}) delegated OAuth to cross-origin authorization server ${meta.authOrigin}. Pass confirmedAuthOrigin="${meta.authOrigin}" after verifying this host.`,
    };
  }
  if (!meta.supported || !meta.authorizationEndpoint || !meta.tokenEndpoint) {
    return {
      ok: false,
      status: 400,
      error: 'oauth_metadata_not_found',
      message: 'Remote MCP server did not advertise valid HTTPS OAuth 2.1 authorization_endpoint and token_endpoint.',
    };
  }

  const redirectUri = `${params.hubOrigin.replace(/\/+$/, '')}/admin/mcp/oauth/callback`;
  let clientId = (params.clientId ?? '').trim();
  let clientSecret = (params.clientSecret ?? '').trim() || undefined;

  if (!clientId && meta.registrationEndpoint) {
    try {
      const dcrRes = await fetchJsonSafeBounded(meta.registrationEndpoint, fetchFn, params.selfHost, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          client_name: 'EdgeFetch Federated MCP Hub',
          redirect_uris: [redirectUri],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none',
        }),
      });
      if ((dcrRes.status === 200 || dcrRes.status === 201) && typeof dcrRes.json?.client_id === 'string') {
        clientId = dcrRes.json.client_id.trim();
        if (typeof dcrRes.json.client_secret === 'string' && dcrRes.json.client_secret.trim()) {
          clientSecret = dcrRes.json.client_secret.trim();
        }
      }
    } catch {
      // fall through to CIMD default
    }
  }
  if (!clientId) {
    clientId = `${params.hubOrigin.replace(/\/+$/, '')}/.well-known/edgefetch-bot.json`;
  }

  const effectiveConfirmedAuthOrigin =
    probePlan.confirmedOrigin && probePlan.confirmedOrigin !== urlCheck.origin ? probePlan.confirmedOrigin : undefined;
  const canonicalResource = meta.resource ?? urlCheck.normalized;

  const codeVerifier = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const codeChallenge = await sha256Base64UrlHost(codeVerifier);
  const state = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const stateHash = await sha256Base64UrlHost(state);
  const bindCookieValue = await computeOAuthBindHmacHost(keyCheck.key, params.userId, state, params.sessionCsrf);

  const pkcePrep = callCoreWasm<{
    ok: boolean;
    authorizationUrl: string;
    hkdfInfo: string;
    aad: string;
    plaintext: string;
  }>('mcp_vault_prepare_oauth_pkce_init', {
    userId: params.userId,
    remoteOrigin: urlCheck.origin,
    authorizationEndpoint: meta.authorizationEndpoint,
    tokenEndpoint: meta.tokenEndpoint,
    clientId,
    clientSecret: clientSecret ?? '',
    redirectUri,
    scope: params.scope ?? '',
    scopesSupported: meta.scopesSupported ?? [],
    resource: canonicalResource,
    confirmedAuthOrigin: effectiveConfirmedAuthOrigin ?? '',
    issuer: meta.issuer ?? '',
    codeVerifier,
    codeChallenge,
    state,
  });
  const pkceSalt = crypto.getRandomValues(new Uint8Array(16));
  const pkceIv = crypto.getRandomValues(new Uint8Array(12));
  const pkceKey = await deriveVaultAesGcmKey(keyCheck.key, pkceSalt, pkcePrep.hkdfInfo);
  const pkceCtBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: pkceIv as BufferSource, additionalData: vaultTextEncoder.encode(pkcePrep.aad) },
    pkceKey,
    vaultTextEncoder.encode(pkcePrep.plaintext),
  );
  const encryptedPkceBlob = `pkce2.${bytesToBase64Url(pkceSalt)}.${bytesToBase64Url(pkceIv)}.${bytesToBase64Url(new Uint8Array(pkceCtBuf))}`;

  const now = params.now ?? Date.now();
  await params.vaultStore.putOAuthState({
    stateHash,
    userId: params.userId,
    slug,
    name: cleanName,
    remoteUrl: urlCheck.normalized,
    remoteOrigin: urlCheck.origin,
    transport: params.transport === 'sse' ? 'sse' : 'streamable-http',
    domains: domValidation.domains,
    autoRouteScrape,
    ...(effectiveConfirmedAuthOrigin ? { confirmedAuthOrigin: effectiveConfirmedAuthOrigin } : {}),
    encryptedPkceBlob,
    expiresAt: now + MCP_OAUTH_STATE_TTL_MS,
  });

  return {
    ok: true,
    authorizationUrl: pkcePrep.authorizationUrl,
    bindCookieValue,
    slug,
  };
}

export const startMcpOAuthConnect = startDownstreamMcpOAuth;

export async function completeDownstreamMcpOAuthCallback(params: {
  userId: string;
  sessionCsrf: string;
  bindCookieHeader: string | null;
  code: string;
  state: string;
  iss?: string | null;
  vaultMasterKey: string | undefined;
  vaultStore: McpVaultStore;
  fetchFn?: typeof fetch;
  selfHost?: string;
  now?: number;
}): Promise<
  | { ok: true; server: StoredMcpServerRow }
  | { ok: false; status: number; error: string; message: string }
> {
  const keyCheck = validateVaultMasterKey(params.vaultMasterKey);
  if (!keyCheck.ok) return keyCheck;

  if (!params.code || !params.state) {
    return { ok: false, status: 400, error: 'missing_code_or_state', message: 'Missing OAuth authorization code or state.' };
  }

  const bindMatched = params.bindCookieHeader
    ? await verifyOAuthBindHmacHost(params.bindCookieHeader, keyCheck.key, params.userId, params.state, params.sessionCsrf)
    : false;
  if (!params.bindCookieHeader || !bindMatched) {
    return { ok: false, status: 403, error: 'invalid_oauth_state_binding', message: 'OAuth state cookie binding mismatch.' };
  }

  const stateHash = await sha256Base64UrlHost(params.state);
  const now = params.now ?? Date.now();
  const pending = await params.vaultStore.consumeOAuthState(stateHash, params.userId, now);
  if (!pending) {
    return { ok: false, status: 400, error: 'expired_or_unknown_state', message: 'OAuth state expired, replayed, or belongs to another user.' };
  }

  const pkceUnsealPrep = callCoreWasm<{
    ok: boolean;
    hkdfInfo?: string;
    aad?: string;
    saltB64?: string;
    ivB64?: string;
    ctB64?: string;
  }>('mcp_vault_prepare_pkce_unseal', {
    userId: params.userId,
    remoteOrigin: pending.remoteOrigin,
    ciphertext: pending.encryptedPkceBlob,
  });
  let pkce: Record<string, unknown> | undefined;
  if (pkceUnsealPrep.ok && pkceUnsealPrep.hkdfInfo && pkceUnsealPrep.aad && pkceUnsealPrep.saltB64 && pkceUnsealPrep.ivB64 && pkceUnsealPrep.ctB64) {
    try {
      const pKey = await deriveVaultAesGcmKey(keyCheck.key, base64UrlToBytes(pkceUnsealPrep.saltB64), pkceUnsealPrep.hkdfInfo);
      const pPlainBuf = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: base64UrlToBytes(pkceUnsealPrep.ivB64) as BufferSource,
          additionalData: vaultTextEncoder.encode(pkceUnsealPrep.aad),
        },
        pKey,
        base64UrlToBytes(pkceUnsealPrep.ctB64) as BufferSource,
      );
      const pPlainStr = vaultTextDecoder.decode(pPlainBuf);
      const vPkce = callCoreWasm<{ ok: boolean; blob?: Record<string, unknown> }>('mcp_vault_verify_pkce_unseal', {
        plaintext: pPlainStr,
      });
      if (vPkce.ok) pkce = vPkce.blob;
    } catch {
      pkce = undefined;
    }
  }
  if (!pkce || typeof pkce.codeVerifier !== 'string' || typeof pkce.tokenEndpoint !== 'string' || typeof pkce.clientId !== 'string') {
    return { ok: false, status: 400, error: 'corrupt_pkce_state', message: 'Unable to unseal PKCE verifier.' };
  }

  const expectedIssuer = typeof pkce.issuer === 'string' ? pkce.issuer.trim().replace(/\/+$/, '') : '';
  if (params.iss !== undefined && params.iss !== null && params.iss.trim() !== '') {
    const callbackIss = params.iss.trim().replace(/\/+$/, '');
    if (!expectedIssuer || callbackIss !== expectedIssuer) {
      return { ok: false, status: 400, error: 'oauth_issuer_mismatch', message: 'Authorization callback iss parameter did not match expected issuer.' };
    }
  }

  const pkceConfirmed =
    typeof pkce.confirmedAuthOrigin === 'string' && pkce.confirmedAuthOrigin
      ? pkce.confirmedAuthOrigin.trim().toLowerCase()
      : undefined;
  const rowConfirmed = pending.confirmedAuthOrigin ? pending.confirmedAuthOrigin.trim().toLowerCase() : undefined;
  if (pkceConfirmed !== rowConfirmed) {
    return {
      ok: false,
      status: 400,
      error: 'corrupt_pkce_state',
      message: 'Confirmed authorization origin mismatch in pending OAuth state.',
    };
  }

  const epCheck = callCoreWasm<{
    ok: boolean;
    normalizedUrl?: string;
    status?: number;
    error?: string;
    message?: string;
  }>('mcp_vault_oauth_validate_token_ep', {
    tokenEndpoint: pkce.tokenEndpoint,
    expectedIssuer,
    confirmedAuthOrigin: pkceConfirmed ?? '',
    remoteOrigin: pending.remoteOrigin,
    selfHost: params.selfHost ?? '',
  });
  if (!epCheck.ok || !epCheck.normalizedUrl) {
    return {
      ok: false,
      status: epCheck.status ?? 400,
      error: epCheck.error ?? 'unsafe_token_endpoint',
      message: epCheck.message ?? 'Invalid token endpoint',
    };
  }

  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: String(pkce.redirectUri ?? ''),
    client_id: pkce.clientId,
    code_verifier: pkce.codeVerifier,
  });
  if (typeof pkce.clientSecret === 'string' && pkce.clientSecret) form.set('client_secret', pkce.clientSecret);
  if (typeof pkce.resource === 'string' && pkce.resource) form.set('resource', pkce.resource);

  let tokenRes: { status: number; headers: Headers; json: Record<string, unknown> | null };
  try {
    tokenRes = await fetchJsonSafeBounded(epCheck.normalizedUrl, params.fetchFn ?? fetch, params.selfHost, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: form.toString(),
    });
  } catch (err) {
    return {
      ok: false,
      status: 502,
      error: 'token_exchange_failed',
      message: err instanceof Error ? err.message : 'Downstream OAuth token exchange failed',
    };
  }

  const accessToken = typeof tokenRes.json?.access_token === 'string' ? tokenRes.json.access_token.trim() : '';
  if (tokenRes.status !== 200 || !accessToken || /[\r\n\0]/.test(accessToken)) {
    const errDesc =
      typeof tokenRes.json?.error_description === 'string'
        ? tokenRes.json.error_description
        : typeof tokenRes.json?.error === 'string'
          ? tokenRes.json.error
          : `HTTP ${tokenRes.status}`;
    return {
      ok: false,
      status: 502,
      error: 'token_exchange_rejected',
      message: `Downstream OAuth server rejected code exchange: ${stripMcpSmugglingChars(errDesc).slice(0, 160)}`,
    };
  }

  const refreshToken =
    typeof tokenRes.json?.refresh_token === 'string' && tokenRes.json.refresh_token.trim() && !/[\r\n\0]/.test(tokenRes.json.refresh_token)
      ? tokenRes.json.refresh_token.trim()
      : undefined;
  const expiresInSec = Number(tokenRes.json?.expires_in);
  const expiresAt = Number.isFinite(expiresInSec) && expiresInSec > 0 ? now + Math.floor(expiresInSec * 1_000) : undefined;
  const scopeStr = typeof tokenRes.json?.scope === 'string' ? tokenRes.json.scope.slice(0, 400) : undefined;

  const secretPayload: VaultSecretPayload = {
    kind: 'oauth2',
    pinnedOrigin: pending.remoteOrigin,
    pinnedUrl: pending.remoteUrl,
    oauth: {
      accessToken,
      ...(refreshToken ? { refreshToken } : {}),
      tokenType: 'Bearer',
      ...(expiresAt ? { expiresAt } : {}),
      ...(scopeStr ? { scope: scopeStr } : {}),
      ...(expectedIssuer ? { issuer: expectedIssuer } : {}),
      resource: typeof pkce.resource === 'string' && pkce.resource ? pkce.resource : pending.remoteUrl,
      tokenEndpoint: epCheck.normalizedUrl,
      ...(pkceConfirmed ? { confirmedAuthOrigin: pkceConfirmed } : {}),
      clientId: pkce.clientId,
      ...(typeof pkce.clientSecret === 'string' && pkce.clientSecret ? { clientSecret: pkce.clientSecret } : {}),
    },
  };

  const existing = await params.vaultStore.getServer(params.userId, pending.slug);
  const serverId = existing?.id ?? `mcp_${crypto.randomUUID().replace(/-/g, '').slice(0, 20)}`;

  const sealed = await sealVaultCredentials({
    vaultMasterKey: keyCheck.key,
    userId: params.userId,
    remoteOrigin: pending.remoteOrigin,
    id: serverId,
    slug: pending.slug,
    authType: 'oauth2',
    payload: secretPayload,
  });
  if (!sealed.ok) return sealed;

  const row: StoredMcpServerRow = {
    id: serverId,
    userId: params.userId,
    slug: pending.slug,
    name: pending.name,
    remoteUrl: pending.remoteUrl,
    remoteOrigin: pending.remoteOrigin,
    transport: pending.transport,
    authType: 'oauth2',
    encryptedCredentials: sealed.ciphertext,
    secretVersion: sealed.secretVersion,
    authSummary: buildMaskedAuthSummary(secretPayload),
    domains: pending.domains,
    autoRouteScrape: Boolean(pending.autoRouteScrape),
    cachedTools: existing?.cachedTools ?? [],
    toolCount: existing?.toolCount ?? 0,
    enabled: true,
    lastVerifiedAt: now,
    lastError: null,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };

  await params.vaultStore.upsertServer(row);
  return { ok: true, server: row };
}
