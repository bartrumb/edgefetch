/**
 * Per-User `AES-256-GCM` Downstream MCP Credential Vault & OAuth 2.1 PKCE Connector (`hub/src/mcp-vault.ts`).
 *
 * Cryptographic & Tenant-Isolation Invariants:
 *  - Requires `VAULT_MASTER_KEY` (`>= 24` chars). Fails closed when unset; never falls back to `CALLER_TOKEN`.
 *  - Derives a unique per-user + per-origin `AES-256-GCM` key via WebCrypto `HKDF-SHA256`:
 *      `HKDF(VAULT_MASTER_KEY, salt_128b, info = "edgefetch-mcp-vault-v1:" + userId + ":" + remoteOrigin)`
 *  - Encrypts with a fresh 96-bit (`12`-byte) random IV and Additional Authenticated Data (`AAD = "${userId}|${remoteOrigin}"`).
 *    Cross-user row copying OR `remote_url` origin tampering fails GCM authentication before any outbound request!
 *  - Write-only secret storage: decrypted credentials NEVER leave the server or return to `/admin` APIs.
 *  - Shared Interface Contract with Pillar 1: Every row carries `user_id TEXT NOT NULL DEFAULT 'owner'`.
 */

import { MIN_TOKEN_LENGTH, sameBytes } from './auth';
import {
  isJsonDepthWithinLimit,
  isSafePublicHttpsUrl,
  isSharedHostingHostname,
  slugifyMcpServerName,
  stripMcpSmugglingChars,
  validateConnectorDomains,
} from './mcp-registry';
import { sha256Base64Url, type SqlStorageLike } from './oauth';

export const SAFE_MCP_IDENTIFIER_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const FORBIDDEN_MCP_IDENTIFIERS = new Set(['__proto__', 'constructor', 'prototype']);
export const PROMPT_INJECTION_MCP_ID_RE =
  /(?:^|[_.-])(?:ignore|disregard|override|bypass|exfiltrate|jailbreak|forget)(?:[_.-]|$|[A-Z])|system[_.-]?(?:prompt|instruction|message|override)|developer[_.-]?(?:prompt|instruction|message)|prompt[_.-]?injection/i;

export function isSafeMcpIdentifier(raw: string): boolean {
  if (!raw || !SAFE_MCP_IDENTIFIER_RE.test(raw) || FORBIDDEN_MCP_IDENTIFIERS.has(raw)) {
    return false;
  }
  return !PROMPT_INJECTION_MCP_ID_RE.test(raw);
}

export const MCP_OAUTH_STATE_TTL_MS = 10 * 60_000; // 10m single-use PKCE state lifetime
export const MCP_OAUTH_BIND_COOKIE = '__Host-ef_mcp_oauth_bind';
export const MCP_OAUTH_BIND_COOKIE_DEV = 'ef_mcp_oauth_bind';
const MAX_OAUTH_META_BYTES = 256 * 1024;
const OAUTH_META_TIMEOUT_MS = 10_000;
const MAX_VAULT_SERVERS_PER_USER = 64;
const MAX_PENDING_OAUTH_STATES_PER_USER = 16;
const MAX_SECRET_HEADERS_TOTAL_BYTES = 32 * 1024;

const FORBIDDEN_SECRET_HEADER_NAMES = new Set([
  'host',
  ':authority',
  ':method',
  ':path',
  ':scheme',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'upgrade',
  'te',
  'trailer',
  'proxy-connection',
  'proxy-authorization',
  'content-type',
  'content-encoding',
  'accept',
  'accept-encoding',
  'user-agent',
  'origin',
  'referer',
  'expect',
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'cf-connecting-ip',
  'true-client-ip',
  'fly-client-ip',
  'x-http-method-override',
  'last-event-id',
  'cookie',
  'cookie2',
  'mcp-session-id',
  'mcp-protocol-version',
]);

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

/** Safe write-only projection returned to `/admin` and `query_mcp(action="list_connected")` (NEVER includes ciphertext or secrets). */
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
  getServer(userId: string, slugOrDomain: string): Promise<StoredMcpServerRow | null> | StoredMcpServerRow | null;
  upsertServer(row: StoredMcpServerRow): Promise<void> | void;
  deleteServer(userId: string, slug: string): Promise<boolean> | boolean;
  putOAuthState(row: PendingMcpOAuthStateRow): Promise<void> | void;
  consumeOAuthState(stateHash: string, userId: string, now: number): Promise<PendingMcpOAuthStateRow | null> | PendingMcpOAuthStateRow | null;
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

/**
 * Shared Interface Contract with Pillar 1:
 * Resolves the isolated tenant `user_id` from `(auth as { userId?: string }).userId ?? auth.principal ?? 'owner'`,
 * normalizing single-owner `owner_token` / `mcp_token` principals to `'owner'` so `/admin` and headless API calls align.
 */
export function resolveCallerUserId(
  auth?: { userId?: string; principal?: string } | null,
): string {
  const rawUserId = (auth as { userId?: string } | null | undefined)?.userId;
  if (typeof rawUserId === 'string' && rawUserId.trim()) {
    return rawUserId.trim().slice(0, 128);
  }
  const rawPrincipal = auth?.principal?.trim();
  if (
    !rawPrincipal ||
    rawPrincipal === 'owner_token' ||
    rawPrincipal === 'mcp_token' ||
    rawPrincipal === 'api' ||
    rawPrincipal === 'mcp' ||
    rawPrincipal === 'client'
  ) {
    return 'owner';
  }
  return rawPrincipal.slice(0, 128);
}

export function toPublicMcpServerSummary(row: StoredMcpServerRow): PublicMcpServerSummary {
  return {
    id: row.id,
    userId: row.userId,
    slug: row.slug,
    name: row.name,
    remoteUrl: row.remoteUrl,
    remoteOrigin: row.remoteOrigin,
    transport: row.transport,
    authType: row.authType,
    authSummary: row.authSummary,
    domains: row.domains,
    autoRouteScrape: Boolean(row.autoRouteScrape),
    tools: row.cachedTools,
    toolCount: row.toolCount,
    enabled: row.enabled,
    lastVerifiedAt: row.lastVerifiedAt,
    lastError: row.lastError,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(raw: string): Uint8Array | null {
  if (!raw || !/^[A-Za-z0-9_-]+$/.test(raw)) return null;
  try {
    const b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function randomBase64Url(byteLen = 32): string {
  const buf = new Uint8Array(byteLen);
  crypto.getRandomValues(buf);
  return bytesToBase64Url(buf);
}

export function validateVaultMasterKey(
  vaultMasterKey: string | undefined,
): { ok: true; key: string } | { ok: false; status: 503; error: 'vault_master_key_unconfigured'; message: string } {
  const clean = (vaultMasterKey ?? '').trim();
  if (clean.length < MIN_TOKEN_LENGTH) {
    return {
      ok: false,
      status: 503,
      error: 'vault_master_key_unconfigured',
      message: `VAULT_MASTER_KEY must be configured with at least ${MIN_TOKEN_LENGTH} random characters to encrypt MCP credentials.`,
    };
  }
  return { ok: true, key: clean };
}

async function derivePerUserOriginAesKey(params: {
  vaultMasterKey: string;
  salt: Uint8Array;
  userId: string;
  remoteOrigin: string;
  purpose?: string;
}): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(params.vaultMasterKey),
    { name: 'HKDF' },
    false,
    ['deriveKey'],
  );
  const originLower = params.remoteOrigin.toLowerCase();
  const scopedPair = `${params.userId.length}:${params.userId}|${originLower.length}:${originLower}`;
  const infoLabel = params.purpose
    ? `edgefetch-mcp-vault-v1:${params.purpose}:${scopedPair}`
    : `edgefetch-mcp-vault-v1:${scopedPair}`;
  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: params.salt as BufferSource,
      info: enc.encode(infoLabel),
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * @deprecated Remove in v2.7.5 — auto-reseals to length-prefixed v2.7.1+ AAD on first decrypt.
 */
async function deriveLegacyV270PerUserOriginAesKey(params: {
  vaultMasterKey: string;
  salt: Uint8Array;
  userId: string;
  remoteOrigin: string;
}): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(params.vaultMasterKey),
    { name: 'HKDF' },
    false,
    ['deriveKey'],
  );
  const originLower = params.remoteOrigin.toLowerCase();
  const infoLabel = `edgefetch-mcp-vault-v1:${params.userId}:${originLower}`;
  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: params.salt as BufferSource,
      info: enc.encode(infoLabel),
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

const VAULT_CREDENTIALS_PURPOSE_V2 = 'user_mcp_servers:credentials:v2';
const VAULT_PKCE_STATE_PURPOSE_V2 = 'mcp_oauth_states:pkce:v2';

/**
 * Encrypts a `VaultSecretPayload` using `HKDF-SHA256` + `AES-256-GCM` with 96-bit random IV,
 * explicit `v2.` version header, and table/purpose-bound length-prefixed AAD.
 */
export async function sealVaultCredentials(params: {
  vaultMasterKey: string | undefined;
  userId: string;
  remoteOrigin: string;
  payload: VaultSecretPayload;
}): Promise<
  | { ok: true; ciphertext: string }
  | { ok: false; status: 503; error: 'vault_master_key_unconfigured'; message: string }
> {
  const keyCheck = validateVaultMasterKey(params.vaultMasterKey);
  if (!keyCheck.ok) return keyCheck;

  const canonicalOrigin = params.remoteOrigin.trim().toLowerCase();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit GCM IV
  const aesKey = await derivePerUserOriginAesKey({
    vaultMasterKey: keyCheck.key,
    salt,
    userId: params.userId,
    remoteOrigin: canonicalOrigin,
    purpose: VAULT_CREDENTIALS_PURPOSE_V2,
  });

  const aad = new TextEncoder().encode(
    `v2|user_mcp_servers:credentials|${params.userId.length}:${params.userId}|${canonicalOrigin.length}:${canonicalOrigin}`,
  );
  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      ...params.payload,
      purpose: 'user_mcp_servers:credentials',
      pinnedOrigin: canonicalOrigin,
    }),
  );
  const encryptedBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad, tagLength: 128 },
    aesKey,
    plaintext,
  );

  return {
    ok: true,
    ciphertext: `v2.${bytesToBase64Url(salt)}.${bytesToBase64Url(iv)}.${bytesToBase64Url(new Uint8Array(encryptedBuf))}`,
  };
}

function parseEnvelopeHeader(ciphertext: string): { version: string; saltB64: string; ivB64: string; ctB64: string } | null {
  if (!ciphertext || typeof ciphertext !== 'string') return null;
  const normalized = ciphertext.startsWith('v2:') ? `v2.${ciphertext.slice(3)}` : ciphertext;
  const parts = normalized.split('.');
  if (parts.length !== 4) return null;
  return {
    version: parts[0]!,
    saltB64: parts[1]!,
    ivB64: parts[2]!,
    ctB64: parts[3]!,
  };
}

function isValidCredentialPayloadKind(kind: unknown): kind is VaultSecretPayload['kind'] {
  return kind === 'headers' || kind === 'oauth2' || kind === 'none';
}

/**
 * Decrypts and authenticates an `AES-256-GCM` vault envelope:
 *  - `v2.` envelopes strictly require table/purpose-bound `user_mcp_servers:credentials` HKDF + length-prefixed AAD (NEVER falling back!).
 *  - `v1.` envelopes try `v2.7.1–v2.7.4` length-prefixed HKDF + AAD on primary decrypt; ONLY when the ciphertext lacks `v2` (`version === 'v1'`),
 *    primary decrypt fails, AND `userId` contains neither `|` nor `:`, tries legacy `v2.7.0` fallback with strict credential payload schema verification,
 *    immediately emitting `resealedCiphertext` (`v2....`) so callers auto-upgrade on read.
 */
export async function unsealVaultCredentials(params: {
  vaultMasterKey: string | undefined;
  userId: string;
  remoteOrigin: string;
  remoteUrl?: string;
  ciphertext: string;
}): Promise<
  | { ok: true; payload: VaultSecretPayload; resealedCiphertext?: string }
  | { ok: false; error: 'vault_master_key_unconfigured' | 'vault_decryption_failed'; message: string }
> {
  const keyCheck = validateVaultMasterKey(params.vaultMasterKey);
  if (!keyCheck.ok) {
    return { ok: false, error: 'vault_master_key_unconfigured', message: keyCheck.message };
  }
  const envHeader = parseEnvelopeHeader(params.ciphertext);
  if (!envHeader || (envHeader.version !== 'v2' && envHeader.version !== 'v1')) {
    return { ok: false, error: 'vault_decryption_failed', message: 'Malformed vault ciphertext envelope' };
  }
  const salt = base64UrlToBytes(envHeader.saltB64);
  const iv = base64UrlToBytes(envHeader.ivB64);
  const ct = base64UrlToBytes(envHeader.ctB64);
  if (!salt || salt.byteLength !== 16 || !iv || iv.byteLength !== 12 || !ct || ct.byteLength < 17) {
    return { ok: false, error: 'vault_decryption_failed', message: 'Invalid vault IV or authentication tag length' };
  }

  const canonicalOrigin = params.remoteOrigin.trim().toLowerCase();
  if (params.remoteOrigin !== canonicalOrigin) {
    return { ok: false, error: 'vault_decryption_failed', message: 'Non-canonical origin supplied to vault decryption' };
  }

  let plainBuf: ArrayBuffer;
  let usedLegacyV270Fallback = false;
  if (envHeader.version === 'v2') {
    try {
      const aesKey = await derivePerUserOriginAesKey({
        vaultMasterKey: keyCheck.key,
        salt,
        userId: params.userId,
        remoteOrigin: canonicalOrigin,
        purpose: VAULT_CREDENTIALS_PURPOSE_V2,
      });
      const aad = new TextEncoder().encode(
        `v2|user_mcp_servers:credentials|${params.userId.length}:${params.userId}|${canonicalOrigin.length}:${canonicalOrigin}`,
      );
      plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad, tagLength: 128 },
        aesKey,
        ct as BufferSource,
      );
    } catch {
      return {
        ok: false,
        error: 'vault_decryption_failed',
        message: 'AES-256-GCM authentication failed (wrong user_id, tampered origin/purpose, or rotated VAULT_MASTER_KEY)',
      };
    }
  } else {
    try {
      const aesKey = await derivePerUserOriginAesKey({
        vaultMasterKey: keyCheck.key,
        salt,
        userId: params.userId,
        remoteOrigin: canonicalOrigin,
      });
      const aad = new TextEncoder().encode(
        `${params.userId.length}:${params.userId}|${canonicalOrigin.length}:${canonicalOrigin}`,
      );
      plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad, tagLength: 128 },
        aesKey,
        ct as BufferSource,
      );
    } catch {
      /**
       * Legacy v2.7.0 backward-compatibility fallback:
       * ONLY attempted when ciphertext lacks `v2` (`envHeader.version === 'v1'`) AND `userId` contains neither `|` nor `:`.
       */
      if (params.userId.includes('|') || params.userId.includes(':')) {
        return {
          ok: false,
          error: 'vault_decryption_failed',
          message: 'AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)',
        };
      }
      try {
        const legacyKey = await deriveLegacyV270PerUserOriginAesKey({
          vaultMasterKey: keyCheck.key,
          salt,
          userId: params.userId,
          remoteOrigin: canonicalOrigin,
        });
        const legacyAad = new TextEncoder().encode(`${params.userId}|${canonicalOrigin}`);
        plainBuf = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv as BufferSource, additionalData: legacyAad, tagLength: 128 },
          legacyKey,
          ct as BufferSource,
        );
        usedLegacyV270Fallback = true;
      } catch {
        return {
          ok: false,
          error: 'vault_decryption_failed',
          message: 'AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)',
        };
      }
    }
  }

  try {
    const rawParsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plainBuf)) as Record<string, unknown>;
    if (
      !rawParsed ||
      typeof rawParsed !== 'object' ||
      Array.isArray(rawParsed) ||
      !isValidCredentialPayloadKind(rawParsed.kind) ||
      (rawParsed.purpose !== undefined && rawParsed.purpose !== 'user_mcp_servers:credentials') ||
      typeof rawParsed.pinnedOrigin !== 'string' ||
      rawParsed.pinnedOrigin.toLowerCase() !== canonicalOrigin
    ) {
      return { ok: false, error: 'vault_decryption_failed', message: 'Pinned origin or credential purpose mismatch during vault decryption' };
    }
    const parsed = rawParsed as unknown as VaultSecretPayload;
    if (params.remoteUrl && typeof parsed.pinnedUrl === 'string' && parsed.pinnedUrl) {
      if (params.remoteUrl.trim().replace(/\/+$/, '') !== parsed.pinnedUrl.trim().replace(/\/+$/, '')) {
        return { ok: false, error: 'vault_decryption_failed', message: 'Pinned endpoint URL path mismatch during vault decryption' };
      }
    }
    if (usedLegacyV270Fallback) {
      const resealed = await sealVaultCredentials({
        vaultMasterKey: keyCheck.key,
        userId: params.userId,
        remoteOrigin: canonicalOrigin,
        payload: parsed,
      });
      if (resealed.ok) {
        return { ok: true, payload: parsed, resealedCiphertext: resealed.ciphertext };
      }
    }
    return { ok: true, payload: parsed };
  } catch {
    return {
      ok: false,
      error: 'vault_decryption_failed',
      message: 'AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)',
    };
  }
}

async function sealPkceStateBlob(params: {
  vaultMasterKey: string;
  userId: string;
  remoteOrigin: string;
  blob: Record<string, unknown>;
}): Promise<string> {
  const canonicalOrigin = params.remoteOrigin.trim().toLowerCase();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePerUserOriginAesKey({
    vaultMasterKey: params.vaultMasterKey,
    salt,
    userId: params.userId,
    remoteOrigin: canonicalOrigin,
    purpose: VAULT_PKCE_STATE_PURPOSE_V2,
  });
  const aad = new TextEncoder().encode(
    `pkce2|mcp_oauth_states:pkce|${params.userId.length}:${params.userId}|${canonicalOrigin.length}:${canonicalOrigin}`,
  );
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad, tagLength: 128 },
    key,
    new TextEncoder().encode(JSON.stringify({ ...params.blob, purpose: 'mcp_oauth_states:pkce' })),
  );
  return `pkce2.${bytesToBase64Url(salt)}.${bytesToBase64Url(iv)}.${bytesToBase64Url(new Uint8Array(ct))}`;
}

async function unsealPkceStateBlob(params: {
  vaultMasterKey: string;
  userId: string;
  remoteOrigin: string;
  ciphertext: string;
}): Promise<Record<string, unknown> | null> {
  const parts = params.ciphertext.split('.');
  if (parts.length !== 4 || (parts[0] !== 'pkce2' && parts[0] !== 'v1')) return null;
  const version = parts[0];
  const salt = base64UrlToBytes(parts[1]!);
  const iv = base64UrlToBytes(parts[2]!);
  const ct = base64UrlToBytes(parts[3]!);
  if (!salt || salt.byteLength !== 16 || !iv || iv.byteLength !== 12 || !ct || ct.byteLength < 17) return null;
  const canonicalOrigin = params.remoteOrigin.trim().toLowerCase();
  try {
    const key = await derivePerUserOriginAesKey({
      vaultMasterKey: params.vaultMasterKey,
      salt,
      userId: params.userId,
      remoteOrigin: canonicalOrigin,
      purpose: version === 'pkce2' ? VAULT_PKCE_STATE_PURPOSE_V2 : 'pkce-state',
    });
    const aad = new TextEncoder().encode(
      version === 'pkce2'
        ? `pkce2|mcp_oauth_states:pkce|${params.userId.length}:${params.userId}|${canonicalOrigin.length}:${canonicalOrigin}`
        : `${params.userId}|pkce|${canonicalOrigin}`,
    );
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad, tagLength: 128 },
      key,
      ct as BufferSource,
    );
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain)) as Record<string, unknown>;
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      typeof parsed.codeVerifier !== 'string' ||
      (version === 'pkce2' && parsed.purpose !== 'mcp_oauth_states:pkce')
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

const HEADER_CONTROL_BYTE_RE = /[\x00-\x08\x0a-\x1f\x7f]/;

export function sanitizeSecretHeadersInput(params: {
  bearerToken?: unknown;
  headers?: unknown;
}): { ok: true; headers: Record<string, string> } | { ok: false; error: string } {
  const cleaned: Record<string, string> = {};
  const seenLowerKeys = new Set<string>();
  let totalBytes = 0;

  if (typeof params.bearerToken === 'string' && params.bearerToken.trim()) {
    const tok = params.bearerToken.trim().replace(/^Bearer\s+/i, '').trim();
    if (!tok || HEADER_CONTROL_BYTE_RE.test(tok) || tok.length > 4_096) {
      return { ok: false, error: 'Invalid Bearer token format or control characters' };
    }
    cleaned['Authorization'] = `Bearer ${tok}`;
    seenLowerKeys.add('authorization');
    totalBytes += 'Authorization'.length + cleaned['Authorization'].length;
  }

  if (params.headers !== undefined && params.headers !== null) {
    if (typeof params.headers !== 'object' || Array.isArray(params.headers)) {
      return { ok: false, error: 'headers must be a JSON object mapping header names to string values' };
    }
    const entries = Object.entries(params.headers as Record<string, unknown>);
    if (entries.length > 20) {
      return { ok: false, error: 'At most 20 custom headers are supported per MCP connector' };
    }
    for (const [rawKey, rawVal] of entries) {
      if (rawVal === undefined || rawVal === null || rawVal === '') continue;
      if (typeof rawVal !== 'string') {
        return { ok: false, error: `Header "${rawKey}" value must be a string` };
      }
      const key = rawKey.trim();
      if (!key || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(key)) {
        return { ok: false, error: `Invalid HTTP header name "${rawKey}"` };
      }
      const lowerKey = key.toLowerCase();
      if (FORBIDDEN_SECRET_HEADER_NAMES.has(lowerKey)) {
        return { ok: false, error: `Disallowed reserved HTTP header "${key}"` };
      }
      const val = rawVal.trim();
      if (!val) continue;
      if (HEADER_CONTROL_BYTE_RE.test(val) || val.length > 8_192) {
        return { ok: false, error: `Header "${key}" contains control characters or exceeds 8 KiB` };
      }
      if (seenLowerKeys.has(lowerKey)) {
        return { ok: false, error: `Duplicate HTTP header "${key}" (case-insensitive collision)` };
      }
      totalBytes += key.length + val.length;
      if (totalBytes > MAX_SECRET_HEADERS_TOTAL_BYTES) {
        return { ok: false, error: 'Combined custom headers exceed 32 KiB limit' };
      }
      seenLowerKeys.add(lowerKey);
      cleaned[key] = val;
    }
  }

  return { ok: true, headers: cleaned };
}

export function buildMaskedAuthSummary(payload: VaultSecretPayload): MaskedAuthSummary {
  if (payload.kind === 'oauth2' && payload.oauth) {
    return {
      authMode: 'oauth2',
      headerNames: ['Authorization'],
      maskedBadge: payload.oauth.refreshToken ? 'OAuth 2.1 PKCE (Auto-Refresh)' : 'OAuth 2.1 PKCE',
      hasRefreshToken: Boolean(payload.oauth.refreshToken),
      ...(payload.oauth.expiresAt ? { tokenExpiresAt: payload.oauth.expiresAt } : {}),
    };
  }
  const hdrs = payload.headers ?? {};
  const names = Object.keys(hdrs);
  if (names.length === 0) {
    return {
      authMode: 'none',
      headerNames: [],
      maskedBadge: 'Public (No Auth)',
    };
  }
  const authEntry = Object.entries(hdrs).find(([k]) => k.toLowerCase() === 'authorization');
  if (authEntry && names.length === 1 && /^bearer\s+/i.test(authEntry[1])) {
    return {
      authMode: 'bearer',
      headerNames: ['Authorization'],
      maskedBadge: 'AES-256-GCM • Bearer ••••••••',
    };
  }
  return {
    authMode: 'headers',
    headerNames: names,
    maskedBadge: `AES-256-GCM • ${names.join(', ')} (••••)`,
  };
}

function filterSafeSchemaNode(rawSchema: unknown, depth = 0): Record<string, unknown> {
  if (!rawSchema || typeof rawSchema !== 'object' || Array.isArray(rawSchema) || depth > 6) {
    return depth === 0 ? { type: 'object', properties: {} } : {};
  }
  const src = rawSchema as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(src)) {
    if (FORBIDDEN_MCP_IDENTIFIERS.has(k)) continue;
    out[k] = v;
  }

  let validProps: Set<string> | null = null;
  if (src.properties && typeof src.properties === 'object' && !Array.isArray(src.properties)) {
    const cleanProps: Record<string, unknown> = {};
    validProps = new Set<string>();
    for (const [rawK, rawV] of Object.entries(src.properties as Record<string, unknown>).slice(0, 32)) {
      const cleanK = stripMcpSmugglingChars(rawK).trim();
      if (!isSafeMcpIdentifier(cleanK)) continue;
      cleanProps[cleanK] = filterSafeSchemaNode(rawV, depth + 1);
      validProps.add(cleanK);
    }
    out.properties = cleanProps;
  } else if (depth === 0) {
    out.properties = {};
  }

  if (Array.isArray(src.required)) {
    const cleanReq = src.required.filter(
      (r): r is string =>
        typeof r === 'string' &&
        isSafeMcpIdentifier(r) &&
        (!validProps || validProps.has(r)),
    );
    if (cleanReq.length > 0) out.required = cleanReq;
    else delete out.required;
  }

  if (src.items && typeof src.items === 'object' && !Array.isArray(src.items)) {
    out.items = filterSafeSchemaNode(src.items, depth + 1);
  }
  return out;
}

export function filterSafeCachedMcpTools(rawTools: unknown): CachedMcpToolSchema[] {
  if (!Array.isArray(rawTools)) return [];
  const out: CachedMcpToolSchema[] = [];
  for (const item of rawTools.slice(0, 64)) {
    if (!item || typeof item !== 'object') continue;
    const t = item as CachedMcpToolSchema;
    const cleanName = typeof t.name === 'string' ? stripMcpSmugglingChars(t.name).trim() : '';
    if (!isSafeMcpIdentifier(cleanName)) {
      continue;
    }
    out.push({
      ...t,
      name: cleanName,
      inputSchema: filterSafeSchemaNode(t.inputSchema, 0),
    });
  }
  return out;
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
      const parsed = JSON.parse(r.cached_tools_json);
      cachedTools = filterSafeCachedMcpTools(parsed);
    }
  } catch {
    // ignore
  }
  const rawTransport = String(r.transport ?? 'streamable-http');
  const rawAuthType = String(r.auth_type ?? 'headers');
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
      const rows = sql
        .exec<Record<string, unknown>>(
          'SELECT * FROM user_mcp_servers WHERE user_id = ? ORDER BY updated_at DESC',
          uid,
        )
        .toArray();
      return rows.map(parseStoredRow);
    },
    getServer(userId, slugOrDomain) {
      ensureTables();
      const uid = userId.trim() || 'owner';
      const needle = slugOrDomain.trim().toLowerCase();
      if (!needle) return null;
      const direct = sql
        .exec<Record<string, unknown>>(
          'SELECT * FROM user_mcp_servers WHERE user_id = ? AND (slug = ? OR LOWER(id) = ?) LIMIT 1',
          uid,
          needle,
          needle,
        )
        .toArray()[0];
      if (direct) return parseStoredRow(direct);

      const all = this.listServers(uid) as StoredMcpServerRow[];
      const cleanHost = needle.replace(/^https?:\/\//, '').split('/')[0]!.replace(/^www\./, '');
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cleanHost)) {
        return null;
      }
      return (
        all.find((s) => {
          if (s.remoteOrigin.replace(/^https:\/\//, '') === cleanHost) return true;
          if (!s.autoRouteScrape) return false;
          return s.domains.some((rawDom) => {
            const validDom = validateConnectorDomains([rawDom], s.remoteOrigin, true);
            if (!validDom.ok || validDom.domains.length === 0) return false;
            const d = validDom.domains[0]!;
            return cleanHost === d || cleanHost.endsWith(`.${d}`);
          });
        }) ?? null
      );
    },
    upsertServer(row) {
      ensureTables();
      const uid = row.userId.trim() || 'owner';
      const safeTools = filterSafeCachedMcpTools(row.cachedTools);
      const safeToolCount = Array.isArray(row.cachedTools) && row.cachedTools.length > 0 ? safeTools.length : row.toolCount;
      sql.exec(
        `DELETE FROM user_mcp_servers
         WHERE user_id = ? AND slug != ? AND id IN (
           SELECT id FROM user_mcp_servers WHERE user_id = ? ORDER BY updated_at DESC LIMIT -1 OFFSET ?
         )`,
        uid,
        row.slug,
        uid,
        MAX_VAULT_SERVERS_PER_USER - 1,
      );
      sql.exec(
        `INSERT INTO user_mcp_servers (
           id, user_id, slug, name, remote_url, remote_origin, transport, auth_type,
           encrypted_credentials, auth_summary_json, domains_json, auto_route_scrape, cached_tools_json,
           tool_count, enabled, last_verified_at, last_error, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, slug) DO UPDATE SET
           name = excluded.name,
           remote_url = excluded.remote_url,
           remote_origin = excluded.remote_origin,
           transport = excluded.transport,
           auth_type = excluded.auth_type,
           encrypted_credentials = excluded.encrypted_credentials,
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
        row.slug,
        row.name,
        row.remoteUrl,
        row.remoteOrigin,
        row.transport,
        row.authType,
        row.encryptedCredentials,
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
      // Evict ONLY this user's oldest pending states so one tenant cannot evict another user's in-flight OAuth state!
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
      // Delete ONLY matching `(state_hash, user_id)` or expired rows so another user cannot burn a victim's pending state!
      sql.exec('DELETE FROM mcp_oauth_states WHERE (state_hash = ? AND user_id = ?) OR expires_at <= ?', stateHash, uid, now);
      const r = rows[0];
      if (!r) return null;
      if (Number(r.expires_at ?? 0) <= now) return null;
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
    getServer(userId, slugOrDomain) {
      const uid = userId.trim() || 'owner';
      const needle = slugOrDomain.trim().toLowerCase();
      const direct = servers.get(keyOf(uid, needle));
      if (direct) return structuredClone(direct);
      for (const s of servers.values()) {
        if (s.userId === uid && s.id.toLowerCase() === needle) {
          return structuredClone(s);
        }
      }
      const cleanHost = needle.replace(/^https?:\/\//, '').split('/')[0]!.replace(/^www\./, '');
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cleanHost)) {
        return null;
      }
      for (const s of servers.values()) {
        if (s.userId !== uid) continue;
        if (s.remoteOrigin.replace(/^https:\/\//, '') === cleanHost) {
          return structuredClone(s);
        }
        if (s.autoRouteScrape) {
          const matchedDom = s.domains.some((rawDom) => {
            const validDom = validateConnectorDomains([rawDom], s.remoteOrigin, true);
            if (!validDom.ok || validDom.domains.length === 0) return false;
            const d = validDom.domains[0]!;
            return cleanHost === d || cleanHost.endsWith(`.${d}`);
          });
          if (matchedDom) {
            return structuredClone(s);
          }
        }
      }
      return null;
    },
    upsertServer(row) {
      const uid = row.userId.trim() || 'owner';
      const safeTools = filterSafeCachedMcpTools(row.cachedTools);
      const safeToolCount = Array.isArray(row.cachedTools) && row.cachedTools.length > 0 ? safeTools.length : row.toolCount;
      const userRows = [...servers.entries()].filter(([, v]) => v.userId === uid && v.slug.toLowerCase() !== row.slug.toLowerCase());
      if (userRows.length >= MAX_VAULT_SERVERS_PER_USER) {
        userRows.sort((a, b) => a[1].updatedAt - b[1].updatedAt);
        for (let i = 0; i <= userRows.length - MAX_VAULT_SERVERS_PER_USER; i++) {
          servers.delete(userRows[i]![0]);
        }
      }
      servers.set(keyOf(uid, row.slug), structuredClone({ ...row, userId: uid, cachedTools: safeTools, toolCount: safeToolCount }));
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
  const text = new TextDecoder('utf-8', { fatal: false }).decode(merged);
  let json: Record<string, unknown> | null = null;
  try {
    const trimmed = text.trim();
    const parsed = trimmed && isJsonDepthWithinLimit(trimmed, 32) ? JSON.parse(trimmed) : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      json = parsed as Record<string, unknown>;
    }
  } catch {
    json = null;
  }
  return { status: resp.status, headers: resp.headers, json };
}

async function computeMcpOAuthBindHmac(
  vaultMasterKey: string,
  userId: string,
  state: string,
  sessionCsrf: string,
): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(`edgefetch-mcp-oauth-bind:${vaultMasterKey}`),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${userId}|${state}|${sessionCsrf}`));
  return bytesToBase64Url(new Uint8Array(sig));
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

function normalizeConfirmedAuthOrigin(
  raw: string | undefined,
  selfHost?: string,
): { ok: true; origin?: string } | { ok: false; reason: string } {
  if (raw === undefined || raw === null || raw.trim() === '') {
    return { ok: true };
  }
  const check = isSafePublicHttpsUrl(raw, selfHost);
  if (!check.ok) {
    return { ok: false, reason: check.reason };
  }
  if ((check.url.pathname && check.url.pathname !== '/') || check.url.search) {
    return { ok: false, reason: 'confirmedAuthOrigin must be an exact https:// origin without path or query' };
  }
  return { ok: true, origin: check.origin };
}

/**
 * Probes RFC 9728 (`/.well-known/oauth-protected-resource`) and RFC 8414 (`/.well-known/oauth-authorization-server`)
 * on a remote MCP URL using `SAFE_PUBLIC_FETCH`, enforcing that the Authorization Server issuer and endpoints equal
 * `connectorOrigin` unless the operator explicitly confirms a cross-origin `confirmedAuthOrigin`.
 */
export async function probeRemoteMcpOAuthMetadata(params: {
  remoteUrl: string;
  confirmedAuthOrigin?: string;
  fetchFn?: typeof fetch;
  selfHost?: string;
}): Promise<DiscoveredRemoteOAuthMetadata> {
  const urlCheck = isSafePublicHttpsUrl(params.remoteUrl, params.selfHost);
  if (!urlCheck.ok) return { supported: false };

  const confirmedCheck = normalizeConfirmedAuthOrigin(params.confirmedAuthOrigin, params.selfHost);
  if (!confirmedCheck.ok) return { supported: false };

  const fetchFn = params.fetchFn ?? fetch;
  const origin = urlCheck.url.origin;
  const connectorOrigin = urlCheck.origin;
  const canonicalRemoteNoSlash = urlCheck.normalized.replace(/\/+$/, '');
  const pathSuffix = urlCheck.url.pathname && urlCheck.url.pathname !== '/' ? urlCheck.url.pathname.replace(/\/+$/, '') : '';

  let resourceUri = urlCheck.normalized;
  let authIssuerUrl = origin;
  let allowedAuthOrigin = connectorOrigin;
  let scopesSupported: string[] | undefined;

  // 1. RFC 9728 Protected Resource Metadata probe (strict §3.3 `resource` match against `remoteUrl`!)
  const prCandidates = pathSuffix
    ? [`${origin}/.well-known/oauth-protected-resource${pathSuffix}`, `${origin}/.well-known/oauth-protected-resource`]
    : [`${origin}/.well-known/oauth-protected-resource`];

  for (const cand of prCandidates) {
    try {
      const pr = await fetchJsonSafeBounded(cand, fetchFn, params.selfHost, {
        method: 'GET',
        headers: { accept: 'application/json' },
      });
      if (pr.status === 200) {
        if (!pr.json || typeof pr.json.resource !== 'string') {
          // RFC 9728 §3.3: `resource` is REQUIRED and MUST match the connector's canonical URL!
          return { supported: false };
        }
        const rc = isSafePublicHttpsUrl(pr.json.resource, params.selfHost);
        if (!rc.ok || rc.url.search) {
          return { supported: false };
        }
        const prResourceNoSlash = rc.normalized.replace(/\/+$/, '');
        const matchesExactUrl = prResourceNoSlash === canonicalRemoteNoSlash;
        const matchesPathlessOrigin = !pathSuffix && prResourceNoSlash === connectorOrigin;
        if (!matchesExactUrl && !matchesPathlessOrigin) {
          return { supported: false };
        }
        resourceUri = rc.normalized;

        if (pr.json.authorization_servers !== undefined) {
          if (!Array.isArray(pr.json.authorization_servers) || typeof pr.json.authorization_servers[0] !== 'string') {
            return { supported: false };
          }
          const asCheck = isSafePublicHttpsUrl(pr.json.authorization_servers[0], params.selfHost);
          if (!asCheck.ok || asCheck.url.search) {
            return { supported: false };
          }
          if (asCheck.origin !== connectorOrigin) {
            // Never trust sibling shared-hosting PaaS/BaaS tenants as cross-origin authorization servers.
            if (isSharedHostingHostname(urlCheck.url.hostname) && isSharedHostingHostname(asCheck.url.hostname)) {
              return { supported: false };
            }
            if (confirmedCheck.origin !== asCheck.origin) {
              return {
                supported: false,
                requiresAuthOriginConfirmation: true,
                error: 'cross_origin_auth_confirmation_required',
                authOrigin: asCheck.origin,
                connectorOrigin,
              };
            }
            allowedAuthOrigin = confirmedCheck.origin;
          }
          authIssuerUrl = asCheck.normalized.replace(/\/+$/, '');
        }
        if (Array.isArray(pr.json.scopes_supported)) {
          scopesSupported = pr.json.scopes_supported
            .filter((s): s is string => typeof s === 'string' && /^[\x21-\x7e]{1,80}$/.test(s))
            .slice(0, 20);
        }
        break;
      }
    } catch {
      // continue to fallback only on 404/network error before 200 PRM
    }
  }

  // 2. RFC 8414 Authorization Server Metadata probe (strict `issuer` & endpoint origin === `allowedAuthOrigin`!)
  const expectedIssuerNorm = authIssuerUrl.replace(/\/+$/, '');
  const issuerParsed = new URL(authIssuerUrl);
  const issuerPath = issuerParsed.pathname && issuerParsed.pathname !== '/' ? issuerParsed.pathname.replace(/\/+$/, '') : '';
  const asCandidates = issuerPath
    ? [
        `${issuerParsed.origin}/.well-known/oauth-authorization-server${issuerPath}`,
        `${issuerParsed.origin}${issuerPath}/.well-known/openid-configuration`,
      ]
    : [
        `${issuerParsed.origin}/.well-known/oauth-authorization-server`,
        `${issuerParsed.origin}/.well-known/openid-configuration`,
      ];

  for (const asUrl of asCandidates) {
    try {
      const asRes = await fetchJsonSafeBounded(asUrl, fetchFn, params.selfHost, {
        method: 'GET',
        headers: { accept: 'application/json' },
      });
      if (asRes.status === 200 && asRes.json) {
        if (typeof asRes.json.issuer !== 'string') continue;
        const issCheck = isSafePublicHttpsUrl(asRes.json.issuer, params.selfHost);
        if (!issCheck.ok || issCheck.url.search) continue;
        const reportedIssuerNorm = issCheck.normalized.replace(/\/+$/, '');
        if (reportedIssuerNorm !== expectedIssuerNorm || issCheck.origin !== allowedAuthOrigin) continue;

        const authEpCheck = isSafePublicHttpsUrl(asRes.json.authorization_endpoint, params.selfHost);
        const tokenEpCheck = isSafePublicHttpsUrl(asRes.json.token_endpoint, params.selfHost);
        if (!authEpCheck.ok || !tokenEpCheck.ok) continue;
        if (authEpCheck.origin !== allowedAuthOrigin || tokenEpCheck.origin !== allowedAuthOrigin) {
          continue;
        }

        let validatedRegistrationEndpoint: string | undefined;
        if (asRes.json.registration_endpoint !== undefined && asRes.json.registration_endpoint !== null) {
          const regEpCheck = isSafePublicHttpsUrl(asRes.json.registration_endpoint, params.selfHost);
          if (!regEpCheck.ok || regEpCheck.origin !== allowedAuthOrigin) {
            return { supported: false };
          }
          validatedRegistrationEndpoint = regEpCheck.normalized;
        }

        const methods = Array.isArray(asRes.json.code_challenge_methods_supported)
          ? asRes.json.code_challenge_methods_supported.filter((m): m is string => typeof m === 'string')
          : ['S256'];
        if (!methods.includes('S256')) continue;

        if (!scopesSupported && Array.isArray(asRes.json.scopes_supported)) {
          scopesSupported = asRes.json.scopes_supported
            .filter((s): s is string => typeof s === 'string' && /^[\x21-\x7e]{1,80}$/.test(s))
            .slice(0, 20);
        }
        return {
          supported: true,
          ...(allowedAuthOrigin !== connectorOrigin ? { authOrigin: allowedAuthOrigin, connectorOrigin } : {}),
          resource: resourceUri,
          issuer: reportedIssuerNorm,
          authorizationEndpoint: authEpCheck.normalized,
          tokenEndpoint: tokenEpCheck.normalized,
          ...(validatedRegistrationEndpoint ? { registrationEndpoint: validatedRegistrationEndpoint } : {}),
          ...(scopesSupported ? { scopesSupported } : {}),
          codeChallengeMethods: methods,
        };
      }
    } catch {
      // try next candidate
    }
  }

  return { supported: false };
}

/**
 * Initiates Downstream OAuth 2.1 PKCE (`S256`) authorization for a remote MCP server, performing optional
 * RFC 7591 Dynamic Client Registration when `clientId` is omitted and `registration_endpoint` is available.
 * Cross-origin Authorization Servers are rejected with `cross_origin_auth_confirmation_required` unless `confirmedAuthOrigin` matches.
 */
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

  const confirmedCheck = normalizeConfirmedAuthOrigin(params.confirmedAuthOrigin, params.selfHost);
  if (!confirmedCheck.ok) {
    return { ok: false, status: 400, error: 'invalid_confirmed_auth_origin', message: confirmedCheck.reason };
  }

  const fetchFn = params.fetchFn ?? fetch;
  const meta = await probeRemoteMcpOAuthMetadata({
    remoteUrl: urlCheck.normalized,
    ...(confirmedCheck.origin ? { confirmedAuthOrigin: confirmedCheck.origin } : {}),
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
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
        },
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
      // fall through to check clientId below
    }
  }

  if (!clientId) {
    // Support OAuth Client ID Metadata Document (CIMD) default if server omits DCR, or explicit clientId
    clientId = `${params.hubOrigin.replace(/\/+$/, '')}/.well-known/edgefetch-bot.json`;
  }

  const autoRouteScrape = params.autoRouteScrape === true;
  const domValidation = validateConnectorDomains(params.domains, urlCheck.origin, autoRouteScrape);
  if (!domValidation.ok) {
    return { ok: false, status: 400, error: 'invalid_domains', message: domValidation.error };
  }

  const codeVerifier = randomBase64Url(32);
  const codeChallenge = await sha256Base64Url(codeVerifier);
  const state = randomBase64Url(32);
  const stateHash = await sha256Base64Url(state);
  const bindCookieValue = await computeMcpOAuthBindHmac(keyCheck.key, params.userId, state, params.sessionCsrf);

  const cleanName = stripMcpSmugglingChars(params.name ?? '').trim().slice(0, 120) || urlCheck.url.hostname;
  const slug = slugifyMcpServerName(params.slug?.trim() || cleanName);
  const domains = domValidation.domains;
  const canonicalResource = meta.resource ?? urlCheck.normalized;

  const effectiveConfirmedAuthOrigin =
    confirmedCheck.origin && confirmedCheck.origin !== urlCheck.origin ? confirmedCheck.origin : undefined;

  const encryptedPkceBlob = await sealPkceStateBlob({
    vaultMasterKey: keyCheck.key,
    userId: params.userId,
    remoteOrigin: urlCheck.origin,
    blob: {
      codeVerifier,
      issuer: meta.issuer,
      tokenEndpoint: meta.tokenEndpoint,
      ...(effectiveConfirmedAuthOrigin ? { confirmedAuthOrigin: effectiveConfirmedAuthOrigin } : {}),
      clientId,
      ...(clientSecret ? { clientSecret } : {}),
      redirectUri,
      resource: canonicalResource,
    },
  });

  const now = params.now ?? Date.now();
  await params.vaultStore.putOAuthState({
    stateHash,
    userId: params.userId,
    slug,
    name: cleanName,
    remoteUrl: urlCheck.normalized,
    remoteOrigin: urlCheck.origin,
    transport: params.transport === 'sse' ? 'sse' : 'streamable-http',
    domains,
    autoRouteScrape,
    ...(effectiveConfirmedAuthOrigin ? { confirmedAuthOrigin: effectiveConfirmedAuthOrigin } : {}),
    encryptedPkceBlob,
    expiresAt: now + MCP_OAUTH_STATE_TTL_MS,
  });

  const authUrl = new URL(meta.authorizationEndpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);
  const effectiveScope = (params.scope ?? '').trim() || (meta.scopesSupported?.length ? meta.scopesSupported.join(' ') : '');
  if (effectiveScope) {
    authUrl.searchParams.set('scope', effectiveScope);
  }
  authUrl.searchParams.set('resource', canonicalResource);

  return {
    ok: true,
    authorizationUrl: authUrl.toString(),
    bindCookieValue,
    slug,
  };
}

export const startMcpOAuthConnect = startDownstreamMcpOAuth;

/**
 * Completes the Downstream OAuth 2.1 PKCE callback (`GET /admin/mcp/oauth/callback`), verifying session + bind cookie,
 * exchanging `code` + `code_verifier`, and sealing `access_token` + `refresh_token` into `user_mcp_servers`.
 */
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

  const expectedBind = await computeMcpOAuthBindHmac(keyCheck.key, params.userId, params.state, params.sessionCsrf);
  if (!params.bindCookieHeader || !sameBytes(params.bindCookieHeader, expectedBind)) {
    return { ok: false, status: 403, error: 'invalid_oauth_state_binding', message: 'OAuth state cookie binding mismatch.' };
  }

  const now = params.now ?? Date.now();
  const stateHash = await sha256Base64Url(params.state);
  const pending = await params.vaultStore.consumeOAuthState(stateHash, params.userId, now);
  if (!pending) {
    return { ok: false, status: 400, error: 'expired_or_unknown_state', message: 'OAuth state expired, replayed, or belongs to another user.' };
  }

  const pkce = await unsealPkceStateBlob({
    vaultMasterKey: keyCheck.key,
    userId: params.userId,
    remoteOrigin: pending.remoteOrigin,
    ciphertext: pending.encryptedPkceBlob,
  });
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
  const allowedAuthOrigin = pkceConfirmed ?? pending.remoteOrigin.toLowerCase();

  const tokenEpCheck = isSafePublicHttpsUrl(pkce.tokenEndpoint, params.selfHost);
  if (!tokenEpCheck.ok) {
    return { ok: false, status: 400, error: 'unsafe_token_endpoint', message: tokenEpCheck.reason };
  }
  if (tokenEpCheck.origin !== allowedAuthOrigin) {
    return {
      ok: false,
      status: 409,
      error: 'cross_origin_auth_confirmation_required',
      message: 'Token endpoint origin does not match connector origin or confirmed authorization server origin.',
    };
  }
  if (expectedIssuer) {
    const issCheck = isSafePublicHttpsUrl(expectedIssuer, params.selfHost);
    if (!issCheck.ok || issCheck.origin !== allowedAuthOrigin || tokenEpCheck.origin !== issCheck.origin) {
      return { ok: false, status: 400, error: 'unsafe_token_endpoint', message: 'Token endpoint origin does not match expected issuer origin.' };
    }
  }

  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: String(pkce.redirectUri ?? ''),
    client_id: pkce.clientId,
    code_verifier: pkce.codeVerifier,
  });
  if (typeof pkce.clientSecret === 'string' && pkce.clientSecret) {
    form.set('client_secret', pkce.clientSecret);
  }
  if (typeof pkce.resource === 'string' && pkce.resource) {
    form.set('resource', pkce.resource);
  }

  const fetchFn = params.fetchFn ?? fetch;
  let tokenRes: { status: number; headers: Headers; json: Record<string, unknown> | null };
  try {
    tokenRes = await fetchJsonSafeBounded(tokenEpCheck.normalized, fetchFn, params.selfHost, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
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
  const expiresAt =
    Number.isFinite(expiresInSec) && expiresInSec > 0 ? now + Math.floor(expiresInSec * 1_000) : undefined;
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
      tokenEndpoint: tokenEpCheck.normalized,
      ...(pkceConfirmed ? { confirmedAuthOrigin: pkceConfirmed } : {}),
      clientId: pkce.clientId,
      ...(typeof pkce.clientSecret === 'string' && pkce.clientSecret ? { clientSecret: pkce.clientSecret } : {}),
    },
  };

  const sealed = await sealVaultCredentials({
    vaultMasterKey: keyCheck.key,
    userId: params.userId,
    remoteOrigin: pending.remoteOrigin,
    payload: secretPayload,
  });
  if (!sealed.ok) return sealed;

  const existing = await params.vaultStore.getServer(params.userId, pending.slug);
  const row: StoredMcpServerRow = {
    id: existing?.id ?? `mcp_${crypto.randomUUID().replace(/-/g, '').slice(0, 20)}`,
    userId: params.userId,
    slug: pending.slug,
    name: pending.name,
    remoteUrl: pending.remoteUrl,
    remoteOrigin: pending.remoteOrigin,
    transport: pending.transport,
    authType: 'oauth2',
    encryptedCredentials: sealed.ciphertext,
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
