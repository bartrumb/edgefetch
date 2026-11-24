/**
 * Self-hosted OAuth 2.1 + PKCE (`S256`) + Dynamic Client Registration (RFC 7591) + Protected Resource Metadata
 * (RFC 9728) + Authorization Server Metadata (RFC 8414) + HMAC-signed Admin Session cookies.
 *
 * Built with 100% Web Standard Crypto (`crypto.subtle`) and zero external npm packages or external IdP dependencies so
 * MCP clients like Claude Code (`claude mcp add --transport http <name> https://<worker>/mcp`) authenticate out of the
 * box with full consent-screen protection, PKCE S256 verification, audience (`resource`) binding, and instant grant
 * revocation in `/admin`.
 */
// @ts-ignore: `hub/tsconfig.json` uses `@cloudflare/workers-types` without `@types/node`
import { AsyncLocalStorage } from 'node:async_hooks';
import { callerToken, isValidSecretMatch, MIN_TOKEN_LENGTH, sameBytes } from './auth';
import {
  GITHUB_ORG_REVERIFY_TTL_MS,
  isGitHubAuthConfigured,
  isGitHubUserDeAllowlisted,
  isPinnedGitHubFounder,
  reconcileUpgradedFounderOwners,
  resolvePinnedGitHubOwnerId,
  reverifyGitHubOrgAdmission,
  verifySessionJwt,
  type GitHubAuthEnv,
} from './github-auth';
import { getActiveRequestTracer, type ActiveSpanHandle } from './otel';
import { normalizeClientRateLimitIp, readBodyTextCapped, safeDecodeURIComponent } from './safe-input';

export const MCP_SCOPES = ['crawl:read', 'crawl:fetch'] as const;
export const SUPPORTED_MCP_SCOPES = ['crawl:read', 'crawl:fetch', 'mcp:call'] as const;
export type McpScope = (typeof SUPPORTED_MCP_SCOPES)[number];
export type UserRole = 'owner' | 'member';

export interface ActiveCallerAuthContext {
  userId: string;
  role: UserRole;
  scopes: string[];
  principal: string;
}

interface CallerAuthSlot {
  current?: ActiveCallerAuthContext;
  githubAuthEnv?: GitHubAuthEnv;
}

interface AsyncLocalStorageLike<T> {
  getStore(): T | undefined;
  run<R>(store: T, callback: () => R): R;
}

const callerAuthAls: AsyncLocalStorageLike<CallerAuthSlot> = (() => {
  try {
    if (typeof AsyncLocalStorage === 'function') {
      return new (AsyncLocalStorage as unknown as new () => AsyncLocalStorageLike<CallerAuthSlot>)();
    }
  } catch {
    // fallback when async_hooks is unavailable
  }
  let fallbackSlot: CallerAuthSlot | undefined;
  return {
    getStore: () => fallbackSlot,
    run<T>(slot: CallerAuthSlot, fn: () => T): T {
      const prev = fallbackSlot;
      fallbackSlot = slot;
      try {
        return fn();
      } finally {
        fallbackSlot = prev;
      }
    },
  };
})();

export function runWithCallerAuthContext<T>(
  fn: () => T,
  initial?: ActiveCallerAuthContext,
  githubAuthEnv?: GitHubAuthEnv,
): T {
  return callerAuthAls.run(
    {
      ...(initial ? { current: initial } : {}),
      ...(githubAuthEnv ? { githubAuthEnv } : {}),
    },
    fn,
  );
}

export function setActiveCallerAuthContext(ctx: ActiveCallerAuthContext): void {
  const slot = callerAuthAls.getStore();
  if (slot) {
    slot.current = ctx;
  }
}

export function getActiveCallerAuthContext(): ActiveCallerAuthContext | undefined {
  return callerAuthAls.getStore()?.current;
}

export type UserAdmissionMethod = 'owner' | 'allowlist_id' | 'allowlist_login' | 'org' | 'open';

export type UserMutationKind =
  | 'org_reverify'
  | 'org_revoke'
  | 'oauth_login_existing'
  | 'oauth_login_new'
  | 'founder_heal'
  | 'admin_disable'
  | 'admin_role'
  | 'demote_unapproved_owner';

export interface HubUserRecord {
  userId: string;
  githubId?: string;
  githubLogin?: string;
  avatarUrl?: string;
  role: UserRole;
  promotedByOwnerId?: string;
  sessionEpoch?: number;
  disabled?: boolean;
  admittedVia?: UserAdmissionMethod;
  admittedOrg?: string;
  encryptedGhToken?: string;
  orgVerifiedAt?: number;
  createdAt: number;
  lastLoginAt: number;
  tokenCount?: number;
  storedTokenCount?: number;
  activeTokenCount?: number;
  usedTokenCount?: number;
  grantCount?: number;
  mutationKind?: UserMutationKind;
  expectedSessionEpoch?: number;
  expectedRole?: UserRole;
  reconcilePinnedOwnerId?: string;
  callerIsImmutableFounder?: boolean;
  configuredFounderUserId?: string | null;
  allowAlreadyDisabled?: boolean;
  disableFailedReason?: 'not_found' | 'already_disabled' | 'owner_protected' | 'founder_protected';
  mutationAborted?: boolean;
}

export const MAX_OAUTH_GRANTS_PER_USER = 64;
export const MAX_OAUTH_TOKENS_PER_USER = MAX_OAUTH_GRANTS_PER_USER * 3;
export const MAX_OAUTH_TOKENS_GLOBAL = 65_536;
export const MAX_OAUTH_TOKENS_NON_OWNER_GLOBAL = MAX_OAUTH_TOKENS_GLOBAL - MAX_OAUTH_TOKENS_PER_USER * 4;
export const MAX_OAUTH_CODES_PER_USER = 32;
export const MAX_OAUTH_CODES_GLOBAL = 16_384;
export const MAX_REFRESH_ROTATIONS_PER_GRANT_WINDOW = 6;
export const REFRESH_RATE_LIMIT_WINDOW_MS = 60_000;

export class OAuthQuotaExceededError extends Error {
  readonly status = 429;
  readonly code = 'user_quota_exceeded';
  constructor(message = 'OAuth token quota exceeded; revoke unused grants before minting new tokens') {
    super(message);
    this.name = 'OAuthQuotaExceededError';
  }
}

export interface AdminPrincipal {
  userId: string;
  role: UserRole;
  authMethod: 'github' | 'owner_token';
  csrf: string;
  epoch?: number;
  jti?: string;
  githubLogin?: string;
  avatarUrl?: string;
  expiresAt: number;
}

const AUTH_CODE_TTL_MS = 90_000; // 90s single-use authorization code
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1_000; // 1h access token (with 90d rotating refresh token)
const REFRESH_TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1_000; // 90d rotating refresh token
const ADMIN_SESSION_TTL_MS = 8 * 60 * 60_000; // 8h admin browser session
const RATE_LIMIT_WINDOW_MS = 5 * 60_000; // 5m brute-force window
const RATE_LIMIT_MAX_FAILURES = 5;
const REGISTER_RATE_LIMIT_MAX = 20; // Max 20 anonymous client registrations per 5m per IP (H-S1)
const MAX_AUTH_FAILURE_BUCKETS = 100; // Bounds SQLite auth_failures against spoofed IPv6 sprays (H-S5)

export const ADMIN_COOKIE_NAME = '__Host-ef_admin_session';
export const ADMIN_COOKIE_NAME_DEV = 'ef_admin_session';
const CONSENT_CSRF_COOKIE = 'ef_oauth_csrf';

export interface OAuthClientRecord {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  createdAt: number;
}

export interface OAuthCodeRecord {
  codeHash: string;
  clientId: string;
  clientName: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
  userId?: string;
  userRole?: UserRole;
  expiresAt: number;
}

export interface OAuthTokenRecord {
  grantId: string;
  kind: 'access' | 'refresh';
  clientId: string;
  clientName: string;
  scopes: string[];
  resource: string;
  userId?: string;
  userRole?: UserRole;
  createdAt: number;
  expiresAt: number;
}

export interface OAuthGrantSummary {
  grantId: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  userId?: string;
  userRole?: UserRole;
  createdAt: number;
  expiresAt: number;
}

export interface RotateRefreshParams {
  refreshHash: string;
  clientId: string;
  nextAccessHash: string;
  nextRefreshHash: string;
  now: number;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  claimedGrantId?: string;
  claimedGeneration?: number;
}

export type RotateRefreshResult =
  | {
      ok: true;
      grantId: string;
      clientId: string;
      clientName: string;
      scopes: string[];
      resource: string;
      userId: string;
      userRole: UserRole;
      rotationCounter: number;
    }
  | {
      ok: false;
      error: 'invalid_grant';
      replayDetected?: boolean;
      grantId?: string;
      clientId?: string;
    }
  | {
      ok: false;
      error: 'slow_down';
      retryAfterSec: number;
      grantId?: string;
      clientId?: string;
    }
  | {
      ok: false;
      error: 'user_quota_exceeded';
      message: string;
      grantId?: string;
      clientId?: string;
    };

export interface OAuthStore {
  putClient(client: OAuthClientRecord): Promise<void> | void;
  getClient(clientId: string): Promise<OAuthClientRecord | null> | OAuthClientRecord | null;
  putCode(code: OAuthCodeRecord): Promise<void> | void;
  consumeCode(codeHash: string, now: number): Promise<OAuthCodeRecord | null> | OAuthCodeRecord | null;
  putTokenPair(params: {
    grantId: string;
    accessHash: string;
    refreshHash: string;
    clientId: string;
    clientName: string;
    scopes: string[];
    resource: string;
    userId?: string;
    userRole?: UserRole;
    createdAt: number;
    accessExpiresAt: number;
    refreshExpiresAt: number;
  }): Promise<void> | void;
  getAccessToken(tokenHash: string, now: number): Promise<OAuthTokenRecord | null> | OAuthTokenRecord | null;
  consumeRefreshToken(tokenHash: string, now: number): Promise<OAuthTokenRecord | null> | OAuthTokenRecord | null;
  rotateRefreshToken(params: RotateRefreshParams): Promise<RotateRefreshResult> | RotateRefreshResult;
  listGrants(now: number, userId?: string): Promise<OAuthGrantSummary[]> | OAuthGrantSummary[];
  revokeGrant(grantId: string, userId?: string): Promise<boolean> | boolean;
  revokeByTokenHash(tokenHash: string): Promise<void> | void;
  upsertUser?(user: HubUserRecord): Promise<HubUserRecord> | HubUserRecord;
  getUser?(userId: string): Promise<HubUserRecord | null> | HubUserRecord | null;
  listUsers?(): Promise<HubUserRecord[]> | HubUserRecord[];
  countUsers?(): Promise<number> | number;
  updateUserRole?(userId: string, role: UserRole, promotedByOwnerId?: string | null): Promise<boolean> | boolean;
  enforcePinnedFounderOwners?(pinnedOwnerId: string): Promise<number> | number;
  checkAuthLockout(
    bucket: string,
    now: number,
    maxFailures?: number,
  ): Promise<{ allowed: boolean; retryAfterSec: number }> | { allowed: boolean; retryAfterSec: number };
  recordAuthFailure(
    bucket: string,
    now: number,
    windowMs: number,
    maxFailures: number,
  ): Promise<{ allowed: boolean; retryAfterSec: number }> | { allowed: boolean; retryAfterSec: number };
  clearAuthFailures(bucket: string): Promise<void> | void;
}

export interface SqlStorageLike {
  exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): { toArray(): T[] };
}

export const OAUTH_SQLITE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_name TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    resource TEXT NOT NULL,
    user_id TEXT NOT NULL DEFAULT 'owner',
    user_role TEXT NOT NULL DEFAULT 'owner',
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_name TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    resource TEXT NOT NULL,
    user_id TEXT NOT NULL DEFAULT 'owner',
    user_role TEXT NOT NULL DEFAULT 'owner',
    used_at INTEGER,
    rotation_counter INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS oauth_grant_rate_limits (
    grant_id TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    github_id TEXT,
    github_login TEXT NOT NULL,
    avatar_url TEXT,
    role TEXT NOT NULL DEFAULT 'member',
    promoted_by_owner_id TEXT,
    session_epoch INTEGER NOT NULL DEFAULT 1,
    disabled INTEGER NOT NULL DEFAULT 0,
    admitted_via TEXT,
    admitted_org TEXT,
    encrypted_gh_token TEXT,
    org_verified_at INTEGER,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS auth_failures (
    bucket TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS admin_revocations (
    key TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );
`;

function normalizeRoleForUser(userId: string, rawRole?: string | null): UserRole {
  if (rawRole === 'owner') return 'owner';
  if (rawRole === 'member') return 'member';
  return userId === 'owner' ? 'owner' : 'member';
}

/** SQLite-backed `OAuthStore` living inside `AgentHubDO` (requires zero separate KV namespaces). */
export function createSqliteOAuthStore(sql: SqlStorageLike): OAuthStore {
  let multiUserMigrated = false;
  const ensureMultiUserColumns = () => {
    if (multiUserMigrated) return;
    try {
      sql.exec(OAUTH_SQLITE_SCHEMA);
      const readExistingCols = (tbl: string): Set<string> => {
        try {
          const rows = sql.exec<{ name?: string }>(`PRAGMA table_info(${tbl})`).toArray();
          return new Set(rows.map((r) => (typeof r?.name === 'string' ? r.name : '')).filter(Boolean));
        } catch {
          return new Set();
        }
      };
      const existingByTable: Record<string, Set<string>> = {
        oauth_codes: readExistingCols('oauth_codes'),
        oauth_tokens: readExistingCols('oauth_tokens'),
        users: readExistingCols('users'),
      };
      const alterSpecs: Array<{ table: 'oauth_codes' | 'oauth_tokens' | 'users'; col: string; ddl: string }> = [
        { table: 'oauth_codes', col: 'user_id', ddl: "ALTER TABLE oauth_codes ADD COLUMN user_id TEXT NOT NULL DEFAULT 'owner'" },
        { table: 'oauth_codes', col: 'user_role', ddl: "ALTER TABLE oauth_codes ADD COLUMN user_role TEXT NOT NULL DEFAULT 'owner'" },
        { table: 'oauth_tokens', col: 'user_id', ddl: "ALTER TABLE oauth_tokens ADD COLUMN user_id TEXT NOT NULL DEFAULT 'owner'" },
        { table: 'oauth_tokens', col: 'user_role', ddl: "ALTER TABLE oauth_tokens ADD COLUMN user_role TEXT NOT NULL DEFAULT 'owner'" },
        { table: 'oauth_tokens', col: 'used_at', ddl: 'ALTER TABLE oauth_tokens ADD COLUMN used_at INTEGER' },
        { table: 'oauth_tokens', col: 'rotation_counter', ddl: 'ALTER TABLE oauth_tokens ADD COLUMN rotation_counter INTEGER NOT NULL DEFAULT 0' },
        { table: 'users', col: 'promoted_by_owner_id', ddl: 'ALTER TABLE users ADD COLUMN promoted_by_owner_id TEXT' },
        { table: 'users', col: 'session_epoch', ddl: 'ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 1' },
        { table: 'users', col: 'disabled', ddl: 'ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0' },
        { table: 'users', col: 'admitted_via', ddl: 'ALTER TABLE users ADD COLUMN admitted_via TEXT' },
        { table: 'users', col: 'admitted_org', ddl: 'ALTER TABLE users ADD COLUMN admitted_org TEXT' },
        { table: 'users', col: 'encrypted_gh_token', ddl: 'ALTER TABLE users ADD COLUMN encrypted_gh_token TEXT' },
        { table: 'users', col: 'org_verified_at', ddl: 'ALTER TABLE users ADD COLUMN org_verified_at INTEGER' },
      ];
      for (const spec of alterSpecs) {
        if (existingByTable[spec.table]?.has(spec.col)) continue;
        try {
          sql.exec(spec.ddl);
        } catch {
          // Column already exists
        }
      }
      sql.exec('SELECT user_id FROM oauth_tokens LIMIT 1');
      sql.exec(
        'SELECT promoted_by_owner_id, session_epoch, disabled, admitted_via, admitted_org, encrypted_gh_token, org_verified_at FROM users LIMIT 1',
      );
      multiUserMigrated = true;
    } catch {
      // Schema not yet initialized; will run on first query
    }
  };
  const demoteUnapprovedOwnersSqlite = (explicitPinnedOwnerId?: string | null): number => {
    ensureMultiUserColumns();
    const pinnedOwnerId =
      (explicitPinnedOwnerId && /^[1-9][0-9]{0,19}$/.test(explicitPinnedOwnerId.trim())
        ? explicitPinnedOwnerId.trim()
        : null) ?? resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
    if (!pinnedOwnerId) return 0;
    const staleOwners = sql
      .exec<{ user_id: string }>(
        `SELECT user_id FROM users
          WHERE user_id != 'owner'
            AND role = 'owner'
            AND COALESCE(github_id, '') != ?
            AND COALESCE(promoted_by_owner_id, '') NOT IN (?, 'owner')`,
        pinnedOwnerId,
        pinnedOwnerId,
      )
      .toArray();
    if (staleOwners.length === 0) return 0;
    sql.exec(
      `UPDATE users
          SET role = 'member',
              promoted_by_owner_id = NULL,
              session_epoch = COALESCE(session_epoch, 1) + 1
        WHERE user_id != 'owner'
          AND role = 'owner'
          AND COALESCE(github_id, '') != ?
          AND COALESCE(promoted_by_owner_id, '') NOT IN (?, 'owner')`,
      pinnedOwnerId,
      pinnedOwnerId,
    );
    for (const row of staleOwners) {
      sql.exec("UPDATE oauth_tokens SET user_role = 'member' WHERE user_id = ?", row.user_id);
      sql.exec("UPDATE oauth_codes SET user_role = 'member' WHERE user_id = ?", row.user_id);
    }
    return staleOwners.length;
  };
  ensureMultiUserColumns();
  demoteUnapprovedOwnersSqlite();

  return {
    putClient(c) {
      // Evict only clients that have NO active grants or pending authorization codes (H-S1).
      sql.exec(
        `DELETE FROM oauth_clients
         WHERE client_id IN (
           SELECT oc.client_id
           FROM oauth_clients oc
           WHERE NOT EXISTS (SELECT 1 FROM oauth_tokens ot WHERE ot.client_id = oc.client_id AND ot.expires_at > ?)
             AND NOT EXISTS (SELECT 1 FROM oauth_codes cd WHERE cd.client_id = oc.client_id AND cd.expires_at > ?)
           ORDER BY oc.created_at DESC
           LIMIT -1 OFFSET 499
         )`,
        c.createdAt,
        c.createdAt,
      );
      sql.exec(
        'INSERT OR REPLACE INTO oauth_clients (client_id, client_name, redirect_uris_json, created_at) VALUES (?, ?, ?, ?)',
        c.clientId,
        c.clientName,
        JSON.stringify(c.redirectUris),
        c.createdAt,
      );
    },
    getClient(clientId) {
      const rows = sql
        .exec<{ client_id: string; client_name: string; redirect_uris_json: string; created_at: number }>(
          'SELECT client_id, client_name, redirect_uris_json, created_at FROM oauth_clients WHERE client_id = ?',
          clientId,
        )
        .toArray();
      const r = rows[0];
      if (!r) return null;
      return {
        clientId: r.client_id,
        clientName: r.client_name,
        redirectUris: JSON.parse(r.redirect_uris_json) as string[],
        createdAt: r.created_at,
      };
    },
    putCode(code) {
      ensureMultiUserColumns();
      const userId = code.userId ?? 'owner';
      const userRole = normalizeRoleForUser(userId, code.userRole);
      sql.exec('DELETE FROM oauth_codes WHERE expires_at <= ?', code.expiresAt - AUTH_CODE_TTL_MS);
      // Per-user authorization code cap: evict ONLY this user's oldest pending codes beyond MAX_OAUTH_CODES_PER_USER - 1.
      sql.exec(
        `DELETE FROM oauth_codes
         WHERE user_id = ?
           AND code_hash IN (
             SELECT code_hash FROM oauth_codes
              WHERE user_id = ?
              ORDER BY expires_at DESC, ROWID DESC
              LIMIT -1 OFFSET ?
           )`,
        userId,
        userId,
        MAX_OAUTH_CODES_PER_USER - 1,
      );
      const totalCodes = sql.exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_codes').toArray()[0]?.c ?? 0;
      if (totalCodes >= MAX_OAUTH_CODES_GLOBAL) {
        if (userId !== 'owner') {
          throw new OAuthQuotaExceededError('Global OAuth authorization code capacity reached; retry shortly');
        }
        sql.exec(
          `DELETE FROM oauth_codes
           WHERE user_id = 'owner'
             AND code_hash IN (
               SELECT code_hash FROM oauth_codes WHERE user_id = 'owner' ORDER BY expires_at ASC, ROWID ASC LIMIT 1
             )`,
        );
      }
      sql.exec(
        `INSERT OR REPLACE INTO oauth_codes
         (code_hash, client_id, client_name, redirect_uri, code_challenge, scopes_json, resource, user_id, user_role, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        code.codeHash,
        code.clientId,
        code.clientName,
        code.redirectUri,
        code.codeChallenge,
        JSON.stringify(code.scopes),
        code.resource,
        userId,
        userRole,
        code.expiresAt,
      );
    },
    consumeCode(codeHash, now) {
      ensureMultiUserColumns();
      const rows = sql
        .exec<{
          code_hash: string;
          client_id: string;
          client_name: string;
          redirect_uri: string;
          code_challenge: string;
          scopes_json: string;
          resource: string;
          user_id?: string;
          user_role?: string;
          expires_at: number;
        }>('SELECT * FROM oauth_codes WHERE code_hash = ?', codeHash)
        .toArray();
      sql.exec('DELETE FROM oauth_codes WHERE code_hash = ? OR expires_at <= ?', codeHash, now);
      const r = rows[0];
      if (!r || r.expires_at <= now) return null;
      const userId = r.user_id || 'owner';
      return {
        codeHash: r.code_hash,
        clientId: r.client_id,
        clientName: r.client_name,
        redirectUri: r.redirect_uri,
        codeChallenge: r.code_challenge,
        scopes: JSON.parse(r.scopes_json) as string[],
        resource: r.resource,
        userId,
        userRole: normalizeRoleForUser(userId, r.user_role),
        expiresAt: r.expires_at,
      };
    },
    putTokenPair(p) {
      ensureMultiUserColumns();
      const userId = p.userId ?? 'owner';
      const userRole = normalizeRoleForUser(userId, p.userRole);
      const pinnedFounderId = resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
      const isFounderUser = userId === 'owner' || (pinnedFounderId !== null && userId === `gh_${pinnedFounderId}`);
      sql.exec('DELETE FROM oauth_tokens WHERE expires_at <= ?', p.createdAt);
      sql.exec('DELETE FROM oauth_grant_rate_limits WHERE reset_at <= ?', p.createdAt);
      // Ensure at most 1 used marker per grant for this user before checking caps
      sql.exec(
        `DELETE FROM oauth_tokens
         WHERE user_id = ? AND (kind = 'refresh_used' OR used_at IS NOT NULL)
           AND token_hash NOT IN (
             SELECT MAX(token_hash) FROM oauth_tokens
              WHERE user_id = ? AND (kind = 'refresh_used' OR used_at IS NOT NULL)
              GROUP BY grant_id
           )`,
        userId,
        userId,
      );
      // Per-user active grant cap: evict ONLY oldest grants belonging to THIS user_id beyond MAX_OAUTH_GRANTS_PER_USER - 1.
      sql.exec(
        `DELETE FROM oauth_tokens
         WHERE user_id = ?
           AND grant_id IN (
             SELECT grant_id FROM oauth_tokens
              WHERE user_id = ?
              GROUP BY grant_id
              ORDER BY MIN(created_at) DESC, MAX(ROWID) DESC
              LIMIT -1 OFFSET ?
           )`,
        userId,
        userId,
        MAX_OAUTH_GRANTS_PER_USER - 1,
      );
      // If still above MAX_OAUTH_TOKENS_PER_USER - 2, evict oldest used markers for THIS user first
      const curUserTokens =
        sql.exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE user_id = ?', userId).toArray()[0]?.c ?? 0;
      if (curUserTokens + 2 > MAX_OAUTH_TOKENS_PER_USER) {
        const excess = curUserTokens + 2 - MAX_OAUTH_TOKENS_PER_USER;
        sql.exec(
          `DELETE FROM oauth_tokens
           WHERE user_id = ?
             AND token_hash IN (
               SELECT token_hash FROM oauth_tokens
                WHERE user_id = ? AND (kind = 'refresh_used' OR used_at IS NOT NULL)
                ORDER BY COALESCE(used_at, created_at) ASC, ROWID ASC
                LIMIT ?
             )`,
          userId,
          userId,
          excess,
        );
      }
      sql.exec(
        `DELETE FROM oauth_tokens
         WHERE user_id = ?
           AND token_hash IN (
             SELECT token_hash FROM oauth_tokens
              WHERE user_id = ?
              ORDER BY created_at DESC, ROWID DESC
              LIMIT -1 OFFSET ?
           )`,
        userId,
        userId,
        MAX_OAUTH_TOKENS_PER_USER - 2,
      );
      const totalTokens = sql.exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens').toArray()[0]?.c ?? 0;
      const effectiveGlobalCap = isFounderUser ? MAX_OAUTH_TOKENS_GLOBAL : MAX_OAUTH_TOKENS_NON_OWNER_GLOBAL;
      if (totalTokens + 2 > effectiveGlobalCap) {
        // Evict stale used refresh markers from non-founder users first so used markers never block new grants
        const needed = totalTokens + 2 - effectiveGlobalCap;
        sql.exec(
          `DELETE FROM oauth_tokens
           WHERE token_hash IN (
             SELECT token_hash FROM oauth_tokens
              WHERE user_id != 'owner' AND (kind = 'refresh_used' OR used_at IS NOT NULL)
              ORDER BY COALESCE(used_at, created_at) ASC, ROWID ASC
              LIMIT ?
           )`,
          needed,
        );
        const afterTrimTotal = sql.exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens').toArray()[0]?.c ?? 0;
        if (afterTrimTotal + 2 > effectiveGlobalCap) {
          if (!isFounderUser) {
            throw new OAuthQuotaExceededError();
          }
          sql.exec(
            `DELETE FROM oauth_tokens
             WHERE user_id = ?
               AND grant_id IN (
                 SELECT grant_id FROM oauth_tokens
                  WHERE user_id = ?
                  GROUP BY grant_id
                  ORDER BY MIN(created_at) ASC, MIN(ROWID) ASC
                  LIMIT 1
               )`,
            userId,
            userId,
          );
        }
      }
      const scopesJson = JSON.stringify(p.scopes);
      sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', p.grantId);
      sql.exec(
        `INSERT OR REPLACE INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, user_id, user_role, used_at, rotation_counter, created_at, expires_at)
         VALUES (?, ?, 'access', ?, ?, ?, ?, ?, ?, NULL, 0, ?, ?)`,
        p.accessHash,
        p.grantId,
        p.clientId,
        p.clientName,
        scopesJson,
        p.resource,
        userId,
        userRole,
        p.createdAt,
        p.accessExpiresAt,
      );
      sql.exec(
        `INSERT OR REPLACE INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, user_id, user_role, used_at, rotation_counter, created_at, expires_at)
         VALUES (?, ?, 'refresh', ?, ?, ?, ?, ?, ?, NULL, 0, ?, ?)`,
        p.refreshHash,
        p.grantId,
        p.clientId,
        p.clientName,
        scopesJson,
        p.resource,
        userId,
        userRole,
        p.createdAt,
        p.refreshExpiresAt,
      );
    },
    getAccessToken(tokenHash, now) {
      ensureMultiUserColumns();
      const rows = sql
        .exec<{
          grant_id: string;
          kind: string;
          client_id: string;
          client_name: string;
          scopes_json: string;
          resource: string;
          user_id?: string;
          user_role?: string;
          created_at: number;
          expires_at: number;
        }>("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'access'", tokenHash)
        .toArray();
      const r = rows[0];
      if (!r) return null;
      if (r.expires_at <= now) {
        sql.exec('DELETE FROM oauth_tokens WHERE token_hash = ?', tokenHash);
        return null;
      }
      const userId = r.user_id || 'owner';
      return {
        grantId: r.grant_id,
        kind: 'access',
        clientId: r.client_id,
        clientName: r.client_name,
        scopes: JSON.parse(r.scopes_json) as string[],
        resource: r.resource,
        userId,
        userRole: normalizeRoleForUser(userId, r.user_role),
        createdAt: r.created_at,
        expiresAt: r.expires_at,
      };
    },
    consumeRefreshToken(tokenHash, now) {
      ensureMultiUserColumns();
      const rows = sql
        .exec<{
          grant_id: string;
          kind: string;
          client_id: string;
          client_name: string;
          scopes_json: string;
          resource: string;
          user_id?: string;
          user_role?: string;
          created_at: number;
          expires_at: number;
        }>("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'", tokenHash)
        .toArray();
      const r = rows[0];
      if (!r) return null;
      // Rotate both previous access & refresh tokens under this grant before minting the fresh pair.
      sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', r.grant_id);
      if (r.expires_at <= now) return null;
      const userId = r.user_id || 'owner';
      return {
        grantId: r.grant_id,
        kind: 'refresh',
        clientId: r.client_id,
        clientName: r.client_name,
        scopes: JSON.parse(r.scopes_json) as string[],
        resource: r.resource,
        userId,
        userRole: normalizeRoleForUser(userId, r.user_role),
        createdAt: r.created_at,
        expiresAt: r.expires_at,
      };
    },
    rotateRefreshToken(params) {
      ensureMultiUserColumns();
      const rows = sql
        .exec<{
          grant_id: string;
          kind: string;
          client_id: string;
          client_name: string;
          scopes_json: string;
          resource: string;
          user_id?: string;
          user_role?: string;
          used_at?: number | null;
          rotation_counter?: number;
          created_at: number;
          expires_at: number;
        }>("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind IN ('refresh', 'refresh_used')", params.refreshHash)
        .toArray();
      const r = rows[0];
      if (!r) {
        // Lineage replay check: if an authenticated older-generation refresh token (`gen < active.rotation_counter`)
        // whose used marker was replaced on a subsequent rotation is re-presented, revoke the entire grant!
        if (
          params.claimedGrantId &&
          typeof params.claimedGeneration === 'number' &&
          params.claimedGeneration >= 0 &&
          params.clientId
        ) {
          const activeGrant = sql
            .exec<{ client_id: string; expires_at: number; rotation_counter?: number }>(
              "SELECT client_id, expires_at, rotation_counter FROM oauth_tokens WHERE grant_id = ? AND kind = 'refresh' LIMIT 1",
              params.claimedGrantId,
            )
            .toArray()[0];
          if (
            activeGrant &&
            activeGrant.expires_at > params.now &&
            activeGrant.client_id === params.clientId &&
            params.claimedGeneration < Number(activeGrant.rotation_counter ?? 0)
          ) {
            sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', params.claimedGrantId);
            sql.exec('DELETE FROM oauth_grant_rate_limits WHERE grant_id = ?', params.claimedGrantId);
            return {
              ok: false,
              error: 'invalid_grant',
              replayDetected: true,
              grantId: params.claimedGrantId,
              clientId: params.clientId,
            };
          }
        }
        return { ok: false, error: 'invalid_grant' };
      }
      if (r.expires_at <= params.now) {
        sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', r.grant_id);
        sql.exec('DELETE FROM oauth_grant_rate_limits WHERE grant_id = ?', r.grant_id);
        return { ok: false, error: 'invalid_grant' };
      }
      // Replay of an already-rotated refresh token immediately revokes the ENTIRE grant (H-S3 / U2)!
      if (r.kind === 'refresh_used' || (r.used_at !== null && r.used_at !== undefined)) {
        sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', r.grant_id);
        sql.exec('DELETE FROM oauth_grant_rate_limits WHERE grant_id = ?', r.grant_id);
        return {
          ok: false,
          error: 'invalid_grant',
          replayDetected: true,
          grantId: r.grant_id,
          clientId: r.client_id,
        };
      }
      // Verify client_id BEFORE mutating the grant or touching rate limits so a wrong client_id cannot burn a valid grant (H-S3)!
      if (!params.clientId || r.client_id !== params.clientId) {
        return { ok: false, error: 'invalid_grant' };
      }

      const userId = r.user_id || 'owner';
      let userRole = normalizeRoleForUser(userId, r.user_role);
      if (userId !== 'owner') {
        const liveRow = sql
          .exec<{ role: string; disabled?: number }>('SELECT role, disabled FROM users WHERE user_id = ? LIMIT 1', userId)
          .toArray()[0];
        if (!liveRow || Number(liveRow.disabled ?? 0) !== 0) {
          sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', r.grant_id);
          sql.exec('DELETE FROM oauth_grant_rate_limits WHERE grant_id = ?', r.grant_id);
          return { ok: false, error: 'invalid_grant' };
        }
        userRole = normalizeRoleForUser(userId, liveRow.role);
      }

      // U2: Per-grant refresh rate limit (max 6 rotations per 60s window)
      sql.exec('DELETE FROM oauth_grant_rate_limits WHERE reset_at <= ?', params.now);
      const rlRow = sql
        .exec<{ count: number; reset_at: number }>(
          'SELECT count, reset_at FROM oauth_grant_rate_limits WHERE grant_id = ?',
          r.grant_id,
        )
        .toArray()[0];
      if (rlRow && rlRow.reset_at > params.now && rlRow.count >= MAX_REFRESH_ROTATIONS_PER_GRANT_WINDOW) {
        return {
          ok: false,
          error: 'slow_down',
          retryAfterSec: Math.max(1, Math.ceil((rlRow.reset_at - params.now) / 1_000)),
          grantId: r.grant_id,
          clientId: r.client_id,
        };
      }

      // U2: Prune expired tokens first, then enforce per-user & global caps BEFORE mutating this grant
      sql.exec('DELETE FROM oauth_tokens WHERE expires_at <= ?', params.now);
      const pinnedFounderId = resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
      const isFounderUser = userId === 'owner' || (pinnedFounderId !== null && userId === `gh_${pinnedFounderId}`);

      let otherUserRows =
        sql
          .exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE user_id = ? AND grant_id != ?', userId, r.grant_id)
          .toArray()[0]?.c ?? 0;
      if (otherUserRows + 3 > MAX_OAUTH_TOKENS_PER_USER) {
        const excess = otherUserRows + 3 - MAX_OAUTH_TOKENS_PER_USER;
        sql.exec(
          `DELETE FROM oauth_tokens
           WHERE user_id = ? AND grant_id != ?
             AND token_hash IN (
               SELECT token_hash FROM oauth_tokens
                WHERE user_id = ? AND grant_id != ? AND (kind = 'refresh_used' OR used_at IS NOT NULL)
                ORDER BY COALESCE(used_at, created_at) ASC, ROWID ASC
                LIMIT ?
             )`,
          userId,
          r.grant_id,
          userId,
          r.grant_id,
          excess,
        );
        otherUserRows =
          sql
            .exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE user_id = ? AND grant_id != ?', userId, r.grant_id)
            .toArray()[0]?.c ?? 0;
      }
      const otherUserGrants =
        sql
          .exec<{ c: number }>(
            'SELECT COUNT(DISTINCT grant_id) AS c FROM oauth_tokens WHERE user_id = ? AND grant_id != ?',
            userId,
            r.grant_id,
          )
          .toArray()[0]?.c ?? 0;
      if (otherUserRows + 3 > MAX_OAUTH_TOKENS_PER_USER || otherUserGrants + 1 > MAX_OAUTH_GRANTS_PER_USER) {
        return {
          ok: false,
          error: 'user_quota_exceeded',
          message: 'Per-user OAuth token quota exceeded; revoke unused grants before rotating',
          grantId: r.grant_id,
          clientId: r.client_id,
        };
      }

      const effectiveGlobalCap = isFounderUser ? MAX_OAUTH_TOKENS_GLOBAL : MAX_OAUTH_TOKENS_NON_OWNER_GLOBAL;
      let totalOtherRows =
        sql.exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE grant_id != ?', r.grant_id).toArray()[0]?.c ?? 0;
      if (totalOtherRows + 3 > effectiveGlobalCap) {
        const needed = totalOtherRows + 3 - effectiveGlobalCap;
        sql.exec(
          `DELETE FROM oauth_tokens
           WHERE grant_id != ?
             AND token_hash IN (
               SELECT token_hash FROM oauth_tokens
                WHERE grant_id != ? AND user_id != 'owner' AND (kind = 'refresh_used' OR used_at IS NOT NULL)
                ORDER BY COALESCE(used_at, created_at) ASC, ROWID ASC
                LIMIT ?
             )`,
          r.grant_id,
          r.grant_id,
          needed,
        );
        totalOtherRows =
          sql.exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE grant_id != ?', r.grant_id).toArray()[0]?.c ?? 0;
        if (totalOtherRows + 3 > effectiveGlobalCap) {
          if (!isFounderUser) {
            return {
              ok: false,
              error: 'user_quota_exceeded',
              message: 'Global OAuth token capacity reached; retry shortly',
              grantId: r.grant_id,
              clientId: r.client_id,
            };
          }
          sql.exec(
            `DELETE FROM oauth_tokens
             WHERE grant_id != ? AND user_id = ?
               AND token_hash IN (
                 SELECT token_hash FROM oauth_tokens
                  WHERE grant_id != ? AND user_id = ? AND (kind = 'refresh_used' OR used_at IS NOT NULL)
                  ORDER BY COALESCE(used_at, created_at) ASC, ROWID ASC
                  LIMIT ?
               )`,
            r.grant_id,
            userId,
            r.grant_id,
            userId,
            totalOtherRows + 3 - effectiveGlobalCap,
          );
        }
      }

      // Record per-grant rate limit hit
      if (!rlRow || rlRow.reset_at <= params.now) {
        sql.exec(
          'INSERT OR REPLACE INTO oauth_grant_rate_limits (grant_id, count, reset_at) VALUES (?, 1, ?)',
          r.grant_id,
          params.now + REFRESH_RATE_LIMIT_WINDOW_MS,
        );
      } else {
        sql.exec('UPDATE oauth_grant_rate_limits SET count = ? WHERE grant_id = ?', rlRow.count + 1, r.grant_id);
      }

      // U2: Delete ALL prior access & prior `refresh_used` markers for this grant so each grant holds
      // at most 1 active access + 1 active refresh + 1 `refresh_used` marker (`<= 3` rows O(1) forever)!
      sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ? AND token_hash != ?', r.grant_id, params.refreshHash);
      const nextCounter = Number(r.rotation_counter ?? 0) + 1;
      sql.exec(
        "UPDATE oauth_tokens SET kind = 'refresh_used', used_at = ?, expires_at = ? WHERE token_hash = ?",
        params.now,
        Math.max(r.expires_at, params.refreshExpiresAt),
        params.refreshHash,
      );
      sql.exec(
        `INSERT OR REPLACE INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, user_id, user_role, used_at, rotation_counter, created_at, expires_at)
         VALUES (?, ?, 'access', ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)`,
        params.nextAccessHash,
        r.grant_id,
        r.client_id,
        r.client_name,
        r.scopes_json,
        r.resource,
        userId,
        userRole,
        nextCounter,
        r.created_at,
        params.accessExpiresAt,
      );
      sql.exec(
        `INSERT OR REPLACE INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, user_id, user_role, used_at, rotation_counter, created_at, expires_at)
         VALUES (?, ?, 'refresh', ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)`,
        params.nextRefreshHash,
        r.grant_id,
        r.client_id,
        r.client_name,
        r.scopes_json,
        r.resource,
        userId,
        userRole,
        nextCounter,
        r.created_at,
        params.refreshExpiresAt,
      );
      return {
        ok: true,
        grantId: r.grant_id,
        clientId: r.client_id,
        clientName: r.client_name,
        scopes: JSON.parse(r.scopes_json) as string[],
        resource: r.resource,
        userId,
        userRole,
        rotationCounter: nextCounter,
      };
    },
    listGrants(now, userId) {
      ensureMultiUserColumns();
      sql.exec('DELETE FROM oauth_tokens WHERE expires_at <= ?', now);
      const rows = userId
        ? sql
            .exec<{
              grant_id: string;
              client_id: string;
              client_name: string;
              scopes_json: string;
              user_id: string;
              user_role: string;
              created_at: number;
              max_exp: number;
            }>(
              `SELECT grant_id, client_id, client_name, scopes_json, user_id, user_role, MIN(created_at) AS created_at, MAX(expires_at) AS max_exp
               FROM oauth_tokens
               WHERE kind IN ('access', 'refresh') AND user_id = ?
               GROUP BY grant_id
               ORDER BY created_at DESC`,
              userId,
            )
            .toArray()
        : sql
            .exec<{
              grant_id: string;
              client_id: string;
              client_name: string;
              scopes_json: string;
              user_id: string;
              user_role: string;
              created_at: number;
              max_exp: number;
            }>(
              `SELECT grant_id, client_id, client_name, scopes_json, user_id, user_role, MIN(created_at) AS created_at, MAX(expires_at) AS max_exp
               FROM oauth_tokens
               WHERE kind IN ('access', 'refresh')
               GROUP BY grant_id
               ORDER BY created_at DESC`,
            )
            .toArray();
      return rows.map((r) => {
        const uid = r.user_id || 'owner';
        return {
          grantId: r.grant_id,
          clientId: r.client_id,
          clientName: r.client_name,
          scopes: JSON.parse(r.scopes_json) as string[],
          userId: uid,
          userRole: normalizeRoleForUser(uid, r.user_role),
          createdAt: r.created_at,
          expiresAt: r.max_exp,
        };
      });
    },
    revokeGrant(grantId, userId) {
      ensureMultiUserColumns();
      if (userId) {
        const existing = sql
          .exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE grant_id = ? AND user_id = ?', grantId, userId)
          .toArray()[0];
        if (!existing || existing.c <= 0) return false;
        sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ? AND user_id = ?', grantId, userId);
        sql.exec('DELETE FROM oauth_grant_rate_limits WHERE grant_id = ?', grantId);
        return true;
      }
      const existing = sql
        .exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE grant_id = ?', grantId)
        .toArray()[0];
      sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', grantId);
      sql.exec('DELETE FROM oauth_grant_rate_limits WHERE grant_id = ?', grantId);
      return Boolean(existing && existing.c > 0);
    },
    revokeByTokenHash(tokenHash) {
      const row = sql
        .exec<{ grant_id: string }>('SELECT grant_id FROM oauth_tokens WHERE token_hash = ?', tokenHash)
        .toArray()[0];
      if (row?.grant_id) {
        sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', row.grant_id);
        sql.exec('DELETE FROM oauth_grant_rate_limits WHERE grant_id = ?', row.grant_id);
      }
    },
    upsertUser(user) {
      ensureMultiUserColumns();
      if (user.reconcilePinnedOwnerId) {
        demoteUnapprovedOwnersSqlite(user.reconcilePinnedOwnerId);
      } else {
        demoteUnapprovedOwnersSqlite();
      }
      const readRawUser = (uid: string) =>
        sql
          .exec<{
            user_id: string;
            github_id: string | null;
            github_login: string;
            avatar_url: string | null;
            role: string;
            promoted_by_owner_id?: string | null;
            session_epoch?: number;
            disabled?: number;
            admitted_via?: string | null;
            admitted_org?: string | null;
            encrypted_gh_token?: string | null;
            org_verified_at?: number | null;
            created_at: number;
            last_login_at: number;
          }>('SELECT * FROM users WHERE user_id = ? LIMIT 1', uid)
          .toArray()[0] ?? null;

      const admittedViaVal = user.admittedVia ?? null;
      const admittedOrgVal = user.admittedOrg ? user.admittedOrg.toLowerCase() : null;
      const orgVerifiedAtVal =
        typeof user.orgVerifiedAt === 'number' && Number.isFinite(user.orgVerifiedAt) ? user.orgVerifiedAt : null;

      // H5: Conditional org re-verification update — NEVER INSERT, NEVER touch role/disabled/session_epoch!
      if (user.mutationKind === 'org_reverify') {
        const expectedEpoch =
          typeof user.expectedSessionEpoch === 'number' && user.expectedSessionEpoch >= 1
            ? user.expectedSessionEpoch
            : (user.sessionEpoch ?? 1);
        const expectedRole: UserRole = user.expectedRole ?? user.role;
        const before = readRawUser(user.userId);
        if (
          !before ||
          Number(before.disabled ?? 0) !== 0 ||
          normalizeRoleForUser(before.user_id, before.role) !== expectedRole ||
          (typeof before.session_epoch === 'number' && before.session_epoch >= 1 ? before.session_epoch : 1) !==
            expectedEpoch
        ) {
          const cur = this.getUser!(user.userId) as HubUserRecord | null;
          return {
            ...(cur ?? { ...user, sessionEpoch: expectedEpoch, disabled: Boolean(before?.disabled) }),
            mutationAborted: true,
          };
        }
        sql.exec(
          `UPDATE users
              SET admitted_via = 'org',
                  admitted_org = ?,
                  org_verified_at = ?,
                  encrypted_gh_token = COALESCE(?, encrypted_gh_token)
            WHERE user_id = ?
              AND COALESCE(disabled, 0) = 0
              AND COALESCE(session_epoch, 1) = ?
              AND role = ?`,
          admittedOrgVal,
          orgVerifiedAtVal,
          user.encryptedGhToken ?? null,
          user.userId,
          expectedEpoch,
          expectedRole,
        );
        const stored = this.getUser!(user.userId) as HubUserRecord | null;
        if (
          !stored ||
          stored.disabled ||
          stored.role !== expectedRole ||
          (stored.sessionEpoch ?? 1) !== expectedEpoch
        ) {
          return {
            ...(stored ?? { ...user, sessionEpoch: expectedEpoch, disabled: true }),
            mutationAborted: true,
          };
        }
        return stored;
      }

      // H5: Conditional org revocation — NEVER INSERT a deleted user and NEVER overwrite disabled=1 or role!
      if (user.mutationKind === 'org_revoke') {
        const expectedEpoch =
          typeof user.expectedSessionEpoch === 'number' && user.expectedSessionEpoch >= 1
            ? user.expectedSessionEpoch
            : Math.max(1, (user.sessionEpoch ?? 2) - 1);
        const before = readRawUser(user.userId);
        if (
          !before ||
          Number(before.disabled ?? 0) !== 0 ||
          (typeof before.session_epoch === 'number' && before.session_epoch >= 1 ? before.session_epoch : 1) !==
            expectedEpoch
        ) {
          const cur = this.getUser!(user.userId) as HubUserRecord | null;
          return {
            ...(cur ?? { ...user, sessionEpoch: expectedEpoch, disabled: Boolean(before?.disabled) }),
            mutationAborted: true,
          };
        }
        sql.exec(
          `UPDATE users
              SET session_epoch = COALESCE(session_epoch, 1) + 1,
                  admitted_via = NULL,
                  admitted_org = NULL,
                  encrypted_gh_token = NULL,
                  org_verified_at = NULL
            WHERE user_id = ?
              AND COALESCE(disabled, 0) = 0
              AND COALESCE(session_epoch, 1) = ?`,
          user.userId,
          expectedEpoch,
        );
        const stored = this.getUser!(user.userId) as HubUserRecord | null;
        return stored ?? { ...user, mutationAborted: true };
      }

      // H6: Atomic founder recovery — evict/rename any squatter row with founder's login/github_id, then force-heal founder!
      if (user.mutationKind === 'founder_heal') {
        const pinnedId = (user.githubId ?? user.reconcilePinnedOwnerId ?? '').trim();
        const founderLogin = (user.githubLogin ?? user.userId).trim();
        const squatters = sql
          .exec<{ user_id: string }>(
            `SELECT user_id FROM users
              WHERE user_id != ?
                AND (LOWER(github_login) = LOWER(?) OR (? != '' AND COALESCE(github_id, '') = ?))`,
            user.userId,
            founderLogin,
            pinnedId,
            pinnedId,
          )
          .toArray();
        for (const sq of squatters) {
          sql.exec('DELETE FROM oauth_tokens WHERE user_id = ?', sq.user_id);
          sql.exec('DELETE FROM oauth_codes WHERE user_id = ?', sq.user_id);
          sql.exec(
            `UPDATE users
                SET disabled = 1,
                    role = 'member',
                    promoted_by_owner_id = NULL,
                    session_epoch = COALESCE(session_epoch, 1) + 1,
                    github_login = '__evicted_' || user_id,
                    github_id = CASE WHEN ? != '' AND COALESCE(github_id, '') = ? THEN NULL ELSE github_id END,
                    admitted_via = NULL,
                    admitted_org = NULL,
                    encrypted_gh_token = NULL,
                    org_verified_at = NULL
              WHERE user_id = ?`,
            pinnedId,
            pinnedId,
            sq.user_id,
          );
        }
        if (pinnedId) {
          demoteUnapprovedOwnersSqlite(pinnedId);
        }
        const beforeFounder = readRawUser(user.userId);
        const nextFounderEpoch = beforeFounder
          ? Number(beforeFounder.disabled ?? 0) !== 0
            ? (beforeFounder.session_epoch ?? 1) + 1
            : (beforeFounder.session_epoch ?? 1)
          : 1;
        sql.exec(
          `INSERT INTO users (
             user_id, github_id, github_login, avatar_url, role, promoted_by_owner_id, session_epoch, disabled,
             admitted_via, admitted_org, encrypted_gh_token, org_verified_at, created_at, last_login_at
           )
           VALUES (?, ?, ?, ?, 'owner', ?, ?, 0, 'owner', NULL, ?, ?, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET
             github_id = excluded.github_id,
             github_login = excluded.github_login,
             avatar_url = excluded.avatar_url,
             role = 'owner',
             promoted_by_owner_id = excluded.promoted_by_owner_id,
             session_epoch = excluded.session_epoch,
             disabled = 0,
             admitted_via = 'owner',
             admitted_org = NULL,
             encrypted_gh_token = excluded.encrypted_gh_token,
             org_verified_at = excluded.org_verified_at,
             last_login_at = excluded.last_login_at`,
          user.userId,
          pinnedId || null,
          founderLogin,
          user.avatarUrl ?? null,
          pinnedId || 'owner',
          nextFounderEpoch,
          user.encryptedGhToken ?? null,
          orgVerifiedAtVal,
          beforeFounder?.created_at ?? user.createdAt,
          user.lastLoginAt,
        );
        sql.exec("UPDATE oauth_tokens SET user_role = 'owner' WHERE user_id = ?", user.userId);
        sql.exec("UPDATE oauth_codes SET user_role = 'owner' WHERE user_id = ?", user.userId);
        return (this.getUser!(user.userId) as HubUserRecord | null) ?? {
          ...user,
          role: 'owner',
          promotedByOwnerId: pinnedId || 'owner',
          disabled: false,
          sessionEpoch: nextFounderEpoch,
        };
      }

      // H5: OAuth callback sign-in for an EXISTING user — NEVER INSERT (cannot resurrect concurrent DELETE),
      // reject disabled=1, and preserve live role + promoted_by_owner_id + session_epoch atomically!
      if (user.mutationKind === 'oauth_login_existing') {
        const live = readRawUser(user.userId);
        if (!live || Number(live.disabled ?? 0) !== 0) {
          const cur = this.getUser!(user.userId) as HubUserRecord | null;
          return {
            ...(cur ?? { ...user, disabled: true }),
            mutationAborted: true,
          };
        }
        sql.exec(
          `UPDATE users
              SET github_id = COALESCE(?, github_id),
                  github_login = ?,
                  avatar_url = ?,
                  admitted_via = ?,
                  admitted_org = ?,
                  encrypted_gh_token = ?,
                  org_verified_at = ?,
                  last_login_at = ?
            WHERE user_id = ?
              AND COALESCE(disabled, 0) = 0`,
          user.githubId ?? null,
          user.githubLogin ?? user.userId,
          user.avatarUrl ?? null,
          admittedViaVal,
          admittedOrgVal,
          user.encryptedGhToken ?? null,
          orgVerifiedAtVal,
          user.lastLoginAt,
          user.userId,
        );
        const stored = this.getUser!(user.userId) as HubUserRecord | null;
        if (!stored || stored.disabled) {
          return { ...(stored ?? { ...user, disabled: true }), mutationAborted: true };
        }
        return stored;
      }

      // H5: OAuth callback sign-in for a NEW user — if a row appeared concurrently and is disabled, abort;
      // if active, preserve live role & session_epoch atomically!
      if (user.mutationKind === 'oauth_login_new') {
        const live = readRawUser(user.userId);
        if (live && Number(live.disabled ?? 0) !== 0) {
          const cur = this.getUser!(user.userId) as HubUserRecord | null;
          return { ...(cur ?? { ...user, disabled: true }), mutationAborted: true };
        }
        sql.exec(
          `INSERT INTO users (
             user_id, github_id, github_login, avatar_url, role, promoted_by_owner_id, session_epoch, disabled,
             admitted_via, admitted_org, encrypted_gh_token, org_verified_at, created_at, last_login_at
           )
           VALUES (?, ?, ?, ?, 'member', NULL, 1, 0, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET
             github_id = COALESCE(excluded.github_id, users.github_id),
             github_login = CASE WHEN COALESCE(users.disabled, 0) = 0 THEN excluded.github_login ELSE users.github_login END,
             avatar_url = CASE WHEN COALESCE(users.disabled, 0) = 0 THEN excluded.avatar_url ELSE users.avatar_url END,
             admitted_via = CASE WHEN COALESCE(users.disabled, 0) = 0 THEN excluded.admitted_via ELSE users.admitted_via END,
             admitted_org = CASE WHEN COALESCE(users.disabled, 0) = 0 THEN excluded.admitted_org ELSE users.admitted_org END,
             encrypted_gh_token = CASE WHEN COALESCE(users.disabled, 0) = 0 THEN excluded.encrypted_gh_token ELSE users.encrypted_gh_token END,
             org_verified_at = CASE WHEN COALESCE(users.disabled, 0) = 0 THEN excluded.org_verified_at ELSE users.org_verified_at END,
             last_login_at = CASE WHEN COALESCE(users.disabled, 0) = 0 THEN excluded.last_login_at ELSE users.last_login_at END`,
          user.userId,
          user.githubId ?? null,
          user.githubLogin ?? user.userId,
          user.avatarUrl ?? null,
          admittedViaVal,
          admittedOrgVal,
          user.encryptedGhToken ?? null,
          orgVerifiedAtVal,
          user.createdAt,
          user.lastLoginAt,
        );
        const stored = this.getUser!(user.userId) as HubUserRecord | null;
        if (!stored || stored.disabled) {
          return { ...(stored ?? { ...user, disabled: true }), mutationAborted: true };
        }
        return stored;
      }

      if (user.mutationKind === 'admin_disable') {
        const resolvedPin = resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
        const founderUserId =
          user.configuredFounderUserId !== undefined
            ? (user.configuredFounderUserId ?? '')
            : resolvedPin
              ? `gh_${resolvedPin}`
              : '';
        if (user.userId === 'owner' || (founderUserId !== '' && user.userId === founderUserId)) {
          const cur = (this.getUser!(user.userId) as HubUserRecord | null) ?? user;
          return { ...cur, mutationAborted: true, disableFailedReason: 'founder_protected' };
        }
        const live = readRawUser(user.userId);
        if (!live) {
          return { ...user, disabled: true, mutationAborted: true, disableFailedReason: 'not_found' };
        }
        const callerIsFounder = user.callerIsImmutableFounder === true;
        if (!callerIsFounder && normalizeRoleForUser(live.user_id, live.role) === 'owner') {
          const cur = (this.getUser!(user.userId) as HubUserRecord | null) ?? { ...user, role: 'owner', disabled: false };
          return { ...cur, mutationAborted: true, disableFailedReason: 'owner_protected' };
        }
        if (Number(live.disabled ?? 0) !== 0) {
          if (user.allowAlreadyDisabled) {
            sql.exec(
              'DELETE FROM oauth_grant_rate_limits WHERE grant_id IN (SELECT DISTINCT grant_id FROM oauth_tokens WHERE user_id = ?)',
              user.userId,
            );
            sql.exec('DELETE FROM oauth_tokens WHERE user_id = ?', user.userId);
            sql.exec('DELETE FROM oauth_codes WHERE user_id = ?', user.userId);
            return (this.getUser!(user.userId) as HubUserRecord | null) ?? { ...user, role: 'member', disabled: true };
          }
          const cur = (this.getUser!(user.userId) as HubUserRecord | null) ?? { ...user, disabled: true };
          return { ...cur, mutationAborted: true, disableFailedReason: 'already_disabled' };
        }
        const updatedRows = sql
          .exec<{ user_id: string }>(
            `UPDATE users
                SET role = 'member',
                    promoted_by_owner_id = NULL,
                    disabled = 1,
                    session_epoch = COALESCE(session_epoch, 1) + 1,
                    github_login = COALESCE(?, github_login),
                    admitted_via = NULL,
                    admitted_org = NULL,
                    encrypted_gh_token = NULL,
                    org_verified_at = NULL
              WHERE user_id = ?
                AND user_id != 'owner'
                AND (? = '' OR user_id != ?)
                AND COALESCE(disabled, 0) = 0
                AND (? = 1 OR role != 'owner')
              RETURNING user_id`,
            user.githubLogin ?? null,
            user.userId,
            founderUserId,
            founderUserId,
            callerIsFounder ? 1 : 0,
          )
          .toArray();
        if (updatedRows.length === 0) {
          const after = readRawUser(user.userId);
          const cur = (this.getUser!(user.userId) as HubUserRecord | null) ?? user;
          if (after && !callerIsFounder && normalizeRoleForUser(after.user_id, after.role) === 'owner') {
            return { ...cur, mutationAborted: true, disableFailedReason: 'owner_protected' };
          }
          return {
            ...cur,
            mutationAborted: true,
            disableFailedReason: after ? 'already_disabled' : 'not_found',
          };
        }
        sql.exec(
          'DELETE FROM oauth_grant_rate_limits WHERE grant_id IN (SELECT DISTINCT grant_id FROM oauth_tokens WHERE user_id = ?)',
          user.userId,
        );
        sql.exec('DELETE FROM oauth_tokens WHERE user_id = ?', user.userId);
        sql.exec('DELETE FROM oauth_codes WHERE user_id = ?', user.userId);
        return (this.getUser!(user.userId) as HubUserRecord | null) ?? { ...user, role: 'member', disabled: true };
      }

      if (user.mutationKind === 'demote_unapproved_owner' || user.mutationKind === 'admin_role') {
        const live = readRawUser(user.userId);
        if (!live || Number(live.disabled ?? 0) !== 0) {
          const cur = this.getUser!(user.userId) as HubUserRecord | null;
          return { ...(cur ?? { ...user, disabled: true }), mutationAborted: true };
        }
        const nextRole: UserRole = user.mutationKind === 'demote_unapproved_owner' ? 'member' : user.role;
        const nextPromoted = nextRole === 'owner' ? (user.promotedByOwnerId ?? null) : null;
        sql.exec(
          `UPDATE users
              SET role = ?,
                  promoted_by_owner_id = ?,
                  session_epoch = COALESCE(session_epoch, 1) + 1
            WHERE user_id = ? AND COALESCE(disabled, 0) = 0`,
          nextRole,
          nextPromoted,
          user.userId,
        );
        sql.exec('UPDATE oauth_tokens SET user_role = ? WHERE user_id = ?', nextRole, user.userId);
        sql.exec('UPDATE oauth_codes SET user_role = ? WHERE user_id = ?', nextRole, user.userId);
        return (this.getUser!(user.userId) as HubUserRecord | null) ?? { ...user, role: nextRole };
      }

      const epoch =
        typeof user.sessionEpoch === 'number' && Number.isInteger(user.sessionEpoch) && user.sessionEpoch >= 1
          ? user.sessionEpoch
          : undefined;
      const disabledInt = user.disabled ? 1 : 0;
      // Default safety guard: never silently resurrect an already-disabled user unless `founder_heal` is used!
      if (disabledInt === 0) {
        const existingLive = readRawUser(user.userId);
        if (existingLive && Number(existingLive.disabled ?? 0) !== 0) {
          const cur = this.getUser!(user.userId) as HubUserRecord | null;
          return { ...(cur ?? { ...user, disabled: true }), mutationAborted: true };
        }
      }
      const encryptedGhTokenVal = disabledInt !== 0 ? null : (user.encryptedGhToken ?? null);
      const promotedByVal = disabledInt !== 0 || user.role !== 'owner' ? null : (user.promotedByOwnerId ?? null);
      if (epoch !== undefined) {
        sql.exec(
          `INSERT INTO users (
             user_id, github_id, github_login, avatar_url, role, promoted_by_owner_id, session_epoch, disabled,
             admitted_via, admitted_org, encrypted_gh_token, org_verified_at, created_at, last_login_at
           )
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET
             github_id = COALESCE(excluded.github_id, users.github_id),
             github_login = excluded.github_login,
             avatar_url = excluded.avatar_url,
             role = excluded.role,
             promoted_by_owner_id = COALESCE(excluded.promoted_by_owner_id, CASE WHEN excluded.role = 'owner' THEN users.promoted_by_owner_id ELSE NULL END),
             session_epoch = excluded.session_epoch,
             disabled = excluded.disabled,
             admitted_via = excluded.admitted_via,
             admitted_org = excluded.admitted_org,
             encrypted_gh_token = excluded.encrypted_gh_token,
             org_verified_at = excluded.org_verified_at,
             last_login_at = excluded.last_login_at`,
          user.userId,
          user.githubId ?? null,
          user.githubLogin ?? user.userId,
          user.avatarUrl ?? null,
          user.role,
          promotedByVal,
          epoch,
          disabledInt,
          admittedViaVal,
          admittedOrgVal,
          encryptedGhTokenVal,
          orgVerifiedAtVal,
          user.createdAt,
          user.lastLoginAt,
        );
      } else {
        sql.exec(
          `INSERT INTO users (
             user_id, github_id, github_login, avatar_url, role, promoted_by_owner_id, session_epoch, disabled,
             admitted_via, admitted_org, encrypted_gh_token, org_verified_at, created_at, last_login_at
           )
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET
             github_id = COALESCE(excluded.github_id, users.github_id),
             github_login = excluded.github_login,
             avatar_url = excluded.avatar_url,
             role = excluded.role,
             promoted_by_owner_id = COALESCE(excluded.promoted_by_owner_id, CASE WHEN excluded.role = 'owner' THEN users.promoted_by_owner_id ELSE NULL END),
             disabled = excluded.disabled,
             admitted_via = excluded.admitted_via,
             admitted_org = excluded.admitted_org,
             encrypted_gh_token = excluded.encrypted_gh_token,
             org_verified_at = excluded.org_verified_at,
             last_login_at = excluded.last_login_at`,
          user.userId,
          user.githubId ?? null,
          user.githubLogin ?? user.userId,
          user.avatarUrl ?? null,
          user.role,
          promotedByVal,
          disabledInt,
          admittedViaVal,
          admittedOrgVal,
          encryptedGhTokenVal,
          orgVerifiedAtVal,
          user.createdAt,
          user.lastLoginAt,
        );
      }
      if (disabledInt !== 0) {
        sql.exec('DELETE FROM oauth_tokens WHERE user_id = ?', user.userId);
        sql.exec('DELETE FROM oauth_codes WHERE user_id = ?', user.userId);
      }
      const stored = this.getUser!(user.userId) as HubUserRecord | null;
      return stored ?? { ...user, sessionEpoch: epoch ?? 1, disabled: Boolean(user.disabled) };
    },
    getUser(userId) {
      ensureMultiUserColumns();
      demoteUnapprovedOwnersSqlite();
      const r = sql
        .exec<{
          user_id: string;
          github_id: string | null;
          github_login: string;
          avatar_url: string | null;
          role: string;
          promoted_by_owner_id?: string | null;
          session_epoch?: number;
          disabled?: number;
          admitted_via?: string | null;
          admitted_org?: string | null;
          encrypted_gh_token?: string | null;
          org_verified_at?: number | null;
          created_at: number;
          last_login_at: number;
        }>('SELECT * FROM users WHERE user_id = ? LIMIT 1', userId)
        .toArray()[0];
      if (!r) return null;
      const tokStats = sql
        .exec<{ total_rows: number; active_rows: number; used_rows: number; grant_count: number }>(
          `SELECT COUNT(*) AS total_rows,
                  COALESCE(SUM(CASE WHEN kind IN ('access', 'refresh') AND used_at IS NULL THEN 1 ELSE 0 END), 0) AS active_rows,
                  COALESCE(SUM(CASE WHEN kind = 'refresh_used' OR used_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS used_rows,
                  COUNT(DISTINCT grant_id) AS grant_count
             FROM oauth_tokens
            WHERE user_id = ?`,
          r.user_id,
        )
        .toArray()[0];
      const totalRows = Number(tokStats?.total_rows ?? 0);
      const activeRows = Number(tokStats?.active_rows ?? 0);
      const usedRows = Number(tokStats?.used_rows ?? 0);
      const grantCount = Number(tokStats?.grant_count ?? 0);
      const validVia =
        r.admitted_via === 'owner' ||
        r.admitted_via === 'allowlist_id' ||
        r.admitted_via === 'allowlist_login' ||
        r.admitted_via === 'org' ||
        r.admitted_via === 'open'
          ? r.admitted_via
          : undefined;
      return {
        userId: r.user_id,
        ...(r.github_id ? { githubId: r.github_id } : {}),
        githubLogin: r.github_login,
        ...(r.avatar_url ? { avatarUrl: r.avatar_url } : {}),
        role: normalizeRoleForUser(r.user_id, r.role),
        ...(r.promoted_by_owner_id ? { promotedByOwnerId: r.promoted_by_owner_id } : {}),
        sessionEpoch: typeof r.session_epoch === 'number' && r.session_epoch >= 1 ? r.session_epoch : 1,
        disabled: Number(r.disabled ?? 0) !== 0,
        ...(validVia ? { admittedVia: validVia } : {}),
        ...(r.admitted_org ? { admittedOrg: r.admitted_org } : {}),
        ...(r.encrypted_gh_token ? { encryptedGhToken: r.encrypted_gh_token } : {}),
        ...(typeof r.org_verified_at === 'number' ? { orgVerifiedAt: r.org_verified_at } : {}),
        createdAt: r.created_at,
        lastLoginAt: r.last_login_at,
        tokenCount: totalRows,
        storedTokenCount: totalRows,
        activeTokenCount: activeRows,
        usedTokenCount: usedRows,
        grantCount,
      };
    },
    listUsers() {
      ensureMultiUserColumns();
      demoteUnapprovedOwnersSqlite();
      const countsByUser = new Map<
        string,
        { totalRows: number; activeRows: number; usedRows: number; grantCount: number }
      >();
      const tokRows = sql
        .exec<{ user_id: string; total_rows: number; active_rows: number; used_rows: number; grant_count: number }>(
          `SELECT user_id,
                  COUNT(*) AS total_rows,
                  COALESCE(SUM(CASE WHEN kind IN ('access', 'refresh') AND used_at IS NULL THEN 1 ELSE 0 END), 0) AS active_rows,
                  COALESCE(SUM(CASE WHEN kind = 'refresh_used' OR used_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS used_rows,
                  COUNT(DISTINCT grant_id) AS grant_count
             FROM oauth_tokens
            GROUP BY user_id`,
        )
        .toArray();
      for (const tr of tokRows) {
        countsByUser.set(tr.user_id || 'owner', {
          totalRows: Number(tr.total_rows ?? 0),
          activeRows: Number(tr.active_rows ?? 0),
          usedRows: Number(tr.used_rows ?? 0),
          grantCount: Number(tr.grant_count ?? 0),
        });
      }
      return sql
        .exec<{
          user_id: string;
          github_id: string | null;
          github_login: string;
          avatar_url: string | null;
          role: string;
          promoted_by_owner_id?: string | null;
          session_epoch?: number;
          disabled?: number;
          admitted_via?: string | null;
          admitted_org?: string | null;
          org_verified_at?: number | null;
          created_at: number;
          last_login_at: number;
        }>(
          `SELECT user_id, github_id, github_login, avatar_url, role, promoted_by_owner_id, session_epoch, disabled,
                  admitted_via, admitted_org, org_verified_at, created_at, last_login_at
           FROM users WHERE COALESCE(disabled, 0) = 0 ORDER BY last_login_at DESC LIMIT 500`,
        )
        .toArray()
        .map((r) => {
          const validVia =
            r.admitted_via === 'owner' ||
            r.admitted_via === 'allowlist_id' ||
            r.admitted_via === 'allowlist_login' ||
            r.admitted_via === 'org' ||
            r.admitted_via === 'open'
              ? r.admitted_via
              : undefined;
          const stats = countsByUser.get(r.user_id) ?? { totalRows: 0, activeRows: 0, usedRows: 0, grantCount: 0 };
          return {
            userId: r.user_id,
            ...(r.github_id ? { githubId: r.github_id } : {}),
            githubLogin: r.github_login,
            ...(r.avatar_url ? { avatarUrl: r.avatar_url } : {}),
            role: normalizeRoleForUser(r.user_id, r.role),
            ...(r.promoted_by_owner_id ? { promotedByOwnerId: r.promoted_by_owner_id } : {}),
            sessionEpoch: typeof r.session_epoch === 'number' && r.session_epoch >= 1 ? r.session_epoch : 1,
            disabled: false,
            ...(validVia ? { admittedVia: validVia } : {}),
            ...(r.admitted_org ? { admittedOrg: r.admitted_org } : {}),
            ...(typeof r.org_verified_at === 'number' ? { orgVerifiedAt: r.org_verified_at } : {}),
            createdAt: r.created_at,
            lastLoginAt: r.last_login_at,
            tokenCount: stats.totalRows,
            storedTokenCount: stats.totalRows,
            activeTokenCount: stats.activeRows,
            usedTokenCount: stats.usedRows,
            grantCount: stats.grantCount,
          };
        });
    },
    countUsers() {
      ensureMultiUserColumns();
      const row = sql
        .exec<{ c: number }>("SELECT COUNT(*) AS c FROM users WHERE user_id != 'owner'")
        .toArray()[0];
      return row?.c ?? 0;
    },
    updateUserRole(userId, role, promotedByOwnerId) {
      ensureMultiUserColumns();
      if (userId === 'owner' && role !== 'owner') return false;
      const existing = sql
        .exec<{ c: number }>('SELECT COUNT(*) AS c FROM users WHERE user_id = ? AND COALESCE(disabled, 0) = 0', userId)
        .toArray()[0];
      if (!existing || existing.c <= 0) return false;
      const nextPromoted = role === 'owner' ? (promotedByOwnerId ?? null) : null;
      sql.exec(
        'UPDATE users SET role = ?, promoted_by_owner_id = ?, session_epoch = COALESCE(session_epoch, 1) + 1 WHERE user_id = ?',
        role,
        nextPromoted,
        userId,
      );
      sql.exec('UPDATE oauth_tokens SET user_role = ? WHERE user_id = ?', role, userId);
      sql.exec('UPDATE oauth_codes SET user_role = ? WHERE user_id = ?', role, userId);
      return true;
    },
    enforcePinnedFounderOwners(pinnedOwnerId) {
      return demoteUnapprovedOwnersSqlite(pinnedOwnerId);
    },
    checkAuthLockout(bucket, now, maxFailures = RATE_LIMIT_MAX_FAILURES) {
      if (bucket.startsWith('revoked_admin:')) {
        const revRow = sql
          .exec<{ expires_at: number }>('SELECT expires_at FROM admin_revocations WHERE key = ?', bucket)
          .toArray()[0];
        if (!revRow || revRow.expires_at <= now) {
          if (revRow) sql.exec('DELETE FROM admin_revocations WHERE key = ?', bucket);
          return { allowed: true, retryAfterSec: 0 };
        }
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((revRow.expires_at - now) / 1_000)) };
      }
      const row = sql
        .exec<{ count: number; reset_at: number }>('SELECT count, reset_at FROM auth_failures WHERE bucket = ?', bucket)
        .toArray()[0];
      if (!row || row.reset_at <= now) {
        if (row) sql.exec('DELETE FROM auth_failures WHERE bucket = ?', bucket);
        return { allowed: true, retryAfterSec: 0 };
      }
      if (row.count >= maxFailures) {
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((row.reset_at - now) / 1_000)) };
      }
      return { allowed: true, retryAfterSec: 0 };
    },
    recordAuthFailure(bucket, now, windowMs, maxFailures) {
      if (bucket.startsWith('revoked_admin:')) {
        // Dedicated `admin_revocations` table pruned ONLY by `expires_at <= now` (bounded to 4096 entries) so brute-force
        // `auth_failures` buckets can NEVER evict a logged-out admin session revocation (`Low`)!
        sql.exec('DELETE FROM admin_revocations WHERE expires_at <= ?', now);
        sql.exec(
          `DELETE FROM admin_revocations
           WHERE key IN (
             SELECT key FROM admin_revocations ORDER BY expires_at DESC LIMIT -1 OFFSET 4095
           )`,
        );
        const expiresAt = now + windowMs;
        sql.exec('INSERT OR REPLACE INTO admin_revocations (key, expires_at) VALUES (?, ?)', bucket, expiresAt);
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil(windowMs / 1_000)) };
      }
      sql.exec('DELETE FROM auth_failures WHERE reset_at <= ?', now);
      const row = sql
        .exec<{ count: number; reset_at: number }>('SELECT count, reset_at FROM auth_failures WHERE bucket = ?', bucket)
        .toArray()[0];
      if (!row) {
        // Evict non-locked single-attempt buckets first so IPv6 sprays cannot displace active lockouts (H-S5).
        sql.exec(
          `DELETE FROM auth_failures
           WHERE bucket IN (
             SELECT bucket FROM auth_failures
             ORDER BY (count >= ?) DESC, reset_at DESC
             LIMIT -1 OFFSET ?
           )`,
          maxFailures,
          MAX_AUTH_FAILURE_BUCKETS - 1,
        );
        sql.exec('INSERT OR REPLACE INTO auth_failures (bucket, count, reset_at) VALUES (?, 1, ?)', bucket, now + windowMs);
        return { allowed: true, retryAfterSec: 0 };
      }
      const nextCount = row.count + 1;
      sql.exec('UPDATE auth_failures SET count = ? WHERE bucket = ?', nextCount, bucket);
      if (nextCount > maxFailures) {
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((row.reset_at - now) / 1_000)) };
      }
      return { allowed: true, retryAfterSec: 0 };
    },
    clearAuthFailures(bucket) {
      if (bucket.startsWith('revoked_admin:')) {
        sql.exec('DELETE FROM admin_revocations WHERE key = ?', bucket);
        return;
      }
      sql.exec('DELETE FROM auth_failures WHERE bucket = ?', bucket);
    },
  };
}

export function createMemoryOAuthStore(): OAuthStore {
  const clients = new Map<string, OAuthClientRecord>();
  const codes = new Map<string, OAuthCodeRecord>();
  const tokens = new Map<string, OAuthTokenRecord & { used?: boolean; usedAt?: number; rotationCounter?: number }>();
  const grantRefreshRateLimits = new Map<string, { count: number; resetAt: number }>();
  const users = new Map<string, HubUserRecord>();
  const failures = new Map<string, { count: number; resetAt: number }>();
  const adminRevocations = new Map<string, number>();

  const computeMemoryUserTokenStats = (targetUserId: string) => {
    let totalRows = 0;
    let activeRows = 0;
    let usedRows = 0;
    const grants = new Set<string>();
    for (const t of tokens.values()) {
      if ((t.userId ?? 'owner') !== targetUserId) continue;
      totalRows++;
      if (t.used) usedRows++;
      else activeRows++;
      grants.add(t.grantId);
    }
    return {
      tokenCount: totalRows,
      storedTokenCount: totalRows,
      activeTokenCount: activeRows,
      usedTokenCount: usedRows,
      grantCount: grants.size,
    };
  };

  return {
    putClient(c) {
      if (clients.size >= 500) {
        for (const id of clients.keys()) {
          const hasGrant = [...tokens.values()].some((t) => t.clientId === id && t.expiresAt > c.createdAt);
          const hasCode = [...codes.values()].some((cd) => cd.clientId === id && cd.expiresAt > c.createdAt);
          if (!hasGrant && !hasCode) {
            clients.delete(id);
            break;
          }
        }
      }
      clients.set(c.clientId, { ...c, redirectUris: [...c.redirectUris] });
    },
    getClient(clientId) {
      const c = clients.get(clientId);
      return c ? { ...c, redirectUris: [...c.redirectUris] } : null;
    },
    putCode(code) {
      const approxNow = code.expiresAt - AUTH_CODE_TTL_MS;
      for (const [k, v] of codes.entries()) {
        if (v.expiresAt <= approxNow) codes.delete(k);
      }
      const userId = code.userId ?? 'owner';
      const userCodeKeys: string[] = [];
      for (const [k, v] of codes.entries()) {
        if ((v.userId ?? 'owner') === userId) userCodeKeys.push(k);
      }
      while (userCodeKeys.length >= MAX_OAUTH_CODES_PER_USER) {
        const oldest = userCodeKeys.shift();
        if (oldest !== undefined) codes.delete(oldest);
      }
      if (codes.size >= MAX_OAUTH_CODES_GLOBAL) {
        if (userId !== 'owner') {
          throw new OAuthQuotaExceededError('Global OAuth authorization code capacity reached; retry shortly');
        }
        for (const [k, v] of codes.entries()) {
          if ((v.userId ?? 'owner') === 'owner') {
            codes.delete(k);
            break;
          }
        }
      }
      codes.set(code.codeHash, {
        ...code,
        userId,
        userRole: normalizeRoleForUser(userId, code.userRole),
        scopes: [...code.scopes],
      });
    },
    consumeCode(codeHash, now) {
      const c = codes.get(codeHash);
      codes.delete(codeHash);
      if (!c || c.expiresAt <= now) return null;
      return c;
    },
    putTokenPair(p) {
      for (const [k, v] of tokens.entries()) {
        if (v.expiresAt <= p.createdAt) tokens.delete(k);
      }
      for (const [gid, rl] of grantRefreshRateLimits.entries()) {
        if (rl.resetAt <= p.createdAt) grantRefreshRateLimits.delete(gid);
      }
      const userId = p.userId ?? 'owner';
      const userRole = normalizeRoleForUser(userId, p.userRole);
      const pinnedFounderId = resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
      const isFounderUser = userId === 'owner' || (pinnedFounderId !== null && userId === `gh_${pinnedFounderId}`);
      const userGrantsInOrder: string[] = [];
      const seenUserGrants = new Set<string>();
      for (const [, v] of tokens.entries()) {
        if ((v.userId ?? 'owner') !== userId) continue;
        if (!seenUserGrants.has(v.grantId)) {
          seenUserGrants.add(v.grantId);
          userGrantsInOrder.push(v.grantId);
        }
      }
      while (userGrantsInOrder.length >= MAX_OAUTH_GRANTS_PER_USER) {
        const oldestGrant = userGrantsInOrder.shift();
        if (oldestGrant === undefined) break;
        for (const [k, v] of tokens.entries()) {
          if ((v.userId ?? 'owner') === userId && v.grantId === oldestGrant) {
            tokens.delete(k);
          }
        }
      }
      const userTokenHashes: string[] = [];
      const userUsedHashes: string[] = [];
      for (const [k, v] of tokens.entries()) {
        if ((v.userId ?? 'owner') !== userId) continue;
        userTokenHashes.push(k);
        if (v.used) userUsedHashes.push(k);
      }
      while (userTokenHashes.length + 2 > MAX_OAUTH_TOKENS_PER_USER && userUsedHashes.length > 0) {
        const oldestUsed = userUsedHashes.shift();
        if (oldestUsed !== undefined) {
          tokens.delete(oldestUsed);
          const idx = userTokenHashes.indexOf(oldestUsed);
          if (idx >= 0) userTokenHashes.splice(idx, 1);
        }
      }
      while (userTokenHashes.length + 2 > MAX_OAUTH_TOKENS_PER_USER) {
        const oldest = userTokenHashes.shift();
        if (oldest !== undefined) tokens.delete(oldest);
      }
      const effectiveGlobalCap = isFounderUser ? MAX_OAUTH_TOKENS_GLOBAL : MAX_OAUTH_TOKENS_NON_OWNER_GLOBAL;
      if (tokens.size + 2 > effectiveGlobalCap) {
        for (const [k, v] of tokens.entries()) {
          if (tokens.size + 2 <= effectiveGlobalCap) break;
          if ((v.userId ?? 'owner') !== 'owner' && v.used) tokens.delete(k);
        }
      }
      if (tokens.size + 2 > effectiveGlobalCap) {
        if (!isFounderUser) {
          throw new OAuthQuotaExceededError();
        }
        let ownerOldestGrant: string | undefined;
        for (const v of tokens.values()) {
          if ((v.userId ?? 'owner') === userId) {
            ownerOldestGrant = v.grantId;
            break;
          }
        }
        if (ownerOldestGrant) {
          for (const [k, v] of tokens.entries()) {
            if ((v.userId ?? 'owner') === userId && v.grantId === ownerOldestGrant) {
              tokens.delete(k);
            }
          }
        }
      }
      for (const [k, v] of tokens.entries()) {
        if (v.grantId === p.grantId) tokens.delete(k);
      }
      tokens.set(p.accessHash, {
        grantId: p.grantId,
        kind: 'access',
        clientId: p.clientId,
        clientName: p.clientName,
        scopes: [...p.scopes],
        resource: p.resource,
        userId,
        userRole,
        rotationCounter: 0,
        createdAt: p.createdAt,
        expiresAt: p.accessExpiresAt,
      });
      tokens.set(p.refreshHash, {
        grantId: p.grantId,
        kind: 'refresh',
        clientId: p.clientId,
        clientName: p.clientName,
        scopes: [...p.scopes],
        resource: p.resource,
        userId,
        userRole,
        rotationCounter: 0,
        createdAt: p.createdAt,
        expiresAt: p.refreshExpiresAt,
      });
    },
    getAccessToken(tokenHash, now) {
      const t = tokens.get(tokenHash);
      if (!t || t.kind !== 'access') return null;
      if (t.expiresAt <= now) {
        tokens.delete(tokenHash);
        return null;
      }
      return { ...t, scopes: [...t.scopes] };
    },
    consumeRefreshToken(tokenHash, now) {
      const t = tokens.get(tokenHash);
      if (!t || t.kind !== 'refresh' || t.used) return null;
      tokens.delete(tokenHash);
      if (t.expiresAt <= now) return null;
      return { ...t, scopes: [...t.scopes] };
    },
    rotateRefreshToken(params) {
      const t = tokens.get(params.refreshHash);
      if (!t || t.kind !== 'refresh') {
        if (
          params.claimedGrantId &&
          typeof params.claimedGeneration === 'number' &&
          params.claimedGeneration >= 0 &&
          params.clientId
        ) {
          for (const row of tokens.values()) {
            if (
              row.grantId === params.claimedGrantId &&
              row.kind === 'refresh' &&
              !row.used &&
              row.expiresAt > params.now &&
              row.clientId === params.clientId &&
              params.claimedGeneration < (row.rotationCounter ?? 0)
            ) {
              for (const [h, delRow] of tokens.entries()) {
                if (delRow.grantId === params.claimedGrantId) tokens.delete(h);
              }
              grantRefreshRateLimits.delete(params.claimedGrantId);
              return {
                ok: false,
                error: 'invalid_grant',
                replayDetected: true,
                grantId: params.claimedGrantId,
                clientId: params.clientId,
              };
            }
          }
        }
        return { ok: false, error: 'invalid_grant' };
      }
      if (t.expiresAt <= params.now) {
        for (const [h, row] of tokens.entries()) if (row.grantId === t.grantId) tokens.delete(h);
        grantRefreshRateLimits.delete(t.grantId);
        return { ok: false, error: 'invalid_grant' };
      }
      if (t.used) {
        for (const [h, row] of tokens.entries()) if (row.grantId === t.grantId) tokens.delete(h);
        grantRefreshRateLimits.delete(t.grantId);
        return { ok: false, error: 'invalid_grant', replayDetected: true, grantId: t.grantId, clientId: t.clientId };
      }
      if (!params.clientId || t.clientId !== params.clientId) {
        return { ok: false, error: 'invalid_grant' };
      }
      const userId = t.userId ?? 'owner';
      let userRole = normalizeRoleForUser(userId, t.userRole);
      if (userId !== 'owner') {
        const liveUser = users.get(userId);
        if (!liveUser || liveUser.disabled) {
          for (const [h, row] of tokens.entries()) if (row.grantId === t.grantId) tokens.delete(h);
          grantRefreshRateLimits.delete(t.grantId);
          return { ok: false, error: 'invalid_grant' };
        }
        userRole = normalizeRoleForUser(userId, liveUser.role);
      }

      for (const [gid, rl] of grantRefreshRateLimits.entries()) {
        if (rl.resetAt <= params.now) grantRefreshRateLimits.delete(gid);
      }
      const rlCur = grantRefreshRateLimits.get(t.grantId);
      if (rlCur && rlCur.resetAt > params.now && rlCur.count >= MAX_REFRESH_ROTATIONS_PER_GRANT_WINDOW) {
        return {
          ok: false,
          error: 'slow_down',
          retryAfterSec: Math.max(1, Math.ceil((rlCur.resetAt - params.now) / 1_000)),
          grantId: t.grantId,
          clientId: t.clientId,
        };
      }

      for (const [h, row] of tokens.entries()) {
        if (row.expiresAt <= params.now) tokens.delete(h);
      }
      const pinnedFounderId = resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
      const isFounderUser = userId === 'owner' || (pinnedFounderId !== null && userId === `gh_${pinnedFounderId}`);

      let otherUserRows = 0;
      const otherUserUsedHashes: string[] = [];
      const otherUserGrants = new Set<string>();
      for (const [h, row] of tokens.entries()) {
        if ((row.userId ?? 'owner') !== userId || row.grantId === t.grantId) continue;
        otherUserRows++;
        otherUserGrants.add(row.grantId);
        if (row.used) otherUserUsedHashes.push(h);
      }
      while (otherUserRows + 3 > MAX_OAUTH_TOKENS_PER_USER && otherUserUsedHashes.length > 0) {
        const victim = otherUserUsedHashes.shift();
        if (victim !== undefined && tokens.delete(victim)) otherUserRows--;
      }
      if (otherUserRows + 3 > MAX_OAUTH_TOKENS_PER_USER || otherUserGrants.size + 1 > MAX_OAUTH_GRANTS_PER_USER) {
        return {
          ok: false,
          error: 'user_quota_exceeded',
          message: 'Per-user OAuth token quota exceeded; revoke unused grants before rotating',
          grantId: t.grantId,
          clientId: t.clientId,
        };
      }

      const effectiveGlobalCap = isFounderUser ? MAX_OAUTH_TOKENS_GLOBAL : MAX_OAUTH_TOKENS_NON_OWNER_GLOBAL;
      let totalOtherRows = 0;
      for (const row of tokens.values()) {
        if (row.grantId !== t.grantId) totalOtherRows++;
      }
      if (totalOtherRows + 3 > effectiveGlobalCap) {
        for (const [h, row] of tokens.entries()) {
          if (totalOtherRows + 3 <= effectiveGlobalCap) break;
          if (row.grantId !== t.grantId && (row.userId ?? 'owner') !== 'owner' && row.used) {
            tokens.delete(h);
            totalOtherRows--;
          }
        }
        if (totalOtherRows + 3 > effectiveGlobalCap && !isFounderUser) {
          return {
            ok: false,
            error: 'user_quota_exceeded',
            message: 'Global OAuth token capacity reached; retry shortly',
            grantId: t.grantId,
            clientId: t.clientId,
          };
        }
      }

      if (!rlCur || rlCur.resetAt <= params.now) {
        grantRefreshRateLimits.set(t.grantId, { count: 1, resetAt: params.now + REFRESH_RATE_LIMIT_WINDOW_MS });
      } else {
        rlCur.count++;
      }

      // Delete ALL prior access & prior used refresh markers for this grant (`<= 3` rows O(1) per grant)
      for (const [h, row] of tokens.entries()) {
        if (row.grantId === t.grantId && h !== params.refreshHash) tokens.delete(h);
      }
      const nextCounter = (t.rotationCounter ?? 0) + 1;
      t.used = true;
      t.usedAt = params.now;
      t.expiresAt = Math.max(t.expiresAt, params.refreshExpiresAt);
      tokens.set(params.nextAccessHash, {
        grantId: t.grantId,
        kind: 'access',
        clientId: t.clientId,
        clientName: t.clientName,
        scopes: [...t.scopes],
        resource: t.resource,
        userId,
        userRole,
        rotationCounter: nextCounter,
        createdAt: t.createdAt,
        expiresAt: params.accessExpiresAt,
      });
      tokens.set(params.nextRefreshHash, {
        grantId: t.grantId,
        kind: 'refresh',
        clientId: t.clientId,
        clientName: t.clientName,
        scopes: [...t.scopes],
        resource: t.resource,
        userId,
        userRole,
        rotationCounter: nextCounter,
        createdAt: t.createdAt,
        expiresAt: params.refreshExpiresAt,
      });
      return {
        ok: true,
        grantId: t.grantId,
        clientId: t.clientId,
        clientName: t.clientName,
        scopes: [...t.scopes],
        resource: t.resource,
        userId,
        userRole,
        rotationCounter: nextCounter,
      };
    },
    listGrants(now, userId) {
      const byGrant = new Map<string, OAuthGrantSummary>();
      for (const [hash, t] of tokens.entries()) {
        if (t.expiresAt <= now) {
          tokens.delete(hash);
          continue;
        }
        if (t.used) continue;
        const rowUserId = t.userId ?? 'owner';
        if (userId && rowUserId !== userId) continue;
        const prev = byGrant.get(t.grantId);
        if (!prev || t.expiresAt > prev.expiresAt) {
          byGrant.set(t.grantId, {
            grantId: t.grantId,
            clientId: t.clientId,
            clientName: t.clientName,
            scopes: [...t.scopes],
            userId: rowUserId,
            userRole: normalizeRoleForUser(rowUserId, t.userRole),
            createdAt: t.createdAt,
            expiresAt: t.expiresAt,
          });
        }
      }
      return [...byGrant.values()].sort((a, b) => b.createdAt - a.createdAt);
    },
    revokeGrant(grantId, userId) {
      let removed = false;
      for (const [hash, t] of tokens.entries()) {
        if (t.grantId === grantId && (!userId || (t.userId ?? 'owner') === userId)) {
          tokens.delete(hash);
          removed = true;
        }
      }
      if (removed) grantRefreshRateLimits.delete(grantId);
      return removed;
    },
    revokeByTokenHash(tokenHash) {
      const t = tokens.get(tokenHash);
      if (!t) return;
      for (const [hash, row] of tokens.entries()) {
        if (row.grantId === t.grantId) tokens.delete(hash);
      }
      grantRefreshRateLimits.delete(t.grantId);
    },
    upsertUser(user) {
      const demoteMemoryUnapprovedOwners = (explicitPinned?: string | null): number => {
        const pinnedOwnerId =
          (explicitPinned && /^[1-9][0-9]{0,19}$/.test(explicitPinned.trim()) ? explicitPinned.trim() : null) ??
          resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
        if (!pinnedOwnerId) return 0;
        let count = 0;
        for (const u of users.values()) {
          if (
            u.userId !== 'owner' &&
            u.role === 'owner' &&
            String(u.githubId ?? '') !== pinnedOwnerId &&
            u.promotedByOwnerId !== pinnedOwnerId &&
            u.promotedByOwnerId !== 'owner'
          ) {
            u.role = 'member';
            delete u.promotedByOwnerId;
            u.sessionEpoch = (u.sessionEpoch ?? 1) + 1;
            for (const t of tokens.values()) {
              if ((t.userId ?? 'owner') === u.userId) t.userRole = 'member';
            }
            for (const cd of codes.values()) {
              if ((cd.userId ?? 'owner') === u.userId) cd.userRole = 'member';
            }
            count++;
          }
        }
        return count;
      };
      demoteMemoryUnapprovedOwners(user.reconcilePinnedOwnerId);

      const stripMeta = (u: HubUserRecord): HubUserRecord => {
        const {
          mutationKind: _mk,
          expectedSessionEpoch: _ee,
          expectedRole: _er,
          reconcilePinnedOwnerId: _rp,
          callerIsImmutableFounder: _cif,
          configuredFounderUserId: _cfu,
          allowAlreadyDisabled: _aad,
          disableFailedReason: _dfr,
          mutationAborted: _ma,
          ...clean
        } = u;
        return clean;
      };

      const prev = users.get(user.userId);
      if (user.mutationKind === 'org_reverify') {
        const expectedEpoch =
          typeof user.expectedSessionEpoch === 'number' && user.expectedSessionEpoch >= 1
            ? user.expectedSessionEpoch
            : (user.sessionEpoch ?? 1);
        const expectedRole: UserRole = user.expectedRole ?? user.role;
        if (!prev || prev.disabled || prev.role !== expectedRole || (prev.sessionEpoch ?? 1) !== expectedEpoch) {
          return { ...(prev ? { ...prev } : stripMeta(user)), mutationAborted: true };
        }
        prev.admittedVia = 'org';
        prev.admittedOrg = user.admittedOrg ? user.admittedOrg.toLowerCase() : undefined;
        prev.orgVerifiedAt = user.orgVerifiedAt;
        if (user.encryptedGhToken) prev.encryptedGhToken = user.encryptedGhToken;
        return { ...prev };
      }

      if (user.mutationKind === 'org_revoke') {
        const expectedEpoch =
          typeof user.expectedSessionEpoch === 'number' && user.expectedSessionEpoch >= 1
            ? user.expectedSessionEpoch
            : Math.max(1, (user.sessionEpoch ?? 2) - 1);
        if (!prev || prev.disabled || (prev.sessionEpoch ?? 1) !== expectedEpoch) {
          return { ...(prev ? { ...prev } : stripMeta(user)), mutationAborted: true };
        }
        prev.sessionEpoch = expectedEpoch + 1;
        delete prev.admittedVia;
        delete prev.admittedOrg;
        delete prev.encryptedGhToken;
        delete prev.orgVerifiedAt;
        return { ...prev };
      }

      if (user.mutationKind === 'founder_heal') {
        const pinnedId = (user.githubId ?? user.reconcilePinnedOwnerId ?? '').trim();
        const founderLoginLower = (user.githubLogin ?? user.userId).trim().toLowerCase();
        for (const sq of users.values()) {
          if (
            sq.userId !== user.userId &&
            ((sq.githubLogin ?? '').toLowerCase() === founderLoginLower ||
              (pinnedId && String(sq.githubId ?? '') === pinnedId))
          ) {
            sq.disabled = true;
            sq.role = 'member';
            delete sq.promotedByOwnerId;
            sq.sessionEpoch = (sq.sessionEpoch ?? 1) + 1;
            sq.githubLogin = `__evicted_${sq.userId}`;
            if (pinnedId && String(sq.githubId ?? '') === pinnedId) delete sq.githubId;
            delete sq.admittedVia;
            delete sq.admittedOrg;
            delete sq.encryptedGhToken;
            delete sq.orgVerifiedAt;
            for (const [h, t] of tokens.entries()) {
              if ((t.userId ?? 'owner') === sq.userId) tokens.delete(h);
            }
            for (const [ch, cd] of codes.entries()) {
              if ((cd.userId ?? 'owner') === sq.userId) codes.delete(ch);
            }
          }
        }
        if (pinnedId) demoteMemoryUnapprovedOwners(pinnedId);
        const nextEpoch = prev ? (prev.disabled ? (prev.sessionEpoch ?? 1) + 1 : (prev.sessionEpoch ?? 1)) : 1;
        const healed: HubUserRecord = {
          ...stripMeta(user),
          ...(pinnedId ? { githubId: pinnedId } : {}),
          role: 'owner',
          promotedByOwnerId: pinnedId || 'owner',
          sessionEpoch: nextEpoch,
          disabled: false,
          admittedVia: 'owner',
          createdAt: prev?.createdAt ?? user.createdAt,
          lastLoginAt: user.lastLoginAt,
        };
        delete healed.admittedOrg;
        users.set(user.userId, healed);
        for (const t of tokens.values()) {
          if ((t.userId ?? 'owner') === user.userId) t.userRole = 'owner';
        }
        for (const cd of codes.values()) {
          if ((cd.userId ?? 'owner') === user.userId) cd.userRole = 'owner';
        }
        return { ...healed };
      }

      if (user.mutationKind === 'oauth_login_existing') {
        if (!prev || prev.disabled) {
          return { ...(prev ? { ...prev } : stripMeta(user)), mutationAborted: true };
        }
        const updated: HubUserRecord = {
          ...prev,
          ...(user.githubId ? { githubId: user.githubId } : {}),
          githubLogin: user.githubLogin ?? prev.githubLogin,
          ...(user.avatarUrl ? { avatarUrl: user.avatarUrl } : {}),
          admittedVia: user.admittedVia,
          ...(user.admittedOrg ? { admittedOrg: user.admittedOrg.toLowerCase() } : {}),
          ...(user.encryptedGhToken ? { encryptedGhToken: user.encryptedGhToken } : {}),
          ...(user.orgVerifiedAt !== undefined ? { orgVerifiedAt: user.orgVerifiedAt } : {}),
          lastLoginAt: user.lastLoginAt,
        };
        if (!user.avatarUrl) delete updated.avatarUrl;
        if (!user.admittedOrg) delete updated.admittedOrg;
        if (!user.encryptedGhToken) delete updated.encryptedGhToken;
        if (user.orgVerifiedAt === undefined) delete updated.orgVerifiedAt;
        users.set(user.userId, updated);
        return { ...updated };
      }

      if (user.mutationKind === 'oauth_login_new') {
        if (prev) {
          if (prev.disabled) {
            return { ...prev, mutationAborted: true };
          }
          const updated: HubUserRecord = {
            ...prev,
            ...(user.githubId ? { githubId: user.githubId } : {}),
            githubLogin: user.githubLogin ?? prev.githubLogin,
            ...(user.avatarUrl ? { avatarUrl: user.avatarUrl } : {}),
            admittedVia: user.admittedVia,
            ...(user.admittedOrg ? { admittedOrg: user.admittedOrg.toLowerCase() } : {}),
            ...(user.encryptedGhToken ? { encryptedGhToken: user.encryptedGhToken } : {}),
            ...(user.orgVerifiedAt !== undefined ? { orgVerifiedAt: user.orgVerifiedAt } : {}),
            lastLoginAt: user.lastLoginAt,
          };
          users.set(user.userId, updated);
          return { ...updated };
        }
        const fresh: HubUserRecord = {
          ...stripMeta(user),
          role: 'member',
          sessionEpoch: 1,
          disabled: false,
          ...(user.admittedOrg ? { admittedOrg: user.admittedOrg.toLowerCase() } : {}),
        };
        delete fresh.promotedByOwnerId;
        users.set(user.userId, fresh);
        return { ...fresh };
      }

      if (user.mutationKind === 'admin_disable') {
        const resolvedPin = resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
        const founderUserId =
          user.configuredFounderUserId !== undefined
            ? (user.configuredFounderUserId ?? '')
            : resolvedPin
              ? `gh_${resolvedPin}`
              : '';
        if (user.userId === 'owner' || (founderUserId !== '' && user.userId === founderUserId)) {
          return {
            ...(prev ? { ...prev } : stripMeta(user)),
            mutationAborted: true,
            disableFailedReason: 'founder_protected',
          };
        }
        if (!prev) {
          return { ...stripMeta(user), disabled: true, mutationAborted: true, disableFailedReason: 'not_found' };
        }
        const callerIsFounder = user.callerIsImmutableFounder === true;
        if (!callerIsFounder && prev.role === 'owner') {
          return { ...prev, mutationAborted: true, disableFailedReason: 'owner_protected' };
        }
        if (prev.disabled) {
          if (user.allowAlreadyDisabled) {
            for (const [h, t] of tokens.entries()) {
              if ((t.userId ?? 'owner') === user.userId) {
                grantRefreshRateLimits.delete(t.grantId);
                tokens.delete(h);
              }
            }
            for (const [ch, cd] of codes.entries()) {
              if ((cd.userId ?? 'owner') === user.userId) codes.delete(ch);
            }
            return { ...prev, ...computeMemoryUserTokenStats(user.userId) };
          }
          return { ...prev, mutationAborted: true, disableFailedReason: 'already_disabled' };
        }
        prev.role = 'member';
        delete prev.promotedByOwnerId;
        prev.disabled = true;
        prev.sessionEpoch = (prev.sessionEpoch ?? 1) + 1;
        if (user.githubLogin) prev.githubLogin = user.githubLogin;
        delete prev.admittedVia;
        delete prev.admittedOrg;
        delete prev.encryptedGhToken;
        delete prev.orgVerifiedAt;
        for (const [h, t] of tokens.entries()) {
          if ((t.userId ?? 'owner') === user.userId) {
            grantRefreshRateLimits.delete(t.grantId);
            tokens.delete(h);
          }
        }
        for (const [ch, cd] of codes.entries()) {
          if ((cd.userId ?? 'owner') === user.userId) codes.delete(ch);
        }
        return { ...prev, ...computeMemoryUserTokenStats(user.userId) };
      }

      if (user.mutationKind === 'demote_unapproved_owner' || user.mutationKind === 'admin_role') {
        if (!prev || prev.disabled) {
          return { ...(prev ? { ...prev } : stripMeta(user)), mutationAborted: true };
        }
        const nextRole: UserRole = user.mutationKind === 'demote_unapproved_owner' ? 'member' : user.role;
        prev.role = nextRole;
        if (nextRole === 'owner' && user.promotedByOwnerId) {
          prev.promotedByOwnerId = user.promotedByOwnerId;
        } else {
          delete prev.promotedByOwnerId;
        }
        prev.sessionEpoch = (prev.sessionEpoch ?? 1) + 1;
        for (const t of tokens.values()) {
          if ((t.userId ?? 'owner') === user.userId) t.userRole = nextRole;
        }
        for (const cd of codes.values()) {
          if ((cd.userId ?? 'owner') === user.userId) cd.userRole = nextRole;
        }
        return { ...prev };
      }

      const isDisabled = Boolean(user.disabled);
      if (!isDisabled && prev?.disabled) {
        return { ...prev, mutationAborted: true };
      }
      const copy: HubUserRecord = {
        ...stripMeta(user),
        ...(user.admittedOrg ? { admittedOrg: user.admittedOrg.toLowerCase() } : {}),
        ...(isDisabled ? { encryptedGhToken: undefined } : {}),
        sessionEpoch:
          typeof user.sessionEpoch === 'number' && user.sessionEpoch >= 1
            ? user.sessionEpoch
            : (prev?.sessionEpoch ?? 1),
        disabled: isDisabled,
      };
      if (copy.role === 'owner' && !copy.promotedByOwnerId && prev?.promotedByOwnerId) {
        copy.promotedByOwnerId = prev.promotedByOwnerId;
      }
      if (isDisabled || copy.role !== 'owner') {
        delete copy.promotedByOwnerId;
      }
      if (isDisabled) {
        delete copy.encryptedGhToken;
      }
      users.set(user.userId, copy);
      if (copy.disabled) {
        for (const [h, t] of tokens.entries()) {
          if ((t.userId ?? 'owner') === user.userId) tokens.delete(h);
        }
        for (const [ch, cd] of codes.entries()) {
          if ((cd.userId ?? 'owner') === user.userId) codes.delete(ch);
        }
      }
      return { ...copy };
    },
    getUser(userId) {
      const pinnedOwnerId = resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
      if (pinnedOwnerId) {
        this.enforcePinnedFounderOwners?.(pinnedOwnerId);
      }
      const u = users.get(userId);
      return u ? { ...u, ...computeMemoryUserTokenStats(userId) } : null;
    },
    listUsers() {
      const pinnedOwnerId = resolvePinnedGitHubOwnerId(callerAuthAls.getStore()?.githubAuthEnv);
      if (pinnedOwnerId) {
        this.enforcePinnedFounderOwners?.(pinnedOwnerId);
      }
      return [...users.values()]
        .filter((u) => !u.disabled)
        .map(({ encryptedGhToken: _omitSecret, ...u }) => ({ ...u, ...computeMemoryUserTokenStats(u.userId) }))
        .sort((a, b) => b.lastLoginAt - a.lastLoginAt);
    },
    countUsers() {
      let c = 0;
      for (const k of users.keys()) {
        if (k !== 'owner') c++;
      }
      return c;
    },
    updateUserRole(userId, role, promotedByOwnerId) {
      if (userId === 'owner' && role !== 'owner') return false;
      const u = users.get(userId);
      if (!u || u.disabled) return false;
      u.role = role;
      if (role === 'owner' && promotedByOwnerId) {
        u.promotedByOwnerId = promotedByOwnerId;
      } else {
        delete u.promotedByOwnerId;
      }
      u.sessionEpoch = (u.sessionEpoch ?? 1) + 1;
      for (const t of tokens.values()) {
        if ((t.userId ?? 'owner') === userId) t.userRole = role;
      }
      for (const cd of codes.values()) {
        if ((cd.userId ?? 'owner') === userId) cd.userRole = role;
      }
      return true;
    },
    enforcePinnedFounderOwners(pinnedOwnerId) {
      if (!pinnedOwnerId || !/^[1-9][0-9]{0,19}$/.test(pinnedOwnerId.trim())) return 0;
      const cleanPin = pinnedOwnerId.trim();
      let count = 0;
      for (const u of users.values()) {
        if (
          u.userId !== 'owner' &&
          u.role === 'owner' &&
          String(u.githubId ?? '') !== cleanPin &&
          u.promotedByOwnerId !== cleanPin &&
          u.promotedByOwnerId !== 'owner'
        ) {
          u.role = 'member';
          delete u.promotedByOwnerId;
          u.sessionEpoch = (u.sessionEpoch ?? 1) + 1;
          for (const t of tokens.values()) {
            if ((t.userId ?? 'owner') === u.userId) t.userRole = 'member';
          }
          for (const cd of codes.values()) {
            if ((cd.userId ?? 'owner') === u.userId) cd.userRole = 'member';
          }
          count++;
        }
      }
      return count;
    },
    checkAuthLockout(bucket, now, maxFailures = RATE_LIMIT_MAX_FAILURES) {
      if (bucket.startsWith('revoked_admin:')) {
        const exp = adminRevocations.get(bucket);
        if (exp === undefined || exp <= now) {
          if (exp !== undefined) adminRevocations.delete(bucket);
          return { allowed: true, retryAfterSec: 0 };
        }
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((exp - now) / 1_000)) };
      }
      const cur = failures.get(bucket);
      if (!cur || cur.resetAt <= now) {
        if (cur) failures.delete(bucket);
        return { allowed: true, retryAfterSec: 0 };
      }
      if (cur.count >= maxFailures) {
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((cur.resetAt - now) / 1_000)) };
      }
      return { allowed: true, retryAfterSec: 0 };
    },
    recordAuthFailure(bucket, now, windowMs, maxFailures) {
      if (bucket.startsWith('revoked_admin:')) {
        for (const [k, exp] of adminRevocations.entries()) {
          if (exp <= now) adminRevocations.delete(k);
        }
        while (adminRevocations.size >= 4096) {
          const oldest = adminRevocations.keys().next().value;
          if (oldest === undefined) break;
          adminRevocations.delete(oldest);
        }
        adminRevocations.set(bucket, now + windowMs);
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil(windowMs / 1_000)) };
      }
      for (const [b, v] of failures.entries()) {
        if (v.resetAt <= now) failures.delete(b);
      }
      const cur = failures.get(bucket);
      if (!cur) {
        if (failures.size >= MAX_AUTH_FAILURE_BUCKETS) {
          for (const [b, v] of failures.entries()) {
            if (v.count < maxFailures) {
              failures.delete(b);
              break;
            }
          }
        }
        failures.set(bucket, { count: 1, resetAt: now + windowMs });
        return { allowed: true, retryAfterSec: 0 };
      }
      cur.count++;
      if (cur.count > maxFailures) {
        return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((cur.resetAt - now) / 1_000)) };
      }
      return { allowed: true, retryAfterSec: 0 };
    },
    clearAuthFailures(bucket) {
      if (bucket.startsWith('revoked_admin:')) {
        adminRevocations.delete(bucket);
        return;
      }
      failures.delete(bucket);
    },
  };
}

export function escapeHtml(v: string): string {
  return v
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function randomUrlToken(byteLen = 32): string {
  const buf = new Uint8Array(byteLen);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

export async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return base64UrlEncode(new Uint8Array(digest));
}

async function hmacSha256Base64Url(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return base64UrlEncode(new Uint8Array(sig));
}

export function readCookie(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${name}=`)) {
      const rawVal = trimmed.slice(name.length + 1);
      return rawVal.includes('%') ? (safeDecodeURIComponent(rawVal) ?? rawVal) : rawVal;
    }
  }
  return null;
}

export function isEffectiveHttpsOrigin(url: URL, publicOrigin?: string): boolean {
  if (url.protocol === 'https:') return true;
  if (typeof publicOrigin === 'string' && publicOrigin.trim().toLowerCase().startsWith('https://')) {
    return true;
  }
  return false;
}

export async function isAdminSessionRevoked(
  store: Pick<OAuthStore, 'checkAuthLockout'> | undefined,
  csrf: string,
  now: number,
  jti?: string,
): Promise<boolean> {
  if (!store || typeof store.checkAuthLockout !== 'function') return false;
  if (jti) {
    const jtiHash = await sha256Base64Url(jti);
    const jtiCheck = await store.checkAuthLockout(`revoked_admin:jti:${jtiHash}`, now, 1);
    if (!jtiCheck.allowed) return true;
  }
  const csrfHash = await sha256Base64Url(csrf);
  const hashedCheck = await store.checkAuthLockout(`revoked_admin:${csrfHash}`, now, 1);
  if (!hashedCheck.allowed) return true;
  const legacyCheck = await store.checkAuthLockout(`revoked_admin:${csrf}`, now, 1);
  return !legacyCheck.allowed;
}

export function isSameOriginFormPost(request: Request, url: URL, publicOrigin?: string): boolean {
  const secFetchSite = (request.headers.get('sec-fetch-site') ?? '').trim().toLowerCase();
  if (secFetchSite === 'cross-site' || secFetchSite === 'same-site') return false;
  const rawOrigin = request.headers.get('origin');
  if (!rawOrigin || !rawOrigin.trim()) return true;
  if (rawOrigin.trim().toLowerCase() === 'null') {
    // Privacy browsers/extensions (e.g. Brave Shields, Firefox privacy flags, AdGuard/Privacy Badger)
    // and `Referrer-Policy: no-referrer` navigations can rewrite `Origin` to `"null"` on genuine
    // same-origin form POSTs after the browser has already stamped the forbidden `Sec-Fetch-Site: same-origin`
    // Fetch Metadata header. Reject `Origin: null` unless `Sec-Fetch-Site` is explicitly `same-origin`.
    return secFetchSite === 'same-origin';
  }
  try {
    const reqOriginUrl = new URL(rawOrigin.trim());
    if (reqOriginUrl.origin.toLowerCase() === url.origin.toLowerCase()) return true;
    if (publicOrigin?.trim()) {
      try {
        const pubUrl = new URL(publicOrigin.trim());
        if (reqOriginUrl.origin.toLowerCase() === pubUrl.origin.toLowerCase()) return true;
      } catch {
        // ignore invalid publicOrigin
      }
    }
    // Allow loopback equivalence (`127.0.0.1:<port>` <-> `localhost:<port>` <-> `hub.local:<port>`) when Hub runs over local HTTP
    if (
      url.protocol === 'http:' &&
      reqOriginUrl.protocol === 'http:' &&
      isLoopbackHost(reqOriginUrl.hostname.toLowerCase()) &&
      (isLoopbackHost(url.hostname.toLowerCase()) || url.hostname.toLowerCase() === 'hub.local') &&
      (reqOriginUrl.port || '80') === (url.port || '80')
    ) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

export function formatCookie(
  name: string,
  value: string,
  opts: { maxAge: number; path?: string; sameSite?: 'Strict' | 'Lax'; secure?: boolean },
): string {
  const parts = [
    `${name}=${value}`,
    'HttpOnly',
    `SameSite=${opts.sameSite ?? 'Lax'}`,
    `Path=${opts.path ?? '/'}`,
    `Max-Age=${opts.maxAge}`,
  ];
  if (opts.secure !== false) parts.push('Secure');
  return parts.join('; ');
}

/** Signs an 8-hour browser session cookie (`v1.<expiresAt>.<csrf>.<hmac>`) bound to the hub's secret token. */
export async function createAdminSessionValue(
  secret: string,
  now = Date.now(),
  ttlMs = ADMIN_SESSION_TTL_MS,
): Promise<{ value: string; csrf: string; maxAgeSec: number }> {
  const expiresAt = now + ttlMs;
  const csrf = randomUrlToken(24);
  const payload = `v1.${expiresAt}.${csrf}`;
  const sig = await hmacSha256Base64Url(`admin-cookie:${secret}`, payload);
  return {
    value: `${payload}.${sig}`,
    csrf,
    maxAgeSec: Math.floor(ttlMs / 1_000),
  };
}

export function resolveAdminCookieAttrs(url: URL, publicOrigin?: string): { name: string; secure: boolean; strictHostPrefix: boolean } {
  const isSecure = isEffectiveHttpsOrigin(url, publicOrigin);
  if (!isSecure) {
    return { name: ADMIN_COOKIE_NAME_DEV, secure: false, strictHostPrefix: false };
  }
  return { name: ADMIN_COOKIE_NAME, secure: true, strictHostPrefix: true };
}

export async function verifyAdminSessionCookie(
  cookieHeader: string | null,
  secret: string | undefined,
  now = Date.now(),
  opts?: { strictHostPrefix?: boolean; githubAuthEnabled?: boolean },
): Promise<({ ok: true } & AdminPrincipal) | { ok: false }> {
  if (!secret) return { ok: false };
  const hostPrefixedVal = readCookie(cookieHeader, ADMIN_COOKIE_NAME);
  let raw: string | null = null;
  if (hostPrefixedVal !== null) {
    // Never fall back to unprefixed `ef_admin_session` when `__Host-ef_admin_session` is present in the Cookie header!
    raw = hostPrefixedVal;
  } else {
    const devVal = readCookie(cookieHeader, ADMIN_COOKIE_NAME_DEV);
    if (devVal !== null) {
      if (opts?.strictHostPrefix) {
        // On HTTPS / non-loopback origins, never accept tossed GitHub (`gh_*`) JWTs from unprefixed cookies;
        // allow only legacy `v1.` owner-token HMAC cookies when GitHub multi-user OAuth is disabled.
        if (!opts.githubAuthEnabled && devVal.startsWith('v1.')) {
          raw = devVal;
        }
      } else {
        raw = devVal;
      }
    }
  }
  if (!raw) return { ok: false };
  const parts = raw.split('.');
  if (parts.length === 3 && !raw.startsWith('v1.')) {
    return verifySessionJwt(raw, secret, now);
  }
  if (secret.length < MIN_TOKEN_LENGTH) return { ok: false };
  if (parts.length !== 4 || parts[0] !== 'v1') return { ok: false };
  const expiresAt = Number(parts[1]);
  const csrf = parts[2] ?? '';
  const sig = parts[3] ?? '';
  if (!Number.isFinite(expiresAt) || expiresAt <= now || csrf.length < 16 || sig.length < 16) {
    return { ok: false };
  }
  const expected = await hmacSha256Base64Url(`admin-cookie:${secret}`, `v1.${expiresAt}.${csrf}`);
  if (!sameBytes(sig, expected)) return { ok: false };
  return { ok: true, userId: 'owner', role: 'owner', authMethod: 'owner_token', csrf, expiresAt };
}

/**
 * Verifies an admin session cookie against BOTH server-side `jti`/`csrf` revocations AND the live `users` table
 * (`disabled`, `sessionEpoch`, live `role`, and `GITHUB_ALLOWED_USERS` de-allowlisting).
 */
export async function verifyLiveAdminSession(params: {
  cookieHeader: string | null;
  signingSecret: string | undefined;
  store: OAuthStore;
  now?: number;
  strictHostPrefix?: boolean;
  githubAuthEnv?: GitHubAuthEnv;
}): Promise<({ ok: true } & AdminPrincipal) | { ok: false }> {
  const now = params.now ?? Date.now();
  const githubEnabled = Boolean(params.githubAuthEnv && isGitHubAuthConfigured(params.githubAuthEnv));
  const session = await verifyAdminSessionCookie(params.cookieHeader, params.signingSecret, now, {
    strictHostPrefix: params.strictHostPrefix,
    githubAuthEnabled: githubEnabled,
  });
  if (!session.ok) return { ok: false };
  if (await isAdminSessionRevoked(params.store, session.csrf, now, session.jti)) {
    return { ok: false };
  }
  if (session.authMethod === 'github' || session.userId !== 'owner') {
    await reconcileUpgradedFounderOwners({ store: params.store, env: params.githubAuthEnv });
    let liveUser = (await params.store.getUser?.(session.userId)) ?? null;
    if (!liveUser) {
      const userCount = (await params.store.countUsers?.()) ?? 0;
      if (githubEnabled || userCount > 0 || session.role === 'owner') {
        return { ok: false };
      }
      return session;
    }
    if (liveUser.disabled) {
      return { ok: false };
    }
    const expectedEpoch = liveUser.sessionEpoch ?? 1;
    if ((session.epoch ?? 1) !== expectedEpoch) {
      return { ok: false };
    }
    if (isGitHubUserDeAllowlisted(liveUser, params.githubAuthEnv)) {
      return { ok: false };
    }
    if (
      liveUser.admittedVia === 'org' &&
      !isPinnedGitHubFounder(liveUser, params.githubAuthEnv) &&
      params.githubAuthEnv &&
      isGitHubAuthConfigured(params.githubAuthEnv) &&
      (!liveUser.orgVerifiedAt || now - liveUser.orgVerifiedAt > GITHUB_ORG_REVERIFY_TTL_MS)
    ) {
      const orgCheck = await reverifyGitHubOrgAdmission({
        user: liveUser,
        env: params.githubAuthEnv,
        sessionSecret: params.signingSecret,
        store: params.store,
        now,
      });
      if (!orgCheck.ok) {
        return { ok: false };
      }
      liveUser = (await params.store.getUser?.(session.userId)) ?? null;
      if (!liveUser || liveUser.disabled || (liveUser.sessionEpoch ?? 1) !== expectedEpoch) {
        return { ok: false };
      }
    }
    return {
      ...session,
      role: liveUser.role,
      ...(liveUser.githubLogin ? { githubLogin: liveUser.githubLogin } : {}),
      ...(liveUser.avatarUrl ? { avatarUrl: liveUser.avatarUrl } : {}),
    };
  }
  return session;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
}

function isLoopbackRedirectUri(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' && isLoopbackHost(u.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function isRedirectHostAllowlisted(hostname: string, allowlist: readonly string[]): boolean {
  const host = hostname.toLowerCase().replace(/\.+$/, '');
  if (!host) return false;
  for (const raw of allowlist) {
    const rule = raw.trim().toLowerCase().replace(/^\*\./, '').replace(/^\./, '').replace(/\.+$/, '');
    if (!rule) continue;
    if (host === rule || host.endsWith(`.${rule}`)) return true;
  }
  return false;
}

/**
 * Validates OAuth 2.1 redirect URIs for Dynamic Client Registration (RFC 7591 + RFC 8252):
 *  - Loopback native CLI callbacks (`http://localhost(:port)/...`, `http://127.0.0.1(:port)/...`, `http://[::1](:port)/...`), OR
 *  - External `https://` callbacks ONLY when explicitly allowlisted in `redirectAllowlist` (off by default, H-S2).
 */
export function isValidRedirectUri(raw: string, selfOrigin: string, redirectAllowlist: readonly string[] = []): boolean {
  if (typeof raw !== 'string' || raw.length > 512) return false;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.hash || u.username || u.password) return false;
  if (u.protocol === 'http:') {
    return isLoopbackHost(u.hostname.toLowerCase());
  }
  if (u.protocol === 'https:') {
    if (u.origin.toLowerCase() === selfOrigin.toLowerCase()) return false;
    return isRedirectHostAllowlisted(u.hostname, redirectAllowlist);
  }
  return false;
}

/** Matches a requested `redirect_uri` against registered URIs (exact match, plus RFC 8252 §7.3 dynamic loopback port). */
export function matchesRegisteredRedirectUri(requested: string, registeredList: string[]): boolean {
  if (registeredList.includes(requested)) return true;
  let reqUrl: URL;
  try {
    reqUrl = new URL(requested);
  } catch {
    return false;
  }
  if (reqUrl.protocol !== 'http:' || !isLoopbackHost(reqUrl.hostname.toLowerCase())) {
    return false;
  }
  for (const reg of registeredList) {
    try {
      const regUrl = new URL(reg);
      if (
        regUrl.protocol === 'http:' &&
        regUrl.hostname.toLowerCase() === reqUrl.hostname.toLowerCase() &&
        regUrl.port === '' &&
        regUrl.pathname === reqUrl.pathname &&
        regUrl.search === reqUrl.search
      ) {
        return true;
      }
    } catch {
      // ignore
    }
  }
  return false;
}

export function parseRequestedScopes(
  rawScope: string | null | undefined,
): { ok: true; scopes: McpScope[] } | { ok: false; invalid: string[] } {
  if (!rawScope || !rawScope.trim()) return { ok: true, scopes: [...MCP_SCOPES] };
  const tokens = rawScope
    .split(/\s+/)
    .map((s) => s.trim())
    .filter((s) => Boolean(s) && s !== 'offline_access');
  if (tokens.length === 0) return { ok: true, scopes: [...MCP_SCOPES] };
  const invalid = tokens.filter((s) => !(SUPPORTED_MCP_SCOPES as readonly string[]).includes(s));
  if (invalid.length > 0) {
    return { ok: false, invalid };
  }
  return { ok: true, scopes: [...new Set(tokens as McpScope[])] };
}

/**
 * Resolves an OAuth Client ID Metadata Document (CIMD, `draft-ietf-oauth-client-id-metadata-document-00` / MCP SEP-991)
 * when `client_id` is an `https://` URL hosted on an allowlisted domain (e.g. Claude's published identity).
 */
async function resolveCimdClient(params: {
  clientId: string;
  selfOrigin: string;
  redirectAllowlist: readonly string[];
  store: OAuthStore;
  now: number;
}): Promise<OAuthClientRecord | null> {
  const { clientId, selfOrigin, redirectAllowlist, store, now } = params;
  if (!clientId.startsWith('https://') || clientId.length > 512) return null;
  let u: URL;
  try {
    u = new URL(clientId);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || !u.pathname || u.pathname === '/' || u.hash || u.username || u.password) {
    return null;
  }
  const segments = u.pathname.split('/');
  if (segments.some((s) => s === '.' || s === '..')) return null;
  if (u.origin.toLowerCase() === selfOrigin.toLowerCase()) return null;
  if (!isRedirectHostAllowlisted(u.hostname, redirectAllowlist)) return null;

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), 5_000);
  try {
    // Note: Cloudflare Workers `workerd` only supports `redirect: 'follow' | 'manual'` (`'error'` throws TypeError).
    const res = await fetch(clientId, {
      method: 'GET',
      headers: { accept: 'application/json', 'user-agent': 'EdgeFetch-OAuth-CIMD/2.0' },
      redirect: 'manual',
      signal: abortController.signal,
    });
    if (res.status !== 200) return null;
    const text = await res.text();
    if (text.length > 32_768) return null;
    const doc = JSON.parse(text) as {
      client_id?: unknown;
      client_name?: unknown;
      redirect_uris?: unknown;
    };
    if (doc.client_id !== clientId) return null;
    if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0 || doc.redirect_uris.length > 10) {
      return null;
    }
    const redirectUris: string[] = [];
    for (const r of doc.redirect_uris) {
      if (typeof r !== 'string' || !isValidRedirectUri(r, selfOrigin, redirectAllowlist)) {
        return null;
      }
      redirectUris.push(r);
    }
    const clientName =
      typeof doc.client_name === 'string' && doc.client_name.trim()
        ? doc.client_name.trim().slice(0, 80)
        : u.hostname;
    const record: OAuthClientRecord = { clientId, clientName, redirectUris, createdAt: now };
    await store.putClient(record);
    return record;
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

export function normalizeScopes(rawScope: string | null | undefined): string[] {
  const parsed = parseRequestedScopes(rawScope);
  return parsed.ok ? parsed.scopes : [];
}

function normalizeResource(rawResource: string | null | undefined, origin: string): { ok: true; resource: string } | { ok: false } {
  const canonical = `${origin}/mcp`;
  if (!rawResource || !rawResource.trim()) return { ok: true, resource: canonical };
  try {
    const u = new URL(rawResource.trim());
    if (u.origin.toLowerCase() !== origin.toLowerCase()) return { ok: false };
    if (u.pathname === '/' || u.pathname === '' || u.pathname === '/mcp') {
      return { ok: true, resource: canonical };
    }
    return { ok: false };
  } catch {
    return { ok: false };
  }
}

export const DEFAULT_TRUSTED_MCP_HOSTS = [
  'claude.ai',
  'claude.com',
  'antigravity.google',
  'chatgpt.com',
  'openai.com',
  'platform.openai.com',
  'cursor.sh',
  'cursor.com',
  'vscode.dev',
  'insiders.vscode.dev',
  'windsurf.com',
  'codeium.com',
  'modelcontextprotocol.io',
  'smithery.ai',
] as const;

export function isTrustedMcpBrowserOrigin(
  originHeader: string | null,
  selfOrigin: string,
  extraAllowedHosts: readonly string[] = [],
): boolean {
  if (!originHeader) return true;
  try {
    const u = new URL(originHeader);
    if (u.protocol === 'vscode-webview:') return true;
    const host = u.hostname.toLowerCase().replace(/\.+$/, '');
    if (isLoopbackHost(host)) {
      return u.protocol === 'http:' || u.protocol === 'https:';
    }
    if (u.protocol !== 'https:') return false;
    const selfHost = new URL(selfOrigin).hostname.toLowerCase().replace(/\.+$/, '');
    if (host === selfHost) return true;
    const allowlist = [...DEFAULT_TRUSTED_MCP_HOSTS, ...extraAllowedHosts];
    return allowlist.some((rawAllowed) => {
      const allowed = rawAllowed.trim().toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
      return Boolean(allowed) && (host === allowed || host.endsWith(`.${allowed}`));
    });
  } catch {
    return false;
  }
}

export function oauthCorsHeaders(
  request: Request,
  selfOrigin: string,
  extraAllowedHosts: readonly string[] = [],
): Record<string, string> {
  const reqOrigin = request.headers.get('origin');
  if (!reqOrigin || !isTrustedMcpBrowserOrigin(reqOrigin, selfOrigin, extraAllowedHosts)) return {};
  try {
    const u = new URL(reqOrigin);
    const allowOrigin = u.protocol === 'vscode-webview:' ? reqOrigin : u.origin;
    return {
      'access-control-allow-origin': allowOrigin,
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'authorization, x-api-key, content-type, accept, mcp-protocol-version',
      vary: 'Origin',
    };
  } catch {
    return {};
  }
}

const OAUTH_SECURITY_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
};

function oauthRedirect(targetUrl: string): Response {
  return new Response(null, {
    status: 302,
    headers: {
      location: targetUrl,
      'cache-control': 'no-store',
      ...OAUTH_SECURITY_HEADERS,
    },
  });
}

function oauthJson(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      pragma: 'no-cache',
      ...OAUTH_SECURITY_HEADERS,
      ...extraHeaders,
    },
  });
}

// Note: `form-action` is intentionally omitted from CSP because Chromium applies `form-action` to `302` redirects after
// form submission (`POST /oauth/authorize` redirects to the MCP client's `http://localhost:<port>/callback` URI).
const CONSENT_PAGE_HEADERS: Record<string, string> = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

function renderAuthorizePage(params: {
  serviceName: string;
  clientName: string;
  redirectUri: string;
  scopes: string[];
  sealedState: string;
  csrf: string;
  alreadySignedIn: boolean;
  signedInLabel?: string;
  githubLoginUrl?: string;
  hasOwnerTokenAuth?: boolean;
  errorMessage?: string;
}): string {
  let redirectHost = params.redirectUri;
  try {
    redirectHost = new URL(params.redirectUri).host || params.redirectUri;
  } catch {
    // keep raw
  }
  const scopeBadges = params.scopes
    .map(
      (s) =>
        `<li><code>${escapeHtml(s)}</code> — ${
          s === 'mcp:call'
            ? '<strong>Invoke external tools</strong> on your connected federated MCP servers'
            : s === 'crawl:fetch'
              ? 'Trigger polite HTTPS fetches across container &amp; standby sites'
              : 'Inspect connected standby sites &amp; affinity pins'
        }</li>`,
    )
    .join('');

  const ghBtnHtml = params.githubLoginUrl
    ? `<a class="gh-btn" href="${escapeHtml(params.githubLoginUrl)}"><svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>${params.alreadySignedIn ? 'Switch GitHub Account' : 'Sign in with GitHub'}</a>`
    : '';

  const hasTokenInput = params.hasOwnerTokenAuth !== false;
  const authField = params.alreadySignedIn
    ? `<p class="ok-banner">Authenticated via ${escapeHtml(params.signedInLabel ?? 'active Admin Portal session')}.</p>${ghBtnHtml}`
    : `${ghBtnHtml}${
        ghBtnHtml && hasTokenInput ? '<div class="divider"><span>or use owner token</span></div>' : ''
      }${
        hasTokenInput
          ? `<label for="owner_token">EdgeFetch Token (<code>MCP_TOKEN</code> or <code>CALLER_TOKEN</code>)</label>
       <input id="owner_token" name="owner_token" type="password" required autocomplete="current-password" placeholder="Paste your MCP_TOKEN to authorize">`
          : '<p class="muted-note">Sign in with GitHub above to authorize MCP access for your account.</p>'
      }`;

  const canApproveNow = params.alreadySignedIn || hasTokenInput;
  const errHtml = params.errorMessage ? `<div class="err">${escapeHtml(params.errorMessage)}</div>` : '';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize MCP Access — ${escapeHtml(params.serviceName)}</title>
  <style>
    :root { color-scheme: light dark; }
    body { font: 15px/1.55 system-ui, -apple-system, sans-serif; margin: 0; padding: 32px 16px; background: #0f172a; color: #e2e8f0; }
    main { max-width: 520px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 26px; box-shadow: 0 12px 32px rgba(0,0,0,.35); }
    h1 { font-size: 1.25rem; margin: 0 0 10px; color: #f8fafc; }
    p { margin: 8px 0; color: #cbd5e1; }
    code { background: #0f172a; color: #38bdf8; padding: 2px 6px; border-radius: 5px; word-break: break-all; font-size: 0.88em; }
    ul { margin: 10px 0 16px; padding-left: 20px; color: #cbd5e1; }
    li { margin-bottom: 6px; }
    label { display: block; font-weight: 600; font-size: 0.88rem; margin: 14px 0 6px; color: #f1f5f9; }
    input[type="password"] { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font: inherit; }
    .meta { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 10px 12px; margin: 12px 0; font-size: 0.88rem; }
    .err { background: #450a0a; border: 1px solid #dc2626; color: #fecaca; padding: 10px 12px; border-radius: 8px; margin-bottom: 12px; font-size: 0.9rem; }
    .ok-banner { background: #052e16; border: 1px solid #16a34a; color: #bbf7d0; padding: 8px 12px; border-radius: 8px; font-size: 0.88rem; margin-bottom: 10px; }
    .gh-btn { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; box-sizing: border-box; padding: 10px 16px; border-radius: 8px; border: 1px solid #475569; background: #24292f; color: #ffffff; text-decoration: none; font-weight: 600; margin: 10px 0; }
    .gh-btn:hover { background: #32383f; }
    .divider { display: flex; align-items: center; gap: 10px; color: #94a3b8; font-size: 0.8rem; margin: 12px 0; }
    .divider::before, .divider::after { content: ""; flex: 1; border-top: 1px solid #334155; }
    .muted-note { font-size: 0.86rem; color: #94a3b8; }
    .actions { display: flex; gap: 10px; margin-top: 20px; }
    button { font: inherit; font-weight: 600; padding: 10px 18px; border-radius: 8px; border: 1px solid #475569; background: #334155; color: #f8fafc; cursor: pointer; }
    button.approve { background: #2563eb; border-color: #3b82f6; color: #fff; flex: 1; }
    button.approve:hover { background: #1d4ed8; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    @media (prefers-color-scheme: light) {
      body { background: #f1f5f9; color: #0f172a; }
      main { background: #ffffff; border-color: #cbd5e1; box-shadow: 0 8px 24px rgba(15,23,42,.08); }
      h1, label { color: #0f172a; }
      p, ul { color: #334155; }
      code, .meta, input[type="password"] { background: #f8fafc; color: #0f172a; border-color: #cbd5e1; }
      button { background: #f1f5f9; color: #0f172a; border-color: #cbd5e1; }
    }
  </style>
</head>
<body>
  <main>
    <h1>Connect MCP client to ${escapeHtml(params.serviceName)}?</h1>
    ${errHtml}
    <p>An MCP client is requesting scoped OAuth 2.1 access. Verify the callback destination before approving:</p>
    <div class="meta">
      <div><strong>Self-reported Client Name (unverified):</strong> <code>${escapeHtml(params.clientName)}</code></div>
      <div style="margin-top:4px"><strong>Callback Host:</strong> <code>${escapeHtml(redirectHost)}</code></div>
      <div style="margin-top:4px"><strong>Redirect URI:</strong> <code>${escapeHtml(params.redirectUri)}</code></div>
    </div>
    <p><strong>Requested permissions:</strong></p>
    <ul>${scopeBadges}</ul>
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="sealed" value="${escapeHtml(params.sealedState)}">
      <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}">
      ${authField}
      <div class="actions">
        <button class="approve" type="submit" name="decision" value="approve"${canApproveNow ? '' : ' disabled'}>Approve MCP Access</button>
        <button type="submit" name="decision" value="deny" formnovalidate>Deny</button>
      </div>
    </form>
  </main>
</body>
</html>`;
}

interface SealedConsentPayload {
  clientId: string;
  clientName: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
  csrf: string;
  exp: number;
}

async function sealConsent(secret: string, payload: SealedConsentPayload): Promise<string> {
  const jsonB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await hmacSha256Base64Url(`oauth-consent:${secret}`, jsonB64);
  return `${jsonB64}.${sig}`;
}

async function unsealConsent(secret: string, token: string, now: number): Promise<SealedConsentPayload | null> {
  const dot = token.indexOf('.');
  if (dot <= 0) return null;
  const jsonB64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = await hmacSha256Base64Url(`oauth-consent:${secret}`, jsonB64);
  if (!sameBytes(sig, expected)) return null;
  try {
    const raw = atob(jsonB64.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as SealedConsentPayload;
    if (!parsed || typeof parsed.exp !== 'number' || parsed.exp <= now) return null;
    return parsed;
  } catch {
    return null;
  }
}

const MAX_OAUTH_FORM_BYTES = 32 * 1024; // 32 KiB cap on unauthenticated OAuth form/JSON bodies (M6)

async function parseFormOrJson(request: Request): Promise<Record<string, string> | null> {
  const capped = await readBodyTextCapped(request, MAX_OAUTH_FORM_BYTES);
  if (!capped.ok) return null;
  const ct = (request.headers.get('content-type') ?? '').toLowerCase();
  if (ct.includes('application/json')) {
    try {
      const raw = JSON.parse(capped.text || '{}') as Record<string, unknown>;
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(raw ?? {})) {
        if (typeof v === 'string') out[k] = v;
      }
      return out;
    } catch {
      return {};
    }
  }
  const params = new URLSearchParams(capped.text);
  const out: Record<string, string> = {};
  for (const [k, v] of params.entries()) out[k] = v;
  return out;
}

export interface OAuthHandlerDeps {
  store: OAuthStore;
  ownerSecret?: string;
  mcpToken?: string;
  sessionSecret?: string;
  githubAuthEnabled?: boolean;
  githubAuthEnv?: GitHubAuthEnv;
  serviceName: string;
  publicOrigin?: string;
  redirectAllowlist?: readonly string[];
  now?: () => number;
  onEvent?: (ev: {
    level: 'info' | 'warn' | 'error';
    category: 'oauth';
    event: string;
    summary: string;
    details?: Record<string, unknown>;
  }) => Promise<void> | void;
}

/**
 * Handles all RFC 9728 / RFC 8414 / RFC 7591 / OAuth 2.1 routes (`/.well-known/*` and `/oauth/*`).
 * Returns `null` when `url.pathname` is not an OAuth/discovery route.
 */
type OAuthAuditSpan = Pick<ActiveSpanHandle, 'setAttribute' | 'setAttributes' | 'setStatus'>;
const NOOP_OAUTH_AUDIT_SPAN: OAuthAuditSpan = {
  setAttribute() {},
  setAttributes() {},
  setStatus() {},
};

async function withOAuthAuditSpan<T>(
  op: 'register' | 'authorize' | 'token' | 'refresh' | 'revoke',
  fn: (span: OAuthAuditSpan) => Promise<T>,
): Promise<T> {
  const tracer = getActiveRequestTracer();
  if (!tracer) return fn(NOOP_OAUTH_AUDIT_SPAN);
  return tracer.withSpan(`edgefetch.oauth.${op}`, { kind: 1, attributes: { 'oauth.op': op } }, (span) => fn(span));
}

export async function handleOAuthRoute(request: Request, url: URL, deps: OAuthHandlerDeps): Promise<Response | null> {
  const path = url.pathname;
  const isDiscovery =
    path === '/.well-known/oauth-protected-resource' ||
    path === '/.well-known/oauth-protected-resource/mcp' ||
    path === '/.well-known/oauth-authorization-server' ||
    path === '/.well-known/openid-configuration';
  const isOAuth =
    path === '/oauth/register' || path === '/oauth/authorize' || path === '/oauth/token' || path === '/oauth/revoke';

  if (!isDiscovery && !isOAuth) return null;

  const origin = url.origin;
  const cors = oauthCorsHeaders(request, origin, deps.redirectAllowlist);
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  const now = deps.now ? deps.now() : Date.now();

  // 1. RFC 9728 Protected Resource Metadata
  if (path === '/.well-known/oauth-protected-resource' || path === '/.well-known/oauth-protected-resource/mcp') {
    if (request.method !== 'GET') return oauthJson({ error: 'method_not_allowed' }, 405, cors);
    return oauthJson(
      {
        resource: `${origin}/mcp`,
        authorization_servers: [origin],
        bearer_methods_supported: ['header'],
        scopes_supported: [...SUPPORTED_MCP_SCOPES],
        resource_name: deps.serviceName,
      },
      200,
      cors,
    );
  }

  // 2. RFC 8414 Authorization Server Metadata
  if (path === '/.well-known/oauth-authorization-server' || path === '/.well-known/openid-configuration') {
    if (request.method !== 'GET') return oauthJson({ error: 'method_not_allowed' }, 405, cors);
    return oauthJson(
      {
        issuer: origin,
        authorization_endpoint: `${origin}/oauth/authorize`,
        token_endpoint: `${origin}/oauth/token`,
        registration_endpoint: `${origin}/oauth/register`,
        revocation_endpoint: `${origin}/oauth/revoke`,
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['none'],
        code_challenge_methods_supported: ['S256'],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
        scopes_supported: [...SUPPORTED_MCP_SCOPES],
      },
      200,
      cors,
    );
  }

  const ownerSecret = deps.ownerSecret;
  const hasOwnerTokenAuth = Boolean(
    (ownerSecret && ownerSecret.length >= MIN_TOKEN_LENGTH) || (deps.mcpToken && deps.mcpToken.length >= MIN_TOKEN_LENGTH),
  );
  const signingSecret =
    deps.sessionSecret && deps.sessionSecret.length >= 16
      ? deps.sessionSecret
      : ownerSecret && ownerSecret.length >= MIN_TOKEN_LENGTH
        ? ownerSecret
        : undefined;
  if (!signingSecret) {
    return oauthJson({ error: 'server_error', error_description: 'Owner token secret is not configured on hub' }, 503, cors);
  }

  // 3. RFC 7591 Dynamic Client Registration (`POST /oauth/register`)
  if (path === '/oauth/register') {
    return withOAuthAuditSpan('register', async (span) => {
      if (request.method !== 'POST') {
        span.setAttributes({ 'oauth.outcome': 'method_not_allowed', 'http.response.status_code': 405 });
        span.setStatus(false, 'method_not_allowed');
        return oauthJson({ error: 'method_not_allowed' }, 405, cors);
      }
      const clientIp = normalizeClientRateLimitIp(request.headers.get('cf-connecting-ip'));
      const regLock = await deps.store.checkAuthLockout(`reg:${clientIp}`, now, REGISTER_RATE_LIMIT_MAX);
      if (!regLock.allowed) {
        await request.body?.cancel().catch(() => undefined);
        span.setAttributes({ 'oauth.outcome': 'rate_limited', 'http.response.status_code': 429 });
        span.setStatus(false, 'rate_limited');
        return oauthJson(
          { error: 'too_many_requests', error_description: 'Too many client registrations from this IP' },
          429,
          { ...cors, 'retry-after': String(regLock.retryAfterSec) },
        );
      }
      const regCount = await deps.store.recordAuthFailure(`reg:${clientIp}`, now, RATE_LIMIT_WINDOW_MS, REGISTER_RATE_LIMIT_MAX);
      if (!regCount.allowed) {
        await request.body?.cancel().catch(() => undefined);
        span.setAttributes({ 'oauth.outcome': 'rate_limited', 'http.response.status_code': 429 });
        span.setStatus(false, 'rate_limited');
        return oauthJson(
          { error: 'too_many_requests', error_description: 'Too many client registrations from this IP' },
          429,
          { ...cors, 'retry-after': String(regCount.retryAfterSec) },
        );
      }
      const cappedBody = await readBodyTextCapped(request, 16_384);
      if (!cappedBody.ok) {
        span.setAttributes({ 'oauth.outcome': 'payload_too_large', 'http.response.status_code': 413 });
        span.setStatus(false, 'payload_too_large');
        return oauthJson({ error: 'invalid_client_metadata' }, 413, cors);
      }
      const bodyText = cappedBody.text;
      let body: { client_name?: unknown; redirect_uris?: unknown; application_type?: unknown };
      try {
        body = JSON.parse(bodyText) as { client_name?: unknown; redirect_uris?: unknown; application_type?: unknown };
      } catch {
        span.setAttributes({ 'oauth.outcome': 'invalid_client_metadata', 'http.response.status_code': 400 });
        span.setStatus(false, 'invalid_client_metadata');
        return oauthJson({ error: 'invalid_client_metadata', error_description: 'Invalid JSON' }, 400, cors);
      }
      if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0 || body.redirect_uris.length > 10) {
        span.setAttributes({ 'oauth.outcome': 'invalid_redirect_uri', 'http.response.status_code': 400 });
        span.setStatus(false, 'invalid_redirect_uri');
        return oauthJson({ error: 'invalid_redirect_uri', error_description: 'redirect_uris must be a 1-10 item array' }, 400, cors);
      }
      const redirectUris: string[] = [];
      for (const u of body.redirect_uris) {
        if (typeof u !== 'string' || !isValidRedirectUri(u, origin, deps.redirectAllowlist)) {
          span.setAttributes({ 'oauth.outcome': 'invalid_redirect_uri', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_redirect_uri');
          return oauthJson(
            {
              error: 'invalid_redirect_uri',
              error_description: 'Only loopback http:// or owner-allowlisted external https:// redirect URIs are allowed',
            },
            400,
            cors,
          );
        }
        redirectUris.push(u);
      }
      const clientName =
        typeof body.client_name === 'string' && body.client_name.trim()
          ? body.client_name.trim().slice(0, 80)
          : 'MCP Client';
      const applicationType = body.application_type === 'native' || body.application_type === 'web' ? body.application_type : undefined;
      const clientId = `mcp_${randomUrlToken(18)}`;
      // Do NOT write an info ring event on anonymous /oauth/register so attackers cannot flush hub_events (H-S1).
      await deps.store.putClient({ clientId, clientName, redirectUris, createdAt: now });
      span.setAttributes({
        'oauth.client_id': clientId,
        'oauth.redirect_uri_count': redirectUris.length,
        ...(applicationType ? { 'oauth.application_type': applicationType } : {}),
        'oauth.outcome': 'registered',
        'http.response.status_code': 201,
      });
      return oauthJson(
        {
          client_id: clientId,
          client_id_issued_at: Math.floor(now / 1_000),
          client_name: clientName,
          redirect_uris: redirectUris,
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none',
          ...(applicationType ? { application_type: applicationType } : {}),
        },
        201,
        cors,
      );
    });
  }

  // 4. OAuth 2.1 Authorization & Consent (`GET` & `POST /oauth/authorize`)
  if (path === '/oauth/authorize') {
    return withOAuthAuditSpan('authorize', async (span) => {
      const isSecure = isEffectiveHttpsOrigin(url, deps.publicOrigin);
      const cookieAttrs = resolveAdminCookieAttrs(url, deps.publicOrigin);
      const adminSession = await verifyLiveAdminSession({
        cookieHeader: request.headers.get('cookie'),
        signingSecret,
        store: deps.store,
        now,
        strictHostPrefix: cookieAttrs.strictHostPrefix,
        githubAuthEnv: deps.githubAuthEnv,
      });

      if (request.method === 'GET') {
        const clientId = (url.searchParams.get('client_id') ?? '').trim();
        const redirectUri = (url.searchParams.get('redirect_uri') ?? '').trim();
        const responseType = (url.searchParams.get('response_type') ?? '').trim();
        const state = url.searchParams.get('state') ?? '';
        const codeChallenge = (url.searchParams.get('code_challenge') ?? '').trim();
        const codeChallengeMethod = (url.searchParams.get('code_challenge_method') ?? '').trim();
        const scopeCheck = parseRequestedScopes(url.searchParams.get('scope'));
        const resCheck = normalizeResource(url.searchParams.get('resource'), origin);

        let client = clientId ? await deps.store.getClient(clientId) : null;
        if (!client && clientId.startsWith('https://')) {
          client = await resolveCimdClient({
            clientId,
            selfOrigin: origin,
            redirectAllowlist: deps.redirectAllowlist ?? [],
            store: deps.store,
            now,
          });
        }
        if (!client) {
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'unknown_client', 'http.response.status_code': 400 });
          span.setStatus(false, 'unknown_client');
          return new Response('Unknown client_id. Register via POST /oauth/register or use an allowlisted Client ID Metadata Document URL.', {
            status: 400,
            headers: CONSENT_PAGE_HEADERS,
          });
        }
        span.setAttribute('oauth.client_id', client.clientId);
        if (
          !redirectUri ||
          !isValidRedirectUri(redirectUri, origin, deps.redirectAllowlist) ||
          !matchesRegisteredRedirectUri(redirectUri, client.redirectUris)
        ) {
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'invalid_redirect_uri', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_redirect_uri');
          return new Response('Unregistered or disallowed redirect_uri for this client_id.', { status: 400, headers: CONSENT_PAGE_HEADERS });
        }
        if (responseType !== 'code') {
          const errUrl = new URL(redirectUri);
          errUrl.searchParams.set('error', 'unsupported_response_type');
          if (state) errUrl.searchParams.set('state', state);
          errUrl.searchParams.set('iss', origin);
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'unsupported_response_type', 'http.response.status_code': 302 });
          span.setStatus(false, 'unsupported_response_type');
          return oauthRedirect(errUrl.toString());
        }
        if (!scopeCheck.ok) {
          const errUrl = new URL(redirectUri);
          errUrl.searchParams.set('error', 'invalid_scope');
          if (state) errUrl.searchParams.set('state', state);
          errUrl.searchParams.set('iss', origin);
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'invalid_scope', 'http.response.status_code': 302 });
          span.setStatus(false, 'invalid_scope');
          return oauthRedirect(errUrl.toString());
        }
        const scopes = scopeCheck.scopes;
        if (codeChallengeMethod !== 'S256' || !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) {
          const errUrl = new URL(redirectUri);
          errUrl.searchParams.set('error', 'invalid_request');
          errUrl.searchParams.set('error_description', 'PKCE code_challenge with S256 is required');
          if (state) errUrl.searchParams.set('state', state);
          errUrl.searchParams.set('iss', origin);
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'invalid_request', 'http.response.status_code': 302 });
          span.setStatus(false, 'invalid_request');
          return oauthRedirect(errUrl.toString());
        }
        if (!resCheck.ok) {
          const errUrl = new URL(redirectUri);
          errUrl.searchParams.set('error', 'invalid_target');
          if (state) errUrl.searchParams.set('state', state);
          errUrl.searchParams.set('iss', origin);
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'invalid_target', 'http.response.status_code': 302 });
          span.setStatus(false, 'invalid_target');
          return oauthRedirect(errUrl.toString());
        }

        const isExternalRedirect = !isLoopbackRedirectUri(redirectUri);
        const csrf = randomUrlToken(24);
        const sealedState = await sealConsent(signingSecret, {
          clientId: client.clientId,
          clientName: client.clientName,
          redirectUri,
          state,
          codeChallenge,
          scopes,
          resource: resCheck.resource,
          csrf,
          exp: now + 10 * 60_000,
        });

        const githubLoginUrl = deps.githubAuthEnabled
          ? `/admin/auth/github?return_to=${encodeURIComponent(`${url.pathname}${url.search}`)}`
          : undefined;
        // Non-loopback external redirects require explicit CALLER_TOKEN when signed in via legacy owner cookie (H-S2),
        // while verified GitHub OAuth sessions (`authMethod === 'github'`) carry per-user identity.
        const canReuseSession = adminSession.ok && (!isExternalRedirect || adminSession.authMethod === 'github');
        const signedInLabel = adminSession.ok
          ? adminSession.githubLogin
            ? `GitHub @${adminSession.githubLogin} (${adminSession.role})`
            : 'active Admin Portal session'
          : undefined;

        const headers = new Headers(CONSENT_PAGE_HEADERS);
        headers.append('set-cookie', formatCookie(CONSENT_CSRF_COOKIE, csrf, { maxAge: 600, path: '/oauth/authorize', sameSite: 'Lax', secure: isSecure }));
        span.setAttributes({
          'oauth.phase': 'consent_render',
          'oauth.scopes': scopes.join(' '),
          'oauth.external_redirect': isExternalRedirect,
          'oauth.admin_session': adminSession.ok,
          'oauth.outcome': 'consent_rendered',
          'http.response.status_code': 200,
        });
        return new Response(
          renderAuthorizePage({
            serviceName: deps.serviceName,
            clientName: client.clientName,
            redirectUri,
            scopes,
            sealedState,
            csrf,
            alreadySignedIn: canReuseSession,
            ...(signedInLabel ? { signedInLabel } : {}),
            ...(githubLoginUrl ? { githubLoginUrl } : {}),
            hasOwnerTokenAuth,
          }),
          { status: 200, headers },
        );
      }

      if (request.method === 'POST') {
        if (!isSameOriginFormPost(request, url, deps.publicOrigin)) {
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'invalid_origin', 'http.response.status_code': 403 });
          span.setStatus(false, 'invalid_origin');
          return new Response('Cross-origin authorization submission rejected.', {
            status: 403,
            headers: CONSENT_PAGE_HEADERS,
          });
        }
        const form = await parseFormOrJson(request);
        if (!form) {
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'payload_too_large', 'http.response.status_code': 413 });
          span.setStatus(false, 'payload_too_large');
          return new Response('Request payload too large.', { status: 413, headers: CONSENT_PAGE_HEADERS });
        }
        const sealed = await unsealConsent(signingSecret, form.sealed ?? '', now);
        const cookieCsrf = readCookie(request.headers.get('cookie'), CONSENT_CSRF_COOKIE) ?? '';
        if (!sealed || !cookieCsrf || !sameBytes(cookieCsrf, sealed.csrf) || !sameBytes(form.csrf ?? '', sealed.csrf)) {
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'invalid_csrf', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_csrf');
          return new Response('Authorization session expired or invalid CSRF token. Please retry from your MCP client.', {
            status: 400,
            headers: CONSENT_PAGE_HEADERS,
          });
        }
        span.setAttribute('oauth.client_id', sealed.clientId);
        if (!isValidRedirectUri(sealed.redirectUri, origin, deps.redirectAllowlist)) {
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'invalid_redirect_uri', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_redirect_uri');
          return new Response('Disallowed redirect_uri.', { status: 400, headers: CONSENT_PAGE_HEADERS });
        }

        if (form.decision !== 'approve') {
          const denyUrl = new URL(sealed.redirectUri);
          denyUrl.searchParams.set('error', 'access_denied');
          if (sealed.state) denyUrl.searchParams.set('state', sealed.state);
          denyUrl.searchParams.set('iss', origin);
          const denyHeaders = new Headers({
            location: denyUrl.toString(),
            'cache-control': 'no-store',
            ...OAUTH_SECURITY_HEADERS,
          });
          denyHeaders.append(
            'set-cookie',
            formatCookie(CONSENT_CSRF_COOKIE, '', { maxAge: 0, path: '/oauth/authorize', sameSite: 'Lax', secure: isSecure }),
          );
          span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'access_denied', 'http.response.status_code': 302 });
          span.setStatus(false, 'access_denied');
          return new Response(null, { status: 302, headers: denyHeaders });
        }

        const clientIp = normalizeClientRateLimitIp(request.headers.get('cf-connecting-ip'));
        const isExternalRedirect = !isLoopbackRedirectUri(sealed.redirectUri);
        const canReuseSession = adminSession.ok && (!isExternalRedirect || adminSession.authMethod === 'github');
        let grantedUserId = adminSession.ok ? adminSession.userId : 'owner';
        let grantedUserRole: UserRole = adminSession.ok ? adminSession.role : 'owner';

        if (!canReuseSession) {
          const supplied = (form.owner_token ?? '').trim();
          // Verify constant-time secret match FIRST (`R3-M4`): a valid owner/MCP token succeeds and clears any spoofed/shared-IP
          // lockout bucket, while invalid guesses are rejected with `429` once the bucket reaches `RATE_LIMIT_MAX_FAILURES`!
          if (isValidSecretMatch(supplied, deps.ownerSecret, deps.mcpToken)) {
            await deps.store.clearAuthFailures(`oauth:${clientIp}`);
            grantedUserId = 'owner';
            grantedUserRole = 'owner';
          } else {
            const preLock = await deps.store.checkAuthLockout(`oauth:${clientIp}`, now, RATE_LIMIT_MAX_FAILURES);
            if (!preLock.allowed) {
              span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'rate_limited', 'http.response.status_code': 429 });
              span.setStatus(false, 'rate_limited');
              return new Response('Too many failed authorization attempts. Please wait 5 minutes.', {
                status: 429,
                headers: { ...CONSENT_PAGE_HEADERS, 'retry-after': String(preLock.retryAfterSec) },
              });
            }
            const rl = await deps.store.recordAuthFailure(`oauth:${clientIp}`, now, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_FAILURES);
            if (!rl.allowed) {
              span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'rate_limited', 'http.response.status_code': 429 });
              span.setStatus(false, 'rate_limited');
              return new Response('Too many failed authorization attempts. Please wait 5 minutes.', {
                status: 429,
                headers: { ...CONSENT_PAGE_HEADERS, 'retry-after': String(rl.retryAfterSec) },
              });
            }
            span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'unauthorized', 'http.response.status_code': 401 });
            span.setStatus(false, 'unauthorized');
            return new Response(
              renderAuthorizePage({
                serviceName: deps.serviceName,
                clientName: sealed.clientName,
                redirectUri: sealed.redirectUri,
                scopes: sealed.scopes,
                sealedState: form.sealed ?? '',
                csrf: sealed.csrf,
                alreadySignedIn: false,
                ...(deps.githubAuthEnabled ? { githubLoginUrl: '/admin/auth/github' } : {}),
                hasOwnerTokenAuth,
                errorMessage: hasOwnerTokenAuth
                  ? 'Invalid token. Paste your MCP_TOKEN or CALLER_TOKEN.'
                  : 'Sign in with GitHub first to authorize MCP access.',
              }),
              { status: 401, headers: CONSENT_PAGE_HEADERS },
            );
          }
        }

        const rawCode = `efc_${randomUrlToken(32)}`;
        const codeHash = await sha256Base64Url(rawCode);
        try {
          await deps.store.putCode({
            codeHash,
            clientId: sealed.clientId,
            clientName: sealed.clientName,
            redirectUri: sealed.redirectUri,
            codeChallenge: sealed.codeChallenge,
            scopes: sealed.scopes,
            resource: sealed.resource,
            userId: grantedUserId,
            userRole: grantedUserRole,
            expiresAt: now + AUTH_CODE_TTL_MS,
          });
        } catch (err) {
          if (err instanceof OAuthQuotaExceededError) {
            span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'quota_exceeded', 'http.response.status_code': 429 });
            span.setStatus(false, 'user_quota_exceeded');
            return oauthJson(
              { error: 'user_quota_exceeded', error_description: err.message },
              429,
              { ...cors, 'retry-after': '2' },
            );
          }
          throw err;
        }

        const cb = new URL(sealed.redirectUri);
        cb.searchParams.set('code', rawCode);
        if (sealed.state) cb.searchParams.set('state', sealed.state);
        cb.searchParams.set('iss', origin);

        const headers = new Headers({
          location: cb.toString(),
          'cache-control': 'no-store',
          ...OAUTH_SECURITY_HEADERS,
        });
        headers.append('set-cookie', formatCookie(CONSENT_CSRF_COOKIE, '', { maxAge: 0, path: '/oauth/authorize', sameSite: 'Lax', secure: isSecure }));
        span.setAttributes({
          'oauth.phase': 'code_issued',
          'oauth.scopes': sealed.scopes.join(' '),
          'oauth.user_id': grantedUserId,
          'oauth.external_redirect': isExternalRedirect,
          'oauth.admin_session': adminSession.ok,
          'oauth.outcome': 'approved',
          'http.response.status_code': 302,
        });
        return new Response(null, { status: 302, headers });
      }

      span.setAttributes({ 'oauth.phase': 'error', 'oauth.outcome': 'method_not_allowed', 'http.response.status_code': 405 });
      span.setStatus(false, 'method_not_allowed');
      return oauthJson({ error: 'method_not_allowed' }, 405, cors);
    });
  }

  // 5. OAuth 2.1 Token Endpoint (`POST /oauth/token`)
  if (path === '/oauth/token') {
    if (request.method !== 'POST') {
      return withOAuthAuditSpan('token', async (span) => {
        span.setAttributes({ 'oauth.outcome': 'method_not_allowed', 'http.response.status_code': 405 });
        span.setStatus(false, 'method_not_allowed');
        return oauthJson({ error: 'method_not_allowed' }, 405, cors);
      });
    }
    const params = await parseFormOrJson(request);
    if (!params) {
      return withOAuthAuditSpan('token', async (span) => {
        span.setAttributes({ 'oauth.outcome': 'payload_too_large', 'http.response.status_code': 413 });
        span.setStatus(false, 'payload_too_large');
        return oauthJson({ error: 'invalid_request', error_description: 'Request payload too large' }, 413, cors);
      });
    }
    const grantType = params.grant_type ?? '';

    if (grantType === 'authorization_code') {
      return withOAuthAuditSpan('token', async (span) => {
        span.setAttribute('oauth.grant_type', 'authorization_code');
        const code = params.code ?? '';
        const verifier = params.code_verifier ?? '';
        const clientId = (params.client_id ?? '').trim();
        const redirectUri = (params.redirect_uri ?? '').trim();
        if (clientId) span.setAttribute('oauth.client_id', clientId);
        if (!code || !clientId || !redirectUri || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
          span.setAttributes({ 'oauth.outcome': 'invalid_request', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_request');
          return oauthJson(
            { error: 'invalid_request', error_description: 'code, client_id, redirect_uri, and PKCE code_verifier are required' },
            400,
            cors,
          );
        }

        const codeHash = await sha256Base64Url(code);
        const record = await deps.store.consumeCode(codeHash, now);
        if (!record) {
          span.setAttributes({ 'oauth.outcome': 'invalid_grant', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_grant');
          return oauthJson({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or already used' }, 400, cors);
        }
        if (clientId !== record.clientId || redirectUri !== record.redirectUri) {
          span.setAttributes({ 'oauth.outcome': 'client_mismatch', 'http.response.status_code': 400 });
          span.setStatus(false, 'client_mismatch');
          return oauthJson({ error: 'invalid_grant', error_description: 'client_id or redirect_uri mismatch' }, 400, cors);
        }
        const computedChallenge = await sha256Base64Url(verifier);
        if (!sameBytes(computedChallenge, record.codeChallenge)) {
          span.setAttributes({ 'oauth.outcome': 'pkce_failed', 'http.response.status_code': 400 });
          span.setStatus(false, 'pkce_failed');
          return oauthJson({ error: 'invalid_grant', error_description: 'PKCE S256 verification failed' }, 400, cors);
        }
        if (params.resource) {
          const resCheck = normalizeResource(params.resource, origin);
          if (!resCheck.ok || resCheck.resource !== record.resource) {
            span.setAttributes({ 'oauth.outcome': 'invalid_target', 'http.response.status_code': 400 });
            span.setStatus(false, 'invalid_target');
            return oauthJson({ error: 'invalid_target', error_description: 'Resource mismatch' }, 400, cors);
          }
        }

        const grantUserId = record.userId ?? 'owner';
        let grantUserRole = normalizeRoleForUser(grantUserId, record.userRole);
        if (grantUserId !== 'owner') {
          await reconcileUpgradedFounderOwners({ store: deps.store, env: deps.githubAuthEnv });
          let liveUser = (await deps.store.getUser?.(grantUserId)) ?? null;
          if (!liveUser || liveUser.disabled || isGitHubUserDeAllowlisted(liveUser, deps.githubAuthEnv)) {
            span.setAttributes({ 'oauth.outcome': 'user_revoked', 'http.response.status_code': 400 });
            span.setStatus(false, 'user_revoked');
            return oauthJson({ error: 'invalid_grant', error_description: 'Authorized user account is disabled or no longer permitted' }, 400, cors);
          }
          if (
            liveUser.admittedVia === 'org' &&
            !isPinnedGitHubFounder(liveUser, deps.githubAuthEnv) &&
            deps.githubAuthEnv &&
            isGitHubAuthConfigured(deps.githubAuthEnv) &&
            (!liveUser.orgVerifiedAt || now - liveUser.orgVerifiedAt > GITHUB_ORG_REVERIFY_TTL_MS)
          ) {
            const initialEpoch = liveUser.sessionEpoch ?? 1;
            const orgCheck = await reverifyGitHubOrgAdmission({
              user: liveUser,
              env: deps.githubAuthEnv,
              sessionSecret: signingSecret,
              store: deps.store,
              now,
            });
            if (!orgCheck.ok) {
              span.setAttributes({ 'oauth.outcome': 'org_membership_revoked', 'http.response.status_code': 400 });
              span.setStatus(false, 'org_membership_revoked');
              return oauthJson({ error: 'invalid_grant', error_description: 'GitHub organization membership is no longer active' }, 400, cors);
            }
            liveUser = (await deps.store.getUser?.(grantUserId)) ?? null;
            if (!liveUser || liveUser.disabled || (liveUser.sessionEpoch ?? 1) !== initialEpoch) {
              span.setAttributes({ 'oauth.outcome': 'user_revoked', 'http.response.status_code': 400 });
              span.setStatus(false, 'user_revoked');
              return oauthJson({ error: 'invalid_grant', error_description: 'Authorized user account state changed during verification' }, 400, cors);
            }
          }
          grantUserRole = liveUser.role;
        }
        const grantId = `grant_${randomUrlToken(12)}`;
        const refreshRand = randomUrlToken(24);
        const refreshSig = (
          await hmacSha256Base64Url(`efr-v2:${signingSecret}`, `${grantId}.0.${record.clientId}.${refreshRand}`)
        ).slice(0, 22);
        const accessToken = `efa_${randomUrlToken(32)}`;
        const refreshToken = `efr_${grantId}.0.${refreshRand}.${refreshSig}`;
        try {
          await deps.store.putTokenPair({
            grantId,
            accessHash: await sha256Base64Url(accessToken),
            refreshHash: await sha256Base64Url(refreshToken),
            clientId: record.clientId,
            clientName: record.clientName,
            scopes: record.scopes,
            resource: record.resource,
            userId: grantUserId,
            userRole: grantUserRole,
            createdAt: now,
            accessExpiresAt: now + ACCESS_TOKEN_TTL_MS,
            refreshExpiresAt: now + REFRESH_TOKEN_TTL_MS,
          });
        } catch (err) {
          if (err instanceof OAuthQuotaExceededError) {
            span.setAttributes({ 'oauth.outcome': 'quota_exceeded', 'http.response.status_code': 429 });
            span.setStatus(false, 'user_quota_exceeded');
            return oauthJson(
              { error: 'user_quota_exceeded', error_description: err.message },
              429,
              { ...cors, 'retry-after': '2' },
            );
          }
          throw err;
        }
        await deps.onEvent?.({
          level: 'info',
          category: 'oauth',
          event: 'oauth_token_issued',
          summary: `Issued OAuth 2.1 access + refresh tokens for "${record.clientName}" (${grantId})`,
          details: { grantId, clientId: record.clientId, clientName: record.clientName, userId: grantUserId, scopes: record.scopes },
        });
        span.setAttributes({
          'oauth.client_id': record.clientId,
          'oauth.grant_id': grantId,
          'oauth.user_id': grantUserId,
          'oauth.scopes': record.scopes.join(' '),
          'oauth.outcome': 'issued',
          'http.response.status_code': 200,
        });

        return oauthJson(
          {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1_000),
            refresh_token: refreshToken,
            scope: record.scopes.join(' '),
            resource: record.resource,
          },
          200,
          cors,
        );
      });
    }

    if (grantType === 'refresh_token') {
      return withOAuthAuditSpan('refresh', async (span) => {
        span.setAttribute('oauth.grant_type', 'refresh_token');
        const refreshToken = params.refresh_token ?? '';
        const clientId = (params.client_id ?? '').trim();
        if (clientId) span.setAttribute('oauth.client_id', clientId);
        if (!refreshToken || !clientId) {
          span.setAttributes({ 'oauth.outcome': 'invalid_request', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_request');
          return oauthJson({ error: 'invalid_request', error_description: 'refresh_token and client_id are required' }, 400, cors);
        }

        // Parse & verify HMAC-authenticated lineage (`efr_<grantId>.<gen>.<rand>.<sig22>`) if present
        let claimedGrantId: string | undefined;
        let claimedGeneration: number | undefined;
        const lineageMatch = /^efr_(grant_[A-Za-z0-9_-]{8,40})\.([0-9]{1,12})\.([A-Za-z0-9_-]{16,64})\.([A-Za-z0-9_-]{22})$/.exec(
          refreshToken,
        );
        if (lineageMatch) {
          const [, parsedGrantId, parsedGenStr, parsedRand, parsedSig] = lineageMatch;
          const expectedSig = (
            await hmacSha256Base64Url(`efr-v2:${signingSecret}`, `${parsedGrantId}.${parsedGenStr}.${clientId}.${parsedRand}`)
          ).slice(0, 22);
          const parsedGen = Number(parsedGenStr);
          if (sameBytes(parsedSig!, expectedSig) && Number.isSafeInteger(parsedGen) && parsedGen >= 0) {
            claimedGrantId = parsedGrantId;
            claimedGeneration = parsedGen;
          }
        }

        const nextAccess = `efa_${randomUrlToken(32)}`;
        let nextRefresh = `efr_${randomUrlToken(32)}`;
        if (claimedGrantId !== undefined && claimedGeneration !== undefined) {
          const nextGen = claimedGeneration + 1;
          const nextRand = randomUrlToken(24);
          const nextSig = (
            await hmacSha256Base64Url(`efr-v2:${signingSecret}`, `${claimedGrantId}.${nextGen}.${clientId}.${nextRand}`)
          ).slice(0, 22);
          nextRefresh = `efr_${claimedGrantId}.${nextGen}.${nextRand}.${nextSig}`;
        }
        const rotated = await deps.store.rotateRefreshToken({
          refreshHash: await sha256Base64Url(refreshToken),
          clientId,
          nextAccessHash: await sha256Base64Url(nextAccess),
          nextRefreshHash: await sha256Base64Url(nextRefresh),
          now,
          accessExpiresAt: now + ACCESS_TOKEN_TTL_MS,
          refreshExpiresAt: now + REFRESH_TOKEN_TTL_MS,
          ...(claimedGrantId !== undefined ? { claimedGrantId, claimedGeneration } : {}),
        });
        if (!rotated.ok) {
          if (rotated.error === 'slow_down') {
            span.setAttributes({
              ...(rotated.grantId ? { 'oauth.grant_id': rotated.grantId } : {}),
              'oauth.outcome': 'rate_limited',
              'http.response.status_code': 429,
            });
            span.setStatus(false, 'slow_down');
            return oauthJson(
              { error: 'slow_down', error_description: 'Refresh rate limit exceeded for grant' },
              429,
              { ...cors, 'retry-after': String(rotated.retryAfterSec) },
            );
          }
          if (rotated.error === 'user_quota_exceeded') {
            span.setAttributes({
              ...(rotated.grantId ? { 'oauth.grant_id': rotated.grantId } : {}),
              'oauth.outcome': 'quota_exceeded',
              'http.response.status_code': 429,
            });
            span.setStatus(false, 'user_quota_exceeded');
            return oauthJson(
              { error: 'user_quota_exceeded', error_description: rotated.message },
              429,
              { ...cors, 'retry-after': '2' },
            );
          }
          if (rotated.replayDetected) {
            await deps.onEvent?.({
              level: 'warn',
              category: 'oauth',
              event: 'oauth_refresh_replay_revoked',
              summary: `Detected replay of rotated refresh token; revoked entire grant ${rotated.grantId ?? ''}`,
              details: { grantId: rotated.grantId ?? '', clientId: rotated.clientId ?? clientId },
            });
          }
          span.setAttributes({
            ...(rotated.grantId ? { 'oauth.grant_id': rotated.grantId } : {}),
            ...(rotated.replayDetected ? { 'oauth.replay_detected': true } : {}),
            'oauth.outcome': rotated.replayDetected ? 'replay_detected' : 'invalid_grant',
            'http.response.status_code': 400,
          });
          span.setStatus(false, rotated.replayDetected ? 'replay_detected' : 'invalid_grant');
          return oauthJson({ error: 'invalid_grant', error_description: 'Refresh token is invalid, expired, or revoked' }, 400, cors);
        }

        if (rotated.userId !== 'owner') {
          await reconcileUpgradedFounderOwners({ store: deps.store, env: deps.githubAuthEnv });
          const liveUser = (await deps.store.getUser?.(rotated.userId)) ?? null;
          if (!liveUser || liveUser.disabled || isGitHubUserDeAllowlisted(liveUser, deps.githubAuthEnv)) {
            await deps.store.revokeGrant(rotated.grantId);
            span.setAttributes({
              'oauth.grant_id': rotated.grantId,
              'oauth.outcome': 'user_revoked',
              'http.response.status_code': 400,
            });
            span.setStatus(false, 'user_revoked');
            return oauthJson({ error: 'invalid_grant', error_description: 'Account access has been revoked' }, 400, cors);
          }
          if (
            liveUser.admittedVia === 'org' &&
            !isPinnedGitHubFounder(liveUser, deps.githubAuthEnv) &&
            deps.githubAuthEnv &&
            isGitHubAuthConfigured(deps.githubAuthEnv)
          ) {
            const initialEpoch = liveUser.sessionEpoch ?? 1;
            const orgCheck = await reverifyGitHubOrgAdmission({
              user: liveUser,
              env: deps.githubAuthEnv,
              sessionSecret: signingSecret,
              store: deps.store,
              now,
            });
            if (!orgCheck.ok) {
              await deps.store.revokeGrant(rotated.grantId);
              span.setAttributes({
                'oauth.grant_id': rotated.grantId,
                'oauth.outcome': 'org_membership_revoked',
                'http.response.status_code': 400,
              });
              span.setStatus(false, 'org_membership_revoked');
              return oauthJson({ error: 'invalid_grant', error_description: 'GitHub organization membership is no longer active' }, 400, cors);
            }
            const afterUser = (await deps.store.getUser?.(rotated.userId)) ?? null;
            if (!afterUser || afterUser.disabled || (afterUser.sessionEpoch ?? 1) !== initialEpoch) {
              await deps.store.revokeGrant(rotated.grantId);
              span.setAttributes({
                'oauth.grant_id': rotated.grantId,
                'oauth.outcome': 'user_revoked',
                'http.response.status_code': 400,
              });
              span.setStatus(false, 'user_revoked');
              return oauthJson({ error: 'invalid_grant', error_description: 'Account state changed during verification' }, 400, cors);
            }
          }
        }

        span.setAttributes({
          'oauth.grant_id': rotated.grantId,
          'oauth.scopes': rotated.scopes.join(' '),
          'oauth.outcome': 'rotated',
          'http.response.status_code': 200,
        });
        return oauthJson(
          {
            access_token: nextAccess,
            token_type: 'Bearer',
            expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1_000),
            refresh_token: nextRefresh,
            scope: rotated.scopes.join(' '),
            resource: rotated.resource,
          },
          200,
          cors,
        );
      });
    }

    return withOAuthAuditSpan('token', async (span) => {
      span.setAttributes({
        ...(grantType ? { 'oauth.grant_type': grantType.slice(0, 64) } : {}),
        'oauth.outcome': 'unsupported_grant_type',
        'http.response.status_code': 400,
      });
      span.setStatus(false, 'unsupported_grant_type');
      return oauthJson({ error: 'unsupported_grant_type' }, 400, cors);
    });
  }

  // 6. RFC 7009 Token Revocation (`POST /oauth/revoke`)
  if (path === '/oauth/revoke') {
    return withOAuthAuditSpan('revoke', async (span) => {
      if (request.method !== 'POST') {
        span.setAttributes({ 'oauth.outcome': 'method_not_allowed', 'http.response.status_code': 405 });
        span.setStatus(false, 'method_not_allowed');
        return oauthJson({ error: 'method_not_allowed' }, 405, cors);
      }
      const params = await parseFormOrJson(request);
      if (!params) {
        span.setAttributes({ 'oauth.outcome': 'payload_too_large', 'http.response.status_code': 413 });
        span.setStatus(false, 'payload_too_large');
        return oauthJson({ error: 'invalid_request' }, 413, cors);
      }
      const hasToken = Boolean(params.token);
      if (params.token) {
        await deps.store.revokeByTokenHash(await sha256Base64Url(params.token));
      }
      span.setAttributes({
        'oauth.token_present': hasToken,
        'oauth.outcome': hasToken ? 'revoked' : 'noop',
        'http.response.status_code': 200,
      });
      return oauthJson({ ok: true }, 200, cors);
    });
  }

  return null;
}

export type McpAuthResult =
  | { ok: true; scopes: string[]; principal: string; userId: string; role: UserRole }
  | { ok: false; status: number; wwwAuthenticate: string };

/**
 * Authenticates a `/mcp` or `/v1/*` request via EITHER a direct `Bearer <MCP_TOKEN|CALLER_TOKEN>`, `x-api-key: <MCP_TOKEN>`,
 * OR a self-hosted OAuth 2.1 access token, returning canonical `userId` (`'owner'` or `'gh_<id>'`) and `role` (`'owner' | 'member'`).
 */
export async function authorizeMcpRequest(params: {
  request: Request;
  origin: string;
  ownerSecret?: string;
  mcpToken?: string;
  githubAuthEnv?: GitHubAuthEnv;
  store: OAuthStore;
  now?: number;
}): Promise<McpAuthResult> {
  const wwwAuthenticate = `Bearer resource_metadata="${params.origin}/.well-known/oauth-protected-resource", scope="${MCP_SCOPES.join(' ')}"`;
  const tok = callerToken(params.request);
  if (!tok) return { ok: false, status: 401, wwwAuthenticate };

  if (isValidSecretMatch(tok, params.ownerSecret)) {
    const res: McpAuthResult = {
      ok: true,
      scopes: [...SUPPORTED_MCP_SCOPES],
      principal: 'owner_token',
      userId: 'owner',
      role: 'owner',
    };
    setActiveCallerAuthContext(res);
    return res;
  }
  if (isValidSecretMatch(tok, params.mcpToken)) {
    const res: McpAuthResult = {
      ok: true,
      scopes: [...SUPPORTED_MCP_SCOPES],
      principal: 'mcp_token',
      userId: 'owner',
      role: 'owner',
    };
    setActiveCallerAuthContext(res);
    return res;
  }

  const record = await params.store.getAccessToken(await sha256Base64Url(tok), params.now ?? Date.now());
  if (!record || record.resource.toLowerCase() !== `${params.origin.toLowerCase()}/mcp`) {
    return { ok: false, status: 401, wwwAuthenticate };
  }
  const userId = record.userId ?? 'owner';
  let role = normalizeRoleForUser(userId, record.userRole);
  if (userId !== 'owner') {
    const effectiveGhEnv = params.githubAuthEnv ?? callerAuthAls.getStore()?.githubAuthEnv;
    const nowMs = params.now ?? Date.now();
    await reconcileUpgradedFounderOwners({ store: params.store, env: effectiveGhEnv });
    let liveUser = (await params.store.getUser?.(userId)) ?? null;
    if (!liveUser || liveUser.disabled || isGitHubUserDeAllowlisted(liveUser, effectiveGhEnv)) {
      await params.store.revokeGrant(record.grantId);
      return { ok: false, status: 401, wwwAuthenticate };
    }
    if (
      liveUser.admittedVia === 'org' &&
      !isPinnedGitHubFounder(liveUser, effectiveGhEnv) &&
      effectiveGhEnv &&
      isGitHubAuthConfigured(effectiveGhEnv) &&
      (!liveUser.orgVerifiedAt || nowMs - liveUser.orgVerifiedAt > GITHUB_ORG_REVERIFY_TTL_MS)
    ) {
      const initialEpoch = liveUser.sessionEpoch ?? 1;
      const orgCheck = await reverifyGitHubOrgAdmission({
        user: liveUser,
        env: effectiveGhEnv,
        store: params.store,
        now: nowMs,
      });
      if (!orgCheck.ok) {
        await params.store.revokeGrant(record.grantId);
        return { ok: false, status: 401, wwwAuthenticate };
      }
      liveUser = (await params.store.getUser?.(userId)) ?? null;
      if (!liveUser || liveUser.disabled || (liveUser.sessionEpoch ?? 1) !== initialEpoch) {
        await params.store.revokeGrant(record.grantId);
        return { ok: false, status: 401, wwwAuthenticate };
      }
    }
    role = liveUser.role;
  }
  const res: McpAuthResult = { ok: true, scopes: record.scopes, principal: `oauth:${record.clientId}`, userId, role };
  setActiveCallerAuthContext(res);
  return res;
}
