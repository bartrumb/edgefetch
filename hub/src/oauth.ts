/**
 * Self-hosted OAuth 2.1 + PKCE (`S256`) + Dynamic Client Registration (RFC 7591) + Protected Resource Metadata
 * (RFC 9728) + Authorization Server Metadata (RFC 8414) + HMAC-signed Admin Session cookies.
 *
 * Built with 100% Web Standard Crypto (`crypto.subtle`) and zero external npm packages or external IdP dependencies so
 * MCP clients like Claude Code (`claude mcp add --transport http <name> https://<worker>/mcp`) authenticate out of the
 * box with full consent-screen protection, PKCE S256 verification, audience (`resource`) binding, and instant grant
 * revocation in `/admin`.
 */
import { callerToken, isValidSecretMatch, MIN_TOKEN_LENGTH, sameBytes } from './auth';
import { getActiveRequestTracer, type ActiveSpanHandle } from './otel';
import { normalizeClientRateLimitIp, readBodyTextCapped, safeDecodeURIComponent } from './safe-input';

export const MCP_SCOPES = ['crawl:read', 'crawl:fetch'] as const;
export type McpScope = (typeof MCP_SCOPES)[number];

const AUTH_CODE_TTL_MS = 90_000; // 90s single-use authorization code
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1_000; // 1h access token (with 90d rotating refresh token)
const REFRESH_TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1_000; // 90d rotating refresh token
const ADMIN_SESSION_TTL_MS = 8 * 60 * 60_000; // 8h admin browser session
const RATE_LIMIT_WINDOW_MS = 5 * 60_000; // 5m brute-force window
const RATE_LIMIT_MAX_FAILURES = 5;
const REGISTER_RATE_LIMIT_MAX = 20; // Max 20 anonymous client registrations per 5m per IP (H-S1)
const MAX_AUTH_FAILURE_BUCKETS = 100; // Bounds SQLite auth_failures against spoofed IPv6 sprays (H-S5)

export const ADMIN_COOKIE_NAME = 'ef_admin_session';
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
  expiresAt: number;
}

export interface OAuthTokenRecord {
  grantId: string;
  kind: 'access' | 'refresh';
  clientId: string;
  clientName: string;
  scopes: string[];
  resource: string;
  createdAt: number;
  expiresAt: number;
}

export interface OAuthGrantSummary {
  grantId: string;
  clientId: string;
  clientName: string;
  scopes: string[];
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
}

export type RotateRefreshResult =
  | {
      ok: true;
      grantId: string;
      clientId: string;
      clientName: string;
      scopes: string[];
      resource: string;
    }
  | {
      ok: false;
      error: 'invalid_grant';
      replayDetected?: boolean;
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
    createdAt: number;
    accessExpiresAt: number;
    refreshExpiresAt: number;
  }): Promise<void> | void;
  getAccessToken(tokenHash: string, now: number): Promise<OAuthTokenRecord | null> | OAuthTokenRecord | null;
  consumeRefreshToken(tokenHash: string, now: number): Promise<OAuthTokenRecord | null> | OAuthTokenRecord | null;
  rotateRefreshToken(params: RotateRefreshParams): Promise<RotateRefreshResult> | RotateRefreshResult;
  listGrants(now: number): Promise<OAuthGrantSummary[]> | OAuthGrantSummary[];
  revokeGrant(grantId: string): Promise<boolean> | boolean;
  revokeByTokenHash(tokenHash: string): Promise<void> | void;
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
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
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

/** SQLite-backed `OAuthStore` living inside `AgentHubDO` (requires zero separate KV namespaces). */
export function createSqliteOAuthStore(sql: SqlStorageLike): OAuthStore {
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
      sql.exec('DELETE FROM oauth_codes WHERE expires_at <= ?', code.expiresAt - AUTH_CODE_TTL_MS);
      sql.exec(
        `DELETE FROM oauth_codes
         WHERE code_hash IN (
           SELECT code_hash FROM oauth_codes ORDER BY expires_at DESC LIMIT -1 OFFSET 2047
         )`,
      );
      sql.exec(
        `INSERT OR REPLACE INTO oauth_codes
         (code_hash, client_id, client_name, redirect_uri, code_challenge, scopes_json, resource, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        code.codeHash,
        code.clientId,
        code.clientName,
        code.redirectUri,
        code.codeChallenge,
        JSON.stringify(code.scopes),
        code.resource,
        code.expiresAt,
      );
    },
    consumeCode(codeHash, now) {
      const rows = sql
        .exec<{
          code_hash: string;
          client_id: string;
          client_name: string;
          redirect_uri: string;
          code_challenge: string;
          scopes_json: string;
          resource: string;
          expires_at: number;
        }>('SELECT * FROM oauth_codes WHERE code_hash = ?', codeHash)
        .toArray();
      sql.exec('DELETE FROM oauth_codes WHERE code_hash = ? OR expires_at <= ?', codeHash, now);
      const r = rows[0];
      if (!r || r.expires_at <= now) return null;
      return {
        codeHash: r.code_hash,
        clientId: r.client_id,
        clientName: r.client_name,
        redirectUri: r.redirect_uri,
        codeChallenge: r.code_challenge,
        scopes: JSON.parse(r.scopes_json) as string[],
        resource: r.resource,
        expiresAt: r.expires_at,
      };
    },
    putTokenPair(p) {
      sql.exec('DELETE FROM oauth_tokens WHERE expires_at <= ?', p.createdAt);
      sql.exec(
        `DELETE FROM oauth_tokens
         WHERE token_hash IN (
           SELECT token_hash FROM oauth_tokens ORDER BY expires_at DESC LIMIT -1 OFFSET 4093
         )`,
      );
      const scopesJson = JSON.stringify(p.scopes);
      sql.exec(
        `INSERT OR REPLACE INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, created_at, expires_at)
         VALUES (?, ?, 'access', ?, ?, ?, ?, ?, ?)`,
        p.accessHash,
        p.grantId,
        p.clientId,
        p.clientName,
        scopesJson,
        p.resource,
        p.createdAt,
        p.accessExpiresAt,
      );
      sql.exec(
        `INSERT OR REPLACE INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, created_at, expires_at)
         VALUES (?, ?, 'refresh', ?, ?, ?, ?, ?, ?)`,
        p.refreshHash,
        p.grantId,
        p.clientId,
        p.clientName,
        scopesJson,
        p.resource,
        p.createdAt,
        p.refreshExpiresAt,
      );
    },
    getAccessToken(tokenHash, now) {
      const rows = sql
        .exec<{
          grant_id: string;
          kind: string;
          client_id: string;
          client_name: string;
          scopes_json: string;
          resource: string;
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
      return {
        grantId: r.grant_id,
        kind: 'access',
        clientId: r.client_id,
        clientName: r.client_name,
        scopes: JSON.parse(r.scopes_json) as string[],
        resource: r.resource,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
      };
    },
    consumeRefreshToken(tokenHash, now) {
      const rows = sql
        .exec<{
          grant_id: string;
          kind: string;
          client_id: string;
          client_name: string;
          scopes_json: string;
          resource: string;
          created_at: number;
          expires_at: number;
        }>("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'", tokenHash)
        .toArray();
      const r = rows[0];
      if (!r) return null;
      // Rotate both previous access & refresh tokens under this grant before minting the fresh pair.
      sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', r.grant_id);
      if (r.expires_at <= now) return null;
      return {
        grantId: r.grant_id,
        kind: 'refresh',
        clientId: r.client_id,
        clientName: r.client_name,
        scopes: JSON.parse(r.scopes_json) as string[],
        resource: r.resource,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
      };
    },
    rotateRefreshToken(params) {
      const rows = sql
        .exec<{
          grant_id: string;
          kind: string;
          client_id: string;
          client_name: string;
          scopes_json: string;
          resource: string;
          created_at: number;
          expires_at: number;
        }>("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind IN ('refresh', 'refresh_used')", params.refreshHash)
        .toArray();
      const r = rows[0];
      if (!r) return { ok: false, error: 'invalid_grant' };
      if (r.expires_at <= params.now) {
        sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', r.grant_id);
        return { ok: false, error: 'invalid_grant' };
      }
      // Replay of an already-rotated refresh token immediately revokes the ENTIRE grant (H-S3)!
      if (r.kind === 'refresh_used') {
        sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', r.grant_id);
        return {
          ok: false,
          error: 'invalid_grant',
          replayDetected: true,
          grantId: r.grant_id,
          clientId: r.client_id,
        };
      }
      // Verify client_id BEFORE mutating the grant so a wrong client_id cannot burn a valid grant (H-S3)!
      if (!params.clientId || r.client_id !== params.clientId) {
        return { ok: false, error: 'invalid_grant' };
      }

      sql.exec('DELETE FROM oauth_tokens WHERE expires_at <= ?', params.now);
      sql.exec("DELETE FROM oauth_tokens WHERE grant_id = ? AND kind = 'access'", r.grant_id);
      sql.exec(
        "UPDATE oauth_tokens SET kind = 'refresh_used', expires_at = ? WHERE token_hash = ?",
        Math.max(r.expires_at, params.refreshExpiresAt),
        params.refreshHash,
      );
      sql.exec(
        `INSERT OR REPLACE INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, created_at, expires_at)
         VALUES (?, ?, 'access', ?, ?, ?, ?, ?, ?)`,
        params.nextAccessHash,
        r.grant_id,
        r.client_id,
        r.client_name,
        r.scopes_json,
        r.resource,
        r.created_at,
        params.accessExpiresAt,
      );
      sql.exec(
        `INSERT OR REPLACE INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, created_at, expires_at)
         VALUES (?, ?, 'refresh', ?, ?, ?, ?, ?, ?)`,
        params.nextRefreshHash,
        r.grant_id,
        r.client_id,
        r.client_name,
        r.scopes_json,
        r.resource,
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
      };
    },
    listGrants(now) {
      sql.exec('DELETE FROM oauth_tokens WHERE expires_at <= ?', now);
      const rows = sql
        .exec<{
          grant_id: string;
          client_id: string;
          client_name: string;
          scopes_json: string;
          created_at: number;
          max_exp: number;
        }>(
          `SELECT grant_id, client_id, client_name, scopes_json, MIN(created_at) AS created_at, MAX(expires_at) AS max_exp
           FROM oauth_tokens
           WHERE kind IN ('access', 'refresh')
           GROUP BY grant_id
           ORDER BY created_at DESC`,
        )
        .toArray();
      return rows.map((r) => ({
        grantId: r.grant_id,
        clientId: r.client_id,
        clientName: r.client_name,
        scopes: JSON.parse(r.scopes_json) as string[],
        createdAt: r.created_at,
        expiresAt: r.max_exp,
      }));
    },
    revokeGrant(grantId) {
      const existing = sql
        .exec<{ c: number }>('SELECT COUNT(*) AS c FROM oauth_tokens WHERE grant_id = ?', grantId)
        .toArray()[0];
      sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', grantId);
      return Boolean(existing && existing.c > 0);
    },
    revokeByTokenHash(tokenHash) {
      const row = sql
        .exec<{ grant_id: string }>('SELECT grant_id FROM oauth_tokens WHERE token_hash = ?', tokenHash)
        .toArray()[0];
      if (row?.grant_id) {
        sql.exec('DELETE FROM oauth_tokens WHERE grant_id = ?', row.grant_id);
      }
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
  const tokens = new Map<string, OAuthTokenRecord & { used?: boolean }>();
  const failures = new Map<string, { count: number; resetAt: number }>();
  const adminRevocations = new Map<string, number>();

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
      while (codes.size >= 2048) {
        const oldest = codes.keys().next().value;
        if (oldest === undefined) break;
        codes.delete(oldest);
      }
      codes.set(code.codeHash, { ...code, scopes: [...code.scopes] });
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
      while (tokens.size >= 4094) {
        const oldest = tokens.keys().next().value;
        if (oldest === undefined) break;
        tokens.delete(oldest);
      }
      tokens.set(p.accessHash, {
        grantId: p.grantId,
        kind: 'access',
        clientId: p.clientId,
        clientName: p.clientName,
        scopes: [...p.scopes],
        resource: p.resource,
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
      if (!t || t.kind !== 'refresh') return { ok: false, error: 'invalid_grant' };
      if (t.expiresAt <= params.now) {
        for (const [h, row] of tokens.entries()) if (row.grantId === t.grantId) tokens.delete(h);
        return { ok: false, error: 'invalid_grant' };
      }
      if (t.used) {
        for (const [h, row] of tokens.entries()) if (row.grantId === t.grantId) tokens.delete(h);
        return { ok: false, error: 'invalid_grant', replayDetected: true, grantId: t.grantId, clientId: t.clientId };
      }
      if (!params.clientId || t.clientId !== params.clientId) {
        return { ok: false, error: 'invalid_grant' };
      }
      for (const [h, row] of tokens.entries()) {
        if (row.grantId === t.grantId && row.kind === 'access') tokens.delete(h);
      }
      t.used = true;
      t.expiresAt = Math.max(t.expiresAt, params.refreshExpiresAt);
      tokens.set(params.nextAccessHash, {
        grantId: t.grantId,
        kind: 'access',
        clientId: t.clientId,
        clientName: t.clientName,
        scopes: [...t.scopes],
        resource: t.resource,
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
      };
    },
    listGrants(now) {
      const byGrant = new Map<string, OAuthGrantSummary>();
      for (const [hash, t] of tokens.entries()) {
        if (t.expiresAt <= now) {
          tokens.delete(hash);
          continue;
        }
        if (t.used) continue;
        const prev = byGrant.get(t.grantId);
        if (!prev || t.expiresAt > prev.expiresAt) {
          byGrant.set(t.grantId, {
            grantId: t.grantId,
            clientId: t.clientId,
            clientName: t.clientName,
            scopes: [...t.scopes],
            createdAt: t.createdAt,
            expiresAt: t.expiresAt,
          });
        }
      }
      return [...byGrant.values()].sort((a, b) => b.createdAt - a.createdAt);
    },
    revokeGrant(grantId) {
      let removed = false;
      for (const [hash, t] of tokens.entries()) {
        if (t.grantId === grantId) {
          tokens.delete(hash);
          removed = true;
        }
      }
      return removed;
    },
    revokeByTokenHash(tokenHash) {
      const t = tokens.get(tokenHash);
      if (!t) return;
      for (const [hash, row] of tokens.entries()) {
        if (row.grantId === t.grantId) tokens.delete(hash);
      }
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
): Promise<boolean> {
  if (!store || typeof store.checkAuthLockout !== 'function') return false;
  const csrfHash = await sha256Base64Url(csrf);
  const hashedCheck = await store.checkAuthLockout(`revoked_admin:${csrfHash}`, now, 1);
  if (!hashedCheck.allowed) return true;
  const legacyCheck = await store.checkAuthLockout(`revoked_admin:${csrf}`, now, 1);
  return !legacyCheck.allowed;
}

export function isSameOriginFormPost(request: Request, url: URL, publicOrigin?: string): boolean {
  const secFetchSite = (request.headers.get('sec-fetch-site') ?? '').trim().toLowerCase();
  if (secFetchSite === 'cross-site') return false;
  const rawOrigin = request.headers.get('origin');
  if (!rawOrigin || !rawOrigin.trim()) return true;
  if (rawOrigin.trim().toLowerCase() === 'null') return false;
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

export async function verifyAdminSessionCookie(
  cookieHeader: string | null,
  secret: string | undefined,
  now = Date.now(),
): Promise<{ ok: true; csrf: string; expiresAt: number } | { ok: false }> {
  if (!secret || secret.length < MIN_TOKEN_LENGTH) return { ok: false };
  const raw = readCookie(cookieHeader, ADMIN_COOKIE_NAME);
  if (!raw) return { ok: false };
  const parts = raw.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') return { ok: false };
  const expiresAt = Number(parts[1]);
  const csrf = parts[2] ?? '';
  const sig = parts[3] ?? '';
  if (!Number.isFinite(expiresAt) || expiresAt <= now || csrf.length < 16 || sig.length < 16) {
    return { ok: false };
  }
  const expected = await hmacSha256Base64Url(`admin-cookie:${secret}`, `v1.${expiresAt}.${csrf}`);
  if (!sameBytes(sig, expected)) return { ok: false };
  return { ok: true, csrf, expiresAt };
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
  const invalid = tokens.filter((s) => !(MCP_SCOPES as readonly string[]).includes(s));
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
          s === 'crawl:fetch' ? 'Trigger polite HTTPS fetches across container &amp; standby sites' : 'Inspect connected standby sites &amp; affinity pins'
        }</li>`,
    )
    .join('');

  const authField = params.alreadySignedIn
    ? `<p class="ok-banner">Authenticated via active Admin Portal session.</p>`
    : `<label for="owner_token">EdgeFetch Token (<code>MCP_TOKEN</code> or <code>CRAWLER_TOKEN</code>)</label>
       <input id="owner_token" name="owner_token" type="password" required autocomplete="current-password" placeholder="Paste your MCP_TOKEN to authorize">`;

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
    .ok-banner { background: #052e16; border: 1px solid #16a34a; color: #bbf7d0; padding: 8px 12px; border-radius: 8px; font-size: 0.88rem; }
    .actions { display: flex; gap: 10px; margin-top: 20px; }
    button { font: inherit; font-weight: 600; padding: 10px 18px; border-radius: 8px; border: 1px solid #475569; background: #334155; color: #f8fafc; cursor: pointer; }
    button.approve { background: #2563eb; border-color: #3b82f6; color: #fff; flex: 1; }
    button.approve:hover { background: #1d4ed8; }
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
        <button class="approve" type="submit" name="decision" value="approve">Approve MCP Access</button>
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
        scopes_supported: [...MCP_SCOPES],
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
        scopes_supported: [...MCP_SCOPES],
      },
      200,
      cors,
    );
  }

  const ownerSecret = deps.ownerSecret;
  if (!ownerSecret || ownerSecret.length < MIN_TOKEN_LENGTH) {
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
      let adminSession = await verifyAdminSessionCookie(request.headers.get('cookie'), ownerSecret, now);
      if (adminSession.ok && (await isAdminSessionRevoked(deps.store, adminSession.csrf, now))) {
        adminSession = { ok: false };
      }

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
        const sealedState = await sealConsent(ownerSecret, {
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
            // Non-loopback external redirects ALWAYS require explicit CALLER_TOKEN entry even if signed into /admin (H-S2).
            alreadySignedIn: adminSession.ok && !isExternalRedirect,
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
        const sealed = await unsealConsent(ownerSecret, form.sealed ?? '', now);
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
        if (!adminSession.ok || isExternalRedirect) {
          const supplied = (form.owner_token ?? '').trim();
          // Verify constant-time secret match FIRST (`R3-M4`): a valid owner/MCP token succeeds and clears any spoofed/shared-IP
          // lockout bucket, while invalid guesses are rejected with `429` once the bucket reaches `RATE_LIMIT_MAX_FAILURES`!
          if (isValidSecretMatch(supplied, deps.ownerSecret, deps.mcpToken)) {
            await deps.store.clearAuthFailures(`oauth:${clientIp}`);
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
                errorMessage: 'Invalid token. Paste your MCP_TOKEN or CRAWLER_TOKEN.',
              }),
              { status: 401, headers: CONSENT_PAGE_HEADERS },
            );
          }
        }

        const rawCode = `efc_${randomUrlToken(32)}`;
        const codeHash = await sha256Base64Url(rawCode);
        await deps.store.putCode({
          codeHash,
          clientId: sealed.clientId,
          clientName: sealed.clientName,
          redirectUri: sealed.redirectUri,
          codeChallenge: sealed.codeChallenge,
          scopes: sealed.scopes,
          resource: sealed.resource,
          expiresAt: now + AUTH_CODE_TTL_MS,
        });

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

        const accessToken = `efa_${randomUrlToken(32)}`;
        const refreshToken = `efr_${randomUrlToken(32)}`;
        const grantId = `grant_${randomUrlToken(12)}`;
        await deps.store.putTokenPair({
          grantId,
          accessHash: await sha256Base64Url(accessToken),
          refreshHash: await sha256Base64Url(refreshToken),
          clientId: record.clientId,
          clientName: record.clientName,
          scopes: record.scopes,
          resource: record.resource,
          createdAt: now,
          accessExpiresAt: now + ACCESS_TOKEN_TTL_MS,
          refreshExpiresAt: now + REFRESH_TOKEN_TTL_MS,
        });
        await deps.onEvent?.({
          level: 'info',
          category: 'oauth',
          event: 'oauth_token_issued',
          summary: `Issued OAuth 2.1 access + refresh tokens for "${record.clientName}" (${grantId})`,
          details: { grantId, clientId: record.clientId, clientName: record.clientName, scopes: record.scopes },
        });
        span.setAttributes({
          'oauth.client_id': record.clientId,
          'oauth.grant_id': grantId,
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

        const nextAccess = `efa_${randomUrlToken(32)}`;
        const nextRefresh = `efr_${randomUrlToken(32)}`;
        const rotated = await deps.store.rotateRefreshToken({
          refreshHash: await sha256Base64Url(refreshToken),
          clientId,
          nextAccessHash: await sha256Base64Url(nextAccess),
          nextRefreshHash: await sha256Base64Url(nextRefresh),
          now,
          accessExpiresAt: now + ACCESS_TOKEN_TTL_MS,
          refreshExpiresAt: now + REFRESH_TOKEN_TTL_MS,
        });
        if (!rotated.ok) {
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

/**
 * Authenticates a `/mcp` request via EITHER a direct `Bearer <MCP_TOKEN|CRAWLER_TOKEN>`, `x-api-key: <MCP_TOKEN>`,
 * OR a self-hosted OAuth 2.1 access token, returning RFC 9728 `WWW-Authenticate` on `401`.
 */
export async function authorizeMcpRequest(params: {
  request: Request;
  origin: string;
  ownerSecret?: string;
  mcpToken?: string;
  store: OAuthStore;
  now?: number;
}): Promise<
  | { ok: true; scopes: string[]; principal: string }
  | { ok: false; status: number; wwwAuthenticate: string }
> {
  const wwwAuthenticate = `Bearer resource_metadata="${params.origin}/.well-known/oauth-protected-resource", scope="${MCP_SCOPES.join(' ')}"`;
  const tok = callerToken(params.request);
  if (!tok) return { ok: false, status: 401, wwwAuthenticate };

  if (isValidSecretMatch(tok, params.ownerSecret)) {
    return { ok: true, scopes: [...MCP_SCOPES], principal: 'owner_token' };
  }
  if (isValidSecretMatch(tok, params.mcpToken)) {
    return { ok: true, scopes: [...MCP_SCOPES], principal: 'mcp_token' };
  }

  const record = await params.store.getAccessToken(await sha256Base64Url(tok), params.now ?? Date.now());
  if (!record || record.resource.toLowerCase() !== `${params.origin.toLowerCase()}/mcp`) {
    return { ok: false, status: 401, wwwAuthenticate };
  }
  return { ok: true, scopes: record.scopes, principal: `oauth:${record.clientId}` };
}
