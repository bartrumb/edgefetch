/**
 * Self-hosted OAuth 2.1 + PKCE (`S256`) + Dynamic Client Registration (RFC 7591) + Protected Resource Metadata
 * (RFC 9728) + Authorization Server Metadata (RFC 8414) + HMAC-signed Admin Session cookies.
 *
 * Built with 100% Web Standard Crypto (`crypto.subtle`) and zero external npm packages or external IdP dependencies so
 * MCP clients like Claude Code (`claude mcp add --transport http <name> https://<worker>/mcp`) authenticate out of the
 * box with full consent-screen protection, PKCE S256 verification, audience (`resource`) binding, and instant grant
 * revocation in `/admin`.
 */
import { MIN_TOKEN_LENGTH, sameBytes } from './auth';

export const MCP_SCOPES = ['crawl:read', 'crawl:fetch'] as const;
export type McpScope = (typeof MCP_SCOPES)[number];

const AUTH_CODE_TTL_MS = 90_000; // 90s single-use authorization code
const ACCESS_TOKEN_TTL_MS = 60 * 60_000; // 1h access token
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60_000; // 30d rotating refresh token
const ADMIN_SESSION_TTL_MS = 8 * 60 * 60_000; // 8h admin browser session
const RATE_LIMIT_WINDOW_MS = 5 * 60_000; // 5m brute-force window
const RATE_LIMIT_MAX_FAILURES = 5;

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
  listGrants(now: number): Promise<OAuthGrantSummary[]> | OAuthGrantSummary[];
  revokeGrant(grantId: string): Promise<boolean> | boolean;
  revokeByTokenHash(tokenHash: string): Promise<void> | void;
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
`;

/** SQLite-backed `OAuthStore` living inside `AgentHubDO` (requires zero separate KV namespaces). */
export function createSqliteOAuthStore(sql: SqlStorageLike): OAuthStore {
  return {
    putClient(c) {
      sql.exec(
        'DELETE FROM oauth_clients WHERE client_id IN (SELECT client_id FROM oauth_clients ORDER BY created_at DESC LIMIT -1 OFFSET 499)',
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
    recordAuthFailure(bucket, now, windowMs, maxFailures) {
      const row = sql
        .exec<{ count: number; reset_at: number }>('SELECT count, reset_at FROM auth_failures WHERE bucket = ?', bucket)
        .toArray()[0];
      if (!row || row.reset_at <= now) {
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
      sql.exec('DELETE FROM auth_failures WHERE bucket = ?', bucket);
    },
  };
}

export function createMemoryOAuthStore(): OAuthStore {
  const clients = new Map<string, OAuthClientRecord>();
  const codes = new Map<string, OAuthCodeRecord>();
  const tokens = new Map<string, OAuthTokenRecord>();
  const failures = new Map<string, { count: number; resetAt: number }>();

  return {
    putClient(c) {
      if (clients.size >= 500) {
        const oldest = clients.keys().next().value;
        if (oldest) clients.delete(oldest);
      }
      clients.set(c.clientId, { ...c, redirectUris: [...c.redirectUris] });
    },
    getClient(clientId) {
      const c = clients.get(clientId);
      return c ? { ...c, redirectUris: [...c.redirectUris] } : null;
    },
    putCode(code) {
      codes.set(code.codeHash, { ...code, scopes: [...code.scopes] });
    },
    consumeCode(codeHash, now) {
      const c = codes.get(codeHash);
      codes.delete(codeHash);
      if (!c || c.expiresAt <= now) return null;
      return c;
    },
    putTokenPair(p) {
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
      if (!t || t.kind !== 'refresh') return null;
      tokens.delete(tokenHash);
      if (t.expiresAt <= now) return null;
      return { ...t, scopes: [...t.scopes] };
    },
    listGrants(now) {
      const byGrant = new Map<string, OAuthGrantSummary>();
      for (const [hash, t] of tokens.entries()) {
        if (t.expiresAt <= now) {
          tokens.delete(hash);
          continue;
        }
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
    recordAuthFailure(bucket, now, windowMs, maxFailures) {
      const cur = failures.get(bucket);
      if (!cur || cur.resetAt <= now) {
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
      return trimmed.slice(name.length + 1);
    }
  }
  return null;
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

/**
 * Validates OAuth 2.1 redirect URIs for Dynamic Client Registration (RFC 7591 + RFC 8252):
 *  - Loopback native CLI callbacks (`http://localhost(:port)/...` or `http://127.0.0.1(:port)/...`), OR
 *  - External `https://` callbacks (never our own hub origin, no `#fragment`, no embedded userinfo).
 */
export function isValidRedirectUri(raw: string, selfOrigin: string): boolean {
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
    return u.origin.toLowerCase() !== selfOrigin.toLowerCase();
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

export function normalizeScopes(rawScope: string | null | undefined): string[] {
  if (!rawScope || !rawScope.trim()) return [...MCP_SCOPES];
  const requested = rawScope
    .split(/\s+/)
    .map((s) => s.trim())
    .filter((s): s is McpScope => (MCP_SCOPES as readonly string[]).includes(s));
  return requested.length > 0 ? [...new Set(requested)] : [...MCP_SCOPES];
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

export function oauthCorsHeaders(request: Request, selfOrigin: string): Record<string, string> {
  const reqOrigin = request.headers.get('origin');
  if (!reqOrigin) return {};
  try {
    const u = new URL(reqOrigin);
    const host = u.hostname.toLowerCase();
    const selfHost = new URL(selfOrigin).hostname.toLowerCase();
    if (isLoopbackHost(host) || host === 'claude.ai' || host.endsWith('.claude.ai') || host === selfHost) {
      return {
        'access-control-allow-origin': u.origin,
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'authorization, content-type, accept, mcp-protocol-version',
        vary: 'Origin',
      };
    }
  } catch {
    // ignore invalid Origin
  }
  return {};
}

function oauthJson(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      pragma: 'no-cache',
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
    : `<label for="owner_token">Owner Token (<code>CALLER_TOKEN</code>)</label>
       <input id="owner_token" name="owner_token" type="password" required autocomplete="current-password" placeholder="Paste your hub caller token to authorize">`;

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
    <h1>Connect &ldquo;${escapeHtml(params.clientName)}&rdquo; to ${escapeHtml(params.serviceName)}?</h1>
    ${errHtml}
    <p>An MCP client is requesting scoped OAuth 2.1 access. Verify the callback destination before approving:</p>
    <div class="meta">
      <div><strong>Callback Host:</strong> <code>${escapeHtml(redirectHost)}</code></div>
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

async function parseFormOrJson(request: Request): Promise<Record<string, string>> {
  const ct = (request.headers.get('content-type') ?? '').toLowerCase();
  if (ct.includes('application/json')) {
    const raw = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw ?? {})) {
      if (typeof v === 'string') out[k] = v;
    }
    return out;
  }
  const text = await request.text();
  const params = new URLSearchParams(text);
  const out: Record<string, string> = {};
  for (const [k, v] of params.entries()) out[k] = v;
  return out;
}

export interface OAuthHandlerDeps {
  store: OAuthStore;
  ownerSecret?: string;
  serviceName: string;
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
  const cors = oauthCorsHeaders(request, origin);
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
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['none'],
        code_challenge_methods_supported: ['S256'],
        scopes_supported: [...MCP_SCOPES],
      },
      200,
      cors,
    );
  }

  if (!deps.ownerSecret || deps.ownerSecret.length < MIN_TOKEN_LENGTH) {
    return oauthJson({ error: 'server_error', error_description: 'Owner token secret is not configured on hub' }, 503, cors);
  }

  // 3. RFC 7591 Dynamic Client Registration (`POST /oauth/register`)
  if (path === '/oauth/register') {
    if (request.method !== 'POST') return oauthJson({ error: 'method_not_allowed' }, 405, cors);
    const bodyText = await request.text();
    if (bodyText.length > 16_384) return oauthJson({ error: 'invalid_client_metadata' }, 400, cors);
    let body: { client_name?: unknown; redirect_uris?: unknown };
    try {
      body = JSON.parse(bodyText) as { client_name?: unknown; redirect_uris?: unknown };
    } catch {
      return oauthJson({ error: 'invalid_client_metadata', error_description: 'Invalid JSON' }, 400, cors);
    }
    if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0 || body.redirect_uris.length > 10) {
      return oauthJson({ error: 'invalid_redirect_uri', error_description: 'redirect_uris must be a 1-10 item array' }, 400, cors);
    }
    const redirectUris: string[] = [];
    for (const u of body.redirect_uris) {
      if (typeof u !== 'string' || !isValidRedirectUri(u, origin)) {
        return oauthJson(
          { error: 'invalid_redirect_uri', error_description: 'Only loopback http:// or external https:// redirect URIs are allowed' },
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
    const clientId = `mcp_${randomUrlToken(18)}`;
    await deps.store.putClient({ clientId, clientName, redirectUris, createdAt: now });
    await deps.onEvent?.({
      level: 'info',
      category: 'oauth',
      event: 'oauth_client_registered',
      summary: `Registered OAuth 2.1 client "${clientName}" (${clientId})`,
      details: { clientId, clientName, redirectUris },
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
      },
      201,
      cors,
    );
  }

  // 4. OAuth 2.1 Authorization & Consent (`GET` & `POST /oauth/authorize`)
  if (path === '/oauth/authorize') {
    const isSecure = url.protocol === 'https:';
    const adminSession = await verifyAdminSessionCookie(request.headers.get('cookie'), deps.ownerSecret, now);

    if (request.method === 'GET') {
      const clientId = (url.searchParams.get('client_id') ?? '').trim();
      const redirectUri = (url.searchParams.get('redirect_uri') ?? '').trim();
      const responseType = (url.searchParams.get('response_type') ?? '').trim();
      const state = url.searchParams.get('state') ?? '';
      const codeChallenge = (url.searchParams.get('code_challenge') ?? '').trim();
      const codeChallengeMethod = (url.searchParams.get('code_challenge_method') ?? '').trim();
      const scopes = normalizeScopes(url.searchParams.get('scope'));
      const resCheck = normalizeResource(url.searchParams.get('resource'), origin);

      const client = clientId ? await deps.store.getClient(clientId) : null;
      if (!client) {
        return new Response('Unknown client_id. Register via POST /oauth/register first.', { status: 400, headers: CONSENT_PAGE_HEADERS });
      }
      if (!redirectUri || !matchesRegisteredRedirectUri(redirectUri, client.redirectUris)) {
        return new Response('Unregistered redirect_uri for this client_id.', { status: 400, headers: CONSENT_PAGE_HEADERS });
      }
      if (responseType !== 'code') {
        const errUrl = new URL(redirectUri);
        errUrl.searchParams.set('error', 'unsupported_response_type');
        if (state) errUrl.searchParams.set('state', state);
        return Response.redirect(errUrl.toString(), 302);
      }
      if (codeChallengeMethod !== 'S256' || !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) {
        const errUrl = new URL(redirectUri);
        errUrl.searchParams.set('error', 'invalid_request');
        errUrl.searchParams.set('error_description', 'PKCE code_challenge with S256 is required');
        if (state) errUrl.searchParams.set('state', state);
        return Response.redirect(errUrl.toString(), 302);
      }
      if (!resCheck.ok) {
        const errUrl = new URL(redirectUri);
        errUrl.searchParams.set('error', 'invalid_target');
        if (state) errUrl.searchParams.set('state', state);
        return Response.redirect(errUrl.toString(), 302);
      }

      const csrf = randomUrlToken(24);
      const sealedState = await sealConsent(deps.ownerSecret, {
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
      return new Response(
        renderAuthorizePage({
          serviceName: deps.serviceName,
          clientName: client.clientName,
          redirectUri,
          scopes,
          sealedState,
          csrf,
          alreadySignedIn: adminSession.ok,
        }),
        { status: 200, headers },
      );
    }

    if (request.method === 'POST') {
      const form = await parseFormOrJson(request);
      const sealed = await unsealConsent(deps.ownerSecret, form.sealed ?? '', now);
      const cookieCsrf = readCookie(request.headers.get('cookie'), CONSENT_CSRF_COOKIE) ?? '';
      if (!sealed || !cookieCsrf || !sameBytes(cookieCsrf, sealed.csrf) || !sameBytes(form.csrf ?? '', sealed.csrf)) {
        return new Response('Authorization session expired or invalid CSRF token. Please retry from your MCP client.', {
          status: 400,
          headers: CONSENT_PAGE_HEADERS,
        });
      }

      if (form.decision !== 'approve') {
        const denyUrl = new URL(sealed.redirectUri);
        denyUrl.searchParams.set('error', 'access_denied');
        if (sealed.state) denyUrl.searchParams.set('state', sealed.state);
        return Response.redirect(denyUrl.toString(), 302);
      }

      const clientIp = request.headers.get('cf-connecting-ip') ?? 'local';
      if (!adminSession.ok) {
        const supplied = (form.owner_token ?? '').trim();
        if (!supplied || !sameBytes(supplied, deps.ownerSecret)) {
          const rl = await deps.store.recordAuthFailure(`oauth:${clientIp}`, now, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_FAILURES);
          if (!rl.allowed) {
            return new Response('Too many failed authorization attempts. Please wait 5 minutes.', {
              status: 429,
              headers: { ...CONSENT_PAGE_HEADERS, 'retry-after': String(rl.retryAfterSec) },
            });
          }
          return new Response(
            renderAuthorizePage({
              serviceName: deps.serviceName,
              clientName: sealed.clientName,
              redirectUri: sealed.redirectUri,
              scopes: sealed.scopes,
              sealedState: form.sealed ?? '',
              csrf: sealed.csrf,
              alreadySignedIn: false,
              errorMessage: 'Invalid owner token. Paste your CALLER_TOKEN.',
            }),
            { status: 401, headers: CONSENT_PAGE_HEADERS },
          );
        }
        await deps.store.clearAuthFailures(`oauth:${clientIp}`);
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

      const headers = new Headers({ location: cb.toString(), 'cache-control': 'no-store' });
      headers.append('set-cookie', formatCookie(CONSENT_CSRF_COOKIE, '', { maxAge: 0, path: '/oauth/authorize', sameSite: 'Lax', secure: isSecure }));
      return new Response(null, { status: 302, headers });
    }

    return oauthJson({ error: 'method_not_allowed' }, 405, cors);
  }

  // 5. OAuth 2.1 Token Endpoint (`POST /oauth/token`)
  if (path === '/oauth/token') {
    if (request.method !== 'POST') return oauthJson({ error: 'method_not_allowed' }, 405, cors);
    const params = await parseFormOrJson(request);
    const grantType = params.grant_type ?? '';

    if (grantType === 'authorization_code') {
      const code = params.code ?? '';
      const verifier = params.code_verifier ?? '';
      const clientId = params.client_id ?? '';
      const redirectUri = params.redirect_uri ?? '';
      if (!code || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
        return oauthJson({ error: 'invalid_request', error_description: 'Missing code or valid PKCE code_verifier' }, 400, cors);
      }

      const codeHash = await sha256Base64Url(code);
      const record = await deps.store.consumeCode(codeHash, now);
      if (!record) {
        return oauthJson({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or already used' }, 400, cors);
      }
      if ((clientId && clientId !== record.clientId) || (redirectUri && redirectUri !== record.redirectUri)) {
        return oauthJson({ error: 'invalid_grant', error_description: 'client_id or redirect_uri mismatch' }, 400, cors);
      }
      const computedChallenge = await sha256Base64Url(verifier);
      if (!sameBytes(computedChallenge, record.codeChallenge)) {
        return oauthJson({ error: 'invalid_grant', error_description: 'PKCE S256 verification failed' }, 400, cors);
      }
      if (params.resource) {
        const resCheck = normalizeResource(params.resource, origin);
        if (!resCheck.ok || resCheck.resource !== record.resource) {
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

      return oauthJson(
        {
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1_000),
          refresh_token: refreshToken,
          scope: record.scopes.join(' '),
        },
        200,
        cors,
      );
    }

    if (grantType === 'refresh_token') {
      const refreshToken = params.refresh_token ?? '';
      if (!refreshToken) return oauthJson({ error: 'invalid_request' }, 400, cors);
      const prev = await deps.store.consumeRefreshToken(await sha256Base64Url(refreshToken), now);
      if (!prev) {
        return oauthJson({ error: 'invalid_grant', error_description: 'Refresh token is invalid, expired, or revoked' }, 400, cors);
      }
      if (params.client_id && params.client_id !== prev.clientId) {
        return oauthJson({ error: 'invalid_grant' }, 400, cors);
      }

      const nextAccess = `efa_${randomUrlToken(32)}`;
      const nextRefresh = `efr_${randomUrlToken(32)}`;
      await deps.store.putTokenPair({
        grantId: prev.grantId,
        accessHash: await sha256Base64Url(nextAccess),
        refreshHash: await sha256Base64Url(nextRefresh),
        clientId: prev.clientId,
        clientName: prev.clientName,
        scopes: prev.scopes,
        resource: prev.resource,
        createdAt: prev.createdAt,
        accessExpiresAt: now + ACCESS_TOKEN_TTL_MS,
        refreshExpiresAt: now + REFRESH_TOKEN_TTL_MS,
      });

      return oauthJson(
        {
          access_token: nextAccess,
          token_type: 'Bearer',
          expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1_000),
          refresh_token: nextRefresh,
          scope: prev.scopes.join(' '),
        },
        200,
        cors,
      );
    }

    return oauthJson({ error: 'unsupported_grant_type' }, 400, cors);
  }

  // 6. RFC 7009 Token Revocation (`POST /oauth/revoke`)
  if (path === '/oauth/revoke') {
    if (request.method !== 'POST') return oauthJson({ error: 'method_not_allowed' }, 405, cors);
    const params = await parseFormOrJson(request);
    if (params.token) {
      await deps.store.revokeByTokenHash(await sha256Base64Url(params.token));
    }
    return oauthJson({ ok: true }, 200, cors);
  }

  return null;
}

/**
 * Authenticates a `/mcp` request via EITHER a direct `Bearer <CALLER_TOKEN>` OR a self-hosted OAuth 2.1 access token,
 * returning the RFC 9728 `WWW-Authenticate` header on `401` so Claude Code auto-triggers OAuth discovery.
 */
export async function authorizeMcpRequest(params: {
  request: Request;
  origin: string;
  ownerSecret?: string;
  store: OAuthStore;
  now?: number;
}): Promise<
  | { ok: true; scopes: string[]; principal: string }
  | { ok: false; status: number; wwwAuthenticate: string }
> {
  const wwwAuthenticate = `Bearer resource_metadata="${params.origin}/.well-known/oauth-protected-resource", scope="${MCP_SCOPES.join(' ')}"`;
  const m = /^bearer\s+(\S+)$/i.exec(params.request.headers.get('authorization') ?? '');
  const tok = m ? m[1] : null;
  if (!tok) return { ok: false, status: 401, wwwAuthenticate };

  if (params.ownerSecret && params.ownerSecret.length >= MIN_TOKEN_LENGTH && sameBytes(tok, params.ownerSecret)) {
    return { ok: true, scopes: [...MCP_SCOPES], principal: 'owner_token' };
  }

  const record = await params.store.getAccessToken(await sha256Base64Url(tok), params.now ?? Date.now());
  if (!record || record.resource.toLowerCase() !== `${params.origin.toLowerCase()}/mcp`) {
    return { ok: false, status: 401, wwwAuthenticate };
  }
  return { ok: true, scopes: record.scopes, principal: `oauth:${record.clientName}` };
}
