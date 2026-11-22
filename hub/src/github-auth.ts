/**
 * Sign in with GitHub (`oauth4webapi` OAuth 2.0 + PKCE `S256` + `state` cookie) & `jose` `HS256` Session JWTs
 * for Multi-User EdgeFetch Hub (`/admin/auth/github` -> `/admin/auth/github/callback`).
 *
 * Security Invariants:
 *  - Uses `oauth4webapi` PKCE `S256` + cryptographic `state` bound to a short-lived `HttpOnly; SameSite=Lax` cookie
 *    (`__Host-ef_gh_oauth` with `Secure` on HTTPS, single-use cleared on callback).
 *  - All outbound GitHub token & user API calls route strictly through `SAFE_PUBLIC_FETCH ?? SAFE_FETCH ?? fetch`.
 *  - Fails closed by default (`SIGNUP_MODE='invite_only'`): unlisted GitHub accounts are denied (`403`) unless matching
 *    `GITHUB_OWNER_LOGIN`, `GITHUB_ALLOWED_USERS` (user login or `@org`), or first-user owner bootstrap when
 *    `SIGNUP_MODE='bootstrap_first'`.
 *  - Mints `HS256` session JWTs via `jose` (`SignJWT` / `jwtVerify`) using a 256-bit key derived via WebCrypto HKDF-SHA256
 *    from `SESSION_SECRET ?? CALLER_TOKEN ?? GITHUB_CLIENT_SECRET`, with server-side `jti` revocation in `admin_revocations`.
 *  - Zero secrets, tokens, or authorization codes are ever recorded in OTLP spans or activity logs.
 */

import { SignJWT, jwtVerify } from 'jose';
import * as oauth from 'oauth4webapi';
import { MIN_TOKEN_LENGTH, sameBytes } from './auth';
import {
  escapeHtml,
  formatCookie,
  isEffectiveHttpsOrigin,
  randomUrlToken,
  readCookie,
  resolveAdminCookieAttrs,
  sha256Base64Url,
  type HubUserRecord,
  type OAuthStore,
  type UserRole,
} from './oauth';
import { normalizeClientRateLimitIp } from './safe-input';

export const GITHUB_STATE_COOKIE_SECURE = '__Host-ef_gh_oauth';
export const GITHUB_STATE_COOKIE_DEV = 'ef_gh_oauth';
export const PINNED_OWNER_GITHUB_ID_SETTING_KEY = 'pinned_owner_github_id';
const GITHUB_STATE_TTL_MS = 10 * 60_000; // 10m PKCE + state flow window
const ADMIN_JWT_TTL_MS = 8 * 60 * 60_000; // 8h browser session
const CALLBACK_RATE_LIMIT_WINDOW_MS = 5 * 60_000;
const CALLBACK_RATE_LIMIT_MAX_FAILURES = 10;

const JWT_ISSUER = 'urn:edgefetch:hub';
const JWT_AUDIENCE = 'urn:edgefetch:admin';

const GITHUB_LOGIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,38})$/i;
const GITHUB_NUMERIC_ID_RE = /^[1-9][0-9]{0,19}$/;

const GITHUB_AS: oauth.AuthorizationServer = {
  issuer: 'https://github.com',
  authorization_endpoint: 'https://github.com/login/oauth/authorize',
  token_endpoint: 'https://github.com/login/oauth/access_token',
};

const GITHUB_HTML_HEADERS: Record<string, string> = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'content-security-policy':
    "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

const GITHUB_REDIRECT_HEADERS: Record<string, string> = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
};

export type SignupMode = 'invite_only' | 'allowlist' | 'open' | 'bootstrap_first';

export interface GitHubAuthEnv {
  SESSION_SECRET?: string;
  CALLER_TOKEN?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GITHUB_ALLOWED_USERS?: string;
  GITHUB_OWNER_LOGIN?: string;
  GITHUB_OWNER_ID?: string;
  SIGNUP_MODE?: string;
  SAFE_PUBLIC_FETCH?: typeof fetch;
  SAFE_FETCH?: typeof fetch;
}

export interface VerifiedSessionJwt {
  ok: true;
  userId: string;
  role: UserRole;
  authMethod: 'github' | 'owner_token';
  epoch: number;
  jti: string;
  csrf: string;
  githubLogin?: string;
  avatarUrl?: string;
  expiresAt: number;
}

export function isGitHubAuthConfigured(env: Pick<GitHubAuthEnv, 'GITHUB_CLIENT_ID' | 'GITHUB_CLIENT_SECRET'>): boolean {
  const id = (env.GITHUB_CLIENT_ID ?? '').trim();
  const secret = (env.GITHUB_CLIENT_SECRET ?? '').trim();
  return id.length > 0 && secret.length >= 16;
}

/**
 * Resolves the canonical Hub session/HMAC signing secret:
 *  - If `SESSION_SECRET` is configured, it MUST be `>= MIN_TOKEN_LENGTH` (fails closed as `undefined` if too short — never silently falling back to `CALLER_TOKEN`!).
 *  - When `SESSION_SECRET` is omitted and GitHub OAuth is configured, mixes `GITHUB_CLIENT_SECRET` with `CALLER_TOKEN` so `CALLER_TOKEN` alone cannot forge GitHub user JWTs.
 */
export function resolveSessionSecret(env: Pick<GitHubAuthEnv, 'SESSION_SECRET' | 'CALLER_TOKEN' | 'GITHUB_CLIENT_ID' | 'GITHUB_CLIENT_SECRET'>): string | undefined {
  const rawSessionSec = env.SESSION_SECRET;
  if (typeof rawSessionSec === 'string' && rawSessionSec.trim().length > 0) {
    const sessionSec = rawSessionSec.trim();
    return sessionSec.length >= MIN_TOKEN_LENGTH ? sessionSec : undefined;
  }
  const callerTok = (env.CALLER_TOKEN ?? '').trim();
  if (isGitHubAuthConfigured(env)) {
    const ghSecret = (env.GITHUB_CLIENT_SECRET ?? '').trim();
    return callerTok.length >= MIN_TOKEN_LENGTH ? `gh-sess:${callerTok}:${ghSecret}` : ghSecret;
  }
  if (callerTok.length >= MIN_TOKEN_LENGTH) return callerTok;
  return undefined;
}

export function normalizeSignupMode(raw?: string): SignupMode {
  const clean = (raw ?? '').trim().toLowerCase();
  if (clean === 'open') return 'open';
  if (clean === 'allowlist') return 'allowlist';
  if (clean === 'bootstrap_first') return 'bootstrap_first';
  return 'invite_only';
}

export function parseGitHubAllowlist(raw?: string): { users: Set<string>; userIds: Set<string>; orgs: Set<string> } {
  const users = new Set<string>();
  const userIds = new Set<string>();
  const orgs = new Set<string>();
  if (!raw || !raw.trim()) return { users, userIds, orgs };
  for (const part of raw.split(/[\s,]+/)) {
    const trimmed = part.trim().toLowerCase();
    if (!trimmed) continue;
    if (trimmed.startsWith('@')) {
      const org = trimmed.slice(1);
      if (GITHUB_LOGIN_RE.test(org)) orgs.add(org);
    } else if (trimmed.startsWith('id:') && GITHUB_NUMERIC_ID_RE.test(trimmed.slice(3))) {
      userIds.add(trimmed.slice(3));
    } else if (GITHUB_NUMERIC_ID_RE.test(trimmed)) {
      userIds.add(trimmed);
      users.add(trimmed);
    } else if (GITHUB_LOGIN_RE.test(trimmed)) {
      users.add(trimmed);
    }
  }
  return { users, userIds, orgs };
}

export function isGitHubUserDeAllowlisted(user: HubUserRecord, env?: GitHubAuthEnv): boolean {
  if (!env || !isGitHubAuthConfigured(env)) return false;
  if (user.role === 'owner' || user.userId === 'owner') return false;
  const mode = normalizeSignupMode(env.SIGNUP_MODE);
  if (mode === 'open') return false;
  const allowlist = parseGitHubAllowlist(env.GITHUB_ALLOWED_USERS);
  if (allowlist.orgs.size > 0) return false;
  if (mode === 'allowlist' || mode === 'invite_only') {
    const loginOk = Boolean(user.githubLogin && allowlist.users.has(user.githubLogin.toLowerCase()));
    const idOk = Boolean(user.githubId && allowlist.userIds.has(String(user.githubId)));
    return !loginOk && !idOk;
  }
  return false;
}

export function sanitizeRelativeReturnTo(raw: string | null | undefined): string {
  if (typeof raw !== 'string') return '/admin';
  const trimmed = raw.trim();
  if (!trimmed || !trimmed.startsWith('/') || trimmed.startsWith('//') || trimmed.startsWith('/\\')) {
    return '/admin';
  }
  if (/[\r\n\0]/.test(trimmed)) return '/admin';
  const qIdx = trimmed.indexOf('?');
  const pathPart = qIdx >= 0 ? trimmed.slice(0, qIdx) : trimmed;
  if (pathPart === '/admin') {
    // Strip arbitrary query parameters (`/admin?next=...`) to prevent post-login open-redirect gadget chains.
    return '/admin';
  }
  if (pathPart === '/oauth/authorize') {
    return trimmed.slice(0, 1_024);
  }
  return '/admin';
}

const hkdfKeyCache = new Map<string, Uint8Array>();

async function deriveAdminJwtKey(secret: string): Promise<Uint8Array> {
  const cached = hkdfKeyCache.get(secret);
  if (cached) return cached;
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: enc.encode('edgefetch-v2.7-session-salt'),
      info: enc.encode('edgefetch-admin-jwt-hs256-v1'),
    },
    baseKey,
    256,
  );
  const derived = new Uint8Array(bits);
  if (hkdfKeyCache.size >= 32) {
    const oldest = hkdfKeyCache.keys().next().value;
    if (oldest !== undefined) hkdfKeyCache.delete(oldest);
  }
  hkdfKeyCache.set(secret, derived);
  return derived;
}

export async function mintSessionJwt(params: {
  secret: string;
  userId: string;
  role: UserRole;
  epoch?: number;
  authMethod?: 'github' | 'owner_token';
  githubLogin?: string;
  avatarUrl?: string;
  now?: number;
  ttlMs?: number;
}): Promise<{ token: string; jti: string; csrf: string; epoch: number; maxAgeSec: number; expiresAt: number }> {
  const now = params.now ?? Date.now();
  const ttlMs = params.ttlMs ?? ADMIN_JWT_TTL_MS;
  const expiresAt = now + ttlMs;
  const epoch = typeof params.epoch === 'number' && Number.isInteger(params.epoch) && params.epoch >= 1 ? params.epoch : 1;
  const jti = `jti_${randomUrlToken(18)}`;
  const csrf = randomUrlToken(24);
  const key = await deriveAdminJwtKey(params.secret);

  const token = await new SignJWT({
    csrf,
    role: params.role,
    ep: epoch,
    auth: params.authMethod ?? 'github',
    ...(params.githubLogin ? { login: params.githubLogin } : {}),
    ...(params.avatarUrl ? { avatar: params.avatarUrl } : {}),
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(params.userId)
    .setJti(jti)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setIssuedAt(Math.floor(now / 1_000))
    .setExpirationTime(Math.floor(expiresAt / 1_000))
    .sign(key);

  return {
    token,
    jti,
    csrf,
    epoch,
    maxAgeSec: Math.floor(ttlMs / 1_000),
    expiresAt,
  };
}

export async function verifySessionJwt(
  token: string,
  secret: string | undefined,
  now = Date.now(),
): Promise<VerifiedSessionJwt | { ok: false }> {
  if (!secret || secret.length < 16 || !token) return { ok: false };
  const segs = token.split('.');
  if (segs.length !== 3) return { ok: false };
  try {
    const key = await deriveAdminJwtKey(secret);
    const { payload, protectedHeader } = await jwtVerify(token, key, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      currentDate: new Date(now),
    });
    if (protectedHeader.alg !== 'HS256') return { ok: false };
    const sub = typeof payload.sub === 'string' ? payload.sub.trim() : '';
    const jti = typeof payload.jti === 'string' ? payload.jti.trim() : '';
    const csrf = typeof payload.csrf === 'string' ? payload.csrf.trim() : '';
    const role: UserRole | null = payload.role === 'owner' ? 'owner' : payload.role === 'member' ? 'member' : null;
    const epoch = typeof payload.ep === 'number' && Number.isInteger(payload.ep) && payload.ep >= 1 ? payload.ep : 1;
    const expSec = typeof payload.exp === 'number' ? payload.exp : 0;
    if (!sub || !jti || csrf.length < 16 || !role || !Number.isFinite(expSec) || expSec * 1_000 <= now) {
      return { ok: false };
    }
    const authMethod = payload.auth === 'owner_token' ? 'owner_token' : 'github';
    return {
      ok: true,
      userId: sub,
      role,
      authMethod,
      epoch,
      jti,
      csrf,
      ...(typeof payload.login === 'string' && payload.login ? { githubLogin: payload.login } : {}),
      ...(typeof payload.avatar === 'string' && payload.avatar ? { avatarUrl: payload.avatar } : {}),
      expiresAt: expSec * 1_000,
    };
  } catch {
    return { ok: false };
  }
}

interface SealedGitHubState {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
  exp: number;
}

function base64UrlBytes(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmacSignState(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(`gh-oauth-state:${secret}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return base64UrlBytes(new Uint8Array(sig));
}

async function sealGitHubState(secret: string, data: SealedGitHubState): Promise<string> {
  const payloadB64 = base64UrlBytes(new TextEncoder().encode(JSON.stringify(data)));
  const sig = await hmacSignState(secret, payloadB64);
  return `${payloadB64}.${sig}`;
}

async function unsealGitHubState(secret: string, raw: string, now: number): Promise<SealedGitHubState | null> {
  const dot = raw.indexOf('.');
  if (dot <= 0) return null;
  const payloadB64 = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = await hmacSignState(secret, payloadB64);
  if (!sameBytes(sig, expected)) return null;
  try {
    const padded = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as SealedGitHubState;
    if (
      !parsed ||
      typeof parsed.state !== 'string' ||
      typeof parsed.nonce !== 'string' ||
      parsed.nonce.length < 16 ||
      typeof parsed.codeVerifier !== 'string' ||
      typeof parsed.exp !== 'number' ||
      parsed.exp <= now
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function resolveGitHubSafeFetch(env: Pick<GitHubAuthEnv, 'SAFE_PUBLIC_FETCH' | 'SAFE_FETCH'>): typeof fetch {
  return env.SAFE_PUBLIC_FETCH ?? env.SAFE_FETCH ?? fetch;
}

function renderGitHubAuthErrorHtml(serviceName: string, title: string, message: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} — ${escapeHtml(serviceName)}</title>
  <style>
    :root { color-scheme: dark light; }
    body { font: 15px/1.55 system-ui, -apple-system, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0b1120; color: #e2e8f0; padding: 16px; }
    main { width: 100%; max-width: 440px; background: #1e293b; border: 1px solid #334155; border-radius: 14px; padding: 28px; box-shadow: 0 16px 40px rgba(0,0,0,.45); }
    h1 { margin: 0 0 8px; font-size: 1.2rem; color: #f8fafc; }
    p { margin: 0 0 18px; color: #cbd5e1; font-size: 0.92rem; }
    .err { background: #450a0a; border: 1px solid #dc2626; color: #fecaca; padding: 10px 12px; border-radius: 8px; margin-bottom: 16px; font-size: 0.88rem; }
    a.btn { display: inline-block; text-decoration: none; padding: 9px 16px; border-radius: 8px; background: #2563eb; border: 1px solid #3b82f6; color: #fff; font-weight: 600; font-size: 0.9rem; }
    a.btn:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(title)}</h1>
    <div class="err">${escapeHtml(message)}</div>
    <p>Return to the Hub login screen to sign in with an authorized account.</p>
    <a class="btn" href="/admin">Back to Sign In</a>
  </main>
</body>
</html>`;
}

async function mirrorUserToMetaD1(metaDb: D1Database | undefined, user: HubUserRecord): Promise<void> {
  if (!metaDb) return;
  try {
    await metaDb
      .prepare(
        `CREATE TABLE IF NOT EXISTS users (
           user_id TEXT PRIMARY KEY,
           github_id TEXT UNIQUE,
           github_login TEXT NOT NULL,
           avatar_url TEXT,
           role TEXT NOT NULL DEFAULT 'member',
           session_epoch INTEGER NOT NULL DEFAULT 1,
           disabled INTEGER NOT NULL DEFAULT 0,
           created_at INTEGER NOT NULL,
           last_login_at INTEGER NOT NULL
         )`,
      )
      .run();
    await metaDb.prepare('ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 1').run().catch(() => undefined);
    await metaDb.prepare('ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0').run().catch(() => undefined);
    await metaDb
      .prepare(
        `INSERT INTO users (user_id, github_id, github_login, avatar_url, role, session_epoch, disabled, created_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
           github_id = COALESCE(excluded.github_id, users.github_id),
           github_login = excluded.github_login,
           avatar_url = excluded.avatar_url,
           role = excluded.role,
           session_epoch = excluded.session_epoch,
           disabled = excluded.disabled,
           last_login_at = excluded.last_login_at`,
      )
      .bind(
        user.userId,
        user.githubId ?? null,
        user.githubLogin ?? user.userId,
        user.avatarUrl ?? null,
        user.role,
        user.sessionEpoch ?? 1,
        user.disabled ? 1 : 0,
        user.createdAt,
        user.lastLoginAt,
      )
      .run();
  } catch {
    // Non-fatal mirror when optional META D1 is unmigrated or read-only in tests
  }
}

function resolveCanonicalCallbackOrigin(url: URL, publicOrigin?: string): string {
  if (typeof publicOrigin === 'string' && publicOrigin.trim()) {
    try {
      return new URL(publicOrigin.trim()).origin;
    } catch {
      // fall back to url.origin
    }
  }
  return url.origin;
}

function resolveGitHubStateCookieAttrs(url: URL, publicOrigin?: string): { name: string; secure: boolean; strictHostPrefix: boolean } {
  const adminAttrs = resolveAdminCookieAttrs(url, publicOrigin);
  return {
    name: adminAttrs.strictHostPrefix ? GITHUB_STATE_COOKIE_SECURE : GITHUB_STATE_COOKIE_DEV,
    secure: adminAttrs.secure,
    strictHostPrefix: adminAttrs.strictHostPrefix,
  };
}

export async function startGitHubOAuthFlow(params: {
  request: Request;
  url: URL;
  env: GitHubAuthEnv;
  publicOrigin?: string;
  now?: number;
}): Promise<{ response: Response; outcome: string }> {
  const { url, env, publicOrigin, now = Date.now() } = params;
  const signingSecret = resolveSessionSecret(env);
  if (!isGitHubAuthConfigured(env) || !signingSecret) {
    return {
      outcome: 'github_unconfigured',
      response: Response.json({ error: 'github_oauth_not_configured' }, { status: 503, headers: GITHUB_REDIRECT_HEADERS }),
    };
  }

  const clientId = env.GITHUB_CLIENT_ID!.trim();
  const stateCookieAttrs = resolveGitHubStateCookieAttrs(url, publicOrigin);
  const returnTo = sanitizeRelativeReturnTo(url.searchParams.get('return_to'));

  const codeVerifier = oauth.generateRandomCodeVerifier();
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
  const state = oauth.generateRandomState();
  const nonce = randomUrlToken(24);

  const sealedCookie = await sealGitHubState(signingSecret, {
    state,
    nonce,
    codeVerifier,
    returnTo,
    exp: now + GITHUB_STATE_TTL_MS,
  });

  const allowlist = parseGitHubAllowlist(env.GITHUB_ALLOWED_USERS);
  const ghScope = allowlist.orgs.size > 0 ? 'read:user read:org' : 'read:user';
  const callbackOrigin = resolveCanonicalCallbackOrigin(url, publicOrigin);
  const redirectUri = `${callbackOrigin}/admin/auth/github/callback`;

  const authorizeUrl = new URL(GITHUB_AS.authorization_endpoint!);
  authorizeUrl.searchParams.set('client_id', clientId);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', ghScope);
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', codeChallenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  const headers = new Headers({
    location: authorizeUrl.toString(),
    ...GITHUB_REDIRECT_HEADERS,
  });
  headers.append(
    'set-cookie',
    formatCookie(stateCookieAttrs.name, sealedCookie, {
      maxAge: Math.floor(GITHUB_STATE_TTL_MS / 1_000),
      path: '/',
      sameSite: 'Lax',
      secure: stateCookieAttrs.secure,
    }),
  );
  return {
    outcome: 'redirected',
    response: new Response(null, { status: 302, headers }),
  };
}

export async function handleGitHubOAuthCallback(params: {
  request: Request;
  url: URL;
  env: GitHubAuthEnv;
  oauthStore: OAuthStore;
  metaDb?: D1Database;
  serviceName: string;
  publicOrigin?: string;
  getHubSetting?: (key: string) => Promise<string | null>;
  setHubSetting?: (key: string, value: string) => Promise<void>;
  now?: number;
  onEvent?: (ev: {
    level: 'info' | 'warn' | 'error';
    category: 'oauth';
    event: string;
    summary: string;
    details?: Record<string, unknown>;
  }) => Promise<void> | void;
}): Promise<{ response: Response; outcome: string; userId?: string; role?: UserRole }> {
  const { request, url, env, oauthStore, metaDb, serviceName, publicOrigin, getHubSetting, setHubSetting, now = Date.now(), onEvent } = params;
  const signingSecret = resolveSessionSecret(env);
  if (!isGitHubAuthConfigured(env) || !signingSecret) {
    return {
      outcome: 'github_unconfigured',
      response: Response.json({ error: 'github_oauth_not_configured' }, { status: 503, headers: GITHUB_REDIRECT_HEADERS }),
    };
  }

  const stateCookieAttrs = resolveGitHubStateCookieAttrs(url, publicOrigin);
  const adminCookieAttrs = resolveAdminCookieAttrs(url, publicOrigin);
  const clearStateCookieHeader = formatCookie(stateCookieAttrs.name, '', {
    maxAge: 0,
    path: '/',
    sameSite: 'Lax',
    secure: stateCookieAttrs.secure,
  });

  const makeErrorResponse = (status: number, outcome: string, title: string, message: string, extraHeaders?: Record<string, string>) => {
    const headers = new Headers({ ...GITHUB_HTML_HEADERS, ...(extraHeaders ?? {}) });
    headers.append('set-cookie', clearStateCookieHeader);
    return {
      outcome,
      response: new Response(renderGitHubAuthErrorHtml(serviceName, title, message), { status, headers }),
    };
  };

  const clientIp = normalizeClientRateLimitIp(request.headers.get('cf-connecting-ip'));
  const preLock = await oauthStore.checkAuthLockout(`gh_cb:${clientIp}`, now, CALLBACK_RATE_LIMIT_MAX_FAILURES);
  if (!preLock.allowed) {
    return makeErrorResponse(
      429,
      'rate_limited',
      'Too Many Sign-In Attempts',
      'Too many failed GitHub callback attempts from this IP. Please wait a few minutes and try again.',
      { 'retry-after': String(preLock.retryAfterSec) },
    );
  }

  // Login CSRF hardening: on HTTPS / non-loopback origins, read STRICTLY `__Host-ef_gh_oauth` and NEVER fall back to
  // an unprefixed `ef_gh_oauth` cookie that a sibling subdomain could toss!
  const rawCookieHeader = request.headers.get('cookie');
  const rawStateCookie = stateCookieAttrs.strictHostPrefix
    ? readCookie(rawCookieHeader, GITHUB_STATE_COOKIE_SECURE)
    : (readCookie(rawCookieHeader, GITHUB_STATE_COOKIE_DEV) ?? readCookie(rawCookieHeader, GITHUB_STATE_COOKIE_SECURE));
  if (!rawStateCookie) {
    await oauthStore.recordAuthFailure(`gh_cb:${clientIp}`, now, CALLBACK_RATE_LIMIT_WINDOW_MS, CALLBACK_RATE_LIMIT_MAX_FAILURES);
    return makeErrorResponse(400, 'missing_state_cookie', 'Sign-In Session Expired', 'Missing or expired OAuth state cookie. Please start sign-in again.');
  }

  const sealed = await unsealGitHubState(signingSecret, rawStateCookie, now);
  if (!sealed) {
    await oauthStore.recordAuthFailure(`gh_cb:${clientIp}`, now, CALLBACK_RATE_LIMIT_WINDOW_MS, CALLBACK_RATE_LIMIT_MAX_FAILURES);
    return makeErrorResponse(400, 'invalid_state_cookie', 'Invalid Sign-In State', 'OAuth state verification failed or expired. Please try again.');
  }

  const clientId = env.GITHUB_CLIENT_ID!.trim();
  const clientSecret = env.GITHUB_CLIENT_SECRET!.trim();
  const oauthClient: oauth.Client = { client_id: clientId };
  const callbackOrigin = resolveCanonicalCallbackOrigin(url, publicOrigin);
  const redirectUri = `${callbackOrigin}/admin/auth/github/callback`;
  const customFetch = resolveGitHubSafeFetch(env);

  let validatedParams: URLSearchParams;
  try {
    validatedParams = oauth.validateAuthResponse(GITHUB_AS, oauthClient, url, sealed.state);
  } catch (err) {
    await oauthStore.recordAuthFailure(`gh_cb:${clientIp}`, now, CALLBACK_RATE_LIMIT_WINDOW_MS, CALLBACK_RATE_LIMIT_MAX_FAILURES);
    if (err instanceof oauth.AuthorizationResponseError) {
      return makeErrorResponse(400, 'oauth_denied', 'GitHub Sign-In Cancelled', 'GitHub authorization was cancelled or denied.');
    }
    return makeErrorResponse(400, 'state_mismatch', 'Invalid OAuth Callback', 'State parameter mismatch or malformed callback parameters.');
  }

  // Strictly single-use state nonce check BEFORE exchanging authorization code (prevents state cookie replay!).
  const stateNonceHash = await sha256Base64Url(`${sealed.state}:${sealed.nonce}`);
  const replayKey = `revoked_admin:gh_state:${stateNonceHash}`;
  const stateFresh = await oauthStore.checkAuthLockout(replayKey, now, 1);
  if (!stateFresh.allowed) {
    await oauthStore.recordAuthFailure(`gh_cb:${clientIp}`, now, CALLBACK_RATE_LIMIT_WINDOW_MS, CALLBACK_RATE_LIMIT_MAX_FAILURES);
    return makeErrorResponse(400, 'replayed_state_cookie', 'Sign-In State Already Used', 'This OAuth sign-in state has already been consumed. Please start sign-in again.');
  }
  await oauthStore.recordAuthFailure(replayKey, now, GITHUB_STATE_TTL_MS + 60_000, 1);

  let accessToken: string;
  try {
    const tokenRes = await oauth.authorizationCodeGrantRequest(
      GITHUB_AS,
      oauthClient,
      oauth.ClientSecretPost(clientSecret),
      validatedParams,
      redirectUri,
      sealed.codeVerifier,
      {
        headers: {
          accept: 'application/json',
          'user-agent': 'EdgeFetch-Hub/2.7',
        },
        [oauth.customFetch]: customFetch,
      },
    );
    const processed = await oauth.processAuthorizationCodeResponse(GITHUB_AS, oauthClient, tokenRes);
    accessToken = processed.access_token;
  } catch {
    await oauthStore.recordAuthFailure(`gh_cb:${clientIp}`, now, CALLBACK_RATE_LIMIT_WINDOW_MS, CALLBACK_RATE_LIMIT_MAX_FAILURES);
    return makeErrorResponse(401, 'token_exchange_failed', 'GitHub Token Exchange Failed', 'Could not exchange GitHub authorization code for an access token.');
  }

  let ghId: number;
  let ghLogin: string;
  let ghAvatarUrl: string | undefined;
  try {
    const userRes = await oauth.protectedResourceRequest(
      accessToken,
      'GET',
      new URL('https://api.github.com/user'),
      new Headers({
        accept: 'application/vnd.github+json',
        'user-agent': 'EdgeFetch-Hub/2.7',
        'x-github-api-version': '2022-11-28',
      }),
      undefined,
      { [oauth.customFetch]: (reqUrl, reqOpts) => customFetch(reqUrl, reqOpts as unknown as RequestInit) },
    );
    if (userRes.status !== 200) {
      return makeErrorResponse(502, 'github_user_error', 'GitHub Profile Error', `GitHub /user API returned HTTP ${userRes.status}.`);
    }
    const profileText = await userRes.text();
    if (profileText.length > 131_072) {
      return makeErrorResponse(502, 'github_user_error', 'GitHub Profile Error', 'GitHub /user payload exceeded size limit.');
    }
    const profile = JSON.parse(profileText) as { id?: unknown; login?: unknown; avatar_url?: unknown };
    if (
      typeof profile.id !== 'number' ||
      !Number.isSafeInteger(profile.id) ||
      profile.id <= 0 ||
      typeof profile.login !== 'string' ||
      !GITHUB_LOGIN_RE.test(profile.login.trim())
    ) {
      return makeErrorResponse(502, 'github_user_invalid', 'Invalid GitHub Profile', 'GitHub profile response did not contain a valid numeric id and login.');
    }
    ghId = profile.id;
    ghLogin = profile.login.trim();
    if (typeof profile.avatar_url === 'string' && profile.avatar_url.startsWith('https://')) {
      ghAvatarUrl = profile.avatar_url.trim().slice(0, 512);
    }
  } catch {
    return makeErrorResponse(502, 'github_user_error', 'GitHub Profile Fetch Failed', 'Unable to verify GitHub account profile.');
  }

  const ghIdStr = String(ghId);
  const userId = `gh_${ghIdStr}`;
  const loginLower = ghLogin.toLowerCase();
  const ownerLoginLower = (env.GITHUB_OWNER_LOGIN ?? '').trim().toLowerCase();
  const rawConfiguredOwnerId = (env.GITHUB_OWNER_ID ?? '').trim();
  if (rawConfiguredOwnerId && !GITHUB_NUMERIC_ID_RE.test(rawConfiguredOwnerId)) {
    return makeErrorResponse(500, 'invalid_owner_id_config', 'Invalid Owner Configuration', 'GITHUB_OWNER_ID must be a positive numeric GitHub user ID.');
  }
  const signupMode = normalizeSignupMode(env.SIGNUP_MODE);
  const allowlist = parseGitHubAllowlist(env.GITHUB_ALLOWED_USERS);

  const existingUser = (await oauthStore.getUser?.(userId)) ?? null;
  if (existingUser?.disabled) {
    await onEvent?.({
      level: 'warn',
      category: 'oauth',
      event: 'github_disabled_user_denied',
      summary: `Blocked sign-in for removed/disabled GitHub user @${ghLogin} (${userId})`,
      details: { userId, githubLogin: ghLogin },
    });
    return makeErrorResponse(
      403,
      'account_disabled',
      'Account Removed',
      `GitHub account @${ghLogin} has been disabled or removed from this Hub.`,
    );
  }

  const activeUsers = (await oauthStore.listUsers?.()) ?? [];
  const totalUsers = (await oauthStore.countUsers?.()) ?? activeUsers.length;

  // Block recycled/squatted GitHub logins claiming an active Hub member/owner's handle with a different numeric `github_id`!
  const collidingUser = activeUsers.find(
    (u) => u.userId !== userId && !u.disabled && (u.githubLogin ?? '').toLowerCase() === loginLower,
  );
  if (collidingUser) {
    await onEvent?.({
      level: 'warn',
      category: 'oauth',
      event: 'github_login_collision_blocked',
      summary: `Blocked recycled GitHub handle @${ghLogin} (${userId}) colliding with existing ${collidingUser.userId}`,
      details: { userId, existingUserId: collidingUser.userId, githubLogin: ghLogin },
    });
    return makeErrorResponse(
      403,
      'login_collision',
      'Account Handle Conflict',
      `GitHub login @${ghLogin} is already bound to a different immutable GitHub numeric ID on this Hub.`,
    );
  }

  // H6: Resolve immutable numeric owner GitHub ID (`GITHUB_OWNER_ID` env OR `pinned_owner_github_id` in `hub_settings` / existing owner row).
  const storedPinnedOwnerId = (await getHubSetting?.(PINNED_OWNER_GITHUB_ID_SETTING_KEY))?.trim() || '';
  const fallbackExistingOwner = activeUsers
    .filter((u) => u.role === 'owner' && !u.disabled && u.githubId && GITHUB_NUMERIC_ID_RE.test(u.githubId))
    .sort((a, b) => a.createdAt - b.createdAt)[0];
  const pinnedOwnerGithubId =
    rawConfiguredOwnerId ||
    (GITHUB_NUMERIC_ID_RE.test(storedPinnedOwnerId) ? storedPinnedOwnerId : '') ||
    (fallbackExistingOwner?.githubId ?? '');

  // If `GITHUB_OWNER_LOGIN` is claimed by a DIFFERENT numeric GitHub ID after an account rename, REJECT immediately!
  if (ownerLoginLower && loginLower === ownerLoginLower && pinnedOwnerGithubId && ghIdStr !== pinnedOwnerGithubId) {
    await onEvent?.({
      level: 'warn',
      category: 'oauth',
      event: 'github_owner_impersonation_blocked',
      summary: `Blocked GitHub login @${ghLogin} (${userId}) from claiming owner handle pinned to gh_${pinnedOwnerGithubId}`,
      details: { userId, pinnedOwnerGithubId, githubLogin: ghLogin },
    });
    return makeErrorResponse(
      403,
      'owner_id_mismatch',
      'Owner Identity Mismatch',
      'This GitHub handle does not match the Hub’s pinned immutable numeric owner ID.',
    );
  }

  let allowed = false;
  let assignedRole: UserRole = existingUser?.role ?? 'member';
  let shouldPinOwnerId = false;

  if (pinnedOwnerGithubId && ghIdStr === pinnedOwnerGithubId) {
    allowed = true;
    assignedRole = 'owner';
    if (!storedPinnedOwnerId) shouldPinOwnerId = true;
  } else if (!pinnedOwnerGithubId && ownerLoginLower && loginLower === ownerLoginLower) {
    allowed = true;
    assignedRole = 'owner';
    shouldPinOwnerId = true;
  } else if (!pinnedOwnerGithubId && signupMode === 'bootstrap_first' && totalUsers === 0 && !ownerLoginLower) {
    allowed = true;
    assignedRole = 'owner';
    shouldPinOwnerId = true;
  } else if (existingUser?.role === 'owner') {
    allowed = true;
    assignedRole = 'owner';
  } else if (allowlist.userIds.has(ghIdStr) || allowlist.users.has(loginLower)) {
    allowed = true;
  } else if (allowlist.orgs.size > 0) {
    try {
      const orgsRes = await oauth.protectedResourceRequest(
        accessToken,
        'GET',
        new URL('https://api.github.com/user/orgs?per_page=100'),
        new Headers({
          accept: 'application/vnd.github+json',
          'user-agent': 'EdgeFetch-Hub/2.7',
          'x-github-api-version': '2022-11-28',
        }),
        undefined,
        { [oauth.customFetch]: (reqUrl, reqOpts) => customFetch(reqUrl, reqOpts as unknown as RequestInit) },
      );
      if (orgsRes.status === 200) {
        const orgsText = await orgsRes.text();
        if (orgsText.length <= 262_144) {
          const orgsList = JSON.parse(orgsText) as Array<{ login?: unknown }>;
          if (Array.isArray(orgsList)) {
            for (const o of orgsList) {
              if (typeof o?.login === 'string' && allowlist.orgs.has(o.login.trim().toLowerCase())) {
                allowed = true;
                break;
              }
            }
          }
        }
      }
    } catch {
      allowed = false;
    }
  }

  if (!allowed && signupMode === 'invite_only' && existingUser !== null && allowlist.users.size === 0 && allowlist.orgs.size === 0) {
    allowed = true;
  }

  if (!allowed && signupMode === 'open') {
    allowed = true;
  }

  if (!allowed) {
    await onEvent?.({
      level: 'warn',
      category: 'oauth',
      event: 'github_signup_denied',
      summary: `Denied GitHub sign-in for @${ghLogin} (${userId}) under SIGNUP_MODE=${signupMode}`,
      details: { userId, githubLogin: ghLogin, signupMode },
    });
    return makeErrorResponse(
      403,
      'signup_denied',
      'Account Not Authorized',
      `GitHub account @${ghLogin} is not authorized on this Hub (SIGNUP_MODE=${signupMode}). Ask the Hub owner to add your login to GITHUB_ALLOWED_USERS.`,
    );
  }

  await oauthStore.clearAuthFailures(`gh_cb:${clientIp}`);

  if (shouldPinOwnerId) {
    await setHubSetting?.(PINNED_OWNER_GITHUB_ID_SETTING_KEY, ghIdStr);
  }

  const sessionEpoch = existingUser?.sessionEpoch ?? 1;
  const userRecord: HubUserRecord = {
    userId,
    githubId: ghIdStr,
    githubLogin: ghLogin,
    ...(ghAvatarUrl ? { avatarUrl: ghAvatarUrl } : {}),
    role: assignedRole,
    sessionEpoch,
    disabled: false,
    createdAt: existingUser?.createdAt ?? now,
    lastLoginAt: now,
  };
  const savedUser = (await oauthStore.upsertUser?.(userRecord)) ?? userRecord;
  await mirrorUserToMetaD1(metaDb, savedUser);

  const minted = await mintSessionJwt({
    secret: signingSecret,
    userId,
    role: savedUser.role,
    epoch: savedUser.sessionEpoch ?? sessionEpoch,
    authMethod: 'github',
    githubLogin: ghLogin,
    ...(ghAvatarUrl ? { avatarUrl: ghAvatarUrl } : {}),
    now,
  });

  await onEvent?.({
    level: 'info',
    category: 'oauth',
    event: 'github_login_ok',
    summary: `GitHub user @${ghLogin} (${userId}, role=${savedUser.role}) signed in`,
    details: { userId, githubLogin: ghLogin, role: savedUser.role },
  });

  const redirectHeaders = new Headers({
    location: sanitizeRelativeReturnTo(sealed.returnTo),
    ...GITHUB_REDIRECT_HEADERS,
  });
  redirectHeaders.append('set-cookie', clearStateCookieHeader);
  redirectHeaders.append(
    'set-cookie',
    formatCookie(adminCookieAttrs.name, minted.token, {
      maxAge: minted.maxAgeSec,
      path: '/',
      sameSite: 'Lax',
      secure: adminCookieAttrs.secure,
    }),
  );

  return {
    outcome: 'authenticated',
    userId,
    role: savedUser.role,
    response: new Response(null, { status: 302, headers: redirectHeaders }),
  };
}
