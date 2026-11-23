/**
 * Round 8 Security Closure Suite — Stream 2:
 *  - H4: `@org` Revocation Bypass Fix + Server-Side Org Membership Re-Verification on Refresh & Stale (>5m) Sessions
 *  - H5: Explicit `GITHUB_OWNER_ID` Requirement (Zero Auto-Pinning) & Secondary-Owner Mutation Guard
 *  - Bare All-Digit Disambiguation in `GITHUB_ALLOWED_USERS` (`id:<digits>` vs `login:<digits>`)
 *  - Multi-User Crawl Private R2/D1 Isolation (`private/<userId>/derived/...`, zero shared cache/artifact seeding)
 *  - Per-User Concurrency Quotas on `scrape` (16), `interact` (4), and `agent` (4, including background async runs)
 *  - `mcp:call` Scope Bypass Fix on `scrape`, Opt-In `/v1/agent` Connectors, `v2.7.0` Vault Fallback,
 *    Shared-Hosting Sibling Tenant Isolation (`*.supabase.co`, `*.up.railway.app`, `*.run.app`), & Strict Tool ID Regex
 */

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { LocalAgentHubCoordinator, NodeFsR2Bucket, NodeSqliteD1Database } from '../portable/node-adapters.ts';
import { startOrExecuteAgentCall } from '../src/agent-runner.ts';
import {
  GITHUB_ORG_REVERIFY_TTL_MS,
  handleGitHubOAuthCallback,
  isGitHubUserDeAllowlisted,
  parseGitHubAllowlist,
  reverifyGitHubOrgAdmission,
} from '../src/github-auth.ts';
import hubWorker from '../src/index.ts';
import { executeFederatedMcpQuery, sanitizeRemoteMcpToolDefs, testAndListRemoteMcpTools } from '../src/mcp-federation.ts';
import { extractRegistrableDomain, isSharedHostingHostname, validateConnectorDomains } from '../src/mcp-registry.ts';
import {
  createMemoryMcpVaultStore,
  filterSafeCachedMcpTools,
  probeRemoteMcpOAuthMetadata,
  sealVaultCredentials,
  startDownstreamMcpOAuth,
  unsealVaultCredentials,
} from '../src/mcp-vault.ts';
import { ADMIN_COOKIE_NAME, createMemoryOAuthStore, sha256Base64Url, verifyAdminSessionCookie } from '../src/oauth.ts';

import meta0001 from '../migrations/meta/0001_tracking.sql';
import meta0002 from '../migrations/meta/0002_multiuser.sql';
import search0001 from '../migrations/search/0001_fts.sql';

const TEST_OWNER_TOKEN = 'r8-owner-caller-secret-0123456789abcdef';
const TEST_SESSION_SECRET = 'r8-session-signing-secret-0123456789abcdef';
const TEST_VAULT_KEY = 'r8-vault-master-secret-key-9876543210fedcba';

function extractSetCookies(headers: Headers): string[] {
  const anyH = headers as unknown as { getSetCookie?: () => string[] };
  if (typeof anyH.getSetCookie === 'function') {
    const list = anyH.getSetCookie();
    if (list.length > 0) return list;
  }
  const raw = headers.get('set-cookie');
  return raw ? [raw] : [];
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sealLegacyV270Ciphertext(params: {
  vaultMasterKey: string;
  userId: string;
  remoteOrigin: string;
  payload: Record<string, unknown>;
}): Promise<string> {
  const canonicalOrigin = params.remoteOrigin.trim().toLowerCase();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(params.vaultMasterKey), { name: 'HKDF' }, false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      info: enc.encode(`edgefetch-mcp-vault-v1:${params.userId}:${canonicalOrigin}`),
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const aad = enc.encode(`${params.userId}|${canonicalOrigin}`);
  const plaintext = enc.encode(JSON.stringify({ ...params.payload, pinnedOrigin: canonicalOrigin }));
  const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad, tagLength: 128 }, aesKey, plaintext);
  return `v1.${bytesToBase64Url(salt)}.${bytesToBase64Url(iv)}.${bytesToBase64Url(new Uint8Array(ctBuf))}`;
}

test('R8-H4 & Bare-Digit Allowlist: @org revocation no longer bypasses direct user removal, refresh re-verifies GitHub /user/orgs, encryptedGhToken never leaks, and bare digits fail closed', async () => {
  // 1. Bare all-digit allowlist entries are rejected; id:<digits> and login:<digits> are strictly separated
  const parsedAllow = parseGitHubAllowlist('12345, 0099, id:67890, login:54321, user42, @Trusted-Org');
  assert.equal(parsedAllow.userIds.has('12345'), false, 'Bare digits must not populate userIds');
  assert.equal(parsedAllow.users.has('12345'), false, 'Bare digits must not populate users');
  assert.equal(parsedAllow.userIds.has('67890'), true);
  assert.equal(parsedAllow.users.has('67890'), false);
  assert.equal(parsedAllow.users.has('54321'), true);
  assert.equal(parsedAllow.userIds.has('54321'), false);
  assert.equal(parsedAllow.users.has('user42'), true);
  assert.equal(parsedAllow.orgs.has('trusted-org'), true);

  const tmpDir = mkdtempSync(join(tmpdir(), 'ef-r8-h4-'));
  const coordinator = new LocalAgentHubCoordinator(join(tmpDir, 'hub.sqlite'));
  const metaDb = new NodeSqliteD1Database(':memory:', [
    { name: 'meta/0001_tracking.sql', sql: meta0001 },
    { name: 'meta/0002_multiuser.sql', sql: meta0002 },
  ]);

  const orgsByUserId = new Map<number, string[]>([
    [100, []],
    [201, []], // Alice is NOT in @trusted-org (or admitted via allowlist_login)
    [202, ['Trusted-Org']], // Charlie is admitted ONLY via @trusted-org
    [203, []],
    [12345, []],
  ]);

  const ghUsersByCode = new Map<string, { id: number; login: string }>([
    ['code_founder', { id: 100, login: 'founder' }],
    ['code_alice', { id: 201, login: 'alice' }],
    ['code_charlie_org', { id: 202, login: 'charlie' }],
    ['code_bare_id', { id: 12345, login: 'intruder-id' }],
    ['code_bare_login', { id: 99999, login: '12345' }],
  ]);
  const ghTokenToUser = new Map<string, { id: number; login: string }>();
  let githubOrgsApiCalls = 0;

  const mockSafeFetch: typeof fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const u = new URL(req.url);
    if (u.origin === 'https://github.com' && u.pathname === '/login/oauth/access_token') {
      const form = new URLSearchParams(await req.text());
      const user = ghUsersByCode.get(form.get('code') ?? '');
      if (!user || !form.get('code_verifier')) return Response.json({ error: 'invalid_grant' }, { status: 400 });
      const tok = `gho_secret_token_${user.login}_${crypto.randomUUID().replace(/-/g, '')}`;
      ghTokenToUser.set(tok, user);
      return Response.json({ access_token: tok, token_type: 'bearer', scope: 'read:user,read:org' });
    }
    if (u.origin === 'https://api.github.com' && u.pathname === '/user') {
      const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
      const user = m?.[1] ? ghTokenToUser.get(m[1]) : undefined;
      if (!user) return Response.json({ message: 'Bad credentials' }, { status: 401 });
      return Response.json({ id: user.id, login: user.login, avatar_url: `https://avatars.githubusercontent.com/u/${user.id}` });
    }
    if (u.origin === 'https://api.github.com' && u.pathname === '/user/orgs') {
      githubOrgsApiCalls++;
      const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
      const user = m?.[1] ? ghTokenToUser.get(m[1]) : undefined;
      if (!user) return Response.json({ message: 'Bad credentials' }, { status: 401 });
      const orgs = orgsByUserId.get(user.id) ?? [];
      return Response.json(orgs.map((login) => ({ login })));
    }
    return new Response('not found', { status: 404 });
  };

  const env: Record<string, unknown> = {
    AGENT_HUB: coordinator.asNamespace(),
    META: metaDb,
    CALLER_TOKEN: TEST_OWNER_TOKEN,
    SESSION_SECRET: TEST_SESSION_SECRET,
    GITHUB_CLIENT_ID: 'Iv23liRound8H4',
    GITHUB_CLIENT_SECRET: 'ghs_round8_client_secret_0123456789abcdef',
    GITHUB_OWNER_LOGIN: 'founder',
    GITHUB_OWNER_ID: '100',
    GITHUB_ALLOWED_USERS: 'alice,12345,@trusted-org',
    SIGNUP_MODE: 'invite_only',
    SAFE_PUBLIC_FETCH: mockSafeFetch,
    SAFE_FETCH: mockSafeFetch,
  };

  const dispatch = async (path: string, init?: RequestInit): Promise<Response> => {
    const req = new Request(`https://hub.example.com${path}`, init);
    return await (hubWorker as { fetch(r: Request, e: unknown): Promise<Response> }).fetch(req, env);
  };

  const signIn = async (code: string) => {
    const r1 = await dispatch('/admin/auth/github');
    assert.equal(r1.status, 302);
    const state = new URL(r1.headers.get('location')!).searchParams.get('state')!;
    const stateCookie = extractSetCookies(r1.headers)
      .map((c) => c.split(';')[0]!.trim())
      .find((c) => c.startsWith('__Host-ef_gh_oauth='))!;
    const r2 = await dispatch(`/admin/auth/github/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`, {
      headers: { cookie: stateCookie },
    });
    const sessionCookie =
      extractSetCookies(r2.headers)
        .map((c) => c.split(';')[0]!.trim())
        .find((c) => c.startsWith(`${ADMIN_COOKIE_NAME}=`) && c.length > `${ADMIN_COOKIE_NAME}=`.length) ?? null;
    return { status: r2.status, sessionCookie };
  };

  const mintOAuthTokens = async (sessionCookie: string, scopes = 'crawl:read crawl:fetch') => {
    const reg = await dispatch('/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'R8 CLI', redirect_uris: ['http://127.0.0.1:54321/cb'] }),
    });
    const { client_id } = (await reg.json()) as { client_id: string };
    const verifier = 'verifier_' + crypto.randomUUID().replace(/-/g, '') + '_0123456789abcdef';
    const challenge = await sha256Base64Url(verifier);
    const getAuth = await dispatch(
      `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:54321/cb')}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256&scope=${encodeURIComponent(scopes)}&state=s1`,
      { headers: { cookie: sessionCookie } },
    );
    const csrfCookie = extractSetCookies(getAuth.headers)
      .map((c) => c.split(';')[0]!.trim())
      .find((c) => c.startsWith('ef_oauth_csrf='))!;
    const html = await getAuth.text();
    const sealed = /name="sealed"\s+value="([^"]+)"/.exec(html)![1]!;
    const csrf = /name="csrf"\s+value="([^"]+)"/.exec(html)![1]!;
    const postAuth = await dispatch('/oauth/authorize', {
      method: 'POST',
      headers: {
        cookie: `${sessionCookie}; ${csrfCookie}`,
        origin: 'https://hub.example.com',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ decision: 'approve', sealed, csrf }).toString(),
    });
    const code = new URL(postAuth.headers.get('location')!).searchParams.get('code')!;
    const tokRes = await dispatch('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id,
        redirect_uri: 'http://127.0.0.1:54321/cb',
        code_verifier: verifier,
      }).toString(),
    });
    assert.equal(tokRes.status, 200);
    const j = (await tokRes.json()) as { access_token: string; refresh_token: string };
    return { accessToken: j.access_token, refreshToken: j.refresh_token, clientId: client_id };
  };

  try {
    // Bare "12345" in GITHUB_ALLOWED_USERS must reject BOTH numeric ID 12345 AND login "12345"
    assert.equal((await signIn('code_bare_id')).status, 403);
    assert.equal((await signIn('code_bare_login')).status, 403);

    const founder = await signIn('code_founder');
    const alice = await signIn('code_alice');
    const charlie = await signIn('code_charlie_org');
    assert.ok(founder.sessionCookie && alice.sessionCookie && charlie.sessionCookie);

    // Verify `/admin/api/state` NEVER exposes `encryptedGhToken` or `gho_` token!
    const founderStateRes = await dispatch('/admin/api/state', { headers: { cookie: founder.sessionCookie! } });
    const founderStateText = await founderStateRes.text();
    assert.equal(founderStateText.includes('encryptedGhToken'), false, 'encryptedGhToken must never be exposed in /admin/api/state');
    assert.equal(founderStateText.includes('gho_secret_token_'), false);
    assert.equal(founderStateText.includes('ght1.'), false);

    const aliceTok = await mintOAuthTokens(alice.sessionCookie!);
    const charlieTok = await mintOAuthTokens(charlie.sessionCookie!);

    // H4 PART 1: Remove `alice` while `@trusted-org` REMAINS in GITHUB_ALLOWED_USERS!
    // Previously `if (allowlist.orgs.size > 0) return false;` let Alice keep using her session, access token, and refresh rotations!
    env.GITHUB_ALLOWED_USERS = '@trusted-org';

    assert.equal(
      (await dispatch('/admin/api/state', { headers: { cookie: alice.sessionCookie! } })).status,
      401,
      'Removing alice must immediately revoke her admin session even when @trusted-org is present',
    );
    assert.equal(
      (await dispatch('/v1/capabilities', { headers: { authorization: `Bearer ${aliceTok.accessToken}` } })).status,
      401,
      'Removing alice must immediately revoke her OAuth access token even when @trusted-org is present',
    );
    const aliceRefresh = await dispatch('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: aliceTok.refreshToken,
        client_id: aliceTok.clientId,
      }).toString(),
    });
    assert.equal(aliceRefresh.status, 400, 'Removing alice must immediately block refresh rotation');

    // Legacy user row without `admittedVia` is ALSO revoked when not directly matched even with `@trusted-org` present
    assert.equal(
      isGitHubUserDeAllowlisted(
        {
          userId: 'gh_777',
          githubId: '777',
          githubLogin: 'legacy-removed',
          role: 'member',
          createdAt: 1,
          lastLoginAt: 1,
        },
        env as never,
      ),
      true,
    );

    // Meanwhile Charlie (admitted via `@trusted-org`, still in `Trusted-Org` on GitHub) CAN rotate his refresh token!
    const orgCallsBeforeGoodRefresh = githubOrgsApiCalls;
    const charlieGoodRefresh = await dispatch('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: charlieTok.refreshToken,
        client_id: charlieTok.clientId,
      }).toString(),
    });
    assert.equal(charlieGoodRefresh.status, 200);
    assert.ok(githubOrgsApiCalls > orgCallsBeforeGoodRefresh, 'Refresh rotation must live-check GitHub /user/orgs');
    const charlieRotated1 = (await charlieGoodRefresh.json()) as { access_token: string; refresh_token: string };

    // H4 PART 2: Charlie is removed from `Trusted-Org` on GitHub while `@trusted-org` remains in Hub env!
    orgsByUserId.set(202, []);
    const charlieRevokedRefresh = await dispatch('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: charlieRotated1.refresh_token,
        client_id: charlieTok.clientId,
      }).toString(),
    });
    assert.equal(charlieRevokedRefresh.status, 400, 'Refresh must fail closed (400 invalid_grant) once removed from GitHub org');
    assert.equal(
      (await dispatch('/admin/api/state', { headers: { cookie: charlie.sessionCookie! } })).status,
      401,
      'Session epoch / de-allowlist update from failed org re-verification must invalidate Charlie session immediately',
    );
    assert.equal(
      (await dispatch('/v1/capabilities', { headers: { authorization: `Bearer ${charlieRotated1.access_token}` } })).status,
      401,
    );

    // H4 PART 3: Removing `@trusted-org` from `GITHUB_ALLOWED_USERS` revokes org-admitted users immediately without waiting
    orgsByUserId.set(202, ['Trusted-Org']);
    const charlie2 = await signIn('code_charlie_org');
    assert.ok(charlie2.sessionCookie);
    env.GITHUB_ALLOWED_USERS = 'bob';
    assert.equal((await dispatch('/admin/api/state', { headers: { cookie: charlie2.sessionCookie! } })).status, 401);

    // H4 PART 4: Missing `encryptedGhToken` fails closed in `reverifyGitHubOrgAdmission` + stale (> 5m) re-verification check
    const memStore = createMemoryOAuthStore();
    const userWithoutToken = await memStore.upsertUser!({
      userId: 'gh_555',
      githubId: '555',
      githubLogin: 'notoken',
      role: 'member',
      admittedVia: 'org',
      admittedOrg: 'trusted-org',
      orgVerifiedAt: Date.now() - GITHUB_ORG_REVERIFY_TTL_MS - 1_000,
      createdAt: 1,
      lastLoginAt: 1,
    });
    const missingTokCheck = await reverifyGitHubOrgAdmission({
      user: userWithoutToken,
      env: { ...env, GITHUB_ALLOWED_USERS: '@trusted-org' } as never,
      sessionSecret: TEST_SESSION_SECRET,
      store: memStore,
    });
    assert.equal(missingTokCheck.ok, false);
  } finally {
    coordinator.close();
    metaDb.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('R8-H5: Require explicit GITHUB_OWNER_ID, never auto-pin oldest owner, and forbid secondary owners from demoting/disabling/deleting any owner', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'ef-r8-h5-'));
  const coordinator = new LocalAgentHubCoordinator(join(tmpDir, 'hub.sqlite'));
  const ghUsersByCode = new Map<string, { id: number; login: string }>([
    ['code_founder_100', { id: 100, login: 'real-founder' }],
    ['code_coowner_201', { id: 201, login: 'alice-sec-owner' }],
    ['code_coowner_203', { id: 203, login: 'carol-sec-owner' }],
    ['code_member_204', { id: 204, login: 'dave-member' }],
  ]);
  const ghTokens = new Map<string, { id: number; login: string }>();

  const mockSafeFetch: typeof fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const u = new URL(req.url);
    if (u.origin === 'https://github.com' && u.pathname === '/login/oauth/access_token') {
      const form = new URLSearchParams(await req.text());
      const user = ghUsersByCode.get(form.get('code') ?? '');
      if (!user) return Response.json({ error: 'invalid_grant' }, { status: 400 });
      const tok = `gho_h5_${user.id}_${crypto.randomUUID()}`;
      ghTokens.set(tok, user);
      return Response.json({ access_token: tok, token_type: 'bearer', scope: 'read:user' });
    }
    if (u.origin === 'https://api.github.com' && u.pathname === '/user') {
      const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
      const user = m?.[1] ? ghTokens.get(m[1]) : undefined;
      if (!user) return Response.json({ message: 'Unauthorized' }, { status: 401 });
      return Response.json({ id: user.id, login: user.login });
    }
    return new Response('nf', { status: 404 });
  };

  const env: Record<string, unknown> = {
    AGENT_HUB: coordinator.asNamespace(),
    CALLER_TOKEN: TEST_OWNER_TOKEN,
    SESSION_SECRET: TEST_SESSION_SECRET,
    GITHUB_CLIENT_ID: 'Iv23liRound8H5',
    GITHUB_CLIENT_SECRET: 'ghs_round8_h5_secret_0123456789abcdef',
    GITHUB_OWNER_LOGIN: 'real-founder',
    // Intentionally omit GITHUB_OWNER_ID first!
    GITHUB_ALLOWED_USERS: 'alice-sec-owner,carol-sec-owner,dave-member',
    SIGNUP_MODE: 'invite_only',
    SAFE_PUBLIC_FETCH: mockSafeFetch,
    SAFE_FETCH: mockSafeFetch,
  };

  const dispatch = async (path: string, init?: RequestInit): Promise<Response> => {
    const req = new Request(`https://hub.example.com${path}`, init);
    return await (hubWorker as { fetch(r: Request, e: unknown): Promise<Response> }).fetch(req, env);
  };

  const signIn = async (code: string) => {
    const r1 = await dispatch('/admin/auth/github');
    assert.equal(r1.status, 302);
    const state = new URL(r1.headers.get('location')!).searchParams.get('state')!;
    const stateCookie = extractSetCookies(r1.headers)
      .map((c) => c.split(';')[0]!.trim())
      .find((c) => c.startsWith('__Host-ef_gh_oauth='))!;
    const r2 = await dispatch(`/admin/auth/github/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`, {
      headers: { cookie: stateCookie },
    });
    const cookie = extractSetCookies(r2.headers)
      .map((c) => c.split(';')[0]!.trim())
      .find((c) => c.startsWith(`${ADMIN_COOKIE_NAME}=`) && c.length > `${ADMIN_COOKIE_NAME}=`.length)!;
    const parsed = await verifyAdminSessionCookie(cookie, TEST_SESSION_SECRET);
    if (!parsed.ok) throw new Error('invalid cookie');
    return { cookie, csrf: parsed.csrf, role: parsed.role, userId: parsed.userId };
  };

  try {
    // 1. GITHUB_OWNER_LOGIN without GITHUB_OWNER_ID fails closed (503 owner_id_required)!
    const missingIdRes1 = await dispatch('/admin/auth/github');
    assert.equal(missingIdRes1.status, 503);
    const missingBody1 = (await missingIdRes1.json()) as { error: string; message: string };
    assert.equal(missingBody1.error, 'owner_id_required');
    assert.match(missingBody1.message, /GITHUB_OWNER_ID/);

    // SIGNUP_MODE=bootstrap_first without GITHUB_OWNER_ID ALSO fails closed (503 owner_id_required)!
    env.GITHUB_OWNER_LOGIN = '';
    env.SIGNUP_MODE = 'bootstrap_first';
    const missingIdBoot = await dispatch('/admin/auth/github');
    assert.equal(missingIdBoot.status, 503);
    assert.equal(((await missingIdBoot.json()) as { error: string }).error, 'owner_id_required');

    // Callback also fails closed if GITHUB_OWNER_ID is missing/invalid when callback arrives
    const cbMissing = await handleGitHubOAuthCallback({
      request: new Request('https://hub.example.com/admin/auth/github/callback?code=x&state=y'),
      url: new URL('https://hub.example.com/admin/auth/github/callback?code=x&state=y'),
      env: env as never,
      oauthStore: createMemoryOAuthStore(),
      serviceName: 'EdgeFetch Hub',
    });
    assert.equal(cbMissing.outcome, 'owner_id_required');
    assert.equal(cbMissing.response.status, 503);

    // 2. When NEITHER GITHUB_OWNER_ID NOR GITHUB_OWNER_LOGIN is set (CALLER_TOKEN owner + invited GitHub members),
    // GitHub sign-in works strictly as `role: 'member'`, NEVER granting `owner`!
    env.SIGNUP_MODE = 'invite_only';
    const aliceInitial = await signIn('code_coowner_201');
    const carolInitial = await signIn('code_coowner_203');
    assert.equal(aliceInitial.role, 'member');
    assert.equal(carolInitial.role, 'member');

    // CALLER_TOKEN owner signs in via `/admin/login` and promotes BOTH Alice (`gh_201`) and Carol (`gh_203`) to `owner`
    // BEFORE the real GitHub founder (`gh_100`) has EVER signed in!
    const callerLogin = await dispatch('/admin/login', {
      method: 'POST',
      headers: { origin: 'https://hub.example.com', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: TEST_OWNER_TOKEN }).toString(),
    });
    const callerCookie = extractSetCookies(callerLogin.headers)[0]!.split(';')[0]!.trim();
    const callerSession = await verifyAdminSessionCookie(callerCookie, TEST_SESSION_SECRET);
    assert.equal(callerSession.ok, true);
    if (!callerSession.ok) throw new Error('caller cookie invalid');

    // 3. Operator sets explicit `GITHUB_OWNER_ID='100'` and `GITHUB_OWNER_LOGIN='real-founder'` BEFORE `gh_100` has ever signed in,
    // and promotes Alice (`gh_201`) and Carol (`gh_203`) as founder-approved co-owners (`promoted_by_owner_id = '100'`).
    // Previously `fallbackExistingOwner` auto-pinned `gh_201` (oldest owner row) and LOCKED OUT `gh_100`!
    env.GITHUB_OWNER_ID = '100';
    env.GITHUB_OWNER_LOGIN = 'real-founder';

    for (const uid of ['gh_201', 'gh_203']) {
      const p = await dispatch('/admin/api/users/role', {
        method: 'POST',
        headers: {
          cookie: callerCookie,
          origin: 'https://hub.example.com',
          'x-csrf-token': callerSession.csrf,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ userId: uid, role: 'owner' }),
      });
      assert.equal(p.status, 200);
    }

    const realFounder = await signIn('code_founder_100');
    assert.equal(realFounder.userId, 'gh_100');
    assert.equal(realFounder.role, 'owner');

    const aliceCoOwner = await signIn('code_coowner_201');
    assert.equal(aliceCoOwner.role, 'owner');

    // 4. Secondary owner Alice (`gh_201`) CANNOT demote, disable, or delete immutable founder `gh_100` OR co-owner Carol `gh_203`!
    for (const [path, method, body] of [
      ['/admin/api/users/role', 'POST', { userId: 'gh_100', role: 'member' }],
      ['/admin/api/users/gh_100', 'PATCH', { disabled: true }],
      ['/admin/api/users/delete', 'POST', { userId: 'gh_100' }],
      ['/admin/api/users/gh_100', 'DELETE', {}],
      ['/admin/api/users/role', 'POST', { userId: 'gh_203', role: 'member' }],
      ['/admin/api/users/gh_203', 'PATCH', { disabled: true }],
      ['/admin/api/users/delete', 'POST', { userId: 'gh_203' }],
      ['/admin/api/users/gh_203', 'DELETE', {}],
    ] as const) {
      const res = await dispatch(path, {
        method,
        headers: {
          cookie: aliceCoOwner.cookie,
          origin: 'https://hub.example.com',
          'x-csrf-token': aliceCoOwner.csrf,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      assert.equal(res.status, 403, `Secondary owner must get 403 on ${method} ${path}`);
    }

    // 5. Immutable founder `gh_100` CAN demote Carol (`gh_203`) and delete Alice (`gh_201`), while NOBODY can delete `gh_100` or `'owner'`!
    const founderDemoteCarol = await dispatch('/admin/api/users/role', {
      method: 'POST',
      headers: {
        cookie: realFounder.cookie,
        origin: 'https://hub.example.com',
        'x-csrf-token': realFounder.csrf,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ userId: 'gh_203', role: 'member' }),
    });
    assert.equal(founderDemoteCarol.status, 200);

    const founderDeleteAlice = await dispatch('/admin/api/users/gh_201', {
      method: 'DELETE',
      headers: {
        cookie: realFounder.cookie,
        origin: 'https://hub.example.com',
        'x-csrf-token': realFounder.csrf,
      },
    });
    assert.equal(founderDeleteAlice.status, 200);
    assert.equal((await dispatch('/admin/api/state', { headers: { cookie: aliceCoOwner.cookie } })).status, 401);

    // Even `CALLER_TOKEN` `'owner'` cannot delete `gh_100` (immutable configured founder)!
    const callerDeleteFounder = await dispatch('/admin/api/users/gh_100', {
      method: 'DELETE',
      headers: {
        cookie: callerCookie,
        origin: 'https://hub.example.com',
        'x-csrf-token': callerSession.csrf,
      },
    });
    assert.equal(callerDeleteFounder.status, 403);
  } finally {
    coordinator.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('R8-Crawl-Isolation & Per-User Quotas: Non-owner crawls write ONLY private R2/D1 keys; per-user scrape/interact/agent concurrency caps return 429 with Retry-After: 2', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'ef-r8-crawl-quota-'));
  const coordinator = new LocalAgentHubCoordinator(join(tmpDir, 'hub.sqlite'));
  const metaDb = new NodeSqliteD1Database(':memory:', [
    { name: 'meta/0001_tracking.sql', sql: meta0001 },
    { name: 'meta/0002_multiuser.sql', sql: meta0002 },
  ]);
  const searchDb = new NodeSqliteD1Database(':memory:', [{ name: 'search/0001_fts.sql', sql: search0001 }]);
  const artifacts = new NodeFsR2Bucket(join(tmpDir, 'r2'));
  const recordedR2PutKeys: string[] = [];
  const origPut = artifacts.put.bind(artifacts);
  artifacts.put = (async (key: string, value: unknown, options?: unknown) => {
    recordedR2PutKeys.push(key);
    return await origPut(key, value as never, options as never);
  }) as typeof artifacts.put;

  let gatePromise: Promise<void> | null = null;

  const ghTokens = new Map<string, { id: number; login: string }>();
  const mockSafeFetch: typeof fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const u = new URL(req.url);
    if (u.origin === 'https://github.com' && u.pathname === '/login/oauth/access_token') {
      const tok = 'gho_alice_crawl_201';
      ghTokens.set(tok, { id: 201, login: 'alice' });
      return Response.json({ access_token: tok, token_type: 'bearer', scope: 'read:user' });
    }
    if (u.origin === 'https://api.github.com' && u.pathname === '/user') {
      return Response.json({ id: 201, login: 'alice' });
    }
    if (u.pathname === '/robots.txt') {
      return new Response('User-agent: *\nAllow: /\n', { status: 200 });
    }
    if (u.pathname === '/sitemap.xml' || u.pathname === '/sitemap-index.xml' || u.pathname === '/llms.txt') {
      return new Response('not found', { status: 404 });
    }
    if (gatePromise) {
      await gatePromise;
    }
    if (u.origin === 'https://llm.slow.example') {
      return Response.json({
        choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: '{"ok":true}' } }],
      });
    }
    return new Response(
      `<html><head><title>Confidential Tenant Page</title></head><body><main><h1>Tenant Alpha Secret</h1><p>PRIVATE_CRAWL_MARKER_8842 on ${u.href}</p></main></body></html>`,
      { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } },
    );
  };

  const pendingWaitUntil: Promise<unknown>[] = [];
  const ctx = {
    waitUntil(p: Promise<unknown>) {
      pendingWaitUntil.push(p);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;

  const env: Record<string, unknown> = {
    AGENT_HUB: coordinator.asNamespace(),
    META: metaDb,
    SEARCH: searchDb,
    ARTIFACTS: artifacts,
    CALLER_TOKEN: TEST_OWNER_TOKEN,
    SESSION_SECRET: TEST_SESSION_SECRET,
    GITHUB_CLIENT_ID: 'Iv23liRound8Crawl',
    GITHUB_CLIENT_SECRET: 'ghs_round8_crawl_secret_0123456789abcdef',
    GITHUB_ALLOWED_USERS: 'alice',
    SIGNUP_MODE: 'invite_only',
    ROBOTS_BYPASS_HOSTS: 'slow.example.com,priv-crawl.example.com',
    EDGEFETCH_LLM_PROVIDER: 'openai',
    EDGEFETCH_LLM_BASE_URL: 'https://llm.slow.example/v1',
    EDGEFETCH_LLM_API_KEY: 'sk-mock-llm-key-0123456789abcdef',
    EDGEFETCH_LLM_MODEL: 'gpt-4o-mini',
    SAFE_PUBLIC_FETCH: mockSafeFetch,
    SAFE_FETCH: mockSafeFetch,
  };

  const dispatch = async (path: string, init?: RequestInit): Promise<Response> => {
    const req = new Request(`https://hub.example.com${path}`, init);
    return await (hubWorker as { fetch(r: Request, e: unknown, c?: ExecutionContext): Promise<Response> }).fetch(req, env, ctx);
  };

  try {
    // Sign in Alice (`gh_201`, role='member') and mint OAuth token
    const r1 = await dispatch('/admin/auth/github');
    const state = new URL(r1.headers.get('location')!).searchParams.get('state')!;
    const stateCookie = extractSetCookies(r1.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith('__Host-ef_gh_oauth='))!;
    const r2 = await dispatch(`/admin/auth/github/callback?code=c1&state=${encodeURIComponent(state)}`, { headers: { cookie: stateCookie } });
    const aliceCookie = extractSetCookies(r2.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith(`${ADMIN_COOKIE_NAME}=`))!;

    const reg = await dispatch('/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Alice CLI', redirect_uris: ['http://127.0.0.1:54321/cb'] }),
    });
    const { client_id } = (await reg.json()) as { client_id: string };
    const verifier = 'verifier_' + crypto.randomUUID().replace(/-/g, '') + '_0123456789abcdef';
    const challenge = await sha256Base64Url(verifier);
    const authGet = await dispatch(
      `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:54321/cb')}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256&scope=crawl:read+crawl:fetch&state=s1`,
      { headers: { cookie: aliceCookie } },
    );
    const csrfCookie = extractSetCookies(authGet.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith('ef_oauth_csrf='))!;
    const html = await authGet.text();
    const sealed = /name="sealed"\s+value="([^"]+)"/.exec(html)![1]!;
    const csrf = /name="csrf"\s+value="([^"]+)"/.exec(html)![1]!;
    const postAuth = await dispatch('/oauth/authorize', {
      method: 'POST',
      headers: { cookie: `${aliceCookie}; ${csrfCookie}`, origin: 'https://hub.example.com', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ decision: 'approve', sealed, csrf }).toString(),
    });
    const code = new URL(postAuth.headers.get('location')!).searchParams.get('code')!;
    const tokRes = await dispatch('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id, redirect_uri: 'http://127.0.0.1:54321/cb', code_verifier: verifier }).toString(),
    });
    const { access_token: aliceAccess } = (await tokRes.json()) as { access_token: string };
    const aliceAuth = { authorization: `Bearer ${aliceAccess}`, 'content-type': 'application/json' };
    const ownerAuth = { authorization: `Bearer ${TEST_OWNER_TOKEN}`, 'content-type': 'application/json' };

    // 1. Non-owner crawl (`gh_201`) MUST write ONLY `private/gh_201/derived/...` keys and ZERO shared `META` rows!
    recordedR2PutKeys.length = 0;
    const crawlRes = await dispatch('/v1/crawl', {
      method: 'POST',
      headers: aliceAuth,
      body: JSON.stringify({
        url: 'https://priv-crawl.example.com/secret-doc',
        limit: 1,
        sitemap: 'skip',
        collectionId: 'team-kb',
        sync: true,
      }),
    });
    assert.equal(crawlRes.status, 200);
    const { id: crawlId } = (await crawlRes.json()) as { id: string };

    assert.ok(recordedR2PutKeys.length >= 1, 'Expected private derived Markdown object in R2');
    for (const k of recordedR2PutKeys) {
      assert.ok(k.startsWith('private/gh_201/derived/'), `Non-owner crawl wrote non-private R2 key: ${k}`);
    }
    const sharedArtifactsCount = await metaDb.prepare('SELECT COUNT(*) AS c FROM artifacts').first<{ c: number }>();
    const sharedDocsCount = await metaDb.prepare('SELECT COUNT(*) AS c FROM documents').first<{ c: number }>();
    const sharedFetchesCount = await metaDb.prepare('SELECT COUNT(*) AS c FROM fetches').first<{ c: number }>();
    assert.equal(sharedArtifactsCount?.c ?? 0, 0, 'Non-owner crawl must NEVER seed shared META artifacts');
    assert.equal(sharedDocsCount?.c ?? 0, 0, 'Non-owner crawl must NEVER seed shared META documents');
    assert.equal(sharedFetchesCount?.c ?? 0, 0, 'Non-owner crawl must NEVER seed shared META fetches');

    const aliceCrawlStatus = await dispatch(`/v1/crawl/${crawlId}`, { headers: aliceAuth });
    assert.equal(aliceCrawlStatus.status, 200);
    const aliceCrawlJson = (await aliceCrawlStatus.json()) as { fetchedCount: number; data: Array<{ visibility: string; markdown: string }> };
    assert.equal(aliceCrawlJson.fetchedCount, 1);
    assert.equal(aliceCrawlJson.data[0]?.visibility, 'private');
    assert.match(aliceCrawlJson.data[0]?.markdown ?? '', /PRIVATE_CRAWL_MARKER_8842/);

    // Alice's FTS5 search hits her private collection, while Owner searching `team-kb` sees 0 hits!
    const aliceSearch = (await (await dispatch('/v1/collections/team-kb/search?q=PRIVATE_CRAWL_MARKER_8842', { headers: aliceAuth })).json()) as { hits: unknown[] };
    assert.equal(aliceSearch.hits.length, 1);
    const ownerSearch = (await (await dispatch('/v1/collections/team-kb/search?q=PRIVATE_CRAWL_MARKER_8842', { headers: ownerAuth })).json()) as { hits: unknown[] };
    assert.equal(ownerSearch.hits.length, 0);

    // 2. Per-User Concurrency Quotas: `scrape` (max 16), `interact` (max 4), `agent` (max 4 including async background runs)
    let releaseGate!: () => void;
    gatePromise = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });

    // 2a. Hold 16 concurrent scrapes for `gh_201`; 17th REST `/v1/scrape`, `/v2/scrape`, and MCP `scrape` return 429 + Retry-After: 2
    const heldScrapes = Array.from({ length: 16 }, (_, idx) =>
      dispatch('/v1/scrape', {
        method: 'POST',
        headers: aliceAuth,
        body: JSON.stringify({ url: `https://slow.example.com/p-${idx}` }),
      }),
    );
    await new Promise((r) => setTimeout(r, 40));

    const scrape17 = await dispatch('/v1/scrape', {
      method: 'POST',
      headers: aliceAuth,
      body: JSON.stringify({ url: 'https://slow.example.com/overflow' }),
    });
    assert.equal(scrape17.status, 429);
    assert.equal(scrape17.headers.get('retry-after'), '2');
    assert.equal(((await scrape17.json()) as { error: string }).error, 'user_quota_exceeded');

    const v2Scrape17 = await dispatch('/v2/scrape', {
      method: 'POST',
      headers: aliceAuth,
      body: JSON.stringify({ url: 'https://slow.example.com/overflow-v2' }),
    });
    assert.equal(v2Scrape17.status, 429);
    assert.equal(v2Scrape17.headers.get('retry-after'), '2');

    // Owner is unaffected by Alice's full scrape quota!
    const ownerWhileAliceFull = dispatch('/v1/scrape', {
      method: 'POST',
      headers: ownerAuth,
      body: JSON.stringify({ url: 'https://slow.example.com/owner-ok' }),
    });

    releaseGate();
    const settledScrapes = await Promise.all([...heldScrapes, ownerWhileAliceFull]);
    assert.ok(settledScrapes.every((r) => r.status === 200));

    // 2b. Hold 4 concurrent `async: true` background `/v1/agent` runs for `gh_201`; 5th returns 429 user_quota_exceeded!
    gatePromise = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });
    const bgAgents = await Promise.all(
      Array.from({ length: 4 }, (_, i) =>
        dispatch('/v1/agent', {
          method: 'POST',
          headers: aliceAuth,
          body: JSON.stringify({ prompt: `Background research ${i}`, async: true, maxSteps: 1 }),
        }),
      ),
    );
    assert.ok(bgAgents.every((r) => r.status === 202));

    const agent5 = await dispatch('/v1/agent', {
      method: 'POST',
      headers: aliceAuth,
      body: JSON.stringify({ prompt: '5th background loop', async: true, maxSteps: 1 }),
    });
    assert.equal(agent5.status, 429);
    assert.equal(agent5.headers.get('retry-after'), '2');
    assert.equal(((await agent5.json()) as { error: string }).error, 'user_quota_exceeded');

    releaseGate();
    gatePromise = null;
    while (pendingWaitUntil.length > 0) {
      await Promise.allSettled(pendingWaitUntil.splice(0, pendingWaitUntil.length));
    }

    // After background runs finish, Alice's agent quota is released cleanly!
    const agentAfterRelease = await dispatch('/v1/agent', {
      method: 'POST',
      headers: aliceAuth,
      body: JSON.stringify({ prompt: 'Post-release agent run', maxSteps: 1 }),
    });
    assert.equal(agentAfterRelease.status, 200);
  } finally {
    gatePromise = null;
    while (pendingWaitUntil.length > 0) {
      await Promise.allSettled(pendingWaitUntil.splice(0, pendingWaitUntil.length));
    }
    coordinator.close();
    metaDb.close();
    searchDb.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('R8-MCP: mcp:call scrape scope enforcement, /v1/agent vault opt-in, v2.7.0 vault fallback, shared-hosting isolation, and strict tool/prop regex', async () => {
  // 1. Shared-hosting sibling tenant isolation (`evil.supabase.co` vs `victim.supabase.co`, `up.railway.app`, `a.run.app`, `ts.net`)
  assert.equal(extractRegistrableDomain('supabase.co'), null);
  assert.equal(extractRegistrableDomain('up.railway.app'), null);
  assert.equal(extractRegistrableDomain('workers.dev'), null);
  assert.equal(extractRegistrableDomain('ts.net'), null);
  assert.equal(extractRegistrableDomain('evil.supabase.co'), 'evil.supabase.co');
  assert.equal(extractRegistrableDomain('victim.supabase.co'), 'victim.supabase.co');
  assert.equal(extractRegistrableDomain('evil.up.railway.app'), 'evil.up.railway.app');
  assert.equal(extractRegistrableDomain('victim.up.railway.app'), 'victim.up.railway.app');
  assert.equal(extractRegistrableDomain('svc1.a.run.app'), 'svc1.a.run.app');
  assert.equal(extractRegistrableDomain('svc2.a.run.app'), 'svc2.a.run.app');
  assert.equal(isSharedHostingHostname('evil.supabase.co'), true);

  assert.equal(validateConnectorDomains(['supabase.co'], 'https://evil.supabase.co', true).ok, false);
  assert.equal(validateConnectorDomains(['up.railway.app'], 'https://evil.up.railway.app', true).ok, false);
  assert.equal(validateConnectorDomains(['victim.supabase.co'], 'https://evil.supabase.co', false).ok, false);
  assert.equal(validateConnectorDomains(['evil.supabase.co'], 'https://evil.supabase.co', false).ok, true);

  // Downstream OAuth PRM on `evil.supabase.co` pointing `authorization_servers` to sibling `victim.supabase.co` MUST fail closed!
  const siblingOAuthProbe = await probeRemoteMcpOAuthMetadata({
    remoteUrl: 'https://evil.supabase.co/mcp',
    selfHost: 'hub.example.com',
    fetchFn: async (input) => {
      const u = new URL(String(input));
      if (u.host === 'evil.supabase.co' && u.pathname.startsWith('/.well-known/oauth-protected-resource')) {
        return Response.json({
          resource: 'https://evil.supabase.co/mcp',
          authorization_servers: ['https://victim.supabase.co'],
        });
      }
      if (u.host === 'victim.supabase.co') {
        return Response.json({
          issuer: 'https://victim.supabase.co',
          authorization_endpoint: 'https://victim.supabase.co/authorize',
          token_endpoint: 'https://victim.supabase.co/token',
        });
      }
      return new Response('nf', { status: 404 });
    },
  });
  assert.equal(siblingOAuthProbe.supported, false, 'Shared-hosting sibling AS must never be trusted');

  const sameTenantSupabaseStart = await startDownstreamMcpOAuth({
    userId: 'gh_1',
    sessionCsrf: 'csrf_1',
    hubOrigin: 'https://hub.example.com',
    remoteUrl: 'https://victim.supabase.co/mcp',
    vaultMasterKey: TEST_VAULT_KEY,
    vaultStore: createMemoryMcpVaultStore(),
    selfHost: 'hub.example.com',
    fetchFn: async (input) => {
      const u = new URL(String(input));
      if (u.host === 'victim.supabase.co' && u.pathname.startsWith('/.well-known/oauth-protected-resource')) {
        return Response.json({
          resource: 'https://victim.supabase.co/mcp',
          authorization_servers: ['https://victim.supabase.co'],
        });
      }
      if (u.host === 'victim.supabase.co' && u.pathname === '/.well-known/oauth-authorization-server') {
        return Response.json({
          issuer: 'https://victim.supabase.co',
          authorization_endpoint: 'https://victim.supabase.co/oauth/authorize',
          token_endpoint: 'https://victim.supabase.co/oauth/token',
        });
      }
      return new Response('nf', { status: 404 });
    },
  });
  assert.equal(sameTenantSupabaseStart.ok, true, 'Exact same full hostname on shared hosting works cleanly');

  // 1b. Cross-origin / cross-subdomain OAuth Authorization Server requires explicit `confirmedAuthOrigin` (Item 8b)
  const crossSubFetch: typeof fetch = async (input) => {
    const u = new URL(String(input));
    if (u.origin === 'https://mcp.acme.example' && u.pathname.startsWith('/.well-known/oauth-protected-resource')) {
      return Response.json({
        resource: 'https://mcp.acme.example/mcp',
        authorization_servers: ['https://auth.acme.example'],
      });
    }
    if (u.origin === 'https://auth.acme.example' && u.pathname === '/.well-known/oauth-authorization-server') {
      return Response.json({
        issuer: 'https://auth.acme.example',
        authorization_endpoint: 'https://auth.acme.example/oauth/authorize',
        token_endpoint: 'https://auth.acme.example/oauth/token',
      });
    }
    return new Response('nf', { status: 404 });
  };

  const unconfirmedProbe = await probeRemoteMcpOAuthMetadata({
    remoteUrl: 'https://mcp.acme.example/mcp',
    selfHost: 'hub.example.com',
    fetchFn: crossSubFetch,
  });
  assert.equal(unconfirmedProbe.supported, false);
  assert.equal(unconfirmedProbe.error, 'cross_origin_auth_confirmation_required');
  assert.equal(unconfirmedProbe.authOrigin, 'https://auth.acme.example');
  assert.equal(unconfirmedProbe.connectorOrigin, 'https://mcp.acme.example');

  const unconfirmedStart = await startDownstreamMcpOAuth({
    userId: 'gh_1',
    sessionCsrf: 'csrf_1',
    hubOrigin: 'https://hub.example.com',
    remoteUrl: 'https://mcp.acme.example/mcp',
    vaultMasterKey: TEST_VAULT_KEY,
    vaultStore: createMemoryMcpVaultStore(),
    selfHost: 'hub.example.com',
    fetchFn: crossSubFetch,
  });
  assert.equal(unconfirmedStart.ok, false);
  if (!unconfirmedStart.ok) {
    assert.equal(unconfirmedStart.error, 'cross_origin_auth_confirmation_required');
    assert.equal(unconfirmedStart.authOrigin, 'https://auth.acme.example');
    assert.equal(unconfirmedStart.connectorOrigin, 'https://mcp.acme.example');
  }

  const confirmedStart = await startDownstreamMcpOAuth({
    userId: 'gh_1',
    sessionCsrf: 'csrf_1',
    hubOrigin: 'https://hub.example.com',
    remoteUrl: 'https://mcp.acme.example/mcp',
    confirmedAuthOrigin: 'https://auth.acme.example',
    vaultMasterKey: TEST_VAULT_KEY,
    vaultStore: createMemoryMcpVaultStore(),
    selfHost: 'hub.example.com',
    fetchFn: crossSubFetch,
  });
  assert.equal(confirmedStart.ok, true, 'Explicitly confirmed cross-origin OAuth AS must be accepted');

  // 2. Restore v2.7.0 vault ciphertext decryption compatibility AND auto-reseal to v2.7.1+ length-prefixed AAD on first read (Item 7)
  const legacyCiphertext = await sealLegacyV270Ciphertext({
    vaultMasterKey: TEST_VAULT_KEY,
    userId: 'gh_1001',
    remoteOrigin: 'https://mcp.linear.app',
    payload: {
      kind: 'headers',
      pinnedUrl: 'https://mcp.linear.app/mcp',
      headers: { Authorization: 'Bearer v270_legacy_pat_secret' },
    },
  });
  const unsealedLegacy = await unsealVaultCredentials({
    vaultMasterKey: TEST_VAULT_KEY,
    userId: 'gh_1001',
    remoteOrigin: 'https://mcp.linear.app',
    remoteUrl: 'https://mcp.linear.app/mcp',
    ciphertext: legacyCiphertext,
  });
  assert.equal(unsealedLegacy.ok, true, 'v2.7.0 ciphertext must decrypt cleanly for clean userIds');
  if (unsealedLegacy.ok) {
    assert.equal(unsealedLegacy.payload.headers?.Authorization, 'Bearer v270_legacy_pat_secret');
    assert.ok(unsealedLegacy.resealedCiphertext, 'v2.7.0 fallback must produce resealedCiphertext');
    assert.notEqual(unsealedLegacy.resealedCiphertext, legacyCiphertext);
  }

  // Prove that after 1 federated vault read, `vaultStore` automatically persists the rotated v2.7.1+ length-prefixed ciphertext!
  const autoResealStore = createMemoryMcpVaultStore();
  await autoResealStore.upsertServer({
    id: 'm_legacy_1',
    userId: 'gh_1001',
    slug: 'legacy-linear',
    name: 'Legacy Linear',
    remoteUrl: 'https://mcp.linear.app/mcp',
    remoteOrigin: 'https://mcp.linear.app',
    transport: 'streamable-http',
    authType: 'headers',
    encryptedCredentials: legacyCiphertext,
    authSummary: { authMode: 'bearer', headerNames: ['Authorization'], maskedBadge: 'Bearer' },
    domains: ['linear.app'],
    cachedTools: [{ name: 'ping', readOnlyHint: true, inputSchema: { type: 'object', properties: {} } }],
    toolCount: 1,
    enabled: true,
    lastVerifiedAt: 1,
    lastError: null,
    createdAt: 1,
    updatedAt: 1,
  });
  const legacyCallOut = await executeFederatedMcpQuery({
    userId: 'gh_1001',
    input: { action: 'call_tool', server: 'legacy-linear', tool: 'ping', arguments: {} },
    vaultStore: autoResealStore,
    vaultMasterKey: TEST_VAULT_KEY,
    selfHost: 'hub.example.com',
    fetchFn: async (_i, init) => {
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer v270_legacy_pat_secret');
      const rpc = JSON.parse(String(init?.body ?? '{}')) as { id?: string | number };
      return Response.json({ jsonrpc: '2.0', id: rpc.id, result: { content: [{ type: 'text', text: 'pong' }] } });
    },
  });
  assert.equal(legacyCallOut.status, 200);
  const rotatedServer = await autoResealStore.getServer('gh_1001', 'legacy-linear');
  assert.ok(rotatedServer?.encryptedCredentials);
  assert.notEqual(rotatedServer.encryptedCredentials, legacyCiphertext, 'Stored ciphertext must be rotated after 1 read');
  const postRotateUnseal = await unsealVaultCredentials({
    vaultMasterKey: TEST_VAULT_KEY,
    userId: 'gh_1001',
    remoteOrigin: 'https://mcp.linear.app',
    remoteUrl: 'https://mcp.linear.app/mcp',
    ciphertext: rotatedServer.encryptedCredentials!,
  });
  assert.equal(postRotateUnseal.ok, true);
  if (postRotateUnseal.ok) {
    assert.equal(postRotateUnseal.resealedCiphertext, undefined, 'Rotated ciphertext must decrypt natively on v2.7.1+ AAD path');
  }
  // Wrong userId, wrong remoteUrl path, or userId with `|` / `:` must still fail closed!
  assert.equal(
    (
      await unsealVaultCredentials({
        vaultMasterKey: TEST_VAULT_KEY,
        userId: 'gh_2002',
        remoteOrigin: 'https://mcp.linear.app',
        ciphertext: legacyCiphertext,
      })
    ).ok,
    false,
  );
  assert.equal(
    (
      await unsealVaultCredentials({
        vaultMasterKey: TEST_VAULT_KEY,
        userId: 'gh_1001',
        remoteOrigin: 'https://mcp.linear.app',
        remoteUrl: 'https://mcp.linear.app/evil-path',
        ciphertext: legacyCiphertext,
      })
    ).ok,
    false,
  );
  const ambiguousLegacy = await sealLegacyV270Ciphertext({
    vaultMasterKey: TEST_VAULT_KEY,
    userId: 'user:ambig',
    remoteOrigin: 'https://mcp.linear.app',
    payload: { kind: 'headers', headers: { Authorization: 'Bearer X' } },
  });
  assert.equal(
    (
      await unsealVaultCredentials({
        vaultMasterKey: TEST_VAULT_KEY,
        userId: 'user:ambig',
        remoteOrigin: 'https://mcp.linear.app',
        ciphertext: ambiguousLegacy,
      })
    ).ok,
    false,
    'Legacy v2.7.0 fallback must be refused when userId contains : or |',
  );

  // 3. Strict tool & property identifier hygiene (`/^[A-Za-z0-9_.-]{1,64}$/`) across vault, federation, and agent-runner
  const dirtyDefs = sanitizeRemoteMcpToolDefs([
    {
      name: 'bad:colon:tool',
      inputSchema: { type: 'object', properties: { url: { type: 'string' } } },
    },
    {
      name: 'inject space tool',
      inputSchema: { type: 'object', properties: { url: { type: 'string' } } },
    },
    {
      name: 'a'.repeat(65),
      inputSchema: { type: 'object', properties: { url: { type: 'string' } } },
    },
    {
      name: 'valid_tool.v1-read',
      readOnlyHint: true,
      inputSchema: {
        type: 'object',
        properties: {
          query_text: { type: 'string' },
          'bad:prop': { type: 'string' },
          'prop with spaces': { type: 'string' },
          ['p'.repeat(65)]: { type: 'string' },
        },
        required: ['query_text', 'bad:prop'],
      },
    },
  ]);
  assert.equal(dirtyDefs.tools.length, 1);
  assert.equal(dirtyDefs.tools[0]!.name, 'valid_tool.v1-read');
  assert.deepEqual(Object.keys(dirtyDefs.tools[0]!.inputSchema.properties ?? {}), ['query_text']);
  assert.deepEqual(dirtyDefs.tools[0]!.inputSchema.required, ['query_text']);

  const vaultStore = createMemoryMcpVaultStore();
  const sealedConn = await sealVaultCredentials({
    vaultMasterKey: TEST_VAULT_KEY,
    userId: 'gh_201',
    remoteOrigin: 'https://mcp.linear.app',
    payload: {
      kind: 'headers',
      pinnedOrigin: 'https://mcp.linear.app',
      pinnedUrl: 'https://mcp.linear.app/mcp',
      headers: { Authorization: 'Bearer lin_tok_201' },
    },
  });
  assert.equal(sealedConn.ok, true);
  await vaultStore.upsertServer({
    id: 'm_1',
    userId: 'gh_201',
    slug: 'linear',
    name: 'Linear',
    remoteUrl: 'https://mcp.linear.app/mcp',
    remoteOrigin: 'https://mcp.linear.app',
    transport: 'streamable-http',
    authType: 'headers',
    encryptedCredentials: sealedConn.ciphertext,
    authSummary: { authMode: 'bearer', headerNames: ['Authorization'], maskedBadge: 'Bearer' },
    domains: ['linear.app'],
    autoRouteScrape: true,
    cachedTools: [
      {
        name: 'get_issue',
        readOnlyHint: true,
        inputSchema: { type: 'object', properties: { url: { type: 'string' }, 'evil:key': { type: 'string' } } },
      },
      {
        name: 'evil:tool',
        readOnlyHint: true,
        inputSchema: { type: 'object', properties: { url: { type: 'string' } } },
      },
    ],
    toolCount: 2,
    enabled: true,
    lastVerifiedAt: Date.now(),
    lastError: null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });
  const storedLinear = await vaultStore.getServer('gh_201', 'linear');
  assert.equal(storedLinear?.cachedTools.length, 1, 'Vault upsert must strip invalid tool names');
  assert.deepEqual(Object.keys(storedLinear?.cachedTools[0]?.inputSchema.properties ?? {}), ['url']);
  assert.equal(filterSafeCachedMcpTools([{ name: 'bad:name', inputSchema: {} }]).length, 0);

  // Also verify `call_tool` rejects colon/space tool names with 400
  const badToolCall = await executeFederatedMcpQuery({
    userId: 'gh_201',
    input: { action: 'call_tool', server: 'linear', tool: 'bad:tool' },
    vaultStore,
    vaultMasterKey: TEST_VAULT_KEY,
    selfHost: 'hub.example.com',
  });
  assert.equal(badToolCall.status, 400);

  // 4. `/v1/agent` vault connectors MUST be strictly opt-in (`preferMcp`, `useConnectedMcp`, or `mcpServers`)!
  let capturedToolsDefault: string[] = [];
  let capturedPromptDefault = '';
  const defaultAgentOut = await startOrExecuteAgentCall({
    payload: {
      prompt: 'Summarize https://linear.app/acme/issue/ENG-9',
      urls: ['https://linear.app/acme/issue/ENG-9'],
    },
    env: {
      OPENAI_API_KEY: 'sk-mock',
      VAULT_MASTER_KEY: TEST_VAULT_KEY,
    },
    executeHubFetch: async () => ({ status: 200, via: 'auto', bodyText: '{"results":[]}' }),
    userId: 'gh_201',
    vaultStore,
    selfHost: 'hub.example.com',
    llmFetchFn: async (_i, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as {
        messages: Array<{ role: string; content: string }>;
        tools?: Array<{ function?: { name: string }; name?: string }>;
      };
      capturedPromptDefault = body.messages.find((m) => m.role === 'system')?.content ?? '';
      capturedToolsDefault = (body.tools ?? []).map((t) => t.function?.name ?? t.name ?? '');
      return Response.json({
        choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'Done without MCP.' } }],
      });
    },
  });
  assert.equal(defaultAgentOut.kind, 'json');
  assert.equal(capturedToolsDefault.includes('query_mcp'), false, 'Default /v1/agent run must NOT expose query_mcp without opt-in');
  assert.equal(capturedPromptDefault.includes('TIER-1 CONNECTED MCP ROUTING'), false);

  // 5. Full E2E `mcp:call` scope enforcement on `/v1/scrape`, `/mcp` `scrape`, and `/v1/agent`!
  const tmpDir = mkdtempSync(join(tmpdir(), 'ef-r8-mcp-scope-'));
  const coordinator = new LocalAgentHubCoordinator(join(tmpDir, 'hub.sqlite'));
  let mcpDownstreamHits = 0;
  let httpScrapeHits = 0;
  const ghTokMap = new Map<string, { id: number; login: string }>();

  const mockHubFetch: typeof fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const u = new URL(req.url);
    if (u.origin === 'https://github.com' && u.pathname === '/login/oauth/access_token') {
      const tok = 'gho_scope_201';
      ghTokMap.set(tok, { id: 201, login: 'alice' });
      return Response.json({ access_token: tok, token_type: 'bearer', scope: 'read:user' });
    }
    if (u.origin === 'https://api.github.com' && u.pathname === '/user') {
      return Response.json({ id: 201, login: 'alice' });
    }
    if (u.origin === 'https://mcp.linear.app' && u.pathname === '/mcp') {
      const rpc = JSON.parse(await req.text()) as { id?: string | number; method: string };
      if (rpc.method === 'initialize') return Response.json({ jsonrpc: '2.0', id: rpc.id, result: {} });
      if (rpc.method === 'tools/list') {
        return Response.json({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            tools: [
              {
                name: 'get_issue',
                annotations: { readOnlyHint: true },
                inputSchema: { type: 'object', properties: { url: { type: 'string' } } },
              },
            ],
          },
        });
      }
      if (rpc.method === 'tools/call') {
        mcpDownstreamHits++;
        return Response.json({
          jsonrpc: '2.0',
          id: rpc.id,
          result: { content: [{ type: 'text', text: 'FROM_CONNECTED_MCP_SERVER' }] },
        });
      }
    }
    if (u.pathname === '/robots.txt') return new Response('User-agent: *\nAllow: /\n', { status: 200 });
    httpScrapeHits++;
    return new Response('<html><body><main>FROM_NORMAL_HTTP_SCRAPE</main></body></html>', {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  };

  const env: Record<string, unknown> = {
    AGENT_HUB: coordinator.asNamespace(),
    CALLER_TOKEN: TEST_OWNER_TOKEN,
    SESSION_SECRET: TEST_SESSION_SECRET,
    VAULT_MASTER_KEY: TEST_VAULT_KEY,
    GITHUB_CLIENT_ID: 'Iv23liRound8Scope',
    GITHUB_CLIENT_SECRET: 'ghs_round8_scope_secret_0123456789abcdef',
    GITHUB_ALLOWED_USERS: 'alice',
    SIGNUP_MODE: 'invite_only',
    SAFE_PUBLIC_FETCH: mockHubFetch,
    SAFE_FETCH: mockHubFetch,
  };

  const dispatch = async (path: string, init?: RequestInit): Promise<Response> => {
    const req = new Request(`https://hub.example.com${path}`, init);
    return await (hubWorker as { fetch(r: Request, e: unknown): Promise<Response> }).fetch(req, env);
  };

  try {
    const r1 = await dispatch('/admin/auth/github');
    const st = new URL(r1.headers.get('location')!).searchParams.get('state')!;
    const stCookie = extractSetCookies(r1.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith('__Host-ef_gh_oauth='))!;
    const r2 = await dispatch(`/admin/auth/github/callback?code=c&state=${encodeURIComponent(st)}`, { headers: { cookie: stCookie } });
    const aliceCookie = extractSetCookies(r2.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith(`${ADMIN_COOKIE_NAME}=`))!;
    const aliceParsed = await verifyAdminSessionCookie(aliceCookie, TEST_SESSION_SECRET);
    assert.equal(aliceParsed.ok, true);
    if (!aliceParsed.ok) throw new Error('alice session invalid');

    // Connect Linear MCP with `autoRouteScrape: true`!
    const connRes = await dispatch('/admin/api/mcp/connect', {
      method: 'POST',
      headers: {
        cookie: aliceCookie,
        origin: 'https://hub.example.com',
        'x-csrf-token': aliceParsed.csrf,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Linear',
        slug: 'linear',
        remoteUrl: 'https://mcp.linear.app/mcp',
        bearerToken: 'lin_secret_201',
        domains: ['linear.app'],
        autoRouteScrape: true,
      }),
    });
    assert.equal(connRes.status, 200);

    const mintWithScope = async (scopeStr: string) => {
      const reg = await dispatch('/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_name: 'Scope CLI', redirect_uris: ['http://127.0.0.1:54321/cb'] }),
      });
      const { client_id } = (await reg.json()) as { client_id: string };
      const verifier = 'verifier_' + crypto.randomUUID().replace(/-/g, '') + '_0123456789abcdef';
      const challenge = await sha256Base64Url(verifier);
      const g = await dispatch(
        `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:54321/cb')}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256&scope=${encodeURIComponent(scopeStr)}&state=s`,
        { headers: { cookie: aliceCookie } },
      );
      const csrfC = extractSetCookies(g.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith('ef_oauth_csrf='))!;
      const h = await g.text();
      const sealed = /name="sealed"\s+value="([^"]+)"/.exec(h)![1]!;
      const csrf = /name="csrf"\s+value="([^"]+)"/.exec(h)![1]!;
      const p = await dispatch('/oauth/authorize', {
        method: 'POST',
        headers: { cookie: `${aliceCookie}; ${csrfC}`, origin: 'https://hub.example.com', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ decision: 'approve', sealed, csrf }).toString(),
      });
      const code = new URL(p.headers.get('location')!).searchParams.get('code')!;
      const t = await dispatch('/oauth/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id, redirect_uri: 'http://127.0.0.1:54321/cb', code_verifier: verifier }).toString(),
      });
      return ((await t.json()) as { access_token: string }).access_token;
    };

    const fetchOnlyTok = await mintWithScope('crawl:read crawl:fetch');
    const mcpCallTok = await mintWithScope('crawl:read crawl:fetch mcp:call');

    // `crawl:fetch`-only token + `preferMcp: true` -> 403 insufficient_scope (on `/v1/scrape`, `/v2/scrape`, `/mcp` `scrape`, and `/v1/agent`)!
    const restPreferDenied = await dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: `Bearer ${fetchOnlyTok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://linear.app/acme/issue/ENG-1', preferMcp: true }),
    });
    assert.equal(restPreferDenied.status, 403);
    assert.equal(((await restPreferDenied.json()) as { error: string }).error, 'insufficient_scope');

    const v2PreferDenied = await dispatch('/v2/scrape', {
      method: 'POST',
      headers: { authorization: `Bearer ${fetchOnlyTok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://linear.app/acme/issue/ENG-1', preferMcp: true }),
    });
    assert.equal(v2PreferDenied.status, 403);

    const mcpScrapePreferDenied = await dispatch('/mcp', {
      method: 'POST',
      headers: { authorization: `Bearer ${fetchOnlyTok}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'scrape', arguments: { url: 'https://linear.app/acme/issue/ENG-1', preferMcp: true } },
      }),
    });
    const mcpPreferJson = (await mcpScrapePreferDenied.json()) as { result: { isError?: boolean; content: Array<{ text: string }> } };
    assert.equal(mcpPreferJson.result.isError, true);
    assert.match(mcpPreferJson.result.content[0]!.text, /insufficient_scope/);

    const agentOptInWithoutScope = await dispatch('/v1/agent', {
      method: 'POST',
      headers: { authorization: `Bearer ${fetchOnlyTok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ prompt: 'Read ENG-1', urls: ['https://linear.app/acme/issue/ENG-1'], useConnectedMcp: true }),
    });
    assert.equal(agentOptInWithoutScope.status, 403);
    assert.equal(((await agentOptInWithoutScope.json()) as { error: string }).error, 'insufficient_scope');
    assert.equal(mcpDownstreamHits, 0, 'Zero MCP calls may occur without mcp:call scope');

    // `crawl:fetch`-only token calling `/v1/scrape` WITHOUT `preferMcp` skips `autoRouteScrape` MCP and runs normal HTTP scrape!
    const normalHttpScrape = await dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: `Bearer ${fetchOnlyTok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://linear.app/acme/issue/ENG-1' }),
    });
    assert.equal(normalHttpScrape.status, 200);
    assert.match(((await normalHttpScrape.json()) as { markdown: string }).markdown, /FROM_NORMAL_HTTP_SCRAPE/);
    assert.equal(mcpDownstreamHits, 0);
    assert.ok(httpScrapeHits >= 1);

    // Token WITH `mcp:call` routes through connected MCP as expected!
    const mcpScopedScrape = await dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: `Bearer ${mcpCallTok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://linear.app/acme/issue/ENG-1', preferMcp: true }),
    });
    assert.equal(mcpScopedScrape.status, 200);
    assert.match(((await mcpScopedScrape.json()) as { markdown: string }).markdown, /FROM_CONNECTED_MCP_SERVER/);
    assert.equal(mcpDownstreamHits, 1);

    // Unused test import check for `testAndListRemoteMcpTools`
    assert.equal(typeof testAndListRemoteMcpTools, 'function');
  } finally {
    coordinator.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
