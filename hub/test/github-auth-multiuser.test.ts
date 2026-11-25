import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import metaSchema0001 from '../migrations/meta/0001_tracking.sql';
import metaSchema0002 from '../migrations/meta/0002_multiuser.sql';
import searchSchemaSql from '../migrations/search/0001_fts.sql';
import { NodeFsR2Bucket, NodeSqliteD1Database } from '../portable/node-adapters.ts';
import workerEntry from '../src/index.ts';
import { mintSessionJwt, verifySessionJwt } from '../src/github-auth.ts';
import { createSqliteOAuthStore, isAdminSessionRevoked, sha256Base64Url, verifyAdminSessionCookie } from '../src/oauth.ts';
import type { SqlStorageLike } from '../src/oauth.ts';

function createNodeSqlStorage(db: DatabaseSync): SqlStorageLike {
  return {
    exec(query: string, ...bindings: Array<string | number | null>) {
      const trimmed = query.trim();
      if (bindings.length === 0 && trimmed.includes(';') && !trimmed.toUpperCase().startsWith('SELECT')) {
        db.exec(query);
        return { toArray: () => [] };
      }
      const stmt = db.prepare(query);
      if (/^\s*(SELECT|PRAGMA|WITH)\b/i.test(trimmed)) {
        const rows = stmt.all(...bindings) as Record<string, unknown>[];
        return { toArray: () => rows };
      }
      stmt.run(...bindings);
      return { toArray: () => [] };
    },
  };
}

function makePkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function extractSetCookies(headers: Headers): string[] {
  const anyHeaders = headers as unknown as { getSetCookie?: () => string[] };
  if (typeof anyHeaders.getSetCookie === 'function') {
    const list = anyHeaders.getSetCookie();
    if (list.length > 0) return list;
  }
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

function cookiePairFromSetCookie(setCookies: string[], prefix: string): string {
  for (const sc of setCookies) {
    const first = sc.split(';')[0]?.trim() ?? '';
    if (first.startsWith(`${prefix}=`)) return first;
  }
  throw new Error(`Expected Set-Cookie starting with ${prefix}=, got: ${JSON.stringify(setCookies)}`);
}

interface MockGitHubUser {
  id: number;
  login: string;
  avatar_url?: string;
  orgs?: string[];
}

function createMockGitHubSafeFetch(params: {
  usersByCode: Record<string, MockGitHubUser>;
  expectedClientId: string;
  expectedClientSecret: string;
  recordedRequests?: Array<{ url: string; method: string; authHeader: string | null; bodyText: string }>;
  extraHandler?: (req: Request) => Promise<Response> | Response | null;
}): typeof fetch {
  const tokenToUser = new Map<string, MockGitHubUser>();
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const u = new URL(req.url);
    const bodyText = req.method === 'POST' ? await req.clone().text() : '';
    params.recordedRequests?.push({
      url: req.url,
      method: req.method,
      authHeader: req.headers.get('authorization'),
      bodyText,
    });

    if (u.origin === 'https://github.com' && u.pathname === '/login/oauth/access_token' && req.method === 'POST') {
      const form = new URLSearchParams(bodyText);
      const clientId = form.get('client_id') ?? '';
      const clientSecret = form.get('client_secret') ?? '';
      const code = form.get('code') ?? '';
      const codeVerifier = form.get('code_verifier') ?? '';
      if (clientId !== params.expectedClientId || clientSecret !== params.expectedClientSecret) {
        return Response.json({ error: 'invalid_client' }, { status: 401 });
      }
      if (!codeVerifier || codeVerifier.length < 43) {
        return Response.json({ error: 'invalid_grant', error_description: 'Missing PKCE code_verifier' }, { status: 400 });
      }
      const ghUser = params.usersByCode[code];
      if (!ghUser) {
        return Response.json({ error: 'bad_verification_code' }, { status: 400 });
      }
      const ghAccessToken = `gho_mock_${ghUser.login}_${randomBytes(12).toString('hex')}`;
      tokenToUser.set(ghAccessToken, ghUser);
      return Response.json(
        {
          access_token: ghAccessToken,
          token_type: 'bearer',
          scope: 'read:user,read:org',
        },
        { status: 200 },
      );
    }

    if (u.origin === 'https://api.github.com' && u.pathname === '/user' && req.method === 'GET') {
      const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
      const ghUser = m?.[1] ? tokenToUser.get(m[1]) : undefined;
      if (!ghUser) return Response.json({ message: 'Bad credentials' }, { status: 401 });
      return Response.json({
        id: ghUser.id,
        login: ghUser.login,
        avatar_url: ghUser.avatar_url ?? `https://avatars.githubusercontent.com/u/${ghUser.id}`,
      });
    }

    if (u.origin === 'https://api.github.com' && u.pathname === '/user/orgs' && req.method === 'GET') {
      const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
      const ghUser = m?.[1] ? tokenToUser.get(m[1]) : undefined;
      if (!ghUser) return Response.json({ message: 'Bad credentials' }, { status: 401 });
      return Response.json((ghUser.orgs ?? []).map((login) => ({ login })));
    }

    if (params.extraHandler) {
      const custom = await params.extraHandler(req);
      if (custom) return custom;
    }

    return new Response('not found', { status: 404 });
  };
}

function createInProcessHubHarness(overrides: Record<string, unknown> = {}) {
  const tempDir = mkdtempSync(join(tmpdir(), 'ef-gh-multi-'));
  const doSqlite = new DatabaseSync(':memory:');
  const oauthStore = createSqliteOAuthStore(createNodeSqlStorage(doSqlite));
  const metaDb = new NodeSqliteD1Database(':memory:', [
    { name: 'meta/0001_tracking.sql', sql: metaSchema0001 },
    { name: 'meta/0002_multiuser.sql', sql: metaSchema0002 },
  ]);
  const searchDb = new NodeSqliteD1Database(':memory:', [
    { name: 'search/0001_fts.sql', sql: searchSchemaSql },
  ]);
  const artifacts = new NodeFsR2Bucket(join(tempDir, 'r2'));
  const events: Array<Record<string, unknown>> = [];

  // Minimal in-process AgentHubDO stub backed by real SQLite OAuthStore so workerEntry.fetch runs all real Hub routes.
  const stubObj = {
    getPortalState: async (now: number) => ({
      connected: 1,
      distinctPublicIps: 1,
      agents: [
        {
          siteId: 'site-alpha',
          publicIp: '198.51.100.42',
          arch: 'amd64',
          version: '2.7.0',
          connectedAt: now - 10_000,
          lastJobAt: now - 1_000,
        },
      ],
      affinities: [{ host: 'docs.example.com', siteId: 'site-alpha', expiresAt: now + 60_000 }],
      grants: await oauthStore.listGrants(now),
      mcpClients: [],
      events,
      users: (await oauthStore.listUsers?.()) ?? [],
    }),
    listAgents: async () => ({ connected: 1, distinctPublicIps: 1, agents: [] }),
    listHostHealth: async () => [],
    clearAffinities: async () => 1,
    clearHubEvents: async () => {
      events.length = 0;
    },
    recordHubEvents: async (evs: Array<Record<string, unknown>>) => {
      events.push(...evs);
    },
    recordMcpCall: async () => undefined,
    waitForHostWindow: async () => ({ ok: true as const }),
    dispatchFetch: async (rawCallBody: string, _trace: Record<string, string>, preferredSite?: string) => {
      const parsed = JSON.parse(rawCallBody) as {
        requests?: Array<{
          id?: string;
          url?: string;
          interact?: { sessionId?: string; keepSession?: boolean; closeSession?: boolean; actions?: unknown[] };
        }>;
      };
      const firstReq = parsed.requests?.[0] ?? {};
      const interact = firstReq.interact;
      const siteId = preferredSite || 'site-alpha';
      if (interact?.closeSession) {
        return {
          ok: true as const,
          siteId,
          bodyText: JSON.stringify({
            results: [{ id: firstReq.id ?? '1', status: 200, outcome: 'ok', headers: {}, body: '' }],
          }),
        };
      }
      if (interact && (interact.keepSession || interact.sessionId || interact.actions)) {
        const sid = interact.sessionId || `efsess_${randomBytes(8).toString('hex')}`;
        return {
          ok: true as const,
          siteId,
          bodyText: JSON.stringify({
            results: [
              {
                id: firstReq.id ?? '1',
                status: 200,
                outcome: 'ok',
                finalUrl: firstReq.url || 'https://app.example.com/dashboard',
                sessionId: sid,
                headers: { 'content-type': 'text/html; charset=utf-8' },
                body: `<html><head><title>Interactive Session</title></head><body><main><h1>Dashboard</h1><p>Active browser session ${sid}</p></main></body></html>`,
              },
            ],
          }),
        };
      }
      const targetUrl = String(firstReq.url ?? 'https://docs.example.com/');
      if (targetUrl.endsWith('/robots.txt')) {
        return {
          ok: true as const,
          siteId: 'site-alpha',
          bodyText: JSON.stringify({
            results: [{ id: firstReq.id ?? '1', status: 200, outcome: 'ok', headers: { 'content-type': 'text/plain' }, body: 'User-agent: *\nAllow: /\n' }],
          }),
        };
      }
      return {
        ok: true as const,
        siteId: 'site-alpha',
        bodyText: JSON.stringify({
          results: [
            {
              id: firstReq.id ?? '1',
              status: 200,
              outcome: 'ok',
              finalUrl: targetUrl,
              headers: { 'content-type': 'text/html; charset=utf-8' },
              body: `<html><head><title>Doc for ${targetUrl}</title></head><body><main><h1>Private Knowledge</h1><p>Fetched content for ${targetUrl} at ${Date.now()}</p></main></body></html>`,
            },
          ],
        }),
      };
    },
    oauthPutClient: (c: Parameters<typeof oauthStore.putClient>[0]) => oauthStore.putClient(c),
    oauthGetClient: (id: string) => oauthStore.getClient(id),
    oauthPutCode: (c: Parameters<typeof oauthStore.putCode>[0]) => oauthStore.putCode(c),
    oauthConsumeCode: (h: string, now: number) => oauthStore.consumeCode(h, now),
    oauthPutTokenPair: (p: Parameters<typeof oauthStore.putTokenPair>[0]) => oauthStore.putTokenPair(p),
    oauthGetAccessToken: (h: string, now: number) => oauthStore.getAccessToken(h, now),
    oauthConsumeRefreshToken: (h: string, now: number) => oauthStore.consumeRefreshToken(h, now),
    oauthRotateRefreshToken: (p: Parameters<typeof oauthStore.rotateRefreshToken>[0]) => oauthStore.rotateRefreshToken(p),
    oauthListGrants: (now: number, userId?: string) => oauthStore.listGrants(now, userId),
    oauthRevokeGrant: (id: string, userId?: string) => oauthStore.revokeGrant(id, userId),
    oauthRevokeByTokenHash: (h: string) => oauthStore.revokeByTokenHash(h),
    oauthCheckAuthLockout: (b: string, now: number, m?: number) => oauthStore.checkAuthLockout(b, now, m),
    oauthRecordAuthFailure: (b: string, now: number, w: number, m: number) => oauthStore.recordAuthFailure(b, now, w, m),
    oauthClearAuthFailures: (b: string) => oauthStore.clearAuthFailures(b),
    oauthUpsertUser: (u: Parameters<NonNullable<typeof oauthStore.upsertUser>>[0]) => oauthStore.upsertUser!(u),
    oauthGetUser: (id: string) => oauthStore.getUser!(id),
    oauthListUsers: () => oauthStore.listUsers!(),
    oauthCountUsers: () => oauthStore.countUsers!(),
    oauthUpdateUserRole: (id: string, role: 'owner' | 'member') => oauthStore.updateUserRole!(id, role),
  };

  const pendingWaitUntil: Promise<unknown>[] = [];
  const env = {
    AGENT_HUB: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => stubObj,
    },
    CALLER_TOKEN: 'owner_caller_secret_token_0123456789',
    SESSION_SECRET: ' dedicated_session_secret_key_0123456789'.trim(),
    GITHUB_CLIENT_ID: 'Iv23liMockGitHubClientId01',
    GITHUB_CLIENT_SECRET: 'ghs_mock_client_secret_value_0123456789',
    GITHUB_OWNER_LOGIN: 'founder',
    GITHUB_OWNER_ID: '7',
    GITHUB_ALLOWED_USERS: 'alice,bob,@trusted-org',
    SIGNUP_MODE: 'invite_only',
    ROBOTS_BYPASS_HOSTS: 'docs.example.com,app.example.com',
    META: metaDb,
    SEARCH: searchDb,
    ARTIFACTS: artifacts,
    ...overrides,
  };

  const dispatch = async (pathOrUrl: string, init?: RequestInit): Promise<Response> => {
    const fullUrl = pathOrUrl.startsWith('http') ? pathOrUrl : `https://hub.example.com${pathOrUrl}`;
    const req = new Request(fullUrl, init);
    const ctx = {
      waitUntil: (p: Promise<unknown>) => {
        pendingWaitUntil.push(p);
      },
      passThroughOnException: () => undefined,
    };
    return await workerEntry.fetch(req, env as never, ctx as never);
  };

  const flushWaitUntil = async () => {
    while (pendingWaitUntil.length > 0) {
      const batch = pendingWaitUntil.splice(0, pendingWaitUntil.length);
      await Promise.allSettled(batch);
    }
  };

  const cleanup = () => {
    try {
      doSqlite.close();
    } catch {
      // ignore
    }
    try {
      metaDb.close();
    } catch {
      // ignore
    }
    try {
      searchDb.close();
    } catch {
      // ignore
    }
    rmSync(tempDir, { recursive: true, force: true });
  };

  return { env, oauthStore, doSqlite, metaDb, searchDb, artifacts, dispatch, flushWaitUntil, cleanup };
}

async function loginViaGitHub(
  dispatch: (path: string, init?: RequestInit) => Promise<Response>,
  code: string,
  returnTo?: string,
): Promise<{ status: number; location: string | null; sessionCookie: string | null; body: string; setCookies: string[] }> {
  const startPath = returnTo ? `/admin/auth/github?return_to=${encodeURIComponent(returnTo)}` : '/admin/auth/github';
  const r1 = await dispatch(startPath, { method: 'GET' });
  assert.equal(r1.status, 302);
  const authRedirect = r1.headers.get('location') ?? '';
  assert.ok(authRedirect.startsWith('https://github.com/login/oauth/authorize?'));
  const authUrl = new URL(authRedirect);
  assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256');
  const state = authUrl.searchParams.get('state') ?? '';
  assert.ok(state.length >= 20);

  const startCookies = extractSetCookies(r1.headers);
  const ghStateCookie = cookiePairFromSetCookie(startCookies, '__Host-ef_gh_oauth');
  assert.ok(startCookies.some((c) => c.includes('HttpOnly') && c.includes('SameSite=Lax') && c.includes('Secure')));

  const r2 = await dispatch(`/admin/auth/github/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`, {
    method: 'GET',
    headers: { cookie: ghStateCookie },
  });
  const setCookies = extractSetCookies(r2.headers);
  const sessionPair =
    setCookies
      .map((c) => c.split(';')[0]?.trim() ?? '')
      .find(
        (c) =>
          (c.startsWith('__Host-ef_admin_session=') && c.length > '__Host-ef_admin_session='.length) ||
          (c.startsWith('ef_admin_session=') && c.length > 'ef_admin_session='.length),
      ) ?? null;
  return {
    status: r2.status,
    location: r2.headers.get('location'),
    sessionCookie: sessionPair,
    body: await r2.text(),
    setCookies,
  };
}

async function issueUserOAuthToken(
  dispatch: (path: string, init?: RequestInit) => Promise<Response>,
  sessionCookie: string,
  clientName: string,
): Promise<{ accessToken: string; refreshToken: string; clientId: string }> {
  const regRes = await dispatch('/oauth/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: clientName,
      redirect_uris: ['http://127.0.0.1:54321/callback'],
    }),
  });
  assert.equal(regRes.status, 201);
  const regJson = (await regRes.json()) as { client_id: string };

  const pkce = makePkcePair();
  const consentGet = await dispatch(
    `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(regJson.client_id)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:54321/callback')}&code_challenge=${encodeURIComponent(pkce.challenge)}&code_challenge_method=S256&state=st123&scope=crawl:fetch+crawl:read`,
    {
      method: 'GET',
      headers: { cookie: sessionCookie },
    },
  );
  assert.equal(consentGet.status, 200);
  const consentHtml = await consentGet.text();
  const csrfCookie = cookiePairFromSetCookie(extractSetCookies(consentGet.headers), 'ef_oauth_csrf');
  const sealedMatch = /name="sealed"\s+value="([^"]+)"/.exec(consentHtml);
  const csrfMatch = /name="csrf"\s+value="([^"]+)"/.exec(consentHtml);
  assert.ok(sealedMatch?.[1] && csrfMatch?.[1]);

  const approveForm = new URLSearchParams({
    decision: 'approve',
    sealed: sealedMatch[1],
    csrf: csrfMatch[1],
  });
  const approveRes = await dispatch('/oauth/authorize', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://hub.example.com',
      cookie: `${sessionCookie}; ${csrfCookie}`,
    },
    body: approveForm.toString(),
  });
  assert.equal(approveRes.status, 302);
  const cbUrl = new URL(approveRes.headers.get('location') ?? '');
  const code = cbUrl.searchParams.get('code') ?? '';
  assert.ok(code.startsWith('efc_'));

  const tokRes = await dispatch('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: regJson.client_id,
      redirect_uri: 'http://127.0.0.1:54321/callback',
      code_verifier: pkce.verifier,
    }).toString(),
  });
  assert.equal(tokRes.status, 200);
  const tokJson = (await tokRes.json()) as { access_token: string; refresh_token: string };
  return {
    accessToken: tokJson.access_token,
    refreshToken: tokJson.refresh_token,
    clientId: regJson.client_id,
  };
}

test('Pillar 1A: GitHub OAuth PKCE S256 login, SIGNUP_MODE=invite_only, @org membership, bootstrap_first & open-redirect defense', async () => {
  const outboundCalls: Array<{ url: string; method: string; authHeader: string | null; bodyText: string }> = [];
  const safeFetch = createMockGitHubSafeFetch({
    expectedClientId: 'Iv23liMockGitHubClientId01',
    expectedClientSecret: 'ghs_mock_client_secret_value_0123456789',
    recordedRequests: outboundCalls,
    usersByCode: {
      code_alice: { id: 1001, login: 'alice', orgs: [] },
      code_org_member: { id: 1002, login: 'charlie', orgs: ['Trusted-Org'] },
      code_outsider: { id: 9999, login: 'mallory', orgs: ['Untrusted-Org'] },
      code_founder: { id: 7, login: 'Founder', orgs: [] },
    },
  });

  const h = createInProcessHubHarness({ SAFE_PUBLIC_FETCH: safeFetch });
  try {
    // 1. /admin and /oauth/authorize both render "Sign in with GitHub" with strict Round 6 CSP/nosniff/XFO headers
    const adminLoginPage = await h.dispatch('/admin');
    assert.equal(adminLoginPage.status, 200);
    assert.equal(adminLoginPage.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(adminLoginPage.headers.get('x-frame-options'), 'DENY');
    assert.ok((adminLoginPage.headers.get('content-security-policy') ?? '').includes("frame-ancestors 'none'"));
    const adminHtml = await adminLoginPage.text();
    assert.ok(adminHtml.includes('Sign in with GitHub'));
    assert.ok(adminHtml.includes('/admin/auth/github'));

    // Register a client and verify /oauth/authorize consent screen also renders "Sign in with GitHub" with return_to
    const reg = await h.dispatch('/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Cursor IDE', redirect_uris: ['http://127.0.0.1:4444/cb'] }),
    });
    const { client_id } = (await reg.json()) as { client_id: string };
    const pkce = makePkcePair();
    const authorizeUrl = `/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent('http://127.0.0.1:4444/cb')}&code_challenge=${pkce.challenge}&code_challenge_method=S256`;
    const consentUnauth = await h.dispatch(authorizeUrl);
    assert.equal(consentUnauth.status, 200);
    assert.equal(consentUnauth.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(consentUnauth.headers.get('x-frame-options'), 'DENY');
    const consentHtml = await consentUnauth.text();
    assert.ok(consentHtml.includes('Sign in with GitHub'));
    assert.ok(consentHtml.includes('/admin/auth/github?return_to='));

    // 2. Unlisted GitHub user (not in GITHUB_ALLOWED_USERS and not in @trusted-org) is rejected fail-closed (403)
    const outsiderRes = await loginViaGitHub(h.dispatch, 'code_outsider');
    assert.equal(outsiderRes.status, 403);
    assert.equal(outsiderRes.sessionCookie, null);
    assert.ok(outsiderRes.body.includes('Account Not Authorized'));
    assert.ok(outboundCalls.some((c) => c.url.startsWith('https://api.github.com/user/orgs')));

    // 3. Explicit allowlisted login ("alice") succeeds as role="member" and sanitizes hostile return_to to /admin
    const aliceLogin = await loginViaGitHub(h.dispatch, 'code_alice', '//evil.example.com/phish');
    assert.equal(aliceLogin.status, 302);
    assert.equal(aliceLogin.location, '/admin');
    assert.ok(aliceLogin.sessionCookie);

    // 4. @org allowlist ("@trusted-org") admits org member "charlie" and preserves valid /oauth/authorize return_to
    const charlieLogin = await loginViaGitHub(h.dispatch, 'code_org_member', authorizeUrl);
    assert.equal(charlieLogin.status, 302);
    assert.equal(charlieLogin.location, authorizeUrl);
    assert.ok(charlieLogin.sessionCookie);

    // 5. GITHUB_OWNER_LOGIN ("founder", case-insensitive) receives role="owner"
    const founderLogin = await loginViaGitHub(h.dispatch, 'code_founder');
    assert.equal(founderLogin.status, 302);
    assert.ok(founderLogin.sessionCookie);

    const ownerStateRes = await h.dispatch('/admin/api/state', {
      headers: { cookie: founderLogin.sessionCookie! },
    });
    assert.equal(ownerStateRes.status, 200);
    const ownerState = (await ownerStateRes.json()) as {
      viewer: { userId: string; role: string; githubLogin: string };
      users: Array<{ userId: string; githubLogin: string; role: string }>;
    };
    assert.equal(ownerState.viewer.userId, 'gh_7');
    assert.equal(ownerState.viewer.role, 'owner');
    assert.equal(ownerState.users.length, 3);

    // Also verify D1 META `users` row persistence
    const d1Users = await h.metaDb.prepare('SELECT user_id, github_login, role FROM users ORDER BY user_id ASC').all();
    assert.equal(d1Users.results.length, 3);

    // 6. State mismatch / missing cookie fails closed (400)
    const badCb = await h.dispatch('/admin/auth/github/callback?code=code_alice&state=wrong_state', {
      headers: { cookie: '__Host-ef_gh_oauth=tampered' },
    });
    assert.equal(badCb.status, 400);
  } finally {
    h.cleanup();
  }

  // 7. SIGNUP_MODE=bootstrap_first promotes very first GitHub user to owner and rejects subsequent unlisted users
  const bootSafeFetch = createMockGitHubSafeFetch({
    expectedClientId: 'Iv23liMockGitHubClientId01',
    expectedClientSecret: 'ghs_mock_client_secret_value_0123456789',
    usersByCode: {
      code_first: { id: 501, login: 'first-admin' },
      code_second: { id: 502, login: 'late-comer' },
    },
  });
  const hBoot = createInProcessHubHarness({
    SAFE_PUBLIC_FETCH: bootSafeFetch,
    GITHUB_OWNER_LOGIN: '',
    GITHUB_OWNER_ID: '501',
    GITHUB_ALLOWED_USERS: '',
    SIGNUP_MODE: 'bootstrap_first',
    CALLER_TOKEN: undefined, // GitHub-only Hub without CALLER_TOKEN!
  });
  try {
    const first = await loginViaGitHub(hBoot.dispatch, 'code_first');
    assert.equal(first.status, 302);
    assert.ok(first.sessionCookie);
    const st = (await (await hBoot.dispatch('/admin/api/state', { headers: { cookie: first.sessionCookie! } })).json()) as {
      viewer: { userId: string; role: string };
    };
    assert.equal(st.viewer.userId, 'gh_501');
    assert.equal(st.viewer.role, 'owner');

    const second = await loginViaGitHub(hBoot.dispatch, 'code_second');
    assert.equal(second.status, 403);
    assert.equal(second.sessionCookie, null);
  } finally {
    hBoot.cleanup();
  }
});

test('Pillar 1B: jose HS256 JWT tamper/alg=none/expiry rejection, jti logout revocation & legacy SQLite ALTER TABLE safety', async () => {
  const secret = 'jwt_unit_signing_secret_0123456789abcdef';
  const minted = await mintSessionJwt({
    secret,
    userId: 'gh_1001',
    role: 'member',
    githubLogin: 'alice',
    ttlMs: 3_600_000,
  });
  const verified = await verifySessionJwt(minted.token, secret);
  assert.equal(verified.ok, true);
  if (verified.ok) {
    assert.equal(verified.userId, 'gh_1001');
    assert.equal(verified.role, 'member');
    assert.equal(verified.jti, minted.jti);
  }

  // Tamper payload role from "member" -> "owner" while keeping signature
  const parts = minted.token.split('.');
  const forgedPayload = Buffer.from(
    JSON.stringify({ sub: 'gh_1001', role: 'owner', csrf: minted.csrf, jti: minted.jti, exp: Math.floor(Date.now() / 1000) + 3600 }),
  ).toString('base64url');
  const forgedJwt = `${parts[0]}.${forgedPayload}.${parts[2]}`;
  assert.equal((await verifySessionJwt(forgedJwt, secret)).ok, false);

  // alg: "none" unsigned JWT attack must fail closed
  const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  assert.equal((await verifySessionJwt(`${noneHeader}.${forgedPayload}.`, secret)).ok, false);

  // Wrong secret & expired JWT must fail closed
  assert.equal((await verifySessionJwt(minted.token, 'different_secret_value_0123456789abcdef')).ok, false);
  const expired = await mintSessionJwt({
    secret,
    userId: 'gh_1001',
    role: 'member',
    now: Date.now() - 120_000,
    ttlMs: 60_000,
  });
  assert.equal((await verifySessionJwt(expired.token, secret)).ok, false);

  // Legacy SQLite database WITHOUT user_id/user_role columns on oauth_codes & oauth_tokens upgrades cleanly via ALTER TABLE
  const legacyDb = new DatabaseSync(':memory:');
  legacyDb.exec(`
    CREATE TABLE oauth_clients (
      client_id TEXT PRIMARY KEY,
      client_secret_hash TEXT,
      token_endpoint_auth_method TEXT NOT NULL,
      redirect_uris_json TEXT NOT NULL,
      client_name TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE oauth_codes (
      code_hash TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      client_name TEXT NOT NULL DEFAULT 'CLI',
      redirect_uri TEXT NOT NULL,
      scopes_json TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      resource TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE oauth_tokens (
      token_hash TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      grant_id TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_name TEXT NOT NULL,
      scopes_json TEXT NOT NULL,
      resource TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      last_used_at INTEGER
    );
  `);
  legacyDb.exec(
    `INSERT INTO oauth_tokens (token_hash, kind, grant_id, client_id, client_name, scopes_json, resource, created_at, expires_at)
     VALUES ('legacy_hash_1', 'access', 'legacy_grant_1', 'cid_1', 'Legacy CLI', '["crawl:read","crawl:fetch"]', '', 1000, 9999999999999)`,
  );
  const upgradedStore = createSqliteOAuthStore(createNodeSqlStorage(legacyDb));
  const legacyTok = await upgradedStore.getAccessToken('legacy_hash_1', 2000);
  assert.ok(legacyTok);
  assert.equal(legacyTok.userId, 'owner');
  assert.equal(legacyTok.userRole, 'owner');

  // Revoking session jti marks session revoked immediately
  const jtiHash = await sha256Base64Url(minted.jti);
  await upgradedStore.recordAuthFailure(`revoked_admin:jti:${jtiHash}`, Date.now(), 8 * 60 * 60_000, 1);
  const cookieRes = await verifyAdminSessionCookie(`ef_admin_session=${minted.token}`, secret);
  assert.equal(cookieRes.ok, true);
  assert.equal(await isAdminSessionRevoked(upgradedStore, minted.csrf, Date.now(), minted.jti), true);
  legacyDb.close();
});

test('Pillar 1C: Strict User A vs User B isolation across OAuth grants, /admin, /v1/agent, /v1/interact, private cache, R2 artifacts & FTS5 collections', async () => {
  let originScrapeCount = 0;
  const safeFetch = createMockGitHubSafeFetch({
    expectedClientId: 'Iv23liMockGitHubClientId01',
    expectedClientSecret: 'ghs_mock_client_secret_value_0123456789',
    usersByCode: {
      code_user_a: { id: 1001, login: 'alice' },
      code_user_b: { id: 2002, login: 'bob' },
      code_owner: { id: 7, login: 'founder' },
    },
    extraHandler: async (req) => {
      const u = new URL(req.url);
      if (u.origin === 'https://llm.example.com' && u.pathname === '/v1/chat/completions') {
        const body = JSON.parse(await req.text()) as { messages?: Array<{ role: string; content?: string }> };
        const allText = JSON.stringify(body.messages ?? []);
        return Response.json({
          choices: [
            {
              message: {
                role: 'assistant',
                content: JSON.stringify({
                  answer: allText.includes('ALPHA_SECRET_MEMO') ? 'LEAKED_ALPHA_MEMO' : 'Isolated clean answer',
                }),
              },
              finish_reason: 'stop',
            },
          ],
          usage: { prompt_tokens: 20, completion_tokens: 10 },
        });
      }
      return null;
    },
  });

  const h = createInProcessHubHarness({
    SAFE_PUBLIC_FETCH: safeFetch,
    SAFE_FETCH: safeFetch,
    EDGEFETCH_LLM_PROVIDER: 'openai',
    EDGEFETCH_LLM_BASE_URL: 'https://llm.example.com/v1',
    EDGEFETCH_LLM_API_KEY: 'sk_mock_llm_key_0123456789abcdef',
    EDGEFETCH_LLM_MODEL: 'gpt-4o-mini',
  });
  // Count actual upstream hub dispatches for private cache hit/miss verification
  const origDispatchFetch = h.env.AGENT_HUB.get().dispatchFetch;
  h.env.AGENT_HUB.get().dispatchFetch = async (...args: Parameters<typeof origDispatchFetch>) => {
    const parsed = JSON.parse(args[0]) as { requests?: Array<{ url?: string }> };
    if (!String(parsed.requests?.[0]?.url ?? '').endsWith('/robots.txt')) {
      originScrapeCount++;
    }
    return await origDispatchFetch(...args);
  };

  try {
    const loginA = await loginViaGitHub(h.dispatch, 'code_user_a');
    const loginB = await loginViaGitHub(h.dispatch, 'code_user_b');
    const loginOwner = await loginViaGitHub(h.dispatch, 'code_owner');
    assert.ok(loginA.sessionCookie && loginB.sessionCookie && loginOwner.sessionCookie);

    const tokA = await issueUserOAuthToken(h.dispatch, loginA.sessionCookie!, 'Alice Claude Code');
    const tokB = await issueUserOAuthToken(h.dispatch, loginB.sessionCookie!, 'Bob Cursor');

    // Refresh token rotation preserves userId='gh_1001'
    const rotRes = await h.dispatch('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokA.refreshToken,
        client_id: tokA.clientId,
      }).toString(),
    });
    assert.equal(rotRes.status, 200);
    const rotJson = (await rotRes.json()) as { access_token: string };
    const aliceBearer = `Bearer ${rotJson.access_token}`;
    const bobBearer = `Bearer ${tokB.accessToken}`;
    const ownerBearer = `Bearer ${h.env.CALLER_TOKEN}`;

    // --- 1. /admin Multi-User Grant & Fleet Scoping + Logout Revocation ---
    const parsedCookieA = await verifyAdminSessionCookie(loginA.sessionCookie!, h.env.SESSION_SECRET);
    assert.equal(parsedCookieA.ok, true);
    const aliceCsrf = parsedCookieA.ok ? parsedCookieA.csrf : '';

    const stateARes = await h.dispatch('/admin/api/state', { headers: { cookie: loginA.sessionCookie! } });
    assert.equal(stateARes.status, 200);
    const stateA = (await stateARes.json()) as {
      viewer: { userId: string; role: string };
      agents: unknown[];
      events: unknown[];
      grants: Array<{ grantId: string; userId?: string; clientName: string }>;
    };
    assert.equal(stateA.viewer.userId, 'gh_1001');
    assert.equal(stateA.viewer.role, 'member');
    assert.equal(stateA.agents.length, 0, 'member must not see fleet WAN IPs');
    assert.equal(stateA.events.length, 0, 'member must not see global hub events');
    assert.equal(stateA.grants.length, 1);
    assert.equal(stateA.grants[0]?.clientName, 'Alice Claude Code');

    const stateOwner = (await (
      await h.dispatch('/admin/api/state', { headers: { cookie: loginOwner.sessionCookie! } })
    ).json()) as {
      viewer: { role: string };
      agents: Array<{ publicIp?: string }>;
      grants: Array<{ grantId: string; userId?: string; clientName: string }>;
    };
    assert.equal(stateOwner.viewer.role, 'owner');
    assert.equal(stateOwner.agents.length, 1);
    assert.equal(stateOwner.grants.length, 2);
    const bobGrantId = stateOwner.grants.find((g) => g.clientName === 'Bob Cursor')?.grantId ?? '';
    assert.ok(bobGrantId);

    // Alice attempting to revoke Bob's OAuth grant must fail (revoked: false) and leave Bob's token working!
    const crossRevoke = await h.dispatch('/admin/api/grants/revoke', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://hub.example.com',
        cookie: loginA.sessionCookie!,
        'x-csrf-token': aliceCsrf,
      },
      body: JSON.stringify({ grantId: bobGrantId }),
    });
    assert.equal(crossRevoke.status, 200);
    assert.deepEqual(await crossRevoke.json(), { ok: true, revoked: false });

    // Member attempting owner-only /admin/api/events/clear or /admin/api/fetch gets 403 forbidden_role
    const memberClear = await h.dispatch('/admin/api/events/clear', {
      method: 'POST',
      headers: {
        origin: 'https://hub.example.com',
        cookie: loginA.sessionCookie!,
        'x-csrf-token': aliceCsrf,
      },
    });
    assert.equal(memberClear.status, 403);

    // --- 2. /v1/interact Browser Session HMAC Isolation ---
    const interactStartA = await h.dispatch('/v1/interact', {
      method: 'POST',
      headers: { authorization: aliceBearer, 'content-type': 'application/json' },
      body: JSON.stringify({
        url: 'https://app.example.com/dashboard',
        keepSession: true,
        actions: [{ type: 'wait', milliseconds: 10 }],
      }),
    });
    assert.equal(interactStartA.status, 200);
    const interactJsonA = (await interactStartA.json()) as { sessionId: string };
    assert.ok(interactJsonA.sessionId);

    // Alice can resume her own sessionId
    const interactResumeA = await h.dispatch('/v1/interact', {
      method: 'POST',
      headers: { authorization: aliceBearer, 'content-type': 'application/json' },
      body: JSON.stringify({
        sessionId: interactJsonA.sessionId,
        keepSession: true,
        actions: [{ type: 'wait', milliseconds: 10 }],
      }),
    });
    assert.equal(interactResumeA.status, 200);

    // Bob attempting to hijack or close Alice's sessionId gets 403 session_principal_mismatch!
    for (const payload of [
      { sessionId: interactJsonA.sessionId, actions: [{ type: 'wait', milliseconds: 10 }] },
      { sessionId: interactJsonA.sessionId, closeSession: true },
    ]) {
      const hijackRes = await h.dispatch('/v1/interact', {
        method: 'POST',
        headers: { authorization: bobBearer, 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });
      assert.equal(hijackRes.status, 403);
      const hijackBody = (await hijackRes.json()) as { error: string };
      assert.equal(hijackBody.error, 'session_principal_mismatch');
    }

    // --- 3. /v1/agent Run Ownership, Cancel Protection & Thread Memory Isolation ---
    const agentRunARes = await h.dispatch('/v1/agent', {
      method: 'POST',
      headers: { authorization: aliceBearer, 'content-type': 'application/json' },
      body: JSON.stringify({
        prompt: 'Remember ALPHA_SECRET_MEMO for my private research.',
        threadId: 'shared_thread_name',
        sync: true,
        maxSteps: 2,
      }),
    });
    assert.equal(agentRunARes.status, 200);
    const agentRunA = (await agentRunARes.json()) as { id: string; threadId: string };
    assert.ok(agentRunA.id.startsWith('agt_'));

    // Alice can read her own run; Bob AND other principals get 404 on GET, GET /trace, and DELETE!
    assert.equal((await h.dispatch(`/v1/agent/${agentRunA.id}`, { headers: { authorization: aliceBearer } })).status, 200);
    assert.equal((await h.dispatch(`/v1/agent/${agentRunA.id}`, { headers: { authorization: ownerBearer } })).status, 404);
    assert.equal((await h.dispatch(`/v1/agent/${agentRunA.id}`, { headers: { authorization: bobBearer } })).status, 404);
    assert.equal((await h.dispatch(`/v1/agent/${agentRunA.id}/trace`, { headers: { authorization: bobBearer } })).status, 404);
    assert.equal(
      (await h.dispatch(`/v1/agent/${agentRunA.id}`, { method: 'DELETE', headers: { authorization: bobBearer } })).status,
      404,
    );
    // Verify Alice's run was NOT marked cancelled by Bob's rejected DELETE
    const aliceAfterBobDelete = (await (
      await h.dispatch(`/v1/agent/${agentRunA.id}`, { headers: { authorization: aliceBearer } })
    ).json()) as { status: string };
    assert.equal(aliceAfterBobDelete.status, 'completed');

    // Bob using the exact same `threadId: "shared_thread_name"` must NOT inherit Alice's prior thread messages!
    const agentRunBRes = await h.dispatch('/v1/agent', {
      method: 'POST',
      headers: { authorization: bobBearer, 'content-type': 'application/json' },
      body: JSON.stringify({
        prompt: 'What did I ask earlier?',
        threadId: 'shared_thread_name',
        sync: true,
        maxSteps: 2,
      }),
    });
    assert.equal(agentRunBRes.status, 200);
    const agentRunB = (await agentRunBRes.json()) as { data?: { answer?: string }; result?: unknown };
    assert.notEqual(JSON.stringify(agentRunB).includes('LEAKED_ALPHA_MEMO'), true);

    // --- 4. Private Scrape Cache, Private R2 Artifacts & Private FTS5 Collections ---
    const beforeCount = originScrapeCount;
    const scrapeA1 = await h.dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: aliceBearer, 'content-type': 'application/json' },
      body: JSON.stringify({
        url: 'https://docs.example.com/confidential-roadmap',
        visibility: 'private',
        storeArtifact: true,
        collectionId: 'notes',
        maxAgeMs: 60_000,
      }),
    });
    assert.equal(scrapeA1.status, 200);
    await h.flushWaitUntil();
    const scrapeBodyA1 = (await scrapeA1.json()) as {
      cached: boolean;
      visibility: string;
      artifactId?: string;
      markdown?: string;
      contentSha256: string;
    };
    assert.equal(scrapeBodyA1.cached, false);
    assert.equal(scrapeBodyA1.visibility, 'private');
    assert.ok(scrapeBodyA1.artifactId);
    assert.equal(originScrapeCount, beforeCount + 1);

    // Alice repeating her private scrape hits her own `cache:private-r2` without re-scraping upstream
    const scrapeA2 = await h.dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: aliceBearer, 'content-type': 'application/json' },
      body: JSON.stringify({
        url: 'https://docs.example.com/confidential-roadmap',
        visibility: 'private',
        maxAgeMs: 60_000,
      }),
    });
    assert.equal(scrapeA2.status, 200);
    assert.equal(scrapeA2.headers.get('x-crawler-via'), 'cache:private-r2');
    assert.equal(((await scrapeA2.json()) as { cached: boolean }).cached, true);
    assert.equal(originScrapeCount, beforeCount + 1);

    // Bob scraping the EXACT same URL (private OR public) NEVER hits Alice's private cache!
    const scrapeB1 = await h.dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: bobBearer, 'content-type': 'application/json' },
      body: JSON.stringify({
        url: 'https://docs.example.com/confidential-roadmap',
        visibility: 'private',
        maxAgeMs: 60_000,
      }),
    });
    assert.equal(scrapeB1.status, 200);
    assert.equal(((await scrapeB1.json()) as { cached: boolean }).cached, false);
    assert.equal(originScrapeCount, beforeCount + 2);

    // Alice can read her private Markdown / raw artifact via GET /v1/artifacts/..., while Bob gets 404!
    const mdShaA1 = createHash('sha256').update(scrapeBodyA1.markdown ?? '').digest('hex');
    const mdRef = `md:${mdShaA1}`;
    const artAlice = await h.dispatch(`/v1/artifacts/${mdRef}?visibility=private`, {
      headers: { authorization: aliceBearer },
    });
    assert.equal(artAlice.status, 200);
    assert.ok((await artAlice.text()).includes('Private Knowledge'));

    const artBob = await h.dispatch(`/v1/artifacts/${mdRef}?visibility=private`, {
      headers: { authorization: bobBearer },
    });
    assert.equal(artBob.status, 404);

    assert.equal(
      (await h.dispatch(`/v1/artifacts/${scrapeBodyA1.artifactId}?visibility=private`, { headers: { authorization: aliceBearer } })).status,
      200,
    );
    assert.equal(
      (await h.dispatch(`/v1/artifacts/${scrapeBodyA1.artifactId}?visibility=private`, { headers: { authorization: bobBearer } })).status,
      404,
    );

    // FTS5 collection isolation: Alice clips a private note into "notes" via /v1/ingest-tab
    const clipAlice = await h.dispatch('/v1/ingest-tab', {
      method: 'POST',
      headers: { authorization: aliceBearer, 'content-type': 'application/json' },
      body: JSON.stringify({
        url: 'https://docs.example.com/alice-secret-clip',
        title: 'Project Zephyr Token',
        markdown: '# Project Zephyr\n\nUnique keyword ZEPHYR_OMEGA_991 belongs only to Alice.',
        collectionId: 'notes',
      }),
    });
    assert.equal(clipAlice.status, 200);

    const searchAlice = await h.dispatch('/v1/collections/notes/search?q=ZEPHYR_OMEGA_991', {
      headers: { authorization: aliceBearer },
    });
    assert.equal(searchAlice.status, 200);
    const searchAliceBody = (await searchAlice.json()) as { collectionId: string; hits: Array<{ collectionId: string }> };
    assert.equal(searchAliceBody.collectionId, 'notes');
    assert.equal(searchAliceBody.hits.length, 1);
    assert.equal(searchAliceBody.hits[0]?.collectionId, 'notes');

    // Bob searching "notes" sees 0 hits; Bob explicitly targeting "private:gh_1001:notes" gets 403 forbidden_collection!
    const searchBobOwn = await h.dispatch('/v1/collections/notes/search?q=ZEPHYR_OMEGA_991', {
      headers: { authorization: bobBearer },
    });
    assert.equal(searchBobOwn.status, 200);
    assert.equal(((await searchBobOwn.json()) as { hits: unknown[] }).hits.length, 0);

    const searchBobCross = await h.dispatch('/v1/collections/private:gh_1001:notes/search?q=ZEPHYR_OMEGA_991', {
      headers: { authorization: bobBearer },
    });
    assert.equal(searchBobCross.status, 403);
    assert.equal(((await searchBobCross.json()) as { error: string }).error, 'forbidden_collection');

    // --- 5. Logout revokes Alice's JWT jti so replaying her cookie fails closed (401) ---
    const logoutRes = await h.dispatch('/admin/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'https://hub.example.com',
        cookie: loginA.sessionCookie!,
      },
      body: new URLSearchParams({ csrf: aliceCsrf }).toString(),
    });
    assert.equal(logoutRes.status, 302);
    const replayAfterLogout = await h.dispatch('/admin/api/state', {
      headers: { cookie: loginA.sessionCookie! },
    });
    assert.equal(replayAfterLogout.status, 401);
  } finally {
    h.cleanup();
  }
});

test('Pillar 1D: OTLP span hygiene & real Cloudflare workerd (Miniflare) E2E for oauth4webapi + jose + AgentHubDO multi-user', async () => {
  const workerBundlePath = process.env.EDGEFETCH_WORKERD_BUNDLE;
  assert.ok(workerBundlePath, 'EDGEFETCH_WORKERD_BUNDLE must be provided by scripts/run-tests.mjs');
  const hubRootRequire = createRequire(join(resolve(process.env.EDGEFETCH_HUB_ROOT ?? '.'), 'package.json'));
  const { Miniflare, Response: MfResponse, convertV4MiniflareOptions } = hubRootRequire('miniflare') as typeof import('miniflare');

  const otlpPayloads: string[] = [];
  const ghSecret = 'ghs_workerd_client_secret_0123456789abcdef';
  const callerSecret = 'caller_workerd_secret_token_0123456789abcdef';
  const sessionSecret = 'session_workerd_secret_key_0123456789abcdef';
  const tokenToGhUser = new Map<string, { id: number; login: string }>();

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'hub-multiuser-e2e',
          modules: [
            { type: 'ESModule', path: 'entry.mjs', contents: readFileSync(workerBundlePath, 'utf8') },
            {
              type: 'CompiledWasm',
              path: 'edgefetch-core.wasm',
              contents: readFileSync(join(resolve(process.env.EDGEFETCH_HUB_ROOT ?? '.'), 'src', 'edgefetch-core.wasm')),
            },
          ],
          compatibilityDate: '2026-10-01',
          durableObjects: { AGENT_HUB: { className: 'AgentHubDO', useSQLite: true } },
          bindings: {
            CALLER_TOKEN: callerSecret,
            SESSION_SECRET: sessionSecret,
            GITHUB_CLIENT_ID: 'Iv23liWorkerdClientId',
            GITHUB_CLIENT_SECRET: ghSecret,
            GITHUB_OWNER_LOGIN: 'octo-owner',
            GITHUB_OWNER_ID: '1',
            GITHUB_ALLOWED_USERS: 'alice,bob',
            SIGNUP_MODE: 'invite_only',
            OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com/v1/traces',
          },
          outboundService: async (req) => {
            const u = new URL(req.url);
            if (u.origin === 'https://otel.example.com' && u.pathname === '/v1/traces') {
              otlpPayloads.push(await req.text());
              return new MfResponse('{}', { status: 200, headers: { 'content-type': 'application/json' } });
            }
            if (u.origin === 'https://github.com' && u.pathname === '/login/oauth/access_token') {
              const form = new URLSearchParams(await req.text());
              const code = form.get('code') ?? '';
              const map: Record<string, { id: number; login: string }> = {
                wk_alice: { id: 3001, login: 'alice' },
                wk_bob: { id: 3002, login: 'bob' },
                wk_intruder: { id: 3999, login: 'intruder' },
              };
              const user = map[code];
              if (!user || !form.get('code_verifier')) {
                return new MfResponse(JSON.stringify({ error: 'invalid_grant' }), {
                  status: 400,
                  headers: { 'content-type': 'application/json' },
                });
              }
              const tok = `gho_wk_secret_${user.login}_9988776655`;
              tokenToGhUser.set(tok, user);
              return new MfResponse(
                JSON.stringify({ access_token: tok, token_type: 'bearer', scope: 'read:user' }),
                { status: 200, headers: { 'content-type': 'application/json' } },
              );
            }
            if (u.origin === 'https://api.github.com' && u.pathname === '/user') {
              const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
              const user = m?.[1] ? tokenToGhUser.get(m[1]) : undefined;
              if (!user) return new MfResponse('{"message":"Unauthorized"}', { status: 401 });
              return new MfResponse(
                JSON.stringify({ id: user.id, login: user.login, avatar_url: `https://avatars.githubusercontent.com/u/${user.id}` }),
                { status: 200, headers: { 'content-type': 'application/json' } },
              );
            }
            return new MfResponse('not found', { status: 404 });
          },
        },
      ],
    }),
  );

  try {
    const wf = async (path: string, init?: RequestInit) =>
      (await mf.dispatchFetch(`https://hub.example.com${path}`, {
        redirect: 'manual',
        ...(init as Record<string, unknown>),
      })) as unknown as Response;

    // 1. Intruder rejected in real workerd runtime
    const intruder = await loginViaGitHub(wf, 'wk_intruder');
    assert.equal(intruder.status, 403);

    // 2. Alice & Bob sign in via oauth4webapi PKCE + jose HS256 inside real workerd + AgentHubDO SQLite
    const wkAlice = await loginViaGitHub(wf, 'wk_alice');
    const wkBob = await loginViaGitHub(wf, 'wk_bob');
    assert.equal(wkAlice.status, 302);
    assert.equal(wkBob.status, 302);
    assert.ok(wkAlice.sessionCookie && wkBob.sessionCookie);

    const aliceOauth = await issueUserOAuthToken(wf, wkAlice.sessionCookie!, 'Workerd Alice CLI');
    const bobOauth = await issueUserOAuthToken(wf, wkBob.sessionCookie!, 'Workerd Bob CLI');
    assert.ok(aliceOauth.accessToken.startsWith('efa_'));
    assert.ok(bobOauth.accessToken.startsWith('efa_'));

    // 3. Verify Alice's /admin/api/state in workerd DO SQLite shows ONLY Alice's grant
    const wkStateA = (await (await wf('/admin/api/state', { headers: { cookie: wkAlice.sessionCookie! } })).json()) as {
      viewer: { userId: string; role: string };
      grants: Array<{ clientName: string }>;
    };
    assert.equal(wkStateA.viewer.userId, 'gh_3001');
    assert.equal(wkStateA.grants.length, 1);
    assert.equal(wkStateA.grants[0]?.clientName, 'Workerd Alice CLI');

    // 4. Headless CALLER_TOKEN still works seamlessly as owner alongside GitHub OAuth users
    const capRes = await wf('/v1/capabilities', {
      headers: { authorization: `Bearer ${callerSecret}` },
    });
    assert.equal(capRes.status, 200);

    // 5. Verify zero secret leakage in exported OTLP spans
    const allOtlp = otlpPayloads.join('\n');
    assert.ok(allOtlp.includes('edgefetch.admin.github_login'));
    assert.ok(allOtlp.includes('edgefetch.admin.github_callback'));
    const wkAliceCookieVal = wkAlice.sessionCookie!.slice(wkAlice.sessionCookie!.indexOf('=') + 1);
    for (const secretValue of [
      ghSecret,
      callerSecret,
      sessionSecret,
      'gho_wk_secret_',
      'wk_alice',
      aliceOauth.accessToken,
      wkAliceCookieVal,
    ]) {
      assert.equal(allOtlp.includes(secretValue), false, `OTLP trace leaked sensitive value: ${secretValue.slice(0, 12)}...`);
    }
  } finally {
    await mf.dispose();
  }
});
