import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import hubWorker from '../src/index';
import {
  executeJobsCall,
  matchesAllowedCompanyOrDomain,
  resetJobsCacheForTests,
  type StructuredJobRecord,
} from '../src/jobs';
import {
  ADMIN_COOKIE_NAME,
  createMemoryOAuthStore,
  createSqliteOAuthStore,
  handleOAuthRoute,
  MAX_OAUTH_GRANTS_PER_OPEN_USER,
  MAX_OAUTH_TOKENS_GLOBAL,
  MAX_OAUTH_TOKENS_OPEN_GLOBAL,
  OAuthQuotaExceededError,
  RESERVED_VETTED_OAUTH_TOKEN_POOL,
  sha256Base64Url,
  verifyAdminSessionCookie,
  type OAuthStore,
  type SqlStorageLike,
} from '../src/oauth';
import {
  checkAndRecordWikipediaArticleQuota,
  parseWikipediaArticleUrl,
  resetWikipediaStateForTests,
} from '../src/wikipedia';
import { LocalAgentHubCoordinator } from '../portable/node-adapters';
import { validateManifest } from '../scripts/compile-manifests.mjs';
import {
  analyzeHtmlForManifestProposal,
  checkClaimedAdapterOrTwinHost,
  fetchPolitePublicHttps,
} from '../scripts/propose-manifest.mjs';

function wrapNodeSqlite(db: DatabaseSync): SqlStorageLike {
  return {
    exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): { toArray(): T[] } {
      if (bindings.length === 0 && query.includes(';') && !/^\s*SELECT\b/i.test(query)) {
        db.exec(query);
        return { toArray: () => [] };
      }
      const stmt = db.prepare(query);
      const isRead = /^\s*(?:SELECT|PRAGMA)\b/i.test(query) || /\bRETURNING\b/i.test(query);
      if (isRead) {
        return { toArray: () => stmt.all(...(bindings as never[])) as T[] };
      }
      stmt.run(...(bindings as never[]));
      return { toArray: () => [] };
    },
  };
}

function extractSetCookies(headers: Headers): string[] {
  const anyHeaders = headers as unknown as { getSetCookie?: () => string[] };
  if (typeof anyHeaders.getSetCookie === 'function') {
    return anyHeaders.getSetCookie();
  }
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

test('Round 11 Stream 5 [S6]: /v1/scrape & MCP scrape enforce requireExplicitReadOnlyHint: true on connected MCP tools', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'ef-r11-s6-'));
  const coordinator = new LocalAgentHubCoordinator(join(tmpDir, 'hub.sqlite'));
  const OWNER_TOKEN = 'owner-secret-token-r11-stream5-0123456789';
  const SESSION_SECRET = 'session-secret-token-r11-stream5-0123456789';
  const VAULT_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  let mcpToolCalls = 0;
  let exposeExplicitReadOnly = false;

  const mockFetch: typeof fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const u = new URL(req.url);
    if (u.origin === 'https://github.com' && u.pathname === '/login/oauth/access_token') {
      return Response.json({ access_token: 'gho_s6', token_type: 'bearer' });
    }
    if (u.origin === 'https://api.github.com' && u.pathname === '/user') {
      return Response.json({ id: 701, login: 'alice' });
    }
    if (u.origin === 'https://mcp.docs-corp.example' && u.pathname === '/mcp') {
      const rpc = JSON.parse(await req.text()) as { id?: string | number; method: string };
      if (rpc.method === 'initialize') return Response.json({ jsonrpc: '2.0', id: rpc.id, result: {} });
      if (rpc.method === 'tools/list') {
        return Response.json({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            tools: [
              {
                // Read-like name `get_page` WITHOUT explicit `readOnlyHint: true` unless toggled!
                name: 'get_page',
                ...(exposeExplicitReadOnly ? { annotations: { readOnlyHint: true } } : {}),
                inputSchema: { type: 'object', properties: { url: { type: 'string' } } },
              },
            ],
          },
        });
      }
      if (rpc.method === 'tools/call') {
        mcpToolCalls++;
        return Response.json({
          jsonrpc: '2.0',
          id: rpc.id,
          result: { content: [{ type: 'text', text: 'MCP_READONLY_VERIFIED_BODY' }] },
        });
      }
    }
    if (u.pathname === '/robots.txt') return new Response('User-agent: *\nAllow: /\n', { status: 200 });
    return new Response('<html><body><main>HTTP_FALLBACK_SCRAPE_BODY</main></body></html>', {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  };

  const env: Record<string, unknown> = {
    AGENT_HUB: coordinator.asNamespace(),
    CALLER_TOKEN: OWNER_TOKEN,
    SESSION_SECRET,
    VAULT_MASTER_KEY: VAULT_KEY,
    GITHUB_CLIENT_ID: 'Iv23liR11S6',
    GITHUB_CLIENT_SECRET: 'ghs_r11_s6_secret_0123456789abcdef',
    GITHUB_ALLOWED_USERS: 'alice',
    SIGNUP_MODE: 'invite_only',
    SAFE_PUBLIC_FETCH: mockFetch,
    SAFE_FETCH: mockFetch,
  };
  const dispatch = (path: string, init?: RequestInit) =>
    (hubWorker as { fetch(r: Request, e: unknown): Promise<Response> }).fetch(
      new Request(`https://hub.example.com${path}`, init),
      env,
    );

  try {
    const r1 = await dispatch('/admin/auth/github');
    const st = new URL(r1.headers.get('location')!).searchParams.get('state')!;
    const stCookie = extractSetCookies(r1.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith('__Host-ef_gh_oauth='))!;
    const r2 = await dispatch(`/admin/auth/github/callback?code=c&state=${encodeURIComponent(st)}`, { headers: { cookie: stCookie } });
    const aliceCookie = extractSetCookies(r2.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith(`${ADMIN_COOKIE_NAME}=`))!;
    const aliceSession = await verifyAdminSessionCookie(aliceCookie, SESSION_SECRET);
    assert.equal(aliceSession.ok, true);
    if (!aliceSession.ok) throw new Error('alice session invalid');

    // Connect connector whose `get_page` tool OMITS `readOnlyHint: true`
    exposeExplicitReadOnly = false;
    const conn1 = await dispatch('/admin/api/mcp/connect', {
      method: 'POST',
      headers: {
        cookie: aliceCookie,
        origin: 'https://hub.example.com',
        'x-csrf-token': aliceSession.csrf,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Docs Corp',
        slug: 'docs-corp',
        remoteUrl: 'https://mcp.docs-corp.example/mcp',
        domains: ['docs-corp.example'],
        autoRouteScrape: true,
      }),
    });
    assert.equal(conn1.status, 200);

    // Mint OAuth token with `crawl:read crawl:fetch mcp:call` for Alice
    const reg = await dispatch('/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'R11 CLI', redirect_uris: ['http://127.0.0.1:54329/cb'] }),
    });
    const { client_id } = (await reg.json()) as { client_id: string };
    const verifier = 'verifier_r11_s6_0123456789abcdefghijklmnopqrstuvwxyzABC';
    const challenge = await sha256Base64Url(verifier);
    const authGet = await dispatch(
      `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:54329/cb')}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256&scope=${encodeURIComponent('crawl:read crawl:fetch mcp:call')}&state=s`,
      { headers: { cookie: aliceCookie } },
    );
    const csrfCookie = extractSetCookies(authGet.headers).map((c) => c.split(';')[0]!.trim()).find((c) => c.startsWith('ef_oauth_csrf='))!;
    const html = await authGet.text();
    const sealed = /name="sealed"\s+value="([^"]+)"/.exec(html)![1]!;
    const csrf = /name="csrf"\s+value="([^"]+)"/.exec(html)![1]!;
    const authPost = await dispatch('/oauth/authorize', {
      method: 'POST',
      headers: { cookie: `${aliceCookie}; ${csrfCookie}`, origin: 'https://hub.example.com', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ decision: 'approve', sealed, csrf }).toString(),
    });
    const code = new URL(authPost.headers.get('location')!).searchParams.get('code')!;
    const tokRes = await dispatch('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        client_id,
        redirect_uri: 'http://127.0.0.1:54329/cb',
        code_verifier: verifier,
      }),
    });
    const { access_token: aliceMcpToken } = (await tokRes.json()) as { access_token: string };

    // 1. Both `/v1/scrape` and MCP `scrape` MUST skip `get_page` because `readOnlyHint !== true`!
    const restUnannotated = await dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: `Bearer ${aliceMcpToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://docs-corp.example/page-1', preferMcp: true }),
    });
    assert.equal(restUnannotated.status, 200);
    assert.match(((await restUnannotated.json()) as { markdown: string }).markdown, /HTTP_FALLBACK_SCRAPE_BODY/);
    assert.equal(mcpToolCalls, 0, 'POST /v1/scrape must NOT invoke MCP tool lacking readOnlyHint: true');

    const mcpUnannotated = await dispatch('/mcp', {
      method: 'POST',
      headers: { authorization: `Bearer ${aliceMcpToken}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'scrape', arguments: { url: 'https://docs-corp.example/page-2', preferMcp: true } },
      }),
    });
    assert.equal(mcpUnannotated.status, 200);
    assert.equal(mcpToolCalls, 0, 'MCP scrape tool must NOT invoke MCP tool lacking readOnlyHint: true');

    // Forwarding explicit `allowedMcpTools: ["docs-corp/get_page"]` permits that specific unannotated tool!
    const restExplicitAllowed = await dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: `Bearer ${aliceMcpToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        url: 'https://docs-corp.example/page-allowlisted',
        preferMcp: true,
        allowedMcpTools: ['docs-corp/get_page'],
      }),
    });
    assert.equal(restExplicitAllowed.status, 200);
    assert.match(((await restExplicitAllowed.json()) as { markdown: string }).markdown, /MCP_READONLY_VERIFIED_BODY/);
    assert.equal(mcpToolCalls, 1);
    mcpToolCalls = 0;

    // 2. Once connector tool explicitly declares `annotations: { readOnlyHint: true }`, both route via MCP!
    exposeExplicitReadOnly = true;
    const conn2 = await dispatch('/admin/api/mcp/connect', {
      method: 'POST',
      headers: {
        cookie: aliceCookie,
        origin: 'https://hub.example.com',
        'x-csrf-token': aliceSession.csrf,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Docs Corp',
        slug: 'docs-corp',
        remoteUrl: 'https://mcp.docs-corp.example/mcp',
        domains: ['docs-corp.example'],
        autoRouteScrape: true,
      }),
    });
    assert.equal(conn2.status, 200);

    const restAnnotated = await dispatch('/v1/scrape', {
      method: 'POST',
      headers: { authorization: `Bearer ${aliceMcpToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://docs-corp.example/page-3', preferMcp: true }),
    });
    assert.equal(restAnnotated.status, 200);
    assert.match(((await restAnnotated.json()) as { markdown: string }).markdown, /MCP_READONLY_VERIFIED_BODY/);
    assert.equal(mcpToolCalls, 1);
  } finally {
    coordinator.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Round 11 Stream 5 [M5]: Pre-v2.7.5 legacy opaque refresh tokens upgrade to HMAC lineage on first rotation & revoke on replay', async () => {
  const db = new DatabaseSync(':memory:');
  const sqlStore = createSqliteOAuthStore(wrapNodeSqlite(db));
  const memStore = createMemoryOAuthStore();
  const SECRET = 'r11-m5-signing-secret-0123456789abcdef';

  try {
    for (const [label, store] of [
      ['sqlite', sqlStore],
      ['memory', memStore],
    ] as Array<[string, OAuthStore]>) {
      let now = 10_000_000;
      const clientId = `cli_m5_${label}`;
      await store.putClient({
        clientId,
        clientName: 'Legacy Upgrade Client',
        redirectUris: ['http://127.0.0.1:8123/cb'],
        createdAt: now,
      });

      // Seed TWO pre-v2.7.5 legacy non-lineage refresh tokens:
      //  (a) `grant_legacy_v274_abcd` (matches `grant_*` prefix)
      //  (b) `old_custom_id` (pre-v2.7.5 non-`grant_` ID -> upgraded to `grant_<rand>` on first rotation)
      for (const seed of [
        { initialGrantId: 'grant_legacy_v274_abcd', legacyRefresh: `efr_legacy_opaque_secret_${label}_a` },
        { initialGrantId: 'old_custom_id', legacyRefresh: `efr_legacy_opaque_secret_${label}_b` },
      ]) {
        await store.putTokenPair({
          grantId: seed.initialGrantId,
          accessHash: await sha256Base64Url(`efa_legacy_${label}_${seed.initialGrantId}`),
          refreshHash: await sha256Base64Url(seed.legacyRefresh),
          clientId,
          clientName: 'Legacy Upgrade Client',
          scopes: ['crawl:read', 'crawl:fetch'],
          resource: 'https://hub.example.com/mcp',
          userId: 'owner',
          userRole: 'owner',
          createdAt: now,
          accessExpiresAt: now + 3_600_000,
          refreshExpiresAt: now + 90 * 86_400_000,
        });

        const callTokenEndpoint = async (refreshTok: string) =>
          (await handleOAuthRoute(
            new Request('https://hub.example.com/oauth/token', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: refreshTok, client_id: clientId }),
            }),
            new URL('https://hub.example.com/oauth/token'),
            {
              store,
              ownerSecret: SECRET,
              sessionSecret: SECRET,
              serviceName: 'EdgeFetch Hub',
              now: () => now,
            },
          ))!;

        // 1st rotation of legacy opaque refresh token MUST immediately emit HMAC-authenticated lineage token `efr_grant_...1.<rand>.<sig22>`!
        now += 1_000;
        const rot1Res = await callTokenEndpoint(seed.legacyRefresh);
        assert.equal(rot1Res.status, 200, `${label}/${seed.initialGrantId}: first legacy rotation must succeed`);
        const rot1Json = (await rot1Res.json()) as { access_token: string; refresh_token: string };
        assert.match(
          rot1Json.refresh_token,
          /^efr_grant_[A-Za-z0-9_-]{8,40}\.1\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{22}$/,
          `${label}/${seed.initialGrantId}: first rotation must upgrade legacy token to lineage format`,
        );

        // Rotate two more times (`gen 1 -> gen 2 -> gen 3`) so `rot1Json.refresh_token`'s `refresh_used` marker is pruned!
        now += 65_000;
        const rot2Res = await callTokenEndpoint(rot1Json.refresh_token);
        assert.equal(rot2Res.status, 200);
        const rot2Json = (await rot2Res.json()) as { refresh_token: string };

        now += 1_000;
        const rot3Res = await callTokenEndpoint(rot2Json.refresh_token);
        assert.equal(rot3Res.status, 200);
        const rot3Json = (await rot3Res.json()) as { access_token: string; refresh_token: string };
        assert.ok(await store.getAccessToken(await sha256Base64Url(rot3Json.access_token), now));

        // Replaying pruned `rot1Json.refresh_token` (`gen = 1 < 3`) MUST trigger lineage replay detection and revoke `rot3Json.access_token`!
        now += 1_000;
        const replayRes = await callTokenEndpoint(rot1Json.refresh_token);
        assert.equal(replayRes.status, 400);
        assert.equal(
          await store.getAccessToken(await sha256Base64Url(rot3Json.access_token), now),
          null,
          `${label}/${seed.initialGrantId}: replay of gen-1 token after legacy upgrade must revoke the entire grant`,
        );
      }
    }

    // Also verify corrupted SQLite rows with empty `grant_id` are cleaned up on store initialization
    db.prepare(
      `INSERT INTO oauth_tokens (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, user_id, user_role, created_at, expires_at)
       VALUES ('corrupt_empty_gid', '', 'refresh', 'cli_x', 'Corrupt', '["crawl:read"]', 'https://hub.example.com/mcp', 'owner', 'owner', 1000, 999999999)`,
    ).run();
    const freshSqlStore = createSqliteOAuthStore(wrapNodeSqlite(db));
    const badRot = await freshSqlStore.rotateRefreshToken({
      refreshHash: 'corrupt_empty_gid',
      clientId: 'cli_x',
      nextAccessHash: 'na',
      nextRefreshHash: 'nr',
      now: 2_000,
      accessExpiresAt: 10_000,
      refreshExpiresAt: 20_000,
    });
    assert.equal(badRot.ok, false);
  } finally {
    db.close();
  }
});

test('Round 11 Stream 5 [M6]: /v1/jobs & MCP jobs enforce per-user scrape concurrency slot + isolate jobs scrape cache by caller userId/tier', async () => {
  // Part B: Verify `executeJobsCall` keys shared cache & in-flight dedup by `(authTier, userId)` so users never cross-bleed!
  resetJobsCacheForTests();
  const sharedEnv = { JOBS_SHARED_CACHE: true };
  const scrapedByCaller: string[] = [];

  const runForUser = (userId: string, authTier: string, roleTitle: string) =>
    executeJobsCall({
      payload: { domains: ['isolated-corp.com'], query: 'Engineer', includeBuiltIn: false },
      env: sharedEnv,
      userId,
      authTier,
      executeSearch: async () => ({ status: 200, body: { results: [] } }),
      executeScrape: async (args) => {
        const u = String(args.url);
        scrapedByCaller.push(`${authTier}:${userId}:${u}`);
        if (u === 'https://isolated-corp.com/careers') {
          return {
            status: 200,
            body: {
              ok: true,
              url: u,
              finalUrl: u,
              markdown: '# Careers',
              rawHtml: '<a href="https://jobs.ashbyhq.com/isolatedcorp">Openings</a>',
              links: ['https://jobs.ashbyhq.com/isolatedcorp'],
            },
          };
        }
        if (u.startsWith('https://jobs.ashbyhq.com/isolatedcorp')) {
          return {
            status: 200,
            body: {
              ok: true,
              extractorId: 'ashby',
              url: u,
              total: 1,
              returned: 1,
              truncated: false,
              jobs: [
                {
                  title: roleTitle,
                  company: 'IsolatedCorp',
                  url: 'https://jobs.ashbyhq.com/isolatedcorp/1',
                  applyUrl: 'https://jobs.ashbyhq.com/isolatedcorp/1',
                  workplaceType: 'remote',
                  locations: ['Remote'],
                  pay: null,
                  postedAt: '2026-11-20',
                  source: 'ashby',
                },
              ],
            },
          };
        }
        return { status: 404, body: { ok: false, status: 404 } };
      },
    });

  const userAOut = await runForUser('gh_101', 'member', 'Alice Private Tenant Staff Engineer');
  const userBOut = await runForUser('gh_102', 'member', 'Bob Distinct Staff Engineer');
  const ownerOut = await runForUser('owner', 'owner', 'Owner Staff Engineer');

  assert.equal((userAOut.body.jobs as StructuredJobRecord[])[0]?.title, 'Alice Private Tenant Staff Engineer');
  assert.equal(
    (userBOut.body.jobs as StructuredJobRecord[])[0]?.title,
    'Bob Distinct Staff Engineer',
    'User B must NOT receive User A cached jobs scrape response',
  );
  assert.equal(
    (ownerOut.body.jobs as StructuredJobRecord[])[0]?.title,
    'Owner Staff Engineer',
    'Owner tier must NOT receive member cached jobs scrape response',
  );

  // Part A: Verify `POST /v1/jobs` and MCP `jobs` share the 16-slot per-user `inFlightScrapesByUser` limiter without self-deadlocking!
  const tmpDir = mkdtempSync(join(tmpdir(), 'ef-r11-m6-'));
  const coordinator = new LocalAgentHubCoordinator(join(tmpDir, 'hub.sqlite'));
  const OWNER_TOKEN = 'owner-secret-token-r11-m6-0123456789abcdef';

  let releaseBarrier!: () => void;
  const barrier = new Promise<void>((r) => {
    releaseBarrier = r;
  });
  let enteredCount = 0;
  let allSixteenEnteredResolve!: () => void;
  const allSixteenEntered = new Promise<void>((r) => {
    allSixteenEnteredResolve = r;
  });

  const slowFetch: typeof fetch = async (input) => {
    const u = new URL(input instanceof Request ? input.url : String(input));
    if (u.pathname === '/robots.txt') {
      return new Response('User-agent: *\nAllow: /\n', { status: 200 });
    }
    enteredCount++;
    if (enteredCount === 16) allSixteenEnteredResolve();
    await barrier;
    return new Response('<html><body><main>Done</main></body></html>', {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  };

  const env: Record<string, unknown> = {
    AGENT_HUB: coordinator.asNamespace(),
    CALLER_TOKEN: OWNER_TOKEN,
    SAFE_PUBLIC_FETCH: slowFetch,
    SAFE_FETCH: slowFetch,
  };
  const dispatch = (path: string, init?: RequestInit) =>
    (hubWorker as { fetch(r: Request, e: unknown): Promise<Response> }).fetch(
      new Request(`https://hub.example.com${path}`, init),
      env,
    );

  try {
    // Hold 15 `/v1/scrape` slots + 1 `/v1/jobs` slot = 16 concurrent slots for `owner`
    const held: Array<Promise<Response>> = [];
    for (let i = 0; i < 15; i++) {
      held.push(
        dispatch('/v1/scrape', {
          method: 'POST',
          headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
          body: JSON.stringify({ url: `https://slot-${i}.example.com/page` }),
        }),
      );
    }
    held.push(
      dispatch('/v1/jobs', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ mode: 'verify', urls: ['https://slot-jobs.example.com/role-1'] }),
      }),
    );

    await allSixteenEntered;

    // 17th concurrent `/v1/jobs` call MUST be rejected with 429!
    const overRestJobs = await dispatch('/v1/jobs', {
      method: 'POST',
      headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
      body: JSON.stringify({ mode: 'verify', urls: ['https://extra.example.com/role-2'] }),
    });
    assert.equal(overRestJobs.status, 429, 'POST /v1/jobs must enforce per-user 16-slot scrape concurrency cap');
    assert.equal(((await overRestJobs.json()) as { error: string }).error, 'user_quota_exceeded');

    // 17th concurrent MCP `jobs` tool call MUST ALSO be rejected with 429 (`isError: true`)!
    const overMcpJobs = await dispatch('/mcp', {
      method: 'POST',
      headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 77,
        method: 'tools/call',
        params: { name: 'jobs', arguments: { mode: 'verify', urls: ['https://extra.example.com/role-3'] } },
      }),
    });
    assert.equal(overMcpJobs.status, 200);
    const mcpRpc = (await overMcpJobs.json()) as { result?: { isError?: boolean; content?: Array<{ text: string }> } };
    assert.equal(mcpRpc.result?.isError, true, 'MCP jobs tool must reject when per-user scrape concurrency slots are full');
    assert.match(mcpRpc.result?.content?.[0]?.text ?? '', /user_quota_exceeded|concurrent scrape limit/i);

    // Release barrier and verify the in-flight `/v1/jobs` call completes cleanly without deadlocking against itself!
    releaseBarrier();
    const settled = await Promise.all(held);
    assert.equal(settled[15]?.status, 200, 'Active /v1/jobs call holding slot #16 must complete cleanly without self-deadlock');
  } finally {
    releaseBarrier();
    coordinator.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Round 11 Stream 5 [M7]: Open-signup users are capped per-account & blocked from consuming reserved owner/allowlist OAuth pool', async () => {
  assert.ok(MAX_OAUTH_GRANTS_PER_OPEN_USER <= 5);
  assert.ok(RESERVED_VETTED_OAUTH_TOKEN_POOL >= Math.floor(MAX_OAUTH_TOKENS_GLOBAL * 0.2));
  assert.equal(MAX_OAUTH_TOKENS_OPEN_GLOBAL, MAX_OAUTH_TOKENS_GLOBAL - RESERVED_VETTED_OAUTH_TOKEN_POOL);

  const db = new DatabaseSync(':memory:');
  const sqlStore = createSqliteOAuthStore(wrapNodeSqlite(db));
  const memStore = createMemoryOAuthStore();

  try {
    for (const [label, store] of [
      ['sqlite', sqlStore],
      ['memory', memStore],
    ] as Array<[string, OAuthStore]>) {
      const now = 50_000_000;
      await store.upsertUser!({
        userId: 'gh_open_1',
        githubId: '9001',
        githubLogin: 'open-signup-user',
        role: 'member',
        admittedVia: 'open',
        createdAt: now,
        lastLoginAt: now,
      });
      await store.upsertUser!({
        userId: 'gh_allow_1',
        githubId: '8001',
        githubLogin: 'vetted-member',
        role: 'member',
        admittedVia: 'allowlist_id',
        createdAt: now,
        lastLoginAt: now,
      });

      // 1. Per-account cap: open user minting 12 grants retains at most `MAX_OAUTH_GRANTS_PER_OPEN_USER` (4) active grants!
      for (let i = 0; i < 12; i++) {
        await store.putTokenPair({
          grantId: `open_g_${i}`,
          accessHash: `open_acc_${label}_${i}`,
          refreshHash: `open_ref_${label}_${i}`,
          clientId: 'cli_open',
          clientName: 'Open Client',
          scopes: ['crawl:read'],
          resource: 'https://hub.example.com/mcp',
          userId: 'gh_open_1',
          userRole: 'member',
          createdAt: now + i,
          accessExpiresAt: now + 3_600_000,
          refreshExpiresAt: now + 86_400_000,
        });
      }
      const openGrants = await store.listGrants(now + 100, 'gh_open_1');
      assert.equal(
        openGrants.length,
        MAX_OAUTH_GRANTS_PER_OPEN_USER,
        `${label}: open-admission user must be capped at ${MAX_OAUTH_GRANTS_PER_OPEN_USER} active grants`,
      );
    }

    // 2. Reserved pool protection: when open accounts reach `MAX_OAUTH_TOKENS_OPEN_GLOBAL`,
    //    new open accounts are rejected (429 OAuthQuotaExceededError) WITHOUT evicting allowlist/owner tokens,
    //    while both `allowlist` AND `owner` accounts continue minting freely in the 20% reserved pool!
    const dbFull = new DatabaseSync(':memory:');
    try {
      const fullStore = createSqliteOAuthStore(wrapNodeSqlite(dbFull));
      const now = 60_000_000;
      await fullStore.upsertUser!({
        userId: 'gh_allow_vip',
        githubId: '777',
        githubLogin: 'vip-allowlisted',
        role: 'member',
        admittedVia: 'allowlist_id',
        createdAt: now,
        lastLoginAt: now,
      });
      await fullStore.upsertUser!({
        userId: 'gh_open_late',
        githubId: '999999',
        githubLogin: 'late-open',
        role: 'member',
        admittedVia: 'open',
        createdAt: now,
        lastLoginAt: now,
      });

      // Seed one allowlisted grant + one owner grant before filling open pool
      await fullStore.putTokenPair({
        grantId: 'grant_vip_1',
        accessHash: 'vip_acc_1',
        refreshHash: 'vip_ref_1',
        clientId: 'cli_1',
        clientName: 'VIP CLI',
        scopes: ['crawl:read', 'crawl:fetch'],
        resource: 'https://hub.example.com/mcp',
        userId: 'gh_allow_vip',
        userRole: 'member',
        createdAt: now,
        accessExpiresAt: now + 3_600_000,
        refreshExpiresAt: now + 86_400_000,
      });
      await fullStore.putTokenPair({
        grantId: 'grant_owner_1',
        accessHash: 'owner_acc_1',
        refreshHash: 'owner_ref_1',
        clientId: 'cli_1',
        clientName: 'Owner CLI',
        scopes: ['crawl:read', 'crawl:fetch'],
        resource: 'https://hub.example.com/mcp',
        userId: 'owner',
        userRole: 'owner',
        createdAt: now,
        accessExpiresAt: now + 3_600_000,
        refreshExpiresAt: now + 86_400_000,
      });

      // Bulk-insert active open-user token pairs up to `MAX_OAUTH_TOKENS_OPEN_GLOBAL - 1`
      dbFull.exec('BEGIN');
      const insTok = dbFull.prepare(
        `INSERT INTO oauth_tokens
         (token_hash, grant_id, kind, client_id, client_name, scopes_json, resource, user_id, user_role, used_at, rotation_counter, created_at, expires_at)
         VALUES (?, ?, 'access', 'cli_1', 'Open', '["crawl:read"]', 'https://hub.example.com/mcp', ?, 'member', NULL, 0, ?, ?)`,
      );
      const rowsToFill = MAX_OAUTH_TOKENS_OPEN_GLOBAL - 4;
      for (let r = 0; r < rowsToFill; r++) {
        insTok.run(`bulk_open_tok_${r}`, `bulk_open_grant_${r}`, `gh_open_u_${r >> 2}`, now, now + 3_600_000);
      }
      dbFull.exec('COMMIT');

      // Open user attempting to cross `MAX_OAUTH_TOKENS_OPEN_GLOBAL` MUST throw `OAuthQuotaExceededError`!
      assert.throws(
        () =>
          fullStore.putTokenPair({
            grantId: 'grant_open_blocked',
            accessHash: 'open_blocked_acc',
            refreshHash: 'open_blocked_ref',
            clientId: 'cli_1',
            clientName: 'Open Blocked',
            scopes: ['crawl:read'],
            resource: 'https://hub.example.com/mcp',
            userId: 'gh_open_late',
            userRole: 'member',
            createdAt: now + 10,
            accessExpiresAt: now + 3_600_000,
            refreshExpiresAt: now + 86_400_000,
          }),
        OAuthQuotaExceededError,
      );

      // Allowlisted user AND Owner MUST still mint grants cleanly inside the reserved 20% pool!
      await fullStore.putTokenPair({
        grantId: 'grant_vip_2',
        accessHash: 'vip_acc_2',
        refreshHash: 'vip_ref_2',
        clientId: 'cli_1',
        clientName: 'VIP CLI 2',
        scopes: ['crawl:read', 'crawl:fetch'],
        resource: 'https://hub.example.com/mcp',
        userId: 'gh_allow_vip',
        userRole: 'member',
        createdAt: now + 20,
        accessExpiresAt: now + 3_600_000,
        refreshExpiresAt: now + 86_400_000,
      });
      await fullStore.putTokenPair({
        grantId: 'grant_owner_2',
        accessHash: 'owner_acc_2',
        refreshHash: 'owner_ref_2',
        clientId: 'cli_1',
        clientName: 'Owner CLI 2',
        scopes: ['crawl:read', 'crawl:fetch'],
        resource: 'https://hub.example.com/mcp',
        userId: 'owner',
        userRole: 'owner',
        createdAt: now + 30,
        accessExpiresAt: now + 3_600_000,
        refreshExpiresAt: now + 86_400_000,
      });

      assert.ok(await fullStore.getAccessToken('vip_acc_1', now + 50));
      assert.ok(await fullStore.getAccessToken('vip_acc_2', now + 50));
      assert.ok(await fullStore.getAccessToken('owner_acc_1', now + 50));
      assert.ok(await fullStore.getAccessToken('owner_acc_2', now + 50));
    } finally {
      dbFull.close();
    }
  } finally {
    db.close();
  }
});

test('Round 11 Stream 5 [M11 & M12]: compile-manifests dot-segment parity + propose-manifest host binding, robots 3xx/hop checks, claimed hosts & recursion bounds', async () => {
  // M11: Reject `/./`, `/../`, trailing `/.` or `/..`, backslash `\`, and `%2e` / `%2E` dot segments in `fetchUrl`!
  const makeTwinManifest = (fetchUrl: string) => ({
    id: 'r11-dot-check',
    name: 'R11 Dot Check',
    category: 'developer',
    description: 'Validates dot-segment and backslash rejection in twin fetchUrl.',
    domains: ['docs.example.org'],
    exampleUrls: ['https://docs.example.org/items/1'],
    routes: [
      {
        match: { pathSegments: ['items', { param: 'id' }] },
        twin: { id: 'r11-dot-twin', fetchUrl, kind: 'json', accept: 'application/json' },
        extract: { titleTemplate: 'Item' },
      },
    ],
  });

  for (const badFetchUrl of [
    'https://docs.example.org/api/./items/{id}',
    'https://docs.example.org/api/../admin/{id}',
    'https://docs.example.org/api/items/.',
    'https://docs.example.org/api/items/..',
    'https://docs.example.org/api\\items/{id}',
    'https://docs.example.org/api/%5citems/{id}',
    'https://docs.example.org/api/%2e/items/{id}',
    'https://docs.example.org/api/%2E%2e/admin/{id}',
    'https://docs.example.org/api/.%2e/admin/{id}',
    'https://docs.example.org/api/items/%2e%2E',
    'https://{host}/api/../admin/{id}',
    '{origin}/api/%2e%2e/admin/{id}',
    'https://{host}/api/./items/{id}',
    '{origin}/api/items/..',
  ]) {
    assert.throws(
      () => validateManifest(makeTwinManifest(badFetchUrl), 'r11-dot.yaml'),
      /fetchUrl/,
      `M11: compile-manifests must reject dot-segment/backslash fetchUrl "${badFetchUrl}"`,
    );
  }

  // Legitimate filenames containing dots (`items.json`, `v1.2`) MUST still pass
  assert.doesNotThrow(() =>
    validateManifest(makeTwinManifest('https://docs.example.org/api/v1.2/items/{id}.json'), 'r11-ok.yaml'),
  );

  // M12 (1) & (2): `fetchPolitePublicHttps` refuses cross-host redirects, treats `robots.txt` `3xx` as disallow,
  //                and re-checks `robots.txt` on every same-host redirect hop!
  const fakeAddr = async () => ({ address: '93.184.216.34', family: 4 });

  // 1a) Cross-host redirect is refused
  await assert.rejects(
    () =>
      fetchPolitePublicHttps(new URL('https://user-named.example.com/start'), 'text/html', {
        resolveAddr: fakeAddr,
        fetchOnce: async (u: URL) => {
          if (u.pathname === '/robots.txt') return { status: 200, headers: {}, body: 'User-agent: *\nAllow: /\n' };
          return { status: 302, headers: { location: 'https://other-host.example.org/landed' }, body: '' };
        },
      }),
    /cross-host/i,
  );

  // 1b) `analyzeHtmlForManifestProposal` also refuses mismatched `requestedUrlStr` vs `urlStr` host
  assert.throws(
    () =>
      analyzeHtmlForManifestProposal({
        html: '<html><body><h1>Hi</h1><article><p>Text</p></article></body></html>',
        urlStr: 'https://redirected.example.org/docs',
        requestedUrlStr: 'https://user-named.example.com/docs',
      }),
    /cross-host/i,
  );

  // 2a) `robots.txt` returning `301`/`302` redirect is treated as disallow!
  await assert.rejects(
    () =>
      fetchPolitePublicHttps(new URL('https://redir-robots.example.com/docs'), 'text/html', {
        resolveAddr: fakeAddr,
        fetchOnce: async (u: URL) => {
          if (u.pathname === '/robots.txt') {
            return { status: 302, headers: { location: 'https://redir-robots.example.com/login' }, body: '' };
          }
          return { status: 200, headers: {}, body: '<html><body>ok</body></html>' };
        },
      }),
    /robots\.txt.*302.*disallow/i,
  );

  // 2b) Same-host redirect into a `Disallow:` path is caught on hop 1 BEFORE fetching the disallowed target!
  let fetchedSecretHop = false;
  await assert.rejects(
    () =>
      fetchPolitePublicHttps(new URL('https://hop-check.example.com/public-entry'), 'text/html', {
        resolveAddr: fakeAddr,
        fetchOnce: async (u: URL) => {
          if (u.pathname === '/robots.txt') {
            return { status: 200, headers: {}, body: 'User-agent: *\nDisallow: /private-internal/\nAllow: /\n' };
          }
          if (u.pathname === '/public-entry') {
            return { status: 302, headers: { location: '/private-internal/dump' }, body: '' };
          }
          fetchedSecretHop = true;
          return { status: 200, headers: {}, body: 'SECRET' };
        },
      }),
    /Disallowed by .*\/robots\.txt for path \/private-internal\/dump/i,
  );
  assert.equal(fetchedSecretHop, false, 'Must block disallowed redirect hop BEFORE fetching redirected path');

  // M12 (3): Refuse hosts already claimed as an adapter domain, wildcard domain, or twin `fetchUrl` host!
  for (const claimedHost of [
    'rubygems.org', // exact YAML manifest domain
    'en.wikipedia.org', // wildcard `*.wikipedia.org` manifest domain
    'jobs.ashbyhq.com', // built-in ATS core adapter domain
    'acme.wd5.myworkdayjobs.com', // built-in Workday wildcard domain
    'api.crossref.org', // cross-domain twin `fetchUrl` host
    'hn.algolia.com', // cross-domain twin `fetchUrl` host
    'registry.npmjs.org', // cross-domain twin `fetchUrl` host
    'boards-api.greenhouse.io', // built-in ATS twin `fetchUrl` host
  ]) {
    assert.ok(checkClaimedAdapterOrTwinHost(claimedHost), `Expected "${claimedHost}" to be recognized as claimed`);
    assert.throws(
      () =>
        analyzeHtmlForManifestProposal({
          urlStr: `https://${claimedHost}/sample/1`,
          html: '<html><body><h1>Sample</h1><article><p>Body</p></article></body></html>',
        }),
      /already claimed/i,
      `propose-manifest must refuse already-claimed host "${claimedHost}"`,
    );
  }

  // M12 (4): Deeply nested DOM (`5,000` levels) and deeply nested JSON-LD (`10,000` levels) complete cleanly without RangeError!
  const deepDomHtml = `${'<div>'.repeat(2_500)}<h1>Safe Title</h1>${'</div>'.repeat(2_500)}<script type="application/ld+json">${'['.repeat(5_000)}"Article"${']'.repeat(5_000)}</script>`;
  const boundedProposal = analyzeHtmlForManifestProposal({
    urlStr: 'https://fresh-unclaimed-site.example.com/articles/1',
    slugOverride: 'fresh-unclaimed',
    html: `<!doctype html><html><body><h1>Top Heading</h1><article><p>Body</p></article>${deepDomHtml}</body></html>`,
  });
  assert.equal(boundedProposal.host, 'fresh-unclaimed-site.example.com');
});

test('Round 11 Stream 5 [P3-2 & P3-5]: Wikipedia quota bucket non-eviction + query-string article URLs & Jobs cross-TLD spoofing rejection', () => {
  // P3-2 Part 1: Spraying 1,100 other buckets MUST NOT evict an actively blocked (or non-expired within-window) quota bucket!
  resetWikipediaStateForTests();
  const baseNow = 1_000_000;
  assert.equal(
    checkAndRecordWikipediaArticleQuota({ callerKey: 'attacker', host: 'en.wikipedia.org', now: baseNow, limitPerHour: 2 }).allowed,
    true,
  );
  assert.equal(
    checkAndRecordWikipediaArticleQuota({ callerKey: 'attacker', host: 'en.wikipedia.org', now: baseNow + 10, limitPerHour: 2 }).allowed,
    true,
  );
  const blockedInitial = checkAndRecordWikipediaArticleQuota({
    callerKey: 'attacker',
    host: 'en.wikipedia.org',
    now: baseNow + 20,
    limitPerHour: 2,
  });
  assert.equal(blockedInitial.allowed, false);

  // Also put a 1-of-2 active bucket in slot 1 (`pacing-attacker|de.wikipedia.org`)
  assert.equal(
    checkAndRecordWikipediaArticleQuota({ callerKey: 'pacing', host: 'de.wikipedia.org', now: baseNow + 30, limitPerHour: 2 }).allowed,
    true,
  );

  // Spray 1,100 distinct caller/host buckets within the same hour window
  for (let i = 0; i < 1_100; i++) {
    checkAndRecordWikipediaArticleQuota({
      callerKey: `spray_${i}`,
      host: `l${i % 200}.wikipedia.org`,
      now: baseNow + 100 + i,
      limitPerHour: 200,
    });
  }

  // Blocked bucket MUST remain blocked!
  const stillBlocked = checkAndRecordWikipediaArticleQuota({
    callerKey: 'attacker',
    host: 'en.wikipedia.org',
    now: baseNow + 5_000,
    limitPerHour: 2,
  });
  assert.equal(stillBlocked.allowed, false, 'P3-2: Blocked Wikipedia quota bucket must NEVER be evicted by other-host/caller spray');

  // Pacing bucket (`1/2`) MUST retain its prior hit count (so hit #2 succeeds and hit #3 blocks)!
  const pacingSecond = checkAndRecordWikipediaArticleQuota({
    callerKey: 'pacing',
    host: 'de.wikipedia.org',
    now: baseNow + 5_010,
    limitPerHour: 2,
  });
  assert.equal(pacingSecond.allowed, true);
  if (pacingSecond.allowed) assert.equal(pacingSecond.count, 2);
  const pacingThird = checkAndRecordWikipediaArticleQuota({
    callerKey: 'pacing',
    host: 'de.wikipedia.org',
    now: baseNow + 5_020,
    limitPerHour: 2,
  });
  assert.equal(pacingThird.allowed, false, 'P3-2: Active within-window quota bucket must not lose its count to spray eviction');

  // After the 1-hour window expires, expired buckets sweep cleanly and new callers succeed
  const afterWindow = checkAndRecordWikipediaArticleQuota({
    callerKey: 'fresh_after_hour',
    host: 'fr.wikipedia.org',
    now: baseNow + 3_700_000,
    limitPerHour: 2,
  });
  assert.equal(afterWindow.allowed, true);
  resetWikipediaStateForTests();

  // P3-2 Part 2: `?title=`, `?oldid=`, and `action=render` forms count as Wikipedia article URLs!
  const rustIndex = parseWikipediaArticleUrl('https://en.wikipedia.org/w/index.php?title=Rust_(programming_language)');
  assert.ok(rustIndex);
  assert.equal(rustIndex.canonicalUrl, 'https://en.wikipedia.org/wiki/Rust_(programming_language)');

  const oldIdOnly = parseWikipediaArticleUrl('https://en.wikipedia.org/w/index.php?oldid=123456');
  assert.ok(oldIdOnly);
  assert.equal(oldIdOnly.host, 'en.wikipedia.org');

  const wSlashRender = parseWikipediaArticleUrl('https://en.wikipedia.org/w/?title=Foo&action=render');
  assert.ok(wSlashRender);
  assert.equal(wSlashRender.canonicalUrl, 'https://en.wikipedia.org/wiki/Foo');

  const wikiActionRender = parseWikipediaArticleUrl('https://en.wikipedia.org/wiki/Foo?action=render');
  assert.ok(wikiActionRender);
  assert.equal(wikiActionRender.canonicalUrl, 'https://en.wikipedia.org/wiki/Foo');

  // Disallowed namespaces and non-render actions (`action=edit`, `diff=`, `/w/api.php`) MUST still return `null`!
  assert.equal(parseWikipediaArticleUrl('https://en.wikipedia.org/w/index.php?title=Special:Search'), null);
  assert.equal(parseWikipediaArticleUrl('https://en.wikipedia.org/w/index.php?title=Foo&action=edit'), null);
  assert.equal(parseWikipediaArticleUrl('https://en.wikipedia.org/w/index.php?oldid=123456&diff=prev'), null);
  assert.equal(parseWikipediaArticleUrl('https://en.wikipedia.org/w/api.php?action=render&oldid=123'), null);

  // P3-5: Jobs brand filter MUST reject cross-TLD spoofing (`acme.io` must NOT accept `acme.com`, `acme.ai`, `acme.xyz`, `acme.ru`, `acme.attacker.tld`)!
  const mkJob = (company: string, url: string): StructuredJobRecord => ({
    title: 'Security Engineer',
    company,
    url,
    applyUrl: url,
    workplaceType: 'remote',
    locations: ['Remote'],
    pay: null,
    postedAt: null,
    source: 'custom',
  });

  // Exact registrable domain & subdomains of `acme.io` ARE accepted
  assert.equal(matchesAllowedCompanyOrDomain(mkJob('Acme', 'https://acme.io/jobs/1'), new Set(['acme.io']), []), true);
  assert.equal(matchesAllowedCompanyOrDomain(mkJob('Engineering', 'https://careers.acme.io/jobs/1'), new Set(['acme.io']), []), true);

  // Same registrable brand label on ANY other TLD (or subdomain of attacker TLD) MUST be rejected!
  for (const crossTldSpoof of [
    'https://acme.com/jobs/1',
    'https://careers.acme.com/jobs/1',
    'https://acme.ai/jobs/1',
    'https://acme.co/jobs/1',
    'https://acme.xyz/jobs/1',
    'https://acme.ru/jobs/1',
    'https://acme.de/jobs/1',
    'https://acme.sh/jobs/1',
    'https://acme.attacker.tld/jobs/1',
  ]) {
    assert.equal(
      matchesAllowedCompanyOrDomain(mkJob('Acme', crossTldSpoof), new Set(['acme.io']), []),
      false,
      `P3-5: domains=["acme.io"] must reject cross-TLD URL "${crossTldSpoof}"`,
    );
    assert.equal(
      matchesAllowedCompanyOrDomain(mkJob('Acme', crossTldSpoof), new Set(['acme', 'acme.io']), []),
      false,
      `P3-5: company="acme" + domains=["acme.io"] must reject cross-TLD URL "${crossTldSpoof}"`,
    );
  }

  // Bare company token (`"acme"` or `"stripe"`) must ALSO reject non-official cross-TLDs (`acme.io`, `stripe.io`, `stripe.ai`, `stripe.co`)!
  assert.equal(matchesAllowedCompanyOrDomain(mkJob('Acme', 'https://acme.io/jobs/1'), new Set(['acme']), []), false);
  assert.equal(matchesAllowedCompanyOrDomain(mkJob('Stripe', 'https://stripe.io/jobs/1'), new Set(['stripe']), []), false);
  assert.equal(matchesAllowedCompanyOrDomain(mkJob('Stripe', 'https://stripe.ai/jobs/1'), new Set(['stripe']), []), false);
});

test('R11-M5-portable: LocalAgentHubCoordinator preserves grantId and increments rotation_counter when upgrading pre-v2.7.5 refresh token', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'ef-r11-m5-portable-'));
  const coordinator = new LocalAgentHubCoordinator(join(tmpDir, 'hub.sqlite'));
  const SESSION_SECRET = 'r11-m5-portable-session-secret-0123456789abcdef';
  const now = Date.now();
  try {
    const ns = coordinator.asNamespace();
    const stub = ns.get(ns.idFromName('global')) as unknown as {
      oauthPutClient(c: Parameters<OAuthStore['putClient']>[0]): Promise<void> | void;
      oauthPutTokenPair(p: Parameters<OAuthStore['putTokenPair']>[0]): Promise<void> | void;
      oauthRevokeGrant(id: string, userId?: string): Promise<boolean> | boolean;
      oauthGetRefreshTokenLineageHint?: (h: string, now: number) => unknown;
    };
    assert.equal(typeof stub.oauthGetRefreshTokenLineageHint, 'function');

    await stub.oauthPutClient({
      clientId: 'ef_client_portable_m5',
      clientName: 'Portable M5 Client',
      redirectUris: ['http://127.0.0.1:8910/cb'],
      tokenEndpointAuthMethod: 'none',
      createdAt: now,
    });

    const legacyOpaqueRefresh = 'efr_legacy_pre_275_opaque_token_portable_12345';
    const legacyRefreshHash = await sha256Base64Url(legacyOpaqueRefresh);
    await stub.oauthPutTokenPair({
      grantId: 'grant_original_portable_1234',
      accessHash: await sha256Base64Url('efa_legacy_access_portable_12345'),
      refreshHash: legacyRefreshHash,
      clientId: 'ef_client_portable_m5',
      clientName: 'Portable M5 Client',
      scopes: ['mcp:read'],
      resource: 'https://hub.example.com/mcp',
      userId: 'owner',
      userRole: 'owner',
      createdAt: now - 10_000,
      accessExpiresAt: now + 3_600_000,
      refreshExpiresAt: now + 86_400_000,
    });
    // Simulate 5 prior pre-v2.7.5 rotations directly in SQLite (`rotation_counter = 5`) before Portable Hub upgrade!
    const rawDb = new DatabaseSync(join(tmpDir, 'hub.sqlite'));
    rawDb.prepare('UPDATE oauth_tokens SET rotation_counter = 5 WHERE token_hash = ?').run(legacyRefreshHash);
    rawDb.close();

    const env = {
      AGENT_HUB: ns,
      ADMIN_SESSION_SECRET: SESSION_SECRET,
      CALLER_TOKEN: 'owner-caller-token-portable-m5-0123456789',
    };
    const res = await (hubWorker as { fetch(r: Request, e: unknown): Promise<Response> }).fetch(
      new Request('https://hub.example.com/oauth/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: legacyOpaqueRefresh,
          client_id: 'ef_client_portable_m5',
        }).toString(),
      }),
      env,
    );
    assert.equal(res.status, 200);
    const tokJson = (await res.json()) as { refresh_token: string };
    assert.match(tokJson.refresh_token, /^efr_grant_original_portable_1234\.6\./);

    const revoked = await stub.oauthRevokeGrant('grant_original_portable_1234', 'owner');
    assert.equal(revoked, true, 'Original grantId must remain revocable after Portable Hub legacy refresh upgrade');
  } finally {
    coordinator.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
