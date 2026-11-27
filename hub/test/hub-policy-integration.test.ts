import assert from 'node:assert/strict';
import test from 'node:test';
import { invalidateAccessPolicyCache } from '../src/access-policy.ts';
import { mintSessionJwt } from '../src/github-auth.ts';
import { applyHubSecretOverlayFromBinding, invalidateHubSecretsCache } from '../src/hub-secrets.ts';
import hubWorker from '../src/index.ts';
import { sanitizeSecretHeadersInput } from '../src/mcp-vault.ts';
import { ADMIN_COOKIE_NAME, createAdminSessionValue, sha256Base64Url } from '../src/oauth.ts';
import { LocalAgentHubCoordinator } from './stubs/cf-storage-mocks.ts';

const OWNER_SECRET = 'policy-int-owner-secret-0123456789abcdef';
const VAULT_KEY = 'policy-int-vault-master-key-0123456789abcdef';
const ORIGIN = 'https://hub.example.com';
const MAPS_URL = 'https://mapstools.example.com/mcp';
const ALICE_MAPS_KEY = 'AIzaALICE_PRIVATE_MAPS_KEY_123';
const SERPER_OVERRIDE = 'serper-override-value-XYZ-987';

interface OtlpSpan {
  name: string;
  attributes?: Array<{ key: string; value?: { stringValue?: string; intValue?: string; boolValue?: boolean } }>;
}

function traceparent(): string {
  const hex = (n: number) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `00-${hex(16)}-${hex(8)}-01`;
}

async function setup() {
  invalidateAccessPolicyCache();
  invalidateHubSecretsCache();
  const coordinator = new LocalAgentHubCoordinator(':memory:');
  const otlpSpans: OtlpSpan[] = [];
  const otlpBodies: string[] = [];
  const mapsCalls: Array<{ method: string; key: string | null; args?: unknown }> = [];

  const mcpRemote = async (req: Request): Promise<Response> => {
    const rpc = JSON.parse(await req.text()) as { id?: number | string; method?: string; params?: Record<string, unknown> };
    mapsCalls.push({ method: String(rpc.method), key: req.headers.get('x-goog-api-key'), args: rpc.params?.arguments });
    if (req.headers.get('x-goog-api-key') !== ALICE_MAPS_KEY) return new Response('Unauthorized', { status: 401 });
    if (rpc.method === 'initialize') {
      return Response.json({
        jsonrpc: '2.0',
        id: rpc.id,
        result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'maps', version: '1.0.0' } },
      });
    }
    if (rpc.method === 'notifications/initialized') return new Response(null, { status: 202 });
    if (rpc.method === 'tools/list') {
      return Response.json({
        jsonrpc: '2.0',
        id: rpc.id,
        result: {
          tools: [
            {
              name: 'search_places',
              description: 'Search Google Maps places.',
              annotations: { readOnlyHint: true },
              inputSchema: { type: 'object', properties: { textQuery: { type: 'string' } }, required: ['textQuery'] },
            },
          ],
        },
      });
    }
    if (rpc.method === 'tools/call') {
      const places = {
        places: [
          {
            displayName: { text: 'Acme Widgets HQ' },
            formattedAddress: '1 Widget Way, Springfield, IL',
            websiteUri: 'https://www.acmewidgets.com/',
            googleMapsUri: 'https://maps.google.com/?cid=1',
            rating: 4.4,
            userRatingCount: 120,
          },
        ],
      };
      return Response.json({ jsonrpc: '2.0', id: rpc.id, result: { content: [{ type: 'text', text: JSON.stringify(places) }] } });
    }
    return Response.json({ jsonrpc: '2.0', id: rpc.id, error: { code: -32601, message: 'nope' } });
  };

  const safeFetch: typeof fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const u = new URL(req.url);
    if (u.href === 'http://127.0.0.1:4318/v1/traces') {
      const bodyText = await req.text();
      otlpBodies.push(bodyText);
      const parsed = JSON.parse(bodyText) as { resourceSpans?: Array<{ scopeSpans?: Array<{ spans?: OtlpSpan[] }> }> };
      for (const rs of parsed.resourceSpans ?? []) for (const ss of rs.scopeSpans ?? []) otlpSpans.push(...(ss.spans ?? []));
      return new Response('{}', { status: 200 });
    }
    if (`${u.origin}${u.pathname}` === MAPS_URL && req.method === 'POST') return mcpRemote(req);
    if (u.pathname === '/robots.txt') return new Response('User-agent: *\nAllow: /\n', { status: 200, headers: { 'content-type': 'text/plain' } });
    return new Response('not found', { status: 404 });
  };

  const now = Date.now();
  const users = [
    ['gh_101', '101', 'alice'],
    ['gh_202', '202', 'bob'],
  ] as const;
  const tokens: Record<string, string> = {};
  for (const [uid, gid, login] of users) {
    await coordinator.oauth.upsertUser!({
      userId: uid,
      githubId: gid,
      githubLogin: login,
      role: 'member',
      sessionEpoch: 1,
      disabled: false,
      admittedVia: 'allowlist_login',
      createdAt: now,
      lastLoginAt: now,
    });
    const bearer = `efa_policy_int_${login}_member_bearer_token_0123456789`;
    tokens[uid] = bearer;
    await coordinator.oauth.putTokenPair({
      grantId: `g_${login}`,
      accessHash: await sha256Base64Url(bearer),
      refreshHash: await sha256Base64Url(`efr_${login}_refresh`),
      clientId: 'c_policy',
      clientName: 'Policy Test',
      scopes: ['crawl:read', 'crawl:fetch', 'mcp:call'],
      resource: `${ORIGIN}/mcp`,
      userId: uid,
      userRole: 'member',
      createdAt: now,
      accessExpiresAt: now + 3_600_000,
      refreshExpiresAt: now + 86_400_000,
    });
  }

  const env = {
    AGENT_HUB: coordinator.asNamespace() as never,
    CALLER_TOKEN: OWNER_SECRET,
    VAULT_MASTER_KEY: VAULT_KEY,
    SERPER_API_KEY: 'env-serper-value-111',
    EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    OTEL_EXPORTER_OTLP_ENDPOINT: 'http://127.0.0.1:4318',
    OTEL_SERVICE_NAME: 'edgefetch-hub-policy-test',
    SAFE_FETCH: safeFetch,
    SAFE_PUBLIC_FETCH: safeFetch,
  };
  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil(p: Promise<unknown>) {
      pending.push(Promise.resolve(p).catch(() => undefined));
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;
  const drain = async () => {
    while (pending.length > 0) await Promise.all(pending.splice(0, pending.length));
  };
  const call = async (path: string, init: RequestInit = {}) => {
    const res = await hubWorker.fetch(new Request(`${ORIGIN}${path}`, init), env as never, ctx);
    await drain();
    return res;
  };

  const ownerSession = await createAdminSessionValue(OWNER_SECRET);
  const ownerCookie = `${ADMIN_COOKIE_NAME}=${ownerSession.value}`;
  const memberSessions: Record<string, { cookie: string; csrf: string }> = {};
  for (const [uid, , login] of users) {
    const minted = await mintSessionJwt({ secret: OWNER_SECRET, userId: uid, role: 'member', githubLogin: login, epoch: 1 });
    memberSessions[uid] = { cookie: `${ADMIN_COOKIE_NAME}=${minted.token}`, csrf: minted.csrf };
  }
  const admin = (
    path: string,
    who: { cookie: string; csrf?: string },
    method: 'GET' | 'POST' | 'DELETE' = 'GET',
    body?: unknown,
    traced = false,
  ) =>
    call(path, {
      method,
      headers: {
        cookie: who.cookie,
        origin: ORIGIN,
        accept: 'application/json',
        ...(who.csrf ? { 'x-csrf-token': who.csrf } : {}),
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(traced ? { traceparent: traceparent() } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
  const owner = { cookie: ownerCookie, csrf: ownerSession.csrf };
  const bearer = (uid: string) => ({ authorization: `Bearer ${tokens[uid]}` });
  const mcp = (uid: string, payload: unknown) =>
    call('/mcp', {
      method: 'POST',
      headers: { ...bearer(uid), 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify(payload),
    });
  const query = (uid: string, payload: unknown) =>
    call('/v1/mcp/query', {
      method: 'POST',
      headers: { ...bearer(uid), 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
  return { coordinator, env, call, admin, owner, memberSessions, bearer, mcp, query, otlpSpans, otlpBodies, mapsCalls };
}

const spanAttr = (span: OtlpSpan, key: string) => {
  const v = span.attributes?.find((a) => a.key === key)?.value;
  return v?.stringValue ?? (v?.intValue !== undefined ? Number(v.intValue) : v?.boolValue);
};

test('policy integration: admin secrets API is owner-only, CSRF-gated, audited, and never returns values', async () => {
  const h = await setup();
  try {
    const alice = h.memberSessions.gh_101!;

    const noCsrf = await h.admin('/admin/api/secrets', { cookie: h.owner.cookie }, 'POST', { name: 'SERPER_API_KEY', value: SERPER_OVERRIDE });
    assert.equal(noCsrf.status, 403);
    assert.equal(((await noCsrf.json()) as { error: string }).error, 'invalid_csrf');

    assert.equal((await h.admin('/admin/api/secrets', alice)).status, 403, 'members cannot read secret status');
    const memberSet = await h.admin('/admin/api/secrets', alice, 'POST', { name: 'SERPER_API_KEY', value: SERPER_OVERRIDE }, true);
    assert.equal(memberSet.status, 403);
    assert.equal(((await memberSet.json()) as { error: string }).error, 'forbidden_role');

    const setRes = await h.admin('/admin/api/secrets', h.owner, 'POST', { name: 'SERPER_API_KEY', value: SERPER_OVERRIDE }, true);
    const setText = await setRes.text();
    assert.equal(setRes.status, 200, setText);
    assert.ok(!setText.includes(SERPER_OVERRIDE), 'set response must not echo the value');
    assert.match(setText, /"fingerprint":"[0-9a-f]{8}"/);

    const boot = await h.admin('/admin/api/secrets', h.owner, 'POST', { name: 'CALLER_TOKEN', value: 'x'.repeat(40) }, true);
    assert.equal(boot.status, 403);
    assert.equal(((await boot.json()) as { error: string }).error, 'bootstrap_secret_readonly');

    const statusRes = await h.admin('/admin/api/secrets', h.owner);
    const statusText = await statusRes.text();
    assert.equal(statusRes.status, 200);
    for (const leaked of [SERPER_OVERRIDE, 'env-serper-value-111', OWNER_SECRET, VAULT_KEY]) {
      assert.ok(!statusText.includes(leaked), `status leaked ${leaked.slice(0, 6)}…`);
    }
    const status = JSON.parse(statusText) as { vaultConfigured: boolean; secrets: Array<Record<string, unknown>> };
    assert.equal(status.vaultConfigured, true);
    const serper = status.secrets.find((s) => s.name === 'SERPER_API_KEY')!;
    assert.equal(serper.source, 'override');
    assert.equal(serper.envSet, true);
    assert.equal(serper.updatedBy, 'owner');
    const callerTok = status.secrets.find((s) => s.name === 'CALLER_TOKEN')!;
    assert.equal(callerTok.managed, false);
    assert.equal(callerTok.source, 'env');

    // The request-entry overlay now resolves the override over the deployment env.
    const overlaid = (await applyHubSecretOverlayFromBinding(h.env)) as Record<string, unknown>;
    assert.equal(overlaid.SERPER_API_KEY, SERPER_OVERRIDE);
    assert.equal(overlaid.CALLER_TOKEN, OWNER_SECRET, 'bootstrap names are never overlaid');

    const del = await h.admin('/admin/api/secrets/SERPER_API_KEY', h.owner, 'DELETE', undefined, true);
    assert.equal(del.status, 200);
    assert.equal(((await del.json()) as { deleted: boolean }).deleted, true);

    const events = await h.coordinator.activity.listEvents(100);
    const adminEvents = events.filter((e) => e.category === 'admin');
    assert.ok(adminEvents.some((e) => e.event === 'hub_secret_set' && e.details.name === 'SERPER_API_KEY'));
    assert.ok(adminEvents.some((e) => e.event === 'hub_secret_delete'));
    assert.ok(adminEvents.some((e) => e.event === 'hub_secret_rejected' && e.details.error === 'bootstrap_secret_readonly'));
    assert.ok(!JSON.stringify(events).includes(SERPER_OVERRIDE), 'activity log must never carry secret values');

    const spanNames = h.otlpSpans.map((s) => s.name);
    assert.ok(spanNames.includes('edgefetch.admin.secret_set'), spanNames.join(','));
    assert.ok(spanNames.includes('edgefetch.admin.secret_delete'), spanNames.join(','));
    const okSet = h.otlpSpans.find((s) => s.name === 'edgefetch.admin.secret_set' && spanAttr(s, 'admin.outcome') === 'ok');
    assert.equal(okSet && spanAttr(okSet, 'admin.setting_name'), 'SERPER_API_KEY');
    assert.ok(h.otlpSpans.some((s) => s.name === 'edgefetch.admin.secret_set' && spanAttr(s, 'admin.outcome') === 'forbidden_role'));
    assert.ok(!h.otlpBodies.join('\n').includes(SERPER_OVERRIDE), 'OTLP spans must never carry secret values');
  } finally {
    h.coordinator.close();
  }
});

test('policy integration: tool + /v1 route rules filter tools/list, 403 tools/call and routes, owners bypass, compat aliases gated', async () => {
  const h = await setup();
  try {
    const alice = h.memberSessions.gh_101!;
    assert.equal((await h.admin('/admin/api/policies', alice)).status, 403);
    const memberRule = await h.admin('/admin/api/policies', alice, 'POST', { subject: '*', resource: 'tool:*', effect: 'deny' }, true);
    assert.equal(memberRule.status, 403);

    for (const rule of [
      { subject: 'gh_202', resource: 'tool:fetch_url', effect: 'deny' },
      { subject: '*', resource: 'route:/v1/capabilities', effect: 'deny' },
      { subject: 'gh_202', resource: 'route:/v1/scrape', effect: 'deny' },
    ]) {
      const res = await h.admin('/admin/api/policies', h.owner, 'POST', rule, true);
      assert.equal(res.status, 200, await res.clone().text());
    }
    const bad = await h.admin('/admin/api/policies', h.owner, 'POST', { subject: '*', resource: 'route:/admin', effect: 'deny' });
    assert.equal(bad.status, 400);
    const listed = (await (await h.admin('/admin/api/policies', h.owner)).json()) as { rules: unknown[]; toolNames: string[] };
    assert.equal(listed.rules.length, 3);
    assert.ok(listed.toolNames.includes('fetch_url'));

    const bobTools = (await (await h.mcp('gh_202', { jsonrpc: '2.0', id: 1, method: 'tools/list' })).json()) as {
      result: { tools: Array<{ name: string }> };
    };
    assert.ok(!bobTools.result.tools.some((t) => t.name === 'fetch_url'), 'denied tool hidden from tools/list');
    assert.ok(bobTools.result.tools.some((t) => t.name === 'scrape'));
    const aliceTools = (await (await h.mcp('gh_101', { jsonrpc: '2.0', id: 2, method: 'tools/list' })).json()) as {
      result: { tools: Array<{ name: string }> };
    };
    assert.ok(aliceTools.result.tools.some((t) => t.name === 'fetch_url'), 'user-specific rule does not affect others');

    const bobCall = await h.mcp('gh_202', {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'fetch_url', arguments: { url: 'https://example.com/' } },
    });
    assert.equal(bobCall.status, 403);
    const bobCallJson = (await bobCall.json()) as { error: { code: number; data: { error: string; tool: string } } };
    assert.equal(bobCallJson.error.data.error, 'forbidden_by_policy');
    assert.equal(bobCallJson.error.data.tool, 'fetch_url');
    const unknownTool = await h.mcp('gh_202', { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'no_such_tool', arguments: {} } });
    assert.notEqual(unknownTool.status, 403, 'unknown tools keep the normal unknown-tool result');

    for (const uid of ['gh_202', 'gh_101']) {
      const capRes = await h.call('/v1/capabilities', { headers: h.bearer(uid) });
      assert.equal(capRes.status, 403, uid);
      assert.equal(((await capRes.json()) as { error: string }).error, 'forbidden_by_policy');
    }
    const ownerCap = await h.call('/v1/capabilities', { headers: { authorization: `Bearer ${OWNER_SECRET}` } });
    assert.equal(ownerCap.status, 200, 'owners bypass route policy');
    const unauth = await h.call('/v1/capabilities');
    assert.equal(unauth.status, 401, 'policy runs only after successful auth');

    const bobScrape = await h.call('/v1/scrape', {
      method: 'POST',
      headers: { ...h.bearer('gh_202'), 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com/' }),
    });
    assert.equal(bobScrape.status, 403);
    const bobV2Scrape = await h.call('/v2/scrape', {
      method: 'POST',
      headers: { ...h.bearer('gh_202'), 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com/' }),
    });
    assert.equal(bobV2Scrape.status, 403, 'Firecrawl /v2 alias cannot bypass a /v1 rule');
    assert.equal(((await bobV2Scrape.json()) as { error: string }).error, 'forbidden_by_policy');

    const events = await h.coordinator.activity.listEvents(200);
    assert.ok(events.some((e) => e.event === 'access_denied_tool' && e.details.tool === 'fetch_url'));
    assert.ok(events.some((e) => e.event === 'access_denied_route' && e.details.path === '/v1/capabilities'));
    assert.ok(events.some((e) => e.event === 'access_rule_set' && e.details.resource === 'tool:fetch_url'));
    assert.ok(h.otlpSpans.some((s) => s.name === 'edgefetch.admin.policy_set' && spanAttr(s, 'admin.outcome') === 'ok'));

    const delRes = await h.admin('/admin/api/policies', h.owner, 'DELETE', { subject: '*', resource: 'route:/v1/capabilities' }, true);
    assert.equal(delRes.status, 200);
    assert.equal((await h.call('/v1/capabilities', { headers: h.bearer('gh_202') })).status, 200, 'cache invalidated on write');
    assert.ok(h.otlpSpans.some((s) => s.name === 'edgefetch.admin.policy_delete'));
  } finally {
    h.coordinator.close();
  }
});

test('policy integration: members share their own MCP server; shared calls unseal the owner credential and never expose URL/headers', async () => {
  const h = await setup();
  try {
    const alice = h.memberSessions.gh_101!;
    const bob = h.memberSessions.gh_202!;

    // Google Maps preset header name is accepted by the connect flow.
    const hdr = sanitizeSecretHeadersInput({ headers: { 'X-Goog-Api-Key': ALICE_MAPS_KEY } });
    assert.equal(hdr.ok, true);

    const connect = await h.admin('/admin/api/mcp/connect', alice, 'POST', {
      name: 'Google Maps',
      slug: 'google-maps',
      remoteUrl: MAPS_URL,
      headers: { 'X-Goog-Api-Key': ALICE_MAPS_KEY },
    });
    assert.equal(connect.status, 200, await connect.clone().text());
    assert.ok(h.mapsCalls.some((c) => c.method === 'tools/list' && c.key === ALICE_MAPS_KEY));

    // Not shared yet: bob can't see or call it.
    const before = await h.query('gh_202', { action: 'list_tools', server: 'google-maps' });
    assert.equal(before.status, 404);
    const beforeExplicit = await h.query('gh_202', { action: 'list_tools', server: 'gh_101/google-maps' });
    assert.equal(beforeExplicit.status, 404);

    // Members may only share their OWN servers.
    const foreign = await h.admin('/admin/api/mcp/shares', bob, 'POST', { ownerUserId: 'gh_101', slug: 'google-maps', subject: 'gh_202' }, true);
    assert.equal(foreign.status, 403);
    const notMine = await h.admin('/admin/api/mcp/shares', bob, 'POST', { slug: 'google-maps', subject: '*' });
    assert.equal(notMine.status, 404, 'bob has no google-maps server of his own');
    const noCsrf = await h.admin('/admin/api/mcp/shares', { cookie: alice.cookie }, 'POST', { slug: 'google-maps', subject: 'gh_202' });
    assert.equal(noCsrf.status, 403);
    const share = await h.admin('/admin/api/mcp/shares', alice, 'POST', { slug: 'google-maps', subject: 'gh_202' }, true);
    assert.equal(share.status, 200, await share.clone().text());

    const aliceShares = (await (await h.admin('/admin/api/mcp/shares', alice)).json()) as Record<string, unknown>;
    assert.equal((aliceShares.shares as unknown[]).length, 1);
    assert.equal(aliceShares.allShares, undefined, 'members never see other users shares');
    const ownerShares = (await (await h.admin('/admin/api/mcp/shares', h.owner)).json()) as Record<string, unknown>;
    assert.equal((ownerShares.allShares as unknown[]).length, 1);

    const sharedList = await h.call('/v1/mcp/shared', { headers: h.bearer('gh_202') });
    const sharedText = await sharedList.text();
    assert.equal(sharedList.status, 200);
    assert.match(sharedText, /gh_101\/google-maps/);
    assert.match(sharedText, /search_places/);
    for (const leaked of ['mapstools.example.com', ALICE_MAPS_KEY, 'X-Goog-Api-Key', 'authSummary']) {
      assert.ok(!sharedText.includes(leaked), `shared listing leaked ${leaked}`);
    }

    const connected = await (await h.query('gh_202', { action: 'list_connected' })).text();
    assert.match(connected, /"shared":\[/);
    assert.ok(!connected.includes('mapstools.example.com'));

    h.mapsCalls.length = 0;
    const callRes = await h.query('gh_202', {
      action: 'call_tool',
      server: 'google-maps',
      tool: 'search_places',
      arguments: { textQuery: 'acme widgets' },
    });
    const callText = await callRes.text();
    assert.equal(callRes.status, 200, callText);
    assert.match(callText, /Acme Widgets HQ/);
    assert.ok(
      h.mapsCalls.some((c) => c.method === 'tools/call' && c.key === ALICE_MAPS_KEY),
      'owner credential unsealed (bound to the owner user id) and sent upstream',
    );
    for (const leaked of ['mapstools.example.com', ALICE_MAPS_KEY]) {
      assert.ok(!callText.includes(leaked), `shared call_tool response leaked ${leaked}`);
    }

    // Company profile for a member uses the Google Maps server shared with them.
    h.mapsCalls.length = 0;
    const company = await h.call('/v1/company', {
      method: 'POST',
      headers: { ...h.bearer('gh_202'), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Acme Widgets', domain: 'acmewidgets.com' }),
    });
    const companyJson = (await company.json()) as Record<string, unknown>;
    assert.equal(company.status, 200, JSON.stringify(companyJson).slice(0, 400));
    assert.notEqual(companyJson.googleMaps, 'not_connected');
    assert.equal(companyJson.googleMaps, 'used', JSON.stringify(companyJson).slice(0, 400));
    assert.ok(h.mapsCalls.some((c) => c.method === 'tools/call' && c.key === ALICE_MAPS_KEY));
    assert.ok(!JSON.stringify(companyJson).includes(ALICE_MAPS_KEY));

    // Unshare revokes access.
    const unshare = await h.admin('/admin/api/mcp/shares', alice, 'DELETE', { slug: 'google-maps', subject: 'gh_202' }, true);
    assert.equal(unshare.status, 200);
    const after = await h.query('gh_202', { action: 'call_tool', server: 'google-maps', tool: 'search_places', arguments: { textQuery: 'x' } });
    assert.equal(after.status, 404);

    const events = await h.coordinator.activity.listEvents(200);
    assert.ok(events.some((e) => e.event === 'access_share_set' && e.details.slug === 'google-maps' && e.details.subject === 'gh_202'));
    assert.ok(events.some((e) => e.event === 'access_share_delete'));
    assert.ok(!JSON.stringify(events).includes(ALICE_MAPS_KEY));
    const shareSpanNames = h.otlpSpans.map((s) => s.name);
    assert.ok(shareSpanNames.includes('edgefetch.admin.share_set'));
    assert.ok(shareSpanNames.includes('edgefetch.admin.share_delete'));
    assert.ok(h.otlpSpans.some((s) => s.name === 'edgefetch.admin.share_set' && spanAttr(s, 'admin.outcome') === 'forbidden_role'));
  } finally {
    h.coordinator.close();
  }
});

test('policy integration: dashboard renders the three new cards and its script parses', async () => {
  const h = await setup();
  try {
    const res = await h.call('/admin', { headers: { cookie: h.owner.cookie } });
    assert.equal(res.status, 200);
    const html = await res.text();
    for (const id of ['secrets-card', 'policy-card', 'sharing-card', 'mcp-gmaps-hint', 'secrets-vault-banner', 'pol-resource-list']) {
      assert.ok(html.includes(`id="${id}"`), id);
    }
    const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map((m) => m[1] ?? '');
    const main = scripts.find((s) => s.includes('loadPolicyCards'));
    assert.ok(main, 'dashboard script includes the new loaders');
    assert.doesNotThrow(() => new Function(main!), 'dashboard script must parse');
  } finally {
    h.coordinator.close();
  }
});
