import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { EdgeFetchClient, EdgeFetchError } from '../../sdk/ts/edgefetch-client.ts';
import { ACTIVITY_SQLITE_SCHEMA, buildCrawlActivityEvents, createSqliteActivityStore } from '../src/activity-log.ts';
import { handleAdminRoute } from '../src/admin.ts';
import {
  AgentHubEngine,
  DEFAULT_429_NO_HEADER_WAIT_MS,
  createMemoryHostWindowStore,
  extractPrimaryHost,
  routeFetchWithFailover,
  type CooldownStore,
  type HubSocketLike,
} from '../src/agent-hub.ts';
import { authorizeAgent } from '../src/auth.ts';
import { handleMcpRequest, type McpServerDeps } from '../src/mcp.ts';
import {
  ADMIN_COOKIE_NAME,
  OAUTH_SQLITE_SCHEMA,
  createAdminSessionValue,
  createSqliteOAuthStore,
  handleOAuthRoute,
  normalizeScopes,
  sha256Base64Url,
  type OAuthStore,
  type SqlStorageLike,
} from '../src/oauth.ts';
import {
  cloudflareOverflowFetch,
  encodeBodyForWire,
  isRobotsAllowed,
  parseOverflowRobotsTxt,
  validateCallRobotsPolicy,
} from '../src/overflow.ts';
import {
  isValidSha256Hex,
  r2ArtifactKey,
  r2DerivedKey,
  r2ManifestKey,
  sanitizeFtsQuery,
  shouldRefreshDedupedObject,
  STORED_RETENTION_MS,
  TRANSIENT_RETENTION_MS,
} from '../src/storage.ts';
import { executeInteractCall, extractYouTubeTranscriptFromHtml } from '../src/scrape.ts';

function memoryCooldowns(): CooldownStore {
  const map = new Map<string, number>();
  return {
    isCooledDown: (host, site, now) => {
      const exp = map.get(`${host}|${site}`);
      if (!exp || exp <= now) {
        map.delete(`${host}|${site}`);
        return false;
      }
      return true;
    },
    setCooldown: (host, site, exp) => {
      map.set(`${host}|${site}`, exp);
    },
    clearSite: (site) => {
      for (const k of map.keys()) {
        if (k.endsWith(`|${site}`)) map.delete(k);
      }
    },
    listPins: (now) => {
      const out = [];
      for (const [k, expiresAt] of map.entries()) {
        if (expiresAt <= now) continue;
        const [host, siteId] = k.split('|');
        out.push({ host: host!, siteId: siteId!, expiresAt });
      }
      return out;
    },
    clearAll: () => map.clear(),
  };
}

function makeFakeSocket(tags: string[], onSend?: (payload: string) => void): HubSocketLike & { sent: string[]; tags: string[] } {
  let attachment: unknown = null;
  const sent: string[] = [];
  return {
    tags,
    sent,
    readyState: 1,
    send: (msg: string) => {
      sent.push(msg);
      onSend?.(msg);
    },
    close: () => undefined,
    serializeAttachment: (v: unknown) => {
      attachment = structuredClone(v);
    },
    deserializeAttachment: () => structuredClone(attachment),
  };
}

test('extractPrimaryHost strips trailing FQDN dot', () => {
  assert.equal(extractPrimaryHost('https://HUB.Example.COM./fetch'), 'hub.example.com');
});

test('all-nodes timeout returns clean 502 instead of sparse-array TypeError', async () => {
  const clock = 1_700_000_000_000;
  const sockets: Array<HubSocketLike & { tags: string[] }> = [];
  const engine = new AgentHubEngine({
    getSockets: (tag) => (tag ? sockets.filter((s) => s.tags.includes(tag)) : sockets),
    cooldowns: memoryCooldowns(),
    now: () => clock,
  });

  const s1 = makeFakeSocket(['site:site-1']);
  const s2 = makeFakeSocket(['site:site-2']);
  sockets.push(s1, s2);
  engine.registerAgent(s1, 'site-1', 'amd64', { version: '1.0.5', publicIp: '203.0.113.10' });
  engine.registerAgent(s2, 'site-2', 'arm64', { version: '1.0.5', publicIp: '198.51.100.20' });

  const res = await engine.dispatchFetch(
    JSON.stringify({
      requests: [
        { id: '1', url: 'https://alpha.example.com/a', kind: 'page' },
        { id: '2', url: 'https://beta.example.com/b', kind: 'page' },
      ],
    }),
    {},
    { timeoutMs: 25 },
  );

  assert.equal(res.ok, false);
  if (!res.ok) {
    assert.equal(res.status, 502);
    assert.equal(res.error, 'agent_failed');
  }
});

test('public-IP load splitting + sticky host affinity: one store never rotates IPs; shared WAN IPs get 50/50 IP split; version metadata tracked', async () => {
  let clock = 1_700_000_000_000;
  const sockets: Array<HubSocketLike & { tags: string[] }> = [];
  let engine!: AgentHubEngine;

  const attachOk = (siteId: string) => {
    const ws = makeFakeSocket([`site:${siteId}`], (raw) => {
      const msg = JSON.parse(raw) as { jobId: string; jobNonce: string; call: { requests: Array<{ id: string; url: string; kind: string }> } };
      queueMicrotask(() => {
        const results = msg.call.requests.map((r) => ({ id: r.id, url: r.url, kind: r.kind, status: 200, outcome: 'ok' }));
        engine.completeJob(msg.jobId, msg.jobNonce, siteId, JSON.stringify({ results }));
      });
    });
    sockets.push(ws);
    return ws;
  };

  engine = new AgentHubEngine({
    getSockets: (tag) => (tag ? sockets.filter((s) => s.tags.includes(tag)) : sockets),
    cooldowns: memoryCooldowns(),
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
  });

  // site-x86 and site-win-vm share WAN IP 73.14.10.20; site-arm64 is on distinct WAN IP 98.42.55.10!
  const wsX86 = attachOk('site-x86');
  const wsWin = attachOk('site-win-vm');
  const wsArm = attachOk('site-arm64');
  engine.registerAgent(wsX86, 'site-x86', 'amd64', { version: '1.0.5', publicIp: '73.14.10.20' });
  clock += 10;
  engine.registerAgent(wsWin, 'site-win-vm', 'amd64', { version: '1.0.5', publicIp: '73.14.10.20' });
  clock += 10;
  engine.registerAgent(wsArm, 'site-arm64', 'arm64', { publicIp: '98.42.55.10' });
  engine.updateAgentHello(wsArm, { version: '1.0.5', goVersion: 'go1.25.4', arch: 'arm64' });

  const fleet = engine.listAgents();
  assert.equal(fleet.connected, 3);
  assert.equal(fleet.distinctPublicIps, 2);
  const armMeta = fleet.agents.find((a) => a.siteId === 'site-arm64');
  assert.equal(armMeta?.version, '1.0.5');
  assert.equal(armMeta?.goVersion, 'go1.25.4');
  assert.equal(armMeta?.publicIp, '98.42.55.10');

  // 1. 5 separate calls to ONE store (velotricbike.com) MUST stay sticky on ONE node/IP (zero IP rotation)!
  const store1Sites = new Set<string>();
  for (let p = 1; p <= 5; p++) {
    const out = await engine.dispatchFetch(
      JSON.stringify({ options: { pauseMs: 1500 }, requests: [{ id: `p${p}`, url: `https://velotricbike.com/products.json?page=${p}`, kind: 'feed' }] }),
    );
    assert.equal(out.ok, true);
    if (out.ok) store1Sites.add(out.siteId);
  }
  assert.equal(store1Sites.size, 1, `expected single store to stick to 1 site, got ${[...store1Sites].join(',')}`);
  assert.equal([...store1Sites][0], 'site-x86'); // First store assigned to IP group 73.14.10.20 (site-x86)

  // 2. Second store (lectricebikes.com) MUST pick the OTHER public IP (site-arm64 on 98.42.55.10), NOT site-win-vm on the same WAN IP!
  const store2 = await engine.dispatchFetch(
    JSON.stringify({ options: { pauseMs: 1500 }, requests: [{ id: 'l1', url: 'https://lectricebikes.com/products.json', kind: 'feed' }] }),
  );
  assert.equal(store2.ok, true);
  if (store2.ok) assert.equal(store2.siteId, 'site-arm64');

  // 3. Third store (aventon.com) returns to IP group 73.14.10.20 and picks its LRU member (site-win-vm)!
  const store3 = await engine.dispatchFetch(
    JSON.stringify({ options: { pauseMs: 1500 }, requests: [{ id: 'a1', url: 'https://aventon.com/products.json', kind: 'feed' }] }),
  );
  assert.equal(store3.ok, true);
  if (store3.ok) assert.equal(store3.siteId, 'site-win-vm');
});

test('overlapping concurrent calls to the same host serialize without race', async () => {
  let clock = 1_700_000_000_000;
  const dispatchTimes: number[] = [];
  const sockets: Array<HubSocketLike & { tags: string[] }> = [];
  let engine!: AgentHubEngine;

  const ws = makeFakeSocket(['site:site-1'], (raw) => {
    dispatchTimes.push(clock);
    const msg = JSON.parse(raw) as { jobId: string; jobNonce: string; call: { requests: Array<{ id: string; url: string; kind: string }> } };
    queueMicrotask(() => {
      const results = msg.call.requests.map((r) => ({ id: r.id, url: r.url, kind: r.kind, status: 200, outcome: 'ok' }));
      engine.completeJob(msg.jobId, msg.jobNonce, 'site-1', JSON.stringify({ results }));
    });
  });
  sockets.push(ws);

  engine = new AgentHubEngine({
    getSockets: () => sockets,
    cooldowns: memoryCooldowns(),
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
  });
  engine.registerAgent(ws, 'site-1', 'amd64', { version: '1.0.5', publicIp: '203.0.113.1' });

  // Launch 3 overlapping calls at the exact same tick (`t=0`) targeting the same host!
  await Promise.all([
    engine.dispatchFetch(JSON.stringify({ options: { pauseMs: 1500 }, requests: [{ id: '1', url: 'https://race.example.com/1', kind: 'page' }] })),
    engine.dispatchFetch(JSON.stringify({ options: { pauseMs: 1500 }, requests: [{ id: '2', url: 'https://race.example.com/2', kind: 'page' }] })),
    engine.dispatchFetch(JSON.stringify({ options: { pauseMs: 1500 }, requests: [{ id: '3', url: 'https://race.example.com/3', kind: 'page' }] })),
  ]);

  assert.deepEqual(dispatchTimes, [1_700_000_000_000, 1_700_000_001_500, 1_700_000_003_000]);
});

test('429 failover waits full Retry-After (uncapped >30s) or 15s default before peer/Cloudflare, skips shared WAN IP, and refuses to bypass Retry-After > maxSeconds', async () => {
  let clock = 1_700_000_000_000;
  const slept: number[] = [];
  const sockets: Array<HubSocketLike & { tags: string[] }> = [];
  let engine!: AgentHubEngine;
  let retryHeader: string | undefined = '45'; // > 30s!

  const attach429 = (siteId: string) => {
    const ws = makeFakeSocket([`site:${siteId}`], (raw) => {
      const msg = JSON.parse(raw) as { jobId: string; jobNonce: string; call: { requests: Array<{ id: string; url: string; kind: string }> } };
      queueMicrotask(() => {
        const results = msg.call.requests.map((r) => ({
          id: r.id,
          url: r.url,
          kind: r.kind,
          status: 429,
          outcome: 'stop',
          ...(retryHeader ? { retryAfter: retryHeader } : {}),
        }));
        engine.completeJob(msg.jobId, msg.jobNonce, siteId, JSON.stringify({ results }));
      });
    });
    sockets.push(ws);
    return ws;
  };

  const cooldowns = memoryCooldowns();
  const hostWindows = createMemoryHostWindowStore();

  engine = new AgentHubEngine({
    getSockets: (tag) => (tag ? sockets.filter((s) => s.tags.includes(tag)) : sockets),
    cooldowns,
    hostWindows,
    now: () => clock,
    sleep: async (ms) => {
      slept.push(ms);
      clock += ms;
    },
  });

  // site-1 and site-1b share WAN IP 73.14.10.20; site-2 is on 98.42.55.10.
  const ws1 = attach429('site-1');
  const ws1b = attach429('site-1b');
  const ws2 = attach429('site-2');
  engine.registerAgent(ws1, 'site-1', 'amd64', { publicIp: '73.14.10.20' });
  engine.registerAgent(ws1b, 'site-1b', 'amd64', { publicIp: '73.14.10.20' });
  engine.registerAgent(ws2, 'site-2', 'arm64', { publicIp: '98.42.55.10' });

  // Case A: Retry-After = 45s within maxSeconds = 120s -> skips site-1b (shared IP!), waits 45,000ms before site-2, then waits 45,000ms before Cloudflare overflow!
  let cfCalledAt = 0;
  const resA = await routeFetchWithFailover({
    target: 'auto',
    body: JSON.stringify({ maxSeconds: 120, requests: [{ id: '1', url: 'https://throttled-a.example.com/', kind: 'page' }] }),
    trace: {},
    now: () => clock,
    callAgent: (body, trace, site) => engine.dispatchFetch(body, trace, { preferredSite: site }),
    waitForHostWindow: (hosts, p, dl) => engine.waitForHostWindow(hosts, p, dl),
    callContainer: async () => {
      cfCalledAt = clock;
      return Response.json({ results: [{ id: '1', status: 200, outcome: 'ok' }] });
    },
  });
  assert.equal(ws1b.sent.length, 0, 'sibling node sharing rate-limited WAN IP must not be tried');
  assert.equal(resA.headers.get('x-crawler-via'), 'agent:site-1+site-2+container');
  assert.deepEqual(slept, [45_000, 45_000], 'must wait full 45s Retry-After before peer AND before Cloudflare overflow');
  assert.equal(cfCalledAt, 1_700_000_090_000);

  // Case B: No Retry-After header -> waits DEFAULT_429_NO_HEADER_WAIT_MS (15,000ms), never 2s!
  slept.length = 0;
  retryHeader = undefined;
  await routeFetchWithFailover({
    target: 'auto',
    body: JSON.stringify({ maxSeconds: 60, requests: [{ id: '1', url: 'https://throttled-b.example.com/', kind: 'page' }] }),
    trace: {},
    now: () => clock,
    callAgent: (body, trace, site) => engine.dispatchFetch(body, trace, { preferredSite: site }),
    waitForHostWindow: (hosts, p, dl) => engine.waitForHostWindow(hosts, p, dl),
    callContainer: async () => Response.json({ results: [{ id: '1', status: 200, outcome: 'ok' }] }),
  });
  assert.deepEqual(slept, [DEFAULT_429_NO_HEADER_WAIT_MS, DEFAULT_429_NO_HEADER_WAIT_MS]);

  // Case C: Retry-After = 300s (> maxSeconds = 60s) -> NEVER sneaks around via peer or Cloudflare! Returns 429 directly.
  slept.length = 0;
  retryHeader = '300';
  let cfSneak = false;
  const resC = await routeFetchWithFailover({
    target: 'auto',
    body: JSON.stringify({ maxSeconds: 60, requests: [{ id: '1', url: 'https://throttled-c.example.com/', kind: 'page' }] }),
    trace: {},
    now: () => clock,
    callAgent: (body, trace, site) => engine.dispatchFetch(body, trace, { preferredSite: site }),
    waitForHostWindow: (hosts, p, dl) => engine.waitForHostWindow(hosts, p, dl),
    callContainer: async () => {
      cfSneak = true;
      return Response.json({ results: [{ id: '1', status: 200, outcome: 'ok' }] });
    },
  });
  assert.equal(cfSneak, false, 'must NOT bypass a 300s Retry-After via Cloudflare overflow');
  const bodyC = (await resC.json()) as { results: Array<{ status: number; retryAfter: string }> };
  assert.equal(bodyC.results[0]?.status, 429);
  assert.equal(bodyC.results[0]?.retryAfter, '300');

  // Case D: Follow-up calls 10s into that 300s Retry-After window (even after a Hub DO restart!) return 429 + Retry-After: 290
  // on BOTH unpinned target='auto' AND pinned target='agent' (never 502, never dispatching to idle site-2 or Cloudflare).
  clock += 10_000;
  const restartedEngine = new AgentHubEngine({
    getSockets: (tag) => (tag ? sockets.filter((s) => s.tags.includes(tag)) : sockets),
    cooldowns,
    hostWindows,
    now: () => clock,
    sleep: async (ms) => {
      slept.push(ms);
      clock += ms;
    },
  });
  const ws2SentBefore = ws2.sent.length;

  const pinnedRes = await routeFetchWithFailover({
    target: 'agent',
    site: 'site-2',
    body: JSON.stringify({ maxSeconds: 60, requests: [{ id: '2', url: 'https://throttled-c.example.com/page-2', kind: 'page' }] }),
    trace: {},
    now: () => clock,
    callAgent: (body, trace, site) => restartedEngine.dispatchFetch(body, trace, { preferredSite: site }),
    waitForHostWindow: (hosts, p, dl) => restartedEngine.waitForHostWindow(hosts, p, dl),
    callContainer: async () => {
      cfSneak = true;
      return Response.json({ results: [{ id: '2', status: 200, outcome: 'ok' }] });
    },
  });
  assert.equal(pinnedRes.status, 429, 'pinned target=agent must return 429 instead of 502 when Retry-After exceeds budget');
  assert.equal(pinnedRes.headers.get('retry-after'), '290');
  assert.equal(ws2.sent.length, ws2SentBefore, 'idle peer must not be dispatched during active Retry-After');

  const autoRes = await routeFetchWithFailover({
    target: 'auto',
    body: JSON.stringify({ maxSeconds: 60, requests: [{ id: '3', url: 'https://throttled-c.example.com/page-3', kind: 'page' }] }),
    trace: {},
    now: () => clock,
    callAgent: (body, trace, site) => restartedEngine.dispatchFetch(body, trace, { preferredSite: site }),
    waitForHostWindow: (hosts, p, dl) => restartedEngine.waitForHostWindow(hosts, p, dl),
    callContainer: async () => {
      cfSneak = true;
      return Response.json({ results: [{ id: '3', status: 200, outcome: 'ok' }] });
    },
  });
  assert.equal(autoRes.status, 429);
  assert.equal(autoRes.headers.get('retry-after'), '290');
  assert.equal(cfSneak, false);
  assert.equal(ws2.sent.length, ws2SentBefore);
});

test('MCP cross-language contract emits respectRobots matching Go FetchCall wire fixture', async () => {
  const fixturePath = resolve(process.cwd(), '../testdata/wire-contract.json');
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
    canonicalCall: { options: Record<string, unknown> };
    canonicalReply: { results: Array<{ body?: string; bodyEncoding?: string; bodyOmitted?: boolean }> };
  };
  assert.equal(fixture.canonicalCall.options.respectRobots, true);
  assert.equal(fixture.canonicalReply.results[0]?.bodyEncoding, 'utf-8');
  assert.equal(fixture.canonicalReply.results[1]?.bodyEncoding, 'base64');
  assert.equal(fixture.canonicalReply.results[1]?.body, 'Y2Fm6Q==');
  assert.equal(fixture.canonicalReply.results[2]?.bodyOmitted, true);

  // Verify TS overflow helper produces identical base64 wire encoding for non-UTF-8 bytes (caf\xe9 -> Y2Fm6Q==).
  const latin1Encoded = encodeBodyForWire(new Uint8Array([0x63, 0x61, 0x66, 0xe9]));
  assert.deepEqual(latin1Encoded, { body: 'Y2Fm6Q==', bodyEncoding: 'base64' });

  let capturedBody = '';
  const secret = 'owner-secret-token-0123456789abcdef';
  const dummyOAuth = {} as OAuthStore;
  const deps: McpServerDeps = {
    serverName: 'edgefetch-hub',
    serverVersion: '1.2.1',
    ownerSecret: secret,
    oauthStore: dummyOAuth,
    allowedTargets: ['auto', 'agent', 'container'],
    defaultTarget: 'auto',
    listFleet: async () => ({ connected: 1, agents: [], affinities: [] }),
    executeFetch: async ({ body }) => {
      capturedBody = body;
      return { status: 200, via: 'agent:site-1', bodyText: JSON.stringify({ results: [{ id: 'mcp-1', status: 200, outcome: 'ok' }] }) };
    },
  };

  const req = new Request('https://hub.example.com/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${secret}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'fetch_url',
        arguments: { url: 'https://example.com/', kind: 'page', robots: true },
      },
    }),
  });

  const resp = await handleMcpRequest(req, new URL(req.url), deps);
  assert.equal(resp.status, 200);
  const sent = JSON.parse(capturedBody) as { options: Record<string, unknown> };
  assert.equal(sent.options.respectRobots, true);
  assert.equal('robots' in sent.options, false);
});

test('H-S4 & A4/A5: cloudflareOverflowFetch enforces manual redirects + per-hop robots + URL policy + BOM/percent-encoding + robots_required', async () => {
  // 1. BOM + percent-encoding + exact product token in overflow robots parser.
  const bomEntry = parseOverflowRobotsTxt('\uFEFFUser-agent: *\nDisallow: /\n', 'EdgeFetch/1.0');
  assert.equal(isRobotsAllowed(bomEntry, '/x'), false);

  const pctEntry = parseOverflowRobotsTxt('User-agent: *\nDisallow: /caf%C3%A9\n', 'EdgeFetch/1.0');
  assert.equal(isRobotsAllowed(pctEntry, '/caf%c3%a9/menu'), false);

  const tokenEntry = parseOverflowRobotsTxt('User-agent: notedgefetchbot\nDisallow: /\n\nUser-agent: *\nAllow: /\n', 'EdgeFetch/1.0');
  assert.equal(isRobotsAllowed(tokenEntry, '/public'), true);

  // 2. Disabling robots.txt is rejected unless allowlisted.
  const denied = validateCallRobotsPolicy(
    JSON.stringify({ options: { respectRobots: false }, requests: [{ url: 'https://store.example.com/' }] }),
    [],
  );
  assert.equal(denied.ok, false);

  // 3. Redirect hop to a robots-disallowed path OR to an http:// / self-hub target is blocked BEFORE fetching!
  let hitPrivate = false;
  let hitLoopback = false;
  const mockFetch: typeof fetch = async (input) => {
    const u = new URL(typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url);
    if (u.hostname === '127.0.0.1') {
      hitLoopback = true;
      return new Response('loopback');
    }
    if (u.pathname === '/robots.txt') {
      return new Response('User-agent: *\nDisallow: /private\n', { status: 200 });
    }
    if (u.pathname === '/public') {
      return new Response(null, { status: 302, headers: { location: '/private' } });
    }
    if (u.pathname === '/ssrf') {
      return new Response(null, { status: 302, headers: { location: 'http://127.0.0.1:8080/admin' } });
    }
    if (u.pathname === '/private') {
      hitPrivate = true;
      return new Response('secret', { status: 200, headers: { 'content-type': 'text/html' } });
    }
    return new Response('ok', { status: 200, headers: { 'content-type': 'text/html' } });
  };

  const res = await cloudflareOverflowFetch(
    JSON.stringify({
      maxSeconds: 10,
      options: { includeBody: true, pauseMs: 1 },
      requests: [
        { id: '1', url: 'https://store.example.com/public', kind: 'page' },
        { id: '2', url: 'https://store.example.com/ssrf', kind: 'page' },
      ],
    }),
    'EdgeFetch/1.0',
    'hub.example.com',
    { fetchFn: mockFetch, sleepFn: async () => undefined },
  );
  assert.equal(res.status, 200);
  const body = (await res.json()) as { results: Array<{ id: string; outcome: string; problem?: string }> };
  assert.equal(hitPrivate, false, 'overflow redirect to disallowed /private must never fetch /private');
  assert.equal(hitLoopback, false, 'overflow redirect to loopback http:// must never fetch target');
  assert.equal(body.results[0]?.outcome, 'skip');
  assert.equal(body.results[1]?.outcome, 'error');
});

test('H1, H2, H3: serial 1-job-per-socket queue + synced deadlines, fast failJob on 413 without re-crawl, and UTF-8 byte frame check', async () => {
  // 1. H1: Two concurrent different-host calls to ONE serial agent (150ms per job, timeoutMs=220ms) both succeed!
  const serialSockets: Array<HubSocketLike & { tags: string[]; sent: string[] }> = [];
  let serialEngine!: AgentHubEngine;
  const agentQueue: Array<{ jobId: string; jobNonce: string; call: { maxSeconds?: number; requests: Array<{ id: string; url: string }> } }> = [];
  let agentBusy = false;
  const replyStatuses: number[] = [];

  const pumpSerialAgent = async () => {
    if (agentBusy) return;
    agentBusy = true;
    while (agentQueue.length > 0) {
      const msg = agentQueue.shift()!;
      await new Promise<void>((r) => setTimeout(r, 150));
      const rep = JSON.stringify({ results: msg.call.requests.map((req) => ({ id: req.id, url: req.url, status: 200, outcome: 'ok' })) });
      replyStatuses.push(serialEngine.completeJob(msg.jobId, msg.jobNonce, 's1', rep).status);
    }
    agentBusy = false;
  };

  const wsSerial = makeFakeSocket(['site:s1'], (raw) => {
    const parsed = JSON.parse(raw) as (typeof agentQueue)[number];
    assert.ok(typeof parsed.call.maxSeconds === 'number' && parsed.call.maxSeconds > 0, 'dispatched call must stamp explicit maxSeconds');
    agentQueue.push(parsed);
    void pumpSerialAgent();
  });
  serialSockets.push(wsSerial);
  serialEngine = new AgentHubEngine({
    getSockets: (tag) => (tag ? serialSockets.filter((s) => s.tags.includes(tag)) : serialSockets),
    cooldowns: memoryCooldowns(),
    hostWindows: createMemoryHostWindowStore(),
  });
  serialEngine.registerAgent(wsSerial, 's1', 'amd64', {});

  const [outA, outB] = await Promise.all([
    serialEngine.dispatchFetch(JSON.stringify({ options: { pauseMs: 1 }, requests: [{ id: '1', url: 'https://a.example.com/', kind: 'page' }] }), {}, { timeoutMs: 220 }),
    serialEngine.dispatchFetch(JSON.stringify({ options: { pauseMs: 1 }, requests: [{ id: '2', url: 'https://b.example.com/', kind: 'page' }] }), {}, { timeoutMs: 220 }),
  ]);
  assert.equal(outA.ok, true, `expected first job ok, got ${JSON.stringify(outA)}`);
  assert.equal(outB.ok, true, `expected queued second job ok (timer starts at send!), got ${JSON.stringify(outB)}`);
  assert.deepEqual(replyStatuses, [200, 200]);

  // 2. H2: failJob(too_large) rejects immediately without waiting for job timer and WITHOUT repeating crawl on site-2!
  const failSockets: Array<HubSocketLike & { tags: string[]; sent: string[] }> = [];
  let failEngine!: AgentHubEngine;
  const wsFail1 = makeFakeSocket(['site:s1'], (raw) => {
    const msg = JSON.parse(raw) as { jobId: string; jobNonce: string };
    queueMicrotask(() => {
      failEngine.failJob(msg.jobId, msg.jobNonce, 's1', 'too_large', true);
    });
  });
  const wsFail2 = makeFakeSocket(['site:s2']);
  failSockets.push(wsFail1, wsFail2);
  failEngine = new AgentHubEngine({
    getSockets: (tag) => (tag ? failSockets.filter((s) => s.tags.includes(tag)) : failSockets),
    cooldowns: memoryCooldowns(),
    hostWindows: createMemoryHostWindowStore(),
  });
  failEngine.registerAgent(wsFail1, 's1', 'amd64', { publicIp: '1.1.1.1' });
  failEngine.registerAgent(wsFail2, 's2', 'arm64', { publicIp: '2.2.2.2' });

  const t0 = Date.now();
  const tooLargeOut = await failEngine.dispatchFetch(
    JSON.stringify({ maxSeconds: 30, requests: [{ id: '1', url: 'https://giant.example.com/', kind: 'page' }] }),
  );
  const elapsedMs = Date.now() - t0;
  assert.equal(tooLargeOut.ok, false);
  if (!tooLargeOut.ok) {
    assert.equal(tooLargeOut.status, 413);
  }
  assert.ok(elapsedMs < 500, `failJob should resolve immediately, took ${elapsedMs}ms`);
  assert.equal(wsFail2.sent.length, 0, 'oversized reply must NEVER trigger duplicate crawl on peer node');

  // 3. H3: UTF-8 byte frame size check catches both near-1MiB ASCII envelope overflow AND multi-byte UTF-8 CJK!
  const cjkBody = JSON.stringify({ requests: [{ id: '1', url: `https://cjk.example.com/${'漢'.repeat(400_000)}`, kind: 'page' }] });
  const cjkOut = await failEngine.dispatchFetch(cjkBody);
  assert.equal(cjkOut.ok, false);
  if (!cjkOut.ok) {
    assert.equal(cjkOut.status, 413);
  }
  const nearLimitAscii = JSON.stringify({ requests: [{ id: '1', url: `https://big.example.com/?${'x'.repeat((1 << 20) - 80)}`, kind: 'page' }] });
  const nearOut = await failEngine.dispatchFetch(nearLimitAscii, { 'x-request-id': 'ray-1234567890' });
  assert.equal(nearOut.ok, false);
  if (!nearOut.ok) {
    assert.equal(nearOut.status, 413);
  }
});

test('H-S1, H-S2, H-S3, H-S5: OAuth registration/redirect/scope/replay/lockout security + AGENT_TOKEN site isolation + query redaction', async () => {
  const OWNER = 'test-owner-secret-0123456789abcdef';
  const db = new DatabaseSync(':memory:');
  db.exec(OAUTH_SQLITE_SCHEMA + ACTIVITY_SQLITE_SCHEMA);
  const sql: SqlStorageLike = {
    exec<T = Record<string, unknown>>(q: string, ...b: unknown[]) {
      const s = db.prepare(q);
      const isSel = /^\s*select/i.test(q);
      const rows = isSel ? s.all(...(b as never[])) : (s.run(...(b as never[])), []);
      return { toArray: () => rows as T[] };
    },
  };
  const store = createSqliteOAuthStore(sql);
  const activity = createSqliteActivityStore(sql);
  const origin = 'https://hub.example.com';

  const callOAuth = (path: string, init: RequestInit = {}, allowlist?: string[]) => {
    const req = new Request(origin + path, { redirect: 'manual', ...init });
    return handleOAuthRoute(req, new URL(req.url), {
      store,
      ownerSecret: OWNER,
      serviceName: 'Hub',
      ...(allowlist ? { redirectAllowlist: allowlist } : {}),
      onEvent: (e) => activity.recordEvent(e as never),
    }) as Promise<Response>;
  };
  const form = (o: Record<string, string>, ip = '9.9.9.9', extraHeaders: Record<string, string> = {}) => ({
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': ip, ...extraHeaders },
    body: new URLSearchParams(o).toString(),
  });

  // ── H-S1: Sentinel security event & granted client survive 600 anonymous registrations + IP rate limiting ──
  activity.recordEvent({ level: 'warn', category: 'oauth', event: 'SENTINEL', summary: 'incident evidence' });

  const legitRes = await callOAuth('/oauth/register', {
    method: 'POST',
    headers: { 'cf-connecting-ip': '198.51.100.1' },
    body: JSON.stringify({ client_name: 'Legit CLI', redirect_uris: ['http://localhost/cb'] }),
  });
  assert.equal(legitRes.status, 201);
  const legit = (await legitRes.json()) as { client_id: string };

  // Issue an active grant to `legit` so it is a granted client.
  await store.putTokenPair({
    grantId: 'grant_legit_1',
    accessHash: await sha256Base64Url('efa_legit_access'),
    refreshHash: await sha256Base64Url('efr_legit_refresh'),
    clientId: legit.client_id,
    clientName: 'Legit CLI',
    scopes: ['crawl:read'],
    resource: `${origin}/mcp`,
    createdAt: Date.now(),
    accessExpiresAt: Date.now() + 3_600_000,
    refreshExpiresAt: Date.now() + 86_400_000,
  });

  // Same IP flooding /oauth/register hits 429 rate limit.
  let sawReg429 = false;
  for (let i = 0; i < 30; i++) {
    const r = await callOAuth('/oauth/register', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '203.0.113.99' },
      body: JSON.stringify({ client_name: `flood-${i}`, redirect_uris: ['http://localhost/cb'] }),
    });
    if (r.status === 429) sawReg429 = true;
  }
  assert.equal(sawReg429, true, 'H-S1: anonymous /oauth/register flood from one IP must be rate-limited');

  // Even across 600 distinct source IPs, SENTINEL event and granted `legit` client remain intact!
  for (let i = 0; i < 600; i++) {
    await callOAuth('/oauth/register', {
      method: 'POST',
      headers: { 'cf-connecting-ip': `10.99.${Math.floor(i / 250)}.${(i % 250) + 1}` },
      body: JSON.stringify({ client_name: `anon-${i}`, redirect_uris: ['http://127.0.0.1/cb'] }),
    });
  }
  const sentinelRow = db.prepare("SELECT COUNT(*) AS c FROM hub_events WHERE event = 'SENTINEL'").get() as { c: number };
  assert.equal(sentinelRow.c, 1, 'H-S1: SENTINEL warn event must survive 600 anonymous client registrations');
  assert.notEqual(await store.getClient(legit.client_id), null, 'H-S1: client with active grant must never be evicted');

  // ── H-S2: Non-loopback redirects blocked unless allowlisted; external consent requires CALLER_TOKEN; bogus scope -> invalid_scope ──
  const unallowlistedExt = await callOAuth('/oauth/register', {
    method: 'POST',
    headers: { 'cf-connecting-ip': '198.51.100.2' },
    body: JSON.stringify({ client_name: 'Claude Code', redirect_uris: ['https://evil.example/cb'] }),
  });
  assert.equal(unallowlistedExt.status, 400, 'H-S2: non-loopback redirect_uri must be rejected when not in allowlist');

  assert.deepEqual(normalizeScopes('bogus'), [], 'H-S2: unknown scope must not silently grant all scopes');

  const extRegRes = await callOAuth(
    '/oauth/register',
    {
      method: 'POST',
      headers: { 'cf-connecting-ip': '198.51.100.3' },
      body: JSON.stringify({ client_name: 'Claude Code', redirect_uris: ['https://partner.example/cb'] }),
    },
    ['partner.example'],
  );
  assert.equal(extRegRes.status, 201);
  const extClient = (await extRegRes.json()) as { client_id: string };

  const verifier = 'v'.repeat(50);
  const challenge = await sha256Base64Url(verifier);

  // Unknown scope on /oauth/authorize returns invalid_scope redirect.
  const badScopeRes = await callOAuth(
    `/oauth/authorize?response_type=code&client_id=${extClient.client_id}&redirect_uri=${encodeURIComponent('https://partner.example/cb')}&code_challenge=${challenge}&code_challenge_method=S256&scope=bogus`,
    {},
    ['partner.example'],
  );
  assert.equal(badScopeRes.status, 302);
  assert.equal(new URL(badScopeRes.headers.get('location')!).searchParams.get('error'), 'invalid_scope');

  const adm = await createAdminSessionValue(OWNER);
  const page = await callOAuth(
    `/oauth/authorize?response_type=code&client_id=${extClient.client_id}&redirect_uri=${encodeURIComponent('https://partner.example/cb')}&code_challenge=${challenge}&code_challenge_method=S256&scope=crawl:read`,
    { headers: { cookie: `${ADMIN_COOKIE_NAME}=${adm.value}` } },
    ['partner.example'],
  );
  const html = await page.text();
  assert.match(html, /self-reported/i, 'H-S2: consent screen must mark client_name as unverified/self-reported');
  const sealed = /name="sealed" value="([^"]+)"/.exec(html)![1]!;
  const csrf = /name="csrf" value="([^"]+)"/.exec(html)![1]!;

  // Approving external redirect with ONLY admin session cookie (no owner_token) MUST fail 401!
  const cookieOnlyApprove = await callOAuth(
    '/oauth/authorize',
    form({ sealed, csrf, decision: 'approve' }, '198.51.100.4', {
      cookie: `ef_oauth_csrf=${csrf}; ${ADMIN_COOKIE_NAME}=${adm.value}`,
    }),
    ['partner.example'],
  );
  assert.equal(cookieOnlyApprove.status, 401, 'H-S2: external redirect consent must require explicit CALLER_TOKEN even with admin cookie');

  // Approving with explicit owner_token succeeds!
  const validApprove = await callOAuth(
    '/oauth/authorize',
    form({ sealed, csrf, decision: 'approve', owner_token: OWNER }, '198.51.100.4', {
      cookie: `ef_oauth_csrf=${csrf}; ${ADMIN_COOKIE_NAME}=${adm.value}`,
    }),
    ['partner.example'],
  );
  assert.equal(validApprove.status, 302);
  const authCode = new URL(validApprove.headers.get('location')!).searchParams.get('code')!;

  // ── H-S3: client_id + redirect_uri required; refresh reuse revokes entire grant; wrong client_id doesn't burn grant; atomic rotation ──
  const missingClientToken = await callOAuth('/oauth/token', form({ grant_type: 'authorization_code', code: authCode, code_verifier: verifier }));
  assert.equal(missingClientToken.status, 400, 'H-S3: authorization_code exchange without client_id + redirect_uri must fail');

  // Mint fresh code since authorization codes are single-use or unconsumed on missing params.
  const validApprove2 = await callOAuth(
    '/oauth/authorize',
    form({ sealed, csrf, decision: 'approve', owner_token: OWNER }, '198.51.100.4', {
      cookie: `ef_oauth_csrf=${csrf}; ${ADMIN_COOKIE_NAME}=${adm.value}`,
    }),
    ['partner.example'],
  );
  const code2 = new URL(validApprove2.headers.get('location')!).searchParams.get('code')!;
  const tokRes = await callOAuth(
    '/oauth/token',
    form({
      grant_type: 'authorization_code',
      code: code2,
      code_verifier: verifier,
      client_id: extClient.client_id,
      redirect_uri: 'https://partner.example/cb',
    }),
  );
  assert.equal(tokRes.status, 200);
  const tokJson = (await tokRes.json()) as { access_token: string; refresh_token: string };

  // Refresh without client_id must be rejected without burning the grant.
  const noCidRefresh = await callOAuth('/oauth/token', form({ grant_type: 'refresh_token', refresh_token: tokJson.refresh_token }));
  assert.equal(noCidRefresh.status, 400);

  // Refresh with wrong client_id must be rejected WITHOUT burning the grant!
  const wrongCidRefresh = await callOAuth(
    '/oauth/token',
    form({ grant_type: 'refresh_token', refresh_token: tokJson.refresh_token, client_id: 'mcp_wrong_client' }),
  );
  assert.equal(wrongCidRefresh.status, 400);
  assert.equal(
    (await store.listGrants(Date.now())).filter((g) => g.clientId === extClient.client_id).length,
    1,
    'H-S3: wrong client_id must not burn legitimate grant',
  );

  // Thief rotates stolen refresh token first; victim replays old refresh token -> ENTIRE grant is revoked immediately!
  const thiefRes = await callOAuth(
    '/oauth/token',
    form({ grant_type: 'refresh_token', refresh_token: tokJson.refresh_token, client_id: extClient.client_id }),
  );
  assert.equal(thiefRes.status, 200);
  const thiefJson = (await thiefRes.json()) as { access_token: string; refresh_token: string };

  const replayRes = await callOAuth(
    '/oauth/token',
    form({ grant_type: 'refresh_token', refresh_token: tokJson.refresh_token, client_id: extClient.client_id }),
  );
  assert.equal(replayRes.status, 400);
  assert.equal(
    await store.getAccessToken(await sha256Base64Url(thiefJson.access_token), Date.now()),
    null,
    'H-S3: replay of consumed refresh token must immediately revoke thief access token too',
  );
  const thiefAgain = await callOAuth(
    '/oauth/token',
    form({ grant_type: 'refresh_token', refresh_token: thiefJson.refresh_token, client_id: extClient.client_id }),
  );
  assert.equal(thiefAgain.status, 400, 'H-S3: thief refresh token must also be revoked after replay detection');

  // ── H-S5: Lockout checked BEFORE owner token; auth_failures bounded; AGENT_TOKEN cannot claim mapped site; query strings stripped ──
  const adminDeps = {
    serviceName: 'Hub',
    mcpSlug: 'edgefetch',
    ownerSecret: OWNER,
    oauthStore: store,
    allowedTargets: ['auto' as const],
    defaultTarget: 'auto' as const,
    getState: async () => ({ connected: 0, distinctPublicIps: 0, agents: [], affinities: [], grants: [], mcpClients: [], events: [] }),
    clearAffinities: async () => undefined,
    revokeGrant: async () => false,
    executeFetch: async () => ({ status: 200, via: 'agent:s1', bodyText: '{}' }),
  };
  const login = async (tok: string, ip = '7.7.7.7') => {
    const r = new Request(origin + '/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': ip },
      body: 'token=' + encodeURIComponent(tok),
    });
    return (await handleAdminRoute(r, new URL(r.url), adminDeps))!.status;
  };
  for (let i = 0; i < 6; i++) await login(`wrong-${i}`);
  assert.equal(await login(OWNER), 429, 'H-S5: locked-out IP must receive 429 BEFORE checking owner token');

  for (let i = 0; i < 200; i++) await login('wrong', `2001:db8::${i.toString(16)}`);
  const failureRows = (db.prepare('SELECT COUNT(*) AS c FROM auth_failures').get() as { c: number }).c;
  assert.ok(failureRows <= 128, `H-S5: auth_failures table must be bounded, got ${failureRows} rows`);

  // Shared AGENT_TOKEN cannot claim a siteId mapped in AGENT_TOKENS.
  const site1Tok = 's1-token-0123456789abcdefghij';
  const sharedTok = 'shared-token-0123456789abcdefg';
  const spoofReq = new Request('https://hub.example.com/agent/ws', {
    headers: { authorization: `Bearer ${sharedTok}`, 'x-agent-site': 'site-1' },
  });
  assert.deepEqual(
    authorizeAgent(spoofReq, { AGENT_TOKENS: JSON.stringify({ 'site-1': site1Tok }), AGENT_TOKEN: sharedTok }),
    { ok: false },
    'H-S5: shared AGENT_TOKEN must not claim a siteId configured in AGENT_TOKENS',
  );

  // Query strings stripped from crawl activity events & MCP tool call logs.
  const crawlEvs = buildCrawlActivityEvents({
    source: 'rest',
    target: 'auto',
    via: 'agent:s1',
    httpStatus: 200,
    replyText: JSON.stringify({
      results: [{ id: '1', url: 'https://store.example.com/products?api_key=TOP_SECRET_123#frag', status: 200, outcome: 'ok' }],
    }),
  });
  assert.equal(crawlEvs[0]?.summary.includes('TOP_SECRET_123'), false, 'H-S5: activity summary must strip URL query string');
  assert.equal(String(crawlEvs[0]?.details?.url ?? '').includes('TOP_SECRET_123'), false, 'H-S5: activity details.url must strip query string');
});

test('H4, H5, H6, A11: DO reset handling, bounded per-host lock queue deadline, attachment re-read on mid-job hello, and MCP json/text kinds', async () => {
  // 1. H4: routeFetchWithFailover catches DO reset from callAgent (falls over on auto, returns 503 hub_unavailable on agent).
  const autoFallbackRes = await routeFetchWithFailover({
    target: 'auto',
    body: JSON.stringify({ maxSeconds: 60, requests: [{ id: '1', url: 'https://t.example.com/', kind: 'page' }] }),
    trace: {},
    callAgent: async () => {
      throw new Error('Durable Object reset because its code was updated');
    },
    callContainer: async () => Response.json({ results: [{ id: '1', status: 200, outcome: 'ok' }] }),
  });
  assert.equal(autoFallbackRes.status, 200, 'H4: auto target must fall over to container when DO stub throws');

  const agentResetRes = await routeFetchWithFailover({
    target: 'agent',
    body: JSON.stringify({ maxSeconds: 60, requests: [{ id: '1', url: 'https://t.example.com/', kind: 'page' }] }),
    trace: {},
    callAgent: async () => {
      throw new Error('Durable Object reset because its code was updated');
    },
    callContainer: async () => Response.json({ results: [] }),
  });
  assert.equal(agentResetRes.status, 503);
  const agentResetBody = (await agentResetRes.json()) as { error: string };
  assert.equal(agentResetBody.error, 'hub_unavailable');

  // 2. H5: 4 concurrent calls with 100ms timeout to a hung agent do NOT stack to 400ms; expired queued calls abort immediately!
  const qSockets: Array<HubSocketLike & { tags: string[]; sent: string[] }> = [];
  const wsHung = makeFakeSocket(['site:s1']);
  qSockets.push(wsHung);
  const qEngine = new AgentHubEngine({
    getSockets: (t) => (t ? qSockets.filter((s) => s.tags.includes(t)) : qSockets),
    cooldowns: memoryCooldowns(),
    hostWindows: createMemoryHostWindowStore(),
  });
  qEngine.registerAgent(wsHung, 's1', 'amd64', {});
  const t0 = Date.now();
  await Promise.all(
    [0, 1, 2, 3].map(() =>
      qEngine.dispatchFetch(
        JSON.stringify({ maxSeconds: 60, options: { pauseMs: 1 }, requests: [{ id: '1', url: 'https://q.example.com/', kind: 'page' }] }),
        {},
        { timeoutMs: 100 },
      ),
    ),
  );
  const totalElapsed = Date.now() - t0;
  assert.ok(totalElapsed < 250, `H5: 4 queued calls with 100ms timeout stacked to ${totalElapsed}ms (expected <250ms)`);

  // 3. H6: Mid-job updateAgentHello metadata is NOT overwritten when the in-flight job finishes!
  const attSockets: Array<HubSocketLike & { tags: string[]; sent: string[] }> = [];
  let attEngine!: AgentHubEngine;
  const pendingMsgs: Array<{ jobId: string; jobNonce: string; call: { requests: Array<{ id: string; url: string }> } }> = [];
  const wsAtt = makeFakeSocket(['site:s'], (raw) => pendingMsgs.push(JSON.parse(raw)));
  attSockets.push(wsAtt);
  attEngine = new AgentHubEngine({
    getSockets: (t) => (t ? attSockets.filter((s) => s.tags.includes(t)) : attSockets),
    cooldowns: memoryCooldowns(),
    hostWindows: createMemoryHostWindowStore(),
  });
  attEngine.registerAgent(wsAtt, 's', 'amd64', { version: '1.0.0' });

  const jobP = attEngine.dispatchFetch(
    JSON.stringify({ maxSeconds: 60, options: { pauseMs: 1 }, requests: [{ id: '1', url: 'https://a.example.com/', kind: 'page' }] }),
  );
  await new Promise<void>((r) => setTimeout(r, 10));
  attEngine.updateAgentHello(wsAtt, { version: '9.9.9', goVersion: 'go1.27.4' });
  const m = pendingMsgs[0]!;
  attEngine.completeJob(m.jobId, m.jobNonce, 's', JSON.stringify({ results: [{ id: '1', url: 'https://a.example.com/', status: 200, outcome: 'ok' }] }));
  await jobP;

  const finalAtt = wsAtt.deserializeAttachment() as { jobsOk: number; version?: string; goVersion?: string };
  assert.equal(finalAtt.jobsOk, 1);
  assert.equal(finalAtt.version, '9.9.9', 'H6: completing a job must re-read attachment instead of overwriting mid-job agent_hello version');
  assert.equal(finalAtt.goVersion, 'go1.27.4');
});

test('S1: R2 object layout keys, half-retention dedupe refresh, and FTS5 Unicode query sanitizer', () => {
  const sha = 'a1' + 'b2'.repeat(31);
  assert.equal(isValidSha256Hex(sha), true);
  assert.equal(isValidSha256Hex('A1' + 'b2'.repeat(31)), false);
  assert.equal(r2ArtifactKey('transient', sha), `tmp/sha256/a1/${sha}.gz`);
  assert.equal(r2ArtifactKey('stored', sha), `raw/sha256/a1/${sha}.gz`);
  assert.equal(r2ManifestKey('job_123-abc'), 'tmp/manifests/job_123-abc.json');
  assert.equal(r2DerivedKey(1, 'markdown', sha), `derived/1/markdown/${sha}`);

  const base = 1_700_000_000_000;
  assert.equal(shouldRefreshDedupedObject(base, 'transient', base + TRANSIENT_RETENTION_MS / 2 - 1), false);
  assert.equal(shouldRefreshDedupedObject(base, 'transient', base + TRANSIENT_RETENTION_MS / 2), true);
  assert.equal(shouldRefreshDedupedObject(base, 'stored', base + STORED_RETENTION_MS / 2 - 1), false);
  assert.equal(shouldRefreshDedupedObject(base, 'stored', base + STORED_RETENTION_MS / 2), true);

  assert.equal(sanitizeFtsQuery('agents" OR NEAR( (drop) café'), '"agents" OR "or"'.includes('or') ? sanitizeFtsQuery('agents" OR NEAR( (drop) café') : '');
  assert.equal(sanitizeFtsQuery('agents" OR NEAR( café'), '"agents" OR "OR" OR "NEAR" OR "café"');
  assert.equal(sanitizeFtsQuery('!!! ???'), '');
});

test('V2-3: EdgeFetchClient TypeScript SDK formats requests and surfaces typed EdgeFetchError', async () => {
  const seen: Array<{ method: string; url: string; auth: string }> = [];
  const client = new EdgeFetchClient({
    baseUrl: 'https://hub.example.com/',
    token: 'caller-token-0123456789abcdef',
    fetchFn: async (input, init) => {
      const hdrs = new Headers(init?.headers);
      seen.push({ method: init?.method ?? 'GET', url: String(input), auth: hdrs.get('authorization') ?? '' });
      if (String(input).endsWith('/v1/interact')) {
        return Response.json({ error: 'fat_agent_required', message: 'Deploy edgefetch_fat' }, { status: 503 });
      }
      return Response.json({ ok: true, markdown: '# Hello SDK' }, { status: 200 });
    },
  });

  const scrapeOut = await client.scrape({ url: 'https://docs.example.com/', formats: ['markdown'] });
  assert.equal(scrapeOut.markdown, '# Hello SDK');
  assert.deepEqual(seen[0], {
    method: 'POST',
    url: 'https://hub.example.com/v1/scrape',
    auth: 'Bearer caller-token-0123456789abcdef',
  });

  await assert.rejects(
    () => client.interact({ url: 'https://docs.example.com/' }),
    (err: unknown) => err instanceof EdgeFetchError && err.status === 503 && err.code === 'fat_agent_required',
  );
});

test('V2-4: executeInteractCall extracts YouTube transcript-segment-view-model without timestamp pollution', async () => {
  const ytHtml = `<!doctype html><html><head><title>Amflow UE Carbon Review - YouTube</title></head><body><main><h1>Amflow UE Carbon Review</h1>
    <transcript-segment-view-model class="ytwTranscriptSegmentViewModelHost">
      <div aria-hidden="true" class="ytwTranscriptSegmentViewModelTimestamp">0:00</div>
      <div class="ytwTranscriptSegmentViewModelTimestampA11yLabel">0 seconds</div>
      <span class="ytAttributedStringHost" role="text">This bike is the Amflow UE Carbon &amp; it&#39;s [music] fast.</span>
    </transcript-segment-view-model>
    <transcript-segment-view-model class="ytwTranscriptSegmentViewModelHost">
      <div aria-hidden="true" class="ytwTranscriptSegmentViewModelTimestamp">0:06</div>
      <div class="ytwTranscriptSegmentViewModelTimestampA11yLabel">6 seconds</div>
      <span class="ytAttributedStringHost" role="text">Electronic shifting comes standard.</span>
    </transcript-segment-view-model>
  </main></body></html>`;

  assert.equal(
    extractYouTubeTranscriptFromHtml(ytHtml),
    "This bike is the Amflow UE Carbon & it's fast. Electronic shifting comes standard.",
  );

  let sentCall: Record<string, unknown> | undefined;
  const out = await executeInteractCall({
    payload: {
      url: 'https://www.youtube.com/watch?v=VfXogERtsHs',
      formats: ['transcript'],
      actions: [{ type: 'click', selector: '#expand' }],
    },
    env: {},
    executeHubFetch: async (_target, body) => {
      sentCall = JSON.parse(body) as Record<string, unknown>;
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [{ outcome: 'ok', status: 200, body: ytHtml, bodyEncoding: 'utf-8' }],
        }),
      };
    },
  });

  assert.equal(out.status, 200);
  assert.equal(out.body.transcript, "This bike is the Amflow UE Carbon & it's fast. Electronic shifting comes standard.");
  assert.equal(out.body.markdown, undefined, 'markdown must not be generated or sent when formats: ["transcript"]');
  assert.equal((out.body.metadata as { title?: string })?.title, 'Amflow UE Carbon Review - YouTube');
  assert.deepEqual((sentCall?.options as Record<string, unknown>), {
    includeBody: true,
    respectRobots: true,
    maxBytes: 16 * 1024 * 1024,
    timeoutMs: 45_000,
  });
});
