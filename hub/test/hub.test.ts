import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  AgentHubEngine,
  DEFAULT_429_NO_HEADER_WAIT_MS,
  createMemoryHostWindowStore,
  extractPrimaryHost,
  routeFetchWithFailover,
  type CooldownStore,
  type HubSocketLike,
} from '../src/agent-hub.ts';
import { handleMcpRequest, type McpServerDeps } from '../src/mcp.ts';
import type { OAuthStore } from '../src/oauth.ts';
import {
  cloudflareOverflowFetch,
  isRobotsAllowed,
  parseOverflowRobotsTxt,
  validateCallRobotsPolicy,
} from '../src/overflow.ts';

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
  };
  assert.equal(fixture.canonicalCall.options.respectRobots, true);

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
