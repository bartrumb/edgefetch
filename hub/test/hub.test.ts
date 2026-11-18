import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import { AgentHubEngine, extractPrimaryHost, routeFetchWithFailover, type CooldownStore, type HubSocketLike } from '../src/agent-hub.ts';
import { handleMcpRequest, type McpServerDeps } from '../src/mcp.ts';
import type { OAuthStore } from '../src/oauth.ts';

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
  engine.registerAgent(s1, 'site-1', 'amd64');
  engine.registerAgent(s2, 'site-2', 'arm64');

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

test('per-host pacing: 6 URLs on ONE host stay on 1 node; 6 distinct hosts shard 2/2/2; sequential same-host calls sleep pauseMs', async () => {
  let clock = 1_700_000_000_000;
  const slept: number[] = [];
  const sockets: Array<HubSocketLike & { tags: string[] }> = [];
  let engine!: AgentHubEngine;

  const attachAutoReply = (siteId: string, statusForHost?: (url: string) => number) => {
    const ws = makeFakeSocket([`site:${siteId}`], (raw) => {
      const msg = JSON.parse(raw) as { jobId: string; jobNonce: string; call: { requests: Array<{ id: string; url: string; kind: string }> } };
      queueMicrotask(() => {
        const results = msg.call.requests.map((r) => {
          const st = statusForHost ? statusForHost(r.url) : 200;
          return { id: r.id, url: r.url, kind: r.kind, status: st, outcome: st === 200 ? 'ok' : 'stop' };
        });
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
      slept.push(ms);
      clock += ms;
    },
  });

  const ws1 = attachAutoReply('site-1');
  const ws2 = attachAutoReply('site-2');
  const ws3 = attachAutoReply('site-3');
  engine.registerAgent(ws1, 'site-1', 'amd64');
  engine.registerAgent(ws2, 'site-2', 'arm64');
  engine.registerAgent(ws3, 'site-3', 'amd64');

  // 1. 6 URLs on ONE host -> ALL 6 must go to a SINGLE node so Go's per-host lock spaces them cleanly!
  const sameHostReqs = Array.from({ length: 6 }, (_, i) => ({
    id: `s-${i}`,
    url: `https://single-origin.example.com/p/${i}`,
    kind: 'page',
  }));
  const rSame = await engine.dispatchFetch(JSON.stringify({ options: { pauseMs: 1500 }, requests: sameHostReqs }));
  assert.equal(rSame.ok, true);
  if (rSame.ok) {
    assert.equal(rSame.siteId.includes('+'), false, `expected 1 site for single host, got ${rSame.siteId}`);
  }

  // 2. Immediate second call to the SAME host -> Hub enforces remaining 1500ms pauseMs before dispatching to next LRU site!
  const rFollow = await engine.dispatchFetch(
    JSON.stringify({
      options: { pauseMs: 1500 },
      requests: [{ id: 's-next', url: 'https://single-origin.example.com/p/99', kind: 'page' }],
    }),
  );
  assert.equal(rFollow.ok, true);
  assert.deepEqual(slept, [1500]);

  // 3. 6 URLs on 6 DISTINCT hosts -> shards evenly 2 / 2 / 2 across all 3 nodes!
  ws1.sent.length = 0;
  ws2.sent.length = 0;
  ws3.sent.length = 0;
  const multiHostReqs = Array.from({ length: 6 }, (_, i) => ({
    id: `m-${i}`,
    url: `https://host-${i}.example.com/feed.json`,
    kind: 'feed',
  }));
  const rMulti = await engine.dispatchFetch(JSON.stringify({ options: { pauseMs: 1500 }, requests: multiHostReqs }));
  assert.equal(rMulti.ok, true);
  assert.equal(ws1.sent.length, 1);
  assert.equal(ws2.sent.length, 1);
  assert.equal(ws3.sent.length, 1);
});

test('429 fallback feature preserved: remote 429 cools down site and overflows to Cloudflare after peers 429', async () => {
  const clock = 1_700_000_000_000;
  const sockets: Array<HubSocketLike & { tags: string[] }> = [];
  let engine!: AgentHubEngine;

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
          retryAfter: '60',
        }));
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
  });
  engine.registerAgent(attach429('site-1'), 'site-1', 'amd64');
  engine.registerAgent(attach429('site-2'), 'site-2', 'arm64');

  let cloudflareCalled = false;
  const res = await routeFetchWithFailover({
    target: 'auto',
    body: JSON.stringify({ requests: [{ id: '1', url: 'https://throttled.example.com/', kind: 'page' }] }),
    trace: {},
    callAgent: (body, trace, site) => engine.dispatchFetch(body, trace, { preferredSite: site }),
    callContainer: async () => {
      cloudflareCalled = true;
      return Response.json({ results: [{ id: '1', status: 200, outcome: 'ok' }] });
    },
  });

  assert.equal(cloudflareCalled, true);
  assert.equal(res.headers.get('x-crawler-via'), 'agent:site-1+site-2+container');
  assert.equal(engine.listAffinities().length, 2);
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
    serverVersion: '1.1.2',
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
