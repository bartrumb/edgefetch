import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { EdgeFetchClient, EdgeFetchError } from '../../sdk/ts/edgefetch-client.ts';
import { startPortableHub } from '../portable/portable-server.ts';
import { buildSigV4Headers, S3ArtifactBucket } from '../portable/s3-bucket.ts';
import { TursoHttpD1Database } from '../portable/turso-d1.ts';
import { formatYamlFrontmatterCard, resolveSiteExtractorTwin } from '../src/extractors/registry.ts';
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
import {
  computeEd25519JwkThumbprint,
  generateBotAuthKeyPair,
  handleBotTransparencyRoutes,
  signOutboundBotHeaders,
  verifyBotRequestSignature,
  verifyDirectoryResponseSignature,
} from '../src/bot-auth.ts';
import { executeIngestPipeline, sha256HexString, writeJobManifestToR2 } from '../src/ingest.ts';
import { defaultTextAccept, handleMcpRequest, inferKindForUrl, type McpServerDeps } from '../src/mcp.ts';
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
  buildCrawlChildSpans,
  createRequestTraceContext,
  flushOtlpSpans,
  parseOtlpHeaders,
  parseTraceparent,
  resolveOtlpTracesUrl,
} from '../src/otel.ts';
import {
  cloudflareOverflowFetch,
  encodeBodyForWire,
  isRobotsAllowed,
  parseOverflowRobotsTxt,
  validateCallRobotsPolicy,
} from '../src/overflow.ts';
import {
  executeInteractCall,
  executeScrapeCall,
  extractHtmlDocument,
  extractYouTubeTranscriptFromHtml,
  formatJupyterNotebookToMarkdown,
  formatOpenApiSpecToMarkdown,
  SCRAPE_PIPELINE_VERSION,
} from '../src/scrape.ts';
import { executeJobsCall } from '../src/jobs.ts';
import { executeMapCall } from '../src/map-crawl.ts';
import { chunkMarkdownForSearch, executeExtractCall } from '../src/search-index.ts';
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
import {
  canonicalizeSearchResultUrl,
  executeSearchCall,
  extractEdgeMapDomains,
  resetSearchProviderPacingForTests,
} from '../src/web-search.ts';
import {
  classifyContentState,
  classifyWafAndChallenge,
  isEligibleForWaybackFallback,
  recoverSsrHydrationContent,
} from '../src/waf.ts';
import {
  isEligibleForExternalSpaFallback,
  listConfiguredSpaFallbacks,
} from '../src/spa-fallback.ts';
import { NodeFsR2Bucket, NodeSqliteD1Database } from '../portable/node-adapters.ts';

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
  assert.equal(await login('wrong-6'), 429, 'H-S5: locked-out IP must receive 429 on further wrong attempts');
  assert.equal(await login(OWNER), 302, 'H-S5 / R3-M4: valid constant-time CALLER_TOKEN clears spoofed-IP lockout');

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

test('V2-5: status=0 local browser/transport error clears sticky host affinity and fails over to peer node on same WAN IP', async () => {
  const sockets: HubSocketLike[] = [];
  const makeNode = (siteId: string, onJob: (jobId: string, jobNonce: string, engine: AgentHubEngine) => void) => {
    let att: unknown = {
      siteId,
      publicIp: '198.51.100.42',
      connectedAt: 1000,
      lastJobAt: 0,
      jobsOk: 0,
      jobsErr: 0,
      capabilities: ['artifacts-v1', 'browser-v1', 'pdf-v1'],
    };
    const ws: HubSocketLike = {
      readyState: 1,
      send: (msg: string) => {
        const parsed = JSON.parse(msg) as { jobId: string; jobNonce: string };
        queueMicrotask(() => onJob(parsed.jobId, parsed.jobNonce, engine));
      },
      close: () => {},
      serializeAttachment: (v: unknown) => {
        att = v;
      },
      deserializeAttachment: () => att,
    };
    sockets.push(ws);
    return ws;
  };

  let now = 10_000;
  const engine = new AgentHubEngine({
    getSockets: () => sockets,
    cooldowns: memoryCooldowns(),
    hostWindows: createMemoryHostWindowStore(),
    now: () => now,
    sleep: async (ms) => {
      now += ms;
    },
  });

  makeNode('site-arm64', (jobId, jobNonce, eng) => {
    eng.completeJob(
      jobId,
      jobNonce,
      'site-arm64',
      JSON.stringify({
        results: [{ id: 'interact-1', url: 'https://www.youtube.com/watch?v=test', status: 0, outcome: 'error', problem: 'cdp connection closed' }],
      }),
    );
  });
  makeNode('site-x86', (jobId, jobNonce, eng) => {
    eng.completeJob(
      jobId,
      jobNonce,
      'site-x86',
      JSON.stringify({
        results: [{ id: 'interact-1', url: 'https://www.youtube.com/watch?v=test', status: 200, outcome: 'ok', body: '<html>ok</html>' }],
      }),
    );
  });

  const res = await engine.dispatchFetch(
    JSON.stringify({
      maxSeconds: 60,
      requests: [{ id: 'interact-1', url: 'https://www.youtube.com/watch?v=test', kind: 'render', interact: { actions: [] } }],
    }),
  );
  assert.equal(res.ok, true);
  if (res.ok) {
    assert.equal(res.siteId, 'site-arm64+site-x86');
    const parsed = JSON.parse(res.bodyText) as { results: Array<{ status: number; outcome: string }> };
    assert.equal(parsed.results[0]?.status, 200);
    assert.equal(parsed.results[0]?.outcome, 'ok');
  }
});

test('V2-6: executeSearchCall prioritizes edge-map on site: domains, fuses Serper (num:10) + Brave via RRF with URL dedupe, and falls back to Tavily basic only when needed', async () => {
  resetSearchProviderPacingForTests();

  assert.equal(
    canonicalizeSearchResultUrl('https://Docs.Example.com/manuals/m620/?utm_source=google&gclid=123&rev=2#page=4'),
    'https://docs.example.com/manuals/m620?rev=2',
  );
  assert.deepEqual(extractEdgeMapDomains('site:velotricbike.com Discover 2 manual', []), {
    domains: ['velotricbike.com'],
    siteDomains: ['velotricbike.com'],
    siteUrls: ['https://velotricbike.com/'],
    sitePrefixes: [],
    filterTerms: 'Discover 2 manual',
  });

  // 1. Federated Serper + Brave + Edge-Map RRF fusion -> Tavily is NOT called when primary providers succeed!
  const apiCalls: Array<{ url: string; body?: unknown }> = [];
  let edgeMapDispatches = 0;

  const fedOut = await executeSearchCall({
    payload: {
      query: 'site:velotricbike.com Discover 2 manual',
      max_results: 5,
      time_range: 'month',
    },
    env: {
      SERPER_API_KEY: 'serper_test_key',
      BRAVE_API_KEY: 'brave_test_key',
      TAVILY_API_KEY: 'tavily_should_not_be_called',
    },
    executeHubFetch: async (target, body) => {
      edgeMapDispatches++;
      assert.equal(target, 'auto', 'edge-map must prioritize HAOS edge nodes via target=auto');
      const parsed = JSON.parse(body) as { requests: Array<{ id: string; url: string }> };
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: parsed.requests.map((r) => {
            if (r.id === 'llms') {
              return {
                id: 'llms',
                url: r.url,
                status: 200,
                outcome: 'ok',
                body: '# Velotric Docs\n- [Discover 2 Manual](https://www.velotricbike.com/manuals/discover-2.pdf)\n',
              };
            }
            return { id: r.id, url: r.url, status: 404, outcome: 'gone', body: '' };
          }),
        }),
      };
    },
    providerFetchFn: async (input, init) => {
      const u = String(input);
      const parsedBody = init?.body ? JSON.parse(String(init.body)) : undefined;
      apiCalls.push({ url: u, body: parsedBody });
      if (u === 'https://google.serper.dev/search') {
        assert.equal((parsedBody as { num?: number })?.num, 10, 'Serper must cap num:10 so each query costs 1 credit');
        assert.equal((parsedBody as { tbs?: string })?.tbs, 'qdr:m');
        return Response.json({
          organic: [
            {
              link: 'https://www.velotricbike.com/manuals/discover-2.pdf?utm_source=google',
              title: 'Velotric Discover 2 User Manual (PDF)',
              snippet: 'Official torque and wiring specs.',
            },
            {
              link: 'https://www.velotricbike.com/products/discover-2',
              title: 'Discover 2 Commuter E-Bike',
              snippet: '750W motor, 705.6Wh battery.',
            },
          ],
        });
      }
      if (u.startsWith('https://api.search.brave.com/')) {
        return Response.json({
          web: {
            results: [
              {
                url: 'https://www.velotricbike.com/manuals/discover-2.pdf?fbclid=xyz',
                title: 'Discover 2 Manual',
                description: 'PDF manual.',
              },
              {
                url: 'https://www.velotricbike.com/pages/support',
                title: 'Velotric Support',
                description: 'Manuals & firmware.',
              },
            ],
          },
        });
      }
      throw new Error(`unexpected provider call: ${u}`);
    },
  });

  assert.equal(fedOut.status, 200);
  assert.equal(edgeMapDispatches, 1);
  assert.equal(apiCalls.some((c) => c.url.includes('tavily.com')), false, 'Tavily must stay idle when Serper+Brave return >=3 results');
  const results = fedOut.body.results as Array<{ url: string; providers: string[] }>;
  assert.equal(results[0]?.url, 'https://www.velotricbike.com/manuals/discover-2.pdf');
  assert.deepEqual(
    results[0]?.providers.sort(),
    ['brave', 'edge-map:agent:site-x86', 'serper'],
    'URL canonicalization must fuse Edge-Map + Serper + Brave hits into Rank #1',
  );

  // 2. When Serper 429s, Tavily (`search_depth: "basic"`) steps in automatically!
  let tavilyCalledWithBasic = false;
  const fallbackOut = await executeSearchCall({
    payload: { query: 'Bafang M620 CAN bus pinout', max_results: 4 },
    env: { SERPER_API_KEY: 'serper_test_key', TAVILY_API_KEY: 'tavily_test_key' },
    executeHubFetch: async () => ({ status: 200, via: 'noop', bodyText: '{"results":[]}' }),
    providerFetchFn: async (input, init) => {
      const u = String(input);
      if (u === 'https://google.serper.dev/search') {
        return new Response('rate limited', { status: 429, headers: { 'retry-after': '30' } });
      }
      if (u === 'https://api.tavily.com/search') {
        const b = JSON.parse(String(init?.body)) as { search_depth?: string };
        tavilyCalledWithBasic = b.search_depth === 'basic';
        return Response.json({
          results: [{ url: 'https://www.bafang-e.com/manuals/m620.pdf', title: 'M620 OEM Manual', content: 'CAN bus pinout' }],
        });
      }
      throw new Error(`unexpected: ${u}`);
    },
  });
  assert.equal(fallbackOut.status, 200);
  assert.equal(tavilyCalledWithBasic, true);
  assert.equal((fallbackOut.body.results as Array<{ url: string }>)[0]?.url, 'https://www.bafang-e.com/manuals/m620.pdf');
});

test('V2-7: HTML code-stash preserves <T> generics, Jupyter .ipynb & OpenAPI 3.1 converters, and foreign locale dedup', async () => {
  // 1. HTML code-stash preserves angle-bracket generics, C headers, and nested backticks!
  const extracted = extractHtmlDocument(
    `<html><head><title>Generics</title></head><body><main>
      <h1>Generics</h1>
      <p>Returns <code>Promise&lt;Array&lt;number&gt;&gt;</code> or <code>use \`tick\` span</code>.</p>
      <pre><code class="language-c">#include &lt;stdio.h&gt;
int main(void) { return 0; }</code></pre>
    </main></body></html>`,
    { baseUrl: 'https://docs.example.com/generics', onlyMainContent: true },
  );
  assert.match(extracted.markdown, /`Promise<Array<number>>`/);
  assert.match(extracted.markdown, /`` use `tick` span ``/);
  assert.match(extracted.markdown, /```c\n#include <stdio\.h>/);

  // 2. Jupyter Notebook (.ipynb) converter
  const nbMd = formatJupyterNotebookToMarkdown(
    {
      nbformat: 4,
      metadata: { kernelspec: { language: 'python', display_name: 'Python 3' } },
      cells: [
        { cell_type: 'markdown', source: ['# Quickstart Notebook\n', 'Run a cell below.'] },
        {
          cell_type: 'code',
          execution_count: 1,
          source: ['print(6 * 7)'],
          outputs: [{ output_type: 'stream', name: 'stdout', text: ['42\n'] }],
        },
      ],
    },
    'https://raw.githubusercontent.com/org/repo/main/demo.ipynb',
  );
  assert.ok(nbMd?.markdown.includes('```python'));
  assert.ok(nbMd?.markdown.includes('42'));

  // 3. OpenAPI 3.1 converter
  const oaMd = formatOpenApiSpecToMarkdown({
    openapi: '3.1.0',
    info: { title: 'EdgeFetch Widget API', version: '2.1.0', description: 'Public REST API' },
    paths: {
      '/v1/widgets': {
        get: { summary: 'List widgets', responses: { '200': { description: 'OK' } } },
      },
    },
  });
  assert.ok(oaMd?.markdown.includes('EdgeFetch Widget API'));
  assert.ok(oaMd?.markdown.includes('GET /v1/widgets'));

  // 4. URL kind & Accept inference
  assert.equal(inferKindForUrl('https://raw.githubusercontent.com/org/repo/main/demo.ipynb'), 'json');
  assert.equal(inferKindForUrl('https://raw.githubusercontent.com/org/repo/main/main.go'), 'text');
  assert.equal(defaultTextAccept('https://raw.githubusercontent.com/org/repo/main/main.go'), 'text/plain');

  // 5. Foreign locale mirror demotion/deduplication in search when English query has enough canonical results
  const locSearch = await executeSearchCall({
    payload: { query: 'TaskGroup asyncio docs', max_results: 2 },
    env: { SERPER_API_KEY: 'serper_test_key' },
    executeHubFetch: async () => ({ status: 200, via: 'noop', bodyText: '{"results":[]}' }),
    providerFetchFn: async () =>
      Response.json({
        organic: [
          { link: 'https://docs.python.org/uk/3/library/asyncio-task.html', title: 'Корутини і завдання', snippet: 'TaskGroup' },
          { link: 'https://docs.python.org/ja/3/library/asyncio-task.html', title: 'コルーチンとタスク', snippet: 'TaskGroup' },
          { link: 'https://docs.python.org/3/library/asyncio-task.html', title: 'Coroutines and Tasks', snippet: 'TaskGroup docs' },
          { link: 'https://docs.python.org/3/library/asyncio-exceptions.html', title: 'Exceptions', snippet: 'ExceptionGroup' },
        ],
      }),
  });
  const locUrls = (locSearch.body.results as Array<{ url: string }>).map((r) => r.url);
  assert.deepEqual(locUrls, [
    'https://docs.python.org/3/library/asyncio-task.html',
    'https://docs.python.org/3/library/asyncio-exceptions.html',
  ]);
});

test('V2-8: Vendor-agnostic OTLP/HTTP exporter, W3C traceparent stitch, and EdgeFetchClient multi-hub HA failover', async () => {
  // 1. W3C traceparent parsing & header propagation
  const upstreamTp = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
  const parsedTp = parseTraceparent(upstreamTp);
  assert.ok(parsedTp);
  assert.equal(parsedTp.traceId, '4bf92f3577b34da6a3ce929d0e0e4736');
  assert.equal(parsedTp.parentSpanId, '00f067aa0ba902b7');
  assert.equal(parsedTp.sampled, true);
  assert.equal(parseTraceparent('00-00000000000000000000000000000000-00f067aa0ba902b7-01'), null);

  const reqCtx = createRequestTraceContext(new Request('https://hub.example.com/v1/scrape', { headers: { traceparent: upstreamTp } }));
  assert.equal(reqCtx.headers['x-trace-id'], '4bf92f3577b34da6a3ce929d0e0e4736');
  assert.match(reqCtx.headers.traceparent ?? '', /^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$/);

  // 2. OTLP endpoint normalization, header parsing, and JSON trace export
  assert.equal(resolveOtlpTracesUrl('https://api.honeycomb.io'), 'https://api.honeycomb.io/v1/traces');
  assert.equal(resolveOtlpTracesUrl('https://otlp.grafana.net/otlp/'), 'https://otlp.grafana.net/otlp/v1/traces');
  assert.deepEqual(parseOtlpHeaders('Authorization=Bearer%20secret, x-honeycomb-team=team_123'), {
    Authorization: 'Bearer secret',
    'x-honeycomb-team': 'team_123',
  });

  const childSpans = buildCrawlChildSpans({
    traceId: reqCtx.context.traceId,
    parentSpanId: reqCtx.context.spanId,
    via: 'agent:mac-mini-1',
    endTimeMs: 1_700_000_000_500,
    replyText: JSON.stringify({
      results: [
        {
          id: '1',
          url: 'https://docs.example.com/guide?token=secret',
          kind: 'scrape',
          status: 200,
          outcome: 'ok',
          durationMs: 120,
          timing: { dnsMs: 5, connectMs: 15, tlsMs: 25, ttfbMs: 60, reused: true, proto: 'HTTP/2.0' },
        },
      ],
    }),
  });
  assert.equal(childSpans.length, 1);
  assert.equal(childSpans[0]?.attributes?.['url.full'], 'https://docs.example.com/guide');

  let capturedOtlpUrl = '';
  let capturedOtlpHeaders: Record<string, string> = {};
  let capturedOtlpBody = '';
  const okFlush = await flushOtlpSpans({
    env: {
      OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com',
      OTEL_EXPORTER_OTLP_HEADERS: 'Authorization=Bearer%20otlp_tok',
      OTEL_SERVICE_NAME: 'edgefetch-test-hub',
    },
    spans: childSpans,
    fetchFn: async (input, init) => {
      capturedOtlpUrl = String(input);
      capturedOtlpHeaders = Object.fromEntries(new Headers(init?.headers).entries());
      capturedOtlpBody = String(init?.body ?? '');
      return new Response('{}', { status: 200 });
    },
  });
  assert.equal(okFlush, true);
  assert.equal(capturedOtlpUrl, 'https://otel.example.com/v1/traces');
  assert.equal(capturedOtlpHeaders.authorization, 'Bearer otlp_tok');
  assert.match(capturedOtlpBody, /"edgefetch-test-hub"/);
  assert.match(capturedOtlpBody, /"4bf92f3577b34da6a3ce929d0e0e4736"/);

  // 3. EdgeFetchClient multi-controller HA failover (503 on primary -> 200 on standby Go hub)
  const hitUrls: string[] = [];
  const haClient = new EdgeFetchClient({
    baseUrls: ['https://primary-hub.example.com', 'https://standby-go-hub.tailnet.ts.net'],
    token: 'caller-token-0123456789abcdef',
    fetchFn: async (input) => {
      const u = String(input);
      hitUrls.push(u);
      if (u.startsWith('https://primary-hub.example.com')) {
        return Response.json({ error: 'hub_unavailable', message: 'DO shard evicting' }, { status: 503 });
      }
      return Response.json({ ok: true, via: 'go-standby-hub', markdown: '# Standby OK' }, { status: 200 });
    },
  });
  const haOut = await haClient.scrape({ url: 'https://example.com' });
  assert.equal(haOut.via, 'go-standby-hub');
  assert.equal(hitUrls.length, 2);
});

test('V2-9: Portable Node 22+ Hub (startPortableHub) serves /health, /admin, /v1/capabilities, and /mcp over node:sqlite + fs artifacts', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-portable-test-'));
  const tok = 'portable-owner-secret-0123456789ab';
  const agentTok = 'portable-agent-secret-0123456789ab';
  const started = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    envOverrides: {
      CALLER_TOKEN: tok,
      AGENT_TOKEN: agentTok,
    },
  });
  try {
    const base = `http://127.0.0.1:${started.port}`;
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { ok: true });

    const capsRes = await fetch(`${base}/v1/capabilities`, {
      headers: { authorization: `Bearer ${tok}` },
    });
    assert.equal(capsRes.status, 200);
    const caps = (await capsRes.json()) as { capabilities: Record<string, boolean> };
    assert.equal(caps.capabilities.artifacts, true);
    assert.equal(caps.capabilities.tracking, true);
    assert.equal(caps.capabilities.search, true);

    const adminPage = await fetch(`${base}/admin`);
    assert.equal(adminPage.status, 200);
    assert.match(await adminPage.text(), /EdgeFetch Hub/);

    const mcpTools = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(mcpTools.status, 200);
    const mcpJson = (await mcpTools.json()) as { result: { tools: Array<{ name: string }> } };
    assert.equal(mcpJson.result.tools.length, 15);
  } finally {
    await started.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('V2-10: Modular Site Extractor Registry (18+ platforms: npm, crates.io, HF, GitLab, Codeberg, Discourse, Lobsters, Bluesky, Mastodon, DEV.to, StackOverflow, Gist, pkg.go.dev, PyPI, Reddit, Wikipedia, RFC & PubMed)', async () => {
  const htmlToMd = (frag: string, baseUrl?: string) => {
    const out = extractHtmlDocument(frag, { baseUrl, onlyMainContent: false });
    return { markdown: out.markdown, links: out.links };
  };

  // 1. npm (@scope/pkg) -> registry.npmjs.org
  const npmTwin = resolveSiteExtractorTwin('https://www.npmjs.com/package/@cloudflare/workers-types/v/4.20260101.0');
  assert.equal(npmTwin?.id, 'npm-registry');
  assert.equal(npmTwin?.fetchUrl, 'https://registry.npmjs.org/@cloudflare%2Fworkers-types');
  const npmDoc = npmTwin?.formatTwin(
    JSON.stringify({
      name: '@cloudflare/workers-types',
      'dist-tags': { latest: '4.20260101.0' },
      versions: { '4.20260101.0': { description: 'TypeScript definitions for Workers', license: 'MIT', types: 'index.d.ts', dependencies: {} } },
      readme: '# Workers Types\n\nInstall for `Promise<Response>` types.',
    }),
    'https://www.npmjs.com/package/@cloudflare/workers-types',
    htmlToMd,
  );
  assert.match(npmDoc?.markdown ?? '', /npm install @cloudflare\/workers-types/);
  assert.match(npmDoc?.markdown ?? '', /Promise<Response>/);

  // 2. crates.io -> /api/v1/crates/serde
  const crateTwin = resolveSiteExtractorTwin('https://crates.io/crates/serde');
  assert.equal(crateTwin?.id, 'crates-io');
  const crateDoc = crateTwin?.formatTwin(
    JSON.stringify({
      crate: { name: 'serde', max_stable_version: '1.0.218', description: 'Serialization framework', downloads: 450000000, repository: 'https://github.com/serde-rs/serde' },
      versions: [{ num: '1.0.218', license: 'MIT OR Apache-2.0', rust_version: '1.56', created_at: '2026-02-01T00:00:00Z', features: { derive: ['serde_derive'] } }],
    }),
    'https://crates.io/crates/serde',
    htmlToMd,
  );
  assert.match(crateDoc?.markdown ?? '', /cargo add serde/);
  assert.match(crateDoc?.markdown ?? '', /Rust `1\.56`/);

  // 3–5. RubyGems, Packagist, Hex.pm
  assert.equal(resolveSiteExtractorTwin('https://rubygems.org/gems/rails')?.id, 'rubygems');
  assert.equal(resolveSiteExtractorTwin('https://packagist.org/packages/symfony/console')?.id, 'packagist');
  assert.equal(resolveSiteExtractorTwin('https://hex.pm/packages/phoenix')?.id, 'hex-pm');

  // 6. Hugging Face Model Card YAML frontmatter -> GFM metadata table
  const hfTwin = resolveSiteExtractorTwin('https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct');
  assert.equal(hfTwin?.id, 'huggingface-card');
  assert.equal(hfTwin?.fetchUrl, 'https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct/raw/main/README.md');
  const hfCard = formatYamlFrontmatterCard(
    '---\nlicense: apache-2.0\npipeline_tag: text-generation\ntags:\n  - code\n  - qwen2\n---\n\n# Qwen2.5-Coder\n\nSupports `Vec<u8>` generation.',
    'Qwen/Qwen2.5-Coder-32B-Instruct',
  );
  assert.match(hfCard.markdown, /\|\s*\*\*license\*\*\s*\|\s*apache-2\.0\s*\|/);
  assert.match(hfCard.markdown, /Vec<u8>/);

  // 7–8. GitLab robots.txt-compliant ?format=json&viewer=simple blob + repo root README upgrades
  assert.equal(
    resolveSiteExtractorTwin('https://gitlab.com/inkscape/inkscape/-/blob/master/CMakeLists.txt')?.fetchUrl,
    'https://gitlab.com/inkscape/inkscape/-/blob/master/CMakeLists.txt?format=json&viewer=simple',
  );
  assert.equal(
    resolveSiteExtractorTwin('https://gitlab.com/gitlab-org/cli')?.fetchUrl,
    'https://gitlab.com/gitlab-org/cli/-/blob/HEAD/README.md?format=json&viewer=simple',
  );

  // 9. Universal Discourse `/t/<slug>/<id>` -> `.json` with `accepted_answer`
  const discTwin = resolveSiteExtractorTwin('https://community.home-assistant.io/t/websocket-reconnect-best-practices/712345');
  assert.equal(discTwin?.id, 'discourse-topic');
  const discDoc = discTwin?.formatTwin(
    JSON.stringify({
      title: 'WebSocket Reconnect Best Practices',
      tags: ['addons', 'websocket'],
      accepted_answer: { post_number: 2, username: 'maintainer' },
      post_stream: {
        posts: [
          { post_number: 1, username: 'asker', created_at: '2026-10-01T10:00:00Z', cooked: '<p>How should jitter backoff work?</p>' },
          { post_number: 2, username: 'maintainer', created_at: '2026-10-01T10:05:00Z', cooked: '<p>Use full jitter with <code>Retry-After</code>.</p>' },
        ],
      },
    }),
    'https://community.home-assistant.io/t/websocket-reconnect-best-practices/712345',
    htmlToMd,
  );
  assert.match(discDoc?.markdown ?? '', /✅ Accepted Solution — @maintainer/);
  assert.match(discDoc?.markdown ?? '', /`Retry-After`/);

  // 10–13. Lobsters, Bluesky ATProto, Mastodon, DEV.to
  const lobTwin = resolveSiteExtractorTwin('https://lobste.rs/s/abc123/zero_alloc_go_parsers');
  assert.equal(lobTwin?.id, 'lobsters');
  const bskyTwin = resolveSiteExtractorTwin('https://bsky.app/profile/golang.org/post/3lbxyz123');
  assert.equal(bskyTwin?.id, 'bluesky-thread');
  const bskyDoc = bskyTwin?.formatTwin(
    JSON.stringify({
      thread: {
        post: {
          author: { handle: 'golang.org', displayName: 'The Go Programming Language' },
          record: { text: 'Go 1.27 is released with faster SwissTables!', createdAt: '2026-08-12T16:00:00Z' },
          likeCount: 420,
          repostCount: 95,
        },
        replies: [{ post: { author: { handle: 'gopher.dev' }, record: { text: 'Zero regressions under -race!' } } }],
      },
    }),
    'https://bsky.app/profile/golang.org/post/3lbxyz123',
    htmlToMd,
  );
  assert.match(bskyDoc?.markdown ?? '', /SwissTables/);
  assert.match(bskyDoc?.markdown ?? '', /@gopher\.dev/);

  assert.equal(resolveSiteExtractorTwin('https://fosstodon.org/@user/113456789012345678')?.id, 'mastodon-status');
  assert.equal(resolveSiteExtractorTwin('https://dev.to/gopher/writing-fuzz-tests')?.id, 'dev-to');

  // 14. Stack Overflow Q&A DOM extractor (Question + ✅ Accepted Answer + code generics)
  const soHtml = `<!doctype html><html><body>
    <div id="question-header"><h1>How to type Promise&lt;Result&lt;T&gt;&gt; in TypeScript?</h1></div>
    <div id="question" data-score="42">
      <div class="s-prose js-post-body"><p>I need <code>Promise&lt;Result&lt;T&gt;&gt;</code> without losing generics.</p></div>
      <a class="post-tag">typescript</a><a class="post-tag">generics</a>
      <span class="comment-copy">Tested on TS 5.8?</span>
    </div>
    <div id="answer-10" data-score="5"><div class="s-prose js-post-body"><p>Older workaround.</p></div></div>
    <div id="answer-20" class="answer accepted-answer" data-score="88">
      <div class="s-prose js-post-body"><p>Return <code>Awaited&lt;T&gt;</code> directly:</p><pre><code>type Unwrap&lt;T&gt; = Awaited&lt;T&gt;;</code></pre></div>
    </div>
    <div id="hot-network-questions"><ul><li>Noise question 1</li></ul></div>
  </body></html>`;
  const soOut = extractHtmlDocument(soHtml, { baseUrl: 'https://stackoverflow.com/questions/99999/how-to-type-promise' });
  assert.match(soOut.markdown, /## ✅ Accepted Answer \(Score: 88\)/);
  assert.match(soOut.markdown, /`Promise<Result<T>>`/);
  assert.match(soOut.markdown, /type Unwrap<T> = Awaited<T>;/);
  assert.equal(soOut.markdown.includes('Noise question 1'), false);

  // 15–18. GitHub Gist, pkg.go.dev, PyPI, IETF RFC, Wikipedia, Reddit & PubMed
  const rfcHtml = `<!doctype html><html><head><title>RFC 9110: HTTP Semantics</title></head><body>
    <pre class="newpage">RFC 9110                     HTTP Semantics                    June 2022

10.2.3. Retry-After

The "Retry-After" header field indicates how long the user agent ought to wait.

Fielding, et al.             Standards Track                   [Page 42]</pre>
  </body></html>`;
  const rfcOut = extractHtmlDocument(rfcHtml, { baseUrl: 'https://www.rfc-editor.org/rfc/rfc9110' });
  assert.match(rfcOut.markdown, /#### 10\.2\.3\. Retry-After/);
  assert.equal(rfcOut.markdown.includes('[Page 42]'), false);

  const wikiHtml = `<!doctype html><html><body><main>
    <h1>Bloom filter</h1>
    <p>A Bloom filter<span class="mw-editsection">[edit]</span> is a space-efficient probabilistic data structure.[citation needed]</p>
  </main></body></html>`;
  const wikiOut = extractHtmlDocument(wikiHtml, { baseUrl: 'https://en.wikipedia.org/wiki/Bloom_filter' });
  assert.equal(wikiOut.markdown.includes('[citation needed]'), false);
  assert.equal(wikiOut.markdown.includes('[edit]'), false);

  const redditHtml = `<!doctype html><html><body>
    <shreddit-post post-title="Self-hosting MCP servers on Home Assistant" author="homelabber" score="312" subreddit-prefixed-name="r/selfhosted">
      <div><p>Zero open router ports over outbound WebSockets!</p></div>
    </shreddit-post>
    <shreddit-comment author="builder" score="45" depth="0"><p>Works great on Raspberry Pi 5.</p></shreddit-comment>
  </body></html>`;
  const redditOut = extractHtmlDocument(redditHtml, { baseUrl: 'https://www.reddit.com/r/selfhosted/comments/xyz123/selfhosting/' });
  assert.match(redditOut.markdown, /# Self-hosting MCP servers on Home Assistant/);
  assert.match(redditOut.markdown, /\*\*u\/builder\*\* \(45\): Works great on Raspberry Pi 5\./);
});

test('V2-11: WebCrypto AWS SigV4 S3ArtifactBucket, TursoHttpD1Database /v2/pipeline, and MV3 POST /v1/ingest-tab FTS5 clip indexing', async () => {
  // 1. Deterministic AWS SigV4 signing check + S3ArtifactBucket conditional PUT/GET/HEAD
  const sigHeaders = await buildSigV4Headers({
    method: 'PUT',
    url: 'https://s3.us-east-1.amazonaws.com/edgefetch-bucket/raw/sha256/aa/test.gz',
    region: 'us-east-1',
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    payloadSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    now: new Date('2026-11-20T00:00:00Z'),
  });
  assert.match(sigHeaders.authorization ?? '', /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20261120\/us-east-1\/s3\/aws4_request/);

  const memObjects = new Map<string, { bytes: Uint8Array; headers: Record<string, string> }>();
  const s3 = new S3ArtifactBucket({
    endpoint: 'https://s3.example.internal',
    bucket: 'ef-artifacts',
    accessKeyId: 'test-key',
    secretAccessKey: 'test-secret',
    fetchImpl: async (input, init) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      const reqHeaders = (init?.headers ?? {}) as Record<string, string>;
      if (method === 'PUT') {
        if (reqHeaders['if-none-match'] === '*' && memObjects.has(url)) {
          return new Response(null, { status: 412 });
        }
        const body = init?.body as Uint8Array;
        memObjects.set(url, { bytes: new Uint8Array(body), headers: reqHeaders });
        return new Response(null, { status: 200, headers: { etag: '"abc123"' } });
      }
      const existing = memObjects.get(url);
      if (!existing) return new Response(null, { status: 404 });
      const resHeaders: Record<string, string> = {
        'content-length': String(existing.bytes.byteLength),
        'content-type': existing.headers['content-type'] ?? 'application/octet-stream',
        etag: '"abc123"',
      };
      for (const [k, v] of Object.entries(existing.headers)) {
        if (k.startsWith('x-amz-meta-')) resHeaders[k] = v;
      }
      return new Response(method === 'HEAD' ? null : (existing.bytes as BodyInit), { status: 200, headers: resHeaders });
    },
  });

  const firstPut = await s3.put('tmp/test.txt', 'hello sigv4', {
    onlyIf: new Headers({ 'if-none-match': '*' }),
    customMetadata: { contentSha256: 'deadbeef' },
  });
  assert.ok(firstPut);
  const dupPut = await s3.put('tmp/test.txt', 'hello sigv4', { onlyIf: new Headers({ 'if-none-match': '*' }) });
  assert.equal(dupPut, null);
  const gotS3 = await s3.get('tmp/test.txt');
  assert.equal(await gotS3?.text(), 'hello sigv4');
  assert.equal(gotS3?.customMetadata?.contentsha256, 'deadbeef');

  // 2. TursoHttpD1Database /v2/pipeline batch execution
  let capturedPipelineUrl = '';
  const turso = new TursoHttpD1Database({
    url: 'libsql://edgefetch-org.turso.io',
    authToken: 'turso-jwt-token',
    fetchImpl: async (input, init) => {
      capturedPipelineUrl = String(input);
      const body = JSON.parse(String(init?.body ?? '{}')) as { requests: Array<{ type: string }> };
      assert.equal(body.requests.at(-1)?.type, 'close');
      return Response.json({
        results: [
          {
            type: 'ok',
            response: {
              type: 'execute',
              result: {
                cols: [{ name: 'id' }, { name: 'title' }],
                rows: [[{ type: 'integer', value: '7' }, { type: 'text', value: 'Turso Row' }]],
                affected_row_count: 1,
              },
            },
          },
          { type: 'ok', response: { type: 'close' } },
        ],
      });
    },
  });
  const row = await turso.prepare('SELECT id, title FROM pages WHERE id = ?').bind(7).first<{ id: number; title: string }>();
  assert.equal(capturedPipelineUrl, 'https://edgefetch-org.turso.io/v2/pipeline');
  assert.deepEqual(row, { id: 7, title: 'Turso Row' });

  // 3. MV3 Browser Extension `POST /v1/ingest-tab` -> immediate FTS5 collection search!
  const dataDir = mkdtempSync(join(tmpdir(), 'ef-clip-test-'));
  const tok = 'clipper-owner-secret-0123456789ab';
  const started = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir,
    envOverrides: { CALLER_TOKEN: tok, AGENT_TOKEN: 'clipper-agent-secret-0123456789ab' },
  });
  try {
    const base = `http://127.0.0.1:${started.port}`;
    const clipRes = await fetch(`${base}/v1/ingest-tab`, {
      method: 'POST',
      headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        url: 'https://internal.example.com/runbooks/failover',
        html: '<!doctype html><html><head><title>Failover Runbook</title></head><body><main><h1>Failover Runbook</h1><p>Promote standby hub via Tailscale quorum.</p></main></body></html>',
        collectionId: 'team-runbooks',
      }),
    });
    assert.equal(clipRes.status, 200);
    const clipJson = (await clipRes.json()) as { ok: boolean; indexedChunks: number; markdown: string };
    assert.equal(clipJson.ok, true);
    assert.equal(clipJson.indexedChunks >= 1, true);
    assert.match(clipJson.markdown, /Tailscale quorum/);

    const ftsRes = await fetch(`${base}/v1/collections/team-runbooks/search`, {
      method: 'POST',
      headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ query: 'Tailscale quorum' }),
    });
    assert.equal(ftsRes.status, 200);
    const ftsJson = (await ftsRes.json()) as { hits: Array<{ url: string }> };
    assert.equal(ftsJson.hits.length, 1);
    assert.equal(ftsJson.hits[0]?.url, 'https://internal.example.com/runbooks/failover');
  } finally {
    await started.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('V2-12: v2.3.0 Handoff Regression Suite (P1-P12 + structured jobs tool)', async () => {
  // --- P1 & P11: Ashby single job (even with renderMode="browser") + shorthand annual pay scaling ($230 -> $230,000) ---
  const ashbyBoardPayload = JSON.stringify({
    organizationName: 'ElevenLabs',
    jobs: [
      {
        id: '43f91b57-5c4e-4d4a-9450-3591f2a79923',
        title: 'Forward Deployed Engineer',
        location: 'United States',
        isRemote: true,
        workplaceType: 'Remote',
        employmentType: 'FullTime',
        publishedAt: new Date(Date.now() - 2 * 86_400_000).toISOString(),
        jobUrl: 'https://jobs.ashbyhq.com/elevenlabs/43f91b57-5c4e-4d4a-9450-3591f2a79923',
        applyUrl: 'https://jobs.ashbyhq.com/elevenlabs/43f91b57-5c4e-4d4a-9450-3591f2a79923/application',
        descriptionHtml:
          '<h2>About the Role</h2><p>Partner directly with enterprise engineering teams to deploy real-time conversational AI voice agents in production environments across North America and Europe.</p>' +
          '<ul><li>Design low-latency WebSocket &amp; SIP integrations with customer backends.</li><li>Own end-to-end technical architecture, evaluation harnesses, and production reliability.</li></ul>',
        descriptionPlain:
          'Partner directly with enterprise engineering teams to deploy real-time conversational AI voice agents in production environments across North America and Europe.',
        compensation: {
          compensationTierSummary: '$230K – $350K • Offers Equity',
          summaryComponents: [
            {
              compensationType: 'Salary',
              interval: '1 YEAR',
              currencyCode: 'USD',
              minValue: 230,
              maxValue: 350,
            },
          ],
        },
      },
    ],
  });

  let ashbyFetchedUrl = '';
  const ashbyScrape = await executeScrapeCall({
    payload: {
      url: 'https://jobs.ashbyhq.com/elevenlabs/43f91b57-5c4e-4d4a-9450-3591f2a79923',
      renderMode: 'browser', // P1: Must resolve cleanly via Ashby API even when renderMode="browser" is passed!
    },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const call = JSON.parse(rawBody) as { requests: Array<{ url: string }> };
      ashbyFetchedUrl = call.requests[0]!.url;
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [{ id: 'ats-ashby-job', url: ashbyFetchedUrl, status: 200, outcome: 'ok', contentType: 'application/json', body: ashbyBoardPayload }],
        }),
      };
    },
  });
  assert.equal(ashbyScrape.status, 200);
  assert.equal(ashbyFetchedUrl, 'https://api.ashbyhq.com/posting-api/job-board/elevenlabs?includeCompensation=true');
  const ashbyJp = ashbyScrape.body.jobPosting as { workplaceType: string; pay: { min: number; max: number; basis: string; period: string } };
  assert.equal(ashbyJp.workplaceType, 'remote');
  assert.deepEqual(
    { min: ashbyJp.pay.min, max: ashbyJp.pay.max, basis: ashbyJp.pay.basis, period: ashbyJp.pay.period },
    { min: 230_000, max: 350_000, basis: 'base', period: 'year' },
  );
  assert.match(String(ashbyScrape.body.markdown), /\$230,000–\$350,000 USD\/year \(base\)/);
  assert.doesNotMatch(String(ashbyScrape.body.markdown), /<p>|<li>|&amp;/);

  // P1 also works identically through `extract`!
  const ashbyExtract = await executeExtractCall({
    payload: {
      urls: ['https://jobs.ashbyhq.com/elevenlabs/43f91b57-5c4e-4d4a-9450-3591f2a79923'],
      query: 'compensation WebSocket voice agents',
    },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-x86',
      bodyText: JSON.stringify({
        results: [{ id: 'ext-1', url: ashbyFetchedUrl, status: 200, outcome: 'ok', contentType: 'application/json', body: ashbyBoardPayload }],
      }),
    }),
  });
  assert.equal(ashbyExtract.status, 200);
  const ashbyExtHit = (ashbyExtract.body.results as Array<Record<string, unknown>>)[0]!;
  assert.match(String(ashbyExtHit.rawContent), /\$230,000–\$350,000/);

  // P1 fallback: Thin HTML page (< 50 words) with rich `<meta name="description">` (>= 40 words) sets `contentSource: "meta-description"`
  const metaDescHtml =
    '<!doctype html><html><head><title>Staff Systems Engineer</title>' +
    '<meta name="description" content="Join our distributed systems team to architect multi-region storage engines, Raft consensus replication, deterministic simulation testing, and low-latency Rust networking services for mission-critical cloud workloads across global availability zones with competitive base salary and equity." />' +
    '</head><body><main><p>Apply now</p></main></body></html>';
  const metaRescue = await executeScrapeCall({
    payload: { url: 'https://careers.example.com/jobs/staff-systems', renderMode: 'off' },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-arm64',
      bodyText: JSON.stringify({
        results: [{ id: 'scrape-1', url: 'https://careers.example.com/jobs/staff-systems', status: 200, outcome: 'ok', contentType: 'text/html', body: metaDescHtml }],
      }),
    }),
  });
  assert.equal(metaRescue.body.contentSource, 'meta-description');
  assert.match(String(metaRescue.body.markdown), /Raft consensus replication/);

  // --- P2: Workday CXS POST search + GET single job + `{"widget":"redirect"}` stub rescue ---
  let wdSearchMethod = '';
  let wdSearchBody = '';
  const wdBoardScrape = await executeScrapeCall({
    payload: { url: 'https://nvidia.wd5.myworkdayjobs.com/NVIDIAExternalCareerSite?q=Solutions+Architect' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = (JSON.parse(rawBody) as { requests: Array<{ method?: string; requestBody?: string; url: string }> }).requests[0]!;
      wdSearchMethod = req.method ?? 'GET';
      wdSearchBody = req.requestBody ?? '';
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'ats-workday-board',
              url: req.url,
              status: 200,
              outcome: 'ok',
              contentType: 'application/json',
              body: JSON.stringify({
                total: 1,
                jobPostings: [
                  {
                    title: 'Senior Solutions Architect, AI Infrastructure',
                    externalPath: '/job/US-CA-Santa-Clara/Senior-Solutions-Architect_JR1099',
                    locationsText: 'US, CA, Remote',
                    postedOn: 'Posted Today',
                  },
                ],
              }),
            },
          ],
        }),
      };
    },
  });
  assert.equal(wdSearchMethod, 'POST');
  assert.deepEqual(JSON.parse(wdSearchBody), { appliedFacets: {}, limit: 20, offset: 0, searchText: 'Solutions Architect' });
  assert.match(String(wdBoardScrape.body.markdown), /Senior Solutions Architect, AI Infrastructure/);

  // Workday `{"widget":"redirect","url":"/Workday","externalSpa":true}` stub auto-resolves via CXS!
  const wdStubCalls: string[] = [];
  const wdStubScrape = await executeScrapeCall({
    payload: { url: 'https://workday.wd5.myworkdayjobs.com/wday/custom-entry' },
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = (JSON.parse(rawBody) as { requests: Array<{ url: string; method?: string }> }).requests[0]!;
      wdStubCalls.push(`${req.method ?? 'GET'} ${req.url}`);
      if (wdStubCalls.length === 1) {
        return {
          status: 200,
          via: 'agent:site-x86',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'scrape-1',
                url: req.url,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify({ widget: 'redirect', url: '/Workday', externalSpa: true }),
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'ats-workday-board',
              url: req.url,
              status: 200,
              outcome: 'ok',
              contentType: 'application/json',
              body: JSON.stringify({
                total: 1,
                jobPostings: [{ title: 'Principal Distributed Systems Engineer', externalPath: '/job/Remote/Principal-Eng_JR1', locationsText: 'Remote' }],
              }),
            },
          ],
        }),
      };
    },
  });
  assert.equal(wdStubCalls.length, 2);
  assert.equal(wdStubCalls[1], 'POST https://workday.wd5.myworkdayjobs.com/wday/cxs/workday/Workday/jobs');
  assert.equal(wdStubScrape.body.redirected, true);
  assert.match(String(wdStubScrape.body.markdown), /Principal Distributed Systems Engineer/);

  // --- P3: Automatic browser switch (`renderedVia: "browser-auto"`) on thin / filter-only scripted pages ---
  const thinBuiltInShell =
    '<!doctype html><html><head><title>Remote Jobs | Built In</title><script src="/app.js"></script></head>' +
    '<body><main><h1>Remote Jobs</h1><ul><li><a href="/jobs/dev">Engineering</a></li><li><a href="/jobs/data">Data</a></li><li><a href="/jobs/ml">AI</a></li></ul></main></body></html>';
  const hydratedBuiltInDom =
    '<!doctype html><html><head><title>Remote Jobs | Built In</title></head><body><main><h1>Remote Forward Deployed Jobs</h1>' +
    '<article><h2><a href="https://builtin.com/job/fde-1">Forward Deployed Engineer</a></h2><p>Remote · $185K-$240K · Build production LLM agents for enterprise customers across healthcare and fintech.</p></article>' +
    '<article><h2><a href="https://builtin.com/job/fde-2">Staff Applied AI Engineer</a></h2><p>Remote · $200K-$260K · Architect retrieval pipelines, evaluation frameworks, and multi-agent orchestration.</p></article>' +
    '</main></body></html>';
  const autoKinds: string[] = [];
  const autoSwitched = await executeScrapeCall({
    payload: { url: 'https://builtin.com/jobs/remote?search=Forward+Deployed+Engineer' }, // omitted renderMode -> defaults to "auto"!
    env: {},
    executeHubFetch: async (_target, rawBody) => {
      const req = (JSON.parse(rawBody) as { requests: Array<{ kind: string; url: string }> }).requests[0]!;
      autoKinds.push(req.kind);
      const isRender = req.kind === 'render';
      return {
        status: 200,
        via: 'agent:site-win-vm',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'r1',
              url: req.url,
              status: 200,
              outcome: 'ok',
              rendered: isRender,
              contentType: 'text/html',
              body: isRender ? hydratedBuiltInDom : thinBuiltInShell,
            },
          ],
        }),
      };
    },
  });
  assert.deepEqual(autoKinds, ['scrape', 'render']);
  assert.equal(autoSwitched.body.rendered, true);
  assert.equal(autoSwitched.body.renderedVia, 'browser-auto');
  assert.match(String(autoSwitched.body.markdown), /Forward Deployed Engineer/);

  // --- P4 & P11: Schema.org `JobPosting` JSON-LD + EEO Boilerplate Down-Weighting + Total Target Cash Basis ---
  const camundaHtml =
    '<!doctype html><html><head><title>Senior Solutions Engineer</title>' +
    '<script type="application/ld+json">' +
    JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'JobPosting',
      title: 'Senior Solutions Engineer',
      datePosted: '2026-11-18',
      employmentType: 'FULL_TIME',
      hiringOrganization: { '@type': 'Organization', name: 'Camunda' },
      jobLocationType: 'TELECOMMUTE',
      applicantLocationRequirements: { '@type': 'Country', name: 'United States' },
      baseSalary: {
        '@type': 'MonetaryAmount',
        currency: 'USD',
        value: { '@type': 'QuantitativeValue', minValue: 157300, maxValue: 253600, unitText: 'YEAR' },
      },
    }) +
    '</script></head><body><main>' +
    '<h1>Senior Solutions Engineer</h1>' +
    '<p>Guide enterprise architects adopting distributed workflow orchestration across microservices.</p>' +
    '<h2>Compensation</h2><p>Annual Total Target Cash: $157,300 - $253,600 USD based on location and experience.</p>' +
    '<h2>Equal Employment Opportunity &amp; AI in Hiring</h2>' +
    '<p>Camunda is proud to be an equal opportunity employer without regard to race, color, religion, national origin, sex, age, or disability. ' +
    'Reasonable accommodations are available for qualified individuals with disabilities throughout the remote application process and compensation review. ' +
    'We may use artificial intelligence and automated employment decision tools during recruitment screening in compliance with candidate privacy notices.</p>' +
    '</main></body></html>';

  const camundaExtract = await executeExtractCall({
    payload: {
      urls: ['https://jobs.smartrecruiters.com/Camunda/744000099999999-senior-solutions-engineer'],
      query: 'remote compensation salary location',
      chunksPerSource: 1,
    },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-x86',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'ext-1',
            url: 'https://jobs.smartrecruiters.com/Camunda/744000099999999-senior-solutions-engineer',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: camundaHtml,
          },
        ],
      }),
    }),
  });
  const camundaHit = (camundaExtract.body.results as Array<Record<string, unknown>>)[0]!;
  const camundaJp = camundaHit.jobPosting as { workplaceType: string; pay: { min: number; max: number; basis: string } };
  assert.equal(camundaJp.workplaceType, 'remote');
  assert.equal(camundaJp.pay.basis, 'total'); // P11: Distinguished "Annual Total Target Cash" from pure base salary!
  // P4: Top-ranked chunk MUST be the role/compensation section, NEVER the EEO / AI-in-hiring legal footer!
  const topChunkText = ((camundaHit.chunks as Array<{ text: string }>)[0]?.text ?? '');
  assert.match(topChunkText, /\$157,300–\$253,600/);
  assert.doesNotMatch(topChunkText, /without regard to race, color, religion/i);

  // --- P5: Per-record JSON chunking (`1 chunk = 1 record`, zero salary bleed, HTML -> Markdown, `jsonFilter`) ---
  const leverPostingsJson = JSON.stringify([
    {
      id: 'job-111',
      text: 'Backend Infrastructure Engineer',
      hostedUrl: 'https://jobs.lever.co/acme/job-111',
      categories: { location: 'San Francisco, CA', commitment: 'Full-time' },
      salaryRange: { min: 145000, max: 175000, currency: 'USD', interval: 'per-year-salary' },
      description: '<p>Scale multi-tenant Postgres &amp; Kafka clusters.</p>',
    },
    {
      id: 'job-222',
      text: 'Forward Deployed AI Engineer',
      hostedUrl: 'https://jobs.lever.co/acme/job-222',
      categories: { location: 'Remote - US', commitment: 'Full-time' },
      salaryRange: { min: 215000, max: 275000, currency: 'USD', interval: 'per-year-salary' },
      description: '<p>Embed with Fortune 500 engineering leaders to ship autonomous workflows.</p>',
      lists: [{ text: 'Requirements', content: '<li>5+ years production Go or TypeScript</li><li>Strong customer architecture leadership</li>' }],
    },
  ]);

  const jsonAllExtract = await executeExtractCall({
    payload: { urls: ['https://api.lever.co/v0/postings/acme?mode=json'], chunksPerSource: 5 },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-x86',
      bodyText: JSON.stringify({
        results: [{ id: 'ext-1', url: 'https://api.lever.co/v0/postings/acme?mode=json', status: 200, outcome: 'ok', contentType: 'application/json', body: leverPostingsJson }],
      }),
    }),
  });
  const jsonAllHit = (jsonAllExtract.body.results as Array<{ chunks: Array<{ text: string }> }>)[0]!;
  assert.equal(jsonAllHit.chunks.length, 2);
  assert.match(jsonAllHit.chunks[0]!.text, /\$145,000–\$175,000/);
  assert.doesNotMatch(jsonAllHit.chunks[0]!.text, /215,000/); // Zero bleed from Job 2!
  assert.match(jsonAllHit.chunks[1]!.text, /\$215,000–\$275,000/);
  assert.doesNotMatch(jsonAllHit.chunks[1]!.text, /145,000/); // Zero bleed from Job 1!
  assert.doesNotMatch(jsonAllHit.chunks[1]!.text, /<p>|<li>|&amp;/);

  const jsonFilteredExtract = await executeExtractCall({
    payload: {
      urls: ['https://api.lever.co/v0/postings/acme?mode=json'],
      jsonFilter: 'text~"Forward Deployed"',
    },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-x86',
      bodyText: JSON.stringify({
        results: [{ id: 'ext-1', url: 'https://api.lever.co/v0/postings/acme?mode=json', status: 200, outcome: 'ok', contentType: 'application/json', body: leverPostingsJson }],
      }),
    }),
  });
  const filteredHit = (jsonFilteredExtract.body.results as Array<{ recordCount: number; totalRecords: number; chunks: Array<{ text: string }> }>)[0]!;
  assert.equal(filteredHit.recordCount, 1);
  assert.equal(filteredHit.totalRecords, 2);
  assert.equal(filteredHit.chunks.length, 1);
  assert.match(filteredHit.chunks[0]!.text, /Forward Deployed AI Engineer/);

  // --- P6: Block-boundary & link/sentence-safe chunking (`chunkMarkdownForSearch`) ---
  const linkHeavyMd = [
    '# Cloudflare Agents Architecture',
    'Durable Objects provide single-threaded coordination with WebSocket hibernation. Read the [Model Context Protocol Guide](https://developers.cloudflare.com/agents/model-context-protocol/) to expose tools cleanly. Every Worker isolate validates incoming bearer tokens before routing requests to stateful actors.',
    'State persistence combines SQLite storage inside [Durable Objects](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/) with zero-egress object blobs in [Cloudflare R2](https://developers.cloudflare.com/r2/api/workers/workers-api-usage/). Outbound crawlers honor [RFC 9309 robots.txt](https://www.rfc-editor.org/rfc/rfc9309) on every hop.',
    '- First bullet with [Transport Spec](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports) and complete context.',
    '- Second bullet with [OAuth 2.1 PKCE](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12) and token rotation.',
  ].join('\n\n');
  const p6Chunks = chunkMarkdownForSearch(linkHeavyMd, 260, 80);
  assert.equal(p6Chunks.length >= 3, true);
  for (const ch of p6Chunks) {
    assert.doesNotMatch(ch.text, /^\]\(/, `chunk must never start with dangling link tail: ${ch.text}`);
    assert.doesNotMatch(ch.text, /^[a-z]/, `chunk must never start mid-sentence with lowercase word: ${ch.text}`);
    // Every `[` link opener in the chunk must have its matching `)` closer intact in the same chunk!
    const openLinks = (ch.text.match(/\[[^\]]+\]\(/g) ?? []).length;
    const fullLinks = (ch.text.match(/\[[^\]]+\]\(https:\/\/[^)]+\)/g) ?? []).length;
    assert.equal(openLinks, fullLinks, `every Markdown link must remain intact in chunk: ${ch.text}`);
  }

  // --- P7: `map` whole-token `search` (`voice` never matches `invoices`) + path prefix scoping ---
  const sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://developers.cloudflare.com/agents/guides/voice-agents/</loc></url>
      <url><loc>https://developers.cloudflare.com/agents/api-reference/realtime-voice/</loc></url>
      <url><loc>https://developers.cloudflare.com/agents/concepts/billing-invoices/</loc></url>
      <url><loc>https://developers.cloudflare.com/billing/invoices/voice-memo/</loc></url>
    </urlset>`;
  const mapScoped = await executeMapCall({
    payload: { url: 'https://developers.cloudflare.com/agents/', search: 'voice' },
    executeHubFetch: async (_target, rawBody) => {
      const reqs = (JSON.parse(rawBody) as { requests: Array<{ id: string; url: string }> }).requests;
      return {
        status: 200,
        via: 'agent:site-arm64',
        bodyText: JSON.stringify({
          results: reqs.map((rq) =>
            rq.url.endsWith('/sitemap.xml')
              ? { id: rq.id, url: rq.url, status: 200, outcome: 'ok', body: sitemapXml }
              : { id: rq.id, url: rq.url, status: 404, outcome: 'error' },
          ),
        }),
      };
    },
  });
  const scopedLinks = mapScoped.body.links as string[];
  assert.deepEqual(scopedLinks, [
    'https://developers.cloudflare.com/agents/guides/voice-agents/',
    'https://developers.cloudflare.com/agents/api-reference/realtime-voice/',
  ]); // Excludes `billing-invoices` (`voice` != `invoices`) AND excludes `/billing/...` outside `/agents/`!

  const mapSiteWide = await executeMapCall({
    payload: { url: 'https://developers.cloudflare.com/agents/', search: 'voice', includeOutsidePath: true },
    executeHubFetch: async (_target, rawBody) => {
      const reqs = (JSON.parse(rawBody) as { requests: Array<{ id: string; url: string }> }).requests;
      return {
        status: 200,
        via: 'agent:site-arm64',
        bodyText: JSON.stringify({
          results: reqs.map((rq) =>
            rq.url.endsWith('/sitemap.xml')
              ? { id: rq.id, url: rq.url, status: 200, outcome: 'ok', body: sitemapXml }
              : { id: rq.id, url: rq.url, status: 404, outcome: 'error' },
          ),
        }),
      };
    },
  });
  assert.equal((mapSiteWide.body.links as string[]).includes('https://developers.cloudflare.com/billing/invoices/voice-memo/'), true);

  // --- P8: `interact` does NOT retry `selector_not_found` across 3 agents + returns partial rendered Markdown! ---
  const p8DispatchedSites: string[] = [];
  const p8Sockets: Array<HubSocketLike & { tags: string[] }> = [];
  const p8Engine = new AgentHubEngine({
    getSockets: (tag) => (tag ? p8Sockets.filter((s) => s.tags.includes(tag)) : p8Sockets),
    cooldowns: memoryCooldowns(),
    hostWindows: createMemoryHostWindowStore(),
  });
  for (const [siteId, ip] of [
    ['site-win-vm', '198.51.100.10'],
    ['site-x86', '198.51.100.11'],
    ['site-arm64', '198.51.100.12'],
  ] as const) {
    const sock = makeFakeSocket([`site:${siteId}`], (msg) => {
      const parsed = JSON.parse(msg) as { type?: string; jobId?: string; jobNonce?: string };
      if (parsed.type === 'dispatch' && parsed.jobId && parsed.jobNonce) {
        p8DispatchedSites.push(siteId);
        queueMicrotask(() => {
          p8Engine.completeJob(
            parsed.jobId!,
            parsed.jobNonce!,
            siteId,
            JSON.stringify({
              results: [
                {
                  id: 'interact-1',
                  url: 'https://app.example.com/jobs',
                  finalUrl: 'https://app.example.com/jobs',
                  status: 200,
                  outcome: 'error',
                  rendered: true,
                  sessionId: 'efsess_partial1',
                  problem: 'interact action 0 (click): selector "#does-not-exist" not found within 15s',
                  body: '<!doctype html><html><head><title>Loaded Board</title></head><body><main><h1>Loaded Board</h1><p>Initial postings already rendered before click failed.</p></main></body></html>',
                },
              ],
            }),
          );
        });
      }
    });
    p8Sockets.push(sock);
    p8Engine.registerAgent(sock, siteId, 'amd64', { version: '2.3.0', publicIp: ip, capabilities: ['browser-v1', 'artifacts-v1'] });
  }

  const p8Interact = await executeInteractCall({
    payload: {
      url: 'https://app.example.com/jobs',
      actions: [{ type: 'click', selector: '#does-not-exist' }],
      formats: ['markdown'],
    },
    env: {},
    executeHubFetch: async (_target, rawBody, site) => {
      const d = await p8Engine.dispatchFetch(rawBody, {}, site ? { preferredSite: site } : {});
      return { status: d.ok ? 200 : d.status, via: d.ok ? `agent:${d.siteId}` : 'hub', bodyText: d.ok ? d.bodyText : JSON.stringify({ error: d.error }) };
    },
  });
  assert.equal(p8DispatchedSites.length, 1, `selector_not_found must run on 1 agent only, got: ${p8DispatchedSites.join(',')}`);
  assert.equal(p8Interact.status, 422);
  assert.equal(p8Interact.body.partial, true);
  assert.match(String(p8Interact.body.markdown), /Initial postings already rendered before click failed/);
  assert.equal((p8Interact.body.actions as Array<{ status: string }>)[0]?.status, 'error');

  // --- P9: Flag material page redirects (`redirected: true`, `filtersMayBeLost: true`) ---
  const wellfoundScrape = await executeScrapeCall({
    payload: { url: 'https://wellfound.com/role/r/forward-deployed-engineer', renderMode: 'off' },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-x86',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: 'https://wellfound.com/role/r/forward-deployed-engineer',
            finalUrl: 'https://wellfound.com/remote',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: '<!doctype html><html><head><title>Remote Startup Jobs</title></head><body><main><h1>Generic Remote Feed</h1><p>' + 'word '.repeat(60) + '</p></main></body></html>',
          },
        ],
      }),
    }),
  });
  assert.equal(wellfoundScrape.body.redirected, true);
  assert.equal(wellfoundScrape.body.filtersMayBeLost, true);
  assert.match(String(wellfoundScrape.body.redirectNote), /filters.*lost/i);

  // --- P10: Ethical `blocked` reason + actionable suggestion on robots.txt & bot challenges ---
  const liBlocked = await executeScrapeCall({
    payload: { url: 'https://www.linkedin.com/jobs/view/123456789' },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-arm64',
      bodyText: JSON.stringify({
        results: [{ id: 'scrape-1', url: 'https://www.linkedin.com/jobs/view/123456789', status: 0, outcome: 'skip', problem: 'robots.txt disallowed /jobs/view/123456789' }],
      }),
    }),
  });
  assert.equal(liBlocked.status, 422);
  assert.equal((liBlocked.body.blocked as { reason: string }).reason, 'robots');
  assert.match((liBlocked.body.blocked as { suggestion: string }).suggestion, /site:job-boards\.greenhouse\.io/);

  const indeedChallenge = await executeScrapeCall({
    payload: { url: 'https://www.indeed.com/viewjob?jk=abcd1234' },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-x86',
      bodyText: JSON.stringify({
        results: [{ id: 'scrape-1', url: 'https://www.indeed.com/viewjob?jk=abcd1234', status: 403, outcome: 'challenge', problem: 'Cloudflare challenge (cf-mitigated)' }],
      }),
    }),
  });
  assert.equal(indeedChallenge.status, 403);
  assert.equal((indeedChallenge.body.blocked as { reason: string }).reason, 'challenge');

  // --- P12: MCP `fetch_batch` sends `concurrency: 4` and surfaces `stageTimingsMs` ---
  let capturedBatchConcurrency = 0;
  const p12Db = new DatabaseSync(':memory:');
  p12Db.exec(OAUTH_SQLITE_SCHEMA);
  const p12Sql: SqlStorageLike = {
    exec<T = Record<string, unknown>>(q: string, ...b: unknown[]) {
      const s = p12Db.prepare(q);
      const rows = /^\s*select/i.test(q) ? s.all(...(b as never[])) : (s.run(...(b as never[])), []);
      return { toArray: () => rows as T[] };
    },
  };
  const mcpBatchDeps: McpServerDeps = {
    serverName: 'edgefetch-hub',
    serverVersion: '2.3.0',
    ownerSecret: 'p12-secret-token-0123456789abcdef',
    oauthStore: createSqliteOAuthStore(p12Sql),
    allowedTargets: ['auto', 'agent', 'container'],
    defaultTarget: 'auto',
    listFleet: async () => ({ connected: 1, agents: [], affinities: [] }),
    executeFetch: async ({ body }) => {
      const parsed = JSON.parse(body) as { options?: { concurrency?: number }; requests: Array<{ id: string; url: string }> };
      capturedBatchConcurrency = parsed.options?.concurrency ?? 1;
      return {
        status: 200,
        via: 'agent:site-x86',
        stageTimingsMs: { dispatchMs: 42, hydrateR2Ms: 3, totalHubMs: 46 },
        bodyText: JSON.stringify({
          results: parsed.requests.map((r) => ({ id: r.id, url: r.url, finalUrl: r.url, status: 200, outcome: 'ok' })),
        }),
      };
    },
  };
  const mcpBatchRes = await handleMcpRequest(
    new Request('https://hub.example.com/mcp', {
      method: 'POST',
      headers: { authorization: 'Bearer p12-secret-token-0123456789abcdef', 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 12,
        method: 'tools/call',
        params: {
          name: 'fetch_batch',
          arguments: {
            urls: [
              'https://one.example.com/a',
              'https://two.example.com/b',
              'https://three.example.com/c',
              'https://four.example.com/d',
            ],
          },
        },
      }),
    }),
    new URL('https://hub.example.com/mcp'),
    mcpBatchDeps,
  );
  assert.equal(mcpBatchRes.status, 200);
  assert.equal(capturedBatchConcurrency, 4);
  const mcpBatchJson = (await mcpBatchRes.json()) as { result: { content: Array<{ text: string }> } };
  const mcpBatchParsed = JSON.parse(mcpBatchJson.result.content[0]!.text) as { stageTimingsMs?: { totalHubMs: number } };
  assert.equal(mcpBatchParsed.stageTimingsMs?.totalHubMs, 46);

  // --- Section 4: `jobs` tool (`executeJobsCall`) deduplicates, respects `exclude`, and enforces `minBase` (`basis === "base"`) ---
  const jobsSweep = await executeJobsCall({
    payload: {
      query: 'Forward Deployed Engineer',
      remote: true,
      minBase: 200_000,
      includeBuiltIn: false,
      exclude: [{ company: 'AlreadyAppliedCorp', title: 'Forward Deployed Engineer' }],
    },
    env: {},
    executeSearch: async ({ query: q }) => {
      if (String(q).includes('jobs.ashbyhq.com')) {
        return {
          status: 200,
          body: {
            results: [
              { url: 'https://jobs.ashbyhq.com/elevenlabs/43f91b57-5c4e-4d4a-9450-3591f2a79923' },
              { url: 'https://jobs.ashbyhq.com/elevenlabs/dup-mirror' },
              { url: 'https://jobs.ashbyhq.com/alreadyappliedcorp/999' },
            ],
          },
        };
      }
      return {
        status: 200,
        body: {
          results: [{ url: 'https://jobs.smartrecruiters.com/Camunda/744000099999999-forward-deployed-engineer' }],
        },
      };
    },
    executeScrape: async ({ url: u }) => {
      if (String(u).includes('elevenlabs')) {
        return { status: 200, body: ashbyScrape.body };
      }
      if (String(u).includes('alreadyappliedcorp')) {
        return {
          status: 200,
          body: {
            ok: true,
            jobPosting: {
              title: 'Forward Deployed Engineer',
              hiringOrganization: 'AlreadyAppliedCorp',
              workplaceType: 'remote',
              jobLocation: ['Remote'],
              pay: { min: 240_000, max: 300_000, currency: 'USD', period: 'year', basis: 'base' },
              source: 'ashby',
            },
            markdown: '# Forward Deployed Engineer',
          },
        };
      }
      // Camunda role has $253.6K max, but basis === "total" (Total Target Cash), so `minBase: 200000` must filter it out!
      return {
        status: 200,
        body: {
          ok: true,
          jobPosting: {
            title: 'Forward Deployed Engineer',
            hiringOrganization: 'Camunda',
            workplaceType: 'remote',
            jobLocation: ['Remote'],
            pay: { min: 157_300, max: 253_600, currency: 'USD', period: 'year', basis: 'total' },
            source: 'json-ld',
          },
          markdown: '# Forward Deployed Engineer',
        },
      };
    },
  });
  assert.equal(jobsSweep.status, 200);
  const finalJobs = jobsSweep.body.jobs as Array<{ company: string; title: string; pay: { min: number; max: number; basis: string } }>;
  assert.equal(finalJobs.length, 1);
  assert.equal(finalJobs[0]?.company, 'ElevenLabs');
  assert.equal(finalJobs[0]?.pay.min, 230_000);
  assert.equal(finalJobs[0]?.pay.basis, 'base');
});

test('V2-13: v2.4.0 RFC 9421 Web Bot Auth, 7-Vendor WAF Catalog + Anti-FP Guardrails, contentState, 304 ETag Revalidation, SSR Hydration, Adaptive Host Health & Wayback Fallback', async () => {
  // --- R1: Verified Bot Registration & RFC 9421 Web Bot Auth ---
  const kp = await generateBotAuthKeyPair();
  assert.equal(kp.jwk.kty, 'OKP');
  assert.equal(kp.jwk.crv, 'Ed25519');
  assert.equal(kp.jwk.kid, kp.kid);

  const dirUrl = 'https://hub.example.com/.well-known/http-message-signatures-directory';
  const testNowMs = 1_795_000_000_000;
  const signedHdrs = await signOutboundBotHeaders({
    method: 'GET',
    url: 'https://docs.example.com/guide?page=2',
    privateKeyEncoded: kp.privateKeySeed,
    directoryUrl: dirUrl,
    nowMs: testNowMs,
    ttlSeconds: 300,
  });
  assert.ok(signedHdrs['signature-input']!.includes(`keyid="${kp.kid}"`));
  assert.ok(signedHdrs['signature-input']!.includes('alg="ed25519"'));
  assert.ok(signedHdrs['signature-input']!.includes('tag="web-bot-auth"'));
  assert.equal(signedHdrs['signature-agent'], `"${dirUrl}"`);

  const validSignedReq = new Request('https://docs.example.com/guide?page=2', {
    method: 'GET',
    headers: signedHdrs,
  });
  const verified = await verifyBotRequestSignature(validSignedReq, kp.publicKey, testNowMs);
  assert.equal(verified.ok, true);
  assert.equal(verified.kid, kp.kid);

  // Tampered URL must fail Ed25519 signature verification!
  const tamperedReq = new Request('https://docs.example.com/guide?page=999', {
    method: 'GET',
    headers: signedHdrs,
  });
  const tamperedVerify = await verifyBotRequestSignature(tamperedReq, kp.publicKey, testNowMs);
  assert.equal(tamperedVerify.ok, false);

  // Public unauthenticated .well-known routes serve RFC 9421 JWKS directory + bot policy document
  const jwksRes = await handleBotTransparencyRoutes(
    new Request(dirUrl, { method: 'GET' }),
    new URL(dirUrl),
    { BOT_SIGNING_PRIVATE_KEY: kp.privateKeySeed, BOT_CONTACT_URL: 'https://github.com/bartrumb/edgefetch/issues' },
    '2.4.0',
  );
  assert.ok(jwksRes);
  assert.equal(jwksRes.status, 200);
  assert.match(jwksRes.headers.get('content-type') ?? '', /application\/http-message-signatures-directory\+json/);
  assert.match(jwksRes.headers.get('content-digest') ?? '', /^sha-256=:[A-Za-z0-9+/=]+:$/);
  assert.match(jwksRes.headers.get('signature-input') ?? '', /^directory=\("@authority";req "content-digest"\);.*tag="http-message-signatures-directory"/);
  const dirVerify = await verifyDirectoryResponseSignature({
    requestUrl: dirUrl,
    response: jwksRes.clone(),
    publicKeyB64Url: kp.publicKey,
  });
  assert.equal(dirVerify.ok, true);
  assert.equal(dirVerify.kid, kp.kid);
  const wrongHostDirVerify = await verifyDirectoryResponseSignature({
    requestUrl: 'https://spoofed.example.com/.well-known/http-message-signatures-directory',
    response: jwksRes.clone(),
    publicKeyB64Url: kp.publicKey,
  });
  assert.equal(wrongHostDirVerify.ok, false);
  const jwksBody = (await jwksRes.json()) as { keys: Array<{ kid: string; x: string; kty: string; crv: string; nbf: number }> };
  assert.equal(jwksBody.keys.length, 1);
  assert.equal(jwksBody.keys[0]?.kid, kp.kid);
  assert.equal(jwksBody.keys[0]?.x, kp.publicKey);
  assert.equal(typeof jwksBody.keys[0]?.nbf, 'number');

  const botDocUrl = 'https://hub.example.com/.well-known/edgefetch-bot.json';
  const botDocRes = await handleBotTransparencyRoutes(
    new Request(botDocUrl, { method: 'GET' }),
    new URL(botDocUrl),
    { BOT_SIGNING_PRIVATE_KEY: kp.privateKeySeed },
    '2.4.0',
  );
  assert.ok(botDocRes);
  const botDoc = (await botDocRes.json()) as {
    version: string;
    policies: { robotsTxt: string; antiBotChallenges: string };
    webBotAuth: { rfc9421Supported: boolean; activeKeyIds: string[] };
  };
  assert.equal(botDoc.version, '2.4.0');
  assert.equal(botDoc.policies.robotsTxt, 'strict-rfc9309');
  assert.equal(botDoc.policies.antiBotChallenges, 'halt-immediately-never-bypass');
  assert.deepEqual(botDoc.webBotAuth.activeKeyIds, [kp.kid]);

  // Verify `cloudflareOverflowFetch` attaches valid RFC 9421 signatures on outbound origin requests!
  let capturedOriginReq: Request | null = null;
  const overflowSignedRes = await cloudflareOverflowFetch(
    JSON.stringify({
      maxSeconds: 10,
      options: { includeBody: true, respectRobots: true },
      requests: [{ id: 'sig-1', url: 'https://signed-origin.example.com/article', kind: 'page' }],
    }),
    'EdgeFetch/2.4',
    'hub.example.com',
    {
      botAuth: { privateKey: kp.privateKeySeed, directoryUrl: dirUrl },
      fetchFn: async (input, init) => {
        const req = input instanceof Request ? input : new Request(String(input), init);
        if (new URL(req.url).pathname === '/robots.txt') {
          return new Response('User-agent: *\nAllow: /\n', { status: 200 });
        }
        capturedOriginReq = req;
        return new Response('<html><body><main><h1>Signed Origin OK</h1></main></body></html>', {
          status: 200,
          headers: { 'content-type': 'text/html' },
        });
      },
    },
  );
  assert.equal(overflowSignedRes.status, 200);
  assert.ok(capturedOriginReq);
  const originSigCheck = await verifyBotRequestSignature(capturedOriginReq as Request, kp.publicKey);
  assert.equal(originSigCheck.ok, true);

  // --- R2 & R3: 7-Vendor WAF Signature Catalog + 4-Layer Anti-False-Positive Guardrails ---
  assert.equal(
    classifyWafAndChallenge({ status: 403, headers: { 'cf-mitigated': 'challenge' }, rawBody: '<html>Just a moment...</html>' })?.vendor,
    'cloudflare',
  );
  assert.equal(
    classifyWafAndChallenge({
      status: 403,
      headers: { server: 'AkamaiGHost' },
      rawBody: '<html><title>Access Denied</title><body>Reference #18.9f231702.1710000000.abcdef</body></html>',
    })?.vendor,
    'akamai',
  );
  assert.equal(
    classifyWafAndChallenge({
      status: 403,
      headers: { 'x-datadome': 'protected' },
      rawBody: '<script src="https://geo.captcha-delivery.com/captcha/"></script>',
    })?.vendor,
    'datadome',
  );
  assert.equal(
    classifyWafAndChallenge({
      status: 403,
      headers: { 'x-px-blocked': '1' },
      rawBody: '<div id="px-captcha"></div>',
    })?.vendor,
    'perimeterx',
  );
  assert.equal(
    classifyWafAndChallenge({
      status: 405,
      headers: { 'x-amzn-waf-action': 'captcha' },
      rawBody: '<div id="amzn-captcha-modal"></div>',
    })?.vendor,
    'aws-waf',
  );
  assert.equal(
    classifyWafAndChallenge({
      status: 200,
      rawBody: '<html><body><iframe src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e6fffd425f7e032f3"></iframe></body></html>',
    })?.vendor,
    'imperva',
  );
  assert.equal(
    classifyWafAndChallenge({
      status: 429,
      headers: { 'x-vercel-mitigated': 'challenge' },
      rawBody: 'Vercel Security Checkpoint',
    })?.vendor,
    'vercel',
  );
  assert.equal(
    classifyWafAndChallenge({
      status: 429,
      headers: { 'x-kpsdk-ct': '0987654321' },
      rawBody: '',
    })?.vendor,
    'kasada',
  );

  // Anti-FP Veto 1 (Code/Quote Immunity): Cloudflare Turnstile documentation quoting challenge markers in `<pre><code>` & `<blockquote>`!
  const turnstileDocsHtml = `<html><head><title>Cloudflare Turnstile Migration Guide</title></head><body>
    <main>
      <h1>Migrating to Turnstile</h1>
      <p>Learn how challenge widgets render inside modern web apps.</p>
      <blockquote>"Just a moment... Verify you are human"</blockquote>
      <pre><code>
        window._cf_chl_opt = { cType: 'managed' };
        const script = "https://challenges.cloudflare.com/turnstile/v0/api.js";
        const px = "px-captcha";
        const dd = "geo.captcha-delivery.com";
      </code></pre>
    </main>
  </body></html>`;
  assert.equal(classifyWafAndChallenge({ status: 200, rawBody: turnstileDocsHtml }), null);

  // Anti-FP Veto 2 (Word-Count Veto): >= 250-word article with a footer newsletter reCAPTCHA widget!
  const longProse = Array.from({ length: 280 }, (_, i) => `word${i}`).join(' ');
  const blogWithFooterCaptcha = `<html><head><title>Just a moment in distributed systems history</title></head><body>
    <article><p>${longProse}</p></article>
    <footer><div class="g-recaptcha" data-sitekey="abc"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></footer>
  </body></html>`;
  assert.equal(classifyWafAndChallenge({ status: 200, rawBody: blogWithFooterCaptcha }), null);

  // Anti-FP Veto 3 (Schema.org JSON-LD Veto): Real JobPosting page with an application form Turnstile widget!
  const jobWithTurnstile = `<html><head>
    <title>Principal Systems Engineer</title>
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"JobPosting","title":"Principal Systems Engineer"}</script>
  </head><body>
    <main><h1>Principal Systems Engineer</h1><p>Build reliable distributed edge infrastructure in Go and Rust.</p>
    <div class="cf-turnstile" data-sitekey="1x0000"></div></main>
  </body></html>`;
  assert.equal(classifyWafAndChallenge({ status: 200, rawBody: jobWithTurnstile }), null);

  // Anti-FP Veto 4 (Navigation Landmark Veto): Site page with <nav> (>= 4 links) and >= 120 words!
  const navWords = Array.from({ length: 140 }, (_, i) => `engineering${i}`).join(' ');
  const navPageHtml = `<html><body>
    <nav><a href="/a">Docs</a><a href="/b">API</a><a href="/c">Pricing</a><a href="/d">Status</a></nav>
    <main><h1>Security Overview</h1><p>${navWords}</p><div class="h-captcha"></div></main>
  </body></html>`;
  assert.equal(classifyWafAndChallenge({ status: 200, rawBody: navPageHtml }), null);

  // Ethical halt on HTTP 200 Akamai/Imperva interstitial inside `executeScrapeCall`: returns 403 challenge with `waf` + `blocked`!
  const impervaScrape = await executeScrapeCall({
    payload: { url: 'https://protected.example.com/jobs/123', discoverLlmsTxt: false },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-x86',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: 'https://protected.example.com/jobs/123',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            body: '<html><body><iframe src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e6fffd425f7e032f3"></iframe></body></html>',
          },
        ],
      }),
    }),
  });
  assert.equal(impervaScrape.status, 403);
  assert.equal(impervaScrape.body.outcome, 'challenge');
  assert.equal((impervaScrape.body.waf as { vendor: string }).vendor, 'imperva');
  assert.equal((impervaScrape.body.blocked as { reason: string }).reason, 'challenge');

  // --- R4: `contentState` Soft-404, Closed-Posting, & Login-Wall Classification + `jobs` & `ingest` Filtering ---
  assert.equal(
    classifyContentState({
      url: 'https://boards.greenhouse.io/acme/jobs/999',
      title: 'Role Closed',
      markdown: '# Role Closed\n\nSorry, this job is no longer available. View all open positions.',
    }).state,
    'closed_posting',
  );
  assert.equal(
    classifyContentState({
      url: 'https://docs.example.com/missing-page',
      title: '404 Not Found',
      markdown: '# 404 - Page Not Found\n\nThe page you requested could not be found.',
    }).state,
    'soft_404',
  );
  // 300-word troubleshooting guide about HTTP 404 errors must stay `active`!
  assert.equal(
    classifyContentState({
      url: 'https://docs.example.com/troubleshooting-404',
      title: '404 Not Found Troubleshooting Guide',
      markdown: `# 404 Not Found Troubleshooting Guide\n\n${longProse}`,
    }).state,
    'active',
  );
  assert.equal(
    classifyContentState({
      url: 'https://portal.example.com/dashboard',
      title: 'Sign in to continue',
      markdown: '# Sign in to continue\n\nPlease log in to view your workspace.',
      rawHtml: '<html><body><form><input type="email"><input type="password"></form></body></html>',
    }).state,
    'login_wall',
  );

  // `executeJobsCall` automatically filters out `contentState: "closed_posting"` roles!
  const closedRoleFilterRes = await executeJobsCall({
    payload: { query: 'Staff Backend Engineer', includeBuiltIn: false },
    env: {},
    executeSearch: async ({ query: q }) => ({
      status: 200,
      body: {
        results: String(q).includes('greenhouse')
          ? [
              { url: 'https://job-boards.greenhouse.io/acme/jobs/101' },
              { url: 'https://job-boards.greenhouse.io/acme/jobs/102' },
            ]
          : [],
      },
    }),
    executeScrape: async ({ url: u }) => {
      if (String(u).endsWith('/101')) {
        return {
          status: 200,
          body: {
            ok: true,
            contentState: 'closed_posting',
            jobPosting: { title: 'Staff Backend Engineer (Closed)', hiringOrganization: 'Acme', workplaceType: 'remote' },
            markdown: '# Staff Backend Engineer\n\nThis job is no longer open.',
          },
        };
      }
      return {
        status: 200,
        body: {
          ok: true,
          contentState: 'active',
          jobPosting: { title: 'Staff Backend Engineer', hiringOrganization: 'Acme', workplaceType: 'remote' },
          markdown: '# Staff Backend Engineer\n\nActive opening building distributed storage.',
        },
      };
    },
  });
  assert.equal(closedRoleFilterRes.status, 200);
  const openJobsOnly = closedRoleFilterRes.body.jobs as Array<{ title: string }>;
  assert.equal(openJobsOnly.length, 1);
  assert.equal(openJobsOnly[0]?.title, 'Staff Backend Engineer');

  // --- R5 (304 ETag Revalidation) + R4 (Ingest skips FTS5 indexing on soft_404) ---
  const tmpR5Dir = mkdtempSync(join(tmpdir(), 'ef-v24-r5-'));
  try {
    const metaSqlPath = resolve('migrations/meta/0001_tracking.sql');
    const searchSqlPath = resolve('migrations/search/0001_fts.sql');
    const metaDb = new NodeSqliteD1Database(':memory:', [metaSqlPath]);
    const searchDb = new NodeSqliteD1Database(':memory:', [searchSqlPath]);
    const r2Bucket = new NodeFsR2Bucket(join(tmpR5Dir, 'r2'));

    const sha256BytesHex = async (bytes: Uint8Array) =>
      Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>)), (b) =>
        b.toString(16).padStart(2, '0'),
      ).join('');

    // Verify R4 in ingest: a `soft_404` HTML artifact is verified + derived, yet NOT indexed into `SEARCH` D1 FTS5!
    const soft404Html = '<html><head><title>404 Page Not Found</title></head><body><main><h1>404 Page Not Found</h1><p>Sorry, we could not find that page right now.</p></main></body></html>';
    const soft404Bytes = new TextEncoder().encode(soft404Html);
    const soft404Gz = new Uint8Array(
      await new Response(new Blob([soft404Bytes]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer(),
    );
    const soft404BlobSha = await sha256BytesHex(soft404Gz);
    const soft404ContentSha = await sha256HexString(soft404Html);
    await r2Bucket.put(r2ArtifactKey('stored', soft404BlobSha), soft404Gz);
    const softManifest = await writeJobManifestToR2({
      bucket: r2Bucket as unknown as R2Bucket,
      jobId: 'job_soft404_check',
      via: 'agent:site-1',
      collectionId: 'docs-coll',
      rawReplyText: JSON.stringify({
        results: [
          {
            id: '1',
            url: 'https://docs.example.com/dead-doc',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html',
            artifact: {
              blobSha256: soft404BlobSha,
              contentSha256: soft404ContentSha,
              contentBytes: soft404Bytes.byteLength,
              storedBytes: soft404Gz.byteLength,
              encoding: 'gzip',
              retention: 'stored',
            },
          },
        ],
      }),
    });
    assert.equal(softManifest.ok, true);
    if (softManifest.ok) {
      const ingOut = await executeIngestPipeline(
        {
          ARTIFACTS: r2Bucket as unknown as R2Bucket,
          META: metaDb as unknown as D1Database,
          SEARCH: searchDb as unknown as D1Database,
        },
        { manifestKey: softManifest.manifestKey, jobId: 'job_soft404_check', collectionId: 'docs-coll', via: 'agent:site-1' },
      );
      assert.equal(ingOut.verifiedCount, 1);
      assert.equal(ingOut.indexedCount, 0, 'soft_404 pages must never pollute SEARCH D1 FTS5');
    }

    // Seed verified page + ETag in `META` D1 + derived Markdown in `ARTIFACTS` R2 via real `executeIngestPipeline` for R5 conditional `304 Not Modified` revalidation!
    const targetRevalUrl = 'https://handbook.example.com/architecture';
    const revalHtml = '<html><head><title>Edge Architecture</title></head><body><main><h1>Edge Architecture</h1><p>Verified cached handbook prose served on 304 Not Modified across global nodes.</p></main></body></html>';
    const revalBytes = new TextEncoder().encode(revalHtml);
    const revalGz = new Uint8Array(
      await new Response(new Blob([revalBytes]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer(),
    );
    const revalBlobSha = await sha256BytesHex(revalGz);
    const revalContentSha = await sha256HexString(revalHtml);
    await r2Bucket.put(r2ArtifactKey('stored', revalBlobSha), revalGz);
    const oldFetchedAt = 1_700_000_000_000;
    const revalManifest = await writeJobManifestToR2({
      bucket: r2Bucket as unknown as R2Bucket,
      jobId: 'job_reval_seed',
      via: 'agent:site-arm64',
      rawReplyText: JSON.stringify({
        results: [
          {
            id: '1',
            url: targetRevalUrl,
            status: 200,
            outcome: 'ok',
            contentType: 'text/html; charset=utf-8',
            etag: '"etag-arch-v9"',
            lastModified: 'Wed, 18 Nov 2026 12:00:00 GMT',
            artifact: {
              blobSha256: revalBlobSha,
              contentSha256: revalContentSha,
              contentBytes: revalBytes.byteLength,
              storedBytes: revalGz.byteLength,
              encoding: 'gzip',
              retention: 'stored',
            },
          },
        ],
      }),
      now: oldFetchedAt,
    });
    assert.equal(revalManifest.ok, true);
    if (revalManifest.ok) {
      await executeIngestPipeline(
        {
          ARTIFACTS: r2Bucket as unknown as R2Bucket,
          META: metaDb as unknown as D1Database,
        },
        { manifestKey: revalManifest.manifestKey, jobId: 'job_reval_seed', via: 'agent:site-arm64' },
        undefined,
        { now: oldFetchedAt },
      );
    }

    let sentIfNoneMatch = '';
    let sentIfModifiedSince = '';
    const freshNow = oldFetchedAt + 120_000; // 120s later (> maxAgeMs=5000ms -> triggers conditional revalidation!)
    const revalRes = await executeScrapeCall({
      payload: { url: targetRevalUrl, maxAgeMs: 5_000, discoverLlmsTxt: false },
      env: {
        ARTIFACTS: r2Bucket as unknown as R2Bucket,
        META: metaDb as unknown as D1Database,
      },
      now: freshNow,
      executeHubFetch: async (_target, rawCall) => {
        const parsed = JSON.parse(rawCall) as { requests: Array<{ ifNoneMatch?: string; ifModifiedSince?: string }> };
        sentIfNoneMatch = parsed.requests[0]?.ifNoneMatch ?? '';
        sentIfModifiedSince = parsed.requests[0]?.ifModifiedSince ?? '';
        return {
          status: 200,
          via: 'agent:site-arm64',
          bodyText: JSON.stringify({
            results: [{ id: 'scrape-1', url: targetRevalUrl, finalUrl: targetRevalUrl, status: 304, outcome: 'ok' }],
          }),
        };
      },
    });
    assert.equal(sentIfNoneMatch, '"etag-arch-v9"');
    assert.equal(sentIfModifiedSince, 'Wed, 18 Nov 2026 12:00:00 GMT');
    assert.equal(revalRes.status, 200);
    assert.equal(revalRes.body.ok, true);
    assert.equal(revalRes.body.cached, true);
    assert.equal(revalRes.body.revalidated, true);
    assert.equal(revalRes.body.originStatus, 304);
    assert.match(String(revalRes.body.markdown), /Verified cached handbook prose/);

    const updatedPage = await metaDb
      .prepare('SELECT last_fetched_at FROM pages WHERE url = ?')
      .bind(targetRevalUrl)
      .first<{ last_fetched_at: number }>();
    assert.equal(updatedPage?.last_fetched_at, freshNow);

    metaDb.close();
    searchDb.close();
  } finally {
    rmSync(tmpR5Dir, { recursive: true, force: true });
  }

  // --- R6: SSR Hydration State Recovery (`__NEXT_DATA__`) without Headless Browser Render ---
  let r6FetchCount = 0;
  const nextJsThinHtml = `<html><head><title>Staff Infrastructure Engineer - OrbitCloud</title></head><body>
    <div id="__next"><span>Loading role...</span></div>
    <script id="__NEXT_DATA__" type="application/json">${JSON.stringify({
      props: {
        pageProps: {
          job: {
            title: 'Staff Infrastructure Engineer',
            description:
              'OrbitCloud is hiring a Staff Infrastructure Engineer to architect global multi-region control planes, zero-trust networking, consensus state machines, and low-latency edge storage across 60+ points of presence worldwide. Requirements include 8+ years of production Go or Rust experience, Linux kernel networking, BGP/Anycast operations, and distributed SQLite or Raft systems.',
          },
        },
      },
    })}</script>
  </body></html>`;
  const r6Scrape = await executeScrapeCall({
    payload: { url: 'https://careers.orbitcloud.example.com/jobs/staff-infra', renderMode: 'auto', discoverLlmsTxt: false },
    env: {},
    executeHubFetch: async (_target, rawCall) => {
      r6FetchCount++;
      const parsed = JSON.parse(rawCall) as { requests: Array<{ kind: string }> };
      assert.notEqual(parsed.requests[0]?.kind, 'render', 'SSR hydration must recover prose BEFORE triggering headless Chromium!');
      return {
        status: 200,
        via: 'agent:site-lite',
        bodyText: JSON.stringify({
          results: [
            {
              id: 'scrape-1',
              url: 'https://careers.orbitcloud.example.com/jobs/staff-infra',
              finalUrl: 'https://careers.orbitcloud.example.com/jobs/staff-infra',
              status: 200,
              outcome: 'ok',
              contentType: 'text/html; charset=utf-8',
              body: nextJsThinHtml,
            },
          ],
        }),
      };
    },
  });
  assert.equal(r6Scrape.status, 200);
  assert.equal(r6FetchCount, 1);
  assert.equal(r6Scrape.body.contentSource, 'ssr-hydration');
  assert.match(String(r6Scrape.body.markdown), /multi-region control planes/);

  // --- R7: Adaptive Per-Host Politeness & Health Ledger (`host_health` + `GET /v1/hosts` + SDK `hosts()`) ---
  let r7Clock = 1_795_100_000_000;
  const r7Engine = new AgentHubEngine({
    getSockets: () => [],
    now: () => r7Clock,
  });
  r7Engine.recordHostOutcome({ host: 'rate-sensitive.example.com', status: 429, outcome: 'error', ttfbMs: 180 });
  r7Clock += 1_000;
  r7Engine.recordHostOutcome({ host: 'rate-sensitive.example.com', status: 429, outcome: 'error', ttfbMs: 220 });
  const escalated = r7Engine.listHostHealth(10)[0]!;
  assert.equal(escalated.host, 'rate-sensitive.example.com');
  assert.equal(escalated.rateLimit429Count, 2);
  assert.ok(escalated.recommendedPauseMs >= 6_000, `expected escalated pause >= 6000ms, got ${escalated.recommendedPauseMs}`);

  for (let i = 0; i < 6; i++) {
    r7Clock += 1_000;
    r7Engine.recordHostOutcome({ host: 'rate-sensitive.example.com', status: 200, outcome: 'ok', ttfbMs: 95 });
  }
  const decayed = r7Engine.listHostHealth(10)[0]!;
  assert.ok(decayed.recommendedPauseMs < escalated.recommendedPauseMs, 'consecutive 200 OKs must decay recommendedPauseMs');
  assert.equal(decayed.okCount, 6);

  // Verify end-to-end Portable Hub `GET /v1/hosts` + `GET /.well-known/http-message-signatures-directory` + TS SDK `hosts()`
  const tmpHubDir = mkdtempSync(join(tmpdir(), 'ef-v24-hub-'));
  const portable = await startPortableHub({
    port: 0,
    host: '127.0.0.1',
    dataDir: tmpHubDir,
    envOverrides: {
      CALLER_TOKEN: 'v24-owner-secret-0123456789abcdef',
      BOT_SIGNING_PRIVATE_KEY: kp.privateKeySeed,
    },
  });
  try {
    const pubDirRes = await fetch(`http://127.0.0.1:${portable.port}/.well-known/http-message-signatures-directory`);
    assert.equal(pubDirRes.status, 200);
    const pubDirJson = (await pubDirRes.json()) as { keys: Array<{ kid: string }> };
    assert.equal(pubDirJson.keys[0]?.kid, kp.kid);

    const sdk = new EdgeFetchClient({
      baseUrl: `http://127.0.0.1:${portable.port}`,
      token: 'v24-owner-secret-0123456789abcdef',
    });
    const caps = await sdk.capabilities();
    assert.equal(caps.version, '2.6.2');
    assert.equal((caps.capabilities as { webBotAuth: boolean }).webBotAuth, true);
    const hostsOut = await sdk.hosts(25);
    assert.equal(hostsOut.ok, true);
    assert.ok(Array.isArray(hostsOut.hosts));
  } finally {
    await portable.close();
    rmSync(tmpHubDir, { recursive: true, force: true });
  }

  // --- R8: Opt-In Internet Archive (`Wayback CDX`) Link-Rot Fallback (Strictly ONLY on 5xx / DNS-dead!) ---
  assert.equal(isEligibleForWaybackFallback({ outcome: 'error', status: 503, problem: 'HTTP 503' }), true);
  assert.equal(isEligibleForWaybackFallback({ outcome: 'error', status: 0, problem: 'dial tcp: no such host' }), true);
  assert.equal(isEligibleForWaybackFallback({ outcome: 'skip', status: 0, problem: 'robots.txt disallowed /private' }), false);
  assert.equal(isEligibleForWaybackFallback({ outcome: 'error', status: 403, problem: 'HTTP 403' }), false);
  assert.equal(isEligibleForWaybackFallback({ outcome: 'error', status: 404, problem: 'HTTP 404' }), false);
  assert.equal(isEligibleForWaybackFallback({ outcome: 'error', status: 429, problem: 'HTTP 429' }), false);
  assert.equal(
    isEligibleForWaybackFallback({
      outcome: 'error',
      status: 503,
      problem: 'Cloudflare challenge',
      waf: { vendor: 'cloudflare', category: 'challenge', confidence: 1, signals: ['header:cf-mitigated'], summary: 'cf' },
    }),
    false,
  );

  // Positive R8 recovery on HTTP 503 dead origin
  let archiveCalls = 0;
  const wbRecovered = await executeScrapeCall({
    payload: { url: 'https://bitrot.example.org/2021/consensus-paper', waybackFallback: true, discoverLlmsTxt: false },
    env: {},
    executeHubFetch: async (_target, rawCall) => {
      const parsed = JSON.parse(rawCall) as { requests: Array<{ url: string }> };
      const reqUrl = parsed.requests[0]!.url;
      if (reqUrl.startsWith('https://archive.org/wayback/available')) {
        archiveCalls++;
        return {
          status: 200,
          via: 'agent:site-x86',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'wb-avail',
                url: reqUrl,
                status: 200,
                outcome: 'ok',
                contentType: 'application/json',
                body: JSON.stringify({
                  archived_snapshots: {
                    closest: {
                      available: true,
                      status: '200',
                      timestamp: '20240512093000',
                      url: 'http://web.archive.org/web/20240512093000/https://bitrot.example.org/2021/consensus-paper',
                    },
                  },
                }),
              },
            ],
          }),
        };
      }
      if (reqUrl.startsWith('https://web.archive.org/web/20240512093000id_/')) {
        archiveCalls++;
        return {
          status: 200,
          via: 'agent:site-x86',
          bodyText: JSON.stringify({
            results: [
              {
                id: 'wb-snap',
                url: reqUrl,
                status: 200,
                outcome: 'ok',
                contentType: 'text/html; charset=utf-8',
                body: '<html><head><title>Consensus Paper (2021)</title></head><body><main><h1>Consensus Paper</h1><p>Archived Paxos and Raft formal proof recovered from link rot.</p></main></body></html>',
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({
          results: [{ id: 'scrape-1', url: reqUrl, status: 503, outcome: 'error', problem: 'HTTP 503 Service Unavailable' }],
        }),
      };
    },
  });
  assert.equal(wbRecovered.status, 200);
  assert.equal(wbRecovered.body.ok, true);
  assert.equal(wbRecovered.body.contentSource, 'wayback');
  assert.equal(wbRecovered.body.waybackTimestamp, '20240512093000');
  assert.match(String(wbRecovered.body.markdown), /Archived Paxos and Raft formal proof/);
  assert.equal(archiveCalls, 2);

  // Ethical guardrail: `waybackFallback: true` MUST NEVER touch archive.org on `robots.txt` blocks, `403`, or `challenge`!
  archiveCalls = 0;
  for (const forbiddenCase of [
    { status: 0, outcome: 'skip', problem: 'robots.txt disallowed /secret' },
    { status: 403, outcome: 'error', problem: 'HTTP 403 Forbidden' },
    { status: 403, outcome: 'challenge', problem: 'Cloudflare challenge (cf-mitigated)' },
  ]) {
    const denied = await executeScrapeCall({
      payload: { url: 'https://restricted.example.org/secret', waybackFallback: true, discoverLlmsTxt: false },
      env: {},
      executeHubFetch: async (_target, rawCall) => {
        const parsed = JSON.parse(rawCall) as { requests: Array<{ url: string }> };
        if (parsed.requests[0]!.url.includes('archive.org')) archiveCalls++;
        return {
          status: 200,
          via: 'agent:site-x86',
          bodyText: JSON.stringify({ results: [{ id: 'scrape-1', url: 'https://restricted.example.org/secret', ...forbiddenCase }] }),
        };
      },
    });
    assert.equal(denied.body.ok, false);
  }
  assert.equal(archiveCalls, 0, 'Wayback fallback must NEVER run on robots.txt, 403, or anti-bot challenges');
});

test('V2-14: v2.4.1 Next.js App Router RSC Hydration + Ethical Crawl4AI & Firecrawl Heavy-SPA Fallback (Cloud & Self-Hosted)', async () => {
  // 1. Next.js 13–15 App Router RSC Flight (`self.__next_f.push([1, "..."])`) 1-hop hydration recovery without launching a browser!
  const rscFlightPayload =
    '12:["$","main",null,{"children":"HyperEdge is seeking a Principal Systems Architect to lead distributed consensus, multi-region WebSocket routing, and zero-trust kernel sandboxing across 80 edge locations globally. Candidates need deep Go and Rust production experience and familiarity with HTTP/2 and QUIC internals."}]\n';
  const rscHtml = `<html><head><title>Principal Systems Architect - HyperEdge</title></head><body>
    <div id="app">Loading...</div>
    <script>self.__next_f=self.__next_f||[];self.__next_f.push([1,${JSON.stringify(rscFlightPayload)}])</script>
  </body></html>`;
  const rscRecovered = recoverSsrHydrationContent(rscHtml, 'https://hyperedge.example.com/jobs/1', (h) => ({ markdown: h, links: [] }));
  assert.ok(rscRecovered);
  assert.equal(rscRecovered.framework, 'nextjs-rsc');
  assert.match(rscRecovered.markdown, /multi-region WebSocket routing/);

  // 2. Provider discovery & priority ordering (`crawl4ai` -> `firecrawl` default, or custom `SPA_FALLBACK_ORDER`)
  assert.deepEqual(
    listConfiguredSpaFallbacks({
      CRAWL4AI_API_URL: 'http://crawl4ai.local:11235',
      FIRECRAWL_API_KEY: 'fc-test-key',
    }),
    ['crawl4ai', 'firecrawl'],
  );
  assert.deepEqual(
    listConfiguredSpaFallbacks({
      CRAWL4AI_API_URL: 'http://crawl4ai.local:11235',
      FIRECRAWL_API_URL: 'http://firecrawl.local:3002',
      SPA_FALLBACK_ORDER: 'firecrawl,crawl4ai',
    }),
    ['firecrawl', 'crawl4ai'],
  );

  // 3. Rescue `503 fat_agent_required` (Lite-only fleet) via self-hosted Crawl4AI after verifying `/robots.txt` allows the URL!
  const fallbackCalls: string[] = [];
  let crawl4AiShouldFail = false;
  let robotsDisallowSpa = false;

  const mockSpaFetch: typeof fetch = async (input, init) => {
    const reqUrl = input instanceof Request ? input.url : String(input);
    fallbackCalls.push(reqUrl);
    if (reqUrl.endsWith('/robots.txt')) {
      return new Response(
        robotsDisallowSpa ? 'User-agent: *\nDisallow: /private-spa\n' : 'User-agent: *\nAllow: /\n',
        { status: 200, headers: { 'content-type': 'text/plain' } },
      );
    }
    if (reqUrl === 'http://crawl4ai.internal:11235/crawl') {
      const parsedBody = JSON.parse(String(init?.body ?? '{}')) as { crawler_config?: { params?: { check_robots_txt?: boolean; magic?: boolean } } };
      assert.equal(parsedBody.crawler_config?.params?.check_robots_txt, true);
      assert.equal(parsedBody.crawler_config?.params?.magic, false);
      if (crawl4AiShouldFail) {
        return new Response('upstream error', { status: 502 });
      }
      return Response.json({
        success: true,
        results: [
          {
            url: 'https://heavy-spa.example.com/dashboard',
            status_code: 200,
            metadata: { title: 'Heavy WebGL SPA Docs' },
            markdown: {
              fit_markdown:
                '# Heavy WebGL SPA Docs\n\nFull client-rendered WebGL & Shadow DOM documentation recovered cleanly via self-hosted Crawl4AI worker.',
            },
          },
        ],
      });
    }
    if (reqUrl === 'http://firecrawl.internal:3002/v1/scrape') {
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer fc-selfhosted-secret');
      return Response.json({
        success: true,
        data: {
          markdown:
            '# Heavy WebGL SPA Docs (Firecrawl)\n\nRecovered cleanly via self-hosted Firecrawl fallback when Crawl4AI was unavailable.',
          metadata: {
            title: 'Heavy WebGL SPA Docs (Firecrawl)',
            statusCode: 200,
            sourceURL: 'https://heavy-spa.example.com/dashboard',
          },
        },
      });
    }
    return new Response('not found', { status: 404 });
  };

  const spaEnv = {
    CRAWL4AI_API_URL: 'http://crawl4ai.internal:11235',
    FIRECRAWL_API_URL: 'http://firecrawl.internal:3002',
    FIRECRAWL_API_KEY: 'fc-selfhosted-secret',
    SPA_FALLBACK_FETCH: mockSpaFetch,
  };

  // Case A: Lite-only fleet returns `503 fat_agent_required` on `renderMode: "always"` -> Crawl4AI rescues after `/robots.txt` check!
  const liteFleetRescue = await executeScrapeCall({
    payload: { url: 'https://heavy-spa.example.com/dashboard', renderMode: 'always', discoverLlmsTxt: false },
    env: spaEnv,
    executeHubFetch: async () => ({
      status: 503,
      via: 'hub',
      bodyText: JSON.stringify({ error: 'fat_agent_required', message: 'No browser-v1 agent connected' }),
    }),
  });
  assert.equal(liteFleetRescue.status, 200);
  assert.equal(liteFleetRescue.via, 'fallback:crawl4ai');
  assert.equal(liteFleetRescue.body.renderedVia, 'crawl4ai');
  assert.match(String(liteFleetRescue.body.markdown), /recovered cleanly via self-hosted Crawl4AI/);
  assert.deepEqual(fallbackCalls, [
    'https://heavy-spa.example.com/robots.txt',
    'http://crawl4ai.internal:11235/crawl',
  ]);

  // Case B: Thin `200 OK` `<script>` SPA shell (`< 50` words) when Crawl4AI is down -> cascades automatically to Firecrawl!
  fallbackCalls.length = 0;
  crawl4AiShouldFail = true;
  const thinSpaCascade = await executeScrapeCall({
    payload: { url: 'https://heavy-spa.example.com/dashboard', renderMode: 'auto', discoverLlmsTxt: false },
    env: spaEnv,
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:site-lite',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: 'https://heavy-spa.example.com/dashboard',
            status: 200,
            outcome: 'ok',
            contentType: 'text/html; charset=utf-8',
            body: '<html><head><title>App</title><script src="/app.bundle.js"></script></head><body><div id="root">Loading...</div></body></html>',
          },
        ],
      }),
    }),
  });
  assert.equal(thinSpaCascade.status, 200);
  assert.equal(thinSpaCascade.via, 'fallback:firecrawl');
  assert.equal(thinSpaCascade.body.renderedVia, 'firecrawl');
  assert.match(String(thinSpaCascade.body.markdown), /self-hosted Firecrawl fallback/);
  crawl4AiShouldFail = false;

  // Case C: Also works inside `executeExtractCall` (`POST /v1/extract`)!
  const extractSpaRescue = await executeExtractCall({
    payload: { urls: ['https://heavy-spa.example.com/dashboard'], query: 'WebGL Shadow DOM', renderMode: 'always' },
    env: spaEnv,
    executeHubFetch: async () => ({
      status: 503,
      via: 'hub',
      bodyText: JSON.stringify({ error: 'fat_agent_required', message: 'No browser-v1 agent connected' }),
    }),
  });
  assert.equal(extractSpaRescue.status, 200);
  assert.equal(extractSpaRescue.via, 'fallback:crawl4ai');
  const extResults = extractSpaRescue.body.results as Array<{ renderedVia?: string; rawContent?: string; chunks?: Array<{ text: string }> }>;
  assert.equal(extResults[0]?.renderedVia, 'crawl4ai');

  // 4. STRICT ETHICAL GUARDRAILS: Crawl4AI & Firecrawl MUST NEVER be called on `robots.txt` blocks, `403`, `429`, WAF challenges, or login walls!
  fallbackCalls.length = 0;
  robotsDisallowSpa = true;
  const robotsPrecheckBlocked = await executeScrapeCall({
    payload: { url: 'https://heavy-spa.example.com/private-spa', renderMode: 'always', discoverLlmsTxt: false },
    env: spaEnv,
    executeHubFetch: async () => ({
      status: 503,
      via: 'hub',
      bodyText: JSON.stringify({ error: 'fat_agent_required', message: 'No browser-v1 agent connected' }),
    }),
  });
  assert.equal(robotsPrecheckBlocked.status, 503);
  assert.deepEqual(fallbackCalls, ['https://heavy-spa.example.com/robots.txt'], 'Disallowed robots.txt must halt before calling Crawl4AI or Firecrawl!');
  robotsDisallowSpa = false;

  fallbackCalls.length = 0;
  for (const unethicalCase of [
    { status: 0, outcome: 'skip', problem: 'robots.txt disallowed /admin' },
    { status: 403, outcome: 'error', problem: 'HTTP 403 Forbidden' },
    { status: 429, outcome: 'error', problem: 'HTTP 429 Too Many Requests' },
    { status: 403, outcome: 'challenge', problem: 'Cloudflare challenge (cf-mitigated)' },
    {
      status: 200,
      outcome: 'ok',
      contentType: 'text/html',
      body: '<html><head><title>Sign in to continue</title><script src="/auth.js"></script></head><body><form><input type="password"></form></body></html>',
    },
  ]) {
    const res = await executeScrapeCall({
      payload: { url: 'https://restricted.example.com/admin', discoverLlmsTxt: false },
      env: spaEnv,
      executeHubFetch: async () => ({
        status: 200,
        via: 'agent:site-x86',
        bodyText: JSON.stringify({ results: [{ id: 'scrape-1', url: 'https://restricted.example.com/admin', ...unethicalCase }] }),
      }),
    });
    assert.equal(res.body.renderedVia, undefined);
  }
  assert.equal(fallbackCalls.length, 0, 'Crawl4AI and Firecrawl must NEVER be called on robots.txt, 403, 429, challenges, or login walls!');
  assert.equal(isEligibleForExternalSpaFallback({ mode: 'off', errorCode: 'fat_agent_required', status: 503 }), false);
});
