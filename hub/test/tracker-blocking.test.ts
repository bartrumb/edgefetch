import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import meta0001 from '../migrations/meta/0001_tracking.sql';
import worker from '../src/index';
import { buildOpenApiSpec } from '../src/openapi';
import { MCP_TOOL_SCHEMAS } from '../src/mcp';
import { NodeFsR2Bucket, NodeSqliteD1Database, LocalAgentHubCoordinator } from './stubs/cf-storage-mocks';
import {
  EASYPRIVACY_SOURCE_URL,
  EASYPRIVACY_LICENCE_URL,
  refreshHubTrackerList,
  loadStoredTrackerList,
  buildTrackerListWsFrames,
} from '../src/tracker-list';
import { AgentHubEngine } from '../src/agent-hub';
import { buildCrawlChildSpans } from '../src/otel';
import { buildCrawlActivityEvents } from '../src/activity-log';
import { executeJobsCall, resetJobsCacheForTests } from '../src/jobs';
import { executeCatalogCall, getCatalogRecords, resetCatalogStateForTests } from '../src/catalog';

const OWNER_TOKEN = 'ef_owner_tracker_test_secret_token_0123456789';
const AGENT_TOKEN = 'ef_agent_tracker_test_secret_token_0123456789';

/**
 * Generates a deterministic offline EasyPrivacy fixture (>= 200 KB and >= 5,000 plain `||host^` rules by default)
 * with realistic ignored syntax (paths, `$` options, `@@` exceptions, wildcards, cosmetic rules, IP literals, dotless hosts).
 */
function buildEasyPrivacyFixture(opts: {
  version?: string;
  lastModified?: string;
  titleLine?: string;
  includeVersionLine?: boolean;
  hostCount?: number;
  extraHosts?: string[];
  padCommentBytes?: number;
} = {}): string {
  const {
    version = '2026112401',
    lastModified = '24 Nov 2026 04:00 UTC',
    titleLine = '! Title: EasyPrivacy',
    includeVersionLine = true,
    hostCount = 6_500,
    extraHosts = [],
    padCommentBytes = 120_000,
  } = opts;

  const lines: string[] = ['[Adblock Plus 2.0]'];
  if (titleLine) lines.push(titleLine);
  if (includeVersionLine) lines.push(`! Version: ${version}`);
  if (lastModified) lines.push(`! Last modified: ${lastModified}`);
  lines.push('! Expires: 4 days (update frequency)');
  lines.push('! Homepage: https://easylist.to/');
  lines.push(`! Licence: ${EASYPRIVACY_LICENCE_URL}`);

  // Ignored syntax lines that MUST be skipped by the strict `^\|\|[a-z0-9.-]+\^$` parser:
  lines.push('||tracker-with-path.example.com/collect.js^');
  lines.push('||tracker-with-opt.example.com^$third-party,script');
  lines.push('@@||exception-host.example.com^');
  lines.push('||wildcard-*.example.com^');
  lines.push('example.com##.ad-beacon');
  lines.push('/collect?tid=*');
  lines.push('||198.51.100.42^');
  lines.push('||127.0.0.1^');
  lines.push('||localhost^');
  lines.push('||dotlesshost^');
  lines.push('||-badlabel.example.com^');
  lines.push('||badlabel-.example.com^');
  lines.push('||com^');
  lines.push('||co.uk^');
  lines.push('||github.io^');

  for (let i = 0; i < hostCount; i++) {
    lines.push(`||trk-${String(i).padStart(5, '0')}.analytics-fixture.net^`);
  }
  lines.push('||TrailingDot.Tracker-Fixture.org.^');
  for (const h of extraHosts) {
    lines.push(`||${h}^`);
  }

  let body = lines.join('\n') + '\n';
  if (body.length < padCommentBytes + 220_000) {
    const needed = 230_000 - body.length;
    if (needed > 0) {
      const chunk = '! ' + 'x'.repeat(96) + '\n';
      body += chunk.repeat(Math.ceil(needed / chunk.length));
    }
  }
  return body;
}

test('Acceptance 1 & 2: Valid EasyPrivacy fixture loads + 304 ETag no-op + 6h poll guard; invalid fixtures rejected keeping previous list', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'ef-tracker-acc12-'));
  try {
    const bucket = new NodeFsR2Bucket(join(tmp, 'r2'));
    let fetchCalls = 0;
    let lastReqHeaders: Headers | null = null;
    let responder: (req: Request) => Response | Promise<Response> = () =>
      new Response('unexpected', { status: 500 });

    const fetchStub: typeof fetch = async (input, init) => {
      fetchCalls++;
      const req = input instanceof Request ? input : new Request(String(input), init);
      lastReqHeaders = new Headers(req.headers);
      return responder(req);
    };

    // --- Acceptance 2 (part A): With NO previous good list, every invalid fixture is rejected and blocking stays off ---
    const invalidFixtures: Array<{ name: string; makeResponse: () => Response }> = [
      {
        name: 'HTML instead of text/plain',
        makeResponse: () =>
          new Response('<!doctype html><html><body>Captive Portal</body></html>'.repeat(5_000), {
            status: 200,
            headers: { 'content-type': 'text/html; charset=utf-8' },
          }),
      },
      {
        name: 'Truncated (< 200 KB and < 5,000 hosts)',
        makeResponse: () =>
          new Response(
            '[Adblock Plus 2.0]\n! Title: EasyPrivacy\n! Version: 2026112400\n||tiny.tracker.net^\n',
            { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } },
          ),
      },
      {
        name: 'Oversized (> 10 MB)',
        makeResponse: () =>
          new Response(
            '[Adblock Plus 2.0]\n! Title: EasyPrivacy\n! Version: 2026112400\n' + 'x'.repeat(10 * 1024 * 1024 + 4096),
            { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } },
          ),
      },
      {
        name: 'Missing ! Title: EasyPrivacy header',
        makeResponse: () =>
          new Response(
            buildEasyPrivacyFixture({ titleLine: '! Title: WrongList', version: '2026112400' }),
            { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } },
          ),
      },
      {
        name: 'Missing ! Version: header',
        makeResponse: () =>
          new Response(
            buildEasyPrivacyFixture({ includeVersionLine: false }),
            { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } },
          ),
      },
    ];

    let virtualNow = 1_760_000_000_000;
    for (const inv of invalidFixtures) {
      responder = inv.makeResponse;
      const res = await refreshHubTrackerList({
        bucket,
        fetchFn: fetchStub,
        now: virtualNow,
      });
      assert.equal(res.updated, false, `Expected invalid fixture (${inv.name}) to be rejected`);
      assert.equal(res.current, null, `With no previous list, active list must stay null after ${inv.name}`);
      const storedNull = await loadStoredTrackerList(bucket);
      assert.equal(storedNull, null);
      // Advance virtual clock by > 6h so the 6-hour retry guard allows the next fixture test
      virtualNow += 6 * 60 * 60_000 + 1_000;
    }

    // --- Acceptance 1: Valid fixture loads; hostCount and version are recorded; 304 ETag makes no state change ---
    const validBodyV1 = buildEasyPrivacyFixture({
      version: '2026112401',
      lastModified: '24 Nov 2026 04:00 UTC',
      hostCount: 6_500,
    });
    assert.ok(Buffer.byteLength(validBodyV1, 'utf8') >= 200 * 1024);

    responder = () =>
      new Response(validBodyV1, {
        status: 200,
        headers: {
          'content-type': 'text/plain; charset=utf-8',
          etag: '"ep-v1-etag"',
          'last-modified': 'Tue, 24 Nov 2026 04:00:00 GMT',
        },
      });

    const loadedV1 = await refreshHubTrackerList({
      bucket,
      fetchFn: fetchStub,
      now: virtualNow,
    });
    assert.equal(loadedV1.updated, true);
    assert.ok(loadedV1.current);
    assert.equal(loadedV1.current.meta.version, '2026112401');
    // 6,500 generated + 1 trailing-dot normalized host = 6,501 valid hosts (all path/$/@@/*/cosmetic/IP/dotless/bare-PSL skipped)
    assert.equal(loadedV1.current.meta.hostCount, 6_501);
    assert.ok(loadedV1.current.hosts.includes('trailingdot.tracker-fixture.org'));
    assert.ok(!loadedV1.current.hosts.includes('tracker-with-path.example.com'));
    assert.ok(!loadedV1.current.hosts.includes('tracker-with-opt.example.com'));
    assert.ok(!loadedV1.current.hosts.includes('exception-host.example.com'));
    assert.ok((lastReqHeaders?.get('user-agent') ?? '').startsWith('EdgeFetch/'));

    // Polling again within < 6 hours must NOT make any outbound HTTP request!
    const callsBeforeRateLimitCheck = fetchCalls;
    const skippedEarly = await refreshHubTrackerList({
      bucket,
      fetchFn: fetchStub,
      now: virtualNow + 2 * 60 * 60_000,
    });
    assert.equal(fetchCalls, callsBeforeRateLimitCheck, 'Must never poll more often than every 6 hours');
    assert.equal(skippedEarly.updated, false);
    assert.equal(skippedEarly.current?.meta.version, '2026112401');

    // Second fetch after >= 6h with matching ETag -> conditional request sends If-None-Match & If-Modified-Since -> 304 Not Modified -> no state change!
    virtualNow += 24 * 60 * 60_000;
    responder = (req) => {
      assert.equal(req.headers.get('if-none-match'), '"ep-v1-etag"');
      assert.equal(req.headers.get('if-modified-since'), 'Tue, 24 Nov 2026 04:00:00 GMT');
      return new Response(null, { status: 304, headers: { etag: '"ep-v1-etag"' } });
    };
    const res304 = await refreshHubTrackerList({
      bucket,
      fetchFn: fetchStub,
      now: virtualNow,
    });
    assert.equal(res304.notModified, true);
    assert.equal(res304.updated, false);
    assert.equal(res304.current?.meta.version, '2026112401');
    assert.equal(res304.current?.meta.hostCount, 6_501);
    assert.equal(res304.current?.meta.sha256, loadedV1.current.meta.sha256);
    assert.equal(res304.current?.meta.fetchedAt, loadedV1.current.meta.fetchedAt);

    // --- Acceptance 2 (part B): Each invalid fixture (including a 50% host-count change!) is rejected and previous good list stays active ---
    const delta50Body = buildEasyPrivacyFixture({
      version: '2026112501',
      hostCount: 9_800, // +50.7% jump vs 6,501 (> 20% threshold)
    });
    const postValidInvalidCases: Array<{ name: string; makeResponse: () => Response }> = [
      ...invalidFixtures,
      {
        name: '50% host-count jump (> 20% delta)',
        makeResponse: () =>
          new Response(delta50Body, {
            status: 200,
            headers: { 'content-type': 'text/plain; charset=utf-8' },
          }),
      },
      {
        name: '50% host-count drop (> 20% delta)',
        makeResponse: () =>
          new Response(
            buildEasyPrivacyFixture({ version: '2026112502', hostCount: 5_050 }), // -22.3% drop vs 6,501 (> 20% threshold)
            { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } },
          ),
      },
    ];

    for (const bad of postValidInvalidCases) {
      virtualNow += 6 * 60 * 60_000 + 5_000;
      responder = bad.makeResponse;
      const attempt = await refreshHubTrackerList({
        bucket,
        fetchFn: fetchStub,
        now: virtualNow,
      });
      assert.equal(attempt.updated, false, `Expected ${bad.name} to be rejected`);
      assert.equal(attempt.current?.meta.version, '2026112401', `Previous good list must stay active after ${bad.name}`);
      assert.equal(attempt.current?.meta.hostCount, 6_501);

      // Even after a failed fetch, retry must NOT poll again within 6 hours!
      const callsAfterFail = fetchCalls;
      await refreshHubTrackerList({
        bucket,
        fetchFn: fetchStub,
        now: virtualNow + 60_000,
      });
      assert.equal(fetchCalls, callsAfterFail, `Retry after ${bad.name} must respect 6h minimum interval`);
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('Acceptance 4: Never-block allow-list strips bot-challenge/WAF, feature-flag/A-B SDKs, hub selfHost, and EDGEFETCH_PUBLIC_ORIGIN hosts', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'ef-tracker-acc4-'));
  try {
    const bucket = new NodeFsR2Bucket(join(tmp, 'r2'));
    const mustNeverBlock = [
      'challenges.cloudflare.com',
      'geo.captcha-delivery.com',
      'api-js.datadome.co',
      'client.perimeterx.net',
      'collector.px-cloud.net',
      'sensor.humansecurity.com',
      's.go-mpulse.net',
      'ds.akamaihd.net',
      'client-api.arkoselabs.com',
      'cdn.funcaptcha.com',
      'www.recaptcha.net',
      'js.hcaptcha.com',
      'newassets.hcaptcha.com',
      'app.launchdarkly.com',
      'cdn.optimizely.com',
      'api.statsig.com',
      'featureassets.org',
      'sdk.split.io',
      'cdn.growthbook.io',
      'my-hub.internal.example.com',
      'public-hub.edgefetch.example.org',
      'sub.public-hub.edgefetch.example.org',
    ];

    const raw = buildEasyPrivacyFixture({
      version: '2026112499',
      hostCount: 6_000,
      extraHosts: [...mustNeverBlock, 'real-session-replay.evil-tracker.com'],
    });

    const loaded = await refreshHubTrackerList({
      bucket,
      selfHost: 'my-hub.internal.example.com',
      publicOrigin: 'https://public-hub.edgefetch.example.org',
      fetchFn: async () =>
        new Response(raw, {
          status: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        }),
      now: 1_760_000_000_000,
    });

    assert.equal(loaded.updated, true);
    assert.ok(loaded.current);
    const set = new Set(loaded.current.hosts);
    assert.ok(set.has('real-session-replay.evil-tracker.com'));
    for (const protectedHost of mustNeverBlock) {
      assert.equal(set.has(protectedHost), false, `Never-block host ${protectedHost} must be stripped from tracker list`);
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('Acceptance 5, 6 & 7: EDGEFETCH_TRACKER_LIST=off makes zero requests; startup never fetches; WS connect/reconnect + update pushes version; blockTrackers:false, /admin owner-only & list_agents wired', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'ef-tracker-acc567-'));
  try {
    // --- Schema checks: MCP tools & OpenAPI 3.1.0 expose `blockTrackers` on `scrape` and `interact` ---
    assert.equal(MCP_TOOL_SCHEMAS.scrape?.properties?.blockTrackers?.type, 'boolean');
    assert.equal(MCP_TOOL_SCHEMAS.interact?.properties?.blockTrackers?.type, 'boolean');
    const spec = buildOpenApiSpec({ origin: 'https://hub.example.com' }) as {
      components: { schemas: Record<string, { properties?: Record<string, unknown> }> };
    };
    assert.ok(spec.components.schemas.ScrapeRequest?.properties?.blockTrackers);
    assert.ok(spec.components.schemas.InteractRequest?.properties?.blockTrackers);

    // --- Acceptance 6: With daily fetch disabled (`EDGEFETCH_TRACKER_LIST=off`), Cloudflare scheduled(), Portable Hub, and Deno Hub make ZERO requests ---
    let disabledFetchCalls = 0;
    const disabledFetchStub: typeof fetch = async () => {
      disabledFetchCalls++;
      return new Response('should never be called', { status: 500 });
    };

    const cfBucket = new NodeFsR2Bucket(join(tmp, 'cf-off'));
    const cfCoordinator = new LocalAgentHubCoordinator(join(tmp, 'cf-off.sqlite'));
    const waitUntilPromises: Promise<unknown>[] = [];
    await worker.scheduled!(
      { cron: '0 4 * * *', scheduledTime: Date.now(), noRetry() {} } as ScheduledController,
      {
        AGENT_HUB: cfCoordinator.asNamespace() as unknown as DurableObjectNamespace,
        ARTIFACTS: cfBucket as unknown as R2Bucket,
        SAFE_PUBLIC_FETCH: disabledFetchStub,
        EDGEFETCH_TRACKER_LIST: 'off',
      } as never,
      {
        waitUntil(p: Promise<unknown>) {
          waitUntilPromises.push(p);
        },
        passThroughOnException() {},
      } as unknown as ExecutionContext,
    );
    await Promise.all(waitUntilPromises);
    assert.equal(disabledFetchCalls, 0, 'Cloudflare scheduled() with EDGEFETCH_TRACKER_LIST=off must make 0 requests');
    cfCoordinator.close();

    // --- Worker Hub: verify ZERO fetch calls before scheduled(), then test live agent connect/reconnect + version update + /admin + scrape/interact ---
    let listFetchCalls = 0;
    let currentFixtureVersion = '2026112401';
    const liveBucket = new NodeFsR2Bucket(join(tmp, 'worker-live-r2'));
    const liveMetaDb = new NodeSqliteD1Database(':memory:', [{ name: 'meta/0001_tracking.sql', sql: meta0001 }]);
    const liveCoordinator = new LocalAgentHubCoordinator(join(tmp, 'worker-live.sqlite'));
    const baseUrl = 'https://hub.example.com';
    const liveEnv = {
      AGENT_HUB: liveCoordinator.asNamespace() as unknown as DurableObjectNamespace,
      ARTIFACTS: liveBucket as unknown as R2Bucket,
      META: liveMetaDb as unknown as D1Database,
      CALLER_TOKEN: OWNER_TOKEN,
      AGENT_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
      SAFE_PUBLIC_FETCH: (async (input: RequestInfo | URL) => {
        const u = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        if (u === EASYPRIVACY_SOURCE_URL) {
          listFetchCalls++;
          return new Response(
            buildEasyPrivacyFixture({ version: currentFixtureVersion, hostCount: 6_100 }),
            {
              status: 200,
              headers: {
                'content-type': 'text/plain; charset=utf-8',
                etag: `"etag-${currentFixtureVersion}"`,
              },
            },
          );
        }
        return new Response('User-agent: *\nAllow: /\n', { status: 200 });
      }) as typeof fetch,
    };
    const dispatchWorker = (path: string, init?: RequestInit) =>
      worker.fetch(new Request(`${baseUrl}${path}`, init), liveEnv as never);

    try {
      assert.equal(listFetchCalls, 0, 'Worker Hub must NEVER fetch EasyPrivacy before scheduled()');

      // Trigger first scheduled refresh on the Worker Hub
      await worker.scheduled!(
        { cron: '0 4 * * *', scheduledTime: Date.now(), noRetry() {} } as ScheduledController,
        liveEnv as never,
      );
      assert.equal(listFetchCalls, 1);

      // Connect a simulated agent -> must immediately receive `tracker_list` v1 (`2026112401`)!
      const connectMockAgent = () => {
        const receivedTrackerVersions: string[] = [];
        const observedCrawlRequests: Array<Record<string, unknown>> = [];
        const handle = liveCoordinator.connectMockAgent({
          siteId: 'node-test-1',
          arch: 'amd64',
          version: '2.7.8',
          capabilities: 'http2,browser-v1,interact-v1',
          publicIp: '198.51.100.10',
          onServerMessage: (raw) => {
            const msg = JSON.parse(String(raw)) as Record<string, unknown>;
            if (msg.type === 'tracker_list' && typeof msg.version === 'string') {
              receivedTrackerVersions.push(msg.version);
              queueMicrotask(() => {
                handle.sendFromAgent(JSON.stringify({ type: 'tracker_list_ack', version: msg.version }));
              });
            } else if (
              msg.type === 'dispatch' &&
              typeof msg.jobId === 'string' &&
              typeof msg.jobNonce === 'string' &&
              msg.call &&
              typeof msg.call === 'object'
            ) {
              const call = msg.call as { requests: Array<Record<string, unknown>> };
              const firstReq = call.requests[0] ?? {};
              observedCrawlRequests.push(firstReq);
              const blockEnabled = firstReq.blockTrackers !== false;
              const reply = {
                results: [
                  {
                    id: firstReq.id,
                    url: firstReq.url,
                    finalUrl: firstReq.url || 'https://example.com/app',
                    kind: firstReq.kind,
                    outcome: 'ok',
                    status: 200,
                    rendered: true,
                    blockedTrackers: blockEnabled ? 3 : 0,
                    contentType: 'text/html; charset=utf-8',
                    body: '<!doctype html><html><head><title>SPA App</title></head><body><main><h1>Clean Content</h1></main></body></html>',
                    bodyEncoding: 'utf-8',
                  },
                ],
              };
              queueMicrotask(() => {
                void dispatchWorker('/agent/reply', {
                  method: 'POST',
                  headers: {
                    authorization: `Bearer ${AGENT_TOKEN}`,
                    'x-agent-site': 'node-test-1',
                    'x-job-id': String(msg.jobId),
                    'x-job-nonce': String(msg.jobNonce),
                    'content-type': 'application/json',
                  },
                  body: JSON.stringify(reply),
                });
              });
            }
          },
        });
        handle.sendFromAgent(
          JSON.stringify({
            type: 'agent_hello',
            version: '2.7.8',
            arch: 'amd64',
            goVersion: 'go1.27',
            capabilities: ['http2', 'browser-v1', 'interact-v1'],
          }),
        );

        const waitForVersion = async (want: string) => {
          for (let i = 0; i < 60; i++) {
            if (receivedTrackerVersions.includes(want)) return;
            await new Promise((r) => setTimeout(r, 10));
          }
          assert.fail(`Timed out waiting for agent to receive tracker_list ${want}; got ${JSON.stringify(receivedTrackerVersions)}`);
        };

        return { handle, receivedTrackerVersions, observedCrawlRequests, waitForVersion };
      };

      const agent1 = connectMockAgent();
      await agent1.waitForVersion('2026112401');

      // Verify `GET /agents` and MCP `list_agents` expose `trackerListVersion: "2026112401"`
      const agentsRes = await dispatchWorker('/agents', {
        headers: { authorization: `Bearer ${OWNER_TOKEN}` },
      });
      assert.equal(agentsRes.status, 200);
      const agentsJson = (await agentsRes.json()) as {
        trackerListVersion?: string | null;
        agents: Array<{ siteId: string; trackerListVersion?: string | null }>;
      };
      assert.equal(agentsJson.trackerListVersion, '2026112401');
      assert.equal(agentsJson.agents[0]?.trackerListVersion, '2026112401');

      const mcpListRes = await dispatchWorker('/mcp', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${OWNER_TOKEN}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'list_agents', arguments: {} },
        }),
      });
      assert.equal(mcpListRes.status, 200);
      const mcpListJson = (await mcpListRes.json()) as {
        result: { content: Array<{ text: string }> };
      };
      const mcpFleet = JSON.parse(mcpListJson.result.content[0]!.text) as {
        trackerListVersion?: string | null;
      };
      assert.equal(mcpFleet.trackerListVersion, '2026112401');

      // Acceptance 5: Default `scrape` (rendered) blocks trackers (`blockedTrackers: 3` in metadata), while `blockTrackers: false` disables blocking for THAT request only (`blockedTrackers: 0`)!
      const scrapeDefaultRes = await dispatchWorker('/v1/scrape', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://spa1.example.com/app', renderMode: 'always', noCache: true }),
      });
      assert.equal(scrapeDefaultRes.status, 200);
      const scrapeDefaultBody = (await scrapeDefaultRes.json()) as { metadata?: { blockedTrackers?: number } };
      assert.equal(scrapeDefaultBody.metadata?.blockedTrackers, 3);

      const scrapeOptOutRes = await dispatchWorker('/v1/scrape', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          url: 'https://spa2.example.com/app',
          renderMode: 'always',
          blockTrackers: false,
          noCache: true,
        }),
      });
      assert.equal(scrapeOptOutRes.status, 200);
      const scrapeOptOutBody = (await scrapeOptOutRes.json()) as { metadata?: { blockedTrackers?: number } };
      assert.equal(scrapeOptOutBody.metadata?.blockedTrackers, 0);
      assert.equal(agent1.observedCrawlRequests[1]?.blockTrackers, false);

      // Same per-request check on `/v1/interact`
      const interactOptOutRes = await dispatchWorker('/v1/interact', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://spa3.example.com/app', blockTrackers: false }),
      });
      assert.equal(interactOptOutRes.status, 200);
      const interactOptOutBody = (await interactOptOutRes.json()) as { metadata?: { blockedTrackers?: number } };
      assert.equal(interactOptOutBody.metadata?.blockedTrackers, 0);

      const interactDefaultRes = await dispatchWorker('/v1/interact', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://spa4.example.com/app' }),
      });
      assert.equal(interactDefaultRes.status, 200);
      const interactDefaultBody = (await interactDefaultRes.json()) as { metadata?: { blockedTrackers?: number } };
      assert.equal(interactDefaultBody.metadata?.blockedTrackers, 3);

      // Update list version on Hub -> connected agent receives new version `2026112501` live, AND reconnecting agent receives `2026112501`!
      currentFixtureVersion = '2026112501';
      const updatedOutcome = await refreshHubTrackerList({
        bucket: liveBucket,
        fetchFn: liveEnv.SAFE_PUBLIC_FETCH,
        now: Date.now() + 7 * 60 * 60_000,
      });
      assert.equal(updatedOutcome.updated, true);
      liveCoordinator.syncTrackerList(
        updatedOutcome.current!.meta.version,
        buildTrackerListWsFrames(updatedOutcome.current!),
      );
      await agent1.waitForVersion('2026112501');

      agent1.handle.close();

      const agentReconnected = connectMockAgent();
      await agentReconnected.waitForVersion('2026112501');

      // `/admin` owner session sees `trackerList` metadata (`version`, `fetchedAt`, `hostCount`, `sourceUrl`, `licenseUrl`) AND dashboard HTML links EasyPrivacy licence!
      const loginRes = await dispatchWorker('/admin/login', {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: baseUrl,
        },
        body: new URLSearchParams({ token: OWNER_TOKEN }).toString(),
      });
      assert.equal(loginRes.status, 302);
      const cookie = loginRes.headers.get('set-cookie')?.split(';')[0] ?? '';
      assert.ok(cookie.length > 10);

      const adminHtmlRes = await dispatchWorker('/admin', { headers: { cookie } });
      assert.equal(adminHtmlRes.status, 200);
      const adminHtml = await adminHtmlRes.text();
      assert.ok(adminHtml.includes(EASYPRIVACY_LICENCE_URL), 'Admin UI must link EasyPrivacy licence');
      assert.ok(adminHtml.includes(EASYPRIVACY_SOURCE_URL), 'Admin UI must show EasyPrivacy source URL');

      const stateRes = await dispatchWorker('/admin/api/state', { headers: { cookie } });
      assert.equal(stateRes.status, 200);
      const stateJson = (await stateRes.json()) as {
        trackerList?: {
          version: string | null;
          fetchedAt: number | null;
          hostCount: number;
          sourceUrl: string;
          licenseUrl: string;
        };
      };
      assert.ok(stateJson.trackerList);
      assert.equal(stateJson.trackerList.version, '2026112501');
      assert.equal(stateJson.trackerList.hostCount, 6_101);
      assert.equal(typeof stateJson.trackerList.fetchedAt, 'number');
      assert.equal(stateJson.trackerList.sourceUrl, EASYPRIVACY_SOURCE_URL);
      assert.equal(stateJson.trackerList.licenseUrl, EASYPRIVACY_LICENCE_URL);

      agentReconnected.handle.close();
    } finally {
      liveCoordinator.close();
      liveMetaDb.close();
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('Hardening & Perf Regressions: redirects, gunzip caps, multi-chunk WS, hibernation dedup, scrape/extract cache isolation & OTel/activity traces', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'ef-tracker-hardening-'));
  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown) => {
    unhandled.push(reason);
  };
  process.on('unhandledRejection', onUnhandled);

  try {
    // 1. Corrupt gzip, decompression cap, sha256 mismatch, and <5,000 lines on cold buckets -> null with ZERO unhandled rejections
    const corruptBucket = new NodeFsR2Bucket(join(tmp, 'r2-corrupt'));
    await corruptBucket.put(
      'system/tracker-list/meta.json',
      JSON.stringify({
        version: '2026112401',
        lastModified: null,
        etag: null,
        fetchedAt: Date.now(),
        hostCount: 6000,
        rawParsedHostCount: 6000,
        sha256: 'a'.repeat(64),
        sourceUrl: EASYPRIVACY_SOURCE_URL,
        licenseUrl: EASYPRIVACY_LICENCE_URL,
      }),
    );
    await corruptBucket.put('system/tracker-list/hosts.txt.gz', new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00]));
    assert.equal(await loadStoredTrackerList(corruptBucket), null);

    // Oversized decompression (> 16 MiB zeros gzipped) -> capped without unhandled rejection
    const bigZeroCs = new CompressionStream('gzip');
    const bigZeroWriter = bigZeroCs.writable.getWriter();
    const zeroChunk = new Uint8Array(1024 * 1024);
    void (async () => {
      for (let i = 0; i < 18; i++) {
        await bigZeroWriter.write(zeroChunk);
      }
      await bigZeroWriter.close();
    })().catch(() => undefined);
    const bigZeroGz = new Uint8Array(await new Response(bigZeroCs.readable).arrayBuffer());
    const bombBucket = new NodeFsR2Bucket(join(tmp, 'r2-bomb'));
    await bombBucket.put(
      'system/tracker-list/meta.json',
      JSON.stringify({
        version: '2026112401',
        lastModified: null,
        etag: null,
        fetchedAt: Date.now(),
        hostCount: 6000,
        rawParsedHostCount: 6000,
        sha256: 'b'.repeat(64),
        sourceUrl: EASYPRIVACY_SOURCE_URL,
        licenseUrl: EASYPRIVACY_LICENCE_URL,
      }),
    );
    await bombBucket.put('system/tracker-list/hosts.txt.gz', bigZeroGz);
    assert.equal(await loadStoredTrackerList(bombBucket), null);
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(unhandled.length, 0, `Expected 0 unhandled rejections, got ${unhandled.length}`);

    // 2. Redirect pinning (`redirect: 'manual'`), Content-Length cap, 304 without prior list, and fetchTimeoutMs abort
    let virtualNow = 1_760_500_000_000;
    const redirectBucket = new NodeFsR2Bucket(join(tmp, 'r2-redir'));

    // 304 without cached list -> rejected
    const resUnexpected304 = await refreshHubTrackerList({
      bucket: redirectBucket,
      now: virtualNow,
      fetchFn: async () => new Response(null, { status: 304 }),
    });
    assert.equal(resUnexpected304.ok, false);
    assert.equal(resUnexpected304.current, null);

    // 302 redirect to foreign host -> rejected
    virtualNow += 7 * 60 * 60_000;
    const resForeignRedir = await refreshHubTrackerList({
      bucket: redirectBucket,
      now: virtualNow,
      fetchFn: async () =>
        new Response(null, {
          status: 302,
          headers: { location: 'https://evil.example.com/easyprivacy.txt' },
        }),
    });
    assert.equal(resForeignRedir.ok, false);
    assert.match(resForeignRedir.reason ?? '', /disallowed redirect/);

    // 302 redirect to http:// scheme downgrade -> rejected
    virtualNow += 7 * 60 * 60_000;
    const resHttpRedir = await refreshHubTrackerList({
      bucket: redirectBucket,
      now: virtualNow,
      fetchFn: async () =>
        new Response(null, {
          status: 301,
          headers: { location: 'http://easylist.to/easylist/easyprivacy.txt' },
        }),
    });
    assert.equal(resHttpRedir.ok, false);
    assert.match(resHttpRedir.reason ?? '', /disallowed redirect/);

    // Content-Length > 10 MiB header -> rejected immediately
    virtualNow += 7 * 60 * 60_000;
    const resOversizeCl = await refreshHubTrackerList({
      bucket: redirectBucket,
      now: virtualNow,
      fetchFn: async () =>
        new Response('small', {
          status: 200,
          headers: {
            'content-type': 'text/plain',
            'content-length': String(12 * 1024 * 1024),
          },
        }),
    });
    assert.equal(resOversizeCl.ok, false);
    assert.match(resOversizeCl.reason ?? '', /content-length/);

    // Slow-loris stream aborted cleanly via fetchTimeoutMs
    virtualNow += 7 * 60 * 60_000;
    const resTimeout = await refreshHubTrackerList({
      bucket: redirectBucket,
      now: virtualNow,
      fetchTimeoutMs: 40,
      fetchFn: async (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new Error('aborted_by_timeout'));
          });
        }),
    });
    assert.equal(resTimeout.ok, false);
    assert.match(resTimeout.reason ?? '', /aborted_by_timeout/);

    // Same-host https://easylist.to redirect succeeds, and cold bucket reload avoids retaining 45k strings in heap cache
    virtualNow += 7 * 60 * 60_000;
    const validFixture = buildEasyPrivacyFixture({ version: '2026112405', hostCount: 5_500 });
    const resSameHostRedir = await refreshHubTrackerList({
      bucket: redirectBucket,
      now: virtualNow,
      fetchFn: async (input) => {
        const u = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        if (u === EASYPRIVACY_SOURCE_URL) {
          return new Response(null, {
            status: 302,
            headers: { location: 'https://easylist.to/mirror/easyprivacy.txt' },
          });
        }
        assert.equal(u, 'https://easylist.to/mirror/easyprivacy.txt');
        return new Response(validFixture, {
          status: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      },
    });
    assert.equal(resSameHostRedir.ok, true);
    assert.equal(resSameHostRedir.updated, true);

    const coldReloadBucket = new NodeFsR2Bucket(join(tmp, 'r2-redir'));
    const coldLoaded = await loadStoredTrackerList(coldReloadBucket);
    assert.ok(coldLoaded);
    assert.equal(coldLoaded.meta.version, '2026112405');
    assert.equal(coldLoaded.meta.hostCount, 5_501);
    assert.equal(coldLoaded.hosts.length, 0, 'Cold R2 load must keep compact gzipB64 without retaining 45k host strings');

    // 3. Multi-chunk `buildTrackerListWsFrames` when `hostsGzipB64.length > 700_000`
    const syntheticLarge = {
      meta: coldLoaded.meta,
      hosts: [],
      hostsGzipB64: 'A'.repeat(920_000),
    };
    const multiFrames = buildTrackerListWsFrames(syntheticLarge, ['hub.example.org']);
    assert.equal(multiFrames.length, 3);
    const f0 = JSON.parse(multiFrames[0]!) as Record<string, unknown>;
    const f2 = JSON.parse(multiFrames[2]!) as Record<string, unknown>;
    assert.equal(f0.type, 'tracker_list_chunk');
    assert.equal(f0.chunkIndex, 0);
    assert.equal(f0.totalChunks, 3);
    assert.deepEqual(f0.neverBlockHosts, ['hub.example.org']);
    assert.equal(f2.chunkIndex, 2);
    assert.equal(f2.neverBlockHosts, undefined);

    // 4. DO hibernation wakeup dedup: `AgentHubEngine.setTrackerListBroadcast` skips sockets already on `cleanVer`
    let socketAlreadySyncedSends = 0;
    let socketStaleSends = 0;
    let att1: unknown = null;
    let att2: unknown = null;
    const mockWsSynced = {
      readyState: 1,
      send() {
        socketAlreadySyncedSends++;
      },
      close() {},
      serializeAttachment(v: unknown) {
        att1 = v;
      },
      deserializeAttachment() {
        return att1;
      },
    };
    const mockWsStale = {
      readyState: 1,
      send() {
        socketStaleSends++;
      },
      close() {},
      serializeAttachment(v: unknown) {
        att2 = v;
      },
      deserializeAttachment() {
        return att2;
      },
    };
    const engine = new AgentHubEngine({
      getSockets: (tag) =>
        !tag
          ? [mockWsSynced, mockWsStale]
          : tag === 'site:site-a'
            ? [mockWsSynced]
            : tag === 'site:site-b'
              ? [mockWsStale]
              : [],
    });
    engine.registerAgent(mockWsSynced, 'site-a', 'amd64', { version: '2.7.8', capabilities: 'browser-v1' });
    engine.registerAgent(mockWsStale, 'site-b', 'amd64', { version: '2.7.8', capabilities: 'browser-v1' });
    engine.noteTrackerListAck(mockWsSynced, '2026112405');
    engine.setTrackerListBroadcast('2026112405', [JSON.stringify({ type: 'tracker_list', version: '2026112405' })]);
    assert.equal(socketAlreadySyncedSends, 0, 'Hibernated socket already on version must NOT receive duplicate 300KB broadcast');
    assert.equal(socketStaleSends, 1, 'Unsynced socket must receive broadcast');

    // 5. Scrape & Extract cache isolation when `blockTrackers: false` + OTel & crawl activity traces
    const cacheBucket = new NodeFsR2Bucket(join(tmp, 'worker-cache-r2'));
    const cacheMetaDb = new NodeSqliteD1Database(':memory:', [{ name: 'meta/0001_tracking.sql', sql: meta0001 }]);
    const cacheCoordinator = new LocalAgentHubCoordinator(join(tmp, 'worker-cache.sqlite'));
    const cacheBaseUrl = 'https://hub.example.com';
    const cacheEnv = {
      AGENT_HUB: cacheCoordinator.asNamespace() as unknown as DurableObjectNamespace,
      ARTIFACTS: cacheBucket as unknown as R2Bucket,
      META: cacheMetaDb as unknown as D1Database,
      CALLER_TOKEN: OWNER_TOKEN,
      AGENT_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
      SAFE_PUBLIC_FETCH: (async () => new Response('User-agent: *\nAllow: /\n', { status: 200 })) as typeof fetch,
    };
    const dispatchCacheWorker = (path: string, init?: RequestInit) =>
      worker.fetch(new Request(`${cacheBaseUrl}${path}`, init), cacheEnv as never);

    try {
      const observedReqs: Array<Record<string, unknown>> = [];
      const cacheAgent = cacheCoordinator.connectMockAgent({
        siteId: 'node-cache-1',
        arch: 'amd64',
        version: '2.7.8',
        capabilities: 'http2,browser-v1,interact-v1,artifacts-v1',
        publicIp: '198.51.100.11',
        onServerMessage: (raw) => {
          const msg = JSON.parse(String(raw)) as Record<string, unknown>;
          if (msg.type === 'dispatch' && typeof msg.jobId === 'string' && typeof msg.jobNonce === 'string') {
            const call = msg.call as { requests: Array<Record<string, unknown>> };
            const results = call.requests.map((r) => {
              observedReqs.push(r);
              const blockOn = r.blockTrackers !== false;
              const htmlBody = blockOn
                ? '<!doctype html><html><head><title>Blocked Variant</title></head><body><main><p>Contact alice@example.com — Blocked Variant Marker</p></main></body></html>'
                : '<!doctype html><html><head><title>Unblocked Variant</title></head><body><main><p>Contact alice@example.com — Unblocked Tracker Variant Marker</p></main></body></html>';
              return {
                id: r.id,
                url: r.url,
                finalUrl: r.url,
                kind: r.kind,
                outcome: 'ok',
                status: 200,
                rendered: true,
                blockedTrackers: blockOn ? 4 : 0,
                contentType: 'text/html; charset=utf-8',
                body: htmlBody,
                bodyEncoding: 'utf-8',
              };
            });
            queueMicrotask(() => {
              void dispatchCacheWorker('/agent/reply', {
                method: 'POST',
                headers: {
                  authorization: `Bearer ${AGENT_TOKEN}`,
                  'x-agent-site': 'node-cache-1',
                  'x-job-id': String(msg.jobId),
                  'x-job-nonce': String(msg.jobNonce),
                  'content-type': 'application/json',
                },
                body: JSON.stringify({ results }),
              });
            });
          }
        },
      });

      // Step A: Scrape with `blockTrackers: false` FIRST (without `noCache`) -> must NOT poison canonical default `META` D1 cache!
      const optOutFirstRes = await dispatchCacheWorker('/v1/scrape', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://cache-iso.example.com/page', blockTrackers: false, maxAgeMs: 60_000 }),
      });
      assert.equal(optOutFirstRes.status, 200);
      const optOutFirstJson = (await optOutFirstRes.json()) as { markdown?: string; cached?: boolean };
      assert.equal(optOutFirstJson.cached, false);
      assert.match(optOutFirstJson.markdown ?? '', /Unblocked Tracker Variant Marker/);

      // Step B: Default scrape (`blockTrackers` omitted = true) with `maxAgeMs: 60_000` -> MUST miss canonical cache and fetch live Blocked Variant!
      const defaultSecondRes = await dispatchCacheWorker('/v1/scrape', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://cache-iso.example.com/page', maxAgeMs: 60_000 }),
      });
      assert.equal(defaultSecondRes.status, 200);
      const defaultSecondJson = (await defaultSecondRes.json()) as { markdown?: string; cached?: boolean };
      assert.equal(defaultSecondJson.cached, false);
      assert.match(defaultSecondJson.markdown ?? '', /Blocked Variant Marker/);

      // Step C: `blockTrackers: false` + `redactPii: true` + `maxAgeMs: 60_000` on a URL with canonical cache -> MUST NOT return Blocked Variant!
      const canonicalSeedRes = await dispatchCacheWorker('/v1/scrape', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://redact-iso.example.com/page', maxAgeMs: 60_000 }),
      });
      assert.equal(canonicalSeedRes.status, 200);

      const redactOptOutRes = await dispatchCacheWorker('/v1/scrape', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          url: 'https://redact-iso.example.com/page',
          blockTrackers: false,
          redactPii: true,
          maxAgeMs: 60_000,
        }),
      });
      assert.equal(redactOptOutRes.status, 200);
      const redactOptOutJson = (await redactOptOutRes.json()) as { markdown?: string; cached?: boolean };
      assert.equal(redactOptOutJson.cached, false);
      assert.match(redactOptOutJson.markdown ?? '', /Unblocked Tracker Variant Marker/);
      assert.doesNotMatch(redactOptOutJson.markdown ?? '', /alice@example\.com/);

      // Step D: `POST /v1/extract` forwards `blockTrackers: false`
      const reqCountBeforeExtract = observedReqs.length;
      const extractRes = await dispatchCacheWorker('/v1/extract', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          urls: ['https://extract-iso.example.com/spa'],
          renderMode: 'always',
          blockTrackers: false,
        }),
      });
      assert.equal(extractRes.status, 200);
      assert.equal(observedReqs[reqCountBeforeExtract]?.blockTrackers, false);

      cacheAgent.close();
    } finally {
      cacheCoordinator.close();
      cacheMetaDb.close();
    }

    // 6. OTel child spans & Activity Log crawl events include `blockedTrackers`
    const mockReplyText = JSON.stringify({
      results: [
        {
          id: 'scrape-1',
          url: 'https://spa.example.com/dashboard?secret=1',
          kind: 'render',
          status: 200,
          outcome: 'ok',
          rendered: true,
          blockedTrackers: 5,
          durationMs: 420,
          timing: { dnsMs: 5, connectMs: 12, tlsMs: 18, ttfbMs: 95, reused: true, proto: 'h2' },
        },
      ],
    });
    const spans = buildCrawlChildSpans({
      traceId: '0123456789abcdef0123456789abcdef',
      parentSpanId: '0123456789abcdef',
      via: 'agent:node-1',
      endTimeMs: 1_760_000_001_000,
      replyText: mockReplyText,
    });
    assert.equal(spans.length, 1);
    assert.equal(spans[0]?.attributes?.['browser.blocked_trackers'], 5);

    const events = buildCrawlActivityEvents({
      source: 'scrape',
      target: 'agent',
      via: 'agent:node-1',
      httpStatus: 200,
      replyText: mockReplyText,
    });
    assert.equal(events.length, 1);
    assert.match(events[0]!.summary, /blocked=5/);
    assert.equal((events[0]!.details as Record<string, unknown>).blockedTrackers, 5);

    // 7. Owner-only `POST /admin/api/tracker-list/refresh` hydrates cold R2, broadcasts over WS, and respects 6h floor
    const adminRefreshBucket = new NodeFsR2Bucket(join(tmp, 'worker-admin-refresh-r2'));
    const adminRefreshMetaDb = new NodeSqliteD1Database(':memory:', [{ name: 'meta/0001_tracking.sql', sql: meta0001 }]);
    const adminRefreshCoord = new LocalAgentHubCoordinator(join(tmp, 'worker-admin-refresh.sqlite'));
    let adminRefreshCalls = 0;
    const adminRefreshEnv = {
      AGENT_HUB: adminRefreshCoord.asNamespace() as unknown as DurableObjectNamespace,
      ARTIFACTS: adminRefreshBucket as unknown as R2Bucket,
      META: adminRefreshMetaDb as unknown as D1Database,
      CALLER_TOKEN: OWNER_TOKEN,
      AGENT_TOKEN,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
      SAFE_PUBLIC_FETCH: (async (input: RequestInfo | URL) => {
        if (String(input) === EASYPRIVACY_SOURCE_URL) {
          adminRefreshCalls++;
          return new Response(buildEasyPrivacyFixture({ version: '2026112501', hostCount: 6_200 }), {
            status: 200,
            headers: { 'content-type': 'text/plain; charset=utf-8', etag: '"etag-2026112501"' },
          });
        }
        return new Response('User-agent: *\nAllow: /\n', { status: 200 });
      }) as typeof fetch,
    };
    const dispatchRefreshWorker = (path: string, init?: RequestInit) =>
      worker.fetch(new Request(`https://hub.example.com${path}`, init), adminRefreshEnv as never);

    try {
      const wsVersions: string[] = [];
      const wsAgent = adminRefreshCoord.connectMockAgent({
        siteId: 'node-refresh-1',
        arch: 'amd64',
        version: '2.8.0',
        capabilities: 'http2,browser-v1,interact-v1',
        publicIp: '198.51.100.12',
        onServerMessage: (raw) => {
          const msg = JSON.parse(String(raw)) as Record<string, unknown>;
          if (msg.type === 'tracker_list' && typeof msg.version === 'string') {
            wsVersions.push(msg.version);
          }
        },
      });

      assert.equal(adminRefreshCalls, 0);
      const unauthRes = await dispatchRefreshWorker('/admin/api/tracker-list/refresh', { method: 'POST' });
      assert.equal(unauthRes.status, 401);
      assert.equal(adminRefreshCalls, 0);

      const wrongTokRes = await dispatchRefreshWorker('/admin/api/tracker-list/refresh', {
        method: 'POST',
        headers: { authorization: 'Bearer wrong-token-value-1234567890' },
      });
      assert.equal(wrongTokRes.status, 401);
      assert.equal(adminRefreshCalls, 0);

      const okRes = await dispatchRefreshWorker('/admin/api/tracker-list/refresh', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}` },
      });
      assert.equal(okRes.status, 200);
      const okJson = (await okRes.json()) as {
        ok: boolean;
        updated: boolean;
        trackerList: { version: string | null; hostCount: number };
      };
      assert.equal(okJson.ok, true);
      assert.equal(okJson.updated, true);
      assert.equal(okJson.trackerList.version, '2026112501');
      assert.ok(okJson.trackerList.hostCount >= 5_000);
      assert.equal(adminRefreshCalls, 1);
      assert.deepEqual(wsVersions, ['2026112501']);

      // Immediate second call within 6h floor must be rate-limited without hitting EasyPrivacy origin
      const secondRes = await dispatchRefreshWorker('/admin/api/tracker-list/refresh', {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}` },
      });
      assert.equal(secondRes.status, 200);
      const secondJson = (await secondRes.json()) as { ok: boolean; updated: boolean; rateLimited?: boolean };
      assert.equal(secondJson.ok, true);
      assert.equal(secondJson.updated, false);
      assert.equal(secondJson.rateLimited, true);
      assert.equal(adminRefreshCalls, 1);

      // Production-scale 45,000-host EasyPrivacy list parses in a single Go WASM call well within Worker CPU limits (< 500ms)
      const fullScaleBody = buildEasyPrivacyFixture({ version: '2026112599', hostCount: 45_000 });
      const fullScaleBucket = new NodeFsR2Bucket(join(tmp, 'worker-45k-r2'));
      const t45k = performance.now();
      const strictWorkerdFetch = async function (this: unknown) {
        if (this !== undefined && this !== globalThis) {
          throw new TypeError('Illegal invocation: function called with incorrect `this` reference.');
        }
        return new Response(fullScaleBody, {
          status: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      } as unknown as typeof fetch;
      const fullScaleOut = await refreshHubTrackerList({
        bucket: fullScaleBucket,
        fetchFn: strictWorkerdFetch,
      });
      const elapsed45k = performance.now() - t45k;
      assert.equal(fullScaleOut.ok, true);
      assert.equal(fullScaleOut.updated, true);
      assert.equal(fullScaleOut.current?.meta.hostCount, 45_001);
      assert.ok(elapsed45k < 1_000, `Expected 45k EasyPrivacy list refresh in < 1000ms, took ${elapsed45k.toFixed(1)}ms`);

      // Multi-domain 10 MiB Greenhouse + Ashby `jobs` (`cloudflare.com`, `linear.app`, `anthropic.com` scale)
      // streams through `edgefetch-core.wasm` without exceeding Cloudflare's 128 MiB Worker + WASM ceiling
      resetJobsCacheForTests();
      const bigHtmlDesc =
        '&lt;p&gt;Build distributed systems in Go/Rust across global edge nodes. US Base Salary Range: $185,000 - $240,000 USD.&lt;/p&gt;'.repeat(
          135,
        );
      const buildLargeGhBoard = (slug: string, count: number): string => {
        const parts: string[] = [];
        for (let i = 0; i < count; i++) {
          parts.push(
            `{"id":${20000 + i},"title":"${i % 25 === 0 ? 'Distributed Systems Engineer' : 'Account Executive'} ${i}","absolute_url":"https://boards.greenhouse.io/${slug}/jobs/${20000 + i}","location":{"name":"Distributed, United States"},"updated_at":"2026-11-24T12:00:00Z","content":"${bigHtmlDesc}"}`,
          );
        }
        return `{"jobs":[${parts.join(',')}],"meta":{"total":${count}}}`;
      };
      const cfBigJson = buildLargeGhBoard('cloudflare', 550);
      const antBigJson = buildLargeGhBoard('anthropic', 580);
      assert.ok(cfBigJson.length > 8_500_000 && antBigJson.length > 9_000_000);
      const cfInBudgetJson = buildLargeGhBoard('cloudflare', 220);
      const antInBudgetJson = buildLargeGhBoard('anthropic', 230);
      assert.ok(cfInBudgetJson.length > 3_300_000 && cfInBudgetJson.length < 4_000_000);
      assert.ok(antInBudgetJson.length > 3_500_000 && antInBudgetJson.length < 4_100_000);

      const { resolveAtsPreFetchSpec } = await import('../src/jobs');
      const { isWasmInputBudgetExceededError } = await import('../src/wasm-bridge');
      assert.throws(
        () => resolveAtsPreFetchSpec('https://boards.greenhouse.io/cloudflare')!.format(cfBigJson, 'https://boards.greenhouse.io/cloudflare'),
        (err: unknown) => isWasmInputBudgetExceededError(err),
        '> 4 MiB Greenhouse JSON must be rejected by global MAX_WASM_INPUT_BYTES in wasm-bridge',
      );
      const cfFormatted = resolveAtsPreFetchSpec('https://boards.greenhouse.io/cloudflare')!.format(
        cfInBudgetJson,
        'https://boards.greenhouse.io/cloudflare',
      );
      const antFormatted = resolveAtsPreFetchSpec('https://boards.greenhouse.io/anthropic')!.format(
        antInBudgetJson,
        'https://boards.greenhouse.io/anthropic',
      );
      assert.equal(cfFormatted?.total, 220);
      assert.equal(antFormatted?.total, 230);

      const multiDomainJobs = await executeJobsCall({
        payload: {
          domains: ['cloudflare.com', 'linear.app', 'anthropic.com'],
          query: 'Distributed Systems Engineer',
          remote: true,
          minBase: 150_000,
          limit: 10,
        },
        env: {},
        executeSearch: async () => ({ status: 200, body: { results: [] } }),
        executeScrape: async (args) => {
          const u = String(args.url ?? '');
          if (u === 'https://cloudflare.com/careers') {
            return { status: 200, body: { ok: true, finalUrl: u, rawHtml: '<a href="https://boards.greenhouse.io/cloudflare">Jobs</a>', links: ['https://boards.greenhouse.io/cloudflare'] } };
          }
          if (u === 'https://anthropic.com/careers') {
            return { status: 200, body: { ok: true, finalUrl: u, rawHtml: '<a href="https://boards.greenhouse.io/anthropic">Jobs</a>', links: ['https://boards.greenhouse.io/anthropic'] } };
          }
          if (u === 'https://linear.app/careers') {
            return { status: 200, body: { ok: true, finalUrl: u, rawHtml: '<a href="https://jobs.ashbyhq.com/linear">Jobs</a>', links: ['https://jobs.ashbyhq.com/linear'] } };
          }
          if (u.includes('greenhouse.io/cloudflare')) {
            return { status: 200, body: { ok: true, extractorId: 'greenhouse-board', ...cfFormatted } };
          }
          if (u.includes('greenhouse.io/anthropic')) {
            return { status: 200, body: { ok: true, extractorId: 'greenhouse-board', ...antFormatted } };
          }
          if (u.includes('ashbyhq.com/linear')) {
            const linFmt = resolveAtsPreFetchSpec('https://jobs.ashbyhq.com/linear')!.format(
              JSON.stringify({
                organizationName: 'Linear',
                jobs: [
                  {
                    id: 'lin-1',
                    title: 'Distributed Systems Engineer',
                    location: 'Remote',
                    isRemote: true,
                    publishedAt: '2026-11-24T00:00:00Z',
                    descriptionPlain: 'Base salary $190,000 - $230,000',
                  },
                ],
              }),
              'https://jobs.ashbyhq.com/linear',
            );
            return { status: 200, body: { ok: true, extractorId: 'ashby-board', ...linFmt } };
          }
          return { status: 404, body: { ok: false } };
        },
      });
      assert.equal(multiDomainJobs.status, 200);
      assert.equal(multiDomainJobs.body.ok, true);
      assert.equal((multiDomainJobs.body.jobs as unknown[]).length, 10);

      // Catalog parallel currency + UCP probes warm caches so repeat runs & `getCatalogRecords` avoid redundant `/meta.json` & `/robots.txt` fetches
      resetCatalogStateForTests();
      let metaCalls = 0;
      let robotsCalls = 0;
      const mockCatalogFetch = async ({ url: u, timeoutMs }: { url: string; timeoutMs?: number }) => {
        if (u.includes('/products.json')) {
          return {
            status: 200,
            body: JSON.stringify({
              products: [
                {
                  id: 777,
                  title: 'Wool Runner NZ',
                  handle: 'wool-runner-nz',
                  vendor: 'Allbirds',
                  product_type: 'Shoes',
                  variants: [{ id: 888, title: '10', price: '112.00', available: true }],
                },
              ],
            }),
          };
        }
        if (u.endsWith('/meta.json')) {
          assert.ok(typeof timeoutMs === 'number' && timeoutMs <= 4_000, `Expected bounded timeoutMs on /meta.json, got ${timeoutMs}`);
          metaCalls++;
          return { status: 200, body: JSON.stringify({ currency: 'USD' }) };
        }
        if (u.endsWith('/robots.txt')) {
          assert.ok(typeof timeoutMs === 'number' && timeoutMs <= 4_500, `Expected bounded timeoutMs on /robots.txt, got ${timeoutMs}`);
          robotsCalls++;
          return { status: 200, body: 'User-agent: *\nDisallow: /cart.js\n# /.well-known/ucp\n' };
        }
        return { status: 404, body: '' };
      };
      const catFirst = await executeCatalogCall({
        payload: { url: 'https://www.allbirds-cache-test.example.com', maxPages: 1, fields: 'lean' },
        executeHubFetch: mockCatalogFetch,
      });
      assert.equal(catFirst.status, 200);
      assert.equal(metaCalls, 1);
      assert.equal(robotsCalls, 1);
      assert.equal((catFirst.body.ucp as { advertised?: boolean })?.advertised, true);

      const catFirstRecs = await getCatalogRecords({
        catalogId: String(catFirst.body.catalogId),
        fields: 'lean',
        executeHubFetch: mockCatalogFetch,
      });
      assert.equal((catFirstRecs.body.records as Array<{ currency: string }>)[0]?.currency, 'USD');
      assert.equal(metaCalls, 1, 'getCatalogRecords must reuse backfilled/cached currency with zero extra /meta.json calls');

      const catSecond = await executeCatalogCall({
        payload: { url: 'https://www.allbirds-cache-test.example.com', maxPages: 1, fields: 'lean' },
        executeHubFetch: mockCatalogFetch,
      });
      assert.equal(catSecond.status, 200);
      assert.equal(metaCalls, 1, 'Repeat catalog pull on warm origin must hit SHOPIFY_ORIGIN_CURRENCY_CACHE');
      assert.equal(robotsCalls, 1, 'Repeat catalog pull on warm origin must hit ORIGIN_UCP_CACHE');

      // ── WASM Memory Eviction, Exact Raw-Pair Sizing, RE2 Stale-Handle Safety & Lite Greenhouse Boards (Tests 1–5) ──
      const {
        callCoreWasmRawMetaPair,
        callCoreWasmRawPair,
        compileWasmRe2,
        getWasmReactorStats,
        resetWasmReactor,
      } = await import('../src/wasm-bridge');
      const {
        compileLinearRegex,
        compileSafeUserRegex,
        compileSafeUserRegexUnion,
      } = await import('../src/safe-input');
      const { tryParseJsonPayloadForScrape } = await import('../src/scrape');

      // Test 1: Oversized (>8 MiB) WASM calls evict `cachedReactor` immediately after decoding output so grown
      // `WebAssembly.Memory` pages are freed and the next call spawns a fresh baseline reactor instance.
      resetWasmReactor();
      compileWasmRe2('^warmup-gen$')?.test('warmup-gen');
      const statsBeforeOversized = getWasmReactorStats();
      assert.equal(statsBeforeOversized.active, true);
      assert.ok(statsBeforeOversized.initialMemoryBytes > 0);

      const { sanitizeInlineHtmlInMarkdown: sanitizeInline2M } = await import('../src/scrape');
      const hugeIngestJsonDoc = tryParseJsonPayloadForScrape(
        antInBudgetJson,
        'application/json',
        'https://boards-api.greenhouse.io/v1/boards/anthropic/jobs',
      );
      assert.ok(hugeIngestJsonDoc && hugeIngestJsonDoc.markdown.length > 1_000 && hugeIngestJsonDoc.markdown.length < 600_000);
      assert.equal(hugeIngestJsonDoc.parsed, null, 'Oversized >2 MiB JSON must skip V8 object graph allocation');

      // `3M` `<` (`2.86 MiB` in <= `4 MiB` budget -> `12.00 MB` `&lt;` out > `8 MiB` `WASM_EVICT_IO_BYTES`) evicts `cachedReactor`!
      assert.equal(sanitizeInline2M('<'.repeat(3_000_000)).length, 12_000_000);
      const statsAfterOversized = getWasmReactorStats();
      assert.equal(statsAfterOversized.active, false, '>8 MiB WASM output must evict cachedReactor');
      assert.equal(statsAfterOversized.memoryBytes, 0);

      compileWasmRe2('^post-evict$')?.test('post-evict');
      const statsFreshInstance = getWasmReactorStats();
      assert.equal(statsFreshInstance.active, true);
      assert.equal(statsFreshInstance.generation, statsBeforeOversized.generation + 1);
      assert.ok(
        statsFreshInstance.memoryBytes >= statsFreshInstance.initialMemoryBytes &&
          statsFreshInstance.memoryBytes <= statsFreshInstance.initialMemoryBytes + 2 * 1024 * 1024,
        `Fresh reactor post-eviction memory (${statsFreshInstance.memoryBytes}) must stay within 2 MiB of initial baseline (${statsFreshInstance.initialMemoryBytes})`,
      );

      // Ordinary 2 MB documents (`2M` `<` sanitize -> `~50 MiB` total) must NOT trigger reactor rebuilds across
      // 12 consecutive calls (`generation` stays constant, zero `~50 ms` rebuild stalls or dual-instance overlap).
      const twoMillionLt = '<'.repeat(2_000_000);
      const genBefore2M = getWasmReactorStats().generation;
      for (let runIdx = 0; runIdx < 12; runIdx++) {
        const sanitized2M = sanitizeInline2M(twoMillionLt);
        assert.equal(sanitized2M.length, 8_000_000);
      }
      const statsAfter2M = getWasmReactorStats();
      assert.equal(statsAfter2M.active, true, '12 consecutive 2M `<` sanitize calls must keep cachedReactor active');
      assert.equal(
        statsAfter2M.generation,
        genBefore2M,
        '12 consecutive 2M `<` sanitize calls must have 0 reactor rebuilds',
      );
      assert.ok(statsAfter2M.memoryBytes <= 64 * 1024 * 1024);

      // Oversized (>4 MiB) WASM inputs are rejected BEFORE touching WASM memory (`0` extra pages, `0` retry instances)!
      const genBeforeOverBudget = getWasmReactorStats().generation;
      assert.throws(
        () => callCoreWasmRawPair('detect_prompt_injection', 'ok', 'z'.repeat(4 * 1024 * 1024 + 1024)),
        (err: unknown) => isWasmInputBudgetExceededError(err),
      );
      assert.equal(getWasmReactorStats().active, true);
      assert.equal(
        getWasmReactorStats().generation,
        genBeforeOverBudget,
        'Over-budget WASM call must reject before touching or rebuilding cachedReactor',
      );

      // Test 2: `callCoreWasmRawMetaPair` and `callCoreWasmRawPair` use exact UTF-8 byte lengths (`0` `rawB.length * 3`)
      // up to `MAX_WASM_INPUT_BYTES` (`4 MiB`) and reject `> 4 MiB` inputs cleanly!
      const rawB38MiB = 'x'.repeat(3_800_000);
      const metaPairOut = callCoreWasmRawMetaPair<{ thin: boolean }>(
        'jobs_is_thin_scripted',
        {},
        '<html><body><p>ok</p></body></html>',
        rawB38MiB,
      );
      assert.equal(typeof metaPairOut.thin, 'boolean');
      assert.ok(getWasmReactorStats().memoryBytes <= 64 * 1024 * 1024);

      const rawPairOut = callCoreWasmRawPair<{ detected: boolean }>(
        'detect_prompt_injection',
        'Normal clean markdown',
        rawB38MiB,
      );
      assert.equal(rawPairOut.detected, false);
      assert.ok(getWasmReactorStats().memoryBytes <= 64 * 1024 * 1024);

      // Test 3: RE2 matchers (`compileWasmRe2`, `compileLinearRegex`, `compileSafeUserRegex`, `compileSafeUserRegexUnion`)
      // bind the reactor instance reference and never mis-evaluate against recycled handles (`1..k`) after reactor reset/eviction.
      resetWasmReactor();
      const directRe2 = compileWasmRe2('^https://allow\\.example\\.com/(?P<id>[0-9]+)$')!;
      const linearRe = compileLinearRegex('^https://allow-linear\\.example\\.com/v1/[0-9]+$')!;
      const userRe = compileSafeUserRegex('^/allowed-user/[a-z0-9-]+$')!;
      const unionMatcher = compileSafeUserRegexUnion(['^/union-alpha/[0-9]+$', '^/union-beta/[0-9]+$'])!;

      assert.equal(directRe2.test('https://allow.example.com/42'), true);
      assert.equal(directRe2.exec('https://allow.example.com/42')?.groups?.id, '42');
      assert.equal(linearRe.test('https://allow-linear.example.com/v1/7'), true);
      assert.equal(linearRe.test('https://poison.example.org/hijack'), false);
      assert.equal(userRe.test('/allowed-user/ok-1'), true);
      assert.equal(userRe.test('/poison-user/hijack'), false);
      assert.equal(unionMatcher('/union-alpha/10'), true);
      assert.equal(unionMatcher('/poison-union/99'), false);

      // Evict the reactor via a real >8 MiB output call (`3M` `<` -> `12 MB` `&lt;`), then populate handles 1..8 on the new reactor with OPPOSITE poison patterns!
      assert.equal(sanitizeInline2M('<'.repeat(3_000_000)).length, 12_000_000);
      assert.equal(getWasmReactorStats().active, false);
      for (let k = 0; k < 8; k++) {
        const poison = compileWasmRe2('^(?:https://poison\\.example\\.org/hijack|/poison-user/hijack|/poison-union/99)$')!;
        assert.equal(poison.test('https://poison.example.org/hijack'), true);
      }

      // Every pre-eviction cached matcher MUST recompile onto the new reactor and reject the poison subjects (both seen & unseen)!
      assert.equal(directRe2.test('https://poison.example.org/hijack'), false);
      assert.equal(directRe2.test('https://allow.example.com/42'), true);
      assert.equal(directRe2.exec('https://allow.example.com/99')?.groups?.id, '99');
      assert.equal(linearRe.test('https://poison.example.org/hijack'), false);
      assert.equal(linearRe.test('https://allow-linear.example.com/v1/7'), true);
      assert.equal(linearRe.test('https://allow-linear.example.com/v1/88'), true);
      assert.equal(userRe.test('/poison-user/hijack'), false);
      assert.equal(userRe.test('/allowed-user/ok-1'), true);
      assert.equal(userRe.test('/allowed-user/ok-2'), true);
      assert.equal(unionMatcher('/poison-union/99'), false);
      assert.equal(unionMatcher('/union-beta/55'), true);

      // Test 4: RE2 ring-buffer wraparound (>1,024 patterns on the SAME reactor) verifies per-slot `{ id, re }` identity.
      const ringFirst = compileWasmRe2('^ring-origin-(?P<num>[0-9]+)$')!;
      assert.equal(ringFirst.test('ring-origin-1'), true);
      const genDuringRing = getWasmReactorStats().generation;
      for (let rIdx = 0; rIdx < 1_050; rIdx++) {
        const filler = compileWasmRe2(`^ring-overwrite-${rIdx}$`)!;
        if (rIdx === 1_023 || rIdx === 1_049) {
          assert.equal(filler.test(`ring-overwrite-${rIdx}`), true);
        }
      }
      assert.equal(getWasmReactorStats().generation, genDuringRing, '1,050 small regexes must stay on the same reactor instance');
      assert.equal(ringFirst.test('ring-overwrite-1023'), false, 'Evicted ring slot must not match overwriting pattern');
      assert.equal(ringFirst.exec('ring-overwrite-1023'), null);
      assert.equal(ringFirst.exec('ring-origin-777')?.groups?.num, '777', 'Evicted ring handle must recompile and preserve groups');

      // Test 5: Lite Greenhouse board (`?content=false`) across `verify`, `runSlugProbeWave`, AND `search` (`runCandidateWave`),
      // with bounded (`<= 6`) per-posting `/jobs/{id}` enrichment populating `pay` & `snippet` (zero `?content=true` board downloads!).
      resetJobsCacheForTests();
      const liteGhBoardSpec = resolveAtsPreFetchSpec('https://job-boards.greenhouse.io/anthropic', { liteBoard: true });
      const liteGhJobSpec = resolveAtsPreFetchSpec('https://job-boards.greenhouse.io/anthropic/jobs/5462972008', { liteBoard: true });
      const fullGhBoardSpec = resolveAtsPreFetchSpec('https://job-boards.greenhouse.io/anthropic');
      assert.equal(liteGhBoardSpec?.fetchUrl, 'https://boards-api.greenhouse.io/v1/boards/anthropic/jobs');
      assert.equal(liteGhJobSpec?.fetchUrl, 'https://boards-api.greenhouse.io/v1/boards/anthropic/jobs/5462972008');
      assert.equal(fullGhBoardSpec?.fetchUrl, 'https://boards-api.greenhouse.io/v1/boards/anthropic/jobs?content=true');

      const seenJobsScrapeCalls: Array<{ url: string; ephemeral?: unknown; atsLiteBoard?: unknown }> = [];
      const mockJobsScrape = async (args: Record<string, unknown>) => {
        const u = String(args.url ?? '');
        seenJobsScrapeCalls.push({ url: u, ephemeral: args.ephemeral, atsLiteBoard: args.atsLiteBoard });
        if (u === 'https://stealthco.com/careers') {
          // Stays on `/careers` with 200 OK but zero ATS links -> triggers `runSlugProbeWave`!
          return { status: 200, body: { ok: true, finalUrl: u, rawHtml: '<html><body><h1>Join StealthCo</h1></body></html>', links: [] } };
        }
        if (u === 'https://bigghco.com/careers') {
          return {
            status: 200,
            body: {
              ok: true,
              finalUrl: u,
              rawHtml: '<a href="https://job-boards.greenhouse.io/bigghco">Careers</a>',
              links: ['https://job-boards.greenhouse.io/bigghco'],
            },
          };
        }
        if (u === 'https://boards.greenhouse.io/stealthco' || u === 'https://job-boards.greenhouse.io/stealthco') {
          const isLite = args.atsLiteBoard === true;
          return {
            status: 200,
            body: {
              ok: true,
              extractorId: 'greenhouse-board',
              total: 1,
              returned: 1,
              truncated: false,
              links: ['https://job-boards.greenhouse.io/stealthco/jobs/5001'],
              jobs: [
                {
                  title: 'Systems Engineer',
                  company: 'StealthCo',
                  url: 'https://job-boards.greenhouse.io/stealthco/jobs/5001',
                  applyUrl: 'https://job-boards.greenhouse.io/stealthco/jobs/5001',
                  workplaceType: 'remote',
                  locations: ['Remote - US'],
                  pay: isLite ? null : { currency: 'USD', min: 180_000, max: 220_000, period: 'year', basis: 'base', raw: '$180k-$220k' },
                  postedAt: '2026-11-24T00:00:00Z',
                  source: 'greenhouse',
                  ...(isLite ? {} : { snippet: 'Full ?content=true description body with compensation details.' }),
                },
              ],
            },
          };
        }
        if (u === 'https://job-boards.greenhouse.io/stealthco/jobs/5001') {
          return {
            status: 200,
            body: {
              ok: true,
              extractorId: 'greenhouse-job',
              jobPosting: {
                title: 'Systems Engineer',
                hiringOrganization: 'StealthCo',
                workplaceType: 'remote',
                jobLocation: ['Remote - US'],
                pay: { currency: 'USD', min: 180_000, max: 220_000, period: 'year', basis: 'base', raw: '$180k-$220k' },
                datePosted: '2026-11-24T00:00:00Z',
                url: u,
                applyUrl: u,
                source: 'greenhouse',
              },
              markdown: '# Systems Engineer @ StealthCo\n\nSingle-posting description body with $180k-$220k USD base compensation.',
            },
          };
        }
        if (u === 'https://job-boards.greenhouse.io/bigghco' || u === 'https://boards.greenhouse.io/bigghco') {
          assert.equal(args.atsLiteBoard, true, 'Search-mode Greenhouse board fetch must ALWAYS pass atsLiteBoard: true');
          const roleTeams = ['Runtime', 'Storage', 'Networking', 'Security', 'Edge', 'Kernel', 'Compiler', 'Platform'];
          const liteJobs = roleTeams.map((team, idx) => ({
            title: `Systems Engineer, ${team}`,
            company: 'BigGhCo',
            url: `https://job-boards.greenhouse.io/bigghco/jobs/${6001 + idx}`,
            applyUrl: `https://job-boards.greenhouse.io/bigghco/jobs/${6001 + idx}`,
            workplaceType: 'remote',
            locations: ['Remote - US'],
            pay: null,
            postedAt: '2026-11-24T00:00:00Z',
            source: 'greenhouse',
          }));
          return {
            status: 200,
            body: {
              ok: true,
              extractorId: 'greenhouse-board',
              total: 8,
              returned: 8,
              truncated: false,
              links: liteJobs.map((j) => j.url),
              jobs: liteJobs,
            },
          };
        }
        if (/^https:\/\/job-boards\.greenhouse\.io\/bigghco\/jobs\/600\d$/.test(u)) {
          const roleTeams = ['Runtime', 'Storage', 'Networking', 'Security', 'Edge', 'Kernel', 'Compiler', 'Platform'];
          const teamName = roleTeams[Number(u.slice(-1)) - 1] ?? 'Core';
          return {
            status: 200,
            body: {
              ok: true,
              extractorId: 'greenhouse-job',
              jobPosting: {
                title: `Systems Engineer, ${teamName}`,
                hiringOrganization: 'BigGhCo',
                workplaceType: 'remote',
                jobLocation: ['Remote - US'],
                pay: { currency: 'USD', min: 195_000, max: 240_000, period: 'year', basis: 'base', raw: '$195k-$240k' },
                datePosted: '2026-11-24T00:00:00Z',
                url: u,
                applyUrl: u,
                source: 'greenhouse',
              },
              markdown: `Single-posting detail body for ${u} with $195k-$240k base salary.`,
            },
          };
        }
        return { status: 404, body: { ok: false } };
      };

      const verifyStealth = await executeJobsCall({
        payload: {
          verify: [
            'https://job-boards.greenhouse.io/stealthco/jobs/5001',
            'https://job-boards.greenhouse.io/stealthco/jobs/9999',
          ],
        },
        env: { JOBS_SHARED_CACHE: true },
        executeSearch: async () => ({ status: 200, body: { results: [] } }),
        executeScrape: mockJobsScrape,
      });
      assert.equal(verifyStealth.status, 200);
      assert.equal(seenJobsScrapeCalls.length, 1);
      assert.equal(seenJobsScrapeCalls[0]?.ephemeral, true);
      assert.equal(seenJobsScrapeCalls[0]?.atsLiteBoard, true);
      const vStealthRes = verifyStealth.body.results as Array<{ status: string }>;
      assert.equal(vStealthRes[0]?.status, 'live');
      assert.equal(vStealthRes[1]?.status, 'closed');

      // On a cold cache, BOTH `runSlugProbeWave` AND `runCandidateWave` use `atsLiteBoard: true` (zero `?content=true` board downloads!),
      // `runCandidateWave` reuses the `|lite` board cache entry, and single-posting `/jobs/5001` enrichment populates `pay` & `snippet`!
      seenJobsScrapeCalls.length = 0;
      resetJobsCacheForTests();
      const slugProbeSearch = await executeJobsCall({
        payload: {
          domains: ['stealthco.com'],
          query: 'Systems Engineer',
          minBase: 170_000,
          strictPay: true,
        },
        env: { JOBS_SHARED_CACHE: true },
        executeSearch: async () => ({ status: 200, body: { results: [] } }),
        executeScrape: mockJobsScrape,
      });
      assert.equal(slugProbeSearch.status, 200);
      const ghLiteBoardCalls = seenJobsScrapeCalls.filter((c) => c.url === 'https://boards.greenhouse.io/stealthco' && c.atsLiteBoard === true);
      const ghFullBoardCalls = seenJobsScrapeCalls.filter((c) => c.url === 'https://boards.greenhouse.io/stealthco' && c.atsLiteBoard !== true);
      const ghDetailCalls = seenJobsScrapeCalls.filter((c) => c.url === 'https://job-boards.greenhouse.io/stealthco/jobs/5001');
      assert.equal(ghLiteBoardCalls.length, 1, 'runCandidateWave must reuse runSlugProbeWave |lite board cache entry');
      assert.equal(ghFullBoardCalls.length, 0, 'Search mode must NEVER download full ?content=true Greenhouse boards');
      assert.equal(ghDetailCalls.length, 1, 'Search mode must enrich matching Greenhouse posting via /jobs/{id}');
      const enrichedStealthJobs = slugProbeSearch.body.jobs as Array<{ pay: { min: number } | null; snippet?: string }>;
      assert.equal(enrichedStealthJobs.length, 1);
      assert.equal(enrichedStealthJobs[0]?.pay?.min, 180_000);
      assert.ok(enrichedStealthJobs[0]?.snippet?.includes('Single-posting description body'));

      // Direct `/careers` -> Greenhouse board (`domains: ["bigghco.com"]`) also uses `atsLiteBoard: true`, caps per-posting
      // detail lookups at `<= 6`, and reports `payUnverifiedCount: 2` under `strictPay: true`!
      seenJobsScrapeCalls.length = 0;
      resetJobsCacheForTests();
      const bigGhSearch = await executeJobsCall({
        payload: {
          domains: ['bigghco.com'],
          query: 'Systems Engineer',
          minBase: 170_000,
          strictPay: true,
          limit: 10,
        },
        env: { JOBS_SHARED_CACHE: true },
        executeSearch: async () => ({ status: 200, body: { results: [] } }),
        executeScrape: mockJobsScrape,
      });
      assert.equal(bigGhSearch.status, 200);
      const bigGhDetailCalls = seenJobsScrapeCalls.filter((c) => /\/bigghco\/jobs\/600\d$/.test(c.url));
      assert.equal(bigGhDetailCalls.length, 6, 'Per-posting Greenhouse detail lookups must cap at <= 6');
      assert.equal((bigGhSearch.body.jobs as unknown[]).length, 6);
      assert.equal(bigGhSearch.body.payUnverifiedCount, 2);

      // Test 6: `parseHtmlDoc` / `HtmlNode` DOM handles check reactor generation IN JS before calling Go and return empty
      // across reactor eviction, never instantiating or reading from a recycled `docId` (`1..32`) on a new reactor.
      const { parseHtmlDoc } = await import('../src/extractors/utils');
      const preEvictDoc = parseHtmlDoc('<html><body><div class="secret" data-tok="orig">AlphaOriginal</div></body></html>');
      const preEvictNode = preEvictDoc.first('.secret')!;
      assert.equal(preEvictNode.text(), 'AlphaOriginal');
      assert.equal(preEvictNode.attr('data-tok'), 'orig');
      resetWasmReactor();
      assert.equal(getWasmReactorStats().active, false);
      assert.equal(preEvictDoc.select('.secret').length, 0);
      assert.equal(preEvictNode.text(), '');
      assert.equal(preEvictNode.attr('data-tok'), undefined);
      assert.equal(
        getWasmReactorStats().active,
        false,
        'Evicted HtmlDoc/HtmlNode methods must short-circuit in JS before reaching Go',
      );
      const postEvictDoc = parseHtmlDoc('<html><body><div class="secret" data-tok="poison">PoisonOtherDoc</div></body></html>');
      assert.equal(postEvictDoc.first('.secret')?.text(), 'PoisonOtherDoc');
      assert.equal(preEvictDoc.select('.secret').length, 0, 'Evicted HtmlDoc handle must not read new reactor docId=1');
      assert.equal(preEvictNode.text(), '', 'Evicted HtmlNode handle must return empty string');
      assert.equal(preEvictNode.attr('data-tok'), undefined, 'Evicted HtmlNode attr() must return undefined');

      // Test 7: `strictPay` surfaces `payUnverifiedCount` + `notes` when Workday postings exceed the per-call enrichment cap (6).
      resetJobsCacheForTests();
      const wdTiers = ['Platform', 'Storage', 'Networking', 'Runtime', 'Security', 'Observability', 'Compiler', 'Consensus'];
      const wdBoardPostings = wdTiers.map((tier, idx) => ({
        title: `Staff Systems Engineer, ${tier}`,
        company: 'WdScaleCo',
        url: `https://wdscaleco.wd5.myworkdayjobs.com/en-US/External/job/Remote-US/Staff-Systems-Engineer-${tier}_JR${100 + idx}`,
        applyUrl: `https://wdscaleco.wd5.myworkdayjobs.com/en-US/External/job/Remote-US/Staff-Systems-Engineer-${tier}_JR${100 + idx}`,
        workplaceType: 'remote' as const,
        locations: ['Remote - United States'],
        pay: null,
        postedAt: '2026-11-24T00:00:00Z',
        source: 'workday',
      }));
      const wdStrictPayRes = await executeJobsCall({
        payload: {
          company: 'WdScaleCo',
          query: 'Staff Systems Engineer',
          minBase: 180_000,
          strictPay: true,
          limit: 10,
          includeBuiltIn: false,
        },
        env: { JOBS_SHARED_CACHE: true },
        executeSearch: async () => ({
          status: 200,
          body: { results: [{ url: 'https://wdscaleco.wd5.myworkdayjobs.com/External' }] },
        }),
        executeScrape: async (args) => {
          const u = String(args.url ?? '');
          if (u.startsWith('https://wdscaleco.wd5.myworkdayjobs.com/External') && !u.includes('/job/')) {
            return {
              status: 200,
              body: {
                ok: true,
                extractorId: 'workday-board',
                total: 8,
                returned: 8,
                truncated: false,
                jobs: wdBoardPostings.map((p) => ({ ...p })),
              },
            };
          }
          if (u.includes('/job/')) {
            return {
              status: 200,
              body: {
                ok: true,
                markdown: 'Compensation: US Base Salary Range $195,000 - $235,000 USD.',
              },
            };
          }
          return { status: 404, body: { ok: false } };
        },
      });
      assert.equal(wdStrictPayRes.status, 200);
      assert.equal((wdStrictPayRes.body.jobs as unknown[]).length, 6);
      assert.equal(wdStrictPayRes.body.payUnverifiedCount, 2);
      assert.ok(
        Array.isArray(wdStrictPayRes.body.notes) &&
          (wdStrictPayRes.body.notes as string[]).some((n) => n.includes('pay not verified')),
        'strictPay response must note postings excluded past enrichment cap',
      );

      // Test 8: Multi-byte CJK & surrogate-pair emoji inputs just above the 512K-char `EXACT_UTF8_ENCODE_THRESHOLD_CHARS`
      // switch point (`530K+` UTF-16 code units, ~1.6 MiB UTF-8 > `~1.06x` optimistic buffer) verify `enc.read === str.length`
      // and fall back to exact UTF-8 encoding with zero silent truncation before reaching Go's sanitizer.
      const { sanitizeInlineHtmlInMarkdown } = await import('../src/scrape');
      const cjkPrefix = '日本語セキュリティ検証テキスト\n'.repeat(35_500); // ~532,500 chars (~1.56 MiB UTF-8)
      const emojiPrefix = '🦀🔒🌐'.repeat(108_000); // 540,000 UTF-16 code units (surrogate pairs + BMP, ~1.18 MiB UTF-8)
      assert.ok(cjkPrefix.length > 524_288 && emojiPrefix.length > 524_288);

      for (const [label, prefix] of [
        ['cjk-over-512k', cjkPrefix],
        ['emoji-over-512k', emojiPrefix],
      ] as const) {
        const tailAttackAndSentinel = `\n<script>alert("${label}")</script>\n[bad](javascript:alert(1))\nTAIL_SENTINEL_${label}_END`;
        const sanitizedMultiByte = sanitizeInlineHtmlInMarkdown(prefix + tailAttackAndSentinel, 'https://example.com/');
        assert.ok(
          sanitizedMultiByte.endsWith(`TAIL_SENTINEL_${label}_END`),
          `${label}: encodeInto must never truncate tail characters past optimistic buffer`,
        );
        assert.equal(sanitizedMultiByte.includes('<script'), false, `${label}: trailing <script> must be stripped`);
        assert.equal(sanitizedMultiByte.includes('javascript:'), false, `${label}: trailing javascript: link must be neutralized`);
      }

      wsAgent.close();
    } finally {
      adminRefreshCoord.close();
      adminRefreshMetaDb.close();
    }
  } finally {
    process.off('unhandledRejection', onUnhandled);
    rmSync(tmp, { recursive: true, force: true });
  }
});
