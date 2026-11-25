import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import WebSocket from 'ws';

import worker from '../src/index';
import { buildOpenApiSpec } from '../src/openapi';
import { MCP_TOOL_SCHEMAS } from '../src/mcp';
import { NodeFsR2Bucket, NodeSqliteD1Database, LocalAgentHubCoordinator } from '../portable/node-adapters';
import { startPortableHub } from '../portable/portable-server';
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

    // --- Portable Hub: verify ZERO fetch calls during startup even when enabled, then test live WS connect/reconnect + version update + /admin + scrape/interact ---
    let listFetchCalls = 0;
    let currentFixtureVersion = '2026112401';
    const portableDataDir = join(tmp, 'portable-live');
    const hub = await startPortableHub({
      port: 0,
      host: '127.0.0.1',
      dataDir: portableDataDir,
      env: {
        CALLER_TOKEN: OWNER_TOKEN,
        AGENT_TOKEN,
        EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
      },
      trackerFetchImpl: async () => {
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
      },
    });

    try {
      assert.equal(listFetchCalls, 0, 'Portable Hub must NEVER fetch EasyPrivacy during startup');
      const baseUrl = `http://127.0.0.1:${hub.port}`;

      // Trigger first scheduled refresh on the Portable Hub (simulating the delayed timer tick)
      await hub.refreshTrackerListNow?.();
      assert.equal(listFetchCalls, 1);

      // Connect a simulated agent over `/agent/ws` -> must immediately receive `tracker_list` v1 (`2026112401`)!
      const connectMockAgent = async () => {
        const receivedTrackerVersions: string[] = [];
        const observedCrawlRequests: Array<Record<string, unknown>> = [];
        const ws = new WebSocket(`ws://127.0.0.1:${hub.port}/agent/ws`, 'edgefetch-agent', {
          headers: {
            authorization: `Bearer ${AGENT_TOKEN}`,
            'x-agent-site': 'node-test-1',
            'x-agent-version': '2.7.8',
            'x-agent-capabilities': 'http2,browser-v1,interact-v1',
          },
        });

        ws.on('message', (raw) => {
          const msg = JSON.parse(String(raw)) as Record<string, unknown>;
          if (msg.type === 'tracker_list' && typeof msg.version === 'string') {
            receivedTrackerVersions.push(msg.version);
            ws.send(JSON.stringify({ type: 'tracker_list_ack', version: msg.version }));
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
            void fetch(`${baseUrl}/agent/reply`, {
              method: 'POST',
              headers: {
                authorization: `Bearer ${AGENT_TOKEN}`,
                'x-agent-site': 'node-test-1',
                'x-job-id': msg.jobId,
                'x-job-nonce': msg.jobNonce,
                'content-type': 'application/json',
              },
              body: JSON.stringify(reply),
            });
          }
        });

        await new Promise<void>((resolveOpen, rejectOpen) => {
          ws.once('open', () => {
            ws.send(
              JSON.stringify({
                type: 'agent_hello',
                version: '2.7.8',
                arch: 'amd64',
                goVersion: 'go1.27',
                capabilities: ['http2', 'browser-v1', 'interact-v1'],
              }),
            );
            resolveOpen();
          });
          ws.once('error', rejectOpen);
        });

        const waitForVersion = async (want: string) => {
          for (let i = 0; i < 60; i++) {
            if (receivedTrackerVersions.includes(want)) return;
            await new Promise((r) => setTimeout(r, 25));
          }
          assert.fail(`Timed out waiting for agent to receive tracker_list ${want}; got ${JSON.stringify(receivedTrackerVersions)}`);
        };

        return { ws, receivedTrackerVersions, observedCrawlRequests, waitForVersion };
      };

      const agent1 = await connectMockAgent();
      await agent1.waitForVersion('2026112401');

      // Verify `GET /agents` and MCP `list_agents` expose `trackerListVersion: "2026112401"`
      const agentsRes = await fetch(`${baseUrl}/agents`, {
        headers: { authorization: `Bearer ${OWNER_TOKEN}` },
      });
      assert.equal(agentsRes.status, 200);
      const agentsJson = (await agentsRes.json()) as {
        trackerListVersion?: string | null;
        agents: Array<{ siteId: string; trackerListVersion?: string | null }>;
      };
      assert.equal(agentsJson.trackerListVersion, '2026112401');
      assert.equal(agentsJson.agents[0]?.trackerListVersion, '2026112401');

      const mcpListRes = await fetch(`${baseUrl}/mcp`, {
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
      const scrapeDefaultRes = await fetch(`${baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://spa1.example.com/app', renderMode: 'always', noCache: true }),
      });
      assert.equal(scrapeDefaultRes.status, 200);
      const scrapeDefaultBody = (await scrapeDefaultRes.json()) as { metadata?: { blockedTrackers?: number } };
      assert.equal(scrapeDefaultBody.metadata?.blockedTrackers, 3);

      const scrapeOptOutRes = await fetch(`${baseUrl}/v1/scrape`, {
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
      const interactOptOutRes = await fetch(`${baseUrl}/v1/interact`, {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://spa3.example.com/app', blockTrackers: false }),
      });
      assert.equal(interactOptOutRes.status, 200);
      const interactOptOutBody = (await interactOptOutRes.json()) as { metadata?: { blockedTrackers?: number } };
      assert.equal(interactOptOutBody.metadata?.blockedTrackers, 0);

      const interactDefaultRes = await fetch(`${baseUrl}/v1/interact`, {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://spa4.example.com/app' }),
      });
      assert.equal(interactDefaultRes.status, 200);
      const interactDefaultBody = (await interactDefaultRes.json()) as { metadata?: { blockedTrackers?: number } };
      assert.equal(interactDefaultBody.metadata?.blockedTrackers, 3);

      // Update list version on Hub -> connected agent receives new version `2026112501` live, AND reconnecting agent receives `2026112501`!
      currentFixtureVersion = '2026112501';
      await hub.refreshTrackerListNow?.({ forceAfter6hOverrideForTest: true });
      await agent1.waitForVersion('2026112501');

      agent1.ws.close();
      await new Promise((r) => setTimeout(r, 50));

      const agentReconnected = await connectMockAgent();
      await agentReconnected.waitForVersion('2026112501');

      // `/admin` owner session sees `trackerList` metadata (`version`, `fetchedAt`, `hostCount`, `sourceUrl`, `licenseUrl`) AND dashboard HTML links EasyPrivacy licence!
      const loginRes = await fetch(`${baseUrl}/admin/login`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: baseUrl,
        },
        body: new URLSearchParams({ token: OWNER_TOKEN }).toString(),
        redirect: 'manual',
      });
      assert.equal(loginRes.status, 302);
      const cookie = loginRes.headers.get('set-cookie')?.split(';')[0] ?? '';
      assert.ok(cookie.length > 10);

      const adminHtmlRes = await fetch(`${baseUrl}/admin`, { headers: { cookie } });
      assert.equal(adminHtmlRes.status, 200);
      const adminHtml = await adminHtmlRes.text();
      assert.ok(adminHtml.includes(EASYPRIVACY_LICENCE_URL), 'Admin UI must link EasyPrivacy licence');
      assert.ok(adminHtml.includes(EASYPRIVACY_SOURCE_URL), 'Admin UI must show EasyPrivacy source URL');

      const stateRes = await fetch(`${baseUrl}/admin/api/state`, { headers: { cookie } });
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

      agentReconnected.ws.close();
    } finally {
      await hub.close();
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
    const cacheDir = join(tmp, 'portable-cache');
    const hub = await startPortableHub({
      port: 0,
      host: '127.0.0.1',
      dataDir: cacheDir,
      env: {
        CALLER_TOKEN: OWNER_TOKEN,
        AGENT_TOKEN,
        EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
      },
      trackerFetchImpl: async () => new Response(validFixture, { status: 200, headers: { 'content-type': 'text/plain' } }),
    });
    try {
      const baseUrl = `http://127.0.0.1:${hub.port}`;
      const observedReqs: Array<Record<string, unknown>> = [];
      const ws = new WebSocket(`ws://127.0.0.1:${hub.port}/agent/ws`, 'edgefetch-agent', {
        headers: {
          authorization: `Bearer ${AGENT_TOKEN}`,
          'x-agent-site': 'node-cache-1',
          'x-agent-version': '2.7.8',
          'x-agent-capabilities': 'http2,browser-v1,interact-v1,artifacts-v1',
        },
      });
      ws.on('message', (raw) => {
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
          void fetch(`${baseUrl}/agent/reply`, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${AGENT_TOKEN}`,
              'x-agent-site': 'node-cache-1',
              'x-job-id': msg.jobId,
              'x-job-nonce': msg.jobNonce,
              'content-type': 'application/json',
            },
            body: JSON.stringify({ results }),
          });
        }
      });
      await new Promise<void>((resolve, reject) => {
        ws.once('open', () => resolve());
        ws.once('error', reject);
      });

      // Step A: Scrape with `blockTrackers: false` FIRST (without `noCache`) -> must NOT poison canonical default `META` D1 cache!
      const optOutFirstRes = await fetch(`${baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://cache-iso.example.com/page', blockTrackers: false, maxAgeMs: 60_000 }),
      });
      assert.equal(optOutFirstRes.status, 200);
      const optOutFirstJson = (await optOutFirstRes.json()) as { markdown?: string; cached?: boolean };
      assert.equal(optOutFirstJson.cached, false);
      assert.match(optOutFirstJson.markdown ?? '', /Unblocked Tracker Variant Marker/);

      // Step B: Default scrape (`blockTrackers` omitted = true) with `maxAgeMs: 60_000` -> MUST miss canonical cache and fetch live Blocked Variant!
      const defaultSecondRes = await fetch(`${baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://cache-iso.example.com/page', maxAgeMs: 60_000 }),
      });
      assert.equal(defaultSecondRes.status, 200);
      const defaultSecondJson = (await defaultSecondRes.json()) as { markdown?: string; cached?: boolean };
      assert.equal(defaultSecondJson.cached, false);
      assert.match(defaultSecondJson.markdown ?? '', /Blocked Variant Marker/);

      // Step C: `blockTrackers: false` + `redactPii: true` + `maxAgeMs: 60_000` on a URL with canonical cache -> MUST NOT return Blocked Variant!
      const canonicalSeedRes = await fetch(`${baseUrl}/v1/scrape`, {
        method: 'POST',
        headers: { authorization: `Bearer ${OWNER_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://redact-iso.example.com/page', maxAgeMs: 60_000 }),
      });
      assert.equal(canonicalSeedRes.status, 200);

      const redactOptOutRes = await fetch(`${baseUrl}/v1/scrape`, {
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
      const extractRes = await fetch(`${baseUrl}/v1/extract`, {
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

      ws.close();
    } finally {
      await hub.close();
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
  } finally {
    process.off('unhandledRejection', onUnhandled);
    rmSync(tmp, { recursive: true, force: true });
  }
});
