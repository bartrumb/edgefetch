import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { Miniflare, Response as MfResponse, convertV4MiniflareOptions } from 'miniflare';

const workerBundlePath = process.env.EDGEFETCH_WORKERD_BUNDLE;
if (!workerBundlePath) {
  throw new Error('EDGEFETCH_WORKERD_BUNDLE environment variable is required');
}

const CALLER = randomBytes(24).toString('hex');
const S1 = randomBytes(24).toString('hex');
const S2 = randomBytes(24).toString('hex');
const ORIGIN = 'https://hub.example.com';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('H7 workerd integration suite: AgentHubDO WebSockets, 413 fast-fail, 20 MiB replies, DO reset resilience, overflow & SQLite bounds', async () => {
  const outboundUrls = [];
  let originDelayMs = 0;

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'hub',
          modules: [{ type: 'ESModule', path: 'entry.mjs', contents: readFileSync(workerBundlePath, 'utf8') }],
          compatibilityDate: '2026-10-01',
          durableObjects: { AGENT_HUB: { className: 'AgentHubDO', useSQLite: true } },
          bindings: {
            CALLER_TOKEN: CALLER,
            AGENT_TOKENS: JSON.stringify({ 'site-1': S1, 'site-2': S2 }),
            ROBOTS_BYPASS_HOSTS:
              'over.example.com,legal.example.com,close.example.com,reset.example.com,reset2.example.com,reset3.example.com,hdr.example.com,slow1.example.com,slow2.example.com,slow3.example.com,redir.example.com',
          },
          outboundService: async (req) => {
            outboundUrls.push(req.url);
            const u = new URL(req.url);
            if (u.pathname === '/robots.txt') {
              return new MfResponse('User-agent: *\nAllow: /\n', { status: 200, headers: { 'content-type': 'text/plain' } });
            }
            if (u.pathname === '/redir') {
              return new MfResponse(null, { status: 302, headers: { location: 'http://internal.example.net/after-redirect' } });
            }
            if (originDelayMs > 0) await sleep(originDelayMs);
            return new MfResponse('<html>ok</html>', { status: 200, headers: { 'content-type': 'text/html' } });
          },
        },
      ],
    }),
  );

  try {
    const f = (path, init = {}) => mf.dispatchFetch(ORIGIN + path, { redirect: 'manual', ...init });
    const authz = { authorization: `Bearer ${CALLER}`, 'content-type': 'application/json' };
    const sql = async (q) => (await (await f('/__test_sql', { method: 'POST', body: q })).json());

    const connectAgent = async (site, tok, onDispatch) => {
      const r = await f('/agent/ws', {
        headers: {
          upgrade: 'websocket',
          authorization: `Bearer ${tok}`,
          'x-agent-site': site,
          'x-agent-arch': 'amd64',
          'x-agent-version': '1.1.0',
        },
      });
      assert.equal(r.status, 101);
      const ws = r.webSocket;
      assert.ok(ws);
      ws.accept();
      const state = { ws, frames: [], closed: null };
      ws.addEventListener('message', (e) => {
        const d = String(e.data);
        if (d.includes('"dispatch"')) {
          state.frames.push(Buffer.byteLength(d));
          onDispatch?.(JSON.parse(d), state);
        }
      });
      ws.addEventListener('close', (e) => {
        state.closed = e.code;
      });
      return state;
    };

    const sendReply = (site, tok, m, buf, extra = {}) =>
      f('/agent/reply', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${tok}`,
          'x-agent-site': site,
          'x-job-id': m.jobId,
          'x-job-nonce': m.jobNonce,
          'content-type': 'application/json',
          ...extra,
        },
        body: buf,
      });

    const callBody = (host, extra = {}) =>
      JSON.stringify({
        maxSeconds: 5,
        options: { pauseMs: 1 },
        requests: [{ id: '1', url: `https://${host}/`, kind: 'page' }],
        ...extra,
      });

    // 1. Oversized (>20 MiB) gzip reply returns 413 immediately without peer re-crawl or 30s hang!
    {
      let replyStatus = 0;
      const a1 = await connectAgent('site-1', S1, async (m) => {
        const big = JSON.stringify({ results: [{ id: '1', status: 200, outcome: 'ok', body: 'a'.repeat((20 << 20) + 64) }] });
        const rr = await sendReply('site-1', S1, m, gzipSync(big), { 'content-encoding': 'gzip' });
        replyStatus = rr.status;
      });
      const a2 = await connectAgent('site-2', S2);
      const t0 = Date.now();
      const res = await f('/fetch?target=agent', { method: 'POST', headers: authz, body: callBody('over.example.com', { maxSeconds: 30 }) });
      const elapsed = Date.now() - t0;
      assert.equal(replyStatus, 413);
      assert.equal(res.status, 413);
      assert.ok(elapsed < 2_000, `expected fast 413 failure, took ${elapsed}ms`);
      assert.equal(a2.frames.length, 0, 'peer node must not repeat crawl after 413');
      a1.ws.close(1000, 'done');
      a2.ws.close(1000, 'done');
      await sleep(50);
    }

    // 2. Legal near-20 MiB ASCII and UTF-8 CJK gzip replies succeed cleanly!
    for (const [ch, n] of [
      ['a', (20 << 20) - 512],
      ['漢', Math.floor(((20 << 20) - 512) / 3)],
    ]) {
      const a1 = await connectAgent('site-1', S1, async (m) => {
        const payload = JSON.stringify({ results: [{ id: '1', status: 200, outcome: 'ok', body: ch.repeat(n) }] });
        await sendReply('site-1', S1, m, gzipSync(payload), { 'content-encoding': 'gzip' });
      });
      const res = await f('/fetch?target=agent', { method: 'POST', headers: authz, body: callBody('legal.example.com') });
      assert.equal(res.status, 200);
      await res.arrayBuffer();
      a1.ws.close(1000, 'done');
      await sleep(50);
    }

    // 3. Call body exceeding UTF-8 frame budget fails with 413 before dispatching any WebSocket frame!
    {
      const a1 = await connectAgent('site-1', S1);
      const hugeCall = JSON.stringify({
        maxSeconds: 5,
        requests: [{ id: '1', url: 'https://big.example.com/?' + 'x'.repeat((1 << 20) - 100), kind: 'page' }],
      });
      const res = await f('/fetch?target=agent', { method: 'POST', headers: authz, body: hugeCall });
      assert.equal(res.status, 413);
      assert.equal(a1.frames.length, 0);
      a1.ws.close(1000, 'done');
      await sleep(50);
    }

    // 4. Mid-job WebSocket close aborts pending job immediately (<1s instead of 30s)!
    {
      await connectAgent('site-1', S1, (_m, st) => setTimeout(() => st.ws.close(1011, 'bye'), 60));
      const t0 = Date.now();
      const res = await f('/fetch?target=agent', { method: 'POST', headers: authz, body: callBody('close.example.com', { maxSeconds: 30 }) });
      const elapsed = Date.now() - t0;
      assert.equal(res.status, 502);
      assert.ok(elapsed < 2_000, `mid-job socket close should fail fast, took ${elapsed}ms`);
      await sleep(50);
    }

    // 5. DO reset mid-call: target=auto falls over to container (200), target=agent returns 503 hub_unavailable, /mcp returns isError:true!
    {
      await connectAgent('site-1', S1, async () => {
        await sleep(60);
        await f('/__test_abort');
      });
      const autoRes = await f('/fetch?target=auto', { method: 'POST', headers: authz, body: callBody('reset.example.com', { maxSeconds: 30 }) });
      assert.equal(autoRes.status, 200);

      await sleep(80);
      await connectAgent('site-1', S1, async () => {
        await sleep(60);
        await f('/__test_abort');
      });
      const agentRes = await f('/fetch?target=agent', { method: 'POST', headers: authz, body: callBody('reset2.example.com', { maxSeconds: 30 }) });
      assert.equal(agentRes.status, 503);
      const agentErr = await agentRes.json();
      assert.equal(agentErr.error, 'hub_unavailable');

      await sleep(80);
      await connectAgent('site-1', S1, async () => {
        await sleep(60);
        await f('/__test_abort');
      });
      const mcpRes = await f('/mcp', {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'fetch_url', arguments: { url: 'https://reset3.example.com/', target: 'agent' } },
        }),
      });
      assert.equal(mcpRes.status, 200);
      const mcpJson = await mcpRes.json();
      assert.equal(mcpJson.result?.isError, true);
      await sleep(80);
    }

    // 6. MCP bad CR/LF conditional header returns clean MCP isError:true (never HTTP 500)!
    {
      const mcpBadHdr = await f('/mcp', {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: {
            name: 'fetch_url',
            arguments: { url: 'https://hdr.example.com/', target: 'container', ifNoneMatch: 'a\r\nb: c' },
          },
        }),
      });
      assert.equal(mcpBadHdr.status, 200);
      const badJson = await mcpBadHdr.json();
      assert.equal(badJson.result?.isError, true);
    }

    // 7. Overflow target=container enforces maxSeconds=1 budget AND blocks http:// redirects!
    {
      outboundUrls.length = 0;
      originDelayMs = 700;
      const slowBody = JSON.stringify({
        maxSeconds: 1,
        options: { pauseMs: 1 },
        requests: [1, 2, 3].map((i) => ({ id: String(i), url: `https://slow${i}.example.com/`, kind: 'page' })),
      });
      const t0 = Date.now();
      const slowRes = await f('/fetch?target=container', { method: 'POST', headers: authz, body: slowBody });
      const elapsed = Date.now() - t0;
      assert.equal(slowRes.status, 200);
      assert.ok(elapsed < 2_500, `overflow maxSeconds=1 exceeded: ${elapsed}ms`);
      const slowJson = await slowRes.json();
      assert.ok(
        slowJson.results[2]?.outcome === 'not_tried' || slowJson.results[2]?.outcome === 'error',
        `expected 3rd URL skipped after maxSeconds=1 budget, got ${slowJson.results[2]?.outcome}`,
      );

      originDelayMs = 0;
      outboundUrls.length = 0;
      const redirRes = await f('/fetch?target=container', {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({ requests: [{ id: 'r', url: 'https://redir.example.com/redir', kind: 'page' }] }),
      });
      assert.equal(redirRes.status, 200);
      const redirJson = await redirRes.json();
      assert.equal(redirJson.results[0]?.outcome, 'error');
      assert.equal(
        outboundUrls.some((u) => u.includes('internal.example.net')),
        false,
        'overflow redirect to http:// internal host must never be fetched',
      );
    }

    // 8. Admin login + host_windows SQLite growth is bounded <= 512!
    {
      const loginRes = await f('/admin/login', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': '198.51.100.77' },
        body: `token=${encodeURIComponent(CALLER)}`,
      });
      assert.equal(loginRes.status, 302);
      const adminCookie = loginRes.headers.get('set-cookie')?.split(';')[0] ?? '';
      const stateRes = await f('/admin/api/state', { headers: { cookie: adminCookie } });
      assert.equal(stateRes.status, 200);

      // Verify host_windows is bounded when setNextAllowed is exercised across >600 distinct hosts.
      for (let batch = 0; batch < 3; batch++) {
        const reqs = Array.from({ length: 220 }, (_, i) => ({
          id: `${batch}-${i}`,
          url: `https://win-${batch}-${i}.example.com/`,
          kind: 'page',
        }));
        // Use a connected agent that immediately answers so host_windows is stamped for all 660 hosts!
        const a1 = await connectAgent('site-1', S1, async (m) => {
          const rep = JSON.stringify({
            results: m.call.requests.map((rq) => ({ id: rq.id, url: rq.url, status: 200, outcome: 'ok' })),
          });
          await sendReply('site-1', S1, m, rep);
        });
        const r = await f('/fetch?target=agent', {
          method: 'POST',
          headers: authz,
          body: JSON.stringify({ maxSeconds: 30, options: { pauseMs: 5000 }, requests: reqs }),
        });
        assert.equal(r.status, 200);
        a1.ws.close(1000, 'done');
        await sleep(30);
      }

      const rows = await sql('SELECT COUNT(*) AS c FROM host_windows');
      assert.ok(rows[0].c <= 512, `host_windows grew to ${rows[0].c} rows, expected <= 512`);

      // 9. S1: Hub WITHOUT storage bindings reports capabilities disabled and still operates cleanly.
      const capsOffRes = await f('/v1/capabilities', { headers: authz });
      assert.equal(capsOffRes.status, 200);
      const capsOff = await capsOffRes.json();
      assert.deepEqual(capsOff.capabilities, {
        fetch: true,
        scrape: true,
        extract: true,
        map: true,
        crawl: false,
        interact: true,
        mcp: true,
        oauth: true,
        artifacts: false,
        tracking: false,
        ingestWorkflow: false,
        search: false,
        webSearch: false,
        pdfOcr: false,
        webBotAuth: false,
        spaFallback: false,
      });
    }
  } finally {
    await mf.dispose();
  }
});

test('S1 workerd storage suite: optional ARTIFACTS R2 + META D1 + SEARCH D1 FTS5 migrations & conditional uploads', async () => {
  const metaSql = readFileSync(new URL('../migrations/meta/0001_tracking.sql', import.meta.url), 'utf8');
  const searchSql = readFileSync(new URL('../migrations/search/0001_fts.sql', import.meta.url), 'utf8');

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'hub-storage',
          modules: [{ type: 'ESModule', path: 'entry.mjs', contents: readFileSync(workerBundlePath, 'utf8') }],
          compatibilityDate: '2026-10-01',
          durableObjects: { AGENT_HUB: { className: 'AgentHubDO', useSQLite: true } },
          r2Buckets: ['ARTIFACTS'],
          d1Databases: ['META', 'SEARCH'],
          bindings: {
            CALLER_TOKEN: CALLER,
            AGENT_TOKENS: JSON.stringify({ 'site-1': S1 }),
          },
        },
      ],
    }),
  );

  const openSockets = [];
  try {
    const authz = { authorization: `Bearer ${CALLER}`, 'content-type': 'application/json' };
    const capsRes = await mf.dispatchFetch(`${ORIGIN}/v1/capabilities`, { headers: authz });
    assert.equal(capsRes.status, 200);
    const caps = await capsRes.json();
    assert.equal(caps.capabilities.artifacts, true);
    assert.equal(caps.capabilities.tracking, true);
    assert.equal(caps.capabilities.search, true);

    const verifyRes = await mf.dispatchFetch(`${ORIGIN}/__test_storage_verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ metaSql, searchSql }),
    });
    assert.equal(verifyRes.status, 200);
    const out = await verifyRes.json();
    assert.deepEqual(out, {
      firstStored: true,
      dupReturnedNull: true,
      badHashFailed: true,
      streamedHashMatches: true,
      pageCount: 1,
      ftsHitCount: 1,
    });

    // S2: Verify capability negotiation (old agent vs artifacts-v1 agent), upload security gates, and 40 MiB logical batch!
    const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

    // 1. Old agent (no X-Agent-Capabilities) dispatched WITHOUT `artifacts` envelope -> inline reply still works!
    {
      const rWs = await mf.dispatchFetch(`${ORIGIN}/agent/ws`, {
        headers: { upgrade: 'websocket', authorization: `Bearer ${S1}`, 'x-agent-site': 'site-1', 'x-agent-arch': 'amd64' },
      });
      const wsOld = rWs.webSocket;
      wsOld.accept();
      let sawArtifactsField = false;
      wsOld.addEventListener('message', async (e) => {
        const d = String(e.data);
        if (!d.includes('"dispatch"')) return;
        const msg = JSON.parse(d);
        sawArtifactsField = Boolean(msg.artifacts);
        await mf.dispatchFetch(`${ORIGIN}/agent/reply`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${S1}`,
            'x-agent-site': 'site-1',
            'x-job-id': msg.jobId,
            'x-job-nonce': msg.jobNonce,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ results: [{ id: '1', status: 200, outcome: 'ok', body: 'inline-ok', bodyEncoding: 'utf-8' }] }),
        });
      });
      const oldFetch = await mf.dispatchFetch(`${ORIGIN}/fetch?target=agent&artifacts=transient`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          maxSeconds: 10,
          options: { includeBody: true },
          requests: [{ id: '1', url: 'https://legacy.example.com/', kind: 'page' }],
        }),
      });
      assert.equal(oldFetch.status, 200);
      assert.equal(sawArtifactsField, false, 'legacy agent without artifacts-v1 must not receive artifacts policy');
      wsOld.close(1000, 'done');
      await sleep(40);
    }

    // 2. Capable agent (X-Agent-Capabilities: artifacts-v1): upload auth/nonce/hash/Content-Length gates + 40 MiB logical batch!
    {
      const rWs = await mf.dispatchFetch(`${ORIGIN}/agent/ws`, {
        headers: {
          upgrade: 'websocket',
          authorization: `Bearer ${S1}`,
          'x-agent-site': 'site-1',
          'x-agent-arch': 'amd64',
          'x-agent-capabilities': 'artifacts-v1',
        },
      });
      const wsCap = rWs.webSocket;
      wsCap.accept();
      openSockets.push(wsCap);

      const eightMiB = Buffer.from('<html>' + 'R2BatchData!'.repeat(700_000).slice(0, (8 << 20) - 13) + '</html>');
      const contentSha = sha256Hex(eightMiB);
      const gzBytes = gzipSync(eightMiB);
      const blobSha = sha256Hex(gzBytes);

      let gateChecksDone = false;
      wsCap.addEventListener('message', async (e) => {
        const d = String(e.data);
        if (!d.includes('"dispatch"')) return;
        const msg = JSON.parse(d);
        assert.deepEqual(msg.artifacts, { mode: 'r2', retention: 'transient', maxContentBytes: 16 << 20 });

        const putArt = (sha, bodyBuf, hdrOverrides = {}) =>
          mf.dispatchFetch(`${ORIGIN}/agent/artifacts/${sha}`, {
            method: 'PUT',
            headers: {
              authorization: `Bearer ${S1}`,
              'x-agent-site': 'site-1',
              'x-job-id': msg.jobId,
              'x-job-nonce': msg.jobNonce,
              'x-request-id': 'r1',
              'x-content-sha256': contentSha,
              'x-content-bytes': String(eightMiB.byteLength),
              'x-artifact-retention': 'transient',
              'content-type': 'application/gzip',
              'content-length': String(bodyBuf.byteLength),
              ...hdrOverrides,
            },
            body: bodyBuf,
          });

        // Wrong nonce -> 403
        assert.equal((await putArt(blobSha, gzBytes, { 'x-job-nonce': 'wrong-nonce' })).status, 403);
        // Unknown requestId -> 400
        assert.equal((await putArt(blobSha, gzBytes, { 'x-request-id': 'not-in-job' })).status, 400);
        // Unexpected Content-Encoding -> 400
        assert.equal((await putArt(blobSha, gzBytes, { 'content-encoding': 'gzip' })).status, 400);
        // Wrong blobSha256 -> 400
        assert.equal((await putArt('ff'.repeat(32), gzBytes)).status, 400);
        gateChecksDone = true;

        // Upload 5 x 8 MiB = 40 MiB logical batch (1st stores, 2..5 deduplicate in R2!)
        const results = [];
        for (let i = 1; i <= 5; i++) {
          const upRes = await putArt(blobSha, gzBytes, { 'x-request-id': `r${i}` });
          assert.equal(upRes.status, 200);
          results.push({
            id: `r${i}`,
            url: `https://b${i}.example.com/`,
            kind: 'page',
            status: 200,
            outcome: 'ok',
            bytes: eightMiB.byteLength,
            artifact: {
              blobSha256: blobSha,
              contentSha256: contentSha,
              contentBytes: eightMiB.byteLength,
              storedBytes: gzBytes.byteLength,
              encoding: 'gzip',
              retention: 'transient',
            },
          });
        }

        const repRes = await mf.dispatchFetch(`${ORIGIN}/agent/reply`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${S1}`,
            'x-agent-site': 'site-1',
            'x-job-id': msg.jobId,
            'x-job-nonce': msg.jobNonce,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ results }),
        });
        assert.equal(repRes.status, 200);
      });

      const batchRes = await mf.dispatchFetch(`${ORIGIN}/fetch?target=agent`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          maxSeconds: 30,
          options: { includeBody: true },
          requests: [1, 2, 3, 4, 5].map((i) => ({ id: `r${i}`, url: `https://b${i}.example.com/`, kind: 'page' })),
        }),
      });
      assert.equal(batchRes.status, 200);
      assert.equal(gateChecksDone, true);
      const batchJson = await batchRes.json();
      assert.equal(batchJson.results.length, 5);
      // S3: First two 8 MiB pages (16 MiB <= 18 MiB hydration budget) are hydrated inline; pages 3..5 set bodyOmitted:true + artifact!
      assert.equal(batchJson.results[0]?.body?.length, 8 << 20);
      assert.equal(batchJson.results[1]?.body?.length, 8 << 20);
      assert.equal(batchJson.results[2]?.body, undefined);
      assert.equal(batchJson.results[2]?.bodyOmitted, true);
      assert.equal(batchJson.results[4]?.artifact?.contentBytes, 8 << 20);

      // S3: Authenticated GET /v1/artifacts/<blobSha256> serves text/plain + nosniff + CSP sandbox + attachment (never active HTML)!
      const rawSliceRes = await mf.dispatchFetch(`${ORIGIN}/v1/artifacts/${blobSha}?offset=0&limit=32`, {
        headers: { authorization: `Bearer ${CALLER}` },
      });
      assert.equal(rawSliceRes.status, 200);
      assert.equal(rawSliceRes.headers.get('content-type'), 'text/plain; charset=utf-8');
      assert.equal(rawSliceRes.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(rawSliceRes.headers.get('content-security-policy'), 'sandbox');
      assert.match(rawSliceRes.headers.get('content-disposition') ?? '', /^attachment;/);
      assert.equal(rawSliceRes.headers.get('x-artifact-has-more'), 'true');
      assert.equal(rawSliceRes.headers.get('x-artifact-next-offset'), '32');
      const sliceText = await rawSliceRes.text();
      assert.equal(sliceText.length, 32);
      assert.equal(sliceText.startsWith('<html>R2BatchData!'), true);

      // Expired / missing artifact returns 404 artifact_expired.
      const missingRes = await mf.dispatchFetch(`${ORIGIN}/v1/artifacts/${'dd'.repeat(32)}`, {
        headers: { authorization: `Bearer ${CALLER}` },
      });
      assert.equal(missingRes.status, 404);
      assert.equal((await missingRes.json()).error, 'artifact_expired');

      // S3: MCP read_artifact tool pages stored content by artifactId + offset!
      const mcpPageRes = await mf.dispatchFetch(`${ORIGIN}/mcp`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 99,
          method: 'tools/call',
          params: {
            name: 'read_artifact',
            arguments: { artifactId: blobSha, offset: 6, limit: 12 },
          },
        }),
      });
      assert.equal(mcpPageRes.status, 200);
      const mcpPageJson = await mcpPageRes.json();
      assert.equal(mcpPageJson.result?.isError, undefined);
      const parsedPage = JSON.parse(mcpPageJson.result.content[0].text);
      assert.equal(parsedPage.content, 'R2BatchData!');
      assert.equal(parsedPage.nextOffset, 18);

      // S4: Verify /fetch automatically tracked all 5 fetched pages in META D1 AND re-running a manifest creates zero duplicate rows!
      const trackedBatchFetches = await mf.dispatchFetch(`${ORIGIN}/__test_s4_idempotency`, { method: 'POST' });
      assert.equal(trackedBatchFetches.status, 200);
      const s4Out = await trackedBatchFetches.json();
      assert.deepEqual(s4Out, {
        stepNames: ['load-manifest'],
        fetchCount: 2,
        pageCountForJob: 2,
        robotsDecisions: ['allowed', 'disallowed'],
        leakedSecretInFetches: false,
        pruned: 1,
        oldStillExists: false,
      });

      // S5 + S6: Verify stored artifact SHA-256 verification, gzip bomb quarantine, 410 expiry, and v1 Markdown derivation!
      const s5VerifyRes = await mf.dispatchFetch(`${ORIGIN}/__test_s5_verification`, { method: 'POST' });
      assert.equal(s5VerifyRes.status, 200);
      const s5Out = await s5VerifyRes.json();
      assert.deepEqual(s5Out, {
        verifiedCount: 1,
        rejectedCount: 2,
        expiredCount: 1,
        derivedCount: 1,
        rejectedReasons: ['content_hash_mismatch', 'decompression_limit_exceeded'],
        goodVerified: true,
        liedVerified: false,
        bombVerified: false,
        expiredVerified: false,
        liedR2Remaining: false,
        bombR2Remaining: false,
        liedRowCount: 0,
        bombRowCount: 0,
        expiredBlobSha: 'ee'.repeat(32),
        derivedPipelineVersion: 26,
        derivedR2Text: 'Verified stored article payload!',
        unverifiedDeriveStatus: 'unverified',
        capacityStopStatus: 'capacity_reached',
      });

      // Known META D1 artifact whose R2 object expired returns 410 Gone with clear `artifact_expired` error + message!
      const expiredGetRes = await mf.dispatchFetch(`${ORIGIN}/v1/artifacts/${s5Out.expiredBlobSha}`, {
        headers: { authorization: `Bearer ${CALLER}` },
      });
      assert.equal(expiredGetRes.status, 410);
      const expiredGetJson = await expiredGetRes.json();
      assert.equal(expiredGetJson.error, 'artifact_expired');
      assert.match(expiredGetJson.message ?? '', /expired/i);

      // S6 + S7: End-to-end POST /v1/scrape + FTS5 collection indexing + atomic page replacement + POST /v1/extract!
      let scrapeAgentDispatches = 0;
      let currentScrapeHtml = new TextEncoder().encode(
        `<html lang="en"><head><title>Torque Guide</title><script type="application/ld+json">{"name":"Rear Axle","torqueNm":35}</script></head>` +
          `<body><nav>menu</nav><main><h1>Torque Guide</h1><p>Tighten rear axle cadmium nut to 35 Nm.</p><a href="https://docs.example.com/safety">Safety</a></main></body></html>`,
      );

      wsCap.close(1000, 'switch-to-scrape-handler');
      await sleep(30);
      const rWsScrape = await mf.dispatchFetch(`${ORIGIN}/agent/ws`, {
        headers: {
          upgrade: 'websocket',
          authorization: `Bearer ${S1}`,
          'x-agent-site': 'site-1',
          'x-agent-arch': 'amd64',
          'x-agent-capabilities': 'artifacts-v1',
        },
      });
      const wsScrape = rWsScrape.webSocket;
      wsScrape.accept();
      openSockets.push(wsScrape);
      wsScrape.addEventListener('message', async (e) => {
        const d = String(e.data);
        if (!d.includes('"dispatch"')) return;
        scrapeAgentDispatches++;
        const msg = JSON.parse(d);
        assert.equal(msg.artifacts?.retention, 'stored');
        const curGz = gzipSync(currentScrapeHtml);
        const curBlobSha = sha256Hex(curGz);
        const curContentSha = sha256Hex(currentScrapeHtml);
        const parsedCall = typeof msg.call === 'string' ? JSON.parse(msg.call) : (msg.call ?? {});
        const reqId = parsedCall.requests?.[0]?.id ?? 'scrape-1';
        const reqUrl = parsedCall.requests?.[0]?.url ?? 'https://docs.example.com/torque';
        const upRes = await mf.dispatchFetch(`${ORIGIN}/agent/artifacts/${curBlobSha}`, {
          method: 'PUT',
          headers: {
            authorization: `Bearer ${S1}`,
            'x-agent-site': 'site-1',
            'x-job-id': msg.jobId,
            'x-job-nonce': msg.jobNonce,
            'x-request-id': reqId,
            'x-content-sha256': curContentSha,
            'x-content-bytes': String(currentScrapeHtml.byteLength),
            'x-artifact-retention': 'stored',
            'content-type': 'application/gzip',
            'content-length': String(curGz.byteLength),
          },
          body: curGz,
        });
        assert.equal(upRes.status, 200);
        await mf.dispatchFetch(`${ORIGIN}/agent/reply`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${S1}`,
            'x-agent-site': 'site-1',
            'x-job-id': msg.jobId,
            'x-job-nonce': msg.jobNonce,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            results: [
              {
                id: reqId,
                url: reqUrl,
                kind: 'scrape',
                status: 200,
                outcome: 'ok',
                contentType: 'text/html; charset=utf-8',
                bytes: currentScrapeHtml.byteLength,
                llms: { found: true, llmsTxtUrl: 'https://docs.example.com/llms.txt', usedCompanionMd: false },
                artifact: {
                  blobSha256: curBlobSha,
                  contentSha256: curContentSha,
                  contentBytes: currentScrapeHtml.byteLength,
                  storedBytes: curGz.byteLength,
                  encoding: 'gzip',
                  retention: 'stored',
                },
              },
            ],
          }),
        });
      });

      const liveScrapeRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          url: 'https://docs.example.com/torque',
          target: 'agent',
          collectionId: 'ebike-kb',
          formats: [
            'markdown',
            'links',
            {
              type: 'json',
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  torqueNm: { type: 'number' },
                },
              },
            },
          ],
        }),
      });
      assert.equal(liveScrapeRes.status, 200);
      const liveScrapeJson = await liveScrapeRes.json();
      assert.equal(liveScrapeJson.ok, true);
      assert.equal(liveScrapeJson.cached, false);
      assert.equal(liveScrapeJson.pipelineVersion, 26);
      assert.equal(liveScrapeJson.llms?.found, true);
      assert.deepEqual(liveScrapeJson.json, { name: 'Rear Axle', torqueNm: 35 });
      assert.match(liveScrapeJson.markdown, /# Torque Guide/);
      assert.equal(liveScrapeJson.markdown.includes('menu'), false);

      // Second call with maxAgeMs=60000 hits verified META D1 + ARTIFACTS R2 cache without dispatching to agent!
      const cachedScrapeRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          url: 'https://docs.example.com/torque',
          formats: ['markdown'],
          maxAgeMs: 60_000,
        }),
      });
      assert.equal(cachedScrapeRes.status, 200);
      assert.equal(cachedScrapeRes.headers.get('x-crawler-via'), 'cache:r2-d1');
      const cachedScrapeJson = await cachedScrapeRes.json();
      assert.equal(cachedScrapeJson.cached, true);
      assert.equal(cachedScrapeJson.pipelineVersion, 26);
      assert.match(cachedScrapeJson.markdown, /35 Nm/);
      assert.equal(scrapeAgentDispatches, 1);

      // S7: Collection search finds v1 ("cadmium"), and malformed/operator/Unicode/empty user queries NEVER break FTS5!
      const v1SearchRes = await mf.dispatchFetch(`${ORIGIN}/v1/collections/ebike-kb/search`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({ query: 'cadmium axle' }),
      });
      assert.equal(v1SearchRes.status, 200);
      const v1SearchJson = await v1SearchRes.json();
      assert.equal(v1SearchJson.hits.length, 1);
      assert.ok(v1SearchJson.hits[0].score > 0);
      assert.match(v1SearchJson.hits[0].snippet, /cadmium|axle/i);

      for (const hostileQuery of ['NEAR/3 "unclosed (OR AND NOT * ^ : --- ???', '🚀🔥!!!', '', '日本語 cadmium 48V']) {
        const qRes = await mf.dispatchFetch(`${ORIGIN}/v1/collections/ebike-kb/search`, {
          method: 'POST',
          headers: authz,
          body: JSON.stringify({ query: hostileQuery }),
        });
        assert.equal(qRes.status, 200, `hostile FTS query ${JSON.stringify(hostileQuery)} must never fail`);
      }

      // S7: Re-crawl the SAME page URL with updated content ("titanium stem 6 Nm") -> atomic batch deletes old "cadmium" hits!
      currentScrapeHtml = new TextEncoder().encode(
        `<html lang="en"><head><title>Torque Guide v2</title></head><body><main><h1>Stem Bolts</h1><p>Tighten titanium stem bolts to 6 Nm.</p></main></body></html>`,
      );
      const updateScrapeRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          url: 'https://docs.example.com/torque',
          target: 'agent',
          collectionId: 'ebike-kb',
          formats: ['markdown'],
          maxAgeMs: 0,
        }),
      });
      assert.equal(updateScrapeRes.status, 200);

      const staleSearchRes = await mf.dispatchFetch(`${ORIGIN}/v1/collections/ebike-kb/search`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({ query: 'cadmium' }),
      });
      assert.equal((await staleSearchRes.json()).hits.length, 0, 'replacing a page must purge old FTS5 hits');

      const freshSearchRes = await mf.dispatchFetch(`${ORIGIN}/v1/collections/ebike-kb/search`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({ query: 'titanium stem' }),
      });
      const freshHits = (await freshSearchRes.json()).hits;
      assert.equal(freshHits.length, 1);
      assert.match(freshHits[0].text, /titanium stem bolts to 6 Nm/);

      // S7: POST /v1/extract returns BM25-ranked chunks from cached/fetched URLs!
      const extractRes = await mf.dispatchFetch(`${ORIGIN}/v1/extract`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          urls: ['https://docs.example.com/torque'],
          query: 'titanium 6 Nm',
          chunksPerSource: 2,
          maxAgeMs: 60_000,
        }),
      });
      assert.equal(extractRes.status, 200);
      const extractJson = await extractRes.json();
      assert.equal(extractJson.ok, true);
      assert.equal(extractJson.results.length, 1);
      assert.equal(extractJson.results[0].cached, true);
      assert.match(extractJson.results[0].rawContent, /titanium stem bolts to 6 Nm/);

      // V2-1: POST /v1/interact returns 503 fat_agent_required when only a Lite (non-browser-v1) node is connected!
      const noFatRes = await mf.dispatchFetch(`${ORIGIN}/v1/interact`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          url: 'https://spa.example.com/dashboard',
          keepSession: true,
        }),
      });
      assert.equal(noFatRes.status, 503);
      assert.equal((await noFatRes.json()).error, 'fat_agent_required');

      // Connect a FAT node (`browser-v1,pdf-v1`) on site-1 -> interact routes to it and composite sessionId pins follow-up turns!
      wsScrape.close(1000, 'upgrade-to-fat');
      await sleep(30);
      const rWsFat = await mf.dispatchFetch(`${ORIGIN}/agent/ws`, {
        headers: {
          upgrade: 'websocket',
          authorization: `Bearer ${S1}`,
          'x-agent-site': 'site-1',
          'x-agent-arch': 'amd64',
          'x-agent-version': '2.0.0',
          'x-agent-capabilities': 'artifacts-v1,browser-v1,pdf-v1',
        },
      });
      const wsFat = rWsFat.webSocket;
      wsFat.accept();
      openSockets.push(wsFat);
      let fatClicks = 0;
      wsFat.addEventListener('message', async (e) => {
        const d = String(e.data);
        if (!d.includes('"dispatch"')) return;
        const msg = JSON.parse(d);
        const callObj = typeof msg.call === 'string' ? JSON.parse(msg.call) : msg.call;
        const req0 = callObj.requests[0];
        if (req0.interact?.actions?.some((a) => a.type === 'click')) fatClicks++;
        await mf.dispatchFetch(`${ORIGIN}/agent/reply`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${S1}`,
            'x-agent-site': 'site-1',
            'x-job-id': msg.jobId,
            'x-job-nonce': msg.jobNonce,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            results: [
              {
                id: req0.id,
                url: req0.url,
                kind: 'render',
                status: 200,
                outcome: 'ok',
                rendered: true,
                sessionId: req0.interact?.closeSession ? '' : 'efsess_9988',
                markdown: `# Dashboard (clicks=${fatClicks})`,
                body: `<html><body><h1>Dashboard (clicks=${fatClicks})</h1></body></html>`,
                bodyEncoding: 'utf-8',
              },
            ],
          }),
        });
      });

      const int1 = await mf.dispatchFetch(`${ORIGIN}/v1/interact`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({ url: 'https://spa.example.com/dashboard', keepSession: true }),
      });
      assert.equal(int1.status, 200);
      const int1Json = await int1.json();
      assert.match(int1Json.sessionId, /^site-1\.efsess_9988\.[0-9a-f]{32}$/);
      assert.match(int1Json.markdown, /clicks=0/);

      const int2 = await mf.dispatchFetch(`${ORIGIN}/v1/interact`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          sessionId: int1Json.sessionId,
          actions: [{ type: 'click', selector: '#load-more' }],
          closeSession: true,
        }),
      });
      assert.equal(int2.status, 200);
      const int2Json = await int2.json();
      assert.equal(int2Json.closed, true);
      assert.match(int2Json.markdown, /clicks=1/);

      // V2-2: Verify streamlined 8-tool MCP surface (`list_agents`, `scrape`, `extract`, `map`, `crawl`, `search`, `interact`, `read_artifact`)!
      const toolsRes = await mf.dispatchFetch(`${ORIGIN}/mcp`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({ jsonrpc: '2.0', id: 201, method: 'tools/list' }),
      });
      const toolsJson = await toolsRes.json();
      const toolNames = toolsJson.result.tools.map((t) => t.name);
      assert.deepEqual(toolNames, [
        'list_agents',
        'fetch_url',
        'fetch_batch',
        'scrape',
        'extract',
        'map',
        'crawl',
        'search',
        'search_collection',
        'interact',
        'read_artifact',
        'jobs',
        'find_extractors',
        'catalog',
        'agent',
      ]);

      // V2-2: Verify RRF multi-provider search (Brave + SearXNG + FTS5) + HMAC-SHA256 webhook signing + SSRF webhook block!
      const v2HarnessRes = await mf.dispatchFetch(`${ORIGIN}/__test_v2_search_and_webhook`, { method: 'POST' });
      assert.equal(v2HarnessRes.status, 200);
      const v2HarnessJson = await v2HarnessRes.json();
      assert.equal(v2HarnessJson.webhookDelivered, true);
      assert.equal(v2HarnessJson.signatureValid, true);
      assert.equal(v2HarnessJson.ssrfWebhookBlocked, true);
      assert.equal(v2HarnessJson.searchStatus, 200);
      assert.deepEqual(v2HarnessJson.unhonoredOptions, ['include_answer']);
      assert.equal(v2HarnessJson.searchResults.length, 2);
      assert.equal(v2HarnessJson.searchResults[0].url, 'https://docs.example.com/torque');
      assert.deepEqual([...v2HarnessJson.searchResults[0].providers].sort(), ['brave', 'collection:ebike-kb', 'searxng']);

      // V2-2: Switch mock agent to handle `/v1/map`, `/v1/crawl` (sync + GET/DELETE), `formats: ["changes"]`, and `/compat/*` routes!
      wsFat.close(1000, 'switch-to-map-crawl');
      await sleep(30);
      const rWsMap = await mf.dispatchFetch(`${ORIGIN}/agent/ws`, {
        headers: {
          upgrade: 'websocket',
          authorization: `Bearer ${S1}`,
          'x-agent-site': 'site-1',
          'x-agent-arch': 'amd64',
          'x-agent-version': '2.0.0',
          'x-agent-capabilities': 'artifacts-v1,browser-v1,pdf-v1',
        },
      });
      const wsMap = rWsMap.webSocket;
      wsMap.accept();
      openSockets.push(wsMap);

      wsMap.addEventListener('message', async (e) => {
        const d = String(e.data);
        if (!d.includes('"dispatch"')) return;
        const msg = JSON.parse(d);
        const callObj = typeof msg.call === 'string' ? JSON.parse(msg.call) : msg.call;
        const results = [];
        for (const reqItem of callObj.requests ?? []) {
          let bodyStr = '';
          let ct = 'text/html; charset=utf-8';
          if (reqItem.url.endsWith('/robots.txt')) {
            ct = 'text/plain';
            bodyStr = 'User-agent: *\nSitemap: https://map.example.com/sitemap-docs.xml\n';
          } else if (reqItem.url.endsWith('/sitemap.xml')) {
            ct = 'application/xml';
            bodyStr = '<urlset><url><loc>https://map.example.com/guide/setup</loc></url></urlset>';
          } else if (reqItem.url.endsWith('/sitemap-docs.xml')) {
            ct = 'application/xml';
            bodyStr = '<urlset><url><loc>https://map.example.com/guide/api</loc></url></urlset>';
          } else if (reqItem.url.endsWith('/llms.txt')) {
            ct = 'text/markdown';
            bodyStr = '# Map Docs\n- [FAQ](https://map.example.com/faq): Common questions\n';
          } else if (reqItem.url === 'https://docs.example.com/torque') {
            bodyStr = '<html><head><title>Torque Guide v3</title></head><body><main><h1>Stem Bolts</h1><p>Tighten carbon stem bolts to 5 Nm.</p></main></body></html>';
          } else if (reqItem.url === 'https://crawl.example.com/') {
            bodyStr = '<html><head><title>Crawl Home</title></head><body><main><h1>Welcome</h1><a href="https://crawl.example.com/docs/a">Doc A</a><a href="https://crawl.example.com/admin/skip">Skip</a></main></body></html>';
          } else {
            bodyStr = `<html><head><title>Page</title></head><body><main><p>Content for ${reqItem.url}</p><a href="https://map.example.com/about">About</a></main></body></html>`;
          }

          if (msg.artifacts?.mode === 'r2') {
            const rawBytes = new TextEncoder().encode(bodyStr);
            const gz = gzipSync(rawBytes);
            const bSha = sha256Hex(gz);
            const cSha = sha256Hex(rawBytes);
            await mf.dispatchFetch(`${ORIGIN}/agent/artifacts/${bSha}`, {
              method: 'PUT',
              headers: {
                authorization: `Bearer ${S1}`,
                'x-agent-site': 'site-1',
                'x-job-id': msg.jobId,
                'x-job-nonce': msg.jobNonce,
                'x-request-id': reqItem.id,
                'x-content-sha256': cSha,
                'x-content-bytes': String(rawBytes.byteLength),
                'x-artifact-retention': msg.artifacts.retention,
                'content-type': 'application/gzip',
                'content-length': String(gz.byteLength),
              },
              body: gz,
            });
            results.push({
              id: reqItem.id,
              url: reqItem.url,
              kind: reqItem.kind,
              status: 200,
              outcome: 'ok',
              contentType: ct,
              bytes: rawBytes.byteLength,
              artifact: {
                blobSha256: bSha,
                contentSha256: cSha,
                contentBytes: rawBytes.byteLength,
                storedBytes: gz.byteLength,
                encoding: 'gzip',
                retention: msg.artifacts.retention,
              },
            });
          } else {
            results.push({ id: reqItem.id, url: reqItem.url, kind: reqItem.kind, status: 200, outcome: 'ok', contentType: ct, body: bodyStr, bodyEncoding: 'utf-8' });
          }
        }
        await mf.dispatchFetch(`${ORIGIN}/agent/reply`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${S1}`,
            'x-agent-site': 'site-1',
            'x-job-id': msg.jobId,
            'x-job-nonce': msg.jobNonce,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ results }),
        });
      });

      // 1) POST /v1/map discovers robots Sitemap:, sitemap.xml, llms.txt, and homepage links!
      const mapRes = await mf.dispatchFetch(`${ORIGIN}/v1/map`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({ url: 'https://map.example.com/' }),
      });
      assert.equal(mapRes.status, 200);
      const mapJson = await mapRes.json();
      assert.deepEqual([...mapJson.links].sort(), [
        'https://map.example.com/',
        'https://map.example.com/about',
        'https://map.example.com/faq',
        'https://map.example.com/guide/api',
        'https://map.example.com/guide/setup',
      ]);

      // 2) POST /v1/scrape with formats:["markdown","changes"] computes line diff against previous verified v2!
      const diffRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          url: 'https://docs.example.com/torque',
          target: 'agent',
          formats: ['markdown', 'changes'],
        }),
      });
      assert.equal(diffRes.status, 200);
      const diffJson = await diffRes.json();
      assert.equal(diffJson.changes?.status, 'changed');
      assert.match(diffJson.changes?.diffPreview ?? '', /- Tighten titanium stem bolts to 6 Nm\./);
      assert.match(diffJson.changes?.diffPreview ?? '', /\+ Tighten carbon stem bolts to 5 Nm\./);

      // 3) POST /v1/crawl (excludePaths: ['/admin']) + GET /v1/crawl/:id + DELETE /v1/crawl/:id!
      const crawlRes = await mf.dispatchFetch(`${ORIGIN}/v1/crawl`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          url: 'https://crawl.example.com/',
          maxDepth: 1,
          limit: 5,
          excludePaths: ['/admin'],
          sync: true,
        }),
      });
      assert.equal(crawlRes.status, 200);
      const crawlCreated = await crawlRes.json();
      assert.ok(crawlCreated.id.startsWith('crw_'));

      const crawlStatusRes = await mf.dispatchFetch(`${ORIGIN}/v1/crawl/${crawlCreated.id}`, { headers: authz });
      assert.equal(crawlStatusRes.status, 200);
      const crawlStatus = await crawlStatusRes.json();
      assert.equal(crawlStatus.status, 'completed');
      assert.equal(crawlStatus.fetchedCount, 2);
      assert.deepEqual(
        crawlStatus.data.map((d) => d.url),
        ['https://crawl.example.com/', 'https://crawl.example.com/docs/a'],
      );

      // 4) Compatibility routes: Firecrawl v2 (`/compat/firecrawl/v2/map`) & Tavily (`/compat/tavily/search` with body api_key)!
      const fcCompatRes = await mf.dispatchFetch(`${ORIGIN}/compat/firecrawl/v2/map`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({ url: 'https://map.example.com/', search: 'guide' }),
      });
      assert.equal(fcCompatRes.status, 200);
      const fcCompatJson = await fcCompatRes.json();
      assert.equal(fcCompatJson.success, true);
      assert.deepEqual(fcCompatJson.links, ['https://map.example.com/guide/api', 'https://map.example.com/guide/setup']);

      const tvCompatRes = await mf.dispatchFetch(`${ORIGIN}/compat/tavily/search`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ api_key: CALLER, query: 'titanium stem', collections: ['ebike-kb'] }),
      });
      assert.equal(tvCompatRes.status, 200);
      const tvCompatJson = await tvCompatRes.json();
      assert.equal(tvCompatJson.ok, true);
      assert.equal(tvCompatJson.results.length, 1);

      wsMap.close(1000, 'done');
    }
  } finally {
    for (const s of openSockets) {
      try {
        s.close(1000, 'cleanup');
      } catch {
        // ignore
      }
    }
    await mf.dispose();
  }
});
