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
        mcp: true,
        oauth: true,
        artifacts: false,
        tracking: false,
        ingestWorkflow: false,
        search: false,
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

      wsCap.close(1000, 'done');
    }
  } finally {
    await mf.dispose();
  }
});
