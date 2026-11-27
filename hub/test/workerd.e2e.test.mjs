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
const wasmBundlePath = process.env.EDGEFETCH_WASM_PATH || new URL('../src/edgefetch-core.wasm', import.meta.url);
const WORKERD_MODULES = [
  { type: 'ESModule', path: 'entry.mjs', contents: readFileSync(workerBundlePath, 'utf8') },
  { type: 'CompiledWasm', path: 'edgefetch-core.wasm', contents: readFileSync(wasmBundlePath) },
];

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
          modules: WORKERD_MODULES,
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
      // 8a. 10 consecutive 2 MB `/v1/scrape` sanitize calls inside `workerd` complete with 0 `exceededMemory` crashes!
      const twoMbHtmlChunk = '<p>Safe prose &lt;not-a-tag&gt; and raw angle brackets a &lt; b &amp; c < d for 2 MB sanitize steady-state test. </p>\n';
      const twoMbHtmlDoc =
        '<!doctype html><html><head><title>2MB Steady Doc</title></head><body><article>' +
        twoMbHtmlChunk.repeat(Math.ceil((2 * 1024 * 1024) / twoMbHtmlChunk.length)) +
        '</article></body></html>';
      for (let i = 0; i < 10; i++) {
        const a1 = await connectAgent('site-1', S1, async (m) => {
          const rq = m.call.requests[0];
          const rep = JSON.stringify({
            results: [
              {
                id: rq.id,
                url: rq.url,
                finalUrl: rq.url,
                status: 200,
                outcome: 'ok',
                headers: { 'content-type': 'text/html; charset=utf-8' },
                body: twoMbHtmlDoc,
              },
            ],
          });
          await sendReply('site-1', S1, m, gzipSync(rep), { 'content-encoding': 'gzip' });
        });
        const sc2mRes = await f('/v1/scrape', {
          method: 'POST',
          headers: authz,
          body: JSON.stringify({
            url: `https://legal.example.com/2mb-doc-${i}`,
            target: 'agent',
            ephemeral: true,
            formats: ['markdown'],
          }),
        });
        assert.equal(sc2mRes.status, 200, `2 MB workerd scrape #${i + 1} failed with HTTP ${sc2mRes.status}`);
        const sc2mJson = await sc2mRes.json();
        assert.equal(sc2mJson.ok, true);
        assert.ok(typeof sc2mJson.markdown === 'string' && sc2mJson.markdown.length > 1_500_000);
        assert.equal(/<[a-z!/]/i.test(sc2mJson.markdown), false);
        a1.ws.close(1000, 'done');
        await sleep(20);
      }
    }
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
          modules: WORKERD_MODULES,
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

      // Expired / missing artifact returns 404 artifact_not_found.
      const missingRes = await mf.dispatchFetch(`${ORIGIN}/v1/artifacts/${'dd'.repeat(32)}`, {
        headers: { authorization: `Bearer ${CALLER}` },
      });
      assert.equal(missingRes.status, 404);
      assert.equal((await missingRes.json()).error, 'artifact_not_found');

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
        derivedPipelineVersion: 36,
        derivedR2Text: 'Verified stored article payload!',
        unverifiedDeriveStatus: 'unverified',
        capacityStopStatus: 'capacity_reached',
      });

      // Known META D1 artifact whose R2 object expired returns 404 with consistent `artifact_not_found` error + message!
      const expiredGetRes = await mf.dispatchFetch(`${ORIGIN}/v1/artifacts/${s5Out.expiredBlobSha}`, {
        headers: { authorization: `Bearer ${CALLER}` },
      });
      assert.equal(expiredGetRes.status, 404);
      const expiredGetJson = await expiredGetRes.json();
      assert.equal(expiredGetJson.error, 'artifact_not_found');
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
      assert.equal(liveScrapeJson.pipelineVersion, 36);
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
      assert.equal(cachedScrapeJson.pipelineVersion, 36);
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
      assert.equal(v1SearchJson.hits[0].snippet, undefined);
      assert.match(v1SearchJson.hits[0].text, /cadmium|axle/i);

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
      assert.equal(extractJson.results[0].rawContent, undefined);
      assert.match(extractJson.results[0].chunks[0].text, /titanium stem bolts to 6 Nm/);

      // V2-1: POST /v1/interact returns 503 browser_worker_required when only a Lite (non-browser-v1) node is connected!
      const noFatRes = await mf.dispatchFetch(`${ORIGIN}/v1/interact`, {
        method: 'POST',
        headers: authz,
        body: JSON.stringify({
          url: 'https://spa.example.com/dashboard',
          keepSession: true,
        }),
      });
      assert.equal(noFatRes.status, 503);
      assert.equal((await noFatRes.json()).error, 'browser_worker_required');

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
        'discover_mcps',
        'query_mcp',
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

function extractOtlpSpansFromPayload(payload) {
  const out = [];
  for (const rs of payload?.resourceSpans ?? []) {
    const resourceAttrs = {};
    for (const a of rs?.resource?.attributes ?? []) {
      const v = a?.value;
      resourceAttrs[a.key] =
        v?.boolValue !== undefined
          ? v.boolValue
          : v?.intValue !== undefined
            ? Number(v.intValue)
            : v?.doubleValue !== undefined
              ? v.doubleValue
              : v?.stringValue;
    }
    for (const ss of rs?.scopeSpans ?? []) {
      for (const s of ss?.spans ?? []) {
        const attrs = {};
        for (const a of s?.attributes ?? []) {
          const v = a?.value;
          attrs[a.key] =
            v?.boolValue !== undefined
              ? v.boolValue
              : v?.intValue !== undefined
                ? Number(v.intValue)
                : v?.doubleValue !== undefined
                  ? v.doubleValue
                  : v?.stringValue;
        }
        out.push({ ...s, attrs, resourceAttrs });
      }
    }
  }
  return out;
}

test('F15.1 workerd E2E: /v1/scrape (SSR HTML, declarative YAML twin, 304 Not Modified) & multi-turn /v1/interact lifecycle', async () => {
  const metaSql = readFileSync(new URL('../migrations/meta/0001_tracking.sql', import.meta.url), 'utf8');
  const searchSql = readFileSync(new URL('../migrations/search/0001_fts.sql', import.meta.url), 'utf8');
  const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

  const outboundUrls = [];
  const otlpPayloads = [];

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'hub-f15-1',
          modules: WORKERD_MODULES,
          compatibilityDate: '2026-10-01',
          durableObjects: { AGENT_HUB: { className: 'AgentHubDO', useSQLite: true } },
          r2Buckets: ['ARTIFACTS'],
          d1Databases: ['META', 'SEARCH'],
          bindings: {
            CALLER_TOKEN: CALLER,
            AGENT_TOKENS: JSON.stringify({ 'site-1': S1 }),
            ROBOTS_BYPASS_HOSTS: 'ssr.example.com,rubygems.org,reval.example.com,spa.example.com',
            OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com/v1/traces',
            OTEL_SERVICE_NAME: 'edgefetch-workerd-f15-1',
          },
          outboundService: async (req) => {
            const u = new URL(req.url);
            if (u.origin === 'https://otel.example.com' && u.pathname === '/v1/traces') {
              const txt = await req.text();
              otlpPayloads.push(JSON.parse(txt));
              return new MfResponse('{}', { status: 200, headers: { 'content-type': 'application/json' } });
            }
            outboundUrls.push(req.url);
            if (u.pathname === '/robots.txt') {
              return new MfResponse('User-agent: *\nAllow: /\n', { status: 200, headers: { 'content-type': 'text/plain' } });
            }
            if (u.hostname === 'ssr.example.com' && u.pathname === '/guide') {
              return new MfResponse(
                '<html lang="en"><head><title>Edge SSR Guide</title></head><body><nav>ignore-sidebar-nav</nav><main><h1>Edge SSR Guide</h1><p>Server-rendered HTML extracted cleanly inside workerd.</p></main></body></html>',
                { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } },
              );
            }
            if (u.hostname === 'ssr.example.com' && u.pathname === '/inertia') {
              const pageJson = JSON.stringify({
                component: 'Docs/Overview',
                props: {
                  title: 'Inertia SSR Overview',
                  body: 'Hydrated directly from Inertia data-page props without launching headless Chromium.',
                },
                url: '/inertia',
                version: '1',
              }).replace(/"/g, '&quot;');
              return new MfResponse(
                `<html lang="en"><head><title>App</title></head><body><div id="app" data-page="${pageJson}"></div><script src="/app.js"></script></body></html>`,
                { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } },
              );
            }
            if (u.hostname === 'rubygems.org' && u.pathname === '/api/v1/gems/rack.json') {
              return new MfResponse(
                JSON.stringify({
                  name: 'rack',
                  version: '3.1.8',
                  info: 'Rack provides a minimal, modular, and adaptable interface for developing web applications in Ruby.',
                  licenses: ['MIT'],
                  authors: 'Christian Neukirchen',
                  source_code_uri: 'https://github.com/rack/rack',
                  documentation_uri: 'https://rubydoc.info/gems/rack',
                }),
                { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } },
              );
            }
            return new MfResponse('not found', { status: 404 });
          },
        },
      ],
    }),
  );

  const openSockets = [];
  try {
    const authz = { authorization: `Bearer ${CALLER}`, 'content-type': 'application/json' };
    const migRes = await mf.dispatchFetch(`${ORIGIN}/__test_migrate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ metaSql, searchSql }),
    });
    assert.equal(migRes.status, 200);

    // 1. SSR HTML scrape + Inertia SSR hydration recovery inside workerd
    const ssrRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({ url: 'https://ssr.example.com/guide', formats: ['markdown'], discoverLlmsTxt: false }),
    });
    assert.equal(ssrRes.status, 200);
    const ssrJson = await ssrRes.json();
    assert.equal(ssrJson.ok, true);
    assert.match(ssrJson.markdown, /# Edge SSR Guide/);
    assert.match(ssrJson.markdown, /Server-rendered HTML extracted cleanly inside workerd\./);
    assert.equal(ssrJson.markdown.includes('ignore-sidebar-nav'), false);

    const inertiaRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({ url: 'https://ssr.example.com/inertia', formats: ['markdown'], discoverLlmsTxt: false }),
    });
    assert.equal(inertiaRes.status, 200);
    const inertiaJson = await inertiaRes.json();
    assert.equal(inertiaJson.ok, true);
    assert.equal(inertiaJson.contentSource, 'ssr-hydration');
    assert.match(inertiaJson.markdown, /Hydrated directly from Inertia data-page props/);

    // 2. Declarative YAML manifest twin resolution (`rubygems` -> `edgefetch.adapter_id = "rubygems"`)
    otlpPayloads.length = 0;
    outboundUrls.length = 0;
    const twinRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({ url: 'https://rubygems.org/gems/rack', formats: ['markdown'], discoverLlmsTxt: false }),
    });
    assert.equal(twinRes.status, 200);
    const twinJson = await twinRes.json();
    assert.equal(twinJson.ok, true);
    assert.equal(twinJson.extractorId, 'rubygems');
    assert.match(twinJson.markdown, /# rack 3\.1\.8 \(RubyGem\)/);
    assert.match(twinJson.markdown, /`gem install rack`/);
    assert.equal(
      outboundUrls.some((u) => u === 'https://rubygems.org/api/v1/gems/rack.json'),
      true,
      'declarative rubygems YAML manifest must upgrade to /api/v1/gems/rack.json twin',
    );
    assert.equal(
      outboundUrls.some((u) => u === 'https://rubygems.org/gems/rack'),
      false,
      'declarative twin upgrade must skip HTML page download',
    );
    await sleep(60);
    const twinSpans = otlpPayloads.flatMap(extractOtlpSpansFromPayload);
    const twinScrapeSpan = twinSpans.find((s) => s.name === 'edgefetch.scrape');
    assert.ok(twinScrapeSpan, 'expected edgefetch.scrape OTLP span');
    assert.equal(twinScrapeSpan.attrs['edgefetch.adapter_id'], 'rubygems');

    // 3. `304 Not Modified` conditional cache hit + multi-turn `/v1/interact` session lifecycle via fat agent
    const rWs = await mf.dispatchFetch(`${ORIGIN}/agent/ws`, {
      headers: {
        upgrade: 'websocket',
        authorization: `Bearer ${S1}`,
        'x-agent-site': 'site-1',
        'x-agent-arch': 'amd64',
        'x-agent-version': '2.7.0',
        'x-agent-capabilities': 'artifacts-v1,browser-v1,pdf-v1',
      },
    });
    assert.equal(rWs.status, 101);
    const ws = rWs.webSocket;
    ws.accept();
    openSockets.push(ws);

    const revalHtmlBytes = new TextEncoder().encode(
      '<html lang="en"><head><title>Reval Spec</title></head><body><main><h1>Reval Spec</h1><p>Conditional ETag 304 revalidation verified inside workerd.</p></main></body></html>',
    );
    let sawIfNoneMatch = '';
    let sawIfModifiedSince = '';
    let wizardStep = 0;
    let closedAgentSessionId = '';

    ws.addEventListener('message', async (e) => {
      const d = String(e.data);
      if (!d.includes('"dispatch"')) return;
      const msg = JSON.parse(d);
      const callObj = typeof msg.call === 'string' ? JSON.parse(msg.call) : msg.call;
      const req0 = callObj.requests[0];

      // Multi-turn /v1/interact handler
      if (req0.interact) {
        if (req0.interact.closeSession) {
          closedAgentSessionId = req0.interact.sessionId ?? '';
        } else {
          wizardStep++;
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
          body: JSON.stringify({
            results: [
              {
                id: req0.id,
                url: req0.url || 'https://spa.example.com/wizard',
                finalUrl: 'https://spa.example.com/wizard',
                kind: 'render',
                status: 200,
                outcome: 'ok',
                rendered: true,
                sessionId: req0.interact.closeSession ? '' : 'efsess_f15_wiz77',
                markdown: `# Wizard Step ${wizardStep}`,
                body: `<html><head><title>Wizard</title></head><body><main><h1>Wizard Step ${wizardStep}</h1></main></body></html>`,
                bodyEncoding: 'utf-8',
              },
            ],
          }),
        });
        return;
      }

      // Conditional 304 Not Modified revalidation handler
      if (req0.ifNoneMatch === '"etag-f15-v1"') {
        sawIfNoneMatch = req0.ifNoneMatch;
        sawIfModifiedSince = req0.ifModifiedSince ?? '';
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
                kind: req0.kind ?? 'scrape',
                status: 304,
                outcome: 'ok',
              },
            ],
          }),
        });
        return;
      }

      // Initial 200 stored artifact upload with ETag + Last-Modified
      const gz = gzipSync(revalHtmlBytes);
      const blobSha = sha256Hex(gz);
      const contentSha = sha256Hex(revalHtmlBytes);
      const upRes = await mf.dispatchFetch(`${ORIGIN}/agent/artifacts/${blobSha}`, {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${S1}`,
          'x-agent-site': 'site-1',
          'x-job-id': msg.jobId,
          'x-job-nonce': msg.jobNonce,
          'x-request-id': req0.id,
          'x-content-sha256': contentSha,
          'x-content-bytes': String(revalHtmlBytes.byteLength),
          'x-artifact-retention': 'stored',
          'content-type': 'application/gzip',
          'content-length': String(gz.byteLength),
        },
        body: gz,
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
              id: req0.id,
              url: req0.url,
              kind: 'scrape',
              status: 200,
              outcome: 'ok',
              contentType: 'text/html; charset=utf-8',
              etag: '"etag-f15-v1"',
              lastModified: 'Wed, 21 Oct 2026 07:28:00 GMT',
              bytes: revalHtmlBytes.byteLength,
              artifact: {
                blobSha256: blobSha,
                contentSha256: contentSha,
                contentBytes: revalHtmlBytes.byteLength,
                storedBytes: gz.byteLength,
                encoding: 'gzip',
                retention: 'stored',
              },
            },
          ],
        }),
      });
    });

    const firstReval = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        url: 'https://reval.example.com/spec',
        target: 'agent',
        formats: ['markdown'],
        discoverLlmsTxt: false,
      }),
    });
    assert.equal(firstReval.status, 200);
    const firstRevalJson = await firstReval.json();
    assert.equal(firstRevalJson.cached, false);
    assert.match(firstRevalJson.markdown, /Conditional ETag 304 revalidation verified inside workerd\./);

    otlpPayloads.length = 0;
    const secondReval = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        url: 'https://reval.example.com/spec',
        target: 'agent',
        formats: ['markdown'],
        maxAgeMs: 0,
        discoverLlmsTxt: false,
      }),
    });
    assert.equal(secondReval.status, 200);
    assert.equal(secondReval.headers.get('x-crawler-via'), 'agent:site-1+cache:304');
    assert.equal(sawIfNoneMatch, '"etag-f15-v1"');
    assert.equal(sawIfModifiedSince, 'Wed, 21 Oct 2026 07:28:00 GMT');
    const secondRevalJson = await secondReval.json();
    assert.equal(secondRevalJson.ok, true);
    assert.equal(secondRevalJson.cached, true);
    assert.equal(secondRevalJson.revalidated, true);
    assert.equal(secondRevalJson.originStatus, 304);
    assert.match(secondRevalJson.markdown, /Conditional ETag 304 revalidation verified inside workerd\./);

    await sleep(60);
    const revalSpans = otlpPayloads.flatMap(extractOtlpSpansFromPayload);
    const cache304Span = revalSpans.find((s) => s.name === 'cache:r2-d1');
    assert.ok(cache304Span, 'expected cache:r2-d1 OTLP span on 304 revalidation');
    assert.equal(cache304Span.attrs['cache.hit'], true);
    assert.equal(cache304Span.attrs['cache.revalidated'], true);
    assert.equal(cache304Span.attrs['http.response.status_code'], 304);

    // 4. Multi-turn `/v1/interact` session lifecycle: create -> follow-up action -> ownership check -> close teardown
    const turn1 = await mf.dispatchFetch(`${ORIGIN}/v1/interact`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        url: 'https://spa.example.com/wizard',
        keepSession: true,
        actions: [{ type: 'wait', waitMs: 5 }],
      }),
    });
    assert.equal(turn1.status, 200);
    const turn1Json = await turn1.json();
    assert.match(turn1Json.sessionId, /^site-1\.efsess_f15_wiz77\.[0-9a-f]{32}$/);
    assert.match(turn1Json.markdown, /Wizard Step 1/);

    const turn2 = await mf.dispatchFetch(`${ORIGIN}/v1/interact`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        sessionId: turn1Json.sessionId,
        keepSession: true,
        actions: [
          { type: 'fill', selector: '#project', value: 'edgefetch' },
          { type: 'click', selector: '#continue' },
        ],
      }),
    });
    assert.equal(turn2.status, 200);
    const turn2Json = await turn2.json();
    assert.equal(turn2Json.sessionId, turn1Json.sessionId);
    assert.equal(turn2Json.actions.length, 2);
    assert.match(turn2Json.markdown, /Wizard Step 2/);

    // Forged session signature must be rejected with 403 session_principal_mismatch
    const forgedSid = `${turn1Json.sessionId.slice(0, -4)}ffff`;
    const forgedRes = await mf.dispatchFetch(`${ORIGIN}/v1/interact`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({ sessionId: forgedSid, closeSession: true }),
    });
    assert.equal(forgedRes.status, 403);
    assert.equal((await forgedRes.json()).error, 'session_principal_mismatch');

    // Teardown retained browser session cleanly (`closeSession: true`) and confirm unknown DELETE `/v1/scrape/:sessionId` returns clean 404 JSON
    const turnClose = await mf.dispatchFetch(`${ORIGIN}/v1/interact`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({ sessionId: turn1Json.sessionId, closeSession: true }),
    });
    assert.equal(turnClose.status, 200);
    const turnCloseJson = await turnClose.json();
    assert.equal(turnCloseJson.closed, true);
    assert.equal(closedAgentSessionId, 'efsess_f15_wiz77');

    const delScrapeSidRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape/${encodeURIComponent(turn1Json.sessionId)}`, {
      method: 'DELETE',
      headers: authz,
    });
    assert.equal(delScrapeSidRes.status, 404);
    assert.equal((await delScrapeSidRes.json()).error, 'not_found');
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

test('F15.2 workerd E2E: GET /v1/extractors, POST /v1/jobs, POST /v1/catalog, & POST /v1/batch/scrape', async () => {
  const metaSql = readFileSync(new URL('../migrations/meta/0001_tracking.sql', import.meta.url), 'utf8');
  const searchSql = readFileSync(new URL('../migrations/search/0001_fts.sql', import.meta.url), 'utf8');

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'hub-f15-2',
          modules: WORKERD_MODULES,
          compatibilityDate: '2026-10-01',
          durableObjects: { AGENT_HUB: { className: 'AgentHubDO', useSQLite: true } },
          r2Buckets: ['ARTIFACTS'],
          d1Databases: ['META', 'SEARCH'],
          bindings: {
            CALLER_TOKEN: CALLER,
            ROBOTS_BYPASS_HOSTS:
              'acme.example.com,boards.greenhouse.io,boards-api.greenhouse.io,jobs.lever.co,api.lever.co,store.example.com,batch.example.com',
          },
          outboundService: async (req) => {
            const u = new URL(req.url);
            if (u.pathname === '/robots.txt') {
              return new MfResponse('User-agent: *\nAllow: /\n', { status: 200, headers: { 'content-type': 'text/plain' } });
            }
            if (u.hostname === 'acme.example.com' && u.pathname === '/careers') {
              return new MfResponse(
                '<html lang="en"><body><main><h1>Careers at Acme</h1><a href="https://boards.greenhouse.io/acme">Greenhouse Board</a><a href="https://jobs.lever.co/acme">Lever Board</a></main></body></html>',
                { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } },
              );
            }
            if (u.hostname === 'boards-api.greenhouse.io' && u.pathname === '/v1/boards/acme/jobs') {
              return new MfResponse(
                JSON.stringify({
                  meta: { total: 2 },
                  jobs: [
                    {
                      id: 501,
                      title: 'Staff Systems Engineer',
                      absolute_url: 'https://boards.greenhouse.io/acme/jobs/501',
                      location: { name: 'Remote - US' },
                      updated_at: new Date().toISOString(),
                      content: '<p>Build global edge workers. Base salary range: $210,000 - $260,000 USD.</p>',
                    },
                    {
                      id: 502,
                      title: 'Facilities Coordinator',
                      absolute_url: 'https://boards.greenhouse.io/acme/jobs/502',
                      location: { name: 'Austin, TX (On-site)' },
                      updated_at: new Date().toISOString(),
                      content: '<p>In-office operations role.</p>',
                    },
                  ],
                }),
                { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } },
              );
            }
            if (u.hostname === 'api.lever.co' && u.pathname === '/v0/postings/acme') {
              return new MfResponse(
                JSON.stringify([
                  {
                    id: '01234567-89ab-cdef-0123-456789abcdef',
                    text: 'Principal Runtime Engineer',
                    hostedUrl: 'https://jobs.lever.co/acme/01234567-89ab-cdef-0123-456789abcdef',
                    applyUrl: 'https://jobs.lever.co/acme/01234567-89ab-cdef-0123-456789abcdef/apply',
                    workplaceType: 'remote',
                    categories: { location: 'Remote', allLocations: ['Remote'] },
                    salaryDescriptionPlain: 'Compensation: $220K - $275K USD base',
                    createdAt: Date.now(),
                  },
                ]),
                { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } },
              );
            }
            if (u.hostname === 'store.example.com' && u.pathname === '/products.json') {
              const page = u.searchParams.get('page') ?? '1';
              if (page === '1') {
                return new MfResponse(
                  JSON.stringify({
                    products: [
                      {
                        id: 9001,
                        title: 'Titanium Bolt Kit',
                        handle: 'titanium-bolt-kit',
                        vendor: 'EdgeHardware',
                        product_type: 'Fasteners',
                        tags: ['titanium', 'hardware'],
                        variants: [
                          { id: 9101, title: 'M5 Pack', sku: 'TI-M5', price: '29.00', available: true },
                          { id: 9102, title: 'M6 Pack', sku: 'TI-M6', price: '34.00', available: false },
                        ],
                      },
                      {
                        id: 9002,
                        title: 'Carbon Spacer Set',
                        handle: 'carbon-spacer-set',
                        vendor: 'AeroParts',
                        product_type: 'Spacers',
                        tags: ['carbon'],
                        variants: [{ id: 9201, title: 'Default Title', sku: 'CB-SP', price: '19.50', available: false }],
                      },
                    ],
                  }),
                  { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } },
                );
              }
              return new MfResponse(JSON.stringify({ products: [] }), {
                status: 200,
                headers: { 'content-type': 'application/json; charset=utf-8' },
              });
            }
            if (u.hostname === 'batch.example.com' && (u.pathname === '/alpha' || u.pathname === '/beta')) {
              const label = u.pathname === '/alpha' ? 'Alpha' : 'Beta';
              return new MfResponse(
                `<html lang="en"><head><title>${label} Document</title></head><body><main><h1>${label} Document</h1><p>Batch item ${label} body.</p></main></body></html>`,
                { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } },
              );
            }
            return new MfResponse('not found', { status: 404 });
          },
        },
      ],
    }),
  );

  try {
    const authz = { authorization: `Bearer ${CALLER}`, 'content-type': 'application/json' };
    const migRes = await mf.dispatchFetch(`${ORIGIN}/__test_migrate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ metaSql, searchSql }),
    });
    assert.equal(migRes.status, 200);

    // 1. GET /v1/extractors: auth gate + YAML declarative manifests + category filter
    const unauthExt = await mf.dispatchFetch(`${ORIGIN}/v1/extractors`);
    assert.equal(unauthExt.status, 401);
    assert.match(unauthExt.headers.get('www-authenticate') ?? '', /resource_metadata=/);

    const extRes = await mf.dispatchFetch(`${ORIGIN}/v1/extractors`, { headers: authz });
    assert.equal(extRes.status, 200);
    const extJson = await extRes.json();
    assert.equal(extJson.ok, true);
    assert.ok(extJson.total >= 49, `expected >= 49 registered adapters, got ${extJson.total}`);
    const ids = new Set(extJson.extractors.map((e) => e.id));
    for (const yamlId of [
      'rubygems',
      'dev-to',
      'polymarket',
      'huggingface',
      'openrouter',
      'doi-crossref',
      'usaspending',
      'lobsters',
      'packagist',
      'hex-pm',
    ]) {
      assert.equal(ids.has(yamlId), true, `expected declarative YAML adapter "${yamlId}" in /v1/extractors`);
      const entry = extJson.extractors.find((e) => e.id === yamlId);
      assert.ok(entry.modes.includes('twin'), `expected "${yamlId}" to advertise twin mode`);
    }

    const jobsCatRes = await mf.dispatchFetch(`${ORIGIN}/v1/extractors?category=jobs`, { headers: authz });
    assert.equal(jobsCatRes.status, 200);
    const jobsCatJson = await jobsCatRes.json();
    assert.ok(jobsCatJson.extractors.length >= 10);
    assert.equal(jobsCatJson.extractors.every((e) => e.category === 'jobs'), true);

    // 2. POST /v1/jobs: domain ATS board discovery (Greenhouse + Lever) + remote & minBase pay filtering
    const jobsRes = await mf.dispatchFetch(`${ORIGIN}/v1/jobs`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        domains: ['acme.example.com'],
        query: 'Engineer',
        remote: true,
        minBase: 200_000,
      }),
    });
    assert.equal(jobsRes.status, 200);
    const jobsJson = await jobsRes.json();
    assert.equal(jobsJson.ok, true);
    assert.equal(jobsJson.count, 2);
    const platforms = jobsJson.discoveredBoards.map((b) => b.platform).sort();
    assert.deepEqual(platforms, ['greenhouse', 'lever']);
    assert.equal(jobsJson.jobs.every((j) => j.workplaceType === 'remote'), true);
    assert.equal(jobsJson.jobs.every((j) => j.pay?.basis === 'base' && j.pay.min >= 210_000), true);

    // 3. POST /v1/catalog (Shopify /products.json pagination -> R2 NDJSON) + GET status & filtered records
    const catRes = await mf.dispatchFetch(`${ORIGIN}/v1/catalog`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        url: 'https://store.example.com',
        platform: 'shopify',
        sync: true,
      }),
    });
    assert.equal(catRes.status, 200);
    const catJson = await catRes.json();
    assert.equal(catJson.ok, true);
    assert.equal(catJson.status, 'complete');
    assert.equal(catJson.platform, 'shopify');
    assert.equal(catJson.products, 2);
    assert.equal(catJson.variants, 3);
    assert.equal(catJson.pagesRead, 2);
    assert.match(catJson.artifactId ?? '', /^catalog\/cat_[A-Za-z0-9_-]+\.ndjson$/);

    const catStatusRes = await mf.dispatchFetch(`${ORIGIN}/v1/catalog/${catJson.catalogId}`, { headers: authz });
    assert.equal(catStatusRes.status, 200);
    assert.equal((await catStatusRes.json()).status, 'complete');

    const catRecsRes = await mf.dispatchFetch(
      `${ORIGIN}/v1/catalog/${catJson.catalogId}/records?availableOnly=true&vendor=EdgeHardware`,
      { headers: authz },
    );
    assert.equal(catRecsRes.status, 200);
    const catRecsJson = await catRecsRes.json();
    assert.equal(catRecsJson.ok, true);
    assert.equal(catRecsJson.totalProducts, 2);
    assert.equal(catRecsJson.matchedProducts, 1);
    assert.equal(catRecsJson.records[0].handle, 'titanium-bolt-kit');

    // 4. POST /v1/batch/scrape multi-URL execution + GET status + DELETE cancel
    const batchRes = await mf.dispatchFetch(`${ORIGIN}/v1/batch/scrape`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        urls: ['https://batch.example.com/alpha', 'https://batch.example.com/beta'],
        formats: ['markdown'],
        sync: true,
      }),
    });
    assert.equal(batchRes.status, 200);
    const batchJson = await batchRes.json();
    assert.equal(batchJson.ok, true);
    assert.equal(batchJson.status, 'completed');
    assert.equal(batchJson.total, 2);
    assert.equal(batchJson.completed, 2);
    assert.equal(batchJson.data.length, 2);
    assert.match(batchJson.data[0].markdown, /# Alpha Document/);
    assert.match(batchJson.data[1].markdown, /# Beta Document/);

    const batchGetRes = await mf.dispatchFetch(`${ORIGIN}/v1/batch/scrape/${batchJson.id}`, { headers: authz });
    assert.equal(batchGetRes.status, 200);
    assert.equal((await batchGetRes.json()).completed, 2);

    const batchDelRes = await mf.dispatchFetch(`${ORIGIN}/v1/batch/scrape/${batchJson.id}`, {
      method: 'DELETE',
      headers: authz,
    });
    assert.equal(batchDelRes.status, 200);
    assert.equal((await batchDelRes.json()).status, 'cancelled');
  } finally {
    await mf.dispose();
  }
});

test('F15.3 workerd E2E: /v1/agent autonomous LLM loop, SSE streaming, GET /trace, & DELETE cancellation', async () => {
  const metaSql = readFileSync(new URL('../migrations/meta/0001_tracking.sql', import.meta.url), 'utf8');
  const searchSql = readFileSync(new URL('../migrations/search/0001_fts.sql', import.meta.url), 'utf8');
  const OPENAI_CANARY = 'sk-workerd-agent-canary-secret-998877';

  let releaseSlowTurn;
  const slowTurnGate = new Promise((r) => {
    releaseSlowTurn = r;
  });
  let sawBearerHeader = '';

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'hub-f15-3',
          modules: WORKERD_MODULES,
          compatibilityDate: '2026-10-01',
          durableObjects: { AGENT_HUB: { className: 'AgentHubDO', useSQLite: true } },
          r2Buckets: ['ARTIFACTS'],
          d1Databases: ['META', 'SEARCH'],
          bindings: {
            CALLER_TOKEN: CALLER,
            OPENAI_API_KEY: OPENAI_CANARY,
            EDGEFETCH_LLM_PROVIDER: 'openai',
            EDGEFETCH_LLM_MODEL: 'gpt-4o-mini',
            ROBOTS_BYPASS_HOSTS: 'research.example.com',
          },
          outboundService: async (req) => {
            const u = new URL(req.url);
            if (u.pathname === '/robots.txt') {
              return new MfResponse('User-agent: *\nAllow: /\n', { status: 200, headers: { 'content-type': 'text/plain' } });
            }
            if (u.hostname === 'research.example.com' && u.pathname === '/metrics') {
              return new MfResponse(
                '<html lang="en"><head><title>Edge Benchmark v2.7</title></head><body><main><h1>Edge Benchmark v2.7</h1><p>Sustained throughput reached 48000 req/s with 3.2ms P99 latency.</p></main></body></html>',
                { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } },
              );
            }
            if (u.hostname === 'api.openai.com' && u.pathname === '/v1/chat/completions') {
              sawBearerHeader = req.headers.get('authorization') ?? '';
              const body = JSON.parse(await req.text());
              const msgs = body.messages ?? [];
              const userText = msgs.map((m) => (typeof m.content === 'string' ? m.content : '')).join('\n');
              if (userText.includes('SLOW_CANCEL_RUN')) {
                await slowTurnGate;
                return new MfResponse(
                  JSON.stringify({
                    choices: [{ message: { role: 'assistant', content: '{"cancelled":true}' } }],
                  }),
                  { status: 200, headers: { 'content-type': 'application/json' } },
                );
              }
              const hasToolOutput = msgs.some((m) => m.role === 'tool');
              if (!hasToolOutput) {
                return new MfResponse(
                  JSON.stringify({
                    id: 'chatcmpl_step1',
                    choices: [
                      {
                        index: 0,
                        message: {
                          role: 'assistant',
                          content: null,
                          tool_calls: [
                            {
                              id: 'call_scrape_1',
                              type: 'function',
                              function: {
                                name: 'scrape_url',
                                arguments: JSON.stringify({ url: 'https://research.example.com/metrics' }),
                              },
                            },
                          ],
                        },
                      },
                    ],
                    usage: { prompt_tokens: 120, completion_tokens: 24, total_tokens: 144 },
                  }),
                  { status: 200, headers: { 'content-type': 'application/json' } },
                );
              }
              const toolMsg = msgs.find((m) => m.role === 'tool');
              assert.match(String(toolMsg?.content ?? ''), /48000 req\/s/);
              return new MfResponse(
                JSON.stringify({
                  id: 'chatcmpl_step2',
                  choices: [
                    {
                      index: 0,
                      message: {
                        role: 'assistant',
                        content: JSON.stringify({
                          version: '2.7',
                          throughputRps: 48000,
                          summary: 'Sustained 48000 req/s at 3.2ms P99.',
                        }),
                      },
                    },
                  ],
                  usage: { prompt_tokens: 260, completion_tokens: 32, total_tokens: 292 },
                }),
                { status: 200, headers: { 'content-type': 'application/json' } },
              );
            }
            return new MfResponse('not found', { status: 404 });
          },
        },
      ],
    }),
  );

  try {
    const authz = { authorization: `Bearer ${CALLER}`, 'content-type': 'application/json' };
    const migRes = await mf.dispatchFetch(`${ORIGIN}/__test_migrate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ metaSql, searchSql }),
    });
    assert.equal(migRes.status, 200);

    // 1. Autonomous multi-step tool call + structured JSON schema answer + GET /v1/agent/:id + GET /v1/agent/:id/trace
    const agentRes = await mf.dispatchFetch(`${ORIGIN}/v1/agent`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        prompt: 'Read the benchmark metrics page and extract version and throughputRps.',
        urls: ['https://research.example.com/metrics'],
        strictConstrainToURLs: true,
        schema: {
          type: 'object',
          properties: {
            version: { type: 'string' },
            throughputRps: { type: 'number' },
            summary: { type: 'string' },
          },
          required: ['version', 'throughputRps'],
        },
      }),
    });
    assert.equal(agentRes.status, 200);
    assert.equal(sawBearerHeader, `Bearer ${OPENAI_CANARY}`);
    const agentJson = await agentRes.json();
    assert.equal(agentJson.status, 'completed');
    assert.equal(agentJson.llmUsed, true);
    assert.equal(agentJson.schemaValid, true);
    assert.equal(agentJson.stepsUsed, 2);
    assert.equal(agentJson.pagesRead, 1);
    assert.equal(agentJson.data?.version, '2.7');
    assert.equal(agentJson.data?.throughputRps, 48000);
    assert.equal(agentJson.sources?.[0]?.url, 'https://research.example.com/metrics');
    assert.equal(JSON.stringify(agentJson).includes(OPENAI_CANARY), false, 'agent response must never leak OPENAI_API_KEY');

    const getRunRes = await mf.dispatchFetch(`${ORIGIN}/v1/agent/${agentJson.id}`, { headers: authz });
    assert.equal(getRunRes.status, 200);
    assert.equal((await getRunRes.json()).status, 'completed');

    const traceRes = await mf.dispatchFetch(`${ORIGIN}/v1/agent/${agentJson.id}/trace`, { headers: authz });
    assert.equal(traceRes.status, 200);
    const traceJson = await traceRes.json();
    assert.equal(traceJson.ok, true);
    assert.ok(traceJson.spans.length >= 5);
    for (let i = 0; i < traceJson.spans.length; i++) {
      assert.equal(traceJson.spans[i].sequence, i + 1, 'agent trace sequence numbers must be strictly monotonic');
    }
    const traceKinds = new Set(traceJson.spans.map((s) => s.kind));
    assert.equal(traceKinds.has('router'), true);
    assert.equal(traceKinds.has('llm_turn'), true);
    assert.equal(traceKinds.has('tool_call'), true);
    assert.equal(traceKinds.has('synthesis'), true);
    assert.equal(JSON.stringify(traceJson).includes(OPENAI_CANARY), false);

    // 2. Real-time SSE streaming (`Accept: text/event-stream`)
    const sseRes = await mf.dispatchFetch(`${ORIGIN}/v1/agent`, {
      method: 'POST',
      headers: { ...authz, accept: 'text/event-stream' },
      body: JSON.stringify({
        prompt: 'Stream the benchmark metrics summary.',
        urls: ['https://research.example.com/metrics'],
      }),
    });
    assert.equal(sseRes.status, 200);
    assert.match(sseRes.headers.get('content-type') ?? '', /text\/event-stream/i);
    const sseText = await sseRes.text();
    const startedIdx = sseText.indexOf('event: agent.started');
    const actionIdx = sseText.indexOf('event: agent.action');
    const traceIdx = sseText.indexOf('event: agent.trace');
    const completedIdx = sseText.indexOf('event: agent.completed');
    assert.ok(startedIdx >= 0, 'SSE stream must emit agent.started');
    assert.ok(actionIdx > startedIdx, 'SSE stream must emit agent.action after agent.started');
    assert.ok(traceIdx > startedIdx, 'SSE stream must emit agent.trace');
    assert.ok(completedIdx > actionIdx, 'SSE stream must emit agent.completed after tool action');
    assert.match(sseText, /"tool":"scrape_url"/);

    // 3. Async start + DELETE /v1/agent/:id cancellation
    const asyncStartRes = await mf.dispatchFetch(`${ORIGIN}/v1/agent`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        prompt: 'SLOW_CANCEL_RUN: wait for cancellation',
        urls: ['https://research.example.com/metrics'],
        async: true,
      }),
    });
    assert.equal(asyncStartRes.status, 202);
    const asyncCreated = await asyncStartRes.json();
    assert.match(asyncCreated.id, /^agt_/);
    assert.equal(asyncCreated.status, 'processing');

    const delRes = await mf.dispatchFetch(`${ORIGIN}/v1/agent/${asyncCreated.id}`, {
      method: 'DELETE',
      headers: authz,
    });
    assert.equal(delRes.status, 200);
    const delJson = await delRes.json();
    assert.equal(delJson.ok, true);
    assert.equal(delJson.status, 'cancelled');

    const cancelledGetRes = await mf.dispatchFetch(`${ORIGIN}/v1/agent/${asyncCreated.id}`, { headers: authz });
    assert.equal(cancelledGetRes.status, 200);
    assert.equal((await cancelledGetRes.json()).status, 'cancelled');

    releaseSlowTurn();
    await sleep(40);
  } finally {
    releaseSlowTurn?.();
    await mf.dispose();
  }
});

test('F15.4 workerd E2E: /v1/ingest-tab CORS & Auth + OAuth 2.1 PKCE S256 Full Lifecycle', async () => {
  const metaSql = readFileSync(new URL('../migrations/meta/0001_tracking.sql', import.meta.url), 'utf8');
  const searchSql = readFileSync(new URL('../migrations/search/0001_fts.sql', import.meta.url), 'utf8');

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'hub-f15-4',
          modules: WORKERD_MODULES,
          compatibilityDate: '2026-10-01',
          durableObjects: { AGENT_HUB: { className: 'AgentHubDO', useSQLite: true } },
          r2Buckets: ['ARTIFACTS'],
          d1Databases: ['META', 'SEARCH'],
          bindings: {
            CALLER_TOKEN: CALLER,
          },
        },
      ],
    }),
  );

  try {
    const authz = { authorization: `Bearer ${CALLER}`, 'content-type': 'application/json' };
    const migRes = await mf.dispatchFetch(`${ORIGIN}/__test_migrate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ metaSql, searchSql }),
    });
    assert.equal(migRes.status, 200);

    // 1. OPTIONS /v1/ingest-tab preflight & POST /v1/ingest-tab auth enforcement + valid tab ingest
    const preflightRes = await mf.dispatchFetch(`${ORIGIN}/v1/ingest-tab`, {
      method: 'OPTIONS',
      headers: {
        origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'Authorization, Content-Type',
      },
    });
    assert.equal(preflightRes.status, 204);
    assert.equal(preflightRes.headers.get('access-control-allow-origin'), '*');
    assert.match(preflightRes.headers.get('access-control-allow-methods') ?? '', /POST/);
    assert.match(preflightRes.headers.get('access-control-allow-headers') ?? '', /Authorization/i);

    const unauthClipRes = await mf.dispatchFetch(`${ORIGIN}/v1/ingest-tab`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://wiki.example.com/page', markdown: '# Secret' }),
    });
    assert.equal(unauthClipRes.status, 401);
    assert.equal(unauthClipRes.headers.get('access-control-allow-origin'), '*');
    assert.match(unauthClipRes.headers.get('www-authenticate') ?? '', /Bearer/);

    const badTokClipRes = await mf.dispatchFetch(`${ORIGIN}/v1/ingest-tab`, {
      method: 'POST',
      headers: { authorization: 'Bearer wrong-token-value-1234567890', 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://wiki.example.com/page', markdown: '# Secret' }),
    });
    assert.equal(badTokClipRes.status, 401);

    const validClipRes = await mf.dispatchFetch(`${ORIGIN}/v1/ingest-tab`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({
        url: 'https://wiki.example.com/runbook#section-rotation',
        title: 'Key Rotation Runbook',
        html: '<html lang="en"><body><nav>top-nav-links</nav><main><h1>Key Rotation Runbook</h1><p>Rotate Ed25519 bot signing keys every thirty days.</p></main></body></html>',
        collectionId: 'clipped-docs',
      }),
    });
    assert.equal(validClipRes.status, 200);
    assert.equal(validClipRes.headers.get('access-control-allow-origin'), '*');
    const validClipJson = await validClipRes.json();
    assert.equal(validClipJson.ok, true);
    assert.equal(validClipJson.url, 'https://wiki.example.com/runbook');
    assert.equal(validClipJson.collectionId, 'clipped-docs');
    assert.ok(validClipJson.indexedChunks >= 1);
    assert.match(validClipJson.markdown, /Rotate Ed25519 bot signing keys every thirty days\./);
    assert.equal(validClipJson.markdown.includes('top-nav-links'), false);

    const clipSearchRes = await mf.dispatchFetch(`${ORIGIN}/v1/collections/clipped-docs/search`, {
      method: 'POST',
      headers: authz,
      body: JSON.stringify({ query: 'Ed25519 signing keys' }),
    });
    assert.equal(clipSearchRes.status, 200);
    assert.equal((await clipSearchRes.json()).hits.length, 1);

    // 2. OAuth 2.1 PKCE S256 Full Lifecycle: discovery -> register -> authorize -> token -> /mcp tools/list -> revoke
    const metaDocRes = await mf.dispatchFetch(`${ORIGIN}/.well-known/oauth-authorization-server`);
    assert.equal(metaDocRes.status, 200);
    const metaDoc = await metaDocRes.json();
    assert.equal(metaDoc.issuer, ORIGIN);
    assert.equal(metaDoc.registration_endpoint, `${ORIGIN}/oauth/register`);
    assert.equal(metaDoc.authorization_endpoint, `${ORIGIN}/oauth/authorize`);
    assert.equal(metaDoc.token_endpoint, `${ORIGIN}/oauth/token`);
    assert.equal(metaDoc.revocation_endpoint, `${ORIGIN}/oauth/revoke`);
    assert.deepEqual(metaDoc.code_challenge_methods_supported, ['S256']);

    const redirectUri = 'http://127.0.0.1:54321/callback';
    const regRes = await mf.dispatchFetch(`${ORIGIN}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.44' },
      body: JSON.stringify({
        client_name: 'Workerd PKCE Test Client',
        redirect_uris: [redirectUri],
        application_type: 'native',
      }),
    });
    assert.equal(regRes.status, 201);
    const regJson = await regRes.json();
    assert.match(regJson.client_id, /^mcp_/);

    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const oauthState = 'state_pkce_workerd_1';

    const authGetUrl = new URL(`${ORIGIN}/oauth/authorize`);
    authGetUrl.searchParams.set('client_id', regJson.client_id);
    authGetUrl.searchParams.set('redirect_uri', redirectUri);
    authGetUrl.searchParams.set('response_type', 'code');
    authGetUrl.searchParams.set('scope', 'crawl:read crawl:fetch');
    authGetUrl.searchParams.set('state', oauthState);
    authGetUrl.searchParams.set('code_challenge', codeChallenge);
    authGetUrl.searchParams.set('code_challenge_method', 'S256');

    const consentGetRes = await mf.dispatchFetch(authGetUrl.toString(), { redirect: 'manual' });
    assert.equal(consentGetRes.status, 200);
    const csrfCookie = consentGetRes.headers.get('set-cookie')?.split(';')[0] ?? '';
    assert.match(csrfCookie, /^ef_oauth_csrf=/);
    const consentHtml = await consentGetRes.text();
    const sealedMatch = /name="sealed"\s+value="([^"]+)"/.exec(consentHtml);
    const csrfMatch = /name="csrf"\s+value="([^"]+)"/.exec(consentHtml);
    assert.ok(sealedMatch?.[1] && csrfMatch?.[1], 'consent HTML must include sealed state and csrf inputs');

    const approveBody = new URLSearchParams({
      sealed: sealedMatch[1],
      csrf: csrfMatch[1],
      owner_token: CALLER,
      decision: 'approve',
    });
    const approveRes = await mf.dispatchFetch(`${ORIGIN}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: csrfCookie,
        'cf-connecting-ip': '198.51.100.44',
      },
      body: approveBody.toString(),
    });
    assert.equal(approveRes.status, 302);
    const cbUrl = new URL(approveRes.headers.get('location') ?? '');
    assert.equal(`${cbUrl.origin}${cbUrl.pathname}`, redirectUri);
    assert.equal(cbUrl.searchParams.get('state'), oauthState);
    assert.equal(cbUrl.searchParams.get('iss'), ORIGIN);
    const authCode = cbUrl.searchParams.get('code') ?? '';
    assert.match(authCode, /^efc_/);

    const tokenRes = await mf.dispatchFetch(`${ORIGIN}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: authCode,
        client_id: regJson.client_id,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      }).toString(),
    });
    assert.equal(tokenRes.status, 200);
    const tokenJson = await tokenRes.json();
    assert.match(tokenJson.access_token, /^efa_/);
    assert.match(tokenJson.refresh_token, /^efr_/);
    assert.equal(tokenJson.token_type, 'Bearer');

    // Replaying the single-use authorization code must fail with 400 invalid_grant
    const replayCodeRes = await mf.dispatchFetch(`${ORIGIN}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: authCode,
        client_id: regJson.client_id,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      }).toString(),
    });
    assert.equal(replayCodeRes.status, 400);
    assert.equal((await replayCodeRes.json()).error, 'invalid_grant');

    // Authenticated /mcp tools/list using issued OAuth 2.1 access_token
    const mcpRes = await mf.dispatchFetch(`${ORIGIN}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${tokenJson.access_token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(mcpRes.status, 200);
    const mcpJson = await mcpRes.json();
    assert.equal(mcpJson.result.tools.length, 17);

    // Revoke access_token via /oauth/revoke -> subsequent /mcp call returns 401
    const revokeRes = await mf.dispatchFetch(`${ORIGIN}/oauth/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: tokenJson.access_token }).toString(),
    });
    assert.equal(revokeRes.status, 200);
    assert.equal((await revokeRes.json()).ok, true);

    const mcpAfterRevoke = await mf.dispatchFetch(`${ORIGIN}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${tokenJson.access_token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
    });
    assert.equal(mcpAfterRevoke.status, 401);
  } finally {
    await mf.dispose();
  }
});

test('F15.5 workerd E2E: End-to-End OTLP Span Capture, W3C traceparent propagation, child spans, & zero leaked secrets', async () => {
  const metaSql = readFileSync(new URL('../migrations/meta/0001_tracking.sql', import.meta.url), 'utf8');
  const searchSql = readFileSync(new URL('../migrations/search/0001_fts.sql', import.meta.url), 'utf8');

  const OTLP_HEADER_SECRET = 'otlp-collector-ingest-tok-canary-4455';
  const OPENAI_SECRET_CANARY = 'sk-otel-canary-secret-never-export-6677';
  const URL_QUERY_CANARY = 'SUPER_SECRET_QUERY_TOKEN_8899';

  const capturedOtlpRequests = [];

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'hub-f15-5',
          modules: WORKERD_MODULES,
          compatibilityDate: '2026-10-01',
          durableObjects: { AGENT_HUB: { className: 'AgentHubDO', useSQLite: true } },
          r2Buckets: ['ARTIFACTS'],
          d1Databases: ['META', 'SEARCH'],
          bindings: {
            CALLER_TOKEN: CALLER,
            AGENT_TOKENS: JSON.stringify({ 'site-1': S1 }),
            OPENAI_API_KEY: OPENAI_SECRET_CANARY,
            OTEL_EXPORTER_OTLP_ENDPOINT: 'https://otel.example.com/v1/traces',
            OTEL_EXPORTER_OTLP_HEADERS: `Authorization=Bearer ${OTLP_HEADER_SECRET}`,
            OTEL_SERVICE_NAME: 'edgefetch-workerd-e2e',
            ROBOTS_BYPASS_HOSTS: 'rubygems.org,boards.greenhouse.io,boards-api.greenhouse.io,store.example.com',
          },
          outboundService: async (req) => {
            const u = new URL(req.url);
            if (u.origin === 'https://otel.example.com' && u.pathname === '/v1/traces') {
              const rawText = await req.text();
              capturedOtlpRequests.push({
                authHeader: req.headers.get('authorization') ?? '',
                contentType: req.headers.get('content-type') ?? '',
                rawText,
                payload: JSON.parse(rawText),
              });
              return new MfResponse('{}', { status: 200, headers: { 'content-type': 'application/json' } });
            }
            if (u.pathname === '/robots.txt') {
              return new MfResponse('User-agent: *\nAllow: /\n', { status: 200, headers: { 'content-type': 'text/plain' } });
            }
            if (u.hostname === 'rubygems.org' && u.pathname === '/api/v1/gems/sinatra.json') {
              return new MfResponse(
                JSON.stringify({
                  name: 'sinatra',
                  version: '4.1.1',
                  info: 'Classy web-development dressed in a DSL.',
                  licenses: ['MIT'],
                  authors: 'Blake Mizerany',
                }),
                { status: 200, headers: { 'content-type': 'application/json' } },
              );
            }
            if (u.hostname === 'boards-api.greenhouse.io' && u.pathname === '/v1/boards/acme/jobs/777') {
              return new MfResponse(
                JSON.stringify({
                  id: 777,
                  title: 'Staff Security Engineer',
                  company_name: 'Acme',
                  absolute_url: 'https://boards.greenhouse.io/acme/jobs/777',
                  location: { name: 'Remote - US' },
                  updated_at: new Date().toISOString(),
                  pay_input_ranges: [{ currency_type: 'USD', min_cents: 22_000_000, max_cents: 27_000_000, title: 'Base Salary' }],
                  content: '<p>Secure distributed edge runtimes.</p>',
                }),
                { status: 200, headers: { 'content-type': 'application/json' } },
              );
            }
            if (u.hostname === 'store.example.com' && u.pathname === '/products.json') {
              return new MfResponse(
                JSON.stringify({
                  products: [
                    {
                      id: 1,
                      title: 'Edge Sensor',
                      handle: 'edge-sensor',
                      vendor: 'EdgeLab',
                      product_type: 'Sensors',
                      variants: [{ id: 11, title: 'Default Title', sku: 'ES-1', price: '49.00', available: true }],
                    },
                  ],
                }),
                { status: 200, headers: { 'content-type': 'application/json' } },
              );
            }
            return new MfResponse('not found', { status: 404 });
          },
        },
      ],
    }),
  );

  try {
    const migRes = await mf.dispatchFetch(`${ORIGIN}/__test_migrate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ metaSql, searchSql }),
    });
    assert.equal(migRes.status, 200);

    const makeTraceHeaders = (traceHexByte, parentHexByte, extra = {}) => {
      const traceId = traceHexByte.repeat(32);
      const parentId = parentHexByte.repeat(16);
      return {
        traceId,
        parentId,
        headers: {
          authorization: `Bearer ${CALLER}`,
          'content-type': 'application/json',
          traceparent: `00-${traceId}-${parentId}-01`,
          ...extra,
        },
      };
    };

    const assertResponseTraceHeaders = (res, expectedTraceId) => {
      assert.equal(res.headers.get('x-trace-id'), expectedTraceId);
      assert.match(res.headers.get('traceparent') ?? '', new RegExp(`^00-${expectedTraceId}-[0-9a-f]{16}-01$`));
    };

    // 1. Traced POST /v1/scrape (with query-string secret canary that MUST be stripped from spans!)
    const tScrape = makeTraceHeaders('a', '1');
    const scRes = await mf.dispatchFetch(`${ORIGIN}/v1/scrape`, {
      method: 'POST',
      headers: tScrape.headers,
      body: JSON.stringify({
        url: `https://rubygems.org/gems/sinatra?api_key=${URL_QUERY_CANARY}`,
        formats: ['markdown'],
        discoverLlmsTxt: false,
      }),
    });
    assert.equal(scRes.status, 200);
    assertResponseTraceHeaders(scRes, tScrape.traceId);

    // 2. Traced POST /v1/jobs (verify mode on Greenhouse job)
    const tJobs = makeTraceHeaders('b', '2');
    const jbRes = await mf.dispatchFetch(`${ORIGIN}/v1/jobs`, {
      method: 'POST',
      headers: tJobs.headers,
      body: JSON.stringify({
        verify: [`https://boards.greenhouse.io/acme/jobs/777?token=${URL_QUERY_CANARY}`],
      }),
    });
    assert.equal(jbRes.status, 200);
    assertResponseTraceHeaders(jbRes, tJobs.traceId);

    // 3. Traced POST /v1/catalog (`maxPages: 1` for instant completion without inter-page sleep)
    const tCat = makeTraceHeaders('c', '3');
    const ctRes = await mf.dispatchFetch(`${ORIGIN}/v1/catalog`, {
      method: 'POST',
      headers: tCat.headers,
      body: JSON.stringify({
        url: 'https://store.example.com',
        platform: 'shopify',
        maxPages: 1,
        sync: true,
      }),
    });
    assert.equal(ctRes.status, 200);
    assertResponseTraceHeaders(ctRes, tCat.traceId);

    // 4. Traced OAuth 2.1 lifecycle (`register` -> `authorize` -> `token` -> `revoke`)
    const tOAuth = makeTraceHeaders('d', '4');
    const redirectUri = 'http://127.0.0.1:55111/cb';
    const oaRegRes = await mf.dispatchFetch(`${ORIGIN}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', traceparent: `00-${tOAuth.traceId}-${tOAuth.parentId}-01`, 'cf-connecting-ip': '198.51.100.88' },
      body: JSON.stringify({ client_name: 'OTLP OAuth Client', redirect_uris: [redirectUri] }),
    });
    assert.equal(oaRegRes.status, 201);
    assertResponseTraceHeaders(oaRegRes, tOAuth.traceId);
    const { client_id: oaClientId } = await oaRegRes.json();

    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const oaGetRes = await mf.dispatchFetch(
      `${ORIGIN}/oauth/authorize?client_id=${encodeURIComponent(oaClientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&state=st_otel`,
      { headers: { traceparent: `00-${tOAuth.traceId}-${tOAuth.parentId}-01` }, redirect: 'manual' },
    );
    assert.equal(oaGetRes.status, 200);
    assertResponseTraceHeaders(oaGetRes, tOAuth.traceId);
    const oaCookie = oaGetRes.headers.get('set-cookie')?.split(';')[0] ?? '';
    const oaHtml = await oaGetRes.text();
    const oaSealed = /name="sealed"\s+value="([^"]+)"/.exec(oaHtml)?.[1] ?? '';
    const oaCsrf = /name="csrf"\s+value="([^"]+)"/.exec(oaHtml)?.[1] ?? '';

    const oaPostRes = await mf.dispatchFetch(`${ORIGIN}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: oaCookie,
        traceparent: `00-${tOAuth.traceId}-${tOAuth.parentId}-01`,
        'cf-connecting-ip': '198.51.100.88',
      },
      body: new URLSearchParams({ sealed: oaSealed, csrf: oaCsrf, owner_token: CALLER, decision: 'approve' }).toString(),
    });
    assert.equal(oaPostRes.status, 302);
    assertResponseTraceHeaders(oaPostRes, tOAuth.traceId);
    const oaCode = new URL(oaPostRes.headers.get('location') ?? '').searchParams.get('code') ?? '';

    const oaTokRes = await mf.dispatchFetch(`${ORIGIN}/oauth/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        traceparent: `00-${tOAuth.traceId}-${tOAuth.parentId}-01`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: oaCode,
        client_id: oaClientId,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    assert.equal(oaTokRes.status, 200);
    assertResponseTraceHeaders(oaTokRes, tOAuth.traceId);
    const oaTokJson = await oaTokRes.json();

    const oaRevRes = await mf.dispatchFetch(`${ORIGIN}/oauth/revoke`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        traceparent: `00-${tOAuth.traceId}-${tOAuth.parentId}-01`,
      },
      body: new URLSearchParams({ token: oaTokJson.access_token }).toString(),
    });
    assert.equal(oaRevRes.status, 200);
    assertResponseTraceHeaders(oaRevRes, tOAuth.traceId);

    // Allow ctx.waitUntil OTLP flushes to complete inside workerd
    await sleep(100);

    assert.ok(capturedOtlpRequests.length >= 7, `expected >= 7 OTLP trace flushes, got ${capturedOtlpRequests.length}`);
    for (const reqItem of capturedOtlpRequests) {
      assert.equal(reqItem.authHeader, `Bearer ${OTLP_HEADER_SECRET}`);
      assert.match(reqItem.contentType, /application\/json/i);
    }

    const allSpans = capturedOtlpRequests.flatMap((r) => extractOtlpSpansFromPayload(r.payload));
    assert.ok(allSpans.every((s) => s.resourceAttrs['service.name'] === 'edgefetch-workerd-e2e'));

    // Verify scrape trace tree: inbound parentSpanId -> edgefetch.http -> edgefetch.scrape -> edgefetch.dispatch
    const scrapeTraceSpans = allSpans.filter((s) => s.traceId === tScrape.traceId);
    const scrapeHttp = scrapeTraceSpans.find((s) => s.name === 'edgefetch.http');
    const scrapeChild = scrapeTraceSpans.find((s) => s.name === 'edgefetch.scrape');
    const scrapeDispatch = scrapeTraceSpans.find((s) => s.name === 'edgefetch.dispatch');
    assert.ok(scrapeHttp && scrapeChild && scrapeDispatch, 'expected edgefetch.http -> edgefetch.scrape -> edgefetch.dispatch hierarchy');
    assert.equal(scrapeHttp.parentSpanId, tScrape.parentId);
    assert.equal(scrapeChild.parentSpanId, scrapeHttp.spanId);
    assert.equal(scrapeChild.attrs['edgefetch.adapter_id'], 'rubygems');
    assert.equal(scrapeDispatch.parentSpanId, scrapeChild.spanId);

    // Verify jobs trace tree: inbound parentSpanId -> edgefetch.http -> edgefetch.jobs
    const jobsTraceSpans = allSpans.filter((s) => s.traceId === tJobs.traceId);
    const jobsHttp = jobsTraceSpans.find((s) => s.name === 'edgefetch.http');
    const jobsChild = jobsTraceSpans.find((s) => s.name === 'edgefetch.jobs');
    assert.ok(jobsHttp && jobsChild, 'expected edgefetch.http -> edgefetch.jobs hierarchy');
    assert.equal(jobsHttp.parentSpanId, tJobs.parentId);
    assert.equal(jobsChild.parentSpanId, jobsHttp.spanId);

    // Verify catalog trace tree: inbound parentSpanId -> edgefetch.http -> edgefetch.catalog
    const catTraceSpans = allSpans.filter((s) => s.traceId === tCat.traceId);
    const catHttp = catTraceSpans.find((s) => s.name === 'edgefetch.http');
    const catChild = catTraceSpans.find((s) => s.name === 'edgefetch.catalog');
    assert.ok(catHttp && catChild, 'expected edgefetch.http -> edgefetch.catalog hierarchy');
    assert.equal(catHttp.parentSpanId, tCat.parentId);
    assert.equal(catChild.parentSpanId, catHttp.spanId);
    assert.equal(catChild.attrs['edgefetch.adapter_id'], 'shopify');

    // Verify OAuth audit child spans (`edgefetch.oauth.register`, `authorize`, `token`, `revoke`)
    const oauthSpanNames = new Set(allSpans.filter((s) => s.traceId === tOAuth.traceId).map((s) => s.name));
    for (const expectedOAuthSpan of [
      'edgefetch.http',
      'edgefetch.oauth.register',
      'edgefetch.oauth.authorize',
      'edgefetch.oauth.token',
      'edgefetch.oauth.revoke',
    ]) {
      assert.equal(oauthSpanNames.has(expectedOAuthSpan), true, `missing expected OAuth OTLP span ${expectedOAuthSpan}`);
    }

    // Zero leaked secrets across ALL exported OTLP JSON payloads!
    const allRawOtlpText = capturedOtlpRequests.map((r) => r.rawText).join('\n');
    for (const secretValue of [
      CALLER,
      S1,
      OPENAI_SECRET_CANARY,
      OTLP_HEADER_SECRET,
      URL_QUERY_CANARY,
      oaCode,
      oaTokJson.access_token,
      oaTokJson.refresh_token,
      verifier,
      oaSealed,
      oaCsrf,
    ]) {
      assert.ok(secretValue && secretValue.length >= 8);
      assert.equal(
        allRawOtlpText.includes(secretValue),
        false,
        `OTLP exported spans MUST NEVER leak secret/token value (${secretValue.slice(0, 6)}...)`,
      );
    }
  } finally {
    await mf.dispose();
  }
});
