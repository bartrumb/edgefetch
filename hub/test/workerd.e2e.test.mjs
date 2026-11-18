import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
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
    }
  } finally {
    await mf.dispose();
  }
});
