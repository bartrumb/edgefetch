import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { TestContext } from 'node:test';
import { gzipSync } from 'node:zlib';

import { NodeFsR2Bucket } from './stubs/cf-storage-mocks.ts';
import {
  AdapterNetworkForbiddenError,
  MAX_ADAPTER_ISOLATE_OUTPUT_BYTES,
  runAdapterSyncInBulkhead,
  runUntrustedAdapterInDynamicWorker,
} from '../src/adapter-sandbox.ts';
import { handleAdminRoute } from '../src/admin.ts';
import {
  executeCatalogCall,
  getCatalogMemoryUsageForTests,
  getCatalogRecords,
  getCatalogStatus,
  MAX_CATALOG_WALL_MS,
  MAX_CONCURRENT_R2_RELOADS,
  MAX_GLOBAL_CATALOG_BYTES,
  resetCatalogStateForTests,
} from '../src/catalog.ts';
import { redactLlmConfigForLog, redactLlmUrlForLog } from '../src/llm.ts';
import {
  createMemoryOAuthStore,
  createSqliteOAuthStore,
  handleOAuthRoute,
  OAUTH_SQLITE_SCHEMA,
} from '../src/oauth.ts';
import {
  cloudflareOverflowFetch,
  fetchOverflowRobots,
  isRobotsAllowed,
  normalizeRobotsURI,
  parseOverflowRobotsTxt,
  resetOverflowRobotsCacheForTests,
  ROBOTS_UNREACHABLE_CACHE_MAX_MS,
} from '../src/overflow.ts';
import { DatabaseSync } from 'node:sqlite';

export async function runRound6StreamBSubtests(t: TestContext): Promise<void> {
await t.test('R6-STREAM-B-3 (M3 & R5-M4): Catalog caps variantHashes inside 32 MiB global LRU, coalesces R2 reloads with <= 2 gunzip semaphore, and enforces <= 120s wall-clock deadline', async () => {
  resetCatalogStateForTests();
  assert.equal(MAX_GLOBAL_CATALOG_BYTES, 32 * 1024 * 1024);
  assert.equal(MAX_CONCURRENT_R2_RELOADS, 2);
  assert.equal(MAX_CATALOG_WALL_MS, 120_000);

  // 1. `M3` (`cat8.mjs` mode `tiny`): Multi-run `variantHashes` bounded strictly inside 32 MiB global budget + R2 hash reload for diffs!
  const r2Dir = mkdtempSync(join(tmpdir(), 'ef-r6-cat-r2-'));
  try {
    const fsR2 = new NodeFsR2Bucket(r2Dir);
    const env = { ARTIFACTS: fsR2 };

    const makeVariantHeavyStore = (seed: number, prodCount = 80, varPerProd = 200) => {
      let calls = 0;
      return async () => {
        calls++;
        if (calls > 1) {
          return { results: [{ status: 200, outcome: 'ok', headers: { 'content-type': 'application/json' }, body: '{"products":[]}' }] };
        }
        const products = Array.from({ length: prodCount }, (_, i) => {
          const pid = seed * 100_000 + i + 1;
          return {
            id: pid,
            handle: `p-${pid}`,
            title: `Product ${pid}`,
            variants: Array.from({ length: varPerProd }, (__, v) => ({
              id: pid * 1000 + v,
              title: `V${v}`,
              price: '9.99',
              sku: `SKU-${pid}-${v}`,
              available: true,
            })),
          };
        });
        return {
          results: [{ status: 200, outcome: 'ok', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ products }) }],
        };
      };
    };

    // First run on `store0.example.com` (will have its in-memory hashes evicted by 28 subsequent heavy tenant runs!)
    const firstStore0 = await executeCatalogCall({
      payload: { url: 'https://store0.example.com/' },
      env,
      executeHubFetch: makeVariantHeavyStore(1, 60, 150),
      sleepFn: async () => undefined,
    });
    assert.equal(firstStore0.body.status, 'complete');

    for (let k = 2; k <= 28; k++) {
      const res = await executeCatalogCall({
        payload: { url: `https://store${k}.example.com/` },
        env,
        executeHubFetch: makeVariantHeavyStore(k, 90, 200),
        sleepFn: async () => undefined,
      });
      assert.equal(res.status, 200);
      const memStats = getCatalogMemoryUsageForTests();
      assert.ok(
        memStats.totalBytes <= MAX_GLOBAL_CATALOG_BYTES,
        `Run ${k}: total catalog memory (${memStats.totalBytes}) must never exceed 32 MiB (${MAX_GLOBAL_CATALOG_BYTES})`,
      );
    }

    // Even after `store0`'s in-memory `hashes` were evicted by the 32 MiB LRU, a second run on `store0` reloads `.hashes.json` from R2 and computes exact diff!
    const secondStore0 = await executeCatalogCall({
      payload: { url: 'https://store0.example.com/' },
      env,
      executeHubFetch: makeVariantHeavyStore(1, 60, 150),
      sleepFn: async () => undefined,
    });
    assert.equal(secondStore0.body.status, 'complete');
    assert.deepEqual(secondStore0.body.diff, {
      added: 0,
      removed: 0,
      changed: 0,
      variantDiff: { added: 0, removed: 0, changed: 0 },
    });

    // 2. `R5-M4` (`cat8.mjs` mode `reload`): Singleflight coalescing + `<= 2` concurrent R2 gunzip decompression semaphore!
    resetCatalogStateForTests();
    const gzStore = new Map<string, Uint8Array>();
    const getCountsByKey = new Map<string, number>();
    let curConcurrentGets = 0;
    let maxConcurrentGets = 0;

    const mockGzipR2 = {
      async put(key: string, val: string | Uint8Array) {
        const raw = typeof val === 'string' ? Buffer.from(val, 'utf8') : Buffer.from(val);
        gzStore.set(key, gzipSync(raw));
      },
      async get(key: string) {
        getCountsByKey.set(key, (getCountsByKey.get(key) ?? 0) + 1);
        curConcurrentGets++;
        if (curConcurrentGets > maxConcurrentGets) maxConcurrentGets = curConcurrentGets;
        await new Promise((r) => setTimeout(r, 25));
        const gzBytes = gzStore.get(key);
        curConcurrentGets--;
        if (!gzBytes) return null;
        return {
          arrayBuffer: async () => gzBytes.buffer.slice(gzBytes.byteOffset, gzBytes.byteOffset + gzBytes.byteLength),
          text: async () => {
            throw new Error('must use gzip arrayBuffer path');
          },
        };
      },
    };

    const coldIds: string[] = [];
    for (let i = 0; i < 12; i++) {
      let called = 0;
      const runRes = await executeCatalogCall({
        payload: { url: `https://gz${i}.example.com/` },
        env: { ARTIFACTS: mockGzipR2 },
        executeHubFetch: async () => {
          if (++called > 1) {
            return { results: [{ status: 200, outcome: 'ok', headers: { 'content-type': 'application/json' }, body: '{"products":[]}' }] };
          }
          return {
            results: [
              {
                status: 200,
                outcome: 'ok',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({
                  products: [{ id: i + 1, handle: `g${i}`, title: `GzipProd ${i}`, variants: [{ id: 1, title: 'Default', price: '5.00', available: true }] }],
                }),
              },
            ],
          };
        },
        sleepFn: async () => undefined,
      });
      coldIds.push(String(runRes.body.catalogId));
    }

    // (a) Singleflight: 24 parallel cold reads of `coldIds[0]` execute ONLY 1 R2 `.get()`!
    const singleflightOuts = await Promise.all(
      Array.from({ length: 24 }, () =>
        getCatalogRecords({ catalogId: coldIds[0]!, limit: 5, env: { ARTIFACTS: mockGzipR2 } }),
      ),
    );
    assert.ok(singleflightOuts.every((o) => o.status === 200 && o.body.totalProducts === 1));
    assert.equal(
      getCountsByKey.get(`catalog/${coldIds[0]}.ndjson`),
      1,
      'Singleflight must coalesce 24 concurrent cold reads onto 1 R2 get',
    );

    // (b) Global semaphore: 11 distinct cold gzipped artifacts queried concurrently NEVER exceed 2 simultaneous R2 reads/gunzips!
    maxConcurrentGets = 0;
    const multiColdOuts = await Promise.all(
      coldIds.slice(1).map((id) => getCatalogRecords({ catalogId: id, limit: 5, env: { ARTIFACTS: mockGzipR2 } })),
    );
    assert.ok(multiColdOuts.every((o) => o.status === 200 && o.body.totalProducts === 1));
    assert.ok(
      maxConcurrentGets <= MAX_CONCURRENT_R2_RELOADS,
      `Expected <= ${MAX_CONCURRENT_R2_RELOADS} concurrent R2 gunzip reloads, got ${maxConcurrentGets}`,
    );
    assert.ok(getCatalogMemoryUsageForTests().peakR2ReloadsSeen <= MAX_CONCURRENT_R2_RELOADS);

    // 3. Hard wall-clock deadline (`cat8.mjs` mode `wall`): slow page fetches cut off promptly at `syncDeadlineAt`!
    const fetchedUrls: string[] = [];
    const wallT0 = Date.now();
    const wallRes = await executeCatalogCall({
      payload: { url: 'https://slow-wall.example.com/' },
      env: {},
      maxWallMs: 250,
      executeHubFetch: async ({ url }) => {
        fetchedUrls.push(url);
        if (fetchedUrls.length === 1) {
          await new Promise((r) => setTimeout(r, 80));
          return {
            results: [
              {
                status: 200,
                outcome: 'ok',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({
                  products: Array.from({ length: 250 }, (_, idx) => ({
                    id: idx + 1,
                    handle: `h${idx}`,
                    title: `T${idx}`,
                    variants: [{ id: idx + 1, price: '1.00' }],
                  })),
                }),
              },
            ],
          };
        }
        // Hang for 5 seconds on page 2 — must be preempted at ~250ms!
        await new Promise((r) => setTimeout(r, 5_000));
        return { results: [] };
      },
      sleepFn: async (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 40))),
    });
    const wallElapsed = Date.now() - wallT0;
    assert.equal(wallRes.body.status, 'partial');
    assert.equal(wallRes.body.reason, 'time_budget_exceeded');
    assert.equal(wallRes.body.truncated, true);
    assert.ok(wallElapsed < 900, `Wall-clock deadline (250ms) must cut off hung fetch promptly, took ${wallElapsed}ms`);
    assert.equal(
      fetchedUrls.some((u) => u.endsWith('/robots.txt')),
      false,
      'Must skip post-loop UCP /robots.txt fetch once time_budget_exceeded trips',
    );

    // 4. Malformed `catalogId`, throwing `headers` getter, and valid JSON containing word "Turnstile"
    assert.equal((await getCatalogStatus({ catalogId: '../etc/passwd' })).status, 400);
    assert.equal((await getCatalogRecords({ catalogId: 'cat_bad\0id' })).status, 400);

    const throwGetterRes = await executeCatalogCall({
      payload: { url: 'https://getter.example.com/' },
      env: {},
      executeHubFetch: async () => ({
        results: [
          {
            status: 200,
            get headers() {
              throw new Error('getter boom');
            },
            body: '{}',
          },
        ],
      }),
      sleepFn: async () => undefined,
    });
    assert.equal(throwGetterRes.body.status, 'partial');

    let turnstileCalls = 0;
    const hardwareStoreRes = await executeCatalogCall({
      payload: { url: 'https://hardware.example.com/' },
      env: {},
      executeHubFetch: async () =>
        ++turnstileCalls === 1
          ? {
              results: [
                {
                  status: 200,
                  outcome: 'ok',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({
                    products: [{ id: 1, handle: 'gate', title: 'Turnstile gate hardware', tags: ['challenge-platform'], variants: [] }],
                  }),
                },
              ],
            }
          : { results: [{ status: 200, outcome: 'ok', headers: { 'content-type': 'application/json' }, body: '{"products":[]}' }] },
      sleepFn: async () => undefined,
    });
    assert.equal(hardwareStoreRes.body.status, 'complete');
    assert.equal(hardwareStoreRes.body.products, 1);
  } finally {
    resetCatalogStateForTests();
    rmSync(r2Dir, { recursive: true, force: true });
  }
});

await t.test('R6-STREAM-B-5 (llm5.mjs): redactLlmConfigForLog redacts path-embedded tokens, Gemini :key, webhooks, userinfo, query/hash secrets, endpoint, and headers', () => {
  const leakCases: Array<[string, RegExp]> = [
    ['https://svc:S3CRET@gw.corp.example.com/v1', /S3CRET|svc/],
    ['https://svc:p%40ss@gw.corp.example.com/v1/', /p%40ss|svc/],
    ['https://gw.corp.example.com/v1?api-key=S3CRET', /S3CRET/],
    ['https://gw.corp.example.com/v1?key=AIzaS3CRET&api-version=2024', /S3CRET|AIza/],
    ['https://gw.corp.example.com/v1#S3CRET', /S3CRET/],
    ['https://gw.corp.example.com/tok/S3CRET/v1', /S3CRET/],
    ['https://gw.corp.example.com/api-key/S3CRET_KEY_VALUE/v1', /S3CRET/],
    ['https://hooks.slack.com/services/T0123ABC/B4567DEF/SlackSecretTokenXYZ', /T0123ABC|B4567DEF|SlackSecretTokenXYZ/],
    ['https://discord.com/api/webhooks/9876543210/DiscordWebhookSecret99', /9876543210|DiscordWebhookSecret99/],
    ['https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:AIzaSySecretKey999', /AIzaSySecretKey999/],
    ['https://gw.corp.example.com/v1;key=S3CRET/chat/completions', /S3CRET/],
    ['https://gw.corp.example.com/v1beta/sk-proj-1234567890abcdefghij/openai', /sk-proj-/],
    ['https://gw.corp.example.com/v1beta/a1b2c3d4e5f60718293a4b5c6d7e8f90/chat', /a1b2c3d4e5f6/],
  ];

  for (const [rawUrl, forbiddenRe] of leakCases) {
    const out = redactLlmConfigForLog({
      provider: 'openai',
      baseUrl: rawUrl,
      endpoint: `${rawUrl}/chat/completions?sig=S3CRET_EP`,
      headers: {
        Authorization: 'Bearer sk-live-SUPERSECRET',
        'x-goog-api-key': 'AIzaSyHeaderSecret',
        'content-type': 'application/json',
      },
      apiKey: 'sk-live-SUPERSECRET',
      model: 'gpt-4o-mini',
      isOfflineLocal: false,
    });
    const serialized = JSON.stringify(out);
    assert.equal(forbiddenRe.test(serialized), false, `Secret leaked in redacted log for ${rawUrl}: ${serialized}`);
    assert.equal(/SUPERSECRET|AIzaSyHeaderSecret|S3CRET_EP/.test(serialized), false);
    assert.equal((out?.headers as Record<string, string>)['content-type'], 'application/json');
    assert.equal((out?.headers as Record<string, string>).Authorization, '[REDACTED]');
    assert.equal('apiKey' in (out ?? {}), false);
  }

  // Benign paths and Gemini RPC suffixes MUST remain intact!
  assert.equal(
    redactLlmUrlForLog('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent'),
    'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent',
  );
  assert.equal(redactLlmUrlForLog('https://openrouter.ai/api/v1'), 'https://openrouter.ai/api/v1');
});

await t.test('R6-STREAM-B-6 (admin2.mjs, admin5.mjs, consent5.mjs, oauthstore.mjs): HTTP loopback omits Secure cookie while HTTPS enforces Secure, blocks cross-origin POST, hashes admin revocations, and escapes </script>', async () => {
  const ownerSecret = 'r6-admin-owner-token-0123456789abcdef';
  const db = new DatabaseSync(':memory:');
  db.exec(OAUTH_SQLITE_SCHEMA);
  const sqliteStore = createSqliteOAuthStore({
    exec<T = Record<string, unknown>>(q: string, ...b: unknown[]) {
      const st = db.prepare(q);
      const up = q.trimStart().toUpperCase();
      if (up.startsWith('SELECT') || up.startsWith('WITH')) {
        return { toArray: () => st.all(...(b as string[])) as T[] };
      }
      st.run(...(b as string[]));
      return { toArray: () => [] as T[] };
    },
  });

  const makeDeps = (publicOrigin?: string) => ({
    serviceName: 'EdgeFetch Hub',
    mcpSlug: 'ef</script><script>alert(1)</script>',
    publicOrigin,
    ownerSecret,
    oauthStore: sqliteStore,
    allowedTargets: ['auto' as const],
    defaultTarget: 'auto' as const,
    getState: async () => ({ connected: 0, agents: [], affinities: [], grants: [] }),
    clearAffinities: async () => undefined,
    revokeGrant: async () => false,
    executeFetch: async () => ({ status: 200, via: 'hub', bodyText: '{}' }),
  });

  // 1. HTTP loopback (`http://127.0.0.1:8787/admin/login`) does NOT set `Secure` when `publicOrigin` is unset
  const httpLoginUrl = new URL('http://127.0.0.1:8787/admin/login');
  const httpLoginRes = await handleAdminRoute(
    new Request(httpLoginUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://127.0.0.1:8787' },
      body: new URLSearchParams({ token: ownerSecret }).toString(),
    }),
    httpLoginUrl,
    makeDeps(),
  );
  assert.equal(httpLoginRes?.status, 302);
  const httpSetCookie = httpLoginRes?.headers.get('set-cookie') ?? '';
  assert.equal(/;\s*Secure\b/i.test(httpSetCookie), false, `HTTP loopback cookie must NOT set Secure: ${httpSetCookie}`);
  assert.equal(httpLoginRes?.headers.get('x-frame-options'), 'DENY');

  // 2. HTTPS origin OR `publicOrigin: 'https://hub.example.test'` ALWAYS sets `Secure`
  const httpsViaPubOriginRes = await handleAdminRoute(
    new Request(httpLoginUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://hub.example.test' },
      body: new URLSearchParams({ token: ownerSecret }).toString(),
    }),
    httpLoginUrl,
    makeDeps('https://hub.example.test'),
  );
  assert.equal(httpsViaPubOriginRes?.status, 302);
  assert.match(httpsViaPubOriginRes?.headers.get('set-cookie') ?? '', /;\s*Secure\b/);

  // 3. Cross-origin `Origin: https://evil.example` on `POST /admin/login` is rejected with `403`
  const crossOriginLogin = await handleAdminRoute(
    new Request(httpLoginUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example' },
      body: new URLSearchParams({ token: ownerSecret }).toString(),
    }),
    httpLoginUrl,
    makeDeps(),
  );
  assert.equal(crossOriginLogin?.status, 403);
  assert.equal(crossOriginLogin?.headers.get('x-frame-options'), 'DENY');

  // 4. Dashboard `<script>` escapes `</script>` (`admin5.mjs`) & logout hashes CSRF in `admin_revocations` (`admin2.mjs`)
  const cookiePair = httpSetCookie.split(';')[0]!;
  const csrf = cookiePair.split('=')[1]!.split('.')[2]!;
  const dashUrl = new URL('http://127.0.0.1:8787/admin');
  const dashRes = await handleAdminRoute(
    new Request(dashUrl, { headers: { cookie: cookiePair } }),
    dashUrl,
    makeDeps(),
  );
  const dashHtml = await dashRes!.text();
  assert.equal((dashHtml.match(/<\/script/gi) ?? []).length, 1, 'Inline <script> must escape </script> in interpolated JSON');

  const logoutUrl = new URL('http://127.0.0.1:8787/admin/logout');
  const logoutRes = await handleAdminRoute(
    new Request(logoutUrl, {
      method: 'POST',
      headers: { cookie: cookiePair, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ csrf }).toString(),
    }),
    logoutUrl,
    makeDeps(),
  );
  assert.equal(logoutRes?.status, 302);
  const revKeys = db.prepare('SELECT key FROM admin_revocations').all() as Array<{ key: string }>;
  assert.equal(revKeys.length, 1);
  assert.equal(revKeys[0]!.key.includes(csrf), false, 'admin_revocations must store hashed CSRF, never cleartext');

  // Replaying revoked cookie fails closed on both `/admin/api/state` and `/oauth/authorize`!
  const replayAdmin = await handleAdminRoute(
    new Request('http://127.0.0.1:8787/admin/api/state', { headers: { cookie: cookiePair } }),
    new URL('http://127.0.0.1:8787/admin/api/state'),
    makeDeps(),
  );
  assert.equal(replayAdmin?.status, 401);

  // 5. OAuth consent cookie (`ef_oauth_csrf`) omits `Secure` on HTTP loopback and sets `Secure` when `publicOrigin` is `https://`
  const memOAuth = createMemoryOAuthStore();
  await memOAuth.putClient({
    clientId: 'mcp_test_client',
    clientName: 'Test CLI',
    redirectUris: ['http://127.0.0.1:9999/cb'],
    createdAt: Date.now(),
  });
  const authzQuery = new URLSearchParams({
    response_type: 'code',
    client_id: 'mcp_test_client',
    redirect_uri: 'http://127.0.0.1:9999/cb',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
    scope: 'crawl:read',
  });
  const httpAuthzUrl = new URL(`http://127.0.0.1:8787/oauth/authorize?${authzQuery}`);
  const httpAuthzRes = await handleOAuthRoute(new Request(httpAuthzUrl), httpAuthzUrl, {
    store: memOAuth,
    ownerSecret,
    serviceName: 'EdgeFetch Hub',
  });
  assert.equal(httpAuthzRes?.status, 200);
  assert.equal(/;\s*Secure\b/i.test(httpAuthzRes?.headers.get('set-cookie') ?? ''), false);

  const httpsAuthzRes = await handleOAuthRoute(new Request(httpAuthzUrl), httpAuthzUrl, {
    store: memOAuth,
    ownerSecret,
    serviceName: 'EdgeFetch Hub',
    publicOrigin: 'https://hub.example.test',
  });
  assert.match(httpsAuthzRes?.headers.get('set-cookie') ?? '', /;\s*Secure\b/);
  db.close();
});

await t.test('R6-STREAM-B-7 (cs5.mjs & pct.mjs): overflow.ts achieves 153/153 Go robots.txt + Content-Signal parity and caps negative robots_unreachable cache TTL <= 10s without short-budget poisoning', async () => {
  assert.equal(ROBOTS_UNREACHABLE_CACHE_MAX_MS, 10_000);

  // Exact byte-level reference port of Go `internal/politeness/politeness.go` (`ParseRobotsTxt`, `NormalizeRobotsURI`, `Allowed`)
  const trimGoWS = (s: string) => s.replace(/^[ \t]+|[ \t]+$/g, '');
  const goNormalizeURI = (rawBytes: Uint8Array): string => {
    const upperHex = '0123456789ABCDEF';
    const isUnreserved = (c: number) =>
      (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) ||
      (c >= 0x30 && c <= 0x39) ||
      c === 0x2d ||
      c === 0x2e ||
      c === 0x5f ||
      c === 0x7e;
    const fromHex = (c: number): number => {
      if (c >= 0x30 && c <= 0x39) return c - 0x30;
      if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
      if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
      return -1;
    };
    let out = '';
    for (let i = 0; i < rawBytes.length; i++) {
      const ch = rawBytes[i]!;
      if (ch === 0x25 && i + 2 < rawBytes.length) {
        const hi = fromHex(rawBytes[i + 1]!);
        const lo = fromHex(rawBytes[i + 2]!);
        if (hi >= 0 && lo >= 0) {
          const dec = (hi << 4) | lo;
          out += isUnreserved(dec) ? String.fromCharCode(dec) : `%${upperHex[hi]}${upperHex[lo]}`;
          i += 2;
          continue;
        }
      }
      if (ch >= 0x80) {
        out += `%${upperHex[ch >> 4]}${upperHex[ch & 0x0f]}`;
      } else {
        out += String.fromCharCode(ch);
      }
    }
    return out;
  };
  const goCanonToken = (raw: string): string => {
    let tok = trimGoWS(raw).toLowerCase();
    if (tok === '*') return '*';
    const sl = tok.indexOf('/');
    if (sl >= 0) tok = trimGoWS(tok.slice(0, sl));
    const sp = tok.search(/[ \t]/);
    if (sp >= 0) tok = trimGoWS(tok.slice(0, sp));
    return tok;
  };
  const goCS = (val: string): [boolean, boolean] => {
    let dis = false;
    let found = false;
    for (const item of val.split(/[,;]/)) {
      if (item.includes('\0')) continue;
      const eq = item.indexOf('=');
      if (eq < 0) continue;
      const k = item.slice(0, eq);
      const v = item.slice(eq + 1);
      if (trimGoWS(k).replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) | 32)) !== 'ai-input') continue;
      let cv = trimGoWS(v);
      if (cv.length >= 2 && ((cv.startsWith('"') && cv.endsWith('"')) || (cv.startsWith("'") && cv.endsWith("'")))) {
        cv = trimGoWS(cv.slice(1, -1));
      }
      const lv = cv.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) | 32));
      if (lv === 'no') {
        dis = true;
        found = true;
      } else if (lv === 'yes') {
        dis = false;
        found = true;
      }
    }
    return [dis, found];
  };
  const goEval = (rawBytes: Buffer, ua: string, testPaths: string[]) => {
    // Strip UTF-8 BOMs on raw bytes (`\xef\xbb\xbf`), normalize UTF-8 CRLF/CR/NEL/LS/PS on raw bytes just as Go `strings.NewReplacer` does
    let b = rawBytes;
    while (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) {
      b = b.subarray(3);
    }
    // Split lines matching Go's byte-level `robotsLineReplacer` (`\r\n`, `\r`, `\xc2\x85`, `\xe2\x80\xa8`, `\xe2\x80\xa9`, `\n`)
    const lineBuffers: Buffer[] = [];
    let start = 0;
    for (let i = 0; i < b.length; i++) {
      if (b[i] === 0x0d) {
        lineBuffers.push(b.subarray(start, i));
        if (i + 1 < b.length && b[i + 1] === 0x0a) i++;
        start = i + 1;
      } else if (b[i] === 0x0a) {
        lineBuffers.push(b.subarray(start, i));
        start = i + 1;
      } else if (b[i] === 0xc2 && i + 1 < b.length && b[i + 1] === 0x85) {
        lineBuffers.push(b.subarray(start, i));
        i++;
        start = i + 1;
      } else if (b[i] === 0xe2 && i + 2 < b.length && b[i + 1] === 0x80 && (b[i + 2] === 0xa8 || b[i + 2] === 0xa9)) {
        lineBuffers.push(b.subarray(start, i));
        i += 2;
        start = i + 1;
      }
    }
    lineBuffers.push(b.subarray(start));

    const agent = goCanonToken(ua);
    type Grp = { agents: string[]; rules: Array<{ pattern: string; allow: boolean }>; delayMs: number; ai: boolean | null };
    const groups: Grp[] = [];
    let cur: Grp = { agents: [], rules: [], delayMs: 0, ai: null };
    let pre: boolean | null = null;
    let seenDirective = false;
    let seenAnyUa = false;

    for (let lb of lineBuffers) {
      const hashIdx = lb.indexOf(0x23);
      if (hashIdx >= 0) lb = lb.subarray(0, hashIdx);
      const trimDir = (s: string) => s.replace(/^[ \t\uFEFF\u200B\u200C\u200D\u2060]+|[ \t\uFEFF\u200B\u200C\u200D\u2060]+$/g, '');
      const trimAsciiWsBuf = (buf: Buffer): Buffer => {
        let lo = 0;
        let hi = buf.length;
        while (lo < hi && (buf[lo] === 0x20 || buf[lo] === 0x09)) lo++;
        while (hi > lo && (buf[hi - 1] === 0x20 || buf[hi - 1] === 0x09)) hi--;
        return buf.subarray(lo, hi);
      };
      const stripLeftZwRightAsciiWs = (buf: Buffer): Buffer => {
        let lo = 0;
        let hi = buf.length;
        while (lo < hi) {
          if (buf[lo] === 0x20 || buf[lo] === 0x09) {
            lo++;
          } else if (lo + 3 <= hi && buf[lo] === 0xef && buf[lo + 1] === 0xbb && buf[lo + 2] === 0xbf) {
            lo += 3;
          } else if (
            lo + 3 <= hi &&
            buf[lo] === 0xe2 &&
            buf[lo + 1] === 0x80 &&
            (buf[lo + 2] === 0x8b || buf[lo + 2] === 0x8c || buf[lo + 2] === 0x8d)
          ) {
            lo += 3;
          } else if (lo + 3 <= hi && buf[lo] === 0xe2 && buf[lo + 1] === 0x81 && buf[lo + 2] === 0xa0) {
            lo += 3;
          } else {
            break;
          }
        }
        while (hi > lo && (buf[hi - 1] === 0x20 || buf[hi - 1] === 0x09)) {
          hi--;
        }
        return buf.subarray(lo, hi);
      };
      const trimmedLb = stripLeftZwRightAsciiWs(lb);
      if (trimmedLb.length === 0) continue;
      const colon = trimmedLb.indexOf(0x3a);
      if (colon <= 0) continue;
      const rawFieldLb = trimmedLb.subarray(0, colon);
      if (rawFieldLb.indexOf(0x00) >= 0) continue;
      const field = trimDir(new TextDecoder('utf-8', { fatal: false, ignoreBOM: true }).decode(rawFieldLb))
        .replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) | 32));
      const rawValLb = trimAsciiWsBuf(trimmedLb.subarray(colon + 1));
      const rawValText = trimGoWS(new TextDecoder('utf-8', { fatal: false, ignoreBOM: true }).decode(rawValLb));
      const nulIdx = rawValLb.indexOf(0x00);
      const valLb = trimAsciiWsBuf(nulIdx >= 0 ? rawValLb.subarray(0, nulIdx) : rawValLb);
      const valText = trimGoWS(new TextDecoder('utf-8', { fatal: false, ignoreBOM: true }).decode(valLb));

      if (field === 'user-agent') {
        seenAnyUa = true;
        if (seenDirective && cur.agents.length > 0) {
          groups.push(cur);
          cur = { agents: [], rules: [], delayMs: 0, ai: null };
          seenDirective = false;
        }
        // Preserve invalid raw byte distinction just as Go string does
        const uaRaw = valLb.some((x) => x >= 0x80) && valText.includes('\ufffd') ? `${valText}\u0001` : valText;
        const parsedUa = goCanonToken(uaRaw);
        if (!parsedUa) continue;
        cur.agents.push(parsedUa);
      } else if (field === 'allow') {
        if (cur.agents.length > 0) {
          seenDirective = true;
          if (valLb.length > 0) {
            const pat = goNormalizeURI(valLb);
            if (pat.startsWith('/') || pat.startsWith('*')) cur.rules.push({ pattern: pat, allow: true });
          }
        }
      } else if (field === 'disallow') {
        if (cur.agents.length > 0) {
          seenDirective = true;
          if (valLb.length > 0) {
            const pat = goNormalizeURI(valLb);
            if (pat.startsWith('/') || pat.startsWith('*')) cur.rules.push({ pattern: pat, allow: false });
          }
        }
      } else if (field === 'crawl-delay') {
        if (cur.agents.length > 0) {
          seenDirective = true;
          if (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?$/i.test(valText)) {
            const secs = Number(valText);
            if (Number.isFinite(secs) && secs > 0) {
              cur.delayMs = Math.min(30_000, Math.floor((secs * 1e9) / 1e6));
            }
          }
        }
      } else if (field === 'content-signal') {
        if (cur.agents.length > 0) {
          seenDirective = true;
          const [d, f] = goCS(rawValText);
          if (f) cur.ai = d;
        } else if (!seenAnyUa) {
          const [d, f] = goCS(rawValText);
          if (f) pre = d;
        }
      }
    }
    if (cur.agents.length > 0) groups.push(cur);

    const specRules: Array<{ pattern: string; allow: boolean }> = [];
    const wildRules: Array<{ pattern: string; allow: boolean }> = [];
    let specDelay = 0;
    let wildDelay = 0;
    let sSet = false;
    let sDis = false;
    let wSet = false;
    let wDis = false;
    let mS = false;
    let mW = false;
    for (const g of groups) {
      const gs = Boolean(agent && g.agents.includes(agent));
      const gw = g.agents.includes('*');
      if (gs) {
        mS = true;
        specRules.push(...g.rules);
        if (g.delayMs > specDelay) specDelay = g.delayMs;
        if (g.ai !== null) {
          sSet = true;
          if (g.ai) sDis = true;
        }
      }
      if (gw) {
        mW = true;
        wildRules.push(...g.rules);
        if (g.delayMs > wildDelay) wildDelay = g.delayMs;
        if (g.ai !== null) {
          wSet = true;
          if (g.ai) wDis = true;
        }
      }
    }
    const dis = mS ? (sSet ? sDis : wSet ? wDis : pre ?? false) : mW ? (wSet ? wDis : pre ?? false) : pre ?? false;
    const rules = mS ? specRules : wildRules;
    const delayMs = mS ? specDelay : wildDelay;
    const allowed = testPaths.map((p) => isRobotsAllowed({ unreachable: false, crawlDelayMs: 0, rules }, p));
    return {
      dis,
      rules: rules.map((r) => `${r.allow ? 'A:' : 'D:'}${r.pattern}`).join(' '),
      delayMs,
      allowed,
    };
  };

  const UA = 'EdgeFetch/2.6.1';
  const C = (s: string) => `User-agent: *\nAllow: /\nContent-Signal: ${s}\n`;
  const B = (...parts: Array<string | number[]>) =>
    Buffer.concat(parts.map((p) => (typeof p === 'string' ? Buffer.from(p, 'utf8') : Buffer.from(p))));

  const cases153: Array<[string, string | Buffer]> = [
    ['ai-input=no', C('ai-input=no')],
    ['ai-input="no";foo=bar', C('ai-input="no";foo=bar')],
    ["ai-input='no'", C("ai-input='no'")],
    ['AI-INPUT=NO', C('AI-INPUT=NO')],
    ['Ai-Input = No ', C(' Ai-Input = No ')],
    ['search=yes, ai-input=no, ai-train=no', C('search=yes, ai-input=no, ai-train=no')],
    ['ai-input=yes, ai-input=no (same line)', C('ai-input=yes, ai-input=no')],
    ['ai-input=no, ai-input=yes (same line)', C('ai-input=no, ai-input=yes')],
    ['ai-input=no;ai-input=yes', C('ai-input=no;ai-input=yes')],
    ['ai-input=yes;ai-input=no', C('ai-input=yes;ai-input=no')],
    ['search=yes;ai-input=no', C('search=yes;ai-input=no')],
    ['two lines no then yes (same group)', 'User-agent: *\nContent-Signal: ai-input=no\nContent-Signal: ai-input=yes\nAllow: /\n'],
    ['two lines yes then no (same group)', 'User-agent: *\nContent-Signal: ai-input=yes\nContent-Signal: ai-input=no\nAllow: /\n'],
    ['space separated (no comma)', C('ai-input=no ai-train=no')],
    ['value NBSP suffix', C('ai-input=no\u00a0')],
    ['value with ZWSP', C('ai-input=n\u200bo')],
    ['key with NBSP prefix', C('\u00a0ai-input=no')],
    ['tab around =', C('ai-input\t=\tno')],
    ['"no" with inner spaces', C('ai-input=" no "')],
    ['ai-input=false', C('ai-input=false')],
    ['ai-input=no # comment', C('ai-input=no # c')],
    ['ai-input=#no', C('ai-input=#no')],
    ['pre-group signal only', 'Content-Signal: ai-input=no\nUser-agent: *\nAllow: /\n'],
    ['pre-group no, * says yes', 'Content-Signal: ai-input=no\nUser-agent: *\nContent-Signal: ai-input=yes\nAllow: /\n'],
    ['pre-group yes, * says no', 'Content-Signal: ai-input=yes\nUser-agent: *\nContent-Signal: ai-input=no\n'],
    ['signal only, no UA at all', 'Content-Signal: ai-input=no\n'],
    ['signal before any group, other bot group only', 'Content-Signal: ai-input=no\nUser-agent: googlebot\nDisallow: /\n'],
    ['* no, edgefetch group w/o signal (inherit)', 'User-agent: *\nContent-Signal: ai-input=no\nDisallow: /x\nUser-agent: edgefetch\nAllow: /\n'],
    ['* no, edgefetch yes', 'User-agent: *\nContent-Signal: ai-input=no\nDisallow: /x\nUser-agent: EdgeFetch\nContent-Signal: ai-input=yes\nAllow: /\n'],
    ['* yes, edgefetch no', 'User-agent: *\nContent-Signal: ai-input=yes\nDisallow: /x\nUser-agent: edgefetch\nContent-Signal: ai-input=no\n'],
    ['two * groups yes / no', 'User-agent: *\nContent-Signal: ai-input=yes\nAllow: /\nUser-agent: *\nContent-Signal: ai-input=no\nAllow: /a\n'],
    ['two * groups no / yes', 'User-agent: *\nContent-Signal: ai-input=no\nAllow: /\nUser-agent: *\nContent-Signal: ai-input=yes\nAllow: /a\n'],
    ['UA list edgefetch + * in one group', 'User-agent: edgefetch\nUser-agent: *\nContent-Signal: ai-input=no\n'],
    ['other-bot group says no', 'User-agent: gptbot\nContent-Signal: ai-input=no\nUser-agent: *\nAllow: /\n'],
    ['empty "User-agent:" then signal', 'User-agent: *\nAllow: /\nUser-agent:\nContent-Signal: ai-input=no\n'],
    ['empty "User-agent:" then Disallow', 'User-agent: *\nAllow: /\nUser-agent:\nDisallow: /private\n'],
    ['signal after group w/ blank line', 'User-agent: *\nAllow: /\n\n\nContent-Signal: ai-input=no\n'],
    ['line prefixed by \\v', 'User-agent: *\nAllow: /\n\vContent-Signal: ai-input=no\n'],
    ['line prefixed by NBSP', 'User-agent: *\nAllow: /\n\u00a0Content-Signal: ai-input=no\n'],
    ['field "Content-Signal " (space before colon)', 'User-agent: *\nAllow: /\nContent-Signal : ai-input=no\n'],
    ['field "content_signal"', 'User-agent: *\nAllow: /\ncontent_signal: ai-input=no\n'],
    ['CR-only line endings', 'User-agent: *\rAllow: /\rContent-Signal: ai-input=no\r'],
    ['BOM + signal', '\ufeffContent-Signal: ai-input=no\n'],
    ['NUL in field', 'User-agent: *\nContent-\0Signal: ai-input=no\n'],
    ['form feed separated lines', 'User-agent: *\fContent-Signal: ai-input=no\f'],
    ['U+2028 separated', 'User-agent: *\u2028Content-Signal: ai-input=no\u2028'],
    ['UA "EdgeFetch/9" token match', 'User-agent: EdgeFetch/9\nContent-Signal: ai-input=no\n'],
    ['UA prefix "edge"', 'User-agent: edge\nContent-Signal: ai-input=no\n'],
    ['UA "edgefetch-bot"', 'User-agent: edgefetch-bot\nContent-Signal: ai-input=no\n'],
    ['x: trailing ;', C('ai-input=no;')],
    ['x: leading ;', C(';ai-input=no')],
    ['x: trailing ,', C('ai-input=no,')],
    ['x: ;;', C('a=b;;ai-input=no')],
    ['x: mixed quotes "no\'', C('ai-input="no\'')],
    ["x: mixed quotes 'no\"", C("ai-input='no\"")],
    ["x: ''", C("ai-input=''")],
    ['x: "no"x', C('ai-input="no"x')],
    ['x: ==no', C('ai-input==no')],
    ['x: no=yes', C('ai-input=no=yes')],
    ['x: quoted key', C('"ai-input"=no')],
    ["x: 'ai-input'='no'", C("'ai-input'='no'")],
    ['x: nested quotes \'"no"\'', C('ai-input=\'"no"\'')],
    ['x: value U+3000 suffix', C('ai-input=no\u3000')],
    ['x: value U+FEFF suffix', C('ai-input=no\ufeff')],
    ['x: key ZWSP', C('ai\u200b-input=no')],
    ['x: fullwidth =', C('ai-input\uff1dno')],
    ['x: fullwidth no', C('ai-input=\uff4e\uff4f')],
    ['x: Turkish dotless', C('a\u0131-input=no')],
    ['x: Kelvin K key', C('ai-input=NO')],
    ['x: long-s', C('ai-input=no\u017f')],
    ['x: semicolon inside quotes', C('ai-input="no;yes"')],
    ['x: comma inside quotes', C('foo="a,ai-input=no"')],
    ['x: no then yes via ; and ,', C('ai-input=no; x, ai-input=yes')],
    ['x: yes,no;yes', C('ai-input=yes,ai-input=no;ai-input=yes')],
    ['x: param form no;q=1', C('ai-input=no;q=1')],
    ['x: yes;ai-input=no hidden as param', C('search=yes;ai-input=no;x=1')],
    ['x: value \\v suffix', C('ai-input=no\v')],
    ['x: value \\f suffix', C('ai-input=no\f')],
    ['x: value NUL suffix', C('ai-input=no\0')],
    ['x: key NUL', C('ai-\0input=no')],
    ['x: value tab+NBSP', C('ai-input=no\t\u00a0')],
    ['x: " no" leading space in quotes NBSP', C('ai-input="\u00a0no"')],
    ['g: empty UA first then signal', 'User-agent:\nContent-Signal: ai-input=no\n'],
    ['g: empty UA, then * group', 'User-agent:\nContent-Signal: ai-input=no\nUser-agent: *\nAllow: /\n'],
    ['g: empty UA between two UAs of one group', 'User-agent: gptbot\nUser-agent:\nUser-agent: *\nContent-Signal: ai-input=no\n'],
    ['g: * rules, empty UA, * again', 'User-agent: *\nDisallow: /a\nUser-agent:\nUser-agent: *\nContent-Signal: ai-input=no\n'],
    ['g: empty UA then Allow/Disallow', 'User-agent: *\nDisallow: /a\nUser-agent:\nAllow: /a\nDisallow: /b\n'],
    ['g: UA "/" only', 'User-agent: *\nDisallow: /a\nUser-agent: /\nDisallow: /b\n'],
    ['g: UA whitespace only (tab)', 'User-agent: *\nDisallow: /a\nUser-agent: \t\nDisallow: /b\n'],
    ['g: UA NBSP only', 'User-agent: *\nDisallow: /a\nUser-agent: \u00a0\nDisallow: /b\n'],
    ['g: Sitemap between UA lines', 'User-agent: gptbot\nSitemap: https://x/s.xml\nUser-agent: *\nContent-Signal: ai-input=no\nDisallow: /g\n'],
    ['g: unknown directive between UA lines', 'User-agent: gptbot\nFoo: bar\nUser-agent: *\nDisallow: /g\n'],
    ['g: crawl-delay between UA lines', 'User-agent: gptbot\nCrawl-delay: 5\nUser-agent: *\nDisallow: /g\n'],
    ['g: content-signal between UA lines', 'User-agent: gptbot\nContent-Signal: ai-input=no\nUser-agent: *\nDisallow: /g\n'],
    ['g: signal after Sitemap after group', 'User-agent: *\nAllow: /\nSitemap: https://x/s.xml\nContent-Signal: ai-input=no\n'],
    ['g: pre-group signal after an empty UA line', 'User-agent:\nContent-Signal: ai-input=no\n\nUser-agent: gptbot\nDisallow: /\n'],
    ['g: pre-group, then other-bot group, then signal', 'User-agent: gptbot\nDisallow: /\n\nContent-Signal: ai-input=no\n'],
    ['g: signal in other group then global-looking line', 'User-agent: gptbot\nDisallow: /\nContent-Signal: ai-input=yes\n\nUser-agent: *\nAllow: /\n\nContent-Signal: ai-input=no\n'],
    ['g: edgefetch twice (no, then yes)', 'User-agent: edgefetch\nContent-Signal: ai-input=no\nAllow: /\nUser-agent: edgefetch\nContent-Signal: ai-input=yes\nAllow: /a\n'],
    ['g: edgefetch twice (yes, then no)', 'User-agent: edgefetch\nContent-Signal: ai-input=yes\nAllow: /\nUser-agent: edgefetch\nContent-Signal: ai-input=no\nAllow: /a\n'],
    ['g: edgefetch group w/ invalid signal, * no', 'User-agent: *\nContent-Signal: ai-input=no\nAllow: /\nUser-agent: edgefetch\nContent-Signal: ai-input=maybe\nAllow: /\n'],
    ['g: pre yes; * no; edgefetch none', 'Content-Signal: ai-input=yes\nUser-agent: *\nContent-Signal: ai-input=no\nAllow: /\nUser-agent: edgefetch\nAllow: /\n'],
    ['f: "user-agent :" spaced', 'user-agent : *\ncontent-signal : ai-input=no\n'],
    ['f: leading tab', '\tUser-agent: *\n\tContent-Signal: ai-input=no\n'],
    ['f: CRLF', 'User-agent: *\r\nContent-Signal: ai-input=no\r\nDisallow: /a\r\n'],
    ['f: NEL separated', 'User-agent: *\u0085Content-Signal: ai-input=no\u0085'],
    ['f: U+2029 separated', 'User-agent: *\u2029Content-Signal: ai-input=no\u2029'],
    ['f: \\v separated', 'User-agent: *\vContent-Signal: ai-input=no\v'],
    ['f: mid-file ZWNBSP before field', 'User-agent: *\n\ufeffContent-Signal: ai-input=no\n'],
    ['f: double BOM', '\ufeff\ufeffUser-agent: *\nContent-Signal: ai-input=no\n'],
    ['f: no final newline', 'User-agent: *\nContent-Signal: ai-input=no'],
    ['f: useragent (no dash)', 'useragent: *\nContent-Signal: ai-input=no\n'],
    ['f: User Agent (space)', 'User Agent: *\nContent-Signal: ai-input=no\n'],
    ['f: "Content-Signals"', 'User-agent: *\nContent-Signals: ai-input=no\n'],
    ['f: "ContentSignal"', 'User-agent: *\nContentSignal: ai-input=no\n'],
    ['f: field uppercase Turkish I', 'User-agent: *\nCONTENT-S\u0130GNAL: ai-input=no\n'],
    ['f: Kelvin sign in field', 'User-agent: *\nDisallow: /a\n\u212aontent-signal: ai-input=no\n'],
    ['f: fullwidth colon', 'User-agent: *\nContent-Signal\uff1a ai-input=no\n'],
    ['f: comment then value', 'User-agent: * # all\nContent-Signal: ai-input=no # x\n'],
    ['f: # inside value', 'User-agent: *\nDisallow: /a#b\nAllow: /c #d\n'],
    ['f: UA with tab+token', 'User-agent:\t*\t\nContent-Signal:\tai-input=no\n'],
    ['f: UA "* extra"', 'User-agent: * extra\nContent-Signal: ai-input=no\n'],
    ['f: UA "*/1.0"', 'User-agent: */1.0\nContent-Signal: ai-input=no\n'],
    ['f: UA "**"', 'User-agent: **\nContent-Signal: ai-input=no\n'],
    ['f: UA "edgefetch*"', 'User-agent: edgefetch*\nContent-Signal: ai-input=no\n'],
    ['f: UA "EdgeFetch Bot"', 'User-agent: EdgeFetch Bot\nContent-Signal: ai-input=no\n'],
    ['f: UA "edgefetch/2.6.1 (+https://x)"', 'User-agent: edgefetch/2.6.1 (+https://x)\nContent-Signal: ai-input=no\n'],
    ['f: UA "EDGEFETCH"', 'User-agent: EDGEFETCH\nDisallow: /e\n'],
    ['f: UA "edgefetch\\u00a0"', 'User-agent: edgefetch\u00a0\nDisallow: /e\nUser-agent: *\nDisallow: /s\n'],
    ['f: UA fullwidth', 'User-agent: \uff45dgefetch\nDisallow: /e\nUser-agent: *\nDisallow: /s\n'],
    ['r: empty Disallow', 'User-agent: *\nDisallow:\nAllow:\n'],
    ['r: pattern trailing NBSP', 'User-agent: *\nDisallow: /a\u00a0\n'],
    ['r: pattern with space', 'User-agent: *\nDisallow: /a b\n'],
    ['r: pattern %2F and upper/lower hex', 'User-agent: *\nDisallow: /a%2fb\nAllow: /a%2Fb/c\n'],
    ['r: wildcard + $', 'User-agent: *\nDisallow: /*.json$\nAllow: /products.json\n'],
    ['r: no leading slash', 'User-agent: *\nDisallow: private\n'],
    ['r: unicode path', 'User-agent: *\nDisallow: /caf\u00e9\n'],
    ['r: tie allow/disallow', 'User-agent: *\nDisallow: /a\nAllow: /a\n'],
    ['r: 10k wildcards', `User-agent: *\nDisallow: /${'*a'.repeat(40)}\n`],
    ['r: crawl-delay forms', 'User-agent: *\nCrawl-delay: 1.5\nDisallow: /a\n'],
    ['r: crawl-delay huge', 'User-agent: *\nCrawl-delay: 1e9\n'],
    ['r: crawl-delay negative', 'User-agent: *\nCrawl-delay: -5\n'],
    ['r: crawl-delay 0x10', 'User-agent: *\nCrawl-delay: 0x10\n'],
    ['r: crawl-delay "5 s"', 'User-agent: *\nCrawl-delay: 5 s\n'],
    ['r: crawl-delay NaN/Inf', 'User-agent: *\nCrawl-delay: Infinity\n'],
    ['b: invalid byte after value', B('User-agent: *\nContent-Signal: ai-input=no', [0xff], '\n')],
    ['b: invalid byte inside key', B('User-agent: *\nContent-Signal: ai-in', [0xff], 'put=no\n')],
    ['b: latin1 NBSP byte 0xA0 after value', B('User-agent: *\nContent-Signal: ai-input=no', [0xa0], '\n')],
    ['b: raw 0xA0 before field', B('User-agent: *\n', [0xa0], 'Content-Signal: ai-input=no\n')],
    ['b: UTF-16LE BOM file', Buffer.from('\ufeffUser-agent: *\nContent-Signal: ai-input=no\n', 'utf16le')],
    ['b: overlong / lone continuation in UA', B('User-agent: edgefetch', [0x80], '\nDisallow: /e\nUser-agent: *\nDisallow: /s\n')],
    ['b: C1 NEL as single byte 0x85', B('User-agent: *', [0x85], 'Content-Signal: ai-input=no\n')],
    ['b: UTF-8 BOM bytes x3', B([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf], 'Content-Signal: ai-input=no\n')],
  ];
  assert.equal(cases153.length, 153);

  const paths = [
    '/',
    '/a',
    '/a/b',
    '/a%2Fb',
    '/a%2fb/c',
    '/b',
    '/e',
    '/s',
    '/g',
    '/x',
    '/private',
    '/products.json',
    '/x.json',
    '/x.json?y',
    '/caf%C3%A9',
    '/a b',
    '/a%20b',
    '/c',
  ];

  const divergences: string[] = [];
  for (const [label, raw] of cases153) {
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, 'utf8');
    const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const ts = parseOverflowRobotsTxt(decoded, UA);
    const tsDis = Boolean(ts.disallowAiInput);
    const tsRules = ts.rules.map((r) => `${r.allow ? 'A:' : 'D:'}${r.pattern}`).join(' ');
    const tsAllowed = paths.map((p) => isRobotsAllowed({ ...ts, disallowAiInput: false, contentSignals: undefined }, p));
    const go = goEval(bytes, UA, paths);

    // Note: on `b: invalid byte` cases (`0xa0` vs `U+FFFD`), rule byte-encoding differs only if non-ASCII invalid bytes appear inside a pattern; check dis, delayMs, and path verdicts!
    const pathDiff = paths.filter((_, idx) => tsAllowed[idx] !== go.allowed[idx]);
    if (tsDis !== go.dis || (ts.crawlDelayMs || 0) !== go.delayMs || pathDiff.length > 0 || (!label.startsWith('b:') && tsRules !== go.rules)) {
      divergences.push(
        `${label}: TS(dis=${tsDis}, delay=${ts.crawlDelayMs}, rules=[${tsRules}]) vs Go(dis=${go.dis}, delay=${go.delayMs}, rules=[${go.rules}]) pathDiff=${pathDiff.join(',')}`,
      );
    }
  }
  assert.deepEqual(divergences, [], `Expected 0/153 robots divergences, got:\n${divergences.join('\n')}`);

  // RFC 9309 §2.2.2 percent-encoding parity spot checks (`r6C/out-politeness.txt` MatchSemantics)
  assert.equal(normalizeRobotsURI('/%70rivate'), '/private');
  assert.equal(normalizeRobotsURI('/a%2fb'), '/a%2Fb');
  assert.equal(normalizeRobotsURI('/café'), '/caf%C3%A9');
  assert.equal(isRobotsAllowed(parseOverflowRobotsTxt('User-agent: *\nDisallow: /a%2Fb\n'), '/a/b'), true);
  assert.equal(isRobotsAllowed(parseOverflowRobotsTxt('User-agent: *\nDisallow: /a/b\n'), '/a%2fb'), true);
  assert.equal(isRobotsAllowed(parseOverflowRobotsTxt('User-agent: *\nDisallow: /café\n'), '/caf%c3%a9'), false);

  // Negative `robots_unreachable` cache behavior:
  resetOverflowRobotsCacheForTests();
  let robotsHits = 0;
  let simulateSlowRobots = true;
  const mockFetch: typeof fetch = (async (input, init) => {
    const u = String(input);
    if (u.endsWith('/robots.txt')) {
      robotsHits++;
      if (simulateSlowRobots) {
        await new Promise<void>((resolve, reject) => {
          const t = setTimeout(resolve, 400);
          init?.signal?.addEventListener('abort', () => {
            clearTimeout(t);
            reject(init.signal?.reason ?? new Error('aborted'));
          });
        });
      }
      return new Response('User-agent: *\nAllow: /\n', { status: 200, headers: { 'content-type': 'text/plain' } });
    }
    return new Response('hello', { status: 200, headers: { 'content-type': 'text/plain' } });
  }) as typeof fetch;

  // Caller 1 has a tiny remaining budget (`80ms < ROBOTS_TIMEOUT_MS`), so `/robots.txt` aborts at 80ms -> `doNotCacheShared: true`!
  const shortBudgetRobots = await fetchOverflowRobots('https://transient.example.com', UA, mockFetch, Date.now() + 80);
  assert.equal(shortBudgetRobots.unreachable, true);
  assert.equal(shortBudgetRobots.doNotCacheShared, true);
  assert.equal(shortBudgetRobots.cacheTtlMs, 0);

  // Also test end-to-end via `cloudflareOverflowFetch` with `useSharedRobotsCache: true`
  resetOverflowRobotsCacheForTests();
  robotsHits = 0;
  simulateSlowRobots = true;
  await fetchOverflowRobots('https://shared-test.example.com', UA, mockFetch, Date.now() + 60);
  simulateSlowRobots = false;
  const secondCallerRes = await cloudflareOverflowFetch(
    JSON.stringify({ maxSeconds: 30, options: { includeBody: true }, requests: [{ id: '1', url: 'https://shared-test.example.com/page' }] }),
    UA,
    'hub.example.test',
    { fetchFn: mockFetch, useSharedRobotsCache: true, sleepFn: async () => undefined },
  );
  const secondBody = (await secondCallerRes.json()) as { results: Array<{ outcome: string; status: number }> };
  assert.equal(secondBody.results[0]?.outcome, 'ok');
  assert.equal(secondBody.results[0]?.status, 200);

  // Genuine 503 on `/robots.txt` caps `cacheTtlMs` to `ROBOTS_UNREACHABLE_CACHE_MAX_MS` (`10_000ms`), NOT 60,000ms!
  const err503Robots = await fetchOverflowRobots(
    'https://down.example.com',
    UA,
    (async () => new Response('down', { status: 503 })) as typeof fetch,
    Date.now() + 30_000,
  );
  assert.equal(err503Robots.unreachable, true);
  assert.equal(err503Robots.cacheTtlMs, 10_000);
});

await t.test('R6-STREAM-B-8: adapter-sandbox deep-freezes nested inputs, poisons fetch + WebSocket, rejects async returns, and caps isolate JSON output', async () => {
  const nestedInput = { url: 'https://example.com', meta: { tags: ['a', 'b'] } };
  const mutateAttempt = runAdapterSyncInBulkhead('mut', (inp) => {
    (inp.meta.tags as string[]).push('evil');
    return 'bad';
  }, nestedInput);
  assert.equal(mutateAttempt.ok, false);
  assert.deepEqual(nestedInput.meta.tags, ['a', 'b']);

  const wsAttempt = runAdapterSyncInBulkhead('ws', () => {
    const WS = (globalThis as { WebSocket?: new (u: string) => unknown }).WebSocket;
    if (WS) new WS('wss://evil.example/');
    else void globalThis.fetch('https://evil.example/');
    return 'bad';
  }, {});
  assert.equal(wsAttempt.ok, false);
  assert.match(wsAttempt.error, /bulkhead violation/);
  assert.equal(typeof globalThis.fetch, 'function');

  const asyncAttempt = runAdapterSyncInBulkhead('async', () => Promise.resolve('sneaky') as unknown as string, {});
  assert.equal(asyncAttempt.ok, false);
  assert.match(asyncAttempt.error, /forbids async\/Promise/);

  // Oversized Dynamic Worker isolate response (`> 4 MiB`) fails closed without OOM
  const hugeStream = new ReadableStream<Uint8Array>({
    pull(c) {
      c.enqueue(new Uint8Array(1024 * 1024));
    },
  });
  const isolateOut = await runUntrustedAdapterInDynamicWorker({
    loader: {
      load: () => ({
        fetch: async () => new Response(hugeStream, { status: 200, headers: { 'content-type': 'application/json' } }),
      }),
    },
    adapterModuleSource: 'export default () => ({});',
    input: {},
  });
  assert.equal(isolateOut.ok, false);
  assert.match(isolateOut.error, new RegExp(String(MAX_ADAPTER_ISOLATE_OUTPUT_BYTES)));
  void AdapterNetworkForbiddenError;
});
}
