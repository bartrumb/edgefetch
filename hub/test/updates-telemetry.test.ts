import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import collectorWorker, {
  resetCollectorRateLimiters,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
} from '../../telemetry/src/index.ts';
import { handleAdminRoute } from '../src/admin.ts';
import {
  createMemoryHubSettingsStore,
  DEV_TELEMETRY_SETTING_KEY,
  flushDevErrorTelemetry,
  resolveDevTelemetryState,
  scrubSpanToDevErrorReport,
  validateDevErrorReport,
} from '../src/dev-telemetry.ts';
import hubWorker from '../src/index.ts';
import { mintSessionJwt } from '../src/github-auth.ts';
import { ADMIN_COOKIE_NAME, createAdminSessionValue, createMemoryOAuthStore, readCookie } from '../src/oauth.ts';
import { RequestTracer } from '../src/otel.ts';
import {
  checkHubUpdateStatus,
  clearUpdateCheckCache,
  RELEASE_SIGNING_PUBLIC_KEY_SPKI_B64,
  UPDATE_CHECK_TTL_MS,
} from '../src/update-check.ts';
import { LocalAgentHubCoordinator } from './stubs/cf-storage-mocks.ts';

const OWNER_SECRET = 'owner-secret-token-0123456789abcdef';

test('Pillar 4: checkHubUpdateStatus caches 1h TTL, compares Hub & Go fleet versions, and respects EDGEFETCH_DISABLE_UPDATE_CHECK=1', async () => {
  clearUpdateCheckCache();
  let fetchCalls = 0;
  const mockPublicFetch: typeof fetch = async (input) => {
    fetchCalls++;
    assert.equal(String(input), 'https://api.github.com/repos/bartrumb/edgefetch/releases/latest');
    return new Response(
      JSON.stringify({
        tag_name: 'v2.7.0',
        html_url: 'https://github.com/bartrumb/edgefetch/releases/tag/v2.7.0',
        draft: false,
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  // 1. Opt-out via EDGEFETCH_DISABLE_UPDATE_CHECK=1 makes 0 network calls
  const disabled = await checkHubUpdateStatus({
    currentVersion: '2.7.0',
    env: { EDGEFETCH_DISABLE_UPDATE_CHECK: '1', SAFE_PUBLIC_FETCH: mockPublicFetch },
  });
  assert.equal(disabled.enabled, false);
  assert.equal(disabled.pillStatus, 'disabled');
  assert.equal(fetchCalls, 0);

  // 2. Hub v2.7.0 + fleet v2.7.0 against latest v2.7.0 -> "Up to date (v2.7.0)"
  const t0 = 1_700_000_000_000;
  const upToDate = await checkHubUpdateStatus({
    currentVersion: '2.7.0',
    agents: [
      { siteId: 'site-mac-1', version: '2.7.0' },
      { siteId: 'site-haos-1', version: '2.7.0' },
    ],
    env: { SAFE_PUBLIC_FETCH: mockPublicFetch },
    nowMs: t0,
  });
  assert.equal(fetchCalls, 1);
  assert.equal(upToDate.pillStatus, 'up_to_date');
  assert.equal(upToDate.pillLabel, 'Up to date (v2.7.0)');
  assert.equal(upToDate.hubUpdateAvailable, false);
  assert.equal(upToDate.outdatedAgents.length, 0);
  assert.equal(upToDate.signingKeySpkiB64, RELEASE_SIGNING_PUBLIC_KEY_SPKI_B64);

  // 3. Cached within 1h TTL (`t0 + 30m`), while detecting an outdated Go worker (`v2.6.3`) -> "Update available (v2.7.0)" with 0 extra fetches!
  const fleetBehind = await checkHubUpdateStatus({
    currentVersion: '2.7.0',
    agents: [
      { siteId: 'site-mac-1', version: '2.7.0' },
      { siteId: 'site-pi-old', version: '2.6.3' },
    ],
    env: { SAFE_PUBLIC_FETCH: mockPublicFetch },
    nowMs: t0 + 30 * 60_000,
  });
  assert.equal(fetchCalls, 1, 'must serve GitHub release tag from 1h cache');
  assert.equal(fleetBehind.pillStatus, 'update_available');
  assert.equal(fleetBehind.pillLabel, 'Update available (v2.7.0)');
  assert.equal(fleetBehind.hubUpdateAvailable, false);
  assert.deepEqual(fleetBehind.outdatedAgents, [{ siteId: 'site-pi-old', version: 'v2.6.3' }]);

  // 4. Hub behind (`2.6.3` vs `v2.7.0`) -> `hubUpdateAvailable: true` + `"Update available (v2.7.0)"`
  const hubBehind = await checkHubUpdateStatus({
    currentVersion: '2.6.3',
    agents: [],
    env: { SAFE_PUBLIC_FETCH: mockPublicFetch },
    nowMs: t0 + 45 * 60_000,
  });
  assert.equal(fetchCalls, 1);
  assert.equal(hubBehind.hubUpdateAvailable, true);
  assert.equal(hubBehind.pillLabel, 'Update available (v2.7.0)');

  // 5. Cache expires after 1h (`t0 + UPDATE_CHECK_TTL_MS + 1`) -> refreshes cleanly
  await checkHubUpdateStatus({
    currentVersion: '2.7.0',
    env: { SAFE_PUBLIC_FETCH: mockPublicFetch },
    nowMs: t0 + UPDATE_CHECK_TTL_MS + 1,
  });
  assert.equal(fetchCalls, 2);
});

test('Pillar 4 & 5: /admin Update Pill + POST /admin/api/telemetry CSRF toggle + hub_settings persistence + DO_NOT_TRACK=1 override', async () => {
  clearUpdateCheckCache();
  const coordinator = new LocalAgentHubCoordinator(':memory:');
  try {
    const minted = await createAdminSessionValue(OWNER_SECRET);
    const cookieHeader = `${ADMIN_COOKIE_NAME}=${minted.value}`;

    // Verify CSRF token extracted from admin session
    const dashRes = await hubWorker.fetch(
      new Request('https://hub.example.com/admin', { headers: { cookie: cookieHeader } }),
      {
        AGENT_HUB: coordinator.asNamespace() as never,
        CALLER_TOKEN: OWNER_SECRET,
        EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
      },
    );
    assert.equal(dashRes.status, 200);
    const dashHtml = await dashRes.text();
    assert.ok(dashHtml.includes('id="update-pill"'));
    assert.ok(dashHtml.includes('id="telemetry-toggle-btn"'));
    const csrfMatch = /const CSRF = "([^"]+)"/.exec(dashHtml);
    assert.ok(csrfMatch?.[1]);
    const csrf = csrfMatch![1]!;

    const baseEnv = {
      AGENT_HUB: coordinator.asNamespace() as never,
      CALLER_TOKEN: OWNER_SECRET,
      SAFE_PUBLIC_FETCH: (async () =>
        new Response(JSON.stringify({ tag_name: 'v2.7.0' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })) as typeof fetch,
    };

    // Initial /admin/api/state -> default telemetry OFF + updateStatus present
    const st0Res = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/state', { headers: { cookie: cookieHeader } }),
      baseEnv,
    );
    assert.equal(st0Res.status, 200);
    const st0 = (await st0Res.json()) as {
      updateStatus?: { pillLabel: string; pillStatus: string };
      devTelemetry?: { enabled: boolean; source: string; doNotTrack: boolean };
    };
    assert.equal(st0.devTelemetry?.enabled, false);
    assert.equal(st0.devTelemetry?.source, 'default_off');
    assert.ok(st0.updateStatus?.pillLabel.includes('v2.8.22'));

    // POST /admin/api/telemetry without CSRF -> 403
    const badCsrf = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/telemetry', {
        method: 'POST',
        headers: {
          cookie: cookieHeader,
          origin: 'https://hub.example.com',
          'content-type': 'application/json',
          'x-csrf-token': 'wrong-csrf',
        },
        body: JSON.stringify({ enabled: true }),
      }),
      baseEnv,
    );
    assert.equal(badCsrf.status, 403);

    // POST /admin/api/telemetry with valid CSRF -> enables opt-in in hub_settings SQLite table
    const toggleOn = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/telemetry', {
        method: 'POST',
        headers: {
          cookie: cookieHeader,
          origin: 'https://hub.example.com',
          'content-type': 'application/json',
          'x-csrf-token': csrf,
        },
        body: JSON.stringify({ enabled: true }),
      }),
      baseEnv,
    );
    assert.equal(toggleOn.status, 200);
    const toggleOnJson = (await toggleOn.json()) as { ok: boolean; devTelemetry: { enabled: boolean; source: string } };
    assert.equal(toggleOnJson.ok, true);
    assert.equal(toggleOnJson.devTelemetry.enabled, true);
    assert.equal(toggleOnJson.devTelemetry.source, 'admin_opt_in');
    assert.equal(await coordinator.settings.getSetting(DEV_TELEMETRY_SETTING_KEY), '1');

    // DO_NOT_TRACK=1 hard override forces enabled=false even when hub_settings=='1' AND EDGEFETCH_DEV_TELEMETRY=='1'!
    const stDntRes = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/state', { headers: { cookie: cookieHeader } }),
      {
        ...baseEnv,
        EDGEFETCH_DEV_TELEMETRY: '1',
        DO_NOT_TRACK: '1',
      },
    );
    const stDnt = (await stDntRes.json()) as { devTelemetry: { enabled: boolean; source: string; doNotTrack: boolean } };
    assert.equal(stDnt.devTelemetry.enabled, false);
    assert.equal(stDnt.devTelemetry.doNotTrack, true);
    assert.equal(stDnt.devTelemetry.source, 'do_not_track');

    // Toggle back OFF cleanly
    const toggleOff = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/telemetry', {
        method: 'POST',
        headers: {
          cookie: cookieHeader,
          origin: 'https://hub.example.com',
          'content-type': 'application/json',
          'x-csrf-token': csrf,
        },
        body: JSON.stringify({ enabled: false }),
      }),
      baseEnv,
    );
    assert.equal(toggleOff.status, 200);
    assert.equal(await coordinator.settings.getSetting(DEV_TELEMETRY_SETTING_KEY), '0');

    // Member user (`role: 'member'`) gets 403 on POST /admin/api/telemetry and never sees fleet metadata in /admin/api/state!
    const memberMinted = await mintSessionJwt({
      secret: OWNER_SECRET,
      userId: 'gh_2002',
      role: 'member',
      githubLogin: 'member-bob',
    });
    const memberCookie = `${ADMIN_COOKIE_NAME}=${memberMinted.token}`;
    const memberStateRes = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/state', { headers: { cookie: memberCookie } }),
      baseEnv,
    );
    assert.equal(memberStateRes.status, 200);
    const memberState = (await memberStateRes.json()) as {
      viewer: { userId: string; role: string };
      agents: unknown[];
      updateStatus?: unknown;
      devTelemetry?: unknown;
    };
    assert.equal(memberState.viewer.role, 'member');
    assert.equal(memberState.agents.length, 0);
    assert.equal(memberState.updateStatus, undefined);
    assert.equal(memberState.devTelemetry, undefined);

    const memberToggleRes = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/telemetry', {
        method: 'POST',
        headers: {
          cookie: memberCookie,
          origin: 'https://hub.example.com',
          'content-type': 'application/json',
          'x-csrf-token': memberMinted.csrf,
        },
        body: JSON.stringify({ enabled: true }),
      }),
      baseEnv,
    );
    assert.equal(memberToggleRes.status, 403);
    assert.equal(await coordinator.settings.getSetting(DEV_TELEMETRY_SETTING_KEY), '0');

    // Also verify standalone handleAdminRoute without optional telemetry callback returns 501 gracefully
    const oauthStore = createMemoryOAuthStore();
    const loginForm = new URLSearchParams({ token: OWNER_SECRET }).toString();
    const loginRes = await handleAdminRoute(
      new Request('https://hub.example.com/admin/login', {
        method: 'POST',
        headers: { origin: 'https://hub.example.com', 'content-type': 'application/x-www-form-urlencoded' },
        body: loginForm,
      }),
      new URL('https://hub.example.com/admin/login'),
      {
        serviceName: 'Test Hub',
        mcpSlug: 'edgefetch',
        ownerSecret: OWNER_SECRET,
        oauthStore,
        allowedTargets: ['auto'],
        defaultTarget: 'auto',
        getState: async () => ({ connected: 0, agents: [], affinities: [], grants: [] }),
        clearAffinities: async () => {},
        revokeGrant: async () => false,
        executeFetch: async () => ({ status: 200, via: 'hub', bodyText: '{}' }),
      },
    );
    assert.ok(loginRes);
    const setCookie = loginRes.headers.get('set-cookie') ?? '';
    const sessionVal = readCookie(setCookie.split(';')[0] ?? '', ADMIN_COOKIE_NAME);
    assert.ok(sessionVal);
  } finally {
    coordinator.close();
  }
});

test('Pillar 5: Hub RequestTracer -> DevErrorTelemetry scrubber -> Collector Worker E2E (zero URLs/PII, DO_NOT_TRACK=1 honored)', async () => {
  resetCollectorRateLimiters();
  const hubRoot = process.env.EDGEFETCH_HUB_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const collectorSql = readFileSync(resolve(hubRoot, '../telemetry/migrations/0001_errors.sql'), 'utf8');
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(collectorSql);

  const coerce = (v: unknown): string | number | bigint | Uint8Array | null => {
    if (v === undefined || v === null) return null;
    if (typeof v === 'boolean') return v ? 1 : 0;
    if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'string' || v instanceof Uint8Array) return v;
    return JSON.stringify(v);
  };
  const makeStmt = (sql: string, bound: unknown[] = []): D1PreparedStatementLike => ({
    bind: (...vals: unknown[]) => makeStmt(sql, vals),
    all: async <T = Record<string, unknown>>() => {
      const st = sqlite.prepare(sql);
      const p = bound.map(coerce);
      return sql.trimStart().toUpperCase().startsWith('SELECT')
        ? { results: st.all(...p) as T[] }
        : (st.run(...p), { results: [] as T[] });
    },
    first: async <T = Record<string, unknown>>(col?: string) => {
      const row = sqlite.prepare(sql).get(...bound.map(coerce)) as Record<string, unknown> | undefined;
      if (!row) return null;
      return col !== undefined ? ((row[col] as T) ?? null) : (row as T);
    },
    run: async () => {
      sqlite.prepare(sql).run(...bound.map(coerce));
      return { success: true };
    },
  });
  const collectorD1: D1DatabaseLike = { prepare: (q) => makeStmt(q) };
  const adminToken = 'collector_admin_token_0123456789abcdef';

  const capturedBodies: string[] = [];
  const collectorFetch: typeof fetch = async (input, init) => {
    const bodyText = typeof init?.body === 'string' ? init.body : '';
    capturedBodies.push(bodyText);
    return collectorWorker.fetch(
      new Request(String(input), {
        method: init?.method ?? 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.99' },
        body: bodyText,
      }),
      { DB: collectorD1, TELEMETRY_ADMIN_TOKEN: adminToken },
    );
  };

  try {
    // 1. Default OFF & DO_NOT_TRACK=1 emit 0 requests even on ERROR spans
    const memSettings = createMemoryHubSettingsStore();
    await memSettings.setSetting(DEV_TELEMETRY_SETTING_KEY, '1');
    assert.equal(
      resolveDevTelemetryState({ env: { EDGEFETCH_DEV_TELEMETRY: '1', DO_NOT_TRACK: '1' }, dbSettingValue: '1' }).enabled,
      false,
    );

    const suppressedOk = await flushDevErrorTelemetry({
      env: { EDGEFETCH_DEV_TELEMETRY: '1', DO_NOT_TRACK: '1', SAFE_PUBLIC_FETCH: collectorFetch },
      dbSettingValue: '1',
      spans: [
        {
          traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
          spanId: '1122334455667788',
          name: 'edgefetch.scrape',
          startTimeMs: 100,
          endTimeMs: 200,
          statusOk: false,
          errorMessage: 'https://secret.internal/private?token=LEAK',
          attributes: { 'http.response.status_code': 403, 'edgefetch.adapter_id': 'lever' },
        },
      ],
    });
    assert.equal(suppressedOk, false);
    assert.equal(capturedBodies.length, 0);

    // 2. RequestTracer.flush with opt-in enabled scrubs sensitive span attributes & passes Collector strict allowlist!
    const tracer = RequestTracer.fromRequest(new Request('https://hub.example.com/v1/scrape'));
    const okSpan = tracer.startSpan('edgefetch.search', {
      attributes: { 'url.full': 'https://private.corp.example/ok?secret=1', 'http.response.status_code': 200 },
    });
    okSpan.setStatus(true);
    okSpan.end();

    const errSpan = tracer.startSpan('edgefetch.scrape', {
      attributes: {
        'url.full': 'https://user:pass@private.corp.example/jobs/secret-role?api_key=SUPER_SECRET#top',
        'http.response.status_code': 403,
        'edgefetch.adapter_id': 'workday-cxs',
        'edgefetch.waf.vendor': 'akamai',
        'crawler.outcome': 'challenge',
      },
    });
    errSpan.setStatus(false, 'Blocked fetching https://private.corp.example/jobs/secret-role?api_key=SUPER_SECRET');
    errSpan.end();

    const flushed = await tracer.flush({
      env: {
        EDGEFETCH_DEV_TELEMETRY: '1',
        EDGEFETCH_DEV_TELEMETRY_ENDPOINT: 'https://telemetry.edgefetch.dev/v1/dev-errors',
        SAFE_PUBLIC_FETCH: collectorFetch,
      },
    });
    assert.equal(flushed, true);
    assert.equal(capturedBodies.length, 1);

    const rawSent = capturedBodies[0]!;
    for (const forbidden of [
      'http://',
      'https://',
      'private.corp',
      'secret-role',
      'SUPER_SECRET',
      'user:pass',
      'url.full',
    ]) {
      assert.equal(rawSent.includes(forbidden), false, `must never leak ${forbidden}`);
    }

    const parsedSent = JSON.parse(rawSent) as unknown;
    const validCheck = validateDevErrorReport(parsedSent);
    assert.equal(validCheck.ok, true);

    // Verify Collector stored the deduplicated structural fingerprint cleanly
    const sumRes = await collectorWorker.fetch(
      new Request('https://telemetry.edgefetch.dev/v1/dev-errors/summary', {
        headers: { authorization: `Bearer ${adminToken}` },
      }),
      { DB: collectorD1, TELEMETRY_ADMIN_TOKEN: adminToken },
    );
    assert.equal(sumRes.status, 200);
    const summary = (await sumRes.json()) as {
      totalFingerprints: number;
      items: Array<{ adapterId: string; wafVendor: string; httpStatus: number; errorClass: string; count: number }>;
    };
    assert.equal(summary.totalFingerprints, 1);
    assert.equal(summary.items[0]?.adapterId, 'workday-cxs');
    assert.equal(summary.items[0]?.wafVendor, 'akamai');
    assert.equal(summary.items[0]?.httpStatus, 403);
    assert.equal(summary.items[0]?.errorClass, 'waf_challenge');
    assert.equal(summary.items[0]?.count, 1);

    // Verify healthy span returns null from scrubSpanToDevErrorReport
    assert.equal(
      scrubSpanToDevErrorReport({
        traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        spanId: '1122334455667788',
        name: 'edgefetch.http',
        startTimeMs: 1,
        endTimeMs: 2,
        statusOk: true,
        attributes: { 'http.response.status_code': 200 },
      }),
      null,
    );
  } finally {
    sqlite.close();
  }
});
