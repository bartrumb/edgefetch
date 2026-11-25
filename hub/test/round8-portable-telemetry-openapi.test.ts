/**
 * Round 8 Security & Contract Suite (`hub/test/round8-portable-telemetry-openapi.test.ts`):
 *
 *  1. Live Workers Hub `x-ef-verified-auth: 1` header spoofing closed (`0` OTLP & `0` dev-telemetry exports on 200 unauth requests).
 *  2. Portable Hub pre-header socket defenses:
 *     - 33-address 1-byte reconnect flood cannot drop valid-token clients (`40/40` succeed).
 *     - 8-connection & 24-connection normal client bursts succeed (`100%`).
 *     - 4 idle sockets behind a shared NAT (`maxPreHeaderSocketsPerIp: 4`) cannot block 153 peers behind the same NAT (`153/153` succeed).
 *     - Public discovery routes (`/openapi.json`, `/.well-known/*`, `/admin/login`) never starve under slow `unauthInflight` saturation.
 *  3. `fly.toml` public origin auto-derives `https://${FLY_APP_NAME}.fly.dev` on renamed Fly apps (`0` CSRF `403`s).
 *  4. `jobs.ts` `matchesAllowedCompanyOrDomain` precision & recall (`50/50` real corporate names/slugs accepted; `35/35` multi-tenant/domain impostors rejected).
 *  5. OAuth 2.1 scope enforcement across ALL `/v1/*` and `/v2/*` routes (`mcp:call`-only token gets `403 insufficient_scope` on all 7 previously un-scoped endpoints).
 *  6. `catalog.ts` memory-only per-tenant isolation (User B's 40 runs never wipe User A's runs, records, or diff baseline).
 *  7. `robots.txt` redirect-to-NXDOMAIN treated as `unreachable: true` (blocking external SPA fallback) + shared Go/TS RFC 9309 parity corpus.
 *  8. Real OpenAPI `3.1.0` source + runtime schema contract validator with a **10-mutation self-test** (`10/10` mutations caught!).
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import meta0001 from '../migrations/meta/0001_tracking.sql';
import search0001 from '../migrations/search/0001_fts.sql';
import { LocalAgentHubCoordinator, NodeFsR2Bucket, NodeSqliteD1Database } from './stubs/cf-storage-mocks';
import { executeCatalogCall, getCatalogRecords, getCatalogStatus, resetCatalogStateForTests } from '../src/catalog';
import hubWorker from '../src/index';
import { matchesAllowedCompanyOrDomain, type StructuredJobRecord } from '../src/jobs';
import { buildCanonicalMcpToolSchemas, MCP_TOOL_SCHEMAS } from '../src/mcp';
import { createMemoryOAuthStore } from '../src/oauth';
import { buildOpenApiSpec } from '../src/openapi';
import {
  cloudflareOverflowFetch,
  fetchOverflowRobots,
  isRobotsAllowed,
  parseOverflowRobotsTxt,
  resetOverflowRobotsCacheForTests,
} from '../src/overflow';
import { executeScrapeCall } from '../src/scrape';

function sha256Base64Url(input: string): string {
  return createHash('sha256').update(input).digest('base64url');
}

test('Round 8 [Live Hub Medium]: Workers hub ignores forged x-ef-verified-auth: 1 header for OTLP & dev-telemetry', async () => {
  const origFetch = globalThis.fetch;
  let otlpExports = 0;
  let devTelemetryPosts = 0;

  globalThis.fetch = (async (input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
    const u = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (u.includes('collector.otlp.example')) {
      otlpExports++;
      return new Response('{}', { status: 200 });
    }
    if (u.includes('telemetry.edgefetch.dev')) {
      devTelemetryPosts++;
      return new Response('{"ok":true}', { status: 202 });
    }
    return new Response('not found', { status: 404 });
  }) as typeof fetch;

  try {
    const pending: Promise<unknown>[] = [];
    const ctx = {
      waitUntil(p: Promise<unknown>) {
        pending.push(p.catch(() => undefined));
      },
      passThroughOnException() {},
    } as unknown as ExecutionContext;

    const env = {
      CALLER_TOKEN: 'real-owner-caller-secret-0123456789abcdef',
      OTEL_EXPORTER_OTLP_ENDPOINT: 'https://collector.otlp.example/v1/traces',
      EDGEFETCH_DEV_TELEMETRY: '1',
      EDGEFETCH_DEV_TELEMETRY_ENDPOINT: 'https://telemetry.edgefetch.dev/v1/dev-errors',
    };

    // 200 unauthenticated requests forging `x-ef-verified-auth: 1` (including error routes) MUST produce 0 OTLP & 0 telemetry posts!
    for (let i = 0; i < 200; i++) {
      const targetPath = i % 2 === 0 ? '/v1/scrape' : '/v1/capabilities';
      const method = i % 2 === 0 ? 'POST' : 'GET';
      const req = new Request(`https://hub.edgefetch.example${targetPath}`, {
        method,
        headers: {
          'x-ef-verified-auth': '1',
          'traceparent': '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
          ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
        },
        ...(method === 'POST' ? { body: '{"url":"https://example.com"}' } : {}),
      });
      const res = await (hubWorker as { fetch(r: Request, e: unknown, c: ExecutionContext): Promise<Response> }).fetch(
        req,
        env,
        ctx,
      );
      assert.equal(res.status, 401);
    }
    await Promise.allSettled(pending);
    assert.equal(otlpExports, 0, `Expected 0 OTLP exports from forged header, got ${otlpExports}`);
    assert.equal(devTelemetryPosts, 0, `Expected 0 dev-telemetry posts from forged header, got ${devTelemetryPosts}`);

    // Sanity check: 1 genuinely authenticated request DOES export OTLP spans!
    pending.length = 0;
    const authReq = new Request('https://hub.edgefetch.example/v1/capabilities', {
      method: 'GET',
      headers: {
        authorization: 'Bearer real-owner-caller-secret-0123456789abcdef',
        traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      },
    });
    const authRes = await (hubWorker as { fetch(r: Request, e: unknown, c: ExecutionContext): Promise<Response> }).fetch(
      authReq,
      env,
      ctx,
    );
    assert.equal(authRes.status, 200);
    await Promise.allSettled(pending);
    assert.equal(otlpExports, 1, 'Expected 1 OTLP export for genuinely authenticated caller');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Round 8 [New Medium — Jobs Filter]: matchesAllowedCompanyOrDomain accepts 50/50 legitimate corporate postings & rejects 35/35 impostors', () => {
  const mkJob = (company: string, url: string, source?: string): StructuredJobRecord => ({
    title: 'Senior Software Engineer',
    company,
    url,
    applyUrl: url,
    workplaceType: 'remote',
    locations: ['Remote'],
    pay: null,
    postedAt: null,
    source: source ?? 'ats',
  });

  const legitCases: Array<{ label: string; tok: string; job: StructuredJobRecord }> = [
    // Stripe corporate & international entities
    { label: 'Stripe exact GH', tok: 'stripe', job: mkJob('Stripe', 'https://boards.greenhouse.io/stripe/jobs/1001') },
    { label: 'Stripe Inc', tok: 'stripe', job: mkJob('Stripe, Inc.', 'https://boards.greenhouse.io/stripe/jobs/1002') },
    { label: 'Stripe Payments UK', tok: 'stripe', job: mkJob('Stripe Payments UK', 'https://boards.greenhouse.io/stripe/jobs/1003') },
    { label: 'Stripe Payments UK Ltd', tok: 'stripe', job: mkJob('Stripe Payments UK, Ltd.', 'https://stripe.com/jobs/listing/eng/1004') },
    { label: 'Stripe Payments Europe Limited', tok: 'stripe', job: mkJob('Stripe Payments Europe, Limited', 'https://stripe.com/jobs/listing/eng/1005') },
    { label: 'Stripe Technology Company', tok: 'stripe', job: mkJob('Stripe Technology Company', 'https://careers.stripe.com/jobs/1006') },
    { label: 'Stripe Japan KK', tok: 'stripe', job: mkJob('Stripe Japan K.K.', 'https://jobs.stripe.co.jp/1007') },
    { label: 'Stripe Germany GmbH', tok: 'stripe', job: mkJob('Stripe Germany GmbH', 'https://boards.greenhouse.io/stripe/jobs/1008') },
    { label: 'Stripe Singapore Pte Ltd', tok: 'stripe', job: mkJob('Stripe Singapore Pte. Ltd.', 'https://boards.greenhouse.io/stripe/jobs/1009') },
    { label: 'Stripe Australia Pty Ltd', tok: 'stripe', job: mkJob('Stripe Australia Pty Ltd', 'https://boards.greenhouse.io/stripe/jobs/1010') },
    { label: 'Stripe U.K. dotted', tok: 'stripe', job: mkJob('Stripe U.K. Limited', 'https://jobs.stripe.co.uk/roles/1') },
    { label: 'Stripe Mexico diacritic', tok: 'stripe', job: mkJob('Stripe México', 'https://stripe.com/jobs/1011') },
    { label: 'Stripe GH embed param', tok: 'stripe', job: mkJob('Stripe', 'https://boards.greenhouse.io/embed/job_app?for=stripe&token=999') },
    // Notion Labs & HQ slugs
    { label: 'Notion Labs Inc Ashby', tok: 'notion', job: mkJob('Notion Labs, Inc.', 'https://jobs.ashbyhq.com/notion/abc-1') },
    { label: 'Notion Labs on notionhq', tok: 'notion', job: mkJob('Notion Labs, Inc.', 'https://jobs.ashbyhq.com/notionhq/abc-2') },
    { label: 'Notion on notion.so', tok: 'notion', job: mkJob('Notion Labs', 'https://www.notion.so/careers/eng-1') },
    { label: 'Caller passed Notion Labs, Inc.', tok: 'Notion Labs, Inc.', job: mkJob('Notion', 'https://jobs.ashbyhq.com/notion/abc-3') },
    // DoorDash & official unhyphenated regional/HQ slugs
    { label: 'DoorDash on doordashusa', tok: 'doordash', job: mkJob('DoorDash', 'https://boards.greenhouse.io/doordashusa/jobs/2001') },
    { label: 'DoorDash USA', tok: 'doordash', job: mkJob('DoorDash USA', 'https://boards.greenhouse.io/doordashusa/jobs/2002') },
    { label: 'DoorDash Technologies Canada', tok: 'doordash', job: mkJob('DoorDash Technologies Canada, Inc.', 'https://careers.doordash.com/jobs/2003') },
    { label: 'Datadog on datadoghq.com', tok: 'datadog', job: mkJob('Datadog, Inc.', 'https://careers.datadoghq.com/detail/3001') },
    { label: 'Datadog Federal', tok: 'datadog', job: mkJob('Datadog Federal', 'https://boards.greenhouse.io/datadog/jobs/3002') },
    { label: 'Datadog on datadoghq GH', tok: 'datadog', job: mkJob('Datadog', 'https://boards.greenhouse.io/datadoghq/jobs/3003') },
    // PBC, dotted L.L.C., 2-char brands, dba, multi-word brands
    { label: 'Anthropic PBC', tok: 'anthropic', job: mkJob('Anthropic, PBC', 'https://boards.greenhouse.io/anthropic/jobs/4001') },
    { label: 'Anthropic P.B.C.', tok: 'anthropic', job: mkJob('Anthropic P.B.C.', 'https://jobs.ashbyhq.com/anthropic/4002') },
    { label: 'OpenAI L.L.C.', tok: 'openai', job: mkJob('OpenAI, L.L.C.', 'https://jobs.ashbyhq.com/openai/5001') },
    { label: 'Open AI spaced display', tok: 'openai', job: mkJob('Open AI, Inc.', 'https://openai.com/careers/5002') },
    { label: 'F5 2-char Workday', tok: 'f5', job: mkJob('F5, Inc.', 'https://f5.wd5.myworkdayjobs.com/F5/job/Seattle/Eng_R1') },
    { label: 'HP 2-char Workday', tok: 'hp', job: mkJob('HP Inc.', 'https://hp.wd5.myworkdayjobs.com/ExternalCareerSite/job/1') },
    { label: '3M 2-char Workday', tok: '3m', job: mkJob('3M Company', 'https://3m.wd1.myworkdayjobs.com/Search/job/1') },
    { label: 'Instacart dba', tok: 'instacart', job: mkJob('Maplebear Inc. dba Instacart', 'https://boards.greenhouse.io/instacart/jobs/6001') },
    { label: 'Palo Alto Networks hyphen slug', tok: 'paloaltonetworks', job: mkJob('Palo Alto Networks', 'https://jobs.lever.co/palo-alto-networks/7001') },
    { label: 'Palo Alto Networks SmartRecruiters', tok: 'paloaltonetworks', job: mkJob('Palo Alto Networks, Inc.', 'https://jobs.smartrecruiters.com/PaloAltoNetworks/7002') },
    { label: 'Scale AI hyphen slug', tok: 'scaleai', job: mkJob('Scale AI, Inc.', 'https://jobs.lever.co/scale-ai/7003') },
    { label: 'Hugging Face hyphen slug', tok: 'huggingface', job: mkJob('Hugging Face', 'https://apply.workable.com/hugging-face/j/1') },
    // Rippling localized URL, EU boards, enterprise corporate names
    { label: 'Rippling localized en-US URL', tok: 'rippling', job: mkJob('Rippling People Center Inc.', 'https://ats.rippling.com/en-US/rippling/jobs/8001') },
    { label: 'Rippling direct URL', tok: 'rippling', job: mkJob('Rippling', 'https://ats.rippling.com/rippling/jobs/8002') },
    { label: 'Cloudflare UK Limited', tok: 'cloudflare', job: mkJob('Cloudflare UK Limited', 'https://boards.greenhouse.io/cloudflare/jobs/9001') },
    { label: 'Cloudflare Germany GmbH', tok: 'cloudflare', job: mkJob('Cloudflare Germany GmbH', 'https://boards.eu.greenhouse.io/cloudflare/jobs/9002') },
    { label: 'Lever EU board', tok: 'klarna', job: mkJob('Klarna Bank AB', 'https://jobs.eu.lever.co/klarna/9003') },
    { label: 'Palantir Technologies', tok: 'palantir', job: mkJob('Palantir Technologies Inc.', 'https://jobs.lever.co/palantir/9004') },
    { label: 'Anduril Industries', tok: 'anduril', job: mkJob('Anduril Industries, Inc.', 'https://boards.greenhouse.io/anduril/jobs/9005') },
    { label: 'Coinbase Global', tok: 'coinbase', job: mkJob('Coinbase Global, Inc.', 'https://boards.greenhouse.io/coinbase/jobs/9006') },
    { label: 'Robinhood Markets', tok: 'robinhood', job: mkJob('Robinhood Markets, Inc.', 'https://boards.greenhouse.io/robinhood/jobs/9007') },
    { label: 'Block Inc', tok: 'block', job: mkJob('Block, Inc.', 'https://boards.greenhouse.io/block/jobs/9008') },
    { label: 'Snowflake Computing', tok: 'snowflake', job: mkJob('Snowflake Inc.', 'https://jobs.ashbyhq.com/snowflake/9009') },
    { label: 'Amazon .jobs TLD', tok: 'amazon', job: mkJob('Amazon Web Services, Inc.', 'https://www.amazon.jobs/en/jobs/25001') },
    { label: 'Fly.io first-party', tok: 'fly', job: mkJob('Fly.io', 'https://fly.io/jobs/infra-eng') },
    { label: 'Linear.app first-party', tok: 'linear', job: mkJob('Linear, Inc.', 'https://linear.app/careers/eng') },
    { label: 'Curated WWR feed with verified source', tok: 'tailscale', job: mkJob('Tailscale Inc.', 'https://weworkremotely.com/remote-jobs/tailscale-eng', 'weworkremotely') },
  ];

  assert.equal(legitCases.length, 50);
  for (const lc of legitCases) {
    assert.equal(
      matchesAllowedCompanyOrDomain(lc.job, new Set([lc.tok]), []),
      true,
      `Expected legitimate posting "${lc.label}" (${lc.job.company} @ ${lc.job.url}) to match "${lc.tok}"`,
    );
  }

  const impostorCases: Array<{ label: string; tok: string; job: StructuredJobRecord }> = [
    // Multi-tenant ATS hyphenated/underscored legal & generic suffix impostors (the 26 that previously leaked!)
    { label: 'lever stripe-inc', tok: 'stripe', job: mkJob('Stripe, Inc.', 'https://jobs.lever.co/stripe-inc/1') },
    { label: 'gh stripe-llc', tok: 'stripe', job: mkJob('Stripe LLC', 'https://boards.greenhouse.io/stripe-llc/jobs/1') },
    { label: 'ashby stripe-corp', tok: 'stripe', job: mkJob('Stripe Corp', 'https://jobs.ashbyhq.com/stripe-corp/1') },
    { label: 'workable stripe-gmbh', tok: 'stripe', job: mkJob('Stripe GmbH', 'https://apply.workable.com/stripe-gmbh/j/1') },
    { label: 'gem stripe-plc', tok: 'stripe', job: mkJob('Stripe PLC', 'https://jobs.gem.com/stripe-plc/1') },
    { label: 'rippling stripe-incorporated', tok: 'stripe', job: mkJob('Stripe Incorporated', 'https://ats.rippling.com/stripe-incorporated/jobs/1') },
    { label: 'smartrecruiters stripe-corporation', tok: 'stripe', job: mkJob('Stripe Corporation', 'https://jobs.smartrecruiters.com/stripe-corporation/1') },
    { label: 'lever stripe_inc underscore', tok: 'stripe', job: mkJob('Stripe', 'https://jobs.lever.co/stripe_inc/1') },
    { label: 'lever stripe-ltd', tok: 'stripe', job: mkJob('Stripe Ltd', 'https://jobs.lever.co/stripe-ltd/1') },
    { label: 'lever stripe-co', tok: 'stripe', job: mkJob('Stripe Co', 'https://jobs.lever.co/stripe-co/1') },
    { label: 'lever stripe-jobs', tok: 'stripe', job: mkJob('Stripe', 'https://jobs.lever.co/stripe-jobs/1') },
    { label: 'gh stripe-careers', tok: 'stripe', job: mkJob('Stripe', 'https://boards.greenhouse.io/stripe-careers/jobs/1') },
    { label: 'ashby stripe-hq', tok: 'stripe', job: mkJob('Stripe', 'https://jobs.ashbyhq.com/stripe-hq/1') },
    { label: 'lever stripe-usa hyphen', tok: 'stripe', job: mkJob('Stripe USA', 'https://jobs.lever.co/stripe-usa/1') },
    { label: 'lever stripe-uk hyphen', tok: 'stripe', job: mkJob('Stripe UK', 'https://jobs.lever.co/stripe-uk/1') },
    { label: 'lever stripe-ai', tok: 'stripe', job: mkJob('Stripe AI', 'https://jobs.lever.co/stripe-ai/1') },
    { label: 'lever stripe-labs', tok: 'stripe', job: mkJob('Stripe Labs', 'https://jobs.lever.co/stripe-labs/1') },
    { label: 'lever official-stripe', tok: 'stripe', job: mkJob('Stripe', 'https://jobs.lever.co/official-stripe/1') },
    { label: 'lever s-t-r-i-p-e', tok: 'stripe', job: mkJob('Stripe', 'https://jobs.lever.co/s-t-r-i-p-e/1') },
    // Unhyphenated lookalike/impostor ATS slugs
    { label: 'lever stripeinc', tok: 'stripe', job: mkJob('Stripe Inc', 'https://jobs.lever.co/stripeinc/1') },
    { label: 'lever stripejobs', tok: 'stripe', job: mkJob('Stripe', 'https://jobs.lever.co/stripejobs/1') },
    { label: 'lever stripecareers', tok: 'stripe', job: mkJob('Stripe', 'https://jobs.lever.co/stripecareers/1') },
    { label: 'lever stripeai startup', tok: 'stripe', job: mkJob('Stripe AI', 'https://jobs.lever.co/stripeai/1') },
    { label: 'lever stripelabs startup', tok: 'stripe', job: mkJob('Stripe Labs', 'https://jobs.lever.co/stripelabs/1') },
    // Phishing / third-party / aggregator domains claiming `company: "Stripe"`!
    { label: 'evil.com claiming Stripe', tok: 'stripe', job: mkJob('Stripe', 'https://evil-phishing.com/jobs/1') },
    { label: 'stripe.evil.com subdomain spoof', tok: 'stripe', job: mkJob('Stripe, Inc.', 'https://stripe.evil.com/jobs/1') },
    { label: 'stripecareers.com typosquat', tok: 'stripe', job: mkJob('Stripe', 'https://stripecareers.com/jobs/1') },
    { label: 'stripejobs.com typosquat', tok: 'stripe', job: mkJob('Stripe', 'https://stripejobs.com/jobs/1') },
    { label: 'stripe-careers.com typosquat', tok: 'stripe', job: mkJob('Stripe', 'https://stripe-careers.com/jobs/1') },
    { label: 'jobvite impostor org', tok: 'stripe', job: mkJob('Stripe', 'https://jobs.jobvite.com/othercorp/job/1') },
    { label: 'linkedin unverified aggregator', tok: 'stripe', job: mkJob('Stripe', 'https://www.linkedin.com/jobs/view/12345') },
    // Display-name spoofing / negations / homoglyphs even on matching domain
    { label: 'Not Stripe negation', tok: 'stripe', job: mkJob('Not Stripe', 'https://stripe.com/jobs/1') },
    { label: 'Ex-Stripe agency', tok: 'stripe', job: mkJob('Ex-Stripe Recruiting', 'https://stripe.com/jobs/1') },
    { label: 'Cyrillic homoglyph Fаke', tok: 'stripe', job: mkJob('Stripe F\u0430ke', 'https://boards.greenhouse.io/stripe/jobs/1') },
    { label: 'Dotted S.T.R.I.P.E spoof', tok: 'stripe', job: mkJob('S.T.R.I.P.E.', 'https://boards.greenhouse.io/stripe/jobs/1') },
  ];

  assert.equal(impostorCases.length, 35);
  for (const ic of impostorCases) {
    assert.equal(
      matchesAllowedCompanyOrDomain(ic.job, new Set([ic.tok]), []),
      false,
      `SECURITY: impostor posting "${ic.label}" (${ic.job.company} @ ${ic.job.url}) must be REJECTED for "${ic.tok}"`,
    );
  }
});

test('Round 8 [New Medium — 7 Un-Scoped Endpoints]: mcp:call-only OAuth token gets 403 insufficient_scope on ALL non-MCP /v1/* & /v2/* endpoints', async () => {
  const { createHash } = await import('node:crypto');
  const tmpData = mkdtempSync(join(tmpdir(), 'ef-r8-scopes-'));
  const ownerToken = 'owner-secret-token-0123456789abcdef';
  const coordinator = new LocalAgentHubCoordinator(join(tmpData, 'hub.sqlite'));
  const metaDb = new NodeSqliteD1Database(':memory:', [{ name: 'meta/0001_tracking.sql', sql: meta0001 }]);
  const searchDb = new NodeSqliteD1Database(':memory:', [{ name: 'search/0001_fts.sql', sql: search0001 }]);
  const artifacts = new NodeFsR2Bucket(join(tmpData, 'r2'));
  const workerEnv = {
    AGENT_HUB: coordinator.asNamespace() as never,
    META: metaDb as never,
    SEARCH: searchDb as never,
    ARTIFACTS: artifacts as never,
    CALLER_TOKEN: ownerToken,
    SAFE_PUBLIC_FETCH: async () => new Response('User-agent: *\nAllow: /\n', { status: 200 }),
    SAFE_FETCH: async () => new Response('User-agent: *\nAllow: /\n', { status: 200 }),
  };
  const baseUrl = 'https://hub.edgefetch.example';
  const dispatch = (path: string, init?: RequestInit) =>
    hubWorker.fetch(new Request(`${baseUrl}${path}`, init), workerEnv);

  try {
    const regRes = await dispatch('/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Round 8 Scope Tester',
        redirect_uris: ['http://127.0.0.1:9999/cb'],
      }),
    });
    assert.equal(regRes.status, 201);
    const { client_id: clientId } = (await regRes.json()) as { client_id: string };

    const mintScopedToken = async (scope: string): Promise<string> => {
      const verifier = `pkce_verifier_${scope.replace(/[^a-z]/g, '')}_0123456789abcdef0123456789abcdef`;
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      const authGet = await dispatch(
        `/oauth/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:9999/cb')}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256&scope=${encodeURIComponent(scope)}&state=st1`,
      );
      assert.equal(authGet.status, 200);
      const html = await authGet.text();
      const csrfCookie = authGet.headers.get('set-cookie')?.split(';')[0] ?? '';
      const csrfVal = /name="csrf"\s+value="([^"]+)"/.exec(html)?.[1] ?? '';
      const sealedVal = /name="sealed"\s+value="([^"]+)"/.exec(html)?.[1] ?? '';
      const authPost = await dispatch('/oauth/authorize', {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: csrfCookie,
          origin: baseUrl,
        },
        body: new URLSearchParams({
          decision: 'approve',
          owner_token: ownerToken,
          csrf: csrfVal,
          sealed: sealedVal,
        }).toString(),
      });
      assert.ok(authPost.status === 302 || authPost.status === 303, `Expected OAuth redirect, got ${authPost.status}`);
      const loc = new URL(authPost.headers.get('location')!);
      const code = loc.searchParams.get('code')!;
      assert.ok(code);

      const tokRes = await dispatch('/oauth/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://127.0.0.1:9999/cb',
          client_id: clientId,
          code_verifier: verifier,
        }).toString(),
      });
      assert.equal(tokRes.status, 200);
      const tokJson = (await tokRes.json()) as { access_token: string };
      return tokJson.access_token;
    };

    const mcpOnlyPlain = await mintScopedToken('mcp:call');
    const readOnlyPlain = await mintScopedToken('crawl:read');

    const nonMcpEndpoints: Array<{ method: string; path: string; body?: string; readAllowed?: boolean }> = [
      // The 7 previously un-scoped endpoints flagged by Reviewer #3:
      { method: 'GET', path: '/v1/capabilities', readAllowed: true },
      { method: 'GET', path: '/v1/extractors', readAllowed: true },
      { method: 'GET', path: `/v1/artifacts/${'a'.repeat(64)}`, readAllowed: true },
      { method: 'POST', path: '/v1/crawl/params-preview', body: '{"url":"https://example.com","prompt":"docs"}', readAllowed: true },
      { method: 'GET', path: '/v1/batch/scrape/bat_nonexistent', readAllowed: true },
      { method: 'GET', path: '/v1/agent/agt_nonexistent', readAllowed: true },
      { method: 'GET', path: '/v1/agent/agt_nonexistent/trace', readAllowed: true },
      // All remaining /v1/* & /v2/* endpoints:
      { method: 'GET', path: '/v1/hosts', readAllowed: true },
      { method: 'GET', path: '/v1/mcp/registry?q=github', readAllowed: true },
      { method: 'GET', path: '/v1/crawl/crw_nonexistent', readAllowed: true },
      { method: 'GET', path: '/v1/collections/default/search?q=test', readAllowed: true },
      { method: 'GET', path: '/v1/catalog/cat_nonexistent', readAllowed: true },
      { method: 'GET', path: '/v1/catalog/cat_nonexistent/records', readAllowed: true },
      { method: 'POST', path: '/v1/scrape', body: '{"url":"https://example.com"}' },
      { method: 'POST', path: '/v1/batch/scrape', body: '{"urls":["https://example.com"]}' },
      { method: 'DELETE', path: '/v1/batch/scrape/bat_nonexistent' },
      { method: 'POST', path: '/v1/extract', body: '{"urls":["https://example.com"],"query":"test"}' },
      { method: 'POST', path: '/v1/interact', body: '{"url":"https://example.com"}' },
      { method: 'POST', path: '/v1/map', body: '{"url":"https://example.com"}' },
      { method: 'POST', path: '/v1/crawl', body: '{"url":"https://example.com"}' },
      { method: 'DELETE', path: '/v1/crawl/crw_nonexistent' },
      { method: 'POST', path: '/v1/ingest-tab', body: '{"url":"https://example.com","markdown":"# hi"}' },
      { method: 'POST', path: '/v1/jobs', body: '{"query":"engineer"}' },
      { method: 'POST', path: '/v1/catalog', body: '{"url":"https://example.com"}' },
      { method: 'POST', path: '/v1/agent', body: '{"prompt":"research"}' },
      { method: 'DELETE', path: '/v1/agent/agt_nonexistent' },
      { method: 'POST', path: '/v2/scrape', body: '{"url":"https://example.com"}' },
      { method: 'GET', path: '/v2/batch/scrape/bat_nonexistent' },
    ];

    for (const ep of nonMcpEndpoints) {
      const res = await dispatch(ep.path, {
        method: ep.method,
        headers: {
          authorization: `Bearer ${mcpOnlyPlain}`,
          ...(ep.body ? { 'content-type': 'application/json' } : {}),
        },
        ...(ep.body ? { body: ep.body } : {}),
      });
      assert.equal(
        res.status,
        403,
        `SECURITY: mcp:call-only token on ${ep.method} ${ep.path} returned ${res.status}, expected 403 insufficient_scope!`,
      );

      if (ep.readAllowed) {
        const readRes = await dispatch(ep.path, {
          method: ep.method,
          headers: {
            authorization: `Bearer ${readOnlyPlain}`,
            ...(ep.body ? { 'content-type': 'application/json' } : {}),
          },
          ...(ep.body ? { body: ep.body } : {}),
        });
        assert.notEqual(
          readRes.status,
          403,
          `crawl:read token should be permitted past scope gate on ${ep.method} ${ep.path}, got 403`,
        );
      } else {
        const readDeniedRes = await dispatch(ep.path, {
          method: ep.method,
          headers: {
            authorization: `Bearer ${readOnlyPlain}`,
            ...(ep.body ? { 'content-type': 'application/json' } : {}),
          },
          ...(ep.body ? { body: ep.body } : {}),
        });
        assert.equal(
          readDeniedRes.status,
          403,
          `crawl:read-only token on mutation route ${ep.method} ${ep.path} must return 403`,
        );
      }
    }

    // Meanwhile `POST /v1/mcp/query` (`list_connected`) DOES allow `mcp:call`-only tokens!
    const mcpQueryRes = await dispatch('/v1/mcp/query', {
      method: 'POST',
      headers: { authorization: `Bearer ${mcpOnlyPlain}`, 'content-type': 'application/json' },
      body: '{"action":"list_connected"}',
    });
    assert.equal(mcpQueryRes.status, 200);
  } finally {
    coordinator.close();
    metaDb.close();
    searchDb.close();
    rmSync(tmpData, { recursive: true, force: true });
  }
});

test('Round 8 [Catalog Memory-Only Tenant Isolation]: User B running 40 memory-only catalog jobs cannot evict User A runs, records, or diff baseline', async () => {
  resetCatalogStateForTests();
  try {
    let priceCents = 1999;
    const mockCatalogFetch = async ({ url }: { url: string }) => {
      const pageMatch = /[?&]page=(\d+)/.exec(url);
      const page = pageMatch ? Number(pageMatch[1]) : 1;
      if (page > 1) {
        return { results: [{ status: 200, outcome: 'ok', headers: {}, body: '{"products":[]}' }] };
      }
      return {
        results: [
          {
            status: 200,
            outcome: 'ok',
            headers: {},
            body: JSON.stringify({
              products: [
                {
                  id: 101,
                  title: 'Widget Pro',
                  handle: 'widget-pro',
                  vendor: 'Acme',
                  product_type: 'Hardware',
                  tags: ['pro'],
                  variants: [
                    {
                      id: 501,
                      title: 'Default',
                      sku: 'W-PRO-1',
                      price: (priceCents / 100).toFixed(2),
                      available: true,
                    },
                  ],
                },
              ],
            }),
          },
        ],
      };
    };

    // 1. User A runs 2 catalog jobs in pure memory-only mode (`env = {}`)
    const userARun1 = await executeCatalogCall({
      payload: { url: 'https://shop-a.example.com', platform: 'shopify', sync: true, pauseMs: 0 },
      env: {},
      executeHubFetch: mockCatalogFetch,
      sleepFn: async () => {},
      principal: 'oauth:user-a',
      userId: 'user_alice',
    });
    assert.equal(userARun1.status, 200);
    const aliceCatalogId = String(userARun1.body.catalogId);
    assert.ok(aliceCatalogId.startsWith('cat_'));

    // 2. User B floods 40 catalog jobs in pure memory-only mode (`env = {}`)!
    for (let i = 0; i < 40; i++) {
      const bRes = await executeCatalogCall({
        payload: { url: `https://shop-b-${i}.example.com`, platform: 'shopify', sync: true, pauseMs: 0 },
        env: {},
        executeHubFetch: mockCatalogFetch,
        sleepFn: async () => {},
        principal: 'oauth:user-b',
        userId: 'user_bob',
      });
      assert.equal(bRes.status, 200);
    }

    // 3. User A's status AND full records AND diff baseline MUST all still be intact!
    const aliceStatus = await getCatalogStatus({ catalogId: aliceCatalogId, userId: 'user_alice', env: {} });
    assert.equal(aliceStatus.status, 200, 'User A catalog status must NOT be wiped by User B');

    const aliceRecords = await getCatalogRecords({ catalogId: aliceCatalogId, userId: 'user_alice', env: {} });
    assert.equal(aliceRecords.status, 200, 'User A in-memory catalog records must NOT be evicted by User B');
    assert.equal((aliceRecords.body.records as unknown[])?.length, 1);

    // Cross-tenant read by User B still gets 404
    const bobSnooping = await getCatalogRecords({ catalogId: aliceCatalogId, userId: 'user_bob', env: {} });
    assert.equal(bobSnooping.status, 404);

    // User A's next snapshot on `shop-a.example.com` still computes an exact `changed: 1` diff against User A's baseline!
    priceCents = 2499;
    const userARun2 = await executeCatalogCall({
      payload: { url: 'https://shop-a.example.com', platform: 'shopify', sync: true, pauseMs: 0 },
      env: {},
      executeHubFetch: mockCatalogFetch,
      sleepFn: async () => {},
      principal: 'oauth:user-a',
      userId: 'user_alice',
    });
    assert.equal(userARun2.status, 200);
    const run2Diff = userARun2.body.diff as { added: number; removed: number; changed: number };
    assert.equal(run2Diff.added, 0);
    assert.equal(run2Diff.removed, 0);
    assert.equal(run2Diff.changed, 1);
  } finally {
    resetCatalogStateForTests();
  }
});

test('Round 8 [Robots Parity + Redirect-to-NXDOMAIN Low]: /robots.txt redirect to DNS-failing host blocks SPA fallback & shared Go/TS corpus matches 100%', async () => {
  resetOverflowRobotsCacheForTests();
  const hubDir = process.env.EDGEFETCH_HUB_ROOT ?? process.cwd();
  const corpus = JSON.parse(
    readFileSync(resolve(hubDir, 'test', 'fixtures', 'robots-parity-corpus.json'), 'utf8'),
  ) as Array<{
    id: string;
    robots: string;
    ua: string;
    crawlDelayMs: number;
    disallowAiInput: boolean;
    checks: Array<{ path: string; allowed: boolean }>;
  }>;

  // 1. Shared Go/TS corpus check (`internal/politeness/parity_corpus_test.go` runs this exact JSON file in Go!)
  let totalChecks = 0;
  for (const tc of corpus) {
    const parsed = parseOverflowRobotsTxt(tc.robots, tc.ua);
    assert.equal(parsed.crawlDelayMs, tc.crawlDelayMs, `[${tc.id}] crawlDelayMs`);
    assert.equal(Boolean(parsed.disallowAiInput), tc.disallowAiInput, `[${tc.id}] disallowAiInput`);
    for (const chk of tc.checks) {
      totalChecks++;
      assert.equal(isRobotsAllowed(parsed, chk.path), chk.allowed, `[${tc.id}] isRobotsAllowed(${JSON.stringify(chk.path)})`);
    }
  }
  assert.ok(totalChecks >= 60);

  // Also check 1 MiB (`1_048_576` bytes) partial-line truncation parity in `parseOverflowRobotsTxt`!
  const hdr = 'User-agent: *\nDisallow: /\n';
  const padLen = 1_048_576 - hdr.length - 'Allow: /'.length;
  const truncBody = `${hdr}${'#'.repeat(padLen - 1)}\nAllow: /public-docs`;
  const truncParsed = parseOverflowRobotsTxt(truncBody, 'edgefetch');
  assert.equal(
    isRobotsAllowed(truncParsed, '/secret'),
    false,
    'Partial Allow line split across 1 MiB boundary must be dropped identically to Go ParseRobotsTxt',
  );

  // 2. `/robots.txt` redirecting (`302`) to a host with no DNS (`ENOTFOUND`) MUST be `unreachable: true` (disallowed!)
  let crawl4AiCalled = 0;
  const mockPublicFetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const u = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (u === 'https://spa-origin.example/robots.txt') {
      return new Response(null, {
        status: 302,
        headers: { location: 'https://missing-cdn.example/robots.txt' },
      });
    }
    if (u === 'https://missing-cdn.example/robots.txt') {
      throw new Error('getaddrinfo ENOTFOUND missing-cdn.example');
    }
    if (u.includes('crawl4ai.example')) {
      crawl4AiCalled++;
      return Response.json({ success: true, results: [{ markdown: '# External Rendered', status_code: 200 }] });
    }
    return new Response('<html><head><script src="/app.js"></script></head><body><div id="root"></div></body></html>', {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }) as typeof fetch;

  const robRedirectNx = await fetchOverflowRobots(
    'https://spa-origin.example',
    'EdgeFetch/2.7.3',
    mockPublicFetch,
    Date.now() + 5_000,
  );
  assert.equal(robRedirectNx.unreachable, true, 'Redirect of /robots.txt to NXDOMAIN host must set unreachable: true');
  assert.equal(Boolean(robRedirectNx.dnsNotFound), false, 'Origin itself exists; redirect target NXDOMAIN must not set dnsNotFound');
  assert.equal(isRobotsAllowed(robRedirectNx, '/app'), false, 'isRobotsAllowed must return false when /robots.txt redirect target has no DNS');

  const ovRes = await cloudflareOverflowFetch(
    JSON.stringify({
      requests: [{ id: 'r1', url: 'https://spa-origin.example/app', kind: 'page' }],
      options: { includeBody: true, respectRobots: true },
    }),
    'EdgeFetch/2.7.3',
    'hub.local',
    { fetchFn: mockPublicFetch, useSharedRobotsCache: false },
  );
  const ovBody = (await ovRes.json()) as { results: Array<{ outcome: string }> };
  assert.equal(ovBody.results[0]?.outcome, 'stop', 'Overflow fetch must halt with outcome="stop" when /robots.txt redirects to NXDOMAIN');

  // External SPA fallback (`Crawl4AI`) MUST ALSO refuse to render when `/robots.txt` redirects to NXDOMAIN!
  const scrapeOut = await executeScrapeCall({
    payload: { url: 'https://spa-origin.example/app', renderMode: 'always', spaFallback: 'crawl4ai' },
    env: {
      CRAWL4AI_API_URL: 'https://crawl4ai.example',
      SAFE_PUBLIC_FETCH: mockPublicFetch,
      SAFE_FETCH: mockPublicFetch,
    } as Record<string, unknown>,
    executeHubFetch: async () => ({
      status: 503,
      via: 'hub',
      bodyText: JSON.stringify({ error: 'fat_agent_required', message: 'No browser-capable worker connected' }),
    }),
  });
  assert.equal(crawl4AiCalled, 0, 'External SPA fallback must NEVER be called when /robots.txt redirects to NXDOMAIN!');
  assert.equal(scrapeOut.status, 503);
});

// ── Real Mutation-Verified OpenAPI 3.1.0 Contract Validator ──────────────────────────────────────────────────────────

interface ExtractedSourceRoute {
  path: string;
  methods: Set<string>;
  securityKind: 'public' | 'owner_bearer' | 'oauth_read' | 'oauth_fetch' | 'oauth_mcp_query' | 'oauth_mcp_rpc';
  pathParams: string[];
  queryParams: Set<string>;
}

function extractCanonicalRoutesFromSource(sources: {
  indexSrc: string;
  compatSrc: string;
  botAuthSrc: string;
  oauthSrc: string;
  githubAuthSrc: string;
  adminSrc?: string;
}): Map<string, ExtractedSourceRoute> {
  const routes = new Map<string, ExtractedSourceRoute>();
  const upsert = (
    path: string,
    method: string,
    securityKind: ExtractedSourceRoute['securityKind'],
    queryParams: string[] = [],
  ) => {
    const pathParams = [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]!);
    const existing = routes.get(path);
    if (existing) {
      existing.methods.add(method.toLowerCase());
      // When a path has both GET (`oauth_read`) and DELETE (`oauth_fetch`), track per-method below
      for (const qp of queryParams) existing.queryParams.add(qp);
      return;
    }
    routes.set(path, {
      path,
      methods: new Set([method.toLowerCase()]),
      securityKind,
      pathParams,
      queryParams: new Set(queryParams),
    });
  };

  // 1. Public Discovery & OAuth 2.1 / GitHub Auth routes verified in source files
  if (/request\.method\s*===\s*'GET'\s*&&\s*url\.pathname\s*===\s*'\/health'/.test(sources.indexSrc)) {
    upsert('/health', 'get', 'public');
  }
  if (/handleOpenApiRoute/.test(sources.indexSrc)) {
    upsert('/openapi.json', 'get', 'public');
  }
  if (sources.botAuthSrc.includes("'/.well-known/edgefetch-bot.json'")) {
    upsert('/.well-known/edgefetch-bot.json', 'get', 'public');
  }
  if (sources.botAuthSrc.includes("'/.well-known/http-message-signatures-directory'")) {
    upsert('/.well-known/http-message-signatures-directory', 'get', 'public');
  }
  if (sources.oauthSrc.includes("'/.well-known/oauth-protected-resource'")) {
    upsert('/.well-known/oauth-protected-resource', 'get', 'public');
  }
  if (sources.oauthSrc.includes("'/.well-known/oauth-authorization-server'")) {
    upsert('/.well-known/oauth-authorization-server', 'get', 'public');
  }
  const ghRouteSrc = sources.adminSrc ?? sources.githubAuthSrc;
  if (ghRouteSrc.includes("'/admin/auth/github'") || sources.githubAuthSrc.includes('/admin/auth/github/callback')) {
    if (!sources.adminSrc || sources.adminSrc.includes("'/admin/auth/github'")) {
      upsert('/admin/auth/github', 'get', 'public', ['return_to']);
    }
    if (!sources.adminSrc || sources.adminSrc.includes("'/admin/auth/github/callback'")) {
      upsert('/admin/auth/github/callback', 'get', 'public', ['code', 'state']);
    }
  }
  if (/url\.pathname\s*===\s*'\/mcp'/.test(sources.indexSrc)) {
    upsert('/mcp', 'post', 'oauth_mcp_rpc');
  }
  if (/request\.method\s*===\s*'GET'\s*&&\s*url\.pathname\s*===\s*'\/agents'/.test(sources.indexSrc)) {
    upsert('/agents', 'get', 'owner_bearer');
  }
  if (/request\.method\s*===\s*'POST'\s*&&\s*\(?url\.pathname\s*===\s*'\/fetch'/.test(sources.indexSrc)) {
    upsert('/fetch', 'post', 'owner_bearer', ['target', 'site', 'artifacts', 'hydrate']);
  }

  // 2. Parse every `/v1/*` route handler block directly from `hub/src/index.ts` and inspect its real method + scope checks!
  const normalizeV1Path = (raw: string) =>
    raw
      .replace('/batch/scrape/([^/]+)', '/batch/scrape/{batchId}')
      .replace('/agent/([^/]+)/trace', '/agent/{agentId}/trace')
      .replace('/agent/([^/]+)', '/agent/{agentId}')
      .replace('/crawl/([^/]+)', '/crawl/{crawlId}')
      .replace('/collections/([^/]+)/search', '/collections/{collectionId}/search')
      .replace('/catalog/([^/]+)/records', '/catalog/{catalogId}/records')
      .replace('/catalog/([^/]+)', '/catalog/{catalogId}');

  const lines = sources.indexSrc.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    let detectedPath: string | null = null;
    const exactM = /url\.pathname\s*===\s*'(\/v1\/[^']+)'/.exec(line);
    const startsM = /url\.pathname\.startsWith\('(\/v1\/[^']+)'\)/.exec(line);
    const regexM = /const\s+(\w+)\s*=\s*\/\^\\\/v1\\\/([^$]+)\$\/\.exec\(url\.pathname\)/.exec(line);
    if (exactM) {
      detectedPath = exactM[1]!;
    } else if (startsM) {
      detectedPath = startsM[1] === '/v1/artifacts/' ? '/v1/artifacts/{blobSha256}' : `${startsM[1]}{id}`;
    } else if (regexM) {
      detectedPath = normalizeV1Path(`/v1/${regexM[2]!.replace(/\\\//g, '/')}`);
    }
    if (!detectedPath) continue;

    // Slice the route handler block up to the next top-level route check
    let depth = 0;
    let entered = false;
    const blockLines: string[] = [];
    for (let j = i; j < Math.min(lines.length, i + 160); j++) {
      const l = lines[j]!;
      blockLines.push(l);
      for (const ch of l) {
        if (ch === '{') {
          depth++;
          entered = true;
        } else if (ch === '}') {
          depth--;
        }
      }
      if (entered && depth <= 0 && j > i) break;
    }
    const block = blockLines.join('\n');
    const qParams = [...block.matchAll(/url\.searchParams\.(?:get|getAll)\('([^']+)'\)/g)].map((m) => m[1]!);

    // Determine HTTP methods handled in this block
    const methodsInBlock: string[] = [];
    for (const m of ['GET', 'POST', 'DELETE']) {
      if (new RegExp(`request\\.method\\s*===\\s*'${m}'`).test(block)) {
        methodsInBlock.push(m.toLowerCase());
      }
    }

    for (const m of methodsInBlock) {
      let methodSubBlock = block;
      if (methodsInBlock.length > 1) {
        const subIdx = block.indexOf(`request.method === '${m.toUpperCase()}'`);
        if (subIdx >= 0) {
          methodSubBlock = block.slice(subIdx, subIdx + 900);
        }
      }
      let sec: ExtractedSourceRoute['securityKind'];
      if (detectedPath === '/v1/mcp/query') {
        sec = methodSubBlock.includes("includes('mcp:call')") ? 'oauth_mcp_query' : 'public';
      } else if (
        methodSubBlock.includes("includes('crawl:read')") ||
        (block.includes("includes('crawl:read')") && m === 'get')
      ) {
        sec = 'oauth_read';
      } else if (methodSubBlock.includes("includes('crawl:fetch')") || block.includes("includes('crawl:fetch')")) {
        sec = 'oauth_fetch';
      } else {
        // Un-scoped route bug! Mark as `'public'` so contract validation against `oauth2Pkce` immediately FAILS!
        sec = 'public';
      }
      upsert(detectedPath, m, sec, m === 'get' ? qParams : []);
      // Store exact per-method security on multi-method paths
      (routes.get(detectedPath) as ExtractedSourceRoute & { methodSecurity?: Record<string, string> }).methodSecurity ??= {};
      (routes.get(detectedPath) as ExtractedSourceRoute & { methodSecurity?: Record<string, string> }).methodSecurity![m] = sec;
    }
  }

  // 3. Parse `/v2/*` documented compatibility routes from `hub/src/compat.ts`
  for (const fcMatch of sources.compatSrc.matchAll(/fcSubpath\s*===\s*'\/(scrape|crawl|map|search|extract|agent)'\s*&&\s*request\.method\s*===\s*'([A-Z]+)'/g)) {
    const sub = fcMatch[1]!;
    const method = fcMatch[2]!.toLowerCase();
    const hasFetchScope = sources.compatSrc.includes("auth.scopes.includes('crawl:fetch')");
    upsert(`/v2/${sub}`, method, hasFetchScope ? 'oauth_fetch' : 'public');
  }

  return routes;
}

function validateJsonValueAgainstSchema(
  value: unknown,
  schema: Record<string, unknown>,
  allSchemas: Record<string, Record<string, unknown>>,
  atPath: string,
): void {
  if (typeof schema.$ref === 'string') {
    const prefix = '#/components/schemas/';
    assert.ok(schema.$ref.startsWith(prefix), `${atPath}: unsupported $ref "${schema.$ref}"`);
    const refName = schema.$ref.slice(prefix.length);
    const target = allSchemas[refName];
    assert.ok(target, `${atPath}: broken $ref "${schema.$ref}" (schema missing from components.schemas)`);
    validateJsonValueAgainstSchema(value, target, allSchemas, `${atPath}($ref:${refName})`);
    return;
  }

  if (schema.const !== undefined) {
    assert.equal(value, schema.const, `${atPath}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
  }

  if (Array.isArray(schema.enum)) {
    assert.ok(schema.enum.includes(value), `${atPath}: value ${JSON.stringify(value)} not in enum ${JSON.stringify(schema.enum)}`);
  }

  const rawType = schema.type;
  if (rawType !== undefined) {
    const allowedTypes = Array.isArray(rawType) ? rawType : [rawType];
    const actualType =
      value === null
        ? 'null'
        : Array.isArray(value)
          ? 'array'
          : typeof value === 'number' && Number.isInteger(value)
            ? 'integer'
            : typeof value;
    const typeMatches =
      allowedTypes.includes(actualType) || (actualType === 'integer' && allowedTypes.includes('number'));
    assert.ok(
      typeMatches,
      `${atPath}: expected type ${JSON.stringify(allowedTypes)}, got ${actualType} (${JSON.stringify(value)})`,
    );
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    if (Array.isArray(schema.required)) {
      for (const reqKey of schema.required as string[]) {
        assert.ok(
          Object.prototype.hasOwnProperty.call(obj, reqKey),
          `${atPath}: missing required response property "${reqKey}"`,
        );
      }
    }
    const props = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
    for (const [k, v] of Object.entries(obj)) {
      if (v !== undefined && props[k]) {
        validateJsonValueAgainstSchema(v, props[k]!, allSchemas, `${atPath}.${k}`);
      }
    }
  } else if (Array.isArray(value) && schema.items && typeof schema.items === 'object') {
    for (let i = 0; i < Math.min(value.length, 5); i++) {
      validateJsonValueAgainstSchema(value[i], schema.items as Record<string, unknown>, allSchemas, `${atPath}[${i}]`);
    }
  }
}

export function assertOpenApiSourceAndSchemaContract(params: {
  spec: Record<string, unknown>;
  indexSrc: string;
  compatSrc: string;
  botAuthSrc: string;
  oauthSrc: string;
  githubAuthSrc: string;
  mcpTools?: ReturnType<typeof buildCanonicalMcpToolSchemas>;
}): void {
  const { spec } = params;
  assert.equal(spec.openapi, '3.1.0');
  const specPaths = spec.paths as Record<string, Record<string, Record<string, unknown>>>;
  const components = spec.components as {
    securitySchemes: Record<string, Record<string, unknown>>;
    schemas: Record<string, Record<string, unknown>>;
  };
  assert.ok(specPaths && typeof specPaths === 'object');
  assert.ok(components?.schemas && typeof components.schemas === 'object');

  // 1. Verify EVERY `$ref` anywhere in the entire OpenAPI spec resolves to an existing schema in `components.schemas`!
  const walkRefs = (node: unknown, loc: string) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      node.forEach((item, idx) => walkRefs(item, `${loc}[${idx}]`));
      return;
    }
    const rec = node as Record<string, unknown>;
    if (typeof rec.$ref === 'string') {
      const prefix = '#/components/schemas/';
      assert.ok(rec.$ref.startsWith(prefix), `${loc}: invalid $ref prefix "${rec.$ref}"`);
      const name = rec.$ref.slice(prefix.length);
      assert.ok(
        Object.prototype.hasOwnProperty.call(components.schemas, name),
        `${loc}: dangling $ref "${rec.$ref}" not found in components.schemas`,
      );
    }
    for (const [k, v] of Object.entries(rec)) {
      walkRefs(v, `${loc}.${k}`);
    }
  };
  walkRefs(specPaths, 'paths');
  walkRefs(components.schemas, 'components.schemas');

  // 2. Bidirectional 1:1 Route + HTTP Method + Security Scope + Path/Query Parameter Parity against source!
  const sourceRoutes = extractCanonicalRoutesFromSource(params);
  const specRouteKeys = Object.keys(specPaths).sort();
  const sourceRouteKeys = [...sourceRoutes.keys()].sort();
  assert.deepEqual(
    specRouteKeys,
    sourceRouteKeys,
    'OpenAPI spec.paths and Hub source routes drifted (phantom or missing route)!',
  );

  const validHttpMethods = new Set(['get', 'post', 'put', 'delete', 'patch']);
  for (const [routePath, srcInfo] of sourceRoutes.entries()) {
    const specItem = specPaths[routePath]!;
    const specMethods = Object.keys(specItem)
      .filter((k) => validHttpMethods.has(k.toLowerCase()))
      .map((k) => k.toLowerCase())
      .sort();
    const expectedMethods = [...srcInfo.methods].sort();
    assert.deepEqual(
      specMethods,
      expectedMethods,
      `HTTP method drift on "${routePath}": spec has [${specMethods.join(',')}], source has [${expectedMethods.join(',')}]`,
    );

    for (const method of expectedMethods) {
      const op = specItem[method]!;
      assert.ok(typeof op.operationId === 'string' && op.operationId.length > 0, `${method.toUpperCase()} ${routePath} missing operationId`);

      // Verify path parameters match `{param}` placeholders 1:1
      const opParams = (Array.isArray(op.parameters) ? op.parameters : []) as Array<{
        name: string;
        in: string;
        required?: boolean;
      }>;
      const specPathParams = opParams
        .filter((p) => p.in === 'path')
        .map((p) => {
          assert.equal(p.required, true, `Path param ${p.name} on ${routePath} must have required: true`);
          return p.name;
        });
      assert.deepEqual(
        specPathParams,
        srcInfo.pathParams,
        `Path parameter drift on ${method.toUpperCase()} ${routePath}`,
      );

      // Verify query parameters read in `index.ts` are documented in `op.parameters`
      if (method === 'get' && srcInfo.queryParams.size > 0) {
        const specQueryParams = new Set(opParams.filter((p) => p.in === 'query').map((p) => p.name));
        for (const qp of srcInfo.queryParams) {
          assert.ok(
            specQueryParams.has(qp),
            `Query parameter "${qp}" read by ${method.toUpperCase()} ${routePath} in source is missing from OpenAPI parameters!`,
          );
        }
      }

      // Verify OAuth security scopes match actual handler enforcement!
      const methodSec =
        (srcInfo as ExtractedSourceRoute & { methodSecurity?: Record<string, string> }).methodSecurity?.[method] ??
        srcInfo.securityKind;
      const specSec = op.security as Array<Record<string, string[]>> | undefined;
      assert.ok(Array.isArray(specSec), `${method.toUpperCase()} ${routePath} must declare explicit security array`);

      if (methodSec === 'public') {
        assert.deepEqual(
          specSec,
          [],
          `Security drift on ${method.toUpperCase()} ${routePath}: source enforces NO scope/auth, while spec claims ${JSON.stringify(specSec)}`,
        );
      } else if (methodSec === 'owner_bearer') {
        assert.deepEqual(specSec, [{ bearerAuth: [] }], `Expected owner bearerAuth on ${method.toUpperCase()} ${routePath}`);
      } else if (methodSec === 'oauth_read') {
        const oauthEntry = specSec.find((s) => 'oauth2Pkce' in s);
        assert.deepEqual(
          oauthEntry?.oauth2Pkce,
          ['crawl:read'],
          `Expected oauth2Pkce: ['crawl:read'] on ${method.toUpperCase()} ${routePath}, got ${JSON.stringify(specSec)}`,
        );
      } else if (methodSec === 'oauth_fetch') {
        const oauthEntry = specSec.find((s) => 'oauth2Pkce' in s);
        assert.deepEqual(
          oauthEntry?.oauth2Pkce,
          ['crawl:fetch'],
          `Expected oauth2Pkce: ['crawl:fetch'] on ${method.toUpperCase()} ${routePath}, got ${JSON.stringify(specSec)}`,
        );
      } else if (methodSec === 'oauth_mcp_query') {
        const oauthEntry = specSec.find((s) => 'oauth2Pkce' in s);
        assert.deepEqual(oauthEntry?.oauth2Pkce, ['crawl:read', 'mcp:call']);
      } else if (methodSec === 'oauth_mcp_rpc') {
        const oauthEntry = specSec.find((s) => 'oauth2Pkce' in s);
        assert.deepEqual(oauthEntry?.oauth2Pkce, ['crawl:read', 'crawl:fetch', 'mcp:call']);
      }
    }
  }

  // 3. Verify ALL 17 canonical MCP tool schemas match `McpTool_*Input` AND shared REST request schemas!
  const mcpTools = params.mcpTools ?? buildCanonicalMcpToolSchemas();
  assert.equal(mcpTools.length, 17);
  for (const tool of mcpTools) {
    const pascal = tool.name
      .split('_')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join('');
    const key = `McpTool_${pascal}Input`;
    const inSpec = components.schemas[key];
    assert.ok(inSpec, `Missing MCP tool schema ${key} in OpenAPI components.schemas`);
    const { title: _t, description: _d, ...restSchema } = inSpec;
    assert.deepEqual(restSchema, tool.inputSchema, `MCP tool "${tool.name}" inputSchema drifted from OpenAPI ${key}`);
  }
  assert.deepEqual(components.schemas.ScrapeRequest, MCP_TOOL_SCHEMAS.scrape);
  assert.deepEqual(components.schemas.ExtractRequest, MCP_TOOL_SCHEMAS.extract);
  assert.deepEqual(components.schemas.InteractRequest, MCP_TOOL_SCHEMAS.interact);
  assert.deepEqual(components.schemas.MapRequest, MCP_TOOL_SCHEMAS.map);
  assert.deepEqual(components.schemas.SearchRequest, MCP_TOOL_SCHEMAS.search);
  assert.deepEqual(components.schemas.JobsRequest, MCP_TOOL_SCHEMAS.jobs);
  assert.deepEqual(components.schemas.CatalogRequest, MCP_TOOL_SCHEMAS.catalog);
}

test('Round 8 [Mutation-Proof OpenAPI Contract]: validates source parity, live response schemas & catches 10/10 synthetic mutations', async () => {
  const hubDir = process.env.EDGEFETCH_HUB_ROOT ?? process.cwd();
  const pkg = JSON.parse(readFileSync(resolve(hubDir, 'package.json'), 'utf8')) as { version: string };
  const indexSrc = readFileSync(resolve(hubDir, 'src', 'index.ts'), 'utf8');
  const compatSrc = readFileSync(resolve(hubDir, 'src', 'compat.ts'), 'utf8');
  const botAuthSrc = readFileSync(resolve(hubDir, 'src', 'bot-auth.ts'), 'utf8');
  const oauthSrc = readFileSync(resolve(hubDir, 'src', 'oauth.ts'), 'utf8');
  const githubAuthSrc = readFileSync(resolve(hubDir, 'src', 'github-auth.ts'), 'utf8');

  const spec = buildOpenApiSpec({ origin: 'https://edgefetch.dev', version: pkg.version });

  // 1. Baseline contract MUST pass 100% cleanly!
  assertOpenApiSourceAndSchemaContract({
    spec,
    indexSrc,
    compatSrc,
    botAuthSrc,
    oauthSrc,
    githubAuthSrc,
  });

  // 2. Validate LIVE HTTP responses from `hubWorker.fetch` against OpenAPI `responses[status]` JSON Schemas!
  const tmpData = mkdtempSync(join(tmpdir(), 'ef-r8-oa-live-'));
  const callerToken = 'r8-openapi-live-secret-0123456789abcdef';
  const oaCoordinator = new LocalAgentHubCoordinator(join(tmpData, 'hub.sqlite'));
  const oaMetaDb = new NodeSqliteD1Database(':memory:', [{ name: 'meta/0001_tracking.sql', sql: meta0001 }]);
  const oaSearchDb = new NodeSqliteD1Database(':memory:', [{ name: 'search/0001_fts.sql', sql: search0001 }]);
  const oaArtifacts = new NodeFsR2Bucket(join(tmpData, 'r2'));
  const oaEnv = {
    AGENT_HUB: oaCoordinator.asNamespace() as never,
    META: oaMetaDb as never,
    SEARCH: oaSearchDb as never,
    ARTIFACTS: oaArtifacts as never,
    CALLER_TOKEN: callerToken,
  };

  try {
    const specPaths = spec.paths as Record<string, Record<string, Record<string, unknown>>>;
    const allSchemas = (spec.components as { schemas: Record<string, Record<string, unknown>> }).schemas;

    const liveProbes: Array<{
      specPath: string;
      actualPath: string;
      method: 'GET' | 'POST';
      auth?: boolean;
      body?: unknown;
      expectedStatus: number;
    }> = [
      { specPath: '/health', actualPath: '/health', method: 'GET', expectedStatus: 200 },
      { specPath: '/.well-known/edgefetch-bot.json', actualPath: '/.well-known/edgefetch-bot.json', method: 'GET', expectedStatus: 200 },
      { specPath: '/.well-known/oauth-protected-resource', actualPath: '/.well-known/oauth-protected-resource', method: 'GET', expectedStatus: 200 },
      { specPath: '/.well-known/oauth-authorization-server', actualPath: '/.well-known/oauth-authorization-server', method: 'GET', expectedStatus: 200 },
      { specPath: '/v1/capabilities', actualPath: '/v1/capabilities', method: 'GET', auth: true, expectedStatus: 200 },
      { specPath: '/v1/capabilities', actualPath: '/v1/capabilities', method: 'GET', auth: false, expectedStatus: 401 },
      { specPath: '/v1/extractors', actualPath: '/v1/extractors', method: 'GET', auth: true, expectedStatus: 200 },
      { specPath: '/v1/hosts', actualPath: '/v1/hosts', method: 'GET', auth: true, expectedStatus: 200 },
      { specPath: '/agents', actualPath: '/agents', method: 'GET', auth: true, expectedStatus: 200 },
      {
        specPath: '/v1/crawl/params-preview',
        actualPath: '/v1/crawl/params-preview',
        method: 'POST',
        auth: true,
        body: { url: 'https://example.com', prompt: 'only /docs' },
        expectedStatus: 200,
      },
      {
        specPath: '/v1/ingest-tab',
        actualPath: '/v1/ingest-tab',
        method: 'POST',
        auth: true,
        body: { url: 'https://example.com/guide', markdown: '# Guide\n\nHello world.' },
        expectedStatus: 200,
      },
      {
        specPath: '/v1/collections/{collectionId}/search',
        actualPath: '/v1/collections/browser-clips/search?q=Guide',
        method: 'GET',
        auth: true,
        expectedStatus: 200,
      },
      {
        specPath: '/mcp',
        actualPath: '/mcp',
        method: 'POST',
        auth: true,
        body: { jsonrpc: '2.0', id: 1, method: 'ping' },
        expectedStatus: 200,
      },
    ];

    for (const probe of liveProbes) {
      const res = await hubWorker.fetch(
        new Request(`https://edgefetch.dev${probe.actualPath}`, {
          method: probe.method,
          headers: {
            ...(probe.auth ? { authorization: `Bearer ${callerToken}` } : {}),
            ...(probe.body !== undefined ? { 'content-type': 'application/json' } : {}),
          },
          ...(probe.body !== undefined ? { body: JSON.stringify(probe.body) } : {}),
        }),
        oaEnv,
      );
      assert.equal(res.status, probe.expectedStatus, `${probe.method} ${probe.actualPath} status`);
      const jsonBody = await res.json();
      const op = specPaths[probe.specPath]![probe.method.toLowerCase()]!;
      const responses = op.responses as Record<string, { content?: Record<string, { schema?: Record<string, unknown> }> }>;
      const respSchema = responses[String(probe.expectedStatus)]?.content?.['application/json']?.schema;
      assert.ok(respSchema, `Missing response schema for ${probe.method} ${probe.specPath} -> ${probe.expectedStatus}`);
      validateJsonValueAgainstSchema(jsonBody, respSchema!, allSchemas, `${probe.method} ${probe.specPath}[${probe.expectedStatus}]`);
    }
  } finally {
    oaCoordinator.close();
    oaMetaDb.close();
    oaSearchDb.close();
    rmSync(tmpData, { recursive: true, force: true });
  }

  // 3. 10-Mutation Self-Test: prove EVERY SINGLE ONE of 10 synthetic contract drifts FAILS `assertOpenApiSourceAndSchemaContract`
  //    or `validateJsonValueAgainstSchema` (`0/10` false passes)!
  const cloneSpec = () => JSON.parse(JSON.stringify(spec)) as Record<string, unknown>;

  const mutations: Array<{ name: string; run: () => void }> = [
    {
      name: '1. Missing /v1/jobs route in spec.paths',
      run: () => {
        const s = cloneSpec();
        delete (s.paths as Record<string, unknown>)['/v1/jobs'];
        assertOpenApiSourceAndSchemaContract({ spec: s, indexSrc, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '2. Phantom /v1/ghost-endpoint route added to spec.paths',
      run: () => {
        const s = cloneSpec();
        (s.paths as Record<string, unknown>)['/v1/ghost-endpoint'] = {
          get: { operationId: 'ghost', security: [], responses: { '200': { description: 'ok' } } },
        };
        assertOpenApiSourceAndSchemaContract({ spec: s, indexSrc, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '3. Wrong HTTP method (DELETE missing from /v1/crawl/{crawlId})',
      run: () => {
        const s = cloneSpec();
        delete ((s.paths as Record<string, Record<string, unknown>>)['/v1/crawl/{crawlId}'])!.delete;
        assertOpenApiSourceAndSchemaContract({ spec: s, indexSrc, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '4. Weakened OAuth scope in spec (/v1/scrape changed from crawl:fetch to crawl:read)',
      run: () => {
        const s = cloneSpec();
        const op = ((s.paths as Record<string, Record<string, Record<string, unknown>>>)['/v1/scrape'])!.post!;
        op.security = [{ bearerAuth: [] }, { oauth2Pkce: ['crawl:read'] }];
        assertOpenApiSourceAndSchemaContract({ spec: s, indexSrc, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '5. Missing scope check in index.ts source (/v1/capabilities drops crawl:read guard)',
      run: () => {
        const mutatedIndex = indexSrc.replace(
          /if \(request\.method === 'GET' && url\.pathname === '\/v1\/capabilities'\) \{[\s\S]*?return Response\.json\(buildCapabilities/,
          `if (request.method === 'GET' && url.pathname === '/v1/capabilities') {\n  return withRouteSpan('edgefetch.capabilities', {}, async () => {\n    return Response.json(buildCapabilities`,
        );
        assertOpenApiSourceAndSchemaContract({ spec, indexSrc: mutatedIndex, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '6. Path parameter name drift ({crawlId} documented as {id})',
      run: () => {
        const s = cloneSpec();
        const params = (((s.paths as Record<string, Record<string, Record<string, unknown>>>)['/v1/crawl/{crawlId}'])!.get!.parameters as Array<{ name: string }>);
        params[0]!.name = 'id';
        assertOpenApiSourceAndSchemaContract({ spec: s, indexSrc, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '7. Undocumented query parameter (category removed from /v1/extractors)',
      run: () => {
        const s = cloneSpec();
        (((s.paths as Record<string, Record<string, Record<string, unknown>>>)['/v1/extractors'])!.get!).parameters = [];
        assertOpenApiSourceAndSchemaContract({ spec: s, indexSrc, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '8. Dangling $ref in response schema',
      run: () => {
        const s = cloneSpec();
        (((s.paths as Record<string, Record<string, Record<string, unknown>>>)['/health'])!.get!.responses as Record<string, unknown>)['200'] = {
          description: 'broken',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/NonExistentSchema' } } },
        };
        assertOpenApiSourceAndSchemaContract({ spec: s, indexSrc, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '9. MCP tool inputSchema drift vs OpenAPI McpTool_SearchInput',
      run: () => {
        const s = cloneSpec();
        const schemas = (s.components as { schemas: Record<string, Record<string, unknown>> }).schemas;
        const props = schemas.McpTool_SearchInput!.properties as Record<string, unknown>;
        delete props.maxResults;
        assertOpenApiSourceAndSchemaContract({ spec: s, indexSrc, compatSrc, botAuthSrc, oauthSrc, githubAuthSrc });
      },
    },
    {
      name: '10. Live response body violates OpenAPI HealthResponse schema (wrong type / missing required field)',
      run: () => {
        const allSchemas = (spec.components as { schemas: Record<string, Record<string, unknown>> }).schemas;
        validateJsonValueAgainstSchema({ ok: 'yes' }, { $ref: '#/components/schemas/HealthResponse' }, allSchemas, 'GET /health');
      },
    },
  ];

  assert.equal(mutations.length, 10);
  for (const m of mutations) {
    assert.throws(
      () => m.run(),
      `Mutation "${m.name}" MUST fail the OpenAPI contract validator, but it passed!`,
    );
  }
});
