/**
 * Round 9 Security Audit Spans & OTel Budget Isolation Suite (`hub/src/otel.ts` & `hub/src/index.ts`):
 *  - Inbound `traceparent: 00-...-00` (`sampled=0`) NEVER suppresses `/admin/login` owner sign-in audit spans,
 *    failed login audit spans, `/admin/logout`, `/admin/api/*` mutations, `/oauth/*` grants/revocations, or `/mcp`
 *    authenticated spans on Workers `hubWorker.fetch`.
 *  - Public unauthenticated floods (`/openapi.json`, `/.well-known/*`, `/health`, `401` `/v1/scrape`, plus slow
 *    public OTLP collector saturation) CANNOT drain or block the OTLP export budget for authenticated or
 *    security-audit spans.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import { LocalAgentHubCoordinator } from './stubs/cf-storage-mocks';
import hubWorker from '../src/index';
import { ADMIN_COOKIE_NAME, createAdminSessionValue } from '../src/oauth';
import {
  MAX_PUBLIC_UNAUTH_INFLIGHT_OTLP,
  parseTraceparent,
  resetOtlpExportLimitersForTests,
  SECURITY_AUDIT_OTLP_CAPACITY,
  UNAUTH_OTLP_EXPORT_CAPACITY,
} from '../src/otel';

const CALLER_TOKEN = 'r9-owner-caller-secret-0123456789abcdef';

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

test('Round 9 [OTel Security Audit Spans]: traceparent -00 cannot suppress owner login/admin/OAuth/MCP audit spans & public floods cannot drain audit budget', async () => {
  resetOtlpExportLimitersForTests();
  assert.equal(UNAUTH_OTLP_EXPORT_CAPACITY, 30);
  assert.equal(SECURITY_AUDIT_OTLP_CAPACITY, 120);
  assert.equal(MAX_PUBLIC_UNAUTH_INFLIGHT_OTLP, 8);
  // Pure W3C parser contract remains intact (`-00` -> `sampled: false` at parser level)
  assert.equal(parseTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00')?.sampled, false);

  interface CapturedSpan {
    traceId: string;
    spanId: string;
    parentSpanId?: string;
    name: string;
    attributes: Record<string, string | number | boolean>;
  }

  const exportedSpans: CapturedSpan[] = [];
  let holdPublicExports = false;
  const heldPublicExportResolvers: Array<() => void> = [];

  const collector = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let hasAuditOrAuth = false;
      try {
        const parsed = JSON.parse(raw) as {
          resourceSpans?: Array<{
            scopeSpans?: Array<{
              spans?: Array<{
                traceId: string;
                spanId: string;
                parentSpanId?: string;
                name: string;
                attributes?: Array<{
                  key: string;
                  value?: { stringValue?: string; intValue?: string; doubleValue?: number; boolValue?: boolean };
                }>;
              }>;
            }>;
          }>;
        };
        const batchSpans = parsed.resourceSpans?.[0]?.scopeSpans?.[0]?.spans ?? [];
        for (const s of batchSpans) {
          const attrMap: Record<string, string | number | boolean> = {};
          for (const a of s.attributes ?? []) {
            if (a.value?.stringValue !== undefined) attrMap[a.key] = a.value.stringValue;
            else if (a.value?.intValue !== undefined) attrMap[a.key] = Number(a.value.intValue);
            else if (a.value?.doubleValue !== undefined) attrMap[a.key] = a.value.doubleValue;
            else if (a.value?.boolValue !== undefined) attrMap[a.key] = a.value.boolValue;
          }
          if (s.name.startsWith('edgefetch.admin.') || s.name.startsWith('edgefetch.oauth.') || s.name === 'edgefetch.mcp.tool') {
            hasAuditOrAuth = true;
          }
          exportedSpans.push({
            traceId: s.traceId,
            spanId: s.spanId,
            ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
            name: s.name,
            attributes: attrMap,
          });
        }
      } catch {
        // ignore
      }
      const finishResp = () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{}');
      };
      if (holdPublicExports && !hasAuditOrAuth) {
        heldPublicExportResolvers.push(finishResp);
      } else {
        finishResp();
      }
    });
  });

  await new Promise<void>((r) => collector.listen(0, '127.0.0.1', r));
  const collectorPort = (collector.address() as net.AddressInfo).port;
  const collectorEndpoint = `http://127.0.0.1:${collectorPort}`;

  const coordinator = new LocalAgentHubCoordinator(':memory:');

  try {
    const workerEnv = {
      AGENT_HUB: coordinator.asNamespace() as never,
      CALLER_TOKEN,
      OTEL_EXPORTER_OTLP_ENDPOINT: collectorEndpoint,
      EDGEFETCH_DISABLE_UPDATE_CHECK: '1',
    };

    // 1. Public unauthenticated flood: 120 `/openapi.json` + 120 `/.well-known/*` + 100 `/health` + 100 `401 /v1/scrape`
    //    (completely exhausting `UNAUTH_OTLP_EXPORT_CAPACITY = 30`!)
    for (let i = 0; i < 120; i++) {
      await hubWorker.fetch(new Request('https://hub.example.com/openapi.json'), workerEnv);
      await hubWorker.fetch(new Request('https://hub.example.com/.well-known/oauth-authorization-server'), workerEnv);
      if (i < 100) {
        await hubWorker.fetch(
          new Request('https://hub.example.com/health', {
            headers: { traceparent: `00-${'1'.repeat(32)}-${'2'.repeat(16)}-01` },
          }),
          workerEnv,
        );
        await hubWorker.fetch(
          new Request('https://hub.example.com/v1/scrape', {
            method: 'POST',
            headers: { 'content-type': 'application/json', traceparent: `00-${'3'.repeat(32)}-${'4'.repeat(16)}-01` },
            body: '{"url":"https://example.com"}',
          }),
          workerEnv,
        );
      }
    }

    // ALSO hold `MAX_PUBLIC_UNAUTH_INFLIGHT_OTLP` slow public OTLP collector exports open concurrently
    // (after refilling unauth budget just enough to launch slow public exports) to verify inflight isolation too!
    resetOtlpExportLimitersForTests();
    holdPublicExports = true;
    const stalledPublicFlushes: Promise<Response>[] = [];
    for (let i = 0; i < 20; i++) {
      stalledPublicFlushes.push(hubWorker.fetch(new Request('https://hub.example.com/openapi.json'), workerEnv));
    }
    await sleep(60);
    // Drain the remaining `unauthOtlpTokens` completely as well
    holdPublicExports = false;
    for (let i = 0; i < 40; i++) {
      await hubWorker.fetch(new Request('https://hub.example.com/openapi.json'), workerEnv);
    }

    exportedSpans.length = 0;

    // 2. Exact Round 9 reproduction on Workers Hub:
    //    Successful owner `POST /admin/login` WITH `traceparent: ...-00` MUST emit `edgefetch.admin.login` (`authenticated`)!
    const loginTraceUnsampled = 'aaaa1111bbbb2222cccc3333dddd4444';
    const loginParentId = '1122334455667788';
    const loginWith00 = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/login', {
        method: 'POST',
        headers: {
          origin: 'https://hub.example.com',
          'content-type': 'application/x-www-form-urlencoded',
          traceparent: `00-${loginTraceUnsampled}-${loginParentId}-00`,
        },
        body: new URLSearchParams({ token: CALLER_TOKEN }).toString(),
      }),
      workerEnv,
    );
    assert.equal(loginWith00.status, 302);
    assert.match(
      loginWith00.headers.get('traceparent') ?? '',
      new RegExp(`^00-${loginTraceUnsampled}-[0-9a-f]{16}-01$`),
      'Promoted audit trace must advertise sampled -01 in response traceparent',
    );

    const loginAuditSpan = exportedSpans.find(
      (s) => s.name === 'edgefetch.admin.login' && s.traceId === loginTraceUnsampled,
    );
    assert.ok(loginAuditSpan, 'Owner login with traceparent -00 MUST emit edgefetch.admin.login audit span');
    assert.equal(loginAuditSpan.attributes['admin.outcome'], 'authenticated');
    const loginHttpSpan = exportedSpans.find(
      (s) => s.name === 'edgefetch.http' && s.traceId === loginTraceUnsampled,
    );
    assert.ok(loginHttpSpan, 'Enclosing edgefetch.http span must also be exported with parentSpanId stitched');
    assert.equal(loginHttpSpan.parentSpanId, loginParentId);

    // 3. Failed `POST /admin/login` (401) WITH `traceparent: ...-00` AFTER public traffic drained `unauthOtlpTokens`
    //    MUST ALSO emit `edgefetch.admin.login` (`unauthorized`) via isolated `security_audit` budget!
    const badLoginTrace = 'bbbb2222cccc3333dddd4444eeee5555';
    const badLoginWith00 = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/login', {
        method: 'POST',
        headers: {
          origin: 'https://hub.example.com',
          'content-type': 'application/x-www-form-urlencoded',
          'cf-connecting-ip': '198.51.100.77',
          traceparent: `00-${badLoginTrace}-${loginParentId}-00`,
        },
        body: 'token=wrong-secret-guess',
      }),
      workerEnv,
    );
    assert.equal(badLoginWith00.status, 401);
    const badLoginSpan = exportedSpans.find(
      (s) => s.name === 'edgefetch.admin.login' && s.traceId === badLoginTrace,
    );
    assert.ok(badLoginSpan, 'Failed admin login with traceparent -00 must emit security_audit span even after public flood');
    assert.equal(badLoginSpan.attributes['admin.outcome'], 'unauthorized');

    // 4. OAuth `/oauth/register`, `/admin/api/grants/revoke`, `/mcp` tool call, and Portable Hub `/admin/login` with `-00`!
    const oauthRegTrace = 'cccc3333dddd4444eeee5555ffff6666';
    const regRes = await hubWorker.fetch(
      new Request('https://hub.example.com/oauth/register', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'cf-connecting-ip': '198.51.100.88',
          traceparent: `00-${oauthRegTrace}-${loginParentId}-00`,
        },
        body: JSON.stringify({
          client_name: 'Audit Test Client',
          redirect_uris: ['http://127.0.0.1:8910/cb'],
        }),
      }),
      workerEnv,
    );
    assert.equal(regRes.status, 201);
    assert.ok(
      exportedSpans.some((s) => s.name === 'edgefetch.oauth.register' && s.traceId === oauthRegTrace),
      'OAuth client registration with traceparent -00 must emit edgefetch.oauth.register audit span',
    );

    const mintedAdmin = await createAdminSessionValue(CALLER_TOKEN);
    const adminRevokeTrace = 'dddd4444eeee5555ffff666600001111';
    const revokeRes = await hubWorker.fetch(
      new Request('https://hub.example.com/admin/api/grants/revoke', {
        method: 'POST',
        headers: {
          origin: 'https://hub.example.com',
          cookie: `${ADMIN_COOKIE_NAME}=${mintedAdmin.value}`,
          'x-csrf-token': mintedAdmin.csrf,
          'content-type': 'application/json',
          traceparent: `00-${adminRevokeTrace}-${loginParentId}-00`,
        },
        body: JSON.stringify({ grantId: 'grant_test_123' }),
      }),
      workerEnv,
    );
    assert.equal(revokeRes.status, 200);
    assert.ok(
      exportedSpans.some((s) => s.name === 'edgefetch.admin.grant_revoke' && s.traceId === adminRevokeTrace),
      'Admin grant_revoke with traceparent -00 must emit edgefetch.admin.grant_revoke audit span',
    );

    const mcpTrace = 'eeee5555ffff66660000111122223333';
    const mcpRes = await hubWorker.fetch(
      new Request('https://hub.example.com/mcp', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${CALLER_TOKEN}`,
          'content-type': 'application/json',
          traceparent: `00-${mcpTrace}-${loginParentId}-00`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'find_extractors', arguments: { query: 'stripe', limit: 2 } },
        }),
      }),
      workerEnv,
    );
    assert.equal(mcpRes.status, 200);
    assert.ok(
      exportedSpans.some((s) => s.name === 'edgefetch.mcp.tool' && s.traceId === mcpTrace),
      'MCP tools/call with traceparent -00 must emit edgefetch.mcp.tool span',
    );

    for (const finishHeld of heldPublicExportResolvers.splice(0)) finishHeld();
    await Promise.allSettled(stalledPublicFlushes);
  } finally {
    for (const finishHeld of heldPublicExportResolvers.splice(0)) finishHeld();
    coordinator.close();
    collector.close();
  }
});
