/**
 * Deno Deploy Edge Hub Entrypoint (`hub/portable/deno-server.ts`).
 *
 * Bridges EdgeFetch's standard Web `fetch` Worker (`hub/src/index.ts`), `Deno.upgradeWebSocket` for outbound Go
 * `/agent/ws` nodes, `BroadcastChannel('edgefetch-hub-bus')` for cross-region isolate dispatch notifications, and
 * optional `TursoHttpD1Database` + `S3ArtifactBucket` storage bindings.
 */
import {
  createMemoryActivityStore,
  sanitizeDetails,
  type ActivityStore,
  type HubEventInput,
} from '../src/activity-log.ts';
import {
  AgentHubEngine,
  createMemoryAffinityStore,
  createMemoryCooldownStore,
  createMemoryHostHealthStore,
  createMemoryHostWindowStore,
  type AgentAttachment,
  type ArtifactDispatchPolicy,
  type AuthorizeArtifactUploadParams,
  type HubSocketLike,
} from '../src/agent-hub.ts';
import { authorizeAgent } from '../src/auth.ts';
import hubWorker from '../src/index.ts';
import {
  createMemoryOAuthStore,
  type OAuthClientRecord,
  type OAuthCodeRecord,
  type OAuthStore,
  type RotateRefreshParams,
} from '../src/oauth.ts';
import { validatePublicHttpsTargetUrl } from '../src/overflow.ts';
import { isPublicIpAddress } from './safe-fetch.ts';
import { S3ArtifactBucket } from './s3-bucket.ts';
import { TursoHttpD1Database } from './turso-d1.ts';

declare const Deno: {
  env: { get(key: string): string | undefined; toObject(): Record<string, string> };
  serve(
    options: { port?: number; hostname?: string },
    handler: (req: Request, info: { remoteAddr?: { hostname?: string } }) => Response | Promise<Response>,
  ): unknown;
  upgradeWebSocket(req: Request, options?: { protocol?: string }): { socket: WebSocket; response: Response };
  resolveDns?(query: string, recordType: 'A' | 'AAAA'): Promise<string[]>;
};

const MAX_DENO_WS_FRAME_BYTES = 1 * 1024 * 1024; // 1 MiB (`M6`)
const MAX_DENO_SAFE_HOPS = 5;

class DenoHubSocket implements HubSocketLike {
  private attachment: AgentAttachment | null = null;
  constructor(
    readonly raw: WebSocket,
    readonly tags: string[],
  ) {}
  get readyState(): number {
    return this.raw.readyState;
  }
  send(message: string): void {
    if (this.raw.readyState === WebSocket.OPEN) {
      this.raw.send(message);
    }
  }
  close(code?: number, reason?: string): void {
    try {
      this.raw.close(code, reason);
    } catch {
      // ignore
    }
  }
  serializeAttachment(value: AgentAttachment): void {
    this.attachment = structuredClone(value);
  }
  deserializeAttachment(): unknown {
    return this.attachment ? structuredClone(this.attachment) : null;
  }
}

async function assertDenoResolvedPublicIp(hostname: string): Promise<void> {
  if (typeof Deno === 'undefined' || typeof Deno.resolveDns !== 'function') return;
  const [v4, v6] = await Promise.all([
    Deno.resolveDns(hostname, 'A').catch(() => [] as string[]),
    Deno.resolveDns(hostname, 'AAAA').catch(() => [] as string[]),
  ]);
  const ips = [...v4, ...v6];
  if (ips.length === 0) {
    throw new Error(`DNS resolution returned no A/AAAA records for ${hostname}`);
  }
  for (const ip of ips) {
    if (!isPublicIpAddress(ip)) {
      throw new Error(`SSRF blocked: ${hostname} resolved to non-public IP ${ip}`);
    }
  }
}

function createDenoSafeFetch(selfHost?: string): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const reqObj = input instanceof Request ? input : null;
    let currentUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const callerRedirect = init?.redirect ?? reqObj?.redirect ?? 'follow';
    let method = (init?.method ?? reqObj?.method ?? 'GET').toUpperCase();
    let body = init?.body ?? (reqObj ? reqObj.body : undefined);
    const baseHeaders = new Headers(init?.headers ?? reqObj?.headers);
    const initialOrigin = new URL(currentUrl).origin;

    for (let hop = 0; hop <= MAX_DENO_SAFE_HOPS; hop++) {
      const check = validatePublicHttpsTargetUrl(currentUrl, selfHost);
      if (!check.ok) {
        throw new Error(`SSRF blocked outbound URL: ${check.message}`);
      }
      await assertDenoResolvedPublicIp(check.url.hostname);

      const hopHeaders = new Headers(baseHeaders);
      if (check.url.origin !== initialOrigin) {
        hopHeaders.delete('authorization');
        hopHeaders.delete('cookie');
        hopHeaders.delete('proxy-authorization');
        hopHeaders.delete('x-api-key');
        hopHeaders.delete('x-goog-api-key');
      }

      const res = await fetch(check.url.toString(), {
        ...init,
        method,
        headers: hopHeaders,
        body: method === 'GET' || method === 'HEAD' ? undefined : body,
        redirect: 'manual',
      });

      if (res.status >= 300 && res.status < 400) {
        if (callerRedirect === 'manual') return res;
        await res.body?.cancel().catch(() => undefined);
        if (callerRedirect === 'error') {
          throw new TypeError(`Redirect mode is 'error' (HTTP ${res.status})`);
        }
        const loc = res.headers.get('location');
        if (!loc || hop === MAX_DENO_SAFE_HOPS) {
          throw new Error(`Too many or invalid redirects from ${check.url.origin}`);
        }
        currentUrl = new URL(loc, check.url).toString();
        if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
          method = 'GET';
          body = undefined;
        }
        continue;
      }
      return res;
    }
    throw new Error('Max redirects exceeded');
  }) as typeof fetch;
}

export function startDenoHub() {
  const envMap = Deno.env.toObject();
  const sockets = new Set<DenoHubSocket>();
  const lastHelloLogBySite = new Map<string, number>();
  const engine = new AgentHubEngine({
    getSockets: (tag) => {
      const all = [...sockets];
      return tag ? all.filter((s) => s.tags.includes(tag)) : all;
    },
    cooldowns: createMemoryCooldownStore(),
    hostWindows: createMemoryHostWindowStore(),
    affinities: createMemoryAffinityStore(),
    hostHealth: createMemoryHostHealthStore(),
  });
  const oauth: OAuthStore = createMemoryOAuthStore();
  const activity: ActivityStore = createMemoryActivityStore();
  const bus = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('edgefetch-hub-bus') : null;
  void bus;

  const tursoUrl = envMap.TURSO_DATABASE_URL;
  const tursoToken = envMap.TURSO_AUTH_TOKEN;
  const metaDb = (envMap.META_TURSO_URL || tursoUrl)
    ? new TursoHttpD1Database({ url: envMap.META_TURSO_URL || tursoUrl!, authToken: tursoToken }).asD1Database()
    : undefined;
  const searchDb = (envMap.SEARCH_TURSO_URL || tursoUrl)
    ? new TursoHttpD1Database({ url: envMap.SEARCH_TURSO_URL || tursoUrl!, authToken: tursoToken }).asD1Database()
    : undefined;
  const s3Bucket =
    envMap.S3_ENDPOINT && envMap.S3_BUCKET && envMap.S3_ACCESS_KEY_ID && envMap.S3_SECRET_ACCESS_KEY
      ? new S3ArtifactBucket({
          endpoint: envMap.S3_ENDPOINT,
          bucket: envMap.S3_BUCKET,
          accessKeyId: envMap.S3_ACCESS_KEY_ID,
          secretAccessKey: envMap.S3_SECRET_ACCESS_KEY,
          region: envMap.S3_REGION || 'auto',
        }).asR2Bucket()
      : undefined;

  let selfHost: string | undefined;
  if (envMap.EDGEFETCH_PUBLIC_ORIGIN) {
    try {
      selfHost = new URL(envMap.EDGEFETCH_PUBLIC_ORIGIN).hostname;
    } catch {
      selfHost = undefined;
    }
  }
  const safePublicFetch = createDenoSafeFetch(selfHost);

  const stub = {
    fetch: async () => new Response('use deno upgrade handler', { status: 426 }),
    listAgents: async () => engine.listAgents(),
    listAffinities: async () => engine.listAffinities(),
    clearAffinities: async (siteId?: string) => engine.clearAffinities(siteId),
    listHostHealth: async (limit = 100) => engine.listHostHealth(limit),
    recordHostOutcome: async (p: Parameters<AgentHubEngine['recordHostOutcome']>[0]) => engine.recordHostOutcome(p),
    recordHubEvents: async (events: HubEventInput[]) => {
      for (const ev of events) await activity.recordEvent(ev);
    },
    clearHubEvents: async () => activity.clearEvents(),
    recordMcpCall: async (p: Parameters<ActivityStore['recordMcpCall']>[0]) => activity.recordMcpCall(p),
    getPortalState: async (now: number) => ({
      ...engine.listAgents(),
      affinities: engine.listAffinities(),
      grants: await oauth.listGrants(now),
      mcpClients: await activity.listMcpClients(),
      events: activity.listPortalEvents ? await activity.listPortalEvents(75, 75) : await activity.listEvents(150),
    }),
    waitForHostWindow: async (hosts: string[], pauseMs?: number, dl?: number) => engine.waitForHostWindow(hosts, pauseMs, dl),
    dispatchFetch: async (rawBody: string, trace: Record<string, string>, preferredSite?: string, artifactPolicy?: ArtifactDispatchPolicy) =>
      engine.dispatchFetch(rawBody, trace, { preferredSite, ...(artifactPolicy ? { artifactPolicy } : {}) }),
    hasPendingJob: async (jobId: string, siteId: string) => engine.hasPendingJob(jobId, siteId),
    verifyPendingJob: async (jobId: string, jobNonce: string, siteId: string) => engine.verifyPendingJob(jobId, jobNonce, siteId),
    authorizeArtifactUpload: async (p: AuthorizeArtifactUploadParams) => engine.authorizeArtifactUpload(p),
    failJob: async (jobId: string, jobNonce: string, siteId: string, reason: string, permanent = true) =>
      engine.failJob(jobId, jobNonce, siteId, reason, permanent),
    completeJob: async (jobId: string, jobNonce: string, siteId: string, bodyText: string) =>
      engine.completeJob(jobId, jobNonce, siteId, bodyText),
    oauthPutClient: (c: OAuthClientRecord) => oauth.putClient(c),
    oauthGetClient: (id: string) => oauth.getClient(id),
    oauthPutCode: (c: OAuthCodeRecord) => oauth.putCode(c),
    oauthConsumeCode: (h: string, now: number) => oauth.consumeCode(h, now),
    oauthPutTokenPair: (p: Parameters<OAuthStore['putTokenPair']>[0]) => oauth.putTokenPair(p),
    oauthGetAccessToken: (h: string, now: number) => oauth.getAccessToken(h, now),
    oauthConsumeRefreshToken: (h: string, now: number) => oauth.consumeRefreshToken(h, now),
    oauthRotateRefreshToken: (p: RotateRefreshParams) => oauth.rotateRefreshToken(p),
    oauthListGrants: (now: number) => oauth.listGrants(now),
    oauthRevokeGrant: (id: string) => oauth.revokeGrant(id),
    oauthRevokeByTokenHash: (h: string) => oauth.revokeByTokenHash(h),
    oauthCheckAuthLockout: (b: string, now: number, m?: number) => oauth.checkAuthLockout(b, now, m),
    oauthRecordAuthFailure: (b: string, now: number, w: number, m: number) => oauth.recordAuthFailure(b, now, w, m),
    oauthClearAuthFailures: (b: string) => oauth.clearAuthFailures(b),
  };

  const workerEnv: Record<string, unknown> = {
    ...envMap,
    SAFE_FETCH: safePublicFetch,
    SAFE_PUBLIC_FETCH: safePublicFetch,
    AGENT_HUB: {
      idFromName: () => ({ toString: () => 'deno-global' }),
      get: () => stub,
    },
    ...(metaDb ? { META: metaDb } : {}),
    ...(searchDb ? { SEARCH: searchDb } : {}),
    ...(s3Bucket ? { ARTIFACTS: s3Bucket } : {}),
  };

  const ctx = {
    waitUntil(p: Promise<unknown>) {
      p.catch(() => undefined);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;

  const port = Number(envMap.PORT || 8787);
  return Deno.serve({ port }, (req, info) => {
    const url = new URL(req.url);
    if (url.pathname === '/agent/ws' && req.headers.get('upgrade')?.toLowerCase() === 'websocket') {
      const auth = authorizeAgent(req, workerEnv as never);
      if (!auth.ok) {
        return Response.json({ error: 'unauthorized' }, { status: 401 });
      }
      const offeredProtocols = (req.headers.get('sec-websocket-protocol') ?? '')
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean);
      const chosenSubprotocol = offeredProtocols.includes('edgefetch-agent') ? 'edgefetch-agent' : undefined;
      const { socket, response } = Deno.upgradeWebSocket(
        req,
        chosenSubprotocol ? { protocol: chosenSubprotocol } : undefined,
      );
      const hubSock = new DenoHubSocket(socket, [`site:${auth.siteId}`]);
      socket.onopen = () => {
        sockets.add(hubSock);
        const att = engine.registerAgent(hubSock, auth.siteId, req.headers.get('x-agent-arch')?.slice(0, 32) || null, {
          version: req.headers.get('x-agent-version')?.slice(0, 64) || null,
          publicIp: info.remoteAddr?.hostname || null,
          capabilities: req.headers.get('x-agent-capabilities') || null,
        });
        hubSock.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
      };
      socket.onmessage = (ev) => {
        const byteLen =
          typeof ev.data === 'string'
            ? new TextEncoder().encode(ev.data).byteLength
            : ev.data instanceof ArrayBuffer
              ? ev.data.byteLength
              : 0;
        if (byteLen > MAX_DENO_WS_FRAME_BYTES) {
          hubSock.close(1009, 'Message too big');
          return;
        }
        if (typeof ev.data === 'string') {
          if (ev.data === 'ping') {
            hubSock.send('pong');
            return;
          }
          if (ev.data.length > 2048) return;
          try {
            const msg = JSON.parse(ev.data) as {
              type?: string;
              version?: string;
              arch?: string;
              goVersion?: string;
              capabilities?: string[];
              reconnectAttempt?: number;
            };
            if (msg.type === 'agent_hello' || msg.type === 'hello') {
              const updated = engine.updateAgentHello(hubSock, msg);
              const att = updated ?? (hubSock.deserializeAttachment() as AgentAttachment | null);
              const verifiedSiteId = att?.siteId ?? auth.siteId;
              const nowMs = Date.now();
              const lastLoggedAt = lastHelloLogBySite.get(verifiedSiteId) ?? 0;
              if (nowMs - lastLoggedAt >= 60_000) {
                lastHelloLogBySite.set(verifiedSiteId, nowMs);
                void activity.recordEvent({
                  level: 'info',
                  category: 'agent',
                  event: (msg.reconnectAttempt ?? 0) > 0 ? 'agent_reconnected' : 'agent_ready',
                  summary: `Remote node "${verifiedSiteId}" ready (${msg.goVersion ?? 'go'}, ${msg.arch ?? ''})`,
                  details: sanitizeDetails({ ...msg, siteId: verifiedSiteId }),
                });
              }
            }
          } catch {
            // ignore malformed frame
          }
        }
      };
      socket.onclose = (ev) => {
        sockets.delete(hubSock);
        engine.handleDisconnect(hubSock, ev.reason || `closed_${ev.code}`);
      };
      return response;
    }
    return (hubWorker as { fetch(r: Request, e: unknown, c?: ExecutionContext): Promise<Response> }).fetch(req, workerEnv, ctx);
  });
}

if (typeof Deno !== 'undefined') {
  startDenoHub();
}
