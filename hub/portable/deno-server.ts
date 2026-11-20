/**
 * Deno Deploy Edge Hub Entrypoint (`hub/portable/deno-server.ts`).
 *
 * Bridges EdgeFetch's standard Web `fetch` Worker (`hub/src/index.ts`), `Deno.upgradeWebSocket` for outbound Go
 * `/agent/ws` nodes, `BroadcastChannel('edgefetch-hub-bus')` for cross-region isolate dispatch notifications, and
 * optional `TursoHttpD1Database` + `S3ArtifactBucket` storage bindings.
 */
import { AgentHubEngine, createMemoryHostWindowStore, type CooldownStore, type HubSocketLike } from '../src/agent-hub.ts';
import { authorizeAgent } from '../src/auth.ts';
import hubWorker from '../src/index.ts';
import { S3ArtifactBucket } from './s3-bucket.ts';
import { TursoHttpD1Database } from './turso-d1.ts';

declare const Deno: {
  env: { get(key: string): string | undefined; toObject(): Record<string, string> };
  serve(
    options: { port?: number; hostname?: string },
    handler: (req: Request, info: { remoteAddr?: { hostname?: string } }) => Response | Promise<Response>,
  ): unknown;
  upgradeWebSocket(req: Request): { socket: WebSocket; response: Response };
};

class MemoryCooldownStore implements CooldownStore {
  private readonly map = new Map<string, number>();
  get(key: string): number | undefined {
    const v = this.map.get(key);
    if (v !== undefined && v <= Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    return v;
  }
  set(key: string, untilEpochMs: number): void {
    this.map.set(key, untilEpochMs);
  }
  delete(key: string): void {
    this.map.delete(key);
  }
  entries(): IterableIterator<[string, number]> {
    return this.map.entries();
  }
}

class DenoHubSocket implements HubSocketLike {
  private attachment: unknown = null;
  constructor(readonly raw: WebSocket) {}
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
  serializeAttachment(value: unknown): void {
    this.attachment = structuredClone(value);
  }
  deserializeAttachment(): unknown {
    return this.attachment ? structuredClone(this.attachment) : null;
  }
}

export function startDenoHub() {
  const envMap = Deno.env.toObject();
  const sockets = new Set<DenoHubSocket>();
  const engine = new AgentHubEngine(() => Array.from(sockets), new MemoryCooldownStore(), createMemoryHostWindowStore());
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

  const stub = {
    async listAgents() {
      return engine.listAgents();
    },
    async routeFetch(bodyText: string, siteFilter?: string, artifactSpec?: unknown) {
      return engine.routeFetch(bodyText, siteFilter, artifactSpec as never);
    },
    async validateArtifactUpload(input: unknown) {
      return engine.validateArtifactUpload(input as never);
    },
    async completeJob(jobId: string, nonce: string, siteId: string, bodyText: string) {
      return engine.completeJob(jobId, nonce, siteId, bodyText);
    },
    async failJob(jobId: string, nonce: string, siteId: string, reason: string, message?: string) {
      return engine.failJob(jobId, nonce, siteId, reason, message);
    },
    async listActivity(filter?: unknown) {
      return { events: [], summary: { totalEvents: 0 }, filter };
    },
    async recordActivity() {
      // Stateless edge memory mode
    },
  };

  const workerEnv: Record<string, unknown> = {
    ...envMap,
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
        return Response.json({ error: 'unauthorized', message: auth.reason }, { status: auth.status });
      }
      const { socket, response } = Deno.upgradeWebSocket(req);
      const hubSock = new DenoHubSocket(socket);
      socket.onopen = () => {
        sockets.add(hubSock);
        engine.registerSocket(hubSock, {
          siteId: auth.siteId,
          version: req.headers.get('x-agent-version')?.slice(0, 64) || 'unknown',
          arch: req.headers.get('x-agent-arch')?.slice(0, 32) || 'unknown',
          publicIp: info.remoteAddr?.hostname || 'unknown',
          capabilitiesHeader: req.headers.get('x-agent-capabilities') ?? undefined,
        });
      };
      socket.onmessage = (ev) => {
        if (typeof ev.data === 'string') {
          if (ev.data === 'ping') {
            socket.send('pong');
            return;
          }
          engine.handleSocketMessage(hubSock, ev.data);
        }
      };
      socket.onclose = () => {
        sockets.delete(hubSock);
        engine.handleSocketClose(hubSock);
      };
      return response;
    }
    return (hubWorker as { fetch(r: Request, e: unknown, c?: ExecutionContext): Promise<Response> }).fetch(req, workerEnv, ctx);
  });
}

if (typeof Deno !== 'undefined') {
  startDenoHub();
}
