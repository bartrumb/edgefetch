import prodWorker, { AgentHubDO as ProdAgentHubDO } from '../src/index.ts';

export class AgentHubDO extends ProdAgentHubDO {
  async __testSql(query: string): Promise<unknown[]> {
    return this.ctx.storage.sql.exec(query).toArray();
  }

  async __testAbort(): Promise<void> {
    (this.ctx as unknown as { abort(reason?: string): void }).abort('test_do_reset');
  }

  async __testSeedHosts(count: number): Promise<void> {
    const base = Date.now() + 2_000;
    for (let i = 0; i < count; i++) {
      await this.waitForHostWindow([`h${i}.example.com`], 0, base + 60_000);
      this.ctx.storage.sql.exec(
        'INSERT OR REPLACE INTO host_windows (host, next_allowed_at) VALUES (?, ?)',
        `raw-${i}.example.com`,
        base + i,
      );
    }
  }
}

export default {
  async fetch(request: Request, env: Record<string, unknown>, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const ns = env.AGENT_HUB as DurableObjectNamespace<AgentHubDO>;
    if (url.pathname === '/__test_sql' && request.method === 'POST') {
      const q = await request.text();
      const stub = ns.get(ns.idFromName('global'));
      return Response.json(await stub.__testSql(q));
    }
    if (url.pathname === '/__test_abort') {
      const stub = ns.get(ns.idFromName('global'));
      await stub.__testAbort().catch(() => undefined);
      return Response.json({ aborted: true });
    }
    return (prodWorker as { fetch(req: Request, e: unknown, c?: unknown): Promise<Response> }).fetch(request, env, ctx);
  },
};
