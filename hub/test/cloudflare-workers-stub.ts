export class WorkflowEntrypoint<Env = unknown, Params = unknown> {
  protected ctx: unknown;
  protected env: Env;
  constructor(ctx?: unknown, env?: Env) {
    this.ctx = ctx;
    this.env = env as Env;
  }
}

export class DurableObject<Env = unknown> {
  protected ctx: unknown;
  protected env: Env;
  constructor(ctx?: unknown, env?: Env) {
    this.ctx = ctx;
    this.env = env as Env;
  }
}

export const tracing = {
  enterSpan(_name: string, fn: (span: { setAttribute(k: string, v: unknown): void }) => unknown): unknown {
    return fn({ setAttribute: () => undefined });
  },
};
