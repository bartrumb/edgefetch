export class WorkflowEntrypoint {}
export class DurableObject {}
export const tracing = {
  enterSpan(_name: string, fn: (span: { setAttribute(k: string, v: unknown): void }) => unknown): unknown {
    return fn({ setAttribute: () => undefined });
  },
};
