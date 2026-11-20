export class WorkflowEntrypoint {}
export class DurableObject {}
export const tracing = {
  enterSpan<T>(_name: string, fn: (span: { setAttribute(k: string, v: unknown): void }) => T): T {
    return fn({ setAttribute: () => undefined });
  },
};
