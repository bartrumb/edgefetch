/**
 * Zero-dependency Turso / libSQL HTTP `/v2/pipeline` `D1Database` adapter (`hub/portable/turso-d1.ts`).
 *
 * Allows EdgeFetch's `META` and `SEARCH` (SQLite FTS5) schemas to run unchanged across stateless or multi-region
 * runtimes (Deno Deploy, Fly.io multi-region, Cloudflare, Node, Bun) using standard `fetch()`.
 */

export interface TursoD1Config {
  url: string;
  authToken?: string;
  fetchImpl?: typeof fetch;
}

type HranaArg =
  | { type: 'null' }
  | { type: 'integer'; value: string }
  | { type: 'float'; value: number }
  | { type: 'text'; value: string }
  | { type: 'blob'; base64: string };

interface HranaCol {
  name: string;
  decltype?: string | null;
}

interface HranaValue {
  type: string;
  value?: unknown;
  base64?: string;
}

interface HranaExecuteResult {
  cols: HranaCol[];
  rows: HranaValue[][];
  affected_row_count?: number;
  last_insert_rowid?: string | null;
}

function toHranaArg(v: unknown): HranaArg {
  if (v === null || v === undefined) return { type: 'null' };
  if (typeof v === 'boolean') return { type: 'integer', value: v ? '1' : '0' };
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return { type: 'integer', value: String(v) };
    return { type: 'float', value: v };
  }
  if (typeof v === 'bigint') return { type: 'integer', value: v.toString() };
  if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
    const bytes = v instanceof Uint8Array ? v : new Uint8Array(v);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
    return { type: 'blob', base64: btoa(bin) };
  }
  return { type: 'text', value: String(v) };
}

function fromHranaValue(cell: HranaValue): unknown {
  if (!cell || cell.type === 'null') return null;
  if (cell.type === 'integer') return Number(cell.value);
  if (cell.type === 'float') return Number(cell.value);
  if (cell.type === 'blob' && typeof cell.base64 === 'string') {
    const bin = atob(cell.base64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return cell.value ?? null;
}

function normalizePipelineUrl(rawUrl: string): string {
  const converted = rawUrl.trim().replace(/^libsql:\/\//i, 'https://').replace(/\/+$/, '');
  return converted.endsWith('/v2/pipeline') ? converted : `${converted}/v2/pipeline`;
}

class TursoPreparedStatement {
  private boundArgs: unknown[] = [];

  constructor(
    private readonly db: TursoHttpD1Database,
    readonly sql: string,
  ) {}

  bind(...values: unknown[]): TursoPreparedStatement {
    const clone = new TursoPreparedStatement(this.db, this.sql);
    clone.boundArgs = values;
    return clone;
  }

  toHranaStmt(): { sql: string; args: HranaArg[] } {
    return {
      sql: this.sql,
      args: this.boundArgs.map(toHranaArg),
    };
  }

  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const [res] = await this.db.executeBatch([this]);
    return res as D1Result<T>;
  }

  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return this.all<T>();
  }

  async first<T = unknown>(colName?: string): Promise<T | null> {
    const out = await this.all<Record<string, unknown>>();
    const firstRow = out.results?.[0];
    if (!firstRow) return null;
    if (colName !== undefined) return (firstRow[colName] as T) ?? null;
    return firstRow as unknown as T;
  }

  async raw<T = unknown[]>(): Promise<T[]> {
    const [rawRes] = await this.db.executeRaw([this]);
    return rawRes.rows.map((r) => r.map(fromHranaValue) as unknown as T);
  }
}

export class TursoHttpD1Database {
  private readonly pipelineUrl: string;
  private readonly authToken?: string;
  private readonly fetchFn: typeof fetch;

  constructor(cfg: TursoD1Config) {
    this.pipelineUrl = normalizePipelineUrl(cfg.url);
    this.authToken = cfg.authToken;
    this.fetchFn = cfg.fetchImpl ?? fetch;
  }

  prepare(query: string): D1PreparedStatement {
    return new TursoPreparedStatement(this, query) as unknown as D1PreparedStatement;
  }

  async executeRaw(stmts: TursoPreparedStatement[]): Promise<HranaExecuteResult[]> {
    const requests = [
      ...stmts.map((s) => ({ type: 'execute', stmt: s.toHranaStmt() })),
      { type: 'close' },
    ];
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (this.authToken) headers.authorization = `Bearer ${this.authToken}`;

    const res = await this.fetchFn(this.pipelineUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ requests }),
    });
    if (!res.ok) {
      throw new Error(`Turso HTTP pipeline failed with status ${res.status}`);
    }
    const payload = (await res.json()) as {
      results?: Array<{
        type: string;
        error?: { message?: string };
        response?: { type: string; result?: HranaExecuteResult };
      }>;
    };
    const results = payload.results ?? [];
    const out: HranaExecuteResult[] = [];
    for (let i = 0; i < stmts.length; i++) {
      const entry = results[i];
      if (!entry || entry.type === 'error') {
        throw new Error(`Turso SQL error: ${entry?.error?.message ?? 'unknown error'}`);
      }
      out.push(entry.response?.result ?? { cols: [], rows: [] });
    }
    return out;
  }

  async executeBatch(stmts: TursoPreparedStatement[]): Promise<Array<D1Result<Record<string, unknown>>>> {
    const rawResults = await this.executeRaw(stmts);
    return rawResults.map((r) => {
      const rows = r.rows.map((rowCells) => {
        const obj: Record<string, unknown> = {};
        for (let c = 0; c < r.cols.length; c++) {
          const colName = r.cols[c]?.name ?? `col_${c}`;
          obj[colName] = fromHranaValue(rowCells[c]!);
        }
        return obj;
      });
      const affected = r.affected_row_count ?? 0;
      return {
        success: true,
        results: rows,
        meta: {
          duration: 0,
          size_after: 0,
          rows_read: rows.length,
          rows_written: affected,
          last_row_id: r.last_insert_rowid ? Number(r.last_insert_rowid) : 0,
          changed_db: affected > 0,
          changes: affected,
        },
      } as unknown as D1Result<Record<string, unknown>>;
    });
  }

  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    const typed = statements as unknown as TursoPreparedStatement[];
    return (await this.executeBatch(typed)) as unknown as D1Result<T>[];
  }

  async exec(query: string): Promise<D1ExecResult> {
    const parts = query
      .split(/;\s*(?:\r?\n|$)/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (parts.length === 0) return { count: 0, duration: 0 };
    const stmts = parts.map((sql) => new TursoPreparedStatement(this, sql));
    await this.executeRaw(stmts);
    return { count: stmts.length, duration: 0 };
  }

  asD1Database(): D1Database {
    return this as unknown as D1Database;
  }
}
