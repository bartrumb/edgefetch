/**
 * Idempotent D1 column migrations that do not emit Cloudflare Observability error spans.
 *
 * Kept dependency-free so auth/admin modules can use it without importing search-index.ts.
 */

export interface D1PragmaStatementLike {
  all?: <T = Record<string, unknown>>() => Promise<{ results?: T[] }>;
  run?: () => Promise<unknown>;
  bind?: (...values: unknown[]) => {
    all?: <T = Record<string, unknown>>() => Promise<{ results?: T[] }>;
    run?: () => Promise<unknown>;
  };
}

export interface D1SchemaInspectableDb {
  prepare(query: string): D1PragmaStatementLike;
}

const d1ColumnVerifiedByTarget = new Map<string, WeakSet<object>>();

/**
 * Inspects `PRAGMA table_info(<table>)` before running `ALTER TABLE <table> ADD COLUMN <col> ...` so cold Worker
 * isolates never emit `d1_run ERROR: duplicate column name: ...: SQLITE_ERROR` spans in Cloudflare Observability.
 */
export async function ensureD1ColumnIfMissing(params: {
  db: D1SchemaInspectableDb;
  table: string;
  column: string;
  alterSql: string;
  cacheSet?: WeakSet<object>;
}): Promise<boolean> {
  const { db, table, column, alterSql } = params;
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(column)) {
    throw new Error(`Invalid SQLite identifier: ${table}.${column}`);
  }
  const mapKey = `${table}.${column}`;
  let verified = params.cacheSet ?? d1ColumnVerifiedByTarget.get(mapKey);
  if (!verified) {
    verified = new WeakSet<object>();
    if (!params.cacheSet) d1ColumnVerifiedByTarget.set(mapKey, verified);
  }
  const dbObj = db as unknown as object;
  if (verified.has(dbObj)) return false;

  const stmt = db.prepare(`PRAGMA table_info(${table})`);
  const allFn = typeof stmt.all === 'function' ? stmt.all.bind(stmt) : null;
  const bindFn = typeof stmt.bind === 'function' ? stmt.bind.bind(stmt) : null;
  const queryAll = allFn
    ? () => allFn<{ name?: unknown }>()
    : bindFn
      ? () => {
          const bound = bindFn();
          return typeof bound.all === 'function' ? bound.all<{ name?: unknown }>() : null;
        }
      : null;
  if (!queryAll) {
    verified.add(dbObj);
    return false;
  }

  let cols: Array<{ name?: unknown }> = [];
  try {
    const res = await queryAll();
    cols = Array.isArray(res?.results) ? res.results : [];
  } catch {
    cols = [];
  }

  if (cols.length === 0) {
    verified.add(dbObj);
    return false;
  }

  const wantLower = column.toLowerCase();
  const hasColumn = cols.some((c) => typeof c?.name === 'string' && c.name.trim().toLowerCase() === wantLower);
  if (!hasColumn) {
    try {
      const alterStmt = db.prepare(alterSql);
      if (typeof alterStmt.run === 'function') {
        await alterStmt.run();
      } else if (typeof alterStmt.bind === 'function') {
        await alterStmt.bind().run?.();
      }
      verified.add(dbObj);
      return true;
    } catch {
      // Ignore concurrent isolate race if another isolate added the column simultaneously
    }
  }

  verified.add(dbObj);
  return false;
}

const d1TableColumnsVerified = new Map<string, WeakSet<object>>();

/**
 * Multi-column variant of {@link ensureD1ColumnIfMissing}: one `PRAGMA table_info` read, then `ALTER TABLE ... ADD
 * COLUMN` only for columns that are actually absent, so steady-state cold starts and sign-ins emit zero
 * `duplicate column name` error spans. Verified (db, table, column-set) triples are cached per isolate.
 *
 * When the PRAGMA cannot be read (binding without `.all()`, query failure, or an empty result) it falls back to the
 * legacy best-effort behaviour of attempting every ALTER and ignoring failures, so it never under-migrates.
 * Returns the columns it added (or attempted, in fallback mode).
 */
export async function ensureD1ColumnsIfMissing(params: {
  db: D1SchemaInspectableDb;
  table: string;
  columns: ReadonlyArray<{ column: string; alterSql: string }>;
}): Promise<string[]> {
  const { db, table, columns } = params;
  const ident = /^[A-Za-z_][A-Za-z0-9_]*$/;
  if (!ident.test(table) || columns.some((c) => !ident.test(c.column))) {
    throw new Error(`Invalid SQLite identifier in ${table}`);
  }
  const cacheKey = `${table}:${columns.map((c) => c.column).join(',')}`;
  let verified = d1TableColumnsVerified.get(cacheKey);
  if (!verified) {
    verified = new WeakSet<object>();
    d1TableColumnsVerified.set(cacheKey, verified);
  }
  const dbObj = db as unknown as object;
  if (verified.has(dbObj)) return [];

  const runAlter = async (sql: string): Promise<boolean> => {
    try {
      const stmt = db.prepare(sql);
      if (typeof stmt.run === 'function') await stmt.run();
      else if (typeof stmt.bind === 'function') await stmt.bind().run?.();
      return true;
    } catch {
      // Concurrent isolate already added it (or legacy fallback on an existing column).
      return false;
    }
  };

  let existing: Set<string> | null = null;
  try {
    const stmt = db.prepare(`PRAGMA table_info(${table})`);
    const res =
      typeof stmt.all === 'function'
        ? await stmt.all<{ name?: unknown }>()
        : typeof stmt.bind === 'function'
          ? await stmt.bind().all?.<{ name?: unknown }>()
          : undefined;
    const rows = Array.isArray(res?.results) ? res.results : [];
    if (rows.length > 0) {
      existing = new Set(
        rows.map((r) => (typeof r?.name === 'string' ? r.name.trim().toLowerCase() : '')).filter(Boolean),
      );
    }
  } catch {
    existing = null;
  }

  const added: string[] = [];
  for (const { column, alterSql } of columns) {
    if (existing?.has(column.toLowerCase())) continue;
    await runAlter(alterSql);
    added.push(column);
  }
  verified.add(dbObj);
  return added;
}
