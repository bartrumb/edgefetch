/**
 * Salary aggregation (`salaries` tool / `POST /v1/salaries`) — thin Cloudflare glue over Go `internal/jobs/salary.go`.
 *
 * Every `jobs` search records the employer-posted pay ranges it returned (official ATS boards) as observations in META
 * D1, keyed by posting URL. `salaries` normalizes the caller's title/location in Go, reads matching observations, and
 * aggregates them in Go (percentiles, seniority/location/company breakdowns, per-employer collapse). When data is thin
 * (or `refresh: true`), it first runs a bounded jobs search to collect fresh observations.
 */

import { callCoreWasm } from './wasm-bridge';
import type { StructuredJobRecord } from './jobs';

const SALARY_OBS_DDL =
  'CREATE TABLE IF NOT EXISTS jobs_salary_observations (' +
  'url TEXT PRIMARY KEY, title_family TEXT NOT NULL, seniority TEXT NOT NULL, company_key TEXT NOT NULL, ' +
  'location_bucket TEXT NOT NULL, currency TEXT NOT NULL, seen_at INTEGER NOT NULL, obs_json TEXT NOT NULL)';
const SALARY_OBS_INDEX_DDL =
  'CREATE INDEX IF NOT EXISTS jobs_salary_observations_family ON jobs_salary_observations (title_family, seen_at)';
/** Observations read per aggregation (most recent first). */
export const MAX_SALARY_OBSERVATIONS_READ = 2_000;
const MAX_SALARY_OBSERVATIONS_WRITE = 100;
/** Below this many matching observations, `salaries` tops up with a live jobs search (when allowed). */
export const SALARY_REFRESH_THRESHOLD = 5;
const DEFAULT_MAX_AGE_DAYS = 180;

const salaryTablesReady = new WeakSet<object>();
async function ensureSalaryTables(metaDb: D1Database): Promise<boolean> {
  const key = metaDb as unknown as object;
  if (salaryTablesReady.has(key)) return true;
  try {
    await metaDb.prepare(SALARY_OBS_DDL).run();
    await metaDb.prepare(SALARY_OBS_INDEX_DDL).run();
    salaryTablesReady.add(key);
    return true;
  } catch {
    return false;
  }
}

/** One normalized pay observation (shape owned by Go `jobs.SalaryObservation`). */
export interface SalaryObservation {
  url: string;
  titleFamily: string;
  seniority: string;
  companyKey: string;
  locationBucket: string;
  currency: string;
  seenAt: number;
  [k: string]: unknown;
}

/** Converts job records with pay into observations (Go plausibility gate) and upserts them. Best-effort. */
export async function recordSalaryObservations(
  metaDb: D1Database | undefined,
  jobs: readonly StructuredJobRecord[],
  now = Date.now(),
): Promise<number> {
  if (!metaDb || jobs.length === 0) return 0;
  const withPay = jobs.filter((j) => j && (j as { pay?: unknown }).pay).slice(0, MAX_SALARY_OBSERVATIONS_WRITE);
  if (withPay.length === 0) return 0;
  let observations: SalaryObservation[] = [];
  try {
    observations = callCoreWasm<{ observations: SalaryObservation[] }>('salary_observations', {
      jobs: withPay,
      seenAtMs: now,
    }).observations;
  } catch {
    return 0;
  }
  if (observations.length === 0 || !(await ensureSalaryTables(metaDb))) return 0;
  const stmts = observations.map((o) =>
    metaDb
      .prepare(
        `INSERT INTO jobs_salary_observations (url, title_family, seniority, company_key, location_bucket, currency, seen_at, obs_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(url) DO UPDATE SET title_family = excluded.title_family, seniority = excluded.seniority,
           company_key = excluded.company_key, location_bucket = excluded.location_bucket, currency = excluded.currency,
           seen_at = excluded.seen_at, obs_json = excluded.obs_json`,
      )
      .bind(o.url, o.titleFamily, o.seniority, o.companyKey, o.locationBucket, o.currency, o.seenAt, JSON.stringify(o)),
  );
  try {
    await metaDb.batch(stmts);
    return observations.length;
  } catch {
    return 0;
  }
}

async function readSalaryObservations(
  metaDb: D1Database,
  titleFamily: string,
  sinceMs: number,
): Promise<SalaryObservation[]> {
  if (!(await ensureSalaryTables(metaDb))) return [];
  const rows = await metaDb
    .prepare(
      'SELECT obs_json FROM jobs_salary_observations WHERE title_family = ? AND seen_at >= ? ORDER BY seen_at DESC LIMIT ?',
    )
    .bind(titleFamily, sinceMs, MAX_SALARY_OBSERVATIONS_READ)
    .all<{ obs_json: string }>()
    .catch(() => null);
  const out: SalaryObservation[] = [];
  for (const r of rows?.results ?? []) {
    try {
      const parsed = JSON.parse(r.obs_json) as SalaryObservation;
      if (parsed && typeof parsed.url === 'string') out.push(parsed);
    } catch {
      // skip corrupt rows; Go re-validates every row anyway
    }
  }
  return out;
}

export interface SalariesToolPayload {
  title?: string;
  location?: string;
  seniority?: string;
  company?: string;
  currency?: string;
  basis?: 'base' | 'total' | 'ote' | 'all';
  maxAgeDays?: number;
  /** Run a live jobs search first to collect fresh observations (also automatic when data is thin). */
  refresh?: boolean;
}

/**
 * Executes a salary aggregation. `runJobsSearch` (optional) performs a bounded jobs search whose results are recorded
 * by the jobs tool itself; it is used for `refresh` or when fewer than `SALARY_REFRESH_THRESHOLD` observations match.
 */
export async function executeSalariesCall(params: {
  payload: SalariesToolPayload;
  env: { META?: D1Database };
  runJobsSearch?: (args: { query: string; locations?: string[]; company?: string }) => Promise<unknown>;
  now?: number;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const { payload, env } = params;
  const title = typeof payload.title === 'string' ? payload.title.trim().slice(0, 200) : '';
  if (!title) {
    return { status: 400, body: { ok: false, error: 'missing_title', message: 'salaries requires `title` (e.g. "Senior Software Engineer").' } };
  }
  if (!env.META) {
    return { status: 503, body: { ok: false, error: 'storage_unavailable', message: 'Salary observations need the META D1 binding.' } };
  }
  const location = typeof payload.location === 'string' ? payload.location.trim().slice(0, 200) : '';
  const matched = callCoreWasm<{ titleFamily: string; seniority: string; locationBucket: string }>('salary_match_query', {
    title,
    location,
  });
  if (!matched.titleFamily) {
    return { status: 400, body: { ok: false, error: 'unrecognized_title', message: `Could not normalize title "${title}".` } };
  }
  const now = params.now ?? Date.now();
  const maxAgeDays =
    typeof payload.maxAgeDays === 'number' && Number.isFinite(payload.maxAgeDays) && payload.maxAgeDays > 0
      ? Math.min(730, Math.floor(payload.maxAgeDays))
      : DEFAULT_MAX_AGE_DAYS;
  const sinceMs = now - maxAgeDays * 24 * 60 * 60 * 1000;
  const query = {
    titleFamily: matched.titleFamily,
    ...(payload.seniority ? { seniority: String(payload.seniority) } : matched.seniority ? { seniority: matched.seniority } : {}),
    ...(matched.locationBucket ? { locationBucket: matched.locationBucket } : {}),
    ...(payload.company ? { company: String(payload.company).slice(0, 120) } : {}),
    ...(payload.currency ? { currency: String(payload.currency).toUpperCase().slice(0, 3) } : {}),
    ...(payload.basis ? { basis: payload.basis } : {}),
    maxAgeDays,
    nowMs: now,
  };
  const aggregate = (observations: SalaryObservation[]) =>
    callCoreWasm<Record<string, unknown> & { matched: number }>('salary_aggregate', { observations, query });

  let observations = await readSalaryObservations(env.META, matched.titleFamily, sinceMs);
  let report = aggregate(observations);
  let refreshed = false;
  if (params.runJobsSearch && (payload.refresh === true || report.matched < SALARY_REFRESH_THRESHOLD)) {
    try {
      await params.runJobsSearch({
        query: title,
        ...(location ? { locations: [location] } : {}),
        ...(payload.company ? { company: String(payload.company) } : {}),
      });
      refreshed = true;
      observations = await readSalaryObservations(env.META, matched.titleFamily, sinceMs);
      report = aggregate(observations);
    } catch {
      // keep the stored-data report
    }
  }
  return {
    status: 200,
    body: {
      ok: true,
      ...report,
      refreshed,
      source: 'employer-posted pay ranges from official ATS job boards seen by EdgeFetch jobs searches',
    },
  };
}
