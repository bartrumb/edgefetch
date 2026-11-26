import assert from 'node:assert/strict';

/**
 * Shared CPU-budget helpers for regression tests that guard against superlinear (e.g. quadratic) blowups.
 *
 * These budgets exist to catch order-of-magnitude regressions (a 30 ms scan turning into 3 s), not to
 * benchmark. A single wall-clock sample on a shared CI runner, or under `--test-concurrency=2`, routinely
 * lands a few ms over a tight limit, so:
 *   - every check takes the best of up to `maxRuns` samples, stopping as soon as one fits the budget
 *     (noise passes on a retry; a real blowup fails every sample), and
 *   - every budget is multiplied by one shared `PERF_SCALE` instead of per-file ad-hoc multipliers.
 *
 * Override with `EDGEFETCH_PERF_SCALE=<n>` (e.g. `1` to check the raw budgets locally).
 */
export const PERF_SCALE: number = (() => {
  const fromEnv = Number(process.env.EDGEFETCH_PERF_SCALE);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return fromEnv;
  if (process.env.NODE_V8_COVERAGE) return 4;
  if (process.env.CI) return 3;
  return 1.5;
})();

const DEFAULT_MAX_RUNS = 5;

function formatFailure(label: string, bestMs: number, budgetMs: number, baseBudgetMs: number, runs: number): string {
  return (
    `${label}: best of ${runs} run(s) took ${bestMs.toFixed(1)}ms, budget ${budgetMs.toFixed(0)}ms ` +
    `(${baseBudgetMs}ms x PERF_SCALE ${PERF_SCALE})`
  );
}

/**
 * Runs `fn` up to `maxRuns` times and asserts the fastest sample is under `baseBudgetMs * PERF_SCALE`.
 * Returns the last result of `fn` so callers can also assert on output.
 */
export function assertFastSync<T>(label: string, baseBudgetMs: number, fn: () => T, maxRuns = DEFAULT_MAX_RUNS): T {
  const budgetMs = baseBudgetMs * PERF_SCALE;
  let best = Infinity;
  let runs = 0;
  let result!: T;
  while (runs < maxRuns) {
    const t0 = performance.now();
    result = fn();
    best = Math.min(best, performance.now() - t0);
    runs++;
    if (best < budgetMs) break;
  }
  assert.ok(best < budgetMs, formatFailure(label, best, budgetMs, baseBudgetMs, runs));
  return result;
}

/**
 * Like {@link assertFastSync} but the budget is NOT multiplied by `PERF_SCALE`: it only retries (best of up to
 * `maxRuns` samples) against the exact `budgetMs`. Use it where the budget already has generous headroom over
 * typical runs and only single-sample noise needs absorbing, so the threshold itself stays unchanged.
 */
export function assertFastUnscaledSync<T>(label: string, budgetMs: number, fn: () => T, maxRuns = DEFAULT_MAX_RUNS): T {
  let best = Infinity;
  let runs = 0;
  let result!: T;
  while (runs < maxRuns) {
    const t0 = performance.now();
    result = fn();
    best = Math.min(best, performance.now() - t0);
    runs++;
    if (best < budgetMs) break;
  }
  assert.ok(best < budgetMs, `${label}: best of ${runs} run(s) took ${best.toFixed(1)}ms, budget ${budgetMs}ms (unscaled)`);
  return result;
}

/** Async variant of {@link assertFastSync}. */
export async function assertFastAsync<T>(
  label: string,
  baseBudgetMs: number,
  fn: () => Promise<T>,
  maxRuns = DEFAULT_MAX_RUNS,
): Promise<T> {
  const budgetMs = baseBudgetMs * PERF_SCALE;
  let best = Infinity;
  let runs = 0;
  let result!: T;
  while (runs < maxRuns) {
    const t0 = performance.now();
    result = await fn();
    best = Math.min(best, performance.now() - t0);
    runs++;
    if (best < budgetMs) break;
  }
  assert.ok(best < budgetMs, formatFailure(label, best, budgetMs, baseBudgetMs, runs));
  return result;
}
