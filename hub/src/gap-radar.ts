/**
 * Telemetry-Driven Adapter Gap Radar (`GET /v1/hosts/gaps` & `/admin` Gap Radar panel).
 *
 * Queries `META` D1 (`fetches` indexed by `fetches_time_idx`) to rank origin hosts burning headless browser time
 * (`request_id = 'auto-render-1'` / `ext-auto-*`) or experiencing elevated non-OK fetch rates, cross-referenced
 * against `listRegisteredAdapters()` so operators and contributors can target the highest-ROI domains first.
 */

import { listRegisteredAdapters, type AdapterCatalogEntry } from './extractors/registry';

export interface HostGapCandidate {
  host: string;
  totalFetches: number;
  browserFallbacks: number;
  browserSharePct: number;
  browserMsTotal: number;
  nonOkCount: number;
  avgDurationMs: number;
  lastSeenAt: number;
  hasAdapter: boolean;
  matchedAdapterId?: string;
  proposeCommand?: string;
}

export interface HostGapRadarResponse {
  ok: true;
  configured: boolean;
  windowDays: number;
  sinceMs: number;
  hosts: HostGapCandidate[];
  note?: string;
}

const SAFE_HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;

function matchesCatalogPattern(hostLower: string, rawPattern: string): boolean {
  const pat = rawPattern.trim().toLowerCase().replace(/\.+$/, '');
  if (!pat) return false;
  if (!pat.includes('*')) return hostLower === pat;
  if (pat.startsWith('*.') && !pat.slice(2).includes('*')) {
    const suf = pat.slice(2);
    return hostLower !== suf && hostLower.endsWith(`.${suf}`);
  }
  if (pat.endsWith('.*') && !pat.slice(0, -2).includes('*')) {
    const pre = pat.slice(0, -2);
    return hostLower.startsWith(`${pre}.`) && hostLower.length > pre.length + 1;
  }
  const star = pat.indexOf('*');
  if (star > 0 && pat.lastIndexOf('*') === star) {
    const head = pat.slice(0, star);
    const tail = pat.slice(star + 1);
    return hostLower.startsWith(head) && hostLower.endsWith(tail) && hostLower.length > head.length + tail.length;
  }
  return false;
}

export function matchHostAgainstRegisteredAdapters(
  rawHost: string,
  catalog?: readonly AdapterCatalogEntry[],
): { hasAdapter: boolean; matchedAdapterId?: string } {
  const host = rawHost.trim().toLowerCase().replace(/\.+$/, '');
  if (!host) return { hasAdapter: false };
  const entries = catalog ?? listRegisteredAdapters();
  // Prefer exact-domain matches first, then wildcard matches.
  for (const entry of entries) {
    for (const dom of entry.domains) {
      if (!dom.includes('*') && dom.trim().toLowerCase() === host) {
        return { hasAdapter: true, matchedAdapterId: entry.id };
      }
    }
  }
  for (const entry of entries) {
    for (const dom of entry.domains) {
      if (dom.includes('*') && matchesCatalogPattern(host, dom)) {
        return { hasAdapter: true, matchedAdapterId: entry.id };
      }
    }
  }
  return { hasAdapter: false };
}

export async function queryHostGapRadar(params: {
  metaDb?: D1Database;
  days?: number;
  limit?: number;
  onlyUnadapted?: boolean;
  now?: number;
}): Promise<HostGapRadarResponse> {
  const now = typeof params.now === 'number' && Number.isFinite(params.now) ? params.now : Date.now();
  const rawDays = typeof params.days === 'number' && Number.isFinite(params.days) ? params.days : 7;
  const windowDays = Math.max(1, Math.min(90, Math.floor(rawDays)));
  const rawLimit = typeof params.limit === 'number' && Number.isFinite(params.limit) ? params.limit : 25;
  const limit = Math.max(1, Math.min(100, Math.floor(rawLimit)));
  const sinceMs = now - windowDays * 24 * 60 * 60_000;

  if (!params.metaDb) {
    return {
      ok: true,
      configured: false,
      windowDays,
      sinceMs,
      hosts: [],
      note: 'META D1 database is not configured on this Hub instance.',
    };
  }

  const sqlLimit = params.onlyUnadapted ? Math.min(250, limit * 3) : limit;
  let rows: Array<Record<string, unknown>> = [];
  try {
    const stmt = params.metaDb
      .prepare(
        `SELECT
           final_host,
           COUNT(*) AS total_fetches,
           SUM(CASE WHEN request_id = 'auto-render-1' OR request_id LIKE 'ext-auto-%' THEN 1 ELSE 0 END) AS browser_fallbacks,
           SUM(CASE WHEN request_id = 'auto-render-1' OR request_id LIKE 'ext-auto-%' THEN COALESCE(duration_ms, 0) ELSE 0 END) AS browser_ms_total,
           SUM(CASE WHEN outcome != 'ok' AND status NOT IN (404, 410) THEN 1 ELSE 0 END) AS non_ok_count,
           AVG(COALESCE(duration_ms, 0)) AS avg_duration_ms,
           MAX(fetched_at) AS last_seen_at
         FROM fetches
         WHERE fetched_at >= ?1 AND final_host != ''
         GROUP BY final_host
         HAVING browser_fallbacks > 0 OR non_ok_count >= 2
         ORDER BY browser_ms_total DESC, browser_fallbacks DESC, non_ok_count DESC, total_fetches DESC
         LIMIT ?2`,
      )
      .bind(sinceMs, sqlLimit);
    const res = await stmt.all<Record<string, unknown>>();
    rows = Array.isArray(res?.results) ? res.results : [];
  } catch {
    return {
      ok: true,
      configured: true,
      windowDays,
      sinceMs,
      hosts: [],
      note: 'META D1 fetches table is empty or awaiting initial migration.',
    };
  }

  const catalog = listRegisteredAdapters();
  const candidates: HostGapCandidate[] = [];

  for (const row of rows) {
    const rawHost = typeof row.final_host === 'string' ? row.final_host.trim().toLowerCase().replace(/\.+$/, '') : '';
    if (!rawHost || !SAFE_HOSTNAME_RE.test(rawHost) || !rawHost.includes('.')) continue;

    const match = matchHostAgainstRegisteredAdapters(rawHost, catalog);
    if (params.onlyUnadapted && match.hasAdapter) continue;

    const totalFetches = Math.max(0, Math.round(Number(row.total_fetches ?? 0)));
    const browserFallbacks = Math.max(0, Math.round(Number(row.browser_fallbacks ?? 0)));
    const browserMsTotal = Math.max(0, Math.round(Number(row.browser_ms_total ?? 0)));
    const nonOkCount = Math.max(0, Math.round(Number(row.non_ok_count ?? 0)));
    const avgDurationMs = Math.max(0, Math.round(Number(row.avg_duration_ms ?? 0)));
    const lastSeenAt = Math.max(0, Math.round(Number(row.last_seen_at ?? 0)));
    const browserSharePct = totalFetches > 0 ? Math.min(100, Math.round((browserFallbacks / totalFetches) * 1000) / 10) : 0;

    candidates.push({
      host: rawHost,
      totalFetches,
      browserFallbacks,
      browserSharePct,
      browserMsTotal,
      nonOkCount,
      avgDurationMs,
      lastSeenAt,
      hasAdapter: match.hasAdapter,
      ...(match.matchedAdapterId ? { matchedAdapterId: match.matchedAdapterId } : {}),
      ...(!match.hasAdapter
        ? { proposeCommand: `npm --prefix hub run adapter:propose -- https://${rawHost}` }
        : {}),
    });
    if (candidates.length >= limit) break;
  }

  return {
    ok: true,
    configured: true,
    windowDays,
    sinceMs,
    hosts: candidates,
  };
}
