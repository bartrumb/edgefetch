/**
 * Company profile (`company` tool / `POST /v1/company`) — thin Cloudflare orchestration over Go `internal/company`.
 *
 * Go plans the fetches, picks and corroborates the Wikidata entity against the company domain, derives SEC / GitHub
 * follow-ups, parses every source and merges them with per-field attribution. This module only runs the fetches:
 * homepage/about pages through the hub's own `scrape` (robots + politeness), public JSON APIs (Wikidata, SEC EDGAR,
 * GitHub) through the SSRF-safe public fetch, the ATS board summary through the `jobs` tool, and — when the caller has
 * Google's official Maps MCP connected — a `search_places` call for headquarters details.
 */

import { callCoreWasm } from './wasm-bridge';

export interface CompanyToolPayload {
  name?: string;
  domain?: string;
  /** Include the ATS hiring summary (default true). */
  includeHiring?: boolean;
  /** Include Google Maps place details when a Maps MCP is connected (default true). */
  includePlaces?: boolean;
}

interface PlanRequest {
  id: string;
  url: string;
  method: 'GET';
  kind: 'html' | 'json';
  optional?: boolean;
}

interface PlanOutput {
  name?: string;
  domain?: string;
  searchTerm?: string;
  githubSlug?: string;
  requests: PlanRequest[];
}

interface EntityFollowups {
  qid?: string;
  cik?: string;
  secSubmissionsUrl?: string;
  secCompanyFactsUrl?: string;
  labelIds?: string[];
  labelsUrl?: string;
  homepageUrl?: string;
  githubOrgUrl?: string;
}

interface PageSource {
  url: string;
  finalUrl?: string;
  title?: string;
  description?: string;
  siteName?: string;
  html?: string;
}

/** Overall wall budget for one profile (MCP clients give up at 60 s). */
export const COMPANY_WALL_BUDGET_MS = 35_000;
const JSON_FETCH_TIMEOUT_MS = 12_000;
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_HTML_BYTES = 4 * 1024 * 1024;

export interface CompanyDeps {
  /** Hub scrape of a page; must return the raw HTML (`rawHtml`/`html`) plus metadata. */
  scrapePage: (url: string) => Promise<{ status: number; body: Record<string, unknown> }>;
  /** SSRF-safe public fetch for JSON APIs. */
  fetchFn: typeof fetch;
  /** Company-scoped jobs search (the jobs tool), used for the hiring summary. */
  runJobs?: (args: { company: string; domains?: string[]; limit: number }) => Promise<{ status: number; body: Record<string, unknown> }>;
  /** Calls a tool on the caller's connected Google Maps MCP; resolves to the raw text result or null when unavailable. */
  callMapsPlaces?: (query: string) => Promise<string | null>;
  userAgent?: string;
}

async function readTextBounded(resp: Response, maxBytes: number): Promise<string> {
  const len = Number(resp.headers.get('content-length') ?? '0');
  if (len > maxBytes) {
    await resp.body?.cancel().catch(() => undefined);
    throw new Error('response_too_large');
  }
  const reader = resp.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error('response_too_large');
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

async function fetchJsonText(deps: CompanyDeps, url: string, deadlineAt: number): Promise<string | null> {
  const remaining = deadlineAt - Date.now();
  if (remaining < 1_000) return null;
  try {
    const resp = await deps.fetchFn(url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'user-agent': deps.userAgent ?? 'EdgeFetch-Company-Profile/2.8 (+https://github.com/bartrumb/edgefetch)',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(Math.min(JSON_FETCH_TIMEOUT_MS, remaining)),
    });
    if (!resp.ok) {
      await resp.body?.cancel().catch(() => undefined);
      return null;
    }
    return await readTextBounded(resp, MAX_JSON_BYTES);
  } catch {
    return null;
  }
}

async function fetchPage(deps: CompanyDeps, url: string, deadlineAt: number): Promise<PageSource | null> {
  if (deadlineAt - Date.now() < 2_000) return null;
  try {
    const res = await deps.scrapePage(url);
    if (res.status !== 200 || res.body?.ok === false) return null;
    const b = res.body;
    const meta = (b.metadata && typeof b.metadata === 'object' ? b.metadata : {}) as Record<string, unknown>;
    const html = typeof b.rawHtml === 'string' ? b.rawHtml : typeof b.html === 'string' ? b.html : '';
    return {
      url,
      ...(typeof b.finalUrl === 'string' ? { finalUrl: b.finalUrl } : {}),
      ...(typeof b.title === 'string' ? { title: b.title } : {}),
      ...(typeof meta.description === 'string' ? { description: meta.description } : {}),
      ...(typeof meta.siteName === 'string' ? { siteName: meta.siteName } : {}),
      ...(html ? { html: html.slice(0, MAX_HTML_BYTES) } : {}),
    };
  } catch {
    return null;
  }
}

function summarizeHiring(body: Record<string, unknown>): Record<string, unknown> | null {
  const jobs = Array.isArray(body.jobs) ? (body.jobs as Array<Record<string, unknown>>) : [];
  if (jobs.length === 0) return null;
  const boardUrls = new Set<string>();
  const locations = new Map<string, number>();
  const departments = new Map<string, number>();
  let platform = '';
  for (const j of jobs) {
    if (!platform && typeof j.source === 'string') platform = j.source;
    if (typeof j.url === 'string') {
      try {
        const u = new URL(j.url);
        const seg = u.pathname.split('/').filter(Boolean)[0];
        boardUrls.add(`${u.origin}/${seg ?? ''}`.replace(/\/$/, ''));
      } catch {
        // ignore
      }
    }
    for (const l of Array.isArray(j.locations) ? (j.locations as unknown[]) : []) {
      if (typeof l === 'string' && l) locations.set(l, (locations.get(l) ?? 0) + 1);
    }
    const dept = typeof j.department === 'string' ? j.department : '';
    if (dept) departments.set(dept, (departments.get(dept) ?? 0) + 1);
  }
  const top = (m: Map<string, number>) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k]) => k);
  const total = typeof body.count === 'number' ? body.count : jobs.length;
  return {
    boardUrls: [...boardUrls].slice(0, 5),
    platform,
    openRoles: total,
    departments: top(departments),
    locations: top(locations),
    sampleRoles: jobs.slice(0, 8).map((j) => String(j.title ?? '')).filter(Boolean),
  };
}

const PLACES_TEXT_SEARCH_URL = 'https://places.googleapis.com/v1/places:searchText';
const PLACES_FIELD_MASK = [
  'places.displayName',
  'places.formattedAddress',
  'places.location',
  'places.googleMapsUri',
  'places.nationalPhoneNumber',
  'places.internationalPhoneNumber',
  'places.rating',
  'places.userRatingCount',
  'places.websiteUri',
  'places.types',
].join(',');

/**
 * Google Places API (New) Text Search with the hub's own `GOOGLE_MAPS_API_KEY` (admin-managed secret). Used by the
 * `company` tool when the caller has no Google Maps MCP connected. Returns the raw `{places:[...]}` JSON text (the
 * shape Go `company.Merge` parses), or null on any failure. Billed to the key's Google Cloud project.
 */
export async function searchPlacesWithApiKey(params: {
  apiKey: string;
  query: string;
  fetchFn: typeof fetch;
  timeoutMs?: number;
}): Promise<string | null> {
  const query = params.query.trim().slice(0, 300);
  if (!query || !params.apiKey.trim()) return null;
  try {
    const resp = await params.fetchFn(PLACES_TEXT_SEARCH_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-goog-api-key': params.apiKey.trim(),
        'x-goog-fieldmask': PLACES_FIELD_MASK,
      },
      body: JSON.stringify({ textQuery: query, pageSize: 5 }),
      signal: AbortSignal.timeout(params.timeoutMs ?? 10_000),
    });
    if (!resp.ok) {
      await resp.body?.cancel().catch(() => undefined);
      return null;
    }
    const text = await readTextBounded(resp, 2 * 1024 * 1024);
    return text || null;
  } catch {
    return null;
  }
}

export async function executeCompanyCall(params: {
  payload: CompanyToolPayload;
  deps: CompanyDeps;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const { payload, deps } = params;
  const name = typeof payload.name === 'string' ? payload.name.trim().slice(0, 200) : '';
  const domain = typeof payload.domain === 'string' ? payload.domain.trim().slice(0, 253) : '';
  if (!name && !domain) {
    return { status: 400, body: { ok: false, error: 'missing_company', message: 'company requires `name` and/or `domain`.' } };
  }
  let plan: PlanOutput;
  try {
    plan = callCoreWasm<PlanOutput>('company_plan', { ...(name ? { name } : {}), ...(domain ? { domain } : {}) });
  } catch (e) {
    return { status: 400, body: { ok: false, error: 'invalid_company', message: e instanceof Error ? e.message : String(e) } };
  }
  const deadlineAt = Date.now() + COMPANY_WALL_BUDGET_MS;
  const byId = new Map(plan.requests.map((r) => [r.id, r]));
  const companyName = plan.name ?? name;

  // Hiring summary runs alongside everything else (it has its own 40 s budget; ours caps the wait).
  const hiringPromise =
    payload.includeHiring !== false && deps.runJobs && (companyName || plan.domain)
      ? deps
          .runJobs({ company: companyName || (plan.domain ?? ''), ...(plan.domain ? { domains: [plan.domain] } : {}), limit: 50 })
          .then((r) => (r.status === 200 ? summarizeHiring(r.body) : null))
          .catch(() => null)
      : Promise.resolve(null);

  // Phase 1: homepage, about, Wikidata search, GitHub org.
  const [homepage, about, wikidataSearchJson, githubOrgJson] = await Promise.all([
    byId.get('homepage') ? fetchPage(deps, byId.get('homepage')!.url, deadlineAt) : Promise.resolve(null),
    byId.get('about') ? fetchPage(deps, byId.get('about')!.url, deadlineAt) : Promise.resolve(null),
    byId.get('wikidata_search') ? fetchJsonText(deps, byId.get('wikidata_search')!.url, deadlineAt) : Promise.resolve(null),
    byId.get('github_org') ? fetchJsonText(deps, byId.get('github_org')!.url, deadlineAt) : Promise.resolve(null),
  ]);

  // Phase 2: Wikidata entity pick (domain-corroborated) and follow-ups.
  let wikidataEntityJson: string | null = null;
  let followups: EntityFollowups | undefined;
  let wikidataId: string | undefined;
  if (wikidataSearchJson) {
    const fu = callCoreWasm<{ wikidataEntityUrls: string[]; wikidataBatchUrl?: string }>('company_followups', {
      wikidataSearchJson,
      ...(plan.domain ? { domain: plan.domain } : {}),
      ...(companyName ? { name: companyName } : {}),
    });
    const entityUrl = fu.wikidataBatchUrl ?? fu.wikidataEntityUrls[0];
    const entityJsons: string[] = [];
    if (fu.wikidataBatchUrl) {
      const t = await fetchJsonText(deps, fu.wikidataBatchUrl, deadlineAt);
      if (t) entityJsons.push(t);
    } else if (entityUrl) {
      const ts = await Promise.all(fu.wikidataEntityUrls.slice(0, 5).map((u) => fetchJsonText(deps, u, deadlineAt)));
      for (const t of ts) if (t) entityJsons.push(t);
    }
    if (entityJsons.length > 0) {
      const pick = callCoreWasm<{ qid?: string; ok: boolean; reason: string; followups?: EntityFollowups }>('company_pick_wikidata', {
        wikidataSearchJson,
        entityJsons,
        ...(plan.domain ? { domain: plan.domain } : {}),
        ...(companyName ? { name: companyName } : {}),
      });
      if (pick.ok && pick.qid) {
        wikidataId = pick.qid;
        followups = pick.followups;
        // The merge needs the chosen entity's JSON; the batch body contains it (Go selects by qid).
        wikidataEntityJson = entityJsons.find((t) => t.includes(`"${pick.qid}"`)) ?? entityJsons[0] ?? null;
      }
    }
  }

  // Phase 3: SEC filings + Wikidata labels (+ GitHub org from P2037 when the plan had none), and Maps place search.
  const placesQuery =
    payload.includePlaces !== false && deps.callMapsPlaces
      ? callCoreWasm<{ query: string }>('company_places_query', {
          ...(companyName ? { name: companyName } : {}),
          ...(plan.domain ? { domain: plan.domain } : {}),
        }).query
      : '';
  const [secSubmissionsJson, secCompanyFactsJson, wikidataLabelsJson, githubFromWikidata, placesJson] = await Promise.all([
    followups?.secSubmissionsUrl ? fetchJsonText(deps, followups.secSubmissionsUrl, deadlineAt) : Promise.resolve(null),
    followups?.secCompanyFactsUrl ? fetchJsonText(deps, followups.secCompanyFactsUrl, deadlineAt) : Promise.resolve(null),
    followups?.labelsUrl ? fetchJsonText(deps, followups.labelsUrl, deadlineAt) : Promise.resolve(null),
    !githubOrgJson && followups?.githubOrgUrl ? fetchJsonText(deps, followups.githubOrgUrl, deadlineAt) : Promise.resolve(null),
    placesQuery && deps.callMapsPlaces ? deps.callMapsPlaces(placesQuery).catch(() => null) : Promise.resolve(null),
  ]);

  const remainingForHiring = Math.max(0, deadlineAt - Date.now());
  const ats = await Promise.race([
    hiringPromise,
    new Promise<null>((r) => setTimeout(() => r(null), remainingForHiring)),
  ]);

  const profile = callCoreWasm<Record<string, unknown>>('company_merge', {
    ...(companyName ? { name: companyName } : {}),
    ...(plan.domain ? { domain: plan.domain } : {}),
    ...(homepage ? { homepage } : {}),
    ...(about ? { about } : {}),
    ...(wikidataId ? { wikidataId } : {}),
    ...(wikidataEntityJson ? { wikidataEntityJson } : {}),
    ...(wikidataLabelsJson ? { wikidataLabelsJson } : {}),
    ...(secSubmissionsJson ? { secSubmissionsJson } : {}),
    ...(secCompanyFactsJson ? { secCompanyFactsJson } : {}),
    ...(githubOrgJson || githubFromWikidata ? { githubOrgJson: githubOrgJson ?? githubFromWikidata } : {}),
    ...(ats ? { ats } : {}),
    ...(placesJson ? { placesJson } : {}),
  });
  return {
    status: 200,
    body: {
      ok: true,
      ...profile,
      googleMaps: deps.callMapsPlaces ? (placesJson ? 'used' : 'no_result') : 'not_connected',
    },
  };
}
