/**
 * Job & ATS Intelligence Layer (`hub/src/jobs.ts` — Handoff Items `P1`–`P5`, `P9`–`P11`, & `jobs` Tool):
 *
 *  - `P1`: Ashby public posting API adapter (`api.ashbyhq.com/posting-api/job-board/{org}?includeCompensation=true`) +
 *          thin-page `metadata.description` rescue (`contentSource: "meta-description"`).
 *  - `P2`: Workday CXS adapter (`POST /wday/cxs/{tenant}/{site}/jobs` + `GET /wday/cxs/{tenant}/{site}/job/{path}`) +
 *          `{"widget":"redirect","externalSpa":true}` stub detector.
 *  - `P3`: Thin / filter-only scripted HTML detector (`isThinScriptedPage`: `<80` words or `>60%` link/nav lines).
 *  - `P4`: Schema.org `JobPosting` JSON-LD parser (`extractJobPostingJsonLd`) + EEO/AI-notice boilerplate detector.
 *  - `P5`: Per-record JSON array chunker (`chunkJsonRecords`: 1 chunk = 1 record, HTML fields -> Markdown, `jsonFilter`).
 *  - `P9`: Material redirect & lost-filter detector (`analyzeUrlRedirect`).
 *  - `P10`: Ethical `blocked: { reason: "robots" | "challenge", suggestion }` helper (strictly honors blocks).
 *  - `P11`: Standardized compensation parser (`normalizePay`: `{ min, max, currency, period, basis: "base"|"ote"|"total" }`).
 *  - `Section 4`: First-class `executeJobsCall` (`POST /v1/jobs` & MCP `jobs` tool).
 */

import { compileSafeUserRegex } from './safe-input';
import type { ArtifactRetention, OptionalStorageBindings } from './storage';

export type PayPeriod = 'year' | 'month' | 'week' | 'day' | 'hour';
export type PayBasis = 'base' | 'ote' | 'total';
export type WorkplaceType = 'remote' | 'hybrid' | 'onsite' | 'unknown';
export type AtsBoardStatus = 'ok' | 'empty_board' | 'wrong_slug' | 'blocked_or_down';

export interface DiscoveredAtsBoard {
  platform: string;
  slug: string;
  boardUrl: string;
  discoveredFrom: string;
  boardStatus?: AtsBoardStatus;
}

export interface NormalizedPay {
  min: number | null;
  max: number | null;
  currency: string;
  period: PayPeriod;
  basis: PayBasis;
  raw?: string;
}

export interface StructuredJobPosting {
  title: string;
  hiringOrganization?: string;
  jobLocation?: string[];
  jobLocationType?: string;
  workplaceType: WorkplaceType;
  baseSalary?: NormalizedPay | null;
  pay?: NormalizedPay | null;
  datePosted?: string;
  validThrough?: string;
  employmentType?: string;
  url?: string;
  applyUrl?: string;
  source?: string;
}

export interface BlockedSuggestion {
  reason: 'robots' | 'challenge';
  host?: string;
  suggestion: string;
}

export interface RedirectAnalysis {
  redirected: boolean;
  redirectNote?: string;
  filtersMayBeLost?: boolean;
}

export type HtmlToMdFn = (html: string, baseUrl?: string) => { markdown: string; links: string[] };

export interface AtsPreFetchSpec {
  id: string;
  fetchUrl: string;
  method: 'GET' | 'POST';
  requestBody?: string;
  contentType?: string;
  kind: 'json' | 'text';
  accept: string;
  format: (
    rawBody: string,
    originalUrl: string,
    htmlToMd: HtmlToMdFn,
  ) => {
    title: string;
    description?: string;
    publishedTime?: string;
    markdown: string;
    links?: string[];
    jobPosting?: StructuredJobPosting;
    jobs?: StructuredJobRecord[];
  } | null;
}

export interface StructuredJobRecord {
  title: string;
  company: string;
  url: string;
  applyUrl: string;
  workplaceType: WorkplaceType;
  locations: string[];
  pay: NormalizedPay | null;
  postedAt: string | null;
  source: string;
  employmentType?: string;
  snippet?: string;
}

function decodeEntitiesBasic(s: string): string {
  return s
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&ndash;/gi, '–')
    .replace(/&mdash;/gi, '—')
    .replace(/&#x([0-9a-f]+);/gi, (_m, h: string) => {
      const cp = parseInt(h, 16);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : _m;
    })
    .replace(/&#(\d+);/g, (_m, d: string) => {
      const cp = parseInt(d, 10);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : _m;
    });
}

function stripTagsPlain(s: string): string {
  return decodeEntitiesBasic(s.replace(/<[^>]+>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
}

function safeJsonParse(raw: string): unknown {
  try {
    return JSON.parse(raw.replace(/^\ufeff/, ''));
  } catch {
    return null;
  }
}

/** Classifies compensation basis (`base` vs `ote` vs `total`) from surrounding label or prose context (`P11`). */
export function inferPayBasis(labelOrContext: string): PayBasis {
  const lower = labelOrContext.toLowerCase();
  if (
    /\b(?:total\s+target\s+cash|total\s+cash|total\s+comp(?:ensation)?|total\s+rewards|annual\s+total|base\s*\+\s*(?:bonus|variable|equity)|ttc\b|target\s+cash)\b/.test(
      lower,
    )
  ) {
    return 'total';
  }
  if (/\b(?:ote|on[- ]target\s+earnings|target\s+commission|base\s*\+\s*commission|variable\s+target)\b/.test(lower)) {
    return 'ote';
  }
  return 'base';
}

export function normalizePeriod(rawPeriod: unknown): PayPeriod {
  const s = typeof rawPeriod === 'string' ? rawPeriod.toLowerCase().trim() : '';
  if (/hour|hr|hourly/.test(s)) return 'hour';
  if (/day|daily/.test(s)) return 'day';
  if (/week|wk|weekly/.test(s)) return 'week';
  if (/month|mo|monthly/.test(s)) return 'month';
  return 'year';
}

function scaleShorthandAnnualAmount(val: number | null, period: PayPeriod): number | null {
  if (val === null || !Number.isFinite(val) || val <= 0) return null;
  // P11: Ashby & shorthand postings report annual pay in thousands (`minValue: 230, maxValue: 350` -> `230000`, `350000`).
  if (period === 'year' && val >= 25 && val < 1_000) {
    return Math.round(val * 1_000);
  }
  return Math.round(val);
}

/** Formats a `NormalizedPay` into a crisp human summary (e.g. `$230,000–$350,000 USD/year (base)`). */
export function formatNormalizedPay(pay: NormalizedPay | null | undefined): string {
  if (!pay || (pay.min === null && pay.max === null)) return '';
  const sym = pay.currency === 'USD' ? '$' : pay.currency === 'GBP' ? '£' : pay.currency === 'EUR' ? '€' : `${pay.currency} `;
  const fmt = (n: number) => `${sym}${n.toLocaleString('en-US')}`;
  const range =
    pay.min !== null && pay.max !== null && pay.min !== pay.max
      ? `${fmt(pay.min)}–${fmt(pay.max)}`
      : fmt((pay.min ?? pay.max)!);
  return `${range} ${pay.currency}/${pay.period} (${pay.basis})`;
}

/**
 * Extracts standardized `NormalizedPay` (`P11`) from prose compensation text such as:
 *  - `"$160K–$270K"` / `"$160,000 - $270,000 USD"`
 *  - `"Annual Total Target Cash: $157.3K - $253.6K"` -> `basis: "total"`
 *  - `"$230 – $350"` (Ashby annual shorthand) -> `230000`–`350000`
 */
export function parsePayFromText(text: string): NormalizedPay | null {
  if (!text) return null;
  const normalized = decodeEntitiesBasic(text).replace(/\u00a0/g, ' ');
  const rangeRe =
    /(?:(USD|CAD|EUR|GBP|AUD|CHF)\s*)?([\$£€])\s*(\d{2,3}(?:,\d{3})+|\d{2,3}(?:\.\d+)?)\s*([kK])?\s*(?:[-–—]|to)\s*(?:(?:USD|CAD|EUR|GBP|AUD|CHF)\s*)?[\$£€]?\s*(\d{2,3}(?:,\d{3})+|\d{2,3}(?:\.\d+)?)\s*([kK])?/g;

  let m: RegExpExecArray | null;
  while ((m = rangeRe.exec(normalized)) !== null) {
    const windowStart = Math.max(0, m.index - 90);
    const windowEnd = Math.min(normalized.length, m.index + m[0].length + 90);
    const ctxWindow = normalized.slice(windowStart, windowEnd);
    // Skip funding/ARR/valuation numbers ("raised $150M", "$200K ARR")
    if (/\b(?:arr|mrr|funding|raised|valuation|series\s+[a-f]|revenue)\b/i.test(ctxWindow)) continue;

    const explicitCur = m[1]?.toUpperCase();
    const sym = m[2];
    const currency = explicitCur || (sym === '£' ? 'GBP' : sym === '€' ? 'EUR' : 'USD');
    const rawMin = parseFloat(m[3]!.replace(/,/g, ''));
    const minHasK = Boolean(m[4]);
    const rawMax = parseFloat(m[5]!.replace(/,/g, ''));
    const maxHasK = Boolean(m[6] || m[4]);

    const period: PayPeriod = /\b(?:per\s+hour|\/\s*hr|hourly)\b/i.test(ctxWindow)
      ? 'hour'
      : /\b(?:per\s+month|\/\s*mo|monthly)\b/i.test(ctxWindow)
        ? 'month'
        : 'year';

    let minVal = minHasK ? rawMin * 1_000 : rawMin;
    let maxVal = maxHasK ? rawMax * 1_000 : rawMax;
    minVal = scaleShorthandAnnualAmount(minVal, period) ?? minVal;
    maxVal = scaleShorthandAnnualAmount(maxVal, period) ?? maxVal;

    if (period === 'year' && (minVal < 25_000 || maxVal > 2_500_000 || maxVal < minVal)) continue;

    return {
      min: Math.round(minVal),
      max: Math.round(maxVal),
      currency,
      period,
      basis: inferPayBasis(ctxWindow),
      raw: m[0].trim(),
    };
  }
  return null;
}

export function inferWorkplaceType(text: string): WorkplaceType {
  const lower = text.toLowerCase();
  if (/\bhybrid\b/.test(lower)) return 'hybrid';
  if (/\b(?:remote|telecommute|work\s+from\s+anywhere|distributed)\b/.test(lower)) return 'remote';
  if (/\b(?:on[- ]?site|in[- ]?office|in[- ]?person)\b/.test(lower)) return 'onsite';
  return 'unknown';
}

/**
 * `P4`: Parses `<script type="application/ld+json">` blocks (including `@graph` arrays) for `@type: JobPosting`.
 */
export function extractJobPostingJsonLd(rawHtml: string, baseUrl?: string, fallbackProse = ''): StructuredJobPosting | null {
  const scriptRe = /<script\b[^>]*\btype\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  const candidates: Array<Record<string, unknown>> = [];

  const collectEntities = (node: unknown) => {
    if (!node) return;
    if (Array.isArray(node)) {
      for (const item of node) collectEntities(item);
      return;
    }
    if (typeof node === 'object') {
      const obj = node as Record<string, unknown>;
      const t = obj['@type'];
      const isJob =
        (typeof t === 'string' && /JobPosting/i.test(t)) ||
        (Array.isArray(t) && t.some((x) => typeof x === 'string' && /JobPosting/i.test(x)));
      if (isJob) candidates.push(obj);
      if (Array.isArray(obj['@graph'])) collectEntities(obj['@graph']);
    }
  };

  let sm: RegExpExecArray | null;
  while ((sm = scriptRe.exec(rawHtml)) !== null) {
    const rawJson = sm[1]!.trim();
    if (!rawJson) continue;
    const parsed = safeJsonParse(rawJson) ?? safeJsonParse(decodeEntitiesBasic(rawJson));
    collectEntities(parsed);
  }

  const jp = candidates[0];
  if (!jp) return null;

  const title = stripTagsPlain(String(jp.title ?? jp.name ?? ''));
  if (!title) return null;

  const orgObj = jp.hiringOrganization as Record<string, unknown> | string | undefined;
  const hiringOrganization =
    typeof orgObj === 'string' ? stripTagsPlain(orgObj) : typeof orgObj?.name === 'string' ? stripTagsPlain(orgObj.name) : undefined;

  const locations: string[] = [];
  const rawLocs = Array.isArray(jp.jobLocation) ? jp.jobLocation : jp.jobLocation ? [jp.jobLocation] : [];
  for (const loc of rawLocs) {
    if (typeof loc === 'string') {
      if (loc.trim()) locations.push(loc.trim());
      continue;
    }
    if (loc && typeof loc === 'object') {
      const addr = ((loc as Record<string, unknown>).address ?? loc) as Record<string, unknown> | string;
      if (typeof addr === 'string') {
        if (addr.trim()) locations.push(addr.trim());
      } else if (addr && typeof addr === 'object') {
        const parts = [addr.addressLocality, addr.addressRegion, addr.addressCountry]
          .map((x) => (typeof x === 'string' ? x.trim() : typeof (x as { name?: string })?.name === 'string' ? (x as { name: string }).name.trim() : ''))
          .filter(Boolean);
        if (parts.length > 0) locations.push(parts.join(', '));
      }
    }
  }

  const jobLocationType = typeof jp.jobLocationType === 'string' ? jp.jobLocationType.trim() : undefined;
  const applicantLocReq = jp.applicantLocationRequirements;
  if (jobLocationType && /TELECOMMUTE/i.test(jobLocationType) && locations.length === 0) {
    if (applicantLocReq && typeof applicantLocReq === 'object' && typeof (applicantLocReq as { name?: string }).name === 'string') {
      locations.push(`Remote (${(applicantLocReq as { name: string }).name})`);
    } else {
      locations.push('Remote');
    }
  }

  // Parse structured `baseSalary` / `estimatedSalary`
  let structuredPay: NormalizedPay | null = null;
  const rawSal = (jp.baseSalary ?? (Array.isArray(jp.estimatedSalary) ? jp.estimatedSalary[0] : jp.estimatedSalary)) as
    | Record<string, unknown>
    | undefined;
  if (rawSal && typeof rawSal === 'object') {
    const currency = typeof rawSal.currency === 'string' && rawSal.currency.trim() ? rawSal.currency.trim().toUpperCase() : 'USD';
    const valObj = rawSal.value as Record<string, unknown> | number | string | undefined;
    let minVal: number | null = null;
    let maxVal: number | null = null;
    let unitText = '';
    if (typeof valObj === 'number') {
      minVal = valObj;
      maxVal = valObj;
    } else if (typeof valObj === 'string') {
      const n = parseFloat(valObj.replace(/,/g, ''));
      if (Number.isFinite(n)) {
        minVal = n;
        maxVal = n;
      }
    } else if (valObj && typeof valObj === 'object') {
      const rawMin = Number(valObj.minValue ?? valObj.value ?? NaN);
      const rawMax = Number(valObj.maxValue ?? valObj.value ?? NaN);
      if (Number.isFinite(rawMin) && rawMin > 0) minVal = rawMin;
      if (Number.isFinite(rawMax) && rawMax > 0) maxVal = rawMax;
      if (typeof valObj.unitText === 'string') unitText = valObj.unitText;
    }
    const period = normalizePeriod(unitText || rawSal.unitText);
    minVal = scaleShorthandAnnualAmount(minVal, period);
    maxVal = scaleShorthandAnnualAmount(maxVal, period);
    if (minVal !== null || maxVal !== null) {
      structuredPay = {
        min: minVal,
        max: maxVal ?? minVal,
        currency,
        period,
        basis: 'base',
      };
    }
  }

  const descHtml = typeof jp.description === 'string' ? jp.description : '';
  const proseForPay = `${stripTagsPlain(descHtml)} ${fallbackProse}`;
  const prosePay = parsePayFromText(proseForPay);
  // If JSON-LD lacks baseSalary, fall back to prose pay; if prose reveals "Total Target Cash" on the exact same numbers, preserve its `basis`!
  let finalPay = structuredPay ?? prosePay;
  if (structuredPay && prosePay && prosePay.basis !== 'base' && prosePay.min === structuredPay.min && prosePay.max === structuredPay.max) {
    finalPay = { ...structuredPay, basis: prosePay.basis };
  }

  const wpText = `${jobLocationType ?? ''} ${locations.join(' ')} ${title}`;
  const workplaceType: WorkplaceType =
    jobLocationType && /TELECOMMUTE/i.test(jobLocationType)
      ? /hybrid/i.test(wpText)
        ? 'hybrid'
        : 'remote'
      : inferWorkplaceType(wpText);

  const empRaw = jp.employmentType;
  const employmentType = Array.isArray(empRaw) ? empRaw.map(String).join(', ') : typeof empRaw === 'string' ? empRaw : undefined;
  const datePosted = typeof jp.datePosted === 'string' ? jp.datePosted : undefined;
  const validThrough = typeof jp.validThrough === 'string' ? jp.validThrough : undefined;
  const applyUrl = typeof jp.url === 'string' && jp.url.startsWith('http') ? jp.url : baseUrl;

  return {
    title,
    ...(hiringOrganization ? { hiringOrganization } : {}),
    ...(locations.length > 0 ? { jobLocation: locations } : {}),
    ...(jobLocationType ? { jobLocationType } : {}),
    workplaceType,
    baseSalary: finalPay?.basis === 'base' ? finalPay : structuredPay,
    pay: finalPay,
    ...(datePosted ? { datePosted } : {}),
    ...(validThrough ? { validThrough } : {}),
    ...(employmentType ? { employmentType } : {}),
    ...(baseUrl ? { url: baseUrl } : {}),
    ...(applyUrl ? { applyUrl } : {}),
    source: 'json-ld',
  };
}

/** Formats a crisp top-of-document Markdown summary block for a `StructuredJobPosting` so pay/location rank #1. */
export function formatJobPostingHeaderMarkdown(jp: StructuredJobPosting): string {
  const bullets: string[] = [];
  if (jp.hiringOrganization) bullets.push(`- **Company**: ${jp.hiringOrganization}`);
  if (jp.jobLocation && jp.jobLocation.length > 0) bullets.push(`- **Location**: ${jp.jobLocation.join('; ')}`);
  if (jp.workplaceType && jp.workplaceType !== 'unknown') bullets.push(`- **Workplace**: ${jp.workplaceType}`);
  if (jp.pay) bullets.push(`- **Compensation**: ${formatNormalizedPay(jp.pay)}`);
  if (jp.employmentType) bullets.push(`- **Employment Type**: ${jp.employmentType}`);
  if (jp.datePosted) bullets.push(`- **Posted**: ${jp.datePosted.slice(0, 10)}`);
  if (jp.applyUrl) bullets.push(`- **Apply URL**: ${jp.applyUrl}`);
  return bullets.length > 0 ? bullets.join('\n') : '';
}

/**
 * `P4`: Detects EEO, disability accommodations, AI-in-hiring, and applicant privacy boilerplate chunks so they are
 * down-weighted during BM25 passage ranking and never outrank pay/location/role requirements.
 */
export function isJobLegalBoilerplateChunk(text: string, heading = ''): boolean {
  const combined = `${heading}\n${text}`.toLowerCase();
  if (
    /^(?:equal\s+(?:employment\s+)?opportunity|eeo\s+statement|accommodations?|reasonable\s+accommodation|ai\s+in\s+hiring|applicant\s+privacy|privacy\s+notice|ccpa|fair\s+chance)/i.test(
      heading.trim(),
    )
  ) {
    return true;
  }
  let signals = 0;
  if (/\bequal\s+(?:employment\s+)?opportunity\s+employer\b|\bproud\s+to\s+be\s+an?\s+equal\s+opportunity\b/.test(combined)) signals += 2;
  if (/\bwithout\s+regard\s+to\s+race,\s*color,\s*religion\b|\bnational\s+origin,\s*(?:sex|gender|age|disability)\b/.test(combined)) signals += 2;
  if (/\breasonable\s+accommodations?\b[\s\S]{0,120}\b(?:disabilit(?:y|ies)|qualified\s+individuals)\b/.test(combined)) signals += 2;
  if (/\bartificial\s+intelligence\b[\s\S]{0,140}\b(?:hiring|recruitment|application\s+process|automated\s+employment\s+decision)\b/.test(combined)) {
    signals += 2;
  }
  if (/\bautomated\s+employment\s+decision\s+tool\b|\bnyc\s+local\s+law\s+144\b|\bcandidate\s+privacy\s+notice\b/.test(combined)) {
    signals += 2;
  }
  return signals >= 2;
}

function parseAshbyPay(job: Record<string, unknown>, descText: string): NormalizedPay | null {
  const comp = job.compensation as Record<string, unknown> | undefined;
  if (comp && typeof comp === 'object') {
    const components = [
      ...(Array.isArray(comp.summaryComponents) ? (comp.summaryComponents as Array<Record<string, unknown>>) : []),
      ...(Array.isArray(comp.compensationTiers)
        ? ((comp.compensationTiers as Array<Record<string, unknown>>)[0]?.components as Array<Record<string, unknown>> | undefined) ?? []
        : []),
    ];
    // Prefer Salary / Base component over equity/bonus components
    const salaryComp =
      components.find((c) => /salary|base|cash/i.test(String(c.compensationType ?? c.summary ?? c.title ?? ''))) ?? components[0];
    if (salaryComp && typeof salaryComp === 'object') {
      const currency = typeof salaryComp.currencyCode === 'string' && salaryComp.currencyCode ? salaryComp.currencyCode.toUpperCase() : 'USD';
      const period = normalizePeriod(salaryComp.interval ?? salaryComp.period ?? 'year');
      const rawMin = typeof salaryComp.minValue === 'number' ? salaryComp.minValue : null;
      const rawMax = typeof salaryComp.maxValue === 'number' ? salaryComp.maxValue : null;
      const min = scaleShorthandAnnualAmount(rawMin, period);
      const max = scaleShorthandAnnualAmount(rawMax, period);
      if (min !== null || max !== null) {
        const summaryLabel = `${String(salaryComp.compensationType ?? '')} ${String(comp.compensationTierSummary ?? '')}`;
        return {
          min,
          max: max ?? min,
          currency,
          period,
          basis: inferPayBasis(summaryLabel),
          ...(typeof comp.compensationTierSummary === 'string' ? { raw: comp.compensationTierSummary } : {}),
        };
      }
    }
    if (typeof comp.compensationTierSummary === 'string') {
      const fromSummary = parsePayFromText(comp.compensationTierSummary);
      if (fromSummary) return fromSummary;
    }
  }
  return parsePayFromText(descText);
}

/**
 * Resolves pre-fetch ATS API adapters (`P1` Ashby, `P2` Workday CXS `GET` & `POST`, Greenhouse, Lever) for both
 * `scrape` and `extract`.
 */
export function resolveAtsPreFetchSpec(urlStr: string): AtsPreFetchSpec | null {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase();
  const parts = u.pathname.split('/').filter(Boolean);

  // P1: Ashby (`jobs.ashbyhq.com/{org}[/{jobId}[/application]]`)
  if (host === 'jobs.ashbyhq.com' && parts.length >= 1) {
    const org = decodeURIComponent(parts[0]!);
    const jobId = parts.length >= 2 && parts[1]!.toLowerCase() !== 'application' ? decodeURIComponent(parts[1]!) : '';
    if (/^[A-Za-z0-9._-]+$/.test(org)) {
      return {
        id: jobId ? 'ashby-job' : 'ashby-board',
        fetchUrl: `https://api.ashbyhq.com/posting-api/job-board/${encodeURIComponent(org)}?includeCompensation=true`,
        method: 'GET',
        kind: 'json',
        accept: 'application/json',
        format: (rawBody, origUrl, htmlToMd) => {
          const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
          const jobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : [];
          if (jobs.length === 0) return null;
          const orgTitle = typeof data?.organizationName === 'string' && data.organizationName ? data.organizationName : org;

          if (jobId) {
            const match = jobs.find((j) => String(j.id ?? '').toLowerCase() === jobId.toLowerCase());
            if (!match) return null;
            const title = String(match.title ?? 'Job Posting').trim();
            const loc = typeof match.location === 'string' ? match.location.trim() : '';
            const secLocs = Array.isArray(match.secondaryLocations)
              ? (match.secondaryLocations as Array<Record<string, unknown> | string>)
                  .map((s) => (typeof s === 'string' ? s : String(s?.location ?? '')))
                  .filter(Boolean)
              : [];
            const allLocs = [loc, ...secLocs].filter(Boolean);
            const wpRaw = String(match.workplaceType ?? (match.isRemote ? 'Remote' : ''));
            const workplaceType: WorkplaceType = /hybrid/i.test(wpRaw)
              ? 'hybrid'
              : /remote/i.test(wpRaw) || Boolean(match.isRemote)
                ? 'remote'
                : /onsite|on-site|office/i.test(wpRaw)
                  ? 'onsite'
                  : inferWorkplaceType(`${wpRaw} ${allLocs.join(' ')}`);
            const descHtml = typeof match.descriptionHtml === 'string' ? match.descriptionHtml : '';
            const descPlain = typeof match.descriptionPlain === 'string' ? match.descriptionPlain : '';
            const bodyMd = descHtml.trim() ? htmlToMd(descHtml, origUrl).markdown.trim() : descPlain.trim();
            const pay = parseAshbyPay(match, `${descPlain} ${bodyMd}`);
            const postedAt = typeof match.publishedAt === 'string' ? match.publishedAt : undefined;
            const empType = typeof match.employmentType === 'string' ? match.employmentType : undefined;
            const jobUrl = typeof match.jobUrl === 'string' && match.jobUrl ? match.jobUrl : origUrl;
            const applyUrl = typeof match.applyUrl === 'string' && match.applyUrl ? match.applyUrl : `${jobUrl.replace(/\/+$/, '')}/application`;

            const jp: StructuredJobPosting = {
              title,
              hiringOrganization: orgTitle,
              ...(allLocs.length > 0 ? { jobLocation: allLocs } : {}),
              workplaceType,
              baseSalary: pay?.basis === 'base' ? pay : null,
              pay,
              ...(postedAt ? { datePosted: postedAt } : {}),
              ...(empType ? { employmentType: empType } : {}),
              url: jobUrl,
              applyUrl,
              source: 'ashby',
            };
            const headerMd = formatJobPostingHeaderMarkdown(jp);
            return {
              title: `${title} @ ${orgTitle}`,
              ...(descPlain ? { description: descPlain.slice(0, 280) } : {}),
              ...(postedAt ? { publishedTime: postedAt } : {}),
              jobPosting: jp,
              markdown: [`# ${title} @ ${orgTitle}`, ...(headerMd ? [headerMd] : []), bodyMd].filter(Boolean).join('\n\n'),
              links: [applyUrl],
            };
          }

          // Whole Ashby job board summary
          const records: StructuredJobRecord[] = [];
          const lines: string[] = [`# ${orgTitle} — Open Roles (${jobs.length})`];
          const links: string[] = [];
          for (const j of jobs.slice(0, 100)) {
            const jId = String(j.id ?? '');
            const jTitle = String(j.title ?? 'Role').trim();
            const jLoc = String(j.location ?? '').trim();
            const wpRaw = String(j.workplaceType ?? (j.isRemote ? 'Remote' : ''));
            const wp = inferWorkplaceType(`${wpRaw} ${jLoc}`);
            const pay = parseAshbyPay(j, String(j.descriptionPlain ?? ''));
            const jUrl = typeof j.jobUrl === 'string' && j.jobUrl ? j.jobUrl : `https://jobs.ashbyhq.com/${org}/${jId}`;
            const applyUrl = typeof j.applyUrl === 'string' && j.applyUrl ? j.applyUrl : `${jUrl}/application`;
            const postedAt = typeof j.publishedAt === 'string' ? j.publishedAt : null;
            links.push(jUrl);
            records.push({
              title: jTitle,
              company: orgTitle,
              url: jUrl,
              applyUrl,
              workplaceType: wp,
              locations: jLoc ? [jLoc] : [],
              pay,
              postedAt,
              source: 'ashby',
            });
            const meta = [jLoc, wp !== 'unknown' ? wp : '', pay ? formatNormalizedPay(pay) : ''].filter(Boolean).join(' · ');
            lines.push(`- **[${jTitle}](${jUrl})**${meta ? ` — ${meta}` : ''}`);
          }
          return {
            title: `${orgTitle} Jobs (${jobs.length})`,
            markdown: lines.join('\n'),
            links,
            jobs: records,
          };
        },
      };
    }
  }

  // P2: Workday CXS (`{tenant}.wd{N}.myworkdayjobs.com/[{locale}/]{site}[/job/{externalPath}]`)
  const wdHostMatch = /^([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com$/i.exec(host);
  if (wdHostMatch && parts.length >= 1) {
    const tenant = wdHostMatch[1]!;
    let idx = 0;
    if (/^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2) {
      idx = 1; // skip locale segment like `en-US`
    }
    const site = parts[idx]!;
    const rest = parts.slice(idx + 1);
    if (site && site.toLowerCase() !== 'wday') {
      if (rest[0] === 'job' && rest.length >= 2) {
        const extPath = rest.slice(1).join('/');
        return {
          id: 'workday-job',
          fetchUrl: `https://${host}/wday/cxs/${tenant}/${site}/job/${extPath}`,
          method: 'GET',
          kind: 'json',
          accept: 'application/json',
          format: (rawBody, origUrl, htmlToMd) => {
            const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
            const info = (data?.jobPostingInfo ?? data) as Record<string, unknown> | undefined;
            if (!info || typeof info.title !== 'string') return null;
            const title = info.title.trim();
            const loc = typeof info.location === 'string' ? info.location.trim() : '';
            const addLocs = Array.isArray(info.additionalLocations) ? info.additionalLocations.map(String).filter(Boolean) : [];
            const allLocs = [loc, ...addLocs].filter(Boolean);
            const remoteType = typeof info.remoteType === 'string' ? info.remoteType : '';
            const timeType = typeof info.timeType === 'string' ? info.timeType : undefined;
            const postedOn = typeof info.startDate === 'string' ? info.startDate : typeof info.postedOn === 'string' ? info.postedOn : undefined;
            const descHtml = typeof info.jobDescription === 'string' ? info.jobDescription : '';
            const bodyMd = descHtml ? htmlToMd(descHtml, origUrl).markdown.trim() : '';
            const pay = parsePayFromText(bodyMd);
            const extUrl = typeof info.externalUrl === 'string' && info.externalUrl.startsWith('http') ? info.externalUrl : origUrl;
            const wp = inferWorkplaceType(`${remoteType} ${allLocs.join(' ')} ${title}`);

            const jp: StructuredJobPosting = {
              title,
              hiringOrganization: tenant,
              ...(allLocs.length > 0 ? { jobLocation: allLocs } : {}),
              workplaceType: wp,
              baseSalary: pay?.basis === 'base' ? pay : null,
              pay,
              ...(postedOn ? { datePosted: postedOn } : {}),
              ...(timeType ? { employmentType: timeType } : {}),
              url: origUrl,
              applyUrl: extUrl,
              source: 'workday',
            };
            const headerMd = formatJobPostingHeaderMarkdown(jp);
            return {
              title: `${title} (${tenant})`,
              ...(postedOn ? { publishedTime: postedOn } : {}),
              jobPosting: jp,
              markdown: [`# ${title}`, ...(headerMd ? [headerMd] : []), bodyMd].filter(Boolean).join('\n\n'),
              links: [extUrl],
            };
          },
        };
      }

      // Workday Board / Search URL -> `POST /wday/cxs/{tenant}/{site}/jobs`
      const searchText = (u.searchParams.get('q') ?? u.searchParams.get('searchText') ?? u.searchParams.get('search') ?? '').trim();
      return {
        id: 'workday-board',
        fetchUrl: `https://${host}/wday/cxs/${tenant}/${site}/jobs`,
        method: 'POST',
        requestBody: JSON.stringify({ appliedFacets: {}, limit: 20, offset: 0, searchText }),
        contentType: 'application/json',
        kind: 'json',
        accept: 'application/json',
        format: (rawBody) => {
          const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
          const postings = Array.isArray(data?.jobPostings) ? (data.jobPostings as Array<Record<string, unknown>>) : null;
          if (!postings) return null;
          const total = typeof data?.total === 'number' ? data.total : postings.length;
          const heading = `${tenant} (${site}) — Workday Job Board (${total} open roles${searchText ? ` matching "${searchText}"` : ''})`;
          const lines: string[] = [`# ${heading}`];
          const links: string[] = [];
          const records: StructuredJobRecord[] = [];
          for (const p of postings) {
            const pTitle = String(p.title ?? '').trim();
            if (!pTitle) continue;
            const extPath = typeof p.externalPath === 'string' ? p.externalPath : '';
            const fullUrl = extPath ? `https://${host}/${site}${extPath.startsWith('/') ? '' : '/'}${extPath}` : `https://${host}/${site}`;
            const locTxt = typeof p.locationsText === 'string' ? p.locationsText.trim() : '';
            const postedOn = typeof p.postedOn === 'string' ? p.postedOn.trim() : null;
            const bullets = Array.isArray(p.bulletFields) ? p.bulletFields.map(String).filter(Boolean).join(', ') : '';
            const wp = inferWorkplaceType(`${locTxt} ${pTitle} ${String(p.remoteType ?? '')}`);
            links.push(fullUrl);
            records.push({
              title: pTitle,
              company: tenant,
              url: fullUrl,
              applyUrl: fullUrl,
              workplaceType: wp,
              locations: locTxt ? [locTxt] : [],
              pay: null,
              postedAt: postedOn,
              source: 'workday',
            });
            const meta = [locTxt, postedOn, bullets].filter(Boolean).join(' · ');
            lines.push(`- **[${pTitle}](${fullUrl})**${meta ? ` — ${meta}` : ''}`);
          }
          return {
            title: heading,
            markdown: lines.join('\n'),
            links,
            jobs: records,
          };
        },
      };
    }
  }

  // Greenhouse US & EU (`boards.greenhouse.io`, `job-boards.greenhouse.io`, `eu-boards.greenhouse.io`, `job-boards.eu.greenhouse.io`)
  const isGhUs = host === 'boards.greenhouse.io' || host === 'job-boards.greenhouse.io';
  const isGhEu = host === 'eu-boards.greenhouse.io' || host === 'job-boards.eu.greenhouse.io';
  if ((isGhUs || isGhEu) && parts.length >= 1) {
    const ghApiHost = isGhEu ? 'boards-api.eu.greenhouse.io' : 'boards-api.greenhouse.io';
    const co = parts[0]!;
    if (parts.length === 1 && /^[A-Za-z0-9_-]+$/.test(co) && co.toLowerCase() !== 'embed' && co.toLowerCase() !== 'v1') {
      return {
        id: isGhEu ? 'greenhouse-eu-board' : 'greenhouse-board',
        fetchUrl: `https://${ghApiHost}/v1/boards/${encodeURIComponent(co)}/jobs?content=true`,
        method: 'GET',
        kind: 'json',
        accept: 'application/json',
        format: (rawBody) => {
          const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
          const jobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : null;
          if (!jobs) return null;
          const records: StructuredJobRecord[] = [];
          const links: string[] = [];
          const lines: string[] = [`# ${co} — Greenhouse Job Board (${jobs.length} open roles)`];
          for (const j of jobs.slice(0, 120)) {
            const jTitle = String(j.title ?? '').trim();
            if (!jTitle) continue;
            const loc = String((j.location as Record<string, unknown> | undefined)?.name ?? '').trim();
            const jUrl =
              typeof j.absolute_url === 'string' && j.absolute_url.startsWith('https://')
                ? j.absolute_url
                : `https://${host}/${co}/jobs/${String(j.id ?? '')}`;
            const wp = inferWorkplaceType(`${loc} ${jTitle}`);
            const rawDesc = typeof j.content === 'string' ? decodeEntitiesBasic(j.content) : '';
            const pay = parsePayFromText(stripTagsPlain(rawDesc));
            const postedAt = typeof j.updated_at === 'string' ? j.updated_at : null;
            links.push(jUrl);
            records.push({
              title: jTitle,
              company: co,
              url: jUrl,
              applyUrl: jUrl,
              workplaceType: wp,
              locations: loc ? [loc] : [],
              pay,
              postedAt,
              source: 'greenhouse',
            });
            const meta = [loc, wp !== 'unknown' ? wp : '', pay ? formatNormalizedPay(pay) : ''].filter(Boolean).join(' · ');
            lines.push(`- **[${jTitle}](${jUrl})**${meta ? ` — ${meta}` : ''}`);
          }
          return {
            title: `${co} Jobs (${records.length})`,
            markdown: lines.join('\n'),
            links,
            jobs: records,
          };
        },
      };
    }
    if (parts.length >= 3 && parts[1] === 'jobs') {
      const jobId = parts[2]!;
      if (/^[A-Za-z0-9_-]+$/.test(co) && /^\d+$/.test(jobId)) {
        return {
          id: 'greenhouse-job',
          fetchUrl: `https://${ghApiHost}/v1/boards/${encodeURIComponent(co)}/jobs/${jobId}?content=true`,
          method: 'GET',
          kind: 'json',
          accept: 'application/json',
          format: (rawBody, origUrl, htmlToMd) => {
            const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
            if (!data || typeof data.title !== 'string') return null;
            const title = data.title.trim();
            const companyName = typeof data.company_name === 'string' && data.company_name ? data.company_name : co;
            const locObj = data.location as { name?: string } | undefined;
            const loc = typeof locObj?.name === 'string' ? locObj.name.trim() : '';
            const rawContent = typeof data.content === 'string' ? decodeEntitiesBasic(data.content) : '';
            const bodyMd = rawContent ? htmlToMd(rawContent, origUrl).markdown.trim() : '';

            let pay: NormalizedPay | null = null;
            const payRanges = Array.isArray(data.pay_input_ranges) ? (data.pay_input_ranges as Array<Record<string, unknown>>) : [];
            if (payRanges[0]) {
              const pr = payRanges[0];
              const cur = typeof pr.currency_type === 'string' ? pr.currency_type.toUpperCase() : 'USD';
              const minCents = typeof pr.min_cents === 'number' ? Math.round(pr.min_cents / 100) : null;
              const maxCents = typeof pr.max_cents === 'number' ? Math.round(pr.max_cents / 100) : null;
              if (minCents || maxCents) {
                pay = {
                  min: minCents,
                  max: maxCents ?? minCents,
                  currency: cur,
                  period: 'year',
                  basis: inferPayBasis(`${String(pr.title ?? '')} ${String(pr.blurb ?? '')}`),
                };
              }
            }
            if (!pay) pay = parsePayFromText(bodyMd);

            const updatedAt = typeof data.updated_at === 'string' ? data.updated_at : typeof data.first_published === 'string' ? data.first_published : undefined;
            const absUrl = typeof data.absolute_url === 'string' && data.absolute_url.startsWith('http') ? data.absolute_url : origUrl;
            const wp = inferWorkplaceType(`${loc} ${title} ${bodyMd.slice(0, 400)}`);

            const jp: StructuredJobPosting = {
              title,
              hiringOrganization: companyName,
              ...(loc ? { jobLocation: [loc] } : {}),
              workplaceType: wp,
              baseSalary: pay?.basis === 'base' ? pay : null,
              pay,
              ...(updatedAt ? { datePosted: updatedAt } : {}),
              url: origUrl,
              applyUrl: absUrl,
              source: 'greenhouse',
            };
            const headerMd = formatJobPostingHeaderMarkdown(jp);
            return {
              title: `${title} @ ${companyName}`,
              ...(updatedAt ? { publishedTime: updatedAt } : {}),
              jobPosting: jp,
              markdown: [`# ${title} @ ${companyName}`, ...(headerMd ? [headerMd] : []), bodyMd].filter(Boolean).join('\n\n'),
              links: [absUrl],
            };
          },
        };
      }
    }
  }

  // Lever US & EU (`jobs.lever.co` & `jobs.eu.lever.co`)
  if ((host === 'jobs.lever.co' || host === 'jobs.eu.lever.co') && parts.length >= 1) {
    const leverApiHost = host === 'jobs.eu.lever.co' ? 'api.eu.lever.co' : 'api.lever.co';
    const co = parts[0]!;
    if (parts.length === 1 && /^[A-Za-z0-9_.-]+$/.test(co)) {
      return {
        id: host === 'jobs.eu.lever.co' ? 'lever-eu-board' : 'lever-board',
        fetchUrl: `https://${leverApiHost}/v0/postings/${encodeURIComponent(co)}?mode=json`,
        method: 'GET',
        kind: 'json',
        accept: 'application/json',
        format: (rawBody) => {
          const parsed = safeJsonParse(rawBody);
          if (!Array.isArray(parsed)) return null;
          const jobs = parsed as Array<Record<string, unknown>>;
          const records: StructuredJobRecord[] = [];
          const links: string[] = [];
          const lines: string[] = [`# ${co} — Lever Job Board (${jobs.length} open roles)`];
          for (const j of jobs.slice(0, 120)) {
            const jTitle = String(j.text ?? '').trim();
            if (!jTitle) continue;
            const cats = (j.categories as Record<string, unknown> | undefined) ?? {};
            const allLocs = Array.isArray(cats.allLocations)
              ? cats.allLocations.map(String).filter(Boolean)
              : typeof cats.location === 'string' && cats.location
                ? [cats.location]
                : [];
            const wp = inferWorkplaceType(`${String(j.workplaceType ?? '')} ${allLocs.join(' ')}`);
            const jUrl = typeof j.hostedUrl === 'string' && j.hostedUrl.startsWith('https://') ? j.hostedUrl : `https://${host}/${co}/${String(j.id ?? '')}`;
            const applyUrl = typeof j.applyUrl === 'string' && j.applyUrl.startsWith('https://') ? j.applyUrl : `${jUrl}/apply`;
            const createdIso = typeof j.createdAt === 'number' ? new Date(j.createdAt).toISOString() : null;
            links.push(jUrl);
            records.push({
              title: jTitle,
              company: co,
              url: jUrl,
              applyUrl,
              workplaceType: wp,
              locations: allLocs,
              pay: parsePayFromText(String(j.salaryDescriptionPlain ?? '')),
              postedAt: createdIso,
              source: 'lever',
            });
            const meta = [allLocs[0] ?? '', wp !== 'unknown' ? wp : ''].filter(Boolean).join(' · ');
            lines.push(`- **[${jTitle}](${jUrl})**${meta ? ` — ${meta}` : ''}`);
          }
          return {
            title: `${co} Jobs (${records.length})`,
            markdown: lines.join('\n'),
            links,
            jobs: records,
          };
        },
      };
    }
    if (parts.length >= 2 && /^[0-9a-f-]{20,40}$/i.test(parts[1]!)) {
      const id = parts[1]!;
      return {
        id: 'lever-job',
        fetchUrl: `https://${leverApiHost}/v0/postings/${encodeURIComponent(co)}/${encodeURIComponent(id)}`,
        method: 'GET',
        kind: 'json',
        accept: 'application/json',
        format: (rawBody, origUrl, htmlToMd) => {
          const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
          if (!data || typeof data.text !== 'string') return null;
          const title = data.text.trim();
          const cats = (data.categories as Record<string, unknown> | undefined) ?? {};
          const allLocs = Array.isArray(cats.allLocations)
            ? cats.allLocations.map(String).filter(Boolean)
            : typeof cats.location === 'string' && cats.location
              ? [cats.location]
              : [];
          const commitment = typeof cats.commitment === 'string' ? cats.commitment : undefined;
          const wpRaw = `${String(data.workplaceType ?? '')} ${allLocs.join(' ')}`;
          const wp = inferWorkplaceType(wpRaw);

          const salObj = data.salaryRange as Record<string, unknown> | undefined;
          let pay: NormalizedPay | null = null;
          if (salObj && typeof salObj === 'object') {
            const period = normalizePeriod(salObj.interval ?? 'year');
            const min = scaleShorthandAnnualAmount(typeof salObj.min === 'number' ? salObj.min : null, period);
            const max = scaleShorthandAnnualAmount(typeof salObj.max === 'number' ? salObj.max : null, period);
            if (min !== null || max !== null) {
              pay = {
                min,
                max: max ?? min,
                currency: typeof salObj.currency === 'string' ? salObj.currency.toUpperCase() : 'USD',
                period,
                basis: inferPayBasis(String(data.salaryDescriptionPlain ?? '')),
              };
            }
          }

          const descParts: string[] = [];
          const introHtml = typeof data.description === 'string' ? data.description : '';
          if (introHtml) descParts.push(htmlToMd(introHtml, origUrl).markdown.trim());
          const lists = Array.isArray(data.lists) ? (data.lists as Array<Record<string, unknown>>) : [];
          for (const lst of lists) {
            const lHead = typeof lst.text === 'string' ? lst.text.trim() : '';
            const lContent = typeof lst.content === 'string' ? htmlToMd(`<ul>${lst.content}</ul>`, origUrl).markdown.trim() : '';
            if (lHead || lContent) descParts.push([lHead ? `## ${lHead}` : '', lContent].filter(Boolean).join('\n\n'));
          }
          const addHtml = typeof data.additional === 'string' ? data.additional : '';
          if (addHtml) descParts.push(htmlToMd(addHtml, origUrl).markdown.trim());
          const bodyMd = descParts.filter(Boolean).join('\n\n');
          if (!pay) pay = parsePayFromText(`${String(data.salaryDescriptionPlain ?? '')} ${bodyMd}`);

          const createdMs = typeof data.createdAt === 'number' ? new Date(data.createdAt).toISOString() : undefined;
          const applyUrl = typeof data.applyUrl === 'string' && data.applyUrl.startsWith('http') ? data.applyUrl : `${origUrl.replace(/\/+$/, '')}/apply`;

          const jp: StructuredJobPosting = {
            title,
            hiringOrganization: co,
            ...(allLocs.length > 0 ? { jobLocation: allLocs } : {}),
            workplaceType: wp,
            baseSalary: pay?.basis === 'base' ? pay : null,
            pay,
            ...(createdMs ? { datePosted: createdMs } : {}),
            ...(commitment ? { employmentType: commitment } : {}),
            url: origUrl,
            applyUrl,
            source: 'lever',
          };
          const headerMd = formatJobPostingHeaderMarkdown(jp);
          return {
            title: `${title} @ ${co}`,
            ...(createdMs ? { publishedTime: createdMs } : {}),
            jobPosting: jp,
            markdown: [`# ${title} @ ${co}`, ...(headerMd ? [headerMd] : []), bodyMd].filter(Boolean).join('\n\n'),
            links: [applyUrl],
          };
        },
      };
    }
  }

  // Workable (`apply.workable.com/<org>[/j/<shortcode>]`)
  if (host === 'apply.workable.com' && parts.length >= 1) {
    const org = parts[0]!;
    if (/^[A-Za-z0-9_-]{1,80}$/.test(org) && !['api', 'j', 'assets', 'static'].includes(org.toLowerCase())) {
      if (parts.length === 1) {
        return {
          id: 'workable-board',
          fetchUrl: `https://apply.workable.com/api/v1/widget/accounts/${encodeURIComponent(org)}?details=true`,
          method: 'GET',
          kind: 'json',
          accept: 'application/json',
          format: (rawBody) => {
            const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
            const rawJobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : null;
            if (!rawJobs) return null;
            const orgName = typeof data?.name === 'string' && data.name ? data.name.trim() : org;
            const merged = new Map<string, StructuredJobRecord>();
            for (const j of rawJobs) {
              const code = String(j.shortcode ?? '').trim();
              const jTitle = String(j.title ?? '').trim();
              if (!code || !jTitle) continue;
              const loc = [j.city, j.state, j.country].filter((x) => typeof x === 'string' && x).join(', ');
              const isRemote = Boolean(j.telecommuting) || /remote/i.test(String(j.workplace_type ?? ''));
              const wp: WorkplaceType = isRemote ? 'remote' : inferWorkplaceType(`${String(j.workplace_type ?? '')} ${loc}`);
              const jUrl = typeof j.url === 'string' && j.url.startsWith('https://') ? j.url : `https://apply.workable.com/${org}/j/${code}/`;
              const existing = merged.get(code);
              if (existing) {
                if (loc && !existing.locations.includes(loc)) existing.locations.push(loc);
                if (isRemote) existing.workplaceType = 'remote';
              } else {
                const descPlain = stripTagsPlain(String(j.description ?? ''));
                merged.set(code, {
                  title: jTitle,
                  company: orgName,
                  url: jUrl,
                  applyUrl: `${jUrl.replace(/\/+$/, '')}/apply/`,
                  workplaceType: wp,
                  locations: loc ? [loc] : [],
                  pay: parsePayFromText(descPlain),
                  postedAt: typeof j.published_on === 'string' ? j.published_on : null,
                  source: 'workable',
                });
              }
            }
            const records = [...merged.values()];
            const lines = [`# ${orgName} — Workable Job Board (${records.length} open roles)`];
            const links: string[] = [];
            for (const r of records) {
              links.push(r.url);
              const meta = [r.locations.join('; '), r.workplaceType !== 'unknown' ? r.workplaceType : ''].filter(Boolean).join(' · ');
              lines.push(`- **[${r.title}](${r.url})**${meta ? ` — ${meta}` : ''}`);
            }
            return {
              title: `${orgName} Jobs (${records.length})`,
              markdown: lines.join('\n'),
              links,
              jobs: records,
            };
          },
        };
      }
      if (parts[1] === 'j' && parts[2] && /^[A-Za-z0-9_-]{4,24}$/.test(parts[2])) {
        const code = parts[2];
        return {
          id: 'workable-job',
          fetchUrl: `https://apply.workable.com/api/v2/accounts/${encodeURIComponent(org)}/jobs/${encodeURIComponent(code)}`,
          method: 'GET',
          kind: 'json',
          accept: 'application/json',
          format: (rawBody, origUrl, htmlToMd) => {
            const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
            if (!data || typeof data.title !== 'string') return null;
            const title = data.title.trim();
            const locObj = (data.location as Record<string, unknown> | undefined) ?? {};
            const loc = [locObj.city, locObj.region, locObj.country].filter((x) => typeof x === 'string' && x).join(', ');
            const wp: WorkplaceType = locObj.telecommuting ? 'remote' : inferWorkplaceType(`${String(data.workplace ?? '')} ${loc}`);
            const bodyParts: string[] = [];
            for (const [label, field] of [
              ['', data.description],
              ['Requirements', data.requirements],
              ['Benefits', data.benefits],
            ] as const) {
              if (typeof field === 'string' && field.trim()) {
                const md = htmlToMd(field, origUrl).markdown.trim();
                bodyParts.push(label ? `## ${label}\n\n${md}` : md);
              }
            }
            const bodyMd = bodyParts.join('\n\n');
            const salObj = data.salary as Record<string, unknown> | undefined;
            let pay: NormalizedPay | null = null;
            if (salObj && (typeof salObj.salary_from === 'number' || typeof salObj.salary_to === 'number')) {
              pay = {
                min: typeof salObj.salary_from === 'number' ? salObj.salary_from : null,
                max: typeof salObj.salary_to === 'number' ? salObj.salary_to : null,
                currency: typeof salObj.salary_currency === 'string' ? salObj.salary_currency.toUpperCase() : 'USD',
                period: 'year',
                basis: 'base',
              };
            }
            if (!pay) pay = parsePayFromText(bodyMd);
            const published = typeof data.published === 'string' ? data.published : undefined;
            const applyUrl = `https://apply.workable.com/${org}/j/${code}/apply/`;
            const jp: StructuredJobPosting = {
              title,
              hiringOrganization: org,
              ...(loc ? { jobLocation: [loc] } : {}),
              workplaceType: wp,
              baseSalary: pay?.basis === 'base' ? pay : null,
              pay,
              ...(published ? { datePosted: published } : {}),
              url: origUrl,
              applyUrl,
              source: 'workable',
            };
            const headerMd = formatJobPostingHeaderMarkdown(jp);
            return {
              title: `${title} @ ${org}`,
              ...(published ? { publishedTime: published } : {}),
              jobPosting: jp,
              markdown: [`# ${title} @ ${org}`, ...(headerMd ? [headerMd] : []), bodyMd].filter(Boolean).join('\n\n'),
              links: [applyUrl],
            };
          },
        };
      }
    }
  }

  // Gem (`jobs.gem.com/<org>`)
  if (host === 'jobs.gem.com' && parts.length === 1 && /^[A-Za-z0-9_-]{1,80}$/.test(parts[0]!)) {
    const org = parts[0]!;
    return {
      id: 'gem-board',
      fetchUrl: `https://api.gem.com/job_board/v0/${encodeURIComponent(org)}/job_posts/`,
      method: 'GET',
      kind: 'json',
      accept: 'application/json',
      format: (rawBody) => {
        const parsed = safeJsonParse(rawBody);
        if (!Array.isArray(parsed)) return null;
        const posts = parsed as Array<Record<string, unknown>>;
        const records: StructuredJobRecord[] = [];
        const links: string[] = [];
        const lines = [`# ${org} — Gem Job Board (${posts.length} open roles)`];
        for (const p of posts.slice(0, 100)) {
          const pTitle = String(p.title ?? '').trim();
          if (!pTitle) continue;
          const loc = String((p.location as Record<string, unknown> | undefined)?.name ?? '').trim();
          const wp = inferWorkplaceType(`${String(p.location_type ?? '')} ${loc}`);
          const pUrl = typeof p.absolute_url === 'string' && p.absolute_url.startsWith('https://') ? p.absolute_url : `https://jobs.gem.com/${org}/${String(p.id ?? '')}`;
          links.push(pUrl);
          records.push({
            title: pTitle,
            company: org,
            url: pUrl,
            applyUrl: pUrl,
            workplaceType: wp,
            locations: loc ? [loc] : [],
            pay: parsePayFromText(String(p.content_plain ?? '')),
            postedAt: typeof p.first_published_at === 'string' ? p.first_published_at : null,
            source: 'gem',
          });
          lines.push(`- **[${pTitle}](${pUrl})**${loc ? ` — ${loc}` : ''}`);
        }
        return { title: `${org} Jobs (${records.length})`, markdown: lines.join('\n'), links, jobs: records };
      },
    };
  }

  // Rippling (`ats.rippling.com/[locale/]<org>/jobs` — merge rows by `uuid`!)
  if (host === 'ats.rippling.com' && parts.length >= 1) {
    const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2 ? 1 : 0;
    const org = parts[idx]!;
    const rest = parts.slice(idx + 1);
    if (org && /^[A-Za-z0-9_-]{1,80}$/.test(org) && (rest.length === 0 || (rest.length === 1 && rest[0] === 'jobs'))) {
      return {
        id: 'rippling-board',
        fetchUrl: `https://api.rippling.com/platform/api/ats/v1/board/${encodeURIComponent(org)}/jobs`,
        method: 'GET',
        kind: 'json',
        accept: 'application/json',
        format: (rawBody) => {
          const parsed = safeJsonParse(rawBody);
          const items = Array.isArray(parsed)
            ? (parsed as Array<Record<string, unknown>>)
            : Array.isArray((parsed as Record<string, unknown> | undefined)?.results)
              ? ((parsed as Record<string, unknown>).results as Array<Record<string, unknown>>)
              : null;
          if (!items) return null;
          const byUuid = new Map<string, StructuredJobRecord>();
          for (const item of items) {
            const uuid = String(item.uuid || item.id || '').trim();
            const jTitle = String(item.name || item.title || '').trim();
            if (!uuid || !jTitle) continue;
            const workLoc = item.workLocation as Record<string, unknown> | string | undefined;
            const locLabel = typeof workLoc === 'string' ? workLoc : typeof workLoc?.label === 'string' ? workLoc.label : '';
            const jUrl = typeof item.url === 'string' && item.url.startsWith('https://') ? item.url : `https://ats.rippling.com/${org}/jobs/${uuid}`;
            const existing = byUuid.get(uuid);
            if (existing) {
              if (locLabel && !existing.locations.includes(locLabel)) existing.locations.push(locLabel);
              if (/remote/i.test(locLabel)) existing.workplaceType = 'remote';
            } else {
              byUuid.set(uuid, {
                title: jTitle,
                company: org,
                url: jUrl,
                applyUrl: jUrl,
                workplaceType: inferWorkplaceType(`${locLabel} ${jTitle}`),
                locations: locLabel ? [locLabel] : [],
                pay: null,
                postedAt: null,
                source: 'rippling',
              });
            }
          }
          const records = [...byUuid.values()];
          const links = records.map((r) => r.url);
          const lines = [`# ${org} — Rippling Job Board (${records.length} open roles)`];
          for (const r of records) {
            lines.push(`- **[${r.title}](${r.url})**${r.locations.length > 0 ? ` — ${r.locations.join('; ')}` : ''}`);
          }
          return { title: `${org} Jobs (${records.length})`, markdown: lines.join('\n'), links, jobs: records };
        },
      };
    }
  }

  return null;
}

/** `P2`: Detects Workday's `{"widget":"redirect","url":"/Workday","externalSpa":true}` stub response. */
export function detectWorkdayRedirectStub(rawBody: string, baseUrl: string): { redirectUrl: string } | null {
  const parsed = safeJsonParse(rawBody);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  if (obj.widget === 'redirect' && typeof obj.url === 'string' && obj.url.trim()) {
    try {
      return { redirectUrl: new URL(obj.url.trim(), baseUrl).toString() };
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * `P3`: Determines whether a `<script>`-bearing HTML page yielded a thin / filter-only shell that should automatically
 * upgrade to headless Chromium in `auto` mode (`< 80` words OR `> 60%` link-only / short filter-label lines).
 */
export function isThinScriptedPage(rawHtml: string, extractedMarkdown: string): boolean {
  if (!/<script\b/i.test(rawHtml)) return false;
  const trimmed = extractedMarkdown.trim();
  const words = (trimmed.match(/[\p{L}\p{N}_]+/gu) ?? []).length;
  if (words < 80) return true;

  const lines = trimmed
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !/^#{1,6}\s/.test(l));
  if (lines.length >= 6) {
    let navOrLinkLines = 0;
    for (const ln of lines) {
      const withoutLinks = ln.replace(/\[([^\]]*)\]\([^)]+\)/g, '').replace(/^[-*+]\s*/, '').trim();
      const lineWords = (ln.match(/[\p{L}\p{N}_]+/gu) ?? []).length;
      if (withoutLinks.length <= 4 || lineWords <= 3) {
        navOrLinkLines++;
      }
    }
    if (navOrLinkLines / lines.length > 0.6) return true;
  }
  return false;
}

function parseJsonFilterClauses(filterStr: string): Array<{ field: string; op: '=' | '!=' | '~'; value: string }> {
  const clauses: Array<{ field: string; op: '=' | '!=' | '~'; value: string }> = [];
  for (const rawPart of filterStr.split(/\s*(?:&&|,)\s*/)) {
    const m = /^([A-Za-z0-9_.-]+)\s*(!=|~|=)\s*(.+)$/.exec(rawPart.trim());
    if (!m) continue;
    const field = m[1]!;
    const op = m[2] as '=' | '!=' | '~';
    const value = m[3]!.trim().replace(/^(['"])([\s\S]*)\1$/, '$2');
    clauses.push({ field, op, value });
  }
  return clauses;
}

function readNestedField(obj: Record<string, unknown>, path: string): string {
  let cur: unknown = obj;
  for (const seg of path.split('.')) {
    if (cur && typeof cur === 'object' && !Array.isArray(cur)) {
      cur = (cur as Record<string, unknown>)[seg];
    } else {
      return '';
    }
  }
  if (cur === null || cur === undefined) return '';
  if (typeof cur === 'object') return JSON.stringify(cur);
  return String(cur);
}

/**
 * `P5`: Detects JSON responses whose root (or `.jobs`, `.postings`, `.data`, `.results`, `.items`, `.jobPostings`)
 * is an array of records, applies optional `jsonFilter`, converts HTML string fields into clean Markdown, and returns
 * **one self-contained chunk per record** so fields (such as salary ranges) never bleed across adjacent records.
 */
export function chunkJsonRecords(params: {
  rawBody: string;
  contentType?: unknown;
  url?: string;
  jsonFilter?: string;
  htmlToMd: HtmlToMdFn;
}): {
  title: string;
  totalRecords: number;
  matchedRecords: number;
  chunks: Array<{ ordinal: number; heading: string; text: string; recordId?: string }>;
  markdown: string;
} | null {
  const ct = typeof params.contentType === 'string' ? params.contentType.toLowerCase() : '';
  const trimmed = params.rawBody.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;
  if (!ct.includes('json') && !/\.json(?:$|[?#])|\/api\/|posting-api|\/v\d+\//i.test(params.url ?? '')) {
    if (!trimmed.startsWith('[')) return null;
  }

  const parsed = safeJsonParse(trimmed);
  if (!parsed) return null;

  let records: Array<Record<string, unknown>> | null = null;
  let containerTitle = 'JSON Records';
  if (Array.isArray(parsed) && parsed.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
    records = parsed as Array<Record<string, unknown>>;
  } else if (parsed && typeof parsed === 'object') {
    const rootObj = parsed as Record<string, unknown>;
    if (typeof rootObj.organizationName === 'string') containerTitle = rootObj.organizationName;
    for (const arrKey of ['jobs', 'postings', 'jobPostings', 'results', 'data', 'items']) {
      const cand = rootObj[arrKey];
      if (Array.isArray(cand) && cand.length > 0 && cand.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
        records = cand as Array<Record<string, unknown>>;
        break;
      }
    }
  }
  if (!records || records.length === 0) return null;

  const clauses = params.jsonFilter ? parseJsonFilterClauses(params.jsonFilter) : [];
  const filtered =
    clauses.length === 0
      ? records
      : records.filter((rec) =>
          clauses.every((c) => {
            const val = readNestedField(rec, c.field);
            if (c.op === '=') return val.toLowerCase() === c.value.toLowerCase();
            if (c.op === '!=') return val.toLowerCase() !== c.value.toLowerCase();
            const safeRe = compileSafeUserRegex(c.value, 'i');
            if (!safeRe) {
              return val.toLowerCase().includes(c.value.toLowerCase());
            }
            return safeRe.test(val);
          }),
        );

  const chunks: Array<{ ordinal: number; heading: string; text: string; recordId?: string }> = [];
  for (let i = 0; i < filtered.length; i++) {
    const rec = filtered[i]!;
    const recId = String(rec.id ?? rec.reqId ?? rec.jobId ?? rec.slug ?? i + 1);
    const recTitle = String(rec.title ?? rec.text ?? rec.name ?? `Record ${i + 1}`).trim();
    const heading = recId && recId !== recTitle ? `${recTitle} [${recId}]` : recTitle;

    const lines: string[] = [`## ${heading}`];
    // Standardize Ashby / Lever / Greenhouse pay inline on job records so pay stays bound to THIS record only!
    let pay: NormalizedPay | null = null;
    if (rec.compensation) {
      pay = parseAshbyPay(rec, String(rec.descriptionPlain ?? ''));
    } else if (rec.salaryRange && typeof rec.salaryRange === 'object') {
      const sr = rec.salaryRange as Record<string, unknown>;
      const period = normalizePeriod(sr.interval ?? 'year');
      const min = scaleShorthandAnnualAmount(typeof sr.min === 'number' ? sr.min : null, period);
      const max = scaleShorthandAnnualAmount(typeof sr.max === 'number' ? sr.max : null, period);
      if (min !== null || max !== null) {
        pay = {
          min,
          max: max ?? min,
          currency: typeof sr.currency === 'string' && sr.currency ? sr.currency.toUpperCase() : 'USD',
          period,
          basis: inferPayBasis(String(rec.salaryDescriptionPlain ?? '')),
        };
      }
    } else if (Array.isArray(rec.pay_input_ranges) && rec.pay_input_ranges[0] && typeof rec.pay_input_ranges[0] === 'object') {
      const pr = rec.pay_input_ranges[0] as Record<string, unknown>;
      const minCents = typeof pr.min_cents === 'number' ? Math.round(pr.min_cents / 100) : null;
      const maxCents = typeof pr.max_cents === 'number' ? Math.round(pr.max_cents / 100) : null;
      if (minCents || maxCents) {
        pay = {
          min: minCents,
          max: maxCents ?? minCents,
          currency: typeof pr.currency_type === 'string' ? pr.currency_type.toUpperCase() : 'USD',
          period: 'year',
          basis: inferPayBasis(`${String(pr.title ?? '')} ${String(pr.blurb ?? '')}`),
        };
      }
    }
    if (pay) lines.push(`- **Compensation**: ${formatNormalizedPay(pay)}`);

    const scalarFields = ['id', 'location', 'locationsText', 'workplaceType', 'department', 'team', 'employmentType', 'publishedAt', 'postedOn', 'jobUrl', 'applyUrl', 'hostedUrl', 'absolute_url'];
    for (const fk of scalarFields) {
      const fv = rec[fk];
      if (typeof fv === 'string' && fv.trim()) {
        lines.push(`- **${fk}**: ${fv.trim()}`);
      }
    }
    if (rec.categories && typeof rec.categories === 'object') {
      const cats = rec.categories as Record<string, unknown>;
      for (const [ck, cv] of Object.entries(cats)) {
        if (typeof cv === 'string' && cv.trim()) lines.push(`- **${ck}**: ${cv.trim()}`);
      }
    }

    // Convert HTML fields inside the record into clean Markdown (never leave raw `<p>` / `<li>` / `&amp;` HTML strings!)
    let addedRichBody = false;
    for (const htmlKey of ['descriptionHtml', 'content', 'description', 'body_html', 'jobDescription']) {
      const hv = rec[htmlKey];
      if (typeof hv === 'string' && hv.trim()) {
        const decoded = /<[a-z][\s\S]*>/i.test(hv) || /&(?:lt|gt|amp|nbsp|#\d+);/i.test(hv) ? decodeEntitiesBasic(hv) : hv;
        const md = /<[a-z][\s\S]*>/i.test(decoded) ? params.htmlToMd(decoded, params.url).markdown.trim() : decoded.trim();
        if (md) {
          lines.push('', md);
          addedRichBody = true;
          break;
        }
      }
    }
    if (!addedRichBody && typeof rec.descriptionPlain === 'string' && rec.descriptionPlain.trim()) {
      lines.push('', rec.descriptionPlain.trim());
      addedRichBody = true;
    }
    if (Array.isArray(rec.lists)) {
      for (const lst of rec.lists as Array<Record<string, unknown>>) {
        const lt = typeof lst?.text === 'string' ? lst.text.trim() : '';
        const lc = typeof lst?.content === 'string' ? params.htmlToMd(`<ul>${lst.content}</ul>`, params.url).markdown.trim() : '';
        if (lt || lc) lines.push('', [lt ? `### ${lt}` : '', lc].filter(Boolean).join('\n'));
      }
    }
    if (!addedRichBody && lines.length <= 2) {
      // Generic non-job JSON object: render clean key-value bullets
      for (const [k, v] of Object.entries(rec)) {
        if (v === null || v === undefined || k === 'title' || k === 'name' || k === 'id') continue;
        if (typeof v === 'string') {
          const cleanV = /<[a-z][\s\S]*>/i.test(v) ? params.htmlToMd(v, params.url).markdown.trim() : v.trim();
          if (cleanV) lines.push(`- **${k}**: ${cleanV.slice(0, 1200)}`);
        } else if (typeof v === 'number' || typeof v === 'boolean') {
          lines.push(`- **${k}**: ${String(v)}`);
        }
      }
    }

    chunks.push({
      ordinal: i,
      heading,
      text: lines.join('\n').trim(),
      recordId: recId,
    });
  }

  return {
    title: `${containerTitle} (${filtered.length} of ${records.length} records)`,
    totalRecords: records.length,
    matchedRecords: filtered.length,
    chunks,
    markdown: chunks.map((c) => c.text).join('\n\n---\n\n'),
  };
}

/**
 * `P9`: Flags material URL redirects (beyond scheme, `www.`, or trailing slash) and warns when role/search/query
 * filters on a listing URL may have been dropped (`filtersMayBeLost: true`).
 */
export function analyzeUrlRedirect(requestedUrl: string, finalUrl?: string): RedirectAnalysis {
  if (!finalUrl || !requestedUrl) return { redirected: false };
  try {
    const reqU = new URL(requestedUrl);
    const finU = new URL(finalUrl);
    const normHost = (h: string) => h.toLowerCase().replace(/^www\./, '').replace(/\.+$/, '');
    const normPath = (p: string) => (p.length > 1 ? p.replace(/\/+$/, '') : '/');

    const sameHost = normHost(reqU.hostname) === normHost(finU.hostname);
    const reqPath = normPath(reqU.pathname);
    const finPath = normPath(finU.pathname);
    const sameQuery = reqU.search === finU.search;

    if (sameHost && reqPath.toLowerCase() === finPath.toLowerCase() && sameQuery) {
      return { redirected: false };
    }

    const reqDepth = reqPath.split('/').filter(Boolean).length;
    const finDepth = finPath.split('/').filter(Boolean).length;
    const hadFilterSignals =
      reqU.searchParams.size > 0 ||
      /\/(?:role|roles|search|category|department|team|location|tag|filter|q)\b/i.test(reqPath);
    const collapsedToGeneric =
      finDepth < reqDepth ||
      (reqU.searchParams.size > 0 && finU.searchParams.size === 0) ||
      /^\/(?:jobs?|careers?|remote|openings?)?$/i.test(finPath);
    const filtersMayBeLost = Boolean(hadFilterSignals && collapsedToGeneric);

    const fromLabel = sameHost ? `${reqPath}${reqU.search}` : reqU.toString();
    const toLabel = sameHost ? `${finPath}${finU.search}` : finU.toString();
    const redirectNote = filtersMayBeLost
      ? `Redirected from ${fromLabel} to ${toLabel}; role or search filters from the original URL may have been lost.`
      : `Redirected from ${fromLabel} to ${toLabel}.`;

    return {
      redirected: true,
      redirectNote,
      ...(filtersMayBeLost ? { filtersMayBeLost: true } : {}),
    };
  } catch {
    return { redirected: false };
  }
}

/**
 * `P10`: Builds a structured, ethical `blocked: { reason, host, suggestion }` hint when a request is refused by
 * `robots.txt` or a bot challenge — never bypassing blocks, always guiding the agent to clean public sources.
 */
export function buildBlockedInfo(urlStr: string, outcome?: unknown, problem?: unknown, status?: unknown): BlockedSuggestion | null {
  const outStr = typeof outcome === 'string' ? outcome.toLowerCase() : '';
  const probStr = typeof problem === 'string' ? problem : '';
  const isRobots = /robots\.txt/i.test(probStr) || outStr === 'robots_disallowed';
  const isChallenge =
    outStr === 'challenge' ||
    /challenge|cf-mitigated|turnstile|captcha|verify you are human/i.test(probStr) ||
    (status === 403 && /cloudflare|bot|forbidden/i.test(probStr));

  if (!isRobots && !isChallenge) return null;

  let host = '';
  let pathname = '';
  try {
    const u = new URL(urlStr);
    host = u.hostname.toLowerCase();
    pathname = u.pathname;
  } catch {
    // ignore
  }

  const reason: 'robots' | 'challenge' = isRobots ? 'robots' : 'challenge';

  if (/api\.smartrecruiters\.com/i.test(host)) {
    return {
      reason,
      host,
      suggestion:
        'api.smartrecruiters.com disallows automated access in robots.txt. Scrape the public HTML posting on `https://jobs.smartrecruiters.com/{Company}/{JobId}` instead (it embeds structured schema.org JobPosting metadata).',
    };
  }

  if (/(?:^|\.)(?:linkedin\.com|indeed\.com|dice\.com|icims\.com|startup\.jobs|glassdoor\.com|ziprecruiter\.com)$/i.test(host)) {
    return {
      reason,
      host,
      suggestion:
        `${host} blocks automated ${reason === 'robots' ? 'crawlers via robots.txt' : 'requests with an anti-bot challenge'}. ` +
        'Run `jobs` or `search` with `site:job-boards.greenhouse.io OR site:jobs.ashbyhq.com OR site:jobs.lever.co OR site:myworkdayjobs.com "<company> <role>"` (or `builtin.com`) to read the employer\'s official posting directly.',
    };
  }

  if (host === 'pypi.org' && /\/json\/?$/i.test(pathname)) {
    return {
      reason,
      host,
      suggestion: 'pypi.org disallows /pypi/*/json in robots.txt; scrape https://pypi.org/project/<package>/ instead.',
    };
  }

  if (host === 'openstreetmap.org' || host.endsWith('.openstreetmap.org')) {
    return {
      reason,
      host,
      suggestion:
        'openstreetmap.org disallows /node/, /way/, /relation/, and /api/ in robots.txt to protect community servers. Query Nominatim, the Overpass API, or bulk Planet.osm extracts instead.',
    };
  }

  return {
    reason,
    ...(host ? { host } : {}),
    suggestion:
      reason === 'robots'
        ? `${host || 'This host'} disallows this path in robots.txt. Use \`search\` for official documentation, public API endpoints, or search snippets instead.`
        : `${host || 'This host'} returned an anti-bot challenge. Do not retry this URL; use \`search\` to find an official mirror, package registry, or primary source.`,
  };
}

export interface JobsToolPayload {
  query?: unknown;
  company?: unknown;
  domains?: unknown;
  remote?: unknown;
  locations?: unknown;
  minBase?: unknown;
  postedWithinDays?: unknown;
  limit?: unknown;
  includeBuiltIn?: unknown;
  exclude?: unknown;
  target?: unknown;
  site?: unknown;
}

const JUNK_ATS_SLUGS = new Set([
  'embed',
  '__assets__',
  'api',
  'v0',
  'v1',
  'v2',
  'v3',
  'static',
  'assets',
  'cdn',
  'js',
  'css',
  'www',
  'app',
  'resources',
  'help',
  'docs',
  'documentation',
  'developers',
  'support',
  'blog',
  'status',
  'login',
  'signin',
  'internal',
  'careers',
  'jobs',
  'favicon.ico',
]);

function isValidAtsSlug(slug: string): boolean {
  const parts = slug.trim().split('/');
  if (parts.length < 1 || parts.length > 2) return false;
  return parts.every((seg) => {
    const s = seg.toLowerCase();
    if (!s || s.length < 2 || s.length > 80) return false;
    if (JUNK_ATS_SLUGS.has(s) || s.startsWith('internal-') || s.startsWith('_')) return false;
    return /^[a-z0-9][a-z0-9_.-]*$/i.test(s);
  });
}

/**
 * Classifies ATS board response status into 4 deterministic states (`ok` | `empty_board` | `wrong_slug` | `blocked_or_down`)
 * so callers never confuse an empty board (`0` open roles) with a wrong slug (404 / vendor-homepage redirect) or a 403/429 block.
 */
export function classifyAtsBoardStatus(params: {
  httpStatus: number;
  requestedUrl: string;
  finalUrl?: string;
  contentState?: string;
  jobCount?: number;
}): AtsBoardStatus {
  const { httpStatus, requestedUrl, finalUrl, contentState, jobCount = 0 } = params;
  if (httpStatus === 404 || httpStatus === 410 || contentState === 'soft_404') {
    return 'wrong_slug';
  }
  if (httpStatus === 401 || httpStatus === 403 || httpStatus === 422 || httpStatus === 429 || httpStatus >= 500 || httpStatus === 0) {
    return 'blocked_or_down';
  }
  if (finalUrl) {
    try {
      const reqU = new URL(requestedUrl);
      const finU = new URL(finalUrl);
      const finHost = finU.hostname.toLowerCase();
      // BambooHR / Breezy / JazzHR redirect invalid org subdomains to vendor marketing homepages with HTTP 200!
      if (
        (reqU.hostname.toLowerCase() !== finHost && /^(?:www\.)?(?:bamboohr\.com|breezy\.hr|applytojob\.com|recruitee\.com|pinpointhq\.com)$/i.test(finHost)) ||
        (finHost.includes('greenhouse.io') && finU.searchParams.get('error') === 'true')
      ) {
        return 'wrong_slug';
      }
    } catch {
      // ignore
    }
  }
  return jobCount > 0 ? 'ok' : 'empty_board';
}

/**
 * Scans a company `/careers` or `/jobs` page (`finalUrl`, raw HTML, scripts, iframes, and links) for 15+ ATS platforms
 * whose board slugs often differ from the company's marketing domain (e.g. `f5.com` -> `ffive`, `paloaltonetworks.com` -> `panwexternalcareers`).
 */
export function discoverAtsBoardsFromHtml(params: {
  sourceUrl: string;
  finalUrl?: string;
  rawHtml?: string;
  links?: string[];
}): DiscoveredAtsBoard[] {
  const { sourceUrl, finalUrl = '', rawHtml = '', links = [] } = params;
  const corpus = [finalUrl, ...links, rawHtml.replace(/&(?:amp|#0*38|#x0*26);/gi, '&')].join('\n');
  const found = new Map<string, DiscoveredAtsBoard>();

  const addBoard = (platform: string, slug: string, boardUrl: string) => {
    if (!isValidAtsSlug(slug)) return;
    const key = `${platform}:${slug.toLowerCase()}`;
    if (!found.has(key)) {
      found.set(key, { platform, slug, boardUrl, discoveredFrom: sourceUrl });
    }
  };

  // 1. Greenhouse (US & EU, including `?for=<slug>` embed scripts & `boards-api.greenhouse.io/v1/boards/<slug>`!)
  for (const m of corpus.matchAll(
    /https?:\/\/((?:job-boards|boards|eu-boards|job-boards\.eu)\.greenhouse\.io)\/(?:embed\/job_board(?:\/js)?\?for=([A-Za-z0-9_-]+)|([A-Za-z0-9_-]+))/gi,
  )) {
    const ghHost = m[1]!.toLowerCase();
    const slug = m[2] || m[3] || '';
    const canonicalHost = ghHost.includes('eu') ? 'job-boards.eu.greenhouse.io' : 'job-boards.greenhouse.io';
    addBoard('greenhouse', slug, `https://${canonicalHost}/${slug}`);
  }
  for (const m of corpus.matchAll(/https?:\/\/(boards-api(?:\.eu)?\.greenhouse\.io)\/v1\/boards\/([A-Za-z0-9_-]+)/gi)) {
    const canonicalHost = m[1]!.toLowerCase().includes('.eu.') ? 'job-boards.eu.greenhouse.io' : 'job-boards.greenhouse.io';
    addBoard('greenhouse', m[2]!, `https://${canonicalHost}/${m[2]!}`);
  }

  // 2. Ashby (`jobs.ashbyhq.com/<org>` or `api.ashbyhq.com/posting-api/job-board/<org>`)
  for (const m of corpus.matchAll(/https?:\/\/(?:jobs\.ashbyhq\.com|api\.ashbyhq\.com\/posting-api\/job-board)\/([A-Za-z0-9_.-]+)/gi)) {
    addBoard('ashby', m[1]!, `https://jobs.ashbyhq.com/${m[1]!}`);
  }

  // 3. Lever (US & EU)
  for (const m of corpus.matchAll(/https?:\/\/(jobs(?:\.eu)?\.lever\.co)\/([A-Za-z0-9_.-]+)/gi)) {
    addBoard('lever', m[2]!, `https://${m[1]!.toLowerCase()}/${m[2]!}`);
  }

  // 4. Workday (`<tenant>.wd<N>.myworkdayjobs.com/[en-US/]<site>`)
  for (const m of corpus.matchAll(/https?:\/\/(([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com)\/([A-Za-z0-9_/-]+)/gi)) {
    const wdHost = m[1]!.toLowerCase();
    const tenant = m[2]!;
    const segs = m[3]!.split('/').filter(Boolean);
    const siteIdx = segs[0] && /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(segs[0]) && segs.length >= 2 ? 1 : 0;
    const site = segs[siteIdx] ?? '';
    if (site && site.toLowerCase() !== 'wday' && isValidAtsSlug(tenant)) {
      addBoard('workday', `${tenant}/${site}`, `https://${wdHost}/${site}`);
    }
  }

  // 5. Workable (`apply.workable.com/<org>` or `www.workable.com/j/...`)
  for (const m of corpus.matchAll(/https?:\/\/apply\.workable\.com\/([A-Za-z0-9_-]+)/gi)) {
    addBoard('workable', m[1]!, `https://apply.workable.com/${m[1]!}/`);
  }

  // 6. Gem (`jobs.gem.com/<org>`)
  for (const m of corpus.matchAll(/https?:\/\/jobs\.gem\.com\/([A-Za-z0-9_-]+)/gi)) {
    addBoard('gem', m[1]!, `https://jobs.gem.com/${m[1]!}`);
  }

  // 7. Rippling (`ats.rippling.com/[locale/]<org>/jobs`)
  for (const m of corpus.matchAll(/https?:\/\/ats\.rippling\.com\/(?:[a-z]{2}(?:-[A-Za-z]{2,4})?\/)?([A-Za-z0-9_-]+)/gi)) {
    addBoard('rippling', m[1]!, `https://ats.rippling.com/${m[1]!}/jobs`);
  }

  // 8. Pinpoint (`<org>.pinpointhq.com`)
  for (const m of corpus.matchAll(/https?:\/\/([a-z0-9-]+)\.pinpointhq\.com\b/gi)) {
    addBoard('pinpoint', m[1]!, `https://${m[1]!.toLowerCase()}.pinpointhq.com/`);
  }

  // 9. Teamtailor (`<org>[.na].teamtailor.com`)
  for (const m of corpus.matchAll(/https?:\/\/(([a-z0-9-]+)(?:\.[a-z]{2})?\.teamtailor\.com)\b/gi)) {
    addBoard('teamtailor', m[2]!, `https://${m[1]!.toLowerCase()}/`);
  }

  // 10. BambooHR (`<org>.bamboohr.com/careers`)
  for (const m of corpus.matchAll(/https?:\/\/([a-z0-9-]+)\.bamboohr\.com\/(?:careers|jobs)/gi)) {
    addBoard('bamboohr', m[1]!, `https://${m[1]!.toLowerCase()}.bamboohr.com/careers`);
  }

  // 11. Breezy HR, Recruitee, JazzHR, Personio, SmartRecruiters, Jobvite
  for (const m of corpus.matchAll(/https?:\/\/([a-z0-9-]+)\.breezy\.hr\b/gi)) {
    addBoard('breezy', m[1]!, `https://${m[1]!.toLowerCase()}.breezy.hr/`);
  }
  for (const m of corpus.matchAll(/https?:\/\/([a-z0-9-]+)\.recruitee\.com\b/gi)) {
    addBoard('recruitee', m[1]!, `https://${m[1]!.toLowerCase()}.recruitee.com/`);
  }
  for (const m of corpus.matchAll(/https?:\/\/([a-z0-9-]+)\.applytojob\.com\b/gi)) {
    addBoard('jazzhr', m[1]!, `https://${m[1]!.toLowerCase()}.applytojob.com/`);
  }
  for (const m of corpus.matchAll(/https?:\/\/(([a-z0-9-]+)\.jobs\.personio\.(?:de|com))\b/gi)) {
    addBoard('personio', m[2]!, `https://${m[1]!.toLowerCase()}/`);
  }
  for (const m of corpus.matchAll(/https?:\/\/jobs\.smartrecruiters\.com\/([A-Za-z0-9_-]+)/gi)) {
    addBoard('smartrecruiters', m[1]!, `https://jobs.smartrecruiters.com/${m[1]!}`);
  }
  for (const m of corpus.matchAll(/https?:\/\/jobs\.jobvite\.com\/([A-Za-z0-9_-]+)/gi)) {
    addBoard('jobvite', m[1]!, `https://jobs.jobvite.com/${m[1]!}`);
  }

  return [...found.values()];
}

function canonicalJobKey(company: string, title: string): string {
  const c = company.toLowerCase().replace(/[^a-z0-9]+/g, '');
  const t = title
    .toLowerCase()
    .replace(/\(.*?\)/g, '')
    .replace(/[^a-z0-9]+/g, '');
  return `${c}::${t}`;
}

function inferCompanyFromAtsUrl(urlStr: string): string {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    const parts = u.pathname.split('/').filter(Boolean);
    if (
      (host.includes('greenhouse.io') ||
        host === 'jobs.ashbyhq.com' ||
        host === 'jobs.lever.co' ||
        host === 'jobs.eu.lever.co' ||
        host === 'jobs.smartrecruiters.com' ||
        host === 'apply.workable.com' ||
        host === 'jobs.gem.com' ||
        host === 'ats.rippling.com') &&
      parts[0]
    ) {
      return decodeURIComponent(parts[0]);
    }
    const wd = /^([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com$/i.exec(host);
    if (wd?.[1]) return wd[1];
    const subAts = /^([a-z0-9-]+)\.(?:pinpointhq\.com|bamboohr\.com|breezy\.hr|recruitee\.com|applytojob\.com|teamtailor\.com)$/i.exec(host);
    if (subAts?.[1]) return subAts[1];
    return host.replace(/^(?:www|jobs|careers)\./, '');
  } catch {
    return 'unknown';
  }
}

/**
 * `Section 4`: One-call `jobs` sweep across Greenhouse, Ashby, Lever, Workday, Workable, Gem, Rippling, SmartRecruiters,
 * company-domain -> ATS auto-discovery (`domains`), and optional Built In browser rendering.
 */
export async function executeJobsCall(params: {
  payload: JobsToolPayload;
  env: OptionalStorageBindings & Record<string, unknown>;
  executeSearch: (args: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeScrape: (args: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const { payload, executeSearch, executeScrape } = params;
  const query = typeof payload.query === 'string' ? payload.query.trim() : '';
  const companyFilter = typeof payload.company === 'string' ? payload.company.trim() : '';
  const domainsInput = Array.isArray(payload.domains)
    ? payload.domains
        .filter((d): d is string => typeof d === 'string' && d.trim().length > 0)
        .map((d) => d.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase())
        .filter((d) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d))
        .slice(0, 10)
    : [];

  if (!query && !companyFilter && domainsInput.length === 0) {
    return {
      status: 400,
      body: { ok: false, error: 'missing_query', message: 'Provide at least `query`, `company`, or `domains`.' },
    };
  }

  const wantRemote = payload.remote === true ? true : payload.remote === false ? false : undefined;
  const locationsFilter = Array.isArray(payload.locations)
    ? payload.locations.filter((x): x is string => typeof x === 'string' && x.trim().length > 0).map((s) => s.trim().toLowerCase())
    : [];
  const minBase = typeof payload.minBase === 'number' && Number.isFinite(payload.minBase) && payload.minBase > 0 ? payload.minBase : undefined;
  const postedWithinDays =
    typeof payload.postedWithinDays === 'number' && Number.isFinite(payload.postedWithinDays) && payload.postedWithinDays > 0
      ? payload.postedWithinDays
      : undefined;
  const limit =
    typeof payload.limit === 'number' && Number.isFinite(payload.limit) ? Math.min(50, Math.max(1, Math.floor(payload.limit))) : 20;
  const includeBuiltIn = payload.includeBuiltIn !== false;
  const excludeList = Array.isArray(payload.exclude)
    ? (payload.exclude as Array<Record<string, unknown>>)
        .filter((x) => x && typeof x === 'object')
        .map((x) => ({
          company: typeof x.company === 'string' ? x.company.trim().toLowerCase() : '',
          title: typeof x.title === 'string' ? x.title.trim().toLowerCase() : '',
          url: typeof x.url === 'string' ? x.url.trim().replace(/\/+$/, '').toLowerCase() : '',
        }))
    : [];

  const candidateUrls = new Set<string>();
  const notes: string[] = [];
  const discoveredBoards: DiscoveredAtsBoard[] = [];

  // 1. Company Domain -> ATS Board Auto-Discovery (`domains: ["stripe.com", "f5.com"]`)
  if (domainsInput.length > 0) {
    await Promise.all(
      domainsInput.map(async (dom) => {
        for (const probePath of ['/careers', '/jobs', '/about/careers']) {
          const probeUrl = `https://${dom}${probePath}`;
          const res = await executeScrape({
            url: probeUrl,
            renderMode: 'auto',
            onlyMainContent: false,
            formats: ['markdown', 'rawHtml', 'links'],
            ...(payload.target ? { target: payload.target } : {}),
            ...(payload.site ? { site: payload.site } : {}),
          }).catch(() => null);
          if (!res || res.status !== 200 || res.body?.ok !== true) continue;
          const boards = discoverAtsBoardsFromHtml({
            sourceUrl: probeUrl,
            finalUrl: typeof res.body.finalUrl === 'string' ? res.body.finalUrl : probeUrl,
            rawHtml: typeof res.body.rawHtml === 'string' ? res.body.rawHtml : '',
            links: Array.isArray(res.body.links) ? (res.body.links as string[]) : [],
          });
          if (boards.length > 0) {
            for (const b of boards) {
              discoveredBoards.push(b);
              candidateUrls.add(b.boardUrl);
            }
            return;
          }
        }
        // Fallback when company uses a custom SPA careers portal: probe canonical domain slug across Greenhouse, Ashby & Lever JSON boards
        const baseSlug = dom.split('.')[0]?.toLowerCase() ?? '';
        if (isValidAtsSlug(baseSlug)) {
          const slugProbes: Array<{ platform: string; boardUrl: string }> = [
            { platform: 'greenhouse', boardUrl: `https://boards.greenhouse.io/${baseSlug}` },
            { platform: 'ashby', boardUrl: `https://jobs.ashbyhq.com/${baseSlug}` },
            { platform: 'lever', boardUrl: `https://jobs.lever.co/${baseSlug}` },
          ];
          const probeResults = await Promise.all(
            slugProbes.map(async (sp) => {
              const r = await executeScrape({
                url: sp.boardUrl,
                formats: ['markdown', 'links'],
                ...(payload.target ? { target: payload.target } : {}),
                ...(payload.site ? { site: payload.site } : {}),
              }).catch(() => null);
              return { sp, r };
            }),
          );
          for (const { sp, r } of probeResults) {
            const links = Array.isArray(r?.body?.links) ? (r!.body.links as string[]) : [];
            if (r?.status === 200 && r.body?.ok === true && links.length > 0) {
              discoveredBoards.push({
                platform: sp.platform,
                slug: baseSlug,
                boardUrl: sp.boardUrl,
                discoveredFrom: `slug-probe:${dom}`,
                boardStatus: 'ok',
              });
              candidateUrls.add(sp.boardUrl);
            }
          }
        }
      }),
    );
  }

  const atsGroups = [
    '(site:job-boards.greenhouse.io OR site:boards.greenhouse.io OR site:jobs.ashbyhq.com)',
    '(site:jobs.lever.co OR site:myworkdayjobs.com OR site:jobs.smartrecruiters.com)',
    '(site:apply.workable.com OR site:jobs.gem.com OR site:ats.rippling.com)',
  ];
  const coreTerms = [companyFilter ? `"${companyFilter}"` : '', query ? `"${query}"` : '', wantRemote ? 'remote' : '']
    .filter(Boolean)
    .join(' ');

  if (coreTerms) {
    const searchResponses = await Promise.all(
      atsGroups.map((grp) =>
        executeSearch({
          query: `${grp} ${coreTerms}`.trim(),
          maxResults: 10,
          ...(postedWithinDays && postedWithinDays <= 7 ? { timeRange: 'week' } : postedWithinDays && postedWithinDays <= 31 ? { timeRange: 'month' } : {}),
        }).catch(() => ({ status: 500, body: {} as Record<string, unknown> })),
      ),
    );

    for (const sr of searchResponses) {
      const webResults = Array.isArray(sr.body?.results) ? (sr.body.results as Array<Record<string, unknown>>) : [];
      for (const hit of webResults) {
        const u = typeof hit.url === 'string' ? hit.url.trim() : '';
        if (u.startsWith('https://') && candidateUrls.size < Math.min(35, limit * 2)) {
          candidateUrls.add(u);
        }
      }
    }
  }

  const collected: StructuredJobRecord[] = [];

  // Optional Built In remote search board (rendered in browser when available)
  if (includeBuiltIn && query) {
    const builtInUrl = `https://builtin.com/jobs${wantRemote !== false ? '/remote' : ''}?search=${encodeURIComponent(query)}`;
    const biRes = await executeScrape({
      url: builtInUrl,
      renderMode: 'auto',
      formats: ['markdown', 'links'],
    }).catch(() => null);
    const biMd = typeof biRes?.body?.markdown === 'string' ? biRes.body.markdown : '';
    if (biRes?.status === 200 && biMd) {
      // Extract Built In job links (`https://builtin.com/job/...`) + inline card compensation if present
      const cardRe = /\[([^\]]{4,120})\]\((https:\/\/(?:www\.)?builtin\.com\/job\/[^)\s]+)\)([\s\S]{0,260}?)(?=\[[^\]]+\]\(https:\/\/(?:www\.)?builtin\.com\/job\/|$)/gi;
      let bm: RegExpExecArray | null;
      while ((bm = cardRe.exec(biMd)) !== null && collected.length < limit * 2) {
        const cardTitle = bm[1]!.trim();
        const cardUrl = bm[2]!.trim();
        const cardCtx = bm[3] ?? '';
        const cardPay = parsePayFromText(cardCtx);
        const wp = inferWorkplaceType(`${wantRemote !== false ? 'remote' : ''} ${cardCtx}`);
        collected.push({
          title: cardTitle,
          company: 'Built In Listing',
          url: cardUrl,
          applyUrl: cardUrl,
          workplaceType: wp,
          locations: wp === 'remote' ? ['Remote'] : [],
          pay: cardPay,
          postedAt: null,
          source: 'builtin',
          snippet: stripTagsPlain(cardCtx).slice(0, 200),
        });
      }
    }
  }

  // Fetch candidate ATS URLs in parallel batches of 5 through `executeScrape` (which invokes Ashby, Workday CXS, Greenhouse, Lever & JSON-LD!)
  const urlList = [...candidateUrls];
  for (let i = 0; i < urlList.length; i += 5) {
    const slice = urlList.slice(i, i + 5);
    const batchOut = await Promise.all(
      slice.map((u) =>
        executeScrape({
          url: u,
          renderMode: 'auto',
          formats: ['markdown'],
          ...(payload.target ? { target: payload.target } : {}),
          ...(payload.site ? { site: payload.site } : {}),
        }).catch(() => null),
      ),
    );
    for (let j = 0; j < slice.length; j++) {
      const origU = slice[j]!;
      const sc = batchOut[j];
      const discEntry = discoveredBoards.find((b) => b.boardUrl === origU);
      if (!sc || sc.status !== 200 || sc.body?.ok !== true) {
        if (discEntry) {
          discEntry.boardStatus = classifyAtsBoardStatus({
            httpStatus: sc?.status ?? 0,
            requestedUrl: origU,
            finalUrl: typeof sc?.body?.finalUrl === 'string' ? sc.body.finalUrl : undefined,
          });
        }
        continue;
      }
      // R4: Automatically drop closed/filled job postings, soft-404s, and login walls from active `jobs` search results!
      const cState = typeof sc.body.contentState === 'string' ? sc.body.contentState : undefined;
      if (cState === 'closed_posting' || cState === 'soft_404' || cState === 'login_wall') {
        if (discEntry) {
          discEntry.boardStatus = classifyAtsBoardStatus({
            httpStatus: sc.status,
            requestedUrl: origU,
            finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
            contentState: cState,
          });
        }
        continue;
      }

      // If board returned multiple `jobs` directly (e.g. Ashby / Workday / Greenhouse / Lever / Workable / Gem / Rippling board URL)
      if (Array.isArray(sc.body.jobs)) {
        const boardJobs = sc.body.jobs as StructuredJobRecord[];
        if (discEntry) {
          discEntry.boardStatus = classifyAtsBoardStatus({
            httpStatus: sc.status,
            requestedUrl: origU,
            finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
            jobCount: boardJobs.length,
          });
        }
        for (const br of boardJobs) {
          collected.push(br);
        }
        continue;
      }

      const jp = sc.body.jobPosting as StructuredJobPosting | undefined;
      const meta = (sc.body.metadata as Record<string, unknown> | undefined) ?? {};
      const md = typeof sc.body.markdown === 'string' ? sc.body.markdown : '';
      const rawTitle = (jp?.title || (typeof meta.title === 'string' ? meta.title : '')).replace(/\s*[@|–-]\s*[^@|–-]+$/, '').trim();
      if (!rawTitle) continue;
      const company = jp?.hiringOrganization || inferCompanyFromAtsUrl(origU);
      const pay = jp?.pay ?? parsePayFromText(md);
      const locs = jp?.jobLocation ?? [];
      const wp = jp?.workplaceType && jp.workplaceType !== 'unknown' ? jp.workplaceType : inferWorkplaceType(`${locs.join(' ')} ${md.slice(0, 400)}`);
      const postedAt = jp?.datePosted ?? (typeof meta.publishedTime === 'string' ? meta.publishedTime : null);
      const applyUrl = jp?.applyUrl || origU;

      collected.push({
        title: rawTitle,
        company,
        url: origU,
        applyUrl,
        workplaceType: wp,
        locations: locs,
        pay,
        postedAt,
        source: jp?.source || String(sc.body.extractorId ?? 'ats'),
        ...(jp?.employmentType ? { employmentType: jp.employmentType } : {}),
      });
    }
  }

  const nowMs = Date.now();
  const maxAgeCutoffMs = postedWithinDays ? nowMs - postedWithinDays * 86_400_000 : null;
  const seenKeys = new Set<string>();
  const seenUrls = new Set<string>();
  const finalJobs: StructuredJobRecord[] = [];

  for (const job of collected) {
    const cleanUrlKey = job.url.replace(/\/+$/, '').toLowerCase();
    const dedupKey = canonicalJobKey(job.company, job.title);
    if (seenUrls.has(cleanUrlKey) || seenKeys.has(dedupKey)) continue;

    // Exclude already-applied list
    const isExcluded = excludeList.some((ex) => {
      if (ex.url && ex.url === cleanUrlKey) return true;
      const compMatch = ex.company && job.company.toLowerCase().includes(ex.company);
      const titleMatch = ex.title && job.title.toLowerCase().includes(ex.title);
      return Boolean((ex.company && ex.title && compMatch && titleMatch) || (ex.company && !ex.title && compMatch));
    });
    if (isExcluded) continue;

    // Query relevance filter on board-level expansions
    if (query) {
      const qTokens = (query.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? []).filter((t) => t.length >= 3);
      const hay = `${job.title} ${job.company} ${job.snippet ?? ''}`.toLowerCase();
      if (qTokens.length > 0 && !qTokens.some((qt) => hay.includes(qt))) continue;
    }

    if (wantRemote === true && job.workplaceType !== 'remote' && !job.locations.some((l) => /remote/i.test(l))) {
      continue;
    }
    if (locationsFilter.length > 0) {
      const locHay = `${job.locations.join(' ')} ${job.workplaceType}`.toLowerCase();
      if (!locationsFilter.some((lf) => locHay.includes(lf))) continue;
    }
    if (minBase !== undefined && job.pay) {
      // P11: Never treat `total` / `ote` target cash as meeting `minBase` unless its floor meets `minBase` and basis === 'base'
      if (job.pay.basis !== 'base') continue;
      const ceiling = job.pay.max ?? job.pay.min ?? 0;
      if (ceiling < minBase) continue;
    }
    if (maxAgeCutoffMs !== null && job.postedAt) {
      const parsedTs = Date.parse(job.postedAt);
      if (Number.isFinite(parsedTs) && parsedTs < maxAgeCutoffMs) continue;
    }

    seenUrls.add(cleanUrlKey);
    seenKeys.add(dedupKey);
    finalJobs.push(job);
    if (finalJobs.length >= limit) break;
  }

  if (candidateUrls.size === 0 && collected.length === 0) {
    notes.push('No ATS search results returned; ensure SERPER_API_KEY or SEARXNG_URL is configured on the Hub.');
  }

  return {
    status: 200,
    body: {
      ok: true,
      query,
      ...(companyFilter ? { company: companyFilter } : {}),
      ...(domainsInput.length > 0 ? { domains: domainsInput, discoveredBoards } : {}),
      count: finalJobs.length,
      candidatesChecked: candidateUrls.size,
      jobs: finalJobs,
      ...(notes.length > 0 ? { notes } : {}),
    },
  };
}
