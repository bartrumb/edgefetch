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

import { getActiveRequestTracer, type RequestTracer, type TraceContext } from './otel';
import { compileSafeUserRegex, replaceHtmlTagBlocksLinear, stripHtmlTagsQuoteAwareLinear } from './safe-input';
import type { ArtifactRetention, OptionalStorageBindings } from './storage';
import { buildWikimediaRobotsSuggestion, isWikimediaHost } from './wikipedia';

export type PayPeriod = 'year' | 'month' | 'week' | 'day' | 'hour';
export type PayBasis = 'base' | 'ote' | 'total';
export type WorkplaceType = 'remote' | 'hybrid' | 'onsite' | 'unknown';
export type AtsBoardStatus = 'ok' | 'empty_board' | 'wrong_slug' | 'blocked_or_down' | 'not_found' | 'budget_exhausted';

export interface DiscoveredAtsBoard {
  domain?: string;
  platform: string;
  slug: string;
  boardUrl: string;
  discoveredFrom: string;
  boardStatus?: AtsBoardStatus;
  tried?: string[];
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
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

export interface X402ExtraMetadata {
  name?: string;
  version?: string;
  decimals?: number;
}

export interface X402PaymentTerms {
  x402Version?: number;
  scheme?: string;
  price?: string;
  amount?: string;
  maxAmountRequired?: string;
  asset?: string;
  currency?: string;
  network?: string;
  payTo?: string;
  resource?: string;
  description?: string;
  invoice?: string;
  macaroon?: string;
  extra?: X402ExtraMetadata;
  [k: string]: unknown;
}

export interface BlockedSuggestion {
  reason: 'robots' | 'challenge' | 'content-signal' | 'payment_required';
  host?: string;
  signal?: string;
  price?: string;
  terms?: X402PaymentTerms;
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
    total?: number;
    returned?: number;
    truncated?: boolean;
    nextCursor?: string;
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
  payUnknown?: boolean;
  matchedOn?: 'phrase' | 'all_tokens' | 'company_filter';
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
    .replace(/&dollar;/gi, '$')
    .replace(/&pound;/gi, '£')
    .replace(/&euro;/gi, '€')
    .replace(/&ndash;/gi, '–')
    .replace(/&mdash;/gi, '—')
    .replace(/&minus;/gi, '-')
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
  return decodeEntitiesBasic(stripHtmlTagsQuoteAwareLinear(s, ' '))
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
  const onceDecoded = decodeEntitiesBasic(text);
  const normalized = (onceDecoded.includes('&') ? decodeEntitiesBasic(onceDecoded) : onceDecoded).replace(/\u00a0/g, ' ');
  const rangeRe =
    /(?:(USD|CAD|EUR|GBP|AUD|CHF)\s*)?([\$£€])?\s*(\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d{2,7}(?:\.\d+)?)\s*([kK])?\s*(?:[-–—]|to)\s*(?:(USD|CAD|EUR|GBP|AUD|CHF)\s*)?([\$£€])?\s*(\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d{2,7}(?:\.\d+)?)\s*([kK])?(?:\s*(USD|CAD|EUR|GBP|AUD|CHF)\b)?/gi;

  let m: RegExpExecArray | null;
  while ((m = rangeRe.exec(normalized)) !== null) {
    const explicitCur = (m[1] ?? m[5] ?? m[9])?.toUpperCase();
    const sym = m[2] ?? m[6];
    if (!explicitCur && !sym) continue;

    const windowStart = Math.max(0, m.index - 90);
    const windowEnd = Math.min(normalized.length, m.index + m[0].length + 90);
    const ctxWindow = normalized.slice(windowStart, windowEnd);
    // Skip funding/ARR/valuation numbers ("raised $150M", "$200K ARR")
    if (/\b(?:arr|mrr|funding|raised|valuation|series\s+[a-f]|revenue)\b/i.test(ctxWindow)) continue;

    const currency = explicitCur || (sym === '£' ? 'GBP' : sym === '€' ? 'EUR' : 'USD');
    const rawMin = parseFloat(m[3]!.replace(/,/g, ''));
    const minHasK = Boolean(m[4]);
    const rawMax = parseFloat(m[7]!.replace(/,/g, ''));
    const maxHasK = Boolean(m[8] || (minHasK && rawMax < 1_000));

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

function resolveExplicitWorkplaceType(
  explicitField: unknown,
  htmlContext = '',
  proseContext = '',
): WorkplaceType | null {
  const checkToken = (val: string): WorkplaceType | null => {
    const t = val.trim();
    if (!t) return null;
    if (/^hybrid$|\bhybrid\b/i.test(t)) return 'hybrid';
    if (/^(?:on[-_\s]?site|in[-_\s]?office|in[-_\s]?person)$|\bon[-_\s]?site\b|\bin[-_\s]?office\b/i.test(t)) return 'onsite';
    if (/^remote$|\bremote\b/i.test(t)) return 'remote';
    return null;
  };

  if (typeof explicitField === 'string') {
    const direct = checkToken(explicitField);
    if (direct) return direct;
  }

  if (htmlContext) {
    const ashbyEmbedded = /"workplaceType"\s*:\s*"(Hybrid|OnSite|On-site|Remote)"/i.exec(htmlContext.slice(0, 200_000));
    if (ashbyEmbedded?.[1]) {
      const parsed = checkToken(ashbyEmbedded[1]);
      if (parsed) return parsed;
    }
  }

  if (proseContext) {
    const labelMatch = /(?:Location|Workplace)\s*Type\s*[:\n\r\t-]+\s*(Hybrid|On[-_\s]?site|In[-_\s]?office|Remote)\b/i.exec(
      proseContext,
    );
    if (labelMatch?.[1]) {
      const parsed = checkToken(labelMatch[1]);
      if (parsed) return parsed;
    }
  }

  return null;
}

/**
 * `P4`: Parses `<script type="application/ld+json">` blocks (including `@graph` arrays) for `@type: JobPosting`.
 */
export function extractJobPostingJsonLd(rawHtml: string, baseUrl?: string, fallbackProse = ''): StructuredJobPosting | null {
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

  replaceHtmlTagBlocksLinear(rawHtml, 'script', (_full, attrStr, inner) => {
    if (!/\btype[ \t\r\n]*=[ \t\r\n]*["']application\/ld\+json["']/i.test(attrStr)) return '';
    const rawJson = inner.trim();
    if (!rawJson) return '';
    const parsed = safeJsonParse(rawJson) ?? safeJsonParse(decodeEntitiesBasic(rawJson));
    collectEntities(parsed);
    return '';
  });

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
  const pagePlainWindow = `${stripTagsPlain(rawHtml.slice(0, 120_000))} ${fallbackProse}`;
  // Prefer Ashby / ATS explicit `workplaceType` or `"Location Type: Hybrid"` over JSON-LD `jobLocationType: "TELECOMMUTE"`!
  const explicitWorkplace = resolveExplicitWorkplaceType(jp.workplaceType, rawHtml, pagePlainWindow);

  if (
    (!explicitWorkplace || explicitWorkplace === 'remote') &&
    jobLocationType &&
    /TELECOMMUTE/i.test(jobLocationType) &&
    locations.length === 0
  ) {
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
    | string
    | number
    | undefined;
  const parseNumericSalField = (v: unknown): number | null => {
    if (typeof v === 'number') return Number.isFinite(v) && v > 0 ? v : null;
    if (typeof v === 'string') {
      const cleaned = v.replace(/[\$£€,\s]/g, '');
      const n = parseFloat(cleaned);
      return Number.isFinite(n) && n > 0 ? n : null;
    }
    return null;
  };
  if (typeof rawSal === 'string') {
    structuredPay = parsePayFromText(rawSal);
  } else if (typeof rawSal === 'number' && Number.isFinite(rawSal) && rawSal > 0) {
    const scaled = scaleShorthandAnnualAmount(rawSal, 'year');
    if (scaled !== null) {
      structuredPay = { min: scaled, max: scaled, currency: 'USD', period: 'year', basis: 'base' };
    }
  } else if (rawSal && typeof rawSal === 'object') {
    const currency =
      typeof rawSal.currency === 'string' && rawSal.currency.trim()
        ? rawSal.currency.trim().toUpperCase()
        : typeof rawSal.priceCurrency === 'string' && rawSal.priceCurrency.trim()
          ? rawSal.priceCurrency.trim().toUpperCase()
          : 'USD';
    const valObj = rawSal.value as Record<string, unknown> | number | string | undefined;
    let minVal: number | null = null;
    let maxVal: number | null = null;
    let unitText = '';
    if (typeof valObj === 'number') {
      minVal = valObj;
      maxVal = valObj;
    } else if (typeof valObj === 'string') {
      const parsedStrRange = parsePayFromText(valObj) ?? parsePayFromText(`${currency} ${valObj}`);
      if (parsedStrRange) {
        minVal = parsedStrRange.min;
        maxVal = parsedStrRange.max;
      } else {
        const singleNum = parseNumericSalField(valObj);
        if (singleNum !== null) {
          minVal = singleNum;
          maxVal = singleNum;
        }
      }
    } else if (valObj && typeof valObj === 'object') {
      minVal = parseNumericSalField(valObj.minValue ?? valObj.value);
      maxVal = parseNumericSalField(valObj.maxValue ?? valObj.value);
      if (typeof valObj.unitText === 'string') unitText = valObj.unitText;
    }
    if (minVal === null && maxVal === null) {
      minVal = parseNumericSalField(rawSal.minValue);
      maxVal = parseNumericSalField(rawSal.maxValue);
    }
    const period = normalizePeriod(unitText || rawSal.unitText);
    minVal = scaleShorthandAnnualAmount(minVal, period);
    maxVal = scaleShorthandAnnualAmount(maxVal, period);
    if (minVal !== null || maxVal !== null) {
      structuredPay = {
        min: minVal ?? maxVal,
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
    explicitWorkplace ??
    (jobLocationType && /TELECOMMUTE/i.test(jobLocationType)
      ? /hybrid/i.test(wpText)
        ? 'hybrid'
        : 'remote'
      : inferWorkplaceType(wpText));

  const empRaw = jp.employmentType;
  const rawEmpStr = Array.isArray(empRaw) ? empRaw.map(String).join(', ') : typeof empRaw === 'string' ? empRaw : '';
  const cleanEmp = rawEmpStr ? stripTagsPlain(rawEmpStr).slice(0, 160).trim() : '';
  const employmentType = cleanEmp || undefined;
  const datePosted = typeof jp.datePosted === 'string' ? stripTagsPlain(jp.datePosted).slice(0, 64).trim() || undefined : undefined;
  const validThrough = typeof jp.validThrough === 'string' ? stripTagsPlain(jp.validThrough).slice(0, 64).trim() || undefined : undefined;
  const rawJpUrl = typeof jp.url === 'string' ? jp.url.trim() : '';
  const applyUrl = /^https?:\/\/[^\s<>()"`]{1,2048}$/i.test(rawJpUrl) ? rawJpUrl : baseUrl;

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
 * Linear O(N) quote-aware brace scanner that salvages complete job objects from an Ashby
 * `posting-api/job-board/{org}` JSON response even if an extreme board exceeded `maxBytes` mid-stream.
 */
export function salvageAshbyBoardFromTruncatedJson(raw: string): {
  salvaged: true;
  organizationName?: string;
  jobs: Array<Record<string, unknown>>;
} | null {
  const jobsKeyIdx = raw.indexOf('"jobs"');
  if (jobsKeyIdx < 0) return null;
  let organizationName: string | undefined;
  const headSlice = raw.slice(0, Math.min(raw.length, 4096));
  const orgMatch = /"organizationName"\s*:\s*"((?:\\.|[^"\\])*)"/.exec(headSlice);
  if (orgMatch?.[1]) {
    try {
      organizationName = JSON.parse(`"${orgMatch[1]}"`) as string;
    } catch {
      organizationName = orgMatch[1];
    }
  }

  let pos = jobsKeyIdx + 6;
  while (pos < raw.length && (raw[pos] === ' ' || raw[pos] === '\t' || raw[pos] === '\r' || raw[pos] === '\n')) pos++;
  if (raw[pos] !== ':') return null;
  pos++;
  while (pos < raw.length && (raw[pos] === ' ' || raw[pos] === '\t' || raw[pos] === '\r' || raw[pos] === '\n')) pos++;
  if (raw[pos] !== '[') return null;
  pos++;

  const jobs: Array<Record<string, unknown>> = [];
  let inString = false;
  let escaped = false;
  let depth = 0;
  let objStart = -1;

  for (let i = pos; i < raw.length; i++) {
    const ch = raw[i]!;
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === '{') {
      if (depth === 0) objStart = i;
      depth++;
    } else if (ch === '}') {
      if (depth > 0) {
        depth--;
        if (depth === 0 && objStart >= 0) {
          const parsed = safeJsonParse(raw.slice(objStart, i + 1));
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            jobs.push(parsed as Record<string, unknown>);
            if (jobs.length >= 5_000) break;
          }
          objStart = -1;
        }
      }
    } else if (ch === ']' && depth === 0) {
      break;
    }
  }

  if (jobs.length === 0) return null;
  return {
    salvaged: true,
    ...(organizationName ? { organizationName } : {}),
    jobs,
  };
}

function parseGreenhousePay(job: Record<string, unknown>, extraProse = ''): NormalizedPay | null {
  const payRanges = Array.isArray(job.pay_input_ranges) ? (job.pay_input_ranges as Array<Record<string, unknown>>) : [];
  if (payRanges[0] && typeof payRanges[0] === 'object') {
    const pr = payRanges[0];
    const cur = typeof pr.currency_type === 'string' && pr.currency_type.trim() ? pr.currency_type.trim().toUpperCase() : 'USD';
    const rawMinCents = typeof pr.min_cents === 'number' ? pr.min_cents : typeof pr.min_cents === 'string' ? Number(pr.min_cents) : NaN;
    const rawMaxCents = typeof pr.max_cents === 'number' ? pr.max_cents : typeof pr.max_cents === 'string' ? Number(pr.max_cents) : NaN;
    const minCents = Number.isFinite(rawMinCents) && rawMinCents > 0 ? Math.round(rawMinCents / 100) : null;
    const maxCents = Number.isFinite(rawMaxCents) && rawMaxCents > 0 ? Math.round(rawMaxCents / 100) : null;
    if (minCents !== null || maxCents !== null) {
      return {
        min: minCents ?? maxCents,
        max: maxCents ?? minCents,
        currency: cur,
        period: 'year',
        basis: inferPayBasis(`${String(pr.title ?? '')} ${String(pr.blurb ?? '')}`),
      };
    }
  }

  if (Array.isArray(job.metadata)) {
    for (const m of job.metadata as Array<Record<string, unknown>>) {
      const mName = typeof m?.name === 'string' ? m.name : '';
      if (!/salary|compensation|pay|wage|remuneration|base/i.test(mName)) continue;
      const mVal = Array.isArray(m?.value) ? m.value.map(String).join(' ') : typeof m?.value === 'string' ? m.value : '';
      if (mVal) {
        const fromMeta = parsePayFromText(`${mName}: ${mVal}`);
        if (fromMeta) return fromMeta;
      }
    }
  }

  const rawContent = typeof job.content === 'string' ? job.content : '';
  const decodedContent = rawContent ? decodeEntitiesBasic(decodeEntitiesBasic(rawContent.slice(0, 48_000))) : '';
  const plainContent = decodedContent ? stripTagsPlain(decodedContent) : '';
  const combined = extraProse ? `${plainContent} ${extraProse}` : plainContent;
  return combined ? parsePayFromText(combined) : null;
}

function parseLeverPay(job: Record<string, unknown>, extraProse = ''): NormalizedPay | null {
  const salObj = job.salaryRange as Record<string, unknown> | undefined;
  if (salObj && typeof salObj === 'object') {
    const period = normalizePeriod(salObj.interval ?? 'year');
    const rawMin = typeof salObj.min === 'number' ? salObj.min : typeof salObj.min === 'string' ? parseFloat(salObj.min.replace(/,/g, '')) : NaN;
    const rawMax = typeof salObj.max === 'number' ? salObj.max : typeof salObj.max === 'string' ? parseFloat(salObj.max.replace(/,/g, '')) : NaN;
    const min = scaleShorthandAnnualAmount(Number.isFinite(rawMin) && rawMin > 0 ? rawMin : null, period);
    const max = scaleShorthandAnnualAmount(Number.isFinite(rawMax) && rawMax > 0 ? rawMax : null, period);
    if (min !== null || max !== null) {
      return {
        min: min ?? max,
        max: max ?? min,
        currency: typeof salObj.currency === 'string' && salObj.currency.trim() ? salObj.currency.trim().toUpperCase() : 'USD',
        period,
        basis: inferPayBasis(String(job.salaryDescriptionPlain ?? job.salaryDescription ?? '')),
      };
    }
  }

  const textChunks: string[] = [];
  for (const field of ['salaryDescriptionPlain', 'salaryDescription', 'descriptionPlain', 'additionalPlain']) {
    const v = job[field];
    if (typeof v === 'string' && v.trim()) textChunks.push(stripTagsPlain(v.slice(0, 32_000)));
  }
  if (Array.isArray(job.lists)) {
    for (const lst of job.lists as Array<Record<string, unknown>>) {
      const lText = typeof lst?.text === 'string' ? lst.text : '';
      const lContent = typeof lst?.content === 'string' ? stripTagsPlain(lst.content.slice(0, 16_000)) : '';
      if (lText || lContent) textChunks.push(`${lText} ${lContent}`);
    }
  }
  if (!job.descriptionPlain && typeof job.description === 'string') {
    textChunks.push(stripTagsPlain(String(job.description).slice(0, 32_000)));
  }
  if (!job.additionalPlain && typeof job.additional === 'string') {
    textChunks.push(stripTagsPlain(String(job.additional).slice(0, 32_000)));
  }
  if (extraProse) textChunks.push(extraProse);
  const combined = textChunks.join('\n');
  return combined ? parsePayFromText(combined) : null;
}

function parseRipplingPay(item: Record<string, unknown>, extraProse = ''): NormalizedPay | null {
  const payDetails = (item.payRangeDetails ?? item.payRange ?? item.compensation) as Record<string, unknown> | Array<Record<string, unknown>> | undefined;
  const candidate = Array.isArray(payDetails) ? payDetails[0] : payDetails;
  if (candidate && typeof candidate === 'object') {
    const period = normalizePeriod(candidate.frequency ?? candidate.interval ?? candidate.period ?? 'year');
    const rawMin = Number(candidate.min ?? candidate.minValue ?? candidate.minAmount ?? NaN);
    const rawMax = Number(candidate.max ?? candidate.maxValue ?? candidate.maxAmount ?? NaN);
    const min = scaleShorthandAnnualAmount(Number.isFinite(rawMin) && rawMin > 0 ? rawMin : null, period);
    const max = scaleShorthandAnnualAmount(Number.isFinite(rawMax) && rawMax > 0 ? rawMax : null, period);
    if (min !== null || max !== null) {
      const cur = typeof candidate.currency === 'string' && candidate.currency.trim()
        ? candidate.currency.trim().toUpperCase()
        : typeof candidate.currencyCode === 'string' && candidate.currencyCode.trim()
          ? candidate.currencyCode.trim().toUpperCase()
          : 'USD';
      return {
        min: min ?? max,
        max: max ?? min,
        currency: cur,
        period,
        basis: 'base',
      };
    }
  }
  return extraProse ? parsePayFromText(extraProse) : null;
}

function inferWorkdayWorkplaceType(remoteType: string, locText: string, title: string): WorkplaceType {
  const explicit = resolveExplicitWorkplaceType(remoteType, '', '');
  if (explicit) return explicit;
  const inferred = inferWorkplaceType(`${remoteType} ${locText} ${title}`);
  if (inferred !== 'unknown') return inferred;
  const cleanLoc = locText.trim();
  if (
    cleanLoc.length > 0 &&
    !/^(?:locations?|multiple(?:\s+locations?)?|various|flexible|global|worldwide|anywhere|tbd|n\/a|\d+\s+locations?)$/i.test(
      cleanLoc,
    )
  ) {
    return 'onsite';
  }
  return 'unknown';
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
    const secondSeg = parts.length >= 2 ? parts[1]!.toLowerCase() : '';
    const jobId =
      parts.length >= 2 && secondSeg !== 'application' && !(parts.length === 2 && secondSeg === 'jobs')
        ? decodeURIComponent(parts[1]!)
        : '';
    const reqOffset = Math.max(0, parseInt(u.searchParams.get('offset') ?? '0', 10) || 0);
    if (/^[A-Za-z0-9._-]+$/.test(org)) {
      return {
        id: jobId ? 'ashby-job' : 'ashby-board',
        fetchUrl: `https://api.ashbyhq.com/posting-api/job-board/${encodeURIComponent(org)}?includeCompensation=true`,
        method: 'GET',
        kind: 'json',
        accept: 'application/json',
        format: (rawBody, origUrl, htmlToMd) => {
          let data = safeJsonParse(rawBody) as Record<string, unknown> | null;
          let salvaged = false;
          if ((!data || !Array.isArray(data.jobs)) && rawBody.includes('"jobs"')) {
            const salv = salvageAshbyBoardFromTruncatedJson(rawBody);
            if (salv) {
              data = {
                ...(salv.organizationName ? { organizationName: salv.organizationName } : {}),
                jobs: salv.jobs,
              };
              salvaged = true;
            }
          }
          if (!data || !Array.isArray(data.jobs)) return null;
          const jobs = data.jobs as Array<Record<string, unknown>>;
          const orgTitle = typeof data.organizationName === 'string' && data.organizationName ? data.organizationName : org;

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
            const descHtml = typeof match.descriptionHtml === 'string' ? match.descriptionHtml : '';
            const descPlain = typeof match.descriptionPlain === 'string' ? match.descriptionPlain : '';
            const bodyMd = descHtml.trim() ? htmlToMd(descHtml, origUrl).markdown.trim() : descPlain.trim();
            const explicitWp = resolveExplicitWorkplaceType(match.workplaceType, '', `${descPlain} ${bodyMd}`);
            const workplaceType: WorkplaceType =
              explicitWp ??
              (match.isRemote === true ? 'remote' : inferWorkplaceType(`${allLocs.join(' ')} ${title}`));
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

          // Whole Ashby job board summary (never return `null` on `jobs.length === 0` so empty Ashby boards never trigger Chromium!)
          const total = jobs.length;
          if (total === 0) {
            return {
              title: `${orgTitle} Jobs (0)`,
              markdown: `# ${orgTitle} — Open Roles (0)\n\nNo open positions currently listed.`,
              links: [],
              jobs: [],
              total: 0,
              returned: 0,
              truncated: false,
            };
          }

          const links: string[] = [];
          for (const j of jobs.slice(0, 2000)) {
            const jId = String(j.id ?? '');
            const jUrl = typeof j.jobUrl === 'string' && j.jobUrl ? j.jobUrl : `https://jobs.ashbyhq.com/${org}/${jId}`;
            links.push(jUrl);
          }

          const records: StructuredJobRecord[] = [];
          const countLabel = salvaged ? `${total}+` : String(total);
          const lines: string[] = [`# ${orgTitle} — Open Roles (${countLabel})`];
          const maxBoardRecords = 2_500;
          const maxMarkdownBullets = 120;
          for (const j of jobs.slice(reqOffset, reqOffset + maxBoardRecords)) {
            const jId = String(j.id ?? '');
            const jTitle = String(j.title ?? 'Role').trim();
            const jLoc = String(j.location ?? '').trim();
            const secLocs = Array.isArray(j.secondaryLocations)
              ? (j.secondaryLocations as Array<Record<string, unknown> | string>)
                  .map((s) => (typeof s === 'string' ? s.trim() : String(s?.location ?? '').trim()))
                  .filter(Boolean)
              : [];
            const allLocs = [jLoc, ...secLocs].filter(Boolean);
            const rawDescPlain = String(j.descriptionPlain ?? '');
            const descPlain =
              rawDescPlain ||
              (typeof j.descriptionHtml === 'string' && j.descriptionHtml
                ? stripTagsPlain(j.descriptionHtml.slice(0, 12_000))
                : '');
            const explicitWp = resolveExplicitWorkplaceType(j.workplaceType, '', descPlain.slice(0, 16_000));
            const wp: WorkplaceType =
              explicitWp ?? (j.isRemote === true ? 'remote' : inferWorkplaceType(`${allLocs.join(' ')} ${jTitle}`));
            const pay = parseAshbyPay(j, descPlain.slice(0, 24_000));
            const jUrl = typeof j.jobUrl === 'string' && j.jobUrl ? j.jobUrl : `https://jobs.ashbyhq.com/${org}/${jId}`;
            const applyUrl = typeof j.applyUrl === 'string' && j.applyUrl ? j.applyUrl : `${jUrl}/application`;
            const postedAt = typeof j.publishedAt === 'string' ? j.publishedAt : null;
            const empType = typeof j.employmentType === 'string' && j.employmentType ? j.employmentType : undefined;
            records.push({
              title: jTitle,
              company: orgTitle,
              url: jUrl,
              applyUrl,
              workplaceType: wp,
              locations: allLocs,
              pay,
              postedAt,
              ...(empType ? { employmentType: empType } : {}),
              source: 'ashby',
              ...(descPlain ? { snippet: descPlain.slice(0, 240) } : {}),
            });
            if (lines.length - 1 < maxMarkdownBullets) {
              const meta = [allLocs[0] ?? '', wp !== 'unknown' ? wp : '', pay ? formatNormalizedPay(pay) : ''].filter(Boolean).join(' · ');
              lines.push(`- **[${jTitle}](${jUrl})**${meta ? ` — ${meta}` : ''}`);
            }
          }
          if (records.length > maxMarkdownBullets) {
            lines.push(`- *... and ${records.length - maxMarkdownBullets} additional open roles*`);
          }
          const returned = records.length;
          const truncated = salvaged || total > reqOffset + returned;
          const nextOffsetVal = reqOffset + returned;
          return {
            title: `${orgTitle} Jobs (${countLabel})`,
            markdown: lines.join('\n'),
            links,
            jobs: records,
            ...(salvaged ? {} : { total }),
            returned,
            truncated,
            ...(truncated && (salvaged || nextOffsetVal < total) ? { nextCursor: String(nextOffsetVal) } : {}),
          };
        },
      };
    }
  }

  // P2: Workday CXS (`{tenant}.wd{N}.myworkdayjobs.com/[{locale}/]{site}[/job/{externalPath}]` or `/wday/cxs/{tenant}/{site}/jobs`)
  const wdHostMatch = /^([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com$/i.exec(host);
  if (wdHostMatch && parts.length >= 1) {
    let tenant = wdHostMatch[1]!;
    let site = '';
    let rest: string[] = [];
    if (parts[0]?.toLowerCase() === 'wday' && parts[1]?.toLowerCase() === 'cxs' && parts.length >= 4) {
      tenant = parts[2] || tenant;
      site = parts[3]!;
      rest = parts.slice(4);
    } else {
      let idx = 0;
      if (/^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2) {
        idx = 1; // skip locale segment like `en-US`
      }
      site = parts[idx] ?? '';
      rest = parts.slice(idx + 1);
    }
    if (site && site.toLowerCase() !== 'wday' && /^[A-Za-z0-9_.-]{1,120}$/.test(site)) {
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
            const rawPostedOn = typeof info.startDate === 'string' ? info.startDate : typeof info.postedOn === 'string' ? info.postedOn : undefined;
            const postedOn = normalizeWorkdayPostedAt(rawPostedOn) ?? undefined;
            const descHtml = typeof info.jobDescription === 'string' ? info.jobDescription : '';
            const bodyMd = descHtml ? htmlToMd(descHtml, origUrl).markdown.trim() : '';
            const pay = parsePayFromText(bodyMd);
            const extUrl = typeof info.externalUrl === 'string' && info.externalUrl.startsWith('http') ? info.externalUrl : origUrl;
            const wp = inferWorkdayWorkplaceType(remoteType, allLocs.join(' '), title);

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
      const reqOffset = Math.max(0, parseInt(u.searchParams.get('offset') ?? '0', 10) || 0);
      return {
        id: 'workday-board',
        fetchUrl: `https://${host}/wday/cxs/${tenant}/${site}/jobs`,
        method: 'POST',
        requestBody: JSON.stringify({ appliedFacets: {}, limit: 20, offset: reqOffset, searchText }),
        contentType: 'application/json',
        kind: 'json',
        accept: 'application/json',
        format: (rawBody) => {
          const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
          const postings = Array.isArray(data?.jobPostings) ? (data.jobPostings as Array<Record<string, unknown>>) : null;
          if (!postings) return null;
          const rawTotal = typeof data?.total === 'number' && Number.isFinite(data.total) && data.total > 0 ? data.total : 0;
          const total = Math.max(rawTotal, postings.length > 0 ? reqOffset + postings.length : 0);
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
            const rawPostedOn = typeof p.postedOn === 'string' ? p.postedOn.trim() : null;
            const postedOn = normalizeWorkdayPostedAt(rawPostedOn);
            const bullets = Array.isArray(p.bulletFields) ? p.bulletFields.map(String).filter(Boolean).join(', ') : '';
            const wp = inferWorkdayWorkplaceType(String(p.remoteType ?? ''), locTxt, pTitle);
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
          const returned = records.length;
          const truncated = postings.length > 0 && total > reqOffset + returned;
          return {
            title: heading,
            markdown: lines.join('\n'),
            links,
            jobs: records,
            total,
            returned,
            truncated,
            ...(truncated ? { nextCursor: String(reqOffset + 20) } : {}),
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
      const reqOffset = Math.max(0, parseInt(u.searchParams.get('offset') ?? '0', 10) || 0);
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
          const metaObj = data?.meta as Record<string, unknown> | undefined;
          const total =
            typeof metaObj?.total === 'number' && Number.isFinite(metaObj.total)
              ? Math.max(metaObj.total, jobs.length)
              : jobs.length;
          const records: StructuredJobRecord[] = [];
          const links: string[] = [];
          for (const j of jobs.slice(0, 2500)) {
            const jUrl =
              typeof j.absolute_url === 'string' && j.absolute_url.startsWith('https://')
                ? j.absolute_url
                : `https://${host}/${co}/jobs/${String(j.id ?? '')}`;
            links.push(jUrl);
          }
          const lines: string[] = [`# ${co} — Greenhouse Job Board (${total} open roles)`];
          const maxBoardRecords = 2_500;
          const maxMarkdownBullets = 120;
          for (const j of jobs.slice(reqOffset, reqOffset + maxBoardRecords)) {
            const jTitle = String(j.title ?? '').trim();
            if (!jTitle) continue;
            const loc = String((j.location as Record<string, unknown> | undefined)?.name ?? '').trim();
            const jUrl =
              typeof j.absolute_url === 'string' && j.absolute_url.startsWith('https://')
                ? j.absolute_url
                : `https://${host}/${co}/jobs/${String(j.id ?? '')}`;
            const rawContent = typeof j.content === 'string' ? j.content : '';
            const plainPreview = rawContent
              ? stripTagsPlain(decodeEntitiesBasic(decodeEntitiesBasic(rawContent.slice(0, 12_000))))
              : '';
            const wp = inferWorkplaceType(`${loc} ${jTitle} ${plainPreview.slice(0, 320)}`);
            const pay = parseGreenhousePay(j);
            const postedAt = typeof j.updated_at === 'string' ? j.updated_at : typeof j.first_published === 'string' ? j.first_published : null;
            const companyName = typeof j.company_name === 'string' && j.company_name.trim() ? j.company_name.trim() : co;
            records.push({
              title: jTitle,
              company: companyName,
              url: jUrl,
              applyUrl: jUrl,
              workplaceType: wp,
              locations: loc ? [loc] : [],
              pay,
              postedAt,
              source: 'greenhouse',
              ...(plainPreview ? { snippet: plainPreview.slice(0, 240) } : {}),
            });
            if (lines.length - 1 < maxMarkdownBullets) {
              const meta = [loc, wp !== 'unknown' ? wp : '', pay ? formatNormalizedPay(pay) : ''].filter(Boolean).join(' · ');
              lines.push(`- **[${jTitle}](${jUrl})**${meta ? ` — ${meta}` : ''}`);
            }
          }
          if (records.length > maxMarkdownBullets) {
            lines.push(`- *... and ${records.length - maxMarkdownBullets} additional open roles*`);
          }
          const returned = records.length;
          const nextOffsetVal = reqOffset + returned;
          const truncated = total > nextOffsetVal;
          return {
            title: `${co} Jobs (${total})`,
            markdown: lines.join('\n'),
            links,
            jobs: records,
            total,
            returned,
            truncated,
            ...(truncated ? { nextCursor: String(nextOffsetVal) } : {}),
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
            const rawContent = typeof data.content === 'string' ? decodeEntitiesBasic(decodeEntitiesBasic(data.content)) : '';
            const bodyMd = rawContent ? htmlToMd(rawContent, origUrl).markdown.trim() : '';
            const pay = parseGreenhousePay(data, bodyMd);

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
      const reqOffset = Math.max(0, parseInt(u.searchParams.get('offset') ?? '0', 10) || 0);
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
          const total = jobs.length;
          const records: StructuredJobRecord[] = [];
          const links: string[] = [];
          for (const j of jobs.slice(0, 2500)) {
            const jUrl = typeof j.hostedUrl === 'string' && j.hostedUrl.startsWith('https://') ? j.hostedUrl : `https://${host}/${co}/${String(j.id ?? '')}`;
            links.push(jUrl);
          }
          const lines: string[] = [`# ${co} — Lever Job Board (${total} open roles)`];
          const maxBoardRecords = 2_500;
          const maxMarkdownBullets = 120;
          for (const j of jobs.slice(reqOffset, reqOffset + maxBoardRecords)) {
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
            const pay = parseLeverPay(j);
            const descSnippet = typeof j.descriptionPlain === 'string' && j.descriptionPlain.trim()
              ? j.descriptionPlain.trim().slice(0, 240)
              : undefined;
            records.push({
              title: jTitle,
              company: co,
              url: jUrl,
              applyUrl,
              workplaceType: wp,
              locations: allLocs,
              pay,
              postedAt: createdIso,
              source: 'lever',
              ...(descSnippet ? { snippet: descSnippet } : {}),
            });
            if (lines.length - 1 < maxMarkdownBullets) {
              const meta = [allLocs[0] ?? '', wp !== 'unknown' ? wp : '', pay ? formatNormalizedPay(pay) : ''].filter(Boolean).join(' · ');
              lines.push(`- **[${jTitle}](${jUrl})**${meta ? ` — ${meta}` : ''}`);
            }
          }
          if (records.length > maxMarkdownBullets) {
            lines.push(`- *... and ${records.length - maxMarkdownBullets} additional open roles*`);
          }
          const returned = records.length;
          const truncated = total > reqOffset + returned;
          return {
            title: `${co} Jobs (${total})`,
            markdown: lines.join('\n'),
            links,
            jobs: records,
            total,
            returned,
            truncated,
            ...(truncated ? { nextCursor: String(reqOffset + returned) } : {}),
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
          const pay = parseLeverPay(data, bodyMd);

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
        for (const p of posts.slice(0, 2_500)) {
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
          if (lines.length - 1 < 120) {
            lines.push(`- **[${pTitle}](${pUrl})**${loc ? ` — ${loc}` : ''}`);
          }
        }
        return { title: `${org} Jobs (${records.length})`, markdown: lines.join('\n'), links, jobs: records };
      },
    };
  }

  // Rippling (`ats.rippling.com/[locale/]<org>/jobs[/<uuid>]` — merge rows by `uuid` & resolve single job via public API!)
  if (host === 'ats.rippling.com' && parts.length >= 1) {
    const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2 ? 1 : 0;
    const org = parts[idx]!;
    const rest = parts.slice(idx + 1);
    if (org && /^[A-Za-z0-9_-]{1,80}$/.test(org)) {
      if (rest.length === 0 || (rest.length === 1 && rest[0] === 'jobs')) {
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
              const workLocsArr = Array.isArray(item.workLocations) ? item.workLocations : [];
              const locLabel =
                typeof workLoc === 'string'
                  ? workLoc
                  : typeof workLoc?.label === 'string'
                    ? workLoc.label
                    : workLocsArr
                        .map((wl) => (typeof wl === 'string' ? wl : typeof (wl as { label?: string })?.label === 'string' ? (wl as { label: string }).label : ''))
                        .filter(Boolean)
                        .join('; ');
              const jUrl = typeof item.url === 'string' && item.url.startsWith('https://') ? item.url : `https://ats.rippling.com/${org}/jobs/${uuid}`;
              const createdAt = typeof item.createdOn === 'string' ? item.createdOn : typeof item.publishedAt === 'string' ? item.publishedAt : null;
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
                  pay: parseRipplingPay(item),
                  postedAt: createdAt,
                  source: 'rippling',
                });
              }
            }
            const records = [...byUuid.values()];
            const links = records.map((r) => r.url);
            const lines = [`# ${org} — Rippling Job Board (${records.length} open roles)`];
            for (const r of records.slice(0, 120)) {
              lines.push(`- **[${r.title}](${r.url})**${r.locations.length > 0 ? ` — ${r.locations.join('; ')}` : ''}`);
            }
            return {
              title: `${org} Jobs (${records.length})`,
              markdown: lines.join('\n'),
              links,
              jobs: records,
              total: records.length,
              returned: records.length,
              truncated: false,
            };
          },
        };
      }
      if (rest.length >= 2 && rest[0] === 'jobs' && /^[A-Za-z0-9_-]{6,64}$/.test(rest[1]!)) {
        const uuid = rest[1]!;
        return {
          id: 'rippling-job',
          fetchUrl: `https://api.rippling.com/platform/api/ats/v1/board/${encodeURIComponent(org)}/jobs/${encodeURIComponent(uuid)}`,
          method: 'GET',
          kind: 'json',
          accept: 'application/json',
          format: (rawBody, origUrl, htmlToMd) => {
            const parsed = safeJsonParse(rawBody);
            const data = Array.isArray(parsed)
              ? (parsed as Array<Record<string, unknown>>).find(
                  (it) => String(it?.uuid ?? it?.id ?? '').toLowerCase() === uuid.toLowerCase(),
                ) ?? null
              : parsed && typeof parsed === 'object'
                ? (parsed as Record<string, unknown>)
                : null;
            if (!data) return null;
            const title = String(data.name ?? data.title ?? '').trim();
            if (!title) return null;
            const companyName =
              typeof data.companyName === 'string' && data.companyName.trim() ? data.companyName.trim() : org;
            const locs: string[] = [];
            const workLoc = data.workLocation as Record<string, unknown> | string | undefined;
            if (typeof workLoc === 'string') {
              if (workLoc.trim()) locs.push(workLoc.trim());
            } else if (workLoc && typeof workLoc === 'object' && typeof workLoc.label === 'string' && workLoc.label.trim()) {
              locs.push(workLoc.label.trim());
            }
            if (Array.isArray(data.workLocations)) {
              for (const wl of data.workLocations) {
                const lbl = typeof wl === 'string' ? wl.trim() : typeof (wl as { label?: string })?.label === 'string' ? (wl as { label: string }).label.trim() : '';
                if (lbl && !locs.includes(lbl)) locs.push(lbl);
              }
            }
            const descObj = data.description as Record<string, unknown> | string | undefined;
            const descParts: string[] = [];
            if (typeof descObj === 'string' && descObj.trim()) {
              descParts.push(htmlToMd(descObj, origUrl).markdown.trim());
            } else if (descObj && typeof descObj === 'object') {
              for (const k of ['company', 'role']) {
                const htmlPart = descObj[k];
                if (typeof htmlPart === 'string' && htmlPart.trim()) {
                  descParts.push(htmlToMd(htmlPart, origUrl).markdown.trim());
                }
              }
            }
            const bodyMd = descParts.filter(Boolean).join('\n\n');
            const pay = parseRipplingPay(data, bodyMd);
            const wp = inferWorkplaceType(`${locs.join(' ')} ${title} ${bodyMd.slice(0, 400)}`);
            const postedAt = typeof data.createdOn === 'string' ? data.createdOn : typeof data.publishedAt === 'string' ? data.publishedAt : undefined;
            const jobUrl = typeof data.url === 'string' && data.url.startsWith('https://') ? data.url : origUrl;

            const jp: StructuredJobPosting = {
              title,
              hiringOrganization: companyName,
              ...(locs.length > 0 ? { jobLocation: locs } : {}),
              workplaceType: wp,
              baseSalary: pay?.basis === 'base' ? pay : null,
              pay,
              ...(postedAt ? { datePosted: postedAt } : {}),
              url: origUrl,
              applyUrl: jobUrl,
              source: 'rippling',
            };
            const headerMd = formatJobPostingHeaderMarkdown(jp);
            return {
              title: `${title} @ ${companyName}`,
              ...(postedAt ? { publishedTime: postedAt } : {}),
              jobPosting: jp,
              markdown: [`# ${title} @ ${companyName}`, ...(headerMd ? [headerMd] : []), bodyMd].filter(Boolean).join('\n\n'),
              links: [jobUrl],
            };
          },
        };
      }
    }
  }

  // Robots-allowed Public Remote Job Feeds (We Work Remotely RSS, Himalayas, Working Nomads — Remotive is excluded per robots.txt)
  if ((host === 'weworkremotely.com' || host === 'www.weworkremotely.com') && /\.rss$/i.test(u.pathname)) {
    return {
      id: 'weworkremotely-feed',
      fetchUrl: urlStr,
      method: 'GET',
      kind: 'text',
      accept: 'application/rss+xml',
      format: (rawBody) => {
        const records = parsePublicJobFeedRecords('weworkremotely', rawBody);
        if (records.length === 0) return null;
        const lines = [`# We Work Remotely Jobs (${records.length})`];
        const links = records.map((r) => r.url);
        for (const r of records.slice(0, 50)) {
          lines.push(`- **[${r.title}](${r.url})** — ${r.company} · ${r.locations[0] ?? 'Remote'}`);
        }
        return {
          title: `We Work Remotely Jobs (${records.length})`,
          markdown: lines.join('\n'),
          links,
          jobs: records,
          total: records.length,
          returned: records.length,
          truncated: false,
        };
      },
    };
  }

  if ((host === 'himalayas.app' || host === 'www.himalayas.app') && u.pathname.startsWith('/jobs/api')) {
    return {
      id: 'himalayas-feed',
      fetchUrl: urlStr,
      method: 'GET',
      kind: 'json',
      accept: 'application/json',
      format: (rawBody) => {
        const parsed = safeJsonParse(rawBody) as Record<string, unknown> | null;
        const records = parsePublicJobFeedRecords('himalayas', rawBody);
        if (!parsed || !Array.isArray(parsed.jobs)) return null;
        const total = typeof parsed.totalCount === 'number' ? Math.max(parsed.totalCount, records.length) : records.length;
        const lines = [`# Himalayas Remote Jobs (${records.length} of ${total})`];
        const links = records.map((r) => r.url);
        for (const r of records) {
          lines.push(`- **[${r.title}](${r.url})** — ${r.company}`);
        }
        return {
          title: `Himalayas Remote Jobs (${records.length})`,
          markdown: lines.join('\n'),
          links,
          jobs: records,
          total,
          returned: records.length,
          truncated: total > records.length,
        };
      },
    };
  }

  if ((host === 'www.workingnomads.com' || host === 'workingnomads.com') && u.pathname.startsWith('/api/exposed_jobs')) {
    return {
      id: 'workingnomads-feed',
      fetchUrl: urlStr,
      method: 'GET',
      kind: 'json',
      accept: 'application/json',
      format: (rawBody) => {
        const records = parsePublicJobFeedRecords('workingnomads', rawBody);
        if (records.length === 0) return null;
        const lines = [`# Working Nomads Remote Jobs (${records.length})`];
        const links = records.map((r) => r.url);
        for (const r of records.slice(0, 50)) {
          lines.push(`- **[${r.title}](${r.url})** — ${r.company}`);
        }
        return {
          title: `Working Nomads Remote Jobs (${records.length})`,
          markdown: lines.join('\n'),
          links,
          jobs: records,
          total: records.length,
          returned: records.length,
          truncated: false,
        };
      },
    };
  }

  return null;
}

/**
 * Keyless `robots.txt`-allowed public remote job feeds integrated into `jobs` (`remotive.com/api/remote-jobs` is intentionally omitted per `robots.txt`).
 */
export const PUBLIC_JOB_FEEDS = [
  { id: 'weworkremotely' as const, url: 'https://weworkremotely.com/remote-jobs.rss' },
  { id: 'himalayas' as const, url: 'https://himalayas.app/jobs/api?limit=50' },
  { id: 'workingnomads' as const, url: 'https://www.workingnomads.com/api/exposed_jobs/' },
] as const;

function extractLinearXmlSimpleTag(xml: string, tag: string): string {
  const openToken = `<${tag.toLowerCase()}`;
  const closeToken = `</${tag.toLowerCase()}>`;
  const lower = xml.toLowerCase();
  const openIdx = lower.indexOf(openToken);
  if (openIdx === -1) return '';
  const gt = xml.indexOf('>', openIdx + openToken.length);
  if (gt === -1) return '';
  const closeIdx = lower.indexOf(closeToken, gt + 1);
  if (closeIdx === -1) return '';
  const inner = xml.slice(gt + 1, closeIdx).trim();
  if (inner.startsWith('<![CDATA[') && inner.endsWith(']]>')) {
    return inner.slice(9, -3).trim();
  }
  return inner;
}

export function parsePublicJobFeedRecords(
  feedId: 'weworkremotely' | 'himalayas' | 'workingnomads',
  rawBody: string,
): StructuredJobRecord[] {
  const out: StructuredJobRecord[] = [];
  if (feedId === 'weworkremotely') {
    const lower = rawBody.toLowerCase();
    let pos = 0;
    while (pos < rawBody.length && out.length < 100) {
      const openIdx = lower.indexOf('<item', pos);
      if (openIdx === -1) break;
      const gt = rawBody.indexOf('>', openIdx + 5);
      if (gt === -1) break;
      const closeIdx = lower.indexOf('</item>', gt + 1);
      if (closeIdx === -1) break;
      const itemXml = rawBody.slice(gt + 1, closeIdx);
      pos = closeIdx + 7;

      const fullTitle = stripTagsPlain(extractLinearXmlSimpleTag(itemXml, 'title'));
      const link = stripTagsPlain(extractLinearXmlSimpleTag(itemXml, 'link'));
      if (!fullTitle || !link.startsWith('https://')) continue;
      const colon = fullTitle.indexOf(':');
      const company = colon > 0 ? fullTitle.slice(0, colon).trim() : 'We Work Remotely';
      const role = colon > 0 ? fullTitle.slice(colon + 1).trim() : fullTitle;
      const region = stripTagsPlain(extractLinearXmlSimpleTag(itemXml, 'region')) || 'Remote';
      const pubDate = stripTagsPlain(extractLinearXmlSimpleTag(itemXml, 'pubDate'));
      const desc = stripTagsPlain(extractLinearXmlSimpleTag(itemXml, 'description'));
      const parsedTs = pubDate ? Date.parse(pubDate) : NaN;

      out.push({
        title: role,
        company,
        url: link,
        applyUrl: link,
        workplaceType: 'remote',
        locations: [region],
        pay: parsePayFromText(desc),
        postedAt: Number.isFinite(parsedTs) ? new Date(parsedTs).toISOString() : null,
        source: 'weworkremotely',
        ...(desc ? { snippet: desc.slice(0, 220) } : {}),
      });
    }
    return out;
  }

  if (feedId === 'himalayas') {
    const data = safeJsonParse(rawBody) as Record<string, unknown> | null;
    const jobs = Array.isArray(data?.jobs) ? (data.jobs as Array<Record<string, unknown>>) : [];
    for (const j of jobs.slice(0, 100)) {
      const title = String(j.title ?? '').trim();
      const company = String(j.companyName ?? '').trim();
      const url =
        typeof j.applicationLink === 'string' && j.applicationLink.startsWith('https://')
          ? j.applicationLink
          : typeof j.guid === 'string' && j.guid.startsWith('https://')
            ? j.guid
            : '';
      if (!title || !url) continue;
      const locs = Array.isArray(j.locationRestrictions)
        ? j.locationRestrictions.map(String).filter(Boolean)
        : ['Remote'];
      const minSal = typeof j.minSalary === 'number' && j.minSalary > 0 ? Math.round(j.minSalary) : null;
      const maxSal = typeof j.maxSalary === 'number' && j.maxSalary > 0 ? Math.round(j.maxSalary) : null;
      const cur = typeof j.currency === 'string' && j.currency.trim() ? j.currency.trim().toUpperCase() : 'USD';
      const pay: NormalizedPay | null =
        minSal || maxSal
          ? { min: minSal, max: maxSal ?? minSal, currency: cur, period: 'year', basis: 'base' }
          : null;
      const pubSec = typeof j.pubDate === 'number' ? j.pubDate : NaN;
      const postedAt = Number.isFinite(pubSec)
        ? new Date(pubSec > 1e12 ? pubSec : pubSec * 1_000).toISOString()
        : typeof j.pubDate === 'string'
          ? j.pubDate
          : null;
      out.push({
        title,
        company: company || 'Himalayas Listing',
        url,
        applyUrl: url,
        workplaceType: 'remote',
        locations: locs.length > 0 ? locs : ['Remote'],
        pay,
        postedAt,
        source: 'himalayas',
        ...(typeof j.excerpt === 'string' && j.excerpt ? { snippet: stripTagsPlain(j.excerpt).slice(0, 220) } : {}),
      });
    }
    return out;
  }

  // `workingnomads`
  const parsed = safeJsonParse(rawBody);
  const items = Array.isArray(parsed) ? (parsed as Array<Record<string, unknown>>) : [];
  for (const j of items.slice(0, 100)) {
    const title = String(j.title ?? '').trim();
    const company = String(j.company_name ?? '').trim();
    const url = typeof j.url === 'string' && j.url.startsWith('https://') ? j.url : '';
    if (!title || !url) continue;
    const loc = String(j.location || 'Remote').trim();
    const desc = stripTagsPlain(String(j.description ?? ''));
    const postedAt = typeof j.pub_date === 'string' && j.pub_date ? j.pub_date : null;
    out.push({
      title,
      company: company || 'Working Nomads Listing',
      url,
      applyUrl: url,
      workplaceType: 'remote',
      locations: [loc],
      pay: parsePayFromText(desc),
      postedAt,
      source: 'workingnomads',
      ...(desc ? { snippet: desc.slice(0, 220) } : {}),
    });
  }
  return out;
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

/** Returns true only when `rawHtml` contains at least one executable `<script>` tag (ignoring static JSON-LD, JSON data, templates, and MathJax TeX blocks). */
export function hasExecutableScriptTag(rawHtml: string): boolean {
  if (!/<script\b/i.test(rawHtml)) return false;
  const scriptOpenRe = /<script\b([^>]{0,600})>/gi;
  let m: RegExpExecArray | null;
  while ((m = scriptOpenRe.exec(rawHtml)) !== null) {
    const attrs = m[1] ?? '';
    const tm = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
    const tVal = (tm?.[1] ?? tm?.[2] ?? tm?.[3] ?? '').trim().toLowerCase();
    if (
      tVal === 'application/ld+json' ||
      tVal === 'application/json' ||
      tVal === 'text/plain' ||
      tVal === 'text/template' ||
      tVal === 'text/x-template' ||
      tVal.startsWith('math/tex')
    ) {
      continue;
    }
    return true;
  }
  return false;
}

/**
 * `P3`: Determines whether a `<script>`-bearing HTML page yielded a thin / filter-only shell that should automatically
 * upgrade to headless Chromium in `auto` mode (`< 80` words OR `> 60%` link-only / short filter-label lines).
 */
export function isThinScriptedPage(rawHtml: string, extractedMarkdown: string): boolean {
  if (!hasExecutableScriptTag(rawHtml)) return false;
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
    const m = /^([A-Za-z0-9_.-]+)\s*(!=|~=|~|=)\s*(.+)$/.exec(rawPart.trim());
    if (!m) continue;
    const field = m[1]!;
    const op: '=' | '!=' | '~' = m[2] === '~=' ? '~' : (m[2] as '=' | '!=' | '~');
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
              // Fail closed if caller supplied regex metacharacters that were rejected as unsafe/malformed;
              // keep case-insensitive substring fallback only for plain keyword tokens (e.g. "Senior").
              if (/[\\^$.*+?()[\]{}|]/.test(c.value) || c.value.length > 256) {
                return false;
              }
              return val.toLowerCase().includes(c.value.toLowerCase());
            }
            return safeRe.test(val.length > 2048 ? val.slice(0, 2048) : val);
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
    } else if (rec.salaryRange || rec.salaryDescriptionPlain || Array.isArray(rec.lists) || rec.additionalPlain) {
      pay = parseLeverPay(rec);
    } else if (Array.isArray(rec.pay_input_ranges) || Array.isArray(rec.metadata)) {
      pay = parseGreenhousePay(rec);
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

function readPaymentHeader(
  headers: Headers | Record<string, string | undefined> | undefined,
  name: string,
): string {
  if (!headers) return '';
  if (typeof (headers as Headers).get === 'function') {
    return ((headers as Headers).get(name) ?? '').trim();
  }
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers as Record<string, string | undefined>)) {
    if (k.toLowerCase() === lower && typeof v === 'string') return v.trim();
  }
  return '';
}

function tryDecodePaymentHeaderJson(raw: string): Record<string, unknown> | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 65_536) return null;
  if (trimmed.startsWith('{')) {
    const parsed = safeJsonParse(trimmed);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  }
  // Try base64 / base64url JSON (standard x402 `PAYMENT-REQUIRED` header encoding)
  if (/^[A-Za-z0-9+/_=-]{8,}$/.test(trimmed)) {
    try {
      const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
      const bin = atob(padded);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      const parsed = safeJsonParse(decoded);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // ignore invalid base64
    }
  }
  return null;
}

const KNOWN_MAINNET_USDC_CONTRACTS = new Map<string, readonly string[]>([
  ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', ['base', 'base-mainnet', 'eip155:8453']],
  ['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', ['ethereum', 'eth', 'mainnet', 'eip155:1']],
  ['0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', ['polygon', 'matic', 'eip155:137']],
  ['0x2791bca1f2de4661ed88a30c99a7a9449aa84174', ['polygon', 'matic', 'eip155:137']],
  ['0xaf88d065e77c8cc2239327c5edb3a432268e5831', ['arbitrum', 'arbitrum-one', 'eip155:42161']],
  ['0xff970a61a04b1ca14834a43f5de4533ebddb5cc8', ['arbitrum', 'arbitrum-one', 'eip155:42161']],
  ['0x0b2c639c533813f4aa9d7837caf62653d097ff85', ['optimism', 'op-mainnet', 'eip155:10']],
  ['0x7f5c764cbc14f9669b88837ca1490cca17c31607', ['optimism', 'op-mainnet', 'eip155:10']],
  ['0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e', ['avalanche', 'avax', 'eip155:43114']],
  ['epjfwdd5aufqssqem2qn1xzybapc8g4weggkzwytdt1v', ['solana', 'solana-mainnet']],
]);

const TESTNET_NETWORK_RE = /(?:sepolia|goerli|holesky|testnet|devnet|mumbai|amoy|fuji)/i;

const X402_FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function hasOwnProp(obj: Record<string, unknown>, key: string): boolean {
  return !X402_FORBIDDEN_KEYS.has(key) && Object.prototype.hasOwnProperty.call(obj, key);
}

const DECEPTIVE_402_TOKEN_RE =
  /(?:\b(?:gratis|free|trial|complimentary|paid|prepaid|waived|comped|zero|refunded|settled|included|authorized|authorised|allowed|bypass|exempt|sponsored|covered|ok|go|yes)\b|free|gratis|complimentary|ok2fetch|oktofetch|freetrial|nocost|nofee|nocharge|prepaid|already[-_.: ]*paid|fr33|f2ee)/i;
const X402_INJECTION_PROSE_RE =
  /\b(?:ignore|disregard|forget|override|system[ \t]+prompt|assistant[ \t]*:|pre-?authori[sz]ed|already[ \t]+settled|fetch_url|bearer[ \t]+token|rm[ \t]+-rf|instructions?)\b/i;
const ZERO_VALUE_402_PRICE_RE = /^[$€£]?\s*0+(?:\.0+)?(?:\b|\s|$)/;

/**
 * Strips ANSI CSI/OSC escape sequences, ASCII C0/C1 control characters, CR/LF newlines, DEL, zero-width / soft-hyphen,
 * Variation Selectors (`U+FE00`–`U+FE0F`), Combining Grapheme Joiner (`U+034F`), Hangul fillers, Unicode Tag smuggling (`U+E0000`–`U+E01EF`),
 * and Unicode BiDi override/isolate controls, normalizing Unicode whitespace to `' '` and capping at `maxLen` chars.
 */
function sanitizeX402String(raw: unknown, maxLen = 256): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const cleaned = raw
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?/g, '')
    .replace(
      /[\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\u{e0000}-\u{e01ef}]+/gu,
      '',
    )
    .replace(/[\x00-\x1f\x7f-\x9f\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim();
  if (!cleaned) return undefined;
  return cleaned.length > maxLen ? cleaned.slice(0, maxLen) : cleaned;
}

/**
 * Strips Markdown inline/image/reference links (`[label](dest)` -> `label`, `![alt](dest)` -> `''`, including unbalanced
 * `[label](https://...`), bare `https?://` / `javascript:` URLs, angle-bracket tags (`<...>`), and prompt-injection prose in O(N) time.
 */
function sanitizeX402PlainField(raw: unknown, maxLen = 140, strictIdentifier = false): string | undefined {
  const base = sanitizeX402String(raw, 2_048);
  if (!base) return undefined;
  let out = '';
  let i = 0;
  while (i < base.length) {
    const ch = base.charCodeAt(i);
    // Strip `<...>` angle-bracket autolinks or inline HTML tags (if unclosed `<`, skip `<` itself!)
    if (ch === 60 /* '<' */) {
      const gt = base.indexOf('>', i + 1);
      i = gt > i ? gt + 1 : i + 1;
      continue;
    }
    // Strip `![alt](dest)` (closed or unclosed)
    if (ch === 33 /* '!' */ && i + 1 < base.length && base.charCodeAt(i + 1) === 91 /* '[' */) {
      const closeBr = base.indexOf(']', i + 2);
      if (closeBr >= 0 && closeBr + 1 < base.length && base.charCodeAt(closeBr + 1) === 40 /* '(' */) {
        let p = closeBr + 2;
        let depth = 1;
        while (p < base.length && depth > 0) {
          const pc = base.charCodeAt(p);
          if (pc === 92 /* '\\' */ && p + 1 < base.length) {
            p += 2;
            continue;
          }
          if (pc === 32 && depth === 1) break;
          if (pc === 40) depth++;
          else if (pc === 41) depth--;
          p++;
        }
        i = p;
        continue;
      }
      i += 2;
      continue;
    }
    if (ch === 91 /* '[' */) {
      const closeBr = base.indexOf(']', i + 1);
      if (closeBr >= 0) {
        const label = base.slice(i + 1, closeBr);
        if (closeBr + 1 < base.length && base.charCodeAt(closeBr + 1) === 40 /* '(' */) {
          let p = closeBr + 2;
          let depth = 1;
          while (p < base.length && depth > 0) {
            const pc = base.charCodeAt(p);
            if (pc === 92 /* '\\' */ && p + 1 < base.length) {
              p += 2;
              continue;
            }
            if (pc === 32 && depth === 1) break;
            if (pc === 40) depth++;
            else if (pc === 41) depth--;
            p++;
          }
          out += label;
          i = p;
          continue;
        }
        if (closeBr + 1 < base.length && base.charCodeAt(closeBr + 1) === 91 /* '[' */) {
          const refClose = base.indexOf(']', closeBr + 2);
          if (refClose >= 0) {
            out += label;
            i = refClose + 1;
            continue;
          }
        }
      }
      // Drop stray `[` so `60000` unclosed `[` cannot clutter terms
      i++;
      continue;
    }
    if (ch === 93 /* ']' */ || ch === 62 /* '>' */ || ch === 96 /* '`' */) {
      i++;
      continue;
    }
    if (strictIdentifier && (ch === 40 /* '(' */ || ch === 41 /* ')' */)) {
      i++;
      continue;
    }
    out += base[i]!;
    i++;
  }
  const withoutUrls = out
    .replace(/\b(?:https?|ftp|javascript|vbscript|data|file|blob):[^\s)]*/gi, '')
    .replace(/[ \t]+/g, ' ')
    .trim();
  if (!withoutUrls) return undefined;
  if (X402_INJECTION_PROSE_RE.test(withoutUrls)) return undefined;
  return withoutUrls.length > maxLen ? withoutUrls.slice(0, maxLen).trim() : withoutUrls;
}

function sanitizeX402Identifier(raw: unknown, re: RegExp, maxLen: number): string | undefined {
  const s = sanitizeX402String(raw, maxLen + 8);
  if (!s || s.length > maxLen) return undefined;
  if (/^(?:https?|ftp|javascript|vbscript|data|file|blob):/i.test(s)) return undefined;
  if (!re.test(s) || X402_INJECTION_PROSE_RE.test(s)) return undefined;
  return s;
}

const ALLOWED_X402_ONCHAIN_ASSET_LABELS = new Set([
  'USDC',
  'USDC.e',
  'USDT',
  'DAI',
  'PYUSD',
  'EURC',
  'USDP',
  'FRAX',
  'LUSD',
  'WETH',
  'ETH',
  'WBTC',
  'BTC',
  'SAT',
  'SATS',
  'SOL',
]);

const ALLOWED_X402_FIAT_CURRENCIES = new Set(['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY', 'CHF', 'NZD', 'SGD', 'HKD']);

function isSafeX402AssetLabel(rawLabel: string): boolean {
  if (!rawLabel || /[^\x21-\x7e]/.test(rawLabel)) return false;
  if (DECEPTIVE_402_TOKEN_RE.test(rawLabel) || X402_INJECTION_PROSE_RE.test(rawLabel)) return false;
  // Explicit allowlist: verified `0x...` token/contract ID (`0xDeadBeefToken`, `0x8335...`), Solana base58 mint,
  // or canonical case-checked crypto asset ticker (`USDC`, `USDC.e`, `USDT`, `DAI`, `WETH`, `SAT`, `SOL`) — NEVER arbitrary words (`PAIDUP`, `SETTLD`, `USDCE`, `USD`, `CENTS`)!
  if (/^0x[A-Za-z0-9]{4,64}$/.test(rawLabel)) return true;
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(rawLabel)) return true;
  if (rawLabel === 'USDC.e') return true;
  return ALLOWED_X402_ONCHAIN_ASSET_LABELS.has(rawLabel.toUpperCase()) && !rawLabel.includes('.');
}

function isSafeX402CurrencyLabel(rawLabel: string): boolean {
  if (isSafeX402AssetLabel(rawLabel)) return true;
  return ALLOWED_X402_FIAT_CURRENCIES.has(rawLabel.toUpperCase());
}

const KNOWN_MAINNET_USDC_NETWORKS: ReadonlySet<string> = new Set(
  Array.from(KNOWN_MAINNET_USDC_CONTRACTS.values()).flat(),
);

function isKnownUsdcAsset(assetRaw: string, network?: string): boolean {
  const trimmed = assetRaw.trim();
  if (!trimmed || /[^\x21-\x7e]/.test(trimmed)) return false;
  if (network && TESTNET_NETWORK_RE.test(network)) return false;
  if (trimmed.toUpperCase() === 'USDC') {
    return !network || KNOWN_MAINNET_USDC_NETWORKS.has(network.trim().toLowerCase());
  }
  const chains = KNOWN_MAINNET_USDC_CONTRACTS.get(trimmed.toLowerCase());
  if (!chains) return false;
  if (!network) return true;
  const normNet = network.trim().toLowerCase();
  return chains.includes(normNet);
}

function sanitizeX402HttpsResource(raw: unknown, expectedHost?: string): string | undefined {
  const s = sanitizeX402String(raw, 512);
  if (!s || !/^https:\/\//i.test(s) || /[\s<>[\]`]/.test(s) || X402_INJECTION_PROSE_RE.test(s)) return undefined;
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:' || u.username || u.password || !u.hostname) return undefined;
    if (expectedHost && u.hostname.toLowerCase() !== expectedHost.toLowerCase()) return undefined;
    return s.startsWith('https://') ? s : u.toString();
  } catch {
    return undefined;
  }
}

/**
 * Validates atomic integer amounts strictly as `/^\d{1,30}$/` (or safe non-negative integer `0..2^53-1`),
 * rejecting negative numbers, floats, `NaN`, `Infinity`, scientific notation (`2e3`, `1e+21`), and 400-digit strings.
 */
function normalizeX402AtomicAmount(raw: unknown): string | undefined {
  if (typeof raw === 'number') {
    if (!Number.isSafeInteger(raw) || raw < 0) return undefined;
    return String(raw === 0 ? 0 : raw);
  }
  if (typeof raw === 'string') {
    if (/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(raw)) return undefined;
    const s = raw.trim();
    if (!/^\d{1,30}$/.test(s)) return undefined;
    return BigInt(s).toString();
  }
  return undefined;
}

/**
 * Formats an atomic integer string (`1..30` digits) with `decimals` (`0..18`) purely via string padding and slicing —
 * ZERO `Number.toFixed`, ZERO IEEE-754 precision loss above `2^53`, and ZERO scientific notation!
 */
function formatAtomicAmountDecimalString(atomicDigits: string, decimals: number): string {
  const canonical = BigInt(atomicDigits).toString();
  if (decimals <= 0) return canonical;
  const padded = canonical.padStart(decimals + 1, '0');
  const splitIdx = padded.length - decimals;
  const whole = padded.slice(0, splitIdx);
  const frac = padded.slice(splitIdx).replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole;
}

/**
 * Validates standalone free-text `price` strictly against `/^\$?\d{1,12}(?:\.\d{1,8})?(?: [A-Z0-9]{2,10})?$/`
 * (blocking `$0.00 (FREE)` spoofing, ANSI/newline sequences, and prompt-injection payloads).
 */
function validateX402StandalonePrice(raw: unknown, fallbackCurrency?: string): string | undefined {
  let s: string;
  if (typeof raw === 'number') {
    if (!Number.isFinite(raw) || raw <= 0 || raw > 999_999_999_999 || String(raw).includes('e') || String(raw).includes('E')) {
      return undefined;
    }
    s = String(raw);
  } else if (typeof raw === 'string') {
    if (
      /[\x00-\x1f\x7f-\x9f\u00a0\u1680\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\ufeff]/.test(raw) ||
      DECEPTIVE_402_TOKEN_RE.test(raw) ||
      X402_INJECTION_PROSE_RE.test(raw) ||
      ZERO_VALUE_402_PRICE_RE.test(raw.trim())
    ) {
      return undefined;
    }
    s = raw.trim().replace(/[ \t]+/g, ' ');
  } else {
    return undefined;
  }
  if (!/^\$?\d{1,12}(?:\.\d{1,8})?(?: [A-Z0-9]{2,10})?$/.test(s) || DECEPTIVE_402_TOKEN_RE.test(s) || ZERO_VALUE_402_PRICE_RE.test(s)) {
    return undefined;
  }
  const numPart = /^\$?(\d{1,12}(?:\.\d{1,8})?)/.exec(s);
  if (!numPart || !(Number(numPart[1]) > 0)) return undefined;
  if (s.startsWith('$') || / [A-Z0-9]{2,10}$/.test(s)) return s;
  if (fallbackCurrency && (DECEPTIVE_402_TOKEN_RE.test(fallbackCurrency) || !isSafeX402AssetLabel(fallbackCurrency))) return undefined;
  const curRaw = (fallbackCurrency ?? 'USD').trim().toUpperCase();
  const cur = /^[A-Z0-9]{2,10}$/.test(curRaw) && !DECEPTIVE_402_TOKEN_RE.test(curRaw) ? curRaw : 'USD';
  return cur === 'USD' ? `$${s}` : `$${s} ${cur}`;
}

function formatX402PriceString(
  terms: X402PaymentTerms,
  sawDeceptiveCurrency = false,
  rawUntrustedAssetPresent = false,
): string | undefined {
  const assetRaw = typeof terms.asset === 'string' ? terms.asset.trim() : '';
  const currencyRaw = typeof terms.currency === 'string' ? terms.currency.trim() : '';
  const networkRaw = typeof terms.network === 'string' ? terms.network.trim() : undefined;
  const isUsdc =
    isKnownUsdcAsset(assetRaw, networkRaw) ||
    (!assetRaw && !rawUntrustedAssetPresent && isKnownUsdcAsset(currencyRaw, networkRaw));
  const rawLabel = isUsdc ? 'USDC' : assetRaw || (!rawUntrustedAssetPresent ? currencyRaw : '');
  const assetLabel = isUsdc ? 'USDC' : isSafeX402AssetLabel(rawLabel) ? rawLabel : '';

  const normMax = normalizeX402AtomicAmount(terms.maxAmountRequired);
  const normAmt = normalizeX402AtomicAmount(terms.amount);
  const maxBig = normMax !== undefined ? BigInt(normMax) : null;
  const amtBigCandidate = normAmt !== undefined ? BigInt(normAmt) : null;
  const validAmt =
    maxBig !== null && maxBig > 0n && amtBigCandidate !== null && amtBigCandidate > 0n
      ? maxBig >= amtBigCandidate
        ? normMax
        : normAmt
      : maxBig !== null && maxBig > 0n
        ? normMax
        : amtBigCandidate !== null && amtBigCandidate > 0n
          ? normAmt
          : normMax ?? normAmt;

  if (validAmt !== undefined) {
    const amtBig = BigInt(validAmt);
    // Reject zero-value atomic amounts (`0` / `0n`) on HTTP 402 paywalls so zero/free claims are never classified as paid prices.
    if (amtBig <= 0n) {
      return undefined;
    }
    if (isUsdc) {
      // Force `decimals = 6` on verified mainnet USDC so `extra.decimals: 18` or `9` can NEVER understate a USDC price!
      const decStr = formatAtomicAmountDecimalString(validAmt, 6);
      return `$${decStr} USDC`;
    }
    // For non-USDC assets, never divide `validAmt` by untrusted `extra.decimals` — explicitly label raw atomic units!
    return assetLabel ? `${validAmt} atomic units (${assetLabel})` : `${validAmt} atomic units`;
  }

  if (sawDeceptiveCurrency) {
    return undefined;
  }
  return validateX402StandalonePrice(terms.price, currencyRaw || assetLabel);
}

function isAuthTokenChar(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 45 ||
    code === 95
  );
}

/**
 * Strictly linear `O(N)` `WWW-Authenticate` key-value scanner capped at `8192` chars (replaces superlinear regex).
 */
function parseWwwAuthenticateLinear(rawWwwAuth: string): { scheme?: string; pairs: Array<[string, string]> } {
  const s = rawWwwAuth.slice(0, 8_192);
  const n = s.length;
  const pairs: Array<[string, string]> = [];
  let i = 0;

  while (i < n && (s.charCodeAt(i) === 32 || s.charCodeAt(i) === 9 || s.charCodeAt(i) === 44)) i++;
  let scheme: string | undefined;
  const schemeStart = i;
  while (i < n && isAuthTokenChar(s.charCodeAt(i))) i++;
  if (i > schemeStart) {
    let probe = i;
    while (probe < n && (s.charCodeAt(probe) === 32 || s.charCodeAt(probe) === 9)) probe++;
    if (probe >= n || s.charCodeAt(probe) !== 61 /* '=' */) {
      const cand = s.slice(schemeStart, i);
      if (/^(?:x402|l402|lsat)$/i.test(cand)) {
        scheme = cand.toLowerCase() === 'lsat' ? 'L402' : cand;
      }
    } else {
      i = schemeStart;
    }
  }

  while (i < n) {
    while (
      i < n &&
      (s.charCodeAt(i) === 32 ||
        s.charCodeAt(i) === 9 ||
        s.charCodeAt(i) === 13 ||
        s.charCodeAt(i) === 10 ||
        s.charCodeAt(i) === 44)
    ) {
      i++;
    }
    if (i >= n) break;

    const kStart = i;
    while (i < n && isAuthTokenChar(s.charCodeAt(i))) i++;
    if (i === kStart) {
      // Skip unexpected delimiter or non-token run up to next whitespace/comma without backtracking
      while (i < n && s.charCodeAt(i) !== 32 && s.charCodeAt(i) !== 9 && s.charCodeAt(i) !== 44) i++;
      continue;
    }
    const key = s.slice(kStart, i).toLowerCase();

    while (i < n && (s.charCodeAt(i) === 32 || s.charCodeAt(i) === 9)) i++;
    if (i >= n || s.charCodeAt(i) !== 61 /* '=' */) {
      continue;
    }
    i++; // consume '='
    while (i < n && (s.charCodeAt(i) === 32 || s.charCodeAt(i) === 9)) i++;
    if (i >= n) break;

    let val = '';
    const q = s.charCodeAt(i);
    if (q === 34 /* '"' */ || q === 39 /* "'" */) {
      i++;
      const chunks: string[] = [];
      while (i < n) {
        const ch = s.charCodeAt(i);
        if (ch === q) {
          i++;
          break;
        }
        if (ch === 92 /* '\\' */ && q === 34 && i + 1 < n) {
          chunks.push(s[i + 1]!);
          i += 2;
          continue;
        }
        chunks.push(s[i]!);
        i++;
      }
      val = chunks.join('');
    } else {
      const vStart = i;
      while (
        i < n &&
        s.charCodeAt(i) !== 32 &&
        s.charCodeAt(i) !== 9 &&
        s.charCodeAt(i) !== 13 &&
        s.charCodeAt(i) !== 10 &&
        s.charCodeAt(i) !== 44
      ) {
        i++;
      }
      val = s.slice(vStart, i);
    }

    if (val) pairs.push([key, val]);
  }

  return { ...(scheme ? { scheme } : {}), pairs };
}

function mergeHigherAtomicAmount(existing: string | undefined, incoming: string | undefined): string | undefined {
  if (incoming === undefined) return existing;
  if (existing === undefined) return incoming;
  const exBig = BigInt(existing);
  const inBig = BigInt(incoming);
  return inBig > exBig ? incoming : existing;
}

/**
 * `G3` (`R3-M5` + `R6` Hardened): Parses HTTP `402 Payment Required` (`x402` v1/v2 `PAYMENT-REQUIRED` / `X-Payment-Required`
 * JSON or base64 headers, `WWW-Authenticate: x402` / `L402`, and JSON `402` response bodies) into sanitized `{ price, terms }` —
 * NEVER paying automatically, NEVER calling `Number.toFixed` on untrusted `decimals`, choosing maximum positive `accepts`
 * requirement against cheap decoys, and strictly allowlisting `asset` / `currency` / `payTo` / `network` / `scheme` identifiers.
 */
export function parseX402PaymentTerms(
  status: unknown,
  headers?: Headers | Record<string, string | undefined>,
  rawBody?: string,
  expectedHost?: string,
): { price?: string; terms: X402PaymentTerms } | null {
  if (status !== 402) return null;

  const terms: X402PaymentTerms = {};
  let rawCandidatePrice: unknown;
  let sawDeceptiveCurrency = false;
  let sawRawAssetField = false;

  const payHdr =
    readPaymentHeader(headers, 'payment-required') || readPaymentHeader(headers, 'x-payment-required');
  const wwwAuth = readPaymentHeader(headers, 'www-authenticate');

  const pickBestAcceptEntry = (accepts: unknown[]): Record<string, unknown> | null => {
    let bestObj: Record<string, unknown> | null = null;
    let bestAmt = -1n;
    const limit = Math.min(accepts.length, 32);
    for (let i = 0; i < limit; i++) {
      const cand = accepts[i];
      if (!cand || typeof cand !== 'object' || Array.isArray(cand)) continue;
      const obj = cand as Record<string, unknown>;
      if (bestObj === null) bestObj = obj;
      const mAmt = normalizeX402AtomicAmount(hasOwnProp(obj, 'maxAmountRequired') ? obj.maxAmountRequired : undefined);
      const aAmt = normalizeX402AtomicAmount(hasOwnProp(obj, 'amount') ? obj.amount : undefined);
      const mBig = mAmt !== undefined ? BigInt(mAmt) : -1n;
      const aBig = aAmt !== undefined ? BigInt(aAmt) : -1n;
      const topBig = mBig > aBig ? mBig : aBig;
      if (topBig > bestAmt) {
        bestAmt = topBig;
        bestObj = obj;
      }
    }
    return bestObj;
  };

  const applyRequirementObj = (root: Record<string, unknown>) => {
    if (
      hasOwnProp(root, 'x402Version') &&
      typeof root.x402Version === 'number' &&
      Number.isInteger(root.x402Version) &&
      root.x402Version >= 1 &&
      root.x402Version <= 10
    ) {
      terms.x402Version = root.x402Version;
    }

    const accepts = hasOwnProp(root, 'accepts') && Array.isArray(root.accepts) ? root.accepts : [];
    const chosenAccept = accepts.length > 0 ? pickBestAcceptEntry(accepts) : null;
    if (accepts.length > 1) {
      terms.acceptsCount = Math.min(accepts.length, 32);
    }
    const primary = chosenAccept ?? root;

    const readOwn = (k: string): unknown => {
      if (hasOwnProp(primary, k) && primary[k] !== undefined && primary[k] !== null) return primary[k];
      if (primary !== root && hasOwnProp(root, k) && root[k] !== undefined && root[k] !== null) return root[k];
      return undefined;
    };

    const scheme = sanitizeX402Identifier(readOwn('scheme'), /^[A-Za-z0-9._-]{1,32}$/, 32);
    const rawAssetVal = readOwn('asset');
    if (rawAssetVal !== undefined && rawAssetVal !== null && String(rawAssetVal).trim() !== '') {
      sawRawAssetField = true;
    }
    const assetRaw = sanitizeX402String(rawAssetVal, 128);
    const currency = sanitizeX402String(readOwn('currency'), 64);
    const network = sanitizeX402Identifier(readOwn('network'), /^[A-Za-z0-9:._-]{1,48}$/, 48);
    const payTo = sanitizeX402Identifier(readOwn('payTo') ?? readOwn('recipient'), /^[A-Za-z0-9:._@-]{1,128}$/, 128);
    const resource = sanitizeX402HttpsResource(readOwn('resource'), expectedHost);
    const rawDescVal = readOwn('description');
    if (typeof rawDescVal === 'string' && DECEPTIVE_402_TOKEN_RE.test(sanitizeX402String(rawDescVal, 512) ?? '')) {
      sawDeceptiveCurrency = true;
    }
    const description = sanitizeX402PlainField(rawDescVal, 140, false);
    const amount = normalizeX402AtomicAmount(readOwn('amount'));
    const maxAmountRequired = normalizeX402AtomicAmount(readOwn('maxAmountRequired'));
    const candPrice = readOwn('price');

    if (scheme) terms.scheme = scheme;
    if (candPrice !== undefined) rawCandidatePrice = candPrice;
    terms.amount = mergeHigherAtomicAmount(terms.amount, amount);
    terms.maxAmountRequired = mergeHigherAtomicAmount(terms.maxAmountRequired, maxAmountRequired);

    const effectiveNet = network ?? terms.network;
    if (network) terms.network = network;

    if (assetRaw) {
      if (DECEPTIVE_402_TOKEN_RE.test(assetRaw)) {
        sawDeceptiveCurrency = true;
      } else if (isKnownUsdcAsset(assetRaw, effectiveNet)) {
        terms.asset = 'USDC';
      } else if (isSafeX402AssetLabel(assetRaw)) {
        terms.asset = assetRaw;
      } else {
        sawDeceptiveCurrency = true;
      }
    }
    if (currency) {
      if (DECEPTIVE_402_TOKEN_RE.test(currency)) {
        sawDeceptiveCurrency = true;
      } else if (isSafeX402AssetLabel(currency)) {
        terms.currency = currency;
      } else {
        sawDeceptiveCurrency = true;
      }
    }
    if (payTo) terms.payTo = payTo;
    if (resource) terms.resource = resource;
    if (description) {
      if (DECEPTIVE_402_TOKEN_RE.test(description)) {
        sawDeceptiveCurrency = true;
      } else {
        terms.description = description;
      }
    }

    // Shallow depth-1 allowlisted `extra` (`{ name?, version?, decimals? }`) — never copies `__proto__` or unverified `decimals`!
    const rawExtra = hasOwnProp(primary, 'extra') ? primary.extra : undefined;
    if (rawExtra && typeof rawExtra === 'object' && !Array.isArray(rawExtra)) {
      const eo = rawExtra as Record<string, unknown>;
      const safeExtra: X402ExtraMetadata = {};
      const extraName = hasOwnProp(eo, 'name') ? sanitizeX402PlainField(eo.name, 80, false) : undefined;
      const extraVer = hasOwnProp(eo, 'version')
        ? sanitizeX402Identifier(eo.version, /^[A-Za-z0-9._-]{1,32}$/, 32)
        : undefined;
      if (extraName && !DECEPTIVE_402_TOKEN_RE.test(extraName)) safeExtra.name = extraName;
      if (extraVer) safeExtra.version = extraVer;

      const effectiveIsUsdc =
        isKnownUsdcAsset(assetRaw ?? '', effectiveNet) ||
        (!sawRawAssetField && isKnownUsdcAsset(currency ?? terms.currency ?? '', effectiveNet));
      if (effectiveIsUsdc && hasOwnProp(eo, 'decimals') && typeof eo.decimals === 'number') {
        safeExtra.decimals = 6;
      } else if (hasOwnProp(eo, 'decimals') && eo.decimals === 0) {
        safeExtra.decimals = 0;
      }
      if (Object.keys(safeExtra).length > 0) {
        terms.extra = safeExtra;
      }
    }
  };

  if (payHdr) {
    const hdrObj = tryDecodePaymentHeaderJson(payHdr);
    if (hdrObj) applyRequirementObj(hdrObj);
  }

  if (rawBody && rawBody.length <= 65_536 && rawBody.trim().startsWith('{')) {
    const bodyObj = safeJsonParse(rawBody);
    if (bodyObj && typeof bodyObj === 'object' && !Array.isArray(bodyObj)) {
      applyRequirementObj(bodyObj as Record<string, unknown>);
    }
  }

  if (wwwAuth) {
    const parsedAuth = parseWwwAuthenticateLinear(wwwAuth);
    if (parsedAuth.scheme && !terms.scheme) {
      const sc = sanitizeX402Identifier(parsedAuth.scheme, /^[A-Za-z0-9._-]{1,32}$/, 32);
      if (sc) terms.scheme = sc;
    }
    for (const [k, rawV] of parsedAuth.pairs) {
      if (k === 'price' && rawCandidatePrice === undefined) {
        rawCandidatePrice = rawV;
      } else if (k === 'amount') {
        const a = normalizeX402AtomicAmount(rawV);
        terms.amount = mergeHigherAtomicAmount(terms.amount, a);
      } else if (k === 'maxamountrequired') {
        const m = normalizeX402AtomicAmount(rawV);
        terms.maxAmountRequired = mergeHigherAtomicAmount(terms.maxAmountRequired, m);
      } else if (k === 'asset' && !terms.asset) {
        sawRawAssetField = true;
        const as = sanitizeX402String(rawV, 128);
        if (as) {
          if (DECEPTIVE_402_TOKEN_RE.test(as)) sawDeceptiveCurrency = true;
          else if (isKnownUsdcAsset(as, terms.network)) terms.asset = 'USDC';
          else if (isSafeX402AssetLabel(as)) terms.asset = as;
          else sawDeceptiveCurrency = true;
        }
      } else if (k === 'currency' && !terms.currency) {
        const cu = sanitizeX402String(rawV, 64);
        if (cu) {
          if (DECEPTIVE_402_TOKEN_RE.test(cu)) sawDeceptiveCurrency = true;
          else if (isSafeX402CurrencyLabel(cu)) terms.currency = cu;
          else sawDeceptiveCurrency = true;
        }
      } else if (k === 'network' && !terms.network) {
        const nw = sanitizeX402Identifier(rawV, /^[A-Za-z0-9:._-]{1,48}$/, 48);
        if (nw) terms.network = nw;
      } else if ((k === 'payto' || k === 'recipient') && !terms.payTo) {
        const pt = sanitizeX402Identifier(rawV, /^[A-Za-z0-9:._@-]{1,128}$/, 128);
        if (pt) terms.payTo = pt;
      } else if (k === 'resource' && !terms.resource) {
        const rs = sanitizeX402HttpsResource(rawV, expectedHost);
        if (rs) terms.resource = rs;
      } else if (k === 'description' && !terms.description) {
        if (DECEPTIVE_402_TOKEN_RE.test(sanitizeX402String(rawV, 512) ?? '')) {
          sawDeceptiveCurrency = true;
        }
        const ds = sanitizeX402PlainField(rawV, 140, false);
        if (ds) {
          if (DECEPTIVE_402_TOKEN_RE.test(ds)) sawDeceptiveCurrency = true;
          else terms.description = ds;
        }
      } else if (k === 'invoice') {
        const inv = sanitizeX402Identifier(rawV, /^[A-Za-z0-9+/=_.:-]{1,512}$/, 512);
        if (inv) terms.invoice = inv;
      } else if (k === 'macaroon') {
        const mac = !rawV.includes('://') ? sanitizeX402Identifier(rawV, /^[A-Za-z0-9+/=_."':-]{1,512}$/, 512) : undefined;
        if (mac) terms.macaroon = mac;
      }
    }
  }

  const validStandalone =
    sawDeceptiveCurrency &&
    typeof rawCandidatePrice === 'string' &&
    !rawCandidatePrice.trim().startsWith('$') &&
    !/ [A-Z0-9]{2,10}$/.test(rawCandidatePrice.trim())
      ? undefined
      : validateX402StandalonePrice(rawCandidatePrice, terms.currency || terms.asset);
  if (validStandalone) {
    terms.price = validStandalone;
  }

  const formattedPrice = formatX402PriceString(terms, sawDeceptiveCurrency, sawRawAssetField);
  if (formattedPrice) {
    terms.price = formattedPrice;
  } else {
    delete terms.price;
  }

  return {
    ...(formattedPrice ? { price: formattedPrice } : {}),
    terms,
  };
}

/**
 * `P10` + `G2` + `G3`: Builds a structured, ethical `blocked: { reason, host, ... }` hint when a request is refused by
 * `robots.txt`, Cloudflare `Content-Signal: ai-input=no`, HTTP `402 Payment Required` (`x402`), or a bot challenge —
 * never bypassing blocks and never paying automatically.
 */
export function buildBlockedInfo(
  urlStr: string,
  outcome?: unknown,
  problem?: unknown,
  status?: unknown,
  paymentContext?: { headers?: Headers | Record<string, string | undefined>; rawBody?: string },
): BlockedSuggestion | null {
  const outStr = typeof outcome === 'string' ? outcome.toLowerCase() : '';
  const probStr = typeof problem === 'string' ? problem : '';

  let host = '';
  let pathname = '';
  try {
    const u = new URL(urlStr);
    host = u.hostname.toLowerCase();
    pathname = u.pathname;
  } catch {
    // ignore
  }

  // G3: HTTP 402 Payment Required / x402
  if (status === 402 || outStr === 'payment_required') {
    const parsedPayment = parseX402PaymentTerms(402, paymentContext?.headers, paymentContext?.rawBody, host || undefined);
    const price = parsedPayment?.price;
    const terms = parsedPayment?.terms;
    return {
      reason: 'payment_required',
      ...(host ? { host } : {}),
      ...(price ? { price } : {}),
      ...(terms && Object.keys(terms).length > 0 ? { terms } : {}),
      suggestion: price
        ? `${host || 'This origin'} requires payment (${price}) via HTTP 402 / x402 for this resource. EdgeFetch never pays automatically; surface the price to the user or select a free public source.`
        : `${host || 'This origin'} returned HTTP 402 Payment Required. EdgeFetch never pays automatically; inform the user or select a free public source.`,
    };
  }

  // G2: Cloudflare Content Signals (`Content-Signal: ai-input=no`)
  const isContentSignal =
    outStr === 'content_signal_disallowed' || /content-signal|ai-input\s*=\s*no/i.test(probStr);
  if (isContentSignal) {
    return {
      reason: 'content-signal',
      signal: 'ai-input=no',
      ...(host ? { host } : {}),
      suggestion: `${host || 'This host'} declares \`Content-Signal: ai-input=no\` in robots.txt, opting out of agent input retrieval. Respect the publisher's preference and use an official API or opted-in source instead.`,
    };
  }

  if (
    outStr === 'dns_not_found' ||
    /\b(?:enotfound|nxdomain|dns_not_found|eai_noname)\b|no such host|name or service not known|nodename nor servname provided|domain does not exist/i.test(
      probStr,
    )
  ) {
    return null;
  }

  const isRobots = /robots\.txt/i.test(probStr) || outStr === 'robots_disallowed';
  const isChallenge =
    outStr === 'challenge' ||
    /challenge|cf-mitigated|turnstile|captcha|verify you are human/i.test(probStr) ||
    (status === 403 && /cloudflare|bot|forbidden/i.test(probStr));

  if (!isRobots && !isChallenge) return null;

  const reason: 'robots' | 'challenge' = isRobots ? 'robots' : 'challenge';

  if (reason === 'robots' && isWikimediaHost(host)) {
    return {
      reason: 'robots',
      host,
      suggestion: buildWikimediaRobotsSuggestion(host),
    };
  }

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

  if (host === 'npr.org' || host.endsWith('.npr.org')) {
    return {
      reason,
      host,
      suggestion:
        `${host} blocks automated HTML scraping via ${reason === 'robots' ? 'robots.txt' : 'bot protection'}. Fetch NPR's official public RSS feeds instead: \`https://feeds.npr.org/1001/rss.xml\` (News), \`https://feeds.npr.org/1003/rss.xml\` (US), or \`https://feeds.npr.org/1004/rss.xml\` (World).`,
    };
  }

  if (host === 'bbc.com' || host.endsWith('.bbc.com') || host === 'bbc.co.uk' || host.endsWith('.bbc.co.uk')) {
    return {
      reason,
      host,
      suggestion:
        `${host} restricts automated HTML scraping via ${reason === 'robots' ? 'robots.txt' : 'bot protection'}. Fetch BBC News's official public RSS feed instead: \`https://feeds.bbci.co.uk/news/rss.xml\` (or \`https://feeds.bbci.co.uk/news/world/rss.xml\`).`,
    };
  }

  if (host === 'apnews.com' || host.endsWith('.apnews.com') || host === 'reuters.com' || host.endsWith('.reuters.com')) {
    return {
      reason,
      host,
      suggestion:
        `${host} blocks automated HTML scraping via ${reason === 'robots' ? 'robots.txt' : 'anti-bot challenge'}. Call \`search\` with \`topic: "news"\` or scrape official broadcaster RSS feeds (\`https://www.cbsnews.com/latest/rss/main\`, \`https://feeds.nbcnews.com/nbcnews/public/news\`, \`https://feeds.npr.org/1001/rss.xml\`, \`https://feeds.bbci.co.uk/news/rss.xml\`).`,
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

export type VerifiedPostingStatus = 'live' | 'closed' | 'board_gone' | 'unknown';

export interface VerifiedJobResult {
  url: string;
  status: VerifiedPostingStatus;
  platform?: string;
  slug?: string;
  boardStatus?: AtsBoardStatus;
  similarOpenRoles?: Array<{ title: string; url: string }>;
}

export interface JobsToolPayload {
  mode?: unknown;
  verify?: unknown;
  urls?: unknown;
  query?: unknown;
  company?: unknown;
  domains?: unknown;
  remote?: unknown;
  locations?: unknown;
  minBase?: unknown;
  minBaseMode?: unknown;
  strictPay?: unknown;
  postedWithinDays?: unknown;
  limit?: unknown;
  includeBuiltIn?: unknown;
  includePublicFeeds?: unknown;
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
  const unescapedHtml = rawHtml
    .replace(/\\u002[fF]/g, '/')
    .replace(/\\\//g, '/')
    .replace(/&(?:amp|#0*38|#x0*26);/gi, '&');
  const corpus = [finalUrl, ...links, unescapedHtml].join('\n');
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
    /(?:https?:)?\/\/((?:job-boards|boards|eu-boards|job-boards\.eu)\.greenhouse\.io)\/(?:embed\/job_board(?:\/js)?\?for=([A-Za-z0-9_-]+)|([A-Za-z0-9_-]+))/gi,
  )) {
    const ghHost = m[1]!.toLowerCase();
    const slug = m[2] || m[3] || '';
    const canonicalHost = ghHost.includes('eu') ? 'job-boards.eu.greenhouse.io' : 'job-boards.greenhouse.io';
    addBoard('greenhouse', slug, `https://${canonicalHost}/${slug}`);
  }
  for (const m of corpus.matchAll(/(?:https?:)?\/\/(boards-api(?:\.eu)?\.greenhouse\.io)\/v1\/boards\/([A-Za-z0-9_-]+)/gi)) {
    const canonicalHost = m[1]!.toLowerCase().includes('.eu.') ? 'job-boards.eu.greenhouse.io' : 'job-boards.greenhouse.io';
    addBoard('greenhouse', m[2]!, `https://${canonicalHost}/${m[2]!}`);
  }

  // 2. Ashby (`jobs.ashbyhq.com/<org>` or `api.ashbyhq.com/posting-api/job-board/<org>`)
  for (const m of corpus.matchAll(/(?:https?:)?\/\/(?:jobs\.ashbyhq\.com|api\.ashbyhq\.com\/posting-api\/job-board)\/([A-Za-z0-9_.-]+)/gi)) {
    addBoard('ashby', m[1]!, `https://jobs.ashbyhq.com/${m[1]!}`);
  }

  // 3. Lever (US & EU)
  for (const m of corpus.matchAll(/(?:https?:)?\/\/(jobs(?:\.eu)?\.lever\.co)\/([A-Za-z0-9_.-]+)/gi)) {
    addBoard('lever', m[2]!, `https://${m[1]!.toLowerCase()}/${m[2]!}`);
  }

  // 4. Workday (`<tenant>.wd<N>.myworkdayjobs.com/[en-US/]<site>` or `/wday/cxs/<tenant>/<site>/jobs`)
  for (const m of corpus.matchAll(/(?:https?:)?\/\/(([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com)\/([A-Za-z0-9_/-]+)/gi)) {
    const wdHost = m[1]!.toLowerCase();
    let tenant = m[2]!;
    const segs = m[3]!.split('/').filter(Boolean);
    let site = '';
    if (segs[0]?.toLowerCase() === 'wday' && segs[1]?.toLowerCase() === 'cxs' && segs.length >= 4) {
      tenant = segs[2] || tenant;
      site = segs[3]!;
    } else {
      const siteIdx = segs[0] && /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(segs[0]) && segs.length >= 2 ? 1 : 0;
      site = segs[siteIdx] ?? '';
    }
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
  for (const m of corpus.matchAll(/https?:\/\/([a-z0-9-]+)\.icims\.com\/jobs\b/gi)) {
    const icimsSlug = m[1]!.toLowerCase();
    if (icimsSlug !== 'www' && icimsSlug !== 'login') {
      addBoard('icims', icimsSlug, `https://${icimsSlug}.icims.com/jobs/search?ss=1&in_iframe=1`);
    }
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
    const host = u.hostname.toLowerCase().replace(/\.+$/, '');
    const parts = u.pathname.split('/').filter(Boolean);
    if (host === 'greenhouse.io' || host.endsWith('.greenhouse.io')) {
      const forParam = u.searchParams.get('for')?.trim();
      if (forParam && (parts.length === 0 || /^(?:embed|view_job)$/i.test(parts[0]!))) {
        return forParam;
      }
      if (parts[0]?.toLowerCase() === 'v1' && parts[1]?.toLowerCase() === 'boards' && parts[2]) {
        return decodeURIComponent(parts[2]);
      }
      if (parts[0] && parts[0].toLowerCase() !== 'embed') return decodeURIComponent(parts[0]);
      return '';
    }
    if ((host === 'ats.rippling.com' || host === 'rippling.com' || host.endsWith('.rippling.com')) && parts.length >= 1) {
      const idx = parts.length >= 2 && /^[a-z]{2}(?:-[a-z]{2,4})?$/i.test(parts[0]!) ? 1 : 0;
      if (parts[idx] && !/^(?:jobs|careers|api)$/i.test(parts[idx]!)) return decodeURIComponent(parts[idx]!);
      return '';
    }
    if (host.endsWith('.rippling-ats.com')) {
      const sub = host.slice(0, -'.rippling-ats.com'.length);
      if (sub && !sub.includes('.')) return sub;
    }
    if (host === 'ashbyhq.com' || host.endsWith('.ashbyhq.com')) {
      if (parts[0]?.toLowerCase() === 'posting-api' && parts[1]?.toLowerCase() === 'job-board' && parts[2]) {
        return decodeURIComponent(parts[2]);
      }
      if (parts[0] && !/^(?:api|posting-api)$/i.test(parts[0])) return decodeURIComponent(parts[0]);
      return '';
    }
    if (host === 'lever.co' || host.endsWith('.lever.co')) {
      if (parts[0]?.toLowerCase() === 'v0' && parts[1]?.toLowerCase() === 'postings' && parts[2]) {
        return decodeURIComponent(parts[2]);
      }
      if (parts[0] && !/^(?:v0|api)$/i.test(parts[0])) return decodeURIComponent(parts[0]);
      return '';
    }
    if (host === 'smartrecruiters.com' || host.endsWith('.smartrecruiters.com')) {
      if (parts[0]?.toLowerCase() === 'v1' && parts[1]?.toLowerCase() === 'companies' && parts[2]) {
        return decodeURIComponent(parts[2]);
      }
      if (parts[0] && !/^(?:v1|api|app)$/i.test(parts[0])) return decodeURIComponent(parts[0]);
      return '';
    }
    if (host === 'workable.com' || host.endsWith('.workable.com')) {
      if (host !== 'apply.workable.com' && host !== 'jobs.workable.com' && host !== 'www.workable.com' && host !== 'workable.com') {
        const sub = host.slice(0, -'.workable.com'.length);
        if (sub && !sub.includes('.')) return sub;
      }
      if (parts[0]?.toLowerCase() === 'api' && parts[2]?.toLowerCase() === 'accounts' && parts[3]) {
        return decodeURIComponent(parts[3]);
      }
      if (parts[0] && !/^(?:j|view|api|jobs)$/i.test(parts[0])) return decodeURIComponent(parts[0]);
      return '';
    }
    if (host === 'dover.com' || host.endsWith('.dover.com') || host === 'dover.io' || host.endsWith('.dover.io')) {
      if (parts[0] && /^(?:apply|jobs|careers)$/i.test(parts[0]) && parts[1]) {
        return decodeURIComponent(parts[1]);
      }
      if (parts[0] && !/^(?:apply|jobs|careers|api)$/i.test(parts[0])) return decodeURIComponent(parts[0]);
      return '';
    }
    if (host === 'jobvite.com' || host.endsWith('.jobvite.com')) {
      if (host !== 'jobs.jobvite.com' && host !== 'www.jobvite.com' && host !== 'jobvite.com') {
        const sub = host.slice(0, -'.jobvite.com'.length);
        if (sub && !sub.includes('.')) return sub;
      }
      if (parts[0]?.toLowerCase() === 'careers' && parts[1]) return decodeURIComponent(parts[1]);
      if (parts[0] && !/^(?:CompanyJobs|j|api)$/i.test(parts[0])) return decodeURIComponent(parts[0]);
      return '';
    }
    if (host === 'app.jazz.co') {
      const createIdx = parts.findIndex((p) => p.toLowerCase() === 'create');
      if (createIdx >= 0 && parts[createIdx + 1]) return decodeURIComponent(parts[createIdx + 1]!);
      return '';
    }
    if ((host === 'gem.com' || host.endsWith('.gem.com') || host === 'jobs.polymer.co' || host.endsWith('.polymer.co')) && parts[0]) {
      return decodeURIComponent(parts[0]);
    }
    if ((host === 'join.com' || host === 'www.join.com') && parts[0]?.toLowerCase() === 'companies' && parts[1]) {
      return decodeURIComponent(parts[1]);
    }
    const wd = /^([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com$/i.exec(host);
    if (wd?.[1]) return wd[1];
    const icims = /^(?:(?:careers|jobs|external|hub|global)-)?([a-z0-9-]+?)(?:-(?:careers|jobs|portal))?\.icims\.com$/i.exec(host);
    if (icims?.[1] && !/^(?:www|jobs|careers|apply|search|login)$/i.test(icims[1])) return icims[1];
    const subAts =
      /^(?:careers-|jobs-)?([a-z0-9-]+)\.(?:pinpointhq\.com|pinpoint\.hq|bamboohr\.com|breezy\.hr|recruitee\.com|applytojob\.com|jazzhr\.(?:com|co)|(?:[a-z]{2}\.)?teamtailor\.com|(?:jobs\.)?personio\.(?:de|com)|eightfold\.ai|avature\.net|taleo\.net|homerun\.co|traffit\.com|zohorecruit\.com|freshteam\.com|comeet\.com)$/i.exec(
        host,
      );
    if (subAts?.[1] && !/^(?:www|jobs|careers|apply|search|login|app)$/i.test(subAts[1])) return subAts[1];
    return host.replace(/^(?:www|jobs|careers)\./, '');
  } catch {
    return 'unknown';
  }
}

export interface AtsPostingIdentity {
  platform: string;
  slug: string;
  boardUrl: string;
  postingId: string;
  roleTokens: string[];
}

const GENERIC_ROLE_TOKENS = new Set([
  'engineer',
  'engineering',
  'developer',
  'software',
  'manager',
  'director',
  'staff',
  'principal',
  'specialist',
  'analyst',
  'associate',
  'intern',
  'consultant',
  'architect',
  'designer',
  'product',
  'operations',
  'systems',
  'technical',
  'remote',
  'hybrid',
  'junior',
  'senior',
  'lead',
]);

function tokenizeRoleSlug(slugOrPath: string, excludeSlug?: string): string[] {
  const stop = new Set(['job', 'jobs', 'apply', 'application', 'careers', 'postings', 'senior', 'lead', 'the', 'and', 'for']);
  if (excludeSlug) {
    for (const part of excludeSlug.slice(0, 256).toLowerCase().split(/[^a-z0-9]+/)) {
      if (part.length >= 2) stop.add(part);
    }
  }
  return (slugOrPath.slice(0, 512).toLowerCase().match(/[a-z]{3,}/g) ?? []).filter((w) => !stop.has(w)).slice(0, 32);
}

/**
 * Parses a saved ATS posting URL into `(platform, slug, boardUrl, postingId)` so `verify` mode can batch-check
 * dozens of saved postings by fetching each company's board only **once**.
 */
export function parseAtsPostingIdentity(urlStr: string): AtsPostingIdentity | null {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase();
  const parts = u.pathname.split('/').filter(Boolean);

  // 1. Greenhouse (`boards.greenhouse.io/<org>/jobs/<id>`, `job-boards.[eu.]greenhouse.io/<org>/jobs/<id>`, or `?gh_jid=<id>`)
  const isGhUs = host === 'boards.greenhouse.io' || host === 'job-boards.greenhouse.io';
  const isGhEu = host === 'eu-boards.greenhouse.io' || host === 'job-boards.eu.greenhouse.io';
  if ((isGhUs || isGhEu) && parts[0]) {
    const org = parts[0];
    const ghJid = u.searchParams.get('gh_jid') ?? '';
    const postingId = parts[1] === 'jobs' && parts[2] ? parts[2] : /^\d+$/.test(ghJid) ? ghJid : '';
    if (postingId && isValidAtsSlug(org)) {
      const boardHost = isGhEu ? 'job-boards.eu.greenhouse.io' : 'job-boards.greenhouse.io';
      return {
        platform: 'greenhouse',
        slug: org,
        boardUrl: `https://${boardHost}/${org}`,
        postingId,
        roleTokens: tokenizeRoleSlug(parts.slice(2).join('-') || u.pathname, org),
      };
    }
  }
  const ghQueryId = u.searchParams.get('gh_jid');
  if (ghQueryId && /^\d+$/.test(ghQueryId)) {
    const baseCo = host.replace(/^(?:www|careers|jobs)\./, '').split('.')[0] ?? '';
    if (isValidAtsSlug(baseCo)) {
      return {
        platform: 'greenhouse',
        slug: baseCo,
        boardUrl: `https://job-boards.greenhouse.io/${baseCo}`,
        postingId: ghQueryId,
        roleTokens: tokenizeRoleSlug(u.pathname, baseCo),
      };
    }
  }

  // 2. Ashby (`jobs.ashbyhq.com/<org>/<jobId>[/application]`)
  if (host === 'jobs.ashbyhq.com' && parts.length >= 2 && parts[1]!.toLowerCase() !== 'jobs' && parts[1]!.toLowerCase() !== 'application') {
    const org = decodeURIComponent(parts[0]!);
    const jobId = decodeURIComponent(parts[1]!);
    return {
      platform: 'ashby',
      slug: org,
      boardUrl: `https://jobs.ashbyhq.com/${encodeURIComponent(org)}`,
      postingId: jobId,
      roleTokens: [],
    };
  }

  // 3. Lever (`jobs.[eu.]lever.co/<org>/<id>[/apply]`)
  if ((host === 'jobs.lever.co' || host === 'jobs.eu.lever.co') && parts.length >= 2) {
    const org = parts[0]!;
    const id = parts[1]!;
    return {
      platform: 'lever',
      slug: org,
      boardUrl: `https://${host}/${org}`,
      postingId: id,
      roleTokens: [],
    };
  }

  // 4. Workday (`<tenant>.wd<N>.myworkdayjobs.com/[locale/]<site>/job/...`)
  const wdMatch = /^([a-z0-9-]+)\.(?:wd\d+\.)?myworkday(?:jobs|site)\.com$/i.exec(host);
  if (wdMatch?.[1] && parts.length >= 3) {
    const tenant = wdMatch[1];
    const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) ? 1 : 0;
    const site = parts[idx] ?? '';
    const rest = parts.slice(idx + 1);
    if (site && rest[0] === 'job' && rest.length >= 2) {
      const tailSeg = rest[rest.length - 1]!;
      return {
        platform: 'workday',
        slug: `${tenant}/${site}`,
        boardUrl: `https://${host}/${site}`,
        postingId: tailSeg,
        roleTokens: tokenizeRoleSlug(tailSeg),
      };
    }
  }

  // 5. Workable (`apply.workable.com/<org>/j/<shortcode>`)
  if (host === 'apply.workable.com' && parts.length >= 3 && parts[1] === 'j') {
    return {
      platform: 'workable',
      slug: parts[0]!,
      boardUrl: `https://apply.workable.com/${parts[0]!}/`,
      postingId: parts[2]!,
      roleTokens: [],
    };
  }

  // 6. Gem (`jobs.gem.com/<org>/<id>`)
  if (host === 'jobs.gem.com' && parts.length >= 2) {
    return {
      platform: 'gem',
      slug: parts[0]!,
      boardUrl: `https://jobs.gem.com/${parts[0]!}`,
      postingId: parts[1]!,
      roleTokens: [],
    };
  }

  // 7. Rippling (`ats.rippling.com/[locale/]<org>/jobs/<uuid>`)
  if (host === 'ats.rippling.com' && parts.length >= 3) {
    const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) ? 1 : 0;
    const org = parts[idx] ?? '';
    const rest = parts.slice(idx + 1);
    if (org && rest[0] === 'jobs' && rest[1]) {
      return {
        platform: 'rippling',
        slug: org,
        boardUrl: `https://ats.rippling.com/${org}/jobs`,
        postingId: rest[1],
        roleTokens: [],
      };
    }
  }

  // 8. Pinpoint, BambooHR, Recruitee, iCIMS
  const pinpoint = /^([a-z0-9-]+)\.pinpointhq\.com$/i.exec(host);
  if (pinpoint?.[1] && parts[0] === 'postings' && parts[1]) {
    return {
      platform: 'pinpoint',
      slug: pinpoint[1],
      boardUrl: `https://${host}/`,
      postingId: parts[1],
      roleTokens: tokenizeRoleSlug(parts[1]),
    };
  }
  const bamboo = /^([a-z0-9-]+)\.bamboohr\.com$/i.exec(host);
  if (bamboo?.[1] && parts[0] === 'careers' && parts[1]) {
    return {
      platform: 'bamboohr',
      slug: bamboo[1],
      boardUrl: `https://${host}/careers`,
      postingId: parts[1],
      roleTokens: [],
    };
  }
  const recruitee = /^([a-z0-9-]+)\.recruitee\.com$/i.exec(host);
  if (recruitee?.[1] && parts[0] === 'o' && parts[1]) {
    return {
      platform: 'recruitee',
      slug: recruitee[1],
      boardUrl: `https://${host}/`,
      postingId: parts[1],
      roleTokens: tokenizeRoleSlug(parts[1]),
    };
  }
  const icims = /^([a-z0-9-]+)\.icims\.com$/i.exec(host);
  if (icims?.[1] && parts[0] === 'jobs' && parts[1] && /^\d+$/.test(parts[1])) {
    return {
      platform: 'icims',
      slug: icims[1],
      boardUrl: `https://${host}/jobs/search?ss=1&in_iframe=1`,
      postingId: parts[1],
      roleTokens: tokenizeRoleSlug(parts.slice(2).join('-')),
    };
  }

  return null;
}

function findSimilarRoles(
  openRoles: Array<{ title: string; url: string }>,
  roleTokens: string[],
): Array<{ title: string; url: string }> {
  if (openRoles.length === 0 || roleTokens.length === 0) {
    return [];
  }
  const uniqueTokens = [...new Set(roleTokens)].slice(0, 32);
  const boundedRoles = openRoles.length > 500 ? openRoles.slice(0, 500) : openRoles;
  const scored = boundedRoles
    .map((r) => {
      const titleWords = new Set(r.title.slice(0, 256).toLowerCase().match(/[a-z0-9]{2,}/g) ?? []);
      let distinctiveHits = 0;
      let genericHits = 0;
      for (const tok of uniqueTokens) {
        if (!titleWords.has(tok)) continue;
        if (GENERIC_ROLE_TOKENS.has(tok)) {
          genericHits++;
        } else {
          distinctiveHits++;
        }
      }
      const totalHits = distinctiveHits + genericHits;
      const qualifies =
        distinctiveHits >= 2 ||
        (distinctiveHits >= 1 && totalHits >= 2) ||
        (distinctiveHits >= 1 && uniqueTokens.length === 1) ||
        (distinctiveHits === 0 && genericHits >= 2 && uniqueTokens.every((t) => GENERIC_ROLE_TOKENS.has(t)));
      return { role: r, score: distinctiveHits * 3 + genericHits, qualifies };
    })
    .filter((s) => s.qualifies)
    .sort((a, b) => b.score - a.score);

  return scored.slice(0, 3).map((s) => s.role);
}

async function executeJobsVerifyMode(params: {
  urls: string[];
  payload: JobsToolPayload;
  executeScrape: (args: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  tracer?: RequestTracer | TraceContext;
  didExhaustBudget?: () => boolean;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const { urls, payload, executeScrape, didExhaustBudget } = params;
  const activeTracer = getActiveRequestTracer(params.tracer);
  const resolvedAdapterIds = new Set<string>();
  const parsedItems = urls.slice(0, 100).map((rawUrl) => ({
    url: rawUrl,
    identity: parseAtsPostingIdentity(rawUrl),
  }));

  // Group by `(platform, slug)` so each company board is fetched ONLY ONCE!
  const boardGroups = new Map<string, { boardUrl: string; platform: string; slug: string }>();
  for (const it of parsedItems) {
    if (!it.identity) continue;
    const key = `${it.identity.platform}:${it.identity.slug.toLowerCase()}`;
    if (!boardGroups.has(key)) {
      boardGroups.set(key, {
        boardUrl: it.identity.boardUrl,
        platform: it.identity.platform,
        slug: it.identity.slug,
      });
    }
  }

  const boardSnapshots = new Map<
    string,
    {
      boardStatus: AtsBoardStatus;
      truncated: boolean;
      boardIncomplete: boolean;
      openLinksLower: string[];
      openRoles: Array<{ title: string; url: string }>;
    }
  >();

  const groupEntries = [...boardGroups.entries()];
  for (let i = 0; i < groupEntries.length; i += 2) {
    const batch = groupEntries.slice(i, i + 2);
    const outs = await Promise.all(
      batch.map(([, grp]) =>
        executeScrape({
          url: grp.boardUrl,
          renderMode: 'auto',
          formats: ['markdown', 'links'],
          ...(payload.target ? { target: payload.target } : {}),
          ...(payload.site ? { site: payload.site } : {}),
        }).catch(() => null),
      ),
    );
    for (let j = 0; j < batch.length; j++) {
      const [key, grp] = batch[j]!;
      const sc = outs[j];
      if (!sc || sc.status !== 200 || sc.body?.ok !== true) {
        const hitBudget = sc?.body?.error === 'jobs_scrape_budget_exceeded';
        const upstreamStatus =
          typeof sc?.body?.status === 'number' && sc.body.status > 0 ? sc.body.status : (sc?.status ?? 0);
        boardSnapshots.set(key, {
          boardStatus: hitBudget
            ? 'budget_exhausted'
            : classifyAtsBoardStatus({
                httpStatus: upstreamStatus,
                requestedUrl: grp.boardUrl,
                finalUrl: typeof sc?.body?.finalUrl === 'string' ? sc.body.finalUrl : undefined,
              }),
          truncated: false,
          boardIncomplete: false,
          openLinksLower: [],
          openRoles: [],
        });
        continue;
      }

      const cState = typeof sc.body.contentState === 'string' ? sc.body.contentState : undefined;
      const rawJobs = Array.isArray(sc.body.jobs) ? (sc.body.jobs as StructuredJobRecord[]) : [];
      const rawRecords = Array.isArray(sc.body.records) ? (sc.body.records as Array<Record<string, unknown>>) : [];
      const rawLinks = Array.isArray(sc.body.links) ? (sc.body.links as string[]) : [];

      const openRoles: Array<{ title: string; url: string }> = [];
      for (const rj of rawJobs) {
        if (rj?.title && rj?.url) openRoles.push({ title: rj.title, url: rj.url });
      }
      if (openRoles.length === 0) {
        for (const rc of rawRecords) {
          if (typeof rc?.title === 'string' && typeof rc?.url === 'string') {
            openRoles.push({ title: rc.title, url: rc.url });
          }
        }
      }

      const openLinksLower = [
        ...rawLinks.map((l) => String(l).toLowerCase()),
        ...openRoles.map((r) => r.url.toLowerCase()),
      ];
      const bStatus = classifyAtsBoardStatus({
        httpStatus: sc.status,
        requestedUrl: grp.boardUrl,
        finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
        contentState: cState,
        jobCount: Math.max(openRoles.length, rawLinks.length),
      });
      const totalNum = typeof sc.body.total === 'number' && Number.isFinite(sc.body.total) ? sc.body.total : undefined;
      const extId = typeof sc.body.extractorId === 'string' ? sc.body.extractorId : '';
      const resolvedAts = extId || resolveAtsPreFetchSpec(grp.boardUrl)?.id || grp.platform;
      if (resolvedAts) resolvedAdapterIds.add(resolvedAts);
      const linksCoverFullBoard =
        totalNum !== undefined &&
        rawLinks.length >= totalNum &&
        extId !== 'workday-board' &&
        extId !== 'icims';

      boardSnapshots.set(key, {
        boardStatus: bStatus,
        truncated: sc.body.truncated === true,
        boardIncomplete: sc.body.truncated === true && !linksCoverFullBoard,
        openLinksLower,
        openRoles,
      });
    }
  }

  const results: VerifiedJobResult[] = [];
  for (const item of parsedItems) {
    if (!item.identity) {
      // Non-grouped custom URL: check directly once
      const direct = await executeScrape({
        url: item.url,
        renderMode: 'auto',
        formats: ['markdown'],
        ...(payload.target ? { target: payload.target } : {}),
        ...(payload.site ? { site: payload.site } : {}),
      }).catch(() => null);
      if (!direct) {
        results.push({ url: item.url, status: 'unknown' });
      } else if (
        direct.status === 404 ||
        direct.status === 410 ||
        direct.body?.status === 404 ||
        direct.body?.status === 410 ||
        direct.body?.contentState === 'closed_posting' ||
        direct.body?.contentState === 'soft_404' ||
        isClosedSchemeDowngradeResult(item.url, direct)
      ) {
        results.push({ url: item.url, status: 'closed' });
      } else if (direct.status === 200 && direct.body?.ok === true) {
        if (typeof direct.body.extractorId === 'string' && direct.body.extractorId) {
          resolvedAdapterIds.add(direct.body.extractorId);
        }
        results.push({ url: item.url, status: 'live' });
      } else {
        results.push({ url: item.url, status: 'unknown' });
      }
      continue;
    }

    const key = `${item.identity.platform}:${item.identity.slug.toLowerCase()}`;
    const snap = boardSnapshots.get(key);
    if (!snap || snap.boardStatus === 'blocked_or_down' || snap.boardStatus === 'budget_exhausted') {
      results.push({
        url: item.url,
        status: 'unknown',
        platform: item.identity.platform,
        slug: item.identity.slug,
        ...(snap?.boardStatus === 'budget_exhausted' ? { boardStatus: 'budget_exhausted' as const } : {}),
      });
      continue;
    }
    if (snap.boardStatus === 'wrong_slug') {
      results.push({
        url: item.url,
        status: 'board_gone',
        platform: item.identity.platform,
        slug: item.identity.slug,
      });
      continue;
    }

    const idLower = item.identity.postingId.toLowerCase();
    const cleanOrigLower = item.url.replace(/\/+$/, '').toLowerCase();
    const isMatch = snap.openLinksLower.some(
      (lnk) =>
        lnk.replace(/\/+$/, '') === cleanOrigLower ||
        lnk.includes(`/${idLower}`) ||
        lnk.endsWith(`=${idLower}`),
    );

    if (isMatch) {
      results.push({
        url: item.url,
        status: 'live',
        platform: item.identity.platform,
        slug: item.identity.slug,
      });
      continue;
    }

    // Paginated boards (Workday CXS 20/page, iCIMS, or salvaged >16 MiB boards): check the single job URL before marking closed!
    if (snap.boardIncomplete) {
      const wdCheck = await executeScrape({
        url: item.url,
        renderMode: 'auto',
        formats: ['markdown'],
        ...(payload.target ? { target: payload.target } : {}),
        ...(payload.site ? { site: payload.site } : {}),
      }).catch(() => null);
      if (wdCheck?.body?.error === 'jobs_scrape_budget_exceeded') {
        results.push({
          url: item.url,
          status: 'unknown',
          platform: item.identity.platform,
          slug: item.identity.slug,
          boardStatus: 'budget_exhausted',
        });
        continue;
      }
      if (wdCheck?.status === 200 && wdCheck.body?.ok === true && wdCheck.body?.contentState !== 'closed_posting' && wdCheck.body?.contentState !== 'soft_404') {
        const wdExtId = typeof wdCheck.body.extractorId === 'string' ? wdCheck.body.extractorId : resolveAtsPreFetchSpec(item.url)?.id;
        if (wdExtId) resolvedAdapterIds.add(wdExtId);
        results.push({
          url: item.url,
          status: 'live',
          platform: item.identity.platform,
          slug: item.identity.slug,
        });
        continue;
      }
    }

    const similar = findSimilarRoles(snap.openRoles, item.identity.roleTokens);
    results.push({
      url: item.url,
      status: 'closed',
      platform: item.identity.platform,
      slug: item.identity.slug,
      ...(similar.length > 0 ? { similarOpenRoles: similar } : {}),
    });
  }

  activeTracer?.setAttribute('edgefetch.jobs.mode', 'verify');
  activeTracer?.setAttribute('edgefetch.jobs.boards_discovered', boardGroups.size);
  activeTracer?.setAttribute('edgefetch.jobs.jobs_returned', results.length);
  if (resolvedAdapterIds.size > 0) {
    activeTracer?.setAttribute('edgefetch.adapter_id', [...resolvedAdapterIds].join(','));
  }

  const verifyHitBudget = Boolean(didExhaustBudget?.());
  return {
    status: 200,
    body: {
      ok: true,
      mode: 'verify',
      boardsFetched: boardGroups.size,
      checked: results.length,
      ...(verifyHitBudget
        ? {
            budgetExhausted: true,
            notes: [`Scrape budget (${MAX_JOBS_TOTAL_SCRAPES}) exhausted before all postings could be verified.`],
          }
        : {}),
      results,
    },
  };
}

const MAX_JOBS_QUERY_CHARS = 256;
const QUERY_STOP_WORDS = new Set(['the', 'and', 'for', 'with', 'from', 'into', 'role', 'job', 'jobs', 'open', 'position']);
const REMOTE_LOCATION_TOKENS = new Set(['remote', 'anywhere', 'work from home', 'wfh']);

function extractJobWordTokens(text: string): string[] {
  return text.match(/[\p{L}\p{N}+#]+/gu) ?? [];
}

function jobWordTokensMatch(hayToken: string, queryToken: string): boolean {
  if (hayToken === queryToken) return true;
  if (queryToken.length >= 3) {
    if (hayToken === `${queryToken}s` || hayToken === `${queryToken}es`) return true;
    if (queryToken.endsWith('s') && queryToken.slice(0, -1) === hayToken) return true;
    if (queryToken.endsWith('es') && queryToken.length >= 4 && queryToken.slice(0, -2) === hayToken) return true;
  }
  return false;
}

function containsJobTokenSequence(hayTokens: readonly string[], querySeq: readonly string[]): boolean {
  if (querySeq.length === 0 || hayTokens.length < querySeq.length) return false;
  const maxStart = hayTokens.length - querySeq.length;
  for (let i = 0; i <= maxStart; i++) {
    let ok = true;
    for (let j = 0; j < querySeq.length; j++) {
      if (!jobWordTokensMatch(hayTokens[i + j]!, querySeq[j]!)) {
        ok = false;
        break;
      }
    }
    if (ok) return true;
  }
  return false;
}

function matchesJobQueryRelevance(
  title: string,
  snippet: string | undefined,
  query: string,
): 'phrase' | 'all_tokens' | null {
  const cappedQuery = query.length > MAX_JOBS_QUERY_CHARS ? query.slice(0, MAX_JOBS_QUERY_CHARS) : query;
  const normPhrase = cappedQuery.toLowerCase().replace(/\s+/g, ' ').trim();
  if (!normPhrase) return 'phrase';
  const cappedTitle = title.length > 1024 ? title.slice(0, 1024) : title;
  const titleLower = cappedTitle.toLowerCase().replace(/\s+/g, ' ');
  const rawQueryWords = extractJobWordTokens(normPhrase).slice(0, 32);
  const titleWords = extractJobWordTokens(titleLower);
  if (rawQueryWords.length > 0 && containsJobTokenSequence(titleWords, rawQueryWords)) {
    return 'phrase';
  }
  if (rawQueryWords.length === 0 && titleLower.includes(normPhrase)) {
    return 'phrase';
  }

  const qTokens = rawQueryWords.filter((t) => t.length >= 2 && !QUERY_STOP_WORDS.has(t));
  if (qTokens.length === 0) {
    return rawQueryWords.length > 0 ? (containsJobTokenSequence(titleWords, rawQueryWords) ? 'phrase' : null) : null;
  }
  if (qTokens.every((qt) => titleWords.some((tw) => jobWordTokensMatch(tw, qt)))) {
    return 'all_tokens';
  }
  const distinctiveQ = qTokens.filter((qt) => !GENERIC_ROLE_TOKENS.has(qt));
  if (distinctiveQ.length > 0 && distinctiveQ.every((qt) => titleWords.some((tw) => jobWordTokensMatch(tw, qt)))) {
    const cappedSnippet = snippet ? (snippet.length > 2048 ? snippet.slice(0, 2048) : snippet) : '';
    const fullWords = [...titleWords, ...extractJobWordTokens(cappedSnippet.toLowerCase())];
    if (qTokens.every((qt) => fullWords.some((fw) => jobWordTokensMatch(fw, qt)))) {
      return 'all_tokens';
    }
  }
  return null;
}

function matchesSingleGeoLocation(locStr: string, filterTerm: string): boolean {
  const isUsFilter =
    filterTerm === 'united states' ||
    filterTerm === 'usa' ||
    filterTerm === 'u.s.' ||
    filterTerm === 'u.s.a.' ||
    filterTerm === 'us';
  if (!isUsFilter) {
    return locStr.includes(filterTerm);
  }
  const hasExplicitUsCountryOrCity =
    /\b(?:united states|usa|u\.s\.a?\.?|us\b|americas?[ \t]{0,8}\(us\)|us-[a-z]{2}\b|california|new york|texas|washington|massachusetts|virginia|colorado|illinois|georgia|florida|san francisco|nyc|seattle|austin|boston|chicago|los angeles|denver|atlanta|menlo park|mountain view|palo alto|sunnyvale|santa clara|san jose|redmond|bellevue|mclean|reston)\b/i.test(
      locStr,
    );
  if (hasExplicitUsCountryOrCity) return true;

  // Match `, CA` / `, NY` / `, WA` state abbreviations unless `, ON, CA` / `Canada` ISO country code
  const hasCanadianProvinceOrCountry =
    /\b(?:canada|toronto|vancouver|montreal|ottawa|calgary|ontario|quebec|british columbia)\b|,[ \t]{0,8}(?:on|bc|qc|ab),[ \t]{0,8}ca\b/i.test(
      locStr,
    );
  if (hasCanadianProvinceOrCountry) return false;

  return /,[ \t]{0,8}(?:al|ak|az|ar|ca|co|ct|de|dc|fl|ga|hi|id|il|in|ia|ks|ky|la|me|md|ma|mi|mn|ms|mo|mt|ne|nv|nh|nj|nm|ny|nc|nd|oh|ok|or|pa|ri|sc|sd|tn|tx|ut|vt|va|wa|wv|wi|wy)\b/i.test(
    locStr,
  );
}

function matchesGeoLocationsFilter(jobLocations: string[], geoFilters: string[]): boolean {
  if (jobLocations.length === 0 || geoFilters.length === 0) return false;
  const locStr = jobLocations
    .slice(0, 32)
    .map((s) => (s.length > 256 ? s.slice(0, 256) : s))
    .join(' | ')
    .toLowerCase()
    .trim();
  if (!locStr) return false;
  const boundedFilters = geoFilters.slice(0, 32).map((gf) => (gf.length > 128 ? gf.slice(0, 128) : gf));
  return boundedFilters.some((gf) => matchesSingleGeoLocation(locStr, gf));
}

const COMPANY_LEGAL_ENTITY_SUFFIXES = new Set([
  'inc',
  'incorporated',
  'corp',
  'corporation',
  'llc',
  'llp',
  'lp',
  'pbc',
  'plc',
  'ltd',
  'limited',
  'gmbh',
  'ag',
  'se',
  'sa',
  'sas',
  'sarl',
  'bv',
  'nv',
  'oy',
  'ab',
  'as',
  'aps',
  'kk',
  'gk',
  'pty',
  'pte',
  'bhd',
  'sdn',
  'co',
  'company',
  'companies',
  'holdings',
  'holding',
  'enterprises',
]);

const COMPANY_SUBSIDIARY_AND_GEO_QUALIFIERS = new Set([
  ...COMPANY_LEGAL_ENTITY_SUFFIXES,
  // Corporate divisions, business lines & tech descriptors ("Stripe Payments UK", "Notion Labs, Inc.", "Palantir Technologies", "Coinbase Global, Inc.")
  'labs',
  'lab',
  'technologies',
  'technology',
  'tech',
  'systems',
  'software',
  'networks',
  'network',
  'security',
  'cloud',
  'ai',
  'research',
  'robotics',
  'industries',
  'industrial',
  'payments',
  'financial',
  'finance',
  'markets',
  'capital',
  'bank',
  'banking',
  'commerce',
  'media',
  'studios',
  'studio',
  'entertainment',
  'gaming',
  'games',
  'health',
  'healthcare',
  'bio',
  'therapeutics',
  'energy',
  'power',
  'logistics',
  'mobility',
  'automotive',
  'motors',
  'aerospace',
  'aviation',
  'space',
  'defense',
  'pharma',
  'pharmaceuticals',
  'biosciences',
  'biotech',
  'diagnostics',
  'medical',
  'devices',
  'insurance',
  'retail',
  'electronics',
  'semiconductor',
  'semiconductors',
  'microelectronics',
  'federal',
  'government',
  'public',
  'sector',
  'services',
  'solutions',
  'web',
  'people',
  'center',
  'digital',
  'platform',
  'platforms',
  'data',
  'analytics',
  'computing',
  'communications',
  'telecom',
  'wireless',
  'group',
  'international',
  'intl',
  'hq',
  'io',
  'so',
  'app',
  'dev',
  'net',
  'org',
  'com',
  // Geographic / regional subsidiary qualifiers
  'us',
  'usa',
  'uk',
  'eu',
  'na',
  'emea',
  'apac',
  'latam',
  'americas',
  'europe',
  'asia',
  'pacific',
  'global',
  'worldwide',
  'north',
  'south',
  'east',
  'west',
  'america',
  'canada',
  'mexico',
  'brazil',
  'argentina',
  'chile',
  'colombia',
  'ireland',
  'germany',
  'france',
  'spain',
  'italy',
  'netherlands',
  'sweden',
  'norway',
  'denmark',
  'finland',
  'poland',
  'switzerland',
  'austria',
  'belgium',
  'portugal',
  'india',
  'japan',
  'korea',
  'singapore',
  'australia',
  'new',
  'zealand',
  'israel',
  'uae',
  'taiwan',
  'philippines',
  'indonesia',
  'vietnam',
  'thailand',
  'malaysia',
  'china',
  'hong',
  'kong',
]);

// Tight allowlist of official unhyphenated regional/HQ ATS tenant suffixes (`boards.greenhouse.io/doordashusa`, `jobs.ashbyhq.com/notionhq`).
// NEVER allows `-inc`, `-llc`, `-corp`, `-jobs`, `-careers`, or unhyphenated `inc`/`jobs`/`careers`/`ai`/`labs` on unverified ATS slugs!
const UNHYPHENATED_ATS_GEO_HQ_SUFFIXES = new Set([
  'usa',
  'us',
  'uk',
  'eu',
  'hq',
  'na',
  'emea',
  'apac',
  'latam',
  'canada',
  'japan',
  'india',
  'australia',
  'germany',
  'france',
  'ireland',
  'singapore',
]);

const COMPANY_NEGATION_WORDS = new Set([
  'not',
  'non',
  'anti',
  'ex',
  'former',
  'unlike',
  'never',
  'no',
  'without',
  'vs',
  'versus',
  'fake',
  'clone',
  'mock',
  'phish',
  'phishing',
  'scam',
  'spoof',
  'parody',
  'impostor',
  'imposter',
  'unofficial',
  'recruiting',
  'recruitment',
  'recruiter',
  'recruiters',
  'staffing',
  'headhunter',
  'agency',
  'outsourcing',
  'confidential',
  'stealth',
]);

const CONCAT_NEGATION_PREFIX_RE = /^(?:not|non|anti|ex|former|unlike|fake|clone|mock|spoof|phish|scam|impostor|imposter|unofficial)/;

const TWO_PART_PUBLIC_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'me.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.jp',
  'ne.jp',
  'or.jp',
  'co.nz',
  'co.in',
  'firm.in',
  'co.kr',
  'co.il',
  'com.br',
  'com.mx',
  'com.ar',
  'com.co',
  'com.sg',
  'com.hk',
  'com.tw',
  'com.my',
  'com.ph',
  'com.vn',
  'com.tr',
  'co.za',
  'co.id',
  'co.th',
]);

const UNVERIFIED_JOB_AGGREGATOR_DOMAINS = [
  'linkedin.com',
  'indeed.com',
  'glassdoor.com',
  'ziprecruiter.com',
  'monster.com',
  'dice.com',
  'simplyhired.com',
  'careerbuilder.com',
  'talent.com',
  'jooble.org',
  'snagajob.com',
  'lensa.com',
  'wayup.com',
  'wellfound.com',
  'angel.co',
  'otta.com',
  'builtin.com',
  'levels.fyi',
  'ycombinator.com',
  'reddit.com',
  'medium.com',
  'substack.com',
  'wordpress.com',
  'blogspot.com',
  'wixsite.com',
  'squarespace.com',
  'webflow.io',
  'notion.site',
  'github.io',
  'gitlab.io',
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'workers.dev',
  'herokuapp.com',
  'onrender.com',
  'railway.app',
  'fly.dev',
  'web.app',
  'firebaseapp.com',
  'myshopify.com',
];

const VETTED_CORPORATE_TLDS = new Set([
  'com',
  'io',
  'ai',
  'co',
  'org',
  'net',
  'app',
  'dev',
  'so',
  'sh',
  'gg',
  'tech',
  'cloud',
  'security',
  'finance',
  'money',
  'vc',
  'bio',
  'health',
  'energy',
  'jobs',
  'uk',
  'de',
  'fr',
  'ca',
  'eu',
  'ch',
  'nl',
  'se',
  'no',
  'dk',
  'fi',
  'ie',
  'es',
  'it',
  'pl',
  'at',
  'be',
  'pt',
  'jp',
  'au',
  'nz',
  'in',
  'sg',
  'kr',
  'il',
  'br',
  'mx',
  'ar',
  'za',
  'hk',
  'tw',
  'google',
  'apple',
  'amazon',
  'aws',
  'microsoft',
  'netflix',
  'bloomberg',
  'barclays',
  'deloitte',
  'cern',
]);

const OFFICIAL_COMPANY_CAREER_DOMAINS: Readonly<Record<string, readonly string[]>> = {
  google: ['google.com', 'about.google', 'careers.google', 'deepmind.google', 'alphabet.com'],
  alphabet: ['alphabet.com', 'google.com', 'about.google', 'waymo.com', 'verily.com'],
  meta: ['meta.com', 'metacareers.com', 'facebook.com', 'fb.com'],
  facebook: ['metacareers.com', 'meta.com', 'facebook.com'],
  amazon: ['amazon.com', 'amazon.jobs'],
  aws: ['amazon.jobs', 'amazon.com'],
  apple: ['apple.com'],
  microsoft: ['microsoft.com', 'github.com', 'linkedin.com'],
  netflix: ['netflix.com', 'netflix.net'],
  stripe: ['stripe.com', 'stripe.co.jp', 'stripe.co.uk'],
  cloudflare: ['cloudflare.com'],
  openai: ['openai.com'],
  anthropic: ['anthropic.com'],
  datadog: ['datadoghq.com'],
  notion: ['notion.so', 'makenotion.com'],
  block: ['block.xyz', 'squareup.com', 'cash.app'],
  xai: ['x.ai'],
  '1password': ['1password.com'],
  huggingface: ['huggingface.co'],
  paloaltonetworks: ['paloaltonetworks.com'],
  scaleai: ['scale.com'],
};

const CENTRALNIC_PRIVATE_SUFFIXES = new Set([
  'us.com',
  'uk.com',
  'eu.com',
  'de.com',
  'jpn.com',
  'cn.com',
  'br.com',
  'ru.com',
  'sa.com',
  'za.com',
  'se.com',
  'no.com',
  'qc.com',
  'uy.com',
  'kr.com',
  'co.com',
  'com.de',
  'com.se',
  'gb.net',
  'uk.net',
  'se.net',
  'in.net',
]);

const CURATED_PUBLIC_FEED_HOST_BY_SOURCE: Readonly<Record<string, string>> = {
  weworkremotely: 'weworkremotely.com',
  'weworkremotely-feed': 'weworkremotely.com',
  himalayas: 'himalayas.app',
  'himalayas-feed': 'himalayas.app',
  workingnomads: 'workingnomads.com',
  'workingnomads-feed': 'workingnomads.com',
  workatastartup: 'workatastartup.com',
  'workatastartup-yc-mirror': 'workatastartup.com',
};

function isKnownMultiTenantAtsHost(host: string): boolean {
  return (
    host === 'greenhouse.io' ||
    host.endsWith('.greenhouse.io') ||
    host === 'ashbyhq.com' ||
    host.endsWith('.ashbyhq.com') ||
    host === 'lever.co' ||
    host.endsWith('.lever.co') ||
    host === 'smartrecruiters.com' ||
    host.endsWith('.smartrecruiters.com') ||
    host === 'workable.com' ||
    host.endsWith('.workable.com') ||
    host === 'gem.com' ||
    host.endsWith('.gem.com') ||
    host === 'rippling.com' ||
    host.endsWith('.rippling.com') ||
    host.endsWith('.rippling-ats.com') ||
    host === 'jobvite.com' ||
    host.endsWith('.jobvite.com') ||
    host === 'dover.com' ||
    host.endsWith('.dover.com') ||
    host === 'dover.io' ||
    host.endsWith('.dover.io') ||
    host === 'polymer.co' ||
    host.endsWith('.polymer.co') ||
    host === 'join.com' ||
    host === 'www.join.com' ||
    host === 'app.jazz.co' ||
    host.endsWith('.myworkdayjobs.com') ||
    host.endsWith('.myworkdaysite.com') ||
    host.endsWith('.pinpointhq.com') ||
    host === 'pinpoint.hq' ||
    host.endsWith('.pinpoint.hq') ||
    host === 'bamboohr.com' ||
    host.endsWith('.bamboohr.com') ||
    host === 'breezy.hr' ||
    host.endsWith('.breezy.hr') ||
    host === 'recruitee.com' ||
    host.endsWith('.recruitee.com') ||
    host === 'applytojob.com' ||
    host.endsWith('.applytojob.com') ||
    host === 'jazzhr.com' ||
    host.endsWith('.jazzhr.com') ||
    host === 'jazzhr.co' ||
    host.endsWith('.jazzhr.co') ||
    host.endsWith('.teamtailor.com') ||
    host === 'icims.com' ||
    host.endsWith('.icims.com') ||
    host === 'personio.de' ||
    host.endsWith('.personio.de') ||
    host === 'personio.com' ||
    host.endsWith('.personio.com') ||
    host.endsWith('.oraclecloud.com') ||
    host.endsWith('.taleo.net') ||
    host.endsWith('.successfactors.com') ||
    host.endsWith('.successfactors.eu') ||
    host.endsWith('.eightfold.ai') ||
    host.endsWith('.avature.net') ||
    host.endsWith('.dayforcehcm.com') ||
    host.endsWith('.ultipro.com') ||
    host.endsWith('.paylocity.com') ||
    host.endsWith('.paycomonline.net') ||
    host.endsWith('.adp.com') ||
    host.endsWith('.homerun.co') ||
    host.endsWith('.traffit.com') ||
    host.endsWith('.zohorecruit.com') ||
    host.endsWith('.freshteam.com') ||
    host.endsWith('.comeet.com')
  );
}

function extractRegistrableBrandInfo(hostname: string): {
  sld: string;
  tld: string;
  registrableDomain: string;
  joinedRegistrable: string;
  isVettedTld: boolean;
} | null {
  const clean = hostname.trim().toLowerCase().replace(/\.+$/, '');
  if (!clean || !clean.includes('.')) return null;
  const labels = clean.split('.');
  if (labels.length < 2 || labels.some((l) => !l)) return null;
  // Reject raw IPv4/hex TLD literals
  if (/^(?:\d+|0x[0-9a-f]+)$/i.test(labels[labels.length - 1]!)) return null;
  const lastTwo = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`;
  if (CENTRALNIC_PRIVATE_SUFFIXES.has(lastTwo)) return null;
  if (TWO_PART_PUBLIC_SUFFIXES.has(lastTwo)) {
    if (labels.length < 3) return null;
    const sld = labels[labels.length - 3]!;
    const cc = labels[labels.length - 1]!;
    return {
      sld,
      tld: lastTwo,
      registrableDomain: `${sld}.${lastTwo}`,
      joinedRegistrable: `${sld}${lastTwo.replace(/\./g, '')}`,
      isVettedTld: VETTED_CORPORATE_TLDS.has(cc),
    };
  }
  const sld = labels[labels.length - 2]!;
  const tld = labels[labels.length - 1]!;
  return {
    sld,
    tld,
    registrableDomain: `${sld}.${tld}`,
    joinedRegistrable: `${sld}${tld}`,
    isVettedTld: VETTED_CORPORATE_TLDS.has(tld),
  };
}

function normalizeDottedCorporateAbbreviations(raw: string): string {
  // Collapse known dotted legal/country abbreviations (`L.L.C.` -> `llc`, `P.B.C.` -> `pbc`, `U.K.` -> `uk`, `U.S.A.` -> `usa`)
  // WITHOUT collapsing arbitrary spaced/dotted brand spoofs like `S.T.R.I.P.E`!
  return raw.replace(
    /\b(?:l\.l\.c|p\.b\.c|p\.l\.c|l\.l\.p|i\.n\.c|c\.o\.r\.p|l\.t\.d|u\.s\.a|u\.s|u\.k|s\.a|b\.v|n\.v|a\.g|s\.e|k\.k)\.?/gi,
    (m) => m.replace(/\./g, ''),
  );
}

const SUBDOMAIN_CAREER_PREFIXES = new Set(['www', 'jobs', 'careers', 'career', 'hiring', 'work', 'join', 'about', 'people', 'talent', 'boards']);

const KNOWN_MULTIWORD_SLUG_PARTS = new Set([
  'ai',
  'io',
  'db',
  'os',
  'ui',
  'ml',
  'labs',
  'tech',
  'cloud',
  'data',
  'face',
  'open',
  'scale',
  'hugging',
  'palo',
  'alto',
  'networks',
  'systems',
  'crowd',
  'strike',
  'snow',
  'flake',
  'dog',
  'mongo',
  'cyber',
  'digital',
  'ocean',
  'tail',
  'eleven',
  'deep',
  'mind',
  'together',
  'fire',
  'crawl',
  'edge',
  'fetch',
  'new',
  'relic',
  'service',
  'now',
  'work',
  'day',
  'door',
  'dash',
  'coin',
  'base',
  'robin',
  'hood',
  'instacart',
  'one',
  'password',
  'weights',
  'biases',
  'magic',
  'red',
  'hat',
]);

export function expandCompanyFilterTokens(rawCompany: string): string[] {
  const out = new Set<string>();
  let bounded = rawCompany.length > 256 ? rawCompany.slice(0, 256).trim() : rawCompany.trim();
  if (!bounded) return [];

  // If caller passed a URL or domain (`https://careers.stripe.com`, `jobs.netflix.com`, `about.google`, `datadoghq.com`),
  // extract the registrable brand SLD (and brand TLD like `.google` / `.apple`) cleanly!
  let candidateHost = '';
  if (/^https?:\/\//i.test(bounded)) {
    try {
      candidateHost = new URL(bounded).hostname.toLowerCase().replace(/\.+$/, '');
    } catch {
      candidateHost = '';
    }
  } else if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(bounded) && !/\.(?:l\.l\.c|p\.b\.c|p\.l\.c|i\.n\.c|l\.t\.d|u\.k|u\.s\.a|k\.k)\.?$/i.test(bounded)) {
    candidateHost = bounded.toLowerCase().replace(/\.+$/, '');
  }
  if (candidateHost && !isKnownMultiTenantAtsHost(candidateHost)) {
    const info = extractRegistrableBrandInfo(candidateHost);
    if (info) {
      if (info.sld.length >= 2 && !SUBDOMAIN_CAREER_PREFIXES.has(info.sld)) {
        out.add(info.sld.replace(/[^a-z0-9]+/g, ''));
        if (info.sld.endsWith('hq') && info.sld.length >= 5) {
          out.add(info.sld.slice(0, -2).replace(/[^a-z0-9]+/g, ''));
        }
      }
      if (info.joinedRegistrable.length >= 2 && !SUBDOMAIN_CAREER_PREFIXES.has(info.sld)) {
        out.add(info.joinedRegistrable);
      }
      if (
        info.tld.length >= 3 &&
        !TWO_PART_PUBLIC_SUFFIXES.has(info.tld) &&
        !['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'app', 'dev', 'tech', 'cloud', 'jobs', 'info', 'biz', 'xyz'].includes(info.tld)
      ) {
        out.add(info.tld);
      }
      return [...out].filter((t) => t.length >= 2);
    }
  }

  const collapsed = normalizeDottedCorporateAbbreviations(bounded).toLowerCase();
  const fullClean = collapsed.replace(/[^a-z0-9]+/g, '');
  if (fullClean.length >= 2) out.add(fullClean);

  const words = collapsed.match(/[a-z0-9]+/g) ?? [];
  while (words.length > 1 && COMPANY_SUBSIDIARY_AND_GEO_QUALIFIERS.has(words[words.length - 1]!)) {
    words.pop();
    const core = words.join('');
    if (core.length >= 2) out.add(core);
  }
  return [...out];
}

function isVerifiedMultiWordHyphenJoin(parts: string[], tok: string, rawCompanyHint?: string, segmentedTokens?: Set<string>): boolean {
  if (parts.length < 2 || parts.length > 4 || parts.some((p) => p.length < 2)) return false;
  if (parts.join('') !== tok) return false;
  const segmentedKey = parts.join('-');
  if (segmentedTokens?.has(segmentedKey)) return true;
  if (rawCompanyHint) {
    const normHint = normalizeDottedCorporateAbbreviations(rawCompanyHint);
    if (!/[.\-/_]/.test(normHint.slice(0, Math.min(normHint.length, tok.length + 4)))) {
      const cWords = normHint.toLowerCase().match(/[a-z0-9]+/g) ?? [];
      if (
        cWords.length >= parts.length &&
        parts.every((p, idx) => cWords[idx] === p) &&
        cWords.slice(parts.length).every((w) => COMPANY_SUBSIDIARY_AND_GEO_QUALIFIERS.has(w))
      ) {
        return true;
      }
    }
  }
  // Without space-separated corroboration, ONLY allow hyphenated split when every part is a known multi-word brand stem
  // (so `"palo-alto-networks"`, `"hugging-face"`, `"scale-ai"` match, while `"st-ripe"`, `"str-ipe"`, `"stri-pe"` NEVER match `"stripe"`!)
  return parts.every((p) => KNOWN_MULTIWORD_SLUG_PARTS.has(p));
}

function matchesAtsTenantSlugAgainstToken(
  rawSlug: string,
  tok: string,
  opts?: { host?: string; jobCompany?: string; segmentedTokens?: Set<string> },
): boolean {
  if (!rawSlug || !tok || tok.length < 2 || tok.length > 128) return false;
  const bounded = rawSlug.length > 128 ? rawSlug.slice(0, 128) : rawSlug;
  if (/[\u0000-\u001f\u007f-\u00a0\u00ad\u034f\u061c\u17b4\u17b5\u180b-\u180f\u2000-\u200f\u2028-\u202f\u205f-\u206f\ufeff]/.test(bounded)) {
    return false;
  }
  if (!/^[A-Za-z0-9_-]+$/.test(bounded)) return false;
  const lower = bounded.toLowerCase();

  // 1. Exact tenant slug (`boards.greenhouse.io/stripe` === `"stripe"`)
  if (lower === tok) return true;

  // 2. Multi-word brand joined strictly with `-` or `_` (`jobs.lever.co/palo-alto-networks` <-> `"paloaltonetworks"`):
  // ZERO extra suffix/prefix words (`-careers-portal`, `-hiring-team`, `-recruiting-agency`, `-unofficial`, `-fake`, `-scam`,
  // `-external`, `-inc`, `-llc`, `-jobs`, `st-ripe`, `s-t-r-i-p-e` -> 100% REJECTED!)
  if (lower.includes('-') || lower.includes('_')) {
    const parts = lower.split(/[-_]+/).filter(Boolean);
    return isVerifiedMultiWordHyphenJoin(parts, tok, opts?.jobCompany, opts?.segmentedTokens);
  }

  // 3. Official unhyphenated geographic/HQ/Inc ATS tenant slug (`doordashusa`, `notionhq`, `stripehq`, `stripeinc`, `cloudflareinc`):
  if (tok.length >= 3 && /^[a-z0-9]+$/.test(lower) && lower.startsWith(tok)) {
    const rem = lower.slice(tok.length);
    if (UNHYPHENATED_ATS_GEO_HQ_SUFFIXES.has(rem)) return true;
    // Official `<brand>inc` board slug on Greenhouse/Ashby/Workday/etc. (`boards.greenhouse.io/stripeinc`, `cloudflareinc`),
    // while keeping unverified `lever.co/<brand>inc` rejected unless `<brand>inc` / `<Brand>, Inc.` was explicitly requested.
    if (rem === 'inc' && !(opts?.host && (opts.host === 'lever.co' || opts.host.endsWith('.lever.co')))) {
      return true;
    }
  }
  return false;
}

function hasExplicitSpoofOrNegationInCompany(rawCompany: string, allowedTokens: Set<string>): boolean {
  const bounded = rawCompany.length > 256 ? rawCompany.slice(0, 256) : rawCompany;
  if (/[\u0000-\u001f\u007f-\u00a0\u00ad\u034f\u061c\u17b4\u17b5\u180b-\u180f\u2000-\u200f\u2028-\u202f\u205f-\u206f\ufeff]/.test(bounded)) {
    return true;
  }
  const normalizedAbbrev = normalizeDottedCorporateAbbreviations(bounded);
  // Reject dotted/spaced/hyphenated single-letter brand spoofs (`S.T.R.I.P.E.`, `S-T-R-I-P-E`, `S/T/R/I/P/E`)
  if (/(?:^|\s)[A-Za-z](?:[.\-/][A-Za-z]){3,}\b/.test(normalizedAbbrev)) {
    return true;
  }
  const rawWords = normalizedAbbrev.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
  for (const rw of rawWords) {
    let w = rw;
    if (!/^[a-z0-9]+$/.test(w)) {
      if (/^[\p{Script=Latin}0-9]+$/u.test(w)) {
        w = w.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      } else {
        // Non-Latin homoglyphs (`Stripe Fаke`, `Не Stripe`, `Stripe 偽物`)
        return true;
      }
    }
    if (!/^[a-z0-9]+$/.test(w)) return true;
    if (COMPANY_NEGATION_WORDS.has(w) && !allowedTokens.has(w)) return true;
    if (!allowedTokens.has(w) && CONCAT_NEGATION_PREFIX_RE.test(w)) {
      for (const tok of allowedTokens) {
        if (tok.length >= 3 && w.endsWith(tok)) return true;
      }
    }
  }
  return false;
}

function matchesFirstPartyDomainAgainstToken(
  hostname: string,
  tok: string,
  opts?: { rawCompany?: string; segmentedTokens?: Set<string> },
): boolean {
  const info = extractRegistrableBrandInfo(hostname);
  if (!info) return false;
  const { sld, tld, registrableDomain, joinedRegistrable, isVettedTld } = info;
  if (!sld.startsWith(tok) && CONCAT_NEGATION_PREFIX_RE.test(sld)) return false;

  // 1. Official known corporate / career domain mapping (`about.google`, `metacareers.com`, `amazon.jobs`, `datadoghq.com`, etc.)
  const officialDomains = OFFICIAL_COMPANY_CAREER_DOMAINS[tok];
  if (officialDomains && officialDomains.some((d) => registrableDomain === d || hostname === d || hostname.endsWith(`.${d}`))) {
    // Guard multi-tenant sub-brands like `github.com` / `linkedin.com` under `microsoft` so `linkedin.com` stays blocked above
    return true;
  }

  // 2. Brand TLD (`about.google` -> tld `google`, `jobs.apple` -> tld `apple`, `careers.microsoft` -> tld `microsoft`)
  if (
    tok.length >= 3 &&
    tld === tok &&
    !['com', 'org', 'net', 'edu', 'gov', 'io', 'ai', 'co', 'app', 'dev', 'so', 'sh', 'gg', 'tech', 'cloud', 'jobs'].includes(tld)
  ) {
    return true;
  }

  // 3. Exact registrable joined token (`flyio` <-> `fly.io`, `linearapp` <-> `linear.app`) or exact SLD on a vetted corporate/ccTLD
  if (joinedRegistrable === tok) return true;
  if (sld === tok && isVettedTld) return true;

  // 4. Verified multi-word hyphenated domain (`palo-alto-networks.com` <-> `paloaltonetworks`, NEVER `st-ripe.com` or `stripe-careers.com`!)
  if (sld.includes('-') && isVettedTld) {
    const parts = sld.split('-').filter(Boolean);
    return isVerifiedMultiWordHyphenJoin(parts, tok, opts?.rawCompany, opts?.segmentedTokens);
  }
  return false;
}

function matchesCompanyCandidateAgainstToken(
  rawCandidate: string,
  tok: string,
  opts: { isAtsSlug?: boolean } = {},
): boolean {
  if (opts.isAtsSlug) {
    return matchesAtsTenantSlugAgainstToken(rawCandidate, tok);
  }
  if (!rawCandidate || !tok || tok.length < 2 || tok.length > 128) return false;
  const bounded = rawCandidate.length > 256 ? rawCandidate.slice(0, 256) : rawCandidate;
  // Reject zero-width / bidi / non-breaking-space format chars used to spoof company names (`Stripe\u200b`, `STRIPE\u00a0INC`)
  if (/[\u0000-\u001f\u007f-\u00a0\u00ad\u034f\u061c\u17b4\u17b5\u180b-\u180f\u2000-\u200f\u2028-\u202f\u205f-\u206f\ufeff]/.test(bounded)) {
    return false;
  }
  const normalizedAbbrev = normalizeDottedCorporateAbbreviations(bounded);
  // Tokenize ALL Unicode letter/number words (`\p{L}\p{N}`) so Cyrillic/Greek/CJK homoglyphs (`Не Stripe`, `Stripe 偽物`, `Stripe Fаke`) are NEVER dropped!
  const rawWords: string[] = normalizedAbbrev.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
  if (rawWords.length === 0) return false;

  const words: string[] = [];
  for (let i = 0; i < rawWords.length; i++) {
    let w = rawWords[i]!;
    if (i > 0 && !/^[a-z0-9]+$/.test(w)) {
      // Allow Latin diacritics on subsidiary country/city qualifiers (`México`, `Zürich`, `São Paulo`) while rejecting non-Latin scripts (Cyrillic/Greek/CJK)
      if (/^[\p{Script=Latin}0-9]+$/u.test(w)) {
        w = w.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      }
    }
    if (!/^[a-z0-9]+$/.test(w)) return false;
    if (COMPANY_NEGATION_WORDS.has(w) && w !== tok) return false;
    words.push(w);
  }

  // Support explicit `"<Legal Parent> dba <Brand>"` (`"Maplebear Inc. dba Instacart"`)
  const dbaIdx = words.indexOf('dba');
  if (dbaIdx > 0 && dbaIdx + 1 < words.length) {
    const afterDba = words.slice(dbaIdx + 1);
    if (afterDba[0] === tok && afterDba.slice(1).every((w) => COMPANY_SUBSIDIARY_AND_GEO_QUALIFIERS.has(w))) {
      return true;
    }
  }

  if (words.length === 1) {
    const only = words[0]!;
    if (only === tok) return true;
    if (tok.length >= 3 && only.startsWith(tok)) {
      const rem = only.slice(tok.length);
      if (COMPANY_SUBSIDIARY_AND_GEO_QUALIFIERS.has(rem)) return true;
    }
    return false;
  }

  const clean = words.join('');
  if (!clean.startsWith(tok) && CONCAT_NEGATION_PREFIX_RE.test(clean)) return false;

  // 1. Exact leading brand token followed by `1..6` vetted legal, subsidiary, division, or geographic qualifiers
  // (`"Stripe Payments UK"`, `"Notion Labs, Inc."`, `"Anthropic, PBC"`, `"OpenAI, L.L.C."`, `"F5, Inc."`)
  if (
    words[0] === tok &&
    words.length <= 7 &&
    words.slice(1).every((w) => COMPANY_SUBSIDIARY_AND_GEO_QUALIFIERS.has(w))
  ) {
    return true;
  }

  // 2. Space-separated multi-word company name (`"Open AI"` <-> `"openai"`, `"Palo Alto Networks"` <-> `"paloaltonetworks"`):
  // ONLY when separated by spaces/commas (NOT `.`, `-`, `/`, `_` in the brand prefix so `S.T.R.I.P.E`, `St-Ripe`, `s/t/r/i/p/e`, `s-t-r-i-p-e` are 100% rejected!)
  if (tok.length >= 4 && !/[.\-/_]/.test(normalizedAbbrev.slice(0, Math.min(normalizedAbbrev.length, tok.length + 4)))) {
    let acc = '';
    for (let k = 0; k < Math.min(words.length, 4); k++) {
      const part = words[k]!;
      if (k === 0 ? part.length < 2 : part.length < 2) break;
      if (k === 0 && part.length < 3 && words.length === 2 && words[1]!.length < 3) break;
      acc += part;
      if (acc === tok && k >= 1) {
        if (words.slice(k + 1).every((w) => COMPANY_SUBSIDIARY_AND_GEO_QUALIFIERS.has(w))) {
          return true;
        }
      }
      if (acc.length >= tok.length) break;
    }
  }

  return false;
}

export function matchesAllowedCompanyOrDomain(
  job: StructuredJobRecord,
  allowedTokens: Set<string>,
  allowedBoardPrefixes: string[],
): boolean {
  const rawUrl = typeof job.url === 'string' ? (job.url.length > 2048 ? job.url.slice(0, 2048) : job.url) : '';
  const urlLower = rawUrl.toLowerCase();
  const hasExplicitCompany =
    typeof job.company === 'string' && job.company.trim() !== '' && job.company.trim().toLowerCase() !== 'unknown';

  // Expand compound tokens (`"Notion Labs, Inc."` -> `"notion"`, `"careers.stripe.com"` -> `"stripe"` + domain `"stripe.com"`) while bounding checks
  const expandedTokens = new Set<string>();
  const segmentedTokens = new Set<string>();
  const explicitAllowedRegistrableDomains = new Set<string>();

  const registerAllowedDomainCandidate = (rawStr: string) => {
    const trimmed = rawStr.trim().toLowerCase().replace(/\/+$/, '');
    if (!trimmed) return;
    let hostCand = '';
    if (/^https?:\/\//.test(trimmed)) {
      try {
        const u = new URL(trimmed);
        const h = u.hostname.toLowerCase().replace(/\.+$/, '');
        if (h && !isKnownMultiTenantAtsHost(h) && (u.pathname === '' || u.pathname === '/' || /^\/(?:careers|jobs|about|company|en|intl)\b/i.test(u.pathname))) {
          hostCand = h;
        }
      } catch {
        hostCand = '';
      }
    } else if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(trimmed) && !/\.(?:l\.l\.c|p\.b\.c|p\.l\.c|i\.n\.c|l\.t\.d|u\.k|u\.s\.a|k\.k)\.?$/.test(trimmed)) {
      hostCand = trimmed.replace(/\.+$/, '');
    }
    if (hostCand && !isKnownMultiTenantAtsHost(hostCand) && !UNVERIFIED_JOB_AGGREGATOR_DOMAINS.some((d) => hostCand === d || hostCand.endsWith(`.${d}`))) {
      const info = extractRegistrableBrandInfo(hostCand);
      if (info) {
        explicitAllowedRegistrableDomains.add(info.registrableDomain);
        // If a brand TLD like `about.google` was passed, also allow `*.google` and mapped official domains (`google.com`)
        if (info.tld.length >= 3 && OFFICIAL_COMPANY_CAREER_DOMAINS[info.tld]) {
          for (const d of OFFICIAL_COMPANY_CAREER_DOMAINS[info.tld]!) {
            if (!UNVERIFIED_JOB_AGGREGATOR_DOMAINS.includes(d)) explicitAllowedRegistrableDomains.add(d);
          }
        }
      }
    }
  };

  for (const rawTok of allowedTokens) {
    if (!rawTok || expandedTokens.size >= 128) continue;
    const bounded = rawTok.length > 256 ? rawTok.slice(0, 256).trim() : rawTok.trim();
    if (!bounded) continue;
    registerAllowedDomainCandidate(bounded);
    const words = normalizeDottedCorporateAbbreviations(bounded).toLowerCase().match(/[a-z0-9]+/g) ?? [];
    if (words.length >= 2 && words.length <= 4) {
      segmentedTokens.add(words.join('-'));
    }
    const cleanLower = bounded.toLowerCase();
    if (/^[a-z0-9_-]{2,128}$/.test(cleanLower)) {
      expandedTokens.add(cleanLower.replace(/[-_]+/g, ''));
      if (cleanLower.includes('-') || cleanLower.includes('_')) {
        segmentedTokens.add(cleanLower.replace(/_/g, '-'));
      }
    }
    for (const exp of expandCompanyFilterTokens(bounded)) {
      expandedTokens.add(exp);
    }
  }

  for (const p of allowedBoardPrefixes) {
    if (p) registerAllowedDomainCandidate(p);
  }

  // 1. Boards explicitly discovered from the caller's verified `domains: [...]` careers page
  if (
    allowedBoardPrefixes.some((rawP) => {
      if (!rawP) return false;
      const p = rawP.trim().toLowerCase().replace(/\/+$/, '');
      return Boolean(p && (urlLower === p || urlLower.startsWith(`${p}/`) || urlLower.startsWith(`${p}?`)));
    })
  ) {
    if (hasExplicitCompany && hasExplicitSpoofOrNegationInCompany(job.company, expandedTokens)) {
      return false;
    }
    return true;
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return false;
  }
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    return false;
  }
  const host = parsedUrl.hostname.toLowerCase().replace(/\.+$/, '');
  if (!host) return false;

  // Reject unverified open job aggregators and user-generated shared hosting subdomains
  if (UNVERIFIED_JOB_AGGREGATOR_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`))) {
    return false;
  }

  const isMultiTenantAts = isKnownMultiTenantAtsHost(host);
  const inferredSlug = isMultiTenantAts ? inferCompanyFromAtsUrl(rawUrl) : '';
  const curatedFeedHost = job.source ? CURATED_PUBLIC_FEED_HOST_BY_SOURCE[job.source] : undefined;
  const isCuratedPublicFeed =
    Boolean(curatedFeedHost && (host === curatedFeedHost || host.endsWith(`.${curatedFeedHost}`)));

  // Reject any explicit negation/homoglyph/dotted-letter spoof in `job.company` upfront across ALL host classes
  if (hasExplicitCompany && hasExplicitSpoofOrNegationInCompany(job.company, expandedTokens)) {
    return false;
  }

  // 2. Explicit first-party registrable domain match (`careers.stripe.com` for `stripe.com`, `jobs.netflix.com` for `netflix.com`, `about.google`)
  if (!isMultiTenantAts && !isCuratedPublicFeed && explicitAllowedRegistrableDomains.size > 0) {
    const hostInfo = extractRegistrableBrandInfo(host);
    if (
      hostInfo &&
      (explicitAllowedRegistrableDomains.has(hostInfo.registrableDomain) ||
        [...explicitAllowedRegistrableDomains].some((d) => host === d || host.endsWith(`.${d}`)))
    ) {
      // First-party company domain verified: accept WITHOUT requiring `job.company` to repeat the company name!
      return true;
    }
  }

  let checked = 0;
  for (const tok of expandedTokens) {
    if (!tok || tok.length < 2) continue;
    if (++checked > 128) break;

    if (isMultiTenantAts) {
      if (!matchesAtsTenantSlugAgainstToken(inferredSlug, tok, { host, jobCompany: job.company, segmentedTokens })) {
        continue;
      }
      if (hasExplicitCompany) {
        const cleanComp = job.company.trim().toLowerCase();
        // When `job.company` was simply populated from `inferredSlug` (`stripeinc`, `stripehq`, `doordashusa`), accept directly;
        // otherwise `job.company` must corroborate `tok` (blocking `Acme` or `Stripe Careers` on unverified ATS boards!).
        if (cleanComp !== inferredSlug.toLowerCase() && !matchesCompanyCandidateAgainstToken(job.company, tok)) {
          continue;
        }
      }
      return true;
    }

    if (isCuratedPublicFeed) {
      if (hasExplicitCompany && matchesCompanyCandidateAgainstToken(job.company, tok)) {
        return true;
      }
      continue;
    }

    // 3. First-party company career site (`stripe.com/jobs`, `careers.stripe.com`, `jobs.netflix.com`, `about.google`, `notion.so/careers`, `amazon.jobs`):
    // Once the URL's registrable domain matches `tok` (blocking third-party `evil.com`, `stripe.evil.com`, `stripecareers.com`, `stripe-careers.com`),
    // accept WITHOUT dropping postings whose `job.company` is a department (`"Engineering"`), `"Stripe Careers"`, or omitted!
    if (!matchesFirstPartyDomainAgainstToken(host, tok, { rawCompany: job.company, segmentedTokens })) continue;
    return true;
  }
  return false;
}

export const MAX_JOBS_CONCURRENT_SCRAPES = 4;
export const MAX_JOBS_TOTAL_SCRAPES = 40;
export const JOBS_CACHE_TTL_MS = 5 * 60 * 1_000; // 5-minute TTL for ATS boards & job enrichment
export const MAX_JOBS_CACHE_ENTRIES = 128;
export const JOBS_PER_ITEM_TIMEOUT_MS = 12_000;

interface JobsScrapeResponse {
  status: number;
  body: Record<string, unknown>;
}

interface JobsCachePartition {
  lru: Map<string, { expiresAt: number; value: JobsScrapeResponse }>;
  inFlight: Map<string, Promise<JobsScrapeResponse>>;
}

const SHARED_JOBS_CACHE_PARTITION: JobsCachePartition = {
  lru: new Map(),
  inFlight: new Map(),
};
const TEST_SCOPED_JOBS_PARTITIONS = new WeakMap<object, JobsCachePartition>();

export function resetJobsCacheForTests(): void {
  SHARED_JOBS_CACHE_PARTITION.lru.clear();
  SHARED_JOBS_CACHE_PARTITION.inFlight.clear();
}

function resolveJobsCachePartition(
  env: (OptionalStorageBindings & Record<string, unknown>) | undefined,
  rawExecuteScrape: unknown,
): JobsCachePartition {
  if (
    env &&
    ('AGENT_HUB' in env ||
      'CALLER_TOKEN' in env ||
      'META' in env ||
      'ARTIFACTS' in env ||
      'SERPER_API_KEY' in env ||
      'SEARXNG_URL' in env ||
      'SAFE_PUBLIC_FETCH' in env ||
      env.JOBS_SHARED_CACHE === true)
  ) {
    return SHARED_JOBS_CACHE_PARTITION;
  }
  const keyObj =
    env && typeof env === 'object' && Object.keys(env).length > 0
      ? (env as object)
      : (rawExecuteScrape as object);
  if (!keyObj || (typeof keyObj !== 'object' && typeof keyObj !== 'function')) {
    return SHARED_JOBS_CACHE_PARTITION;
  }
  let part = TEST_SCOPED_JOBS_PARTITIONS.get(keyObj);
  if (!part) {
    part = { lru: new Map(), inFlight: new Map() };
    TEST_SCOPED_JOBS_PARTITIONS.set(keyObj, part);
  }
  return part;
}

function cloneJobsScrapeResponse(res: JobsScrapeResponse): JobsScrapeResponse {
  const body = res.body ?? {};
  return {
    status: res.status,
    body: {
      ...body,
      ...(Array.isArray(body.jobs)
        ? {
            jobs: (body.jobs as StructuredJobRecord[]).map((j) => ({
              ...j,
              locations: Array.isArray(j.locations) ? [...j.locations] : [],
              ...(j.pay ? { pay: { ...j.pay } } : {}),
            })),
          }
        : {}),
      ...(Array.isArray(body.links) ? { links: [...(body.links as string[])] } : {}),
    },
  };
}

function buildJobsScrapeCacheKey(args: Record<string, unknown>): string | null {
  const rawUrl = typeof args.url === 'string' ? args.url.trim() : '';
  if (!rawUrl.startsWith('https://')) return null;
  let canonicalUrl = rawUrl;
  try {
    const u = new URL(rawUrl);
    u.hash = '';
    const host = u.hostname.toLowerCase();
    const parts = u.pathname.split('/').filter(Boolean);
    if (host === 'jobs.ashbyhq.com' && parts.length === 1 && !u.searchParams.has('offset')) {
      canonicalUrl = `https://jobs.ashbyhq.com/${decodeURIComponent(parts[0]!).toLowerCase()}`;
    } else if (
      (host === 'boards.greenhouse.io' || host === 'job-boards.greenhouse.io') &&
      parts.length === 1 &&
      !u.searchParams.has('offset')
    ) {
      canonicalUrl = `https://job-boards.greenhouse.io/${parts[0]!.toLowerCase()}`;
    } else if (host === 'jobs.lever.co' && parts.length === 1 && !u.searchParams.has('offset')) {
      canonicalUrl = `https://jobs.lever.co/${parts[0]!.toLowerCase()}`;
    } else if (host === 'ats.rippling.com' && parts.length >= 1) {
      const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2 ? 1 : 0;
      const org = parts[idx];
      const rest = parts.slice(idx + 1);
      if (org && (rest.length === 0 || (rest.length === 1 && rest[0] === 'jobs'))) {
        canonicalUrl = `https://ats.rippling.com/${org.toLowerCase()}/jobs`;
      } else {
        canonicalUrl = u.toString();
      }
    } else {
      canonicalUrl = u.toString();
    }
  } catch {
    return null;
  }
  const fmts = Array.isArray(args.formats) ? [...(args.formats as string[])].sort().join(',') : 'markdown';
  const siteKey = typeof args.site === 'string' ? args.site.trim().toLowerCase() : '';
  const targetKey = typeof args.target === 'string' ? args.target.trim().toLowerCase() : '';
  return `${canonicalUrl}|${fmts}|${targetKey}|${siteKey}`;
}

function readJobsScrapeCache(partition: JobsCachePartition, key: string, now = Date.now()): JobsScrapeResponse | null {
  const hit = partition.lru.get(key);
  if (!hit) return null;
  if (hit.expiresAt <= now) {
    partition.lru.delete(key);
    return null;
  }
  partition.lru.delete(key);
  partition.lru.set(key, hit);
  return cloneJobsScrapeResponse(hit.value);
}

function writeJobsScrapeCache(partition: JobsCachePartition, key: string, value: JobsScrapeResponse, now = Date.now()): void {
  if (value.status !== 200 || value.body?.ok !== true) return;
  for (const [k, v] of partition.lru.entries()) {
    if (v.expiresAt <= now) partition.lru.delete(k);
  }
  partition.lru.delete(key);
  partition.lru.set(key, { expiresAt: now + JOBS_CACHE_TTL_MS, value: cloneJobsScrapeResponse(value) });
  while (partition.lru.size > MAX_JOBS_CACHE_ENTRIES) {
    const oldest = partition.lru.keys().next().value;
    if (oldest === undefined) break;
    partition.lru.delete(oldest);
  }
}

function withJobsItemTimeout(promise: Promise<JobsScrapeResponse>, timeoutMs = JOBS_PER_ITEM_TIMEOUT_MS): Promise<JobsScrapeResponse> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<JobsScrapeResponse>((resolve) => {
    timer = setTimeout(() => {
      resolve({ status: 504, body: { ok: false, error: 'jobs_item_timeout', message: 'ATS enrichment timed out' } });
    }, timeoutMs);
  });
  return Promise.race([
    promise.catch(() => ({ status: 502, body: { ok: false, error: 'jobs_item_failed' } })),
    timeoutPromise,
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

function isClosedSchemeDowngradeResult(urlStr: string, res: JobsScrapeResponse | null | undefined): boolean {
  if (!res) return false;
  const body = res.body ?? {};
  const blockedObj = body.blocked as Record<string, unknown> | undefined;
  const prob = typeof body.problem === 'string' ? body.problem : typeof body.message === 'string' ? body.message : '';
  const isDowngrade =
    blockedObj?.reason === 'scheme_downgrade' ||
    body.blockedReason === 'scheme_downgrade' ||
    body.outcome === 'scheme_downgrade' ||
    /scheme_downgrade|https-to-http\s+redirect\s+downgrade/i.test(prob);
  if (!isDowngrade) return false;
  return /rippling\.com/i.test(urlStr) || Boolean(parseAtsPostingIdentity(urlStr));
}

function normalizeWorkdayPostedAt(rawPostedOn: string | null | undefined, nowMs = Date.now()): string | null {
  if (!rawPostedOn) return null;
  const trimmed = rawPostedOn.trim();
  if (!trimmed) return null;
  if (/^\d{4}-\d{2}-\d{2}/.test(trimmed)) return trimmed;
  if (/^posted\s+today\b/i.test(trimmed)) return new Date(nowMs).toISOString().slice(0, 10);
  if (/^posted\s+yesterday\b/i.test(trimmed)) return new Date(nowMs - 86_400_000).toISOString().slice(0, 10);
  const daysMatch = /^posted\s+(\d+)(\+)?\s+days?\s+ago\b/i.exec(trimmed);
  if (daysMatch) {
    const baseDays = parseInt(daysMatch[1]!, 10);
    if (Number.isFinite(baseDays) && baseDays >= 0) {
      const effectiveDays = daysMatch[2] ? baseDays + 5 : baseDays;
      return new Date(nowMs - effectiveDays * 86_400_000).toISOString().slice(0, 10);
    }
  }
  return trimmed;
}

function classifyFullBoardKey(urlStr: string): { key: string; platform: string; slug: string; isBoard: boolean; boardUrl: string } | null {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return null;
    const host = u.hostname.toLowerCase();
    const parts = u.pathname.split('/').filter(Boolean);
    if (host === 'jobs.ashbyhq.com' && parts.length >= 1) {
      const org = decodeURIComponent(parts[0]!);
      if (!isValidAtsSlug(org)) return null;
      const isBoard = parts.length === 1 || (parts.length === 2 && parts[1]!.toLowerCase() === 'jobs');
      return {
        key: `ashby:${org.toLowerCase()}`,
        platform: 'ashby',
        slug: org,
        isBoard,
        boardUrl: `https://jobs.ashbyhq.com/${encodeURIComponent(org)}`,
      };
    }
    const isGhUs = host === 'boards.greenhouse.io' || host === 'job-boards.greenhouse.io';
    const isGhEu = host === 'eu-boards.greenhouse.io' || host === 'job-boards.eu.greenhouse.io';
    if ((isGhUs || isGhEu) && parts.length >= 1) {
      const org = parts[0]!;
      if (!isValidAtsSlug(org)) return null;
      const canonicalHost = isGhEu ? 'job-boards.eu.greenhouse.io' : 'job-boards.greenhouse.io';
      return {
        key: `greenhouse:${org.toLowerCase()}`,
        platform: 'greenhouse',
        slug: org,
        isBoard: parts.length === 1 && !u.searchParams.has('gh_jid'),
        boardUrl: `https://${canonicalHost}/${org}`,
      };
    }
    if ((host === 'jobs.lever.co' || host === 'jobs.eu.lever.co') && parts.length >= 1) {
      const org = parts[0]!;
      if (!isValidAtsSlug(org)) return null;
      return {
        key: `lever:${org.toLowerCase()}`,
        platform: 'lever',
        slug: org,
        isBoard: parts.length === 1,
        boardUrl: `https://${host}/${org}`,
      };
    }
    if (host === 'ats.rippling.com' && parts.length >= 1) {
      const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2 ? 1 : 0;
      const org = parts[idx];
      const rest = parts.slice(idx + 1);
      if (org && isValidAtsSlug(org)) {
        const isBoard = rest.length === 0 || (rest.length === 1 && rest[0] === 'jobs');
        return {
          key: `rippling:${org.toLowerCase()}`,
          platform: 'rippling',
          slug: org,
          isBoard,
          boardUrl: `https://ats.rippling.com/${org}/jobs`,
        };
      }
    }
    if (host === 'apply.workable.com' && parts.length >= 1 && isValidAtsSlug(parts[0]!)) {
      return {
        key: `workable:${parts[0]!.toLowerCase()}`,
        platform: 'workable',
        slug: parts[0]!,
        isBoard: parts.length === 1,
        boardUrl: `https://apply.workable.com/${parts[0]!}/`,
      };
    }
    if (host === 'jobs.gem.com' && parts.length >= 1 && isValidAtsSlug(parts[0]!)) {
      return {
        key: `gem:${parts[0]!.toLowerCase()}`,
        platform: 'gem',
        slug: parts[0]!,
        isBoard: parts.length === 1,
        boardUrl: `https://jobs.gem.com/${parts[0]!}`,
      };
    }
    const wdMatch = /^([a-z0-9-]+)\.wd\d+\.myworkday(?:jobs|site)\.com$/i.exec(host);
    if (wdMatch && parts.length >= 1) {
      let tenant = wdMatch[1]!.toLowerCase();
      let site = '';
      let rest: string[] = [];
      if (parts[0]?.toLowerCase() === 'wday' && parts[1]?.toLowerCase() === 'cxs' && parts.length >= 4) {
        tenant = (parts[2] || tenant).toLowerCase();
        site = parts[3]!;
        rest = parts.slice(4);
      } else {
        const idx = /^[a-z]{2}(?:-[A-Za-z]{2,4})?$/.test(parts[0]!) && parts.length >= 2 ? 1 : 0;
        site = parts[idx] ?? '';
        rest = parts.slice(idx + 1);
      }
      if (site && site.toLowerCase() !== 'wday' && /^[A-Za-z0-9_.-]{1,120}$/.test(site)) {
        return {
          key: `workday:${tenant}:${site.toLowerCase()}`,
          platform: 'workday',
          slug: `${tenant}/${site}`,
          isBoard: rest.length === 0,
          boardUrl: `https://${host}/${site}`,
        };
      }
    }
  } catch {
    return null;
  }
  return null;
}

function isSmartRecruitersBoardUrl(urlStr: string): { org: string; boardUrl: string } | null {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:' || u.hostname.toLowerCase() !== 'jobs.smartrecruiters.com') return null;
    const parts = u.pathname.split('/').filter(Boolean);
    if (parts.length === 1 && isValidAtsSlug(parts[0]!)) {
      return { org: decodeURIComponent(parts[0]!), boardUrl: `https://jobs.smartrecruiters.com/${parts[0]!}` };
    }
  } catch {
    return null;
  }
  return null;
}

function humanizeSmartRecruitersSlugTitle(jobSeg: string): string {
  const withoutNumericPrefix = jobSeg.replace(/^\d{6,}-/, '');
  if (!withoutNumericPrefix || /^\d+$/.test(withoutNumericPrefix)) return '';
  return withoutNumericPrefix
    .split(/[-_]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
    .trim();
}

/**
 * Parses public `https://jobs.smartrecruiters.com/{Company}` HTML/Markdown board listings (strictly respecting `robots.txt`
 * and NEVER calling `api.smartrecruiters.com`, which disallows bots in `robots.txt`).
 */
export function parseSmartRecruitersBoardScrape(origUrl: string, body: Record<string, unknown>): StructuredJobRecord[] {
  const boardInfo = isSmartRecruitersBoardUrl(origUrl);
  if (!boardInfo) return [];
  const company = boardInfo.org;
  const orgLower = company.toLowerCase();
  const md = typeof body.markdown === 'string' ? body.markdown : '';
  const rawHtml = typeof body.rawHtml === 'string' ? body.rawHtml : typeof body.html === 'string' ? body.html : '';
  const links = Array.isArray(body.links) ? (body.links as string[]) : [];

  const byUrl = new Map<string, StructuredJobRecord>();
  const isPostingPath = (candidateUrl: string): { cleanUrl: string; seg: string } | null => {
    try {
      const u = new URL(candidateUrl, origUrl);
      if (u.protocol !== 'https:' || u.hostname.toLowerCase() !== 'jobs.smartrecruiters.com') return null;
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length < 2 || parts[0]!.toLowerCase() !== orgLower) return null;
      const seg = decodeURIComponent(parts[1]!);
      if (!seg || seg.length < 4 || /^(?:api|reset|login|signin|privacy|legal|terms|cookies|search|jobs)$/i.test(seg)) {
        return null;
      }
      u.hash = '';
      u.search = '';
      return { cleanUrl: `https://jobs.smartrecruiters.com/${parts[0]!}/${parts[1]!}`, seg };
    } catch {
      return null;
    }
  };

  // 1. Parse Markdown `[Title](https://jobs.smartrecruiters.com/<Company>/<JobId>)` links + surrounding location/pay context
  const mdLinkRe = /\[([^\[\]\n]{3,180})\]\((https:\/\/jobs\.smartrecruiters\.com\/[^)\s]+)\)([^\n]{0,200})(?:\n+([^\n#\[]{0,160}))?/gi;
  let m: RegExpExecArray | null;
  while ((m = mdLinkRe.exec(md)) !== null && byUrl.size < 500) {
    const parsedLink = isPostingPath(m[2]!);
    if (!parsedLink || byUrl.has(parsedLink.cleanUrl.toLowerCase())) continue;
    const rawTitle = m[1]!.replace(/\*+/g, '').trim();
    if (!rawTitle || /^(?:apply|read more|learn more|view job)$/i.test(rawTitle)) continue;
    const tailCtx = `${m[3] ?? ''} ${m[4] ?? ''}`.replace(/^[ \t·|–—-]+/, '').trim();
    const locLine = (m[3] ?? '').replace(/^[ \t·|–—-]+/, '').trim() || (m[4] ?? '').trim();
    const cleanLoc = locLine && locLine.length <= 96 && !/\[|\]|\bhttp/i.test(locLine) ? locLine : '';
    const wp = inferWorkplaceType(`${cleanLoc} ${rawTitle} ${tailCtx}`);
    const pay = parsePayFromText(tailCtx);
    byUrl.set(parsedLink.cleanUrl.toLowerCase(), {
      title: rawTitle,
      company,
      url: parsedLink.cleanUrl,
      applyUrl: parsedLink.cleanUrl,
      workplaceType: wp,
      locations: cleanLoc ? [cleanLoc] : wp === 'remote' ? ['Remote'] : [],
      pay,
      postedAt: null,
      source: 'smartrecruiters',
      ...(tailCtx ? { snippet: tailCtx.slice(0, 220) } : {}),
    });
  }

  // 2. Parse raw HTML anchors if present
  if (rawHtml) {
    const htmlAnchorRe = /<a\b[^>]{0,400}\bhref=["'](https?:\/\/jobs\.smartrecruiters\.com\/[^"'#?\s]+|\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]{6,})["'][^>]*>([\s\S]{1,600}?)<\/a>/gi;
    let hm: RegExpExecArray | null;
    while ((hm = htmlAnchorRe.exec(rawHtml)) !== null && byUrl.size < 500) {
      const parsedLink = isPostingPath(hm[1]!);
      if (!parsedLink || byUrl.has(parsedLink.cleanUrl.toLowerCase())) continue;
      const anchorText = stripTagsPlain(hm[2]!);
      const title = anchorText && !/^(?:apply|view|details)$/i.test(anchorText) ? anchorText : humanizeSmartRecruitersSlugTitle(parsedLink.seg);
      if (!title) continue;
      const afterSlice = stripTagsPlain(rawHtml.slice(hm.index + hm[0].length, hm.index + hm[0].length + 260));
      const wp = inferWorkplaceType(`${afterSlice} ${title}`);
      byUrl.set(parsedLink.cleanUrl.toLowerCase(), {
        title,
        company,
        url: parsedLink.cleanUrl,
        applyUrl: parsedLink.cleanUrl,
        workplaceType: wp,
        locations: wp === 'remote' ? ['Remote'] : [],
        pay: parsePayFromText(afterSlice),
        postedAt: null,
        source: 'smartrecruiters',
      });
    }
  }

  // 3. Fallback to `links[]` array using humanized URL slug titles
  for (const lnk of links) {
    if (byUrl.size >= 500) break;
    const parsedLink = isPostingPath(String(lnk));
    if (!parsedLink || byUrl.has(parsedLink.cleanUrl.toLowerCase())) continue;
    const title = humanizeSmartRecruitersSlugTitle(parsedLink.seg);
    if (!title) continue;
    const wp = inferWorkplaceType(title);
    byUrl.set(parsedLink.cleanUrl.toLowerCase(), {
      title,
      company,
      url: parsedLink.cleanUrl,
      applyUrl: parsedLink.cleanUrl,
      workplaceType: wp,
      locations: wp === 'remote' ? ['Remote'] : [],
      pay: null,
      postedAt: null,
      source: 'smartrecruiters',
    });
  }

  return [...byUrl.values()];
}

/**
 * `Section 4`: One-call `jobs` sweep across Greenhouse, Ashby, Lever, Workday, Workable, Gem, Rippling, SmartRecruiters,
 * iCIMS, robots-allowed public feeds (We Work Remotely, Himalayas, Working Nomads), company-domain -> ATS auto-discovery (`domains`),
 * and batch saved-posting verification (`verify` / `mode: 'verify'`).
 */
export async function executeJobsCall(params: {
  payload: JobsToolPayload;
  env: OptionalStorageBindings & Record<string, unknown>;
  executeSearch: (args: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  executeScrape: (args: Record<string, unknown>) => Promise<{ status: number; body: Record<string, unknown> }>;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  const activeTracer = getActiveRequestTracer(params.tracer);
  const runJobs = async (): Promise<{ status: number; body: Record<string, unknown> }> => {
  const { payload } = params;
  const rawExecuteSearch = params.executeSearch;
  const executeSearch = (args: Record<string, unknown>) =>
    activeTracer ? activeTracer.run(() => rawExecuteSearch(args)) : rawExecuteSearch(args);
  const rawExecuteScrape = params.executeScrape;
  const cachePartition = resolveJobsCachePartition(params.env, rawExecuteScrape);

  // Enforce hard `<= 4` concurrent scrapes and `<= 40` total scrapes per `executeJobsCall` across discovery, verify & boards,
  // backed by a 5-minute (`300_000 ms`) 128-entry LRU cache + `inFlight` singleflight coalescer + 12s per-item timeout guard.
  let activeScrapes = 0;
  let totalScrapesUsed = 0;
  let budgetExhausted = false;
  const scrapeWaitQueue: Array<() => void> = [];
  const executeScrape = async (
    args: Record<string, unknown>,
  ): Promise<{ status: number; body: Record<string, unknown> }> => {
    const cacheKey = args.noCache === true ? null : buildJobsScrapeCacheKey(args);
    if (cacheKey) {
      const cached = readJobsScrapeCache(cachePartition, cacheKey);
      if (cached) return cached;
      const existingFlight = cachePartition.inFlight.get(cacheKey);
      if (existingFlight) {
        const sharedRes = await withJobsItemTimeout(existingFlight);
        return cloneJobsScrapeResponse(sharedRes);
      }
    }

    while (activeScrapes >= MAX_JOBS_CONCURRENT_SCRAPES) {
      if (totalScrapesUsed >= MAX_JOBS_TOTAL_SCRAPES) {
        budgetExhausted = true;
        return { status: 429, body: { ok: false, error: 'jobs_scrape_budget_exceeded' } };
      }
      await new Promise<void>((resolve) => scrapeWaitQueue.push(resolve));
      if (cacheKey) {
        const cachedAfterWait = readJobsScrapeCache(cachePartition, cacheKey);
        if (cachedAfterWait) return cachedAfterWait;
      }
    }
    if (totalScrapesUsed >= MAX_JOBS_TOTAL_SCRAPES) {
      budgetExhausted = true;
      while (scrapeWaitQueue.length > 0) {
        scrapeWaitQueue.shift()?.();
      }
      return { status: 429, body: { ok: false, error: 'jobs_scrape_budget_exceeded' } };
    }
    activeScrapes++;
    totalScrapesUsed++;
    const runSingle = (): Promise<JobsScrapeResponse> =>
      withJobsItemTimeout(
        Promise.resolve().then(() => (activeTracer ? activeTracer.run(() => rawExecuteScrape(args)) : rawExecuteScrape(args))),
      );
    const flightPromise = runSingle();
    if (cacheKey) {
      cachePartition.inFlight.set(cacheKey, flightPromise);
    }
    try {
      const out = await flightPromise;
      if (cacheKey && out.status === 200 && out.body?.ok === true) {
        writeJobsScrapeCache(cachePartition, cacheKey, out);
      }
      return cacheKey ? cloneJobsScrapeResponse(out) : out;
    } finally {
      if (cacheKey && cachePartition.inFlight.get(cacheKey) === flightPromise) {
        cachePartition.inFlight.delete(cacheKey);
      }
      activeScrapes--;
      if (totalScrapesUsed >= MAX_JOBS_TOTAL_SCRAPES) {
        while (scrapeWaitQueue.length > 0) {
          scrapeWaitQueue.shift()?.();
        }
      } else {
        scrapeWaitQueue.shift()?.();
      }
    }
  };

  // Batch `verify` mode (`verify: [...]` or `mode: 'verify', urls: [...]`)
  const rawVerifyArray = Array.isArray(payload.verify)
    ? payload.verify
    : payload.mode === 'verify' && Array.isArray(payload.urls)
      ? payload.urls
      : null;
  if (rawVerifyArray !== null || payload.mode === 'verify') {
    // Bound verify array BEFORE filtering/trimming so 100k-entry arrays finish in O(1) (`jobs8.mjs` Part E)
    const cleanVerifyUrls = (rawVerifyArray ?? [])
      .slice(0, 100)
      .filter((u): u is string => typeof u === 'string' && u.length <= 2_048 && u.trim().startsWith('https://'))
      .map((u) => u.trim());
    if (cleanVerifyUrls.length === 0) {
      activeTracer?.setAttribute('edgefetch.jobs.mode', 'verify');
      activeTracer?.setAttribute('edgefetch.jobs.boards_discovered', 0);
      activeTracer?.setAttribute('edgefetch.jobs.jobs_returned', 0);
      return {
        status: 400,
        body: {
          ok: false,
          error: 'missing_verify_urls',
          message: 'Provide one or more `https://` posting URLs in `verify` (or `mode: "verify", urls: [...]`).',
        },
      };
    }
    return executeJobsVerifyMode({
      urls: cleanVerifyUrls,
      payload,
      executeScrape,
      ...(activeTracer ? { tracer: activeTracer } : {}),
      didExhaustBudget: () => budgetExhausted,
    });
  }

  if (typeof payload.query === 'string' && payload.query.length > 4_096) {
    return {
      status: 400,
      body: {
        ok: false,
        error: 'invalid_query',
        message: `\`query\` must be at most ${MAX_JOBS_QUERY_CHARS} characters.`,
      },
    };
  }
  const rawQueryTrimmed = typeof payload.query === 'string' ? payload.query.trim() : '';
  if (rawQueryTrimmed.length > MAX_JOBS_QUERY_CHARS) {
    return {
      status: 400,
      body: {
        ok: false,
        error: 'invalid_query',
        message: `\`query\` must be at most ${MAX_JOBS_QUERY_CHARS} characters.`,
      },
    };
  }
  const query = rawQueryTrimmed;
  if (typeof payload.company === 'string' && payload.company.length > 4_096) {
    return {
      status: 400,
      body: {
        ok: false,
        error: 'invalid_company',
        message: '`company` must be at most 128 characters.',
      },
    };
  }
  const rawCompanyTrimmed = typeof payload.company === 'string' ? payload.company.trim() : '';
  if (rawCompanyTrimmed.length > 128) {
    return {
      status: 400,
      body: {
        ok: false,
        error: 'invalid_company',
        message: '`company` must be at most 128 characters.',
      },
    };
  }
  const companyFilter = rawCompanyTrimmed;
  const domainsInput = Array.isArray(payload.domains)
    ? payload.domains
        .slice(0, 25)
        .filter((d): d is string => typeof d === 'string' && d.length <= 256 && d.trim().length > 0)
        .map((d) => d.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase())
        .filter((d) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d))
        .slice(0, 10)
    : [];

  if (!query && !companyFilter && domainsInput.length === 0) {
    activeTracer?.setAttribute('edgefetch.jobs.mode', 'search');
    activeTracer?.setAttribute('edgefetch.jobs.boards_discovered', 0);
    activeTracer?.setAttribute('edgefetch.jobs.jobs_returned', 0);
    return {
      status: 400,
      body: { ok: false, error: 'missing_query', message: 'Provide at least `query`, `company`, or `domains`.' },
    };
  }

  const rawLocationsFilter = Array.isArray(payload.locations)
    ? payload.locations
        .slice(0, 32)
        .filter((x): x is string => typeof x === 'string')
        .map((s) => (s.length > 160 ? s.slice(0, 160) : s).trim().toLowerCase())
        .filter((s) => s.length > 0)
    : [];
  const geoLocationsFilter = rawLocationsFilter.filter((s) => !REMOTE_LOCATION_TOKENS.has(s));
  const hasRemoteInLocations = rawLocationsFilter.some((s) => REMOTE_LOCATION_TOKENS.has(s));
  const rawWantRemote = payload.remote === true ? true : payload.remote === false ? false : undefined;
  const wantRemote = rawWantRemote !== undefined ? rawWantRemote : hasRemoteInLocations ? true : undefined;

  const minBase = typeof payload.minBase === 'number' && Number.isFinite(payload.minBase) && payload.minBase > 0 ? payload.minBase : undefined;
  const minBaseMode: 'floor' | 'ceiling' | 'overlap' =
    payload.minBaseMode === 'ceiling' ? 'ceiling' : payload.minBaseMode === 'overlap' ? 'overlap' : 'floor';
  const strictPay = payload.strictPay === true;
  const postedWithinDays =
    typeof payload.postedWithinDays === 'number' && Number.isFinite(payload.postedWithinDays) && payload.postedWithinDays > 0
      ? payload.postedWithinDays
      : undefined;
  const limit =
    typeof payload.limit === 'number' && Number.isFinite(payload.limit) ? Math.min(50, Math.max(1, Math.floor(payload.limit))) : 20;
  const hasCompanyOrDomainScope = Boolean(companyFilter) || domainsInput.length > 0;
  const includeBuiltIn = hasCompanyOrDomainScope ? payload.includeBuiltIn === true : payload.includeBuiltIn !== false;
  const excludeList = Array.isArray(payload.exclude)
    ? (payload.exclude as Array<Record<string, unknown>>)
        .slice(0, 200)
        .filter((x) => x && typeof x === 'object')
        .map((x) => ({
          company: typeof x.company === 'string' ? (x.company.length > 256 ? x.company.slice(0, 256) : x.company).trim().toLowerCase() : '',
          title: typeof x.title === 'string' ? (x.title.length > 256 ? x.title.slice(0, 256) : x.title).trim().toLowerCase() : '',
          url: typeof x.url === 'string' ? (x.url.length > 2_048 ? x.url.slice(0, 2_048) : x.url).trim().replace(/\/+$/, '').toLowerCase() : '',
        }))
    : [];

  const candidateUrls = new Set<string>();
  const notes: string[] = [];
  const discoveredBoards: DiscoveredAtsBoard[] = [];
  const sourcesUsed = new Set<string>();
  const resolvedAdapterIds = new Set<string>();

  // 1. Company Domain -> ATS Board Auto-Discovery (`domains: ["stripe.com", "nvidia.com", "f5.com"]`)
  if (domainsInput.length > 0) {
    await Promise.all(
      domainsInput.map(async (dom) => {
        const tried: string[] = [];
        const foundForDom: DiscoveredAtsBoard[] = [];
        let domHitBudgetCap = false;
        for (const probePath of ['/careers', '/jobs', '/about/careers']) {
          const probeUrl = `https://${dom}${probePath}`;
          tried.push(probeUrl);
          const res = await executeScrape({
            url: probeUrl,
            renderMode: 'off',
            discoverLlmsTxt: false,
            preferOriginMarkdown: false,
            onlyMainContent: false,
            formats: ['markdown', 'rawHtml', 'links'],
            ...(payload.target ? { target: payload.target } : {}),
            ...(payload.site ? { site: payload.site } : {}),
          }).catch(() => null);
          if (res?.body?.error === 'jobs_scrape_budget_exceeded') {
            domHitBudgetCap = true;
            break;
          }
          if (!res || res.status !== 200 || res.body?.ok !== true) continue;
          const boards = discoverAtsBoardsFromHtml({
            sourceUrl: probeUrl,
            finalUrl: typeof res.body.finalUrl === 'string' ? res.body.finalUrl : probeUrl,
            rawHtml: typeof res.body.rawHtml === 'string' ? res.body.rawHtml : '',
            links: Array.isArray(res.body.links) ? (res.body.links as string[]) : [],
          });
          if (boards.length > 0) {
            for (const b of boards) {
              const entry: DiscoveredAtsBoard = { ...b, domain: dom };
              foundForDom.push(entry);
              discoveredBoards.push(entry);
              candidateUrls.add(entry.boardUrl);
            }
            return;
          }
        }
        // Fallback when company uses a custom SPA careers portal (e.g. Eightfold/AEM):
        // Phase 1 probes fast JSON/HTML boards first; Phase 2 probes speculative Workday CXS ONLY if Phase 1 yielded nothing!
        const baseSlug = dom.split('.')[0]?.toLowerCase() ?? '';
        if (isValidAtsSlug(baseSlug) && !domHitBudgetCap) {
          const upperSlug = baseSlug.toUpperCase();
          const phase1Probes: Array<{ platform: string; slug: string; boardUrl: string }> = [
            { platform: 'greenhouse', slug: baseSlug, boardUrl: `https://boards.greenhouse.io/${baseSlug}` },
            { platform: 'ashby', slug: baseSlug, boardUrl: `https://jobs.ashbyhq.com/${baseSlug}` },
            { platform: 'lever', slug: baseSlug, boardUrl: `https://jobs.lever.co/${baseSlug}` },
            { platform: 'smartrecruiters', slug: baseSlug, boardUrl: `https://jobs.smartrecruiters.com/${baseSlug}` },
          ];
          const phase2WorkdayProbes: Array<{ platform: string; slug: string; boardUrl: string }> = [
            {
              platform: 'workday',
              slug: `${baseSlug}/${upperSlug}ExternalCareerSite`,
              boardUrl: `https://${baseSlug}.wd5.myworkdayjobs.com/${upperSlug}ExternalCareerSite`,
            },
            {
              platform: 'workday',
              slug: `${baseSlug}/${upperSlug}ExternalCareerSite`,
              boardUrl: `https://${baseSlug}.wd1.myworkdayjobs.com/${upperSlug}ExternalCareerSite`,
            },
            {
              platform: 'workday',
              slug: `${baseSlug}/External`,
              boardUrl: `https://${baseSlug}.wd5.myworkdayjobs.com/External`,
            },
            {
              platform: 'workday',
              slug: `${baseSlug}/External`,
              boardUrl: `https://${baseSlug}.wd1.myworkdayjobs.com/External`,
            },
          ];
          const runSlugProbeWave = async (wave: Array<{ platform: string; slug: string; boardUrl: string }>) => {
            for (const sp of wave) tried.push(sp.boardUrl);
            const probeResults = await Promise.all(
              wave.map(async (sp) => {
                const r = await executeScrape({
                  url: sp.boardUrl,
                  renderMode: 'off',
                  discoverLlmsTxt: false,
                  preferOriginMarkdown: false,
                  formats: ['markdown', 'links'],
                  ...(payload.target ? { target: payload.target } : {}),
                  ...(payload.site ? { site: payload.site } : {}),
                }).catch(() => null);
                if (r?.body?.error === 'jobs_scrape_budget_exceeded') {
                  domHitBudgetCap = true;
                }
                return { sp, r };
              }),
            );
            for (const { sp, r } of probeResults) {
              if (!r || r.status !== 200 || r.body?.ok !== true) continue;
              const srJobs = sp.platform === 'smartrecruiters' ? parseSmartRecruitersBoardScrape(sp.boardUrl, r.body) : [];
              const links = Array.isArray(r.body.links) ? (r.body.links as string[]) : [];
              const jobsArr = Array.isArray(r.body.jobs) ? (r.body.jobs as unknown[]) : [];
              const hasRealJobs =
                sp.platform === 'smartrecruiters'
                  ? srJobs.length > 0
                  : jobsArr.length > 0 || links.length > 0;
              if (hasRealJobs) {
                const entry: DiscoveredAtsBoard = {
                  domain: dom,
                  platform: sp.platform,
                  slug: sp.slug,
                  boardUrl: sp.boardUrl,
                  discoveredFrom: `slug-probe:${dom}`,
                  boardStatus: 'ok',
                };
                foundForDom.push(entry);
                discoveredBoards.push(entry);
                candidateUrls.add(sp.boardUrl);
              }
            }
          };

          await runSlugProbeWave(phase1Probes);
          if (foundForDom.length === 0 && !domHitBudgetCap) {
            await runSlugProbeWave(phase2WorkdayProbes);
          }

          // Search-assisted ATS board fallback when company uses a non-standard Workday/Greenhouse/Ashby tenant slug
          if (foundForDom.length === 0) {
            tried.push(`search:ats:${dom}`);
            const sr = await executeSearch({
              query: `(site:myworkdayjobs.com OR site:job-boards.greenhouse.io OR site:boards.greenhouse.io OR site:jobs.ashbyhq.com OR site:jobs.lever.co OR site:apply.workable.com OR site:jobs.smartrecruiters.com OR site:icims.com) "${baseSlug}"`,
              maxResults: 10,
            }).catch(() => null);
            const srHits = Array.isArray(sr?.body?.results) ? (sr!.body.results as Array<Record<string, unknown>>) : [];
            const hitLinks = srHits
              .map((h) => (typeof h.url === 'string' ? h.url.trim() : ''))
              .filter((u) => u.startsWith('https://'));
            if (hitLinks.length > 0) {
              const searchBoards = discoverAtsBoardsFromHtml({
                sourceUrl: `search:${dom}`,
                links: hitLinks,
              });
              const normBase = baseSlug.replace(/[^a-z0-9]+/g, '');
              for (const sb of searchBoards) {
                const rootBoardSlug = sb.slug.split('/')[0] ?? '';
                if (normBase && matchesAtsTenantSlugAgainstToken(rootBoardSlug, normBase)) {
                  const entry: DiscoveredAtsBoard = { ...sb, domain: dom };
                  foundForDom.push(entry);
                  discoveredBoards.push(entry);
                  candidateUrls.add(entry.boardUrl);
                }
              }
            }
          }
        }

        if (foundForDom.length === 0) {
          const finalStatus: AtsBoardStatus = domHitBudgetCap ? 'budget_exhausted' : 'not_found';
          discoveredBoards.push({
            domain: dom,
            platform: 'unknown',
            slug: baseSlug || dom,
            boardUrl: '',
            discoveredFrom: 'none',
            boardStatus: finalStatus,
            tried,
          });
          notes.push(
            domHitBudgetCap
              ? `Scrape budget (${MAX_JOBS_TOTAL_SCRAPES}) exhausted before completing ATS board discovery for "${dom}".`
              : `No ATS job board discovered for "${dom}" after probing ${tried.length} candidates.`,
          );
        }
      }),
    );
  }

  const companyTokensForSearch = companyFilter ? expandCompanyFilterTokens(companyFilter) : [];
  const primaryCompanySlug = companyTokensForSearch[0] && isValidAtsSlug(companyTokensForSearch[0]) ? companyTokensForSearch[0] : '';

  const atsGroups = [
    '(site:job-boards.greenhouse.io OR site:boards.greenhouse.io OR site:jobs.ashbyhq.com)',
    '(site:jobs.lever.co OR site:myworkdayjobs.com OR site:jobs.smartrecruiters.com)',
    '(site:apply.workable.com OR site:jobs.gem.com OR site:ats.rippling.com)',
  ];
  const coreTerms = [companyFilter ? `"${companyFilter}"` : '', query ? `"${query}"` : '', wantRemote ? 'remote' : '']
    .filter(Boolean)
    .join(' ');
  const scopedQueries = atsGroups.map((grp) => `${grp} ${coreTerms}`.trim());
  if (primaryCompanySlug) {
    const nonCompanyTerms = [query ? `"${query}"` : '', wantRemote ? 'remote' : ''].filter(Boolean).join(' ');
    scopedQueries.push(
      `(site:jobs.smartrecruiters.com/${primaryCompanySlug} OR site:${primaryCompanySlug}.wd5.myworkdayjobs.com OR site:${primaryCompanySlug}.wd1.myworkdayjobs.com) ${nonCompanyTerms}`.trim(),
    );
  }

  // Never pass `timeRange` (`qdr:w`/`qdr:m`) on ATS `site:` queries — Google omits indexed publish dates on ATS SPA/board URLs
  // and returns 0 results for `postedWithinDays <= 30`; `maxAgeCutoffMs` filters accurately using authoritative ATS `postedAt`!
  if (coreTerms && (domainsInput.length === 0 || Boolean(companyFilter))) {
    const searchMaxResults = postedWithinDays !== undefined ? 15 : 10;
    const searchCandidateCap =
      postedWithinDays !== undefined ? Math.min(40, Math.max(35, limit * 3)) : Math.min(35, limit * 2);
    const searchResponses = await Promise.all(
      scopedQueries.map((sq) =>
        executeSearch({
          query: sq,
          maxResults: searchMaxResults,
        }).catch(() => ({ status: 500, body: {} as Record<string, unknown> })),
      ),
    );

    let addedSearchHits = 0;
    for (const sr of searchResponses) {
      const webResults = Array.isArray(sr.body?.results) ? (sr.body.results as Array<Record<string, unknown>>) : [];
      for (const hit of webResults) {
        const u = typeof hit.url === 'string' ? hit.url.trim() : '';
        if (u.startsWith('https://') && candidateUrls.size < searchCandidateCap) {
          candidateUrls.add(u);
          addedSearchHits++;
        }
      }
    }
    if (addedSearchHits > 0) sourcesUsed.add('ats_search');
  }

  // Direct company board discovery when `company` is provided without `domains` (e.g. `company: "Visa"` -> `jobs.smartrecruiters.com/Visa`,
  // `company: "Spotify"` -> `jobs.lever.co/spotify`, with `respectRobots: true` — NEVER `api.smartrecruiters.com`!)
  if (companyFilter && domainsInput.length === 0) {
    const primarySlug = primaryCompanySlug;
    if (primarySlug) {
      const lowerSlug = primarySlug.toLowerCase();
      const rawTrimmedSlug = companyFilter.replace(/[^A-Za-z0-9_-]+/g, '');
      const srDisplaySlug =
        rawTrimmedSlug && rawTrimmedSlug.toLowerCase() === lowerSlug ? rawTrimmedSlug : primarySlug;
      const existingBoardKeys = new Set(
        [...candidateUrls]
          .map((u) => classifyFullBoardKey(u))
          .filter((x): x is NonNullable<typeof x> => Boolean(x?.isBoard))
          .map((x) => x.key),
      );
      const hasSmartRecruitersForCompany = [...candidateUrls].some((u) =>
        new RegExp(`^https://jobs\\.smartrecruiters\\.com/${lowerSlug.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:/|$)`, 'i').test(u),
      );
      if (!hasSmartRecruitersForCompany) {
        candidateUrls.add(`https://jobs.smartrecruiters.com/${srDisplaySlug}`);
      }
      if (!existingBoardKeys.has(`greenhouse:${lowerSlug}`)) {
        candidateUrls.add(`https://boards.greenhouse.io/${primarySlug}`);
      }
      if (!existingBoardKeys.has(`ashby:${lowerSlug}`)) {
        candidateUrls.add(`https://jobs.ashbyhq.com/${primarySlug}`);
      }
      if (!existingBoardKeys.has(`lever:${lowerSlug}`)) {
        candidateUrls.add(`https://jobs.lever.co/${primarySlug}`);
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
      sourcesUsed.add('builtin');
      // Extract Built In job links (`https://builtin.com/job/...`) + inline card compensation if present
      const cardRe = /\[([^\[\]\n]{4,120})\]\((https:\/\/(?:www\.)?builtin\.com\/job\/[^)\s]+)\)([\s\S]{0,260}?)(?=\[[^\[\]\n]+\]\(https:\/\/(?:www\.)?builtin\.com\/job\/|$)/gi;
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

  // Strictly opt-in robots.txt-allowed public remote job feeds (We Work Remotely RSS, Himalayas, Working Nomads)
  const shouldFetchPublicFeeds = payload.includePublicFeeds === true;
  if (shouldFetchPublicFeeds) {
    const feedOuts = await Promise.all(
      PUBLIC_JOB_FEEDS.map(async (feed) => ({
        feed,
        fo: await executeScrape({
          url: feed.url,
          renderMode: 'auto',
          formats: ['markdown'],
          ...(payload.target ? { target: payload.target } : {}),
          ...(payload.site ? { site: payload.site } : {}),
        }).catch(() => null),
      })),
    );
    for (const { feed, fo } of feedOuts) {
      if (fo?.status === 200 && fo.body?.ok === true && Array.isArray(fo.body.jobs)) {
        sourcesUsed.add(`public_feed:${feed.id}`);
        for (const fj of fo.body.jobs as StructuredJobRecord[]) {
          collected.push(fj);
        }
      }
    }
  }

  // Deduplicate redundant single-posting fetches when the parent board (especially Ashby 1.22 MB `posting-api/job-board/<slug>`
  // and Rippling `ats/v1/board/<org>/jobs`) is also present or has >= 2 postings from the same company!
  const rawUrlList = [...candidateUrls];
  const postingCountByBoard = new Map<string, { count: number; boardUrl: string; hasBoard: boolean }>();
  for (const u of rawUrlList) {
    const info = classifyFullBoardKey(u);
    if (!info) continue;
    const entry = postingCountByBoard.get(info.key) ?? { count: 0, boardUrl: info.boardUrl, hasBoard: false };
    if (info.isBoard) entry.hasBoard = true;
    else entry.count++;
    postingCountByBoard.set(info.key, entry);
  }
  const promotedBoardUrls: string[] = [];
  for (const [bKey, meta] of postingCountByBoard.entries()) {
    const isWorkdayCompanyMatch =
      bKey.startsWith('workday:') &&
      hasCompanyOrDomainScope &&
      meta.count >= 1 &&
      (!primaryCompanySlug || bKey.startsWith(`workday:${primaryCompanySlug.toLowerCase()}:`));
    if (
      !meta.hasBoard &&
      (isWorkdayCompanyMatch ||
        (meta.count >= 2 && (bKey.startsWith('ashby:') || bKey.startsWith('rippling:') || bKey.startsWith('workday:'))))
    ) {
      promotedBoardUrls.push(meta.boardUrl);
    }
  }
  const boardWaveUrls = [
    ...new Set([
      ...promotedBoardUrls,
      ...rawUrlList.filter((u) => {
        const info = classifyFullBoardKey(u);
        return Boolean(info?.isBoard || isSmartRecruitersBoardUrl(u));
      }),
    ]),
  ];
  const postingWaveUrls = [
    ...new Set(
      rawUrlList.filter((u) => {
        const info = classifyFullBoardKey(u);
        return !info?.isBoard && !isSmartRecruitersBoardUrl(u);
      }),
    ),
  ];
  const fetchedCompleteBoards = new Set<string>();
  const smartRecruitersPostingsToEnrich: StructuredJobRecord[] = [];

  // Run board URLs in Wave 1 BEFORE single-posting URLs in Wave 2 so `fetchedCompleteBoards` is populated before any
  // single-posting Ashby/Greenhouse/Lever/Gem/Rippling URL is dispatched (preventing concurrent-slice board re-downloads!).
  for (const waveUrls of [boardWaveUrls, postingWaveUrls]) {
    for (let i = 0; i < waveUrls.length; i += MAX_JOBS_CONCURRENT_SCRAPES) {
      const rawSlice = waveUrls.slice(i, i + MAX_JOBS_CONCURRENT_SCRAPES);
      const slice = rawSlice.filter((u) => {
        const info = classifyFullBoardKey(u);
        // Skip redundant single-posting download if we ALREADY collected the complete board for this `(platform, slug)`!
        if (info && !info.isBoard && fetchedCompleteBoards.has(info.key)) {
          return false;
        }
        return true;
      });
      if (slice.length === 0) continue;

    const batchOut = await Promise.all(
      slice.map((u) => {
        let scrapeUrl = u;
        const srBoard = isSmartRecruitersBoardUrl(u);
        const info = classifyFullBoardKey(u);
        if (query && /myworkday(?:jobs|site)\.com/i.test(u) && !/\/job\//i.test(u)) {
          try {
            const wdU = new URL(u);
            if (!wdU.searchParams.has('q')) wdU.searchParams.set('q', query);
            scrapeUrl = wdU.toString();
          } catch {
            scrapeUrl = u;
          }
        }
        const needLinks = Boolean(srBoard || info?.isBoard || discoveredBoards.some((b) => b.boardUrl === u));
        return executeScrape({
          url: scrapeUrl,
          renderMode: srBoard ? 'off' : 'auto',
          discoverLlmsTxt: false,
          preferOriginMarkdown: false,
          formats: needLinks ? ['markdown', 'links'] : ['markdown'],
          ...(payload.target ? { target: payload.target } : {}),
          ...(payload.site ? { site: payload.site } : {}),
        }).catch(() => null);
      }),
    );
    for (let j = 0; j < slice.length; j++) {
      const origU = slice[j]!;
      const sc = batchOut[j];
      const discEntry = discoveredBoards.find((b) => b.boardUrl === origU);
      if (!sc || sc.status !== 200 || sc.body?.ok !== true) {
        if (isClosedSchemeDowngradeResult(origU, sc)) {
          // Treat Rippling / ATS HTTPS->HTTP redirect downgrade on a job posting URL cleanly as a closed/unavailable posting!
          continue;
        }
        if (discEntry) {
          if (sc?.body?.error === 'jobs_scrape_budget_exceeded') {
            discEntry.boardStatus = 'budget_exhausted';
          } else {
            const upstreamStatus =
              typeof sc?.body?.status === 'number' && sc.body.status > 0 ? sc.body.status : (sc?.status ?? 0);
            discEntry.boardStatus = classifyAtsBoardStatus({
              httpStatus: upstreamStatus,
              requestedUrl: origU,
              finalUrl: typeof sc?.body?.finalUrl === 'string' ? sc.body.finalUrl : undefined,
            });
          }
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
        const fullInfo = classifyFullBoardKey(origU);
        if (fullInfo && sc.body.truncated !== true) {
          fetchedCompleteBoards.add(fullInfo.key);
        }
        const boardExtId =
          typeof sc.body.extractorId === 'string' && sc.body.extractorId
            ? sc.body.extractorId
            : resolveAtsPreFetchSpec(origU)?.id;
        if (boardExtId) resolvedAdapterIds.add(boardExtId);
        const boardJobs = [...(sc.body.jobs as StructuredJobRecord[])];
        let boardTotal = typeof sc.body.total === 'number' ? sc.body.total : boardJobs.length;
        let boardTruncated = sc.body.truncated === true;
        let boardNextCursor = typeof sc.body.nextCursor === 'string' ? sc.body.nextCursor : undefined;

        // Paginate Workday CXS boards (`offset: 20, 40, ...` up to `offset <= 80`) when truncated!
        if (boardTruncated && boardNextCursor && /myworkday(?:jobs|site)\.com/i.test(origU)) {
          let nextOffset = parseInt(boardNextCursor, 10);
          while (Number.isFinite(nextOffset) && nextOffset > 0 && nextOffset <= 80) {
            let pageUrlStr = '';
            try {
              const wdPageU = new URL(origU);
              wdPageU.searchParams.set('offset', String(nextOffset));
              if (query && !wdPageU.searchParams.has('q')) wdPageU.searchParams.set('q', query);
              pageUrlStr = wdPageU.toString();
            } catch {
              break;
            }
            const wdPageRes = await executeScrape({
              url: pageUrlStr,
              renderMode: 'off',
              discoverLlmsTxt: false,
              preferOriginMarkdown: false,
              formats: ['markdown'],
              ...(payload.target ? { target: payload.target } : {}),
              ...(payload.site ? { site: payload.site } : {}),
            }).catch(() => null);
            const moreJobs = Array.isArray(wdPageRes?.body?.jobs)
              ? (wdPageRes!.body.jobs as StructuredJobRecord[])
              : [];
            if (wdPageRes?.status !== 200 || moreJobs.length === 0) {
              boardTruncated = boardTotal > boardJobs.length;
              break;
            }
            boardJobs.push(...moreJobs);
            if (typeof wdPageRes.body.total === 'number') {
              boardTotal = Math.max(boardTotal, wdPageRes.body.total);
            }
            boardTruncated = wdPageRes.body.truncated === true;
            boardNextCursor = typeof wdPageRes.body.nextCursor === 'string' ? wdPageRes.body.nextCursor : undefined;
            if (!boardTruncated || !boardNextCursor) break;
            nextOffset = parseInt(boardNextCursor, 10);
          }
        }

        if (discEntry) {
          discEntry.boardStatus = classifyAtsBoardStatus({
            httpStatus: sc.status,
            requestedUrl: origU,
            finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
            jobCount: boardJobs.length,
          });
          discEntry.total = boardTotal;
          discEntry.returned = boardJobs.length;
          discEntry.truncated = boardTotal > boardJobs.length;
          if (boardTotal > boardJobs.length && boardNextCursor) {
            discEntry.nextCursor = boardNextCursor;
          }
        }
        for (const br of boardJobs) {
          if (br.source) {
            sourcesUsed.add(`ats:${br.source}`);
            resolvedAdapterIds.add(br.source);
          }
          collected.push(br);
        }
        continue;
      }

      // SmartRecruiters public HTML board (`https://jobs.smartrecruiters.com/{Company}`, strictly respecting `robots.txt`!)
      if (isSmartRecruitersBoardUrl(origU)) {
        const srRecords = parseSmartRecruitersBoardScrape(origU, sc.body);
        if (discEntry) {
          discEntry.boardStatus = classifyAtsBoardStatus({
            httpStatus: sc.status,
            requestedUrl: origU,
            finalUrl: typeof sc.body.finalUrl === 'string' ? sc.body.finalUrl : undefined,
            jobCount: srRecords.length,
          });
          discEntry.total = srRecords.length;
          discEntry.returned = srRecords.length;
          discEntry.truncated = false;
        }
        if (srRecords.length > 0) {
          sourcesUsed.add('ats:smartrecruiters');
          resolvedAdapterIds.add('smartrecruiters');
          const matchingSr = query
            ? srRecords.filter((r) => matchesJobQueryRelevance(r.title, r.snippet, query) !== null)
            : srRecords;
          for (const r of matchingSr.slice(0, Math.min(limit, 8))) {
            smartRecruitersPostingsToEnrich.push(r);
          }
          for (const r of srRecords) {
            collected.push(r);
          }
        }
        continue;
      }

      // Support twin-extracted job boards (`icims` `records[]`) in `jobs` search mode
      if (Array.isArray(sc.body.records) && sc.body.extractorId === 'icims') {
        sourcesUsed.add('ats:icims');
        resolvedAdapterIds.add('icims');
        const icimsRecs = sc.body.records as Array<Record<string, unknown>>;
        const icimsCo = inferCompanyFromAtsUrl(origU);
        for (const rc of icimsRecs) {
          const rTitle = typeof rc.title === 'string' ? rc.title.trim() : '';
          const rUrl = typeof rc.url === 'string' ? rc.url.trim() : '';
          if (!rTitle || !rUrl) continue;
          const rLoc =
            typeof rc.location === 'string'
              ? rc.location.trim()
              : Array.isArray(rc.locations) && typeof rc.locations[0] === 'string'
                ? rc.locations[0].trim()
                : '';
          const rSalary = typeof rc.salary === 'string' ? rc.salary : typeof rc.payRaw === 'string' ? rc.payRaw : '';
          collected.push({
            title: rTitle,
            company: icimsCo,
            url: rUrl,
            applyUrl: rUrl,
            workplaceType: inferWorkdayWorkplaceType('', rLoc, rTitle),
            locations: rLoc ? [rLoc] : [],
            pay: rSalary ? parsePayFromText(rSalary) : null,
            postedAt: typeof rc.postedAt === 'string' ? rc.postedAt : null,
            source: 'icims',
          });
        }
        continue;
      }

      const rawPageHtml = typeof sc.body.rawHtml === 'string' ? sc.body.rawHtml : typeof sc.body.html === 'string' ? sc.body.html : '';
      const md = typeof sc.body.markdown === 'string' ? sc.body.markdown : '';
      const jp =
        (sc.body.jobPosting as StructuredJobPosting | undefined) ??
        (rawPageHtml ? (extractJobPostingJsonLd(rawPageHtml, origU, md) ?? undefined) : undefined);
      const meta = (sc.body.metadata as Record<string, unknown> | undefined) ?? {};
      const rawTitle = (jp?.title || (typeof meta.title === 'string' ? meta.title : '')).replace(/\s*[@|–-]\s*[^@|–-]+$/, '').trim();
      if (!rawTitle) continue;
      const company = jp?.hiringOrganization || inferCompanyFromAtsUrl(origU);
      const pay = jp?.pay ?? parsePayFromText(md);
      const locs = jp?.jobLocation ?? [];
      const wp = jp?.workplaceType && jp.workplaceType !== 'unknown' ? jp.workplaceType : inferWorkplaceType(`${locs.join(' ')} ${md.slice(0, 400)}`);
      const postedAt = jp?.datePosted ?? (typeof meta.publishedTime === 'string' ? meta.publishedTime : null);
      const applyUrl = jp?.applyUrl || origU;
      const jobSource = jp?.source || (/smartrecruiters\.com/i.test(origU) ? 'smartrecruiters' : String(sc.body.extractorId ?? 'ats'));
      sourcesUsed.add(`ats:${jobSource}`);
      const postExtId =
        typeof sc.body.extractorId === 'string' && sc.body.extractorId
          ? sc.body.extractorId
          : resolveAtsPreFetchSpec(origU)?.id ?? (jobSource !== 'ats' ? jobSource : undefined);
      if (postExtId) resolvedAdapterIds.add(postExtId);

      collected.push({
        title: rawTitle,
        company,
        url: origU,
        applyUrl,
        workplaceType: wp,
        locations: locs,
        pay,
        postedAt,
        source: jobSource,
        ...(jp?.employmentType ? { employmentType: jp.employmentType } : {}),
        ...(md ? { snippet: md.slice(0, 240) } : {}),
      });
      }
    }
  }

  // Enrich top matching SmartRecruiters posting pages in bounded batches of 4 to populate schema.org/JobPosting JSON-LD (`datePosted`, `jobLocation`, `baseSalary`)
  if (smartRecruitersPostingsToEnrich.length > 0 && !budgetExhausted) {
    for (let i = 0; i < smartRecruitersPostingsToEnrich.length; i += MAX_JOBS_CONCURRENT_SCRAPES) {
      const batch = smartRecruitersPostingsToEnrich.slice(i, i + MAX_JOBS_CONCURRENT_SCRAPES);
      const outs = await Promise.all(
        batch.map((srRec) =>
          executeScrape({
            url: srRec.url,
            renderMode: 'off',
            discoverLlmsTxt: false,
            preferOriginMarkdown: false,
            formats: ['markdown'],
            ...(payload.target ? { target: payload.target } : {}),
            ...(payload.site ? { site: payload.site } : {}),
          }).catch(() => null),
        ),
      );
      for (let j = 0; j < batch.length; j++) {
        const srRec = batch[j]!;
        const det = outs[j];
        if (!det || det.status !== 200 || det.body?.ok !== true) continue;
        const detState = typeof det.body.contentState === 'string' ? det.body.contentState : undefined;
        if (detState === 'closed_posting' || detState === 'soft_404') {
          const dropIdx = collected.findIndex((c) => c.url.toLowerCase() === srRec.url.toLowerCase());
          if (dropIdx >= 0) collected.splice(dropIdx, 1);
          continue;
        }
        const detHtml = typeof det.body.rawHtml === 'string' ? det.body.rawHtml : typeof det.body.html === 'string' ? det.body.html : '';
        const detMd = typeof det.body.markdown === 'string' ? det.body.markdown : '';
        const jp =
          (det.body.jobPosting as StructuredJobPosting | undefined) ??
          (detHtml ? (extractJobPostingJsonLd(detHtml, srRec.url, detMd) ?? undefined) : undefined);
        const target = collected.find((c) => c.url.toLowerCase() === srRec.url.toLowerCase());
        if (!target) continue;
        if (jp?.title) target.title = jp.title;
        if (jp?.hiringOrganization) target.company = jp.hiringOrganization;
        if (jp?.jobLocation && jp.jobLocation.length > 0) target.locations = jp.jobLocation;
        if (jp?.workplaceType && jp.workplaceType !== 'unknown') target.workplaceType = jp.workplaceType;
        if (jp?.pay) target.pay = jp.pay;
        else if (!target.pay && detMd) target.pay = parsePayFromText(detMd);
        if (jp?.datePosted) target.postedAt = jp.datePosted;
        if (jp?.employmentType) target.employmentType = jp.employmentType;
        if (jp?.applyUrl) target.applyUrl = jp.applyUrl;
      }
    }
  }

  const allowedCompanyTokens = new Set<string>();
  if (companyFilter) {
    allowedCompanyTokens.add(companyFilter);
    for (const expanded of expandCompanyFilterTokens(companyFilter)) {
      allowedCompanyTokens.add(expanded);
    }
  }
  for (const dom of domainsInput) {
    allowedCompanyTokens.add(dom);
    for (const expanded of expandCompanyFilterTokens(dom)) {
      allowedCompanyTokens.add(expanded);
    }
  }
  for (const db of discoveredBoards) {
    if (db.boardStatus !== 'not_found' && db.boardStatus !== 'budget_exhausted' && db.slug) {
      const rootSlug = (db.slug.split('/')[0] ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '');
      if (rootSlug) allowedCompanyTokens.add(rootSlug);
    }
  }
  const allowedBoardPrefixes = discoveredBoards
    .filter((b) => b.boardStatus !== 'not_found' && b.boardStatus !== 'budget_exhausted' && b.boardUrl)
    .map((b) => b.boardUrl.replace(/\/+$/, '').toLowerCase());

  const nowMs = Date.now();
  const maxAgeCutoffMs = postedWithinDays ? nowMs - postedWithinDays * 86_400_000 : null;
  const seenKeys = new Set<string>();
  const seenUrls = new Set<string>();
  const matchedJobs: StructuredJobRecord[] = [];

  for (const rawJob of collected) {
    const cleanUrlKey = rawJob.url.replace(/\/+$/, '').toLowerCase();
    const dedupKey = canonicalJobKey(rawJob.company, rawJob.title);
    if (seenUrls.has(cleanUrlKey) || seenKeys.has(dedupKey)) continue;

    // Strict company / domain scope guard: never leak unrelated companies' postings when `company` or `domains` is set
    if (hasCompanyOrDomainScope && !matchesAllowedCompanyOrDomain(rawJob, allowedCompanyTokens, allowedBoardPrefixes)) {
      continue;
    }

    // Exclude already-applied list
    const isExcluded = excludeList.some((ex) => {
      if (ex.url && ex.url === cleanUrlKey) return true;
      const compMatch = ex.company && rawJob.company.toLowerCase().includes(ex.company);
      const titleMatch = ex.title && rawJob.title.toLowerCase().includes(ex.title);
      return Boolean((ex.company && ex.title && compMatch && titleMatch) || (ex.company && !ex.title && compMatch));
    });
    if (isExcluded) continue;

    // Strict phrase / all-tokens query relevance filter (`matchedOn`)
    let matchedOn: 'phrase' | 'all_tokens' | 'company_filter' = 'company_filter';
    if (query) {
      const qMatch = matchesJobQueryRelevance(rawJob.title, rawJob.snippet, query);
      if (!qMatch) continue;
      matchedOn = qMatch;
    }

    if (wantRemote === true && rawJob.workplaceType !== 'remote' && !rawJob.locations.some((l) => /remote/i.test(l))) {
      continue;
    }
    if (geoLocationsFilter.length > 0 && !matchesGeoLocationsFilter(rawJob.locations, geoLocationsFilter)) {
      continue;
    }

    let payUnknown = false;
    if (minBase !== undefined) {
      if (!rawJob.pay) {
        if (strictPay) continue;
        payUnknown = true;
      } else {
        // P11: Never treat `total` / `ote` target cash as meeting `minBase` unless basis === 'base'
        if (rawJob.pay.basis !== 'base') continue;
        const comparedPay =
          minBaseMode === 'ceiling' || minBaseMode === 'overlap'
            ? (rawJob.pay.max ?? rawJob.pay.min ?? 0)
            : (rawJob.pay.min ?? rawJob.pay.max ?? 0);
        if (comparedPay < minBase) continue;
      }
    }

    if (maxAgeCutoffMs !== null && rawJob.postedAt) {
      const parsedTs = Date.parse(rawJob.postedAt);
      if (Number.isFinite(parsedTs) && parsedTs < maxAgeCutoffMs) continue;
    }

    seenUrls.add(cleanUrlKey);
    seenKeys.add(dedupKey);
    matchedJobs.push({
      ...rawJob,
      matchedOn,
      ...(payUnknown ? { payUnknown: true } : {}),
    });
  }

  // Rank exact phrase matches ahead of all-tokens matches (and verified base pay ahead of unknown pay when `minBase` is set)
  matchedJobs.sort((a, b) => {
    const rankMatch = (m?: string) => (m === 'phrase' ? 0 : m === 'all_tokens' ? 1 : 2);
    const dm = rankMatch(a.matchedOn) - rankMatch(b.matchedOn);
    if (dm !== 0) return dm;
    if (minBase !== undefined) {
      const dp = (a.payUnknown ? 1 : 0) - (b.payUnknown ? 1 : 0);
      if (dp !== 0) return dp;
    }
    return 0;
  });

  const finalJobs = matchedJobs.slice(0, limit);
  const payUnknownCount = minBase !== undefined ? finalJobs.filter((j) => j.payUnknown === true).length : undefined;

  if (budgetExhausted && !notes.some((n) => n.includes('Scrape budget'))) {
    notes.push(`Scrape budget (${MAX_JOBS_TOTAL_SCRAPES}) exhausted before all candidate boards could be checked.`);
  }
  if (candidateUrls.size === 0 && collected.length === 0 && domainsInput.length === 0) {
    notes.push('No ATS search results returned; ensure SERPER_API_KEY or SEARXNG_URL is configured on the Hub.');
  }

  const boardsDiscoveredCount = discoveredBoards.filter((b) => b.boardStatus !== 'not_found' && Boolean(b.boardUrl)).length;
  activeTracer?.setAttribute('edgefetch.jobs.mode', 'search');
  activeTracer?.setAttribute('edgefetch.jobs.boards_discovered', boardsDiscoveredCount);
  activeTracer?.setAttribute('edgefetch.jobs.jobs_returned', finalJobs.length);
  if (resolvedAdapterIds.size > 0) {
    activeTracer?.setAttribute('edgefetch.adapter_id', [...resolvedAdapterIds].join(','));
  }

  return {
    status: 200,
    body: {
      ok: true,
      query,
      ...(companyFilter ? { company: companyFilter } : {}),
      ...(domainsInput.length > 0 ? { domains: domainsInput, discoveredBoards } : {}),
      ...(minBase !== undefined ? { minBaseMode, strictPay, payUnknownCount } : {}),
      ...(budgetExhausted ? { budgetExhausted: true } : {}),
      sourcesUsed: [...sourcesUsed],
      count: finalJobs.length,
      candidatesChecked: candidateUrls.size,
      jobs: finalJobs,
      ...(notes.length > 0 ? { notes } : {}),
    },
  };
  };
  return activeTracer ? activeTracer.run(runJobs) : runJobs();
}
