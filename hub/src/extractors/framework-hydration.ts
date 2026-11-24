/**
 * Tier 2 Universal Framework State Hydrator v2 & Captured XHR JSON Record Distiller
 * (`hub/src/extractors/framework-hydration.ts`).
 *
 * Upgrades `recoverSsrHydrationContent` (`R6`) across modern SSR/SPA state containers:
 *  1. Linear O(N) Next.js 13–15 App Router RSC Flight stream scanner (`self.__next_f.push`) — zero regex backtracking!
 *  2. Nuxt 3 `devalue` flat index-pointer array dereferencer (`#__NUXT_DATA__`, bounded `maxNodes = 2_000`, cycle-safe).
 *  3. Next.js Pages (`#__NEXT_DATA__`), Remix (`__remixContext`), Apollo (`__APOLLO_STATE__`),
 *     Angular (`#ng-state`), Wix (`#wix-viewer-model`), Squarespace (`Static.SQUARESPACE_CONTEXT`),
 *     and Substack (`window._preloads`).
 *  4. Homogeneous Object-Array Record Distiller (`records[]` + GFM table/bullets), shared with Phase 2's
 *     Chromium CDP same-origin JSON XHR/Fetch response harvester (`distillCapturedJsonResponses`).
 *
 * Security & Anti-False-Zero Invariants:
 *  - Never emits `records: []` or `(0 results)` when no homogeneous data array matches — returns `null`.
 *  - Rejects nav/menu chrome arrays (`<= 10` short `{ label, href }` items with zero metadata keys).
 *  - Blocks prototype pollution (`__proto__`, `constructor`, `prototype`) in all dereferenced/distilled objects.
 *  - Sanitizes every surfaced string via pre/post-entity-decode `stripInvisibleSchemaChars`,
 *    `neutralizeAllUnsafeMarkdownLinksLinear`, and `<`/`>` escaping.
 */

import {
  MAX_HTML_SCAN_CHARS,
  replaceHtmlTagBlocksLinear,
  replacePairedHtmlElementsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from '../safe-input';
import { neutralizeAllUnsafeMarkdownLinksLinear } from '../scrape-advanced';
import {
  sanitizeSchemaHttpsUrl,
  sanitizeSchemaPlainField,
  stripInvisibleSchemaChars,
} from './schema-org';
import type { HtmlFragmentConverter } from './types';
import { decodeBasicEntities, formatGfmTable, hasRawOrEncodedUnicodeTagLinear } from './utils';

export interface HydratedFrameworkStateResult {
  title?: string;
  description?: string;
  markdown: string;
  framework: string;
  records?: Array<Record<string, unknown>>;
  structured?: Record<string, unknown>;
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
  rawDecodedStringsForPiCheck?: string;
}

export interface CapturedJsonPayloadInput {
  url?: string;
  method?: string;
  status?: number;
  body: string;
}

const UNSAFE_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const SKIP_WALK_KEYS = new Set([
  'buildid',
  'scriptloader',
  '__n_ssg',
  '__n_ssp',
  'assetprefix',
  'runtimeconfig',
  'stylesheet',
  'css',
  'svg',
  'icon',
  'webpack',
  'chunks',
  'polyfillfiles',
  'lowpriorityfiles',
  'ampfirstpages',
]);

const NAV_CONTAINER_KEY_RE =
  /^(?:nav|navigation|navbar|menu|menus|menuitems|header|footer|breadcrumbs?|social|sociallinks|locales?|languages?|tabs|routes|icons?|themes?|shortcuts)$/i;

const RICH_PROSE_KEYS = new Set([
  'content',
  'body',
  'markdown',
  'mdx',
  'articlebody',
  'descriptionhtml',
  'descriptionplain',
  'jobdescription',
  'responsibilities',
  'qualifications',
  'requirements',
  'summary',
  'overview',
  'about',
  'bio',
  'details',
  'text',
  'rendered',
  'body_html',
  'html',
]);

const RECORD_TITLE_KEYS = [
  'title',
  'name',
  'headline',
  'jobTitle',
  'role',
  'position',
  'question',
  'subject',
  'package',
  'repo',
  'full_name',
  'model',
  'label',
];

const RECORD_URL_KEYS = [
  'url',
  'href',
  'permalink',
  'canonicalUrl',
  'applyUrl',
  'jobUrl',
  'absolute_url',
  'hostedUrl',
  'html_url',
  'link',
  'path',
  'slug',
];

const RECORD_META_KEYS = [
  'summary',
  'description',
  'excerpt',
  'snippet',
  'answer',
  'location',
  'locationName',
  'city',
  'workplaceType',
  'price',
  'salary',
  'compensation',
  'date',
  'publishedAt',
  'published_at',
  'createdAt',
  'created_at',
  'updatedAt',
  'updated_at',
  'postedAt',
  'company',
  'organization',
  'department',
  'team',
  'category',
  'type',
  'status',
  'author',
  'version',
  'downloads',
  'stars',
  'stargazers_count',
];

function countWords(s: string): number {
  return (s.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
}

/**
 * Linear O(N) quote-and-escape-aware JSON string literal scanner starting at opening `"` (`s[quoteStart] === '"'`).
 * Returns `{ rawJsonLiteral, endIndex }` or `null` if unclosed or exceeding `maxLen`.
 */
export function scanJsonStringLiteralAt(
  s: string,
  quoteStart: number,
  maxLen = 1_500_000,
): { rawLiteral: string; endIndex: number } | null {
  if (quoteStart < 0 || quoteStart >= s.length || s.charCodeAt(quoteStart) !== 34 /* '"' */) return null;
  const limit = Math.min(s.length, quoteStart + 1 + maxLen);
  let i = quoteStart + 1;
  while (i < limit) {
    const ch = s.charCodeAt(i);
    if (ch === 34 /* '"' */) {
      return { rawLiteral: s.slice(quoteStart, i + 1), endIndex: i + 1 };
    }
    if (ch === 92 /* '\\' */) {
      i += 2;
      continue;
    }
    i++;
  }
  return null;
}

/**
 * Linear O(N) balanced `{...}` or `[...]` JSON slice extractor starting at or after `searchFrom`.
 */
export function extractBalancedJsonAtLinear(
  s: string,
  searchFrom: number,
  maxChars = 1_500_000,
): string | null {
  const limit = Math.min(s.length, searchFrom + maxChars);
  let start = -1;
  let openCode = 0;
  let closeCode = 0;
  for (let i = Math.max(0, searchFrom); i < limit; i++) {
    const c = s.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 13 || c === 61 /* '=' */) continue;
    if (c === 123 /* '{' */) {
      start = i;
      openCode = 123;
      closeCode = 125;
    } else if (c === 91 /* '[' */) {
      start = i;
      openCode = 91;
      closeCode = 93;
    }
    break;
  }
  if (start < 0) return null;

  let depth = 0;
  let inString = false;
  for (let i = start; i < limit; i++) {
    const ch = s.charCodeAt(i);
    if (inString) {
      if (ch === 92 /* '\\' */) {
        i++;
        continue;
      }
      if (ch === 34 /* '"' */) inString = false;
      continue;
    }
    if (ch === 34 /* '"' */) {
      inString = true;
      continue;
    }
    if (ch === openCode) {
      depth++;
    } else if (ch === closeCode) {
      depth--;
      if (depth === 0) {
        return s.slice(start, i + 1);
      }
    }
  }
  return null;
}

const DEVALUE_WRAPPER_TAGS = new Set(['Reactive', 'ShallowReactive', 'Ref', 'ShallowRef', 'Object']);
const DEVALUE_EMPTY_TAGS = new Set(['EmptyRef', 'EmptyShallowRef', 'Undefined', 'NaN', 'Infinity', '-Infinity', '-0', 'RegExp']);
const DEVALUE_STRING_TAGS = new Set(['Date', 'URL', 'BigInt']);

/**
 * Detects whether a parsed JSON value is a Nuxt 3 `devalue` flat index-pointer array (`#__NUXT_DATA__`).
 */
export function isNuxtDevalueFlatArray(parsed: unknown): parsed is unknown[] {
  if (!Array.isArray(parsed) || parsed.length < 2) return false;
  const root = parsed[0];
  if (Array.isArray(root) && root.length === 2 && typeof root[0] === 'string' && DEVALUE_WRAPPER_TAGS.has(root[0]) && typeof root[1] === 'number') {
    return true;
  }
  if (root && typeof root === 'object' && !Array.isArray(root)) {
    const vals = Object.values(root as Record<string, unknown>);
    if (vals.length > 0 && vals.every((v) => typeof v === 'number' && Number.isInteger(v) && v >= -8 && v < parsed.length)) {
      return true;
    }
  }
  return false;
}

/**
 * Safely dereferences a Nuxt 3 `devalue` flat slot table into a bounded, cycle-free plain JS tree.
 */
export function dereferenceNuxtDevaluePayload(
  table: unknown[],
  maxNodes = 2_000,
  maxDepth = 12,
): unknown {
  if (!Array.isArray(table) || table.length === 0) return null;
  const memo = new Map<number, unknown>();
  const activeStack = new Set<number>();
  let allocatedNodes = 0;

  const isSlotIndex = (v: unknown): v is number =>
    typeof v === 'number' && Number.isInteger(v) && v >= 0 && v < table.length;

  const derefSlot = (idx: number, depth: number): unknown => {
    if (idx < 0 || idx >= table.length || depth > maxDepth || allocatedNodes >= maxNodes) return null;
    if (memo.has(idx)) return memo.get(idx);
    if (activeStack.has(idx)) return null; // Cycle breaker

    const raw = table[idx];
    if (raw === null || raw === undefined || typeof raw !== 'object') {
      return raw;
    }

    activeStack.add(idx);
    allocatedNodes++;
    let result: unknown = null;

    if (Array.isArray(raw)) {
      const tag = typeof raw[0] === 'string' ? raw[0] : '';
      if (tag && DEVALUE_WRAPPER_TAGS.has(tag)) {
        result = isSlotIndex(raw[1]) ? derefSlot(raw[1], depth + 1) : null;
      } else if (tag && DEVALUE_EMPTY_TAGS.has(tag)) {
        result = null;
      } else if (tag && DEVALUE_STRING_TAGS.has(tag)) {
        result = typeof raw[1] === 'string' ? raw[1] : isSlotIndex(raw[1]) ? derefSlot(raw[1], depth + 1) : null;
      } else if (tag === 'Set') {
        const items: unknown[] = [];
        for (const el of raw.slice(1, 251)) {
          if (allocatedNodes >= maxNodes) break;
          items.push(isSlotIndex(el) ? derefSlot(el, depth + 1) : el);
        }
        result = items;
      } else if (tag === 'Map') {
        const obj: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
        for (let i = 1; i + 1 < raw.length && i < 201; i += 2) {
          if (allocatedNodes >= maxNodes) break;
          const kVal = isSlotIndex(raw[i]) ? derefSlot(raw[i] as number, depth + 1) : raw[i];
          const kStr = typeof kVal === 'string' || typeof kVal === 'number' ? String(kVal) : '';
          if (!kStr || UNSAFE_OBJECT_KEYS.has(kStr)) continue;
          obj[kStr] = isSlotIndex(raw[i + 1]) ? derefSlot(raw[i + 1] as number, depth + 1) : raw[i + 1];
        }
        result = obj;
      } else {
        const outArr: unknown[] = [];
        const allIndices = raw.length > 0 && raw.every((x) => typeof x === 'number' && Number.isInteger(x) && x >= -8 && x < table.length);
        for (const el of raw.slice(0, 300)) {
          if (allocatedNodes >= maxNodes) break;
          if (allIndices) {
            outArr.push(isSlotIndex(el) ? derefSlot(el, depth + 1) : null);
          } else {
            outArr.push(el);
          }
        }
        result = outArr;
      }
    } else {
      const outObj: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const entries = Object.entries(raw as Record<string, unknown>);
      for (let i = 0; i < Math.min(200, entries.length); i++) {
        if (allocatedNodes >= maxNodes) break;
        const [k, v] = entries[i]!;
        if (UNSAFE_OBJECT_KEYS.has(k) || SKIP_WALK_KEYS.has(k.toLowerCase())) continue;
        if (isSlotIndex(v)) {
          outObj[k] = derefSlot(v, depth + 1);
        } else if (typeof v === 'number' && v < 0) {
          // devalue negative sentinels (-1 = undefined, -2 = NaN, etc.)
          continue;
        } else {
          outObj[k] = v;
        }
      }
      result = outObj;
    }

    activeStack.delete(idx);
    memo.set(idx, result);
    return result;
  };

  return derefSlot(0, 0);
}

function readCaseInsensitiveScalar(obj: Record<string, unknown>, candidateKeys: readonly string[]): string {
  for (const key of candidateKeys) {
    if (key in obj) {
      const s = extractNestedScalar(obj[key]);
      if (s) return s;
    }
  }
  const entries = Object.entries(obj);
  for (const want of candidateKeys) {
    const wantLower = want.toLowerCase();
    for (const [k, v] of entries) {
      if (k.toLowerCase() === wantLower) {
        const s = extractNestedScalar(v);
        if (s) return s;
      }
    }
  }
  return '';
}

function extractNestedScalar(val: unknown): string {
  if (typeof val === 'string') return val.trim();
  if (typeof val === 'number' && Number.isFinite(val)) return String(val);
  if (val && typeof val === 'object' && !Array.isArray(val)) {
    const o = val as Record<string, unknown>;
    for (const sub of ['rendered', 'name', 'title', 'label', 'text', 'value', 'url', 'href', 'slug']) {
      if (typeof o[sub] === 'string' && (o[sub] as string).trim()) {
        return (o[sub] as string).trim();
      }
      if (typeof o[sub] === 'number' && Number.isFinite(o[sub] as number)) {
        return String(o[sub]);
      }
    }
  }
  return '';
}

function resolveCandidateRecordUrl(rawVal: string, baseUrl?: string): string | undefined {
  if (!rawVal) return undefined;
  const trimmed = stripInvisibleSchemaChars(rawVal).trim();
  if (!trimmed || /^(?:javascript|vbscript|data|file|blob|mailto|tel|#)/i.test(trimmed)) return undefined;
  if (/^https:\/\//i.test(trimmed)) {
    return sanitizeSchemaHttpsUrl(trimmed, baseUrl);
  }
  if (trimmed.startsWith('/') && !trimmed.startsWith('//') && baseUrl) {
    return sanitizeSchemaHttpsUrl(trimmed, baseUrl);
  }
  return undefined;
}

function unwrapRelayNode(item: unknown): Record<string, unknown> | null {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
  const obj = item as Record<string, unknown>;
  if (
    obj.node &&
    typeof obj.node === 'object' &&
    !Array.isArray(obj.node) &&
    Object.keys(obj).length <= 3
  ) {
    return obj.node as Record<string, unknown>;
  }
  return obj;
}

interface ScoredRecordCandidate {
  score: number;
  items: Array<Record<string, unknown>>;
  parentObj: Record<string, unknown> | null;
  keyHint: string;
}

/**
 * Walks an arbitrary JSON state or XHR payload tree (`maxVisited = 2_500`, `maxDepth = 12`) to extract
 * the highest-confidence homogeneous data record array (`3..500` items), rejecting nav/menu chrome.
 */
export function distillStructuredRecordsFromJsonTree(
  root: unknown,
  baseUrl?: string,
): {
  records: Array<Record<string, unknown>>;
  markdown: string;
  returned: number;
  total?: number;
  truncated?: boolean;
  nextCursor?: string;
} | null {
  if (!root || typeof root !== 'object') return null;

  let visited = 0;
  let best: ScoredRecordCandidate | null = null;

  const evaluateArray = (arr: unknown[], parentObj: Record<string, unknown> | null, keyHint: string) => {
    if (arr.length < 3 || arr.length > 500) return;
    if (NAV_CONTAINER_KEY_RE.test(keyHint)) return;

    const sampleCount = Math.min(25, arr.length);
    const unwrappedSample: Array<Record<string, unknown>> = [];
    for (let i = 0; i < sampleCount; i++) {
      const u = unwrapRelayNode(arr[i]);
      if (u) unwrappedSample.push(u);
    }
    if (unwrappedSample.length < Math.ceil(sampleCount * 0.8)) return;

    let validTitleCount = 0;
    let urlCount = 0;
    let richMetaCount = 0;
    let totalTitleLen = 0;
    let maxKeysSeen = 0;

    for (const item of unwrappedSample) {
      const keys = Object.keys(item).filter((k) => !UNSAFE_OBJECT_KEYS.has(k));
      if (keys.length > maxKeysSeen) maxKeysSeen = keys.length;
      if (keys.length < 2) continue;

      const rawTitle = readCaseInsensitiveScalar(item, RECORD_TITLE_KEYS);
      const cleanTitle = sanitizeSchemaPlainField(rawTitle, 240);
      if (
        cleanTitle.length >= 2 &&
        cleanTitle.length <= 220 &&
        !/^https?:\/\//i.test(cleanTitle) &&
        !/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(cleanTitle)
      ) {
        validTitleCount++;
        totalTitleLen += cleanTitle.length;
      }

      const rawUrl = readCaseInsensitiveScalar(item, RECORD_URL_KEYS);
      if (rawUrl && (rawUrl.startsWith('https://') || rawUrl.startsWith('/') || /^[a-z0-9][a-z0-9/_-]{2,120}$/i.test(rawUrl))) {
        urlCount++;
      }

      const rawMeta = readCaseInsensitiveScalar(item, RECORD_META_KEYS);
      if (rawMeta && rawMeta !== rawTitle) {
        richMetaCount++;
      }
    }

    const titleRatio = validTitleCount / unwrappedSample.length;
    const anchorOrMetaRatio = Math.max(urlCount, richMetaCount) / unwrappedSample.length;
    if (titleRatio < 0.8 || anchorOrMetaRatio < 0.6) return;

    const avgTitleLen = validTitleCount > 0 ? totalTitleLen / validTitleCount : 0;
    // Anti-Nav-Menu Guard: reject short `{ label, href }` link lists (`Home`, `Pricing`, `Docs`, `Blog`) with zero metadata!
    if (arr.length <= 10 && richMetaCount === 0 && (maxKeysSeen <= 3 || avgTitleLen < 22)) {
      return;
    }
    if (richMetaCount === 0 && avgTitleLen < 14) {
      return;
    }

    const bonus =
      /^(?:items|results|records|jobs|postings|posts|articles|products|Hits|hits|nodes|edges|entries|listings|packages|models|datasets|events|questions|threads|topics|rows)$/i.test(
        keyHint,
      )
        ? 25
        : 0;
    const score = Math.min(arr.length, 100) * 2 + richMetaCount * 4 + urlCount * 2 + bonus;
    if (!best || score > best.score) {
      const allUnwrapped: Array<Record<string, unknown>> = [];
      for (const el of arr.slice(0, 250)) {
        const u = unwrapRelayNode(el);
        if (u) allUnwrapped.push(u);
      }
      best = { score, items: allUnwrapped, parentObj, keyHint };
    }
  };

  const walk = (node: unknown, parentObj: Record<string, unknown> | null, keyHint: string, depth: number) => {
    if (!node || typeof node !== 'object' || depth > 12 || visited > 2_500) return;
    visited++;

    if (Array.isArray(node)) {
      evaluateArray(node, parentObj, keyHint);
      for (const el of node.slice(0, 30)) {
        if (el && typeof el === 'object') walk(el, null, keyHint, depth + 1);
      }
      return;
    }

    const rec = node as Record<string, unknown>;
    for (const [k, v] of Object.entries(rec)) {
      if (UNSAFE_OBJECT_KEYS.has(k) || SKIP_WALK_KEYS.has(k.toLowerCase())) continue;
      if (v && typeof v === 'object') {
        walk(v, rec, k, depth + 1);
      }
    }
  };

  walk(root, null, '', 0);
  if (!best) return null;

  const chosen: ScoredRecordCandidate = best;
  const records: Array<Record<string, unknown>> = [];
  const tableRows: Array<Array<string>> = [];
  let hasLocationCol = false;
  let hasPriceOrDateCol = false;
  let hasSummaryCol = false;

  for (const item of chosen.items) {
    const title = sanitizeSchemaPlainField(readCaseInsensitiveScalar(item, RECORD_TITLE_KEYS), 240);
    if (!title) continue;

    const rawUrlCandidate = readCaseInsensitiveScalar(item, RECORD_URL_KEYS);
    let url = resolveCandidateRecordUrl(rawUrlCandidate, baseUrl);
    if (!url && rawUrlCandidate && /^[a-z0-9][a-z0-9/_.-]{1,120}$/i.test(rawUrlCandidate) && rawUrlCandidate.includes('/') && baseUrl) {
      url = resolveCandidateRecordUrl(`/${rawUrlCandidate}`, baseUrl);
    }

    const location = sanitizeSchemaPlainField(
      readCaseInsensitiveScalar(item, ['location', 'locationName', 'city', 'workplaceType']),
      140,
    );
    const price = sanitizeSchemaPlainField(
      readCaseInsensitiveScalar(item, ['price', 'salary', 'compensation']),
      80,
    );
    const date = sanitizeSchemaPlainField(
      readCaseInsensitiveScalar(item, ['publishedAt', 'published_at', 'date', 'postedAt', 'createdAt', 'created_at', 'updatedAt']),
      64,
    );
    const companyOrAuthor = sanitizeSchemaPlainField(
      readCaseInsensitiveScalar(item, ['company', 'organization', 'author', 'department', 'category']),
      120,
    );
    const summaryRaw = sanitizeSchemaPlainField(
      readCaseInsensitiveScalar(item, ['summary', 'description', 'excerpt', 'snippet', 'answer']),
      320,
    );
    const summary = summaryRaw !== title ? summaryRaw : '';
    const idVal = sanitizeSchemaPlainField(readCaseInsensitiveScalar(item, ['id', 'jobId', 'reqId', 'sku', 'version']), 80);

    const outRec: Record<string, unknown> = {
      title,
      ...(url ? { url } : {}),
      ...(companyOrAuthor ? { meta: companyOrAuthor } : {}),
      ...(location ? { location } : {}),
      ...(price ? { price } : {}),
      ...(date ? { date } : {}),
      ...(summary ? { summary } : {}),
      ...(idVal ? { id: idVal } : {}),
    };
    records.push(outRec);

    if (location) hasLocationCol = true;
    if (price || date || companyOrAuthor) hasPriceOrDateCol = true;
    if (summary) hasSummaryCol = true;

    const escapedTitle = title.replace(/\\/g, '\\\\').replace(/\[/g, '\\[').replace(/\]/g, '\\]');
    const safeLink = url
      ? `[${escapedTitle}](${url.replace(/\(/g, '%28').replace(/\)/g, '%29')})`
      : escapedTitle;
    const infoBits = [companyOrAuthor, price, date].filter(Boolean).join(' · ');
    tableRows.push([safeLink, location || '-', infoBits || '-', summary || '-']);
  }

  if (records.length < 3) return null;

  // Extract optional pagination hints from enclosing parent object
  let total: number | undefined;
  let nextCursor: string | undefined;
  let truncated: boolean | undefined;
  if (chosen.parentObj) {
    const p = chosen.parentObj;
    const pagSub =
      (p.pagination && typeof p.pagination === 'object' && !Array.isArray(p.pagination)
        ? (p.pagination as Record<string, unknown>)
        : p.pageInfo && typeof p.pageInfo === 'object' && !Array.isArray(p.pageInfo)
          ? (p.pageInfo as Record<string, unknown>)
          : p.meta && typeof p.meta === 'object' && !Array.isArray(p.meta)
            ? (p.meta as Record<string, unknown>)
            : null);

    for (const src of [p, pagSub]) {
      if (!src) continue;
      for (const tk of ['total', 'totalCount', 'total_count', 'totalHits', 'nbHits', 'totalResults', 'count', 'found']) {
        const tv = Number(src[tk]);
        if (Number.isFinite(tv) && tv >= records.length && tv <= 10_000_000) {
          total = Math.floor(tv);
          break;
        }
      }
      for (const ck of ['nextCursor', 'next_cursor', 'endCursor', 'nextPageToken']) {
        if (typeof src[ck] === 'string' && (src[ck] as string).trim().length > 0 && (src[ck] as string).length <= 256) {
          nextCursor = sanitizeSchemaPlainField(src[ck], 256);
          break;
        }
      }
      if (src.hasNextPage === true || src.hasMore === true) {
        truncated = true;
      }
    }
    if (total !== undefined && total > records.length) {
      truncated = true;
    }
  }

  const colIndices: number[] = [0];
  const headers: string[] = ['Item'];
  if (hasLocationCol) {
    colIndices.push(1);
    headers.push('Location');
  }
  if (hasPriceOrDateCol) {
    colIndices.push(2);
    headers.push('Info');
  }
  if (hasSummaryCol) {
    colIndices.push(3);
    headers.push('Summary');
  }
  if (colIndices.length === 1) {
    // At least show Info or Summary if no secondary column fired
    headers.push('Details');
    colIndices.push(3);
  }
  const projectedRows = tableRows.map((row) => colIndices.map((idx) => row[idx] ?? '-'));
  let md = formatGfmTable(headers, projectedRows);
  if (truncated) {
    const totalNote = total !== undefined ? `${records.length} of ${total}` : `${records.length}`;
    md += `\n\n*Showing ${totalNote} records${nextCursor ? ` (nextCursor: \`${nextCursor}\`)` : ' (list truncated)'}.*`;
  }

  return {
    records,
    markdown: md,
    returned: records.length,
    ...(total !== undefined ? { total } : {}),
    ...(truncated !== undefined ? { truncated } : {}),
    ...(nextCursor ? { nextCursor } : {}),
  };
}

/**
 * Linear O(N) Next.js App Router RSC Flight (`self.__next_f.push([1, "..."])`) extractor.
 * Zero backtracking regexes — safe on 2 MiB adversarial inputs.
 */
export function extractNextRscFlightLinear(
  boundedHtml: string,
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
): HydratedFrameworkStateResult | null {
  if (!boundedHtml.includes('__next_f.push')) return null;

  const rscChunks: string[] = [];
  let totalRscChars = 0;
  let searchPos = 0;
  const marker = '__next_f.push(';

  while (searchPos < boundedHtml.length && rscChunks.length < 300 && totalRscChars < 1_500_000) {
    const idx = boundedHtml.indexOf(marker, searchPos);
    if (idx < 0) break;
    let p = idx + marker.length;
    while (p < boundedHtml.length && (boundedHtml.charCodeAt(p) <= 32 || boundedHtml.charCodeAt(p) === 91 /* '[' */)) p++;
    // Expect chunk tag `0`, `1`, or `2` followed by `,`
    if (p < boundedHtml.length && boundedHtml.charCodeAt(p) >= 48 && boundedHtml.charCodeAt(p) <= 50) {
      p++;
      while (p < boundedHtml.length && boundedHtml.charCodeAt(p) <= 32) p++;
      if (p < boundedHtml.length && boundedHtml.charCodeAt(p) === 44 /* ',' */) {
        p++;
        while (p < boundedHtml.length && boundedHtml.charCodeAt(p) <= 32) p++;
        if (p < boundedHtml.length && boundedHtml.charCodeAt(p) === 34 /* '"' */) {
          const lit = scanJsonStringLiteralAt(boundedHtml, p, 1_000_000);
          if (lit) {
            searchPos = lit.endIndex;
            try {
              const decoded = JSON.parse(lit.rawLiteral) as unknown;
              if (typeof decoded === 'string' && decoded.length > 0) {
                rscChunks.push(decoded);
                totalRscChars += decoded.length;
              }
            } catch {
              // ignore malformed RSC string chunk
            }
            continue;
          }
        }
      }
    }
    searchPos = idx + marker.length;
  }

  if (rscChunks.length === 0) return null;

  let rscTitle = '';
  replacePairedHtmlElementsLinear(
    boundedHtml.slice(0, 65_536),
    ['title'],
    (_f, _t, _a, inner) => {
      if (!rscTitle) rscTitle = sanitizeSchemaPlainField(inner, 300);
      return '';
    },
    { maxChars: 65_536, maxInnerChars: 4096 },
  );

  const combinedRsc = rscChunks.join('');
  const rscBlocks: string[] = [];
  const seenRsc = new Set<string>();
  const parsedFlightObjects: unknown[] = [];

  const addProseCandidate = (rawStr: string, minWords: number) => {
    const pre = stripInvisibleSchemaChars(rawStr).trim();
    if (pre.length < 80 || !/\s/.test(pre.slice(0, 80)) || /^(?:https?:\/\/|\/_next\/)/i.test(pre)) return;
    const hasHtml = /<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|a)\b/i.test(pre);
    let converted = hasHtml ? htmlToMd(pre, baseUrl).markdown.trim() : pre;
    converted = neutralizeAllUnsafeMarkdownLinksLinear(stripInvisibleSchemaChars(converted));
    converted = converted.replace(/<(?=[ \t]*(?:javascript|vbscript|data|file|blob|\/?[a-zA-Z!]))/gi, '&lt;');
    const wc = countWords(converted);
    if (wc >= minWords && !seenRsc.has(converted)) {
      seenRsc.add(converted);
      rscBlocks.push(converted);
    }
  };

  // Strictly single-pass O(N) escape-aware character state machine over `combinedRsc` (`HIGH-1` & `HIGH-3`):
  // visits each UTF-16 code unit at most once (zero `indexOf` re-scanning on `\"` or unclosed/oversized strings!),
  // while also collecting inner JSON-decoded Flight string leaves for `checkPromptInjection: true`.
  const piDecodedChunks: string[] = [];
  let piDecodedChars = 0;
  let sawRscUnicodeTag = hasRawOrEncodedUnicodeTagLinear(combinedRsc);
  const recordPiLeaf = (s: string) => {
    const dec = s.includes('&') ? decodeBasicEntities(s) : s;
    if (!sawRscUnicodeTag && hasRawOrEncodedUnicodeTagLinear(dec)) {
      sawRscUnicodeTag = true;
    }
    if (piDecodedChars < 1_048_576 && dec) {
      const slice = dec.slice(0, Math.max(0, 1_048_576 - piDecodedChars));
      piDecodedChunks.push(slice);
      piDecodedChars += slice.length;
    }
  };

  let stringLiteralsDecoded = 0;
  let inRscStr = false;
  let rscStrStart = -1;
  for (let i = 0; i < combinedRsc.length; i++) {
    const ch = combinedRsc.charCodeAt(i);
    if (!inRscStr) {
      if (ch === 92 /* '\\' */) {
        i++; // skip escaped character outside string literal (`\"` is never an opening quote!)
        continue;
      }
      if (ch === 34 /* '"' */) {
        inRscStr = true;
        rscStrStart = i;
      }
      continue;
    }
    if (ch === 92 /* '\\' */) {
      i++; // skip escaped character inside string literal
      continue;
    }
    if (ch === 34 /* '"' */) {
      inRscStr = false;
      const litLen = i + 1 - rscStrStart;
      // Only decode candidate prose/escaped/entity literals — never burn budget on short JSON keys (`"id"`, `NEW-HIGH-1`)!
      if (litLen >= 10 && litLen <= 250_002 && stringLiteralsDecoded < 30_000) {
        const rawLiteral = combinedRsc.slice(rscStrStart, i + 1);
        if (litLen >= 82 || rawLiteral.includes('\\') || rawLiteral.includes('&')) {
          stringLiteralsDecoded++;
          try {
            const unescaped = JSON.parse(rawLiteral) as unknown;
            if (typeof unescaped === 'string') {
              recordPiLeaf(unescaped);
              if (unescaped.length >= 80) {
                addProseCandidate(unescaped, 25);
              }
            }
          } catch {
            // ignore non-JSON string token
          }
        }
      }
    }
  }

  // Line-by-line scan for `T<hex>,` raw prose blocks and structured JSON Flight payloads (`<id>:[...]` / `<id>:{...}`)
  let lineStart = 0;
  let linesScanned = 0;
  while (lineStart < combinedRsc.length && linesScanned < 3_000) {
    const nl = combinedRsc.indexOf('\n', lineStart);
    const lineEnd = nl >= 0 ? nl : combinedRsc.length;
    const line = combinedRsc.slice(lineStart, lineEnd).trim();
    lineStart = nl >= 0 ? nl + 1 : combinedRsc.length;
    linesScanned++;
    if (!line) continue;

    const colonIdx = line.indexOf(':');
    const payload = colonIdx > 0 && colonIdx <= 12 ? line.slice(colonIdx + 1) : line;
    if (payload.startsWith('T') || payload.startsWith('t')) {
      const commaIdx = payload.indexOf(',');
      if (commaIdx > 1 && commaIdx <= 10) {
        const tBody = payload.slice(commaIdx + 1);
        recordPiLeaf(tBody);
        addProseCandidate(tBody, 30);
        continue;
      }
    }
    if (
      parsedFlightObjects.length < 60 &&
      payload.length >= 40 &&
      payload.length <= 512_000 &&
      (payload.charCodeAt(0) === 91 /* '[' */ || payload.charCodeAt(0) === 123 /* '{' */)
    ) {
      try {
        const parsedLineObj = JSON.parse(payload) as unknown;
        parsedFlightObjects.push(parsedLineObj);
      } catch {
        // ignore partial flight line
      }
    }
  }

  // Walk parsed Flight JSON objects to ensure nested/escaped string leaves are decoded for PI inspection (`HIGH-3` & `NEW-HIGH-1`).
  let flightPiVisited = 0;
  const walkFlightPi = (val: unknown, depth: number) => {
    if (val === null || val === undefined || depth > 18 || flightPiVisited > 100_000) return;
    if (typeof val === 'string') {
      if (!val) return;
      flightPiVisited++;
      recordPiLeaf(val);
      return;
    }
    if (Array.isArray(val)) {
      if (val.length === 0) return;
      flightPiVisited++;
      for (const el of val) {
        if (flightPiVisited > 100_000) break;
        if (typeof el === 'string' || (el !== null && typeof el === 'object')) {
          walkFlightPi(el, depth + 1);
        }
      }
      return;
    }
    if (typeof val === 'object') {
      const entries = Object.entries(val as Record<string, unknown>);
      if (entries.length === 0) return;
      flightPiVisited++;
      for (const [k, v] of entries) {
        if (UNSAFE_OBJECT_KEYS.has(k) || SKIP_WALK_KEYS.has(k.toLowerCase())) continue;
        if (flightPiVisited > 100_000) break;
        if (typeof v === 'string' || (v !== null && typeof v === 'object')) {
          walkFlightPi(v, depth + 1);
        }
      }
    }
  };
  for (const fo of parsedFlightObjects) walkFlightPi(fo, 0);

  const distilledRecords =
    parsedFlightObjects.length > 0
      ? distillStructuredRecordsFromJsonTree(parsedFlightObjects, baseUrl)
      : null;

  const proseJoined = rscBlocks.join('\n\n').trim();
  const proseWords = countWords(proseJoined);

  if (proseWords < 25 && !distilledRecords) return null;

  const bodyParts = [
    ...(proseWords >= 25 ? [proseJoined] : []),
    ...(distilledRecords ? [distilledRecords.markdown] : []),
  ];
  const combinedBody = bodyParts.join('\n\n').trim();
  const finalMd = rscTitle && !combinedBody.startsWith('# ') ? `# ${rscTitle}\n\n${combinedBody}` : combinedBody;
  const piCombined = [
    combinedRsc.slice(0, 524_288),
    ...piDecodedChunks,
    ...(sawRscUnicodeTag ? ['\u{E0069}'] : []),
  ].join('\n');

  return {
    ...(rscTitle ? { title: rscTitle } : {}),
    markdown: finalMd,
    framework: 'nextjs-rsc',
    ...(distilledRecords
      ? {
          records: distilledRecords.records,
          returned: distilledRecords.returned,
          ...(distilledRecords.total !== undefined ? { total: distilledRecords.total } : {}),
          ...(distilledRecords.truncated !== undefined ? { truncated: distilledRecords.truncated } : {}),
          ...(distilledRecords.nextCursor ? { nextCursor: distilledRecords.nextCursor } : {}),
        }
      : {}),
    rawDecodedStringsForPiCheck: piCombined,
  };
}

/**
 * Walks an already-parsed framework state object (Next.js, Nuxt, Remix, Angular, Wix, Squarespace, Substack, Gatsby)
 * to extract rich prose sections AND/OR homogeneous `records[]`.
 */
export function extractFromParsedStateTree(
  parsed: unknown,
  framework: string,
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
  fallbackTitle?: string,
  rawSourceHasUnicodeTag = false,
): HydratedFrameworkStateResult | null {
  if (!parsed || typeof parsed !== 'object') return null;

  let rootTarget: unknown = parsed;
  if (framework === 'nuxt' && isNuxtDevalueFlatArray(parsed)) {
    rootTarget = dereferenceNuxtDevaluePayload(parsed);
  } else if (
    framework === 'nextjs' &&
    !Array.isArray(parsed) &&
    (parsed as { props?: { pageProps?: unknown } }).props?.pageProps
  ) {
    rootTarget = (parsed as { props: { pageProps: unknown } }).props.pageProps;
  }
  if (!rootTarget || typeof rootTarget !== 'object') return null;

  let bestTitle = fallbackTitle ? sanitizeSchemaPlainField(fallbackTitle, 200) : '';
  let bestDescription = '';
  const richSections: string[] = [];
  const seenBlocks = new Set<string>();
  const rawPiStrings: string[] = [];
  let rawPiLen = 0;
  let sawStateUnicodeTag = rawSourceHasUnicodeTag;
  let piVisited = 0;
  const collectStatePiLeaves = (node: unknown, depth: number) => {
    if (node === null || node === undefined || depth > 20 || piVisited > 100_000) return;
    if (typeof node === 'string') {
      const trimmed = node.trim();
      if (!trimmed) return;
      piVisited++;
      const decodedForPi = trimmed.includes('&') ? decodeBasicEntities(trimmed) : trimmed;
      if (!sawStateUnicodeTag && hasRawOrEncodedUnicodeTagLinear(decodedForPi)) {
        sawStateUnicodeTag = true;
      }
      if (rawPiLen < 1_048_576) {
        const chunk = decodedForPi.slice(0, Math.max(0, 1_048_576 - rawPiLen));
        rawPiStrings.push(chunk);
        rawPiLen += chunk.length;
      }
      return;
    }
    if (Array.isArray(node)) {
      if (node.length === 0) return; // Never count primitive/empty noise against PI budget (`NEW-HIGH-1`)
      piVisited++;
      for (const item of node) {
        if (piVisited > 100_000) break;
        if (typeof item === 'string' || (item !== null && typeof item === 'object')) {
          collectStatePiLeaves(item, depth + 1);
        }
      }
      return;
    }
    if (typeof node === 'object') {
      const entries = Object.entries(node as Record<string, unknown>);
      if (entries.length === 0) return;
      piVisited++;
      for (const [k, v] of entries) {
        if (UNSAFE_OBJECT_KEYS.has(k) || SKIP_WALK_KEYS.has(k.toLowerCase())) continue;
        if (piVisited > 100_000) break;
        if (typeof v === 'string' || (v !== null && typeof v === 'object')) {
          collectStatePiLeaves(v, depth + 1);
        }
      }
    }
  };
  collectStatePiLeaves(rootTarget, 0);
  if (sawStateUnicodeTag) {
    rawPiStrings.push('\u{E0069}');
  }

  let visited = 0;

  const walkProse = (node: unknown, depth: number, keyHint: string) => {
    if (!node || depth > 11 || visited > 2_000) return;
    visited++;

    if (typeof node === 'string') {
      const rawTrimmed = node.trim();
      if (!rawTrimmed) return;

      const lowerKey = keyHint.toLowerCase();
      if (
        !bestTitle &&
        (lowerKey === 'title' || lowerKey === 'jobtitle' || lowerKey === 'headline' || lowerKey === 'pagetitle') &&
        rawTrimmed.length >= 4 &&
        rawTrimmed.length <= 180 &&
        !/<[a-z]/i.test(rawTrimmed)
      ) {
        bestTitle = sanitizeSchemaPlainField(rawTrimmed, 180);
        return;
      }
      if (
        !bestDescription &&
        (lowerKey === 'description' || lowerKey === 'shortdescription' || lowerKey === 'excerpt' || lowerKey === 'subtitle') &&
        rawTrimmed.length >= 40 &&
        rawTrimmed.length <= 400 &&
        !/<[a-z]/i.test(rawTrimmed)
      ) {
        bestDescription = sanitizeSchemaPlainField(rawTrimmed, 400);
      }

      const isRichKey =
        RICH_PROSE_KEYS.has(lowerKey) || /description|content|markdown|body|overview|article|post/i.test(lowerKey);
      if (!isRichKey || rawTrimmed.length < 120) return;
      if (!/\s/.test(rawTrimmed.slice(0, 100))) return;

      const preClean = stripInvisibleSchemaChars(rawTrimmed);
      const hasHtml = /<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|a)\b/i.test(preClean);
      let converted = hasHtml ? htmlToMd(preClean, baseUrl).markdown.trim() : preClean;
      converted = stripInvisibleSchemaChars(converted.includes('&') && !hasHtml ? decodeBasicEntities(converted) : converted);
      converted = neutralizeAllUnsafeMarkdownLinksLinear(converted);
      converted = converted.replace(/<(?=[ \t]*(?:javascript|vbscript|data|file|blob|\/?[a-zA-Z!]))/gi, '&lt;');

      const wc = countWords(converted);
      if (wc >= 25 && !seenBlocks.has(converted)) {
        seenBlocks.add(converted);
        richSections.push(converted);
      }
      return;
    }

    if (Array.isArray(node)) {
      for (const item of node.slice(0, 80)) {
        walkProse(item, depth + 1, keyHint);
      }
      return;
    }

    if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (UNSAFE_OBJECT_KEYS.has(k) || SKIP_WALK_KEYS.has(k.toLowerCase())) continue;
        walkProse(v, depth + 1, k);
      }
    }
  };

  walkProse(rootTarget, 0, '');
  const distilledRecords = distillStructuredRecordsFromJsonTree(rootTarget, baseUrl);

  const proseJoined = richSections.join('\n\n').trim();
  const proseWords = countWords(proseJoined);

  if (proseWords < 35 && !distilledRecords) return null;

  const sections: string[] = [];
  if (proseWords >= 35) sections.push(proseJoined);
  if (distilledRecords) sections.push(distilledRecords.markdown);
  const bodyJoined = sections.join('\n\n').trim();
  const finalMd = bestTitle && !/^#\s+/.test(bodyJoined) ? `# ${bestTitle}\n\n${bodyJoined}` : bodyJoined;

  return {
    ...(bestTitle ? { title: bestTitle } : {}),
    ...(bestDescription ? { description: bestDescription } : {}),
    markdown: finalMd,
    framework,
    ...(distilledRecords
      ? {
          records: distilledRecords.records,
          returned: distilledRecords.returned,
          ...(distilledRecords.total !== undefined ? { total: distilledRecords.total } : {}),
          ...(distilledRecords.truncated !== undefined ? { truncated: distilledRecords.truncated } : {}),
          ...(distilledRecords.nextCursor ? { nextCursor: distilledRecords.nextCursor } : {}),
          structured: {
            source: `hydration:${framework}`,
            returned: distilledRecords.returned,
            ...(distilledRecords.total !== undefined ? { total: distilledRecords.total } : {}),
          },
        }
      : {}),
    ...(rawPiStrings.length > 0 ? { rawDecodedStringsForPiCheck: rawPiStrings.join('\n') } : {}),
  };
}

/**
 * `R6` v2: Recovers rich prose AND structured object arrays (`records[]`) from embedded SSR/SPA state scripts
 * (`__NEXT_DATA__`, `__next_f.push`, `__NUXT_DATA__` including Nuxt 3 `devalue`, `__remixContext`,
 * `__APOLLO_STATE__`, `#ng-state`, `#wix-viewer-model`, `Static.SQUARESPACE_CONTEXT`, `window._preloads`)
 * in linear O(N) time before falling back to headless Chromium!
 */
export function recoverSsrHydrationContent(
  rawHtml: string,
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
): HydratedFrameworkStateResult | null {
  if (!rawHtml || !rawHtml.includes('<script')) return null;
  const boundedHtml = rawHtml.length > MAX_HTML_SCAN_CHARS ? rawHtml.slice(0, MAX_HTML_SCAN_CHARS) : rawHtml;

  let rawJson = '';
  let framework = '';

  replaceHtmlTagBlocksLinear(
    boundedHtml,
    'script',
    (_full, attrStr, inner) => {
      if (rawJson) return '';
      const trimmedInner = inner.trim();
      if (!trimmedInner) return '';

      if (/\bid\s*=\s*["']__NEXT_DATA__["']/i.test(attrStr)) {
        rawJson = trimmedInner;
        framework = 'nextjs';
      } else if (/\bid\s*=\s*["']__NUXT_DATA__["']/i.test(attrStr)) {
        rawJson = trimmedInner;
        framework = 'nuxt';
      } else if (/\bid\s*=\s*["']ng-state["']/i.test(attrStr)) {
        rawJson = trimmedInner;
        framework = 'angular';
      } else if (/\bid\s*=\s*["']wix-viewer-model["']/i.test(attrStr)) {
        rawJson = trimmedInner;
        framework = 'wix';
      } else if (trimmedInner.includes('__remixContext')) {
        const idx = trimmedInner.indexOf('__remixContext');
        const balanced = extractBalancedJsonAtLinear(trimmedInner, idx + '__remixContext'.length);
        if (balanced) {
          rawJson = balanced;
          framework = 'remix';
        }
      } else if (trimmedInner.includes('__APOLLO_STATE__')) {
        const idx = trimmedInner.indexOf('__APOLLO_STATE__');
        const balanced = extractBalancedJsonAtLinear(trimmedInner, idx + '__APOLLO_STATE__'.length);
        if (balanced) {
          rawJson = balanced;
          framework = 'apollo';
        }
      } else if (trimmedInner.includes('SQUARESPACE_CONTEXT')) {
        const idx = trimmedInner.indexOf('SQUARESPACE_CONTEXT');
        const balanced = extractBalancedJsonAtLinear(trimmedInner, idx + 'SQUARESPACE_CONTEXT'.length);
        if (balanced) {
          rawJson = balanced;
          framework = 'squarespace';
        }
      } else if (trimmedInner.includes('window._preloads')) {
        const idx = trimmedInner.indexOf('window._preloads');
        const parseCallIdx = trimmedInner.indexOf('JSON.parse(', idx);
        if (parseCallIdx >= 0) {
          const qStart = trimmedInner.indexOf('"', parseCallIdx + 10);
          const lit = qStart >= 0 ? scanJsonStringLiteralAt(trimmedInner, qStart, 1_500_000) : null;
          if (lit) {
            try {
              const innerJsonStr = JSON.parse(lit.rawLiteral) as unknown;
              if (typeof innerJsonStr === 'string' && innerJsonStr.trim()) {
                rawJson = innerJsonStr.trim();
                framework = 'substack';
              }
            } catch {
              // ignore malformed Substack preload literal
            }
          }
        }
      }
      return '';
    },
    MAX_HTML_SCAN_CHARS,
  );

  if (!rawJson && boundedHtml.includes('__next_f.push')) {
    return extractNextRscFlightLinear(boundedHtml, baseUrl, htmlToMd);
  }

  if (!rawJson || rawJson.length > 2 * 1024 * 1024) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return null;
  }

  let docTitle = '';
  replacePairedHtmlElementsLinear(
    boundedHtml.slice(0, 65_536),
    ['title'],
    (_f, _t, _a, inner) => {
      if (!docTitle) docTitle = stripHtmlTagsQuoteAwareLinear(inner, ' ', 4096).replace(/\s+/g, ' ').trim();
      return '';
    },
    { maxChars: 65_536, maxInnerChars: 4096 },
  );

  const rawHasUnicodeTag = hasRawOrEncodedUnicodeTagLinear(rawJson);
  return extractFromParsedStateTree(parsed, framework, baseUrl, htmlToMd, docTitle || undefined, rawHasUnicodeTag);
}

/**
 * Phase 2 (`v2.7.8`): Distills same-origin `200 OK` `application/json` XHR/Fetch responses captured by
 * Go worker's Chromium CDP renderer (`item.capturedJson[]`) into sanitized `records[]` + `structured` metadata,
 * plus raw decoded strings for `checkPromptInjection: true`.
 */
export function distillCapturedJsonResponses(
  captured: unknown,
  finalUrl: string,
): {
  records?: Array<Record<string, unknown>>;
  markdown?: string;
  structured?: Record<string, unknown>;
  returned?: number;
  total?: number;
  truncated?: boolean;
  nextCursor?: string;
  rawDecodedStringsForPiCheck: string;
} | null {
  if (!Array.isArray(captured) || captured.length === 0) return null;

  let expectedOrigin = '';
  try {
    const u = new URL(finalUrl);
    if (u.protocol !== 'https:') return null;
    expectedOrigin = u.origin;
  } catch {
    return null;
  }

  const piChunks: string[] = [];
  let piBytes = 0;
  let sawCapturedUnicodeTag = false;
  let bestDistilled: ReturnType<typeof distillStructuredRecordsFromJsonTree> = null;
  let bestSourceUrl = '';

  for (const rawEntry of captured.slice(0, 6)) {
    if (!rawEntry || typeof rawEntry !== 'object' || Array.isArray(rawEntry)) continue;
    const entry = rawEntry as Record<string, unknown>;
    const respUrl = typeof entry.url === 'string' ? entry.url.trim() : '';
    const bodyStr = typeof entry.body === 'string' ? entry.body.trim() : '';
    const status = typeof entry.status === 'number' ? entry.status : 200;
    if (!respUrl || !bodyStr || bodyStr.length > 512 * 1024 || status !== 200) continue;

    // Defense-in-depth Hub check: require non-empty `respUrl` and verify it is strictly same-origin https:// as `finalUrl` (`MEDIUM-1`)!
    const valid = sanitizeSchemaHttpsUrl(respUrl);
    if (!valid) continue;
    try {
      if (new URL(valid).origin !== expectedOrigin) continue;
    } catch {
      continue;
    }

    if (!sawCapturedUnicodeTag && hasRawOrEncodedUnicodeTagLinear(bodyStr)) {
      sawCapturedUnicodeTag = true;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(bodyStr);
    } catch {
      continue;
    }

    // Per-entry node budget skipping primitives/empty containers so `captured[0]` noise can never blind `captured[1..5]` (`NEW-HIGH-1`).
    let entryVisited = 0;
    const collectPiLeaves = (val: unknown, depth: number) => {
      if (val === null || val === undefined || depth > 20 || entryVisited > 100_000) return;
      if (typeof val === 'string') {
        if (!val) return;
        entryVisited++;
        const dec = val.includes('&') ? decodeBasicEntities(val) : val;
        if (!sawCapturedUnicodeTag && hasRawOrEncodedUnicodeTagLinear(dec)) {
          sawCapturedUnicodeTag = true;
        }
        if (piBytes < 1_048_576) {
          const slice = dec.slice(0, Math.max(0, 1_048_576 - piBytes));
          if (slice) {
            piChunks.push(slice);
            piBytes += slice.length;
          }
        }
        return;
      }
      if (Array.isArray(val)) {
        if (val.length === 0) return;
        entryVisited++;
        for (const el of val) {
          if (entryVisited > 100_000) break;
          if (typeof el === 'string' || (el !== null && typeof el === 'object')) {
            collectPiLeaves(el, depth + 1);
          }
        }
        return;
      }
      if (typeof val === 'object') {
        const entries = Object.entries(val as Record<string, unknown>);
        if (entries.length === 0) return;
        entryVisited++;
        for (const [k, v] of entries) {
          if (UNSAFE_OBJECT_KEYS.has(k) || SKIP_WALK_KEYS.has(k.toLowerCase())) continue;
          if (entryVisited > 100_000) break;
          if (typeof v === 'string' || (v !== null && typeof v === 'object')) {
            collectPiLeaves(v, depth + 1);
          }
        }
      }
    };
    collectPiLeaves(parsed, 0);

    const cand = distillStructuredRecordsFromJsonTree(parsed, finalUrl);
    if (cand && (!bestDistilled || cand.records.length > bestDistilled.records.length)) {
      bestDistilled = cand;
      bestSourceUrl = valid;
    }
  }

  if (sawCapturedUnicodeTag) {
    piChunks.push('\u{E0069}');
  }
  if (!bestDistilled && piChunks.length === 0) return null;

  return {
    ...(bestDistilled
      ? {
          records: bestDistilled.records,
          markdown: bestDistilled.markdown,
          returned: bestDistilled.returned,
          ...(bestDistilled.total !== undefined ? { total: bestDistilled.total } : {}),
          ...(bestDistilled.truncated !== undefined ? { truncated: bestDistilled.truncated } : {}),
          ...(bestDistilled.nextCursor ? { nextCursor: bestDistilled.nextCursor } : {}),
          structured: {
            source: 'cdp-xhr-json',
            ...(bestSourceUrl ? { endpoint: bestSourceUrl } : {}),
            returned: bestDistilled.returned,
            ...(bestDistilled.total !== undefined ? { total: bestDistilled.total } : {}),
          },
        }
      : {}),
    rawDecodedStringsForPiCheck: piChunks.join('\n'),
  };
}
