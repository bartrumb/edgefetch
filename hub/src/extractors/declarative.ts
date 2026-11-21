/**
 * Shared Go + TypeScript Declarative YAML/JSON Site Adapter Engine (`hub/src/extractors/declarative.ts`).
 *
 * Compiles canonical zero-code YAML manifests in `internal/extract/manifests/<id>.yaml` (shared with
 * `internal/extract/declarative.go` via `//go:embed`) into standard `SiteAdapter` definitions.
 *
 * Security & Complexity Invariants:
 *  - Zero arbitrary code execution (`eval`, `Function`), zero `fetch()` escape, and zero regex backtracking.
 *  - YAML manifests are parsed strictly with `maxAliasCount: 0` (forbidding aliases/billion-laughs bombs).
 *  - URL route matching uses strict character-class byte predicates and bounded segment/query captures.
 *  - Resolved `fetchUrl` targets are strictly validated as public `https://` URLs with URI-encoded parameters.
 */

import { parse as parseYaml } from 'yaml';

import devToManifest from '../../../internal/extract/manifests/dev-to.yaml';
import doiCrossrefManifest from '../../../internal/extract/manifests/doi-crossref.yaml';
import hexPmManifest from '../../../internal/extract/manifests/hex-pm.yaml';
import huggingfaceManifest from '../../../internal/extract/manifests/huggingface.yaml';
import lobstersManifest from '../../../internal/extract/manifests/lobsters.yaml';
import openrouterManifest from '../../../internal/extract/manifests/openrouter.yaml';
import packagistManifest from '../../../internal/extract/manifests/packagist.yaml';
import polymarketManifest from '../../../internal/extract/manifests/polymarket.yaml';
import rubygemsManifest from '../../../internal/extract/manifests/rubygems.yaml';
import usaspendingManifest from '../../../internal/extract/manifests/usaspending.yaml';

import type { AdapterCategory, SiteAdapter, SiteExtractorTwin, TwinFormattedDoc, TwinMatchContext } from './types';
import {
  detectFenceLang,
  formatGfmTable,
  formatUsdCompact,
  formatYamlFrontmatterCard,
  parseJsonValue,
  safeFence,
  stripTagsInline,
} from './utils';

export type DeclarativeCharset =
  | 'alnum'
  | 'alnum_dash'
  | 'slug'
  | 'pkg'
  | 'model_slug'
  | 'doi_rest'
  | 'safe_subpath';

export interface DeclarativeParamSegment {
  param: string;
  charset?: DeclarativeCharset;
  allowValues?: string[];
  reserved?: string[];
  stripSuffix?: string;
  minLen?: number;
  maxLen?: number;
  greedy?: boolean;
}

export type DeclarativeSegmentSpec = string | DeclarativeParamSegment;

export interface DeclarativeQueryParamSpec {
  name: string;
  param: string;
  charset?: DeclarativeCharset;
  minLen?: number;
  maxLen?: number;
}

export interface DeclarativeMatchSpec {
  exactSegments?: boolean;
  pathSegments?: DeclarativeSegmentSpec[];
  queryParams?: DeclarativeQueryParamSpec[];
  defaults?: Record<string, string>;
  anyOf?: DeclarativeMatchSpec[];
}

export interface DeclarativeTwinSpec {
  id?: string;
  fetchUrl: string;
  rawPathParams?: string[];
  kind: 'json' | 'text';
  accept: string;
}

export interface DeclarativeDynamicKeyPath {
  base: string;
  keyVar: string;
  subPath?: string;
}

export interface DeclarativeSubFieldsJoin {
  fields: string[];
  sep: string;
  fallbackField?: string;
}

export type DeclarativeVarFormat =
  | 'trim'
  | 'strip_tags'
  | 'jats_abstract'
  | 'int_comma'
  | 'usd_compact'
  | 'usd_per_million_tokens'
  | 'date_parts'
  | 'bool_map';

export interface DeclarativeVarSpec {
  paths?: string[];
  dynamicKeyPath?: DeclarativeDynamicKeyPath;
  template?: string;
  whenVars?: string[];
  fallbackVar?: string;
  firstNonMatchingKey?: string;
  subField?: string;
  subFieldsJoin?: DeclarativeSubFieldsJoin;
  itemWrap?: string;
  join?: string;
  limit?: number;
  format?: DeclarativeVarFormat;
  trueValue?: string;
  falseValue?: string;
  stripFrontmatter?: boolean;
  trim?: boolean;
  requireHttps?: boolean;
  sliceMax?: number;
  default?: string;
  fallbackTemplate?: string;
}

export interface DeclarativeBulletSpec {
  label: string;
  template: string;
  whenVar?: string;
}

export interface DeclarativeTableColumn {
  header: string;
  paths?: string[];
  fallbackVar?: string;
  format?: 'usd_compact' | 'int_comma' | 'strip_tags' | 'paired_percent';
  outcomesField?: string;
  pricesField?: string;
  defaultOutcomes?: string[];
  code?: boolean;
  sliceMax?: number;
}

export interface DeclarativeSectionSpec {
  heading: string;
  textVar?: string;
  arrayPath?: string;
  columns?: DeclarativeTableColumn[];
  listArrayPath?: string;
  limit?: number;
  indentField?: string;
  indentOffset?: number;
  maxIndent?: number;
  itemTemplate?: string;
  requireItemVar?: string;
  itemVars?: Record<string, DeclarativeVarSpec>;
}

export interface DeclarativeFindInArray {
  arrayPath: string;
  matchField: string;
  matchTemplate: string;
  ignoreCase?: boolean;
}

export interface DeclarativeExtractSpec {
  textMode?: 'yaml_frontmatter_card' | 'code_or_markdown_by_path' | 'raw';
  pathParam?: string;
  unwrapFirstArrayElement?: boolean;
  rootPath?: string;
  findInArray?: DeclarativeFindInArray;
  requireFields?: string[];
  requireAnyFields?: string[];
  requireVars?: string[];
  vars?: Record<string, DeclarativeVarSpec>;
  titleTemplate: string;
  titleWhenVar?: string;
  titleFallbackTemplate?: string;
  descriptionVar?: string;
  authorVar?: string;
  publishedTimeVar?: string;
  metaLine?: DeclarativeBulletSpec[];
  introVar?: string;
  bullets?: DeclarativeBulletSpec[];
  objectLinksPath?: string;
  bodyVar?: string;
  sections?: DeclarativeSectionSpec[];
  linksVars?: string[];
}

export interface DeclarativeRouteSpec {
  match: DeclarativeMatchSpec;
  twin: DeclarativeTwinSpec;
  extract: DeclarativeExtractSpec;
}

export interface DeclarativeAdapterManifest {
  id: string;
  name: string;
  category: AdapterCategory;
  description: string;
  domains: string[];
  exampleUrls: string[];
  match?: DeclarativeMatchSpec;
  twin?: DeclarativeTwinSpec;
  extract?: DeclarativeExtractSpec;
  routes?: DeclarativeRouteSpec[];
}

function isAsciiAlnum(code: number): boolean {
  return (code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57);
}

function isIdentChar(code: number): boolean {
  return isAsciiAlnum(code) || code === 95 /* '_' */;
}

function expandTemplate(tmpl: string, lookup: (key: string) => string): string {
  if (!tmpl.includes('{')) return tmpl;
  let out = '';
  const n = tmpl.length;
  let i = 0;
  while (i < n) {
    if (tmpl.charCodeAt(i) !== 123 /* '{' */) {
      out += tmpl[i]!;
      i++;
      continue;
    }
    let j = i + 1;
    while (j < n && isIdentChar(tmpl.charCodeAt(j))) {
      j++;
    }
    if (j > i + 1 && j < n && tmpl.charCodeAt(j) === 125 /* '}' */) {
      out += lookup(tmpl.slice(i + 1, j));
      i = j + 1;
    } else {
      out += '{';
      i++;
    }
  }
  return out;
}

function isValidDoiRest(val: string): boolean {
  if (!val.startsWith('10.')) return false;
  const slashIdx = val.indexOf('/');
  if (slashIdx < 7 || slashIdx > 12) return false;
  for (let i = 3; i < slashIdx; i++) {
    const c = val.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  const suffix = val.slice(slashIdx + 1);
  if (!suffix) return false;
  for (let i = 0; i < suffix.length; i++) {
    const c = suffix.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return false;
  }
  return true;
}

function isValidSafeSubpath(val: string): boolean {
  const parts = val.split('/');
  if (parts.length === 0) return false;
  for (const seg of parts) {
    if (!seg || seg === '.' || seg === '..') return false;
    for (let i = 0; i < seg.length; i++) {
      const c = seg.charCodeAt(i);
      if (c <= 0x20 || c >= 0x7f || c === 63 /* '?' */ || c === 35 /* '#' */ || c === 92 /* '\\' */) {
        return false;
      }
    }
  }
  return true;
}

function validateDeclarativeParam(
  val: string,
  charset: DeclarativeCharset | undefined,
  allowValues: string[] | undefined,
  reserved: string[] | undefined,
  minLen = 1,
  maxLen = 160,
): boolean {
  const lo = minLen > 0 ? minLen : 1;
  const hi = maxLen > 0 ? maxLen : 160;
  if (val.length < lo || val.length > hi) return false;
  if (allowValues && allowValues.length > 0 && !allowValues.includes(val)) {
    return false;
  }
  if (reserved && reserved.length > 0) {
    const lower = val.toLowerCase();
    for (const r of reserved) {
      if (lower === r.toLowerCase()) return false;
    }
  }
  const cs = charset ?? 'pkg';
  switch (cs) {
    case 'alnum':
      for (let i = 0; i < val.length; i++) {
        if (!isAsciiAlnum(val.charCodeAt(i))) return false;
      }
      return true;
    case 'alnum_dash':
    case 'slug':
      for (let i = 0; i < val.length; i++) {
        const c = val.charCodeAt(i);
        if (!isAsciiAlnum(c) && c !== 95 && c !== 45) return false;
      }
      return true;
    case 'pkg':
      if (val === '.' || val === '..') return false;
      for (let i = 0; i < val.length; i++) {
        const c = val.charCodeAt(i);
        if (!isAsciiAlnum(c) && c !== 95 && c !== 45 && c !== 46) return false;
      }
      return true;
    case 'model_slug':
      if (val === '.' || val === '..') return false;
      for (let i = 0; i < val.length; i++) {
        const c = val.charCodeAt(i);
        if (!isAsciiAlnum(c) && c !== 95 && c !== 45 && c !== 46 && c !== 58) return false;
      }
      return true;
    case 'doi_rest':
      return isValidDoiRest(val);
    case 'safe_subpath':
      return isValidSafeSubpath(val);
    default:
      return false;
  }
}

function safeDecodeURIComponent(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

function matchDeclarativeRoute(spec: DeclarativeMatchSpec, ctx: TwinMatchContext): Record<string, string> | null {
  if (spec.anyOf && spec.anyOf.length > 0) {
    for (const sub of spec.anyOf) {
      const m = matchDeclarativeRoute(sub, ctx);
      if (m) return m;
    }
    return null;
  }

  const params: Record<string, string> = { host: ctx.host, ...(spec.defaults ?? {}) };
  const segSpecs = spec.pathSegments ?? [];
  const rawParts = ctx.parts;
  const lastSpec = segSpecs[segSpecs.length - 1];
  const hasGreedy = Boolean(lastSpec && typeof lastSpec === 'object' && lastSpec.greedy);
  const exact = spec.exactSegments ?? true;

  if (hasGreedy) {
    if (rawParts.length < segSpecs.length) return null;
  } else if (exact) {
    if (rawParts.length !== segSpecs.length) return null;
  } else {
    if (rawParts.length < segSpecs.length) return null;
  }

  for (let idx = 0; idx < segSpecs.length; idx++) {
    const seg = segSpecs[idx]!;
    if (typeof seg === 'string') {
      const dec = safeDecodeURIComponent(rawParts[idx]!);
      if (dec === null || dec !== seg) return null;
      continue;
    }
    const rawCandidate = seg.greedy && idx === segSpecs.length - 1 ? rawParts.slice(idx).join('/') : rawParts[idx]!;
    let decoded = safeDecodeURIComponent(rawCandidate);
    if (decoded === null) return null;
    if (seg.stripSuffix && decoded.endsWith(seg.stripSuffix)) {
      decoded = decoded.slice(0, -seg.stripSuffix.length);
    }
    if (!validateDeclarativeParam(decoded, seg.charset, seg.allowValues, seg.reserved, seg.minLen, seg.maxLen)) {
      return null;
    }
    params[seg.param] = decoded;
  }

  if (spec.queryParams && spec.queryParams.length > 0) {
    for (const qp of spec.queryParams) {
      const qVal = ctx.url.searchParams.get(qp.name) ?? '';
      if (!validateDeclarativeParam(qVal, qp.charset, undefined, undefined, qp.minLen, qp.maxLen)) {
        return null;
      }
      params[qp.param] = qVal;
    }
  }

  return params;
}

function isIpv4Literal(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!p || p.length > 3) return false;
    for (let i = 0; i < p.length; i++) {
      const c = p.charCodeAt(i);
      if (c < 48 || c > 57) return false;
    }
  }
  return true;
}

function isSafeDeclarativeTwinUrl(fetchUrl: string): boolean {
  if (!fetchUrl.startsWith('https://')) return false;
  try {
    const u = new URL(fetchUrl);
    if (u.protocol !== 'https:' || u.username || u.password) return false;
    if (u.port && u.port !== '443') return false;
    const h = u.hostname.toLowerCase();
    if (!h || h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || !h.includes('.') || h.includes(':') || isIpv4Literal(h)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function getByDotPath(root: unknown, dotPath: string): unknown {
  if (!dotPath || root === null || root === undefined) return root;
  let cur: unknown = root;
  for (const seg of dotPath.split('.')) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    if (Array.isArray(cur)) {
      const idx = Number(seg);
      if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return undefined;
      cur = cur[idx];
    } else {
      cur = (cur as Record<string, unknown>)[seg];
    }
  }
  return cur;
}

function scalarToString(val: unknown): string {
  if (typeof val === 'string') return val;
  if (typeof val === 'number' && Number.isFinite(val)) return String(val);
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  return '';
}

function toFiniteNumber(val: unknown): number | null {
  if (typeof val === 'number') return Number.isFinite(val) ? val : null;
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (!trimmed) return null;
    const n = Number(trimmed);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function isLikelyHtmlSoft404(rawBody: string): boolean {
  const trimmed = rawBody.trimStart();
  if (!trimmed) return true;
  const prefix = trimmed.slice(0, 64).toLowerCase();
  return prefix.startsWith('<!doctype html') || prefix.startsWith('<html');
}

function stripLeadingYamlFrontmatter(s: string): string {
  const norm = s.replaceAll('\r\n', '\n');
  if (!norm.startsWith('---')) return s;
  const window = norm.slice(0, 1510);
  const closeIdx = window.indexOf('\n---', 3);
  if (closeIdx === -1) return s;
  let afterDash = closeIdx + 4;
  if (afterDash >= norm.length || norm.charCodeAt(afterDash) !== 10 /* '\n' */) return s;
  while (afterDash < norm.length && norm.charCodeAt(afterDash) === 10) {
    afterDash++;
  }
  return norm.slice(afterDash);
}

function stripXmlNamespaceTagsLinear(input: string): string {
  if (!input.includes('<')) return input;
  let out = '';
  let i = 0;
  const n = input.length;
  while (i < n) {
    if (input.charCodeAt(i) !== 60 /* '<' */) {
      out += input[i]!;
      i++;
      continue;
    }
    const gt = input.indexOf('>', i + 1);
    if (gt === -1) {
      out += input.slice(i);
      break;
    }
    const inner = input.slice(i + 1, gt).trim().toLowerCase();
    if (inner.startsWith('jats:') || inner.startsWith('/jats:')) {
      out += ' ';
    } else {
      out += input.slice(i, gt + 1);
    }
    i = gt + 1;
  }
  return out;
}

function formatJatsAbstract(raw: string): string {
  const withoutJats = stripXmlNamespaceTagsLinear(raw);
  let cleaned = stripTagsInline(withoutJats);
  if (cleaned.length >= 9 && cleaned.slice(0, 8).toLowerCase() === 'abstract') {
    const nextCode = cleaned.charCodeAt(8);
    if (nextCode === 32 || nextCode === 9) {
      cleaned = cleaned.slice(9).trim();
    }
  }
  return cleaned;
}

function stripInvisibleSmuggling(s: string): string {
  if (!s) return '';
  let clean = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if ((cp >= 0xe0000 && cp <= 0xe007f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) {
      continue;
    }
    clean += ch;
  }
  return clean;
}

function collapseNewlinesWithIndent(s: string, indent: string): string {
  let out = '';
  let prevNl = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 13 /* '\r' */) continue;
    if (c === 10 /* '\n' */) {
      if (!prevNl) {
        out += `\n${indent}`;
        prevNl = true;
      }
      continue;
    }
    prevNl = false;
    out += s[i]!;
  }
  return out;
}

function formatExtractedJsonValue(raw: unknown, spec: DeclarativeVarSpec): string {
  if (raw === null || raw === undefined) return '';

  switch (spec.format) {
    case 'int_comma': {
      const n = toFiniteNumber(raw);
      return n !== null ? Math.round(n).toLocaleString('en-US') : '';
    }
    case 'usd_compact':
      return formatUsdCompact(raw);
    case 'usd_per_million_tokens': {
      const n = toFiniteNumber(raw);
      if (n === null || n < 0) return '';
      if (n === 0) return '$0.00 / 1M tokens';
      return `$${(n * 1_000_000).toFixed(2)} / 1M tokens`;
    }
    case 'date_parts': {
      if (!Array.isArray(raw) || raw.length === 0) return '';
      const parts: string[] = [];
      for (let idx = 0; idx < raw.length; idx++) {
        const n = toFiniteNumber(raw[idx]);
        if (n === null) continue;
        const iv = Math.trunc(n);
        parts.push(idx === 0 ? String(iv) : String(iv).padStart(2, '0'));
      }
      return parts.join('-');
    }
    default:
      break;
  }

  if (Array.isArray(raw)) {
    const sliced = spec.limit && spec.limit > 0 ? raw.slice(0, spec.limit) : raw;
    const items: string[] = [];
    for (const el of sliced) {
      let itemStr = '';
      if (spec.subFieldsJoin) {
        if (el && typeof el === 'object' && !Array.isArray(el)) {
          const obj = el as Record<string, unknown>;
          const subParts = spec.subFieldsJoin.fields
            .map((f) => obj[f])
            .filter((x): x is string => typeof x === 'string' && x.length > 0);
          itemStr =
            subParts.length > 0
              ? subParts.join(spec.subFieldsJoin.sep)
              : spec.subFieldsJoin.fallbackField
                ? scalarToString(obj[spec.subFieldsJoin.fallbackField])
                : '';
        }
      } else if (spec.subField) {
        if (el && typeof el === 'object') {
          itemStr = scalarToString(getByDotPath(el, spec.subField));
        }
      } else {
        itemStr = scalarToString(el);
      }
      if (itemStr) {
        items.push(spec.itemWrap ? `${spec.itemWrap}${itemStr}${spec.itemWrap}` : itemStr);
      }
    }
    if (items.length === 0) return '';
    return spec.join !== undefined ? items.join(spec.join) : items[0]!;
  }

  return scalarToString(raw);
}

function renderTableColumnCell(itemObj: Record<string, unknown>, col: DeclarativeTableColumn, lookup: (k: string) => string): string {
  if (col.format === 'paired_percent') {
    const rawOutcomes = col.outcomesField ? itemObj[col.outcomesField] : undefined;
    const rawPrices = col.pricesField ? itemObj[col.pricesField] : undefined;
    const parsedOutcomes = typeof rawOutcomes === 'string' ? parseJsonValue(rawOutcomes) : rawOutcomes;
    const parsedPrices = typeof rawPrices === 'string' ? parseJsonValue(rawPrices) : rawPrices;
    const outcomes = Array.isArray(parsedOutcomes) ? parsedOutcomes.map(scalarToString) : (col.defaultOutcomes ?? []);
    const prices = Array.isArray(parsedPrices) ? parsedPrices.map((p) => toFiniteNumber(p)) : [];
    const summary = outcomes
      .map((o, idx) => {
        const pr = prices[idx];
        return pr !== null && pr !== undefined ? `${o}: ${(pr * 100).toFixed(1)}%` : o;
      })
      .join(' · ');
    return summary || '-';
  }

  let val = '';
  for (const p of col.paths ?? []) {
    const raw = getByDotPath(itemObj, p);
    if (raw === null || raw === undefined) continue;
    if (col.format === 'usd_compact') {
      val = formatUsdCompact(raw);
    } else if (col.format === 'int_comma') {
      const n = toFiniteNumber(raw);
      val = n !== null ? Math.round(n).toLocaleString('en-US') : '';
    } else if (col.format === 'strip_tags') {
      val = stripTagsInline(scalarToString(raw));
    } else {
      val = scalarToString(raw).trim();
    }
    if (val) break;
  }
  if (!val && col.fallbackVar) {
    val = lookup(col.fallbackVar).trim();
  }
  val = stripInvisibleSmuggling(val);
  if (col.sliceMax && col.sliceMax > 0 && val.length > col.sliceMax) {
    val = val.slice(0, col.sliceMax);
  }
  if (!val) return '-';
  return col.code ? `\`${val}\`` : val;
}

function formatTextRouteTwin(rawBody: string, route: DeclarativeRouteSpec, params: Record<string, string>): TwinFormattedDoc | null {
  const cleanBody = rawBody.replace(/^\ufeff/, '');
  if (isLikelyHtmlSoft404(cleanBody)) return null;
  const sanitized = stripInvisibleSmuggling(cleanBody);
  const fallbackTitle = expandTemplate(route.extract.titleTemplate, (k) => params[k] ?? '').trim();

  if (route.extract.textMode === 'yaml_frontmatter_card') {
    return formatYamlFrontmatterCard(sanitized, fallbackTitle);
  }
  if (route.extract.textMode === 'code_or_markdown_by_path') {
    const filePath = route.extract.pathParam ? (params[route.extract.pathParam] ?? '') : '';
    const { lang, isMarkdown } = detectFenceLang(filePath);
    if (isMarkdown) return formatYamlFrontmatterCard(sanitized, fallbackTitle);
    return {
      title: fallbackTitle,
      markdown: `# ${fallbackTitle}\n\n${safeFence(sanitized, lang)}`,
    };
  }
  const trimmed = sanitized.trim();
  if (!trimmed) return null;
  const md = fallbackTitle && !trimmed.startsWith('# ') ? `# ${fallbackTitle}\n\n${trimmed}` : trimmed;
  return { title: fallbackTitle, markdown: md };
}

function formatJsonRouteTwin(rawBody: string, route: DeclarativeRouteSpec, params: Record<string, string>): TwinFormattedDoc | null {
  let rootVal = parseJsonValue(rawBody);
  if (rootVal === null || rootVal === undefined) return null;
  const ext = route.extract;

  if (ext.unwrapFirstArrayElement && Array.isArray(rootVal)) {
    if (rootVal.length === 0) return null;
    rootVal = rootVal[0];
  }
  if (!rootVal || typeof rootVal !== 'object' || Array.isArray(rootVal)) return null;
  let rootObj = rootVal as Record<string, unknown>;

  if (ext.rootPath) {
    const sub = getByDotPath(rootObj, ext.rootPath);
    if (!sub || typeof sub !== 'object' || Array.isArray(sub)) return null;
    rootObj = sub as Record<string, unknown>;
  }

  if (ext.findInArray) {
    const arr = getByDotPath(rootObj, ext.findInArray.arrayPath);
    if (!Array.isArray(arr)) return null;
    const want = expandTemplate(ext.findInArray.matchTemplate, (k) => params[k] ?? '');
    const wantLower = want.toLowerCase();
    const hit = arr.find((el) => {
      if (!el || typeof el !== 'object' || Array.isArray(el)) return false;
      const got = scalarToString((el as Record<string, unknown>)[ext.findInArray!.matchField]);
      return ext.findInArray!.ignoreCase ? got.toLowerCase() === wantLower : got === want;
    });
    if (!hit || typeof hit !== 'object' || Array.isArray(hit)) return null;
    rootObj = hit as Record<string, unknown>;
  }

  for (const rf of ext.requireFields ?? []) {
    if (typeof getByDotPath(rootObj, rf) !== 'string') return null;
  }
  if (ext.requireAnyFields && ext.requireAnyFields.length > 0) {
    const anyOk = ext.requireAnyFields.some((f) => Boolean(getByDotPath(rootObj, f)));
    if (!anyOk) return null;
  }

  const varsMap = ext.vars ?? {};
  const resolved = new Map<string, string>();
  const visiting = new Set<string>();

  const evalVar = (spec: DeclarativeVarSpec, activeObj: Record<string, unknown>): string => {
    let val = '';
    if (spec.template !== undefined) {
      const ok = (spec.whenVars ?? []).every((w) => lookup(w) !== '');
      if (ok) {
        val = expandTemplate(spec.template, lookup);
      } else if (spec.fallbackVar) {
        val = lookup(spec.fallbackVar);
      }
    } else if (spec.format === 'bool_map') {
      const raw = spec.paths && spec.paths[0] ? getByDotPath(activeObj, spec.paths[0]) : undefined;
      val = Boolean(raw) ? (spec.trueValue ?? 'true') : (spec.falseValue ?? 'false');
    } else if (spec.dynamicKeyPath) {
      const keyVal = lookup(spec.dynamicKeyPath.keyVar);
      if (keyVal) {
        const baseObj = getByDotPath(activeObj, spec.dynamicKeyPath.base);
        if (baseObj && typeof baseObj === 'object' && !Array.isArray(baseObj)) {
          let entry = (baseObj as Record<string, unknown>)[keyVal];
          if (spec.dynamicKeyPath.subPath) {
            entry = entry && typeof entry === 'object' ? getByDotPath(entry, spec.dynamicKeyPath.subPath) : undefined;
          }
          val = formatExtractedJsonValue(entry, spec);
        }
      }
    } else {
      for (const p of spec.paths ?? []) {
        const raw = getByDotPath(activeObj, p);
        if (raw === null || raw === undefined) continue;
        if (spec.firstNonMatchingKey) {
          if (typeof raw === 'object' && !Array.isArray(raw)) {
            const keys = Object.keys(raw as Record<string, unknown>);
            val = keys.find((k) => !k.includes(spec.firstNonMatchingKey!)) ?? keys[0] ?? '';
            if (val) break;
          }
          continue;
        }
        const formatted = formatExtractedJsonValue(raw, spec);
        if (formatted !== '') {
          val = formatted;
          break;
        }
      }
    }

    if (val === '') {
      if (spec.fallbackTemplate !== undefined) {
        val = expandTemplate(spec.fallbackTemplate, lookup);
      } else if (spec.default !== undefined) {
        val = spec.default;
      }
    }
    if (spec.stripFrontmatter && val) {
      val = stripLeadingYamlFrontmatter(val);
    }
    if (spec.format === 'trim') {
      val = val.trim();
    } else if (spec.format === 'strip_tags') {
      val = stripTagsInline(val);
    } else if (spec.format === 'jats_abstract') {
      val = formatJatsAbstract(val);
    }
    if (spec.trim) {
      val = val.trim();
    }
    val = stripInvisibleSmuggling(val);
    if (spec.requireHttps && !val.startsWith('https://')) {
      val = '';
    }
    if (spec.sliceMax && spec.sliceMax > 0 && val.length > spec.sliceMax) {
      val = val.slice(0, spec.sliceMax);
    }
    return val;
  };

  function lookup(name: string): string {
    if (resolved.has(name)) return resolved.get(name)!;
    const spec = varsMap[name];
    if (spec) {
      if (visiting.has(name)) return '';
      visiting.add(name);
      const v = evalVar(spec, rootObj);
      visiting.delete(name);
      resolved.set(name, v);
      return v;
    }
    return params[name] ?? '';
  }

  for (const name of Object.keys(varsMap)) {
    lookup(name);
  }
  for (const reqVar of ext.requireVars ?? []) {
    if (!lookup(reqVar).trim()) return null;
  }

  let title = '';
  if (ext.titleWhenVar) {
    title = lookup(ext.titleWhenVar)
      ? expandTemplate(ext.titleTemplate, lookup)
      : expandTemplate(ext.titleFallbackTemplate ?? '', lookup);
  } else {
    title = expandTemplate(ext.titleTemplate, lookup);
    if (!title.trim() && ext.titleFallbackTemplate) {
      title = expandTemplate(ext.titleFallbackTemplate, lookup);
    }
  }
  title = stripInvisibleSmuggling(title.trim());
  if (!title) return null;

  const metaParts: string[] = [];
  for (const ml of ext.metaLine ?? []) {
    if (ml.whenVar && !lookup(ml.whenVar)) continue;
    const rendered = expandTemplate(ml.template, lookup).trim();
    if (rendered) metaParts.push(`**${ml.label}**: ${rendered}`);
  }

  const bulletLines: string[] = [];
  for (const b of ext.bullets ?? []) {
    if (b.whenVar && !lookup(b.whenVar)) continue;
    const rendered = expandTemplate(b.template, lookup).trim();
    if (rendered) bulletLines.push(`- **${b.label}**: ${rendered}`);
  }
  if (ext.objectLinksPath) {
    const linksObj = getByDotPath(rootObj, ext.objectLinksPath);
    if (linksObj && typeof linksObj === 'object' && !Array.isArray(linksObj)) {
      for (const [label, href] of Object.entries(linksObj as Record<string, unknown>)) {
        if (typeof href === 'string' && href.startsWith('https://')) {
          bulletLines.push(`- **${stripInvisibleSmuggling(label)}**: ${href}`);
        }
      }
    }
  }

  const intro = ext.introVar ? lookup(ext.introVar).trim() : '';
  const bodyText = ext.bodyVar ? lookup(ext.bodyVar).trim() : '';

  const renderedSections: string[] = [];
  for (const sec of ext.sections ?? []) {
    if (sec.textVar) {
      const txt = lookup(sec.textVar).trim();
      if (txt) renderedSections.push(`## ${sec.heading}\n\n${txt}`);
      continue;
    }
    if (sec.arrayPath && sec.columns && sec.columns.length > 0) {
      const arr = getByDotPath(rootObj, sec.arrayPath);
      if (!Array.isArray(arr) || arr.length === 0) continue;
      const sliced = sec.limit && sec.limit > 0 ? arr.slice(0, sec.limit) : arr;
      const headers = sec.columns.map((c) => c.header);
      const rows: string[][] = [];
      for (const rawItem of sliced) {
        if (!rawItem || typeof rawItem !== 'object' || Array.isArray(rawItem)) continue;
        const itemObj = rawItem as Record<string, unknown>;
        rows.push(sec.columns.map((col) => renderTableColumnCell(itemObj, col, lookup)));
      }
      if (rows.length > 0) {
        renderedSections.push(`## ${sec.heading}\n\n${formatGfmTable(headers, rows)}`);
      }
      continue;
    }
    if (sec.listArrayPath && sec.itemTemplate) {
      const arr = getByDotPath(rootObj, sec.listArrayPath);
      if (!Array.isArray(arr) || arr.length === 0) continue;
      const sliced = sec.limit && sec.limit > 0 ? arr.slice(0, sec.limit) : arr;
      const maxInd = sec.maxIndent && sec.maxIndent > 0 ? sec.maxIndent : 6;
      const lines: string[] = [`## ${sec.heading}`];
      for (const rawItem of sliced) {
        if (!rawItem || typeof rawItem !== 'object' || Array.isArray(rawItem)) continue;
        const itemObj = rawItem as Record<string, unknown>;
        const itemMap: Record<string, string> = {};
        for (const [ivName, ivSpec] of Object.entries(sec.itemVars ?? {})) {
          itemMap[ivName] = evalVar(ivSpec, itemObj);
        }
        if (sec.requireItemVar && !(itemMap[sec.requireItemVar] ?? '').trim()) {
          continue;
        }
        let depth = 0;
        if (sec.indentField) {
          const rawDepth = toFiniteNumber(getByDotPath(itemObj, sec.indentField));
          if (rawDepth !== null) {
            depth = Math.max(0, Math.min(maxInd, Math.trunc(rawDepth) + (sec.indentOffset ?? 0)));
          }
        }
        const indent = '  '.repeat(depth);
        if (sec.requireItemVar) {
          itemMap[sec.requireItemVar] = collapseNewlinesWithIndent(itemMap[sec.requireItemVar]!, `${indent}  `);
        }
        const rendered = expandTemplate(sec.itemTemplate, (k) => (k in itemMap ? itemMap[k]! : lookup(k)));
        lines.push(`${indent}- ${rendered}`);
      }
      if (lines.length > 1) {
        renderedSections.push(lines.join('\n'));
      }
    }
  }

  const blocks: string[] = [];
  const onlyBodyAlreadyTitled =
    bodyText !== '' &&
    bodyText.startsWith('# ') &&
    metaParts.length === 0 &&
    intro === '' &&
    bulletLines.length === 0 &&
    renderedSections.length === 0;
  if (!onlyBodyAlreadyTitled) {
    blocks.push(`# ${title}`);
  }
  if (metaParts.length > 0) blocks.push(metaParts.join(' · '));
  if (intro) blocks.push(intro);
  if (bulletLines.length > 0) blocks.push(bulletLines.join('\n'));
  if (bodyText) blocks.push(bodyText);
  blocks.push(...renderedSections);

  const links = (ext.linksVars ?? [])
    .map((lv) => lookup(lv).trim())
    .filter((u) => u.startsWith('https://'));

  const description = ext.descriptionVar ? lookup(ext.descriptionVar) : '';
  const author = ext.authorVar ? lookup(ext.authorVar) : '';
  const publishedTime = ext.publishedTimeVar ? lookup(ext.publishedTimeVar) : '';

  return {
    title,
    ...(description ? { description } : {}),
    ...(author ? { author } : {}),
    ...(publishedTime ? { publishedTime } : {}),
    markdown: blocks.join('\n\n'),
    ...(links.length > 0 ? { links } : {}),
  };
}

/** Parses a raw YAML manifest string (with `maxAliasCount: 0` to block alias expansion) or returns an object manifest. */
export function parseDeclarativeManifest(input: DeclarativeAdapterManifest | string): DeclarativeAdapterManifest {
  if (typeof input !== 'string') {
    return input;
  }
  const parsed = parseYaml(input, { maxAliasCount: 0, merge: false }) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid declarative adapter YAML manifest: root must be a mapping');
  }
  return parsed as DeclarativeAdapterManifest;
}

/** Compiles a canonical declarative YAML string or JSON manifest object into an executable `SiteAdapter`. */
export function compileDeclarativeAdapter(manifestOrYaml: DeclarativeAdapterManifest | string): SiteAdapter {
  const manifest = parseDeclarativeManifest(manifestOrYaml);
  const routes: DeclarativeRouteSpec[] =
    manifest.routes && manifest.routes.length > 0
      ? manifest.routes
      : manifest.match && manifest.twin && manifest.extract
        ? [{ match: manifest.match, twin: manifest.twin, extract: manifest.extract }]
        : [];

  return {
    id: manifest.id,
    name: manifest.name,
    category: manifest.category,
    description: manifest.description,
    domains: [...manifest.domains],
    exampleUrls: [...manifest.exampleUrls],
    resolveTwin(ctx: TwinMatchContext): SiteExtractorTwin | null {
      for (const route of routes) {
        const params = matchDeclarativeRoute(route.match, ctx);
        if (!params) continue;
        const rawSet = new Set(route.twin.rawPathParams ?? []);
        const fetchUrl = expandTemplate(route.twin.fetchUrl, (key) => {
          if (key === 'host') return ctx.host;
          const val = params[key] ?? '';
          if (rawSet.has(key)) {
            return val
              .split('/')
              .map((seg) => encodeURIComponent(seg))
              .join('/');
          }
          return encodeURIComponent(val);
        });
        if (!isSafeDeclarativeTwinUrl(fetchUrl)) continue;
        return {
          id: route.twin.id || manifest.id,
          fetchUrl,
          kind: route.twin.kind,
          accept: route.twin.accept,
          formatTwin: (rawBody: string) =>
            route.twin.kind === 'text' || route.extract.textMode
              ? formatTextRouteTwin(rawBody, route, params)
              : formatJsonRouteTwin(rawBody, route, params),
        };
      }
      return null;
    },
  };
}

const RAW_DECLARATIVE_MANIFESTS: ReadonlyArray<DeclarativeAdapterManifest | string> = [
  rubygemsManifest,
  packagistManifest,
  hexPmManifest,
  huggingfaceManifest,
  openrouterManifest,
  polymarketManifest,
  usaspendingManifest,
  doiCrossrefManifest,
  lobstersManifest,
  devToManifest,
];

export const DECLARATIVE_SITE_ADAPTERS: readonly SiteAdapter[] = RAW_DECLARATIVE_MANIFESTS.map(compileDeclarativeAdapter);
