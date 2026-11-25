#!/usr/bin/env node
/**
 * Canonical Declarative YAML Manifest Compiler (`hub/scripts/compile-manifests.mjs`).
 *
 * Parses all contributor `#`-commented `.yaml` manifests in `internal/extract/manifests/*.yaml`
 * using the single vetted `yaml` 1.2 Core parser (`maxAliasCount: 0, merge: false, uniqueKeys: true`),
 * enforces strict ASCII-only exact schema keys (eliminating Go-vs-TS YAML/JSON parser differentials — R6-H5/M8),
 * enforces M2 host-claim & duplicate-ID guards, and writes deterministic `internal/extract/manifests/compiled.json`
 * embedded by both TypeScript and Go (`//go:embed manifests/compiled.json`).
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isAlias, isMap, isPair, isScalar, isSeq, parseDocument } from 'yaml';

const hubRoot = process.env.EDGEFETCH_HUB_ROOT
  ? resolve(process.env.EDGEFETCH_HUB_ROOT)
  : resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(hubRoot, '..');
const manifestsDir = join(repoRoot, 'internal', 'extract', 'manifests');
const outPath = join(manifestsDir, 'compiled.json');
const checkOnly = process.argv.includes('--check');

const VALID_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const VALID_CATEGORIES = new Set([
  'developer',
  'genai',
  'jobs',
  'finance',
  'public-records',
  'research-health',
  'commerce-social',
]);
export const VALID_CATALOG_PLATFORMS = new Set(['shopify', 'woocommerce']);
export const VALID_HTML_MODES = new Set([
  'dom',
  'embedded_json',
  'xml_items_table',
  'markdown_clean',
  'gist_files',
  'stackexchange_html',
  'reddit_shreddit',
  'icims_portal',
  'shopify_html',
  'woocommerce_html',
]);

const pslDatPath = join(manifestsDir, 'public_suffix_list.dat');
const pslExact = new Map();
const pslWildcards = new Map();
const pslExceptions = new Map();
{
  let inPrivate = false;
  for (const rawLine of readFileSync(pslDatPath, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('//')) {
      if (line.includes('===BEGIN PRIVATE DOMAINS===')) inPrivate = true;
      else if (line.includes('===END PRIVATE DOMAINS===')) inPrivate = false;
      continue;
    }
    if (line.startsWith('!')) pslExceptions.set(line.slice(1), inPrivate);
    else if (line.startsWith('*.')) pslWildcards.set(line.slice(2), inPrivate);
    else pslExact.set(line, inPrivate);
  }
}

function normalizeHostLabels(rawHost) {
  let clean = String(rawHost ?? '').trim().toLowerCase();
  if (!clean || clean.startsWith('.')) return null;
  clean = clean.replace(/\.+$/, '');
  if (!clean || /[\s/*\\:?#@[\]]/.test(clean)) return null;
  if (/[^\x20-\x7e]/.test(clean)) {
    try {
      clean = new URL(`http://${clean}`).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  const labels = clean.split('.');
  for (const l of labels) {
    if (!l || l.length > 63 || l.startsWith('-') || l.endsWith('-') || !/^[a-z0-9-]+$/.test(l)) {
      return null;
    }
  }
  const tld = labels[labels.length - 1];
  if (tld.charCodeAt(0) >= 48 && tld.charCodeAt(0) <= 57) return null;
  return labels;
}

function matchPsl(labels) {
  let suffixLen = 1;
  let isPrivate = false;
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join('.');
    const rem = labels.length - i;
    if (pslExceptions.has(cand)) return { suffixLen: rem - 1, isPrivate: pslExceptions.get(cand) };
    if (pslExact.has(cand) && rem > suffixLen) {
      suffixLen = rem;
      isPrivate = pslExact.get(cand);
    }
    if (i > 0 && pslWildcards.has(cand) && rem + 1 > suffixLen) {
      suffixLen = rem + 1;
      isPrivate = pslWildcards.get(cand);
    }
  }
  return { suffixLen, isPrivate };
}

export function getRegistrableDomain(host) {
  const labels = normalizeHostLabels(host);
  if (!labels) return null;
  const { suffixLen } = matchPsl(labels);
  if (labels.length <= suffixLen) return null;
  return labels.slice(labels.length - suffixLen - 1).join('.');
}

export function isPublicOrPrivateSuffix(host) {
  return getRegistrableDomain(host) === null;
}

export function hasPrivateSharedHostingSuffix(host) {
  const labels = normalizeHostLabels(host);
  if (!labels) return false;
  const { isPrivate } = matchPsl(labels);
  return isPrivate || pslWildcards.get(labels.join('.')) === true;
}

function normalizeManifestDomainPattern(raw) {
  return String(raw ?? '').trim().toLowerCase().replace(/\.+$/, '');
}

function claimedRegistrableDomains(domains) {
  const regs = new Set();
  for (const raw of domains ?? []) {
    const d = normalizeManifestDomainPattern(raw);
    if (!d) continue;
    const probe = d.startsWith('*.') && !d.slice(2).includes('*') ? d.slice(2) : d.includes('*') ? '' : d;
    if (!probe) continue;
    const reg = getRegistrableDomain(probe);
    if (reg) regs.add(reg);
  }
  return regs;
}

/**
 * Frozen 5-entry built-in public-archive map for existing cross-domain public APIs.
 * No new or contributor manifest can point `twin.fetchUrl` to another registrable domain.
 */
const APPROVED_CROSS_DOMAIN_TWIN_HOSTS = Object.freeze(
  new Map([
    ['doi-crossref', Object.freeze(new Set(['api.crossref.org']))],
    ['hackernews', Object.freeze(new Set(['hn.algolia.com', 'hacker-news.firebaseio.com']))],
    ['jazzhr', Object.freeze(new Set(['app.jazz.co']))],
    ['npm-registry', Object.freeze(new Set(['registry.npmjs.org']))],
    ['pubmed-pmc', Object.freeze(new Set(['www.ebi.ac.uk']))],
  ]),
);

/**
 * Explicit allowlist of vetted multi-tenant platform wildcard patterns permitted in compiled manifests.
 * No new manifest may claim an arbitrary wildcard suffix without updating this security-reviewed allowlist.
 */
const APPROVED_WILDCARD_DOMAIN_PATTERNS = new Set([
  '*.arcgis.com',
  '*.bamboohr.com',
  '*.breezy.hr',
  '*.recruitee.com',
  '*.jobs.personio.de',
  '*.jobs.personio.com',
  '*.oraclecloud.com',
  'gitlab.*',
  '*.icims.com',
  '*.applytojob.com',
  '*.legistar.com',
  '*.wikipedia.org',
  '*.openfoodfacts.org',
  '*.pinpointhq.com',
  '*.reddit.com',
  'careers.*.com',
  'jobs.*.com',
  '*.myshopify.com',
  '*.socrata.com',
  '*.stackexchange.com',
  '*.teamtailor.com',
]);

const RESERVED_CORE_ATS_DOMAINS = new Set([
  'jobs.ashbyhq.com',
  '*.myworkdayjobs.com',
  '*.myworkdaysite.com',
]);

/**
 * Simple, auditable wildcard matcher for the 3 allowlisted shapes (`*.suffix`, `gitlab.*`, `careers.*.com` / `jobs.*.com`).
 */
export function matchesApprovedWildcard(rawWildcard, rawCandidate) {
  const w = normalizeManifestDomainPattern(rawWildcard);
  const c = normalizeManifestDomainPattern(rawCandidate);
  if (!w || !c || !w.includes('*')) return false;
  if (w === c) return true;
  if (w.startsWith('*.') && !w.slice(2).includes('*')) {
    const suf = w.slice(2);
    return c !== suf && c.endsWith(`.${suf}`);
  }
  if (w.endsWith('.*') && !w.slice(0, -2).includes('*')) {
    const pre = w.slice(0, -2);
    return c.startsWith(`${pre}.`) && c.length > pre.length + 1;
  }
  const star = w.indexOf('*');
  if (star > 0 && w.lastIndexOf('*') === star) {
    const head = w.slice(0, star);
    const tail = w.slice(star + 1);
    return c.startsWith(head) && c.endsWith(tail) && c.length > head.length + tail.length;
  }
  return false;
}

const APPROVED_SAP_ATS_EXACT_EXEMPTIONS = Object.freeze(
  new Set([
    'enterprise-ats:jobs.smartrecruiters.com',
    'enterprise-ats:jobs.jobvite.com',
    'gem-ats:jobs.gem.com',
  ]),
);

function isExemptSapAtsExactClaim(wildOwnerId, wildPat, exactOwnerId, exactDom) {
  return wildOwnerId === 'sap-rmk-jibe' && wildPat === 'jobs.*.com' && APPROVED_SAP_ATS_EXACT_EXEMPTIONS.has(`${exactOwnerId}:${exactDom}`);
}

const SCHEMA_KEYS = {
  manifest: new Set([
    'id', 'name', 'category', 'description', 'domains', 'universalEngine', 'exampleUrls',
    'match', 'twin', 'extract', 'routes', 'htmlRoutes', 'catalog',
  ]),
  route: new Set(['match', 'twin', 'extract']),
  match: new Set([
    'anyOf', 'hosts', 'excludeHosts', 'socrataHost', 'hostSubdomain', 'hostMap',
    'optionalLeadingLocale', 'exactSegments', 'minSegments', 'maxSegments',
    'pathPrefix', 'pathSuffix', 'pathEquals', 'pathContainsSegment',
    'excludeSegmentSuffixes', 'allSegmentsCharset', 'reservedFirstSegment',
    'scanSegment', 'splitOnSegment', 'arcgisRestLayer',
    'pathSegments', 'queryParams', 'derivedParams', 'defaults',
  ]),
  paramSegment: new Set([
    'param', 'charset', 'allowValues', 'reserved', 'stripPrefix', 'stripSuffix',
    'minLen', 'maxLen', 'greedy', 'optional', 'transform',
  ]),
  queryParam: new Set([
    'name', 'names', 'param', 'charset', 'minLen', 'maxLen', 'optional', 'default', 'transform',
  ]),
  hostSubdomain: new Set(['suffix', 'param', 'reserved', 'stripOptional2LetterRegion']),
  hostMap: new Set(['param', 'exact', 'stripWww', 'suffixSubdomain']),
  scanSegment: new Set([
    'afterLiteral', 'lastOrBeforeLiteral', 'param', 'charset',
    'stripPrefix', 'stripSuffix', 'minLen', 'maxLen', 'transform',
  ]),
  splitOnSegment: new Set(['delimiter', 'leftParam', 'leftMinSegs', 'afterLiteral', 'rightParam', 'tailParam']),
  derivedParam: new Set(['fromParam', 'transform']),
  twin: new Set([
    'id', 'fetchUrl', 'rawPathParams', 'overridePathIf', 'setQueryParams', 'defaultQueryParams', 'kind', 'accept', 'maxBytes',
  ]),
  overridePathIf: new Set(['matchPaths', 'newPath']),
  extract: new Set([
    'commerceMode', 'icimsPortal', 'textMode', 'pathParam', 'xml', 'jsonSource',
    'wrapRootArrayAs', 'unwrapFirstArrayElement', 'rootPath', 'rejectIfFieldTruthy',
    'requireFieldEquals', 'requireArrayItemField', 'findInArray', 'fallbackExtract',
    'requireFields', 'requireAnyFields', 'requireVars', 'vars', 'codeByPath',
    'titleTemplate', 'titleWhenVar', 'titleFallbackTemplate',
    'descriptionVar', 'descriptionTemplate', 'authorVar', 'authorTemplate', 'publishedTimeVar',
    'blockquoteTemplate', 'blockquoteWhenVar', 'metaLine', 'metaLineItalic',
    'footerItalicTemplate', 'footerItalicWhenVar', 'introVar', 'bullets',
    'objectLinksPath', 'bodyVar', 'sections', 'linksVars', 'linkTemplates',
  ]),
  varSpec: new Set([
    'paths', 'dynamicKeyPath', 'nestedSubValues', 'tocHeading', 'findInArrayLang',
    'template', 'whenVars', 'whenAnyVars', 'fallbackVar', 'firstNonMatchingKey',
    'subField', 'subFieldsJoin', 'itemWrap', 'join', 'limit', 'format',
    'trueValue', 'falseValue', 'stripFrontmatter', 'stripPrefix', 'stripSuffix',
    'replaceAll', 'excludeEquals', 'equalsVar', 'trim', 'upper', 'lower',
    'requireHttps', 'requireHttpPrefix', 'sliceMax', 'default', 'fallbackTemplate',
  ]),
  bullet: new Set(['label', 'template', 'whenVar', 'unlessVar']),
  section: new Set([
    'heading', 'headingTemplate', 'whenVar', 'unlessVar', 'textVar',
    'arrayPath', 'parallelArrays', 'minItems', 'emptyText', 'filter', 'dedupeBy', 'sortBy',
    'columns', 'listArrayPath', 'subsectionsArrayPath', 'subsectionHeadingTemplate',
    'subsectionAltHeadingTemplate', 'subsectionAltWhenVar', 'subsectionBodyVar', 'subsectionSubkeys',
    'treeComments', 'limit', 'indentField', 'indentOffset', 'maxIndent',
    'itemTemplate', 'requireItemVar', 'itemVars', 'collectLinkVars', 'linkScanLimit',
    'recordFields', 'paginationMeta',
  ]),
  column: new Set([
    'header', 'paths', 'template', 'fallbackVar', 'format',
    'outcomesField', 'pricesField', 'defaultOutcomes', 'stripPrefix', 'code', 'sliceMax',
  ]),
  xml: new Set([
    'mode', 'requireAnyTags', 'itemTag', 'channelTitleFallbackParam', 'firstItemVars',
    'titleTemplate', 'emptyText', 'limit', 'requireItemVar', 'itemVars',
    'columns', 'collectLinkVar', 'recordFields', 'emitTotals',
  ]),
  xmlItemVar: new Set(['tags', 'splitColonPart', 'sliceMax', 'default']),
  htmlRoute: new Set([
    'id', 'match', 'mode', 'jsonLdTypes', 'embeddedBalancedKey', 'vars',
    'requireVars', 'requireBulletsOrVars', 'titleTemplate', 'titleWhenVar', 'titleFallbackTemplate',
    'descriptionVar', 'authorVar', 'publishedTimeVar', 'blockquoteTemplate', 'blockquoteWhenVar',
    'metaItalicTemplate', 'metaItalicWhenVar', 'introVar', 'bullets', 'bodyVar', 'bodyFallbackHeading',
    'sections', 'appendCurrentMdDelta', 'linkTemplates', 'preserveBodyLinksFromVar',
    'scriptId', 'dataAttr', 'extract', 'xml', 'cleanPreset',
  ]),
  htmlVar: new Set([
    'jsonLdPaths', 'embeddedPaths', 'metaKeys', 'allMetaKey', 'cssText', 'cssAttr',
    'cssAllText', 'cssHtmlToMd', 'regexExtract', 'template', 'whenVars', 'whenAnyVars',
    'fallbackVar', 'fallbackTemplate', 'default', 'join', 'limit', 'format', 'currencyVar',
    'stripPrefix', 'stripSuffix', 'stripRegexSuffix', 'replaceAll', 'sliceMax', 'minLen', 'trim',
  ]),
  catalog: new Set([
    'platform', 'pauseMs', 'pageCap', 'firstPageTemplate', 'collectionPageTemplate',
    'perPage', 'maxVariantsPerProduct', 'maxImagesPerProduct',
  ]),
};

function isAsciiPrintable(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

export function checkAstSafety(node, ctxPath) {
  if (!node || typeof node !== 'object') return;
  if (isAlias(node)) {
    throw new Error(`${ctxPath}: YAML alias (*alias) is forbidden`);
  }
  if (node.anchor) {
    throw new Error(`${ctxPath}: YAML anchor (&${node.anchor}) is forbidden`);
  }
  if (node.tag) {
    throw new Error(`${ctxPath}: explicit YAML tag (${node.tag}) is forbidden`);
  }
  if (isMap(node)) {
    for (const pair of node.items) {
      if (!isPair(pair)) continue;
      checkAstSafety(pair.key, ctxPath);
      if (isScalar(pair.key)) {
        const k = String(pair.key.value ?? '');
        if (k === '<<') throw new Error(`${ctxPath}: YAML merge key (<<) is forbidden`);
        if (!isAsciiPrintable(k)) throw new Error(`${ctxPath}: non-ASCII YAML key "${k}" is forbidden`);
      }
      const keyLabel = isScalar(pair.key) ? String(pair.key.value ?? '') : '?';
      checkAstSafety(pair.value, `${ctxPath}.${keyLabel}`);
    }
  } else if (isSeq(node)) {
    node.items.forEach((child, i) => checkAstSafety(child, `${ctxPath}[${i}]`));
  }
}

function assertAllowedKeys(obj, allowSet, ctxPath) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error(`${ctxPath}: expected object mapping`);
  }
  for (const k of Object.keys(obj)) {
    if (!isAsciiPrintable(k)) {
      throw new Error(`${ctxPath}: non-ASCII key "${k}" is forbidden`);
    }
    if (!allowSet.has(k)) {
      throw new Error(`${ctxPath}: unknown or case-mismatched schema key "${k}"`);
    }
  }
}

function validateMatch(match, ctxPath) {
  assertAllowedKeys(match, SCHEMA_KEYS.match, ctxPath);
  for (const [i, sub] of (match.anyOf ?? []).entries()) {
    validateMatch(sub, `${ctxPath}.anyOf[${i}]`);
  }
  if (match.hostSubdomain) {
    assertAllowedKeys(match.hostSubdomain, SCHEMA_KEYS.hostSubdomain, `${ctxPath}.hostSubdomain`);
  }
  if (match.hostMap) {
    assertAllowedKeys(match.hostMap, SCHEMA_KEYS.hostMap, `${ctxPath}.hostMap`);
  }
  if (match.scanSegment) {
    assertAllowedKeys(match.scanSegment, SCHEMA_KEYS.scanSegment, `${ctxPath}.scanSegment`);
  }
  if (match.splitOnSegment) {
    assertAllowedKeys(match.splitOnSegment, SCHEMA_KEYS.splitOnSegment, `${ctxPath}.splitOnSegment`);
  }
  for (const [i, seg] of (match.pathSegments ?? []).entries()) {
    if (typeof seg === 'string') continue;
    assertAllowedKeys(seg, SCHEMA_KEYS.paramSegment, `${ctxPath}.pathSegments[${i}]`);
    if (typeof seg.param !== 'string' || !seg.param) {
      throw new Error(`${ctxPath}.pathSegments[${i}]: missing param name`);
    }
    for (const listKey of ['reserved', 'allowValues']) {
      if (seg[listKey] !== undefined) {
        if (!Array.isArray(seg[listKey]) || !seg[listKey].every((x) => typeof x === 'string')) {
          throw new Error(`${ctxPath}.pathSegments[${i}].${listKey}: must be array of strings`);
        }
      }
    }
  }
  for (const [i, qp] of (match.queryParams ?? []).entries()) {
    assertAllowedKeys(qp, SCHEMA_KEYS.queryParam, `${ctxPath}.queryParams[${i}]`);
  }
  if (match.derivedParams) {
    for (const [dk, dv] of Object.entries(match.derivedParams)) {
      assertAllowedKeys(dv, SCHEMA_KEYS.derivedParam, `${ctxPath}.derivedParams.${dk}`);
    }
  }
}

function validateExtract(ext, ctxPath) {
  assertAllowedKeys(ext, SCHEMA_KEYS.extract, ctxPath);
  if (ext.fallbackExtract) {
    validateExtract(ext.fallbackExtract, `${ctxPath}.fallbackExtract`);
  }
  if (ext.vars) {
    for (const [vk, vs] of Object.entries(ext.vars)) {
      assertAllowedKeys(vs, SCHEMA_KEYS.varSpec, `${ctxPath}.vars.${vk}`);
    }
  }
  for (const [i, ml] of (ext.metaLine ?? []).entries()) {
    assertAllowedKeys(ml, SCHEMA_KEYS.bullet, `${ctxPath}.metaLine[${i}]`);
  }
  for (const [i, b] of (ext.bullets ?? []).entries()) {
    assertAllowedKeys(b, SCHEMA_KEYS.bullet, `${ctxPath}.bullets[${i}]`);
  }
  for (const [i, sec] of (ext.sections ?? []).entries()) {
    assertAllowedKeys(sec, SCHEMA_KEYS.section, `${ctxPath}.sections[${i}]`);
    for (const [ci, col] of (sec.columns ?? []).entries()) {
      assertAllowedKeys(col, SCHEMA_KEYS.column, `${ctxPath}.sections[${i}].columns[${ci}]`);
    }
    if (sec.itemVars) {
      for (const [ivk, ivs] of Object.entries(sec.itemVars)) {
        assertAllowedKeys(ivs, SCHEMA_KEYS.varSpec, `${ctxPath}.sections[${i}].itemVars.${ivk}`);
      }
    }
  }
  if (ext.xml) {
    assertAllowedKeys(ext.xml, SCHEMA_KEYS.xml, `${ctxPath}.xml`);
    if (ext.xml.itemVars) {
      for (const [xk, xv] of Object.entries(ext.xml.itemVars)) {
        assertAllowedKeys(xv, SCHEMA_KEYS.xmlItemVar, `${ctxPath}.xml.itemVars.${xk}`);
      }
    }
  }
}

function hasRawDotOrBackslashPathSegments(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.includes('\\')) return true;
  if (/%5c/i.test(rawUrl)) return true;
  if (!rawUrl.startsWith('https://')) return true;
  const afterScheme = rawUrl.slice('https://'.length);
  const qOrHash = afterScheme.search(/[?#]/);
  const authAndPath = qOrHash >= 0 ? afterScheme.slice(0, qOrHash) : afterScheme;
  const firstSlash = authAndPath.indexOf('/');
  if (firstSlash < 0) return false;
  const rawPath = authAndPath.slice(firstSlash);
  for (const seg of rawPath.split('/')) {
    if (seg === '.' || seg === '..') return true;
    const dotDecoded = seg.replace(/%2e/gi, '.');
    if (dotDecoded === '.' || dotDecoded === '..') return true;
  }
  return false;
}

function isSafePublicHost(fetchUrl) {
  if (!fetchUrl.startsWith('https://') || /[\s\\]/.test(fetchUrl)) return false;
  if (hasRawDotOrBackslashPathSegments(fetchUrl)) return false;
  try {
    const u = new URL(fetchUrl);
    if (u.protocol !== 'https:' || u.username || u.password || u.hash) return false;
    if (u.port && u.port !== '443') return false;
    const h = u.hostname.toLowerCase().replace(/\.+$/, '');
    if (
      !h || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') ||
      h.endsWith('.internal') || h.endsWith('.nip.io') || h.endsWith('.sslip.io') ||
      h.endsWith('.xip.io') || !h.includes('.') || h.includes(':') ||
      isPublicOrPrivateSuffix(h) || hasPrivateSharedHostingSuffix(h)
    ) {
      return false;
    }
    const labels = h.split('.');
    if (labels.some((l) => !l)) return false;
    const tld = labels[labels.length - 1];
    if (tld.charCodeAt(0) >= 48 && tld.charCodeAt(0) <= 57) return false;
    return true;
  } catch {
    return false;
  }
}

function validateTwin(manifest, twin, ctxPath) {
  assertAllowedKeys(twin, SCHEMA_KEYS.twin, ctxPath);
  if (twin.kind !== 'json' && twin.kind !== 'text') {
    throw new Error(`${ctxPath}.kind: must be "json" or "text"`);
  }
  if (twin.id !== undefined && !VALID_ID_RE.test(twin.id)) {
    throw new Error(`${ctxPath}.id: invalid twin id "${twin.id}"`);
  }
  if (
    twin.maxBytes !== undefined &&
    (!Number.isInteger(twin.maxBytes) || twin.maxBytes < 16_384 || twin.maxBytes > 4 * 1024 * 1024)
  ) {
    throw new Error(`${ctxPath}.maxBytes: must be an integer between 16384 and 4194304`);
  }
  if (twin.overridePathIf) {
    assertAllowedKeys(twin.overridePathIf, SCHEMA_KEYS.overridePathIf, `${ctxPath}.overridePathIf`);
  }
  const fu = twin.fetchUrl;
  if (typeof fu !== 'string' || !fu.trim()) {
    throw new Error(`${ctxPath}.fetchUrl: required`);
  }
  if (fu !== '{requestUrl}') {
    if (fu.includes('\\') || /%5c/i.test(fu)) {
      throw new Error(`${ctxPath}.fetchUrl: backslash is forbidden in "${fu}" (M11)`);
    }
    if (!fu.startsWith('https://') && !fu.startsWith('{origin}/')) {
      throw new Error(`${ctxPath}.fetchUrl: must start with https:// (got "${fu}")`);
    }
    if (fu.includes('{host}') || fu.includes('{origin}')) {
      if (
        (!fu.startsWith('https://{host}/') && !fu.startsWith('{origin}/')) ||
        fu.startsWith('https://{host}//') ||
        fu.startsWith('{origin}//')
      ) {
        throw new Error(`${ctxPath}.fetchUrl: {host}/{origin} must be bound strictly to https://{host}/... or {origin}/... (M2)`);
      }
      const restAfterOrigin = fu.startsWith('https://{host}/') ? fu.slice('https://{host}/'.length) : fu.slice('{origin}/'.length);
      if (restAfterOrigin.includes('{origin}')) {
        throw new Error(`${ctxPath}.fetchUrl: {origin} must not appear more than once in "${fu}" (M2)`);
      }
      const dynSample = fu
        .replace(/^https:\/\/\{host\}\//, 'https://example.com/')
        .replace(/^\{origin\}\//, 'https://example.com/')
        .replace(/\{[A-Za-z0-9_]+\}/g, 'sample');
      if (!isSafePublicHost(dynSample) || new URL(dynSample).hostname.toLowerCase() !== 'example.com') {
        throw new Error(`${ctxPath}.fetchUrl: failed same-origin public HTTPS check ("${fu}")`);
      }
    }
    if (!fu.startsWith('https://{host}/') && !fu.startsWith('{origin}/')) {
      const sample = fu.replace(/\{[A-Za-z0-9_]+\}/g, 'sample');
      if (!isSafePublicHost(sample)) {
        throw new Error(`${ctxPath}.fetchUrl: failed public HTTPS host check ("${fu}")`);
      }
      const targetHost = new URL(sample).hostname.toLowerCase().replace(/\.+$/, '');
      const targetReg = getRegistrableDomain(targetHost);
      const manifestRegs = claimedRegistrableDomains(manifest.domains);
      const approvedCross = APPROVED_CROSS_DOMAIN_TWIN_HOSTS.get(manifest.id);
      if (
        (!targetReg || !manifestRegs.has(targetReg)) &&
        !(approvedCross && approvedCross.has(targetHost))
      ) {
        throw new Error(
          `${ctxPath}.fetchUrl: cross-domain twin host "${targetHost}" does not match manifest registrable domains and is not in APPROVED_CROSS_DOMAIN_TWIN_HOSTS (H7)`,
        );
      }
    }
  }
}

export function validateManifest(m, fileLabel) {
  const assertStringArray = (val, fieldPath) => {
    if (!Array.isArray(val) || !val.every((x) => typeof x === 'string')) {
      throw new Error(`${fieldPath}: must be string[]`);
    }
  };
  assertAllowedKeys(m, SCHEMA_KEYS.manifest, fileLabel);
  if (typeof m.id !== 'string' || !VALID_ID_RE.test(m.id)) {
    throw new Error(`${fileLabel}: invalid id "${m.id}"`);
  }
  if (typeof m.name !== 'string' || m.name.trim().length < 2) {
    throw new Error(`${fileLabel}: missing name`);
  }
  if (!VALID_CATEGORIES.has(m.category)) {
    throw new Error(`${fileLabel}: invalid category "${m.category}"`);
  }
  if (typeof m.description !== 'string' || m.description.trim().length < 10) {
    throw new Error(`${fileLabel}: description too short`);
  }
  if (!Array.isArray(m.domains) || m.domains.length === 0 || !m.domains.every((d) => typeof d === 'string' && d.trim())) {
    throw new Error(`${fileLabel}: domains must be non-empty string[]`);
  }
  const seenInManifest = new Set();
  for (const rawPat of m.domains) {
    const pat = normalizeManifestDomainPattern(rawPat);
    if (!pat || !isAsciiPrintable(pat) || /[\s/\\:?#@]/.test(pat) || pat === '*' || pat === '*.*') {
      throw new Error(`${fileLabel}: invalid or overly broad domain "${rawPat}" (M2)`);
    }
    if (seenInManifest.has(pat)) {
      throw new Error(`${fileLabel}: duplicate domain "${pat}" within manifest "${m.id}" (M2)`);
    }
    seenInManifest.add(pat);
    if (RESERVED_CORE_ATS_DOMAINS.has(pat)) {
      throw new Error(`${fileLabel}: domain "${rawPat}" is reserved by a built-in core ATS adapter and cannot be hijacked`);
    }
    if (pat.includes('*')) {
      if (pat.startsWith('*.') && !pat.slice(2).includes('*')) {
        const suffix = pat.slice(2);
        const isBuiltInShopify = m.id === 'shopify' && pat === '*.myshopify.com';
        if (!isBuiltInShopify && (isPublicOrPrivateSuffix(suffix) || hasPrivateSharedHostingSuffix(suffix))) {
          throw new Error(`${fileLabel}: overly broad TLD/eTLD/hosting wildcard "${rawPat}" is forbidden (M2)`);
        }
      }
      if (!APPROVED_WILDCARD_DOMAIN_PATTERNS.has(pat)) {
        throw new Error(
          `${fileLabel}: unapproved wildcard domain "${rawPat}" is forbidden — must be explicitly allowlisted in APPROVED_WILDCARD_DOMAIN_PATTERNS`,
        );
      }
    } else if (isPublicOrPrivateSuffix(pat) || hasPrivateSharedHostingSuffix(pat)) {
      throw new Error(`${fileLabel}: public or private shared-hosting suffix in domain "${rawPat}" is forbidden (H7)`);
    }
  }
  if (!Array.isArray(m.exampleUrls) || m.exampleUrls.length === 0 || !m.exampleUrls.every((u) => typeof u === 'string' && u.startsWith('https://'))) {
    throw new Error(`${fileLabel}: exampleUrls must be non-empty https:// string[]`);
  }

  const hasSingle = Boolean(m.match || m.twin || m.extract);
  if (hasSingle && (!m.match || !m.twin || !m.extract)) {
    throw new Error(`${fileLabel}: single-route manifest must specify match, twin, and extract together`);
  }
  if (hasSingle) {
    validateMatch(m.match, `${fileLabel}.match`);
    validateTwin(m, m.twin, `${fileLabel}.twin`);
    validateExtract(m.extract, `${fileLabel}.extract`);
  }
  for (const [i, r] of (m.routes ?? []).entries()) {
    assertAllowedKeys(r, SCHEMA_KEYS.route, `${fileLabel}.routes[${i}]`);
    validateMatch(r.match, `${fileLabel}.routes[${i}].match`);
    validateTwin(m, r.twin, `${fileLabel}.routes[${i}].twin`);
    validateExtract(r.extract, `${fileLabel}.routes[${i}].extract`);
  }
  for (const [i, hr] of (m.htmlRoutes ?? []).entries()) {
    assertAllowedKeys(hr, SCHEMA_KEYS.htmlRoute, `${fileLabel}.htmlRoutes[${i}]`);
    if (hr.id !== undefined && !VALID_ID_RE.test(hr.id)) {
      throw new Error(`${fileLabel}.htmlRoutes[${i}].id: invalid "${hr.id}"`);
    }
    if (typeof hr.mode !== 'string' || !VALID_HTML_MODES.has(hr.mode)) {
      throw new Error(
        `${fileLabel}.htmlRoutes[${i}].mode: must be one of [${[...VALID_HTML_MODES].join(', ')}] (got "${String(hr.mode)}")`,
      );
    }
    for (const arrField of ['jsonLdTypes', 'requireVars', 'requireBulletsOrVars', 'linkTemplates']) {
      if (hr[arrField] !== undefined) {
        assertStringArray(hr[arrField], `${fileLabel}.htmlRoutes[${i}].${arrField}`);
      }
    }
    validateMatch(hr.match, `${fileLabel}.htmlRoutes[${i}].match`);
    if (hr.vars) {
      for (const [vk, vs] of Object.entries(hr.vars)) {
        assertAllowedKeys(vs, SCHEMA_KEYS.htmlVar, `${fileLabel}.htmlRoutes[${i}].vars.${vk}`);
        for (const varArrField of [
          'jsonLdPaths',
          'embeddedPaths',
          'metaKeys',
          'cssText',
          'cssHtmlToMd',
          'whenVars',
          'whenAnyVars',
        ]) {
          if (vs[varArrField] !== undefined) {
            assertStringArray(vs[varArrField], `${fileLabel}.htmlRoutes[${i}].vars.${vk}.${varArrField}`);
          }
        }
        if (vs.cssAttr !== undefined) {
          if (
            !vs.cssAttr ||
            typeof vs.cssAttr !== 'object' ||
            Array.isArray(vs.cssAttr) ||
            typeof vs.cssAttr.selector !== 'string' ||
            typeof vs.cssAttr.attr !== 'string'
          ) {
            throw new Error(`${fileLabel}.htmlRoutes[${i}].vars.${vk}.cssAttr: must be { selector: string, attr: string }`);
          }
        }
        if (vs.cssAllText !== undefined) {
          if (
            !vs.cssAllText ||
            typeof vs.cssAllText !== 'object' ||
            Array.isArray(vs.cssAllText) ||
            typeof vs.cssAllText.selector !== 'string'
          ) {
            throw new Error(`${fileLabel}.htmlRoutes[${i}].vars.${vk}.cssAllText: must be { selector: string, ... }`);
          }
        }
      }
    }
    for (const [bi, b] of (hr.bullets ?? []).entries()) {
      assertAllowedKeys(b, SCHEMA_KEYS.bullet, `${fileLabel}.htmlRoutes[${i}].bullets[${bi}]`);
    }
    if (hr.extract) {
      validateExtract(hr.extract, `${fileLabel}.htmlRoutes[${i}].extract`);
    }
    if (hr.xml) {
      assertAllowedKeys(hr.xml, SCHEMA_KEYS.xml, `${fileLabel}.htmlRoutes[${i}].xml`);
    }
  }
  if (m.catalog) {
    assertAllowedKeys(m.catalog, SCHEMA_KEYS.catalog, `${fileLabel}.catalog`);
    if (typeof m.catalog.platform !== 'string' || !VALID_CATALOG_PLATFORMS.has(m.catalog.platform)) {
      throw new Error(
        `${fileLabel}.catalog.platform: must be "shopify" or "woocommerce" (got "${String(m.catalog.platform)}")`,
      );
    }
  }

  const totalRoutes = (hasSingle ? 1 : 0) + (m.routes?.length ?? 0) + (m.htmlRoutes?.length ?? 0) + (m.catalog ? 1 : 0);
  if (totalRoutes === 0) {
    throw new Error(`${fileLabel}: manifest defines no routes, htmlRoutes, or catalog`);
  }
}

export function validateManifestSet(manifestEntries) {
  const seenIds = new Set();
  const twinOwnerById = new Map();
  const exactOwners = new Map();
  const wildcardOwners = new Map();
  const wildcardClaims = [];
  const catalogOwnerByPlatform = new Map();

  for (const { obj, label } of manifestEntries) {
    validateManifest(obj, label);

    if (seenIds.has(obj.id)) {
      throw new Error(`${label}: duplicate manifest id "${obj.id}" (M2)`);
    }
    seenIds.add(obj.id);

    for (const rawDomain of obj.domains) {
      const normDomain = normalizeManifestDomainPattern(rawDomain);
      if (normDomain.includes('*')) {
        const prevWildOwner = wildcardOwners.get(normDomain);
        if (prevWildOwner && prevWildOwner !== obj.id) {
          throw new Error(
            `${label}: wildcard domain "${normDomain}" overlaps "${normDomain}" already claimed by manifest "${prevWildOwner}" (H7)`,
          );
        }
        for (const [prevExact, prevOwner] of exactOwners.entries()) {
          if (prevOwner === obj.id) continue;
          if (matchesApprovedWildcard(normDomain, prevExact) && !isExemptSapAtsExactClaim(obj.id, normDomain, prevOwner, prevExact)) {
            throw new Error(
              `${label}: wildcard "${normDomain}" overlaps exact domain "${prevExact}" already claimed by manifest "${prevOwner}" (H7)`,
            );
          }
        }
        for (const prevWild of wildcardClaims) {
          if (prevWild.id === obj.id) continue;
          if (matchesApprovedWildcard(normDomain, prevWild.pattern) || matchesApprovedWildcard(prevWild.pattern, normDomain)) {
            throw new Error(
              `${label}: wildcard "${normDomain}" overlaps "${prevWild.pattern}" already claimed by manifest "${prevWild.id}" (H7)`,
            );
          }
        }
        wildcardOwners.set(normDomain, obj.id);
        wildcardClaims.push({ id: obj.id, pattern: normDomain });
      } else {
        const prevExactOwner = exactOwners.get(normDomain);
        if (prevExactOwner && prevExactOwner !== obj.id) {
          throw new Error(
            `${label}: duplicate domain "${normDomain}" overlaps claim by manifest "${prevExactOwner}" (M2)`,
          );
        }
        for (const prevWild of wildcardClaims) {
          if (prevWild.id === obj.id) continue;
          if (matchesApprovedWildcard(prevWild.pattern, normDomain) && !isExemptSapAtsExactClaim(prevWild.id, prevWild.pattern, obj.id, normDomain)) {
            throw new Error(
              `${label}: domain "${normDomain}" overlaps "${prevWild.pattern}" already claimed by manifest "${prevWild.id}" (H7 cross-manifest collision)`,
            );
          }
        }
        exactOwners.set(normDomain, obj.id);
      }
    }

    if (obj.catalog !== undefined) {
      const plat = String(obj.catalog.platform ?? '').trim().toLowerCase();
      if (!VALID_CATALOG_PLATFORMS.has(plat)) {
        throw new Error(`${label}: unsupported catalog platform "${String(obj.catalog.platform)}"`);
      }
      const prevCatOwner = catalogOwnerByPlatform.get(plat);
      if (prevCatOwner && prevCatOwner !== obj.id) {
        throw new Error(`${label}: catalog platform "${plat}" already claimed by manifest "${prevCatOwner}"`);
      }
      catalogOwnerByPlatform.set(plat, obj.id);
    }

    const routes = obj.routes?.length ? obj.routes : obj.match && obj.twin && obj.extract ? [{ twin: obj.twin }] : [];
    for (const r of routes) {
      const tid = r.twin.id || obj.id;
      const prev = twinOwnerById.get(tid);
      if (prev && prev !== obj.id) {
        throw new Error(`${label}: duplicate twin id "${tid}" already owned by "${prev}" (M2)`);
      }
      twinOwnerById.set(tid, obj.id);
    }
  }
}

const isMainModule =
  Boolean(process.argv[1]) &&
  resolve(process.argv[1]).replace(/\\/g, '/').endsWith('/compile-manifests.mjs') &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMainModule) {
  const yamlFiles = readdirSync(manifestsDir)
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    .sort((a, b) => a.localeCompare(b));

  if (yamlFiles.length === 0) {
    console.error(`No .yaml manifests found in ${manifestsDir}`);
    process.exit(1);
  }

  const parsedEntries = [];
  for (const file of yamlFiles) {
    const fullPath = join(manifestsDir, file);
    const raw = readFileSync(fullPath, 'utf8');
    const doc = parseDocument(raw, {
      maxAliasCount: 0,
      merge: false,
      uniqueKeys: true,
      schema: 'core',
    });
    if (doc.errors.length > 0) {
      throw new Error(`${file}: YAML syntax error: ${doc.errors[0].message}`);
    }
    checkAstSafety(doc.contents, file);
    const obj = doc.toJS({ maxAliasCount: 0 });
    parsedEntries.push({ obj, label: file });
  }

  validateManifestSet(parsedEntries);
  const manifests = parsedEntries.map((e) => e.obj);
  const canonicalJson = `${JSON.stringify({ version: 2, manifests }, null, 2)}\n`;

  if (checkOnly) {
    const existing = existsSync(outPath) ? readFileSync(outPath, 'utf8').replace(/\r\n/g, '\n') : '';
    if (existing !== canonicalJson) {
      console.error('internal/extract/manifests/compiled.json is out of date. Run: npm run adapter:compile');
      process.exit(1);
    }
    console.log(`✔ Verified ${manifests.length} declarative YAML manifests match compiled.json.`);
  } else {
    const existing = existsSync(outPath) ? readFileSync(outPath, 'utf8').replace(/\r\n/g, '\n') : '';
    if (existing !== canonicalJson) {
      writeFileSync(outPath, canonicalJson, 'utf8');
    }
    console.log(`✔ Compiled ${manifests.length} declarative YAML manifests -> internal/extract/manifests/compiled.json`);
  }
}
