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
import { fileURLToPath } from 'node:url';
import { isAlias, isMap, isPair, isScalar, isSeq, parseDocument } from 'yaml';

const hubRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
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

const FORBIDDEN_BROAD_SUFFIXES = new Set([
  'com', 'org', 'net', 'io', 'gov', 'edu', 'mil', 'int',
  'uk', 'de', 'fr', 'jp', 'au', 'ca', 'us', 'eu', 'ai', 'co', 'app', 'dev',
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk', 'plc.uk', 'ltd.uk', 'sch.uk',
  'com.au', 'org.au', 'gov.au', 'edu.au', 'net.au', 'asn.au', 'id.au',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp',
  'com.br', 'org.br', 'gov.br', 'edu.br', 'net.br', 'mil.br',
  'co.nz', 'org.nz', 'govt.nz', 'ac.nz', 'net.nz',
  'co.za', 'org.za', 'gov.za', 'ac.za', 'net.za',
  'co.in', 'org.in', 'gov.in', 'ac.in', 'net.in', 'res.in', 'edu.in',
  'com.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn', 'net.cn',
  'com.sg', 'org.sg', 'gov.sg', 'edu.sg', 'net.sg',
  'com.hk', 'org.hk', 'gov.hk', 'edu.hk', 'net.hk',
  'com.tw', 'org.tw', 'gov.tw', 'edu.tw', 'net.tw',
  'co.kr', 'or.kr', 'go.kr', 'ac.kr', 'ne.kr',
  'com.mx', 'org.mx', 'gob.mx', 'edu.mx', 'net.mx',
  'com.ar', 'org.ar', 'gob.ar', 'gov.ar', 'edu.ar',
  'com.tr', 'org.tr', 'gov.tr', 'edu.tr',
  'co.il', 'org.il', 'gov.il', 'ac.il',
  'co.id', 'or.id', 'go.id', 'ac.id',
  'com.my', 'org.my', 'gov.my', 'edu.my',
  'com.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'com.vn', 'org.vn', 'gov.vn', 'edu.vn',
  'co.th', 'or.th', 'go.th', 'ac.th',
  // Shared multi-tenant PaaS / static-hosting public suffixes (PSL private section)
  'github.io', 'gitlab.io', 'bitbucket.io', 'pages.dev', 'workers.dev', 'cloudflarepages.com', 'r2.dev',
  'vercel.app', 'now.sh', 'netlify.app', 'herokuapp.com', 'herokudns.com', 'fly.dev', 'onrender.com',
  'railway.app', 'surge.sh', 'web.app', 'firebaseapp.com', 'appspot.com', 'cloudfunctions.net', 'run.app',
  'amazonaws.com', 'cloudfront.net', 'azurewebsites.net', 'azurestaticapps.net', 'trafficmanager.net',
  'blogspot.com', 'wordpress.com', 'substack.com', 'ghost.io', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com',
]);

const MULTI_PART_PSL_SLD_RE =
  /^(?:co|com|org|net|gov|edu|ac|mil|or|ne|go|lg|gob|gouv|govt|nic|nom|sch|asn|id|med|res|jus|leg|ind)\.[a-z]{2,3}$/;
const US_CA_STATE_PSL_RE = /^[a-z]{2}\.(?:us|ca|gov|edu)$/;

function isForbiddenPublicOrHostingSuffix(rest) {
  if (!rest || !rest.includes('.')) return true;
  if (FORBIDDEN_BROAD_SUFFIXES.has(rest)) return true;
  if (MULTI_PART_PSL_SLD_RE.test(rest) || US_CA_STATE_PSL_RE.test(rest)) return true;
  for (const hs of [
    '.amazonaws.com', '.cloudfront.net', '.azurewebsites.net', '.herokuapp.com',
    '.pages.dev', '.workers.dev', '.github.io', '.gitlab.io', '.vercel.app', '.netlify.app',
  ]) {
    if (rest.endsWith(hs)) return true;
  }
  return false;
}

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
    'id', 'fetchUrl', 'rawPathParams', 'overridePathIf', 'setQueryParams', 'defaultQueryParams', 'kind', 'accept',
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

function checkAstSafety(node, ctxPath) {
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

function isSafePublicHost(fetchUrl) {
  if (!fetchUrl.startsWith('https://') || /[\s\\]/.test(fetchUrl)) return false;
  try {
    const u = new URL(fetchUrl);
    if (u.protocol !== 'https:' || u.username || u.password || u.hash) return false;
    if (u.port && u.port !== '443') return false;
    const h = u.hostname.toLowerCase().replace(/\.+$/, '');
    if (
      !h || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') ||
      h.endsWith('.internal') || h.endsWith('.nip.io') || h.endsWith('.sslip.io') ||
      h.endsWith('.xip.io') || !h.includes('.') || h.includes(':')
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
  if (twin.overridePathIf) {
    assertAllowedKeys(twin.overridePathIf, SCHEMA_KEYS.overridePathIf, `${ctxPath}.overridePathIf`);
  }
  const fu = twin.fetchUrl;
  if (typeof fu !== 'string' || !fu.trim()) {
    throw new Error(`${ctxPath}.fetchUrl: required`);
  }
  if (fu !== '{requestUrl}') {
    if (!fu.startsWith('https://') && !fu.startsWith('{origin}/')) {
      throw new Error(`${ctxPath}.fetchUrl: must start with https:// (got "${fu}")`);
    }
    const hasWildcard = Boolean(manifest.universalEngine) || manifest.domains.some((d) => d.includes('*'));
    if ((fu.includes('{host}') || fu.includes('{origin}')) && hasWildcard) {
      if (!fu.startsWith('https://{host}/') && !fu.startsWith('{origin}/')) {
        throw new Error(`${ctxPath}.fetchUrl: {host}/{origin} must be same-origin on wildcard/universal adapters (M2)`);
      }
    }
    if (!fu.startsWith('https://{host}') && !fu.startsWith('{origin}')) {
      const sample = fu.replace(/\{[A-Za-z0-9_]+\}/g, 'sample');
      if (!isSafePublicHost(sample)) {
        throw new Error(`${ctxPath}.fetchUrl: failed public HTTPS host check ("${fu}")`);
      }
    }
  }
}

function validateManifest(m, fileLabel) {
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
  for (const rawPat of m.domains) {
    const pat = rawPat.trim().toLowerCase();
    if (!isAsciiPrintable(pat) || /[\s/\\:?#@]/.test(pat) || pat === '*' || pat === '*.*') {
      throw new Error(`${fileLabel}: invalid or overly broad domain "${rawPat}" (M2)`);
    }
    if (pat.startsWith('*.')) {
      const rest = pat.slice(2);
      if (isForbiddenPublicOrHostingSuffix(rest)) {
        throw new Error(`${fileLabel}: overly broad TLD/eTLD/hosting wildcard "${rawPat}" (M2)`);
      }
    }
    if (pat.endsWith('.*')) {
      const pre = pat.slice(0, -2);
      if (!pre || pre.includes('*') || pre.length < 3) {
        throw new Error(`${fileLabel}: invalid prefix wildcard "${rawPat}" (M2)`);
      }
    }
    if (pat.includes('*') && !APPROVED_WILDCARD_DOMAIN_PATTERNS.has(pat)) {
      throw new Error(`${fileLabel}: unapproved wildcard domain "${rawPat}" — must be explicitly allowlisted in APPROVED_WILDCARD_DOMAIN_PATTERNS`);
    }
    if (RESERVED_CORE_ATS_DOMAINS.has(pat)) {
      throw new Error(`${fileLabel}: domain "${rawPat}" is reserved by a built-in core ATS adapter and cannot be hijacked`);
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
    validateMatch(hr.match, `${fileLabel}.htmlRoutes[${i}].match`);
    if (hr.vars) {
      for (const [vk, vs] of Object.entries(hr.vars)) {
        assertAllowedKeys(vs, SCHEMA_KEYS.htmlVar, `${fileLabel}.htmlRoutes[${i}].vars.${vk}`);
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
  }

  const totalRoutes = (hasSingle ? 1 : 0) + (m.routes?.length ?? 0) + (m.htmlRoutes?.length ?? 0) + (m.catalog ? 1 : 0);
  if (totalRoutes === 0) {
    throw new Error(`${fileLabel}: manifest defines no routes, htmlRoutes, or catalog`);
  }
}

const yamlFiles = readdirSync(manifestsDir)
  .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
  .sort((a, b) => a.localeCompare(b));

if (yamlFiles.length === 0) {
  console.error(`No .yaml manifests found in ${manifestsDir}`);
  process.exit(1);
}

const seenIds = new Set();
const twinOwnerById = new Map();
const domainOwnerByPattern = new Map();
const catalogOwnerByPlatform = new Map();
const manifests = [];

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
  validateManifest(obj, file);

  if (seenIds.has(obj.id)) {
    throw new Error(`${file}: duplicate manifest id "${obj.id}" (M2)`);
  }
  seenIds.add(obj.id);

  for (const rawDomain of obj.domains) {
    const normDomain = rawDomain.trim().toLowerCase();
    const prevDomOwner = domainOwnerByPattern.get(normDomain);
    if (prevDomOwner && prevDomOwner !== obj.id) {
      throw new Error(`${file}: domain "${normDomain}" already claimed by manifest "${prevDomOwner}" (cross-manifest collision)`);
    }
    domainOwnerByPattern.set(normDomain, obj.id);
  }

  if (obj.catalog?.platform) {
    const plat = String(obj.catalog.platform).trim().toLowerCase();
    const prevCatOwner = catalogOwnerByPlatform.get(plat);
    if (prevCatOwner && prevCatOwner !== obj.id) {
      throw new Error(`${file}: catalog platform "${plat}" already claimed by manifest "${prevCatOwner}"`);
    }
    catalogOwnerByPlatform.set(plat, obj.id);
  }

  const routes = obj.routes?.length ? obj.routes : obj.match && obj.twin && obj.extract ? [{ twin: obj.twin }] : [];
  for (const r of routes) {
    const tid = r.twin.id || obj.id;
    const prev = twinOwnerById.get(tid);
    if (prev && prev !== obj.id) {
      throw new Error(`${file}: duplicate twin id "${tid}" already owned by "${prev}" (M2)`);
    }
    twinOwnerById.set(tid, obj.id);
  }

  manifests.push(obj);
}

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
