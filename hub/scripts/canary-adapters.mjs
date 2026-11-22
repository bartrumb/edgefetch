#!/usr/bin/env node
/**
 * EdgeFetch Ring 1 Polite Adapter Canary & Prompt-Injection-Free Health Reporter (`hub/scripts/canary-adapters.mjs`).
 *
 *   node scripts/canary-adapters.mjs --out ../docs/adapter-health.json          # Deterministic offline validation (< 2s)
 *   node scripts/canary-adapters.mjs --live --out ../docs/adapter-health.json   # Polite live HTTP canary (robots.txt + SSRF + >=1.2s/host)
 *   node scripts/canary-adapters.mjs --live --limit 5
 *
 * Security Invariants:
 *  1. Dial-time DNS-rebinding SSRF protection via `createSafeOutboundFetch({ pinResolvedIp: true })`.
 *  2. Fetches `https://<origin>/robots.txt` FIRST on every origin (both `exampleUrl` and cross-origin `twin.fetchUrl`, plus any redirect hop)
 *     using `EdgeFetch-Canary/2.7 (+https://edgefetch.dev/adapters/status/)` and honors `Disallow` and `Content-Signal: ai-input=no`.
 *  3. Enforces `>= 1,200ms` per-host politeness pacing, `15s` request timeout, and immediate zero-retry halt on HTTP 401/403/429/5xx or WAF challenges.
 *  4. Hostile-HTML / JSON Prompt-Injection Defense: `adapter-health.json` NEVER stores raw scraped prose, titles, descriptions,
 *     error messages, or HTML snippets from upstream websites — ONLY sanitized structural diagnostics (`kind`, `/^[A-Za-z0-9_.-]{1,40}$/`
 *     JSON keys capped at 15, integer `rootTagCount`, `wordCount`, and `recordCount`).
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseDocument } from 'yaml';

export const CANARY_USER_AGENT = 'EdgeFetch-Canary/2.7 (+https://edgefetch.dev/adapters/status/)';
export const DEFAULT_POLITENESS_MS = 1_200;
export const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_LIVE_BODY_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECT_HOPS = 3;
const SAFE_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const SAFE_JSON_KEY_RE = /^[A-Za-z0-9_.-]{1,40}$/;
const MAX_JSON_KEYS = 15;

function resolveHubRoot() {
  if (process.env.EDGEFETCH_HUB_ROOT) {
    return resolve(process.env.EDGEFETCH_HUB_ROOT);
  }
  const fromModule = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  if (existsSync(join(fromModule, 'src', 'extractors', 'registry.ts'))) {
    return fromModule;
  }
  const cwd = resolve(process.cwd());
  if (existsSync(join(cwd, 'src', 'extractors', 'registry.ts'))) {
    return cwd;
  }
  return resolve(cwd, 'hub');
}

const hubRoot = resolveHubRoot();
const scriptsDir = join(hubRoot, 'scripts');
const repoRoot = resolve(hubRoot, '..');
const defaultManifestsDir = join(repoRoot, 'internal', 'extract', 'manifests');
const defaultFixturesDir = join(hubRoot, 'test', 'fixtures', 'adapters');
const hubRequire = createRequire(join(hubRoot, 'package.json'));

let cachedRuntimePromise = null;

async function loadBundledHubRuntime() {
  if (cachedRuntimePromise) return cachedRuntimePromise;
  cachedRuntimePromise = (async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'ef-adapter-canary-'));
    const harnessEntry = join(tmp, 'entry.ts');
    const harnessBundle = join(tmp, 'bundle.mjs');
    writeFileSync(
      harnessEntry,
      `
export {
  applyPostFetchSiteExtractor,
  getRawRegisteredSiteAdapters,
  GO_KIND_TEXT_ACCEPT_ALLOWLIST,
  resolveSiteExtractorTwin,
} from ${JSON.stringify(join(hubRoot, 'src', 'extractors', 'registry.ts'))};
export { runAdapterSyncInBulkhead } from ${JSON.stringify(join(hubRoot, 'src', 'adapter-sandbox.ts'))};
export { extractHtmlDocument } from ${JSON.stringify(join(hubRoot, 'src', 'scrape.ts'))};
export {
  fetchOverflowRobots,
  isRobotsAllowed,
  resetOverflowRobotsCacheForTests,
  validatePublicHttpsTargetUrl,
} from ${JSON.stringify(join(hubRoot, 'src', 'overflow.ts'))};
export { classifyWafAndChallenge } from ${JSON.stringify(join(hubRoot, 'src', 'waf.ts'))};
export { createSafeOutboundFetch } from ${JSON.stringify(join(hubRoot, 'portable', 'safe-fetch.ts'))};
`,
      'utf8',
    );
    try {
      const { buildSync } = hubRequire('esbuild');
      buildSync({
        entryPoints: [harnessEntry],
        bundle: true,
        platform: 'node',
        target: 'node22',
        format: 'esm',
        banner: {
          js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);",
        },
        alias: { 'cloudflare:workers': join(hubRoot, 'test', 'cloudflare-workers-stub.ts') },
        loader: { '.sql': 'text', '.yaml': 'text', '.yml': 'text' },
        external: ['node:*'],
        outfile: harnessBundle,
      });
      return await import(pathToFileURL(harnessBundle).href);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  })();
  return cachedRuntimePromise;
}

/**
 * Filters raw JSON object property names strictly to `/^[A-Za-z0-9_.-]{1,40}$/` (max 15 keys)
 * so hostile keys like `"IGNORE PREVIOUS INSTRUCTIONS"` are dropped completely.
 */
export function sanitizeTopLevelJsonKeys(rawKeys) {
  if (!Array.isArray(rawKeys)) return [];
  const out = [];
  const seen = new Set();
  for (const k of rawKeys) {
    if (typeof k !== 'string') continue;
    if (!SAFE_JSON_KEY_RE.test(k)) continue;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(k);
    if (out.length >= MAX_JSON_KEYS) break;
  }
  return out;
}

function countHtmlRootTagsLinear(raw) {
  if (typeof raw !== 'string' || !raw) return 0;
  const limit = Math.min(raw.length, 65_536);
  let count = 0;
  for (let i = 0; i < limit - 1; i++) {
    if (raw.charCodeAt(i) !== 60 /* '<' */) continue;
    const next = raw.charCodeAt(i + 1);
    if ((next >= 65 && next <= 90) || (next >= 97 && next <= 122)) {
      count++;
    }
  }
  return count;
}

function countMarkdownWords(md) {
  if (typeof md !== 'string' || !md.trim()) return 0;
  const bounded = md.length > 131_072 ? md.slice(0, 131_072) : md;
  const tokens = bounded.match(/[\p{L}\p{N}_'-]+/gu);
  return tokens ? tokens.length : 0;
}

/**
 * Produces a strictly prompt-injection-free structural diagnostic.
 * Zero prose, titles, descriptions, error strings, or HTML snippets from `rawBody` or `doc` can ever escape.
 */
export function buildStructuralDiagnostic({ rawBody = '', kind = 'html', doc = null }) {
  const safeKind = kind === 'json' || kind === 'text' ? kind : 'html';
  let topLevelJsonKeys = [];
  const trimmed = typeof rawBody === 'string' ? rawBody.trim() : '';

  if (safeKind === 'json' || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      const sampleObj = Array.isArray(parsed)
        ? parsed.find((item) => item && typeof item === 'object' && !Array.isArray(item))
        : parsed && typeof parsed === 'object'
          ? parsed
          : null;
      if (sampleObj) {
        topLevelJsonKeys = sanitizeTopLevelJsonKeys(Object.keys(sampleObj));
      }
    } catch {
      topLevelJsonKeys = [];
    }
  }

  const wordCount = Number.isInteger(doc?.markdown ? countMarkdownWords(doc.markdown) : 0)
    ? countMarkdownWords(doc?.markdown ?? '')
    : 0;
  const recordCount = Array.isArray(doc?.records) ? doc.records.length : 0;
  const out = {
    kind: safeKind,
    topLevelJsonKeys,
    wordCount,
    recordCount,
  };
  if (safeKind === 'html' || (safeKind === 'text' && trimmed.startsWith('<'))) {
    out.rootTagCount = countHtmlRootTagsLinear(rawBody);
  }
  return out;
}

function setDeepPath(root, dotPath, val, overwrite = false) {
  if (!dotPath || dotPath === '.') return;
  const parts = dotPath.split('.').filter(Boolean);
  let cur = root;
  for (let i = 0; i < parts.length - 1; i++) {
    const seg = parts[i];
    const nextSeg = parts[i + 1];
    const nextIsIdx = /^\d+$/.test(nextSeg);
    if (Array.isArray(cur) && /^\d+$/.test(seg)) {
      const idx = Number(seg);
      if (!cur[idx] || typeof cur[idx] !== 'object') cur[idx] = nextIsIdx ? [] : {};
      cur = cur[idx];
    } else {
      if (!cur[seg] || typeof cur[seg] !== 'object') cur[seg] = nextIsIdx ? [] : {};
      cur = cur[seg];
    }
  }
  const leaf = parts[parts.length - 1];
  if (Array.isArray(cur) && /^\d+$/.test(leaf)) {
    cur[Number(leaf)] = val;
  } else if (overwrite || cur[leaf] === undefined) {
    cur[leaf] = val;
  }
}

function buildSyntheticExtractPayload(ext, exampleUrl = 'https://docs.example.com/item-1') {
  if (!ext) return { kind: 'json', body: '{}' };
  const sampleText = 'Declarative synthetic structural verification summary for EdgeFetch adapter canary check.';
  const sampleUrl = 'https://docs.example.com/item-1';

  if (ext.textMode) {
    const body =
      ext.textMode === 'frontmatter_card'
        ? `---\npretty_name: Synthetic Model\nlicense: mit\ntags:\n  - nlp\n---\n# Synthetic Model Card\n\n${sampleText}`
        : ext.textMode === 'git_patch'
          ? `From 0123456789abcdef Mon Sep 17 00:00:00 2001\nSubject: [PATCH] Synthetic verification patch\n---\n a.txt | 1 +\n---\ndiff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1,2 @@\n+${sampleText}\n`
          : `# Synthetic Markdown Twin\n\n${sampleText}\n`;
    return { kind: 'text', body };
  }

  if (ext.icimsPortal) {
    return {
      kind: 'html',
      body: `<!doctype html><html><head><title>Careers Portal</title></head><body><div class="iCIMS_JobsTable"><div class="row"><a class="iCIMS_Anchor" href="https://careers-acme.icims.com/jobs/101/eng/job"><h3>Senior Systems Engineer</h3></a><span>Remote</span></div></div></body></html>`,
    };
  }

  if (ext.xml) {
    const itemTag = ext.xml.itemTag || 'item';
    const reqTags = ext.xml.requireAnyTags ?? [itemTag];
    const itemVarEntries = Object.entries(ext.xml.itemVars ?? {});
    const itemsXml = Array.from({ length: 3 }, (_, idx) => {
      const innerTags = itemVarEntries
        .map(([vn, vs]) => {
          const tName = vs.tags?.[0] || vn;
          const isLink = /link|url|guid/i.test(vn) || /link|url/i.test(tName);
          const val = isLink ? sampleUrl : `${vn} ${sampleText}`;
          return `<${tName}><![CDATA[${val}]]></${tName}>`;
        })
        .join('');
      return `<${itemTag}><title><![CDATA[Synthetic Item ${idx}]]></title><link>${sampleUrl}</link>${innerTags}</${itemTag}>`;
    }).join('');
    const extraReq = reqTags[0] ? `<${reqTags[0]}></${reqTags[0]}>` : '';
    const xmlBody =
      ext.xml.mode === 'jats_article'
        ? `<article><front><journal-meta><journal-title-group><journal-title>Synthetic Journal</journal-title></journal-title-group></journal-meta><article-meta><title-group><article-title>Synthetic Research Article</article-title></title-group><contrib-group><contrib contrib-type="author"><name><surname>Doe</surname><given-names>J</given-names></name></contrib></contrib-group><abstract><p>${sampleText}</p></abstract></article-meta></front><body><sec><title>Introduction</title><p>${sampleText}</p></sec></body></article>`
        : `<?xml version="1.0"?><rss version="2.0"><channel><title>Synthetic Feed</title>${extraReq}${itemsXml}</channel></rss>`;
    return { kind: 'text', body: xmlBody };
  }

  if (ext.commerceMode) {
    const wcItem = {
      id: 101,
      title: 'Synthetic Storefront Item',
      handle: 'item-1',
      name: 'Synthetic Woo Item',
      permalink: sampleUrl,
      short_description: `<p>${sampleText}</p>`,
      prices: { price: '1999', currency_code: 'USD', currency_minor_unit: 2 },
      variants: [{ id: 1, title: 'Default', price: '19.99', available: true }],
      images: [{ src: sampleUrl }],
    };
    if (ext.commerceMode === 'woocommerce_catalog_page') {
      return { kind: 'json', body: JSON.stringify([wcItem]) };
    }
    if (ext.commerceMode === 'woocommerce_product') {
      return { kind: 'json', body: JSON.stringify(wcItem) };
    }
    return {
      kind: 'json',
      body: JSON.stringify({
        product: {
          id: 101,
          title: 'Synthetic Travel Jacket',
          handle: 'jacket',
          vendor: 'Acme',
          body_html: `<p>${sampleText}</p>`,
          variants: [{ id: 1, title: 'M', price: '49.00', available: true, sku: 'SKU-1' }],
          images: [{ src: sampleUrl }],
        },
        products: [wcItem],
      }),
    };
  }

  const populateTargetObj = (target) => {
    for (const rf of ext.requireFields ?? []) setDeepPath(target, rf, sampleText);
    for (const raf of ext.requireAnyFields ?? []) setDeepPath(target, raf, sampleText);
    if (ext.requireFieldEquals?.path) {
      setDeepPath(target, ext.requireFieldEquals.path, ext.requireFieldEquals.value, true);
    }
    if (ext.codeByPath?.path) setDeepPath(target, ext.codeByPath.path, sampleText);
    if (ext.objectLinksPath) {
      setDeepPath(target, ext.objectLinksPath, { Homepage: sampleUrl });
    }
    for (const [vn, vs] of Object.entries(ext.vars ?? {})) {
      if (vs.format === 'array_len') continue;
      const p0 = vs.paths?.[0] || vn;
      const isUrl = Boolean(vs.requireHttps || vs.requireHttpPrefix || /url|link|homepage|repo/i.test(vn));
      const val = vs.nestedSubValues
        ? { sub1: { name: 'Synthetic Subitem', description: sampleText } }
        : vs.findInArrayLang
          ? [{ lang: 'en', value: sampleText }]
          : vs.subFieldsJoin || vs.subField
            ? [{ display_name: 'tag-1', name: 'tag-1', category: 'cat-1', keyword: 'kw-1' }]
            : isUrl
              ? sampleUrl
              : vs.format === 'usd_compact' ||
                  vs.format === 'int_locale' ||
                  vs.format === 'int_comma' ||
                  vs.format === 'duration' ||
                  vs.format === 'unix_date' ||
                  vs.format === 'usd_per_million_tokens'
                ? 1700000
                : sampleText;
      setDeepPath(target, p0, val);
    }
  };

  const obj = {};
  populateTargetObj(obj);

  if (ext.findInArray?.arrayPath) {
    const item = {};
    populateTargetObj(item);
    let urlPathValue = 'item-1';
    try {
      urlPathValue = new URL(exampleUrl).pathname.replace(/^\/+|\/+$/g, '') || 'item-1';
    } catch {
      // ignore
    }
    const mFields = ext.findInArray.matchFields ?? (ext.findInArray.matchField ? [ext.findInArray.matchField] : ['id']);
    for (const mf of mFields) {
      setDeepPath(item, mf, urlPathValue, true);
    }
    setDeepPath(obj, ext.findInArray.arrayPath, [item], true);
  }

  for (const sec of ext.sections ?? []) {
    if (sec.arrayPath) {
      const items = Array.from({ length: 3 }, (_, idx) => {
        const it = {
          id: `id-${idx}`,
          parent_id: null,
          depth: 0,
          title: `Synthetic Row ${idx}`,
          name: `row-${idx}`,
          text: sampleText,
          body: sampleText,
          url: sampleUrl,
        };
        if (ext.requireArrayItemField?.arrayPath === sec.arrayPath && ext.requireArrayItemField.field) {
          setDeepPath(it, ext.requireArrayItemField.field, { title: `Synthetic Row ${idx}` });
        }
        if (sec.filter?.field) {
          setDeepPath(it, sec.filter.field, sec.filter.equals ?? 'open', true);
        }
        for (const col of sec.columns ?? []) {
          if (col.paths?.[0]) setDeepPath(it, col.paths[0], col.format === 'usd_compact' ? 12500 : sampleText);
          if (col.outcomesField) setDeepPath(it, col.outcomesField, '["Yes","No"]');
          if (col.pricesField) setDeepPath(it, col.pricesField, '["0.65","0.35"]');
        }
        for (const [ivn, ivs] of Object.entries(sec.itemVars ?? {})) {
          if (ivs.paths?.[0]) {
            const val = ivs.subField
              ? [{ [ivs.subField]: 'Engineering' }]
              : /url|link/i.test(ivn) || ivs.requireHttps
                ? sampleUrl
                : sampleText;
            setDeepPath(it, ivs.paths[0], val);
          }
        }
        return it;
      });
      if (sec.arrayPath === '.') {
        obj.__rootArray = items;
      } else {
        setDeepPath(obj, sec.arrayPath, items, true);
      }
    }
    if (sec.subsectionsArrayPath) {
      setDeepPath(obj, sec.subsectionsArrayPath, [{ title: 'Details', name: 'Details', description: sampleText, text: sampleText }], true);
    }
    if (sec.listArrayPath) {
      setDeepPath(obj, sec.listArrayPath, [sampleText, 'Additional bullet'], true);
    }
    if (sec.parallelArrays) {
      setDeepPath(obj, sec.parallelArrays.keysPath, ['field_a', 'field_b'], true);
      setDeepPath(obj, sec.parallelArrays.rowsPath, [[sampleText, '42']], true);
    }
  }

  let finalRoot = obj.__rootArray ?? obj;
  if (ext.rootPath && ext.rootPath !== '.') {
    const wrapper = {};
    setDeepPath(wrapper, ext.rootPath, finalRoot, true);
    finalRoot = wrapper;
  }
  if (ext.unwrapFirstArrayElement) {
    finalRoot = [finalRoot];
  }
  if (ext.wrapRootArrayAs && Array.isArray(finalRoot)) {
    // already an array
  } else if (ext.wrapRootArrayAs && finalRoot && typeof finalRoot === 'object' && Array.isArray(finalRoot[ext.wrapRootArrayAs])) {
    finalRoot = finalRoot[ext.wrapRootArrayAs];
  } else if (ext.wrapRootArrayAs && !Array.isArray(finalRoot)) {
    finalRoot = [finalRoot];
  }
  return { kind: 'json', body: JSON.stringify(finalRoot) };
}

function buildSyntheticHtmlPayload(manifest) {
  const hr = manifest?.htmlRoutes?.[0];
  const sampleText = 'Declarative synthetic HTML verification body for EdgeFetch Ring 1 adapter canary.';
  if (!hr) {
    return {
      body: `<!doctype html><html><head><title>Synthetic Page</title></head><body><main><h1>Synthetic Page</h1><p>${sampleText}</p></main></body></html>`,
      currentMd: `# Synthetic Page\n\n${sampleText}`,
    };
  }
  if (hr.mode === 'embedded_json' && hr.extract) {
    const syn = buildSyntheticExtractPayload(hr.extract);
    if (hr.scriptId) {
      return {
        body: `<!doctype html><html><body><script id="${hr.scriptId}" type="application/json">${syn.body}</script></body></html>`,
        currentMd: sampleText,
      };
    }
    if (hr.dataAttr) {
      const attrSafe = syn.body.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
      return {
        body: `<!doctype html><html><body><div ${hr.dataAttr}="${attrSafe}"></div></body></html>`,
        currentMd: sampleText,
      };
    }
  }
  if (hr.mode === 'xml_items_table' && hr.xml) {
    const syn = buildSyntheticExtractPayload({ xml: hr.xml });
    return { body: syn.body, currentMd: '' };
  }
  if (hr.mode === 'markdown_clean') {
    if (hr.cleanPreset === 'jsr_io') {
      return {
        body: '<!doctype html><html><body><main><h1>@std/path</h1></main></body></html>',
        currentMd: `Skip to main content\n# @std/path\nPublished 2 days ago\nOverview Docs Versions Score\n\n${sampleText}`,
      };
    }
    return {
      body: '<!doctype html><html><head><meta name="generator" content="MediaWiki 1.43"></head><body><main><p>Wiki article</p></main></body></html>',
      currentMd: `# Synthetic Wiki Article [edit]\n\n${sampleText} [citation needed]\n\n## Navigation menu\nFooter`,
    };
  }
  if (hr.mode === 'gist_files') {
    return {
      body: `<!doctype html><html><head><title>demo.ts · GitHub</title></head><body><div itemprop="about">${sampleText}</div><div class="file"><div class="file-header"><strong class="gist-blob-name">demo.ts</strong></div><table><tr><td class="blob-code blob-code-inner">export const verifiedCanaryGist = true;</td></tr></table></div></body></html>`,
      currentMd: sampleText,
    };
  }
  if (hr.mode === 'stackexchange_html') {
    return {
      body: `<!doctype html><html><body><div id="question-header"><h1><a class="question-hyperlink">Synthetic Question Heading</a></h1></div><div id="question" data-score="12"><div class="js-post-body"><p>${sampleText}</p></div><a class="post-tag">go</a></div><div class="answer accepted-answer" data-score="25"><div class="js-post-body"><p>Accepted answer details for verification.</p></div></div></body></html>`,
      currentMd: sampleText,
    };
  }
  if (hr.mode === 'reddit_shreddit') {
    return {
      body: `<!doctype html><html><body><shreddit-post post-title="Synthetic Discussion Thread" author="alice" subreddit-prefixed-name="r/golang" score="99" comment-count="4"><div slot="text-body"><p>${sampleText}</p></div></shreddit-post><shreddit-comment author="bob" score="10"><div slot="comment"><p>Top reply text.</p></div></shreddit-comment></body></html>`,
      currentMd: sampleText,
    };
  }
  if (hr.mode === 'icims_portal') {
    const syn = buildSyntheticExtractPayload({ icimsPortal: true });
    return { body: syn.body, currentMd: sampleText };
  }
  if (hr.mode === 'shopify_html' || hr.mode === 'woocommerce_html') {
    return {
      body: `<!doctype html><html><head><script type="application/ld+json">${JSON.stringify({ '@context': 'https://schema.org', '@type': 'Product', name: 'Synthetic Product', description: sampleText, brand: { name: 'Acme' }, offers: { '@type': 'Offer', price: '29.99', priceCurrency: 'USD', availability: 'https://schema.org/InStock' } })}</script></head><body><h1>Synthetic Product</h1></body></html>`,
      currentMd: sampleText,
    };
  }

  const ldType = hr.jsonLdTypes?.[0] || 'Thing';
  const ldObj = {
    '@context': 'https://schema.org',
    '@type': ldType,
    name: 'Synthetic Structured Entity',
    title: 'Synthetic Structured Title',
    headline: 'Synthetic Structured Headline',
    description: sampleText,
    hiringOrganization: { name: 'Acme Corp' },
    url: 'https://docs.example.com/entity',
    author: { name: 'Author' },
    offers: { price: '9.99', priceCurrency: 'USD' },
    aggregateRating: { ratingValue: '4.8', ratingCount: '120' },
    molecularFormula: 'C8H10N4O2',
    molecularWeight: '194.19',
    inChIKey: 'RYYVLZVUVIJVGH-UHFFFAOYSA-N',
  };
  const metaTags = [];
  const domEls = [];
  for (const [vn, vs] of Object.entries(hr.vars ?? {})) {
    for (const mk of vs.metaKeys ?? []) {
      metaTags.push(`<meta name="${mk}" content="${vn} ${sampleText}">`);
    }
    if (vs.allMetaKey) {
      metaTags.push(`<meta name="${vs.allMetaKey}" content="Alice">`);
    }
    const toSelArr = (x) => (Array.isArray(x) ? x : typeof x === 'string' ? [x] : []);
    for (const sel of [...toSelArr(vs.cssText), ...toSelArr(vs.cssAllText), ...toSelArr(vs.cssHtmlToMd)]) {
      const s = sel.trim();
      const tagIdMatch = /^(?:([a-z0-9]+))?#([A-Za-z0-9_-]+)$/i.exec(s);
      const tagClassMatch = /^(?:([a-z0-9]+))?\.([A-Za-z0-9_-]+)$/i.exec(s);
      const tagAttrMatch = /^([a-z0-9]+)\[([A-Za-z0-9_-]+)=["']?([^"'\]\s]+)["']?\]$/i.exec(s);
      if (tagIdMatch) {
        const tag = tagIdMatch[1] || 'div';
        domEls.push(`<${tag} id="${tagIdMatch[2]}"><p>${sampleText}</p></${tag}>`);
      } else if (tagClassMatch) {
        const tag = tagClassMatch[1] || 'div';
        domEls.push(`<${tag} class="${tagClassMatch[2]}">${sampleText}</${tag}>`);
      } else if (tagAttrMatch) {
        const tag = tagAttrMatch[1];
        domEls.push(`<${tag} ${tagAttrMatch[2]}="${tagAttrMatch[3]}"><p>${sampleText}</p></${tag}>`);
      }
    }
  }
  const embScript = hr.embeddedBalancedKey
    ? `<script>window.__DATA = { "${hr.embeddedBalancedKey}": ${JSON.stringify({ name: 'Synthetic Entity', description: sampleText, title: 'Synthetic Title' })} };</script>`
    : '';
  return {
    body: `<!doctype html><html><head><title>Synthetic Page</title>${metaTags.join('')}<script type="application/ld+json">${JSON.stringify(ldObj)}</script>${embScript}</head><body><main><h1>Main Heading</h1>${domEls.join('')}<p>${sampleText}</p></main></body></html>`,
    currentMd: `# Main Heading\n\n${sampleText}`,
  };
}

function loadManifestFilesMap(manifestsDir) {
  const fileById = new Map();
  if (!existsSync(manifestsDir)) return fileById;
  for (const file of readdirSync(manifestsDir).sort((a, b) => a.localeCompare(b))) {
    if (!file.endsWith('.yaml') && !file.endsWith('.yml')) continue;
    const doc = parseDocument(readFileSync(join(manifestsDir, file), 'utf8'), {
      maxAliasCount: 0,
      merge: false,
      uniqueKeys: true,
      schema: 'core',
    });
    const js = doc.toJS({ maxAliasCount: 0 });
    if (js && typeof js.id === 'string') {
      fileById.set(js.id, file);
    }
  }
  return fileById;
}

function loadFixturesIndex(fixturesDir) {
  const byAdapterId = new Map();
  if (!existsSync(fixturesDir)) return byAdapterId;
  for (const file of readdirSync(fixturesDir).filter((f) => f.endsWith('.json')).sort((a, b) => a.localeCompare(b))) {
    const fx = JSON.parse(readFileSync(join(fixturesDir, file), 'utf8'));
    const list = byAdapterId.get(fx.adapterId) ?? [];
    list.push({ file, fx });
    byAdapterId.set(fx.adapterId, list);
  }
  return byAdapterId;
}

function resolveDeterministicOfflineTimestamp() {
  try {
    const iso = execFileSync('git', ['log', '-1', '--format=%cI', '--', 'internal/extract/manifests'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (iso) return new Date(iso).toISOString();
  } catch {
    // ignore fallback
  }
  return '2026-01-01T00:00:00.000Z';
}

async function readBoundedText(res, maxBytes) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        const keep = Math.min(value.byteLength, Math.max(0, maxBytes - total));
        if (keep > 0) {
          chunks.push(keep === value.byteLength ? value : value.subarray(0, keep));
          total += keep;
        }
        if (total >= maxBytes) {
          await reader.cancel().catch(() => undefined);
          break;
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(merged);
}

function isHealthyExtractedDoc(doc) {
  if (!doc || typeof doc !== 'object') return false;
  const mdLen = typeof doc.markdown === 'string' ? doc.markdown.trim().length : 0;
  const recLen = Array.isArray(doc.records) ? doc.records.length : 0;
  return mdLen >= 20 || recLen >= 1;
}

/**
 * Runs the EdgeFetch Ring 1 Adapter Canary in `'offline'` (deterministic validation) or `'live'` (polite HTTP) mode.
 */
export async function runAdapterCanary(options = {}) {
  const mode = options.mode === 'live' ? 'live' : 'offline';
  const limit =
    typeof options.limit === 'number' && Number.isInteger(options.limit) && options.limit > 0
      ? options.limit
      : undefined;
  const politenessMs =
    typeof options.politenessMs === 'number' && options.politenessMs >= 0
      ? options.politenessMs
      : DEFAULT_POLITENESS_MS;
  const timeoutMs =
    typeof options.timeoutMs === 'number' && options.timeoutMs > 0 ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
  const userAgent = options.userAgent ?? CANARY_USER_AGENT;

  if (!options.adapters && options.compileManifests !== false) {
    execFileSync(process.execPath, [join(scriptsDir, 'compile-manifests.mjs')], { stdio: 'pipe' });
  }

  const runtime = await loadBundledHubRuntime();
  const {
    getRawRegisteredSiteAdapters,
    GO_KIND_TEXT_ACCEPT_ALLOWLIST,
    runAdapterSyncInBulkhead,
    extractHtmlDocument,
    fetchOverflowRobots,
    isRobotsAllowed,
    resetOverflowRobotsCacheForTests,
    validatePublicHttpsTargetUrl,
    classifyWafAndChallenge,
    createSafeOutboundFetch,
  } = runtime;

  resetOverflowRobotsCacheForTests();

  const simpleHtmlToMd = (frag, base) => {
    const doc = extractHtmlDocument(`<!doctype html><html><body>${frag}</body></html>`, {
      baseUrl: base ?? 'https://example.com',
      onlyMainContent: false,
    });
    return { markdown: doc.markdown, links: doc.links };
  };

  const allAdapters = options.adapters ?? [...getRawRegisteredSiteAdapters()];
  const selected = limit ? allAdapters.slice(0, limit) : allAdapters;

  const compiledPath = join(defaultManifestsDir, 'compiled.json');
  const compiledManifests =
    options.manifests ??
    (existsSync(compiledPath) ? (JSON.parse(readFileSync(compiledPath, 'utf8')).manifests ?? []) : []);
  const manifestById = new Map(compiledManifests.map((m) => [m.id, m]));
  const manifestFileById = options.manifestFileById ?? loadManifestFilesMap(defaultManifestsDir);
  const fixturesByAdapterId = loadFixturesIndex(options.fixturesDir ?? defaultFixturesDir);

  const safeFetch =
    mode === 'live'
      ? (options.fetchFn ?? createSafeOutboundFetch({ pinResolvedIp: true, defaultTimeoutMs: timeoutMs }))
      : null;

  const lastHostRequestAt = new Map();
  const robotsByOrigin = new Map();

  const waitPoliteHostGap = async (hostname, extraDelayMs = 0) => {
    const effectiveGap = politenessMs === 0 ? 0 : Math.max(politenessMs, Math.min(extraDelayMs || 0, 5_000));
    if (effectiveGap <= 0) return;
    const key = hostname.toLowerCase();
    const prev = lastHostRequestAt.get(key);
    const now = Date.now();
    if (prev !== undefined && now - prev < effectiveGap) {
      const waitMs = effectiveGap - (now - prev);
      await new Promise((r) => setTimeout(r, waitMs));
    }
    lastHostRequestAt.set(key, Date.now());
  };

  const checkOriginRobots = async (targetUrlObj) => {
    const origin = targetUrlObj.origin;
    let rob = robotsByOrigin.get(origin);
    if (!rob) {
      await waitPoliteHostGap(targetUrlObj.hostname);
      rob = await fetchOverflowRobots(origin, userAgent, safeFetch, Date.now() + Math.min(timeoutMs, 10_000));
      robotsByOrigin.set(origin, rob);
    }
    if (rob.disallowAiInput) {
      return { state: 'robots_disallowed', rob };
    }
    if (rob.unreachable) {
      return { state: 'upstream_blocked', rob };
    }
    const pathAndQuery = `${targetUrlObj.pathname || '/'}${targetUrlObj.search || ''}`;
    if (!isRobotsAllowed(rob, pathAndQuery)) {
      return { state: 'robots_disallowed', rob };
    }
    return { state: 'allowed', rob };
  };

  const fetchPoliteTarget = async (initialUrlStr, acceptHeader) => {
    let curUrlStr = initialUrlStr;
    for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
      const urlCheck = validatePublicHttpsTargetUrl(curUrlStr);
      if (!urlCheck.ok) {
        return { outcome: 'broken', httpStatus: null, rawBody: '' };
      }
      const u = urlCheck.url;
      const robRes = await checkOriginRobots(u);
      if (robRes.state !== 'allowed') {
        return { outcome: robRes.state, httpStatus: null, rawBody: '' };
      }
      await waitPoliteHostGap(u.hostname, robRes.rob.crawlDelayMs);

      let res;
      try {
        res = await safeFetch(u.toString(), {
          method: 'GET',
          headers: {
            accept: acceptHeader,
            'user-agent': userAgent,
          },
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch {
        return { outcome: 'upstream_blocked', httpStatus: null, rawBody: '' };
      }

      if (res.status === 301 || res.status === 302 || res.status === 303 || res.status === 307 || res.status === 308) {
        const loc = res.headers.get('location');
        await res.body?.cancel().catch(() => undefined);
        if (!loc || hop === MAX_REDIRECT_HOPS) {
          return { outcome: 'broken', httpStatus: res.status, rawBody: '' };
        }
        let nextUrl;
        try {
          nextUrl = new URL(loc, u).toString();
        } catch {
          return { outcome: 'broken', httpStatus: res.status, rawBody: '' };
        }
        curUrlStr = nextUrl;
        continue;
      }

      const rawBody = await readBoundedText(res, MAX_LIVE_BODY_BYTES);
      const waf = classifyWafAndChallenge({ status: res.status, headers: res.headers, rawBody });
      if (res.status === 401 || res.status === 403 || res.status === 429 || res.status >= 500 || waf !== null) {
        return { outcome: 'upstream_blocked', httpStatus: res.status, rawBody };
      }
      if (res.status !== 200) {
        return { outcome: 'broken', httpStatus: res.status, rawBody };
      }
      return { outcome: 'ok', httpStatus: 200, rawBody, finalUrl: u.toString() };
    }
    return { outcome: 'broken', httpStatus: null, rawBody: '' };
  };

  const resolveAdapterTwinForUrl = (adapter, urlStr) => {
    if (typeof adapter.resolveTwin !== 'function') return null;
    const urlCheck = validatePublicHttpsTargetUrl(urlStr);
    if (!urlCheck.ok) return null;
    const u = urlCheck.url;
    const ctx = {
      url: u,
      urlStr,
      host: u.hostname.toLowerCase(),
      path: u.pathname,
      parts: u.pathname.split('/').filter(Boolean),
    };
    const twinBox = runAdapterSyncInBulkhead(adapter.id, (inp) => adapter.resolveTwin(inp), ctx);
    if (!twinBox.ok || !twinBox.value) return null;
    const twin = twinBox.value;
    const twinUrlCheck = validatePublicHttpsTargetUrl(twin.fetchUrl);
    if (!twinUrlCheck.ok) return null;
    return twin;
  };

  const results = [];

  for (const adapter of selected) {
    const modes = [];
    if (typeof adapter.resolveTwin === 'function') modes.push('twin');
    if (typeof adapter.extractHtml === 'function') modes.push('html');
    if (adapter.catalog) modes.push('catalog');

    const exampleUrl = adapter.exampleUrls?.[0] ?? '';
    const manifestFile = manifestFileById.get(adapter.id) ?? `${adapter.id}.yaml`;
    const rawManifest = manifestById.get(adapter.id);

    // Match fixtures by `adapter.id` or `<adapter.id>-*` twin IDs
    const matchedFixtures = [];
    for (const [fxAdapterId, list] of fixturesByAdapterId.entries()) {
      if (fxAdapterId === adapter.id || fxAdapterId.startsWith(`${adapter.id}-`)) {
        matchedFixtures.push(...list);
      }
    }

    if (mode === 'offline') {
      let validStructure =
        SAFE_ID_RE.test(adapter.id) &&
        typeof adapter.name === 'string' &&
        adapter.name.trim().length >= 2 &&
        typeof adapter.category === 'string' &&
        Array.isArray(adapter.domains) &&
        adapter.domains.length > 0 &&
        modes.length > 0 &&
        validatePublicHttpsTargetUrl(exampleUrl).ok;

      let fixtureVerified = false;
      let sampleRawBody = '';
      let sampleKind = modes.includes('twin') ? 'json' : 'html';
      let sampleDoc = null;

      if (validStructure && matchedFixtures.length > 0) {
        for (const { fx } of matchedFixtures) {
          if (fx.mode === 'twin') {
            const twin = resolveAdapterTwinForUrl(adapter, fx.inputUrl);
            if (!twin) {
              validStructure = false;
              break;
            }
            const outBox = runAdapterSyncInBulkhead(
              adapter.id,
              (inp) => twin.formatTwin(inp.mockPayload, inp.inputUrl, simpleHtmlToMd),
              { mockPayload: fx.mockPayload, inputUrl: fx.inputUrl },
            );
            if (!outBox.ok || !isHealthyExtractedDoc(outBox.value)) {
              validStructure = false;
              break;
            }
            sampleRawBody = fx.mockPayload;
            sampleKind = twin.kind === 'text' ? 'text' : 'json';
            sampleDoc = outBox.value;
          } else if (fx.mode === 'html' && typeof adapter.extractHtml === 'function') {
            const u = new URL(fx.inputUrl);
            const outBox = runAdapterSyncInBulkhead(
              adapter.id,
              (ctx) => adapter.extractHtml(ctx),
              {
                url: u,
                baseUrl: fx.inputUrl,
                host: u.hostname.toLowerCase(),
                path: u.pathname,
                parts: u.pathname.split('/').filter(Boolean),
                rawHtml: fx.mockPayload,
                currentMd: '',
                htmlToMd: simpleHtmlToMd,
              },
            );
            if (!outBox.ok || !isHealthyExtractedDoc(outBox.value)) {
              validStructure = false;
              break;
            }
            sampleRawBody = fx.mockPayload;
            sampleKind = 'html';
            sampleDoc = outBox.value;
          }
        }
        fixtureVerified = validStructure;
      }

      if (validStructure && !sampleDoc) {
        const twin = resolveAdapterTwinForUrl(adapter, exampleUrl);
        if (twin) {
          if (twin.kind === 'text' && !GO_KIND_TEXT_ACCEPT_ALLOWLIST.has(twin.accept)) {
            validStructure = false;
          } else {
            const manifestRoutes = rawManifest?.routes?.length
              ? rawManifest.routes
              : rawManifest?.match && rawManifest?.twin && rawManifest?.extract
                ? [{ match: rawManifest.match, twin: rawManifest.twin, extract: rawManifest.extract }]
                : [];
            const routeSpec =
              manifestRoutes.find((r) => (r.twin?.id || adapter.id) === twin.id) ?? manifestRoutes[0];
            const syn = buildSyntheticExtractPayload(routeSpec?.extract, exampleUrl);
            const outBox = runAdapterSyncInBulkhead(
              adapter.id,
              (inp) => twin.formatTwin(inp.body, inp.exampleUrl, simpleHtmlToMd),
              { body: syn.body, exampleUrl },
            );
            if (outBox.ok && isHealthyExtractedDoc(outBox.value)) {
              sampleRawBody = syn.body;
              sampleKind = twin.kind === 'text' ? 'text' : 'json';
              sampleDoc = outBox.value;
            } else {
              validStructure = false;
            }
          }
        } else if (typeof adapter.extractHtml === 'function') {
          const synHtml = buildSyntheticHtmlPayload(rawManifest);
          const u = new URL(exampleUrl);
          const outBox = runAdapterSyncInBulkhead(
            adapter.id,
            (ctx) => adapter.extractHtml(ctx),
            {
              url: u,
              baseUrl: exampleUrl,
              host: u.hostname.toLowerCase(),
              path: u.pathname,
              parts: u.pathname.split('/').filter(Boolean),
              rawHtml: synHtml.body,
              currentMd: synHtml.currentMd,
              htmlToMd: simpleHtmlToMd,
            },
          );
          if (outBox.ok && isHealthyExtractedDoc(outBox.value)) {
            sampleRawBody = synHtml.body;
            sampleKind = 'html';
            sampleDoc = outBox.value;
          } else {
            validStructure = false;
          }
        }
      }

      results.push({
        id: adapter.id,
        name: adapter.name,
        category: adapter.category,
        manifestFile,
        domains: [...adapter.domains],
        universalEngine: Boolean(adapter.universalEngine),
        modes,
        exampleUrl,
        fixtureVerified,
        ring1Locked: true,
        status: validStructure ? 'healthy' : 'broken',
        httpStatus: null,
        latencyMs: 0,
        structuralDiagnostic: buildStructuralDiagnostic({
          rawBody: sampleRawBody,
          kind: sampleKind,
          doc: sampleDoc,
        }),
      });
      continue;
    }

    // `--live` mode: strict SSRF + robots.txt FIRST on exampleUrl origin AND twin.fetchUrl origin + >=1,200ms politeness gap
    const t0 = performance.now();
    const urlCheck = validatePublicHttpsTargetUrl(exampleUrl);
    if (!urlCheck.ok) {
      results.push({
        id: adapter.id,
        name: adapter.name,
        category: adapter.category,
        manifestFile,
        domains: [...adapter.domains],
        universalEngine: Boolean(adapter.universalEngine),
        modes,
        exampleUrl,
        fixtureVerified: matchedFixtures.length > 0,
        ring1Locked: true,
        status: 'broken',
        httpStatus: null,
        latencyMs: Math.round(performance.now() - t0),
        structuralDiagnostic: buildStructuralDiagnostic({ rawBody: '', kind: 'html', doc: null }),
      });
      continue;
    }

    // 1. Always check `robots.txt` on `exampleUrl`'s origin FIRST before any target request
    const exampleOriginCheck = await checkOriginRobots(urlCheck.url);
    if (exampleOriginCheck.state !== 'allowed') {
      results.push({
        id: adapter.id,
        name: adapter.name,
        category: adapter.category,
        manifestFile,
        domains: [...adapter.domains],
        universalEngine: Boolean(adapter.universalEngine),
        modes,
        exampleUrl,
        fixtureVerified: matchedFixtures.length > 0,
        ring1Locked: true,
        status: exampleOriginCheck.state,
        httpStatus: null,
        latencyMs: Math.round(performance.now() - t0),
        structuralDiagnostic: buildStructuralDiagnostic({ rawBody: '', kind: modes.includes('twin') ? 'json' : 'html', doc: null }),
      });
      continue;
    }

    const twin = resolveAdapterTwinForUrl(adapter, exampleUrl);
    if (twin) {
      const fetchRes = await fetchPoliteTarget(twin.fetchUrl, twin.accept || 'application/json');
      const diagKind = twin.kind === 'text' ? 'text' : 'json';
      if (fetchRes.outcome !== 'ok') {
        results.push({
          id: adapter.id,
          name: adapter.name,
          category: adapter.category,
          manifestFile,
          domains: [...adapter.domains],
          universalEngine: Boolean(adapter.universalEngine),
          modes,
          exampleUrl,
          fixtureVerified: matchedFixtures.length > 0,
          ring1Locked: true,
          status: fetchRes.outcome,
          httpStatus: fetchRes.httpStatus,
          latencyMs: Math.round(performance.now() - t0),
          structuralDiagnostic: buildStructuralDiagnostic({ rawBody: fetchRes.rawBody, kind: diagKind, doc: null }),
        });
        continue;
      }

      const fmtBox = runAdapterSyncInBulkhead(
        adapter.id,
        (inp) => twin.formatTwin(inp.rawBody, inp.exampleUrl, simpleHtmlToMd),
        { rawBody: fetchRes.rawBody, exampleUrl },
      );
      const doc = fmtBox.ok ? fmtBox.value : null;
      const status = isHealthyExtractedDoc(doc) ? 'healthy' : 'broken';
      results.push({
        id: adapter.id,
        name: adapter.name,
        category: adapter.category,
        manifestFile,
        domains: [...adapter.domains],
        universalEngine: Boolean(adapter.universalEngine),
        modes,
        exampleUrl,
        fixtureVerified: matchedFixtures.length > 0,
        ring1Locked: true,
        status,
        httpStatus: fetchRes.httpStatus,
        latencyMs: Math.round(performance.now() - t0),
        structuralDiagnostic: buildStructuralDiagnostic({ rawBody: fetchRes.rawBody, kind: diagKind, doc }),
      });
    } else {
      const fetchRes = await fetchPoliteTarget(exampleUrl, 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8');
      if (fetchRes.outcome !== 'ok') {
        results.push({
          id: adapter.id,
          name: adapter.name,
          category: adapter.category,
          manifestFile,
          domains: [...adapter.domains],
          universalEngine: Boolean(adapter.universalEngine),
          modes,
          exampleUrl,
          fixtureVerified: matchedFixtures.length > 0,
          ring1Locked: true,
          status: fetchRes.outcome,
          httpStatus: fetchRes.httpStatus,
          latencyMs: Math.round(performance.now() - t0),
          structuralDiagnostic: buildStructuralDiagnostic({ rawBody: fetchRes.rawBody, kind: 'html', doc: null }),
        });
        continue;
      }

      let doc = null;
      if (typeof adapter.extractHtml === 'function') {
        const baseDoc = extractHtmlDocument(fetchRes.rawBody, { baseUrl: exampleUrl, onlyMainContent: true });
        const u = new URL(exampleUrl);
        const hBox = runAdapterSyncInBulkhead(
          adapter.id,
          (ctx) => adapter.extractHtml(ctx),
          {
            url: u,
            baseUrl: exampleUrl,
            host: u.hostname.toLowerCase(),
            path: u.pathname,
            parts: u.pathname.split('/').filter(Boolean),
            rawHtml: fetchRes.rawBody,
            currentMd: baseDoc.markdown,
            htmlToMd: simpleHtmlToMd,
          },
        );
        doc = hBox.ok ? hBox.value : null;
      }

      const status = isHealthyExtractedDoc(doc) ? 'healthy' : 'broken';
      results.push({
        id: adapter.id,
        name: adapter.name,
        category: adapter.category,
        manifestFile,
        domains: [...adapter.domains],
        universalEngine: Boolean(adapter.universalEngine),
        modes,
        exampleUrl,
        fixtureVerified: matchedFixtures.length > 0,
        ring1Locked: true,
        status,
        httpStatus: fetchRes.httpStatus,
        latencyMs: Math.round(performance.now() - t0),
        structuralDiagnostic: buildStructuralDiagnostic({ rawBody: fetchRes.rawBody, kind: 'html', doc }),
      });
    }
  }

  const summary = {
    total: results.length,
    healthy: results.filter((r) => r.status === 'healthy').length,
    robotsDisallowed: results.filter((r) => r.status === 'robots_disallowed').length,
    upstreamBlocked: results.filter((r) => r.status === 'upstream_blocked').length,
    broken: results.filter((r) => r.status === 'broken').length,
    fixturesVerified: results.filter((r) => r.fixtureVerified).length,
    ring1PolicyLocked: results.filter((r) => r.ring1Locked).length,
  };

  return {
    schemaVersion: 1,
    mode,
    generatedAt:
      options.generatedAt ?? (mode === 'live' ? new Date().toISOString() : resolveDeterministicOfflineTimestamp()),
    canaryUserAgent: userAgent,
    policy: {
      robotsCheckedOnEveryHop: true,
      minHostGapMs: DEFAULT_POLITENESS_MS,
      requestTimeoutMs: DEFAULT_TIMEOUT_MS,
      zeroUntrustedProseStored: true,
      ring1DiffGate: 'hub/scripts/verify-adapter-only-diff.mjs',
    },
    summary,
    adapters: results,
  };
}

function parseCliArgs(argv) {
  let mode = 'offline';
  let outPath = null;
  let limit = undefined;
  let help = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--live') {
      mode = 'live';
    } else if (arg === '--offline') {
      mode = 'offline';
    } else if (arg === '--out') {
      outPath = argv[++i] ?? null;
    } else if (arg.startsWith('--out=')) {
      outPath = arg.slice('--out='.length);
    } else if (arg === '--limit') {
      limit = Number(argv[++i]);
    } else if (arg.startsWith('--limit=')) {
      limit = Number(arg.slice('--limit='.length));
    } else if (arg === '--help' || arg === '-h') {
      help = true;
    } else {
      throw new Error(`Unknown CLI flag: ${arg}`);
    }
  }
  return { mode, outPath, limit, help };
}

const isMainModule =
  Boolean(process.argv[1]) &&
  resolve(process.argv[1]).replace(/\\/g, '/').endsWith('/canary-adapters.mjs') &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMainModule) {
  const { mode, outPath, limit, help } = parseCliArgs(process.argv.slice(2));
  if (help) {
    console.log(
      [
        'Usage:',
        '  node scripts/canary-adapters.mjs [--offline] [--out ../docs/adapter-health.json]',
        '  node scripts/canary-adapters.mjs --live [--out ../docs/adapter-health.json] [--limit N]',
      ].join('\n'),
    );
    process.exit(0);
  }

  const report = await runAdapterCanary({ mode, limit });
  const jsonText = `${JSON.stringify(report, null, 2)}\n`;

  if (outPath) {
    const resolvedOut = resolve(process.cwd(), outPath);
    mkdirSync(dirname(resolvedOut), { recursive: true });
    writeFileSync(resolvedOut, jsonText, 'utf8');
    console.log(
      `✔ Adapter canary (${report.mode}): ${report.summary.healthy}/${report.summary.total} healthy, ` +
        `${report.summary.robotsDisallowed} robots_disallowed, ${report.summary.upstreamBlocked} upstream_blocked, ` +
        `${report.summary.broken} broken -> ${resolvedOut}`,
    );
  } else {
    process.stdout.write(jsonText);
  }
}
