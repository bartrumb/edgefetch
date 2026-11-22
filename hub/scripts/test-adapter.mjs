#!/usr/bin/env node
/**
 * EdgeFetch Declarative YAML Adapter Workbench, Live Polite Recorder & Linear-Time Fuzzer:
 *
 *   npm run adapter:test                                    # Compile YAML -> IR, validate + fuzz all adapters & fixtures
 *   npm run adapter:test crates-io                          # Compile + validate + fuzz a single adapter + its fixture
 *   npm run adapter:test crates-io https://crates.io/crates/serde
 *   npm run adapter:test crates-io https://crates.io/crates/serde --record
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildSync } from 'esbuild';

const SAFE_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MAX_FUZZ_MS_PER_PAYLOAD = 50;

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const hubRoot = resolve(scriptsDir, '..');
const rawArgs = process.argv.slice(2);
const recordFlag = rawArgs.includes('--record');
const positional = rawArgs.filter((a) => !a.startsWith('--'));

const targetSlug = positional[0] && !positional[0].startsWith('https://') ? positional[0].trim() : null;
const liveUrlArg = positional.find((a) => a.startsWith('https://')) ?? null;

if (rawArgs.includes('--help') || rawArgs.includes('-h')) {
  console.log(
    [
      'Usage:',
      '  npm run adapter:test                                      # Compile YAML, validate, run fixtures & fuzz all adapters',
      '  npm run adapter:test <adapter-id>                         # Compile YAML, validate, run fixture & fuzz one adapter',
      '  npm run adapter:test <adapter-id> <https://url>           # Polite live test (checks robots.txt + SSRF)',
      '  npm run adapter:test <adapter-id> <https://url> --record  # Polite live test + write test/fixtures/adapters/<id>.json',
    ].join('\n'),
  );
  process.exit(0);
}

if (targetSlug && !SAFE_ID_RE.test(targetSlug)) {
  console.error(`Invalid adapter id "${targetSlug}". Must match ${SAFE_ID_RE}.`);
  process.exit(1);
}

// Always compile & schema-validate `internal/extract/manifests/*.yaml` -> `compiled.json` first.
execFileSync(process.execPath, [join(scriptsDir, 'compile-manifests.mjs')], { stdio: 'inherit' });

function resolveSafeFixtureWritePath(fixturesRoot, rawId) {
  if (typeof rawId !== 'string' || !SAFE_ID_RE.test(rawId)) {
    throw new Error(`Refusing to write fixture for unsafe id "${String(rawId)}"`);
  }
  const baseDir = resolve(fixturesRoot);
  const candidate = resolve(baseDir, `${rawId}.json`);
  if (!candidate.startsWith(baseDir + sep)) {
    throw new Error(`Path traversal blocked when resolving fixture path for "${rawId}"`);
  }
  return candidate;
}

const tmp = mkdtempSync(join(tmpdir(), 'ef-adapter-workbench-'));
const harnessEntry = join(tmp, 'entry.ts');
const harnessBundle = join(tmp, 'bundle.mjs');

writeFileSync(
  harnessEntry,
  `
export {
  applyPostFetchSiteExtractor,
  getRawRegisteredSiteAdapters,
  GO_KIND_TEXT_ACCEPT_ALLOWLIST,
  listRegisteredAdapters,
  resolveSiteExtractorTwin,
} from ${JSON.stringify(join(hubRoot, 'src', 'extractors', 'registry.ts'))};
export { runAdapterSyncInBulkhead } from ${JSON.stringify(join(hubRoot, 'src', 'adapter-sandbox.ts'))};
export { extractHtmlDocument } from ${JSON.stringify(join(hubRoot, 'src', 'scrape.ts'))};
export { fetchOverflowRobots, isRobotsAllowed } from ${JSON.stringify(join(hubRoot, 'src', 'overflow.ts'))};
export { createSafeOutboundFetch } from ${JSON.stringify(join(hubRoot, 'portable', 'safe-fetch.ts'))};
`,
  'utf8',
);

try {
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

  const mod = await import(pathToFileURL(harnessBundle).href);
  const {
    applyPostFetchSiteExtractor,
    getRawRegisteredSiteAdapters,
    GO_KIND_TEXT_ACCEPT_ALLOWLIST,
    resolveSiteExtractorTwin,
    runAdapterSyncInBulkhead,
    extractHtmlDocument,
    fetchOverflowRobots,
    isRobotsAllowed,
    createSafeOutboundFetch,
  } = mod;

  const simpleHtmlToMd = (frag, base) => {
    const doc = extractHtmlDocument(`<!doctype html><html><body>${frag}</body></html>`, {
      baseUrl: base ?? 'https://example.com',
      onlyMainContent: false,
    });
    return { markdown: doc.markdown, links: doc.links };
  };

  const allAdapters = getRawRegisteredSiteAdapters();
  const selected = targetSlug ? allAdapters.filter((a) => a.id === targetSlug) : allAdapters;

  if (selected.length === 0) {
    console.error(`No registered adapter found with id "${targetSlug}".`);
    console.error(`Available IDs (${allAdapters.length}): ${allAdapters.map((a) => a.id).join(', ')}`);
    process.exit(1);
  }

  // Adversarial >100 KB HTML/XML AND valid-JSON payloads (Round 6 M1/M7/Low bulkhead fuzzing)
  const deepJsonObj = (() => {
    let cur = { leaf: '<'.repeat(5_000) };
    for (let i = 0; i < 40; i++) cur = { next: cur };
    return cur;
  })();

  const adversarialPayloads = [
    { name: 'unclosed-pseudo-tags-50k (R4-H1/M7)', body: `<p>ok</p>${'<x'.repeat(50_000)}` },
    { name: 'unquoted-attr-50k (R4-H2)', body: `<div ${'a'.repeat(50_000)}>text</div>` },
    { name: 'deep-nested-divs-5k (R6-M1)', body: `${'<div>'.repeat(5_000)}leaf${'</div>'.repeat(5_000)}` },
    { name: 'dl-trailing-colons-50k (R6-M1)', body: `<dl><dt>Key${':'.repeat(50_000)}   </dt><dd>Val</dd></dl>` },
    { name: 'unclosed-comments-30k (R3-H1)', body: '<!--'.repeat(30_000) },
    { name: 'truncated-nested-json', body: `{"data":${'['.repeat(4_000)}` },
    {
      name: 'valid-json-hostile-angles-100k (R6-Low)',
      body: JSON.stringify({
        id: 'adv-1',
        name: 'adv-pkg',
        title: `Title ${'<'.repeat(35_000)}`,
        summary: '<a href="javascript:alert(1)">click</a> '.repeat(1_500),
        description: `${'<img src=x onerror=alert(1)>'.repeat(1_500)}`,
        body_markdown: `---\ntitle: fm\n---\n${'<'.repeat(25_000)}`,
        message: {
          title: [`Paper ${'<'.repeat(20_000)}`],
          abstract: `<jats:p>${'<tag "unclosed '.repeat(3_000)}</jats:p>`,
        },
        crate: { id: 'serde', max_version: '1.0.0', description: '<'.repeat(20_000) },
        info: { name: 'pkg', version: '1.0.0', summary: '<'.repeat(20_000) },
        deep: deepJsonObj,
      }),
    },
    {
      name: 'valid-json-dense-array-600 (R6-Low)',
      body: JSON.stringify({
        total: 600,
        jobs: Array.from({ length: 300 }, (_, i) => ({
          id: `job-${i}`,
          title: `Engineer ${i} ${':'.repeat(40)}`,
          text: `Role ${i}`,
          location: { name: 'Remote' },
          absolute_url: `https://example.com/jobs/${i}`,
        })),
        items: Array.from({ length: 300 }, (_, i) => ({
          id: `id-${i}`,
          name: `Item ${i}`,
          title: `Role ${i}`,
        })),
        products: Array.from({ length: 120 }, (_, i) => ({
          id: i + 1,
          handle: `prod-${i}`,
          title: `Product ${i}`,
          variants: [{ id: i * 10, title: 'Default', price: '19.99', available: true }],
          images: [{ src: `https://cdn.example.com/p-${i}.jpg` }],
        })),
      }),
    },
  ];

  const compiledBundlePath = resolve(hubRoot, '..', 'internal', 'extract', 'manifests', 'compiled.json');
  const compiledManifests = JSON.parse(readFileSync(compiledBundlePath, 'utf8')).manifests ?? [];
  const manifestById = new Map(compiledManifests.map((m) => [m.id, m]));

  function setDeepPath(root, dotPath, val) {
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
    } else if (cur[leaf] === undefined) {
      cur[leaf] = val;
    }
  }

  function buildSchemaMatchedExtractPayloads(ext, labelPrefix) {
    if (!ext) return [];
    const seeds = [
      {
        suffix: 'xss-and-js-links',
        str: 'Hostile <script>alert(1)</script> [click](javascript:alert(1)) [tab](java&Tab;script:alert(1)) https://docs.example.com/ok',
        url: 'https://docs.example.com/item-1',
        badUrl: 'http://127.0.0.1/private-feed',
      },
      {
        suffix: 'h9-unclosed-js-dest-20k',
        str: `Heading ${'[x](javascript:a'.repeat(1_200)}`,
        url: 'https://docs.example.com/item-2',
        badUrl: 'javascript:alert(1)',
      },
      {
        suffix: 'fence-tilde-and-nul',
        str: 'Body\n```\ncode\n```~\n<img src=x onerror=alert(1)>\u0000\u{E0041}',
        url: 'https://docs.example.com/item-3',
        badUrl: 'https://localhost/ssrf',
      },
      {
        suffix: 'dense-40-items',
        str: 'Item summary with `inline <svg>` and safe prose '.repeat(8),
        url: 'https://docs.example.com/item-4',
        badUrl: 'data:text/html,<script>alert(1)</script>',
        arrayLen: 40,
      },
      {
        suffix: 'entity-vbscript-and-file-schemes',
        str: 'Ref [v](vbscript:msgbox(1)) [f](file:///etc/passwd) [b](blob:https://evil.example/1) <!-- comment -->',
        url: 'https://docs.example.com/item-5',
        badUrl: 'http://169.254.169.254/latest/meta-data/',
      },
      {
        suffix: 'bidi-and-multiline-backtick-span',
        str: 'Para `open\n2. `<img src=x onerror=alert(1)>`\u202e and ~`<svg onload=alert(1)>`',
        url: 'https://docs.example.com/item-6',
        badUrl: 'https://evil.nip.io/rebind',
      },
    ];

    if (ext.textMode) {
      return seeds.map((sd) => ({
        name: `${labelPrefix}:${sd.suffix}`,
        body:
          ext.textMode === 'frontmatter_card'
            ? `---\npretty_name: ${sd.str.slice(0, 80)}\nlicense: mit\ntags:\n  - nlp\n---\n# Card Title\n\n${sd.str}`
            : ext.textMode === 'git_patch'
              ? `From 0123456789abcdef Mon Sep 17 00:00:00 2001\nSubject: [PATCH] ${sd.str.slice(0, 120)}\n---\n a.txt | 1 +\n---\ndiff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1,2 @@\n+${sd.str.slice(0, 200)}\n`
              : `# Markdown Twin\n\n${sd.str}\n`,
      }));
    }

    if (ext.icimsPortal) {
      return seeds.map((sd) => ({
        name: `${labelPrefix}:${sd.suffix}`,
        body: `<!doctype html><html><head><title>Careers ${sd.str.slice(0, 60)}</title></head><body><div class="iCIMS_JobsTable"><div class="row"><a class="iCIMS_Anchor" href="https://careers-acme.icims.com/jobs/101/eng/job"><h3>Senior Engineer ${sd.str.slice(0, 80)}</h3></a><span>Remote</span></div></div></body></html>`,
      }));
    }

    if (ext.xml) {
      const itemTag = ext.xml.itemTag || 'item';
      const reqTags = ext.xml.requireAnyTags ?? [itemTag];
      const itemVarEntries = Object.entries(ext.xml.itemVars ?? {});
      return seeds.map((sd) => {
        const count = sd.arrayLen ? 15 : 3;
        const itemsXml = Array.from({ length: count }, (_, idx) => {
          const innerTags = itemVarEntries
            .map(([vn, vs]) => {
              const tName = vs.tags?.[0] || vn;
              const isLink = /link|url|guid/i.test(vn) || /link|url/i.test(tName);
              const val = isLink ? (idx === 0 ? sd.url : sd.badUrl) : `${vn}:${sd.str.slice(0, 240)}`;
              return `<${tName}><![CDATA[${val}]]></${tName}>`;
            })
            .join('');
          return `<${itemTag}><title><![CDATA[Title ${idx} ${sd.str.slice(0, 120)}]]></title><link>${idx % 2 === 0 ? sd.url : sd.badUrl}</link>${innerTags}</${itemTag}>`;
        }).join('');
        const extraReq = reqTags[0] ? `<${reqTags[0]}></${reqTags[0]}>` : '';
        const xmlBody =
          ext.xml.mode === 'jats_article'
            ? `<article><front><journal-meta><journal-title-group><journal-title>Journal</journal-title></journal-title-group></journal-meta><article-meta><title-group><article-title>${sd.str.slice(0, 200)}</article-title></title-group><contrib-group><contrib contrib-type="author"><name><surname>Doe</surname><given-names>J</given-names></name></contrib></contrib-group><abstract><p>${sd.str}</p></abstract></article-meta></front><body><sec><title>Intro</title><p>${sd.str}</p></sec></body></article>`
            : `<?xml version="1.0"?><rss version="2.0"><channel><title>Feed ${sd.str.slice(0, 80)}</title>${extraReq}${itemsXml}</channel></rss>`;
        return { name: `${labelPrefix}:${sd.suffix}`, body: xmlBody };
      });
    }

    if (ext.commerceMode) {
      return seeds.map((sd) => ({
        name: `${labelPrefix}:${sd.suffix}`,
        body: JSON.stringify({
          product: {
            id: 101,
            title: ` Jacket ${sd.str.slice(0, 180)}`,
            handle: 'jacket',
            vendor: 'Acme',
            body_html: `<p>${sd.str}</p>`,
            variants: [{ id: 1, title: 'M', price: '49.00', available: true, sku: 'SKU-1' }],
            images: [{ src: sd.url }],
          },
          products: [
            {
              id: 101,
              title: `Item ${sd.str.slice(0, 120)}`,
              handle: 'item-1',
              name: `Woo ${sd.str.slice(0, 120)}`,
              permalink: sd.url,
              short_description: `<p>${sd.str.slice(0, 200)}</p>`,
              prices: { price: '1999', currency_code: 'USD', currency_minor_unit: 2 },
              variants: [{ id: 1, title: 'Default', price: '19.99', available: true }],
              images: [{ src: sd.url }],
            },
          ],
        }),
      }));
    }

    return seeds.map((sd) => {
      const obj = {};
      for (const rf of ext.requireFields ?? []) setDeepPath(obj, rf, sd.str);
      for (const raf of ext.requireAnyFields ?? []) setDeepPath(obj, raf, sd.str);
      if (ext.requireFieldEquals) {
        for (const [fk, fv] of Object.entries(ext.requireFieldEquals)) setDeepPath(obj, fk, fv);
      }
      if (ext.codeByPath?.path) setDeepPath(obj, ext.codeByPath.path, sd.str);
      if (ext.objectLinksPath) {
        setDeepPath(obj, ext.objectLinksPath, { Homepage: sd.url, Insecure: sd.badUrl });
      }
      for (const [vn, vs] of Object.entries(ext.vars ?? {})) {
        const p0 = vs.paths?.[0] || vn;
        const isUrl = Boolean(vs.requireHttps || vs.requireHttpPrefix || /url|link|homepage|repo/i.test(vn));
        const val = vs.nestedSubValues
          ? { sub1: { name: sd.str.slice(0, 80), description: sd.str.slice(0, 120) } }
          : vs.findInArrayLang
            ? [{ lang: 'en', value: sd.str }]
            : isUrl
              ? sd.url
              : vs.format === 'usd_compact' || vs.format === 'int_locale' || vs.format === 'duration' || vs.format === 'unix_date'
                ? 1700000000
                : sd.str;
        setDeepPath(obj, p0, val);
      }
      const arrLen = sd.arrayLen ?? 4;
      for (const sec of ext.sections ?? []) {
        if (sec.arrayPath) {
          const items = Array.from({ length: arrLen }, (_, idx) => {
            const it = { id: `id-${idx}`, parent_id: null, depth: 0, title: `${sd.str.slice(0, 120)}`, name: `row-${idx}`, text: sd.str, body: sd.str, url: idx % 2 === 0 ? sd.url : sd.badUrl };
            if (sec.filter?.field) {
              setDeepPath(it, sec.filter.field, sec.filter.equals ?? 'open');
            }
            for (const col of sec.columns ?? []) {
              if (col.paths?.[0]) setDeepPath(it, col.paths[0], col.format === 'usd_compact' ? 12500 : sd.str.slice(0, 120));
              if (col.outcomesField) setDeepPath(it, col.outcomesField, '["Yes","No"]');
              if (col.pricesField) setDeepPath(it, col.pricesField, '["0.65","0.35"]');
            }
            for (const [ivn, ivs] of Object.entries(sec.itemVars ?? {})) {
              if (ivs.paths?.[0]) {
                setDeepPath(it, ivs.paths[0], /url|link/i.test(ivn) ? (idx % 2 === 0 ? sd.url : sd.badUrl) : sd.str.slice(0, 140));
              }
            }
            return it;
          });
          if (sec.arrayPath === '.') {
            obj.__rootArray = items;
          } else {
            setDeepPath(obj, sec.arrayPath, items);
          }
        }
        if (sec.subsectionsArrayPath) {
          setDeepPath(obj, sec.subsectionsArrayPath, [{ title: 'Sub', name: 'Sub', description: sd.str, text: sd.str }]);
        }
        if (sec.listArrayPath) {
          setDeepPath(obj, sec.listArrayPath, [sd.str.slice(0, 120), 'Item B']);
        }
        if (sec.parallelArrays) {
          setDeepPath(obj, sec.parallelArrays.keysPath, ['col_a', 'col_b']);
          setDeepPath(obj, sec.parallelArrays.rowsPath, [[sd.str.slice(0, 80), '42']]);
        }
      }

      let finalRoot = obj.__rootArray ?? obj;
      if (ext.rootPath && ext.rootPath !== '.') {
        const wrapper = {};
        setDeepPath(wrapper, ext.rootPath, finalRoot);
        finalRoot = wrapper;
      }
      if (ext.unwrapFirstArrayElement) {
        finalRoot = [finalRoot];
      }
      if (ext.wrapRootArrayAs && !Array.isArray(finalRoot)) {
        finalRoot = [finalRoot];
      }
      if (ext.jsonSource === 'inertia_Or_json' && sd.suffix === 'xss-and-js-links') {
        const escaped = JSON.stringify({ props: finalRoot }).replace(/"/g, '&quot;');
        return { name: `${labelPrefix}:inertia-html`, body: `<div id="app" data-page="${escaped}"></div>` };
      }
      return { name: `${labelPrefix}:${sd.suffix}`, body: JSON.stringify(finalRoot) };
    });
  }

  function buildSchemaMatchedHtmlPayloads(manifest) {
    const out = [];
    for (const [idx, hr] of (manifest?.htmlRoutes ?? []).entries()) {
      const pfx = `htmlRoute[${idx}]:${hr.mode}`;
      const hostile = 'Hostile <script>alert(1)</script> [click](javascript:alert(1)) ' + '[x](javascript:a'.repeat(400);
      if (hr.mode === 'embedded_json' && hr.extract) {
        for (const ep of buildSchemaMatchedExtractPayloads(hr.extract, pfx)) {
          if (hr.scriptId) {
            out.push({ name: `${ep.name}:script`, body: `<!doctype html><html><body><script id="${hr.scriptId}" type="application/json">${ep.body}</script></body></html>` });
          } else if (hr.dataAttr) {
            const attrSafe = ep.body.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
            out.push({ name: `${ep.name}:attr`, body: `<!doctype html><html><body><div ${hr.dataAttr}="${attrSafe}"></div></body></html>` });
          }
        }
      } else if (hr.mode === 'xml_items_table' && hr.xml) {
        out.push(...buildSchemaMatchedExtractPayloads({ xml: hr.xml }, pfx));
      } else if (hr.mode === 'markdown_clean') {
        out.push({
          name: `${pfx}:clean-hostile`,
          body: '<!doctype html><html><head><meta name="generator" content="MediaWiki 1.43"></head><body><main><p>Wiki</p></main></body></html>',
          currentMd: `# Article [edit]\n\nText with [citation needed] and ${hostile}\n\n^ a b c Ref 1\n\n## Navigation menu\nFooter chrome`,
        });
        out.push({
          name: `${pfx}:clean-spaces-200k`,
          body: '<!doctype html><html><head><meta name="generator" content="MediaWiki 1.43"></head><body></body></html>',
          currentMd: `# Title [edit]\n\n${' '.repeat(200_000)}\n${'\n'.repeat(20_000)}tail`,
        });
      } else if (hr.mode === 'gist_files') {
        out.push({
          name: `${pfx}:gist`,
          body: `<!doctype html><html><head><title>demo.ts · GitHub</title></head><body><div itemprop="about">${hostile}</div><div class="file"><div class="file-header"><strong class="gist-blob-name">demo.ts</strong></div><table><tr><td class="blob-code">const x = 1;</td></tr></table></div></body></html>`,
        });
      } else if (hr.mode === 'stackexchange_html') {
        out.push({
          name: `${pfx}:se`,
          body: `<!doctype html><html><body><div id="question-header"><h1><a class="question-hyperlink">${hostile}</a></h1></div><div id="question" data-score="12"><div class="js-post-body"><p>Question ${hostile}</p></div><a class="post-tag">rust</a></div><div class="answer accepted-answer" data-score="25"><div class="js-post-body"><p>Answer body</p></div></div></body></html>`,
        });
      } else if (hr.mode === 'reddit_shreddit') {
        out.push({
          name: `${pfx}:shreddit`,
          body: `<!doctype html><html><body><shreddit-post post-title="${hostile.slice(0, 180)}" author="alice" subreddit-prefixed-name="r/rust" score="99" comment-count="4"><div slot="text-body"><p>${hostile}</p></div></shreddit-post><shreddit-comment author="bob" score="10"><div slot="comment"><p>Reply ${hostile.slice(0, 120)}</p></div></shreddit-comment></body></html>`,
        });
      } else if (hr.mode === 'icims_portal') {
        out.push(...buildSchemaMatchedExtractPayloads({ icimsPortal: true }, pfx));
      } else if (hr.mode === 'shopify_html' || hr.mode === 'woocommerce_html') {
        out.push({
          name: `${pfx}:ld-product`,
          body: `<!doctype html><html><head><script type="application/ld+json">${JSON.stringify({ '@context': 'https://schema.org', '@type': 'Product', name: `Prod ${hostile.slice(0, 140)}`, description: hostile, brand: { name: 'Acme' }, offers: { '@type': 'Offer', price: '29.99', priceCurrency: 'USD', availability: 'https://schema.org/InStock' } })}</script></head><body><h1>Product</h1></body></html>`,
        });
      } else if (hr.mode === 'dom') {
        const ldType = hr.jsonLdTypes?.[0] || 'Thing';
        const ldObj = {
          '@context': 'https://schema.org',
          '@type': ldType,
          name: `Entity ${hostile.slice(0, 160)}`,
          headline: `Headline ${hostile.slice(0, 160)}`,
          description: hostile,
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
            metaTags.push(`<meta name="${mk}" content="${vn} ${hostile.slice(0, 100).replace(/"/g, '&quot;')}">`);
          }
          if (vs.allMetaKey) {
            metaTags.push(`<meta name="${vs.allMetaKey}" content="Alice">`);
          }
          const toSelArr = (x) => (Array.isArray(x) ? x : typeof x === 'string' ? [x] : []);
          for (const sel of [...toSelArr(vs.cssText), ...toSelArr(vs.cssAllText), ...toSelArr(vs.cssHtmlToMd)]) {
            const idm = /^#([A-Za-z0-9_-]+)$/.exec(sel.trim());
            const clm = /^\.([A-Za-z0-9_-]+)$/.exec(sel.trim());
            if (idm) domEls.push(`<div id="${idm[1]}"><p>${hostile}</p></div>`);
            else if (clm) domEls.push(`<div class="${clm[1]}"><p>${hostile}</p></div>`);
          }
        }
        const embScript = hr.embeddedBalancedKey
          ? `<script>window.__DATA = { "${hr.embeddedBalancedKey}": ${JSON.stringify({ name: hostile.slice(0, 120), description: hostile, title: hostile.slice(0, 120) })} };</script>`
          : '';
        out.push({
          name: `${pfx}:dom-structured`,
          body: `<!doctype html><html><head><title>Page ${hostile.slice(0, 80)}</title>${metaTags.join('')}<script type="application/ld+json">${JSON.stringify(ldObj)}</script>${embScript}</head><body><main><h1>Main Heading</h1>${domEls.join('')}<p>Extra body text</p></main></body></html>`,
          currentMd: `# Main Heading\n\nBody paragraph with more than enough extra characters to exercise appendCurrentMdDelta cleanly.`,
        });
      }
    }
    return out;
  }

  function assertSafeFormattedOutput(adapterId, caseName, res) {
    if (!res || typeof res.markdown !== 'string') return;
    const md = res.markdown;
    if (/\]\(\s*(?:javascript|vbscript|data):/i.test(md)) {
      throw new Error(`[${adapterId}] Dangerous URI scheme survived in Markdown on ${caseName}!`);
    }
    // Outside fenced code blocks, raw `<script` must always be escaped
    const lines = md.split('\n');
    let inFence = false;
    for (const ln of lines) {
      if (/^[ ]{0,3}(?:`{3,}|~{3,})/.test(ln)) {
        inFence = !inFence;
        continue;
      }
      if (!inFence && /<script\b/i.test(ln.replace(/`[^`]*`/g, ''))) {
        throw new Error(`[${adapterId}] Unescaped <script> tag survived outside code in ${caseName}!`);
      }
    }
    for (const lk of res.links ?? []) {
      if (!lk.startsWith('https://') || /^https:\/\/(?:127\.|localhost\b|0\.0\.0\.0)/i.test(lk)) {
        throw new Error(`[${adapterId}] Non-HTTPS or private link "${lk}" leaked in links[] on ${caseName}!`);
      }
    }
  }

  // Warm up V8 JIT once before enforcing strict < 50ms per-case bulkhead wall-clock budget
  if (selected[0]?.extractHtml) {
    const warmUrl = new URL(selected[0].exampleUrls[0]);
    for (const warmHtml of [
      '<!doctype html><html><body><h1>Warmup</h1></body></html>',
      adversarialPayloads[6]?.body ?? '',
    ]) {
      selected[0].extractHtml({
        url: warmUrl,
        baseUrl: selected[0].exampleUrls[0],
        host: warmUrl.hostname.toLowerCase(),
        path: warmUrl.pathname,
        parts: warmUrl.pathname.split('/').filter(Boolean),
        rawHtml: warmHtml,
        currentMd: '# Warmup',
        htmlToMd: simpleHtmlToMd,
      });
    }
  }

  let totalFuzzed = 0;
  let formattedFuzzHits = 0;
  let worstMs = 0;
  let worstLabel = '';

  for (const adapter of selected) {
    if (!SAFE_ID_RE.test(adapter.id)) {
      throw new Error(`Adapter id "${adapter.id}" violates ${SAFE_ID_RE}`);
    }
    if (!adapter.exampleUrls?.length || !adapter.exampleUrls[0]?.startsWith('https://')) {
      throw new Error(`[${adapter.id}] Must define at least one https:// exampleUrl`);
    }
    const rawManifest = manifestById.get(adapter.id);
    const manifestRoutes =
      rawManifest?.routes?.length
        ? rawManifest.routes
        : rawManifest?.match && rawManifest?.twin && rawManifest?.extract
          ? [{ match: rawManifest.match, twin: rawManifest.twin, extract: rawManifest.extract }]
          : [];

    if (typeof adapter.resolveTwin === 'function') {
      let testedTwins = 0;
      const seenTwinIds = new Set();
      for (const sampleUrl of adapter.exampleUrls) {
        const parsedUrl = new URL(sampleUrl);
        const parts = parsedUrl.pathname.split('/').filter(Boolean);
        const twinBox = runAdapterSyncInBulkhead(
          adapter.id,
          (ctx) => adapter.resolveTwin(ctx),
          { url: parsedUrl, urlStr: sampleUrl, host: parsedUrl.hostname.toLowerCase(), path: parsedUrl.pathname, parts },
        );
        if (!twinBox.ok) {
          throw new Error(`[${adapter.id}] resolveTwin threw in bulkhead: ${twinBox.error}`);
        }
        const twin = twinBox.value;
        if (!twin) continue;
        if (!SAFE_ID_RE.test(twin.id)) {
          throw new Error(`[${adapter.id}] twin.id "${twin.id}" violates ${SAFE_ID_RE}`);
        }
        if (typeof twin.fetchUrl !== 'string' || !twin.fetchUrl.startsWith('https://')) {
          throw new Error(`[${adapter.id}] twin.fetchUrl must start with https:// (got ${JSON.stringify(twin)})`);
        }
        if (twin.kind === 'text' && !GO_KIND_TEXT_ACCEPT_ALLOWLIST.has(twin.accept)) {
          throw new Error(
            `[${adapter.id}] kind="text" accept="${twin.accept}" violates Go allowlist: ${[...GO_KIND_TEXT_ACCEPT_ALLOWLIST].join(', ')}`,
          );
        }
        if (seenTwinIds.has(twin.id)) continue;
        seenTwinIds.add(twin.id);
        testedTwins++;

        const matchedRouteSpec =
          manifestRoutes.find((r) => (r.twin?.id || adapter.id) === twin.id) ?? manifestRoutes[0];
        const routeStructuredPayloads = buildSchemaMatchedExtractPayloads(matchedRouteSpec?.extract, `structured:${twin.id}`);
        const combinedTwinPayloads = [...adversarialPayloads, ...routeStructuredPayloads];

        for (const p of combinedTwinPayloads) {
          let lastBox = null;
          const runTwinTrial = () => {
            const t0 = performance.now();
            const fBox = runAdapterSyncInBulkhead(
              adapter.id,
              (inp) => twin.formatTwin(inp.body, inp.sampleUrl, simpleHtmlToMd),
              { body: p.body, sampleUrl },
              MAX_FUZZ_MS_PER_PAYLOAD,
            );
            const elapsed = performance.now() - t0;
            if (!fBox.ok && String(fBox.error).includes('AdapterNetworkForbiddenError')) {
              throw new Error(`[${adapter.id}] Forbidden fetch() call inside formatTwin!`);
            }
            lastBox = fBox;
            return elapsed;
          };
          let dt = runTwinTrial();
          if (dt > MAX_FUZZ_MS_PER_PAYLOAD) dt = Math.min(dt, runTwinTrial(), runTwinTrial());
          totalFuzzed++;
          if (lastBox?.ok && lastBox.value?.markdown) {
            formattedFuzzHits++;
            assertSafeFormattedOutput(adapter.id, p.name, lastBox.value);
          }
          if (dt > worstMs) {
            worstMs = dt;
            worstLabel = `${adapter.id}/${twin.id} (twin:${p.name})`;
          }
          if (dt > MAX_FUZZ_MS_PER_PAYLOAD) {
            throw new Error(
              `[${adapter.id}/${twin.id}] Superlinear slowdown on ${p.name}: ${dt.toFixed(1)}ms > ${MAX_FUZZ_MS_PER_PAYLOAD}ms`,
            );
          }
        }
      }
      if (testedTwins === 0 && !adapter.extractHtml) {
        throw new Error(`[${adapter.id}] Twin-only adapter did not resolve any of its exampleUrls: ${adapter.exampleUrls.join(', ')}`);
      }
    }

    if (typeof adapter.extractHtml === 'function') {
      const htmlStructuredPayloads = buildSchemaMatchedHtmlPayloads(rawManifest);
      const combinedHtmlPayloads = [...adversarialPayloads, ...htmlStructuredPayloads];
      for (const sampleUrl of adapter.exampleUrls) {
        const parsedUrl = new URL(sampleUrl);
        const parts = parsedUrl.pathname.split('/').filter(Boolean);
        for (const p of combinedHtmlPayloads) {
          let lastBox = null;
          const runHtmlTrial = () => {
            const t0 = performance.now();
            const hBox = runAdapterSyncInBulkhead(
              adapter.id,
              (ctx) => adapter.extractHtml(ctx),
              {
                url: parsedUrl,
                baseUrl: sampleUrl,
                host: parsedUrl.hostname.toLowerCase(),
                path: parsedUrl.pathname,
                parts,
                rawHtml: p.body,
                currentMd: p.currentMd ?? p.body.slice(0, 4_000),
                htmlToMd: simpleHtmlToMd,
              },
              MAX_FUZZ_MS_PER_PAYLOAD,
            );
            const elapsed = performance.now() - t0;
            if (!hBox.ok && String(hBox.error).includes('AdapterNetworkForbiddenError')) {
              throw new Error(`[${adapter.id}] Forbidden fetch() call inside extractHtml!`);
            }
            lastBox = hBox;
            return elapsed;
          };
          let dt = runHtmlTrial();
          if (dt > MAX_FUZZ_MS_PER_PAYLOAD) dt = Math.min(dt, runHtmlTrial(), runHtmlTrial());
          totalFuzzed++;
          if (lastBox?.ok && lastBox.value?.markdown) {
            formattedFuzzHits++;
            assertSafeFormattedOutput(adapter.id, p.name, lastBox.value);
          }
          if (dt > worstMs) {
            worstMs = dt;
            worstLabel = `${adapter.id} (html:${p.name})`;
          }
          if (dt > MAX_FUZZ_MS_PER_PAYLOAD) {
            throw new Error(
              `[${adapter.id}] Superlinear slowdown in extractHtml on ${p.name}: ${dt.toFixed(1)}ms > ${MAX_FUZZ_MS_PER_PAYLOAD}ms`,
            );
          }
        }
      }
    }
  }

  if (!targetSlug && formattedFuzzHits < 250) {
    throw new Error(`Adapter fuzz corpus only exercised formatting on ${formattedFuzzHits} cases (expected >= 250)!`);
  }

  // Run matching JSON fixtures (both twin and html modes)
  const fixturesDir = resolve(hubRoot, 'test', 'fixtures', 'adapters');
  let fixturesChecked = 0;
  if (existsSync(fixturesDir)) {
    for (const file of readdirSync(fixturesDir).filter((f) => f.endsWith('.json'))) {
      const fx = JSON.parse(readFileSync(join(fixturesDir, file), 'utf8'));
      if (targetSlug && fx.adapterId !== targetSlug) continue;
      fixturesChecked++;
      if (fx.mode === 'twin') {
        const twin = resolveSiteExtractorTwin(fx.inputUrl);
        if (!twin || (twin.id !== fx.adapterId && !twin.id.startsWith(`${fx.adapterId}-`))) {
          throw new Error(`[fixture ${file}] Expected twin "${fx.adapterId}" for ${fx.inputUrl} (got ${twin?.id ?? 'null'})`);
        }
        const out = twin.formatTwin(fx.mockPayload, fx.inputUrl, simpleHtmlToMd);
        if (!out) throw new Error(`[fixture ${file}] formatTwin returned null`);
        for (const needle of fx.expectMarkdownIncludes ?? []) {
          if (!out.markdown.includes(needle)) {
            throw new Error(`[fixture ${file}] Markdown missing expected "${needle}"`);
          }
        }
      } else if (fx.mode === 'html') {
        const out = applyPostFetchSiteExtractor(fx.mockPayload, fx.inputUrl, '', simpleHtmlToMd);
        if (!out) throw new Error(`[fixture ${file}] applyPostFetchSiteExtractor returned null`);
        for (const needle of fx.expectMarkdownIncludes ?? []) {
          if (!out.markdown.includes(needle)) {
            throw new Error(`[fixture ${file}] HTML Markdown missing expected "${needle}"`);
          }
        }
      }
    }
  }

  console.log(
    `✔ Validated ${selected.length} declarative YAML adapter(s), ${fixturesChecked} fixture(s), and ${totalFuzzed} adversarial bulkhead fuzz cases (${formattedFuzzHits} exercised formatting & sanitization; < ${MAX_FUZZ_MS_PER_PAYLOAD}ms budget; max: ${worstMs.toFixed(2)}ms on ${worstLabel || 'n/a'}).`,
  );

  // Live polite test + optional `--record`
  if (liveUrlArg) {
    const safeFetch = createSafeOutboundFetch();
    const userAgent = 'EdgeFetch/2.7 (+https://github.com/bartrumb/edgefetch)';
    const checkPoliteRobots = async (uStr) => {
      const u = new URL(uStr);
      const rob = await fetchOverflowRobots(u.origin, userAgent, safeFetch, Date.now() + 8_000);
      if (rob.disallowAiInput) {
        throw new Error(`Blocked by Content-Signal: ai-input=no on ${u.origin}/robots.txt`);
      }
      if (rob.unreachable) {
        throw new Error(rob.reason || `Unable to verify ${u.origin}/robots.txt`);
      }
      const pathAndQuery = `${u.pathname}${u.search}`;
      if (!isRobotsAllowed(rob, pathAndQuery)) {
        throw new Error(
          `Disallowed by ${u.origin}/robots.txt for path "${pathAndQuery}". Use htmlRoutes on a robots-permitted HTML path instead of twin.`,
        );
      }
    };

    await checkPoliteRobots(liveUrlArg);
    const twin = resolveSiteExtractorTwin(liveUrlArg);
    if (twin) {
      if (twin.fetchUrl !== liveUrlArg) {
        await checkPoliteRobots(twin.fetchUrl);
      }
      const res = await safeFetch(twin.fetchUrl, {
        headers: { accept: twin.accept, 'user-agent': userAgent },
      });
      const rawBody = await res.text();
      if (!res.ok) {
        throw new Error(`Live twin fetch returned HTTP ${res.status} from ${twin.fetchUrl}`);
      }
      const fmtBox = runAdapterSyncInBulkhead(
        twin.id,
        (inp) => twin.formatTwin(inp.rawBody, inp.liveUrlArg, simpleHtmlToMd),
        { rawBody, liveUrlArg },
      );
      const formatted = fmtBox.ok ? fmtBox.value : null;
      if (!formatted) {
        throw new Error(`Adapter "${twin.id}" formatTwin() returned null on live response (${rawBody.length} chars)`);
      }
      const savings = rawBody.length > 0 ? ((1 - formatted.markdown.length / rawBody.length) * 100).toFixed(1) : '0.0';
      console.log(`\n── Live Twin Result (${twin.id}) ─────────────────────────────────`);
      console.log(`Input URL:   ${liveUrlArg}`);
      console.log(`Twin URL:    ${twin.fetchUrl} (HTTP ${res.status}, ${rawBody.length.toLocaleString()} chars)`);
      console.log(`Title:       ${formatted.title}`);
      console.log(`Compression: ${formatted.markdown.length.toLocaleString()} Markdown chars (${savings}% reduction)`);
      console.log('──────────────────────────────────────────────────────────────────');
      console.log(formatted.markdown.split('\n').slice(0, 30).join('\n'));

      if (recordFlag) {
        mkdirSync(fixturesDir, { recursive: true });
        const outPath = resolveSafeFixtureWritePath(fixturesDir, twin.id);
        const firstHeading = formatted.markdown.split('\n').find((l) => l.startsWith('# ')) ?? formatted.title;
        const fxObj = {
          adapterId: twin.id,
          mode: 'twin',
          inputUrl: liveUrlArg,
          expectedFetchUrl: twin.fetchUrl,
          mockPayload: rawBody.slice(0, 65_536),
          expectTitleIncludes: formatted.title.slice(0, 40),
          expectMarkdownIncludes: [firstHeading.slice(0, 60)],
        };
        writeFileSync(outPath, `${JSON.stringify(fxObj, null, 2)}\n`, 'utf8');
        console.log(`\n✔ Recorded fixture: ${outPath}`);
      }
    } else {
      const res = await safeFetch(liveUrlArg, {
        headers: { accept: 'text/html', 'user-agent': userAgent },
      });
      const rawHtml = await res.text();
      const baseDoc = extractHtmlDocument(rawHtml, { baseUrl: liveUrlArg, onlyMainContent: true });
      console.log(`\n── Live HTML Extraction (${baseDoc.extractorId ?? 'generic'}) ─────────────────`);
      console.log(`Input URL: ${liveUrlArg} (HTTP ${res.status}, ${rawHtml.length.toLocaleString()} chars)`);
      console.log(`Title:     ${baseDoc.title ?? '(none)'}`);
      console.log(baseDoc.markdown.split('\n').slice(0, 30).join('\n'));

      if (recordFlag && baseDoc.extractorId) {
        mkdirSync(fixturesDir, { recursive: true });
        const outPath = resolveSafeFixtureWritePath(fixturesDir, baseDoc.extractorId);
        const firstHeading = baseDoc.markdown.split('\n').find((l) => l.startsWith('# ')) ?? (baseDoc.title || '');
        const fxObj = {
          adapterId: baseDoc.extractorId,
          mode: 'html',
          inputUrl: liveUrlArg,
          mockPayload: rawHtml.slice(0, 65_536),
          expectTitleIncludes: (baseDoc.title || '').slice(0, 40),
          expectMarkdownIncludes: [firstHeading.slice(0, 60)].filter(Boolean),
        };
        writeFileSync(outPath, `${JSON.stringify(fxObj, null, 2)}\n`, 'utf8');
        console.log(`\n✔ Recorded HTML fixture: ${outPath}`);
      }
    }
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
