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
  let worstMs = 0;
  let worstLabel = '';

  for (const adapter of selected) {
    if (!SAFE_ID_RE.test(adapter.id)) {
      throw new Error(`Adapter id "${adapter.id}" violates ${SAFE_ID_RE}`);
    }
    if (!adapter.exampleUrls?.length || !adapter.exampleUrls[0]?.startsWith('https://')) {
      throw new Error(`[${adapter.id}] Must define at least one https:// exampleUrl`);
    }

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

        for (const p of adversarialPayloads) {
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
            return elapsed;
          };
          // Best-of-3 re-measurement when a single iteration hits a V8 GC or CI hypervisor preemption pause:
          // deterministic O(N^2) slowdowns exceed MAX_FUZZ_MS_PER_PAYLOAD on every trial.
          let dt = runTwinTrial();
          if (dt > MAX_FUZZ_MS_PER_PAYLOAD) dt = Math.min(dt, runTwinTrial(), runTwinTrial());
          totalFuzzed++;
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
      const sampleUrl = adapter.exampleUrls[adapter.exampleUrls.length - 1];
      const parsedUrl = new URL(sampleUrl);
      const parts = parsedUrl.pathname.split('/').filter(Boolean);
      for (const p of adversarialPayloads) {
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
              currentMd: p.body.slice(0, 4_000),
              htmlToMd: simpleHtmlToMd,
            },
            MAX_FUZZ_MS_PER_PAYLOAD,
          );
          const elapsed = performance.now() - t0;
          if (!hBox.ok && String(hBox.error).includes('AdapterNetworkForbiddenError')) {
            throw new Error(`[${adapter.id}] Forbidden fetch() call inside extractHtml!`);
          }
          return elapsed;
        };
        let dt = runHtmlTrial();
        if (dt > MAX_FUZZ_MS_PER_PAYLOAD) dt = Math.min(dt, runHtmlTrial(), runHtmlTrial());
        totalFuzzed++;
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
    `✔ Validated ${selected.length} declarative YAML adapter(s), ${fixturesChecked} fixture(s), and ${totalFuzzed} adversarial bulkhead fuzz cases (< ${MAX_FUZZ_MS_PER_PAYLOAD}ms budget; max: ${worstMs.toFixed(2)}ms on ${worstLabel || 'n/a'}).`,
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
