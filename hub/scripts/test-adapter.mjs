#!/usr/bin/env node
/**
 * EdgeFetch Adapter Workbench, Live Polite Recorder & Linear-Time Fuzzer:
 *
 *   npm run adapter:test                                    # Validate + fuzz all registered adapters & fixtures
 *   npm run adapter:test crates-io                          # Validate + fuzz a single adapter + its fixture
 *   npm run adapter:test crates-io https://crates.io/crates/serde
 *   npm run adapter:test crates-io https://crates.io/crates/serde --record
 */

import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';

const hubRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const rawArgs = process.argv.slice(2);
const recordFlag = rawArgs.includes('--record');
const positional = rawArgs.filter((a) => !a.startsWith('--'));

const targetSlug = positional[0] && !positional[0].startsWith('https://') ? positional[0].trim() : null;
const liveUrlArg = positional.find((a) => a.startsWith('https://')) ?? null;

if (rawArgs.includes('--help') || rawArgs.includes('-h')) {
  console.log(
    [
      'Usage:',
      '  npm run adapter:test                                      # Validate, run fixtures & fuzz all adapters',
      '  npm run adapter:test <adapter-id>                         # Validate, run fixture & fuzz one adapter',
      '  npm run adapter:test <adapter-id> <https://url>           # Polite live test (checks robots.txt + SSRF)',
      '  npm run adapter:test <adapter-id> <https://url> --record  # Polite live test + write test/fixtures/adapters/<id>.json',
    ].join('\n'),
  );
  process.exit(0);
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

const MAX_FUZZ_MS_PER_PAYLOAD = 120;

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

  const adversarialPayloads = [
    { name: 'unclosed-pseudo-tags-20k (R4-H1)', body: `<p>ok</p>${'<x'.repeat(20_000)}` },
    { name: 'unquoted-attr-40k (R4-H2)', body: `<div ${'a'.repeat(40_000)}>text</div>` },
    { name: 'unanchored-repeat-120k (R4-H2)', body: 'a'.repeat(120_000) },
    { name: 'unclosed-comments-30k (R3-H1)', body: '<!--'.repeat(30_000) },
    { name: 'truncated-nested-json', body: `{"data":${'['.repeat(4_000)}` },
    {
      name: 'dense-json-array-500',
      body: JSON.stringify({
        items: Array.from({ length: 500 }, (_, i) => ({ id: `id-${i}`, name: `Item ${i}`, title: `Role ${i}` })),
      }),
    },
  ];

  let totalFuzzed = 0;
  let worstMs = 0;
  let worstLabel = '';

  for (const adapter of selected) {
    if (!adapter.exampleUrls?.length || !adapter.exampleUrls[0]?.startsWith('https://')) {
      throw new Error(`[${adapter.id}] Must define at least one https:// exampleUrl`);
    }
    const sampleUrl = adapter.exampleUrls[0];
    const parsedUrl = new URL(sampleUrl);
    const parts = parsedUrl.pathname.split('/').filter(Boolean);

    if (typeof adapter.resolveTwin === 'function') {
      const twinBox = runAdapterSyncInBulkhead(
        adapter.id,
        (ctx) => adapter.resolveTwin(ctx),
        { url: parsedUrl, urlStr: sampleUrl, host: parsedUrl.hostname.toLowerCase(), path: parsedUrl.pathname, parts },
      );
      if (!twinBox.ok) {
        throw new Error(`[${adapter.id}] resolveTwin threw in bulkhead: ${twinBox.error}`);
      }
      const twin = twinBox.value;
      if (twin) {
        if (typeof twin.fetchUrl !== 'string' || !twin.fetchUrl.startsWith('https://')) {
          throw new Error(`[${adapter.id}] twin.fetchUrl must start with https:// (got ${JSON.stringify(twin)})`);
        }
        if (twin.kind === 'text' && !GO_KIND_TEXT_ACCEPT_ALLOWLIST.has(twin.accept)) {
          throw new Error(
            `[${adapter.id}] kind="text" accept="${twin.accept}" violates Go allowlist: ${[...GO_KIND_TEXT_ACCEPT_ALLOWLIST].join(', ')}`,
          );
        }
        for (const p of adversarialPayloads) {
          const t0 = performance.now();
          const fBox = runAdapterSyncInBulkhead(
            adapter.id,
            (inp) => twin.formatTwin(inp.body, inp.sampleUrl, simpleHtmlToMd),
            { body: p.body, sampleUrl },
            MAX_FUZZ_MS_PER_PAYLOAD,
          );
          const dt = performance.now() - t0;
          if (!fBox.ok && String(fBox.error).includes('AdapterNetworkForbiddenError')) {
            throw new Error(`[${adapter.id}] Forbidden fetch() call inside formatTwin!`);
          }
          totalFuzzed++;
          if (dt > worstMs) {
            worstMs = dt;
            worstLabel = `${adapter.id} (twin:${p.name})`;
          }
          if (dt > MAX_FUZZ_MS_PER_PAYLOAD) {
            throw new Error(
              `[${adapter.id}] Potential superlinear slowdown on ${p.name}: ${dt.toFixed(1)}ms > ${MAX_FUZZ_MS_PER_PAYLOAD}ms`,
            );
          }
        }
      }
    }

    if (typeof adapter.extractHtml === 'function') {
      for (const p of adversarialPayloads) {
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
        const dt = performance.now() - t0;
        if (!hBox.ok && String(hBox.error).includes('AdapterNetworkForbiddenError')) {
          throw new Error(`[${adapter.id}] Forbidden fetch() call inside extractHtml!`);
        }
        totalFuzzed++;
        if (dt > worstMs) {
          worstMs = dt;
          worstLabel = `${adapter.id} (html:${p.name})`;
        }
        if (dt > MAX_FUZZ_MS_PER_PAYLOAD) {
          throw new Error(
            `[${adapter.id}] Potential superlinear slowdown in extractHtml on ${p.name}: ${dt.toFixed(1)}ms > ${MAX_FUZZ_MS_PER_PAYLOAD}ms`,
          );
        }
      }
    }
  }

  // Run matching JSON fixtures
  const fixturesDir = join(hubRoot, 'test', 'fixtures', 'adapters');
  let fixturesChecked = 0;
  if (existsSync(fixturesDir)) {
    for (const file of readdirSync(fixturesDir).filter((f) => f.endsWith('.json'))) {
      const fx = JSON.parse(readFileSync(join(fixturesDir, file), 'utf8'));
      if (targetSlug && fx.adapterId !== targetSlug) continue;
      fixturesChecked++;
      if (fx.mode === 'twin') {
        const twin = resolveSiteExtractorTwin(fx.inputUrl);
        if (!twin || twin.id !== fx.adapterId) {
          throw new Error(`[fixture ${file}] Expected twin "${fx.adapterId}" for ${fx.inputUrl}`);
        }
        const out = twin.formatTwin(fx.mockPayload, fx.inputUrl, simpleHtmlToMd);
        if (!out) throw new Error(`[fixture ${file}] formatTwin returned null`);
        for (const needle of fx.expectMarkdownIncludes ?? []) {
          if (!out.markdown.includes(needle)) {
            throw new Error(`[fixture ${file}] Markdown missing expected "${needle}"`);
          }
        }
      }
    }
  }

  console.log(
    `✔ Validated ${selected.length} adapter(s), ${fixturesChecked} fixture(s), and ${totalFuzzed} adversarial bulkhead fuzz cases (max: ${worstMs.toFixed(2)}ms on ${worstLabel || 'n/a'}).`,
  );

  // Live polite test + optional `--record`
  if (liveUrlArg) {
    const safeFetch = createSafeOutboundFetch();
    const userAgent = 'EdgeFetch/2.6 (+https://github.com/bartrumb/edgefetch)';
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
          `Disallowed by ${u.origin}/robots.txt for path "${pathAndQuery}". Use extractHtml() on a robots-permitted HTML path instead of resolveTwin().`,
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
        const outPath = join(fixturesDir, `${twin.id}.json`);
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
    }
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
