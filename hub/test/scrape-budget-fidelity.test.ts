import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { cutMarkdownToSanitizerBudget, stripInvisibleSmugglingChars } from '../src/scrape-advanced';
import {
  executeScrapeCall,
  finalizeScrapedMarkdown,
  redactPiiText,
  sanitizeNodeSuppliedUrls,
  sniffLargeStructuredJsonKind,
  tryParseJsonPayloadForScrape,
} from '../src/scrape';
import { readArtifactPage } from '../src/storage';
import { MAX_WASM_INPUT_BYTES, resetIsolateBudgetForTests } from '../src/wasm-bridge';
import { NodeFsR2Bucket } from './stubs/cf-storage-mocks';

function tempBucket(dirs: string[]): NodeFsR2Bucket {
  const dir = mkdtempSync(join(tmpdir(), 'ef-budget-fidelity-'));
  dirs.push(dir);
  return new NodeFsR2Bucket(dir);
}

const overBudget = (unit: string) => unit.repeat(Math.ceil((MAX_WASM_INPUT_BYTES + 512 * 1024) / unit.length));

test('parsers: [] with an omitted body returns a warning and the artifact reference instead of a bare ok', async () => {
  resetIsolateBudgetForTests();
  const pdfUrl = 'https://files.example.com/big.pdf';
  const blobSha = 'a'.repeat(64);
  const res = await executeScrapeCall({
    payload: { url: pdfUrl, formats: ['rawBase64'], parsers: [] },
    env: {},
    executeHubFetch: async () => ({
      status: 200,
      via: 'agent:home-node',
      bodyText: JSON.stringify({
        results: [
          {
            id: 'scrape-1',
            url: pdfUrl,
            status: 200,
            outcome: 'ok',
            contentType: 'application/pdf',
            bodyOmitted: true,
            bodyBase64Omitted: true,
            artifact: { blobSha256: blobSha, contentSha256: 'b'.repeat(64), contentBytes: 15 * 1024 * 1024 },
          },
        ],
      }),
    }),
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.rawBase64, undefined);
  assert.equal(res.body.artifactId, blobSha);
  const warnings = (res.body.warnings as string[] | undefined) ?? [];
  assert.ok(warnings.some((w) => w.includes('rawBase64') && w.includes('artifactId')), JSON.stringify(warnings));
});

test('cutMarkdownToSanitizerBudget keeps long single-line documents instead of snapping back to an early line break', () => {
  // A short first line followed by multi-MiB minified content: the only `\n` is at offset 7.
  const minified = `# Data\n${'{"k":"v","n":1},'.repeat(400_000)}`;
  assert.ok(minified.length > MAX_WASM_INPUT_BYTES);
  const ascii = cutMarkdownToSanitizerBudget(minified);
  assert.equal(ascii.cut, true);
  assert.ok(ascii.text.length > 3 * 1024 * 1024, `ASCII cut kept only ${ascii.text.length} chars`);

  // Same with non-ASCII content (encodeInto path), including a surrogate pair at the boundary region.
  const wide = `# Données\n${'é😀'.repeat(1_200_000)}`;
  const cutWide = cutMarkdownToSanitizerBudget(wide);
  assert.equal(cutWide.cut, true);
  assert.ok(cutWide.text.length > 1024 * 1024, `non-ASCII cut kept only ${cutWide.text.length} chars`);
  const last = cutWide.text.charCodeAt(cutWide.text.length - 1);
  assert.equal(last >= 0xd800 && last <= 0xdbff, false, 'cut must not end on a lone high surrogate');
  assert.ok(new TextEncoder().encode(cutWide.text).byteLength <= MAX_WASM_INPUT_BYTES);

  // A nearby line break is still preferred.
  const lined = `${'line of prose\n'.repeat(400_000)}`;
  const cutLined = cutMarkdownToSanitizerBudget(lined);
  assert.equal(cutLined.text.endsWith('line of prose'), true);
});

test('finalizeScrapedMarkdown bounds sanitizer growth to the budget and flags it (no silent downstream cuts)', () => {
  // ~3.6 MB of `a < b` prose: under the input budget, but escaping `<` grows the sanitized output past it.
  const doc = `# Growth\n\n${'a < b and c < d\n'.repeat(225_000)}TAIL_SENTINEL\n`;
  assert.equal(cutMarkdownToSanitizerBudget(doc).cut, false, 'fixture input must fit the sanitizer budget');
  const fin = finalizeScrapedMarkdown(doc, { isPdf: false, includeImages: false, baseUrl: 'https://growth.example.com/doc.md' });
  assert.equal(
    cutMarkdownToSanitizerBudget(fin.markdown).cut,
    false,
    'sanitized output must already fit the budget so redactPiiText / stripInvisible / neutralize never cut it',
  );
  assert.equal(stripInvisibleSmugglingChars(fin.markdown).length, fin.markdown.length);
  assert.equal(redactPiiText(fin.markdown).length, fin.markdown.length);
  assert.equal(fin.markdown.includes('TAIL_SENTINEL'), false, 'fixture must grow past the budget when sanitized');
  assert.equal(fin.truncated, true, 'any cut of the sanitized document must set truncated: true');
  assert.equal(fin.sourceTruncated, true);
  assert.equal(fin.sourceChars, doc.length);
  // Sanitized-output coordinates: everything that exists is in `markdown`; nothing unfetchable is advertised.
  assert.equal(fin.totalChars, fin.markdown.length);
  assert.equal(fin.nextOffset, fin.markdown.length);
  assert.equal(fin.remainingChars, 0);
  assert.ok(fin.markdown.length > 3_000_000, `bounded output should stay close to the budget, got ${fin.markdown.length}`);
  assert.equal(fin.markdown.includes('a < b'), false, 'raw `<` must never survive sanitization');
});

test('finalizeScrapedMarkdown over-budget input: totals are sanitized-output chars, raw length is sourceChars', () => {
  const doc = `# Big\n\n${overBudget('plain prose line for paging\n')}`;
  const fin = finalizeScrapedMarkdown(doc, { isPdf: false, includeImages: false, maxChars: 100_000 });
  assert.equal(fin.truncated, true);
  assert.equal(fin.sourceTruncated, true);
  assert.equal(fin.sourceChars, doc.length);
  assert.ok((fin.totalChars ?? 0) < doc.length, 'totalChars must not be the raw input length');
  assert.equal((fin.nextOffset ?? 0) + (fin.remainingChars ?? 0), fin.totalChars);
  assert.ok(fin.markdown.length <= 100_000);
});

test('scrape pagination: totalChars / nextOffset / remainingChars match what read_artifact serves', async (t) => {
  const dirs: string[] = [];
  t.after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  resetIsolateBudgetForTests();
  const pageUrl = 'https://paging.example.com/guide.md';
  // ~3.6 MB origin markdown (between MAX_HTML_SCAN_CHARS and the 4 MiB budget) whose sanitized form grows past it.
  const body = `# Paging Guide\n\n${'Compare a < b with c < d.\n'.repeat(140_000)}`;
  const bucket = tempBucket(dirs);
  const res = await executeScrapeCall({
    payload: { url: pageUrl, formats: ['markdown'] },
    env: { ARTIFACTS: bucket as unknown as R2Bucket },
    executeHubFetch: async () => ({
      status: 200,
      via: 'cloudflare',
      bodyText: JSON.stringify({
        results: [
          { id: 'scrape-1', url: pageUrl, status: 200, outcome: 'ok', contentType: 'text/markdown; charset=utf-8', body, bodyEncoding: 'utf-8' },
        ],
      }),
    }),
  });
  assert.equal(res.status, 200);
  const b = res.body as Record<string, unknown>;
  assert.equal(b.truncated, true);
  const totalChars = b.totalChars as number;
  const nextOffset = b.nextOffset as number;
  const remainingChars = b.remainingChars as number;
  assert.equal(nextOffset + remainingChars, totalChars, 'one coordinate system: nextOffset + remainingChars === totalChars');
  assert.ok(remainingChars > 0);
  assert.equal(b.sourceTruncated, true, 'sanitized growth past the budget must be reported');
  assert.equal(b.sourceChars, body.length);
  assert.ok(totalChars < 5_000_000 && totalChars !== body.length);
  assert.equal(typeof b.markdownArtifactId, 'string');

  // Every advertised remaining char must be fetchable from the stored Markdown artifact.
  let cursor: number | null = nextOffset;
  let fetched = 0;
  let hops = 0;
  while (cursor !== null && hops < 50) {
    const page = await readArtifactPage({
      bucket: bucket as unknown as R2Bucket,
      blobSha256: b.markdownArtifactId as string,
      format: 'markdown',
      offset: cursor,
      limit: 1_000_000,
    });
    assert.equal(page.ok, true, JSON.stringify(page));
    if (!page.ok) break;
    assert.equal(page.page.totalChars, totalChars, 'read_artifact totalChars must equal the scrape response totalChars');
    fetched += (page.page.nextOffset ?? page.page.totalChars) - page.page.offset;
    cursor = page.page.nextOffset;
    hops++;
  }
  assert.equal(fetched, remainingChars, 'read_artifact must serve exactly the advertised remainingChars');
});

test('Go-node offload: accepted origin markdown (with query) is used, node links/favicon are sanitized, jsonFilter is sent', async (t) => {
  const dirs: string[] = [];
  t.after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  resetIsolateBudgetForTests();
  const pageUrl = 'https://offload.example.com/doc';

  const run = async (opts: { payload: Record<string, unknown>; body: string; contentType: string; nodeItem: Record<string, unknown> }) => {
    const agentRequests: Array<Record<string, unknown>> = [];
    const res = await executeScrapeCall({
      payload: { url: pageUrl, ...opts.payload },
      env: { ARTIFACTS: tempBucket(dirs) as unknown as R2Bucket },
      executeHubFetch: async (targetArg, callJson) => {
        if (targetArg === 'agent') {
          agentRequests.push(JSON.parse(String(callJson)) as Record<string, unknown>);
          return {
            status: 200,
            via: 'agent:home-node',
            bodyText: JSON.stringify({ results: [{ id: 'scrape-1', url: pageUrl, status: 200, outcome: 'ok', ...opts.nodeItem }] }),
          };
        }
        return {
          status: 200,
          via: 'cloudflare',
          bodyText: JSON.stringify({
            results: [{ id: 'scrape-1', url: pageUrl, status: 200, outcome: 'ok', contentType: opts.contentType, body: opts.body, bodyEncoding: 'utf-8' }],
          }),
        };
      },
    });
    return { res, agentRequests };
  };

  // 1) Over-budget origin markdown accepted from the node (reranked for `query`): the hub must use it, not ''.
  const originMd = `# Origin\n\n${overBudget('Origin markdown prose line about widgets.\n')}`;
  const origin = await run({
    payload: { formats: ['markdown'], query: 'widgets' },
    body: originMd,
    contentType: 'text/markdown; charset=utf-8',
    nodeItem: {
      contentType: 'text/markdown',
      contentSource: 'origin-markdown',
      extractedOnNode: true,
      bodyOmitted: true,
      markdown: '# Origin\n\nNODE_RERANKED_WIDGETS passage about widgets.\n\n<script>alert(1)</script>',
    },
  });
  assert.equal(origin.agentRequests.length, 1);
  assert.equal(origin.res.status, 200);
  const originOut = String(origin.res.body.markdown ?? '');
  assert.ok(originOut.includes('NODE_RERANKED_WIDGETS'), `expected accepted node markdown, got ${JSON.stringify(originOut.slice(0, 200))}`);
  assert.equal(originOut.includes('<script'), false, 'node markdown must still pass the edge sanitizer');

  // 2) Node-supplied links / favicon go through the edge URL sanitizer.
  const bigHtml = `<!doctype html><html><head><title>Big</title></head><body><main>${overBudget('<p>edge words</p>')}</main></body></html>`;
  const html = await run({
    payload: { formats: ['markdown', 'links'] },
    body: bigHtml,
    contentType: 'text/html; charset=utf-8',
    nodeItem: {
      contentType: 'text/html',
      extractedOnNode: true,
      bodyOmitted: true,
      title: 'Big',
      markdown: '# Big\n\nNODE_HTML_MD',
      favicon: 'javascript:alert(1)',
      links: [
        'javascript:alert(1)',
        'https://offload.example.com/ok',
        'https://offload.example.com/ok',
        'http://127.0.0.1/internal',
        'data:text/html,<script>alert(1)</script>',
        'https://offload.example.com/a b(c)',
      ],
    },
  });
  const links = (html.res.body.links as string[] | undefined) ?? [];
  assert.ok(links.includes('https://offload.example.com/ok'));
  assert.equal(links.filter((l) => l === 'https://offload.example.com/ok').length, 1, 'duplicates collapsed');
  assert.equal(links.some((l) => /^(?:javascript|data):/i.test(l) || l.includes('127.0.0.1')), false, JSON.stringify(links));
  assert.equal(links.some((l) => /[ ()]/.test(l)), false, `unsafe URL chars must be percent-encoded: ${JSON.stringify(links)}`);
  assert.equal(String(html.res.body.favicon ?? '').toLowerCase().startsWith('javascript:'), false);

  // 3) jsonFilter is sent with the offload request and no longer reported as unavailable.
  const records = JSON.stringify(
    Array.from({ length: 20_000 }, (_, i) => ({ id: `r${i}`, title: `Role ${i}`, team: i % 2 ? 'Sales' : 'Platform', descriptionPlain: 'x'.repeat(200) })),
  );
  const json = await run({
    payload: { formats: ['markdown'], jsonFilter: 'team=Platform' },
    body: records,
    contentType: 'application/json',
    nodeItem: { contentType: 'application/json', extractedOnNode: true, bodyOmitted: true, title: 'JSON Records (1 of 2 records)', markdown: '## Role 0 [r0]\n- **team**: Platform' },
  });
  assert.equal(json.agentRequests.length, 1);
  const sentReq = ((json.agentRequests[0]!.requests as Array<Record<string, unknown>>) ?? [])[0]!;
  assert.equal(sentReq.jsonFilter, 'team=Platform');
  const jsonWarnings = (json.res.body.warnings as string[] | undefined) ?? [];
  assert.equal(jsonWarnings.some((w) => w.includes('jsonFilter')), false, JSON.stringify(jsonWarnings));
  assert.ok(String(json.res.body.markdown ?? '').includes('Role 0'));
});

test('sanitizeNodeSuppliedUrls drops unsafe node URLs and keeps safe https ones', () => {
  const out = sanitizeNodeSuppliedUrls(
    { links: ['https://a.example.com/x', 'vbscript:msgbox(1)', 42, 'https://a.example.com/x'], favicon: 'http://10.0.0.1/f.ico' },
    'https://a.example.com/',
  );
  assert.deepEqual(out.links, ['https://a.example.com/x']);
  assert.equal('favicon' in out, false);
  const keep = sanitizeNodeSuppliedUrls({ favicon: '/favicon.png' }, 'https://a.example.com/page');
  assert.equal(keep.favicon, 'https://a.example.com/favicon.png');

  const imgs = sanitizeNodeSuppliedUrls(
    {
      images: [
        { url: '/img/a.png', alt: 'A <b>bold</b> alt' },
        { url: 'javascript:alert(1)', alt: 'x' },
        { url: 'http://192.168.1.5/private.png' },
        'https://cdn.example.com/b.jpg',
        { url: '/img/a.png' },
      ],
    },
    'https://a.example.com/page',
  );
  const imgList = imgs.images as Array<{ url: string; alt?: string }>;
  assert.deepEqual(
    imgList.map((i) => i.url),
    ['https://a.example.com/img/a.png', 'https://cdn.example.com/b.jpg'],
  );
  assert.equal((imgList[0]?.alt ?? '').includes('<'), false, 'node image alt text must be plain text');
});

test('JSON over the 2 MiB JS-parse cap keeps OpenAPI / notebook formatting via the Go formatters', () => {
  const paths = Array.from({ length: 60 }, (_, i) => `"/v1/items-${i}":{"get":{"summary":"List items ${i}"}}`).join(',');
  const pad = JSON.stringify('vendor extension padding '.repeat(100_000));
  const spec = `{"openapi":"3.0.3","info":{"title":"Large Spec","version":"2"},"x-pad":${pad},"paths":{${paths}}}`;
  assert.ok(spec.length > 2 * 1024 * 1024 && spec.length < MAX_WASM_INPUT_BYTES);
  assert.equal(sniffLargeStructuredJsonKind(spec, 'https://api.example.com/openapi.json'), 'openapi');
  const specDoc = tryParseJsonPayloadForScrape(spec, 'application/json', 'https://api.example.com/openapi.json');
  assert.ok(specDoc);
  assert.equal(specDoc.structuredKind, 'openapi');
  assert.ok(specDoc.markdown.includes('/v1/items-12'), specDoc.markdown.slice(0, 300));
  assert.equal(specDoc.markdown.includes('JSON payload truncated'), false);

  const cells = Array.from({ length: 8_000 }, (_, i) => ({
    cell_type: i % 2 ? 'code' : 'markdown',
    metadata: {},
    source: [i % 2 ? `print(${i})  # ${'c'.repeat(300)}` : `## Section ${i}\n${'m'.repeat(300)}`],
    ...(i % 2 ? { outputs: [], execution_count: i } : {}),
  }));
  const nb = JSON.stringify({ cells, metadata: { kernelspec: { name: 'python3' } }, nbformat: 4, nbformat_minor: 5 });
  assert.ok(nb.length > 2 * 1024 * 1024 && nb.length < MAX_WASM_INPUT_BYTES);
  assert.equal(sniffLargeStructuredJsonKind(nb, 'https://nb.example.com/analysis.ipynb'), 'ipynb');
  const nbDoc = tryParseJsonPayloadForScrape(nb, 'application/x-ipynb+json', 'https://nb.example.com/analysis.ipynb');
  assert.ok(nbDoc);
  assert.equal(nbDoc.structuredKind, 'ipynb');
  assert.ok(nbDoc.markdown.includes('Section 7998'), 'notebook tail cells must be rendered, not cut at a preview');

  // Generic large JSON is unaffected (bounded preview).
  const generic = JSON.stringify({ rows: Array.from({ length: 60_000 }, (_, i) => ({ i, v: 'value-'.repeat(6) })) });
  assert.ok(generic.length > 2 * 1024 * 1024);
  assert.equal(sniffLargeStructuredJsonKind(generic, 'https://data.example.com/rows.json'), null);
  assert.equal(tryParseJsonPayloadForScrape(generic, 'application/json', 'https://data.example.com/rows.json')?.structuredKind, undefined);
});
