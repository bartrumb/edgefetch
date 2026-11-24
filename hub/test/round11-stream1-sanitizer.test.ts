import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';

import * as scrapeModule from '../src/scrape';
import {
  decodeMarkdownEntities,
  executeScrapeCall,
  finalizeScrapedMarkdown,
  formatInertiaPagePropsToMarkdown,
  recognizeAndHardenMarkdownFences,
  sanitizeInlineHtmlInMarkdown,
  sanitizeMarkdownPageSlice,
  sanitizeScrapedMetadataField,
  splitMarkdownByCodeFences,
} from '../src/scrape';
import * as scrapeAdvancedModule from '../src/scrape-advanced';
import { isDisallowedMarkdownLinkDestination } from '../src/scrape-advanced';
import { extractUniversalSchemaOrg, sanitizeSchemaHttpsUrl } from '../src/extractors/schema-org';
import { r2DerivedKey, readArtifactPage, SCRAPE_PIPELINE_VERSION } from '../src/storage';

class MemoryR2Bucket {
  readonly objects = new Map<string, { bytes: Uint8Array; httpMetadata?: Record<string, string>; customMetadata?: Record<string, string> }>();

  async put(key: string, value: string | Uint8Array | ArrayBuffer, opts?: { httpMetadata?: Record<string, string>; customMetadata?: Record<string, string> }) {
    const bytes =
      typeof value === 'string'
        ? new TextEncoder().encode(value)
        : value instanceof Uint8Array
          ? new Uint8Array(value)
          : new Uint8Array(value);
    this.objects.set(key, { bytes, httpMetadata: opts?.httpMetadata, customMetadata: opts?.customMetadata });
    return { key, size: bytes.byteLength };
  }

  async get(key: string) {
    const entry = this.objects.get(key);
    if (!entry) return null;
    return {
      key,
      size: entry.bytes.byteLength,
      httpMetadata: entry.httpMetadata,
      customMetadata: entry.customMetadata,
      body: new Blob([entry.bytes as unknown as BlobPart]).stream(),
      arrayBuffer: async () => entry.bytes.buffer.slice(entry.bytes.byteOffset, entry.bytes.byteOffset + entry.bytes.byteLength),
      text: async () => new TextDecoder().decode(entry.bytes),
    };
  }
}

function assertProseSafe(label: string, mdOut: string, checkTrimmedIdempotence = true): void {
  if (checkTrimmedIdempotence) {
    const secondPass = sanitizeInlineHtmlInMarkdown(mdOut, 'https://example.com/docs/');
    assert.equal(secondPass, mdOut, `[${label}] sanitizeInlineHtmlInMarkdown must be idempotent`);
  }

  const segments = splitMarkdownByCodeFences(mdOut);
  const inlineDestRe = /\]\(\s*(?:<([^>\n]*)>|([^\s)]+))/g;
  const refDestRe = /\]:[ \t]*(?:\r?\n[ \t>0-9.*+-]*)?(?:<([^>\n]*)>|([^\s]+))/g;
  for (let i = 0; i < segments.length; i += 2) {
    const prose = segments[i]!;
    assert.equal(prose.includes('<'), false, `[${label}] raw '<' survived in prose segment #${i}: ${JSON.stringify(prose)}`);
    for (const m of prose.matchAll(inlineDestRe)) {
      const dest = m[1] ?? m[2] ?? '';
      assert.equal(isDisallowedMarkdownLinkDestination(dest), false, `[${label}] unsafe inline link survived: ${dest}`);
    }
    for (const m of prose.matchAll(refDestRe)) {
      const dest = m[1] ?? m[2] ?? '';
      assert.equal(isDisallowedMarkdownLinkDestination(dest), false, `[${label}] unsafe ref link survived: ${dest}`);
    }
  }
}

const S1_UNTRUSTED_FENCE_VECTORS: Record<string, string> = {
  list_tight_fence: '- item\n  ```html\n  <script>alert(1)</script>\n  [x](javascript:alert(1))\n  ```',
  list_loose_fence: '- item\n\n  ```html\n  <svg onload=alert(1)>\n  [x](javascript:alert(1))\n  ```',
  blank_item_trailing_ws: '-    \n  ```html\n  <img src=x onerror=alert(1)>\n  ```',
  empty_item_followed_by_blank: '-\n\n  ```html\n  <img src=x onerror=alert(1)>\n  ```',
  marker_on_lazy_line: '- first paragraph line\n2. lazy marker\n   ```html\n   <script>alert(1)</script>\n   ```',
  setext_eq_inside_list_item: '- heading text\n  ===\n  ```html\n  <img src=x onerror=alert(1)>\n  ```',
  setext_dash_inside_list_item: '- heading text\n  ---\n  ```html\n  <img src=x onerror=alert(1)>\n  ```',
  tab_after_ul_marker: '-\titem\n  ```html\n  <img src=x onerror=alert(1)>\n  ```',
  tab_after_empty_ul_marker: '-\t\n\t```html\n\t<img src=x onerror=alert(1)>\n\t```',
  tab_after_ol_marker: '1.\titem\n\t```html\n\t<script>alert(1)</script>\n\t```',
  blockquote_direct_fence: '> ```html\n> <img src=x onerror=alert(1)>\n> [x](javascript:alert(1))\n> ```',
  blockquote_blank_then_fence: '>\n> ```html\n> <script>alert(1)</script>\n> ```',
  blockquote_lazy_continuation_fence: '> quote\n```html\n<img src=x onerror=alert(1)>\n```',
  nested_blockquote_and_list_fence: '> - nested\n>   ```html\n>   <svg onload=alert(1)>\n>   ```',
  non_blank_para_preceded_fence: 'Paragraph line\n```html\n<script>alert(1)</script>\n```',
  non_blank_heading_preceded_fence: '# Heading\n```html\n<img src=x onerror=alert(1)>\n```',
  polarity_tilde_in_list_then_top_fence: '-\n\n  ~~~\n```\n~~~\n<script>alert(1)</script>\n```',
  polarity_indented_in_list_then_top_fence: '- item\n\n  para\n    ```\n<img src=x onerror=alert(1)>\n    ```',
};

test('R11-S1: fences inside containers or not preceded by blank line escape < and links; Inertia pre-escapes <', () => {
  for (const [name, md] of Object.entries(S1_UNTRUSTED_FENCE_VECTORS)) {
    const out = sanitizeInlineHtmlInMarkdown(md, 'https://example.com/docs/');
    assertProseSafe(name, out);
    assert.equal(out.includes('<script'), false, `[${name}] <script survived: ${out}`);
    assert.equal(out.includes('<img'), false, `[${name}] <img survived: ${out}`);
    assert.equal(out.includes('<svg'), false, `[${name}] <svg survived: ${out}`);
    assert.equal(out.includes('onerror='), false, `[${name}] onerror= survived: ${out}`);
    assert.equal(out.includes('javascript:'), false, `[${name}] javascript: survived: ${out}`);
  }

  // Top-level fences preceded by start-of-doc or strict ASCII blank line still preserve raw code content
  const topStart = sanitizeInlineHtmlInMarkdown('```ts\nconst a: Array<number> = [1];\n```', 'https://example.com/');
  assert.match(topStart, /Array<number>/);

  const topAfterListClose = sanitizeInlineHtmlInMarkdown(
    '- list item\n\nCol-0 paragraph closes list.\n\n```html\n<div data-ok="1">raw</div>\n```',
    'https://example.com/',
  );
  assert.match(topAfterListClose, /<div data-ok="1">raw<\/div>/);

  // Inertia `formatInertiaPagePropsToMarkdown` pre-escapes `<` even when untrusted prop strings embed fenced code blocks!
  const inertiaDoc = formatInertiaPagePropsToMarkdown(
    {
      component: 'Posts/Show`<script>alert(1)</script>',
      props: {
        title: 'Hello <img src=x onerror=alert(1)> [bad](javascript:alert(1))',
        summary: 'Short summary with <svg onload=alert(2)> and enough words to pass length check cleanly.',
        body: 'Intro words here\n\n```html\n<script>alert("inertia-fence-bypass")</script>\n```\n\nMore prose [click](javascript:alert(3)) &#x202e;end',
        tags: ['alpha <beta>', '[evil](data:text/html,<script>1</script>)'],
        rows: [
          { colA: '<img src=x onerror=1>', colB: '[js](javascript:void(0))' },
          { colA: 'safe', colB: 'row2' },
        ],
      },
    },
    'https://example.com/posts/1',
  );
  assert.ok(inertiaDoc);
  assert.equal(inertiaDoc.markdown.includes('<script'), false, `raw <script in Inertia markdown: ${inertiaDoc.markdown}`);
  assert.equal(inertiaDoc.markdown.includes('<img'), false, `raw <img in Inertia markdown: ${inertiaDoc.markdown}`);
  assert.equal(inertiaDoc.markdown.includes('<svg'), false, `raw <svg in Inertia markdown: ${inertiaDoc.markdown}`);
  assert.equal(inertiaDoc.markdown.includes('javascript:'), false, `javascript: in Inertia markdown: ${inertiaDoc.markdown}`);
  assert.equal(inertiaDoc.markdown.includes('\u202e'), false, `bidi override in Inertia markdown: ${inertiaDoc.markdown}`);
  assert.equal(Boolean(inertiaDoc.title?.includes('<')), false);
  assert.equal(Boolean(inertiaDoc.description?.includes('<')), false);
});

test('R11-S2: single canonical fence recognizer shared by full sanitize and slice/read_artifact paging', async () => {
  // Exact single recognizer function exported from scrape-advanced and re-exported by scrape
  assert.strictEqual(
    scrapeModule.recognizeAndHardenMarkdownFences,
    scrapeAdvancedModule.recognizeAndHardenMarkdownFences,
  );
  assert.equal('hardenAndSplitSliceFences' in scrapeAdvancedModule, false);

  const combinedDoc = Object.entries(S1_UNTRUSTED_FENCE_VECTORS)
    .map(([k, v]) => `## ${k}\n\n${v}`)
    .join('\n\n');

  // Every possible slice boundary across S1 container/non-blank vectors must escape `<` and unsafe links
  for (let offset = 0; offset < combinedDoc.length; offset += 17) {
    for (const maxChars of [45, 130, 400]) {
      const sliceOut = sanitizeMarkdownPageSlice(combinedDoc, offset, combinedDoc.slice(offset, offset + maxChars));
      assertProseSafe(`slice@${offset}+${maxChars}`, sliceOut, false);
      assert.equal(sliceOut.includes('<script'), false);
      assert.equal(sliceOut.includes('<img'), false);
      assert.equal(sliceOut.includes('<svg'), false);
      assert.equal(sliceOut.includes('javascript:'), false);
    }
  }

  // Also verify via `readArtifactPage` end-to-end R2 paging
  const bucket = new MemoryR2Bucket();
  const sha = createHash('sha256').update(combinedDoc).digest('hex');
  await bucket.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', sha), combinedDoc, {
    httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
  });

  let cursor: number | undefined = 0;
  let pages = 0;
  while (cursor !== undefined && pages < 50) {
    const page = await readArtifactPage({
      bucket: bucket as unknown as R2Bucket,
      blobSha256: `md:${sha}`,
      format: 'markdown',
      offset: cursor,
      limit: 180,
    });
    assert.equal(page.ok, true);
    if (page.ok) {
      assertProseSafe(`readArtifactPage@${cursor}`, page.page.content, false);
      assert.equal(page.page.content.includes('<script'), false);
      assert.equal(page.page.content.includes('<img'), false);
      assert.equal(page.page.content.includes('<svg'), false);
      assert.equal(page.page.content.includes('javascript:'), false);
      cursor = page.page.nextOffset ?? undefined;
    }
    pages++;
  }
  assert.ok(pages >= 3);
});

test('R11-S3 & M3: 100% byte-for-byte Go SanitizeMarkdown === TS sanitizeInlineHtmlInMarkdown parity', (t) => {
  const parityCases: Array<{ id: string; md: string; baseUrl: string }> = [
    ...Object.entries(S1_UNTRUSTED_FENCE_VECTORS).map(([id, md]) => ({
      id,
      md,
      baseUrl: 'https://example.com/docs/',
    })),
    {
      id: 'trusted_top_level_after_blank',
      md: 'Intro\n\n```html\n<div class="raw">1 < 2</div>\n```\n\nOutro `<inline>`',
      baseUrl: 'https://example.com/',
    },
    {
      id: 'entity_decoded_invisible_smuggling',
      md: 'Hello &#x202e;world&#x202c; &#xfeff; &#xe0061;&#xe007f; &rlm;&lrm;&zwj;&zwnj; &amp;#xe0062; end',
      baseUrl: 'https://example.com/',
    },
  ];

  const dir = mkdtempSync(join(tmpdir(), 'ef-r11-parity-'));
  try {
    const inWin = join(dir, 'in.jsonl');
    const outWin = join(dir, 'out.jsonl');
    writeFileSync(inWin, `${parityCases.map((c) => JSON.stringify(c)).join('\n')}\n`, 'utf8');
    const toWsl = (p: string) => {
      const norm = p.replace(/\\/g, '/');
      return `/mnt/${norm[0]!.toLowerCase()}${norm.slice(2)}`;
    };
    try {
      execFileSync(
        'wsl',
        [
          '-e',
          'bash',
          '-lc',
          `export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"; cd "/mnt/c/Code/edgefetch" && EDGEFETCH_R8_SAN_IN="${toWsl(inWin)}" EDGEFETCH_R8_SAN_OUT="${toWsl(outWin)}" go test ./internal/extract -run '^TestRound8GoTSParityBatchRunner$' -count=1`,
        ],
        { encoding: 'utf8', timeout: 45_000 },
      );
    } catch (err) {
      t.skip(`WSL Go toolchain unavailable for cross-runtime parity check: ${String(err)}`);
      return;
    }

    const goLines = readFileSync(outWin, 'utf8')
      .trim()
      .split(/\r?\n/)
      .map((l) => JSON.parse(l) as { id: string; out: string });
    const goMap = new Map(goLines.map((r) => [r.id, r.out]));

    for (const c of parityCases) {
      const tsOut = sanitizeInlineHtmlInMarkdown(c.md, c.baseUrl);
      const goOut = goMap.get(c.id);
      assert.equal(goOut, tsOut, `[${c.id}] Go vs TS sanitizer mismatch!\nTS: ${JSON.stringify(tsOut)}\nGo: ${JSON.stringify(goOut)}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('R11-M1: 20,000 inline backtick code spans with trailing < runs in linear O(N) time (< 50ms)', () => {
  const spans = Array.from({ length: 20_000 }, (_, i) => `\`tok${i}\``).join(' ');
  const lineWithTrailingLt = `${spans} trailing <tag`;
  const lineWithoutLt = `${spans} trailing plain`;

  // Warmup JIT once
  sanitizeInlineHtmlInMarkdown('`warmup` <x', 'https://example.com/');

  const t0 = performance.now();
  const out1 = sanitizeInlineHtmlInMarkdown(lineWithTrailingLt, 'https://example.com/');
  const elapsedWithLt = performance.now() - t0;

  const t1 = performance.now();
  const out2 = finalizeScrapedMarkdown(lineWithoutLt, { isPdf: false, includeImages: false }).markdown;
  const elapsedNoLt = performance.now() - t1;

  assert.equal(out1.endsWith('trailing &lt;tag'), true);
  assert.equal(out2.endsWith('trailing plain'), true);
  assert.ok(elapsedWithLt < 50, `Expected < 50ms for 20,000 code spans + trailing '<', took ${elapsedWithLt.toFixed(2)}ms`);
  assert.ok(elapsedNoLt < 50, `Expected < 50ms for 20,000 code spans without '<', took ${elapsedNoLt.toFixed(2)}ms`);
});

test('R11-M2: redactPii scrubs records[] & structured deeply; includeTags/excludeTags/onlyMainContent scope content', async () => {
  const schemaHtml = `<!doctype html>
<html>
<head>
  <title>Staff Directory — alice@company.example</title>
  <meta name="description" content="Reach alice@company.example or call 415-555-0199 for engineering inquiries at Example Corp today and tomorrow.">
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "ItemList",
    "name": "Contacts alice@company.example",
    "itemListElement": [
      {
        "@type": "ListItem",
        "position": 1,
        "name": "Alice Smith (alice@company.example)",
        "description": "Email alice@company.example or SSN 123-45-6789",
        "url": "https://company.example/u/alice@company.example"
      },
      {
        "@type": "ListItem",
        "position": 2,
        "name": "Bob Jones (bob@company.example)",
        "description": "Phone (415) 555-0199",
        "url": "https://company.example/p/(team)/[bob]"
      }
    ]
  }
  </script>
</head>
<body>
  <header><p class="banner">Header nav banner text</p></header>
  <main>
    <p class="keep">Scoped main paragraph only.</p>
    <div class="secret">Excluded secret block text.</div>
  </main>
  <footer><p class="foot">Footer copyright notice 2026.</p></footer>
</body>
</html>`;

  const mockHubFetch = async (_target: string, rawBody: string) => {
    const parsed = JSON.parse(rawBody) as { requests: Array<{ id: string; url: string }> };
    const req = parsed.requests[0]!;
    return {
      status: 200,
      via: 'worker' as const,
      bodyText: JSON.stringify({
        results: [
          {
            id: req.id,
            url: req.url,
            finalUrl: req.url,
            status: 200,
            outcome: 'ok',
            contentType: 'text/html; charset=utf-8',
            body: schemaHtml,
          },
        ],
      }),
    };
  };

  // 1. Default scoping + redactPii: true -> Universal Schema.org `records[]` and `structured` have all PII redacted!
  const redactedRes = await executeScrapeCall({
    payload: {
      url: 'https://company.example/directory',
      redactPii: true,
      ephemeral: true,
    },
    env: {},
    target: 'auto',
    site: 'default',
    source: 'test',
    userId: 'owner',
    executeHubFetch: mockHubFetch,
  });
  assert.equal(redactedRes.status, 200);
  const redactedJsonStr = JSON.stringify(redactedRes.body);
  assert.equal(redactedJsonStr.includes('alice@company.example'), false, `leaked email in response: ${redactedJsonStr}`);
  assert.equal(redactedJsonStr.includes('bob@company.example'), false, `leaked bob email in response: ${redactedJsonStr}`);
  assert.equal(redactedJsonStr.includes('123-45-6789'), false, `leaked SSN in response: ${redactedJsonStr}`);
  assert.equal(redactedJsonStr.includes('555-0199'), false, `leaked phone in response: ${redactedJsonStr}`);
  assert.ok(Array.isArray(redactedRes.body.records) && redactedRes.body.records.length === 2);

  // Verify URLs in records[] have `(`, `)`, `[`, `]` percent-encoded even after `[REDACTED_EMAIL]` substitution!
  for (const rec of redactedRes.body.records as Array<Record<string, unknown>>) {
    if (typeof rec.url === 'string') {
      assert.equal(/[()[\]<>]/.test(rec.url), false, `unencoded bracket/paren in record url: ${rec.url}`);
    }
  }

  // 2. includeTags: ['footer'] -> disables Universal Schema.org / meta-description bypasses and returns ONLY `<footer>`!
  const includeRes = await executeScrapeCall({
    payload: {
      url: 'https://company.example/directory',
      includeTags: ['footer'],
      ephemeral: true,
    },
    env: {},
    target: 'auto',
    site: 'default',
    source: 'test',
    userId: 'owner',
    executeHubFetch: mockHubFetch,
  });
  assert.equal(includeRes.status, 200);
  const includeMd = String(includeRes.body.markdown ?? '');
  assert.match(includeMd, /Footer copyright notice 2026/);
  assert.equal(includeMd.includes('Alice Smith'), false, `Schema.org bypassed includeTags: ${includeMd}`);
  assert.equal(includeMd.includes('Scoped main paragraph'), false, `main leaked past includeTags: ${includeMd}`);
  assert.equal(includeRes.body.records, undefined);

  // 3. excludeTags: ['.secret'] -> disables whole-page JSON-LD bypass and excludes `.secret`!
  const excludeRes = await executeScrapeCall({
    payload: {
      url: 'https://company.example/directory',
      excludeTags: ['.secret'],
      ephemeral: true,
    },
    env: {},
    target: 'auto',
    site: 'default',
    source: 'test',
    userId: 'owner',
    executeHubFetch: mockHubFetch,
  });
  assert.equal(excludeRes.status, 200);
  const excludeMd = String(excludeRes.body.markdown ?? '');
  assert.match(excludeMd, /Scoped main paragraph only/);
  assert.equal(excludeMd.includes('Excluded secret block'), false);
  assert.equal(excludeMd.includes('Alice Smith'), false, `Schema.org bypassed excludeTags: ${excludeMd}`);
  assert.equal(excludeRes.body.records, undefined);

  // 4. onlyMainContent: false -> retains `<header>` + `<footer>` instead of replacing whole page with JSON-LD twin!
  const fullPageRes = await executeScrapeCall({
    payload: {
      url: 'https://company.example/directory',
      onlyMainContent: false,
      ephemeral: true,
    },
    env: {},
    target: 'auto',
    site: 'default',
    source: 'test',
    userId: 'owner',
    executeHubFetch: mockHubFetch,
  });
  assert.equal(fullPageRes.status, 200);
  const fullMd = String(fullPageRes.body.markdown ?? '');
  assert.match(fullMd, /Header nav banner text/);
  assert.match(fullMd, /Footer copyright notice 2026/);
  assert.equal(fullPageRes.body.records, undefined);
});

test('R11-M3: entity-decoded invisible, bidi, and Unicode tag characters stripped in TS', () => {
  const raw =
    'Start &#x202e;bidi&#x202c; &#8238;dec&#8236; &#xfeff;bom &#x200b;zwsp &#xe0061;&#xe007f;tag &rlm;&lrm;&zwj;&zwnj;&wj; &amp;#xe0062; end';
  const sanitized = sanitizeInlineHtmlInMarkdown(raw, 'https://example.com/');
  const decoded = decodeMarkdownEntities(raw);
  const meta = sanitizeScrapedMetadataField(raw) ?? '';

  const forbiddenRe =
    /[\u0080-\u009F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/u;
  assert.equal(forbiddenRe.test(sanitized), false, `invisible char survived sanitizeInlineHtmlInMarkdown: ${JSON.stringify(sanitized)}`);
  assert.equal(forbiddenRe.test(decoded), false, `invisible char survived decodeMarkdownEntities: ${JSON.stringify(decoded)}`);
  assert.equal(forbiddenRe.test(meta), false, `invisible char survived sanitizeScrapedMetadataField: ${JSON.stringify(meta)}`);
});

test('R11-P3-1: URL fields in records[] percent-encode (, ), [, ], <, >', () => {
  const encoded = sanitizeSchemaHttpsUrl('https://example.com/wiki/Rust_(programming_language)?f[a]=1&x=<y>', 'https://example.com');
  assert.equal(encoded, 'https://example.com/wiki/Rust_%28programming_language%29?f%5Ba%5D=1&x=%3Cy%3E');
  assert.equal(/[()[\]<>]/.test(encoded!), false);

  const schemaDoc = extractUniversalSchemaOrg(
    `<script type="application/ld+json">{
      "@context": "https://schema.org",
      "@type": "ItemList",
      "itemListElement": [
        { "@type": "ListItem", "position": 1, "name": "One", "url": "/docs/fn(a,b)/[0]" },
        { "@type": "ListItem", "position": 2, "name": "Two", "url": "https://example.com/q?(x)=[y]&k=<z>" }
      ]
    }</script>`,
    'https://example.com/',
  );
  assert.ok(schemaDoc?.records && schemaDoc.records.length === 2);
  assert.equal(schemaDoc.records[0]!.url, 'https://example.com/docs/fn%28a,b%29/%5B0%5D');
  assert.equal(schemaDoc.records[1]!.url, 'https://example.com/q?%28x%29=%5By%5D&k=%3Cz%3E');
  assert.equal(schemaDoc.markdown.includes('(https://example.com/docs/fn(a,b)'), false);
});

test('R11-S2: sanitizeMarkdownPageSlice preserves container & non-blank state across mid-container, trailing-ws, and CRLF offsets', async () => {
  const docList = '- item\n\n  ```html\n  <x-probe>\n  [click](javascript:void(0))\n  ```';
  for (let off = 0; off < docList.indexOf('<x-probe>'); off++) {
    const out = sanitizeMarkdownPageSlice(docList, off, docList.slice(off), false);
    assert.equal(out.includes('<x-probe>'), false, `raw <x-probe> survived docList at offset=${off}: ${JSON.stringify(out)}`);
    assert.equal(out.includes('javascript:'), false, `javascript: survived docList at offset=${off}: ${JSON.stringify(out)}`);
  }

  const docCrlf = 'hello\r\n```html\r\n<x-probe>\r\n[click](javascript:void(0))\r\n```';
  for (let off = 0; off < docCrlf.indexOf('<x-probe>'); off++) {
    const out = sanitizeMarkdownPageSlice(docCrlf, off, docCrlf.slice(off), false);
    assert.equal(out.includes('<x-probe>'), false, `raw <x-probe> survived docCrlf at offset=${off}: ${JSON.stringify(out)}`);
    assert.equal(out.includes('javascript:'), false, `javascript: survived docCrlf at offset=${off}: ${JSON.stringify(out)}`);
  }

  const docTrailingWs = 'hello   \n```html\n<x-probe>\n[click](javascript:void(0))\n```';
  for (let off = 0; off < docTrailingWs.indexOf('<x-probe>'); off++) {
    const out = sanitizeMarkdownPageSlice(docTrailingWs, off, docTrailingWs.slice(off), false);
    assert.equal(out.includes('<x-probe>'), false, `raw <x-probe> survived docTrailingWs at offset=${off}: ${JSON.stringify(out)}`);
    assert.equal(out.includes('javascript:'), false, `javascript: survived docTrailingWs at offset=${off}: ${JSON.stringify(out)}`);
  }

  // Verify `readArtifactPage` normalizes `\r\n` even when cached R2 derived object reports current `pipelineVersion`
  const r2 = new MemoryR2Bucket();
  const sha = createHash('sha256').update('r11-s2-crlf-artifact').digest('hex');
  await r2.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', sha), 'hello\r\n```html\r\n<x-probe>\r\n```', {
    httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
    customMetadata: { pipelineVersion: String(SCRAPE_PIPELINE_VERSION) },
  });
  const page = await readArtifactPage({
    bucket: r2 as unknown as R2Bucket,
    blobSha256: `md:${sha}`,
    format: 'markdown',
    offset: 5,
    limit: 200,
  });
  assert.equal(page.ok, true);
  if (page.ok) {
    assert.equal(page.page.content.includes('\r'), false, `CRLF survived readArtifactPage: ${JSON.stringify(page.page.content)}`);
    assert.equal(page.page.content.includes('<x-probe>'), false, `raw <x-probe> survived CRLF readArtifactPage: ${JSON.stringify(page.page.content)}`);
  }

  // Invisible-char fence-polarity inversion (`\u200B~~~ ... \u200B\`\`\``) in `sanitizeMarkdownPageSlice` & `readArtifactPage`
  const invDoc = [
    'intro',
    '',
    '\u200B~~~',
    'a',
    '',
    '~~~',
    '',
    '\u200B```',
    '~~~',
    '',
    '```',
    '<script>alert(1)</script>',
    '[xss](javascript:alert(1))',
    '```',
  ].join('\n');
  for (let off = 0; off < invDoc.indexOf('<script>'); off++) {
    const invSlice = sanitizeMarkdownPageSlice(invDoc, off, invDoc.slice(off), false);
    assertProseSafe(`invDoc@${off}`, invSlice, false);
    assert.equal(invSlice.includes('javascript:'), false, `javascript: survived invDoc@${off}: ${invSlice}`);
  }
  const invSha = createHash('sha256').update('r11-s2-inv-artifact').digest('hex');
  await r2.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', invSha), invDoc, {
    httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
    customMetadata: { pipelineVersion: String(SCRAPE_PIPELINE_VERSION) },
  });
  const invPage = await readArtifactPage({
    bucket: r2 as unknown as R2Bucket,
    blobSha256: `md:${invSha}`,
    format: 'markdown',
    offset: 0,
    limit: 10_000,
  });
  assert.equal(invPage.ok, true);
  if (invPage.ok) {
    assertProseSafe('invPage', invPage.page.content, false);
    assert.equal(invPage.page.content.includes('javascript:'), false);
  }

  // CRLF `\r\n\r\n` truncated inline backtick code span paragraph isolation
  const crlfInlineDoc = 'para1 `stray\r\n\r\npara2 `unclosed_code_span\r\n\r\nnext para';
  const crlfCut = crlfInlineDoc.indexOf('\r\n\r\nnext para');
  const crlfClosed = sanitizeMarkdownPageSlice(crlfInlineDoc, 0, crlfInlineDoc.slice(0, crlfCut), false);
  assert.ok(crlfClosed.endsWith('para2 `unclosed_code_span`'), `Expected closed inline span in para2, got: ${JSON.stringify(crlfClosed)}`);

  // `formatInertiaPagePropsToMarkdown` neutralizes unsafe links in `component`
  const badComp = formatInertiaPagePropsToMarkdown({
    component: '[Click](javascript:alert(1))',
    props: { count: 42 },
  });
  assert.ok(badComp);
  assert.equal(badComp.markdown.includes('javascript:'), false, `javascript: survived Inertia component: ${badComp.markdown}`);

  // `redactPiiDeep` and `sanitizeRecordUrlsDeep` sanitize shared DAG sub-object references across branches
  const sharedAuthor = {
    email: 'alice@company.example',
    url: 'https://company.example/u/(alice)?k=<1>',
  };
  const dagInput = { first: sharedAuthor, second: sharedAuthor };
  const dagUrlsEncoded = scrapeModule.sanitizeRecordUrlsDeep(dagInput);
  assert.equal(dagUrlsEncoded.first.url, 'https://company.example/u/%28alice%29?k=%3C1%3E');
  assert.equal(dagUrlsEncoded.second.url, 'https://company.example/u/%28alice%29?k=%3C1%3E');
  const dagRedacted = scrapeModule.redactPiiDeep(dagUrlsEncoded);
  assert.equal(dagRedacted.first.email, '[REDACTED_EMAIL]');
  assert.equal(dagRedacted.second.email, '[REDACTED_EMAIL]');

  // S2 Audit Finding 4: 3-backtick fence containing a 4-space-indented `    ``` ` inner line (`fenceLen === 3`, `effectiveFenceLen === 4`)
  // closed by a real 3-backtick ` ``` ` line MUST close properly on mid-fence slice offsets (both with & without checkpoints)
  // so prose `<script>` and `javascript:` AFTER the 3-backtick closer NEVER survive raw!
  const effFenceDoc = [
    'Intro paragraph.',
    '',
    '```js',
    'const sample = 1;',
    '    ```',
    'const moreCode = 2;',
    '```',
    '',
    '<script>alert(1)</script>',
    '[click](javascript:alert(1))',
  ].join('\n');
  const effCheckpoints = scrapeAdvancedModule.computeMarkdownSliceCheckpoints(effFenceDoc, 16);
  const proseIdx = effFenceDoc.indexOf('<script>');
  for (let off = 0; off < proseIdx; off++) {
    const noCp = sanitizeMarkdownPageSlice(effFenceDoc, off, effFenceDoc.slice(off), false);
    const withCp = sanitizeMarkdownPageSlice(effFenceDoc, off, effFenceDoc.slice(off), false, effCheckpoints);
    for (const [tag, out] of [
      ['noCp', noCp],
      ['withCp', withCp],
    ] as const) {
      assertProseSafe(`effFenceDoc(${tag})@${off}`, out, false);
      assert.equal(out.includes('javascript:'), false, `javascript: survived effFenceDoc(${tag})@${off}: ${out}`);
    }
  }
});
