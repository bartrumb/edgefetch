import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { gzipSync } from 'node:zlib';

import {
  enrichShopifyProductFromJson,
  enrichWooCommerceProductFromStoreApi,
  extractShopifyProductHtml,
  extractWooCommerceProductHtml,
  formatShopifyProductsFeedTwin,
  formatWcStoreApiListTwin,
  formatWcStoreApiProductTwin,
  normalizePublicCommerceImageUrl,
  normalizeShopifyProductRecord,
  normalizeWooCommerceProductRecord,
  sanitizeCommerceField,
  sanitizeCommerceTimestamp,
} from '../src/extractors/commerce-engine';
import {
  executeScrapeCall,
  extractHtmlDocument,
  finalizeScrapedMarkdown,
  recognizeAndHardenMarkdownFences,
  sanitizeInlineHtmlInMarkdown,
  sanitizeMarkdownPageSlice,
  SCRAPE_PIPELINE_VERSION,
  splitMarkdownByCodeFences,
} from '../src/scrape';
import * as scrapeAdvancedExports from '../src/scrape-advanced';
import {
  extractStructuredProduct,
  isAsciiSpaceOrTabOnly,
  isDisallowedMarkdownLinkDestination,
  sanitizeFullMarkdownDocumentForArtifact,
} from '../src/scrape-advanced';
import {
  primeSanitizedMarkdownCache,
  r2ArtifactKey,
  r2DerivedKey,
  r2PrivateDerivedKey,
  readArtifactPage,
  SCRAPE_PIPELINE_VERSION as STORAGE_PIPELINE_VERSION,
} from '../src/storage';

const covMul = process.env.NODE_V8_COVERAGE ? 2.5 : 1;

class MemoryR2Bucket {
  readonly objects = new Map<
    string,
    { bytes: Uint8Array; httpMetadata?: Record<string, string>; customMetadata?: Record<string, string> }
  >();

  async put(
    key: string,
    value: string | Uint8Array | ArrayBuffer,
    opts?: { httpMetadata?: Record<string, string>; customMetadata?: Record<string, string> },
  ) {
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
      arrayBuffer: async () =>
        entry.bytes.buffer.slice(entry.bytes.byteOffset, entry.bytes.byteOffset + entry.bytes.byteLength),
      text: async () => new TextDecoder().decode(entry.bytes),
    };
  }

  async head(key: string) {
    const entry = this.objects.get(key);
    return entry
      ? { key, size: entry.bytes.byteLength, httpMetadata: entry.httpMetadata, customMetadata: entry.customMetadata }
      : null;
  }

  async delete(keys: string | string[]) {
    for (const k of Array.isArray(keys) ? keys : [keys]) {
      this.objects.delete(k);
    }
  }
}

/**
 * Audits that `sanitizedMd` contains ZERO unescaped `<` anywhere outside recognized CommonMark fenced code blocks
 * (except genuine standalone PDF page markers when `allowPdfMarkers === true`) AND zero disallowed link destinations.
 */
function assertStrictS1ProseSafety(sanitizedMd: string, label: string, allowPdfMarkers = false): void {
  const segments = splitMarkdownByCodeFences(sanitizedMd);
  for (let idx = 0; idx < segments.length; idx += 2) {
    let prose = segments[idx] ?? '';
    if (allowPdfMarkers) {
      prose = prose.replace(/^[ \t]*<!-- (?:page \d{1,6}|pdf-page: \d{1,6}) -->[ \t]*$/gm, '');
    }
    assert.equal(
      prose.includes('<'),
      false,
      `[${label}] unescaped '<' survived outside fenced code block in prose segment ${idx}: ${JSON.stringify(prose.slice(0, 240))}`,
    );
    for (const m of prose.matchAll(/!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?/g)) {
      assert.equal(
        isDisallowedMarkdownLinkDestination(m[1]!),
        false,
        `[${label}] disallowed Markdown link destination survived: ${JSON.stringify(m[1])}`,
      );
    }
  }
}

test('Round 10 (S1): < restorer removed, SCRAPE_PIPELINE_VERSION === 33, every prose < escaped, and 512 KiB `<a>` runs in < 25 ms', () => {
  assert.equal(SCRAPE_PIPELINE_VERSION, 33);
  assert.equal(STORAGE_PIPELINE_VERSION, 33);

  // 1. Confirm `escapeResidualLtPreservingSafeCodeSpansLinear` and false dialect-agreement comment are completely gone
  assert.equal('escapeResidualLtPreservingSafeCodeSpansLinear' in scrapeAdvancedExports, false);
  const hubDir = resolve(process.cwd().endsWith('hub') ? process.cwd() : join(process.cwd(), 'hub'));
  const advSrc = readFileSync(join(hubDir, 'src', 'scrape-advanced.ts'), 'utf8');
  assert.equal(advSrc.includes('escapeResidualLtPreservingSafeCodeSpansLinear'), false);
  assert.equal(advSrc.includes('agree 100%'), false);

  // 2. Every `<` outside real fenced code blocks is escaped (`&lt;`), including inside inline code spans, while fenced code stays raw
  const sampleMd = [
    '# Generics `Vec<T>` and `<a>` in Prose',
    '',
    'Inline `Map<string, Array<number>>` and `<script>alert(1)</script>` plus table:',
    '',
    '| Type | Example |',
    '| --- | --- |',
    '| Generic | `Result<T, E>` |',
    '| Tag | `<img src=x onerror=1>` |',
    '',
    '```ts',
    'export function id<T>(x: T): Array<T> { return [x]; }',
    '```',
  ].join('\n');

  const outInline = sanitizeInlineHtmlInMarkdown(sampleMd, 'https://docs.example.com/');
  assertStrictS1ProseSafety(outInline, 'S1:sanitizeInlineHtmlInMarkdown');
  assert.ok(outInline.includes('`Vec&lt;T>`'));
  assert.ok(outInline.includes('`&lt;a>`'));
  assert.ok(outInline.includes('`Result&lt;T, E>`'));
  assert.ok(outInline.includes('export function id<T>(x: T): Array<T> { return [x]; }'), 'fenced code block must keep raw <T>');

  const outFin = finalizeScrapedMarkdown(sampleMd, { isPdf: false, includeImages: true, baseUrl: 'https://docs.example.com/' });
  assertStrictS1ProseSafety(outFin.markdown, 'S1:finalizeScrapedMarkdown');

  const outFull = sanitizeFullMarkdownDocumentForArtifact(sampleMd);
  assertStrictS1ProseSafety(outFull, 'S1:sanitizeFullMarkdownDocumentForArtifact');

  const outSlice = sanitizeMarkdownPageSlice(outFull, 0, outFull.slice(0, 120), false);
  assertStrictS1ProseSafety(outSlice, 'S1:sanitizeMarkdownPageSlice');

  // Genuine standalone PDF page markers preserved ONLY when `allowPdfPageMarkers === true`; forged suffix markers escaped
  const pdfMd = '<!-- page 1 -->\nParagraph with `<a>`.\n<!-- pdf-page: 2 -->\n<!-- page 3 --><img src=x onerror=1>';
  const pdfAllowed = sanitizeInlineHtmlInMarkdown(pdfMd, undefined, true);
  assertStrictS1ProseSafety(pdfAllowed, 'S1:pdfMarkersAllowed', true);
  assert.ok(pdfAllowed.includes('<!-- page 1 -->'));
  assert.ok(pdfAllowed.includes('<!-- pdf-page: 2 -->'));
  assert.equal(pdfAllowed.includes('<img'), false);
  assert.equal(pdfAllowed.includes('<!-- page 3 -->'), false);

  const pdfDisallowed = sanitizeInlineHtmlInMarkdown(pdfMd, undefined, false);
  assertStrictS1ProseSafety(pdfDisallowed, 'S1:pdfMarkersDisallowed', false);

  // 3. Linear CPU check: 64 KiB and 512 KiB single-line repeated `` `<a>` `` MUST run in < 25 ms at 512 KiB!
  const line64k = '`<a>` '.repeat(Math.ceil(65_536 / 6)).slice(0, 65_536);
  const line512kSpaced = '`<a>` '.repeat(Math.ceil(524_288 / 6));
  const line512kGlued = '`<a>`'.repeat(Math.ceil(524_288 / 5));

  // Warmup JIT
  sanitizeInlineHtmlInMarkdown(line64k);
  sanitizeFullMarkdownDocumentForArtifact(line64k);

  for (const [variant, input512k] of [
    ['spaced-512KiB', line512kSpaced],
    ['glued-512KiB', line512kGlued],
  ] as const) {
    assert.ok(input512k.length >= 524_288);
    let bestInlineMs = Infinity;
    let bestArtifactMs = Infinity;
    for (let run = 0; run < 3; run++) {
      const t0 = performance.now();
      const resA = sanitizeInlineHtmlInMarkdown(input512k);
      const dtA = performance.now() - t0;
      assert.equal(resA.includes('<'), false);
      if (dtA < bestInlineMs) bestInlineMs = dtA;

      const t1 = performance.now();
      const resB = sanitizeFullMarkdownDocumentForArtifact(input512k);
      const dtB = performance.now() - t1;
      assert.equal(resB.includes('<'), false);
      if (dtB < bestArtifactMs) bestArtifactMs = dtB;
    }
    assert.ok(
      bestInlineMs < 25 * covMul,
      `S1 sanitizeInlineHtmlInMarkdown(${variant}) took ${bestInlineMs.toFixed(2)}ms (expected < 25ms)`,
    );
    assert.ok(
      bestArtifactMs < 25 * covMul,
      `S1 sanitizeFullMarkdownDocumentForArtifact(${variant}) took ${bestArtifactMs.toFixed(2)}ms (expected < 25ms)`,
    );
  }
});

test('Round 10 (S2): Fence container depth cap (< 30 ms on 512 KiB-2 MiB nested inputs) & per-user SHA-256 sanitized-doc LRU isolation', async () => {
  // 1. Deeply nested list / blockquote inputs (single-line 2,000 deep + 50,000 lines, and 1 MiB multi-line) run in < 30 ms
  const deepSingleLineList512k = `${'- '.repeat(2_000)}leaf\n${'\n'.repeat(60_000)}\`\`\`js\nx\n\`\`\`\n${'plain line\n'.repeat(45_000)}`;
  const deepSingleLineBq512k = `${'> '.repeat(2_000)}quote\n${'> line\n'.repeat(75_000)}\`\`\`js\nx\n\`\`\``;
  const oneMiBPlainFences = `${'Ordinary prose line without containers.\n'.repeat(24_000)}\`\`\`ts\nconst ok = true;\n\`\`\`\n`;

  assert.ok(deepSingleLineList512k.length >= 524_288);
  assert.ok(deepSingleLineBq512k.length >= 524_288);
  assert.ok(oneMiBPlainFences.length >= 950_000);

  // Warmup
  recognizeAndHardenMarkdownFences('- - a\n```\nx\n```', { harden: true });

  for (const [name, doc] of [
    ['deep-list-512KiB+', deepSingleLineList512k],
    ['deep-bq-512KiB+', deepSingleLineBq512k],
    ['fastpath-zero-containers-1MiB', oneMiBPlainFences],
  ] as const) {
    let bestMs = Infinity;
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      const res = recognizeAndHardenMarkdownFences(doc, { harden: true });
      const dt = performance.now() - t0;
      assert.ok(res.hardened.length > 0);
      if (dt < bestMs) bestMs = dt;
    }
    assert.ok(bestMs < 30 * covMul, `S2 recognizeAndHardenMarkdownFences(${name}) took ${bestMs.toFixed(2)}ms (expected < 30ms)`);
  }

  // Fail-closed escaping of fences at/beyond `MAX_MD_CONTAINER_DEPTH = 32`
  const overCapBq = `${'> '.repeat(40)}\`\`\`html\n<img src=x onerror=alert(1)>\n${'> '.repeat(40)}\`\`\``;
  const overCapListNested = `${'- '.repeat(40)}\`\`\`html\n${'  '.repeat(40)}<script>alert(1)</script>\n${'  '.repeat(40)}\`\`\`\n<svg onload=alert(1)>`;
  const overCapListDedented = `${'- '.repeat(40)}\`\`\`html\n<script>alert(1)</script>\n  \`\`\`\n<svg onload=alert(1)>\n\`\`\`\n<img src=x onerror=alert(1)>`;
  for (const raw of [overCapBq, overCapListNested, overCapListDedented]) {
    const clean = sanitizeInlineHtmlInMarkdown(raw);
    assertStrictS1ProseSafety(clean, 'S2:overCapFailClosed');
  }

  // 2. Blind-audit regressions (`R10-BLIND-1`): non-1 ordered list (`10. item`) & 4-space lazy continuation after paragraph
  //    in `sanitizeFullMarkdownDocumentForArtifact`, `sanitizeMarkdownPageSlice` (at EVERY offset), and cold `readArtifactPage`!
  const blindSlicePayloads = [
    'Paragraph line\n10. item\n    ```\n    <x-probe data-id="1">raw</x-probe>\n    ```',
    '- outer para\n  10. inner\n      ```\n      <x-probe data-id="4">raw</x-probe>\n      ```',
    'Paragraph\n\u00A0\n10. item\n    ```\n    <x-s3-blank>\n    ```',
    'Paragraph line\n    lazy 4-space continuation\n10. item\n    ```\n    <x-lazy-probe>\n    ```',
  ];
  for (const [idx, badMd] of blindSlicePayloads.entries()) {
    const cleanFull = sanitizeFullMarkdownDocumentForArtifact(badMd);
    assertStrictS1ProseSafety(cleanFull, `S1:blindFull[${idx}]`);
    assert.equal(cleanFull.includes('<x-'), false, `raw <x-*> survived sanitizeFullMarkdownDocumentForArtifact[${idx}]: ${cleanFull}`);
    for (let off = 0; off < badMd.length; off += 4) {
      const cleanSlice = sanitizeMarkdownPageSlice(badMd, off, badMd.slice(off), false);
      assertStrictS1ProseSafety(cleanSlice, `S1:blindSlice[${idx}]@${off}`);
      assert.equal(cleanSlice.includes('<x-'), false, `raw <x-*> survived sanitizeMarkdownPageSlice[${idx}]@${off}: ${cleanSlice}`);
    }
  }

  // Contiguous `page0 + page1` concatenation (`R10-BLIND-4`) across EVERY cut offset 1..N-1 MUST never fuse synthetic fences!
  const concatFenceDocs = [
    '```html\nline1\n<x-inside-fence>\n```',
    '````\nconst a = 1;\n````\nprose\n<script>x\n````\n<script>x\n````',
    '> \u00A0```\nParagraph <img src=x onerror=1>\n```js\nconst ok = "<raw>";\n```',
    '> \u00A0```\n    Paragraph text\n`````\n<script>x\n`````',
  ];
  for (const [dIdx, rawDoc] of concatFenceDocs.entries()) {
    const cleanDoc = sanitizeFullMarkdownDocumentForArtifact(rawDoc);
    for (let cut = 1; cut < cleanDoc.length; cut++) {
      const p0 = sanitizeMarkdownPageSlice(cleanDoc, 0, cleanDoc.slice(0, cut), false);
      const p1 = sanitizeMarkdownPageSlice(cleanDoc, cut, cleanDoc.slice(cut), false);
      assertStrictS1ProseSafety(p0 + p1, `S1:contiguousConcat[${dIdx}]@${cut}`);
    }
  }

  // 3. Full-content hash validation catches middle-byte changes even when `length`, `head(96)`, and `tail(96)` are 100% identical!
  const bucket = new MemoryR2Bucket();
  const blindSha = '9'.repeat(64);
  await bucket.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', blindSha), blindSlicePayloads[0]!);
  const blindPage = await readArtifactPage({ bucket: bucket as unknown as R2Bucket, blobSha256: `md:${blindSha}`, format: 'markdown' });
  assert.equal(blindPage.ok, true);
  if (blindPage.ok) {
    assert.equal(blindPage.page.content.includes('<x-probe'), false);
    assertStrictS1ProseSafety(blindPage.page.content, 'S1:blindReadArtifactPage');
  }

  const head96 = 'H'.repeat(128);
  const tail96 = 'T'.repeat(128);
  const docV1 = `${head96}\nMiddle section ALPHA with <img src=x onerror=1> payload.\n${tail96}`;
  const docV2 = `${head96}\nMiddle section BRAVO with <svg onload=1> payload!!!!!!!!\n${tail96}`;
  assert.equal(docV1.length, docV2.length, 'test setup: identical total length');
  assert.equal(docV1.slice(0, 96), docV2.slice(0, 96), 'test setup: identical 96-char head');
  assert.equal(docV1.slice(-96), docV2.slice(-96), 'test setup: identical 96-char tail');

  const midTestSha = '1'.repeat(64);
  await bucket.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', midTestSha), docV1);
  const p1 = await readArtifactPage({ bucket: bucket as unknown as R2Bucket, blobSha256: `md:${midTestSha}`, format: 'markdown' });
  assert.equal(p1.ok, true);
  if (p1.ok) assert.ok(p1.page.content.includes('ALPHA'));

  await bucket.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', midTestSha), docV2);
  const p2 = await readArtifactPage({ bucket: bucket as unknown as R2Bucket, blobSha256: `md:${midTestSha}`, format: 'markdown' });
  assert.equal(p2.ok, true);
  if (p2.ok) {
    assert.ok(p2.page.content.includes('BRAVO'), 'Full-content SHA-256 must detect middle-byte mutation and re-sanitize');
    assert.equal(p2.page.content.includes('<svg'), false);
  }

  // 4. Dedicated `'pub'` pool & per-user LRU isolation: 100 SHAs by `attacker` + 70 private users NEVER evict `'pub'`!
  const pubRawBytes = new TextEncoder().encode('# Public Cached Doc\n\nPublic content body.');
  const pubGz = gzipSync(pubRawBytes);
  const pubBlobSha = createHash('sha256').update(pubGz).digest('hex');
  const pubContentSha = createHash('sha256').update(pubRawBytes).digest('hex');
  await bucket.put(r2ArtifactKey('stored', pubBlobSha), pubGz, { customMetadata: { contentSha256: pubContentSha } });

  let pubDeriveCount = 0;
  const pubFirst = await readArtifactPage({
    bucket: bucket as unknown as R2Bucket,
    blobSha256: `md:${pubBlobSha}`,
    format: 'markdown',
    deriveMarkdownFromRaw: (b) => {
      pubDeriveCount++;
      return new TextDecoder().decode(b);
    },
  });
  assert.equal(pubFirst.ok, true);
  assert.equal(pubDeriveCount, 1);

  // Now `attacker` floods 100 distinct private SHAs, and 70 distinct users prime private entries
  for (let i = 0; i < 100; i++) {
    const fakeSha = i.toString(16).padStart(64, '2');
    await primeSanitizedMarkdownCache(fakeSha, `# Private Doc ${i}`, { userId: 'attacker-user', privateOnly: true });
  }
  for (let u = 0; u < 70; u++) {
    const fakeSha = u.toString(16).padStart(64, '3');
    await primeSanitizedMarkdownCache(fakeSha, `# User ${u} Doc`, { userId: `member-${u}`, privateOnly: true });
  }

  // Also test `victim-user` isolation against `attacker-user` flooding 100 SHAs
  const victimSha = '4'.repeat(64);
  const victimClean = '# Victim Cached Doc\n\nAlready sanitized.';
  await bucket.put(r2PrivateDerivedKey('victim-user', SCRAPE_PIPELINE_VERSION, 'markdown', victimSha), victimClean, {
    customMetadata: { pipelineVersion: String(SCRAPE_PIPELINE_VERSION), userId: 'victim-user', visibility: 'private' },
  });
  await primeSanitizedMarkdownCache(victimSha, victimClean, { userId: 'victim-user', privateOnly: true });
  for (let i = 0; i < 100; i++) {
    const atkSha = i.toString(16).padStart(64, '5');
    await primeSanitizedMarkdownCache(atkSha, `# Attacker Flood ${i}`, { userId: 'attacker-user', privateOnly: true });
  }
  const victimRead = await readArtifactPage({
    bucket: bucket as unknown as R2Bucket,
    blobSha256: `md:${victimSha}`,
    format: 'markdown',
    userId: 'victim-user',
    visibility: 'private',
  });
  assert.equal(victimRead.ok, true);

  // Verify `'pub'` entry is STILL warm in `publicSanitizedMarkdownPool`
  const pubAfterFlood = await readArtifactPage({
    bucket: bucket as unknown as R2Bucket,
    blobSha256: `md:${pubContentSha}`,
    format: 'markdown',
  });
  assert.equal(pubAfterFlood.ok, true);
  assert.equal(pubDeriveCount, 1);

  // 5. Private entries WITHOUT a `userId` (`privateOnly: true`, missing/empty `userId`) MUST NEVER populate or read `'pub'`!
  const orphanPrivSha = '6'.repeat(64);
  await primeSanitizedMarkdownCache(orphanPrivSha, '# Secret Private Doc Without UserId', {
    userId: '',
    privateOnly: true,
  });
  await primeSanitizedMarkdownCache(orphanPrivSha, '# Secret Private Doc Undefined UserId', {
    privateOnly: true,
  });
  await bucket.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', orphanPrivSha), '# Public Version Only');
  const checkPubNotPoisoned = await readArtifactPage({
    bucket: bucket as unknown as R2Bucket,
    blobSha256: `md:${orphanPrivSha}`,
    format: 'markdown',
  });
  assert.equal(checkPubNotPoisoned.ok, true);
  if (checkPubNotPoisoned.ok) {
    assert.equal(
      checkPubNotPoisoned.page.content.includes('Secret Private Doc'),
      false,
      'privateOnly without userId MUST NEVER poison the public cache scope!',
    );
    assert.ok(checkPubNotPoisoned.page.content.includes('Public Version Only'));
  }
});

test('Round 10 (S3): Strict CommonMark §2.1 ASCII space/tab blank-line checks (NBSP, U+3000, U+2000..U+200A, U+FEFF)', () => {
  assert.equal(isAsciiSpaceOrTabOnly(''), true);
  assert.equal(isAsciiSpaceOrTabOnly('    \t  \t '), true);
  for (const nonBlankWs of [
    '\u00A0', // NBSP
    '\u1680', // Ogham space mark
    '\u2000',
    '\u2002',
    '\u2003',
    '\u2007',
    '\u2009',
    '\u200A',
    '\u202F',
    '\u205F',
    '\u3000', // Ideographic space
    '\uFEFF', // BOM
    '\v',
    '\f',
  ]) {
    assert.equal(isAsciiSpaceOrTabOnly(nonBlankWs), false, `U+${nonBlankWs.codePointAt(0)!.toString(16)} must NOT be treated as blank`);
    assert.equal(isAsciiSpaceOrTabOnly(`  ${nonBlankWs}\t`), false);
  }

  // List-indented code fence followed by `\u00A0` (or `\u3000`) at col 0: CommonMark closes the list & fence on that line,
  // so `<img src=x onerror=alert(1)>` on the next line is OUTSIDE the fence and MUST be escaped!
  for (const unicodeSpace of ['\u00A0', '\u2003', '\u3000', '\uFEFF']) {
    const md = `- item\n  \`\`\`html\n  <b>code</b>\n${unicodeSpace}\n<img src=x onerror=alert(1)>`;
    const sanitized = sanitizeInlineHtmlInMarkdown(md);
    assertStrictS1ProseSafety(sanitized, `S3:inline:${unicodeSpace.codePointAt(0)!.toString(16)}`);
    assert.equal(sanitized.includes('<img'), false);

    const artifactClean = sanitizeFullMarkdownDocumentForArtifact(md);
    assertStrictS1ProseSafety(artifactClean, `S3:artifact:${unicodeSpace.codePointAt(0)!.toString(16)}`);

    for (let off = 0; off < md.length; off += 3) {
      const sliced = sanitizeMarkdownPageSlice(md, off, md.slice(off), false);
      assertStrictS1ProseSafety(sliced, `S3:slice@${off}`);
    }
  }
});

test('Round 10 (S4): Unclosed <script>/<style>/hidden tags/comments before a fence preserve newline boundary & run Pass 2 fence hardening', () => {
  const s4Payloads = [
    // Unclosed `<script>` immediately before opening fence: `const safe = 1;` must remain fenced, trailing `<img>` must be escaped!
    'Intro paragraph<script>unclosed_js(\n```js\nconst safe = 1;\n```\n<img src=x onerror=alert(1)>',
    // Unclosed `<style>` before fence
    'Header text<style>.a { color: red;\n```html\n<div class="inside-code">ok</div>\n```\n<svg onload=alert(1)>',
    // Unclosed HTML comment before fence
    'Before comment<!-- unclosed comment\n```ts\nexport type Box<T> = { value: T };\n```\n<img src=x onerror=alert(1)>',
    // Unclosed `<script>` BETWEEN two fences (`parts[2]` becomes empty except preserved `\n` so fences NEVER glue onto one line!)
    '```js\na();\n```\n<script>unclosed_between_fences\n```html\n<img src=x onerror=in_second_fence>\n```\n<img src=x onerror=in_prose>',
    // Hidden subtree before fence
    'Lead<div style="display:none">hidden\n</div>```py\nprint("hi")\n```\n<iframe src="javascript:alert(1)"></iframe>',
    // Stripped inline tag exposing a fence at column 0 in Pass 2
    '<span></span>```html\n<b>fenced</b>\n```\n<script>alert(1)</script>',
  ];

  for (const raw of s4Payloads) {
    const sInline = sanitizeInlineHtmlInMarkdown(raw, 'https://example.com/');
    assertStrictS1ProseSafety(sInline, `S4:inline:${raw.slice(0, 28)}`);
    assert.equal(sInline, sanitizeInlineHtmlInMarkdown(sInline, 'https://example.com/'), 'S4 output must be idempotent');

    const sFin = finalizeScrapedMarkdown(raw, { isPdf: false, includeImages: true, baseUrl: 'https://example.com/' });
    assertStrictS1ProseSafety(sFin.markdown, `S4:finalize:${raw.slice(0, 28)}`);
  }

  // Verify the fenced code block after unclosed `<script>` genuinely stayed a fenced code block at column 0!
  const unclosedBeforeFence = sanitizeInlineHtmlInMarkdown(
    'Intro paragraph<script>unclosed_js(\n```js\nconst safe = 1;\n```\n<img src=x onerror=alert(1)>',
  );
  const segs = splitMarkdownByCodeFences(unclosedBeforeFence);
  assert.ok(
    segs.some((seg, i) => i % 2 === 1 && seg.includes('const safe = 1;')),
    `Expected \`\`\`js fence to remain an intact col-0 code fence after unclosed <script>, got:\n${unclosedBeforeFence}`,
  );
});

test('Round 10 (S5): Tab-indented fence closers and openers inside list items & blockquotes (CommonMark §2.2 4-col tab stops)', () => {
  const s5Payloads = [
    // Tab-indented fence closer inside 2-space bullet list (`\t` advances col 0->4, `baseCol=2`, `remCols=2 <= 3` -> CLOSES fence!)
    '- item\n  ```html\n  <b>inside fence</b>\n\t```\n<img src=x onerror=alert(1)>',
    // Space + tab closer inside 2-space bullet list (` \t` advances col 0->1->4, `baseCol=2`, `remCols=2 <= 3` -> CLOSES fence!)
    '- item\n  ```html\n  <b>inside fence</b>\n \t```\n<svg onload=alert(1)>',
    // Tab-indented fence closer inside 3-space ordered list (`\t` advances col 0->4, `baseCol=3`, `remCols=1 <= 3` -> CLOSES fence!)
    '1. item\n   ~~~\n   inside tilde fence\n\t~~~\n[click](javascript:alert(1))',
    // Tab-indented fence closer inside blockquote (`>\t``` ` -> `col` after `>` is 1, `\t` advances 1->4, `baseCol=2`, `remCols=2 <= 3`)
    '> ```html\n> <b>quoted code</b>\n>\t```\n<img src=x onerror=alert(1)>',
    // Tab-indented fence opener on continuation line inside list (`- item\n\t``` ` -> escaped risky fence + matching closer escaped!)
    '- item\n\t```html\n  <img src=x onerror=alert(1)>\n  ```\n<svg onload=alert(1)>',
    // Tab-indented fence opener AND tab-indented closer inside list
    '- item\n\t```html\n  <img src=x onerror=alert(1)>\n\t```\n<svg onload=alert(1)>',
    // List marker followed directly by tab + fence (`-\t``` `)
    '-\t```html\n  <img src=x onerror=alert(1)>\n\t```\n<svg onload=alert(1)>',
    // Top-level `\t``` ` inside a col-0 fence (`remCols = 4 > 3`: does NOT close in CommonMark; opener lengthened so regex parsers agree!)
    '```html\n\t```\n<img src=x onerror=alert(1)>\n```',
  ];

  for (const raw of s5Payloads) {
    const out = sanitizeInlineHtmlInMarkdown(raw, 'https://example.com/');
    assertStrictS1ProseSafety(out, `S5:inline:${JSON.stringify(raw.slice(0, 32))}`);
    assert.equal(out, sanitizeInlineHtmlInMarkdown(out, 'https://example.com/'), 'S5 output must be idempotent');

    const fullArt = sanitizeFullMarkdownDocumentForArtifact(raw);
    assertStrictS1ProseSafety(fullArt, `S5:artifact:${JSON.stringify(raw.slice(0, 32))}`);

    for (let off = 0; off <= raw.length; off++) {
      const slice = sanitizeMarkdownPageSlice(raw, off, raw.slice(off), false);
      assertStrictS1ProseSafety(slice, `S5:slice@${off}:${JSON.stringify(raw.slice(0, 24))}`);
    }
  }
});

test('Round 10 (P5): Commerce timestamp/author escaping, SSRF/non-public image URL rejection, & non-destructive SKU/title escaping', async () => {
  // 1. Public vs non-public commerce image URL filter (`normalizePublicCommerceImageUrl`)
  const blockedImageUrls = [
    'http://localhost/img.png',
    'http://cdn.shopify.com/s/files/1/cleartext.jpg',
    'https://cdn.shopify.com:8443/s/files/1/port.jpg',
    'https://localhost/img.png',
    'https://api.localhost/img.png',
    'https://nas.local/img.png',
    'https://metadata.internal/img.png',
    'http://127.0.0.1/img.png',
    'https://127.0.0.1/img.png',
    'http://169.254.169.254/latest/meta-data/',
    'http://10.0.0.1/img.png',
    'http://172.16.5.4/img.png',
    'http://192.168.1.10/img.png',
    'http://2130706433/img.png', // decimal 127.0.0.1
    'http://0177.0.0.1/img.png', // octal 127.0.0.1
    'http://0x7f000001/img.png', // hex 127.0.0.1
    'http://[::1]/img.png',
    'http://[::ffff:127.0.0.1]/img.png',
    '//localhost/img.png',
    '//169.254.169.254/img.png',
    'https://user:pass@cdn.shopify.com/img.png',
    'https://cdn.shopify.com:8443/img.png',
    'javascript:alert(1)',
    'data:image/svg+xml,<svg onload=1>',
    'file:///etc/passwd',
    'ftp://cdn.shopify.com/img.png',
  ];
  for (const bad of blockedImageUrls) {
    assert.equal(normalizePublicCommerceImageUrl(bad), null, `Expected non-public/unsafe image URL rejected: ${bad}`);
  }
  assert.equal(
    normalizePublicCommerceImageUrl('https://cdn.shopify.com/s/files/1/product.jpg'),
    'https://cdn.shopify.com/s/files/1/product.jpg',
  );
  assert.equal(
    normalizePublicCommerceImageUrl('//cdn.shopify.com/s/files/1/product.png'),
    'https://cdn.shopify.com/s/files/1/product.png',
  );

  // 2. Non-destructive SKU & product title escaping (`<USB-C>`, `[Gen 2]`, `*Pro*`, `_v2_`, `#1`, `` ` ``, `|`) + `publishedAt`/`updatedAt` escaping
  const shopifyPayload = {
    id: 9001,
    handle: 'usb-c-dock',
    title: 'Thunderbolt Dock <USB-C> [Gen 2] *Pro* _Edition_ #1 & Hub',
    vendor: 'Acme <Hardware> & Co [Official](javascript:alert(1))',
    published_at: '2026-11-20T10:00:00Z\r\n<script>alert(1)</script> & [x](javascript:alert(1))',
    updated_at: '2026-11-21T12:00:00Z\n<img src=x onerror=1> | [y](https://evil.example)',
    images: [
      { id: 1, src: 'http://169.254.169.254/latest/meta-data/iam' },
      { id: 2, src: 'http://localhost:3000/private.png' },
      { id: 3, src: 'https://user:secret@cdn.shopify.com/leak.png' },
      { id: 4, src: 'https://cdn.shopify.com/s/files/1/dock.jpg' },
    ],
    body_html:
      '<p>Includes cable. <img src="http://127.0.0.1/pixel.png" alt="ssrf"> <img src="https://cdn.shopify.com/s/files/1/diagram.png" alt="diagram"></p>',
    variants: [
      {
        id: 501,
        title: '100W <PD> [US] *Fast*',
        sku: 'SKU<USB-C>[v2]*pro*_1#A`B|C',
        price: '129.00',
        available: true,
        featured_image: { src: 'http://10.0.0.5/internal.png' },
      },
    ],
  };

  const normShop = normalizeShopifyProductRecord(shopifyPayload, 'https://store.example.com');
  assert.ok(normShop);
  // Every meaningful product token in title & SKU is preserved via escaping (NOT stripped!)
  assert.ok(normShop.title.includes('&lt;USB-C&gt;'), `Expected <USB-C> escaped non-destructively in title, got: ${normShop.title}`);
  assert.ok(normShop.title.includes('\\[Gen 2\\]'));
  assert.ok(normShop.title.includes('\\*Pro\\*'));
  assert.ok(normShop.title.includes('\\_Edition\\_'));
  assert.ok(normShop.title.includes('\\#1'));
  assert.ok(normShop.title.includes('&amp;'));
  assert.equal(normShop.title.includes('<'), false);

  const normSku = normShop.variants[0]?.sku ?? '';
  assert.ok(normSku.includes('&lt;USB-C&gt;'), `Expected <USB-C> preserved in SKU, got: ${normSku}`);
  assert.ok(normSku.includes('\\[v2\\]'));
  assert.ok(normSku.includes('\\*pro\\*'));
  assert.ok(normSku.includes('\\_1'));
  assert.ok(normSku.includes('\\#A'));
  assert.ok(normSku.includes('\\`B'));
  assert.ok(normSku.includes('|C'), `Expected pipe character preserved in SKU record, got: ${normSku}`);
  assert.equal(normSku.includes('<'), false);

  // `publishedAt` and `updatedAt` escaped (`&`, `<`, `>`, `\r`, `\n`, `[`, `]`, `(`, `)`)
  assert.ok(normShop.publishedAt);
  assert.equal(normShop.publishedAt!.includes('<'), false);
  assert.equal(normShop.publishedAt!.includes('>'), false);
  assert.equal(normShop.publishedAt!.includes('\n'), false);
  assert.equal(normShop.publishedAt!.includes('\r'), false);
  assert.ok(normShop.publishedAt!.includes('&lt;script&gt;'));
  assert.ok(normShop.publishedAt!.includes('\\('));
  assert.ok(normShop.publishedAt!.includes('\\)'));
  assert.ok(normShop.updatedAt);
  assert.equal(normShop.updatedAt!.includes('<'), false);
  assert.equal(normShop.updatedAt!.includes('\n'), false);

  // Only public image survived; variant's private featured_image was dropped
  assert.deepEqual(normShop.images, ['https://cdn.shopify.com/s/files/1/dock.jpg']);
  assert.equal(normShop.variants[0]?.image, null);

  const enrichedShop = enrichShopifyProductFromJson({
    rawJson: JSON.stringify({ product: shopifyPayload }),
    productUrl: 'https://store.example.com/products/usb-c-dock',
    htmlToMd: (html) => ({
      markdown: html
        .replace(/<img\s+src="([^"]+)"\s+alt="([^"]+)">/g, '![$2]($1)')
        .replace(/<\/?p>/g, ''),
      links: [],
    }),
  });
  assert.ok(enrichedShop);
  assertStrictS1ProseSafety(enrichedShop.markdown, 'P5:enrichedShopify');
  assert.equal(enrichedShop.markdown.includes('127.0.0.1'), false, 'Non-public body image must be stripped');
  assert.ok(enrichedShop.markdown.includes('https://cdn.shopify.com/s/files/1/diagram.png'));

  const feedShop = formatShopifyProductsFeedTwin(
    JSON.stringify({ products: [shopifyPayload] }),
    'https://store.example.com/products.json',
  );
  assert.ok(feedShop);
  assertStrictS1ProseSafety(feedShop.markdown, 'P5:shopifyFeed');

  // 3. WooCommerce Store API & HTML + `extractStructuredProduct` SSRF image rejection & non-destructive SKU/title
  const wooPayload = {
    id: 303,
    slug: 'cable-usb-c',
    name: 'Braided Cable <USB-C> *2m* [Black] #Pro',
    sku: 'WC<USB-C>*2M*|BLK`1',
    permalink: 'http://127.0.0.1/pwn',
    date_created: '2026-10-01T00:00:00Z <svg onload=1> (tz)',
    prices: { price: '1999', currency_code: 'USD', currency_minor_unit: 2 },
    images: [
      { src: 'http://2130706433/ssrf.png' },
      { src: 'http://[::1]/ssrf6.png' },
      { src: 'https://shop.example.org/wp-content/uploads/cable.jpg' },
    ],
  };
  const normWoo = normalizeWooCommerceProductRecord(wooPayload, 'https://shop.example.org');
  assert.ok(normWoo);
  assert.equal(normWoo.url, 'https://shop.example.org/product/cable-usb-c/');
  assert.deepEqual(normWoo.images, ['https://shop.example.org/wp-content/uploads/cable.jpg']);
  assert.ok(normWoo.title.includes('&lt;USB-C&gt;'));
  assert.ok(normWoo.variants[0]?.sku?.includes('&lt;USB-C&gt;'));
  assert.equal(normWoo.publishedAt?.includes('<'), false);

  const wcTwin = formatWcStoreApiProductTwin(JSON.stringify(wooPayload), 'https://shop.example.org/wp-json/wc/store/v1/products/303', (h) => ({
    markdown: h,
    links: [],
  }));
  assert.ok(wcTwin);
  assertStrictS1ProseSafety(wcTwin.markdown, 'P5:wcProductTwin');

  const wcList = formatWcStoreApiListTwin(JSON.stringify([wooPayload]), 'https://shop.example.org/wp-json/wc/store/v1/products');
  assert.ok(wcList);
  assertStrictS1ProseSafety(wcList.markdown, 'P5:wcListTwin');

  const wcEnrich = enrichWooCommerceProductFromStoreApi({
    rawJson: JSON.stringify([wooPayload]),
    productUrl: 'https://shop.example.org/product/cable-usb-c/',
    slug: 'cable-usb-c',
    htmlToMd: (h) => ({ markdown: h, links: [] }),
  });
  assert.ok(wcEnrich);
  assertStrictS1ProseSafety(wcEnrich.markdown, 'P5:wcEnrich');

  const structuredProd = extractStructuredProduct({
    rawBody: `<html><head><meta property="og:image" content="http://169.254.169.254/latest/meta-data/"></head><body><script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Adapter","image":["http://localhost/a.png","https://cdn.example.com/ok.png"],"offers":{"price":"19.00","priceCurrency":"USD"}}</script></body></html>`,
    finalUrl: 'https://shop.example.com/p/adapter',
  });
  assert.ok(structuredProd);
  assert.deepEqual(structuredProd.images, ['https://cdn.example.com/ok.png']);

  // Also check `sanitizeCommerceField`, `sanitizeCommerceTimestamp`, `extractShopifyProductHtml`, and `extractWooCommerceProductHtml`
  assert.equal(sanitizeCommerceField('Adapter <USB-C>'), 'Adapter &lt;USB-C&gt;');
  assert.equal(sanitizeCommerceTimestamp('2026-01-01 <x> & (y)'), '2026-01-01 &lt;x&gt; &amp; \\(y\\)');

  const shopHtmlRes = extractShopifyProductHtml({
    url: new URL('https://www.allbirds.com/products/usb-cable'),
    urlStr: 'https://www.allbirds.com/products/usb-cable',
    host: 'www.allbirds.com',
    path: '/products/usb-cable',
    parts: ['products', 'usb-cable'],
    rawHtml: `<html><head><script>Shopify.shop="allbirds.myshopify.com";</script><script type="application/ld+json">{"@type":"Product","name":"Cable <USB-C>","sku":"SKU<1>|A","offers":[{"price":"15.00","priceCurrency":"USD","image":"http://127.0.0.1/bad.png"}]}</script></head><body></body></html>`,
    htmlToMd: (h) => ({ markdown: h, links: [] }),
  });
  assert.ok(shopHtmlRes);
  assert.ok(shopHtmlRes.title.includes('&lt;USB-C&gt;'));
  assert.equal(shopHtmlRes.markdown.includes('127.0.0.1'), false);

  const wooHtmlRes = extractWooCommerceProductHtml({
    url: new URL('https://woo.example.com/product/usb-cable/'),
    urlStr: 'https://woo.example.com/product/usb-cable/',
    host: 'woo.example.com',
    path: '/product/usb-cable/',
    parts: ['product', 'usb-cable'],
    rawHtml: `<html><body class="woocommerce-page single-product"><script type="application/ld+json">{"@type":"Product","name":"Woo <USB-C>","sku":"WOO<1>|B","image":"http://localhost/bad.png","offers":{"price":"25.00","priceCurrency":"USD"}}</script></body></html>`,
    htmlToMd: (h) => ({ markdown: h, links: [] }),
  });
  assert.ok(wooHtmlRes);
  assert.ok(wooHtmlRes.title.includes('&lt;USB-C&gt;'));
  assert.equal((wooHtmlRes.records?.[0] as { images?: string[] })?.images?.length, 0);

  // 4. End-to-end `executeScrapeCall` twin fast-path & HTML path sanitize `metadata.author`, `metadata.publishedTime`, `metadata.modifiedTime`
  const dirtyShopifyTwinScrape = await executeScrapeCall({
    payload: { url: 'https://testshop.myshopify.com/products/usb-c-dock' },
    env: {},
    executeHubFetch: async (_t, rawReq) => {
      const req = (JSON.parse(rawReq) as { requests: Array<{ id: string; url: string }> }).requests[0]!;
      return {
        status: 200,
        via: 'cloudflare',
        bodyText: JSON.stringify({
          results: [
            {
              id: req.id,
              url: req.url,
              finalUrl: req.url,
              status: 200,
              outcome: 'ok',
              contentType: 'application/json',
              body: JSON.stringify({
                product: {
                  ...shopifyPayload,
                  vendor: 'Vendor\r\n<script>evil()</script> [Phish](javascript:alert(1))',
                  published_at: '2026-11-23T00:00:00Z\n<svg onload=1> & (bad)',
                },
              }),
            },
          ],
        }),
      };
    },
  });
  assert.equal(dirtyShopifyTwinScrape.status, 200);
  const twinMeta = dirtyShopifyTwinScrape.body.metadata as { author?: string; publishedTime?: string };
  assert.ok(twinMeta.author);
  assert.equal(twinMeta.author!.includes('<'), false);
  assert.equal(twinMeta.author!.includes('\n'), false);
  assert.equal(twinMeta.author!.includes('javascript:'), false);
  assert.ok(twinMeta.publishedTime);
  assert.equal(twinMeta.publishedTime!.includes('<'), false);
  assert.equal(twinMeta.publishedTime!.includes('\n'), false);

  const dirtyHtmlMetaScrape = await executeScrapeCall({
    payload: { url: 'https://blog.example.com/post' },
    env: {},
    executeHubFetch: async (_t, rawReq) => {
      const req = (JSON.parse(rawReq) as { requests: Array<{ id: string; url: string }> }).requests[0]!;
      return {
        status: 200,
        via: 'cloudflare',
        bodyText: JSON.stringify({
          results: [
            {
              id: req.id,
              url: req.url,
              finalUrl: req.url,
              status: 200,
              outcome: 'ok',
              contentType: 'text/html',
              body: `<!doctype html><html><head>
                <title>Clean Post</title>
                <meta name="author" content="Alice\n<script>alert(1)</script> [Link](javascript:alert(1))">
                <meta property="article:published_time" content="2026-11-23\r\n<img src=x onerror=1> & (utc)">
                <meta property="article:modified_time" content="2026-11-24\n<svg onload=1> [m](data:text/html,1)">
              </head><body><main><p>Substantive article body with plenty of words so extraction treats it as full content.</p></main></body></html>`,
            },
          ],
        }),
      };
    },
  });
  assert.equal(dirtyHtmlMetaScrape.status, 200);
  const htmlMeta = dirtyHtmlMetaScrape.body.metadata as {
    author?: string;
    publishedTime?: string;
    modifiedTime?: string;
  };
  assert.ok(htmlMeta.author);
  assert.equal(htmlMeta.author!.includes('<'), false);
  assert.equal(htmlMeta.author!.includes('javascript:'), false);
  assert.ok(htmlMeta.publishedTime);
  assert.equal(htmlMeta.publishedTime!.includes('<'), false);
  assert.equal(htmlMeta.publishedTime!.includes('\n'), false);
  assert.ok(htmlMeta.modifiedTime);
  assert.equal(htmlMeta.modifiedTime!.includes('<'), false);
  assert.equal(htmlMeta.modifiedTime!.includes('\n'), false);
});
