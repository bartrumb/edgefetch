// L-01: `jsonFilter` must be part of the scrape result cache identity.
//
// A `jsonFilter` scrape changes the returned Markdown (only matching JSON records), so it must never be served
// from — or written into — a cache slot that an unfiltered (or differently filtered) request can read.
// Covered read paths: options-scoped R2 cache (`scrapeOptionsHash`), plain META D1 + R2 lookup, and R5
// conditional revalidation (`If-None-Match` -> `304` served as `+cache:304`). Covered write path: the
// options-scoped R2 cache record written after every scrape.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';

import meta0001Sql from '../migrations/meta/0001_tracking.sql';
import { executeIngestPipeline, sha256HexString, writeJobManifestToR2 } from '../src/ingest';
import { executeScrapeCall } from '../src/scrape';
import { r2ArtifactKey } from '../src/storage';
import { NodeFsR2Bucket, NodeSqliteD1Database } from './stubs/cf-storage-mocks';

// `scrapeOptionsHash` of a default `{ url, maxAgeMs }` markdown scrape (unchanged since v2.8.2 except the pipeline v35, v36 and v37 bumps).
// Requests without `jsonFilter` must keep this exact value so the release invalidates no existing cache entry.
// Pinned for SCRAPE_PIPELINE_VERSION 35 (v2.8.14 bump): the hash includes the pipeline version, so it changes only on a deliberate bump.
const V282_DEFAULT_OPTIONS_HASH = 'f19a4869d4161cec478d048d36870076c8b2b2a6c060555c9e414f4c28a3afbd';

const JSON_URL = 'https://api.example.com/roles.json';
const RECORDS = [
  { id: 'r1', title: 'Platform Role Alpha', team: 'Platform' },
  { id: 'r2', title: 'Sales Role Bravo', team: 'Sales' },
  { id: 'r3', title: 'Platform Role Charlie', team: 'Platform' },
  { id: 'r4', title: 'Sales Role Delta', team: 'Sales' },
];
const JSON_BODY = JSON.stringify(RECORDS);
const ETAG = '"etag-roles-v1"';

type PutRecord = { key: string; json: Record<string, unknown> | null };

/** Fs-backed R2 bucket that also records every options-scoped scrape-cache write. */
function recordingBucket(dirs: string[]): { bucket: R2Bucket; raw: NodeFsR2Bucket; puts: PutRecord[] } {
  const dir = mkdtempSync(join(tmpdir(), 'ef-jsonfilter-cache-'));
  dirs.push(dir);
  const raw = new NodeFsR2Bucket(dir);
  const puts: PutRecord[] = [];
  const bucket = new Proxy(raw, {
    get(target, prop, receiver) {
      if (prop === 'put') {
        return async (key: string, value: unknown, opts?: unknown) => {
          if (key.includes('/scrape-cache/')) {
            let json: Record<string, unknown> | null = null;
            try {
              json = typeof value === 'string' ? (JSON.parse(value) as Record<string, unknown>) : null;
            } catch {
              json = null;
            }
            puts.push({ key, json });
          }
          return (target.put as (k: string, v: unknown, o?: unknown) => Promise<unknown>).call(target, key, value, opts);
        };
      }
      const v = Reflect.get(target, prop, receiver);
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
  return { bucket: bucket as unknown as R2Bucket, raw, puts };
}

type FetchLog = { ifNoneMatch: string[]; calls: number };

/** Origin stub: `304` when the hub sends a matching `If-None-Match`, otherwise `200` with the JSON body. */
function originStub(log: FetchLog) {
  return async (_target: string, rawCall: string) => {
    log.calls++;
    const parsed = JSON.parse(rawCall) as { requests: Array<{ id?: string; ifNoneMatch?: string }> };
    const req0 = parsed.requests[0] ?? {};
    if (req0.ifNoneMatch) log.ifNoneMatch.push(req0.ifNoneMatch);
    const id = req0.id ?? 'scrape-1';
    if (req0.ifNoneMatch === ETAG) {
      return {
        status: 200,
        via: 'agent:site-l01',
        bodyText: JSON.stringify({ results: [{ id, url: JSON_URL, finalUrl: JSON_URL, status: 304, outcome: 'ok' }] }),
      };
    }
    return {
      status: 200,
      via: 'agent:site-l01',
      bodyText: JSON.stringify({
        results: [
          {
            id,
            url: JSON_URL,
            finalUrl: JSON_URL,
            status: 200,
            outcome: 'ok',
            contentType: 'application/json',
            etag: ETAG,
            body: JSON_BODY,
            bodyEncoding: 'utf-8',
          },
        ],
      }),
    };
  };
}

/** Seed a verified page (with ETag) in META D1 + its raw artifact in R2 via the real ingest pipeline. */
async function seedVerifiedJsonPage(bucket: R2Bucket, metaDb: NodeSqliteD1Database, fetchedAt: number): Promise<void> {
  const bytes = new TextEncoder().encode(JSON_BODY);
  const gz = gzipSync(bytes);
  const blobSha = createHash('sha256').update(gz).digest('hex');
  const contentSha = await sha256HexString(JSON_BODY);
  await bucket.put(r2ArtifactKey('stored', blobSha), gz);
  const manifest = await writeJobManifestToR2({
    bucket,
    jobId: 'job_l01_seed',
    via: 'agent:site-l01',
    rawReplyText: JSON.stringify({
      results: [
        {
          id: '1',
          url: JSON_URL,
          status: 200,
          outcome: 'ok',
          contentType: 'application/json',
          etag: ETAG,
          artifact: {
            blobSha256: blobSha,
            contentSha256: contentSha,
            contentBytes: bytes.byteLength,
            storedBytes: gz.byteLength,
            encoding: 'gzip',
            retention: 'stored',
          },
        },
      ],
    }),
    now: fetchedAt,
  });
  assert.equal(manifest.ok, true);
  if (!manifest.ok) return;
  await executeIngestPipeline(
    { ARTIFACTS: bucket, META: metaDb as unknown as D1Database },
    { manifestKey: manifest.manifestKey, jobId: 'job_l01_seed', via: 'agent:site-l01' },
    undefined,
    { now: fetchedAt },
  );
}

const md = (res: { body: Record<string, unknown> }) => String(res.body.markdown ?? '');
const via = (res: { body: Record<string, unknown> }) => String(res.body.via ?? '');

function assertFilteredLive(res: { status: number; body: Record<string, unknown> }, label: string): void {
  assert.equal(res.status, 200, `${label}: ${JSON.stringify(res.body).slice(0, 300)}`);
  assert.equal(res.body.cached === true, false, `${label}: must not be a cache hit (via=${via(res)})`);
  assert.equal(via(res).includes('+cache'), false, `${label}: via must not be +cache / +cache:304, got ${via(res)}`);
  assert.equal(res.body.revalidated === true, false, `${label}: must not be served via 304 revalidation`);
  assert.ok(md(res).includes('Platform Role Alpha'), `${label}: filtered output keeps matching records: ${md(res).slice(0, 400)}`);
  assert.equal(md(res).includes('Sales Role Bravo'), false, `${label}: filtered output must drop non-matching records: ${md(res).slice(0, 400)}`);
}

test('L-01: a jsonFilter scrape is not served the cached unfiltered result (options R2 cache + META D1 lookup)', async (t) => {
  const dirs: string[] = [];
  const metaDb = new NodeSqliteD1Database(':memory:', [{ name: 'meta/0001_tracking.sql', sql: meta0001Sql }]);
  t.after(() => {
    metaDb.close();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  const { bucket } = recordingBucket(dirs);
  const now = 1_800_000_000_000;
  await seedVerifiedJsonPage(bucket, metaDb, now - 10_000);
  const env = { ARTIFACTS: bucket, META: metaDb as unknown as D1Database };

  // Plain scrape: served from the verified META D1 + R2 cache and holds every record.
  const log: FetchLog = { ifNoneMatch: [], calls: 0 };
  const plain = await executeScrapeCall({
    payload: { url: JSON_URL, maxAgeMs: 600_000, discoverLlmsTxt: false },
    env,
    now,
    executeHubFetch: originStub(log),
  });
  assert.equal(plain.status, 200);
  assert.ok(md(plain).includes('Sales Role Bravo'), md(plain).slice(0, 400));

  // A live plain scrape also populates the options-scoped R2 cache under the default options hash.
  const plainLive = await executeScrapeCall({
    payload: { url: JSON_URL, maxAgeMs: 0, discoverLlmsTxt: false },
    env: { ARTIFACTS: bucket },
    now: now + 1,
    executeHubFetch: originStub({ ifNoneMatch: [], calls: 0 }),
  });
  assert.equal(plainLive.status, 200);

  // jsonFilter on the already-cached URL, without META: only the options-scoped R2 cache is consulted.
  const filteredR2Only = await executeScrapeCall({
    payload: { url: JSON_URL, maxAgeMs: 600_000, discoverLlmsTxt: false, jsonFilter: 'team=Sales' },
    env: { ARTIFACTS: bucket },
    now: now + 2,
    executeHubFetch: originStub({ ifNoneMatch: [], calls: 0 }),
  });
  assert.equal(filteredR2Only.body.cached === true, false, `filtered (options R2 only): must not be a cache hit (via=${via(filteredR2Only)})`);
  assert.ok(md(filteredR2Only).includes('Sales Role Bravo'), md(filteredR2Only).slice(0, 400));
  assert.equal(md(filteredR2Only).includes('Platform Role Alpha'), false, md(filteredR2Only).slice(0, 400));

  // jsonFilter on the already-cached URL, with META: must be fetched and filtered, never a cache hit.
  const filteredLog: FetchLog = { ifNoneMatch: [], calls: 0 };
  const filtered = await executeScrapeCall({
    payload: { url: JSON_URL, maxAgeMs: 600_000, discoverLlmsTxt: false, jsonFilter: 'team=Platform' },
    env,
    now: now + 3,
    executeHubFetch: originStub(filteredLog),
  });
  assertFilteredLive(filtered, 'filtered (META + R2)');
  assert.equal(filteredLog.calls, 1, 'filtered scrape must reach the origin');

  // Repeating the same filter may be served from its own (filtered) cache entry.
  const repeatLog: FetchLog = { ifNoneMatch: [], calls: 0 };
  const repeat = await executeScrapeCall({
    payload: { url: JSON_URL, maxAgeMs: 600_000, discoverLlmsTxt: false, jsonFilter: 'team=Platform' },
    env,
    now: now + 4,
    executeHubFetch: originStub(repeatLog),
  });
  assert.equal(repeat.status, 200);
  assert.equal(repeat.body.cached, true, 'the same filter is cached under its own options hash');
  assert.equal(repeatLog.calls, 0);
  assert.ok(md(repeat).includes('Platform Role Alpha'), md(repeat).slice(0, 400));
  assert.equal(md(repeat).includes('Sales Role Bravo'), false, `cached filtered result must stay filtered: ${md(repeat).slice(0, 400)}`);
});

test('L-01: a jsonFilter scrape with maxAgeMs: 0 and a stored ETag is not served by R5 304 revalidation', async (t) => {
  const dirs: string[] = [];
  const metaDb = new NodeSqliteD1Database(':memory:', [{ name: 'meta/0001_tracking.sql', sql: meta0001Sql }]);
  t.after(() => {
    metaDb.close();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  const { bucket } = recordingBucket(dirs);
  const now = 1_800_000_000_000;
  await seedVerifiedJsonPage(bucket, metaDb, now - 10_000);
  const env = { ARTIFACTS: bucket, META: metaDb as unknown as D1Database };

  // Control: the plain request does revalidate with the stored ETag and is served as +cache:304.
  const plainLog: FetchLog = { ifNoneMatch: [], calls: 0 };
  const plain = await executeScrapeCall({
    payload: { url: JSON_URL, maxAgeMs: 0, discoverLlmsTxt: false },
    env,
    now,
    executeHubFetch: originStub(plainLog),
  });
  assert.equal(plain.status, 200);
  assert.deepEqual(plainLog.ifNoneMatch, [ETAG], 'plain request revalidates with the stored ETag');
  assert.equal(plain.body.revalidated, true);
  assert.ok(via(plain).includes('+cache:304'), via(plain));

  // jsonFilter: no conditional request, live filtered body.
  const log: FetchLog = { ifNoneMatch: [], calls: 0 };
  const filtered = await executeScrapeCall({
    payload: { url: JSON_URL, maxAgeMs: 0, discoverLlmsTxt: false, jsonFilter: 'team=Platform' },
    env,
    now: now + 1,
    executeHubFetch: originStub(log),
  });
  assert.deepEqual(log.ifNoneMatch, [], 'a jsonFilter scrape must not send If-None-Match from the unfiltered cached document');
  assertFilteredLive(filtered, 'filtered (R5)');
});

test('L-01: scrapeOptionsHash includes the trimmed jsonFilter and is unchanged without one', async (t) => {
  const dirs: string[] = [];
  t.after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  const { bucket, puts } = recordingBucket(dirs);
  const now = 1_800_000_000_000;

  const hashFor = async (extra: Record<string, unknown>, at: number): Promise<string> => {
    const before = puts.length;
    const res = await executeScrapeCall({
      payload: { url: JSON_URL, maxAgeMs: 0, discoverLlmsTxt: false, ...extra },
      env: { ARTIFACTS: bucket },
      now: at,
      executeHubFetch: originStub({ ifNoneMatch: [], calls: 0 }),
    });
    assert.equal(res.status, 200);
    const written = puts.slice(before);
    assert.equal(written.length, 1, `expected one options-cache write, got ${written.length}`);
    const h = written[0]!.json?.optionsHash;
    assert.equal(typeof h, 'string');
    return h as string;
  };

  const plain = await hashFor({}, now);
  const emptyFilter = await hashFor({ jsonFilter: '   ' }, now + 1);
  const platform = await hashFor({ jsonFilter: 'team=Platform' }, now + 2);
  const platformPadded = await hashFor({ jsonFilter: '  team=Platform  ' }, now + 3);
  const sales = await hashFor({ jsonFilter: 'team=Sales' }, now + 4);

  assert.equal(plain, V282_DEFAULT_OPTIONS_HASH, 'no-filter options hash must equal the pinned default (no unintended cache invalidation)');
  assert.equal(emptyFilter, plain, 'a blank jsonFilter is no filter');
  assert.notEqual(platform, plain, 'a jsonFilter must change the options hash');
  assert.notEqual(sales, plain);
  assert.notEqual(platform, sales, 'different jsonFilter values must hash differently');
  assert.equal(platformPadded, platform, 'the filter is trimmed before hashing');
});

test('L-01: a filtered result is never returned to a later unfiltered (or differently filtered) request', async (t) => {
  const dirs: string[] = [];
  const metaDb = new NodeSqliteD1Database(':memory:', [{ name: 'meta/0001_tracking.sql', sql: meta0001Sql }]);
  t.after(() => {
    metaDb.close();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  const now = 1_800_000_000_000;

  for (const withMeta of [false, true]) {
    const { bucket } = recordingBucket(dirs);
    const env = withMeta ? { ARTIFACTS: bucket, META: metaDb as unknown as D1Database } : { ARTIFACTS: bucket };
    const label = withMeta ? 'META + R2' : 'R2 only';
    // Filtered scrape first: populates the cache with filtered Markdown.
    const filtered = await executeScrapeCall({
      payload: { url: JSON_URL, maxAgeMs: 600_000, discoverLlmsTxt: false, jsonFilter: 'team=Platform' },
      env,
      now,
      executeHubFetch: originStub({ ifNoneMatch: [], calls: 0 }),
    });
    assert.equal(filtered.status, 200);
    assert.equal(md(filtered).includes('Sales Role Bravo'), false, `${label}: fixture filter must drop Sales records`);

    // Later unfiltered request: must see every record.
    const plain = await executeScrapeCall({
      payload: { url: JSON_URL, maxAgeMs: 600_000, discoverLlmsTxt: false },
      env,
      now: now + 1,
      executeHubFetch: originStub({ ifNoneMatch: [], calls: 0 }),
    });
    assert.equal(plain.status, 200);
    assert.ok(md(plain).includes('Sales Role Bravo'), `${label}: unfiltered request got filtered Markdown: ${md(plain).slice(0, 400)}`);
    assert.ok(md(plain).includes('Platform Role Alpha'), `${label}: ${md(plain).slice(0, 400)}`);

    // Differently filtered request: must see its own records, not the earlier filter's.
    const sales = await executeScrapeCall({
      payload: { url: JSON_URL, maxAgeMs: 600_000, discoverLlmsTxt: false, jsonFilter: 'team=Sales' },
      env,
      now: now + 2,
      executeHubFetch: originStub({ ifNoneMatch: [], calls: 0 }),
    });
    assert.equal(sales.status, 200);
    assert.ok(md(sales).includes('Sales Role Bravo'), `${label}: team=Sales got another filter's result: ${md(sales).slice(0, 400)}`);
    assert.equal(md(sales).includes('Platform Role Alpha'), false, `${label}: ${md(sales).slice(0, 400)}`);
  }
});

test('TS-6: ocrMode and pdfParserOpts affect scrapeOptionsHash and do not collide in options cache', async (t) => {
  const dirs: string[] = [];
  t.after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });
  const { bucket, puts } = recordingBucket(dirs);
  const now = 1_800_000_100_000;
  const PDF_URL = 'https://docs.example.com/ts6-manual.pdf';

  const pdfReply = async () => ({
    status: 200,
    via: 'agent:stub',
    bodyText: JSON.stringify({
      results: [
        {
          id: 'r1',
          url: PDF_URL,
          finalUrl: PDF_URL,
          status: 200,
          outcome: 'ok',
          contentType: 'application/pdf',
          markdown: '# Manual\nAlpha Page One\fBeta Page Two',
          bodyBase64: Buffer.from('%PDF-1.7 mock bytes').toString('base64'),
        },
      ],
    }),
  });

  const hashFor = async (extra: Record<string, unknown>, at: number): Promise<string> => {
    const before = puts.length;
    const res = await executeScrapeCall({
      payload: { url: PDF_URL, maxAgeMs: 0, discoverLlmsTxt: false, ...extra },
      env: { ARTIFACTS: bucket },
      now: at,
      executeHubFetch: pdfReply,
    });
    assert.equal(res.status, 200);
    const written = puts.slice(before);
    assert.equal(written.length, 1, `expected one options-cache write, got ${written.length}`);
    const h = written[0]!.json?.optionsHash;
    assert.equal(typeof h, 'string');
    return h as string;
  };

  const hashDefault = await hashFor({}, now);
  const hashOcrAuto = await hashFor({ ocr: 'auto' }, now + 1);
  const hashOcrOff = await hashFor({ ocr: 'off' }, now + 2);
  const hashPagesMarkers = await hashFor({ parsers: [{ type: 'pdf', pages: true, pageMarkers: true }] }, now + 3);
  const hashMaxPages = await hashFor({ parsers: [{ type: 'pdf', maxPages: 5 }] }, now + 4);
  const hashFast = await hashFor({ parsers: [{ type: 'pdf', mode: 'fast' }] }, now + 5);

  assert.equal(hashDefault, V282_DEFAULT_OPTIONS_HASH, 'default request optionsHash must equal the pinned default');
  assert.equal(hashOcrAuto, hashDefault, 'explicit ocr:auto matches default');
  assert.notEqual(hashOcrOff, hashDefault, 'ocr:off must hash differently from ocr:auto');
  assert.notEqual(hashPagesMarkers, hashDefault, 'pdf pages/pageMarkers must hash differently from default');
  assert.notEqual(hashMaxPages, hashDefault, 'pdf maxPages must hash differently from default');
  assert.notEqual(hashFast, hashDefault, 'pdf mode:fast must hash differently from default');
  assert.notEqual(hashMaxPages, hashPagesMarkers);

  // Separate bucket: verify cache hit restores pages + pageMarkers while plain default does NOT receive them.
  const { bucket: bucket2 } = recordingBucket(dirs);
  let originFetches = 0;
  const countedPdfFetch = async () => {
    originFetches++;
    return await pdfReply();
  };

  const firstWithPages = await executeScrapeCall({
    payload: {
      url: PDF_URL,
      maxAgeMs: 600_000,
      discoverLlmsTxt: false,
      parsers: [{ type: 'pdf', pages: true, pageMarkers: true }],
    },
    env: { ARTIFACTS: bucket2 },
    now: now + 10,
    executeHubFetch: countedPdfFetch,
  });
  assert.equal(firstWithPages.status, 200);
  const b1 = firstWithPages.body as { markdown?: string; pages?: unknown[]; cached?: boolean };
  assert.ok(b1.markdown?.includes('<!-- page 1 -->'), 'first response must include page 1 marker');
  assert.ok(b1.markdown?.includes('<!-- page 2 -->'), 'first response must include page 2 marker');
  assert.equal(Array.isArray(b1.pages), true);
  assert.equal(b1.pages?.length, 2);
  assert.equal(originFetches, 1);

  const plainFollowUp = await executeScrapeCall({
    payload: {
      url: PDF_URL,
      maxAgeMs: 600_000,
      discoverLlmsTxt: false,
    },
    env: { ARTIFACTS: bucket2 },
    now: now + 11,
    executeHubFetch: countedPdfFetch,
  });
  assert.equal(plainFollowUp.status, 200);
  const bPlain = plainFollowUp.body as { markdown?: string; pages?: unknown[]; cached?: boolean };
  assert.equal(originFetches, 2, 'plain scrape must NOT collide with parsers:[{pages:true,pageMarkers:true}] cache');
  assert.equal(bPlain.markdown?.includes('<!-- page 1 -->'), false, 'plain scrape must not leak pageMarkers');
  assert.equal(bPlain.pages, undefined, 'plain scrape must not receive pages array');

  const cachedPagesHit = await executeScrapeCall({
    payload: {
      url: PDF_URL,
      maxAgeMs: 600_000,
      discoverLlmsTxt: false,
      parsers: [{ type: 'pdf', pages: true, pageMarkers: true }],
    },
    env: { ARTIFACTS: bucket2 },
    now: now + 12,
    executeHubFetch: countedPdfFetch,
  });
  assert.equal(cachedPagesHit.status, 200);
  const bHit = cachedPagesHit.body as { markdown?: string; pages?: unknown[]; cached?: boolean };
  assert.equal(originFetches, 2, 'identical pdfParserOpts must hit cache');
  assert.equal(bHit.cached, true);
  assert.ok(bHit.markdown?.includes('<!-- page 1 -->'), 'cache hit must preserve page 1 marker');
  assert.ok(bHit.markdown?.includes('<!-- page 2 -->'), 'cache hit must preserve page 2 marker');
  assert.equal(Array.isArray(bHit.pages), true);
  assert.equal(bHit.pages?.length, 2);
});
