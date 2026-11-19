/**
 * `SEARCH` D1 FTS5 chunking, atomic page replacement, 7 GB warn / 9 GB stop capacity guard, `POST /v1/collections/:id/search`,
 * and `POST /v1/extract` (Tavily / Firecrawl `extract` parity) (`PR S7`).
 *
 * Security & D1 FTS5 Invariants:
 *  - User queries NEVER touch `MATCH` raw: `sanitizeFtsQuery()` extracts up to 12 Unicode alphanumeric terms (`"t1" OR "t2"`).
 *  - Page re-indexing runs `DELETE FROM chunks WHERE collection_id = ? AND page_id = ?` + `INSERT INTO chunks ...` inside
 *    one `db.batch()`, firing the `chunks_ad` + `chunks_ai` triggers atomically so stale search hits are never left behind.
 *  - Only verified documents (`isContentVerifiedInMetaD1 === true`) are indexed into `SEARCH` D1.
 */

import { extractHtmlDocument, lookupCachedScrape, redactPiiText, SCRAPE_PIPELINE_VERSION } from './scrape';
import { sanitizeFtsQuery, type ArtifactRetention, type OptionalStorageBindings } from './storage';

export const DEFAULT_CHUNK_CHARS = 1_500;
export const DEFAULT_CHUNK_OVERLAP = 150;
export const MAX_CHUNK_CHARS = 64_000; // Well under D1's 2 MB row limit
export const SEARCH_BATCH_INSERT_LIMIT = 45; // <= 46 statements per db.batch() including initial DELETE
export const WARN_SEARCH_DB_BYTES = 7 * 1024 * 1024 * 1024; // 7 GB warning threshold
export const MAX_SEARCH_DB_BYTES = 9 * 1024 * 1024 * 1024; // 9 GB hard stop for new indexing
export const COLLECTION_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

export interface MarkdownChunk {
  ordinal: number;
  heading: string;
  text: string;
}

export interface SearchChunkHit {
  collectionId: string;
  pageId: string;
  documentId: string;
  ordinal: number;
  url: string;
  title: string;
  heading: string;
  snippet: string;
  text: string;
  score: number;
  fetchedAt: number;
}

export type ReplacePageChunksResult =
  | {
      status: 'indexed';
      chunkCount: number;
      rowsWritten: number;
      dbSizeBytes: number;
      capacityWarning: boolean;
    }
  | {
      status: 'capacity_reached';
      error: 'search_capacity_reached';
      dbSizeBytes: number;
    };

export interface SearchIndex {
  replacePageChunks(params: {
    collectionId: string;
    documentId: string;
    pageId: string;
    url: string;
    title: string;
    markdown: string;
    fetchedAt: number;
  }): Promise<ReplacePageChunksResult>;

  searchCollection(params: {
    collectionId: string;
    query: string;
    limit?: number;
  }): Promise<SearchChunkHit[]>;
}

/**
 * Splits extracted Markdown or text into ~1,500-character chunks with a 150-character overlap while preserving
 * Markdown `#`..`######` section headings on every chunk.
 */
export function chunkMarkdownForSearch(
  markdown: string,
  targetChars = DEFAULT_CHUNK_CHARS,
  overlapChars = DEFAULT_CHUNK_OVERLAP,
): MarkdownChunk[] {
  const clean = markdown.replace(/\r\n/g, '\n').trim();
  if (!clean) return [];

  const safeTarget = Math.min(MAX_CHUNK_CHARS, Math.max(200, Math.floor(targetChars)));
  const safeOverlap = Math.min(Math.floor(safeTarget / 3), Math.max(0, Math.floor(overlapChars)));

  // Split into sections at Markdown headings first so every chunk knows its nearest heading.
  const lines = clean.split('\n');
  const sections: Array<{ heading: string; body: string }> = [];
  let currentHeading = '';
  let buf: string[] = [];

  for (const line of lines) {
    const hm = /^(#{1,6})\s+(.+)$/.exec(line.trim());
    if (hm) {
      if (buf.length > 0) {
        const body = buf.join('\n').trim();
        if (body) sections.push({ heading: currentHeading, body });
        buf = [];
      }
      currentHeading = hm[2]!.trim().slice(0, 200);
      buf.push(line);
    } else {
      buf.push(line);
    }
  }
  if (buf.length > 0) {
    const body = buf.join('\n').trim();
    if (body) sections.push({ heading: currentHeading, body });
  }

  const chunks: MarkdownChunk[] = [];
  for (const sec of sections) {
    const text = sec.body;
    if (text.length <= safeTarget) {
      chunks.push({ ordinal: chunks.length, heading: sec.heading, text });
      continue;
    }

    let start = 0;
    while (start < text.length) {
      let end = Math.min(text.length, start + safeTarget);
      if (end < text.length) {
        const paraBreak = text.lastIndexOf('\n\n', end);
        const lineBreak = text.lastIndexOf('\n', end);
        const spaceBreak = text.lastIndexOf(' ', end);
        const minSplit = start + Math.floor(safeTarget * 0.6);
        if (paraBreak >= minSplit) end = paraBreak;
        else if (lineBreak >= minSplit) end = lineBreak;
        else if (spaceBreak >= minSplit) end = spaceBreak;
      }
      const slice = text.slice(start, end).trim();
      if (slice) {
        chunks.push({ ordinal: chunks.length, heading: sec.heading, text: slice });
      }
      if (end >= text.length) break;
      start = Math.max(start + 1, end - safeOverlap);
    }
  }

  return chunks;
}

/**
 * Converts SQLite FTS5 `bm25()` rank (lower / more negative = stronger match; ~`-1e-6` on tiny 1-2 row tables)
 * into a strictly monotonic `(0, 1)` local relevance score where higher numbers indicate stronger matches.
 */
export function bm25RankToScore(rank: number): number {
  if (!Number.isFinite(rank)) return 0;
  const clamped = Math.max(-50, Math.min(50, rank));
  return Number((1 / (1 + Math.exp(clamped))).toFixed(4));
}

export class D1FtsSearchIndex implements SearchIndex {
  private lastKnownDbSizeBytes = 0;
  private readonly warnBytes: number;
  private readonly maxBytes: number;
  private readonly onCapacityWarning?: (sizeBytes: number) => Promise<void> | void;

  constructor(
    private readonly db: D1Database,
    options: {
      warnBytes?: number;
      maxBytes?: number;
      initialSizeBytes?: number;
      onCapacityWarning?: (sizeBytes: number) => Promise<void> | void;
    } = {},
  ) {
    this.warnBytes = options.warnBytes ?? WARN_SEARCH_DB_BYTES;
    this.maxBytes = options.maxBytes ?? MAX_SEARCH_DB_BYTES;
    this.lastKnownDbSizeBytes = options.initialSizeBytes ?? 0;
    this.onCapacityWarning = options.onCapacityWarning;
  }

  private async observeMeta(meta?: D1Meta): Promise<void> {
    const sizeAfter = (meta as { size_after?: number } | undefined)?.size_after;
    if (typeof sizeAfter === 'number' && Number.isFinite(sizeAfter) && sizeAfter >= 0) {
      this.lastKnownDbSizeBytes = sizeAfter;
      if (sizeAfter >= this.warnBytes && this.onCapacityWarning) {
        await this.onCapacityWarning(sizeAfter);
      }
    }
  }

  async replacePageChunks(params: {
    collectionId: string;
    documentId: string;
    pageId: string;
    url: string;
    title: string;
    markdown: string;
    fetchedAt: number;
  }): Promise<ReplacePageChunksResult> {
    const { collectionId, documentId, pageId, url, title, markdown, fetchedAt } = params;
    if (!COLLECTION_ID_RE.test(collectionId)) {
      throw new Error(`invalid collectionId: ${collectionId}`);
    }

    // Probe current D1 database size via a lightweight no-op metadata read if unknown, and enforce the 9 GB stop ceiling.
    if (this.lastKnownDbSizeBytes === 0) {
      const probe = await this.db.prepare('SELECT 1 AS ok').run();
      await this.observeMeta(probe.meta);
    }
    if (this.lastKnownDbSizeBytes >= this.maxBytes) {
      return {
        status: 'capacity_reached',
        error: 'search_capacity_reached',
        dbSizeBytes: this.lastKnownDbSizeBytes,
      };
    }

    const chunks = chunkMarkdownForSearch(markdown);
    const safeTitle = title.slice(0, 300);

    // Batch 0 ALWAYS starts with `DELETE FROM chunks WHERE collection_id = ? AND page_id = ?` so old FTS tokens are purged atomically.
    const firstSlice = chunks.slice(0, SEARCH_BATCH_INSERT_LIMIT);
    const firstStmts: D1PreparedStatement[] = [
      this.db.prepare('DELETE FROM chunks WHERE collection_id = ? AND page_id = ?').bind(collectionId, pageId),
    ];
    for (const ch of firstSlice) {
      firstStmts.push(
        this.db
          .prepare(
            `INSERT INTO chunks (collection_id, document_id, page_id, ordinal, url, title, heading, text, fetched_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(collectionId, documentId, pageId, ch.ordinal, url, safeTitle, ch.heading, ch.text, fetchedAt),
      );
    }

    let rowsWritten = 0;
    const firstRes = await this.db.batch(firstStmts);
    for (const r of firstRes) {
      rowsWritten += r.meta?.rows_written ?? 0;
      await this.observeMeta(r.meta);
    }

    for (let offset = SEARCH_BATCH_INSERT_LIMIT; offset < chunks.length; offset += SEARCH_BATCH_INSERT_LIMIT) {
      if (this.lastKnownDbSizeBytes >= this.maxBytes) {
        return {
          status: 'capacity_reached',
          error: 'search_capacity_reached',
          dbSizeBytes: this.lastKnownDbSizeBytes,
        };
      }
      const slice = chunks.slice(offset, offset + SEARCH_BATCH_INSERT_LIMIT);
      const stmts = slice.map((ch) =>
        this.db
          .prepare(
            `INSERT INTO chunks (collection_id, document_id, page_id, ordinal, url, title, heading, text, fetched_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(collection_id, page_id, ordinal) DO UPDATE SET
               document_id = excluded.document_id,
               url = excluded.url,
               title = excluded.title,
               heading = excluded.heading,
               text = excluded.text,
               fetched_at = excluded.fetched_at`,
          )
          .bind(collectionId, documentId, pageId, ch.ordinal, url, safeTitle, ch.heading, ch.text, fetchedAt),
      );
      const res = await this.db.batch(stmts);
      for (const r of res) {
        rowsWritten += r.meta?.rows_written ?? 0;
        await this.observeMeta(r.meta);
      }
    }

    return {
      status: 'indexed',
      chunkCount: chunks.length,
      rowsWritten,
      dbSizeBytes: this.lastKnownDbSizeBytes,
      capacityWarning: this.lastKnownDbSizeBytes >= this.warnBytes,
    };
  }

  async searchCollection(params: { collectionId: string; query: string; limit?: number }): Promise<SearchChunkHit[]> {
    const { collectionId, query, limit = 10 } = params;
    if (!COLLECTION_ID_RE.test(collectionId)) return [];
    const safeMatch = sanitizeFtsQuery(query);
    if (!safeMatch) return [];

    const safeLimit = Math.min(50, Math.max(1, Math.floor(limit)));
    const rows = await this.db
      .prepare(
        `SELECT c.page_id,
                c.document_id,
                c.ordinal,
                c.url,
                c.title,
                c.heading,
                c.text,
                c.fetched_at,
                bm25(chunks_fts, 5.0, 2.0, 1.0) AS rank,
                snippet(chunks_fts, 2, '[', ']', '...', 8) AS snippet
         FROM chunks_fts
         JOIN chunks c ON c.id = chunks_fts.rowid
         WHERE chunks_fts MATCH ?
           AND c.collection_id = ?
         ORDER BY rank
         LIMIT ?`,
      )
      .bind(safeMatch, collectionId, safeLimit)
      .all<{
        page_id: string;
        document_id: string;
        ordinal: number;
        url: string;
        title: string;
        heading: string;
        text: string;
        fetched_at: number;
        rank: number;
        snippet: string;
      }>();

    await this.observeMeta(rows.meta);
    return (rows.results ?? []).map((r) => ({
      collectionId,
      pageId: r.page_id,
      documentId: r.document_id,
      ordinal: r.ordinal,
      url: r.url,
      title: r.title,
      heading: r.heading,
      snippet: r.snippet,
      text: r.text,
      score: bm25RankToScore(r.rank),
      fetchedAt: r.fetched_at,
    }));
  }
}

/** In-memory BM25 chunk scorer used by `POST /v1/extract` to select top `chunksPerSource` passages for a `query`. */
export function rankChunksInMemory(
  chunks: MarkdownChunk[],
  query: string,
  topK: number,
): Array<MarkdownChunk & { score: number }> {
  const safeTopK = Math.max(1, Math.min(20, Math.floor(topK)));
  if (chunks.length === 0) return [];
  const terms = [...new Set((query.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? []).filter((t) => t.length >= 2))].slice(0, 12);
  if (terms.length === 0) {
    return chunks.slice(0, safeTopK).map((c) => ({ ...c, score: 1 }));
  }

  const tokenized: string[][] = chunks.map((c) => [...(`${c.heading} ${c.text}`.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? [])]);
  const avgLen = Math.max(1, tokenized.reduce((s, t) => s + t.length, 0) / tokenized.length);
  const df = new Map<string, number>();
  for (const q of terms) {
    let count = 0;
    for (const toks of tokenized) if (toks.includes(q)) count++;
    df.set(q, count);
  }

  const k1 = 1.5;
  const b = 0.75;
  const scored = chunks.map((chunk, idx) => {
    const toks = tokenized[idx]!;
    const tf = new Map<string, number>();
    for (const t of toks) tf.set(t, (tf.get(t) ?? 0) + 1);
    let rawScore = 0;
    for (const q of terms) {
      const f = tf.get(q) ?? 0;
      if (f === 0) continue;
      const n = df.get(q) ?? 0;
      const idf = Math.log(1 + (chunks.length - n + 0.5) / (n + 0.5));
      const norm = (f * (k1 + 1)) / (f + k1 * (1 - b + (b * toks.length) / avgLen));
      const headingBoost = chunk.heading.toLowerCase().includes(q) ? 1.35 : 1.0;
      rawScore += idf * norm * headingBoost;
    }
    return { ...chunk, score: Number(rawScore.toFixed(4)) };
  });

  scored.sort((a, b2) => (b2.score !== a.score ? b2.score - a.score : a.ordinal - b2.ordinal));
  return scored.slice(0, safeTopK);
}

export interface ExtractRequestPayload {
  urls?: unknown;
  query?: unknown;
  chunksPerSource?: unknown;
  maxAgeMs?: unknown;
  redactPii?: unknown;
  collectionId?: unknown;
  target?: unknown;
  site?: unknown;
}

export async function executeExtractCall(params: {
  payload: ExtractRequestPayload;
  env: OptionalStorageBindings;
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: ArtifactRetention | 'off',
    hydrateInline?: boolean,
    collectionId?: string,
  ) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;
  source?: string;
  now?: number;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, env, executeHubFetch, source = 'extract', now = Date.now() } = params;
  if (!Array.isArray(payload.urls) || payload.urls.length === 0 || payload.urls.length > 20) {
    return {
      status: 400,
      via: 'hub',
      body: { ok: false, error: 'invalid_urls', message: 'urls must be an array of 1..20 public https:// URLs' },
    };
  }

  const normalizedUrls: string[] = [];
  for (const raw of payload.urls) {
    if (typeof raw !== 'string' || !raw.trim()) {
      return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_urls', message: 'every URL must be a non-empty string' } };
    }
    let u: URL;
    try {
      u = new URL(raw.trim());
    } catch {
      return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_urls', message: `invalid URL: ${raw}` } };
    }
    if (u.protocol !== 'https:' || (u.port && u.port !== '443') || u.username || u.password) {
      return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_urls', message: 'only https:// URLs on port 443 are permitted' } };
    }
    normalizedUrls.push(u.toString());
  }

  const query = typeof payload.query === 'string' ? payload.query.trim() : '';
  const chunksPerSource =
    typeof payload.chunksPerSource === 'number' && Number.isFinite(payload.chunksPerSource)
      ? Math.min(10, Math.max(1, Math.floor(payload.chunksPerSource)))
      : 3;
  const maxAgeMs =
    typeof payload.maxAgeMs === 'number' && Number.isFinite(payload.maxAgeMs) ? Math.max(0, Math.floor(payload.maxAgeMs)) : 0;
  const redactPii = Boolean(payload.redactPii);
  const collectionId =
    typeof payload.collectionId === 'string' && COLLECTION_ID_RE.test(payload.collectionId.trim())
      ? payload.collectionId.trim()
      : undefined;
  const target: 'auto' | 'agent' | 'container' =
    payload.target === 'agent' || payload.target === 'container' ? payload.target : 'auto';
  const site = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim() : undefined;

  const byUrl = new Map<
    string,
    {
      url: string;
      status: number;
      cached: boolean;
      title?: string;
      markdown?: string;
      failedReason?: string;
    }
  >();

  const toFetch: Array<{ idx: number; url: string }> = [];
  for (let i = 0; i < normalizedUrls.length; i++) {
    const u = normalizedUrls[i]!;
    if (maxAgeMs > 0 && env.ARTIFACTS && env.META) {
      const hit = await lookupCachedScrape({
        bucket: env.ARTIFACTS,
        metaDb: env.META,
        url: u,
        maxAgeMs,
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
        now,
      });
      if (hit) {
        byUrl.set(u, {
          url: u,
          status: hit.status,
          cached: true,
          ...(hit.title ? { title: hit.title } : {}),
          markdown: redactPii ? redactPiiText(hit.markdown) : hit.markdown,
        });
        continue;
      }
    }
    toFetch.push({ idx: i, url: u });
  }

  let via = 'cache:r2-d1';
  if (toFetch.length > 0) {
    const retentionMode: ArtifactRetention | undefined = env.ARTIFACTS && env.META ? 'stored' : env.ARTIFACTS ? 'transient' : undefined;
    const call = {
      maxSeconds: 60,
      options: {
        includeBody: true,
        respectRobots: true,
        discoverLlms: true,
      },
      requests: toFetch.map((item) => ({
        id: `ext-${item.idx + 1}`,
        url: item.url,
        kind: 'scrape',
        formats: ['markdown'],
        onlyMainContent: true,
        discoverLlms: true,
        redactPii,
      })),
    };
    const fetchOut = await executeHubFetch(target, JSON.stringify(call), site, source, retentionMode, true, collectionId);
    via = fetchOut.via;
    if (fetchOut.status !== 200) {
      let errBody: Record<string, unknown> = { ok: false, error: 'extract_failed' };
      try {
        errBody = { ok: false, ...(JSON.parse(fetchOut.bodyText) as Record<string, unknown>) };
      } catch {
        // ignore
      }
      return { status: fetchOut.status, via, body: errBody };
    }

    const parsed = JSON.parse(fetchOut.bodyText) as { results?: Array<Record<string, unknown>> };
    const resMap = new Map<string, Record<string, unknown>>();
    for (const r of parsed.results ?? []) {
      if (typeof r.id === 'string') resMap.set(r.id, r);
    }

    for (const item of toFetch) {
      const r = resMap.get(`ext-${item.idx + 1}`);
      if (!r || r.outcome !== 'ok') {
        byUrl.set(item.url, {
          url: item.url,
          status: typeof r?.status === 'number' ? r.status : 0,
          cached: false,
          failedReason: typeof r?.problem === 'string' && r.problem ? r.problem : String(r?.outcome ?? 'error'),
        });
        continue;
      }
      const rawBodyStr = typeof r.body === 'string' && r.bodyEncoding !== 'base64' ? r.body : '';
      const extracted = rawBodyStr ? extractHtmlDocument(rawBodyStr, { baseUrl: item.url, onlyMainContent: true, redactPii }) : undefined;
      const md = (typeof r.markdown === 'string' && r.markdown) || extracted?.markdown || rawBodyStr;
      const title = (typeof r.title === 'string' && r.title) || extracted?.title;
      byUrl.set(item.url, {
        url: item.url,
        status: typeof r.status === 'number' ? r.status : 200,
        cached: false,
        ...(title ? { title } : {}),
        markdown: md,
      });
    }
  }

  const results: Array<Record<string, unknown>> = [];
  const failedResults: Array<Record<string, unknown>> = [];
  for (const u of normalizedUrls) {
    const entry = byUrl.get(u);
    if (!entry || entry.failedReason !== undefined) {
      failedResults.push({
        url: u,
        status: entry?.status ?? 0,
        error: entry?.failedReason ?? 'not_fetched',
      });
      continue;
    }
    const allChunks = chunkMarkdownForSearch(entry.markdown ?? '');
    const selectedChunks = query ? rankChunksInMemory(allChunks, query, chunksPerSource) : allChunks.slice(0, chunksPerSource).map((c) => ({ ...c, score: 1 }));
    results.push({
      url: u,
      status: entry.status,
      cached: entry.cached,
      ...(entry.title ? { title: entry.title } : {}),
      rawContent: query ? selectedChunks.map((c) => (c.heading ? `## ${c.heading}\n${c.text}` : c.text)).join('\n\n...\n\n') : (entry.markdown ?? ''),
      chunks: selectedChunks,
    });
  }

  return {
    status: 200,
    via,
    body: {
      ok: true,
      ...(query ? { query } : {}),
      ...(collectionId ? { collectionId } : {}),
      results,
      failedResults,
    },
  };
}
