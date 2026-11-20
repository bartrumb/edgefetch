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

import { validatePublicHttpsTargetUrl } from './overflow';
import {
  cleanPdfMarkdown,
  decodeHtmlEntities,
  decodeMarkdownEntities,
  detectUnsupportedBinaryPayload,
  extractHtmlDocument,
  extractPdfTitle,
  formatDelimitedTableToMarkdown,
  formatFeedXmlToMarkdown,
  formatGitPatchToMarkdown,
  formatIcalendarToMarkdown,
  formatSourceCodeUrlToMarkdown,
  formatVcardToMarkdown,
  lookupCachedScrape,
  lookupCompanionMdUrl,
  redactPiiText,
  sanitizeInlineHtmlInMarkdown,
  SCRAPE_PIPELINE_VERSION,
  tryParseJsonPayloadForScrape,
} from './scrape';
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
 * Strips YAML frontmatter (`---\n...\n---`) from origin-served `text/markdown` documents (e.g. Cloudflare "Markdown for
 * Agents") so extracted chunks don't waste tokens on metadata blocks, while preserving `title:` if present.
 */
export function stripYamlFrontmatter(md: string): { title?: string; body: string } {
  const normalized = md.replace(/\r\n/g, '\n');
  const m = /^---\n([\s\S]{1,4000}?)\n---(?:\n+|$)/.exec(normalized);
  if (!m) return { body: normalized };
  let title: string | undefined;
  for (const line of m[1]!.split('\n')) {
    const tm = /^title\s*:\s*(.+)$/i.exec(line.trim());
    if (tm?.[1]) {
      title = tm[1].trim().replace(/^(['"])([\s\S]*)\1$/, '$2').trim();
      break;
    }
  }
  return {
    ...(title ? { title } : {}),
    body: normalized.slice(m[0].length),
  };
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

  // Split into sections at Markdown headings first (ignoring `#` comments inside fenced code blocks) so every chunk knows its nearest heading.
  const lines = clean.split('\n');
  const sections: Array<{ heading: string; body: string }> = [];
  let currentHeading = '';
  let buf: string[] = [];
  let secFenceChar = '';
  let secFenceLen = 0;

  for (const line of lines) {
    const trimmedLine = line.trim();
    const fenceMatch = /^(`{3,}|~{3,})/.exec(trimmedLine);
    if (fenceMatch?.[1]) {
      const ch = fenceMatch[1][0]!;
      const len = fenceMatch[1].length;
      if (!secFenceChar) {
        secFenceChar = ch;
        secFenceLen = len;
      } else if (ch === secFenceChar && len >= secFenceLen && /^[`~]+\s*$/.test(trimmedLine)) {
        secFenceChar = '';
        secFenceLen = 0;
      }
      buf.push(line);
      continue;
    }
    const hm = !secFenceChar ? /^(#{1,6})\s+(.+)$/.exec(trimmedLine) : null;
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
    let body = buf.join('\n').trim();
    if (secFenceChar && body) {
      body = `${body}\n${secFenceChar.repeat(secFenceLen)}`;
    }
    if (body) sections.push({ heading: currentHeading, body });
  }

  const scanFenceState = (
    segment: string,
    initialHeader: string,
  ): { openHeader: string; openChar: string; openLen: number; lastOpenOffsetInSegment: number } => {
    let openHeader = initialHeader;
    let openChar = initialHeader ? initialHeader[0]! : '';
    let openLen = 0;
    if (initialHeader) {
      const im = /^(`{3,}|~{3,})/.exec(initialHeader);
      openLen = im?.[1]?.length ?? 3;
    }
    let lastOpenOffsetInSegment = -1;
    let offset = 0;
    for (const rawLine of segment.split('\n')) {
      const trimmed = rawLine.trim();
      const fm = /^(`{3,}|~{3,})/.exec(trimmed);
      if (fm?.[1]) {
        const ch = fm[1][0]!;
        const len = fm[1].length;
        if (!openChar) {
          openChar = ch;
          openLen = len;
          openHeader = trimmed;
          lastOpenOffsetInSegment = offset;
        } else if (ch === openChar && len >= openLen && /^[`~]+\s*$/.test(trimmed)) {
          openChar = '';
          openLen = 0;
          openHeader = '';
          lastOpenOffsetInSegment = -1;
        }
      }
      offset += rawLine.length + 1;
    }
    return { openHeader, openChar, openLen, lastOpenOffsetInSegment };
  };

  const chunks: MarkdownChunk[] = [];
  for (const sec of sections) {
    const text = sec.body;
    if (text.length <= safeTarget) {
      chunks.push({ ordinal: chunks.length, heading: sec.heading, text });
      continue;
    }

    let start = 0;
    let reopenFenceHeader = '';
    while (start < text.length) {
      let end = Math.min(text.length, start + safeTarget);
      if (end < text.length) {
        const paraBreak = text.lastIndexOf('\n\n', end);
        const lineBreak = text.lastIndexOf('\n', end);
        const sentenceBreak = text.lastIndexOf('. ', end);
        const spaceBreak = text.lastIndexOf(' ', end);
        const minSplit = start + Math.floor(safeTarget * 0.5);
        const isMidTableLineBreak =
          lineBreak > start &&
          text.slice(text.lastIndexOf('\n', lineBreak - 1) + 1, lineBreak).trimStart().startsWith('|') &&
          text.slice(lineBreak + 1, text.indexOf('\n', lineBreak + 1) === -1 ? text.length : text.indexOf('\n', lineBreak + 1)).trimStart().startsWith('|');
        const tableSafeMinSplit = start + Math.floor(safeTarget * 0.25);
        if (paraBreak >= minSplit || (isMidTableLineBreak && paraBreak >= tableSafeMinSplit)) end = paraBreak;
        else if (lineBreak >= minSplit) end = lineBreak;
        else if (sentenceBreak >= minSplit) end = sentenceBreak + 1;
        else if (spaceBreak >= minSplit) end = spaceBreak;
        else {
          // Avoid splitting a long token/URL mid-character if whitespace follows shortly after `end`.
          const fwdSpace = text.slice(end, Math.min(text.length, end + 120)).search(/\s/);
          if (fwdSpace >= 0) end += fwdSpace;
        }
      }

      let forcedNextStart: number | undefined;
      let fenceState = scanFenceState(text.slice(start, end), reopenFenceHeader);
      if (
        end < text.length &&
        !reopenFenceHeader &&
        fenceState.openChar &&
        fenceState.lastOpenOffsetInSegment >= Math.floor(safeTarget * 0.2)
      ) {
        // Back up right before the opening code fence so normal-sized code blocks stay intact in the next chunk.
        end = start + fenceState.lastOpenOffsetInSegment;
        forcedNextStart = end;
        fenceState = { openHeader: '', openChar: '', openLen: 0, lastOpenOffsetInSegment: -1 };
      }

      let rawSlice = text.slice(start, end);
      if (reopenFenceHeader) {
        rawSlice = `${reopenFenceHeader}\n${rawSlice.replace(/^\n+/, '')}`;
      }
      let slice = rawSlice.trim();
      if (fenceState.openChar) {
        // Oversized code block that must span multiple chunks: close fence cleanly here and reopen on next chunk.
        slice = `${slice}\n${fenceState.openChar.repeat(fenceState.openLen)}`;
        reopenFenceHeader = fenceState.openHeader;
        forcedNextStart = end;
      } else {
        reopenFenceHeader = '';
      }

      if (slice) {
        chunks.push({ ordinal: chunks.length, heading: sec.heading, text: slice });
      }
      if (end >= text.length) break;

      let nextStart: number;
      if (forcedNextStart !== undefined) {
        nextStart = forcedNextStart;
        while (nextStart < text.length && (text[nextStart] === '\n' || text[nextStart] === '\r')) {
          nextStart++;
        }
      } else {
        nextStart = Math.max(start + 1, end - safeOverlap);
        if (nextStart > 0 && nextStart < end) {
          const nearLine = text.indexOf('\n', nextStart);
          if (nearLine !== -1 && nearLine < end && nearLine - nextStart <= Math.max(24, Math.floor(safeOverlap * 0.6))) {
            nextStart = nearLine + 1;
          } else if (!/\s/.test(text[nextStart - 1]!)) {
            while (nextStart < end && !/\s/.test(text[nextStart]!)) {
              nextStart++;
            }
          }
        }
        while (nextStart < text.length && /\s/.test(text[nextStart]!)) {
          nextStart++;
        }
        // Never overlap mid-table rows (`| ... |`) without their table header: advance past headless table continuation rows.
        if (nextStart < end && text[nextStart] === '|') {
          const prevNl = text.lastIndexOf('\n', nextStart - 2);
          const prevLine = text.slice(prevNl + 1, nextStart).trimStart();
          if (prevLine.startsWith('|')) {
            nextStart = end;
            while (nextStart < text.length && (text[nextStart] === '\n' || text[nextStart] === '\r')) {
              nextStart++;
            }
          }
        }
      }
      start = nextStart > start ? nextStart : end;
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
                snippet(chunks_fts, 2, '', '', '...', 32) AS snippet
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

function chunkBoilerplateMultiplier(text: string, heading = ''): number {
  const trimmed = text.trim();
  if (!trimmed) return 0.1;
  if (/was this (page )?helpful|all rights reserved|cookie preferences|privacy policy\s*\|\s*terms/i.test(trimmed)) {
    return 0.25;
  }
  if (/"@context"\s*:\s*"https?:\/\/schema\.org"/i.test(trimmed)) {
    return 0.2;
  }
  if (/^(?:on this page|table of contents|in this article|related resources|was this page helpful\??)$/i.test(heading.trim())) {
    return 0.35;
  }
  const withoutLinks = trimmed.replace(/\[([^\]]*)\]\([^)]+\)/g, ' ');
  const linkSyntaxChars = trimmed.length - withoutLinks.length;
  const linkRatio = linkSyntaxChars / Math.max(1, trimmed.length);
  const proseChars = withoutLinks.replace(/[#>*_`\-\s|]+/g, ' ').trim().length;
  if (linkRatio > 0.55 || (trimmed.length > 120 && proseChars < 50)) {
    return 0.25;
  }
  return 1.0;
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
    rawScore *= chunkBoilerplateMultiplier(chunk.text, chunk.heading);
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
  ephemeral?: boolean;
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
  selfHost?: string;
  now?: number;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, env, executeHubFetch, source = 'extract', selfHost, now = Date.now() } = params;
  if (!Array.isArray(payload.urls) || payload.urls.length === 0 || payload.urls.length > 20) {
    return {
      status: 400,
      via: 'hub',
      body: { ok: false, error: 'invalid_urls', message: 'urls must be an array of 1..20 public https:// URLs' },
    };
  }

  const normalizedUrls: string[] = [];
  const seenNormalizedUrls = new Set<string>();
  for (const raw of payload.urls) {
    const check = validatePublicHttpsTargetUrl(raw, selfHost);
    if (!check.ok) {
      return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_urls', message: check.message } };
    }
    if (!seenNormalizedUrls.has(check.normalized)) {
      seenNormalizedUrls.add(check.normalized);
      normalizedUrls.push(check.normalized);
    }
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
        const strippedCached = stripYamlFrontmatter(hit.markdown);
        const cleanCachedMd = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(strippedCached.body), u);
        byUrl.set(u, {
          url: u,
          status: hit.status,
          cached: true,
          ...(hit.title || strippedCached.title ? { title: hit.title || strippedCached.title } : {}),
          markdown: redactPii ? redactPiiText(cleanCachedMd) : cleanCachedMd,
        });
        continue;
      }
    }
    toFetch.push({ idx: i, url: u });
  }

  let via = 'cache:r2-d1';
  if (toFetch.length > 0) {
    const isEphemeral = Boolean(payload.ephemeral) && !collectionId;
    const retentionMode: ArtifactRetention | 'off' | undefined = isEphemeral
      ? 'off'
      : env.ARTIFACTS && env.META
        ? 'stored'
        : env.ARTIFACTS
          ? 'transient'
          : undefined;
    const call = {
      maxSeconds: isEphemeral ? 35 : 60,
      options: {
        includeBody: true,
        respectRobots: true,
        discoverLlms: false,
        concurrency: 4,
        pauseMs: isEphemeral ? 500 : 800,
        pauseJitterMs: isEphemeral ? 150 : 200,
      },
      requests: toFetch.map((item) => {
        const companionMd = lookupCompanionMdUrl(item.url, now);
        if (companionMd) {
          return {
            id: `ext-${item.idx + 1}`,
            url: companionMd,
            kind: 'text',
            accept: 'text/markdown, text/plain;q=0.9',
          };
        }
        return {
          id: `ext-${item.idx + 1}`,
          url: item.url,
          kind: 'scrape',
          formats: ['markdown'],
          onlyMainContent: true,
          discoverLlms: false,
          redactPii,
        };
      }),
    };
    const fetchOut = await executeHubFetch(target, JSON.stringify(call), site, source, retentionMode, !isEphemeral, collectionId);
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

    const missedCompanionItems = toFetch.filter((item) => {
      if (!lookupCompanionMdUrl(item.url, now)) return false;
      const r = resMap.get(`ext-${item.idx + 1}`);
      return !r || r.outcome !== 'ok';
    });
    if (missedCompanionItems.length > 0) {
      const retryCall = {
        maxSeconds: isEphemeral ? 25 : 45,
        options: {
          includeBody: true,
          respectRobots: true,
          discoverLlms: false,
          concurrency: 4,
          pauseMs: isEphemeral ? 500 : 800,
          pauseJitterMs: isEphemeral ? 150 : 200,
        },
        requests: missedCompanionItems.map((item) => ({
          id: `ext-${item.idx + 1}`,
          url: item.url,
          kind: 'scrape',
          formats: ['markdown'],
          onlyMainContent: true,
          discoverLlms: false,
          redactPii,
        })),
      };
      const retryOut = await executeHubFetch(target, JSON.stringify(retryCall), site, `${source}:retry-html`, retentionMode, !isEphemeral, collectionId);
      if (retryOut.status === 200) {
        const retryParsed = JSON.parse(retryOut.bodyText) as { results?: Array<Record<string, unknown>> };
        for (const r of retryParsed.results ?? []) {
          if (typeof r.id === 'string') resMap.set(r.id, r);
        }
      }
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
      const ctLower = typeof r.contentType === 'string' ? r.contentType.toLowerCase() : '';
      const isPdf = Boolean(
        (typeof r.pdfEngine === 'string' && r.pdfEngine) ||
          ctLower.includes('application/pdf') ||
          /\.pdf(?:$|[?#])/i.test(item.url) ||
          /^https?:\/\/(?:export\.)?arxiv\.org\/pdf\/[A-Za-z0-9._/-]+$/i.test(item.url),
      );
      const binaryProblem = detectUnsupportedBinaryPayload({
        rawBody: rawBodyStr,
        contentType: r.contentType,
        url: item.url,
        bodyEncoding: r.bodyEncoding,
        isPdf,
      });
      if (binaryProblem) {
        byUrl.set(item.url, {
          url: item.url,
          status: typeof r.status === 'number' ? r.status : 200,
          cached: false,
          failedReason: binaryProblem,
        });
        continue;
      }
      const isVcard = Boolean(!isPdf && (ctLower.includes('vcard') || /^BEGIN:VCARD\b/im.test(rawBodyStr.trim())));
      const isHtml = Boolean(
        !isPdf &&
          !isVcard &&
          rawBodyStr &&
          (ctLower.includes('html') || /^\s*<!doctype\s+html|^\s*<html|<(head|body|main|article)\b/i.test(rawBodyStr)),
      );
      const icsDoc = !isPdf && !isVcard && !isHtml && rawBodyStr ? formatIcalendarToMarkdown(rawBodyStr) : null;
      const feedDoc = !isPdf && !isVcard && !isHtml && !icsDoc && rawBodyStr ? formatFeedXmlToMarkdown(rawBodyStr, item.url) : null;
      const jsonDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && rawBodyStr
          ? tryParseJsonPayloadForScrape(rawBodyStr, r.contentType, item.url)
          : null;
      const csvDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && !jsonDoc && rawBodyStr
          ? formatDelimitedTableToMarkdown(rawBodyStr, r.contentType, item.url)
          : null;
      const patchDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && !jsonDoc && !csvDoc && rawBodyStr
          ? formatGitPatchToMarkdown(rawBodyStr, r.contentType, item.url)
          : null;
      const srcDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && !jsonDoc && !csvDoc && !patchDoc && rawBodyStr
          ? formatSourceCodeUrlToMarkdown(rawBodyStr, r.contentType, item.url)
          : null;
      const structuredDoc = icsDoc || feedDoc || jsonDoc || csvDoc || patchDoc || srcDoc;
      let md: string;
      let title: string | undefined;
      if (isVcard) {
        const vc = formatVcardToMarkdown(rawBodyStr);
        md = redactPii ? redactPiiText(vc.markdown) : vc.markdown;
        title = vc.title;
      } else if (structuredDoc) {
        const cleanStructured = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(structuredDoc.markdown), item.url).trim();
        md = redactPii ? redactPiiText(cleanStructured) : cleanStructured;
        title = structuredDoc.title;
      } else {
        const extracted = isHtml ? extractHtmlDocument(rawBodyStr, { baseUrl: item.url, onlyMainContent: true, redactPii }) : undefined;
        const rawCandidateMd =
          (isHtml ? extracted?.markdown : undefined) ||
          (typeof r.markdown === 'string' && r.markdown ? r.markdown : '') ||
          extracted?.markdown ||
          rawBodyStr;
        const stripped = stripYamlFrontmatter(rawCandidateMd);
        let cleaned = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(stripped.body), item.url);
        if (isPdf) {
          cleaned = cleanPdfMarkdown(cleaned);
        }
        if (redactPii) {
          cleaned = redactPiiText(cleaned);
        }
        md = cleaned.trim();
        title =
          extracted?.title ||
          stripped.title ||
          (typeof r.title === 'string' && r.title ? decodeHtmlEntities(r.title) : undefined) ||
          (isPdf && md ? extractPdfTitle(md, item.url) : undefined);
      }
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
      rawContent: query
        ? [...selectedChunks]
            .sort((a, b) => a.ordinal - b.ordinal)
            .map((c) => (c.heading && !/^#{1,6}\s/.test(c.text.trimStart()) ? `## ${c.heading}\n${c.text}` : c.text))
            .join('\n\n...\n\n')
        : (entry.markdown ?? ''),
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
