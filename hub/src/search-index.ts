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

import { resolveSiteExtractorTwin } from './extractors/registry';
import {
  analyzeUrlRedirect,
  buildBlockedInfo,
  chunkJsonRecords,
  detectWorkdayRedirectStub,
  extractJobPostingJsonLd,
  formatJobPostingHeaderMarkdown,
  isJobLegalBoilerplateChunk,
  isThinScriptedPage,
  resolveAtsPreFetchSpec,
  type BlockedSuggestion,
  type RedirectAnalysis,
  type StructuredJobPosting,
} from './jobs';
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
import {
  classifyContentState,
  classifyWafAndChallenge,
  isEligibleForWaybackFallback,
  recoverSsrHydrationContent,
  tryFetchWaybackSnapshot,
  type ContentState,
  type WafClassification,
} from './waf';
import {
  isEligibleForExternalSpaFallback,
  listConfiguredSpaFallbacks,
  normalizeSpaFallbackMode,
  tryExternalSpaFallback,
  type SpaFallbackProvider,
} from './spa-fallback';

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
 * Splits an oversized prose paragraph or list item into link-safe, inline-code-safe sentence units (`<= maxLen`)
 * so `chunkMarkdownForSearch` (`P6`) NEVER cuts inside `[anchor](https://...)` or `` `code` `` and never starts a
 * chunk mid-sentence with a lowercase continuation word or a dangling `](...)` tail.
 */
function splitOversizedBlockIntoSafeUnits(block: string, maxLen: number): Array<{ text: string; allowOverlap: boolean }> {
  const trimmed = block.trim();
  if (!trimmed) return [];
  if (trimmed.length <= maxLen) return [{ text: trimmed, allowOverlap: true }];

  // Step 1: Extract natural sentence spans while respecting inline `` `...` `` and `[...](...)` Markdown links.
  const sentences: string[] = [];
  let inCodeTicks = 0;
  let bracketDepth = 0;
  let linkParenDepth = 0;
  let sentStart = 0;
  const len = trimmed.length;

  for (let i = 0; i < len; i++) {
    const ch = trimmed[i]!;
    if (ch === '`') {
      let run = 1;
      while (i + run < len && trimmed[i + run] === '`') run++;
      if (inCodeTicks === 0) inCodeTicks = run;
      else if (run === inCodeTicks) inCodeTicks = 0;
      i += run - 1;
      continue;
    }
    if (inCodeTicks > 0) continue;

    if (linkParenDepth > 0) {
      if (ch === '(') linkParenDepth++;
      else if (ch === ')') linkParenDepth = Math.max(0, linkParenDepth - 1);
      continue;
    }
    if (ch === '[') {
      bracketDepth++;
      continue;
    }
    if (ch === ']' && bracketDepth > 0) {
      bracketDepth--;
      if (i + 1 < len && trimmed[i + 1] === '(') {
        linkParenDepth = 1;
        i++;
      }
      continue;
    }

    if (bracketDepth === 0 && (ch === '.' || ch === '!' || ch === '?')) {
      // Skip common abbreviations ("e.g.", "i.e.", "vs.", "Mr.", "Dr.", "St.", "U.S.") and decimal numbers ("3.14")
      if (ch === '.' && i > 0 && i + 1 < len && /\d/.test(trimmed[i - 1]!) && /\d/.test(trimmed[i + 1]!)) {
        continue;
      }
      const prevWord = trimmed.slice(Math.max(0, i - 5), i);
      if (ch === '.' && /(?:^|\s)(?:e\.g|i\.e|vs|mr|mrs|ms|dr|jr|sr|st|inc|ltd|co|corp|fig|no)$/i.test(prevWord)) {
        continue;
      }

      let after = i + 1;
      while (after < len && (trimmed[after] === '"' || trimmed[after] === "'" || trimmed[after] === '\u201d' || trimmed[after] === ')' || trimmed[after] === ']')) {
        after++;
      }
      if (after < len && /\s/.test(trimmed[after]!)) {
        let nextNonWs = after;
        while (nextNonWs < len && /\s/.test(trimmed[nextNonWs]!)) nextNonWs++;
        if (nextNonWs < len && /[\p{Lu}0-9#*`\[>-]/u.test(trimmed[nextNonWs]!)) {
          const piece = trimmed.slice(sentStart, after).trim();
          if (piece) sentences.push(piece);
          sentStart = nextNonWs;
          i = nextNonWs - 1;
        }
      }
    }
  }
  const tail = trimmed.slice(sentStart).trim();
  if (tail) sentences.push(tail);

  // Step 2: Pack sentences up to `maxLen`; if a single mega-sentence still exceeds `maxLen`, split at link-safe whitespace with `allowOverlap: false`.
  const units: Array<{ text: string; allowOverlap: boolean }> = [];
  for (const sent of sentences) {
    if (sent.length <= maxLen) {
      units.push({ text: sent, allowOverlap: true });
      continue;
    }
    // Split oversized single sentence only at whitespace outside `[...](...)` and `` `...` ``
    let pos = 0;
    while (pos < sent.length) {
      if (sent.length - pos <= maxLen) {
        const rem = sent.slice(pos).trim();
        if (rem) units.push({ text: rem, allowOverlap: false });
        break;
      }
      let bestWs = -1;
      let firstSafeWsAfter = -1;
      let cTicks = 0;
      let bDepth = 0;
      let pDepth = 0;
      const scanLimit = Math.min(sent.length, pos + maxLen + 240);
      for (let j = pos; j < scanLimit; j++) {
        const c = sent[j]!;
        if (c === '`') {
          let r = 1;
          while (j + r < scanLimit && sent[j + r] === '`') r++;
          if (cTicks === 0) cTicks = r;
          else if (r === cTicks) cTicks = 0;
          j += r - 1;
          continue;
        }
        if (cTicks > 0) continue;
        if (pDepth > 0) {
          if (c === '(') pDepth++;
          else if (c === ')') pDepth = Math.max(0, pDepth - 1);
          continue;
        }
        if (c === '[') {
          bDepth++;
          continue;
        }
        if (c === ']' && bDepth > 0) {
          bDepth--;
          if (j + 1 < scanLimit && sent[j + 1] === '(') {
            pDepth = 1;
            j++;
          }
          continue;
        }
        if (bDepth === 0 && pDepth === 0 && /\s/.test(c)) {
          if (j - pos <= maxLen) {
            bestWs = j;
          } else if (firstSafeWsAfter === -1) {
            firstSafeWsAfter = j;
            break;
          }
        }
      }
      const cut = bestWs > pos + Math.floor(maxLen * 0.25) ? bestWs : firstSafeWsAfter > pos ? firstSafeWsAfter : Math.min(sent.length, pos + maxLen);
      const sub = sent.slice(pos, cut).trim();
      if (sub) units.push({ text: sub, allowOverlap: false });
      pos = cut;
      while (pos < sent.length && /\s/.test(sent[pos]!)) pos++;
    }
  }
  return units;
}

interface AtomicMdUnit {
  text: string;
  sepBefore: ' ' | '\n' | '\n\n';
  allowOverlap: boolean;
}

function parseSectionIntoAtomicUnits(sectionBody: string, safeTarget: number): AtomicMdUnit[] {
  const lines = sectionBody.split('\n');
  const rawBlocks: Array<{ kind: 'heading' | 'fence' | 'table' | 'list' | 'quote' | 'para'; text: string; fenceHeader?: string; fenceClose?: string }> = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i]!;
    const trimmed = line.trim();
    if (!trimmed) {
      i++;
      continue;
    }

    // 1. Fenced code block
    const fm = /^(`{3,}|~{3,})(.*)$/.exec(trimmed);
    if (fm?.[1] && !(fm[1][0] === '`' && fm[2]!.includes('`'))) {
      const fChar = fm[1][0]!;
      const fLen = fm[1].length;
      const fLines = [line];
      i++;
      let closed = false;
      while (i < lines.length) {
        const cl = lines[i]!;
        fLines.push(cl);
        i++;
        const ct = cl.trim();
        const cm = /^(`{3,}|~{3,})\s*$/.exec(ct);
        if (cm?.[1] && cm[1][0] === fChar && cm[1].length >= fLen) {
          closed = true;
          break;
        }
      }
      const closeFence = fChar.repeat(fLen);
      if (!closed) fLines.push(closeFence);
      rawBlocks.push({ kind: 'fence', text: fLines.join('\n'), fenceHeader: trimmed, fenceClose: closeFence });
      continue;
    }

    // 2. Heading
    if (/^#{1,6}\s+/.test(trimmed)) {
      rawBlocks.push({ kind: 'heading', text: trimmed });
      i++;
      continue;
    }

    // 3. Markdown Table
    if (trimmed.startsWith('|')) {
      const tLines: string[] = [];
      while (i < lines.length && lines[i]!.trim().startsWith('|')) {
        tLines.push(lines[i]!);
        i++;
      }
      rawBlocks.push({ kind: 'table', text: tLines.join('\n') });
      continue;
    }

    // 4. List item (`- `, `* `, `+ `, `1. ` + indented continuation lines)
    if (/^(?:[-*+]|\d+[.)])\s+/.test(trimmed)) {
      const itemLines = [line];
      i++;
      while (i < lines.length) {
        const nl = lines[i]!;
        const nt = nl.trim();
        if (!nt) break;
        if (/^(?:[-*+]|\d+[.)])\s+/.test(nt) && !/^\s{2,}/.test(nl)) break;
        if (/^(?:#{1,6}\s+|`{3,}|~{3,}|\|)/.test(nt)) break;
        itemLines.push(nl);
        i++;
      }
      rawBlocks.push({ kind: 'list', text: itemLines.join('\n') });
      continue;
    }

    // 5. Blockquote
    if (trimmed.startsWith('>')) {
      const qLines: string[] = [];
      while (i < lines.length && lines[i]!.trim().startsWith('>')) {
        qLines.push(lines[i]!);
        i++;
      }
      rawBlocks.push({ kind: 'quote', text: qLines.join('\n') });
      continue;
    }

    // 6. Prose paragraph
    const pLines: string[] = [];
    while (i < lines.length) {
      const pl = lines[i]!;
      const pt = pl.trim();
      if (!pt) break;
      if (/^(?:#{1,6}\s+|`{3,}|~{3,}|\||>|(?:[-*+]|\d+[.)])\s+)/.test(pt)) break;
      pLines.push(pl);
      i++;
    }
    if (pLines.length > 0) {
      rawBlocks.push({ kind: 'para', text: pLines.join('\n') });
    } else {
      i++;
    }
  }

  const units: AtomicMdUnit[] = [];
  let prevKind: string | null = null;

  for (const b of rawBlocks) {
    const sepBefore: '\n' | '\n\n' = prevKind === 'list' && b.kind === 'list' ? '\n' : '\n\n';
    prevKind = b.kind;

    if (b.text.length <= safeTarget) {
      units.push({
        text: b.text,
        sepBefore,
        allowOverlap: b.kind === 'para' || b.kind === 'list' || b.kind === 'quote',
      });
      continue;
    }

    if (b.kind === 'fence') {
      const innerLines = b.text.split('\n');
      const openHdr = b.fenceHeader ?? '```';
      const closeHdr = b.fenceClose ?? '```';
      const bodyLines = innerLines.slice(1, innerLines.length - 1);
      const maxInner = Math.max(80, safeTarget - openHdr.length - closeHdr.length - 4);
      let curLines: string[] = [];
      let curLen = 0;
      for (const cl of bodyLines) {
        if (curLines.length > 0 && curLen + cl.length + 1 > maxInner) {
          units.push({ text: `${openHdr}\n${curLines.join('\n')}\n${closeHdr}`, sepBefore: '\n\n', allowOverlap: false });
          curLines = [];
          curLen = 0;
        }
        curLines.push(cl);
        curLen += cl.length + 1;
      }
      if (curLines.length > 0) {
        units.push({ text: `${openHdr}\n${curLines.join('\n')}\n${closeHdr}`, sepBefore: '\n\n', allowOverlap: false });
      }
      continue;
    }

    if (b.kind === 'table') {
      const tRows = b.text.split('\n');
      const hasHeader = tRows.length >= 2 && /^\|\s*[-:]+/.test(tRows[1]!.trim());
      const headerPrefix = hasHeader ? `${tRows[0]}\n${tRows[1]}` : '';
      const dataRows = hasHeader ? tRows.slice(2) : tRows;
      let curRows: string[] = headerPrefix ? [headerPrefix] : [];
      let curLen = headerPrefix.length;
      for (const r of dataRows) {
        if (curRows.length > (headerPrefix ? 1 : 0) && curLen + r.length + 1 > safeTarget) {
          units.push({ text: curRows.join('\n'), sepBefore: '\n\n', allowOverlap: false });
          curRows = headerPrefix ? [headerPrefix] : [];
          curLen = headerPrefix.length;
        }
        curRows.push(r);
        curLen += r.length + 1;
      }
      if (curRows.length > (headerPrefix ? 1 : 0)) {
        units.push({ text: curRows.join('\n'), sepBefore: '\n\n', allowOverlap: false });
      }
      continue;
    }

    const subUnits = splitOversizedBlockIntoSafeUnits(b.text, safeTarget);
    subUnits.forEach((su, idx) => {
      units.push({
        text: su.text,
        sepBefore: idx === 0 ? sepBefore : ' ',
        allowOverlap: su.allowOverlap,
      });
    });
  }

  return units;
}

/**
 * Splits extracted Markdown or text into ~1,500-character chunks on clean block & sentence boundaries (`P6`),
 * preserving Markdown `#`..`######` section headings on every chunk while guaranteeing that NO chunk ever cuts
 * inside `[anchor](url)` links or starts mid-sentence with a lowercase fragment or dangling `](...)` link tail.
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
    const fenceMatch = /^(`{3,}|~{3,})(.*)$/.exec(trimmedLine);
    if (fenceMatch?.[1] && !(!secFenceChar && fenceMatch[1][0] === '`' && fenceMatch[2]!.includes('`'))) {
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

  const chunks: MarkdownChunk[] = [];
  for (const sec of sections) {
    const text = sec.body;
    if (text.length <= safeTarget) {
      chunks.push({ ordinal: chunks.length, heading: sec.heading, text });
      continue;
    }

    const units = parseSectionIntoAtomicUnits(text, safeTarget);
    if (units.length === 0) continue;

    let curUnits: AtomicMdUnit[] = [];
    let curLen = 0;

    const renderUnits = (arr: AtomicMdUnit[]): string => {
      if (arr.length === 0) return '';
      let out = arr[0]!.text;
      for (let k = 1; k < arr.length; k++) {
        out += arr[k]!.sepBefore + arr[k]!.text;
      }
      return out.trim();
    };

    for (let uIdx = 0; uIdx < units.length; uIdx++) {
      const u = units[uIdx]!;
      const addedLen = curUnits.length === 0 ? u.text.length : u.sepBefore.length + u.text.length;

      // Never strand a lone section heading in its own tiny chunk before the first content block.
      const onlyHeadingSoFar = curUnits.length === 1 && /^#{1,6}\s+/.test(curUnits[0]!.text);

      if (curUnits.length > 0 && !onlyHeadingSoFar && curLen + addedLen > safeTarget) {
        const rendered = renderUnits(curUnits);
        if (rendered) {
          chunks.push({ ordinal: chunks.length, heading: sec.heading, text: rendered });
        }

        // Carry over trailing complete sentence/list/paragraph units (`allowOverlap === true`) up to `safeOverlap` chars!
        const overlapSeed: AtomicMdUnit[] = [];
        if (safeOverlap > 0) {
          let ovLen = 0;
          for (let back = curUnits.length - 1; back >= 0; back--) {
            const cand = curUnits[back]!;
            if (!cand.allowOverlap) break;
            const candCost = overlapSeed.length === 0 ? cand.text.length : cand.sepBefore.length + cand.text.length;
            if (ovLen + candCost > safeOverlap) break;
            overlapSeed.unshift(cand);
            ovLen += candCost;
          }
        }
        curUnits = [...overlapSeed];
        curLen = renderUnits(curUnits).length;
      }

      const nextAdded = curUnits.length === 0 ? u.text.length : u.sepBefore.length + u.text.length;
      curUnits.push(u);
      curLen += nextAdded;
    }

    if (curUnits.length > 0) {
      const rendered = renderUnits(curUnits);
      if (rendered) {
        chunks.push({ ordinal: chunks.length, heading: sec.heading, text: rendered });
      }
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
  // P4: Down-weight EEO, disability accommodations, AI-in-hiring, and applicant privacy notices so they never outrank pay/role facts.
  if (isJobLegalBoilerplateChunk(trimmed, heading)) {
    return 0.18;
  }
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
  jsonFilter?: unknown;
  renderMode?: unknown;
  chunksPerSource?: unknown;
  maxAgeMs?: unknown;
  redactPii?: unknown;
  waybackFallback?: unknown;
  spaFallback?: unknown;
  noCache?: unknown;
  collectionId?: unknown;
  ephemeral?: boolean;
  target?: unknown;
  site?: unknown;
}

function countExtractWords(s: string): number {
  return (s.trim().match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
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
  const jsonFilterStr = typeof payload.jsonFilter === 'string' ? payload.jsonFilter.trim() : '';
  const rawRenderModeStr = typeof payload.renderMode === 'string' ? payload.renderMode.trim().toLowerCase() : '';
  const explicitRenderMode: 'always' | 'auto' | 'off' | undefined =
    rawRenderModeStr === 'always' || rawRenderModeStr === 'browser'
      ? 'always'
      : rawRenderModeStr === 'auto' || rawRenderModeStr === 'off'
        ? rawRenderModeStr
        : undefined;
  const effectiveRenderMode: 'always' | 'auto' | 'off' = explicitRenderMode ?? 'auto';
  const chunksPerSource =
    typeof payload.chunksPerSource === 'number' && Number.isFinite(payload.chunksPerSource)
      ? Math.min(10, Math.max(1, Math.floor(payload.chunksPerSource)))
      : 3;
  const maxAgeMs =
    typeof payload.maxAgeMs === 'number' && Number.isFinite(payload.maxAgeMs) ? Math.max(0, Math.floor(payload.maxAgeMs)) : 0;
  const redactPii = Boolean(payload.redactPii);
  const waybackFallback = Boolean(payload.waybackFallback);
  const spaFallbackMode = normalizeSpaFallbackMode(payload.spaFallback);
  const collectionId =
    typeof payload.collectionId === 'string' && COLLECTION_ID_RE.test(payload.collectionId.trim())
      ? payload.collectionId.trim()
      : undefined;
  const target: 'auto' | 'agent' | 'container' =
    payload.target === 'agent' || payload.target === 'container' ? payload.target : 'auto';
  const site = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim() : undefined;

  const htmlFragToMd = (frag: string, fragBase?: string) => {
    const sub = extractHtmlDocument(frag, { baseUrl: fragBase, onlyMainContent: false, redactPii });
    return { markdown: sub.markdown, links: sub.links };
  };

  const byUrl = new Map<
    string,
    {
      url: string;
      finalUrl?: string;
      redirectInfo?: RedirectAnalysis;
      status: number;
      cached: boolean;
      title?: string;
      markdown?: string;
      jobPosting?: StructuredJobPosting;
      contentState?: ContentState;
      contentSource?: 'meta-description' | 'ssr-hydration' | 'wayback';
      waybackSnapshotUrl?: string;
      waybackTimestamp?: string;
      renderedVia?: 'browser' | 'browser-auto' | SpaFallbackProvider;
      preChunkedRecords?: MarkdownChunk[];
      recordCount?: number;
      totalRecords?: number;
      failedReason?: string;
      waf?: WafClassification;
      blocked?: BlockedSuggestion;
    }
  >();

  const toFetch: Array<{ idx: number; url: string }> = [];
  for (let i = 0; i < normalizedUrls.length; i++) {
    const u = normalizedUrls[i]!;
    if (maxAgeMs > 0 && env.ARTIFACTS && env.META && !jsonFilterStr) {
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

    const atsByIdx = new Map<number, NonNullable<ReturnType<typeof resolveAtsPreFetchSpec>>>();
    const twinByIdx = new Map<number, NonNullable<ReturnType<typeof resolveSiteExtractorTwin>>>();

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
        // P1 & P2: Route Ashby, Workday CXS (`GET` & `POST`), Greenhouse, and Lever URLs directly to their structured APIs!
        const ats = resolveAtsPreFetchSpec(item.url);
        if (ats) {
          atsByIdx.set(item.idx, ats);
          return {
            id: `ext-${item.idx + 1}`,
            url: ats.fetchUrl,
            method: ats.method,
            ...(ats.requestBody ? { requestBody: ats.requestBody } : {}),
            ...(ats.contentType ? { contentType: ats.contentType } : {}),
            kind: ats.kind,
            accept: ats.accept,
          };
        }
        const twin = effectiveRenderMode !== 'always' ? resolveSiteExtractorTwin(item.url) : null;
        if (twin) {
          twinByIdx.set(item.idx, twin);
          return {
            id: `ext-${item.idx + 1}`,
            url: twin.fetchUrl,
            kind: twin.kind,
            accept: twin.accept,
          };
        }
        const companionMd = effectiveRenderMode !== 'always' ? lookupCompanionMdUrl(item.url, now) : undefined;
        if (companionMd) {
          return {
            id: `ext-${item.idx + 1}`,
            url: companionMd,
            kind: 'text',
            accept: 'text/markdown',
          };
        }
        return {
          id: `ext-${item.idx + 1}`,
          url: item.url,
          kind: explicitRenderMode === 'always' ? 'render' : 'scrape',
          ...(explicitRenderMode ? { renderMode: explicitRenderMode } : {}),
          formats: ['markdown'],
          onlyMainContent: true,
          discoverLlms: false,
          redactPii,
        };
      }),
    };
    const fetchOut = await executeHubFetch(target, JSON.stringify(call), site, source, retentionMode, !isEphemeral, collectionId);
    via = fetchOut.via;
    let batchHubErrCode: unknown;
    const resMap = new Map<string, Record<string, unknown>>();
    if (fetchOut.status !== 200) {
      let errBody: Record<string, unknown> = { ok: false, error: 'extract_failed' };
      try {
        errBody = { ok: false, ...(JSON.parse(fetchOut.bodyText) as Record<string, unknown>) };
      } catch {
        // ignore
      }
      batchHubErrCode = errBody.error;
      const canSpaRescue =
        listConfiguredSpaFallbacks(env).length > 0 &&
        isEligibleForExternalSpaFallback({
          mode: spaFallbackMode,
          status: fetchOut.status,
          errorCode: batchHubErrCode,
          problem: typeof errBody.message === 'string' ? errBody.message : '',
        });
      if (!canSpaRescue) {
        return { status: fetchOut.status, via, body: errBody };
      }
    } else {
      const parsed = JSON.parse(fetchOut.bodyText) as { results?: Array<Record<string, unknown>> };
      for (const r of parsed.results ?? []) {
        if (typeof r.id === 'string') resMap.set(r.id, r);
      }
    }

    const fallbackHtmlItems = toFetch.filter((item) => {
      const hadTwinOrComp =
        atsByIdx.has(item.idx) || twinByIdx.has(item.idx) || Boolean(lookupCompanionMdUrl(item.url, now));
      if (!hadTwinOrComp) return false;
      const r = resMap.get(`ext-${item.idx + 1}`);
      return !r || r.outcome !== 'ok';
    });
    if (fallbackHtmlItems.length > 0) {
      for (const fItem of fallbackHtmlItems) {
        atsByIdx.delete(fItem.idx);
        twinByIdx.delete(fItem.idx);
      }
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
        requests: fallbackHtmlItems.map((item) => ({
          id: `ext-${item.idx + 1}`,
          url: item.url,
          kind: explicitRenderMode === 'always' ? 'render' : 'scrape',
          ...(explicitRenderMode ? { renderMode: explicitRenderMode } : {}),
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
      let r = resMap.get(`ext-${item.idx + 1}`);
      if (!r || r.outcome !== 'ok') {
        const prob = typeof r?.problem === 'string' && r.problem ? r.problem : String(r?.outcome ?? 'error');
        const rawErrBody = typeof r?.body === 'string' && r.bodyEncoding !== 'base64' ? r.body : '';
        const errWaf =
          (r?.waf && typeof r.waf === 'object' ? (r.waf as WafClassification) : null) ??
          classifyWafAndChallenge({ status: typeof r?.status === 'number' ? r.status : 0, rawBody: rawErrBody });

        if (
          isEligibleForExternalSpaFallback({
            mode: spaFallbackMode,
            outcome: r?.outcome ?? 'error',
            status: r?.status ?? (batchHubErrCode === 'fat_agent_required' ? 503 : 0),
            errorCode: batchHubErrCode,
            problem: prob,
            waf: errWaf,
          })
        ) {
          const spaOut = await tryExternalSpaFallback({
            url: item.url,
            env,
            mode: spaFallbackMode,
            robotsAlreadyVerified: false,
            onlyMainContent: true,
            noCache: Boolean(payload.noCache),
          });
          if (spaOut) {
            via = spaOut.via;
            byUrl.set(item.url, {
              url: item.url,
              finalUrl: spaOut.finalUrl,
              redirectInfo: analyzeUrlRedirect(item.url, spaOut.finalUrl),
              status: spaOut.status,
              cached: false,
              ...(spaOut.title ? { title: spaOut.title } : {}),
              contentState: 'active',
              renderedVia: spaOut.provider,
              markdown: redactPii ? redactPiiText(spaOut.markdown) : spaOut.markdown,
            });
            continue;
          }
        }

        if (
          waybackFallback &&
          isEligibleForWaybackFallback({
            outcome: r?.outcome,
            status: r?.status,
            problem: prob,
            waf: errWaf,
          })
        ) {
          const wb = await tryFetchWaybackSnapshot({
            url: item.url,
            target,
            site,
            source,
            executeHubFetch,
          });
          if (wb) {
            const wbExt = extractHtmlDocument(wb.rawBody, { baseUrl: item.url, onlyMainContent: true, redactPii });
            const wbMd = (wbExt.markdown.trim() || wb.rawBody.trim());
            byUrl.set(item.url, {
              url: item.url,
              finalUrl: item.url,
              status: 200,
              cached: false,
              ...(wbExt.title ? { title: wbExt.title } : {}),
              contentSource: 'wayback',
              waybackSnapshotUrl: wb.snapshotUrl,
              waybackTimestamp: wb.timestamp,
              markdown: redactPii ? redactPiiText(wbMd) : wbMd,
            });
            continue;
          }
        }

        const effectiveProb = errWaf ? errWaf.summary : prob;
        const blocked = buildBlockedInfo(item.url, errWaf ? 'challenge' : r?.outcome, effectiveProb, r?.status);
        byUrl.set(item.url, {
          url: item.url,
          status: typeof r?.status === 'number' ? r.status : 0,
          cached: false,
          failedReason: effectiveProb,
          ...(errWaf ? { waf: errWaf } : {}),
          ...(blocked ? { blocked } : {}),
        });
        continue;
      }

      let rawBodyStr = typeof r.body === 'string' && r.bodyEncoding !== 'base64' ? r.body : '';
      let finalUrl = typeof r.finalUrl === 'string' && r.finalUrl ? r.finalUrl : item.url;
      let renderedVia: 'browser' | 'browser-auto' | SpaFallbackProvider | undefined =
        explicitRenderMode === 'always' ? 'browser' : r.rendered === true ? 'browser-auto' : undefined;

      // R2 & R3: Guard against HTTP 200 WAF/CAPTCHA interstitials with all 4 anti-false-positive layers!
      const okWaf =
        (r.waf && typeof r.waf === 'object' ? (r.waf as WafClassification) : null) ??
        (rawBodyStr ? classifyWafAndChallenge({ status: typeof r.status === 'number' ? r.status : 200, rawBody: rawBodyStr }) : null);
      if (okWaf) {
        const blocked = buildBlockedInfo(finalUrl, 'challenge', okWaf.summary, r.status);
        byUrl.set(item.url, {
          url: item.url,
          status: typeof r.status === 'number' ? r.status : 200,
          cached: false,
          failedReason: okWaf.summary,
          waf: okWaf,
          ...(blocked ? { blocked } : {}),
        });
        continue;
      }

      // Handle ATS pre-fetch adapter response (`P1` Ashby, `P2` Workday CXS, Greenhouse, Lever)
      const atsSpec = atsByIdx.get(item.idx);
      if (atsSpec && rawBodyStr) {
        const filteredBoard =
          jsonFilterStr || atsSpec.id.endsWith('-board')
            ? chunkJsonRecords({
                rawBody: rawBodyStr,
                contentType: 'application/json',
                url: item.url,
                ...(jsonFilterStr ? { jsonFilter: jsonFilterStr } : {}),
                htmlToMd: htmlFragToMd,
              })
            : null;
        const formatted = atsSpec.format(rawBodyStr, item.url, htmlFragToMd);
        if ((jsonFilterStr && filteredBoard) || (formatted && formatted.markdown.trim())) {
          const mdRaw = jsonFilterStr && filteredBoard ? filteredBoard.markdown : formatted!.markdown;
          const cleanMd = redactPii ? redactPiiText(mdRaw) : mdRaw;
          byUrl.set(item.url, {
            url: item.url,
            finalUrl: item.url,
            status: typeof r.status === 'number' ? r.status : 200,
            cached: false,
            title: (jsonFilterStr && filteredBoard ? filteredBoard.title : formatted?.title) || undefined,
            markdown: cleanMd,
            ...(formatted?.jobPosting ? { jobPosting: formatted.jobPosting } : {}),
            ...(filteredBoard && (jsonFilterStr || atsSpec.id.endsWith('-board'))
              ? {
                  preChunkedRecords: filteredBoard.chunks,
                  recordCount: filteredBoard.matchedRecords,
                  totalRecords: filteredBoard.totalRecords,
                }
              : {}),
          });
          continue;
        }
      }

      // Handle Site Extractor Twin response
      const twinSpec = twinByIdx.get(item.idx);
      if (twinSpec && rawBodyStr) {
        const twinOut = twinSpec.formatTwin(rawBodyStr, item.url, htmlFragToMd);
        if (twinOut && twinOut.markdown.trim()) {
          byUrl.set(item.url, {
            url: item.url,
            finalUrl: item.url,
            status: typeof r.status === 'number' ? r.status : 200,
            cached: false,
            title: twinOut.title,
            markdown: redactPii ? redactPiiText(twinOut.markdown) : twinOut.markdown,
          });
          continue;
        }
      }

      // P2: Workday Redirect Stub Rescue (`{"widget":"redirect","url":"/Workday","externalSpa":true}`)
      const wdStub = rawBodyStr ? detectWorkdayRedirectStub(rawBodyStr, finalUrl) : null;
      if (wdStub) {
        const stubAts = resolveAtsPreFetchSpec(wdStub.redirectUrl);
        if (stubAts) {
          try {
            const stubOut = await executeHubFetch(
              target,
              JSON.stringify({
                maxSeconds: 25,
                options: { includeBody: true, respectRobots: true },
                requests: [
                  {
                    id: 'wd-stub-1',
                    url: stubAts.fetchUrl,
                    method: stubAts.method,
                    ...(stubAts.requestBody ? { requestBody: stubAts.requestBody } : {}),
                    ...(stubAts.contentType ? { contentType: stubAts.contentType } : {}),
                    kind: stubAts.kind,
                    accept: stubAts.accept,
                  },
                ],
              }),
              site,
              `${source}:workday-stub`,
              retentionMode,
              !isEphemeral,
              collectionId,
            );
            if (stubOut.status === 200) {
              const stubParsed = JSON.parse(stubOut.bodyText) as { results?: Array<Record<string, unknown>> };
              const stubItem = stubParsed.results?.[0];
              const stubBody = typeof stubItem?.body === 'string' && stubItem.bodyEncoding !== 'base64' ? stubItem.body : '';
              const stubFmt = stubItem?.outcome === 'ok' && stubBody ? stubAts.format(stubBody, wdStub.redirectUrl, htmlFragToMd) : null;
              if (stubFmt && stubFmt.markdown.trim()) {
                byUrl.set(item.url, {
                  url: item.url,
                  finalUrl: wdStub.redirectUrl,
                  redirectInfo: analyzeUrlRedirect(item.url, wdStub.redirectUrl),
                  status: typeof stubItem?.status === 'number' ? stubItem.status : 200,
                  cached: false,
                  title: stubFmt.title,
                  markdown: redactPii ? redactPiiText(stubFmt.markdown) : stubFmt.markdown,
                  ...(stubFmt.jobPosting ? { jobPosting: stubFmt.jobPosting } : {}),
                });
                continue;
              }
            }
          } catch {
            // Fall through if stub resolution fails.
          }
        }
      }

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
      let isHtml = Boolean(
        !isPdf &&
          !isVcard &&
          rawBodyStr &&
          (ctLower.includes('html') || /^\s*<!doctype\s+html|^\s*<html|<(head|body|main|article)\b/i.test(rawBodyStr)),
      );

      // P5: Per-record JSON array chunking (`1 chunk = 1 record`, HTML converted to Markdown, `jsonFilter` applied)
      const icsDoc = !isPdf && !isVcard && !isHtml && rawBodyStr ? formatIcalendarToMarkdown(rawBodyStr) : null;
      const feedDoc = !isPdf && !isVcard && !isHtml && !icsDoc && rawBodyStr ? formatFeedXmlToMarkdown(rawBodyStr, finalUrl) : null;
      const jsonDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && rawBodyStr
          ? tryParseJsonPayloadForScrape(rawBodyStr, r.contentType, finalUrl)
          : null;
      const isNotebookOrOpenApi = Boolean(
        jsonDoc?.parsed &&
          typeof jsonDoc.parsed === 'object' &&
          !Array.isArray(jsonDoc.parsed) &&
          ('openapi' in (jsonDoc.parsed as Record<string, unknown>) ||
            'swagger' in (jsonDoc.parsed as Record<string, unknown>) ||
            'nbformat' in (jsonDoc.parsed as Record<string, unknown>)),
      );
      const jsonRecordsDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && !isNotebookOrOpenApi && rawBodyStr
          ? chunkJsonRecords({
              rawBody: rawBodyStr,
              contentType: r.contentType,
              url: finalUrl,
              ...(jsonFilterStr ? { jsonFilter: jsonFilterStr } : {}),
              htmlToMd: htmlFragToMd,
            })
          : null;
      if (jsonRecordsDoc) {
        const cleanJsonMd = redactPii ? redactPiiText(jsonRecordsDoc.markdown) : jsonRecordsDoc.markdown;
        byUrl.set(item.url, {
          url: item.url,
          finalUrl,
          redirectInfo: analyzeUrlRedirect(item.url, finalUrl),
          status: typeof r.status === 'number' ? r.status : 200,
          cached: false,
          title: jsonRecordsDoc.title,
          markdown: cleanJsonMd,
          preChunkedRecords: redactPii
            ? jsonRecordsDoc.chunks.map((c) => ({ ...c, text: redactPiiText(c.text) }))
            : jsonRecordsDoc.chunks,
          recordCount: jsonRecordsDoc.matchedRecords,
          totalRecords: jsonRecordsDoc.totalRecords,
        });
        continue;
      }

      const csvDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && !jsonDoc && rawBodyStr
          ? formatDelimitedTableToMarkdown(rawBodyStr, r.contentType, finalUrl)
          : null;
      const patchDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && !jsonDoc && !csvDoc && rawBodyStr
          ? formatGitPatchToMarkdown(rawBodyStr, r.contentType, finalUrl)
          : null;
      const srcDoc =
        !isPdf && !isVcard && !isHtml && !icsDoc && !feedDoc && !jsonDoc && !csvDoc && !patchDoc && rawBodyStr
          ? formatSourceCodeUrlToMarkdown(rawBodyStr, r.contentType, finalUrl)
          : null;
      const structuredDoc = icsDoc || feedDoc || jsonDoc || csvDoc || patchDoc || srcDoc;
      let md: string;
      let title: string | undefined;
      let jobPosting: StructuredJobPosting | undefined;
      let contentSource: 'meta-description' | 'ssr-hydration' | undefined;

      if (isVcard) {
        const vc = formatVcardToMarkdown(rawBodyStr);
        md = redactPii ? redactPiiText(vc.markdown) : vc.markdown;
        title = vc.title;
      } else if (structuredDoc) {
        const cleanStructured = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(structuredDoc.markdown), finalUrl).trim();
        md = redactPii ? redactPiiText(cleanStructured) : cleanStructured;
        title = structuredDoc.title;
      } else {
        let extracted = isHtml ? extractHtmlDocument(rawBodyStr, { baseUrl: finalUrl, onlyMainContent: true, redactPii }) : undefined;

        // R6: SSR Hydration State Recovery (`__NEXT_DATA__`, Remix, Apollo) before falling back to Chromium!
        const ssrHydrated =
          isHtml && !isPdf && countExtractWords(extracted?.markdown ?? '') < 80
            ? recoverSsrHydrationContent(rawBodyStr, finalUrl, htmlFragToMd)
            : null;
        if (ssrHydrated && countExtractWords(ssrHydrated.markdown) > countExtractWords(extracted?.markdown ?? '') * 2) {
          contentSource = 'ssr-hydration';
        }

        // P3: Automatic browser switch on thin / filter-only scripted HTML pages (`renderedVia: "browser-auto"`).
        if (
          isHtml &&
          !contentSource &&
          effectiveRenderMode === 'auto' &&
          r.rendered !== true &&
          target !== 'container' &&
          isThinScriptedPage(rawBodyStr, extracted?.markdown ?? '')
        ) {
          try {
            const autoRes = await executeHubFetch(
              'agent',
              JSON.stringify({
                maxSeconds: 40,
                options: { includeBody: true, respectRobots: true, maxBytes: 16 * 1024 * 1024, timeoutMs: 35_000 },
                requests: [
                  {
                    id: `ext-auto-${item.idx + 1}`,
                    url: finalUrl,
                    kind: 'render',
                    renderMode: 'always',
                    formats: ['markdown'],
                    onlyMainContent: true,
                    redactPii,
                    waitForMs: 1_800,
                  },
                ],
              }),
              site,
              `${source}:browser-auto`,
              retentionMode,
              !isEphemeral,
              collectionId,
            );
            if (autoRes.status === 200) {
              const autoParsed = JSON.parse(autoRes.bodyText) as { results?: Array<Record<string, unknown>> };
              const autoItem = autoParsed.results?.[0];
              const autoHtml = typeof autoItem?.body === 'string' && autoItem.bodyEncoding !== 'base64' ? autoItem.body : '';
              if (autoItem?.outcome === 'ok' && autoHtml) {
                const autoFinal = typeof autoItem.finalUrl === 'string' && autoItem.finalUrl ? autoItem.finalUrl : finalUrl;
                const autoExt = extractHtmlDocument(autoHtml, { baseUrl: autoFinal, onlyMainContent: true, redactPii });
                if (countExtractWords(autoExt.markdown) > countExtractWords(extracted?.markdown ?? '')) {
                  r = autoItem;
                  rawBodyStr = autoHtml;
                  finalUrl = autoFinal;
                  isHtml = true;
                  extracted = autoExt;
                  renderedVia = 'browser-auto';
                }
              }
            }
          } catch {
            // Keep static extraction when no browser-v1 node is connected.
          }
        }

        const jp = isHtml ? extractJobPostingJsonLd(rawBodyStr, finalUrl, extracted?.markdown ?? '') : null;
        if (jp) jobPosting = jp;

        const rawCandidateMd =
          (contentSource === 'ssr-hydration' && ssrHydrated ? ssrHydrated.markdown : undefined) ||
          (isHtml ? extracted?.markdown : undefined) ||
          (typeof r.markdown === 'string' && r.markdown ? r.markdown : '') ||
          extracted?.markdown ||
          rawBodyStr;
        const stripped = stripYamlFrontmatter(rawCandidateMd);
        let cleaned = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(stripped.body), finalUrl);
        if (isPdf) {
          cleaned = cleanPdfMarkdown(cleaned);
        }
        if (redactPii) {
          cleaned = redactPiiText(cleaned);
        }
        md = cleaned.trim();
        title =
          (contentSource === 'ssr-hydration' ? ssrHydrated?.title : undefined) ||
          extracted?.title ||
          stripped.title ||
          (typeof r.title === 'string' && r.title ? decodeHtmlEntities(r.title) : undefined) ||
          (isPdf && md ? extractPdfTitle(md, finalUrl) : undefined);

        // P4: Prepend structured JobPosting facts header so pay/workplace/location rank #1 during passage selection!
        if (jobPosting) {
          const jpHdr = formatJobPostingHeaderMarkdown(jobPosting);
          if (jpHdr && !/\*\*Compensation\*\*:/.test(md.slice(0, 400))) {
            const topH = /^(#\s+[^\n]+)\n+([\s\S]*)$/.exec(md);
            md = topH ? `${topH[1]}\n\n${jpHdr}\n\n${topH[2]}` : `# ${jobPosting.title}\n\n${jpHdr}\n\n${md}`;
          }
        }

        // P1: Meta-description rescue when extracted HTML body has < 50 words and `metadata.description` has >= 18 words.
        const desc = extracted?.description;
        const mdWords = countExtractWords(md);
        const descWords = desc ? countExtractWords(desc) : 0;
        if (isHtml && !isPdf && mdWords < 50 && desc && descWords >= 18 && descWords > mdWords * 2) {
          const cleanDesc = redactPii ? redactPiiText(desc) : desc;
          md = [title ? `# ${title}` : '', cleanDesc].filter(Boolean).join('\n\n');
          contentSource = 'meta-description';
        }
      }

      let stateRes = classifyContentState({
        status: typeof r.status === 'number' ? r.status : 200,
        title,
        markdown: md,
        ...(isHtml ? { rawHtml: rawBodyStr } : {}),
        ...(jobPosting?.validThrough ? { validThrough: jobPosting.validThrough } : {}),
        nowMs: now,
      });

      if (
        isHtml &&
        !isPdf &&
        effectiveRenderMode !== 'off' &&
        countExtractWords(md) < 50 &&
        isThinScriptedPage(rawBodyStr, md) &&
        isEligibleForExternalSpaFallback({
          mode: spaFallbackMode,
          outcome: 'ok',
          status: r.status ?? 200,
          waf: okWaf,
          contentState: stateRes.state,
          isThinSpa200: true,
        })
      ) {
        const spaOut = await tryExternalSpaFallback({
          url: finalUrl,
          env,
          mode: spaFallbackMode,
          robotsAlreadyVerified: true,
          onlyMainContent: true,
          noCache: Boolean(payload.noCache),
        });
        if (spaOut && countExtractWords(spaOut.markdown) > countExtractWords(md)) {
          md = redactPii ? redactPiiText(spaOut.markdown) : spaOut.markdown;
          finalUrl = spaOut.finalUrl;
          if (spaOut.title) title = spaOut.title;
          via = spaOut.via;
          renderedVia = spaOut.provider;
          contentSource = undefined;
          stateRes = { state: 'active' };
        }
      }

      byUrl.set(item.url, {
        url: item.url,
        finalUrl,
        redirectInfo: analyzeUrlRedirect(item.url, finalUrl),
        status: typeof r.status === 'number' ? r.status : 200,
        cached: false,
        ...(title ? { title } : {}),
        ...(jobPosting ? { jobPosting } : {}),
        contentState: stateRes.state,
        ...(contentSource ? { contentSource } : {}),
        ...(renderedVia ? { renderedVia } : {}),
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
        ...(entry?.waf ? { waf: entry.waf } : {}),
        ...(entry?.blocked ? { blocked: entry.blocked } : {}),
      });
      continue;
    }
    const allChunks = entry.preChunkedRecords ?? chunkMarkdownForSearch(entry.markdown ?? '');
    const selectedChunks = query
      ? rankChunksInMemory(allChunks, query, chunksPerSource)
      : allChunks.slice(0, chunksPerSource).map((c) => ({ ...c, score: 1 }));
    results.push({
      url: u,
      ...(entry.finalUrl && entry.finalUrl !== u ? { finalUrl: entry.finalUrl } : {}),
      ...(entry.redirectInfo?.redirected ? entry.redirectInfo : {}),
      status: entry.status,
      cached: entry.cached,
      ...(entry.title ? { title: entry.title } : {}),
      ...(entry.contentState ? { contentState: entry.contentState } : {}),
      ...(entry.contentSource ? { contentSource: entry.contentSource } : {}),
      ...(entry.waybackSnapshotUrl ? { waybackSnapshotUrl: entry.waybackSnapshotUrl, waybackTimestamp: entry.waybackTimestamp } : {}),
      ...(entry.renderedVia ? { renderedVia: entry.renderedVia } : {}),
      ...(entry.jobPosting ? { jobPosting: entry.jobPosting } : {}),
      ...(entry.recordCount !== undefined ? { recordCount: entry.recordCount, totalRecords: entry.totalRecords } : {}),
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
      ...(jsonFilterStr ? { jsonFilter: jsonFilterStr } : {}),
      ...(collectionId ? { collectionId } : {}),
      results,
      failedResults,
    },
  };
}
