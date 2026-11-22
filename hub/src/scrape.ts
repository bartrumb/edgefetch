/**
 * Markdown derivation pipeline (`SCRAPE_PIPELINE_VERSION = 1`), `llms.txt` parser, `maxAgeMs` verified cache lookup,
 * and `POST /v1/scrape` + MCP `scrape` execution (`PR S6`).
 *
 * Security Invariants:
 *  - `deriveMarkdownDocument` NEVER reuses or derives from unverified artifacts (`isContentVerifiedInMetaD1` must be true).
 *  - Derived outputs are stored deterministically at `derived/<pipelineVersion>/markdown/<contentSha256>` in `ARTIFACTS` R2
 *    and tracked in `META` D1 `documents` with `(content_sha256, format, pipeline_version)` uniqueness.
 */

import {
  applyPostFetchSiteExtractor,
  enrichShopifyProductFromJson,
  enrichWooCommerceProductFromStoreApi,
  extractShopifyCurrencyFromHtml,
  isShopifyHtmlOrHeaders,
  isWooCommerceHtmlOrHeaders,
  resolveCustomDomainShopifyProductTwinUrl,
  resolveCustomDomainWooCommerceProductTwinUrl,
  resolveSiteExtractorTwin,
  type PaginationInfo,
  type PostFetchSiteResult,
  type TwinFormattedDoc,
} from './extractors/registry';
import {
  detectSiteFrameworkLinear,
  extractInertiaPagePropsLinear,
  type BrowserFrameworkGlobals,
} from './framework-detect';
import {
  asciiLower,
  escapeRegexLiteral,
  isTagNameBoundary,
  MAX_HTML_SCAN_CHARS,
  replaceHtmlOpenTagsLinear,
  replaceHtmlTagBlocksLinear,
  replaceHtmlTagsQuoteAwareLinear,
  replacePairedHtmlElementsLinear,
  scanHtmlTagsLinear,
  stripHtmlCommentsLinear,
  stripHtmlTagsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from './safe-input';
import { isContentVerifiedInMetaD1, sha256HexString } from './ingest';
import {
  analyzeUrlRedirect,
  buildBlockedInfo,
  chunkJsonRecords,
  detectWorkdayRedirectStub,
  extractJobPostingJsonLd,
  formatJobPostingHeaderMarkdown,
  isThinScriptedPage,
  resolveAtsPreFetchSpec,
  type StructuredJobPosting,
} from './jobs';
import { computeMarkdownChanges } from './map-crawl';
import { MARKDOWN_FOR_AGENTS_ACCEPT, validatePublicHttpsTargetUrl } from './overflow';
import { getActiveRequestTracer, sanitizeUrlForSpan, setActiveSpanAttribute, type RequestTracer, type TraceContext } from './otel';
import { chunkMarkdownForSearch, rankChunksInMemory } from './search-index';
import {
  isValidSha256Hex,
  r2DerivedKey,
  readVerifiedArtifactFromR2,
  type ArtifactRetention,
  type OptionalStorageBindings,
} from './storage';
import {
  classifyContentState,
  classifyWafAndChallenge,
  hasExternalOrWidgetIframeLinear,
  isEligibleForWaybackFallback,
  recoverSsrHydrationContent,
  refineBlockedInfo,
  tryFetchWaybackSnapshot,
  type ContentState,
  type WafClassification,
} from './waf';
import {
  isEligibleForExternalSpaFallback,
  normalizeSpaFallbackMode,
  tryExternalSpaFallback,
  type SpaFallbackProvider,
  type SpaFallbackSuccess,
} from './spa-fallback';
import {
  extractJsonWithOptionalLlm,
  resolveLlmConfig,
  summarizeMarkdownWithOptionalLlm,
  type LlmEnvBindings,
} from './llm';
import {
  detectPromptInjection,
  encodeBodyToRawBase64,
  extractHtmlAttributesBySelectors,
  extractStructuredProduct,
  normalizeInlineBrowserActions,
  parsePdfParserOptions,
  splitPdfPagesAndMarkers,
} from './scrape-advanced';

export const SCRAPE_PIPELINE_VERSION = 30;

export interface ScrapedImage {
  url: string;
  alt?: string;
}

export interface BrandingProfile {
  title?: string;
  description?: string;
  canonicalUrl?: string;
  favicon?: string;
  logo?: string;
  ogImage?: string;
  themeColor?: string;
  colors?: string[];
  fonts?: string[];
}

export interface LlmsLinkItem {
  section?: string;
  title: string;
  url: string;
  notes?: string;
}

export interface ParsedLlmsTxt {
  sourceUrl: string;
  title?: string;
  summary?: string;
  fullTxtUrl?: string;
  links: LlmsLinkItem[];
}

export interface ExtractedDocument {
  title?: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  modifiedTime?: string;
  siteName?: string;
  wordCount?: number;
  language?: string;
  canonicalUrl?: string;
  markdownAlternateUrl?: string;
  favicon?: string;
  extractorId?: string;
  records?: Array<Record<string, unknown>>;
  pagination?: PaginationInfo;
  total?: number;
  returned?: number;
  truncated?: boolean;
  nextCursor?: string;
  inertiaHydrated?: boolean;
  markdown: string;
  text: string;
  links: string[];
  images: ScrapedImage[];
  branding: BrandingProfile;
}

const NAMED_HTML_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  rsquo: '\u2019',
  lsquo: '\u2018',
  rdquo: '\u201d',
  ldquo: '\u201c',
  ndash: '\u2013',
  mdash: '\u2014',
  hellip: '\u2026',
  bull: '\u2022',
  middot: '\u00b7',
  copy: '\u00a9',
  reg: '\u00ae',
  trade: '\u2122',
  deg: '\u00b0',
  plusmn: '\u00b1',
  times: '\u00d7',
  divide: '\u00f7',
  frac12: '\u00bd',
  frac14: '\u00bc',
  frac34: '\u00be',
  rarr: '\u2192',
  larr: '\u2190',
  uarr: '\u2191',
  darr: '\u2193',
  harr: '\u2194',
  laquo: '\u00ab',
  raquo: '\u00bb',
  lsaquo: '\u2039',
  rsaquo: '\u203a',
  ensp: ' ',
  emsp: ' ',
  thinsp: ' ',
  euro: '\u20ac',
  pound: '\u00a3',
  yen: '\u00a5',
  cent: '\u00a2',
  sect: '\u00a7',
  para: '\u00b6',
  dagger: '\u2020',
  Dagger: '\u2021',
  permil: '\u2030',
  prime: '\u2032',
  Prime: '\u2033',
  shy: '',
  zwj: '\u200d',
  zwnj: '\u200c',
  colon: ':',
  tab: '\t',
  newline: '\n',
  lpar: '(',
  rpar: ')',
  sol: '/',
  bsol: '\\',
  semi: ';',
  equals: '=',
  num: '#',
  quest: '?',
  excl: '!',
  commat: '@',
  lsqb: '[',
  rsqb: ']',
  grave: '`',
};

export function decodeHtmlEntities(input: string): string {
  if (!input || !input.includes('&')) return input;
  return input
    .replace(/&#(\d+);/g, (_m, dec) => {
      const code = Number(dec);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex) => {
      const code = parseInt(hex, 16);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&([a-zA-Z][a-zA-Z0-9]{1,15});/g, (full, name: string) => {
      return NAMED_HTML_ENTITIES[name] ?? NAMED_HTML_ENTITIES[name.toLowerCase()] ?? full;
    });
}

function measureLeadingIndentCols(raw: string): { cols: number; bytePos: number; isBlank: boolean } {
  let cols = 0;
  let i = 0;
  while (i < raw.length) {
    const ch = raw.charCodeAt(i);
    if (ch === 32 /* ' ' */) {
      cols++;
      i++;
    } else if (ch === 9 /* '\t' */) {
      cols += 4 - (cols % 4);
      i++;
    } else {
      break;
    }
  }
  return { cols, bytePos: i, isBlank: i >= raw.length };
}

function detectListItemContentCol(raw: string, leadCols: number, leadPos: number): number {
  if (leadCols > 3 || leadPos >= raw.length) return 0;
  const c = raw.charCodeAt(leadPos);
  let markerEnd = -1;
  let markerWidth = 0;
  if (c === 45 /* '-' */ || c === 42 /* '*' */ || c === 43 /* '+' */) {
    markerEnd = leadPos + 1;
    markerWidth = 1;
  } else if (c >= 48 && c <= 57) {
    let d = leadPos + 1;
    while (d < raw.length && d - leadPos < 9 && raw.charCodeAt(d) >= 48 && raw.charCodeAt(d) <= 57) d++;
    if (d < raw.length && (raw.charCodeAt(d) === 46 /* '.' */ || raw.charCodeAt(d) === 41 /* ')' */)) {
      markerEnd = d + 1;
      markerWidth = markerEnd - leadPos;
    }
  }
  if (markerEnd < 0 || markerEnd >= raw.length) return 0;
  const after = raw.charCodeAt(markerEnd);
  if (after !== 32 && after !== 9) return 0;

  // Compute column where content starts after list marker + 1..4 spaces
  let col = leadCols + markerWidth;
  let p = markerEnd;
  while (p < raw.length) {
    const sc = raw.charCodeAt(p);
    if (sc === 32) {
      col++;
      p++;
    } else if (sc === 9) {
      col += 4 - (col % 4);
      p++;
    } else {
      break;
    }
  }
  if (p >= raw.length || col - (leadCols + markerWidth) > 4) {
    return leadCols + markerWidth + 1;
  }
  return col;
}

function scanContainerPrefixLinear(raw: string): { prefixLen: number; risky: boolean } {
  let i = 0;
  let risky = false;
  let col = 0;
  for (;;) {
    const runStartCol = col;
    while (i < raw.length && (raw.charCodeAt(i) === 32 || raw.charCodeAt(i) === 9)) {
      if (raw.charCodeAt(i) === 9) {
        col += 4 - (col % 4);
        risky = true;
      } else {
        col++;
      }
      i++;
    }
    if (col - runStartCol >= 4) risky = true;
    if (i >= raw.length) break;
    const c = raw.charCodeAt(i);
    if (c === 62 /* '>' */) {
      risky = true;
      i++;
      col++;
      continue;
    }
    if ((c === 45 || c === 42 || c === 43) && i + 1 < raw.length && (raw.charCodeAt(i + 1) === 32 || raw.charCodeAt(i + 1) === 9)) {
      risky = true;
      i++;
      col++;
      continue;
    }
    if (c >= 48 && c <= 57) {
      let j = i;
      while (j < raw.length && j - i < 9 && raw.charCodeAt(j) >= 48 && raw.charCodeAt(j) <= 57) j++;
      if (j < raw.length) {
        const d = raw.charCodeAt(j);
        if ((d === 46 || d === 41) && j + 1 < raw.length && (raw.charCodeAt(j + 1) === 32 || raw.charCodeAt(j + 1) === 9)) {
          risky = true;
          col += j + 1 - i;
          i = j + 1;
          continue;
        }
      }
    }
    break;
  }
  return { prefixLen: i, risky };
}

function cleanFenceInfoStringLinear(rawInfo: string): string {
  if (!rawInfo) return '';
  // Bound info string to 200 chars in O(1) so 64K-tab/bracket fence headers (`fh.6.mjs`) run in <0.1ms!
  const capped = rawInfo.length > 200 ? rawInfo.slice(0, 200) : rawInfo;
  // Strip `theme={...}` and `[[...]]` linearly before removing stray brackets/angles
  let s = capped;
  while (s.includes('theme={')) {
    const idx = s.indexOf('theme={');
    let wsStart = idx;
    while (wsStart > 0 && (s.charCodeAt(wsStart - 1) === 32 || s.charCodeAt(wsStart - 1) === 9)) wsStart--;
    const closeBrace = s.indexOf('}', idx + 7);
    s = closeBrace >= 0 ? s.slice(0, wsStart) + s.slice(closeBrace + 1) : s.slice(0, wsStart);
  }
  while (s.includes('[[')) {
    const idx = s.indexOf('[[');
    let wsStart = idx;
    while (wsStart > 0 && (s.charCodeAt(wsStart - 1) === 32 || s.charCodeAt(wsStart - 1) === 9)) wsStart--;
    const closeBrackets = s.indexOf(']]', idx + 2);
    s = closeBrackets >= 0 ? s.slice(0, wsStart) + s.slice(closeBrackets + 2) : s.slice(0, wsStart);
  }
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    // Strip `[`, `]`, `<`, `>` so `marked` never parses inline links or tags in fence info strings
    if (c === 91 || c === 93 || c === 60 || c === 62) continue;
    if (c === 9) {
      out += ' ';
      continue;
    }
    if (c < 32) continue;
    out += s[i]!;
  }
  out = out.replace(/(?:^|[ \t]+)twoslash(?=[ \t]+|$)/gi, '').trimEnd();
  // If truncation cut mid-token after huge whitespace (`'```js' + '\t'.repeat(65536) + 'x'`), collapse multi-space tail cleanly
  const firstWordMatch = /^([ \t]*[^\s`~]{1,64})(?:[ \t]{8,}.*)?$/.exec(out);
  if (firstWordMatch && out.length >= 100) {
    return firstWordMatch[1]!.trimEnd();
  }
  return out;
}

/**
 * Normalizes ambiguous indented, container-prefixed, Setext-adjacent, and EOF-unclosed code fences (`R6-H1` & `M9`)
 * so `splitMarkdownByCodeFences`, CommonMark (`micromark`), and `marked` always agree 100% on prose vs code boundaries.
 */
function hardenMarkdownFenceStructure(md: string): string {
  if (!md) return md;
  const hasFenceChars = md.includes('```') || md.includes('~~~');
  const hasBracketRef = md.includes('[');
  if (!hasFenceChars && !hasBracketRef) return md;

  const hasPotentialSetext = hasFenceChars && /(?:^|\n)[ ]{0,3}(?:=+|-+)[ \t]*(?:\r?\n|$)/.test(md);
  const lines = md.split('\n');
  const out: string[] = [];
  let inFence = false;
  let fenceChar = '';
  let fenceLen = 0;
  let fenceContainerIndent = 0;
  let activeListIndent = 0;
  let escapedRiskyFence: { ch: string; len: number; needBlockquote: boolean } | null = null;

  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    const cr = line.endsWith('\r') ? '\r' : '';
    const raw = cr ? line.slice(0, -1) : line;
    const { cols, bytePos, isBlank } = measureLeadingIndentCols(raw);

    if (inFence) {
      // Container dedent MUST be checked BEFORE closing fence so `- item\n  ```\n``` ` emits an explicit close for the list fence first!
      if (!isBlank && fenceContainerIndent > 0 && cols < fenceContainerIndent) {
        out.push(`${' '.repeat(fenceContainerIndent)}${fenceChar.repeat(fenceLen)}`);
        inFence = false;
        fenceChar = '';
        fenceLen = 0;
        fenceContainerIndent = 0;
        activeListIndent = 0;
        // Fall through and process `raw` as prose / new block!
      } else {
        const maxCloseIndent = fenceContainerIndent > 0 ? fenceContainerIndent + 3 : 3;
        if (cols <= maxCloseIndent && bytePos === cols) {
          let p = bytePos;
          const fcCode = fenceChar.charCodeAt(0);
          while (p < raw.length && raw.charCodeAt(p) === fcCode) p++;
          const runLen = p - bytePos;
          if (runLen >= fenceLen) {
            while (p < raw.length && (raw.charCodeAt(p) === 32 || raw.charCodeAt(p) === 9)) p++;
            if (p === raw.length) {
              out.push(`${' '.repeat(fenceContainerIndent)}${fenceChar.repeat(runLen)}${cr}`);
              inFence = false;
              fenceChar = '';
              fenceLen = 0;
              fenceContainerIndent = 0;
              continue;
            }
          }
        }
        out.push(line);
        continue;
      }
    }

    if (!isBlank && activeListIndent > 0 && cols < activeListIndent) {
      activeListIndent = 0;
      if (escapedRiskyFence && !escapedRiskyFence.needBlockquote) {
        escapedRiskyFence = null;
      }
    }

    const listCol = detectListItemContentCol(raw, cols, bytePos);
    if (listCol > 0) {
      activeListIndent = listCol;
      escapedRiskyFence = null;
    }

    const { prefixLen, risky } = scanContainerPrefixLinear(raw);
    const lineHasBlockquote = prefixLen > 0 && raw.slice(0, prefixLen).includes('>');
    if (escapedRiskyFence?.needBlockquote && !lineHasBlockquote) {
      escapedRiskyFence = null;
    }

    // If we previously escaped a container-prefixed fence opener (`- \`\`\` ` / `1. \`\`\` `) inside the current container,
    // also escape its matching closing fence line (`  \`\`\` `) so it cannot invert polarity and open a new fence!
    if (escapedRiskyFence && !escapedRiskyFence.needBlockquote && listCol === 0 && bytePos === cols && cols <= activeListIndent + 3) {
      const escCode = escapedRiskyFence.ch.charCodeAt(0);
      let p = bytePos;
      while (p < raw.length && raw.charCodeAt(p) === escCode) p++;
      const runLen = p - bytePos;
      if (runLen >= escapedRiskyFence.len) {
        while (p < raw.length && (raw.charCodeAt(p) === 32 || raw.charCodeAt(p) === 9)) p++;
        if (p === raw.length) {
          const escapedRun = `\\${escapedRiskyFence.ch}`.repeat(runLen);
          out.push(`${raw.slice(0, bytePos)}${escapedRun}${raw.slice(bytePos + runLen)}${cr}`);
          escapedRiskyFence = null;
          continue;
        }
      }
    }

    // Check valid fence opener (top-level `0..3` spaces when `activeListIndent === 0`, or list-item `activeListIndent .. activeListIndent + 3` spaces)
    const allowedMinCols = activeListIndent > 0 ? activeListIndent : 0;
    const allowedMaxCols = allowedMinCols + 3;
    if (listCol === 0 && cols >= allowedMinCols && cols <= allowedMaxCols && bytePos === cols && bytePos + 3 <= raw.length) {
      const c0 = raw.charCodeAt(bytePos);
      if (c0 === 96 /* '`' */ || c0 === 126 /* '~' */) {
        let fEnd = bytePos + 1;
        while (fEnd < raw.length && raw.charCodeAt(fEnd) === c0) fEnd++;
        const fLen = fEnd - bytePos;
        if (fLen >= 3) {
          const infoRaw = raw.slice(fEnd);
          if (!(c0 === 96 && infoRaw.includes('`'))) {
            // Prevent `marked4` Setext `lheading` (`para\n```\n<img...>\n===`) from crossing into a col-0 fence
            if (hasPotentialSetext && activeListIndent === 0 && out.length > 0 && out[out.length - 1]!.trim() !== '') {
              out.push('');
            }
            inFence = true;
            fenceChar = c0 === 96 ? '`' : '~';
            fenceLen = fLen;
            // Normalize top-level `1..3` space fences to col-0 so dedented lines inside top-level fences never cause desync
            fenceContainerIndent = activeListIndent > 0 ? activeListIndent : 0;
            const cleanInfo = cleanFenceInfoStringLinear(infoRaw);
            out.push(`${' '.repeat(fenceContainerIndent)}${fenceChar.repeat(fLen)}${cleanInfo}${cr}`);
            continue;
          }
        }
      }
    }

    // Escape container-prefixed or tab/4-space fence openers (`- ``` `, `1. ~~~`, `> ``` `, `\t``` `, `    ``` `)
    if (prefixLen > 0 && risky && prefixLen + 3 <= raw.length) {
      const c0 = raw.charCodeAt(prefixLen);
      if ((c0 === 96 || c0 === 126) && raw.charCodeAt(prefixLen + 1) === c0 && raw.charCodeAt(prefixLen + 2) === c0) {
        let fEnd = prefixLen + 3;
        while (fEnd < raw.length && raw.charCodeAt(fEnd) === c0) fEnd++;
        const fLen = fEnd - prefixLen;
        const tailAfterFence = raw.slice(fEnd);
        // Backtick runs with another backtick on the same line (`- ``` x ``` `) are inline code spans in CommonMark/marked, NEVER fences!
        if (!(c0 === 96 && tailAfterFence.includes('`'))) {
          const fChar = c0 === 96 ? '`' : '~';
          if (escapedRiskyFence && escapedRiskyFence.ch === fChar && fLen >= escapedRiskyFence.len && tailAfterFence.trim() === '') {
            escapedRiskyFence = null;
          } else if (listCol > 0 || lineHasBlockquote) {
            escapedRiskyFence = { ch: fChar, len: fLen, needBlockquote: lineHasBlockquote };
          }
          const escapedRun = `\\${fChar}`.repeat(fLen);
          out.push(`${raw.slice(0, prefixLen)}${escapedRun}${tailAfterFence}${cr}`);
          continue;
        }
      }
    }

    // Guard `marked` multi-line `[label\n~~~\n]: url` and empty-destination `[y]:\n``` ` swallowing fences (both top-level & in containers)
    const checkPos = prefixLen > 0 ? prefixLen : bytePos <= 3 ? bytePos : -1;
    if (checkPos >= 0 && checkPos < raw.length && raw.charCodeAt(checkPos) === 91 /* '[' */) {
      const tail = raw.slice(checkPos);
      let closeIdx = -1;
      for (let q = 1; q < tail.length; q++) {
        const qc = tail.charCodeAt(q);
        if (qc === 92 /* '\\' */) {
          q++;
          continue;
        }
        if (qc === 93 /* ']' */) {
          closeIdx = q;
          break;
        }
      }
      if (closeIdx < 0) {
        out.push(`${raw.slice(0, checkPos)}\\${tail}${cr}`);
        continue;
      }
      if (closeIdx + 1 < tail.length && tail.charCodeAt(closeIdx + 1) === 58 /* ':' */ && tail.slice(closeIdx + 2).trim() === '') {
        out.push(`${raw.slice(0, checkPos)}${tail.slice(0, closeIdx + 1)}\\${tail.slice(closeIdx + 1)}${cr}`);
        continue;
      }
    }

    out.push(line);
  }

  // Never leave a code fence unclosed at EOF (`marked4` renders unclosed single-line EOF fences as inline prose!)
  if (inFence) {
    out.push(`${' '.repeat(fenceContainerIndent)}${fenceChar.repeat(fenceLen)}`);
  }

  return out.join('\n');
}

/**
 * Splits Markdown into alternating `[prose, codeFence, prose, codeFence, ...]` segments (`idx % 2 === 1` is always a
 * fenced code block) while honoring CommonMark variable-length backtick (```` ``` ````, ```` ```` ````) and tilde
 * (`~~~`, `~~~~`) fences as well as list-container indentation boundaries (`R6-H1`).
 */
export function splitMarkdownByCodeFences(md: string): string[] {
  if (!md || (!md.includes('```') && !md.includes('~~~'))) {
    return [md];
  }
  const out: string[] = [];
  let inFence = false;
  let fenceChar = '';
  let fenceLen = 0;
  let fenceContainerIndent = 0;
  let activeListIndent = 0;
  let segStart = 0;
  let pos = 0;
  const len = md.length;

  while (pos < len) {
    const nl = md.indexOf('\n', pos);
    const nextPos = nl === -1 ? len : nl + 1;
    const lineRawEnd = nl === -1 ? len : nl > pos && md[nl - 1] === '\r' ? nl - 1 : nl;
    const rawLine = md.slice(pos, lineRawEnd);
    const { cols, bytePos, isBlank } = measureLeadingIndentCols(rawLine);

    if (inFence) {
      // Only a list-container fence (`fenceContainerIndent > 0`) closes on dedent (`cols < fenceContainerIndent`) in CommonMark!
      if (!isBlank && fenceContainerIndent > 0 && cols < fenceContainerIndent) {
        out.push(md.slice(segStart, pos));
        inFence = false;
        fenceChar = '';
        fenceLen = 0;
        fenceContainerIndent = 0;
        activeListIndent = 0;
        segStart = pos;
        continue;
      }
      const maxCloseCols = fenceContainerIndent > 0 ? fenceContainerIndent + 3 : 3;
      if (cols <= maxCloseCols && bytePos === cols) {
        const rest = rawLine.slice(bytePos);
        const closeMatch = /^(`{3,}|~{3,})[ \t]*$/.exec(rest);
        if (closeMatch && closeMatch[1]![0] === fenceChar && closeMatch[1]!.length >= fenceLen) {
          out.push(md.slice(segStart, lineRawEnd));
          inFence = false;
          fenceChar = '';
          fenceLen = 0;
          fenceContainerIndent = 0;
          segStart = lineRawEnd;
          pos = nextPos;
          continue;
        }
      }
      pos = nextPos;
      continue;
    }

    if (!isBlank && activeListIndent > 0 && cols < activeListIndent) {
      activeListIndent = 0;
    }
    const listCol = detectListItemContentCol(rawLine, cols, bytePos);
    if (listCol > 0) {
      activeListIndent = listCol;
    }

    const minOpenCols = activeListIndent > 0 ? activeListIndent : 0;
    const maxOpenCols = minOpenCols + 3;
    if (listCol === 0 && cols >= minOpenCols && cols <= maxOpenCols && bytePos === cols) {
      const rest = rawLine.slice(bytePos);
      const openMatch = /^(`{3,}|~{3,})(.*)$/.exec(rest);
      if (openMatch && !(openMatch[1]![0] === '`' && openMatch[2]!.includes('`'))) {
        out.push(md.slice(segStart, pos));
        inFence = true;
        fenceChar = openMatch[1]![0]!;
        fenceLen = openMatch[1]!.length;
        fenceContainerIndent = activeListIndent > 0 ? activeListIndent : 0;
        segStart = pos;
      }
    }
    pos = nextPos;
  }

  out.push(md.slice(segStart));
  return out;
}

export function makeSafeCodeFence(code: string, lang = '', preferTilde = false): string {
  const cleanCode = code.replace(/\r\n/g, '\n').trimEnd();
  const safeLang = lang.trim();
  if (preferTilde) {
    let maxTildes = 3;
    for (const m of cleanCode.matchAll(/~{3,}/g)) {
      if (m[0].length >= maxTildes) maxTildes = m[0].length + 1;
    }
    const fence = '~'.repeat(Math.max(4, maxTildes));
    return `${fence}${safeLang}\n${cleanCode}\n${fence}`;
  }
  let maxTicks = 2;
  for (const m of cleanCode.matchAll(/`{3,}/g)) {
    if (m[0].length > maxTicks) maxTicks = m[0].length;
  }
  const fence = '`'.repeat(maxTicks + 1);
  return `${fence}${safeLang}\n${cleanCode}\n${fence}`;
}

/** Decodes HTML entities in Markdown prose while leaving fenced code blocks untouched. */
export function decodeMarkdownEntities(md: string): string {
  if (!md || !md.includes('&')) return md;
  const parts = splitMarkdownByCodeFences(md);
  return parts.map((part, idx) => (idx % 2 === 1 ? part : decodeHtmlEntities(part))).join('');
}

function safeDecodeURIComponent(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** Normalizes Poppler / OCR PDF layout whitespace (column-alignment spaces and line-wrap hyphenations). */
export function cleanPdfMarkdown(md: string): string {
  if (!md) return md;
  const bounded = md.length > MAX_HTML_SCAN_CHARS ? md.slice(0, MAX_HTML_SCAN_CHARS) : md;
  const compoundPrefixes = new Set([
    'self',
    'multi',
    'cross',
    'non',
    'well',
    'high',
    'low',
    'long',
    'short',
    'full',
    'part',
    'real',
    'end',
    'one',
    'two',
    'three',
    'four',
    'five',
    'six',
    'ten',
    'all',
    'auto',
    'co',
    'over',
    'under',
    'hyper',
    'micro',
    'macro',
    'zero',
    'open',
    'closed',
    'right',
    'hand',
    'rule',
    'role',
    'user',
    'site',
    'host',
    'edge',
    'cloud',
  ]);
  const parts = splitMarkdownByCodeFences(bounded);
  return parts
    .map((part, idx) => {
      if (idx % 2 === 1) return part;
      const dehyphenated =
        part.includes('-\n') || part.includes('-\r\n')
          ? part.replace(/(?<![A-Za-z0-9])([A-Za-z0-9]{1,64})-\r?\n[ \t]{0,32}([A-Za-z]{1,64})/g, (_m, left: string, right: string) => {
              if (/\d$/.test(left) || /^[A-Z]/.test(right) || compoundPrefixes.has(left.toLowerCase())) {
                return `${left}-${right}`;
              }
              return `${left}${right}`;
            })
          : part;
      return dehyphenated
        .split('\n')
        .map((line) => {
          const trimmed = line.trimStart();
          if (trimmed.startsWith('|')) return line.trimEnd();
          return line.replace(/[ \t]{2,}/g, ' ').trim();
        })
        .join('\n')
        .replace(/\n{3,}/g, '\n\n');
    })
    .join('')
    .trim();
}

const URL_ONLY_TAG_ATTRS = new Set(['href', 'src', 'srcset', 'data-src', 'data-srcset', 'action', 'poster']);

function unescapeUrlAttrAmpOnly(raw: string): string {
  return raw.includes('&') ? raw.replace(/&(?:amp|#0*38|#x0*26);/gi, '&') : raw;
}

function parseTagAttrs(tag: string): Record<string, string> {
  if (tag.length > 65_536) tag = tag.slice(0, 65_536);
  const attrs: Record<string, string> = {};
  const re = /(?<![a-zA-Z0-9_:-])([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(tag)) !== null) {
    const key = m[1]!.toLowerCase();
    if (!(key in attrs)) {
      const val = m[2] ?? m[3] ?? m[4] ?? '';
      attrs[key] = URL_ONLY_TAG_ATTRS.has(key) ? unescapeUrlAttrAmpOnly(val) : decodeHtmlEntities(val);
    }
  }
  return attrs;
}

function formatInlineCodeSpan(raw: string): string {
  const text = raw.replace(/\s*\r?\n\s*/g, ' ').trim();
  if (!text) return '';
  if (!text.includes('`')) return `\`${text}\``;
  let maxRun = 1;
  for (const m of text.matchAll(/`+/g)) {
    if (m[0].length > maxRun) maxRun = m[0].length;
  }
  const fence = '`'.repeat(maxRun + 1);
  return `${fence} ${text} ${fence}`;
}

function resolveHttpsHref(rawHref: string | undefined, baseUrl?: string, preserveHash = false): string | undefined {
  if (!rawHref) return undefined;
  const trimmed = rawHref.trim();
  if (
    !trimmed ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('javascript:') ||
    trimmed.startsWith('mailto:') ||
    trimmed.startsWith('tel:') ||
    trimmed.startsWith('data:')
  ) {
    return undefined;
  }
  try {
    const u = baseUrl ? new URL(trimmed, baseUrl) : new URL(trimmed);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return undefined;
    if (!preserveHash || /[\s<>()]/.test(u.hash)) {
      u.hash = '';
    }
    return u.toString();
  } catch {
    return undefined;
  }
}

function collapseTagBoundaryPunctuation(s: string): string {
  return s
    .replace(/(?<!\[) +([,.;:!?)\]}])(?=\s|$|[,.;:!?)\]}])/g, '$1')
    .replace(/ +([’'](?:s|t|re|ve|ll|d|m)\b)/gi, '$1')
    .replace(/\( +(?=[^\s)])/g, '(')
    .replace(/\[\s+(\d{1,4})\s*\]/g, '[$1]');
}

function cleanInlineHtml(fragment: string): string {
  const stripped = replaceHtmlTagsQuoteAwareLinear(fragment, (t) => (!t.isClosing && t.tagNameLower === 'wbr' ? '' : ' '));
  return collapseTagBoundaryPunctuation(
    decodeHtmlEntities(stripped)
      .replace(/\s+/g, ' ')
      .trim(),
  );
}

const CODE_LANG_ALIASES: Record<string, string> = {
  javascript: 'js',
  mjs: 'js',
  cjs: 'js',
  typescript: 'ts',
  py: 'python',
  py3: 'python',
  python3: 'python',
  pycon: 'python',
  pycon3: 'python',
  default: 'python',
  rs: 'rust',
  golang: 'go',
  sh: 'bash',
  shell: 'bash',
  'shell-session': 'bash',
  zsh: 'bash',
  console: 'bash',
  terminal: 'bash',
  doscon: 'cmd',
  objc: 'objectivec',
  yml: 'yaml',
  md: 'markdown',
  cs: 'csharp',
  'c++': 'cpp',
  plaintext: '',
  plain: '',
  text: '',
  txt: '',
  none: '',
  nohighlight: '',
  output: '',
};

function normalizeFenceLang(raw: string | undefined): string {
  if (!raw) return '';
  const clean = raw.trim().toLowerCase().replace(/^language-|^lang-/, '');
  if (!clean || !/^[a-z0-9_+#-]{1,20}$/.test(clean)) return '';
  if (clean in CODE_LANG_ALIASES) return CODE_LANG_ALIASES[clean]!;
  return clean;
}

function inferCodeFenceLang(preAttrStr: string, codeAttrStr = ''): string {
  const preAttrs = parseTagAttrs(preAttrStr);
  const codeAttrs = parseTagAttrs(codeAttrStr);
  const direct =
    codeAttrs['data-language'] ??
    codeAttrs['data-lang'] ??
    codeAttrs['data-wrapper-lang'] ??
    preAttrs['data-language'] ??
    preAttrs['data-lang'] ??
    preAttrs['data-wrapper-lang'] ??
    codeAttrs.lang ??
    preAttrs.lang;
  const directNorm = normalizeFenceLang(direct);
  if (directNorm) return directNorm;

  const classes = `${(codeAttrs.class ?? '').slice(0, 512)} ${(preAttrs.class ?? '').slice(0, 512)}`;
  const m =
    /\b(?:highlight-source-|language-|lang-|highlight-|syntax-|code-|brush:\s*)([a-zA-Z0-9_+#-]+)/i.exec(classes) ??
    /\b([a-zA-Z0-9_+#-]+)-(?:code|snippet)\b/i.exec(classes) ??
    /\bhljs\s+([a-zA-Z0-9_+#-]+)\b/i.exec(classes);
  if (m?.[1]) {
    const norm = normalizeFenceLang(m[1]);
    if (norm) return norm;
  }
  if (/\brust(?:-example-rendered)?\b/i.test(classes)) return 'rust';
  if (/\bDocumentation-exampleCode\b/.test(classes)) return 'go';
  return '';
}

function cleanHeadingPermalinks(headingText: string): string {
  return headingText
    .replace(/^§\s+/, '')
    .replace(/\s+¶\s+(added in\s+\S+)$/i, ' ($1)')
    .replace(/\s+[§¶#]+$/, '')
    .trim();
}

const PII_EMAIL_RE =
  /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,10}[A-Za-z]{2,24}\b/g;
const PII_SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const PII_PHONE_RE =
  /(?<![0-9A-Za-z-])(?:\+?1[-.\s]?)?(?:\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}|\d{3}[-.\s]\d{3}[-.\s]\d{4})\b/g;

export function redactPiiText(text: string): string {
  if (!text) return text;
  let out = text;
  if (out.includes('@')) {
    out = out.replace(PII_EMAIL_RE, '[REDACTED_EMAIL]');
  }
  if (/\d{3}/.test(out)) {
    if (out.includes('-')) {
      out = out.replace(PII_SSN_RE, '[REDACTED_SSN]');
    }
    out = out.replace(PII_PHONE_RE, '[REDACTED_PHONE]');
  }
  return out;
}

const VOID_HTML_TAGS = new Set([
  'area',
  'base',
  'br',
  'col',
  'embed',
  'hr',
  'img',
  'input',
  'link',
  'meta',
  'param',
  'source',
  'track',
  'wbr',
]);

const ALWAYS_HIDDEN_OR_CHROME_CLASSES = new Set([
  'sr-only',
  'visually-hidden',
  'screenreader-only',
  'hideme',
  'unitheader-banner',
  'js-comment-minimize',
  'js-comment-hide-button',
  'js-suggestion-button-placeholder',
  'js-clipboard-copy',
  'zeroclipboard-container',
  'doc-anchor',
  'documentation-idlink',
  'headerlink',
  'sphinxsidebar',
  'katex-html',
  'mwe-math-fallback-image-inline',
  'mwe-math-fallback-image-display',
  'lnt',
  'line-numbers-rows',
  'line-numbers-wrapper',
  'hljs-ln-numbers',
  'swiper-slide-duplicate',
  'slick-cloned',
  'splide__slide--clone',
  'flickity-cloned',
  'glide__slide--clone',
  'owl-cloned',
]);

/** Extracts the inner HTML of a balanced `<div|section ... role="main">` landmark in guaranteed O(N) time (`H1`). */
function extractBalancedRoleMainHtml(html: string): string | null {
  let targetTag = '';
  let contentStart = -1;
  let depth = 0;
  let matchedInner: string | null = null;

  scanHtmlTagsLinear(
    html,
    (tag) => {
      if (tag.tagNameLower !== 'div' && tag.tagNameLower !== 'section') return;
      if (!targetTag) {
        if (tag.isClosing || tag.isSelfClosing) return;
        const attrs = parseTagAttrs(tag.attrs);
        if ((attrs.role ?? '').trim().toLowerCase() === 'main') {
          targetTag = tag.tagNameLower;
          contentStart = tag.end;
          depth = 1;
        }
        return undefined;
      }
      if (tag.tagNameLower !== targetTag) return;
      if (tag.isClosing) {
        depth--;
        if (depth === 0) {
          matchedInner = html.slice(contentStart, tag.index);
          return false;
        }
      } else if (!tag.isSelfClosing) {
        depth++;
      }
      return undefined;
    },
    MAX_HTML_SCAN_CHARS,
    false,
  );

  return matchedInner;
}

function shouldStripSubtreeOpenTag(tagLower: string, attrStr: string): boolean {
  if (!attrStr || tagLower === 'html' || tagLower === 'body' || tagLower === 'main' || tagLower === 'article') {
    return false;
  }
  const strippedQuotes = attrStr.replace(/"[^"]*"|'[^']*'/g, '""');
  if (/\bhidden(?:\s*=\s*(?:""|hidden|true))?(?=\s|$)/i.test(strippedQuotes)) {
    const hm = /\bhidden\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrStr);
    const hv = (hm?.[1] ?? hm?.[2] ?? hm?.[3] ?? '').trim().toLowerCase();
    if (hv !== 'false' && hv !== '0') return true;
  }
  if (/\bstyle\s*=/i.test(strippedQuotes) && !/\b(?:mwe-math|katex-mathml|mjx-assistive)\b/i.test(attrStr)) {
    const sm = /\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(attrStr);
    const styleVal = sm?.[1] ?? sm?.[2] ?? '';
    if (
      styleVal &&
      /(?:^|;)\s*(?:display\s*:\s*none\b|visibility\s*:\s*hidden\b|opacity\s*:\s*0(?:\.0+)?(?=\s*(?:;|$))|font-size\s*:\s*0(?:px|em|rem|%|pt)?(?=\s*(?:;|$)))/i.test(
        styleVal,
      )
    ) {
      return true;
    }
  }
  if (
    /\brole\s*=/i.test(strippedQuotes) &&
    /\brole\s*=\s*(?:"(?:navigation|search|banner|contentinfo|dialog|alertdialog|menu|menubar|toolbar)"|'(?:navigation|search|banner|contentinfo|dialog|alertdialog|menu|menubar|toolbar)')/i.test(
      attrStr,
    )
  ) {
    return true;
  }
  if (
    (tagLower === 'span' || tagLower === 'i') &&
    /\baria-hidden\s*=\s*(?:"true"|'true')/i.test(attrStr)
  ) {
    return true;
  }
  if (/\bclass\s*=/i.test(strippedQuotes)) {
    const cm = /\bclass\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrStr);
    const classVal = (cm?.[1] ?? cm?.[2] ?? cm?.[3] ?? '').trim();
    if (classVal) {
      const tokens = classVal.toLowerCase().split(/\s+/);
      for (const tok of tokens) {
        if (ALWAYS_HIDDEN_OR_CHROME_CLASSES.has(tok)) return true;
      }
      if (
        (tokens.includes('d-none') || tokens.includes('tw-hidden')) &&
        !/\b(?:d-(?:sm|md|lg|xl|xxl)-(?:block|flex|inline|inline-block|grid|table)|(?:sm|md|lg|xl|2xl):(?:block|flex|inline|inline-block|grid|table))\b/i.test(
          classVal,
        )
      ) {
        return true;
      }
    }
  }
  return false;
}

/** O(N) quote-aware balanced tag scanner that removes hidden (`.d-none`, `[hidden]`, `display:none`) and WAI-ARIA nav/chrome subtrees (`H1`). */
function stripHiddenAndChromeSubtrees(html: string): string {
  const src = html.length > MAX_HTML_SCAN_CHARS ? html.slice(0, MAX_HTML_SCAN_CHARS) : html;
  const chunks: string[] = [];
  let lastKeepIdx = 0;
  let skipTag = '';
  let skipDepth = 0;
  let skipStartIdx = 0;

  scanHtmlTagsLinear(
    src,
    (tag) => {
      const tagLower = tag.tagNameLower;
      const isClosing = tag.isClosing;
      const isSelfClosing = !isClosing && (VOID_HTML_TAGS.has(tagLower) || tag.isSelfClosing);

      if (skipDepth > 0) {
        if (tagLower === skipTag) {
          if (isClosing) {
            skipDepth--;
            if (skipDepth === 0) {
              lastKeepIdx = tag.end;
            }
          } else if (!isSelfClosing) {
            skipDepth++;
          }
        }
        return;
      }

      if (!isClosing && shouldStripSubtreeOpenTag(tagLower, tag.attrs)) {
        chunks.push(src.slice(lastKeepIdx, tag.index));
        if (isSelfClosing) {
          lastKeepIdx = tag.end;
        } else {
          skipTag = tagLower;
          skipDepth = 1;
          skipStartIdx = tag.index;
        }
      }
    },
    MAX_HTML_SCAN_CHARS,
    false,
  );

  if (chunks.length === 0 && skipDepth === 0) return src;
  if (skipDepth > 0) {
    // Unclosed malformed tag: preserve tail from `skipStartIdx` so broken HTML never truncates prose.
    chunks.push(src.slice(skipStartIdx));
  } else if (lastKeepIdx < src.length) {
    chunks.push(src.slice(lastKeepIdx));
  }
  return chunks.join('');
}

function isPlaceholderMetaValue(raw: string | undefined): boolean {
  if (!raw) return true;
  const s = raw.trim();
  if (!s) return true;
  if (/^(?:loading(?:\.{0,3})?|untitled|please wait(?:\.{0,3})?)$/i.test(s)) return true;
  if (/[{}]/.test(s) || /^#[a-zA-Z_$][\w$]*(?:\.[\w$]+)+$/.test(s)) return true;
  return !/[\p{L}\p{N}]/u.test(s);
}

function cleanAuthorMetaString(raw: string): string {
  return raw
    .replace(/^by\s+/i, '')
    .replace(/\(?\s*https?:\/\/\S+\s*\)?/gi, '')
    .replace(/,?\s+and\s+/gi, ', ')
    .replace(/\s*[-–—|]\s*$/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function countTextWords(text: string): number {
  const trimmed = text.trim();
  if (!trimmed) return 0;
  return (trimmed.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
}

/**
 * Selects the highest-resolution candidate URL from an HTML `srcset` attribute (`1200w`, `2x`, etc.),
 * preserving commas inside CDN transform paths (e.g. Cloudinary `w_800,q_auto`) that lack post-comma whitespace.
 */
export function extractLargestUrlFromSrcset(srcset: string | undefined): string | undefined {
  if (!srcset || !srcset.trim()) return undefined;
  let bestUrl: string | undefined;
  let bestScore = -1;
  const entryRe = /(?:^|,\s+)(\S+)(?:\s+(\d+(?:\.\d+)?)([wx]))?(?=\s*(?:,\s+\S|$))/g;
  let m: RegExpExecArray | null;
  while ((m = entryRe.exec(srcset.trim())) !== null) {
    const candidate = m[1]!.replace(/,+$/, '').trim();
    if (!candidate || candidate.startsWith('data:')) continue;
    const num = m[2] ? parseFloat(m[2]) : 1;
    const unit = m[3]?.toLowerCase();
    const score = unit === 'w' ? num : unit === 'x' ? num * 1_000 : 100;
    if (score >= bestScore) {
      bestScore = score;
      bestUrl = candidate;
    }
  }
  return bestUrl;
}

function flattenJsonLdEntities(rawHtml: string): Array<Record<string, unknown>> {
  const entities: Array<Record<string, unknown>> = [];
  const visit = (node: unknown, depth: number) => {
    if (!node || depth > 6) return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item, depth + 1);
      return;
    }
    if (typeof node === 'object') {
      const obj = node as Record<string, unknown>;
      entities.push(obj);
      if (Array.isArray(obj['@graph'])) {
        visit(obj['@graph'], depth + 1);
      }
    }
  };
  if (rawHtml.includes('ld+json')) {
    replaceHtmlTagBlocksLinear(
      rawHtml,
      'script',
      (_full, attrStr, inner) => {
        if (/\btype\s*=\s*["']application\/ld\+json["']/i.test(attrStr)) {
          try {
            visit(JSON.parse(inner.trim()), 0);
          } catch {
            // ignore malformed JSON-LD blocks
          }
        }
        return '';
      },
      MAX_HTML_SCAN_CHARS,
    );
  }
  return entities;
}

function extractSchemaMetadataAndBody(entities: Array<Record<string, unknown>>): {
  author?: string;
  publishedTime?: string;
  modifiedTime?: string;
  siteName?: string;
  articleBody?: string;
} {
  let author: string | undefined;
  let publishedTime: string | undefined;
  let modifiedTime: string | undefined;
  let siteName: string | undefined;
  let articleBody: string | undefined;

  const extractAuthorNames = (rawAuthor: unknown): string[] => {
    if (!rawAuthor) return [];
    if (typeof rawAuthor === 'string') {
      const c = cleanAuthorMetaString(rawAuthor);
      return c && !isPlaceholderMetaValue(c) ? [c] : [];
    }
    if (Array.isArray(rawAuthor)) {
      return rawAuthor.flatMap((a) => extractAuthorNames(a));
    }
    if (typeof rawAuthor === 'object') {
      const name = (rawAuthor as { name?: unknown }).name;
      if (typeof name === 'string') {
        const c = cleanAuthorMetaString(name);
        return c && !isPlaceholderMetaValue(c) ? [c] : [];
      }
    }
    return [];
  };

  for (const ent of entities) {
    if (!author && ent.author) {
      const names = [...new Set(extractAuthorNames(ent.author))].slice(0, 8);
      if (names.length > 0) author = names.join(', ');
    }
    if (!publishedTime && typeof ent.datePublished === 'string' && !isPlaceholderMetaValue(ent.datePublished)) {
      publishedTime = ent.datePublished.trim();
    }
    if (!modifiedTime && typeof ent.dateModified === 'string' && !isPlaceholderMetaValue(ent.dateModified)) {
      modifiedTime = ent.dateModified.trim();
    }
    if (!siteName) {
      const pub = ent.publisher as { name?: unknown } | undefined;
      const cand =
        (typeof pub?.name === 'string' ? pub.name : undefined) ??
        (String(ent['@type'] ?? '').toLowerCase() === 'website' && typeof ent.name === 'string' ? ent.name : undefined);
      if (cand && !isPlaceholderMetaValue(cand)) siteName = cand.trim();
    }
    const bodyCand =
      typeof ent.articleBody === 'string'
        ? ent.articleBody.trim()
        : typeof ent.text === 'string' && /article|posting|question|answer/i.test(String(ent['@type'] ?? ''))
          ? ent.text.trim()
          : '';
    if (bodyCand && (!articleBody || bodyCand.length > articleBody.length)) {
      articleBody = bodyCand;
    }
  }
  return {
    ...(author ? { author } : {}),
    ...(publishedTime ? { publishedTime } : {}),
    ...(modifiedTime ? { modifiedTime } : {}),
    ...(siteName ? { siteName } : {}),
    ...(articleBody ? { articleBody } : {}),
  };
}

interface ParsedSimpleSelector {
  tag?: string;
  id?: string;
  cls?: string;
}

function parseSimpleSelectorList(rawSelectors: readonly string[] | undefined): ParsedSimpleSelector[] {
  if (!rawSelectors || rawSelectors.length === 0) return [];
  const out: ParsedSimpleSelector[] = [];
  for (const raw of rawSelectors.slice(0, 25)) {
    const s = raw.trim();
    if (!s || s.length > 80) continue;
    const m = /^([a-zA-Z][a-zA-Z0-9:-]*)?(?:#([a-zA-Z0-9_:-]+))?(?:\.([a-zA-Z0-9_:-]+))?$/.exec(s);
    if (!m || (!m[1] && !m[2] && !m[3])) continue;
    out.push({
      ...(m[1] ? { tag: m[1].toLowerCase() } : {}),
      ...(m[2] ? { id: m[2].toLowerCase() } : {}),
      ...(m[3] ? { cls: m[3].toLowerCase() } : {}),
    });
  }
  return out;
}

function tagMatchesSimpleSelectors(tagLower: string, attrStr: string, selectors: readonly ParsedSimpleSelector[]): boolean {
  if (selectors.length === 0) return false;
  let parsedAttrs: Record<string, string> | undefined;
  let classTokens: string[] | undefined;
  for (const sel of selectors) {
    if (sel.tag && sel.tag !== tagLower) continue;
    if (sel.id || sel.cls) {
      parsedAttrs ??= parseTagAttrs(attrStr);
      if (sel.id && (parsedAttrs.id ?? '').trim().toLowerCase() !== sel.id) continue;
      if (sel.cls) {
        classTokens ??= (parsedAttrs.class ?? '')
          .toLowerCase()
          .split(/\s+/)
          .filter(Boolean);
        if (!classTokens.includes(sel.cls)) continue;
      }
    }
    return true;
  }
  return false;
}

/** Applies Firecrawl-compatible `includeTags` and `excludeTags` (`tag`, `#id`, `.class`) using O(N) balanced subtree scanning (`H1`). */
function applyIncludeAndExcludeTagSelectors(
  html: string,
  includeTags?: readonly string[],
  excludeTags?: readonly string[],
): string {
  let out = html.length > MAX_HTML_SCAN_CHARS ? html.slice(0, MAX_HTML_SCAN_CHARS) : html;
  const parsedInclude = parseSimpleSelectorList(includeTags);
  if (parsedInclude.length > 0) {
    const kept: string[] = [];
    let matchTag = '';
    let matchDepth = 0;
    let matchStart = 0;
    const src = out;
    scanHtmlTagsLinear(
      src,
      (tag) => {
        const tagLower = tag.tagNameLower;
        const isClosing = tag.isClosing;
        const isSelfClosing = !isClosing && (VOID_HTML_TAGS.has(tagLower) || tag.isSelfClosing);
        if (matchDepth > 0) {
          if (tagLower === matchTag) {
            if (isClosing) {
              matchDepth--;
              if (matchDepth === 0) {
                kept.push(src.slice(matchStart, tag.end));
              }
            } else if (!isSelfClosing) {
              matchDepth++;
            }
          }
          return;
        }
        if (!isClosing && tagMatchesSimpleSelectors(tagLower, tag.attrs, parsedInclude)) {
          if (isSelfClosing) {
            kept.push(tag.rawTag);
          } else {
            matchTag = tagLower;
            matchDepth = 1;
            matchStart = tag.index;
          }
        }
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );
    if (matchDepth > 0) kept.push(src.slice(matchStart));
    if (kept.length > 0) {
      out = kept.join('\n\n');
    }
  }

  const parsedExclude = parseSimpleSelectorList(excludeTags);
  if (parsedExclude.length > 0) {
    const chunks: string[] = [];
    let lastKeepIdx = 0;
    let skipTag = '';
    let skipDepth = 0;
    let skipStartIdx = 0;
    const src = out;
    scanHtmlTagsLinear(
      src,
      (tag) => {
        const tagLower = tag.tagNameLower;
        const isClosing = tag.isClosing;
        const isSelfClosing = !isClosing && (VOID_HTML_TAGS.has(tagLower) || tag.isSelfClosing);
        if (skipDepth > 0) {
          if (tagLower === skipTag) {
            if (isClosing) {
              skipDepth--;
              if (skipDepth === 0) lastKeepIdx = tag.end;
            } else if (!isSelfClosing) {
              skipDepth++;
            }
          }
          return;
        }
        if (!isClosing && tagMatchesSimpleSelectors(tagLower, tag.attrs, parsedExclude)) {
          chunks.push(src.slice(lastKeepIdx, tag.index));
          if (isSelfClosing) {
            lastKeepIdx = tag.end;
          } else {
            skipTag = tagLower;
            skipDepth = 1;
            skipStartIdx = tag.index;
          }
        }
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );
    if (chunks.length > 0 || skipDepth > 0) {
      if (skipDepth > 0) chunks.push(src.slice(skipStartIdx));
      else if (lastKeepIdx < src.length) chunks.push(src.slice(lastKeepIdx));
      out = chunks.join('');
    }
  }
  return out;
}

function normalizeLatexSource(rawTex: string): string {
  let tex = decodeHtmlEntities(rawTex).trim();
  const wikiWrap = /^\{\\displaystyle\s+([\s\S]*)\}$/.exec(tex);
  if (wikiWrap?.[1]) tex = wikiWrap[1].trim();
  return tex;
}

function mapCalloutTypeToGfm(rawType: string): string {
  const t = rawType.toLowerCase();
  if (t === 'tip' || t === 'hint' || t === 'success') return 'TIP';
  if (t === 'important') return 'IMPORTANT';
  if (t === 'warning' || t === 'warn' || t === 'attention') return 'WARNING';
  if (t === 'caution' || t === 'danger' || t === 'error' || t === 'bug' || t === 'failure') return 'CAUTION';
  return 'NOTE';
}

interface SubstackPreloadExtracted {
  title?: string;
  subtitle?: string;
  author?: string;
  publishedTime?: string;
  bodyHtml?: string;
}

function extractSubstackPreloadData(rawHtml: string): SubstackPreloadExtracted | null {
  if (!rawHtml.includes('preloads-json') && !(rawHtml.includes('window._preloads') && rawHtml.includes('body_html'))) {
    return null;
  }
  const readFromData = (data: unknown): SubstackPreloadExtracted | null => {
    if (!data || typeof data !== 'object') return null;
    const d = data as Record<string, unknown>;
    const feedData = d.feedData as Record<string, unknown> | undefined;
    const initialPost = feedData?.initialPost as Record<string, unknown> | undefined;
    const post = (d.post ?? initialPost?.post) as Record<string, unknown> | undefined;
    if (!post || typeof post !== 'object') return null;
    const bodyHtml = typeof post.body_html === 'string' && post.body_html.trim() ? post.body_html : undefined;
    const title = typeof post.title === 'string' && post.title.trim() ? post.title.trim() : undefined;
    const subtitle = typeof post.subtitle === 'string' && post.subtitle.trim() ? post.subtitle.trim() : undefined;
    const publishedTime = typeof post.post_date === 'string' && post.post_date.trim() ? post.post_date.trim() : undefined;
    const bylines = Array.isArray(post.publishedBylines) ? (post.publishedBylines as Array<Record<string, unknown>>) : [];
    const author = typeof bylines[0]?.name === 'string' && bylines[0].name.trim() ? bylines[0].name.trim() : undefined;
    if (!bodyHtml && !title) return null;
    return {
      ...(title ? { title } : {}),
      ...(subtitle ? { subtitle } : {}),
      ...(author ? { author } : {}),
      ...(publishedTime ? { publishedTime } : {}),
      ...(bodyHtml ? { bodyHtml } : {}),
    };
  };

  if (rawHtml.includes('preloads-json')) {
    let preloadJsonStr = '';
    replaceHtmlTagBlocksLinear(
      rawHtml,
      'script',
      (_full, attrStr, inner) => {
        if (!preloadJsonStr && (parseTagAttrs(attrStr).id ?? '').toLowerCase() === 'preloads-json') {
          preloadJsonStr = inner;
        }
        return '';
      },
      MAX_HTML_SCAN_CHARS,
    );
    if (preloadJsonStr) {
      try {
        const res = readFromData(JSON.parse(preloadJsonStr));
        if (res) return res;
      } catch {
        // fall through
      }
    }
  }

  const markerIdx = rawHtml.indexOf('window._preloads');
  if (markerIdx !== -1) {
    const parsePrefix = 'JSON.parse("';
    const parseIdx = rawHtml.indexOf(parsePrefix, markerIdx);
    if (parseIdx !== -1 && parseIdx - markerIdx < 200) {
      const start = parseIdx + parsePrefix.length;
      let i = start;
      const maxEnd = Math.min(rawHtml.length, start + 1_500_000);
      while (i < maxEnd) {
        const ch = rawHtml[i];
        if (ch === '\\') i += 2;
        else if (ch === '"') break;
        else i++;
      }
      if (i < maxEnd) {
        try {
          const jsonStr = JSON.parse(`"${rawHtml.slice(start, i)}"`) as string;
          const res = readFromData(JSON.parse(jsonStr));
          if (res) return res;
        } catch {
          // ignore malformed _preloads payload
        }
      }
    }
  }
  return null;
}

function hasClassToken(attrStr: string, tokenLower: string): boolean {
  const cls = (parseTagAttrs(attrStr).class ?? '').toLowerCase();
  if (!cls) return false;
  return cls.split(/\s+/).includes(tokenLower);
}

function hnFragmentToMarkdown(fragHtml: string, baseUrl: string): string {
  const codeBlocks: string[] = [];
  let s = fragHtml.includes('reply')
    ? replacePairedHtmlElementsLinear(fragHtml, ['div'], (full, _t, attrStr) =>
        hasClassToken(attrStr, 'reply') ? '' : full,
      )
    : fragHtml;
  s = replacePairedHtmlElementsLinear(s, ['pre'], (_full, _t, _attrs, inner) => {
    const clean = decodeHtmlEntities(stripHtmlTagsQuoteAwareLinear(inner, '')).trimEnd();
    const idx = codeBlocks.push(`\n\n${makeSafeCodeFence(clean)}\n\n`) - 1;
    return `\u0000HNCODE${idx}\u0000`;
  });
  s = replacePairedHtmlElementsLinear(s, ['code'], (_full, _t, _attrs, c) => {
    const span = formatInlineCodeSpan(cleanInlineHtml(c));
    if (!span) return '';
    const idx = codeBlocks.push(span) - 1;
    return `\u0000HNCODE${idx}\u0000`;
  });
  s = replacePairedHtmlElementsLinear(s, ['a'], (_full, _t, attrStr, inner) => {
    const attrs = parseTagAttrs(attrStr);
    const href = resolveHttpsHref(attrs.href, baseUrl, true);
    const label = cleanInlineHtml(inner);
    if (!label) return href ?? '';
    return href ? `[${label}](${href})` : label;
  });
  s = replacePairedHtmlElementsLinear(s, ['i', 'em'], (_full, _t, _attrs, inner) => {
    const t = cleanInlineHtml(inner);
    return t ? `*${t}*` : '';
  });
  s = replaceHtmlOpenTagsLinear(s, ['p', 'br'], (t) => (t.tagNameLower === 'p' ? '\n\n' : '\n'));
  s = stripHtmlTagsQuoteAwareLinear(s, '');

  s = decodeHtmlEntities(s)
    .split('\n')
    .map((l) => l.replace(/[ \t]{2,}/g, ' ').trim())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  return s.replace(/\u0000HNCODE(\d+)\u0000/g, (_m, idx: string) => codeBlocks[Number(idx)] ?? '');
}

function findFirstClassSubtreeLinear(html: string, tagNames: readonly string[], classTokenLower: string): { inner: string; endIdx: number } | null {
  const tagSet = new Set(tagNames);
  let matchTag = '';
  let depth = 0;
  let innerStart = -1;
  let result: { inner: string; endIdx: number } | null = null;

  scanHtmlTagsLinear(
    html,
    (tag) => {
      if (!tagSet.has(tag.tagNameLower)) return;
      if (!matchTag) {
        if (tag.isClosing || tag.isSelfClosing) return;
        if (hasClassToken(tag.attrs, classTokenLower)) {
          matchTag = tag.tagNameLower;
          depth = 1;
          innerStart = tag.end;
        }
        return undefined;
      }
      if (tag.tagNameLower !== matchTag) return;
      if (tag.isClosing) {
        depth--;
        if (depth === 0) {
          result = { inner: html.slice(innerStart, tag.index), endIdx: tag.end };
          return false;
        }
      } else if (!tag.isSelfClosing) {
        depth++;
      }
      return undefined;
    },
    MAX_HTML_SCAN_CHARS,
    false,
  );
  return result;
}

function findFirstAnchorInFragment(frag: string): { href?: string; text: string } | null {
  let found: { href?: string; text: string } | null = null;
  replacePairedHtmlElementsLinear(
    frag,
    ['a'],
    (_full, _t, attrStr, inner) => {
      if (!found) {
        const attrs = parseTagAttrs(attrStr);
        found = { ...(attrs.href ? { href: attrs.href } : {}), text: cleanInlineHtml(inner) };
      }
      return '';
    },
    { maxChars: 24_000, maxInnerChars: 4_000 },
  );
  return found;
}

function findHnAuthorInFragment(frag: string): string | undefined {
  let author: string | undefined;
  replacePairedHtmlElementsLinear(
    frag,
    ['a'],
    (_full, _t, attrStr, inner) => {
      if (author === undefined) {
        const attrs = parseTagAttrs(attrStr);
        const href = attrs.href ?? '';
        const cls = (attrs.class ?? '').toLowerCase();
        if (href.startsWith('user?id=') || cls.split(/\s+/).includes('hnuser')) {
          const cleaned = cleanInlineHtml(inner);
          if (cleaned) author = cleaned;
        }
      }
      return '';
    },
    { maxChars: 32_000, maxInnerChars: 1_000 },
  );
  return author;
}

function findSpanAttrInFragment(frag: string, classTokenLower: string, attrNameLower: string): string {
  let val = '';
  scanHtmlTagsLinear(
    frag,
    (tag) => {
      if (!tag.isClosing && tag.tagNameLower === 'span' && hasClassToken(tag.attrs, classTokenLower)) {
        val = parseTagAttrs(tag.attrs)[attrNameLower] ?? '';
        return false;
      }
      return undefined;
    },
    32_000,
    false,
  );
  return val;
}

function extractHackerNewsMarkdown(
  rawHtml: string,
  baseUrl?: string,
): { title?: string; author?: string; publishedTime?: string; markdown: string; links: string[] } | null {
  const boundedHtml = rawHtml.length > MAX_HTML_SCAN_CHARS ? rawHtml.slice(0, MAX_HTML_SCAN_CHARS) : rawHtml;
  let isHnHost = false;
  if (baseUrl) {
    try {
      isHnHost = /^(?:www\.)?news\.ycombinator\.com$/i.test(new URL(baseUrl).hostname);
    } catch {
      isHnHost = false;
    }
  }
  if (!isHnHost) {
    if (!boundedHtml.includes('hnmain') && !boundedHtml.includes('HNMAIN')) {
      return null;
    }
    let hasHnMainTable = false;
    scanHtmlTagsLinear(
      boundedHtml,
      (tag) => {
        if (!tag.isClosing && tag.tagNameLower === 'table' && (parseTagAttrs(tag.attrs).id ?? '').toLowerCase() === 'hnmain') {
          hasHnMainTable = true;
          return false;
        }
        return undefined;
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );
    if (!hasHnMainTable) return null;
  }

  const hnBase = baseUrl || 'https://news.ycombinator.com/';
  const links: string[] = [];
  const addLink = (rawHref: string | undefined) => {
    const r = resolveHttpsHref(rawHref, hnBase, false);
    if (r && !links.includes(r) && links.length < 250) links.push(r);
    return r;
  };

  const fatSub = boundedHtml.includes('fatitem') ? findFirstClassSubtreeLinear(boundedHtml, ['table'], 'fatitem') : null;
  if (fatSub && fatSub.inner.length > 0 && fatSub.inner.length <= 120_000) {
    const fat = fatSub.inner;
    const titlelineSpan = fat.includes('titleline') ? findFirstClassSubtreeLinear(fat, ['span'], 'titleline') : null;
    const titleLink = titlelineSpan ? findFirstAnchorInFragment(titlelineSpan.inner) : null;
    const onStorySpan = fat.includes('onstory') ? findFirstClassSubtreeLinear(fat, ['span'], 'onstory') : null;
    const onStoryLink = onStorySpan ? findFirstAnchorInFragment(onStorySpan.inner) : null;
    const author = findHnAuthorInFragment(fat);
    const rawAgeTitle = fat.includes('age') ? findSpanAttrInFragment(fat, 'age', 'title') : '';
    const rawIso = rawAgeTitle.split(' ')[0]?.trim() || undefined;
    const dateShort = rawIso ? rawIso.split('T')[0] : undefined;
    const scoreSub = fat.includes('score') ? findFirstClassSubtreeLinear(fat, ['span'], 'score') : null;
    const score = scoreSub ? cleanInlineHtml(scoreSub.inner) : '';

    const sections: string[] = [];
    let outTitle: string | undefined;

    if (titleLink) {
      const storyUrl = addLink(titleLink.href);
      outTitle = titleLink.text;
      sections.push(storyUrl ? `# [${outTitle}](${storyUrl})` : `# ${outTitle}`);
      const metaBits = [score, author ? `by ${author}` : '', dateShort ?? ''].filter(Boolean);
      if (metaBits.length > 0) sections.push(`*${metaBits.join(' · ')}*`);
      const topTextSub = fat.includes('toptext') ? findFirstClassSubtreeLinear(fat, ['div'], 'toptext') : null;
      if (topTextSub?.inner) {
        const topMd = hnFragmentToMarkdown(topTextSub.inner, hnBase);
        if (topMd) sections.push(topMd);
      }
    } else {
      const storyTitle = onStoryLink?.text || 'Hacker News Thread';
      const storyHref = onStoryLink ? addLink(onStoryLink.href) : undefined;
      outTitle = storyTitle;
      sections.push(`# ${storyTitle}`);
      const metaBits = [
        author ? `Comment by **${author}**` : '',
        dateShort ?? '',
        storyHref ? `on [${storyTitle}](${storyHref})` : '',
      ].filter(Boolean);
      if (metaBits.length > 0) sections.push(metaBits.join(' · '));
      const mainCommSub = fat.includes('commtext') ? findFirstClassSubtreeLinear(fat, ['div', 'span'], 'commtext') : null;
      if (mainCommSub?.inner) {
        const bodyMd = hnFragmentToMarkdown(mainCommSub.inner, hnBase);
        if (bodyMd) sections.push(bodyMd);
      }
    }

    const commentItems: string[] = [];
    const seenIds = new Set<string>();
    const afterFat = boundedHtml.slice(fatSub.endIdx);
    if (afterFat.includes('comtr')) {
      const comRows: Array<{ attrs: Record<string, string>; inner: string }> = [];
      let comDepth = 0;
      let comInnerStart = -1;
      let comAttrs: Record<string, string> = {};
      scanHtmlTagsLinear(
        afterFat,
        (tag) => {
          if (tag.tagNameLower !== 'tr') return;
          if (comDepth === 0) {
            if (!tag.isClosing && !tag.isSelfClosing && hasClassToken(tag.attrs, 'comtr')) {
              const parsed = parseTagAttrs(tag.attrs);
              if (!(parsed.class ?? '').toLowerCase().split(/\s+/).includes('noshow')) {
                comDepth = 1;
                comInnerStart = tag.end;
                comAttrs = parsed;
              }
            }
            return undefined;
          }
          if (tag.isClosing) {
            comDepth--;
            if (comDepth === 0) {
              if (tag.index - comInnerStart <= 32_000) {
                comRows.push({ attrs: comAttrs, inner: afterFat.slice(comInnerStart, tag.index) });
                if (comRows.length >= 120) return false;
              }
            }
          } else if (!tag.isSelfClosing) {
            comDepth++;
          }
          return undefined;
        },
        MAX_HTML_SCAN_CHARS,
        false,
      );

      for (const cr of comRows) {
        const cid = cr.attrs.id ?? '';
        if (cid && seenIds.has(cid)) continue;
        if (cid) seenIds.add(cid);
        const rowHtml = cr.inner;
        let px = 0;
        const indTd = rowHtml.includes('ind') ? findFirstClassSubtreeLinear(rowHtml, ['td'], 'ind') : null;
        if (indTd) {
          scanHtmlTagsLinear(
            indTd.inner,
            (t) => {
              if (!t.isClosing && t.tagNameLower === 'img') {
                px = Number(parseTagAttrs(t.attrs).width ?? '0') || 0;
                return false;
              }
              return undefined;
            },
            1024,
            false,
          );
        }
        const depth = Math.min(5, Math.max(0, Math.round(px / 40)));
        const cAuthor = findHnAuthorInFragment(rowHtml) ?? '[deleted]';
        const cDate = (rowHtml.includes('age') ? findSpanAttrInFragment(rowHtml, 'age', 'title') : '').split('T')[0] ?? '';
        const commSub = rowHtml.includes('commtext') ? findFirstClassSubtreeLinear(rowHtml, ['div', 'span'], 'commtext') : null;
        if (!commSub?.inner) continue;
        const cBody = hnFragmentToMarkdown(commSub.inner, hnBase);
        if (!cBody || cBody === '[dead]' || cBody === '[flagged]') continue;
        const indent = '  '.repeat(depth);
        const indentedBody = cBody
          .split('\n')
          .map((line, idx) => (idx === 0 ? line : line ? `${indent}  ${line}` : ''))
          .join('\n');
        const header = cDate ? `**${cAuthor}** *(${cDate})*` : `**${cAuthor}**`;
        commentItems.push(`${indent}- ${header}: ${indentedBody}`);
      }
    }
    if (commentItems.length > 0) {
      sections.push(`## Comments\n\n${commentItems.join('\n\n')}`);
    }
    const md = sections.join('\n\n').trim();
    if (md.length >= 24) {
      return {
        ...(outTitle ? { title: outTitle } : {}),
        ...(author ? { author } : {}),
        ...(rawIso ? { publishedTime: rawIso } : {}),
        markdown: md,
        links,
      };
    }
  }

  // Hacker News story listing page (`news`, `newest`, `ask`, `show`, `front`) — strictly linear O(N) `<tr>` pair scan
  const listingItems: string[] = [];
  if (boundedHtml.includes('athing')) {
    const trList: Array<{ attrs: string; inner: string }> = [];
    let trDepth = 0;
    let trStart = -1;
    let trAttrStr = '';
    scanHtmlTagsLinear(
      boundedHtml,
      (tag) => {
        if (tag.tagNameLower !== 'tr') return;
        if (trDepth === 0) {
          if (!tag.isClosing && !tag.isSelfClosing) {
            trDepth = 1;
            trStart = tag.end;
            trAttrStr = tag.attrs;
          }
          return undefined;
        }
        if (tag.isClosing) {
          trDepth--;
          if (trDepth === 0) {
            if (tag.index - trStart <= 12_000) {
              trList.push({ attrs: trAttrStr, inner: boundedHtml.slice(trStart, tag.index) });
              if (trList.length >= 300) return false;
            }
          }
        } else if (!tag.isSelfClosing) {
          trDepth++;
        }
        return undefined;
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );

    for (let idx = 0; idx < trList.length; idx++) {
      const curTr = trList[idx]!;
      if (!hasClassToken(curTr.attrs, 'athing') || hasClassToken(curTr.attrs, 'comtr')) continue;
      const nextTr = trList[idx + 1];
      if (!nextTr || hasClassToken(nextTr.attrs, 'athing')) continue;
      const rowAttrs = parseTagAttrs(curTr.attrs);
      const id = rowAttrs.id ?? '';
      const tSpan = curTr.inner.includes('titleline') ? findFirstClassSubtreeLinear(curTr.inner, ['span'], 'titleline') : null;
      const tAnchor = tSpan ? findFirstAnchorInFragment(tSpan.inner) : null;
      if (!tAnchor?.text) continue;
      const storyTitle = tAnchor.text;
      const storyHref = addLink(tAnchor.href);
      const siteSub = curTr.inner.includes('sitestr') ? findFirstClassSubtreeLinear(curTr.inner, ['span'], 'sitestr') : null;
      const siteStr = siteSub ? cleanInlineHtml(siteSub.inner) : '';
      const subHtml = nextTr.inner;
      const scoreSub = subHtml.includes('score') ? findFirstClassSubtreeLinear(subHtml, ['span'], 'score') : null;
      const pts = scoreSub ? cleanInlineHtml(scoreSub.inner) : '';
      const byUser = findHnAuthorInFragment(subHtml) ?? '';
      let lastAnchorText = '';
      replacePairedHtmlElementsLinear(
        subHtml,
        ['a'],
        (_f, _t, _a, aInner) => {
          lastAnchorText = cleanInlineHtml(aInner);
          return '';
        },
        { maxChars: 8_000, maxInnerChars: 500 },
      );
      const commentsPart =
        id && /\bcomment|\bdiscuss/i.test(lastAnchorText)
          ? `[${lastAnchorText}](${addLink(`https://news.ycombinator.com/item?id=${id}`)})`
          : '';
      const meta = [pts, byUser ? `by ${byUser}` : '', commentsPart].filter(Boolean).join(' · ');
      const head = storyHref ? `**[${storyTitle}](${storyHref})**` : `**${storyTitle}**`;
      listingItems.push(
        `${listingItems.length + 1}. ${head}${siteStr ? ` *(${siteStr})*` : ''}${meta ? ` — ${meta}` : ''}`,
      );
      idx++; // skip consumed subtext row
      if (listingItems.length >= 60) break;
    }
  }
  if (listingItems.length >= 2) {
    return {
      title: 'Hacker News',
      markdown: `# Hacker News\n\n${listingItems.join('\n')}`,
      links,
    };
  }
  return null;
}

function cleanGitHubIssueOrPrMarkdown(md: string): string {
  let out = md.replace(/(^#\s+[^\n]+\n+(?:(?:Open|Closed|Merged|Draft)\n+[\s\S]{0,400}?\n+)?)##\s+[^\n]+#\d+\s+[^\n]+\n+/i, '$1');
  const lower = asciiLower(out);
  const signUpIdx = lower.indexOf('[sign up for free](https://github.com/join');
  if (signUpIdx >= 0) {
    out = out.slice(0, signUpIdx);
  }
  const revIdx = asciiLower(out).indexOf('\n### reviewers');
  if (revIdx >= 0) {
    out = out.slice(0, revIdx);
  }
  return out.trim();
}

function cleanArxivAbstractMarkdown(md: string): string {
  return md
    .replace(/^#\s+[^\n]+>\s+[^\n]+\n+/, '')
    .replace(/^#\s+Title:\s+/m, '# ')
    .replace(/\n###\s+(?:Current browse context|Bibliographic and Citation Tools|Code, Data and Media Associated with this Article|Demos|Recommenders and Search Tools|arXivLabs:)\b[\s\S]*$/i, '')
    .trim();
}

/**
 * Defuddle-inspired HTML element standardization pass:
 *  - Propagates Sphinx/Pygments outer `<div class="highlight-{lang}"><div class="highlight"><pre>` onto `<pre>`
 *  - Unwraps GitHub `<div class="highlight highlight-source-{lang}" data-snippet-clipboard-copy-content="...">` with exact language tags
 *  - Propagates VitePress/Prism wrapper `<div class="language-{lang}">` onto child `<pre>` and strips Chroma/Rouge line-number table gutters
 *  - Extracts clean `$...$` / `$$...$$` LaTeX from KaTeX (`<annotation encoding="application/x-tex">`), Wikipedia Parsoid `data-mw`, and MathJax
 *  - Converts GFM task-list `<input type="checkbox">`, footnotes (`[^id]`), and HTML callouts into GFM syntax
 */
function standardizeElementsInHtml(html: string, stashCode?: (mdBlock: string) => string): string {
  let out = html;

  // Strip pure line-number gutter cells in 2-column Chroma / Rouge / Highlight.js code tables, then unwrap 1x1 `<pre>` wrapper tables (`R3-H1` linear O(N)).
  if (/(?:lntd|gutter|hljs-ln-numbers|blob-num)/i.test(out)) {
    out = replacePairedHtmlElementsLinear(
      out,
      ['td'],
      (full, _t, attrStr, inner) => {
        const clsTokens = (parseTagAttrs(attrStr).class ?? '').toLowerCase().split(/\s+/);
        if (
          !clsTokens.includes('lntd') &&
          !clsTokens.includes('gutter') &&
          !clsTokens.includes('hljs-ln-numbers') &&
          !clsTokens.includes('blob-num')
        ) {
          return full;
        }
        const plain = stripHtmlTagsQuoteAwareLinear(inner, '').trim();
        return /^[\d\s]+$/.test(plain) ? '' : full;
      },
      { maxInnerChars: 12_000 },
    );
    out = replacePairedHtmlElementsLinear(
      out,
      ['table'],
      (full, _t, _attrStr, inner) => {
        if (!/<pre\b/i.test(inner)) return full;
        const strippedLayout = replaceHtmlTagsQuoteAwareLinear(
          inner,
          (t) => (t.tagNameLower === 'tbody' || t.tagNameLower === 'tr' || t.tagNameLower === 'td' ? '' : t.rawTag),
          65_536,
          false,
        ).trim();
        if (/^<pre\b/i.test(strippedLayout) && /<\/pre>$/i.test(strippedLayout)) {
          return `\n\n${strippedLayout}\n\n`;
        }
        return full;
      },
      { maxInnerChars: 65_536 },
    );
  }

  // Propagate Sphinx / ReadTheDocs two-level `<div class="highlight-python3 notranslate"><div class="highlight"><pre>` language onto inner `<pre>`.
  if (out.includes('highlight-')) {
    out = out.replace(
      /<div\b([^>]{1,350})>\s*<div\b([^>]{1,350})>\s*<pre\b/gi,
      (full, outerAttrs: string, innerAttrs: string) => {
        if (!/\bhighlight\b/i.test(innerAttrs)) return full;
        const lm = /\bhighlight-(?!source-)([a-zA-Z0-9_+#-]+)\b/i.exec(outerAttrs);
        if (!lm?.[1]) return full;
        const norm = normalizeFenceLang(lm[1]);
        if (!norm) return full;
        return `<div${outerAttrs}><div${innerAttrs}><pre data-wrapper-lang="${norm}"`;
      },
    );
  }

  // Convert GitHub / Sphinx syntax-highlighted `<div class="highlight ..."><pre>...</pre></div>` linearly (`R3-H1`: zero backtracking on `<div "`).
  if (out.includes('highlight')) {
    const src = out;
    const chunks: string[] = [];
    let lastCopied = 0;
    const lowerSrc = asciiLower(src);
    scanHtmlTagsLinear(
      src,
      (tag) => {
        if (tag.index < lastCopied || tag.isClosing || tag.isSelfClosing || tag.tagNameLower !== 'div') return;
        if (!tag.attrs.includes('highlight') && !tag.attrs.includes('HIGHLIGHT')) return;
        const divAttrs = parseTagAttrs(tag.attrs);
        const cls = divAttrs.class ?? '';
        if (!cls.toLowerCase().split(/\s+/).includes('highlight')) return;

        let afterDiv = tag.end;
        while (afterDiv < src.length && (src.charCodeAt(afterDiv) === 32 || src.charCodeAt(afterDiv) === 9 || src.charCodeAt(afterDiv) === 10 || src.charCodeAt(afterDiv) === 13)) {
          afterDiv++;
        }
        if (lowerSrc.slice(afterDiv, afterDiv + 4) !== '<pre' || (afterDiv + 4 < src.length && !isTagNameBoundary(src.charCodeAt(afterDiv + 4)))) {
          return undefined;
        }
        const preOpenGt = src.indexOf('>', afterDiv + 4);
        if (preOpenGt < 0 || preOpenGt - afterDiv > 800) return undefined;
        const preAttrStr = src.slice(afterDiv + 4, preOpenGt);
        const preCloseIdx = lowerSrc.indexOf('</pre>', preOpenGt + 1);
        if (preCloseIdx < 0 || preCloseIdx - (preOpenGt + 1) > 100_000) return undefined;
        let afterPre = preCloseIdx + 6;
        while (afterPre < src.length && (src.charCodeAt(afterPre) === 32 || src.charCodeAt(afterPre) === 9 || src.charCodeAt(afterPre) === 10 || src.charCodeAt(afterPre) === 13)) {
          afterPre++;
        }
        if (lowerSrc.slice(afterPre, afterPre + 6) !== '</div>') return undefined;

        const preInner = src.slice(preOpenGt + 1, preCloseIdx);
        const lang = inferCodeFenceLang(tag.attrs, preAttrStr);
        const rawClip = divAttrs['data-snippet-clipboard-copy-content'];
        const codeText =
          rawClip && rawClip.trim().length > 0
            ? rawClip
            : decodeHtmlEntities(stripHtmlTagsQuoteAwareLinear(preInner, ''));
        const block = `\n\n${makeSafeCodeFence(codeText.trim(), lang)}\n\n`;
        chunks.push(src.slice(lastCopied, tag.index));
        chunks.push(stashCode ? stashCode(block) : block);
        lastCopied = afterPre + 6;
        return undefined;
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );
    if (chunks.length > 0) {
      chunks.push(src.slice(lastCopied));
      out = chunks.join('');
    }
  }

  // Convert GFM / HTML task-list checkboxes (`<input type="checkbox" checked>`) before generic void tags are stripped (`H1` linear O(N)).
  if (/<input/i.test(out)) {
    out = replaceHtmlOpenTagsLinear(out, ['input'], (tag) => {
      const attrStr = tag.attrs;
      if (!/\btype\s*=\s*(?:"checkbox"|'checkbox'|checkbox\b)/i.test(attrStr)) return tag.rawTag;
      const isChecked =
        /\bchecked\b/i.test(attrStr.replace(/"[^"]*"|'[^']*'/g, '""')) ||
        /\bchecked\s*=\s*(?:"(?:checked|true)"|'(?:checked|true)')/i.test(attrStr);
      return isChecked ? '\u0000EFTASKX\u0000 ' : '\u0000EFTASKO\u0000 ';
    });
  }

  // Standardize HTML footnotes (`<sup id="fnref:1"><a href="#fn:1">1</a></sup>` and `<section id="footnotes"><ol>...</ol></section>`).
  if (/(?:fnref|footnote)/i.test(out)) {
    out = out
      .replace(
        /<sup\b([^>]{1,300})>\s*<a\b([^>]{1,300})>[\s\S]{0,60}?<\/a>\s*<\/sup>/gi,
        (full, supAttrs: string, aAttrs: string) => {
          const sa = parseTagAttrs(supAttrs);
          const aa = parseTagAttrs(aAttrs);
          const rawHref = aa.href ?? '';
          const rawId =
            /^#(?:fn:|user-content-fn-|footnote-)(.+)$/i.exec(rawHref)?.[1] ??
            /^(?:fnref:|user-content-fnref-)(.+)$/i.exec(sa.id ?? '')?.[1];
          if (!rawId) return full;
          const cleanId = rawId.replace(/-\d+$/, '').replace(/[^a-zA-Z0-9_-]/g, '');
          return cleanId ? `[^${cleanId}]` : full;
        },
      )
      .replace(
        /<(section|div)\b([^>]{1,400})>\s*(?:<h[1-6]\b[^>]*>[\s\S]{0,120}?<\/h[1-6]>\s*)?(?:<hr\b[^>]*\/?>\s*)?<ol\b[^>]*>([\s\S]{1,40000}?)<\/ol>\s*<\/\1>/gi,
        (full, _tag: string, attrStr: string, olInner: string) => {
          const attrs = parseTagAttrs(attrStr);
          const hay = `${attrs.id ?? ''} ${attrs.class ?? ''}`.toLowerCase();
          if (!hay.includes('footnote')) return full;
          const defs: string[] = [];
          for (const lm of olInner.matchAll(/<li\b([^>]{0,300})>([\s\S]{1,4000}?)<\/li>/gi)) {
            const la = parseTagAttrs(lm[1]!);
            const rawId = /^(?:fn:|user-content-fn-|footnote-)(.+)$/i.exec(la.id ?? '')?.[1] ?? `${defs.length + 1}`;
            const cleanId = rawId.replace(/[^a-zA-Z0-9_-]/g, '') || `${defs.length + 1}`;
            const cleanedLi = cleanInlineHtml(
              lm[2]!.replace(/<a\b[^>]*(?:footnote-backref|#fnref|#user-content-fnref)[^>]*>[\s\S]*?<\/a>/gi, ''),
            ).replace(/\s*[↩↩︎]+$/u, '');
            if (cleanedLi) defs.push(`[^${cleanId}]: ${cleanedLi}`);
          }
          return defs.length > 0 ? `\n\n${defs.join('\n')}\n\n` : full;
        },
      );
  }

  // Propagate VitePress / Docusaurus / Prism wrapper `<div class="... language-ts ...">` language onto child `<pre>`
  // and strip empty `<button class="copy">` + `<span class="lang">js</span>` badges in strictly O(N) time (no nested `*`).
  if (/\b(?:language|lang|highlight-source)-[a-zA-Z0-9_+#-]+/i.test(out)) {
    out = out.replace(
      /<div\b([^>]{1,500})>(\s*(?:<button\b[^>]{0,240}>[^<]{0,40}<\/button>\s*)?(?:<span\b[^>]{0,240}>[^<]{0,40}<\/span>\s*)?)<pre\b/gi,
      (full, divAttrStr: string, mid: string) => {
        const lm = /\b(?:language|lang|highlight-source)-([a-zA-Z0-9_+#-]+)\b/i.exec(divAttrStr);
        if (!lm?.[1]) return full;
        const cleanedMid = mid
          .replace(/<button\b[^>]*>[^<]*<\/button>/gi, '')
          .replace(/<span\b[^>]*\blang\b[^>]*>[^<]*<\/span>/gi, '');
        return `<div${divAttrStr}>${cleanedMid}<pre data-wrapper-lang="${lm[1]}"`;
      },
    );
  }

  // Strip MediaWiki visual math fallback `<img>` tags (the sibling `<math alttext="...">` carries clean LaTeX).
  if (out.includes('mwe-math-fallback-image')) {
    out = replaceHtmlOpenTagsLinear(out, ['img'], (tag) =>
      /\bmwe-math-fallback-image\b/i.test(tag.attrs) ? '' : tag.rawTag,
    );
  }

  // Mark `<math>` inside `.katex-display` or `.MathJax_Display` so `<math>` emits display `$$...$$` blocks.
  if (/(?:katex-display|MathJax_Display)/i.test(out)) {
    out = out.replace(
      /<(span|div)\b[^>]{0,600}\b(?:katex-display|MathJax_Display)\b[^>]{0,600}>((?:(?!<\/math>)[\s\S]){0,12000}?)<\/math>/gi,
      (full) => full.replace(/<math\b/i, '<math data-ef-display="block"'),
    );
  }

  // Convert `<math>` (KaTeX `<annotation encoding="application/x-tex">` or Wikipedia/MathML `alttext`) to LaTeX (`H1` linear O(N)).
  if (/<math/i.test(out)) {
    out = replacePairedHtmlElementsLinear(
      out,
      ['math'],
      (full, _t, attrStr, inner) => {
        const attrs = parseTagAttrs(attrStr);
        let annotTex: string | undefined;
        replacePairedHtmlElementsLinear(
          inner,
          ['annotation'],
          (_af, _at, aAttr, aInner) => {
            if (annotTex === undefined && /encoding\s*=\s*(?:"application\/x-tex"|'application\/x-tex')/i.test(aAttr)) {
              annotTex = aInner;
            }
            return '';
          },
          { maxChars: 24_000, maxInnerChars: 24_000 },
        );
        let mwExtSrc: string | undefined;
        if (attrs['data-mw'] && attrs['data-mw'].includes('extsrc')) {
          try {
            const parsedMw = JSON.parse(attrs['data-mw']) as { body?: { extsrc?: string } };
            if (typeof parsedMw?.body?.extsrc === 'string') mwExtSrc = parsedMw.body.extsrc;
          } catch {
            // ignore malformed Parsoid data-mw JSON
          }
        }
        const rawTex = annotTex ?? attrs.alttext ?? attrs['data-latex'] ?? mwExtSrc;
        if (!rawTex) return full;
        const tex = normalizeLatexSource(rawTex);
        if (!tex) return full;
        const isBlock = attrs.display === 'block' || attrs['data-ef-display'] === 'block' || tex.includes('\n');
        return isBlock ? `\n\n$$\n${tex}\n$$\n\n` : `$${tex.replace(/\s+/g, ' ')}$`;
      },
      { maxInnerChars: 24_000 },
    );
  }

  // Convert MathJax `<mjx-container data-latex="...">` when assistive `<math>` was absent (`H1` linear O(N)).
  if (/<mjx-container/i.test(out)) {
    out = replacePairedHtmlElementsLinear(
      out,
      ['mjx-container'],
      (full, _t, attrStr) => {
        const attrs = parseTagAttrs(attrStr);
        const rawTex = attrs['data-latex'] ?? attrs['data-math'];
        if (!rawTex) return full;
        const tex = normalizeLatexSource(rawTex);
        if (!tex) return full;
        const isBlock = attrs.display === 'true' || attrs.display === 'block';
        return isBlock ? `\n\n$$\n${tex}\n$$\n\n` : `$${tex.replace(/\s+/g, ' ')}$`;
      },
      { maxInnerChars: 12_000 },
    );
  }

  // Convert GitHub `.markdown-alert`, Docusaurus/MkDocs `.admonition`, Starlight `.starlight-aside`, and Obsidian `[data-callout]` blocks.
  if (/(?:markdown-alert-|admonition|starlight-aside--|data-callout)/i.test(out)) {
    out = out.replace(
      /<(div|aside)\b([^>]{1,600})>((?:(?!<\1\b)[\s\S]){0,8000}?)<\/\1>/gi,
      (full, _tag: string, attrStr: string, inner: string) => {
        if (!/(?:markdown-alert-|admonition|starlight-aside--|data-callout)/i.test(attrStr)) return full;
        const attrs = parseTagAttrs(attrStr);
        const cls = (attrs.class ?? '').toLowerCase();
        if (
          !attrs['data-callout'] &&
          !/\b(?:markdown-alert-\w+|admonition|theme-admonition-\w+|starlight-aside--\w+)\b/.test(cls)
        ) {
          return full;
        }
        const rawType =
          attrs['data-callout'] ??
          /\bmarkdown-alert-([a-z]+)\b/.exec(cls)?.[1] ??
          /\btheme-admonition-([a-z]+)\b/.exec(cls)?.[1] ??
          /\bstarlight-aside--([a-z]+)\b/.exec(cls)?.[1] ??
          /\b(note|tip|info|warning|caution|danger|important)\b/.exec(cls)?.[1] ??
          'note';
        const gfmType = mapCalloutTypeToGfm(rawType);
        let customTitle = '';
        const bodyWithoutTitle = inner.replace(
          /<(?:p|div)\b[^>]{0,600}\b(?:markdown-alert-title|admonition-title|callout-title|starlight-aside__title)\b[^>]{0,600}>([\s\S]*?)<\/(?:p|div)>/i,
          (_tm, tInner: string) => {
            const candidate = cleanInlineHtml(tInner);
            if (candidate && candidate.toLowerCase() !== rawType.toLowerCase() && candidate.toLowerCase() !== gfmType.toLowerCase()) {
              customTitle = candidate;
            }
            return '';
          },
        );
        const bodyText = cleanInlineHtml(bodyWithoutTitle);
        if (!bodyText) return full;
        return `\n\n> [!${gfmType}]${customTitle ? ` ${customTitle}` : ''}\n> ${bodyText}\n\n`;
      },
    );
  }

  // Upgrade `<picture><source srcset="..."><img></picture>` to highest-resolution image candidate (`H1` linear O(N)).
  if (/<picture/i.test(out)) {
    out = replacePairedHtmlElementsLinear(
      out,
      ['picture'],
      (full, _t, _attrs, inner) => {
        let bestSrc: string | undefined;
        scanHtmlTagsLinear(
          inner,
          (tag) => {
            if (!tag.isClosing && tag.tagNameLower === 'source') {
              const sAttrs = parseTagAttrs(tag.attrs);
              const cand = extractLargestUrlFromSrcset(sAttrs.srcset ?? sAttrs['data-srcset']);
              if (cand) {
                bestSrc = cand;
                return false;
              }
            }
            return undefined;
          },
          8000,
        );
        if (!bestSrc) return full;
        let replacedImg = false;
        return replaceHtmlOpenTagsLinear(inner, ['img'], (imgTag) => {
          if (replacedImg) return imgTag.rawTag;
          replacedImg = true;
          const imgAttrs = parseTagAttrs(imgTag.attrs);
          if (imgAttrs.src && !isLazyPlaceholderImageUrl(imgAttrs.src)) return imgTag.rawTag;
          return `<img src="${bestSrc}" ${imgTag.attrs}>`;
        });
      },
      { maxInnerChars: 8000 },
    );
  }

  return out;
}

/**
 * Crawl4AI + Defuddle link-density boilerplate filter (`H1` linear O(N) tag & anchor scanning).
 */
function pruneHighLinkDensityBlocks(html: string): string {
  const beforeWords = countTextWords(stripHtmlTagsQuoteAwareLinear(html, ' '));
  if (beforeWords < 140) return html;

  const clutterAttrRe =
    /\b(?:sidebar|related|popular|trending|recommended|most-read|more-stories|toc|table-of-contents|breadcrumb|pagination|pager|tag-cloud|tags-list|categories|social|share|widget|footer-links)\b/i;

  const candidate = html.replace(
    /<(div|section|ul)\b([^>]{0,500})>((?:(?!<\1\b)[\s\S]){0,12000}?)<\/\1>/gi,
    (full, tag: string, attrStr: string, inner: string) => {
      if (/<(?:pre|code|table|h1|article|figure|math)\b/i.test(inner)) return full;
      const anchorPairs: Array<{ attrs: string; inner: string }> = [];
      replacePairedHtmlElementsLinear(
        inner,
        ['a'],
        (_af, _at, aAttrs, aInner) => {
          anchorPairs.push({ attrs: aAttrs, inner: aInner });
          return '';
        },
        { maxChars: 12_000 },
      );
      if (anchorPairs.length < 5) return full;

      const totalText = cleanInlineHtml(inner);
      const words = countTextWords(totalText);
      if (words === 0 || words >= 95) return full;

      let anchorTextLen = 0;
      let hashOnlyAnchors = 0;
      for (const am of anchorPairs) {
        const aAttrs = parseTagAttrs(am.attrs);
        if ((aAttrs.href ?? '').trim().startsWith('#')) hashOnlyAnchors++;
        anchorTextLen += cleanInlineHtml(am.inner).length;
      }
      const linkRatio = anchorTextLen / Math.max(1, totalText.length);
      if (linkRatio < 0.8) return full;

      const isSamePageToc = hashOnlyAnchors >= 4 && hashOnlyAnchors === anchorPairs.length;
      const attrs = parseTagAttrs(attrStr);
      const hasClutterAttr = clutterAttrRe.test(`${attrs.class ?? ''} ${attrs.id ?? ''}`);
      if (isSamePageToc || (hasClutterAttr && tag.toLowerCase() !== 'article')) {
        return '';
      }
      return full;
    },
  );

  if (candidate === html) return html;
  const afterWords = countTextWords(stripHtmlTagsQuoteAwareLinear(candidate, ' '));
  return afterWords >= beforeWords * 0.55 ? candidate : html;
}

/** Extracts clean GFM Markdown, metadata, links, images, and branding from raw HTML without external DOM dependencies. */
export function extractHtmlDocument(
  rawHtml: string,
  options: {
    baseUrl?: string;
    onlyMainContent?: boolean;
    redactPii?: boolean;
    includeImages?: boolean;
    includeTags?: readonly string[];
    excludeTags?: readonly string[];
  } = {},
): ExtractedDocument {
  const { baseUrl, onlyMainContent = true, redactPii = false, includeImages = true, includeTags, excludeTags } = options;
  const deadlineAt = Date.now() + 2_500;
  let boundedRawHtml = rawHtml.length > MAX_HTML_SCAN_CHARS ? rawHtml.slice(0, MAX_HTML_SCAN_CHARS) : rawHtml;
  if (boundedRawHtml.includes('\u0000')) boundedRawHtml = boundedRawHtml.replace(/\u0000/g, '');

  const jsonLdEntities = flattenJsonLdEntities(boundedRawHtml);
  const schemaMeta = extractSchemaMetadataAndBody(jsonLdEntities);

  let rawDocTitle: string | undefined;
  replacePairedHtmlElementsLinear(
    boundedRawHtml,
    ['title'],
    (_full, _t, _a, inner) => {
      if (rawDocTitle === undefined) rawDocTitle = cleanInlineHtml(inner);
      return '';
    },
    { maxChars: MAX_HTML_SCAN_CHARS, maxInnerChars: 4096 },
  );
  let title = rawDocTitle && !isPlaceholderMetaValue(rawDocTitle) ? rawDocTitle : undefined;
  let language: string | undefined;
  let description: string | undefined;
  let author: string | undefined;
  let publishedTime: string | undefined;
  let modifiedTime: string | undefined;
  let siteName: string | undefined;
  let ogImage: string | undefined;
  let themeColor: string | undefined;
  let firstDatetimeAttr: string | undefined;
  let canonicalUrl: string | undefined;
  let markdownAlternateUrl: string | undefined;
  let favicon: string | undefined;
  let logo: string | undefined;
  const citationAuthors: string[] = [];

  // Single linear O(N) open-tag pass across `<html>`, `<meta>`, `<link>`, `<time>`, `<relative-time>`, and `<img logo>` (`H1`)
  scanHtmlTagsLinear(
    boundedRawHtml,
    (tag) => {
      if (tag.isClosing || tag.isDeclaration) return;
      const tName = tag.tagNameLower;
      if (tName === 'html') {
        if (!language) {
          const htmlAttrs = parseTagAttrs(tag.attrs);
          language = htmlAttrs.lang?.trim() || undefined;
        }
        return;
      }
      if (tName === 'meta') {
        const attrs = parseTagAttrs(tag.attrs);
        const key = (attrs.name ?? attrs.property ?? '').toLowerCase();
        const content = (attrs.content ?? '').trim();
        if (!content || isPlaceholderMetaValue(content)) return;
        if ((key === 'description' || key === 'og:description') && !description) description = content;
        if (key === 'og:title' && !title) title = content;
        if ((key === 'og:image' || key === 'twitter:image') && !ogImage) ogImage = resolveHttpsHref(content, baseUrl);
        if (key === 'theme-color' && !themeColor) themeColor = content;
        if ((key === 'og:site_name' || key === 'application-name') && !siteName) siteName = content;
        if (
          (key === 'author' || key === 'article:author' || key === 'sailthru.author' || key === 'byl') &&
          !author &&
          !/^https?:\/\//i.test(content)
        ) {
          const cleaned = cleanAuthorMetaString(content);
          if (cleaned && !isPlaceholderMetaValue(cleaned)) author = cleaned;
        }
        if ((key === 'citation_author' || key === 'dc.creator') && citationAuthors.length < 10) {
          citationAuthors.push(cleanAuthorMetaString(content));
        }
        if (
          (key === 'article:published_time' ||
            key === 'date' ||
            key === 'pubdate' ||
            key === 'publishdate' ||
            key === 'citation_publication_date' ||
            key === 'citation_date' ||
            key === 'citation_online_date' ||
            key === 'dc.date' ||
            key === 'dc.date.issued' ||
            key === 'dcterms.created' ||
            key === 'dcterms.issued') &&
          !publishedTime
        ) {
          publishedTime = content;
        }
        if ((key === 'article:modified_time' || key === 'og:updated_time') && !modifiedTime) {
          modifiedTime = content;
        }
        return;
      }
      if (tName === 'link') {
        const attrs = parseTagAttrs(tag.attrs);
        const rel = (attrs.rel ?? '').toLowerCase();
        const mimeType = (attrs.type ?? '').toLowerCase();
        const href = resolveHttpsHref(attrs.href, baseUrl);
        if (!href) return;
        if (rel.includes('canonical') && !canonicalUrl) canonicalUrl = href;
        if (rel.includes('icon') && !favicon) favicon = href;
        if (
          rel.includes('alternate') &&
          (mimeType.includes('text/markdown') || mimeType.includes('application/markdown')) &&
          !markdownAlternateUrl
        ) {
          markdownAlternateUrl = href;
        }
        return;
      }
      if ((tName === 'time' || tName === 'relative-time') && !firstDatetimeAttr) {
        const attrs = parseTagAttrs(tag.attrs);
        if (attrs.datetime?.trim()) firstDatetimeAttr = attrs.datetime.trim();
        return;
      }
      if (tName === 'img' && !logo) {
        const attrs = parseTagAttrs(tag.attrs);
        const hay = `${attrs.alt ?? ''} ${attrs.class ?? ''} ${attrs.id ?? ''} ${attrs.src ?? ''}`.toLowerCase();
        if (hay.includes('logo')) {
          logo = resolveHttpsHref(attrs.src ?? attrs['data-src'], baseUrl);
        }
      }
    },
    MAX_HTML_SCAN_CHARS,
    false,
  );

  if (!author && citationAuthors.length > 0) {
    author = [...new Set(citationAuthors.filter(Boolean))].join(', ');
  }
  author = author || schemaMeta.author;
  publishedTime = publishedTime || schemaMeta.publishedTime || firstDatetimeAttr;
  modifiedTime = modifiedTime || schemaMeta.modifiedTime;
  siteName = siteName || schemaMeta.siteName;
  if (!favicon && baseUrl) {
    try {
      const bu = new URL(baseUrl);
      favicon = `${bu.origin}/favicon.ico`;
    } catch {
      // ignore
    }
  }

  // Extract colors and fonts from <style> tags before stripping them.
  const styleChunks: string[] = [];
  if (boundedRawHtml.includes('<style') || boundedRawHtml.includes('<STYLE')) {
    replaceHtmlTagBlocksLinear(
      boundedRawHtml,
      'style',
      (_full, _attr, inner) => {
        styleChunks.push(inner);
        return '';
      },
      MAX_HTML_SCAN_CHARS,
    );
  }
  const styleText = styleChunks.join('\n');
  const colors = [...new Set((styleText.match(/#[0-9a-fA-F]{6}\b/g) ?? []).map((c) => c.toLowerCase()))]
    .filter((c) => c !== '#ffffff' && c !== '#000000')
    .slice(0, 8);
  const fonts = [
    ...new Set(
      [...styleText.matchAll(/font-family\s*:\s*([^;}{]+)/gi)]
        .flatMap((m) => m[1]!.split(','))
        .map((f) => f.trim().replace(/^["']|["']$/g, ''))
        .filter(
          (f) =>
            f &&
            !/^var\s*\(/i.test(f) &&
            !/^(sans-serif|serif|monospace|cursive|fantasy|inherit|initial|unset|revert|system-ui|ui-sans-serif|ui-serif|ui-monospace|-apple-system|blinkmacsystemfont)$/i.test(
              f,
            ),
        ),
    ),
  ].slice(0, 6);

  // Discover Mintlify / docs HTML comment companion Markdown hints before stripping HTML comments:
  // e.g. `<!-- AI agents: this page is available as Markdown at /docs/.../intro.md. -->`
  if (!markdownAlternateUrl) {
    const commentMdMatch = /<!--[\s\S]{0,600}?\bavailable as Markdown at\s+(\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]+\.md|https:\/\/[A-Za-z0-9._~!$&'()*+,;=:@/%-]+\.md)\b[\s\S]{0,600}?-->/i.exec(
      rawHtml,
    );
    if (commentMdMatch?.[1]) {
      markdownAlternateUrl = resolveHttpsHref(commentMdMatch[1], baseUrl);
    }
  }

  // Extract YouTube watch-page `ytInitialPlayerResponse.videoDetails`, Substack `window._preloads`, and Hacker News threads
  // BEFORE stripping `<script>` tags so rich SSR payloads are preserved.
  const ytMeta = extractYouTubeWatchMetadataFromHtml(rawHtml);
  const substackPreload = onlyMainContent && (!includeTags || includeTags.length === 0) ? extractSubstackPreloadData(rawHtml) : null;
  if (substackPreload) {
    if (substackPreload.title) title = substackPreload.title;
    if (substackPreload.subtitle && !description) description = substackPreload.subtitle;
    if (substackPreload.author && !author) author = substackPreload.author;
    if (substackPreload.publishedTime && !publishedTime) publishedTime = substackPreload.publishedTime;
  }
  const hnExtracted =
    onlyMainContent && (!includeTags || includeTags.length === 0) ? extractHackerNewsMarkdown(rawHtml, baseUrl) : null;
  if (hnExtracted) {
    if (hnExtracted.title) title = hnExtracted.title;
    if (hnExtracted.author && !author) author = hnExtracted.author;
    if (hnExtracted.publishedTime && !publishedTime) publishedTime = hnExtracted.publishedTime;
  }

  // Capture `<noscript>` prose fallback (e.g. Discourse / Ghost SSR crawler fallback) before stripping `<noscript>`,
  // while promoting `<noscript><img ...></noscript>` lazy-load fallbacks inline (`M4` linear O(N) scanner, 2 MiB cap).
  const noscriptChunks: string[] = [];
  const withPromotedNoscriptImgs = replaceHtmlTagBlocksLinear(
    boundedRawHtml,
    'noscript',
    (_full, _attrStr, inner) => {
      const trimmedInner = inner.trim();
      let singleImg = false;
      scanHtmlTagsLinear(
        trimmedInner,
        (tag) => {
          if (tag.index === 0 && tag.end === trimmedInner.length && !tag.isClosing && tag.tagNameLower === 'img') {
            singleImg = true;
          }
          return false;
        },
        4096,
      );
      if (singleImg) {
        return trimmedInner;
      }
      if (countTextWords(stripHtmlTagsQuoteAwareLinear(trimmedInner, ' ')) >= 35) {
        noscriptChunks.push(trimmedInner);
      }
      return '';
    },
    MAX_HTML_SCAN_CHARS,
  );

  // Convert YouTube & X/Twitter `<iframe>` embeds into clean Markdown links before stripping `<iframe>` tags.
  const withEmbedLinks = replaceHtmlTagBlocksLinear(
    withPromotedNoscriptImgs,
    'iframe',
    (_full, attrStr) => {
      const attrs = parseTagAttrs(attrStr);
      const src = attrs.src ?? attrs['data-src'] ?? '';
      if (!src) return '';
      const yt = /(?:youtube\.com|youtube-nocookie\.com)\/embed\/([A-Za-z0-9_-]{6,20})/i.exec(src);
      if (yt?.[1]) return `\n\n[Embedded YouTube Video](https://www.youtube.com/watch?v=${yt[1]})\n\n`;
      const xDirect = /(?:twitter\.com|x\.com)\/([A-Za-z0-9_]+)\/status\/(\d+)/i.exec(src);
      if (xDirect?.[1] && xDirect[2]) return `\n\n[Embedded Post](https://x.com/${xDirect[1]}/status/${xDirect[2]})\n\n`;
      const xEmbed = /platform\.twitter\.com\/embed\/Tweet\.html\?[^"']*?\bid=(\d+)/i.exec(src);
      if (xEmbed?.[1]) return `\n\n[Embedded Post](https://x.com/i/status/${xEmbed[1]})\n\n`;
      return '';
    },
    MAX_HTML_SCAN_CHARS,
  );

  // Preserve MathJax `<script type="math/tex">` equations BEFORE stripping `<script>` tags.
  const withPreservedMathScripts = replaceHtmlTagBlocksLinear(
    withEmbedLinks,
    'script',
    (_full, attrStr, inner) => {
      if (!/\btype\s*=\s*["']math\/tex/i.test(attrStr)) return '';
      const tex = normalizeLatexSource(inner);
      if (!tex) return '';
      return /mode\s*=\s*display/i.test(attrStr) ? `\n\n$$\n${tex}\n$$\n\n` : `$${tex.replace(/\s+/g, ' ')}$`;
    },
    MAX_HTML_SCAN_CHARS,
  );

  // Strip comments (including Lit-SSR `<?>` bogus comments on MDN) and non-content elements in guaranteed linear O(N) time.
  const withoutComments = stripHtmlCommentsLinear(withPreservedMathScripts, MAX_HTML_SCAN_CHARS).replace(
    /<\?[\s\S]{0,400}?\?>|<\?>/g,
    '',
  );
  const withoutSvg = stripHtmlTagsLinear(withoutComments, ['svg'], ' ', MAX_HTML_SCAN_CHARS);
  const withoutCommentsAndScripts = stripHtmlTagsLinear(
    withoutSvg,
    [
      'head',
      'noscript',
      'template',
      'canvas',
      'iframe',
      'include-fragment',
      'details-dialog',
      'details-menu',
      'tool-tip',
      'clipboard-copy',
      'script',
      'style',
    ],
    '',
    MAX_HTML_SCAN_CHARS,
  );
  let work = withoutCommentsAndScripts;

  let extractedMarkdownBodyOnly = false;
  if (includeTags && includeTags.length > 0) {
    work = applyIncludeAndExcludeTagSelectors(work, includeTags, excludeTags);
  } else if (onlyMainContent) {
    work = stripHtmlTagsLinear(work, ['nav', 'footer', 'aside', 'dialog', 'menu'], '', MAX_HTML_SCAN_CHARS);
    // Substack rendered post body (`<div class="body markup">`) or `window._preloads` `body_html`
    const substackMarkup = applyIncludeAndExcludeTagSelectors(work, ['.markup'], undefined);
    // GitHub / GFM pages wrap repo chrome + duplicate file tables inside `<main>` around `<article class="markdown-body">`
    const mdBodyParts: string[] = [];
    const articleParts: string[] = [];
    replacePairedHtmlElementsLinear(work, ['article'], (_af, _at, aAttrs, aInner) => {
      articleParts.push(aInner);
      const cls = parseTagAttrs(aAttrs).class ?? '';
      if (/\bmarkdown-body\b/i.test(cls)) {
        mdBodyParts.push(aInner);
      }
      return '';
    });
    const joinedMdBody = mdBodyParts.join('\n\n<hr/>\n\n');

    let firstMainEnd = -1;
    let lastMainCloseIdx = -1;
    scanHtmlTagsLinear(
      work,
      (tag) => {
        if (tag.tagNameLower !== 'main') return;
        if (!tag.isClosing && !tag.isSelfClosing && firstMainEnd < 0) {
          firstMainEnd = tag.end;
        } else if (tag.isClosing && firstMainEnd >= 0) {
          lastMainCloseIdx = tag.index;
        }
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );
    const mainInner =
      firstMainEnd >= 0 && lastMainCloseIdx > firstMainEnd ? work.slice(firstMainEnd, lastMainCloseIdx) : undefined;

    const isGitHubIssueOrPr = Boolean(baseUrl && /^https?:\/\/github\.com\/[^/]+\/[^/]+\/(?:issues|pull)\/\d+/i.test(baseUrl));
    if (!isGitHubIssueOrPr && joinedMdBody.trim().length >= 32) {
      work = joinedMdBody;
      extractedMarkdownBodyOnly = true;
    } else if (/\bbody\s+markup\b|\bmarkup\s+body\b/i.test(work) && substackMarkup.trim().length >= 64) {
      work = substackMarkup;
      extractedMarkdownBodyOnly = true;
    } else if (substackPreload?.bodyHtml && (!mainInner || countTextWords(stripHtmlTagsQuoteAwareLinear(mainInner, ' ')) < 40)) {
      work = substackPreload.bodyHtml;
      extractedMarkdownBodyOnly = true;
    } else if (mainInner && mainInner.trim().length >= 32) {
      work = mainInner;
    } else {
      const joinedArticles = articleParts.join('\n\n');
      if (joinedArticles.trim().length >= 32) {
        work = joinedArticles;
      } else {
        const roleMain = extractBalancedRoleMainHtml(work);
        if (roleMain && roleMain.trim().length >= 32) {
          work = roleMain;
        } else {
          work = stripHtmlTagsLinear(work, ['header'], '', MAX_HTML_SCAN_CHARS);
        }
      }
    }
    if (excludeTags && excludeTags.length > 0) {
      work = applyIncludeAndExcludeTagSelectors(work, undefined, excludeTags);
    }
    // Strip hidden DOM subtrees (`[hidden]`, `.d-none`, `style="display:none"`), WAI-ARIA non-content landmarks,
    // MediaWiki edit/interlanguage chrome, copy-page buttons, and feedback forms in linear O(N) time (`H1`).
    work = stripHtmlTagsLinear(stripHiddenAndChromeSubtrees(work), ['nav', 'footer', 'aside'], '', MAX_HTML_SCAN_CHARS);
    work = replacePairedHtmlElementsLinear(work, ['span', 'a', 'label', 'ul', 'form', 'button', 'details'], (full, tag, attrStr, inner) => {
      if (tag === 'span') {
        if (/\bmw-editsection-bracket\b/i.test(attrStr)) return '';
        if (/\bmw-editsection\b/i.test(attrStr) && !inner.trim()) return '';
        return full;
      }
      if (tag === 'a') {
        if (
          /[?&]action=edit\b/i.test(attrStr) ||
          /href=(?:"https:\/\/www\.wikidata\.org\/wiki\/Special:EntityPage\/[^"]*"|'https:\/\/www\.wikidata\.org\/wiki\/Special:EntityPage\/[^']*')/i.test(
            attrStr,
          )
        ) {
          return '';
        }
        return full;
      }
      if (tag === 'label') {
        return /\bp-lang-btn-label\b/i.test(attrStr) ? '' : full;
      }
      if (tag === 'ul') {
        return (inner.match(/\binterlanguage-link\b/gi) ?? []).length >= 3 ? '' : full;
      }
      if (tag === 'form') {
        return /was this (page )?helpful|did this help|page feedback/i.test(inner) ? '' : full;
      }
      if (tag === 'button') {
        const btnTxt = cleanInlineHtml(inner);
        return /^(?:copy(?:\s+(?:page|code|link|markdown|item path|path|url|to clipboard|head branch name to clipboard))?|copied!?|yes|no|skip|submit feedback|back to top|ask ai|dark mode|light mode|toggle theme|see all|hide|hide comment|show more|show less|share|format|run)$/i.test(
          btnTxt,
        )
          ? ''
          : full;
      }
      if (tag === 'details') {
        const linkCount = (inner.match(/<a\b/gi) ?? []).length;
        const proseWithoutLinks = cleanInlineHtml(
          replacePairedHtmlElementsLinear(inner, ['a'], () => ' '),
        );
        if (linkCount >= 4 && proseWithoutLinks.length < 120) return '';
        return full;
      }
      return full;
    });
    work = pruneHighLinkDensityBlocks(work);
  } else if (excludeTags && excludeTags.length > 0) {
    work = applyIncludeAndExcludeTagSelectors(work, undefined, excludeTags);
  }

  const codeStash: string[] = [];
  const stashCode = (renderedCodeMd: string): string => `\u0000EFCODE${codeStash.push(renderedCodeMd) - 1}\u0000`;

  if (Date.now() <= deadlineAt) {
    work = standardizeElementsInHtml(work, stashCode);
  }

  const collectAnchorLinks = (htmlSource: string): string[] => {
    const outLinks: string[] = [];
    const seen = new Set<string>();
    replacePairedHtmlElementsLinear(htmlSource, ['a'], (_full, _t, attrStr) => {
      if (outLinks.length >= 250) return '';
      const attrs = parseTagAttrs(attrStr);
      const resolved = resolveHttpsHref(attrs.href, baseUrl);
      if (resolved && !seen.has(resolved)) {
        seen.add(resolved);
        outLinks.push(resolved);
      }
      return '';
    });
    return outLinks;
  };
  let links = collectAnchorLinks(work);
  // If `<main>` is a client-hydrated SPA shell with 0 inline `<a href>` links (or we narrowed to `<article class="markdown-body">`),
  // merge full-document links so repo/site navigation targets remain discoverable in `links`.
  if ((links.length === 0 || extractedMarkdownBodyOnly) && onlyMainContent) {
    const seenLinkSet = new Set(links);
    for (const l of collectAnchorLinks(withoutCommentsAndScripts)) {
      if (!seenLinkSet.has(l)) {
        seenLinkSet.add(l);
        links.push(l);
        if (links.length >= 250) break;
      }
    }
  }

  const isDecorativeOrTinyImage = (attrs: Record<string, string>, resolvedSrc: string): boolean => {
    const w = parseInt(attrs.width ?? '', 10);
    const h = parseInt(attrs.height ?? '', 10);
    if ((Number.isFinite(w) && w > 0 && w < 100) || (Number.isFinite(h) && h > 0 && h < 100)) {
      return true;
    }
    const hay = `${attrs.alt ?? ''} ${attrs.class ?? ''} ${attrs.id ?? ''} ${resolvedSrc}`;
    return /\b(avatar|gravatar|author[-_]?photo|author[-_]?image|1x1|pixel|spacer|badge)\b/i.test(hay) || isLazyPlaceholderImageUrl(resolvedSrc);
  };

  const images: ScrapedImage[] = [];
  const seenImages = new Set<string>();
  if (includeImages) {
    scanHtmlTagsLinear(
      work,
      (tag) => {
        if (tag.isClosing || tag.tagNameLower !== 'img') return;
        const attrs = parseTagAttrs(tag.attrs);
        const primarySrc = attrs.src && !isLazyPlaceholderImageUrl(attrs.src) ? attrs.src : undefined;
        const bestCandidate =
          primarySrc ??
          attrs['data-src'] ??
          attrs['data-lazy-src'] ??
          attrs['data-original'] ??
          extractLargestUrlFromSrcset(attrs.srcset ?? attrs['data-srcset'] ?? attrs['data-lazy-srcset']) ??
          attrs.src;
        const src = resolveHttpsHref(bestCandidate, baseUrl);
        if (src && !seenImages.has(src) && !isDecorativeOrTinyImage(attrs, src)) {
          seenImages.add(src);
          const alt = attrs.alt?.trim();
          images.push({ url: src, ...(alt ? { alt } : {}) });
          if (images.length >= 60) return false;
        }
        return undefined;
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );
  }

  const stashFence = (fenceMd: string): string => `\n\n\u0000EFFENCE${codeStash.push(fenceMd.trim()) - 1}\u0000\n\n`;
  const stashInline = (spanMd: string): string => (spanMd ? `\`\u0000EFINLINE${codeStash.push(spanMd) - 1}\u0000\`` : '');

  const formatTableCellMarkdown = (cellHtml: string): string => {
    let withInline = cellHtml.replace(/<\/a>(?=<a\b)/gi, '</a> ');
    withInline = replacePairedHtmlElementsLinear(withInline, ['code'], (_f, _t, _a, c) =>
      stashInline(formatInlineCodeSpan(cleanInlineHtml(c))),
    );
    withInline = replacePairedHtmlElementsLinear(withInline, ['strong', 'b'], (_f, _t, _a, inner) => {
      const txt = cleanInlineHtml(inner);
      return txt ? `**${txt}**` : ' ';
    });
    withInline = replacePairedHtmlElementsLinear(withInline, ['em', 'i'], (_f, _t, _a, inner) => {
      const txt = cleanInlineHtml(inner);
      return txt ? `*${txt}*` : ' ';
    });
    withInline = replacePairedHtmlElementsLinear(withInline, ['a'], (_f, _t, attrStr, inner) => {
      const attrs = parseTagAttrs(attrStr);
      const href = resolveHttpsHref(attrs.href, baseUrl, true);
      const label = cleanInlineHtml(inner);
      if (!label) return ' ';
      return href ? `[${label}](${href})` : label;
    });
    return cleanInlineHtml(withInline).replace(/\|/g, '\\|');
  };

  // Convert structural HTML to Markdown in strictly O(N) linear passes (`H1`).
  let md = replaceHtmlOpenTagsLinear(work, ['wbr'], () => '')
    .replace(/<\/a>(?=<a\b)/gi, '</a> ')
    .replace(/<\/code>(?=<code\b)/gi, '</code> ')
    .replace(/([A-Za-z0-9])(?=<a\b)/g, '$1 ');

  // Strip Expressive Code empty header figcaptions (`<figcaption class="header"><span class="title"></span><span class="sr-only">...</span></figcaption>`) linearly!
  if (/<figcaption/i.test(md)) {
    md = replacePairedHtmlElementsLinear(
      md,
      ['figcaption'],
      (full, _t, attrStr, inner) => {
        if (!/\bheader\b/i.test(attrStr)) return full;
        if (inner.length > 600) return full;
        if (/\btitle\b/i.test(inner) && /\bsr-only\b/i.test(inner)) {
          const withoutSrOnly = replacePairedHtmlElementsLinear(inner, ['span'], (sf, _st, sAttr) =>
            /\bsr-only\b/i.test(sAttr) ? '' : sf,
          );
          if (!cleanInlineHtml(withoutSrOnly)) return '';
        }
        return full;
      },
      { maxInnerChars: 600 },
    );
  }

  // `<pre>` blocks (optionally wrapping `<code ...>...</code>`)
  if (/<pre/i.test(md)) {
    md = replacePairedHtmlElementsLinear(md, ['pre'], (_full, _t, preAttrs, preInner) => {
      let codeAttrs = '';
      let rawCodeHtml = preInner;
      const trimmedPre = preInner.trim();
      if (/^<code\b/i.test(trimmedPre) && /<\/code>$/i.test(trimmedPre)) {
        replacePairedHtmlElementsLinear(trimmedPre, ['code'], (_cf, _ct, cAttrs, cInner) => {
          if (!codeAttrs) {
            codeAttrs = cAttrs;
            rawCodeHtml = cInner;
          }
          return '';
        });
      }
      const lang = inferCodeFenceLang(preAttrs, codeAttrs);
      const withEcLines =
        !rawCodeHtml.includes('\n') && rawCodeHtml.includes('ec-line')
          ? replaceHtmlOpenTagsLinear(rawCodeHtml, ['div'], (t) => (/\bec-line\b/i.test(t.attrs) ? '\n' : t.rawTag))
          : rawCodeHtml;
      const decodedCode = decodeHtmlEntities(stripHtmlTagsQuoteAwareLinear(withEcLines, '')).trim();
      return stashFence(makeSafeCodeFence(decodedCode, lang));
    });
  }

  if (/<figure/i.test(md)) {
    md = replacePairedHtmlElementsLinear(
      md,
      ['figure'],
      (full, _t, _attrs, figInner) => {
        if (/<figure\b/i.test(figInner)) return full;
        const withoutCap = stripHtmlTagsLinear(figInner, ['figcaption'], '', 8000);
        if (/<(?:pre|table|p)\b/i.test(withoutCap)) return full;
        let imgAttrs: Record<string, string> | null = null;
        scanHtmlTagsLinear(
          figInner,
          (t) => {
            if (!t.isClosing && t.tagNameLower === 'img') {
              imgAttrs = parseTagAttrs(t.attrs);
              return false;
            }
            return undefined;
          },
          8000,
        );
        if (!imgAttrs) return full;
        const ia = imgAttrs as Record<string, string>;
        const bestSrc =
          (ia.src && !isLazyPlaceholderImageUrl(ia.src) ? ia.src : undefined) ??
          ia['data-src'] ??
          extractLargestUrlFromSrcset(ia.srcset ?? ia['data-srcset']) ??
          ia.src;
        const resolvedSrc = resolveHttpsHref(bestSrc, baseUrl);
        if (!resolvedSrc || isDecorativeOrTinyImage(ia, resolvedSrc)) return full;
        const alt = cleanInlineHtml(ia.alt ?? '');
        let capText = '';
        replacePairedHtmlElementsLinear(
          figInner,
          ['figcaption'],
          (_cf, _ct, _ca, cInner) => {
            if (!capText) capText = cleanInlineHtml(cInner);
            return '';
          },
          { maxChars: 8000, maxInnerChars: 1200 },
        );
        return capText && capText !== alt
          ? `\n\n![${alt}](${resolvedSrc})\n\n*${capText}*\n\n`
          : `\n\n![${alt}](${resolvedSrc})\n\n`;
      },
      { maxInnerChars: 8000 },
    );
  }

  if (/<table/i.test(md) && Date.now() <= deadlineAt) {
    md = replacePairedHtmlElementsLinear(md, ['table'], (full, _t, _attrs, tbl) => {
      if (/<table\b/i.test(tbl)) return full;
      const rows: string[][] = [];
      replacePairedHtmlElementsLinear(tbl, ['tr'], (_rf, _rt, _ra, rInner) => {
        const cells: string[] = [];
        replacePairedHtmlElementsLinear(rInner, ['th', 'td'], (_cf, _ct, _ca, cInner) => {
          cells.push(formatTableCellMarkdown(cInner));
          return '';
        });
        rows.push(cells);
        return '';
      });
      const nonEmpty = rows.filter((r) => r.some((cell) => cell.length > 0));
      if (nonEmpty.length === 0) return '';
      const cols = Math.max(...nonEmpty.map((r) => r.length));
      const pad = (r: string[]) => Array.from({ length: cols }, (_, i) => r[i] ?? '');
      const header = `| ${pad(nonEmpty[0]!).join(' | ')} |`;
      const sep = `| ${Array.from({ length: cols }, () => '---').join(' | ')} |`;
      const bodyRows = nonEmpty.slice(1).map((r) => `| ${pad(r).join(' | ')} |`);
      return `\n\n${[header, sep, ...bodyRows].join('\n')}\n\n`;
    });
  }

  if (/<(?:code|kbd)/i.test(md)) {
    md = replacePairedHtmlElementsLinear(md, ['code', 'kbd'], (_f, _t, _a, c) =>
      stashInline(formatInlineCodeSpan(cleanInlineHtml(c))),
    );
  }

  // Convert links wrapping headings (`<a href="..."><h2>Title</h2></a>`) into `## [Title](url)` before generic `<h1>` / `<a>` rules.
  if (/<a/i.test(md) && /<h[1-6]/i.test(md)) {
    md = replacePairedHtmlElementsLinear(md, ['a'], (full, _t, attrStr, inner) => {
      const trimmed = inner.trim();
      if (!/^<h[1-6]\b/i.test(trimmed)) return full;
      let matchedHeading: { lvl: number; inner: string } | null = null;
      replacePairedHtmlElementsLinear(trimmed, ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'], (hf, ht, _ha, hInner) => {
        if (!matchedHeading && hf.length === trimmed.length) {
          matchedHeading = { lvl: Number(ht.slice(1)), inner: hInner };
        }
        return '';
      });
      if (!matchedHeading) return full;
      const mh = matchedHeading as { lvl: number; inner: string };
      const attrs = parseTagAttrs(attrStr);
      const href = resolveHttpsHref(attrs.href, baseUrl, true);
      const txt = cleanHeadingPermalinks(cleanInlineHtml(mh.inner));
      if (!txt) return '';
      const hashes = '#'.repeat(mh.lvl);
      return href ? `\n\n${hashes} [${txt}](${href})\n\n` : `\n\n${hashes} ${txt}\n\n`;
    });
  }

  if (/<h[1-6]/i.test(md)) {
    md = replacePairedHtmlElementsLinear(md, ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'], (_f, tag, _a, inner) => {
      const txt = cleanHeadingPermalinks(cleanInlineHtml(inner));
      return txt ? `\n\n${'#'.repeat(Number(tag.slice(1)))} ${txt}\n\n` : '';
    });
  }

  if (/<summary/i.test(md)) {
    md = replacePairedHtmlElementsLinear(md, ['summary'], (_f, _t, _a, inner) => {
      const txt = cleanHeadingPermalinks(
        cleanInlineHtml(inner).replace(/\s+(?:see all(?:\s+hide)?|show more(?:\s+show less)?)$/i, ''),
      );
      if (!txt) return '';
      return /^#{1,6}\s/.test(txt) ? `\n\n${txt}\n\n` : `\n\n**${txt}**\n\n`;
    });
  }

  if (/<(?:del|s|strike|mark|strong|b|em|i|a|dt|blockquote)/i.test(md)) {
    md = replacePairedHtmlElementsLinear(md, ['del', 's', 'strike'], (full, _t, _a, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(inner)) return full;
      const txt = cleanInlineHtml(inner);
      return txt ? `~~${txt}~~` : '';
    });
    md = replacePairedHtmlElementsLinear(md, ['mark'], (full, _t, _a, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(inner)) return full;
      const txt = cleanInlineHtml(inner);
      return txt ? `==${txt}==` : '';
    });
    md = replacePairedHtmlElementsLinear(md, ['strong', 'b'], (full, _t, _a, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(inner)) return full;
      const txt = cleanInlineHtml(inner);
      return txt ? `**${txt}**` : ' ';
    });
    md = replacePairedHtmlElementsLinear(md, ['em', 'i'], (full, _t, _a, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(inner)) return full;
      const txt = cleanInlineHtml(inner);
      return txt ? `*${txt}*` : ' ';
    });
    md = replacePairedHtmlElementsLinear(md, ['a'], (full, _t, attrStr, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(inner)) return full;
      const attrs = parseTagAttrs(attrStr);
      const href = resolveHttpsHref(attrs.href, baseUrl, true);
      const label = cleanInlineHtml(inner);
      if (!label) return ' ';
      return href ? `[${label}](${href})` : label;
    });
    md = replacePairedHtmlElementsLinear(
      md,
      ['dt'],
      (_f, _t, _a, inner) => {
        const compactSpans = replaceHtmlTagsQuoteAwareLinear(
          inner,
          (t) => (t.tagNameLower === 'span' ? '' : t.rawTag),
          2000,
          false,
        )
          .replace(/\*([^*\n]+)\*(?=[A-Za-z0-9_`])/g, '$1 ')
          .replace(/\*([^*\n]+)\*/g, '$1');
        const term = cleanHeadingPermalinks(cleanInlineHtml(compactSpans));
        if (!term) return '';
        if (/^\*\*[\s\S]+\*\*$/.test(term) || /^`[^`]+`$/.test(term)) {
          return `\n\n**${term.replace(/^\*\*|\*\*$/g, '')}**\n\n`;
        }
        return `\n\n**${term}**\n\n`;
      },
      { maxInnerChars: 1800 },
    );
    md = replacePairedHtmlElementsLinear(md, ['blockquote'], (_f, _t, _a, inner) => {
      const txt = cleanInlineHtml(inner);
      return txt ? `\n\n> ${txt}\n\n` : '';
    });
  }

  // Convert `<ul>`/`<ol>`/`<li>` in a single O(N) stack pass (`H1`).
  if (/<li/i.test(md)) {
    const listSrc = md;
    const listOut: string[] = [];
    let listDepth = 0;
    const liStack: Array<{ depth: number; emitted: boolean }> = [];
    let lastListIdx = 0;

    const flushListSeg = (seg: string) => {
      if (!seg) return;
      const activeLi = liStack[liStack.length - 1];
      if (!activeLi) {
        listOut.push(seg);
        return;
      }
      const indent = '  '.repeat(Math.min(3, Math.max(0, activeLi.depth - 1)));
      if (/```|~~~|\u0000(?:EFFENCE|EFCODE)\d+\u0000|^\s*(?:#{1,6}\s|\|\s|>\s)/m.test(seg)) {
        const cleanedBlock = splitMarkdownByCodeFences(seg)
          .map((p, idx) => (idx % 2 === 1 ? p : stripHtmlTagsQuoteAwareLinear(p, ' ')))
          .join('')
          .trim();
        if (!cleanedBlock) return;
        if (!activeLi.emitted) {
          listOut.push(`\n${indent}- ${cleanedBlock}`);
          activeLi.emitted = true;
        } else {
          listOut.push(`\n\n${cleanedBlock}`);
        }
        return;
      }
      const txt = cleanInlineHtml(seg);
      if (!txt) return;
      if (!activeLi.emitted) {
        listOut.push(`\n${indent}- ${txt}`);
        activeLi.emitted = true;
      } else {
        listOut.push(` ${txt}`);
      }
    };

    scanHtmlTagsLinear(
      listSrc,
      (tag) => {
        const t = tag.tagNameLower;
        if (t !== 'ul' && t !== 'ol' && t !== 'li') return;
        flushListSeg(listSrc.slice(lastListIdx, tag.index));
        lastListIdx = tag.end;
        if (!tag.isClosing && (t === 'ul' || t === 'ol')) {
          listDepth++;
        } else if (tag.isClosing && (t === 'ul' || t === 'ol')) {
          while (liStack.length > 0 && liStack[liStack.length - 1]!.depth >= listDepth) {
            liStack.pop();
          }
          listDepth = Math.max(0, listDepth - 1);
          if (listDepth === 0) listOut.push('\n\n');
        } else if (!tag.isClosing && t === 'li') {
          const targetDepth = Math.max(1, listDepth);
          while (liStack.length > 0 && liStack[liStack.length - 1]!.depth >= targetDepth) {
            liStack.pop();
          }
          liStack.push({ depth: targetDepth, emitted: false });
        } else if (tag.isClosing && t === 'li') {
          if (liStack.length > 0) liStack.pop();
        }
      },
      MAX_HTML_SCAN_CHARS,
      false,
    );
    flushListSeg(listSrc.slice(lastListIdx));
    md = listOut.join('');
  }

  if (/<a/i.test(md)) {
    md = replacePairedHtmlElementsLinear(md, ['a'], (_f, _t, attrStr, inner) => {
      const attrs = parseTagAttrs(attrStr);
      const href = resolveHttpsHref(attrs.href, baseUrl, true);
      const label = cleanInlineHtml(inner);
      if (!label) return '';
      return href ? `[${label}](${href})` : label;
    });
  }

  const blockCloseTags = new Set([
    'p',
    'div',
    'section',
    'article',
    'main',
    'ul',
    'ol',
    'dl',
    'dd',
    'dt',
    'figure',
    'figcaption',
    'tr',
    'header',
    'details',
  ]);
  const spaceCloseTags = new Set(['span', 'button', 'label', 'time', 'td', 'th']);

  md = replaceHtmlTagsQuoteAwareLinear(
    md,
    (tag) => {
      if (!tag.isClosing && tag.tagNameLower === 'hr') return '\n\n---\n\n';
      if (!tag.isClosing && tag.tagNameLower === 'br') return '\n';
      if (tag.isClosing && blockCloseTags.has(tag.tagNameLower)) return '\n\n';
      if (tag.isClosing && spaceCloseTags.has(tag.tagNameLower)) return ' ';
      return '';
    },
    MAX_HTML_SCAN_CHARS,
    true,
  )
    .replace(/\u0000EFTASKX\u0000/g, '[x]')
    .replace(/\u0000EFTASKO\u0000/g, '[ ]')
    .replace(/\u0000EFFENCE(\d+)\u0000/g, (_m, idx: string) => codeStash[Number(idx)] ?? '')
    .replace(/\u0000EFCODE(\d+)\u0000/g, (_m, idx: string) => codeStash[Number(idx)] ?? '');

  md = splitMarkdownByCodeFences(decodeMarkdownEntitiesPreservingLt(md))
    .map((part, idx) => {
      if (idx % 2 === 1) return part;
      const withCleanLinks = sanitizeAndResolveMarkdownProseLinksLinear(part, {
        baseUrl,
        includeImages,
        spaceAdjacentAlnum: true,
      });
      return withCleanLinks
        .split('\n')
        .map((line) => {
          const normalizedTask = line.replace(/^(\s*-\s+)\[\s*([xX])\s*\]/, '$1[x]');
          const listIndent = /^( {2}| {4}| {6})(-\s+\S[\s\S]*)$/.exec(normalizedTask);
          if (listIndent) {
            return `${listIndent[1]}${collapseTagBoundaryPunctuation(listIndent[2]!.replace(/[ \t]{2,}/g, ' ').trim())}`;
          }
          return collapseTagBoundaryPunctuation(normalizedTask.replace(/[ \t]{2,}/g, ' ').trim());
        })
        .filter(
          (line) =>
            !/^(was this (page )?helpful\??|yes\s*no|copy page(?:\s*copy page)*|back to top(?:\s*was this page helpful\??\s*yes\s*no)?|what could we improve on this page\?\s*submit feedback\s*skip|thanks for your feedback!?|edit this page.*|##\s+repository navigation|click to (?:show|hide) internal directories\.)$/i.test(
              line,
            ),
        )
        .join('\n')
        .replace(/\n{3,}/g, '\n\n');
    })
    .join('')
    .replace(/`\u0000EFINLINE(\d+)\u0000`/g, (_m, idx: string) => codeStash[Number(idx)] ?? '')
    // Fold standalone MDN-style language header lines (`js`, `ts`, `bash`, etc.) into the following code fence (tagged or untagged).
    .replace(
      /(^|\n\n)(js|javascript|ts|typescript|jsx|tsx|html|css|scss|json|bash|sh|shell|python|py|rust|go|sql|yaml|toml|xml|http|wasm)[ \t]*\n+```([a-z0-9_+#-]*)[ \t]*\n/gi,
      (_m, lead: string, rawLang: string, existingFenceLang: string) =>
        `${lead}\`\`\`${existingFenceLang.trim() || normalizeFenceLang(rawLang)}\n`,
    );
  if (md.slice(Math.max(0, md.length - 800)).toLowerCase().includes('help improve mdn')) {
    md = md.replace(/\n+##[ \t]+Help improve MDN\b[\s\S]{0,600}$/i, '');
  }
  md = md.replace(/\n{3,}/g, '\n\n').trim();

  let matchedSiteExtracted: PostFetchSiteResult | null = null;
  let inertiaHydrated = false;
  if (ytMeta) {
    if (ytMeta.title) title = ytMeta.title;
    if (ytMeta.description) description = ytMeta.description.slice(0, 320);
    md = ytMeta.markdown;
  } else if (hnExtracted) {
    md = hnExtracted.markdown;
    if (hnExtracted.links.length > 0) {
      const seenLinks = new Set(hnExtracted.links);
      for (const l of links) {
        if (!seenLinks.has(l) && hnExtracted.links.length < 250) {
          seenLinks.add(l);
          hnExtracted.links.push(l);
        }
      }
      links = hnExtracted.links;
    }
  } else if (onlyMainContent && (!includeTags || includeTags.length === 0) && Date.now() <= deadlineAt) {
    if (baseUrl && /^https?:\/\/github\.com\/[^/]+\/[^/]+\/(?:issues|pull)\/\d+/i.test(baseUrl)) {
      md = cleanGitHubIssueOrPrMarkdown(md);
    } else {
      const siteExtracted = applyPostFetchSiteExtractor(boundedRawHtml, baseUrl, md, (frag, fragBase) => {
        const sub = extractHtmlDocument(frag, {
          baseUrl: fragBase,
          onlyMainContent: false,
          includeImages,
        });
        return { markdown: sub.markdown, links: sub.links };
      });
      if (siteExtracted) {
        matchedSiteExtracted = siteExtracted;
        if (siteExtracted.extractorId) {
          setActiveSpanAttribute('edgefetch.adapter_id', siteExtracted.extractorId);
        }
        md = siteExtracted.markdown;
        if (siteExtracted.title) title = siteExtracted.title;
        if (siteExtracted.description && !description) description = siteExtracted.description;
        if (siteExtracted.author && !author) author = siteExtracted.author;
        if (siteExtracted.publishedTime && !publishedTime) publishedTime = siteExtracted.publishedTime;
        if (siteExtracted.links && siteExtracted.links.length > 0) {
          const seen = new Set(siteExtracted.links);
          for (const l of links) {
            if (!seen.has(l) && siteExtracted.links.length < 250) {
              seen.add(l);
              siteExtracted.links.push(l);
            }
          }
          links = siteExtracted.links;
        }
      } else if (baseUrl && /^https?:\/\/(?:export\.)?arxiv\.org\/abs\//i.test(baseUrl)) {
        md = cleanArxivAbstractMarkdown(md);
      }
    }

    // Defuddle schema.org `articleBody` & `<noscript>` SSR rescue: if DOM extraction yielded <30 words on a client-hydrated shell.
    const mdWords = countTextWords(md);
    if (mdWords < 30 && schemaMeta.articleBody) {
      const schemaWords = countTextWords(schemaMeta.articleBody);
      if (schemaWords > Math.max(40, mdWords * 2)) {
        const cleanSchemaMd = schemaMeta.articleBody.includes('<')
          ? cleanInlineHtml(schemaMeta.articleBody)
          : decodeHtmlEntities(schemaMeta.articleBody).trim();
        if (cleanSchemaMd) {
          md = title && !cleanSchemaMd.startsWith('# ') ? `# ${title}\n\n${cleanSchemaMd}` : cleanSchemaMd;
        }
      }
    } else if (mdWords < 25 && noscriptChunks.length > 0 && Date.now() <= deadlineAt) {
      const rescuedDoc = extractHtmlDocument(noscriptChunks.join('\n\n'), {
        baseUrl,
        onlyMainContent: false,
        includeImages,
      });
      if (countTextWords(rescuedDoc.markdown) > Math.max(35, mdWords * 2)) {
        md = rescuedDoc.markdown;
        if (links.length === 0 && rescuedDoc.links.length > 0) links = rescuedDoc.links;
      }
    }

    // Inertia.js SSR `data-page` hydration unlock: extract structured `component` + `props` without Chromium when prose < 50 words.
    if (
      countTextWords(md) < 50 &&
      (boundedRawHtml.includes('data-page="{&quot;component&quot;') || boundedRawHtml.includes("data-page='{\"component\""))
    ) {
      const inertiaPage = extractInertiaPagePropsLinear(boundedRawHtml);
      if (inertiaPage) {
        const inertiaDoc = formatInertiaPagePropsToMarkdown(inertiaPage, baseUrl, (frag, fragBase) => {
          const sub = extractHtmlDocument(frag, {
            baseUrl: fragBase,
            onlyMainContent: false,
            includeImages,
          });
          return { markdown: sub.markdown, links: sub.links };
        });
        if (inertiaDoc && inertiaDoc.markdown.trim()) {
          md = inertiaDoc.markdown;
          if (inertiaDoc.title && !title) title = inertiaDoc.title;
          if (inertiaDoc.description && !description) description = inertiaDoc.description;
          inertiaHydrated = true;
        }
      }
    }
  }

  let plainText = ytMeta
    ? ytMeta.markdown
    : hnExtracted
      ? hnExtracted.markdown
      : inertiaHydrated
        ? md
        : cleanInlineHtml(work);
  if (redactPii) {
    md = redactPiiText(md);
    plainText = redactPiiText(plainText);
  }
  const strippedDocMd = hardenMarkdownFenceStructure(stripInvisibleSmugglingChars(md));
  const detachedDocMd = strippedDocMd.includes('`')
    ? splitMarkdownByCodeFences(strippedDocMd)
        .map((part, idx) => (idx % 2 === 1 ? part : detachBareUrlsFromCodeSpansLinear(part)))
        .join('')
    : strippedDocMd;
  md = escapeResidualHtmlOutsideCodeLinear(detachedDocMd, false);
  plainText = stripInvisibleSmugglingChars(plainText);
  const wordCount = countTextWords(md);

  return {
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    ...(author ? { author } : {}),
    ...(publishedTime ? { publishedTime } : {}),
    ...(modifiedTime ? { modifiedTime } : {}),
    ...(siteName ? { siteName } : {}),
    ...(wordCount > 0 ? { wordCount } : {}),
    ...(language ? { language } : {}),
    ...(canonicalUrl ? { canonicalUrl } : {}),
    ...(markdownAlternateUrl ? { markdownAlternateUrl } : {}),
    ...(favicon ? { favicon } : {}),
    ...(matchedSiteExtracted?.extractorId ? { extractorId: matchedSiteExtracted.extractorId } : {}),
    ...(matchedSiteExtracted?.records !== undefined ? { records: matchedSiteExtracted.records } : {}),
    ...(matchedSiteExtracted?.pagination !== undefined ? { pagination: matchedSiteExtracted.pagination } : {}),
    ...(matchedSiteExtracted?.total !== undefined ? { total: matchedSiteExtracted.total } : {}),
    ...(matchedSiteExtracted?.returned !== undefined ? { returned: matchedSiteExtracted.returned } : {}),
    ...(matchedSiteExtracted?.truncated !== undefined ? { truncated: matchedSiteExtracted.truncated } : {}),
    ...(matchedSiteExtracted?.nextCursor !== undefined ? { nextCursor: matchedSiteExtracted.nextCursor } : {}),
    ...(inertiaHydrated ? { inertiaHydrated: true } : {}),
    markdown: md,
    text: plainText,
    links,
    images,
    branding: {
      ...(title ? { title } : {}),
      ...(description ? { description } : {}),
      ...(canonicalUrl ? { canonicalUrl } : {}),
      ...(favicon ? { favicon } : {}),
      ...(logo ? { logo } : {}),
      ...(ogImage ? { ogImage } : {}),
      ...(themeColor ? { themeColor } : {}),
      ...(colors.length > 0 ? { colors } : {}),
      ...(fonts.length > 0 ? { fonts } : {}),
    },
  };
}

const INERTIA_SKIP_PROP_KEYS = new Set([
  'errors',
  'flash',
  'ziggy',
  'csrf_token',
  '_token',
  'jetstream',
  'locale',
  'locales',
  'translations',
  '__inertia',
]);

/**
 * Renders an Inertia.js `data-page` payload (`{ component, props, url, version }`) into a clean GFM summary
 * of the component and its non-boilerplate props so Laravel/Rails Inertia apps extract without Chromium.
 */
export function formatInertiaPagePropsToMarkdown(
  inertiaObj: Record<string, unknown>,
  baseUrl?: string,
  htmlToMd?: (frag: string, base?: string) => { markdown: string; links: string[] },
): { title?: string; description?: string; markdown: string } | null {
  const component = typeof inertiaObj.component === 'string' ? inertiaObj.component.trim() : '';
  if (!component) return null;
  const rawProps =
    inertiaObj.props && typeof inertiaObj.props === 'object' && !Array.isArray(inertiaObj.props)
      ? (inertiaObj.props as Record<string, unknown>)
      : {};

  let bestTitle = '';
  let bestDescription = '';
  let visited = 0;

  const escapeCell = (val: unknown): string =>
    String(val ?? '')
      .replace(/\r?\n+/g, ' ')
      .replace(/\|/g, '\\|')
      .trim()
      .slice(0, 160);

  const convertRichString = (raw: string): string => {
    const trimmed = raw.trim();
    if (!trimmed) return '';
    if (htmlToMd && /<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|em|a|table|blockquote)\b/i.test(trimmed)) {
      return htmlToMd(trimmed, baseUrl).markdown.trim();
    }
    return trimmed;
  };

  const renderObjectFields = (obj: Record<string, unknown>, depth: number): string[] => {
    if (depth > 3 || visited > 400) return [];
    const bullets: string[] = [];
    const subBlocks: string[] = [];
    for (const [k, v] of Object.entries(obj)) {
      if (visited++ > 400) break;
      const lower = k.toLowerCase();
      if (INERTIA_SKIP_PROP_KEYS.has(lower) || v === null || v === undefined || v === '') continue;
      if (lower === 'auth' && typeof v === 'object' && !Array.isArray(v) && !(v as Record<string, unknown>).user) {
        continue;
      }
      if (typeof v === 'string') {
        const clean = v.trim();
        if (!clean) continue;
        if (!bestTitle && (lower === 'title' || lower === 'pagetitle' || lower === 'headline' || lower === 'name') && clean.length <= 180) {
          bestTitle = clean;
        }
        if (!bestDescription && (lower === 'description' || lower === 'summary' || lower === 'excerpt') && clean.length >= 20 && clean.length <= 400 && !/<[a-z]/i.test(clean)) {
          bestDescription = clean;
        }
        const isProse =
          clean.length >= 80 ||
          lower === 'body' ||
          lower === 'content' ||
          lower === 'markdown' ||
          lower === 'html' ||
          lower === 'descriptionhtml';
        if (isProse && /\s/.test(clean)) {
          const rich = convertRichString(clean);
          if (rich) subBlocks.push(rich);
        } else {
          bullets.push(`- **${k}**: ${clean.slice(0, 300)}`);
        }
      } else if (typeof v === 'number' || typeof v === 'boolean') {
        bullets.push(`- **${k}**: ${String(v)}`);
      } else if (Array.isArray(v) && v.length > 0) {
        const slice = v.slice(0, 40);
        if (slice.every((it) => typeof it === 'string' || typeof it === 'number' || typeof it === 'boolean')) {
          bullets.push(`- **${k}**: ${slice.map(String).join(', ')}`);
        } else if (slice.every((it) => it && typeof it === 'object' && !Array.isArray(it))) {
          const firstRow = slice[0] as Record<string, unknown>;
          const cols = Object.keys(firstRow)
            .filter((ck) => {
              const cv = firstRow[ck];
              return typeof cv === 'string' || typeof cv === 'number' || typeof cv === 'boolean';
            })
            .slice(0, 6);
          if (cols.length >= 2) {
            const header = `| ${cols.map(escapeCell).join(' | ')} |`;
            const sep = `| ${cols.map(() => '---').join(' | ')} |`;
            const rows = slice.map((it) => {
              const r = it as Record<string, unknown>;
              return `| ${cols.map((c) => escapeCell(r[c])).join(' | ')} |`;
            });
            subBlocks.push(`### ${k}\n\n${[header, sep, ...rows].join('\n')}`);
          } else {
            const itemLines: string[] = [];
            for (const it of slice) {
              const r = it as Record<string, unknown>;
              const label = String(r.title ?? r.name ?? r.label ?? r.id ?? '').trim();
              const desc = typeof r.body === 'string' ? convertRichString(r.body) : typeof r.description === 'string' ? convertRichString(r.description) : '';
              if (label && desc) itemLines.push(`- **${label}**: ${desc.slice(0, 400)}`);
              else if (label) itemLines.push(`- ${label}`);
            }
            if (itemLines.length > 0) subBlocks.push(`### ${k}\n\n${itemLines.join('\n')}`);
          }
        }
      } else if (typeof v === 'object' && !Array.isArray(v) && depth < 2) {
        const nestedParts = renderObjectFields(v as Record<string, unknown>, depth + 1);
        if (nestedParts.length > 0) {
          subBlocks.push(`${depth === 0 ? '##' : '###'} ${k}\n\n${nestedParts.join('\n\n')}`);
        }
      }
    }
    const out: string[] = [];
    if (bullets.length > 0) out.push(bullets.join('\n'));
    out.push(...subBlocks);
    return out;
  };

  const propSections = renderObjectFields(rawProps, 0);
  if (propSections.length === 0) return null;

  const headingTitle = bestTitle || component.replace(/\//g, ' — ');
  const sections = [`# ${headingTitle}`, `- **Inertia Component**: \`${component}\``, ...propSections];
  return {
    ...(bestTitle ? { title: bestTitle } : {}),
    ...(bestDescription ? { description: bestDescription } : {}),
    markdown: sections.join('\n\n').trim(),
  };
}

const COMPANION_MD_TTL_MS = 30 * 60_000;
const MAX_COMPANION_MD_ENTRIES = 2_048;
const companionMdUrlCache = new Map<string, { mdUrl: string; expiresAt: number }>();

export function resetCompanionMdCacheForTests(): void {
  companionMdUrlCache.clear();
}

export function recordCompanionMdUrl(mdUrlStr: string, now = Date.now()): void {
  if (!mdUrlStr || !/\.md$/i.test(mdUrlStr)) return;
  let u: URL;
  try {
    u = new URL(mdUrlStr);
  } catch {
    return;
  }
  if (u.protocol !== 'https:' || u.search || u.hash) return;
  const cleanMd = u.toString();
  const keys: string[] = [];
  if (/\/index\.md$/i.test(u.pathname)) {
    const dirWithSlash = `${u.origin}${u.pathname.slice(0, -'index.md'.length)}`;
    keys.push(dirWithSlash);
    if (dirWithSlash.endsWith('/') && dirWithSlash.length > u.origin.length + 1) {
      keys.push(dirWithSlash.slice(0, -1));
    }
  } else {
    const withoutExt = `${u.origin}${u.pathname.slice(0, -3)}`;
    keys.push(withoutExt, `${withoutExt}/`);
  }
  const expiresAt = now + COMPANION_MD_TTL_MS;
  for (const key of keys) {
    if (companionMdUrlCache.size >= MAX_COMPANION_MD_ENTRIES && !companionMdUrlCache.has(key)) {
      const oldest = companionMdUrlCache.keys().next().value;
      if (oldest !== undefined) companionMdUrlCache.delete(oldest);
    }
    companionMdUrlCache.set(key, { mdUrl: cleanMd, expiresAt });
  }
}

export function lookupCompanionMdUrl(pageUrlStr: string, now = Date.now()): string | undefined {
  if (!pageUrlStr || /\.md(?:$|[?#])/i.test(pageUrlStr)) return undefined;
  let key = pageUrlStr;
  try {
    const u = new URL(pageUrlStr);
    u.hash = '';
    key = u.toString();
  } catch {
    return undefined;
  }
  const hit = companionMdUrlCache.get(key);
  if (!hit) return undefined;
  if (now >= hit.expiresAt) {
    companionMdUrlCache.delete(key);
    return undefined;
  }
  return hit.mdUrl;
}

function recordCompanionMdLinksFromLlmsPayload(llmsPayload: unknown, now = Date.now()): void {
  if (!llmsPayload || typeof llmsPayload !== 'object') return;
  const obj = llmsPayload as {
    companionMdUrl?: unknown;
    matchedEntry?: { url?: unknown };
    relatedLinks?: Array<{ url?: unknown }>;
  };
  if (typeof obj.companionMdUrl === 'string') recordCompanionMdUrl(obj.companionMdUrl, now);
  if (typeof obj.matchedEntry?.url === 'string') recordCompanionMdUrl(obj.matchedEntry.url, now);
  if (Array.isArray(obj.relatedLinks)) {
    for (const rel of obj.relatedLinks) {
      if (typeof rel?.url === 'string') recordCompanionMdUrl(rel.url, now);
    }
  }
}

/** Parses `/llms.txt` Markdown index files per https://llmstxt.org/, rejecting HTML 200 soft-404 pages. */
export function parseLlmsTxt(raw: string, sourceUrl: string): ParsedLlmsTxt | null {
  const trimmed = raw.trim();
  if (trimmed.length < 8) return null;
  const prefix = trimmed.slice(0, 256).toLowerCase();
  if (prefix.startsWith('<!doctype') || prefix.startsWith('<html') || prefix.includes('<body')) {
    return null;
  }

  let title: string | undefined;
  const summaryLines: string[] = [];
  let section: string | undefined;
  let fullTxtUrl: string | undefined;
  const links: LlmsLinkItem[] = [];
  const itemRe = /^[-*]\s+\[([^\]]+)\]\(([^)]+)\)(?:\s*:\s*(.*))?$/;

  for (const rawLine of trimmed.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('# ') && !title) {
      title = line.slice(2).trim();
      continue;
    }
    if (line.startsWith('## ')) {
      section = line.slice(3).trim();
      continue;
    }
    if (line.startsWith('>') && !section && summaryLines.length < 4) {
      summaryLines.push(line.replace(/^>+\s*/, '').trim());
      continue;
    }
    const m = itemRe.exec(line);
    if (m) {
      const resolved = resolveHttpsHref(m[2], sourceUrl);
      if (!resolved) continue;
      if (resolved.toLowerCase().endsWith('/llms-full.txt') && !fullTxtUrl) {
        fullTxtUrl = resolved;
      }
      if (links.length < 500) {
        links.push({
          ...(section ? { section } : {}),
          title: m[1]!.trim(),
          url: resolved,
          ...(m[3]?.trim() ? { notes: m[3].trim() } : {}),
        });
      }
      if (resolved.toLowerCase().endsWith('.md')) {
        recordCompanionMdUrl(resolved);
      }
    }
  }

  const summary = summaryLines.join(' ').trim() || undefined;
  if (!title && !summary && links.length === 0) return null;
  return {
    sourceUrl,
    ...(title ? { title } : {}),
    ...(summary ? { summary } : {}),
    ...(fullTxtUrl ? { fullTxtUrl } : {}),
    links,
  };
}

/**
 * Deterministic schema-guided structured JSON extractor (`formats: [{ type: 'json', schema }]`).
 * Inspects JSON-LD (`application/ld+json`), meta tags, and Markdown key/value lines without calling external LLMs.
 */
export function extractStructuredJsonFromPage(
  rawHtml: string,
  doc: ExtractedDocument,
  schema?: Record<string, unknown>,
): Record<string, unknown> {
  const jsonLdObjects = flattenJsonLdEntities(rawHtml);

  const props = (schema?.properties ?? undefined) as Record<string, { type?: string }> | undefined;
  if (!props || typeof props !== 'object') {
    return {
      ...(doc.title ? { title: doc.title } : {}),
      ...(doc.description ? { description: doc.description } : {}),
      ...(jsonLdObjects.length > 0 ? { jsonLd: jsonLdObjects } : {}),
    };
  }

  const out: Record<string, unknown> = {};
  for (const [propName, propSpec] of Object.entries(props)) {
    const lowerProp = propName.toLowerCase();
    let val: unknown;

    for (const ld of jsonLdObjects) {
      for (const [k, v] of Object.entries(ld)) {
        if (k.toLowerCase() === lowerProp && v !== undefined && v !== null) {
          val = v;
          break;
        }
      }
      if (val !== undefined) break;
    }

    if (val === undefined) {
      const mdWithoutFences = doc.markdown
        ? splitMarkdownByCodeFences(doc.markdown)
            .filter((_, idx) => idx % 2 === 0)
            .join('')
        : '';
      const mdScanSlice = doc.markdown ? doc.markdown.slice(0, 65_536) : '';
      if (lowerProp === 'title' || lowerProp === 'name' || lowerProp === 'headline') val = doc.title;
      else if (lowerProp === 'description' || lowerProp === 'summary' || lowerProp === 'overview') {
        val = doc.description;
        if (!val && mdWithoutFences) {
          const proseBlocks = mdWithoutFences
            .split(/\n{2,}/)
            .map((b) => b.trim())
            .filter(
              (b) =>
                b.length >= 30 &&
                !/^(?:#{1,6}\s|>|\||[-*]\s|\d+\.\s|!\[)/.test(b),
            );
          if (proseBlocks[0]) {
            val = stripMarkdownLinksToLabelsLinear(proseBlocks[0]).replace(/\s+/g, ' ').trim().slice(0, 500);
          }
        }
      } else if (lowerProp === 'url' || lowerProp === 'canonicalurl') val = doc.canonicalUrl;
      else if (lowerProp === 'links') val = doc.links;
      else if (lowerProp === 'images') val = doc.images.map((i) => i.url);
      else if (propSpec?.type === 'array' && mdWithoutFences) {
        const cleanMd = mdWithoutFences;
        if (/headings|sections|topics/i.test(propName)) {
          const headings = [...cleanMd.matchAll(/^#{2,3}[ \t]+(.+)$/gm)]
            .map((m) => stripMarkdownLinksToLabelsLinear(m[1]!).trim())
            .filter(Boolean)
            .slice(0, 20);
          if (headings.length > 0) val = headings;
        } else {
          const propWords = propName
            .replace(/([a-z])([A-Z])/g, '$1 $2')
            .toLowerCase()
            .split(/[^a-z0-9]+/)
            .filter((w) => w.length >= 3 && w !== 'key' && w !== 'main' && w !== 'all');
          const lines = cleanMd.split(/\r?\n/);
          const collectBullets = (subset: string[]): string[] =>
            subset
              .map((l) => /^(?:[-*]|\d+\.)[ \t]+(.+)$/.exec(l.trim())?.[1] ?? '')
              .map((s) => stripMarkdownLinksToLabelsLinear(s).replace(/\*{1,2}([^*\n]+)\*{1,2}/g, '$1').trim())
              .filter((s) => s.length >= 4)
              .slice(0, 15);
          if (propWords.length > 0) {
            for (let i = 0; i < lines.length; i++) {
              const hm = /^#{1,4}[ \t]+(.+)$/.exec(lines[i]!.trim());
              if (hm && propWords.some((w) => hm[1]!.toLowerCase().includes(w))) {
                const sectionLines: string[] = [];
                for (let j = i + 1; j < lines.length; j++) {
                  if (/^#{1,3}[ \t]+/.test(lines[j]!.trim())) break;
                  sectionLines.push(lines[j]!);
                }
                const secBullets = collectBullets(sectionLines);
                if (secBullets.length > 0) {
                  val = secBullets;
                  break;
                }
              }
            }
          }
          if (val === undefined) {
            const allBullets = collectBullets(lines);
            if (allBullets.length > 0) val = allBullets;
          }
        }
      } else if (propName.length <= 80 && /[A-Za-z0-9]/.test(propName)) {
        const trimmedKey = propName.replace(/^[\s_-]+|[\s_-]+$/g, '');
        if (trimmedKey && /[A-Za-z0-9]/.test(trimmedKey) && mdScanSlice) {
          const fuzzyKey = escapeRegexLiteral(trimmedKey)
            .replace(/([a-z0-9])([A-Z])/g, '$1[ \\t_-]{0,8}$2')
            .replace(/(?:\\_|\\-)+|[_-\s]+/g, '[ \\t_-]{0,8}');
          const kvRe = new RegExp(
            `(?:^|\\n)[ \\t]{0,32}(?:[-*][ \\t]{0,16})?\\*{0,2}${fuzzyKey}\\*{0,2}[ \\t]{0,16}:[ \\t]{0,16}([^\\r\\n]{1,500})`,
            'i',
          );
          const m = kvRe.exec(mdScanSlice);
          if (m?.[1]) {
            val = m[1].replace(/^`([^`]+)`$/, '$1').trim();
          }
        }
        if (val === undefined && /^(?:version|latestversion|currentversion|release)$/i.test(lowerProp)) {
          const verFromHeading =
            /^#{1,2}[ \t]+[^\r\n#]{0,120}?\bv?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)\b/m.exec(mdScanSlice)?.[1] ??
            /\bv?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)\b/.exec(doc.title ?? '')?.[1];
          if (verFromHeading) val = verFromHeading;
        }
        if (val === undefined && /^(?:installcommand|install|installation)$/i.test(lowerProp) && propSpec?.type !== 'array') {
          const installMatch =
            /\b((?:pip3?|uv[ \t]+(?:pip[ \t]+install|add)|poetry[ \t]+add|conda[ \t]+install|npm[ \t]+(?:install|i|add|create)|pnpm[ \t]+(?:add|install|i|create)|yarn[ \t]+(?:add|create)|bun[ \t]+(?:add|install|i|create)|cargo[ \t]+(?:add|install)|go[ \t]+(?:get|install)|brew[ \t]+install|gem[ \t]+install|composer[ \t]+require|dotnet[ \t]+add[ \t]+package)[ \t]+[^\r\n`"'|;]{1,120})/i.exec(
              mdScanSlice,
            );
          if (installMatch?.[1]) {
            val = installMatch[1].replace(/[ \t]+#.*$/, '').trim();
          }
        }
        if (val === undefined && /^(?:license|spdxlicense)$/i.test(lowerProp)) {
          const licHeading =
            /(?:^|\n)(?:#{1,4}[ \t]*License|\*\*License\*\*|License[ \t]*:)[ \t]*\r?\n+([^\r\n#|]{2,120})/i.exec(mdScanSlice)?.[1] ??
            /\b((?:MIT|Apache-2\.0|Apache[ \t]+Software[ \t]+License|BSD-[23]-Clause|BSD[ \t]+License|GPL-[23]\.0(?:-only|-or-later)?|LGPL-[23]\.[01]|MPL-2\.0|ISC|Unlicense)(?:[ \t]*\([^)\r\n]{1,40}\))?)\b/i.exec(
              mdScanSlice,
            )?.[1];
          if (licHeading) {
            val = stripMarkdownLinksToLabelsLinear(licHeading.replace(/^[-*][ \t]+/, '')).trim();
          }
        }
      }
    }

    if (val !== undefined) {
      if (propSpec?.type === 'number' && typeof val === 'string') {
        const num = Number(val.replace(/[^0-9.-]/g, ''));
        if (Number.isFinite(num)) val = num;
      } else if (propSpec?.type === 'boolean' && typeof val === 'string') {
        val = /^(true|yes|1)$/i.test(val.trim());
      }
      out[propName] = val;
    }
  }
  return out;
}

export type DeriveDocumentResult =
  | {
      status: 'derived' | 'cached';
      documentId: string;
      contentSha256: string;
      pipelineVersion: number;
      r2Key: string;
      bytes: number;
      title?: string;
      language?: string;
      markdown?: string;
    }
  | {
      status: 'unverified' | 'expired' | 'unsupported';
      contentSha256: string;
    };

export function extractPdfTitle(md: string, urlStr?: string): string | undefined {
  const head = md.slice(0, 2_400).replace(/\r\n/g, '\n');
  const paragraphs = head
    .split(/\n\s*\n/)
    .map((p) => p.trim())
    .filter(Boolean)
    .slice(0, 6);

  const isBoilerplateParagraph = (p: string): boolean =>
    /\b(?:hereby grants permission|proper attribution|all rights reserved|copyright\s+(?:©|\(c\)|\d{4})|published as a conference paper|under review as a conference paper|proceedings of the|preprint\.\s+under review|journalistic or\s+scholarly works)\b/i.test(
      p,
    );

  const candidateParagraphs = paragraphs.filter((p) => !isBoilerplateParagraph(p));
  const scanLines = (candidateParagraphs.length > 0 ? candidateParagraphs : paragraphs).flatMap((p) => p.split('\n'));

  for (const rawLine of scanLines.slice(0, 14)) {
    const line = rawLine.replace(/^#+\s*/, '').replace(/\s+/g, ' ').trim();
    if (!line || line.length < 3 || line.length > 120) continue;
    if (/^(?:page\s+\d+|\d+|https?:\/\/|table of contents|arxiv:\s*\d)/i.test(line)) continue;
    if (/^[A-Z][A-Z\s&.'-]{3,80}$/.test(line) && !/[a-z]/.test(line)) {
      return line
        .toLowerCase()
        .replace(/\b([a-z])/g, (_m, c: string) => c.toUpperCase());
    }
    return line;
  }
  if (urlStr) {
    try {
      const seg = safeDecodeURIComponent(new URL(urlStr).pathname.split('/').pop() ?? '').replace(/\.pdf$/i, '');
      if (seg) return seg.replace(/[-_]+/g, ' ').trim();
    } catch {
      // ignore
    }
  }
  return undefined;
}

export function formatVcardToMarkdown(raw: string): { title?: string; markdown: string } {
  const unfolded = raw.replace(/\r?\n[ \t]/g, '');
  let fullName = '';
  const bullets: string[] = [];
  for (const rawLine of unfolded.split(/\r?\n/)) {
    const colon = rawLine.indexOf(':');
    if (colon <= 0) continue;
    const keyPart = rawLine.slice(0, colon).split(';')[0]!.trim().toUpperCase();
    const val = rawLine
      .slice(colon + 1)
      .replace(/\\n/gi, ', ')
      .replace(/\\([,;\\])/g, '$1')
      .trim();
    if (!val || keyPart === 'BEGIN' || keyPart === 'END' || keyPart === 'VERSION' || keyPart === 'PRODID') continue;
    if (keyPart === 'FN' && !fullName) {
      fullName = val;
    } else if (keyPart === 'TITLE') {
      bullets.push(`- **Title**: ${val}`);
    } else if (keyPart === 'ORG') {
      bullets.push(`- **Organization**: ${val.replace(/;/g, ' · ')}`);
    } else if (keyPart === 'EMAIL') {
      bullets.push(`- **Email**: ${val}`);
    } else if (keyPart === 'TEL') {
      bullets.push(`- **Phone**: ${val}`);
    } else if (keyPart === 'URL') {
      bullets.push(`- **URL**: ${val}`);
    } else if (keyPart === 'ADR') {
      const cleanAdr = val
        .split(';')
        .map((s) => s.trim())
        .filter(Boolean)
        .join(', ');
      if (cleanAdr) bullets.push(`- **Location**: ${cleanAdr}`);
    } else if (keyPart === 'NOTE') {
      bullets.push(`- **Note**: ${val}`);
    }
  }
  const heading = fullName ? `# ${fullName}` : '# Contact Card (vCard)';
  return {
    ...(fullName ? { title: fullName } : {}),
    markdown: [heading, '', ...bullets].join('\n').trim(),
  };
}

/**
 * Derives clean Markdown from a VERIFIED stored R2 artifact (`isContentVerifiedInMetaD1 === true`), writes the derived
 * Markdown to `derived/<pipelineVersion>/markdown/<contentSha256>` in `ARTIFACTS` R2, and upserts `META` D1 `documents`.
 */
export async function deriveMarkdownDocument(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  blobSha256: string;
  contentSha256: string;
  contentType?: string;
  baseUrl?: string;
  pipelineVersion?: number;
  now?: number;
  alreadyVerified?: boolean;
  preloadedBytes?: Uint8Array;
  includeMarkdown?: boolean;
}): Promise<DeriveDocumentResult> {
  const {
    bucket,
    metaDb,
    blobSha256,
    contentSha256,
    contentType = 'text/html',
    baseUrl,
    pipelineVersion = SCRAPE_PIPELINE_VERSION,
    now = Date.now(),
    alreadyVerified = false,
    preloadedBytes,
    includeMarkdown = false,
  } = params;

  if (!isValidSha256Hex(contentSha256) || !isValidSha256Hex(blobSha256)) {
    return { status: 'unverified', contentSha256 };
  }

  // SECURITY GATE: Never derive or index unverified agent claims.
  if (!alreadyVerified) {
    const verified = await isContentVerifiedInMetaD1(metaDb, contentSha256);
    if (!verified) {
      return { status: 'unverified', contentSha256 };
    }
  }

  const ctLower = contentType.toLowerCase();
  if (
    ctLower &&
    !ctLower.startsWith('text/') &&
    !ctLower.includes('html') &&
    !ctLower.includes('markdown') &&
    !ctLower.includes('xml') &&
    !ctLower.includes('json') &&
    !(baseUrl && isLikelyPdfUrl(baseUrl))
  ) {
    return { status: 'unsupported', contentSha256 };
  }

  const r2Key = r2DerivedKey(pipelineVersion, 'markdown', contentSha256);
  const docId = `doc_${(await sha256HexString(`${contentSha256}:markdown:${pipelineVersion}`)).slice(0, 32)}`;

  const existingDoc = await metaDb
    .prepare(
      `SELECT id, r2_key, bytes, title, language
       FROM documents
       WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version = ?
       LIMIT 1`,
    )
    .bind(contentSha256, pipelineVersion)
    .first<{ id: string; r2_key: string; bytes: number; title: string | null; language: string | null }>();

  if (existingDoc) {
    if (includeMarkdown) {
      const cachedObj = await bucket.get(existingDoc.r2_key);
      if (cachedObj) {
        const cachedMd = await cachedObj.text();
        return {
          status: 'cached',
          documentId: existingDoc.id,
          contentSha256,
          pipelineVersion,
          r2Key: existingDoc.r2_key,
          bytes: existingDoc.bytes,
          ...(existingDoc.title ? { title: existingDoc.title } : {}),
          ...(existingDoc.language ? { language: existingDoc.language } : {}),
          markdown: cachedMd,
        };
      }
    } else if ((await bucket.head(existingDoc.r2_key)) !== null) {
      return {
        status: 'cached',
        documentId: existingDoc.id,
        contentSha256,
        pipelineVersion,
        r2Key: existingDoc.r2_key,
        bytes: existingDoc.bytes,
        ...(existingDoc.title ? { title: existingDoc.title } : {}),
        ...(existingDoc.language ? { language: existingDoc.language } : {}),
      };
    }
  }

  let rawBytes: Uint8Array;
  if (preloadedBytes) {
    rawBytes = preloadedBytes;
  } else {
    const loaded = await readVerifiedArtifactFromR2({
      bucket,
      blobSha256,
      preferredRetention: 'stored',
      expectedContentSha256: contentSha256,
    });
    if (!loaded.ok) {
      return { status: 'expired', contentSha256 };
    }
    rawBytes = loaded.bytes;
  }
  if (hasPdfMagicHeader(rawBytes)) {
    return { status: 'unsupported', contentSha256 };
  }

  const rawText = new TextDecoder('utf-8', { fatal: false }).decode(rawBytes);
  if (detectUnsupportedBinaryPayload({ rawBody: rawText, contentType, url: baseUrl })) {
    return { status: 'unsupported', contentSha256 };
  }
  let markdown: string;
  let title: string | undefined;
  let language: string | undefined;

  if (ctLower.includes('html') || /^\s*<!doctype\s+html|^\s*<html/i.test(rawText)) {
    const extracted = extractHtmlDocument(rawText, { baseUrl, onlyMainContent: true });
    markdown = extracted.markdown;
    title = extracted.title;
    language = extracted.language;
  } else if (ctLower.includes('vcard') || /^BEGIN:VCARD\b/im.test(rawText.trim())) {
    const vc = formatVcardToMarkdown(rawText);
    markdown = vc.markdown;
    title = vc.title;
  } else if (ctLower.includes('calendar') || /^BEGIN:VCALENDAR\b/im.test(rawText.trim())) {
    const ics = formatIcalendarToMarkdown(rawText);
    markdown = ics ? ics.markdown : rawText.trim();
    title = ics?.title;
  } else {
    const feedDoc = formatFeedXmlToMarkdown(rawText, baseUrl);
    const jsonDoc = !feedDoc ? tryParseJsonPayloadForScrape(rawText, contentType, baseUrl ?? '') : null;
    const csvDoc = !feedDoc && !jsonDoc ? formatDelimitedTableToMarkdown(rawText, contentType, baseUrl) : null;
    const patchDoc = !feedDoc && !jsonDoc && !csvDoc ? formatGitPatchToMarkdown(rawText, contentType, baseUrl) : null;
    const srcDoc = !feedDoc && !jsonDoc && !csvDoc && !patchDoc ? formatSourceCodeUrlToMarkdown(rawText, contentType, baseUrl) : null;
    if (feedDoc) {
      markdown = feedDoc.markdown;
      title = feedDoc.title;
    } else if (jsonDoc) {
      markdown = jsonDoc.markdown;
      title = jsonDoc.title;
    } else if (csvDoc) {
      markdown = csvDoc.markdown;
      title = csvDoc.title;
    } else if (patchDoc) {
      markdown = patchDoc.markdown;
      title = patchDoc.title;
    } else if (srcDoc) {
      markdown = srcDoc.markdown;
      title = srcDoc.title;
    } else {
      const isPdfDoc = Boolean(baseUrl && isLikelyPdfUrl(baseUrl));
      const fm = isPdfDoc ? { body: rawText.trim() } : parseMarkdownFrontmatter(rawText.trim());
      title = fm.title;
      let cleaned = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(fm.body), baseUrl);
      if (isPdfDoc) {
        cleaned = cleanPdfMarkdown(cleaned);
      }
      markdown = cleaned.trim();
      if (!title && markdown) {
        title = isPdfDoc
          ? extractPdfTitle(markdown, baseUrl)
          : extractMarkdownLinksAndImages(markdown, baseUrl ?? 'https://example.com/', false).title;
      }
    }
  }

  const mdBytes = new TextEncoder().encode(markdown);
  await bucket.put(r2Key, mdBytes, {
    httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
    customMetadata: {
      contentSha256,
      pipelineVersion: String(pipelineVersion),
      ...(title ? { title: title.slice(0, 200) } : {}),
    },
  });

  await metaDb
    .prepare(
      `INSERT INTO documents (id, content_sha256, format, pipeline_version, r2_key, title, language, bytes, created_at)
       VALUES (?, ?, 'markdown', ?, ?, ?, ?, ?, ?)
       ON CONFLICT(content_sha256, format, pipeline_version) DO UPDATE SET
         r2_key = excluded.r2_key,
         title = COALESCE(excluded.title, documents.title),
         language = COALESCE(excluded.language, documents.language),
         bytes = excluded.bytes`,
    )
    .bind(docId, contentSha256, pipelineVersion, r2Key, title ?? null, language ?? null, mdBytes.byteLength, now)
    .run();

  return {
    status: 'derived',
    documentId: docId,
    contentSha256,
    pipelineVersion,
    r2Key,
    bytes: mdBytes.byteLength,
    ...(title ? { title } : {}),
    ...(language ? { language } : {}),
    ...(includeMarkdown ? { markdown } : {}),
  };
}

export async function lookupCachedScrape(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  url: string;
  maxAgeMs: number;
  pipelineVersion?: number;
  now?: number;
}): Promise<{
  markdown: string;
  contentSha256: string;
  documentId: string;
  pipelineVersion: number;
  title?: string;
  language?: string;
  status: number;
  lastFetchedAt: number;
} | null> {
  const { bucket, metaDb, url, maxAgeMs, pipelineVersion = SCRAPE_PIPELINE_VERSION, now = Date.now() } = params;
  if (!(maxAgeMs > 0)) return null;

  const pageRow = await metaDb
    .prepare(
      `SELECT latest_status, latest_outcome, latest_content_sha256, last_fetched_at
       FROM pages
       WHERE url = ?
       LIMIT 1`,
    )
    .bind(url)
    .first<{
      latest_status: number | null;
      latest_outcome: string | null;
      latest_content_sha256: string | null;
      last_fetched_at: number | null;
    }>();

  if (
    !pageRow ||
    pageRow.latest_outcome !== 'ok' ||
    !pageRow.latest_content_sha256 ||
    !pageRow.last_fetched_at ||
    now - pageRow.last_fetched_at > maxAgeMs
  ) {
    return null;
  }

  const [verified, docRow] = await Promise.all([
    isContentVerifiedInMetaD1(metaDb, pageRow.latest_content_sha256),
    metaDb
      .prepare(
        `SELECT id, r2_key, title, language
         FROM documents
         WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version = ?
         LIMIT 1`,
      )
      .bind(pageRow.latest_content_sha256, pipelineVersion)
      .first<{ id: string; r2_key: string; title: string | null; language: string | null }>(),
  ]);

  if (!verified || !docRow) return null;
  const obj = await bucket.get(docRow.r2_key);
  if (!obj) return null;
  const markdown = await obj.text();

  return {
    markdown,
    contentSha256: pageRow.latest_content_sha256,
    documentId: docRow.id,
    pipelineVersion,
    ...(docRow.title ? { title: docRow.title } : {}),
    ...(docRow.language ? { language: docRow.language } : {}),
    status: pageRow.latest_status ?? 200,
    lastFetchedAt: pageRow.last_fetched_at,
  };
}

/**
 * `R5`: Looks up stored `etag` / `last_modified` + verified derived Markdown in `META` D1 + `ARTIFACTS` R2 when
 * `maxAgeMs` has expired (or `maxAgeMs === 0`), enabling `If-None-Match` / `If-Modified-Since` -> `304 Not Modified`
 * millisecond revalidation without re-downloading or re-chunking unchanged pages.
 */
export async function lookupRevalidationCandidate(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  url: string;
  pipelineVersion?: number;
}): Promise<{
  etag?: string;
  lastModified?: string;
  markdown: string;
  contentSha256: string;
  documentId: string;
  pipelineVersion: number;
  title?: string;
  language?: string;
} | null> {
  const { bucket, metaDb, url, pipelineVersion = SCRAPE_PIPELINE_VERSION } = params;
  const pageRow = await metaDb
    .prepare(
      `SELECT latest_outcome, latest_content_sha256, etag, last_modified
       FROM pages
       WHERE url = ?
       LIMIT 1`,
    )
    .bind(url)
    .first<{
      latest_outcome: string | null;
      latest_content_sha256: string | null;
      etag: string | null;
      last_modified: string | null;
    }>();

  if (
    !pageRow ||
    pageRow.latest_outcome !== 'ok' ||
    !pageRow.latest_content_sha256 ||
    (!pageRow.etag && !pageRow.last_modified)
  ) {
    return null;
  }

  const [verified, docRow] = await Promise.all([
    isContentVerifiedInMetaD1(metaDb, pageRow.latest_content_sha256),
    metaDb
      .prepare(
        `SELECT id, r2_key, title, language
         FROM documents
         WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version = ?
         LIMIT 1`,
      )
      .bind(pageRow.latest_content_sha256, pipelineVersion)
      .first<{ id: string; r2_key: string; title: string | null; language: string | null }>(),
  ]);
  if (!verified || !docRow) return null;
  const obj = await bucket.get(docRow.r2_key);
  if (!obj) return null;
  const markdown = await obj.text();

  return {
    ...(pageRow.etag ? { etag: pageRow.etag } : {}),
    ...(pageRow.last_modified ? { lastModified: pageRow.last_modified } : {}),
    markdown,
    contentSha256: pageRow.latest_content_sha256,
    documentId: docRow.id,
    pipelineVersion,
    ...(docRow.title ? { title: docRow.title } : {}),
    ...(docRow.language ? { language: docRow.language } : {}),
  };
}

export async function touchRevalidatedPage(metaDb: D1Database, url: string, now = Date.now()): Promise<void> {
  await metaDb
    .prepare('UPDATE pages SET last_fetched_at = ? WHERE url = ?')
    .bind(now, url)
    .run()
    .catch(() => undefined);
}

export type ScrapeFormatInput =
  | 'markdown'
  | 'text'
  | 'summary'
  | 'product'
  | 'rawBase64'
  | 'html'
  | 'rawHtml'
  | 'links'
  | 'images'
  | 'branding'
  | 'llmsTxt'
  | 'screenshot'
  | 'changes'
  | { type: 'json'; prompt?: string; schema?: Record<string, unknown> }
  | { type: 'attributes'; selectors: Array<{ selector: string; attribute: string }> }
  | { type: 'screenshot'; fullPage?: boolean; quality?: number; viewport?: { width?: number; height?: number } }
  | { type: 'changeTracking'; modes?: Array<'git-diff' | 'json'>; tag?: string };

export interface ScrapeRequestPayload {
  url?: unknown;
  formats?: unknown;
  onlyMainContent?: unknown;
  includeImages?: unknown;
  includeTags?: unknown;
  excludeTags?: unknown;
  maxChars?: unknown;
  defaultMaxChars?: unknown;
  maxAgeMs?: unknown;
  maxAge?: unknown;
  discoverLlmsTxt?: unknown;
  preferOriginMarkdown?: unknown;
  redactPii?: unknown;
  checkPromptInjection?: unknown;
  query?: unknown;
  jsonFilter?: unknown;
  headers?: unknown;
  renderMode?: unknown;
  mobile?: unknown;
  location?: unknown;
  actions?: unknown;
  parsers?: unknown;
  llm?: unknown;
  waitForMs?: unknown;
  waitFor?: unknown;
  timeout?: unknown;
  waitSelector?: unknown;
  maxPages?: unknown;
  ocr?: unknown;
  waybackFallback?: unknown;
  spaFallback?: unknown;
  noCache?: unknown;
  ephemeral?: unknown;
  collectionId?: unknown;
  target?: unknown;
  site?: unknown;
}

function isLazyPlaceholderImageUrl(urlStr: string): boolean {
  const trimmed = urlStr.trim();
  if (!trimmed || trimmed.startsWith('data:')) return true;
  return /(?:^|[/_-])placeholder(?:[-_]{1,2}[a-z0-9_-]+)?\.(?:png|gif|svg|webp|jpe?g|avif)(?:$|[?#])/i.test(trimmed);
}

function isTinyOrAvatarImageUrl(urlStr: string, alt = ''): boolean {
  if (isLazyPlaceholderImageUrl(urlStr)) return true;
  if (/\b(avatar|gravatar|author[-_]?photo|author[-_]?image|1x1|pixel|spacer|badge)\b/i.test(`${alt} ${urlStr}`)) {
    return true;
  }
  const dimMatches = [...urlStr.matchAll(/[?&](?:w|width|h|height)=(\d{1,4})\b/gi)];
  for (const m of dimMatches) {
    const dim = Number(m[1]);
    if (Number.isFinite(dim) && dim > 0 && dim < 100) return true;
  }
  return false;
}

function dedupeConsecutiveStandaloneLinkParagraphs(prose: string): string {
  const blocks = prose.split(/\n{2,}/);
  if (blocks.length < 2) return prose;
  const out: string[] = [];
  for (const b of blocks) {
    const trimmed = b.trim();
    const prev = out.length > 0 ? out[out.length - 1]!.trim() : '';
    if (trimmed && trimmed === prev && /^\[[^\]\n]+\]\(https?:\/\/[^)\s]+\)$/.test(trimmed)) {
      continue;
    }
    out.push(b);
  }
  return out.join('\n\n');
}

interface MarkdownLineScanCursors {
  nextCloseBracket: number;
  noCloseBracket: boolean;
  nextCloseParen: number;
  noCloseParen: boolean;
  noTickMask: number;
}

interface ParsedMarkdownLinkToken {
  isImage: boolean;
  rawLabel: string;
  rawUrl: string;
  titleSuffix: string;
  end: number;
}

function createMarkdownLineScanCursors(): MarkdownLineScanCursors {
  return {
    nextCloseBracket: -1,
    noCloseBracket: false,
    nextCloseParen: -1,
    noCloseParen: false,
    noTickMask: 0,
  };
}

function isBackslashEscapedAt(str: string, idx: number): boolean {
  let bs = 0;
  let p = idx - 1;
  while (p >= 0 && str.charCodeAt(p) === 92 /* '\\' */) {
    bs++;
    p--;
  }
  return (bs & 1) === 1;
}

function scanCodeSpanEndLinear(line: string, start: number, cursors: MarkdownLineScanCursors): { tickEnd: number; spanEnd: number } {
  let tickEnd = start + 1;
  while (tickEnd < line.length && line.charCodeAt(tickEnd) === 96) tickEnd++;
  const tickLen = tickEnd - start;
  if (tickLen < 31 && (cursors.noTickMask & (1 << tickLen)) !== 0) {
    return { tickEnd, spanEnd: -1 };
  }
  let pos = tickEnd;
  while (pos < line.length) {
    const idx = line.indexOf('`', pos);
    if (idx < 0) break;
    let runEnd = idx + 1;
    while (runEnd < line.length && line.charCodeAt(runEnd) === 96) runEnd++;
    if (runEnd - idx === tickLen) {
      return { tickEnd, spanEnd: runEnd };
    }
    pos = runEnd;
  }
  if (tickLen < 31) cursors.noTickMask |= 1 << tickLen;
  return { tickEnd, spanEnd: -1 };
}

function decodeUriEntitiesForScheme(input: string): string {
  if (!input.includes('&')) return input;
  return decodeHtmlEntities(input)
    .replace(/&#0*(\d{1,7});?/g, (full, dec: string) => {
      const code = Number(dec);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff
        ? code === 0
          ? ''
          : String.fromCodePoint(code)
        : full;
    })
    .replace(/&#[xX]0*([0-9a-fA-F]{1,6});?/g, (full, hex: string) => {
      const code = parseInt(hex, 16);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff
        ? code === 0
          ? ''
          : String.fromCodePoint(code)
        : full;
    });
}


function detectParagraphBreakKind(line: string): 'blank_or_atomic' | 'block_start' | 'atx_heading' | 'none' {
  const { cols, bytePos, isBlank } = measureLeadingIndentCols(line);
  if (isBlank) return 'blank_or_atomic';
  const c = line.charCodeAt(bytePos);
  if (cols <= 3) {
    if (c === 35 /* '#' */) {
      let h = bytePos;
      while (h < line.length && line.charCodeAt(h) === 35 && h - bytePos < 7) h++;
      if (
        h - bytePos <= 6 &&
        (h >= line.length || line.charCodeAt(h) === 32 || line.charCodeAt(h) === 9 || line.charCodeAt(h) === 13)
      ) {
        return 'atx_heading';
      }
    }
    if (c === 62 /* '>' */) return 'block_start';
    if (
      (c === 96 || c === 126) &&
      bytePos + 3 <= line.length &&
      line.charCodeAt(bytePos + 1) === c &&
      line.charCodeAt(bytePos + 2) === c
    ) {
      return 'blank_or_atomic';
    }
    if (c === 61 || c === 45 || c === 42 || c === 95) {
      const rest = line.slice(bytePos);
      if (/^(?:=+|-+)[ \t\r]*$/.test(rest) || /^(?:[-*_][ \t]*){3,}\r?$/.test(rest)) {
        return 'blank_or_atomic';
      }
    }
  }
  if (
    (c === 45 || c === 42 || c === 43) &&
    bytePos + 1 < line.length &&
    (line.charCodeAt(bytePos + 1) === 32 || line.charCodeAt(bytePos + 1) === 9)
  ) {
    return 'block_start';
  }
  if (c >= 48 && c <= 57) {
    let d = bytePos + 1;
    while (d < line.length && d - bytePos < 9 && line.charCodeAt(d) >= 48 && line.charCodeAt(d) <= 57) d++;
    if (
      d + 1 < line.length &&
      (line.charCodeAt(d) === 46 || line.charCodeAt(d) === 41) &&
      (line.charCodeAt(d + 1) === 32 || line.charCodeAt(d + 1) === 9)
    ) {
      return 'block_start';
    }
  }
  return 'none';
}

/** R5/R6: CommonMark code spans may continue across lines of one paragraph, but NEVER cross blank lines, headings, fences, thematic breaks, blockquotes, or sibling list items (`CHANGELOG.md` false-positive fix). */
function computeTickPoisonedLines(lines: string[]): Uint8Array {
  const poisoned = new Uint8Array(lines.length);
  let carry = false;
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    const breakKind = detectParagraphBreakKind(line);
    if (breakKind === 'blank_or_atomic') {
      carry = false;
      continue;
    }
    if (breakKind === 'block_start' || breakKind === 'atx_heading') {
      carry = false;
    }
    if (carry) {
      poisoned[li] = 1;
      continue;
    }
    if (!line.includes('`')) continue;
    const cursors = createMarkdownLineScanCursors();
    let i = 0;
    let lastTick = -2;
    while (i < line.length) {
      const ch = line.charCodeAt(i);
      if (ch === 96) {
        if (isBackslashEscapedAt(line, i)) {
          i++;
          continue;
        }
        const { spanEnd } = scanCodeSpanEndLinear(line, i, cursors);
        if (spanEnd < 0) {
          carry = true;
          break;
        }
        i = spanEnd;
        continue;
      }
      // A link/image destination or title is raw text for CommonMark: a backtick inside one (or after a `](` the precise
      // parser could not consume) makes backtick pairing ambiguous for the rest of the paragraph.
      if ((ch === 33 || ch === 91) && !isBackslashEscapedAt(line, i)) {
        const tok = tryParseMarkdownLinkOrImageAt(line, i, cursors, true);
        if (tok) {
          if (tok.rawUrl.includes('`') || tok.titleSuffix.includes('`')) {
            poisoned[li] = 1;
            carry = true;
            break;
          }
          i = tok.end;
          continue;
        }
      }
      if (ch === 93 && i + 1 < line.length && line.charCodeAt(i + 1) === 40) {
        if (lastTick === -2) lastTick = line.lastIndexOf('`');
        if (lastTick > i) {
          poisoned[li] = 1;
          carry = true;
          break;
        }
      }
      i++;
    }
    if (breakKind === 'atx_heading') {
      carry = false;
    }
  }
  return poisoned;
}

/**
 * `R6-H3`: Detaches bare GFM autolink candidates (`https://`, `http://`, `ftp://`, `www.`, and glued email local-parts)
 * from immediately following backticks outside existing code spans so GFM autolinkers (`marked`, `micromark+GFM`) NEVER
 * swallow an opening code-span backtick into the URL and expose raw `<img onerror>` / `<script>` inside what our scanner
 * thought was a code span. Also percent-encodes `` ` `` inside `<https://...>` angle-bracket autolinks.
 */
function detachBareUrlsFromCodeSpansLinear(prose: string): string {
  if (!prose || !prose.includes('`')) return prose;
  const lines = prose.split('\n');
  const poisoned = computeTickPoisonedLines(lines);
  let changed = false;

  const startsBareGfmUrlAt = (s: string, pos: number): boolean => {
    if (pos > 0) {
      const prev = s.charCodeAt(pos - 1);
      if ((prev >= 48 && prev <= 57) || (prev >= 65 && prev <= 90) || (prev >= 97 && prev <= 122)) return false;
    }
    const rest = s.slice(pos, pos + 12);
    if (/^(?:https?:\/\/|ftp:\/\/)/i.test(rest)) return true;
    if (/^www\.[A-Za-z0-9]/i.test(rest)) return true;
    return false;
  };

  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    if (!line.includes('`')) continue;
    const cursors = createMarkdownLineScanCursors();
    let out = '';
    let last = 0;
    let i = 0;

    while (i < line.length) {
      const ch = line.charCodeAt(i);

      // 1. Angle-bracket autolinks `<https://...>` containing backticks (`<https://ok.example/`>`)
      if (ch === 60 /* '<' */ && i + 4 < line.length && /^(?:https?|ftp|mailto):/i.test(line.slice(i + 1, i + 10))) {
        const gtLimit = Math.min(line.length, i + 2049);
        let gt = -1;
        let hasTick = false;
        for (let p = i + 1; p < gtLimit; p++) {
          const pc = line.charCodeAt(p);
          if (pc === 62 /* '>' */) {
            gt = p;
            break;
          }
          if (pc <= 32 || pc === 60) break;
          if (pc === 96) hasTick = true;
        }
        if (gt > 0 && hasTick) {
          out += `${line.slice(last, i + 1)}${line.slice(i + 1, gt).replace(/`/g, '%60')}>`;
          i = gt + 1;
          last = i;
          changed = true;
          continue;
        }
      }

      // 2. Bare GFM URL (`https?://`, `ftp://`, `www.`) outside code spans: insert space before the first `` ` `` in/after it
      if ((ch === 104 || ch === 72 || ch === 102 || ch === 70 || ch === 119 || ch === 87) && startsBareGfmUrlAt(line, i)) {
        const urlLimit = Math.min(line.length, i + 2048);
        let p = i + 4;
        let detachedAt = -1;
        while (p < urlLimit) {
          const pc = line.charCodeAt(p);
          if (pc <= 32 || pc === 60 || pc === 62) break;
          if (pc === 96 /* '`' */) {
            detachedAt = p;
            break;
          }
          p++;
        }
        if (detachedAt >= 0) {
          out += `${line.slice(last, detachedAt)} `;
          last = detachedAt;
          i = detachedAt;
          changed = true;
          // Fall through so the detached backtick at `i` is scanned as a normal code-span opener!
        } else {
          i = p;
          continue;
        }
      }

      // 3. Glued GFM email local-part (`a`b@c.com`) swallowing an opening backtick in `marked`
      if (line.charCodeAt(i) === 96 && !isBackslashEscapedAt(line, i)) {
        if (i > 0) {
          const prev = line.charCodeAt(i - 1);
          const isEmailLead =
            (prev >= 48 && prev <= 57) ||
            (prev >= 65 && prev <= 90) ||
            (prev >= 97 && prev <= 122) ||
            prev === 46 ||
            prev === 95 ||
            prev === 43 ||
            prev === 45;
          if (isEmailLead && /^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]{0,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/.test(line.slice(i + 1, i + 128))) {
            out += `${line.slice(last, i)} `;
            last = i;
            changed = true;
          }
        }
        if (poisoned[li] === 0) {
          const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, i, cursors);
          i = spanEnd > 0 ? spanEnd : tickEnd;
          continue;
        }
      }

      i++;
    }

    if (last > 0) {
      lines[li] = out + line.slice(last);
    }
  }

  return changed ? lines.join('\n') : prose;
}

const DANGEROUS_SCHEME_PREFIXES = ['javascript:', 'vbscript:', 'data:', 'file:', 'blob:'];

/** O(1)-amortised streaming check: does the (backslash-/entity-encoded) link destination starting at `from` begin with a dangerous scheme? */
function destinationStartsWithDangerousScheme(s: string, from: number, angle: boolean): boolean {
  let acc = '';
  let p = from;
  let steps = 0;
  while (p < s.length && steps++ < 8192) {
    const c = s.charCodeAt(p);
    let piece = '';
    if (c === 92 && p + 1 < s.length && /[!-/:-@[-`{-~]/.test(s[p + 1]!)) {
      piece = s[p + 1]!;
      p += 2;
    } else if (c === 38) {
      const m = /^&(?:#(\d{1,12});?|#[xX]([0-9a-fA-F]{1,12});?|([A-Za-z][A-Za-z0-9]{1,15});)/.exec(s.slice(p, p + 24));
      if (m) {
        if (m[3]) {
          const named = decodeHtmlEntities(m[0]);
          piece = named === m[0] ? '&' : named;
          p += named === m[0] ? 1 : m[0].length;
        } else {
          const code = m[1] ? Number(m[1]) : parseInt(m[2]!, 16);
          piece = code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
          p += m[0].length;
        }
      } else {
        piece = '&';
        p += 1;
      }
    } else {
      if (angle ? c === 62 || c === 10 || c === 13 : c === 32 || c === 9 || c === 10 || c === 13 || c === 41) return false;
      piece = s[p]!;
      p += 1;
    }
    for (let k = 0; k < piece.length; k++) {
      const pc = piece.charCodeAt(k);
      if (
        pc <= 0x20 ||
        (pc >= 0x7f && pc <= 0x9f) ||
        pc === 0xa0 ||
        pc === 0xad ||
        pc === 0x61c ||
        pc === 0x1680 ||
        (pc >= 0x2000 && pc <= 0x200a) ||
        pc === 0x205f ||
        pc === 0x3000 ||
        pc === 0x180e ||
        (pc >= 0x200b && pc <= 0x200f) ||
        (pc >= 0x2028 && pc <= 0x202f) ||
        (pc >= 0x2060 && pc <= 0x206f) ||
        pc === 0xfeff
      ) {
        continue;
      }
      acc += piece[k]!.toLowerCase();
      let viable = false;
      for (const sc of DANGEROUS_SCHEME_PREFIXES) {
        if (sc === acc) return true;
        if (sc.startsWith(acc)) viable = true;
      }
      if (!viable) return false;
    }
  }
  return false;
}

/** R5/R6 fail-closed pass: any `](` / `]:` outside trusted code spans (or after an earlier `[` on the paragraph, covering `marked16` `[a `](javascript:...) `x`) followed by a dangerous scheme is broken with `]\ (` / `]\:`. */
function neutralizeResidualDangerousLinkDestinations(prose: string): string {
  if (!prose.includes('](') && !prose.includes(']:')) return prose;
  const lines = prose.split('\n');
  const poisoned = computeTickPoisonedLines(lines);
  let changed = false;
  let sawBracketInPara = false;
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    const breakKind = detectParagraphBreakKind(line);
    if (breakKind !== 'none') {
      sawBracketInPara = false;
    }
    if (!line.includes('](') && !line.includes(']:')) {
      if (line.includes('[')) {
        const cursors = createMarkdownLineScanCursors();
        let p = 0;
        while (p < line.length) {
          const pc = line.charCodeAt(p);
          if (pc === 96 && poisoned[li] === 0 && !isBackslashEscapedAt(line, p)) {
            const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, p, cursors);
            p = spanEnd > 0 ? spanEnd : tickEnd;
            continue;
          }
          if (pc === 91 && !isBackslashEscapedAt(line, p)) {
            sawBracketInPara = true;
            break;
          }
          p++;
        }
      }
      continue;
    }
    const cursors = createMarkdownLineScanCursors();
    let out = '';
    let last = 0;
    let i = 0;
    while (i < line.length) {
      const ch = line.charCodeAt(i);
      if (ch === 91 && !isBackslashEscapedAt(line, i)) {
        sawBracketInPara = true;
      }
      // Only trust code spans to mask `](` / `]:` when NO unescaped `[` preceded them in the paragraph (`marked16` link-over-codespan bug)!
      if (ch === 96 && poisoned[li] === 0 && !sawBracketInPara && !isBackslashEscapedAt(line, i)) {
        const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, i, cursors);
        i = spanEnd > 0 ? spanEnd : tickEnd;
        continue;
      }
      if (ch === 93 && i + 1 < line.length) {
        const nx = line.charCodeAt(i + 1);
        if (nx === 40 || nx === 58) {
          let hay = line;
          let k = i + 2;
          while (k < hay.length && (hay.charCodeAt(k) === 32 || hay.charCodeAt(k) === 9 || hay.charCodeAt(k) === 13)) k++;
          if (k >= hay.length && li + 1 < lines.length) {
            hay = lines[li + 1]!;
            k = 0;
            let skipped = 0;
            while (k < hay.length && skipped++ < 64 && (hay.charCodeAt(k) === 32 || hay.charCodeAt(k) === 9 || hay.charCodeAt(k) === 62)) k++;
            const lm = /^(?:[-*+][ \t]{1,8}|\d{1,9}[.)][ \t]{1,8})/.exec(hay.slice(k, k + 24));
            if (lm) k += lm[0].length;
          }
          const angle = k < hay.length && hay.charCodeAt(k) === 60;
          if (destinationStartsWithDangerousScheme(hay, angle ? k + 1 : k, angle)) {
            out += `${line.slice(last, i + 1)}\\ `;
            last = i + 1;
            changed = true;
          }
        }
      }
      i++;
    }
    if (last > 0) lines[li] = out + line.slice(last);
    if (breakKind === 'atx_heading') sawBracketInPara = false;
  }
  return changed ? lines.join('\n') : prose;
}

function hasDangerousUriScheme(rawHref: string): boolean {
  if (!rawHref) return false;
  const unescaped = rawHref.replace(/\\([!-/:-@[-`{-~])/g, '$1');
  const decoded = decodeUriEntitiesForScheme(unescaped)
    .replace(
      /[\u0000-\u0020\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u{E0000}-\u{E01EF}]+/gu,
      '',
    )
    .trim();
  if (/^(?:javascript|vbscript|data|file|blob):/i.test(decoded)) {
    return true;
  }
  let stopIdx = decoded.length;
  for (let i = 0; i < decoded.length; i++) {
    const c = decoded.charCodeAt(i);
    if (c === 47 /* '/' */ || c === 63 /* '?' */ || c === 35 /* '#' */) {
      stopIdx = i;
      break;
    }
  }
  const beforePath = decoded.slice(0, stopIdx);
  if (beforePath.includes('&') && /&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});?/.test(beforePath)) {
    return true;
  }
  return false;
}

function tryParseMarkdownLinkOrImageAt(
  line: string,
  pos: number,
  cursors: MarkdownLineScanCursors,
  allowNestedImage = true,
): ParsedMarkdownLinkToken | null {
  const c0 = line.charCodeAt(pos);
  let isImage = false;
  let labelStart = pos + 1;
  if (c0 === 33) {
    if (pos + 1 >= line.length || line.charCodeAt(pos + 1) !== 91) return null;
    isImage = true;
    labelStart = pos + 2;
  } else if (c0 !== 91) {
    return null;
  }

  if (cursors.noCloseBracket) return null;
  if (cursors.nextCloseBracket < labelStart) {
    cursors.nextCloseBracket = line.indexOf(']', labelStart);
    if (cursors.nextCloseBracket < 0) {
      cursors.noCloseBracket = true;
      return null;
    }
  }
  if (cursors.nextCloseBracket - labelStart > 1_000) return null;

  const labelMaxEnd = Math.min(line.length, labelStart + 1_000);
  let labelEnd = -1;
  let j = labelStart;
  while (j < labelMaxEnd) {
    const ch = line.charCodeAt(j);
    if (ch === 92) {
      j += 2;
      continue;
    }
    if (ch === 96) {
      const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, j, cursors);
      if (spanEnd > 0 && spanEnd <= labelMaxEnd) {
        j = spanEnd;
        continue;
      }
      j = tickEnd;
      continue;
    }
    if (ch === 93) {
      labelEnd = j;
      break;
    }
    if (!isImage && allowNestedImage && ch === 33 && j + 1 < labelMaxEnd && line.charCodeAt(j + 1) === 91) {
      const nestedCursors = createMarkdownLineScanCursors();
      const nestedImg = tryParseMarkdownLinkOrImageAt(line, j, nestedCursors, false);
      if (!nestedImg) return null;
      j = nestedImg.end;
      continue;
    }
    if (ch === 91 || (ch === 33 && j + 1 < labelMaxEnd && line.charCodeAt(j + 1) === 91)) {
      return null;
    }
    j++;
  }
  if (labelEnd < 0 || labelEnd + 1 >= line.length || line.charCodeAt(labelEnd + 1) !== 40) {
    return null;
  }

  const destStart = labelEnd + 2;
  if (cursors.noCloseParen) return null;
  if (cursors.nextCloseParen < destStart) {
    cursors.nextCloseParen = line.indexOf(')', destStart);
    if (cursors.nextCloseParen < 0) {
      cursors.noCloseParen = true;
      return null;
    }
  }
  if (cursors.nextCloseParen - destStart > 2_560) return null;

  let k = destStart;
  while (k < line.length && (line.charCodeAt(k) === 32 || line.charCodeAt(k) === 9)) k++;
  if (k >= line.length) return null;

  let rawUrl = '';
  if (line.charCodeAt(k) === 60) {
    const angleLimit = Math.min(line.length, k + 2_049);
    let gt = -1;
    for (let p = k + 1; p < angleLimit; p++) {
      const pc = line.charCodeAt(p);
      if (pc === 62) {
        gt = p;
        break;
      }
      if (pc === 60 || pc === 10 || pc === 13) return null;
    }
    if (gt < 0) return null;
    rawUrl = line.slice(k + 1, gt).trim();
    k = gt + 1;
  } else {
    const urlStart = k;
    const urlLimit = Math.min(line.length, urlStart + 2_048);
    let parenDepth = 0;
    while (k < urlLimit) {
      const uc = line.charCodeAt(k);
      if (uc === 92 && k + 1 < urlLimit) {
        k += 2;
        continue;
      }
      if (uc === 32 || uc === 9) {
        break;
      }
      if (uc === 40) {
        parenDepth++;
        if (parenDepth > 4) return null;
      } else if (uc === 41) {
        if (parenDepth === 0) break;
        parenDepth--;
      } else if (uc === 93 && k + 1 < urlLimit && line.charCodeAt(k + 1) === 40) {
        return null;
      }
      k++;
    }
    if (parenDepth !== 0) return null;
    rawUrl = line.slice(urlStart, k);
  }

  const wsStart = k;
  while (k < line.length && (line.charCodeAt(k) === 32 || line.charCodeAt(k) === 9)) k++;
  let titleSuffix = '';
  if (k < line.length && k > wsStart && (line.charCodeAt(k) === 34 || line.charCodeAt(k) === 39)) {
    const quoteChar = line.charCodeAt(k);
    const titleLimit = Math.min(line.length, k + 512);
    let qEnd = -1;
    for (let p = k + 1; p < titleLimit; p++) {
      const tc = line.charCodeAt(p);
      if (tc === 92) {
        p++;
        continue;
      }
      if (tc === quoteChar) {
        qEnd = p;
        break;
      }
    }
    if (qEnd < 0) return null;
    titleSuffix = line.slice(wsStart, qEnd + 1);
    k = qEnd + 1;
    while (k < line.length && (line.charCodeAt(k) === 32 || line.charCodeAt(k) === 9)) k++;
  }

  if (k >= line.length || line.charCodeAt(k) !== 41) return null;
  return {
    isImage,
    rawLabel: line.slice(labelStart, labelEnd),
    rawUrl,
    titleSuffix,
    end: k + 1,
  };
}

/** Strips `[label](url)` -> `label` and `![alt](url)` -> `alt` in guaranteed O(N) linear time. */
function stripMarkdownLinksToLabelsLinear(text: string): string {
  if (!text || (!text.includes('](') && !text.includes('<'))) return text;
  const bounded = text.length > MAX_HTML_SCAN_CHARS ? text.slice(0, MAX_HTML_SCAN_CHARS) : text;
  return bounded
    .split('\n')
    .map((line) => {
      if (!line.includes('](')) return line;
      const cursors = createMarkdownLineScanCursors();
      let out = '';
      let lastIdx = 0;
      let i = 0;
      while (i < line.length) {
        const ch = line.charCodeAt(i);
        if (ch === 96) {
          if (isBackslashEscapedAt(line, i)) {
            i++;
            continue;
          }
          const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, i, cursors);
          i = spanEnd > 0 ? spanEnd : tickEnd;
          continue;
        }
        if ((ch === 33 || ch === 91) && !isBackslashEscapedAt(line, i)) {
          const tok = tryParseMarkdownLinkOrImageAt(line, i, cursors, true);
          if (tok) {
            out += line.slice(lastIdx, i);
            const cleanLabel = tok.rawLabel.includes('](') ? stripMarkdownLinksToLabelsLinear(tok.rawLabel) : tok.rawLabel;
            out += cleanLabel;
            i = tok.end;
            lastIdx = i;
            continue;
          }
        }
        i++;
      }
      return lastIdx === 0 ? line : out + line.slice(lastIdx);
    })
    .join('\n');
}

function isAsciiAlnumCode(c: number): boolean {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

/**
 * Linear O(N) pass over non-fenced Markdown prose that detects multi-line `[label\nlabel2](dest)` (and `![alt\nalt2](dest)`
 * or `[label](\ndest)`) links within a single paragraph (no blank-line break) and strips the link wrapper to plain
 * `label\nlabel2` whenever `dest` is empty or `hasDangerousUriScheme(dest)` is true (`R4-M6`).
 */
function stripDangerousMultilineMarkdownLinksLinear(prose: string): string {
  if (!prose || !prose.includes('\n') || !prose.includes('](')) return prose;
  const parts = prose.split(/(\r?\n[ \t]*\r?\n+)/);
  let changedAny = false;
  for (let pIdx = 0; pIdx < parts.length; pIdx += 2) {
    const para = parts[pIdx]!;
    if (!para.includes('\n') || !para.includes('](')) continue;

    const cachedTickPos = new Map<number, number>();
    const scannedTickTo = new Map<number, number>();
    const findClosingTicks = (tickLen: number, fromIdx: number): number => {
      if (tickLen > 32) return -1;
      let pos = cachedTickPos.get(tickLen) ?? -2;
      while (pos !== -1 && pos < fromIdx) {
        let search = Math.max(fromIdx, scannedTickTo.get(tickLen) ?? 0);
        pos = -1;
        while (search < para.length) {
          const hit = para.indexOf('`', search);
          if (hit < 0) {
            scannedTickTo.set(tickLen, para.length);
            break;
          }
          let end = hit + 1;
          while (end < para.length && para.charCodeAt(end) === 96) end++;
          scannedTickTo.set(tickLen, end);
          if (end - hit === tickLen && (hit === 0 || para.charCodeAt(hit - 1) !== 96)) {
            pos = hit;
            break;
          }
          search = end;
        }
        cachedTickPos.set(tickLen, pos);
      }
      return pos;
    };

    let nextBracketParen = -1;
    let noBracketParen = false;
    let nextCloseParen = -1;
    let noCloseParen = false;
    const outChunks: string[] = [];
    let lastCopy = 0;
    let i = 0;

    while (i < para.length) {
      const ch = para.charCodeAt(i);
      if (ch === 96) {
        if (isBackslashEscapedAt(para, i)) {
          i++;
          continue;
        }
        let tEnd = i + 1;
        while (tEnd < para.length && para.charCodeAt(tEnd) === 96) tEnd++;
        const tickLen = tEnd - i;
        const closeHit = findClosingTicks(tickLen, tEnd);
        i = closeHit >= tEnd ? closeHit + tickLen : tEnd;
        continue;
      }

      if ((ch === 33 || ch === 91) && !isBackslashEscapedAt(para, i)) {
        const isImg = ch === 33;
        if (isImg && (i + 1 >= para.length || para.charCodeAt(i + 1) !== 91)) {
          i++;
          continue;
        }
        if (noBracketParen || noCloseParen) {
          if (para.indexOf('`', i + 1) < 0) break;
          i++;
          continue;
        }
        const labelStart = isImg ? i + 2 : i + 1;
        if (nextBracketParen < labelStart - 1) {
          nextBracketParen = para.indexOf('](', Math.max(0, labelStart - 1));
          if (nextBracketParen < 0) {
            noBracketParen = true;
            i++;
            continue;
          }
        }
        if (nextBracketParen - labelStart > 1_000) {
          i++;
          continue;
        }

        const labelLimit = Math.min(para.length, labelStart + 1_000);
        let labelEnd = -1;
        let bracketDepth = 0;
        let j = labelStart;
        while (j < labelLimit) {
          const jc = para.charCodeAt(j);
          if (jc === 92) {
            j += 2;
            continue;
          }
          if (jc === 96) {
            let te = j + 1;
            while (te < para.length && para.charCodeAt(te) === 96) te++;
            const tl = te - j;
            const chClose = findClosingTicks(tl, te);
            if (chClose >= te && chClose + tl <= labelLimit) {
              j = chClose + tl;
              continue;
            }
            j = te;
            continue;
          }
          if (jc === 93) {
            if (bracketDepth === 0) {
              if (j + 1 < para.length && para.charCodeAt(j + 1) === 40) {
                labelEnd = j;
              }
              break;
            }
            bracketDepth--;
            j++;
            continue;
          }
          if (jc === 91) {
            bracketDepth++;
            if (bracketDepth > 4) break;
            j++;
            continue;
          }
          j++;
        }

        if (labelEnd >= 0) {
          const destStart = labelEnd + 2;
          if (nextCloseParen < destStart) {
            nextCloseParen = para.indexOf(')', destStart);
            if (nextCloseParen < 0) {
              noCloseParen = true;
              i++;
              continue;
            }
          }
          if (nextCloseParen - destStart <= 2_560) {
            let k = destStart;
            while (
              k < para.length &&
              (para.charCodeAt(k) === 32 || para.charCodeAt(k) === 9 || para.charCodeAt(k) === 13 || para.charCodeAt(k) === 10)
            ) {
              k++;
            }
            let rawUrl = '';
            let validDest = k < para.length;
            if (validDest && para.charCodeAt(k) === 60) {
              const angleLimit = Math.min(para.length, k + 2_049);
              let gt = -1;
              for (let p = k + 1; p < angleLimit; p++) {
                const pc = para.charCodeAt(p);
                if (pc === 62) {
                  gt = p;
                  break;
                }
                if (pc === 60 || pc === 10 || pc === 13) {
                  validDest = false;
                  break;
                }
              }
              if (gt < 0) validDest = false;
              else {
                rawUrl = para.slice(k + 1, gt).trim();
                k = gt + 1;
              }
            } else if (validDest) {
              const urlStart = k;
              const urlLimit = Math.min(para.length, urlStart + 2_048);
              let parenDepth = 0;
              while (k < urlLimit) {
                const uc = para.charCodeAt(k);
                if (uc === 92 && k + 1 < urlLimit) {
                  k += 2;
                  continue;
                }
                if (uc === 32 || uc === 9 || uc === 10 || uc === 13) break;
                if (uc === 40) {
                  parenDepth++;
                  if (parenDepth > 4) {
                    validDest = false;
                    break;
                  }
                } else if (uc === 41) {
                  if (parenDepth === 0) break;
                  parenDepth--;
                }
                k++;
              }
              if (parenDepth !== 0) validDest = false;
              else rawUrl = para.slice(urlStart, k);
            }

            if (validDest) {
              const wsStart = k;
              while (
                k < para.length &&
                (para.charCodeAt(k) === 32 || para.charCodeAt(k) === 9 || para.charCodeAt(k) === 13 || para.charCodeAt(k) === 10)
              ) {
                k++;
              }
              if (k < para.length && k > wsStart && (para.charCodeAt(k) === 34 || para.charCodeAt(k) === 39)) {
                const qChar = para.charCodeAt(k);
                const tLimit = Math.min(para.length, k + 512);
                let qEnd = -1;
                for (let p = k + 1; p < tLimit; p++) {
                  const tc = para.charCodeAt(p);
                  if (tc === 92) {
                    p++;
                    continue;
                  }
                  if (tc === qChar) {
                    qEnd = p;
                    break;
                  }
                }
                if (qEnd < 0) validDest = false;
                else {
                  k = qEnd + 1;
                  while (
                    k < para.length &&
                    (para.charCodeAt(k) === 32 || para.charCodeAt(k) === 9 || para.charCodeAt(k) === 13 || para.charCodeAt(k) === 10)
                  ) {
                    k++;
                  }
                }
              }
            }

            if (validDest && k < para.length && para.charCodeAt(k) === 41) {
              const fullEnd = k + 1;
              if (para.slice(i, fullEnd).includes('\n') && (!rawUrl.trim() || hasDangerousUriScheme(rawUrl.trim()))) {
                outChunks.push(para.slice(lastCopy, i));
                if (!isImg) {
                  const rawLabel = para.slice(labelStart, labelEnd);
                  outChunks.push(
                    rawLabel.includes('](') ? stripDangerousMultilineMarkdownLinksLinear(rawLabel) : rawLabel,
                  );
                }
                i = fullEnd;
                lastCopy = i;
                continue;
              }
            }
          }
        }
      }
      i++;
    }

    if (lastCopy > 0) {
      if (lastCopy < para.length) outChunks.push(para.slice(lastCopy));
      parts[pIdx] = outChunks.join('');
      changedAny = true;
    }
  }
  return changedAny ? parts.join('') : prose;
}

/**
 * Normalizes inline code spacing (`\`a\`\`b\`` -> `\`a\` \`b\``), duplicate link suffixes (`[lbl (url)](url)` / `[lbl](url)(url)`),
 * relative URL resolution, dangerous URI scheme stripping (`javascript:`, `vbscript:`, `data:`, `file:`, `blob:`),
 * autolink conversion (`<https://...>` -> `[https://...](https://...)`), and decorative/optional image stripping in O(N) time.
 */
function sanitizeAndResolveMarkdownProseLinksLinear(
  prose: string,
  opts: { baseUrl?: string; includeImages?: boolean; spaceAdjacentAlnum?: boolean } = {},
): string {
  if (!prose) return prose;
  if (!prose.includes('](') && !prose.includes('<') && !prose.includes('`') && !prose.includes(']:')) {
    return prose;
  }
  const { baseUrl, includeImages = true, spaceAdjacentAlnum = false } = opts;
  const rawBounded = prose.length > MAX_HTML_SCAN_CHARS ? prose.slice(0, MAX_HTML_SCAN_CHARS) : prose;
  const bounded = stripDangerousMultilineMarkdownLinksLinear(rawBounded);
  const proseLines = bounded.split('\n');
  const tickPoisoned = computeTickPoisonedLines(proseLines);
  const resolvedLines = proseLines
    .map((line, lineIdx) => {
      // Strip dangerous reference-link definitions (`[id]: javascript:alert(1)`) in O(1) fast-path + bounded linear check.
      const trimmedLead = line.trimStart();
      if (trimmedLead.startsWith('[') && line.includes(']:')) {
        const closeDef = trimmedLead.indexOf(']:');
        if (closeDef > 1 && closeDef <= 205) {
          const rhs = trimmedLead.slice(closeDef + 2).trim();
          const destToken = rhs.startsWith('<') ? rhs.slice(1, rhs.indexOf('>') > 0 ? rhs.indexOf('>') : rhs.length) : (rhs.split(/\s+/)[0] ?? '');
          if (hasDangerousUriScheme(destToken)) {
            return '';
          }
        }
      }
      if (!line.includes('](') && !line.includes('<') && !line.includes('`')) {
        return line;
      }

      const cursors = createMarkdownLineScanCursors();
      let out = '';
      let lastEmittedCode = 0;
      const emit = (chunk: string) => {
        if (!chunk) return;
        out += chunk;
        lastEmittedCode = chunk.charCodeAt(chunk.length - 1);
      };
      let checkedNoLtOrTick = false;
      let lastCopyIdx = 0;
      let i = 0;
      while (i < line.length) {
        const ch = line.charCodeAt(i);
        // 1. Preserve inline backtick code spans untouched (spacing adjacent single-backtick spans when requested).
        if (ch === 96 && tickPoisoned[lineIdx] === 0) {
          if (isBackslashEscapedAt(line, i)) {
            i++;
            continue;
          }
          const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, i, cursors);
          if (spanEnd > 0) {
            if (spaceAdjacentAlnum && spanEnd < line.length && line.charCodeAt(spanEnd) === 96) {
              emit(`${line.slice(lastCopyIdx, spanEnd)} `);
              lastCopyIdx = spanEnd;
            }
            i = spanEnd;
          } else {
            i = tickEnd;
          }
          continue;
        }

        // 2. Handle angle-bracket autolinks (`<https://...>`, `<mailto:...>`, `<javascript:...>`).
        if (ch === 60 && i + 3 < line.length) {
          const gtLimit = Math.min(line.length, i + 2_049);
          let gt = -1;
          for (let p = i + 1; p < gtLimit; p++) {
            const pc = line.charCodeAt(p);
            if (pc === 62) {
              gt = p;
              break;
            }
            if (pc <= 32 || pc === 60) break;
          }
          if (gt > i + 2) {
            const innerAuto = line.slice(i + 1, gt);
            if (hasDangerousUriScheme(innerAuto)) {
              emit(line.slice(lastCopyIdx, i));
              i = gt + 1;
              lastCopyIdx = i;
              continue;
            }
            if (/^https?:\/\/\S+$/i.test(innerAuto)) {
              emit(`${line.slice(lastCopyIdx, i)}[${innerAuto}](${innerAuto})`);
              i = gt + 1;
              lastCopyIdx = i;
              continue;
            }
            if (/^mailto:[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(innerAuto)) {
              const addr = innerAuto.slice(7);
              emit(`${line.slice(lastCopyIdx, i)}[${addr}](${innerAuto})`);
              i = gt + 1;
              lastCopyIdx = i;
              continue;
            }
          }
        }

        // 3. Handle Markdown links `[label](url)` and images `![alt](url)`.
        if ((ch === 33 || ch === 91) && !isBackslashEscapedAt(line, i)) {
          if (cursors.noCloseBracket || cursors.noCloseParen) {
            // Neither links nor images can match anywhere later on this line; check once if no `<` or `` ` `` remains to finish in O(1)!
            if (!checkedNoLtOrTick) {
              checkedNoLtOrTick = true;
              if (line.indexOf('<', i + 1) < 0 && line.indexOf('`', i + 1) < 0) {
                break;
              }
            }
            i++;
            continue;
          }
          const tok = tryParseMarkdownLinkOrImageAt(line, i, cursors, true);
          if (tok) {
            let href = tok.rawUrl.trim();
            let nextIdx = tok.end;

            if (!href || hasDangerousUriScheme(href)) {
              emit(line.slice(lastCopyIdx, i));
              if (!tok.isImage) {
                const cleanLbl = tok.rawLabel.includes('](')
                  ? sanitizeAndResolveMarkdownProseLinksLinear(tok.rawLabel, { baseUrl, includeImages })
                  : tok.rawLabel;
                emit(cleanLbl);
              }
              i = nextIdx;
              lastCopyIdx = i;
              continue;
            }

            if (baseUrl && /^(?:\/(?!\/)|\.{1,2}\/)/.test(href)) {
              try {
                const resolved = new URL(href, baseUrl);
                if (resolved.protocol === 'https:' || resolved.protocol === 'http:') {
                  href = resolved.toString();
                }
              } catch {
                // keep relative href when baseUrl cannot parse
              }
            }

            if (tok.isImage) {
              emit(line.slice(lastCopyIdx, i));
              if (!includeImages || isTinyOrAvatarImageUrl(href, tok.rawLabel)) {
                i = nextIdx;
                lastCopyIdx = i;
                continue;
              }
              emit(`![${tok.rawLabel}](${href}${tok.titleSuffix})`);
              // Separate consecutive inline images (`![a](u1) ![b](u2)`) onto distinct paragraphs.
              let wsAfter = nextIdx;
              while (wsAfter < line.length && (line.charCodeAt(wsAfter) === 32 || line.charCodeAt(wsAfter) === 9)) wsAfter++;
              if (wsAfter < line.length - 1 && line.charCodeAt(wsAfter) === 33 && line.charCodeAt(wsAfter + 1) === 91) {
                emit('\n\n');
                nextIdx = wsAfter;
              }
              i = nextIdx;
              lastCopyIdx = i;
              continue;
            }

            // Skip `[Skip to content](#...)` anchor boilerplate.
            if (href.startsWith('#') && /^skip to (?:main )?content$/i.test(tok.rawLabel.trim())) {
              emit(line.slice(lastCopyIdx, i));
              while (nextIdx < line.length && (line.charCodeAt(nextIdx) === 32 || line.charCodeAt(nextIdx) === 9)) nextIdx++;
              i = nextIdx;
              lastCopyIdx = i;
              continue;
            }

            let labelOut = tok.rawLabel;
            if (labelOut.includes('](') || labelOut.includes('<')) {
              labelOut = sanitizeAndResolveMarkdownProseLinksLinear(labelOut, { baseUrl, includeImages });
            }
            // Strip redundant `(https://same-url)` suffix inside `[label (https://same-url)](https://same-url)`.
            if (/^https?:\/\//i.test(href) && labelOut.endsWith(`(${href})`)) {
              const trimmedPrefix = labelOut.slice(0, labelOut.length - href.length - 2).trimEnd();
              if (trimmedPrefix) labelOut = trimmedPrefix;
            }
            // Strip redundant trailing `(https://same-url)` immediately after `[label](https://same-url)(https://same-url)`.
            if (/^https?:\/\//i.test(href)) {
              let trail = nextIdx;
              while (trail < line.length && (line.charCodeAt(trail) === 32 || line.charCodeAt(trail) === 9)) trail++;
              if (line.charCodeAt(trail) === 40 && line.startsWith(href, trail + 1) && line.charCodeAt(trail + 1 + href.length) === 41) {
                nextIdx = trail + 2 + href.length;
              }
            }

            const prevCharCode = i > lastCopyIdx ? line.charCodeAt(i - 1) : lastEmittedCode;
            emit(line.slice(lastCopyIdx, i));
            if (spaceAdjacentAlnum && /^https?:\/\//i.test(href) && prevCharCode > 0 && isAsciiAlnumCode(prevCharCode)) {
              emit(' ');
            }
            emit(`[${labelOut}](${href}${tok.titleSuffix})`);
            if (spaceAdjacentAlnum && /^https?:\/\//i.test(href) && nextIdx < line.length && isAsciiAlnumCode(line.charCodeAt(nextIdx))) {
              emit(' ');
            }
            i = nextIdx;
            lastCopyIdx = i;
            continue;
          }
        }

        i++;
      }
      return lastCopyIdx === 0 ? line : out + line.slice(lastCopyIdx);
    });
  return neutralizeResidualDangerousLinkDestinations(resolvedLines.join('\n'));
}

function isResidualHtmlStartChar(c: number): boolean {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 47 || c === 33 || c === 63;
}

/**
 * `R3-H2` defense-in-depth: escapes any residual raw `<tag`, `</tag`, `<!--`, `<!`, or `<?` outside fenced code blocks
 * and inline backtick code spans so raw HTML/XSS tags can never survive into final Markdown prose.
 */
function escapeResidualHtmlInMarkdownProseLinear(prose: string, allowPdfPageMarkers = false): string {
  if (!prose || !prose.includes('<')) return prose;
  const residualLines = prose.split('\n');
  const residualPoisoned = computeTickPoisonedLines(residualLines);
  return residualLines
    .map((line, lineIdx) => {
      if (!line.includes('<')) return line;
      if (allowPdfPageMarkers && /^<!-- page \d{1,6} -->$/.test(line.trim())) {
        return line;
      }
      const isTableRow = line.trimStart().startsWith('|');
      const cursors = createMarkdownLineScanCursors();
      let nextGtIdx = -1;
      let noGtAfter = false;
      let out = '';
      let lastIdx = 0;
      let i = 0;
      while (i < line.length) {
        const ch = line.charCodeAt(i);
        if (ch === 96 && residualPoisoned[lineIdx] === 0) {
          if (isBackslashEscapedAt(line, i)) {
            i++;
            continue;
          }
          const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, i, cursors);
          i = spanEnd > 0 && !(isTableRow && line.slice(i, spanEnd).includes('|')) ? spanEnd : tickEnd;
          continue;
        }
        if (ch === 60 && i + 1 < line.length) {
          const nextCode = line.charCodeAt(i + 1);
          if (isResidualHtmlStartChar(nextCode)) {
            // Preserve valid `<https://...>` and `<mailto:...>` autolinks if not already converted (monotonic `>` cursor).
            if (!noGtAfter && (nextCode === 104 || nextCode === 72 || nextCode === 109 || nextCode === 77)) {
              if (nextGtIdx <= i) {
                nextGtIdx = line.indexOf('>', i + 1);
                if (nextGtIdx < 0) noGtAfter = true;
              }
              if (!noGtAfter && nextGtIdx > i + 2 && nextGtIdx - i <= 2_048) {
                const candidate = line.slice(i + 1, nextGtIdx);
                if (/^(?:https?:\/\/\S+|mailto:[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)$/i.test(candidate)) {
                  i = nextGtIdx + 1;
                  continue;
                }
              }
            }
            out += `${line.slice(lastIdx, i)}&lt;`;
            i++;
            lastIdx = i;
            continue;
          }
        }
        i++;
      }
      return lastIdx === 0 ? line : out + line.slice(lastIdx);
    })
    .join('\n');
}

function escapeResidualHtmlOutsideCodeLinear(md: string, allowPdfPageMarkers = false): string {
  if (!md || !md.includes('<')) return md;
  return splitMarkdownByCodeFences(md)
    .map((part, idx) => (idx % 2 === 1 ? part : escapeResidualHtmlInMarkdownProseLinear(part, allowPdfPageMarkers)))
    .join('');
}

/** Decodes HTML entities in Markdown prose EXCEPT `<` (`&lt;`, `&#60;`, `&#x3c;`) so escaped tag examples never re-materialize as raw HTML. */
function decodeMarkdownEntitiesPreservingLt(prose: string): string {
  if (!prose || !prose.includes('&')) return prose;
  const guarded = prose.replace(/&(?:lt|LT|#0*60|#[xX]0*3[cC]);/g, '\u0000EFLT\u0000');
  return decodeHtmlEntities(guarded).replace(/\u0000EFLT\u0000/g, '&lt;');
}

function stashMarkdownInlineCodeSpansLinear(prose: string, stash: string[]): string {
  if (!prose || !prose.includes('`')) return prose;
  const lines = prose.split('\n');
  const poisoned = computeTickPoisonedLines(lines);
  return lines
    .map((line, lineIdx) => {
      if (!line.includes('`') || poisoned[lineIdx] === 1) return line;
      const cursors = createMarkdownLineScanCursors();
      let out = '';
      let lastIdx = 0;
      let i = 0;
      while (i < line.length) {
        if (line.charCodeAt(i) === 96) {
          if (isBackslashEscapedAt(line, i)) {
            i++;
            continue;
          }
          const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, i, cursors);
          if (spanEnd > 0) {
            out += `${line.slice(lastIdx, i)}\u0000EFMDINLINE${stash.push(line.slice(i, spanEnd)) - 1}\u0000`;
            i = spanEnd;
            lastIdx = i;
            continue;
          }
          i = tickEnd;
          continue;
        }
        i++;
      }
      return lastIdx === 0 ? line : out + line.slice(lastIdx);
    })
    .join('\n');
}

function cleanCodeFenceSegment(rawFenceBlock: string): string {
  let fenceBlock = rawFenceBlock;
  // Strip single-line minified `<script type="application/ld+json">` (`schema.org`) metadata blocks emitted by
  // edge HTML-to-Markdown converters, while leaving multi-line JSON-LD code examples in tutorials untouched.
  if (
    fenceBlock.length < 32_768 &&
    fenceBlock.includes('schema.org') &&
    /^`{3,}json[ \t]*\r?\n\{\s*"@context"\s*:\s*"https?:\/\/schema\.org"[^\r\n]{100,}\r?\n`{3,}$/i.test(fenceBlock.trim())
  ) {
    return '';
  }
  const nlIdx = fenceBlock.indexOf('\n');
  if (nlIdx === -1) {
    const m1 = /^([ ]{0,3}(?:`{3,}|~{3,}))(.*)$/.exec(fenceBlock.replace(/\r$/, ''));
    return m1 ? `${m1[1]!}${cleanFenceInfoStringLinear(m1[2]!)}` : fenceBlock.replace(/</g, '&lt;');
  }
  const rawHeader = fenceBlock.slice(0, nlIdx).replace(/\r$/, '');
  const headerOpenMatch = /^([ ]{0,3}(?:`{3,}|~{3,}))(.*)$/.exec(rawHeader);
  const fencePrefix = headerOpenMatch ? headerOpenMatch[1]! : '';
  const rawInfo = headerOpenMatch ? headerOpenMatch[2]! : '';
  const cleanHeader = fencePrefix ? `${fencePrefix}${cleanFenceInfoStringLinear(rawInfo)}` : rawHeader.slice(0, 256).replace(/</g, '&lt;');

  const closeMatch = /\r?\n([ ]{0,3}(?:`{3,}|~{3,})[ \t]*)$/.exec(fenceBlock);
  if (!closeMatch) {
    return `${cleanHeader}${fenceBlock.slice(nlIdx)}`;
  }
  const closingFence = closeMatch[1]!;
  let innerCode = fenceBlock.slice(nlIdx + 1, closeMatch.index);

  const boundedHeaderPrefix = rawInfo.slice(0, 256);
  const isTwoslash =
    /\btwoslash\b/i.test(boundedHeaderPrefix) || /^[ \t]*\/\/[ \t]*---cut(?:-(?:before|after))?---[ \t]*$/m.test(innerCode);
  if (isTwoslash) {
    const cutLineMatch = /^[ \t]*\/\/[ \t]*---cut(?:-before)?---[ \t]*\r?\n/m.exec(innerCode);
    if (cutLineMatch) {
      innerCode = innerCode.slice(cutLineMatch.index + cutLineMatch[0].length);
    }
    const cutAfterMatch = /\r?\n[ \t]*\/\/[ \t]*---cut-after---[ \t]*(?:\r?\n|$)/m.exec(innerCode);
    if (cutAfterMatch) {
      innerCode = innerCode.slice(0, cutAfterMatch.index);
    }
    innerCode = innerCode.replace(
      /^[ \t]*\/\/[ \t]*@(?:noErrors|errors:[ \t]*[\d \t]+|target:[ \t]*\S+|module:[ \t]*\S+|moduleResolution:[ \t]*\S+|lib:[ \t]*\S+|strict(?::[ \t]*\S+)?)[ \t]*\r?\n/gm,
      '',
    );
  }

  return `${cleanHeader}\n${innerCode}\n${closingFence}`;
}

function sanitizeInlineHtmlInMarkdownSinglePass(md: string, baseUrl?: string, allowPdfPageMarkers = false): string {
  if (!md) return '';
  let boundedInput = md.length > MAX_HTML_SCAN_CHARS ? md.slice(0, MAX_HTML_SCAN_CHARS) : md;
  if (boundedInput.includes('\u0000')) boundedInput = boundedInput.replace(/\u0000/g, '');
  let withoutMintlifyBanner = stripInvisibleSmugglingChars(boundedInput);
  if (withoutMintlifyBanner.includes('\r')) withoutMintlifyBanner = withoutMintlifyBanner.replace(/\r(?!\n)/g, '\n');
  if (withoutMintlifyBanner.slice(0, 256).includes('Documentation Index')) {
    withoutMintlifyBanner = withoutMintlifyBanner.replace(
      /^\s*>\s*##\s*Documentation Index[ \t]*\r?\n>\s*Fetch the complete documentation index at:\s*\S+[ \t]*\r?\n>\s*Use this file to discover all available pages before exploring further\.[ \t]*\r?\n+/i,
      '',
    );
  }
  const mintlifyNeedle = 'this documentation is built and hosted on [mintlify](';
  const tailStart = Math.max(0, withoutMintlifyBanner.length - 600);
  const tailLower = withoutMintlifyBanner.slice(tailStart).toLowerCase();
  const mintlifyRelIdx = tailLower.lastIndexOf(mintlifyNeedle);
  if (mintlifyRelIdx >= 0) {
    const absIdx = tailStart + mintlifyRelIdx;
    const suffix = withoutMintlifyBanner.slice(absIdx);
    if (/^This documentation is built and hosted on \[Mintlify\]\([^)\r\n]{1,300}\),\s*a developer documentation platform\.[ \t]*$/i.test(suffix)) {
      let cut = absIdx;
      while (cut > 0 && (withoutMintlifyBanner.charCodeAt(cut - 1) === 10 || withoutMintlifyBanner.charCodeAt(cut - 1) === 13)) {
        cut--;
      }
      withoutMintlifyBanner = withoutMintlifyBanner.slice(0, cut);
    }
  }

  const hardenedInput = hardenMarkdownFenceStructure(withoutMintlifyBanner);
  const parts = splitMarkdownByCodeFences(hardenedInput);
  return parts
    .map((part, idx) => {
      if (idx % 2 === 1) {
        return cleanCodeFenceSegment(part);
      }
      let proseWork = detachBareUrlsFromCodeSpansLinear(part);
      // Strip JSX / MDX inline comments (`{/*reference*/}`, `{/* ... */}`) outside code fences in linear O(N) time.
      if (proseWork.includes('{/*')) {
        let outJsx = '';
        let cur = 0;
        while (cur < proseWork.length) {
          const start = proseWork.indexOf('{/*', cur);
          if (start < 0) {
            outJsx += proseWork.slice(cur);
            break;
          }
          outJsx += proseWork.slice(cur, start);
          const end = proseWork.indexOf('*/}', start + 3);
          if (end < 0) {
            outJsx += proseWork.slice(start);
            break;
          }
          cur = end + 3;
        }
        proseWork = outJsx;
      }

      // Stash inline backtick code spans (`...`) BEFORE HTML sanitization so `<script>` / `<T>` inside backticks stay untouched.
      const inlineCodeStash: string[] = [];
      proseWork = stashMarkdownInlineCodeSpansLinear(proseWork, inlineCodeStash);

      // Strip HTML comments, dangerous active/script/style/svg/form subtrees, and hidden (`display:none` / `[hidden]`) subtrees linearly.
      if (proseWork.includes('<!--')) {
        if (allowPdfPageMarkers) {
          proseWork = proseWork.replace(/^([ \t]*)<!-- page (\d{1,6}) -->([ \t]*)$/gm, '$1\u0000EFPDFPAGE$2\u0000$3');
        }
        proseWork = stripHtmlCommentsLinear(proseWork, MAX_HTML_SCAN_CHARS);
        if (allowPdfPageMarkers && proseWork.includes('\u0000EFPDFPAGE')) {
          proseWork = proseWork.replace(/\u0000EFPDFPAGE(\d{1,6})\u0000/g, '<!-- page $1 -->');
        }
      }
      if (proseWork.includes('<') && proseWork.includes('>')) {
        if (/<(?:script|style|iframe|object|embed|applet|svg|math|form|noscript|template|head|meta|link|base)\b/i.test(proseWork)) {
          proseWork = stripHtmlTagsLinear(
            proseWork,
            ['script', 'style', 'iframe', 'object', 'embed', 'applet', 'svg', 'math', 'form', 'noscript', 'template', 'head', 'meta', 'link', 'base'],
            '',
            MAX_HTML_SCAN_CHARS,
          );
        }
        if (/(?:hidden|style|role|class)/i.test(proseWork)) {
          proseWork = stripHiddenAndChromeSubtrees(proseWork);
        }
      }

      if (proseWork.includes(':::')) {
        proseWork = proseWork
          // Convert VitePress / Docusaurus `:::` / `::::` admonition containers into clean bold callout headers and strip layout containers.
          .replace(
            /^[ \t]*:{3,}[ \t]*(info|tip|note|warning|caution|danger|important|details)(?:[ \t]+([^\r\n]{1,200}))?[ \t]*$/gim,
            (_m, kindRaw: string, customTitle?: string) => {
              const kindLabel = kindRaw.charAt(0).toUpperCase() + kindRaw.slice(1).toLowerCase();
              const custom = customTitle?.trim();
              if (custom && custom.toLowerCase() !== kindRaw.toLowerCase()) {
                return `\n\n**${kindLabel}: ${custom}**\n\n`;
              }
              return `\n\n**${kindLabel}**\n\n`;
            },
          )
          .replace(/^[ \t]*:{3,}(?:[ \t]*(?:code-group|tabs|tab(?:[ \t]+[^\r\n]{0,120})?|raw|v-pre))?[ \t]*$/gim, '');
      }

      if (proseWork.includes('<') && proseWork.includes('>')) {
        if (proseWork.includes('[') && proseWork.includes('</h')) {
          proseWork = proseWork.replace(/\[\s*<h([1-6])\b[^>"\n]{0,200}>([^<\n]{1,400})<\/h\1>\s*\]\(([^)\s\n]{1,2048})\)/gi, (_m, lvl, inner, href) => {
            const label = cleanInlineHtml(String(inner));
            const rawHref = String(href).trim();
            if (!label || hasDangerousUriScheme(rawHref)) return label;
            return `\n\n${'#'.repeat(Number(lvl))} [${label}](${rawHref})\n\n`;
          });
        }

        if (proseWork.includes('</')) {
          proseWork = replacePairedHtmlElementsLinear(
            proseWork,
            ['a'],
            (_full, _tag, attrStr, inner) => {
              const trimmedInner = inner.trim();
              if (/^<h[1-6]\b/i.test(trimmedInner)) {
                let hInfo: { lvl: number; txt: string } | null = null;
                replacePairedHtmlElementsLinear(trimmedInner, ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'], (hf, ht, _ha, hInner) => {
                  if (!hInfo && hf.length === trimmedInner.length) {
                    hInfo = { lvl: Number(ht.slice(1)), txt: cleanInlineHtml(hInner) };
                  }
                  return '';
                });
                if (hInfo) {
                  const hi = hInfo as { lvl: number; txt: string };
                  if (!hi.txt) return '';
                  const attrs = parseTagAttrs(attrStr);
                  const href = resolveHttpsHref(attrs.href, baseUrl, true);
                  return href ? `\n\n${'#'.repeat(hi.lvl)} [${hi.txt}](${href})\n\n` : `\n\n${'#'.repeat(hi.lvl)} ${hi.txt}\n\n`;
                }
              }
              const attrs = parseTagAttrs(attrStr);
              const href = resolveHttpsHref(attrs.href, baseUrl, true);
              const label = cleanInlineHtml(inner);
              if (!label) return '';
              return href ? `[${label}](${href})` : label;
            },
            { maxChars: MAX_HTML_SCAN_CHARS },
          );

          proseWork = replacePairedHtmlElementsLinear(
            proseWork,
            ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'summary', 'code', 'kbd', 'strong', 'b', 'em', 'i', 'sup'],
            (_full, tag, _attrStr, inner) => {
              const txt = cleanInlineHtml(inner);
              if (!txt) return '';
              if (tag.length === 2 && tag.charCodeAt(0) === 104) {
                const lvl = tag.charCodeAt(1) - 48;
                return `\n\n${'#'.repeat(lvl)} ${txt}\n\n`;
              }
              if (tag === 'summary') return `\n\n**${txt}**\n\n`;
              if (tag === 'code' || tag === 'kbd') {
                const span = formatInlineCodeSpan(txt);
                return span ? `\u0000EFMDINLINE${inlineCodeStash.push(span) - 1}\u0000` : '';
              }
              if (tag === 'strong' || tag === 'b') return `**${txt}**`;
              if (tag === 'em' || tag === 'i') return `*${txt}*`;
              return /^[\d,\s-]+$/.test(txt) ? ` [${txt}]` : `^${txt}`;
            },
            { maxChars: MAX_HTML_SCAN_CHARS },
          );
        }

        // Single linear quote-aware tag pass with monotonic O(1) amortized line-bounds cursor (`< 5 ms` on `<br>`.repeat(100k) and `<A HREF="x">`.repeat(50k)).
        let curLineStart = 0;
        const firstNl = proseWork.indexOf('\n');
        let curLineEnd = firstNl < 0 ? proseWork.length : firstNl;
        const computeStartsWithPipe = (ls: number, le: number): boolean => {
          let p = ls;
          while (p < le && (proseWork.charCodeAt(p) === 32 || proseWork.charCodeAt(p) === 9)) p++;
          return p < le && proseWork.charCodeAt(p) === 124;
        };
        let curLineStartsWithPipe = computeStartsWithPipe(curLineStart, curLineEnd);
        const syncLineBounds = (tagIdx: number) => {
          if (tagIdx > curLineEnd) {
            curLineStart = proseWork.lastIndexOf('\n', tagIdx - 1) + 1;
            const nextNl = proseWork.indexOf('\n', tagIdx);
            curLineEnd = nextNl < 0 ? proseWork.length : nextNl;
            curLineStartsWithPipe = computeStartsWithPipe(curLineStart, curLineEnd);
          }
        };

        proseWork = replaceHtmlTagsQuoteAwareLinear(
          proseWork,
          (tag) => {
            if (tag.tagNameLower === 'br') {
              syncLineBounds(tag.index);
              return curLineStartsWithPipe ? ' / ' : '\n';
            }
            if (tag.tagNameLower === 'hr' && !tag.isClosing) {
              return '\n\n---\n\n';
            }
            if (tag.tagNameLower === 'img' && !tag.isClosing) {
              const attrs = parseTagAttrs(tag.attrs);
              const resolvedSrc = resolveHttpsHref(attrs.src ?? attrs['data-src'], baseUrl);
              const alt = cleanInlineHtml(attrs.alt ?? '');
              if (!resolvedSrc || isTinyOrAvatarImageUrl(resolvedSrc, alt)) return '';
              return `![${alt}](${resolvedSrc})`;
            }
            const firstRawCode = tag.rawTag.charCodeAt(tag.isClosing ? 2 : 1);
            if (firstRawCode >= 65 && firstRawCode <= 90) {
              if (!tag.isClosing && !tag.isSelfClosing && tag.attrs && (tag.attrs.includes('title') || tag.attrs.includes('TITLE'))) {
                syncLineBounds(tag.index);
                if (
                  tag.index - curLineStart <= 64 &&
                  curLineEnd - tag.end <= 64 &&
                  proseWork.slice(curLineStart, tag.index).trim() === '' &&
                  proseWork.slice(tag.end, curLineEnd).trim() === ''
                ) {
                  const attrs = parseTagAttrs(tag.attrs);
                  const headingTitle = cleanInlineHtml(attrs.title ?? attrs.titletext ?? '');
                  if (headingTitle) return `\n\n**${headingTitle}**\n\n`;
                }
              }
              return '';
            }
            if (
              tag.tagNameLower === 'u' ||
              tag.tagNameLower === 'details' ||
              tag.tagNameLower === 'span' ||
              tag.tagNameLower === 'div' ||
              tag.tagNameLower === 'p' ||
              tag.tagNameLower === 'button' ||
              tag.tagNameLower === 'section' ||
              tag.tagNameLower === 'article' ||
              tag.tagNameLower === 'main' ||
              tag.tagNameLower === 'header' ||
              tag.tagNameLower === 'footer' ||
              tag.tagNameLower === 'nav' ||
              tag.tagNameLower === 'aside'
            ) {
              return '';
            }
            return tag.rawTag;
          },
          MAX_HTML_SCAN_CHARS,
          false,
        );
      }

      if (proseWork.includes('&') && (proseWork.includes('](') || proseWork.includes('<') || proseWork.includes(']:'))) {
        proseWork = sanitizeAndResolveMarkdownProseLinksLinear(proseWork, { baseUrl, includeImages: true });
      }
      proseWork = decodeMarkdownEntitiesPreservingLt(proseWork);
      if (inlineCodeStash.length > 0) {
        proseWork = proseWork.replace(/\u0000EFMDINLINE(\d+)\u0000/g, (_m, sIdx: string) => inlineCodeStash[Number(sIdx)] ?? '');
      }

      if (proseWork.toLowerCase().includes('helpful?')) {
        proseWork = proseWork.replace(
          /(?:^|\n)Was this (?:page )?helpful\?[ \t]*(?:\n+(?:Yes[ \t]*No|Yes[ \t]*\/[ \t]*No))?[ \t]*(?=\n|$)/gi,
          '\n',
        );
      }
      if (idx === parts.length - 1) {
        const tailOnPage = proseWork.slice(Math.max(0, proseWork.length - 2_000));
        const onPageIdx = tailOnPage.toLowerCase().lastIndexOf('\n## on this page');
        if (onPageIdx >= 0) {
          const absOnPage = Math.max(0, proseWork.length - 2_000) + onPageIdx;
          const tailCandidate = proseWork.slice(absOnPage);
          if (/^\n##+[ \t]+On this page[ \t]*(?:\n+(?:[-*][ \t]+\[[^\[\]\n]{1,200}\]\(#[^)\n]{1,200}\)[ \t]*)+)?[ \t]*$/i.test(tailCandidate)) {
            proseWork = proseWork.slice(0, absOnPage);
          }
        }
      }

      const detachedAfterRestore = detachBareUrlsFromCodeSpansLinear(proseWork);
      const resolvedProse = sanitizeAndResolveMarkdownProseLinksLinear(detachedAfterRestore, { baseUrl, includeImages: true });
      return escapeResidualHtmlInMarkdownProseLinear(resolvedProse, allowPdfPageMarkers).replace(/\n{3,}/g, '\n\n');
    })
    .map((part, idx) => (idx % 2 === 1 ? part : dedupeConsecutiveStandaloneLinkParagraphs(part)))
    .join('');
}

export function sanitizeInlineHtmlInMarkdown(md: string, baseUrl?: string, allowPdfPageMarkers = false): string {
  if (!md) return '';
  let cur = sanitizeInlineHtmlInMarkdownSinglePass(md, baseUrl, allowPdfPageMarkers);
  if (!cur) return '';
  // Fast exit when output contains no constructs that could re-interact across passes
  if (!cur.includes('<') && !cur.includes('](') && !cur.includes(']:') && !cur.includes('```') && !cur.includes('~~~')) {
    return cur;
  }
  for (let pass = 0; pass < 3; pass++) {
    const again = sanitizeInlineHtmlInMarkdownSinglePass(cur, baseUrl, allowPdfPageMarkers);
    if (again === cur) return cur;
    cur = again;
  }
  // Fail closed if adversarial input did not converge within 4 total passes
  return escapeResidualHtmlOutsideCodeLinear(cur, allowPdfPageMarkers).replace(/\]\((?=[ \t]*[a-zA-Z]+:)/g, ']\\ (');
}

function sanitizeFrontmatterFieldText(raw: string): string {
  const withoutComments = raw.includes('<!--') ? stripHtmlCommentsLinear(raw, 4_096) : raw;
  const withoutScripts = withoutComments.includes('<')
    ? stripHtmlTagsLinear(withoutComments, ['script', 'style', 'iframe', 'svg', 'noscript', 'template'], ' ', 4_096)
    : withoutComments;
  const withoutTags = withoutScripts.includes('<') ? stripHtmlTagsQuoteAwareLinear(withoutScripts, ' ', 4_096) : withoutScripts;
  return stripInvisibleSmugglingChars(decodeHtmlEntities(withoutTags)).replace(/\s+/g, ' ').trim();
}

export function parseMarkdownFrontmatter(md: string): { title?: string; description?: string; body: string } {
  if (!md.startsWith('---')) return { body: md };
  const head = md.slice(0, 4_200).replace(/\r\n/g, '\n');
  if (!head.startsWith('---\n')) return { body: md };
  const closeIdx = head.indexOf('\n---', 4);
  if (closeIdx < 0 || closeIdx > 4_004) return { body: md };
  let afterClose = closeIdx + 4;
  if (afterClose < head.length && head.charCodeAt(afterClose) !== 10) return { body: md };
  while (afterClose < head.length && head.charCodeAt(afterClose) === 10) afterClose++;

  const fmBlock = head.slice(4, closeIdx);
  let title: string | undefined;
  let description: string | undefined;
  for (const line of fmBlock.split('\n')) {
    const kv = /^([a-zA-Z0-9_-]{1,64})[ \t]*:[ \t]*(.+)$/.exec(line.trim());
    if (!kv) continue;
    const k = kv[1]!.toLowerCase();
    const v = kv[2]!.trim().replace(/^(['"])([\s\S]*)\1$/, '$2').trim();
    if (k === 'title' && v && !title) {
      const cleanTitle = sanitizeFrontmatterFieldText(v);
      if (cleanTitle) title = cleanTitle;
    }
    if (k === 'description' && v && !description) {
      const cleanDesc = sanitizeFrontmatterFieldText(v);
      if (cleanDesc) description = cleanDesc;
    }
  }

  // Advance past the matching `---` + blank lines in the original string (handling `\r\n` cleanly).
  const rawCloseMatch = /^---\r?\n[\s\S]{1,4004}?\r?\n---(?:\r?\n+|$)/.exec(md.slice(0, 4_300));
  const body = rawCloseMatch ? md.slice(rawCloseMatch[0].length) : md.slice(afterClose);
  return {
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    body,
  };
}

export function extractMarkdownLinksAndImages(
  md: string,
  baseUrl: string,
  includeImages: boolean,
): { links: string[]; images: ScrapedImage[]; title?: string; description?: string } {
  const boundedMd = md.length > MAX_HTML_SCAN_CHARS ? md.slice(0, MAX_HTML_SCAN_CHARS) : md;
  const fmParsed = parseMarkdownFrontmatter(boundedMd);
  let title = fmParsed.title;
  const description = fmParsed.description;

  const proseOnly = splitMarkdownByCodeFences(fmParsed.body)
    .filter((_, idx) => idx % 2 === 0)
    .join('\n');
  const lines = proseOnly.split(/\r?\n/);
  if (!title) {
    for (const rawLine of lines) {
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.startsWith('>')) continue;
      const h1 = /^#[ \t]+(.+)$/.exec(trimmed);
      if (h1?.[1]) {
        const cleanH1 = sanitizeFrontmatterFieldText(stripMarkdownLinksToLabelsLinear(h1[1]));
        if (cleanH1) title = cleanH1;
        break;
      }
    }
  }

  const images: ScrapedImage[] = [];
  const seenImages = new Set<string>();
  const links: string[] = [];
  const seenLinks = new Set<string>();

  const collectFromLine = (line: string) => {
    if (!line.includes('](') && !line.includes('<')) return;
    const cursors = createMarkdownLineScanCursors();
    let nextGt = -1;
    let noGtLeft = false;
    let i = 0;
    while (i < line.length) {
      if (links.length >= 250 && (!includeImages || images.length >= 60)) break;
      const ch = line.charCodeAt(i);
      if (ch === 96) {
        if (isBackslashEscapedAt(line, i)) {
          i++;
          continue;
        }
        const { tickEnd, spanEnd } = scanCodeSpanEndLinear(line, i, cursors);
        i = spanEnd > 0 ? spanEnd : tickEnd;
        continue;
      }
      if (ch === 60 && !noGtLeft && links.length < 250) {
        if (nextGt <= i) {
          nextGt = line.indexOf('>', i + 1);
          if (nextGt < 0) noGtLeft = true;
        }
        if (!noGtLeft && nextGt > i + 8 && nextGt - i <= 2_048) {
          const autoCandidate = line.slice(i + 1, nextGt);
          if (/^https?:\/\/\S+$/i.test(autoCandidate)) {
            const resolved = resolveHttpsHref(autoCandidate, baseUrl);
            if (resolved && !seenLinks.has(resolved)) {
              seenLinks.add(resolved);
              links.push(resolved);
            }
            i = nextGt + 1;
            continue;
          }
        }
      }
      if ((ch === 33 || ch === 91) && !isBackslashEscapedAt(line, i)) {
        const tok = tryParseMarkdownLinkOrImageAt(line, i, cursors, true);
        if (tok) {
          const rawHref = tok.rawUrl.trim();
          if (tok.isImage) {
            if (includeImages && images.length < 60 && rawHref && !hasDangerousUriScheme(rawHref)) {
              const alt = tok.rawLabel.trim();
              const resolved = resolveHttpsHref(rawHref, baseUrl);
              if (resolved && !seenImages.has(resolved) && !isTinyOrAvatarImageUrl(resolved, alt)) {
                seenImages.add(resolved);
                images.push({ url: resolved, ...(alt ? { alt } : {}) });
              }
            }
          } else {
            if (tok.rawLabel.includes('![') && includeImages && images.length < 60) {
              collectFromLine(tok.rawLabel);
            }
            if (links.length < 250 && rawHref && !rawHref.startsWith('#') && !hasDangerousUriScheme(rawHref)) {
              const resolved = resolveHttpsHref(rawHref, baseUrl);
              if (resolved && !seenLinks.has(resolved)) {
                seenLinks.add(resolved);
                links.push(resolved);
              }
            }
          }
          i = tok.end;
          continue;
        }
      }
      i++;
    }
  };

  for (const line of lines) {
    if (links.length >= 250 && (!includeImages || images.length >= 60)) break;
    collectFromLine(line);
  }

  return {
    links,
    images,
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
  };
}

/**
 * Strips invisible Unicode Tag smuggling (`U+E0000`–`U+E007F`), Variation Selectors Supplement (`U+E0100`–`U+E01EF`),
 * Bidi overrides/isolates, zero-width / soft-hyphen characters, ANSI CSI sequences, and raw ASCII C0/DEL control bytes.
 */
export function stripInvisibleSmugglingChars(s: string): string {
  if (!s) return s;
  return s
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu,
      '',
    );
}

function cleanOriginNegotiatedMarkdown(md: string, baseUrl?: string): string {
  const bounded = md.length > MAX_HTML_SCAN_CHARS ? md.slice(0, MAX_HTML_SCAN_CHARS) : md;
  const parts = splitMarkdownByCodeFences(bounded);
  const withoutSchemaFences = parts
    .map((part, idx) => {
      if (idx % 2 === 1) {
        if (part.length < 32_768 && part.includes('schema.org')) {
          const trimmedFence = part.trim();
          if (
            /^`{3,}json[ \t]*\r?\n(?:\{\s*"@context"\s*:\s*"https?:\/\/schema\.org"[^\r\n]{80,}\r?\n)+\s*`{3,}$/i.test(
              trimmedFence,
            )
          ) {
            return '';
          }
        }
        return part;
      }
      return part;
    })
    .join('');
  // `R3-M3`: Always run full `sanitizeInlineHtmlInMarkdown` + dangerous link scheme stripping + residual `<tag` escaping on `origin-markdown`!
  return sanitizeInlineHtmlInMarkdown(withoutSchemaFences, baseUrl);
}

export function finalizeScrapedMarkdown(
  rawMd: string,
  opts: {
    isPdf: boolean;
    includeImages: boolean;
    maxChars?: number;
    baseUrl?: string;
    preserveOriginMarkdown?: boolean;
    allowPdfPageMarkers?: boolean;
  },
): {
  markdown: string;
  truncated?: boolean;
  totalChars?: number;
  nextOffset?: number;
  frontmatterTitle?: string;
  frontmatterDescription?: string;
} {
  const deadlineAt = Date.now() + 2_500;
  const boundedInput = rawMd.length > MAX_HTML_SCAN_CHARS ? rawMd.slice(0, MAX_HTML_SCAN_CHARS) : rawMd;
  const fm = opts.isPdf ? { body: boundedInput } : parseMarkdownFrontmatter(boundedInput);
  let md = opts.preserveOriginMarkdown
    ? stripInvisibleSmugglingChars(cleanOriginNegotiatedMarkdown(fm.body, opts.baseUrl))
    : stripInvisibleSmugglingChars(sanitizeInlineHtmlInMarkdown(fm.body, opts.baseUrl, Boolean(opts.allowPdfPageMarkers)));
  if (opts.isPdf && Date.now() <= deadlineAt) {
    md = cleanPdfMarkdown(md);
  }
  if (!opts.includeImages && Date.now() <= deadlineAt) {
    md = splitMarkdownByCodeFences(md)
      .map((part, idx) =>
        idx % 2 === 1 ? part : sanitizeAndResolveMarkdownProseLinksLinear(part, { baseUrl: opts.baseUrl, includeImages: false }),
      )
      .join('');
  }
  md = escapeResidualHtmlOutsideCodeLinear(md, Boolean(opts.allowPdfPageMarkers))
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  const fmMeta = {
    ...(fm.title ? { frontmatterTitle: fm.title } : {}),
    ...(fm.description ? { frontmatterDescription: fm.description } : {}),
  };
  if (opts.maxChars && md.length > opts.maxChars) {
    const totalChars = md.length;
    let cut = opts.maxChars;
    const minCut = Math.floor(opts.maxChars * 0.6);
    const paraBreak = md.lastIndexOf('\n\n', cut);
    const lineBreak = md.lastIndexOf('\n', cut);
    const spaceBreak = md.lastIndexOf(' ', cut);
    if (paraBreak >= minCut) cut = paraBreak;
    else if (lineBreak >= minCut) cut = lineBreak;
    else if (spaceBreak >= minCut) cut = spaceBreak;
    let sliced = md.slice(0, cut).trimEnd();
    const nextOffset = sliced.length;
    // Close any open fenced code block so truncated previews never leave unbalanced Markdown fences.
    let openFence = '';
    for (const line of sliced.split('\n')) {
      const fmLine = /^(`{3,}|~{3,})/.exec(line.trim());
      if (fmLine?.[1]) {
        if (!openFence) openFence = fmLine[1][0]!.repeat(fmLine[1].length);
        else if (fmLine[1][0] === openFence[0] && fmLine[1].length >= openFence.length && /^[`~]+\s*$/.test(line.trim())) openFence = '';
      }
    }
    if (openFence) {
      sliced = `${sliced}\n${openFence}`;
    }
    return { markdown: sliced, truncated: true, totalChars, nextOffset, ...fmMeta };
  }
  return { markdown: md, ...fmMeta };
}

interface PdfOcrContainerReply {
  ok?: boolean;
  sha256?: string;
  bytes?: number;
  pageCount?: number;
  totalChars?: number;
  markdown?: string;
  ocr?: {
    mode?: string;
    engine?: string | null;
    pagesAttempted?: number;
    pagesOcred?: number;
    pagesSkipped?: number;
    skippedReason?: string | null;
  };
  error?: string;
  message?: string;
}

function decodeBase64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function hasPdfMagicHeader(bytes: Uint8Array): boolean {
  const limit = Math.min(bytes.byteLength, 1024);
  for (let i = 0; i <= limit - 5; i++) {
    if (
      bytes[i] === 0x25 && // %
      bytes[i + 1] === 0x50 && // P
      bytes[i + 2] === 0x44 && // D
      bytes[i + 3] === 0x46 && // F
      bytes[i + 4] === 0x2d // -
    ) {
      return true;
    }
  }
  return false;
}

const CODE_EXT_LANG_MAP: Record<string, string> = {
  ts: 'ts',
  tsx: 'tsx',
  js: 'js',
  jsx: 'jsx',
  mjs: 'js',
  cjs: 'js',
  json: 'json',
  jsonc: 'jsonc',
  py: 'python',
  go: 'go',
  rs: 'rust',
  rb: 'ruby',
  java: 'java',
  kt: 'kotlin',
  cs: 'csharp',
  cpp: 'cpp',
  c: 'c',
  h: 'c',
  sh: 'bash',
  bash: 'bash',
  zsh: 'zsh',
  ps1: 'powershell',
  yml: 'yaml',
  yaml: 'yaml',
  toml: 'toml',
  sql: 'sql',
  html: 'html',
  css: 'css',
  scss: 'scss',
  xml: 'xml',
  proto: 'protobuf',
  graphql: 'graphql',
};

function parseGitHubBlobRawTarget(urlStr: string): {
  rawUrl: string;
  repoSlug: string;
  filePath: string;
  fenceLang: string;
  isMarkdown: boolean;
} | null {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.hostname.toLowerCase() !== 'github.com') return null;
  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length < 5 || parts[2] !== 'blob') return null;
  const owner = parts[0]!;
  const repo = parts[1]!;
  if (['orgs', 'settings', 'sponsors', 'users', 'login', 'marketplace'].includes(owner.toLowerCase())) {
    return null;
  }
  const restParts = parts.slice(3);
  let filePath = restParts.slice(1).join('/');
  if (restParts[0] === 'refs' && (restParts[1] === 'heads' || restParts[1] === 'tags') && restParts.length >= 4) {
    filePath = restParts.slice(3).join('/');
  }
  if (!filePath) return null;
  const baseName = filePath.split('/').pop() ?? filePath;
  const extMatch = /\.([a-z0-9]+)$/i.exec(baseName);
  const ext = extMatch?.[1]?.toLowerCase() ?? '';
  const isMarkdown = ext === 'md' || ext === 'mdx' || ext === 'markdown';
  const fenceLang =
    baseName.toLowerCase() === 'dockerfile'
      ? 'dockerfile'
      : baseName.toLowerCase() === 'makefile'
        ? 'makefile'
        : (CODE_EXT_LANG_MAP[ext] ?? ext);
  return {
    rawUrl: `https://raw.githubusercontent.com/${owner}/${repo}/${restParts.join('/')}`,
    repoSlug: `${owner}/${repo}`,
    filePath,
    fenceLang,
    isMarkdown,
  };
}

function parseGitHubCommitPatchTarget(urlStr: string): {
  patchUrl: string;
  repoSlug: string;
  sha: string;
} | null {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.hostname.toLowerCase() !== 'github.com') return null;
  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length !== 4 || parts[2] !== 'commit') return null;
  const owner = parts[0]!;
  const repo = parts[1]!;
  const sha = parts[3]!;
  if (['orgs', 'settings', 'sponsors', 'users', 'login', 'marketplace'].includes(owner.toLowerCase())) {
    return null;
  }
  if (!/^[0-9a-f]{7,40}$/i.test(sha)) return null;
  return {
    patchUrl: `https://github.com/${owner}/${repo}/commit/${sha}.patch`,
    repoSlug: `${owner}/${repo}`,
    sha,
  };
}

/** Formats RFC 5545 iCalendar (`text/calendar` / `BEGIN:VCALENDAR`) feeds into clean Markdown event summaries. */
export function formatIcalendarToMarkdown(raw: string): { title?: string; description?: string; markdown: string } | null {
  if (!/^BEGIN:VCALENDAR\b/im.test(raw.slice(0, 512))) return null;
  const boundedRaw = raw.length > MAX_HTML_SCAN_CHARS ? raw.slice(0, MAX_HTML_SCAN_CHARS) : raw;
  const unfolded = boundedRaw.replace(/\r?\n[ \t]/g, '');
  const upperUnfolded = unfolded.toUpperCase();
  const formatIcsDate = (v: string): string => {
    const clean = v.trim();
    const dtMatch = /^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?$/.exec(clean);
    if (!dtMatch) return clean;
    const datePart = `${dtMatch[1]}-${dtMatch[2]}-${dtMatch[3]}`;
    if (!dtMatch[4]) return datePart;
    return `${datePart} ${dtMatch[4]}:${dtMatch[5]}${dtMatch[7] ? ' UTC' : ''}`;
  };
  const unescapeIcsVal = (v: string): string =>
    v
      .replace(/\\n/gi, ' ')
      .replace(/\\([,;\\])/g, '$1')
      .replace(/\s+/g, ' ')
      .trim();

  let calName = '';
  let calDesc = '';
  const firstVeventIdx = upperUnfolded.indexOf('BEGIN:VEVENT');
  const headerSlice = firstVeventIdx >= 0 ? unfolded.slice(0, firstVeventIdx) : unfolded.slice(0, 8_192);
  for (const line of headerSlice.split(/\r?\n/)) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const k = line.slice(0, colon).split(';')[0]!.trim().toUpperCase();
    const v = unescapeIcsVal(line.slice(colon + 1));
    if ((k === 'X-WR-CALNAME' || k === 'NAME') && v && !calName) calName = v;
    if ((k === 'X-WR-CALDESC' || k === 'DESCRIPTION') && v && !calDesc) calDesc = v;
  }

  const eventSections: string[] = [];
  const beginMarker = 'BEGIN:VEVENT';
  const endMarker = 'END:VEVENT';
  let scanPos = firstVeventIdx >= 0 ? firstVeventIdx : unfolded.length;
  while (scanPos < upperUnfolded.length && eventSections.length < 50) {
    const bIdx = upperUnfolded.indexOf(beginMarker, scanPos);
    if (bIdx < 0) break;
    const afterBegin = bIdx + beginMarker.length;
    if (afterBegin < upperUnfolded.length) {
      const nextCh = upperUnfolded.charCodeAt(afterBegin);
      if (nextCh !== 10 && nextCh !== 13 && nextCh !== 32 && nextCh !== 9) {
        scanPos = afterBegin;
        continue;
      }
    }
    const eIdx = upperUnfolded.indexOf(endMarker, afterBegin);
    if (eIdx < 0) break;
    const eventBody = unfolded.slice(afterBegin, eIdx);
    scanPos = eIdx + endMarker.length;

    let summary = '';
    let dtStart = '';
    let dtEnd = '';
    let location = '';
    let url = '';
    let desc = '';
    for (const line of eventBody.split(/\r?\n/)) {
      const colon = line.indexOf(':');
      if (colon <= 0) continue;
      const k = line.slice(0, colon).split(';')[0]!.trim().toUpperCase();
      const rawVal = line.slice(colon + 1).trim();
      if (!rawVal) continue;
      if (k === 'SUMMARY') summary = unescapeIcsVal(rawVal);
      else if (k === 'DTSTART') dtStart = formatIcsDate(rawVal);
      else if (k === 'DTEND') dtEnd = formatIcsDate(rawVal);
      else if (k === 'LOCATION') location = unescapeIcsVal(rawVal);
      else if (k === 'URL') url = rawVal;
      else if (k === 'DESCRIPTION') desc = unescapeIcsVal(rawVal);
    }
    const evTitle = summary || `Event ${eventSections.length + 1}`;
    const bullets: string[] = [];
    if (dtStart) bullets.push(`- **When**: ${dtEnd && dtEnd !== dtStart ? `${dtStart} → ${dtEnd}` : dtStart}`);
    if (location) bullets.push(`- **Location**: ${location}`);
    if (url && /^https?:\/\//i.test(url)) bullets.push(`- **URL**: ${url}`);
    if (desc) bullets.push(`- **Details**: ${desc.slice(0, 600)}`);
    eventSections.push([`## ${evTitle}`, ...bullets].join('\n'));
  }

  if (!calName && eventSections.length === 0) return null;
  const title = calName || 'Calendar Events';
  const blocks = [`# ${title}`];
  if (calDesc && calDesc !== title) blocks.push(calDesc);
  if (eventSections.length > 0) blocks.push(eventSections.join('\n\n'));
  return {
    title,
    ...(calDesc ? { description: calDesc } : {}),
    markdown: blocks.join('\n\n'),
  };
}

/** Formats `git format-patch` and unified `.patch`/`.diff` payloads into clean Markdown with a 4-tilde `diff` fence. */
export function formatGitPatchToMarkdown(
  rawBody: string,
  contentType?: unknown,
  urlStr?: string,
): { title?: string; description?: string; markdown: string } | null {
  const ctLower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  const isPatchCt = ctLower.includes('x-patch') || ctLower.includes('x-diff');
  const isPatchUrl = Boolean(urlStr && /\.(?:patch|diff)(?:$|[?#])/i.test(urlStr));
  const normalized = rawBody.replace(/\r\n/g, '\n');
  const head = normalized.slice(0, 2_048);
  const isFormatPatch = /^From [0-9a-f]{40} /m.test(head) && /^Subject:/m.test(head) && /\ndiff --git /m.test(normalized);
  const isUnifiedDiff = /^diff --git a\//m.test(head) || (/^---\s+\S+/m.test(head) && /^\+\+\+\s+\S+/m.test(head) && /^@@\s+-/m.test(head));
  if (!isPatchCt && !isPatchUrl && !isFormatPatch && !isUnifiedDiff) {
    return null;
  }
  const trimmed = normalized.trim();
  if (!trimmed || /^\s*<!doctype\s+html|^\s*<html/i.test(trimmed)) return null;

  let commitSha = /^From ([0-9a-f]{40})\b/m.exec(head)?.[1] ?? '';
  let author = '';
  let date = '';
  let subject = '';
  let commitBody = '';
  let diffBody = trimmed;

  const diffIdx = normalized.search(/^diff --git /m);
  if (isFormatPatch && diffIdx > 0) {
    const preamble = normalized.slice(0, diffIdx);
    const blankIdx = preamble.indexOf('\n\n');
    const rawHeaders = (blankIdx > 0 ? preamble.slice(0, blankIdx) : preamble).replace(/\n[ \t]+/g, ' ');
    for (const hLine of rawHeaders.split('\n')) {
      if (/^From:\s+/i.test(hLine)) author = hLine.replace(/^From:\s+/i, '').trim();
      else if (/^Date:\s+/i.test(hLine)) date = hLine.replace(/^Date:\s+/i, '').trim();
      else if (/^Subject:\s+/i.test(hLine)) {
        subject = hLine
          .replace(/^Subject:\s+/i, '')
          .replace(/^(?:\[PATCH[^\]]*\]\s*)+/i, '')
          .trim();
      }
    }
    if (blankIdx > 0) {
      commitBody = preamble
        .slice(blankIdx + 2)
        .replace(/(?:^|\n)---\n[\s\S]*$/, '')
        .trim();
    }
    diffBody = normalized.slice(diffIdx).trimEnd();
  }

  let fallbackTitle = 'Git Patch';
  if (urlStr) {
    try {
      const u = new URL(urlStr);
      const parts = u.pathname.split('/').filter(Boolean);
      if (u.hostname.toLowerCase() === 'github.com' && parts.length >= 4 && parts[2] === 'commit') {
        const cleanSha = parts[3]!.replace(/\.(?:patch|diff)$/i, '');
        if (!commitSha && /^[0-9a-f]{7,40}$/i.test(cleanSha)) commitSha = cleanSha;
        fallbackTitle = `${parts[0]}/${parts[1]}@${cleanSha.slice(0, 10)}`;
      } else {
        const last = parts[parts.length - 1];
        if (last) fallbackTitle = safeDecodeURIComponent(last);
      }
    } catch {
      // ignore
    }
  }

  const title = subject || fallbackTitle;
  const metaBullets: string[] = [];
  if (commitSha) metaBullets.push(`- **Commit**: \`${commitSha.slice(0, 12)}\``);
  if (author) metaBullets.push(`- **Author**: ${author}`);
  if (date) metaBullets.push(`- **Date**: ${date}`);

  const sections = [`# ${title}`];
  if (metaBullets.length > 0) sections.push(metaBullets.join('\n'));
  if (commitBody) sections.push(commitBody);
  sections.push(makeSafeCodeFence(diffBody, 'diff', true));

  return {
    title,
    ...(commitBody ? { description: commitBody.split('\n')[0]!.trim().slice(0, 280) } : {}),
    markdown: sections.join('\n\n'),
  };
}

const RAW_SOURCE_EXT_LANG_MAP: Record<string, string> = {
  toml: 'toml',
  yaml: 'yaml',
  yml: 'yaml',
  rs: 'rust',
  go: 'go',
  py: 'python',
  ts: 'ts',
  tsx: 'tsx',
  js: 'js',
  jsx: 'jsx',
  mjs: 'js',
  cjs: 'js',
  rb: 'ruby',
  java: 'java',
  kt: 'kotlin',
  swift: 'swift',
  c: 'c',
  h: 'c',
  cpp: 'cpp',
  hpp: 'cpp',
  cs: 'csharp',
  php: 'php',
  sh: 'bash',
  bash: 'bash',
  zsh: 'zsh',
  ps1: 'powershell',
  sql: 'sql',
  proto: 'protobuf',
  graphql: 'graphql',
  gql: 'graphql',
  lua: 'lua',
  zig: 'zig',
  tf: 'hcl',
  hcl: 'hcl',
  nix: 'nix',
  prisma: 'prisma',
  css: 'css',
  scss: 'scss',
};

/**
 * Wraps raw source-code and config files (`Cargo.toml`, `.yaml`, `.rs`, `.py`, `.ts`, `Dockerfile`, `Makefile`, etc.)
 * served as `text/plain` into fenced Markdown code blocks with accurate filename/package titles so `#` code comments are
 * never misparsed as H1 document titles.
 */
export function formatSourceCodeUrlToMarkdown(
  rawBody: string,
  contentType?: unknown,
  urlStr?: string,
): { title: string; description?: string; markdown: string } | null {
  if (!urlStr) return null;
  const ctLower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  if (ctLower.includes('html') || ctLower.includes('markdown') || ctLower.includes('json') || ctLower.includes('csv')) {
    return null;
  }
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length === 0) return null;
  const baseName = safeDecodeURIComponent(parts[parts.length - 1]!);
  const lowerBase = baseName.toLowerCase();
  let lang = '';
  if (lowerBase === 'dockerfile' || lowerBase.startsWith('dockerfile.')) lang = 'dockerfile';
  else if (lowerBase === 'makefile' || lowerBase === 'gnumakefile') lang = 'makefile';
  else if (lowerBase === 'cmakelists.txt') lang = 'cmake';
  else if (lowerBase === 'go.mod' || lowerBase === 'go.sum') lang = 'go';
  else {
    const ext = /\.([a-z0-9]+)$/i.exec(lowerBase)?.[1] ?? '';
    lang = RAW_SOURCE_EXT_LANG_MAP[ext] ?? '';
  }
  if (!lang) return null;

  const trimmed = rawBody.replace(/\r\n/g, '\n').trimEnd();
  if (!trimmed.trim() || /^\s*<!doctype\s+html|^\s*<html/i.test(trimmed)) return null;

  let title = baseName;
  if (u.hostname.toLowerCase() === 'raw.githubusercontent.com' && parts.length >= 4) {
    const owner = parts[0]!;
    const repo = parts[1]!;
    const rest = parts.slice(2);
    const filePath =
      rest[0] === 'refs' && (rest[1] === 'heads' || rest[1] === 'tags') && rest.length >= 4
        ? rest.slice(3).join('/')
        : rest.slice(1).join('/');
    if (filePath) title = `${owner}/${repo}/${filePath}`;
  } else if (parts.length >= 2) {
    title = `${safeDecodeURIComponent(parts[parts.length - 2]!)}/${baseName}`;
  }

  let description: string | undefined;
  if (lowerBase === 'cargo.toml' || lowerBase === 'pyproject.toml') {
    const pkgName = /^\s*name\s*=\s*["']([^"'\r\n]+)["']/m.exec(trimmed)?.[1];
    const pkgVer = /^\s*version\s*=\s*["']([^"'\r\n]+)["']/m.exec(trimmed)?.[1];
    const multiDesc =
      /^\s*description\s*=\s*(?:"""([\s\S]*?)"""|'''([\s\S]*?)'''|["']([^"'\r\n]+)["'])/m.exec(trimmed);
    const rawPkgDesc = (multiDesc?.[1] ?? multiDesc?.[2] ?? multiDesc?.[3] ?? '').replace(/\s+/g, ' ').trim();
    const pkgDesc = rawPkgDesc ? rawPkgDesc.slice(0, 220) : undefined;
    const summaryParts = [pkgName && pkgVer ? `${pkgName}@${pkgVer}` : pkgName, pkgDesc].filter(Boolean);
    if (summaryParts.length > 0) description = summaryParts.join(' — ');
  }

  return {
    title,
    ...(description ? { description } : {}),
    markdown: `# ${title}\n\n${makeSafeCodeFence(trimmed, lang)}`,
  };
}

function unwrapXmlText(raw: string | undefined): string {
  if (!raw) return '';
  if (!raw.includes('<![CDATA[')) {
    return decodeHtmlEntities(raw).trim();
  }
  let out = '';
  let pos = 0;
  while (pos < raw.length) {
    const start = raw.indexOf('<![CDATA[', pos);
    if (start < 0) {
      out += decodeHtmlEntities(raw.slice(pos));
      break;
    }
    if (start > pos) {
      out += decodeHtmlEntities(raw.slice(pos, start));
    }
    const end = raw.indexOf(']]>', start + 9);
    if (end < 0) {
      out += raw.slice(start + 9);
      break;
    }
    out += raw.slice(start + 9, end);
    pos = end + 3;
  }
  return out.trim();
}

function matchFirstXmlTag(block: string, tagNames: string[]): string {
  const lowerBlock = block.toLowerCase();
  for (const tag of tagNames) {
    const tagLower = tag.toLowerCase();
    const openNeedle = `<${tagLower}`;
    const closeNeedle = `</${tagLower}`;
    let pos = 0;
    while (pos < lowerBlock.length) {
      const openIdx = lowerBlock.indexOf(openNeedle, pos);
      if (openIdx < 0) break;
      const afterName = openIdx + openNeedle.length;
      if (afterName < lowerBlock.length && !isTagNameBoundary(lowerBlock.charCodeAt(afterName))) {
        pos = afterName;
        continue;
      }
      const openGt = lowerBlock.indexOf('>', afterName);
      if (openGt < 0) break;
      if (lowerBlock.charCodeAt(openGt - 1) === 47) {
        pos = openGt + 1;
        continue;
      }
      const closeIdx = lowerBlock.indexOf(closeNeedle, openGt + 1);
      if (closeIdx < 0) break;
      const afterCloseName = closeIdx + closeNeedle.length;
      if (afterCloseName < lowerBlock.length && !isTagNameBoundary(lowerBlock.charCodeAt(afterCloseName))) {
        pos = afterCloseName;
        continue;
      }
      const inner = block.slice(openGt + 1, closeIdx);
      if (inner.trim()) return unwrapXmlText(inner);
      pos = afterCloseName;
    }
  }
  return '';
}

/** Formats RSS 2.0, RDF, and Atom XML feeds into structured Markdown with per-item headings, links, dates, and summaries. */
export function formatFeedXmlToMarkdown(
  rawXml: string,
  baseUrl?: string,
): { title?: string; description?: string; markdown: string; links: string[] } | null {
  if (!rawXml) return null;
  const boundedXml = rawXml.length > MAX_HTML_SCAN_CHARS ? rawXml.slice(0, MAX_HTML_SCAN_CHARS) : rawXml;
  const headLower = boundedXml.slice(0, 1_200).toLowerCase();
  const hasRssRoot = headLower.includes('<rss') || headLower.includes('<rdf:rdf');
  const hasAtomRoot = headLower.includes('<feed');
  if (!hasRssRoot && !hasAtomRoot) return null;

  const lowerXml = boundedXml.toLowerCase();
  const isRss = hasRssRoot && lowerXml.includes('<item');
  const isAtom = !isRss && hasAtomRoot && lowerXml.includes('<entry');
  if (!isRss && !isAtom) return null;

  const openNeedle = isAtom ? '<entry' : '<item';
  const closeNeedle = isAtom ? '</entry>' : '</item>';
  const firstItemIdx = lowerXml.indexOf(openNeedle);
  const channelHeader = firstItemIdx > 0 ? boundedXml.slice(0, Math.min(firstItemIdx, 32_768)) : boundedXml.slice(0, 1_200);
  const feedTitle = cleanInlineHtml(matchFirstXmlTag(channelHeader, ['title']));
  const feedDesc = cleanInlineHtml(matchFirstXmlTag(channelHeader, ['description', 'subtitle']));

  const lines: string[] = [];
  if (feedTitle) lines.push(`# ${feedTitle}`);
  if (feedDesc && feedDesc !== feedTitle) lines.push(feedDesc);

  const links: string[] = [];
  const seenLinks = new Set<string>();
  let count = 0;
  let searchPos = firstItemIdx >= 0 ? firstItemIdx : boundedXml.length;
  while (searchPos < lowerXml.length && count < 40) {
    const openIdx = lowerXml.indexOf(openNeedle, searchPos);
    if (openIdx < 0) break;
    const afterName = openIdx + openNeedle.length;
    if (afterName < lowerXml.length && !isTagNameBoundary(lowerXml.charCodeAt(afterName))) {
      searchPos = afterName;
      continue;
    }
    const openGt = lowerXml.indexOf('>', afterName);
    if (openGt < 0) break;
    if (lowerXml.charCodeAt(openGt - 1) === 47) {
      searchPos = openGt + 1;
      continue;
    }
    const closeIdx = lowerXml.indexOf(closeNeedle, openGt + 1);
    if (closeIdx < 0) break;
    const block = boundedXml.slice(openGt + 1, closeIdx);
    searchPos = closeIdx + closeNeedle.length;

    const itemTitle = cleanInlineHtml(matchFirstXmlTag(block, ['title'])) || `Entry ${count + 1}`;
    let rawLink = '';
    if (isAtom) {
      let altHref = '';
      let anyHref = '';
      scanHtmlTagsLinear(
        block,
        (tag) => {
          if (tag.isClosing || tag.tagNameLower !== 'link') return undefined;
          const attrs = parseTagAttrs(tag.attrs);
          const hrefVal = (attrs.href ?? '').trim();
          if (!hrefVal) return undefined;
          if (!anyHref) anyHref = hrefVal;
          const relVal = (attrs.rel ?? '').trim().toLowerCase();
          if (!relVal || relVal === 'alternate') {
            altHref = hrefVal;
            return false;
          }
          return undefined;
        },
        Math.min(block.length, 65_536),
        false,
      );
      rawLink = decodeHtmlEntities(altHref || anyHref).trim();
    } else {
      rawLink = matchFirstXmlTag(block, ['link']);
      if (!rawLink) {
        const guid = matchFirstXmlTag(block, ['guid']);
        if (/^https?:\/\//i.test(guid)) rawLink = guid;
      }
    }
    const resolvedLink = resolveHttpsHref(rawLink, baseUrl);
    if (resolvedLink && !seenLinks.has(resolvedLink)) {
      seenLinks.add(resolvedLink);
      links.push(resolvedLink);
    }

    const pubDate = cleanInlineHtml(matchFirstXmlTag(block, ['pubDate', 'published', 'updated', 'dc:date']));
    const rawContent = matchFirstXmlTag(block, ['content:encoded', 'content', 'description', 'summary']);
    let bodyMd = '';
    if (rawContent) {
      if (/<(?:p|div|h[1-6]|ul|ol|li|a|pre|blockquote|br|table)\b/i.test(rawContent)) {
        bodyMd = extractHtmlDocument(rawContent, {
          baseUrl: resolvedLink ?? baseUrl,
          onlyMainContent: false,
          includeImages: false,
        }).markdown;
      } else {
        bodyMd = cleanInlineHtml(rawContent);
      }
      if (bodyMd.length > 1_800) {
        const cut = bodyMd.lastIndexOf(' ', 1_800);
        bodyMd = `${bodyMd.slice(0, cut > 900 ? cut : 1_800).trimEnd()}...`;
      }
    }

    const heading = resolvedLink ? `## [${itemTitle}](${resolvedLink})` : `## ${itemTitle}`;
    const parts = [heading];
    if (pubDate) parts.push(`*${pubDate}*`);
    if (bodyMd) parts.push(bodyMd);
    lines.push(parts.join('\n\n'));
    count++;
  }

  if (count === 0) return null;
  return {
    ...(feedTitle ? { title: feedTitle } : {}),
    ...(feedDesc ? { description: feedDesc } : {}),
    markdown: lines.join('\n\n'),
    links,
  };
}

const SKIP_SPECULATIVE_LLMS_HOSTS = new Set([
  'news.ycombinator.com',
  'npmjs.com',
  'www.npmjs.com',
  'registry.npmjs.org',
  'crates.io',
  'www.crates.io',
  'rubygems.org',
  'www.rubygems.org',
  'packagist.org',
  'www.packagist.org',
  'hex.pm',
  'www.hex.pm',
  'pypi.org',
  'www.pypi.org',
  'huggingface.co',
  'www.huggingface.co',
  'arxiv.org',
  'export.arxiv.org',
  'github.com',
  'gist.github.com',
  'raw.githubusercontent.com',
  'gitlab.com',
  'codeberg.org',
  'gitea.com',
  'lobste.rs',
  'bsky.app',
  'public.api.bsky.app',
  'stackoverflow.com',
  'www.stackoverflow.com',
  'serverfault.com',
  'superuser.com',
  'askubuntu.com',
  'datatracker.ietf.org',
  'rfc-editor.org',
  'www.rfc-editor.org',
  'pubmed.ncbi.nlm.nih.gov',
  'pmc.ncbi.nlm.nih.gov',
  'dev.to',
  'www.dev.to',
  'youtube.com',
  'www.youtube.com',
  'm.youtube.com',
  'youtu.be',
]);

const ORIGIN_LLMS_ABSENT_TTL_MS = 30 * 60_000;
const MAX_ORIGIN_LLMS_CACHE_ENTRIES = 512;
const originLlmsAbsentCache = new Map<string, number>();

export function resetOriginLlmsCacheForTests(): void {
  originLlmsAbsentCache.clear();
}

function recordOriginLlmsAbsent(origin: string, now = Date.now()): void {
  if (!origin) return;
  if (originLlmsAbsentCache.size >= MAX_ORIGIN_LLMS_CACHE_ENTRIES && !originLlmsAbsentCache.has(origin)) {
    const oldest = originLlmsAbsentCache.keys().next().value;
    if (oldest !== undefined) originLlmsAbsentCache.delete(oldest);
  }
  originLlmsAbsentCache.set(origin.toLowerCase(), now + ORIGIN_LLMS_ABSENT_TTL_MS);
}

function isOriginLlmsKnownAbsent(origin: string, now = Date.now()): boolean {
  const key = origin.toLowerCase();
  const exp = originLlmsAbsentCache.get(key);
  if (exp === undefined) return false;
  if (now >= exp) {
    originLlmsAbsentCache.delete(key);
    return false;
  }
  return true;
}

function shouldAutoProbeOriginLlms(u: URL, now = Date.now()): boolean {
  const host = u.hostname.toLowerCase();
  if (
    SKIP_SPECULATIVE_LLMS_HOSTS.has(host) ||
    host.endsWith('.wikipedia.org') ||
    host.endsWith('.wikimedia.org') ||
    host.endsWith('.reddit.com') ||
    host === 'reddit.com'
  ) {
    return false;
  }
  if (isOriginLlmsKnownAbsent(u.origin, now)) {
    return false;
  }
  const path = u.pathname.toLowerCase();
  if (
    /\.(?:json|ipynb|xml|rss|atom|pdf|vcf|vcard|ics|csv|tsv|patch|diff|toml|yaml|yml|py|rs|go|ts|tsx|js|jsx|sh|sql|txt|md)(?:$|\.)/.test(
      path,
    ) ||
    /\/(?:rss|feed|atom)\/?$/.test(path)
  ) {
    return false;
  }
  return true;
}

const MAX_MARKDOWN_CSV_ROWS = 1_000;

/**
 * Formats RFC 4180 CSV and TSV payloads (`text/csv`, `text/tab-separated-values`, `*.csv`, `*.tsv`) into a clean
 * GFM Markdown table with column summary and total row count.
 */
export function formatDelimitedTableToMarkdown(
  rawBody: string,
  contentType?: unknown,
  urlStr?: string,
): {
  title?: string;
  description?: string;
  markdown: string;
  rowCount: number;
  columnCount: number;
} | null {
  const ctLower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  const isTsvCt = ctLower.includes('tab-separated-values') || ctLower.includes('text/tsv');
  const isCsvCt = ctLower.includes('text/csv') || ctLower.includes('application/csv');
  const isTsvUrl = Boolean(urlStr && /\.tsv(?:$|[?#])/i.test(urlStr));
  const isCsvUrl = Boolean(urlStr && /\.csv(?:$|[?#])/i.test(urlStr));
  if (!isCsvCt && !isTsvCt && !isCsvUrl && !isTsvUrl) {
    return null;
  }

  const trimmed = rawBody.replace(/^\ufeff/, '').trim();
  if (!trimmed || trimmed.startsWith('<') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return null;
  }

  const delimiter = isTsvCt || isTsvUrl ? '\t' : ',';
  const rows: string[][] = [];
  let totalNonEmptyRows = 0;
  let curRow: string[] = [];
  let curField = '';
  let inQuotes = false;
  const len = trimmed.length;

  const commitRow = () => {
    curRow.push(curField);
    curField = '';
    if (curRow.some((cell) => cell.trim().length > 0)) {
      totalNonEmptyRows++;
      if (rows.length <= MAX_MARKDOWN_CSV_ROWS) {
        rows.push(curRow);
      }
    }
    curRow = [];
  };

  for (let i = 0; i < len; i++) {
    const ch = trimmed[i]!;
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < len && trimmed[i + 1] === '"') {
          curField += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        curField += ch;
      }
    } else if (ch === '"' && curField.length === 0) {
      inQuotes = true;
    } else if (ch === delimiter) {
      if (rows.length <= MAX_MARKDOWN_CSV_ROWS) {
        curRow.push(curField);
      }
      curField = '';
    } else if (ch === '\r') {
      if (i + 1 < len && trimmed[i + 1] === '\n') i++;
      commitRow();
    } else if (ch === '\n') {
      commitRow();
    } else if (rows.length <= MAX_MARKDOWN_CSV_ROWS || curField.length === 0) {
      curField += ch;
    }
  }
  if (curField.length > 0 || curRow.length > 0) {
    commitRow();
  }

  if (rows.length < 2) return null;
  const headerRow = rows[0]!.map((c) => c.replace(/\s+/g, ' ').trim());
  const colCount = Math.min(64, Math.max(...rows.map((r) => r.length)));
  if (colCount < 2) return null;

  const dataRowCount = Math.max(0, totalNonEmptyRows - 1);
  let fileLabel = '';
  if (urlStr) {
    try {
      const seg = safeDecodeURIComponent(new URL(urlStr).pathname.split('/').filter(Boolean).pop() ?? '');
      if (seg) fileLabel = seg;
    } catch {
      // ignore
    }
  }
  const title = fileLabel || (delimiter === '\t' ? 'Tabular Dataset (TSV)' : 'Tabular Dataset (CSV)');
  const formatCell = (raw: string | undefined): string =>
    (raw ?? '')
      .replace(/\r?\n/g, ' ')
      .replace(/[ \t]{2,}/g, ' ')
      .trim()
      .replace(/\|/g, '\\|');

  const padRow = (r: string[]) => Array.from({ length: colCount }, (_, idx) => formatCell(r[idx]));
  const headerCells = padRow(headerRow).map((h, idx) => h || `col_${idx + 1}`);
  const colPreview = headerCells
    .slice(0, 8)
    .map((c) => `\`${c}\``)
    .join(', ');
  const summaryLine = `${dataRowCount.toLocaleString('en-US')} rows × ${colCount} columns (${colPreview}${colCount > 8 ? ', …' : ''})`;

  const renderedDataRows = rows.slice(1, MAX_MARKDOWN_CSV_ROWS + 1);
  const tableLines = [
    `| ${headerCells.join(' | ')} |`,
    `| ${Array.from({ length: colCount }, () => '---').join(' | ')} |`,
    ...renderedDataRows.map((r) => `| ${padRow(r).join(' | ')} |`),
  ];

  const blocks = [`# ${title}`, summaryLine, tableLines.join('\n')];
  if (dataRowCount > renderedDataRows.length) {
    blocks.push(
      `_Showing first ${renderedDataRows.length.toLocaleString('en-US')} of ${dataRowCount.toLocaleString('en-US')} rows (full raw ${delimiter === '\t' ? 'TSV' : 'CSV'} available via \`artifactId\`)._`,
    );
  }

  return {
    title,
    description: summaryLine,
    markdown: blocks.join('\n\n'),
    rowCount: dataRowCount,
    columnCount: colCount,
  };
}

export function detectUnsupportedBinaryPayload(params: {
  rawBody: string;
  contentType?: unknown;
  url?: string;
  bodyEncoding?: unknown;
  isPdf?: boolean;
}): string | null {
  if (params.isPdf) return null;
  const ct = typeof params.contentType === 'string' ? params.contentType.split(';')[0]!.trim().toLowerCase() : '';
  if (
    ct &&
    (/^(?:image|audio|video|font)\//.test(ct) && ct !== 'image/svg+xml' ||
      /^application\/(?:x-)?(?:gzip|tar|gtar|zip|bzip2|xz|zstd|7z-compressed|rar|rar-compressed|octet-stream|wasm|java-archive|x-msdownload|x-executable|x-apple-diskimage|msword|vnd\.ms-|vnd\.openxmlformats)/i.test(
        ct,
      ))
  ) {
    return `Unsupported binary content-type "${ct}" for Markdown extraction`;
  }
  if (params.bodyEncoding === 'base64') {
    return `Unsupported binary payload${ct ? ` (${ct})` : ''} for Markdown extraction`;
  }
  const sample = params.rawBody.slice(0, 2_048);
  if (sample.length > 0) {
    if (
      sample.startsWith('\x1f\x8b') ||
      sample.startsWith('\x1f\ufffd\x08') ||
      sample.startsWith('PK\x03\x04') ||
      sample.startsWith('\x89PNG') ||
      sample.startsWith('\ufffdPNG') ||
      sample.startsWith('\x00asm') ||
      sample.startsWith('GIF87a') ||
      sample.startsWith('GIF89a')
    ) {
      return `Unsupported binary archive or media payload${ct ? ` (${ct})` : ''}`;
    }
    let nulCount = 0;
    let badCtrlCount = 0;
    for (let i = 0; i < sample.length; i++) {
      const code = sample.charCodeAt(i);
      if (code === 0) {
        nulCount++;
        badCtrlCount++;
      } else if ((code > 0 && code < 9) || (code > 13 && code < 32 && code !== 27) || code === 0xfffd) {
        badCtrlCount++;
      }
    }
    if (nulCount >= 2 || (sample.length >= 16 && badCtrlCount / sample.length > 0.1)) {
      return `Unsupported binary payload${ct ? ` (${ct})` : ''} for Markdown extraction`;
    }
  }
  if (params.url && !sample.trim()) {
    try {
      const p = new URL(params.url).pathname.toLowerCase();
      if (
        !/\.xml\.gz$/.test(p) &&
        /\.(?:tar\.gz|tgz|gz|zip|7z|rar|bz2|xz|zst|wasm|exe|dll|dmg|iso|bin|whl|jar|png|jpe?g|gif|webp|avif|mp3|mp4|wav|ogg|webm|mov|woff2?|ttf|otf)$/.test(
          p,
        )
      ) {
        return `Unsupported binary URL extension for Markdown extraction`;
      }
    } catch {
      // ignore
    }
  }
  return null;
}

export function deriveQuickMarkdownFromRawBytes(bytes: Uint8Array, baseUrl?: string): string | null {
  if (bytes.byteLength === 0 || hasPdfMagicHeader(bytes)) return null;
  let rawText: string;
  try {
    rawText = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  if (detectUnsupportedBinaryPayload({ rawBody: rawText, url: baseUrl })) return null;
  if (/^\s*<!doctype\s+html|^\s*<html|<(?:head|body|main|article)\b/i.test(rawText)) {
    return extractHtmlDocument(rawText, { baseUrl, onlyMainContent: true }).markdown;
  }
  if (/^BEGIN:VCARD\b/im.test(rawText.trim())) {
    return formatVcardToMarkdown(rawText).markdown;
  }
  const icsDoc = formatIcalendarToMarkdown(rawText);
  if (icsDoc) return icsDoc.markdown;
  const feedDoc = formatFeedXmlToMarkdown(rawText, baseUrl);
  if (feedDoc) return feedDoc.markdown;
  const trimmed = rawText.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const jsonDoc = tryParseJsonPayloadForScrape(rawText, 'application/json', baseUrl ?? '');
    if (jsonDoc) return jsonDoc.markdown;
  }
  const csvDoc = formatDelimitedTableToMarkdown(rawText, undefined, baseUrl);
  if (csvDoc) return csvDoc.markdown;
  const patchDoc = formatGitPatchToMarkdown(rawText, undefined, baseUrl);
  if (patchDoc) return patchDoc.markdown;
  const srcDoc = formatSourceCodeUrlToMarkdown(rawText, undefined, baseUrl);
  if (srcDoc) return srcDoc.markdown;
  const fm = parseMarkdownFrontmatter(trimmed.length > MAX_HTML_SCAN_CHARS ? trimmed.slice(0, MAX_HTML_SCAN_CHARS) : trimmed);
  return sanitizeInlineHtmlInMarkdown(fm.body, baseUrl).trim();
}

function joinIpynbLines(val: unknown): string {
  if (typeof val === 'string') return val;
  if (Array.isArray(val)) return val.map((x) => (typeof x === 'string' ? x : '')).join('');
  return '';
}

/**
 * Microsoft `markitdown`-inspired Jupyter Notebook (`.ipynb`) converter:
 * Renders Markdown cells natively, wraps code cells in kernel-language fences, includes concise text/markdown/error
 * cell outputs, and strips bloated base64 `image/png` / `application/vnd.plotly` payloads.
 */
export function formatJupyterNotebookToMarkdown(
  parsed: unknown,
  fallbackTitle?: string,
): { title?: string; description?: string; markdown: string } | null {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const nb = parsed as Record<string, unknown>;
  const cellsRaw = Array.isArray(nb.cells)
    ? (nb.cells as Array<Record<string, unknown>>)
    : Array.isArray((nb.worksheets as Array<Record<string, unknown>> | undefined)?.[0]?.cells)
      ? ((nb.worksheets as Array<Record<string, unknown>>)[0]!.cells as Array<Record<string, unknown>>)
      : null;
  if (!cellsRaw || (typeof nb.nbformat !== 'number' && !Array.isArray(nb.cells))) {
    return null;
  }

  const meta = nb.metadata && typeof nb.metadata === 'object' ? (nb.metadata as Record<string, unknown>) : {};
  const kernelspec = meta.kernelspec && typeof meta.kernelspec === 'object' ? (meta.kernelspec as Record<string, unknown>) : {};
  const langInfo = meta.language_info && typeof meta.language_info === 'object' ? (meta.language_info as Record<string, unknown>) : {};
  const rawLang =
    (typeof kernelspec.language === 'string' && kernelspec.language) ||
    (typeof langInfo.name === 'string' && langInfo.name) ||
    'python';
  const fenceLang = normalizeFenceLang(rawLang) || 'python';

  let title: string | undefined = typeof meta.title === 'string' && meta.title.trim() ? meta.title.trim() : undefined;
  let description: string | undefined;
  const blocks: string[] = [];

  for (const cell of cellsRaw) {
    if (!cell || typeof cell !== 'object') continue;
    const cellType = typeof cell.cell_type === 'string' ? cell.cell_type : '';
    const src = joinIpynbLines(cell.source).replace(/\r\n/g, '\n').trimEnd();
    if (!src.trim()) continue;

    if (cellType === 'markdown') {
      const trimmedMd = src.trim();
      blocks.push(trimmedMd);
      for (const line of trimmedMd.split('\n')) {
        const tl = line.trim();
        if (!tl) continue;
        if (!title && tl.startsWith('# ')) {
          title = tl.slice(2).trim();
        } else if (!description && !tl.startsWith('#') && !tl.startsWith('```') && tl.length >= 20) {
          description = stripMarkdownLinksToLabelsLinear(tl).slice(0, 280);
        }
      }
    } else if (cellType === 'code') {
      blocks.push(makeSafeCodeFence(src, fenceLang));
      const outputs = Array.isArray(cell.outputs) ? (cell.outputs as Array<Record<string, unknown>>) : [];
      const outSnippets: string[] = [];
      for (const out of outputs.slice(0, 6)) {
        if (!out || typeof out !== 'object') continue;
        const outType = typeof out.output_type === 'string' ? out.output_type : '';
        if (outType === 'stream') {
          const txt = joinIpynbLines(out.text).trim();
          if (txt) outSnippets.push(makeSafeCodeFence(txt.slice(0, 1_600), 'text'));
        } else if (outType === 'execute_result' || outType === 'display_data') {
          const data = out.data && typeof out.data === 'object' ? (out.data as Record<string, unknown>) : {};
          const mdOut = joinIpynbLines(data['text/markdown']).trim();
          const plainOut = joinIpynbLines(data['text/plain']).trim();
          if (mdOut) {
            outSnippets.push(mdOut.slice(0, 1_600));
          } else if (plainOut && !/^<Figure size .*>$/.test(plainOut)) {
            outSnippets.push(makeSafeCodeFence(plainOut.slice(0, 1_600), 'text'));
          }
        } else if (outType === 'error') {
          const ename = typeof out.ename === 'string' ? out.ename : 'Error';
          const evalue = typeof out.evalue === 'string' ? out.evalue : '';
          outSnippets.push(makeSafeCodeFence(`${ename}${evalue ? `: ${evalue}` : ''}`, 'text'));
        }
      }
      if (outSnippets.length > 0) {
        blocks.push(outSnippets.join('\n\n'));
      }
    } else if (cellType === 'raw') {
      blocks.push(makeSafeCodeFence(src));
    }
  }

  if (blocks.length === 0) return null;
  const finalTitle = title || fallbackTitle;
  const fullMd = finalTitle && !blocks[0]!.startsWith('# ') ? `# ${finalTitle}\n\n${blocks.join('\n\n')}` : blocks.join('\n\n');
  return {
    ...(finalTitle ? { title: finalTitle } : {}),
    ...(description ? { description } : {}),
    markdown: fullMd,
  };
}

/**
 * Formats OpenAPI 3.x (`openapi: "3..."`) and Swagger 2.0 (`swagger: "2..."`) JSON specifications into a compact,
 * LLM-navigable Markdown API reference (Endpoints index table, Servers, Auth schemes, per-operation parameters/responses, and Schemas).
 */
export function formatOpenApiSpecToMarkdown(
  parsed: unknown,
): { title?: string; description?: string; markdown: string } | null {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const spec = parsed as Record<string, unknown>;
  const oaVer = typeof spec.openapi === 'string' ? spec.openapi.trim() : '';
  const swVer = typeof spec.swagger === 'string' ? spec.swagger.trim() : '';
  if (!oaVer.startsWith('3.') && !swVer.startsWith('2.')) return null;
  const pathsObj = spec.paths && typeof spec.paths === 'object' && !Array.isArray(spec.paths) ? (spec.paths as Record<string, unknown>) : null;
  if (!pathsObj) return null;

  const info = spec.info && typeof spec.info === 'object' ? (spec.info as Record<string, unknown>) : {};
  const rawTitle = typeof info.title === 'string' && info.title.trim() ? info.title.trim() : 'API Specification';
  const apiVer = typeof info.version === 'string' && info.version.trim() ? info.version.trim() : '';
  const specBadge = oaVer ? `OpenAPI ${oaVer}` : `Swagger ${swVer}`;
  const rawDesc = typeof info.description === 'string' ? info.description.trim() : '';
  const cleanSummaryDesc = stripMarkdownLinksToLabelsLinear(rawDesc)
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 300);

  const sections: string[] = [`# ${rawTitle}${apiVer ? ` (v${apiVer} — ${specBadge})` : ` (${specBadge})`}`];
  if (rawDesc) sections.push(rawDesc);

  // Servers (`OpenAPI 3.x` `servers[]` or `Swagger 2.0` `host` + `basePath`)
  const servers = Array.isArray(spec.servers) ? (spec.servers as Array<Record<string, unknown>>) : [];
  if (servers.length > 0) {
    const srvLines = servers
      .map((s) => {
        const u = typeof s?.url === 'string' ? s.url.trim() : '';
        const d = typeof s?.description === 'string' ? s.description.trim() : '';
        return u ? `- \`${u}\`${d ? ` — ${d}` : ''}` : '';
      })
      .filter(Boolean);
    if (srvLines.length > 0) sections.push(`## Servers\n\n${srvLines.join('\n')}`);
  } else if (typeof spec.host === 'string' && spec.host.trim()) {
    const scheme = Array.isArray(spec.schemes) && typeof spec.schemes[0] === 'string' ? spec.schemes[0] : 'https';
    const bp = typeof spec.basePath === 'string' ? spec.basePath : '';
    sections.push(`## Servers\n\n- \`${scheme}://${spec.host.trim()}${bp}\``);
  }

  // Security Schemes
  const components = spec.components && typeof spec.components === 'object' ? (spec.components as Record<string, unknown>) : {};
  const secDefs =
    (components.securitySchemes && typeof components.securitySchemes === 'object' ? (components.securitySchemes as Record<string, unknown>) : undefined) ??
    (spec.securityDefinitions && typeof spec.securityDefinitions === 'object' ? (spec.securityDefinitions as Record<string, unknown>) : undefined);
  if (secDefs) {
    const secLines: string[] = [];
    for (const [secName, secVal] of Object.entries(secDefs).slice(0, 12)) {
      if (!secVal || typeof secVal !== 'object') continue;
      const sv = secVal as Record<string, unknown>;
      const t = typeof sv.type === 'string' ? sv.type : '';
      const sch = typeof sv.scheme === 'string' ? ` (${sv.scheme})` : typeof sv.in === 'string' ? ` (in ${sv.in}: ${sv.name ?? ''})` : '';
      secLines.push(`- **${secName}**: \`${t}\`${sch}`);
    }
    if (secLines.length > 0) sections.push(`## Authentication\n\n${secLines.join('\n')}`);
  }

  // Endpoints summary table + per-endpoint details
  const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'] as const;
  const tableRows: string[] = ['| Method | Path | Summary | Operation ID |', '| --- | --- | --- | --- |'];
  const opDetails: string[] = [];
  let opCount = 0;

  const formatSchemaRef = (sObj: unknown): string => {
    if (!sObj || typeof sObj !== 'object') return '';
    const so = sObj as Record<string, unknown>;
    if (typeof so.$ref === 'string') return so.$ref.split('/').pop() ?? so.$ref;
    if (so.type === 'array' && so.items) return `${formatSchemaRef(so.items) || 'any'}[]`;
    if (typeof so.type === 'string') return so.format && typeof so.format === 'string' ? `${so.type}(${so.format})` : so.type;
    return '';
  };

  for (const [routePath, pathItem] of Object.entries(pathsObj)) {
    if (!pathItem || typeof pathItem !== 'object' || Array.isArray(pathItem)) continue;
    const pi = pathItem as Record<string, unknown>;
    const sharedParams = Array.isArray(pi.parameters) ? (pi.parameters as Array<Record<string, unknown>>) : [];
    for (const m of httpMethods) {
      const op = pi[m];
      if (!op || typeof op !== 'object' || Array.isArray(op)) continue;
      const opRec = op as Record<string, unknown>;
      opCount++;
      const upperM = m.toUpperCase();
      const summary = (typeof opRec.summary === 'string' ? opRec.summary : typeof opRec.description === 'string' ? opRec.description.split('\n')[0]! : '')
        .replace(/\s+/g, ' ')
        .replace(/\|/g, '\\|')
        .trim()
        .slice(0, 120);
      const opId = typeof opRec.operationId === 'string' ? opRec.operationId.trim() : '';
      if (opCount <= 150) {
        tableRows.push(`| \`${upperM}\` | \`${routePath.replace(/\|/g, '\\|')}\` | ${summary} | ${opId ? `\`${opId}\`` : ''} |`);
      }
      if (opCount <= 60) {
        const lines: string[] = [`### \`${upperM} ${routePath}\`${summary ? ` — ${summary}` : ''}`];
        const allParams = [
          ...sharedParams,
          ...(Array.isArray(opRec.parameters) ? (opRec.parameters as Array<Record<string, unknown>>) : []),
        ];
        const paramBits: string[] = [];
        for (const p of allParams.slice(0, 12)) {
          if (!p || typeof p !== 'object' || typeof p.name !== 'string') continue;
          const loc = typeof p.in === 'string' ? p.in : 'query';
          const req = p.required === true ? ', required' : '';
          const pType = formatSchemaRef(p.schema) || (typeof p.type === 'string' ? p.type : '');
          paramBits.push(`\`${p.name}\` (${loc}${pType ? `: ${pType}` : ''}${req})`);
        }
        if (paramBits.length > 0) lines.push(`- **Parameters**: ${paramBits.join(', ')}`);

        if (opRec.requestBody && typeof opRec.requestBody === 'object') {
          const rb = opRec.requestBody as Record<string, unknown>;
          const rbContent = rb.content && typeof rb.content === 'object' ? (rb.content as Record<string, unknown>) : {};
          const jsonMedia = (rbContent['application/json'] ?? Object.values(rbContent)[0]) as Record<string, unknown> | undefined;
          const rbSchema = formatSchemaRef(jsonMedia?.schema);
          lines.push(`- **Request Body**${rb.required ? ' *(required)*' : ''}: ${rbSchema ? `\`${rbSchema}\`` : 'JSON'}`);
        }

        if (opRec.responses && typeof opRec.responses === 'object') {
          const respBits: string[] = [];
          for (const [code, rv] of Object.entries(opRec.responses as Record<string, unknown>).slice(0, 6)) {
            if (!rv || typeof rv !== 'object') continue;
            const rRec = rv as Record<string, unknown>;
            const rDesc = typeof rRec.description === 'string' ? rRec.description.replace(/\s+/g, ' ').trim().slice(0, 80) : '';
            const rContent = rRec.content && typeof rRec.content === 'object' ? (rRec.content as Record<string, unknown>) : {};
            const rJson = rContent['application/json'] as Record<string, unknown> | undefined;
            const rSchema = formatSchemaRef(rJson?.schema ?? rRec.schema);
            respBits.push(`\`${code}\`${rSchema ? ` → \`${rSchema}\`` : ''}${rDesc ? ` (${rDesc})` : ''}`);
          }
          if (respBits.length > 0) lines.push(`- **Responses**: ${respBits.join('; ')}`);
        }
        opDetails.push(lines.join('\n'));
      }
    }
  }

  if (tableRows.length > 2) {
    sections.push(`## Endpoints (${opCount})\n\n${tableRows.join('\n')}`);
  }
  if (opDetails.length > 0) {
    sections.push(`## Operations\n\n${opDetails.join('\n\n')}`);
  }

  const schemasObj =
    (components.schemas && typeof components.schemas === 'object' ? (components.schemas as Record<string, unknown>) : undefined) ??
    (spec.definitions && typeof spec.definitions === 'object' ? (spec.definitions as Record<string, unknown>) : undefined);
  if (schemasObj) {
    const schemaLines: string[] = [];
    for (const [sName, sVal] of Object.entries(schemasObj).slice(0, 30)) {
      if (!sVal || typeof sVal !== 'object') continue;
      const sv = sVal as Record<string, unknown>;
      const props = sv.properties && typeof sv.properties === 'object' ? Object.keys(sv.properties as Record<string, unknown>) : [];
      schemaLines.push(`- **\`${sName}\`**${props.length > 0 ? `: \`${props.slice(0, 10).join('`, `')}\`${props.length > 10 ? ', …' : ''}` : ''}`);
    }
    if (schemaLines.length > 0) sections.push(`## Schemas\n\n${schemaLines.join('\n')}`);
  }

  return {
    title: rawTitle,
    ...(cleanSummaryDesc ? { description: cleanSummaryDesc } : {}),
    markdown: sections.join('\n\n'),
  };
}

export function tryParseJsonPayloadForScrape(
  rawBody: string,
  contentType: unknown,
  finalUrl: string,
): {
  parsed: unknown;
  markdown: string;
  title?: string;
  description?: string;
} | null {
  const ctLower = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  const looksJsonCt = ctLower.includes('json');
  const looksJsonUrl = /\.(?:json|ipynb)(?:$|[?#])/i.test(finalUrl);
  const trimmed = rawBody.replace(/^\ufeff/, '').trim();
  if ((!looksJsonCt && !looksJsonUrl) || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) {
    return null;
  }
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    const ipynbDoc = formatJupyterNotebookToMarkdown(parsed);
    if (ipynbDoc) {
      return {
        parsed,
        markdown: ipynbDoc.markdown,
        ...(ipynbDoc.title ? { title: ipynbDoc.title } : {}),
        ...(ipynbDoc.description ? { description: ipynbDoc.description } : {}),
      };
    }
    const openApiDoc = formatOpenApiSpecToMarkdown(parsed);
    if (openApiDoc) {
      return {
        parsed,
        markdown: openApiDoc.markdown,
        ...(openApiDoc.title ? { title: openApiDoc.title } : {}),
        ...(openApiDoc.description ? { description: openApiDoc.description } : {}),
      };
    }
    const pretty = JSON.stringify(parsed, null, 2);
    let title: string | undefined;
    let description: string | undefined;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const obj = parsed as Record<string, unknown>;
      const nested =
        (obj.info && typeof obj.info === 'object' && !Array.isArray(obj.info) ? (obj.info as Record<string, unknown>) : undefined) ??
        (obj.data && typeof obj.data === 'object' && !Array.isArray(obj.data) ? (obj.data as Record<string, unknown>) : undefined);
      const nameStr =
        (typeof obj.name === 'string' && obj.name.trim() ? obj.name.trim() : '') ||
        (typeof nested?.name === 'string' && nested.name.trim() ? nested.name.trim() : '');
      const verStr =
        (typeof obj.version === 'string' && obj.version.trim() ? obj.version.trim() : '') ||
        (typeof nested?.version === 'string' && nested.version.trim() ? nested.version.trim() : '');
      const titleStr =
        (typeof obj.title === 'string' && obj.title.trim() ? obj.title.trim() : '') ||
        (typeof nested?.title === 'string' && nested.title.trim() ? nested.title.trim() : '');
      if (nameStr && verStr) title = `${nameStr}@${verStr}`;
      else if (titleStr) title = titleStr;
      else if (nameStr) title = nameStr;
      const descCandidate =
        (typeof obj.description === 'string' && obj.description.trim() ? obj.description.trim() : '') ||
        (typeof nested?.summary === 'string' && nested.summary.trim() ? nested.summary.trim() : '') ||
        (typeof nested?.description === 'string' && nested.description.trim() ? nested.description.trim() : '');
      if (descCandidate) {
        description = descCandidate.slice(0, 500);
      }
    }
    return {
      parsed,
      markdown: title ? `# ${title}\n\n\`\`\`json\n${pretty}\n\`\`\`` : `\`\`\`json\n${pretty}\n\`\`\``,
      ...(title ? { title } : {}),
      ...(description ? { description } : {}),
    };
  } catch {
    return null;
  }
}

function isLikelyPdfUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    if (/\.pdf$/i.test(u.pathname)) return true;
    return /^(?:export\.)?arxiv\.org$/i.test(u.hostname) && /^\/pdf\/[A-Za-z0-9._/-]+$/.test(u.pathname);
  } catch {
    return false;
  }
}

function buildRobotsAlternativeHint(urlStr: string): string | undefined {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    if (host === 'pypi.org') {
      const m = /^\/pypi\/([^/]+)(?:\/[^/]+)?\/json\/?$/i.exec(u.pathname);
      if (m?.[1]) {
        return `pypi.org disallows /pypi/*/json in robots.txt; scrape https://pypi.org/project/${m[1]}/ instead.`;
      }
    }
    if (host === 'github.com') {
      const m = /^\/([^/]+)\/([^/]+)\/tree\/([^/]+)(?:\/(.+))?$/i.exec(u.pathname);
      if (m?.[1] && m[2] && m[3]) {
        const sub = m[4] ? `${m[4].replace(/\/+$/, '')}/README.md` : 'README.md';
        return `github.com disallows /*/tree/ in robots.txt; use map on https://github.com/${m[1]}/${m[2]} or scrape https://github.com/${m[1]}/${m[2]}/blob/${m[3]}/${sub}.`;
      }
    }
  } catch {
    // ignore
  }
  return undefined;
}

function decodeJsonEscapedString(raw: string): string {
  try {
    return JSON.parse(`"${raw}"`) as string;
  } catch {
    return raw.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\u0026/g, '&');
  }
}

function formatDurationSeconds(totalSec: number): string {
  if (!Number.isFinite(totalSec) || totalSec <= 0) return '';
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = Math.floor(totalSec % 60);
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function extractYouTubeWatchMetadataFromHtml(
  rawHtml: string,
): { title: string; author?: string; description?: string; markdown: string } | null {
  const vdIdx = rawHtml.indexOf('"videoDetails":{');
  if (vdIdx < 0) return null;
  const slice = rawHtml.slice(vdIdx, Math.min(rawHtml.length, vdIdx + 24_000));
  const matchField = (key: string): string => {
    const re = new RegExp(`"${key}":"((?:\\\\.|[^"\\\\])*)"`);
    const m = re.exec(slice);
    return m?.[1] ? decodeJsonEscapedString(m[1]).trim() : '';
  };
  const title = matchField('title');
  if (!title) return null;
  const author = matchField('author');
  const lengthSeconds = Number(matchField('lengthSeconds'));
  const viewCountRaw = matchField('viewCount');
  const shortDescription = matchField('shortDescription');

  const metaBullets: string[] = [];
  if (author) metaBullets.push(`- **Channel**: ${author}`);
  const dur = formatDurationSeconds(lengthSeconds);
  if (dur) metaBullets.push(`- **Duration**: ${dur}`);
  if (viewCountRaw && /^\d+$/.test(viewCountRaw)) {
    metaBullets.push(`- **Views**: ${Number(viewCountRaw).toLocaleString('en-US')}`);
  }

  const parts = [`# ${title}`];
  if (metaBullets.length > 0) parts.push(metaBullets.join('\n'));
  if (shortDescription) parts.push(`## Description\n\n${shortDescription}`);
  return {
    title,
    ...(author ? { author } : {}),
    ...(shortDescription ? { description: shortDescription } : {}),
    markdown: parts.join('\n\n'),
  };
}

async function runPdfOcrFallback(params: {
  url: string;
  ocrParam: 'auto' | 'always';
  maxOcrPages: number;
  redactPii: boolean;
  headers?: unknown;
  target: 'auto' | 'agent' | 'container';
  site?: string;
  source: string;
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
}): Promise<
  | {
      ok: true;
      via: string;
      finalUrl: string;
      status: number;
      contentSha256?: string;
      artifactId?: string;
      markdown: string;
      pdfEngine: string;
      ocr?: PdfOcrContainerReply['ocr'];
    }
  | {
      ok: false;
      originFailure?: { status: number; via: string; body: Record<string, unknown>; retryAfter?: string };
      error: string;
    }
> {
  const { url, ocrParam, maxOcrPages, redactPii, headers, target, site, source, env, executeHubFetch } = params;
  const hasService = Boolean(env.PDF_OCR);
  const ocrUrlBase = env.PDF_OCR_URL?.trim().replace(/\/+$/, '') ?? '';
  const ocrToken = env.PDF_OCR_TOKEN?.trim() ?? '';
  if (!hasService && (!ocrUrlBase || !ocrToken)) {
    return { ok: false, error: 'pdf_ocr_unconfigured' };
  }

  const rawFetchCall = {
    maxSeconds: 110,
    options: {
      includeBody: true,
      respectRobots: true,
      maxBytes: 16 * 1024 * 1024,
      timeoutMs: 95_000,
    },
    requests: [
      {
        id: 'pdf-ocr-1',
        url,
        kind: 'binary',
        accept: 'application/pdf,*/*;q=0.8',
        ...(headers && typeof headers === 'object' ? { headers } : {}),
      },
    ],
  };

  const retention: ArtifactRetention | 'off' = env.ARTIFACTS ? 'transient' : 'off';
  const fetchRes = await executeHubFetch(
    target,
    JSON.stringify(rawFetchCall),
    site,
    `${source}:pdf-bytes`,
    retention,
    !env.ARTIFACTS,
  );
  if (fetchRes.status !== 200) {
    let errJson: Record<string, unknown> = { ok: false, error: 'scrape_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    return {
      ok: false,
      originFailure: {
        status: fetchRes.status,
        via: fetchRes.via,
        body: errJson,
        ...(fetchRes.retryAfter ? { retryAfter: fetchRes.retryAfter } : {}),
      },
      error: `hub_fetch_${fetchRes.status}`,
    };
  }

  const parsed = JSON.parse(fetchRes.bodyText) as { results?: Array<Record<string, unknown>> };
  const item = parsed.results?.[0] ?? {};
  if (item.outcome !== 'ok') {
    return {
      ok: false,
      originFailure: {
        status: item.status === 429 ? 429 : 422,
        via: fetchRes.via,
        body: {
          ok: false,
          url,
          outcome: item.outcome ?? 'error',
          status: item.status ?? 0,
          problem: item.problem ?? 'Origin PDF download did not return HTTP 2xx',
        },
      },
      error: String(item.problem ?? 'origin_not_ok'),
    };
  }

  let pdfBytes: Uint8Array | null = null;
  const art = item.artifact as { blobSha256?: string; contentSha256?: string; retention?: string } | undefined;
  if (art?.blobSha256 && env.ARTIFACTS) {
    const loaded = await readVerifiedArtifactFromR2({
      bucket: env.ARTIFACTS,
      blobSha256: art.blobSha256,
      preferredRetention: art.retention === 'stored' ? 'stored' : 'transient',
      expectedContentSha256: art.contentSha256,
    });
    if (loaded.ok) {
      pdfBytes = loaded.bytes;
    }
  }
  if (!pdfBytes && typeof item.bodyBase64 === 'string' && item.bodyBase64.length > 0) {
    pdfBytes = decodeBase64ToBytes(item.bodyBase64);
  }
  if (!pdfBytes && typeof item.body === 'string' && item.body.length > 0) {
    pdfBytes = item.bodyEncoding === 'base64' ? decodeBase64ToBytes(item.body) : new TextEncoder().encode(item.body);
  }
  if (!pdfBytes || pdfBytes.byteLength === 0 || !hasPdfMagicHeader(pdfBytes)) {
    return { ok: false, error: 'not_a_pdf_payload' };
  }

  const qs = new URLSearchParams({
    ocr: ocrParam,
    maxOcrPages: String(Math.min(500, Math.max(1, maxOcrPages))),
    maxSeconds: '300',
  });
  const bodyPayload = pdfBytes.slice().buffer as ArrayBuffer;

  let ocrRes: Response;
  try {
    if (env.PDF_OCR) {
      ocrRes = await env.PDF_OCR.fetch(`http://pdf-ocr/ocr?${qs}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/pdf',
          'content-length': String(pdfBytes.byteLength),
          'x-pdf-bytes': String(pdfBytes.byteLength),
        },
        body: bodyPayload,
        signal: AbortSignal.timeout(300_000),
      });
    } else {
      ocrRes = await fetch(`${ocrUrlBase}/ocr?${qs}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${ocrToken}`,
          'content-type': 'application/pdf',
          'content-length': String(pdfBytes.byteLength),
          'x-pdf-bytes': String(pdfBytes.byteLength),
        },
        body: bodyPayload,
        signal: AbortSignal.timeout(300_000),
      });
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }

  if (!ocrRes.ok) {
    const errText = await ocrRes.text().catch(() => '');
    return { ok: false, error: `pdf_ocr_http_${ocrRes.status}:${errText.slice(0, 200)}` };
  }

  const ocrJson = (await ocrRes.json().catch(() => ({}))) as PdfOcrContainerReply;
  const rawMd = typeof ocrJson.markdown === 'string' ? ocrJson.markdown : '';
  const finalMd = redactPii ? redactPiiText(rawMd) : rawMd;
  const pagesOcred = ocrJson.ocr?.pagesOcred ?? 0;

  return {
    ok: true,
    via: `${fetchRes.via}+pdf-ocr`,
    finalUrl: typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : url,
    status: typeof item.status === 'number' ? item.status : 200,
    contentSha256: ocrJson.sha256 ?? art?.contentSha256,
    artifactId: art?.blobSha256,
    markdown: finalMd,
    pdfEngine: pagesOcred > 0 ? 'pymupdf-tesseract-ocr' : 'pymupdf',
    ocr: ocrJson.ocr,
  };
}

export async function executeScrapeCall(params: {
  payload: ScrapeRequestPayload;
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
  tracer?: RequestTracer | TraceContext;
}): Promise<{ status: number; body: Record<string, unknown>; via: string; retryAfter?: string }> {
  const activeTracer = getActiveRequestTracer(params.tracer);
  const runScrape = async (): Promise<{ status: number; body: Record<string, unknown>; via: string; retryAfter?: string }> => {
  const { payload, env, executeHubFetch, source = 'scrape', selfHost, now = Date.now() } = params;
  const urlCheck = validatePublicHttpsTargetUrl(payload.url, selfHost);
  if (!urlCheck.ok) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: urlCheck.message } };
  }
  const parsedUrl = urlCheck.url;
  const normalizedUrl = urlCheck.normalized;

  const rawFormats = Array.isArray(payload.formats) && payload.formats.length > 0 ? payload.formats : ['markdown'];
  const stringFormats = new Set<string>();
  let jsonSchemaSpec: { prompt?: string; schema?: Record<string, unknown> } | undefined;
  let attributesSpec: Array<{ selector: string; attribute: string }> | undefined;
  let screenshotSpec: { fullPage?: boolean; quality?: number; viewport?: { width?: number; height?: number } } | undefined;
  let changeTrackingSpec: { modes?: string[]; tag?: string } | undefined;

  for (const f of rawFormats) {
    if (typeof f === 'string') {
      if (f === 'changeTracking') {
        stringFormats.add('changes');
        changeTrackingSpec = {};
      } else {
        stringFormats.add(f);
      }
    } else if (f && typeof f === 'object' && !Array.isArray(f)) {
      const fObj = f as Record<string, unknown>;
      if (fObj.type === 'json') {
        jsonSchemaSpec = {
          ...(typeof fObj.prompt === 'string' && fObj.prompt.trim() ? { prompt: fObj.prompt.trim() } : {}),
          ...(fObj.schema && typeof fObj.schema === 'object' ? { schema: fObj.schema as Record<string, unknown> } : {}),
        };
      } else if (fObj.type === 'attributes' && Array.isArray(fObj.selectors)) {
        attributesSpec = fObj.selectors
          .filter((s): s is { selector: string; attribute: string } => Boolean(s && typeof s === 'object'))
          .slice(0, 25);
      } else if (fObj.type === 'screenshot') {
        stringFormats.add('screenshot');
        screenshotSpec = {
          ...(typeof fObj.fullPage === 'boolean' ? { fullPage: fObj.fullPage } : {}),
          ...(typeof fObj.quality === 'number' && Number.isFinite(fObj.quality)
            ? { quality: Math.min(100, Math.max(1, Math.floor(fObj.quality))) }
            : {}),
          ...(fObj.viewport && typeof fObj.viewport === 'object'
            ? { viewport: fObj.viewport as { width?: number; height?: number } }
            : {}),
        };
      } else if (fObj.type === 'changeTracking') {
        stringFormats.add('changes');
        changeTrackingSpec = {
          ...(Array.isArray(fObj.modes) ? { modes: fObj.modes.map(String) } : {}),
          ...(typeof fObj.tag === 'string' ? { tag: fObj.tag } : {}),
        };
      }
    }
  }
  if (stringFormats.size === 0 && !jsonSchemaSpec && !attributesSpec) {
    stringFormats.add('markdown');
  }

  const inlineActionsParsed = normalizeInlineBrowserActions(payload.actions, selfHost, 50);
  if (!inlineActionsParsed.ok) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_action', message: inlineActionsParsed.message } };
  }
  const inlineActions = inlineActionsParsed.actions;

  const pdfParserOpts = parsePdfParserOptions(payload.parsers);
  const mobileEmulation = Boolean(payload.mobile);
  const checkPromptInjection = Boolean(payload.checkPromptInjection);

  const locationObj =
    payload.location && typeof payload.location === 'object' && !Array.isArray(payload.location)
      ? (payload.location as Record<string, unknown>)
      : null;
  const locationLanguages = Array.isArray(locationObj?.languages)
    ? locationObj!.languages
        .filter((l): l is string => typeof l === 'string' && /^[A-Za-z]{2}(?:-[A-Za-z0-9]{2,8})?$/.test(l.trim()))
        .map((l) => l.trim())
    : [];
  const acceptLanguageOpt = locationLanguages.length > 0 ? locationLanguages.join(', ') : undefined;

  const mergedHeaders: Record<string, string> = {
    ...(acceptLanguageOpt ? { 'Accept-Language': acceptLanguageOpt } : {}),
    ...(payload.headers && typeof payload.headers === 'object' && !Array.isArray(payload.headers)
      ? (payload.headers as Record<string, string>)
      : {}),
  };
  let callerExplicitAccept: string | undefined;
  for (const [hk, hv] of Object.entries(mergedHeaders)) {
    if (hk.toLowerCase() === 'accept' && typeof hv === 'string' && hv.trim()) {
      callerExplicitAccept = hv.trim();
      break;
    }
  }
  if (!callerExplicitAccept && typeof (payload as Record<string, unknown>).accept === 'string') {
    const rawPayloadAccept = String((payload as Record<string, unknown>).accept).trim();
    if (rawPayloadAccept) callerExplicitAccept = rawPayloadAccept;
  }

  const onlyMainContent = typeof payload.onlyMainContent === 'boolean' ? payload.onlyMainContent : true;
  const includeImages = typeof payload.includeImages === 'boolean' ? payload.includeImages : true;
  const includeTags = Array.isArray(payload.includeTags)
    ? payload.includeTags.filter((s): s is string => typeof s === 'string' && s.trim().length > 0).slice(0, 25)
    : [];
  const excludeTags = Array.isArray(payload.excludeTags)
    ? payload.excludeTags.filter((s): s is string => typeof s === 'string' && s.trim().length > 0).slice(0, 25)
    : [];
  const maxChars =
    typeof payload.maxChars === 'number' && Number.isFinite(payload.maxChars)
      ? Math.min(500_000, Math.max(500, Math.floor(payload.maxChars)))
      : typeof payload.defaultMaxChars === 'number' && Number.isFinite(payload.defaultMaxChars)
        ? Math.min(500_000, Math.max(500, Math.floor(payload.defaultMaxChars)))
        : undefined;
  const explicitDiscoverLlms = typeof payload.discoverLlmsTxt === 'boolean' ? payload.discoverLlmsTxt : undefined;
  const discoverLlmsTxt = explicitDiscoverLlms ?? true;
  const goDiscoverLlms =
    stringFormats.has('llmsTxt') ||
    (explicitDiscoverLlms !== false && shouldAutoProbeOriginLlms(parsedUrl, now));
  const redactPii = Boolean(payload.redactPii);
  const spaFallbackMode = normalizeSpaFallbackMode(payload.spaFallback);
  const rawWaitFor =
    typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
      ? payload.waitForMs
      : typeof payload.waitFor === 'number' && Number.isFinite(payload.waitFor)
        ? payload.waitFor
        : undefined;
  const waitForMsOpt = rawWaitFor !== undefined ? Math.min(15_000, Math.max(0, Math.floor(rawWaitFor))) : undefined;
  const waitSelectorOpt =
    typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
      ? payload.waitSelector.trim().slice(0, 200)
      : undefined;
  const rawMaxAge =
    typeof payload.maxAgeMs === 'number' && Number.isFinite(payload.maxAgeMs)
      ? payload.maxAgeMs
      : typeof payload.maxAge === 'number' && Number.isFinite(payload.maxAge)
        ? payload.maxAge
        : 0;
  const maxAgeMs = payload.noCache === true ? 0 : Math.max(0, Math.floor(rawMaxAge));
  const timeoutMsOpt =
    typeof payload.timeout === 'number' && Number.isFinite(payload.timeout)
      ? Math.min(120_000, Math.max(1_000, Math.floor(payload.timeout)))
      : 95_000;
  const maxPagesCap =
    pdfParserOpts.maxPagesOverride ??
    (typeof payload.maxPages === 'number' && Number.isFinite(payload.maxPages)
      ? Math.min(500, Math.max(1, Math.floor(payload.maxPages)))
      : 60);
  const ocrMode: 'auto' | 'always' | 'off' =
    pdfParserOpts.ocrModeOverride ??
    (payload.ocr === 'always' || payload.ocr === 'off' ? payload.ocr : 'auto');
  const hasPdfOcr = Boolean(env.PDF_OCR || (env.PDF_OCR_URL?.trim() && env.PDF_OCR_TOKEN?.trim()));
  const target: 'auto' | 'agent' | 'container' =
    payload.target === 'agent' || payload.target === 'container'
      ? payload.target
      : inlineActions.length > 0
        ? 'agent'
        : 'auto';
  const site = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim() : undefined;

  const focusQuery = typeof payload.query === 'string' ? payload.query.trim() : '';
  const applyQueryFocus = (
    fullMarkdown: string,
  ): { markdown: string; chunks: Array<{ ordinal: number; heading: string; text: string; score: number }>; queryFiltered: boolean } => {
    if (!focusQuery || !fullMarkdown.trim()) {
      return { markdown: fullMarkdown, chunks: [], queryFiltered: false };
    }
    const allChunks = chunkMarkdownForSearch(fullMarkdown);
    const ranked = rankChunksInMemory(allChunks, focusQuery, 5);
    if (ranked.length === 0) {
      return { markdown: fullMarkdown, chunks: [], queryFiltered: false };
    }
    const focused = [...ranked]
      .sort((a, b) => a.ordinal - b.ordinal)
      .map((c) => {
        const trimmed = c.text.trim();
        if (!c.heading || /^#{1,6}\s+/.test(trimmed)) return trimmed;
        return `## ${c.heading}\n${trimmed}`;
      })
      .join('\n\n...\n\n');
    return { markdown: focused, chunks: ranked, queryFiltered: true };
  };

  const preferOriginMarkdown = payload.preferOriginMarkdown !== false;

  // Serve from verified META D1 + ARTIFACTS R2 cache when maxAgeMs is satisfied and only markdown/metadata are requested.
  const needsLiveHtml =
    !preferOriginMarkdown ||
    stringFormats.has('html') ||
    stringFormats.has('rawHtml') ||
    stringFormats.has('rawBase64') ||
    stringFormats.has('product') ||
    stringFormats.has('links') ||
    stringFormats.has('images') ||
    stringFormats.has('branding') ||
    stringFormats.has('llmsTxt') ||
    stringFormats.has('changes') ||
    checkPromptInjection ||
    Boolean(callerExplicitAccept) ||
    inlineActions.length > 0 ||
    pdfParserOpts.skipPdfParsing ||
    includeTags.length > 0 ||
    excludeTags.length > 0 ||
    Boolean(jsonSchemaSpec) ||
    Boolean(attributesSpec);

  const needsDomForTwin =
    stringFormats.has('html') ||
    stringFormats.has('rawHtml') ||
    stringFormats.has('images') ||
    stringFormats.has('branding') ||
    stringFormats.has('screenshot') ||
    stringFormats.has('llmsTxt') ||
    stringFormats.has('changes') ||
    inlineActions.length > 0 ||
    pdfParserOpts.skipPdfParsing ||
    includeTags.length > 0 ||
    excludeTags.length > 0 ||
    Boolean(attributesSpec);

  let prevMarkdownForChanges: string | null = null;
  if (stringFormats.has('changes') && env.ARTIFACTS && env.META) {
    const prevHit = await lookupCachedScrape({
      bucket: env.ARTIFACTS,
      metaDb: env.META,
      url: normalizedUrl,
      maxAgeMs: 365 * 24 * 60 * 60_000,
      pipelineVersion: SCRAPE_PIPELINE_VERSION,
      now,
    });
    if (prevHit) {
      prevMarkdownForChanges = prevHit.markdown;
    }
  }

  if (!needsLiveHtml && ocrMode !== 'always' && maxAgeMs > 0 && env.ARTIFACTS && env.META) {
    const cacheStartMs = Date.now();
    const hit = await lookupCachedScrape({
      bucket: env.ARTIFACTS,
      metaDb: env.META,
      url: normalizedUrl,
      maxAgeMs,
      pipelineVersion: SCRAPE_PIPELINE_VERSION,
      now,
    });
    if (hit) {
      if (activeTracer) {
        const cacheSpan = activeTracer.startSpan('cache:r2-d1', {
          kind: 1,
          startTimeMs: cacheStartMs,
          attributes: {
            'cache.hit': true,
            'cache.tier': 'r2-d1',
            'cache.revalidated': false,
            'url.full': sanitizeUrlForSpan(normalizedUrl),
            'http.response.status_code': hit.status,
            'edgefetch.pipeline_version': hit.pipelineVersion,
          },
        });
        cacheSpan.setStatus(true);
        cacheSpan.end();
        activeTracer.setAttribute('edgefetch.via', 'cache:r2-d1');
        activeTracer.setAttribute('edgefetch.cached', true);
      }
      const fullCached = finalizeScrapedMarkdown(redactPii ? redactPiiText(hit.markdown) : hit.markdown, {
        isPdf: isLikelyPdfUrl(normalizedUrl),
        includeImages,
      }).markdown;
      const focused = applyQueryFocus(fullCached);
      const shaped = finalizeScrapedMarkdown(focused.markdown, {
        isPdf: false,
        includeImages,
        maxChars,
      });
      const cachedTitle = hit.title || (isLikelyPdfUrl(normalizedUrl) ? extractPdfTitle(fullCached, normalizedUrl) : undefined);
      return {
        status: 200,
        via: 'cache:r2-d1',
        body: {
          ok: true,
          cached: true,
          pipelineVersion: hit.pipelineVersion,
          documentId: hit.documentId,
          contentSha256: hit.contentSha256,
          url: normalizedUrl,
          status: hit.status,
          markdown: shaped.markdown,
          ...(focused.queryFiltered ? { queryFiltered: true, chunks: focused.chunks } : {}),
          ...(shaped.truncated
            ? {
                truncated: true,
                totalChars: shaped.totalChars,
                nextOffset: shaped.nextOffset ?? shaped.markdown.length,
                markdownArtifactId: `md:${hit.contentSha256}`,
              }
            : {}),
          metadata: {
            ...(cachedTitle ? { title: cachedTitle } : {}),
            ...(hit.language ? { language: hit.language } : {}),
            lastFetchedAt: hit.lastFetchedAt,
          },
        },
      };
    }
  }

  // Direct PDF OCR path when caller explicitly requests `ocr: "always"` (`kb-fetch --ocr` / MCP `scrape`).
  if (ocrMode === 'always' && hasPdfOcr) {
    const forcedOcr = await runPdfOcrFallback({
      url: normalizedUrl,
      ocrParam: 'always',
      maxOcrPages: maxPagesCap,
      redactPii,
      headers: payload.headers,
      target,
      site,
      source,
      env,
      executeHubFetch,
    });
    if (forcedOcr.ok) {
      const fullOcrMd = finalizeScrapedMarkdown(forcedOcr.markdown, { isPdf: true, includeImages }).markdown;
      const shaped = finalizeScrapedMarkdown(fullOcrMd, { isPdf: false, includeImages, maxChars });
      let ocrMdArtifactId: string | undefined;
      if (shaped.truncated && env.ARTIFACTS && fullOcrMd) {
        const mdSha = await sha256HexString(fullOcrMd);
        await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdSha), fullOcrMd, {
          httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
        }).catch(() => undefined);
        ocrMdArtifactId = `md:${mdSha}`;
      }
      return {
        status: 200,
        via: forcedOcr.via,
        body: {
          ok: true,
          cached: false,
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
          url: normalizedUrl,
          finalUrl: forcedOcr.finalUrl,
          status: forcedOcr.status,
          via: forcedOcr.via,
          ...(forcedOcr.contentSha256 ? { contentSha256: forcedOcr.contentSha256 } : {}),
          ...(forcedOcr.artifactId ? { artifactId: forcedOcr.artifactId } : {}),
          ...(ocrMdArtifactId ? { markdownArtifactId: ocrMdArtifactId } : {}),
          ...(stringFormats.has('markdown') ? { markdown: shaped.markdown } : {}),
          ...(stringFormats.has('text') ? { text: shaped.markdown } : {}),
          ...(shaped.truncated
            ? { truncated: true, totalChars: shaped.totalChars, nextOffset: shaped.nextOffset ?? shaped.markdown.length }
            : {}),
          pdfEngine: forcedOcr.pdfEngine,
          ...(forcedOcr.ocr ? { ocr: forcedOcr.ocr } : {}),
          ...(stringFormats.has('changes') ? { changes: computeMarkdownChanges(prevMarkdownForChanges, fullOcrMd) } : {}),
          metadata: { contentType: 'application/pdf' },
        },
      };
    }
    if (forcedOcr.originFailure) {
      return forcedOcr.originFailure;
    }
  }

  const agentFormats = [...stringFormats].filter((f) =>
    ['markdown', 'text', 'html', 'rawHtml', 'rawBase64', 'links', 'images', 'branding', 'screenshot'].includes(f),
  );
  if (pdfParserOpts.skipPdfParsing && !agentFormats.includes('rawBase64')) {
    agentFormats.push('rawBase64');
  }
  if (agentFormats.length === 0) agentFormats.push('markdown');

  const rawRenderModeStr = typeof payload.renderMode === 'string' ? payload.renderMode.trim().toLowerCase() : '';
  const renderMode: 'always' | 'auto' | 'off' | undefined =
    inlineActions.length > 0 || mobileEmulation || Boolean(screenshotSpec)
      ? 'always'
      : rawRenderModeStr === 'always' || rawRenderModeStr === 'browser'
        ? 'always'
        : rawRenderModeStr === 'auto' || rawRenderModeStr === 'off'
          ? rawRenderModeStr
          : stringFormats.has('screenshot')
            ? 'always'
            : undefined;
  const effectiveRenderMode: 'always' | 'auto' | 'off' = renderMode ?? 'auto';
  const jsonFilterStr = typeof payload.jsonFilter === 'string' ? payload.jsonFilter.trim() : '';
  const waybackFallback = Boolean(payload.waybackFallback);
  const collectionId =
    typeof payload.collectionId === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(payload.collectionId.trim())
      ? payload.collectionId.trim()
      : undefined;
  const retentionMode: ArtifactRetention | undefined =
    payload.ephemeral === true
      ? undefined
      : env.ARTIFACTS && env.META
        ? 'stored'
        : env.ARTIFACTS
          ? 'transient'
          : undefined;

  // R5: Look up stored ETag / Last-Modified validators in META D1 when a verified derived document already exists (and caller isn't updating a collection).
  const revalCandidate =
    !needsLiveHtml && ocrMode !== 'always' && renderMode !== 'always' && !collectionId && env.ARTIFACTS && env.META
      ? await lookupRevalidationCandidate({
          bucket: env.ARTIFACTS,
          metaDb: env.META,
          url: normalizedUrl,
          pipelineVersion: SCRAPE_PIPELINE_VERSION,
        })
      : null;

  const fetchCall = {
    maxSeconds: Math.max(30, Math.ceil(timeoutMsOpt / 1_000) + 15),
    options: {
      includeBody: true,
      respectRobots: true,
      maxBytes: 16 * 1024 * 1024,
      timeoutMs: timeoutMsOpt,
      discoverLlms: goDiscoverLlms,
    },
    requests: [
      {
        id: 'scrape-1',
        url: normalizedUrl,
        kind: pdfParserOpts.skipPdfParsing ? 'binary' : renderMode === 'always' ? 'render' : 'scrape',
        ...(!pdfParserOpts.skipPdfParsing
          ? {
              accept:
                callerExplicitAccept ??
                (!preferOriginMarkdown || stringFormats.has('html') || stringFormats.has('rawHtml')
                  ? 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'
                  : MARKDOWN_FOR_AGENTS_ACCEPT),
            }
          : callerExplicitAccept
            ? { accept: callerExplicitAccept }
            : {}),
        formats: agentFormats,
        onlyMainContent,
        discoverLlms: goDiscoverLlms,
        redactPii,
        ...(revalCandidate?.etag ? { ifNoneMatch: revalCandidate.etag } : {}),
        ...(revalCandidate?.lastModified ? { ifModifiedSince: revalCandidate.lastModified } : {}),
        ...(renderMode ? { renderMode } : {}),
        ...(mobileEmulation ? { mobile: true } : {}),
        ...(screenshotSpec?.fullPage ? { screenshotFullPage: true } : {}),
        ...(screenshotSpec?.quality ? { screenshotQuality: screenshotSpec.quality } : {}),
        ...(typeof screenshotSpec?.viewport?.width === 'number' ? { viewportWidth: Math.floor(screenshotSpec.viewport.width) } : {}),
        ...(typeof screenshotSpec?.viewport?.height === 'number' ? { viewportHeight: Math.floor(screenshotSpec.viewport.height) } : {}),
        ...(acceptLanguageOpt ? { acceptLanguage: acceptLanguageOpt } : {}),
        ...(waitForMsOpt !== undefined ? { waitForMs: waitForMsOpt } : {}),
        ...(waitSelectorOpt ? { waitSelector: waitSelectorOpt } : {}),
        ...(maxPagesCap ? { maxPages: maxPagesCap } : {}),
        ...(Object.keys(mergedHeaders).length > 0 ? { headers: mergedHeaders } : {}),
        ...(inlineActions.length > 0 ? { interact: { actions: inlineActions } } : {}),
      },
    ],
  };

  const htmlFragToMd = (frag: string, fragBase?: string) => {
    const sub = extractHtmlDocument(frag, {
      baseUrl: fragBase,
      onlyMainContent: false,
      includeImages,
    });
    return { markdown: sub.markdown, links: sub.links };
  };

  // Pre-fetch ATS API adapters (`P1` Ashby, `P2` Workday CXS `GET`/`POST`, Greenhouse, Lever) — runs even when
  // `renderMode: "browser"` / `"always"` is passed so client-hydrated ATS boards always resolve cleanly via their official APIs.
  const canUseAtsAdapter =
    inlineActions.length === 0 &&
    !stringFormats.has('html') &&
    !stringFormats.has('rawHtml') &&
    !stringFormats.has('rawBase64') &&
    !stringFormats.has('screenshot') &&
    !stringFormats.has('branding') &&
    !attributesSpec &&
    !jsonSchemaSpec;
  const atsSpec = canUseAtsAdapter ? resolveAtsPreFetchSpec(normalizedUrl) : null;
  if (atsSpec) {
    try {
      const atsRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 45,
          options: { includeBody: true, respectRobots: true, maxBytes: 16_777_216 },
          requests: [
            {
              id: `ats-${atsSpec.id}`,
              url: atsSpec.fetchUrl,
              method: atsSpec.method,
              ...(atsSpec.requestBody ? { requestBody: atsSpec.requestBody } : {}),
              ...(atsSpec.contentType ? { contentType: atsSpec.contentType } : {}),
              kind: atsSpec.kind,
              accept: atsSpec.accept,
            },
          ],
        }),
        site,
        `${source}:ats:${atsSpec.id}`,
        retentionMode,
        true,
        collectionId,
      );
      if (atsRes.status === 200) {
        const atsParsed = JSON.parse(atsRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const atsItem = atsParsed.results?.[0];
        const atsBody = typeof atsItem?.body === 'string' && atsItem.bodyEncoding !== 'base64' ? atsItem.body : '';
        if ((atsItem?.outcome === 'ok' || (atsItem?.truncated === true && atsItem?.status === 200)) && atsBody.trim().length > 0) {
          const filteredBoard =
            jsonFilterStr && atsSpec.id.endsWith('-board')
              ? chunkJsonRecords({
                  rawBody: atsBody,
                  contentType: 'application/json',
                  url: normalizedUrl,
                  jsonFilter: jsonFilterStr,
                  htmlToMd: htmlFragToMd,
                })
              : null;
          const formatted = atsSpec.format(atsBody, normalizedUrl, htmlFragToMd);
          if (filteredBoard || (formatted && formatted.markdown.trim().length > 0)) {
            const rawAtsMd = filteredBoard ? filteredBoard.markdown : formatted!.markdown;
            const cleanAtsMd = redactPii ? redactPiiText(rawAtsMd) : rawAtsMd;
            const atsShapedFull = finalizeScrapedMarkdown(cleanAtsMd, {
              isPdf: false,
              includeImages,
              baseUrl: normalizedUrl,
            });
            const atsFocused = applyQueryFocus(atsShapedFull.markdown);
            const atsShaped =
              atsFocused.queryFiltered || maxChars !== undefined
                ? finalizeScrapedMarkdown(atsFocused.markdown, {
                    isPdf: false,
                    includeImages,
                    maxChars,
                    baseUrl: normalizedUrl,
                  })
                : atsShapedFull;
            const atsArt = atsItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined;
            let atsMdArtifactId: string | undefined;
            if (atsShaped.truncated && env.ARTIFACTS && atsShapedFull.markdown) {
              const mdSha = await sha256HexString(atsShapedFull.markdown);
              await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdSha), atsShapedFull.markdown, {
                httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
              }).catch(() => undefined);
              atsMdArtifactId = `md:${mdSha}`;
            }
            const atsTitle = filteredBoard ? filteredBoard.title : formatted!.title;
            setActiveSpanAttribute('edgefetch.adapter_id', atsSpec.id, activeTracer ?? undefined);
            return {
              status: 200,
              via: atsRes.via,
              body: {
                ok: true,
                cached: false,
                pipelineVersion: SCRAPE_PIPELINE_VERSION,
                url: normalizedUrl,
                finalUrl: normalizedUrl,
                status: atsItem.status ?? 200,
                via: atsRes.via,
                extractorId: atsSpec.id,
                contentState: 'active' as const,
                ...(atsArt?.contentSha256 ? { contentSha256: atsArt.contentSha256 } : {}),
                ...(atsArt?.blobSha256 ? { artifactId: atsArt.blobSha256 } : {}),
                ...(atsMdArtifactId ? { markdownArtifactId: atsMdArtifactId } : {}),
                ...(formatted?.jobPosting ? { jobPosting: formatted.jobPosting } : {}),
                ...(formatted?.jobs && !filteredBoard ? { jobs: formatted.jobs } : {}),
                ...(formatted?.total !== undefined && !filteredBoard ? { total: formatted.total } : {}),
                ...(formatted?.returned !== undefined && !filteredBoard ? { returned: formatted.returned } : {}),
                ...(formatted?.nextCursor !== undefined && !filteredBoard ? { nextCursor: formatted.nextCursor } : {}),
                ...(filteredBoard
                  ? {
                      chunks: filteredBoard.chunks,
                      recordCount: filteredBoard.matchedRecords,
                      totalRecords: filteredBoard.totalRecords,
                    }
                  : {}),
                ...(stringFormats.has('markdown') ? { markdown: atsShaped.markdown } : {}),
                ...(stringFormats.has('text') ? { text: atsShaped.markdown } : {}),
                ...(stringFormats.has('links') && formatted?.links ? { links: formatted.links } : {}),
                ...(atsFocused.queryFiltered ? { queryFiltered: true, chunks: atsFocused.chunks } : {}),
                ...(atsShaped.truncated
                  ? {
                      truncated: true,
                      totalChars: atsShaped.totalChars,
                      nextOffset: atsShaped.nextOffset ?? atsShaped.markdown.length,
                    }
                  : formatted?.truncated !== undefined && !filteredBoard
                    ? { truncated: formatted.truncated }
                    : {}),
                metadata: {
                  title: atsTitle,
                  ...(formatted?.description ? { description: formatted.description } : {}),
                  ...(formatted?.publishedTime ? { publishedTime: formatted.publishedTime } : {}),
                  wordCount: countTextWords(atsShapedFull.markdown),
                  alternateMarkdownUrl: atsSpec.fetchUrl,
                  contentType: atsItem.contentType ?? atsSpec.accept,
                },
              },
            };
          }
        }
      }
    } catch {
      // Fall through cleanly if the ATS API endpoint fails or is unreachable.
    }
  }

  // Single-hop GitHub `/blob/<ref>/<path>` raw upgrade: fetch `raw.githubusercontent.com` directly (~2 KB) instead of
  // downloading 350 KB `github.com` HTML first (and avoiding `github.com` `/*/blob/` non-default branch robots blocks).
  const directGhBlob = !needsLiveHtml && renderMode !== 'always' ? parseGitHubBlobRawTarget(normalizedUrl) : null;
  if (directGhBlob) {
    try {
      const ghDirectRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: { includeBody: true, respectRobots: true },
          requests: [{ id: 'gh-raw-1', url: directGhBlob.rawUrl, kind: 'text', accept: 'text/plain' }],
        }),
        site,
        `${source}:github-raw`,
        retentionMode,
        true,
        collectionId,
      );
      if (ghDirectRes.status === 200) {
        const ghParsed = JSON.parse(ghDirectRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const ghItem = ghParsed.results?.[0];
        const ghBody = typeof ghItem?.body === 'string' && ghItem.bodyEncoding !== 'base64' ? ghItem.body : '';
        if (ghItem?.outcome === 'ok' && ghBody.trim().length > 0 && !/^\s*<!doctype\s+html|^\s*<html/i.test(ghBody)) {
          const cleanGhBody = redactPii ? redactPiiText(ghBody) : ghBody;
          let ghStructuredTitle: string | undefined;
          let ghStructuredDesc: string | undefined;
          let ghFullMd: string;
          if (directGhBlob.isMarkdown) {
            ghFullMd = cleanGhBody;
          } else if (/\.(?:ipynb|json)$/i.test(directGhBlob.filePath)) {
            let parsedGhJson: unknown = null;
            try {
              parsedGhJson = JSON.parse(cleanGhBody.replace(/^\ufeff/, ''));
            } catch {
              parsedGhJson = null;
            }
            const nbDoc = parsedGhJson
              ? formatJupyterNotebookToMarkdown(parsedGhJson, `${directGhBlob.repoSlug}/${directGhBlob.filePath}`)
              : null;
            const oaDoc = !nbDoc && parsedGhJson ? formatOpenApiSpecToMarkdown(parsedGhJson) : null;
            const richDoc = nbDoc ?? oaDoc;
            if (richDoc) {
              ghFullMd = richDoc.markdown;
              ghStructuredTitle = richDoc.title;
              ghStructuredDesc = richDoc.description;
            } else {
              ghFullMd = `# ${directGhBlob.repoSlug}/${directGhBlob.filePath}\n\n${makeSafeCodeFence(cleanGhBody, directGhBlob.fenceLang)}`;
            }
          } else {
            ghFullMd = `# ${directGhBlob.repoSlug}/${directGhBlob.filePath}\n\n${makeSafeCodeFence(cleanGhBody, directGhBlob.fenceLang)}`;
          }
          const ghShapedFull = finalizeScrapedMarkdown(ghFullMd, {
            isPdf: false,
            includeImages,
            baseUrl: directGhBlob.rawUrl,
          });
          const ghFocused = applyQueryFocus(ghShapedFull.markdown);
          const ghShaped =
            ghFocused.queryFiltered || maxChars !== undefined
              ? finalizeScrapedMarkdown(ghFocused.markdown, {
                  isPdf: false,
                  includeImages,
                  maxChars,
                  baseUrl: directGhBlob.rawUrl,
                })
              : ghShapedFull;
          const ghArt = ghItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined;
          let ghMdArtifactId: string | undefined;
          if (ghShaped.truncated && env.ARTIFACTS && ghShapedFull.markdown) {
            const mdSha = await sha256HexString(ghShapedFull.markdown);
            await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdSha), ghShapedFull.markdown, {
              httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
            }).catch(() => undefined);
            ghMdArtifactId = `md:${mdSha}`;
          }
          return {
            status: 200,
            via: ghDirectRes.via,
            body: {
              ok: true,
              cached: false,
              pipelineVersion: SCRAPE_PIPELINE_VERSION,
              url: normalizedUrl,
              finalUrl: normalizedUrl,
              status: ghItem.status ?? 200,
              via: ghDirectRes.via,
              ...(ghArt?.contentSha256 ? { contentSha256: ghArt.contentSha256 } : {}),
              ...(ghArt?.blobSha256 ? { artifactId: ghArt.blobSha256 } : {}),
              ...(ghMdArtifactId ? { markdownArtifactId: ghMdArtifactId } : {}),
              ...(stringFormats.has('markdown') ? { markdown: ghShaped.markdown } : {}),
              ...(stringFormats.has('text') ? { text: cleanGhBody } : {}),
              ...(ghFocused.queryFiltered ? { queryFiltered: true, chunks: ghFocused.chunks } : {}),
              ...(ghShaped.truncated
                ? {
                    truncated: true,
                    totalChars: ghShaped.totalChars,
                    nextOffset: ghShaped.nextOffset ?? ghShaped.markdown.length,
                  }
                : {}),
              metadata: {
                title: ghStructuredTitle ?? `${directGhBlob.repoSlug}/${directGhBlob.filePath}`,
                ...(ghStructuredDesc ? { description: ghStructuredDesc } : {}),
                alternateMarkdownUrl: directGhBlob.rawUrl,
                contentType: ghItem.contentType ?? 'text/plain; charset=utf-8',
              },
            },
          };
        }
      }
    } catch {
      // Fall through to standard HTML fetch if direct raw fetch fails.
    }
  }

  // Single-hop GitHub `/commit/<sha>` patch upgrade: fetch `<sha>.patch` (~5 KB, allowed by `github.com/robots.txt`)
  // instead of GitHub's heavy HTML diff view (which frequently times out or returns HTTP 503 on large commits).
  const directGhCommit = !needsLiveHtml && renderMode !== 'always' ? parseGitHubCommitPatchTarget(normalizedUrl) : null;
  if (directGhCommit) {
    try {
      const ghPatchRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: { includeBody: true, respectRobots: true },
          requests: [{ id: 'gh-patch-1', url: directGhCommit.patchUrl, kind: 'text', accept: 'text/plain' }],
        }),
        site,
        `${source}:github-patch`,
        retentionMode,
        true,
        collectionId,
      );
      if (ghPatchRes.status === 200) {
        const ghPatchParsed = JSON.parse(ghPatchRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const ghPatchItem = ghPatchParsed.results?.[0];
        const ghPatchBody =
          typeof ghPatchItem?.body === 'string' && ghPatchItem.bodyEncoding !== 'base64' ? ghPatchItem.body : '';
        if (ghPatchItem?.outcome === 'ok' && ghPatchBody.trim().length > 0) {
          const cleanPatchRaw = redactPii ? redactPiiText(ghPatchBody) : ghPatchBody;
          const patchDoc = formatGitPatchToMarkdown(cleanPatchRaw, 'text/x-patch', normalizedUrl);
          if (patchDoc) {
            const patchShapedFull = finalizeScrapedMarkdown(patchDoc.markdown, {
              isPdf: false,
              includeImages: false,
              baseUrl: normalizedUrl,
            });
            const patchFocused = applyQueryFocus(patchShapedFull.markdown);
            const patchShaped =
              patchFocused.queryFiltered || maxChars !== undefined
                ? finalizeScrapedMarkdown(patchFocused.markdown, {
                    isPdf: false,
                    includeImages: false,
                    maxChars,
                    baseUrl: normalizedUrl,
                  })
                : patchShapedFull;
            const ghPatchArt = ghPatchItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined;
            let patchMdArtifactId: string | undefined;
            if (patchShaped.truncated && env.ARTIFACTS && patchShapedFull.markdown) {
              const mdSha = await sha256HexString(patchShapedFull.markdown);
              await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdSha), patchShapedFull.markdown, {
                httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
              }).catch(() => undefined);
              patchMdArtifactId = `md:${mdSha}`;
            }
            return {
              status: 200,
              via: ghPatchRes.via,
              body: {
                ok: true,
                cached: false,
                pipelineVersion: SCRAPE_PIPELINE_VERSION,
                url: normalizedUrl,
                finalUrl: normalizedUrl,
                status: ghPatchItem.status ?? 200,
                via: ghPatchRes.via,
                ...(ghPatchArt?.contentSha256 ? { contentSha256: ghPatchArt.contentSha256 } : {}),
                ...(ghPatchArt?.blobSha256 ? { artifactId: ghPatchArt.blobSha256 } : {}),
                ...(patchMdArtifactId ? { markdownArtifactId: patchMdArtifactId } : {}),
                ...(stringFormats.has('markdown') ? { markdown: patchShaped.markdown } : {}),
                ...(stringFormats.has('text') ? { text: cleanPatchRaw } : {}),
                ...(patchFocused.queryFiltered ? { queryFiltered: true, chunks: patchFocused.chunks } : {}),
                ...(patchShaped.truncated
                  ? {
                      truncated: true,
                      totalChars: patchShaped.totalChars,
                      nextOffset: patchShaped.nextOffset ?? patchShaped.markdown.length,
                    }
                  : {}),
                metadata: {
                  title: patchDoc.title ?? `${directGhCommit.repoSlug}@${directGhCommit.sha.slice(0, 10)}`,
                  ...(patchDoc.description ? { description: patchDoc.description } : {}),
                  alternateMarkdownUrl: directGhCommit.patchUrl,
                  contentType: ghPatchItem.contentType ?? 'text/x-patch; charset=utf-8',
                },
              },
            };
          }
        }
      }
    } catch {
      // Fall through to standard HTML fetch if `.patch` fetch fails.
    }
  }

  // Modular Site Extractor Registry 1-hop JSON / raw / patch twin upgrade (`npm`, `crates.io`, `huggingface.co`,
  // `gitlab.com`, `codeberg.org`, Discourse `/t/<slug>/<id>.json`, `lobste.rs`, Bluesky ATProto, Mastodon, `dev.to`, etc.).
  const registryTwin = !needsDomForTwin && renderMode !== 'always' ? resolveSiteExtractorTwin(normalizedUrl) : null;
  if (registryTwin) {
    try {
      const twinRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: { includeBody: true, respectRobots: true },
          requests: [{ id: `twin-${registryTwin.id}`, url: registryTwin.fetchUrl, kind: registryTwin.kind, accept: registryTwin.accept }],
        }),
        site,
        `${source}:extractor:${registryTwin.id}`,
        retentionMode,
        true,
        collectionId,
      );
      if (twinRes.status === 200) {
        const twinParsed = JSON.parse(twinRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const twinItem = twinParsed.results?.[0];
        const twinBody = typeof twinItem?.body === 'string' && twinItem.bodyEncoding !== 'base64' ? twinItem.body : '';
        if (twinItem?.outcome === 'ok' && twinBody.trim().length > 0) {
          const formatted = registryTwin.formatTwin(twinBody, normalizedUrl, (frag, fragBase) => {
            const sub = extractHtmlDocument(frag, {
              baseUrl: fragBase,
              onlyMainContent: false,
              includeImages,
            });
            return { markdown: sub.markdown, links: sub.links };
          });
          if (formatted && formatted.markdown.trim().length > 0) {
            setActiveSpanAttribute('edgefetch.adapter_id', registryTwin.id, activeTracer ?? undefined);
            const rawMd = redactPii ? redactPiiText(formatted.markdown) : formatted.markdown;
            const twinShapedFull = finalizeScrapedMarkdown(rawMd, {
              isPdf: false,
              includeImages,
              baseUrl: normalizedUrl,
            });
            const twinFocused = applyQueryFocus(twinShapedFull.markdown);
            const twinShaped =
              twinFocused.queryFiltered || maxChars !== undefined
                ? finalizeScrapedMarkdown(twinFocused.markdown, {
                    isPdf: false,
                    includeImages,
                    maxChars,
                    baseUrl: normalizedUrl,
                  })
                : twinShapedFull;
            const twinArt = twinItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined;
            let twinMdArtifactId: string | undefined;
            if (twinShaped.truncated && env.ARTIFACTS && twinShapedFull.markdown) {
              const mdSha = await sha256HexString(twinShapedFull.markdown);
              await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdSha), twinShapedFull.markdown, {
                httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
              }).catch(() => undefined);
              twinMdArtifactId = `md:${mdSha}`;
            }
            if (checkPromptInjection) {
              const piTwin = detectPromptInjection({ markdown: `${formatted.title ?? ''}\n${twinShapedFull.markdown}` });
              if (piTwin.detected) {
                return {
                  status: 403,
                  via: twinRes.via,
                  body: {
                    ok: false,
                    success: false,
                    code: 'SCRAPE_PROMPT_INJECTION_DETECTED',
                    error: 'prompt_injection_detected',
                    message: `Prompt injection guard triggered (${piTwin.triggers.join(', ')})`,
                    triggers: piTwin.triggers,
                    url: normalizedUrl,
                  },
                };
              }
            }
            const twinLlmResolved =
              stringFormats.has('summary') || Boolean(jsonSchemaSpec)
                ? resolveLlmConfig({
                    env: env as OptionalStorageBindings & LlmEnvBindings,
                    requestLlm: payload.llm,
                    selfHost,
                  })
                : { ok: true as const, config: null };
            const twinLlmCfg = twinLlmResolved.ok ? twinLlmResolved.config : null;
            let twinSummaryOut: string | undefined;
            if (stringFormats.has('summary')) {
              const sumRes = await summarizeMarkdownWithOptionalLlm({
                markdown: twinShapedFull.markdown,
                title: formatted.title,
                llmConfig: twinLlmCfg,
                ...(activeTracer ? { tracer: activeTracer } : {}),
              });
              twinSummaryOut = sumRes.summary;
            }
            let twinJsonOut: Record<string, unknown> | undefined;
            if (jsonSchemaSpec) {
              const twinDoc: ExtractedDocument = {
                markdown: twinShapedFull.markdown,
                text: twinShapedFull.markdown,
                title: formatted.title,
                description: formatted.description,
                canonicalUrl: normalizedUrl,
                links: formatted.links ?? [],
                images: [],
                branding: { title: formatted.title, description: formatted.description, canonicalUrl: normalizedUrl },
              };
              const heuristic = extractStructuredJsonFromPage(twinBody, twinDoc, jsonSchemaSpec.schema);
              if (twinLlmCfg && (jsonSchemaSpec.prompt || jsonSchemaSpec.schema)) {
                const llmJ = await extractJsonWithOptionalLlm({
                  markdown: twinShapedFull.markdown,
                  title: formatted.title,
                  url: normalizedUrl,
                  prompt: jsonSchemaSpec.prompt,
                  schema: jsonSchemaSpec.schema,
                  llmConfig: twinLlmCfg,
                  heuristicFallback: heuristic,
                  ...(activeTracer ? { tracer: activeTracer } : {}),
                });
                twinJsonOut = llmJ.data;
              } else {
                twinJsonOut = heuristic;
              }
            }
            const twinProductOut = stringFormats.has('product')
              ? extractStructuredProduct({
                  rawBody: twinBody,
                  finalUrl: normalizedUrl,
                  fallbackTitle: formatted.title,
                  fallbackDescription: formatted.description,
                })
              : null;
            const twinRawBase64Out = stringFormats.has('rawBase64') ? encodeBodyToRawBase64(twinItem) : undefined;
            const twinHeaders =
              twinItem.headers && typeof twinItem.headers === 'object' && !Array.isArray(twinItem.headers)
                ? (twinItem.headers as Record<string, string | undefined>)
                : undefined;
            const twinDetected = detectSiteFrameworkLinear({
              url: normalizedUrl,
              ...(twinHeaders ? { headers: twinHeaders } : {}),
            });
            const hasTwinDetected = Boolean(
              twinDetected.platform ||
                twinDetected.framework ||
                twinDetected.generators.length > 0 ||
                (twinDetected.contentFlags && twinDetected.contentFlags.length > 0),
            );
            return {
              status: 200,
              via: twinRes.via,
              body: {
                ok: true,
                cached: false,
                pipelineVersion: SCRAPE_PIPELINE_VERSION,
                url: normalizedUrl,
                finalUrl: normalizedUrl,
                status: twinItem.status ?? 200,
                via: twinRes.via,
                extractorId: registryTwin.id,
                contentState: 'active' as const,
                ...(hasTwinDetected ? { detected: twinDetected } : {}),
                ...(twinArt?.contentSha256 ? { contentSha256: twinArt.contentSha256 } : {}),
                ...(twinArt?.blobSha256 ? { artifactId: twinArt.blobSha256 } : {}),
                ...(twinMdArtifactId ? { markdownArtifactId: twinMdArtifactId } : {}),
                ...(formatted.records !== undefined ? { records: formatted.records } : {}),
                ...(formatted.pagination !== undefined ? { pagination: formatted.pagination } : {}),
                ...(formatted.total !== undefined ? { total: formatted.total } : {}),
                ...(formatted.returned !== undefined ? { returned: formatted.returned } : {}),
                ...(formatted.nextCursor !== undefined ? { nextCursor: formatted.nextCursor } : {}),
                ...(stringFormats.has('markdown') ? { markdown: twinShaped.markdown } : {}),
                ...(stringFormats.has('text') ? { text: twinShaped.markdown } : {}),
                ...(twinSummaryOut !== undefined ? { summary: twinSummaryOut } : {}),
                ...(twinProductOut ? { product: twinProductOut } : {}),
                ...(twinRawBase64Out ? { rawBase64: twinRawBase64Out } : {}),
                ...(twinJsonOut ? { json: twinJsonOut } : {}),
                ...(stringFormats.has('links') && formatted.links ? { links: formatted.links } : {}),
                ...(twinFocused.queryFiltered ? { queryFiltered: true, chunks: twinFocused.chunks } : {}),
                ...(twinShaped.truncated
                  ? {
                      truncated: true,
                      totalChars: twinShaped.totalChars,
                      nextOffset: twinShaped.nextOffset ?? twinShaped.markdown.length,
                    }
                  : formatted.truncated !== undefined
                    ? { truncated: formatted.truncated }
                    : {}),
                metadata: {
                  title: formatted.title,
                  ...(formatted.description ? { description: formatted.description } : {}),
                  ...(formatted.author ? { author: formatted.author } : {}),
                  ...(formatted.publishedTime ? { publishedTime: formatted.publishedTime } : {}),
                  alternateMarkdownUrl: registryTwin.fetchUrl,
                  contentType: twinItem.contentType ?? registryTwin.accept,
                },
              },
            };
          }
        }
      }
    } catch {
      // Fall through cleanly to standard HTML fetch when twin endpoint is absent or fails.
    }
  }

  // Single-hop companion `.md` fast-path when `/llms.txt` (from an earlier `map` or `scrape`) already proved a `.md` twin exists.
  const cachedCompanionUrl =
    discoverLlmsTxt && !needsLiveHtml && renderMode !== 'always' ? lookupCompanionMdUrl(normalizedUrl, now) : undefined;
  if (cachedCompanionUrl) {
    try {
      const compRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 25,
          options: { includeBody: true, respectRobots: true },
          requests: [
            {
              id: 'companion-md-1',
              url: cachedCompanionUrl,
              kind: 'text',
              accept: 'text/markdown',
            },
          ],
        }),
        site,
        `${source}:companion-md`,
        retentionMode,
        true,
        collectionId,
      );
      if (compRes.status === 200) {
        const compParsed = JSON.parse(compRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const compItem = compParsed.results?.[0];
        const compBody = typeof compItem?.body === 'string' && compItem.bodyEncoding !== 'base64' ? compItem.body : '';
        if (compItem?.outcome === 'ok' && compBody.trim().length >= 32 && !/^\s*<!doctype\s+html|^\s*<html/i.test(compBody)) {
          const cleanCompRaw = redactPii ? redactPiiText(compBody) : compBody;
          const compShapedFull = finalizeScrapedMarkdown(cleanCompRaw, {
            isPdf: false,
            includeImages,
            baseUrl: normalizedUrl,
          });
          const compAssets = extractMarkdownLinksAndImages(compShapedFull.markdown, normalizedUrl, includeImages);
          const compFocused = applyQueryFocus(compShapedFull.markdown);
          const compShaped =
            compFocused.queryFiltered || maxChars !== undefined
              ? finalizeScrapedMarkdown(compFocused.markdown, {
                  isPdf: false,
                  includeImages,
                  maxChars,
                  baseUrl: normalizedUrl,
                })
              : compShapedFull;
          const compArt = compItem.artifact as { blobSha256?: string; contentSha256?: string } | undefined;
          let compMdArtifactId: string | undefined;
          if (compShaped.truncated && env.ARTIFACTS && compShapedFull.markdown) {
            const mdSha = await sha256HexString(compShapedFull.markdown);
            await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdSha), compShapedFull.markdown, {
              httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
            }).catch(() => undefined);
            compMdArtifactId = `md:${mdSha}`;
          }
          const compTitle = compShapedFull.frontmatterTitle || compAssets.title;
          const compDesc = compShapedFull.frontmatterDescription || compAssets.description;
          const compWords = countTextWords(compShapedFull.markdown);
          return {
            status: 200,
            via: compRes.via,
            body: {
              ok: true,
              cached: false,
              pipelineVersion: SCRAPE_PIPELINE_VERSION,
              url: normalizedUrl,
              finalUrl: normalizedUrl,
              status: compItem.status ?? 200,
              via: compRes.via,
              ...(compArt?.contentSha256 ? { contentSha256: compArt.contentSha256 } : {}),
              ...(compArt?.blobSha256 ? { artifactId: compArt.blobSha256 } : {}),
              ...(compMdArtifactId ? { markdownArtifactId: compMdArtifactId } : {}),
              ...(stringFormats.has('markdown') ? { markdown: compShaped.markdown } : {}),
              ...(stringFormats.has('text') ? { text: compShaped.markdown } : {}),
              ...(compFocused.queryFiltered ? { queryFiltered: true, chunks: compFocused.chunks } : {}),
              ...(compShaped.truncated
                ? {
                    truncated: true,
                    totalChars: compShaped.totalChars,
                    nextOffset: compShaped.nextOffset ?? compShaped.markdown.length,
                  }
                : {}),
              llms: {
                found: true,
                companionMdUrl: cachedCompanionUrl,
                usedCompanionMd: true,
              },
              metadata: {
                ...(compTitle ? { title: compTitle } : {}),
                ...(compDesc ? { description: compDesc } : {}),
                ...(compWords > 0 ? { wordCount: compWords } : {}),
                alternateMarkdownUrl: cachedCompanionUrl,
                contentType: compItem.contentType ?? 'text/markdown; charset=utf-8',
              },
            },
          };
        }
      }
    } catch {
      // Fall through to standard HTML scrape if direct companion .md fetch fails.
    }
  }

  const formatExternalSpaResponse = (spa: SpaFallbackSuccess): { status: number; via: string; body: Record<string, unknown> } => {
    const cleanRaw = redactPii ? redactPiiText(spa.markdown) : spa.markdown;
    const spaFull = finalizeScrapedMarkdown(cleanRaw, {
      isPdf: false,
      includeImages,
      baseUrl: spa.finalUrl,
    });
    const spaFocused = applyQueryFocus(spaFull.markdown);
    const spaShaped =
      spaFocused.queryFiltered || maxChars !== undefined
        ? finalizeScrapedMarkdown(spaFocused.markdown, { isPdf: false, includeImages, maxChars, baseUrl: spa.finalUrl })
        : spaFull;
    const redir = analyzeUrlRedirect(normalizedUrl, spa.finalUrl);
    return {
      status: 200,
      via: spa.via,
      body: {
        ok: true,
        cached: false,
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
        url: normalizedUrl,
        finalUrl: spa.finalUrl,
        ...(redir.redirected
          ? {
              redirected: true,
              ...(redir.redirectNote ? { redirectNote: redir.redirectNote } : {}),
              ...(redir.filtersMayBeLost ? { filtersMayBeLost: true } : {}),
            }
          : {}),
        status: spa.status,
        via: spa.via,
        renderedVia: spa.provider,
        contentState: 'active' as const,
        ...(stringFormats.has('markdown') ? { markdown: spaShaped.markdown } : {}),
        ...(stringFormats.has('text') ? { text: spaShaped.markdown } : {}),
        ...(stringFormats.has('links') && spa.links ? { links: spa.links } : {}),
        ...(spaFocused.queryFiltered ? { queryFiltered: true, chunks: spaFocused.chunks } : {}),
        ...(spaShaped.truncated
          ? { truncated: true, totalChars: spaShaped.totalChars, nextOffset: spaShaped.nextOffset ?? spaShaped.markdown.length }
          : {}),
        metadata: {
          ...(spa.title ? { title: spa.title } : {}),
          ...(spa.description ? { description: spa.description } : {}),
          wordCount: countTextWords(spaFull.markdown),
          contentType: 'text/html; charset=utf-8',
        },
      },
    };
  };

  const fetchRes = await executeHubFetch(target, JSON.stringify(fetchCall), site, source, retentionMode, true, collectionId);
  if (fetchRes.status !== 200) {
    let errJson: Record<string, unknown> = { ok: false, error: 'scrape_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    if (
      isEligibleForExternalSpaFallback({
        mode: spaFallbackMode,
        status: fetchRes.status,
        errorCode: errJson.error,
        problem: typeof errJson.message === 'string' ? errJson.message : '',
      })
    ) {
      const spaOut = await tryExternalSpaFallback({
        url: normalizedUrl,
        env,
        mode: spaFallbackMode,
        robotsAlreadyVerified: false,
        onlyMainContent,
        waitForMs: waitForMsOpt,
        waitSelector: waitSelectorOpt,
        noCache: Boolean(payload.noCache),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      if (spaOut) {
        return formatExternalSpaResponse(spaOut);
      }
    }
    return {
      status: fetchRes.status,
      via: fetchRes.via,
      body: errJson,
      ...(fetchRes.retryAfter ? { retryAfter: fetchRes.retryAfter } : {}),
    };
  }

  let fetchResUsed = fetchRes;
  const parsedReply = JSON.parse(fetchResUsed.bodyText) as {
    results?: Array<Record<string, unknown>>;
  };
  let item: Record<string, unknown> = parsedReply.results?.[0] ?? {};
  const isPdfResponse =
    typeof item.pdfEngine === 'string' ||
    (typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('application/pdf')) ||
    isLikelyPdfUrl(typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : normalizedUrl);

  if (item.outcome !== 'ok') {
    if (ocrMode !== 'off' && hasPdfOcr && item.outcome === 'error' && isPdfResponse) {
      const rescued = await runPdfOcrFallback({
        url: normalizedUrl,
        ocrParam: 'auto',
        maxOcrPages: maxPagesCap,
        redactPii,
        headers: payload.headers,
        target,
        site,
        source,
        env,
        executeHubFetch,
      });
      if (rescued.ok && rescued.markdown.trim().length > 0) {
        const fullRescuedMd = finalizeScrapedMarkdown(rescued.markdown, { isPdf: true, includeImages }).markdown;
        const shaped = finalizeScrapedMarkdown(fullRescuedMd, { isPdf: false, includeImages, maxChars });
        let rescuedMdArtifactId: string | undefined;
        if (shaped.truncated && env.ARTIFACTS && fullRescuedMd) {
          const mdSha = await sha256HexString(fullRescuedMd);
          await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdSha), fullRescuedMd, {
            httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
          }).catch(() => undefined);
          rescuedMdArtifactId = `md:${mdSha}`;
        }
        return {
          status: 200,
          via: rescued.via,
          body: {
            ok: true,
            cached: false,
            pipelineVersion: SCRAPE_PIPELINE_VERSION,
            url: normalizedUrl,
            finalUrl: rescued.finalUrl,
            status: rescued.status,
            via: rescued.via,
            ...(rescued.contentSha256 ? { contentSha256: rescued.contentSha256 } : {}),
            ...(rescued.artifactId ? { artifactId: rescued.artifactId } : {}),
            ...(rescuedMdArtifactId ? { markdownArtifactId: rescuedMdArtifactId } : {}),
            ...(stringFormats.has('markdown') ? { markdown: shaped.markdown } : {}),
            ...(stringFormats.has('text') ? { text: shaped.markdown } : {}),
            ...(shaped.truncated
              ? { truncated: true, totalChars: shaped.totalChars, nextOffset: shaped.nextOffset ?? shaped.markdown.length }
              : {}),
            pdfEngine: rescued.pdfEngine,
            ...(rescued.ocr ? { ocr: rescued.ocr } : {}),
            metadata: { contentType: 'application/pdf' },
          },
        };
      }
    }
    const problemText = String(item.problem ?? 'Origin scrape did not return HTTP 2xx');
    const rawErrBody = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
    const isPaymentRequiredErr = item.status === 402 || item.outcome === 'payment_required';
    const errWaf = isPaymentRequiredErr
      ? null
      : ((item.waf && typeof item.waf === 'object' ? (item.waf as WafClassification) : null) ??
        classifyWafAndChallenge({ status: typeof item.status === 'number' ? item.status : 0, rawBody: rawErrBody }));

    // Ethical External Heavy-SPA Fallback (`Crawl4AI` / `Firecrawl`) on local browser/transport failure (NEVER on robots.txt, 403, 429, or challenges!)
    if (
      isEligibleForExternalSpaFallback({
        mode: spaFallbackMode,
        outcome: item.outcome,
        status: item.status,
        problem: problemText,
        waf: errWaf,
      })
    ) {
      const spaOut = await tryExternalSpaFallback({
        url: normalizedUrl,
        env,
        mode: spaFallbackMode,
        robotsAlreadyVerified: false,
        onlyMainContent,
        waitForMs: waitForMsOpt,
        waitSelector: waitSelectorOpt,
        noCache: Boolean(payload.noCache),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      if (spaOut) {
        return formatExternalSpaResponse(spaOut);
      }
    }

    // R8: Opt-in Internet Archive (`Wayback CDX`) link-rot fallback — strictly ONLY on 5xx / DNS-dead failures, NEVER on robots/403/429/challenges!
    if (
      waybackFallback &&
      isEligibleForWaybackFallback({
        outcome: item.outcome,
        status: item.status,
        problem: problemText,
        waf: errWaf,
      })
    ) {
      const wb = await tryFetchWaybackSnapshot({
        url: normalizedUrl,
        target,
        site,
        source,
        executeHubFetch,
      });
      if (wb) {
        const wbDoc = extractHtmlDocument(wb.rawBody, {
          baseUrl: normalizedUrl,
          onlyMainContent,
          redactPii,
          includeImages,
          ...(includeTags.length > 0 ? { includeTags } : {}),
          ...(excludeTags.length > 0 ? { excludeTags } : {}),
        });
        const cleanWbMd = wbDoc.markdown.trim() || wb.rawBody.trim();
        const wbFull = finalizeScrapedMarkdown(redactPii ? redactPiiText(cleanWbMd) : cleanWbMd, {
          isPdf: false,
          includeImages,
          baseUrl: normalizedUrl,
        });
        const wbFocused = applyQueryFocus(wbFull.markdown);
        const wbShaped =
          wbFocused.queryFiltered || maxChars !== undefined
            ? finalizeScrapedMarkdown(wbFocused.markdown, { isPdf: false, includeImages, maxChars, baseUrl: normalizedUrl })
            : wbFull;
        return {
          status: 200,
          via: wb.via,
          body: {
            ok: true,
            cached: false,
            pipelineVersion: SCRAPE_PIPELINE_VERSION,
            url: normalizedUrl,
            finalUrl: normalizedUrl,
            status: 200,
            via: wb.via,
            contentSource: 'wayback',
            waybackSnapshotUrl: wb.snapshotUrl,
            waybackTimestamp: wb.timestamp,
            ...(stringFormats.has('markdown') ? { markdown: wbShaped.markdown } : {}),
            ...(stringFormats.has('text') ? { text: wbDoc.text || wbShaped.markdown } : {}),
            ...(stringFormats.has('links') ? { links: wbDoc.links } : {}),
            ...(wbFocused.queryFiltered ? { queryFiltered: true, chunks: wbFocused.chunks } : {}),
            metadata: {
              ...(wbDoc.title ? { title: wbDoc.title } : {}),
              ...(wbDoc.description ? { description: wbDoc.description } : {}),
              wordCount: countTextWords(wbFull.markdown),
              contentType: wb.contentType,
            },
          },
        };
      }
    }

    const effectiveOutcome = isPaymentRequiredErr
      ? 'payment_required'
      : errWaf
        ? 'challenge'
        : (item.outcome ?? 'error');
    if (errWaf?.vendor) {
      setActiveSpanAttribute('edgefetch.waf.vendor', errWaf.vendor, activeTracer ?? undefined);
    }
    setActiveSpanAttribute('edgefetch.outcome', String(effectiveOutcome), activeTracer ?? undefined);
    const effectiveProb = errWaf ? errWaf.summary : problemText;
    const robotsHint =
      /robots\.txt disallowed/i.test(effectiveProb) && !/^robots_unreachable\b/i.test(effectiveProb)
        ? buildRobotsAlternativeHint(normalizedUrl)
        : undefined;
    const itemPaymentHeaders =
      item.paymentHeaders && typeof item.paymentHeaders === 'object' && !Array.isArray(item.paymentHeaders)
        ? (item.paymentHeaders as Record<string, string | undefined>)
        : undefined;
    const rawBlockedInfo = buildBlockedInfo(normalizedUrl, effectiveOutcome, effectiveProb, item.status, {
      headers: itemPaymentHeaders,
      rawBody: rawErrBody,
    });
    const blockedInfo = refineBlockedInfo({
      url: normalizedUrl,
      outcome: effectiveOutcome,
      problem: effectiveProb,
      status: item.status,
      retryAfter: typeof item.retryAfter === 'string' ? item.retryAfter : fetchResUsed.retryAfter,
      baseBlocked: rawBlockedInfo,
    });
    return {
      status: isPaymentRequiredErr
        ? 402
        : item.status === 429
          ? 429
          : effectiveOutcome === 'challenge'
            ? 403
            : 422,
      via: fetchResUsed.via,
      body: {
        ok: false,
        url: normalizedUrl,
        outcome: effectiveOutcome,
        status: item.status ?? (isPaymentRequiredErr ? 402 : 0),
        problem: effectiveProb,
        ...(errWaf ? { waf: errWaf } : {}),
        ...(robotsHint ? { hint: robotsHint } : {}),
        ...(blockedInfo ? { blocked: blockedInfo } : {}),
      },
    };
  }

  // R5: `304 Not Modified` conditional revalidation hit — refresh `pages.last_fetched_at` in META D1 and serve verified R2 Markdown!
  if (item.status === 304 && revalCandidate && env.META) {
    if (activeTracer) {
      await activeTracer.withSpan(
        'cache:r2-d1',
        {
          kind: 1,
          attributes: {
            'cache.hit': true,
            'cache.tier': 'r2-d1',
            'cache.revalidated': true,
            'http.response.status_code': 304,
            'url.full': sanitizeUrlForSpan(normalizedUrl),
            'edgefetch.pipeline_version': revalCandidate.pipelineVersion,
          },
        },
        () => touchRevalidatedPage(env.META!, normalizedUrl, now),
      );
      activeTracer.setAttribute('edgefetch.cached', true);
      activeTracer.setAttribute('edgefetch.revalidated', true);
    } else {
      await touchRevalidatedPage(env.META, normalizedUrl, now);
    }
    const fullReval = finalizeScrapedMarkdown(
      redactPii ? redactPiiText(revalCandidate.markdown) : revalCandidate.markdown,
      { isPdf: isLikelyPdfUrl(normalizedUrl), includeImages },
    ).markdown;
    const revalFocused = applyQueryFocus(fullReval);
    const revalShaped = finalizeScrapedMarkdown(revalFocused.markdown, { isPdf: false, includeImages, maxChars });
    const revalTitle = revalCandidate.title || (isLikelyPdfUrl(normalizedUrl) ? extractPdfTitle(fullReval, normalizedUrl) : undefined);
    return {
      status: 200,
      via: `${fetchResUsed.via}+cache:304`,
      body: {
        ok: true,
        cached: true,
        revalidated: true,
        originStatus: 304,
        pipelineVersion: revalCandidate.pipelineVersion,
        documentId: revalCandidate.documentId,
        contentSha256: revalCandidate.contentSha256,
        url: normalizedUrl,
        finalUrl: normalizedUrl,
        status: 200,
        via: `${fetchResUsed.via}+cache:304`,
        ...(stringFormats.has('markdown') ? { markdown: revalShaped.markdown } : {}),
        ...(stringFormats.has('text') ? { text: revalShaped.markdown } : {}),
        ...(revalFocused.queryFiltered ? { queryFiltered: true, chunks: revalFocused.chunks } : {}),
        ...(revalShaped.truncated
          ? {
              truncated: true,
              totalChars: revalShaped.totalChars,
              nextOffset: revalShaped.nextOffset ?? revalShaped.markdown.length,
              markdownArtifactId: `md:${revalCandidate.contentSha256}`,
            }
          : {}),
        metadata: {
          ...(revalTitle ? { title: revalTitle } : {}),
          ...(revalCandidate.language ? { language: revalCandidate.language } : {}),
          lastFetchedAt: now,
        },
      },
    };
  }

  let rawBodyStr = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
  let finalUrl = typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : normalizedUrl;
  let renderedViaOut: 'browser' | 'browser-auto' | SpaFallbackProvider | undefined =
    renderMode === 'always' ? 'browser' : item.rendered === true ? 'browser-auto' : undefined;

  const rawTrimmedHead = rawBodyStr ? rawBodyStr.trimStart().slice(0, 64) : '';
  const looksLikeHtmlDocument = /^(?:<!doctype\b|<html\b)/i.test(rawTrimmedHead);
  const isOriginMarkdown = Boolean(
    rawBodyStr &&
      !isPdfResponse &&
      !looksLikeHtmlDocument &&
      typeof item.contentType === 'string' &&
      /^text\/(?:x-)?markdown\s*(?:;|$)/i.test(item.contentType.trim()),
  );
  let originMdCapTruncated = false;
  let originMdOriginalChars = 0;
  if (isOriginMarkdown && rawBodyStr.length > MAX_HTML_SCAN_CHARS) {
    originMdCapTruncated = true;
    originMdOriginalChars = rawBodyStr.length;
    rawBodyStr = rawBodyStr.slice(0, MAX_HTML_SCAN_CHARS);
  }

  // R2 & R3 (`R3-M3`): Guard against HTTP 200 WAF/CAPTCHA interstitials on BOTH HTML AND `origin-markdown` responses!
  const wafSourceStr = rawBodyStr || (typeof item.markdown === 'string' ? item.markdown : '');
  const okWafMatch =
    (item.waf && typeof item.waf === 'object' ? (item.waf as WafClassification) : null) ??
    (!isPdfResponse && wafSourceStr
      ? classifyWafAndChallenge({ status: typeof item.status === 'number' ? item.status : 200, rawBody: wafSourceStr })
      : null);
  if (okWafMatch) {
    setActiveSpanAttribute('edgefetch.waf.vendor', okWafMatch.vendor, activeTracer ?? undefined);
    setActiveSpanAttribute('edgefetch.outcome', 'challenge', activeTracer ?? undefined);
    const blockedInfo = refineBlockedInfo({
      url: finalUrl,
      outcome: 'challenge',
      problem: okWafMatch.summary,
      status: item.status,
      baseBlocked: buildBlockedInfo(finalUrl, 'challenge', okWafMatch.summary, item.status),
    });
    return {
      status: 403,
      via: fetchResUsed.via,
      body: {
        ok: false,
        url: normalizedUrl,
        finalUrl,
        outcome: 'challenge',
        status: item.status ?? 200,
        problem: okWafMatch.summary,
        waf: okWafMatch,
        ...(blockedInfo ? { blocked: blockedInfo } : {}),
      },
    };
  }

  // P2: Workday `{"widget":"redirect","url":"/Workday","externalSpa":true}` stub rescue -> CXS API or browser follow.
  const wdStub = !isPdfResponse && rawBodyStr ? detectWorkdayRedirectStub(rawBodyStr, finalUrl) : null;
  if (wdStub) {
    const stubAts = canUseAtsAdapter ? resolveAtsPreFetchSpec(wdStub.redirectUrl) : null;
    if (stubAts) {
      try {
        const stubRes = await executeHubFetch(
          target,
          JSON.stringify({
            maxSeconds: 45,
            options: { includeBody: true, respectRobots: true, maxBytes: 16_777_216 },
            requests: [
              {
                id: `ats-${stubAts.id}`,
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
          `${source}:workday-stub:${stubAts.id}`,
          retentionMode,
          true,
          collectionId,
        );
        if (stubRes.status === 200) {
          const stubParsed = JSON.parse(stubRes.bodyText) as { results?: Array<Record<string, unknown>> };
          const stubItem = stubParsed.results?.[0];
          const stubBody = typeof stubItem?.body === 'string' && stubItem.bodyEncoding !== 'base64' ? stubItem.body : '';
          const stubFormatted =
            (stubItem?.outcome === 'ok' || (stubItem?.truncated === true && stubItem?.status === 200)) && stubBody
              ? stubAts.format(stubBody, wdStub.redirectUrl, htmlFragToMd)
              : null;
          if (stubFormatted && stubFormatted.markdown.trim().length > 0) {
            setActiveSpanAttribute('edgefetch.adapter_id', stubAts.id, activeTracer ?? undefined);
            const stubRedirect = analyzeUrlRedirect(normalizedUrl, wdStub.redirectUrl);
            const cleanStubMd = redactPii ? redactPiiText(stubFormatted.markdown) : stubFormatted.markdown;
            const stubShaped = finalizeScrapedMarkdown(cleanStubMd, { isPdf: false, includeImages, maxChars, baseUrl: wdStub.redirectUrl });
            return {
              status: 200,
              via: stubRes.via,
              body: {
                ok: true,
                cached: false,
                pipelineVersion: SCRAPE_PIPELINE_VERSION,
                url: normalizedUrl,
                finalUrl: wdStub.redirectUrl,
                ...(stubRedirect.redirected ? stubRedirect : {}),
                status: stubItem?.status ?? 200,
                via: stubRes.via,
                extractorId: stubAts.id,
                contentState: 'active' as const,
                ...(stubFormatted.jobPosting ? { jobPosting: stubFormatted.jobPosting } : {}),
                ...(stubFormatted.jobs ? { jobs: stubFormatted.jobs } : {}),
                ...(stubFormatted.total !== undefined ? { total: stubFormatted.total } : {}),
                ...(stubFormatted.returned !== undefined ? { returned: stubFormatted.returned } : {}),
                ...(stubFormatted.nextCursor !== undefined ? { nextCursor: stubFormatted.nextCursor } : {}),
                ...(stringFormats.has('markdown') ? { markdown: stubShaped.markdown } : {}),
                ...(stringFormats.has('text') ? { text: stubShaped.markdown } : {}),
                ...(stringFormats.has('links') && stubFormatted.links ? { links: stubFormatted.links } : {}),
                ...(stubShaped.truncated
                  ? {
                      truncated: true,
                      totalChars: stubShaped.totalChars,
                      nextOffset: stubShaped.nextOffset ?? stubShaped.markdown.length,
                    }
                  : stubFormatted.truncated !== undefined
                    ? { truncated: stubFormatted.truncated }
                    : {}),
                metadata: {
                  title: stubFormatted.title,
                  wordCount: countTextWords(stubShaped.markdown),
                  alternateMarkdownUrl: stubAts.fetchUrl,
                  contentType: 'application/json',
                },
              },
            };
          }
        }
      } catch {
        // Fall back to browser follow below if CXS stub resolution fails.
      }
    }
    if (effectiveRenderMode !== 'off' && target !== 'container') {
      try {
        const wdBrowserRes = await executeHubFetch(
          'agent',
          JSON.stringify({
            maxSeconds: 45,
            options: { includeBody: true, respectRobots: true, maxBytes: 16 * 1024 * 1024, timeoutMs: 40_000 },
            requests: [
              {
                id: 'wd-stub-render-1',
                url: wdStub.redirectUrl,
                kind: 'render',
                renderMode: 'always',
                formats: agentFormats,
                onlyMainContent,
                waitSelector: '[data-automation-id="jobTitle"], [data-automation-id="jobFoundText"]',
                waitForMs: 2_200,
              },
            ],
          }),
          site,
          `${source}:workday-stub-render`,
          retentionMode,
          true,
          collectionId,
        );
        if (wdBrowserRes.status === 200) {
          const wdBrowserParsed = JSON.parse(wdBrowserRes.bodyText) as { results?: Array<Record<string, unknown>> };
          const wdBrowserItem = wdBrowserParsed.results?.[0];
          const wdBrowserBody =
            typeof wdBrowserItem?.body === 'string' && wdBrowserItem.bodyEncoding !== 'base64' ? wdBrowserItem.body : '';
          if (wdBrowserItem?.outcome === 'ok' && wdBrowserBody) {
            fetchResUsed = wdBrowserRes;
            item = wdBrowserItem;
            rawBodyStr = wdBrowserBody;
            finalUrl = typeof wdBrowserItem.finalUrl === 'string' && wdBrowserItem.finalUrl ? wdBrowserItem.finalUrl : wdStub.redirectUrl;
            renderedViaOut = 'browser-auto';
          }
        }
      } catch {
        // Keep original payload if no browser agent is available.
      }
    }
  }

  const rawBase64Requested = stringFormats.has('rawBase64') || pdfParserOpts.skipPdfParsing;
  if (rawBase64Requested && pdfParserOpts.skipPdfParsing) {
    const rawB64 = encodeBodyToRawBase64(item);
    return {
      status: 200,
      via: fetchResUsed.via,
      body: {
        ok: true,
        cached: false,
        pipelineVersion: SCRAPE_PIPELINE_VERSION,
        url: normalizedUrl,
        finalUrl,
        status: item.status ?? 200,
        via: fetchResUsed.via,
        ...(rawB64 ? { rawBase64: rawB64 } : {}),
        metadata: {
          contentType: isPdfResponse ? 'application/pdf' : item.contentType,
        },
      },
    };
  }

  if (!isOriginMarkdown && rawBodyStr && /^\s*(?:<!doctype\s+html|<html\b)/i.test(rawBodyStr)) {
    item.contentType = 'text/html; charset=utf-8';
  }
  const binaryScrapeProblem = rawBase64Requested
    ? null
    : detectUnsupportedBinaryPayload({
        rawBody: rawBodyStr,
        contentType: item.contentType,
        url: finalUrl,
        bodyEncoding: item.bodyEncoding,
        isPdf: isPdfResponse,
      });
  if (binaryScrapeProblem) {
    return {
      status: 422,
      via: fetchResUsed.via,
      body: {
        ok: false,
        url: normalizedUrl,
        finalUrl,
        outcome: 'skip',
        status: item.status ?? 200,
        problem: binaryScrapeProblem,
      },
    };
  }
  let isHtmlBody = Boolean(
    !isOriginMarkdown &&
      rawBodyStr &&
      !isPdfResponse &&
      ((typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('html')) ||
        /^\s*<!doctype\s+html|^\s*<html|<(head|body|main|article)\b/i.test(rawBodyStr)),
  );
  let extracted = isHtmlBody
    ? extractHtmlDocument(rawBodyStr, {
        baseUrl: finalUrl,
        onlyMainContent,
        redactPii,
        includeImages,
        ...(includeTags.length > 0 ? { includeTags } : {}),
        ...(excludeTags.length > 0 ? { excludeTags } : {}),
      })
    : undefined;

  const readItemHeaders = (): Record<string, string | undefined> | undefined =>
    item.headers && typeof item.headers === 'object' && !Array.isArray(item.headers)
      ? (item.headers as Record<string, string | undefined>)
      : undefined;

  // Custom-Domain Commerce Product Enrichment (Shopify + WooCommerce): when an HTML page on a custom domain matches
  // Shopify (`/products/<handle>`) or WooCommerce (`/product/<slug>/`), politely fetch the public JSON/Store API endpoint
  // via `executeHubFetch` and merge its rich GFM variant table + normalized `CatalogRecord`.
  let customShopifyDoc: TwinFormattedDoc | null = null;
  let customCommerceId: 'shopify' | 'woocommerce' | null = null;
  let prelimHostLower = '';
  try {
    prelimHostLower = new URL(finalUrl).hostname.toLowerCase();
  } catch {
    prelimHostLower = '';
  }
  const fetchCommerceTwinBody = async (epUrl: string, tag: string): Promise<string> => {
    const epRes = await executeHubFetch(
      target,
      JSON.stringify({
        maxSeconds: 25,
        options: { includeBody: true, respectRobots: true },
        requests: [{ id: tag, url: epUrl, kind: 'json', accept: 'application/json' }],
      }),
      site,
      `${source}:${tag}`,
      retentionMode,
      true,
      collectionId,
    );
    if (epRes.status !== 200) return '';
    const epParsed = JSON.parse(epRes.bodyText) as { results?: Array<Record<string, unknown>> };
    const epItem = epParsed.results?.[0];
    return epItem?.outcome === 'ok' && typeof epItem.body === 'string' && epItem.bodyEncoding !== 'base64'
      ? epItem.body
      : '';
  };

  if (
    isHtmlBody &&
    !isPdfResponse &&
    prelimHostLower &&
    !prelimHostLower.endsWith('.myshopify.com') &&
    isShopifyHtmlOrHeaders(rawBodyStr, readItemHeaders())
  ) {
    const shopTwin = resolveCustomDomainShopifyProductTwinUrl(finalUrl);
    if (shopTwin) {
      try {
        const htmlCurrency = extractShopifyCurrencyFromHtml(rawBodyStr);
        const jsonBody = await fetchCommerceTwinBody(shopTwin.jsonUrl, 'shopify-product-json');
        if (jsonBody.trim()) {
          let needsJsEnrich = true;
          try {
            const parsedJ = JSON.parse(jsonBody) as {
              product?: { variants?: Array<Record<string, unknown>> };
              variants?: Array<Record<string, unknown>>;
            };
            const firstVar = (parsedJ.product?.variants ?? parsedJ.variants)?.[0];
            if (firstVar && typeof firstVar.available === 'boolean') {
              needsJsEnrich = false;
            }
          } catch {
            needsJsEnrich = false;
          }
          const jsBody = needsJsEnrich
            ? await fetchCommerceTwinBody(shopTwin.jsUrl, 'shopify-product-js').catch(() => '')
            : '';
          customShopifyDoc = enrichShopifyProductFromJson({
            rawJson: jsonBody,
            productUrl: finalUrl,
            htmlToMd: htmlFragToMd,
            currency: htmlCurrency,
            ...(jsBody.trim() ? { ajaxJsBody: jsBody } : {}),
          });
          if (customShopifyDoc) customCommerceId = 'shopify';
        } else {
          const jsBody = await fetchCommerceTwinBody(shopTwin.jsUrl, 'shopify-product-js').catch(() => '');
          if (jsBody.trim()) {
            customShopifyDoc = enrichShopifyProductFromJson({
              rawJson: jsBody,
              productUrl: finalUrl,
              htmlToMd: htmlFragToMd,
              currency: htmlCurrency,
              isAjaxJs: true,
            });
            if (customShopifyDoc) customCommerceId = 'shopify';
          }
        }
      } catch {
        // Gracefully keep standard HTML / JSON-LD extraction if .json / .js endpoints fail.
      }
    }
  } else if (
    isHtmlBody &&
    !isPdfResponse &&
    prelimHostLower &&
    !extracted?.records &&
    isWooCommerceHtmlOrHeaders(rawBodyStr, readItemHeaders())
  ) {
    const wooTwin = resolveCustomDomainWooCommerceProductTwinUrl(finalUrl);
    if (wooTwin) {
      try {
        const wcJsonBody = await fetchCommerceTwinBody(wooTwin.storeApiUrl, 'woocommerce-product-json');
        if (wcJsonBody.trim()) {
          customShopifyDoc = enrichWooCommerceProductFromStoreApi({
            rawJson: wcJsonBody,
            productUrl: finalUrl,
            slug: wooTwin.slug,
            htmlToMd: htmlFragToMd,
            ...(extracted?.markdown ? { fallbackBodyMd: extracted.markdown } : {}),
          });
          if (customShopifyDoc) customCommerceId = 'woocommerce';
        }
      } catch {
        // Gracefully keep standard HTML extraction if WooCommerce Store API is disabled or unreachable.
      }
    }
  }

  // R6: SSR Hydration State Recovery (`__NEXT_DATA__`, Remix, Apollo, Inertia `data-page`) — extract full structured content
  // directly from the embedded hydration JSON on thin `<script>` pages BEFORE paying headless Chromium latency!
  let ssrHydrated: { title?: string; description?: string; markdown: string; framework: string } | null = null;
  if (isHtmlBody && !isPdfResponse && !customShopifyDoc) {
    if (extracted?.inertiaHydrated && extracted.markdown.trim()) {
      ssrHydrated = {
        ...(extracted.title ? { title: extracted.title } : {}),
        ...(extracted.description ? { description: extracted.description } : {}),
        markdown: extracted.markdown,
        framework: 'inertia',
      };
    } else if (countTextWords(extracted?.markdown ?? '') < 80) {
      const candidateHydration = recoverSsrHydrationContent(rawBodyStr, finalUrl, htmlFragToMd);
      if (candidateHydration && countTextWords(candidateHydration.markdown) > countTextWords(extracted?.markdown ?? '') * 2) {
        ssrHydrated = candidateHydration;
      } else if (
        countTextWords(extracted?.markdown ?? '') < 50 &&
        (rawBodyStr.includes('data-page="{&quot;component&quot;') || rawBodyStr.includes("data-page='{\"component\""))
      ) {
        const inertiaPage = extractInertiaPagePropsLinear(rawBodyStr);
        const inertiaDoc = inertiaPage ? formatInertiaPagePropsToMarkdown(inertiaPage, finalUrl, htmlFragToMd) : null;
        if (inertiaDoc && inertiaDoc.markdown.trim()) {
          ssrHydrated = {
            ...(inertiaDoc.title ? { title: inertiaDoc.title } : {}),
            ...(inertiaDoc.description ? { description: inertiaDoc.description } : {}),
            markdown: inertiaDoc.markdown,
            framework: 'inertia',
          };
        }
      }
    }
  }

  // P3: Automatic browser switch when a `<script>`-bearing or thin external/widget `<iframe>` (e.g. `#icims_content_iframe`) HTML page yields < 80 words.
  const hasThinExternalIframe =
    isHtmlBody && !customShopifyDoc && countTextWords(extracted?.markdown ?? '') < 50 && hasExternalOrWidgetIframeLinear(rawBodyStr).found;
  if (
    isHtmlBody &&
    !customShopifyDoc &&
    !ssrHydrated &&
    effectiveRenderMode === 'auto' &&
    item.rendered !== true &&
    target !== 'container' &&
    (isThinScriptedPage(rawBodyStr, extracted?.markdown ?? '') || hasThinExternalIframe)
  ) {
    try {
      const autoBrowserRes = await executeHubFetch(
        'agent',
        JSON.stringify({
          maxSeconds: 45,
          options: { includeBody: true, respectRobots: true, maxBytes: 16 * 1024 * 1024, timeoutMs: 40_000 },
          requests: [
            {
              id: 'auto-render-1',
              url: finalUrl,
              kind: 'render',
              renderMode: 'always',
              formats: agentFormats,
              onlyMainContent,
              redactPii,
              waitForMs:
                typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
                  ? Math.min(15_000, Math.max(0, Math.floor(payload.waitForMs)))
                  : 1_800,
              ...(typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
                ? { waitSelector: payload.waitSelector.trim().slice(0, 200) }
                : {}),
            },
          ],
        }),
        site,
        `${source}:browser-auto`,
        retentionMode,
        true,
        collectionId,
      );
      if (autoBrowserRes.status === 200) {
        const autoParsed = JSON.parse(autoBrowserRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const autoItem = autoParsed.results?.[0];
        const autoHtml = typeof autoItem?.body === 'string' && autoItem.bodyEncoding !== 'base64' ? autoItem.body : '';
        if (autoItem?.outcome === 'ok' && autoHtml) {
          const autoFinalUrl = typeof autoItem.finalUrl === 'string' && autoItem.finalUrl ? autoItem.finalUrl : finalUrl;
          const autoExtracted = extractHtmlDocument(autoHtml, {
            baseUrl: autoFinalUrl,
            onlyMainContent,
            redactPii,
            includeImages,
            ...(includeTags.length > 0 ? { includeTags } : {}),
            ...(excludeTags.length > 0 ? { excludeTags } : {}),
          });
          if (countTextWords(autoExtracted.markdown) > countTextWords(extracted?.markdown ?? '')) {
            fetchResUsed = autoBrowserRes;
            item = { ...autoItem, contentType: 'text/html; charset=utf-8' };
            rawBodyStr = autoHtml;
            finalUrl = autoFinalUrl;
            isHtmlBody = true;
            extracted = autoExtracted;
            renderedViaOut = 'browser-auto';
          }
        }
      }
    } catch {
      // Gracefully keep static HTML extraction when no `browser-v1` agent is connected.
    }
  }

  let alternateMarkdownUrl: string | undefined;
  let alternateMarkdownBody: string | undefined;
  const itemLlmsMeta =
    item.llms && typeof item.llms === 'object'
      ? (item.llms as { usedCompanionMd?: unknown; companionMdUrl?: unknown })
      : undefined;
  const goCompanionMd =
    discoverLlmsTxt &&
    !needsLiveHtml &&
    renderMode !== 'always' &&
    itemLlmsMeta?.usedCompanionMd === true &&
    typeof item.markdown === 'string' &&
    item.markdown.trim().length >= 32 &&
    !/^\s*<!doctype\s+html|^\s*<html/i.test(item.markdown)
      ? item.markdown.trim()
      : undefined;

  const ghBlobTarget =
    isHtmlBody && !goCompanionMd && !needsLiveHtml && renderMode !== 'always' ? parseGitHubBlobRawTarget(finalUrl) : null;
  if (goCompanionMd) {
    alternateMarkdownBody = redactPii ? redactPiiText(goCompanionMd) : goCompanionMd;
    if (typeof itemLlmsMeta?.companionMdUrl === 'string' && itemLlmsMeta.companionMdUrl) {
      alternateMarkdownUrl = itemLlmsMeta.companionMdUrl;
    } else if (extracted?.markdownAlternateUrl) {
      alternateMarkdownUrl = extracted.markdownAlternateUrl;
    }
  } else if (ghBlobTarget) {
    try {
      const ghRawRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 30,
          options: { includeBody: true, respectRobots: true },
          requests: [{ id: 'gh-raw-1', url: ghBlobTarget.rawUrl, kind: 'text', accept: 'text/plain' }],
        }),
        site,
        `${source}:github-raw`,
        'transient',
        true,
      );
      if (ghRawRes.status === 200) {
        const ghParsed = JSON.parse(ghRawRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const ghItem = ghParsed.results?.[0];
        const ghBody = typeof ghItem?.body === 'string' && ghItem.bodyEncoding !== 'base64' ? ghItem.body : '';
        if (ghItem?.outcome === 'ok' && ghBody.trim().length > 0 && !/^\s*<!doctype\s+html|^\s*<html/i.test(ghBody)) {
          alternateMarkdownUrl = ghBlobTarget.rawUrl;
          const cleanGhBody = redactPii ? redactPiiText(ghBody) : ghBody;
          alternateMarkdownBody = ghBlobTarget.isMarkdown
            ? cleanGhBody
            : `# ${ghBlobTarget.repoSlug}/${ghBlobTarget.filePath}\n\n${makeSafeCodeFence(cleanGhBody, ghBlobTarget.fenceLang)}`;
        }
      }
    } catch {
      // Fall back to HTML extraction if raw.githubusercontent.com fetch fails.
    }
  } else if (isHtmlBody && discoverLlmsTxt && extracted?.markdownAlternateUrl && !needsLiveHtml && renderMode !== 'always') {
    try {
      const altUrl = new URL(extracted.markdownAlternateUrl);
      const baseHost = new URL(finalUrl).hostname.toLowerCase();
      if (altUrl.protocol === 'https:' && altUrl.hostname.toLowerCase() === baseHost) {
        const altRes = await executeHubFetch(
          target,
          JSON.stringify({
            maxSeconds: 30,
            options: { includeBody: true, respectRobots: true },
            requests: [{ id: 'alt-md-1', url: altUrl.toString(), kind: 'text', accept: 'text/plain' }],
          }),
          site,
          `${source}:alt-md`,
          'transient',
          true,
        );
        if (altRes.status === 200) {
          const altParsed = JSON.parse(altRes.bodyText) as { results?: Array<Record<string, unknown>> };
          const altItem = altParsed.results?.[0];
          const altText = typeof altItem?.body === 'string' && altItem.bodyEncoding !== 'base64' ? altItem.body.trim() : '';
          if (altItem?.outcome === 'ok' && altText.length >= 32 && !/^\s*<!doctype\s+html|^\s*<html/i.test(altText)) {
            alternateMarkdownUrl = altUrl.toString();
            alternateMarkdownBody = redactPii ? redactPiiText(altText) : altText;
          }
        }
      }
    } catch {
      // Fall back to extracted HTML Markdown if companion .md fetch fails.
    }
  }

  const vcardFormatted =
    !isOriginMarkdown &&
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    ((typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('vcard')) ||
      /^BEGIN:VCARD\b/im.test(rawBodyStr.trim()))
      ? formatVcardToMarkdown(rawBodyStr)
      : null;
  const icsFormatted =
    !isOriginMarkdown && !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted
      ? formatIcalendarToMarkdown(rawBodyStr)
      : null;
  const feedFormatted =
    !isOriginMarkdown && !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted
      ? formatFeedXmlToMarkdown(rawBodyStr, finalUrl)
      : null;
  const jsonFormatted =
    !isOriginMarkdown && !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted && !feedFormatted
      ? tryParseJsonPayloadForScrape(rawBodyStr, item.contentType, finalUrl)
      : null;
  const isNotebookOrOpenApiJson = Boolean(
    jsonFormatted?.parsed &&
      typeof jsonFormatted.parsed === 'object' &&
      !Array.isArray(jsonFormatted.parsed) &&
      ('openapi' in (jsonFormatted.parsed as Record<string, unknown>) ||
        'swagger' in (jsonFormatted.parsed as Record<string, unknown>) ||
        'nbformat' in (jsonFormatted.parsed as Record<string, unknown>)),
  );
  const jsonRecordsFormatted =
    !isOriginMarkdown &&
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    !vcardFormatted &&
    !icsFormatted &&
    !feedFormatted &&
    !isNotebookOrOpenApiJson
      ? chunkJsonRecords({
          rawBody: rawBodyStr,
          contentType: item.contentType,
          url: finalUrl,
          ...(jsonFilterStr ? { jsonFilter: jsonFilterStr } : {}),
          htmlToMd: htmlFragToMd,
        })
      : null;
  const csvFormatted =
    !isOriginMarkdown && !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted && !feedFormatted && !jsonFormatted
      ? formatDelimitedTableToMarkdown(rawBodyStr, item.contentType, finalUrl)
      : null;
  const patchFormatted =
    !isOriginMarkdown &&
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    !vcardFormatted &&
    !icsFormatted &&
    !feedFormatted &&
    !jsonFormatted &&
    !csvFormatted
      ? formatGitPatchToMarkdown(rawBodyStr, item.contentType, finalUrl)
      : null;
  const sourceCodeFormatted =
    !isOriginMarkdown &&
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    !vcardFormatted &&
    !icsFormatted &&
    !feedFormatted &&
    !jsonFormatted &&
    !csvFormatted &&
    !patchFormatted
      ? formatSourceCodeUrlToMarkdown(rawBodyStr, item.contentType, finalUrl)
      : null;

  const structuredTextFormatted =
    vcardFormatted ||
    icsFormatted ||
    feedFormatted ||
    jsonRecordsFormatted ||
    jsonFormatted ||
    csvFormatted ||
    patchFormatted ||
    sourceCodeFormatted;

  // P4: Extract structured schema.org `JobPosting` JSON-LD on HTML pages and surface key facts (pay, workplace, location) at the top.
  const htmlJobPosting: StructuredJobPosting | null = isHtmlBody
    ? extractJobPostingJsonLd(rawBodyStr, finalUrl, extracted?.markdown ?? '')
    : null;

  let markdown = isOriginMarkdown
    ? rawBodyStr
    : alternateMarkdownBody ||
      customShopifyDoc?.markdown ||
      ssrHydrated?.markdown ||
      structuredTextFormatted?.markdown ||
      (isHtmlBody ? extracted?.markdown : undefined) ||
      (typeof item.markdown === 'string' && item.markdown) ||
      extracted?.markdown ||
      (isHtmlBody ? '' : rawBodyStr);
  if (htmlJobPosting && isHtmlBody && !alternateMarkdownBody && !customShopifyDoc) {
    const jpHeader = formatJobPostingHeaderMarkdown(htmlJobPosting);
    if (jpHeader && !/\*\*Compensation\*\*:/.test(markdown.slice(0, 400))) {
      const topHeadingMatch = /^(#\s+[^\n]+)\n+([\s\S]*)$/.exec(markdown.trim());
      markdown = topHeadingMatch
        ? `${topHeadingMatch[1]}\n\n${jpHeader}\n\n${topHeadingMatch[2]}`
        : `# ${htmlJobPosting.title}\n\n${jpHeader}\n\n${markdown}`;
    }
  }
  let textOut = isOriginMarkdown
    ? rawBodyStr
    : alternateMarkdownBody ||
      customShopifyDoc?.markdown ||
      ssrHydrated?.markdown ||
      feedFormatted?.markdown ||
      vcardFormatted?.markdown ||
      icsFormatted?.markdown ||
      jsonRecordsFormatted?.markdown ||
      (jsonFormatted || csvFormatted || patchFormatted || sourceCodeFormatted ? rawBodyStr : undefined) ||
      (isHtmlBody ? extracted?.text : undefined) ||
      (typeof item.text === 'string' && item.text) ||
      extracted?.text ||
      '';
  let viaOut = fetchResUsed.via;
  let pdfEngineOut = typeof item.pdfEngine === 'string' ? item.pdfEngine : undefined;
  let ocrReportOut: PdfOcrContainerReply['ocr'] | undefined;
  let contentSourceOut: 'origin-markdown' | 'meta-description' | 'ssr-hydration' | undefined = isOriginMarkdown
    ? 'origin-markdown'
    : ssrHydrated
      ? 'ssr-hydration'
      : undefined;

  // Automatic PDF OCR fallback when Poppler `pdftotext` returns empty / scanned-image output (<100 non-whitespace chars).
  if (ocrMode === 'auto' && hasPdfOcr && isPdfResponse && markdown.replace(/\s+/g, '').length < 100) {
    const autoOcr = await runPdfOcrFallback({
      url: finalUrl,
      ocrParam: 'auto',
      maxOcrPages: maxPagesCap,
      redactPii,
      headers: payload.headers,
      target,
      site,
      source,
      env,
      executeHubFetch,
    });
    if (autoOcr.ok && autoOcr.markdown.replace(/\s+/g, '').length > markdown.replace(/\s+/g, '').length) {
      markdown = autoOcr.markdown;
      textOut = autoOcr.markdown;
      viaOut = autoOcr.via;
      pdfEngineOut = autoOcr.pdfEngine;
      ocrReportOut = autoOcr.ocr;
    }
  }

  if (redactPii) {
    markdown = redactPiiText(markdown);
    textOut = redactPiiText(textOut);
  }
  let fullShaped = finalizeScrapedMarkdown(markdown, {
    isPdf: isPdfResponse,
    includeImages,
    maxChars: undefined,
    baseUrl: finalUrl,
    preserveOriginMarkdown: isOriginMarkdown,
  });
  let rawCleanMarkdown = fullShaped.markdown;
  const mdAssets = !isHtmlBody && !isPdfResponse ? extractMarkdownLinksAndImages(rawCleanMarkdown, finalUrl, includeImages) : undefined;

  // P1: Short-term / general fallback — when extracted HTML Markdown has < 50 words and `<meta name="description">` / `og:description`
  // holds substantive text (>= 40 words and > 2x the extracted body), rescue `metadata.description` with `contentSource: "meta-description"`.
  const prelimDescription = extracted?.description || (typeof item.description === 'string' && item.description ? decodeHtmlEntities(item.description) : undefined);
  const prelimTitle = extracted?.title || (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined);
  const bodyWordsBeforeRescue = countTextWords(rawCleanMarkdown);
  const metaDescWords = prelimDescription ? countTextWords(prelimDescription) : 0;
  if (
    isHtmlBody &&
    !isPdfResponse &&
    !customShopifyDoc &&
    !ssrHydrated &&
    bodyWordsBeforeRescue < 50 &&
    prelimDescription &&
    metaDescWords >= 18 &&
    metaDescWords > bodyWordsBeforeRescue * 2
  ) {
    const cleanDesc = redactPii ? redactPiiText(prelimDescription) : prelimDescription;
    const cleanTitle = prelimTitle ? (redactPii ? redactPiiText(prelimTitle) : prelimTitle) : '';
    const rescuedMd = [cleanTitle ? `# ${cleanTitle}` : '', cleanDesc].filter(Boolean).join('\n\n');
    fullShaped = finalizeScrapedMarkdown(rescuedMd, {
      isPdf: false,
      includeImages,
      maxChars: undefined,
      baseUrl: finalUrl,
    });
    rawCleanMarkdown = fullShaped.markdown;
    textOut = cleanDesc;
    contentSourceOut = 'meta-description';
  }

  // Ethical Heavy-SPA Fallback (`Crawl4AI` / `Firecrawl`) when a `200 OK` `<script>` or external-iframe SPA shell remained thin (`< 50` words)
  // even after SSR hydration + local browser attempt, provided there is NO WAF challenge, login wall, soft-404, or closed posting!
  const isThinIframeShellAfterLocal =
    isHtmlBody && !customShopifyDoc && countTextWords(rawCleanMarkdown) < 50 && hasExternalOrWidgetIframeLinear(rawBodyStr).found;
  if (
    isHtmlBody &&
    !isPdfResponse &&
    !customShopifyDoc &&
    !ssrHydrated &&
    effectiveRenderMode !== 'off' &&
    countTextWords(rawCleanMarkdown) < 50 &&
    (isThinScriptedPage(rawBodyStr, rawCleanMarkdown) || isThinIframeShellAfterLocal)
  ) {
    const preState = classifyContentState({
      status: typeof item.status === 'number' ? item.status : 200,
      title: prelimTitle,
      markdown: rawCleanMarkdown,
      rawHtml: rawBodyStr,
      rendered: Boolean(item.rendered === true || renderedViaOut !== undefined),
      nowMs: now,
    });
    if (
      isEligibleForExternalSpaFallback({
        mode: spaFallbackMode,
        outcome: 'ok',
        status: item.status ?? 200,
        waf: okWafMatch,
        contentState: preState.state === 'empty_shell' ? 'active' : preState.state,
        isThinSpa200: true,
      })
    ) {
      const spaOut = await tryExternalSpaFallback({
        url: finalUrl,
        env,
        mode: spaFallbackMode,
        robotsAlreadyVerified: true,
        onlyMainContent,
        waitForMs: waitForMsOpt,
        waitSelector: waitSelectorOpt,
        noCache: Boolean(payload.noCache),
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      if (spaOut && countTextWords(spaOut.markdown) > countTextWords(rawCleanMarkdown)) {
        const cleanSpaMd = redactPii ? redactPiiText(spaOut.markdown) : spaOut.markdown;
        fullShaped = finalizeScrapedMarkdown(cleanSpaMd, {
          isPdf: false,
          includeImages,
          maxChars: undefined,
          baseUrl: spaOut.finalUrl,
        });
        rawCleanMarkdown = fullShaped.markdown;
        textOut = rawCleanMarkdown;
        finalUrl = spaOut.finalUrl;
        viaOut = spaOut.via;
        renderedViaOut = spaOut.provider;
        contentSourceOut = undefined;
      }
    }
  }

  // P5: When `query` is combined with a JSON record array, rank across the per-record chunks directly so fields never bleed across records!
  const focused =
    jsonRecordsFormatted && focusQuery
      ? (() => {
          const ranked = rankChunksInMemory(jsonRecordsFormatted.chunks, focusQuery, 5);
          if (ranked.length === 0) return { markdown: rawCleanMarkdown, chunks: [], queryFiltered: false };
          return {
            markdown: [...ranked]
              .sort((a, b) => a.ordinal - b.ordinal)
              .map((c) => c.text)
              .join('\n\n---\n\n'),
            chunks: ranked,
            queryFiltered: true,
          };
        })()
      : applyQueryFocus(rawCleanMarkdown);
  const shaped =
    focused.queryFiltered || maxChars !== undefined
      ? finalizeScrapedMarkdown(focused.markdown, {
          isPdf: false,
          includeImages,
          maxChars,
          baseUrl: finalUrl,
          preserveOriginMarkdown: isOriginMarkdown,
        })
      : fullShaped;
  markdown = shaped.markdown;
  textOut = isOriginMarkdown ? rawCleanMarkdown : decodeHtmlEntities(textOut);

  let llmsPayload: unknown = item.llms;
  if (llmsPayload && typeof llmsPayload === 'object') {
    if ((llmsPayload as { found?: unknown }).found === false) {
      recordOriginLlmsAbsent(parsedUrl.origin, now);
    } else {
      recordCompanionMdLinksFromLlmsPayload(llmsPayload, now);
    }
  }
  if (!llmsPayload && stringFormats.has('llmsTxt')) {
    try {
      const llmsOriginUrl = `${parsedUrl.origin}/llms.txt`;
      const llmsRes = await executeHubFetch(
        target,
        JSON.stringify({
          maxSeconds: 20,
          options: { includeBody: true, respectRobots: true },
          requests: [{ id: 'llms-1', url: llmsOriginUrl, kind: 'text', accept: 'text/plain' }],
        }),
        site,
        `${source}:llms`,
        'transient',
        true,
      );
      if (llmsRes.status === 200) {
        const llmsReply = JSON.parse(llmsRes.bodyText) as { results?: Array<Record<string, unknown>> };
        const llmsItem = llmsReply.results?.[0];
        if (llmsItem?.outcome === 'ok' && typeof llmsItem.body === 'string') {
          const parsedLlms = parseLlmsTxt(llmsItem.body, llmsOriginUrl);
          if (parsedLlms) {
            llmsPayload = {
              found: true,
              llmsTxtUrl: llmsOriginUrl,
              ...(parsedLlms.title ? { siteTitle: parsedLlms.title } : {}),
              ...(parsedLlms.summary ? { summary: parsedLlms.summary } : {}),
              ...(parsedLlms.fullTxtUrl ? { fullTxtUrl: parsedLlms.fullTxtUrl } : {}),
              relatedLinks: parsedLlms.links.slice(0, 25),
            };
          } else {
            recordOriginLlmsAbsent(parsedUrl.origin, now);
          }
        } else {
          recordOriginLlmsAbsent(parsedUrl.origin, now);
        }
      }
    } catch {
      // Best-effort /llms.txt discovery
    }
  }

  const resolvedLinks = isHtmlBody
    ? (extracted?.links ?? (Array.isArray(item.links) ? item.links : []))
    : feedFormatted && feedFormatted.links.length > 0
      ? feedFormatted.links
      : Array.isArray(item.links) && item.links.length > 0
        ? item.links
        : (mdAssets?.links ?? extracted?.links ?? []);
  const resolvedImages = !includeImages
    ? []
    : isHtmlBody
      ? (extracted?.images ?? [])
      : Array.isArray(item.images) && item.images.length > 0
        ? (item.images as ScrapedImage[]).filter((img) => !isTinyOrAvatarImageUrl(img.url ?? '', img.alt ?? ''))
        : (mdAssets?.images ?? extracted?.images ?? []);

  const rawResolvedTitle =
    customShopifyDoc?.title ||
    ssrHydrated?.title ||
    extracted?.title ||
    structuredTextFormatted?.title ||
    fullShaped.frontmatterTitle ||
    mdAssets?.title ||
    (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined) ||
    (typeof (llmsPayload as { matchedEntry?: { title?: string } } | undefined)?.matchedEntry?.title === 'string'
      ? decodeHtmlEntities((llmsPayload as { matchedEntry: { title: string } }).matchedEntry.title)
      : undefined) ||
    (isPdfResponse ? extractPdfTitle(rawCleanMarkdown, finalUrl) : undefined);
  const rawResolvedDescription =
    customShopifyDoc?.description ||
    ssrHydrated?.description ||
    extracted?.description ||
    (structuredTextFormatted as { description?: string } | null)?.description ||
    fullShaped.frontmatterDescription ||
    mdAssets?.description ||
    (typeof item.description === 'string' && item.description ? decodeHtmlEntities(item.description) : undefined);
  const resolvedTitle = rawResolvedTitle ? (redactPii ? redactPiiText(rawResolvedTitle) : rawResolvedTitle) : undefined;
  const resolvedDescription = rawResolvedDescription
    ? redactPii
      ? redactPiiText(rawResolvedDescription)
      : rawResolvedDescription
    : undefined;

  // R4: Classify `contentState` ("active" | "closed_posting" | "soft_404" | "login_wall" | "empty_shell") with anti-false-positive vetoes!
  const contentStateCheck: { state: ContentState; reason?: string } = classifyContentState({
    status: typeof item.status === 'number' ? item.status : 200,
    url: normalizedUrl,
    finalUrl,
    title: resolvedTitle,
    markdown: rawCleanMarkdown,
    ...(isHtmlBody ? { rawHtml: rawBodyStr } : {}),
    rendered: Boolean(item.rendered === true || renderedViaOut !== undefined),
    ...(htmlJobPosting?.validThrough ? { validThrough: htmlJobPosting.validThrough } : {}),
    nowMs: now,
  });

  if (checkPromptInjection) {
    const mdForInjectionCheck = [resolvedTitle, resolvedDescription, rawCleanMarkdown].filter(Boolean).join('\n\n');
    const piCheck = detectPromptInjection({
      markdown: mdForInjectionCheck,
      ...(isHtmlBody || isOriginMarkdown ? { rawHtml: rawBodyStr } : {}),
    });
    if (piCheck.detected) {
      return {
        status: 403,
        via: viaOut,
        body: {
          ok: false,
          url: normalizedUrl,
          finalUrl,
          error: 'SCRAPE_PROMPT_INJECTION_DETECTED',
          message: `Prompt injection guard blocked page content (${piCheck.triggers.join(', ')})`,
          triggers: piCheck.triggers,
        },
      };
    }
  }

  let pdfPagesArray: string[] | undefined;
  if (isPdfResponse && (pdfParserOpts.includePagesArray || pdfParserOpts.includePageMarkers)) {
    const rawPdfSource = typeof item.markdown === 'string' && item.markdown ? item.markdown : rawCleanMarkdown;
    const splitPdf = splitPdfPagesAndMarkers(rawPdfSource, pdfParserOpts.includePageMarkers);
    if (pdfParserOpts.includePagesArray) {
      pdfPagesArray = splitPdf.pages;
    }
    if (pdfParserOpts.includePageMarkers && splitPdf.markedMarkdown) {
      markdown = finalizeScrapedMarkdown(splitPdf.markedMarkdown, {
        isPdf: true,
        includeImages,
        maxChars,
        baseUrl: finalUrl,
        allowPdfPageMarkers: true,
      }).markdown;
    }
  }

  const llmResolved =
    stringFormats.has('summary') || Boolean(jsonSchemaSpec)
      ? resolveLlmConfig({
          env: env as OptionalStorageBindings & LlmEnvBindings,
          requestLlm: payload.llm,
          selfHost,
        })
      : { ok: true as const, config: null };
  const activeLlmConfig = llmResolved.ok ? llmResolved.config : null;

  let summaryOut: string | undefined;
  if (stringFormats.has('summary')) {
    const sumRes = await summarizeMarkdownWithOptionalLlm({
      markdown: rawCleanMarkdown.slice(0, 32_768),
      title: resolvedTitle,
      llmConfig: activeLlmConfig,
      ...(activeTracer ? { tracer: activeTracer } : {}),
    });
    summaryOut = sumRes.summary;
  }

  let productOut: Record<string, unknown> | null = null;
  if (stringFormats.has('product')) {
    productOut = extractStructuredProduct({
      rawBody: rawBodyStr,
      finalUrl,
      fallbackTitle: resolvedTitle,
      fallbackDescription: resolvedDescription,
    });
  }

  const attributesOut =
    attributesSpec && isHtmlBody ? extractHtmlAttributesBySelectors(rawBodyStr, attributesSpec) : undefined;

  const rawBase64Out = rawBase64Requested ? encodeBodyToRawBase64(item) : undefined;

  const docForJson: ExtractedDocument | undefined = jsonSchemaSpec
    ? {
        markdown: rawCleanMarkdown,
        text: textOut || rawCleanMarkdown,
        title: resolvedTitle,
        description: resolvedDescription,
        language: extracted?.language,
        canonicalUrl: extracted?.canonicalUrl ?? finalUrl,
        favicon: (typeof item.favicon === 'string' && item.favicon) || extracted?.favicon,
        links: resolvedLinks as string[],
        images: resolvedImages as ScrapedImage[],
        branding: extracted?.branding ?? {
          title: resolvedTitle,
          description: resolvedDescription,
          canonicalUrl: extracted?.canonicalUrl ?? finalUrl,
        },
      }
    : undefined;

  let structuredJsonOut: Record<string, unknown> | undefined;
  if (jsonSchemaSpec && docForJson) {
    structuredJsonOut = extractStructuredJsonFromPage(rawBodyStr, docForJson, jsonSchemaSpec.schema);
    if (jsonFormatted?.parsed && typeof jsonFormatted.parsed === 'object' && !Array.isArray(jsonFormatted.parsed)) {
      const srcObj = jsonFormatted.parsed as Record<string, unknown>;
      const props =
        jsonSchemaSpec.schema && typeof jsonSchemaSpec.schema.properties === 'object' && jsonSchemaSpec.schema.properties !== null
          ? Object.keys(jsonSchemaSpec.schema.properties as Record<string, unknown>)
          : Object.keys(srcObj);
      const directPicked: Record<string, unknown> = {};
      for (const k of props) {
        if (k in srcObj && srcObj[k] !== undefined) {
          directPicked[k] = srcObj[k];
        }
      }
      structuredJsonOut = { ...structuredJsonOut, ...directPicked };
    }
    if (activeLlmConfig && (jsonSchemaSpec.prompt || jsonSchemaSpec.schema)) {
      const llmExt = await extractJsonWithOptionalLlm({
        markdown: rawCleanMarkdown,
        title: resolvedTitle,
        url: finalUrl,
        prompt: jsonSchemaSpec.prompt,
        schema: jsonSchemaSpec.schema,
        heuristicFallback: structuredJsonOut ?? {},
        llmConfig: activeLlmConfig,
        ...(activeTracer ? { tracer: activeTracer } : {}),
      });
      structuredJsonOut = llmExt.data;
    }
  }

  const art = item.artifact as { blobSha256?: string; contentSha256?: string } | undefined;
  let markdownArtifactId: string | undefined;
  if (shaped.truncated && env.ARTIFACTS && rawCleanMarkdown) {
    const usesUpgradedBody = Boolean(alternateMarkdownBody || ocrReportOut || structuredTextFormatted || contentSourceOut || htmlJobPosting);
    const mdContentSha =
      !usesUpgradedBody && art?.contentSha256 && isValidSha256Hex(art.contentSha256)
        ? art.contentSha256
        : await sha256HexString(rawCleanMarkdown);
    try {
      await env.ARTIFACTS.put(r2DerivedKey(SCRAPE_PIPELINE_VERSION, 'markdown', mdContentSha), rawCleanMarkdown, {
        httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
      });
      markdownArtifactId = `md:${mdContentSha}`;
    } catch {
      // Non-fatal if R2 derived cache write fails.
    }
  }

  const redirectAnalysis = analyzeUrlRedirect(normalizedUrl, finalUrl);
  const computedChanges = stringFormats.has('changes')
    ? computeMarkdownChanges(prevMarkdownForChanges, rawCleanMarkdown)
    : undefined;

  const actionOutputsObj =
    inlineActions.length > 0 ||
    Array.isArray(item.actionScreenshots) ||
    Array.isArray(item.actionScrapes) ||
    Array.isArray(item.javascriptReturns) ||
    typeof item.pdfBase64 === 'string'
      ? {
          ...(Array.isArray(item.actionScreenshots) ? { screenshots: item.actionScreenshots } : {}),
          ...(Array.isArray(item.actionScrapes) ? { scrapes: item.actionScrapes } : {}),
          ...(Array.isArray(item.javascriptReturns) ? { javascriptReturns: item.javascriptReturns } : {}),
          ...(typeof item.pdfBase64 === 'string' && item.pdfBase64 ? { pdfs: [item.pdfBase64] } : {}),
        }
      : undefined;

  const itemGlobals =
    (item.frameworkGlobals ?? item.globals) &&
    typeof (item.frameworkGlobals ?? item.globals) === 'object' &&
    !Array.isArray(item.frameworkGlobals ?? item.globals)
      ? ((item.frameworkGlobals ?? item.globals) as BrowserFrameworkGlobals)
      : undefined;
  const finalHeadersForDetect = readItemHeaders();
  const detectedStack = !isPdfResponse
    ? detectSiteFrameworkLinear({
        url: finalUrl,
        body: isOriginMarkdown || isHtmlBody ? rawBodyStr : '',
        ...(isOriginMarkdown ? { contentSource: 'origin-markdown' as const } : isHtmlBody ? { contentSource: 'html' as const } : {}),
        ...(finalHeadersForDetect ? { headers: finalHeadersForDetect } : {}),
        ...(itemGlobals ? { globals: itemGlobals } : {}),
      })
    : null;
  const hasDetectedStack = Boolean(
    detectedStack &&
      (detectedStack.platform ||
        detectedStack.framework ||
        detectedStack.generators.length > 0 ||
        (detectedStack.contentFlags && detectedStack.contentFlags.length > 0)),
  );

  const extractorIdOut = customCommerceId ?? extracted?.extractorId;
  if (extractorIdOut) {
    setActiveSpanAttribute('edgefetch.adapter_id', extractorIdOut, activeTracer ?? undefined);
  }
  const adapterRecordsOut = customShopifyDoc?.records ?? extracted?.records;
  const adapterPaginationOut = customShopifyDoc?.pagination ?? extracted?.pagination;
  const adapterTotalOut = customShopifyDoc?.total ?? extracted?.total;
  const adapterReturnedOut = customShopifyDoc?.returned ?? extracted?.returned;
  const adapterTruncatedOut = customShopifyDoc?.truncated ?? extracted?.truncated;
  const adapterNextCursorOut = customShopifyDoc?.nextCursor ?? extracted?.nextCursor;
  const resolvedAuthor = customShopifyDoc?.author ?? extracted?.author;
  const resolvedPublishedTime = customShopifyDoc?.publishedTime ?? extracted?.publishedTime ?? htmlJobPosting?.datePosted;

  const out: Record<string, unknown> = {
    ok: true,
    cached: false,
    pipelineVersion: SCRAPE_PIPELINE_VERSION,
    url: normalizedUrl,
    finalUrl,
    ...(redirectAnalysis.redirected ? redirectAnalysis : {}),
    status: item.status ?? 200,
    via: viaOut,
    ...(extractorIdOut ? { extractorId: extractorIdOut } : {}),
    ...(hasDetectedStack && detectedStack ? { detected: detectedStack } : {}),
    contentState: contentStateCheck.state,
    ...(contentStateCheck.reason ? { contentStateReason: contentStateCheck.reason } : {}),
    ...(contentSourceOut ? { contentSource: contentSourceOut } : {}),
    ...(renderedViaOut ? { renderedVia: renderedViaOut } : {}),
    ...(htmlJobPosting ? { jobPosting: htmlJobPosting } : {}),
    ...(adapterRecordsOut !== undefined ? { records: adapterRecordsOut } : {}),
    ...(adapterPaginationOut !== undefined ? { pagination: adapterPaginationOut } : {}),
    ...(adapterTotalOut !== undefined ? { total: adapterTotalOut } : {}),
    ...(adapterReturnedOut !== undefined ? { returned: adapterReturnedOut } : {}),
    ...(adapterTruncatedOut !== undefined ? { truncated: adapterTruncatedOut } : {}),
    ...(adapterNextCursorOut !== undefined ? { nextCursor: adapterNextCursorOut } : {}),
    ...(art?.contentSha256 ? { contentSha256: art.contentSha256 } : {}),
    ...(art?.blobSha256 ? { artifactId: art.blobSha256 } : {}),
    ...(markdownArtifactId ? { markdownArtifactId } : {}),
    ...(stringFormats.has('markdown') ? { markdown } : {}),
    ...(stringFormats.has('text') ? { text: textOut } : {}),
    ...(summaryOut !== undefined ? { summary: summaryOut } : {}),
    ...(productOut ? { product: productOut } : {}),
    ...(attributesOut ? { attributes: attributesOut } : {}),
    ...(rawBase64Out ? { rawBase64: rawBase64Out } : {}),
    ...(pdfPagesArray ? { pages: pdfPagesArray } : {}),
    ...(actionOutputsObj && Object.keys(actionOutputsObj).length > 0 ? { actions: actionOutputsObj } : {}),
    ...(focused.queryFiltered
      ? { queryFiltered: true, chunks: focused.chunks }
      : jsonRecordsFormatted
        ? {
            chunks: jsonRecordsFormatted.chunks,
            recordCount: jsonRecordsFormatted.matchedRecords,
            totalRecords: jsonRecordsFormatted.totalRecords,
          }
        : {}),
    ...(shaped.truncated || originMdCapTruncated
      ? {
          truncated: true,
          totalChars: shaped.totalChars ?? originMdOriginalChars,
          nextOffset: shaped.nextOffset ?? markdown.length,
        }
      : adapterTruncatedOut === true
        ? { truncated: true }
        : {}),
    ...(stringFormats.has('rawHtml') || stringFormats.has('html') ? { rawHtml: rawBodyStr, html: rawBodyStr } : {}),
    ...(stringFormats.has('links') ? { links: resolvedLinks } : {}),
    ...(stringFormats.has('images') ? { images: resolvedImages } : {}),
    ...(stringFormats.has('branding')
      ? {
          branding: (() => {
            const base = {
              ...(extracted?.branding ?? {}),
              ...(item.branding && typeof item.branding === 'object' ? (item.branding as Record<string, unknown>) : {}),
            };
            if (Array.isArray(base.fonts)) {
              const cleanFonts = base.fonts
                .filter((f): f is string => typeof f === 'string')
                .map((f) => f.trim().replace(/^["']|["']$/g, ''))
                .filter(
                  (f) =>
                    f &&
                    !/^var\s*\(/i.test(f) &&
                    !/^(sans-serif|serif|monospace|cursive|fantasy|inherit|initial|unset|revert|system-ui|ui-sans-serif|ui-serif|ui-monospace|-apple-system|blinkmacsystemfont)$/i.test(
                      f,
                    ),
                );
              if (cleanFonts.length > 0) base.fonts = [...new Set(cleanFonts)];
              else delete base.fonts;
            }
            return base;
          })(),
        }
      : {}),
    ...(structuredJsonOut ? { json: structuredJsonOut } : {}),
    ...(typeof item.screenshotBase64 === 'string' && item.screenshotBase64
      ? { screenshotBase64: item.screenshotBase64, screenshot: `data:image/png;base64,${item.screenshotBase64}` }
      : {}),
    ...(item.rendered === true || renderedViaOut !== undefined ? { rendered: true } : {}),
    ...(pdfEngineOut ? { pdfEngine: pdfEngineOut } : {}),
    ...(ocrReportOut ? { ocr: ocrReportOut } : {}),
    ...(computedChanges
      ? {
          changes: computedChanges,
          ...(changeTrackingSpec
            ? {
                changeTracking: {
                  changeStatus: computedChanges.status,
                  ...(changeTrackingSpec.tag ? { tag: changeTrackingSpec.tag } : {}),
                  ...(computedChanges.diffPreview ? { diff: { text: computedChanges.diffPreview } } : {}),
                },
              }
            : {}),
        }
      : {}),
    ...(llmsPayload ? { llms: llmsPayload, ...(stringFormats.has('llmsTxt') ? { llmsTxt: llmsPayload } : {}) } : {}),
    metadata: {
      title: resolvedTitle,
      description: resolvedDescription,
      ...(resolvedAuthor ? { author: resolvedAuthor } : {}),
      ...(resolvedPublishedTime ? { publishedTime: resolvedPublishedTime } : {}),
      ...(extracted?.modifiedTime ? { modifiedTime: extracted.modifiedTime } : {}),
      ...(extracted?.siteName || htmlJobPosting?.hiringOrganization
        ? { siteName: extracted?.siteName ?? htmlJobPosting?.hiringOrganization }
        : {}),
      ...(rawCleanMarkdown ? { wordCount: countTextWords(rawCleanMarkdown) } : {}),
      language: extracted?.language,
      favicon: (typeof item.favicon === 'string' && item.favicon) || extracted?.favicon,
      canonicalUrl: extracted?.canonicalUrl,
      ...(alternateMarkdownUrl ? { alternateMarkdownUrl } : {}),
      ...(contentSourceOut ? { contentSource: contentSourceOut } : {}),
      contentType: isPdfResponse ? 'application/pdf' : item.contentType,
    },
  };

  return { status: 200, via: viaOut, body: out };
  };
  return activeTracer ? activeTracer.run(runScrape) : runScrape();
}

export function extractYouTubeTranscriptFromHtml(rawHtml: string): string {
  if (!rawHtml) return '';
  const bounded = rawHtml.length > MAX_HTML_SCAN_CHARS ? rawHtml.slice(0, MAX_HTML_SCAN_CHARS) : rawHtml;
  const lower = bounded.toLowerCase();
  const segments: string[] = [];
  if (lower.includes('transcript-segment-view-model')) {
    replacePairedHtmlElementsLinear(
      bounded,
      ['transcript-segment-view-model'],
      (_full, _tag, _attrs, segInner) => {
        let roleText = '';
        replacePairedHtmlElementsLinear(
          segInner,
          ['span'],
          (_sf, _st, sAttrs, sInner) => {
            if (!roleText && /\brole\s*=\s*(?:"text"|'text')/i.test(sAttrs)) {
              roleText = sInner;
            }
            return '';
          },
          { maxChars: 4_096, maxInnerChars: 2_048 },
        );
        const cleaned = cleanInlineHtml(roleText || segInner);
        if (cleaned) segments.push(cleaned);
        return '';
      },
      { maxChars: MAX_HTML_SCAN_CHARS, maxInnerChars: 4_096 },
    );
  }
  if (segments.length === 0 && lower.includes('segment-text')) {
    replacePairedHtmlElementsLinear(
      bounded,
      ['yt-formatted-string'],
      (_full, _tag, attrStr, segInner) => {
        const cls = parseTagAttrs(attrStr).class ?? '';
        if (/\bsegment-text\b/i.test(cls)) {
          const cleaned = cleanInlineHtml(segInner);
          if (cleaned) segments.push(cleaned);
        }
        return '';
      },
      { maxChars: MAX_HTML_SCAN_CHARS, maxInnerChars: 4_096 },
    );
  }
  if (segments.length === 0) return '';
  return segments
    .join(' ')
    .replace(/\[(?:music|applause|laughter)\]/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export interface InteractRequestPayload {
  url?: unknown;
  sessionId?: unknown;
  keepSession?: unknown;
  closeSession?: unknown;
  actions?: unknown;
  formats?: unknown;
  waitForMs?: unknown;
  waitSelector?: unknown;
  site?: unknown;
}

function splitCompositeSessionId(raw: unknown): { siteId?: string; agentSessionId?: string; sigHex?: string; malformed?: boolean } {
  if (typeof raw !== 'string' || !raw.trim()) return {};
  const clean = raw.trim();
  const parts = clean.split('.');
  if (parts.length === 3) {
    const [sitePartRaw, sessPart, sigPart] = parts;
    const sitePart = sitePartRaw!.toLowerCase();
    if (
      /^[a-z0-9][a-z0-9_-]{0,31}$/.test(sitePart) &&
      /^[A-Za-z0-9_-]{4,80}$/.test(sessPart!) &&
      /^[0-9a-f]{24,64}$/i.test(sigPart!)
    ) {
      return { siteId: sitePart, agentSessionId: sessPart!, sigHex: sigPart!.toLowerCase() };
    }
    return { malformed: true };
  }
  if (parts.length === 2) {
    const [sitePartRaw, sessPart] = parts;
    const sitePart = sitePartRaw!.toLowerCase();
    if (/^[a-z0-9][a-z0-9_-]{0,31}$/.test(sitePart) && /^[A-Za-z0-9_-]{4,80}$/.test(sessPart!)) {
      return { siteId: sitePart, agentSessionId: sessPart! };
    }
    return { malformed: true };
  }
  if (/^[A-Za-z0-9_-]{4,80}$/.test(clean)) {
    return { agentSessionId: clean };
  }
  return { malformed: true };
}

function normalizeInteractPrincipal(principal?: string, source?: string): string {
  if (typeof principal === 'string' && principal.trim()) {
    return principal.trim();
  }
  const raw = (source ?? 'default').trim();
  const stripped = raw.replace(/^(?:mcp-interact|interact|mcp|compat|agent):/i, '').replace(/:interact$/i, '');
  return stripped || 'default';
}

const DEFAULT_INTERACT_HMAC_KEY_FALLBACK = 'edgefetch-default-interact-key';

async function computeInteractSessionMacHex(secret: string, principal: string, siteId: string, agentSessionId: string): Promise<string> {
  const enc = new TextEncoder();
  const effectiveSecret = secret.trim() || DEFAULT_INTERACT_HMAC_KEY_FALLBACK;
  const derivedKeyBytes = await crypto.subtle.digest('SHA-256', enc.encode(effectiveSecret));
  const key = await crypto.subtle.importKey('raw', derivedKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const macBuf = await crypto.subtle.sign('HMAC', key, enc.encode(`ef-interact-v1|${principal}|${siteId}|${agentSessionId}`));
  return Array.from(new Uint8Array(macBuf).subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Executes `POST /v1/interact` + MCP `interact` (`firecrawl_interact` parity) against a `browser-v1` (`edgefetch_fat`)
 * node. Composite `<siteId>.<efsess_id>[.<hmac32>]` tokens ensure follow-up turns route back to the exact node holding
 * the tab AND prevent cross-caller session hijacking on multi-client OAuth Hubs.
 */
export async function executeInteractCall(params: {
  payload: InteractRequestPayload;
  env: OptionalStorageBindings;
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: ArtifactRetention | 'off',
    hydrateInline?: boolean,
  ) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;
  source?: string;
  selfHost?: string;
  principal?: string;
  sessionSigningSecret?: string;
  tracer?: RequestTracer | TraceContext;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const activeTracer = getActiveRequestTracer(params.tracer);
  const runInteract = async (): Promise<{ status: number; via: string; body: Record<string, unknown> }> => {
  const { payload, env, executeHubFetch, source = 'interact', selfHost, principal, sessionSigningSecret } = params;
  const effectivePrincipal = normalizeInteractPrincipal(principal, source);
  const signingSecret =
    typeof sessionSigningSecret === 'string' && sessionSigningSecret.trim()
      ? sessionSigningSecret.trim()
      : DEFAULT_INTERACT_HMAC_KEY_FALLBACK;
  const parsedSession = splitCompositeSessionId(payload.sessionId);
  if (parsedSession.malformed) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_session_id', message: 'malformed interact sessionId' } };
  }
  if (parsedSession.agentSessionId) {
    if (!parsedSession.siteId || !parsedSession.sigHex) {
      return {
        status: 403,
        via: 'hub',
        body: { ok: false, error: 'session_principal_mismatch', message: 'interact sessionId is missing caller ownership signature' },
      };
    }
    const expectedSig = await computeInteractSessionMacHex(
      signingSecret,
      effectivePrincipal,
      parsedSession.siteId,
      parsedSession.agentSessionId,
    );
    if (!constantTimeHexEqual(parsedSession.sigHex, expectedSig)) {
      return {
        status: 403,
        via: 'hub',
        body: { ok: false, error: 'session_principal_mismatch', message: 'interact sessionId belongs to a different caller principal' },
      };
    }
    const resumedSessionHash = await sha256HexString(`${parsedSession.siteId.toLowerCase()}:${parsedSession.agentSessionId}`);
    setActiveSpanAttribute('edgefetch.interact.session_hash', resumedSessionHash, activeTracer ?? undefined);
  }
  const rawUrl = typeof payload.url === 'string' ? payload.url.trim() : '';

  let normalizedUrl = '';
  if (rawUrl) {
    const urlCheck = validatePublicHttpsTargetUrl(rawUrl, selfHost);
    if (!urlCheck.ok) {
      return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: urlCheck.message } };
    }
    normalizedUrl = urlCheck.normalized;
  } else if (!parsedSession.agentSessionId) {
    return {
      status: 400,
      via: 'hub',
      body: { ok: false, error: 'missing_url_or_session', message: 'provide url (new session) or sessionId (resume/close session)' },
    };
  }

  const parsedInteractActions = normalizeInlineBrowserActions(payload.actions, selfHost, 50);
  if (!parsedInteractActions.ok) {
    return {
      status: 400,
      via: 'hub',
      body: { ok: false, error: parsedInteractActions.message.includes('maximum') ? 'too_many_actions' : 'invalid_action', message: parsedInteractActions.message },
    };
  }
  const actions: Array<Record<string, unknown>> = parsedInteractActions.actions;
  const agentActions: Array<Record<string, unknown>> = [...parsedInteractActions.actions];
  setActiveSpanAttribute('edgefetch.interact.action_count', actions.length, activeTracer ?? undefined);
  if (normalizedUrl) {
    setActiveSpanAttribute('url.full', sanitizeUrlForSpan(normalizedUrl), activeTracer ?? undefined);
  }

  const topWaitForMs =
    typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
      ? Math.min(15_000, Math.max(0, Math.floor(payload.waitForMs)))
      : undefined;
  const topWaitSelector =
    typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
      ? payload.waitSelector.trim().slice(0, 200)
      : undefined;
  // Go's `Execute` only applies top-level `waitForMs`/`waitSelector` during initial `url` navigation before `actions`;
  // append a trailing settle wait when resuming a session (`!normalizedUrl`) or after running `actions`.
  if ((actions.length > 0 || !normalizedUrl) && (topWaitSelector || (topWaitForMs !== undefined && topWaitForMs > 0))) {
    agentActions.push({
      type: 'wait',
      ...(topWaitSelector ? { selector: topWaitSelector } : {}),
      waitMs: topWaitForMs ?? (topWaitSelector ? 5_000 : 900),
    });
  }

  const formats = Array.isArray(payload.formats)
    ? payload.formats.filter((f): f is string => typeof f === 'string')
    : ['markdown'];
  const keepSession = Boolean(payload.keepSession);
  const closeSession = Boolean(payload.closeSession);
  const explicitSite = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim().toLowerCase() : undefined;
  const pinnedSite = parsedSession.siteId ?? explicitSite;

  const call = {
    maxSeconds: 60,
    options: {
      includeBody: true,
      respectRobots: true,
      maxBytes: 16 * 1024 * 1024,
      timeoutMs: 45_000,
    },
    requests: [
      {
        id: 'interact-1',
        url: normalizedUrl,
        kind: 'render',
        renderMode: 'always',
        formats: formats.length > 0 ? formats : ['markdown'],
        ...(topWaitForMs !== undefined ? { waitForMs: topWaitForMs } : {}),
        ...(topWaitSelector ? { waitSelector: topWaitSelector } : {}),
        interact: {
          ...(parsedSession.agentSessionId ? { sessionId: parsedSession.agentSessionId } : {}),
          keepSession,
          closeSession,
          actions: agentActions,
        },
      },
    ],
  };

  const fetchRes = await executeHubFetch('agent', JSON.stringify(call), pinnedSite, source, env.ARTIFACTS ? 'transient' : undefined, true);
  if (fetchRes.status !== 200) {
    let errJson: Record<string, unknown> = { ok: false, error: 'interact_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    return { status: fetchRes.status, via: fetchRes.via, body: errJson };
  }

  const parsed = JSON.parse(fetchRes.bodyText) as { results?: Array<Record<string, unknown>> };
  const item = parsed.results?.[0] ?? {};
  const describeAction = (a: Record<string, unknown>, index: number, status: 'ok' | 'error' | 'skipped', error?: string) => ({
    index,
    type: String(a.type ?? ''),
    ...(typeof a.selector === 'string' ? { selector: a.selector } : {}),
    ...(typeof a.url === 'string' ? { url: a.url } : {}),
    status,
    ...(error ? { error } : {}),
  });

  if (item.outcome !== 'ok') {
    const isYouTubeUrl =
      Boolean(normalizedUrl) &&
      (() => {
        try {
          const h = new URL(normalizedUrl).hostname.toLowerCase();
          return h === 'youtube.com' || h.endsWith('.youtube.com') || h === 'youtu.be';
        } catch {
          return false;
        }
      })();
    // YouTube blocks headless Chromium (`HeadlessChrome`) with HTTP 401/403 while permitting polite plain HTTP watch-page
    // fetches (`ytInitialPlayerResponse.videoDetails`), so stateless metadata/transcript probes degrade gracefully to HTTP scrape.
    if (isYouTubeUrl && actions.length === 0 && !keepSession && !closeSession && !parsedSession.agentSessionId) {
      const ytFallback = await executeHubFetch(
        'auto',
        JSON.stringify({
          maxSeconds: 30,
          options: { includeBody: true, respectRobots: true, discoverLlms: false },
          requests: [{ id: 'yt-watch-1', url: normalizedUrl, kind: 'scrape', formats: ['markdown'], onlyMainContent: true, discoverLlms: false }],
        }),
        pinnedSite,
        `${source}:youtube-fallback`,
        env.ARTIFACTS ? 'transient' : undefined,
        true,
      );
      if (ytFallback.status === 200) {
        const ytParsed = JSON.parse(ytFallback.bodyText) as { results?: Array<Record<string, unknown>> };
        const ytItem = ytParsed.results?.[0];
        const ytRawHtml = typeof ytItem?.body === 'string' && ytItem.bodyEncoding !== 'base64' ? ytItem.body : '';
        if (ytItem?.outcome === 'ok' && ytRawHtml) {
          const ytDoc = extractHtmlDocument(ytRawHtml, { baseUrl: normalizedUrl, onlyMainContent: true });
          const ytTranscript = extractYouTubeTranscriptFromHtml(ytRawHtml);
          const requestedTranscript = formats.includes('transcript');
          const wantMarkdown = formats.includes('markdown');
          return {
            status: 200,
            via: ytFallback.via,
            body: {
              ok: true,
              via: ytFallback.via,
              finalUrl: normalizedUrl,
              status: ytItem.status ?? 200,
              rendered: false,
              actions: [],
              ...(wantMarkdown || (requestedTranscript && !ytTranscript) ? { markdown: ytDoc.markdown } : {}),
              ...(requestedTranscript ? { transcript: ytTranscript || null } : {}),
              ...(requestedTranscript && !ytTranscript
                ? {
                    formatWarnings: {
                      transcript:
                        'YouTube blocks headless Chromium (HTTP 401) and disallows /api/timedtext in robots.txt; returning extracted watch-page title, channel, duration, and description.',
                    },
                  }
                : {}),
              metadata: { title: ytDoc.title },
            },
          };
        }
      }
    }

    const prob = String(item.problem ?? 'Browser interact step failed');
    const actFail = /interact action (\d+) \(([^)]+)\):\s*(.+)/i.exec(prob);
    const failedIdx = actFail ? Number(actFail[1]) : -1;
    const failedDetail = actFail?.[3]?.trim() ?? prob;
    const actionResults =
      failedIdx >= 0 && actions.length > 0
        ? actions.map((a, idx) =>
            idx < failedIdx
              ? describeAction(a, idx, 'ok')
              : idx === failedIdx
                ? describeAction(a, idx, 'error', failedDetail)
                : describeAction(a, idx, 'skipped'),
          )
        : undefined;

    // P8 & P10: Surface any partial rendered DOM/Markdown/transcript captured before the failed action + structured `blocked` guidance!
    const partialHtml = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
    const partialFinalUrl = typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : normalizedUrl;
    const partialDoc = partialHtml ? extractHtmlDocument(partialHtml, { baseUrl: partialFinalUrl || undefined, onlyMainContent: true }) : undefined;
    const partialTranscript = partialHtml ? extractYouTubeTranscriptFromHtml(partialHtml) : '';
    const partialMd = partialDoc?.markdown ? partialDoc.markdown.trim() : '';
    const errSiteMatch = /^agent:(?:[a-z0-9_-]+\+)*([a-z0-9_-]+)/i.exec(fetchRes.via);
    const errActualSite = (errSiteMatch?.[1] ?? pinnedSite ?? 'default').toLowerCase();
    const errAgentSid = typeof item.sessionId === 'string' && item.sessionId ? item.sessionId : undefined;
    if (errAgentSid) {
      const errSessionHash = await sha256HexString(`${errActualSite}:${errAgentSid}`);
      setActiveSpanAttribute('edgefetch.interact.session_hash', errSessionHash, activeTracer ?? undefined);
    }
    const errSig = errAgentSid
      ? await computeInteractSessionMacHex(signingSecret, effectivePrincipal, errActualSite, errAgentSid)
      : undefined;
    const errPublicSid = errAgentSid && errSig ? `${errActualSite}.${errAgentSid}.${errSig}` : errAgentSid;
    const blockedInfo = refineBlockedInfo({
      url: partialFinalUrl || normalizedUrl,
      outcome: item.outcome,
      problem: prob,
      status: item.status,
      retryAfter: typeof item.retryAfter === 'string' ? item.retryAfter : fetchRes.retryAfter,
      baseBlocked: buildBlockedInfo(partialFinalUrl || normalizedUrl, item.outcome, prob, item.status),
    });

    return {
      status: item.outcome === 'challenge' ? 403 : 422,
      via: fetchRes.via,
      body: {
        ok: false,
        outcome: item.outcome ?? 'error',
        status: item.status ?? 0,
        problem: prob,
        ...(partialFinalUrl ? { finalUrl: partialFinalUrl } : {}),
        ...(errPublicSid ? { sessionId: errPublicSid } : {}),
        ...(actionResults ? { actions: actionResults } : {}),
        ...(partialMd && formats.includes('markdown') ? { markdown: partialMd, partial: true } : {}),
        ...(partialTranscript && formats.includes('transcript') ? { transcript: partialTranscript, partial: true } : {}),
        ...(partialHtml && (formats.includes('html') || formats.includes('rawHtml')) ? { html: partialHtml } : {}),
        ...(partialDoc?.title ? { metadata: { title: partialDoc.title } } : {}),
        ...(blockedInfo ? { blocked: blockedInfo } : {}),
      },
    };
  }

  const siteMatch = /^agent:(?:[a-z0-9_-]+\+)*([a-z0-9_-]+)/i.exec(fetchRes.via);
  const actualSite = (siteMatch?.[1] ?? pinnedSite ?? 'default').toLowerCase();
  const returnedAgentSid = typeof item.sessionId === 'string' && item.sessionId ? item.sessionId : undefined;
  if (returnedAgentSid) {
    const okSessionHash = await sha256HexString(`${actualSite}:${returnedAgentSid}`);
    setActiveSpanAttribute('edgefetch.interact.session_hash', okSessionHash, activeTracer ?? undefined);
  }
  const sessionSig = returnedAgentSid
    ? await computeInteractSessionMacHex(signingSecret, effectivePrincipal, actualSite, returnedAgentSid)
    : undefined;
  const publicSessionId = returnedAgentSid && sessionSig ? `${actualSite}.${returnedAgentSid}.${sessionSig}` : returnedAgentSid;

  const rawHtml = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
  const finalUrl = typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : normalizedUrl;
  const interactRedirect = normalizedUrl ? analyzeUrlRedirect(normalizedUrl, finalUrl) : { redirected: false };
  const wantMarkdown = formats.includes('markdown');
  const requestedTranscript = formats.includes('transcript');
  const extracted = rawHtml ? extractHtmlDocument(rawHtml, { baseUrl: finalUrl || undefined, onlyMainContent: true }) : undefined;
  const transcript = (requestedTranscript || wantMarkdown) && rawHtml ? extractYouTubeTranscriptFromHtml(rawHtml) : '';
  let markdown =
    extracted?.markdown ||
    (typeof item.markdown === 'string' && item.markdown ? sanitizeInlineHtmlInMarkdown(item.markdown, finalUrl || undefined).trim() : '');
  if (wantMarkdown && transcript && !/^#{2,3}\s*Transcript\b/im.test(markdown)) {
    const cleanTranscript = sanitizeInlineHtmlInMarkdown(transcript, finalUrl || undefined).trim();
    if (cleanTranscript) {
      markdown = markdown ? `${markdown}\n\n## Transcript\n\n${cleanTranscript}` : `## Transcript\n\n${cleanTranscript}`;
    }
  }
  const fallbackTitle =
    !extracted && rawHtml
      ? (() => {
          let t: string | undefined;
          replacePairedHtmlElementsLinear(
            rawHtml,
            ['title'],
            (_f, _tag, _a, inner) => {
              if (t === undefined) t = cleanInlineHtml(inner);
              return '';
            },
            { maxChars: MAX_HTML_SCAN_CHARS, maxInnerChars: 4_096 },
          );
          return t;
        })()
      : undefined;
  const actionResults = actions.map((a, idx) => describeAction(a, idx, 'ok'));
  const formatWarnings: Record<string, string> = {};
  if (requestedTranscript && !transcript) {
    formatWarnings.transcript = 'No timed caption/transcript segments found on page; returning extracted page Markdown.';
  }

  return {
    status: 200,
    via: fetchRes.via,
    body: {
      ok: true,
      via: fetchRes.via,
      ...(finalUrl ? { finalUrl } : {}),
      ...(interactRedirect.redirected ? interactRedirect : {}),
      status: item.status ?? 200,
      rendered: true,
      ...(publicSessionId ? { sessionId: publicSessionId } : {}),
      ...(closeSession ? { closed: true } : {}),
      actions: actionResults,
      ...(wantMarkdown || (requestedTranscript && !transcript) ? { markdown } : {}),
      ...(requestedTranscript ? { transcript: transcript || null } : transcript ? { transcript } : {}),
      ...(Object.keys(formatWarnings).length > 0 ? { formatWarnings } : {}),
      ...(formats.includes('html') || formats.includes('rawHtml') ? { html: rawHtml } : {}),
      ...(typeof item.screenshotBase64 === 'string' && item.screenshotBase64 ? { screenshotBase64: item.screenshotBase64 } : {}),
      metadata: {
        title: extracted?.title || (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined) || fallbackTitle,
      },
    },
  };
  };
  return activeTracer ? activeTracer.run(runInteract) : runInteract();
}
