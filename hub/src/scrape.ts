/**
 * Markdown derivation pipeline (`SCRAPE_PIPELINE_VERSION = 1`), `llms.txt` parser, `maxAgeMs` verified cache lookup,
 * and `POST /v1/scrape` + MCP `scrape` execution (`PR S6`).
 *
 * Security Invariants:
 *  - `deriveMarkdownDocument` NEVER reuses or derives from unverified artifacts (`isContentVerifiedInMetaD1` must be true).
 *  - Derived outputs are stored deterministically at `derived/<pipelineVersion>/markdown/<contentSha256>` in `ARTIFACTS` R2
 *    and tracked in `META` D1 `documents` with `(content_sha256, format, pipeline_version)` uniqueness.
 */

import { applyPostFetchSiteExtractor, resolveSiteExtractorTwin } from './extractors/registry';
import { isContentVerifiedInMetaD1, sha256HexString } from './ingest';
import { computeMarkdownChanges } from './map-crawl';
import { validatePublicHttpsTargetUrl } from './overflow';
import { chunkMarkdownForSearch, rankChunksInMemory } from './search-index';
import {
  isValidSha256Hex,
  r2DerivedKey,
  readVerifiedArtifactFromR2,
  type ArtifactRetention,
  type OptionalStorageBindings,
} from './storage';

export const SCRAPE_PIPELINE_VERSION = 20;

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

/**
 * Splits Markdown into alternating `[prose, codeFence, prose, codeFence, ...]` segments (`idx % 2 === 1` is always a
 * fenced code block) while honoring CommonMark variable-length backtick (```` ``` ````, ```` ```` ````) and tilde
 * (`~~~`, `~~~~`) fences so outer 4-char fences wrapping inner 3-backtick blocks never split prematurely.
 */
export function splitMarkdownByCodeFences(md: string): string[] {
  if (!md || (!md.includes('```') && !md.includes('~~~'))) {
    return [md];
  }
  const out: string[] = [];
  let inFence = false;
  let fenceChar = '';
  let fenceLen = 0;
  let segStart = 0;
  let pos = 0;
  const len = md.length;

  while (pos < len) {
    const nl = md.indexOf('\n', pos);
    const nextPos = nl === -1 ? len : nl + 1;
    const lineRawEnd = nl === -1 ? len : nl > pos && md[nl - 1] === '\r' ? nl - 1 : nl;
    const rawLine = md.slice(pos, lineRawEnd);
    const trimmedStart = rawLine.replace(/^[ ]{0,3}/, '');

    if (!inFence) {
      const openMatch = /^(`{3,}|~{3,})(.*)$/.exec(trimmedStart);
      if (openMatch && !(openMatch[1]![0] === '`' && openMatch[2]!.includes('`'))) {
        out.push(md.slice(segStart, pos));
        inFence = true;
        fenceChar = openMatch[1]![0]!;
        fenceLen = openMatch[1]!.length;
        segStart = pos;
      }
    } else {
      const closeMatch = /^(`{3,}|~{3,})[ \t]*$/.exec(trimmedStart);
      if (closeMatch && closeMatch[1]![0] === fenceChar && closeMatch[1]!.length >= fenceLen) {
        out.push(md.slice(segStart, lineRawEnd));
        inFence = false;
        fenceChar = '';
        fenceLen = 0;
        segStart = lineRawEnd;
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

/** Normalizes Poppler / OCR PDF layout whitespace (column-alignment spaces and line-wrap hyphenations). */
export function cleanPdfMarkdown(md: string): string {
  if (!md) return md;
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
  const parts = splitMarkdownByCodeFences(md);
  return parts
    .map((part, idx) => {
      if (idx % 2 === 1) return part;
      return part
        .replace(/([A-Za-z0-9]+)-\r?\n[ \t]*([A-Za-z]+)/g, (_m, left: string, right: string) => {
          if (/\d$/.test(left) || /^[A-Z]/.test(right) || compoundPrefixes.has(left.toLowerCase())) {
            return `${left}-${right}`;
          }
          return `${left}${right}`;
        })
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

function parseTagAttrs(tag: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(tag)) !== null) {
    const key = m[1]!.toLowerCase();
    if (!(key in attrs)) {
      attrs[key] = decodeHtmlEntities(m[2] ?? m[3] ?? m[4] ?? '');
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

const HTML_TAG_QUOTE_AWARE_RE = /<\/?[A-Za-z!][A-Za-z0-9:-]*(?:"[^"]*"|'[^']*'|[^>"'])*\/?>/g;

function collapseTagBoundaryPunctuation(s: string): string {
  return s
    .replace(/(?<!\[) +([,.;:!?)\]}])(?=\s|$|[,.;:!?)\]}])/g, '$1')
    .replace(/ +([’'](?:s|t|re|ve|ll|d|m)\b)/gi, '$1')
    .replace(/\( +(?=[^\s)])/g, '(')
    .replace(/\[\s+(\d{1,4})\s*\]/g, '[$1]');
}

function cleanInlineHtml(fragment: string): string {
  return collapseTagBoundaryPunctuation(
    decodeHtmlEntities(fragment.replace(/<wbr\b[^>]*\/?>/gi, '').replace(HTML_TAG_QUOTE_AWARE_RE, ' '))
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

  const classes = `${codeAttrs.class ?? ''} ${preAttrs.class ?? ''}`;
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

export function redactPiiText(text: string): string {
  return text
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    .replace(/(?<![0-9A-Za-z-])(?:\+?1[-.\s]?)?(?:\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}|\d{3}[-.\s]\d{3}[-.\s]\d{4})\b/g, '[REDACTED_PHONE]');
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
]);

/** Extracts the inner HTML of a balanced `<div|section ... role="main">` landmark when `<main>` and `<article>` are absent. */
function extractBalancedRoleMainHtml(html: string): string | null {
  const openMatch =
    /<(div|section)\b(?:"[^"]*"|'[^']*'|[^>"'])*\brole\s*=\s*(?:"main"|'main'|main)(?=[\s/>])(?:"[^"]*"|'[^']*'|[^>"'])*>/i.exec(
      html,
    );
  if (!openMatch || openMatch.index === undefined) return null;
  const tagName = openMatch[1]!.toLowerCase();
  const contentStart = openMatch.index + openMatch[0].length;
  const tagRe = new RegExp(`<\\/?${tagName}\\b(?:"[^"]*"|'[^']*'|[^>"'])*\\/?>`, 'gi');
  tagRe.lastIndex = contentStart;
  let depth = 1;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(html)) !== null) {
    const rawTag = m[0];
    if (rawTag.startsWith('</')) {
      depth--;
      if (depth === 0) {
        return html.slice(contentStart, m.index);
      }
    } else if (!rawTag.endsWith('/>')) {
      depth++;
    }
  }
  return null;
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
  if (
    /\bstyle\s*=/i.test(strippedQuotes) &&
    /\bstyle\s*=\s*(?:"(?:[^"]*;)?\s*display\s*:\s*none\b[^"]*"|'(?:[^']*;)?\s*display\s*:\s*none\b[^']*')/i.test(attrStr) &&
    !/\b(?:mwe-math|katex-mathml|mjx-assistive)\b/i.test(attrStr)
  ) {
    return true;
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

/** O(N) quote-aware balanced tag scanner that removes hidden (`.d-none`, `[hidden]`, `display:none`) and WAI-ARIA nav/chrome subtrees. */
function stripHiddenAndChromeSubtrees(html: string): string {
  const tagScanRe = /<\/?([A-Za-z][A-Za-z0-9:-]*)\b((?:"[^"]*"|'[^']*'|[^>"'])*)\/?>/g;
  const chunks: string[] = [];
  let lastKeepIdx = 0;
  let skipTag = '';
  let skipDepth = 0;
  let skipStartIdx = 0;
  let m: RegExpExecArray | null;
  while ((m = tagScanRe.exec(html)) !== null) {
    const fullTag = m[0];
    const tagLower = m[1]!.toLowerCase();
    const isClosing = fullTag.charCodeAt(1) === 0x2f; // '/'
    const isSelfClosing = !isClosing && (VOID_HTML_TAGS.has(tagLower) || fullTag.endsWith('/>'));

    if (skipDepth > 0) {
      if (tagLower === skipTag) {
        if (isClosing) {
          skipDepth--;
          if (skipDepth === 0) {
            lastKeepIdx = m.index + fullTag.length;
          }
        } else if (!isSelfClosing) {
          skipDepth++;
        }
      }
      continue;
    }

    if (!isClosing && shouldStripSubtreeOpenTag(tagLower, m[2] ?? '')) {
      chunks.push(html.slice(lastKeepIdx, m.index));
      if (isSelfClosing) {
        lastKeepIdx = m.index + fullTag.length;
      } else {
        skipTag = tagLower;
        skipDepth = 1;
        skipStartIdx = m.index;
      }
    }
  }

  if (chunks.length === 0 && skipDepth === 0) return html;
  if (skipDepth > 0) {
    // Unclosed malformed tag: preserve tail from `skipStartIdx` so broken HTML never truncates prose.
    chunks.push(html.slice(skipStartIdx));
  } else if (lastKeepIdx < html.length) {
    chunks.push(html.slice(lastKeepIdx));
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
  for (const m of rawHtml.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      visit(JSON.parse(m[1]!.trim()), 0);
    } catch {
      // ignore malformed JSON-LD blocks
    }
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

/** Applies Firecrawl-compatible `includeTags` and `excludeTags` (`tag`, `#id`, `.class`) using O(N) balanced subtree scanning. */
function applyIncludeAndExcludeTagSelectors(
  html: string,
  includeTags?: readonly string[],
  excludeTags?: readonly string[],
): string {
  let out = html;
  const parsedInclude = parseSimpleSelectorList(includeTags);
  if (parsedInclude.length > 0) {
    const tagScanRe = /<\/?([A-Za-z][A-Za-z0-9:-]*)\b((?:"[^"]*"|'[^']*'|[^>"'])*)\/?>/g;
    const kept: string[] = [];
    let matchTag = '';
    let matchDepth = 0;
    let matchStart = 0;
    let m: RegExpExecArray | null;
    while ((m = tagScanRe.exec(out)) !== null) {
      const fullTag = m[0];
      const tagLower = m[1]!.toLowerCase();
      const isClosing = fullTag.charCodeAt(1) === 0x2f;
      const isSelfClosing = !isClosing && (VOID_HTML_TAGS.has(tagLower) || fullTag.endsWith('/>'));
      if (matchDepth > 0) {
        if (tagLower === matchTag) {
          if (isClosing) {
            matchDepth--;
            if (matchDepth === 0) {
              kept.push(out.slice(matchStart, m.index + fullTag.length));
            }
          } else if (!isSelfClosing) {
            matchDepth++;
          }
        }
        continue;
      }
      if (!isClosing && tagMatchesSimpleSelectors(tagLower, m[2] ?? '', parsedInclude)) {
        if (isSelfClosing) {
          kept.push(fullTag);
        } else {
          matchTag = tagLower;
          matchDepth = 1;
          matchStart = m.index;
        }
      }
    }
    if (matchDepth > 0) kept.push(out.slice(matchStart));
    if (kept.length > 0) {
      out = kept.join('\n\n');
    }
  }

  const parsedExclude = parseSimpleSelectorList(excludeTags);
  if (parsedExclude.length > 0) {
    const tagScanRe = /<\/?([A-Za-z][A-Za-z0-9:-]*)\b((?:"[^"]*"|'[^']*'|[^>"'])*)\/?>/g;
    const chunks: string[] = [];
    let lastKeepIdx = 0;
    let skipTag = '';
    let skipDepth = 0;
    let skipStartIdx = 0;
    let m: RegExpExecArray | null;
    while ((m = tagScanRe.exec(out)) !== null) {
      const fullTag = m[0];
      const tagLower = m[1]!.toLowerCase();
      const isClosing = fullTag.charCodeAt(1) === 0x2f;
      const isSelfClosing = !isClosing && (VOID_HTML_TAGS.has(tagLower) || fullTag.endsWith('/>'));
      if (skipDepth > 0) {
        if (tagLower === skipTag) {
          if (isClosing) {
            skipDepth--;
            if (skipDepth === 0) lastKeepIdx = m.index + fullTag.length;
          } else if (!isSelfClosing) {
            skipDepth++;
          }
        }
        continue;
      }
      if (!isClosing && tagMatchesSimpleSelectors(tagLower, m[2] ?? '', parsedExclude)) {
        chunks.push(out.slice(lastKeepIdx, m.index));
        if (isSelfClosing) {
          lastKeepIdx = m.index + fullTag.length;
        } else {
          skipTag = tagLower;
          skipDepth = 1;
          skipStartIdx = m.index;
        }
      }
    }
    if (chunks.length > 0 || skipDepth > 0) {
      if (skipDepth > 0) chunks.push(out.slice(skipStartIdx));
      else if (lastKeepIdx < out.length) chunks.push(out.slice(lastKeepIdx));
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

  const scriptTagMatch = /<script\b[^>]*\bid=(?:"preloads-json"|'preloads-json')[^>]*>([\s\S]*?)<\/script>/i.exec(rawHtml);
  if (scriptTagMatch?.[1]) {
    try {
      const res = readFromData(JSON.parse(scriptTagMatch[1]));
      if (res) return res;
    } catch {
      // fall through
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

function hnFragmentToMarkdown(fragHtml: string, baseUrl: string): string {
  const codeBlocks: string[] = [];
  let s = fragHtml
    .replace(/<div\b[^>]*\breply\b[^>]*>[\s\S]*?<\/div>/gi, '')
    .replace(/<pre\b[^>]*>\s*(?:<code\b[^>]*>)?([\s\S]*?)(?:<\/code>)?\s*<\/pre>/gi, (_m, code: string) => {
      const clean = decodeHtmlEntities(code.replace(HTML_TAG_QUOTE_AWARE_RE, '')).trimEnd();
      const idx = codeBlocks.push(`\n\n${makeSafeCodeFence(clean)}\n\n`) - 1;
      return `\u0000HNCODE${idx}\u0000`;
    })
    .replace(/<code\b[^>]*>([\s\S]*?)<\/code>/gi, (_m, c: string) => {
      const span = formatInlineCodeSpan(cleanInlineHtml(c));
      if (!span) return '';
      const idx = codeBlocks.push(span) - 1;
      return `\u0000HNCODE${idx}\u0000`;
    })
    .replace(/<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/gi, (_m, attrStr: string, inner: string) => {
      const attrs = parseTagAttrs(attrStr);
      const href = resolveHttpsHref(attrs.href, baseUrl, true);
      const label = cleanInlineHtml(inner);
      if (!label) return href ?? '';
      return href ? `[${label}](${href})` : label;
    })
    .replace(/<(?:i|em)\b[^>]*>([\s\S]*?)<\/(?:i|em)>/gi, (_m, inner: string) => {
      const t = cleanInlineHtml(inner);
      return t ? `*${t}*` : '';
    })
    .replace(/<p\b[^>]*>/gi, '\n\n')
    .replace(/<\/p>/gi, '')
    .replace(/<br\b[^>]*\/?>/gi, '\n')
    .replace(HTML_TAG_QUOTE_AWARE_RE, '');

  s = decodeHtmlEntities(s)
    .split('\n')
    .map((l) => l.replace(/[ \t]{2,}/g, ' ').trim())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  return s.replace(/\u0000HNCODE(\d+)\u0000/g, (_m, idx: string) => codeBlocks[Number(idx)] ?? '');
}

function extractHackerNewsMarkdown(
  rawHtml: string,
  baseUrl?: string,
): { title?: string; author?: string; publishedTime?: string; markdown: string; links: string[] } | null {
  let isHnHost = false;
  if (baseUrl) {
    try {
      isHnHost = /^(?:www\.)?news\.ycombinator\.com$/i.test(new URL(baseUrl).hostname);
    } catch {
      isHnHost = false;
    }
  }
  if (!isHnHost && !/<table\b[^>]*\bid=(?:"hnmain"|'hnmain')/i.test(rawHtml)) {
    return null;
  }
  const hnBase = baseUrl || 'https://news.ycombinator.com/';
  const links: string[] = [];
  const addLink = (rawHref: string | undefined) => {
    const r = resolveHttpsHref(rawHref, hnBase, false);
    if (r && !links.includes(r) && links.length < 250) links.push(r);
    return r;
  };

  const fatMatch = /<table\b[^>]*\bfatitem\b[^>]*>([\s\S]{1,80000}?)<\/table>/i.exec(rawHtml);
  if (fatMatch?.[1]) {
    const fat = fatMatch[1];
    const titleLink = /<span\b[^>]*\btitleline\b[^>]*>\s*<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/i.exec(fat);
    const onStoryLink = /<span\b[^>]*\bonstory\b[^>]*>[\s\S]*?<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/i.exec(fat);
    const authorMatch = /<a\b[^>]*\bhref=(?:"user\?id=([^"&]+)"|'user\?id=([^'&]+)')[^>]*>([\s\S]*?)<\/a>/i.exec(fat);
    const author = authorMatch ? cleanInlineHtml(authorMatch[3]!) : undefined;
    const ageTitleMatch = /<span\b[^>]*\bage\b[^>]*\btitle=(?:"([^"]+)"|'([^']+)')/i.exec(fat);
    const rawIso = (ageTitleMatch?.[1] ?? ageTitleMatch?.[2] ?? '').split(' ')[0]?.trim() || undefined;
    const dateShort = rawIso ? rawIso.split('T')[0] : undefined;
    const scoreMatch = /<span\b[^>]*\bscore\b[^>]*>([\s\S]*?)<\/span>/i.exec(fat);
    const score = scoreMatch ? cleanInlineHtml(scoreMatch[1]!) : '';

    const sections: string[] = [];
    let outTitle: string | undefined;

    if (titleLink) {
      const tAttrs = parseTagAttrs(titleLink[1]!);
      const storyUrl = addLink(tAttrs.href);
      outTitle = cleanInlineHtml(titleLink[2]!);
      sections.push(storyUrl ? `# [${outTitle}](${storyUrl})` : `# ${outTitle}`);
      const metaBits = [score, author ? `by ${author}` : '', dateShort ?? ''].filter(Boolean);
      if (metaBits.length > 0) sections.push(`*${metaBits.join(' · ')}*`);
      const topTextMatch = /<div\b[^>]*\btoptext\b[^>]*>([\s\S]*?)<\/div>/i.exec(fat);
      if (topTextMatch?.[1]) {
        const topMd = hnFragmentToMarkdown(topTextMatch[1], hnBase);
        if (topMd) sections.push(topMd);
      }
    } else {
      const storyTitle = onStoryLink ? cleanInlineHtml(onStoryLink[2]!) : 'Hacker News Thread';
      const storyHref = onStoryLink ? addLink(parseTagAttrs(onStoryLink[1]!).href) : undefined;
      outTitle = storyTitle;
      sections.push(`# ${storyTitle}`);
      const metaBits = [
        author ? `Comment by **${author}**` : '',
        dateShort ?? '',
        storyHref ? `on [${storyTitle}](${storyHref})` : '',
      ].filter(Boolean);
      if (metaBits.length > 0) sections.push(metaBits.join(' · '));
      const mainCommMatch = /<div\b[^>]*\bcommtext\b[^>]*>([\s\S]*?)<\/div>\s*<div\b[^>]*\breply\b/i.exec(fat) ??
        /<span\b[^>]*\bcommtext\b[^>]*>([\s\S]*?)<\/span>/i.exec(fat);
      if (mainCommMatch?.[1]) {
        const bodyMd = hnFragmentToMarkdown(mainCommMatch[1], hnBase);
        if (bodyMd) sections.push(bodyMd);
      }
    }

    const commentItems: string[] = [];
    const seenIds = new Set<string>();
    const afterFat = rawHtml.slice((fatMatch.index ?? 0) + fatMatch[0].length);
    for (const cm of afterFat.matchAll(/<tr\b([^>]*\bcomtr\b[^>]*)>([\s\S]{1,24000}?)<\/tr>/gi)) {
      const trAttrs = parseTagAttrs(cm[1]!);
      const cid = trAttrs.id ?? '';
      if (cid && seenIds.has(cid)) continue;
      if (cid) seenIds.add(cid);
      const rowHtml = cm[2]!;
      if (/\bnoshow\b/i.test(cm[1]!)) continue;
      const indWidth = /<td\b[^>]*\bind\b[^>]*>[\s\S]{0,160}?<img\b[^>]*\bwidth=(?:"(\d+)"|'(\d+)'|(\d+))/i.exec(rowHtml);
      const px = Number(indWidth?.[1] ?? indWidth?.[2] ?? indWidth?.[3] ?? '0') || 0;
      const depth = Math.min(5, Math.max(0, Math.round(px / 40)));
      const cAuthorMatch =
        /<a\b[^>]*\bhref=(?:"user\?id=([^"&]+)"|'user\?id=([^'&]+)')[^>]*>([\s\S]*?)<\/a>/i.exec(rowHtml) ??
        /<a\b[^>]*\bclass=(?:"[^"]*\bhnuser\b[^"]*"|'[^']*\bhnuser\b[^']*')[^>]*>()()([\s\S]*?)<\/a>/i.exec(rowHtml);
      const cAuthor = cAuthorMatch ? cleanInlineHtml(cAuthorMatch[3]!) : '[deleted]';
      const cAgeMatch = /<span\b[^>]*\bage\b[^>]*\btitle=(?:"([^"]+)"|'([^']+)')/i.exec(rowHtml);
      const cDate = (cAgeMatch?.[1] ?? cAgeMatch?.[2] ?? '').split('T')[0] ?? '';
      const commMatch =
        /<div\b[^>]*\bcommtext\b[^>]*>([\s\S]*?)<\/div>\s*<div\b[^>]*\breply\b/i.exec(rowHtml) ??
        /<div\b[^>]*\bcommtext\b[^>]*>([\s\S]*?)<\/div>/i.exec(rowHtml) ??
        /<span\b[^>]*\bcommtext\b[^>]*>([\s\S]*?)<\/span>/i.exec(rowHtml);
      if (!commMatch?.[1]) continue;
      const cBody = hnFragmentToMarkdown(commMatch[1], hnBase);
      if (!cBody || cBody === '[dead]' || cBody === '[flagged]') continue;
      const indent = '  '.repeat(depth);
      const indentedBody = cBody
        .split('\n')
        .map((line, idx) => (idx === 0 ? line : line ? `${indent}  ${line}` : ''))
        .join('\n');
      const header = cDate ? `**${cAuthor}** *(${cDate})*` : `**${cAuthor}**`;
      commentItems.push(`${indent}- ${header}: ${indentedBody}`);
      if (commentItems.length >= 120) break;
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

  // Hacker News story listing page (`news`, `newest`, `ask`, `show`, `front`)
  const listingItems: string[] = [];
  const rowPairsRe =
    /<tr\b([^>]*\bathing\b[^>]*)>([\s\S]{1,4000}?)<\/tr>\s*<tr>([\s\S]{1,3000}?)<\/tr>/gi;
  for (const sm of rawHtml.matchAll(rowPairsRe)) {
    const rowAttrs = parseTagAttrs(sm[1]!);
    const id = rowAttrs.id ?? '';
    const tMatch = /<span\b[^>]*\btitleline\b[^>]*>\s*<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/i.exec(sm[2]!);
    if (!tMatch) continue;
    const storyTitle = cleanInlineHtml(tMatch[2]!);
    const storyHref = addLink(parseTagAttrs(tMatch[1]!).href);
    const siteMatch = /<span\b[^>]*\bsitestr\b[^>]*>([\s\S]*?)<\/span>/i.exec(sm[2]!);
    const siteStr = siteMatch ? cleanInlineHtml(siteMatch[1]!) : '';
    const subHtml = sm[3]!;
    const pts = cleanInlineHtml(/<span\b[^>]*\bscore\b[^>]*>([\s\S]*?)<\/span>/i.exec(subHtml)?.[1] ?? '');
    const byUser = cleanInlineHtml(
      /<a\b[^>]*\bhref=(?:"user\?id=[^"]+"|'user\?id=[^']+')[^>]*>([\s\S]*?)<\/a>/i.exec(subHtml)?.[1] ??
        /<a\b[^>]*\bclass=(?:"hnuser"|'hnuser')[^>]*>([\s\S]*?)<\/a>/i.exec(subHtml)?.[1] ??
        '',
    );
    const commLinks = [...subHtml.matchAll(/<a\b[^>]*>([\s\S]*?)<\/a>/gi)];
    const lastText = commLinks.length > 0 ? cleanInlineHtml(commLinks[commLinks.length - 1]![1]!) : '';
    const commentsPart =
      id && /\bcomment|\bdiscuss/i.test(lastText)
        ? `[${lastText}](${addLink(`https://news.ycombinator.com/item?id=${id}`)})`
        : '';
    const meta = [pts, byUser ? `by ${byUser}` : '', commentsPart].filter(Boolean).join(' · ');
    const head = storyHref ? `**[${storyTitle}](${storyHref})**` : `**${storyTitle}**`;
    listingItems.push(
      `${listingItems.length + 1}. ${head}${siteStr ? ` *(${siteStr})*` : ''}${meta ? ` — ${meta}` : ''}`,
    );
    if (listingItems.length >= 60) break;
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
  return md
    // Strip duplicate sticky header (`## Title #100 user merged 1 commit into ...`) right below `# Title`.
    .replace(/(^#\s+[^\n]+\n+(?:(?:Open|Closed|Merged|Draft)\n+[\s\S]{0,400}?\n+)?)##\s+[^\n]+#\d+\s+[^\n]+\n+/i, '$1')
    // Strip sign-up wall & trailing right-sidebar metadata blocks (`### Reviewers`, `### Assignees`, `### Labels`, etc.).
    .replace(
      /\n+\[Sign up for free\]\(https:\/\/github\.com\/join[^)]*\)[\s\S]*$/i,
      '',
    )
    .replace(
      /\n+###\s+Reviewers\b[\s\S]*$/i,
      '',
    )
    .trim();
}

function cleanArxivAbstractMarkdown(md: string): string {
  return md
    .replace(/^#\s+[^\n]+>\s+[^\n]+\n+/, '')
    .replace(/^#\s+Title:\s+/m, '# ')
    .replace(/\n+###\s+(?:Current browse context|Bibliographic and Citation Tools|Code, Data and Media Associated with this Article|Demos|Recommenders and Search Tools|arXivLabs:)\b[\s\S]*$/i, '')
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

  // Strip pure line-number gutter cells in 2-column Chroma / Rouge / Highlight.js code tables, then unwrap 1x1 `<pre>` wrapper tables.
  if (/(?:lntd|gutter|hljs-ln-numbers|blob-num)/i.test(out)) {
    out = out
      .replace(/<td\b[^>]*\b(?:lntd|gutter|hljs-ln-numbers|blob-num)\b[^>]*>([\s\S]{0,8000}?)<\/td>/gi, (full, inner: string) => {
        const plain = inner.replace(HTML_TAG_QUOTE_AWARE_RE, '').trim();
        return /^[\d\s]+$/.test(plain) ? '' : full;
      })
      .replace(
        /<table\b[^>]*>\s*(?:<tbody\b[^>]*>\s*)?<tr\b[^>]*>\s*<td\b[^>]*>(\s*<pre\b[\s\S]{0,60000}?<\/pre>\s*)<\/td>\s*<\/tr>\s*(?:<\/tbody>\s*)?<\/table>/gi,
        '$1',
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

  // Convert GitHub / Sphinx syntax-highlighted `<div class="highlight ..."><pre>...</pre></div>` directly (stashing code so `<T>` is never stripped!).
  if (out.includes('highlight')) {
    out = out.replace(
      /<div\b((?:"[^"]*"|'[^']*'|[^>"']){1,6000})>\s*<pre\b([^>]{0,600})>([\s\S]{0,100000}?)<\/pre>\s*<\/div>/gi,
      (full, divAttrStr: string, preAttrStr: string, preInner: string) => {
        if (!/\bhighlight\b/i.test(divAttrStr)) return full;
        const divAttrs = parseTagAttrs(divAttrStr);
        const cls = divAttrs.class ?? '';
        if (!/\bhighlight\b/i.test(cls)) return full;
        const lang = inferCodeFenceLang(divAttrStr, preAttrStr);
        const rawClip = divAttrs['data-snippet-clipboard-copy-content'];
        const codeText =
          rawClip && rawClip.trim().length > 0
            ? rawClip
            : decodeHtmlEntities(preInner.replace(HTML_TAG_QUOTE_AWARE_RE, ''));
        const block = `\n\n${makeSafeCodeFence(codeText.trim(), lang)}\n\n`;
        return stashCode ? stashCode(block) : block;
      },
    );
  }

  // Convert GFM / HTML task-list checkboxes (`<input type="checkbox" checked>`) before generic void tags are stripped.
  if (/<input\b/i.test(out)) {
    out = out.replace(/<input\b((?:"[^"]*"|'[^']*'|[^>"'])*)\/?>/gi, (full, attrStr: string) => {
      if (!/\btype\s*=\s*(?:"checkbox"|'checkbox'|checkbox\b)/i.test(attrStr)) return full;
      const isChecked = /\bchecked\b/i.test(attrStr.replace(/"[^"]*"|'[^']*'/g, '""')) || /\bchecked\s*=\s*(?:"(?:checked|true)"|'(?:checked|true)')/i.test(attrStr);
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
    out = out.replace(/<img\b[^>]*\bmwe-math-fallback-image\b[^>]*>/gi, '');
  }

  // Mark `<math>` inside `.katex-display` or `.MathJax_Display` so `<math>` emits display `$$...$$` blocks.
  if (/(?:katex-display|MathJax_Display)/i.test(out)) {
    out = out.replace(
      /<(span|div)\b[^>]*\b(?:katex-display|MathJax_Display)\b[^>]*>((?:(?!<\/math>)[\s\S]){0,12000}?)<\/math>/gi,
      (full) => full.replace(/<math\b/i, '<math data-ef-display="block"'),
    );
  }

  // Convert `<math>` (KaTeX `<annotation encoding="application/x-tex">` or Wikipedia/MathML `alttext`) to LaTeX.
  if (/<math\b/i.test(out)) {
    out = out.replace(/<math\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]{0,24000}?)<\/math>/gi, (full, attrStr: string, inner: string) => {
      const attrs = parseTagAttrs(attrStr);
      const annotMatch = /<annotation\b[^>]*encoding=(?:"application\/x-tex"|'application\/x-tex')[^>]*>([\s\S]*?)<\/annotation>/i.exec(
        inner,
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
      const rawTex = annotMatch?.[1] ?? attrs.alttext ?? attrs['data-latex'] ?? mwExtSrc;
      if (!rawTex) return full;
      const tex = normalizeLatexSource(rawTex);
      if (!tex) return full;
      const isBlock = attrs.display === 'block' || attrs['data-ef-display'] === 'block' || tex.includes('\n');
      return isBlock ? `\n\n$$\n${tex}\n$$\n\n` : `$${tex.replace(/\s+/g, ' ')}$`;
    });
  }

  // Convert MathJax `<mjx-container data-latex="...">` when assistive `<math>` was absent.
  if (/<mjx-container\b/i.test(out)) {
    out = out.replace(/<mjx-container\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]{0,12000}?)<\/mjx-container>/gi, (full, attrStr: string) => {
      const attrs = parseTagAttrs(attrStr);
      const rawTex = attrs['data-latex'] ?? attrs['data-math'];
      if (!rawTex) return full;
      const tex = normalizeLatexSource(rawTex);
      if (!tex) return full;
      const isBlock = attrs.display === 'true' || attrs.display === 'block';
      return isBlock ? `\n\n$$\n${tex}\n$$\n\n` : `$${tex.replace(/\s+/g, ' ')}$`;
    });
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
          /<(?:p|div)\b[^>]*\b(?:markdown-alert-title|admonition-title|callout-title|starlight-aside__title)\b[^>]*>([\s\S]*?)<\/(?:p|div)>/i,
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

  // Upgrade `<picture><source srcset="..."><img></picture>` to highest-resolution image candidate.
  if (/<picture\b/i.test(out)) {
    out = out.replace(/<picture\b[^>]*>([\s\S]{0,8000}?)<\/picture>/gi, (full, inner: string) => {
      let bestSrc: string | undefined;
      for (const sm of inner.matchAll(/<source\b((?:"[^"]*"|'[^']*'|[^>"'])*)\/?>/gi)) {
        const sAttrs = parseTagAttrs(sm[1]!);
        const cand = extractLargestUrlFromSrcset(sAttrs.srcset ?? sAttrs['data-srcset']);
        if (cand) {
          bestSrc = cand;
          break;
        }
      }
      if (!bestSrc) return full;
      return inner.replace(/<img\b((?:"[^"]*"|'[^']*'|[^>"'])*)>/i, (imgFull, imgAttrStr: string) => {
        const imgAttrs = parseTagAttrs(imgAttrStr);
        if (imgAttrs.src && !isLazyPlaceholderImageUrl(imgAttrs.src)) return imgFull;
        return `<img src="${bestSrc}" ${imgAttrStr}>`;
      });
    });
  }

  return out;
}

/**
 * Crawl4AI + Defuddle link-density boilerplate filter:
 * Prunes non-content sidebar/TOC/related/tag-cloud blocks (`>= 5` links, `>80%` anchor-text ratio, `< 90` words)
 * ONLY when total page word count survives with `>= 55%` of words intact (protecting curated directory/index pages).
 */
function pruneHighLinkDensityBlocks(html: string): string {
  const beforeWords = countTextWords(html.replace(HTML_TAG_QUOTE_AWARE_RE, ' '));
  if (beforeWords < 140) return html;

  const clutterAttrRe =
    /\b(?:sidebar|related|popular|trending|recommended|most-read|more-stories|toc|table-of-contents|breadcrumb|pagination|pager|tag-cloud|tags-list|categories|social|share|widget|footer-links)\b/i;

  const candidate = html.replace(
    /<(div|section|ul)\b([^>]{0,500})>((?:(?!<\1\b)[\s\S]){0,12000}?)<\/\1>/gi,
    (full, tag: string, attrStr: string, inner: string) => {
      if (/<(?:pre|code|table|h1|article|figure|math)\b/i.test(inner)) return full;
      const anchorMatches = [...inner.matchAll(/<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/gi)];
      if (anchorMatches.length < 5) return full;

      const totalText = cleanInlineHtml(inner);
      const words = countTextWords(totalText);
      if (words === 0 || words >= 95) return full;

      let anchorTextLen = 0;
      let hashOnlyAnchors = 0;
      for (const am of anchorMatches) {
        const aAttrs = parseTagAttrs(am[1]!);
        if ((aAttrs.href ?? '').trim().startsWith('#')) hashOnlyAnchors++;
        anchorTextLen += cleanInlineHtml(am[2]!).length;
      }
      const linkRatio = anchorTextLen / Math.max(1, totalText.length);
      if (linkRatio < 0.8) return full;

      const isSamePageToc = hashOnlyAnchors >= 4 && hashOnlyAnchors === anchorMatches.length;
      const attrs = parseTagAttrs(attrStr);
      const hasClutterAttr = clutterAttrRe.test(`${attrs.class ?? ''} ${attrs.id ?? ''}`);
      if (isSamePageToc || (hasClutterAttr && tag.toLowerCase() !== 'article')) {
        return '';
      }
      return full;
    },
  );

  if (candidate === html) return html;
  const afterWords = countTextWords(candidate.replace(HTML_TAG_QUOTE_AWARE_RE, ' '));
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

  const htmlTagMatch = /<html\b[^>]*>/i.exec(rawHtml);
  const htmlAttrs = htmlTagMatch ? parseTagAttrs(htmlTagMatch[0]) : {};
  const language = htmlAttrs.lang?.trim() || undefined;

  const jsonLdEntities = flattenJsonLdEntities(rawHtml);
  const schemaMeta = extractSchemaMetadataAndBody(jsonLdEntities);

  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(rawHtml);
  const rawDocTitle = titleMatch ? cleanInlineHtml(titleMatch[1]!) : undefined;
  let title = rawDocTitle && !isPlaceholderMetaValue(rawDocTitle) ? rawDocTitle : undefined;
  let description: string | undefined;
  let author: string | undefined;
  let publishedTime: string | undefined;
  let modifiedTime: string | undefined;
  let siteName: string | undefined;
  let ogImage: string | undefined;
  let themeColor: string | undefined;
  const citationAuthors: string[] = [];

  const metaRe = /<meta\b[^>]*>/gi;
  let metaMatch: RegExpExecArray | null;
  while ((metaMatch = metaRe.exec(rawHtml)) !== null) {
    const attrs = parseTagAttrs(metaMatch[0]);
    const key = (attrs.name ?? attrs.property ?? '').toLowerCase();
    const content = (attrs.content ?? '').trim();
    if (!content || isPlaceholderMetaValue(content)) continue;
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
  }
  if (!author && citationAuthors.length > 0) {
    author = [...new Set(citationAuthors.filter(Boolean))].join(', ');
  }
  author = author || schemaMeta.author;
  publishedTime =
    publishedTime ||
    schemaMeta.publishedTime ||
    /<(?:time|relative-time)\b[^>]*\bdatetime=(?:"([^"]+)"|'([^']+)')/i.exec(rawHtml)?.[1]?.trim() ||
    /<(?:time|relative-time)\b[^>]*\bdatetime=(?:"([^"]+)"|'([^']+)')/i.exec(rawHtml)?.[2]?.trim();
  modifiedTime = modifiedTime || schemaMeta.modifiedTime;
  siteName = siteName || schemaMeta.siteName;

  let canonicalUrl: string | undefined;
  let markdownAlternateUrl: string | undefined;
  let favicon: string | undefined;
  const linkRe = /<link\b[^>]*>/gi;
  let linkMatch: RegExpExecArray | null;
  while ((linkMatch = linkRe.exec(rawHtml)) !== null) {
    const attrs = parseTagAttrs(linkMatch[0]);
    const rel = (attrs.rel ?? '').toLowerCase();
    const mimeType = (attrs.type ?? '').toLowerCase();
    const href = resolveHttpsHref(attrs.href, baseUrl);
    if (!href) continue;
    if (rel.includes('canonical') && !canonicalUrl) canonicalUrl = href;
    if (rel.includes('icon') && !favicon) favicon = href;
    if (rel.includes('alternate') && (mimeType.includes('text/markdown') || mimeType.includes('application/markdown')) && !markdownAlternateUrl) {
      markdownAlternateUrl = href;
    }
  }
  if (!favicon && baseUrl) {
    try {
      const bu = new URL(baseUrl);
      favicon = `${bu.origin}/favicon.ico`;
    } catch {
      // ignore
    }
  }

  // Extract colors and fonts from <style> tags before stripping them.
  const styleText = [...rawHtml.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => m[1]!).join('\n');
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

  let logo: string | undefined;
  for (const imgTag of rawHtml.match(/<img\b[^>]*>/gi) ?? []) {
    const attrs = parseTagAttrs(imgTag);
    const hay = `${attrs.alt ?? ''} ${attrs.class ?? ''} ${attrs.id ?? ''} ${attrs.src ?? ''}`.toLowerCase();
    if (hay.includes('logo')) {
      logo = resolveHttpsHref(attrs.src ?? attrs['data-src'], baseUrl);
      if (logo) break;
    }
  }

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
  // while promoting `<noscript><img ...></noscript>` lazy-load fallbacks inline.
  const noscriptChunks: string[] = [];
  const withPromotedNoscriptImgs = rawHtml.replace(
    /<noscript\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/noscript>/gi,
    (_full, inner: string) => {
      const trimmedInner = inner.trim();
      if (/^<img\b(?:"[^"]*"|'[^']*'|[^>"'])*\/?>$/i.test(trimmedInner)) {
        return trimmedInner;
      }
      if (countTextWords(trimmedInner.replace(HTML_TAG_QUOTE_AWARE_RE, ' ')) >= 35) {
        noscriptChunks.push(trimmedInner);
      }
      return '';
    },
  );

  // Convert YouTube & X/Twitter `<iframe>` embeds into clean Markdown links before stripping `<iframe>` tags.
  const withEmbedLinks = withPromotedNoscriptImgs.replace(
    /<iframe\b((?:"[^"]*"|'[^']*'|[^>"'])*)>[\s\S]*?<\/iframe>/gi,
    (_full, attrStr: string) => {
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
  );

  // Preserve MathJax `<script type="math/tex">` equations BEFORE stripping `<script>` tags.
  const withPreservedMathScripts = withEmbedLinks.replace(
    /<script\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/script>/gi,
    (full, attrStr: string, inner: string) => {
      if (!/\btype\s*=\s*["']math\/tex/i.test(attrStr)) return full;
      const tex = normalizeLatexSource(inner);
      if (!tex) return '';
      return /mode\s*=\s*display/i.test(attrStr) ? `\n\n$$\n${tex}\n$$\n\n` : `$${tex.replace(/\s+/g, ' ')}$`;
    },
  );

  // Strip comments (including Lit-SSR `<?>` bogus comments on MDN) and non-content elements.
  const withoutCommentsAndScripts = withPreservedMathScripts
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<\?[\s\S]{0,400}?\?>|<\?>/g, '')
    .replace(/<svg\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/svg>/gi, ' ')
    .replace(
      /<(head|script|style|noscript|template|canvas|iframe|include-fragment|details-dialog|details-menu|tool-tip|clipboard-copy)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi,
      '',
    );
  let work = withoutCommentsAndScripts;

  let extractedMarkdownBodyOnly = false;
  if (includeTags && includeTags.length > 0) {
    work = applyIncludeAndExcludeTagSelectors(work, includeTags, excludeTags);
  } else if (onlyMainContent) {
    work = work.replace(/<(nav|footer|aside|dialog|menu)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi, '');
    // Substack rendered post body (`<div class="body markup">`) or `window._preloads` `body_html`
    const substackMarkup = applyIncludeAndExcludeTagSelectors(work, ['.markup'], undefined);
    // GitHub / GFM pages wrap repo chrome + duplicate file tables inside `<main>` around `<article class="markdown-body">`
    // (or `.markdown-body` comment blocks on Issues/PRs).
    const mdBodyMatches = [
      ...work.matchAll(
        /<article\b(?:"[^"]*"|'[^']*'|[^>"'])*\bclass=(?:"[^"]*\bmarkdown-body\b[^"]*"|'[^']*\bmarkdown-body\b[^']*')(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/article>/gi,
      ),
    ];
    const joinedMdBody = mdBodyMatches.map((m) => m[1]!).join('\n\n<hr/>\n\n');
    const mainMatch = /<main\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*)<\/main>/i.exec(work);
    const isGitHubIssueOrPr = Boolean(baseUrl && /^https?:\/\/github\.com\/[^/]+\/[^/]+\/(?:issues|pull)\/\d+/i.test(baseUrl));
    if (!isGitHubIssueOrPr && joinedMdBody.trim().length >= 32) {
      work = joinedMdBody;
      extractedMarkdownBodyOnly = true;
    } else if (/\bbody\s+markup\b|\bmarkup\s+body\b/i.test(work) && substackMarkup.trim().length >= 64) {
      work = substackMarkup;
      extractedMarkdownBodyOnly = true;
    } else if (substackPreload?.bodyHtml && (!mainMatch || countTextWords(mainMatch[1]!.replace(HTML_TAG_QUOTE_AWARE_RE, ' ')) < 40)) {
      work = substackPreload.bodyHtml;
      extractedMarkdownBodyOnly = true;
    } else if (mainMatch && mainMatch[1]!.trim().length >= 32) {
      work = mainMatch[1]!;
    } else {
      const articleMatches = [...work.matchAll(/<article\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/article>/gi)];
      const joinedArticles = articleMatches.map((m) => m[1]!).join('\n\n');
      if (joinedArticles.trim().length >= 32) {
        work = joinedArticles;
      } else {
        const roleMain = extractBalancedRoleMainHtml(work);
        if (roleMain && roleMain.trim().length >= 32) {
          work = roleMain;
        } else {
          work = work.replace(/<header\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/header>/gi, '');
        }
      }
    }
    if (excludeTags && excludeTags.length > 0) {
      work = applyIncludeAndExcludeTagSelectors(work, undefined, excludeTags);
    }
    // Strip hidden DOM subtrees (`[hidden]`, `.d-none`, `style="display:none"`), WAI-ARIA non-content landmarks
    // (`role="navigation|search|banner|contentinfo|dialog|menu|toolbar"`), screen-reader-only duplicate labels,
    // Sphinx/rustdoc/pkg.go.dev permalink anchors, MediaWiki edit/interlanguage chrome, copy-page buttons, and feedback forms.
    work = stripHiddenAndChromeSubtrees(work)
      .replace(/<(nav|footer|aside)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi, '')
      .replace(/<span\b[^>]*\bmw-editsection-bracket\b[^>]*>[\s\S]*?<\/span>/gi, '')
      .replace(/<a\b[^>]*(?:[?&]action=edit\b|href=(?:"https:\/\/www\.wikidata\.org\/wiki\/Special:EntityPage\/[^"]*"|'https:\/\/www\.wikidata\.org\/wiki\/Special:EntityPage\/[^']*'))[^>]*>[\s\S]*?<\/a>/gi, '')
      .replace(/<span\b[^>]*\bmw-editsection\b[^>]*>\s*<\/span>/gi, '')
      .replace(/<label\b[^>]*\bp-lang-btn-label\b[^>]*>[\s\S]*?<\/label>/gi, '')
      .replace(/<ul\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/ul>/gi, (full, inner: string) =>
        (inner.match(/\binterlanguage-link\b/gi) ?? []).length >= 3 ? '' : full,
      )
      .replace(/<form\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/form>/gi, (full, inner: string) =>
        /was this (page )?helpful|did this help|page feedback/i.test(inner) ? '' : full,
      )
      .replace(/<button\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/button>/gi, (full, inner: string) => {
        const btnTxt = cleanInlineHtml(inner);
        return /^(?:copy(?:\s+(?:page|code|link|markdown|item path|path|url|to clipboard|head branch name to clipboard))?|copied!?|yes|no|skip|submit feedback|back to top|ask ai|dark mode|light mode|toggle theme|see all|hide|hide comment|show more|show less|share|format|run)$/i.test(
          btnTxt,
        )
          ? ''
          : full;
      })
      .replace(/<details\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/details>/gi, (full, inner: string) => {
        const linkCount = (inner.match(/<a\b/gi) ?? []).length;
        const proseWithoutLinks = cleanInlineHtml(inner.replace(/<a\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/a>/gi, ' '));
        if (linkCount >= 4 && proseWithoutLinks.length < 120) return '';
        return full;
      });
    work = pruneHighLinkDensityBlocks(work);
  } else if (excludeTags && excludeTags.length > 0) {
    work = applyIncludeAndExcludeTagSelectors(work, undefined, excludeTags);
  }

  const codeStash: string[] = [];
  const stashCode = (renderedCodeMd: string): string => `\u0000EFCODE${codeStash.push(renderedCodeMd) - 1}\u0000`;

  work = standardizeElementsInHtml(work, stashCode);

  const collectAnchorLinks = (htmlSource: string): string[] => {
    const outLinks: string[] = [];
    const seen = new Set<string>();
    for (const m of htmlSource.matchAll(/<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/gi)) {
      const attrs = parseTagAttrs(m[1]!);
      const resolved = resolveHttpsHref(attrs.href, baseUrl);
      if (resolved && !seen.has(resolved)) {
        seen.add(resolved);
        outLinks.push(resolved);
        if (outLinks.length >= 250) break;
      }
    }
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
    for (const m of work.matchAll(/<img\b((?:"[^"]*"|'[^']*'|[^>"'])*)>/gi)) {
      const attrs = parseTagAttrs(m[1]!);
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
        if (images.length >= 60) break;
      }
    }
  }

  const stashFence = (fenceMd: string): string => `\n\n\u0000EFFENCE${codeStash.push(fenceMd.trim()) - 1}\u0000\n\n`;
  const stashInline = (spanMd: string): string => (spanMd ? `\`\u0000EFINLINE${codeStash.push(spanMd) - 1}\u0000\`` : '');

  const formatTableCellMarkdown = (cellHtml: string): string => {
    const withInline = cellHtml
      .replace(/<\/a>(?=<a\b)/gi, '</a> ')
      .replace(/<code\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/code>/gi, (_m, c) =>
        stashInline(formatInlineCodeSpan(cleanInlineHtml(String(c)))),
      )
      .replace(/<(strong|b)\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/\1>/gi, (_m, _t, inner) => {
        const txt = cleanInlineHtml(String(inner));
        return txt ? `**${txt}**` : ' ';
      })
      .replace(/<(em|i)\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/\1>/gi, (_m, _t, inner) => {
        const txt = cleanInlineHtml(String(inner));
        return txt ? `*${txt}*` : ' ';
      })
      .replace(/<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/gi, (_m, attrStr, inner) => {
        const attrs = parseTagAttrs(String(attrStr));
        const href = resolveHttpsHref(attrs.href, baseUrl, true);
        const label = cleanInlineHtml(String(inner));
        if (!label) return ' ';
        return href ? `[${label}](${href})` : label;
      });
    return cleanInlineHtml(withInline).replace(/\|/g, '\\|');
  };

  // Convert structural HTML to Markdown (quote-aware attribute matching prevents `class="[&>span]"` truncation).
  // Match leaf `<table>` elements (`(?!<table\b)`) so outer 1990s layout tables unwrap cleanly while preserving inner data tables.
  let md = work
    .replace(/<wbr\b[^>]*\/?>/gi, '')
    .replace(/<\/a>(?=<a\b)/gi, '</a> ')
    .replace(/<\/code>(?=<code\b)/gi, '</code> ')
    .replace(/([A-Za-z0-9])(?=<a\b)/g, '$1 ')
    .replace(
      /<pre\b((?:"[^"]*"|'[^']*'|[^>"'])*)>\s*(?:<code\b((?:"[^"]*"|'[^']*'|[^>"'])*)>)?([\s\S]*?)(?:<\/code>)?\s*<\/pre>/gi,
      (_m, preAttrs, codeAttrs, code) => {
        const lang = inferCodeFenceLang(String(preAttrs ?? ''), String(codeAttrs ?? ''));
        const decodedCode = decodeHtmlEntities(String(code).replace(HTML_TAG_QUOTE_AWARE_RE, '')).trim();
        return stashFence(makeSafeCodeFence(decodedCode, lang));
      },
    )
    .replace(/<figure\b(?:"[^"]*"|'[^']*'|[^>"'])*>((?:(?!<figure\b)[\s\S]){1,8000}?)<\/figure>/gi, (full, figInner: string) => {
      if (/<(?:pre|table|p)\b/i.test(figInner.replace(/<figcaption\b[\s\S]*?<\/figcaption>/gi, ''))) return full;
      const imgMatch = /<img\b((?:"[^"]*"|'[^']*'|[^>"'])*)>/i.exec(figInner);
      if (!imgMatch) return full;
      const imgAttrs = parseTagAttrs(imgMatch[1]!);
      const bestSrc =
        (imgAttrs.src && !isLazyPlaceholderImageUrl(imgAttrs.src) ? imgAttrs.src : undefined) ??
        imgAttrs['data-src'] ??
        extractLargestUrlFromSrcset(imgAttrs.srcset ?? imgAttrs['data-srcset']) ??
        imgAttrs.src;
      const resolvedSrc = resolveHttpsHref(bestSrc, baseUrl);
      if (!resolvedSrc || isDecorativeOrTinyImage(imgAttrs, resolvedSrc)) return full;
      const alt = cleanInlineHtml(imgAttrs.alt ?? '');
      const capMatch = /<figcaption\b[^>]*>([\s\S]{1,1200}?)<\/figcaption>/i.exec(figInner);
      const capText = capMatch ? cleanInlineHtml(capMatch[1]!) : '';
      return capText && capText !== alt
        ? `\n\n![${alt}](${resolvedSrc})\n\n*${capText}*\n\n`
        : `\n\n![${alt}](${resolvedSrc})\n\n`;
    })
    .replace(/<table\b(?:"[^"]*"|'[^']*'|[^>"'])*>((?:(?!<table\b)[\s\S])*?)<\/table>/gi, (_m, tbl) => {
      const rows = [...String(tbl).matchAll(/<tr\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/tr>/gi)].map((rm) =>
        [...rm[1]!.matchAll(/<t[hd]\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/t[hd]>/gi)].map((cm) =>
          formatTableCellMarkdown(cm[1]!),
        ),
      );
      const nonEmpty = rows.filter((r) => r.some((cell) => cell.length > 0));
      if (nonEmpty.length === 0) return '';
      const cols = Math.max(...nonEmpty.map((r) => r.length));
      const pad = (r: string[]) => Array.from({ length: cols }, (_, i) => r[i] ?? '');
      const header = `| ${pad(nonEmpty[0]!).join(' | ')} |`;
      const sep = `| ${Array.from({ length: cols }, () => '---').join(' | ')} |`;
      const bodyRows = nonEmpty.slice(1).map((r) => `| ${pad(r).join(' | ')} |`);
      return `\n\n${[header, sep, ...bodyRows].join('\n')}\n\n`;
    })
    .replace(/<(?:code|kbd)\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/(?:code|kbd)>/gi, (_m, c) =>
      stashInline(formatInlineCodeSpan(cleanInlineHtml(String(c)))),
    )
    // Convert links wrapping headings (`<a href="..."><h2>Title</h2></a>`) into `## [Title](url)` before generic `<h1>` / `<a>` rules.
    .replace(
      /<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>\s*<h([1-6])\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/h\2>\s*<\/a>/gi,
      (_m, attrStr, lvl, inner) => {
        const attrs = parseTagAttrs(String(attrStr));
        const href = resolveHttpsHref(attrs.href, baseUrl, true);
        const txt = cleanHeadingPermalinks(cleanInlineHtml(String(inner)));
        if (!txt) return '';
        const hashes = '#'.repeat(Number(lvl));
        return href ? `\n\n${hashes} [${txt}](${href})\n\n` : `\n\n${hashes} ${txt}\n\n`;
      },
    )
    .replace(/<h([1-6])\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/h\1>/gi, (_m, lvl, inner) => {
      const txt = cleanHeadingPermalinks(cleanInlineHtml(String(inner)));
      return txt ? `\n\n${'#'.repeat(Number(lvl))} ${txt}\n\n` : '';
    })
    .replace(/<summary\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/summary>/gi, (_m, inner) => {
      const txt = cleanHeadingPermalinks(
        cleanInlineHtml(String(inner)).replace(/\s+(?:see all(?:\s+hide)?|show more(?:\s+show less)?)$/i, ''),
      );
      if (!txt) return '';
      return /^#{1,6}\s/.test(txt) ? `\n\n${txt}\n\n` : `\n\n**${txt}**\n\n`;
    })
    .replace(/<(del|s|strike)\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/\1>/gi, (full, _t, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(String(inner))) return full;
      const txt = cleanInlineHtml(String(inner));
      return txt ? `~~${txt}~~` : '';
    })
    .replace(/<mark\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/mark>/gi, (full, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(String(inner))) return full;
      const txt = cleanInlineHtml(String(inner));
      return txt ? `==${txt}==` : '';
    })
    .replace(/<(strong|b)\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/\1>/gi, (full, _t, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(String(inner))) return full;
      const txt = cleanInlineHtml(String(inner));
      return txt ? `**${txt}**` : ' ';
    })
    .replace(/<(em|i)\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/\1>/gi, (full, _t, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(String(inner))) return full;
      const txt = cleanInlineHtml(String(inner));
      return txt ? `*${txt}*` : ' ';
    })
    .replace(/<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/gi, (full, attrStr, inner) => {
      if (/<(?:li|ul|ol|table|blockquote|pre)\b/i.test(String(inner))) return full;
      const attrs = parseTagAttrs(String(attrStr));
      const href = resolveHttpsHref(attrs.href, baseUrl, true);
      const label = cleanInlineHtml(String(inner));
      if (!label) return ' ';
      return href ? `[${label}](${href})` : label;
    })
    .replace(/<dt\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]{1,1800}?)<\/dt>/gi, (_m, inner: string) => {
      const compactSpans = inner
        .replace(/<\/?span\b(?:"[^"]*"|'[^']*'|[^>"'])*>/gi, '')
        .replace(/\*([^*\n]+)\*(?=[A-Za-z0-9_`])/g, '$1 ')
        .replace(/\*([^*\n]+)\*/g, '$1');
      const term = cleanHeadingPermalinks(cleanInlineHtml(compactSpans));
      if (!term) return '';
      if (/^\*\*[\s\S]+\*\*$/.test(term) || /^`[^`]+`$/.test(term)) {
        return `\n\n**${term.replace(/^\*\*|\*\*$/g, '')}**\n\n`;
      }
      return `\n\n**${term}**\n\n`;
    })
    .replace(/<blockquote\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/blockquote>/gi, (_m, inner) => {
      const txt = cleanInlineHtml(String(inner));
      return txt ? `\n\n> ${txt}\n\n` : '';
    });

  // Convert `<ul>`/`<ol>`/`<li>` in a single O(N) stack pass so nested sublists emit indented `  - ` child bullets
  // AND HTML5 optional-end-tag `<li>` siblings (`<li>A\n<li>B</li>`) never merge or drop their `- ` marker.
  if (/<li\b/i.test(md)) {
    const listTagRe = /<\/?(?:ul|ol|li)\b(?:"[^"]*"|'[^']*'|[^>"'])*>/gi;
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
          .map((p, idx) => (idx % 2 === 1 ? p : p.replace(HTML_TAG_QUOTE_AWARE_RE, ' ')))
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

    let lm: RegExpExecArray | null;
    while ((lm = listTagRe.exec(md)) !== null) {
      flushListSeg(md.slice(lastListIdx, lm.index));
      lastListIdx = lm.index + lm[0].length;
      const head = lm[0].slice(0, 5).toLowerCase();
      if (head.startsWith('<ul') || head.startsWith('<ol')) {
        listDepth++;
      } else if (head.startsWith('</ul') || head.startsWith('</ol')) {
        while (liStack.length > 0 && liStack[liStack.length - 1]!.depth >= listDepth) {
          liStack.pop();
        }
        listDepth = Math.max(0, listDepth - 1);
        if (listDepth === 0) listOut.push('\n\n');
      } else if (head.startsWith('<li')) {
        const targetDepth = Math.max(1, listDepth);
        while (liStack.length > 0 && liStack[liStack.length - 1]!.depth >= targetDepth) {
          liStack.pop();
        }
        liStack.push({ depth: targetDepth, emitted: false });
      } else if (head.startsWith('</li')) {
        if (liStack.length > 0) liStack.pop();
      }
    }
    flushListSeg(md.slice(lastListIdx));
    md = listOut.join('');
  }
  md = md
    .replace(/<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/a>/gi, (_m, attrStr, inner) => {
      const attrs = parseTagAttrs(String(attrStr));
      const href = resolveHttpsHref(attrs.href, baseUrl, true);
      const label = cleanInlineHtml(String(inner));
      if (!label) return '';
      return href ? `[${label}](${href})` : label;
    })
    .replace(/<(br|hr)\b(?:"[^"]*"|'[^']*'|[^>"'])*\/?>/gi, (_m, tag) =>
      String(tag).toLowerCase() === 'hr' ? '\n\n---\n\n' : '\n',
    )
    .replace(/<\/(p|div|section|article|main|ul|ol|dl|dd|dt|figure|figcaption|tr|header|details)>/gi, '\n\n')
    .replace(/<\/(span|button|label|time|td|th)>/gi, ' ')
    .replace(HTML_TAG_QUOTE_AWARE_RE, '')
    .replace(/\u0000EFTASKX\u0000/g, '[x]')
    .replace(/\u0000EFTASKO\u0000/g, '[ ]')
    .replace(/\u0000EFFENCE(\d+)\u0000/g, (_m, idx: string) => codeStash[Number(idx)] ?? '')
    .replace(/\u0000EFCODE(\d+)\u0000/g, (_m, idx: string) => codeStash[Number(idx)] ?? '');

  md = splitMarkdownByCodeFences(decodeMarkdownEntities(md))
    .map((part, idx) => {
      if (idx % 2 === 1) return part;
      return part
        .replace(/`([^`\n]+)`(?=`[^`\n]+`)/g, '`$1` ')
        .replace(/([A-Za-z0-9])(\[[^\]\n]+\]\(https?:\/\/[^)\s]+\))/g, '$1 $2')
        .replace(/(\[[^\]\n]+\]\(https?:\/\/[^)\s]+\))([A-Za-z0-9])/g, '$1 $2')
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
    )
    .replace(/\n+##\s+Help improve MDN\b[\s\S]{0,600}$/i, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

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
  } else if (onlyMainContent && (!includeTags || includeTags.length === 0)) {
    if (baseUrl && /^https?:\/\/github\.com\/[^/]+\/[^/]+\/(?:issues|pull)\/\d+/i.test(baseUrl)) {
      md = cleanGitHubIssueOrPrMarkdown(md);
    } else if (baseUrl && /^https?:\/\/(?:export\.)?arxiv\.org\/abs\//i.test(baseUrl)) {
      md = cleanArxivAbstractMarkdown(md);
    } else {
      const siteExtracted = applyPostFetchSiteExtractor(rawHtml, baseUrl, md, (frag, fragBase) => {
        const sub = extractHtmlDocument(frag, {
          baseUrl: fragBase,
          onlyMainContent: false,
          includeImages,
        });
        return { markdown: sub.markdown, links: sub.links };
      });
      if (siteExtracted) {
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
      }
    }

    // Defuddle schema.org `articleBody` & `<noscript>` SSR rescue: if DOM extraction yielded <30 words on a client-hydrated shell.
    const mdWords = countTextWords(md);
    if (mdWords < 30 && schemaMeta.articleBody) {
      const schemaWords = countTextWords(schemaMeta.articleBody);
      if (schemaWords > Math.max(40, mdWords * 2)) {
        const cleanSchemaMd = /<[a-z][\s\S]*>/i.test(schemaMeta.articleBody)
          ? cleanInlineHtml(schemaMeta.articleBody)
          : decodeHtmlEntities(schemaMeta.articleBody).trim();
        if (cleanSchemaMd) {
          md = title && !cleanSchemaMd.startsWith('# ') ? `# ${title}\n\n${cleanSchemaMd}` : cleanSchemaMd;
        }
      }
    } else if (mdWords < 25 && noscriptChunks.length > 0) {
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
  }

  let plainText = ytMeta ? ytMeta.markdown : hnExtracted ? hnExtracted.markdown : cleanInlineHtml(work);
  if (redactPii) {
    md = redactPiiText(md);
    plainText = redactPiiText(plainText);
  }
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
      if (lowerProp === 'title' || lowerProp === 'name' || lowerProp === 'headline') val = doc.title;
      else if (lowerProp === 'description' || lowerProp === 'summary' || lowerProp === 'overview') {
        val = doc.description;
        if (!val && doc.markdown) {
          const proseBlocks = doc.markdown
            .replace(/```[\s\S]*?```/g, '')
            .split(/\n{2,}/)
            .map((b) => b.trim())
            .filter(
              (b) =>
                b.length >= 30 &&
                !/^(?:#{1,6}\s|>|\||[-*]\s|\d+\.\s|!\[)/.test(b),
            );
          if (proseBlocks[0]) {
            val = proseBlocks[0].replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/\s+/g, ' ').trim().slice(0, 500);
          }
        }
      } else if (lowerProp === 'url' || lowerProp === 'canonicalurl') val = doc.canonicalUrl;
      else if (lowerProp === 'links') val = doc.links;
      else if (lowerProp === 'images') val = doc.images.map((i) => i.url);
      else if (propSpec?.type === 'array' && doc.markdown) {
        const cleanMd = doc.markdown.replace(/```[\s\S]*?```/g, '');
        if (/headings|sections|topics/i.test(propName)) {
          const headings = [...cleanMd.matchAll(/^#{2,3}\s+(.+)$/gm)]
            .map((m) => m[1]!.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').trim())
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
              .map((l) => /^(?:[-*]|\d+\.)\s+(.+)$/.exec(l.trim())?.[1] ?? '')
              .map((s) => s.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/\*{1,2}([^*]+)\*{1,2}/g, '$1').trim())
              .filter((s) => s.length >= 4)
              .slice(0, 15);
          if (propWords.length > 0) {
            for (let i = 0; i < lines.length; i++) {
              const hm = /^#{1,4}\s+(.+)$/.exec(lines[i]!.trim());
              if (hm && propWords.some((w) => hm[1]!.toLowerCase().includes(w))) {
                const sectionLines: string[] = [];
                for (let j = i + 1; j < lines.length; j++) {
                  if (/^#{1,3}\s+/.test(lines[j]!.trim())) break;
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
      } else {
        const fuzzyKey = propName
          .replace(/([a-z0-9])([A-Z])/g, '$1[\\s_-]*$2')
          .replace(/[_-]+/g, '[\\s_-]*');
        const kvRe = new RegExp(`(?:^|\\n)\\s*(?:[-*]\\s*)?\\*{0,2}${fuzzyKey}\\*{0,2}\\s*:\\s*([^\\n]+)`, 'i');
        const m = kvRe.exec(doc.markdown);
        if (m?.[1]) {
          val = m[1].replace(/^`([^`]+)`$/, '$1').trim();
        }
        if (val === undefined && /^(?:version|latestversion|currentversion|release)$/i.test(lowerProp)) {
          const verFromHeading =
            /^#{1,2}\s+[^\r\n#]*?\bv?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)\b/m.exec(doc.markdown)?.[1] ??
            /\bv?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)\b/.exec(doc.title ?? '')?.[1];
          if (verFromHeading) val = verFromHeading;
        }
        if (val === undefined && /^(?:installcommand|install|installation)$/i.test(lowerProp) && propSpec?.type !== 'array') {
          const installMatch =
            /\b((?:pip3?|uv\s+(?:pip\s+install|add)|poetry\s+add|conda\s+install|npm\s+(?:install|i|add|create)|pnpm\s+(?:add|install|i|create)|yarn\s+(?:add|create)|bun\s+(?:add|install|i|create)|cargo\s+(?:add|install)|go\s+(?:get|install)|brew\s+install|gem\s+install|composer\s+require|dotnet\s+add\s+package)\s+[^\r\n`"'|;]{1,120})/i.exec(
              doc.markdown,
            );
          if (installMatch?.[1]) {
            val = installMatch[1].replace(/\s+#.*$/, '').trim();
          }
        }
        if (val === undefined && /^(?:license|spdxlicense)$/i.test(lowerProp)) {
          const licHeading =
            /(?:^|\n)(?:#{1,4}\s*License|\*\*License\*\*|License\s*:)\s*\r?\n+([^\r\n#|]{2,120})/i.exec(doc.markdown)?.[1] ??
            /\b((?:MIT|Apache-2\.0|Apache\s+Software\s+License|BSD-[23]-Clause|BSD\s+License|GPL-[23]\.0(?:-only|-or-later)?|LGPL-[23]\.[01]|MPL-2\.0|ISC|Unlicense)(?:\s*\([^)\r\n]{1,40}\))?)\b/i.exec(
              doc.markdown,
            )?.[1];
          if (licHeading) {
            val = licHeading.replace(/^[-*]\s+/, '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').trim();
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
      const seg = decodeURIComponent(new URL(urlStr).pathname.split('/').pop() ?? '').replace(/\.pdf$/i, '');
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

export type ScrapeFormatInput =
  | 'markdown'
  | 'text'
  | 'html'
  | 'rawHtml'
  | 'links'
  | 'images'
  | 'branding'
  | 'llmsTxt'
  | { type: 'json'; schema?: Record<string, unknown> };

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
  discoverLlmsTxt?: unknown;
  redactPii?: unknown;
  query?: unknown;
  headers?: unknown;
  renderMode?: unknown;
  waitForMs?: unknown;
  waitSelector?: unknown;
  maxPages?: unknown;
  ocr?: unknown;
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

function resolveMarkdownRelativeLinksInProse(prose: string, baseUrl?: string): string {
  if (!baseUrl) return prose;
  return prose.replace(/(`+[^`\n]*`+)|(!?\[[^\]\n]*\])\(([^)\s]+)(\s+"[^"]*")?\)/g, (full, codeSpan, labelPart, rawHref, titleSuffix) => {
    if (codeSpan) return String(codeSpan);
    const href = String(rawHref ?? '');
    if (!/^(?:\/(?!\/)|\.{1,2}\/)/.test(href)) return full;
    try {
      const resolved = new URL(href, baseUrl);
      if (resolved.protocol !== 'https:' && resolved.protocol !== 'http:') return full;
      return `${String(labelPart)}(${resolved.toString()}${titleSuffix ?? ''})`;
    } catch {
      return full;
    }
  });
}

function cleanCodeFenceSegment(fenceBlock: string): string {
  // Strip single-line minified `<script type="application/ld+json">` (`schema.org`) metadata blocks emitted by
  // edge HTML-to-Markdown converters, while leaving multi-line JSON-LD code examples in tutorials untouched.
  if (/^`{3,}json[ \t]*\r?\n\{\s*"@context"\s*:\s*"https?:\/\/schema\.org"[^\r\n]{100,}\r?\n`{3,}$/i.test(fenceBlock.trim())) {
    return '';
  }
  const nlIdx = fenceBlock.indexOf('\n');
  if (nlIdx === -1) return fenceBlock;
  const rawHeader = fenceBlock.slice(0, nlIdx).replace(/\r$/, '');
  const closeMatch = /\r?\n([ ]{0,3}(?:`{3,}|~{3,})[ \t]*)$/.exec(fenceBlock);
  if (!closeMatch) return fenceBlock;
  const closingFence = closeMatch[1]!;
  let innerCode = fenceBlock.slice(nlIdx + 1, closeMatch.index);

  const isTwoslash = /\btwoslash\b/i.test(rawHeader) || /^[ \t]*\/\/[ \t]*---cut(?:-(?:before|after))?---[ \t]*$/m.test(innerCode);
  if (isTwoslash) {
    const cutBeforeRe = /^[\s\S]*?^[ \t]*\/\/[ \t]*---cut(?:-before)?---[ \t]*\r?\n/m;
    innerCode = innerCode.replace(cutBeforeRe, '');
    innerCode = innerCode.replace(/\r?\n[ \t]*\/\/[ \t]*---cut-after---[ \t]*(?:\r?\n[\s\S]*)?$/, '');
    innerCode = innerCode.replace(
      /^[ \t]*\/\/[ \t]*@(?:noErrors|errors:\s*[\d\s]+|target:\s*\S+|module:\s*\S+|moduleResolution:\s*\S+|lib:\s*\S+|strict(?::\s*\S+)?)[ \t]*\r?\n/gm,
      '',
    );
  }

  const cleanHeader = rawHeader
    .replace(/[ \t]+theme=\{[^}\r\n]*\}/g, '')
    .replace(/[ \t]+\[\[[^\r\n]*\]\]/g, '')
    .replace(/[ \t]+\btwoslash\b/gi, '')
    .replace(/[ \t]+$/, '');

  return `${cleanHeader}\n${innerCode}\n${closingFence}`;
}

export function sanitizeInlineHtmlInMarkdown(md: string, baseUrl?: string): string {
  const withoutMintlifyBanner = md
    .replace(/[\u200b\u200e\u200f\ufeff]/g, '')
    .replace(
      /^\s*>\s*##\s*Documentation Index[ \t]*\r?\n>\s*Fetch the complete documentation index at:\s*\S+[ \t]*\r?\n>\s*Use this file to discover all available pages before exploring further\.[ \t]*\r?\n+/i,
      '',
    )
    .replace(
      /\r?\n+This documentation is built and hosted on \[Mintlify\]\([^)]+\),\s*a developer documentation platform\.[ \t]*$/i,
      '',
    );
  const parts = splitMarkdownByCodeFences(withoutMintlifyBanner);
  return parts
    .map((part, idx) => {
      if (idx % 2 === 1) {
        return cleanCodeFenceSegment(part);
      }
      const cleanedProse = part
        // Strip JSX / MDX inline comments (`{/*reference*/}`, `{/* ... */}`) outside code fences.
        .replace(/\{\/\*[\s\S]*?\*\/\}/g, '')
        // Convert VitePress / Docusaurus `:::` / `::::` admonition containers into clean bold callout headers and strip layout containers.
        .replace(
          /^[ \t]*:{3,}[ \t]*(info|tip|note|warning|caution|danger|important|details)(?:[ \t]+([^\r\n]+))?[ \t]*$/gim,
          (_m, kindRaw: string, customTitle?: string) => {
            const kindLabel = kindRaw.charAt(0).toUpperCase() + kindRaw.slice(1).toLowerCase();
            const custom = customTitle?.trim();
            if (custom && custom.toLowerCase() !== kindRaw.toLowerCase()) {
              return `\n\n**${kindLabel}: ${custom}**\n\n`;
            }
            return `\n\n**${kindLabel}**\n\n`;
          },
        )
        .replace(/^[ \t]*:{3,}(?:[ \t]*(?:code-group|tabs|tab(?:\s+[^\r\n]*)?|raw|v-pre))?[ \t]*$/gim, '')
        // Unwrap standalone MDX PascalCase component wrapper / self-closing lines (`<Intro>`, `</Intro>`, `<InlineToc />`, `<DeepDive title="...">`)
        // as well as inline MDX components (`<CodeStep step={1}>current state</CodeStep>`).
        .replace(/^[ \t]*<([A-Z][A-Za-z0-9._]*)\b((?:"[^"]*"|'[^']*'|[^>"'])*)\s*(\/?)>[ \t]*$/gm, (_m, _tag, attrStr: string, selfClose: string) => {
          if (selfClose === '/') return '';
          const attrs = parseTagAttrs(String(attrStr ?? ''));
          const headingTitle = (attrs.title ?? attrs.titletext ?? '').trim();
          return headingTitle ? `\n\n**${headingTitle}**\n\n` : '';
        })
        .replace(/^[ \t]*<\/[A-Z][A-Za-z0-9._]*>[ \t]*$/gm, '')
        .replace(/`+[^`\n]*`+|<([A-Z][A-Za-z0-9._]*)\b(?:"[^"]*"|'[^']*'|[^>"'])*>([\s\S]*?)<\/\1>/g, (full, _tag, inner?: string) =>
          inner !== undefined ? inner : full,
        )
        .replace(/\[\s*<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>\s*\]\(([^)]+)\)/gi, (_m, lvl, inner, href) => {
          const label = cleanInlineHtml(String(inner));
          return label ? `\n\n${'#'.repeat(Number(lvl))} [${label}](${String(href).trim()})\n\n` : '';
        })
        .replace(/<a\b([^>]*)>\s*<h([1-6])\b[^>]*>([\s\S]*?)<\/h\2>\s*<\/a>/gi, (_m, attrStr, lvl, inner) => {
          const attrs = parseTagAttrs(String(attrStr));
          const href = resolveHttpsHref(attrs.href, baseUrl);
          const label = cleanInlineHtml(String(inner));
          if (!label) return '';
          return href ? `\n\n${'#'.repeat(Number(lvl))} [${label}](${href})\n\n` : `\n\n${'#'.repeat(Number(lvl))} ${label}\n\n`;
        })
        .replace(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi, (_m, lvl, inner) => {
          const label = cleanInlineHtml(String(inner));
          return label ? `\n\n${'#'.repeat(Number(lvl))} ${label}\n\n` : '';
        })
        .replace(/<summary\b[^>]*>([\s\S]*?)<\/summary>/gi, (_m, inner) => {
          const label = cleanInlineHtml(String(inner));
          return label ? `\n\n**${label}**\n\n` : '';
        })
        .replace(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi, (_m, attrStr, inner) => {
          const attrs = parseTagAttrs(String(attrStr));
          const href = resolveHttpsHref(attrs.href, baseUrl);
          const label = cleanInlineHtml(String(inner));
          if (!label) return '';
          return href ? `[${label}](${href})` : label;
        })
        .replace(/<code\b[^>]*>([\s\S]*?)<\/code>/gi, (_m, inner) => {
          const txt = cleanInlineHtml(String(inner));
          return txt ? `\`${txt}\`` : '';
        })
        .replace(/<(strong|b)\b[^>]*>([\s\S]*?)<\/\1>/gi, (_m, _t, inner) => {
          const txt = cleanInlineHtml(String(inner));
          return txt ? `**${txt}**` : '';
        })
        .replace(/<(em|i)\b[^>]*>([\s\S]*?)<\/\1>/gi, (_m, _t, inner) => {
          const txt = cleanInlineHtml(String(inner));
          return txt ? `*${txt}*` : '';
        })
        .replace(/<sup\b[^>]*>([\s\S]*?)<\/sup>/gi, (_m, inner) => {
          const txt = cleanInlineHtml(String(inner));
          if (!txt) return '';
          return /^[\d,\s-]+$/.test(txt) ? ` [${txt}]` : `^${txt}`;
        })
        .split('\n')
        .map((line) =>
          line.trimStart().startsWith('|')
            ? line.replace(/<br\b[^>]*\/?>/gi, ' / ')
            : line.replace(/<br\b[^>]*\/?>/gi, '\n'),
        )
        .join('\n')
        .replace(/<\/?(?:u|details|span|div|p|button)\b(?:"[^"]*"|'[^']*'|[^>"'])*>/gi, '')
        .replace(/\[Skip to content\]\(#[^)]*\)\s*/gi, '')
        .replace(/(?:^|\n)Was this (?:page )?helpful\?[ \t]*(?:\n+(?:Yes\s*No|Yes[ \t]*\/[ \t]*No))?[ \t]*(?=\n|$)/gi, '\n')
        .replace(/!\[\s*\]\(\s*(?:""|'')?\s*\)/g, '')
        .replace(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, (full, alt: string, rawUrl: string) =>
          isTinyOrAvatarImageUrl(rawUrl, alt) ? '' : full,
        )
        .replace(/(!\[[^\]]*\]\([^)\s]+(?:\s+"[^"]*")?\))[ \t]*(?=!\[)/g, '$1\n\n')
        .replace(
          idx === parts.length - 1
            ? /\n##+\s+On this page[ \t]*(?:\n+(?:[-*]\s+\[[^\]]+\]\(#[^)]+\)[ \t]*)+)?(?:\n+\[!\[[^\]]*\]\([^)]+\)[^\]]*\]\([^)]+\)[ \t]*)?\s*$/i
            : /$^/,
          '',
        );
      return resolveMarkdownRelativeLinksInProse(cleanedProse, baseUrl).replace(/\n{3,}/g, '\n\n');
    })
    .map((part, idx) => (idx % 2 === 1 ? part : dedupeConsecutiveStandaloneLinkParagraphs(part)))
    .join('');
}

export function parseMarkdownFrontmatter(md: string): { title?: string; description?: string; body: string } {
  const normalized = md.replace(/\r\n/g, '\n');
  const m = /^---\n([\s\S]{1,4000}?)\n---(?:\n+|$)/.exec(normalized);
  if (!m?.[1]) return { body: md };
  let title: string | undefined;
  let description: string | undefined;
  for (const line of m[1].split('\n')) {
    const kv = /^([a-zA-Z0-9_-]+)\s*:\s*(.+)$/.exec(line.trim());
    if (!kv) continue;
    const k = kv[1]!.toLowerCase();
    const v = kv[2]!.trim().replace(/^(['"])([\s\S]*)\1$/, '$2').trim();
    if (k === 'title' && v && !title) title = decodeHtmlEntities(v);
    if (k === 'description' && v && !description) description = decodeHtmlEntities(v);
  }
  return {
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    body: normalized.slice(m[0].length),
  };
}

export function extractMarkdownLinksAndImages(
  md: string,
  baseUrl: string,
  includeImages: boolean,
): { links: string[]; images: ScrapedImage[]; title?: string; description?: string } {
  const fmParsed = parseMarkdownFrontmatter(md);
  let title = fmParsed.title;
  const description = fmParsed.description;

  const proseOnly = splitMarkdownByCodeFences(fmParsed.body)
    .filter((_, idx) => idx % 2 === 0)
    .join('\n');
  if (!title) {
    for (const rawLine of proseOnly.split(/\r?\n/)) {
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.startsWith('>')) continue;
      const h1 = /^#\s+(.+)$/.exec(trimmed);
      if (h1?.[1]) {
        title = decodeHtmlEntities(h1[1].replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').trim());
        break;
      }
    }
  }
  const images: ScrapedImage[] = [];
  const seenImages = new Set<string>();
  if (includeImages) {
    for (const im of proseOnly.matchAll(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
      const alt = im[1]?.trim() ?? '';
      const resolved = resolveHttpsHref(im[2], baseUrl);
      if (resolved && !seenImages.has(resolved) && !isTinyOrAvatarImageUrl(resolved, alt)) {
        seenImages.add(resolved);
        images.push({ url: resolved, ...(alt ? { alt } : {}) });
        if (images.length >= 60) break;
      }
    }
  }

  const withoutImages = proseOnly.replace(/!\[[^\]]*\]\([^)]+\)/g, ' ');
  const links: string[] = [];
  const seenLinks = new Set<string>();
  for (const lm of withoutImages.matchAll(/\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
    const rawHref = lm[2]?.trim() ?? '';
    if (!rawHref || rawHref.startsWith('#')) continue;
    const resolved = resolveHttpsHref(rawHref, baseUrl);
    if (resolved && !seenLinks.has(resolved)) {
      seenLinks.add(resolved);
      links.push(resolved);
      if (links.length >= 250) break;
    }
  }

  return {
    links,
    images,
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
  };
}

function finalizeScrapedMarkdown(
  rawMd: string,
  opts: { isPdf: boolean; includeImages: boolean; maxChars?: number; baseUrl?: string },
): {
  markdown: string;
  truncated?: boolean;
  totalChars?: number;
  nextOffset?: number;
  frontmatterTitle?: string;
  frontmatterDescription?: string;
} {
  const fm = opts.isPdf ? { body: rawMd } : parseMarkdownFrontmatter(rawMd);
  let md = sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(fm.body), opts.baseUrl);
  if (opts.isPdf) {
    md = cleanPdfMarkdown(md);
  }
  if (!opts.includeImages) {
    md = md
      .replace(/!\[[^\]]*\]\([^)]+\)/g, '')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  } else {
    md = md.replace(/\n{3,}/g, '\n\n').trim();
  }
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
      const fm = /^(`{3,}|~{3,})/.exec(line.trim());
      if (fm?.[1]) {
        if (!openFence) openFence = fm[1][0]!.repeat(fm[1].length);
        else if (fm[1][0] === openFence[0] && fm[1].length >= openFence.length && /^[`~]+\s*$/.test(line.trim())) openFence = '';
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
  const unfolded = raw.replace(/\r?\n[ \t]/g, '');
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
  const headerSlice = unfolded.split(/^BEGIN:VEVENT\b/im)[0] ?? unfolded;
  for (const line of headerSlice.split(/\r?\n/)) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const k = line.slice(0, colon).split(';')[0]!.trim().toUpperCase();
    const v = unescapeIcsVal(line.slice(colon + 1));
    if ((k === 'X-WR-CALNAME' || k === 'NAME') && v && !calName) calName = v;
    if ((k === 'X-WR-CALDESC' || k === 'DESCRIPTION') && v && !calDesc) calDesc = v;
  }

  const eventSections: string[] = [];
  const eventRe = /BEGIN:VEVENT\b([\s\S]*?)END:VEVENT\b/gi;
  let m: RegExpExecArray | null;
  while ((m = eventRe.exec(unfolded)) !== null && eventSections.length < 50) {
    let summary = '';
    let dtStart = '';
    let dtEnd = '';
    let location = '';
    let url = '';
    let desc = '';
    for (const line of m[1]!.split(/\r?\n/)) {
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
        if (last) fallbackTitle = decodeURIComponent(last);
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
  const baseName = decodeURIComponent(parts[parts.length - 1]!);
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
    title = `${decodeURIComponent(parts[parts.length - 2]!)}/${baseName}`;
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
  const cdata = /^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/.exec(raw);
  if (cdata) return cdata[1]!.trim();
  return decodeHtmlEntities(raw.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')).trim();
}

function matchFirstXmlTag(block: string, tagNames: string[]): string {
  for (const tag of tagNames) {
    const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
    const m = re.exec(block);
    if (m?.[1] !== undefined && m[1].trim()) return unwrapXmlText(m[1]);
  }
  return '';
}

/** Formats RSS 2.0, RDF, and Atom XML feeds into structured Markdown with per-item headings, links, dates, and summaries. */
export function formatFeedXmlToMarkdown(
  rawXml: string,
  baseUrl?: string,
): { title?: string; description?: string; markdown: string; links: string[] } | null {
  const head = rawXml.slice(0, 1200);
  const isRss = /<(?:rss|rdf:RDF)\b/i.test(head) && /<item\b/i.test(rawXml);
  const isAtom = /<feed\b/i.test(head) && /<entry\b/i.test(rawXml);
  if (!isRss && !isAtom) return null;

  const firstItemIdx = rawXml.search(/<(?:item|entry)\b/i);
  const channelHeader = firstItemIdx > 0 ? rawXml.slice(0, firstItemIdx) : head;
  const feedTitle = cleanInlineHtml(matchFirstXmlTag(channelHeader, ['title']));
  const feedDesc = cleanInlineHtml(matchFirstXmlTag(channelHeader, ['description', 'subtitle']));

  const itemRe = isAtom ? /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi : /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
  const lines: string[] = [];
  if (feedTitle) lines.push(`# ${feedTitle}`);
  if (feedDesc && feedDesc !== feedTitle) lines.push(feedDesc);

  const links: string[] = [];
  const seenLinks = new Set<string>();
  let count = 0;
  let m: RegExpExecArray | null;
  while ((m = itemRe.exec(rawXml)) !== null && count < 40) {
    const block = m[1]!;
    const itemTitle = cleanInlineHtml(matchFirstXmlTag(block, ['title'])) || `Entry ${count + 1}`;
    let rawLink = '';
    if (isAtom) {
      const altHref =
        /<link\b[^>]*rel=(?:"alternate"|'alternate')[^>]*href=(?:"([^"]+)"|'([^']+)')/i.exec(block) ??
        /<link\b[^>]*href=(?:"([^"]+)"|'([^']+)')/i.exec(block);
      rawLink = decodeHtmlEntities(altHref?.[1] ?? altHref?.[2] ?? '').trim();
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
      const seg = decodeURIComponent(new URL(urlStr).pathname.split('/').filter(Boolean).pop() ?? '');
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
  const fm = parseMarkdownFrontmatter(trimmed);
  return sanitizeInlineHtmlInMarkdown(decodeMarkdownEntities(fm.body), baseUrl).trim();
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
          description = tl.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').slice(0, 280);
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
  const cleanSummaryDesc = rawDesc
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
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
}): Promise<{ status: number; body: Record<string, unknown>; via: string; retryAfter?: string }> {
  const { payload, env, executeHubFetch, source = 'scrape', selfHost, now = Date.now() } = params;
  const urlCheck = validatePublicHttpsTargetUrl(payload.url, selfHost);
  if (!urlCheck.ok) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: urlCheck.message } };
  }
  const parsedUrl = urlCheck.url;
  const normalizedUrl = urlCheck.normalized;

  const rawFormats = Array.isArray(payload.formats) && payload.formats.length > 0 ? payload.formats : ['markdown'];
  const stringFormats = new Set<string>();
  let jsonSchemaSpec: { schema?: Record<string, unknown> } | undefined;
  for (const f of rawFormats) {
    if (typeof f === 'string') {
      stringFormats.add(f);
    } else if (f && typeof f === 'object' && (f as { type?: unknown }).type === 'json') {
      jsonSchemaSpec = { schema: (f as { schema?: Record<string, unknown> }).schema };
    }
  }
  if (stringFormats.size === 0 && !jsonSchemaSpec) {
    stringFormats.add('markdown');
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
  const maxAgeMs = typeof payload.maxAgeMs === 'number' && Number.isFinite(payload.maxAgeMs) ? Math.max(0, Math.floor(payload.maxAgeMs)) : 0;
  const maxPagesCap =
    typeof payload.maxPages === 'number' && Number.isFinite(payload.maxPages)
      ? Math.min(500, Math.max(1, Math.floor(payload.maxPages)))
      : 60;
  const ocrMode: 'auto' | 'always' | 'off' =
    payload.ocr === 'always' || payload.ocr === 'off' ? payload.ocr : 'auto';
  const hasPdfOcr = Boolean(env.PDF_OCR || (env.PDF_OCR_URL?.trim() && env.PDF_OCR_TOKEN?.trim()));
  const target: 'auto' | 'agent' | 'container' =
    payload.target === 'agent' || payload.target === 'container' ? payload.target : 'auto';
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

  // Serve from verified META D1 + ARTIFACTS R2 cache when maxAgeMs is satisfied and only markdown/metadata are requested.
  const needsLiveHtml =
    stringFormats.has('html') ||
    stringFormats.has('rawHtml') ||
    stringFormats.has('links') ||
    stringFormats.has('images') ||
    stringFormats.has('branding') ||
    stringFormats.has('llmsTxt') ||
    stringFormats.has('changes') ||
    includeTags.length > 0 ||
    excludeTags.length > 0 ||
    Boolean(jsonSchemaSpec);

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
    const hit = await lookupCachedScrape({
      bucket: env.ARTIFACTS,
      metaDb: env.META,
      url: normalizedUrl,
      maxAgeMs,
      pipelineVersion: SCRAPE_PIPELINE_VERSION,
      now,
    });
    if (hit) {
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
    ['markdown', 'text', 'html', 'rawHtml', 'links', 'images', 'branding', 'screenshot'].includes(f),
  );
  if (agentFormats.length === 0) agentFormats.push('markdown');

  const renderMode =
    payload.renderMode === 'always' || payload.renderMode === 'auto' || payload.renderMode === 'off'
      ? payload.renderMode
      : stringFormats.has('screenshot')
        ? 'always'
        : undefined;

  const fetchCall = {
    maxSeconds: 110,
    options: {
      includeBody: true,
      respectRobots: true,
      maxBytes: 16 * 1024 * 1024,
      timeoutMs: 95_000,
      discoverLlms: goDiscoverLlms,
    },
    requests: [
      {
        id: 'scrape-1',
        url: normalizedUrl,
        kind: renderMode === 'always' ? 'render' : 'scrape',
        formats: agentFormats,
        onlyMainContent,
        discoverLlms: goDiscoverLlms,
        redactPii,
        ...(renderMode ? { renderMode } : {}),
        ...(typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
          ? { waitForMs: Math.min(15_000, Math.max(0, Math.floor(payload.waitForMs))) }
          : {}),
        ...(typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
          ? { waitSelector: payload.waitSelector.trim().slice(0, 200) }
          : {}),
        ...(typeof payload.maxPages === 'number' && Number.isFinite(payload.maxPages)
          ? { maxPages: Math.min(500, Math.max(1, Math.floor(payload.maxPages))) }
          : {}),
        ...(payload.headers && typeof payload.headers === 'object' ? { headers: payload.headers } : {}),
      },
    ],
  };

  const collectionId =
    typeof payload.collectionId === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(payload.collectionId.trim())
      ? payload.collectionId.trim()
      : undefined;
  const retentionMode: ArtifactRetention | undefined = env.ARTIFACTS && env.META ? 'stored' : env.ARTIFACTS ? 'transient' : undefined;

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
  const registryTwin = !needsLiveHtml && renderMode !== 'always' ? resolveSiteExtractorTwin(normalizedUrl) : null;
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
                ...(twinArt?.contentSha256 ? { contentSha256: twinArt.contentSha256 } : {}),
                ...(twinArt?.blobSha256 ? { artifactId: twinArt.blobSha256 } : {}),
                ...(twinMdArtifactId ? { markdownArtifactId: twinMdArtifactId } : {}),
                ...(stringFormats.has('markdown') ? { markdown: twinShaped.markdown } : {}),
                ...(stringFormats.has('text') ? { text: twinShaped.markdown } : {}),
                ...(stringFormats.has('links') && formatted.links ? { links: formatted.links } : {}),
                ...(twinFocused.queryFiltered ? { queryFiltered: true, chunks: twinFocused.chunks } : {}),
                ...(twinShaped.truncated
                  ? {
                      truncated: true,
                      totalChars: twinShaped.totalChars,
                      nextOffset: twinShaped.nextOffset ?? twinShaped.markdown.length,
                    }
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
              accept: 'text/markdown, text/plain;q=0.9',
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

  const fetchRes = await executeHubFetch(target, JSON.stringify(fetchCall), site, source, retentionMode, true, collectionId);
  if (fetchRes.status !== 200) {
    let errJson: Record<string, unknown> = { ok: false, error: 'scrape_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    return {
      status: fetchRes.status,
      via: fetchRes.via,
      body: errJson,
      ...(fetchRes.retryAfter ? { retryAfter: fetchRes.retryAfter } : {}),
    };
  }

  const parsedReply = JSON.parse(fetchRes.bodyText) as {
    results?: Array<Record<string, unknown>>;
  };
  const item = parsedReply.results?.[0] ?? {};
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
    const robotsHint = /robots\.txt disallowed/i.test(problemText) ? buildRobotsAlternativeHint(normalizedUrl) : undefined;
    return {
      status: item.status === 429 ? 429 : 422,
      via: fetchRes.via,
      body: {
        ok: false,
        url: normalizedUrl,
        outcome: item.outcome ?? 'error',
        status: item.status ?? 0,
        problem: problemText,
        ...(robotsHint ? { hint: robotsHint } : {}),
      },
    };
  }

  const rawBodyStr = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
  const finalUrl = typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : normalizedUrl;
  const binaryScrapeProblem = detectUnsupportedBinaryPayload({
    rawBody: rawBodyStr,
    contentType: item.contentType,
    url: finalUrl,
    bodyEncoding: item.bodyEncoding,
    isPdf: isPdfResponse,
  });
  if (binaryScrapeProblem) {
    return {
      status: 422,
      via: fetchRes.via,
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
  const isHtmlBody = Boolean(
    rawBodyStr &&
      !isPdfResponse &&
      ((typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('html')) ||
        /^\s*<!doctype\s+html|^\s*<html|<(head|body|main|article)\b/i.test(rawBodyStr)),
  );
  const extracted = isHtmlBody
    ? extractHtmlDocument(rawBodyStr, {
        baseUrl: finalUrl,
        onlyMainContent,
        redactPii,
        includeImages,
        ...(includeTags.length > 0 ? { includeTags } : {}),
        ...(excludeTags.length > 0 ? { excludeTags } : {}),
      })
    : undefined;

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
    !isHtmlBody &&
    !isPdfResponse &&
    !alternateMarkdownBody &&
    ((typeof item.contentType === 'string' && item.contentType.toLowerCase().includes('vcard')) ||
      /^BEGIN:VCARD\b/im.test(rawBodyStr.trim()))
      ? formatVcardToMarkdown(rawBodyStr)
      : null;
  const icsFormatted =
    !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted
      ? formatIcalendarToMarkdown(rawBodyStr)
      : null;
  const feedFormatted =
    !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted
      ? formatFeedXmlToMarkdown(rawBodyStr, finalUrl)
      : null;
  const jsonFormatted =
    !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted && !feedFormatted
      ? tryParseJsonPayloadForScrape(rawBodyStr, item.contentType, finalUrl)
      : null;
  const csvFormatted =
    !isHtmlBody && !isPdfResponse && !alternateMarkdownBody && !vcardFormatted && !icsFormatted && !feedFormatted && !jsonFormatted
      ? formatDelimitedTableToMarkdown(rawBodyStr, item.contentType, finalUrl)
      : null;
  const patchFormatted =
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
    vcardFormatted || icsFormatted || feedFormatted || jsonFormatted || csvFormatted || patchFormatted || sourceCodeFormatted;

  let markdown =
    alternateMarkdownBody ||
    structuredTextFormatted?.markdown ||
    (isHtmlBody ? extracted?.markdown : undefined) ||
    (typeof item.markdown === 'string' && item.markdown) ||
    extracted?.markdown ||
    rawBodyStr;
  let textOut =
    alternateMarkdownBody ||
    feedFormatted?.markdown ||
    vcardFormatted?.markdown ||
    icsFormatted?.markdown ||
    (jsonFormatted || csvFormatted || patchFormatted || sourceCodeFormatted ? rawBodyStr : undefined) ||
    (isHtmlBody ? extracted?.text : undefined) ||
    (typeof item.text === 'string' && item.text) ||
    extracted?.text ||
    '';
  let viaOut = fetchRes.via;
  let pdfEngineOut = typeof item.pdfEngine === 'string' ? item.pdfEngine : undefined;
  let ocrReportOut: PdfOcrContainerReply['ocr'] | undefined;

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
  const fullShaped = finalizeScrapedMarkdown(markdown, {
    isPdf: isPdfResponse,
    includeImages,
    maxChars: undefined,
    baseUrl: finalUrl,
  });
  const rawCleanMarkdown = fullShaped.markdown;
  const mdAssets = !isHtmlBody && !isPdfResponse ? extractMarkdownLinksAndImages(rawCleanMarkdown, finalUrl, includeImages) : undefined;
  const focused = applyQueryFocus(rawCleanMarkdown);
  const shaped =
    focused.queryFiltered || maxChars !== undefined
      ? finalizeScrapedMarkdown(focused.markdown, {
          isPdf: false,
          includeImages,
          maxChars,
          baseUrl: finalUrl,
        })
      : fullShaped;
  markdown = shaped.markdown;
  textOut = decodeHtmlEntities(textOut);

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

  const resolvedTitle =
    extracted?.title ||
    structuredTextFormatted?.title ||
    fullShaped.frontmatterTitle ||
    mdAssets?.title ||
    (typeof item.title === 'string' && item.title ? decodeHtmlEntities(item.title) : undefined) ||
    (typeof (llmsPayload as { matchedEntry?: { title?: string } } | undefined)?.matchedEntry?.title === 'string'
      ? decodeHtmlEntities((llmsPayload as { matchedEntry: { title: string } }).matchedEntry.title)
      : undefined) ||
    (isPdfResponse ? extractPdfTitle(rawCleanMarkdown, finalUrl) : undefined);
  const resolvedDescription =
    extracted?.description ||
    (structuredTextFormatted as { description?: string } | null)?.description ||
    fullShaped.frontmatterDescription ||
    mdAssets?.description ||
    (typeof item.description === 'string' && item.description ? decodeHtmlEntities(item.description) : undefined);

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
  }

  const art = item.artifact as { blobSha256?: string; contentSha256?: string } | undefined;
  let markdownArtifactId: string | undefined;
  if (shaped.truncated && env.ARTIFACTS && rawCleanMarkdown) {
    const usesUpgradedBody = Boolean(alternateMarkdownBody || ocrReportOut || structuredTextFormatted);
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

  const out: Record<string, unknown> = {
    ok: true,
    cached: false,
    pipelineVersion: SCRAPE_PIPELINE_VERSION,
    url: normalizedUrl,
    finalUrl,
    status: item.status ?? 200,
    via: viaOut,
    ...(art?.contentSha256 ? { contentSha256: art.contentSha256 } : {}),
    ...(art?.blobSha256 ? { artifactId: art.blobSha256 } : {}),
    ...(markdownArtifactId ? { markdownArtifactId } : {}),
    ...(stringFormats.has('markdown') ? { markdown } : {}),
    ...(stringFormats.has('text') ? { text: textOut } : {}),
    ...(focused.queryFiltered ? { queryFiltered: true, chunks: focused.chunks } : {}),
    ...(shaped.truncated
      ? {
          truncated: true,
          totalChars: shaped.totalChars,
          nextOffset: shaped.nextOffset ?? markdown.length,
        }
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
    ...(typeof item.screenshotBase64 === 'string' && item.screenshotBase64 ? { screenshotBase64: item.screenshotBase64 } : {}),
    ...(item.rendered === true ? { rendered: true } : {}),
    ...(pdfEngineOut ? { pdfEngine: pdfEngineOut } : {}),
    ...(ocrReportOut ? { ocr: ocrReportOut } : {}),
    ...(stringFormats.has('changes') ? { changes: computeMarkdownChanges(prevMarkdownForChanges, rawCleanMarkdown) } : {}),
    ...(llmsPayload ? { llms: llmsPayload, ...(stringFormats.has('llmsTxt') ? { llmsTxt: llmsPayload } : {}) } : {}),
    metadata: {
      title: resolvedTitle,
      description: resolvedDescription,
      ...(extracted?.author ? { author: extracted.author } : {}),
      ...(extracted?.publishedTime ? { publishedTime: extracted.publishedTime } : {}),
      ...(extracted?.modifiedTime ? { modifiedTime: extracted.modifiedTime } : {}),
      ...(extracted?.siteName ? { siteName: extracted.siteName } : {}),
      ...(rawCleanMarkdown ? { wordCount: countTextWords(rawCleanMarkdown) } : {}),
      language: extracted?.language,
      favicon: (typeof item.favicon === 'string' && item.favicon) || extracted?.favicon,
      canonicalUrl: extracted?.canonicalUrl,
      ...(alternateMarkdownUrl ? { alternateMarkdownUrl } : {}),
      contentType: isPdfResponse ? 'application/pdf' : item.contentType,
    },
  };

  return { status: 200, via: viaOut, body: out };
}

export function extractYouTubeTranscriptFromHtml(rawHtml: string): string {
  if (!rawHtml) return '';
  const segments: string[] = [];
  for (const m of rawHtml.matchAll(/<transcript-segment-view-model\b[^>]*>([\s\S]*?)<\/transcript-segment-view-model>/gi)) {
    const span = /<span\b[^>]*role="text"[^>]*>([\s\S]*?)<\/span>/i.exec(m[1]!);
    const cleaned = cleanInlineHtml(span ? span[1]! : m[1]!);
    if (cleaned) segments.push(cleaned);
  }
  if (segments.length === 0) {
    for (const m of rawHtml.matchAll(/<yt-formatted-string\b[^>]*class="[^"]*\bsegment-text\b[^"]*"[^>]*>([\s\S]*?)<\/yt-formatted-string>/gi)) {
      const cleaned = cleanInlineHtml(m[1]!);
      if (cleaned) segments.push(cleaned);
    }
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

function splitCompositeSessionId(raw: unknown): { siteId?: string; agentSessionId?: string } {
  if (typeof raw !== 'string' || !raw.trim()) return {};
  const clean = raw.trim();
  const dot = clean.indexOf('.');
  if (dot > 0 && dot < clean.length - 1) {
    const sitePart = clean.slice(0, dot).toLowerCase();
    const sessPart = clean.slice(dot + 1);
    if (/^[a-z0-9][a-z0-9_-]{0,31}$/.test(sitePart) && /^[A-Za-z0-9_-]{4,80}$/.test(sessPart)) {
      return { siteId: sitePart, agentSessionId: sessPart };
    }
  }
  if (/^[A-Za-z0-9_-]{4,80}$/.test(clean)) {
    return { agentSessionId: clean };
  }
  return {};
}

/**
 * Executes `POST /v1/interact` + MCP `interact` (`firecrawl_interact` parity) against a `browser-v1` (`edgefetch_fat`)
 * node. Composite `<siteId>.<efsess_id>` tokens ensure follow-up turns route back to the exact node holding the tab.
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
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, env, executeHubFetch, source = 'interact', selfHost } = params;
  const parsedSession = splitCompositeSessionId(payload.sessionId);
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

  const actions: Array<Record<string, unknown>> = [];
  const agentActions: Array<Record<string, unknown>> = [];
  if (Array.isArray(payload.actions)) {
    if (payload.actions.length > 25) {
      return { status: 400, via: 'hub', body: { ok: false, error: 'too_many_actions', message: 'maximum 25 actions per interact turn' } };
    }
    for (const rawAct of payload.actions) {
      if (!rawAct || typeof rawAct !== 'object') continue;
      const a = rawAct as Record<string, unknown>;
      const type = typeof a.type === 'string' ? a.type.trim().toLowerCase() : '';
      if (!['click', 'fill', 'type', 'press', 'wait', 'scroll', 'select', 'navigate'].includes(type)) {
        return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_action', message: `unsupported action type: ${String(a.type)}` } };
      }
      if (type === 'navigate') {
        const navCheck = validatePublicHttpsTargetUrl(a.url, selfHost);
        if (!navCheck.ok) {
          return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: `navigate action: ${navCheck.message}` } };
        }
      }
      const explicitWaitMs =
        typeof a.waitMs === 'number' && Number.isFinite(a.waitMs)
          ? Math.min(15_000, Math.max(0, Math.floor(a.waitMs)))
          : undefined;
      const keyVal = typeof a.key === 'string' ? a.key.slice(0, 40) : undefined;
      const normalizedAct: Record<string, unknown> = {
        type,
        ...(typeof a.selector === 'string' ? { selector: a.selector.slice(0, 240) } : {}),
        ...(typeof a.value === 'string' ? { value: a.value.slice(0, 4096) } : {}),
        ...(keyVal !== undefined ? { key: keyVal } : {}),
        ...(typeof a.url === 'string' ? { url: a.url.trim() } : {}),
        ...(explicitWaitMs !== undefined ? { waitMs: explicitWaitMs } : {}),
      };
      actions.push(normalizedAct);
      // Give `click` and `Enter` `press` actions a >=1200ms / >=900ms default settle window instead of Go's 250ms default
      // so cross-origin link navigations and blocking `<head><script>` tags finish parsing `<body>` before DOM capture.
      const effectiveAgentWaitMs =
        explicitWaitMs !== undefined
          ? explicitWaitMs
          : type === 'click'
            ? 1_200
            : type === 'press' && (!keyVal || /^(?:enter|return)$/i.test(keyVal))
              ? 900
              : undefined;
      agentActions.push({
        ...normalizedAct,
        ...(effectiveAgentWaitMs !== undefined ? { waitMs: effectiveAgentWaitMs } : {}),
      });
    }
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
    return {
      status: item.outcome === 'challenge' ? 403 : 422,
      via: fetchRes.via,
      body: {
        ok: false,
        outcome: item.outcome ?? 'error',
        status: item.status ?? 0,
        problem: prob,
        ...(actionResults ? { actions: actionResults } : {}),
      },
    };
  }

  const siteMatch = /^agent:(?:[a-z0-9_-]+\+)*([a-z0-9_-]+)/i.exec(fetchRes.via);
  const actualSite = siteMatch?.[1] ?? pinnedSite;
  const returnedAgentSid = typeof item.sessionId === 'string' && item.sessionId ? item.sessionId : undefined;
  const publicSessionId = returnedAgentSid && actualSite ? `${actualSite}.${returnedAgentSid}` : returnedAgentSid;

  const rawHtml = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
  const finalUrl = typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : normalizedUrl;
  const wantMarkdown = formats.includes('markdown');
  const requestedTranscript = formats.includes('transcript');
  const extracted = rawHtml ? extractHtmlDocument(rawHtml, { baseUrl: finalUrl || undefined, onlyMainContent: true }) : undefined;
  const transcript = (requestedTranscript || wantMarkdown) && rawHtml ? extractYouTubeTranscriptFromHtml(rawHtml) : '';
  let markdown = decodeMarkdownEntities(extracted?.markdown || (typeof item.markdown === 'string' && item.markdown ? item.markdown : ''));
  if (wantMarkdown && transcript && !/^#{2,3}\s*Transcript\b/im.test(markdown)) {
    markdown = markdown ? `${markdown}\n\n## Transcript\n\n${transcript}` : `## Transcript\n\n${transcript}`;
  }
  const fallbackTitle =
    !extracted && rawHtml
      ? (() => {
          const tm = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(rawHtml);
          return tm ? cleanInlineHtml(tm[1]!) : undefined;
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
}
