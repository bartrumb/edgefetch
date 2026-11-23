/**
 * Advanced `/v1/scrape` & `/v2/scrape` capabilities (`hub/src/scrape-advanced.ts`):
 *  - `$0` High-Precision Prompt Injection Guard (`checkPromptInjection: true` -> `403 SCRAPE_PROMPT_INJECTION_DETECTED`)
 *  - Structured E-Commerce `product` format (Schema.org `Product`, OpenGraph `product:*`, Shopify JSON)
 *  - Targeted `{ type: "attributes", selectors: [{ selector, attribute }] }` extraction
 *  - Inline browser `actions[]` normalizer (up to 50 steps: `click` `all`, `write`, `press`, `scroll`, `screenshot`, `scrape`, `executeJavascript`, `pdf`)
 *  - PDF `parsers` array (`parsers: []` raw base64 mode, `pages: true`, `pageMarkers: true`, `mode: "fast" | "auto" | "ocr"`)
 */

import { extractJsonLdObjects } from './extractors/utils';
import { validatePublicHttpsTargetUrl } from './overflow';
import {
  asciiLower,
  isTagNameBoundary,
  MAX_HTML_SCAN_CHARS,
  replaceHtmlTagsQuoteAwareLinear,
  replacePairedHtmlElementsLinear,
  scanHtmlTagsLinear,
  stripHtmlCommentsLinear,
  stripHtmlTagsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from './safe-input';

const MAX_PROMPT_INJECTION_SCAN_CHARS = 8 * 1024 * 1024;

const INJECTION_PATTERNS: Array<{ id: string; re: RegExp; compactRe: RegExp; weight: number }> = [
  {
    id: 'ignore_previous_instructions',
    re: /\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|each|every)(?:\s+of)?\s+)?(?:(?:the|your|these|those|my|our)\s+)?(?:previous|prior|above|earlier|preceding|system|developer|initial|original)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)\b/i,
    compactRe:
      /(?:ignore|disregard|forget|override)(?:(?:all|any|each|every)(?:of)?)?(?:the|your|these|those|my|our)?(?:previous|prior|above|earlier|preceding|system|developer|initial|original)(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)/i,
    weight: 3,
  },
  {
    id: 'new_system_role_override',
    re: /(?:(?:^|\n)[ \t>]{0,20}(?:\[?[ \t]{0,10}system(?:[ \t]{1,10}(?:prompt|override|instruction|message|role))?[ \t]{0,10}\]?|<[ \t]{0,10}system[ \t]{0,10}>|#{1,6}[ \t]{0,10}system(?:[ \t]{1,10}instruction)?)|(?:^|\s)(?:\[[ \t]{0,6}system[ \t]{1,6}(?:prompt|override|instruction|message|role)[ \t]{0,6}\]|<[ \t]{0,6}system[ \t]{0,6}>))[ \t]{0,10}:/i,
    compactRe:
      /(?:(?:^|\s)\[?system(?:prompt|override|instruction|message|role)\]?:|(?:^|\n)[ \t>]{0,10}system:|<system>:|#{1,6}system(?:instruction)?:)/i,
    weight: 3,
  },
  {
    id: 'exfiltrate_secrets_or_tools',
    re: /\b(?:send|post|upload|exfiltrate|transmit|forward|leak)\s+(?:(?:the|your|all|my|our)\s+)?(?:api[_\s-]?keys?|tokens?|secrets?|passwords?|credentials?|conversation|system\s+prompt|ssh|env)\s+(?:to|via)\s+(?:https?:(?:\/\/|\s+[a-z0-9])|\[[^\]]{1,80}\]\(\s*https?:\/\/|(?:[a-z0-9-]+\s+){0,3}[a-z0-9-]+(?:\.[a-z0-9-]+)+\b|this\b|here\b)/i,
    compactRe:
      /(?:send|post|upload|exfiltrate|transmit|forward|leak)(?:the|your|all|my|our)?(?:api[_-]?keys?|tokens?|secrets?|passwords?|credentials?|conversation|systemprompt|ssh|env)(?:to|via)(?:https?:|[a-z0-9-]+\.[a-z]{2,}|this\b|here\b)/i,
    weight: 4,
  },
  {
    id: 'tool_invocation_hijack',
    re: /(?:(?:\b(?:immediately|now)\s+call\s+the\s+tool|\binvoke\s+the\s+tool)\s+[a-z][a-z0-9_.:/-]{1,63}\b|\b(?:immediately\s+call(?:\s+the\s+tool)?|now\s+call(?:\s+the\s+tool)?|you\s+must\s+now\s+execute|invoke\s+the\s+tool|execute\s+bash\s+command)\b[^\n]{0,80}\b(?:curl|wget|fetch(?:[_\s]?url)?|read[_\s]?artifact|scrape|extract|interact|bash|rm\s+-?rf)\b)/i,
    compactRe:
      /(?:immediatelycall(?:thetool)?|nowcall(?:thetool)?|youmustnowexecute|invokethetool|executebashcommand)[a-z0-9_:/.-]{0,80}(?:curl|wget|fetch(?:_?url)?|read_?artifact|bash|rm-?rf)/i,
    weight: 4,
  },
];

const HIDDEN_STYLE_TOKEN_RE =
  /(?:display[ \t]*:[ \t]*none|visibility[ \t]*:[ \t]*hidden|opacity[ \t]*:[ \t]*0(?:\.0+)?(?![0-9.])|font-size[ \t]*:[ \t]*0(?:px|em|rem|pt|%)?(?![0-9.])|clip-path[ \t]*:[ \t]*inset\(\s*100%|clip[ \t]*:[ \t]*rect\(\s*0|(?:left|top|text-indent)[ \t]*:[ \t]*-\d{3,}|height[ \t]*:[ \t]*0(?:px)?[ \t]*;[^;]{0,60}overflow[ \t]*:[ \t]*hidden|color[ \t]*:[ \t]*(?:#fff(?:fff)?|white|transparent)\b.{0,80}font-size[ \t]*:[ \t]*1px|font-size[ \t]*:[ \t]*1px.{0,80}color[ \t]*:[ \t]*(?:#fff(?:fff)?|white|transparent)\b)/i;
const HIDDEN_DIRECTIVE_OVERRIDE_RE = new RegExp(
  [
    '\\b(?:ignore|disregard|forget|override|bypass)\\s+(?:(?:all|any|each|every|the|your|these|those|my|our|previous|prior|above|earlier|system|developer|safety)\\s+){0,4}(?:instructions?|rules?|prompts?|directives?|guidelines?|constraints?|guardrails?|system)\\b',
    '\\bsystem\\s+(?:prompt|override|instruction|directive|role)\\b',
    '\\b(?:assistant|ai|model|agent)\\s*:\\s*(?:ignore|disregard|forget|override|execute|call|invoke|send|leak|reveal|output|do\\s+not)\\b',
    '\\b(?:assistant|ai|model|agent)\\s+(?:must\\s+|should\\s+|shall\\s+|will\\s+)?(?:now\\s+|immediately\\s+)?(?:execute|invoke|call|run|ignore|disregard|override|leak|exfiltrate)\\s+(?:(?:the|a)\\s+)?(?:tool|command|bash|shell|function|rules?|instructions?)\\b',
    '\\b(?:call|invoke|execute)\\s+(?:the\\s+)?tool\\s+[a-z0-9_-]{2,}\\b',
    '\\bdo\\s+not\\s+(?:tell|inform|mention\\s+to|reveal\\s+to|show)\\s+the\\s+user\\b',
  ].join('|'),
  'i',
);

const CONFUSABLE_CHAR_MAP: Record<string, string> = {
  '\u0456': 'i',
  '\u0406': 'i',
  '\u026A': 'i',
  '\u0430': 'a',
  '\u0410': 'a',
  '\u0435': 'e',
  '\u0415': 'e',
  '\u043E': 'o',
  '\u041E': 'o',
  '\u03BF': 'o',
  '\u039F': 'o',
  '\u0440': 'p',
  '\u0420': 'p',
  '\u0441': 'c',
  '\u0421': 'c',
  '\u0443': 'y',
  '\u0423': 'y',
  '\u0445': 'x',
  '\u0425': 'x',
  '\u0455': 's',
  '\u0405': 's',
  '\u0458': 'j',
  '\u0408': 'j',
  '\u04CF': 'l',
  '\u04C0': 'l',
  '\u0501': 'd',
  '\u0261': 'g',
  '\u0578': 'n',
  '\u03C5': 'u',
  '\u0475': 'v',
};
const CONFUSABLE_CHAR_RE = /[\u0261\u026A\u039F\u03BF\u03C5\u0405\u0406\u0408\u0410\u0415\u041E\u0420\u0421\u0423\u0425\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0455\u0456\u0458\u0475\u04C0\u04CF\u0501\u0578]/g;

const INLINE_SPLIT_TAGS = new Set([
  'a',
  'abbr',
  'b',
  'bdi',
  'bdo',
  'cite',
  'del',
  'dfn',
  'em',
  'font',
  'i',
  'ins',
  'kbd',
  'mark',
  'q',
  's',
  'samp',
  'small',
  'span',
  'strike',
  'strong',
  'sub',
  'sup',
  'time',
  'u',
  'var',
  'wbr',
]);

export function isAsciiWhitespaceCode(c: number): boolean {
  return c === 32 || c === 9 || c === 10 || c === 13;
}

export function trimAsciiWhitespaceLinear(s: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && isAsciiWhitespaceCode(s.charCodeAt(start))) start++;
  while (end > start && isAsciiWhitespaceCode(s.charCodeAt(end - 1))) end--;
  return start === 0 && end === s.length ? s : s.slice(start, end);
}

export function trimTrailingAsciiWhitespaceLinear(s: string): string {
  let end = s.length;
  while (end > 0 && isAsciiWhitespaceCode(s.charCodeAt(end - 1))) end--;
  return end === s.length ? s : s.slice(0, end);
}

const URI_NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  nonbreakingspace: ' ',
  ensp: ' ',
  emsp: ' ',
  thinsp: ' ',
  hairsp: ' ',
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
  shy: '',
  zwj: '',
  zwnj: '',
  zerowidthspace: '',
  negativethinspace: '',
};

function isMarkdownBackslashEscapedAt(str: string, idx: number): boolean {
  let bs = 0;
  let p = idx - 1;
  while (p >= 0 && str.charCodeAt(p) === 92 /* '\\' */) {
    bs++;
    p--;
  }
  return (bs & 1) === 1;
}

function isAsciiPunctCode(c: number): boolean {
  return (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126);
}

function isIgnorableUriCodePoint(cp: number): boolean {
  if (cp <= 0x20 || (cp >= 0x7f && cp <= 0x9f)) return true;
  if (
    cp === 0x00a0 ||
    cp === 0x00ad ||
    cp === 0x061c ||
    cp === 0x1680 ||
    cp === 0x180e ||
    cp === 0x205f ||
    cp === 0x3000 ||
    cp === 0xfeff
  ) {
    return true;
  }
  return (
    (cp >= 0x2000 && cp <= 0x200f) ||
    (cp >= 0x2028 && cp <= 0x202f) ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    (cp >= 0xe0000 && cp <= 0xe01ef)
  );
}

function decodeUriEntitiesLinear(raw: string): string {
  if (!raw.includes('&')) return raw;
  // Collapse arbitrary-depth `&amp;` / `&#38;` / `&#x26;` prefixes in a single O(N) pass
  let cur = raw.replace(/&(?:amp;|#0*38;?|#[xX]0*26;?)+(?=(?:#\d|#[xX][0-9a-fA-F]|[A-Za-z][A-Za-z0-9]{1,20};))/gi, '&');
  for (let pass = 0; pass < 2 && cur.includes('&'); pass++) {
    const next = cur
      .replace(/&#0*(\d{1,10});?/g, (_full, dec: string) => {
        const cp = Number(dec);
        if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return _full;
        return cp === 0 ? '' : String.fromCodePoint(cp);
      })
      .replace(/&#[xX]0*([0-9a-fA-F]{1,8});?/g, (_full, hex: string) => {
        const cp = parseInt(hex, 16);
        if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return _full;
        return cp === 0 ? '' : String.fromCodePoint(cp);
      })
      .replace(/&([A-Za-z][A-Za-z0-9]{1,20});/g, (full, name: string) => {
        const mapped = URI_NAMED_ENTITIES[name.toLowerCase()];
        return mapped !== undefined ? mapped : full;
      });
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

/**
 * Strict fail-closed URI destination allowlist (`H1`):
 * Permits ONLY `https://...`, `http://...`, `mailto:...`, single-slash relative `/...` (never `//` or `/\`),
 * `./...`, `../...`, `#...`, `?...`, or clean relative paths with zero `:` and zero unparsed `&entity` before `/`, `?`, `#`,
 * after stripping Markdown backslash escapes, HTML entities (with or without semicolons), control/whitespace/invisible chars,
 * and unbalanced leading parens/angle brackets.
 */
export function isDisallowedMarkdownLinkDestination(rawHref: string): boolean {
  if (!rawHref) return false;
  if (rawHref.length > 8_192) return true;
  let unescaped = rawHref;
  if (unescaped.includes('\\')) {
    let sb = '';
    for (let i = 0; i < unescaped.length; i++) {
      if (unescaped.charCodeAt(i) === 92 && i + 1 < unescaped.length && isAsciiPunctCode(unescaped.charCodeAt(i + 1))) {
        sb += unescaped[i + 1]!;
        i++;
      } else {
        sb += unescaped[i]!;
      }
    }
    unescaped = sb;
  }
  const decoded = decodeUriEntitiesLinear(unescaped);
  let clean = '';
  let sawDelim = false;
  for (let i = 0; i < decoded.length; ) {
    const cp = decoded.codePointAt(i)!;
    i += cp > 0xffff ? 2 : 1;
    if (isIgnorableUriCodePoint(cp)) continue;
    if (cp === 47 || cp === 63 || cp === 35 || cp === 58) {
      sawDelim = true;
    }
    clean += String.fromCodePoint(cp);
    if (clean.length >= 256 && sawDelim) {
      break;
    }
    if (clean.length > 4_096) {
      return true;
    }
  }
  // Strip any unbalanced leading `(` or `<` wrappers so `((javascript:alert(1)))` / `(<javascript:...` cannot hide a scheme
  let start = 0;
  while (start < clean.length && (clean.charCodeAt(start) === 40 || clean.charCodeAt(start) === 60)) {
    start++;
  }
  if (start > 0) clean = clean.slice(start);
  if (!clean) return false;

  // Protocol-relative `//evil.example` or `/\evil.example` is disallowed
  if (clean.charCodeAt(0) === 47 /* '/' */) {
    if (clean.length > 1 && (clean.charCodeAt(1) === 47 || clean.charCodeAt(1) === 92)) {
      return true;
    }
    return false;
  }
  if (clean.charCodeAt(0) === 35 /* '#' */ || clean.charCodeAt(0) === 63 /* '?' */) {
    return false;
  }
  if (clean.startsWith('./') || clean.startsWith('../')) {
    return false;
  }

  let firstDelim = clean.length;
  let colonIdx = -1;
  for (let i = 0; i < clean.length; i++) {
    const c = clean.charCodeAt(i);
    if (c === 47 /* '/' */ || c === 63 /* '?' */ || c === 35 /* '#' */) {
      firstDelim = i;
      break;
    }
    if (c === 58 /* ':' */ && colonIdx < 0) {
      colonIdx = i;
    }
  }

  const beforeDelim = clean.slice(0, firstDelim);
  if (colonIdx >= 0 && colonIdx < firstDelim) {
    const scheme = clean.slice(0, colonIdx).toLowerCase();
    if (scheme === 'https') {
      return !(clean.slice(colonIdx, colonIdx + 3) === '://' && clean.length > colonIdx + 3);
    }
    if (scheme === 'http') {
      return !(clean.slice(colonIdx, colonIdx + 3) === '://' && clean.length > colonIdx + 3);
    }
    if (scheme === 'mailto') {
      return clean.length <= colonIdx + 1;
    }
    return true;
  }

  // Block residual unparsed entity-like `&...` before path/query/hash delimiter
  const ampIdx = beforeDelim.indexOf('&');
  if (ampIdx >= 0) {
    const afterAmp = beforeDelim.charCodeAt(ampIdx + 1);
    if (
      afterAmp === 35 /* '#' */ ||
      (afterAmp >= 65 && afterAmp <= 90) ||
      (afterAmp >= 97 && afterAmp <= 122)
    ) {
      return true;
    }
  }
  return false;
}

function skipOptionalMdContinuationPrefix(s: string, nlPos: number): number {
  let p = nlPos + 1;
  let steps = 0;
  while (p < s.length && steps < 64) {
    const c = s.charCodeAt(p);
    if (c === 32 || c === 9 || c === 62 /* '>' */) {
      p++;
      steps++;
      continue;
    }
    break;
  }
  const listMatch = /^(?:[-*+][ \t]{1,8}|\d{1,9}[.)][ \t]{1,8})/.exec(s.slice(p, p + 24));
  if (listMatch) p += listMatch[0].length;
  return p;
}

function consumeOptionalMdTitle(s: string, pos: number): number {
  let ws = pos;
  while (ws < s.length && (s.charCodeAt(ws) === 32 || s.charCodeAt(ws) === 9 || s.charCodeAt(ws) === 10 || s.charCodeAt(ws) === 13)) {
    ws++;
  }
  if (ws > pos && ws < s.length && (s.charCodeAt(ws) === 34 || s.charCodeAt(ws) === 39)) {
    const q = s.charCodeAt(ws);
    const lim = Math.min(s.length, ws + 512);
    for (let p = ws + 1; p < lim; p++) {
      if (s.charCodeAt(p) === 92) {
        p++;
        continue;
      }
      if (s.charCodeAt(p) === q) {
        let after = p + 1;
        while (after < s.length && (s.charCodeAt(after) === 32 || s.charCodeAt(after) === 9 || s.charCodeAt(after) === 10 || s.charCodeAt(after) === 13)) {
          after++;
        }
        return after;
      }
    }
  }
  return ws;
}

function scanDestinationTokenEndAndCheckUnsafe(
  s: string,
  destStart: number,
  isInlineParen: boolean,
): { unsafe: boolean; tokenEnd: number; closeParenPos: number } {
  const n = s.length;
  if (destStart >= n) return { unsafe: false, tokenEnd: destStart, closeParenPos: -1 };
  const angle = s.charCodeAt(destStart) === 60 /* '<' */;
  const maxAngleScan = Math.min(n, destStart + 4_097);
  if (angle) {
    let p = destStart + 1;
    while (p < maxAngleScan) {
      const c = s.charCodeAt(p);
      if (c === 92 && p + 1 < maxAngleScan) {
        p += 2;
        continue;
      }
      if (c === 62 /* '>' */) {
        const inner = s.slice(destStart + 1, p);
        const unsafe = isDisallowedMarkdownLinkDestination(inner);
        if (!unsafe) return { unsafe: false, tokenEnd: p + 1, closeParenPos: -1 };
        const afterTitle = consumeOptionalMdTitle(s, p + 1);
        const closeParenPos = isInlineParen && afterTitle < n && s.charCodeAt(afterTitle) === 41 ? afterTitle : -1;
        return { unsafe: true, tokenEnd: closeParenPos >= 0 ? closeParenPos : p + 1, closeParenPos };
      }
      if (c === 60 || c === 10 || c === 13) break;
      p++;
    }
    if (p >= maxAngleScan && maxAngleScan < n) {
      return { unsafe: true, tokenEnd: p, closeParenPos: -1 };
    }
    // Unclosed `<...` destination: check token up to whitespace/EOL/`)`/`](`
    let fallbackEnd = destStart + 1;
    while (fallbackEnd < maxAngleScan) {
      const fc = s.charCodeAt(fallbackEnd);
      if (fc === 32 || fc === 9 || fc === 10 || fc === 13 || fc === 41) break;
      if (fc === 93 && fallbackEnd + 1 < n && s.charCodeAt(fallbackEnd + 1) === 40) break;
      if (fc === 91 && fallbackEnd > destStart + 1) {
        // Stop before a subsequent `[label](`
        const closeBr = s.indexOf('](', fallbackEnd + 1);
        if (closeBr > fallbackEnd && closeBr - fallbackEnd <= 256) break;
      }
      fallbackEnd++;
    }
    if (fallbackEnd >= maxAngleScan && maxAngleScan < n) {
      return { unsafe: true, tokenEnd: fallbackEnd, closeParenPos: -1 };
    }
    const rawUnclosed = s.slice(destStart + 1, fallbackEnd);
    if (isDisallowedMarkdownLinkDestination(rawUnclosed)) {
      const closeParenPos = isInlineParen && fallbackEnd < n && s.charCodeAt(fallbackEnd) === 41 ? fallbackEnd : -1;
      return { unsafe: true, tokenEnd: fallbackEnd, closeParenPos };
    }
    return { unsafe: false, tokenEnd: fallbackEnd, closeParenPos: -1 };
  }

  // Fast O(1) first-byte rejection on `](](](...` so `']('.repeat(3_500_000) + ':'` never scans ahead
  const firstCode = s.charCodeAt(destStart);
  if (firstCode === 93 /* ']' */ || firstCode === 91 /* '[' */ || firstCode === 41 /* ')' */ || firstCode === 96 /* '`' */) {
    return { unsafe: false, tokenEnd: destStart, closeParenPos: -1 };
  }

  let p = destStart;
  let depth = 0;
  const maxRawScan = Math.min(n, destStart + 4_097);
  while (p < maxRawScan) {
    const c = s.charCodeAt(p);
    if (c === 92 && p + 1 < n) {
      p += 2;
      continue;
    }
    if (c === 32 || c === 9 || c === 10 || c === 13) break;
    if (c === 93 && p + 1 < n && (s.charCodeAt(p + 1) === 40 || s.charCodeAt(p + 1) === 58)) {
      break;
    }
    if (c === 91 && p > destStart) {
      const nextBp = s.indexOf('](', p + 1);
      if (nextBp > p && nextBp - p <= 256 && !s.slice(p, nextBp).includes('\n')) {
        break;
      }
    }
    if (c === 40 /* '(' */) {
      depth++;
      if (depth > 8) break;
    } else if (c === 41 /* ')' */) {
      if (!isInlineParen && depth === 0) {
        p++;
        continue;
      }
      if (depth === 0) break;
      depth--;
    }
    p++;
  }
  if (p >= maxRawScan && maxRawScan < n) {
    return { unsafe: true, tokenEnd: p, closeParenPos: -1 };
  }
  if (p <= destStart) return { unsafe: false, tokenEnd: destStart, closeParenPos: -1 };
  const rawToken = s.slice(destStart, p);
  if (!isDisallowedMarkdownLinkDestination(rawToken)) {
    return { unsafe: false, tokenEnd: p, closeParenPos: -1 };
  }
  const afterTitle = isInlineParen ? consumeOptionalMdTitle(s, p) : p;
  const closeParenPos = isInlineParen && afterTitle < n && s.charCodeAt(afterTitle) === 41 ? afterTitle : -1;
  return { unsafe: true, tokenEnd: closeParenPos >= 0 ? closeParenPos : p, closeParenPos };
}

function isAsciiAlphaCode(c: number): boolean {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

function isAsciiAlnumCode(c: number): boolean {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

function isHostLabelCharCode(c: number): boolean {
  return isAsciiAlnumCode(c) || c === 45 /* '-' */ || c >= 0x80;
}

/**
 * Escapes bare protocol-relative `//host` tokens in prose (`\//host`) — including punycode `.xn--*`, 1-char TLDs (or
 * bounded `sanitizeMarkdownPageSlice` windows like `//sub.example.c`), `//localhost`, `//[::1]`, and Unicode IDNs — so
 * `markdown-it({ linkify: true })` never emits protocol-relative `<a href="//...">`, while leaving `https://...`,
 * `// comments`, `//TODO:`, and `///paths` untouched.
 */
function escapeBareProtocolRelativeUrlsLinear(prose: string): string {
  let searchFrom = prose.indexOf('//');
  if (searchFrom < 0) return prose;
  const n = prose.length;
  let out = '';
  let last = 0;
  let changed = false;

  while (searchFrom >= 0 && searchFrom < n) {
    const idx = searchFrom;
    if (idx >= 2 && prose.charCodeAt(idx - 1) === 58 /* ':' */ && isAsciiAlphaCode(prose.charCodeAt(idx - 2))) {
      searchFrom = prose.indexOf('//', idx + 2);
      continue;
    }
    if (idx >= 1) {
      const prev = prose.charCodeAt(idx - 1);
      if (prev === 47 /* '/' */ || prev === 92 /* '\\' */ || prev === 95 /* '_' */ || prev >= 0x80 || isAsciiAlnumCode(prev)) {
        searchFrom = prose.indexOf('//', idx + 2);
        continue;
      }
    }
    const hostStart = idx + 2;
    if (hostStart < n) {
      const firstCode = prose.charCodeAt(hostStart);
      let matchedEnd = -1;

      if (firstCode === 91 /* '[' — IPv6 literal //[::1] */) {
        const ipv6Limit = Math.min(n, hostStart + 64);
        for (let q = hostStart + 1; q < ipv6Limit; q++) {
          const qc = prose.charCodeAt(q);
          if (qc === 93 /* ']' */ && q > hostStart + 1) {
            matchedEnd = q + 1;
            break;
          }
          if (!((qc >= 48 && qc <= 57) || (qc >= 65 && qc <= 70) || (qc >= 97 && qc <= 102) || qc === 58 || qc === 46)) {
            break;
          }
        }
      } else if (firstCode !== 45 /* '-' */ && isHostLabelCharCode(firstCode)) {
        if (
          hostStart + 9 <= n &&
          prose.slice(hostStart, hostStart + 9).toLowerCase() === 'localhost' &&
          (hostStart + 9 === n || !isHostLabelCharCode(prose.charCodeAt(hostStart + 9)))
        ) {
          matchedEnd = hostStart + 9;
        } else {
          let p = hostStart;
          const limit = Math.min(n, hostStart + 253);
          let sawValidDot = false;
          let validLabels = true;
          let lastValidMultiEnd = -1;
          while (p < limit) {
            const hc = prose.charCodeAt(p);
            if (isHostLabelCharCode(hc)) {
              if (sawValidDot && hc !== 45 /* '-' */) {
                lastValidMultiEnd = p + 1;
              }
              p++;
              continue;
            }
            if (hc === 46 /* '.' */) {
              if (p === hostStart || prose.charCodeAt(p - 1) === 46 || prose.charCodeAt(p - 1) === 45) {
                validLabels = false;
                break;
              }
              if (p + 1 >= limit || prose.charCodeAt(p + 1) === 45 || !isHostLabelCharCode(prose.charCodeAt(p + 1))) {
                break;
              }
              sawValidDot = true;
              p++;
              continue;
            }
            break;
          }
          if (validLabels && sawValidDot) {
            if (prose.charCodeAt(p - 1) !== 45) {
              matchedEnd = p;
            } else if (lastValidMultiEnd > hostStart) {
              matchedEnd = lastValidMultiEnd;
            }
          }
        }
      }

      if (matchedEnd > hostStart) {
        out += `${prose.slice(last, idx)}\\`;
        last = idx;
        changed = true;
        searchFrom = prose.indexOf('//', matchedEnd);
        continue;
      }
    }
    searchFrom = prose.indexOf('//', idx + 2);
  }

  return !changed ? prose : out + prose.slice(last);
}

/**
 * Strictly linear **O(N)** fail-closed link & reference-definition neutralizer (`H1` & `H8`):
 * Neutralizes ALL disallowed `](...)` inline destinations, `[id]: ...` reference definitions, and bare `//host.tld`
 * linkify targets EVERYWHERE in `prose` — **including inside inline backtick code spans `` `...` ``** — so parser
 * backtick disagreements can NEVER expose `javascript:`, `vbscript:`, `data:`, `file:`, `blob:`, `//evil`, or custom URI schemes.
 */
export function neutralizeAllUnsafeMarkdownLinksLinear(prose: string): string {
  if (!prose) return prose;
  const hasInline = prose.includes('](');
  const hasRef = prose.includes(']:');
  const hasDoubleSlash = prose.includes('//');
  if (!hasInline && !hasRef) {
    return hasDoubleSlash ? escapeBareProtocolRelativeUrlsLinear(prose) : prose;
  }
  if (!prose.includes(':') && !prose.includes('&') && !prose.includes('\\') && !hasDoubleSlash) {
    return prose;
  }

  let out = '';
  let last = 0;
  let i = 0;
  const n = prose.length;

  while (i < n - 1) {
    const nextBracket = prose.indexOf(']', i);
    if (nextBracket < 0 || nextBracket >= n - 1) break;
    i = nextBracket;
    if (!isMarkdownBackslashEscapedAt(prose, i)) {
      const nx = prose.charCodeAt(i + 1);
      if (nx === 40 /* '(' */) {
        let k = i + 2;
        while (k < n && (prose.charCodeAt(k) === 32 || prose.charCodeAt(k) === 9 || prose.charCodeAt(k) === 13 || prose.charCodeAt(k) === 10)) {
          if (prose.charCodeAt(k) === 10) {
            k = skipOptionalMdContinuationPrefix(prose, k);
            continue;
          }
          k++;
        }
        const check = scanDestinationTokenEndAndCheckUnsafe(prose, k, true);
        if (check.unsafe) {
          // If this was a dangerous image `![alt](unsafe)`, drop the `!` before `[alt]` so no `<img>` element is emitted
          let bangPos = -1;
          const searchFloor = Math.max(last, i - 1005);
          for (let b = i - 1; b >= searchFloor; b--) {
            const bc = prose.charCodeAt(b);
            if (bc === 91 /* '[' */ && !isMarkdownBackslashEscapedAt(prose, b)) {
              if (b > last && prose.charCodeAt(b - 1) === 33 /* '!' */ && !isMarkdownBackslashEscapedAt(prose, b - 1)) {
                bangPos = b - 1;
              }
              break;
            }
          }
          if (bangPos >= last) {
            out += `${prose.slice(last, bangPos)}${prose.slice(bangPos + 1, i + 2)}#)`;
          } else {
            out += `${prose.slice(last, i + 2)}#)`;
          }
          i = check.closeParenPos >= 0 ? check.closeParenPos + 1 : check.tokenEnd;
          last = i;
          continue;
        }
      } else if (nx === 58 /* ':' */) {
        let k = i + 2;
        while (k < n && (prose.charCodeAt(k) === 32 || prose.charCodeAt(k) === 9 || prose.charCodeAt(k) === 13)) k++;
        if (k < n && prose.charCodeAt(k) === 10) {
          k = skipOptionalMdContinuationPrefix(prose, k);
        }
        const check = scanDestinationTokenEndAndCheckUnsafe(prose, k, false);
        if (check.unsafe) {
          out += `${prose.slice(last, i + 1)}: #`;
          i = check.tokenEnd;
          last = i;
          continue;
        }
      }
    }
    i++;
  }

  const res = last === 0 ? prose : out + prose.slice(last);
  return res.includes('//') ? escapeBareProtocolRelativeUrlsLinear(res) : res;
}

/**
 * Escapes GFM task-list checkboxes (`- [ ] `, `* [x] `, `1. [X] `, including nested lists `1. - [ ] ` and blockquotes `> - [ ] `)
 * to `\[ ]` so `marked` / GFM renderers never emit raw `<input type="checkbox">` elements.
 */
export function escapeGfmTaskListCheckboxesLinear(prose: string): string {
  if (!prose || !prose.includes('[')) return prose;
  const lines = prose.split('\n');
  let changed = false;
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    if (!line.includes('[')) continue;
    let i = 0;
    const n = line.length;
    let sawListMarker = false;
    while (i < n) {
      let cols = 0;
      let j = i;
      while (j < n) {
        const c = line.charCodeAt(j);
        if (c === 32) {
          cols++;
          j++;
        } else if (c === 9) {
          cols += 4 - (cols % 4);
          j++;
        } else {
          break;
        }
      }
      if (!sawListMarker && cols > 3) break;
      if (j >= n) {
        i = j;
        break;
      }
      const mc = line.charCodeAt(j);
      if (cols <= 3 && mc === 62 /* '>' */) {
        i = j + 1;
        if (i < n && (line.charCodeAt(i) === 32 || line.charCodeAt(i) === 9)) i++;
        continue;
      }
      if ((mc === 45 || mc === 42 || mc === 43) && j + 1 < n && (line.charCodeAt(j + 1) === 32 || line.charCodeAt(j + 1) === 9)) {
        sawListMarker = true;
        i = j + 2;
        continue;
      }
      if (mc >= 48 && mc <= 57) {
        let d = j;
        while (d < n && d - j < 9 && line.charCodeAt(d) >= 48 && line.charCodeAt(d) <= 57) d++;
        if (d > j && d + 1 < n && (line.charCodeAt(d) === 46 || line.charCodeAt(d) === 41) && (line.charCodeAt(d + 1) === 32 || line.charCodeAt(d + 1) === 9)) {
          sawListMarker = true;
          i = d + 2;
          continue;
        }
      }
      i = j;
      break;
    }
    if (!sawListMarker) continue;
    if (
      i + 3 <= n &&
      line.charCodeAt(i) === 91 /* '[' */ &&
      (line.charCodeAt(i + 1) === 32 || line.charCodeAt(i + 1) === 120 || line.charCodeAt(i + 1) === 88) &&
      line.charCodeAt(i + 2) === 93 /* ']' */ &&
      (i + 3 === n || line.charCodeAt(i + 3) === 32 || line.charCodeAt(i + 3) === 9 || line.charCodeAt(i + 3) === 13)
    ) {
      lines[li] = `${line.slice(0, i)}\\[${line.slice(i + 1)}`;
      changed = true;
    }
  }
  return changed ? lines.join('\n') : prose;
}

/**
 * Unconditional fail-closed `<` escape pass (`H1`):
 * Outside recognized CommonMark fenced code blocks, escapes **EVERY** `<` to `&lt;` — **including inside inline backtick
 * code spans `` `...` ``** — preserving ONLY strictly verified `<!-- page \d{1,6} -->` / `<!-- pdf-page: \d{1,6} -->`
 * markers on their own line when `allowPdfPageMarkers === true`.
 */
function replaceAllLtLinearFast(s: string): string {
  const first = s.indexOf('<');
  if (first < 0) return s;
  const n = s.length;
  const parts: string[] = [];
  let pos = 0;
  let lt = first;
  while (lt >= 0) {
    if (lt > pos) parts.push(s.slice(pos, lt));
    let runEnd = lt + 1;
    while (runEnd < n && s.charCodeAt(runEnd) === 60 /* '<' */) runEnd++;
    const runLen = runEnd - lt;
    parts.push(runLen === 1 ? '&lt;' : '&lt;'.repeat(runLen));
    pos = runEnd;
    if (pos >= n) break;
    lt = s.indexOf('<', pos);
  }
  if (pos < n) parts.push(s.slice(pos));
  return parts.length === 1 ? parts[0]! : parts.join('');
}

export function escapeAllResidualLtInProseLinear(prose: string, allowPdfPageMarkers = false): string {
  if (!prose || !prose.includes('<')) return prose;
  if (!allowPdfPageMarkers) {
    return replaceAllLtLinearFast(prose);
  }
  const lines = prose.split('\n');
  let changed = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!line.includes('<')) continue;
    const trimmed = trimAsciiWhitespaceLinear(line);
    if (/^<!-- (?:page |pdf-page: )\d{1,6} -->$/.test(trimmed)) {
      continue;
    }
    lines[i] = replaceAllLtLinearFast(line);
    changed = true;
  }
  return changed ? lines.join('\n') : prose;
}

function isThematicBreakForSlice(raw: string, leadCols: number, leadPos: number): boolean {
  if (leadCols > 3 || leadPos >= raw.length) return false;
  const ch = raw.charCodeAt(leadPos);
  if (ch !== 45 /* '-' */ && ch !== 42 /* '*' */ && ch !== 95 /* '_' */) return false;
  let count = 0;
  for (let i = leadPos; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c === ch) count++;
    else if (c !== 32 && c !== 9) return false;
  }
  return count >= 3;
}

function isParagraphBreakLineForSafeSpans(
  line: string,
  prevInBq: boolean,
  prevInList: boolean,
): { kind: 'blank_or_atomic' | 'block_start' | 'atx_heading' | 'none'; inBq: boolean; inList: boolean } {
  const { cols, bytePos, isBlank } = measureSliceIndentCols(line);
  if (isBlank) return { kind: 'blank_or_atomic', inBq: false, inList: false };
  const c = line.charCodeAt(bytePos);
  if (cols <= 3) {
    if (c === 35 /* '#' */) {
      let h = bytePos;
      while (h < line.length && line.charCodeAt(h) === 35 && h - bytePos < 7) h++;
      if (h - bytePos <= 6 && (h >= line.length || line.charCodeAt(h) === 32 || line.charCodeAt(h) === 13)) {
        return { kind: 'atx_heading', inBq: false, inList: false };
      }
    }
    if (c === 62 /* '>' */) {
      let q = bytePos;
      while (q < line.length && (line.charCodeAt(q) === 62 || line.charCodeAt(q) === 32 || line.charCodeAt(q) === 9 || line.charCodeAt(q) === 13)) q++;
      if (q === line.length) return { kind: 'blank_or_atomic', inBq: false, inList: false };
      return { kind: prevInBq ? 'none' : 'block_start', inBq: true, inList: false };
    }
    if (isThematicBreakForSlice(line, cols, bytePos)) {
      return { kind: 'blank_or_atomic', inBq: false, inList: false };
    }
    if (!prevInBq && !prevInList && (c === 61 || c === 45)) {
      let p = bytePos;
      while (p < line.length && line.charCodeAt(p) === c) p++;
      while (p < line.length && (line.charCodeAt(p) === 32 || line.charCodeAt(p) === 9 || line.charCodeAt(p) === 13)) p++;
      if (p === line.length) return { kind: 'blank_or_atomic', inBq: false, inList: false };
    }
    if ((c === 45 || c === 42 || c === 43) && bytePos + 1 < line.length && line.charCodeAt(bytePos + 1) === 32) {
      let p = bytePos + 2;
      while (p < line.length && (line.charCodeAt(p) === 32 || line.charCodeAt(p) === 9 || line.charCodeAt(p) === 13)) p++;
      if (p < line.length) {
        return { kind: 'block_start', inBq: false, inList: true };
      }
    }
    if (
      c === 49 /* '1' */ &&
      bytePos + 2 < line.length &&
      (line.charCodeAt(bytePos + 1) === 46 || line.charCodeAt(bytePos + 1) === 41) &&
      line.charCodeAt(bytePos + 2) === 32
    ) {
      let p = bytePos + 3;
      while (p < line.length && (line.charCodeAt(p) === 32 || line.charCodeAt(p) === 9 || line.charCodeAt(p) === 13)) p++;
      if (p < line.length) {
        return { kind: 'block_start', inBq: false, inList: true };
      }
    }
  }
  return { kind: 'none', inBq: prevInBq, inList: prevInList };
}

function hasUnclosedOpenBracketOnLine(line: string, upTo: number): boolean {
  let depth = 0;
  for (let i = 0; i < upTo; i++) {
    const c = line.charCodeAt(i);
    if (c === 92 /* '\\' */) {
      i++;
      continue;
    }
    if (c === 91 /* '[' */) {
      depth++;
    } else if (c === 93 /* ']' */ && depth > 0) {
      // Only consider `[` closed if immediately completed as `[label](...)` on the same prefix;
      // bare `[ref]` could still pair with `[second]` or reference syntax across spans in `marked`.
      if (i + 1 < upTo && line.charCodeAt(i + 1) === 40 /* '(' */) {
        const closeParen = line.indexOf(')', i + 2);
        if (closeParen > i + 1 && closeParen < upTo) {
          depth--;
          i = closeParen;
          continue;
        }
      }
    }
  }
  return depth > 0;
}

/**
 * Preserves intact `<` ONLY inside provably unambiguous single-line paired backtick code spans
 * (e.g. `` `Vec<T>` ``, `` `Map<K, V>` ``, `` `Promise<Response>` ``, `` `<script>` `` in prose code documentation)
 * while escaping `<` -> `&lt;` everywhere else outside fenced code blocks (`Round 9 Item 2`).
 *
 * All 6 Markdown dialect families (`CommonMark`, `GFM`, `marked`, `markdown-it`, `goldmark`, `showdown_regex`) agree
 * 100% on a code span `[openTick, closeTick]` when ALL hold:
 *  1. The paragraph is NOT tick-poisoned by an earlier line, and every backtick run on `line` has exact length `1`
 *     (`k === 1`) and pairs cleanly on `line` (`tickPositions.length % 2 === 0`, non-empty interior).
 *  2. Zero `\` immediately precedes ANY backtick on `line` (nor ends any span interior before closing `` ` ``).
 *  3. Zero link-crossing ambiguity (`paraHasUnclosedBracket` or unclosed `[` before the span when `]`, `](`, `][`, or `]:`
 *     appears inside/after the span, and zero `[` or `]` inside the span when `](` / `][` / `]:` exists on the line/paragraph).
 *  4. If `line` contains `|` (potential GFM table row), ZERO code spans on `line` contain `|`.
 *  5. Not glued to bare URLs (`https://`, `http://`, `ftp://`, `www.`), `~`, or matching `*`/`_`, and interior contains
 *     no `<!--`, `-->`, `<?`, `<![`, or disallowed `](scheme:...)` links.
 */
export function escapeResidualLtPreservingSafeCodeSpansLinear(prose: string, allowPdfPageMarkers = false): string {
  if (!prose || !prose.includes('<')) return prose;
  if (!prose.includes('`')) {
    return escapeAllResidualLtInProseLinear(prose, allowPdfPageMarkers);
  }

  const lines = prose.split('\n');
  let paraTickPoisoned = false;
  let paraHasOpenBracket = false;
  let paraHasLinkContinuation = false;
  let inBq = false;
  let inList = false;
  let anyChanged = false;

  // Pre-scan paragraph link continuation (`](`, `][`, `]:`) per line for cross-line `[foo \`bar\`\n](baz)` guard
  const lineHasLinkTail = new Uint8Array(lines.length);
  for (let li = 0; li < lines.length; li++) {
    const ln = lines[li]!;
    if (ln.includes('](') || ln.includes('][') || ln.includes(']:')) {
      lineHasLinkTail[li] = 1;
    }
  }

  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    const brk = isParagraphBreakLineForSafeSpans(line, inBq, inList);
    inBq = brk.inBq;
    inList = brk.inList;
    if (brk.kind === 'blank_or_atomic' || brk.kind === 'block_start' || brk.kind === 'atx_heading') {
      paraTickPoisoned = false;
      paraHasOpenBracket = false;
      // Check if any subsequent line in this new paragraph has `](` / `][` / `]:`
      paraHasLinkContinuation = lineHasLinkTail[li] === 1;
      for (let look = li + 1; look < Math.min(lines.length, li + 32); look++) {
        const lb = isParagraphBreakLineForSafeSpans(lines[look]!, inBq, inList);
        if (lb.kind !== 'none') break;
        if (lineHasLinkTail[look] === 1) {
          paraHasLinkContinuation = true;
          break;
        }
      }
    }

    if (allowPdfPageMarkers && line.includes('<')) {
      const trimmed = trimAsciiWhitespaceLinear(line);
      if (/^<!-- (?:page |pdf-page: )\d{1,6} -->$/.test(trimmed)) {
        continue;
      }
    }

    const hasTick = line.includes('`');
    if (!hasTick) {
      if (hasUnclosedOpenBracketOnLine(line, line.length)) {
        paraHasOpenBracket = true;
      }
      if (line.includes('<')) {
        const escaped = replaceAllLtLinearFast(line);
        if (escaped !== line) {
          lines[li] = escaped;
          anyChanged = true;
        }
      }
      if (brk.kind === 'atx_heading') {
        paraTickPoisoned = false;
        paraHasOpenBracket = false;
      }
      continue;
    }

    // Scan backtick runs on `line` to verify `paraTickPoisoned` & `k === 1` pairing
    let lineAllSinglePaired = !paraTickPoisoned;
    const singleTicks: number[] = [];
    if (lineAllSinglePaired) {
      let p = 0;
      while (p < line.length) {
        const idx = line.indexOf('`', p);
        if (idx < 0) break;
        if (idx > 0 && line.charCodeAt(idx - 1) === 92 /* '\\' */) {
          lineAllSinglePaired = false;
          paraTickPoisoned = true;
          break;
        }
        let end = idx + 1;
        while (end < line.length && line.charCodeAt(end) === 96) end++;
        if (end - idx !== 1) {
          lineAllSinglePaired = false;
          // Check CommonMark pairing to know whether subsequent lines in paragraph are tick-poisoned
          const runLen = end - idx;
          let search = end;
          let matched = false;
          while (search < line.length) {
            const h = line.indexOf('`', search);
            if (h < 0) break;
            let he = h + 1;
            while (he < line.length && line.charCodeAt(he) === 96) he++;
            if (he - h === runLen && (h === 0 || line.charCodeAt(h - 1) !== 92)) {
              matched = true;
              p = he;
              break;
            }
            search = he;
          }
          if (!matched) {
            paraTickPoisoned = true;
          }
          break;
        }
        singleTicks.push(idx);
        p = end;
      }
      if (lineAllSinglePaired && (singleTicks.length < 2 || (singleTicks.length & 1) === 1)) {
        lineAllSinglePaired = false;
        paraTickPoisoned = true;
      }
    } else {
      paraTickPoisoned = true;
    }

    if (!line.includes('<')) {
      if (hasUnclosedOpenBracketOnLine(line, line.length)) {
        paraHasOpenBracket = true;
      }
      if (brk.kind === 'atx_heading') {
        paraTickPoisoned = false;
        paraHasOpenBracket = false;
      }
      continue;
    }

    if (!lineAllSinglePaired) {
      if (hasUnclosedOpenBracketOnLine(line, line.length)) {
        paraHasOpenBracket = true;
      }
      const escaped = replaceAllLtLinearFast(line);
      if (escaped !== line) {
        lines[li] = escaped;
        anyChanged = true;
      }
      if (brk.kind === 'atx_heading') {
        paraTickPoisoned = false;
        paraHasOpenBracket = false;
      }
      continue;
    }

    const lineHasPipe = line.includes('|');
    let anySpanHasPipe = false;
    if (lineHasPipe) {
      for (let si = 0; si < singleTicks.length; si += 2) {
        if (line.slice(singleTicks[si]! + 1, singleTicks[si + 1]!).includes('|')) {
          anySpanHasPipe = true;
          break;
        }
      }
    }

    // Also check if any link destination/title on `line` outside spans contains a backtick (which poisons pairing)
    let linkContainsTick = false;
    for (let si = 0; si <= singleTicks.length; si += 2) {
      const prevClose = si === 0 ? 0 : singleTicks[si - 1]! + 1;
      const nextOpen = si < singleTicks.length ? singleTicks[si]! : line.length;
      const outsideSeg = line.slice(prevClose, nextOpen);
      if (outsideSeg.includes('](') && si < singleTicks.length) {
        const bpIdx = outsideSeg.lastIndexOf('](');
        if (!outsideSeg.slice(bpIdx + 2).includes(')')) {
          // Unclosed `](` right before a backtick!
          linkContainsTick = true;
          paraTickPoisoned = true;
          break;
        }
      }
    }

    if (linkContainsTick || (lineHasPipe && anySpanHasPipe)) {
      if (hasUnclosedOpenBracketOnLine(line, line.length)) paraHasOpenBracket = true;
      const escaped = replaceAllLtLinearFast(line);
      if (escaped !== line) {
        lines[li] = escaped;
        anyChanged = true;
      }
      if (brk.kind === 'atx_heading') {
        paraTickPoisoned = false;
        paraHasOpenBracket = false;
      }
      continue;
    }

    const lineHasLinkSyntax = lineHasLinkTail[li] === 1 || paraHasLinkContinuation;
    let out = '';
    let cursor = 0;
    for (let si = 0; si < singleTicks.length; si += 2) {
      const openIdx = singleTicks[si]!;
      const closeIdx = singleTicks[si + 1]!;
      out += replaceAllLtLinearFast(line.slice(cursor, openIdx));

      const inner = line.slice(openIdx + 1, closeIdx);
      let spanSafe = inner.length > 0;
      if (spanSafe && inner.includes('<')) {
        // Check backslash before closing tick (already checked in loop, double-verify)
        if (line.charCodeAt(closeIdx - 1) === 92 /* '\\' */) spanSafe = false;
        // Check tilde or emphasis adjacency
        if (spanSafe && openIdx > 0) {
          const prevC = line.charCodeAt(openIdx - 1);
          if (prevC === 126 /* '~' */) spanSafe = false;
          if ((prevC === 42 /* '*' */ || prevC === 95 /* '_' */) && inner.includes(prevC === 42 ? '*' : '_')) {
            spanSafe = false;
          }
          // Glued bare URL check (`https://x\`...`)
          if (prevC > 32 && prevC !== 40 && prevC !== 91 && prevC !== 34 && prevC !== 39) {
            const beforeSlice = line.slice(Math.max(0, openIdx - 256), openIdx);
            if (/(?:https?:\/\/|ftp:\/\/|www\.)\S*$/i.test(beforeSlice)) {
              spanSafe = false;
            }
          }
        }
        if (spanSafe && closeIdx + 1 < line.length && line.charCodeAt(closeIdx + 1) === 126 /* '~' */) {
          spanSafe = false;
        }
        // Check HTML comment / PI / CDATA openers inside span
        if (spanSafe && (inner.includes('<!--') || inner.includes('-->') || inner.includes('<?') || inner.includes('<![') || inner.includes('](') || inner.includes('][') || inner.includes(']:'))) {
          spanSafe = false;
        }
        // Check `marked` / `showdown` link-before-codespan disagreement
        if (spanSafe) {
          const unclosedBefore = paraHasOpenBracket || hasUnclosedOpenBracketOnLine(line, openIdx);
          if (unclosedBefore && (inner.includes(']') || lineHasLinkSyntax || line.indexOf(']', closeIdx + 1) >= 0)) {
            spanSafe = false;
          } else if ((inner.includes('[') || inner.includes(']')) && lineHasLinkSyntax) {
            spanSafe = false;
          }
        }
      }

      if (spanSafe) {
        out += line.slice(openIdx, closeIdx + 1);
      } else {
        out += `\`${replaceAllLtLinearFast(inner)}\``;
      }
      cursor = closeIdx + 1;
    }
    out += replaceAllLtLinearFast(line.slice(cursor));

    if (hasUnclosedOpenBracketOnLine(line, line.length)) {
      paraHasOpenBracket = true;
    }
    if (out !== line) {
      lines[li] = out;
      anyChanged = true;
    }
    if (brk.kind === 'atx_heading') {
      paraTickPoisoned = false;
      paraHasOpenBracket = false;
    }
  }

  return anyChanged ? lines.join('\n') : prose;
}

function measureSliceIndentCols(raw: string): { cols: number; bytePos: number; isBlank: boolean } {
  let cols = 0;
  let i = 0;
  while (i < raw.length) {
    const ch = raw.charCodeAt(i);
    if (ch === 32) {
      cols++;
      i++;
    } else if (ch === 9) {
      cols += 4 - (cols % 4);
      i++;
    } else {
      break;
    }
  }
  return { cols, bytePos: i, isBlank: i >= raw.length };
}

function detectSliceListItemContentCol(raw: string, leadCols: number, leadPos: number, prevLineWasParagraph = false): number {
  if (leadCols > 3 || leadPos >= raw.length) return 0;
  if (isThematicBreakForSlice(raw, leadCols, leadPos)) return 0;
  const c = raw.charCodeAt(leadPos);
  let markerEnd = -1;
  let markerWidth = 0;
  let isOrdered = false;
  let isOrderedOne = false;
  if (c === 45 || c === 42 || c === 43) {
    markerEnd = leadPos + 1;
    markerWidth = 1;
  } else if (c >= 48 && c <= 57) {
    isOrdered = true;
    let d = leadPos + 1;
    while (d < raw.length && d - leadPos < 9 && raw.charCodeAt(d) >= 48 && raw.charCodeAt(d) <= 57) d++;
    if (d < raw.length && (raw.charCodeAt(d) === 46 || raw.charCodeAt(d) === 41)) {
      markerEnd = d + 1;
      markerWidth = markerEnd - leadPos;
      isOrderedOne = d === leadPos + 1 && c === 49 /* '1' */;
    }
  }
  if (markerEnd < 0 || markerEnd >= raw.length) return 0;
  const after = raw.charCodeAt(markerEnd);
  if (after !== 32 && after !== 9) return 0;
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
  if (prevLineWasParagraph) {
    if (p >= raw.length) return 0;
    if (isOrdered && !isOrderedOne) return 0;
  }
  if (p >= raw.length || col - (leadCols + markerWidth) > 4) {
    return leadCols + markerWidth + 1;
  }
  return col;
}

function normalizeSliceLineEndingsLengthPreserving(s: string): string {
  if (!/[\r\u0085\u2028\u2029]/.test(s)) return s;
  return s.replace(/\r(?!\n)/g, '\n').replace(/[\u0085\u2028\u2029]/g, ' ');
}

function hardenAndSplitSliceFences(
  rawMd: string,
  initialReopenedFence?: { ch: string; len: number; sourceIndent: number },
): Array<{ text: string; isFence: boolean }> {
  const md = normalizeSliceLineEndingsLengthPreserving(rawMd);
  const lines = md.split('\n');
  const normLines: string[] = [];
  let inFence = false;
  let fenceChar = '';
  let fenceLen = 0;
  let effectiveFenceLen = 0;
  let fenceOpenIdx = -1;
  let fenceInfo = '';
  let fenceIndent = 0;
  let reopenSourceIndent = 0;
  let activeListIndent = 0;

  if (initialReopenedFence) {
    inFence = true;
    fenceChar = initialReopenedFence.ch;
    fenceLen = initialReopenedFence.len;
    effectiveFenceLen = initialReopenedFence.len;
    fenceIndent = 0;
    reopenSourceIndent = initialReopenedFence.sourceIndent;
    fenceOpenIdx = 0;
    normLines.push(fenceChar.repeat(fenceLen));
  }

  for (let li = 0; li < lines.length; li++) {
    const rawWithCr = lines[li]!;
    const cr = rawWithCr.endsWith('\r') ? '\r' : '';
    const raw = cr ? rawWithCr.slice(0, -1) : rawWithCr;
    const { cols, bytePos, isBlank } = measureSliceIndentCols(raw);

    if (inFence) {
      const containerIndent = reopenSourceIndent > 0 ? reopenSourceIndent : fenceIndent;
      if (!isBlank && containerIndent > 0 && cols < containerIndent && !(reopenSourceIndent > 0 && li === 0)) {
        normLines.push(`${' '.repeat(fenceIndent)}${fenceChar.repeat(effectiveFenceLen)}`);
        inFence = false;
        fenceChar = '';
        fenceLen = 0;
        effectiveFenceLen = 0;
        fenceOpenIdx = -1;
        fenceIndent = 0;
        reopenSourceIndent = 0;
        activeListIndent = 0;
      } else {
        const maxCloseIndent = containerIndent > 0 ? containerIndent + 3 : 3;
        if (cols <= maxCloseIndent && bytePos === cols) {
          let p = bytePos;
          const fcCode = fenceChar.charCodeAt(0);
          while (p < raw.length && raw.charCodeAt(p) === fcCode) p++;
          const runLen = p - bytePos;
          if (runLen >= fenceLen) {
            while (p < raw.length && (raw.charCodeAt(p) === 32 || raw.charCodeAt(p) === 9)) p++;
            if (p === raw.length) {
              const closeLen = Math.max(runLen, effectiveFenceLen);
              normLines.push(`${' '.repeat(fenceIndent)}${fenceChar.repeat(closeLen)}${cr}`);
              inFence = false;
              fenceChar = '';
              fenceLen = 0;
              effectiveFenceLen = 0;
              fenceOpenIdx = -1;
              fenceIndent = 0;
              reopenSourceIndent = 0;
              continue;
            }
            if (runLen >= effectiveFenceLen && fenceOpenIdx >= 0) {
              effectiveFenceLen = runLen + 1;
              normLines[fenceOpenIdx] = `${' '.repeat(fenceIndent)}${fenceChar.repeat(effectiveFenceLen)}${fenceInfo}${cr}`;
            }
          }
        }
        if (reopenSourceIndent > 0 && bytePos > 0) {
          const stripSpaces = Math.min(reopenSourceIndent, bytePos);
          let allSpaces = true;
          for (let sp = 0; sp < stripSpaces; sp++) {
            if (raw.charCodeAt(sp) !== 32) {
              allSpaces = false;
              break;
            }
          }
          if (allSpaces) {
            normLines.push(`${raw.slice(stripSpaces)}${cr}`);
            continue;
          }
        }
        normLines.push(rawWithCr);
        continue;
      }
    }

    if (!isBlank && activeListIndent > 0 && cols < activeListIndent) {
      activeListIndent = 0;
    }
    const listCol = detectSliceListItemContentCol(raw, cols, bytePos);
    if (listCol > 0) activeListIndent = listCol;

    const minCols = activeListIndent > 0 ? activeListIndent : 0;
    const maxCols = minCols + 3;
    if (listCol === 0 && cols >= minCols && cols <= maxCols && bytePos === cols && bytePos + 3 <= raw.length) {
      const c0 = raw.charCodeAt(bytePos);
      if (c0 === 96 || c0 === 126) {
        let fEnd = bytePos + 1;
        while (fEnd < raw.length && raw.charCodeAt(fEnd) === c0) fEnd++;
        const fLen = fEnd - bytePos;
        const infoRaw = raw.slice(fEnd);
        if (fLen >= 3 && !(c0 === 96 && infoRaw.includes('`'))) {
          inFence = true;
          fenceChar = c0 === 96 ? '`' : '~';
          fenceLen = fLen;
          effectiveFenceLen = fLen;
          fenceIndent = activeListIndent > 0 ? activeListIndent : 0;
          fenceInfo = infoRaw.slice(0, 200).replace(/[\[\]<>]/g, '');
          fenceOpenIdx = normLines.length;
          normLines.push(`${' '.repeat(fenceIndent)}${fenceChar.repeat(fLen)}${fenceInfo}${cr}`);
          continue;
        }
      }
    }

    // Escape risky container-prefixed fence openers (`> ``` `, `- ``` `, `\t``` `, `    ``` `)
    let pfx = 0;
    let risky = false;
    let pCol = 0;
    while (pfx < raw.length) {
      const rStart = pCol;
      while (pfx < raw.length && (raw.charCodeAt(pfx) === 32 || raw.charCodeAt(pfx) === 9)) {
        if (raw.charCodeAt(pfx) === 9) {
          pCol += 4 - (pCol % 4);
          risky = true;
        } else {
          pCol++;
        }
        pfx++;
      }
      if (pCol - rStart >= 4) risky = true;
      if (pfx >= raw.length) break;
      const cc = raw.charCodeAt(pfx);
      if (cc === 62) {
        risky = true;
        pfx++;
        pCol++;
        continue;
      }
      if ((cc === 45 || cc === 42 || cc === 43) && pfx + 1 < raw.length && (raw.charCodeAt(pfx + 1) === 32 || raw.charCodeAt(pfx + 1) === 9)) {
        risky = true;
        pfx++;
        pCol++;
        continue;
      }
      break;
    }
    if (pfx > 0 && risky && pfx + 3 <= raw.length) {
      const c0 = raw.charCodeAt(pfx);
      if ((c0 === 96 || c0 === 126) && raw.charCodeAt(pfx + 1) === c0 && raw.charCodeAt(pfx + 2) === c0) {
        let fEnd = pfx + 3;
        while (fEnd < raw.length && raw.charCodeAt(fEnd) === c0) fEnd++;
        const tail = raw.slice(fEnd);
        if (!(c0 === 96 && tail.includes('`'))) {
          const fCh = c0 === 96 ? '`' : '~';
          normLines.push(`${raw.slice(0, pfx)}${`\\${fCh}`.repeat(fEnd - pfx)}${tail}${cr}`);
          continue;
        }
      }
    }

    normLines.push(rawWithCr);
  }

  if (inFence) {
    normLines.push(`${' '.repeat(fenceIndent)}${fenceChar.repeat(effectiveFenceLen)}`);
  }

  const hardened = normLines.join('\n');
  if (!hardened.includes('```') && !hardened.includes('~~~')) {
    return [{ text: hardened, isFence: false }];
  }

  const segs: Array<{ text: string; isFence: boolean }> = [];
  let sInFence = false;
  let sFenceChar = '';
  let sFenceLen = 0;
  let sFenceIndent = 0;
  let sListIndent = 0;
  let segStart = 0;
  let pos = 0;
  while (pos < hardened.length) {
    const nl = hardened.indexOf('\n', pos);
    const nextPos = nl === -1 ? hardened.length : nl + 1;
    const lineEnd = nl === -1 ? hardened.length : nl > pos && hardened[nl - 1] === '\r' ? nl - 1 : nl;
    const rawLine = hardened.slice(pos, lineEnd);
    const { cols, bytePos, isBlank } = measureSliceIndentCols(rawLine);
    if (sInFence) {
      if (!isBlank && sFenceIndent > 0 && cols < sFenceIndent) {
        segs.push({ text: hardened.slice(segStart, pos), isFence: true });
        sInFence = false;
        sFenceChar = '';
        sFenceLen = 0;
        sFenceIndent = 0;
        sListIndent = 0;
        segStart = pos;
        continue;
      }
      const maxClose = sFenceIndent > 0 ? sFenceIndent + 3 : 3;
      if (cols <= maxClose && bytePos === cols) {
        const rest = rawLine.slice(bytePos);
        const cm = /^(`{3,}|~{3,})[ \t]*$/.exec(rest);
        if (cm && cm[1]![0] === sFenceChar && cm[1]!.length >= sFenceLen) {
          segs.push({ text: hardened.slice(segStart, lineEnd), isFence: true });
          sInFence = false;
          sFenceChar = '';
          sFenceLen = 0;
          sFenceIndent = 0;
          segStart = lineEnd;
          pos = nextPos;
          continue;
        }
      }
      pos = nextPos;
      continue;
    }
    if (!isBlank && sListIndent > 0 && cols < sListIndent) sListIndent = 0;
    const lCol = detectSliceListItemContentCol(rawLine, cols, bytePos);
    if (lCol > 0) sListIndent = lCol;
    const minOpen = sListIndent > 0 ? sListIndent : 0;
    const maxOpen = minOpen + 3;
    if (lCol === 0 && cols >= minOpen && cols <= maxOpen && bytePos === cols) {
      const rest = rawLine.slice(bytePos);
      const om = /^(`{3,}|~{3,})(.*)$/.exec(rest);
      if (om && !(om[1]![0] === '`' && om[2]!.includes('`'))) {
        segs.push({ text: hardened.slice(segStart, pos), isFence: false });
        sInFence = true;
        sFenceChar = om[1]![0]!;
        sFenceLen = om[1]!.length;
        sFenceIndent = sListIndent > 0 ? sListIndent : 0;
        segStart = pos;
      }
    }
    pos = nextPos;
  }
  segs.push({ text: hardened.slice(segStart), isFence: sInFence });
  return segs;
}

/**
 * Shared fail-closed paged Markdown slice sanitizer (`H2` — used by both `storage.ts` `readArtifactPage` and `scrape.ts`
 * `sliceMarkdownWithOffsetAndMaxChars`):
 *  1. Scans `fullMd` in **O(N)** up to the full line containing `safeOffset` to detect whether `safeOffset` starts inside an
 *     open CommonMark fenced code block, mid-opening-fence, mid-closing-fence, or mid-prose-line.
 *  2. Re-opens any active fenced code block at the top of the slice (and escapes partial mid-line ` ``` ` / `~~~` prefixes so
 *     fence polarity can NEVER invert).
 *  3. Hardens and closes any truncated fenced code block or trailing inline backtick code span at the end of the slice.
 *  4. Always runs the fail-closed sanitizer (`escapeGfmTaskListCheckboxesLinear` + `neutralizeAllUnsafeMarkdownLinksLinear` +
 *     `escapeAllResidualLtInProseLinear`) across all non-fence segments so **0 of N** character offsets can EVER produce live
 *     HTML or dangerous URI schemes!
 */
export interface MarkdownSliceCheckpoint {
  pos: number;
  inFence: boolean;
  fenceChar: string;
  fenceLen: number;
  fenceIndent: number;
  activeListIndent: number;
  prevLineWasParagraph: boolean;
}

export function computeMarkdownSliceCheckpoints(rawFullMd: string, stepChars = 16_384): MarkdownSliceCheckpoint[] {
  const checkpoints: MarkdownSliceCheckpoint[] = [];
  if (!rawFullMd || rawFullMd.length <= stepChars) return checkpoints;
  const fullMd = normalizeSliceLineEndingsLengthPreserving(rawFullMd);
  let inFence = false;
  let fenceChar = '';
  let fenceLen = 0;
  let fenceIndent = 0;
  let activeListIndent = 0;
  let prevLineWasParagraph = false;
  let nextCheckpointAt = stepChars;
  let pos = 0;
  const n = fullMd.length;

  while (pos < n) {
    if (pos >= nextCheckpointAt) {
      checkpoints.push({
        pos,
        inFence,
        fenceChar,
        fenceLen,
        fenceIndent,
        activeListIndent,
        prevLineWasParagraph,
      });
      nextCheckpointAt = pos + stepChars;
    }
    const nl = fullMd.indexOf('\n', pos);
    const lineEnd = nl === -1 ? n : nl;
    const nextPos = nl === -1 ? n : nl + 1;
    const rawLine = lineEnd > pos && fullMd.charCodeAt(lineEnd - 1) === 13 ? fullMd.slice(pos, lineEnd - 1) : fullMd.slice(pos, lineEnd);
    const { cols, bytePos, isBlank } = measureSliceIndentCols(rawLine);

    let lineOpenedFence: { ch: string; len: number; indent: number } | null = null;
    let lineClosedFenceExplicit = false;

    if (inFence) {
      prevLineWasParagraph = false;
      if (!isBlank && fenceIndent > 0 && cols < fenceIndent) {
        inFence = false;
        fenceChar = '';
        fenceLen = 0;
        fenceIndent = 0;
        activeListIndent = 0;
      } else {
        const maxClose = fenceIndent > 0 ? fenceIndent + 3 : 3;
        if (cols <= maxClose && bytePos === cols) {
          let p = bytePos;
          const fcCode = fenceChar.charCodeAt(0);
          while (p < rawLine.length && rawLine.charCodeAt(p) === fcCode) p++;
          const runLen = p - bytePos;
          if (runLen >= fenceLen) {
            while (p < rawLine.length && (rawLine.charCodeAt(p) === 32 || rawLine.charCodeAt(p) === 9)) p++;
            if (p === rawLine.length) {
              lineClosedFenceExplicit = true;
            }
          }
        }
      }
    }

    if (!inFence && !lineClosedFenceExplicit) {
      if (!isBlank && activeListIndent > 0 && cols < activeListIndent && !prevLineWasParagraph) {
        activeListIndent = 0;
      }
      const listCol = detectSliceListItemContentCol(rawLine, cols, bytePos, prevLineWasParagraph);
      if (listCol > 0) {
        activeListIndent = listCol;
        prevLineWasParagraph = false;
      }
      const minCols = activeListIndent > 0 ? activeListIndent : 0;
      const maxCols = minCols + 3;
      if (listCol === 0 && cols >= minCols && cols <= maxCols && bytePos === cols && bytePos + 3 <= rawLine.length) {
        const c0 = rawLine.charCodeAt(bytePos);
        if (c0 === 96 || c0 === 126) {
          let fEnd = bytePos + 1;
          while (fEnd < rawLine.length && rawLine.charCodeAt(fEnd) === c0) fEnd++;
          const fLen = fEnd - bytePos;
          if (fLen >= 3 && !(c0 === 96 && rawLine.indexOf('`', fEnd) >= 0)) {
            lineOpenedFence = {
              ch: c0 === 96 ? '`' : '~',
              len: fLen,
              indent: activeListIndent > 0 ? activeListIndent : 0,
            };
          }
        }
      }
      if (!lineOpenedFence) {
        if (isBlank || isThematicBreakForSlice(rawLine, cols, bytePos)) {
          prevLineWasParagraph = false;
        } else if (listCol > 0) {
          prevLineWasParagraph = rawLine.slice(Math.min(listCol, rawLine.length)).trim() !== '';
        } else {
          const leadC = rawLine.charCodeAt(bytePos);
          let isAtx = false;
          if (cols <= 3 && leadC === 35) {
            let h = bytePos;
            while (h < rawLine.length && h - bytePos < 7 && rawLine.charCodeAt(h) === 35) h++;
            if (h - bytePos <= 6 && (h === rawLine.length || rawLine.charCodeAt(h) === 32 || rawLine.charCodeAt(h) === 9)) {
              isAtx = true;
            }
          }
          if (isAtx || (!prevLineWasParagraph && activeListIndent === 0 && cols >= 4)) {
            prevLineWasParagraph = false;
          } else if (cols <= 3 && leadC === 62) {
            let q = bytePos;
            while (q < rawLine.length && (rawLine.charCodeAt(q) === 62 || rawLine.charCodeAt(q) === 32 || rawLine.charCodeAt(q) === 9)) q++;
            prevLineWasParagraph = q < rawLine.length;
          } else {
            prevLineWasParagraph = true;
          }
        }
      }
    }

    if (lineClosedFenceExplicit) {
      inFence = false;
      fenceChar = '';
      fenceLen = 0;
      fenceIndent = 0;
      prevLineWasParagraph = false;
    } else if (lineOpenedFence) {
      inFence = true;
      fenceChar = lineOpenedFence.ch;
      fenceLen = lineOpenedFence.len;
      fenceIndent = lineOpenedFence.indent;
      prevLineWasParagraph = false;
    }
    pos = nextPos;
  }
  return checkpoints;
}

export function sanitizeMarkdownPageSlice(
  rawFullMd: string,
  safeOffset: number,
  rawSliceInput: string,
  allowPdfPageMarkers = false,
  checkpoints?: readonly MarkdownSliceCheckpoint[],
): string {
  if (!rawSliceInput) return '';
  const fullMd = normalizeSliceLineEndingsLengthPreserving(rawFullMd);
  const rawSlice = normalizeSliceLineEndingsLengthPreserving(rawSliceInput);

  let inFence = false;
  let fenceChar = '';
  let fenceLen = 0;
  let fenceIndent = 0;
  let activeListIndent = 0;
  let prevLineWasParagraph = false;

  let reconstructed = rawSlice;
  let initialReopenedFence: { ch: string; len: number; sourceIndent: number } | undefined;

  if (safeOffset > 0 && fullMd.length > 0) {
    const clampedOffset = Math.min(safeOffset, fullMd.length);
    let pos = 0;
    if (checkpoints && checkpoints.length > 0) {
      let lo = 0;
      let hi = checkpoints.length - 1;
      let bestIdx = -1;
      while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        if (checkpoints[mid]!.pos <= clampedOffset) {
          bestIdx = mid;
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }
      if (bestIdx >= 0) {
        const cp = checkpoints[bestIdx]!;
        pos = cp.pos;
        inFence = cp.inFence;
        fenceChar = cp.fenceChar;
        fenceLen = cp.fenceLen;
        fenceIndent = cp.fenceIndent;
        activeListIndent = cp.activeListIndent;
        prevLineWasParagraph = cp.prevLineWasParagraph;
      }
    }
    while (pos <= clampedOffset && pos <= fullMd.length) {
      const nl = fullMd.indexOf('\n', pos);
      const lineEnd = nl === -1 ? fullMd.length : nl;
      const nextPos = nl === -1 ? fullMd.length + 1 : nl + 1;
      const rawLine = lineEnd > pos && fullMd.charCodeAt(lineEnd - 1) === 13 ? fullMd.slice(pos, lineEnd - 1) : fullMd.slice(pos, lineEnd);
      const containsOffset = clampedOffset >= pos && clampedOffset <= lineEnd;
      const { cols, bytePos, isBlank } = measureSliceIndentCols(rawLine);

      let lineOpenedFence: { ch: string; len: number; indent: number } | null = null;
      let lineClosedFenceExplicit = false;

      if (inFence) {
        prevLineWasParagraph = false;
        if (!isBlank && fenceIndent > 0 && cols < fenceIndent) {
          inFence = false;
          fenceChar = '';
          fenceLen = 0;
          fenceIndent = 0;
          activeListIndent = 0;
        } else {
          const maxClose = fenceIndent > 0 ? fenceIndent + 3 : 3;
          if (cols <= maxClose && bytePos === cols) {
            let p = bytePos;
            const fcCode = fenceChar.charCodeAt(0);
            while (p < rawLine.length && rawLine.charCodeAt(p) === fcCode) p++;
            const runLen = p - bytePos;
            if (runLen >= fenceLen) {
              while (p < rawLine.length && (rawLine.charCodeAt(p) === 32 || rawLine.charCodeAt(p) === 9)) p++;
              if (p === rawLine.length) {
                lineClosedFenceExplicit = true;
              }
            }
          }
        }
      }

      if (!inFence && !lineClosedFenceExplicit) {
        if (!isBlank && activeListIndent > 0 && cols < activeListIndent && !prevLineWasParagraph) {
          activeListIndent = 0;
        }
        const listCol = detectSliceListItemContentCol(rawLine, cols, bytePos, prevLineWasParagraph);
        if (listCol > 0) {
          activeListIndent = listCol;
          prevLineWasParagraph = false;
        }
        const minCols = activeListIndent > 0 ? activeListIndent : 0;
        const maxCols = minCols + 3;
        if (listCol === 0 && cols >= minCols && cols <= maxCols && bytePos === cols && bytePos + 3 <= rawLine.length) {
          const c0 = rawLine.charCodeAt(bytePos);
          if (c0 === 96 || c0 === 126) {
            let fEnd = bytePos + 1;
            while (fEnd < rawLine.length && rawLine.charCodeAt(fEnd) === c0) fEnd++;
            const fLen = fEnd - bytePos;
            if (fLen >= 3 && !(c0 === 96 && rawLine.indexOf('`', fEnd) >= 0)) {
              lineOpenedFence = {
                ch: c0 === 96 ? '`' : '~',
                len: fLen,
                indent: activeListIndent > 0 ? activeListIndent : 0,
              };
            }
          }
        }
        if (!lineOpenedFence && !containsOffset) {
          if (isBlank || isThematicBreakForSlice(rawLine, cols, bytePos)) {
            prevLineWasParagraph = false;
          } else if (listCol > 0) {
            prevLineWasParagraph = rawLine.slice(Math.min(listCol, rawLine.length)).trim() !== '';
          } else {
            const leadC = rawLine.charCodeAt(bytePos);
            let isAtx = false;
            if (cols <= 3 && leadC === 35) {
              let h = bytePos;
              while (h < rawLine.length && h - bytePos < 7 && rawLine.charCodeAt(h) === 35) h++;
              if (h - bytePos <= 6 && (h === rawLine.length || rawLine.charCodeAt(h) === 32 || rawLine.charCodeAt(h) === 9)) {
                isAtx = true;
              }
            }
            if (isAtx || (!prevLineWasParagraph && activeListIndent === 0 && cols >= 4)) {
              prevLineWasParagraph = false;
            } else if (cols <= 3 && leadC === 62) {
              let q = bytePos;
              while (q < rawLine.length && (rawLine.charCodeAt(q) === 62 || rawLine.charCodeAt(q) === 32 || rawLine.charCodeAt(q) === 9)) q++;
              prevLineWasParagraph = q < rawLine.length;
            } else {
              prevLineWasParagraph = true;
            }
          }
        }
      }

      if (containsOffset) {
        const firstSliceNl = reconstructed.indexOf('\n');
        if (lineOpenedFence) {
          if (clampedOffset > pos || lineOpenedFence.indent > 0) {
            if (firstSliceNl >= 0) {
              reconstructed = reconstructed.slice(firstSliceNl + 1);
              initialReopenedFence = {
                ch: lineOpenedFence.ch,
                len: lineOpenedFence.len,
                sourceIndent: lineOpenedFence.indent,
              };
            } else {
              // Slice ended inside the opening fence header itself before `\n` — no code body yet
              reconstructed = `${lineOpenedFence.ch.repeat(lineOpenedFence.len)}\n${lineOpenedFence.ch.repeat(lineOpenedFence.len)}`;
            }
          }
        } else if (lineClosedFenceExplicit) {
          // `safeOffset` landed on or mid-way through a closing fence line whose opener is NOT in `rawSlice`:
          // escape any leading fence chars on the partial first line so it cannot open a fake inverted fence!
          const firstHead = firstSliceNl >= 0 ? reconstructed.slice(0, firstSliceNl) : reconstructed;
          const escapedFirst = firstHead.replace(/^([ \t]*)([`~]+)/, (_m, ws: string, ticks: string) =>
            `${ws}${ticks.split('').map((ch) => `\\${ch}`).join('')}`,
          );
          reconstructed = firstSliceNl >= 0 ? `${escapedFirst}${reconstructed.slice(firstSliceNl)}` : escapedFirst;
        } else if (inFence) {
          // `safeOffset` landed strictly inside an open fenced code block!
          initialReopenedFence = { ch: fenceChar, len: fenceLen, sourceIndent: fenceIndent };
        } else if (clampedOffset > pos) {
          // `safeOffset` landed mid-way through a prose line: prevent its suffix from acting as a line-start fence!
          const firstHead = firstSliceNl >= 0 ? reconstructed.slice(0, firstSliceNl) : reconstructed;
          const escapedFirst = firstHead.replace(/^([ \t]*)([`~]{3,})/, (_m, ws: string, ticks: string) =>
            `${ws}${ticks.split('').map((ch) => `\\${ch}`).join('')}`,
          );
          reconstructed = firstSliceNl >= 0 ? `${escapedFirst}${reconstructed.slice(firstSliceNl)}` : escapedFirst;
        }
        break;
      }

      if (lineClosedFenceExplicit) {
        inFence = false;
        fenceChar = '';
        fenceLen = 0;
        fenceIndent = 0;
      } else if (lineOpenedFence) {
        inFence = true;
        fenceChar = lineOpenedFence.ch;
        fenceLen = lineOpenedFence.len;
        fenceIndent = lineOpenedFence.indent;
      }
      pos = nextPos;
    }
  }

  let segments = hardenAndSplitSliceFences(reconstructed, initialReopenedFence);
  // Close any unclosed inline backtick code span in the final prose segment (`A1` truncation parity)
  const lastSeg = segments[segments.length - 1];
  if (lastSeg && !lastSeg.isFence && lastSeg.text.includes('`')) {
    const lastBlank = lastSeg.text.lastIndexOf('\n\n');
    const tailPara = lastBlank >= 0 ? lastSeg.text.slice(lastBlank + 2) : lastSeg.text;
    let p = 0;
    let openTickLen = 0;
    while (p < tailPara.length) {
      if (tailPara.charCodeAt(p) === 96 && !isMarkdownBackslashEscapedAt(tailPara, p)) {
        let tEnd = p + 1;
        while (tEnd < tailPara.length && tailPara.charCodeAt(tEnd) === 96) tEnd++;
        const want = tEnd - p;
        let q = tEnd;
        let matchedEnd = -1;
        while (q < tailPara.length) {
          const hit = tailPara.indexOf('`', q);
          if (hit < 0) break;
          let rEnd = hit + 1;
          while (rEnd < tailPara.length && tailPara.charCodeAt(rEnd) === 96) rEnd++;
          if (rEnd - hit === want) {
            matchedEnd = rEnd;
            break;
          }
          q = rEnd;
        }
        if (matchedEnd < 0) {
          openTickLen = want;
          break;
        }
        p = matchedEnd;
        continue;
      }
      p++;
    }
    if (openTickLen > 0) {
      const pad = lastSeg.text.endsWith('`') ? ' ' : '';
      lastSeg.text = `${lastSeg.text}${pad}${'`'.repeat(openTickLen)}`;
      segments = hardenAndSplitSliceFences(segments.map((s) => s.text).join(''));
    }
  }

  return segments
    .map((seg) => {
      if (seg.isFence) return seg.text;
      let cleanProse = escapeGfmTaskListCheckboxesLinear(seg.text);
      cleanProse = neutralizeAllUnsafeMarkdownLinksLinear(cleanProse);
      return escapeResidualLtPreservingSafeCodeSpansLinear(cleanProse, allowPdfPageMarkers);
    })
    .join('');
}

/**
 * Sanitizes an entire cached or freshly derived Markdown document in **O(N)** time before slicing in `readArtifactPage`
 * so multi-line fence polarity, container-prefixed pseudo-fences, unclosed EOF code spans/fences, GFM task-list checkboxes,
 * unsafe link destinations, and residual `<` are hardened across the full document prior to page boundary calculation.
 */
export function sanitizeFullMarkdownDocumentForArtifact(fullMd: string): string {
  if (!fullMd) return '';
  const norm = /[\r\u0085\u2028\u2029]/.test(fullMd)
    ? fullMd.replace(/\r\n?/g, '\n').replace(/[\u0085\u2028\u2029]/g, ' ')
    : fullMd;
  return sanitizeMarkdownPageSlice(norm, 0, norm, false);
}

/**
 * Strictly linear **O(N)** char-code scanner that replaces GFM table alignment divider lines
 * (`/^\|?[ \t:-]+\|[ \t|:-]*$/gm`) with `' '` — zero regular-expression backtracking on inputs like
 * `'|' + '-'.repeat(500_000)` or `'|-'.repeat(500_000)`.
 */
export function stripMarkdownTableDividerLinesLinear(s: string): string {
  if (!s || !s.includes('|')) return s;
  const n = s.length;
  let out = '';
  let lastCopy = 0;
  let lineStart = 0;

  while (lineStart <= n) {
    const nl = s.indexOf('\n', lineStart);
    const rawLineEnd = nl < 0 ? n : nl;
    const lineEnd = rawLineEnd > lineStart && s.charCodeAt(rawLineEnd - 1) === 13 /* '\r' */ ? rawLineEnd - 1 : rawLineEnd;
    const lineLen = lineEnd - lineStart;

    if (lineLen >= 2) {
      let p = lineStart;
      if (s.charCodeAt(p) === 124 /* '|' */) p++;
      const firstSegStart = p;
      let valid = true;
      while (p < lineEnd) {
        const c = s.charCodeAt(p);
        if (c === 32 || c === 9 || c === 58 /* ':' */ || c === 45 /* '-' */) {
          p++;
        } else {
          break;
        }
      }
      if (p > firstSegStart && p < lineEnd && s.charCodeAt(p) === 124 /* '|' */) {
        p++;
        while (p < lineEnd) {
          const c = s.charCodeAt(p);
          if (c === 32 || c === 9 || c === 124 /* '|' */ || c === 58 /* ':' */ || c === 45 /* '-' */) {
            p++;
          } else {
            valid = false;
            break;
          }
        }
        if (valid) {
          out += `${s.slice(lastCopy, lineStart)} `;
          lastCopy = rawLineEnd;
        }
      }
    }

    if (nl < 0) break;
    lineStart = nl + 1;
  }

  return lastCopy === 0 ? s : out + s.slice(lastCopy);
}

const WORD_STREAM_LATIN1_DECODER = new TextDecoder('latin1');
const WORD_STREAM_KEEP = (() => {
  const tbl = new Uint8Array(128);
  for (let c = 48; c <= 57; c++) tbl[c] = 1; // 0-9
  for (let c = 65; c <= 90; c++) tbl[c] = 1; // A-Z
  for (let c = 97; c <= 122; c++) tbl[c] = 1; // a-z
  tbl[46] = 1; // .
  tbl[58] = 1; // :
  return tbl;
})();

/**
 * Single-allocation **O(N)** word-stream builder (`R8`): replaces table divider lines, non-`[A-Za-z0-9.:]` runs,
 * and whitespace runs with single spaces using one `Uint8Array` buffer (avoiding 1M+ `String.prototype.replace`
 * heap slice allocations & GC spikes on `2 MiB` punctuation-dense inputs like `'[a]('.repeat(524_288)`).
 */
function toWordStreamLinear(raw: string): string {
  const s = stripMarkdownTableDividerLinesLinear(raw);
  const n = s.length;
  if (n === 0) return '';
  const out = new Uint8Array(n);
  let w = 0;
  let prevSpace = false;
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if (WORD_STREAM_KEEP[c] === 1) {
      out[w++] = c;
      prevSpace = false;
    } else if (!prevSpace) {
      out[w++] = 32;
      prevSpace = true;
    }
  }
  return WORD_STREAM_LATIN1_DECODER.decode(out.subarray(0, w));
}

function stripWordBracketsLinear(txt: string): string {
  let firstOpen = txt.indexOf('[');
  if (firstOpen < 0 || txt.indexOf(']', firstOpen + 1) < 0) return txt;
  const n = txt.length;
  let out = '';
  let last = 0;
  let i = firstOpen;
  while (i < n) {
    const openPos = txt.indexOf('[', i);
    if (openPos < 0) break;
    let openEnd = openPos + 1;
    while (openEnd < n && txt.charCodeAt(openEnd) === 91 /* '[' */) openEnd++;
    const openLen = openEnd - openPos;
    if (openLen <= 4 && openEnd < n) {
      let wordEnd = openEnd;
      while (wordEnd < n && wordEnd - openEnd <= 32) {
        const wc = txt.charCodeAt(wordEnd);
        if ((wc >= 65 && wc <= 90) || (wc >= 97 && wc <= 122)) wordEnd++;
        else break;
      }
      const wordLen = wordEnd - openEnd;
      if (wordLen >= 2 && wordLen <= 32 && wordEnd < n && txt.charCodeAt(wordEnd) === 93 /* ']' */) {
        let closeEnd = wordEnd + 1;
        while (closeEnd < n && txt.charCodeAt(closeEnd) === 93 /* ']' */) closeEnd++;
        out += txt.slice(last, openPos) + txt.slice(openEnd, wordEnd);
        last = closeEnd;
        i = closeEnd;
        continue;
      }
    }
    i = openEnd;
  }
  return last === 0 ? txt : out + txt.slice(last);
}

const COMPACT_SPACED_OVERRIDE_RE =
  /(?:ignore|disregard|forget|override)(?:(?:all|any|each|every)(?:of)?)?(?:(?:the|your|these|those|my|our))?(?:previous|prior|above|earlier|preceding|system|developer|initial|original)(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)/i;

function collapseSpacedSingleLettersLinear(s: string): string {
  const n = s.length;
  if (n < 7 || !s.includes(' ')) return s;
  let out: Uint8Array | null = null;
  let w = 0;
  let last = 0;
  let i = 0;
  while (i < n) {
    const c = s.charCodeAt(i);
    const isLet = (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
    if (
      isLet &&
      (i === 0 || WORD_STREAM_KEEP[s.charCodeAt(i - 1)] !== 1 || s.charCodeAt(i - 1) === 46 || s.charCodeAt(i - 1) === 58) &&
      i + 2 < n &&
      s.charCodeAt(i + 1) === 32
    ) {
      let p = i + 1;
      let count = 1;
      while (p < n && s.charCodeAt(p) === 32) {
        let wsEnd = p + 1;
        while (wsEnd < n && s.charCodeAt(wsEnd) === 32) wsEnd++;
        if (wsEnd >= n) break;
        const nc = s.charCodeAt(wsEnd);
        const nIsLet = (nc >= 65 && nc <= 90) || (nc >= 97 && nc <= 122);
        const nextAfter = wsEnd + 1 < n ? s.charCodeAt(wsEnd + 1) : 32;
        const nextIsAlnum =
          (nextAfter >= 65 && nextAfter <= 90) ||
          (nextAfter >= 97 && nextAfter <= 122) ||
          (nextAfter >= 48 && nextAfter <= 57);
        if (nIsLet && !nextIsAlnum) {
          count++;
          p = wsEnd + 1;
        } else {
          break;
        }
      }
      if (count >= 4) {
        if (!out) out = new Uint8Array(n);
        for (let k = last; k < i; k++) out[w++] = s.charCodeAt(k) & 0x7f;
        for (let k = i; k < p; k++) {
          const kc = s.charCodeAt(k);
          if (kc !== 32) out[w++] = kc & 0x7f;
        }
        last = p;
        i = p;
        continue;
      }
    }
    i++;
  }
  if (!out) return s;
  for (let k = last; k < n; k++) out[w++] = s.charCodeAt(k) & 0x7f;
  return WORD_STREAM_LATIN1_DECODER.decode(out.subarray(0, w));
}

/**
 * Strictly linear **O(N)** Markdown link, image, autolink-label, reference-link, and footnote stripper (`R7`/`R8`):
 * scans `](` sites over disjoint URL segments with monotonic quote/paren cursors so `'['.repeat(2_097_152)` and
 * `'[a]('.repeat(524_288)` finish in `< 5 ms` (fixing the `O(N^2)` loop), while preserving image alt text and
 * reference-link labels/titles for prompt-injection scanning.
 */
function unwrapMarkdownLinksForScanLinear(s: string, stripScrubbedDecoy = false): string {
  // Strip ONLY the URL target of reference-link definitions (`[label]: url "title"` -> `label "title"`) and footnote markers (`[^1]`),
  // preserving BOTH `[label]` text AND any trailing title text while never stripping `[system prompt]: prose` role-override headers!
  let work = s;
  if (work.includes('[SCRUBBED') || work.includes('[scrubbed')) {
    work = stripScrubbedDecoy
      ? work.replace(/\[SCRUBBED:[^\]\r\n]{0,120}\]/gi, ' ')
      : work.replace(/\[SCRUBBED:?\s*([^\]\r\n]{0,240})\]/gi, ' $1 ');
  }
  // Collapse 3+ consecutive single-letter brackets (`[i][g][n][o][r][e]` -> `ignore`) BEFORE `][` reference-link stripping!
  if (work.includes('][')) {
    work = work.replace(/(?:\[[A-Za-z]\]){3,}/g, (m) => m.replace(/[\[\]]/g, ''));
  }
  if (work.includes(']:')) {
    work = work.replace(
      /^([ \t>]{0,12}(?:(?:[-*+]|\d{1,9}[.)])[ \t]+)?)\[([^\]\r\n]{1,200})\]:[ \t]*<?(?:https?:|ftp:|mailto:|javascript:|vbscript:|data:|file:|blob:|\/|#)[^\s>]*>?/gim,
      '$1$2 ',
    );
  }
  if (work.includes('[^')) {
    work = work.replace(/\[\^[^\]\s]{1,64}\]/g, ' ');
  }
  if (work.includes('][')) {
    work = work.replace(/\]\[[^\]\r\n]{0,200}\]/g, ']');
  }

  if (!work.includes('](') || !work.includes(')')) {
    return stripWordBracketsLinear(work);
  }

  let out = '';
  let last = 0;
  let searchPos = 0;
  let nextCloseParen = -2;
  let nextDblQuote = -2;
  let nextSglQuote = -2;

  while (searchPos < work.length) {
    const bp = work.indexOf('](', searchPos);
    if (bp < 0) break;
    if (nextCloseParen !== -1 && nextCloseParen < bp + 2) {
      nextCloseParen = work.indexOf(')', bp + 2);
    }
    if (nextCloseParen < 0) break;

    let k = bp + 2;
    while (k < work.length && (work.charCodeAt(k) === 32 || work.charCodeAt(k) === 9)) k++;
    let valid = true;
    if (k < work.length && work.charCodeAt(k) === 60 /* '<' */) {
      k++;
      while (k < work.length && work.charCodeAt(k) !== 62 && work.charCodeAt(k) !== 10 && work.charCodeAt(k) !== 13) k++;
      if (k < work.length && work.charCodeAt(k) === 62) k++;
      else valid = false;
    } else {
      let depth = 0;
      while (k < work.length) {
        const c = work.charCodeAt(k);
        if (c === 92 /* '\\' */ && k + 1 < work.length) {
          k += 2;
          continue;
        }
        if (c === 32 || c === 9 || c === 10 || c === 13) break;
        if (c === 40 /* '(' */) {
          depth++;
          if (depth > 6) {
            valid = false;
            break;
          }
        } else if (c === 41 /* ')' */) {
          if (depth === 0) break;
          depth--;
        }
        k++;
      }
      if (depth !== 0) valid = false;
    }

    if (valid && k < work.length && (work.charCodeAt(k) === 32 || work.charCodeAt(k) === 9)) {
      while (k < work.length && (work.charCodeAt(k) === 32 || work.charCodeAt(k) === 9)) k++;
      if (k < work.length && (work.charCodeAt(k) === 34 || work.charCodeAt(k) === 39)) {
        const q = work.charCodeAt(k);
        let qEnd = -1;
        if (q === 34) {
          if (nextDblQuote !== -1 && nextDblQuote <= k) nextDblQuote = work.indexOf('"', k + 1);
          qEnd = nextDblQuote;
        } else {
          if (nextSglQuote !== -1 && nextSglQuote <= k) nextSglQuote = work.indexOf("'", k + 1);
          qEnd = nextSglQuote;
        }
        if (qEnd > k && qEnd - k <= 512 && work.slice(k + 1, qEnd).indexOf('\n') < 0) {
          k = qEnd + 1;
          while (k < work.length && (work.charCodeAt(k) === 32 || work.charCodeAt(k) === 9)) k++;
        } else {
          valid = false;
        }
      }
    }

    if (valid && k < work.length && work.charCodeAt(k) === 41 /* ')' */) {
      // Check bounded back-window `[last, bp)` for `![alt]` image (keep `alt`!) or `[https://...]` autolink label to drop URL noise!
      let openBr = -1;
      const scanBackFloor = Math.max(last, bp - 400);
      for (let b = bp - 1; b >= scanBackFloor; b--) {
        const bc = work.charCodeAt(b);
        if (bc === 10 || bc === 13) break;
        if (bc === 91 /* '[' */) {
          openBr = b;
          break;
        }
      }
      if (openBr >= last) {
        const isImg = openBr > last && work.charCodeAt(openBr - 1) === 33 /* '!' */;
        const lbl = work.slice(openBr + 1, bp).trim();
        if (/^(?:https?:\/\/|mailto:)\S+$/i.test(lbl)) {
          const dropStart = isImg ? openBr - 1 : openBr;
          out += `${work.slice(last, dropStart)} `;
          last = k + 1;
          searchPos = k + 1;
          continue;
        }
        if (isImg) {
          out += `${work.slice(last, openBr - 1)} ${lbl} `;
          last = k + 1;
          searchPos = k + 1;
          continue;
        }
      }
      // Keep the label text before `bp`, drop `](dest)`!
      out += work.slice(last, bp);
      last = k + 1;
      searchPos = k + 1;
      continue;
    }

    searchPos = Math.max(bp + 2, k);
  }

  const unwrapped = last === 0 ? work : out + work.slice(last);
  return stripWordBracketsLinear(unwrapped);
}

function decodeEntitiesForInjectionScan(raw: string): string {
  if (!raw.includes('&')) return raw;
  let out = raw;
  for (let pass = 0; pass < 2 && out.includes('&'); pass++) {
    const next = out
      .replace(/&#(\d{1,7});?/g, (_m, dec: string) => {
        const cp = Number(dec);
        return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
      })
      .replace(/&#x([0-9a-fA-F]{1,6});?/gi, (_m, hex: string) => {
        const cp = parseInt(hex, 16);
        return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
      })
      .replace(/&(?:nbsp|nonbreakingspace|ensp|emsp|thinsp|hairsp|tab|newline);/gi, ' ')
      .replace(/&(?:shy|zwj|zwnj|zerowidthspace|negativethinspace);/gi, '')
      .replace(/&colon;/gi, ':')
      .replace(/&quot;/gi, '"')
      .replace(/&apos;/gi, "'")
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&amp;/gi, '&');
    if (next === out) break;
    out = next;
  }
  return out;
}

function normalizeCssStyleForHiddenCheck(rawStyle: string): string {
  if (!rawStyle) return '';
  let s = decodeEntitiesForInjectionScan(rawStyle);
  if (s.includes('/*')) {
    s = s.replace(/\/\*[\s\S]{0,256}?\*\//g, '');
  }
  if (s.includes('\\')) {
    s = s.replace(/\\([0-9a-fA-F]{1,6})[ \t\r\n]?/g, (_m, hex: string) => {
      const cp = parseInt(hex, 16);
      return cp > 0 && cp <= 0x7f ? String.fromCharCode(cp) : '';
    });
    s = s.replace(/\\(.)/g, '$1');
  }
  return s;
}

function finishFillerPass(base: string, mode: 'space' | 'strip'): string {
  if (mode === 'strip') {
    let sOut = base;
    if (/[`*_~]/.test(sOut)) sOut = sOut.replace(/[`*_~]+/g, '');
    if (sOut.includes('  ')) sOut = sOut.replace(/  +/g, ' ');
    return sOut;
  }
  let res = base;
  if (res.includes('`')) res = res.replace(/`+/g, ' ');
  if (/[*~]/.test(res)) res = res.replace(/[*~]+/g, '');
  if (res.includes('_')) res = res.replace(/_+/g, ' ');
  if (res.includes('  ')) res = res.replace(/  +/g, ' ');
  return res;
}

/**
 * Reconstructs intra-word hyphenated (`I-m-m-e-d-i-a-t-e-l-y`), dot-separated (`F.o.r.g.e.t`),
 * underscore/slash-separated (`f_e_t_c_h`), and single-space-separated (`t o o l`, splitting on `>= 2` spaces,
 * newlines, or punctuation boundaries) single-letter chains in strictly linear **O(N)** time so ALL
 * `INJECTION_PATTERNS` match obfuscated sentences with intact word boundaries (`Round 9 Item 3`).
 */
function reconstructObfuscatedWordsLinear(s: string): string {
  const n = s.length;
  if (n < 3) return s;

  // Pass 1: Collapse intra-word punctuation-separated single-letter chains (`I-m-m-e-d-i-a-t-e-l-y`, `F.o.r.g.e.t`, `t-h-e`)
  let stage1 = s;
  if (
    (s.includes('-') || s.includes('.') || s.includes('_') || s.includes('/') || s.includes('+')) &&
    /(?:^|[^A-Za-z0-9])[A-Za-z][-._/+](?:_[-._/+])?[A-Za-z](?:$|[^A-Za-z0-9.])/.test(s)
  ) {
    let sb = '';
    let last = 0;
    let i = 0;
    const isIntraSep = (c: number) => c === 45 /* '-' */ || c === 46 /* '.' */ || c === 95 /* '_' */ || c === 47 /* '/' */ || c === 43 /* '+' */;
    while (i < n) {
      const c0 = s.charCodeAt(i);
      if (
        isAsciiAlphaCode(c0) &&
        (i === 0 || !isAsciiAlnumCode(s.charCodeAt(i - 1))) &&
        i + 2 < n &&
        isIntraSep(s.charCodeAt(i + 1))
      ) {
        const sep = s.charCodeAt(i + 1);
        let p = i + 1;
        let letters = s[i]!;
        let count = 1;
        while (p + 1 < n && s.charCodeAt(p) === sep) {
          const nc = s.charCodeAt(p + 1);
          // Also allow `_` inside tool names like `f-e-t-c-h-_-u-r-l` -> `fetch_url`
          if (nc === 95 && p + 3 < n && s.charCodeAt(p + 2) === sep && isAsciiAlphaCode(s.charCodeAt(p + 3))) {
            letters += '_';
            p += 2;
            continue;
          }
          const afterNext = p + 2 < n ? s.charCodeAt(p + 2) : 32;
          if (isAsciiAlphaCode(nc) && (!isAsciiAlnumCode(afterNext) || afterNext === sep)) {
            letters += s[p + 1]!;
            count++;
            p += 2;
          } else {
            break;
          }
        }
        // Consume optional trailing dot (`d.i.r.e.c.t.i.v.e.` / `S.T.R.I.P.E.`)
        const endPos = p < n && sep === 46 && s.charCodeAt(p) === 46 && (p + 1 >= n || !isAsciiAlnumCode(s.charCodeAt(p + 1))) ? p + 1 : p;
        if (count >= 2 && (endPos >= n || !isAsciiAlnumCode(s.charCodeAt(endPos)))) {
          sb += s.slice(last, i) + letters;
          last = endPos;
          i = endPos;
          continue;
        }
      }
      i++;
    }
    if (last > 0) stage1 = sb + s.slice(last);
  }

  // Pass 2: Collapse single-space `' '` runs of `>= 2` single-letter tokens (`t o o l` -> `tool`),
  // stopping at `>= 2` spaces, `\n`, `\t`, punctuation, or multi-letter words so word boundaries stay intact!
  const m = stage1.length;
  if (m < 3 || !stage1.includes(' ') || !/(?:^|[^A-Za-z0-9])[A-Za-z] [A-Za-z](?:$|[^A-Za-z0-9])/.test(stage1)) {
    return stage1;
  }
  let sb2 = '';
  let last2 = 0;
  let j = 0;
  while (j < m) {
    const c = stage1.charCodeAt(j);
    if (
      isAsciiAlphaCode(c) &&
      (j === 0 || !isAsciiAlnumCode(stage1.charCodeAt(j - 1))) &&
      j + 2 < m &&
      stage1.charCodeAt(j + 1) === 32 &&
      stage1.charCodeAt(j + 2) !== 32
    ) {
      let p = j + 1;
      let word = stage1[j]!;
      let count = 1;
      while (p + 1 < m && stage1.charCodeAt(p) === 32 && stage1.charCodeAt(p + 1) !== 32) {
        const nc = stage1.charCodeAt(p + 1);
        const after = p + 2 < m ? stage1.charCodeAt(p + 2) : 32;
        if (isAsciiAlphaCode(nc) && !isAsciiAlnumCode(after)) {
          word += stage1[p + 1]!;
          count++;
          p += 2;
        } else {
          break;
        }
      }
      if (count >= 2) {
        sb2 += stage1.slice(last2, j) + word;
        last2 = p;
        j = p;
        continue;
      }
    }
    j++;
  }
  return last2 === 0 ? stage1 : sb2 + stage1.slice(last2);
}

function normalizeProseBaseForInjectionScan(prose: string, fillerMode: 'space' | 'strip'): string {
  let out = decodeEntitiesForInjectionScan(prose);
  if (out.includes('<!--')) {
    out = stripHtmlCommentsLinear(out, MAX_PROMPT_INJECTION_SCAN_CHARS);
  }
  if (out.includes('<')) {
    out = stripHtmlTagsLinear(out, ['script', 'style', 'noscript', 'template'], ' ', MAX_PROMPT_INJECTION_SCAN_CHARS);
    out = replaceHtmlTagsQuoteAwareLinear(
      out,
      (tag) => (INLINE_SPLIT_TAGS.has(tag.tagNameLower) || tag.tagNameLower === 'code' ? '' : ' '),
      MAX_PROMPT_INJECTION_SCAN_CHARS,
      false,
    );
  }
  // Fast ASCII check: all invisible/format/Unicode-space/NFKD/confusable characters (`>= U+0085`) are non-ASCII (`< 10 ms` on `2 MiB`!)
  if (/[^\x00-\x7F]/.test(out)) {
    out = out
      .replace(
        /[\u00AD\u034F\u061C\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\uFEFF\uFFF9-\uFFFB\u{1D173}-\u{1D17A}\u{E0000}-\u{E01EF}]/gu,
        '',
      )
      .replace(/[\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u2800\u3000]/g, ' ')
      .replace(/[\u115F\u1160\u3164\uFFA0]/g, fillerMode === 'strip' ? '' : ' ')
      .normalize('NFKD')
      .replace(/[\u0300-\u036F\u0483-\u0489\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]/g, '')
      .replace(CONFUSABLE_CHAR_RE, (ch) => CONFUSABLE_CHAR_MAP[ch] ?? ch);
  }

  // Strip fenced code block marker lines while keeping inner code content for `checkPromptInjection` scanning (`M11`).
  if (out.includes('```') || out.includes('~~~')) {
    out = out.replace(/^[ \t]{0,3}(?:`{3,}|~{3,})[^\r\n]*$/gm, '');
  }
  // Unwrap backslash escapes (`ignore\ previous`, `previous\_instructions`, `ignore\\\nprevious`)
  if (out.includes('\\')) {
    out = out.replace(/\\\r?\n/g, ' ').replace(/\\_/g, ' ').replace(/\\([!-/:-@[-`{-~ ])/g, '$1');
  }
  if (out.includes('[') || out.includes(']')) {
    out = unwrapMarkdownLinksForScanLinear(out, fillerMode === 'strip');
  }
  return out;
}

function normalizeProseForInjectionScan(prose: string, fillerMode: 'space' | 'strip' | 'wordstream' = 'space'): string {
  const out = normalizeProseBaseForInjectionScan(prose, fillerMode === 'strip' ? 'strip' : 'space');
  const reconstructed = reconstructObfuscatedWordsLinear(out);
  if (fillerMode === 'wordstream') {
    return toWordStreamLinear(reconstructed);
  }
  return finishFillerPass(reconstructed, fillerMode);
}

function normalizeProsePairForInjectionScan(prose: string): { spaced: string; stripped: string; reconstructed: string } {
  const baseSpaced = normalizeProseBaseForInjectionScan(prose, 'space');
  const spaced = finishFillerPass(baseSpaced, 'space');
  // Reconstruct `a-b-c`, `a.b.c`, and `a b c` BEFORE `finishFillerPass` collapses `>= 2` spaces so multi-space word boundaries stay intact!
  const rawReconstructed = reconstructObfuscatedWordsLinear(baseSpaced);
  const reconstructed = rawReconstructed === baseSpaced ? spaced : finishFillerPass(rawReconstructed, 'space');
  const needsDistinctStripBase =
    /[\u115F\u1160\u3164\uFFA0]/.test(prose) || prose.includes('[SCRUBBED') || prose.includes('[scrubbed');
  const baseStripped = needsDistinctStripBase ? normalizeProseBaseForInjectionScan(prose, 'strip') : baseSpaced;
  const stripped =
    baseStripped === baseSpaced && !/[`*_~]/.test(baseSpaced) ? spaced : finishFillerPass(baseStripped, 'strip');
  return { spaced, stripped, reconstructed };
}

function testInjectionPatternAgainstVariants(
  pat: { id: string; re: RegExp; compactRe: RegExp },
  spaced: string,
  stripped: string,
  reconstructed: string,
  wordStream: string,
  reconWordStream: string,
  collapsed: string,
  rawMd?: string,
): boolean {
  if (pat.re.test(spaced)) return true;
  if (reconstructed !== spaced && pat.re.test(reconstructed)) return true;
  if (wordStream !== spaced && pat.re.test(wordStream)) return true;
  if (reconWordStream !== wordStream && pat.re.test(reconWordStream)) return true;
  if (stripped !== spaced && pat.re.test(stripped)) return true;
  if (collapsed !== wordStream && (pat.re.test(collapsed) || pat.compactRe.test(collapsed))) return true;
  if (rawMd !== undefined && rawMd !== spaced && (pat.id === 'exfiltrate_secrets_or_tools' || pat.id === 'new_system_role_override')) {
    if (pat.re.test(rawMd)) return true;
  }
  return false;
}

function matchesHiddenSubtreeInjection(rawFragment: string): boolean {
  const { spaced, stripped, reconstructed } = normalizeProsePairForInjectionScan(rawFragment);
  const wordStream = toWordStreamLinear(spaced);
  const reconWordStream = reconstructed === spaced ? wordStream : toWordStreamLinear(reconstructed);
  const collapsed = collapseSpacedSingleLettersLinear(wordStream);
  if (
    HIDDEN_DIRECTIVE_OVERRIDE_RE.test(wordStream) ||
    (reconWordStream !== wordStream && HIDDEN_DIRECTIVE_OVERRIDE_RE.test(reconWordStream)) ||
    (collapsed !== wordStream && COMPACT_SPACED_OVERRIDE_RE.test(collapsed))
  ) {
    return true;
  }
  for (const pat of INJECTION_PATTERNS) {
    if (testInjectionPatternAgainstVariants(pat, spaced, stripped, reconstructed, wordStream, reconWordStream, collapsed)) {
      return true;
    }
  }
  return false;
}

/**
 * Scans extracted Markdown (including inline code spans and fenced/indented code blocks when `checkPromptInjection` runs)
 * and raw HTML for indirect prompt-injection payloads (`H1`, `R3-M3`, `M11`, `R7`/`R8`/`R9` 8 MiB cap, linear `< 80 ms` on `2 MiB`).
 */
export function detectPromptInjection(params: {
  markdown: string;
  rawHtml?: string;
}): { detected: boolean; triggers: string[] } {
  const boundedHtml = (params.rawHtml ?? '').slice(0, MAX_PROMPT_INJECTION_SCAN_CHARS);
  const boundedMd = params.markdown.slice(0, MAX_PROMPT_INJECTION_SCAN_CHARS);
  const triggers: string[] = [];
  let totalScore = 0;

  // 1. Invisible Unicode Tag ASCII smuggling (`U+E0000`–`U+E007F`, UTF-16 high surrogate `0xDB40`) in raw source or Markdown
  if (
    (boundedHtml.includes('\uDB40') && /[\u{E0000}-\u{E007F}]/u.test(boundedHtml)) ||
    (boundedMd.includes('\uDB40') && /[\u{E0000}-\u{E007F}]/u.test(boundedMd))
  ) {
    triggers.push('unicode_tag_ascii_smuggling');
    totalScore += 4;
  }

  // 2. Hidden CSS / DOM subtree / `<template>` / `<noscript>` / `alt` / `title` attributes containing imperative LLM override phrases
  if (boundedHtml) {
    const rawForHidden = boundedHtml;
    const lowerForHidden = asciiLower(rawForHidden);

    // Extract simple hidden class names declared inside `<style>` blocks (`.h { display:none }`)
    const styleHiddenClasses = new Set<string>(['sr-only', 'visually-hidden', 'screen-reader-text', 'hidden', 'd-none']);
    if (lowerForHidden.includes('<style')) {
      replacePairedHtmlElementsLinear(
        rawForHidden,
        ['style'],
        (_full, _t, _a, cssInner) => {
          const normCss = normalizeCssStyleForHiddenCheck(cssInner.slice(0, 65_536));
          const ruleRe = /\.([A-Za-z_-][A-Za-z0-9_-]{0,63})\s*\{([^}]{1,240})\}/g;
          let cm: RegExpExecArray | null;
          while ((cm = ruleRe.exec(normCss)) !== null) {
            if (HIDDEN_STYLE_TOKEN_RE.test(cm[2]!)) {
              styleHiddenClasses.add(cm[1]!.toLowerCase());
            }
          }
            return '';
          },
          { maxChars: MAX_PROMPT_INJECTION_SCAN_CHARS },
        );
      }

      // Check `<template>` and `<noscript>` inert/fallback subtrees
      if (lowerForHidden.includes('<template') || lowerForHidden.includes('<noscript')) {
        let foundInert = false;
        replacePairedHtmlElementsLinear(
          rawForHidden,
          ['template', 'noscript'],
          (_full, _t, _a, inner) => {
            if (foundInert) return '';
            if (matchesHiddenSubtreeInjection(inner.slice(0, 8_192))) {
              foundInert = true;
            }
            return '';
          },
          { maxChars: MAX_PROMPT_INJECTION_SCAN_CHARS },
        );
      if (foundInert) {
        triggers.push('hidden_css_instruction_injection');
        totalScore += 5;
      }
    }

    if (!triggers.includes('hidden_css_instruction_injection')) {
      // Zero-allocation char-code tag scanner (`H3`: < 15ms on 2 MiB of `<x-0 hidden>a</x-0>...`, zero intermediate `rawTag` slices!)
      const closeFirstByTag = new Map<string, number>();
      const closeMoreByTag = new Map<string, number[]>();
      const closeCursorByTag = new Map<string, number>();
      const candidateOpenTags: Array<{
        nameStart: number;
        nameEnd: number;
        attrStart: number;
        attrEnd: number;
        end: number;
        isSelfClosing: boolean;
        immediateClose: number;
      }> = [];

      let scanPos = 0;
      let noCloseDbl = false;
      let noCloseSgl = false;
      const htmlLen = rawForHidden.length;
      while (scanPos < htmlLen) {
        const lt = rawForHidden.indexOf('<', scanPos);
        if (lt < 0 || lt + 1 >= htmlLen) break;
        let p = lt + 1;
        const c1 = lowerForHidden.charCodeAt(p);
        let isClosing = false;
        if (c1 === 47 /* '/' */) {
          isClosing = true;
          p++;
        } else if (c1 === 33 /* '!' */ || c1 === 63 /* '?' */) {
          const declEnd = rawForHidden.indexOf('>', p + 1);
          if (declEnd < 0) break;
          scanPos = declEnd + 1;
          continue;
        }
        if (p >= htmlLen) break;
        const n0 = lowerForHidden.charCodeAt(p);
        if (n0 < 97 || n0 > 122) {
          scanPos = lt + 1;
          continue;
        }
        const nameStart = p;
        p++;
        while (p < htmlLen) {
          const nc = lowerForHidden.charCodeAt(p);
          if ((nc >= 97 && nc <= 122) || (nc >= 48 && nc <= 57) || nc === 45 || nc === 58) p++;
          else break;
        }
        if (p < htmlLen) {
          const boundary = rawForHidden.charCodeAt(p);
          if (boundary !== 62 && boundary !== 47 && boundary !== 32 && boundary !== 9 && boundary !== 10 && boundary !== 13 && boundary !== 12) {
            scanPos = lt + 1;
            continue;
          }
        }
        if (isClosing) {
          const gt = rawForHidden.indexOf('>', p);
          if (gt < 0) break;
          const tagNameLower = lowerForHidden.slice(nameStart, p);
          if (!closeFirstByTag.has(tagNameLower)) {
            closeFirstByTag.set(tagNameLower, lt);
          } else {
            let list = closeMoreByTag.get(tagNameLower);
            if (!list) {
              list = [];
              closeMoreByTag.set(tagNameLower, list);
            }
            list.push(lt);
          }
          scanPos = gt + 1;
          continue;
        }

        // Open tag: fast path when immediately `>` (zero attributes -> skip without slicing!)
        if (p < htmlLen && rawForHidden.charCodeAt(p) === 62 /* '>' */) {
          scanPos = p + 1;
          continue;
        }

        // Scan to closing `>` quote-aware with dead-quote memoization
        let j = p;
        let quote = 0;
        while (j < htmlLen) {
          const ch = rawForHidden.charCodeAt(j);
          if (quote !== 0) {
            if (ch === quote) quote = 0;
          } else if (ch === 34 && !noCloseDbl) {
            quote = 34;
          } else if (ch === 39 && !noCloseSgl) {
            quote = 39;
          } else if (ch === 62 /* '>' */) {
            break;
          }
          j++;
        }
        if (j >= htmlLen) {
          if (quote === 34) {
            noCloseDbl = true;
            continue;
          }
          if (quote === 39) {
            noCloseSgl = true;
            continue;
          }
          break;
        }
        const selfClosing = j > p && rawForHidden.charCodeAt(j - 1) === 47 /* '/' */;
        const attrEnd = selfClosing ? j - 1 : j;
        if (attrEnd > p) {
          const nameLen = p - nameStart;
          let immediateClose = -1;
          if (!selfClosing) {
            const nextLt = rawForHidden.indexOf('<', j + 1);
            if (
              nextLt >= j + 1 &&
              nextLt - (j + 1) <= 256 &&
              nextLt + 2 + nameLen < htmlLen &&
              rawForHidden.charCodeAt(nextLt + 1) === 47 /* '/' */ &&
              rawForHidden.charCodeAt(nextLt + 2 + nameLen) === 62 /* '>' */
            ) {
              let sameTag = true;
              for (let k = 0; k < nameLen; k++) {
                if (lowerForHidden.charCodeAt(nameStart + k) !== lowerForHidden.charCodeAt(nextLt + 2 + k)) {
                  sameTag = false;
                  break;
                }
              }
              if (sameTag) immediateClose = nextLt;
            }
          }
          candidateOpenTags.push({
            nameStart,
            nameEnd: p,
            attrStart: p,
            attrEnd,
            end: j + 1,
            isSelfClosing: selfClosing,
            immediateClose,
          });
          if (immediateClose >= 0) {
            scanPos = immediateClose + 3 + nameLen;
            continue;
          }
        }
        scanPos = j + 1;
      }

      const attrCandidates: string[] = [];
      const hiddenIntervals: Array<[number, number]> = [];

      for (let ti = 0; ti < candidateOpenTags.length; ti++) {
        const tag = candidateOpenTags[ti]!;
        let isHiddenSubtree = false;

        // O(1) char-code check for bare ` hidden` attribute (`<x-0 hidden>`) — zero string slice!
        let aStart = tag.attrStart;
        let aEnd = tag.attrEnd;
        while (aStart < aEnd && isAsciiWhitespaceCode(lowerForHidden.charCodeAt(aStart))) aStart++;
        while (aEnd > aStart && isAsciiWhitespaceCode(lowerForHidden.charCodeAt(aEnd - 1))) aEnd--;
        const aLen = aEnd - aStart;
        if (
          (aLen === 6 || aLen === 9) &&
          lowerForHidden.charCodeAt(aStart) === 104 /* 'h' */ &&
          lowerForHidden.startsWith('hidden', aStart) &&
          (aLen === 6 || lowerForHidden.slice(aStart + 6, aEnd) === '=""' || lowerForHidden.slice(aStart + 6, aEnd) === "=''")
        ) {
          isHiddenSubtree = !tag.isSelfClosing;
        } else {
          const lowerAttrs = lowerForHidden.slice(aStart, aEnd);
          if (
            !lowerAttrs.includes('hidden') &&
            !lowerAttrs.includes('style') &&
            !lowerAttrs.includes('class') &&
            !lowerAttrs.includes('alt') &&
            !lowerAttrs.includes('title')
          ) {
            continue;
          }
          const attrs = parseOpenTagAttributes(rawForHidden.slice(aStart, aEnd));
          if (attrs.alt || attrs.title) {
            const attrCandidate = `${attrs.alt ?? ''} ${attrs.title ?? ''}`.trim();
            if (attrCandidate) attrCandidates.push(attrCandidate);
          }
          if (!tag.isSelfClosing) {
            const normStyle = attrs.style ? normalizeCssStyleForHiddenCheck(attrs.style) : '';
            const isHiddenAttr = 'hidden' in attrs || (attrs['aria-hidden'] ?? '').trim().toLowerCase() === 'true';
            const classTokens = attrs.class ? attrs.class.toLowerCase().split(/\s+/).filter(Boolean) : [];
            const hasHiddenClass = classTokens.some((c) => styleHiddenClasses.has(c));
            isHiddenSubtree = isHiddenAttr || hasHiddenClass || (normStyle !== '' && HIDDEN_STYLE_TOKEN_RE.test(normStyle));
          }
        }

        if (!isHiddenSubtree) continue;

        let closeIdx = tag.immediateClose;
        const tagNameLower =
          closeIdx < 0 && closeFirstByTag.size > 0 ? lowerForHidden.slice(tag.nameStart, tag.nameEnd) : '';
        const firstClose = tagNameLower ? closeFirstByTag.get(tagNameLower) : undefined;
        if (firstClose !== undefined) {
          if (firstClose >= tag.end) {
            closeIdx = firstClose;
          } else {
            const moreList = closeMoreByTag.get(tagNameLower);
            if (moreList) {
              let cur = closeCursorByTag.get(tagNameLower) ?? 0;
              while (cur < moreList.length && moreList[cur]! < tag.end) {
                cur++;
              }
              closeCursorByTag.set(tagNameLower, cur);
              if (cur < moreList.length) {
                closeIdx = moreList[cur]!;
              }
            }
          }
        }

        const maxSearchEnd = Math.min(rawForHidden.length, tag.end + 16_384);
        const sliceEnd = closeIdx >= 0 && closeIdx <= maxSearchEnd ? closeIdx : Math.min(rawForHidden.length, tag.end + 8_192);
        if (sliceEnd <= tag.end) continue;

        const prevInterval = hiddenIntervals.length > 0 ? hiddenIntervals[hiddenIntervals.length - 1]! : null;
        if (prevInterval && tag.end <= prevInterval[1]) {
          if (sliceEnd > prevInterval[1]) prevInterval[1] = sliceEnd;
        } else {
          hiddenIntervals.push([tag.end, sliceEnd]);
        }
      }

      if (attrCandidates.length > 0) {
        const joinedAttrs = attrCandidates.join('\n.\n').slice(0, MAX_PROMPT_INJECTION_SCAN_CHARS);
        const spacedAttrs = normalizeProseForInjectionScan(joinedAttrs, 'space');
        const wordAttrs = toWordStreamLinear(spacedAttrs);
        const collapsedAttrs = collapseSpacedSingleLettersLinear(wordAttrs);
        for (const pat of INJECTION_PATTERNS) {
          if (pat.re.test(spacedAttrs) || pat.re.test(wordAttrs) || pat.compactRe.test(collapsedAttrs)) {
            triggers.push('hidden_css_instruction_injection');
            totalScore += 5;
            break;
          }
        }
      }

      if (!triggers.includes('hidden_css_instruction_injection') && hiddenIntervals.length > 0) {
        const rawHiddenChunks: string[] = [];
        let accLen = 0;
        for (let hi = 0; hi < hiddenIntervals.length && accLen < MAX_PROMPT_INJECTION_SCAN_CHARS; hi++) {
          const [hStart, hEnd] = hiddenIntervals[hi]!;
          const rawSlice = rawForHidden.slice(hStart, hEnd);
          if (rawSlice) {
            rawHiddenChunks.push(rawSlice);
            accLen += rawSlice.length + 3;
          }
        }
        if (rawHiddenChunks.length > 0) {
          const joinedHidden = rawHiddenChunks.join('\n.\n');
          const boundedJoinedHidden = joinedHidden.slice(0, MAX_PROMPT_INJECTION_SCAN_CHARS);
          const strippedOnce = !boundedJoinedHidden.includes('<')
            ? boundedJoinedHidden
            : !boundedJoinedHidden.includes('"') && !boundedJoinedHidden.includes("'")
              ? boundedJoinedHidden.replace(/<[A-Za-z/!?][^>]{0,4096}>/g, ' ')
              : stripHtmlTagsQuoteAwareLinear(boundedJoinedHidden, ' ', MAX_PROMPT_INJECTION_SCAN_CHARS);
          if (matchesHiddenSubtreeInjection(strippedOnce)) {
            triggers.push('hidden_css_instruction_injection');
            totalScore += 5;
          }
        }
      }
    }
  }

  // 3. Full Markdown + code-span / fenced-block scan (`M11` & `R7`/`R8`/`R9`: 8 MiB cap, linear `< 80 ms` on `2 MiB`!)
  const { spaced: scanSpaced, stripped: scanStripped, reconstructed: scanReconstructed } = normalizeProsePairForInjectionScan(boundedMd);
  const scanWordStream = toWordStreamLinear(scanSpaced);
  const scanReconWordStream = scanReconstructed === scanSpaced ? scanWordStream : toWordStreamLinear(scanReconstructed);
  const scanCollapsed = collapseSpacedSingleLettersLinear(scanWordStream);

  for (const pat of INJECTION_PATTERNS) {
    if (
      testInjectionPatternAgainstVariants(
        pat,
        scanSpaced,
        scanStripped,
        scanReconstructed,
        scanWordStream,
        scanReconWordStream,
        scanCollapsed,
        boundedMd,
      )
    ) {
      triggers.push(pat.id);
      totalScore += pat.weight;
    }
  }

  return {
    detected: totalScore >= 3,
    triggers: [...new Set(triggers)],
  };
}

function parseSimpleSelector(rawSelector: string): {
  tag?: string;
  id?: string;
  classes: string[];
  attrName?: string;
  attrVal?: string;
} | null {
  const s = rawSelector.trim();
  if (!s) return null;
  // Use last descendant segment (e.g. "main a.card" -> "a.card") for fast streaming regex match
  const leaf = s.split(/\s+|>|\+|~/).filter(Boolean).pop() ?? s;
  let rest = leaf;
  let attrName: string | undefined;
  let attrVal: string | undefined;
  const attrMatch = /\[([a-zA-Z0-9_:-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]/.exec(rest);
  if (attrMatch) {
    attrName = attrMatch[1]!.toLowerCase();
    attrVal = attrMatch[2] ?? attrMatch[3] ?? attrMatch[4];
    rest = rest.replace(attrMatch[0], '');
  }
  const idMatch = /#([a-zA-Z0-9_-]+)/.exec(rest);
  const id = idMatch?.[1];
  if (idMatch) rest = rest.replace(idMatch[0], '');
  const classes = [...rest.matchAll(/\.([a-zA-Z0-9_-]+)/g)].map((m) => m[1]!);
  rest = rest.replace(/\.[a-zA-Z0-9_-]+/g, '').trim();
  const tag = rest && rest !== '*' && /^[a-zA-Z][a-zA-Z0-9-]*$/.test(rest) ? rest.toLowerCase() : undefined;
  return { ...(tag ? { tag } : {}), ...(id ? { id } : {}), classes, ...(attrName ? { attrName } : {}), ...(attrVal !== undefined ? { attrVal } : {}) };
}

function parseOpenTagAttributes(attrChunk: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrChunk)) !== null) {
    const key = m[1]!.toLowerCase();
    const val = m[2] ?? m[3] ?? m[4] ?? '';
    attrs[key] = val.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  }
  return attrs;
}

/**
 * Extracts HTML attribute values for `{ type: "attributes", selectors: [{ selector, attribute }] }` without DOM bloat (`H1`).
 */
export function extractHtmlAttributesBySelectors(
  rawHtml: string,
  selectors: Array<{ selector: string; attribute: string }>,
): Record<string, unknown> {
  const cleanedHtml = stripHtmlTagsLinear(
    stripHtmlCommentsLinear(rawHtml, MAX_HTML_SCAN_CHARS),
    ['script', 'style', 'template'],
    '',
    MAX_HTML_SCAN_CHARS,
  );

  // Scan open tags ONCE linearly across all requested selectors
  const openTags: Array<{ tag: string; attrs: Record<string, string> }> = [];
  scanHtmlTagsLinear(
    cleanedHtml,
    (t) => {
      if (t.isClosing || t.isDeclaration) return;
      openTags.push({ tag: t.tagNameLower, attrs: parseOpenTagAttributes(t.attrs) });
      return openTags.length < 25_000 ? undefined : false;
    },
    MAX_HTML_SCAN_CHARS,
    false,
  );

  const results: Array<{ selector: string; attribute: string; values: string[] }> = [];
  for (const spec of selectors.slice(0, 25)) {
    const selStr = typeof spec.selector === 'string' ? spec.selector.trim() : '';
    const attrTarget = typeof spec.attribute === 'string' ? spec.attribute.trim().toLowerCase() : '';
    if (!selStr || !attrTarget) continue;
    const parsed = parseSimpleSelector(selStr);
    if (!parsed) {
      results.push({ selector: selStr, attribute: attrTarget, values: [] });
      continue;
    }

    const values: string[] = [];
    for (const item of openTags) {
      if (values.length >= 200) break;
      if (parsed.tag && item.tag !== parsed.tag) continue;
      const attrs = item.attrs;
      if (parsed.id && attrs.id !== parsed.id) continue;
      if (parsed.classes.length > 0) {
        const clsTokens = (attrs.class ?? '').split(/\s+/).filter(Boolean);
        if (!parsed.classes.every((c) => clsTokens.includes(c))) continue;
      }
      if (parsed.attrName) {
        if (!(parsed.attrName in attrs)) continue;
        if (parsed.attrVal !== undefined && attrs[parsed.attrName] !== parsed.attrVal) continue;
      }
      if (attrTarget in attrs && attrs[attrTarget] !== undefined) {
        values.push(attrs[attrTarget]!);
      }
    }
    results.push({ selector: selStr, attribute: attrTarget, values });
  }

  return { items: results };
}

function matchMetaContent(rawHtml: string, names: readonly string[]): string | undefined {
  const wanted = new Map<string, number>();
  names.forEach((n, idx) => wanted.set(n.toLowerCase(), idx));
  const hits = new Map<number, string>();
  scanHtmlTagsLinear(
    rawHtml,
    (tag) => {
      if (tag.isClosing || tag.tagNameLower !== 'meta') return;
      const attrs = parseOpenTagAttributes(tag.attrs);
      const key = (attrs.property ?? attrs.name ?? attrs.itemprop ?? '').toLowerCase();
      const orderIdx = wanted.get(key);
      if (orderIdx !== undefined && !hits.has(orderIdx) && attrs.content?.trim()) {
        hits.set(orderIdx, attrs.content.trim());
        if (orderIdx === 0) return false;
      }
      return undefined;
    },
    160_000,
    false,
  );
  for (let i = 0; i < names.length; i++) {
    const val = hits.get(i);
    if (val) return val;
  }
  return undefined;
}

function extractFirstHeadingTextLinear(rawBody: string, tagNameLower: string): string | undefined {
  let heading: string | undefined;
  replacePairedHtmlElementsLinear(
    rawBody,
    [tagNameLower],
    (_full, _t, _attrs, inner) => {
      if (heading === undefined) {
        const clean = stripHtmlTagsQuoteAwareLinear(inner, ' ', 8000).replace(/\s+/g, ' ').trim();
        if (clean) heading = clean;
      }
      return '';
    },
    { maxChars: 200_000, maxInnerChars: 8000 },
  );
  return heading;
}

export function sanitizePlainMetadataText(raw: string | undefined, maxLen = 2_000): string | undefined {
  if (!raw || typeof raw !== 'string') return undefined;
  let s = raw.length > maxLen * 2 ? raw.slice(0, maxLen * 2) : raw;
  if (/[^\x20-\x7E]/.test(s)) {
    s = s
      .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
      .replace(
        /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E01EF}]/gu,
        '',
      );
  }
  s = s.replace(/[\r\n\t\u0085\u2028\u2029]+/g, ' ').replace(/ {2,}/g, ' ').trim();
  if (!s) return undefined;
  if (s.length > maxLen) s = s.slice(0, maxLen).trim();
  s = neutralizeAllUnsafeMarkdownLinksLinear(s);
  if (s.includes('<')) {
    s = replaceAllLtLinearFast(s);
  }
  return s || undefined;
}

/**
 * Extracts normalized e-commerce product metadata (`formats: ["product"]`) across Schema.org `Product`,
 * OpenGraph `product:*` / `og:*` tags, and embedded Shopify product JSON.
 */
export function extractStructuredProduct(params: {
  rawBody: string;
  finalUrl: string;
  fallbackTitle?: string;
  fallbackDescription?: string;
}): Record<string, unknown> | null {
  const { rawBody, finalUrl, fallbackTitle, fallbackDescription } = params;
  if (!rawBody) return null;

  const jsonLdList = extractJsonLdObjects(rawBody);
  const productLd = jsonLdList.find((obj) => {
    const t = obj['@type'];
    const types = Array.isArray(t) ? t.map(String) : typeof t === 'string' ? [t] : [];
    return types.some((x) => /^(?:Product|ProductGroup|IndividualProduct|SoftwareApplication)$/i.test(x.replace(/^schema:/i, '')));
  });

  if (productLd) {
    const brandRaw = productLd.brand;
    const brand = sanitizePlainMetadataText(
      typeof brandRaw === 'string'
        ? brandRaw
        : brandRaw && typeof brandRaw === 'object' && typeof (brandRaw as { name?: unknown }).name === 'string'
          ? (brandRaw as { name: string }).name
          : undefined,
      240,
    );

    const offersRaw = productLd.offers;
    const offerList = Array.isArray(offersRaw)
      ? (offersRaw as Array<Record<string, unknown>>)
      : offersRaw && typeof offersRaw === 'object'
        ? [offersRaw as Record<string, unknown>]
        : [];
    const primaryOffer = offerList[0] ?? {};
    const rawPrice = primaryOffer.price ?? primaryOffer.lowPrice;
    const price =
      typeof rawPrice === 'number'
        ? rawPrice
        : typeof rawPrice === 'string' && rawPrice.trim()
          ? Number(rawPrice.replace(/[^0-9.]/g, '')) || rawPrice.trim()
          : undefined;
    const currency = typeof primaryOffer.priceCurrency === 'string' ? primaryOffer.priceCurrency : undefined;
    const availability =
      typeof primaryOffer.availability === 'string'
        ? primaryOffer.availability.replace(/^https?:\/\/schema\.org\//i, '')
        : undefined;

    const imgsRaw = productLd.image;
    const images = (Array.isArray(imgsRaw) ? imgsRaw : imgsRaw ? [imgsRaw] : [])
      .map((im) => (typeof im === 'string' ? im : im && typeof im === 'object' && typeof (im as { url?: unknown }).url === 'string' ? (im as { url: string }).url : ''))
      .filter(Boolean);

    const ratingObj =
      productLd.aggregateRating && typeof productLd.aggregateRating === 'object'
        ? (productLd.aggregateRating as Record<string, unknown>)
        : null;

    const cleanLdTitle = sanitizePlainMetadataText(typeof productLd.name === 'string' ? productLd.name : fallbackTitle, 400);
    const cleanLdDesc = sanitizePlainMetadataText(
      typeof productLd.description === 'string' ? productLd.description : fallbackDescription,
      1_200,
    );
    const cleanSku = sanitizePlainMetadataText(typeof productLd.sku === 'string' ? productLd.sku : undefined, 160);
    const rawLdUrl = typeof productLd.url === 'string' && !isDisallowedMarkdownLinkDestination(productLd.url) ? productLd.url : finalUrl;

    return {
      title: cleanLdTitle,
      ...(cleanLdDesc ? { description: cleanLdDesc } : {}),
      ...(brand ? { brand } : {}),
      ...(cleanSku ? { sku: cleanSku } : {}),
      ...(typeof productLd.gtin13 === 'string' ? { gtin: productLd.gtin13 } : typeof productLd.gtin === 'string' ? { gtin: productLd.gtin } : {}),
      ...(price !== undefined ? { price } : {}),
      ...(currency ? { currency } : {}),
      ...(availability ? { availability } : {}),
      url: rawLdUrl,
      ...(images.length > 0 ? { images } : {}),
      ...(ratingObj?.ratingValue !== undefined ? { rating: Number(ratingObj.ratingValue) || ratingObj.ratingValue } : {}),
      ...(ratingObj?.reviewCount !== undefined ? { reviewCount: Number(ratingObj.reviewCount) || ratingObj.reviewCount } : {}),
      ...(offerList.length > 1
        ? {
            variants: offerList.slice(0, 30).map((o) => {
              const vName = sanitizePlainMetadataText(typeof o.name === 'string' ? o.name : undefined, 240);
              const vSku = sanitizePlainMetadataText(typeof o.sku === 'string' ? o.sku : undefined, 160);
              return {
                ...(vName ? { name: vName } : {}),
                ...(vSku ? { sku: vSku } : {}),
                ...(o.price !== undefined ? { price: Number(String(o.price).replace(/[^0-9.]/g, '')) || o.price } : {}),
                ...(typeof o.priceCurrency === 'string' ? { currency: o.priceCurrency } : {}),
                ...(typeof o.availability === 'string' ? { availability: o.availability.replace(/^https?:\/\/schema\.org\//i, '') } : {}),
              };
            }),
          }
        : {}),
    };
  }

  // Fallback to OpenGraph `product:price:amount` / meta tags
  const ogPrice = matchMetaContent(rawBody, ['product:price:amount', 'og:price:amount', 'price']);
  const ogCurrency = matchMetaContent(rawBody, ['product:price:currency', 'og:price:currency', 'priceCurrency']);
  const ogBrand = sanitizePlainMetadataText(matchMetaContent(rawBody, ['product:brand', 'og:brand', 'brand']), 240);
  const ogAvail = matchMetaContent(rawBody, ['product:availability', 'og:availability', 'availability']);
  const ogImage = matchMetaContent(rawBody, ['og:image']);

  if (ogPrice || ogBrand || ogAvail) {
    const cleanOgTitle = sanitizePlainMetadataText(matchMetaContent(rawBody, ['og:title']) ?? fallbackTitle, 400);
    const cleanOgDesc = sanitizePlainMetadataText(fallbackDescription, 1_200);
    return {
      title: cleanOgTitle,
      ...(cleanOgDesc ? { description: cleanOgDesc } : {}),
      ...(ogBrand ? { brand: ogBrand } : {}),
      ...(ogPrice ? { price: Number(ogPrice.replace(/[^0-9.]/g, '')) || ogPrice } : {}),
      ...(ogCurrency ? { currency: ogCurrency } : {}),
      ...(ogAvail ? { availability: ogAvail } : {}),
      ...(ogImage ? { images: [ogImage] } : {}),
      url: finalUrl,
    };
  }

  // Fallback for barcode / consumer packaged goods & microdata pages (e.g. Open Food Facts `/product/<gtin>`)
  const ogType = matchMetaContent(rawBody, ['og:type'])?.toLowerCase();
  const barcodeMatch = /\/product\/(\d{8,14})(?:\/|$)/i.exec(finalUrl);
  if (ogType === 'product' || ogType === 'og:product' || ogType?.includes('food') || barcodeMatch) {
    const titleCandidate = sanitizePlainMetadataText(
      matchMetaContent(rawBody, ['og:title', 'twitter:title']) ??
        extractFirstHeadingTextLinear(rawBody, 'h1') ??
        fallbackTitle,
      400,
    );
    if (titleCandidate) {
      const brandFromTitle = titleCandidate.includes('–')
        ? titleCandidate.split('–')[1]?.trim()
        : titleCandidate.includes(' - ')
          ? titleCandidate.split(' - ')[1]?.trim()
          : undefined;
      const cleanBarcodeDesc = sanitizePlainMetadataText(fallbackDescription, 1_200);
      return {
        title: titleCandidate,
        ...(cleanBarcodeDesc ? { description: cleanBarcodeDesc } : {}),
        ...(brandFromTitle ? { brand: brandFromTitle } : {}),
        ...(barcodeMatch?.[1] ? { gtin: barcodeMatch[1] } : {}),
        ...(ogImage ? { images: [ogImage] } : {}),
        url: finalUrl,
      };
    }
  }

  return null;
}

const SUPPORTED_INLINE_ACTIONS = new Set([
  'wait',
  'click',
  'write',
  'fill',
  'type',
  'select',
  'press',
  'scroll',
  'navigate',
  'screenshot',
  'scrape',
  'executejavascript',
  'pdf',
]);

/**
 * Validates and normalizes up to 50 sequential inline browser `actions` on `/v1/scrape` or `/v1/interact`.
 */
export function normalizeInlineBrowserActions(
  rawActions: unknown,
  selfHost?: string,
  maxItems = 50,
): { ok: true; actions: Array<Record<string, unknown>> } | { ok: false; message: string } {
  if (!Array.isArray(rawActions) || rawActions.length === 0) {
    return { ok: true, actions: [] };
  }
  if (rawActions.length > maxItems) {
    return { ok: false, message: `maximum ${maxItems} browser actions permitted per request` };
  }

  const out: Array<Record<string, unknown>> = [];
  for (const rawAct of rawActions) {
    if (!rawAct || typeof rawAct !== 'object' || Array.isArray(rawAct)) continue;
    const a = rawAct as Record<string, unknown>;
    const rawType = typeof a.type === 'string' ? a.type.trim() : '';
    const lowerType = rawType.toLowerCase();
    if (!SUPPORTED_INLINE_ACTIONS.has(lowerType)) {
      return { ok: false, message: `unsupported action type: ${rawType}` };
    }
    if (lowerType === 'navigate') {
      const navCheck = validatePublicHttpsTargetUrl(a.url, selfHost);
      if (!navCheck.ok) {
        return { ok: false, message: `navigate action: ${navCheck.message}` };
      }
    }
    const rawMs =
      typeof a.waitMs === 'number' && Number.isFinite(a.waitMs)
        ? a.waitMs
        : typeof a.milliseconds === 'number' && Number.isFinite(a.milliseconds)
          ? a.milliseconds
          : undefined;
    const explicitWaitMs = rawMs !== undefined ? Math.min(15_000, Math.max(0, Math.floor(rawMs))) : undefined;
    const keyVal = typeof a.key === 'string' ? a.key.slice(0, 40) : undefined;
    const textVal =
      typeof a.value === 'string'
        ? a.value.slice(0, 4096)
        : typeof a.text === 'string'
          ? a.text.slice(0, 4096)
          : undefined;
    const effectiveWaitMs =
      explicitWaitMs !== undefined
        ? explicitWaitMs
        : lowerType === 'click'
          ? 1_000
          : lowerType === 'press' && (!keyVal || /^(?:enter|return)$/i.test(keyVal))
            ? 800
            : undefined;

    out.push({
      type: lowerType === 'executejavascript' ? 'executeJavascript' : lowerType,
      ...(typeof a.selector === 'string' ? { selector: a.selector.slice(0, 240) } : {}),
      ...(a.all === true ? { all: true } : {}),
      ...(textVal !== undefined ? { value: textVal, text: textVal } : {}),
      ...(keyVal !== undefined ? { key: keyVal } : {}),
      ...(typeof a.direction === 'string' && /^(?:up|down)$/i.test(a.direction.trim())
        ? { direction: a.direction.trim().toLowerCase() }
        : {}),
      ...(typeof a.script === 'string' ? { script: a.script.slice(0, 16_384) } : {}),
      ...(a.fullPage === true ? { fullPage: true } : {}),
      ...(typeof a.url === 'string' ? { url: a.url.trim() } : {}),
      ...(effectiveWaitMs !== undefined ? { waitMs: effectiveWaitMs } : {}),
    });
  }
  return { ok: true, actions: out };
}

export function parsePdfParserOptions(rawParsers: unknown): {
  skipPdfParsing: boolean;
  ocrModeOverride?: 'off' | 'auto' | 'always';
  maxPagesOverride?: number;
  includePagesArray: boolean;
  includePageMarkers: boolean;
} {
  if (!Array.isArray(rawParsers)) {
    return { skipPdfParsing: false, includePagesArray: false, includePageMarkers: false };
  }
  if (rawParsers.length === 0) {
    return { skipPdfParsing: true, includePagesArray: false, includePageMarkers: false };
  }
  let ocrModeOverride: 'off' | 'auto' | 'always' | undefined;
  let maxPagesOverride: number | undefined;
  let includePagesArray = false;
  let includePageMarkers = false;
  let sawPdfParser = false;

  for (const p of rawParsers) {
    if (p === 'pdf') {
      sawPdfParser = true;
    } else if (p && typeof p === 'object' && !Array.isArray(p)) {
      const po = p as Record<string, unknown>;
      if (po.type === 'pdf') {
        sawPdfParser = true;
        if (po.mode === 'fast') ocrModeOverride = 'off';
        else if (po.mode === 'ocr') ocrModeOverride = 'always';
        else if (po.mode === 'auto') ocrModeOverride = 'auto';
        if (typeof po.maxPages === 'number' && Number.isFinite(po.maxPages)) {
          maxPagesOverride = Math.min(500, Math.max(1, Math.floor(po.maxPages)));
        }
        if (po.pages === true) includePagesArray = true;
        if (po.pageMarkers === true) includePageMarkers = true;
      }
    }
  }
  return {
    skipPdfParsing: !sawPdfParser && rawParsers.length > 0 && !rawParsers.includes('image'),
    ...(ocrModeOverride ? { ocrModeOverride } : {}),
    ...(maxPagesOverride ? { maxPagesOverride } : {}),
    includePagesArray,
    includePageMarkers,
  };
}

export function splitPdfPagesAndMarkers(
  rawPdfMarkdown: string,
  includePageMarkers: boolean,
): { pages: string[]; markedMarkdown: string } {
  if (!rawPdfMarkdown) return { pages: [], markedMarkdown: '' };
  const rawPages = rawPdfMarkdown.includes('\f')
    ? rawPdfMarkdown
        .split('\f')
        .map((p) => p.trim())
        .filter(Boolean)
    : [rawPdfMarkdown.trim()];
  if (!includePageMarkers) {
    return { pages: rawPages, markedMarkdown: rawPdfMarkdown };
  }
  const marked = rawPages.map((p, idx) => `<!-- page ${idx + 1} -->\n\n${p}`).join('\n\n');
  return { pages: rawPages, markedMarkdown: marked };
}

export function encodeBodyToRawBase64(item: Record<string, unknown>): string | undefined {
  if (typeof item.bodyBase64 === 'string' && item.bodyBase64.length > 0) {
    return item.bodyBase64;
  }
  if (typeof item.body === 'string' && item.body.length > 0) {
    if (item.bodyEncoding === 'base64') {
      return item.body;
    }
    const bytes = new TextEncoder().encode(item.body);
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }
  return undefined;
}
