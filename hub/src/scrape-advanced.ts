/**
 * Advanced `/v1/scrape` & `/v2/scrape` capabilities (`hub/src/scrape-advanced.ts`):
 *  - `$0` High-Precision Prompt Injection Guard (`checkPromptInjection: true` -> `403 SCRAPE_PROMPT_INJECTION_DETECTED`)
 *  - Structured E-Commerce `product` format (Schema.org `Product`, OpenGraph `product:*`, Shopify JSON)
 *  - Targeted `{ type: "attributes", selectors: [{ selector, attribute }] }` extraction
 *  - Inline browser `actions[]` normalizer (up to 50 steps: `click` `all`, `write`, `press`, `scroll`, `screenshot`, `scrape`, `executeJavascript`, `pdf`)
 *  - PDF `parsers` array (`parsers: []` raw base64 mode, `pages: true`, `pageMarkers: true`, `mode: "fast" | "auto" | "ocr"`)
 */

import { extractJsonLdObjects } from './extractors/utils';
import { isSafePublicHostname, validatePublicHttpsTargetUrl } from './overflow';
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

/** CommonMark §2.1 strict blank-line check: ONLY ASCII space (`0x20`) and ASCII tab (`0x09`) count as blank-line whitespace. */
export function isAsciiSpaceOrTabOnly(s: string, start = 0, end = s.length): boolean {
  for (let i = start; i < end; i++) {
    const c = s.charCodeAt(i);
    if (c !== 32 /* ' ' */ && c !== 9 /* '\t' */) return false;
  }
  return true;
}

function trimAsciiSpaceOrTabAndCrLinear(line: string): string {
  let start = 0;
  let end = line.length;
  if (end > 0 && line.charCodeAt(end - 1) === 13 /* '\r' */) end--;
  while (start < end && (line.charCodeAt(start) === 32 || line.charCodeAt(start) === 9)) start++;
  while (end > start && (line.charCodeAt(end - 1) === 32 || line.charCodeAt(end - 1) === 9)) end--;
  return start === 0 && end === line.length ? line : line.slice(start, end);
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
  lrm: '',
  rlm: '',
  alm: '',
  wj: '',
  wordjoiner: '',
  nobreak: '',
  af: '',
  applyfunction: '',
  it: '',
  invisibletimes: '',
  ic: '',
  invisiblecomma: '',
  zerowidthspace: '',
  negativethinspace: '',
  negativeverythinspace: '',
  negativemediumspace: '',
  negativethickspace: '',
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
    const trimmed = trimAsciiSpaceOrTabAndCrLinear(line);
    if (/^<!-- (?:page |pdf-page: )\d{1,6} -->$/.test(trimmed)) {
      continue;
    }
    lines[i] = replaceAllLtLinearFast(line);
    changed = true;
  }
  return changed ? lines.join('\n') : prose;
}

/**
 * Strips invisible Unicode Tag smuggling (`U+E0000`–`U+E007F`), Variation Selectors Supplement (`U+E0100`–`U+E01EF`),
 * Bidi overrides/isolates, zero-width / soft-hyphen characters, C1 controls (preserving `U+0085` NEL for line-separator folding),
 * ANSI CSI sequences, and raw ASCII C0/DEL control bytes.
 */
export function stripInvisibleSmugglingChars(s: string): string {
  if (!s || !/[^\x09\x0A\x0D\x20-\x7E]/.test(s)) return s;
  return s
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/\u0000(?!EF[A-Z]{2,12}\d{0,7}\u0000)(?<!\u0000EF[A-Z]{2,12}\d{0,7}\u0000)/g, '')
    .replace(
      /[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F\u0080-\u0084\u0086-\u009F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu,
      '',
    );
}

export function cleanFenceInfoStringLinear(rawInfo: string): string {
  if (!rawInfo) return '';
  const capped = rawInfo.length > 200 ? rawInfo.slice(0, 200) : rawInfo;
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
    if (c === 91 || c === 93 || c === 60 || c === 62) continue;
    if (c === 9) {
      out += ' ';
      continue;
    }
    if (c < 32) continue;
    out += s[i]!;
  }
  out = out.replace(/(?:^|[ \t]+)twoslash(?=[ \t]+|$)/gi, '').trimEnd();
  if (out.length >= 100) {
    let p = 0;
    while (p < out.length && (out.charCodeAt(p) === 32 || out.charCodeAt(p) === 9)) p++;
    const wordStart = p;
    while (p < out.length && p - wordStart <= 64) {
      const ch = out.charCodeAt(p);
      if (ch === 32 || ch === 9 || ch === 96 || ch === 126) break;
      p++;
    }
    const wordEnd = p;
    if (wordEnd > wordStart && wordEnd - wordStart <= 64) {
      let wsRun = 0;
      while (p < out.length && (out.charCodeAt(p) === 32 || out.charCodeAt(p) === 9)) {
        wsRun++;
        p++;
      }
      if (wsRun >= 8) {
        return out.slice(0, wordEnd).trimEnd();
      }
    }
  }
  return out;
}

function normalizeMarkdownLineEndingsUpfrontLinear(raw: string): string {
  if (!/[\r\u0085\u2028\u2029]/.test(raw)) return raw;
  const n = raw.length;
  let firstSpecial = -1;
  for (let i = 0; i < n; i++) {
    const c = raw.charCodeAt(i);
    if (c === 13 /* '\r' */ || c === 0x0085 || c === 0x2028 || c === 0x2029) {
      firstSpecial = i;
      break;
    }
  }
  if (firstSpecial < 0) return raw;
  const parts: string[] = [];
  let last = 0;
  for (let i = firstSpecial; i < n; i++) {
    const c = raw.charCodeAt(i);
    if (c === 13 /* '\r' */) {
      if (i > last) parts.push(raw.slice(last, i));
      parts.push('\n');
      if (i + 1 < n && raw.charCodeAt(i + 1) === 10 /* '\n' */) {
        i++;
      }
      last = i + 1;
    } else if (c === 0x0085 || c === 0x2028 || c === 0x2029) {
      if (i > last) parts.push(raw.slice(last, i));
      parts.push(' ');
      last = i + 1;
    }
  }
  if (last < n) parts.push(raw.slice(last));
  return parts.join('');
}

function normalizeSliceLineEndingsLengthPreserving(s: string): string {
  if (!/[\r\u0085\u2028\u2029]/.test(s)) return s;
  return s.replace(/\r(?!\n)/g, '\n').replace(/[\u0085\u2028\u2029]/g, ' ');
}

function isThematicBreakSimpleAt(raw: string, relCols: number, pos: number): boolean {
  if (relCols > 3 || pos >= raw.length) return false;
  const ch = raw.charCodeAt(pos);
  if (ch !== 45 /* '-' */ && ch !== 42 /* '*' */ && ch !== 95 /* '_' */) return false;
  let count = 0;
  for (let i = pos; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c === ch) count++;
    else if (c !== 32 && c !== 9) return false;
  }
  return count >= 3;
}

const _prefixFlagsOut = { prefixLen: 0, hasBlockquote: false, hasListMarker: false };

function scanContainerPrefixFlagsLinear(raw: string): { prefixLen: number; hasBlockquote: boolean; hasListMarker: boolean } {
  let i = 0;
  let pCol = 0;
  let hasBlockquote = false;
  let hasListMarker = false;
  for (;;) {
    const runStartCol = pCol;
    while (i < raw.length) {
      const ch = raw.charCodeAt(i);
      if (ch === 32) {
        pCol++;
        i++;
      } else if (ch === 9) {
        pCol += 4 - (pCol % 4);
        i++;
      } else {
        break;
      }
    }
    if (i >= raw.length) break;
    const c = raw.charCodeAt(i);
    if (c === 62 /* '>' */) {
      hasBlockquote = true;
      i++;
      pCol++;
      continue;
    }
    if (c === 45 /* '-' */ || c === 42 /* '*' */ || c === 43 /* '+' */) {
      if (i + 1 >= raw.length) {
        hasListMarker = true;
        i++;
        pCol++;
        break;
      }
      const nx = raw.charCodeAt(i + 1);
      if ((nx === 32 || nx === 9) && !isThematicBreakSimpleAt(raw, pCol - runStartCol, i)) {
        hasListMarker = true;
        i++;
        pCol++;
        continue;
      }
    } else if (c >= 48 && c <= 57) {
      let j = i;
      while (j < raw.length && j - i < 9 && raw.charCodeAt(j) >= 48 && raw.charCodeAt(j) <= 57) j++;
      if (j < raw.length && (raw.charCodeAt(j) === 46 /* '.' */ || raw.charCodeAt(j) === 41 /* ')' */)) {
        if (j + 1 >= raw.length || raw.charCodeAt(j + 1) === 32 || raw.charCodeAt(j + 1) === 9) {
          hasListMarker = true;
          pCol += j + 1 - i;
          i = j + 1;
          continue;
        }
      }
    }
    break;
  }
  _prefixFlagsOut.prefixLen = i;
  _prefixFlagsOut.hasBlockquote = hasBlockquote;
  _prefixFlagsOut.hasListMarker = hasListMarker;
  return _prefixFlagsOut;
}

export interface MarkdownFenceRecognizerState {
  inFence: boolean;
  fenceChar: '`' | '~' | '';
  fenceLen: number;
  effectiveFenceLen: number;
  prevLineWasAsciiBlank: boolean;
  possiblyInList: boolean;
  escapedUntrusted: { ch: '`' | '~'; len: number; needBlockquote: boolean } | null;
  untrustedFence: { ch: '`' | '~'; len: number; minIndent: number; needBlockquote: boolean } | null;
}

export function createMarkdownFenceRecognizerState(): MarkdownFenceRecognizerState {
  return {
    inFence: false,
    fenceChar: '',
    fenceLen: 0,
    effectiveFenceLen: 0,
    prevLineWasAsciiBlank: true,
    possiblyInList: false,
    escapedUntrusted: null,
    untrustedFence: null,
  };
}

function cloneMarkdownFenceRecognizerState(s: MarkdownFenceRecognizerState): MarkdownFenceRecognizerState {
  return {
    inFence: s.inFence,
    fenceChar: s.fenceChar,
    fenceLen: s.fenceLen,
    effectiveFenceLen: s.effectiveFenceLen,
    prevLineWasAsciiBlank: s.prevLineWasAsciiBlank,
    possiblyInList: s.possiblyInList,
    escapedUntrusted: s.escapedUntrusted ? { ...s.escapedUntrusted } : null,
    untrustedFence: s.untrustedFence ? { ...s.untrustedFence } : null,
  };
}

type CanonicalFenceStepKind = 'open_trusted' | 'in_trusted' | 'close_trusted' | 'prose';

interface CanonicalFenceStepResult {
  kind: CanonicalFenceStepKind;
  outLine: string;
  openedInfo: string;
  lengthenedEffectiveLen: number;
}

const _stepOut: CanonicalFenceStepResult = {
  kind: 'prose',
  outLine: '',
  openedInfo: '',
  lengthenedEffectiveLen: 0,
};

/**
 * Single canonical Markdown fence state machine (`R11-S1` & `R11-S2`):
 *  - **ONLY** top-level fences (`0..3` spaces, zero tabs, zero open blockquote or list containers) preceded by a strict
 *    ASCII blank line (`^[ \t]*$`) or start of document open a trusted raw fenced code block (`open_trusted`).
 *  - Every fence opened while ANY container (list item or blockquote) is open, tab-indented, `>= 4`-col indented, or not
 *    preceded by a blank line / start of document is treated strictly as prose (its fence delimiter is backslash-escaped
 *    when `harden === true`, and `<` + links inside its body are sanitized identically to prose).
 */
function stepCanonicalMarkdownFenceLine(
  raw: string,
  state: MarkdownFenceRecognizerState,
  harden: boolean,
): CanonicalFenceStepResult {
  _stepOut.openedInfo = '';
  _stepOut.lengthenedEffectiveLen = 0;

  if (state.inFence) {
    let pos = 0;
    let col = 0;
    let sawTab = false;
    while (pos < raw.length) {
      const ch = raw.charCodeAt(pos);
      if (ch === 32) {
        col++;
        pos++;
      } else if (ch === 9) {
        col += 4 - (col % 4);
        pos++;
        sawTab = true;
      } else {
        break;
      }
    }
    if (pos < raw.length) {
      const fcCode = state.fenceChar.charCodeAt(0);
      if (raw.charCodeAt(pos) === fcCode) {
        let p = pos;
        while (p < raw.length && raw.charCodeAt(p) === fcCode) p++;
        const runLen = p - pos;
        if (runLen >= state.fenceLen) {
          const onlyTrailingWs = isAsciiSpaceOrTabOnly(raw, p);
          if (col <= 3 && !sawTab && onlyTrailingWs) {
            const closeLen = Math.max(runLen, state.effectiveFenceLen);
            _stepOut.kind = 'close_trusted';
            _stepOut.outLine = harden ? state.fenceChar.repeat(closeLen) : raw;
            state.inFence = false;
            state.fenceChar = '';
            state.fenceLen = 0;
            state.effectiveFenceLen = 0;
            state.prevLineWasAsciiBlank = false;
            return _stepOut;
          }
          if (harden && runLen >= state.effectiveFenceLen) {
            state.effectiveFenceLen = runLen + 1;
            _stepOut.lengthenedEffectiveLen = state.effectiveFenceLen;
          }
        }
      }
    }
    _stepOut.kind = 'in_trusted';
    _stepOut.outLine = raw;
    return _stepOut;
  }

  // Fast-path empty line when not tracking an unhardened untrusted fence
  if (raw.length === 0 && state.untrustedFence === null) {
    if (state.escapedUntrusted?.needBlockquote) {
      state.escapedUntrusted = null;
    }
    state.prevLineWasAsciiBlank = true;
    _stepOut.kind = 'prose';
    _stepOut.outLine = raw;
    return _stepOut;
  }

  // Fast-path top-level ordinary prose lines starting with an ASCII letter (`A-Z` / `a-z`)
  if (state.untrustedFence === null && raw.length > 0) {
    const c0 = raw.charCodeAt(0);
    if ((c0 >= 65 && c0 <= 90) || (c0 >= 97 && c0 <= 122)) {
      if (state.escapedUntrusted) {
        if (state.escapedUntrusted.needBlockquote || state.prevLineWasAsciiBlank) {
          state.escapedUntrusted = null;
        }
      }
      if (state.prevLineWasAsciiBlank) {
        state.possiblyInList = false;
      }
      state.prevLineWasAsciiBlank = false;
      _stepOut.kind = 'prose';
      _stepOut.outLine = raw;
      return _stepOut;
    }
  }

  // Fast-path blockquote prose lines starting with `> <ASCII-letter>`
  if (
    state.untrustedFence === null &&
    raw.length >= 3 &&
    raw.charCodeAt(0) === 62 /* '>' */ &&
    raw.charCodeAt(1) === 32 /* ' ' */
  ) {
    const c2 = raw.charCodeAt(2);
    if ((c2 >= 65 && c2 <= 90) || (c2 >= 97 && c2 <= 122)) {
      state.prevLineWasAsciiBlank = false;
      _stepOut.kind = 'prose';
      _stepOut.outLine = raw;
      return _stepOut;
    }
  }

  let pos = 0;
  let col = 0;
  let sawTab = false;
  while (pos < raw.length) {
    const ch = raw.charCodeAt(pos);
    if (ch === 32) {
      col++;
      pos++;
    } else if (ch === 9) {
      col += 4 - (col % 4);
      pos++;
      sawTab = true;
    } else {
      break;
    }
  }
  const isBlank = pos >= raw.length;
  if (isBlank) {
    if (state.escapedUntrusted?.needBlockquote) {
      state.escapedUntrusted = null;
    }
    if (state.untrustedFence?.needBlockquote) {
      state.untrustedFence = null;
    }
    if (state.untrustedFence === null) {
      state.prevLineWasAsciiBlank = true;
    }
    _stepOut.kind = 'prose';
    _stepOut.outLine = raw;
    return _stepOut;
  }

  const pfx = scanContainerPrefixFlagsLinear(raw);
  const prefixLen = pfx.prefixLen;
  const hasBlockquote = pfx.hasBlockquote;
  const hasListMarker = pfx.hasListMarker;

  if (state.untrustedFence !== null) {
    if (
      (state.untrustedFence.needBlockquote && !hasBlockquote) ||
      (!state.untrustedFence.needBlockquote && state.untrustedFence.minIndent > 0 && col < state.untrustedFence.minIndent)
    ) {
      state.untrustedFence = null;
    } else {
      const uPos = prefixLen > pos ? prefixLen : pos;
      if (uPos < raw.length && col <= state.untrustedFence.minIndent + 3) {
        const uCode = state.untrustedFence.ch.charCodeAt(0);
        if (raw.charCodeAt(uPos) === uCode) {
          let p = uPos;
          while (p < raw.length && raw.charCodeAt(p) === uCode) p++;
          if (p - uPos >= state.untrustedFence.len && isAsciiSpaceOrTabOnly(raw, p)) {
            state.untrustedFence = null;
          }
        }
      }
      state.prevLineWasAsciiBlank = false;
      _stepOut.kind = 'prose';
      _stepOut.outLine = raw;
      return _stepOut;
    }
  }

  if (state.escapedUntrusted?.needBlockquote && !hasBlockquote) {
    state.escapedUntrusted = null;
  }

  if (state.prevLineWasAsciiBlank && col <= 1 && !hasBlockquote && !hasListMarker) {
    state.possiblyInList = false;
  }
  if (hasListMarker) {
    state.possiblyInList = true;
  }

  const fPos = prefixLen > pos ? prefixLen : pos;
  if (fPos + 3 <= raw.length) {
    const c0 = raw.charCodeAt(fPos);
    if (c0 === 96 /* '`' */ || c0 === 126 /* '~' */) {
      let fEnd = fPos + 1;
      while (fEnd < raw.length && raw.charCodeAt(fEnd) === c0) fEnd++;
      const fLen = fEnd - fPos;
      if (fLen >= 3 && !(c0 === 96 && raw.indexOf('`', fEnd) >= 0)) {
        const fCh: '`' | '~' = c0 === 96 ? '`' : '~';
        const onlyTrailingWs = isAsciiSpaceOrTabOnly(raw, fEnd);

        // 1. If we previously escaped an untrusted fence opener, escape its matching bare closer as well so it cannot invert polarity!
        if (
          harden &&
          state.escapedUntrusted &&
          state.escapedUntrusted.ch === fCh &&
          fLen >= state.escapedUntrusted.len &&
          onlyTrailingWs
        ) {
          state.escapedUntrusted = null;
          state.prevLineWasAsciiBlank = false;
          _stepOut.kind = 'prose';
          _stepOut.outLine = `${raw.slice(0, fPos)}${`\\${fCh}`.repeat(fLen)}${raw.slice(fEnd)}`;
          return _stepOut;
        }

        // 2. S1 Rule: ONLY top-level fences (`0..3` spaces, zero tabs, zero open containers) preceded by a blank line or start of doc keep raw content!
        const isTrustedTopLevel =
          state.prevLineWasAsciiBlank &&
          !sawTab &&
          col <= 3 &&
          fPos === pos &&
          !hasBlockquote &&
          !hasListMarker &&
          !state.possiblyInList;

        if (isTrustedTopLevel) {
          state.escapedUntrusted = null;
          state.inFence = true;
          state.fenceChar = fCh;
          state.fenceLen = fLen;
          state.effectiveFenceLen = fLen;
          state.prevLineWasAsciiBlank = false;
          _stepOut.kind = 'open_trusted';
          if (harden) {
            const cleanInfo = cleanFenceInfoStringLinear(raw.slice(fEnd));
            _stepOut.openedInfo = cleanInfo;
            _stepOut.outLine = `${fCh.repeat(fLen)}${cleanInfo}`;
          } else {
            _stepOut.openedInfo = raw.slice(fEnd);
            _stepOut.outLine = raw;
          }
          return _stepOut;
        }

        // 3. Untrusted fence (inside list/blockquote container, tab-indented, >= 4-col indented, or not preceded by blank line / doc start)
        state.prevLineWasAsciiBlank = false;
        _stepOut.kind = 'prose';
        if (harden) {
          state.escapedUntrusted = { ch: fCh, len: fLen, needBlockquote: hasBlockquote };
          _stepOut.outLine = `${raw.slice(0, fPos)}${`\\${fCh}`.repeat(fLen)}${raw.slice(fEnd)}`;
        } else {
          if (!hasListMarker && (hasBlockquote || col <= (state.possiblyInList ? 7 : 3))) {
            state.untrustedFence = {
              ch: fCh,
              len: fLen,
              minIndent: state.possiblyInList && !hasBlockquote ? Math.min(col, 2) : 0,
              needBlockquote: hasBlockquote,
            };
          }
          _stepOut.outLine = raw;
        }
        return _stepOut;
      }
    }
  }

  if (state.escapedUntrusted && state.prevLineWasAsciiBlank && col === 0 && !hasBlockquote && !hasListMarker) {
    state.escapedUntrusted = null;
  }

  // Guard `marked` multi-line `[label\n~~~\n]: url` and empty-destination `[y]:\n``` ` swallowing fences
  if (harden) {
    const checkBracketPos = prefixLen > pos ? prefixLen : col <= 3 ? pos : -1;
    if (checkBracketPos >= 0 && checkBracketPos < raw.length && raw.charCodeAt(checkBracketPos) === 91 /* '[' */) {
      const tail = raw.slice(checkBracketPos);
      const qLimit = Math.min(tail.length, 1024);
      let closeIdx = -1;
      for (let q = 1; q < qLimit; q++) {
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
      if (closeIdx < 0 && tail.length < 1024) {
        state.prevLineWasAsciiBlank = false;
        _stepOut.kind = 'prose';
        _stepOut.outLine = `${raw.slice(0, checkBracketPos)}\\${tail}`;
        return _stepOut;
      }
      if (
        closeIdx >= 0 &&
        closeIdx + 1 < tail.length &&
        tail.charCodeAt(closeIdx + 1) === 58 /* ':' */ &&
        isAsciiSpaceOrTabOnly(tail, closeIdx + 2)
      ) {
        state.prevLineWasAsciiBlank = false;
        _stepOut.kind = 'prose';
        _stepOut.outLine = `${raw.slice(0, checkBracketPos)}${tail.slice(0, closeIdx + 1)}\\${tail.slice(closeIdx + 1)}`;
        return _stepOut;
      }
    }
  }

  state.prevLineWasAsciiBlank = false;
  _stepOut.kind = 'prose';
  _stepOut.outLine = raw;
  return _stepOut;
}

export interface RecognizeMarkdownFencesOptions {
  harden?: boolean;
  preserveCrLf?: boolean;
  initialReopenedFence?: { ch: '`' | '~'; len: number };
  initialState?: MarkdownFenceRecognizerState;
  skipLeadingSeparatorEmptyLine?: boolean;
}

/**
 * Single canonical CommonMark fence recognizer & hardener (`R11-S1` & `R11-S2`):
 * Shared by both full-document Markdown sanitization (`scrape.ts`) and `read_artifact` / `maxChars` slice paging
 * (`scrape-advanced.ts`, `storage.ts`) so there is literally ONE function in TypeScript that decides what is a fence.
 */
export function recognizeAndHardenMarkdownFences(
  rawMd: string,
  opts: RecognizeMarkdownFencesOptions = {},
): { hardened: string; segments: string[] } {
  const harden = opts.harden !== false;
  const preserveCrLf = Boolean(opts.preserveCrLf);
  const reopened = opts.initialReopenedFence;
  if (!rawMd && !reopened) return { hardened: rawMd, segments: [rawMd] };

  const md = preserveCrLf ? normalizeSliceLineEndingsLengthPreserving(rawMd) : normalizeMarkdownLineEndingsUpfrontLinear(rawMd);
  if (!reopened && !md.includes('```') && !md.includes('~~~')) {
    return { hardened: md, segments: [md] };
  }

  const lines = md.split('\n');
  const outLines: string[] = [];
  const fenceSpans: Array<{ openLine: number; closeLine: number }> = [];
  const state = opts.initialState ? cloneMarkdownFenceRecognizerState(opts.initialState) : createMarkdownFenceRecognizerState();

  let fenceOpenOutIdx = -1;
  let fenceOpenInfo = '';
  let fenceOpenCr = '';

  if (reopened) {
    state.inFence = true;
    state.fenceChar = reopened.ch;
    state.fenceLen = reopened.len;
    state.effectiveFenceLen = reopened.len;
    state.prevLineWasAsciiBlank = false;
    fenceOpenOutIdx = 1;
    fenceOpenInfo = '';
    fenceOpenCr = '';
    outLines.push('', reopened.ch.repeat(reopened.len));
  }

  const skipSepNl = !reopened && Boolean(opts.skipLeadingSeparatorEmptyLine);

  for (let li = 0; li < lines.length; li++) {
    const rawWithCr = lines[li]!;
    const cr = preserveCrLf && rawWithCr.endsWith('\r') ? '\r' : '';
    const raw = cr ? rawWithCr.slice(0, -1) : rawWithCr;

    if (li === 0 && skipSepNl && raw.length === 0 && !state.inFence) {
      outLines.push(rawWithCr);
      continue;
    }

    const activeFenceCh = state.fenceChar;
    const step = stepCanonicalMarkdownFenceLine(raw, state, harden);

    if (step.kind === 'open_trusted') {
      fenceOpenOutIdx = outLines.length;
      fenceOpenInfo = step.openedInfo;
      fenceOpenCr = cr;
      outLines.push(`${step.outLine}${cr}`);
      continue;
    }

    if (step.kind === 'close_trusted') {
      outLines.push(`${step.outLine}${cr}`);
      fenceSpans.push({ openLine: fenceOpenOutIdx, closeLine: outLines.length - 1 });
      fenceOpenOutIdx = -1;
      fenceOpenInfo = '';
      fenceOpenCr = '';
      continue;
    }

    if (step.kind === 'in_trusted') {
      if (harden && step.lengthenedEffectiveLen > 0 && fenceOpenOutIdx >= 0) {
        outLines[fenceOpenOutIdx] = `${activeFenceCh.repeat(step.lengthenedEffectiveLen)}${fenceOpenInfo}${fenceOpenCr}`;
      }
      outLines.push(`${step.outLine}${cr}`);
      continue;
    }

    outLines.push(`${step.outLine}${cr}`);
  }

  if (state.inFence) {
    if (harden) {
      outLines.push(state.fenceChar.repeat(state.effectiveFenceLen));
    }
    fenceSpans.push({ openLine: fenceOpenOutIdx, closeLine: outLines.length - 1 });
  }

  const hardened = outLines.join('\n');
  if (fenceSpans.length === 0) {
    return { hardened, segments: [hardened] };
  }

  const segments: string[] = [];
  let lineCursor = 0;
  let prefixLeadingNewline = false;
  for (let si = 0; si < fenceSpans.length; si++) {
    const sp = fenceSpans[si]!;
    const proseLinesSlice = outLines.slice(lineCursor, sp.openLine);
    let proseText = proseLinesSlice.join('\n');
    if (prefixLeadingNewline) {
      proseText = `\n${proseText}`;
    }
    if (sp.openLine > lineCursor) {
      proseText = `${proseText}\n`;
    }
    segments.push(proseText);

    const fenceText = outLines.slice(sp.openLine, sp.closeLine + 1).join('\n');
    segments.push(fenceText);

    lineCursor = sp.closeLine + 1;
    prefixLeadingNewline = lineCursor < outLines.length;
  }

  if (lineCursor < outLines.length) {
    const tailText = outLines.slice(lineCursor).join('\n');
    segments.push(prefixLeadingNewline ? `\n${tailText}` : tailText);
  } else {
    segments.push('');
  }

  return { hardened, segments };
}

export interface MarkdownSliceCheckpoint {
  pos: number;
  inFence: boolean;
  fenceChar: string;
  fenceLen: number;
  fenceIndent: number;
  activeListIndent: number;
  listIndents?: readonly number[];
  prevLineWasParagraph: boolean;
  prevLineWasAsciiBlank?: boolean;
  possiblyInList?: boolean;
  escapedUntrusted?: { ch: '`' | '~'; len: number; needBlockquote: boolean } | null;
}

export function computeMarkdownSliceCheckpoints(rawFullMd: string, stepChars = 16_384): MarkdownSliceCheckpoint[] {
  const checkpoints: MarkdownSliceCheckpoint[] = [];
  if (!rawFullMd || rawFullMd.length <= stepChars) return checkpoints;
  const fullMd = normalizeSliceLineEndingsLengthPreserving(rawFullMd);
  const state = createMarkdownFenceRecognizerState();
  let nextCheckpointAt = stepChars;
  let pos = 0;
  const n = fullMd.length;

  while (pos < n) {
    if (pos >= nextCheckpointAt) {
      checkpoints.push({
        pos,
        inFence: state.inFence,
        fenceChar: state.fenceChar,
        fenceLen: state.fenceLen,
        fenceIndent: 0,
        activeListIndent: state.possiblyInList ? 2 : 0,
        prevLineWasParagraph: !state.prevLineWasAsciiBlank,
        prevLineWasAsciiBlank: state.prevLineWasAsciiBlank,
        possiblyInList: state.possiblyInList,
        escapedUntrusted: state.escapedUntrusted ? { ...state.escapedUntrusted } : null,
      });
      nextCheckpointAt = pos + stepChars;
    }
    const nl = fullMd.indexOf('\n', pos);
    const lineEnd = nl === -1 ? n : nl;
    const nextPos = nl === -1 ? n : nl + 1;
    const rawLine = lineEnd > pos && fullMd.charCodeAt(lineEnd - 1) === 13 ? fullMd.slice(pos, lineEnd - 1) : fullMd.slice(pos, lineEnd);
    stepCanonicalMarkdownFenceLine(rawLine, state, true);
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

  const state = createMarkdownFenceRecognizerState();
  let reconstructed = rawSlice;
  let initialReopenedFence: { ch: '`' | '~'; len: number } | undefined;
  let sliceInitialState: MarkdownFenceRecognizerState | undefined;
  let skipLeadingSeparatorEmptyLine = false;
  let forceLeadingNewlineForConcat = false;

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
        state.inFence = cp.inFence;
        state.fenceChar = cp.fenceChar === '`' || cp.fenceChar === '~' ? cp.fenceChar : '';
        state.fenceLen = cp.fenceLen;
        state.effectiveFenceLen = cp.fenceLen;
        state.prevLineWasAsciiBlank = cp.prevLineWasAsciiBlank ?? !cp.prevLineWasParagraph;
        state.possiblyInList = cp.possiblyInList ?? cp.activeListIndent > 0;
        state.escapedUntrusted = cp.escapedUntrusted ? { ...cp.escapedUntrusted } : null;
      }
    }

    while (pos <= clampedOffset && pos <= fullMd.length) {
      const nl = fullMd.indexOf('\n', pos);
      const lineEnd = nl === -1 ? fullMd.length : nl;
      const nextPos = nl === -1 ? fullMd.length + 1 : nl + 1;
      const rawLine = lineEnd > pos && fullMd.charCodeAt(lineEnd - 1) === 13 ? fullMd.slice(pos, lineEnd - 1) : fullMd.slice(pos, lineEnd);
      const containsOffset = clampedOffset >= pos && clampedOffset <= lineEnd;

      if (!containsOffset) {
        stepCanonicalMarkdownFenceLine(rawLine, state, true);
        pos = nextPos;
        continue;
      }

      const stateBeforeLine = cloneMarkdownFenceRecognizerState(state);
      const stepRes = stepCanonicalMarkdownFenceLine(rawLine, state, true);
      const firstSliceNl = reconstructed.indexOf('\n');

      if (stepRes.kind === 'open_trusted') {
        forceLeadingNewlineForConcat = true;
        if (clampedOffset > pos) {
          if (firstSliceNl >= 0) {
            reconstructed = reconstructed.slice(firstSliceNl + 1);
            initialReopenedFence = {
              ch: state.fenceChar as '`' | '~',
              len: state.fenceLen,
            };
          } else {
            reconstructed = `\n${state.fenceChar.repeat(state.fenceLen)}\n${state.fenceChar.repeat(state.fenceLen)}`;
          }
        } else {
          sliceInitialState = stateBeforeLine;
        }
      } else if (stepRes.kind === 'close_trusted') {
        forceLeadingNewlineForConcat = true;
        const firstHead = firstSliceNl >= 0 ? reconstructed.slice(0, firstSliceNl) : reconstructed;
        const escapedFirst = firstHead.replace(/^([ \t]*)([`~]+)/, (_m, ws: string, ticks: string) =>
          `${ws}${ticks.split('').map((ch) => `\\${ch}`).join('')}`,
        );
        reconstructed = firstSliceNl >= 0 ? `${escapedFirst}${reconstructed.slice(firstSliceNl)}` : escapedFirst;
        sliceInitialState = cloneMarkdownFenceRecognizerState(state);
      } else if (stateBeforeLine.inFence && stepRes.kind === 'in_trusted') {
        forceLeadingNewlineForConcat = true;
        initialReopenedFence = {
          ch: state.fenceChar as '`' | '~',
          len: state.fenceLen,
        };
      } else if (clampedOffset === pos) {
        sliceInitialState = stateBeforeLine;
      } else if (clampedOffset === lineEnd && rawSlice.startsWith('\n')) {
        sliceInitialState = cloneMarkdownFenceRecognizerState(state);
        skipLeadingSeparatorEmptyLine = true;
      } else {
        const firstHead = firstSliceNl >= 0 ? reconstructed.slice(0, firstSliceNl) : reconstructed;
        const escapedFirst = firstHead
          .replace(/^([ \t]*)([`~]{3,})/, (_m, ws: string, ticks: string) =>
            `${ws}${ticks.split('').map((ch) => `\\${ch}`).join('')}`,
          )
          .replace(/^([ \t]*)(?:([-+*])|(\d{1,9})([.)]))(?=[ \t]|$)/, (_m, ws: string, ul?: string, digits?: string, delim?: string) =>
            ul ? `${ws}\\${ul}` : `${ws}${digits}\\${delim}`,
          );
        reconstructed = firstSliceNl >= 0 ? `${escapedFirst}${reconstructed.slice(firstSliceNl)}` : escapedFirst;
        sliceInitialState = {
          ...stateBeforeLine,
          prevLineWasAsciiBlank: false,
        };
      }
      break;
    }
  }

  let { segments: segTexts } = recognizeAndHardenMarkdownFences(reconstructed, {
    harden: true,
    preserveCrLf: true,
    ...(initialReopenedFence ? { initialReopenedFence } : {}),
    ...(!initialReopenedFence && sliceInitialState ? { initialState: sliceInitialState } : {}),
    ...(!initialReopenedFence && skipLeadingSeparatorEmptyLine ? { skipLeadingSeparatorEmptyLine: true } : {}),
  });

  // Close any unclosed inline backtick code span in the final prose segment (`A1` truncation parity)
  const lastIdx = segTexts.length - 1;
  if (lastIdx >= 0 && lastIdx % 2 === 0 && segTexts[lastIdx]!.includes('`')) {
    const lastProse = segTexts[lastIdx]!;
    const lastBlank = lastProse.lastIndexOf('\n\n');
    const tailPara = lastBlank >= 0 ? lastProse.slice(lastBlank + 2) : lastProse;
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
      let trimEndIdx = lastProse.length;
      let wsProbe = trimEndIdx;
      while (wsProbe > 0 && (lastProse.charCodeAt(wsProbe - 1) === 32 || lastProse.charCodeAt(wsProbe - 1) === 9)) {
        wsProbe--;
      }
      if (wsProbe > 0 && (lastProse.charCodeAt(wsProbe - 1) === 10 || lastProse.charCodeAt(wsProbe - 1) === 13)) {
        trimEndIdx = wsProbe;
      }
      while (
        trimEndIdx > 0 &&
        (lastProse.charCodeAt(trimEndIdx - 1) === 10 || lastProse.charCodeAt(trimEndIdx - 1) === 13)
      ) {
        trimEndIdx--;
        let prevWs = trimEndIdx;
        while (prevWs > 0 && (lastProse.charCodeAt(prevWs - 1) === 32 || lastProse.charCodeAt(prevWs - 1) === 9)) {
          prevWs--;
        }
        if (prevWs > 0 && (lastProse.charCodeAt(prevWs - 1) === 10 || lastProse.charCodeAt(prevWs - 1) === 13)) {
          trimEndIdx = prevWs;
        }
      }
      const bodyBeforeNl = lastProse.slice(0, trimEndIdx);
      const trailingNls = lastProse.slice(trimEndIdx);
      const pad = bodyBeforeNl.endsWith('`') ? ' ' : '';
      segTexts[lastIdx] = `${bodyBeforeNl}${pad}${'`'.repeat(openTickLen)}${trailingNls}`;
      segTexts = recognizeAndHardenMarkdownFences(segTexts.join(''), {
        harden: true,
        preserveCrLf: true,
        ...(!initialReopenedFence && sliceInitialState ? { initialState: sliceInitialState } : {}),
        ...(!initialReopenedFence && skipLeadingSeparatorEmptyLine ? { skipLeadingSeparatorEmptyLine: true } : {}),
      }).segments;
    }
  }

  const sanitizeSliceSegments = (segs: readonly string[]): string =>
    segs
      .map((seg, idx) => {
        if (idx % 2 === 1) return seg;
        let cleanProse = stripInvisibleSmugglingChars(seg);
        cleanProse = escapeGfmTaskListCheckboxesLinear(cleanProse);
        cleanProse = neutralizeAllUnsafeMarkdownLinksLinear(cleanProse);
        return escapeAllResidualLtInProseLinear(cleanProse, allowPdfPageMarkers);
      })
      .join('');

  const pass1 = sanitizeSliceSegments(segTexts);
  const finalOut =
    !pass1.includes('```') && !pass1.includes('~~~')
      ? pass1
      : sanitizeSliceSegments(
          recognizeAndHardenMarkdownFences(pass1, {
            harden: true,
            preserveCrLf: true,
            ...(!initialReopenedFence && sliceInitialState ? { initialState: sliceInitialState } : {}),
            ...(!initialReopenedFence && skipLeadingSeparatorEmptyLine ? { skipLeadingSeparatorEmptyLine: true } : {}),
          }).segments,
        );
  if (
    safeOffset > 0 &&
    (forceLeadingNewlineForConcat || Boolean(initialReopenedFence) || /^[ \t]{0,3}(?:`{3,}|~{3,})/.test(finalOut))
  ) {
    if (!finalOut.startsWith('\n\n')) {
      return finalOut.startsWith('\n') ? `\n${finalOut}` : `\n\n${finalOut}`;
    }
  }
  return finalOut;
}

/**
 * Sanitizes an entire cached or freshly derived Markdown document in **O(N)** time before slicing in `readArtifactPage`
 * so multi-line fence polarity, container-prefixed pseudo-fences, unclosed EOF code spans/fences, GFM task-list checkboxes,
 * unsafe link destinations, and residual `<` are hardened across the full document prior to page boundary calculation.
 */
export function sanitizeFullMarkdownDocumentForArtifact(fullMd: string): string {
  if (!fullMd) return '';
  const stripped = stripInvisibleSmugglingChars(fullMd);
  const norm = /[\r\u0085\u2028\u2029]/.test(stripped)
    ? stripped.replace(/\r\n?/g, '\n').replace(/[\u0085\u2028\u2029]/g, ' ')
    : stripped;
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
  if (!/[^A-Za-z0-9.: ]|  /.test(s)) return s;
  const CHUNK_SIZE = 65_536;
  if (n <= CHUNK_SIZE) {
    return s.replace(/[^A-Za-z0-9.:]+/g, ' ');
  }
  const parts: string[] = [];
  let prevEndedSpace = false;
  for (let off = 0; off < n; off += CHUNK_SIZE) {
    let norm = s.slice(off, Math.min(n, off + CHUNK_SIZE)).replace(/[^A-Za-z0-9.:]+/g, ' ');
    if (prevEndedSpace && norm.charCodeAt(0) === 32) {
      norm = norm.slice(1);
    }
    if (norm.length > 0) {
      prevEndedSpace = norm.charCodeAt(norm.length - 1) === 32;
      parts.push(norm);
    }
  }
  return parts.join('');
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
  if (
    n < 7 ||
    !s.includes(' ') ||
    !/(?:^|[^A-Za-z0-9])[A-Za-z] +[A-Za-z] +[A-Za-z] +[A-Za-z](?:$|[^A-Za-z0-9])/.test(s)
  ) {
    return s;
  }
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

function normalizePublicProductImageUrl(raw: unknown, baseUrl?: string): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.startsWith('data:') || trimmed.startsWith('blob:') || trimmed.startsWith('javascript:')) {
    return null;
  }
  const candidate = trimmed.startsWith('//')
    ? trimmed.length > 2 && trimmed[2] !== '/' && trimmed[2] !== '\\'
      ? `https:${trimmed}`
      : ''
    : trimmed;
  if (!candidate) return null;
  let u: URL;
  try {
    u = baseUrl ? new URL(candidate, baseUrl) : new URL(candidate);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  if (u.username || u.password) return null;
  if (u.port && u.port !== '80' && u.port !== '443') return null;
  if (!isSafePublicHostname(u.hostname)) return null;
  return u.toString();
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
      .map((im) => {
        const rawImg =
          typeof im === 'string'
            ? im
            : im && typeof im === 'object' && typeof (im as { url?: unknown }).url === 'string'
              ? (im as { url: string }).url
              : '';
        return normalizePublicProductImageUrl(rawImg, finalUrl);
      })
      .filter((u): u is string => Boolean(u));

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
  const ogImage = normalizePublicProductImageUrl(matchMetaContent(rawBody, ['og:image']), finalUrl);

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
