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

const INJECTION_PATTERNS: Array<{ id: string; re: RegExp; weight: number }> = [
  {
    id: 'ignore_previous_instructions',
    re: /\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|each|every)(?:\s+of)?\s+)?(?:(?:the|your|these|those|my|our)\s+)?(?:previous|prior|above|earlier|preceding|system|developer|initial|original)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?)\b/i,
    weight: 3,
  },
  {
    id: 'new_system_role_override',
    re: /(?:^|\n)[ \t>]{0,20}(?:\[?[ \t]{0,10}system(?:[ \t]{1,10}(?:prompt|override|instruction|message|role))?[ \t]{0,10}\]?|<[ \t]{0,10}system[ \t]{0,10}>|#{1,6}[ \t]{0,10}system(?:[ \t]{1,10}instruction)?)[ \t]{0,10}:/i,
    weight: 3,
  },
  {
    id: 'exfiltrate_secrets_or_tools',
    re: /\b(?:send|post|upload|exfiltrate|transmit|forward|leak)\s+(?:(?:the|your|all|my|our)\s+)?(?:api[_\s-]?keys?|tokens?|secrets?|passwords?|credentials?|conversation|system\s+prompt|ssh|env)\s+(?:to|via)\s+(?:https?:\/\/|\[[^\]]{1,80}\]\(\s*https?:\/\/|[a-z0-9-]+(?:\.[a-z0-9-]+)+\b|this\b|here\b)/i,
    weight: 4,
  },
  {
    id: 'tool_invocation_hijack',
    re: /\b(?:immediately\s+call(?:\s+the\s+tool)?|now\s+call(?:\s+the\s+tool)?|you\s+must\s+now\s+execute|invoke\s+the\s+tool|execute\s+bash\s+command)\b[^\n]{0,80}\b(?:curl|wget|fetch(?:[_\s]?url)|bash|rm\s+-rf)\b/i,
    weight: 4,
  },
];

const HIDDEN_STYLE_TOKEN_RE =
  /(?:display[ \t]*:[ \t]*none|visibility[ \t]*:[ \t]*hidden|opacity[ \t]*:[ \t]*0(?:\.0+)?(?![0-9.])|font-size[ \t]*:[ \t]*0(?:px|em|rem|pt|%)?(?![0-9.])|clip-path[ \t]*:[ \t]*inset\(\s*100%|clip[ \t]*:[ \t]*rect\(\s*0|(?:left|top|text-indent)[ \t]*:[ \t]*-\d{3,}|height[ \t]*:[ \t]*0(?:px)?[ \t]*;[^;]{0,60}overflow[ \t]*:[ \t]*hidden|color[ \t]*:[ \t]*(?:#fff(?:fff)?|white|transparent)\b.{0,80}font-size[ \t]*:[ \t]*1px|font-size[ \t]*:[ \t]*1px.{0,80}color[ \t]*:[ \t]*(?:#fff(?:fff)?|white|transparent)\b)/i;
const HIDDEN_OVERRIDE_KEYWORD_RE = /\b(?:ignore|disregard|system[ \t\r\n]{1,10}prompt|assistant|tool|execute|instructions?|rules?)\b/i;

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

/**
 * Strictly linear **O(N)** Markdown link, image, autolink-label, reference-link, and footnote stripper (`R7`):
 * scans `](` sites over disjoint URL segments with monotonic quote/paren cursors so `'['.repeat(2_097_152)` and
 * `'[a]('.repeat(524_288)` finish in `< 5 ms` (fixing the `O(N^2)` loop), while handling `>2048`-char URLs,
 * nested `[[label]](url)`, quoted `"a)b"` titles, balanced `(a)` parens, `[label][ref]`, `![](...)`, and `[^fn]`.
 */
function unwrapMarkdownLinksForScanLinear(s: string): string {
  // Strip reference-link definition lines (`[id]: https://...`) and footnote markers (`[^1]`) first —
  // never strip `[system prompt]: prose` role-override headers!
  let work = s;
  if (work.includes(']:')) {
    work = work.replace(/^[ \t]{0,3}\[[^\]\r\n]{1,100}\]:[ \t]*<?(?:https?:|ftp:|mailto:|javascript:|\/|#)\S*[^\r\n]*$/gim, ' ');
  }
  if (work.includes('[^')) {
    work = work.replace(/\[\^[^\]\s]{1,64}\]/g, ' ');
  }
  if (work.includes('][')) {
    work = work.replace(/\]\[[^\]\r\n]{0,200}\]/g, ']');
  }
  const stripWordBrackets = (txt: string): string =>
    txt.includes('[') ? txt.replace(/\[{1,4}([A-Za-z]{2,32})\]*/g, '$1') : txt;

  if (!work.includes('](') || !work.includes(')')) {
    return stripWordBrackets(work);
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
      // Check bounded back-window `[last, bp)` for `![alt]` image or `[https://...]` autolink label to drop completely!
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
        if (isImg || /^(?:https?:\/\/|mailto:)\S+$/i.test(lbl)) {
          const dropStart = isImg ? openBr - 1 : openBr;
          out += `${work.slice(last, dropStart)} `;
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
  return stripWordBrackets(unwrapped);
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

function normalizeProseForInjectionScan(prose: string, fillerMode: 'space' | 'strip' | 'wordstream' = 'space'): string {
  let out = prose.includes('[SCRUBBED:')
    ? prose.replace(/\[SCRUBBED:\s*prompt injection blocked\s*\([^)\r\n]{0,200}\)\]/gi, ' ')
    : prose;
  out = decodeEntitiesForInjectionScan(out);
  if (out.includes('<!--')) {
    out = stripHtmlCommentsLinear(out, MAX_HTML_SCAN_CHARS);
  }
  if (out.includes('<')) {
    out = stripHtmlTagsLinear(out, ['script', 'style', 'noscript', 'template'], ' ', MAX_HTML_SCAN_CHARS);
    out = replaceHtmlTagsQuoteAwareLinear(
      out,
      (tag) => (INLINE_SPLIT_TAGS.has(tag.tagNameLower) || tag.tagNameLower === 'code' ? '' : ' '),
      MAX_HTML_SCAN_CHARS,
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
    out = unwrapMarkdownLinksForScanLinear(out);
  }

  if (fillerMode === 'wordstream') {
    return out
      .replace(/^\|?[ \t:-]+\|[ \t|:-]*$/gm, ' ')
      .replace(/[^A-Za-z0-9.\s:]+/g, ' ')
      .replace(/[ \t\r\n]+/g, ' ');
  }
  if (fillerMode === 'strip') {
    let sOut = out;
    if (/[`*_~]/.test(sOut)) sOut = sOut.replace(/[`*_~]/g, '');
    if (sOut.includes('  ')) sOut = sOut.replace(/  +/g, ' ');
    return sOut;
  }
  let res = out;
  if (res.includes('`')) res = res.replace(/`/g, ' ');
  if (/[*~]/.test(res)) res = res.replace(/[*~]{1,3}/g, '');
  if (res.includes('_')) res = res.replace(/(^|\s)_+|_+(\s|$)/g, '$1$2').replace(/_/g, ' ');
  if (res.includes('  ')) res = res.replace(/  +/g, ' ');
  return res;
}

/**
 * Scans extracted Markdown (including inline code spans and fenced/indented code blocks when `checkPromptInjection` runs)
 * and raw HTML for indirect prompt-injection payloads (`H1`, `R3-M3`, `M11`, `R7` 58/58 + 20/20 linear `< 20 ms` on `2 MiB`).
 */
export function detectPromptInjection(params: {
  markdown: string;
  rawHtml?: string;
}): { detected: boolean; triggers: string[] } {
  const boundedHtml = (params.rawHtml ?? '').slice(0, MAX_HTML_SCAN_CHARS);
  const boundedMd = params.markdown.slice(0, MAX_HTML_SCAN_CHARS);
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
        { maxChars: MAX_HTML_SCAN_CHARS },
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
          const norm = normalizeProseForInjectionScan(inner.slice(0, 8_192), 'wordstream');
          if (HIDDEN_OVERRIDE_KEYWORD_RE.test(norm)) {
            foundInert = true;
          }
          return '';
        },
        { maxChars: MAX_HTML_SCAN_CHARS },
      );
      if (foundInert) {
        triggers.push('hidden_css_instruction_injection');
        totalScore += 5;
      }
    }

    const nextCloseByTag = new Map<string, number>();
    let scannedHiddenUpTo = 0;
    if (!triggers.includes('hidden_css_instruction_injection')) {
      scanHtmlTagsLinear(
        rawForHidden,
        (tag) => {
          if (tag.isClosing || tag.isDeclaration) return;
          if (!tag.attrs) return;
          const attrs = parseOpenTagAttributes(tag.attrs);

          // Check `alt` / `title` attribute injection (`<img alt="ignore all previous instructions">`, `<span title="...">`)
          const attrCandidate = `${attrs.alt ?? ''} ${attrs.title ?? ''}`.trim();
          if (attrCandidate) {
            const normAttr = normalizeProseForInjectionScan(attrCandidate, 'wordstream');
            for (const pat of INJECTION_PATTERNS) {
              if (pat.re.test(normAttr)) {
                triggers.push('hidden_css_instruction_injection');
                totalScore += 5;
                return false;
              }
            }
          }
          if (tag.isSelfClosing) return;

          const normStyle = attrs.style ? normalizeCssStyleForHiddenCheck(attrs.style) : '';
          const isHiddenAttr = 'hidden' in attrs || (attrs['aria-hidden'] ?? '').trim().toLowerCase() === 'true';
          const classTokens = (attrs.class ?? '').toLowerCase().split(/\s+/).filter(Boolean);
          const hasHiddenClass = classTokens.some((c) => styleHiddenClasses.has(c));
          const isHiddenSubtree = isHiddenAttr || hasHiddenClass || (normStyle !== '' && HIDDEN_STYLE_TOKEN_RE.test(normStyle));
          if (!isHiddenSubtree) return;

          const closeNeedle = `</${tag.tagNameLower}`;
          let closeIdx = nextCloseByTag.get(tag.tagNameLower);
          if (closeIdx === undefined || (closeIdx >= 0 && closeIdx < tag.end)) {
            let searchFrom = closeIdx !== undefined && closeIdx >= 0 ? Math.max(tag.end, closeIdx) : tag.end;
            let found = -1;
            while (searchFrom < rawForHidden.length) {
              const cand = lowerForHidden.indexOf(closeNeedle, searchFrom);
              if (cand < 0) break;
              const afterIdx = cand + closeNeedle.length;
              if (afterIdx < rawForHidden.length && isTagNameBoundary(rawForHidden.charCodeAt(afterIdx))) {
                found = cand;
                break;
              }
              searchFrom = afterIdx;
            }
            closeIdx = found;
            nextCloseByTag.set(tag.tagNameLower, closeIdx);
          }

          const maxSearchEnd = Math.min(rawForHidden.length, tag.end + 16_384);
          const sliceEnd = closeIdx >= 0 && closeIdx <= maxSearchEnd ? closeIdx : Math.min(rawForHidden.length, tag.end + 8_192);
          const sliceStart = Math.max(tag.end, scannedHiddenUpTo - 64);
          if (sliceEnd <= sliceStart) return;
          scannedHiddenUpTo = Math.max(scannedHiddenUpTo, sliceEnd);
          const rawSlice = stripHtmlTagsQuoteAwareLinear(rawForHidden.slice(sliceStart, sliceEnd), '', 16_384);
          const innerStream = normalizeProseForInjectionScan(rawSlice, 'wordstream');
          if (HIDDEN_OVERRIDE_KEYWORD_RE.test(innerStream)) {
            triggers.push('hidden_css_instruction_injection');
            totalScore += 5;
            return false;
          }
          return undefined;
        },
        MAX_HTML_SCAN_CHARS,
        false,
      );
    }
  }

  // 3. Full Markdown + code-span / fenced-block scan (`M11` & `R7`: single base normalization pass `< 15 ms` on `2 MiB`!)
  const scanSpaced = normalizeProseForInjectionScan(boundedMd, 'space');
  if (/[A-Za-z]/.test(scanSpaced)) {
    const scanWordStream = /[\n|,$>#-]/.test(scanSpaced)
      ? scanSpaced
          .replace(/^\|?[ \t:-]+\|[ \t|:-]*$/gm, ' ')
          .replace(/[^A-Za-z0-9.\s:]+/g, ' ')
          .replace(/[ \t\r\n]+/g, ' ')
      : scanSpaced;
    const needsStrippedPass = /[\u115F\u1160\u3164\uFFA0`*_~]/.test(boundedMd);
    const scanStripped = needsStrippedPass ? normalizeProseForInjectionScan(boundedMd, 'strip') : '';

    for (const pat of INJECTION_PATTERNS) {
      if (
        pat.re.test(scanSpaced) ||
        (scanWordStream !== scanSpaced && pat.re.test(scanWordStream)) ||
        (scanStripped && pat.re.test(scanStripped)) ||
        (pat.id === 'exfiltrate_secrets_or_tools' && pat.re.test(boundedMd))
      ) {
        triggers.push(pat.id);
        totalScore += pat.weight;
      }
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
    const brand =
      typeof brandRaw === 'string'
        ? brandRaw
        : brandRaw && typeof brandRaw === 'object' && typeof (brandRaw as { name?: unknown }).name === 'string'
          ? (brandRaw as { name: string }).name
          : undefined;

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

    return {
      title: typeof productLd.name === 'string' ? productLd.name : fallbackTitle,
      ...(typeof productLd.description === 'string' ? { description: productLd.description } : fallbackDescription ? { description: fallbackDescription } : {}),
      ...(brand ? { brand } : {}),
      ...(typeof productLd.sku === 'string' ? { sku: productLd.sku } : {}),
      ...(typeof productLd.gtin13 === 'string' ? { gtin: productLd.gtin13 } : typeof productLd.gtin === 'string' ? { gtin: productLd.gtin } : {}),
      ...(price !== undefined ? { price } : {}),
      ...(currency ? { currency } : {}),
      ...(availability ? { availability } : {}),
      url: typeof productLd.url === 'string' ? productLd.url : finalUrl,
      ...(images.length > 0 ? { images } : {}),
      ...(ratingObj?.ratingValue !== undefined ? { rating: Number(ratingObj.ratingValue) || ratingObj.ratingValue } : {}),
      ...(ratingObj?.reviewCount !== undefined ? { reviewCount: Number(ratingObj.reviewCount) || ratingObj.reviewCount } : {}),
      ...(offerList.length > 1
        ? {
            variants: offerList.slice(0, 30).map((o) => ({
              ...(typeof o.name === 'string' ? { name: o.name } : {}),
              ...(typeof o.sku === 'string' ? { sku: o.sku } : {}),
              ...(o.price !== undefined ? { price: Number(String(o.price).replace(/[^0-9.]/g, '')) || o.price } : {}),
              ...(typeof o.priceCurrency === 'string' ? { currency: o.priceCurrency } : {}),
              ...(typeof o.availability === 'string' ? { availability: o.availability.replace(/^https?:\/\/schema\.org\//i, '') } : {}),
            })),
          }
        : {}),
    };
  }

  // Fallback to OpenGraph `product:price:amount` / meta tags
  const ogPrice = matchMetaContent(rawBody, ['product:price:amount', 'og:price:amount', 'price']);
  const ogCurrency = matchMetaContent(rawBody, ['product:price:currency', 'og:price:currency', 'priceCurrency']);
  const ogBrand = matchMetaContent(rawBody, ['product:brand', 'og:brand', 'brand']);
  const ogAvail = matchMetaContent(rawBody, ['product:availability', 'og:availability', 'availability']);
  const ogImage = matchMetaContent(rawBody, ['og:image']);

  if (ogPrice || ogBrand || ogAvail) {
    return {
      title: matchMetaContent(rawBody, ['og:title']) ?? fallbackTitle,
      ...(fallbackDescription ? { description: fallbackDescription } : {}),
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
    const titleCandidate =
      matchMetaContent(rawBody, ['og:title', 'twitter:title']) ??
      extractFirstHeadingTextLinear(rawBody, 'h1') ??
      fallbackTitle;
    if (titleCandidate) {
      const brandFromTitle = titleCandidate.includes('–')
        ? titleCandidate.split('–')[1]?.trim()
        : titleCandidate.includes(' - ')
          ? titleCandidate.split(' - ')[1]?.trim()
          : undefined;
      return {
        title: titleCandidate,
        ...(fallbackDescription ? { description: fallbackDescription } : {}),
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
