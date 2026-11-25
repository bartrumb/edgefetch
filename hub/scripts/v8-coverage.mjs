import { existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';

const VLQ_BASE_SHIFT = 5;
const VLQ_BASE = 1 << VLQ_BASE_SHIFT; // 32
const VLQ_BASE_MASK = VLQ_BASE - 1; // 31
const VLQ_CONTINUATION_BIT = VLQ_BASE; // 32

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_LUT = new Int16Array(128).fill(-1);
for (let i = 0; i < BASE64_ALPHABET.length; i++) {
  BASE64_LUT[BASE64_ALPHABET.charCodeAt(i)] = i;
}

function resolveRealPath(p) {
  if (typeof realpathSync.native === 'function') {
    try {
      return realpathSync.native(p);
    } catch {
      return realpathSync(p);
    }
  }
  return realpathSync(p);
}

export function canonicalizePath(p) {
  let resolved;
  try {
    resolved = existsSync(p) ? resolveRealPath(p) : resolve(p);
  } catch {
    resolved = resolve(p);
  }
  let norm = resolved.replace(/\\/g, '/');
  if (/^[a-z]:\//.test(norm)) {
    norm = norm[0].toUpperCase() + norm.slice(1);
  }
  return norm;
}

function decodeVlqSegment(str, startIdx, endIdx) {
  const values = [];
  let idx = startIdx;
  while (idx < endIdx) {
    let result = 0;
    let shift = 0;
    let continuation = true;
    while (continuation && idx < endIdx) {
      const code = str.charCodeAt(idx++);
      const digit = code < 128 ? BASE64_LUT[code] : -1;
      if (digit < 0) throw new Error(`Invalid Base64-VLQ char at index ${idx - 1}`);
      continuation = (digit & VLQ_CONTINUATION_BIT) !== 0;
      result += (digit & VLQ_BASE_MASK) << shift;
      shift += VLQ_BASE_SHIFT;
    }
    const isNegative = (result & 1) === 1;
    const magnitude = result >> 1;
    values.push(isNegative ? -magnitude : magnitude);
  }
  return values;
}

function computeLineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* '\n' */) {
      starts.push(i + 1);
    }
  }
  return starts;
}

function offsetToLineCol(lineStarts, offset) {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (lineStarts[mid] <= offset) {
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  const line = hi < 0 ? 0 : hi;
  return { line, col: offset - lineStarts[line] };
}

function extractSourceMapJson(jsText, bundlePath) {
  const marker = '//# sourceMappingURL=';
  const idx = jsText.lastIndexOf(marker);
  if (idx < 0) return null;
  const lineEnd = jsText.indexOf('\n', idx);
  const url = (lineEnd < 0 ? jsText.slice(idx + marker.length) : jsText.slice(idx + marker.length, lineEnd)).trim();
  const base64Prefix = 'data:application/json;';
  if (url.startsWith(base64Prefix)) {
    const commaIdx = url.indexOf(',');
    if (commaIdx < 0) return null;
    const meta = url.slice(base64Prefix.length, commaIdx);
    const payload = url.slice(commaIdx + 1);
    if (meta.includes('base64')) {
      return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    }
    return JSON.parse(decodeURIComponent(payload));
  }
  const mapPath = resolve(dirname(bundlePath), url);
  if (existsSync(mapPath)) {
    return JSON.parse(readFileSync(mapPath, 'utf8'));
  }
  return null;
}

export function parseSourceMap(jsText, bundleDir) {
  const rawMap = extractSourceMapJson(jsText, bundleDir);
  if (!rawMap) {
    throw new Error(`Missing inline/external sourcemap in bundle ${bundleDir}`);
  }
  const baseDir = rawMap.sourceRoot ? resolve(bundleDir, rawMap.sourceRoot) : bundleDir;
  const sources = (rawMap.sources ?? []).map((src) => {
    if (src.startsWith('file://')) {
      return canonicalizePath(fileURLToPath(src));
    }
    return canonicalizePath(resolve(baseDir, src));
  });
  const sourcesContent = Array.isArray(rawMap.sourcesContent) ? rawMap.sourcesContent : [];
  const lineStarts = computeLineStarts(jsText);

  const mappings = rawMap.mappings ?? '';
  const lines = [];
  let genLine = 0;
  let prevSrcIdx = 0;
  let prevOrigLine = 0;
  let prevOrigCol = 0;

  let lineStartPos = 0;
  const mapLen = mappings.length;
  while (lineStartPos <= mapLen) {
    let lineEndPos = mappings.indexOf(';', lineStartPos);
    if (lineEndPos < 0) lineEndPos = mapLen;
    const segs = [];
    let prevGenCol = 0;

    if (lineEndPos > lineStartPos) {
      let segStart = lineStartPos;
      while (segStart <= lineEndPos) {
        let segEnd = mappings.indexOf(',', segStart);
        if (segEnd < 0 || segEnd > lineEndPos) segEnd = lineEndPos;
        if (segEnd > segStart) {
          const vals = decodeVlqSegment(mappings, segStart, segEnd);
          const genCol = prevGenCol + vals[0];
          prevGenCol = genCol;
          if (vals.length >= 4) {
            const srcIdx = prevSrcIdx + vals[1];
            const origLine = prevOrigLine + vals[2];
            const origCol = prevOrigCol + vals[3];
            prevSrcIdx = srcIdx;
            prevOrigLine = origLine;
            prevOrigCol = origCol;
            segs.push({ genCol, srcIdx, origLine, origCol });
          } else {
            segs.push({ genCol, srcIdx: -1, origLine: -1, origCol: -1 });
          }
        }
        if (segEnd === lineEndPos) break;
        segStart = segEnd + 1;
      }
    }

    lines[genLine] = segs;
    genLine++;
    if (lineEndPos === mapLen) break;
    lineStartPos = lineEndPos + 1;
  }

  return {
    sources,
    sourcesContent,
    lines,
    lineStarts,
    textLength: jsText.length,
    lookup(offset) {
      const { line, col } = offsetToLineCol(lineStarts, offset);
      const segs = lines[line];
      if (!segs || segs.length === 0) return null;
      let lo = 0;
      let hi = segs.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (segs[mid].genCol <= col) {
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }
      if (hi < 0) return null;
      const seg = segs[hi];
      if (seg.srcIdx < 0 || seg.srcIdx >= sources.length) return null;
      return {
        file: sources[seg.srcIdx],
        line: seg.origLine + 1, // 1-based
        col: seg.origCol,
      };
    },
  };
}

/**
 * Flatten a single V8 ScriptCoverage's functions[].ranges into sorted disjoint
 * intervals [{ start, end, count }] using endpoint coordinate-compression + DSU painting
 * so the innermost (smallest length, latest) range always wins in O(R log R).
 */
export function flattenScriptCoverageRanges(scriptCov) {
  const rawRanges = [];
  let order = 0;
  for (const fn of scriptCov.functions ?? []) {
    for (const r of fn.ranges ?? []) {
      if (r.endOffset > r.startOffset) {
        rawRanges.push({
          start: r.startOffset,
          end: r.endOffset,
          count: r.count,
          len: r.endOffset - r.startOffset,
          order: order++,
        });
      }
    }
  }
  if (rawRanges.length === 0) return [];

  const coordSet = new Set();
  for (const r of rawRanges) {
    coordSet.add(r.start);
    coordSet.add(r.end);
  }
  const coords = Array.from(coordSet).sort((a, b) => a - b);
  const coordIdx = new Map();
  for (let i = 0; i < coords.length; i++) {
    coordIdx.set(coords[i], i);
  }

  const m = coords.length - 1;
  const counts = new Int32Array(m).fill(-1);
  const parent = new Int32Array(m + 1);
  for (let i = 0; i <= m; i++) parent[i] = i;

  const find = (x) => {
    let root = x;
    while (parent[root] !== root) root = parent[root];
    let cur = x;
    while (cur !== root) {
      const nxt = parent[cur];
      parent[cur] = root;
      cur = nxt;
    }
    return root;
  };

  // Smallest span first; on identical span, later (innermost) range first
  rawRanges.sort((a, b) => a.len - b.len || b.order - a.order);

  for (const r of rawRanges) {
    const si = coordIdx.get(r.start);
    const ei = coordIdx.get(r.end);
    for (let k = find(si); k < ei; k = find(k)) {
      counts[k] = r.count;
      parent[k] = find(k + 1);
    }
  }

  const intervals = [];
  for (let k = 0; k < m; k++) {
    const c = counts[k];
    if (c < 0) continue;
    const start = coords[k];
    const end = coords[k + 1];
    const prev = intervals.length > 0 ? intervals[intervals.length - 1] : null;
    if (prev && prev.end === start && prev.count === c) {
      prev.end = end;
    } else {
      intervals.push({ start, end, count: c });
    }
  }
  return intervals;
}

function countAtIntervals(intervals, offset) {
  let lo = 0;
  let hi = intervals.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const iv = intervals[mid];
    if (offset < iv.start) {
      hi = mid - 1;
    } else if (offset >= iv.end) {
      lo = mid + 1;
    } else {
      return iv.count;
    }
  }
  return 0;
}

function createCounter(intervalSets) {
  if (!intervalSets || intervalSets.length === 0) {
    return () => 0;
  }
  if (intervalSets.length === 1) {
    const ivs = intervalSets[0];
    return (offset) => countAtIntervals(ivs, offset);
  }
  return (offset) => {
    let sum = 0;
    for (const ivs of intervalSets) {
      sum += countAtIntervals(ivs, offset);
    }
    return sum;
  };
}

function anyIntervalHitInRange(intervals, start, end) {
  let lo = 0;
  let hi = intervals.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (intervals[mid].end <= start) {
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  for (let i = lo; i < intervals.length; i++) {
    const iv = intervals[i];
    if (iv.start >= end) break;
    if (iv.count > 0) return true;
  }
  return false;
}

// --- ES2022 JS Tokenizer & Branch-Arm Extractor ---

const KEYWORDS = new Set([
  'if', 'else', 'switch', 'case', 'default', 'try', 'catch', 'finally',
  'for', 'while', 'do', 'with', 'function', 'class', 'return', 'throw',
  'typeof', 'void', 'delete', 'await', 'yield', 'new', 'in', 'instanceof',
  'of', 'break', 'continue', 'let', 'const', 'var', 'import', 'export',
  'from', 'as', 'static', 'get', 'set', 'async', 'this', 'super',
  'true', 'false', 'null', 'debugger',
]);

const REGEX_AFTER_KW = new Set([
  'return', 'throw', 'case', 'typeof', 'void', 'delete', 'await', 'yield',
  'new', 'in', 'instanceof', 'of', 'else', 'do', 'export',
]);

function isIdentStart(ch) {
  return (
    (ch >= 65 && ch <= 90) ||
    (ch >= 97 && ch <= 122) ||
    ch === 95 || // _
    ch === 36 || // $
    ch > 127
  );
}

function isIdentPart(ch) {
  return isIdentStart(ch) || (ch >= 48 && ch <= 57);
}

function isDigit(ch) {
  return ch >= 48 && ch <= 57;
}

function isWhitespace(ch) {
  return ch === 32 || ch === 9 || ch === 10 || ch === 13 || ch === 12 || ch === 11 || ch === 0xfeff || ch === 0xa0;
}

export function tokenizeEs2022(src) {
  const tokens = [];
  const len = src.length;
  let i = 0;
  let braceDepth = 0;
  // Stack of { braceDepth } for active `${...}` inside template literals
  const tplStack = [];
  // Track control-flow header parens `if (...)`, `while (...)`, `for (...)`, `with (...)`, `switch (...)`
  const parenStack = [];
  let prevToken = null;
  let prevPrevToken = null;

  const prevAllowsRegex = () => {
    if (!prevToken) return true;
    const { type, value } = prevToken;
    if (type === 'kw') return REGEX_AFTER_KW.has(value);
    if (type === 'punct') {
      if (value === '(' || value === '[' || value === '{' || value === ',' || value === ';' || value === ':') return true;
      if (value === ')') return Boolean(prevToken.isCtrlHeaderClose);
      return false; // `]` or `}`
    }
    if (type === 'op') {
      if (value === '++' || value === '--') {
        // Postfix ++/-- does NOT allow regex; prefix ++/-- does
        if (!prevPrevToken) return true;
        const pt = prevPrevToken;
        return !(pt.type === 'id' || pt.value === ')' || pt.value === ']');
      }
      return true;
    }
    return false;
  };

  const scanTemplateSegment = (startOffset, isHead) => {
    let j = startOffset;
    while (j < len) {
      const c = src.charCodeAt(j);
      if (c === 92 /* \ */) {
        j += 2;
        continue;
      }
      if (c === 96 /* ` */) {
        j++;
        const tok = { type: isHead ? 'tpl_full' : 'tpl_tail', value: '`', start: startOffset, end: j };
        tokens.push(tok);
        prevPrevToken = prevToken;
        prevToken = tok;
        return j;
      }
      if (c === 36 /* $ */ && j + 1 < len && src.charCodeAt(j + 1) === 123 /* { */) {
        j += 2;
        braceDepth++;
        tplStack.push(braceDepth);
        const tok = { type: isHead ? 'tpl_head' : 'tpl_mid', value: '${', start: startOffset, end: j };
        tokens.push(tok);
        prevPrevToken = prevToken;
        prevToken = tok;
        return j;
      }
      j++;
    }
    const tok = { type: isHead ? 'tpl_full' : 'tpl_tail', value: '`', start: startOffset, end: len };
    tokens.push(tok);
    prevPrevToken = prevToken;
    prevToken = tok;
    return len;
  };

  while (i < len) {
    const ch = src.charCodeAt(i);
    if (isWhitespace(ch)) {
      i++;
      continue;
    }

    // Line comment //
    if (ch === 47 /* / */ && i + 1 < len && src.charCodeAt(i + 1) === 47) {
      const nl = src.indexOf('\n', i + 2);
      i = nl < 0 ? len : nl + 1;
      continue;
    }
    // Block comment /* ... */
    if (ch === 47 /* / */ && i + 1 < len && src.charCodeAt(i + 1) === 42) {
      const close = src.indexOf('*/', i + 2);
      i = close < 0 ? len : close + 2;
      continue;
    }
    // Hashbang #! at start of file
    if (i === 0 && ch === 35 && i + 1 < len && src.charCodeAt(i + 1) === 33) {
      const nl = src.indexOf('\n', 2);
      i = nl < 0 ? len : nl + 1;
      continue;
    }

    // String literal '...' or "..."
    if (ch === 39 || ch === 34) {
      const quote = ch;
      const start = i++;
      while (i < len) {
        const c = src.charCodeAt(i);
        if (c === 92 /* \ */) {
          i += 2;
          continue;
        }
        i++;
        if (c === quote) break;
      }
      const tok = { type: 'str', value: src.slice(start, i), start, end: i };
      tokens.push(tok);
      prevPrevToken = prevToken;
      prevToken = tok;
      continue;
    }

    // Template literal `...`
    if (ch === 96 /* ` */) {
      i = scanTemplateSegment(i + 1, true);
      continue;
    }

    // Regex literal vs division /
    if (ch === 47 /* / */ && prevAllowsRegex()) {
      const start = i++;
      let inClass = false;
      while (i < len) {
        const c = src.charCodeAt(i);
        if (c === 92 /* \ */) {
          i += 2;
          continue;
        }
        if (c === 91 /* [ */) {
          inClass = true;
        } else if (c === 93 /* ] */) {
          inClass = false;
        } else if (c === 47 /* / */ && !inClass) {
          i++;
          break;
        } else if (c === 10 || c === 13) {
          break;
        }
        i++;
      }
      while (i < len && isIdentPart(src.charCodeAt(i))) i++;
      const tok = { type: 'regex', value: src.slice(start, i), start, end: i };
      tokens.push(tok);
      prevPrevToken = prevToken;
      prevToken = tok;
      continue;
    }

    // Numbers (0x, 0b, 0o, decimal, float, exponent, BigInt n, _ separators)
    if (isDigit(ch) || (ch === 46 /* . */ && i + 1 < len && isDigit(src.charCodeAt(i + 1)))) {
      const start = i;
      if (ch === 48 && i + 1 < len) {
        const next = src.charCodeAt(i + 1);
        if (next === 120 || next === 88 || next === 98 || next === 66 || next === 111 || next === 79) {
          i += 2;
          while (i < len && (isIdentPart(src.charCodeAt(i)) || src.charCodeAt(i) === 95)) i++;
          const tok = { type: 'num', value: src.slice(start, i), start, end: i };
          tokens.push(tok);
          prevPrevToken = prevToken;
          prevToken = tok;
          continue;
        }
      }
      while (i < len) {
        const c = src.charCodeAt(i);
        if (isDigit(c) || c === 95 || c === 46) {
          i++;
        } else if ((c === 101 || c === 69) && i + 1 < len) {
          i++;
          const sign = src.charCodeAt(i);
          if (sign === 43 || sign === 45) i++;
        } else {
          break;
        }
      }
      if (i < len && src.charCodeAt(i) === 110 /* n */) i++;
      const tok = { type: 'num', value: src.slice(start, i), start, end: i };
      tokens.push(tok);
      prevPrevToken = prevToken;
      prevToken = tok;
      continue;
    }

    // Private identifier #name or identifier / keyword
    if (ch === 35 /* # */ || isIdentStart(ch)) {
      const start = i;
      if (ch === 35) i++;
      while (i < len && isIdentPart(src.charCodeAt(i))) i++;
      const val = src.slice(start, i);
      // After `.` or `?.`, property names like `obj.default` or `obj.if` are identifiers, not keywords
      const afterDot = prevToken && (prevToken.value === '.' || prevToken.value === '?.');
      const isKw = !afterDot && KEYWORDS.has(val);
      const tok = { type: isKw ? 'kw' : 'id', value: val, start, end: i };
      tokens.push(tok);
      prevPrevToken = prevToken;
      prevToken = tok;
      continue;
    }

    // Punctuation
    if (
      ch === 40 || ch === 41 || ch === 91 || ch === 93 ||
      ch === 123 || ch === 125 || ch === 44 || ch === 59 || ch === 58
    ) {
      const val = src[i];
      const start = i++;
      if (val === '(') {
        const isCtrl =
          prevToken &&
          prevToken.type === 'kw' &&
          (prevToken.value === 'if' ||
            prevToken.value === 'while' ||
            prevToken.value === 'for' ||
            prevToken.value === 'with' ||
            prevToken.value === 'switch');
        parenStack.push(Boolean(isCtrl));
      } else if (val === ')') {
        const isCtrlHeaderClose = parenStack.length > 0 ? parenStack.pop() : false;
        const tok = { type: 'punct', value: val, start, end: i, isCtrlHeaderClose };
        tokens.push(tok);
        prevPrevToken = prevToken;
        prevToken = tok;
        continue;
      } else if (val === '{') {
        braceDepth++;
      } else if (val === '}') {
        if (tplStack.length > 0 && tplStack[tplStack.length - 1] === braceDepth) {
          tplStack.pop();
          braceDepth--;
          const tok = { type: 'punct', value: '}', start, end: start + 1 };
          tokens.push(tok);
          prevPrevToken = prevToken;
          prevToken = tok;
          i = scanTemplateSegment(i, false);
          continue;
        }
        braceDepth = Math.max(0, braceDepth - 1);
      }
      const tok = { type: 'punct', value: val, start, end: i };
      tokens.push(tok);
      prevPrevToken = prevToken;
      prevToken = tok;
      continue;
    }

    // Multi-char & single-char operators
    const start = i;
    const c1 = i + 1 < len ? src.charCodeAt(i + 1) : 0;
    const c2 = i + 2 < len ? src.charCodeAt(i + 2) : 0;
    let opLen = 1;
    if (ch === 63 /* ? */) {
      if (c1 === 63 /* ? */) {
        opLen = c2 === 61 ? 3 : 2; // ??= or ??
      } else if (c1 === 46 /* . */ && !isDigit(c2)) {
        opLen = 2; // ?.
      }
    } else if (ch === 38 /* & */) {
      if (c1 === 38) opLen = c2 === 61 ? 3 : 2; // &&= or &&
      else if (c1 === 61) opLen = 2;
    } else if (ch === 124 /* | */) {
      if (c1 === 124) opLen = c2 === 61 ? 3 : 2; // ||= or ||
      else if (c1 === 61) opLen = 2;
    } else if (ch === 46 /* . */ && c1 === 46 && c2 === 46) {
      opLen = 3; // ...
    } else if (ch === 61 /* = */) {
      if (c1 === 62) opLen = 2; // =>
      else if (c1 === 61) opLen = c2 === 61 ? 3 : 2; // === or ==
    } else if (ch === 33 /* ! */) {
      if (c1 === 61) opLen = c2 === 61 ? 3 : 2; // !== or !=
    } else if (ch === 43 /* + */ || ch === 45 /* - */) {
      if (c1 === ch || c1 === 61) opLen = 2; // ++, --, +=, -=
    } else if (ch === 42 /* * */) {
      if (c1 === 42) opLen = c2 === 61 ? 3 : 2; // **= or **
      else if (c1 === 61) opLen = 2;
    } else if (ch === 60 /* < */) {
      if (c1 === 60) opLen = c2 === 61 ? 3 : 2; // <<= or <<
      else if (c1 === 61) opLen = 2;
    } else if (ch === 62 /* > */) {
      if (c1 === 62) {
        if (c2 === 62) opLen = i + 3 < len && src.charCodeAt(i + 3) === 61 ? 4 : 3; // >>>= or >>>
        else opLen = c2 === 61 ? 3 : 2; // >>= or >>
      } else if (c1 === 61) opLen = 2;
    } else if ((ch === 47 || ch === 37 || ch === 94) && c1 === 61) {
      opLen = 2; // /=, %=, ^=
    }

    i += opLen;
    const tok = { type: 'op', value: src.slice(start, i), start, end: i };
    tokens.push(tok);
    prevPrevToken = prevToken;
    prevToken = tok;
  }

  return tokens;
}

function matchBalanced(tokens, openIdx, openVal, closeVal) {
  let depth = 0;
  for (let i = openIdx; i < tokens.length; i++) {
    const v = tokens[i].value;
    if (v === openVal) depth++;
    else if (v === closeVal) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function findStatementEnd(tokens, startIdx) {
  if (startIdx >= tokens.length) return tokens.length - 1;
  const tok = tokens[startIdx];
  if (tok.value === '{') {
    const close = matchBalanced(tokens, startIdx, '{', '}');
    return close < 0 ? tokens.length - 1 : close;
  }
  if (tok.type === 'kw' && tok.value === 'if') {
    if (tokens[startIdx + 1]?.value !== '(') return startIdx;
    const closeParen = matchBalanced(tokens, startIdx + 1, '(', ')');
    if (closeParen < 0) return tokens.length - 1;
    const thenEnd = findStatementEnd(tokens, closeParen + 1);
    if (tokens[thenEnd + 1]?.type === 'kw' && tokens[thenEnd + 1]?.value === 'else') {
      return findStatementEnd(tokens, thenEnd + 2);
    }
    return thenEnd;
  }
  if (tok.type === 'kw' && (tok.value === 'for' || tok.value === 'while' || tok.value === 'with')) {
    if (tokens[startIdx + 1]?.value !== '(') return startIdx;
    const closeParen = matchBalanced(tokens, startIdx + 1, '(', ')');
    if (closeParen < 0) return tokens.length - 1;
    return findStatementEnd(tokens, closeParen + 1);
  }
  if (tok.type === 'kw' && tok.value === 'switch') {
    if (tokens[startIdx + 1]?.value !== '(') return startIdx;
    const closeParen = matchBalanced(tokens, startIdx + 1, '(', ')');
    if (closeParen < 0 || tokens[closeParen + 1]?.value !== '{') return tokens.length - 1;
    const closeBrace = matchBalanced(tokens, closeParen + 1, '{', '}');
    return closeBrace < 0 ? tokens.length - 1 : closeBrace;
  }
  if (tok.type === 'kw' && tok.value === 'try') {
    if (tokens[startIdx + 1]?.value !== '{') return startIdx;
    let end = matchBalanced(tokens, startIdx + 1, '{', '}');
    if (end < 0) return tokens.length - 1;
    if (tokens[end + 1]?.type === 'kw' && tokens[end + 1]?.value === 'catch') {
      let cIdx = end + 2;
      if (tokens[cIdx]?.value === '(') {
        cIdx = matchBalanced(tokens, cIdx, '(', ')') + 1;
      }
      if (tokens[cIdx]?.value === '{') {
        end = matchBalanced(tokens, cIdx, '{', '}');
        if (end < 0) return tokens.length - 1;
      }
    }
    if (tokens[end + 1]?.type === 'kw' && tokens[end + 1]?.value === 'finally') {
      if (tokens[end + 2]?.value === '{') {
        end = matchBalanced(tokens, end + 2, '{', '}');
        if (end < 0) return tokens.length - 1;
      }
    }
    return end;
  }
  let p = 0;
  let b = 0;
  let c = 0;
  for (let i = startIdx; i < tokens.length; i++) {
    const v = tokens[i].value;
    if (v === '(') p++;
    else if (v === ')') {
      if (p === 0) return Math.max(startIdx, i - 1);
      p--;
    } else if (v === '[') b++;
    else if (v === ']') {
      if (b === 0) return Math.max(startIdx, i - 1);
      b--;
    } else if (v === '{' || tokens[i].type === 'tpl_head' || tokens[i].type === 'tpl_mid') {
      c++;
    } else if (v === '}') {
      if (c === 0) return Math.max(startIdx, i - 1);
      c--;
    } else if (p === 0 && b === 0 && c === 0) {
      if (v === ';') return i;
      if (tokens[i].type === 'kw' && tokens[i].value === 'else' && i > startIdx) {
        return i - 1;
      }
    }
  }
  return tokens.length - 1;
}

const LHS_STOP_OPS = new Set([
  '?', ':', '=', '+=', '-=', '*=', '/=', '%=', '**=', '<<=', '>>=', '>>>=',
  '&=', '|=', '^=', '&&=', '||=', '??=', '=>', '...',
]);
const LHS_STOP_KWS = new Set([
  'return', 'throw', 'case', 'else', 'yield', 'in', 'of', 'instanceof',
  'let', 'const', 'var', 'export', 'default', 'do',
]);

function findShortCircuitLhsStart(tokens, opIdx) {
  const opVal = tokens[opIdx].value;
  let p = 0;
  let b = 0;
  let c = 0;
  let lastIdx = opIdx - 1;
  for (let i = opIdx - 1; i >= 0; i--) {
    const t = tokens[i];
    const v = t.value;
    if (v === ')') p++;
    else if (v === '(') {
      if (p === 0) break;
      p--;
    } else if (v === ']') b++;
    else if (v === '[') {
      if (b === 0) break;
      b--;
    } else if (v === '}') {
      c++;
    } else if (v === '{' || t.type === 'tpl_head' || t.type === 'tpl_mid') {
      if (c === 0) break;
      c--;
    } else if (p === 0 && b === 0 && c === 0) {
      if (v === ',' || v === ';') break;
      if (t.type === 'op') {
        if (LHS_STOP_OPS.has(v)) break;
        if (v === '||' || v === '??') break;
        if (opVal === '&&' && v === '&&') break;
      } else if (t.type === 'kw' && LHS_STOP_KWS.has(v)) {
        break;
      }
    }
    lastIdx = i;
  }
  return tokens[Math.max(0, lastIdx)].start;
}

function findOptionalChainBaseOffset(tokens, opIdx) {
  let p = 0;
  let b = 0;
  let c = 0;
  for (let i = opIdx - 1; i >= 0; i--) {
    const t = tokens[i];
    const v = t.value;
    if (v === ')') p++;
    else if (v === '(') {
      if (p === 0) break;
      p--;
    } else if (v === ']') b++;
    else if (v === '[') {
      if (b === 0) break;
      b--;
    } else if (v === '}') {
      c++;
    } else if (v === '{' || t.type === 'tpl_head' || t.type === 'tpl_mid') {
      if (c === 0) break;
      c--;
    } else if (p === 0 && b === 0 && c === 0) {
      if (t.type === 'op' && v === '?.') {
        return t.start;
      }
      if (
        v !== '.' &&
        t.type !== 'id' &&
        t.type !== 'num' &&
        t.type !== 'str' &&
        t.type !== 'regex' &&
        t.type !== 'tpl_full' &&
        t.type !== 'tpl_tail' &&
        !(t.type === 'kw' && (v === 'this' || v === 'super' || v === 'null' || v === 'true' || v === 'false'))
      ) {
        break;
      }
    }
  }
  return tokens[Math.max(0, opIdx - 1)].start;
}

export function extractBranchArms(tokens) {
  const arms = [];
  const switchBraceDepths = [];
  let braceDepth = 0;

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok.value === '{' || tok.type === 'tpl_head' || tok.type === 'tpl_mid') {
      braceDepth++;
      continue;
    }
    if (tok.value === '}') {
      if (switchBraceDepths.length > 0 && switchBraceDepths[switchBraceDepths.length - 1] === braceDepth) {
        switchBraceDepths.pop();
      }
      braceDepth = Math.max(0, braceDepth - 1);
      continue;
    }

    // 1. if (...) thenStmt [else elseStmt]
    if (tok.type === 'kw' && tok.value === 'if' && tokens[i + 1]?.value === '(') {
      const closeParen = matchBalanced(tokens, i + 1, '(', ')');
      if (closeParen >= 0 && closeParen + 1 < tokens.length) {
        const thenTok = tokens[closeParen + 1];
        const thenEndIdx = findStatementEnd(tokens, closeParen + 1);
        const maybeElse = tokens[thenEndIdx + 1];
        const hasElse = Boolean(maybeElse && maybeElse.type === 'kw' && maybeElse.value === 'else' && thenEndIdx + 2 < tokens.length);
        arms.push({
          kind: 'if-then',
          locOffset: thenTok.start,
          evalFn: (countAt) => countAt(thenTok.start) > 0,
        });
        if (hasElse) {
          const elseBodyTok = tokens[thenEndIdx + 2];
          arms.push({
            kind: 'if-else',
            locOffset: elseBodyTok.start,
            evalFn: (countAt) => countAt(elseBodyTok.start) > 0,
          });
        } else {
          const ifOffset = tok.start;
          const thenOffset = thenTok.start;
          arms.push({
            kind: 'if-implicit-else',
            locOffset: ifOffset,
            evalFn: (countAt) => countAt(ifOffset) > countAt(thenOffset),
          });
        }
      }
      continue;
    }

    // 2. cond ? trueExpr : falseExpr
    if (tok.type === 'op' && tok.value === '?' && i + 1 < tokens.length) {
      let p = 0;
      let b = 0;
      let c = 0;
      let nestedTernary = 0;
      let colonIdx = -1;
      for (let j = i + 1; j < tokens.length; j++) {
        const t = tokens[j];
        const v = t.value;
        if (v === '(') p++;
        else if (v === ')') {
          if (p === 0) break;
          p--;
        } else if (v === '[') b++;
        else if (v === ']') {
          if (b === 0) break;
          b--;
        } else if (v === '{' || t.type === 'tpl_head' || t.type === 'tpl_mid') {
          c++;
        } else if (v === '}') {
          if (c === 0) break;
          c--;
        } else if (p === 0 && b === 0 && c === 0) {
          if (v === '?') nestedTernary++;
          else if (v === ':') {
            if (nestedTernary === 0) {
              colonIdx = j;
              break;
            }
            nestedTernary--;
          } else if (v === ';') {
            break;
          }
        }
      }
      if (colonIdx > i + 1 && colonIdx + 1 < tokens.length) {
        const trueTok = tokens[i + 1];
        const falseTok = tokens[colonIdx + 1];
        arms.push({
          kind: 'ternary-true',
          locOffset: trueTok.start,
          evalFn: (countAt) => countAt(trueTok.start) > 0,
        });
        arms.push({
          kind: 'ternary-false',
          locOffset: falseTok.start,
          evalFn: (countAt) => countAt(falseTok.start) > 0,
        });
      }
      continue;
    }

    // 3. lhs && rhs, lhs || rhs, lhs ?? rhs
    if (tok.type === 'op' && (tok.value === '&&' || tok.value === '||' || tok.value === '??') && i + 1 < tokens.length) {
      const lhsStart = findShortCircuitLhsStart(tokens, i);
      const rhsStart = tokens[i + 1].start;
      const opOffset = tok.start;
      arms.push({
        kind: `${tok.value}-rhs`,
        locOffset: rhsStart,
        evalFn: (countAt) => countAt(rhsStart) > 0,
      });
      arms.push({
        kind: `${tok.value}-short-circuit`,
        locOffset: opOffset,
        evalFn: (countAt) => countAt(lhsStart) > countAt(rhsStart),
      });
      continue;
    }

    // 3b. lhs?.prop, lhs?.[expr], lhs?.(...)
    if (tok.type === 'op' && tok.value === '?.' && i > 0 && i + 1 < tokens.length) {
      const baseOffset = findOptionalChainBaseOffset(tokens, i);
      const opOffset = tok.start;
      arms.push({
        kind: 'optchain-eval',
        locOffset: opOffset,
        evalFn: (countAt) => countAt(opOffset) > 0,
      });
      arms.push({
        kind: 'optchain-short-circuit',
        locOffset: opOffset,
        evalFn: (countAt) => countAt(baseOffset) > countAt(opOffset),
      });
      continue;
    }

    // 4. switch (...) { case ...: default: }
    if (tok.type === 'kw' && tok.value === 'switch' && tokens[i + 1]?.value === '(') {
      const closeParen = matchBalanced(tokens, i + 1, '(', ')');
      if (closeParen >= 0 && tokens[closeParen + 1]?.value === '{') {
        switchBraceDepths.push(braceDepth + 1);
      }
      continue;
    }
    if (
      (tok.type === 'kw' && (tok.value === 'case' || tok.value === 'default')) &&
      switchBraceDepths.length > 0 &&
      switchBraceDepths[switchBraceDepths.length - 1] === braceDepth
    ) {
      let colonIdx = -1;
      if (tok.value === 'default') {
        if (tokens[i + 1]?.value === ':') colonIdx = i + 1;
      } else {
        let p = 0;
        let b = 0;
        let c = 0;
        let nestedTernary = 0;
        for (let j = i + 1; j < tokens.length; j++) {
          const t = tokens[j];
          const v = t.value;
          if (v === '(') p++;
          else if (v === ')') p = Math.max(0, p - 1);
          else if (v === '[') b++;
          else if (v === ']') b = Math.max(0, b - 1);
          else if (v === '{' || t.type === 'tpl_head' || t.type === 'tpl_mid') c++;
          else if (v === '}') {
            if (c === 0) break;
            c--;
          } else if (p === 0 && b === 0 && c === 0) {
            if (v === '?') nestedTernary++;
            else if (v === ':') {
              if (nestedTernary === 0) {
                colonIdx = j;
                break;
              }
              nestedTernary--;
            } else if (v === ';') {
              break;
            }
          }
        }
      }
      const nextAfterColon = colonIdx >= 0 ? tokens[colonIdx + 1] : null;
      if (nextAfterColon && nextAfterColon.type === 'kw' && (nextAfterColon.value === 'case' || nextAfterColon.value === 'default')) {
        continue;
      }
      const caseOffset = tok.start;
      arms.push({
        kind: tok.value === 'default' ? 'switch-default' : 'switch-case',
        locOffset: caseOffset,
        evalFn: (countAt) => countAt(caseOffset) > 0,
      });
      continue;
    }

    // 5. try { ... } catch [(e)] { ... }
    if (tok.type === 'kw' && tok.value === 'catch') {
      const catchOffset = tok.start;
      arms.push({
        kind: 'catch',
        locOffset: catchOffset,
        evalFn: (countAt) => countAt(catchOffset) > 0,
      });
    }
  }

  return arms;
}

// --- Coverage Aggregation & Reporting ---

function listTsFilesRecursive(dirPath, out = []) {
  if (!existsSync(dirPath)) return out;
  for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
    const full = resolve(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'test') continue;
      listTsFilesRecursive(full, out);
    } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      out.push(canonicalizePath(full));
    }
  }
  return out;
}

function formatLineRanges(lineNumbers) {
  if (lineNumbers.length === 0) return '';
  const sorted = Array.from(lineNumbers).sort((a, b) => a - b);
  const ranges = [];
  let start = sorted[0];
  let prev = sorted[0];
  for (let i = 1; i < sorted.length; i++) {
    const cur = sorted[i];
    if (cur === prev + 1) {
      prev = cur;
    } else {
      ranges.push(start === prev ? `${start}` : `${start}-${prev}`);
      start = cur;
      prev = cur;
    }
  }
  ranges.push(start === prev ? `${start}` : `${start}-${prev}`);
  if (ranges.length <= 8) return ranges.join(',');
  return `${ranges.slice(0, 8).join(',')},...(+${ranges.length - 8})`;
}

export function collectAndPrintCoverage({
  hubRoot,
  bundles,
  covDir,
  jsonOutPath = null,
  includeSdk = false,
}) {
  const canonHubRoot = canonicalizePath(hubRoot);
  const repoRoot = canonicalizePath(resolve(hubRoot, '..'));
  const srcRoot = `${canonHubRoot}/src/`;
  const sdkRoot = `${repoRoot}/sdk/ts/`;

  const isTargetSourceFile = (canonFile) => {
    if (!canonFile.endsWith('.ts') || canonFile.endsWith('.d.ts')) return false;
    if (canonFile.includes('/node_modules/') || canonFile.startsWith(`${canonHubRoot}/test/`)) return false;
    if (canonFile.startsWith(srcRoot)) return true;
    if (includeSdk && canonFile.startsWith(sdkRoot)) return true;
    return false;
  };

  // Load V8 ScriptCoverage files
  const v8ByBundle = new Map(); // canonBundlePath -> intervalSets[]
  if (existsSync(covDir)) {
    for (const fname of readdirSync(covDir)) {
      if (!fname.endsWith('.json')) continue;
      const raw = JSON.parse(readFileSync(resolve(covDir, fname), 'utf8'));
      for (const scriptCov of raw.result ?? []) {
        if (!scriptCov.url || !scriptCov.url.startsWith('file://')) continue;
        let canonScript;
        try {
          canonScript = canonicalizePath(fileURLToPath(scriptCov.url));
        } catch {
          continue;
        }
        const intervals = flattenScriptCoverageRanges(scriptCov);
        if (!v8ByBundle.has(canonScript)) v8ByBundle.set(canonScript, []);
        v8ByBundle.get(canonScript).push(intervals);
      }
    }
  }

  // fileStats: canonFile -> { execLines: Set<number>, hitLines: Set<number>, branches: Map<string, { line, kind, hit }> }
  const fileStats = new Map();
  const ensureFileStat = (canonFile) => {
    let s = fileStats.get(canonFile);
    if (!s) {
      s = { execLines: new Set(), hitLines: new Set(), branches: new Map() };
      fileStats.set(canonFile, s);
    }
    return s;
  };

  const getStaticImportGenLines = (tokens, lineStarts) => {
    const importGenLines = new Set();
    let braceDepth = 0;
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.value === '{' || t.type === 'tpl_head' || t.type === 'tpl_mid') {
        braceDepth++;
        continue;
      }
      if (t.value === '}') {
        braceDepth = Math.max(0, braceDepth - 1);
        continue;
      }
      if (braceDepth === 0 && t.type === 'kw' && t.value === 'import') {
        const prev = i > 0 ? tokens[i - 1] : undefined;
        const isStmtStart = !prev || prev.value === ';' || prev.value === '}';
        const nxt = tokens[i + 1];
        const isStaticImportNext =
          Boolean(nxt) &&
          (nxt.type === 'str' || nxt.type === 'id' || nxt.value === '{' || nxt.value === '*');
        if (!isStmtStart || !isStaticImportNext) continue;
        const startLine = offsetToLineCol(lineStarts, t.start).line;
        let j = i + 1;
        while (j < tokens.length && tokens[j].value !== ';') {
          const jt = tokens[j];
          if (jt.value === '{' || jt.type === 'tpl_head' || jt.type === 'tpl_mid') {
            braceDepth++;
          } else if (jt.value === '}') {
            braceDepth = Math.max(0, braceDepth - 1);
          }
          j++;
        }
        const endTok = tokens[Math.min(j, tokens.length - 1)];
        const endLine = offsetToLineCol(lineStarts, Math.max(t.start, endTok.end - 1)).line;
        for (let gl = startLine; gl <= endLine; gl++) {
          importGenLines.add(gl);
        }
        i = j;
      }
    }
    return importGenLines;
  };

  const processCompiledBundle = (bundlePath, jsText, intervalSets, isUnbundled = false) => {
    const sm = parseSourceMap(jsText, dirname(bundlePath));
    const countAt = createCounter(intervalSets);
    const tokens = tokenizeEs2022(jsText);
    const importGenLines = isUnbundled ? getStaticImportGenLines(tokens, sm.lineStarts) : null;

    // 1. Line coverage
    for (let gl = 0; gl < sm.lines.length; gl++) {
      if (importGenLines && importGenLines.has(gl)) continue;
      const segs = sm.lines[gl];
      if (!segs || segs.length === 0) continue;
      const lineStart = sm.lineStarts[gl];
      const nextLineStart = gl + 1 < sm.lineStarts.length ? sm.lineStarts[gl + 1] : sm.textLength;
      const lineEnd = nextLineStart > lineStart && jsText.charCodeAt(nextLineStart - 1) === 10
        ? nextLineStart - 1
        : nextLineStart;

      for (let s = 0; s < segs.length; s++) {
        const seg = segs[s];
        if (seg.srcIdx < 0 || seg.srcIdx >= sm.sources.length) continue;
        const origFile = sm.sources[seg.srcIdx];
        if (!isTargetSourceFile(origFile)) continue;

        const segStart = lineStart + seg.genCol;
        const segEnd = s + 1 < segs.length ? Math.min(lineEnd, lineStart + segs[s + 1].genCol) : lineEnd;
        if (segEnd <= segStart) continue;
        if (jsText.slice(segStart, segEnd).trim().length === 0) continue;

        const origLine1 = seg.origLine + 1;
        const stat = ensureFileStat(origFile);
        stat.execLines.add(origLine1);
        if (!stat.hitLines.has(origLine1)) {
          for (const ivs of intervalSets) {
            if (anyIntervalHitInRange(ivs, segStart, segEnd)) {
              stat.hitLines.add(origLine1);
              break;
            }
          }
        }
      }
    }

    // 2. Branch coverage
    const arms = extractBranchArms(tokens);
    for (const arm of arms) {
      const loc = sm.lookup(arm.locOffset);
      if (!loc || !isTargetSourceFile(loc.file)) continue;
      const key = `${loc.line}:${loc.col}:${arm.kind}`;
      const stat = ensureFileStat(loc.file);
      const hit = intervalSets.length > 0 ? arm.evalFn(countAt) : false;
      const existing = stat.branches.get(key);
      if (existing) {
        if (hit) existing.hit = true;
      } else {
        stat.branches.set(key, { line: loc.line, kind: arm.kind, hit });
      }
    }
  };

  for (const bundlePath of bundles) {
    const canonBundle = canonicalizePath(bundlePath);
    const jsText = readFileSync(canonBundle, 'utf8');
    const intervalSets = v8ByBundle.get(canonBundle) ?? [];
    processCompiledBundle(canonBundle, jsText, intervalSets, false);
  }

  // 3. Scan disk for ALL non-type Hub .ts files to seed complete execLines & branches universe
  const diskFiles = [
    ...listTsFilesRecursive(resolve(canonHubRoot, 'src')),
  ];
  if (includeSdk) {
    diskFiles.push(...listTsFilesRecursive(resolve(repoRoot, 'sdk', 'ts')));
  }
  for (const diskFile of diskFiles) {
    const res = buildSync({
      entryPoints: [diskFile],
      absWorkingDir: canonHubRoot,
      bundle: false,
      format: 'esm',
      target: 'ES2022',
      loader: { '.ts': 'ts', '.sql': 'text', '.yaml': 'text', '.yml': 'text' },
      sourcemap: 'inline',
      write: false,
    });
    const jsText = res.outputFiles?.[0]?.text ?? '';
    if (!jsText.trim()) continue;
    processCompiledBundle(resolve(canonHubRoot, '__unimported__.mjs'), jsText, [], true);
  }

  // 4. Compute table & summary
  const rows = [];
  let totalLinesHit = 0;
  let totalLinesExec = 0;
  let totalBranchesHit = 0;
  let totalBranchesExec = 0;

  for (const [canonFile, stat] of fileStats.entries()) {
    if (stat.execLines.size === 0) continue; // skip pure type-definition files
    const linesExec = stat.execLines.size;
    const linesHit = stat.hitLines.size;
    const linePct = linesExec > 0 ? (linesHit / linesExec) * 100 : 100;

    let branchesExec = 0;
    let branchesHit = 0;
    const uncoveredBranchLines = new Set();
    for (const b of stat.branches.values()) {
      branchesExec++;
      if (b.hit) {
        branchesHit++;
      } else {
        uncoveredBranchLines.add(b.line);
      }
    }
    const branchPct = branchesExec > 0 ? (branchesHit / branchesExec) * 100 : 100;

    const uncoveredLines = [];
    for (const ln of stat.execLines) {
      if (!stat.hitLines.has(ln)) uncoveredLines.push(ln);
    }

    totalLinesHit += linesHit;
    totalLinesExec += linesExec;
    totalBranchesHit += branchesHit;
    totalBranchesExec += branchesExec;

    const relPath = relative(canonHubRoot, canonFile).replace(/\\/g, '/');
    rows.push({
      file: relPath,
      linesHit,
      linesExec,
      linePct,
      branchesHit,
      branchesExec,
      branchPct,
      uncoveredLines: uncoveredLines.sort((a, b) => a - b),
      uncoveredBranchLines: Array.from(uncoveredBranchLines).sort((a, b) => a - b),
    });
  }

  rows.sort((a, b) => a.file.localeCompare(b.file));

  const totalLinePct = totalLinesExec > 0 ? (totalLinesHit / totalLinesExec) * 100 : 100;
  const totalBranchPct = totalBranchesExec > 0 ? (totalBranchesHit / totalBranchesExec) * 100 : 100;

  // Print table
  const colFileW = Math.max(28, ...rows.map((r) => r.file.length), 'All Hub files'.length);
  const padL = (s, w) => String(s).padStart(w, ' ');
  const padR = (s, w) => String(s).padEnd(w, ' ');

  const header = `${padR('File', colFileW)} | ${padL('Lines', 11)} | ${padL('Line %', 7)} | ${padL('Branches', 11)} | ${padL('Branch %', 8)} | Uncovered`;
  const sep = `${'-'.repeat(colFileW)}-+-${'-'.repeat(11)}-+-${'-'.repeat(7)}-+-${'-'.repeat(11)}-+-${'-'.repeat(8)}-+----------`;

  console.log('\n=== Hub V8 + Sourcemap Coverage Report ===');
  console.log(header);
  console.log(sep);
  for (const r of rows) {
    const lStr = `${r.linesHit}/${r.linesExec}`;
    const lpStr = `${r.linePct.toFixed(2)}%`;
    const bStr = `${r.branchesHit}/${r.branchesExec}`;
    const bpStr = `${r.branchPct.toFixed(2)}%`;
    const uncovParts = [];
    if (r.uncoveredLines.length > 0) uncovParts.push(`L:${formatLineRanges(r.uncoveredLines)}`);
    if (r.uncoveredBranchLines.length > 0) uncovParts.push(`B:${formatLineRanges(r.uncoveredBranchLines)}`);
    const uncovStr = uncovParts.length > 0 ? uncovParts.join(' ; ') : '-';
    console.log(
      `${padR(r.file, colFileW)} | ${padL(lStr, 11)} | ${padL(lpStr, 7)} | ${padL(bStr, 11)} | ${padL(bpStr, 8)} | ${uncovStr}`,
    );
  }
  console.log(sep);
  console.log(
    `${padR('All Hub files', colFileW)} | ${padL(`${totalLinesHit}/${totalLinesExec}`, 11)} | ${padL(`${totalLinePct.toFixed(2)}%`, 7)} | ${padL(`${totalBranchesHit}/${totalBranchesExec}`, 11)} | ${padL(`${totalBranchPct.toFixed(2)}%`, 8)} | -`,
  );
  console.log('');

  const summary = {
    generatedAt: new Date().toISOString(),
    total: {
      linesCovered: totalLinesHit,
      linesTotal: totalLinesExec,
      linePct: Number(totalLinePct.toFixed(2)),
      branchesCovered: totalBranchesHit,
      branchesTotal: totalBranchesExec,
      branchPct: Number(totalBranchPct.toFixed(2)),
    },
    files: rows.map((r) => ({
      file: r.file,
      linesCovered: r.linesHit,
      linesTotal: r.linesExec,
      linePct: Number(r.linePct.toFixed(2)),
      branchesCovered: r.branchesHit,
      branchesTotal: r.branchesExec,
      branchPct: Number(r.branchPct.toFixed(2)),
      uncoveredLines: r.uncoveredLines,
      uncoveredBranchLines: r.uncoveredBranchLines,
    })),
  };

  if (jsonOutPath) {
    const absJson = resolve(hubRoot, jsonOutPath);
    mkdirSync(dirname(absJson), { recursive: true });
    writeFileSync(absJson, JSON.stringify(summary, null, 2) + '\n', 'utf8');
    console.log(`Wrote coverage JSON report to ${absJson}`);
  }

  return summary;
}
