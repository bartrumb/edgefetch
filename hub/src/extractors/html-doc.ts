/**
 * Linear-time HTML5 DOM parser & bounded CSS selector helper (`parseHtmlDoc`) powered by `htmlparser2`,
 * `domhandler`, `domutils`, and `dom-serializer` — giving Site Adapters ergonomic Cheerio / BeautifulSoup
 * extraction (`select`, `first`, `text`, `html`, `outerHtml`, `attr`, `attrOf`, `dlMap`, `tableRows`)
 * with zero backtracking regexes and guaranteed O(N) execution.
 */

import render from 'dom-serializer';
import { type ChildNode, Document, Element, Text, isTag, isText } from 'domhandler';
import { textContent } from 'domutils';
import { Parser } from 'htmlparser2';

const DEFAULT_MAX_HTML_DOC_CHARS = 2_097_152; // 2 MiB default input cap
const MAX_HARD_HTML_DOC_CHARS = 4_194_304; // 4 MiB hard ceiling even when caller passes higher maxChars
const MAX_DOM_DEPTH = 128;
const MAX_DOM_NODES = 40_000;
const MAX_DLMAP_VISITS = 4_000;
const MAX_SELECTOR_CHARS = 256;
const MAX_SELECTOR_GROUPS = 16;
const MAX_COMBINATOR_STEPS = 8;
const MAX_SELECT_LIMIT = 5_000;

const STRIPPED_TEXT_TAGS: ReadonlySet<string> = new Set([
  'script',
  'style',
  'noscript',
  'template',
  'svg',
  'xmp',
  'plaintext',
  'textarea',
]);

const BLOCK_BOUNDARY_TAGS: ReadonlySet<string> = new Set([
  'address',
  'article',
  'aside',
  'blockquote',
  'br',
  'caption',
  'dd',
  'details',
  'div',
  'dl',
  'dt',
  'fieldset',
  'figcaption',
  'figure',
  'footer',
  'form',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'header',
  'hr',
  'li',
  'main',
  'nav',
  'ol',
  'p',
  'pre',
  'section',
  'summary',
  'table',
  'tbody',
  'td',
  'tfoot',
  'th',
  'thead',
  'tr',
  'ul',
]);

type AttrOp = 'exists' | '=' | '*=' | '^=' | '$=' | '~=' | '|=';

interface AttrMatcher {
  name: string;
  op: AttrOp;
  value: string;
  ignoreCase: boolean;
}

interface CompoundStep {
  tag: string | null; // lowercase tag name, or `null` for `*` / omitted
  ids: string[];
  classes: string[];
  attrs: AttrMatcher[];
}

type Combinator = ' ' | '>' | '+';

interface SelectorStep {
  combinatorFromPrev: Combinator | null; // `'>'` on step 0 means direct child of query scope
  compound: CompoundStep;
}

function isSimpleAsciiIdentChar(ch: number): boolean {
  return (
    (ch >= 97 && ch <= 122) || // a-z
    (ch >= 65 && ch <= 90) || // A-Z
    (ch >= 48 && ch <= 57) || // 0-9
    ch === 45 || // -
    ch === 95 || // _
    ch === 58 // : (for xml/namespaced attrs if escaped/ident)
  );
}

function isSimpleIdentCharNoColon(ch: number): boolean {
  return (
    (ch >= 97 && ch <= 122) ||
    (ch >= 65 && ch <= 90) ||
    (ch >= 48 && ch <= 57) ||
    ch === 45 ||
    ch === 95
  );
}

function splitSelectorGroups(raw: string): string[] | null {
  const groups: string[] = [];
  let bracketDepth = 0;
  let quoteChar = 0; // 0, 34 ("), 39 (')
  let start = 0;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charCodeAt(i);
    if (ch === 92 /* '\\' */) {
      i++;
      continue;
    }
    if (quoteChar !== 0) {
      if (ch === quoteChar) quoteChar = 0;
      continue;
    }
    if (ch === 34 || ch === 39) {
      quoteChar = ch;
      continue;
    }
    if (ch === 91 /* '[' */) {
      bracketDepth++;
      continue;
    }
    if (ch === 93 /* ']' */) {
      if (bracketDepth === 0) return null;
      bracketDepth--;
      continue;
    }
    if (ch === 44 /* ',' */ && bracketDepth === 0) {
      const part = raw.slice(start, i).trim();
      if (!part) return null;
      groups.push(part);
      if (groups.length > MAX_SELECTOR_GROUPS) return null;
      start = i + 1;
    }
  }

  if (quoteChar !== 0 || bracketDepth !== 0) return null;
  const tail = raw.slice(start).trim();
  if (!tail) return null;
  groups.push(tail);
  if (groups.length > MAX_SELECTOR_GROUPS) return null;
  return groups;
}

function parseAttrSelector(src: string, openBracketIdx: number): { matcher: AttrMatcher; nextIdx: number } | null {
  const len = src.length;
  let p = openBracketIdx + 1;
  while (p < len && src.charCodeAt(p) <= 32) p++;

  const nameStart = p;
  while (p < len && (isSimpleAsciiIdentChar(src.charCodeAt(p)) || src.charCodeAt(p) === 46 /* '.' */)) {
    p++;
  }
  if (p === nameStart) return null;
  const attrName = src.slice(nameStart, p).toLowerCase();

  while (p < len && src.charCodeAt(p) <= 32) p++;
  if (p >= len) return null;

  if (src.charCodeAt(p) === 93 /* ']' */) {
    return {
      matcher: { name: attrName, op: 'exists', value: '', ignoreCase: false },
      nextIdx: p + 1,
    };
  }

  let op: AttrOp | null = null;
  const c0 = src[p];
  const c1 = src[p + 1];
  if (c0 === '=') {
    op = '=';
    p += 1;
  } else if (c1 === '=' && (c0 === '*' || c0 === '^' || c0 === '$' || c0 === '~' || c0 === '|')) {
    op = `${c0}=` as AttrOp;
    p += 2;
  }
  if (!op) return null;

  while (p < len && src.charCodeAt(p) <= 32) p++;
  if (p >= len) return null;

  let value = '';
  const q = src.charCodeAt(p);
  if (q === 34 /* '"' */ || q === 39 /* "'" */) {
    p++;
    const chunks: string[] = [];
    let closed = false;
    while (p < len) {
      const ch = src.charCodeAt(p);
      if (ch === 92 /* '\\' */ && p + 1 < len) {
        chunks.push(src[p + 1]!);
        p += 2;
        continue;
      }
      if (ch === q) {
        closed = true;
        p++;
        break;
      }
      chunks.push(src[p]!);
      p++;
    }
    if (!closed) return null;
    value = chunks.join('');
  } else {
    const valStart = p;
    while (p < len && src.charCodeAt(p) > 32 && src.charCodeAt(p) !== 93 /* ']' */) {
      p++;
    }
    value = src.slice(valStart, p);
  }

  while (p < len && src.charCodeAt(p) <= 32) p++;
  let ignoreCase = false;
  if (p < len && (src[p] === 'i' || src[p] === 'I')) {
    const afterFlag = p + 1;
    if (afterFlag < len && (src.charCodeAt(afterFlag) <= 32 || src.charCodeAt(afterFlag) === 93)) {
      ignoreCase = true;
      p = afterFlag;
      while (p < len && src.charCodeAt(p) <= 32) p++;
    }
  }

  if (p >= len || src.charCodeAt(p) !== 93 /* ']' */) return null;
  return {
    matcher: {
      name: attrName,
      op,
      value: ignoreCase ? value.toLowerCase() : value,
      ignoreCase,
    },
    nextIdx: p + 1,
  };
}

function readSimpleIdent(src: string, startIdx: number): { ident: string; nextIdx: number } | null {
  const len = src.length;
  let p = startIdx;
  const out: string[] = [];
  while (p < len) {
    const ch = src.charCodeAt(p);
    if (ch === 92 /* '\\' */ && p + 1 < len) {
      out.push(src[p + 1]!);
      p += 2;
      continue;
    }
    if (isSimpleIdentCharNoColon(ch)) {
      out.push(src[p]!);
      p++;
      continue;
    }
    break;
  }
  if (out.length === 0) return null;
  return { ident: out.join(''), nextIdx: p };
}

function parseSingleSelectorChain(groupSrc: string): SelectorStep[] | null {
  const steps: SelectorStep[] = [];
  const len = groupSrc.length;
  let p = 0;

  while (p < len && groupSrc.charCodeAt(p) <= 32) p++;

  let pendingCombinator: Combinator | null = null;
  if (p < len && (groupSrc[p] === '>' || groupSrc[p] === '+')) {
    if (groupSrc[p] !== '>') return null;
    pendingCombinator = '>';
    p++;
    while (p < len && groupSrc.charCodeAt(p) <= 32) p++;
    if (p >= len) return null;
  }

  while (p < len) {
    let tag: string | null = null;
    let hasExplicitUniversal = false;
    const ids: string[] = [];
    const classes: string[] = [];
    const attrs: AttrMatcher[] = [];

    if (groupSrc[p] === '*') {
      hasExplicitUniversal = true;
      p++;
    } else {
      const firstCh = groupSrc.charCodeAt(p);
      if ((firstCh >= 97 && firstCh <= 122) || (firstCh >= 65 && firstCh <= 90)) {
        const tagRes = readSimpleIdent(groupSrc, p);
        if (!tagRes) return null;
        tag = tagRes.ident.toLowerCase();
        p = tagRes.nextIdx;
      }
    }

    while (p < len) {
      const ch = groupSrc[p];
      if (ch === '#') {
        const idRes = readSimpleIdent(groupSrc, p + 1);
        if (!idRes) return null;
        ids.push(idRes.ident);
        p = idRes.nextIdx;
      } else if (ch === '.') {
        const clsRes = readSimpleIdent(groupSrc, p + 1);
        if (!clsRes) return null;
        classes.push(clsRes.ident);
        p = clsRes.nextIdx;
      } else if (ch === '[') {
        const attrRes = parseAttrSelector(groupSrc, p);
        if (!attrRes) return null;
        attrs.push(attrRes.matcher);
        p = attrRes.nextIdx;
      } else {
        break;
      }
    }

    if (tag === null && !hasExplicitUniversal && ids.length === 0 && classes.length === 0 && attrs.length === 0) {
      return null;
    }

    steps.push({
      combinatorFromPrev: pendingCombinator,
      compound: { tag, ids, classes, attrs },
    });
    if (steps.length > MAX_COMBINATOR_STEPS) return null;

    let sawSpace = false;
    while (p < len && groupSrc.charCodeAt(p) <= 32) {
      sawSpace = true;
      p++;
    }
    if (p >= len) break;

    const combCh = groupSrc[p];
    if (combCh === '>' || combCh === '+') {
      pendingCombinator = combCh;
      p++;
      while (p < len && groupSrc.charCodeAt(p) <= 32) p++;
      if (p >= len) return null;
    } else if (sawSpace) {
      pendingCombinator = ' ';
    } else {
      return null;
    }
  }

  return steps.length > 0 ? steps : null;
}

function parseSelector(selector: string): SelectorStep[][] | null {
  if (typeof selector !== 'string') return null;
  const trimmed = selector.trim();
  if (!trimmed || trimmed.length > MAX_SELECTOR_CHARS) return null;
  const rawGroups = splitSelectorGroups(trimmed);
  if (!rawGroups) return null;

  const chains: SelectorStep[][] = [];
  for (const g of rawGroups) {
    const chain = parseSingleSelectorChain(g);
    if (!chain) return null;
    chains.push(chain);
  }
  return chains;
}

function hasClassToken(classAttr: string | undefined, target: string): boolean {
  if (!classAttr || !target) return false;
  const tLen = target.length;
  let pos = classAttr.indexOf(target);
  while (pos >= 0) {
    const beforeOk = pos === 0 || classAttr.charCodeAt(pos - 1) <= 32;
    const afterIdx = pos + tLen;
    const afterOk = afterIdx === classAttr.length || classAttr.charCodeAt(afterIdx) <= 32;
    if (beforeOk && afterOk) return true;
    pos = classAttr.indexOf(target, pos + 1);
  }
  return false;
}

function matchesAttr(el: Element, m: AttrMatcher): boolean {
  const rawVal = el.attribs[m.name];
  if (rawVal === undefined) return false;
  if (m.op === 'exists') return true;
  const actual = m.ignoreCase ? rawVal.toLowerCase() : rawVal;
  const expected = m.value;
  switch (m.op) {
    case '=':
      return actual === expected;
    case '*=':
      return expected.length > 0 && actual.includes(expected);
    case '^=':
      return expected.length > 0 && actual.startsWith(expected);
    case '$=':
      return expected.length > 0 && actual.endsWith(expected);
    case '~=':
      return expected.length > 0 && hasClassToken(actual, expected);
    case '|=':
      return actual === expected || actual.startsWith(`${expected}-`);
  }
}

function matchesCompound(el: Element, c: CompoundStep): boolean {
  if (c.tag !== null && el.name.toLowerCase() !== c.tag) return false;
  if (c.ids.length > 0) {
    const elId = el.attribs.id;
    if (elId === undefined) return false;
    for (const id of c.ids) {
      if (elId !== id) return false;
    }
  }
  if (c.classes.length > 0) {
    const cls = el.attribs.class;
    if (!cls) return false;
    for (const token of c.classes) {
      if (!hasClassToken(cls, token)) return false;
    }
  }
  for (const attr of c.attrs) {
    if (!matchesAttr(el, attr)) return false;
  }
  return true;
}

function prevElementSibling(el: Element): Element | null {
  let cur = el.prev;
  while (cur) {
    if (isTag(cur)) return cur;
    cur = cur.prev;
  }
  return null;
}

function matchesChainAtStep(
  el: Element,
  steps: SelectorStep[],
  stepIdx: number,
  scopeRoot: Document | Element,
  failedMemo: Array<Set<Element>>,
): boolean {
  const memo = failedMemo[stepIdx]!;
  if (memo.has(el)) return false;

  const step = steps[stepIdx]!;
  if (!matchesCompound(el, step.compound)) {
    memo.add(el);
    return false;
  }

  if (stepIdx === 0) {
    if (step.combinatorFromPrev === '>') {
      const ok = el.parent === scopeRoot;
      if (!ok) memo.add(el);
      return ok;
    }
    return true;
  }

  const comb = step.combinatorFromPrev;
  if (comb === '>') {
    const parent = el.parent;
    if (!parent || parent === scopeRoot.parent || !isTag(parent)) {
      memo.add(el);
      return false;
    }
    const ok = matchesChainAtStep(parent, steps, stepIdx - 1, scopeRoot, failedMemo);
    if (!ok) memo.add(el);
    return ok;
  }

  if (comb === '+') {
    const prev = prevElementSibling(el);
    if (!prev) {
      memo.add(el);
      return false;
    }
    const ok = matchesChainAtStep(prev, steps, stepIdx - 1, scopeRoot, failedMemo);
    if (!ok) memo.add(el);
    return ok;
  }

  // Descendant combinator (`' '`): walk ancestor chain within `scopeRoot` with memoization (`O(K * N)` total!)
  let anc = el.parent;
  while (anc && anc !== scopeRoot.parent) {
    if (isTag(anc) && matchesChainAtStep(anc, steps, stepIdx - 1, scopeRoot, failedMemo)) {
      return true;
    }
    if (anc === scopeRoot) break;
    anc = anc.parent;
  }
  memo.add(el);
  return false;
}

function isSimpleLeafTextElement(node: Document | Element): boolean {
  if (!isTag(node)) return false;
  if (STRIPPED_TEXT_TAGS.has(node.name.toLowerCase())) return false;
  for (const child of node.children) {
    if (!isText(child)) return false;
  }
  return true;
}

const CLEAN_NODE_TEXT_CACHE = new WeakMap<Document | Element, string>();

function trimTrailingColonsAndWsLinear(input: string): string {
  let end = input.length;
  while (end > 0) {
    const code = input.charCodeAt(end - 1);
    if (code <= 32 || code === 58 /* ':' */ || code === 0xff1a /* '：' */ || code === 0x00a0) {
      end--;
    } else {
      break;
    }
  }
  let start = 0;
  while (start < end && input.charCodeAt(start) <= 32) {
    start++;
  }
  return start === 0 && end === input.length ? input : input.slice(start, end);
}

function computeRawNodeTextCached(node: Document | Element, rawCache: WeakMap<Document | Element, string>): string {
  const hit = rawCache.get(node);
  if (hit !== undefined) return hit;

  if (isTag(node) && STRIPPED_TEXT_TAGS.has(node.name.toLowerCase())) {
    rawCache.set(node, '');
    return '';
  }

  // Iterative post-order evaluation so deep subtrees never recurse and every Element is computed at most once.
  const stack: Array<{ target: Document | Element; childIdx: number; chunks: string[] }> = [
    { target: node, childIdx: 0, chunks: [] },
  ];

  while (stack.length > 0) {
    const top = stack[stack.length - 1]!;
    const children = top.target.children;
    if (top.childIdx >= children.length) {
      const joined = top.chunks.length === 0 ? '' : top.chunks.join('');
      rawCache.set(top.target, joined);
      stack.pop();
      if (stack.length > 0) {
        const parentFrame = stack[stack.length - 1]!;
        const finishedTag = isTag(top.target) ? top.target.name.toLowerCase() : '';
        const isBlock = finishedTag !== '' && BLOCK_BOUNDARY_TAGS.has(finishedTag);
        if (isBlock) parentFrame.chunks.push(' ');
        if (joined) parentFrame.chunks.push(joined);
        if (isBlock) parentFrame.chunks.push(' ');
      }
      continue;
    }

    const child = children[top.childIdx++]!;
    if (isText(child)) {
      if (child.data) top.chunks.push(child.data);
      continue;
    }
    if (!isTag(child)) continue;
    const tagLower = child.name.toLowerCase();
    if (STRIPPED_TEXT_TAGS.has(tagLower)) continue;
    if (tagLower === 'br' || tagLower === 'hr') {
      top.chunks.push(' ');
      continue;
    }
    const cachedChild = rawCache.get(child);
    if (cachedChild !== undefined) {
      const isBlock = BLOCK_BOUNDARY_TAGS.has(tagLower);
      if (isBlock) top.chunks.push(' ');
      if (cachedChild) top.chunks.push(cachedChild);
      if (isBlock) top.chunks.push(' ');
      continue;
    }
    stack.push({ target: child, childIdx: 0, chunks: [] });
  }

  return rawCache.get(node) ?? '';
}

const RAW_NODE_TEXT_CACHE = new WeakMap<Document | Element, string>();

function extractCleanNodeText(node: Document | Element): string {
  const cached = CLEAN_NODE_TEXT_CACHE.get(node);
  if (cached !== undefined) return cached;
  if (isTag(node) && STRIPPED_TEXT_TAGS.has(node.name.toLowerCase())) {
    CLEAN_NODE_TEXT_CACHE.set(node, '');
    return '';
  }
  let clean: string;
  if (isSimpleLeafTextElement(node)) {
    clean = textContent(node).replace(/\s+/g, ' ').trim();
  } else {
    const raw = computeRawNodeTextCached(node, RAW_NODE_TEXT_CACHE);
    clean = raw ? raw.replace(/\s+/g, ' ').trim() : '';
  }
  CLEAN_NODE_TEXT_CACHE.set(node, clean);
  return clean;
}

class BoundedHtmlParser extends Parser {
  private overflowDepth = 0;
  private currentOpenOverflowed = false;
  private readonly sourceHtml: string;

  constructor(sourceHtml: string, cbs: ConstructorParameters<typeof Parser>[0], options: ConstructorParameters<typeof Parser>[1]) {
    super(cbs, options);
    this.sourceHtml = sourceHtml;
  }

  override onopentagname(start: number, endIndex: number): void {
    const rawName = this.sourceHtml.slice(start, endIndex).toLowerCase();
    const normName = rawName === 'image' && !this.isInForeignContext() ? 'img' : rawName;
    const stackLen = (this as unknown as { stack: string[] }).stack.length;
    if (stackLen >= MAX_DOM_DEPTH && !this.isVoidElement(normName)) {
      this.endIndex = endIndex;
      this.overflowDepth++;
      this.currentOpenOverflowed = true;
      (this as unknown as { tagname: string }).tagname = '';
      return;
    }
    this.currentOpenOverflowed = false;
    super.onopentagname(start, endIndex);
  }

  override onselfclosingtag(endIndex: number): void {
    if (this.currentOpenOverflowed) {
      this.currentOpenOverflowed = false;
      if (this.isInForeignContext()) {
        this.overflowDepth = Math.max(0, this.overflowDepth - 1);
      }
      this.startIndex = endIndex + 1;
      return;
    }
    super.onselfclosingtag(endIndex);
  }

  override onclosetag(start: number, endIndex: number): void {
    this.currentOpenOverflowed = false;
    if (this.overflowDepth > 0) {
      this.endIndex = endIndex;
      const rawName = this.sourceHtml.slice(start, endIndex).toLowerCase();
      const normName = rawName === 'image' && !this.isInForeignContext() ? 'img' : rawName;
      if (!this.isVoidElement(normName)) {
        this.overflowDepth--;
      }
      this.startIndex = endIndex + 1;
      return;
    }
    super.onclosetag(start, endIndex);
  }
}

function buildBoundedDomDocument(html: string): Document {
  const root = new Document([]);
  const stack: Array<Document | Element> = [root];
  let nodeCount = 0;
  let halted = false;

  const appendChildLinear = (parent: Document | Element, child: ChildNode) => {
    const siblings = parent.children;
    const prev = siblings.length > 0 ? siblings[siblings.length - 1]! : null;
    child.parent = parent;
    child.prev = prev;
    child.next = null;
    if (prev) prev.next = child;
    siblings.push(child);
  };

  const parser = new BoundedHtmlParser(
    html,
    {
      onopentag(name, attribs) {
        if (halted) return;
        if (nodeCount >= MAX_DOM_NODES) {
          halted = true;
          return;
        }
        if (stack.length - 1 < MAX_DOM_DEPTH) {
          const el = new Element(name, attribs, []);
          appendChildLinear(stack[stack.length - 1]!, el);
          stack.push(el);
          nodeCount++;
        }
      },
      ontext(data) {
        if (halted || !data) return;
        const parent = stack[stack.length - 1]!;
        const siblings = parent.children;
        const last = siblings.length > 0 ? siblings[siblings.length - 1]! : null;
        if (last && isText(last)) {
          last.data += data;
          return;
        }
        if (nodeCount >= MAX_DOM_NODES) {
          halted = true;
          return;
        }
        appendChildLinear(parent, new Text(data));
        nodeCount++;
      },
      onclosetag() {
        if (halted) return;
        if (stack.length > 1) {
          stack.pop();
        }
      },
    },
    {
      decodeEntities: true,
      lowerCaseTags: true,
      lowerCaseAttributeNames: true,
    },
  );

  parser.end(html);
  return root;
}

function walkSubtreeElements(root: Document | Element, visit: (el: Element) => boolean | void): void {
  const stack: ChildNode[] = [];
  for (let i = root.children.length - 1; i >= 0; i--) {
    stack.push(root.children[i]!);
  }
  while (stack.length > 0) {
    const cur = stack.pop()!;
    if (!isTag(cur)) continue;
    if (visit(cur) === false) return;
    for (let i = cur.children.length - 1; i >= 0; i--) {
      stack.push(cur.children[i]!);
    }
  }
}

export class HtmlNode {
  public readonly tag: string;

  constructor(protected readonly node: Document | Element) {
    this.tag = isTag(node) ? node.name.toLowerCase() : '';
  }

  /** Selects up to `limit` matching descendant `HtmlNode`s in DOM document order (`O(N)` bounded CSS engine). */
  select(selector: string, limit = 500): HtmlNode[] {
    const cappedLimit = Math.max(0, Math.min(MAX_SELECT_LIMIT, Math.floor(limit)));
    if (cappedLimit === 0) return [];
    const chains = parseSelector(selector);
    if (!chains) return [];

    const memosByChain = chains.map((c) => c.map(() => new Set<Element>()));
    const results: HtmlNode[] = [];

    walkSubtreeElements(this.node, (el) => {
      for (let g = 0; g < chains.length; g++) {
        const steps = chains[g]!;
        if (matchesChainAtStep(el, steps, steps.length - 1, this.node, memosByChain[g]!)) {
          results.push(new HtmlNode(el));
          if (results.length >= cappedLimit) return false;
          break;
        }
      }
      return undefined;
    });

    return results;
  }

  /** Returns the first matching descendant `HtmlNode`, or `null` if none match. */
  first(selector: string): HtmlNode | null {
    return this.select(selector, 1)[0] ?? null;
  }

  /**
   * Returns clean text content (stripping `<script>`, `<style>`, `<noscript>`, `<template>`,
   * collapsing whitespace, and trimming). When `subSelector` is provided, reads from `first(subSelector)`.
   */
  text(subSelector?: string): string {
    if (subSelector !== undefined) {
      const target = this.first(subSelector);
      return target ? target.text() : '';
    }
    return extractCleanNodeText(this.node);
  }

  /**
   * Returns serialized inner HTML via `dom-serializer`. When `subSelector` is provided,
   * serializes the inner HTML of `first(subSelector)`.
   */
  html(subSelector?: string): string {
    if (subSelector !== undefined) {
      const target = this.first(subSelector);
      return target ? target.html() : '';
    }
    return this.node.children.length > 0 ? render(this.node.children) : '';
  }

  /** Returns serialized outer HTML of this node via `dom-serializer`. */
  outerHtml(): string {
    return render(this.node);
  }

  /** Returns the value of attribute `name` (case-insensitive), or `undefined` if absent. */
  attr(name: string): string | undefined {
    if (!isTag(this.node) || !name) return undefined;
    return this.node.attribs[name.toLowerCase()];
  }

  /** Shorthand for `this.first(subSelector)?.attr(name)`. */
  attrOf(subSelector: string, name: string): string | undefined {
    return this.first(subSelector)?.attr(name);
  }

  /**
   * Pairs `<dt>` -> following `<dd>` inside `<dl>` or wrapper containers (e.g. `div.iCIMS_JobHeaderTag`),
   * normalizing `<dt>` keys to lowercase trimmed strings with trailing `:` stripped.
   */
  dlMap(subSelector?: string): Record<string, string> {
    const containers = subSelector !== undefined ? this.select(subSelector, 200) : [this];
    const out: Record<string, string> = {};
    let count = 0;
    let visits = 0;
    const seenElements = new Set<Element>();

    for (const container of containers) {
      if (isTag(container.node) && seenElements.has(container.node)) continue;
      let pendingKey = '';
      walkSubtreeElements(container.node, (el) => {
        if (++visits > MAX_DLMAP_VISITS) return false;
        seenElements.add(el);
        const t = el.name.toLowerCase();
        if (t === 'dt') {
          pendingKey = trimTrailingColonsAndWsLinear(extractCleanNodeText(el).toLowerCase());
        } else if (t === 'dd' && pendingKey) {
          const val = extractCleanNodeText(el);
          if (val && !(pendingKey in out)) {
            out[pendingKey] = val;
            count++;
            if (count >= 200) return false;
          }
          pendingKey = '';
        }
        return undefined;
      });
      if (count >= 200 || visits > MAX_DLMAP_VISITS) break;
    }

    return out;
  }

  /** Extracts 2D array of cleaned cell text from `<tr>` -> `<th>`/`<td>` rows. */
  tableRows(subSelector?: string): string[][] {
    const target = subSelector !== undefined ? this.first(subSelector) : this;
    if (!target) return [];

    const rows: string[][] = [];
    const rootIsTable = isTag(target.node) && target.node.name.toLowerCase() === 'table';

    walkSubtreeElements(target.node, (el) => {
      if (el.name.toLowerCase() !== 'tr') return undefined;
      if (rootIsTable) {
        let p = el.parent;
        while (p && p !== target.node) {
          if (isTag(p) && p.name.toLowerCase() === 'table') return undefined;
          p = p.parent;
        }
      }
      const cells: string[] = [];
      for (const child of el.children) {
        if (!isTag(child)) continue;
        const ct = child.name.toLowerCase();
        if (ct === 'td' || ct === 'th') {
          cells.push(extractCleanNodeText(child));
        }
      }
      if (cells.length > 0 && cells.some((c) => c.length > 0)) {
        rows.push(cells);
        if (rows.length >= 500) return false;
      }
      return undefined;
    });

    return rows;
  }
}

export class HtmlDoc extends HtmlNode {
  public readonly root: Document;

  constructor(root: Document) {
    super(root);
    this.root = root;
  }
}

/**
 * Parses `rawHtml` (capped to `maxChars`, default `2 MiB`) into a linear-time queryable `HtmlDoc`.
 */
export function parseHtmlDoc(rawHtml: string, maxChars = DEFAULT_MAX_HTML_DOC_CHARS): HtmlDoc {
  const effectiveCap = Math.max(0, Math.min(MAX_HARD_HTML_DOC_CHARS, maxChars));
  let safeHtml =
    typeof rawHtml === 'string' ? (rawHtml.length > effectiveCap ? rawHtml.slice(0, effectiveCap) : rawHtml) : '';
  if (safeHtml.includes('\0') || safeHtml.includes('&#')) {
    safeHtml = safeHtml.replace(/\0|&#(?:0+|x0+);/gi, '');
  }
  const doc = buildBoundedDomDocument(safeHtml);
  return new HtmlDoc(doc);
}
