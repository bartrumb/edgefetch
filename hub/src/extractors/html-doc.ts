/**
 * Linear-time HTML5 DOM parser & bounded CSS selector helper (`parseHtmlDoc`) powered by `htmlparser2`,
 * `domhandler`, `domutils`, and `dom-serializer` — giving Site Adapters ergonomic Cheerio / BeautifulSoup
 * extraction (`select`, `first`, `text`, `html`, `outerHtml`, `attr`, `attrOf`, `dlMap`, `tableRows`)
 * with zero backtracking regexes and guaranteed O(N) execution.
 */

import render from 'dom-serializer';
import { type ChildNode, type Document, DomHandler, type Element, isTag, isText } from 'domhandler';
import { Parser } from 'htmlparser2';

const DEFAULT_MAX_HTML_DOC_CHARS = 2_097_152; // 2 MiB default input cap
const HARD_MAX_HTML_DOC_CHARS = 4_194_304; // 4 MiB absolute ceiling
const MAX_DOM_DEPTH = 256;
const MAX_DOM_NODES = 24_000;
const MAX_DOC_TOTAL_VISITS = 90_000;
const MAX_TEXT_NODES_PER_CALL = 20_000;
const MAX_SERIALIZE_NODES_PER_CALL = 15_000;
const MAX_SELECTOR_CHARS = 256;
const MAX_SELECTOR_GROUPS = 16;
const MAX_COMBINATOR_STEPS = 8;
const MAX_SELECT_LIMIT = 5_000;

interface VisitBudget {
  remaining: number;
}

const STRIPPED_TEXT_TAGS: ReadonlySet<string> = new Set(['script', 'style', 'noscript', 'template']);

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

interface ChainMemo {
  step: Array<Map<Element, boolean>>;
  anc: Array<Map<Element, boolean>>;
}

function hasMatchingAncestor(
  el: Element,
  steps: SelectorStep[],
  prevStepIdx: number,
  scopeRoot: Document | Element,
  memo: ChainMemo,
): boolean {
  let p = el.parent;
  if (!p || p === scopeRoot.parent || !isTag(p)) return false;

  const ancMap = memo.anc[prevStepIdx]!;
  const hit = ancMap.get(p);
  if (hit !== undefined) return hit;

  const path: Element[] = [];
  let res = false;
  while (p && p !== scopeRoot.parent && isTag(p)) {
    const cached = ancMap.get(p);
    if (cached !== undefined) {
      res = cached;
      break;
    }
    path.push(p);
    if (p === scopeRoot) break;
    p = p.parent;
  }

  for (let i = path.length - 1; i >= 0; i--) {
    const node = path[i]!;
    if (!res) {
      res = matchesChainAtStep(node, steps, prevStepIdx, scopeRoot, memo);
    }
    ancMap.set(node, res);
  }
  return res;
}

function matchesChainAtStep(
  el: Element,
  steps: SelectorStep[],
  stepIdx: number,
  scopeRoot: Document | Element,
  memo: ChainMemo,
): boolean {
  const stepMap = memo.step[stepIdx]!;
  const existing = stepMap.get(el);
  if (existing !== undefined) return existing;

  const step = steps[stepIdx]!;
  if (!matchesCompound(el, step.compound)) {
    stepMap.set(el, false);
    return false;
  }

  if (stepIdx === 0) {
    const ok = step.combinatorFromPrev === '>' ? el.parent === scopeRoot : true;
    stepMap.set(el, ok);
    return ok;
  }

  const comb = step.combinatorFromPrev;
  if (comb === '>') {
    const parent = el.parent;
    if (!parent || parent === scopeRoot.parent || !isTag(parent)) {
      stepMap.set(el, false);
      return false;
    }
    const ok = matchesChainAtStep(parent, steps, stepIdx - 1, scopeRoot, memo);
    stepMap.set(el, ok);
    return ok;
  }

  if (comb === '+') {
    const prev = prevElementSibling(el);
    if (!prev) {
      stepMap.set(el, false);
      return false;
    }
    const ok = matchesChainAtStep(prev, steps, stepIdx - 1, scopeRoot, memo);
    stepMap.set(el, ok);
    return ok;
  }

  // Descendant combinator (`' '`): memoized `O(1)` amortized ancestor lookup (`O(K * N)` worst-case!)
  const ok = hasMatchingAncestor(el, steps, stepIdx - 1, scopeRoot, memo);
  stepMap.set(el, ok);
  return ok;
}

function isAsciiOrUnicodeWhitespaceCode(ch: number): boolean {
  return (
    ch <= 32 ||
    ch === 0x00a0 ||
    ch === 0x1680 ||
    (ch >= 0x2000 && ch <= 0x200a) ||
    ch === 0x2028 ||
    ch === 0x2029 ||
    ch === 0x202f ||
    ch === 0x205f ||
    ch === 0x3000 ||
    ch === 0xfeff
  );
}

function stripTrailingColonsAndWhitespace(s: string): string {
  let end = s.length;
  while (end > 0) {
    const ch = s.charCodeAt(end - 1);
    if (ch === 58 /* ':' */ || ch === 0xff1a /* '：' */ || isAsciiOrUnicodeWhitespaceCode(ch)) {
      end--;
    } else {
      break;
    }
  }
  let start = 0;
  while (start < end && isAsciiOrUnicodeWhitespaceCode(s.charCodeAt(start))) {
    start++;
  }
  return start === 0 && end === s.length ? s : s.slice(start, end);
}

function collapseAndTrimWhitespace(raw: string): string {
  let out = '';
  let inSpace = true;
  let chunkStart = -1;
  for (let i = 0; i < raw.length; i++) {
    if (isAsciiOrUnicodeWhitespaceCode(raw.charCodeAt(i))) {
      if (chunkStart >= 0) {
        if (out.length > 0) out += ' ';
        out += raw.slice(chunkStart, i);
        chunkStart = -1;
      }
      inSpace = true;
    } else if (inSpace) {
      chunkStart = i;
      inSpace = false;
    }
  }
  if (chunkStart >= 0) {
    if (out.length > 0) out += ' ';
    out += raw.slice(chunkStart);
  }
  return out;
}

function extractCleanNodeText(node: Document | Element, budget: VisitBudget): string {
  if (budget.remaining <= 0) return '';
  if (isTag(node) && STRIPPED_TEXT_TAGS.has(node.name.toLowerCase())) {
    return '';
  }

  const children = node.children;
  if (children.length === 0) return '';

  // Fast leaf check without recursion
  if (children.length === 1 && isText(children[0]!)) {
    budget.remaining--;
    return collapseAndTrimWhitespace(children[0]!.data);
  }

  const out: string[] = [];
  const stack: Array<ChildNode | string> = [];
  for (let i = children.length - 1; i >= 0; i--) {
    stack.push(children[i]!);
  }

  let localVisits = 0;
  while (stack.length > 0) {
    const item = stack.pop()!;
    if (typeof item === 'string') {
      out.push(item);
      continue;
    }
    if (budget.remaining <= 0 || localVisits >= MAX_TEXT_NODES_PER_CALL) break;
    budget.remaining--;
    localVisits++;

    if (isText(item)) {
      if (item.data) out.push(item.data);
      continue;
    }
    if (!isTag(item)) continue;

    const tagLower = item.name.toLowerCase();
    if (STRIPPED_TEXT_TAGS.has(tagLower)) continue;
    if (tagLower === 'br' || tagLower === 'hr') {
      out.push(' ');
      continue;
    }

    const isBlock = BLOCK_BOUNDARY_TAGS.has(tagLower);
    if (isBlock) out.push(' ');
    if (item.children.length > 0) {
      if (isBlock) stack.push(' ');
      for (let i = item.children.length - 1; i >= 0; i--) {
        stack.push(item.children[i]!);
      }
    } else if (isBlock) {
      out.push(' ');
    }
  }

  if (out.length === 0) return '';
  return collapseAndTrimWhitespace(out.join(''));
}

type WalkDirective = boolean | 'skip' | void;

function walkSubtreeElements(
  root: Document | Element,
  budget: VisitBudget,
  visit: (el: Element) => WalkDirective,
): void {
  if (budget.remaining <= 0) return;
  const stack: ChildNode[] = [];
  for (let i = root.children.length - 1; i >= 0; i--) {
    stack.push(root.children[i]!);
  }
  while (stack.length > 0) {
    if (budget.remaining <= 0) return;
    const cur = stack.pop()!;
    if (!isTag(cur)) continue;
    budget.remaining--;
    const res = visit(cur);
    if (res === false) return;
    if (res === 'skip') continue;
    for (let i = cur.children.length - 1; i >= 0; i--) {
      stack.push(cur.children[i]!);
    }
  }
}

function chargeSerializeBudget(nodes: readonly ChildNode[], budget: VisitBudget): boolean {
  if (budget.remaining <= 0) return false;
  const stack: ChildNode[] = [];
  for (let i = nodes.length - 1; i >= 0; i--) {
    stack.push(nodes[i]!);
  }
  let count = 0;
  while (stack.length > 0) {
    if (budget.remaining <= 0 || count >= MAX_SERIALIZE_NODES_PER_CALL) return false;
    const cur = stack.pop()!;
    budget.remaining--;
    count++;
    if (isTag(cur)) {
      for (let i = cur.children.length - 1; i >= 0; i--) {
        stack.push(cur.children[i]!);
      }
    }
  }
  return true;
}

class BoundedDomHandler extends DomHandler {
  private nodeCount = 0;
  private overflowDepth = 0;
  private overflowNodes = 0;
  private hostParser: Parser | null = null;
  public halted = false;

  attachParser(p: Parser): void {
    this.hostParser = p;
  }

  private forceHalt(): void {
    this.halted = true;
    this.hostParser?.pause();
  }

  private haltIfExceeded(): boolean {
    if (this.halted) return true;
    if (this.nodeCount >= MAX_DOM_NODES) {
      this.forceHalt();
      return true;
    }
    return false;
  }

  override onopentag(name: string, attribs: { [key: string]: string }): void {
    this.nodeCount++;
    if (this.haltIfExceeded()) return;
    if (this.overflowDepth > 0 || this.tagStack.length > MAX_DOM_DEPTH) {
      this.overflowDepth++;
      this.overflowNodes++;
      if (this.overflowNodes >= 1_024) {
        this.forceHalt();
      }
      return;
    }
    super.onopentag(name, attribs);
  }

  override onclosetag(): void {
    if (this.halted) return;
    if (this.overflowDepth > 0) {
      this.overflowDepth--;
      return;
    }
    super.onclosetag();
  }

  override ontext(data: string): void {
    if (this.halted) return;
    this.nodeCount++;
    if (this.haltIfExceeded()) return;
    super.ontext(data);
  }

  override oncomment(_data: string): void {
    // Comments are unused by CSS selectors / text extraction; skip allocating Comment nodes.
  }

  override oncommentend(): void {}
}

export class HtmlNode {
  public readonly tag: string;
  protected readonly budget: VisitBudget;

  constructor(
    protected readonly node: Document | Element,
    budget?: VisitBudget,
  ) {
    this.tag = isTag(node) ? node.name.toLowerCase() : '';
    this.budget = budget ?? { remaining: MAX_DOC_TOTAL_VISITS };
  }

  /** Selects up to `limit` matching descendant `HtmlNode`s in DOM document order (`O(N)` bounded CSS engine). */
  select(selector: string, limit = 500): HtmlNode[] {
    const cappedLimit = Math.max(0, Math.min(MAX_SELECT_LIMIT, Math.floor(limit)));
    if (cappedLimit === 0 || this.budget.remaining <= 0) return [];
    const chains = parseSelector(selector);
    if (!chains) return [];

    const memosByChain: ChainMemo[] = chains.map((c) => ({
      step: c.map(() => new Map<Element, boolean>()),
      anc: c.map(() => new Map<Element, boolean>()),
    }));
    const results: HtmlNode[] = [];

    walkSubtreeElements(this.node, this.budget, (el) => {
      for (let g = 0; g < chains.length; g++) {
        const steps = chains[g]!;
        if (matchesChainAtStep(el, steps, steps.length - 1, this.node, memosByChain[g]!)) {
          results.push(new HtmlNode(el, this.budget));
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
    return extractCleanNodeText(this.node, this.budget);
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
    if (this.node.children.length === 0) return '';
    if (!chargeSerializeBudget(this.node.children, this.budget)) return '';
    return render(this.node.children);
  }

  /** Returns serialized outer HTML of this node via `dom-serializer`. */
  outerHtml(): string {
    if (!chargeSerializeBudget([this.node as unknown as ChildNode], this.budget)) return '';
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

    for (const container of containers) {
      let pendingKey = '';
      walkSubtreeElements(container.node, this.budget, (el) => {
        const t = el.name.toLowerCase();
        if (t === 'dt') {
          pendingKey = stripTrailingColonsAndWhitespace(
            extractCleanNodeText(el, this.budget).toLowerCase(),
          );
          return 'skip';
        }
        if (t === 'dd') {
          if (pendingKey) {
            const val = extractCleanNodeText(el, this.budget);
            if (val && !(pendingKey in out)) {
              out[pendingKey] = val;
              count++;
              if (count >= 200) return false;
            }
            pendingKey = '';
          }
          return 'skip';
        }
        return undefined;
      });
      if (count >= 200 || this.budget.remaining <= 0) break;
    }

    return out;
  }

  /** Extracts 2D array of cleaned cell text from `<tr>` -> `<th>`/`<td>` rows. */
  tableRows(subSelector?: string): string[][] {
    const target = subSelector !== undefined ? this.first(subSelector) : this;
    if (!target) return [];

    const rows: string[][] = [];
    const rootIsTable = isTag(target.node) && target.node.name.toLowerCase() === 'table';

    walkSubtreeElements(target.node, this.budget, (el) => {
      const tagLower = el.name.toLowerCase();
      if (rootIsTable && tagLower === 'table') {
        return 'skip';
      }
      if (tagLower !== 'tr') return undefined;
      const cells: string[] = [];
      for (const child of el.children) {
        if (!isTag(child)) continue;
        const ct = child.name.toLowerCase();
        if (ct === 'td' || ct === 'th') {
          cells.push(extractCleanNodeText(child, this.budget));
        }
      }
      if (cells.length > 0 && cells.some((c) => c.length > 0)) {
        rows.push(cells);
        if (rows.length >= 500) return false;
      }
      return rootIsTable ? 'skip' : undefined;
    });

    return rows;
  }
}

export class HtmlDoc extends HtmlNode {
  public readonly root: Document;

  constructor(root: Document, budget?: VisitBudget) {
    super(root, budget);
    this.root = root;
  }
}

/**
 * Parses `rawHtml` (capped to `maxChars`, default `2 MiB`, hard ceiling `4 MiB`) into a linear-time queryable `HtmlDoc`.
 */
export function parseHtmlDoc(rawHtml: string, maxChars = DEFAULT_MAX_HTML_DOC_CHARS): HtmlDoc {
  const effectiveMax =
    Number.isFinite(maxChars) && maxChars > 0
      ? Math.min(HARD_MAX_HTML_DOC_CHARS, Math.floor(maxChars))
      : DEFAULT_MAX_HTML_DOC_CHARS;
  const safeHtml =
    typeof rawHtml === 'string'
      ? rawHtml.length > effectiveMax
        ? rawHtml.slice(0, effectiveMax)
        : rawHtml
      : '';
  const handler = new BoundedDomHandler();
  const parser = new Parser(handler);
  handler.attachParser(parser);
  const PARSE_CHUNK_CHARS = 16_384;
  for (let off = 0; off < safeHtml.length && !handler.halted; off += PARSE_CHUNK_CHARS) {
    parser.write(safeHtml.slice(off, off + PARSE_CHUNK_CHARS));
  }
  if (!handler.halted) {
    parser.end();
  }
  return new HtmlDoc(handler.root);
}
