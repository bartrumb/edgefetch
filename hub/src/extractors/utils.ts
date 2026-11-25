/**
 * HTML5 DOM parsing (`parseHtmlDoc` via Go WASM `internal/extract/html_dom.go`), HTML-stripping, JSON-LD,
 * and Markdown table utilities for Site Adapters.
 */

import {
  compileLinearRegex,
  escapeResidualHtmlTagsOutsideCode,
  findTagOpenEndQuoteAware,
  scanHtmlTagsLinear,
  stripHtmlTagsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from '../safe-input';
import {
  callCoreWasm,
  callCoreWasmRaw,
  callCoreWasmRawString,
  getWasmReactorStats,
  isWasmReactorGenerationCurrent,
} from '../wasm-bridge';

export { compileLinearRegex };

export class HtmlNode {
  readonly tag: string;
  protected readonly docId: number;
  protected readonly nodeId: number;
  protected readonly reactorGen: number;

  constructor(docId: number, nodeId: number, tag = '', reactorGen = 0) {
    this.docId = docId;
    this.nodeId = nodeId;
    this.tag = tag;
    this.reactorGen = reactorGen;
  }

  private isLive(): boolean {
    if (this.docId <= 0) return false;
    return this.reactorGen > 0 ? isWasmReactorGenerationCurrent(this.reactorGen) : false;
  }

  select(selector: string, limit = 500): HtmlNode[] {
    if (!this.isLive() || !selector) return [];
    const res = callCoreWasm<{ items: Array<{ nodeId: number; tag: string }> }>('dom_select', {
      docId: this.docId,
      nodeId: this.nodeId,
      selector: String(selector),
      limit,
    });
    return (res.items ?? []).map((it) => new HtmlNode(this.docId, it.nodeId, it.tag, this.reactorGen));
  }

  first(selector: string): HtmlNode | null {
    return this.select(selector, 1)[0] ?? null;
  }

  text(subSelector?: string): string {
    if (!this.isLive()) return '';
    return (
      callCoreWasm<{ val?: string }>('dom_node_op', {
        docId: this.docId,
        nodeId: this.nodeId,
        op: 'text',
        ...(subSelector !== undefined ? { subSelector } : {}),
      }).val ?? ''
    );
  }

  html(subSelector?: string): string {
    if (!this.isLive()) return '';
    return (
      callCoreWasm<{ val?: string }>('dom_node_op', {
        docId: this.docId,
        nodeId: this.nodeId,
        op: 'html',
        ...(subSelector !== undefined ? { subSelector } : {}),
      }).val ?? ''
    );
  }

  outerHtml(): string {
    if (!this.isLive()) return '';
    return callCoreWasm<{ val?: string }>('dom_node_op', { docId: this.docId, nodeId: this.nodeId, op: 'outerHtml' }).val ?? '';
  }

  attr(name: string): string | undefined {
    if (!this.isLive() || !name) return undefined;
    const res = callCoreWasm<{ ok: boolean; val?: string }>('dom_node_op', {
      docId: this.docId,
      nodeId: this.nodeId,
      op: 'attr',
      attrName: String(name),
    });
    return res.ok ? (res.val ?? '') : undefined;
  }

  attrOf(subSelector: string, name: string): string {
    if (!this.isLive() || !subSelector || !name) return '';
    return (
      callCoreWasm<{ val?: string }>('dom_node_op', {
        docId: this.docId,
        nodeId: this.nodeId,
        op: 'attrOf',
        subSelector: String(subSelector),
        attrName: String(name),
      }).val ?? ''
    );
  }

  dlMap(subSelector?: string): Record<string, string> {
    if (!this.isLive()) return {};
    return (
      callCoreWasm<{ val?: Record<string, string> }>('dom_node_op', {
        docId: this.docId,
        nodeId: this.nodeId,
        op: 'dlMap',
        ...(subSelector !== undefined ? { subSelector } : {}),
      }).val ?? {}
    );
  }

  tableRows(subSelector?: string): string[][] {
    if (!this.isLive()) return [];
    return (
      callCoreWasm<{ val?: string[][] }>('dom_node_op', {
        docId: this.docId,
        nodeId: this.nodeId,
        op: 'tableRows',
        ...(subSelector !== undefined ? { subSelector } : {}),
      }).val ?? []
    );
  }
}

export class HtmlDoc extends HtmlNode {
  constructor(docId: number, rootNodeId: number, reactorGen = 0) {
    super(docId, rootNodeId, '', reactorGen);
  }
}

export function parseHtmlDoc(rawHtml: string, maxChars = 2 * 1024 * 1024): HtmlDoc {
  if (typeof rawHtml !== 'string' || !rawHtml) {
    return new HtmlDoc(0, 0, 0);
  }
  const bounded = maxChars > 0 && rawHtml.length > maxChars ? rawHtml.slice(0, maxChars) : rawHtml;
  const res = callCoreWasm<{ docId: number; rootNodeId: number }>('dom_parse', {
    rawHtml: bounded,
    maxChars,
  });
  const stats = getWasmReactorStats();
  if (!stats.active || res.docId <= 0) {
    return new HtmlDoc(0, 0, 0);
  }
  return new HtmlDoc(res.docId, res.rootNodeId, stats.generation);
}

export const CODE_EXT_FENCE_MAP: Record<string, string> = {
  ts: 'ts',
  tsx: 'tsx',
  js: 'js',
  jsx: 'jsx',
  mjs: 'js',
  cjs: 'js',
  py: 'python',
  go: 'go',
  rs: 'rust',
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
  yaml: 'yaml',
  yml: 'yaml',
  toml: 'toml',
  json: 'json',
  sql: 'sql',
  graphql: 'graphql',
  proto: 'protobuf',
  tf: 'hcl',
  hcl: 'hcl',
  nix: 'nix',
  zig: 'zig',
  lua: 'lua',
  ex: 'elixir',
  exs: 'elixir',
  erl: 'erlang',
  css: 'css',
  scss: 'scss',
  html: 'html',
  xml: 'xml',
};

export function safeFence(code: string, lang = ''): string {
  return callCoreWasm<{ out: string }>('make_safe_fence', { code: String(code ?? ''), lang, preferTilde: false }).out;
}

export function decodeBasicEntities(s: string): string {
  const str = String(s ?? '');
  if (!str || !str.includes('&')) return str;
  return callCoreWasm<{ out: string }>('decode_basic_entities', { input: str }).out;
}

export function stripTagsInline(html: string): string {
  return escapeResidualHtmlTagsOutsideCode(
    decodeBasicEntities(stripHtmlTagsQuoteAwareLinear(html, ' '))
      .replace(/\s+/g, ' ')
      .trim(),
  );
}

export function unescapeHrefUrl(rawHref: string): string {
  return rawHref.replace(/&(?:amp|#0*38|#x0*26);/gi, '&').trim();
}

export function stripScriptsAndStyles(rawHtml: string): string {
  return stripHtmlTagsLinear(rawHtml, ['script', 'style', 'svg', 'iframe', 'object', 'embed'], '');
}

export function detectFenceLang(filePath: string): { lang: string; isMarkdown: boolean } {
  const base = (filePath.split('/').pop() ?? filePath).toLowerCase();
  if (base === 'dockerfile' || base.startsWith('dockerfile.')) return { lang: 'dockerfile', isMarkdown: false };
  if (base === 'makefile' || base === 'gnumakefile') return { lang: 'makefile', isMarkdown: false };
  const ext = /\.([a-z0-9]+)$/i.exec(base)?.[1] ?? '';
  if (ext === 'md' || ext === 'mdx' || ext === 'markdown') return { lang: 'markdown', isMarkdown: true };
  return { lang: CODE_EXT_FENCE_MAP[ext] ?? ext, isMarkdown: false };
}

export function parseJsonObject(raw: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(raw.replace(/^\ufeff/, ''));
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function parseJsonValue(raw: string): unknown {
  try {
    return JSON.parse(raw.replace(/^\ufeff/, ''));
  } catch {
    return null;
  }
}

export function escapeGfmCell(val: unknown, maxLen = 180): string {
  const str = String(val ?? '')
    .replace(/\r?\n+/g, ' ')
    .replace(/\|/g, '\\|')
    .replace(/\s+/g, ' ')
    .trim();
  if (!str) return '-';
  return str.length > maxLen ? `${str.slice(0, maxLen - 1)}…` : str;
}

export function formatGfmTable(headers: string[], rows: Array<Array<unknown>>): string {
  if (headers.length === 0 || rows.length === 0) return '';
  const headLine = `| ${headers.map((h) => escapeGfmCell(h, 80)).join(' | ')} |`;
  const sepLine = `| ${headers.map(() => '---').join(' | ')} |`;
  const bodyLines = rows.map((r) => `| ${headers.map((_h, idx) => escapeGfmCell(r[idx])).join(' | ')} |`);
  return [headLine, sepLine, ...bodyLines].join('\n');
}

function parseMetaTagAttrsLinear(attrChunk: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)[ \t\r\n]*(?:=[ \t\r\n]*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrChunk)) !== null) {
    attrs[m[1]!.toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return attrs;
}

export function extractMetaContent(rawHtml: string, key: string): string {
  if (!/<meta[\s/>]/i.test(rawHtml)) return '';
  const targetKey = key.toLowerCase();
  let found = '';
  scanHtmlTagsLinear(
    rawHtml,
    (tag) => {
      if (tag.isClosing || tag.tagNameLower !== 'meta') return;
      const attrs = parseMetaTagAttrsLinear(tag.attrs);
      const nameVal = (attrs.name ?? attrs.property ?? attrs.itemprop ?? '').toLowerCase();
      if (nameVal === targetKey && attrs.content) {
        const clean = decodeBasicEntities(attrs.content).trim();
        if (clean) {
          found = clean;
          return false;
        }
      }
      return undefined;
    },
    80_000,
    false,
  );
  return found;
}

export function extractAllMetaContents(rawHtml: string, key: string): string[] {
  if (!/<meta[\s/>]/i.test(rawHtml)) return [];
  const targetKey = key.toLowerCase();
  const out: string[] = [];
  scanHtmlTagsLinear(
    rawHtml,
    (tag) => {
      if (tag.isClosing || tag.tagNameLower !== 'meta') return;
      const attrs = parseMetaTagAttrsLinear(tag.attrs);
      const nameVal = (attrs.name ?? attrs.property ?? '').toLowerCase();
      if (nameVal === targetKey && attrs.content) {
        const clean = decodeBasicEntities(attrs.content).trim();
        if (clean && !out.includes(clean)) out.push(clean);
      }
    },
    120_000,
    false,
  );
  return out;
}

export function hasRawOrEncodedUnicodeTagLinear(raw: string): boolean {
  if (!raw) return false;
  return callCoreWasmRaw<{ hit: boolean }>('has_unicode_tag', null, String(raw)).hit;
}

export function isJsonLdScriptAttrLinear(attrStr: string): boolean {
  if (!attrStr) return false;
  return callCoreWasm<{ ok: boolean }>('is_jsonld_script_attr', { attrStr }).ok;
}

export function extractJsonLdObjects(rawHtml: string, maxEntities = 100): Array<Record<string, unknown>> {
  if (!rawHtml || !/ld\+json/i.test(rawHtml)) return [];
  return callCoreWasm<{ objects: Array<Record<string, unknown>> | null }>('extract_jsonld_objects', {
    rawHtml,
    maxEntities,
  }).objects ?? [];
}

export function extractBalancedDivAt(html: string, openTagIndex: number): string | null {
  const deadRef: { mask?: Uint8Array } = {};
  const openTagEnd = findTagOpenEndQuoteAware(html, openTagIndex + 4, deadRef);
  if (openTagEnd < 0) return null;
  if (html[openTagEnd - 1] === '/') return '';
  let depth = 1;
  let result: string | null = null;
  scanHtmlTagsLinear(
    html.slice(openTagEnd + 1),
    (tag) => {
      if (tag.tagNameLower !== 'div') return;
      if (tag.isClosing) {
        depth--;
        if (depth === 0) {
          result = html.slice(openTagEnd + 1, openTagEnd + 1 + tag.index);
          return false;
        }
      } else if (!tag.isSelfClosing) {
        depth++;
      }
      return undefined;
    },
    undefined,
    false,
  );
  return result;
}

export function formatUsdCompact(n: unknown): string {
  const num = typeof n === 'number' ? n : typeof n === 'string' ? Number(n) : NaN;
  if (!Number.isFinite(num)) return '';
  const abs = Math.abs(num);
  const sign = num < 0 ? '-' : '';
  if (abs >= 1e9) return `${sign}$${(abs / 1e9).toFixed(2)}B`;
  if (abs >= 1e6) return `${sign}$${(abs / 1e6).toFixed(2)}M`;
  if (abs >= 1e3) return `${sign}$${abs.toLocaleString('en-US', { maximumFractionDigits: 0 })}`;
  return `${sign}$${abs.toFixed(2)}`;
}

export function formatYamlFrontmatterCard(rawMd: string, fallbackTitle: string): {
  title: string;
  description?: string;
  markdown: string;
} {
  const packed = callCoreWasmRawString(
    'format_yaml_card',
    { fallbackTitle: String(fallbackTitle ?? '') },
    String(rawMd ?? ''),
  );
  if (!packed) {
    return { title: fallbackTitle, markdown: '' };
  }
  const sep1 = packed.indexOf('\0');
  const sep2 = sep1 >= 0 ? packed.indexOf('\0', sep1 + 1) : -1;
  if (sep1 < 0 || sep2 < 0) {
    return { title: fallbackTitle, markdown: packed };
  }
  const title = packed.slice(0, sep1) || fallbackTitle;
  const description = packed.slice(sep1 + 1, sep2);
  const markdown = packed.slice(sep2 + 1);
  return {
    title,
    ...(description ? { description } : {}),
    markdown,
  };
}
