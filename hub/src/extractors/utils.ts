/**
 * HTML5 DOM parsing (`parseHtmlDoc`), HTML-stripping, JSON-LD, and Markdown table utilities for Site Adapters.
 */

import {
  compileLinearRegex,
  escapeResidualHtmlTagsOutsideCode,
  findTagOpenEndQuoteAware,
  replaceHtmlTagBlocksLinear,
  scanHtmlTagsLinear,
  stripHtmlTagsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from '../safe-input';

export { compileLinearRegex };
export { HtmlDoc, HtmlNode, parseHtmlDoc } from './html-doc';

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
  let maxTicks = 2;
  for (const m of code.matchAll(/`{3,}/g)) {
    if (m[0].length > maxTicks) maxTicks = m[0].length;
  }
  const fence = '`'.repeat(maxTicks + 1);
  return `${fence}${lang}\n${code.replace(/\r\n/g, '\n').trimEnd()}\n${fence}`;
}

export function decodeBasicEntities(s: string): string {
  return s
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex: string) => {
      const cp = parseInt(hex, 16);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : _m;
    })
    .replace(/&#(\d+);/g, (_m, dec: string) => {
      const cp = parseInt(dec, 10);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : _m;
    });
}

export function stripTagsInline(html: string): string {
  return escapeResidualHtmlTagsOutsideCode(
    decodeBasicEntities(stripHtmlTagsQuoteAwareLinear(html, ' '))
      .replace(/\s+/g, ' ')
      .trim(),
  );
}

/**
 * Safely unescapes ONLY HTML `&amp;` / `&#38;` / `&#x26;` inside extracted `href` URLs.
 * Never run full HTML entity decoding on query strings — otherwise `&currentTime=` turns into `¤tTime=` (`&curren`)
 * and `&section=` turns into `§ion=` (`&sect`)!
 */
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

/** Escapes pipe and newline characters for safe GitHub-Flavored Markdown table cells. */
export function escapeGfmCell(val: unknown, maxLen = 180): string {
  const str = String(val ?? '')
    .replace(/\r?\n+/g, ' ')
    .replace(/\|/g, '\\|')
    .replace(/\s+/g, ' ')
    .trim();
  if (!str) return '-';
  return str.length > maxLen ? `${str.slice(0, maxLen - 1)}…` : str;
}

/** Builds a clean GitHub-Flavored Markdown table from headers and rows. */
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
    const k = m[1]!.toLowerCase();
    attrs[k] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return attrs;
}

/** Extracts `<meta name="..." content="...">` or `<meta property="..." content="...">` values from HTML in linear O(N) time (`H1`). */
export function extractMetaContent(rawHtml: string, key: string): string {
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

/** Extracts all `<meta name="key" content="...">` values (e.g. multiple `citation_author` tags) in linear O(N) time (`H1`). */
export function extractAllMetaContents(rawHtml: string, key: string): string[] {
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

/** Extracts flattened JSON-LD objects from `<script type="application/ld+json">` blocks in linear O(N) time (`H1`). */
export function extractJsonLdObjects(rawHtml: string): Array<Record<string, unknown>> {
  const results: Array<Record<string, unknown>> = [];
  replaceHtmlTagBlocksLinear(rawHtml, 'script', (_full, attrStr, inner) => {
    if (results.length >= 30) return '';
    if (!/\btype[ \t\r\n]*=[ \t\r\n]*(?:["']application\/ld\+json[^"']*["']|application\/ld\+json\b)/i.test(attrStr)) {
      return '';
    }
    const raw = inner.trim();
    if (!raw) return '';
    const parsed = parseJsonValue(raw);
    const pushItem = (item: unknown) => {
      if (!item || typeof item !== 'object' || results.length >= 30) return;
      if (Array.isArray(item)) {
        for (const el of item) pushItem(el);
        return;
      }
      const obj = item as Record<string, unknown>;
      results.push(obj);
      if (Array.isArray(obj['@graph'])) {
        for (const g of obj['@graph']) pushItem(g);
      }
    };
    pushItem(parsed);
    return '';
  });
  return results;
}

/** Extracts balanced `<div ...>...</div>` inner HTML starting right at the matched opening `<div ...>` index (`H1`). */
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

/** Parses YAML model/dataset card frontmatter (e.g. Hugging Face `README.md`) into a GFM metadata table + clean Markdown body. */
export function formatYamlFrontmatterCard(rawMd: string, fallbackTitle: string): {
  title: string;
  description?: string;
  markdown: string;
} {
  const normalized = rawMd.replace(/\r\n/g, '\n');
  const fmMatch = /^---\n([\s\S]{1,8000}?)\n---\n+([\s\S]*)$/.exec(normalized);
  if (!fmMatch) {
    const h1 = /^#\s+(.+)$/m.exec(normalized)?.[1]?.trim();
    const title = h1 || fallbackTitle;
    const md = normalized.trimStart().startsWith('# ') ? normalized.trim() : `# ${title}\n\n${normalized.trim()}`;
    return { title, markdown: md };
  }

  const yamlBlock = fmMatch[1]!;
  const body = fmMatch[2]!.trim();
  const kvPairs: Array<[string, string]> = [];
  let currentKey = '';
  let listItems: string[] = [];

  const flushList = () => {
    if (currentKey && listItems.length > 0) {
      kvPairs.push([currentKey, listItems.slice(0, 12).join(', ')]);
    }
    currentKey = '';
    listItems = [];
  };

  for (const line of yamlBlock.split('\n')) {
    const listMatch = /^\s*-\s+(.+)$/.exec(line);
    if (listMatch && currentKey) {
      const item = listMatch[1]!.replace(/^["']|["']$/g, '').trim();
      if (item && !item.includes(':')) listItems.push(item);
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
    if (kv) {
      flushList();
      const k = kv[1]!;
      const v = kv[2]!.replace(/^["']|["']$/g, '').trim();
      if (!v) {
        currentKey = k;
      } else if (v.length <= 140 && !v.startsWith('{')) {
        kvPairs.push([k, v]);
      }
    }
  }
  flushList();

  const h1 = /^#\s+(.+)$/m.exec(body)?.[1]?.trim();
  const fmTitle = kvPairs.find(([k]) => k === 'pretty_name' || k === 'title')?.[1];
  const title = h1 || fmTitle || fallbackTitle;
  const keepKeys = new Set([
    'license',
    'pipeline_tag',
    'library_name',
    'base_model',
    'language',
    'tags',
    'datasets',
    'sdk',
    'task_categories',
    'size_categories',
  ]);
  const selected = kvPairs.filter(([k]) => keepKeys.has(k)).slice(0, 10);
  const tableLines =
    selected.length > 0
      ? formatGfmTable(
          ['Property', 'Value'],
          selected.map(([k, v]) => [`**${k}**`, v]),
        )
      : '';

  const parts: string[] = [];
  if (!body.startsWith('# ')) parts.push(`# ${title}`);
  if (tableLines) parts.push(tableLines);
  if (body) parts.push(body);

  const desc = kvPairs.find(([k]) => k === 'description' || k === 'summary')?.[1];
  return {
    title,
    ...(desc ? { description: desc } : {}),
    markdown: parts.join('\n\n').trim(),
  };
}
