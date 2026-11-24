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

/** Extracts all `<meta name="key" content="...">` values (e.g. multiple `citation_author` tags) in linear O(N) time (`H1`). */
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

/**
 * Linear O(N) detector for literal, JSON-escaped (`\udb40\udc69`, `\\udb40\\udc69`, `\u{e0069}`), or
 * HTML-entity-encoded (`&#xE0069;`, `&#917609;`, `&amp;#xE0069;`) Unicode Tag smuggling (`U+E0000..U+E007F`).
 * Operates directly on raw `<script>` / JSON strings with zero tree-node budget so primitive/empty-array
 * padding can never mask smuggled tag characters (`NEW-HIGH-1`).
 */
export function hasRawOrEncodedUnicodeTagLinear(raw: string): boolean {
  if (!raw) return false;
  if (raw.includes('\uDB40') && /[\u{E0000}-\u{E007F}]/u.test(raw)) {
    return true;
  }
  if ((raw.includes('db40') || raw.includes('DB40') || raw.includes('e00') || raw.includes('E00')) && raw.includes('\\')) {
    if (/\\u(?:db40\\{1,16}udc[0-7][0-9a-f]|\{[ \t]{0,4}0{0,8}e00[0-7][0-9a-f][ \t]{0,4}\})/i.test(raw)) {
      return true;
    }
  }
  if (raw.includes('&') && raw.includes('#')) {
    if (
      /&(?:amp;|#0{0,6}38;?|#[xX]0{0,6}26;?){0,4}#(?:[xX]0{0,8}[eE]00[0-7][0-9a-fA-F]|0{0,8}917(?:50[4-9]|5[1-9]\d|6[0-2]\d|63[01]));?/.test(
        raw,
      )
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Linear predicate matching `<script type="application/ld+json">` attribute strings (quoted or unquoted,
 * with optional MIME parameters such as `;charset=utf-8`), shared across `extractJsonLdObjects`,
 * `schema-org.ts`, and `jobs.ts` so extraction and `checkPromptInjection` never desync (`HIGH-3`).
 */
export function isJsonLdScriptAttrLinear(attrStr: string): boolean {
  return /\btype[ \t\r\n]*=[ \t\r\n]*(?:["']application\/ld\+json(?:[ \t]*;[^"']*)?[ \t]*["']|application\/ld\+json(?:;[^ \t\r\n"'>]*)?(?=[ \t\r\n/>]|$))/i.test(
    attrStr,
  );
}

/** Extracts flattened JSON-LD objects from `<script type="application/ld+json">` blocks in linear O(N) time (`H1`). */
export function extractJsonLdObjects(rawHtml: string, maxEntities = 100): Array<Record<string, unknown>> {
  if (!/ld\+json/i.test(rawHtml)) return [];
  const cap = Math.max(1, Math.min(250, Math.floor(maxEntities)));
  const results: Array<Record<string, unknown>> = [];
  replaceHtmlTagBlocksLinear(rawHtml, 'script', (_full, attrStr, inner) => {
    if (results.length >= cap) return '';
    if (!isJsonLdScriptAttrLinear(attrStr)) {
      return '';
    }
    const raw = inner.trim();
    if (!raw || raw.length > 2 * 1024 * 1024) return '';
    const parsed = parseJsonValue(raw) ?? (raw.includes('&') ? parseJsonValue(decodeBasicEntities(raw)) : null);
    const pushItem = (item: unknown, depth: number) => {
      if (!item || typeof item !== 'object' || depth > 16 || results.length >= cap) return;
      if (Array.isArray(item)) {
        for (const el of item) {
          if (results.length >= cap) break;
          pushItem(el, depth + 1);
        }
        return;
      }
      const obj = item as Record<string, unknown>;
      results.push(obj);
      if (Array.isArray(obj['@graph'])) {
        for (const g of obj['@graph']) {
          if (results.length >= cap) break;
          pushItem(g, depth + 1);
        }
      }
    };
    pushItem(parsed, 0);
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
  const boundedRaw = rawMd.length > 2 * 1024 * 1024 ? rawMd.slice(0, 2 * 1024 * 1024) : rawMd;
  const normalized = boundedRaw.includes('\r') ? boundedRaw.replace(/\r\n/g, '\n') : boundedRaw;
  let yamlBlock = '';
  let body = '';
  let hasFrontmatter = false;
  if (normalized.startsWith('---\n')) {
    const headWindow = normalized.slice(0, 8_200);
    const closeMarker = headWindow.indexOf('\n---\n', 4);
    if (closeMarker >= 4 && closeMarker <= 8_004) {
      yamlBlock = normalized.slice(4, closeMarker);
      let bodyStart = closeMarker + 5;
      while (bodyStart < normalized.length && normalized.charCodeAt(bodyStart) === 10) bodyStart++;
      body = normalized.slice(bodyStart).trim();
      hasFrontmatter = true;
    }
  }
  if (!hasFrontmatter) {
    const h1Window = normalized.slice(0, 4_096);
    const h1 = /^#[ \t]+([^\n]{1,500})$/m.exec(h1Window)?.[1]?.trim();
    const title = h1 || fallbackTitle;
    const trimmedNorm = normalized.trim();
    const md = trimmedNorm.startsWith('# ') ? trimmedNorm : `# ${title}\n\n${trimmedNorm}`;
    return { title, markdown: md };
  }
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
