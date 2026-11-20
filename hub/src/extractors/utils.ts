/**
 * Zero-dependency parsing, HTML-stripping, JSON-LD, and Markdown table utilities for Site Adapters.
 */

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
  return decodeBasicEntities(html.replace(/<[^>]+>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
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
  return rawHtml.replace(/<(script|style|svg)\b(?:"[^"]*"|'[^']*'|[^>"'])*>[\s\S]*?<\/\1>/gi, '');
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

/** Extracts `<meta name="..." content="...">` or `<meta property="..." content="...">` values from HTML. */
export function extractMetaContent(rawHtml: string, key: string): string {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const head = rawHtml.slice(0, 80000);
  const re1 = new RegExp(
    `<meta\\b[^>]*(?:name|property)=["']${escaped}["'][^>]*content=["']([^"']*)["'][^>]*>`,
    'i',
  );
  const m1 = re1.exec(head);
  if (m1?.[1]) return decodeBasicEntities(m1[1]).trim();
  const re2 = new RegExp(
    `<meta\\b[^>]*content=["']([^"']*)["'][^>]*(?:name|property)=["']${escaped}["'][^>]*>`,
    'i',
  );
  const m2 = re2.exec(head);
  return m2?.[1] ? decodeBasicEntities(m2[1]).trim() : '';
}

/** Extracts all `<meta name="key" content="...">` values (e.g. multiple `citation_author` tags). */
export function extractAllMetaContents(rawHtml: string, key: string): string[] {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const head = rawHtml.slice(0, 120000);
  const out: string[] = [];
  const tagRe = /<meta\b(?:"[^"]*"|'[^']*'|[^>"'])*>/gi;
  const keyRe = new RegExp(`\\b(?:name|property)=["']${escaped}["']`, 'i');
  const valRe = /\bcontent=["']([^"']*)["']/i;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(head)) !== null) {
    if (keyRe.test(m[0])) {
      const val = valRe.exec(m[0])?.[1];
      if (val) {
        const clean = decodeBasicEntities(val).trim();
        if (clean && !out.includes(clean)) out.push(clean);
      }
    }
  }
  return out;
}

/** Extracts flattened JSON-LD objects from `<script type="application/ld+json">` blocks. */
export function extractJsonLdObjects(rawHtml: string): Array<Record<string, unknown>> {
  const results: Array<Record<string, unknown>> = [];
  const re = /<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rawHtml)) !== null && results.length < 30) {
    const raw = m[1]?.trim();
    if (!raw) continue;
    const parsed = parseJsonValue(raw);
    const pushItem = (item: unknown) => {
      if (!item || typeof item !== 'object') return;
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
  }
  return results;
}

/** Extracts balanced `<div ...>...</div>` inner HTML starting right at the matched opening `<div ...>` index. */
export function extractBalancedDivAt(html: string, openTagIndex: number): string | null {
  const openTagEnd = html.indexOf('>', openTagIndex);
  if (openTagEnd < 0) return null;
  if (html[openTagEnd - 1] === '/') return '';
  let depth = 1;
  const tagRe = /<\/?div\b(?:"[^"]*"|'[^']*'|[^>"'])*>/gi;
  tagRe.lastIndex = openTagEnd + 1;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(html)) !== null) {
    const tok = m[0];
    if (tok.startsWith('</')) {
      depth--;
      if (depth === 0) {
        return html.slice(openTagEnd + 1, m.index);
      }
    } else if (!tok.endsWith('/>')) {
      depth++;
    }
  }
  return null;
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
