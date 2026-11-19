/**
 * Markdown derivation pipeline (`SCRAPE_PIPELINE_VERSION = 1`), `llms.txt` parser, `maxAgeMs` verified cache lookup,
 * and `POST /v1/scrape` + MCP `scrape` execution (`PR S6`).
 *
 * Security Invariants:
 *  - `deriveMarkdownDocument` NEVER reuses or derives from unverified artifacts (`isContentVerifiedInMetaD1` must be true).
 *  - Derived outputs are stored deterministically at `derived/<pipelineVersion>/markdown/<contentSha256>` in `ARTIFACTS` R2
 *    and tracked in `META` D1 `documents` with `(content_sha256, format, pipeline_version)` uniqueness.
 */

import { isContentVerifiedInMetaD1, sha256HexString } from './ingest';
import { computeMarkdownChanges } from './map-crawl';
import {
  isValidSha256Hex,
  r2DerivedKey,
  readVerifiedArtifactFromR2,
  type ArtifactRetention,
  type OptionalStorageBindings,
} from './storage';

export const SCRAPE_PIPELINE_VERSION = 1;

export interface ScrapedImage {
  url: string;
  alt?: string;
}

export interface BrandingProfile {
  title?: string;
  description?: string;
  canonicalUrl?: string;
  favicon?: string;
  logo?: string;
  ogImage?: string;
  themeColor?: string;
  colors?: string[];
  fonts?: string[];
}

export interface LlmsLinkItem {
  section?: string;
  title: string;
  url: string;
  notes?: string;
}

export interface ParsedLlmsTxt {
  sourceUrl: string;
  title?: string;
  summary?: string;
  fullTxtUrl?: string;
  links: LlmsLinkItem[];
}

export interface ExtractedDocument {
  title?: string;
  description?: string;
  language?: string;
  canonicalUrl?: string;
  favicon?: string;
  markdown: string;
  text: string;
  links: string[];
  images: ScrapedImage[];
  branding: BrandingProfile;
}

const HTML_ENTITIES: Record<string, string> = {
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&#39;': "'",
  '&apos;': "'",
  '&nbsp;': ' ',
};

function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&(amp|lt|gt|quot|#39|apos|nbsp);/gi, (m) => HTML_ENTITIES[m.toLowerCase()] ?? m)
    .replace(/&#(\d+);/g, (_m, dec) => {
      const code = Number(dec);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex) => {
      const code = parseInt(hex, 16);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    });
}

function parseTagAttrs(tag: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(tag)) !== null) {
    const key = m[1]!.toLowerCase();
    if (!(key in attrs)) {
      attrs[key] = decodeHtmlEntities(m[2] ?? m[3] ?? m[4] ?? '');
    }
  }
  return attrs;
}

function resolveHttpsHref(rawHref: string | undefined, baseUrl?: string): string | undefined {
  if (!rawHref) return undefined;
  const trimmed = rawHref.trim();
  if (!trimmed || trimmed.startsWith('javascript:') || trimmed.startsWith('mailto:') || trimmed.startsWith('data:')) {
    return undefined;
  }
  try {
    const u = baseUrl ? new URL(trimmed, baseUrl) : new URL(trimmed);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return undefined;
    u.hash = '';
    return u.toString();
  } catch {
    return undefined;
  }
}

function cleanInlineHtml(fragment: string): string {
  return decodeHtmlEntities(fragment.replace(/<[^>]+>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
}

export function redactPiiText(text: string): string {
  return text
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    .replace(/(?:\+?1[-.\s]?)?\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[REDACTED_PHONE]');
}

/** Extracts clean GFM Markdown, metadata, links, images, and branding from raw HTML without external DOM dependencies. */
export function extractHtmlDocument(
  rawHtml: string,
  options: { baseUrl?: string; onlyMainContent?: boolean; redactPii?: boolean } = {},
): ExtractedDocument {
  const { baseUrl, onlyMainContent = true, redactPii = false } = options;

  const htmlTagMatch = /<html\b[^>]*>/i.exec(rawHtml);
  const htmlAttrs = htmlTagMatch ? parseTagAttrs(htmlTagMatch[0]) : {};
  const language = htmlAttrs.lang?.trim() || undefined;

  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(rawHtml);
  let title = titleMatch ? cleanInlineHtml(titleMatch[1]!) : undefined;
  let description: string | undefined;
  let ogImage: string | undefined;
  let themeColor: string | undefined;

  const metaRe = /<meta\b[^>]*>/gi;
  let metaMatch: RegExpExecArray | null;
  while ((metaMatch = metaRe.exec(rawHtml)) !== null) {
    const attrs = parseTagAttrs(metaMatch[0]);
    const key = (attrs.name ?? attrs.property ?? '').toLowerCase();
    const content = (attrs.content ?? '').trim();
    if (!content) continue;
    if ((key === 'description' || key === 'og:description') && !description) description = content;
    if (key === 'og:title' && !title) title = content;
    if ((key === 'og:image' || key === 'twitter:image') && !ogImage) ogImage = resolveHttpsHref(content, baseUrl);
    if (key === 'theme-color' && !themeColor) themeColor = content;
  }

  let canonicalUrl: string | undefined;
  let favicon: string | undefined;
  const linkRe = /<link\b[^>]*>/gi;
  let linkMatch: RegExpExecArray | null;
  while ((linkMatch = linkRe.exec(rawHtml)) !== null) {
    const attrs = parseTagAttrs(linkMatch[0]);
    const rel = (attrs.rel ?? '').toLowerCase();
    const href = resolveHttpsHref(attrs.href, baseUrl);
    if (!href) continue;
    if (rel.includes('canonical') && !canonicalUrl) canonicalUrl = href;
    if (rel.includes('icon') && !favicon) favicon = href;
  }
  if (!favicon && baseUrl) {
    try {
      const bu = new URL(baseUrl);
      favicon = `${bu.origin}/favicon.ico`;
    } catch {
      // ignore
    }
  }

  // Extract colors and fonts from <style> tags before stripping them.
  const styleText = [...rawHtml.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => m[1]!).join('\n');
  const colors = [...new Set((styleText.match(/#[0-9a-fA-F]{6}\b/g) ?? []).map((c) => c.toLowerCase()))]
    .filter((c) => c !== '#ffffff' && c !== '#000000')
    .slice(0, 8);
  const fonts = [
    ...new Set(
      [...styleText.matchAll(/font-family\s*:\s*([^;}{]+)/gi)]
        .flatMap((m) => m[1]!.split(','))
        .map((f) => f.trim().replace(/^["']|["']$/g, ''))
        .filter((f) => f && !/^(sans-serif|serif|monospace|inherit|initial|system-ui|-apple-system)$/i.test(f)),
    ),
  ].slice(0, 6);

  let logo: string | undefined;
  for (const imgTag of rawHtml.match(/<img\b[^>]*>/gi) ?? []) {
    const attrs = parseTagAttrs(imgTag);
    const hay = `${attrs.alt ?? ''} ${attrs.class ?? ''} ${attrs.id ?? ''} ${attrs.src ?? ''}`.toLowerCase();
    if (hay.includes('logo')) {
      logo = resolveHttpsHref(attrs.src ?? attrs['data-src'], baseUrl);
      if (logo) break;
    }
  }

  // Strip comments and non-content elements.
  let work = rawHtml
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|noscript|template|svg|canvas|iframe)\b[^>]*>[\s\S]*?<\/\1>/gi, '');

  if (onlyMainContent) {
    work = work.replace(/<(nav|footer|aside)\b[^>]*>[\s\S]*?<\/\1>/gi, '');
    const mainMatch = /<main\b[^>]*>([\s\S]*?)<\/main>/i.exec(work) ?? /<article\b[^>]*>([\s\S]*?)<\/article>/i.exec(work);
    if (mainMatch && mainMatch[1]!.trim().length >= 32) {
      work = mainMatch[1]!;
    } else {
      work = work.replace(/<header\b[^>]*>[\s\S]*?<\/header>/gi, '');
    }
  }

  const links: string[] = [];
  const seenLinks = new Set<string>();
  for (const m of work.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)) {
    const attrs = parseTagAttrs(m[1]!);
    const resolved = resolveHttpsHref(attrs.href, baseUrl);
    if (resolved && !seenLinks.has(resolved)) {
      seenLinks.add(resolved);
      links.push(resolved);
      if (links.length >= 250) break;
    }
  }

  const images: ScrapedImage[] = [];
  const seenImages = new Set<string>();
  for (const m of work.matchAll(/<img\b([^>]*)>/gi)) {
    const attrs = parseTagAttrs(m[1]!);
    const src = resolveHttpsHref(attrs.src ?? attrs['data-src'], baseUrl);
    if (src && !seenImages.has(src)) {
      seenImages.add(src);
      const alt = attrs.alt?.trim();
      images.push({ url: src, ...(alt ? { alt } : {}) });
      if (images.length >= 60) break;
    }
  }

  // Convert structural HTML to Markdown.
  let md = work
    .replace(/<pre\b[^>]*>\s*(?:<code\b[^>]*>)?([\s\S]*?)(?:<\/code>)?\s*<\/pre>/gi, (_m, code) => {
      return `\n\n\`\`\`\n${decodeHtmlEntities(String(code).replace(/<[^>]+>/g, '')).trim()}\n\`\`\`\n\n`;
    })
    .replace(/<code\b[^>]*>([\s\S]*?)<\/code>/gi, (_m, c) => `\`${cleanInlineHtml(String(c))}\``)
    .replace(/<table\b[^>]*>([\s\S]*?)<\/table>/gi, (_m, tbl) => {
      const rows = [...String(tbl).matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)].map((rm) =>
        [...rm[1]!.matchAll(/<t[hd]\b[^>]*>([\s\S]*?)<\/t[hd]>/gi)].map((cm) => cleanInlineHtml(cm[1]!).replace(/\|/g, '\\|')),
      );
      const nonEmpty = rows.filter((r) => r.length > 0);
      if (nonEmpty.length === 0) return '';
      const cols = Math.max(...nonEmpty.map((r) => r.length));
      const pad = (r: string[]) => Array.from({ length: cols }, (_, i) => r[i] ?? '');
      const header = `| ${pad(nonEmpty[0]!).join(' | ')} |`;
      const sep = `| ${Array.from({ length: cols }, () => '---').join(' | ')} |`;
      const bodyRows = nonEmpty.slice(1).map((r) => `| ${pad(r).join(' | ')} |`);
      return `\n\n${[header, sep, ...bodyRows].join('\n')}\n\n`;
    })
    .replace(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi, (_m, lvl, inner) => {
      const txt = cleanInlineHtml(String(inner));
      return txt ? `\n\n${'#'.repeat(Number(lvl))} ${txt}\n\n` : '';
    })
    .replace(/<blockquote\b[^>]*>([\s\S]*?)<\/blockquote>/gi, (_m, inner) => {
      const txt = cleanInlineHtml(String(inner));
      return txt ? `\n\n> ${txt}\n\n` : '';
    })
    .replace(/<li\b[^>]*>([\s\S]*?)<\/li>/gi, (_m, inner) => {
      const txt = cleanInlineHtml(String(inner));
      return txt ? `\n- ${txt}` : '';
    })
    .replace(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi, (_m, attrStr, inner) => {
      const attrs = parseTagAttrs(String(attrStr));
      const href = resolveHttpsHref(attrs.href, baseUrl);
      const label = cleanInlineHtml(String(inner));
      if (!label) return '';
      return href ? `[${label}](${href})` : label;
    })
    .replace(/<(strong|b)\b[^>]*>([\s\S]*?)<\/\1>/gi, (_m, _t, inner) => {
      const txt = cleanInlineHtml(String(inner));
      return txt ? `**${txt}**` : '';
    })
    .replace(/<(em|i)\b[^>]*>([\s\S]*?)<\/\1>/gi, (_m, _t, inner) => {
      const txt = cleanInlineHtml(String(inner));
      return txt ? `*${txt}*` : '';
    })
    .replace(/<(br|hr)\b[^>]*\/?>/gi, (_m, tag) => (String(tag).toLowerCase() === 'hr' ? '\n\n---\n\n' : '\n'))
    .replace(/<\/(p|div|section|article|main|ul|ol|dl|dd|dt|figure|figcaption|tr|header)>/gi, '\n\n')
    .replace(/<[^>]+>/g, '');

  md = decodeHtmlEntities(md)
    .split('\n')
    .map((line) => line.replace(/[ \t]{2,}/g, ' ').trimEnd())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  let plainText = cleanInlineHtml(work);
  if (redactPii) {
    md = redactPiiText(md);
    plainText = redactPiiText(plainText);
  }

  return {
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    ...(language ? { language } : {}),
    ...(canonicalUrl ? { canonicalUrl } : {}),
    ...(favicon ? { favicon } : {}),
    markdown: md,
    text: plainText,
    links,
    images,
    branding: {
      ...(title ? { title } : {}),
      ...(description ? { description } : {}),
      ...(canonicalUrl ? { canonicalUrl } : {}),
      ...(favicon ? { favicon } : {}),
      ...(logo ? { logo } : {}),
      ...(ogImage ? { ogImage } : {}),
      ...(themeColor ? { themeColor } : {}),
      ...(colors.length > 0 ? { colors } : {}),
      ...(fonts.length > 0 ? { fonts } : {}),
    },
  };
}

/** Parses `/llms.txt` Markdown index files per https://llmstxt.org/, rejecting HTML 200 soft-404 pages. */
export function parseLlmsTxt(raw: string, sourceUrl: string): ParsedLlmsTxt | null {
  const trimmed = raw.trim();
  if (trimmed.length < 8) return null;
  const prefix = trimmed.slice(0, 256).toLowerCase();
  if (prefix.startsWith('<!doctype') || prefix.startsWith('<html') || prefix.includes('<body')) {
    return null;
  }

  let title: string | undefined;
  const summaryLines: string[] = [];
  let section: string | undefined;
  let fullTxtUrl: string | undefined;
  const links: LlmsLinkItem[] = [];
  const itemRe = /^[-*]\s+\[([^\]]+)\]\(([^)]+)\)(?:\s*:\s*(.*))?$/;

  for (const rawLine of trimmed.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('# ') && !title) {
      title = line.slice(2).trim();
      continue;
    }
    if (line.startsWith('## ')) {
      section = line.slice(3).trim();
      continue;
    }
    if (line.startsWith('>') && !section && summaryLines.length < 4) {
      summaryLines.push(line.replace(/^>+\s*/, '').trim());
      continue;
    }
    const m = itemRe.exec(line);
    if (m) {
      const resolved = resolveHttpsHref(m[2], sourceUrl);
      if (!resolved) continue;
      if (resolved.toLowerCase().endsWith('/llms-full.txt') && !fullTxtUrl) {
        fullTxtUrl = resolved;
      }
      if (links.length < 500) {
        links.push({
          ...(section ? { section } : {}),
          title: m[1]!.trim(),
          url: resolved,
          ...(m[3]?.trim() ? { notes: m[3].trim() } : {}),
        });
      }
    }
  }

  const summary = summaryLines.join(' ').trim() || undefined;
  if (!title && !summary && links.length === 0) return null;
  return {
    sourceUrl,
    ...(title ? { title } : {}),
    ...(summary ? { summary } : {}),
    ...(fullTxtUrl ? { fullTxtUrl } : {}),
    links,
  };
}

/**
 * Deterministic schema-guided structured JSON extractor (`formats: [{ type: 'json', schema }]`).
 * Inspects JSON-LD (`application/ld+json`), meta tags, and Markdown key/value lines without calling external LLMs.
 */
export function extractStructuredJsonFromPage(
  rawHtml: string,
  doc: ExtractedDocument,
  schema?: Record<string, unknown>,
): Record<string, unknown> {
  const jsonLdObjects: Array<Record<string, unknown>> = [];
  for (const m of rawHtml.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      const parsed = JSON.parse(m[1]!.trim()) as unknown;
      if (Array.isArray(parsed)) {
        for (const item of parsed) if (item && typeof item === 'object') jsonLdObjects.push(item as Record<string, unknown>);
      } else if (parsed && typeof parsed === 'object') {
        jsonLdObjects.push(parsed as Record<string, unknown>);
      }
    } catch {
      // ignore malformed JSON-LD blocks
    }
  }

  const props = (schema?.properties ?? undefined) as Record<string, { type?: string }> | undefined;
  if (!props || typeof props !== 'object') {
    return {
      ...(doc.title ? { title: doc.title } : {}),
      ...(doc.description ? { description: doc.description } : {}),
      ...(jsonLdObjects.length > 0 ? { jsonLd: jsonLdObjects } : {}),
    };
  }

  const out: Record<string, unknown> = {};
  for (const [propName, propSpec] of Object.entries(props)) {
    const lowerProp = propName.toLowerCase();
    let val: unknown;

    for (const ld of jsonLdObjects) {
      for (const [k, v] of Object.entries(ld)) {
        if (k.toLowerCase() === lowerProp && v !== undefined && v !== null) {
          val = v;
          break;
        }
      }
      if (val !== undefined) break;
    }

    if (val === undefined) {
      if (lowerProp === 'title' || lowerProp === 'name' || lowerProp === 'headline') val = doc.title;
      else if (lowerProp === 'description' || lowerProp === 'summary') val = doc.description;
      else if (lowerProp === 'url' || lowerProp === 'canonicalurl') val = doc.canonicalUrl;
      else if (lowerProp === 'links') val = doc.links;
      else if (lowerProp === 'images') val = doc.images.map((i) => i.url);
      else {
        const escaped = propName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const kvRe = new RegExp(`(?:^|\\n)\\s*(?:[-*]\\s*)?\\*{0,2}${escaped}\\*{0,2}\\s*:\\s*([^\\n]+)`, 'i');
        const m = kvRe.exec(doc.markdown);
        if (m?.[1]) val = m[1].trim();
      }
    }

    if (val !== undefined) {
      if (propSpec?.type === 'number' && typeof val === 'string') {
        const num = Number(val.replace(/[^0-9.-]/g, ''));
        if (Number.isFinite(num)) val = num;
      } else if (propSpec?.type === 'boolean' && typeof val === 'string') {
        val = /^(true|yes|1)$/i.test(val.trim());
      }
      out[propName] = val;
    }
  }
  return out;
}

export type DeriveDocumentResult =
  | {
      status: 'derived' | 'cached';
      documentId: string;
      contentSha256: string;
      pipelineVersion: number;
      r2Key: string;
      bytes: number;
      title?: string;
      language?: string;
    }
  | {
      status: 'unverified' | 'expired' | 'unsupported';
      contentSha256: string;
    };

/**
 * Derives clean Markdown from a VERIFIED stored R2 artifact (`isContentVerifiedInMetaD1 === true`), writes the derived
 * Markdown to `derived/<pipelineVersion>/markdown/<contentSha256>` in `ARTIFACTS` R2, and upserts `META` D1 `documents`.
 */
export async function deriveMarkdownDocument(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  blobSha256: string;
  contentSha256: string;
  contentType?: string;
  baseUrl?: string;
  pipelineVersion?: number;
  now?: number;
}): Promise<DeriveDocumentResult> {
  const {
    bucket,
    metaDb,
    blobSha256,
    contentSha256,
    contentType = 'text/html',
    baseUrl,
    pipelineVersion = SCRAPE_PIPELINE_VERSION,
    now = Date.now(),
  } = params;

  if (!isValidSha256Hex(contentSha256) || !isValidSha256Hex(blobSha256)) {
    return { status: 'unverified', contentSha256 };
  }

  // SECURITY GATE: Never derive or index unverified agent claims.
  const verified = await isContentVerifiedInMetaD1(metaDb, contentSha256);
  if (!verified) {
    return { status: 'unverified', contentSha256 };
  }

  const ctLower = contentType.toLowerCase();
  if (
    ctLower &&
    !ctLower.includes('html') &&
    !ctLower.includes('markdown') &&
    !ctLower.includes('text/plain') &&
    !ctLower.includes('xml') &&
    !ctLower.includes('json')
  ) {
    return { status: 'unsupported', contentSha256 };
  }

  const r2Key = r2DerivedKey(pipelineVersion, 'markdown', contentSha256);
  const docId = `doc_${(await sha256HexString(`${contentSha256}:markdown:${pipelineVersion}`)).slice(0, 32)}`;

  const existingDoc = await metaDb
    .prepare(
      `SELECT id, r2_key, bytes, title, language
       FROM documents
       WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version = ?
       LIMIT 1`,
    )
    .bind(contentSha256, pipelineVersion)
    .first<{ id: string; r2_key: string; bytes: number; title: string | null; language: string | null }>();

  if (existingDoc && (await bucket.head(existingDoc.r2_key)) !== null) {
    return {
      status: 'cached',
      documentId: existingDoc.id,
      contentSha256,
      pipelineVersion,
      r2Key: existingDoc.r2_key,
      bytes: existingDoc.bytes,
      ...(existingDoc.title ? { title: existingDoc.title } : {}),
      ...(existingDoc.language ? { language: existingDoc.language } : {}),
    };
  }

  const loaded = await readVerifiedArtifactFromR2({
    bucket,
    blobSha256,
    preferredRetention: 'stored',
    expectedContentSha256: contentSha256,
  });
  if (!loaded.ok) {
    return { status: 'expired', contentSha256 };
  }

  const rawText = new TextDecoder('utf-8', { fatal: false }).decode(loaded.bytes);
  let markdown: string;
  let title: string | undefined;
  let language: string | undefined;

  if (ctLower.includes('html') || /^\s*<!doctype\s+html|^\s*<html/i.test(rawText)) {
    const extracted = extractHtmlDocument(rawText, { baseUrl, onlyMainContent: true });
    markdown = extracted.markdown;
    title = extracted.title;
    language = extracted.language;
  } else {
    markdown = rawText.trim();
  }

  const mdBytes = new TextEncoder().encode(markdown);
  await bucket.put(r2Key, mdBytes, {
    httpMetadata: { contentType: 'text/markdown; charset=utf-8' },
    customMetadata: {
      contentSha256,
      pipelineVersion: String(pipelineVersion),
      ...(title ? { title: title.slice(0, 200) } : {}),
    },
  });

  await metaDb
    .prepare(
      `INSERT INTO documents (id, content_sha256, format, pipeline_version, r2_key, title, language, bytes, created_at)
       VALUES (?, ?, 'markdown', ?, ?, ?, ?, ?, ?)
       ON CONFLICT(content_sha256, format, pipeline_version) DO UPDATE SET
         r2_key = excluded.r2_key,
         title = COALESCE(excluded.title, documents.title),
         language = COALESCE(excluded.language, documents.language),
         bytes = excluded.bytes`,
    )
    .bind(docId, contentSha256, pipelineVersion, r2Key, title ?? null, language ?? null, mdBytes.byteLength, now)
    .run();

  return {
    status: 'derived',
    documentId: docId,
    contentSha256,
    pipelineVersion,
    r2Key,
    bytes: mdBytes.byteLength,
    ...(title ? { title } : {}),
    ...(language ? { language } : {}),
  };
}

export async function lookupCachedScrape(params: {
  bucket: R2Bucket;
  metaDb: D1Database;
  url: string;
  maxAgeMs: number;
  pipelineVersion?: number;
  now?: number;
}): Promise<{
  markdown: string;
  contentSha256: string;
  documentId: string;
  pipelineVersion: number;
  title?: string;
  language?: string;
  status: number;
  lastFetchedAt: number;
} | null> {
  const { bucket, metaDb, url, maxAgeMs, pipelineVersion = SCRAPE_PIPELINE_VERSION, now = Date.now() } = params;
  if (!(maxAgeMs > 0)) return null;

  const pageRow = await metaDb
    .prepare(
      `SELECT latest_status, latest_outcome, latest_content_sha256, last_fetched_at
       FROM pages
       WHERE url = ?
       LIMIT 1`,
    )
    .bind(url)
    .first<{
      latest_status: number | null;
      latest_outcome: string | null;
      latest_content_sha256: string | null;
      last_fetched_at: number | null;
    }>();

  if (
    !pageRow ||
    pageRow.latest_outcome !== 'ok' ||
    !pageRow.latest_content_sha256 ||
    !pageRow.last_fetched_at ||
    now - pageRow.last_fetched_at > maxAgeMs
  ) {
    return null;
  }

  if (!(await isContentVerifiedInMetaD1(metaDb, pageRow.latest_content_sha256))) {
    return null;
  }

  const docRow = await metaDb
    .prepare(
      `SELECT id, r2_key, title, language
       FROM documents
       WHERE content_sha256 = ? AND format = 'markdown' AND pipeline_version = ?
       LIMIT 1`,
    )
    .bind(pageRow.latest_content_sha256, pipelineVersion)
    .first<{ id: string; r2_key: string; title: string | null; language: string | null }>();

  if (!docRow) return null;
  const obj = await bucket.get(docRow.r2_key);
  if (!obj) return null;
  const markdown = await obj.text();

  return {
    markdown,
    contentSha256: pageRow.latest_content_sha256,
    documentId: docRow.id,
    pipelineVersion,
    ...(docRow.title ? { title: docRow.title } : {}),
    ...(docRow.language ? { language: docRow.language } : {}),
    status: pageRow.latest_status ?? 200,
    lastFetchedAt: pageRow.last_fetched_at,
  };
}

export type ScrapeFormatInput =
  | 'markdown'
  | 'text'
  | 'html'
  | 'rawHtml'
  | 'links'
  | 'images'
  | 'branding'
  | 'llmsTxt'
  | { type: 'json'; schema?: Record<string, unknown> };

export interface ScrapeRequestPayload {
  url?: unknown;
  formats?: unknown;
  onlyMainContent?: unknown;
  maxAgeMs?: unknown;
  discoverLlmsTxt?: unknown;
  redactPii?: unknown;
  query?: unknown;
  headers?: unknown;
  renderMode?: unknown;
  waitForMs?: unknown;
  waitSelector?: unknown;
  maxPages?: unknown;
  collectionId?: unknown;
  target?: unknown;
  site?: unknown;
}

export async function executeScrapeCall(params: {
  payload: ScrapeRequestPayload;
  env: OptionalStorageBindings;
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: ArtifactRetention | 'off',
    hydrateInline?: boolean,
    collectionId?: string,
  ) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;
  source?: string;
  now?: number;
}): Promise<{ status: number; body: Record<string, unknown>; via: string; retryAfter?: string }> {
  const { payload, env, executeHubFetch, source = 'scrape', now = Date.now() } = params;
  const rawUrl = typeof payload.url === 'string' ? payload.url.trim() : '';
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: 'url must be a valid https:// URL' } };
  }
  if (parsedUrl.protocol !== 'https:' || (parsedUrl.port && parsedUrl.port !== '443') || parsedUrl.username || parsedUrl.password) {
    return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: 'only public https:// URLs on port 443 are permitted' } };
  }
  const normalizedUrl = parsedUrl.toString();

  const rawFormats = Array.isArray(payload.formats) && payload.formats.length > 0 ? payload.formats : ['markdown'];
  const stringFormats = new Set<string>();
  let jsonSchemaSpec: { schema?: Record<string, unknown> } | undefined;
  for (const f of rawFormats) {
    if (typeof f === 'string') {
      stringFormats.add(f);
    } else if (f && typeof f === 'object' && (f as { type?: unknown }).type === 'json') {
      jsonSchemaSpec = { schema: (f as { schema?: Record<string, unknown> }).schema };
    }
  }
  if (stringFormats.size === 0 && !jsonSchemaSpec) {
    stringFormats.add('markdown');
  }

  const onlyMainContent = typeof payload.onlyMainContent === 'boolean' ? payload.onlyMainContent : true;
  const discoverLlmsTxt = typeof payload.discoverLlmsTxt === 'boolean' ? payload.discoverLlmsTxt : true;
  const redactPii = Boolean(payload.redactPii);
  const maxAgeMs = typeof payload.maxAgeMs === 'number' && Number.isFinite(payload.maxAgeMs) ? Math.max(0, Math.floor(payload.maxAgeMs)) : 0;
  const target: 'auto' | 'agent' | 'container' =
    payload.target === 'agent' || payload.target === 'container' ? payload.target : 'auto';
  const site = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim() : undefined;

  // Serve from verified META D1 + ARTIFACTS R2 cache when maxAgeMs is satisfied and only markdown/metadata are requested.
  const needsLiveHtml =
    stringFormats.has('html') ||
    stringFormats.has('rawHtml') ||
    stringFormats.has('links') ||
    stringFormats.has('images') ||
    stringFormats.has('branding') ||
    stringFormats.has('changes') ||
    Boolean(jsonSchemaSpec);

  let prevMarkdownForChanges: string | null = null;
  if (stringFormats.has('changes') && env.ARTIFACTS && env.META) {
    const prevHit = await lookupCachedScrape({
      bucket: env.ARTIFACTS,
      metaDb: env.META,
      url: normalizedUrl,
      maxAgeMs: 365 * 24 * 60 * 60_000,
      pipelineVersion: SCRAPE_PIPELINE_VERSION,
      now,
    });
    if (prevHit) {
      prevMarkdownForChanges = prevHit.markdown;
    }
  }

  if (!needsLiveHtml && maxAgeMs > 0 && env.ARTIFACTS && env.META) {
    const hit = await lookupCachedScrape({
      bucket: env.ARTIFACTS,
      metaDb: env.META,
      url: normalizedUrl,
      maxAgeMs,
      pipelineVersion: SCRAPE_PIPELINE_VERSION,
      now,
    });
    if (hit) {
      return {
        status: 200,
        via: 'cache:r2-d1',
        body: {
          ok: true,
          cached: true,
          pipelineVersion: hit.pipelineVersion,
          documentId: hit.documentId,
          contentSha256: hit.contentSha256,
          url: normalizedUrl,
          status: hit.status,
          markdown: redactPii ? redactPiiText(hit.markdown) : hit.markdown,
          metadata: {
            ...(hit.title ? { title: hit.title } : {}),
            ...(hit.language ? { language: hit.language } : {}),
            lastFetchedAt: hit.lastFetchedAt,
          },
        },
      };
    }
  }

  const agentFormats = [...stringFormats].filter((f) =>
    ['markdown', 'text', 'html', 'rawHtml', 'links', 'images', 'branding', 'screenshot'].includes(f),
  );
  if (agentFormats.length === 0) agentFormats.push('markdown');

  const renderMode =
    payload.renderMode === 'always' || payload.renderMode === 'auto' || payload.renderMode === 'off'
      ? payload.renderMode
      : stringFormats.has('screenshot')
        ? 'always'
        : undefined;

  const fetchCall = {
    maxSeconds: 45,
    options: {
      includeBody: true,
      respectRobots: true,
      discoverLlms: discoverLlmsTxt || stringFormats.has('llmsTxt'),
    },
    requests: [
      {
        id: 'scrape-1',
        url: normalizedUrl,
        kind: renderMode === 'always' ? 'render' : 'scrape',
        formats: agentFormats,
        onlyMainContent,
        discoverLlms: discoverLlmsTxt || stringFormats.has('llmsTxt'),
        redactPii,
        ...(renderMode ? { renderMode } : {}),
        ...(typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
          ? { waitForMs: Math.min(15_000, Math.max(0, Math.floor(payload.waitForMs))) }
          : {}),
        ...(typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
          ? { waitSelector: payload.waitSelector.trim().slice(0, 200) }
          : {}),
        ...(typeof payload.maxPages === 'number' && Number.isFinite(payload.maxPages)
          ? { maxPages: Math.min(500, Math.max(1, Math.floor(payload.maxPages))) }
          : {}),
        ...(typeof payload.query === 'string' && payload.query.trim() ? { query: payload.query.trim() } : {}),
        ...(payload.headers && typeof payload.headers === 'object' ? { headers: payload.headers } : {}),
      },
    ],
  };

  const collectionId =
    typeof payload.collectionId === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(payload.collectionId.trim())
      ? payload.collectionId.trim()
      : undefined;
  const retentionMode: ArtifactRetention | undefined = env.ARTIFACTS && env.META ? 'stored' : env.ARTIFACTS ? 'transient' : undefined;
  const fetchRes = await executeHubFetch(target, JSON.stringify(fetchCall), site, source, retentionMode, true, collectionId);
  if (fetchRes.status !== 200) {
    let errJson: Record<string, unknown> = { ok: false, error: 'scrape_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    return {
      status: fetchRes.status,
      via: fetchRes.via,
      body: errJson,
      ...(fetchRes.retryAfter ? { retryAfter: fetchRes.retryAfter } : {}),
    };
  }

  const parsedReply = JSON.parse(fetchRes.bodyText) as {
    results?: Array<Record<string, unknown>>;
  };
  const item = parsedReply.results?.[0] ?? {};
  if (item.outcome !== 'ok') {
    return {
      status: item.status === 429 ? 429 : 422,
      via: fetchRes.via,
      body: {
        ok: false,
        url: normalizedUrl,
        outcome: item.outcome ?? 'error',
        status: item.status ?? 0,
        problem: item.problem ?? 'Origin scrape did not return HTTP 2xx',
      },
    };
  }

  const rawBodyStr = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
  const finalUrl = typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : normalizedUrl;
  const extracted = rawBodyStr
    ? extractHtmlDocument(rawBodyStr, { baseUrl: finalUrl, onlyMainContent, redactPii })
    : undefined;

  const markdown =
    (typeof item.markdown === 'string' && item.markdown) ||
    extracted?.markdown ||
    rawBodyStr;
  const textOut =
    (typeof item.text === 'string' && item.text) ||
    extracted?.text ||
    '';

  const art = item.artifact as { blobSha256?: string; contentSha256?: string } | undefined;
  const out: Record<string, unknown> = {
    ok: true,
    cached: false,
    pipelineVersion: SCRAPE_PIPELINE_VERSION,
    url: normalizedUrl,
    finalUrl,
    status: item.status ?? 200,
    via: fetchRes.via,
    ...(art?.contentSha256 ? { contentSha256: art.contentSha256 } : {}),
    ...(art?.blobSha256 ? { artifactId: art.blobSha256 } : {}),
    ...(stringFormats.has('markdown') ? { markdown } : {}),
    ...(stringFormats.has('text') ? { text: textOut } : {}),
    ...(stringFormats.has('rawHtml') || stringFormats.has('html') ? { rawHtml: rawBodyStr, html: rawBodyStr } : {}),
    ...(stringFormats.has('links')
      ? { links: Array.isArray(item.links) ? item.links : (extracted?.links ?? []) }
      : {}),
    ...(stringFormats.has('images')
      ? { images: Array.isArray(item.images) ? item.images : (extracted?.images ?? []) }
      : {}),
    ...(stringFormats.has('branding')
      ? { branding: item.branding ?? extracted?.branding ?? {} }
      : {}),
    ...(jsonSchemaSpec && extracted
      ? { json: extractStructuredJsonFromPage(rawBodyStr, extracted, jsonSchemaSpec.schema) }
      : {}),
    ...(typeof item.screenshotBase64 === 'string' && item.screenshotBase64 ? { screenshotBase64: item.screenshotBase64 } : {}),
    ...(item.rendered === true ? { rendered: true } : {}),
    ...(typeof item.pdfEngine === 'string' ? { pdfEngine: item.pdfEngine } : {}),
    ...(stringFormats.has('changes') ? { changes: computeMarkdownChanges(prevMarkdownForChanges, markdown) } : {}),
    ...(item.llms ? { llms: item.llms } : {}),
    metadata: {
      title: (typeof item.title === 'string' && item.title) || extracted?.title,
      description: (typeof item.description === 'string' && item.description) || extracted?.description,
      language: extracted?.language,
      favicon: (typeof item.favicon === 'string' && item.favicon) || extracted?.favicon,
      canonicalUrl: extracted?.canonicalUrl,
      contentType: item.contentType,
    },
  };

  return { status: 200, via: fetchRes.via, body: out };
}

export interface InteractRequestPayload {
  url?: unknown;
  sessionId?: unknown;
  keepSession?: unknown;
  closeSession?: unknown;
  actions?: unknown;
  formats?: unknown;
  waitForMs?: unknown;
  waitSelector?: unknown;
  site?: unknown;
}

function splitCompositeSessionId(raw: unknown): { siteId?: string; agentSessionId?: string } {
  if (typeof raw !== 'string' || !raw.trim()) return {};
  const clean = raw.trim();
  const dot = clean.indexOf('.');
  if (dot > 0 && dot < clean.length - 1) {
    const sitePart = clean.slice(0, dot).toLowerCase();
    const sessPart = clean.slice(dot + 1);
    if (/^[a-z0-9][a-z0-9_-]{0,31}$/.test(sitePart) && /^[A-Za-z0-9_-]{4,80}$/.test(sessPart)) {
      return { siteId: sitePart, agentSessionId: sessPart };
    }
  }
  if (/^[A-Za-z0-9_-]{4,80}$/.test(clean)) {
    return { agentSessionId: clean };
  }
  return {};
}

/**
 * Executes `POST /v1/interact` + MCP `interact` (`firecrawl_interact` parity) against a `browser-v1` (`edgefetch_fat`)
 * node. Composite `<siteId>.<efsess_id>` tokens ensure follow-up turns route back to the exact node holding the tab.
 */
export async function executeInteractCall(params: {
  payload: InteractRequestPayload;
  env: OptionalStorageBindings;
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: ArtifactRetention | 'off',
    hydrateInline?: boolean,
  ) => Promise<{ status: number; via: string; bodyText: string; retryAfter?: string }>;
  source?: string;
}): Promise<{ status: number; via: string; body: Record<string, unknown> }> {
  const { payload, env, executeHubFetch, source = 'interact' } = params;
  const parsedSession = splitCompositeSessionId(payload.sessionId);
  const rawUrl = typeof payload.url === 'string' ? payload.url.trim() : '';

  let normalizedUrl = '';
  if (rawUrl) {
    let u: URL;
    try {
      u = new URL(rawUrl);
    } catch {
      return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: 'url must be a valid https:// URL' } };
    }
    if (u.protocol !== 'https:' || (u.port && u.port !== '443') || u.username || u.password) {
      return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: 'only https:// URLs on port 443 are permitted' } };
    }
    normalizedUrl = u.toString();
  } else if (!parsedSession.agentSessionId) {
    return {
      status: 400,
      via: 'hub',
      body: { ok: false, error: 'missing_url_or_session', message: 'provide url (new session) or sessionId (resume/close session)' },
    };
  }

  const actions: Array<Record<string, unknown>> = [];
  if (Array.isArray(payload.actions)) {
    if (payload.actions.length > 25) {
      return { status: 400, via: 'hub', body: { ok: false, error: 'too_many_actions', message: 'maximum 25 actions per interact turn' } };
    }
    for (const rawAct of payload.actions) {
      if (!rawAct || typeof rawAct !== 'object') continue;
      const a = rawAct as Record<string, unknown>;
      const type = typeof a.type === 'string' ? a.type.trim().toLowerCase() : '';
      if (!['click', 'fill', 'type', 'press', 'wait', 'scroll', 'select', 'navigate'].includes(type)) {
        return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_action', message: `unsupported action type: ${String(a.type)}` } };
      }
      if (type === 'navigate') {
        let nu: URL;
        try {
          nu = new URL(typeof a.url === 'string' ? a.url.trim() : '');
        } catch {
          return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: 'navigate action requires a valid https:// URL' } };
        }
        if (nu.protocol !== 'https:' || (nu.port && nu.port !== '443') || nu.username || nu.password) {
          return { status: 400, via: 'hub', body: { ok: false, error: 'invalid_url', message: 'navigate action only permits https:// on port 443' } };
        }
      }
      actions.push({
        type,
        ...(typeof a.selector === 'string' ? { selector: a.selector.slice(0, 240) } : {}),
        ...(typeof a.value === 'string' ? { value: a.value.slice(0, 4096) } : {}),
        ...(typeof a.key === 'string' ? { key: a.key.slice(0, 40) } : {}),
        ...(typeof a.url === 'string' ? { url: a.url.trim() } : {}),
        ...(typeof a.waitMs === 'number' && Number.isFinite(a.waitMs)
          ? { waitMs: Math.min(15_000, Math.max(0, Math.floor(a.waitMs))) }
          : {}),
      });
    }
  }

  const formats = Array.isArray(payload.formats)
    ? payload.formats.filter((f): f is string => typeof f === 'string')
    : ['markdown'];
  const keepSession = Boolean(payload.keepSession);
  const closeSession = Boolean(payload.closeSession);
  const explicitSite = typeof payload.site === 'string' && payload.site.trim() ? payload.site.trim().toLowerCase() : undefined;
  const pinnedSite = parsedSession.siteId ?? explicitSite;

  const call = {
    maxSeconds: 60,
    options: {
      includeBody: true,
      respectRobots: true,
    },
    requests: [
      {
        id: 'interact-1',
        url: normalizedUrl,
        kind: 'render',
        renderMode: 'always',
        formats: formats.length > 0 ? formats : ['markdown'],
        ...(typeof payload.waitForMs === 'number' && Number.isFinite(payload.waitForMs)
          ? { waitForMs: Math.min(15_000, Math.max(0, Math.floor(payload.waitForMs))) }
          : {}),
        ...(typeof payload.waitSelector === 'string' && payload.waitSelector.trim()
          ? { waitSelector: payload.waitSelector.trim().slice(0, 200) }
          : {}),
        interact: {
          ...(parsedSession.agentSessionId ? { sessionId: parsedSession.agentSessionId } : {}),
          keepSession,
          closeSession,
          actions,
        },
      },
    ],
  };

  const fetchRes = await executeHubFetch('agent', JSON.stringify(call), pinnedSite, source, env.ARTIFACTS ? 'transient' : undefined, true);
  if (fetchRes.status !== 200) {
    let errJson: Record<string, unknown> = { ok: false, error: 'interact_failed' };
    try {
      errJson = { ok: false, ...(JSON.parse(fetchRes.bodyText) as Record<string, unknown>) };
    } catch {
      // ignore
    }
    return { status: fetchRes.status, via: fetchRes.via, body: errJson };
  }

  const parsed = JSON.parse(fetchRes.bodyText) as { results?: Array<Record<string, unknown>> };
  const item = parsed.results?.[0] ?? {};
  if (item.outcome !== 'ok') {
    return {
      status: item.outcome === 'challenge' ? 403 : 422,
      via: fetchRes.via,
      body: {
        ok: false,
        outcome: item.outcome ?? 'error',
        status: item.status ?? 0,
        problem: item.problem ?? 'Browser interact step failed',
      },
    };
  }

  const siteMatch = /^agent:([a-z0-9_-]+)/i.exec(fetchRes.via);
  const actualSite = siteMatch?.[1] ?? pinnedSite;
  const returnedAgentSid = typeof item.sessionId === 'string' && item.sessionId ? item.sessionId : undefined;
  const publicSessionId = returnedAgentSid && actualSite ? `${actualSite}.${returnedAgentSid}` : returnedAgentSid;

  const rawHtml = typeof item.body === 'string' && item.bodyEncoding !== 'base64' ? item.body : '';
  const finalUrl = typeof item.finalUrl === 'string' && item.finalUrl ? item.finalUrl : normalizedUrl;
  const extracted = rawHtml ? extractHtmlDocument(rawHtml, { baseUrl: finalUrl || undefined, onlyMainContent: true }) : undefined;
  const markdown = (typeof item.markdown === 'string' && item.markdown) || extracted?.markdown || '';

  return {
    status: 200,
    via: fetchRes.via,
    body: {
      ok: true,
      via: fetchRes.via,
      ...(finalUrl ? { finalUrl } : {}),
      status: item.status ?? 200,
      rendered: true,
      ...(publicSessionId ? { sessionId: publicSessionId } : {}),
      ...(closeSession ? { closed: true } : {}),
      ...(formats.includes('markdown') ? { markdown } : {}),
      ...(formats.includes('html') || formats.includes('rawHtml') ? { html: rawHtml } : {}),
      ...(typeof item.screenshotBase64 === 'string' && item.screenshotBase64 ? { screenshotBase64: item.screenshotBase64 } : {}),
      metadata: {
        title: (typeof item.title === 'string' && item.title) || extracted?.title,
      },
    },
  };
}
