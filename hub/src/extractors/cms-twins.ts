/**
 * Tier 1 Universal CMS & Static-Site Auto-Twins (`hub/src/extractors/cms-twins.ts`).
 *
 * Politely upgrades thin or cluttered CMS/SSG HTML pages to their canonical same-origin JSON endpoints
 * (enforcing `https://` port 443, SSRF-safe public hostname check, `respectRobots: true`, and strict
 * same-host redirect verification):
 *  1. WordPress REST API (`wordpress-rest`): discovers `<link rel="alternate" type="application/json" href="https://<host>/wp-json/wp/v2/(posts|pages)/<id>">` in `<head>`.
 *  2. Gatsby Page-Data (`gatsby-page-data`): probes `https://<host>/page-data/<pathname>/page-data.json` on thin Gatsby shells (`id="___gatsby"`).
 */

import { validatePublicHttpsTargetUrl } from '../overflow';
import { scanHtmlTagsLinear } from '../safe-input';
import { extractFromParsedStateTree } from './framework-hydration';
import {
  sanitizeSchemaPlainField,
  sanitizeSchemaRichMarkdown,
} from './schema-org';
import type { HtmlFragmentConverter } from './types';
import { decodeBasicEntities, hasRawOrEncodedUnicodeTagLinear } from './utils';

export interface CmsAutoTwinResult {
  extractorId: 'wordpress-rest' | 'gatsby-page-data';
  twinUrl: string;
  title?: string;
  description?: string;
  publishedTime?: string;
  modifiedTime?: string;
  markdown: string;
  structured?: Record<string, unknown>;
  records?: Array<Record<string, unknown>>;
  returned?: number;
  total?: number;
  truncated?: boolean;
  nextCursor?: string;
  rawDecodedStringsForPiCheck: string;
}

function parseLinkAttrsLinear(attrChunk: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)[ \t\r\n]*(?:=[ \t\r\n]*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrChunk)) !== null) {
    attrs[m[1]!.toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return attrs;
}

/**
 * Linearly scans `<head>` (`<= 64 KiB`) for WordPress's canonical per-post/page REST JSON `<link rel="alternate" type="application/json">` tag.
 * Enforces exact same-origin `https://` match and `/wp-json/wp/v2/(posts|pages)/<digits>` path format.
 */
export function discoverWordPressRestTwinUrlLinear(
  rawHtml: string,
  pageFinalUrl: string,
  selfHost?: string,
): string | null {
  if (!rawHtml || !rawHtml.includes('wp-json/wp/v2/')) return null;
  let base: URL;
  try {
    base = new URL(pageFinalUrl);
    if (base.protocol !== 'https:' || base.username || base.password) return null;
  } catch {
    return null;
  }
  const baseHost = base.hostname.toLowerCase().replace(/\.+$/, '');
  let matchedUrl: string | null = null;

  scanHtmlTagsLinear(
    rawHtml.slice(0, 96_000),
    (tag) => {
      if (tag.isClosing || tag.tagNameLower !== 'link') return undefined;
      const attrs = parseLinkAttrsLinear(tag.attrs);
      const relTokens = (attrs.rel ?? '').toLowerCase().split(/\s+/);
      const mime = (attrs.type ?? '').toLowerCase().split(';')[0]?.trim();
      const rawHref = (attrs.href ?? '').replace(/&(?:amp|#0*38|#x0*26);/gi, '&').trim();
      if (!relTokens.includes('alternate') || mime !== 'application/json' || !rawHref) return undefined;

      try {
        const cand = new URL(rawHref, base.toString());
        if (cand.protocol !== 'https:' || cand.username || cand.password || cand.hash) return undefined;
        if (cand.port && cand.port !== '443') return undefined;
        if (cand.hostname.toLowerCase().replace(/\.+$/, '') !== baseHost) return undefined;
        if (!/^\/wp-json\/wp\/v2\/(?:posts|pages)\/[1-9][0-9]{0,11}\/?$/.test(cand.pathname)) return undefined;
        cand.search = '';
        const checked = validatePublicHttpsTargetUrl(cand.toString(), selfHost);
        if (!checked.ok) return undefined;
        matchedUrl = checked.url.toString();
        return false;
      } catch {
        return undefined;
      }
    },
    96_000,
    false,
  );

  return matchedUrl;
}

/**
 * Builds Gatsby's static `/page-data/<pathname>/page-data.json` URL for thin `id="___gatsby"` shells.
 */
export function resolveGatsbyPageDataTwinUrl(
  rawHtml: string,
  pageFinalUrl: string,
  selfHost?: string,
): string | null {
  if (!rawHtml || !rawHtml.includes('id="___gatsby"')) return null;
  try {
    const u = new URL(pageFinalUrl);
    if (u.protocol !== 'https:' || u.username || u.password || (u.port && u.port !== '443')) return null;
    if (u.pathname.startsWith('/page-data/')) return null;
    const rawSegs = u.pathname.split('/').filter(Boolean);
    if (rawSegs.length > 16) return null;
    for (const seg of rawSegs) {
      if (seg === '.' || seg === '..' || !/^[A-Za-z0-9._~-]+$/.test(seg) || seg.length > 120) {
        return null;
      }
    }
    const slugPath = rawSegs.length === 0 ? 'index' : rawSegs.join('/');
    const twin = new URL(`/page-data/${slugPath}/page-data.json`, u.origin);
    const checked = validatePublicHttpsTargetUrl(twin.toString(), selfHost);
    return checked.ok ? checked.url.toString() : null;
  } catch {
    return null;
  }
}

export function formatWordPressRestPostJson(
  rawJson: string,
  baseUrl: string,
  htmlToMd: HtmlFragmentConverter,
): Omit<CmsAutoTwinResult, 'extractorId' | 'twinUrl'> | null {
  if (!rawJson || rawJson.length > 4 * 1024 * 1024) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;

  const titleObj = obj.title && typeof obj.title === 'object' && !Array.isArray(obj.title) ? (obj.title as Record<string, unknown>) : null;
  const contentObj = obj.content && typeof obj.content === 'object' && !Array.isArray(obj.content) ? (obj.content as Record<string, unknown>) : null;
  const excerptObj = obj.excerpt && typeof obj.excerpt === 'object' && !Array.isArray(obj.excerpt) ? (obj.excerpt as Record<string, unknown>) : null;

  if (contentObj?.protected === true) return null;

  const rawTitleHtml = typeof titleObj?.rendered === 'string' ? titleObj.rendered : '';
  const rawContentHtml = typeof contentObj?.rendered === 'string' ? contentObj.rendered : '';
  const rawExcerptHtml = typeof excerptObj?.rendered === 'string' ? excerptObj.rendered : '';
  if (!rawContentHtml.trim()) return null;

  const title = sanitizeSchemaPlainField(rawTitleHtml, 350);
  const description = sanitizeSchemaPlainField(rawExcerptHtml, 1_000);
  const bodyMd = sanitizeSchemaRichMarkdown(rawContentHtml, baseUrl, htmlToMd, 128_000);
  const wordCount = (bodyMd.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
  if (wordCount < 25) return null;

  const publishedTime = sanitizeSchemaPlainField(obj.date_gmt ?? obj.date, 64) || undefined;
  const modifiedTime = sanitizeSchemaPlainField(obj.modified_gmt ?? obj.modified, 64) || undefined;
  const slug = sanitizeSchemaPlainField(obj.slug, 160) || undefined;
  const wpType = sanitizeSchemaPlainField(obj.type, 40) || 'post';

  const md = title && !bodyMd.startsWith('# ') ? `# ${title}\n\n${bodyMd}` : bodyMd;
  const wpHasUnicodeTag =
    hasRawOrEncodedUnicodeTagLinear(rawJson) ||
    hasRawOrEncodedUnicodeTagLinear(rawTitleHtml) ||
    hasRawOrEncodedUnicodeTagLinear(rawExcerptHtml) ||
    hasRawOrEncodedUnicodeTagLinear(rawContentHtml);
  const rawForPi = [
    ...[rawTitleHtml, rawExcerptHtml, rawContentHtml]
      .filter(Boolean)
      .map((s) => (s.includes('&') ? decodeBasicEntities(s) : s)),
    ...(wpHasUnicodeTag ? ['\u{E0069}'] : []),
  ]
    .join('\n')
    .slice(0, 1_572_864);

  return {
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    ...(publishedTime ? { publishedTime } : {}),
    ...(modifiedTime ? { modifiedTime } : {}),
    markdown: md,
    structured: {
      source: 'wordpress-rest',
      postType: wpType,
      ...(typeof obj.id === 'number' && Number.isFinite(obj.id) ? { id: obj.id } : {}),
      ...(slug ? { slug } : {}),
      ...(publishedTime ? { datePublished: publishedTime } : {}),
      ...(modifiedTime ? { dateModified: modifiedTime } : {}),
      wordCount,
    },
    rawDecodedStringsForPiCheck: rawForPi,
  };
}

export async function tryFetchCmsAutoTwin(params: {
  rawHtml: string;
  finalUrl: string;
  currentWordCount: number;
  selfHost?: string;
  htmlToMd: HtmlFragmentConverter;
  fetchSameOriginJson: (twinUrl: string, tag: string) => Promise<string>;
}): Promise<CmsAutoTwinResult | null> {
  const { rawHtml, finalUrl, currentWordCount, selfHost, htmlToMd, fetchSameOriginJson } = params;

  // 1. WordPress REST API (`<link rel="alternate" type="application/json" href=".../wp-json/wp/v2/(posts|pages)/<id>">`)
  if (currentWordCount < 120) {
    const wpUrl = discoverWordPressRestTwinUrlLinear(rawHtml, finalUrl, selfHost);
    if (wpUrl) {
      try {
        const rawJson = await fetchSameOriginJson(wpUrl, 'wp-rest-json');
        if (rawJson.trim()) {
          const formatted = formatWordPressRestPostJson(rawJson, finalUrl, htmlToMd);
          if (formatted) {
            const newWords = (formatted.markdown.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
            if (newWords > currentWordCount && newWords >= 30) {
              return {
                extractorId: 'wordpress-rest',
                twinUrl: wpUrl,
                ...formatted,
              };
            }
          }
        }
      } catch {
        // Gracefully keep HTML extraction when /wp-json is disallowed by robots.txt or disabled.
      }
    }
  }

  // 2. Gatsby Static `page-data.json` on thin `<div id="___gatsby">` shells (`< 60` words)
  if (currentWordCount < 60) {
    const gatsbyUrl = resolveGatsbyPageDataTwinUrl(rawHtml, finalUrl, selfHost);
    if (gatsbyUrl) {
      try {
        const rawJson = await fetchSameOriginJson(gatsbyUrl, 'gatsby-page-data');
        if (rawJson.trim() && rawJson.length <= 2 * 1024 * 1024) {
          const parsed = JSON.parse(rawJson) as { result?: unknown };
          const gatsbyHasUnicodeTag = hasRawOrEncodedUnicodeTagLinear(rawJson);
          const hydrated = extractFromParsedStateTree(
            parsed?.result ?? parsed,
            'gatsby',
            finalUrl,
            htmlToMd,
            undefined,
            gatsbyHasUnicodeTag,
          );
          if (hydrated) {
            const newWords = (hydrated.markdown.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
            if (newWords > currentWordCount * 2 || Boolean(hydrated.records && hydrated.records.length >= 3)) {
              return {
                extractorId: 'gatsby-page-data',
                twinUrl: gatsbyUrl,
                ...(hydrated.title ? { title: hydrated.title } : {}),
                ...(hydrated.description ? { description: hydrated.description } : {}),
                markdown: hydrated.markdown,
                ...(hydrated.structured ? { structured: hydrated.structured } : {}),
                ...(hydrated.records ? { records: hydrated.records } : {}),
                ...(hydrated.returned !== undefined ? { returned: hydrated.returned } : {}),
                ...(hydrated.total !== undefined ? { total: hydrated.total } : {}),
                ...(hydrated.truncated !== undefined ? { truncated: hydrated.truncated } : {}),
                ...(hydrated.nextCursor ? { nextCursor: hydrated.nextCursor } : {}),
                rawDecodedStringsForPiCheck: hydrated.rawDecodedStringsForPiCheck ?? rawJson.slice(0, 1_572_864),
              };
            }
          }
        }
      } catch {
        // Gracefully keep HTML extraction when page-data.json is absent or blocked.
      }
    }
  }

  return null;
}
