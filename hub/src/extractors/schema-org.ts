/**
 * Tier 1 Universal Schema.org JSON-LD Extractor (`hub/src/extractors/schema-org.ts`).
 *
 * Hydrates structured facts, threads, FAQs, item directories, and thin JS article shells from
 * `<script type="application/ld+json">` in linear O(N) time with zero network requests:
 *  - `Article`, `NewsArticle`, `BlogPosting`, `TechArticle`, `ScholarlyArticle`, `Report`
 *  - `FAQPage` (`mainEntity[]` Question + AcceptedAnswer -> `records[]` + Q&A Markdown)
 *  - `QAPage` & `DiscussionForumPosting` (OP + `acceptedAnswer` / `suggestedAnswer[]` / `comment[]` -> thread Markdown + `records[]`)
 *  - `ItemList`, `CollectionPage`, `SearchResultsPage` (`itemListElement[]` -> `records[]` + GFM table)
 *  - `Event`, `SoftwareApplication`, `Dataset`, `Recipe`, `LocalBusiness`
 *
 * Security & Anti-False-Zero Invariants:
 *  - Never emits `records: []` or `(0 results)` on empty/unmatched trees — returns `null` to fall through.
 *  - Every surfaced string undergoes pre- and post-entity-decode invisible/Unicode-Tag/Bidi stripping,
 *    `neutralizeAllUnsafeMarkdownLinksLinear`, and `<`/`>` escaping.
 *  - `inspectRawSchemaOrgJsonLdLinear` shares the exact quote-aware `<script>` parser for `checkPromptInjection: true`.
 */

import { validatePublicHttpsTargetUrl } from '../overflow';
import { replaceHtmlTagBlocksLinear, stripHtmlTagsQuoteAwareLinear } from '../safe-input';
import { neutralizeAllUnsafeMarkdownLinksLinear } from '../scrape-advanced';
import type { HtmlFragmentConverter } from './types';
import {
  decodeBasicEntities,
  extractJsonLdObjects,
  formatGfmTable,
  hasRawOrEncodedUnicodeTagLinear,
  isJsonLdScriptAttrLinear,
  parseJsonValue,
} from './utils';

export interface UniversalSchemaOrgResult {
  schemaType: string;
  title?: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  modifiedTime?: string;
  siteName?: string;
  /** Full synthesized Markdown (used for FAQPage, QAPage, DiscussionForumPosting, ItemList, or thin Article hydration). */
  markdown?: string;
  /** Concise structured fact block prepended when visible body prose is thin. */
  headerMarkdown?: string;
  structured: Record<string, unknown>;
  records?: Array<Record<string, unknown>>;
  total?: number;
  returned?: number;
}

const ARTICLE_TYPES = new Set([
  'article',
  'newsarticle',
  'blogposting',
  'techarticle',
  'scholarlyarticle',
  'report',
  'liveblogposting',
]);

const EVENT_TYPES = new Set([
  'event',
  'businessevent',
  'educationevent',
  'musicevent',
  'socialevent',
  'sportsevent',
  'publicationevent',
  'hackathonevent',
]);

const SOFTWARE_TYPES = new Set([
  'softwareapplication',
  'webapplication',
  'mobileapplication',
  'videogame',
]);

const LOCAL_BUSINESS_TYPES = new Set([
  'localbusiness',
  'restaurant',
  'store',
  'medicalbusiness',
  'lodgingbusiness',
  'automotivebusiness',
  'financialservice',
]);

export function stripInvisibleSchemaChars(s: string): string {
  return s
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]+/gu,
      '',
    );
}

export function sanitizeSchemaPlainField(raw: unknown, maxLen = 512): string {
  if (typeof raw !== 'string' && typeof raw !== 'number') return '';
  const str = String(raw);
  if (!str) return '';
  const pre = stripInvisibleSchemaChars(str);
  const tagStripped = stripHtmlTagsQuoteAwareLinear(pre, ' ');
  const decoded = tagStripped.includes('&') ? decodeBasicEntities(tagStripped) : tagStripped;
  // Strip again after entity decoding so `&#xE0069;` / `&#x202E;` never survive.
  let clean = stripInvisibleSchemaChars(decoded).replace(/\s+/g, ' ').trim();
  if (!clean) return '';
  clean = neutralizeAllUnsafeMarkdownLinksLinear(clean);
  clean = clean.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  if (clean.length > maxLen) {
    clean = clean.slice(0, maxLen).trim();
  }
  return clean;
}

export function sanitizeSchemaRichMarkdown(
  raw: unknown,
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
  maxLen = 32_000,
): string {
  if (typeof raw !== 'string') return '';
  const pre = stripInvisibleSchemaChars(raw).trim();
  if (!pre) return '';
  const hasHtml = /<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|em|code|pre|blockquote|table|a)\b/i.test(pre);
  let md = hasHtml ? htmlToMd(pre, baseUrl).markdown : decodeBasicEntities(stripHtmlTagsQuoteAwareLinear(pre, ' '));
  md = stripInvisibleSchemaChars(md);
  md = neutralizeAllUnsafeMarkdownLinksLinear(md);
  md = md.replace(/<(?=[ \t]*(?:javascript|vbscript|data|file|blob|\/?[a-zA-Z!]))/gi, '&lt;');
  md = md.replace(/\r\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  if (md.length > maxLen) {
    md = md.slice(0, maxLen).trim();
  }
  return md;
}

export function percentEncodeUnsafeRecordUrlChars(urlStr: string): string {
  if (!/[()[\]<>]/.test(urlStr)) return urlStr;
  return urlStr.replace(/[()[\]<>]/g, (ch) => {
    switch (ch) {
      case '(':
        return '%28';
      case ')':
        return '%29';
      case '[':
        return '%5B';
      case ']':
        return '%5D';
      case '<':
        return '%3C';
      default:
        return '%3E';
    }
  });
}

export function sanitizeSchemaHttpsUrl(raw: unknown, baseUrl?: string): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const cleaned = stripInvisibleSchemaChars(raw).trim();
  if (!cleaned || /^(?:javascript|vbscript|data|file|blob):/i.test(cleaned)) return undefined;
  try {
    const resolved = baseUrl ? new URL(cleaned, baseUrl) : new URL(cleaned);
    if (resolved.protocol !== 'https:' || resolved.username || resolved.password) return undefined;
    if (resolved.port && resolved.port !== '443') return undefined;
    const check = validatePublicHttpsTargetUrl(resolved.toString());
    if (!check.ok) return undefined;
    return percentEncodeUnsafeRecordUrlChars(check.url.toString());
  } catch {
    return undefined;
  }
}

function formatSafeMarkdownLink(label: string, safeHttpsUrl?: string): string {
  const safeLabel = label.replace(/\\/g, '\\\\').replace(/\[/g, '\\[').replace(/\]/g, '\\]');
  if (!safeHttpsUrl) return safeLabel;
  const escapedUrl = percentEncodeUnsafeRecordUrlChars(safeHttpsUrl);
  return `[${safeLabel}](${escapedUrl})`;
}

function normalizeSchemaTypes(rawType: unknown): string[] {
  const out: string[] = [];
  const pushOne = (v: unknown) => {
    if (typeof v !== 'string') return;
    const short = v.trim().replace(/^https?:\/\/schema\.org\//i, '').trim();
    if (short && /^[A-Za-z][A-Za-z0-9_-]{1,63}$/.test(short)) {
      out.push(short);
    }
  };
  if (Array.isArray(rawType)) {
    for (const item of rawType.slice(0, 8)) pushOne(item);
  } else {
    pushOne(rawType);
  }
  return out;
}

function extractAuthorName(rawAuthor: unknown): string | undefined {
  if (!rawAuthor) return undefined;
  if (typeof rawAuthor === 'string') {
    const s = sanitizeSchemaPlainField(rawAuthor, 180);
    return s || undefined;
  }
  if (Array.isArray(rawAuthor)) {
    const names = rawAuthor
      .slice(0, 5)
      .map((a) => extractAuthorName(a))
      .filter((n): n is string => Boolean(n));
    return names.length > 0 ? names.join(', ') : undefined;
  }
  if (typeof rawAuthor === 'object') {
    const obj = rawAuthor as Record<string, unknown>;
    const n = sanitizeSchemaPlainField(obj.name ?? obj.alternateName, 180);
    return n || undefined;
  }
  return undefined;
}

function extractPublisherName(rawPub: unknown): string | undefined {
  if (!rawPub) return undefined;
  if (typeof rawPub === 'string') {
    const s = sanitizeSchemaPlainField(rawPub, 180);
    return s || undefined;
  }
  if (typeof rawPub === 'object' && !Array.isArray(rawPub)) {
    const n = sanitizeSchemaPlainField((rawPub as Record<string, unknown>).name, 180);
    return n || undefined;
  }
  return undefined;
}

function countWordsSimple(s: string): number {
  return (s.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
}

function extractFaqPage(
  obj: Record<string, unknown>,
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
): UniversalSchemaOrgResult | null {
  const rawMain = obj.mainEntity ?? obj.hasPart;
  const items = Array.isArray(rawMain) ? rawMain : rawMain && typeof rawMain === 'object' ? [rawMain] : [];
  if (items.length === 0) return null;

  const records: Array<Record<string, unknown>> = [];
  const sections: string[] = [];

  for (const item of items.slice(0, 100)) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const qObj = item as Record<string, unknown>;
    const question = sanitizeSchemaPlainField(qObj.name ?? qObj.headline ?? qObj.text, 400);
    const ansRaw = qObj.acceptedAnswer ?? (Array.isArray(qObj.suggestedAnswer) ? qObj.suggestedAnswer[0] : qObj.suggestedAnswer);
    const ansObj = ansRaw && typeof ansRaw === 'object' && !Array.isArray(ansRaw) ? (ansRaw as Record<string, unknown>) : null;
    const answerMd = sanitizeSchemaRichMarkdown(ansObj?.text ?? ansObj?.articleBody ?? qObj.answer, baseUrl, htmlToMd, 4_000);
    const answerPlain = sanitizeSchemaPlainField(ansObj?.text ?? ansObj?.articleBody ?? qObj.answer, 2_000);
    if (!question || !answerMd || !answerPlain) continue;

    const url = sanitizeSchemaHttpsUrl(qObj.url ?? ansObj?.url, baseUrl);
    records.push({
      question,
      answer: answerPlain,
      ...(url ? { url } : {}),
    });
    sections.push(`## ${question}\n\n${answerMd}`);
  }

  if (records.length === 0) return null;
  const title = sanitizeSchemaPlainField(obj.name ?? obj.headline, 300);
  const description = sanitizeSchemaPlainField(obj.description, 1_000);
  const fullMd = [title ? `# ${title}` : '', ...sections].filter(Boolean).join('\n\n');

  return {
    schemaType: 'FAQPage',
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    markdown: fullMd,
    structured: {
      schemaType: 'FAQPage',
      ...(title ? { title } : {}),
      questionCount: records.length,
    },
    records,
    returned: records.length,
    total: records.length,
  };
}

function extractQaOrForumThread(
  obj: Record<string, unknown>,
  schemaType: 'QAPage' | 'DiscussionForumPosting',
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
): UniversalSchemaOrgResult | null {
  const mainObj =
    schemaType === 'QAPage' && obj.mainEntity && typeof obj.mainEntity === 'object' && !Array.isArray(obj.mainEntity)
      ? (obj.mainEntity as Record<string, unknown>)
      : obj;

  const title = sanitizeSchemaPlainField(mainObj.headline ?? mainObj.name ?? obj.name ?? obj.headline, 350);
  const opBody = sanitizeSchemaRichMarkdown(mainObj.text ?? mainObj.articleBody ?? mainObj.description, baseUrl, htmlToMd, 16_000);
  const opAuthor = extractAuthorName(mainObj.author ?? obj.author);
  const publishedTime = sanitizeSchemaPlainField(mainObj.datePublished ?? obj.datePublished, 64) || undefined;
  const modifiedTime = sanitizeSchemaPlainField(mainObj.dateModified ?? obj.dateModified, 64) || undefined;

  const records: Array<Record<string, unknown>> = [];
  const replySections: string[] = [];

  const pushReply = (rawReply: unknown, accepted: boolean) => {
    if (!rawReply || typeof rawReply !== 'object' || Array.isArray(rawReply) || records.length >= 100) return;
    const r = rawReply as Record<string, unknown>;
    const textMd = sanitizeSchemaRichMarkdown(r.text ?? r.articleBody ?? r.description, baseUrl, htmlToMd, 8_000);
    const textPlain = sanitizeSchemaPlainField(r.text ?? r.articleBody ?? r.description, 2_000);
    if (!textMd || !textPlain) return;
    const author = extractAuthorName(r.author);
    const created = sanitizeSchemaPlainField(r.datePublished ?? r.dateCreated, 64);
    const upvotes = typeof r.upvoteCount === 'number' && Number.isFinite(r.upvoteCount) ? r.upvoteCount : undefined;
    const url = sanitizeSchemaHttpsUrl(r.url, baseUrl);
    records.push({
      role: accepted ? 'accepted_answer' : 'reply',
      ...(author ? { author } : {}),
      ...(created ? { publishedAt: created } : {}),
      ...(upvotes !== undefined ? { upvoteCount: upvotes } : {}),
      ...(url ? { url } : {}),
      text: textPlain,
    });
    const metaParts = [
      accepted ? '**Accepted Answer**' : '**Reply**',
      ...(author ? [`by ${author}`] : []),
      ...(created ? [`(${created})`] : []),
      ...(upvotes !== undefined ? [`· ${upvotes} upvotes`] : []),
    ];
    replySections.push(`### ${metaParts.join(' ')}\n\n${textMd}`);
  };

  if (mainObj.acceptedAnswer) pushReply(mainObj.acceptedAnswer, true);
  if (Array.isArray(mainObj.suggestedAnswer)) {
    for (const s of mainObj.suggestedAnswer.slice(0, 50)) pushReply(s, false);
  } else if (mainObj.suggestedAnswer) {
    pushReply(mainObj.suggestedAnswer, false);
  }
  const rawComments = mainObj.comment ?? obj.comment;
  if (Array.isArray(rawComments)) {
    for (const c of rawComments.slice(0, 80)) pushReply(c, false);
  } else if (rawComments) {
    pushReply(rawComments, false);
  }

  if (!title && !opBody && records.length === 0) return null;
  if (!opBody && records.length === 0) return null;

  const opMeta = [opAuthor ? `**Author**: ${opAuthor}` : '', publishedTime ? `**Posted**: ${publishedTime}` : '']
    .filter(Boolean)
    .join(' · ');
  const mdParts = [
    ...(title ? [`# ${title}`] : []),
    ...(opMeta ? [opMeta] : []),
    ...(opBody ? [opBody] : []),
    ...(replySections.length > 0 ? ['## Replies', ...replySections] : []),
  ];

  return {
    schemaType,
    ...(title ? { title } : {}),
    ...(opAuthor ? { author: opAuthor } : {}),
    ...(publishedTime ? { publishedTime } : {}),
    ...(modifiedTime ? { modifiedTime } : {}),
    markdown: mdParts.join('\n\n'),
    structured: {
      schemaType,
      ...(title ? { title } : {}),
      ...(opAuthor ? { author: opAuthor } : {}),
      ...(publishedTime ? { datePublished: publishedTime } : {}),
      replyCount: records.length,
    },
    ...(records.length > 0 ? { records, returned: records.length, total: records.length } : {}),
  };
}

function extractItemList(
  obj: Record<string, unknown>,
  schemaType: string,
  baseUrl: string | undefined,
): UniversalSchemaOrgResult | null {
  const listContainer =
    Array.isArray(obj.itemListElement)
      ? obj
      : obj.mainEntity && typeof obj.mainEntity === 'object' && !Array.isArray(obj.mainEntity) && Array.isArray((obj.mainEntity as Record<string, unknown>).itemListElement)
        ? (obj.mainEntity as Record<string, unknown>)
        : null;
  if (!listContainer || !Array.isArray(listContainer.itemListElement)) return null;

  const records: Array<Record<string, unknown>> = [];
  const tableRows: Array<Array<string>> = [];
  let anySummaryOrPrice = false;

  for (let i = 0; i < Math.min(250, listContainer.itemListElement.length); i++) {
    const rawEl = listContainer.itemListElement[i];
    if (!rawEl) continue;
    if (typeof rawEl === 'string') {
      const asUrl = sanitizeSchemaHttpsUrl(rawEl, baseUrl);
      if (asUrl) {
        records.push({ position: i + 1, url: asUrl });
        tableRows.push([String(i + 1), asUrl, '-']);
      }
      continue;
    }
    if (typeof rawEl !== 'object' || Array.isArray(rawEl)) continue;
    const elObj = rawEl as Record<string, unknown>;
    const inner =
      elObj.item && typeof elObj.item === 'object' && !Array.isArray(elObj.item)
        ? (elObj.item as Record<string, unknown>)
        : elObj;
    const itemUrl =
      sanitizeSchemaHttpsUrl(inner.url ?? inner['@id'] ?? elObj.url ?? (typeof elObj.item === 'string' ? elObj.item : undefined), baseUrl);
    const name = sanitizeSchemaPlainField(inner.name ?? inner.headline ?? elObj.name, 240);
    if (!name && !itemUrl) continue;

    const desc = sanitizeSchemaPlainField(inner.description ?? elObj.description, 300);
    const offers =
      inner.offers && typeof inner.offers === 'object' && !Array.isArray(inner.offers)
        ? (inner.offers as Record<string, unknown>)
        : Array.isArray(inner.offers) && inner.offers[0] && typeof inner.offers[0] === 'object'
          ? (inner.offers[0] as Record<string, unknown>)
          : null;
    const rawPrice = offers ? sanitizeSchemaPlainField(offers.price ?? offers.lowPrice, 40) : '';
    const rawCurrency = offers ? sanitizeSchemaPlainField(offers.priceCurrency, 12) : '';
    const priceStr = rawPrice ? (rawCurrency ? `${rawPrice} ${rawCurrency}` : rawPrice) : '';
    if (desc || priceStr) anySummaryOrPrice = true;

    const pos =
      typeof elObj.position === 'number' && Number.isFinite(elObj.position) && elObj.position > 0
        ? Math.floor(elObj.position)
        : records.length + 1;
    records.push({
      position: pos,
      ...(name ? { title: name } : {}),
      ...(itemUrl ? { url: itemUrl } : {}),
      ...(priceStr ? { price: priceStr } : {}),
      ...(desc ? { summary: desc } : {}),
    });
    const linkCell = name ? formatSafeMarkdownLink(name, itemUrl) : itemUrl ?? '-';
    const detailCell = [priceStr, desc].filter(Boolean).join(' — ') || '-';
    tableRows.push([String(pos), linkCell, detailCell]);
  }

  // Reject tiny breadcrumb-style lists or empty arrays (`BreadcrumbList` or <= 2 bare nav links).
  if (records.length < 2) return null;
  if (records.length <= 3 && !anySummaryOrPrice && !/ItemList|CollectionPage|SearchResultsPage/i.test(schemaType)) {
    return null;
  }

  const title = sanitizeSchemaPlainField(obj.name ?? obj.headline ?? listContainer.name, 300);
  const description = sanitizeSchemaPlainField(obj.description ?? listContainer.description, 1_000);
  const declaredTotal = Number(listContainer.numberOfItems ?? obj.numberOfItems);
  const total =
    Number.isFinite(declaredTotal) && declaredTotal >= records.length ? Math.floor(declaredTotal) : records.length;

  const headers = anySummaryOrPrice ? ['#', 'Item', 'Details'] : ['#', 'Item'];
  const compactRows = anySummaryOrPrice ? tableRows : tableRows.map((r) => [r[0]!, r[1]!]);
  const tableMd = formatGfmTable(headers, compactRows);
  const md = [title ? `# ${title}` : '', description, tableMd].filter(Boolean).join('\n\n');

  return {
    schemaType,
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    markdown: md,
    structured: {
      schemaType,
      ...(title ? { title } : {}),
      returned: records.length,
      total,
    },
    records,
    returned: records.length,
    total,
  };
}

function extractArticle(
  obj: Record<string, unknown>,
  schemaType: string,
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
): UniversalSchemaOrgResult | null {
  const title = sanitizeSchemaPlainField(obj.headline ?? obj.name, 350);
  const description = sanitizeSchemaPlainField(obj.description ?? obj.abstract, 1_200);
  const author = extractAuthorName(obj.author);
  const siteName = extractPublisherName(obj.publisher);
  const publishedTime = sanitizeSchemaPlainField(obj.datePublished ?? obj.dateCreated, 64) || undefined;
  const modifiedTime = sanitizeSchemaPlainField(obj.dateModified, 64) || undefined;
  const section = sanitizeSchemaPlainField(obj.articleSection, 120);
  const bodyMd = sanitizeSchemaRichMarkdown(obj.articleBody ?? obj.text, baseUrl, htmlToMd, 64_000);
  const bodyWords = countWordsSimple(bodyMd);

  if (!title && bodyWords < 25) return null;

  const metaBits = [
    ...(author ? [`**Author**: ${author}`] : []),
    ...(siteName ? [`**Publisher**: ${siteName}`] : []),
    ...(publishedTime ? [`**Published**: ${publishedTime}`] : []),
    ...(section ? [`**Section**: ${section}`] : []),
  ];
  const headerMd = metaBits.join(' · ');
  const fullMd =
    bodyWords >= 30
      ? [title ? `# ${title}` : '', headerMd, bodyMd].filter(Boolean).join('\n\n')
      : undefined;

  return {
    schemaType,
    ...(title ? { title } : {}),
    ...(description ? { description } : {}),
    ...(author ? { author } : {}),
    ...(publishedTime ? { publishedTime } : {}),
    ...(modifiedTime ? { modifiedTime } : {}),
    ...(siteName ? { siteName } : {}),
    ...(fullMd ? { markdown: fullMd } : {}),
    ...(headerMd ? { headerMarkdown: headerMd } : {}),
    structured: {
      schemaType,
      ...(title ? { headline: title } : {}),
      ...(description ? { description } : {}),
      ...(author ? { author } : {}),
      ...(siteName ? { publisher: siteName } : {}),
      ...(publishedTime ? { datePublished: publishedTime } : {}),
      ...(modifiedTime ? { dateModified: modifiedTime } : {}),
      ...(section ? { articleSection: section } : {}),
      ...(bodyWords > 0 ? { wordCount: bodyWords } : {}),
    },
  };
}

function extractEventOrSoftwareOrDataset(
  obj: Record<string, unknown>,
  schemaType: string,
  kind: 'event' | 'software' | 'dataset' | 'recipe' | 'localbusiness',
  baseUrl: string | undefined,
): UniversalSchemaOrgResult | null {
  const title = sanitizeSchemaPlainField(obj.name ?? obj.headline, 350);
  if (!title) return null;
  const description = sanitizeSchemaPlainField(obj.description, 1_500);
  const url = sanitizeSchemaHttpsUrl(obj.url, baseUrl);

  const structured: Record<string, unknown> = {
    schemaType,
    name: title,
    ...(description ? { description } : {}),
    ...(url ? { url } : {}),
  };
  const bullets: string[] = [];

  if (kind === 'event') {
    const startDate = sanitizeSchemaPlainField(obj.startDate, 80);
    const endDate = sanitizeSchemaPlainField(obj.endDate, 80);
    const status = sanitizeSchemaPlainField(obj.eventStatus, 80).replace(/^https?:\/\/schema\.org\//i, '');
    const attendance = sanitizeSchemaPlainField(obj.eventAttendanceMode, 80).replace(/^https?:\/\/schema\.org\//i, '');
    const locObj = obj.location && typeof obj.location === 'object' && !Array.isArray(obj.location) ? (obj.location as Record<string, unknown>) : null;
    const locName = sanitizeSchemaPlainField(locObj?.name ?? (typeof obj.location === 'string' ? obj.location : ''), 180);
    const organizer = extractPublisherName(obj.organizer);
    if (startDate) {
      structured.startDate = startDate;
      bullets.push(`- **Start**: ${startDate}`);
    }
    if (endDate) {
      structured.endDate = endDate;
      bullets.push(`- **End**: ${endDate}`);
    }
    if (locName) {
      structured.location = locName;
      bullets.push(`- **Location**: ${locName}`);
    }
    if (attendance) {
      structured.attendanceMode = attendance;
      bullets.push(`- **Mode**: ${attendance}`);
    }
    if (status) structured.eventStatus = status;
    if (organizer) {
      structured.organizer = organizer;
      bullets.push(`- **Organizer**: ${organizer}`);
    }
  } else if (kind === 'software') {
    const appCat = sanitizeSchemaPlainField(obj.applicationCategory, 120);
    const os = sanitizeSchemaPlainField(obj.operatingSystem, 160);
    const version = sanitizeSchemaPlainField(obj.softwareVersion ?? obj.version, 80);
    const ratingObj =
      obj.aggregateRating && typeof obj.aggregateRating === 'object' && !Array.isArray(obj.aggregateRating)
        ? (obj.aggregateRating as Record<string, unknown>)
        : null;
    const ratingValue = ratingObj ? sanitizeSchemaPlainField(ratingObj.ratingValue, 20) : '';
    const ratingCount = ratingObj ? sanitizeSchemaPlainField(ratingObj.ratingCount ?? ratingObj.reviewCount, 24) : '';
    if (appCat) {
      structured.applicationCategory = appCat;
      bullets.push(`- **Category**: ${appCat}`);
    }
    if (os) {
      structured.operatingSystem = os;
      bullets.push(`- **Operating System**: ${os}`);
    }
    if (version) {
      structured.softwareVersion = version;
      bullets.push(`- **Version**: ${version}`);
    }
    if (ratingValue) {
      structured.ratingValue = ratingValue;
      if (ratingCount) structured.ratingCount = ratingCount;
      bullets.push(`- **Rating**: ${ratingValue}${ratingCount ? ` (${ratingCount} reviews)` : ''}`);
    }
  } else if (kind === 'dataset') {
    const creator = extractAuthorName(obj.creator ?? obj.author);
    const license = sanitizeSchemaPlainField(
      typeof obj.license === 'string' ? obj.license : (obj.license as Record<string, unknown> | undefined)?.name,
      200,
    );
    const temporal = sanitizeSchemaPlainField(obj.temporalCoverage, 120);
    const identifier = sanitizeSchemaPlainField(obj.identifier, 160);
    if (creator) {
      structured.creator = creator;
      bullets.push(`- **Creator**: ${creator}`);
    }
    if (license) {
      structured.license = license;
      bullets.push(`- **License**: ${license}`);
    }
    if (temporal) {
      structured.temporalCoverage = temporal;
      bullets.push(`- **Coverage**: ${temporal}`);
    }
    if (identifier) structured.identifier = identifier;
  } else if (kind === 'recipe') {
    const prepTime = sanitizeSchemaPlainField(obj.prepTime, 40);
    const cookTime = sanitizeSchemaPlainField(obj.cookTime, 40);
    const totalTime = sanitizeSchemaPlainField(obj.totalTime, 40);
    const recipeYield = sanitizeSchemaPlainField(
      Array.isArray(obj.recipeYield) ? obj.recipeYield[0] : obj.recipeYield,
      80,
    );
    const ingredients = Array.isArray(obj.recipeIngredient)
      ? obj.recipeIngredient.slice(0, 60).map((x) => sanitizeSchemaPlainField(x, 200)).filter(Boolean)
      : [];
    if (totalTime || prepTime || cookTime) {
      const tStr = [prepTime ? `prep ${prepTime}` : '', cookTime ? `cook ${cookTime}` : '', totalTime ? `total ${totalTime}` : '']
        .filter(Boolean)
        .join(', ');
      structured.timing = tStr;
      bullets.push(`- **Time**: ${tStr}`);
    }
    if (recipeYield) {
      structured.recipeYield = recipeYield;
      bullets.push(`- **Yield**: ${recipeYield}`);
    }
    if (ingredients.length > 0) {
      structured.recipeIngredient = ingredients;
    }
  } else if (kind === 'localbusiness') {
    const tel = sanitizeSchemaPlainField(obj.telephone, 60);
    const priceRange = sanitizeSchemaPlainField(obj.priceRange, 30);
    const addrObj =
      obj.address && typeof obj.address === 'object' && !Array.isArray(obj.address)
        ? (obj.address as Record<string, unknown>)
        : null;
    const addrStr = addrObj
      ? [addrObj.streetAddress, addrObj.addressLocality, addrObj.addressRegion, addrObj.postalCode, addrObj.addressCountry]
          .map((x) => sanitizeSchemaPlainField(x, 80))
          .filter(Boolean)
          .join(', ')
      : sanitizeSchemaPlainField(obj.address, 200);
    if (!tel && !addrStr) return null;
    if (addrStr) {
      structured.address = addrStr;
      bullets.push(`- **Address**: ${addrStr}`);
    }
    if (tel) {
      structured.telephone = tel;
      bullets.push(`- **Phone**: ${tel}`);
    }
    if (priceRange) structured.priceRange = priceRange;
  }

  if (bullets.length === 0 && !description) return null;
  const headerMd = bullets.join('\n');
  const synthMd = [
    `# ${title}`,
    ...(headerMd ? [headerMd] : []),
    ...(description ? [description] : []),
  ].join('\n\n');

  return {
    schemaType,
    title,
    ...(description ? { description } : {}),
    ...(headerMd ? { headerMarkdown: headerMd } : {}),
    markdown: synthMd,
    structured,
  };
}

/**
 * Extracts rich Schema.org JSON-LD entities from HTML in linear O(N) time.
 * Skips `JobPosting` and standalone `Product` (which have dedicated domain normalizers in `jobs.ts` / `scrape-advanced.ts`)
 * so existing specialized fields (`jobPosting`, `product`) remain untouched.
 */
export function extractUniversalSchemaOrg(
  rawHtml: string,
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
): UniversalSchemaOrgResult | null {
  if (!rawHtml || !/ld\+json/i.test(rawHtml)) return null;
  const entities = extractJsonLdObjects(rawHtml, 100);
  if (entities.length === 0) return null;

  // Priority order:
  // 1. Thread / Q&A / FAQ (`QAPage`, `DiscussionForumPosting`, `FAQPage`)
  // 2. Directory / Collection (`ItemList`, `CollectionPage`, `SearchResultsPage`)
  // 3. Domain entities (`Event`, `SoftwareApplication`, `Dataset`, `Recipe`, `LocalBusiness`)
  // 4. Articles (`Article`, `NewsArticle`, `BlogPosting`, `TechArticle`, `ScholarlyArticle`)
  let fallbackArticle: UniversalSchemaOrgResult | null = null;
  let fallbackDomain: UniversalSchemaOrgResult | null = null;
  let fallbackItemList: UniversalSchemaOrgResult | null = null;

  for (const entity of entities) {
    const types = normalizeSchemaTypes(entity['@type']);
    if (types.length === 0) continue;
    const lowerTypes = types.map((t) => t.toLowerCase());

    // Defer JobPosting and standalone Product to their dedicated extractors.
    if (lowerTypes.includes('jobposting') || lowerTypes.includes('product')) continue;
    if (lowerTypes.includes('breadcrumblist')) continue;

    if (lowerTypes.includes('qapage')) {
      const qa = extractQaOrForumThread(entity, 'QAPage', baseUrl, htmlToMd);
      if (qa) return qa;
    }
    if (lowerTypes.includes('discussionforumposting')) {
      const forum = extractQaOrForumThread(entity, 'DiscussionForumPosting', baseUrl, htmlToMd);
      if (forum) return forum;
    }
    if (lowerTypes.includes('faqpage')) {
      const faq = extractFaqPage(entity, baseUrl, htmlToMd);
      if (faq) return faq;
    }
    if (!fallbackItemList && lowerTypes.some((t) => t === 'itemlist' || t === 'collectionpage' || t === 'searchresultspage')) {
      const matched = types.find((t) => /^(?:itemlist|collectionpage|searchresultspage)$/i.test(t)) ?? 'ItemList';
      fallbackItemList = extractItemList(entity, matched, baseUrl);
    }
    if (!fallbackDomain) {
      const evType = types.find((t) => EVENT_TYPES.has(t.toLowerCase()));
      if (evType) fallbackDomain = extractEventOrSoftwareOrDataset(entity, evType, 'event', baseUrl);
      const swType = !fallbackDomain ? types.find((t) => SOFTWARE_TYPES.has(t.toLowerCase())) : undefined;
      if (swType) fallbackDomain = extractEventOrSoftwareOrDataset(entity, swType, 'software', baseUrl);
      if (!fallbackDomain && lowerTypes.includes('dataset')) {
        fallbackDomain = extractEventOrSoftwareOrDataset(entity, 'Dataset', 'dataset', baseUrl);
      }
      if (!fallbackDomain && lowerTypes.includes('recipe')) {
        fallbackDomain = extractEventOrSoftwareOrDataset(entity, 'Recipe', 'recipe', baseUrl);
      }
      const lbType = !fallbackDomain ? types.find((t) => LOCAL_BUSINESS_TYPES.has(t.toLowerCase())) : undefined;
      if (lbType) fallbackDomain = extractEventOrSoftwareOrDataset(entity, lbType, 'localbusiness', baseUrl);
    }
    if (!fallbackArticle) {
      const artType = types.find((t) => ARTICLE_TYPES.has(t.toLowerCase()));
      if (artType) fallbackArticle = extractArticle(entity, artType, baseUrl, htmlToMd);
    }
  }

  return fallbackItemList ?? fallbackDomain ?? fallbackArticle;
}

/**
 * Quote-aware linear `<script type="application/ld+json">` string-leaf collector for `checkPromptInjection: true`.
 * Shares `isJsonLdScriptAttrLinear` with `extractJsonLdObjects` and walks up to depth 20 / 1.5 MiB without
 * short-array or 64 KiB truncation gaps, plus unconditional Unicode-Tag (`U+E0000..U+E007F`) preservation (`HIGH-3`).
 */
export function inspectRawSchemaOrgJsonLdLinear(rawHtml: string): string {
  if (!rawHtml || !/ld\+json/i.test(rawHtml)) return '';
  const MAX_PI_SCHEMA_CHARS = 1_572_864;
  const chunks: string[] = [];
  let totalChars = 0;
  let sawUnicodeTag = false;
  let totalVisited = 0;

  replaceHtmlTagBlocksLinear(rawHtml, 'script', (_full, attrStr, inner) => {
    if (!isJsonLdScriptAttrLinear(attrStr)) return '';
    const raw = inner.trim();
    if (!raw || raw.length > 2 * 1024 * 1024) return '';
    if (!sawUnicodeTag && hasRawOrEncodedUnicodeTagLinear(raw)) {
      sawUnicodeTag = true;
    }
    const parsed = parseJsonValue(raw) ?? (raw.includes('&') ? parseJsonValue(decodeBasicEntities(raw)) : null);
    let scriptVisited = 0;

    const walkStrings = (val: unknown, depth: number) => {
      if (val === null || val === undefined || depth > 20 || scriptVisited > 100_000 || totalVisited > 250_000) return;
      if (typeof val === 'string') {
        if (!val) return;
        scriptVisited++;
        totalVisited++;
        const decoded = val.includes('&') ? decodeBasicEntities(val) : val;
        if (!sawUnicodeTag && hasRawOrEncodedUnicodeTagLinear(decoded)) {
          sawUnicodeTag = true;
        }
        if (totalChars < MAX_PI_SCHEMA_CHARS) {
          const slice = decoded.slice(0, Math.max(0, MAX_PI_SCHEMA_CHARS - totalChars));
          if (slice) {
            chunks.push(slice);
            totalChars += slice.length;
          }
        }
        return;
      }
      if (Array.isArray(val)) {
        if (val.length === 0) return; // Never charge budget for empty arrays (`[[],[],...]`, `NEW-HIGH-1`)
        scriptVisited++;
        totalVisited++;
        for (const item of val) {
          if (scriptVisited > 100_000 || totalVisited > 250_000) break;
          if (typeof item === 'string' || (item !== null && typeof item === 'object')) {
            walkStrings(item, depth + 1);
          }
        }
        return;
      }
      if (typeof val === 'object') {
        const vals = Object.values(val as Record<string, unknown>);
        if (vals.length === 0) return; // Never charge budget for empty `{}`
        scriptVisited++;
        totalVisited++;
        for (const v of vals) {
          if (scriptVisited > 100_000 || totalVisited > 250_000) break;
          if (typeof v === 'string' || (v !== null && typeof v === 'object')) {
            walkStrings(v, depth + 1);
          }
        }
      }
    };

    walkStrings(parsed, 0);
    return '';
  });

  if (sawUnicodeTag) {
    chunks.push('\u{E0069}');
  }
  return chunks.join('\n');
}
