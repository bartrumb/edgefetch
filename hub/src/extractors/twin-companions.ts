/**
 * Bounded companion fetch & enrichment helpers for M2 declarative twins (`hub/src/extractors/twin-companions.ts`).
 *
 * All network fetches are delegated to `scrape.ts` callbacks backed by `executeHubFetch`
 * (`respectRobots: true`, `maxBytes: MAX_WASM_INPUT_BYTES`, `maxInlineBodyBytes: MAX_WASM_INPUT_BYTES`)
 * and validated via `isTrustedTwinRedirectUrl`. All JSON parsing/formatting runs inside Go WASM.
 */

import { formatJsonWithExtractSpec, isSafeDeclarativeTwinUrl, type DeclarativeExtractSpec } from './declarative';
import { resolveSiteExtractorTwin } from './registry';
import type { HtmlFragmentConverter, TwinFormattedDoc } from './types';

export interface BoundedTwinFetchReply {
  item: Record<string, unknown>;
  body: string;
  via: string;
}

export type FetchBoundedTwinFn = (params: {
  url: string;
  tag: string;
  kind: 'json' | 'text';
  accept: string;
  trustAdapterId: string;
}) => Promise<BoundedTwinFetchReply | null>;

const ZENDESK_ARTICLE_TWIN_RE = /^https:\/\/([^/]+)\/api\/v2\/help_center\/([a-z0-9-]+)\/articles\/(\d+)\.json(?:\?|$)/i;
const DOCKER_HUB_REPO_TWIN_RE = /^https:\/\/hub\.docker\.com\/v2\/repositories\/([^/]+)\/([^/]+)\/?$/i;
const GOVINFO_DETAILS_PATH_RE = /^\/app\/details\/([A-Za-z0-9_.-]{4,120})(?:\/([A-Za-z0-9_.-]{4,160}))?\/?$/;
const SAFERPRODUCTS_RECALL_PATH_RE = /^\/restwebservices\/recall(?:\/.*)?$/i;
const CPSC_RECALL_NUM_RE = /Recall\s*(?:Number|No\.?|#)\s*:?\s*(?:<[^>]{0,60}>|\s|\*|`)*([0-9]{2}-?[0-9]{2,5})/i;

const ZENDESK_ATTACHMENTS_EXTRACT_SPEC: DeclarativeExtractSpec = {
  requireAnyFields: ['article_attachments'],
  titleTemplate: 'Attachments',
  sections: [
    {
      heading: 'Attachments',
      arrayPath: 'article_attachments',
      limit: 25,
      requireItemVar: 'attUrl',
      collectLinkVars: ['attUrl'],
      itemVars: {
        fileName: { paths: ['file_name'], format: 'trim', trim: true, default: 'Attachment' },
        attUrl: { paths: ['content_url'], requireHttps: true },
        mimeType: { paths: ['content_type'], trim: true },
        sizeHuman: { paths: ['size'], format: 'bytes_human' },
      },
      columns: [
        { header: 'Attachment', template: '[{fileName}]({attUrl})' },
        { header: 'Type', template: '{mimeType}' },
        { header: 'Size', template: '{sizeHuman}' },
      ],
    },
  ],
};

function stripLeadingMarkdownHeading(md: string): string {
  const norm = md.replace(/\r\n/g, '\n').trim();
  const match = /^# [^\n]+\n+([\s\S]*)$/.exec(norm);
  return match ? match[1].trim() : norm;
}

/**
 * Pre-fetch guard blocking unfiltered `saferproducts.gov/RestWebServices/Recall` dumps (> 25 MiB)
 * that lack a valid bounded `RecallNumber` query parameter.
 */
export function checkUnboundedTwinEndpointGuard(
  parsedUrl: URL,
  normalizedUrl: string,
): { status: number; via: string; body: Record<string, unknown> } | null {
  const hostLower = parsedUrl.hostname.toLowerCase().replace(/\.+$/, '');
  if (hostLower === 'www.saferproducts.gov' || hostLower === 'saferproducts.gov') {
    let decodedPath = parsedUrl.pathname;
    try {
      for (let pass = 0; pass < 2; pass++) {
        const next = decodeURIComponent(decodedPath);
        if (next === decodedPath) break;
        decodedPath = next;
      }
    } catch {
      return {
        status: 422,
        via: 'hub',
        body: {
          ok: false,
          success: false,
          url: normalizedUrl,
          finalUrl: normalizedUrl,
          outcome: 'skip',
          code: 'UNBOUNDED_ENDPOINT_BLOCKED',
          error: 'unbounded_endpoint_blocked',
          message:
            'Malformed percent-encoding on saferproducts.gov endpoint.',
        },
      };
    }
    const normPath = decodedPath.replace(/[\\/]+/g, '/').toLowerCase();
    if (SAFERPRODUCTS_RECALL_PATH_RE.test(normPath)) {
      const recallMatches: string[] = [];
      for (const [k, v] of parsedUrl.searchParams.entries()) {
        if (k.toLowerCase() === 'recallnumber') {
          recallMatches.push(v.trim());
        }
      }
      const rawRecallNum = recallMatches.length === 1 ? recallMatches[0]! : '';
      const strippedRecallNum = rawRecallNum.replace(/-/g, '');
      if (
        recallMatches.length !== 1 ||
        !/^[A-Za-z0-9-]{2,24}$/.test(rawRecallNum) ||
        !/^[A-Za-z0-9]{2,24}$/.test(strippedRecallNum)
      ) {
        return {
          status: 422,
          via: 'hub',
          body: {
            ok: false,
            success: false,
            url: normalizedUrl,
            finalUrl: normalizedUrl,
            outcome: 'skip',
            code: 'UNBOUNDED_ENDPOINT_BLOCKED',
            error: 'unbounded_endpoint_blocked',
            message:
              'Unfiltered saferproducts.gov/RestWebServices/Recall endpoint exceeds 25 MiB and requires a bounded RecallNumber query parameter (e.g., ?RecallNumber=24123).',
          },
        };
      }
    }
  }
  return null;
}

/**
 * Best-effort enrichment for `zendesk-hc` article twins: fetches `/attachments.json`
 * via Go WASM formatting and appends any PDF/manual attachment links. Silently ignored on 404/401/error.
 */
export async function enrichZendeskArticleAttachments(params: {
  normalizedUrl: string;
  twinFetchUrl: string;
  formatted: TwinFormattedDoc;
  fetchBoundedTwin: FetchBoundedTwinFn;
}): Promise<TwinFormattedDoc> {
  const { normalizedUrl, twinFetchUrl, formatted, fetchBoundedTwin } = params;
  const m = ZENDESK_ARTICLE_TWIN_RE.exec(twinFetchUrl);
  if (!m) return formatted;

  const [, host, locale, articleId] = m;
  const attUrl = `https://${host}/api/v2/help_center/${locale}/articles/${articleId}/attachments.json`;
  if (!isSafeDeclarativeTwinUrl(attUrl)) return formatted;

  try {
    const reply = await fetchBoundedTwin({
      url: attUrl,
      tag: 'zendesk-hc-attachments',
      kind: 'json',
      accept: 'application/json',
      trustAdapterId: 'zendesk-hc',
    });
    if (!reply || !reply.body.trim()) return formatted;

    const attDoc = formatJsonWithExtractSpec(reply.body, ZENDESK_ATTACHMENTS_EXTRACT_SPEC, {}, normalizedUrl);
    if (!attDoc || !attDoc.markdown.includes('## Attachments')) return formatted;

    const sectionBody = stripLeadingMarkdownHeading(attDoc.markdown);
    if (!sectionBody) return formatted;

    const mergedLinks = [...new Set([...(formatted.links ?? []), ...(attDoc.links ?? [])])];
    return {
      ...formatted,
      markdown: `${formatted.markdown.trimEnd()}\n\n${sectionBody}`,
      ...(mergedLinks.length > 0 ? { links: mergedLinks } : {}),
    };
  } catch {
    return formatted;
  }
}

/**
 * Best-effort enrichment for `docker-hub` repo root twins: fetches `/tags?page_size=25`
 * and formats the Recent Tags table via the `docker-hub` Go WASM `/tags` formatter.
 */
export async function enrichDockerHubTags(params: {
  normalizedUrl: string;
  twinFetchUrl: string;
  formatted: TwinFormattedDoc;
  fetchBoundedTwin: FetchBoundedTwinFn;
  htmlToMd: HtmlFragmentConverter;
}): Promise<TwinFormattedDoc> {
  const { normalizedUrl, twinFetchUrl, formatted, fetchBoundedTwin, htmlToMd } = params;
  const m = DOCKER_HUB_REPO_TWIN_RE.exec(twinFetchUrl);
  if (!m) return formatted;

  const [, ns, repo] = m;
  const tagsApiUrl = `https://hub.docker.com/v2/repositories/${ns}/${repo}/tags?page_size=25`;
  const tagsTwin = resolveSiteExtractorTwin(`https://hub.docker.com/r/${ns}/${repo}/tags`);
  if (!tagsTwin || !isSafeDeclarativeTwinUrl(tagsApiUrl)) return formatted;

  try {
    const reply = await fetchBoundedTwin({
      url: tagsApiUrl,
      tag: 'docker-hub-tags',
      kind: 'json',
      accept: 'application/json',
      trustAdapterId: 'docker-hub',
    });
    if (!reply || !reply.body.trim()) return formatted;

    const tagsDoc = tagsTwin.formatTwin(reply.body, normalizedUrl, htmlToMd);
    if (!tagsDoc || !tagsDoc.markdown.trim()) return formatted;

    const sectionBody = stripLeadingMarkdownHeading(tagsDoc.markdown);
    if (!sectionBody) return formatted;

    return {
      ...formatted,
      markdown: `${formatted.markdown.trimEnd()}\n\n${sectionBody}`,
    };
  } catch {
    return formatted;
  }
}

/**
 * Companion fallback for `us-cfr-govinfo` when the `.htm` twin exceeds 4 MiB (`bodyOmitted`)
 * or returns 404/empty: fetches `/wssearch/getContentDetail` summary JSON instead of falling
 * through to the empty Angular `/app/details/` SPA.
 */
export async function fetchGovInfoSummaryFallback(params: {
  normalizedUrl: string;
  primaryBodyOmitted: boolean;
  fetchBoundedTwin: FetchBoundedTwinFn;
  htmlToMd: HtmlFragmentConverter;
}): Promise<{
  formatted: TwinFormattedDoc;
  twinItem: Record<string, unknown>;
  rawBody: string;
  fetchUrl: string;
  accept: string;
  via: string;
  warnings: string[];
} | null> {
  const { normalizedUrl, primaryBodyOmitted, fetchBoundedTwin, htmlToMd } = params;
  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    return null;
  }
  const m = GOVINFO_DETAILS_PATH_RE.exec(parsed.pathname);
  if (!m) return null;

  const pkgId = m[1];
  const granuleId = m[2];
  const summaryUrl =
    `https://www.govinfo.gov/wssearch/getContentDetail?packageId=${encodeURIComponent(pkgId)}` +
    (granuleId ? `&granuleId=${encodeURIComponent(granuleId)}` : '');
  const summaryTwin = resolveSiteExtractorTwin(summaryUrl);
  if (!summaryTwin) return null;

  try {
    const reply = await fetchBoundedTwin({
      url: summaryTwin.fetchUrl,
      tag: 'us-cfr-govinfo-summary',
      kind: 'json',
      accept: 'application/json',
      trustAdapterId: 'us-cfr-govinfo',
    });
    if (!reply || !reply.body.trim()) return null;

    const formatted = summaryTwin.formatTwin(reply.body, normalizedUrl, htmlToMd);
    if (!formatted || !formatted.markdown.trim()) return null;

    const warnings: string[] = [];
    if (primaryBodyOmitted) {
      warnings.push(
        'govinfo.gov full HTML document exceeded the 4 MiB WASM input budget; returned wssearch/getContentDetail summary JSON and download links.',
      );
    }
    return {
      formatted,
      twinItem: reply.item,
      rawBody: reply.body,
      fetchUrl: summaryTwin.fetchUrl,
      accept: summaryTwin.accept,
      via: reply.via,
      warnings,
    };
  } catch {
    return null;
  }
}

/**
 * Post-HTML companion enrichment for `cpsc.gov/Recalls/<year>/<slug>`:
 * extracts `RecallNumber`, strips dashes, and performs a bounded `saferproducts.gov`
 * REST JSON lookup, falling back cleanly to CPSC DOM extraction on empty/error.
 */
export async function enrichCpscRecallFromSaferProducts(params: {
  finalUrl: string;
  rawHtml: string;
  extractedMarkdown?: string;
  fetchBoundedTwin: FetchBoundedTwinFn;
  htmlToMd: HtmlFragmentConverter;
}): Promise<{
  extractorId: 'cpsc-recalls';
  twinUrl: string;
  doc: TwinFormattedDoc;
} | null> {
  const { finalUrl, rawHtml, extractedMarkdown, fetchBoundedTwin, htmlToMd } = params;
  const haystack = [extractedMarkdown ?? '', rawHtml.slice(0, 120_000)].filter(Boolean).join('\n');
  const m = CPSC_RECALL_NUM_RE.exec(haystack);
  if (!m) return null;

  const recallNum = m[1].replace(/-/g, '').trim();
  if (!/^[A-Za-z0-9]{2,24}$/.test(recallNum)) return null;

  const lookupUrl = `https://www.saferproducts.gov/RestWebServices/Recall?RecallNumber=${encodeURIComponent(recallNum)}`;
  const saferTwin = resolveSiteExtractorTwin(lookupUrl);
  if (!saferTwin) return null;

  try {
    const reply = await fetchBoundedTwin({
      url: saferTwin.fetchUrl,
      tag: 'cpsc-saferproducts',
      kind: 'json',
      accept: 'application/json',
      trustAdapterId: 'cpsc-recalls',
    });
    if (!reply || !reply.body.trim()) return null;

    const doc = saferTwin.formatTwin(reply.body, finalUrl, htmlToMd);
    if (!doc || !doc.markdown.trim()) return null;

    return {
      extractorId: 'cpsc-recalls',
      twinUrl: saferTwin.fetchUrl,
      doc,
    };
  } catch {
    return null;
  }
}
