/**
 * WAF & Challenge Signature Catalog (`R2`), 4-Layer Anti-False-Positive Engine (`R3`),
 * `contentState` Soft-404 / Closed-Role / Login-Wall Classifier (`R4`),
 * SSR Hydration State Recovery (`__NEXT_DATA__`, `__NUXT_DATA__`, Remix, Apollo — `R6`),
 * and Opt-In Internet Archive Wayback CDX Link-Rot Fallback (`R8`).
 *
 * Ethical Ground Rule:
 *  - EdgeFetch NEVER solves, clicks through, waits out, or bypasses anti-bot challenges or `robots.txt`.
 *  - Accurate WAF classification stops wasted retries immediately and guides callers to clean official APIs/feeds.
 *  - Wayback fallback runs STRICTLY on `5xx` / network-dead link rot — NEVER on `robots.txt`, `401`/`403`/`429`, or challenges.
 */

import {
  asciiLower,
  MAX_HTML_SCAN_CHARS,
  replaceHtmlTagBlocksLinear,
  replacePairedHtmlElementsLinear,
  scanHtmlTagsLinear,
  stripHtmlCommentsLinear,
  stripHtmlTagsLinear,
  stripHtmlTagsQuoteAwareLinear,
} from './safe-input';

export type WafVendor =
  | 'cloudflare'
  | 'akamai'
  | 'datadome'
  | 'perimeterx'
  | 'aws-waf'
  | 'imperva'
  | 'vercel'
  | 'fastly'
  | 'kasada'
  | 'generic';

export type WafCategory = 'challenge' | 'waf_block' | 'rate_limit';

export interface WafClassification {
  vendor: WafVendor;
  category: WafCategory;
  confidence: number;
  signals: string[];
  summary: string;
}

export type ContentState = 'active' | 'closed_posting' | 'soft_404' | 'login_wall' | 'empty_shell';

export interface ContentStateResult {
  state: ContentState;
  reason?: string;
}

export type HtmlFragmentConverter = (html: string, baseUrl?: string) => { markdown: string; links: string[] };

function stripTagsToWords(htmlFragment: string): number {
  const plain = stripHtmlTagsQuoteAwareLinear(htmlFragment, ' ', 98_304)
    .replace(/&nbsp;/gi, ' ')
    .replace(/&[a-z0-9#]+;/gi, ' ')
    .trim();
  if (!plain) return 0;
  return (plain.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
}

function readHeaderCaseInsensitive(headers: Headers | Record<string, string | undefined> | undefined, name: string): string {
  if (!headers) return '';
  if (typeof (headers as Headers).get === 'function') {
    return ((headers as Headers).get(name) ?? '').trim();
  }
  const rec = headers as Record<string, string | undefined>;
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(rec)) {
    if (k.toLowerCase() === target && typeof v === 'string') return v.trim();
  }
  return '';
}

const RICH_SCHEMA_INNER_RE =
  /"@type"\s*:\s*(?:\[[^\]]{0,400})?["'](?:Article|TechArticle|NewsArticle|BlogPosting|ScholarlyArticle|JobPosting|Product|SoftwareSourceCode|FAQPage|APIReference)["']/i;

function hasRichSchemaJsonLdLinear(sample: string): boolean {
  if (!sample.includes('ld+json') && !sample.includes('LD+JSON')) return false;
  let found = false;
  replaceHtmlTagBlocksLinear(
    sample,
    'script',
    (_full, attrStr, inner) => {
      if (!found && /\btype\s*=\s*["']application\/ld\+json["']/i.test(attrStr)) {
        if (RICH_SCHEMA_INNER_RE.test(inner.slice(0, 24_000))) {
          found = true;
        }
      }
      return '';
    },
    98_304,
  );
  return found;
}

/**
 * Evaluates HTTP status, response headers, and body against the 7-Vendor WAF & Challenge Signature Catalog (`R2`)
 * while enforcing all 4 Anti-False-Positive Guardrails (`R3`):
 *  1. Authoritative headers (`cf-mitigated`, `x-amzn-waf-action`, `x-vercel-mitigated`, `x-datadome`, `x-kpsdk-ct`, `x-px-blocked`) win at `1.0`.
 *  2. Structural Veto on `200 OK`: `>= 250` visible words, `>= 2` `<h2>`/`<h3>` headings + `>= 100` words, rich Schema.org JSON-LD, or `<nav>` with `>= 4` links + `>= 120` words NEVER trigger body challenge rules.
 *  3. Code/Quote/Data Immunity: `<pre>`, `<code>`, `<blockquote>`, JSON-LD, and `__NEXT_DATA__` are stripped before body regexes run.
 *  4. Interstitial Geometry: `200 OK` body-only matches require `< 48 KB` and `< 120` visible words.
 */
export function classifyWafAndChallenge(params: {
  status: number;
  headers?: Headers | Record<string, string | undefined>;
  rawBody?: string;
}): WafClassification | null {
  const { status, headers, rawBody = '' } = params;

  // --- Layer 1: Authoritative HTTP Response Headers ---
  const cfMit = readHeaderCaseInsensitive(headers, 'cf-mitigated').toLowerCase();
  if (cfMit) {
    const category: WafCategory = cfMit === 'block' ? 'waf_block' : 'challenge';
    return {
      vendor: 'cloudflare',
      category,
      confidence: 1.0,
      signals: [`header:cf-mitigated=${cfMit}`],
      summary: `Cloudflare ${category} (cf-mitigated)`,
    };
  }

  const amzWaf = readHeaderCaseInsensitive(headers, 'x-amzn-waf-action').toLowerCase();
  if (amzWaf === 'challenge' || amzWaf === 'captcha' || amzWaf === 'block') {
    return {
      vendor: 'aws-waf',
      category: amzWaf === 'block' ? 'waf_block' : 'challenge',
      confidence: 1.0,
      signals: [`header:x-amzn-waf-action=${amzWaf}`],
      summary: `AWS WAF ${amzWaf} (x-amzn-waf-action)`,
    };
  }

  const vercelMit = readHeaderCaseInsensitive(headers, 'x-vercel-mitigated').toLowerCase();
  if (vercelMit) {
    return {
      vendor: 'vercel',
      category: vercelMit === 'deny' || vercelMit === 'block' ? 'waf_block' : 'challenge',
      confidence: 1.0,
      signals: [`header:x-vercel-mitigated=${vercelMit}`],
      summary: `Vercel Firewall mitigation (${vercelMit})`,
    };
  }

  const ddHdr = readHeaderCaseInsensitive(headers, 'x-datadome').toLowerCase();
  const ddB = readHeaderCaseInsensitive(headers, 'x-dd-b');
  if ((status === 403 || status === 401 || status === 429) && (ddHdr === 'protected' || Boolean(ddB))) {
    return {
      vendor: 'datadome',
      category: 'challenge',
      confidence: 1.0,
      signals: ['header:x-datadome'],
      summary: 'DataDome anti-bot interstitial',
    };
  }

  const kasadaHdr = readHeaderCaseInsensitive(headers, 'x-kpsdk-ct');
  if (kasadaHdr && (status === 429 || status === 403)) {
    return {
      vendor: 'kasada',
      category: 'challenge',
      confidence: 1.0,
      signals: ['header:x-kpsdk-ct'],
      summary: 'Kasada anti-bot challenge',
    };
  }

  if (readHeaderCaseInsensitive(headers, 'x-px-blocked') === '1') {
    return {
      vendor: 'perimeterx',
      category: 'challenge',
      confidence: 1.0,
      signals: ['header:x-px-blocked=1'],
      summary: 'PerimeterX / HUMAN block interstitial',
    };
  }

  if (!rawBody) return null;
  if (status >= 200 && status < 300 && rawBody.length > 49_152) {
    return null;
  }

  const sample = rawBody.length > 98_304 ? rawBody.slice(0, 98_304) : rawBody;
  const noComments = stripHtmlCommentsLinear(sample, 98_304);
  const visibleClean = stripHtmlTagsLinear(
    noComments,
    ['pre', 'code', 'blockquote', 'textarea', 'svg', 'style', 'script'],
    ' ',
    98_304,
  );
  const visibleWords = stripTagsToWords(visibleClean);

  // --- Layer 2 & Layer 4: Structural Content Veto & Payload Geometry Check on 200 OK ---
  if (status >= 200 && status < 300) {
    if (visibleWords >= 120) return null;
    if (hasRichSchemaJsonLdLinear(sample)) return null;
    let richMain = false;
    replacePairedHtmlElementsLinear(
      visibleClean,
      ['main', 'article'],
      (_full, _t, _a, inner) => {
        if (!richMain && stripTagsToWords(inner) >= 250) richMain = true;
        return '';
      },
      { maxChars: 98_304 },
    );
    if (richMain) return null;

    let subheadingCount = 0;
    replacePairedHtmlElementsLinear(
      visibleClean,
      ['h2', 'h3'],
      () => {
        subheadingCount++;
        return '';
      },
      { maxChars: 98_304 },
    );
    if (subheadingCount >= 2 && visibleWords >= 100) return null;

    let richNav = false;
    replacePairedHtmlElementsLinear(
      noComments,
      ['nav'],
      (_full, _t, _a, inner) => {
        if (!richNav && visibleWords >= 120) {
          let hrefCount = 0;
          scanHtmlTagsLinear(
            inner,
            (tag) => {
              if (!tag.isClosing && tag.tagNameLower === 'a' && /\bhref[ \t\r\n]*=/i.test(tag.attrs)) {
                hrefCount++;
                if (hrefCount >= 4) {
                  richNav = true;
                  return false;
                }
              }
              return undefined;
            },
            98_304,
          );
        }
        return '';
      },
      { maxChars: 98_304 },
    );
    if (richNav) return null;
  }

  // --- Layer 3: Strip <pre>, <code>, <blockquote>, JSON-LD, and hydration JSON before DOM pattern matching ---
  const noDataScripts = replaceHtmlTagBlocksLinear(
    noComments,
    'script',
    (full, attrStr) =>
      /\b(?:type\s*=\s*["']application\/(?:ld\+)?json["']|id\s*=\s*["']__(?:NEXT|NUXT)_DATA__["'])/i.test(attrStr)
        ? ' '
        : full,
    98_304,
  );
  const scrubbed = stripHtmlTagsLinear(
    noDataScripts,
    ['pre', 'code', 'blockquote', 'textarea', 'svg', 'style'],
    ' ',
    98_304,
  );
  const scrubbedLower = asciiLower(scrubbed);
  let title = '';
  replacePairedHtmlElementsLinear(
    scrubbed,
    ['title'],
    (_full, _t, _a, inner) => {
      if (!title) {
        title = stripHtmlTagsQuoteAwareLinear(inner, ' ', 4096).replace(/\s+/g, ' ').trim();
      }
      return '';
    },
    { maxChars: 98_304, maxInnerChars: 4096 },
  );

  const serverHdr = readHeaderCaseInsensitive(headers, 'server').toLowerCase();
  const setCookie = readHeaderCaseInsensitive(headers, 'set-cookie').toLowerCase();
  const isGenericChallengeTitle =
    /^(?:verify you are human|human verification|pardon our interruption|access to this page has been denied|bot verification|security check)$/i.test(
      title,
    );

  // 1. Cloudflare
  if (
    /^(?:just a moment\.{0,3}|attention required!\s*\|\s*cloudflare|ddos-guard|checking your browser)$/i.test(title) ||
    (scrubbedLower.includes('_cf_chl_opt') && scrubbedLower.includes('/cdn-cgi/challenge-platform/')) ||
    (visibleWords < 80 && scrubbedLower.includes('challenges.cloudflare.com/turnstile') && isGenericChallengeTitle)
  ) {
    return {
      vendor: 'cloudflare',
      category: 'challenge',
      confidence: 0.95,
      signals: ['dom:cloudflare-challenge'],
      summary: 'Cloudflare anti-bot challenge page',
    };
  }

  // 2. DataDome
  if (scrubbedLower.includes('geo.captcha-delivery.com') || scrubbedLower.includes('ct.captcha-delivery.com')) {
    return {
      vendor: 'datadome',
      category: 'challenge',
      confidence: 0.96,
      signals: ['dom:captcha-delivery.com'],
      summary: 'DataDome CAPTCHA interstitial',
    };
  }

  // 3. PerimeterX / HUMAN
  if (
    (scrubbedLower.includes('px-captcha') &&
      (scrubbedLower.includes('_pxappid') || scrubbedLower.includes('perimeterx') || setCookie.includes('_pxhd='))) ||
    (scrubbedLower.includes('"appid":"px') && scrubbedLower.includes('"blockscript"'))
  ) {
    return {
      vendor: 'perimeterx',
      category: 'challenge',
      confidence: 0.95,
      signals: ['dom:px-captcha'],
      summary: 'PerimeterX / HUMAN anti-bot challenge',
    };
  }

  // 4. Akamai Bot Manager
  if (
    (serverHdr.includes('akamaighost') || serverHdr.includes('akamai') || setCookie.includes('_abck=') || scrubbedLower.includes('edgesuite.net')) &&
    (/reference\s*#18\.[0-9a-f]{4,}\.[0-9]{6,}/i.test(scrubbed) || (status === 403 && scrubbedLower.includes('edgesuite.net')))
  ) {
    return {
      vendor: 'akamai',
      category: 'waf_block',
      confidence: 0.95,
      signals: ['dom:akamai-reference-18'],
      summary: 'Akamai Bot Manager access denied (Reference #18)',
    };
  }

  // 5. AWS WAF
  if (
    scrubbedLower.includes('awswafintegration') ||
    scrubbedLower.includes('aws-waf-token') ||
    scrubbedLower.includes('awswaf-captcha')
  ) {
    return {
      vendor: 'aws-waf',
      category: 'challenge',
      confidence: 0.94,
      signals: ['dom:awswaf-captcha'],
      summary: 'AWS WAF CAPTCHA interstitial',
    };
  }

  // 6. Imperva / Incapsula
  if (
    scrubbedLower.includes('/_incapsula_resource') ||
    (setCookie.includes('visid_incap_') && scrubbedLower.includes('incapsula incident id'))
  ) {
    return {
      vendor: 'imperva',
      category: 'challenge',
      confidence: 0.96,
      signals: ['dom:_incapsula_resource'],
      summary: 'Imperva Incapsula security interstitial',
    };
  }

  // 7. Fastly WAF 403
  if (
    status === 403 &&
    (serverHdr.includes('fastly') || Boolean(readHeaderCaseInsensitive(headers, 'x-served-by'))) &&
    !scrubbedLower.includes('fastly error: unknown domain') &&
    scrubbedLower.includes('request blocked') &&
    visibleWords < 80
  ) {
    return {
      vendor: 'fastly',
      category: 'waf_block',
      confidence: 0.88,
      signals: ['dom:fastly-403-block'],
      summary: 'Fastly WAF 403 block page',
    };
  }

  // 8. Generic interstitial shell (CAPTCHA widget, NCBI JS browser check, or Anubis PoW gate on < 80-word shell)
  if (visibleWords < 80) {
    if (
      isGenericChallengeTitle &&
      (scrubbedLower.includes('g-recaptcha') || scrubbedLower.includes('h-captcha') || scrubbedLower.includes('cf-turnstile'))
    ) {
      return {
        vendor: 'generic',
        category: 'challenge',
        confidence: 0.88,
        signals: [`title:${title}`],
        summary: `anti-bot challenge page (${title})`,
      };
    }
    if (
      scrubbedLower.includes('checking your browser before accessing ') ||
      scrubbedLower.includes('please wait while we check your browser') ||
      (scrubbedLower.includes("making sure you're not a bot") && scrubbedLower.includes('anubis'))
    ) {
      return {
        vendor: 'generic',
        category: 'challenge',
        confidence: 0.9,
        signals: ['dom:js-pow-interstitial'],
        summary: 'JavaScript / proof-of-work anti-bot interstitial',
      };
    }
  }

  return null;
}

const NON_CONTENT_IFRAME_HOST_RE =
  /(?:googletagmanager\.com|doubleclick\.net|googlesyndication\.com|google-analytics\.com|facebook\.com\/tr|challenges\.cloudflare\.com|recaptcha|hcaptcha|captcha-delivery\.com|_incapsula_resource|js\.stripe\.com|newrelic\.com|demdex\.net)/i;

function readSimpleTagAttr(attrChunk: string, targetKeyLower: string): string {
  const re = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrChunk)) !== null) {
    if (m[1]!.toLowerCase() === targetKeyLower) {
      return (m[2] ?? m[3] ?? m[4] ?? '').trim();
    }
  }
  return '';
}

/**
 * Linear O(N) `<iframe` shell detector for `iCIMS` (`#icims_content_iframe`) and external ATS / widget wrapper pages
 * that return `200 OK` with `< 50` words of outer chrome (`isThinSpa200` / `contentState: 'empty_shell'`).
 */
export function hasExternalOrWidgetIframeLinear(rawHtml: string): {
  found: boolean;
  iframeSrc?: string;
  isIcims?: boolean;
} {
  if (!rawHtml || (rawHtml.indexOf('<iframe') < 0 && rawHtml.indexOf('<IFRAME') < 0 && !/iframe/i.test(rawHtml))) {
    return { found: false };
  }
  let found = false;
  let iframeSrc: string | undefined;
  let isIcims = false;

  scanHtmlTagsLinear(
    rawHtml,
    (tag) => {
      if (tag.isClosing || tag.tagNameLower !== 'iframe') return;
      const id = readSimpleTagAttr(tag.attrs, 'id');
      const name = readSimpleTagAttr(tag.attrs, 'name');
      const cls = readSimpleTagAttr(tag.attrs, 'class');
      const src = readSimpleTagAttr(tag.attrs, 'src') || readSimpleTagAttr(tag.attrs, 'data-src');
      const style = readSimpleTagAttr(tag.attrs, 'style');
      const width = readSimpleTagAttr(tag.attrs, 'width');
      const height = readSimpleTagAttr(tag.attrs, 'height');
      const ariaHidden = readSimpleTagAttr(tag.attrs, 'aria-hidden').toLowerCase();
      if (ariaHidden === 'true') return;
      if (width === '0' || width === '1' || height === '0' || height === '1') return;
      if (style && /(?:display\s*:\s*none|visibility\s*:\s*hidden)/i.test(style)) return;
      if (/\bhidden(?:\s*=\s*(?:""|''|"true"|'true'|"hidden"|'hidden'|true|hidden))?(?=\s|$)/i.test(tag.attrs)) return;

      const combinedMeta = `${id} ${name} ${cls} ${src}`.toLowerCase();
      if (combinedMeta.includes('icims')) {
        found = true;
        isIcims = true;
        if (src) iframeSrc = src;
        return false;
      }
      if (!src || /^(?:about:blank|javascript:|data:)/i.test(src)) return;
      if (NON_CONTENT_IFRAME_HOST_RE.test(src)) return;
      if (/^(?:https?:\/\/|\/\/|\/[A-Za-z0-9_.-])/i.test(src)) {
        found = true;
        iframeSrc = src;
        return false;
      }
      return undefined;
    },
    MAX_HTML_SCAN_CHARS,
    false,
  );

  return {
    found,
    ...(iframeSrc ? { iframeSrc } : {}),
    ...(isIcims ? { isIcims: true } : {}),
  };
}

/**
 * `R4`: Classifies `contentState: "active" | "closed_posting" | "soft_404" | "login_wall" | "empty_shell"` with anti-false-positive
 * word-count & structural vetoes so documentation pages mentioning HTTP 404 or login forms stay `"active"`.
 */
export function classifyContentState(params: {
  status?: number;
  url?: string;
  finalUrl?: string;
  title?: string;
  markdown: string;
  rawHtml?: string;
  validThrough?: string;
  rendered?: boolean;
  nowMs?: number;
}): ContentStateResult {
  const { status = 200, url, finalUrl, title = '', markdown, rawHtml = '', validThrough, rendered = false, nowMs = Date.now() } = params;

  // 0. Deterministic ATS silent-redirect dead-link trap (e.g. closed Greenhouse/Lever/Ashby postings 200-redirect to `?error=true`, board root, or custom `/careers` index!)
  const checkUrlStr = finalUrl || url || '';
  if (checkUrlStr) {
    try {
      const finU = new URL(checkUrlStr);
      const finHost = finU.hostname.toLowerCase();
      const origU = url ? new URL(url) : finU;
      const origHost = origU.hostname.toLowerCase();
      const isGhFinHost =
        finHost === 'boards.greenhouse.io' ||
        finHost === 'job-boards.greenhouse.io' ||
        finHost === 'eu-boards.greenhouse.io' ||
        finHost === 'job-boards.eu.greenhouse.io';
      const isGhOrigHost =
        origHost === 'boards.greenhouse.io' ||
        origHost === 'job-boards.greenhouse.io' ||
        origHost === 'eu-boards.greenhouse.io' ||
        origHost === 'job-boards.eu.greenhouse.io';
      if ((isGhFinHost || isGhOrigHost) && finU.searchParams.get('error') === 'true') {
        return { state: 'closed_posting', reason: 'Greenhouse redirected closed posting to ?error=true.' };
      }
      const ghJobMatch = isGhOrigHost ? /\/jobs\/(\d+)/i.exec(origU.pathname) : null;
      const ghQueryId = origU.searchParams.get('gh_jid');
      const leverJobMatch =
        origHost === 'jobs.lever.co' || origHost === 'jobs.eu.lever.co'
          ? /^\/[^/]+\/([0-9a-f]{8}-[0-9a-f-]{27})\b/i.exec(origU.pathname)
          : null;
      const ashbyJobMatch =
        origHost === 'jobs.ashbyhq.com'
          ? /^\/[^/]+\/([0-9a-f]{8}-[0-9a-f-]{27})\b/i.exec(origU.pathname)
          : null;
      const origJobToken = ghJobMatch?.[1] ?? ghQueryId ?? leverJobMatch?.[1] ?? ashbyJobMatch?.[1];
      if (origJobToken && finalUrl && finalUrl !== url) {
        const finCombined = `${finU.pathname}${finU.search}`.toLowerCase();
        if (!finCombined.includes(origJobToken.toLowerCase())) {
          return {
            state: 'closed_posting',
            reason: 'ATS job posting redirected away from its job ID to a generic careers/board index (role closed).',
          };
        }
      }
    } catch {
      // ignore invalid URL
    }
  }

  // Strip fenced code blocks AND any leaked `<script>` / `<style>` / `<noscript>` / `<template>` blocks in linear O(N) time (`M4`)
  // before matching closed-posting or soft-404 phrases (prevents Dayforce i18n "Page not found!" & Rippling script false positives!).
  const boundedMd = markdown.length > MAX_HTML_SCAN_CHARS ? markdown.slice(0, MAX_HTML_SCAN_CHARS) : markdown;
  const withoutFences = (() => {
    if (boundedMd.indexOf('```') < 0 && boundedMd.indexOf('~~~') < 0) return boundedMd;
    const outLines: string[] = [];
    let fenceChar = '';
    let fenceLen = 0;
    for (const ln of boundedMd.split('\n')) {
      if (!fenceChar) {
        const m = /^[ \t]{0,3}(`{3,}|~{3,})/.exec(ln);
        if (m && (m[1]![0] !== '`' || !ln.slice(m[0].length).includes('`'))) {
          fenceChar = m[1]![0]!;
          fenceLen = m[1]!.length;
          continue;
        }
        outLines.push(ln);
      } else {
        const cm = (fenceChar === '`' ? /^[ \t]{0,3}(`{3,})[ \t\r]*$/ : /^[ \t]{0,3}(~{3,})[ \t\r]*$/).exec(ln);
        if (cm && cm[1]!.length >= fenceLen) {
          fenceChar = '';
          fenceLen = 0;
        }
      }
    }
    return outLines.join('\n');
  })();
  const proseOnly = stripHtmlTagsLinear(withoutFences, ['script', 'style', 'noscript', 'template'], ' ', MAX_HTML_SCAN_CHARS).trim();
  const cleanVisibleHtml = rawHtml
    ? stripHtmlTagsLinear(rawHtml, ['script', 'style', 'noscript', 'template', 'svg'], ' ', MAX_HTML_SCAN_CHARS)
    : '';
  const words = (proseOnly.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
  const topSlice = `${title}\n${proseOnly.slice(0, 900)}`;

  // 1. Closed / expired job posting check
  if (validThrough) {
    const expTs = Date.parse(validThrough);
    if (Number.isFinite(expTs) && expTs < nowMs - 86_400_000) {
      return { state: 'closed_posting', reason: `JobPosting validThrough expired (${validThrough.slice(0, 10)})` };
    }
  }
  if (
    /\b(?:this\s+(?:job|position|role|posting)\s+(?:is\s+no\s+longer|has\s+been\s+(?:filled|closed))|no\s+longer\s+accepting\s+applications|position\s+has\s+been\s+filled|job\s+is\s+no\s+longer\s+(?:open|available|active)|sorry,\s*this\s+job\s+(?:opening\s+)?is\s+closed)\b/i.test(
      topSlice,
    ) &&
    words < 350
  ) {
    return { state: 'closed_posting', reason: 'Page indicates the job posting is closed or no longer accepting applications.' };
  }

  // 2. Soft-404 check (HTTP 200 with a compact "< 120 words" not-found body & 404/not-found title or H1)
  if (status >= 200 && status < 300 && words < 120) {
    const h1Match = /^#\s+([^\n]+)/m.exec(proseOnly);
    const headingText = `${title} ${h1Match?.[1] ?? ''}`.trim();
    const isNotFoundHeading =
      /\b(?:404\b|page\s+not\s+found|job\s+not\s+found|post(?:ing)?\s+not\s+found|couldn['’]t\s+find\s+(?:that|this)\s+page|page\s+doesn['’]t\s+exist)\b/i.test(
        headingText,
      );
    const isNotFoundBody =
      /\b(?:the\s+page\s+you\s+(?:requested|are\s+looking\s+for)\s+(?:could\s+not\s+be\s+found|does\s+not\s+exist)|error\s+404|we\s+can['’]t\s+seem\s+to\s+find\s+the\s+page)\b/i.test(
        proseOnly,
      );
    if (isNotFoundHeading || (words < 60 && isNotFoundBody)) {
      return { state: 'soft_404', reason: 'HTTP 200 response contains a Page Not Found (soft-404) body.' };
    }
  }

  // 3. Login-wall check (thin body < 110 words gated by sign-in prompt or password form outside scripts/templates)
  if (words < 110) {
    let hasPasswordInput = false;
    if (cleanVisibleHtml && (cleanVisibleHtml.includes('password') || cleanVisibleHtml.includes('PASSWORD'))) {
      scanHtmlTagsLinear(
        cleanVisibleHtml,
        (tag) => {
          if (!tag.isClosing && tag.tagNameLower === 'input' && readSimpleTagAttr(tag.attrs, 'type').toLowerCase() === 'password') {
            hasPasswordInput = true;
            return false;
          }
          return undefined;
        },
        MAX_HTML_SCAN_CHARS,
        false,
      );
    }
    const hasLoginGateHeading =
      /^(?:sign\s+in|log\s*in|authentication\s+required|members\s+only)(?:\s+to\s+\S+|\s*[-|–]\s*.*)?$/i.test(title.trim());
    const hasLoginGateCopy =
      /\b(?:sign\s+in\s+to\s+(?:view|read|continue|access)|log\s+in\s+to\s+(?:view|read|continue|access)|please\s+(?:sign|log)\s+in\s+to\s+continue|create\s+a\s+free\s+account\s+to\s+continue\s+reading)\b/i.test(
        topSlice,
      );
    if (hasLoginGateCopy || (hasPasswordInput && (hasLoginGateHeading || words < 65))) {
      return { state: 'login_wall', reason: 'Content is gated behind an authentication / sign-in wall.' };
    }
  }

  // 4. Unrendered thin `<iframe>` shell check (e.g. `#icims_content_iframe` or external ATS/widget iframe with < 50 extracted words)
  if (status >= 200 && status < 300 && words < 50 && !rendered && rawHtml) {
    const iframeShell = hasExternalOrWidgetIframeLinear(rawHtml);
    if (iframeShell.found) {
      return {
        state: 'empty_shell',
        reason: iframeShell.isIcims
          ? 'Unrendered iCIMS ATS iframe shell (#icims_content_iframe) with < 50 words of outer chrome.'
          : 'Unrendered HTML shell (< 50 words) wrapping an external or widget <iframe>.',
      };
    }
  }

  return { state: 'active' };
}

/**
 * `R6`: Recovers rich structured prose, job descriptions, and metadata from Next.js (`__NEXT_DATA__`),
 * Nuxt (`__NUXT_DATA__`), Remix (`window.__remixContext`), or Apollo (`__APOLLO_STATE__`) JSON scripts when visible
 * SSR HTML is thin (`< 80` words) — avoiding headless Chromium latency completely!
 */
export function recoverSsrHydrationContent(
  rawHtml: string,
  baseUrl: string | undefined,
  htmlToMd: HtmlFragmentConverter,
): { title?: string; description?: string; markdown: string; framework: string } | null {
  if (!rawHtml || !rawHtml.includes('<script')) return null;
  const boundedHtml = rawHtml.length > MAX_HTML_SCAN_CHARS ? rawHtml.slice(0, MAX_HTML_SCAN_CHARS) : rawHtml;

  let rawJson = '';
  let framework = '';

  // Linear O(N) `<script>` scanner (`M4`) — avoids quadratic backtracking on adversarial HTML with 20,000 unclosed `<script>` tags!
  replaceHtmlTagBlocksLinear(
    boundedHtml,
    'script',
    (_full, attrStr, inner) => {
      if (rawJson) return '';
      if (/\bid\s*=\s*["']__NEXT_DATA__["']/i.test(attrStr) && inner.trim()) {
        rawJson = inner.trim();
        framework = 'nextjs';
      } else if (/\bid\s*=\s*["']__NUXT_DATA__["']/i.test(attrStr) && inner.trim()) {
        rawJson = inner.trim();
        framework = 'nuxt';
      } else if (inner.includes('__remixContext')) {
        const eqIdx = inner.indexOf('__remixContext');
        const braceStart = inner.indexOf('{', eqIdx);
        const braceEnd = inner.lastIndexOf('}');
        if (braceStart >= 0 && braceEnd > braceStart) {
          rawJson = inner.slice(braceStart, braceEnd + 1).trim();
          framework = 'remix';
        }
      } else if (inner.includes('__APOLLO_STATE__')) {
        const eqIdx = inner.indexOf('__APOLLO_STATE__');
        const braceStart = inner.indexOf('{', eqIdx);
        const braceEnd = inner.lastIndexOf('}');
        if (braceStart >= 0 && braceEnd > braceStart) {
          rawJson = inner.slice(braceStart, braceEnd + 1).trim();
          framework = 'apollo';
        }
      }
      return '';
    },
    MAX_HTML_SCAN_CHARS,
  );

  // Next.js 13–15 App Router RSC Flight stream (`self.__next_f.push([1, "..."])`) recovery!
  if (!rawJson && boundedHtml.includes('__next_f.push')) {
    const rscChunks: string[] = [];
    const rscRe = /self\.__next_f\.push\(\s*\[\s*1\s*,\s*("(?:[^"\\]|\\.)*")\s*\]\s*\)/g;
    let rm: RegExpExecArray | null;
    while ((rm = rscRe.exec(boundedHtml)) !== null && rscChunks.length < 250) {
      try {
        const decoded = JSON.parse(rm[1]!) as string;
        if (typeof decoded === 'string' && decoded.length > 0) rscChunks.push(decoded);
      } catch {
        // skip malformed chunk
      }
    }
    if (rscChunks.length > 0) {
      const combinedRsc = rscChunks.join('');
      const rscBlocks: string[] = [];
      const seenRsc = new Set<string>();
      let rscTitle = '';
      // Extract JSON objects or long prose strings embedded inside RSC Flight lines (`12:["$","div",null,{"children":"..."}]` or `T1f4,...markdown...`)
      for (const strMatch of combinedRsc.matchAll(/"((?:[^"\\]|\\.){80,})"/g)) {
        try {
          const unescaped = JSON.parse(`"${strMatch[1]!}"`) as string;
          const trimmed = unescaped.trim();
          if (!/\s/.test(trimmed.slice(0, 80)) || /^(?:https?:\/\/|\/_next\/)/i.test(trimmed)) continue;
          const converted = /<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|a)\b/i.test(trimmed)
            ? htmlToMd(trimmed, baseUrl).markdown.trim()
            : trimmed;
          const wc = (converted.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
          if (wc >= 25 && !seenRsc.has(converted)) {
            seenRsc.add(converted);
            rscBlocks.push(converted);
          }
        } catch {
          // ignore
        }
      }
      let titleTag = '';
      replacePairedHtmlElementsLinear(
        boundedHtml.slice(0, 65_536),
        ['title'],
        (_f, _t, _a, inner) => {
          if (!titleTag) titleTag = stripHtmlTagsQuoteAwareLinear(inner, ' ', 4096).replace(/\s+/g, ' ').trim();
          return '';
        },
        { maxChars: 65_536, maxInnerChars: 4096 },
      );
      if (titleTag) rscTitle = titleTag;
      // Also capture raw RSC `T<hex>,` text blocks (used by Next.js App Router for large Markdown/prose props!)
      for (const rawBlock of combinedRsc.split(/\n[0-9a-f]+:/i)) {
        const trimmed = rawBlock.replace(/^[0-9a-f]*:?T[0-9a-f]+,/i, '').trim();
        if (trimmed.length >= 140 && !trimmed.startsWith('[') && !trimmed.startsWith('{') && /\s/.test(trimmed.slice(0, 80))) {
          const wc = (trimmed.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
          if (wc >= 30 && !seenRsc.has(trimmed)) {
            seenRsc.add(trimmed);
            rscBlocks.push(trimmed);
          }
        }
      }
      const rscJoined = rscBlocks.join('\n\n').trim();
      if ((rscJoined.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length >= 25) {
        return {
          ...(rscTitle ? { title: rscTitle } : {}),
          markdown: rscTitle && !rscJoined.startsWith('# ') ? `# ${rscTitle}\n\n${rscJoined}` : rscJoined,
          framework: 'nextjs-rsc',
        };
      }
    }
  }

  if (!rawJson || rawJson.length > 2 * 1024 * 1024) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return null;
  }

  // Narrow Next.js to `props.pageProps` first so build manifests / router internals are ignored!
  const rootTarget =
    framework === 'nextjs' &&
    parsed &&
    typeof parsed === 'object' &&
    (parsed as { props?: { pageProps?: unknown } }).props?.pageProps
      ? (parsed as { props: { pageProps: unknown } }).props.pageProps
      : parsed;

  let bestTitle = '';
  let bestDescription = '';
  const richSections: string[] = [];
  const seenBlocks = new Set<string>();
  let visited = 0;

  const RICH_PROSE_KEYS = new Set([
    'content',
    'body',
    'markdown',
    'mdx',
    'articlebody',
    'descriptionhtml',
    'descriptionplain',
    'jobdescription',
    'responsibilities',
    'qualifications',
    'requirements',
    'summary',
    'overview',
    'about',
    'bio',
    'details',
    'text',
  ]);
  const SKIP_KEYS = new Set([
    'buildid',
    'scriptloader',
    '__n_ssg',
    '__n_ssp',
    'assetprefix',
    'runtimeconfig',
    'stylesheet',
    'css',
    'svg',
    'icon',
  ]);

  const walk = (node: unknown, depth: number, keyHint: string) => {
    if (!node || depth > 9 || visited > 1_200) return;
    visited++;

    if (typeof node === 'string') {
      const trimmed = node.trim();
      if (!trimmed) return;
      const lowerKey = keyHint.toLowerCase();
      if (!bestTitle && (lowerKey === 'title' || lowerKey === 'jobtitle' || lowerKey === 'headline') && trimmed.length >= 4 && trimmed.length <= 180) {
        bestTitle = trimmed;
        return;
      }
      if (!bestDescription && (lowerKey === 'description' || lowerKey === 'shortdescription' || lowerKey === 'excerpt') && trimmed.length >= 40 && trimmed.length <= 400 && !/<[a-z]/i.test(trimmed)) {
        bestDescription = trimmed;
      }

      const isRichKey = RICH_PROSE_KEYS.has(lowerKey) || /description|content|markdown|body|overview/i.test(lowerKey);
      if (!isRichKey || trimmed.length < 120) return;
      // Ignore URL/token/JSON/base64 blobs without natural whitespace
      if (!/\s/.test(trimmed.slice(0, 100))) return;

      const converted = /<(?:p|div|ul|ol|li|h[1-6]|section|article|br|strong|a)\b/i.test(trimmed)
        ? htmlToMd(trimmed, baseUrl).markdown.trim()
        : trimmed;
      const wordCount = (converted.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
      if (wordCount >= 25 && !seenBlocks.has(converted)) {
        seenBlocks.add(converted);
        richSections.push(converted);
      }
      return;
    }

    if (Array.isArray(node)) {
      for (const item of node.slice(0, 50)) {
        walk(item, depth + 1, keyHint);
      }
      return;
    }

    if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (SKIP_KEYS.has(k.toLowerCase())) continue;
        walk(v, depth + 1, k);
      }
    }
  };

  walk(rootTarget, 0, '');

  const joined = richSections.join('\n\n').trim();
  const totalWords = (joined.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
  if (totalWords < 35) return null;

  const finalMd = bestTitle && !/^#\s+/.test(joined) ? `# ${bestTitle}\n\n${joined}` : joined;
  return {
    ...(bestTitle ? { title: bestTitle } : {}),
    ...(bestDescription ? { description: bestDescription } : {}),
    markdown: finalMd,
    framework,
  };
}

/**
 * `R8`: Determines whether a failed origin fetch is strictly eligible for Internet Archive (`Wayback CDX`) link-rot
 * recovery: ONLY `5xx` or network/DNS unreachability (`status === 0`), NEVER `robots.txt`, `challenge`, `401`, `403`, `404`, `410`, or `429`!
 */
export function isEligibleForWaybackFallback(params: {
  outcome?: unknown;
  status?: unknown;
  problem?: unknown;
  waf?: WafClassification | null;
}): boolean {
  const outcome = typeof params.outcome === 'string' ? params.outcome.toLowerCase() : '';
  const prob = typeof params.problem === 'string' ? params.problem.toLowerCase() : '';
  const status = typeof params.status === 'number' ? params.status : 0;

  if (params.waf) return false;
  if (
    outcome === 'challenge' ||
    outcome === 'robots_disallowed' ||
    outcome === 'robots_unreachable' ||
    outcome === 'content_signal_disallowed' ||
    outcome === 'payment_required' ||
    outcome === 'rate_limited'
  ) {
    return false;
  }
  if (
    prob.includes('robots.txt') ||
    prob.includes('robots_unreachable') ||
    prob.includes('content-signal') ||
    prob.includes('ai-input=no') ||
    prob.includes('challenge') ||
    prob.includes('cf-mitigated') ||
    prob.includes('ssrf') ||
    prob.includes('non-public ip')
  ) {
    return false;
  }
  if (
    status === 401 ||
    status === 402 ||
    status === 403 ||
    status === 404 ||
    status === 410 ||
    status === 429 ||
    status === 451
  ) {
    return false;
  }
  return status === 0 || (status >= 500 && status <= 599);
}

/**
 * `R8`: Queries `https://archive.org/wayback/available?url=...` and fetches the closest clean HTTP 200 snapshot via
 * `executeHubFetch` (strictly respecting `archive.org` & `web.archive.org` `robots.txt`).
 */
export async function tryFetchWaybackSnapshot(params: {
  url: string;
  target: 'auto' | 'agent' | 'container';
  site?: string;
  source: string;
  executeHubFetch: (
    target: 'auto' | 'agent' | 'container',
    body: string,
    site?: string,
    source?: string,
    artifactRetention?: 'transient' | 'stored' | 'off',
    hydrateInline?: boolean,
  ) => Promise<{ status: number; via: string; bodyText: string }>;
}): Promise<{ snapshotUrl: string; timestamp: string; rawBody: string; contentType: string; via: string } | null> {
  const availApiUrl = `https://archive.org/wayback/available?url=${encodeURIComponent(params.url)}`;
  try {
    const cdxRes = await params.executeHubFetch(
      params.target,
      JSON.stringify({
        maxSeconds: 20,
        options: { includeBody: true, respectRobots: true },
        requests: [{ id: 'wb-avail-1', url: availApiUrl, kind: 'json', accept: 'application/json' }],
      }),
      params.site,
      `${params.source}:wayback-cdx`,
      'off',
      true,
    );
    if (cdxRes.status !== 200) return null;
    const cdxParsed = JSON.parse(cdxRes.bodyText) as { results?: Array<Record<string, unknown>> };
    const cdxItem = cdxParsed.results?.[0];
    if (cdxItem?.outcome !== 'ok' || typeof cdxItem.body !== 'string') return null;

    const avail = JSON.parse(cdxItem.body) as {
      archived_snapshots?: {
        closest?: { available?: boolean; url?: string; timestamp?: string; status?: string };
      };
    };
    const closest = avail.archived_snapshots?.closest;
    if (!closest?.available || typeof closest.url !== 'string' || !closest.timestamp) return null;
    if (closest.status && closest.status !== '200') return null;

    // Upgrade http://web.archive.org to https://web.archive.org and use `id_/` raw replay modifier to avoid Wayback toolbar HTML injection!
    const snapParsed = new URL(closest.url.replace(/^http:\/\//i, 'https://'));
    if (snapParsed.hostname.toLowerCase() !== 'web.archive.org') return null;
    const idReplayPath = snapParsed.pathname.replace(/^\/web\/(\d{14})(?:[a-z_]*)\//, '/web/$1id_/');
    snapParsed.pathname = idReplayPath;
    const cleanSnapUrl = snapParsed.toString();

    const snapRes = await params.executeHubFetch(
      params.target,
      JSON.stringify({
        maxSeconds: 30,
        options: { includeBody: true, respectRobots: true },
        requests: [{ id: 'wb-snap-1', url: cleanSnapUrl, kind: 'scrape', formats: ['markdown'] }],
      }),
      params.site,
      `${params.source}:wayback-snap`,
      'transient',
      true,
    );
    if (snapRes.status !== 200) return null;
    const snapReply = JSON.parse(snapRes.bodyText) as { results?: Array<Record<string, unknown>> };
    const snapItem = snapReply.results?.[0];
    const snapBody = typeof snapItem?.body === 'string' && snapItem.bodyEncoding !== 'base64' ? snapItem.body : '';
    if (snapItem?.outcome !== 'ok' || !snapBody.trim()) return null;

    return {
      snapshotUrl: closest.url.replace(/^http:\/\//i, 'https://'),
      timestamp: closest.timestamp,
      rawBody: snapBody,
      contentType: typeof snapItem.contentType === 'string' ? snapItem.contentType : 'text/html',
      via: snapRes.via,
    };
  } catch {
    return null;
  }
}

/**
 * Post-processes `buildBlockedInfo` output across `mcp.ts` and `scrape.ts` so:
 *  - Unreachable `/robots.txt` (`robots_unreachable: ...` or `outcome === 'stop'` with unreachable/timed-out `/robots.txt`)
 *    emits `reason: 'robots_unreachable'` per RFC 9309 §2.3.1.4 instead of claiming the site disallows the path.
 *  - `icims.com` (`*.icims.com`) is treated as the employer's official ATS rather than a third-party job aggregator.
 *  - Non-challenge HTTP `429` responses carry `reason: 'rate_limited'` with `retryAfterMs` when available.
 */
export function refineBlockedInfo(params: {
  url: string;
  outcome?: unknown;
  problem?: unknown;
  status?: unknown;
  retryAfter?: unknown;
  baseBlocked: unknown;
  nowMs?: number;
}): Record<string, unknown> | undefined {
  const { url, outcome, problem, status, retryAfter, nowMs = Date.now() } = params;
  const baseBlocked =
    params.baseBlocked && typeof params.baseBlocked === 'object' && !Array.isArray(params.baseBlocked)
      ? (params.baseBlocked as Record<string, unknown>)
      : undefined;
  let host = '';
  try {
    host = new URL(url).hostname.toLowerCase().replace(/\.+$/, '');
  } catch {
    host = '';
  }
  const outStr = typeof outcome === 'string' ? outcome.trim().toLowerCase() : '';
  const probStr = typeof problem === 'string' ? problem.trim() : '';

  if (
    probStr.toLowerCase().startsWith('robots_unreachable') ||
    ((outStr === 'stop' || outStr === 'robots_unreachable' || outStr === 'error') &&
      /robots\.txt[\s\S]{0,180}?(?:unreachable|timed out|returned http (?:5\d\d|429)|budget exhausted|redirect failed|unexpected http)/i.test(
        probStr,
      ))
  ) {
    const labelHost = host || 'origin';
    return {
      reason: 'robots_unreachable',
      host: labelHost,
      suggestion: `${labelHost}'s /robots.txt timed out or returned 5xx (disallow assumed temporarily per RFC 9309 §2.3.1.4). Retry shortly.`,
    };
  }

  let retryAfterMs: number | undefined;
  if (typeof retryAfter === 'string' && retryAfter.trim()) {
    const trimmed = retryAfter.trim();
    if (/^\d+$/.test(trimmed)) {
      const secs = Number(trimmed);
      if (Number.isFinite(secs) && secs >= 0) retryAfterMs = secs * 1_000;
    } else {
      const parsedDate = Date.parse(trimmed);
      if (Number.isFinite(parsedDate)) retryAfterMs = Math.max(0, parsedDate - nowMs);
    }
  }

  if ((status === 429 || outStr === 'rate_limited') && outStr !== 'challenge' && baseBlocked?.reason !== 'challenge') {
    const labelHost = host || (typeof baseBlocked?.host === 'string' ? baseBlocked.host : 'origin');
    return {
      ...(baseBlocked ?? {}),
      reason: 'rate_limited',
      host: labelHost,
      ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
      suggestion:
        typeof baseBlocked?.suggestion === 'string' &&
        baseBlocked.suggestion &&
        !/disallows\s+this\s+path\s+in\s+robots\.txt/i.test(baseBlocked.suggestion)
          ? baseBlocked.suggestion
          : `${labelHost} returned HTTP 429 Too Many Requests${retryAfterMs !== undefined ? ` (Retry-After: ${Math.ceil(retryAfterMs / 1000)}s)` : ''}. Wait out the cooldown window before retrying.`,
    };
  }

  if (baseBlocked && (host === 'icims.com' || host.endsWith('.icims.com'))) {
    const sug = typeof baseBlocked.suggestion === 'string' ? baseBlocked.suggestion : '';
    if (/aggregator|go\s+directly\s+to\s+the\s+employer|board\s+instead\s+of\s+job\s+boards/i.test(sug) || baseBlocked.category === 'aggregator') {
      const copy = { ...baseBlocked };
      delete copy.category;
      copy.suggestion = `${host} is the employer's iCIMS ATS portal. Try rendering with browser / ?in_iframe=1 or check if the employer mirrors openings on its main careers site.`;
      return copy;
    }
  }

  return baseBlocked ?? undefined;
}
