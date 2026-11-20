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

export type ContentState = 'active' | 'closed_posting' | 'soft_404' | 'login_wall';

export interface ContentStateResult {
  state: ContentState;
  reason?: string;
}

export type HtmlFragmentConverter = (html: string, baseUrl?: string) => { markdown: string; links: string[] };

function stripTagsToWords(htmlFragment: string): number {
  const plain = htmlFragment
    .replace(/<[^>]+>/g, ' ')
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

const RICH_SCHEMA_TYPE_RE =
  /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>[\s\S]{0,16000}?"@type"\s*:\s*(?:\[[^\]]*)?["'](?:Article|TechArticle|NewsArticle|BlogPosting|ScholarlyArticle|JobPosting|Product|SoftwareSourceCode|FAQPage|APIReference)["']/i;

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
  const noComments = sample.replace(/<!--[\s\S]*?-->/g, ' ');
  const visibleClean = noComments
    .replace(/<(?:pre|code|blockquote|textarea|svg|style)\b[^>]*>[\s\S]*?<\/(?:pre|code|blockquote|textarea|svg|style)>/gi, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ');
  const visibleWords = stripTagsToWords(visibleClean);

  // --- Layer 2 & Layer 4: Structural Content Veto & Payload Geometry Check on 200 OK ---
  if (status >= 200 && status < 300) {
    if (visibleWords >= 120) return null;
    if (RICH_SCHEMA_TYPE_RE.test(sample)) return null;
    const mainMatch = /<(?:main|article)\b[^>]*>([\s\S]*?)<\/(?:main|article)>/i.exec(visibleClean);
    if (mainMatch?.[1] && stripTagsToWords(mainMatch[1]) >= 250) return null;
    const subheadings = visibleClean.match(/<h[23]\b[^>]*>[\s\S]*?<\/h[23]>/gi) ?? [];
    if (subheadings.length >= 2 && visibleWords >= 100) return null;
    for (const nm of noComments.matchAll(/<nav\b[^>]*>([\s\S]*?)<\/nav>/gi)) {
      const navLinks = nm[1]?.match(/<a\b[^>]*\bhref\s*=/gi) ?? [];
      if (navLinks.length >= 4 && visibleWords >= 120) return null;
    }
  }

  // --- Layer 3: Strip <pre>, <code>, <blockquote>, JSON-LD, and hydration JSON before DOM pattern matching ---
  const scrubbed = noComments
    .replace(/<script\b[^>]*(?:type\s*=\s*["']application\/(?:ld\+)?json["']|id\s*=\s*["']__(?:NEXT|NUXT)_DATA__["'])[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<(?:pre|code|blockquote|textarea|svg|style)\b[^>]*>[\s\S]*?<\/(?:pre|code|blockquote|textarea|svg|style)>/gi, ' ');
  const scrubbedLower = scrubbed.toLowerCase();
  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(scrubbed);
  const title = titleMatch?.[1] ? titleMatch[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() : '';

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

  // 8. Generic interstitial shell
  if (
    isGenericChallengeTitle &&
    visibleWords < 80 &&
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

  return null;
}

/**
 * `R4`: Classifies `contentState: "active" | "closed_posting" | "soft_404" | "login_wall"` with anti-false-positive
 * word-count & structural vetoes so documentation pages mentioning HTTP 404 or login forms stay `"active"`.
 */
export function classifyContentState(params: {
  status?: number;
  url?: string;
  title?: string;
  markdown: string;
  rawHtml?: string;
  validThrough?: string;
  nowMs?: number;
}): ContentStateResult {
  const { status = 200, title = '', markdown, rawHtml = '', validThrough, nowMs = Date.now() } = params;

  // Strip fenced code blocks before checking prose phrases so docs about HTTP 404 or login flows never false-positive!
  const proseOnly = markdown.replace(/```[\s\S]*?```|~~~[\s\S]*?~~~/g, ' ').trim();
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

  // 3. Login-wall check (thin body < 110 words gated by sign-in prompt or password form)
  if (words < 110) {
    const hasPasswordInput = /<input\b[^>]*\btype\s*=\s*["']password["']/i.test(rawHtml);
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

  let rawJson = '';
  let framework = '';

  const nextMatch = /<script\b[^>]*\bid\s*=\s*["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i.exec(rawHtml);
  if (nextMatch?.[1]) {
    rawJson = nextMatch[1].trim();
    framework = 'nextjs';
  } else {
    const nuxtMatch = /<script\b[^>]*\bid\s*=\s*["']__NUXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i.exec(rawHtml);
    if (nuxtMatch?.[1]) {
      rawJson = nuxtMatch[1].trim();
      framework = 'nuxt';
    } else {
      const remixMatch = /window\.__remixContext\s*=\s*(\{[\s\S]*?\})\s*;?\s*<\/script>/i.exec(rawHtml);
      if (remixMatch?.[1]) {
        rawJson = remixMatch[1].trim();
        framework = 'remix';
      } else {
        const apolloMatch = /window\.__APOLLO_STATE__\s*=\s*(\{[\s\S]*?\})\s*;?\s*<\/script>/i.exec(rawHtml);
        if (apolloMatch?.[1]) {
          rawJson = apolloMatch[1].trim();
          framework = 'apollo';
        }
      }
    }
  }

  // Next.js 13–15 App Router RSC Flight stream (`self.__next_f.push([1, "..."])`) recovery!
  if (!rawJson && rawHtml.includes('__next_f.push')) {
    const rscChunks: string[] = [];
    const rscRe = /self\.__next_f\.push\(\s*\[\s*1\s*,\s*("(?:[^"\\]|\\.)*")\s*\]\s*\)/g;
    let rm: RegExpExecArray | null;
    while ((rm = rscRe.exec(rawHtml)) !== null) {
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
      const titleTag = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(rawHtml)?.[1]?.trim() ?? '';
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
  if (outcome === 'challenge' || outcome === 'robots_disallowed') return false;
  if (prob.includes('robots.txt') || prob.includes('challenge') || prob.includes('cf-mitigated') || prob.includes('ssrf') || prob.includes('non-public ip')) {
    return false;
  }
  if (status === 401 || status === 403 || status === 404 || status === 410 || status === 429 || status === 451) {
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
