/**
 * Linear `64 KiB` Web Framework & Platform Detector (`hub/src/framework-detect.ts`).
 *
 * Security & Performance Contract:
 *  1. Strictly linear O(N) bounded to the first `FRAMEWORK_DETECT_WINDOW_CHARS` (`65_536` UTF-16 code units = 64 KiB).
 *     Markers at offset >= 65_536 are NEVER scanned during detection. Zero unbounded regular expressions.
 *  2. Quote- and attribute-order-agnostic `<meta name=generator>` scanner (`scanGeneratorMetaTagsLinear`) collects ALL
 *     generator tags (e.g. Astro + Starlight dual metas, unquoted `name=generator` in Hugo/MkDocs, single-quoted
 *     content-first `<meta content='blogger' name='generator'/>` in Blogger/Webflow, capitalized `Generator` in Drupal).
 *  3. Detection is an extraction quality hint ONLY — never a security/trust gate. Every downstream extractor must remain
 *     linear and size-bounded on arbitrary adversarial input regardless of `detected`.
 *  4. Tracker/widget scripts (`hs-analytics`, `MktoForms2`, `app.ecwid.com/script.js`, bare `cdn.shopify.com` preconnects)
 *     never classify a host as running that platform without a structural platform marker.
 */

export const FRAMEWORK_DETECT_WINDOW_CHARS = 65_536;

export const SAFE_RESPONSE_HEADER_ALLOWLIST: readonly string[] = [
  'server',
  'powered-by',
  'x-powered-by',
  'x-generator',
  'x-shopid',
  'x-shopify-stage',
  'x-wix-request-id',
  'x-drupal-cache',
  'x-drupal-dynamic-cache',
  'x-nextjs-cache',
  'x-remix-response',
  'x-vercel-id',
  'x-nf-request-id',
  'x-github-request-id',
  'x-hs-hub-id',
  'x-typo3-parsetime',
  'cf-ray',
  'cf-cache-status',
  'cf-mitigated',
  'via',
  'vary',
  'link',
  'x-robots-tag',
  'content-signal',
  'x-markdown-tokens',
  'cache-control',
] as const;

export interface BrowserFrameworkGlobals {
  next?: boolean;
  nuxt?: boolean;
  remix?: boolean;
  reactRouter?: boolean;
  sveltekit?: boolean;
  angular?: boolean;
  qwik?: boolean;
  solid?: boolean;
  shopify?: boolean;
  wp?: boolean;
  webflow?: boolean;
  squarespace?: boolean;
  wix?: boolean;
}

export interface DetectedSiteStack {
  source: 'html' | 'origin-markdown' | 'headers-only';
  platform?: string;
  framework?: string;
  generators: string[];
  signals: string[];
  contentFlags?: string[];
}

function isAsciiWs(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0c || code === 0x0d;
}

function isAttrNameChar(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) || // A-Z
    (code >= 0x61 && code <= 0x7a) || // a-z
    (code >= 0x30 && code <= 0x39) || // 0-9
    code === 0x2d || // -
    code === 0x5f || // _
    code === 0x3a // :
  );
}

function decodeBasicHtmlEntities(s: string): string {
  if (!s.includes('&')) return s;
  return s
    .replace(/&quot;/gi, '"')
    .replace(/&#34;/g, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&#39;/g, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&');
}

/**
 * Linearly scans `<meta ...>` tags inside the first `maxChars` (`64 KiB` default) and returns EVERY `<meta name="generator">`
 * `content` value in document order — supporting unquoted attributes, single/double quotes, `content` before `name`, and
 * case-insensitive `Generator`.
 */
export function scanGeneratorMetaTagsLinear(html: string, maxChars = FRAMEWORK_DETECT_WINDOW_CHARS): string[] {
  const limit = Math.min(html.length, maxChars);
  const generators: string[] = [];
  let pos = 0;

  while (pos < limit) {
    const lt = html.indexOf('<', pos);
    if (lt < 0 || lt + 5 >= limit) break;

    const c1 = html.charCodeAt(lt + 1) | 0x20;
    const c2 = html.charCodeAt(lt + 2) | 0x20;
    const c3 = html.charCodeAt(lt + 3) | 0x20;
    const c4 = html.charCodeAt(lt + 4) | 0x20;
    const c5 = html.charCodeAt(lt + 5);
    if (c1 !== 0x6d || c2 !== 0x65 || c3 !== 0x74 || c4 !== 0x61 || !(isAsciiWs(c5) || c5 === 0x2f || c5 === 0x3e)) {
      pos = lt + 1;
      continue;
    }

    let cur = lt + 5;
    let metaName = '';
    let metaContent = '';
    let closed = false;

    while (cur < limit) {
      while (cur < limit && (isAsciiWs(html.charCodeAt(cur)) || html.charCodeAt(cur) === 0x2f)) cur++;
      if (cur >= limit) break;
      if (html.charCodeAt(cur) === 0x3e) {
        closed = true;
        cur++;
        break;
      }

      const nameStart = cur;
      while (cur < limit && isAttrNameChar(html.charCodeAt(cur))) cur++;
      if (cur === nameStart) {
        // Malformed byte inside `<meta ...>`: skip one char to guarantee strict forward progress.
        cur++;
        continue;
      }
      const attrName = html.slice(nameStart, cur).toLowerCase();

      while (cur < limit && isAsciiWs(html.charCodeAt(cur))) cur++;
      let attrVal = '';
      if (cur < limit && html.charCodeAt(cur) === 0x3d /* = */) {
        cur++;
        while (cur < limit && isAsciiWs(html.charCodeAt(cur))) cur++;
        if (cur < limit) {
          const q = html.charCodeAt(cur);
          if (q === 0x22 || q === 0x27) {
            cur++;
            const valStart = cur;
            const qStr = q === 0x22 ? '"' : "'";
            const closeQ = html.indexOf(qStr, cur);
            if (closeQ < 0 || closeQ >= limit) {
              cur = limit;
              break;
            }
            attrVal = html.slice(valStart, closeQ);
            cur = closeQ + 1;
          } else {
            const valStart = cur;
            while (cur < limit && !isAsciiWs(html.charCodeAt(cur)) && html.charCodeAt(cur) !== 0x3e) {
              cur++;
            }
            // Strip trailing self-close `/` on unquoted `content=Hugo/` only when immediately followed by `>`.
            let valEnd = cur;
            if (valEnd > valStart && html.charCodeAt(valEnd - 1) === 0x2f && cur < limit && html.charCodeAt(cur) === 0x3e) {
              valEnd--;
            }
            attrVal = html.slice(valStart, valEnd);
          }
        }
      }

      if (attrName === 'name') metaName = attrVal.trim().toLowerCase();
      else if (attrName === 'content') metaContent = decodeBasicHtmlEntities(attrVal).trim();
    }

    if (closed && metaName === 'generator' && metaContent) {
      generators.push(metaContent.slice(0, 160));
      if (generators.length >= 8) break;
    }
    pos = cur > lt ? cur : lt + 1;
  }

  return generators;
}

/** Filters an arbitrary header bag down to `SAFE_RESPONSE_HEADER_ALLOWLIST` (never exposing `set-cookie` secrets). */
export function filterSafeResponseHeaders(
  rawHeaders: Record<string, string | undefined> | Headers | undefined,
): Record<string, string> | undefined {
  if (!rawHeaders) return undefined;
  const out: Record<string, string> = {};
  let count = 0;
  for (const key of SAFE_RESPONSE_HEADER_ALLOWLIST) {
    const val =
      typeof (rawHeaders as Headers).get === 'function'
        ? (rawHeaders as Headers).get(key)
        : (rawHeaders as Record<string, string | undefined>)[key] ??
          (rawHeaders as Record<string, string | undefined>)[key.toLowerCase()];
    if (typeof val === 'string' && val.trim()) {
      out[key] = val.trim().slice(0, 512);
      count++;
    }
  }
  return count > 0 ? out : undefined;
}

/**
 * Detects platform and framework from bounded `64 KiB` HTML or `origin-markdown` text, safe response headers,
 * hostname suffixes, and optional browser globals. Runs in `< 1 ms` on 64 KiB and `< 1 ms` on 1 MiB adversarial inputs.
 */
export function detectSiteFrameworkLinear(params: {
  url?: string;
  body?: string;
  contentSource?: 'html' | 'origin-markdown';
  headers?: Record<string, string | undefined> | Headers;
  globals?: BrowserFrameworkGlobals;
}): DetectedSiteStack {
  const rawBody = params.body ?? '';
  const win = rawBody.length > FRAMEWORK_DETECT_WINDOW_CHARS ? rawBody.slice(0, FRAMEWORK_DETECT_WINDOW_CHARS) : rawBody;
  const signals: string[] = [];
  const contentFlags: string[] = [];
  let platform: string | undefined;
  let framework: string | undefined;

  let host = '';
  if (params.url) {
    try {
      host = new URL(params.url).hostname.toLowerCase();
    } catch {
      host = '';
    }
  }

  const safeHeaders = filterSafeResponseHeaders(params.headers) ?? {};
  const poweredBy = `${safeHeaders['powered-by'] ?? ''} ${safeHeaders['x-powered-by'] ?? ''}`.toLowerCase();
  const xGen = (safeHeaders['x-generator'] ?? '').toLowerCase();
  const linkHdr = (safeHeaders.link ?? '').toLowerCase();

  // 1. Header signals (fast, high-signal when present)
  if (safeHeaders['x-shopid'] || safeHeaders['x-shopify-stage'] || poweredBy.includes('shopify')) {
    platform = 'shopify';
    signals.push('header:shopify');
  } else if (safeHeaders['x-wix-request-id']) {
    platform = 'wix';
    signals.push('header:x-wix-request-id');
  } else if (safeHeaders['x-drupal-cache'] || safeHeaders['x-drupal-dynamic-cache'] || xGen.startsWith('drupal')) {
    platform = 'drupal';
    signals.push('header:drupal');
  } else if (linkHdr.includes('https://api.w.org/')) {
    platform = 'wordpress';
    signals.push('header:api.w.org');
  } else if (poweredBy.includes('craft cms')) {
    platform = 'craft-cms';
    signals.push('header:craft-cms');
  } else if (safeHeaders['x-typo3-parsetime']) {
    platform = 'typo3';
    signals.push('header:typo3');
  }
  if (linkHdr.includes('rel="ucp"') || linkHdr.includes('/.well-known/ucp')) {
    contentFlags.push('ucp');
  }
  if (poweredBy.includes('next.js') || safeHeaders['x-nextjs-cache']) {
    framework = 'nextjs';
    signals.push('header:nextjs');
  } else if (safeHeaders['x-remix-response']) {
    framework = 'remix';
    signals.push('header:remix');
  }

  // 2. Hostname suffix signals (unforgeable by page body)
  if (!platform && host) {
    if (host.endsWith('.myshopify.com')) {
      platform = 'shopify';
      signals.push('host:myshopify.com');
    } else if (host.endsWith('.notion.site')) {
      platform = 'notion';
      signals.push('host:notion.site');
    } else if (host.endsWith('.godaddysites.com')) {
      platform = 'godaddy-builder';
      signals.push('host:godaddysites.com');
    } else if (host.endsWith('.jimdosite.com')) {
      platform = 'jimdo';
      signals.push('host:jimdosite.com');
    } else if (host.endsWith('.bigcartel.com')) {
      platform = 'big-cartel';
      signals.push('host:bigcartel.com');
    } else if (host.endsWith('.square.site')) {
      platform = 'square-online';
      signals.push('host:square.site');
    } else if (host.endsWith('.mybigcommerce.com')) {
      platform = 'bigcommerce';
      signals.push('host:mybigcommerce.com');
    } else if (host.endsWith('.mykajabi.com')) {
      platform = 'kajabi';
      signals.push('host:mykajabi.com');
    } else if (host.endsWith('.teachable.com')) {
      platform = 'teachable';
      signals.push('host:teachable.com');
    } else if (host.endsWith('.thinkific.com')) {
      platform = 'thinkific';
      signals.push('host:thinkific.com');
    } else if (host.endsWith('.blogspot.com')) {
      platform = 'blogger';
      signals.push('host:blogspot.com');
    } else if (host.endsWith('.framer.website')) {
      platform = 'framer';
      signals.push('host:framer.website');
    } else if (host.endsWith('.my.site.com')) {
      platform = 'salesforce-experience-cloud';
      signals.push('host:my.site.com');
    }
  }

  // 3. Origin-negotiated Markdown path (`contentSource === 'origin-markdown'`)
  if (params.contentSource === 'origin-markdown') {
    if (
      win.includes('built and hosted on [Mintlify]') ||
      win.includes('mintlify.com') ||
      (win.includes('> ## Documentation Index') && (win.includes('## Agent Instructions') || win.includes('?ask=')))
    ) {
      platform = platform ?? 'mintlify';
      signals.push('md:mintlify');
    } else if (win.includes('This documentation is published with GitBook.')) {
      platform = platform ?? 'gitbook';
      signals.push('md:gitbook');
    } else if (win.includes('agentTools:') && win.includes('projectIndex:')) {
      platform = platform ?? 'readme';
      signals.push('md:readme-frontmatter');
    } else if (win.includes('cdn11.bigcommerce.com/s-')) {
      platform = platform ?? 'bigcommerce';
      signals.push('md:bigcommerce-cdn');
    } else if (win.includes('/fileadmin/') && (win.includes('/extension-storage/_processed_/') || win.includes('cHash='))) {
      platform = platform ?? 'typo3';
      signals.push('md:typo3-paths');
    }
    if (!framework && win.includes('/_astro/')) {
      framework = 'astro';
      signals.push('md:astro-assets');
    } else if (!framework && win.includes('/_next/')) {
      framework = 'nextjs';
      signals.push('md:nextjs-assets');
    }
    if (win.includes('Documentation Index') && win.includes('/llms.txt')) {
      contentFlags.push('llms-index');
    }
    if (win.includes('## Agent Instructions') || win.includes('?ask=<question>&goal=')) {
      contentFlags.push('agent-instructions');
    }
    return {
      source: 'origin-markdown',
      ...(platform ? { platform } : {}),
      ...(framework ? { framework } : {}),
      generators: [],
      signals,
      ...(contentFlags.length > 0 ? { contentFlags } : {}),
    };
  }

  if (!win) {
    return {
      source: 'headers-only',
      ...(platform ? { platform } : {}),
      ...(framework ? { framework } : {}),
      generators: [],
      signals,
      ...(contentFlags.length > 0 ? { contentFlags } : {}),
    };
  }

  // 4. HTML `<meta name="generator">` multi-tag scan (first 64 KiB)
  const generators = scanGeneratorMetaTagsLinear(win, FRAMEWORK_DETECT_WINDOW_CHARS);
  for (const gen of generators) {
    const g = gen.toLowerCase();
    if (g.startsWith('starlight ')) {
      platform = platform ?? 'starlight';
      framework = framework ?? 'astro';
      signals.push('generator:starlight');
    } else if (g.startsWith('astro ')) {
      framework = framework ?? 'astro';
      signals.push('generator:astro');
    } else if (g.startsWith('hugo ')) {
      framework = framework ?? 'hugo';
      signals.push('generator:hugo');
    } else if (g.startsWith('docusaurus')) {
      platform = platform ?? 'docusaurus';
      framework = framework ?? 'react';
      signals.push('generator:docusaurus');
    } else if (g.startsWith('vitepress')) {
      platform = platform ?? 'vitepress';
      framework = framework ?? 'vue';
      signals.push('generator:vitepress');
    } else if (g.startsWith('vuepress')) {
      platform = platform ?? 'vuepress';
      framework = framework ?? 'vue';
      signals.push('generator:vuepress');
    } else if (g.startsWith('hexo ')) {
      framework = framework ?? 'hexo';
      signals.push('generator:hexo');
    } else if (g.startsWith('antora ')) {
      platform = platform ?? 'antora';
      signals.push('generator:antora');
    } else if (g.startsWith('mkdocs-')) {
      platform = g.includes('mkdocs-material') ? 'mkdocs-material' : 'mkdocs';
      signals.push('generator:mkdocs');
    } else if (g.startsWith('jekyll ')) {
      framework = framework ?? 'jekyll';
      signals.push('generator:jekyll');
    } else if (g.startsWith('eleventy')) {
      framework = framework ?? 'eleventy';
      signals.push('generator:eleventy');
    } else if (g.startsWith('next.js')) {
      framework = framework ?? 'nextjs';
      signals.push('generator:nextjs');
    } else if (g.startsWith('gatsby')) {
      framework = framework ?? 'gatsby';
      signals.push('generator:gatsby');
    } else if (g.includes('woocommerce')) {
      if (!platform || platform === 'wordpress') platform = 'woocommerce';
      framework = framework ?? 'wordpress';
      signals.push('generator:woocommerce');
    } else if (g.startsWith('wordpress')) {
      platform = platform ?? 'wordpress';
      signals.push('generator:wordpress');
    } else if (g.startsWith('drupal')) {
      platform = platform ?? 'drupal';
      signals.push('generator:drupal');
    } else if (g.startsWith('joomla!')) {
      platform = platform ?? 'joomla';
      signals.push('generator:joomla');
    } else if (g.startsWith('ghost ')) {
      platform = platform ?? 'ghost';
      signals.push('generator:ghost');
    } else if (g === 'webflow' || g.startsWith('webflow ')) {
      platform = platform ?? 'webflow';
      signals.push('generator:webflow');
    } else if (g.startsWith('wix.com website builder')) {
      platform = platform ?? 'wix';
      signals.push('generator:wix');
    } else if (g === 'blogger') {
      platform = platform ?? 'blogger';
      signals.push('generator:blogger');
    } else if (g === 'big cartel') {
      platform = platform ?? 'big-cartel';
      signals.push('generator:big-cartel');
    } else if (g === 'square online') {
      platform = platform ?? 'square-online';
      signals.push('generator:square-online');
    } else if (g === 'mystmd') {
      platform = platform ?? 'mystmd';
      signals.push('generator:mystmd');
    } else if (g.startsWith('starfield technologies; go daddy')) {
      platform = platform ?? 'godaddy-builder';
      signals.push('generator:godaddy-builder');
    } else if (g.startsWith('jimdo')) {
      platform = platform ?? 'jimdo';
      signals.push('generator:jimdo');
    }
  }

  // 5. Verified structural HTML literals in the first 64 KiB (pure `includes` checks -> linear O(N))
  if (
    (!platform || platform === 'wordpress') &&
    (win.includes('/wp-content/plugins/woocommerce/') || (win.includes('/wp-content/') && win.includes('woocommerce')))
  ) {
    platform = 'woocommerce';
    framework = framework ?? 'wordpress';
    signals.push('html:woocommerce');
  }
  if (!platform) {
    if (
      win.includes('shopify.exit_interstitial') ||
      win.includes('Shopify.shop =') ||
      win.includes('shopify-digital-wallet') ||
      (win.includes('cdn.shopify.com/s/files/') && win.includes('Shopify'))
    ) {
      platform = 'shopify';
      signals.push('html:shopify');
    } else if (win.includes('/wp-content/plugins/woocommerce/') || (win.includes('/wp-content/') && win.includes('woocommerce'))) {
      platform = 'woocommerce';
      signals.push('html:woocommerce');
    } else if (win.includes('/wp-content/') && win.includes('/wp-includes/')) {
      platform = 'wordpress';
      signals.push('html:wp-content+wp-includes');
    } else if (win.includes('<!-- This is Squarespace. -->') || win.includes('Static.SQUARESPACE_CONTEXT')) {
      platform = 'squarespace';
      signals.push('html:squarespace');
    } else if (win.includes('id="wix-viewer-model"') || win.includes("id='wix-viewer-model'")) {
      platform = 'wix';
      signals.push('html:wix-viewer-model');
    } else if (win.includes('data-wf-site=') || win.includes('<!-- This site was created in Webflow.')) {
      platform = 'webflow';
      signals.push('html:webflow');
    } else if (win.includes('data-notion-html=')) {
      platform = 'notion';
      signals.push('html:notion');
    } else if (win.includes('id="gh-members-styles"') || win.includes('data-ghost=')) {
      platform = 'ghost';
      signals.push('html:ghost');
    } else if (win.includes('data-drupal-link-system-path=')) {
      platform = 'drupal';
      signals.push('html:drupal');
    } else if (win.includes('class="joomla-script-options')) {
      platform = 'joomla';
      signals.push('html:joomla');
    } else if (win.includes("xmlns:b='http://www.google.com/2005/gml/b'") || win.includes('xmlns:b="http://www.google.com/2005/gml/b"')) {
      platform = 'blogger';
      signals.push('html:blogger');
    } else if (win.includes('<!-- Served from Big Cartel Storefront -->')) {
      platform = 'big-cartel';
      signals.push('html:big-cartel');
    } else if (win.includes('data-role="square-online-featureflags"')) {
      platform = 'square-online';
      signals.push('html:square-online');
    } else if (win.includes('catalog/view/theme/') && win.includes('route=')) {
      platform = 'opencart';
      signals.push('html:opencart');
    } else if (win.includes('window.Thinkific')) {
      platform = 'thinkific';
      signals.push('html:thinkific');
    } else if (win.includes('teachablecdn.com') && win.includes('/l/_next/')) {
      platform = 'teachable';
      signals.push('html:teachable');
    } else if (win.includes('cdn.podia.com/assets/storefront')) {
      platform = 'podia';
      signals.push('html:podia');
    } else if (win.includes('window.bubble_session_uid')) {
      platform = 'bubble';
      signals.push('html:bubble');
    } else if (win.includes('window.dmAPI') && win.includes('cdn-website.com')) {
      platform = 'duda';
      signals.push('html:duda');
    } else if (win.includes('substackcdn.com/bundle/static/') || win.includes('window._preloads')) {
      platform = 'substack';
      signals.push('html:substack');
    } else if (win.includes('id="__docusaurus"')) {
      platform = 'docusaurus';
      signals.push('html:docusaurus');
    } else if (win.includes('class="VPContent') || win.includes('vitepress-theme-appearance')) {
      platform = 'vitepress';
      signals.push('html:vitepress');
    } else if (win.includes('data-md-component=')) {
      platform = 'mkdocs-material';
      signals.push('html:mkdocs-material');
    } else if (win.includes('window.$docsify')) {
      platform = 'docsify';
      signals.push('html:docsify');
    } else if (win.includes('swagger-ui-bundle.js') && win.includes('id="swagger-ui"')) {
      platform = 'swagger-ui';
      signals.push('html:swagger-ui');
    } else if (win.includes('sb-manager/') && win.includes('STORYBOOK_')) {
      platform = 'storybook';
      signals.push('html:storybook');
    }
  }

  if (!framework) {
    if (win.includes('data-next-head=')) {
      framework = 'nextjs-pages';
      signals.push('html:data-next-head');
    } else if (win.includes('/_next/static/immutable/') || win.includes('data-precedence="next"') || win.includes('self.__next_f.push(')) {
      framework = 'nextjs-app';
      signals.push('html:nextjs-app');
    } else if (win.includes('id="__NEXT_DATA__"') || win.includes('/_next/static/')) {
      framework = 'nextjs';
      signals.push('html:nextjs');
    } else if (win.includes('/_nuxt/') || win.includes('id="__NUXT_DATA__"')) {
      framework = 'nuxt';
      signals.push('html:nuxt');
    } else if (win.includes('/_app/immutable/') || win.includes('data-sveltekit-')) {
      framework = 'sveltekit';
      signals.push('html:sveltekit');
    } else if (win.includes('/_astro/') || win.includes('data-astro-cid-')) {
      framework = 'astro';
      signals.push('html:astro');
    } else if (win.includes('q:container=')) {
      framework = 'qwik';
      signals.push('html:qwik');
    } else if (win.includes('data-hk=') && win.includes('_$HY')) {
      framework = 'solid';
      signals.push('html:solid');
    } else if (win.includes('data-page="{&quot;component&quot;') || win.includes("data-page='{\"component\"")) {
      framework = 'inertia';
      signals.push('html:inertia-data-page');
    } else if (win.includes('livewireautofill') || win.includes('wire:snapshot=')) {
      framework = 'livewire';
      signals.push('html:livewire');
    } else if (win.includes('id="blazor-error-ui"') || win.includes('_framework/blazor.')) {
      framework = 'blazor';
      signals.push('html:blazor');
    } else if (win.includes('ng-version="') || win.includes('id="ng-state"')) {
      framework = 'angular';
      signals.push('html:angular');
    } else if (win.includes('ng-app=')) {
      framework = 'angularjs';
      signals.push('html:angularjs');
    } else if (win.includes('/config/environment"')) {
      framework = 'ember';
      signals.push('html:ember');
    } else if (win.includes('id="___gatsby"')) {
      framework = 'gatsby';
      signals.push('html:gatsby');
    } else if (win.includes('/assets/manifest-') && win.includes('entry.client-')) {
      framework = 'react-router-v7';
      signals.push('html:react-router-v7');
    } else if (win.includes('window.__remixContext')) {
      framework = 'remix';
      signals.push('html:remix');
    } else if (win.includes('hx-get=') || win.includes('hx-post=') || win.includes('hx-boost=')) {
      framework = 'htmx';
      signals.push('html:htmx');
    } else if (win.includes('x-data=')) {
      framework = 'alpine';
      signals.push('html:alpine');
    }
  }

  if (framework?.startsWith('nextjs') && !platform && win.includes('--nextra-primary-hue')) {
    platform = 'nextra';
    signals.push('html:nextra');
  }

  // 6. Browser globals (only present when rendered via CDP)
  const g = params.globals;
  if (g) {
    if (!platform && g.shopify) {
      platform = 'shopify';
      signals.push('global:Shopify');
    } else if (!platform && g.wp) {
      platform = 'wordpress';
      signals.push('global:wp');
    } else if (!platform && g.squarespace) {
      platform = 'squarespace';
      signals.push('global:Squarespace');
    } else if (!platform && g.webflow) {
      platform = 'webflow';
      signals.push('global:Webflow');
    } else if (!platform && g.wix) {
      platform = 'wix';
      signals.push('global:wix');
    }
    if (!framework && g.next) {
      framework = 'nextjs';
      signals.push('global:__NEXT_DATA__');
    } else if (!framework && g.nuxt) {
      framework = 'nuxt';
      signals.push('global:__NUXT__');
    } else if (!framework && g.remix) {
      framework = 'remix';
      signals.push('global:__remixContext');
    } else if (!framework && g.reactRouter) {
      framework = 'react-router';
      signals.push('global:__reactRouterContext');
    } else if (!framework && g.angular) {
      framework = 'angular';
      signals.push('global:ng');
    }
  }

  return {
    source: 'html',
    ...(platform ? { platform } : {}),
    ...(framework ? { framework } : {}),
    generators,
    signals,
    ...(contentFlags.length > 0 ? { contentFlags } : {}),
  };
}

/**
 * Extracts Inertia.js `data-page="{&quot;component&quot;:...}"` serialized page props linearly (capped at `512 KiB`)
 * so Laravel/Rails Inertia SPA shells yield structured props without requiring headless Chromium.
 */
export function extractInertiaPagePropsLinear(rawHtml: string, maxScanChars = 524_288): Record<string, unknown> | null {
  const limit = Math.min(rawHtml.length, maxScanChars);
  const slice = rawHtml.length > limit ? rawHtml.slice(0, limit) : rawHtml;
  const dqIdx = slice.indexOf('data-page="{&quot;component&quot;');
  const sqIdx = dqIdx < 0 ? slice.indexOf("data-page='{\"component\"") : -1;
  if (dqIdx < 0 && sqIdx < 0) return null;

  const isDouble = dqIdx >= 0;
  const startVal = (isDouble ? dqIdx : sqIdx) + 'data-page='.length + 1;
  const closeQuote = slice.indexOf(isDouble ? '"' : "'", startVal);
  if (closeQuote < 0 || closeQuote - startVal > 262_144) return null;

  const decoded = decodeBasicHtmlEntities(slice.slice(startVal, closeQuote));
  try {
    const parsed = JSON.parse(decoded) as Record<string, unknown>;
    return parsed && typeof parsed === 'object' && typeof parsed.component === 'string' ? parsed : null;
  } catch {
    return null;
  }
}
