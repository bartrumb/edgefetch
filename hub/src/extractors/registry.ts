/**
 * Modular Site Adapter Registry (`SCRAPE_PIPELINE_VERSION = 21`).
 *
 *  - O(1) exact-domain lookup (`Map<hostname, SiteAdapter[]>`) + suffix/prefix wildcard matchers +
 *    universal multi-domain platform engines (Socrata, Shopify, ArcGIS, Discourse, Mastodon, MediaWiki, Jibe/RMK).
 *  - Enforces strict `https://` SSRF-safe twin URL validation before returning any `SiteExtractorTwin`.
 *  - Exposes `listRegisteredAdapters()` for `GET /v1/extractors` and automated fixture testing.
 */

import { runAdapterSyncInBulkhead } from '../adapter-sandbox';
import {
  enrichShopifyProductFromJson,
  enrichWooCommerceProductFromStoreApi,
  extractShopifyCurrencyFromHtml,
  isShopifyHtmlOrHeaders,
  isWooCommerceHtmlOrHeaders,
  normalizeShopifyProductRecord,
  normalizeWooCommerceProductRecord,
  resolveCustomDomainShopifyProductTwinUrl,
  resolveCustomDomainWooCommerceProductTwinUrl,
} from './commerce-engine';
import { DECLARATIVE_SITE_ADAPTERS } from './declarative';
import type {
  AdapterCatalogEntry,
  AdapterCategory,
  CatalogRecord,
  CatalogSpec,
  CatalogVariantRecord,
  HtmlFragmentConverter,
  PaginationInfo,
  PostFetchSiteResult,
  SiteAdapter,
  SiteExtractorTwin,
  TwinFormattedDoc,
} from './types';
import { formatYamlFrontmatterCard, unescapeHrefUrl } from './utils';

export { defineAdapter } from './types';
export type {
  AdapterCatalogEntry,
  AdapterCategory,
  CatalogRecord,
  CatalogSpec,
  CatalogVariantRecord,
  HtmlFragmentConverter,
  PaginationInfo,
  PostFetchSiteResult,
  SiteAdapter,
  SiteExtractorTwin,
  TwinFormattedDoc,
};
export {
  enrichShopifyProductFromJson,
  enrichWooCommerceProductFromStoreApi,
  extractShopifyCurrencyFromHtml,
  formatYamlFrontmatterCard,
  isShopifyHtmlOrHeaders,
  isWooCommerceHtmlOrHeaders,
  normalizeShopifyProductRecord,
  normalizeWooCommerceProductRecord,
  resolveCustomDomainShopifyProductTwinUrl,
  resolveCustomDomainWooCommerceProductTwinUrl,
  unescapeHrefUrl,
};

interface WildcardRule {
  kind: 'suffix' | 'prefix' | 'infix';
  prefix?: string;
  suffix?: string;
  adapter: SiteAdapter;
}

class AdapterRegistryIndex {
  readonly all: SiteAdapter[] = [];
  readonly byExactHost = new Map<string, SiteAdapter[]>();
  readonly wildcards: WildcardRule[] = [];
  readonly universalEngines: SiteAdapter[] = [];

  constructor(adapters: readonly SiteAdapter[]) {
    for (const a of adapters) {
      this.register(a);
    }
  }

  register(adapter: SiteAdapter): void {
    this.all.push(adapter);
    for (const rawPattern of adapter.domains) {
      const pat = rawPattern.trim().toLowerCase();
      if (!pat) continue;
      if (pat.startsWith('*.') && !pat.slice(2).includes('*')) {
        this.wildcards.push({ kind: 'suffix', suffix: pat.slice(1), adapter }); // `.stackexchange.com`
      } else if (pat.endsWith('.*') && !pat.slice(0, -2).includes('*')) {
        this.wildcards.push({ kind: 'prefix', prefix: pat.slice(0, -1), adapter }); // `gitlab.`
      } else if (pat.includes('*')) {
        const [pre, suf] = pat.split('*', 2);
        this.wildcards.push({ kind: 'infix', prefix: pre ?? '', suffix: suf ?? '', adapter });
      } else {
        const bucket = this.byExactHost.get(pat);
        if (bucket) {
          if (!bucket.includes(adapter)) bucket.push(adapter);
        } else {
          this.byExactHost.set(pat, [adapter]);
        }
      }
    }
    if (adapter.universalEngine) {
      this.universalEngines.push(adapter);
    }
  }

  candidatesForHost(host: string): SiteAdapter[] {
    const seen = new Set<SiteAdapter>();
    const out: SiteAdapter[] = [];
    const push = (a: SiteAdapter) => {
      if (!seen.has(a)) {
        seen.add(a);
        out.push(a);
      }
    };

    const exact = this.byExactHost.get(host);
    if (exact) {
      for (const a of exact) push(a);
    }
    for (const w of this.wildcards) {
      if (w.kind === 'suffix' && w.suffix && host.endsWith(w.suffix) && host.length > w.suffix.length) {
        push(w.adapter);
      } else if (w.kind === 'prefix' && w.prefix && host.startsWith(w.prefix) && host.length > w.prefix.length) {
        push(w.adapter);
      } else if (w.kind === 'infix' && host.startsWith(w.prefix ?? '') && host.endsWith(w.suffix ?? '')) {
        push(w.adapter);
      }
    }
    for (const u of this.universalEngines) {
      push(u);
    }
    return out;
  }
}

const ALL_REGISTERED_ADAPTERS: SiteAdapter[] = [...DECLARATIVE_SITE_ADAPTERS];

const DEFAULT_INDEX = new AdapterRegistryIndex(ALL_REGISTERED_ADAPTERS);

/** Looks up a registered declarative `SiteAdapter` by exact `id`. */
export function getRegisteredAdapterById(id: string): SiteAdapter {
  const found = DEFAULT_INDEX.all.find((a) => a.id === id);
  if (!found) {
    throw new Error(`Missing required declarative site adapter "${id}"`);
  }
  return found;
}

export const shopifyAdapter: SiteAdapter = getRegisteredAdapterById('shopify');
export const woocommerceAdapter: SiteAdapter = getRegisteredAdapterById('woocommerce');
export const icimsAdapter: SiteAdapter = getRegisteredAdapterById('icims');

/** Go worker `classify.AcceptFor(KindText, ...)` strict MIME allowlist (`internal/classify/classify.go`). */
export const GO_KIND_TEXT_ACCEPT_ALLOWLIST = new Set([
  'text/html',
  'text/markdown',
  'text/x-markdown',
  'application/xml',
  'text/xml',
  'application/rss+xml',
  'application/atom+xml',
  'application/json',
  'text/calendar',
  'text/plain',
]);

function normalizeTwinAcceptForGo(kind: string, rawAccept: string): string {
  if (kind !== 'text') return rawAccept;
  const trimmed = rawAccept.trim().toLowerCase();
  if (GO_KIND_TEXT_ACCEPT_ALLOWLIST.has(trimmed)) return trimmed;
  const primary = trimmed.split(',')[0]?.split(';')[0]?.trim() ?? '';
  if (GO_KIND_TEXT_ACCEPT_ALLOWLIST.has(primary)) return primary;
  return 'text/plain';
}

/** Validates that a twin target URL is strictly `https://` with no embedded credentials, fragments, or loopback/rebinding hosts. */
function isSafePublicTwinUrl(fetchUrl: string): boolean {
  try {
    const u = new URL(fetchUrl);
    if (u.protocol !== 'https:' || u.username || u.password || u.hash) return false;
    if (u.port && u.port !== '443') return false;
    const rawHost = u.hostname.toLowerCase();
    const h = rawHost.endsWith('.') ? rawHost.slice(0, -1) : rawHost;
    if (
      !h ||
      !h.includes('.') ||
      h === 'localhost' ||
      h.endsWith('.localhost') ||
      h.endsWith('.local') ||
      h.endsWith('.internal') ||
      h.endsWith('.nip.io') ||
      h.endsWith('.sslip.io') ||
      h.endsWith('.xip.io') ||
      /^\d+\.\d+\.\d+\.\d+$/.test(h) ||
      h.includes(':')
    ) {
      return false;
    }
    const lastLabel = h.slice(h.lastIndexOf('.') + 1);
    if (!lastLabel || /^\d+$/.test(lastLabel)) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolves a pre-fetch 1-hop JSON / raw / XML / patch twin endpoint when a URL matches a registered adapter.
 * Returns `null` when standard HTML fetching should proceed.
 */
export function resolveSiteExtractorTwin(urlStr: string): SiteExtractorTwin | null {
  if (!urlStr || urlStr !== urlStr.trim() || /[\s\\\u0000-\u001f\u007f]/.test(urlStr)) {
    return null;
  }
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username !== '' || u.password !== '') return null;
  if (u.port !== '' && u.port !== '443') return null;
  // Reject non-ASCII or percent-encoded/empty-label raw authority before WHATWG host normalization
  const authSlice = urlStr.slice(8, urlStr.indexOf('/', 8) >= 0 ? urlStr.indexOf('/', 8) : urlStr.length);
  const hostOnlyRaw = authSlice.split(/[?#]/)[0]!.replace(/:443$/, '');
  if (!hostOnlyRaw || /[^\x21-\x7e%]/.test(hostOnlyRaw) || hostOnlyRaw.includes('%') || hostOnlyRaw.includes('..')) {
    return null;
  }
  if (!isSafePublicTwinUrl(`https://${u.hostname}/`)) return null;
  const host = u.hostname.toLowerCase();
  const path = u.pathname;
  const parts = path.split('/').filter(Boolean);
  const ctx = { url: u, urlStr, host, path, parts };

  for (const adapter of DEFAULT_INDEX.candidatesForHost(host)) {
    if (!adapter.resolveTwin) continue;
    const twinRes = runAdapterSyncInBulkhead(adapter.id, (inp) => adapter.resolveTwin!(inp), ctx);
    if (!twinRes.ok) continue;
    const twin = twinRes.value;
    if (twin && isSafePublicTwinUrl(twin.fetchUrl)) {
      const rawFormat = twin.formatTwin;
      return {
        ...twin,
        accept: normalizeTwinAcceptForGo(twin.kind, twin.accept),
        formatTwin: (rawBody, originalUrl, htmlToMd) => {
          const fmtRes = runAdapterSyncInBulkhead(
            adapter.id,
            (inp) => rawFormat(inp.rawBody, inp.originalUrl, inp.htmlToMd),
            { rawBody, originalUrl, htmlToMd },
          );
          // Fault-isolated bulkhead: if an upstream JSON schema changes or adapter throws (including network attempts),
          // return null so EdgeFetch automatically falls back to standard HTML / JSON-LD / SSR / CDP extraction!
          return fmtRes.ok ? fmtRes.value : null;
        },
      };
    }
  }
  return null;
}

/**
 * Applies platform-specific post-fetch DOM or Markdown extraction when `baseUrl` matches a registered adapter.
 */
export function applyPostFetchSiteExtractor(
  rawHtml: string,
  baseUrl: string | undefined,
  currentMd: string,
  htmlToMd: HtmlFragmentConverter,
): PostFetchSiteResult | null {
  if (!baseUrl) return null;
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  const path = u.pathname;
  const parts = path.split('/').filter(Boolean);
  const ctx = { url: u, baseUrl, host, path, parts, rawHtml, currentMd, htmlToMd };

  for (const adapter of DEFAULT_INDEX.candidatesForHost(host)) {
    if (!adapter.extractHtml) continue;
    // Fault-isolated zero-network bulkhead: never let a DOM change, network call, or buggy community adapter fail a scrape!
    const res = runAdapterSyncInBulkhead(adapter.id, (inp) => adapter.extractHtml!(inp), ctx);
    if (res.ok && res.value && res.value.markdown.trim()) {
      return res.value;
    }
  }
  return null;
}

/** Built-in dedicated ATS adapters implemented in `hub/src/jobs.ts` (`resolveAtsPreFetchSpec`). */
const BUILTIN_ATS_CORE_CATALOG: AdapterCatalogEntry[] = [
  {
    id: 'ashby',
    name: 'Ashby ATS Job Boards & Compensation API',
    category: 'jobs',
    description: 'Upgrades jobs.ashbyhq.com/<org> boards and postings to api.ashbyhq.com/posting-api/job-board/<org>?includeCompensation=true.',
    modes: ['ats'],
    domains: ['jobs.ashbyhq.com'],
    universalEngine: false,
    exampleUrls: ['https://jobs.ashbyhq.com/linear'],
  },
  {
    id: 'workday-cxs',
    name: 'Workday CXS Career Portals',
    category: 'jobs',
    description: 'Upgrades <tenant>.wd<N>.myworkdayjobs.com career boards and job postings to Workday /wday/cxs JSON endpoints.',
    modes: ['ats'],
    domains: ['*.myworkdayjobs.com', '*.myworkdaysite.com'],
    universalEngine: false,
    exampleUrls: ['https://cloudflare.wd1.myworkdayjobs.com/External'],
  },
  {
    id: 'greenhouse-job',
    name: 'Greenhouse Single-Job Postings (US & EU)',
    category: 'jobs',
    description: 'Upgrades Greenhouse job URLs to boards-api.[eu.]greenhouse.io/v1/boards/<org>/jobs/<id>?content=true with normalized pay_input_ranges.',
    modes: ['ats'],
    domains: ['boards.greenhouse.io', 'job-boards.greenhouse.io', 'eu-boards.greenhouse.io', 'job-boards.eu.greenhouse.io'],
    universalEngine: false,
    exampleUrls: ['https://job-boards.greenhouse.io/cloudflare/jobs/6123456'],
  },
  {
    id: 'lever-job',
    name: 'Lever Single-Job Postings (US & EU)',
    category: 'jobs',
    description: 'Upgrades jobs.[eu.]lever.co/<org>/<id> postings to api.[eu.]lever.co/v0/postings/<org>/<id> with salaryRange normalization.',
    modes: ['ats'],
    domains: ['jobs.lever.co', 'jobs.eu.lever.co'],
    universalEngine: false,
    exampleUrls: ['https://jobs.lever.co/mistral/01234567-89ab-cdef-0123-456789abcdef'],
  },
];

/** Returns all registered Site & ATS Adapters for `GET /v1/extractors`, CLI/SDK inspection, and test verification. */
export function listRegisteredAdapters(categoryFilter?: string): AdapterCatalogEntry[] {
  const fromModular: AdapterCatalogEntry[] = DEFAULT_INDEX.all.map((a) => {
    const modes: Array<'twin' | 'html' | 'ats' | 'catalog'> = [];
    if (a.resolveTwin) modes.push('twin');
    if (a.extractHtml) modes.push('html');
    if (a.catalog) modes.push('catalog');
    return {
      id: a.id,
      name: a.name,
      category: a.category,
      description: a.description,
      modes,
      domains: [...a.domains],
      universalEngine: Boolean(a.universalEngine),
      exampleUrls: [...a.exampleUrls],
    };
  });

  const combined = [...fromModular, ...BUILTIN_ATS_CORE_CATALOG];
  if (!categoryFilter) return combined;
  const norm = categoryFilter.trim().toLowerCase();
  return combined.filter((c) => c.category === norm);
}

/** Exposes raw `SiteAdapter` objects for automated test validation. */
export function getRawRegisteredSiteAdapters(): readonly SiteAdapter[] {
  return DEFAULT_INDEX.all;
}

/** Returns all registered `SiteAdapter` definitions that implement a `CatalogSpec` (`shopify`, `woocommerce`, etc.). */
export function listCatalogAdapters(): SiteAdapter[] {
  return DEFAULT_INDEX.all.filter((a) => Boolean(a.catalog));
}

/** Looks up a `CatalogSpec`-capable `SiteAdapter` by platform identifier (`shopify`, `woocommerce`). */
export function getCatalogAdapter(platform: string): SiteAdapter | null {
  const norm = platform.trim().toLowerCase();
  return DEFAULT_INDEX.all.find((a) => a.catalog && a.catalog.platform.toLowerCase() === norm) ?? null;
}
