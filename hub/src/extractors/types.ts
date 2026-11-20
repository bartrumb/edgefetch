/**
 * EdgeFetch Contributor-Friendly Site Adapter SDK (`hub/src/extractors/types.ts`).
 *
 * Every built-in and community adapter lives in its own self-contained file under
 * `hub/src/extractors/providers/<category>/<slug>.ts` and exports `defineAdapter({ ... })`.
 *
 * Security & Ethics Invariant:
 *  - Adapters NEVER make raw `fetch()` calls. `resolveTwin()` returns a declarative `https://`
 *    `SiteExtractorTwin` descriptor that EdgeFetch executes through `executeHubFetch`, guaranteeing
 *    `robots.txt` checks, dial-time SSRF protection, per-host politeness, and OTLP tracing.
 *  - Zero paid B2B API keys: built-in adapters target public, keyless endpoints or structured HTML.
 */

export type AdapterCategory =
  | 'developer'
  | 'genai'
  | 'jobs'
  | 'finance'
  | 'public-records'
  | 'research-health'
  | 'commerce-social';

export interface TwinFormattedDoc {
  title: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  markdown: string;
  links?: string[];
}

export interface HtmlFragmentConverter {
  (htmlFragment: string, baseUrl?: string): {
    markdown: string;
    links: string[];
  };
}

export interface SiteExtractorTwin {
  id: string;
  fetchUrl: string;
  kind: 'json' | 'text';
  accept: string;
  formatTwin: (rawBody: string, originalUrl: string, htmlToMd: HtmlFragmentConverter) => TwinFormattedDoc | null;
}

export interface PostFetchSiteResult {
  extractorId: string;
  title?: string;
  description?: string;
  author?: string;
  publishedTime?: string;
  markdown: string;
  links?: string[];
}

export interface TwinMatchContext {
  url: URL;
  urlStr: string;
  host: string;
  path: string;
  parts: string[];
}

export interface HtmlExtractContext {
  url: URL;
  baseUrl: string;
  host: string;
  path: string;
  parts: string[];
  rawHtml: string;
  currentMd: string;
  htmlToMd: HtmlFragmentConverter;
}

export interface SiteAdapter {
  /** Unique kebab-case identifier (e.g. `sec-edgar`, `socrata`, `npm-registry`). */
  id: string;
  /** Human-readable provider name shown in `GET /v1/extractors` and docs. */
  name: string;
  /** Functional category folder under `hub/src/extractors/providers/<category>/`. */
  category: AdapterCategory;
  /** Concise summary of what structured data or cleanup this adapter provides. */
  description: string;
  /**
   * Hostnames handled by this adapter:
   *  - Exact hostnames (`npmjs.com`, `www.npmjs.com`) are indexed in an O(1) `Map`.
   *  - Leading-wildcard suffixes (`*.stackexchange.com`, `*.myshopify.com`, `*.legistar.com`) match subdomains.
   *  - Prefix wildcards (`gitlab.*`) match host prefixes.
   */
  domains: string[];
  /**
   * Set `true` when the adapter detects a multi-domain platform engine on arbitrary custom domains
   * (e.g. Discourse `/t/<slug>/<id>`, Mastodon `/@user/<id>`, MediaWiki, Socrata, CKAN, ArcGIS, Shopify).
   */
  universalEngine?: boolean;
  /** One or more sample `https://` URLs used for documentation and automated self-tests. */
  exampleUrls: string[];
  /** Optional pre-fetch 1-hop upgrade to an official public JSON, Markdown, or patch endpoint. */
  resolveTwin?: (ctx: TwinMatchContext) => SiteExtractorTwin | null;
  /** Optional post-fetch HTML / DOM / Markdown extractor when live HTML was retrieved. */
  extractHtml?: (ctx: HtmlExtractContext) => PostFetchSiteResult | null;
}

export interface AdapterCatalogEntry {
  id: string;
  name: string;
  category: AdapterCategory;
  description: string;
  modes: Array<'twin' | 'html' | 'ats'>;
  domains: string[];
  universalEngine: boolean;
  exampleUrls: string[];
}

/** Type-safe helper for authoring self-contained adapters in `hub/src/extractors/providers/`. */
export function defineAdapter(adapter: SiteAdapter): SiteAdapter {
  return adapter;
}
