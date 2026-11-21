# Site & ATS Extractor SDK and Registry (`hub/src/extractors`)

## Overview

Defines the keyless `SiteAdapter` SDK (`types.ts`), shared HTML/JSON/GFM parsing and sanitization utilities (`utils.ts`), and the indexed host/wildcard/universal-engine adapter dispatcher (`registry.ts`) for EdgeFetch. Coordinates pre-fetch 1-hop declarative `SiteExtractorTwin` upgrades (`resolveSiteExtractorTwin`), post-fetch live HTML/DOM/Markdown extraction (`applyPostFetchSiteExtractor`), and adapter catalog introspection (`listRegisteredAdapters`) across all built-in provider packages.

## Interface

- `[types.ts:AdapterCategory]`, `[types.ts:TwinFormattedDoc]`, `[types.ts:HtmlFragmentConverter]`, `[types.ts:SiteExtractorTwin]`, `[types.ts:PostFetchSiteResult]`, `[types.ts:TwinMatchContext]`, `[types.ts:HtmlExtractContext]`, `[types.ts:SiteAdapter]`, `[types.ts:AdapterCatalogEntry]` — Core TypeScript contracts for authoring and executing declarative pre-fetch twins and post-fetch HTML extractors (re-exported by `registry.ts` except `TwinMatchContext` and `HtmlExtractContext`).
- `[types.ts:defineAdapter]` — `(adapter: SiteAdapter) => SiteAdapter` type-safe authoring helper (re-exported as `[registry.ts:defineAdapter]`).
- `[registry.ts:resolveSiteExtractorTwin]` — `(urlStr: string) => SiteExtractorTwin | null` resolves an incoming `https://` URL against `DEFAULT_INDEX` to a validated 1-hop `SiteExtractorTwin` descriptor with an exception-safe `formatTwin` wrapper.
- `[registry.ts:applyPostFetchSiteExtractor]` — `(rawHtml: string, baseUrl: string | undefined, currentMd: string, htmlToMd: HtmlFragmentConverter) => PostFetchSiteResult | null` runs candidate `extractHtml` hooks on fetched HTML and returns the first non-empty Markdown extraction.
- `[registry.ts:listRegisteredAdapters]` — `(categoryFilter?: string) => AdapterCatalogEntry[]` returns defensive catalog metadata combining the 54 modular `SiteAdapter` entries with the 4 `BUILTIN_ATS_CORE_CATALOG` entries (`'ashby'`, `'workday-cxs'`, `'greenhouse-job'`, `'lever-job'`).
- `[registry.ts:getRawRegisteredSiteAdapters]` — `() => readonly SiteAdapter[]` exposes `DEFAULT_INDEX.all` for automated test verification.
- `[utils.ts:CODE_EXT_FENCE_MAP]`, `[utils.ts:safeFence]`, `[utils.ts:detectFenceLang]` — Extension-to-language mapping (`42` extensions), collision-safe Markdown code fencing, and filename language/Markdown detection.
- `[utils.ts:decodeBasicEntities]`, `[utils.ts:stripTagsInline]`, `[utils.ts:unescapeHrefUrl]`, `[utils.ts:stripScriptsAndStyles]` — HTML entity decoding, inline tag stripping, query-safe `href` `&amp;` unescaping (re-exported as `[registry.ts:unescapeHrefUrl]`), and `<script>`/`<style>`/`<svg>` removal.
- `[utils.ts:parseJsonObject]`, `[utils.ts:parseJsonValue]` — Exception-free, UTF-8 BOM-tolerant JSON parsers.
- `[utils.ts:escapeGfmCell]`, `[utils.ts:formatGfmTable]`, `[utils.ts:formatUsdCompact]`, `[utils.ts:formatYamlFrontmatterCard]` — GFM table cell sanitization/building, compact USD formatting, and bounded YAML frontmatter-to-GFM card conversion (re-exported as `[registry.ts:formatYamlFrontmatterCard]`).
- `[utils.ts:extractMetaContent]`, `[utils.ts:extractAllMetaContents]`, `[utils.ts:extractJsonLdObjects]`, `[utils.ts:extractBalancedDivAt]` — Bounded `<meta>`, `<script type="application/ld+json">`, and nested `<div>` HTML extractors.
- [Built-In Site Adapter Providers](./providers/EGM.md) — Barrel registry (`BUILTIN_SITE_ADAPTERS`) and 7 category subpackages housing 54 keyless `SiteAdapter` modules.

## Invariants

- `[types.ts:SiteAdapter]`, `[types.ts:SiteExtractorTwin]` — Keyless, zero-I/O adapter contract: adapters never invoke `fetch()` directly; `resolveTwin` returns a declarative `SiteExtractorTwin` descriptor executed through the hub fetch pipeline (`robots.txt`, dial-time SSRF protection, politeness, and tracing).
- `[registry.ts:AdapterRegistryIndex]`, `[registry.ts:DEFAULT_INDEX]` — Indexes normalized lowercase domain patterns into O(1) exact-host `Map<string, SiteAdapter[]>`, strict subdomain/prefix/infix `WildcardRule` lists, and `universalEngine` adapters; `candidatesForHost` evaluates deduplicated candidates strictly in `exact -> wildcards -> universalEngines` order.
- `[registry.ts:isSafePublicTwinUrl]`, `[registry.ts:resolveSiteExtractorTwin]` — Requires input `urlStr` and resolved `twin.fetchUrl` to use `protocol === 'https:'` with empty `username`/`password` and a non-empty hostname that is not `'localhost'`, does not end with `'.local'` or `'.internal'`, does not match IPv4 literal `/^\d+\.\d+\.\d+\.\d+$/`, and contains no `':'` (rejecting IPv6 literals).
- `[registry.ts:resolveSiteExtractorTwin]`, `[registry.ts:applyPostFetchSiteExtractor]` — Fault-isolated execution bulkheads: uncaught exceptions inside `adapter.resolveTwin`, `twin.formatTwin`, or `adapter.extractHtml` are caught and treated as `null` fallbacks; `applyPostFetchSiteExtractor` accepts results only when `res.markdown.trim()` is non-empty.
- `[utils.ts:unescapeHrefUrl]` — Unescapes strictly `/&(?:amp|#0*38|#x0*26);/gi` and never decodes arbitrary named entities on URLs (preserving query parameters such as `&currentTime` or `&section`).
- `[utils.ts:extractMetaContent]`, `[utils.ts:extractAllMetaContents]`, `[utils.ts:extractJsonLdObjects]`, `[utils.ts:formatYamlFrontmatterCard]` — Enforce deterministic input bounds: `extractMetaContent` scans `80000` chars, `extractAllMetaContents` scans `120000` chars, `extractJsonLdObjects` caps at `30` `<script>` blocks, `escapeGfmCell` truncates body cells at `180` chars (`80` for headers), and `formatYamlFrontmatterCard` bounds frontmatter to `8000` chars, `12` list items per key, and `10` whitelisted metadata rows.

## Side Effects

- None (`types.ts`, `utils.ts`, and `registry.ts` construct an immutable in-memory `DEFAULT_INDEX` at module load and perform pure URL matching, JSON/HTML parsing, and Markdown formatting with zero network, disk, or external state mutations).

## Verification

- Run: `npm --prefix hub test`
