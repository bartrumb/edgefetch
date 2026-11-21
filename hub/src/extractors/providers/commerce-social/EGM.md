# Commerce, Food, Social & Wiki Providers (`hub/src/extractors/providers/commerce-social`)

## Overview

Provides built-in keyless `SiteAdapter` definitions for social networks, developer forums, wikis, food product catalogs, and e-commerce storefronts (`bsky.app`, `dev.to`, Discourse forums, `news.ycombinator.com`, `lobste.rs`, Mastodon instances, MediaWiki sites, `openfoodfacts.org`, `reddit.com`, and Shopify stores). Supports both domain-pinned adapters and multi-domain `universalEngine: true` platform detectors via declarative `resolveTwin` descriptors and post-fetch `extractHtml` cleanups.

## Interface

- `[bluesky.ts:default]` — `SiteAdapter` (`id: 'bluesky-thread'`, `category: 'commerce-social'`, `domains: ['bsky.app', 'staging.bsky.app']`) implementing `resolveTwin` for twin `'bluesky-thread'` (`kind: 'json'`, `fetchUrl: 'https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=...&depth=6'`).
- `[dev-to.ts:default]` — `SiteAdapter` (`id: 'dev-to'`, `category: 'commerce-social'`, `domains: ['dev.to', 'www.dev.to']`) implementing `resolveTwin` for twin `'dev-to'` (`kind: 'json'`, `fetchUrl: 'https://dev.to/api/articles/${parts[0]}/${parts[1]}'`).
- `[discourse.ts:default]` — `SiteAdapter` (`id: 'discourse-topic'`, `category: 'commerce-social'`, `domains: ['meta.discourse.org', 'community.home-assistant.io', 'users.rust-lang.org', 'discuss.python.org']`, `universalEngine: true`) implementing `resolveTwin` for twin `'discourse-topic'` (`kind: 'json'`, `fetchUrl: 'https://${host}/t/${parts[1]}/${parts[2]}.json'`).
- `[hackernews.ts:default]` — `SiteAdapter` (`id: 'hackernews'`, `category: 'commerce-social'`, `domains: ['news.ycombinator.com']`) implementing `resolveTwin` for twin `'hackernews'` (`kind: 'json'`, `fetchUrl: 'https://hn.algolia.com/api/v1/items/${itemId}'`).
- `[lobsters.ts:default]` — `SiteAdapter` (`id: 'lobsters'`, `category: 'commerce-social'`, `domains: ['lobste.rs']`) implementing `resolveTwin` for twin `'lobsters'` (`kind: 'json'`, `fetchUrl: 'https://lobste.rs/s/${parts[1]}.json'`).
- `[mastodon.ts:default]` — `SiteAdapter` (`id: 'mastodon-status'`, `category: 'commerce-social'`, `domains: ['mastodon.social', 'fosstodon.org', 'hachyderm.io']`, `universalEngine: true`) implementing `resolveTwin` for twin `'mastodon-status'` (`kind: 'json'`, `fetchUrl: 'https://${host}/api/v1/statuses/${parts[1]}'`).
- `[mediawiki.ts:default]` — `SiteAdapter` (`id: 'mediawiki'`, `category: 'commerce-social'`, `domains: ['*.wikipedia.org', 'wiki.archlinux.org']`, `universalEngine: true`) implementing `extractHtml` (`extractorId: 'mediawiki'`).
- `[openfoodfacts.ts:default]` — `SiteAdapter` (`id: 'openfoodfacts'`, `category: 'commerce-social'`, `domains: ['world.openfoodfacts.org', 'openfoodfacts.org', '*.openfoodfacts.org']`) implementing `extractHtml` (`extractorId: 'openfoodfacts'`).
- `[reddit.ts:default]` — `SiteAdapter` (`id: 'reddit-thread'`, `category: 'commerce-social'`, `domains: ['reddit.com', '*.reddit.com']`) implementing `extractHtml` (`extractorId: 'reddit-thread'`).
- `[shopify.ts:default]`, `[shopify.ts:isShopifyHtmlOrHeaders]`, `[shopify.ts:extractShopifyCurrencyFromHtml]`, `[shopify.ts:resolveCustomDomainShopifyProductTwinUrl]`, `[shopify.ts:normalizeShopifyProductRecord]`, `[shopify.ts:enrichShopifyProductFromJson]`, `[shopify.ts:shopifyCatalogSpec]` — `SiteAdapter` (`id: 'shopify'`, `category: 'commerce-social'`, `domains: ['*.myshopify.com']`, `universalEngine: true`) implementing `/products.json` and `/collections/<handle>/products.json` inventory twins with `records` + `pagination`, `*.myshopify.com` and custom-domain `/products/<handle>` enrichment (`.json`, `.js`, embedded JSON, and JSON-LD), and `CatalogSpec` (`pauseMs: 2000`, `pageCap: 200`).
- `[woocommerce.ts:default]`, `[woocommerce.ts:isWooCommerceHtmlOrHeaders]`, `[woocommerce.ts:normalizeWooCommerceProductRecord]`, `[woocommerce.ts:woocommerceCatalogSpec]` — `SiteAdapter` (`id: 'woocommerce'`, `category: 'commerce-social'`, `universalEngine: true`) implementing WooCommerce public Store API (`/wp-json/wc/store/v1/products`) twins, HTML product extraction (`extractorId: 'woocommerce'`), and `CatalogSpec` (`pauseMs: 2000`, `pageCap: 200`).

## Invariants

- `[bluesky.ts:resolveTwin]`, `[bluesky.ts:formatTwin]` — Requires `/profile/<actor>/post/<rkey>` (`parts.length >= 4`, `actor` `/^[A-Za-z0-9._:-]+$/`, `rkey` `/^[A-Za-z0-9._-]+$/`); requires string `thread.post.record.text`, caps replies at `15`, and truncates `description` to `220` characters.
- `[dev-to.ts:resolveTwin]`, `[dev-to.ts:formatTwin]` — Requires `parts.length === 2` with `parts[0].toLowerCase()` excluded from reserved `Set` `{'t','top','latest','pod','videos','tags','search','settings','enter','new','about','privacy','terms'}` and `/^[A-Za-z0-9_-]+$/` on both segments; strips leading YAML frontmatter up to `1500` characters.
- `[discourse.ts:resolveTwin]`, `[discourse.ts:formatTwin]` — Requires `parts[0] === 't'`, `parts.length >= 3`, and numeric `parts[2]` (`/^\d+$/`); requires non-empty `post_stream.posts` and string `data.title`, capping rendered posts at `20` and deduplicated links at `< 100`.
- `[hackernews.ts:resolveTwin]`, `[hackernews.ts:formatTwin]` — Requires `url.pathname === '/item'` with `id` query param `/^\d{1,12}$/`; caps rendered comment lines at `60` with recursion depth `< 2` and emits `storyUrl` link only when starting with `'https://'`.
- `[lobsters.ts:resolveTwin]`, `[lobsters.ts:formatTwin]` — Requires `parts[0] === 's'` and `parts[1]` `/^[A-Za-z0-9]{4,12}$/`; caps comments at `40`, clamps indentation to `[0, 6]`, and emits `storyUrl` link only when starting with `'https://'`.
- `[mastodon.ts:resolveTwin]`, `[mastodon.ts:formatTwin]` — Requires `parts.length === 2`, `@`-prefixed `parts[0]`, numeric snowflake `parts[1]` `/^\d{15,24}$/`, and excludes `medium.com`, `tiktok.com`, and `threads.net` (plus subdomains); requires string `data.content` and `data.account.acct`.
- `[mediawiki.ts:extractHtml]` — Matches `*.wikipedia.org`, `wiki.archlinux.org`, or `/\bcontent=["']MediaWiki\b/i` within `rawHtml.slice(0, 4000)`; returns `null` if stripped Markdown is empty or unchanged from `currentMd`.
- `[openfoodfacts.ts:extractHtml]` — Extracts from live HTML (avoiding `/api` per `robots.txt`); requires `path` matching `/^\/product\/(\d{6,16})/i` and non-empty title, appending `currentMd` only when exceeding `(ingredients?.length ?? 0) + 120` characters and truncating `description` to `260` characters.
- `[reddit.ts:extractHtml]` — Requires `/\/comments\/[A-Za-z0-9]+/i` in `path`, `<shreddit-post>` with non-empty `post-title`, and caps `<shreddit-comment>` extraction at `25` comments with depth clamped to `[0, 5]`.
- `[shopify.ts:resolveTwin]`, `[shopify.ts:extractHtml]` — `resolveTwin` runs only on `*.myshopify.com` `/products/<handle>` (`handle` `/^[A-Za-z0-9_-]{1,160}$/`); `extractHtml` detects custom-domain storefronts via `/cdn\.shopify\.com|Shopify\.shop\s*=|shopify-digital-wallet/i` in `rawHtml.slice(0, 60000)` plus `Product`/`ProductGroup` JSON-LD, capping variant/offer rows at `30` and `description` at `260` characters. All adapters are pure and never perform direct I/O.

## Side Effects

- None (all 10 `SiteAdapter` modules in `commerce-social` execute pure URL/HTML/JSON transformations without network, disk, or state mutations).

## Verification

- Run: `npm --prefix hub test`
