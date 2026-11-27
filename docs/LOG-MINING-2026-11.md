# Production Log Mining & Ethical Adapter Expansion (2026-11)

This report summarizes the read-only production telemetry and D1 log-mining pass performed in November 2026 to identify recurring unadapted, thin-SSR, slow, or browser-heavy hosts, document which hosts received ethical keyless adapters under strict `robots.txt` compliance, and record every blocked or paywalled host intentionally skipped under our zero-bypass policy.

---

## 1. Data Sources & Scope

| Source | Identifier / Window | Scope |
|---|---|---|
| **D1 Production Crawl Index** | Production hub META D1 crawl index (read-only `SELECT`) | `3,563` indexed pages, `870` distinct hosts, `5,482` fetch records, `3,382` extracted documents |
| **Cloudflare Worker Observability** | Production hub Worker and telemetry collector logs (`2026-11-19` to `2026-11-26`) | Request latency, browser CDP invocations, `403`/WAF blocks, `robots.txt` disallows, and `>4 MiB` overflow events |

---

## 2. Top Production Failure & Latency Patterns

1. **Thin / Hydration-Hidden SSR Pages Triggering Unnecessary Browser Spins**:
   - `www.nfpa.org`: `12.5s` average latency and `9` no-doc failures caused by thin initial DOM shells hiding Sitecore JSS content inside `__NEXT_DATA__` (`placeholders["storefront-main"]`).
   - `productinfo.shimano.com`: `11.2s` latency / `146 B` shell caused by Next.js RSC (`self.__next_f.push`) double-encoded `"spec"` payloads containing `TableSpecContents` / `SpecContent` arrays.
   - `www.youtube.com`: `/watch` pages falling back to Chromium CDP (causing GPU process crashes) when static `ytInitialPlayerResponse.videoDetails` yielded `< 80` words, while `/api/timedtext` and `/youtubei/*` are `robots.txt`-disallowed.
2. **Unadapted Specialty OEM, Regulatory, and Trade Hosts**:
   - `bumm.de` (`8.2s`, TYPO3 JSON-LD + `table.attributes-table` + PDF manuals), `www.bicycleretailer.com` (`7.5s`, Drupal `.node-article` + `.view-content` + `/rss.xml`), `www.giant-bicycles.com` & `www.liv-cycling.com` (`li.datarow` specs, `table.geometry`, PDF manuals), `www.law.cornell.edu` (CFR / US Code HTML with donation sidebar noise), `www.sram.com` (`/sram/models/*` specs), and `www.tq-ebike.com` (drive system product & support pages).
3. **Oversized `>4–16 MiB` PDF Manuals & Wire Hydration**:
   - Large OEM service PDFs (`5–15 MiB`) exceeding `MAX_WASM_INPUT_BYTES` (`4 MiB`), resolved via `L-03` (`rawBase64` / `parsers: []` inline hydration up to the wire budget with `artifactId` fallback above `18 MiB`).

---

## 3. Ethical Keyless Adapters Added (Item 25a–25f)

Every new adapter enforces `respectRobots: true`, `validatePublicHttpsTargetUrl`, `isTrustedTwinRedirectUrl`, and `MAX_WASM_INPUT_BYTES` (`4 MiB`).

| Host(s) | Adapter ID | Mechanism & Keyless Path | `robots.txt` & Politeness Constraints |
|---|---|---|---|
| `www.nfpa.org` | [`nfpa`](../internal/extract/manifests/nfpa.yaml) | `sitecore_jss_html` (`__NEXT_DATA__` `placeholders["storefront-main"]` unpacking `PageTitle`, `ContentBlock`, `SplitScreenCalloutComponent`, `Accordion`, `TwoColumnVideo` + CTA/video links); skips `auto-render-1` in [`scrape.ts`](../hub/src/scrape.ts) | Strictly excludes `link.nfpa.org`, `/-/media/`, `/ar/`, `/en/`, `/data/`, `/standard_items/` |
| `*.giant-bicycles.com`, `*.liv-cycling.com` | [`giant-liv-bikes`](../internal/extract/manifests/giant-liv-bikes.yaml) | `giant_liv_html` (`#specifications li.datarow`, `table.geometry`, `.pdf` manual links, `<main>` overview fallback) | Respects `Crawl-delay: 2`; excludes `/shop*`, `/comparison*`, `/account*`, `/apiproxy/*` |
| `bumm.de`, `www.bumm.de` | [`bumm-de`](../internal/extract/manifests/bumm-de.yaml) | Declarative `dom` mode with JSON-LD `Product`, `table.attributes-table`, comma-decimal EUR prices, and PDF manuals on `/product-detail/*` and `/products/detail/*` | Excludes `/typo3/` |
| `www.bicycleretailer.com`, `bicycleretailer.com` | [`bicycleretailer`](../internal/extract/manifests/bicycleretailer.yaml) | Declarative `dom` mode for `.node-article .field-name-body`, `.view-content`, `author`, `article:published_time`, stripping `aside.region-sidebar-second` | Respects `Crawl-delay: 10`; excludes `/admin/`, `/user/`, and `.xml`/`.rss`/`.atom` (allowing `/rss.xml` feed parser) |
| `www.youtube.com`, `youtube.com`, `m.youtube.com` | `youtube` fast-path | Wires `extractYouTubeWatchMetadataFromHtml` in [`scrape.ts`](../hub/src/scrape.ts) and hardens `ExtractYouTubeWatchMetadataFromHTML` in [`formatters.go`](../internal/extract/formatters.go) with `ExtractBalancedJSONAt` to skip `auto-render-1` | Strictly never calls `/api/timedtext`, `/api/*`, `/youtubei/*`, or `/feeds/videos.xml` |
| `productinfo.shimano.com` | `nextjs-rsc` ([`hydration.go`](../internal/extract/hydration.go)) | Next.js RSC `TableSpecContents` / `SpecContent` parser (including double-encoded JSON `"spec"` strings) producing GFM spec tables + `records[]` | Never touches `403`-blocked `si.shimano.com` or `bike.shimano.com` |
| `www.law.cornell.edu`, `law.cornell.edu` | [`cornell-lii`](../internal/extract/manifests/cornell-lii.yaml) | Declarative `dom` mode on `/cfr/*` and `/uscode/*` extracting `#content .tab-pane.active` / `main#content` while stripping navbar & sidebar donation chrome | Open CFR/USCode HTML mirror |
| `www.sram.com`, `sram.com` | [`sram-models`](../internal/extract/manifests/sram-models.yaml) | Declarative `dom` mode on `/*/sram/models/*` with JSON-LD `Product` & `.product-detail` spec tables | Public product HTML |
| `www.tq-ebike.com`, `tq-ebike.com` | [`tq-ebike`](../internal/extract/manifests/tq-ebike.yaml) | Declarative `dom` mode on `/*/products/*` and `/*/help-support/*` with JSON-LD `Product` & `.tx-specs` | Public product & support HTML |

---

## 4. Explicitly Blocked / Skipped Hosts (Zero-Bypass Policy)

The following hosts observed in D1 or Cloudflare Observability logs were **intentionally skipped** (no `403` evasion, no WAF/Turnstile bypass, no paywall circumvention, no `robots.txt` override):

| Host | Observed Restriction | Policy Decision | Official / Open Alternative Used |
|---|---|---|---|
| `up.codes` | `robots.txt` `Disallow: /` | Fail closed (`422 robots_disallowed`, 0 outbound requests) | `www.nfpa.org`, `www.law.cornell.edu`, `www.govinfo.gov` |
| `standards.iteh.ai` | `robots.txt` `Disallow: /api/` + CSR paywall | Fail closed on `/api/`; no bypass | `www.nfpa.org` public overview pages |
| `www.bike-eu.com` | `isAccessibleForFree: "False"` paywall | Skipped; no paywall bypass | `www.bicycleretailer.com` |
| `link.nfpa.org` | Paywalled NFPA LiNK reader SPA | Excluded from `nfpa.yaml` (`www.nfpa.org` only) | `www.nfpa.org` public standard pages |
| `safetyequipment.org` | Cloudflare `403` block | Fail closed (`403`); no bypass | `www.cpsc.gov`, `www.saferproducts.gov` |
| `www.iso.org` | Cloudflare `403` / paywalled standards | Fail closed (`403`); no bypass | Official public regulatory mirrors |
| `www.ecfr.gov` | `robots.txt` `Disallow: /api/` | Fail closed on `/api/` (`422`) | [`us-cfr-govinfo`](../internal/extract/manifests/us-cfr-govinfo.yaml) (`govinfo.gov/content/pkg/...`) & [`cornell-lii`](../internal/extract/manifests/cornell-lii.yaml) |
| `www.osha.gov` | `66x` HTTP `403` WAF challenge | Fail closed (`403`); no bypass | [`federal-register`](../internal/extract/manifests/federal-register.yaml) (`/api/v1/documents/*.json`) |
| `si.shimano.com` | `64x` HTTP `403` WAF block | Skipped; never probed | `productinfo.shimano.com` (Next.js RSC) |
| `bike.shimano.com` | `32x` HTTP `403` WAF block | Skipped; never probed | `productinfo.shimano.com` |
| `www.bosch-ebike.com` | `64x` HTTP `403` WAF block | Fail closed (`403`); no bypass | [`bosch-ebike-help`](../internal/extract/manifests/bosch-ebike-help.yaml) (`help.bosch-ebike.com` HTML/SSR, never `/api/*`) |
| `www.phmsa.dot.gov` | `16x` HTTP `403` block | Fail closed (`403`); no bypass | [`federal-register`](../internal/extract/manifests/federal-register.yaml) & `govinfo.gov` |
| `leginfo.legislature.ca.gov` | `20x` Cloudflare `403` challenge | Fail closed (`403`); no bypass | Official open mirrors |
| `api.nhtsa.gov` (when `403`) | Intermittent `403` on `/robots.txt` or endpoint | Single request, fail closed (`403`, no retry/bypass) | [`nhtsa-vpic-recalls`](../internal/extract/manifests/nhtsa-vpic-recalls.yaml) fail-open / `vpic.nhtsa.dot.gov` |
