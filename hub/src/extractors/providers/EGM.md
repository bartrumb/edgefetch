# Built-In Site Adapter Providers (`hub/src/extractors/providers`)

## Overview

Barrel registration package aggregating all 54 built-in keyless `SiteAdapter` modules across 7 functional domain categories into an ordered, immutable `BUILTIN_SITE_ADAPTERS` array consumed by the extractor registry (`../registry.ts`).

## Interface

- `[index.ts:BUILTIN_SITE_ADAPTERS]` — `readonly SiteAdapter[]` barrel constant exporting all 54 built-in `SiteAdapter` instances in deterministic registration order across 7 category subpackages.
- [Commerce, Food, Social & Wiki Providers](./commerce-social/EGM.md) — 10 `SiteAdapter` modules (`shopify`, `openfoodfacts`, `hackernews`, `lobsters`, `bluesky-thread`, `dev-to`, `reddit-thread`, `discourse-topic`, `mastodon-status`, `mediawiki`).
- [Developer, Package Registry & Q&A Providers](./developer/EGM.md) — 15 `SiteAdapter` modules (`npm-registry`, `crates-io`, `rubygems`, `packagist`, `hex-pm`, `pypi-project`, `pkg-go-dev`, `jsr-io`, `gitlab-forgejo`, `github-gist`, `stackexchange-qa`, `ietf-rfc`, `nist-nvd`, `apple-app-store`, `google-play`).
- [Finance & Company Profile Providers](./finance/EGM.md) — 3 `SiteAdapter` modules (`sec-edgar`, `ycombinator`, `polymarket`).
- [GenAI & Knowledge Archive Providers](./genai/EGM.md) — 3 `SiteAdapter` modules (`huggingface`, `internet-archive`, `openrouter`).
- [Jobs, ATS & Public Job Feed Providers](./jobs/EGM.md) — 11 `SiteAdapter` modules (`workable`, `greenhouse-lever-boards`, `gem-ats`, `pinpoint`, `rippling`, `teamtailor`, `jazzhr`, `bamboohr-breezy-recruitee`, `enterprise-ats`, `public-job-feeds`, `sap-rmk-jibe`).
- [Public Records & Open Data Providers](./public-records/EGM.md) — 5 `SiteAdapter` modules (`socrata`, `ckan`, `arcgis`, `legistar`, `usaspending`).
- [Research, Academic & Health Providers](./research-health/EGM.md) — 7 `SiteAdapter` modules (`pubmed-pmc`, `doi-crossref`, `openalex`, `arxiv`, `clinicaltrials`, `pubchem`, `openfda`).

## Invariants

- `[index.ts:BUILTIN_SITE_ADAPTERS]` — Typed as `readonly SiteAdapter[]`, preserving compile-time array immutability and a fixed 54-adapter evaluation order grouped by category (`15` developer, `3` genai, `11` jobs, `3` finance, `5` public-records, `7` research-health, `10` commerce-social).
- All registered child adapters inherit the keyless, pure declarative contract defined in `../types.ts`: adapters never execute raw network `fetch()` calls directly and return `null` when URL, host, or payload invariants are unmet.

## Side Effects

- None (`[index.ts:BUILTIN_SITE_ADAPTERS]` performs static ES module aggregation without I/O, network calls, or runtime state mutation).

## Verification

- Run: `npm --prefix hub test`
