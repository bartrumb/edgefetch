# Finance & Company Profile Providers (`hub/src/extractors/providers/finance`)

## Overview

Provides built-in keyless `SiteAdapter` definitions for prediction markets, regulatory corporate filings, and startup company directories (`polymarket.com`, `sec.gov`, `ycombinator.com`, and `workatastartup.com`). Adapters map incoming URLs to declarative `SiteExtractorTwin` descriptors (`resolveTwin`) and/or structured post-fetch HTML extractors (`extractHtml`), formatting JSON submissions, market odds, and Inertia SSR payloads into GitHub Flavored Markdown.

## Interface

- `[polymarket.ts:default]` — `SiteAdapter` (`id: 'polymarket'`, `category: 'finance'`, `domains: ['polymarket.com', 'www.polymarket.com']`) implementing `resolveTwin` for twin `'polymarket'` (`kind: 'json'`, `fetchUrl: 'https://gamma-api.polymarket.com/events?slug=${encodeURIComponent(slug)}'`).
- `[sec-edgar.ts:default]` — `SiteAdapter` (`id: 'sec-edgar'`, `category: 'finance'`, `domains: ['www.sec.gov', 'sec.gov', 'data.sec.gov']`) implementing `resolveTwin` for twin `'sec-edgar'` (`kind: 'json'`, `fetchUrl: 'https://data.sec.gov/submissions/CIK${paddedCik}.json'`).
- `[ycombinator.ts:default]` — `SiteAdapter` (`id: 'ycombinator'`, `category: 'finance'`, `domains: ['www.ycombinator.com', 'ycombinator.com', 'www.workatastartup.com', 'workatastartup.com']`) implementing `resolveTwin` for twin `'workatastartup-yc-mirror'` (`kind: 'text'`, `fetchUrl: 'https://www.ycombinator.com/companies/${encodeURIComponent(slug)}/jobs'`) and `extractHtml` (`extractorId: 'ycombinator'`).

## Invariants

- `[polymarket.ts:resolveTwin]` — Requires `parts[0] === 'event'` and non-empty decoded `slug` matching `/^[A-Za-z0-9_-]{2,140}$/`; otherwise returns `null`.
- `[polymarket.ts:formatTwin]` — Unwraps array or object JSON via `parseJsonValue` and requires `typeof ev.title === 'string'` (else returns `null`); caps market rows at `markets.slice(0, 25)`, defaults non-array `outcomes` to `['Yes', 'No']`, formats finite `outcomePrices` as `(pr * 100).toFixed(1)%`, slices `endDate` to `10` characters, and truncates `description` to `260` characters.
- `[sec-edgar.ts:resolveTwin]` — Extracts `rawCik` only from `sec.gov`/`www.sec.gov` (`/edgar/browse/...` or `/cgi-bin/browse-edgar` `CIK`/`cik` query parameter) or `data.sec.gov` (`/submissions/CIK<digits>.json`), requires `/^\d{1,10}$/`, zero-pads `paddedCik` to 10 digits (`padStart(10, '0')`), and derives unpadded `numericCik` for Archives filing paths; otherwise returns `null`.
- `[sec-edgar.ts:formatTwin]` — Requires `typeof data.name === 'string'` from `parseJsonObject` (else returns `null`); caps filing table rows at `25` and restricts rows past index `12` to `priorityForms` (`'10-K'`, `'10-K/A'`, `'10-Q'`, `'10-Q/A'`, `'8-K'`, `'DEF 14A'`, `'20-F'`, `'S-1'`, `'13F-HR'`, `'4'`), falling back to `${accRaw}-index.htm` when `primaryDocument` is empty.
- `[ycombinator.ts:parseYcInertiaDataPage]` — Extracts `data-page` attribute HTML payload via `/\bdata-page=["']([^"']+)["']/i`, decodes entities via `decodeBasicEntities`, and parses JSON via `parseJsonObject` (returning `null` on mismatch).
- `[ycombinator.ts:formatYcCompanyProps]` — Requires `typeof company.name === 'string'` (else returns `null`), emits `company.website` and founder `linkedin_url` links only when prefixed with `'https://'`, skips founders without `full_name`, and caps job rows at `jobPostings.slice(0, 30)` while normalizing root-relative paths to `https://www.ycombinator.com`.
- `[ycombinator.ts:resolveTwin]`, `[ycombinator.ts:extractHtml]` — `resolveTwin` matches only `workatastartup.com`/`www.workatastartup.com` `/companies/<slug>` where `slug` satisfies `/^[A-Za-z0-9_-]{1,80}$/`; `extractHtml` matches only `ycombinator.com`/`www.ycombinator.com` `/companies/<slug>`; adapters never perform direct network I/O.

## Side Effects

- None (`[polymarket.ts:default]`, `[sec-edgar.ts:default]`, `[ycombinator.ts:default]` execute pure URL matching and JSON/HTML formatting without network, disk, or state mutations).

## Verification

- Run: `npm --prefix hub test`
