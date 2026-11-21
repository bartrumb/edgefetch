# Public Records & Open Data Providers (`hub/src/extractors/providers/public-records`)

## Overview

Provides built-in keyless `SiteAdapter` definitions for municipal, state, federal, and geospatial open data portals (`arcgis.com`, CKAN portals such as `catalog.data.gov`, `*.legistar.com`, Socrata portals, and `usaspending.gov`). Each adapter resolves portal dataset, feature layer, legislative calendar/matter, or federal award URLs into declarative JSON `SiteExtractorTwin` descriptors (`resolveTwin`) and formats schemas, metadata, and records into Markdown tables.

## Interface

- `[arcgis.ts:default]` — `SiteAdapter` (`id: 'arcgis'`, `category: 'public-records'`, `domains: ['services.arcgis.com', '*.arcgis.com']`, `universalEngine: true`) implementing `resolveTwin` for twin `'arcgis'` (`kind: 'json'`, `fetchUrl` set to target `FeatureServer`/`MapServer` URL with `?f=json`).
- `[ckan.ts:default]` — `SiteAdapter` (`id: 'ckan'`, `category: 'public-records'`, `domains: ['catalog.data.gov', 'data.boston.gov', 'data.sanantonio.gov', 'data.sanjoseca.gov', 'data.wprdc.org', 'data.gov.uk', 'www.data.gov.uk', 'data.gov.au', 'open.canada.ca']`) implementing `resolveTwin` for twin `'ckan'` (`kind: 'json'`, `fetchUrl: '${cfg.apiBase}/package_show?id=${encodeURIComponent(pkgId)}'`).
- `[legistar.ts:default]` — `SiteAdapter` (`id: 'legistar'`, `category: 'public-records'`, `domains: ['*.legistar.com']`) implementing `resolveTwin` for twin `'legistar'` (`kind: 'json'`, `fetchUrl` targeting `https://webapi.legistar.com/v1/${encodeURIComponent(client)}/events?$top=20&$orderby=EventDate%20desc` or `/matters?$top=25&$orderby=MatterIntroDate%20desc`).
- `[socrata.ts:default]` — `SiteAdapter` (`id: 'socrata'`, `category: 'public-records'`, `domains: ['data.cityofnewyork.us', 'data.sfgov.org', 'data.sf.gov', 'data.seattle.gov', 'data.cityofchicago.org', 'data.lacity.org', 'data.wa.gov', 'data.nj.gov', 'data.colorado.gov', 'data.texas.gov', 'data.ny.gov', 'data.cdc.gov', '*.socrata.com']`, `universalEngine: true`) implementing `resolveTwin` for twin `'socrata'` (`kind: 'json'`, `fetchUrl: 'https://${host}/api/views/${viewId}.json'`).
- `[usaspending.ts:default]` — `SiteAdapter` (`id: 'usaspending'`, `category: 'public-records'`, `domains: ['www.usaspending.gov', 'usaspending.gov']`) implementing `resolveTwin` for twin `'usaspending'` (`kind: 'json'`, `fetchUrl: 'https://api.usaspending.gov/api/v2/awards/${encodeURIComponent(awardId)}/'`).

## Invariants

- `[arcgis.ts:resolveTwin]`, `[arcgis.ts:formatTwin]` — Matches only `url.pathname` matching `/\/rest\/services\/.+\/(?:FeatureServer|MapServer)(?:\/\d+)?\/?$/i` and appends `f=json`; returns `null` when `parseJsonObject(rawBody)` fails or `data.error` is truthy, capping rendered `fields` at `40` (or `layers` at `30`) and `description` at `260` characters.
- `[ckan.ts:CKAN_PORTALS]`, `[ckan.ts:resolveTwin]`, `[ckan.ts:formatTwin]` — Restricts CKAN resolution to the 9 hosts mapped in `CKAN_PORTALS` with exact `datasetPrefix` segments and `pkgId` matching `/^[A-Za-z0-9_.-]{2,160}$/`; requires `data.success === true` and truthy `data.result`, capping tags at `12`, resources at `20`, `description` at `260` characters, and resource links strictly to `'https://'` URLs.
- `[legistar.ts:resolveTwin]`, `[legistar.ts:formatTwin]` — Requires `^([a-z0-9-]+)\.legistar\.com$` where `client` is neither `'www'` nor `'webapi'`; requires non-empty JSON array response, capping calendar events at `20` rows (linking `EventInSiteURL` only when prefixed with `'https://'`) and legislative matters at `25` rows.
- `[socrata.ts:KNOWN_SOCRATA_HOSTS]`, `[socrata.ts:isLikelySocrataHost]`, `[socrata.ts:resolveTwin]`, `[socrata.ts:formatTwin]` — Accepts hosts in `KNOWN_SOCRATA_HOSTS` (22 hosts), `*.socrata.com`, or `/^data\.[a-z0-9-]+\.(?:gov|org|us)$/i`, and requires a 4x4 Socrata `viewId` containing at least one digit (`/^(?=.*\d)[a-z0-9]{4}-[a-z0-9]{4}$/i`); requires string `data.name` and `data.id`, excludes system columns prefixed with `':@'`, caps visible columns at `40`, and truncates `description` to `260` characters.
- `[usaspending.ts:resolveTwin]`, `[usaspending.ts:formatTwin]` — Requires `parts[0] === 'award'` with decoded `awardId` matching `/^[A-Za-z0-9_.-]{4,140}$/`; requires at least one of `generated_unique_award_id`, `piid`, or `fain` in JSON response, formats obligations via `formatUsdCompact`, and truncates `description` to `260` characters. All adapters are pure and never perform direct I/O.

## Side Effects

- None (`[arcgis.ts:default]`, `[ckan.ts:default]`, `[legistar.ts:default]`, `[socrata.ts:default]`, `[usaspending.ts:default]` execute pure URL matching and JSON formatting without network, disk, or state mutations).

## Verification

- Run: `npm --prefix hub test`
