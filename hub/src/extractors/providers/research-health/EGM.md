# Research, Academic & Health Providers (`hub/src/extractors/providers/research-health`)

## Overview

Provides built-in keyless `SiteAdapter` definitions for academic literature, persistent identifiers, clinical registries, chemical databases, and drug safety APIs (`arxiv.org`, `clinicaltrials.gov`, `doi.org`, `openalex.org`, `api.fda.gov`, `pubchem.ncbi.nlm.nih.gov`, `pubmed.ncbi.nlm.nih.gov`, and `pmc.ncbi.nlm.nih.gov`). Adapters upgrade compatible URLs to declarative public JSON/XML twins (`resolveTwin`) and provide structured post-fetch HTML extraction (`extractHtml`) where live HTML or SSR metadata is required.

## Interface

- `[arxiv.ts:default]` — `SiteAdapter` (`id: 'arxiv'`, `category: 'research-health'`, `domains: ['arxiv.org', 'www.arxiv.org']`) implementing `extractHtml` (`extractorId: 'arxiv'`).
- `[clinicaltrials.ts:default]` — `SiteAdapter` (`id: 'clinicaltrials'`, `category: 'research-health'`, `domains: ['clinicaltrials.gov', 'www.clinicaltrials.gov']`) implementing `extractHtml` (`extractorId: 'clinicaltrials'`).
- `[doi-crossref.ts:default]` — `SiteAdapter` (`id: 'doi-crossref'`, `category: 'research-health'`, `domains: ['doi.org', 'www.doi.org', 'dx.doi.org']`) implementing `resolveTwin` for twin `'doi-crossref'` (`kind: 'json'`, `fetchUrl: 'https://api.crossref.org/works/${encodeURIComponent(rawDoi)}'`).
- `[openalex.ts:default]` — `SiteAdapter` (`id: 'openalex'`, `category: 'research-health'`, `domains: ['openalex.org', 'www.openalex.org', 'api.openalex.org']`) implementing `resolveTwin` for twin `'openalex'` (`kind: 'json'`, `fetchUrl: 'https://api.openalex.org/works/${normId}'`).
- `[openfda.ts:default]` — `SiteAdapter` (`id: 'openfda'`, `category: 'research-health'`, `domains: ['api.fda.gov']`) implementing `resolveTwin` for twin `'openfda'` (`kind: 'json'`, `fetchUrl: urlStr`).
- `[pubchem.ts:default]` — `SiteAdapter` (`id: 'pubchem'`, `category: 'research-health'`, `domains: ['pubchem.ncbi.nlm.nih.gov']`) implementing `resolveTwin` for twin `'pubchem'` (`kind: 'json'`, `fetchUrl: 'https://pubchem.ncbi.nlm.nih.gov/rest/pug_view/data/compound/${rawId}/JSON/?heading=Names+and+Identifiers'`) and `extractHtml` (`extractorId: 'pubchem'`).
- `[pubmed-pmc.ts:default]` — `SiteAdapter` (`id: 'pubmed-pmc'`, `category: 'research-health'`, `domains: ['pubmed.ncbi.nlm.nih.gov', 'pmc.ncbi.nlm.nih.gov']`) implementing `resolveTwin` for twins `'pubmed-europepmc'` (`kind: 'json'`, Europe PMC REST search) and `'pmc-europepmc'` (`kind: 'text'`, Europe PMC `fullTextXML`) plus `extractHtml` (`extractorId: 'pubmed-pmc'`).

## Invariants

- `[arxiv.ts:extractHtml]` — Requires `path` matching `/^\/abs\/([A-Za-z0-9._/-]+)$/i`, non-empty title, and non-empty abstract (else returns `null`); caps authors at `20` in Markdown bullets and `4` in metadata `author`, truncates `description` to `260` characters, and emits canonical `https://arxiv.org/pdf/<id>` and `https://arxiv.org/html/<id>` links.
- `[clinicaltrials.ts:extractBalancedJsonObjectAfter]`, `[clinicaltrials.ts:extractHtml]` — Bounds balanced-brace SSR JSON scanning to `120000` characters past `openIdx`; requires `/\b(NCT\d{8})\b/i` in `path`, non-empty title, and at least one metadata bullet or summary (else returns `null`), capping conditions at `10` items and appending `currentMd` only when exceeding `(summary?.length ?? 0) + 120` characters.
- `[doi-crossref.ts:resolveTwin]` — Requires decoded pathname (stripped of leading slashes) to match `/^10\.\d{4,9}\/\S+$/` (else returns `null`); `formatTwin` requires a JSON `message` object and non-empty title, strips `<jats:*>` tags, caps authors at `16` (`4` in metadata), emits publisher links only for `'https://'` URLs, and truncates `description` to `260` characters.
- `[openalex.ts:reconstructInvertedAbstract]`, `[openalex.ts:resolveTwin]` — Reconstructs inverted-index abstracts strictly for token positions `0 <= pos < 10000`; `resolveTwin` requires work IDs matching `/^W\d{5,15}$/i` at `/<W...>` or `/works/<W...>`, caps authorships at `15` (`4` in metadata), restricts links to `'https://'`, and truncates `description` to `260` characters.
- `[openfda.ts:resolveTwin]` — Matches only `url.pathname.endsWith('.json')` and requires non-empty `data.results` in `formatTwin`; formats recall records (`recall_number` or `reason_for_recall`) as a GFM table capped at `25` rows, or drug/device label records capped at `10` items across 5 fixed label fields sliced to `1200` characters each.
- `[pubchem.ts:resolveTwin]`, `[pubchem.ts:extractHtml]` — `resolveTwin` matches `/compound/<cid>` strictly when `cid` is numeric `/^\d{1,12}$/` so named compounds fall back to `extractHtml`; `extractHtml` requires `/^\/compound\/[^/]+/i`, non-empty title, and at least one chemical bullet or description, appending `currentMd` only when `currentMd.length > 200`.
- `[pubmed-pmc.ts:resolveTwin]`, `[pubmed-pmc.ts:extractHtml]` — Routes `pubmed.ncbi.nlm.nih.gov` `/^\/(\d+)\/?$/` to `'pubmed-europepmc'` and `pmc.ncbi.nlm.nih.gov` `/^\/articles\/(PMC\d+)(?:\/|$)/i` to `'pmc-europepmc'` (capping `<sec>` body sections with `<p>` content at `30`); `extractHtml` requires non-empty `<h1>` and converted `<article>`/abstract Markdown, deduplicating authors capped at `15` (`4` in metadata). All adapters remain pure and perform zero direct I/O.

## Side Effects

- None (`[arxiv.ts:default]`, `[clinicaltrials.ts:default]`, `[doi-crossref.ts:default]`, `[openalex.ts:default]`, `[openfda.ts:default]`, `[pubchem.ts:default]`, `[pubmed-pmc.ts:default]` execute pure URL matching and JSON/XML/HTML transformations without network, disk, or state mutations).

## Verification

- Run: `npm --prefix hub test`
