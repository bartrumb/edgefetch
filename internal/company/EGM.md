# company

## Overview
Package `company` builds a public company profile from raw bodies the caller has already fetched (homepage HTML, Wikidata, SEC EDGAR submissions / XBRL companyfacts, GitHub org, an ATS hiring summary, and an optional Google Maps `search_places` result). It performs no network I/O; the Cloudflare hub only orchestrates fetches and calls these functions through the `company_*` WASM ops in `cmd/edgefetch-wasm/reactor_company.go`.

## Interface
- `[sources.go:Plan]`: `func Plan(PlanInput) (PlanOutput, error)` — normalizes `{name, domain}` and returns the first fetch wave (`homepage`, optional `about`, `wikidata_search`, optional `github_org`).
- `[sources.go:Followups]`, `[sources.go:PickWikidataEntity]`, `[sources.go:EntityFollowupsFor]` — Wikidata candidate URLs, domain-corroborated entity choice, and the SEC / label / homepage follow-up URLs derived from the chosen entity.
- `[company.go:Merge]`: `func Merge(MergeInput) Profile` — precedence merge with `fieldSources` attribution and a compact `markdown` summary.
- `[places.go:PlacesQuery]`, `[places.go:PickPlace]` — Maps search text and best-place selection.
- `[socials.go:NormalizeSocialURL]` — canonical https social profile URLs.

## Invariants
- `[sources.go:PickWikidataEntity]`: with a domain, an entity is chosen only when a P856 official website host matches it (exact, `www.`-stripped, or same registrable domain); `[company.go:Merge]` re-checks this and drops an uncorroborated entity.
- `[company.go:Merge]`: SEC data is used only when its CIK equals the accepted entity's P5531; GitHub only when its blog domain, a homepage/JSON-LD link, or Wikidata P2037 corroborates the login; a Maps place whose website points at a different domain is never chosen.
- `[sources.go:selectClaim]`: Wikidata statement selection is preferred rank (latest P585 among several), else latest normal rank by P585, else first normal; deprecated statements are never used.
- Every emitted string passes `extract.SanitizeSchemaPlainField` and every URL passes `extract.SanitizeSchemaHTTPSURL` (public https only); no raw HTML is emitted. Bodies are size-capped and href scanning is a single linear pass.

## Verification
- Run: `go test ./internal/company ./cmd/edgefetch-wasm`
