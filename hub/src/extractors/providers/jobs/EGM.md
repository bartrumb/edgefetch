# Jobs, ATS & Public Job Feed Providers (`hub/src/extractors/providers/jobs`)

## Overview

Provides built-in keyless `SiteAdapter` definitions for Applicant Tracking Systems (ATS), career boards, and public remote job feeds (`*.bamboohr.com`, `*.breezy.hr`, `*.recruitee.com`, `*.jobs.personio.de/.com`, `jobs.smartrecruiters.com`, `*.oraclecloud.com`, `jobs.jobvite.com`, `jobs.gem.com`, Greenhouse/Lever boards, `*.applytojob.com`, `*.pinpointhq.com`, `themuse.com`/`jobicy.com`/`arbeitnow.com`/`remoteok.com`, `ats.rippling.com`, Jibe/SAP RMK career sites, `*.teamtailor.com`, and `apply.workable.com`). Adapters map job board and posting URLs to declarative JSON/XML/RSS twins (`resolveTwin`) or structured post-fetch HTML/RSS extractors (`extractHtml`).

## Interface

- `[bamboohr-breezy-recruitee.ts:default]` — `SiteAdapter` (`id: 'bamboohr-breezy-recruitee'`, `category: 'jobs'`, `domains: ['*.bamboohr.com', '*.breezy.hr', '*.recruitee.com', '*.jobs.personio.de', '*.jobs.personio.com']`) implementing `resolveTwin` for twins `'bamboohr-board'`, `'bamboohr-job'`, `'breezy-hr'`, `'recruitee'`, and `'personio'`.
- `[enterprise-ats.ts:default]` — `SiteAdapter` (`id: 'enterprise-ats'`, `category: 'jobs'`, `domains: ['jobs.smartrecruiters.com', '*.oraclecloud.com', 'jobs.jobvite.com']`) implementing `resolveTwin` for Oracle Recruiting Cloud twins `'oracle-hcm-job'` and `'oracle-hcm-board'`, plus `extractHtml` for `'smartrecruiters'` and `'jobvite'`.
- `[gem-ats.ts:default]` — `SiteAdapter` (`id: 'gem-ats'`, `category: 'jobs'`, `domains: ['jobs.gem.com']`) implementing `resolveTwin` for twin `'gem-ats'` (`https://api.gem.com/job_board/v0/${encodeURIComponent(org)}/job_posts/`).
- `[greenhouse-lever.ts:default]` — `SiteAdapter` (`id: 'greenhouse-lever-boards'`, `category: 'jobs'`, `domains: ['boards.greenhouse.io', 'job-boards.greenhouse.io', 'eu-boards.greenhouse.io', 'job-boards.eu.greenhouse.io', 'jobs.lever.co', 'jobs.eu.lever.co']`) implementing `resolveTwin` for twins `'greenhouse-board'`, `'greenhouse-eu-board'`, `'lever-board'`, and `'lever-eu-board'` with board truncation metadata (`total`, `returned`, `truncated`, `nextCursor`).
- `[icims.ts:default]` — `SiteAdapter` (`id: 'icims'`, `category: 'jobs'`, `domains: ['*.icims.com']`) implementing `resolveTwin` and `extractHtml` upgrading `/jobs/search`, `/jobs/intro`, and `/jobs/<id>/...` URLs to `?in_iframe=1` server-rendered HTML and extracting `JobPosting` JSON-LD and role links.
- `[jazzhr.ts:default]` — `SiteAdapter` (`id: 'jazzhr'`, `category: 'jobs'`, `domains: ['*.applytojob.com']`) implementing `resolveTwin` for XML twin `'jazzhr'` (`https://app.jazz.co/feeds/export/jobs/${encodeURIComponent(org)}`).
- `[pinpoint.ts:default]` — `SiteAdapter` (`id: 'pinpoint'`, `category: 'jobs'`, `domains: ['*.pinpointhq.com']`) implementing `resolveTwin` for twin `'pinpoint'` (`https://${host}/postings.json`).
- `[public-job-feeds.ts:default]` — `SiteAdapter` (`id: 'public-job-feeds'`, `category: 'jobs'`, `domains: ['weworkremotely.com', 'www.weworkremotely.com', 'himalayas.app', 'www.himalayas.app', 'www.workingnomads.com', 'workingnomads.com', 'www.themuse.com', 'themuse.com', 'jobicy.com', 'www.arbeitnow.com', 'arbeitnow.com', 'remoteok.com']`) implementing `resolveTwin` for `'weworkremotely-feed'`, `'himalayas-feed'`, `'workingnomads-feed'`, `'themuse-feed'`, `'jobicy-feed'`, `'arbeitnow-feed'`, and `'remoteok-feed'`.
- `[rippling.ts:default]` — `SiteAdapter` (`id: 'rippling'`, `category: 'jobs'`, `domains: ['ats.rippling.com']`) implementing `resolveTwin` for twin `'rippling-board'` (`https://api.rippling.com/platform/api/ats/v1/board/${encodeURIComponent(org)}/jobs`) and `extractHtml` (`extractorId: 'rippling-job'`).
- `[sap-rmk-jibe.ts:default]` — `SiteAdapter` (`id: 'sap-rmk-jibe'`, `category: 'jobs'`, `domains: ['careers.*.com', 'jobs.*.com']`, `universalEngine: true`) implementing `resolveTwin` for twin `'jibe-careers'` (`/api/jobs`) and `extractHtml` (`extractorId: 'sap-rmk'`).
- `[teamtailor.ts:default]` — `SiteAdapter` (`id: 'teamtailor'`, `category: 'jobs'`, `domains: ['*.teamtailor.com']`) implementing `resolveTwin` for RSS twin `'teamtailor'` (`https://${host}/jobs.rss`).
- `[workable.ts:default]` — `SiteAdapter` (`id: 'workable'`, `category: 'jobs'`, `domains: ['apply.workable.com']`) implementing `resolveTwin` for twins `'workable-job'` and `'workable-board'`.

## Invariants

- `[bamboohr-breezy-recruitee.ts:BAMBOO_JUNK_SUBDOMAINS]`, `[bamboohr-breezy-recruitee.ts:resolveTwin]` — Excludes `*.bamboohr.com` subdomains in `{'www','resources','help','documentation','developers','blog','status','api'}`, excludes `'www'` and `'app'` on `*.breezy.hr` and `*.recruitee.com`, requires `<workzag-jobs` or `<position` tags for `'personio'`, and caps all board tables at `100` rows.
- `[enterprise-ats.ts:resolveTwin]`, `[enterprise-ats.ts:extractHtml]` — Restricts Oracle HCM twins to `/^[a-z0-9-]+\.fa\.[a-z0-9.-]*oraclecloud\.com$/i` `/sites/<site>` paths (capping board rows at `50`); extracts SmartRecruiters (`jobs.smartrecruiters.com` with `parts.length >= 2`, avoiding `robots.txt`-disallowed `api.smartrecruiters.com`) and Jobvite (`jobs.jobvite.com/<org>/job/<id>`) from script/style-stripped HTML and JSON-LD.
- `[gem-ats.ts:resolveTwin]`, `[pinpoint.ts:resolveTwin]` — Validate org/host slugs (`gem-ats` `/^[A-Za-z0-9_-]{1,80}$/`; `pinpoint` excludes `'www'`/`'app'`), render single postings when a matching posting ID/URL is requested, and otherwise render board tables capped at `100` rows.
- `[greenhouse-lever.ts:resolveTwin]` — Matches whole-board root `/<org>` (`parts.length === 1`) excluding reserved slugs `{'embed','v1','api','static','assets','favicon.ico'}`, routes EU board domains to `boards-api.eu.greenhouse.io` / `api.eu.lever.co`, and caps tables at `120` rows.
- `[jazzhr.ts:resolveTwin]`, `[teamtailor.ts:resolveTwin]`, `[teamtailor.ts:parseRssJobsXml]` — Exclude `'www'`/`'app'` (and `'career'` on Teamtailor), require `<jobs`/`<job` or `<rss`/`<channel` XML markers, skip items missing `<title>`, and cap board tables at `100` rows.
- `[public-job-feeds.ts:resolveTwin]` — Caps all 4 feeds at `50` rows and restricts collected links to `'https://'`; `'remoteok-feed'` always fetches `https://remoteok.com/api` (avoiding `?tag=` 302 redirects), skips the index-0 legal banner by requiring non-empty `item.position`, and filters `catTag` in memory.
- `[rippling.ts:resolveTwin]`, `[rippling.ts:extractHtml]`, `[workable.ts:resolveTwin]` — Strip optional locale prefixes on Rippling, reject reserved Workable slugs `{'api','j','assets','static','favicon.ico','robots.txt'}`, deduplicate multi-location board rows (`uuid || id` on Rippling, `shortcode` on Workable) capped at `100` rows with up to `4` locations per role, and require `__NEXT_DATA__` `jobPost` payload for `'rippling-job'`.
- `[sap-rmk-jibe.ts:resolveTwin]`, `[sap-rmk-jibe.ts:extractHtml]` — `'jibe-careers'` matches `url.pathname === '/api/jobs'` and caps `data.jobs` (requiring `jobs[0]?.data` when non-empty) at `80` rows; `'sap-rmk'` matches `/sitemap\.xml$/i` containing `<g:location>` or `<g:employer>` within `rawHtml.slice(0, 20000)` capped at `100` rows. All adapters are pure and never perform direct I/O.

## Side Effects

- None (all 11 `SiteAdapter` modules in `jobs` execute pure URL matching and JSON/XML/HTML transformations without network, disk, or state mutations).

## Verification

- Run: `npm --prefix hub test`
