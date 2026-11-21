# Developer, Package Registry & Q&A Providers (`hub/src/extractors/providers/developer`)

## Overview

Provides built-in keyless `SiteAdapter` definitions for language package registries, source code hosts, vulnerability databases, engineering standards, mobile app stores, and Q&A networks (`apps.apple.com`, `crates.io`, `gist.github.com`, GitLab/Codeberg/Gitea, `play.google.com`, `hex.pm`, IETF RFCs, `jsr.io`, `nvd.nist.gov`, `npmjs.com`, `packagist.org`, `pkg.go.dev`, `pypi.org`, `rubygems.org`, and Stack Exchange sites). Adapters declare `SiteExtractorTwin` JSON/blob upgrades (`resolveTwin`) and/or structured post-fetch HTML extractors (`extractHtml`).

## Interface

- `[apple-app-store.ts:default]` — `SiteAdapter` (`id: 'apple-app-store'`, `category: 'developer'`, `domains: ['apps.apple.com']`) implementing `extractHtml` (`extractorId: 'apple-app-store'`).
- `[crates-io.ts:default]` — `SiteAdapter` (`id: 'crates-io'`, `category: 'developer'`, `domains: ['crates.io', 'www.crates.io']`) implementing `resolveTwin` for twin `'crates-io'` (`https://crates.io/api/v1/crates/${encodeURIComponent(crateName)}`).
- `[github-gist.ts:default]` — `SiteAdapter` (`id: 'github-gist'`, `category: 'developer'`, `domains: ['gist.github.com']`) implementing `extractHtml` (`extractorId: 'github-gist'`).
- `[gitlab-forgejo.ts:default]` — `SiteAdapter` (`id: 'gitlab-forgejo'`, `category: 'developer'`, `domains: ['gitlab.com', 'gitlab.*', 'codeberg.org', 'gitea.com']`) implementing `resolveTwin` for twins `'gitlab-blob-json'` and `'gitlab-readme-json'`, plus `extractHtml` (`extractorId: 'gitlab-forgejo'`).
- `[google-play.ts:default]` — `SiteAdapter` (`id: 'google-play'`, `category: 'developer'`, `domains: ['play.google.com']`) implementing `extractHtml` (`extractorId: 'google-play'`).
- `[hex-pm.ts:default]` — `SiteAdapter` (`id: 'hex-pm'`, `category: 'developer'`, `domains: ['hex.pm', 'www.hex.pm']`) implementing `resolveTwin` for twin `'hex-pm'` (`https://hex.pm/api/packages/${encodeURIComponent(pkg)}`).
- `[ietf-rfc.ts:default]` — `SiteAdapter` (`id: 'ietf-rfc'`, `category: 'developer'`, `domains: ['datatracker.ietf.org', 'rfc-editor.org', 'www.rfc-editor.org']`) implementing `extractHtml` (`extractorId: 'ietf-rfc'`).
- `[jsr-io.ts:default]` — `SiteAdapter` (`id: 'jsr-io'`, `category: 'developer'`, `domains: ['jsr.io']`) implementing `extractHtml` (`extractorId: 'jsr-io'`).
- `[nist-nvd.ts:default]` — `SiteAdapter` (`id: 'nist-nvd'`, `category: 'developer'`, `domains: ['nvd.nist.gov', 'www.nvd.nist.gov']`) implementing `resolveTwin` for twin `'nist-nvd'` (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`).
- `[npm.ts:default]` — `SiteAdapter` (`id: 'npm-registry'`, `category: 'developer'`, `domains: ['npmjs.com', 'www.npmjs.com']`) implementing `resolveTwin` for twin `'npm-registry'` (`https://registry.npmjs.org/${encodedPkg}`).
- `[packagist.ts:default]` — `SiteAdapter` (`id: 'packagist'`, `category: 'developer'`, `domains: ['packagist.org', 'www.packagist.org']`) implementing `resolveTwin` for twin `'packagist'` (`https://packagist.org/packages/${vendor}/${pkg}.json`).
- `[pkg-go-dev.ts:default]` — `SiteAdapter` (`id: 'pkg-go-dev'`, `category: 'developer'`, `domains: ['pkg.go.dev']`) implementing `extractHtml` (`extractorId: 'pkg-go-dev'`).
- `[pypi.ts:default]` — `SiteAdapter` (`id: 'pypi-project'`, `category: 'developer'`, `domains: ['pypi.org', 'www.pypi.org']`) implementing `extractHtml` (`extractorId: 'pypi-project'`).
- `[rubygems.ts:default]` — `SiteAdapter` (`id: 'rubygems'`, `category: 'developer'`, `domains: ['rubygems.org', 'www.rubygems.org']`) implementing `resolveTwin` for twin `'rubygems'` (`https://rubygems.org/api/v1/gems/${encodeURIComponent(gem)}.json`).
- `[stackexchange.ts:default]` — `SiteAdapter` (`id: 'stackexchange-qa'`, `category: 'developer'`, `domains: ['stackoverflow.com', 'www.stackoverflow.com', 'serverfault.com', 'superuser.com', 'askubuntu.com', 'mathoverflow.net', 'stackapps.com', '*.stackexchange.com']`) implementing `resolveTwin` for twin `'stackexchange-qa'` and `extractHtml` (`extractorId: 'stackexchange-qa'`).

## Invariants

- `[apple-app-store.ts:extractHtml]`, `[google-play.ts:extractHtml]` — Require `/\/app\//i` (`apps.apple.com`) or `/^\/store\/apps\/details/i` (`play.google.com`), extract `SoftwareApplication`/`MobileApplication` JSON-LD plus meta fallbacks, require non-empty title and at least one bullet or description, format `0` price as `'Free'`, and truncate `description` to `260` characters.
- `[crates-io.ts:resolveTwin]`, `[hex-pm.ts:resolveTwin]`, `[npm.ts:resolveTwin]`, `[packagist.ts:resolveTwin]`, `[rubygems.ts:resolveTwin]` — Enforce strict package-name regexes before emitting registry JSON twins (`crates-io` `/^[A-Za-z0-9_-]{1,64}$/`, `hex-pm` `/^[A-Za-z0-9_-]+$/`, `npm` scoped/unscoped `/^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i` with `%2F` encoding, `packagist` `/^[A-Za-z0-9_.-]+$/` vendor/pkg, `rubygems` `/^[A-Za-z0-9_.-]{1,80}$/`); cap `crates-io` features at `14` and releases at `6`, and cap `npm` dependency names at `10`.
- `[github-gist.ts:extractHtml]` — Requires `parts.length >= 2` and at least one valid `.file` block containing `.gist-blob-name` and either `.markdown-body` or `.blob-code-inner` cells, capping extracted files at `20`.
- `[gitlab-forgejo.ts:GITLAB_RESERVED_ROOTS]`, `[gitlab-forgejo.ts:extractGitlabBlobPlainSource]`, `[gitlab-forgejo.ts:resolveTwin]`, `[gitlab-forgejo.ts:extractHtml]` — Restricts JSON viewer twins (`?format=json&viewer=simple`) to `gitlab.com`/`gitlab.*` while excluding `GITLAB_RESERVED_ROOTS` and `.git`/`.atom` suffixes, requiring non-empty `<pre><code>` source in `extractGitlabBlobPlainSource`; restricts `extractHtml` to `codeberg.org`/`gitea.com` repo roots (`parts.length === 2`) with `.markup` README Markdown `>= 40` characters.
- `[ietf-rfc.ts:extractHtml]`, `[jsr-io.ts:extractHtml]`, `[pkg-go-dev.ts:extractHtml]`, `[pypi.ts:extractHtml]` — Gate HTML cleanup by exact path patterns (`datatracker.ietf.org` `/^\/doc\/html\/(?:rfc|draft-)/i` or `rfc-editor.org` `/^\/rfc\/rfc\d+/i` with `>= 80` chars and `[Page N]` header/footer stripping; `jsr.io` `/^\/@[^/]+\/[^/]+/i` nav stripping; `pkg.go.dev` balanced `.UnitReadme-content`/`.Documentation-content` extraction; `pypi.org` `/^\/project\/[^/]+/i` HTML extraction avoiding `robots.txt`-disallowed `/json`).
- `[nist-nvd.ts:resolveTwin]`, `[nist-nvd.ts:formatTwin]` — Requires `/vuln/detail/<CVE>` matching `/^CVE-\d{4}-\d{4,}$/`, prioritizes CVSS `v4.0` -> `v3.1` -> `v3.0`, filters `'NVD-CWE-noinfo'`, inspects at most `15` references retaining only `'https://'` URLs, and truncates `description` to `260` characters.
- `[stackexchange.ts:resolveStackExchangeSiteParam]`, `[stackexchange.ts:SE_QUESTION_ANSWERS_FILTER]`, `[stackexchange.ts:resolveTwin]`, `[stackexchange.ts:extractHtml]` — Maps Stack Exchange hosts to API v2.3 `site` parameter with filter `SE_QUESTION_ANSWERS_FILTER` (`'!20aKG._8Oscv*6dguVOli'`) on `/^\/(?:questions|q)\/(\d+)(?:\/|$)/i`; both `formatTwin` and `extractHtml` fallback sort accepted answers first then by descending score, capping tags at `8` and rendered answers at `8` (`extractHtml` scans up to `12` `#answer-<id>` blocks and `6` comments per post). All adapters are pure and perform zero direct I/O.

## Side Effects

- None (all 15 `SiteAdapter` modules in `developer` execute pure URL matching and JSON/HTML transformations without network, disk, or state mutations).

## Verification

- Run: `npm --prefix hub test`
