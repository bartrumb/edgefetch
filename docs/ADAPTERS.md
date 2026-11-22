# Writing & Contributing Site Adapters

EdgeFetch ships an **open-source (`MIT`) Site, Commerce & ATS Adapter Library** covering **56+ keyless public platforms** across 7 categories (`internal/extract/manifests/*.yaml` and [`hub/src/extractors/`](../hub/src/extractors/LICENSE)), designed so contributors and coding agents can add a new platform in minutes with zero regex pitfalls.

## 1. Two Authoring Tiers (Pick the Simplest One That Fits)

1. **Tier 1 — Shared Zero-Code Declarative YAML Manifest (`internal/extract/manifests/<slug>.yaml`, Recommended for ~80% of Sites):**
   - Best whenever a site exposes a public, `robots.txt`-allowed JSON or Markdown endpoint (e.g., `rubygems`, `packagist`, `hex-pm`, `dev-to`, `huggingface`, `lobsters`, `doi-crossref`, `usaspending`, `polymarket`, `openrouter`).
   - Supports `#` comments, clean unquoted keys, zero trailing-comma errors, **zero code, zero regex ReDoS risk, zero `fetch()` escape, and zero YAML alias expansion (`maxAliasCount: 0`)**.
   - **Runs in BOTH the pure-Go Hub (`edgefetch --mode=hub` via `//go:embed` with zero TypeScript runtime!) AND the Cloudflare / Node Hub.**
2. **Tier 2 — TypeScript Adapter with `parseHtmlDoc()` CSS Selectors (`hub/src/extractors/providers/<category>/<slug>.ts`):**
   - Best when `/api` is disallowed by `robots.txt` so extraction runs over public HTML (`openfoodfacts`, `icims`, `arxiv`, `clinicaltrials`), or when custom multi-endpoint enrichment is required (`shopify`, `woocommerce`, `sec-edgar`).
   - Uses `parseHtmlDoc(rawHtml)` (`htmlparser2` WHATWG HTML5 DOM + linear CSS selectors: `doc.select('.job-card')`, `card.text('h3')`, `card.attr('a', 'href')`, `card.dlMap()`, `card.tableRows()`) and `compileLinearRegex()` (`re2js` Thompson NFA) inside a fault-isolated bulkhead (`runAdapterSyncInBulkhead`).

---

## 2. Ground Rules (Enforced by `npm run adapter:test` & CI)

1. **100% Keyless & Public Sources Only:** Target public APIs, feeds, registries, and structured HTML (no paid B2B API keys).
2. **Strict `robots.txt` & Ethical Compliance:**
   - Adapters **never** call `fetch()` directly (`globalThis.fetch` throws `AdapterNetworkForbiddenError` inside the bulkhead).
   - `npm run adapter:test <id> <https://url>` automatically checks `/robots.txt` (`RFC 9309` + `Content-Signal: ai-input`) and Go's `GO_KIND_TEXT_ACCEPT_ALLOWLIST` before testing live URLs.
3. **Fail-Open Fallback:** Returning `null` from an adapter cleanly falls back to generic HTML / Schema.org JSON-LD / SSR Hydration / Headless CDP extraction.

---

## 3. Quickstart Workflow (`adapter:new` + `adapter:test --record`)

### Option A — Add a Shared Go + TS Declarative YAML Adapter (Zero Code)

```bash
cd hub
npm run adapter:new developer/my-registry
```

This creates `internal/extract/manifests/my-registry.yaml`, registers it in `hub/src/extractors/declarative.ts` (and embeds it into Go's `internal/extract` automatically), and creates `hub/test/fixtures/adapters/my-registry.json`:

```yaml
# Shared Go + TypeScript Declarative Site Adapter: RubyGems Registry
id: rubygems
name: RubyGems Registry
category: developer
description: Upgrades rubygems.org gem pages to /api/v1/gems/<gem>.json metadata.
domains:
  - rubygems.org
  - www.rubygems.org
exampleUrls:
  - https://rubygems.org/gems/rails

# Matches /gems/<gem> (allowing optional trailing version subpaths)
match:
  exactSegments: false
  pathSegments:
    - gems
    - param: gem
      charset: pkg
      minLen: 1
      maxLen: 80

twin:
  fetchUrl: https://rubygems.org/api/v1/gems/{gem}.json
  kind: json
  accept: application/json

extract:
  requireFields: [name]
  vars:
    name:
      paths: [name]
    version:
      paths: [version]
    info:
      paths: [info]
      trim: true
  titleTemplate: "{name} {version} (RubyGem)"
  titleWhenVar: version
  titleFallbackTemplate: "{name} (RubyGem)"
  introVar: info
  bullets:
    - label: Install
      template: "`gem install {name}`"
    - label: Version
      template: "`{version}`"
      whenVar: version
```

### Option B — Add an HTML Adapter Using `parseHtmlDoc()` CSS Selectors

```bash
cd hub
npm run adapter:new jobs/my-board --html
```

```ts
import { defineAdapter } from '../../types';
import { formatGfmTable, parseHtmlDoc } from '../../utils';

export default defineAdapter({
  id: 'my-board',
  name: 'My Job Board',
  category: 'jobs',
  description: 'Extracts structured job cards using WHATWG HTML5 CSS selectors.',
  domains: ['jobs.example.org'],
  exampleUrls: ['https://jobs.example.org/openings'],
  extractHtml({ rawHtml }) {
    const doc = parseHtmlDoc(rawHtml);
    const rows: string[][] = [];
    for (const card of doc.select('.job-card', 50)) {
      const title = card.text('h3, h2');
      const href = card.attrOf('a[href*="/jobs/"]', 'href') ?? '';
      const meta = card.dlMap(); // pairs <dt> -> <dd> cleanly
      if (title) rows.push([href ? `[${title}](${href})` : title, meta['location'] ?? '-']);
    }
    if (rows.length === 0) return null;
    return {
      extractorId: 'my-board',
      title: doc.text('h1') || 'Open Roles',
      markdown: formatGfmTable(['Role', 'Location'], rows),
    };
  },
});
```

### Test Live, Auto-Record Fixture & Fuzz in 1 Command

```bash
cd hub
# Polite live test (verifies /robots.txt + Content-Signal, previews Markdown & token savings, and writes fixture JSON):
npm run adapter:test rubygems https://rubygems.org/gems/rails --record

# Run offline schema validation + fixture checks + 100 KB linear-time bulkhead fuzzer across all adapters:
npm run adapter:test
```
