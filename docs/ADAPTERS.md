# Declarative YAML Site Adapters (`internal/extract/manifests/`)

EdgeFetch includes **`57` open-source (`MIT`) declarative YAML site, commerce, open-data, and ATS adapters** across 7 categories (`developer`, `genai`, `jobs`, `finance`, `public-records`, `research-health`, `commerce-social`), aligned with EdgeFetch's license split: *open-source worker, SDKs, and adapters (`MIT`), fair-source hub (`FSL-1.1`, `MIT` after two years)*.

Every site adapter is authored as a `#`-commented YAML 1.2 Core manifest in [`internal/extract/manifests/<slug>.yaml`](../internal/extract/manifests) and compiled by `npm run adapter:compile` ([`hub/scripts/compile-manifests.mjs`](../hub/scripts/compile-manifests.mjs)) into the canonical IR `internal/extract/manifests/compiled.json`, which is shared by both the TypeScript Hub and the standalone Go Hub (`//go:embed manifests/compiled.json`).

---

## 1. Ring 1 Governance, Canary Monitoring & Security Guarantees

Site adapters sit in **Ring 1** of EdgeFetch's two-ring security model (see **[docs/SECURITY-LOG.md](SECURITY-LOG.md)** and **[CONTRIBUTING.md](../CONTRIBUTING.md)**):

1. **Pure Data — Zero Executable Adapter Code:**
   - Adapters contain **no executable TypeScript, JavaScript, or Go**, **no `eval`/`Function`**, **no direct `fetch()` calls**, and **no backtracking regular expressions** (any `regexExtract` pattern compiles strictly through `re2js` linear-time Thompson NFAs).
   - Post-fetch adapters execute inside a zero-secret, zero-network bulkhead (`runAdapterSyncInBulkhead`) and fail open to standard HTML extraction if an upstream field changes.
2. **Single Schema-Checked Compiler (`compile-manifests.mjs`):**
   - `npm run adapter:compile` parses every manifest with `yaml` (`maxAliasCount: 0, merge: false, uniqueKeys: true`), rejecting YAML anchors (`&`), aliases (`*`), merge keys (`<<`), explicit tags (`!`), non-ASCII keys, and unknown schema fields.
   - Go decodes `compiled.json` with `json.Decoder.DisallowUnknownFields()` and strict ASCII key verification so Go and TypeScript never disagree on YAML edge cases.
3. **Domain-Claim Bounds, Diff Gate & Daily Read-Only Canary:**
   - Duplicate manifest `id`s, cross-manifest domain collisions, and Public Suffix List (PSL) broad wildcards (`*`, `*.com`, `*.org`, `*.co.uk`) are rejected at compile time; all resolved `fetchUrl` targets must be public `https://:443` URLs with no credentials, fragments, or loopback/rebinding suffixes.
   - CI enforces `npm run adapter:check` and `npm run adapter:test` (`1,179` bulkhead fuzz cases), blocking invalid schemas, domain collisions, or broad wildcards.
   - Live adapter health against upstream public endpoints is checked daily by a read-only canary published at **[`edgefetch.dev/adapters/status/`](https://edgefetch.dev/adapters/status/)**.
4. **Keyless, Polite & `robots.txt`-Checked:**
   - Built-in adapters target keyless public APIs, feeds, registries, and structured HTML pages — never paid B2B API keys or undocumented private endpoints.
   - `robots.txt` and `Content-Signal: ai-input` are verified on every hop; when `/api` is disallowed by `robots.txt` (e.g., `openfoodfacts`, `arxiv`, `clinicaltrials`, `icims`), adapters use declarative `htmlRoutes` over `robots.txt`-permitted public HTML instead of `twin`.
   - **Contributor policy:** Broken-adapter reports and new adapter requests are welcome via GitHub Issues; code PRs require maintainer invitation via [`.github/VOUCHED.td`](../.github/VOUCHED.td) (`Inbound = MIT + DCO`, `git commit -s`).

---

## 2. Authoring Workflow (`adapter:new` + `adapter:test --record`)

### Option A — Pre-Fetch Public JSON / XML / Markdown Twin (`match` + `twin` + `extract`)

```bash
cd hub
npm run adapter:new developer/my-registry
```

This scaffolds `internal/extract/manifests/my-registry.yaml`, creates `hub/test/fixtures/adapters/my-registry.json`, and updates `internal/extract/manifests/compiled.json`:

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
      whenVar: version
    - label: Version
      template: "`{version}`"
      whenVar: version
```

### Option B — Post-Fetch HTML CSS-Selector / Schema.org JSON-LD (`htmlRoutes`)

```bash
cd hub
npm run adapter:new jobs/my-board --html
```

```yaml
# Shared Go + TypeScript Declarative Site Adapter: My Job Board
id: my-board
name: My Job Board
category: jobs
description: Extracts structured job postings using declarative CSS selectors and Schema.org JSON-LD.
domains:
  - jobs.example.org
exampleUrls:
  - https://jobs.example.org/listings/senior-systems-engineer

htmlRoutes:
  - id: my-board
    match:
      minSegments: 2
      pathPrefix: /listings
    mode: dom
    jsonLdTypes: [JobPosting]
    vars:
      title:
        jsonLdPaths: [title, name]
        cssText: h1
        trim: true
      location:
        jsonLdPaths: [jobLocation.address.addressLocality]
        cssText: ".job-location"
        trim: true
      body:
        cssHtmlToMd: "article, main, .job-description"
    requireVars: [title]
    titleTemplate: "{title}"
    bullets:
      - label: Location
        template: "{location}"
        whenVar: location
    bodyVar: body
```

---

## 3. Compile, Polite Live-Record & Bulkhead Fuzz

```bash
cd hub

# Compile & validate all 57 manifests in internal/extract/manifests/*.yaml -> compiled.json:
npm run adapter:compile

# Polite live test (checks /robots.txt + Content-Signal first, previews Markdown, and writes fixture JSON):
npm run adapter:test rubygems https://rubygems.org/gems/rails --record

# Run schema validation + fixture checks + >100 KB linear-time (< 50ms/case) bulkhead fuzzer across all 57 adapters:
npm run adapter:test
```
