# Writing & Contributing Declarative YAML Site Adapters

EdgeFetch ships an **open-source (`MIT`) 100% Declarative YAML Site, Commerce & ATS Adapter Library** covering **56+ keyless public platforms** across 7 categories (`developer`, `genai`, `jobs`, `finance`, `public-records`, `research-health`, `commerce-social`), aligned with EdgeFetch's licensing model: *open-source worker, SDKs, and adapters (`MIT`), fair-source hub (`FSL-1.1`, `MIT` after two years)*.

Every built-in and community site adapter is authored as a `#`-commented YAML 1.2 Core manifest in `internal/extract/manifests/<slug>.yaml` (`MIT`-licensed) and compiled by `npm run adapter:compile` (`hub/scripts/compile-manifests.mjs`) into the checked canonical IR `internal/extract/manifests/compiled.json` embedded in **both** the Cloudflare/Node TypeScript Hub and the pure-Go Hub (`//go:embed manifests/compiled.json`).

---

## 1. Security & Architecture Guarantees (Zero TypeScript Adapter Code)

1. **Zero Arbitrary Code Execution & Zero Network Escape:**
   - Adapters contain **zero executable TypeScript/JavaScript**, **zero `eval`/`Function`**, **zero `fetch()` calls**, and **zero backtracking regular expressions** (any `regexExtract` pattern is compiled strictly via `re2js` linear-time Thompson NFA).
2. **Single Checked Canonical IR (Zero Go-vs-TS YAML Differentials):**
   - Contributors write clean `#`-commented `.yaml` files in `internal/extract/manifests/*.yaml`.
   - `npm run adapter:compile` parses every manifest with `yaml` (`maxAliasCount: 0, merge: false, uniqueKeys: true`), rejects anchors (`&`), aliases (`*`), merge keys (`<<`), explicit tags (`!`), non-ASCII keys, and unknown/case-mismatched schema keys, and emits deterministic `internal/extract/manifests/compiled.json`.
   - Go decodes `compiled.json` with `json.Decoder.DisallowUnknownFields()` and strict ASCII key verification.
3. **Host-Claim & SSRF Hardening:**
   - Duplicate manifest `id`s and cross-manifest duplicate `twin.id`s are rejected at compile and load time.
   - Broad TLD/eTLD wildcards (`*`, `*.com`, `*.org`, `*.co.uk`) are forbidden; wildcard or `universalEngine: true` routes may only interpolate `{host}` / `{origin}` into same-origin `https://{host}/...` URLs.
   - All resolved `fetchUrl` targets are validated as public `https://` URLs with no credentials, fragments, non-443 ports, or loopback/rebinding suffixes.
4. **100% Keyless, Polite & `robots.txt`-Compliant:**
   - Target public APIs, feeds, registries, and structured HTML (never paid B2B API keys).
   - When `/api` is disallowed by `robots.txt` (e.g., `openfoodfacts`, `arxiv`, `clinicaltrials`, `icims`), use declarative `htmlRoutes` over `robots.txt`-permitted public HTML instead of `twin`.

---

## 2. Quickstart Workflow (`adapter:new` + `adapter:test --record`)

### Option A — Declarative Pre-Fetch JSON / XML / Markdown Twin (`routes` or `match`+`twin`+`extract`)

```bash
cd hub
npm run adapter:new developer/my-registry
```

This creates `internal/extract/manifests/my-registry.yaml`, creates `hub/test/fixtures/adapters/my-registry.json`, and compiles `internal/extract/manifests/compiled.json`:

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
      whenVar: version
    - label: Version
      template: "`{version}`"
      whenVar: version
```

### Option B — Declarative Post-Fetch HTML CSS-Selector / Schema.org JSON-LD (`htmlRoutes`)

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

## 3. Compile, Polite Live-Record & Fuzz in 1 Command

```bash
cd hub

# Compile & strictly validate all internal/extract/manifests/*.yaml -> compiled.json:
npm run adapter:compile

# Polite live test (verifies /robots.txt + Content-Signal, previews Markdown & token savings, and writes fixture JSON):
npm run adapter:test rubygems https://rubygems.org/gems/rails --record

# Run schema validation + fixture checks + >100 KB linear-time (< 50ms/case) bulkhead fuzzer across all 56+ adapters:
npm run adapter:test
```
