# Writing & Contributing Site Adapters

EdgeFetch ships a modular, zero-dependency **Site & ATS Adapter Library** (`hub/src/extractors/providers/`) covering **49+ keyless public platforms** across 7 categories.

Every adapter lives in **one self-contained file** + **one JSON test fixture**, so contributors and coding agents can add a new site or job board in ~5 minutes with **zero merge conflicts** on core engine code.

> **Architecture Note (Zero Edge-Node Redeploys & Automatic Fail-Open):**
> - **0% of site/ATS adapters are compiled into the Go edge worker binary.** Go edge nodes (`edgefetch`) are stateless HTTP/2, CDP, and PDF engines; all 49+ adapters live on the TypeScript Hub (`hub/src/extractors/providers/` and `hub/src/jobs.ts`). Updating or adding an adapter is a 3-second Hub deploy with **zero binary updates** across your Raspberry Pi / Home Assistant / VM fleet.
> - **Fault-isolated fail-open fallback:** Every `resolveTwin()`, `formatTwin()`, and `extractHtml()` call runs inside an isolated `try / catch` bulkhead. If an upstream site changes a JSON key or DOM selector tomorrow, the adapter returns `null` and EdgeFetch **automatically falls back** to generic HTML / Schema.org JSON-LD / SSR Hydration / Headless CDP extraction instead of failing the request.

---

## 1. Ground Rules (Enforced by CI & Registry Guards)

1. **100% Keyless & Public Sources Only:**
   - Built-in EdgeFetch adapters target **public, keyless APIs, feeds, registries, and structured HTML**.
   - Never add commercial B2B enrichment wrappers that require paid seats or proprietary API keys (users who want commercial third-party providers can configure `FIRECRAWL_API_KEY`).
2. **Strict `robots.txt` & Ethical Compliance:**
   - **Always verify `/robots.txt` on the target host first.** For example, `api.smartrecruiters.com`, `export.arxiv.org`, `clinicaltrials.gov/api/`, and `world.openfoodfacts.org/api` disallow automated crawlers in `robots.txt`, whereas their public HTML pages (`/study/NCT...`, `/abs/...`, `/product/...`) are allowed — so those adapters use `extractHtml()` instead of `resolveTwin()`!
   - Adapters **never** call `fetch()` directly. `resolveTwin()` returns a declarative `https://` URL that EdgeFetch executes through `executeHubFetch`, inheriting `robots.txt` checks, dial-time SSRF protection, per-host politeness, and OTLP tracing automatically.
3. **No Anti-Bot Bypasses:**
   - Never add CAPTCHA solvers, stealth fingerprint spoofing, or WAF workarounds.

---

## 2. Directory Layout

```text
hub/src/extractors/
├── types.ts                      # defineAdapter(), SiteAdapter, TwinMatchContext, HtmlExtractContext
├── utils.ts                      # parseJsonObject, formatGfmTable, extractJsonLdObjects, safeFence, ...
├── registry.ts                   # O(1) exact-domain Map + wildcard & universal-engine dispatcher
└── providers/
    ├── index.ts                  # Barrel registration list
    ├── developer/                # npm, crates.io, PyPI, pkg.go.dev, NIST NVD, App Store, Google Play, ...
    ├── genai/                    # Hugging Face, OpenRouter, Internet Archive
    ├── jobs/                     # Workable, Greenhouse, Lever, Gem, Pinpoint, Rippling, Teamtailor, ...
    ├── finance/                  # SEC EDGAR, Y Combinator / Work at a Startup, Polymarket
    ├── public-records/           # Socrata SODA, CKAN (data.gov), ArcGIS REST, Legistar, USAspending
    ├── research-health/          # PubMed/PMC, DOI/Crossref, OpenAlex, arXiv, ClinicalTrials, PubChem, openFDA
    └── commerce-social/          # Shopify, Open Food Facts, Hacker News, Bluesky, Mastodon, Discourse, Reddit, ...
```

Live catalog inspection is available at **`GET /v1/extractors`** (and `GET /v1/extractors?category=jobs`).

---

## 3. Quickstart: Add an Adapter in 3 Steps

### Step 1 — Scaffold the Adapter & Fixture

```bash
cd hub
npm run adapter:new <category>/<slug>
# Example:
npm run adapter:new developer/deno-land
```

This single command:
1. Creates `hub/src/extractors/providers/developer/deno-land.ts`
2. Creates `hub/test/fixtures/adapters/deno-land.json`
3. Registers `denoLand` in `hub/src/extractors/providers/index.ts`

### Step 2 — Choose `resolveTwin` vs. `extractHtml`

- **Use `resolveTwin({ url, host, path, parts })`** when the site exposes an official, keyless, `robots.txt`-permitted JSON, Markdown, XML/RSS, or `.patch` endpoint (1 network hop total, zero HTML parsing overhead).
- **Use `extractHtml({ url, host, path, parts, rawHtml, currentMd, htmlToMd })`** when the public JSON endpoint is disallowed by `robots.txt` (or doesn't exist), and the public HTML embeds structured JSON-LD (`extractJsonLdObjects`), SSR state, or clean DOM landmarks (`extractBalancedDivAt`).

```ts
import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'my-provider',
  name: 'My Public Registry',
  category: 'developer',
  description: 'Upgrades example.org item pages to clean public JSON metadata.',
  domains: ['example.org', 'www.example.org'], // supports '*.example.org' subdomains too
  exampleUrls: ['https://example.org/pkg/demo'],
  resolveTwin({ parts }) {
    if (parts[0] !== 'pkg' || !parts[1]) return null;
    return {
      id: 'my-provider',
      fetchUrl: `https://example.org/api/v1/pkg/${encodeURIComponent(parts[1])}.json`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.name !== 'string') return null;
        return {
          title: data.name,
          markdown: `# ${data.name}\n\n${String(data.summary ?? '')}`,
        };
      },
    };
  },
});
```

### Step 3 — Update Your JSON Fixture & Run Tests

Edit `hub/test/fixtures/adapters/<slug>.json` with a realistic sample URL, mock API/HTML payload, and expected Markdown substrings. `hub/test/adapters.test.ts` **automatically discovers and runs every `.json` file** in `hub/test/fixtures/adapters/`!

```bash
cd hub
npm run type-check
npm test
```
