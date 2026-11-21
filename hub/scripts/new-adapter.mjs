#!/usr/bin/env node
/**
 * Scaffolds a new contributor Declarative YAML Site Adapter + JSON test fixture in 1 command:
 *
 *   npm run adapter:new <category>/<slug>          # Default: declarative YAML pre-fetch JSON/text twin manifest
 *   npm run adapter:new <category>/<slug> --html   # Declarative YAML post-fetch HTML CSS-selector/JSON-LD manifest
 *
 * 100% of EdgeFetch site adapters are declarative `#`-commented `.yaml` manifests in
 * `internal/extract/manifests/<slug>.yaml` compiled to `internal/extract/manifests/compiled.json`
 * and shared across both the TypeScript Hub and the pure-Go Hub (`//go:embed`).
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const VALID_CATEGORIES = new Set([
  'developer',
  'genai',
  'jobs',
  'finance',
  'public-records',
  'research-health',
  'commerce-social',
]);

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const hubRoot = resolve(scriptsDir, '..');
const repoRoot = resolve(hubRoot, '..');
const args = process.argv.slice(2);

if (args.includes('--ts')) {
  console.error(
    'TypeScript site adapters have been retired: 100% of EdgeFetch site adapters are declarative YAML manifests in internal/extract/manifests/<slug>.yaml.\nUse `npm run adapter:new <category>/<slug>` (or add `--html` for declarative CSS-selector/JSON-LD HTML routes).',
  );
  process.exit(1);
}

const useHtmlTemplate = args.includes('--html');
const rawArg = (args.find((a) => !a.startsWith('--')) ?? '').trim();

if (!rawArg || !rawArg.includes('/')) {
  console.error(
    [
      'Usage:',
      '  npm run adapter:new <category>/<slug>          # Shared Go+TS declarative YAML twin manifest',
      '  npm run adapter:new <category>/<slug> --html   # Shared declarative YAML HTML CSS-selector/JSON-LD manifest',
      `Categories: ${[...VALID_CATEGORIES].join(', ')}`,
      'Example: npm run adapter:new developer/deno-land',
    ].join('\n'),
  );
  process.exit(1);
}

const [category, slug] = rawArg.split('/', 2);
if (!category || !VALID_CATEGORIES.has(category)) {
  console.error(`Invalid category "${category}". Expected one of: ${[...VALID_CATEGORIES].join(', ')}`);
  process.exit(1);
}
if (!slug || !/^[a-z0-9][a-z0-9-]{1,48}$/.test(slug)) {
  console.error(`Invalid slug "${slug}". Use lowercase kebab-case (e.g. "deno-land").`);
  process.exit(1);
}

const titleLabel = slug
  .split('-')
  .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
  .join(' ');

const manifestsDir = resolve(repoRoot, 'internal', 'extract', 'manifests');
const manifestPath = resolve(manifestsDir, `${slug}.yaml`);
if (!manifestPath.startsWith(manifestsDir + sep)) {
  console.error(`Refusing unsafe manifest path: ${manifestPath}`);
  process.exit(1);
}
if (existsSync(manifestPath)) {
  console.error(`Declarative YAML manifest already exists: ${manifestPath}`);
  process.exit(1);
}

const fixturesDir = resolve(hubRoot, 'test', 'fixtures', 'adapters');
const fixturePath = resolve(fixturesDir, `${slug}.json`);
if (!fixturePath.startsWith(fixturesDir + sep)) {
  console.error(`Refusing unsafe fixture path: ${fixturePath}`);
  process.exit(1);
}

mkdirSync(manifestsDir, { recursive: true });
mkdirSync(fixturesDir, { recursive: true });

const manifestYaml = useHtmlTemplate
  ? `# Shared Go + TypeScript Declarative Site Adapter: ${titleLabel}
id: ${slug}
name: ${titleLabel}
category: ${category}
description: Extracts structured records from ${titleLabel} HTML pages using declarative CSS selectors and Schema.org JSON-LD.
domains:
  - example.com
exampleUrls:
  - https://example.com/listings/sample

htmlRoutes:
  - id: ${slug}
    match:
      minSegments: 1
      pathPrefix: /listings
    mode: dom
    jsonLdTypes: [Article, WebPage, JobPosting, Product]
    vars:
      title:
        jsonLdPaths: [name, headline]
        cssText: h1
        metaKeys: [og:title]
        trim: true
      summary:
        jsonLdPaths: [description]
        metaKeys: [description, og:description]
        trim: true
      location:
        cssText: ".listing-location"
        trim: true
      body:
        cssHtmlToMd: "article, main, .listing-body"
    requireVars: [title]
    titleTemplate: "{title}"
    descriptionVar: summary
    introVar: summary
    bullets:
      - label: Location
        template: "{location}"
        whenVar: location
    bodyVar: body
`
  : `# Shared Go + TypeScript Declarative Site Adapter: ${titleLabel}
id: ${slug}
name: ${titleLabel}
category: ${category}
description: Upgrades ${titleLabel} item pages to their public JSON API.
domains:
  - example.com
exampleUrls:
  - https://example.com/items/sample

# Matches /items/<id> without regex backtracking (charsets: alnum, slug, pkg, model_slug, doi_rest, safe_subpath)
match:
  exactSegments: true
  pathSegments:
    - items
    - param: id
      charset: slug
      minLen: 1
      maxLen: 80

twin:
  fetchUrl: https://example.com/api/items/{id}.json
  kind: json
  accept: application/json

extract:
  requireFields:
    - title
  vars:
    title:
      paths: [title]
      trim: true
    summary:
      paths: [summary, description]
      trim: true
    version:
      paths: [version]
  titleTemplate: "{title}"
  descriptionVar: summary
  introVar: summary
  bullets:
    - label: Version
      template: "\`{version}\`"
      whenVar: version
`;

const fixtureTemplate = useHtmlTemplate
  ? {
      adapterId: slug,
      mode: 'html',
      inputUrl: 'https://example.com/listings/sample',
      mockPayload: `<!doctype html><html><body><h1>Sample ${titleLabel}</h1><meta name="description" content="Clean structured HTML extraction." /><span class="listing-location">Remote</span><article><p>Detailed body text.</p></article></body></html>`,
      expectTitleIncludes: `Sample ${titleLabel}`,
      expectMarkdownIncludes: [`# Sample ${titleLabel}`, 'Remote'],
    }
  : {
      adapterId: slug,
      mode: 'twin',
      inputUrl: 'https://example.com/items/sample',
      expectedFetchUrl: 'https://example.com/api/items/sample.json',
      mockPayload: JSON.stringify({
        title: `Sample ${titleLabel} Record`,
        summary: 'Clean structured output verified by the automatic fixture runner.',
        version: '1.0.0',
      }),
      expectTitleIncludes: `Sample ${titleLabel}`,
      expectMarkdownIncludes: [`# Sample ${titleLabel} Record`, 'Clean structured output'],
    };

writeFileSync(manifestPath, manifestYaml, 'utf8');
writeFileSync(fixturePath, `${JSON.stringify(fixtureTemplate, null, 2)}\n`, 'utf8');

execFileSync(process.execPath, [join(scriptsDir, 'compile-manifests.mjs')], { stdio: 'inherit' });

console.log(`Created declarative YAML manifest: ${manifestPath}`);
console.log(`Created fixture:                   ${fixturePath}`);
console.log(`\nNext: customize ${manifestPath}, then run: npm run adapter:test ${slug} <https://live-url> --record`);
