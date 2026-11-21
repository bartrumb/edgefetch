#!/usr/bin/env node
/**
 * Scaffolds a new contributor Site Adapter + JSON test fixture in 1 command:
 *
 *   npm run adapter:new <category>/<slug>                # Default: zero-code shared Go+TS declarative YAML manifest
 *   npm run adapter:new <category>/<slug> --html         # TypeScript HTML adapter powered by parseHtmlDoc() CSS selectors
 *   npm run adapter:new <category>/<slug> --ts           # TypeScript custom logic adapter
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
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

const hubRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(hubRoot, '..');
const args = process.argv.slice(2);
const useTsMode = args.includes('--html') || args.includes('--ts');
const useHtmlTemplate = args.includes('--html');
const rawArg = (args.find((a) => !a.startsWith('--')) ?? '').trim();

if (!rawArg || !rawArg.includes('/')) {
  console.error(
    [
      'Usage:',
      '  npm run adapter:new <category>/<slug>          # Zero-code shared Go+TS YAML manifest (recommended)',
      '  npm run adapter:new <category>/<slug> --html   # TypeScript HTML adapter with parseHtmlDoc() CSS selectors',
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

const camelIdentifier = slug.replace(/-([a-z0-9])/g, (_m, ch) => ch.toUpperCase());
const titleLabel = slug
  .split('-')
  .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
  .join(' ');

const fixturePath = join(hubRoot, 'test', 'fixtures', 'adapters', `${slug}.json`);
mkdirSync(dirname(fixturePath), { recursive: true });

if (!useTsMode) {
  const manifestPath = join(repoRoot, 'internal', 'extract', 'manifests', `${slug}.yaml`);
  const declarativeTsPath = join(hubRoot, 'src', 'extractors', 'declarative.ts');

  if (existsSync(manifestPath) || existsSync(join(repoRoot, 'internal', 'extract', 'manifests', `${slug}.json`))) {
    console.error(`Declarative manifest already exists: ${manifestPath}`);
    process.exit(1);
  }
  mkdirSync(dirname(manifestPath), { recursive: true });

  const manifestYaml = `# Shared Go + TypeScript Declarative Site Adapter: ${titleLabel}
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

  const fixtureTemplate = {
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

  const manifestVar = `${camelIdentifier}Manifest`;
  const importStmt = `import ${manifestVar} from '../../../internal/extract/manifests/${slug}.yaml';\n`;
  const declSrc = readFileSync(declarativeTsPath, 'utf8');
  if (!declSrc.includes(importStmt)) {
    const arrMarker = 'const RAW_DECLARATIVE_MANIFESTS: ReadonlyArray<DeclarativeAdapterManifest | string> = [';
    const updated = declSrc
      .replace("import type { AdapterCategory", `${importStmt}\nimport type { AdapterCategory`)
      .replace(arrMarker, `${arrMarker}\n  ${manifestVar},`);
    writeFileSync(declarativeTsPath, updated, 'utf8');
  }

  console.log(`Created shared Go+TS manifest: ${manifestPath}`);
  console.log(`Created fixture:               ${fixturePath}`);
  console.log(`Registered in:                 ${declarativeTsPath} (and auto-embedded in Go via //go:embed)`);
  console.log(`\nNext: edit ${manifestPath}, then run: npm run adapter:test ${slug} <https://live-url> --record`);
} else {
  const providerPath = join(hubRoot, 'src', 'extractors', 'providers', category, `${slug}.ts`);
  const barrelPath = join(hubRoot, 'src', 'extractors', 'providers', 'index.ts');

  if (existsSync(providerPath)) {
    console.error(`Adapter already exists: ${providerPath}`);
    process.exit(1);
  }
  mkdirSync(dirname(providerPath), { recursive: true });

  const adapterTemplate = useHtmlTemplate
    ? `import { defineAdapter } from '../../types';
import { formatGfmTable, parseHtmlDoc } from '../../utils';

export default defineAdapter({
  id: '${slug}',
  name: '${titleLabel}',
  category: '${category}',
  description: 'Extracts structured records from ${titleLabel} HTML pages using parseHtmlDoc() CSS selectors.',
  domains: ['example.com'],
  exampleUrls: ['https://example.com/listings'],
  extractHtml({ rawHtml }) {
    const doc = parseHtmlDoc(rawHtml);
    const title = doc.text('h1') || '${titleLabel}';
    const rows: string[][] = [];
    for (const card of doc.select('.listing-card', 50)) {
      const name = card.text('h2, h3');
      const meta = card.dlMap();
      if (name) rows.push([name, meta['location'] ?? '-']);
    }
    if (rows.length === 0) return null;
    return {
      extractorId: '${slug}',
      title,
      markdown: [\`# \${title}\`, formatGfmTable(['Item', 'Location'], rows)].join('\\n\\n'),
    };
  },
});
`
    : `import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: '${slug}',
  name: '${titleLabel}',
  category: '${category}',
  description: 'Upgrades ${titleLabel} pages to their public JSON endpoint.',
  domains: ['example.com'],
  exampleUrls: ['https://example.com/items/sample'],
  resolveTwin({ host, parts }) {
    if (parts[0] !== 'items' || !parts[1]) return null;
    const id = encodeURIComponent(parts[1]);
    return {
      id: '${slug}',
      fetchUrl: \`https://\${host}/api/items/\${id}.json\`,
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || typeof data.title !== 'string') return null;
        const title = data.title.trim();
        const summary = typeof data.summary === 'string' ? data.summary.trim() : '';
        return {
          title,
          ...(summary ? { description: summary } : {}),
          markdown: [\`# \${title}\`, summary].filter(Boolean).join('\\n\\n'),
        };
      },
    };
  },
});
`;

  const fixtureTemplate = {
    adapterId: slug,
    mode: useHtmlTemplate ? 'html' : 'twin',
    inputUrl: useHtmlTemplate ? 'https://example.com/listings' : 'https://example.com/items/sample',
    ...(useHtmlTemplate ? {} : { expectedFetchUrl: 'https://example.com/api/items/sample.json' }),
    mockPayload: useHtmlTemplate
      ? `<!doctype html><html><body><h1>Sample ${titleLabel}</h1><div class="listing-card"><h3>First Item</h3><dl><dt>Location</dt><dd>Remote</dd></dl></div></body></html>`
      : JSON.stringify({
          title: `Sample ${titleLabel} Record`,
          summary: 'Clean structured output verified by the automatic fixture runner.',
        }),
    expectTitleIncludes: `Sample ${titleLabel}`,
    expectMarkdownIncludes: [`# Sample ${titleLabel}`],
  };

  writeFileSync(providerPath, adapterTemplate, 'utf8');
  writeFileSync(fixturePath, `${JSON.stringify(fixtureTemplate, null, 2)}\n`, 'utf8');

  const barrelSrc = readFileSync(barrelPath, 'utf8');
  const importStmt = `import ${camelIdentifier} from './${category}/${slug}';\n`;
  if (!barrelSrc.includes(importStmt)) {
    const marker = 'export const BUILTIN_SITE_ADAPTERS: readonly SiteAdapter[] = [';
    const updated = barrelSrc
      .replace(marker, `${importStmt}\n${marker}`)
      .replace(/\n\];\s*$/, `\n  ${camelIdentifier},\n];\n`);
    writeFileSync(barrelPath, updated, 'utf8');
  }

  console.log(`Created TypeScript adapter: ${providerPath}`);
  console.log(`Created fixture:            ${fixturePath}`);
  console.log(`Registered in:              ${barrelPath}`);
  console.log(`\nNext: customize selectors/URLs, then run: npm run adapter:test ${slug}`);
}
