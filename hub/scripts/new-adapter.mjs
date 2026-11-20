#!/usr/bin/env node
/**
 * Scaffolds a new contributor Site Adapter + JSON test fixture in 1 command:
 *   npm run adapter:new <category>/<slug>
 * Example:
 *   npm run adapter:new developer/deno-land
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

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const rawArg = (process.argv[2] ?? '').trim();

if (!rawArg || !rawArg.includes('/')) {
  console.error(
    'Usage: npm run adapter:new <category>/<slug>\n' +
      `Categories: ${[...VALID_CATEGORIES].join(', ')}\n` +
      'Example: npm run adapter:new developer/deno-land',
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

const providerPath = join(rootDir, 'src', 'extractors', 'providers', category, `${slug}.ts`);
const fixturePath = join(rootDir, 'test', 'fixtures', 'adapters', `${slug}.json`);
const barrelPath = join(rootDir, 'src', 'extractors', 'providers', 'index.ts');

if (existsSync(providerPath)) {
  console.error(`Adapter already exists: ${providerPath}`);
  process.exit(1);
}

mkdirSync(dirname(providerPath), { recursive: true });
mkdirSync(dirname(fixturePath), { recursive: true });

const adapterTemplate = `import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: '${slug}',
  name: '${titleLabel}',
  category: '${category}',
  description: 'Describe what public JSON/Markdown twin or clean HTML extraction ${titleLabel} provides.',
  domains: ['example.com'],
  exampleUrls: ['https://example.com/items/sample'],
  // Option A: Pre-fetch 1-hop upgrade to an official public, robots.txt-allowed JSON or Markdown endpoint.
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
  // Option B: Or implement \`extractHtml({ rawHtml, baseUrl, currentMd, htmlToMd })\` for post-fetch DOM cleanup.
});
`;

const fixtureTemplate = JSON.stringify(
  {
    adapterId: slug,
    mode: 'twin',
    inputUrl: 'https://example.com/items/sample',
    expectedFetchUrl: 'https://example.com/api/items/sample.json',
    mockPayload: JSON.stringify({
      title: `Sample ${titleLabel} Record`,
      summary: 'Clean structured output verified by the automatic fixture runner.',
    }),
    expectTitleIncludes: `Sample ${titleLabel}`,
    expectMarkdownIncludes: [`# Sample ${titleLabel} Record`, 'Clean structured output'],
  },
  null,
  2,
);

writeFileSync(providerPath, adapterTemplate, 'utf8');
writeFileSync(fixturePath, `${fixtureTemplate}\n`, 'utf8');

// Auto-register in `src/extractors/providers/index.ts`
const barrelSrc = readFileSync(barrelPath, 'utf8');
const importStmt = `import ${camelIdentifier} from './${category}/${slug}';\n`;
if (!barrelSrc.includes(importStmt)) {
  const marker = 'export const BUILTIN_SITE_ADAPTERS: readonly SiteAdapter[] = [';
  const updated = barrelSrc
    .replace(marker, `${importStmt}\n${marker}`)
    .replace(/\n\];\s*$/, `\n  ${camelIdentifier},\n];\n`);
  writeFileSync(barrelPath, updated, 'utf8');
}

console.log(`Created adapter: ${providerPath}`);
console.log(`Created fixture: ${fixturePath}`);
console.log(`Registered in:   ${barrelPath}`);
console.log('\nNext: customize domains/URLs, check robots.txt on the target host, and run `npm test`!');
