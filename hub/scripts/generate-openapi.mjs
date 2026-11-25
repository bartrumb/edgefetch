import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildSync } from 'esbuild';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const hubRoot = resolve(scriptDir, '..');
const repoRoot = resolve(hubRoot, '..');
const pkg = JSON.parse(readFileSync(resolve(hubRoot, 'package.json'), 'utf8'));

const tmpDir = mkdtempSync(join(tmpdir(), 'edgefetch-openapi-'));
const tmpEntry = join(tmpDir, 'openapi.mjs');
try {
  buildSync({
    entryPoints: [resolve(hubRoot, 'src', 'openapi.ts')],
    bundle: true,
    outfile: tmpEntry,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    banner: {
      js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);",
    },
    alias: { 'cloudflare:workers': resolve(hubRoot, 'test', 'cloudflare-workers-stub.ts') },
    loader: { '.sql': 'text', '.yaml': 'text', '.yml': 'text' },
  });

  const mod = await import(pathToFileURL(tmpEntry).href);

  const spec = mod.buildOpenApiSpec({
    origin: 'https://edgefetch.dev',
    version: pkg.version,
  });

  const outPath = resolve(repoRoot, 'docs', 'openapi.json');
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(spec, null, 2)}\n`, 'utf8');
  console.log(`Generated ${outPath} (OpenAPI ${spec.openapi}, v${spec.info.version}, ${Object.keys(spec.paths).length} paths)`);
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}
