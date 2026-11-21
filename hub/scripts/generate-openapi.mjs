import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const hubRoot = resolve(scriptDir, '..');
const repoRoot = resolve(hubRoot, '..');
const pkg = JSON.parse(readFileSync(resolve(hubRoot, 'package.json'), 'utf8'));

const bundled = buildSync({
  entryPoints: [resolve(hubRoot, 'src', 'openapi.ts')],
  bundle: true,
  write: false,
  platform: 'node',
  format: 'esm',
  target: 'node22',
});

const codeBase64 = Buffer.from(bundled.outputFiles[0].text, 'utf8').toString('base64');
const mod = await import(`data:text/javascript;base64,${codeBase64}`);

const spec = mod.buildOpenApiSpec({
  origin: 'https://edgefetch.dev',
  version: pkg.version,
});

const outPath = resolve(repoRoot, 'docs', 'openapi.json');
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(spec, null, 2)}\n`, 'utf8');
console.log(`Generated ${outPath} (OpenAPI ${spec.openapi}, v${spec.info.version}, ${Object.keys(spec.paths).length} paths)`);
