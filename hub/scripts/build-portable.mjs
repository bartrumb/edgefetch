import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { ensureCoreWasmBuilt } from './build-wasm.mjs';
import { createNodeWasmPlugin } from './esbuild-wasm-plugin.mjs';

const scriptsDir = dirname(fileURLToPath(import.meta.url));
execFileSync(process.execPath, [join(scriptsDir, 'compile-manifests.mjs')], { stdio: 'inherit' });
const coreWasmPath = ensureCoreWasmBuilt();

mkdirSync('dist', { recursive: true });
copyFileSync(coreWasmPath, 'dist/edgefetch-core.wasm');

await build({
  entryPoints: ['portable/portable-server.ts'],
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  banner: {
    js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);",
  },
  alias: {
    'cloudflare:workers': './portable/cloudflare-shim.ts',
  },
  loader: {
    '.sql': 'text',
    '.yaml': 'text',
    '.yml': 'text',
  },
  plugins: [createNodeWasmPlugin({ portableRelative: true })],
  external: ['node:*'],
  outfile: 'dist/portable-server.mjs',
});
console.log('Built hub/dist/portable-server.mjs + hub/dist/edgefetch-core.wasm');
