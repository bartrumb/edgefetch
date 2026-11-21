import { mkdirSync } from 'node:fs';
import { buildSync } from 'esbuild';

mkdirSync('dist', { recursive: true });

buildSync({
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
  external: ['node:*'],
  outfile: 'dist/portable-server.mjs',
});
console.log('Built hub/dist/portable-server.mjs');
