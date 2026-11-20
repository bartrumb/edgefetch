import { mkdirSync } from 'node:fs';
import { buildSync } from 'esbuild';

mkdirSync('dist', { recursive: true });

buildSync({
  entryPoints: ['portable/portable-server.ts'],
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  alias: {
    'cloudflare:workers': './portable/cloudflare-shim.ts',
  },
  external: ['node:*'],
  outfile: 'dist/portable-server.mjs',
});
console.log('Built hub/dist/portable-server.mjs');
