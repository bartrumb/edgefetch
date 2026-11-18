import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSync } from 'esbuild';

const dir = mkdtempSync(join(tmpdir(), 'edgefetch-hub-test-'));
const outfile = join(dir, 'hub.test.mjs');
try {
  buildSync({
    entryPoints: ['test/hub.test.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile,
  });
  execFileSync(process.execPath, ['--test', outfile], { stdio: 'inherit' });
} finally {
  rmSync(dir, { recursive: true, force: true });
}
