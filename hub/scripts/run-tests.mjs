import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { buildSync } from 'esbuild';

const dir = mkdtempSync(join(tmpdir(), 'edgefetch-hub-test-'));
const unitOutfile = join(dir, 'hub.test.mjs');
const workerOutfile = join(dir, 'workerd-entry.mjs');
const e2eTestFile = resolve('test/workerd.e2e.test.mjs');

try {
  buildSync({
    entryPoints: ['test/hub.test.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile: unitOutfile,
  });

  buildSync({
    entryPoints: ['test/workerd-harness-entry.ts'],
    bundle: true,
    platform: 'neutral',
    mainFields: ['module', 'main'],
    conditions: ['workerd', 'worker', 'browser'],
    format: 'esm',
    external: ['cloudflare:workers', 'node:*'],
    outfile: workerOutfile,
  });

  execFileSync(process.execPath, ['--test', '--test-force-exit', unitOutfile, e2eTestFile], {
    stdio: 'inherit',
    env: { ...process.env, EDGEFETCH_WORKERD_BUNDLE: workerOutfile },
  });
} finally {
  rmSync(dir, { recursive: true, force: true });
}
