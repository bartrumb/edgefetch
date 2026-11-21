import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';

const scriptsDir = dirname(fileURLToPath(import.meta.url));
execFileSync(process.execPath, [join(scriptsDir, 'compile-manifests.mjs')], { stdio: 'inherit' });

const dir = mkdtempSync(join(tmpdir(), 'edgefetch-hub-test-'));
const unitOutfile = join(dir, 'hub.test.mjs');
const adaptersOutfile = join(dir, 'adapters.test.mjs');
const agentAdvOutfile = join(dir, 'agent-advanced.test.mjs');
const secAuditOutfile = join(dir, 'security-audit.test.mjs');
const workerOutfile = join(dir, 'workerd-entry.mjs');
const e2eTestFile = resolve('test/workerd.e2e.test.mjs');

const textAssetLoaders = { '.sql': 'text', '.yaml': 'text', '.yml': 'text' };

try {
  buildSync({
    entryPoints: ['test/hub.test.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    banner: { js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);" },
    alias: { 'cloudflare:workers': './test/cloudflare-workers-stub.ts' },
    loader: textAssetLoaders,
    outfile: unitOutfile,
  });

  buildSync({
    entryPoints: ['test/adapters.test.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    banner: { js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);" },
    alias: { 'cloudflare:workers': './test/cloudflare-workers-stub.ts' },
    loader: textAssetLoaders,
    outfile: adaptersOutfile,
  });

  buildSync({
    entryPoints: ['test/agent-advanced.test.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    banner: { js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);" },
    alias: { 'cloudflare:workers': './test/cloudflare-workers-stub.ts' },
    loader: textAssetLoaders,
    outfile: agentAdvOutfile,
  });

  buildSync({
    entryPoints: ['test/security-audit.test.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    banner: { js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);" },
    alias: { 'cloudflare:workers': './test/cloudflare-workers-stub.ts' },
    loader: textAssetLoaders,
    outfile: secAuditOutfile,
  });

  buildSync({
    entryPoints: ['test/workerd-harness-entry.ts'],
    bundle: true,
    platform: 'neutral',
    mainFields: ['module', 'main'],
    conditions: ['workerd', 'worker', 'browser'],
    format: 'esm',
    loader: textAssetLoaders,
    external: ['cloudflare:workers', 'node:*'],
    outfile: workerOutfile,
  });

  execFileSync(process.execPath, ['--test', '--test-force-exit', unitOutfile, adaptersOutfile, agentAdvOutfile, secAuditOutfile, e2eTestFile], {
    stdio: 'inherit',
    env: { ...process.env, EDGEFETCH_WORKERD_BUNDLE: workerOutfile, EDGEFETCH_HUB_ROOT: resolve('.') },
  });
} finally {
  rmSync(dir, { recursive: true, force: true });
}
