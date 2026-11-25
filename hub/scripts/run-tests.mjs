import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { availableParallelism, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { ensureCoreWasmBuilt } from './build-wasm.mjs';
import { createNodeWasmPlugin, createWorkerdWasmExternalPlugin } from './esbuild-wasm-plugin.mjs';
import { collectAndPrintCoverage } from './v8-coverage.mjs';

const args = process.argv.slice(2);
const coverageEnabled = args.includes('--coverage') || process.env.EDGEFETCH_COVERAGE === '1';
const includeSdk = args.includes('--include-sdk');
const jsonArg = args.find((a) => a.startsWith('--coverage-json='));
const jsonOutPath = jsonArg ? jsonArg.slice('--coverage-json='.length) : process.env.EDGEFETCH_COVERAGE_JSON || null;

function resolveRealPath(p) {
  if (typeof realpathSync.native === 'function') {
    try {
      return realpathSync.native(p);
    } catch {
      return realpathSync(p);
    }
  }
  return realpathSync(p);
}

const scriptsDir = dirname(fileURLToPath(import.meta.url));
execFileSync(process.execPath, [join(scriptsDir, 'compile-manifests.mjs')], { stdio: 'inherit' });
const coreWasmPath = ensureCoreWasmBuilt();
const nodeWasmPlugin = createNodeWasmPlugin({ wasmAbsPath: coreWasmPath });
const workerdWasmPlugin = createWorkerdWasmExternalPlugin();

const dir = resolveRealPath(mkdtempSync(join(tmpdir(), 'edgefetch-hub-test-')));
const workerOutfile = join(dir, 'workerd-entry.mjs');
const e2eTestFile = resolve('test/workerd.e2e.test.mjs');

const textAssetLoaders = { '.sql': 'text', '.yaml': 'text', '.yml': 'text' };
const nodeBanner = {
  js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);",
};

function buildNodeTestBundle(entryPoint, outfile) {
  return build({
    entryPoints: [entryPoint],
    bundle: true,
    ...(coverageEnabled ? { treeShaking: false } : {}),
    platform: 'node',
    format: 'esm',
    banner: nodeBanner,
    alias: { 'cloudflare:workers': './test/cloudflare-workers-stub.ts' },
    loader: textAssetLoaders,
    plugins: [nodeWasmPlugin],
    sourcemap: coverageEnabled ? 'inline' : false,
    outfile,
  });
}

const suiteSpecs = [
  ['test/hub.test.ts', 'hub.test.mjs'],
  ['test/adapters.test.ts', 'adapters.test.mjs'],
  ['test/agent-advanced.test.ts', 'agent-advanced.test.mjs'],
  ['test/security-audit.test.ts', 'security-audit.test.mjs'],
  ['test/github-auth-multiuser.test.ts', 'github-auth-multiuser.test.mjs'],
  ['test/mcp-federation.test.ts', 'mcp-federation.test.mjs'],
  ['test/updates-telemetry.test.ts', 'updates-telemetry.test.mjs'],
  ['test/round7-multiuser-mcp.test.ts', 'round7-multiuser-mcp.test.mjs'],
  ['test/round7-portable-telemetry.test.ts', 'round7-portable-telemetry.test.mjs'],
  ...(existsSync(resolve('test/sdk-ts.test.ts')) ? [['test/sdk-ts.test.ts', 'sdk-ts.test.mjs']] : []),
  ['test/round7-sanitizer-adapters.test.ts', 'round7-sanitizer-adapters.test.mjs'],
  ['test/live-mcp-audit.test.ts', 'live-mcp-audit.test.mjs'],
  ['test/round8-portable-telemetry-openapi.test.ts', 'round8-portable-telemetry-openapi.test.mjs'],
  ['test/round8-sanitizer-paging-cpu.test.ts', 'round8-sanitizer-paging-cpu.test.mjs'],
  ['test/round8-auth-mcp-isolation.test.ts', 'round8-auth-mcp-isolation.test.mjs'],
  ['test/round8-manifests-commerce.test.ts', 'round8-manifests-commerce.test.mjs'],
  ['test/round9-sanitizer-jobs.test.ts', 'round9-sanitizer-jobs.test.mjs'],
  ['test/round9-auth-mcp-agent.test.ts', 'round9-auth-mcp-agent.test.mjs'],
  ['test/round9-portable-otel.test.ts', 'round9-portable-otel.test.mjs'],
  ['test/round9-bughunt.test.ts', 'round9-bughunt.test.mjs'],
  ['test/round10-sanitizer-commerce.test.ts', 'round10-sanitizer-commerce.test.mjs'],
  ['test/round10-auth-mcp-vault.test.ts', 'round10-auth-mcp-vault.test.mjs'],
  ['test/round10-live-traces.test.ts', 'round10-live-traces.test.mjs'],
  ['test/universal-extraction-scale.test.ts', 'universal-extraction-scale.test.mjs'],
  ['test/tracker-blocking.test.ts', 'tracker-blocking.test.mjs'],
  ['test/round11-stream1-sanitizer.test.ts', 'round11-stream1-sanitizer.test.mjs'],
  ['test/round11-stream4-mcp-vault.test.ts', 'round11-stream4-mcp-vault.test.mjs'],
  ['test/round11-stream5-oauth-jobs-manifests.test.ts', 'round11-stream5-oauth-jobs-manifests.test.mjs'],
];

try {
  const nodeTestFiles = suiteSpecs.map(([, outName]) => join(dir, outName));

  await Promise.all([
    ...suiteSpecs.map(([entry, outName]) => buildNodeTestBundle(entry, join(dir, outName))),
    build({
      entryPoints: ['test/workerd-harness-entry.ts'],
      bundle: true,
      platform: 'neutral',
      mainFields: ['module', 'main'],
      conditions: ['workerd', 'worker', 'browser'],
      format: 'esm',
      loader: textAssetLoaders,
      plugins: [workerdWasmPlugin],
      external: ['cloudflare:workers', 'node:*'],
      outfile: workerOutfile,
    }),
  ]);

  const covDir = join(dir, 'v8-coverage');
  if (coverageEnabled) {
    mkdirSync(covDir, { recursive: true });
  }

  const childEnv = {
    ...process.env,
    EDGEFETCH_WORKERD_BUNDLE: workerOutfile,
    EDGEFETCH_WASM_PATH: coreWasmPath,
    EDGEFETCH_HUB_ROOT: resolve('.'),
  };
  if (coverageEnabled) {
    childEnv.NODE_V8_COVERAGE = covDir;
  }

  const testConcurrency = Math.min(2, availableParallelism());
  let testErr = null;
  try {
    execFileSync(
      process.execPath,
      ['--test', `--test-concurrency=${testConcurrency}`, '--test-force-exit', ...nodeTestFiles],
      {
        stdio: 'inherit',
        env: childEnv,
      },
    );
    execFileSync(process.execPath, ['--test', '--test-force-exit', e2eTestFile], {
      stdio: 'inherit',
      env: childEnv,
    });
  } catch (err) {
    testErr = err;
  }

  if (coverageEnabled) {
    collectAndPrintCoverage({
      hubRoot: resolve('.'),
      bundles: nodeTestFiles,
      covDir,
      jsonOutPath,
      includeSdk,
    });
  }

  if (testErr) {
    throw testErr;
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
