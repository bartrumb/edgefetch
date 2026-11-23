import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';
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

const dir = resolveRealPath(mkdtempSync(join(tmpdir(), 'edgefetch-hub-test-')));
const unitOutfile = join(dir, 'hub.test.mjs');
const adaptersOutfile = join(dir, 'adapters.test.mjs');
const agentAdvOutfile = join(dir, 'agent-advanced.test.mjs');
const secAuditOutfile = join(dir, 'security-audit.test.mjs');
const ghMultiOutfile = join(dir, 'github-auth-multiuser.test.mjs');
const mcpFedOutfile = join(dir, 'mcp-federation.test.mjs');
const updatesTelOutfile = join(dir, 'updates-telemetry.test.mjs');
const r7MultiMcpOutfile = join(dir, 'round7-multiuser-mcp.test.mjs');
const r7PortTelOutfile = join(dir, 'round7-portable-telemetry.test.mjs');
const sdkTsTestFile = resolve('test/sdk-ts.test.ts');
const hasSdkTsTest = existsSync(sdkTsTestFile);
const sdkTsOutfile = join(dir, 'sdk-ts.test.mjs');
const workerOutfile = join(dir, 'workerd-entry.mjs');
const e2eTestFile = resolve('test/workerd.e2e.test.mjs');

const textAssetLoaders = { '.sql': 'text', '.yaml': 'text', '.yml': 'text' };
const nodeBanner = {
  js: "import { createRequire as __efCreateRequire } from 'node:module'; const require = __efCreateRequire(import.meta.url);",
};

function buildNodeTestBundle(entryPoint, outfile) {
  buildSync({
    entryPoints: [entryPoint],
    bundle: true,
    ...(coverageEnabled ? { treeShaking: false } : {}),
    platform: 'node',
    format: 'esm',
    banner: nodeBanner,
    alias: { 'cloudflare:workers': './test/cloudflare-workers-stub.ts' },
    loader: textAssetLoaders,
    sourcemap: coverageEnabled ? 'inline' : false,
    outfile,
  });
}

try {
  buildNodeTestBundle('test/hub.test.ts', unitOutfile);
  buildNodeTestBundle('test/adapters.test.ts', adaptersOutfile);
  buildNodeTestBundle('test/agent-advanced.test.ts', agentAdvOutfile);
  buildNodeTestBundle('test/security-audit.test.ts', secAuditOutfile);
  buildNodeTestBundle('test/github-auth-multiuser.test.ts', ghMultiOutfile);
  buildNodeTestBundle('test/mcp-federation.test.ts', mcpFedOutfile);
  buildNodeTestBundle('test/updates-telemetry.test.ts', updatesTelOutfile);
  buildNodeTestBundle('test/round7-multiuser-mcp.test.ts', r7MultiMcpOutfile);
  buildNodeTestBundle('test/round7-portable-telemetry.test.ts', r7PortTelOutfile);

  const nodeTestFiles = [
    unitOutfile,
    adaptersOutfile,
    agentAdvOutfile,
    secAuditOutfile,
    ghMultiOutfile,
    mcpFedOutfile,
    updatesTelOutfile,
    r7MultiMcpOutfile,
    r7PortTelOutfile,
  ];
  if (hasSdkTsTest) {
    buildNodeTestBundle('test/sdk-ts.test.ts', sdkTsOutfile);
    nodeTestFiles.push(sdkTsOutfile);
  }
  const round7SanitizerOutfile = join(dir, 'round7-sanitizer-adapters.test.mjs');
  buildNodeTestBundle('test/round7-sanitizer-adapters.test.ts', round7SanitizerOutfile);
  nodeTestFiles.push(round7SanitizerOutfile);
  const liveMcpAuditOutfile = join(dir, 'live-mcp-audit.test.mjs');
  buildNodeTestBundle('test/live-mcp-audit.test.ts', liveMcpAuditOutfile);
  nodeTestFiles.push(liveMcpAuditOutfile);
  const round8PortTelOpenapiOutfile = join(dir, 'round8-portable-telemetry-openapi.test.mjs');
  buildNodeTestBundle('test/round8-portable-telemetry-openapi.test.ts', round8PortTelOpenapiOutfile);
  nodeTestFiles.push(round8PortTelOpenapiOutfile);
  const round8SanitizerOutfile = join(dir, 'round8-sanitizer-paging-cpu.test.mjs');
  buildNodeTestBundle('test/round8-sanitizer-paging-cpu.test.ts', round8SanitizerOutfile);
  nodeTestFiles.push(round8SanitizerOutfile);
  const round8AuthMcpOutfile = join(dir, 'round8-auth-mcp-isolation.test.mjs');
  buildNodeTestBundle('test/round8-auth-mcp-isolation.test.ts', round8AuthMcpOutfile);
  nodeTestFiles.push(round8AuthMcpOutfile);
  const round8ManifestsOutfile = join(dir, 'round8-manifests-commerce.test.mjs');
  buildNodeTestBundle('test/round8-manifests-commerce.test.ts', round8ManifestsOutfile);
  nodeTestFiles.push(round8ManifestsOutfile);

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

  const covDir = join(dir, 'v8-coverage');
  if (coverageEnabled) {
    mkdirSync(covDir, { recursive: true });
  }

  const childEnv = {
    ...process.env,
    EDGEFETCH_WORKERD_BUNDLE: workerOutfile,
    EDGEFETCH_HUB_ROOT: resolve('.'),
  };
  if (coverageEnabled) {
    childEnv.NODE_V8_COVERAGE = covDir;
  }

  let testErr = null;
  try {
    execFileSync(
      process.execPath,
      ['--test', '--test-force-exit', ...nodeTestFiles, e2eTestFile],
      {
        stdio: 'inherit',
        env: childEnv,
      },
    );
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
