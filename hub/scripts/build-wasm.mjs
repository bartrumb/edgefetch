#!/usr/bin/env node
/**
 * Compiles `cmd/edgefetch-wasm` to a persistent WASI Reactor module (`hub/src/edgefetch-core.wasm`)
 * using Go 1.26+ `GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 -buildmode=c-shared`.
 *
 * Skips recompilation when `hub/src/edgefetch-core.wasm` is already newer than all `.go` and manifest inputs.
 * Automatically falls back to WSL Go on Windows developer machines when `go.exe` is not on Windows PATH.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const hubRoot = resolve(scriptsDir, '..');
const repoRoot = resolve(hubRoot, '..');
const outWasmPath = join(hubRoot, 'src', 'edgefetch-core.wasm');
const forceRebuild = process.argv.includes('--force');

function newestMtimeMs(dirPath) {
  if (!existsSync(dirPath)) return 0;
  let maxMs = 0;
  for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
    const full = join(dirPath, entry.name);
    if (entry.isDirectory()) {
      const sub = newestMtimeMs(full);
      if (sub > maxMs) maxMs = sub;
    } else if (
      entry.name.endsWith('.go') ||
      entry.name.endsWith('.json') ||
      entry.name.endsWith('.dat') ||
      entry.name === 'go.mod'
    ) {
      const st = statSync(full);
      if (st.mtimeMs > maxMs) maxMs = st.mtimeMs;
    }
  }
  return maxMs;
}

export function ensureCoreWasmBuilt() {
  if (process.env.EDGEFETCH_SKIP_WASM_BUILD === '1' && existsSync(outWasmPath)) {
    return outWasmPath;
  }

  if (!forceRebuild && existsSync(outWasmPath)) {
    const wasmStat = statSync(outWasmPath);
    if (wasmStat.size > 100_000) {
      const latestInputMs = Math.max(
        newestMtimeMs(join(repoRoot, 'cmd', 'edgefetch-wasm')),
        newestMtimeMs(join(repoRoot, 'internal', 'extract')),
        newestMtimeMs(join(repoRoot, 'internal', 'classify')),
        newestMtimeMs(join(repoRoot, 'internal', 'politeness')),
        existsSync(join(repoRoot, 'go.mod')) ? statSync(join(repoRoot, 'go.mod')).mtimeMs : 0,
      );
      if (wasmStat.mtimeMs >= latestInputMs) {
        return outWasmPath;
      }
    }
  }

  const buildArgs = [
    'build',
    '-buildmode=c-shared',
    '-trimpath',
    '-ldflags=-s -w',
    '-o',
    outWasmPath,
    './cmd/edgefetch-wasm',
  ];

  try {
    execFileSync('go', buildArgs, {
      cwd: repoRoot,
      stdio: 'inherit',
      env: {
        ...process.env,
        GOOS: 'wasip1',
        GOARCH: 'wasm',
        CGO_ENABLED: '0',
      },
    });
    return outWasmPath;
  } catch (nativeErr) {
    if (process.platform === 'win32') {
      const wslRepo = repoRoot
        .replace(/\\/g, '/')
        .replace(/^([A-Za-z]):/, (_m, d) => `/mnt/${d.toLowerCase()}`);
      execFileSync(
        'wsl',
        [
          '-e',
          'bash',
          '-lc',
          `export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH" && cd "${wslRepo}" && GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -buildmode=c-shared -trimpath -ldflags="-s -w" -o hub/src/edgefetch-core.wasm ./cmd/edgefetch-wasm`,
        ],
        { stdio: 'inherit' },
      );
      return outWasmPath;
    }
    if (existsSync(outWasmPath) && statSync(outWasmPath).size > 100_000) {
      return outWasmPath;
    }
    throw nativeErr;
  }
}

const isMain =
  Boolean(process.argv[1]) &&
  resolve(process.argv[1]).replace(/\\/g, '/').endsWith('/build-wasm.mjs');

if (isMain) {
  const built = ensureCoreWasmBuilt();
  const sz = statSync(built).size;
  console.log(`Built ${built} (${(sz / (1024 * 1024)).toFixed(2)} MiB raw)`);
}
