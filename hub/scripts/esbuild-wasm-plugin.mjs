import { resolve } from 'node:path';

/**
 * esbuild plugin for Node 22 ESM test/bench bundles: resolves `*.wasm` imports to a pre-compiled
 * `WebAssembly.Module` loaded via `node:fs` `readFileSync` from `wasmAbsPath`.
 */
export function createNodeWasmPlugin({ wasmAbsPath }) {
  const resolvedWasm = wasmAbsPath ? resolve(wasmAbsPath) : '';
  return {
    name: 'edgefetch-node-wasm',
    setup(build) {
      build.onResolve({ filter: /\.wasm$/ }, () => ({
        path: 'edgefetch-core.wasm',
        namespace: 'ef-wasm-ns',
      }));
      build.onLoad({ filter: /.*/, namespace: 'ef-wasm-ns' }, () => {
        const pathExpr = JSON.stringify(resolvedWasm);
        return {
          contents: [
            'import { readFileSync } from "node:fs";',
            `const __efWasmBytes = readFileSync(${pathExpr});`,
            'const __efWasmModule = new WebAssembly.Module(__efWasmBytes);',
            'export default __efWasmModule;',
          ].join('\n'),
          loader: 'js',
        };
      });
    },
  };
}

/**
 * esbuild plugin for Miniflare `workerd` bundles: rewrites any `*.wasm` import to an external
 * `./edgefetch-core.wasm` module reference satisfied by Miniflare's `CompiledWasm` module entry.
 */
export function createWorkerdWasmExternalPlugin() {
  return {
    name: 'edgefetch-workerd-wasm',
    setup(build) {
      build.onResolve({ filter: /\.wasm$/ }, () => ({
        path: './edgefetch-core.wasm',
        external: true,
      }));
    },
  };
}
