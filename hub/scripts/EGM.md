# Hub Build & Developer Scripts (`hub/scripts`)

## Overview
Node.js ESM developer and CI scripts for bundling the standalone portable Hub server (`build-portable.mjs`), scaffolding new site extraction adapters (`new-adapter.mjs`), and compiling and running the Node + `workerd` test suites (`run-tests.mjs`).

## Interface
- `node scripts/build-portable.mjs` (`npm run build:portable`) — CLI entrypoint taking no arguments that bundles `portable/portable-server.ts` into `dist/portable-server.mjs` `[build-portable.mjs:buildSync]`.
- `node scripts/new-adapter.mjs <category>/<slug>` (`npm run adapter:new <category>/<slug>`) — CLI entrypoint reading `process.argv[2]` to scaffold a provider adapter, JSON test fixture, and barrel registration `[new-adapter.mjs:rawArg]`.
- `node scripts/run-tests.mjs` (`npm test`) — CLI entrypoint taking no arguments that bundles TypeScript test suites and the `workerd` harness with `esbuild`, then executes `node --test --test-force-exit` with `EDGEFETCH_WORKERD_BUNDLE` and `EDGEFETCH_HUB_ROOT` `[run-tests.mjs:execFileSync]`.

## Invariants
- `build-portable.mjs` bundles for Node 22 ESM (`platform: 'node'`, `target: 'node22'`, `format: 'esm'`, `bundle: true`), aliases `'cloudflare:workers'` to `'./portable/cloudflare-shim.ts'`, loads `'.sql'` files as `'text'`, and marks `'node:*'` external `[build-portable.mjs:buildSync]`.
- `new-adapter.mjs` requires a non-empty `process.argv[2]` containing `'/'`, `category` in `VALID_CATEGORIES` (`'developer'`, `'genai'`, `'jobs'`, `'finance'`, `'public-records'`, `'research-health'`, `'commerce-social'`), `slug` matching `/^[a-z0-9][a-z0-9-]{1,48}$/`, and non-existence of `src/extractors/providers/<category>/<slug>.ts` before writing any files `[new-adapter.mjs:rawArg]` `[new-adapter.mjs:VALID_CATEGORIES]` `[new-adapter.mjs:slug]` `[new-adapter.mjs:existsSync]`.
- `new-adapter.mjs` barrel registration in `src/extractors/providers/index.ts` is idempotent if `importStmt` already exists and requires exact marker `'export const BUILTIN_SITE_ADAPTERS: readonly SiteAdapter[] = ['` plus trailing `/\n\];\s*$/` `[new-adapter.mjs:barrelSrc]`.
- `run-tests.mjs` compiles `test/hub.test.ts`, `test/adapters.test.ts`, `test/agent-advanced.test.ts`, and `test/security-audit.test.ts` with `'cloudflare:workers'` aliased to `'./test/cloudflare-workers-stub.ts'` and `'.sql'` loaded as `'text'`, compiles `test/workerd-harness-entry.ts` as neutral ESM (`conditions: ['workerd', 'worker', 'browser']`, `external: ['cloudflare:workers', 'node:*']`), and removes its temporary build directory inside `finally` `[run-tests.mjs:buildSync]` `[run-tests.mjs:rmSync]`.

## Side Effects
- `build-portable.mjs` creates `dist/` (`mkdirSync`) and writes `dist/portable-server.mjs` `[build-portable.mjs:mkdirSync]` `[build-portable.mjs:buildSync]`.
- `new-adapter.mjs` creates `src/extractors/providers/<category>/` and `test/fixtures/adapters/`, writes `src/extractors/providers/<category>/<slug>.ts` and `test/fixtures/adapters/<slug>.json`, mutates `src/extractors/providers/index.ts`, or writes errors to `stderr` and exits with code `1` on validation failure `[new-adapter.mjs:mkdirSync]` `[new-adapter.mjs:writeFileSync]` `[new-adapter.mjs:process.exit]`.
- `run-tests.mjs` creates `<os.tmpdir()>/edgefetch-hub-test-*`, writes compiled `.mjs` test and `workerd` bundles, spawns `process.execPath --test --test-force-exit` synchronously with `stdio: 'inherit'`, and deletes the temporary directory on exit `[run-tests.mjs:mkdtempSync]` `[run-tests.mjs:buildSync]` `[run-tests.mjs:execFileSync]` `[run-tests.mjs:rmSync]`.

## Verification
- Run: `npm --prefix hub test`
