# Hub Build & Developer Scripts (`hub/scripts`)

## Overview
Node.js ESM developer and CI scripts for bundling the standalone portable Hub server (`build-portable.mjs`), scaffolding declarative YAML or TypeScript site extraction adapters (`new-adapter.mjs`), live-testing/recording and fuzzing site adapters (`test-adapter.mjs`), and compiling and running the Node + `workerd` test suites (`run-tests.mjs`).

## Interface
- `node scripts/build-portable.mjs` (`npm run build:portable`) — Bundles `portable/portable-server.ts` into `dist/portable-server.mjs` with `.sql`/`.yaml`/`.yml` text asset loaders and an ESM `createRequire` shim `[build-portable.mjs:buildSync]`.
- `node scripts/new-adapter.mjs <category>/<slug> [--html | --ts]` (`npm run adapter:new`) — Scaffolds either a shared Go+TS declarative YAML manifest (`internal/extract/manifests/<slug>.yaml`) by default or a TypeScript `parseHtmlDoc` / `resolveTwin` provider (`--html` / `--ts`) plus `test/fixtures/adapters/<slug>.json` `[new-adapter.mjs:rawArg]`.
- `node scripts/test-adapter.mjs [<adapter-id>] [<https://url>] [--record]` (`npm run adapter:test`) — Validates adapter metadata & Go `Accept` allowlist compliance, executes JSON fixtures, runs 6 adversarial `100 KB+` linear-time bulkhead fuzz payloads per adapter (`<= 120 ms` cap), and optionally performs a `robots.txt`-checked live preview + `--record` fixture capture `[test-adapter.mjs:MAX_FUZZ_MS_PER_PAYLOAD]`.
- `node scripts/run-tests.mjs` (`npm test`) — Bundles TypeScript test suites and the `workerd` harness with `esbuild` (`.sql`/`.yaml`/`.yml` text loaders), then executes `node --test --test-force-exit` `[run-tests.mjs:execFileSync]`.

## Invariants
- `build-portable.mjs`, `test-adapter.mjs`, and all 5 `buildSync` targets in `run-tests.mjs` register `.yaml` and `.yml` as `text` loaders so shared declarative YAML manifests bundle into both Node ESM and `workerd` (`platform: 'neutral'`) without filesystem reads `[build-portable.mjs:buildSync]` `[run-tests.mjs:textAssetLoaders]`.
- `new-adapter.mjs` validates `category` against `VALID_CATEGORIES` and `slug` against `/^[a-z0-9][a-z0-9-]{1,48}$/`, refusing to overwrite existing manifests or `.ts` adapters `[new-adapter.mjs:VALID_CATEGORIES]`.
- `test-adapter.mjs` enforces `createSafeOutboundFetch` + `fetchOverflowRobots` (`Content-Signal: ai-input` and path rules) before any live HTTP request and wraps adapter calls in `runAdapterSyncInBulkhead` `[test-adapter.mjs:checkPoliteRobots]`.

## Side Effects
- `build-portable.mjs` writes `dist/portable-server.mjs`.
- `new-adapter.mjs` writes `internal/extract/manifests/<slug>.yaml` + updates `src/extractors/declarative.ts` (default) or writes `src/extractors/providers/<category>/<slug>.ts` + updates `src/extractors/providers/index.ts` (`--html`/`--ts`), plus `test/fixtures/adapters/<slug>.json`.
- `test-adapter.mjs` compiles a temporary bundle in `os.tmpdir()` (cleaned up in `finally`), optionally makes polite HTTPS requests when `<https://url>` is given, and writes `test/fixtures/adapters/<id>.json` when `--record` is set.
- `run-tests.mjs` compiles test bundles into `os.tmpdir()`, runs `node --test`, and removes the temp directory on exit.

## Verification
- Run: `npm --prefix hub run adapter:test && npm --prefix hub test`
