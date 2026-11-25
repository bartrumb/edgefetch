# Hub Build & Developer Scripts (`hub/scripts`)

## Overview
Node.js ESM developer and CI scripts for compiling declarative YAML site-adapter manifests into canonical JSON IR (`compile-manifests.mjs`), bundling the embedded Go WASM reactor (`esbuild-wasm-plugin.mjs`), scaffolding declarative YAML site extraction adapters (`new-adapter.mjs`), live-testing/recording and fuzzing site adapters (`test-adapter.mjs`), generating OpenAPI specs (`generate-openapi.mjs`), and running the Node + `workerd` test suites (`run-tests.mjs`, `v8-coverage.mjs`).

## Interface
- `node scripts/compile-manifests.mjs [--check]` (`npm run adapter:compile` / `npm run adapter:check`) — Parses all `#`-commented `.yaml` manifests in `internal/extract/manifests/*.yaml` via `yaml` (`maxAliasCount: 0, merge: false, uniqueKeys: true`), validates strict ASCII schema keys and M2 host-claim rules, and writes deterministic `internal/extract/manifests/compiled.json` `[compile-manifests.mjs:SCHEMA_KEYS]`.
- `node scripts/new-adapter.mjs <category>/<slug> [--html]` (`npm run adapter:new`) — Scaffolds a shared Go+TS declarative YAML manifest (`internal/extract/manifests/<slug>.yaml`, twin by default or `htmlRoutes` with `--html`), writes `test/fixtures/adapters/<slug>.json`, and runs `compile-manifests.mjs` `[new-adapter.mjs:rawArg]`.
- `node scripts/test-adapter.mjs [<adapter-id>] [<https://url>] [--record]` (`npm run adapter:test`) — Runs `compile-manifests.mjs`, validates adapter metadata & Go `Accept` allowlist compliance, executes JSON/HTML fixtures, runs 8 adversarial `100 KB+` HTML & valid-JSON bulkhead fuzz payloads per adapter (`< 50 ms` cap), and optionally performs a `robots.txt`-checked live preview + path-traversal-guarded `--record` fixture capture `[test-adapter.mjs:MAX_FUZZ_MS_PER_PAYLOAD]`.
- `node scripts/run-tests.mjs` (`npm test`) — Runs `compile-manifests.mjs`, bundles TypeScript test suites and the `workerd` harness with `esbuild`, and executes `node --test --test-force-exit` `[run-tests.mjs:execFileSync]`.

## Invariants
- `compile-manifests.mjs` rejects YAML anchors (`&`), aliases (`*`), merge keys (`<<`), explicit tags (`!`), non-ASCII keys, unknown/case-mismatched keys, duplicate adapter or twin IDs, and broad TLD/eTLD wildcards `[compile-manifests.mjs:checkAstSafety]`.
- `new-adapter.mjs` and `test-adapter.mjs` validate IDs against strict lowercase regexes and verify resolved output paths stay strictly inside `internal/extract/manifests/` and `hub/test/fixtures/adapters/` `[test-adapter.mjs:resolveSafeFixtureWritePath]`.
- `test-adapter.mjs` enforces `createSafeOutboundFetch` + `fetchOverflowRobots` (`Content-Signal: ai-input` and path rules) before any live HTTP request and wraps adapter calls in `runAdapterSyncInBulkhead` `[test-adapter.mjs:checkPoliteRobots]`.

## Side Effects
- `compile-manifests.mjs` writes `internal/extract/manifests/compiled.json` (or verifies byte-exact equality with `--check`).
- `new-adapter.mjs` writes `internal/extract/manifests/<slug>.yaml` and `test/fixtures/adapters/<slug>.json`.
- `test-adapter.mjs` compiles a temporary bundle in `os.tmpdir()` (cleaned up in `finally`), optionally makes polite HTTPS requests when `<https://url>` is given, and writes `test/fixtures/adapters/<id>.json` when `--record` is set.

## Verification
- Run: `npm --prefix hub run adapter:test && npm --prefix hub test`
