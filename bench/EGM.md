# bench

## Overview

`bench` provides an offline, deterministic Node.js benchmark and fidelity verification suite (`run-bench.mjs`) for the EdgeFetch TypeScript extraction pipeline. It bundles `hub/src/scrape.ts` and `hub/src/extractors/registry.ts` via `esbuild`, evaluates an 8-fixture developer documentation corpus against required content and boilerplate-removal assertions, measures token reduction and per-document extraction latency, and renders a GitHub Flavored Markdown benchmark table.

## Interface

- `[run-bench.mjs:#!/usr/bin/env node]` — Standalone Node ESM CLI entry point (`node bench/run-bench.mjs`); defines no ES module exports and reads no environment variables.
- `[run-bench.mjs:--write]` — CLI flag (`process.argv.includes('--write')`) that writes the generated Markdown report to `bench/RESULTS.md` instead of printing the full report to `stdout`.
- `[run-bench.mjs:CORPUS]` — 8-fixture offline benchmark array (`{ name, url, raw, run, mustInclude, mustExclude }`) exercising bundled `extractHtmlDocument`, `formatJupyterNotebookToMarkdown`, `formatOpenApiSpecToMarkdown` (`hub/src/scrape.ts`), and `formatYamlFrontmatterCard` (`hub/src/extractors/registry.ts`).
- `[run-bench.mjs:naiveStrip]` — Baseline HTML tag-stripping and whitespace-normalization comparator function `naiveStrip(raw)`.
- `[run-bench.mjs:iterations]` — Timed benchmark loop count (`50` iterations per fixture following 1 warmup pass).
- `[run-bench.mjs:rows]` — Per-fixture benchmark result records (`{ name, rawTok, naiveTok, efTok, savingsLabel, avgMs, passed }`) tracking UTF-8 byte/4 ceiling token estimates, percentage change, mean latency (`performance.now()`), and fidelity status.
- `[run-bench.mjs:totalRawTokens]`, `[run-bench.mjs:totalNaiveTokens]`, `[run-bench.mjs:totalEfTokens]`, `[run-bench.mjs:totalSavingsPct]` — Corpus-wide token totals and aggregate percentage reduction (`((totalRawTokens - totalEfTokens) / totalRawTokens) * 100`).
- `[run-bench.mjs:markdownReport]` — Generated GFM benchmark report embedding `SCRAPE_PIPELINE_VERSION`, per-fixture metrics, and aggregate token reduction.

## Invariants

- `[run-bench.mjs:mustInclude]`, `[run-bench.mjs:mustExclude]`, `[run-bench.mjs:passed]` — Every `CORPUS` fixture output must contain all `mustInclude` substrings (`missing.length === 0`) and omit all `mustExclude` substrings (`leaked.length === 0`).
- `[run-bench.mjs:allChecksPassed]` — Hard fidelity gate: if any fixture fails its substring checks, the process exits with code `1` (`process.exit(1)`) before generating or writing `RESULTS.md`.
- `[run-bench.mjs:CORPUS]`, `[run-bench.mjs:build]` — Runs 100% offline against synthetic in-memory fixtures, aliasing `cloudflare:workers` to `hub/test/cloudflare-workers-stub.ts`.

## Side Effects

- `[run-bench.mjs:tmpDir]` — Creates a temporary directory via `mkdtempSync(join(tmpdir(), 'edgefetch-bench-'))` and deletes it recursively via `rmSync(tmpDir, { recursive: true, force: true })` after corpus execution.
- `[run-bench.mjs:build]` — Loads `esbuild` from `hub/package.json` via `createRequire` to bundle `hub/src/scrape.ts` and `hub/src/extractors/registry.ts` into `${tmpDir}` (Node 22 ESM), then dynamically imports the generated bundles.
- `[run-bench.mjs:--write]` — Overwrites `bench/RESULTS.md` in UTF-8 via `writeFileSync` when `--write` is passed.
- `[run-bench.mjs:console.log]`, `[run-bench.mjs:console.error]`, `[run-bench.mjs:process.exit]` — Writes benchmark reports or summary lines to `stdout`, writes `FAIL [<fixture>]` diagnostics to `stderr`, and terminates via `process.exit(1)` when `!allChecksPassed`.

## Verification

- Run: `node bench/run-bench.mjs`
