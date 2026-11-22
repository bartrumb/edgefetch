# EdgeFetch Extraction & Token-Efficiency Benchmark (`SCRAPE_PIPELINE_VERSION = 30`)

Reproduce locally in <2 seconds with zero external network calls:

```bash
node bench/run-bench.mjs
```

## Synthetic Regression Corpus Results (8 Multi-Platform Developer Fixtures × 50 Iterations)

> **Scope note:** These fixtures are deterministic offline synthetic pages modeled on real developer/documentation DOM layouts so CI can gate extraction fidelity and boilerplate stripping in <2 seconds with zero network flakiness.

| Fixture | Raw Input Tokens | Naive Tag-Strip Tokens | **EdgeFetch `v30` Tokens** | **LLM Token Reduction** | Fidelity & Boilerplate Gate |
|---|---:|---:|---:|---:|:---:|
| Stack Overflow Q&A (Accepted Answer + Generics) | 2,283 | 1,314 | **136** | **-94.0%** | PASS |
| VitePress / MDX Docs (Callouts + GFM Table + Mega-Menu) | 2,172 | 1,230 | **83** | **-96.2%** | PASS |
| Wikipedia Technical Article (KaTeX Math + Edit Chrome) | 1,989 | 1,052 | **70** | **-96.5%** | PASS |
| IETF RFC Specification (Page-Break Stripping + Headings) | 960 | 891 | **82** | **-91.5%** | PASS |
| Hacker News Discussion (Story + Indented Comment Tree) | 355 | 85 | **98** | **-72.4%** | PASS |
| Jupyter Notebook (.ipynb Code + Execution Outputs) | 453 | 334 | **52** | **-88.5%** | PASS |
| OpenAPI 3.1 Specification (Endpoints & Schemas) | 284 | 184 | **143** | **-49.6%** | PASS |
| Hugging Face Model Card (YAML Frontmatter -> GFM Table) | 63 | 60 | **65** | **+3.2%** | PASS |
| **Total Across Corpus** | **8,559** | **5,150** | **729** | **-91.5%** | **8 / 8 PASS** |

## What the Fidelity Gate Enforces on Every Run
1. **Generic Type & Header Safety:** `Promise<Result<T, Error>>`, `ReadableStream<Uint8Array>`, and `Map<string, HostWindow>` survive HTML conversion intact (naive HTML regexes corrupt `<T>` as unknown tags).
2. **Boilerplate & Sidebar Elimination:** 45-link mega-menus, cookie consent dialogs, Stack Exchange *Hot Network Questions*, MediaWiki `[edit]` / `[citation needed]` / interlanguage lists, and RFC `[Page N]` footers are 100% absent.
3. **Rich Format Structure:** Stack Overflow `✅ Accepted Answer` ordering, KaTeX `\sum` LaTeX formulas, GFM tables, Jupyter `.ipynb` cell outputs, OpenAPI `3.1` endpoint summaries, and Hugging Face YAML frontmatter tables are preserved.
