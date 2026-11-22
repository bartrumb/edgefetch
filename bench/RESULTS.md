# EdgeFetch Reproducible Extraction & Comparison Benchmarks

Reproduce locally in under 3 seconds with Node.js 22+ (`cd hub && npm ci`) — zero API keys, zero running servers, and zero external accounts required:

```bash
# 1. Offline HTML -> Markdown fidelity, <T> generics, code-fence balance & latency (< 1s):
node bench/compare.mjs

# 2. Optional polite live check (verifies /robots.txt first) on public technical docs:
node bench/compare.mjs --live
node bench/compare.mjs --live --with-jina   # optional: set JINA_API_KEY if r.jina.ai requires auth

# 3. Multi-format synthetic regression gate (HTML, .ipynb, OpenAPI 3.1, YAML frontmatter):
node bench/run-bench.mjs
```

---

## 1. Offline HTML Comparison (`node bench/compare.mjs` — 6 Fixtures × 25 Runs)

Compares **Raw HTML** (`bytes` and `ceil(chars/4)` estimated tokens), a **Naive HTML Tag-Strip** baseline (`decodeEntities` + `replace(/<[^>]+>/g, ' ')`), and **EdgeFetch** (`extractHtmlDocument` + `recoverSsrHydrationContent` + `finalizeScrapedMarkdown`):

| Fixture | Raw HTML (`bytes` / `~tok`) | Naive Tag-Strip (`~tok` / failure mode) | EdgeFetch (`chars` / `~tok`) | Token Reduction | Latency | Gate (`<T>` + Fences + Clean) |
|---|---:|---:|---:|---:|---:|:---:|
| TypeScript SDK Docs (`<T>` Generics + Code Fences) | 7,550 B / 1,887 | 1,028 (`<T>` broken, nav/script noise) | **445** / **112** | **-94.1%** | 1.50 ms | PASS |
| Politeness & Rate-Limit Reference (GFM Table + Callout) | 11,284 B / 2,821 | 1,235 (`<T>` broken, nav/script noise) | **399** / **100** | **-96.5%** | 1.92 ms | PASS |
| E-Commerce / Tech Review Page (Ad Chrome + Spec Table) | 9,360 B / 2,330 | 1,278 (`<T>` broken, nav/script noise) | **437** / **110** | **-95.3%** | 1.40 ms | PASS |
| Next.js SPA Shell (`__NEXT_DATA__` SSR Hydration) | 7,481 B / 1,871 | 1,072 (`<T>` broken, nav/script noise) | **457** / **115** | **-93.9%** | 0.68 ms | PASS |
| Algorithm Reference (KaTeX MathML + Wiki Edit Chrome) | 9,622 B / 2,406 | 1,049 (`<T>` broken, nav/script noise) | **264** / **66** | **-97.3%** | 1.62 ms | PASS |
| IETF RFC Specification (Page-Break Chrome + Headings) | 7,200 B / 1,800 | 1,023 (structure lost, nav/script noise) | **324** / **81** | **-95.5%** | 0.63 ms | PASS |
| **Total / Sum** | **52,497 B / 13,115** | **6,685 (0/6 clean)** | **2,326** / **584** | **-95.5%** | **7.74 ms** | **6/6 PASS** |

---

## 2. Live Public Technical Pages (`node bench/compare.mjs --live`)

Fetches three real `robots.txt`-permitted public technical documents (checking `https://<origin>/robots.txt` via EdgeFetch's RFC 9309 parser before requesting each page):

| Public URL (`robots.txt` checked) | Raw HTML (`bytes` / `~tok`) | Naive Strip (`~tok`) | EdgeFetch (`chars` / `~tok`) | Token Reduction | Fetch / Extract `ms` | Balanced Fences |
|---|---:|---:|---:|---:|---:|:---:|
| `https://example.com/` | 577 B / 145 | 85 | **156** / **39** | **-73.1%** | 16 / 9.2 ms | PASS |
| `https://go.dev/doc/effective_go` | 142,916 B / 35,718 | 23,871 | **102,226** / **25,557** | **-28.4%** | 118 / 70.1 ms | PASS |
| `https://www.rfc-editor.org/rfc/rfc9309.html` | 82,367 B / 20,562 | 10,566 | **23,465** / **5,867** | **-71.5%** | 70 / 30.1 ms | PASS |

*(Note: on dense prose-and-code manuals like `go.dev/doc/effective_go`, most of the `142 KB` HTML is genuine technical text and Go code blocks that **should** be retained rather than discarded — hence `-28.4%` chrome reduction with balanced code fences intact, versus `-71.5%` on markup-heavy RFC HTML.)*

---

## 3. Multi-Format Synthetic Regression Gate (`node bench/run-bench.mjs` — 8 Fixtures × 50 Runs)

> **Scope note:** Deterministic offline fixtures modeled on developer/documentation layouts so CI gates extraction fidelity, `.ipynb` / OpenAPI / YAML frontmatter formatting, and boilerplate removal in `< 2` seconds with zero network flakiness.

| Fixture | Raw Input Tokens | Naive Tag-Strip Tokens | **EdgeFetch Tokens** | **LLM Token Reduction** | Fidelity & Boilerplate Gate |
|---|---:|---:|---:|---:|:---:|
| Stack Overflow Q&A (Accepted Answer + Generics) | 2,283 | 1,314 | **136** | **-94.0%** | PASS |
| VitePress / MDX Docs (Callouts + GFM Table + Mega-Menu) | 2,172 | 1,230 | **83** | **-96.2%** | PASS |
| Wikipedia Technical Article (KaTeX Math + Edit Chrome) | 1,989 | 1,052 | **57** | **-97.1%** | PASS |
| IETF RFC Specification (Page-Break Stripping + Headings) | 960 | 891 | **82** | **-91.5%** | PASS |
| Hacker News Discussion (Story + Indented Comment Tree) | 355 | 85 | **98** | **-72.4%** | PASS |
| Jupyter Notebook (`.ipynb` Code + Execution Outputs) | 453 | 334 | **52** | **-88.5%** | PASS |
| OpenAPI 3.1 Specification (Endpoints & Schemas) | 284 | 184 | **143** | **-49.6%** | PASS |
| Hugging Face Model Card (YAML Frontmatter -> GFM Table) | 63 | 60 | **65** | **+3.2%** | PASS |
| **Total Across Corpus** | **8,559** | **5,150** | **716** | **-91.6%** | **8 / 8 PASS** |

### What the Automated Gates Enforce on Every Run
1. **Generic Type & Code-Fence Safety:** `Promise<Array<string>>`, `Promise<Result<T, Error>>`, `ReadableStream<Uint8Array>`, `Map<string, HostWindow>`, and CommonMark fenced code blocks survive HTML conversion intact without unclosed fences.
2. **Boilerplate & Sidebar Removal:** 45-link mega-menus, cookie consent dialogs, `<script>` chunk manifests, Stack Exchange *Hot Network Questions*, MediaWiki `[edit]` / `[citation needed]` / interlanguage lists, and RFC `[Page N]` footers are stripped.
3. **Structured Technical Formats:** Stack Overflow accepted-answer ordering, Next.js `__NEXT_DATA__` SSR hydration recovery, KaTeX `\sum` LaTeX formulas, GFM tables, Jupyter `.ipynb` cell outputs, OpenAPI `3.1` endpoint summaries, and Hugging Face YAML frontmatter tables are preserved.
