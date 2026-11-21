# extract

## Overview
Package `extract` converts raw HTML and PDF payloads into GitHub-Flavored Markdown, plain text, resolved links and images, CSS branding profiles, BM25 query-reranked passages, PII-redacted text, `/llms.txt` discovery metadata, and declarative YAML/JSON site-adapter twins (`manifests/*.yaml`) using the Go standard library (with optional Poppler `pdftotext` acceleration).

## Interface
- `[extract.go:ImageInfo]`, `[extract.go:BrandingProfile]`, `[extract.go:PageExtraction]`, `[extract.go:ExtractOptions]`: HTML extraction option and output structs.
- `[extract.go:DetectRenderedChallenge]`: `func DetectRenderedChallenge(rawHTML string) string` — delegates `classify.ClassifyWAF(200, nil, []byte(rawHTML))` and returns `waf.Summary` or `""`.
- `[extract.go:NeedsBrowserRender]`: `func NeedsBrowserRender(rawHTML string) bool` — detects client-side SPA shell documents needing headless Chromium rendering.
- `[extract.go:ExtractHTML]`, `[extract.go:PlainText]`: Convert raw HTML into Markdown, plain text, resolved links/images, and optional branding signals.
- `[extract.go:RerankPassages]`: `func RerankPassages(doc, query string, maxChars int) string` — BM25 + exact-phrase passage reranker preserving original reading order.
- `[extract.go:RedactPII]`: `func RedactPII(s string) string` — redacts emails (`[REDACTED_EMAIL]`), SSNs (`[REDACTED_SSN]`), Luhn-valid payment cards (`[REDACTED_CARD]`), and phone numbers (`[REDACTED_PHONE]`).
- `[sanitize.go:SanitizeScrapedMeta]`, `[sanitize.go:SanitizeScrapedMarkdown]`: Strip NUL/invisible smuggling runes, neutralize `javascript:`/`vbscript:`/`data:` Markdown links, and linearly escape raw HTML tags outside inline/fenced code spans (`O(N)` single-pass scanner).
- `[yaml_subset.go:ParseDeclarativeYAML]`, `[yaml_subset.go:YAMLToJSON]`: Zero-dependency safe YAML 1.2 Core Schema parser converting declarative `.yaml` manifests into Go maps/slices and canonical JSON bytes.
- `[declarative.go:DeclarativeAdapterManifest]`, `[declarative.go:DeclarativeAdapterSummary]`, `[declarative.go:DeclarativeTwinMatch]`, `[declarative.go:DeclarativeFormattedDoc]`: Shared Go + TypeScript declarative YAML v2 manifest schema (`//go:embed manifests/compiled.json`), catalog summary, 1-hop twin match, and formatted Markdown output structs across all 56+ built-in site adapters.
- `[declarative.go:ParseDeclarativeManifest]`, `[declarative.go:ParseDeclarativeYAMLManifest]`, `[declarative.go:ListDeclarativeAdapters]`, `[declarative.go:FindDeclarativeAdapters]`, `[declarative.go:ResolveDeclarativeTwin]`, `[declarative.go:DeclarativeTwinMatch.Format]`: Validate YAML/JSON manifests, list/search embedded adapters, resolve `https://` twin URLs without regex backtracking, and format JSON/text payloads into GitHub-Flavored Markdown.
- `[llms.go:LlmsLink]`, `[llms.go:LlmsDocument]`, `[llms.go:LlmsDiscovery]`: Structured `/llms.txt` index and page-matching structs.
- `[llms.go:ParseLlmsTxt]`, `[llms.go:LlmsDocument.MatchPage]`, `[llms.go:CandidateCompanionMarkdownURL]`: Parse `/llms.txt` indexes, match target pages, and derive candidate `<path>.md` URLs.
- `[pdf.go:HasPDFToText]`, `[pdf.go:IsPDFBytes]`, `[pdf.go:ExtractPDFFileText]`, `[pdf.go:ExtractPDFText]`: Poppler `pdftotext -layout` extraction with a pure-Go FlateDecode fallback.

## Invariants
- `[extract.go:NeedsBrowserRender]`: Returns `false` when `len(PlainText(rawHTML)) >= 240` or `<script` is absent; matches empty `root|app|__next|__nuxt` shells or `< 80` chars with `type="module"`, `/_next/static/`, or `vite`.
- `[extract.go:ExtractHTML]`, `[extract.go:htmlFragmentToMarkdown]`: Focuses `<main>`/`<article>` when `OnlyMainContent` is true and inner plain text `>= 32` chars; protects `<pre><code>`, `<code>`, `<table>`, and URLs with NUL-wrapped sentinel tokens before stripping HTML tags; strips Unicode tag/bidi smuggling characters (`[extract.go:reInvisibleSmuggling]`); and drops `data:`/`javascript:` links.
- `[extract.go:scanHeadMetadata]`, `[extract.go:extractStyleSignals]`, `[extract.go:extractLinks]`, `[extract.go:extractImages]`: Enforces bounded scans and output caps (`<= 250` unique links, `<= 60` unique images, `<= 8` hex colors, `<= 6` fonts).
- `[extract.go:RedactPII]`, `[extract.go:isLuhnCard]`: Replaces candidate 13–19 digit card sequences with `[REDACTED_CARD]` only when `isLuhnCard` (`sum%10 == 0`) passes, prior to phone-number redaction.
- `[yaml_subset.go:ParseDeclarativeYAML]`, `[yaml_subset.go:maxYAMLBytes]`, `[yaml_subset.go:maxYAMLDepth]`: Caps YAML manifests at `1 MiB` and nesting depth `<= 32`, forbids tab indentation, and explicitly rejects YAML anchors (`&`), aliases (`*`), merge keys (`<<`), and custom tags (`!`) to prevent billion-laughs expansion.
- `[declarative.go:ResolveDeclarativeTwin]`, `[declarative.go:isSafePublicTwinURL]`, `[declarative.go:DeclarativeTwinMatch.Format]`: Evaluates character-class segment/query matchers with zero regex backtracking, requires public non-IP `https://` twin URLs without credentials or `..` segments, preserves JSON wire key order (`[declarative.go:extractOrderedObjectKeys]`), strips Unicode tag/bidi smuggling runes, and returns `(nil, false)` on HTML soft-404s or invalid/mismatched JSON so callers fall back to HTML scraping.
- `[llms.go:ParseLlmsTxt]`, `[llms.go:CandidateCompanionMarkdownURL]`: Rejects HTML soft-404 responses (`<!doctype`, `<html`, `<body` in first 256 bytes), caps parsed links at `500` and `RawPreview` at `4096` bytes, and restricts candidate companion `.md` URLs to queryless non-asset `https` paths.
- `[pdf.go:IsPDFBytes]`, `[pdf.go:ExtractPDFFileText]`, `[pdf.go:ExtractPDFText]`, `[pdf.go:maxPDFTextOutputBytes]`: Requires `%PDF-` in the first 1,024 bytes on `ExtractPDFText`, clamps `maxPages` to `[1, 500]` (default `60`), caps extracted text at `8 MiB` (`maxPDFTextOutputBytes`), and bounds pure-Go fallback reads to `32 MiB` and `2 MiB` per zlib stream.

## Side Effects
- `[pdf.go:HasPDFToText]`: Searches host `PATH` for `pdftotext` via `exec.LookPath`.
- `[pdf.go:sanitizedPopplerEnv]`, `[pdf.go:ExtractPDFFileText]`, `[pdf.go:ExtractPDFText]`: Reads `PATH`/`SYSTEMROOT`/`WINDIR` and `os.TempDir()`, spawns `pdftotext` child processes (`45s` file timeout / `25s` stdin timeout, killing the process if stdout exceeds `8 MiB`), and opens `pdfPath` via `os.Open` during pure-Go file fallback.

## Verification
- Run: `go test ./internal/extract`
