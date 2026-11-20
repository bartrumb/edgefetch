// Package extract converts raw HTML and PDF payloads into clean GitHub-Flavored Markdown, plain text,
// resolved links, images, CSS branding signals, BM25 query-reranked passages, and `llms.txt` structured
// discovery metadata using only the Go standard library.
//
// # Extraction Pipeline
//
//  1. Head metadata & branding signals (`<title>`, OpenGraph, canonical URL, favicon, CSS hex palette, fonts).
//  2. Boilerplate & chrome removal (`<nav>`, `<footer>`, `<aside>`, `<script>`, `<style>`) with `<main>` /
//     `<article>` focus when `OnlyMainContent` is enabled.
//  3. Sentinel-protected `<pre><code>` and multi-backtick inline `<code>` conversion so generic type signatures
//     (`Promise<void>`, `#include <stdio.h>`) survive HTML tag stripping intact.
//  4. GFM table reconstruction, optional BM25 passage reranking ([RerankPassages]), and optional PII redaction
//     ([RedactPII]).
//  5. Streaming Poppler `pdftotext -layout` extraction with a pure-Go FlateDecode fallback ([ExtractPDFText])
//     for distroless Lite deployments.
package extract
