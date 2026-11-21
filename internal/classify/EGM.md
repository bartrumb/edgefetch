# classify

## Overview
Package `classify` maps HTTP status codes, response headers, and payload bytes into deterministic crawl `Outcome` values, outbound `Accept` headers, host short-circuit decisions, and multi-vendor WAF/anti-bot challenge detections before upstream extractors run.

## Interface
- `[classify.go:Kind]`: String enum with constants `[classify.go:KindFeed]` (`"feed"`), `[classify.go:KindJSON]` (`"json"`), `[classify.go:KindPage]` (`"page"`), `[classify.go:KindText]` (`"text"`), `[classify.go:KindCatalog]` (`"catalog"`), `[classify.go:KindScrape]` (`"scrape"`), `[classify.go:KindRender]` (`"render"`), `[classify.go:KindPDF]` (`"pdf"`), and `[classify.go:KindBinary]` (`"binary"`).
- `[classify.go:Outcome]`: String enum with constants `[classify.go:OutcomeOK]` (`"ok"`), `[classify.go:OutcomeChallenge]` (`"challenge"`), `[classify.go:OutcomePaymentRequired]` (`"payment_required"`), `[classify.go:OutcomeRateLimited]` (`"rate_limited"`), `[classify.go:OutcomeStop]` (`"stop"`), `[classify.go:OutcomeGone]` (`"gone"`), `[classify.go:OutcomeSkip]` (`"skip"`), `[classify.go:OutcomeError]` (`"error"`), and `[classify.go:OutcomeNotTried]` (`"not_tried"`).
- `[classify.go:DefaultAgentPageAccept]`: Outbound `Accept` header preferring Markdown for Agents (`"text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.8, */*;q=0.7"`).
- `[classify.go:Classify]`: `func Classify(kind Kind, status int, header http.Header, body []byte) (Outcome, string)`.
- `[classify.go:ClassifyAuto]`, `[classify.go:IsAutoPageContentType]`: `func ClassifyAuto(kind Kind, kindAuto bool, status int, header http.Header, body []byte) (Outcome, string)` and `func IsAutoPageContentType(contentType string) bool` — promote structured/text `2xx` MIME types (`application/json`, `application/*+json`, `application/rss+xml`, `application/atom+xml`, `application/xml`, `text/xml`, `text/plain`, `text/markdown`) to `OutcomeOK` when `kindAuto` is `true` (or `kind == ""`).
- `[classify.go:StopsHost]`: `func StopsHost(kind Kind, o Outcome) bool`.
- `[classify.go:AcceptFor]`: `func AcceptFor(kind Kind, requested string) (string, error)`.
- `[waf.go:WAFMatch]`: `type WAFMatch struct { Vendor, Category string; Confidence float64; Signals []string; Summary string }`.
- `[waf.go:ClassifyWAF]`: `func ClassifyWAF(status int, header http.Header, body []byte) *WAFMatch`.

## Invariants
- `[classify.go:Classify]`, `[waf.go:ClassifyWAF]`: Evaluates `ClassifyWAF` first (`OutcomeChallenge`), followed immediately by HTTP `402` (`OutcomePaymentRequired`, `"http 402 payment required"`).
- `[classify.go:Classify]`: Non-WAF HTTP `403`/`429`/`503` yields `OutcomeStop` for `KindText`, `KindPage`, `KindScrape`, `KindRender`, `KindPDF`, and `KindBinary`, whereas `KindCatalog`, `KindJSON`, and `KindFeed` yield `OutcomeError` on any non-2xx status; HTTP `404`/`410` yields `OutcomeGone` for `KindPage`, `KindScrape`, `KindRender`, `KindPDF`, and `KindBinary`.
- `[classify.go:Classify]`, `[classify.go:ClassifyAuto]`: On HTTP `200..299`, `KindPage` accepts `text/html`, `text/markdown`, or `text/x-markdown` in `Content-Type` (else `OutcomeSkip`, unless `kindAuto` promotes structured JSON/XML/RSS/Atom/plain text to `OutcomeOK`); `KindJSON` requires `json.Valid(body)`; `KindPDF` requires `"pdf"` in `Content-Type` or `"%PDF-"` in the first 1,024 bytes; `KindFeed` requires a JSON object containing a `"products"` array.
- `[classify.go:StopsHost]`: Returns `true` iff `o` is `OutcomeChallenge`, `OutcomePaymentRequired`, `OutcomeRateLimited`, or `OutcomeStop`, or `o == OutcomeError` with `kind` in `{KindFeed, KindJSON, KindCatalog}`.
- `[classify.go:AcceptFor]`: Sends `DefaultAgentPageAccept` (`text/markdown` first) for `KindPage` and default `KindScrape`, honors caller `requested` overrides on `KindScrape` and `KindBinary`, restricts `KindText` to an explicit MIME allowlist (including `text/markdown` and `text/x-markdown`), and errors on unknown `Kind`.
- `[waf.go:ClassifyWAF]`, `[waf.go:hasStructuralContentVeto]`: Authoritative mitigation headers (`cf-mitigated`, `x-amzn-waf-action`, `x-vercel-mitigated`, `x-datadome`, `x-dd-b`, `x-kpsdk-ct`, `x-px-blocked`) yield `Confidence: 1.0`; DOM body inspection skips HTTP `2xx` bodies `> 48 KiB` or `>= 120` visible words, caps inspection at `96 KiB`, vetoes rich Schema.org / `<main>` / `<article>` / heading / `<nav>` documents on `2xx`, and strips `<script>`, `<pre>`, `<code>`, `<blockquote>`, `<textarea>`, `<svg>`, and `<style>` blocks before matching vendor signatures.

## Side Effects
- None (`[classify.go:Classify]`, `[waf.go:ClassifyWAF]` are pure in-memory functions).

## Verification
- Run: `go test ./internal/classify`
