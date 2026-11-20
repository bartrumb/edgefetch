// Package classify categorizes HTTP status codes, headers, and payload bytes into deterministic crawl
// outcomes before upstream HTML/JSON/PDF extractors inspect response bodies.
//
// # Outcomes & Host Short-Circuiting
//
// Every fetched [Kind] (`scrape`, `render`, `pdf`, `json`, `feed`, `page`, `text`, `catalog`, `binary`)
// resolves to one [Outcome]:
//
//   - [OutcomeOK]: valid 2xx payload matching the expected [Kind] invariants (for example `%PDF-` magic header
//     on [KindPDF] or valid RFC 8259 JSON on [KindJSON]).
//   - [OutcomeChallenge]: anti-bot edge mitigation (`cf-mitigated` header) — halts remaining queued URLs for
//     the same host immediately and is never retried.
//   - [OutcomeStop]: origin rate-limit or block (`403`, `429`, `503`) — halts remaining queued URLs for the
//     same host (`not_tried`) and records cooldowns in `internal/politeness`.
//   - [OutcomeGone]: permanent/missing document (`404`, `410`).
//   - [OutcomeSkip] / [OutcomeError] / [OutcomeNotTried]: non-fatal skips, transport/schema errors, or
//     short-circuited sibling requests.
package classify
