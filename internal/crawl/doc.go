// Package crawl implements a bounded-concurrency, polite HTTP/2 batch fetcher with `net/http/httptrace`
// phase telemetry, hop-by-hop redirect validation, conditional GETs, `/llms.txt` companion Markdown
// discovery, and strict memory/SSRF guardrails.
//
// # Design Highlights
//
//   - Hop-by-hop redirect checks: `http.Client.CheckRedirect` returns `http.ErrUseLastResponse` so every
//     `301`/`302`/`307`/`308` Location target re-verifies [PublicHTTPS] SSRF rules, per-host locks,
//     `Retry-After` cooldowns, and `/robots.txt` rules on the destination domain.
//   - Socket reuse under body caps: reads `io.LimitReader(resp.Body, maxBytes+1)` so oversized streams close
//     cleanly while normal responses drain to EOF and return warm HTTP/2 connections to the pool.
//   - Disk-streamed large PDFs: on Fat nodes, PDFs up to 256 MiB stream directly to an unlinked temporary file
//     so Poppler `pdftotext` seeks the EOF `xref` table without spiking Go's `GOMEMLIMIT` heap.
package crawl
