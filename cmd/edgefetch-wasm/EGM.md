# edgefetch-wasm

## Overview

`cmd/edgefetch-wasm` provides a standalone WASI WebAssembly (`GOOS=wasip1 GOARCH=wasm`) command-line binary that reads HTML from standard input and emits extracted Markdown or structured JSON to standard output via `internal/extract`. It uses the Go standard library without JavaScript host bindings (`syscall/js`).

## Interface

- `[doc.go:main]` — WASI CLI `main` package targeting `GOOS=wasip1 GOARCH=wasm` with zero exported JS/WASM globals.
- `[main.go:main]` — Process entry point invoking `runWasmCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)` and exiting with its return status.
- `[main.go:runWasmCLI]` — CLI runner `func runWasmCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int` parsing extraction flags and running `extract.ExtractHTML`.
- `[main.go:--json]` — Emit 2-space indented JSON (`extract.ExtractHTML` result) instead of plain Markdown.
- `[main.go:--full]` — Disable main-content filtering (`ExtractOptions.OnlyMainContent = false`).
- `[main.go:--branding]` — Enable branding metadata extraction (`ExtractOptions.IncludeBranding = true`).
- `[main.go:--images]` — Include images in extracted output (`ExtractOptions.IncludeImages = true`).
- `[main.go:--redact-pii]` — Redact personally identifiable information (`ExtractOptions.RedactPII = true`).
- `[main.go:--url=]` — Set base URL (`--url=<url>`) via `ExtractOptions.BaseURL`.
- `[main.go:--query=]` — Set extraction query (`--query=<query>`) via `ExtractOptions.Query`.
- `[main.go:--max-chars=]` — Cap extracted character output (`--max-chars=<N>`) via `ExtractOptions.MaxChars` when `N > 0`.
- `[main.go:--help]`, `[main.go:-h]` — Print CLI usage string to `stdout` and exit `0`.

## Invariants

- `[doc.go:main]` — Compiles for WASI (`GOOS=wasip1 GOARCH=wasm`) with no `syscall/js` dependencies or exported JS globals.
- `[main.go:runWasmCLI]` — Defaults `extract.ExtractOptions` to `OnlyMainContent: true` and `IncludeLinks: true`.
- `[main.go:runWasmCLI]` — Caps `stdin` reads at 16 MiB (`16<<20` bytes) via `io.LimitReader`.
- `[main.go:--max-chars=]` — Ignores non-integer or non-positive (`<= 0`) `--max-chars=` values without failing; unrecognized CLI arguments are also ignored.
- `[main.go:--json]` — Configures `json.NewEncoder` with `SetEscapeHTML(false)` and `SetIndent("", "  ")`.
- `[main.go:runWasmCLI]` — Trims whitespace from `res.Markdown` in plain-Markdown mode and suppresses `stdout` writes when the trimmed output is empty.
- `[main.go:runWasmCLI]` — Returns exit code `0` on `--help`/`-h` or successful extraction, and `1` on `stdin` read or JSON encoding errors.

## Side Effects

- `[main.go:main]` — Reads CLI arguments from `os.Args[1:]` and up to 16 MiB of HTML bytes from `os.Stdin` (`[main.go:runWasmCLI]`).
- `[main.go:runWasmCLI]` — Writes usage text, extracted Markdown, or JSON output to `stdout` (`os.Stdout`), and writes `read stdin` / `encode json` errors to `stderr` (`os.Stderr`).
- `[main.go:main]` — Terminates the WASI process via `os.Exit`.

## Verification

- Run: `go test ./cmd/edgefetch-wasm`
