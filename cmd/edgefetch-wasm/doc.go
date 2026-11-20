// Command edgefetch-wasm compiles EdgeFetch's pure-stdlib HTML -> GFM Markdown, branding, PII redaction,
// and BM25 passage reranker into a standalone WASI WebAssembly module (`GOOS=wasip1 GOARCH=wasm`) for
// sandboxed offline execution inside `wasmtime`, `wazero`, iPad `a-Shell`, and edge Wasm runtimes.
package main
