// Package mcpfed implements the pure-CPU Outbound MCP Credential Vault (HKDF-SHA256 + AES-256-GCM),
// OAuth 2.1 PKCE metadata/state hygiene, Federated MCP untrusted output sanitizer, JSON Schema
// allowlist rebuilder, Streamable HTTP SSE JSON-RPC parser, and Dual-Source MCP Registry fusion engine.
//
// WASM Dependency Invariant:
//   - Zero imports of net/http, crypto/tls, crypto/x509, or host networking packages so cmd/edgefetch-wasm
//     compiles cleanly under GOOS=wasip1 GOARCH=wasm with minimal binary footprint.
//   - Cryptographic operations maintain 100% byte-for-byte wire compatibility with WebCrypto envelopes
//     (v2 row-bound 5-field AAD, v2 origin-bound 2-field AAD, legacy v1 length-prefixed & v2.7.0 fallback,
//     and pkce2 OAuth PKCE state blobs).
package mcpfed
