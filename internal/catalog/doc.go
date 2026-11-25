// Package catalog implements EdgeFetch's pure-CPU e-commerce sanitization,
// Shopify and WooCommerce product/feed normalization, polite storefront catalog
// pagination, deterministic FNV-1a/SHA-256 snapshot hashing and diffing, shrink-guard
// detection, UCP discovery, record filtering, and bounded multi-tenant catalog state.
//
// All files in this package compile cleanly under both native targets and
// GOOS=wasip1 GOARCH=wasm without importing net/http, crypto/tls, or crypto/x509.
package catalog
