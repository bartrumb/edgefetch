# mcpfed

## Overview
Package `mcpfed` implements the pure-CPU Outbound MCP Credential Vault (`HKDF-SHA256` + `AES-256-GCM`), OAuth 2.1 PKCE metadata and state hygiene, Federated MCP untrusted output and JSON Schema sanitization, Streamable HTTP SSE JSON-RPC response parsing, and Dual-Source MCP Registry (`registry.modelcontextprotocol.io` + `glama.ai`) normalization and fusion.

## Interface
- `[ordered_json.go:OrderedObject]`, `[ordered_json.go:ParseOrderedJSON]`, `[ordered_json.go:MarshalUnescapedJSON]`, `[ordered_json.go:MeasureOrderedJSONSizeCapped]`, `[ordered_json.go:IsJSONDepthWithinLimit]`: Insertion-order-preserving JSON object representation, depth-bounded decoder, HTML-unescaped encoder, and `O(maxBytes)` early-aborting size estimator.
- `[vault_crypto.go:ValidateVaultMasterKey]`, `[vault_crypto.go:SealVaultCredentials]`, `[vault_crypto.go:UnsealVaultCredentials]`: Per-user, per-origin `HKDF-SHA256` + `AES-256-GCM` credential encryption with `v2.` 5-field row-bound AAD, downgrade prevention (`secretVersion >= 2`), and automatic reseal-on-read for legacy `v1.` and 2-field `v2.` envelopes.
- `[vault_crypto.go:SealPKCEStateBlob]`, `[vault_crypto.go:UnsealPKCEStateBlob]`, `[vault_crypto.go:ComputeMCPOAuthBindHMAC]`, `[vault_crypto.go:VerifyMCPOAuthBindHMAC]`: `pkce2.` AEAD state sealing and constant-time HMAC-SHA256 OAuth bind-cookie verification.
- `[vault_validation.go:IsSafeMCPIdentifier]`, `[vault_validation.go:IsValidMCPConnectorSlug]`, `[vault_validation.go:NormalizeMCPConnectorSlug]`, `[vault_validation.go:ParseAllowedMCPTools]`, `[vault_validation.go:IsCachedMCPToolPermitted]`, `[vault_validation.go:ResolveCallerUserID]`, `[vault_validation.go:ToPublicMCPServerSummary]`, `[vault_validation.go:SanitizeSecretHeadersInput]`, `[vault_validation.go:BuildMaskedAuthSummary]`, `[vault_validation.go:FilterSafeCachedMCPTools]`: Identifier/slug/header hygiene and S6 `readOnlyHint`/`destructiveHint` tool gating.
- `[vault_oauth.go:PrepareOAuthProbe]`, `[vault_oauth.go:ValidateOAuthProtectedResource]`, `[vault_oauth.go:ValidateOAuthAuthorizationServer]`, `[vault_oauth.go:ValidateOAuthTokenEndpoint]`: RFC 9728 Protected Resource Metadata and RFC 8414 Authorization Server origin-pinning validators.
- `[federation_sanitize.go:NeutralizeUntrustedMCPBoundaryTags]`, `[federation_sanitize.go:FormatFenceSafeUntrustedMCPEnvelope]`, `[federation_sanitize.go:SanitizeMCPMarkdownOutput]`, `[federation_sanitize.go:SanitizeRemoteMCPText]`, `[federation_sanitize.go:SanitizeConnectorText]`, `[federation_sanitize.go:SanitizeConnectorStructuredValue]`, `[federation_rpc.go:SanitizeCallToolRPCResponse]`: Untrusted XML/fence envelope builder, prompt-injection scrubber, secret redactor, and bounded recursive JSON sanitizer.
- `[federation_schema.go:RebuildSafeMCPInputSchema]`, `[federation_schema.go:SanitizeRemoteMCPToolDefs]`: `16 KiB` downstream `tools/list` schema cap and strict recursive JSON Schema allowlist walker.
- `[federation_sse.go:ParseSSEJSONRPCResponse]`, `[federation_sse.go:ParseRemoteJSONRPCBody]`, `[federation_sse.go:ExtractMarkdownFromQueryMCPBody]`, `[federation_sse.go:MatchConnectedMCPsForContext]`, `[federation_sse.go:SelectScrapeMCPCandidate]`, `[federation_sse.go:BuildPinnedOutboundHeaders]`: Streamable HTTP SSE JSON-RPC response matcher, domain-first connector scorer, and origin-pinned header builder.
- `[registry_url.go:StripMCPSmugglingChars]`, `[registry_url.go:IsSafePublicHTTPSURL]`, `[registry_url.go:SlugifyMCPServerName]`, `[registry_url.go:IsSharedHostingHostname]`, `[registry_url.go:ExtractRegistrableDomain]`, `[registry_url.go:ValidateConnectorDomains]`, `[registry_url.go:InferAssociatedDomains]`, `[registry.go:ParseOfficialRegistryPayload]`, `[registry.go:ParseGlamaRegistryPayload]`, `[registry.go:FuseRegistryEntries]`: SSRF-safe `https://` URL validator, PSL shared-hosting tenant isolator, and dual-source MCP registry parser/fuser.

## Invariants
- **WASM Purity**: Zero imports of `net/http`, `crypto/tls`, or `crypto/x509`; compiles cleanly under `GOOS=wasip1 GOARCH=wasm`.
- **Vault AEAD & Downgrade Prevention (`P6`, `M8`)**: Requires `VAULT_MASTER_KEY >= 24` chars; binds `v2` header, table/purpose, and length-prefixed `userId`, `remoteOrigin`, `serverId`, `slug`, and `authType` in AES-GCM AAD; rejects `secretVersion > 2` and blocks `v1` or 2-field `v2` fallback whenever `secretVersion >= 2`.
- **Untrusted Connector Budgets (`H3`, `S8`, `M10`)**: Caps `tools/list` schemas at `16 KiB`, `tools/call` content at `<= 64` blocks and `<= 64 KiB` raw text per block before sanitizing, structured JSON trees at depth `<= 12`, entries `<= 256`, nodes `<= 2048`, string leaves `<= 16 KiB`, and JSON-RPC `error.data` at `<= 4 KiB`.
- **Zero Heuristic Domain Claims (`H1`)**: `InferAssociatedDomains` always returns `[]`, and `ValidateConnectorDomains` rejects wildcards, bare PSL suffixes, and sibling shared-hosting PaaS tenants (`extract.HasPrivateSharedHostingSuffix`).

## Side Effects
- Reads CSPRNG entropy via `crypto/rand.Read` when sealing `v2.` credential envelopes, `pkce2.` state blobs, and OAuth PKCE verifiers/states.

## Verification
- Run: `go test -race -count=1 ./internal/mcpfed`
- WASM check: `GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go vet ./cmd/edgefetch-wasm`
