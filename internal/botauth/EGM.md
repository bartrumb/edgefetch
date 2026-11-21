# botauth

## Overview
Package `botauth` implements RFC 9421 HTTP Message Signatures (`Ed25519`), RFC 7638 JWK SHA-256 thumbprints, RFC 9530 `Content-Digest` headers, and IETF `web-bot-auth` / `/.well-known/http-message-signatures-directory` signing and verification.

## Interface
- `[botauth.go:DefaultSignatureTTL]`: `const DefaultSignatureTTL = 5 * time.Minute` — default `expires - created` window on outbound signatures.
- `[botauth.go:DefaultKeyNotBefore]`: `const DefaultKeyNotBefore int64 = 1_767_225_600` — deterministic default `nbf` Unix timestamp (`2026-01-01T00:00:00Z`) on published JWKs.
- `[botauth.go:KeyPair]`: `type KeyPair struct { PrivateKeySeedB64URL, PublicKeyB64URL, KeyID string; JWK PublicJWK }`.
- `[botauth.go:PublicJWK]`: `type PublicJWK struct { Kty, Crv, Kid, X string; Nbf, Exp int64 }` — OKP Ed25519 JWK entry.
- `[botauth.go:DirectoryDocument]`: `type DirectoryDocument struct { Keys []PublicJWK; Purpose string }` — JSON document body for `/.well-known/http-message-signatures-directory`.
- `[botauth.go:ComputeJWKThumbprint]`: `func ComputeJWKThumbprint(pub ed25519.PublicKey) (string, error)` — computes unpadded base64url RFC 7638 SHA-256 thumbprint.
- `[botauth.go:GenerateKeyPair]`: `func GenerateKeyPair() (KeyPair, error)` — mints a random Ed25519 keypair, thumbprint `kid`, and `PublicJWK`.
- `[botauth.go:ParsePrivateKey]`, `[botauth.go:ParsePublicKey]`: Decode standard or URL-safe base64 Ed25519 private seeds/keys (`32` or `64` bytes) and public keys (`32` bytes).
- `[botauth.go:Signer]`, `[botauth.go:NewSigner]`: `func NewSigner(encodedPrivKey, directoryURL string) (*Signer, error)` — constructs an RFC 9421 Ed25519 signer.
- `[botauth.go:Signer.SetKeyValidity]`, `[botauth.go:Signer.KeyID]`, `[botauth.go:Signer.PublicJWK]`, `[botauth.go:Signer.DirectoryJSON]`: Manage JWK validity bounds and marshal directory JSON.
- `[botauth.go:Signer.SignDirectoryResponse]`, `[botauth.go:Signer.SignRequest]`: Attach RFC 9530 `Content-Digest` and RFC 9421 `Signature-Input` / `Signature` / `Signature-Agent` headers.
- `[botauth.go:VerifyDirectoryResponse]`, `[botauth.go:VerifyRequest]`: Verify directory (`tag="http-message-signatures-directory"`) and request (`sig1`, `tag="web-bot-auth"`) Ed25519 signatures and time windows.

## Invariants
- `[botauth.go:ComputeJWKThumbprint]`: Requires `len(pub) == ed25519.PublicKeySize` (`32`) and canonicalizes thumbprint JSON strictly as `{"crv":"Ed25519","kty":"OKP","x":"<base64url>"}`.
- `[botauth.go:ParsePrivateKey]`, `[botauth.go:ParsePublicKey]`: Reject empty input and require decoded base64 lengths of `32` or `64` bytes for private keys and `32` bytes for public keys.
- `[botauth.go:Signer.SetKeyValidity]`, `[botauth.go:Signer.PublicJWK]`: `SetKeyValidity` is a no-op on `nil` `*Signer`, updates `nbf` only when `nbf > 0`, and updates `exp` only when `exp > s.nbf`; `PublicJWK` falls back to `DefaultKeyNotBefore` when `s.nbf <= 0`.
- `[botauth.go:Signer.SignDirectoryResponse]`: Signs `("@authority";req "content-digest")` with label `directory`, `alg="ed25519"`, `tag="http-message-signatures-directory"`, and `Content-Digest: sha-256=:<std-base64>:`; returns an error if `@authority` is empty.
- `[botauth.go:Signer.SignRequest]`: Signs `("@authority" "@method" "@target-uri")` plus `"signature-agent"` (iff `s.directoryURL != ""`) with label `sig1`, `alg="ed25519"`, `tag="web-bot-auth"`, and `expires = created + s.ttl`.
- `[botauth.go:VerifyDirectoryResponse]`, `[botauth.go:VerifyRequest]`: Require a 32-byte `pub`, 64-byte Ed25519 signature, matching `Content-Digest` (for directory responses), and `created <= now.Unix()+60` with `now.Unix() <= expires` when `!now.IsZero()`.

## Side Effects
- `[botauth.go:GenerateKeyPair]`: Reads OS cryptographic entropy via `crypto/rand.Reader` and current UTC clock via `time.Now()`.
- `[botauth.go:Signer.SetKeyValidity]`: Mutates `s.nbf` and `s.exp` fields on `*Signer` in place without mutex locking.
- `[botauth.go:Signer.SignDirectoryResponse]`, `[botauth.go:Signer.SignRequest]`: Mutate `http.Header` / `req.Header` in place (`Content-Digest`, `Signature-Input`, `Signature`, `Signature-Agent`) and read `time.Now()` when `now.IsZero()`.

## Verification
- Run: `go test ./internal/botauth`
