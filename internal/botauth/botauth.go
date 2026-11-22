// Package botauth implements IETF RFC 9421 HTTP Message Signatures (`web-bot-auth`),
// `draft-meunier-http-message-signatures-directory` self-signed JWKS responses, and RFC 7638 Ed25519 JWK
// Thumbprints using only the Go standard library (`crypto/ed25519`, `crypto/sha256`, `encoding/base64`).
//
// When configured via `EDGEFETCH_BOT_SIGNING_KEY` (base64url 32-byte Ed25519 seed or 64-byte private key) and optional
// `EDGEFETCH_BOT_DIRECTORY_URL` (`https://<hub>/.well-known/http-message-signatures-directory`), EdgeFetch attaches
// cryptographic `Signature-Input`, `Signature`, and `Signature-Agent` headers so origins and Cloudflare Verified Bots
// can cryptographically authenticate the crawler without relying on static IP allowlists.
package botauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultSignatureTTL is the validity window (`expires - created`) stamped on outbound RFC 9421 signatures.
const DefaultSignatureTTL = 5 * time.Minute

// DefaultKeyNotBefore (`2026-01-01T00:00:00Z`) is the deterministic default `nbf` (Unix seconds) on published JWKs.
const DefaultKeyNotBefore int64 = 1_767_225_600

// KeyPair bundles a freshly generated Ed25519 keypair, its RFC 7638 JWK thumbprint (`kid`), and ready-to-serve JWK.
type KeyPair struct {
	PrivateKeySeedB64URL string    `json:"privateKeySeed"`
	PublicKeyB64URL      string    `json:"publicKey"`
	KeyID                string    `json:"kid"`
	JWK                  PublicJWK `json:"jwk"`
}

// PublicJWK represents an OKP Ed25519 public key entry inside `/.well-known/http-message-signatures-directory`.
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid,omitempty"`
	X   string `json:"x"`
	Nbf int64  `json:"nbf,omitempty"`
	Exp int64  `json:"exp,omitempty"`
}

// DirectoryDocument is the JSON body served at `/.well-known/http-message-signatures-directory`.
type DirectoryDocument struct {
	Keys    []PublicJWK `json:"keys"`
	Purpose string      `json:"purpose,omitempty"`
}

// ComputeJWKThumbprint computes the RFC 7638 SHA-256 thumbprint (`base64url`, unpadded) of an Ed25519 public key.
// Per RFC 7638 Section 3.2, members of an OKP JWK are ordered lexicographically: `{"crv":"Ed25519","kty":"OKP","x":"..."}`
// (optional metadata fields such as `nbf` and `exp` are never included in the canonical thumbprint input).
func ComputeJWKThumbprint(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("botauth: invalid Ed25519 public key length %d", len(pub))
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, x)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// GenerateKeyPair mints a new cryptographically random Ed25519 keypair for RFC 9421 Web Bot Auth.
func GenerateKeyPair() (KeyPair, error) {
	return generateKeyPair(rand.Reader)
}

func generateKeyPair(rng io.Reader) (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return KeyPair{}, err
	}
	kid, err := ComputeJWKThumbprint(pub)
	if err != nil {
		return KeyPair{}, err
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	seedB64 := base64.RawURLEncoding.EncodeToString(priv.Seed())
	return KeyPair{
		PrivateKeySeedB64URL: seedB64,
		PublicKeyB64URL:      pubB64,
		KeyID:                kid,
		JWK: PublicJWK{
			Kty: "OKP",
			Crv: "Ed25519",
			Kid: kid,
			X:   pubB64,
			Nbf: time.Now().UTC().Unix(),
		},
	}, nil
}

// ParsePrivateKey decodes a base64url or standard base64 Ed25519 seed (32 bytes) or full private key (64 bytes).
func ParsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	clean := strings.TrimSpace(encoded)
	if clean == "" {
		return nil, errors.New("botauth: empty private key")
	}
	raw, err := decodeFlexibleBase64(clean)
	if err != nil {
		return nil, fmt.Errorf("botauth: invalid base64 key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("botauth: expected 32-byte seed or 64-byte Ed25519 private key, got %d bytes", len(raw))
	}
}

// ParsePublicKey decodes a base64url or standard base64 Ed25519 public key (32 bytes).
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := decodeFlexibleBase64(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("botauth: invalid base64 public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("botauth: expected 32-byte Ed25519 public key, got %d bytes", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func decodeFlexibleBase64(s string) ([]byte, error) {
	trimmed := strings.TrimRight(s, "=")
	if strings.ContainsAny(trimmed, "-_") {
		return base64.RawURLEncoding.DecodeString(trimmed)
	}
	if b, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(trimmed)
}

// Signer signs outbound HTTP requests per IETF RFC 9421 (`tag="web-bot-auth"`) and signs directory responses
// per `draft-meunier-http-message-signatures-directory` (`tag="http-message-signatures-directory"`).
type Signer struct {
	priv         ed25519.PrivateKey
	pub          ed25519.PublicKey
	keyID        string
	directoryURL string
	ttl          time.Duration
	nbf          int64
	exp          int64
}

// NewSigner constructs an RFC 9421 Ed25519 request signer from an encoded seed/key and optional directory URL.
func NewSigner(encodedPrivKey, directoryURL string) (*Signer, error) {
	priv, err := ParsePrivateKey(encodedPrivKey)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	kid, err := ComputeJWKThumbprint(pub)
	if err != nil {
		return nil, err
	}
	dir := strings.TrimSpace(directoryURL)
	return &Signer{
		priv:         priv,
		pub:          pub,
		keyID:        kid,
		directoryURL: dir,
		ttl:          DefaultSignatureTTL,
		nbf:          DefaultKeyNotBefore,
	}, nil
}

// SetKeyValidity configures the JWK `nbf` (not-before) and optional `exp` (expiration) Unix timestamps.
func (s *Signer) SetKeyValidity(nbf, exp int64) {
	if s == nil {
		return
	}
	if nbf > 0 {
		s.nbf = nbf
	}
	if exp > s.nbf {
		s.exp = exp
	}
}

// KeyID returns the RFC 7638 JWK thumbprint identifying this signer's public key.
func (s *Signer) KeyID() string { return s.keyID }

// PublicJWK returns the public OKP JWK for publishing at `/.well-known/http-message-signatures-directory`.
func (s *Signer) PublicJWK() PublicJWK {
	nbf := s.nbf
	if nbf <= 0 {
		nbf = DefaultKeyNotBefore
	}
	return PublicJWK{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: s.keyID,
		X:   base64.RawURLEncoding.EncodeToString(s.pub),
		Nbf: nbf,
		Exp: s.exp,
	}
}

// DirectoryJSON serializes the `/.well-known/http-message-signatures-directory` JSON document for this signer.
func (s *Signer) DirectoryJSON() ([]byte, error) {
	return json.MarshalIndent(DirectoryDocument{
		Keys: []PublicJWK{s.PublicJWK()},
	}, "", "  ")
}

func authorityForRequest(req *http.Request) string {
	if req.Host != "" {
		return strings.ToLower(req.Host)
	}
	if req.URL != nil {
		return strings.ToLower(req.URL.Host)
	}
	return ""
}

// SignDirectoryResponse attaches RFC 9530 `Content-Digest` and RFC 9421 `directory` self-signature headers
// (`tag="http-message-signatures-directory"`) to an HTTP response writer per Cloudflare Verified Bots requirements.
func (s *Signer) SignDirectoryResponse(hdr http.Header, req *http.Request, body []byte, now time.Time) error {
	if s == nil || hdr == nil || req == nil {
		return nil
	}
	authority := authorityForRequest(req)
	if authority == "" {
		return errors.New("botauth: directory request missing @authority")
	}
	if now.IsZero() {
		now = time.Now()
	}
	sum := sha256.Sum256(body)
	contentDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	created := now.Unix()
	expires := now.Add(s.ttl).Unix()

	sigParams := fmt.Sprintf(
		`("@authority";req "content-digest");created=%d;expires=%d;keyid="%s";alg="ed25519";tag="http-message-signatures-directory"`,
		created,
		expires,
		s.keyID,
	)
	sigBase := strings.Join([]string{
		fmt.Sprintf(`"@authority";req: %s`, authority),
		fmt.Sprintf(`"content-digest": %s`, contentDigest),
		fmt.Sprintf(`"@signature-params": %s`, sigParams),
	}, "\n")

	sigBytes := ed25519.Sign(s.priv, []byte(sigBase))
	hdr.Set("Content-Digest", contentDigest)
	hdr.Set("Signature-Input", "directory="+sigParams)
	hdr.Set("Signature", "directory=:"+base64.StdEncoding.EncodeToString(sigBytes)+":")
	return nil
}

// SignRequest attaches RFC 9421 `Signature-Input`, `Signature`, and (when DirectoryURL is set) `Signature-Agent` headers.
func (s *Signer) SignRequest(req *http.Request, now time.Time) error {
	if s == nil || req == nil || req.URL == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	authority := authorityForRequest(req)
	if authority == "" {
		return errors.New("botauth: request missing @authority")
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	targetURI := req.URL.String()
	created := now.Unix()
	expires := now.Add(s.ttl).Unix()

	var comps []string
	var baseLines []string
	comps = append(comps, `"@authority"`, `"@method"`, `"@target-uri"`)
	baseLines = append(baseLines,
		fmt.Sprintf(`"@authority": %s`, authority),
		fmt.Sprintf(`"@method": %s`, method),
		fmt.Sprintf(`"@target-uri": %s`, targetURI),
	)

	if s.directoryURL != "" {
		sigAgentVal := fmt.Sprintf(`"%s"`, s.directoryURL)
		req.Header.Set("Signature-Agent", sigAgentVal)
		comps = append(comps, `"signature-agent"`)
		baseLines = append(baseLines, fmt.Sprintf(`"signature-agent": %s`, sigAgentVal))
	}

	sigParams := fmt.Sprintf(
		`(%s);created=%d;expires=%d;keyid="%s";alg="ed25519";tag="web-bot-auth"`,
		strings.Join(comps, " "),
		created,
		expires,
		s.keyID,
	)
	baseLines = append(baseLines, fmt.Sprintf(`"@signature-params": %s`, sigParams))
	sigBase := strings.Join(baseLines, "\n")

	sigBytes := ed25519.Sign(s.priv, []byte(sigBase))
	req.Header.Set("Signature-Input", "sig1="+sigParams)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sigBytes)+":")
	return nil
}

var (
	reSigInput    = regexp.MustCompile(`^sig1=(\(([^)]*)\)(?:;.*)?)$`)
	reSigValue    = regexp.MustCompile(`^sig1=:([A-Za-z0-9+/=]+):$`)
	reDirSigInput = regexp.MustCompile(`^directory=(\(([^)]*)\)(?:;.*)?)$`)
	reDirSigValue = regexp.MustCompile(`^directory=:([A-Za-z0-9+/=]+):$`)
	reCreated     = regexp.MustCompile(`;created=(\d+)`)
	reExpires     = regexp.MustCompile(`;expires=(\d+)`)
)

// VerifyDirectoryResponse verifies a `draft-meunier-http-message-signatures-directory` response (`Content-Digest` + `directory` signature).
func VerifyDirectoryResponse(req *http.Request, respHdr http.Header, body []byte, pub ed25519.PublicKey, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("botauth: invalid public key")
	}
	digestHdr := strings.TrimSpace(respHdr.Get("Content-Digest"))
	inHdr := strings.TrimSpace(respHdr.Get("Signature-Input"))
	sigHdr := strings.TrimSpace(respHdr.Get("Signature"))
	im := reDirSigInput.FindStringSubmatch(inHdr)
	sm := reDirSigValue.FindStringSubmatch(sigHdr)
	if digestHdr == "" || len(im) != 3 || len(sm) != 2 {
		return errors.New("botauth: missing or malformed directory signature headers")
	}
	sigParams := im[1]
	if !strings.Contains(sigParams, `tag="http-message-signatures-directory"`) {
		return errors.New("botauth: missing http-message-signatures-directory tag")
	}
	if !now.IsZero() {
		nowUnix := now.Unix()
		if cm := reCreated.FindStringSubmatch(sigParams); len(cm) == 2 {
			created, _ := strconv.ParseInt(cm[1], 10, 64)
			if created > nowUnix+60 {
				return errors.New("botauth: directory signature created timestamp is in the future")
			}
		}
		if em := reExpires.FindStringSubmatch(sigParams); len(em) == 2 {
			expires, _ := strconv.ParseInt(em[1], 10, 64)
			if nowUnix > expires {
				return errors.New("botauth: directory signature has expired")
			}
		}
	}
	sum := sha256.Sum256(body)
	expectedDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if digestHdr != expectedDigest {
		return errors.New("botauth: Content-Digest mismatch")
	}
	authority := authorityForRequest(req)
	sigBase := strings.Join([]string{
		fmt.Sprintf(`"@authority";req: %s`, authority),
		fmt.Sprintf(`"content-digest": %s`, digestHdr),
		fmt.Sprintf(`"@signature-params": %s`, sigParams),
	}, "\n")
	sigBytes, err := base64.StdEncoding.DecodeString(sm[1])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("botauth: invalid Ed25519 directory signature bytes")
	}
	if !ed25519.Verify(pub, []byte(sigBase), sigBytes) {
		return errors.New("botauth: Ed25519 directory signature verification failed")
	}
	return nil
}

// VerifyRequest verifies an RFC 9421 `sig1` Ed25519 signature on `req` against `pub` at timestamp `now`.
func VerifyRequest(req *http.Request, pub ed25519.PublicKey, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("botauth: invalid public key")
	}
	inHdr := strings.TrimSpace(req.Header.Get("Signature-Input"))
	sigHdr := strings.TrimSpace(req.Header.Get("Signature"))
	im := reSigInput.FindStringSubmatch(inHdr)
	sm := reSigValue.FindStringSubmatch(sigHdr)
	if len(im) != 3 || len(sm) != 2 {
		return errors.New("botauth: missing or malformed Signature-Input / Signature header")
	}
	sigParams := im[1]
	compList := strings.Fields(im[2])

	if !now.IsZero() {
		nowUnix := now.Unix()
		if cm := reCreated.FindStringSubmatch(sigParams); len(cm) == 2 {
			created, _ := strconv.ParseInt(cm[1], 10, 64)
			if created > nowUnix+60 {
				return errors.New("botauth: signature created timestamp is in the future")
			}
		}
		if em := reExpires.FindStringSubmatch(sigParams); len(em) == 2 {
			expires, _ := strconv.ParseInt(em[1], 10, 64)
			if nowUnix > expires {
				return errors.New("botauth: signature has expired")
			}
		}
	}

	var baseLines []string
	for _, quotedComp := range compList {
		comp := strings.Trim(quotedComp, `"`)
		var val string
		switch comp {
		case "@authority":
			val = authorityForRequest(req)
		case "@method":
			val = strings.ToUpper(req.Method)
			if val == "" {
				val = http.MethodGet
			}
		case "@target-uri":
			val = req.URL.String()
		default:
			val = strings.TrimSpace(req.Header.Get(comp))
			if val == "" {
				return fmt.Errorf("botauth: covered header %q is missing", comp)
			}
		}
		baseLines = append(baseLines, fmt.Sprintf(`"%s": %s`, comp, val))
	}
	baseLines = append(baseLines, fmt.Sprintf(`"@signature-params": %s`, sigParams))
	sigBase := strings.Join(baseLines, "\n")

	sigBytes, err := base64.StdEncoding.DecodeString(sm[1])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("botauth: invalid Ed25519 signature bytes")
	}
	if !ed25519.Verify(pub, []byte(sigBase), sigBytes) {
		return errors.New("botauth: Ed25519 signature verification failed")
	}
	return nil
}
