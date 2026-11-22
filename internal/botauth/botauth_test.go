package botauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("rng failure")
}

func TestGenerateSignAndVerifyRFC9421(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp.KeyID == "" || kp.PrivateKeySeedB64URL == "" || kp.PublicKeyB64URL == "" {
		t.Fatalf("expected non-empty keypair fields: %+v", kp)
	}

	dirURL := "https://hub.example.com/.well-known/http-message-signatures-directory"
	signer, err := NewSigner(kp.PrivateKeySeedB64URL, dirURL)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if signer.KeyID() != kp.KeyID {
		t.Fatalf("KeyID mismatch: %q vs %q", signer.KeyID(), kp.KeyID)
	}

	now := time.Unix(1_760_000_000, 0).UTC()
	req, err := http.NewRequest(http.MethodGet, "https://docs.example.com/guide?page=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SignRequest(req, now); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	if gotAgent := req.Header.Get("Signature-Agent"); gotAgent != `"`+dirURL+`"` {
		t.Fatalf("unexpected Signature-Agent: %q", gotAgent)
	}
	if !strings.Contains(req.Header.Get("Signature-Input"), `tag="web-bot-auth"`) {
		t.Fatalf("expected web-bot-auth tag in Signature-Input: %q", req.Header.Get("Signature-Input"))
	}

	pub, err := ParsePublicKey(kp.PublicKeyB64URL)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if err := VerifyRequest(req, pub, now.Add(30*time.Second)); err != nil {
		t.Fatalf("VerifyRequest valid signature failed: %v", err)
	}

	// Expired check must fail closed
	if err := VerifyRequest(req, pub, now.Add(10*time.Minute)); err == nil {
		t.Fatal("expected expired signature to fail verification")
	}

	// Tampered path must fail closed
	tampered, _ := http.NewRequest(http.MethodGet, "https://docs.example.com/admin", nil)
	tampered.Header = req.Header.Clone()
	if err := VerifyRequest(tampered, pub, now); err == nil {
		t.Fatal("expected tampered @target-uri to fail verification")
	}

	// Self-signed Cloudflare Verified Bots directory response (`draft-meunier-http-message-signatures-directory`)
	dirBody, err := signer.DirectoryJSON()
	if err != nil {
		t.Fatalf("DirectoryJSON: %v", err)
	}
	if !strings.Contains(string(dirBody), `"nbf":`) {
		t.Fatalf("expected nbf in DirectoryJSON: %s", string(dirBody))
	}
	dirReq, _ := http.NewRequest(http.MethodGet, dirURL, nil)
	respHdr := make(http.Header)
	if err := signer.SignDirectoryResponse(respHdr, dirReq, dirBody, now); err != nil {
		t.Fatalf("SignDirectoryResponse: %v", err)
	}
	if err := VerifyDirectoryResponse(dirReq, respHdr, dirBody, pub, now.Add(30*time.Second)); err != nil {
		t.Fatalf("VerifyDirectoryResponse valid failed: %v", err)
	}
	if err := VerifyDirectoryResponse(dirReq, respHdr, append([]byte(nil), append(dirBody, ' ')...), pub, now); err == nil {
		t.Fatal("expected tampered directory body to fail Content-Digest verification")
	}
	wrongHostReq, _ := http.NewRequest(http.MethodGet, "https://evil.example.com/.well-known/http-message-signatures-directory", nil)
	if err := VerifyDirectoryResponse(wrongHostReq, respHdr, dirBody, pub, now); err == nil {
		t.Fatal("expected wrong @authority;req to fail directory signature verification")
	}
}

func TestKeyParsingAndThumbprints(t *testing.T) {
	if _, err := generateKeyPair(failingReader{}); err == nil {
		t.Fatal("expected generateKeyPair with failing reader to fail")
	}

	for _, badPub := range []ed25519.PublicKey{nil, {}, make([]byte, 31), make([]byte, 33)} {
		if _, err := ComputeJWKThumbprint(badPub); err == nil {
			t.Fatalf("expected ComputeJWKThumbprint(len=%d) error", len(badPub))
		}
	}

	// Deterministic seed with bytes producing + and / in std base64 and - and _ in base64url.
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 0xfb
	seed[1] = 0xff
	seed[2] = 0xbf
	for i := 3; i < len(seed); i++ {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	sum := sha256.Sum256([]byte(fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, base64.RawURLEncoding.EncodeToString(pub))))
	wantThumb := base64.RawURLEncoding.EncodeToString(sum[:])
	gotThumb, err := ComputeJWKThumbprint(pub)
	if err != nil || gotThumb != wantThumb {
		t.Fatalf("ComputeJWKThumbprint = (%q, %v), want (%q, nil)", gotThumb, err, wantThumb)
	}

	for _, blank := range []string{"", "  \t\n "} {
		if _, err := ParsePrivateKey(blank); err == nil {
			t.Fatalf("expected ParsePrivateKey(%q) error", blank)
		}
	}

	seedURL := base64.RawURLEncoding.EncodeToString(seed)
	if !strings.ContainsAny(seedURL, "-_") {
		t.Fatalf("expected base64url seed to contain - or _: %q", seedURL)
	}
	seedURLPadded := base64.URLEncoding.EncodeToString(seed)
	seedStd := base64.StdEncoding.EncodeToString(seed)
	privURL := base64.RawURLEncoding.EncodeToString(priv)
	privStd := base64.StdEncoding.EncodeToString(priv)

	for _, enc := range []string{"  " + seedURL + " ", seedURLPadded, seedStd, privURL, privStd} {
		parsed, err := ParsePrivateKey(enc)
		if err != nil || !bytes.Equal(parsed, priv) {
			t.Fatalf("ParsePrivateKey(%q) = (%v, %v), want matching key", enc, parsed != nil, err)
		}
	}

	for _, badPriv := range []string{
		base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		base64.RawURLEncoding.EncodeToString(make([]byte, 33)),
		"!@#$",
		"abc",
		"a-b",
		"a_b",
	} {
		if _, err := ParsePrivateKey(badPriv); err == nil {
			t.Fatalf("expected ParsePrivateKey(%q) error", badPriv)
		}
	}

	pubStd := base64.StdEncoding.EncodeToString(pub)
	if parsedPub, err := ParsePublicKey(" " + pubStd + " "); err != nil || !bytes.Equal(parsedPub, pub) {
		t.Fatalf("ParsePublicKey(std) = (%v, %v), want match", parsedPub != nil, err)
	}
	for _, badPubEnc := range []string{"!@#$", "abc", "a-b", base64.RawURLEncoding.EncodeToString(make([]byte, 16)), privURL} {
		if _, err := ParsePublicKey(badPubEnc); err == nil {
			t.Fatalf("expected ParsePublicKey(%q) error", badPubEnc)
		}
	}

	if _, err := NewSigner("bad-key", "https://hub.example.com/dir"); err == nil {
		t.Fatal("expected NewSigner invalid key error")
	}
	sTrimmed, err := NewSigner(seedURL, "  https://hub.example.com/dir  ")
	if err != nil || sTrimmed.directoryURL != "https://hub.example.com/dir" {
		t.Fatalf("NewSigner trimmed dir = (%v, %v)", sTrimmed, err)
	}
	sNoDir, err := NewSigner(seedStd, "")
	if err != nil || sNoDir.directoryURL != "" {
		t.Fatalf("NewSigner empty dir = (%v, %v)", sNoDir, err)
	}
}

func TestSignerValidityAndNilGuards(t *testing.T) {
	var nilSigner *Signer
	nilSigner.SetKeyValidity(100, 200)

	zeroSigner := &Signer{}
	if got := zeroSigner.PublicJWK(); got.Nbf != DefaultKeyNotBefore {
		t.Fatalf("zero-value Signer.PublicJWK().Nbf = %d, want %d", got.Nbf, DefaultKeyNotBefore)
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(kp.PrivateKeySeedB64URL, "https://hub.example.com/.well-known/http-message-signatures-directory")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(kp.PublicKeyB64URL)
	if err != nil {
		t.Fatal(err)
	}

	signer.SetKeyValidity(0, 0)
	signer.SetKeyValidity(-10, 100)
	if jwk := signer.PublicJWK(); jwk.Nbf != DefaultKeyNotBefore || jwk.Exp != 0 {
		t.Fatalf("expected unchanged validity after non-positive nbf / small exp, got %+v", jwk)
	}
	signer.SetKeyValidity(1_800_000_000, 1_800_000_000)
	if jwk := signer.PublicJWK(); jwk.Nbf != 1_800_000_000 || jwk.Exp != 0 {
		t.Fatalf("expected updated nbf and unset exp when exp == nbf, got %+v", jwk)
	}
	signer.SetKeyValidity(1_800_000_000, 1_800_001_000)
	if jwk := signer.PublicJWK(); jwk.Nbf != 1_800_000_000 || jwk.Exp != 1_800_001_000 {
		t.Fatalf("expected updated nbf and exp, got %+v", jwk)
	}
	rawDir, err := signer.DirectoryJSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc DirectoryDocument
	if err := json.Unmarshal(rawDir, &doc); err != nil || len(doc.Keys) != 1 || doc.Keys[0].Exp != 1_800_001_000 {
		t.Fatalf("unexpected DirectoryJSON: %s (err=%v)", string(rawDir), err)
	}

	// authorityForRequest branches
	if got := authorityForRequest(&http.Request{Host: "UPPER.Example.COM"}); got != "upper.example.com" {
		t.Fatalf("authorityForRequest(Host) = %q", got)
	}
	if got := authorityForRequest(&http.Request{URL: &url.URL{Scheme: "https", Host: "URL.Example.COM", Path: "/"}}); got != "url.example.com" {
		t.Fatalf("authorityForRequest(URL.Host) = %q", got)
	}
	if got := authorityForRequest(&http.Request{}); got != "" {
		t.Fatalf("authorityForRequest(empty) = %q", got)
	}

	// SignDirectoryResponse nil/edge guards
	dirReq, _ := http.NewRequest(http.MethodGet, "https://hub.example.com/dir", nil)
	hdr := make(http.Header)
	if err := nilSigner.SignDirectoryResponse(hdr, dirReq, []byte("{}"), time.Time{}); err != nil {
		t.Fatalf("nil Signer SignDirectoryResponse: %v", err)
	}
	if err := signer.SignDirectoryResponse(nil, dirReq, []byte("{}"), time.Time{}); err != nil {
		t.Fatalf("nil hdr SignDirectoryResponse: %v", err)
	}
	if err := signer.SignDirectoryResponse(hdr, nil, []byte("{}"), time.Time{}); err != nil {
		t.Fatalf("nil req SignDirectoryResponse: %v", err)
	}
	noAuthReq := &http.Request{URL: &url.URL{Path: "/"}}
	if err := signer.SignDirectoryResponse(hdr, noAuthReq, []byte("{}"), time.Time{}); err == nil {
		t.Fatal("expected SignDirectoryResponse missing @authority error")
	}

	// SignDirectoryResponse with req.Host == "" (uses URL.Host) and zero time
	urlHostReq := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "Dir.Example.COM", Path: "/dir"}}
	urlHostHdr := make(http.Header)
	if err := signer.SignDirectoryResponse(urlHostHdr, urlHostReq, []byte(`{"keys":[]}`), time.Time{}); err != nil {
		t.Fatalf("SignDirectoryResponse zero time: %v", err)
	}
	if err := VerifyDirectoryResponse(urlHostReq, urlHostHdr, []byte(`{"keys":[]}`), pub, time.Now()); err != nil {
		t.Fatalf("VerifyDirectoryResponse URL.Host: %v", err)
	}

	// SignRequest nil/edge guards
	if err := nilSigner.SignRequest(dirReq, time.Time{}); err != nil {
		t.Fatalf("nil Signer SignRequest: %v", err)
	}
	if err := signer.SignRequest(nil, time.Time{}); err != nil {
		t.Fatalf("nil req SignRequest: %v", err)
	}
	if err := signer.SignRequest(&http.Request{}, time.Time{}); err != nil {
		t.Fatalf("nil URL SignRequest: %v", err)
	}
	noAuthGetReq := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/p"}, Header: http.Header{}}
	if err := signer.SignRequest(noAuthGetReq, time.Time{}); err == nil {
		t.Fatal("expected SignRequest missing @authority error")
	}

	// SignRequest with empty Method, zero time, and empty directoryURL
	signerNoDir, err := NewSigner(kp.PrivateKeySeedB64URL, "")
	if err != nil {
		t.Fatal(err)
	}
	emptyMethodReq := &http.Request{
		URL:    &url.URL{Scheme: "https", Host: "Docs.Example.COM", Path: "/x"},
		Header: http.Header{},
	}
	if err := signerNoDir.SignRequest(emptyMethodReq, time.Time{}); err != nil {
		t.Fatalf("SignRequest empty method/zero time/no dir: %v", err)
	}
	if emptyMethodReq.Header.Get("Signature-Agent") != "" {
		t.Fatalf("expected no Signature-Agent when directoryURL is empty, got %q", emptyMethodReq.Header.Get("Signature-Agent"))
	}
	if err := VerifyRequest(emptyMethodReq, pub, time.Now()); err != nil {
		t.Fatalf("VerifyRequest empty method: %v", err)
	}
}

func TestVerifyDirectoryResponseEdgeCases(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(kp.PrivateKeySeedB64URL, "https://hub.example.com/dir")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(kp.PublicKeyB64URL)
	if err != nil {
		t.Fatal(err)
	}
	otherKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := ParsePublicKey(otherKP.PublicKeyB64URL)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_760_000_000, 0).UTC()
	req, _ := http.NewRequest(http.MethodGet, "https://hub.example.com/dir", nil)
	body := []byte(`{"keys":[]}`)
	hdr := make(http.Header)
	if err := signer.SignDirectoryResponse(hdr, req, body, now); err != nil {
		t.Fatal(err)
	}

	if err := VerifyDirectoryResponse(req, hdr, body, nil, now); err == nil {
		t.Fatal("expected invalid pub length error")
	}
	if err := VerifyDirectoryResponse(req, nil, body, pub, now); err == nil {
		t.Fatal("expected nil respHdr error")
	}

	missingDigest := hdr.Clone()
	missingDigest.Del("Content-Digest")
	if err := VerifyDirectoryResponse(req, missingDigest, body, pub, now); err == nil {
		t.Fatal("expected missing Content-Digest error")
	}

	wrongTag := hdr.Clone()
	wrongTag.Set("Signature-Input", strings.Replace(hdr.Get("Signature-Input"), `tag="http-message-signatures-directory"`, `tag="web-bot-auth"`, 1))
	if err := VerifyDirectoryResponse(req, wrongTag, body, pub, now); err == nil {
		t.Fatal("expected wrong tag error")
	}

	// Clock skew & expiry boundaries
	if err := VerifyDirectoryResponse(req, hdr, body, pub, now.Add(-61*time.Second)); err == nil {
		t.Fatal("expected future created > now+60 error")
	}
	if err := VerifyDirectoryResponse(req, hdr, body, pub, now.Add(-60*time.Second)); err != nil {
		t.Fatalf("expected created == now+60 to be within skew tolerance: %v", err)
	}
	if err := VerifyDirectoryResponse(req, hdr, body, pub, now.Add(DefaultSignatureTTL+time.Second)); err == nil {
		t.Fatal("expected expired directory signature error")
	}
	if err := VerifyDirectoryResponse(req, hdr, body, pub, now.Add(DefaultSignatureTTL)); err != nil {
		t.Fatalf("expected now == expires to succeed: %v", err)
	}
	if err := VerifyDirectoryResponse(req, hdr, body, pub, time.Time{}); err != nil {
		t.Fatalf("expected zero now to skip time window checks: %v", err)
	}

	// Signature byte & key failures
	shortSig := hdr.Clone()
	shortSig.Set("Signature", "directory=:AAAA:")
	if err := VerifyDirectoryResponse(req, shortSig, body, pub, now); err == nil {
		t.Fatal("expected short directory signature bytes error")
	}
	badB64Sig := hdr.Clone()
	badB64Sig.Set("Signature", "directory=:A:")
	if err := VerifyDirectoryResponse(req, badB64Sig, body, pub, now); err == nil {
		t.Fatal("expected invalid base64 directory signature error")
	}
	if err := VerifyDirectoryResponse(req, hdr, body, otherPub, now); err == nil {
		t.Fatal("expected wrong public key error")
	}
}

func TestVerifyRequestEdgeCasesAndConcurrentRace(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dirURL := "https://hub.example.com/.well-known/http-message-signatures-directory"
	signer, err := NewSigner(kp.PrivateKeySeedB64URL, dirURL)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(kp.PublicKeyB64URL)
	if err != nil {
		t.Fatal(err)
	}
	otherKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := ParsePublicKey(otherKP.PublicKeyB64URL)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_760_000_000, 0).UTC()
	req, _ := http.NewRequest(http.MethodGet, "https://docs.example.com/guide", nil)
	if err := signer.SignRequest(req, now); err != nil {
		t.Fatal(err)
	}

	if err := VerifyRequest(req, make([]byte, 16), now); err == nil {
		t.Fatal("expected invalid pub length error")
	}
	emptyHdrReq, _ := http.NewRequest(http.MethodGet, "https://docs.example.com/guide", nil)
	if err := VerifyRequest(emptyHdrReq, pub, now); err == nil {
		t.Fatal("expected missing signature headers error")
	}

	// Clock skew & zero time
	if err := VerifyRequest(req, pub, now.Add(-61*time.Second)); err == nil {
		t.Fatal("expected future created > now+60 error")
	}
	if err := VerifyRequest(req, pub, now.Add(-60*time.Second)); err != nil {
		t.Fatalf("expected created == now+60 to succeed: %v", err)
	}
	if err := VerifyRequest(req, pub, time.Time{}); err != nil {
		t.Fatalf("expected zero now to skip time window checks: %v", err)
	}

	// Missing covered header (Signature-Agent removed)
	missingCovered := req.Clone(req.Context())
	missingCovered.Header.Del("Signature-Agent")
	if err := VerifyRequest(missingCovered, pub, now); err == nil {
		t.Fatal("expected missing covered header error")
	}

	// Invalid signature bytes & wrong public key
	shortSig := req.Clone(req.Context())
	shortSig.Header.Set("Signature", "sig1=:AAAA:")
	if err := VerifyRequest(shortSig, pub, now); err == nil {
		t.Fatal("expected short signature bytes error")
	}
	badB64Sig := req.Clone(req.Context())
	badB64Sig.Header.Set("Signature", "sig1=:A:")
	if err := VerifyRequest(badB64Sig, pub, now); err == nil {
		t.Fatal("expected bad base64 signature error")
	}
	if err := VerifyRequest(req, otherPub, now); err == nil {
		t.Fatal("expected wrong public key verification error")
	}

	// Concurrent -race safety across SignRequest, VerifyRequest, SignDirectoryResponse, VerifyDirectoryResponse
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://docs.example.com/item/%d", id), nil)
			if err := signer.SignRequest(r, now); err != nil {
				t.Errorf("goroutine %d SignRequest: %v", id, err)
				return
			}
			if err := VerifyRequest(r, pub, now); err != nil {
				t.Errorf("goroutine %d VerifyRequest: %v", id, err)
				return
			}
			dr, _ := http.NewRequest(http.MethodGet, dirURL, nil)
			dh := make(http.Header)
			body := []byte(fmt.Sprintf(`{"id":%d}`, id))
			if err := signer.SignDirectoryResponse(dh, dr, body, now); err != nil {
				t.Errorf("goroutine %d SignDirectoryResponse: %v", id, err)
				return
			}
			if err := VerifyDirectoryResponse(dr, dh, body, pub, now); err != nil {
				t.Errorf("goroutine %d VerifyDirectoryResponse: %v", id, err)
			}
		}(g)
	}
	wg.Wait()
}
