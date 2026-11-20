package botauth

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

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
