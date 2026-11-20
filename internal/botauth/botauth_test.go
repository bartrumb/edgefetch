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
}
