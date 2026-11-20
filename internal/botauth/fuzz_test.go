package botauth

import (
	"net/http"
	"testing"
	"time"
)

func FuzzBotAuthVerifyRequest(f *testing.F) {
	kp, err := GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	pub, err := ParsePublicKey(kp.PublicKeyB64URL)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(
		`sig1=("@authority");created=1760000000;expires=1760000300;keyid="test";alg="ed25519";tag="web-bot-auth"`,
		`sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:`,
		`"https://hub.example.com/.well-known/http-message-signatures-directory"`,
		`sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:`,
	)
	f.Add(`sig1=()`, `sig1=::`, `""`, ``)
	f.Add(`malformed;;;`, `not-sfv`, `bad`, `sha-256=bad`)

	now := time.Unix(1_760_000_010, 0).UTC()
	f.Fuzz(func(t *testing.T, sigInput, sigHdr, sigAgent, contentDigest string) {
		if len(sigInput) > 4096 || len(sigHdr) > 4096 || len(sigAgent) > 1024 || len(contentDigest) > 1024 {
			return
		}
		req, reqErr := http.NewRequest(http.MethodGet, "https://docs.example.com/guide", nil)
		if reqErr != nil {
			return
		}
		req.Header.Set("Signature-Input", sigInput)
		req.Header.Set("Signature", sigHdr)
		req.Header.Set("Signature-Agent", sigAgent)
		// Random/fuzzed signatures under a freshly generated Ed25519 key must never panic and must fail closed.
		if err := VerifyRequest(req, pub, now); err == nil {
			t.Fatalf("unexpected VerifyRequest success on unauthenticated fuzzed headers: %q / %q", sigInput, sigHdr)
		}

		respHdr := make(http.Header)
		respHdr.Set("Signature-Input", sigInput)
		respHdr.Set("Signature", sigHdr)
		respHdr.Set("Content-Digest", contentDigest)
		if err := VerifyDirectoryResponse(req, respHdr, []byte(`{"keys":[]}`), pub, now); err == nil {
			t.Fatalf("unexpected VerifyDirectoryResponse success on unauthenticated fuzzed headers")
		}
	})
}
