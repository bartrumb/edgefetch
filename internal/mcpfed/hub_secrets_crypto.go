//go:build !wasip1

package mcpfed

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// HubSecretFingerprint returns the first 8 lowercase hex chars of SHA-256(value): enough to tell two values
// apart in /admin without revealing the value itself.
func HubSecretFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:hubSecretFingerprintChars]
}

// SealHubSecret encrypts a managed hub secret value into an "hs1" envelope (native Go hub + test parity
// with the hub/src/hub-secrets.ts WebCrypto path, which consumes PrepareHubSecretSeal via WASM).
func SealHubSecret(vaultMasterKey, name, value string) (ciphertext, fingerprint string, failure *HubSecretError) {
	prep := PrepareHubSecretSeal(vaultMasterKey, name, value)
	if !prep.OK {
		return "", "", &HubSecretError{Status: prep.Status, Error: prep.Error, Message: prep.Message}
	}
	salt := make([]byte, 16)
	iv := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", "", &HubSecretError{Status: 503, Error: "hub_secret_encryption_failed", Message: err.Error()}
	}
	if _, err := rand.Read(iv); err != nil {
		return "", "", &HubSecretError{Status: 503, Error: "hub_secret_encryption_failed", Message: err.Error()}
	}
	key, err := hkdf.Key(sha256.New, []byte(prep.CleanKey), salt, prep.HKDFInfo, 32)
	if err != nil {
		return "", "", &HubSecretError{Status: 503, Error: "hub_secret_encryption_failed", Message: err.Error()}
	}
	ct, err := aes256GCMSeal(key, iv, []byte(prep.Plaintext), []byte(prep.AAD))
	if err != nil {
		return "", "", &HubSecretError{Status: 503, Error: "hub_secret_encryption_failed", Message: err.Error()}
	}
	env := prep.EnvelopeVersion + "." + encodeBase64URL(salt) + "." + encodeBase64URL(iv) + "." + encodeBase64URL(ct)
	return env, HubSecretFingerprint(prep.NormalizedValue), nil
}

// UnsealHubSecret decrypts an "hs1" envelope stored under name. A ciphertext sealed for another name fails.
func UnsealHubSecret(vaultMasterKey, name, ciphertext string) (string, *HubSecretError) {
	prep := PrepareHubSecretUnseal(vaultMasterKey, name, ciphertext)
	if !prep.OK {
		return "", &HubSecretError{Status: prep.Status, Error: prep.Error, Message: prep.Message}
	}
	key, err := hkdf.Key(sha256.New, []byte(prep.CleanKey), prep.SaltBytes, prep.HKDFInfo, 32)
	if err != nil {
		return "", &HubSecretError{Status: 500, Error: "hub_secret_decryption_failed", Message: err.Error()}
	}
	plain, err := aes256GCMOpen(key, prep.IVBytes, prep.CTBytes, []byte(prep.AAD))
	if err != nil {
		return "", &HubSecretError{Status: 500, Error: "hub_secret_decryption_failed", Message: "AES-256-GCM authentication failed (wrong secret name, tampered row, or rotated VAULT_MASTER_KEY)"}
	}
	value, ok := VerifyHubSecretPlaintext(name, plain)
	if !ok {
		return "", &HubSecretError{Status: 500, Error: "hub_secret_decryption_failed", Message: "Decrypted hub secret payload does not match its row name."}
	}
	return value, nil
}
