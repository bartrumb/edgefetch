//go:build !wasip1

package mcpfed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
)

// RandomBase64URL generates byteLen CSPRNG bytes encoded as unpadded base64url.
func RandomBase64URL(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = 32
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return encodeBase64URL(buf), nil
}

// SHA256Base64URL computes unpadded base64url(SHA-256(UTF8(input))) for RFC 7636 S256 PKCE challenges and state hashes.
func SHA256Base64URL(input string) string {
	sum := sha256.Sum256([]byte(input))
	return encodeBase64URL(sum[:])
}

func aes256GCMSeal(key, iv, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, iv, plaintext, aad), nil
}

func aes256GCMOpen(key, iv, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ct, aad)
}

// SealVaultCredentials encrypts a VaultSecretPayload with HKDF-SHA256 + AES-256-GCM (v2 envelope).
func SealVaultCredentials(params SealVaultParams) SealVaultResult {
	prep := PrepareSealVaultEnvelope(params)
	if !prep.OK {
		return SealVaultResult{
			OK:      false,
			Status:  prep.Status,
			Error:   prep.Error,
			Message: prep.Message,
		}
	}
	salt := make([]byte, 16)
	iv := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return SealVaultResult{OK: false, Status: 503, Error: "vault_master_key_unconfigured", Message: err.Error()}
	}
	if _, err := rand.Read(iv); err != nil {
		return SealVaultResult{OK: false, Status: 503, Error: "vault_master_key_unconfigured", Message: err.Error()}
	}
	aesKey, err := hkdf.Key(sha256.New, []byte(prep.CleanKey), salt, prep.HKDFInfo, 32)
	if err != nil {
		return SealVaultResult{OK: false, Status: 503, Error: "vault_master_key_unconfigured", Message: err.Error()}
	}
	encryptedBuf, err := aes256GCMSeal(aesKey, iv, []byte(prep.Plaintext), []byte(prep.AAD))
	if err != nil {
		return SealVaultResult{OK: false, Status: 503, Error: "vault_master_key_unconfigured", Message: err.Error()}
	}
	return SealVaultResult{
		OK:            true,
		Ciphertext:    fmt.Sprintf("%s.%s.%s.%s", prep.EnvelopeVersion, encodeBase64URL(salt), encodeBase64URL(iv), encodeBase64URL(encryptedBuf)),
		SecretVersion: prep.SecretVersion,
	}
}

// UnsealVaultCredentials authenticates and decrypts an AES-256-GCM vault envelope with P6/M8 downgrade prevention
// and automatic reseal-on-read for legacy v1 / 2-field v2 rows.
func UnsealVaultCredentials(params UnsealVaultParams) UnsealVaultResult {
	prep := PrepareUnsealVaultEnvelope(params)
	if !prep.OK {
		return UnsealVaultResult{
			OK:      false,
			Error:   prep.Error,
			Message: prep.Message,
		}
	}

	var plainBuf []byte
	var matchedAttempt VaultUnsealAttempt
	decrypted := false
	lastFailMsg := "AES-256-GCM authentication failed"

	for _, att := range prep.Attempts {
		lastFailMsg = att.FailMessage
		aesKey, err := hkdf.Key(sha256.New, []byte(prep.CleanKey), prep.SaltBytes, att.HKDFInfo, 32)
		if err != nil {
			continue
		}
		pt, err := aes256GCMOpen(aesKey, prep.IVBytes, prep.CTBytes, []byte(att.AAD))
		if err == nil {
			plainBuf = pt
			matchedAttempt = att
			decrypted = true
			break
		}
	}
	if !decrypted {
		return vaultDecryptFail(lastFailMsg)
	}

	verified := VerifyUnsealedVaultPlaintext(params, plainBuf, matchedAttempt.ShouldReseal)
	if !verified.OK {
		return verified
	}
	if verified.NeedsReseal {
		canonicalOrigin := strings.ToLower(strings.TrimSpace(params.RemoteOrigin))
		rowID := resolveRowIDOption(params.ID, params.ServerID)
		rowSlug := ""
		if params.Slug != nil {
			rowSlug = strings.ToLower(strings.TrimSpace(*params.Slug))
		}
		rowAuthType := ""
		if params.AuthType != nil {
			rowAuthType = strings.ToLower(strings.TrimSpace(*params.AuthType))
		}
		sealArgs := SealVaultParams{
			VaultMasterKey: prep.CleanKey,
			UserID:         params.UserID,
			RemoteOrigin:   canonicalOrigin,
			Payload:        verified.Payload,
		}
		if rowID != "" && rowSlug != "" && rowAuthType != "" {
			sealArgs.ID = &rowID
			sealArgs.Slug = &rowSlug
			sealArgs.AuthType = &rowAuthType
		}
		resealed := SealVaultCredentials(sealArgs)
		if resealed.OK {
			verCopy := resealed.SecretVersion
			return UnsealVaultResult{
				OK:                    true,
				Payload:               verified.Payload,
				ResealedCiphertext:    resealed.Ciphertext,
				ResealedSecretVersion: &verCopy,
			}
		}
	}
	return UnsealVaultResult{
		OK:      true,
		Payload: verified.Payload,
	}
}

// SealPKCEStateBlob encrypts a downstream OAuth 2.1 PKCE verifier blob using the pkce2 envelope.
func SealPKCEStateBlob(vaultMasterKey, userID, remoteOrigin string, blob OrderedObject) (string, error) {
	hkdfInfo, aad, plain, err := PreparePKCEStateSeal(userID, remoteOrigin, blob)
	if err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	iv := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	key, err := hkdf.Key(sha256.New, []byte(vaultMasterKey), salt, hkdfInfo, 32)
	if err != nil {
		return "", err
	}
	ct, err := aes256GCMSeal(key, iv, []byte(plain), []byte(aad))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pkce2.%s.%s.%s", encodeBase64URL(salt), encodeBase64URL(iv), encodeBase64URL(ct)), nil
}

// UnsealPKCEStateBlob authenticates and decrypts a pkce2 OAuth state blob.
func UnsealPKCEStateBlob(vaultMasterKey, userID, remoteOrigin, ciphertext string) (OrderedObject, bool) {
	hkdfInfo, aad, _, _, _, salt, iv, ct, ok := PreparePKCEStateUnseal(userID, remoteOrigin, ciphertext)
	if !ok {
		return nil, false
	}
	key, err := hkdf.Key(sha256.New, []byte(vaultMasterKey), salt, hkdfInfo, 32)
	if err != nil {
		return nil, false
	}
	plain, err := aes256GCMOpen(key, iv, ct, []byte(aad))
	if err != nil {
		return nil, false
	}
	return VerifyPKCEStatePlaintext(plain)
}

// ComputeMCPOAuthBindHMAC computes the HMAC-SHA256 bind cookie signature over userId|state|sessionCsrf.
func ComputeMCPOAuthBindHMAC(vaultMasterKey, userID, state, sessionCSRF string) string {
	macKey, macMsg := BuildOAuthBindMACInputs(vaultMasterKey, userID, state, sessionCSRF)
	mac := hmac.New(sha256.New, []byte(macKey))
	mac.Write([]byte(macMsg))
	return encodeBase64URL(mac.Sum(nil))
}

// VerifyMCPOAuthBindHMAC compares presented cookie HMAC in constant time.
func VerifyMCPOAuthBindHMAC(presented, vaultMasterKey, userID, state, sessionCSRF string) bool {
	if presented == "" {
		return false
	}
	expected := ComputeMCPOAuthBindHMAC(vaultMasterKey, userID, state, sessionCSRF)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}
