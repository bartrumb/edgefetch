package mcpfed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MinVaultMasterKeyLength matches MIN_TOKEN_LENGTH (24) in hub/src/auth.ts.
	MinVaultMasterKeyLength = 24

	// VaultCredentialsPurposeV2 is the HKDF info purpose label for v2 user_mcp_servers credentials.
	VaultCredentialsPurposeV2 = "user_mcp_servers:credentials:v2"

	// VaultPKCEStatePurposeV2 is the HKDF info purpose label for pkce2 mcp_oauth_states blobs.
	VaultPKCEStatePurposeV2 = "mcp_oauth_states:pkce:v2"
)

// VaultSecretOAuth holds downstream OAuth 2.1 tokens inside VaultSecretPayload.
type VaultSecretOAuth struct {
	AccessToken         string `json:"accessToken"`
	RefreshToken        string `json:"refreshToken,omitempty"`
	TokenType           string `json:"tokenType,omitempty"`
	ExpiresAt           *int64 `json:"expiresAt,omitempty"`
	Scope               string `json:"scope,omitempty"`
	Issuer              string `json:"issuer,omitempty"`
	Resource            string `json:"resource,omitempty"`
	TokenEndpoint       string `json:"tokenEndpoint"`
	ConfirmedAuthOrigin string `json:"confirmedAuthOrigin,omitempty"`
	ClientID            string `json:"clientId"`
	ClientSecret        string `json:"clientSecret,omitempty"`
}

// VaultSecretPayload represents the plaintext credential payload sealed inside user_mcp_servers.
type VaultSecretPayload struct {
	Kind         string            `json:"kind"`
	PinnedOrigin string            `json:"pinnedOrigin"`
	PinnedURL    string            `json:"pinnedUrl,omitempty"`
	Purpose      string            `json:"purpose,omitempty"`
	ServerID     string            `json:"serverId,omitempty"`
	Slug         string            `json:"slug,omitempty"`
	AuthType     string            `json:"authType,omitempty"`
	Headers      OrderedObject     `json:"headers,omitempty"`
	OAuth        *VaultSecretOAuth `json:"oauth,omitempty"`
}

// SealVaultParams configures SealVaultCredentials.
type SealVaultParams struct {
	VaultMasterKey string
	UserID         string
	RemoteOrigin   string
	ID             *string
	ServerID       *string
	Slug           *string
	AuthType       *string
	Payload        OrderedObject
}

// SealVaultResult is the outcome of SealVaultCredentials.
type SealVaultResult struct {
	OK            bool   `json:"ok"`
	Ciphertext    string `json:"ciphertext,omitempty"`
	SecretVersion int    `json:"secretVersion,omitempty"`
	Status        int    `json:"status,omitempty"`
	Error         string `json:"error,omitempty"`
	Message       string `json:"message,omitempty"`
}

// UnsealVaultParams configures UnsealVaultCredentials.
type UnsealVaultParams struct {
	VaultMasterKey string
	UserID         string
	RemoteOrigin   string
	RemoteURL      string
	ID             *string
	ServerID       *string
	Slug           *string
	AuthType       *string
	SecretVersion  *int
	Ciphertext     string
}

// UnsealVaultResult is the outcome of UnsealVaultCredentials.
type UnsealVaultResult struct {
	OK                    bool          `json:"ok"`
	Payload               OrderedObject `json:"payload,omitempty"`
	ResealedCiphertext    string        `json:"resealedCiphertext,omitempty"`
	ResealedSecretVersion *int          `json:"resealedSecretVersion,omitempty"`
	Error                 string        `json:"error,omitempty"`
	Message               string        `json:"message,omitempty"`
}

// ValidateVaultMasterKey enforces VAULT_MASTER_KEY >= 24 trimmed UTF-16 characters.
func ValidateVaultMasterKey(vaultMasterKey string) (clean string, ok bool, message string) {
	clean = strings.TrimSpace(vaultMasterKey)
	if utf16Len(clean) < MinVaultMasterKeyLength {
		return "", false, fmt.Sprintf(
			"VAULT_MASTER_KEY must be configured with at least %d random characters to encrypt MCP credentials.",
			MinVaultMasterKeyLength,
		)
	}
	return clean, true, ""
}

func encodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeBase64URL(raw string) ([]byte, bool) {
	if raw == "" || len(raw)%4 == 1 {
		return nil, false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, false
		}
	}
	out, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, false
	}
	return out, true
}

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

func derivePerUserOriginAESKey(vaultMasterKey string, salt []byte, userID, remoteOrigin, purpose string) ([]byte, error) {
	originLower := strings.ToLower(remoteOrigin)
	scopedPair := fmt.Sprintf("%d:%s|%d:%s", utf16Len(userID), userID, utf16Len(originLower), originLower)
	var infoLabel string
	if purpose != "" {
		infoLabel = "edgefetch-mcp-vault-v1:" + purpose + ":" + scopedPair
	} else {
		infoLabel = "edgefetch-mcp-vault-v1:" + scopedPair
	}
	return hkdf.Key(sha256.New, []byte(vaultMasterKey), salt, infoLabel, 32)
}

func deriveLegacyV270PerUserOriginAESKey(vaultMasterKey string, salt []byte, userID, remoteOrigin string) ([]byte, error) {
	originLower := strings.ToLower(remoteOrigin)
	infoLabel := "edgefetch-mcp-vault-v1:" + userID + ":" + originLower
	return hkdf.Key(sha256.New, []byte(vaultMasterKey), salt, infoLabel, 32)
}

func buildVaultV2RowBoundAAD(envelopeVersion, userID, canonicalOrigin, serverID, slug, authType string) []byte {
	cleanSlug := strings.ToLower(strings.TrimSpace(slug))
	cleanAuthType := strings.ToLower(strings.TrimSpace(authType))
	var sb strings.Builder
	sb.Grow(128 + len(userID) + len(canonicalOrigin) + len(serverID) + len(cleanSlug) + len(cleanAuthType))
	sb.WriteString(envelopeVersion)
	sb.WriteString("|user_mcp_servers:credentials|")
	sb.WriteString(strconv.Itoa(utf16Len(userID)))
	sb.WriteByte(':')
	sb.WriteString(userID)
	sb.WriteByte('|')
	sb.WriteString(strconv.Itoa(utf16Len(canonicalOrigin)))
	sb.WriteByte(':')
	sb.WriteString(canonicalOrigin)
	sb.WriteByte('|')
	sb.WriteString(strconv.Itoa(utf16Len(serverID)))
	sb.WriteByte(':')
	sb.WriteString(serverID)
	sb.WriteByte('|')
	sb.WriteString(strconv.Itoa(utf16Len(cleanSlug)))
	sb.WriteByte(':')
	sb.WriteString(cleanSlug)
	sb.WriteByte('|')
	sb.WriteString(strconv.Itoa(utf16Len(cleanAuthType)))
	sb.WriteByte(':')
	sb.WriteString(cleanAuthType)
	return []byte(sb.String())
}

func buildVaultV2OriginBoundAAD(envelopeVersion, userID, canonicalOrigin string) []byte {
	return []byte(fmt.Sprintf(
		"%s|user_mcp_servers:credentials|%d:%s|%d:%s",
		envelopeVersion,
		utf16Len(userID), userID,
		utf16Len(canonicalOrigin), canonicalOrigin,
	))
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

func resolveRowIDOption(id, serverID *string) string {
	if id != nil {
		return strings.TrimSpace(*id)
	}
	if serverID != nil {
		return strings.TrimSpace(*serverID)
	}
	return ""
}

// SealVaultCredentials encrypts a VaultSecretPayload with HKDF-SHA256 + AES-256-GCM (v2 envelope).
func SealVaultCredentials(params SealVaultParams) SealVaultResult {
	cleanKey, ok, keyMsg := ValidateVaultMasterKey(params.VaultMasterKey)
	if !ok {
		return SealVaultResult{
			OK:      false,
			Status:  503,
			Error:   "vault_master_key_unconfigured",
			Message: keyMsg,
		}
	}

	canonicalOrigin := strings.ToLower(strings.TrimSpace(params.RemoteOrigin))
	rowID := resolveRowIDOption(params.ID, params.ServerID)
	rowSlug := ""
	if params.Slug != nil {
		rowSlug = strings.ToLower(strings.TrimSpace(*params.Slug))
	}
	if rowSlug != "" && !IsValidMCPConnectorSlug(rowSlug) {
		return SealVaultResult{
			OK:      false,
			Status:  400,
			Error:   "invalid_slug",
			Message: `Connector slug must be 1..48 lowercase [a-z0-9_-] characters and must not contain "__".`,
		}
	}
	rowAuthType := ""
	if params.AuthType != nil {
		rowAuthType = strings.ToLower(strings.TrimSpace(*params.AuthType))
	}
	hasRowBinding := rowID != "" && rowSlug != "" && rowAuthType != ""
	const envelopeVersion = "v2"

	salt := make([]byte, 16)
	iv := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return SealVaultResult{OK: false, Status: 503, Error: "vault_master_key_unconfigured", Message: err.Error()}
	}
	if _, err := rand.Read(iv); err != nil {
		return SealVaultResult{OK: false, Status: 503, Error: "vault_master_key_unconfigured", Message: err.Error()}
	}

	aesKey, err := derivePerUserOriginAESKey(cleanKey, salt, params.UserID, canonicalOrigin, VaultCredentialsPurposeV2)
	if err != nil {
		return SealVaultResult{OK: false, Status: 503, Error: "vault_master_key_unconfigured", Message: err.Error()}
	}

	var aad []byte
	if hasRowBinding {
		aad = buildVaultV2RowBoundAAD(envelopeVersion, params.UserID, canonicalOrigin, rowID, rowSlug, rowAuthType)
	} else {
		aad = buildVaultV2OriginBoundAAD(envelopeVersion, params.UserID, canonicalOrigin)
	}

	inner := params.Payload.Clone()
	inner.Set("purpose", "user_mcp_servers:credentials")
	inner.Set("pinnedOrigin", canonicalOrigin)
	if hasRowBinding {
		inner.Set("serverId", rowID)
		inner.Set("slug", rowSlug)
		inner.Set("authType", rowAuthType)
	}

	plaintext, err := MarshalUnescapedJSON(inner)
	if err != nil {
		return SealVaultResult{OK: false, Status: 400, Error: "invalid_slug", Message: err.Error()}
	}
	encryptedBuf, err := aes256GCMSeal(aesKey, iv, plaintext, aad)
	if err != nil {
		return SealVaultResult{OK: false, Status: 503, Error: "vault_master_key_unconfigured", Message: err.Error()}
	}

	secVer := 1
	if hasRowBinding {
		secVer = 2
	}
	return SealVaultResult{
		OK:            true,
		Ciphertext:    fmt.Sprintf("%s.%s.%s.%s", envelopeVersion, encodeBase64URL(salt), encodeBase64URL(iv), encodeBase64URL(encryptedBuf)),
		SecretVersion: secVer,
	}
}

func parseEnvelopeHeader(ciphertext string) (ver, saltB64, ivB64, ctB64 string, ok bool) {
	if ciphertext == "" {
		return "", "", "", "", false
	}
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 4 {
		return "", "", "", "", false
	}
	if parts[0] != "v2" && parts[0] != "v1" {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3], true
}

func isValidCredentialPayloadKind(kind string) bool {
	return kind == "headers" || kind == "oauth2" || kind == "none"
}

func vaultDecryptFail(msg string) UnsealVaultResult {
	return UnsealVaultResult{
		OK:      false,
		Error:   "vault_decryption_failed",
		Message: msg,
	}
}

// UnsealVaultCredentials authenticates and decrypts an AES-256-GCM vault envelope with P6/M8 downgrade prevention
// and automatic reseal-on-read for legacy v1 / 2-field v2 rows.
func UnsealVaultCredentials(params UnsealVaultParams) UnsealVaultResult {
	cleanKey, ok, keyMsg := ValidateVaultMasterKey(params.VaultMasterKey)
	if !ok {
		return UnsealVaultResult{
			OK:      false,
			Error:   "vault_master_key_unconfigured",
			Message: keyMsg,
		}
	}

	ver, saltB64, ivB64, ctB64, hdrOk := parseEnvelopeHeader(params.Ciphertext)
	if !hdrOk {
		return vaultDecryptFail("Malformed vault ciphertext envelope")
	}
	salt, sOk := decodeBase64URL(saltB64)
	iv, iOk := decodeBase64URL(ivB64)
	ct, cOk := decodeBase64URL(ctB64)
	if !sOk || len(salt) != 16 || !iOk || len(iv) != 12 || !cOk || len(ct) < 17 {
		return vaultDecryptFail("Invalid vault IV or authentication tag length")
	}

	canonicalOrigin := strings.ToLower(strings.TrimSpace(params.RemoteOrigin))
	if params.RemoteOrigin != canonicalOrigin {
		return vaultDecryptFail("Non-canonical origin supplied to vault decryption")
	}

	hasAnyRowParam := params.ID != nil || params.ServerID != nil || params.Slug != nil || params.AuthType != nil
	rowID := resolveRowIDOption(params.ID, params.ServerID)
	rowSlug := ""
	if params.Slug != nil {
		rowSlug = strings.ToLower(strings.TrimSpace(*params.Slug))
	}
	rowAuthType := ""
	if params.AuthType != nil {
		rowAuthType = strings.ToLower(strings.TrimSpace(*params.AuthType))
	}
	hasFullRowBinding := rowID != "" && rowSlug != "" && rowAuthType != ""

	if params.SecretVersion != nil && *params.SecretVersion > 2 {
		return vaultDecryptFail(fmt.Sprintf("Unsupported vault secret_version %d", *params.SecretVersion))
	}
	if params.SecretVersion != nil && *params.SecretVersion >= 2 {
		if ver != "v2" {
			return vaultDecryptFail("Vault downgrade blocked: secret_version >= 2 requires a v2 ciphertext envelope")
		}
		if !hasFullRowBinding {
			return vaultDecryptFail("Vault v2 row-bound decryption requires id, slug, and authType")
		}
	} else if hasAnyRowParam && !hasFullRowBinding {
		return vaultDecryptFail("Incomplete row binding attributes supplied to vault decryption")
	}

	var plainBuf []byte
	shouldResealToV2 := false

	if ver == "v2" {
		aesKey, err := derivePerUserOriginAESKey(cleanKey, salt, params.UserID, canonicalOrigin, VaultCredentialsPurposeV2)
		if err != nil {
			return vaultDecryptFail("AES-256-GCM key derivation failed")
		}
		if hasFullRowBinding {
			aad5 := buildVaultV2RowBoundAAD(ver, params.UserID, canonicalOrigin, rowID, rowSlug, rowAuthType)
			plainBuf, err = aes256GCMOpen(aesKey, iv, ct, aad5)
			if err != nil {
				if params.SecretVersion != nil && *params.SecretVersion >= 2 {
					return vaultDecryptFail("AES-256-GCM authentication failed (wrong user_id, tampered id/slug/auth_type/origin, or rotated VAULT_MASTER_KEY)")
				}
				aad2 := buildVaultV2OriginBoundAAD(ver, params.UserID, canonicalOrigin)
				plainBuf, err = aes256GCMOpen(aesKey, iv, ct, aad2)
				if err != nil {
					return vaultDecryptFail("AES-256-GCM authentication failed (wrong user_id, tampered id/slug/auth_type/origin, or rotated VAULT_MASTER_KEY)")
				}
				shouldResealToV2 = true
			}
		} else {
			aad2 := buildVaultV2OriginBoundAAD(ver, params.UserID, canonicalOrigin)
			plainBuf, err = aes256GCMOpen(aesKey, iv, ct, aad2)
			if err != nil {
				return vaultDecryptFail("AES-256-GCM authentication failed (wrong user_id, tampered origin/purpose, or rotated VAULT_MASTER_KEY)")
			}
		}
	} else {
		// v1 envelope (only reachable when SecretVersion == nil || *SecretVersion < 2)
		shouldResealToV2 = true
		aesKey, err := derivePerUserOriginAESKey(cleanKey, salt, params.UserID, canonicalOrigin, "")
		if err != nil {
			return vaultDecryptFail("AES-256-GCM key derivation failed")
		}
		aad := []byte(fmt.Sprintf("%d:%s|%d:%s", utf16Len(params.UserID), params.UserID, utf16Len(canonicalOrigin), canonicalOrigin))
		plainBuf, err = aes256GCMOpen(aesKey, iv, ct, aad)
		if err != nil {
			if strings.Contains(params.UserID, "|") || strings.Contains(params.UserID, ":") {
				return vaultDecryptFail("AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)")
			}
			legacyKey, lErr := deriveLegacyV270PerUserOriginAESKey(cleanKey, salt, params.UserID, canonicalOrigin)
			if lErr != nil {
				return vaultDecryptFail("AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)")
			}
			legacyAAD := []byte(params.UserID + "|" + canonicalOrigin)
			plainBuf, err = aes256GCMOpen(legacyKey, iv, ct, legacyAAD)
			if err != nil {
				return vaultDecryptFail("AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)")
			}
		}
	}

	if !utf8.Valid(plainBuf) {
		return vaultDecryptFail("AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)")
	}
	parsedAny, err := ParseOrderedJSON(plainBuf, 32)
	if err != nil {
		return vaultDecryptFail("AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)")
	}
	rawParsed, isObj := parsedAny.(OrderedObject)
	if !isObj {
		return vaultDecryptFail("Pinned origin or credential purpose mismatch during vault decryption")
	}

	kindStr, kindOk := rawParsed.GetString("kind")
	if !kindOk || !isValidCredentialPayloadKind(kindStr) {
		return vaultDecryptFail("Pinned origin or credential purpose mismatch during vault decryption")
	}
	if rawPurpose, hasPurpose := rawParsed.Get("purpose"); hasPurpose && rawPurpose != nil {
		pStr, pOk := rawPurpose.(string)
		if !pOk || pStr != "user_mcp_servers:credentials" {
			return vaultDecryptFail("Pinned origin or credential purpose mismatch during vault decryption")
		}
	}
	pinnedOrigin, poOk := rawParsed.GetString("pinnedOrigin")
	if !poOk || strings.ToLower(pinnedOrigin) != canonicalOrigin {
		return vaultDecryptFail("Pinned origin or credential purpose mismatch during vault decryption")
	}

	if hasFullRowBinding {
		if srvID, ok := rawParsed.GetString("serverId"); ok && srvID != rowID {
			return vaultDecryptFail("Server id mismatch during vault decryption")
		}
		if slugVal, ok := rawParsed.GetString("slug"); ok && strings.ToLower(slugVal) != rowSlug {
			return vaultDecryptFail("Server slug mismatch during vault decryption")
		}
		if atVal, ok := rawParsed.GetString("authType"); ok && strings.ToLower(atVal) != rowAuthType {
			return vaultDecryptFail("Server auth_type mismatch during vault decryption")
		}
	}

	if params.RemoteURL != "" {
		if pinnedURL, ok := rawParsed.GetString("pinnedUrl"); ok && pinnedURL != "" {
			if strings.TrimRight(strings.TrimSpace(params.RemoteURL), "/") != strings.TrimRight(strings.TrimSpace(pinnedURL), "/") {
				return vaultDecryptFail("Pinned endpoint URL path mismatch during vault decryption")
			}
		}
	}

	if shouldResealToV2 || (params.SecretVersion != nil && *params.SecretVersion < 2 && hasFullRowBinding) {
		sealArgs := SealVaultParams{
			VaultMasterKey: cleanKey,
			UserID:         params.UserID,
			RemoteOrigin:   canonicalOrigin,
			Payload:        rawParsed,
		}
		if hasFullRowBinding {
			sealArgs.ID = &rowID
			sealArgs.Slug = &rowSlug
			sealArgs.AuthType = &rowAuthType
		}
		resealed := SealVaultCredentials(sealArgs)
		if resealed.OK {
			verCopy := resealed.SecretVersion
			return UnsealVaultResult{
				OK:                    true,
				Payload:               rawParsed,
				ResealedCiphertext:    resealed.Ciphertext,
				ResealedSecretVersion: &verCopy,
			}
		}
	}

	return UnsealVaultResult{
		OK:      true,
		Payload: rawParsed,
	}
}

// SealPKCEStateBlob encrypts a downstream OAuth 2.1 PKCE verifier blob using the pkce2 envelope.
func SealPKCEStateBlob(vaultMasterKey, userID, remoteOrigin string, blob OrderedObject) (string, error) {
	canonicalOrigin := strings.ToLower(strings.TrimSpace(remoteOrigin))
	salt := make([]byte, 16)
	iv := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	key, err := derivePerUserOriginAESKey(vaultMasterKey, salt, userID, canonicalOrigin, VaultPKCEStatePurposeV2)
	if err != nil {
		return "", err
	}
	aad := []byte(fmt.Sprintf(
		"pkce2|mcp_oauth_states:pkce|%d:%s|%d:%s",
		utf16Len(userID), userID,
		utf16Len(canonicalOrigin), canonicalOrigin,
	))
	inner := blob.Clone()
	inner.Set("purpose", "mcp_oauth_states:pkce")
	plain, err := MarshalUnescapedJSON(inner)
	if err != nil {
		return "", err
	}
	ct, err := aes256GCMSeal(key, iv, plain, aad)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pkce2.%s.%s.%s", encodeBase64URL(salt), encodeBase64URL(iv), encodeBase64URL(ct)), nil
}

// UnsealPKCEStateBlob authenticates and decrypts a pkce2 OAuth state blob.
func UnsealPKCEStateBlob(vaultMasterKey, userID, remoteOrigin, ciphertext string) (OrderedObject, bool) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 4 || parts[0] != "pkce2" {
		return nil, false
	}
	salt, sOk := decodeBase64URL(parts[1])
	iv, iOk := decodeBase64URL(parts[2])
	ct, cOk := decodeBase64URL(parts[3])
	if !sOk || len(salt) != 16 || !iOk || len(iv) != 12 || !cOk || len(ct) < 17 {
		return nil, false
	}
	canonicalOrigin := strings.ToLower(strings.TrimSpace(remoteOrigin))
	key, err := derivePerUserOriginAESKey(vaultMasterKey, salt, userID, canonicalOrigin, VaultPKCEStatePurposeV2)
	if err != nil {
		return nil, false
	}
	aad := []byte(fmt.Sprintf(
		"%s|mcp_oauth_states:pkce|%d:%s|%d:%s",
		parts[0],
		utf16Len(userID), userID,
		utf16Len(canonicalOrigin), canonicalOrigin,
	))
	plain, err := aes256GCMOpen(key, iv, ct, aad)
	if err != nil || !utf8.Valid(plain) {
		return nil, false
	}
	parsedAny, err := ParseOrderedJSON(plain, 16)
	if err != nil {
		return nil, false
	}
	parsed, isObj := parsedAny.(OrderedObject)
	if !isObj {
		return nil, false
	}
	if _, hasCV := parsed.GetString("codeVerifier"); !hasCV {
		return nil, false
	}
	if purpose, ok := parsed.GetString("purpose"); !ok || purpose != "mcp_oauth_states:pkce" {
		return nil, false
	}
	return parsed, true
}

// ComputeMCPOAuthBindHMAC computes the HMAC-SHA256 bind cookie signature over userId|state|sessionCsrf.
func ComputeMCPOAuthBindHMAC(vaultMasterKey, userID, state, sessionCSRF string) string {
	mac := hmac.New(sha256.New, []byte("edgefetch-mcp-oauth-bind:"+vaultMasterKey))
	mac.Write([]byte(userID + "|" + state + "|" + sessionCSRF))
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

// ParseVaultSecretPayloadObject extracts structured fields from an OrderedObject VaultSecretPayload.
func ParseVaultSecretPayloadObject(obj OrderedObject) (VaultSecretPayload, error) {
	raw, err := MarshalUnescapedJSON(obj)
	if err != nil {
		return VaultSecretPayload{}, err
	}
	var out VaultSecretPayload
	if err := decodeVaultSecretPayload(raw, &out); err != nil {
		return VaultSecretPayload{}, err
	}
	return out, nil
}

func decodeVaultSecretPayload(raw []byte, out *VaultSecretPayload) error {
	val, err := ParseOrderedJSON(raw, 16)
	if err != nil {
		return err
	}
	obj, ok := val.(OrderedObject)
	if !ok {
		return errors.New("expected VaultSecretPayload object")
	}
	out.Kind, _ = obj.GetString("kind")
	out.PinnedOrigin, _ = obj.GetString("pinnedOrigin")
	out.PinnedURL, _ = obj.GetString("pinnedUrl")
	out.Purpose, _ = obj.GetString("purpose")
	out.ServerID, _ = obj.GetString("serverId")
	out.Slug, _ = obj.GetString("slug")
	out.AuthType, _ = obj.GetString("authType")
	if hdrs, ok := obj.GetObject("headers"); ok {
		out.Headers = hdrs
	}
	if oa, ok := obj.GetObject("oauth"); ok {
		oauthOut := &VaultSecretOAuth{}
		oauthOut.AccessToken, _ = oa.GetString("accessToken")
		oauthOut.RefreshToken, _ = oa.GetString("refreshToken")
		oauthOut.TokenType, _ = oa.GetString("tokenType")
		if expVal, hasExp := oa.Get("expiresAt"); hasExp {
			if n, isN := expVal.(json.Number); isN {
				if f, err := strconv.ParseFloat(string(n), 64); err == nil {
					iv := int64(f)
					oauthOut.ExpiresAt = &iv
				}
			}
		}
		oauthOut.Scope, _ = oa.GetString("scope")
		oauthOut.Issuer, _ = oa.GetString("issuer")
		oauthOut.Resource, _ = oa.GetString("resource")
		oauthOut.TokenEndpoint, _ = oa.GetString("tokenEndpoint")
		oauthOut.ConfirmedAuthOrigin, _ = oa.GetString("confirmedAuthOrigin")
		oauthOut.ClientID, _ = oa.GetString("clientId")
		oauthOut.ClientSecret, _ = oa.GetString("clientSecret")
		out.OAuth = oauthOut
	}
	return nil
}
