package mcpfed

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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

// SealVaultParams configures SealVaultCredentials / PrepareSealVaultEnvelope.
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

// PreparedVaultSeal holds Go-computed HKDF info, AAD, and canonical JSON plaintext for AEAD sealing.
type PreparedVaultSeal struct {
	OK              bool   `json:"ok"`
	CleanKey        string `json:"cleanKey,omitempty"`
	HKDFInfo        string `json:"hkdfInfo,omitempty"`
	AAD             string `json:"aad,omitempty"`
	Plaintext       string `json:"plaintext,omitempty"`
	EnvelopeVersion string `json:"envelopeVersion,omitempty"`
	SecretVersion   int    `json:"secretVersion,omitempty"`
	Status          int    `json:"status,omitempty"`
	Error           string `json:"error,omitempty"`
	Message         string `json:"message,omitempty"`
}

// UnsealVaultParams configures UnsealVaultCredentials / PrepareUnsealVaultEnvelope.
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
	NeedsReseal           bool          `json:"needsReseal,omitempty"`
	Error                 string        `json:"error,omitempty"`
	Message               string        `json:"message,omitempty"`
}

// VaultUnsealAttempt describes one ordered AEAD decryption candidate (primary v2 5-field, legacy v2 2-field, or v1).
type VaultUnsealAttempt struct {
	HKDFInfo     string `json:"hkdfInfo"`
	AAD          string `json:"aad"`
	ShouldReseal bool   `json:"shouldReseal"`
	FailMessage  string `json:"failMessage"`
}

// PreparedVaultUnseal holds validated envelope components and ordered AEAD attempts.
type PreparedVaultUnseal struct {
	OK        bool                 `json:"ok"`
	CleanKey  string               `json:"cleanKey,omitempty"`
	SaltB64   string               `json:"saltB64,omitempty"`
	IVB64     string               `json:"ivB64,omitempty"`
	CTB64     string               `json:"ctB64,omitempty"`
	SaltBytes []byte               `json:"-"`
	IVBytes   []byte               `json:"-"`
	CTBytes   []byte               `json:"-"`
	Attempts  []VaultUnsealAttempt `json:"attempts,omitempty"`
	Error     string               `json:"error,omitempty"`
	Message   string               `json:"message,omitempty"`
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

// BuildPerUserOriginHKDFInfo returns the length-prefixed HKDF-SHA256 info string for a user/origin/purpose tuple.
func BuildPerUserOriginHKDFInfo(userID, remoteOrigin, purpose string) string {
	originLower := strings.ToLower(remoteOrigin)
	scopedPair := fmt.Sprintf("%d:%s|%d:%s", utf16Len(userID), userID, utf16Len(originLower), originLower)
	if purpose != "" {
		return "edgefetch-mcp-vault-v1:" + purpose + ":" + scopedPair
	}
	return "edgefetch-mcp-vault-v1:" + scopedPair
}

func buildLegacyV270HKDFInfo(userID, remoteOrigin string) string {
	return "edgefetch-mcp-vault-v1:" + userID + ":" + strings.ToLower(remoteOrigin)
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

func resolveRowIDOption(id, serverID *string) string {
	if id != nil {
		return strings.TrimSpace(*id)
	}
	if serverID != nil {
		return strings.TrimSpace(*serverID)
	}
	return ""
}

// PrepareSealVaultEnvelope validates parameters and constructs the canonical HKDF info, AAD, and JSON plaintext.
func PrepareSealVaultEnvelope(params SealVaultParams) PreparedVaultSeal {
	cleanKey, ok, keyMsg := ValidateVaultMasterKey(params.VaultMasterKey)
	if !ok {
		return PreparedVaultSeal{
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
		return PreparedVaultSeal{
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
		return PreparedVaultSeal{OK: false, Status: 400, Error: "invalid_slug", Message: err.Error()}
	}
	secVer := 1
	if hasRowBinding {
		secVer = 2
	}
	return PreparedVaultSeal{
		OK:              true,
		CleanKey:        cleanKey,
		HKDFInfo:        BuildPerUserOriginHKDFInfo(params.UserID, canonicalOrigin, VaultCredentialsPurposeV2),
		AAD:             string(aad),
		Plaintext:       string(plaintext),
		EnvelopeVersion: envelopeVersion,
		SecretVersion:   secVer,
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

// PrepareUnsealVaultEnvelope validates envelope headers, P6/M8 downgrade rules, and builds ordered AEAD attempts.
func PrepareUnsealVaultEnvelope(params UnsealVaultParams) PreparedVaultUnseal {
	cleanKey, ok, keyMsg := ValidateVaultMasterKey(params.VaultMasterKey)
	if !ok {
		return PreparedVaultUnseal{
			OK:      false,
			Error:   "vault_master_key_unconfigured",
			Message: keyMsg,
		}
	}

	ver, saltB64, ivB64, ctB64, hdrOk := parseEnvelopeHeader(params.Ciphertext)
	if !hdrOk {
		return PreparedVaultUnseal{OK: false, Error: "vault_decryption_failed", Message: "Malformed vault ciphertext envelope"}
	}
	salt, sOk := decodeBase64URL(saltB64)
	iv, iOk := decodeBase64URL(ivB64)
	ct, cOk := decodeBase64URL(ctB64)
	if !sOk || len(salt) != 16 || !iOk || len(iv) != 12 || !cOk || len(ct) < 17 {
		return PreparedVaultUnseal{OK: false, Error: "vault_decryption_failed", Message: "Invalid vault IV or authentication tag length"}
	}

	canonicalOrigin := strings.ToLower(strings.TrimSpace(params.RemoteOrigin))
	if params.RemoteOrigin != canonicalOrigin {
		return PreparedVaultUnseal{OK: false, Error: "vault_decryption_failed", Message: "Non-canonical origin supplied to vault decryption"}
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
		return PreparedVaultUnseal{OK: false, Error: "vault_decryption_failed", Message: fmt.Sprintf("Unsupported vault secret_version %d", *params.SecretVersion)}
	}
	if params.SecretVersion != nil && *params.SecretVersion >= 2 {
		if ver != "v2" {
			return PreparedVaultUnseal{OK: false, Error: "vault_decryption_failed", Message: "Vault downgrade blocked: secret_version >= 2 requires a v2 ciphertext envelope"}
		}
		if !hasFullRowBinding {
			return PreparedVaultUnseal{OK: false, Error: "vault_decryption_failed", Message: "Vault v2 row-bound decryption requires id, slug, and authType"}
		}
	} else if hasAnyRowParam && !hasFullRowBinding {
		return PreparedVaultUnseal{OK: false, Error: "vault_decryption_failed", Message: "Incomplete row binding attributes supplied to vault decryption"}
	}

	var attempts []VaultUnsealAttempt
	if ver == "v2" {
		infoV2 := BuildPerUserOriginHKDFInfo(params.UserID, canonicalOrigin, VaultCredentialsPurposeV2)
		if hasFullRowBinding {
			aad5 := string(buildVaultV2RowBoundAAD(ver, params.UserID, canonicalOrigin, rowID, rowSlug, rowAuthType))
			attempts = append(attempts, VaultUnsealAttempt{
				HKDFInfo:     infoV2,
				AAD:          aad5,
				ShouldReseal: false,
				FailMessage:  "AES-256-GCM authentication failed (wrong user_id, tampered id/slug/auth_type/origin, or rotated VAULT_MASTER_KEY)",
			})
			if params.SecretVersion == nil || *params.SecretVersion < 2 {
				aad2 := string(buildVaultV2OriginBoundAAD(ver, params.UserID, canonicalOrigin))
				attempts = append(attempts, VaultUnsealAttempt{
					HKDFInfo:     infoV2,
					AAD:          aad2,
					ShouldReseal: true,
					FailMessage:  "AES-256-GCM authentication failed (wrong user_id, tampered id/slug/auth_type/origin, or rotated VAULT_MASTER_KEY)",
				})
			}
		} else {
			aad2 := string(buildVaultV2OriginBoundAAD(ver, params.UserID, canonicalOrigin))
			attempts = append(attempts, VaultUnsealAttempt{
				HKDFInfo:     infoV2,
				AAD:          aad2,
				ShouldReseal: false,
				FailMessage:  "AES-256-GCM authentication failed (wrong user_id, tampered origin/purpose, or rotated VAULT_MASTER_KEY)",
			})
		}
	} else {
		infoV1 := BuildPerUserOriginHKDFInfo(params.UserID, canonicalOrigin, "")
		aadV1 := fmt.Sprintf("%d:%s|%d:%s", utf16Len(params.UserID), params.UserID, utf16Len(canonicalOrigin), canonicalOrigin)
		attempts = append(attempts, VaultUnsealAttempt{
			HKDFInfo:     infoV1,
			AAD:          aadV1,
			ShouldReseal: true,
			FailMessage:  "AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)",
		})
		if !strings.Contains(params.UserID, "|") && !strings.Contains(params.UserID, ":") {
			attempts = append(attempts, VaultUnsealAttempt{
				HKDFInfo:     buildLegacyV270HKDFInfo(params.UserID, canonicalOrigin),
				AAD:          params.UserID + "|" + canonicalOrigin,
				ShouldReseal: true,
				FailMessage:  "AES-256-GCM authentication failed (wrong user_id, tampered origin, or rotated VAULT_MASTER_KEY)",
			})
		}
	}

	return PreparedVaultUnseal{
		OK:        true,
		CleanKey:  cleanKey,
		SaltB64:   saltB64,
		IVB64:     ivB64,
		CTB64:     ctB64,
		SaltBytes: salt,
		IVBytes:   iv,
		CTBytes:   ct,
		Attempts:  attempts,
	}
}

// VerifyUnsealedVaultPlaintext validates decrypted JSON credentials against pinned origin, URL, purpose, and row bindings.
func VerifyUnsealedVaultPlaintext(params UnsealVaultParams, plainBuf []byte, attemptShouldReseal bool) UnsealVaultResult {
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
	hasFullRowBinding := rowID != "" && rowSlug != "" && rowAuthType != ""

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

	needsReseal := attemptShouldReseal || (params.SecretVersion != nil && *params.SecretVersion < 2 && hasFullRowBinding)
	return UnsealVaultResult{
		OK:          true,
		Payload:     rawParsed,
		NeedsReseal: needsReseal,
	}
}

// PreparePKCEStateSeal builds the canonical HKDF info, AAD, and JSON plaintext for pkce2 state blobs.
func PreparePKCEStateSeal(userID, remoteOrigin string, blob OrderedObject) (hkdfInfo, aad, plaintext string, err error) {
	canonicalOrigin := strings.ToLower(strings.TrimSpace(remoteOrigin))
	hkdfInfo = BuildPerUserOriginHKDFInfo(userID, canonicalOrigin, VaultPKCEStatePurposeV2)
	aad = fmt.Sprintf(
		"pkce2|mcp_oauth_states:pkce|%d:%s|%d:%s",
		utf16Len(userID), userID,
		utf16Len(canonicalOrigin), canonicalOrigin,
	)
	inner := blob.Clone()
	inner.Set("purpose", "mcp_oauth_states:pkce")
	plain, mErr := MarshalUnescapedJSON(inner)
	if mErr != nil {
		return "", "", "", mErr
	}
	return hkdfInfo, aad, string(plain), nil
}

// PreparePKCEStateUnseal validates a pkce2 ciphertext header and returns HKDF info, AAD, and decoded byte slices.
func PreparePKCEStateUnseal(userID, remoteOrigin, ciphertext string) (hkdfInfo, aad, saltB64, ivB64, ctB64 string, salt, iv, ct []byte, ok bool) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 4 || parts[0] != "pkce2" {
		return "", "", "", "", "", nil, nil, nil, false
	}
	salt, sOk := decodeBase64URL(parts[1])
	iv, iOk := decodeBase64URL(parts[2])
	ct, cOk := decodeBase64URL(parts[3])
	if !sOk || len(salt) != 16 || !iOk || len(iv) != 12 || !cOk || len(ct) < 17 {
		return "", "", "", "", "", nil, nil, nil, false
	}
	canonicalOrigin := strings.ToLower(strings.TrimSpace(remoteOrigin))
	hkdfInfo = BuildPerUserOriginHKDFInfo(userID, canonicalOrigin, VaultPKCEStatePurposeV2)
	aad = fmt.Sprintf(
		"%s|mcp_oauth_states:pkce|%d:%s|%d:%s",
		parts[0],
		utf16Len(userID), userID,
		utf16Len(canonicalOrigin), canonicalOrigin,
	)
	return hkdfInfo, aad, parts[1], parts[2], parts[3], salt, iv, ct, true
}

// VerifyPKCEStatePlaintext validates decrypted pkce2 state JSON.
func VerifyPKCEStatePlaintext(plain []byte) (OrderedObject, bool) {
	if !utf8.Valid(plain) {
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

// BuildOAuthBindMACInputs returns the canonical HMAC-SHA256 key and message strings for MCP OAuth bind cookies.
func BuildOAuthBindMACInputs(vaultMasterKey, userID, state, sessionCSRF string) (macKey, macMessage string) {
	return "edgefetch-mcp-oauth-bind:" + vaultMasterKey, userID + "|" + state + "|" + sessionCSRF
}

// BuildPKCEAuthorizationInit constructs the PKCE OrderedObject state blob and RFC 7636 S256 authorization URL.
func BuildPKCEAuthorizationInit(
	authorizationEndpoint, tokenEndpoint, clientID, clientSecret, redirectURI, scope string,
	scopesSupported []string,
	resource, confirmedAuthOrigin, issuer, codeVerifier, codeChallenge, state string,
) (blob OrderedObject, authorizationURL string, err error) {
	blob = OrderedObject{
		{Key: "codeVerifier", Value: codeVerifier},
	}
	if issuer != "" {
		blob.Set("issuer", issuer)
	}
	blob.Set("tokenEndpoint", tokenEndpoint)
	if confirmedAuthOrigin != "" {
		blob.Set("confirmedAuthOrigin", confirmedAuthOrigin)
	}
	blob.Set("clientId", clientID)
	if clientSecret != "" {
		blob.Set("clientSecret", clientSecret)
	}
	blob.Set("redirectUri", redirectURI)
	blob.Set("resource", resource)

	authURL, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return nil, "", err
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	effectiveScope := strings.TrimSpace(scope)
	if effectiveScope == "" && len(scopesSupported) > 0 {
		effectiveScope = strings.Join(scopesSupported, " ")
	}
	if effectiveScope != "" {
		q.Set("scope", effectiveScope)
	}
	q.Set("resource", resource)
	authURL.RawQuery = q.Encode()
	return blob, authURL.String(), nil
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
