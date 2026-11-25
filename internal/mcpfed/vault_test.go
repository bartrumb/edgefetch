//go:build !wasip1

package mcpfed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const testMasterKey = "ef_phase2_vault_master_key_32chars_minimum_ok"

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }

func buildWebCryptoEquivalentCiphertext(
	t *testing.T,
	masterKey, version, purpose, userID, origin, aadStr string,
	salt, iv []byte,
	innerJSON string,
) string {
	t.Helper()
	var info string
	scoped := "7:" + userID + "|22:" + origin
	if version == "v270" {
		info = "edgefetch-mcp-vault-v1:" + userID + ":" + origin
		version = "v1"
	} else if purpose != "" {
		info = "edgefetch-mcp-vault-v1:" + purpose + ":" + scoped
	} else {
		info = "edgefetch-mcp-vault-v1:" + scoped
	}
	key, err := hkdf.Key(sha256.New, []byte(masterKey), salt, info, 32)
	if err != nil {
		t.Fatalf("hkdf.Key: %v", err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	ct := gcm.Seal(nil, iv, []byte(innerJSON), []byte(aadStr))
	enc := base64.RawURLEncoding.EncodeToString
	return version + "." + enc(salt) + "." + enc(iv) + "." + enc(ct)
}

func TestVaultV2CrossVectorSealUnsealAndDowngradePrevention(t *testing.T) {
	// 1. Master key validation fails closed when < 24 chars
	if _, ok, _ := ValidateVaultMasterKey("short-key"); ok {
		t.Fatal("expected short master key to be rejected")
	}
	badSeal := SealVaultCredentials(SealVaultParams{
		VaultMasterKey: "short",
		UserID:         "gh_1001",
		RemoteOrigin:   "https://mcp.linear.app",
		Payload:        OrderedObject{{Key: "kind", Value: "headers"}},
	})
	if badSeal.OK || badSeal.Status != 503 || badSeal.Error != "vault_master_key_unconfigured" {
		t.Fatalf("unexpected short key seal result: %+v", badSeal)
	}

	// 2. Deterministic cross-vector verification against exact WebCrypto HKDF-SHA256 + AES-256-GCM formula
	fixedSalt := []byte("0123456789abcdef")
	fixedIV := []byte("fedcba987654")
	aad5 := "v2|user_mcp_servers:credentials|7:gh_1001|22:https://mcp.linear.app|13:mcp_row_alpha|11:linear-prod|7:headers"
	innerV2 := `{"kind":"headers","pinnedOrigin":"https://mcp.linear.app","pinnedUrl":"https://mcp.linear.app/mcp","purpose":"user_mcp_servers:credentials","serverId":"mcp_row_alpha","slug":"linear-prod","authType":"headers","headers":{"Authorization":"Bearer lin_v2_secret_token"}}`
	vecV2 := buildWebCryptoEquivalentCiphertext(
		t, testMasterKey, "v2", "user_mcp_servers:credentials:v2",
		"gh_1001", "https://mcp.linear.app", aad5, fixedSalt, fixedIV, innerV2,
	)

	unsealedVec := UnsealVaultCredentials(UnsealVaultParams{
		VaultMasterKey: testMasterKey,
		UserID:         "gh_1001",
		RemoteOrigin:   "https://mcp.linear.app",
		RemoteURL:      "https://mcp.linear.app/mcp",
		ID:             strPtr("mcp_row_alpha"),
		Slug:           strPtr("linear-prod"),
		AuthType:       strPtr("headers"),
		SecretVersion:  intPtr(2),
		Ciphertext:     vecV2,
	})
	if !unsealedVec.OK {
		t.Fatalf("cross-vector v2 unseal failed: %+v", unsealedVec)
	}
	if unsealedVec.ResealedCiphertext != "" {
		t.Fatalf("native v2 5-field AAD row must not trigger reseal, got %q", unsealedVec.ResealedCiphertext)
	}
	hdrsObj, _ := unsealedVec.Payload.GetObject("headers")
	if got, _ := hdrsObj.GetString("Authorization"); got != "Bearer lin_v2_secret_token" {
		t.Fatalf("unexpected Authorization header: %q", got)
	}

	// 3. Seal -> Unseal round-trip with fresh random salt & IV
	s1 := SealVaultCredentials(SealVaultParams{
		VaultMasterKey: testMasterKey,
		UserID:         "gh_1001",
		RemoteOrigin:   "https://mcp.linear.app",
		ID:             strPtr("mcp_row_alpha"),
		Slug:           strPtr("linear-prod"),
		AuthType:       strPtr("headers"),
		Payload: OrderedObject{
			{Key: "kind", Value: "headers"},
			{Key: "pinnedOrigin", Value: "https://mcp.linear.app"},
			{Key: "pinnedUrl", Value: "https://mcp.linear.app/mcp"},
			{Key: "headers", Value: OrderedObject{{Key: "Authorization", Value: "Bearer tok_1"}}},
		},
	})
	s2 := SealVaultCredentials(SealVaultParams{
		VaultMasterKey: testMasterKey,
		UserID:         "gh_1001",
		RemoteOrigin:   "https://mcp.linear.app",
		ID:             strPtr("mcp_row_alpha"),
		Slug:           strPtr("linear-prod"),
		AuthType:       strPtr("headers"),
		Payload: OrderedObject{
			{Key: "kind", Value: "headers"},
			{Key: "pinnedOrigin", Value: "https://mcp.linear.app"},
			{Key: "headers", Value: OrderedObject{{Key: "Authorization", Value: "Bearer tok_1"}}},
		},
	})
	if !s1.OK || !s2.OK || s1.SecretVersion != 2 || s1.Ciphertext == s2.Ciphertext || !strings.HasPrefix(s1.Ciphertext, "v2.") {
		t.Fatalf("unexpected seal results: s1=%+v s2=%+v", s1, s2)
	}

	// 4. Column-swap, separator-swap, version-swap, future secretVersion, and path-swap attacks MUST all fail closed (P6 & M8)
	for _, tc := range []struct {
		name   string
		params UnsealVaultParams
	}{
		{
			name: "swapped userId",
			params: UnsealVaultParams{
				VaultMasterKey: testMasterKey, UserID: "gh_2002", RemoteOrigin: "https://mcp.linear.app",
				ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(2), Ciphertext: s1.Ciphertext,
			},
		},
		{
			name: "swapped id",
			params: UnsealVaultParams{
				VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app",
				ID: strPtr("mcp_row_beta"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(2), Ciphertext: s1.Ciphertext,
			},
		},
		{
			name: "swapped slug",
			params: UnsealVaultParams{
				VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app",
				ID: strPtr("mcp_row_alpha"), Slug: strPtr("evil-slug"), AuthType: strPtr("headers"), SecretVersion: intPtr(2), Ciphertext: s1.Ciphertext,
			},
		},
		{
			name: "swapped authType",
			params: UnsealVaultParams{
				VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app",
				ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("oauth2"), SecretVersion: intPtr(2), Ciphertext: s1.Ciphertext,
			},
		},
		{
			name: "swapped remoteUrl path",
			params: UnsealVaultParams{
				VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app", RemoteURL: "https://mcp.linear.app/evil",
				ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(2), Ciphertext: s1.Ciphertext,
			},
		},
		{
			name: "non-canonical uppercase origin",
			params: UnsealVaultParams{
				VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://MCP.Linear.App",
				ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(2), Ciphertext: s1.Ciphertext,
			},
		},
		{
			name: "colon header tamper v2:",
			params: UnsealVaultParams{
				VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app",
				ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(2), Ciphertext: "v2:" + s1.Ciphertext[3:],
			},
		},
		{
			name: "future secretVersion=3 rejected",
			params: UnsealVaultParams{
				VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app",
				ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(3), Ciphertext: s1.Ciphertext,
			},
		},
	} {
		res := UnsealVaultCredentials(tc.params)
		if res.OK {
			t.Fatalf("%s: expected unseal failure, got OK", tc.name)
		}
	}

	// 5. Legacy v1 length-prefixed & v2.7.0 fallback auto-reseal when secretVersion=1, but BLOCKED when secretVersion=2!
	v1AAD := "7:gh_1001|22:https://mcp.linear.app"
	v1Inner := `{"kind":"headers","pinnedOrigin":"https://mcp.linear.app","headers":{"Authorization":"Bearer legacy_v1_tok"}}`
	v1Ct := buildWebCryptoEquivalentCiphertext(t, testMasterKey, "v1", "", "gh_1001", "https://mcp.linear.app", v1AAD, fixedSalt, fixedIV, v1Inner)

	downgradeRes := UnsealVaultCredentials(UnsealVaultParams{
		VaultMasterKey: testMasterKey,
		UserID:         "gh_1001",
		RemoteOrigin:   "https://mcp.linear.app",
		ID:             strPtr("mcp_row_alpha"),
		Slug:           strPtr("linear-prod"),
		AuthType:       strPtr("headers"),
		SecretVersion:  intPtr(2),
		Ciphertext:     v1Ct,
	})
	if downgradeRes.OK || !strings.Contains(strings.ToLower(downgradeRes.Message), "downgrade blocked") {
		t.Fatalf("expected v1 downgrade block on secretVersion=2, got %+v", downgradeRes)
	}

	upgradeRes := UnsealVaultCredentials(UnsealVaultParams{
		VaultMasterKey: testMasterKey,
		UserID:         "gh_1001",
		RemoteOrigin:   "https://mcp.linear.app",
		ID:             strPtr("mcp_row_alpha"),
		Slug:           strPtr("linear-prod"),
		AuthType:       strPtr("headers"),
		SecretVersion:  intPtr(1),
		Ciphertext:     v1Ct,
	})
	if !upgradeRes.OK || !strings.HasPrefix(upgradeRes.ResealedCiphertext, "v2.") || upgradeRes.ResealedSecretVersion == nil || *upgradeRes.ResealedSecretVersion != 2 {
		t.Fatalf("expected v1 auto-reseal to v2 secretVersion=2, got %+v", upgradeRes)
	}

	// Legacy v2.7.0 fallback works for clean userId, refused when userId contains ':' or '|'
	v270Ct := buildWebCryptoEquivalentCiphertext(t, testMasterKey, "v270", "", "gh_1001", "https://mcp.linear.app", "gh_1001|https://mcp.linear.app", fixedSalt, fixedIV, v1Inner)
	v270Ok := UnsealVaultCredentials(UnsealVaultParams{
		VaultMasterKey: testMasterKey,
		UserID:         "gh_1001",
		RemoteOrigin:   "https://mcp.linear.app",
		Ciphertext:     v270Ct,
	})
	if !v270Ok.OK || !strings.HasPrefix(v270Ok.ResealedCiphertext, "v2.") {
		t.Fatalf("expected v2.7.0 fallback to decrypt and reseal, got %+v", v270Ok)
	}
}

func TestPKCEBlobHMACAndValidationHelpers(t *testing.T) {
	pkceCt, err := SealPKCEStateBlob(testMasterKey, "gh_1001", "https://mcp.acme.example", OrderedObject{
		{Key: "codeVerifier", Value: "verifier_1234567890_abcdefghijklmnopqrstuvwxyz"},
		{Key: "tokenEndpoint", Value: "https://auth.acme.example/token"},
		{Key: "clientId", Value: "cli_1"},
	})
	if err != nil || !strings.HasPrefix(pkceCt, "pkce2.") {
		t.Fatalf("SealPKCEStateBlob failed: ct=%q err=%v", pkceCt, err)
	}
	blob, ok := UnsealPKCEStateBlob(testMasterKey, "gh_1001", "https://mcp.acme.example", pkceCt)
	if !ok {
		t.Fatal("expected UnsealPKCEStateBlob to succeed")
	}
	if cv, _ := blob.GetString("codeVerifier"); cv != "verifier_1234567890_abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("unexpected codeVerifier: %q", cv)
	}
	if _, crossOk := UnsealPKCEStateBlob(testMasterKey, "gh_2002", "https://mcp.acme.example", pkceCt); crossOk {
		t.Fatal("cross-user PKCE unseal must fail")
	}

	sig := ComputeMCPOAuthBindHMAC(testMasterKey, "gh_1001", "st_1", "csrf_1")
	if !VerifyMCPOAuthBindHMAC(sig, testMasterKey, "gh_1001", "st_1", "csrf_1") {
		t.Fatal("expected valid OAuth bind HMAC to verify")
	}
	if VerifyMCPOAuthBindHMAC(sig, testMasterKey, "gh_2002", "st_1", "csrf_1") {
		t.Fatal("expected cross-user OAuth bind HMAC to fail")
	}

	// Identifier, slug, allowedMcpTools, and header hygiene
	if !IsSafeMCPIdentifier("search_issues.v1-read") || IsSafeMCPIdentifier("bad__tool") || IsSafeMCPIdentifier("ignore_all_instructions") {
		t.Fatal("unexpected IsSafeMCPIdentifier outcome")
	}
	if NormalizeMCPConnectorSlug("io.github.org/my__custom___mcp") != "my-custom-mcp" {
		t.Fatalf("unexpected slug normalization: %q", NormalizeMCPConnectorSlug("io.github.org/my__custom___mcp"))
	}
	allowed, ok, _, _ := ParseAllowedMCPTools(json.RawMessage(`["notes/create_note","linear-prod/update_issue"]`))
	if !ok || len(allowed) != 2 {
		t.Fatalf("expected valid allowedMcpTools, got ok=%v allowed=%v", ok, allowed)
	}
	for _, bad := range []string{`["create_note"]`, `["notes/*"]`, `["bad__slug/t"]`, `["Notes/create"]`} {
		if _, ok, _, _ := ParseAllowedMCPTools(json.RawMessage(bad)); ok {
			t.Fatalf("expected invalid allowedMcpTools %s to fail", bad)
		}
	}
	for _, badHdr := range []string{`{"Cookie":"sid=1"}`, `{"X-Forwarded-For":"127.0.0.1"}`, `{"a":"1","A":"2"}`, `{"X":"a\u000bb"}`} {
		if _, ok, _ := SanitizeSecretHeadersInput(nil, json.RawMessage(badHdr), true); ok {
			t.Fatalf("expected bad secret header %s to fail", badHdr)
		}
	}
}

func TestVaultCrossImplKnownAnswerVectors(t *testing.T) {
	// Shared Known-Answer Test (KAT) vectors mirrored byte-for-byte in `hub/test/mcp-federation.test.ts`
	// (`masterKey = testMasterKey`, `salt = "0123456789abcdef"`, `iv = "fedcba987654"`):
	const (
		katV2FiveField  = "v2.MDEyMzQ1Njc4OWFiY2RlZg.ZmVkY2JhOTg3NjU0.ThW41skD9EZIY8WR3mTcg46ojnbEPhpj8oty1o3nH-_Wh3oeNwSzpG0TibQHDiLvZlfAjJ3aYrNsS7UB7ctAsw2Xi_kBSyUD06Sx7SYl4JONM0PIFWSL6Th84zYm5CoS0wzn9Q2QdOHKKVXDWAj0kL0t9pzPYJzWmxMd7PIQS2a3SBkyIQQnikvfVVAQlnkNRoEyWCBt7rVClAA836bcBZ_XYeLb5GjtV5bY7Rs_rc-orq-LIB5XglX94A9Xxk50oIRij-YgN1O_zSZScgULalXaoSj4GtU6tr7wRglsRcl83ZlSR41qkvOv0TKg7H3t9Qevj7yLKcT_YlrdnUh_EREFBgKYxn23U0K5biWK-MHe9JkXtGe6WH0C"
		katV2TwoField   = "v2.MDEyMzQ1Njc4OWFiY2RlZg.ZmVkY2JhOTg3NjU0.ThW41skD9EZIY8WR3mTcg46ojnbEPhpj8oty1o3nH-_Wh3oeNwSzpG0TibQHDiLvZlfAjJ3aYrNsS7UZ4cRKsxux269YU0Ye07iu7HVwroqHLAOGRiis7Ssg5zR2py4f_Fj5iFeTfODDP3mVDRj0rOR77obPeYnEilhIoKVZDFaNRAgnDFcukVPlURF1hm4LUIEocz1j6aMOyzkikw68edDbz1BfN8GPHWk"
		katV1LengthPref = "v1.MDEyMzQ1Njc4OWFiY2RlZg.ZmVkY2JhOTg3NjU0.5GO5JdzXAJINsO2v72Vpm5RHB3VmYjKaYz__olQEXSutfgJqLIHNJBtH--1vA001U-pypOEBscqX1UBzKYDRlG4BJh87Dyfl7IQZ-7fa5th3T3sjdaLRybYckqGn5zUjifA84B_qiiT0eQvDq5wb65dBreGsK9G3KptPSys"
		katV270Legacy   = "v1.MDEyMzQ1Njc4OWFiY2RlZg.ZmVkY2JhOTg3NjU0.3xPoth6GY96_i-hybHp46TVh82W5J1XAtNR9M3tGIeeR20k62QZ2z8Jtp576fkjqtJCeCZmYTB0d6OSRsSq8T_UtGLE0DH1KuoE9iTcqhlpJvKl8l_ZF8Yis7mZ5eBAtV8ZhibQnmFZCufTJ51929BpA_qzdqFJvfZvUMg0"
		katPKCE2        = "pkce2.MDEyMzQ1Njc4OWFiY2RlZg.ZmVkY2JhOTg3NjU0.rIWg0dVMH4e26w-GR4-YcTbPInQjS7GJ9_DidnaKtcflpWRI5VQD1NsOhP4ut8ICUYIsKwFBkn60l4pAoyFNNUFIMwH-aWwUEH9wXhvUUpphInkveed1oaAsaXfVWN6rF83KkdcX6GwFYuM3sDPYO75cHLjs98wEVbTfXIDIF6J30KVc5-_kse72aX5WvNyIXwkceBBe4JOGdpudCPF1cru443o2NatN9-d9Qe6KzGsppm-T029CyFfPaC71UymyLbVY-01b5N6DqSM8Cd4ue2Ep9ZChBXbQGbrG_iEZ7U5mrFD_9C87Nl2zludfFyW4Haac9o-5VBtr9NO0Hjc7AShu0lPjwdZ5SFFyANtMY91d3TQPCRLOl7BlqOgIQvh3eoIgMjHIHdOFEABUONi9-OSXglnDkoai2bA4wn84QLl67lanpa85QkKTx3qNspkJJTAcqew"
		katBindHMAC     = "y-yn6kpxWI0KrlHLiKia91MfSooumt-wbb79IbRSQ5g"
	)

	fixedSalt := []byte("0123456789abcdef")
	fixedIV := []byte("fedcba987654")

	// 1. Native Go PrepareSealVaultEnvelope + HKDF + AES-GCM produces the exact KAT v2 5-field ciphertext
	prep := PrepareSealVaultEnvelope(SealVaultParams{
		VaultMasterKey: testMasterKey,
		UserID:         "gh_1001",
		RemoteOrigin:   "https://mcp.linear.app",
		ID:             strPtr("mcp_row_alpha"),
		Slug:           strPtr("linear-prod"),
		AuthType:       strPtr("headers"),
		Payload: OrderedObject{
			{Key: "kind", Value: "headers"},
			{Key: "pinnedOrigin", Value: "https://mcp.linear.app"},
			{Key: "pinnedUrl", Value: "https://mcp.linear.app/mcp"},
			{Key: "headers", Value: OrderedObject{{Key: "Authorization", Value: "Bearer lin_v2_secret_token"}}},
		},
	})
	if !prep.OK {
		t.Fatalf("PrepareSealVaultEnvelope failed: %+v", prep)
	}
	aesKey, err := hkdf.Key(sha256.New, []byte(prep.CleanKey), fixedSalt, prep.HKDFInfo, 32)
	if err != nil {
		t.Fatalf("hkdf.Key: %v", err)
	}
	ctBytes, err := aes256GCMSeal(aesKey, fixedIV, []byte(prep.Plaintext), []byte(prep.AAD))
	if err != nil {
		t.Fatalf("aes256GCMSeal: %v", err)
	}
	goSealedV2 := prep.EnvelopeVersion + "." + encodeBase64URL(fixedSalt) + "." + encodeBase64URL(fixedIV) + "." + encodeBase64URL(ctBytes)
	if goSealedV2 != katV2FiveField {
		t.Fatalf("Go fixed-nonce seal mismatch:\n got: %s\nwant: %s", goSealedV2, katV2FiveField)
	}

	// 2. Native Go UnsealVaultCredentials opens WebCrypto KAT vectors (v2 5-field, v2 2-field, v1, v2.7.0)
	//    and enforces P6/M8 version-downgrade rejection when SecretVersion=2!
	u5 := UnsealVaultCredentials(UnsealVaultParams{
		VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app", RemoteURL: "https://mcp.linear.app/mcp",
		ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(2), Ciphertext: katV2FiveField,
	})
	if !u5.OK || u5.ResealedCiphertext != "" {
		t.Fatalf("expected katV2FiveField to unseal without reseal: %+v", u5)
	}

	for _, legacyTC := range []struct {
		name string
		ct   string
	}{
		{"v2_2field", katV2TwoField},
		{"v1_len_prefixed", katV1LengthPref},
		{"v270_legacy", katV270Legacy},
	} {
		// Downgrade to legacy ciphertext on a row already at SecretVersion=2 MUST fail closed (P6/M8)!
		down := UnsealVaultCredentials(UnsealVaultParams{
			VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app",
			ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(2), Ciphertext: legacyTC.ct,
		})
		if down.OK {
			t.Fatalf("%s: expected P6/M8 downgrade rejection when SecretVersion=2", legacyTC.name)
		}
		// Pre-v2 row (SecretVersion=1) MUST decrypt and auto-reseal to v2 SecretVersion=2!
		up := UnsealVaultCredentials(UnsealVaultParams{
			VaultMasterKey: testMasterKey, UserID: "gh_1001", RemoteOrigin: "https://mcp.linear.app",
			ID: strPtr("mcp_row_alpha"), Slug: strPtr("linear-prod"), AuthType: strPtr("headers"), SecretVersion: intPtr(1), Ciphertext: legacyTC.ct,
		})
		if !up.OK || !strings.HasPrefix(up.ResealedCiphertext, "v2.") || up.ResealedSecretVersion == nil || *up.ResealedSecretVersion != 2 {
			t.Fatalf("%s: expected SecretVersion=1 legacy row to decrypt and auto-reseal, got %+v", legacyTC.name, up)
		}
	}

	// 3. PKCE2 & OAuth Bind HMAC KAT verification
	pkceObj, pkceOK := UnsealPKCEStateBlob(testMasterKey, "gh_1001", "https://mcp.acme.example", katPKCE2)
	if !pkceOK {
		t.Fatal("expected UnsealPKCEStateBlob on katPKCE2 to succeed")
	}
	if cv, _ := pkceObj.GetString("codeVerifier"); cv != "verifier_1234567890_abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("unexpected katPKCE2 codeVerifier: %q", cv)
	}
	if gotHMAC := ComputeMCPOAuthBindHMAC(testMasterKey, "gh_1001", "st_1", "csrf_1"); gotHMAC != katBindHMAC {
		t.Fatalf("ComputeMCPOAuthBindHMAC mismatch: got %q want %q", gotHMAC, katBindHMAC)
	}
	if !VerifyMCPOAuthBindHMAC(katBindHMAC, testMasterKey, "gh_1001", "st_1", "csrf_1") {
		t.Fatal("expected VerifyMCPOAuthBindHMAC on katBindHMAC to succeed")
	}
}
