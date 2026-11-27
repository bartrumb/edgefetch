//go:build !wasip1

package mcpfed

import (
	"strings"
	"testing"
)

func TestHubSecretBuildersBindScopeAndName(t *testing.T) {
	if got, want := BuildHubSecretHKDFInfo("SERPER_API_KEY"), "edgefetch-hub-secrets-v1:hub_secrets:value:v1:3:hub|14:SERPER_API_KEY"; got != want {
		t.Fatalf("info = %q, want %q", got, want)
	}
	if got, want := BuildHubSecretAAD("hs1", "SERPER_API_KEY"), "hs1|hub_secrets:value|3:hub|14:SERPER_API_KEY"; got != want {
		t.Fatalf("aad = %q, want %q", got, want)
	}
	if BuildHubSecretAAD("hs1", "BRAVE_API_KEY") == BuildHubSecretAAD("hs1", "TAVILY_API_KEY") {
		t.Fatal("AAD must differ per name")
	}
	if BuildHubSecretHKDFInfo("OPENAI_API_KEY") == BuildHubSecretHKDFInfo("GEMINI_API_KEY") {
		t.Fatal("HKDF info must differ per name")
	}
}

func TestHubSecretNameClassification(t *testing.T) {
	for _, n := range []string{"SERPER_API_KEY", "GOOGLE_MAPS_API_KEY", "CLOUDFLARE_WEBSEARCH_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"} {
		if ClassifyHubSecretName(n) != "managed" {
			t.Fatalf("%s should be managed", n)
		}
	}
	for _, n := range []string{"CALLER_TOKEN", "VAULT_MASTER_KEY", "SESSION_SECRET", "AGENT_TOKENS", "BOT_SIGNING_PRIVATE_KEY"} {
		if ClassifyHubSecretName(n) != "bootstrap" {
			t.Fatalf("%s should be bootstrap", n)
		}
		if _, err := ValidateHubSecretName(n); err == nil || err.Error != "bootstrap_secret_readonly" || err.Status != 403 {
			t.Fatalf("%s must be rejected as bootstrap, got %+v", n, err)
		}
	}
	for _, n := range []string{"", "serper_api_key", "PATH", "SERPER_API_KEY2"} {
		if _, err := ValidateHubSecretName(n); err == nil || err.Error != "unknown_secret_name" {
			t.Fatalf("%q must be unknown, got %+v", n, err)
		}
	}
	for _, n := range HubManagedSecretNames() {
		if ClassifyHubSecretName(n) != "managed" {
			t.Fatalf("catalog drift: %s", n)
		}
	}
	for _, n := range HubPlainConfigNames() {
		if ClassifyHubSecretName(n) != "managed" {
			t.Fatalf("plain config %s must be managed", n)
		}
	}
	if IsHubPlainConfigName("CLOUDFLARE_WEBSEARCH_API_TOKEN") || IsHubPlainConfigName("CLOUDFLARE_ACCOUNT_ID") || !IsHubPlainConfigName("CLOUDFLARE_WEBSEARCH_PROVIDER") {
		t.Fatal("plain-config classification wrong")
	}
}

func TestNormalizeHubSecretValue(t *testing.T) {
	ok := []struct{ name, in, want string }{
		{"SERPER_API_KEY", "  abc123  ", "abc123"},
		{"SEARXNG_URL", "https://search.example.com/", "https://search.example.com/"},
		{"SEARXNG_URL", "http://localhost:8080", "http://localhost:8080"},
		{"OLLAMA_HOST", "http://127.0.0.1:11434", "http://127.0.0.1:11434"},
		{"EDGEFETCH_LLM_BASE_URL", "https://api.example.com/v1", "https://api.example.com/v1"},
		{"CLOUDFLARE_WEBSEARCH_PROVIDER", "exa", "exa"},
		{"CLOUDFLARE_WEBSEARCH_BYOK_ALIAS", "my_alias-1", "my_alias-1"},
		{"CLOUDFLARE_AI_GATEWAY_ID", "default", "default"},
		{"CLOUDFLARE_ACCOUNT_ID", "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer x,foo=bar", "authorization=Bearer x,foo=bar"},
	}
	for _, c := range ok {
		got, err := NormalizeHubSecretValue(c.name, c.in)
		if err != nil || got != c.want {
			t.Fatalf("%s %q: got %q err %+v", c.name, c.in, got, err)
		}
	}
	bad := []struct{ name, in, code string }{
		{"SERPER_API_KEY", "   ", "empty_secret_value"},
		{"SERPER_API_KEY", strings.Repeat("a", MaxHubSecretValueBytes+1), "secret_value_too_large"},
		{"SERPER_API_KEY", "abc\ndef", "invalid_secret_value"},
		{"SERPER_API_KEY", "abc\x00", "invalid_secret_value"},
		{"SERPER_API_KEY", "abc def", "invalid_secret_value"},
		{"SERPER_API_KEY", "\xff\xfe", "invalid_secret_value"},
		{"SEARXNG_URL", "http://search.example.com", "invalid_secret_url"},
		{"FIRECRAWL_API_URL", "http://localhost:3002", "invalid_secret_url"},
		{"OLLAMA_HOST", "http://10.0.0.5:11434", "invalid_secret_url"},
		{"PDF_OCR_URL", "ftp://ocr.example.com", "invalid_secret_url"},
		{"PDF_OCR_URL", "ocr.example.com", "invalid_secret_url"},
		{"CRAWL4AI_API_URL", "https://user:pw@crawl.example.com", "invalid_secret_url"},
		{"CLOUDFLARE_WEBSEARCH_PROVIDER", "google", "invalid_secret_value"},
		{"CLOUDFLARE_WEBSEARCH_PROVIDER", "EXA", "invalid_secret_value"},
		{"CLOUDFLARE_WEBSEARCH_BYOK_ALIAS", "bad alias", "invalid_secret_value"},
		{"CLOUDFLARE_WEBSEARCH_BYOK_ALIAS", strings.Repeat("a", 65), "invalid_secret_value"},
		{"CLOUDFLARE_AI_GATEWAY_ID", "gw/../x", "invalid_secret_value"},
		{"CLOUDFLARE_ACCOUNT_ID", "abc-def", "invalid_secret_value"},
	}
	for _, c := range bad {
		if _, err := NormalizeHubSecretValue(c.name, c.in); err == nil || err.Error != c.code {
			t.Fatalf("%s %q: want %s, got %+v", c.name, c.in, c.code, err)
		}
	}
}

func TestHubSecretSealUnsealRoundTripAndNameBinding(t *testing.T) {
	ct, fp, err := SealHubSecret(testMasterKey, "SERPER_API_KEY", "  serper-value-123 ")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "hs1.") || strings.Contains(ct, "serper-value-123") {
		t.Fatalf("bad envelope %q", ct)
	}
	if fp != HubSecretFingerprint("serper-value-123") || len(fp) != 8 {
		t.Fatalf("fingerprint %q", fp)
	}
	got, uErr := UnsealHubSecret(testMasterKey, "SERPER_API_KEY", ct)
	if uErr != nil || got != "serper-value-123" {
		t.Fatalf("unseal got %q err %+v", got, uErr)
	}
	// Ciphertext swapped onto another row name must fail authentication.
	if _, uErr := UnsealHubSecret(testMasterKey, "BRAVE_API_KEY", ct); uErr == nil || uErr.Error != "hub_secret_decryption_failed" {
		t.Fatalf("swapped name must fail, got %+v", uErr)
	}
	// Wrong master key fails.
	if _, uErr := UnsealHubSecret(testMasterKey+"-rotated", "SERPER_API_KEY", ct); uErr == nil {
		t.Fatal("rotated key must fail")
	}
	// Bootstrap names can't be unsealed either (no row should exist, but never trust storage).
	if _, uErr := UnsealHubSecret(testMasterKey, "CALLER_TOKEN", ct); uErr == nil || uErr.Error != "unknown_secret_name" {
		t.Fatalf("bootstrap unseal must fail, got %+v", uErr)
	}
	// Tampered envelope header.
	if _, uErr := UnsealHubSecret(testMasterKey, "SERPER_API_KEY", "v2"+ct[3:]); uErr == nil {
		t.Fatal("wrong envelope version must fail")
	}
	// Missing master key.
	if _, _, sErr := SealHubSecret("short", "SERPER_API_KEY", "x"); sErr == nil || sErr.Error != "vault_master_key_unconfigured" || sErr.Status != 503 {
		t.Fatalf("short key must fail, got %+v", sErr)
	}
	if _, _, sErr := SealHubSecret(testMasterKey, "VAULT_MASTER_KEY", "x"); sErr == nil || sErr.Error != "bootstrap_secret_readonly" {
		t.Fatalf("bootstrap seal must fail, got %+v", sErr)
	}
}

func TestVerifyHubSecretPlaintextRejectsMismatch(t *testing.T) {
	prep := PrepareHubSecretSeal(testMasterKey, "TAVILY_API_KEY", "tv")
	if !prep.OK {
		t.Fatal(prep.Message)
	}
	if v, ok := VerifyHubSecretPlaintext("TAVILY_API_KEY", []byte(prep.Plaintext)); !ok || v != "tv" {
		t.Fatalf("verify %q %v", v, ok)
	}
	if _, ok := VerifyHubSecretPlaintext("SERPER_API_KEY", []byte(prep.Plaintext)); ok {
		t.Fatal("name mismatch must fail")
	}
	if _, ok := VerifyHubSecretPlaintext("TAVILY_API_KEY", []byte(`{"purpose":"other","name":"TAVILY_API_KEY","value":"x"}`)); ok {
		t.Fatal("purpose mismatch must fail")
	}
}

func TestBuildHubSecretStatus(t *testing.T) {
	st := BuildHubSecretStatus(
		[]HubSecretEnvProbe{
			{Name: "BRAVE_API_KEY", Fingerprint: "AABBCCDD"},
			{Name: "SERPER_API_KEY", Fingerprint: "11112222"},
			{Name: "CALLER_TOKEN", Fingerprint: "deadbeef"},
			{Name: "SEARXNG_URL", Fingerprint: "33334444", PlainValue: "https://s.example.com"},
			{Name: "OPENAI_API_KEY", Fingerprint: "55556666", PlainValue: "must-not-leak"},
			{Name: "NOT_A_SECRET", Fingerprint: "00000000"},
		},
		[]HubSecretOverrideMeta{
			{Name: "SERPER_API_KEY", Fingerprint: "99998888", UpdatedAt: 42, UpdatedBy: "gh_1", PlainValue: "must-not-leak"},
			{Name: "CLOUDFLARE_WEBSEARCH_PROVIDER", Fingerprint: "77776666", UpdatedAt: 7, UpdatedBy: "gh_1", PlainValue: "exa"},
			{Name: "CALLER_TOKEN", Fingerprint: "12345678"},
		},
	)
	byName := map[string]HubSecretStatus{}
	for _, s := range st {
		byName[s.Name] = s
	}
	if len(st) != len(HubManagedSecretNames())+len(HubBootstrapSecretNames()) {
		t.Fatalf("len %d", len(st))
	}
	if s := byName["SERPER_API_KEY"]; s.Source != "override" || *s.Fingerprint != "99998888" || !s.EnvSet || *s.UpdatedBy != "gh_1" || s.Value != nil || !s.Secret {
		t.Fatalf("serper %+v", s)
	}
	if s := byName["BRAVE_API_KEY"]; s.Source != "env" || *s.Fingerprint != "aabbccdd" {
		t.Fatalf("brave %+v", s)
	}
	if s := byName["TAVILY_API_KEY"]; s.Source != "unset" || s.Fingerprint != nil {
		t.Fatalf("tavily %+v", s)
	}
	if s := byName["CALLER_TOKEN"]; s.Managed || s.Source != "env" || s.Fingerprint != nil || s.UpdatedAt != nil || s.Value != nil {
		t.Fatalf("bootstrap must be env-only without fingerprint: %+v", s)
	}
	if s := byName["SEARXNG_URL"]; s.Secret || s.Value == nil || *s.Value != "https://s.example.com" {
		t.Fatalf("plain env value %+v", s)
	}
	if s := byName["OPENAI_API_KEY"]; s.Value != nil {
		t.Fatalf("secret env value leaked %+v", s)
	}
	if s := byName["CLOUDFLARE_WEBSEARCH_PROVIDER"]; s.Secret || s.Source != "override" || s.Value == nil || *s.Value != "exa" {
		t.Fatalf("plain override %+v", s)
	}
	if _, ok := byName["NOT_A_SECRET"]; ok {
		t.Fatal("unknown names must be ignored")
	}
}
