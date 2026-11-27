package mcpfed

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Admin-managed Hub secret overrides (`hub_secrets` DO SQLite table).
//
// Contract (mirrored by hub/src/hub-secrets.ts, which only performs WebCrypto + SQLite glue):
//   - Only MANAGED provider keys (HubManagedSecretNames) may be set from /admin. BOOTSTRAP names
//     (HubBootstrapSecretNames: auth tokens, VAULT_MASTER_KEY, session/OAuth secrets) are status-only and
//     can never be overridden, so an admin session can't rotate itself out of the trust root or swap the
//     vault key that seals these very rows.
//   - Each value is sealed with HKDF-SHA256(VAULT_MASTER_KEY, random 16-byte salt, info) -> AES-256-GCM
//     (12-byte IV), envelope "hs1.<salt>.<iv>.<ct>" (unpadded base64url). Both the HKDF info and the AAD are
//     length-prefixed over the fixed scope user "hub" and the secret NAME, and the sealed plaintext repeats
//     the name, so a ciphertext copied from one row to another (e.g. SERPER_API_KEY -> WEBHOOK_SECRET)
//     fails authentication instead of silently decrypting.
//   - Values are trimmed, capped at MaxHubSecretValueBytes, must be valid UTF-8 without control characters,
//     and URL-typed names must be https (http only for localhost/127.0.0.1 on OLLAMA_HOST / SEARXNG_URL).

const (
	// HubSecretsValuePurposeV1 is the HKDF info purpose label for hub_secrets values.
	HubSecretsValuePurposeV1 = "hub_secrets:value:v1"
	// HubSecretsScopeUserID is the fixed pseudo-user every hub_secrets envelope is bound to.
	HubSecretsScopeUserID = "hub"
	// HubSecretsEnvelopeVersion prefixes sealed hub_secrets ciphertexts.
	HubSecretsEnvelopeVersion = "hs1"
	// MaxHubSecretValueBytes caps a single override value (UTF-8 bytes after trimming).
	MaxHubSecretValueBytes = 8 * 1024
	// MaxHubSecretCiphertextBytes bounds envelope parsing work on stored rows.
	MaxHubSecretCiphertextBytes = 16 * 1024

	hubSecretsAADPurpose      = "hub_secrets:value"
	hubSecretsHKDFInfoPrefix  = "edgefetch-hub-secrets-v1:"
	hubSecretClassManaged     = "managed"
	hubSecretClassBootstrap   = "bootstrap"
	hubSecretClassUnknown     = "unknown"
	hubSecretSourceOverride   = "override"
	hubSecretSourceEnv        = "env"
	hubSecretSourceUnset      = "unset"
	hubSecretFingerprintChars = 8
)

// hubManagedSecretNames is the closed allowlist of provider keys an admin may override. Order is display order.
var hubManagedSecretNames = []string{
	"SERPER_API_KEY",
	"BRAVE_API_KEY",
	"TAVILY_API_KEY",
	"SEARXNG_URL",
	"EDGEFETCH_LLM_PROVIDER",
	"EDGEFETCH_LLM_BASE_URL",
	"EDGEFETCH_LLM_API_KEY",
	"EDGEFETCH_LLM_MODEL",
	"OPENAI_API_KEY",
	"OPENROUTER_API_KEY",
	"ANTHROPIC_API_KEY",
	"GEMINI_API_KEY",
	"OLLAMA_HOST",
	"FIRECRAWL_API_URL",
	"FIRECRAWL_API_KEY",
	"CRAWL4AI_API_URL",
	"CRAWL4AI_API_TOKEN",
	"PDF_OCR_URL",
	"PDF_OCR_TOKEN",
	"OTEL_EXPORTER_OTLP_HEADERS",
	"WEBHOOK_SECRET",
	"GOOGLE_MAPS_API_KEY",
	"CLOUDFLARE_ACCOUNT_ID",
	"CLOUDFLARE_WEBSEARCH_API_TOKEN",
	"CLOUDFLARE_AI_GATEWAY_ID",
	"CLOUDFLARE_WEBSEARCH_PROVIDER",
	"CLOUDFLARE_WEBSEARCH_BYOK_ALIAS",
}

// hubPlainConfigNames are non-secret managed config values: /admin status may show them in full. Every
// other managed name is a secret and is only ever reported as a fingerprint.
var hubPlainConfigNames = map[string]bool{
	"SEARXNG_URL":                     true,
	"EDGEFETCH_LLM_PROVIDER":          true,
	"EDGEFETCH_LLM_BASE_URL":          true,
	"EDGEFETCH_LLM_MODEL":             true,
	"OLLAMA_HOST":                     true,
	"FIRECRAWL_API_URL":               true,
	"CRAWL4AI_API_URL":                true,
	"PDF_OCR_URL":                     true,
	"CLOUDFLARE_AI_GATEWAY_ID":        true,
	"CLOUDFLARE_WEBSEARCH_PROVIDER":   true,
	"CLOUDFLARE_WEBSEARCH_BYOK_ALIAS": true,
}

// hubSecretEnumValues restricts enum-typed managed names (exact, case-sensitive after trim).
var hubSecretEnumValues = map[string][]string{
	"CLOUDFLARE_WEBSEARCH_PROVIDER": {"ceramic", "exa", "linkup"},
}

// hubSecretIdentNames must match ^[A-Za-z0-9_-]{1,64}$ (BYOK alias, AI Gateway id) or, for the account id,
// ^[A-Za-z0-9]{1,64}$.
var hubSecretIdentNames = map[string]bool{
	"CLOUDFLARE_WEBSEARCH_BYOK_ALIAS": true,
	"CLOUDFLARE_AI_GATEWAY_ID":        true,
}

// IsHubPlainConfigName reports whether a managed name is non-secret plain config.
func IsHubPlainConfigName(name string) bool { return hubPlainConfigNames[name] }

// HubPlainConfigNames returns the sorted plain-config managed names.
func HubPlainConfigNames() []string {
	out := make([]string, 0, len(hubPlainConfigNames))
	for k := range hubPlainConfigNames {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func isHubSecretIdent(v string, allowPunct bool) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (allowPunct && (c == '_' || c == '-')) {
			continue
		}
		return false
	}
	return true
}

// hubBootstrapSecretNames are reported (set/unset only) but never settable through the override store.
var hubBootstrapSecretNames = []string{
	"CALLER_TOKEN",
	"CALLER_TOKEN_PREVIOUS",
	"MCP_TOKEN",
	"VAULT_MASTER_KEY",
	"SESSION_SECRET",
	"GITHUB_CLIENT_SECRET",
	"AGENT_TOKEN",
	"AGENT_TOKENS",
	"BOT_SIGNING_PRIVATE_KEY",
}

// hubSecretURLNames must parse as absolute https URLs.
var hubSecretURLNames = map[string]bool{
	"SEARXNG_URL":            true,
	"EDGEFETCH_LLM_BASE_URL": true,
	"OLLAMA_HOST":            true,
	"FIRECRAWL_API_URL":      true,
	"CRAWL4AI_API_URL":       true,
	"PDF_OCR_URL":            true,
}

// hubSecretLoopbackHTTPNames may additionally use plain http when the host is localhost / 127.0.0.1.
var hubSecretLoopbackHTTPNames = map[string]bool{
	"OLLAMA_HOST": true,
	"SEARXNG_URL": true,
}

var (
	hubManagedSecretSet   = toStringSet(hubManagedSecretNames)
	hubBootstrapSecretSet = toStringSet(hubBootstrapSecretNames)
)

func toStringSet(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, s := range items {
		out[s] = true
	}
	return out
}

// HubManagedSecretNames returns a copy of the managed (overridable) secret allowlist.
func HubManagedSecretNames() []string { return append([]string(nil), hubManagedSecretNames...) }

// HubBootstrapSecretNames returns a copy of the read-only bootstrap secret names.
func HubBootstrapSecretNames() []string { return append([]string(nil), hubBootstrapSecretNames...) }

// HubSecretURLNames returns the sorted URL-typed managed names.
func HubSecretURLNames() []string {
	out := make([]string, 0, len(hubSecretURLNames))
	for k := range hubSecretURLNames {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ClassifyHubSecretName reports "managed", "bootstrap", or "unknown" for an exact (case-sensitive) name.
func ClassifyHubSecretName(name string) string {
	switch {
	case hubManagedSecretSet[name]:
		return hubSecretClassManaged
	case hubBootstrapSecretSet[name]:
		return hubSecretClassBootstrap
	default:
		return hubSecretClassUnknown
	}
}

// HubSecretError is a structured validation failure for hub_secrets operations.
type HubSecretError struct {
	Status  int    `json:"status"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// ValidateHubSecretName accepts only managed names; bootstrap and unknown names are rejected.
func ValidateHubSecretName(rawName string) (string, *HubSecretError) {
	name := strings.TrimSpace(rawName)
	switch ClassifyHubSecretName(name) {
	case hubSecretClassManaged:
		return name, nil
	case hubSecretClassBootstrap:
		return "", &HubSecretError{
			Status:  403,
			Error:   "bootstrap_secret_readonly",
			Message: name + " is a bootstrap secret and can only be changed in the deployment environment (wrangler secret / env).",
		}
	default:
		return "", &HubSecretError{
			Status:  400,
			Error:   "unknown_secret_name",
			Message: "Secret name is not in the managed provider-key allowlist.",
		}
	}
}

func isHubSecretControlRune(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 || r == 0xfeff
}

func isLoopbackHubSecretHost(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || h == "127.0.0.1"
}

// NormalizeHubSecretValue trims and validates a value for a managed name.
func NormalizeHubSecretValue(name, raw string) (string, *HubSecretError) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", &HubSecretError{Status: 400, Error: "empty_secret_value", Message: "Secret value is empty; delete the override instead."}
	}
	if len(value) > MaxHubSecretValueBytes {
		return "", &HubSecretError{
			Status:  413,
			Error:   "secret_value_too_large",
			Message: "Secret value exceeds " + strconv.Itoa(MaxHubSecretValueBytes) + " bytes.",
		}
	}
	if !utf8.ValidString(value) {
		return "", &HubSecretError{Status: 400, Error: "invalid_secret_value", Message: "Secret value must be valid UTF-8."}
	}
	for _, r := range value {
		if isHubSecretControlRune(r) {
			return "", &HubSecretError{Status: 400, Error: "invalid_secret_value", Message: "Secret value must not contain control or line-separator characters."}
		}
	}
	if allowed, isEnum := hubSecretEnumValues[name]; isEnum {
		match := false
		for _, a := range allowed {
			if value == a {
				match = true
				break
			}
		}
		if !match {
			return "", &HubSecretError{Status: 400, Error: "invalid_secret_value", Message: name + " must be one of: " + strings.Join(allowed, ", ") + "."}
		}
	}
	if hubSecretIdentNames[name] && !isHubSecretIdent(value, true) {
		return "", &HubSecretError{Status: 400, Error: "invalid_secret_value", Message: name + " must match ^[A-Za-z0-9_-]{1,64}$."}
	}
	if name == "CLOUDFLARE_ACCOUNT_ID" && !isHubSecretIdent(value, false) {
		return "", &HubSecretError{Status: 400, Error: "invalid_secret_value", Message: name + " must be 1..64 alphanumeric characters."}
	}
	if hubSecretURLNames[name] {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
			return "", &HubSecretError{Status: 400, Error: "invalid_secret_url", Message: name + " must be an absolute https:// URL."}
		}
		if u.User != nil {
			return "", &HubSecretError{Status: 400, Error: "invalid_secret_url", Message: name + " must not embed user:password credentials; use the matching token secret."}
		}
		if u.Fragment != "" {
			return "", &HubSecretError{Status: 400, Error: "invalid_secret_url", Message: name + " must not contain a #fragment."}
		}
		switch strings.ToLower(u.Scheme) {
		case "https":
		case "http":
			if !hubSecretLoopbackHTTPNames[name] || !isLoopbackHubSecretHost(u.Hostname()) {
				return "", &HubSecretError{Status: 400, Error: "invalid_secret_url", Message: name + " must use https:// (http:// is only allowed for localhost/127.0.0.1 on OLLAMA_HOST and SEARXNG_URL)."}
			}
		default:
			return "", &HubSecretError{Status: 400, Error: "invalid_secret_url", Message: name + " must be an absolute https:// URL."}
		}
	}
	return value, nil
}

func lengthPrefixed(sb *strings.Builder, s string) {
	sb.WriteString(strconv.Itoa(utf16Len(s)))
	sb.WriteByte(':')
	sb.WriteString(s)
}

// BuildHubSecretHKDFInfo returns the length-prefixed HKDF-SHA256 info binding scope user "hub" and the secret name.
func BuildHubSecretHKDFInfo(name string) string {
	var sb strings.Builder
	sb.Grow(len(hubSecretsHKDFInfoPrefix) + len(HubSecretsValuePurposeV1) + len(name) + 16)
	sb.WriteString(hubSecretsHKDFInfoPrefix)
	sb.WriteString(HubSecretsValuePurposeV1)
	sb.WriteByte(':')
	lengthPrefixed(&sb, HubSecretsScopeUserID)
	sb.WriteByte('|')
	lengthPrefixed(&sb, name)
	return sb.String()
}

// BuildHubSecretAAD returns the length-prefixed AES-GCM AAD binding envelope version, scope user, and secret name.
func BuildHubSecretAAD(envelopeVersion, name string) string {
	var sb strings.Builder
	sb.Grow(len(envelopeVersion) + len(hubSecretsAADPurpose) + len(name) + 16)
	sb.WriteString(envelopeVersion)
	sb.WriteByte('|')
	sb.WriteString(hubSecretsAADPurpose)
	sb.WriteByte('|')
	lengthPrefixed(&sb, HubSecretsScopeUserID)
	sb.WriteByte('|')
	lengthPrefixed(&sb, name)
	return sb.String()
}

type hubSecretPlaintext struct {
	Purpose string `json:"purpose"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

// PreparedHubSecretSeal holds Go-computed key material inputs for the host AEAD seal.
type PreparedHubSecretSeal struct {
	OK              bool   `json:"ok"`
	Name            string `json:"name,omitempty"`
	CleanKey        string `json:"cleanKey,omitempty"`
	HKDFInfo        string `json:"hkdfInfo,omitempty"`
	AAD             string `json:"aad,omitempty"`
	Plaintext       string `json:"plaintext,omitempty"`
	EnvelopeVersion string `json:"envelopeVersion,omitempty"`
	// NormalizedValue is the trimmed value the host fingerprints (SHA-256, first 8 hex) for status display.
	NormalizedValue string `json:"normalizedValue,omitempty"`
	Status          int    `json:"status,omitempty"`
	Error           string `json:"error,omitempty"`
	Message         string `json:"message,omitempty"`
}

func hubSecretKeyUnconfigured(msg string) *HubSecretError {
	return &HubSecretError{
		Status:  503,
		Error:   "vault_master_key_unconfigured",
		Message: strings.Replace(msg, "to encrypt MCP credentials", "to encrypt Hub secret overrides", 1),
	}
}

// PrepareHubSecretSeal validates the master key, name, and value, then builds HKDF info, AAD, and plaintext.
func PrepareHubSecretSeal(vaultMasterKey, rawName, rawValue string) PreparedHubSecretSeal {
	cleanKey, ok, keyMsg := ValidateVaultMasterKey(vaultMasterKey)
	if !ok {
		e := hubSecretKeyUnconfigured(keyMsg)
		return PreparedHubSecretSeal{Status: e.Status, Error: e.Error, Message: e.Message}
	}
	name, nErr := ValidateHubSecretName(rawName)
	if nErr != nil {
		return PreparedHubSecretSeal{Status: nErr.Status, Error: nErr.Error, Message: nErr.Message}
	}
	value, vErr := NormalizeHubSecretValue(name, rawValue)
	if vErr != nil {
		return PreparedHubSecretSeal{Status: vErr.Status, Error: vErr.Error, Message: vErr.Message}
	}
	plain, err := json.Marshal(hubSecretPlaintext{Purpose: hubSecretsAADPurpose, Name: name, Value: value})
	if err != nil {
		return PreparedHubSecretSeal{Status: 400, Error: "invalid_secret_value", Message: "Secret value could not be encoded."}
	}
	return PreparedHubSecretSeal{
		OK:              true,
		Name:            name,
		CleanKey:        cleanKey,
		HKDFInfo:        BuildHubSecretHKDFInfo(name),
		AAD:             BuildHubSecretAAD(HubSecretsEnvelopeVersion, name),
		Plaintext:       string(plain),
		EnvelopeVersion: HubSecretsEnvelopeVersion,
		NormalizedValue: value,
	}
}

// PreparedHubSecretUnseal holds validated envelope parts for the host AEAD open.
type PreparedHubSecretUnseal struct {
	OK        bool   `json:"ok"`
	CleanKey  string `json:"cleanKey,omitempty"`
	HKDFInfo  string `json:"hkdfInfo,omitempty"`
	AAD       string `json:"aad,omitempty"`
	SaltB64   string `json:"saltB64,omitempty"`
	IVB64     string `json:"ivB64,omitempty"`
	CTB64     string `json:"ctB64,omitempty"`
	SaltBytes []byte `json:"-"`
	IVBytes   []byte `json:"-"`
	CTBytes   []byte `json:"-"`
	Status    int    `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
}

// PrepareHubSecretUnseal validates an "hs1" envelope for a stored row name (managed names only).
func PrepareHubSecretUnseal(vaultMasterKey, name, ciphertext string) PreparedHubSecretUnseal {
	cleanKey, ok, keyMsg := ValidateVaultMasterKey(vaultMasterKey)
	if !ok {
		e := hubSecretKeyUnconfigured(keyMsg)
		return PreparedHubSecretUnseal{Status: e.Status, Error: e.Error, Message: e.Message}
	}
	if ClassifyHubSecretName(name) != hubSecretClassManaged {
		return PreparedHubSecretUnseal{Status: 400, Error: "unknown_secret_name", Message: "Stored override is not a managed secret name."}
	}
	fail := PreparedHubSecretUnseal{Status: 500, Error: "hub_secret_decryption_failed", Message: "Malformed hub secret envelope."}
	if ciphertext == "" || len(ciphertext) > MaxHubSecretCiphertextBytes {
		return fail
	}
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 4 || parts[0] != HubSecretsEnvelopeVersion {
		return fail
	}
	salt, sOk := decodeBase64URL(parts[1])
	iv, iOk := decodeBase64URL(parts[2])
	ct, cOk := decodeBase64URL(parts[3])
	if !sOk || len(salt) != 16 || !iOk || len(iv) != 12 || !cOk || len(ct) < 17 {
		return fail
	}
	return PreparedHubSecretUnseal{
		OK:        true,
		CleanKey:  cleanKey,
		HKDFInfo:  BuildHubSecretHKDFInfo(name),
		AAD:       BuildHubSecretAAD(parts[0], name),
		SaltB64:   parts[1],
		IVB64:     parts[2],
		CTB64:     parts[3],
		SaltBytes: salt,
		IVBytes:   iv,
		CTBytes:   ct,
	}
}

// VerifyHubSecretPlaintext checks the decrypted JSON is a hub_secrets value for exactly this name.
func VerifyHubSecretPlaintext(name string, plain []byte) (string, bool) {
	if !utf8.Valid(plain) || len(plain) > MaxHubSecretCiphertextBytes {
		return "", false
	}
	var p hubSecretPlaintext
	if err := json.Unmarshal(plain, &p); err != nil {
		return "", false
	}
	if p.Purpose != hubSecretsAADPurpose || p.Name != name || p.Value == "" {
		return "", false
	}
	return p.Value, true
}

// HubSecretOverrideMeta is the non-secret metadata of one stored override row.
type HubSecretOverrideMeta struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	UpdatedAt   int64  `json:"updatedAt"`
	UpdatedBy   string `json:"updatedBy"`
	// PlainValue is the decrypted value, supplied by the host ONLY for plain-config names; it is dropped for
	// secret names regardless.
	PlainValue string `json:"plainValue,omitempty"`
}

// HubSecretEnvProbe reports whether the deployment env sets a name, with the host-computed fingerprint.
type HubSecretEnvProbe struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	// PlainValue is honoured only for plain-config names (see PlainValue on HubSecretOverrideMeta).
	PlainValue string `json:"plainValue,omitempty"`
}

// HubSecretStatus is one admin-facing row. It never carries the value.
type HubSecretStatus struct {
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
	// Secret is false for plain-config names, whose effective Value may be displayed in full.
	Secret      bool    `json:"secret"`
	Value       *string `json:"value"`
	Source      string  `json:"source"`
	Fingerprint *string `json:"fingerprint"`
	EnvSet      bool    `json:"envSet"`
	UpdatedAt   *int64  `json:"updatedAt"`
	UpdatedBy   *string `json:"updatedBy"`
}

func cleanFingerprint(raw string) (string, bool) {
	fp := strings.ToLower(strings.TrimSpace(raw))
	if len(fp) != hubSecretFingerprintChars {
		return "", false
	}
	for i := 0; i < len(fp); i++ {
		c := fp[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}
	return fp, true
}

// BuildHubSecretStatus merges env presence and override metadata into the ordered status list
// (managed names first, then bootstrap). Bootstrap rows never report a fingerprint or an override source;
// unknown names in either input are ignored.
func BuildHubSecretStatus(env []HubSecretEnvProbe, overrides []HubSecretOverrideMeta) []HubSecretStatus {
	envByName := make(map[string]string, len(env))
	envPlain := make(map[string]string)
	for _, e := range env {
		if ClassifyHubSecretName(e.Name) == hubSecretClassUnknown {
			continue
		}
		fp, _ := cleanFingerprint(e.Fingerprint)
		envByName[e.Name] = fp
		if hubPlainConfigNames[e.Name] && e.PlainValue != "" {
			envPlain[e.Name] = e.PlainValue
		}
	}
	ovByName := make(map[string]HubSecretOverrideMeta, len(overrides))
	for _, o := range overrides {
		if ClassifyHubSecretName(o.Name) == hubSecretClassManaged {
			ovByName[o.Name] = o
		}
	}
	out := make([]HubSecretStatus, 0, len(hubManagedSecretNames)+len(hubBootstrapSecretNames))
	for _, name := range hubManagedSecretNames {
		st := HubSecretStatus{Name: name, Managed: true, Secret: !hubPlainConfigNames[name], Source: hubSecretSourceUnset}
		envFP, envSet := envByName[name]
		st.EnvSet = envSet
		if ov, has := ovByName[name]; has {
			st.Source = hubSecretSourceOverride
			if fp, ok := cleanFingerprint(ov.Fingerprint); ok {
				st.Fingerprint = &fp
			}
			at := ov.UpdatedAt
			st.UpdatedAt = &at
			by := ov.UpdatedBy
			st.UpdatedBy = &by
			if !st.Secret && ov.PlainValue != "" {
				v := ov.PlainValue
				st.Value = &v
			}
		} else if envSet {
			st.Source = hubSecretSourceEnv
			if envFP != "" {
				fp := envFP
				st.Fingerprint = &fp
			}
			if v, ok := envPlain[name]; ok && !st.Secret {
				st.Value = &v
			}
		}
		out = append(out, st)
	}
	for _, name := range hubBootstrapSecretNames {
		_, envSet := envByName[name]
		st := HubSecretStatus{Name: name, Managed: false, Secret: true, Source: hubSecretSourceUnset, EnvSet: envSet}
		if envSet {
			st.Source = hubSecretSourceEnv
		}
		out = append(out, st)
	}
	return out
}
