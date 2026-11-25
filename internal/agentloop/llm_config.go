package agentloop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// LLMProvider identifies a supported BYO-LLM or local inference provider.
type LLMProvider string

const (
	ProviderOpenAI     LLMProvider = "openai"
	ProviderOllama     LLMProvider = "ollama"
	ProviderLMStudio   LLMProvider = "lmstudio"
	ProviderVLLM       LLMProvider = "vllm"
	ProviderOpenRouter LLMProvider = "openrouter"
	ProviderAnthropic  LLMProvider = "anthropic"
	ProviderGemini     LLMProvider = "gemini"
	ProviderWorkersAI  LLMProvider = "workers-ai"
)

var defaultBaseURLs = map[LLMProvider]string{
	ProviderOpenAI:     "https://api.openai.com/v1",
	ProviderOllama:     "http://127.0.0.1:11434/v1",
	ProviderLMStudio:   "http://127.0.0.1:1234/v1",
	ProviderVLLM:       "http://127.0.0.1:8000/v1",
	ProviderOpenRouter: "https://openrouter.ai/api/v1",
	ProviderAnthropic:  "https://api.anthropic.com/v1",
	ProviderGemini:     "https://generativelanguage.googleapis.com/v1beta",
	ProviderWorkersAI:  "workers-ai://binding",
}

var defaultModels = map[LLMProvider]string{
	ProviderOpenAI:     "gpt-4o-mini",
	ProviderOllama:     "qwen2.5:7b",
	ProviderLMStudio:   "local-model",
	ProviderVLLM:       "Qwen/Qwen2.5-7B-Instruct",
	ProviderOpenRouter: "openai/gpt-4o-mini",
	ProviderAnthropic:  "claude-3-5-haiku-latest",
	ProviderGemini:     "gemini-2.5-flash",
	ProviderWorkersAI:  "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
}

var officialProviderTrustedPrefixes = map[LLMProvider]string{
	ProviderOpenAI:     "https://api.openai.com/v1",
	ProviderAnthropic:  "https://api.anthropic.com",
	ProviderGemini:     "https://generativelanguage.googleapis.com",
	ProviderOpenRouter: "https://openrouter.ai/api/v1",
}

var localLoopbackInferencePorts = map[string]bool{
	"11434": true,
	"1234":  true,
	"8000":  true,
	"8080":  true,
}

var reValidLLMModel = newLazyRegexp(`^[A-Za-z0-9._:@/-]{1,160}$`)

// LLMEnvConfig holds operator environment variables and binding flags for BYO-LLM resolution.
type LLMEnvConfig struct {
	EdgeFetchLLMProvider        string `json:"EDGEFETCH_LLM_PROVIDER,omitempty"`
	EdgeFetchLLMBaseURL         string `json:"EDGEFETCH_LLM_BASE_URL,omitempty"`
	EdgeFetchLLMAPIKey          string `json:"EDGEFETCH_LLM_API_KEY,omitempty"`
	EdgeFetchLLMModel           string `json:"EDGEFETCH_LLM_MODEL,omitempty"`
	EdgeFetchAllowLocalOverride string `json:"EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE,omitempty"`
	OllamaHost                  string `json:"OLLAMA_HOST,omitempty"`
	OpenAIAPIKey                string `json:"OPENAI_API_KEY,omitempty"`
	OpenRouterAPIKey            string `json:"OPENROUTER_API_KEY,omitempty"`
	AnthropicAPIKey             string `json:"ANTHROPIC_API_KEY,omitempty"`
	GeminiAPIKey                string `json:"GEMINI_API_KEY,omitempty"`
	HasWorkersAI                bool   `json:"hasWorkersAi,omitempty"`
}

// ResolvedLLMConfig contains the validated, key-isolated LLM configuration for a turn or agent run.
type ResolvedLLMConfig struct {
	Provider           LLMProvider `json:"provider"`
	BaseURL            string      `json:"baseUrl"`
	APIKey             string      `json:"apiKey,omitempty"`
	Model              string      `json:"model"`
	IsOfflineLocal     bool        `json:"isOfflineLocal"`
	UseSafePublicFetch bool        `json:"useSafePublicFetch,omitempty"`
}

// ResolveLLMConfigInput describes inputs to ResolveLLMConfig.
type ResolveLLMConfigInput struct {
	Env        LLMEnvConfig    `json:"env"`
	RequestLLM json.RawMessage `json:"requestLlm,omitempty"`
	SelfHost   string          `json:"selfHost,omitempty"`
}

// ResolveLLMConfigOutput represents the outcome of ResolveLLMConfig.
type ResolveLLMConfigOutput struct {
	OK      bool               `json:"ok"`
	Config  *ResolvedLLMConfig `json:"config"`
	Error   string             `json:"error,omitempty"`
	Message string             `json:"message,omitempty"`
}

// NormalizeProvider maps provider aliases to canonical LLMProvider values.
func NormalizeProvider(raw string) (LLMProvider, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "openai", "openai-compatible", "compatible":
		return ProviderOpenAI, true
	case "ollama":
		return ProviderOllama, true
	case "lmstudio", "lm-studio", "llamacpp", "llama.cpp":
		return ProviderLMStudio, true
	case "vllm":
		return ProviderVLLM, true
	case "openrouter":
		return ProviderOpenRouter, true
	case "anthropic", "claude":
		return ProviderAnthropic, true
	case "gemini", "google":
		return ProviderGemini, true
	case "workers-ai", "workers_ai", "cloudflare":
		return ProviderWorkersAI, true
	default:
		return "", false
	}
}

// ResolveLLMConfig resolves operator environment defaults and per-request overrides, enforcing C1/M1 API key
// origin + path-prefix isolation and SSRF validation on caller-supplied baseUrl overrides.
func ResolveLLMConfig(input ResolveLLMConfigInput) ResolveLLMConfigOutput {
	env := input.Env
	var reqObj map[string]any
	if trimmed := bytes.TrimSpace(input.RequestLLM); len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		if trimmed[0] != '{' || json.Unmarshal(trimmed, &reqObj) != nil {
			return ResolveLLMConfigOutput{OK: false, Error: "invalid_llm_config", Message: "llm must be a JSON object"}
		}
	}

	var reqProvider LLMProvider
	hasReqProvider := false
	if reqObj != nil {
		if rawP, exists := reqObj["provider"]; exists {
			pStr, isStr := rawP.(string)
			normP, valid := NormalizeProvider(pStr)
			if !isStr || !valid {
				return ResolveLLMConfigOutput{OK: false, Error: "invalid_llm_provider", Message: "Unsupported llm.provider value"}
			}
			reqProvider, hasReqProvider = normP, true
		}
		if rawB, exists := reqObj["baseUrl"]; exists {
			if bStr, isStr := rawB.(string); !isStr || strings.TrimSpace(bStr) == "" {
				return ResolveLLMConfigOutput{OK: false, Error: "invalid_llm_base_url", Message: "llm.baseUrl must be a non-empty URL string"}
			}
		}
		if rawM, exists := reqObj["model"]; exists {
			if mStr, isStr := rawM.(string); !isStr || strings.TrimSpace(mStr) == "" {
				return ResolveLLMConfigOutput{OK: false, Error: "invalid_llm_model", Message: "llm.model must be a non-empty string"}
			}
		}
	}

	envProvider, hasEnvProvider := NormalizeProvider(env.EdgeFetchLLMProvider)
	operatorDefaultProvider, hasOperatorDefault := inferOperatorProvider(env, envProvider, hasEnvProvider)

	var inferredProvider LLMProvider
	switch {
	case hasReqProvider:
		inferredProvider = reqProvider
	case hasOperatorDefault:
		inferredProvider = operatorDefaultProvider
	default:
		return ResolveLLMConfigOutput{OK: true, Config: nil}
	}

	rawEnvBase := strings.TrimSpace(env.EdgeFetchLLMBaseURL)
	rawOllamaHost := strings.TrimSpace(env.OllamaHost)
	normalizedOllamaBase := ""
	if rawOllamaHost != "" {
		normalizedOllamaBase = strings.TrimSuffix(trimTrailingSlashes(rawOllamaHost), "/v1") + "/v1"
	}
	operatorBaseURL := ""
	if rawEnvBase != "" {
		operatorBaseURL = normalizeOperatorBaseURLPreservingQuery(rawEnvBase)
	} else if hasOperatorDefault && operatorDefaultProvider == ProviderOllama && normalizedOllamaBase != "" {
		operatorBaseURL = normalizedOllamaBase
	}
	operatorDefaultBaseURL := operatorBaseURL
	if operatorDefaultBaseURL == "" && hasOperatorDefault {
		operatorDefaultBaseURL = defaultBaseURLs[operatorDefaultProvider]
	}

	baseURL := defaultBaseURLs[inferredProvider]
	if hasOperatorDefault && inferredProvider == operatorDefaultProvider && operatorBaseURL != "" {
		baseURL = operatorBaseURL
	} else if inferredProvider == ProviderOllama && normalizedOllamaBase != "" {
		baseURL = normalizedOllamaBase
	}

	callerBaseStr, hasCallerBaseURL := "", false
	if reqObj != nil {
		if s, ok := reqObj["baseUrl"].(string); ok {
			callerBaseStr, hasCallerBaseURL = strings.TrimSpace(s), true
		}
	}

	if hasCallerBaseURL {
		candNorm, candParsed, errMsg, cleanOK := ValidateCleanHTTPBaseURL(callerBaseStr)
		if !cleanOK {
			return ResolveLLMConfigOutput{OK: false, Error: "invalid_llm_base_url", Message: "Invalid llm.baseUrl: " + errMsg}
		}
		allowedOverride := operatorBaseURL != "" && MatchesTrustedBaseURLPrefix(candNorm, stripBaseURLQuery(operatorBaseURL))
		if !allowedOverride && env.EdgeFetchAllowLocalOverride == "true" {
			if (candParsed.scheme == "http" || candParsed.scheme == "https") &&
				(candParsed.hostname == "127.0.0.1" || candParsed.hostname == "localhost") &&
				localLoopbackInferencePorts[candParsed.effectivePort] {
				allowedOverride = true
			}
		}
		if !allowedOverride {
			if pubCheck := ValidatePublicHTTPSTargetURL(candNorm, input.SelfHost); !pubCheck.OK {
				return ResolveLLMConfigOutput{
					OK: false, Error: "invalid_llm_base_url",
					Message: "Per-request llm.baseUrl must be a public https:// URL on port 443 (or match EDGEFETCH_LLM_BASE_URL prefix): " + pubCheck.Message,
				}
			}
		}
		baseURL = candNorm
	} else if (inferredProvider == ProviderOllama || inferredProvider == ProviderLMStudio || inferredProvider == ProviderVLLM) &&
		!(hasOperatorDefault && inferredProvider == operatorDefaultProvider && operatorBaseURL != "") &&
		!(inferredProvider == ProviderOllama && normalizedOllamaBase != "") &&
		env.EdgeFetchAllowLocalOverride != "true" {
		return ResolveLLMConfigOutput{
			OK: false, Error: "local_llm_not_configured",
			Message: fmt.Sprintf("Configure EDGEFETCH_LLM_BASE_URL or OLLAMA_HOST (or set EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE=true) to enable %s.", inferredProvider),
		}
	}

	model := resolveModelName(reqObj, env, inferredProvider, reqProvider, hasReqProvider, envProvider, hasEnvProvider, operatorDefaultProvider)
	if !isValidLLMModelIdentifier(model) {
		return ResolveLLMConfigOutput{
			OK: false, Error: "invalid_llm_model",
			Message: "llm.model must match /^[A-Za-z0-9._:@/-]{1,160}$/ without empty, \".\", or \"..\" path segments",
		}
	}
	if inferredProvider == ProviderWorkersAI && !env.HasWorkersAI {
		return ResolveLLMConfigOutput{
			OK: false, Error: "workers_ai_not_bound",
			Message: "Workers AI provider requested, but env.AI binding is not configured on this Hub.",
		}
	}

	apiKey := resolveIsolatedAPIKey(reqObj, env, inferredProvider, operatorDefaultProvider, hasOperatorDefault, baseURL, operatorBaseURL, operatorDefaultBaseURL, hasCallerBaseURL)
	baseForPrefix := baseURL
	if !hasCallerBaseURL {
		baseForPrefix = stripBaseURLQuery(baseURL)
	}
	opForPrefix := stripBaseURLQuery(operatorBaseURL)
	matchesOpPrefix := operatorBaseURL != "" && (!hasCallerBaseURL || MatchesTrustedBaseURLPrefix(baseForPrefix, opForPrefix))
	callerOverrodeBase := hasCallerBaseURL && !matchesOpPrefix
	offline := inferredProvider == ProviderOllama || inferredProvider == ProviderLMStudio || inferredProvider == ProviderVLLM || isOfflineHost(baseURL)

	return ResolveLLMConfigOutput{
		OK: true,
		Config: &ResolvedLLMConfig{
			Provider:           inferredProvider,
			BaseURL:            baseURL,
			APIKey:             apiKey,
			Model:              model,
			IsOfflineLocal:     offline,
			UseSafePublicFetch: callerOverrodeBase && !isOfflineHost(baseURL),
		},
	}
}

func inferOperatorProvider(env LLMEnvConfig, envProvider LLMProvider, hasEnvProvider bool) (LLMProvider, bool) {
	if hasEnvProvider {
		return envProvider, true
	}
	if strings.TrimSpace(env.EdgeFetchLLMBaseURL) != "" {
		lowerBase := strings.ToLower(env.EdgeFetchLLMBaseURL)
		switch {
		case strings.Contains(lowerBase, "11434") || strings.Contains(lowerBase, "ollama"):
			return ProviderOllama, true
		case strings.Contains(lowerBase, "1234"):
			return ProviderLMStudio, true
		case strings.Contains(lowerBase, "anthropic.com"):
			return ProviderAnthropic, true
		case strings.Contains(lowerBase, "googleapis.com"):
			return ProviderGemini, true
		case strings.Contains(lowerBase, "openrouter.ai"):
			return ProviderOpenRouter, true
		default:
			return ProviderOpenAI, true
		}
	}
	switch {
	case strings.TrimSpace(env.OllamaHost) != "":
		return ProviderOllama, true
	case strings.TrimSpace(env.OpenAIAPIKey) != "" || strings.TrimSpace(env.EdgeFetchLLMAPIKey) != "":
		return ProviderOpenAI, true
	case strings.TrimSpace(env.AnthropicAPIKey) != "":
		return ProviderAnthropic, true
	case strings.TrimSpace(env.GeminiAPIKey) != "":
		return ProviderGemini, true
	case strings.TrimSpace(env.OpenRouterAPIKey) != "":
		return ProviderOpenRouter, true
	case env.HasWorkersAI:
		return ProviderWorkersAI, true
	default:
		return "", false
	}
}

func resolveModelName(
	reqObj map[string]any,
	env LLMEnvConfig,
	inferred, reqP LLMProvider,
	hasReqP bool,
	envP LLMProvider,
	hasEnvP bool,
	opDef LLMProvider,
) string {
	if reqObj != nil {
		if mStr, ok := reqObj["model"].(string); ok && strings.TrimSpace(mStr) != "" {
			return strings.TrimSpace(mStr)
		}
	}
	cmpP := opDef
	if hasEnvP {
		cmpP = envP
	}
	if (!hasReqP || reqP == cmpP) && strings.TrimSpace(env.EdgeFetchLLMModel) != "" {
		return strings.TrimSpace(env.EdgeFetchLLMModel)
	}
	return defaultModels[inferred]
}

func resolveIsolatedAPIKey(
	reqObj map[string]any,
	env LLMEnvConfig,
	inferred, opDef LLMProvider,
	hasOpDef bool,
	baseURL, opBaseURL, opDefBaseURL string,
	hasCallerBase bool,
) string {
	if reqObj != nil {
		if kStr, ok := reqObj["apiKey"].(string); ok && strings.TrimSpace(kStr) != "" {
			return strings.TrimSpace(kStr)
		}
	}
	officialPrefix := officialProviderTrustedPrefixes[inferred]
	baseCheck := baseURL
	if !hasCallerBase {
		baseCheck = stripBaseURLQuery(baseURL)
	}
	opCheck := stripBaseURLQuery(opBaseURL)
	matchesOfficial := officialPrefix != "" && MatchesTrustedBaseURLPrefix(baseCheck, officialPrefix)
	matchesOpConfigured := opBaseURL != "" && hasOpDef && opDef == inferred &&
		(!hasCallerBase || MatchesTrustedBaseURLPrefix(baseCheck, opCheck))

	if matchesOfficial || matchesOpConfigured {
		var provKey string
		switch inferred {
		case ProviderAnthropic:
			provKey = strings.TrimSpace(env.AnthropicAPIKey)
		case ProviderGemini:
			provKey = strings.TrimSpace(env.GeminiAPIKey)
		case ProviderOpenRouter:
			provKey = strings.TrimSpace(env.OpenRouterAPIKey)
		case ProviderOpenAI:
			provKey = strings.TrimSpace(env.OpenAIAPIKey)
		}
		if provKey != "" {
			return provKey
		}
	}

	provMatchesDef := hasOpDef && inferred == opDef
	baseMatchesDef := !hasCallerBase
	if !baseMatchesDef && opDefBaseURL != "" {
		c1, _, _, ok1 := ValidateCleanHTTPBaseURL(baseCheck)
		c2, _, _, ok2 := ValidateCleanHTTPBaseURL(opDefBaseURL)
		baseMatchesDef = ok1 && ok2 && c1 == c2
	}
	if provMatchesDef && baseMatchesDef {
		return strings.TrimSpace(env.EdgeFetchLLMAPIKey)
	}
	return ""
}

func isValidLLMModelIdentifier(model string) bool {
	if !reValidLLMModel.MatchString(model) || strings.Contains(model, "..") || strings.ContainsRune(model, ';') {
		return false
	}
	for _, seg := range strings.Split(model, "/") {
		if seg == "" || strings.Trim(seg, ".") == "" {
			return false
		}
	}
	return true
}
