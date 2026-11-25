package agentloop

import (
	"net/url"
	"regexp"
	"strings"
)

var safeRPCColonSuffixes = map[string]bool{
	"generatecontent":       true,
	"streamgeneratecontent": true,
	"batchgeneratecontent":  true,
	"counttokens":           true,
	"embedcontent":          true,
	"batchembedcontents":    true,
	"predict":               true,
	"streamrawpredict":      true,
	"rawpredict":            true,
}

var allowedLLMPathSegments = map[string]bool{
	"v1":              true,
	"v1beta":          true,
	"v1alpha":         true,
	"v1beta1":         true,
	"v1beta2":         true,
	"v2":              true,
	"v3":              true,
	"v4":              true,
	"api":             true,
	"openai":          true,
	"anthropic":       true,
	"gemini":          true,
	"vertex":          true,
	"compat":          true,
	"chat":            true,
	"completions":     true,
	"messages":        true,
	"responses":       true,
	"embeddings":      true,
	"models":          true,
	"generate":        true,
	"tags":            true,
	"transcriptions":  true,
	"classifications": true,
	"chatcompletions": true,
	"fine_tuning":     true,
}

var (
	reSafeModelSegment = regexp.MustCompile(`(?i)^(?:gemini|gpt|claude|llama|mistral|mixtral|codestral|qwen|deepseek|o1|o3|o4|text-embedding|embedding|embed|command|phi|gemma|yi|sonar)[a-z0-9._-]{0,64}$`)
	reSensitiveHeader  = regexp.MustCompile(`(?i)authorization|api[-_]?key|token|secret|cookie|sig|signature|password|credential`)
	reSensitiveValue   = regexp.MustCompile(`(?i)^(?:Bearer|Basic|Digest|Token)\s+|^(?:sk-|AIza|gsk_|gh[pousr]_|xox[abprs]-|glpat-|hf_)`)
	reFallbackUserInfo = regexp.MustCompile(`(?i)^(https?://)[^/@\s]+@`)
)

func redactAllowlistedPathSegment(seg, prevLowerSeg string) string {
	if seg == "" {
		return seg
	}
	decoded, ok := safeDecodeURIComponent(seg)
	if !ok {
		decoded = seg
	}
	if decoded != seg {
		return "[REDACTED]"
	}
	if semiIdx := strings.IndexByte(decoded, ';'); semiIdx >= 0 {
		head := decoded[:semiIdx]
		safeHead := ""
		if head != "" {
			safeHead = redactAllowlistedPathSegment(head, prevLowerSeg)
		}
		return safeHead + ";[REDACTED]"
	}
	if strings.ContainsRune(decoded, '=') {
		return "[REDACTED]"
	}
	if colonIdx := strings.IndexByte(decoded, ':'); colonIdx >= 0 {
		lhs := decoded[:colonIdx]
		rhs := decoded[colonIdx+1:]
		safeLhs := ""
		if lhs != "" {
			safeLhs = redactAllowlistedPathSegment(lhs, prevLowerSeg)
		}
		if rhs != "" && safeLhs != "" && safeLhs != "[REDACTED]" && safeRPCColonSuffixes[strings.ToLower(rhs)] {
			return safeLhs + ":" + rhs
		}
		if safeLhs != "" && safeLhs != "[REDACTED]" {
			return safeLhs + ":[REDACTED]"
		}
		return "[REDACTED]"
	}
	lower := strings.ToLower(decoded)
	if allowedLLMPathSegments[lower] {
		return seg
	}
	if prevLowerSeg == "models" && reSafeModelSegment.MatchString(decoded) {
		return seg
	}
	return "[REDACTED]"
}

// RedactLLMURLForLog strips userinfo, query strings, fragments, and non-allowlisted path segments from an LLM URL.
func RedactLLMURLForLog(rawURL string) string {
	if rawURL == "" || strings.HasPrefix(rawURL, "workers-ai://") {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return stripQueryAndFragFallback(rawURL)
	}
	uNoAuth := *u
	uNoAuth.User = nil
	uNoAuth.RawQuery = ""
	uNoAuth.Fragment = ""
	uNoAuth.ForceQuery = false
	parsed, ok := parseStrictHTTPURL(uNoAuth.String())
	if !ok {
		return stripQueryAndFragFallback(rawURL)
	}
	rawSegs := strings.Split(parsed.escapedPath, "/")
	redactedSegs := make([]string, 0, len(rawSegs))
	prevLower := ""
	for i, seg := range rawSegs {
		if i == 0 || seg == "" {
			redactedSegs = append(redactedSegs, seg)
			continue
		}
		dec, decOK := safeDecodeURIComponent(seg)
		if !decOK {
			dec = seg
		}
		redactedSegs = append(redactedSegs, redactAllowlistedPathSegment(seg, prevLower))
		prevLower = strings.ToLower(dec)
	}
	rebuilt := strings.Join(redactedSegs, "/")
	return trimTrailingSlashes(parsed.originLower + rebuilt)
}

func stripQueryAndFragFallback(rawURL string) string {
	out := reFallbackUserInfo.ReplaceAllString(rawURL, "$1")
	if idx := strings.IndexAny(out, "?#"); idx >= 0 {
		out = out[:idx]
	}
	return out
}

// RedactHeadersForLog redacts sensitive header names and token-like values.
func RedactHeadersForLog(rawHeaders map[string]string) map[string]string {
	if rawHeaders == nil {
		return nil
	}
	out := make(map[string]string, len(rawHeaders))
	for k, v := range rawHeaders {
		if reSensitiveHeader.MatchString(k) || reSensitiveValue.MatchString(strings.TrimSpace(v)) {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}

// LoggableLLMConfigInput describes an LLM configuration plus optional endpoint/headers for safe logging.
type LoggableLLMConfigInput struct {
	Provider       LLMProvider       `json:"provider"`
	BaseURL        string            `json:"baseUrl"`
	Endpoint       *string           `json:"endpoint,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	HasHeaders     bool              `json:"hasHeaders,omitempty"`
	APIKey         string            `json:"apiKey,omitempty"`
	Model          string            `json:"model"`
	IsOfflineLocal bool              `json:"isOfflineLocal"`
}

// RedactLLMConfigForLog produces a zero-secret log summary of a resolved LLM config.
func RedactLLMConfigForLog(cfg *LoggableLLMConfigInput) map[string]any {
	if cfg == nil {
		return nil
	}
	out := map[string]any{
		"provider":       cfg.Provider,
		"baseUrl":        RedactLLMURLForLog(cfg.BaseURL),
		"model":          cfg.Model,
		"isOfflineLocal": cfg.IsOfflineLocal,
		"hasApiKey":      cfg.APIKey != "",
	}
	if cfg.Endpoint != nil {
		out["endpoint"] = RedactLLMURLForLog(*cfg.Endpoint)
	}
	if cfg.HasHeaders || cfg.Headers != nil {
		hdrs := cfg.Headers
		if hdrs == nil {
			hdrs = map[string]string{}
		}
		out["headers"] = RedactHeadersForLog(hdrs)
	}
	return out
}
