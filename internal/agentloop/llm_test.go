package agentloop

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestResolveLLMConfigAndKeyIsolation(t *testing.T) {
	operatorEnv := LLMEnvConfig{
		OpenAIAPIKey:       "sk-operator-openai-secret",
		AnthropicAPIKey:    "sk-ant-operator-secret",
		GeminiAPIKey:       "gem-operator-secret",
		OpenRouterAPIKey:   "or-operator-secret",
		EdgeFetchLLMAPIKey: "ef-generic-operator-secret",
	}

	// 1. Canonical OpenAI default origin receives operator OPENAI_API_KEY
	canon := ResolveLLMConfig(ResolveLLMConfigInput{
		Env:        operatorEnv,
		RequestLLM: json.RawMessage(`{"provider":"openai"}`),
	})
	if !canon.OK || canon.Config == nil || canon.Config.APIKey != "sk-operator-openai-secret" {
		t.Fatalf("expected canonical openai operator key, got %+v", canon)
	}

	// 2. C1: Caller-overridden custom baseUrl NEVER receives operator env keys
	for _, prov := range []string{"", "openai", "anthropic", "gemini", "openrouter"} {
		reqMap := map[string]any{"baseUrl": "https://attacker.example/v1"}
		if prov != "" {
			reqMap["provider"] = prov
		}
		rawReq, _ := json.Marshal(reqMap)
		attempt := ResolveLLMConfig(ResolveLLMConfigInput{
			Env:        operatorEnv,
			RequestLLM: rawReq,
		})
		if attempt.OK && attempt.Config != nil && attempt.Config.APIKey != "" {
			t.Fatalf("operator key leaked for provider=%q: %+v", prov, attempt.Config)
		}
	}

	// 3. M1: Shared-origin AI Gateway path-prefix isolation (case-sensitive account segment!)
	cfGwEnv := LLMEnvConfig{
		EdgeFetchLLMProvider: "openai",
		EdgeFetchLLMBaseURL:  "https://gateway.ai.cloudflare.com/v1/OPERATOR_ACCT/gw/openai",
		OpenAIAPIKey:         "sk-operator-gw",
	}
	gwAttacker := ResolveLLMConfig(ResolveLLMConfigInput{
		Env:        cfGwEnv,
		RequestLLM: json.RawMessage(`{"baseUrl":"https://gateway.ai.cloudflare.com/v1/ATTACKER_ACCT/gw/openai"}`),
	})
	if !gwAttacker.OK || gwAttacker.Config == nil || gwAttacker.Config.APIKey != "" {
		t.Fatalf("expected empty apiKey on sibling gateway path, got %+v", gwAttacker.Config)
	}
	gwCaseMismatch := ResolveLLMConfig(ResolveLLMConfigInput{
		Env:        cfGwEnv,
		RequestLLM: json.RawMessage(`{"baseUrl":"https://gateway.ai.cloudflare.com/v1/operator_acct/gw/openai"}`),
	})
	if !gwCaseMismatch.OK || gwCaseMismatch.Config == nil || gwCaseMismatch.Config.APIKey != "" {
		t.Fatalf("expected case-sensitive path mismatch to withhold key, got %+v", gwCaseMismatch.Config)
	}
	gwShorter := ResolveLLMConfig(ResolveLLMConfigInput{
		Env:        cfGwEnv,
		RequestLLM: json.RawMessage(`{"baseUrl":"https://gateway.ai.cloudflare.com/v1"}`),
	})
	if !gwShorter.OK || gwShorter.Config == nil || gwShorter.Config.APIKey != "" {
		t.Fatalf("expected shorter parent path to withhold key, got %+v", gwShorter.Config)
	}
	gwExact := ResolveLLMConfig(ResolveLLMConfigInput{
		Env:        cfGwEnv,
		RequestLLM: json.RawMessage(`{"baseUrl":"https://gateway.ai.cloudflare.com/v1/OPERATOR_ACCT/gw/openai"}`),
	})
	if !gwExact.OK || gwExact.Config == nil || gwExact.Config.APIKey != "sk-operator-gw" {
		t.Fatalf("expected exact operator gateway path to receive key, got %+v", gwExact.Config)
	}

	// 4. Generic EDGEFETCH_LLM_API_KEY withheld on provider or baseUrl override
	genEnv := LLMEnvConfig{EdgeFetchLLMAPIKey: "ef-generic-secret"}
	genDef := ResolveLLMConfig(ResolveLLMConfigInput{Env: genEnv})
	if !genDef.OK || genDef.Config == nil || genDef.Config.APIKey != "ef-generic-secret" {
		t.Fatalf("expected generic key on default config, got %+v", genDef)
	}
	for _, rawOvr := range []string{
		`{"provider":"anthropic"}`,
		`{"provider":"openrouter"}`,
		`{"baseUrl":"https://other.example/v1"}`,
	} {
		ovr := ResolveLLMConfig(ResolveLLMConfigInput{Env: genEnv, RequestLLM: json.RawMessage(rawOvr)})
		if ovr.OK && ovr.Config != nil && ovr.Config.APIKey != "" {
			t.Fatalf("generic key leaked on override %s", rawOvr)
		}
	}

	// 5. Loopback Ollama / LMStudio / vLLM guard + SSRF rejections
	if r := ResolveLLMConfig(ResolveLLMConfigInput{RequestLLM: json.RawMessage(`{"provider":"ollama"}`), SelfHost: "localhost"}); r.OK || r.Error != "local_llm_not_configured" {
		t.Fatalf("expected local_llm_not_configured, got %+v", r)
	}
	if r := ResolveLLMConfig(ResolveLLMConfigInput{
		Env:        LLMEnvConfig{OllamaHost: "http://127.0.0.1:11434/"},
		RequestLLM: json.RawMessage(`{"provider":"ollama"}`),
	}); !r.OK || r.Config == nil || !r.Config.IsOfflineLocal {
		t.Fatalf("expected OLLAMA_HOST to enable ollama, got %+v", r)
	}
	if r := ResolveLLMConfig(ResolveLLMConfigInput{
		Env:        LLMEnvConfig{EdgeFetchAllowLocalOverride: "true"},
		RequestLLM: json.RawMessage(`{"provider":"ollama","baseUrl":"http://127.0.0.1:11434/v1"}`),
	}); !r.OK || r.Config == nil || !r.Config.IsOfflineLocal {
		t.Fatalf("expected local override to allow port 11434, got %+v", r)
	}

	badBaseURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://127.0.0.1/v1",
		"https://8.8.8.8/v1",
		"https://hub.example.com/v1",
		"https://api.openai.com/v1?x=1",
		"https://api.openai.com/v1#frag",
		"https://api.openai.com/v1%2e%2e",
		"https://api.openai.com/v1/%25252525252e",
		"https://api.openai.com/v1//chat",
		"https://user:pass@api.openai.com/v1",
		"https://api.openai.com./v1",
		"https://api.openai.com/v1/../v2",
		"https:/api.openai.com/v1",
		"https://api.example.com/%E0%A4%A",
		"https://api.example.com/has%20space",
		"https://[invalid-host",
		"https://api.example.com/" + strings.Repeat("a", 2030),
	}
	for _, bad := range badBaseURLs {
		rawReq, _ := json.Marshal(map[string]any{"provider": "openai", "baseUrl": bad})
		r := ResolveLLMConfig(ResolveLLMConfigInput{RequestLLM: rawReq, SelfHost: "hub.example.com"})
		if r.OK {
			t.Fatalf("expected rejection for baseUrl=%q, got %+v", bad, r.Config)
		}
	}

	// Bad models & Workers AI unbound
	for _, badM := range []string{"../etc/passwd", "bad;model", "a//b", "../../v1/evil?key="} {
		rawReq, _ := json.Marshal(map[string]any{"provider": "openai", "model": badM})
		if r := ResolveLLMConfig(ResolveLLMConfigInput{RequestLLM: rawReq}); r.OK || r.Error != "invalid_llm_model" {
			t.Fatalf("expected invalid_llm_model for %q, got %+v", badM, r)
		}
	}
	if r := ResolveLLMConfig(ResolveLLMConfigInput{RequestLLM: json.RawMessage(`{"provider":"workers-ai"}`)}); r.OK || r.Error != "workers_ai_not_bound" {
		t.Fatalf("expected workers_ai_not_bound, got %+v", r)
	}

	// Linear O(N) 200k slash check (anti-infinite-loop/anti-O(N^2) guard)
	slashReq, _ := json.Marshal(map[string]any{"baseUrl": "https://a.example.com/" + strings.Repeat("/", 200000) + "x", "apiKey": "k"})
	t0 := time.Now()
	_ = ResolveLLMConfig(ResolveLLMConfigInput{RequestLLM: slashReq})
	if time.Since(t0) > 5*time.Second {
		t.Fatalf("trailing slash check took too long: %v", time.Since(t0))
	}
}

func TestRedactLLMURLAndConfigForLog(t *testing.T) {
	leakCases := []struct {
		rawURL    string
		forbidden *regexp.Regexp
	}{
		{"https://svc:S3CRET@gw.corp.example.com/v1", regexp.MustCompile(`S3CRET|svc`)},
		{"https://svc:p%40ss@gw.corp.example.com/v1/", regexp.MustCompile(`p%40ss|svc`)},
		{"https://gw.corp.example.com/v1?api-key=S3CRET", regexp.MustCompile(`S3CRET`)},
		{"https://gw.corp.example.com/v1?key=AIzaS3CRET&api-version=2024", regexp.MustCompile(`S3CRET|AIza`)},
		{"https://gw.corp.example.com/v1#S3CRET", regexp.MustCompile(`S3CRET`)},
		{"https://gw.corp.example.com/tok/S3CRET/v1", regexp.MustCompile(`S3CRET`)},
		{"https://gw.corp.example.com/api-key/S3CRET_KEY_VALUE/v1", regexp.MustCompile(`S3CRET`)},
		{"https://hooks.slack.com/services/T0123ABC/B4567DEF/SlackSecretTokenXYZ", regexp.MustCompile(`T0123ABC|B4567DEF|SlackSecretTokenXYZ`)},
		{"https://discord.com/api/webhooks/9876543210/DiscordWebhookSecret99", regexp.MustCompile(`9876543210|DiscordWebhookSecret99`)},
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:AIzaSySecretKey999", regexp.MustCompile(`AIzaSySecretKey999`)},
		{"https://gw.corp.example.com/v1;key=S3CRET/chat/completions", regexp.MustCompile(`S3CRET`)},
		{"https://gw.corp.example.com/v1beta/sk-proj-1234567890abcdefghij/openai", regexp.MustCompile(`sk-proj-`)},
		{"https://gw.corp.example.com/v1beta/a1b2c3d4e5f60718293a4b5c6d7e8f90/chat", regexp.MustCompile(`a1b2c3d4e5f6`)},
		{"https://gw.example.com/%73%6b-live-abcdefghijklmnop/v1", regexp.MustCompile(`%73%6b|sk-live`)},
	}

	for _, tc := range leakCases {
		ep := tc.rawURL + "/chat/completions?sig=S3CRET_EP"
		red := RedactLLMConfigForLog(&LoggableLLMConfigInput{
			Provider: ProviderOpenAI,
			BaseURL:  tc.rawURL,
			Endpoint: &ep,
			Headers: map[string]string{
				"Authorization":  "Bearer sk-live-SUPERSECRET",
				"x-goog-api-key": "AIzaSyHeaderSecret",
				"content-type":   "application/json",
			},
			APIKey: "sk-live-SUPERSECRET",
			Model:  "gpt-4o-mini",
		})
		b, _ := json.Marshal(red)
		s := string(b)
		if tc.forbidden.MatchString(s) {
			t.Fatalf("secret leaked for %q: %s", tc.rawURL, s)
		}
		if strings.Contains(s, "SUPERSECRET") || strings.Contains(s, "AIzaSyHeaderSecret") || strings.Contains(s, "S3CRET_EP") {
			t.Fatalf("header/query secret leaked: %s", s)
		}
		if _, hasAPIKey := red["apiKey"]; hasAPIKey {
			t.Fatalf("apiKey property must never be emitted")
		}
		hdrs := red["headers"].(map[string]string)
		if hdrs["content-type"] != "application/json" || hdrs["Authorization"] != "[REDACTED]" {
			t.Fatalf("unexpected redacted headers: %+v", hdrs)
		}
	}

	if got := RedactLLMURLForLog("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"); got != "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent" {
		t.Fatalf("benign Gemini RPC path mangled: %q", got)
	}
	if got := RedactLLMURLForLog("https://openrouter.ai/api/v1"); got != "https://openrouter.ai/api/v1" {
		t.Fatalf("benign OpenRouter path mangled: %q", got)
	}
	if got := RedactLLMURLForLog("https://user:pass@[invalid/v1?secret=1"); !strings.HasPrefix(got, "https://[invalid") || strings.Contains(got, "pass") || strings.Contains(got, "secret") {
		t.Fatalf("malformed URL fallback failed: %q", got)
	}
}

func TestProviderCodecsLinearPerfAndSchemaValidation(t *testing.T) {
	tools := []LLMToolDefinition{
		{Name: "scrape_url", Description: "Scrape URL", Parameters: map[string]any{"type": "object"}},
	}
	msgs := []LLMMessage{
		{Role: "system", Content: "System rules"},
		{Role: "user", Content: "Hello"},
		{Role: "assistant", Content: "Thinking", ToolCalls: []LLMToolCall{{ID: "t1", Name: "scrape_url", Arguments: map[string]any{"url": "https://a.com"}}}},
		{Role: "tool", ToolCallID: "t1", Name: "scrape_url", Content: `{"ok":true}`},
	}

	// 1. OpenAI, Anthropic, Gemini, Native Ollama /api/chat, Workers AI request builders & parsers
	for _, prov := range []LLMProvider{ProviderOpenAI, ProviderAnthropic, ProviderGemini, ProviderOllama} {
		base := defaultBaseURLs[prov]
		if prov == ProviderOllama {
			base = "http://127.0.0.1:11434/api/chat"
		}
		req, err := BuildProviderHTTPRequest(LLMProviderTurnParams{
			Config:   ResolvedLLMConfig{Provider: prov, BaseURL: base, APIKey: "secret", Model: defaultModels[prov]},
			Messages: msgs,
			Tools:    tools,
		})
		if err != nil || req.Kind != "http" || req.Body == "" {
			t.Fatalf("BuildProviderHTTPRequest(%s) failed: %v %+v", prov, err, req)
		}
		// 302 redirect fail-closed
		redir := ParseProviderHTTPResponse(prov, 302, nil, []string{"scrape_url"})
		if redir.OK || !strings.Contains(redir.Error, "disallowed redirect") {
			t.Fatalf("expected 302 fail-closed for %s, got %+v", prov, redir)
		}
	}

	// Anthropic tool_use + usage
	anthResp := ParseProviderHTTPResponse(ProviderAnthropic, 200, []byte(`{
		"content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"tu1","name":"scrape_url","input":{"url":"https://x.com"}}],
		"usage":{"input_tokens":10,"output_tokens":5}
	}`), []string{"scrape_url"})
	if !anthResp.OK || len(anthResp.ToolCalls) != 1 || anthResp.ToolCalls[0].ID != "tu1" || *anthResp.Usage.TotalTokens != 15 {
		t.Fatalf("unexpected Anthropic parse: %+v", anthResp)
	}

	// Gemini functionCall
	gemResp := ParseProviderHTTPResponse(ProviderGemini, 200, []byte(`{
		"candidates":[{"content":{"parts":[{"functionCall":{"name":"scrape_url","args":{"url":"https://g.com"}}}]}}]
	}`), []string{"scrape_url"})
	if !gemResp.OK || len(gemResp.ToolCalls) != 1 || gemResp.ToolCalls[0].Arguments["url"] != "https://g.com" {
		t.Fatalf("unexpected Gemini parse: %+v", gemResp)
	}

	// Ollama <think> + <tool_call> fallback
	ollResp := ParseProviderHTTPResponse(ProviderOllama, 200, []byte(`{
		"message":{"role":"assistant","content":"<think>reasoning</think>\n<tool_call>{\"name\":\"scrape_url\",\"arguments\":{\"url\":\"https://sec.gov\"}}</tool_call>"}
	}`), []string{"scrape_url"})
	if !ollResp.OK || len(ollResp.ToolCalls) != 1 || ollResp.ToolCalls[0].Arguments["url"] != "https://sec.gov" {
		t.Fatalf("unexpected Ollama fallback parse: %+v", ollResp)
	}

	// M12: 80,000 unclosed <think> and <tool_call> tags anti-O(N^2) guard (exact latency measured in llm_bench_test.go)
	raw80kThink := strings.Repeat("<think>", 80000)
	t1Direct := time.Now()
	if got := StripThinkBlocksLinear(raw80kThink); got != raw80kThink || time.Since(t1Direct) > 5*time.Second {
		t.Fatalf("StripThinkBlocksLinear 80k <think> failed or slow (%v)", time.Since(t1Direct))
	}
	raw80kTool := strings.Repeat("<tool_call>", 80000)
	t2Direct := time.Now()
	if got := ParseFallbackTextToolCalls(raw80kTool, map[string]bool{"scrape_url": true}); len(got) != 0 || time.Since(t2Direct) > 5*time.Second {
		t.Fatalf("ParseFallbackTextToolCalls 80k <tool_call> failed or slow (%v)", time.Since(t2Direct))
	}

	thinkJSON, _ := marshalCompactJSONNoEscape(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": raw80kThink}}}})
	t1 := time.Now()
	rThink := ParseProviderHTTPResponse(ProviderOpenAI, 200, []byte(thinkJSON), nil)
	if !rThink.OK || time.Since(t1) > 5*time.Second {
		t.Fatalf("80k <think> failed or slow (%v)", time.Since(t1))
	}

	toolJSON, _ := marshalCompactJSONNoEscape(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": raw80kTool}}}})
	t2 := time.Now()
	rTool := ParseProviderHTTPResponse(ProviderOpenAI, 200, []byte(toolJSON), []string{"scrape_url"})
	if !rTool.OK || time.Since(t2) > 5*time.Second {
		t.Fatalf("80k <tool_call> failed or slow (%v)", time.Since(t2))
	}

	// ParseLooseJSONObject + BuildDeterministicSummary + ValidateDataAgainstJSONSchema
	if obj := ParseLooseJSONObject("<think>x</think>\n```json\n{\"a\":1}\n```"); obj["a"] != float64(1) {
		t.Fatalf("expected a=1, got %+v", obj)
	}
	if sum := BuildDeterministicSummary("   ", "Fallback Title"); sum != "Fallback Title." {
		t.Fatalf("unexpected fallback summary: %q", sum)
	}
	val := ValidateDataAgainstJSONSchema(map[string]any{"title": "Only One"}, true, map[string]any{
		"type":       "object",
		"required":   []any{"title", "missingField"},
		"properties": map[string]any{"title": map[string]any{"type": "string"}, "missingField": map[string]any{"type": "string"}},
	})
	if val.Valid || !val.PartialValid {
		t.Fatalf("expected valid=false partialValid=true, got %+v", val)
	}

	// Callback-driven Summarize & ExtractJSON
	ctx := context.Background()
	cfg := &ResolvedLLMConfig{Provider: ProviderOpenAI, BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini"}
	data, via := ExtractJSONWithOptionalLLM(ctx, "# Pricing\nFree $0", "Pricing", "https://example.com", "get price", nil, map[string]any{"base": true}, cfg, func(_ context.Context, _ LLMTransportRequest) (LLMTransportResponse, error) {
		return LLMTransportResponse{Status: 200, Body: []byte(`{"choices":[{"message":{"content":"{\"price\":0}"}}]}`)}, nil
	})
	if !via || data["price"] != float64(0) || data["base"] != true {
		t.Fatalf("unexpected ExtractJSONWithOptionalLLM: via=%v data=%+v", via, data)
	}
}
