package agentloop

import (
	"strings"
	"testing"
)

// Current Claude models return 400 "`temperature` is deprecated for this model." when temperature is sent.
func TestClaudeRequestsOmitTemperature(t *testing.T) {
	temp := 0.1
	msgs := []LLMMessage{{Role: "user", Content: "hi"}}
	cases := []struct {
		name     string
		cfg      ResolvedLLMConfig
		wantTemp bool
	}{
		{"anthropic", ResolvedLLMConfig{Provider: ProviderAnthropic, Model: "claude-haiku-5-5", BaseURL: "https://api.anthropic.com/v1"}, false},
		{"openrouter-claude", ResolvedLLMConfig{Provider: ProviderOpenRouter, Model: "anthropic/claude-haiku-5.5", BaseURL: "https://openrouter.ai/api/v1"}, false},
		{"openrouter-other", ResolvedLLMConfig{Provider: ProviderOpenRouter, Model: "qwen/qwen-2.5-coder-32b-instruct", BaseURL: "https://openrouter.ai/api/v1"}, true},
	}
	for _, c := range cases {
		req, err := BuildProviderHTTPRequest(LLMProviderTurnParams{Config: c.cfg, Messages: msgs, Temperature: &temp})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := strings.Contains(req.Body, `"temperature"`); got != c.wantTemp {
			t.Fatalf("%s: temperature present=%v, want %v; body=%s", c.name, got, c.wantTemp, req.Body)
		}
	}
}
