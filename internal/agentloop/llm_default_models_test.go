package agentloop

import "testing"

// Defaults must name currently served models: a retired default (e.g. claude-3-5-haiku-latest) makes every agent call
// fail for operators who only set a provider key.
func TestDefaultModelsAreCurrent(t *testing.T) {
	cases := map[LLMProvider]string{
		ProviderAnthropic:  "claude-haiku-5-5",
		ProviderOpenRouter: "anthropic/claude-haiku-5.5",
	}
	for provider, want := range cases {
		if got := defaultModels[provider]; got != want {
			t.Fatalf("default model for %s = %q, want %q", provider, got, want)
		}
	}
}
