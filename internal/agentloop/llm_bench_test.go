package agentloop

import (
	"strings"
	"testing"
)

var (
	benchLLMSinkStr   string
	benchLLMSinkCalls []LLMToolCall
)

func BenchmarkStripThinkBlocks80k(b *testing.B) {
	raw80kThink := strings.Repeat("<think>", 80000)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw80kThink)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchLLMSinkStr = StripThinkBlocksLinear(raw80kThink)
	}
}

func BenchmarkParseFallbackTextToolCalls80k(b *testing.B) {
	raw80kTool := strings.Repeat("<tool_call>", 80000)
	allowed := map[string]bool{"scrape_url": true}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw80kTool)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchLLMSinkCalls = ParseFallbackTextToolCalls(raw80kTool, allowed)
	}
}
