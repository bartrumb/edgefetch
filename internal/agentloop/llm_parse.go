package agentloop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// StripThinkBlocksLinear strips closed <think>...</think> reasoning blocks in strictly linear O(N) time (M12).
func StripThinkBlocksLinear(raw string) string {
	if len(raw) < 15 || !strings.Contains(raw, "</") {
		return raw
	}
	lower := strings.ToLower(raw)
	if !strings.Contains(lower, "</think>") {
		return raw
	}
	hit := strings.Index(lower, "<think>")
	if hit < 0 {
		return raw
	}
	var sb strings.Builder
	cursor := 0
	for hit >= 0 {
		closeIdx := strings.Index(lower[hit+7:], "</think>")
		if closeIdx < 0 {
			break
		}
		closeIdx += hit + 7
		if hit > cursor {
			sb.WriteString(raw[cursor:hit])
		}
		cursor = closeIdx + 8
		next := strings.Index(lower[cursor:], "<think>")
		if next < 0 {
			break
		}
		hit = cursor + next
	}
	if cursor == 0 {
		return raw
	}
	if cursor < len(raw) {
		sb.WriteString(raw[cursor:])
	}
	return sb.String()
}

func extractFirstCodeFenceBodyLinear(s string) (string, bool) {
	openIdx := strings.Index(s, "```")
	if openIdx < 0 {
		return "", false
	}
	rest := s[openIdx+3:]
	closeRel := strings.Index(rest, "```")
	if closeRel < 0 {
		return "", false
	}
	inner := rest[:closeRel]
	if len(inner) >= 4 && strings.EqualFold(inner[:4], "json") && (len(inner) == 4 || !isIdentContASCII(inner[4])) {
		inner = inner[4:]
	}
	return strings.TrimSpace(inner), true
}

func isIdentContASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func tryUnmarshalJSONObject(s string) map[string]any {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil || out == nil {
		return nil
	}
	return out
}

// ParseLooseJSONObject extracts a JSON object from raw LLM text, stripping <think>...</think> blocks
// and optional Markdown code fences in O(N) time (M12).
func ParseLooseJSONObject(raw string) map[string]any {
	if raw == "" || strings.IndexByte(raw, '{') < 0 || strings.IndexByte(raw, '}') < 0 {
		return nil
	}
	stripped := strings.TrimSpace(StripThinkBlocksLinear(raw))
	if stripped == "" {
		return nil
	}
	if direct := tryUnmarshalJSONObject(stripped); direct != nil {
		return direct
	}
	if fenceBody, ok := extractFirstCodeFenceBodyLinear(stripped); ok && fenceBody != "" {
		if fromFence := tryUnmarshalJSONObject(fenceBody); fromFence != nil {
			return fromFence
		}
	}
	firstBrace := strings.IndexByte(stripped, '{')
	lastBrace := strings.LastIndexByte(stripped, '}')
	if firstBrace >= 0 && lastBrace > firstBrace {
		if sliced := tryUnmarshalJSONObject(stripped[firstBrace : lastBrace+1]); sliced != nil {
			return sliced
		}
	}
	return nil
}

// ParseFallbackTextToolCalls parses <tool_call>{...}</tool_call> or JSON tool_calls emitted in plain assistant
// text by local quantized models (Ollama, llama.cpp, vLLM) in strictly linear O(N) time (M12).
func ParseFallbackTextToolCalls(content string, allowedToolNames map[string]bool) []LLMToolCall {
	calls := make([]LLMToolCall, 0)
	if len(allowedToolNames) == 0 || content == "" {
		return calls
	}
	if len(content) >= 23 && strings.Contains(content, "</") {
		lower := strings.ToLower(content)
		if strings.Contains(lower, "</tool_call>") {
			openIdx := strings.Index(lower, "<tool_call>")
			for openIdx >= 0 {
				closeRel := strings.Index(lower[openIdx+11:], "</tool_call>")
				if closeRel < 0 {
					break
				}
				closeIdx := openIdx + 11 + closeRel
				rawInner := strings.TrimSpace(content[openIdx+11 : closeIdx])
				if obj := ParseLooseJSONObject(rawInner); obj != nil {
					if name, ok := obj["name"].(string); ok && allowedToolNames[name] {
						args, _ := obj["arguments"].(map[string]any)
						if args == nil {
							args = map[string]any{}
						}
						calls = append(calls, LLMToolCall{
							ID:        fmt.Sprintf("call_%d", len(calls)+1),
							Name:      name,
							Arguments: args,
						})
					}
				}
				nextRel := strings.Index(lower[closeIdx+12:], "<tool_call>")
				if nextRel < 0 {
					break
				}
				openIdx = closeIdx + 12 + nextRel
			}
		}
	}
	if len(calls) > 0 {
		return calls
	}

	rootObj := ParseLooseJSONObject(content)
	if rootObj == nil {
		return calls
	}
	if name, ok := rootObj["name"].(string); ok && allowedToolNames[name] {
		args, okArgs := rootObj["arguments"].(map[string]any)
		if !okArgs || args == nil {
			args, _ = rootObj["parameters"].(map[string]any)
		}
		if args == nil {
			args = map[string]any{}
		}
		return []LLMToolCall{{ID: "call_1", Name: name, Arguments: args}}
	}
	if rawArr, ok := rootObj["tool_calls"].([]any); ok {
		for _, item := range rawArr {
			rec, okRec := item.(map[string]any)
			if !okRec || rec == nil {
				continue
			}
			fn := rec
			if nested, okFn := rec["function"].(map[string]any); okFn && nested != nil {
				fn = nested
			}
			name, _ := fn["name"].(string)
			if !allowedToolNames[name] {
				continue
			}
			calls = append(calls, LLMToolCall{
				ID:        fmt.Sprintf("call_%d", len(calls)+1),
				Name:      name,
				Arguments: extractToolCallArgs(fn["arguments"]),
			})
		}
	}
	return calls
}

func extractToolCallArgs(rawArgs any) map[string]any {
	switch v := rawArgs.(type) {
	case string:
		if parsed := ParseLooseJSONObject(v); parsed != nil {
			return parsed
		}
	case map[string]any:
		if v != nil {
			return v
		}
	}
	return map[string]any{}
}

// ParseWorkersAIResponse normalizes the output object from Cloudflare Workers AI.
func ParseWorkersAIResponse(rawOut map[string]any, allowedToolNames []string) LLMChatCompletionResult {
	allowedSet := toAllowedSet(allowedToolNames)
	content, _ := rawOut["response"].(string)
	parsedCalls := make([]LLMToolCall, 0)
	if rawCalls, ok := rawOut["tool_calls"].([]any); ok {
		for idx, item := range rawCalls {
			rec, okRec := item.(map[string]any)
			if !okRec || rec == nil {
				continue
			}
			name, _ := rec["name"].(string)
			if !allowedSet[name] {
				continue
			}
			args, _ := rec["arguments"].(map[string]any)
			if args == nil {
				args = map[string]any{}
			}
			parsedCalls = append(parsedCalls, LLMToolCall{
				ID:        fmt.Sprintf("cf_call_%d", idx+1),
				Name:      name,
				Arguments: args,
			})
		}
	}
	if len(parsedCalls) == 0 {
		parsedCalls = ParseFallbackTextToolCalls(content, allowedSet)
	}
	return LLMChatCompletionResult{
		OK:        true,
		Content:   content,
		ToolCalls: parsedCalls,
	}
}

func providerDisplayLabel(provider LLMProvider) string {
	switch provider {
	case ProviderAnthropic:
		return "Anthropic"
	case ProviderGemini:
		return "Gemini"
	default:
		return string(provider)
	}
}

// ParseProviderHTTPResponse parses a provider HTTP status and raw JSON body into an LLMChatCompletionResult,
// enforcing 3xx redirect fail-closed errors, <think> stripping, and fallback <tool_call> extraction.
func ParseProviderHTTPResponse(provider LLMProvider, status int, rawBody []byte, allowedToolNames []string) LLMChatCompletionResult {
	emptyCalls := make([]LLMToolCall, 0)
	label := providerDisplayLabel(provider)
	if status >= 300 && status < 400 {
		return LLMChatCompletionResult{
			OK:        false,
			ToolCalls: emptyCalls,
			Error:     fmt.Sprintf("%s endpoint returned disallowed redirect HTTP %d", label, status),
		}
	}
	if len(rawBody) > MaxLLMResponseBytes {
		return LLMChatCompletionResult{
			OK:        false,
			ToolCalls: emptyCalls,
			Error:     fmt.Sprintf("LLM response body exceeds %d byte limit", MaxLLMResponseBytes),
		}
	}

	if status < 200 || status >= 300 {
		var doc map[string]any
		if len(bytes.TrimSpace(rawBody)) > 0 {
			_ = json.Unmarshal(rawBody, &doc)
		}
		return LLMChatCompletionResult{
			OK:        false,
			ToolCalls: emptyCalls,
			Error:     extractProviderErrorMessage(doc, label, status),
		}
	}

	allowedSet := toAllowedSet(allowedToolNames)
	trimmedBody := bytes.TrimSpace(rawBody)

	switch provider {
	case ProviderAnthropic:
		var wire struct {
			Content []struct {
				Type  string          `json:"type"`
				Text  *string         `json:"text"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content"`
			Usage *struct {
				InputTokens  *int `json:"input_tokens"`
				OutputTokens *int `json:"output_tokens"`
			} `json:"usage"`
		}
		if len(trimmedBody) > 0 && trimmedBody[0] == '{' {
			_ = json.Unmarshal(trimmedBody, &wire)
		}
		var textParts []string
		toolCalls := make([]LLMToolCall, 0)
		for _, b := range wire.Content {
			if b.Type == "text" && b.Text != nil {
				textParts = append(textParts, *b.Text)
			} else if b.Type == "tool_use" && allowedSet[b.Name] {
				id := b.ID
				if id == "" {
					id = fmt.Sprintf("anth_%d", len(toolCalls)+1)
				}
				var inputObj map[string]any
				if len(b.Input) > 0 {
					_ = json.Unmarshal(b.Input, &inputObj)
				}
				if inputObj == nil {
					inputObj = map[string]any{}
				}
				toolCalls = append(toolCalls, LLMToolCall{ID: id, Name: b.Name, Arguments: inputObj})
			}
		}
		var usage *LLMTokenUsage
		if wire.Usage != nil {
			tot := 0
			if wire.Usage.InputTokens != nil {
				tot += *wire.Usage.InputTokens
			}
			if wire.Usage.OutputTokens != nil {
				tot += *wire.Usage.OutputTokens
			}
			usage = &LLMTokenUsage{
				PromptTokens:     wire.Usage.InputTokens,
				CompletionTokens: wire.Usage.OutputTokens,
				TotalTokens:      &tot,
			}
		}
		return LLMChatCompletionResult{
			OK:        true,
			Content:   strings.TrimSpace(strings.Join(textParts, "\n")),
			ToolCalls: toolCalls,
			Usage:     usage,
		}

	case ProviderGemini:
		var wire struct {
			Candidates []struct {
				Content *struct {
					Parts []struct {
						Text         *string `json:"text"`
						FunctionCall *struct {
							Name string          `json:"name"`
							Args json.RawMessage `json:"args"`
						} `json:"functionCall"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if len(trimmedBody) > 0 && trimmedBody[0] == '{' {
			_ = json.Unmarshal(trimmedBody, &wire)
		}
		var textParts []string
		toolCalls := make([]LLMToolCall, 0)
		if len(wire.Candidates) > 0 && wire.Candidates[0].Content != nil {
			for _, p := range wire.Candidates[0].Content.Parts {
				if p.Text != nil {
					textParts = append(textParts, *p.Text)
				}
				if p.FunctionCall != nil && allowedSet[p.FunctionCall.Name] {
					var args map[string]any
					if len(p.FunctionCall.Args) > 0 {
						_ = json.Unmarshal(p.FunctionCall.Args, &args)
					}
					if args == nil {
						args = map[string]any{}
					}
					toolCalls = append(toolCalls, LLMToolCall{
						ID:        fmt.Sprintf("gem_%d", len(toolCalls)+1),
						Name:      p.FunctionCall.Name,
						Arguments: args,
					})
				}
			}
		}
		return LLMChatCompletionResult{
			OK:        true,
			Content:   strings.TrimSpace(strings.Join(textParts, "\n")),
			ToolCalls: toolCalls,
		}

	default:
		type wireMsg struct {
			Content   *string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Function *struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		}
		var wire struct {
			Choices []struct {
				Message *wireMsg `json:"message"`
			} `json:"choices"`
			Message *wireMsg `json:"message"`
			Usage   *struct {
				PromptTokens     *int `json:"prompt_tokens"`
				CompletionTokens *int `json:"completion_tokens"`
				TotalTokens      *int `json:"total_tokens"`
			} `json:"usage"`
			PromptEvalCount *int `json:"prompt_eval_count"`
			EvalCount       *int `json:"eval_count"`
		}
		if len(trimmedBody) > 0 && trimmedBody[0] == '{' {
			_ = json.Unmarshal(trimmedBody, &wire)
		}
		var msg *wireMsg
		if len(wire.Choices) > 0 && wire.Choices[0].Message != nil {
			msg = wire.Choices[0].Message
		} else if wire.Message != nil {
			msg = wire.Message
		}
		content := ""
		if msg != nil && msg.Content != nil {
			content = strings.TrimSpace(StripThinkBlocksLinear(*msg.Content))
		}
		toolCalls := make([]LLMToolCall, 0)
		if msg != nil {
			for _, tc := range msg.ToolCalls {
				if tc.Function == nil || !allowedSet[tc.Function.Name] {
					continue
				}
				id := tc.ID
				if id == "" {
					id = fmt.Sprintf("call_%d", len(toolCalls)+1)
				}
				toolCalls = append(toolCalls, LLMToolCall{
					ID:        id,
					Name:      tc.Function.Name,
					Arguments: extractRawJSONToolArgs(tc.Function.Arguments),
				})
			}
		}
		if len(toolCalls) == 0 && len(allowedSet) > 0 {
			toolCalls = ParseFallbackTextToolCalls(content, allowedSet)
		}
		var usage *LLMTokenUsage
		if wire.Usage != nil {
			usage = &LLMTokenUsage{
				PromptTokens:     wire.Usage.PromptTokens,
				CompletionTokens: wire.Usage.CompletionTokens,
				TotalTokens:      wire.Usage.TotalTokens,
			}
		} else if wire.PromptEvalCount != nil {
			tot := *wire.PromptEvalCount
			if wire.EvalCount != nil {
				tot += *wire.EvalCount
			}
			usage = &LLMTokenUsage{PromptTokens: wire.PromptEvalCount, CompletionTokens: wire.EvalCount, TotalTokens: &tot}
		}
		return LLMChatCompletionResult{
			OK:        true,
			Content:   content,
			ToolCalls: toolCalls,
			Usage:     usage,
		}
	}
}

func extractRawJSONToolArgs(raw json.RawMessage) map[string]any {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return map[string]any{}
	}
	if trimmed[0] == '"' {
		var str string
		if json.Unmarshal(trimmed, &str) == nil {
			if parsed := ParseLooseJSONObject(str); parsed != nil {
				return parsed
			}
		}
		return map[string]any{}
	}
	if trimmed[0] == '{' {
		var obj map[string]any
		if json.Unmarshal(trimmed, &obj) == nil && obj != nil {
			return obj
		}
	}
	return map[string]any{}
}

func extractProviderErrorMessage(doc map[string]any, label string, status int) string {
	switch errVal := doc["error"].(type) {
	case string:
		if errVal != "" {
			return errVal
		}
	case map[string]any:
		if msg, ok := errVal["message"].(string); ok && msg != "" {
			return msg
		}
	}
	return fmt.Sprintf("%s HTTP %d", label, status)
}

func toAllowedSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		if n != "" {
			out[n] = true
		}
	}
	return out
}
