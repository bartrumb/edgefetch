package agentloop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MaxLLMResponseBytes caps raw LLM API JSON responses at 4 MiB (H5).
const MaxLLMResponseBytes = 4 * 1024 * 1024

// LLMToolDefinition describes a structured tool declaration passed to an LLM provider.
type LLMToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// LLMToolCall represents a parsed tool call emitted by an LLM turn.
type LLMToolCall struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// LLMMessage represents a vendor-neutral chat message across system, user, assistant, and tool roles.
type LLMMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content"`
	ToolCalls  []LLMToolCall `json:"toolCalls,omitempty"`
	ToolCallID string        `json:"toolCallId,omitempty"`
	Name       string        `json:"name,omitempty"`
}

// LLMTokenUsage reports prompt, completion, and total token counts when returned by the provider.
type LLMTokenUsage struct {
	PromptTokens     *int `json:"promptTokens,omitempty"`
	CompletionTokens *int `json:"completionTokens,omitempty"`
	TotalTokens      *int `json:"totalTokens,omitempty"`
}

// LLMChatCompletionResult represents the normalized outcome of a single LLM turn.
type LLMChatCompletionResult struct {
	OK        bool           `json:"ok"`
	Content   string         `json:"content"`
	ToolCalls []LLMToolCall  `json:"toolCalls"`
	Usage     *LLMTokenUsage `json:"usage,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// LLMProviderTurnParams holds inputs for building a provider-specific request payload.
type LLMProviderTurnParams struct {
	Config      ResolvedLLMConfig   `json:"config"`
	Messages    []LLMMessage        `json:"messages"`
	Tools       []LLMToolDefinition `json:"tools,omitempty"`
	JSONMode    bool                `json:"jsonMode,omitempty"`
	Temperature *float64            `json:"temperature,omitempty"`
	MaxTokens   *int                `json:"maxTokens,omitempty"`
}

// ProviderHTTPRequest describes an outbound HTTP request (or Workers AI binding call) for an LLM turn.
type ProviderHTTPRequest struct {
	Kind           string            `json:"kind"` // "http" or "workers-ai"
	Method         string            `json:"method,omitempty"`
	Endpoint       string            `json:"endpoint,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	WorkersAIInput map[string]any    `json:"workersAiInput,omitempty"`
}

// LLMTransportRequest is passed to LLMTransportFunc in native Go (--mode=hub) execution.
type LLMTransportRequest struct {
	Provider       LLMProvider
	Model          string
	IsOfflineLocal bool
	HTTP           *ProviderHTTPRequest
	Timeout        time.Duration
}

// LLMTransportResponse is returned by LLMTransportFunc in native Go (--mode=hub) execution.
type LLMTransportResponse struct {
	Status       int
	Body         []byte
	WorkersAIOut map[string]any
}

// LLMTransportFunc executes an outbound LLM HTTP request (with redirect: manual & SSRF dial guard)
// or invokes a Workers AI binding, keeping internal/agentloop free of net/http and crypto/tls.
type LLMTransportFunc func(ctx context.Context, req LLMTransportRequest) (LLMTransportResponse, error)

func encodeURIComponentModel(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '!' || b == '~' || b == '*' || b == '\'' || b == '(' || b == ')' {
			sb.WriteByte(b)
		} else {
			fmt.Fprintf(&sb, "%%%02X", b)
		}
	}
	return sb.String()
}

func marshalCompactJSONNoEscape(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// BuildWorkersAIInput constructs the input payload for Cloudflare Workers AI env.AI.run(model, inputs).
func BuildWorkersAIInput(params LLMProviderTurnParams) map[string]any {
	temp := 0.1
	if params.Temperature != nil {
		temp = *params.Temperature
	}
	maxTok := 2048
	if params.MaxTokens != nil {
		maxTok = *params.MaxTokens
	}
	cfMsgs := make([]map[string]any, 0, len(params.Messages))
	for _, m := range params.Messages {
		if m.Role == "tool" {
			cfMsgs = append(cfMsgs, map[string]any{"role": "tool", "name": m.Name, "content": m.Content})
		} else {
			cfMsgs = append(cfMsgs, map[string]any{"role": m.Role, "content": m.Content})
		}
	}
	out := map[string]any{
		"messages":    cfMsgs,
		"max_tokens":  maxTok,
		"temperature": temp,
	}
	if len(params.Tools) > 0 {
		tList := make([]map[string]any, len(params.Tools))
		for i, t := range params.Tools {
			tList[i] = map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  nonNilMap(t.Parameters),
				},
			}
		}
		out["tools"] = tList
	}
	return out
}

// BuildProviderHTTPRequest builds the outbound HTTP request (or Workers AI binding spec) for any supported LLM provider.
func BuildProviderHTTPRequest(params LLMProviderTurnParams) (*ProviderHTTPRequest, error) {
	cfg := params.Config
	if cfg.Provider == ProviderWorkersAI {
		return &ProviderHTTPRequest{
			Kind:           "workers-ai",
			Endpoint:       "workers-ai://binding",
			WorkersAIInput: BuildWorkersAIInput(params),
		}, nil
	}

	temp := 0.1
	if params.Temperature != nil {
		temp = *params.Temperature
	}
	maxTok := 2048
	if params.MaxTokens != nil {
		maxTok = *params.MaxTokens
	}

	switch cfg.Provider {
	case ProviderAnthropic:
		var sysParts []string
		anthMsgs := make([]map[string]any, 0, len(params.Messages))
		for _, m := range params.Messages {
			switch m.Role {
			case "system":
				sysParts = append(sysParts, m.Content)
			case "user":
				anthMsgs = append(anthMsgs, map[string]any{"role": "user", "content": m.Content})
			case "assistant":
				blocks := make([]map[string]any, 0, 1+len(m.ToolCalls))
				if m.Content != "" {
					blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
				}
				for _, tc := range m.ToolCalls {
					blocks = append(blocks, map[string]any{
						"type":  "tool_use",
						"id":    tc.ID,
						"name":  tc.Name,
						"input": nonNilMap(tc.Arguments),
					})
				}
				var contentVal any = m.Content
				if len(blocks) > 0 {
					contentVal = blocks
				}
				anthMsgs = append(anthMsgs, map[string]any{"role": "assistant", "content": contentVal})
			case "tool":
				anthMsgs = append(anthMsgs, map[string]any{
					"role": "user",
					"content": []map[string]any{
						{"type": "tool_result", "tool_use_id": m.ToolCallID, "content": m.Content},
					},
				})
			}
		}
		bodyMap := map[string]any{
			"model":       cfg.Model,
			"max_tokens":  maxTok,
			"temperature": temp,
			"messages":    anthMsgs,
		}
		if len(sysParts) > 0 {
			bodyMap["system"] = strings.Join(sysParts, "\n\n")
		}
		if len(params.Tools) > 0 {
			tList := make([]map[string]any, len(params.Tools))
			for i, t := range params.Tools {
				tList[i] = map[string]any{
					"name":         t.Name,
					"description":  t.Description,
					"input_schema": nonNilMap(t.Parameters),
				}
			}
			bodyMap["tools"] = tList
		}
		bodyStr, err := marshalCompactJSONNoEscape(bodyMap)
		if err != nil {
			return nil, err
		}
		hdrs := map[string]string{
			"content-type":      "application/json",
			"anthropic-version": "2023-06-01",
		}
		if cfg.APIKey != "" {
			hdrs["x-api-key"] = cfg.APIKey
		}
		return &ProviderHTTPRequest{
			Kind:     "http",
			Method:   "POST",
			Endpoint: AppendEndpointToBaseURL(cfg.BaseURL, "/messages", "/messages"),
			Headers:  hdrs,
			Body:     bodyStr,
		}, nil

	case ProviderGemini:
		var sysParts []string
		contents := make([]map[string]any, 0, len(params.Messages))
		for _, m := range params.Messages {
			switch m.Role {
			case "system":
				sysParts = append(sysParts, m.Content)
			case "user":
				contents = append(contents, map[string]any{
					"role":  "user",
					"parts": []map[string]any{{"text": m.Content}},
				})
			case "assistant":
				parts := make([]map[string]any, 0, 1+len(m.ToolCalls))
				if m.Content != "" {
					parts = append(parts, map[string]any{"text": m.Content})
				}
				for _, tc := range m.ToolCalls {
					parts = append(parts, map[string]any{
						"functionCall": map[string]any{"name": tc.Name, "args": nonNilMap(tc.Arguments)},
					})
				}
				if len(parts) > 0 {
					contents = append(contents, map[string]any{"role": "model", "parts": parts})
				}
			case "tool":
				parsedResp := map[string]any{"result": m.Content}
				var obj map[string]any
				if err := json.Unmarshal([]byte(m.Content), &obj); err == nil && obj != nil {
					parsedResp = obj
				}
				contents = append(contents, map[string]any{
					"role": "user",
					"parts": []map[string]any{
						{"functionResponse": map[string]any{"name": m.Name, "response": parsedResp}},
					},
				})
			}
		}
		genCfg := map[string]any{
			"temperature":     temp,
			"maxOutputTokens": maxTok,
		}
		if params.JSONMode && len(params.Tools) == 0 {
			genCfg["responseMimeType"] = "application/json"
		}
		bodyMap := map[string]any{
			"contents":         contents,
			"generationConfig": genCfg,
		}
		if len(sysParts) > 0 {
			bodyMap["systemInstruction"] = map[string]any{
				"parts": []map[string]any{{"text": strings.Join(sysParts, "\n\n")}},
			}
		}
		if len(params.Tools) > 0 {
			decls := make([]map[string]any, len(params.Tools))
			for i, t := range params.Tools {
				decls[i] = map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  nonNilMap(t.Parameters),
				}
			}
			bodyMap["tools"] = []map[string]any{{"functionDeclarations": decls}}
		}
		bodyStr, err := marshalCompactJSONNoEscape(bodyMap)
		if err != nil {
			return nil, err
		}
		cleanModel := strings.TrimPrefix(cfg.Model, "models/")
		endpoint := AppendEndpointToBaseURL(cfg.BaseURL, "/models/"+encodeURIComponentModel(cleanModel)+":generateContent", "")
		hdrs := map[string]string{"content-type": "application/json"}
		if cfg.APIKey != "" {
			hdrs["x-goog-api-key"] = cfg.APIKey
		}
		return &ProviderHTTPRequest{
			Kind:     "http",
			Method:   "POST",
			Endpoint: endpoint,
			Headers:  hdrs,
			Body:     bodyStr,
		}, nil

	default:
		oaiMsgs := make([]map[string]any, 0, len(params.Messages))
		for _, m := range params.Messages {
			if m.Role == "assistant" && len(m.ToolCalls) > 0 {
				tcs := make([]map[string]any, len(m.ToolCalls))
				for i, tc := range m.ToolCalls {
					argJSON, _ := marshalCompactJSONNoEscape(nonNilMap(tc.Arguments))
					tcs[i] = map[string]any{
						"id":       tc.ID,
						"type":     "function",
						"function": map[string]any{"name": tc.Name, "arguments": argJSON},
					}
				}
				var contentVal any
				if m.Content != "" {
					contentVal = m.Content
				}
				oaiMsgs = append(oaiMsgs, map[string]any{"role": "assistant", "content": contentVal, "tool_calls": tcs})
				continue
			}
			if m.Role == "tool" {
				oaiMsgs = append(oaiMsgs, map[string]any{
					"role": "tool", "tool_call_id": m.ToolCallID, "name": m.Name, "content": m.Content,
				})
				continue
			}
			oaiMsgs = append(oaiMsgs, map[string]any{"role": m.Role, "content": m.Content})
		}

		isNativeOllamaChat := cfg.Provider == ProviderOllama && strings.HasSuffix(stripBaseURLQuery(cfg.BaseURL), "/api/chat")
		bodyMap := map[string]any{"model": cfg.Model, "messages": oaiMsgs}
		if isNativeOllamaChat {
			bodyMap["stream"] = false
			bodyMap["options"] = map[string]any{"temperature": temp, "num_predict": maxTok}
			if params.JSONMode && len(params.Tools) == 0 {
				bodyMap["format"] = "json"
			}
		} else {
			bodyMap["temperature"] = temp
			bodyMap["max_tokens"] = maxTok
			if params.JSONMode && len(params.Tools) == 0 {
				bodyMap["response_format"] = map[string]any{"type": "json_object"}
			}
		}
		if len(params.Tools) > 0 {
			tList := make([]map[string]any, len(params.Tools))
			for i, t := range params.Tools {
				tList[i] = map[string]any{
					"type":     "function",
					"function": map[string]any{"name": t.Name, "description": t.Description, "parameters": nonNilMap(t.Parameters)},
				}
			}
			bodyMap["tools"] = tList
		}
		bodyStr, err := marshalCompactJSONNoEscape(bodyMap)
		if err != nil {
			return nil, err
		}
		endpoint := AppendEndpointToBaseURL(cfg.BaseURL, "/chat/completions", "/chat/completions")
		if isNativeOllamaChat {
			endpoint = AppendEndpointToBaseURL(cfg.BaseURL, "/api/chat", "/api/chat")
		}
		hdrs := map[string]string{"content-type": "application/json"}
		if cfg.APIKey != "" {
			hdrs["authorization"] = "Bearer " + cfg.APIKey
		}
		return &ProviderHTTPRequest{
			Kind:     "http",
			Method:   "POST",
			Endpoint: endpoint,
			Headers:  hdrs,
			Body:     bodyStr,
		}, nil
	}
}

// CompleteLLMTurn executes a single vendor-neutral LLM turn via an injected LLMTransportFunc callback.
func CompleteLLMTurn(ctx context.Context, params LLMProviderTurnParams, timeout time.Duration, transport LLMTransportFunc) LLMChatCompletionResult {
	emptyCalls := make([]LLMToolCall, 0)
	if transport == nil {
		return LLMChatCompletionResult{OK: false, ToolCalls: emptyCalls, Error: "LLM transport callback is nil"}
	}
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	reqSpec, err := BuildProviderHTTPRequest(params)
	if err != nil {
		return LLMChatCompletionResult{OK: false, ToolCalls: emptyCalls, Error: err.Error()}
	}
	allowedNames := make([]string, len(params.Tools))
	for i, t := range params.Tools {
		allowedNames[i] = t.Name
	}
	resp, tErr := transport(ctx, LLMTransportRequest{
		Provider:       params.Config.Provider,
		Model:          params.Config.Model,
		IsOfflineLocal: params.Config.IsOfflineLocal,
		HTTP:           reqSpec,
		Timeout:        timeout,
	})
	if tErr != nil {
		return LLMChatCompletionResult{OK: false, ToolCalls: emptyCalls, Error: tErr.Error()}
	}
	if reqSpec.Kind == "workers-ai" {
		return ParseWorkersAIResponse(resp.WorkersAIOut, allowedNames)
	}
	return ParseProviderHTTPResponse(params.Config.Provider, resp.Status, resp.Body, allowedNames)
}
