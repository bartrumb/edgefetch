package main

import (
	"bytes"
	"encoding/json"

	"github.com/bartrumb/edgefetch/v2/internal/agentloop"
)

func init() {
	phase2AgentRPC = handlePhase2AgentRPC
	phase2AgentRawRPC = handlePhase2AgentRawRPC
}

func handlePhase2AgentRawRPC(op string, meta json.RawMessage, rawStr string) (any, bool, error) {
	switch op {
	case "llm_parse_loose_json":
		return map[string]any{
			"object": agentloop.ParseLooseJSONObject(rawStr),
		}, true, nil

	case "llm_parse_response":
		var m struct {
			Provider         agentloop.LLMProvider `json:"provider"`
			Status           int                   `json:"status"`
			AllowedToolNames []string              `json:"allowedToolNames"`
		}
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &m); err != nil {
				return nil, true, err
			}
		}
		res := agentloop.ParseProviderHTTPResponse(m.Provider, m.Status, []byte(rawStr), m.AllowedToolNames)
		return res, true, nil

	case "llm_deterministic_summary":
		var m struct {
			Title string `json:"title"`
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &m)
		}
		return map[string]any{
			"summary": agentloop.BuildDeterministicSummary(rawStr, m.Title),
		}, true, nil

	default:
		return nil, false, nil
	}
}

func handlePhase2AgentRPC(op string, payload json.RawMessage) (any, bool, error) {
	switch op {
	case "llm_resolve_config":
		var p agentloop.ResolveLLMConfigInput
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return agentloop.ResolveLLMConfig(p), true, nil

	case "llm_redact_url":
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": agentloop.RedactLLMURLForLog(p.URL)}, true, nil

	case "llm_redact_config":
		var p struct {
			Config *agentloop.LoggableLLMConfigInput `json:"config"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"out": agentloop.RedactLLMConfigForLog(p.Config)}, true, nil

	case "llm_build_request":
		var p agentloop.LLMProviderTurnParams
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		req, err := agentloop.BuildProviderHTTPRequest(p)
		if err != nil {
			return nil, true, err
		}
		return req, true, nil

	case "llm_parse_workers_ai":
		var p struct {
			RawOut           map[string]any `json:"rawOut"`
			AllowedToolNames []string       `json:"allowedToolNames"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		if p.RawOut == nil {
			p.RawOut = map[string]any{}
		}
		return agentloop.ParseWorkersAIResponse(p.RawOut, p.AllowedToolNames), true, nil

	case "llm_validate_schema":
		var rawFields map[string]json.RawMessage
		if err := json.Unmarshal(payload, &rawFields); err != nil {
			return nil, true, err
		}
		var hasDataFlag *bool
		if rawHD, ok := rawFields["hasData"]; ok {
			_ = json.Unmarshal(rawHD, &hasDataFlag)
		}
		rawDataBytes, dataKeyPresent := rawFields["data"]
		hasData := dataKeyPresent
		if hasDataFlag != nil {
			hasData = *hasDataFlag
		}
		var dataVal any
		if hasData && len(bytes.TrimSpace(rawDataBytes)) > 0 {
			_ = json.Unmarshal(rawDataBytes, &dataVal)
		}
		var schemaMap map[string]any
		if rawSch, ok := rawFields["schema"]; ok && len(bytes.TrimSpace(rawSch)) > 0 && !bytes.Equal(bytes.TrimSpace(rawSch), []byte("null")) {
			if err := json.Unmarshal(rawSch, &schemaMap); err != nil {
				// Non-object schema behaves identically to undefined/omitted schema.
				schemaMap = nil
			}
		}
		return agentloop.ValidateDataAgainstJSONSchema(dataVal, hasData, schemaMap), true, nil

	case "llm_build_prompts":
		var p struct {
			Mode     string         `json:"mode"` // "summarize" or "extract_json"
			Markdown string         `json:"markdown"`
			Title    string         `json:"title"`
			URL      string         `json:"url"`
			Prompt   string         `json:"prompt"`
			Schema   map[string]any `json:"schema"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		if p.Mode == "extract_json" {
			return map[string]any{
				"messages": agentloop.BuildExtractJSONMessages(p.URL, p.Title, p.Prompt, p.Schema, p.Markdown),
			}, true, nil
		}
		return map[string]any{
			"messages": agentloop.BuildSummarizeMessages(p.Markdown, p.Title),
		}, true, nil

	case "agent_find_adapters":
		var p agentloop.FindRelevantAdaptersInput
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"matches":              agentloop.FindRelevantAdapters(p),
			"totalIndexedAdapters": agentloop.DefaultTotalIndexedAdapters(),
		}, true, nil

	case "agent_mcp_selector_match":
		var p struct {
			Selector string `json:"selector"`
			RowID    string `json:"rowId"`
			RowSlug  string `json:"rowSlug"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"matched": agentloop.DoesMCPServerSelectorMatchRow(p.Selector, p.RowID, p.RowSlug),
		}, true, nil

	case "agent_sanitize_tool_schema":
		var p struct {
			Node  json.RawMessage `json:"node"`
			Depth int             `json:"depth"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"schema": agentloop.SanitizeRemoteToolSchemaJSON(p.Node, p.Depth),
		}, true, nil

	case "agent_check_url_constraint":
		var p struct {
			CandidateURL    string   `json:"candidateUrl"`
			AllowedSeeds    []string `json:"allowedSeeds"`
			StrictConstrain bool     `json:"strictConstrain"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"allowed": agentloop.IsURLAllowedByConstraint(p.CandidateURL, p.AllowedSeeds, p.StrictConstrain),
		}, true, nil

	case "agent_filter_browser_actions":
		var p struct {
			Actions []any `json:"actions"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"actions": agentloop.FilterSafeAgentBrowserActions(p.Actions),
		}, true, nil

	case "agent_plan_config":
		var p struct {
			Effort     string   `json:"effort"`
			MaxSteps   *float64 `json:"maxSteps"`
			MaxPages   *float64 `json:"maxPages"`
			MaxCredits *float64 `json:"maxCredits"`
			Country    string   `json:"country"`
			Languages  []string `json:"languages"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		effort, maxSteps, maxPages := agentloop.ParseEffortBudgets(p.Effort, p.MaxSteps, p.MaxPages, p.MaxCredits)
		country, langs, acceptLang := agentloop.ParseAgentLocation(p.Country, p.Languages)
		return map[string]any{
			"effort":               effort,
			"maxSteps":             maxSteps,
			"maxPages":             maxPages,
			"country":              country,
			"languages":            langs,
			"acceptLanguageHeader": acceptLang,
		}, true, nil

	case "agent_build_tools":
		var p struct {
			StrictConstrainToURLs bool                               `json:"strictConstrainToURLs"`
			HasSearchCollection   bool                               `json:"hasSearchCollection"`
			ConnectedMCPs         []agentloop.ConnectedMCPServerSpec `json:"connectedMcps"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"tools": agentloop.BuildAgentTools(p.StrictConstrainToURLs, p.HasSearchCollection, p.ConnectedMCPs),
		}, true, nil

	case "agent_build_messages":
		var p agentloop.AgentInitialMessagesInput
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"messages": agentloop.BuildAgentInitialMessages(p),
		}, true, nil

	case "agent_format_response":
		var p struct {
			Record       agentloop.AgentRunRecord `json:"record"`
			HasData      bool                     `json:"hasData"`
			IncludeTrace bool                     `json:"includeTrace"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		if p.HasData {
			p.Record.HasData = true
		}
		return map[string]any{
			"out": agentloop.FormatPublicAgentResponse(p.Record, p.IncludeTrace),
		}, true, nil

	case "agent_wrap_mcp_text":
		var p struct {
			Text       string            `json:"text"`
			MaxChars   int               `json:"maxChars"`
			Attributes map[string]string `json:"attributes"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{
			"out": agentloop.WrapConnectorTextForAgentContext(p.Text, p.MaxChars, p.Attributes),
		}, true, nil

	default:
		return nil, false, nil
	}
}
