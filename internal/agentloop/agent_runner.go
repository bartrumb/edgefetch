package agentloop

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

const agentRunTTLMs = 24 * 60 * 60 * 1000

// AgentEvidenceItem represents a scraped page or MCP tool output collected during an agent run.
type AgentEvidenceItem struct {
	URL       string         `json:"url"`
	Title     string         `json:"title,omitempty"`
	Markdown  string         `json:"markdown"`
	JSON      map[string]any `json:"json,omitempty"`
	FromMCP   bool           `json:"fromMcp,omitempty"`
	MCPServer string         `json:"mcpServer,omitempty"`
	MCPTool   string         `json:"mcpTool,omitempty"`
}

// AgentToolInvocation describes a tool call dispatched by RunAgentLoop to ToolExecutorFunc.
type AgentToolInvocation struct {
	Step      int
	ToolCall  LLMToolCall
	PagesRead int
	MaxPages  int
}

// AgentToolExecutionOutput is returned by ToolExecutorFunc to RunAgentLoop.
type AgentToolExecutionOutput struct {
	OK                 bool
	SummaryForLLM      string
	BudgetExhausted    bool
	ConsumedPage       bool
	TouchedMCP         bool
	Sources            []AgentSourceRef
	Evidence           []AgentEvidenceItem
	DiscoveredAdapters []string
	TraceSpan          *AgentTraceSpan
}

// ToolExecutorFunc executes a single agent tool call (`scrape_url`, `web_search`, `map_site`, `interact_browser`,
// `search_jobs`, `search_collection`, `query_mcp`) in the host runtime (native Go `--mode=hub` or test harness).
type ToolExecutorFunc func(ctx context.Context, inv AgentToolInvocation) (AgentToolExecutionOutput, error)

// AgentLoopCallbacks wires host I/O, persistence, cancellation, and SSE event streaming into RunAgentLoop.
type AgentLoopCallbacks struct {
	LLMTransport LLMTransportFunc
	ExecuteTool  ToolExecutorFunc
	IsCancelled  func() bool
	OnPersist    func(rec *AgentRunRecord) error
	OnEvent      func(event string, data map[string]any)
	NowMs        func() int64
}

// RunAgentLoopInput configures a complete autonomous or deterministic /v1/agent execution.
type RunAgentLoopInput struct {
	AgentID               string
	UserID                string
	ThreadID              string
	Prompt                string
	SeedURLs              []string
	StrictConstrainToURLs bool
	Effort                AgentEffort
	MaxSteps              int
	MaxPages              int
	ZeroDataRetention     bool
	HasSearchCollection   bool
	Schema                map[string]any
	LLMConfig             *ResolvedLLMConfig
	ConnectedMCPs         []ConnectedMCPServerSpec
	RoutedMCPs            []string
	PriorThread           *AgentRunRecord
}

// RunAgentLoop executes the complete /v1/agent state machine (initial BM25 adapter routing, multi-step BYO-LLM
// tool loop or zero-key deterministic research fallback, schema/Markdown synthesis, partial budget recovery, and ZDR).
func RunAgentLoop(ctx context.Context, in RunAgentLoopInput, cb AgentLoopCallbacks) (*AgentRunRecord, error) {
	nowFn := cb.NowMs
	if nowFn == nil {
		nowFn = func() int64 { return time.Now().UnixMilli() }
	}
	isCancelled := func() bool {
		if ctx.Err() != nil {
			return true
		}
		return cb.IsCancelled != nil && cb.IsCancelled()
	}

	prompt := strings.TrimSpace(in.Prompt)
	if prompt == "" {
		return nil, fmt.Errorf("missing_prompt: prompt must be a non-empty string")
	}
	if len(prompt) > 10000 {
		return nil, fmt.Errorf("prompt_too_long: prompt exceeds 10,000 character maximum")
	}

	effort, maxSteps, maxPages := ParseEffortBudgets(string(in.Effort), optFloat(in.MaxSteps), optFloat(in.MaxPages), nil)
	now := nowFn()
	threadID := in.ThreadID
	if threadID == "" {
		if in.PriorThread != nil && in.PriorThread.ThreadID != "" {
			threadID = in.PriorThread.ThreadID
		} else {
			threadID = in.AgentID
		}
	}

	routerStart := nowFn()
	initialMatches := FindRelevantAdapters(FindRelevantAdaptersInput{
		Query: prompt,
		URLs:  in.SeedURLs,
		Limit: 8,
	})
	routedOrder := make([]string, 0, len(in.RoutedMCPs)+len(initialMatches))
	routedSeen := map[string]bool{}
	addRouted := func(id string) {
		if id != "" && !routedSeen[id] {
			routedSeen[id] = true
			routedOrder = append(routedOrder, id)
		}
	}
	for _, slug := range in.RoutedMCPs {
		addRouted("mcp:" + slug)
	}
	for _, m := range initialMatches {
		addRouted(m.ID)
	}

	previewMatches := make([]map[string]any, len(initialMatches))
	for i, m := range initialMatches {
		previewMatches[i] = map[string]any{"id": m.ID, "category": m.Category, "score": m.Score}
	}

	var llmInfo map[string]any
	if in.LLMConfig != nil {
		llmInfo = RedactLLMConfigForLog(&LoggableLLMConfigInput{
			Provider:       in.LLMConfig.Provider,
			BaseURL:        in.LLMConfig.BaseURL,
			APIKey:         in.LLMConfig.APIKey,
			Model:          in.LLMConfig.Model,
			IsOfflineLocal: in.LLMConfig.IsOfflineLocal,
		})
	}

	initSources := make([]AgentSourceRef, 0)
	if in.PriorThread != nil {
		initSources = append(initSources, in.PriorThread.Sources...)
	}

	rec := &AgentRunRecord{
		ID:                    in.AgentID,
		UserID:                in.UserID,
		ThreadID:              threadID,
		Status:                StatusProcessing,
		Prompt:                prompt,
		URLs:                  append([]string(nil), in.SeedURLs...),
		StrictConstrainToURLs: in.StrictConstrainToURLs,
		Effort:                effort,
		MaxSteps:              maxSteps,
		MaxPages:              maxPages,
		StepsUsed:             0,
		PagesRead:             0,
		ZeroDataRetention:     in.ZeroDataRetention,
		RoutedMCPs:            append([]string(nil), in.RoutedMCPs...),
		LLMUsed:               in.LLMConfig != nil,
		LLMInfo:               llmInfo,
		RoutedAdapters:        append([]string(nil), routedOrder...),
		Sources:               initSources,
		CreatedAt:             now,
		UpdatedAt:             now,
		ExpiresAt:             now + agentRunTTLMs,
		Trace: []AgentTraceSpan{
			{
				Sequence:   1,
				SpanID:     "sp_router_init",
				Kind:       "router",
				Name:       "dynamic_adapter_router",
				Status:     "ok",
				StartedAt:  routerStart,
				DurationMs: max64(0, nowFn()-routerStart),
				Input: map[string]any{
					"query":                sliceRunesMax(prompt, 240),
					"seedUrlCount":         len(in.SeedURLs),
					"totalIndexedAdapters": DefaultTotalIndexedAdapters(),
				},
				OutputPreview: previewMatches,
			},
		},
	}

	persistIfAllowed := func() {
		if !rec.ZeroDataRetention && cb.OnPersist != nil {
			_ = cb.OnPersist(rec)
		}
	}
	persistIfAllowed()

	seq := len(rec.Trace)
	pushSpan := func(sp AgentTraceSpan) {
		seq++
		sp.Sequence = seq
		sp.SpanID = fmt.Sprintf("sp_%d", seq)
		rec.Trace = append(rec.Trace, sp)
		rec.UpdatedAt = nowFn()
		if cb.OnEvent != nil {
			cb.OnEvent("agent.trace", spanToMap(sp))
		}
	}

	if cb.OnEvent != nil {
		cb.OnEvent("agent.started", map[string]any{
			"id":             rec.ID,
			"threadId":       rec.ThreadID,
			"effort":         rec.Effort,
			"maxSteps":       rec.MaxSteps,
			"maxPages":       rec.MaxPages,
			"routedAdapters": rec.RoutedAdapters,
			"llmUsed":        rec.LLMUsed,
		})
	}

	touchedConnectedMCP := in.PriorThread != nil && (in.PriorThread.Visibility == "private" ||
		len(in.PriorThread.RoutedMCPs) > 0 ||
		strings.Contains(strings.ToLower(in.PriorThread.ThreadMemory), "untrusted_mcp"))
	if touchedConnectedMCP {
		rec.Visibility = "private"
	}

	replayedEnvelope := ""
	priorID := ""
	var gathered []AgentEvidenceItem
	if in.PriorThread != nil && in.PriorThread.ThreadMemory != "" {
		priorID = in.PriorThread.ID
		replayedEnvelope = WrapConnectorTextForAgentContext(in.PriorThread.ThreadMemory, 4500, map[string]string{
			"source":   "prior_thread",
			"threadId": in.PriorThread.ID,
		})
		gathered = append(gathered, AgentEvidenceItem{
			URL:      "thread://prior-context",
			Title:    "Prior Thread Findings",
			Markdown: in.PriorThread.ThreadMemory,
			FromMCP:  true,
		})
	}

	addSource := func(src AgentSourceRef) {
		if src.URL == "" || strings.HasPrefix(src.URL, "thread://") {
			return
		}
		exists := false
		for _, existing := range rec.Sources {
			if existing.URL == src.URL {
				exists = true
				break
			}
		}
		if !exists {
			rec.Sources = append(rec.Sources, src)
		}
		if src.ExtractorID != "" {
			addRouted(src.ExtractorID)
			rec.RoutedAdapters = append([]string(nil), routedOrder...)
		}
	}

	dispatchTool := func(step int, tc LLMToolCall) AgentToolExecutionOutput {
		t0 := nowFn()
		if tc.Name == "find_extractors" {
			q, _ := tc.Arguments["query"].(string)
			if q == "" {
				q = prompt
			}
			cat, _ := tc.Arguments["category"].(string)
			matches := FindRelevantAdapters(FindRelevantAdaptersInput{Query: q, Category: cat, Limit: 10})
			ids := make([]string, len(matches))
			for i, m := range matches {
				ids[i] = m.ID
				addRouted(m.ID)
			}
			rec.RoutedAdapters = append([]string(nil), routedOrder...)
			spanIn := map[string]any{"query": q}
			if cat != "" {
				spanIn["category"] = cat
			}
			pushSpan(AgentTraceSpan{
				Kind:          "router",
				Name:          "find_extractors",
				Status:        "ok",
				StartedAt:     t0,
				DurationMs:    max64(0, nowFn()-t0),
				Input:         spanIn,
				OutputPreview: ids,
			})
			jb, _ := json.MarshalIndent(map[string]any{"matches": matches}, "", "  ")
			return AgentToolExecutionOutput{OK: true, SummaryForLLM: string(jb)}
		}

		// Built-in guardrails enforced before invoking host ToolExecutorFunc:
		switch tc.Name {
		case "web_search", "search_jobs":
			if rec.StrictConstrainToURLs {
				return AgentToolExecutionOutput{
					OK:            false,
					SummaryForLLM: fmt.Sprintf(`{"error":"strictConstrainToURLs is active; %s is disabled."}`, tc.Name),
				}
			}
		case "scrape_url", "map_site", "interact_browser":
			targetURL, _ := tc.Arguments["url"].(string)
			targetURL = strings.TrimSpace(targetURL)
			if !IsURLAllowedByConstraint(targetURL, rec.URLs, rec.StrictConstrainToURLs) {
				jb, _ := marshalCompactJSONNoEscape(map[string]any{
					"error":       "url_outside_strict_constraint",
					"allowedUrls": rec.URLs,
				})
				return AgentToolExecutionOutput{OK: false, SummaryForLLM: jb}
			}
			if tc.Name == "interact_browser" {
				if rawActs, ok := tc.Arguments["actions"].([]any); ok {
					tc.Arguments["actions"] = FilterSafeAgentBrowserActions(rawActs)
				}
			}
		}

		if (tc.Name == "scrape_url" || tc.Name == "interact_browser" || tc.Name == "search_jobs") && rec.PagesRead >= rec.MaxPages {
			return AgentToolExecutionOutput{
				OK:              false,
				BudgetExhausted: true,
				SummaryForLLM:   `{"error":"maxPages budget reached"}`,
			}
		}

		if cb.ExecuteTool == nil {
			return AgentToolExecutionOutput{OK: false, SummaryForLLM: `{"error":"tool_executor_not_configured"}`}
		}
		if tc.Name == "scrape_url" || tc.Name == "interact_browser" || tc.Name == "search_jobs" {
			rec.PagesRead++
		}
		out, err := cb.ExecuteTool(ctx, AgentToolInvocation{
			Step:      step,
			ToolCall:  tc,
			PagesRead: rec.PagesRead,
			MaxPages:  rec.MaxPages,
		})
		if err != nil {
			return AgentToolExecutionOutput{OK: false, SummaryForLLM: fmt.Sprintf(`{"error":%q}`, err.Error())}
		}
		if out.TouchedMCP {
			touchedConnectedMCP = true
			rec.Visibility = "private"
		}
		for _, dID := range out.DiscoveredAdapters {
			addRouted(dID)
		}
		rec.RoutedAdapters = append([]string(nil), routedOrder...)
		for _, s := range out.Sources {
			addSource(s)
		}
		gathered = append(gathered, out.Evidence...)
		if out.TraceSpan != nil {
			pushSpan(*out.TraceSpan)
		} else {
			status := "error"
			if out.OK {
				status = "ok"
			}
			pushSpan(AgentTraceSpan{
				Kind:       "tool_call",
				Name:       tc.Name,
				Status:     status,
				StartedAt:  t0,
				DurationMs: max64(0, nowFn()-t0),
				Input:      tc.Arguments,
			})
		}
		return out
	}

	hitBudget := false
	if in.LLMConfig != nil {
		tools := BuildAgentTools(rec.StrictConstrainToURLs, in.HasSearchCollection, in.ConnectedMCPs)
		messages := BuildAgentInitialMessages(AgentInitialMessagesInput{
			Prompt:                      prompt,
			SeedURLs:                    rec.URLs,
			StrictConstrainToURLs:       rec.StrictConstrainToURLs,
			MaxSteps:                    rec.MaxSteps,
			MaxPages:                    rec.MaxPages,
			HasConnectedMCPs:            len(in.ConnectedMCPs) > 0,
			InitialMatches:              initialMatches,
			Schema:                      in.Schema,
			PriorThreadID:               priorID,
			ReplayedPriorThreadEnvelope: replayedEnvelope,
		})

		finalAssistantText := ""
		for step := 0; step < rec.MaxSteps; step++ {
			if isCancelled() {
				rec.Status = StatusCancelled
				rec.StopReason = StopCancelled
				break
			}
			rec.StepsUsed = step + 1
			turnStart := nowFn()
			temp := 0.1
			maxTok := 2048
			llmRes := CompleteLLMTurn(ctx, LLMProviderTurnParams{
				Config:      *in.LLMConfig,
				Messages:    messages,
				Tools:       tools,
				Temperature: &temp,
				MaxTokens:   &maxTok,
			}, 45*time.Second, cb.LLMTransport)

			tcNames := make([]string, len(llmRes.ToolCalls))
			for i, tc := range llmRes.ToolCalls {
				tcNames[i] = tc.Name
			}
			turnPreview := map[string]any{
				"toolCalls": tcNames,
				"hasText":   llmRes.Content != "",
			}
			if llmRes.Usage != nil {
				turnPreview["usage"] = llmRes.Usage
			}
			if llmRes.Error != "" {
				turnPreview["error"] = llmRes.Error
			}
			turnStatus := "ok"
			if !llmRes.OK {
				turnStatus = "error"
			}
			pushSpan(AgentTraceSpan{
				Kind:          "llm_turn",
				Name:          string(in.LLMConfig.Provider) + ":" + in.LLMConfig.Model,
				Status:        turnStatus,
				StartedAt:     turnStart,
				DurationMs:    max64(0, nowFn()-turnStart),
				Input:         map[string]any{"step": step + 1, "toolCount": len(tools)},
				OutputPreview: turnPreview,
			})

			if !llmRes.OK {
				rec.Error = llmRes.Error
				if rec.Error == "" {
					rec.Error = "LLM provider call failed"
				}
				rec.Status = StatusFailed
				rec.StopReason = StopFailed
				break
			}
			if len(llmRes.ToolCalls) == 0 {
				finalAssistantText = llmRes.Content
				break
			}

			messages = append(messages, LLMMessage{
				Role:      "assistant",
				Content:   llmRes.Content,
				ToolCalls: llmRes.ToolCalls,
			})

			callLimit := len(llmRes.ToolCalls)
			if callLimit > 6 {
				callLimit = 6
			}
			for _, tc := range llmRes.ToolCalls[:callLimit] {
				if cb.OnEvent != nil {
					cb.OnEvent("agent.action", map[string]any{
						"step":      step + 1,
						"tool":      tc.Name,
						"arguments": tc.Arguments,
					})
				}
				tOut := dispatchTool(step+1, tc)
				messages = append(messages, LLMMessage{
					Role:       "tool",
					ToolCallID: tc.ID,
					Name:       tc.Name,
					Content:    tOut.SummaryForLLM,
				})
				if tOut.BudgetExhausted {
					hitBudget = true
				}
			}

			persistIfAllowed()
			if hitBudget || rec.PagesRead >= rec.MaxPages {
				hitBudget = true
				break
			}
			if step+1 >= rec.MaxSteps {
				hitBudget = true
			}
		}

		if rec.Status != StatusCancelled && rec.Status != StatusFailed {
			synthStart := nowFn()
			if in.Schema != nil {
				var directParsed map[string]any
				if finalAssistantText != "" {
					directParsed = ParseLooseJSONObject(finalAssistantText)
				}
				if len(directParsed) > 0 && !hitBudget {
					rec.Data = directParsed
					rec.HasData = true
				} else {
					combinedMD := formatEvidenceForLLMSynthesis(gathered, 5000, true)
					fallbackDraft := finalAssistantText
					if touchedConnectedMCP && finalAssistantText != "" {
						fallbackDraft = WrapConnectorTextForAgentContext(finalAssistantText, 5000, map[string]string{"source": "assistant_draft"})
					}
					srcMD := combinedMD
					if srcMD == "" {
						srcMD = fallbackDraft
					}
					seedURL := "https://edgefetch.local/agent"
					if len(rec.URLs) > 0 {
						seedURL = rec.URLs[0]
					}
					var heur map[string]any
					for _, e := range gathered {
						if len(e.JSON) > 0 {
							heur = e.JSON
							break
						}
					}
					extracted, _ := ExtractJSONWithOptionalLLM(ctx, srcMD, "", seedURL, prompt, in.Schema, heur, in.LLMConfig, cb.LLMTransport)
					rec.Data = extracted
					rec.HasData = true
				}
				val := ValidateDataAgainstJSONSchema(rec.Data, true, in.Schema)
				rec.SchemaValid = &val.Valid
				if hitBudget {
					rec.Partial = true
					rec.PartialSchemaValid = &val.PartialValid
				}
			} else {
				if finalAssistantText == "" && len(gathered) > 0 {
					combinedMD := formatEvidenceForLLMSynthesis(gathered, 4000, false)
					sumText, _ := SummarizeMarkdownWithOptionalLLM(ctx, combinedMD, sliceRunesMax(prompt, 120), in.LLMConfig, cb.LLMTransport)
					finalAssistantText = sumText
				}
				rec.Markdown = finalAssistantText
				rec.Data = map[string]any{
					"answer":  finalAssistantText,
					"sources": rec.Sources,
				}
				rec.HasData = true
				if hitBudget {
					rec.Partial = true
				}
			}
			synthPreview := map[string]any{"partial": rec.Partial}
			if rec.SchemaValid != nil {
				synthPreview["schemaValid"] = *rec.SchemaValid
			}
			pushSpan(AgentTraceSpan{
				Kind:          "synthesis",
				Name:          "final_synthesis",
				Status:        "ok",
				StartedAt:     synthStart,
				DurationMs:    max64(0, nowFn()-synthStart),
				OutputPreview: synthPreview,
			})
			rec.Status = StatusCompleted
			if hitBudget {
				rec.StopReason = StopBudgetReached
			} else {
				rec.StopReason = StopCompleted
			}
		}
	} else {
		// Zero-Key Deterministic Research Mode
		rec.StepsUsed = 1
		candidateURLs := append([]string(nil), rec.URLs...)
		if len(candidateURLs) == 0 && !rec.StrictConstrainToURLs && len(gathered) == 0 {
			maxRes := rec.MaxPages
			if maxRes > 5 {
				maxRes = 5
			}
			sOut := dispatchTool(1, LLMToolCall{
				ID:        "det_search_1",
				Name:      "web_search",
				Arguments: map[string]any{"query": prompt, "maxResults": maxRes},
			})
			if sOut.OK {
				var hits []struct {
					URL string `json:"url"`
				}
				if json.Unmarshal([]byte(sOut.SummaryForLLM), &hits) == nil {
					capHits := rec.MaxPages
					if capHits > 4 {
						capHits = 4
					}
					for _, h := range hits {
						if h.URL != "" && len(candidateURLs) < capHits {
							candidateURLs = append(candidateURLs, h.URL)
						}
					}
				}
			}
		}
		scrapeCap := len(candidateURLs)
		if scrapeCap > rec.MaxPages {
			scrapeCap = rec.MaxPages
		}
		for i := 0; i < scrapeCap; i++ {
			if isCancelled() {
				break
			}
			dispatchTool(1, LLMToolCall{
				ID:        fmt.Sprintf("det_scrape_%d", i+1),
				Name:      "scrape_url",
				Arguments: map[string]any{"url": candidateURLs[i], "query": prompt},
			})
		}

		combinedMD := formatEvidenceDeterministic(gathered)
		rec.Markdown = combinedMD
		if in.Schema != nil {
			links := make([]string, len(rec.Sources))
			for i, s := range rec.Sources {
				links[i] = s.URL
			}
			var titles []string
			for _, e := range gathered {
				if e.Title != "" {
					titles = append(titles, e.Title)
				}
			}
			docTitle := strings.Join(titles, " | ")
			if docTitle == "" {
				docTitle = sliceRunesMax(prompt, 100)
			}
			merged, _, _ := extract.ExtractStructuredJSONFromPageWithDiagnostics("", extract.ExtractedDocumentFull{
				Markdown: combinedMD,
				Text:     combinedMD,
				Title:    docTitle,
				Links:    links,
				Images:   []extract.ImageInfo{},
				Branding: extract.BrandingProfile{Title: sliceRunesMax(prompt, 100)},
			}, in.Schema, prompt)
			if merged == nil {
				merged = map[string]any{}
			}
			for _, ev := range gathered {
				for k, v := range ev.JSON {
					if cur, exists := merged[k]; !exists || cur == nil || cur == "" {
						merged[k] = v
					}
				}
			}
			if props, ok := in.Schema["properties"].(map[string]any); ok {
				if _, wantSources := props["sources"]; wantSources {
					if curS, okS := merged["sources"].([]string); !okS || len(curS) == 0 {
						merged["sources"] = links
					}
				}
				if _, wantSummary := props["summary"]; wantSummary && combinedMD != "" {
					if detSum := BuildDeterministicSummary(combinedMD, sliceRunesMax(prompt, 100)); detSum != "" {
						merged["summary"] = detSum
					}
				}
			}
			rec.Data = merged
			rec.HasData = true
			val := ValidateDataAgainstJSONSchema(rec.Data, true, in.Schema)
			rec.SchemaValid = &val.Valid
		} else {
			detSum := BuildDeterministicSummary(combinedMD, sliceRunesMax(prompt, 100))
			rec.Data = map[string]any{
				"answer":   detSum,
				"markdown": combinedMD,
				"sources":  rec.Sources,
			}
			rec.HasData = true
		}

		if isCancelled() {
			rec.Status = StatusCancelled
			rec.StopReason = StopCancelled
		} else {
			rec.Status = StatusCompleted
			rec.StopReason = StopCompleted
		}
	}

	fin := nowFn()
	rec.FinishedAt = &fin
	rec.UpdatedAt = fin
	if !rec.ZeroDataRetention {
		rawMem := ""
		if rec.Markdown != "" {
			rawMem = "Findings:\n" + sliceRunesMax(rec.Markdown, 4000)
		} else if rec.HasData || rec.Data != nil {
			if jb, err := marshalCompactJSONNoEscape(rec.Data); err == nil {
				rawMem = "Structured data:\n" + sliceRunesMax(jb, 4000)
			}
		}
		safeMem := ""
		if rawMem != "" {
			if touchedConnectedMCP || rec.Visibility == "private" {
				safeMem = WrapConnectorTextForAgentContext(rawMem, 4000, map[string]string{
					"source":  "thread_memory",
					"agentId": rec.ID,
				})
			} else {
				safeMem = SanitizeMCPMarkdownOutput(rawMem, "", 4100)
			}
		}
		memParts := []string{"Previous prompt: " + prompt}
		if safeMem != "" {
			memParts = append(memParts, safeMem)
		}
		rec.ThreadMemory = strings.Join(memParts, "\n\n")
	}
	persistIfAllowed()

	if cb.OnEvent != nil {
		cb.OnEvent("agent.completed", FormatPublicAgentResponse(*rec, false))
	}
	return rec, nil
}

func optFloat(n int) *float64 {
	if n <= 0 {
		return nil
	}
	f := float64(n)
	return &f
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func spanToMap(sp AgentTraceSpan) map[string]any {
	out := map[string]any{
		"sequence":   sp.Sequence,
		"spanId":     sp.SpanID,
		"kind":       sp.Kind,
		"name":       sp.Name,
		"status":     sp.Status,
		"startedAt":  sp.StartedAt,
		"durationMs": sp.DurationMs,
	}
	if sp.Input != nil {
		out["input"] = sp.Input
	}
	if sp.OutputPreview != nil {
		out["outputPreview"] = sp.OutputPreview
	}
	return out
}
