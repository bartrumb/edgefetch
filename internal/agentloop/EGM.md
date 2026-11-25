# agentloop

## Overview
Package `agentloop` implements EdgeFetch's vendor-neutral BYO-LLM configuration, origin/path-prefix API key isolation, SSRF target validation, log redaction, provider HTTP/Workers-AI wire codecs (OpenAI/OpenRouter/Compatible, Anthropic, Gemini, Ollama), JSON Schema validation, `< 1 ms` dynamic BM25/domain adapter intent routing, remote MCP tool schema sanitization, and the callback-driven `/v1/agent` research loop state machine. It compiles cleanly to both `GOOS=wasip1 GOARCH=wasm` and native Go binaries without `net/http` or `crypto/tls` dependencies.

## Interface
- `[llm_config.go:ResolveLLMConfig]`, `[llm_config.go:NormalizeProvider]`, `[llm_url.go:ValidateCleanHTTPBaseURL]`, `[llm_url.go:ValidatePublicHTTPSTargetURL]`, `[llm_url.go:MatchesTrustedBaseURLPrefix]`: Resolve operator and per-request BYO-LLM settings with C1/M1 API key isolation and SSRF validation.
- `[llm_redact.go:RedactLLMURLForLog]`, `[llm_redact.go:RedactHeadersForLog]`, `[llm_redact.go:RedactLLMConfigForLog]`: Strip credentials, query/fragment secrets, non-allowlisted path segments, and sensitive headers before logging or returning `llmInfo`.
- `[llm_providers.go:BuildProviderHTTPRequest]`, `[llm_parse.go:ParseProviderHTTPResponse]`, `[llm_providers.go:BuildWorkersAIInput]`, `[llm_parse.go:ParseWorkersAIResponse]`, `[llm_providers.go:CompleteLLMTurn]`: Build and parse OpenAI/OpenRouter/Compatible, Anthropic, Gemini, Ollama (`/v1/chat/completions` and `/api/chat`), and Workers AI turns via `LLMTransportFunc`.
- `[llm_parse.go:StripThinkBlocksLinear]`, `[llm_parse.go:ParseLooseJSONObject]`, `[llm_parse.go:ParseFallbackTextToolCalls]`: Linear `O(N)` `<think>` stripping, code-fence/brace JSON extraction, and quantized local `<tool_call>` fallback parsing.
- `[llm_schema.go:BuildDeterministicSummary]`, `[llm_schema.go:SummarizeMarkdownWithOptionalLLM]`, `[llm_schema.go:ExtractJSONWithOptionalLLM]`, `[llm_schema.go:ValidateDataAgainstJSONSchema]`: Zero-LLM extractive summarization, optional LLM synthesis helpers, and strict + `partialValid` JSON Schema validation.
- `[router.go:DefaultAdapterCatalog]`, `[router.go:DefaultTotalIndexedAdapters]`, `[router.go:FindRelevantAdapters]`: Rank all embedded declarative (`extract.ListDeclarativeAdapters()`) and built-in ATS adapters by domain, slug, token specificity, and category intent with zero 3-source cap.
- `[agent_tools.go:DoesMCPServerSelectorMatchRow]`, `[agent_tools.go:SanitizeRemoteToolSchemaJSON]`, `[agent_tools.go:SanitizeRemoteToolSchemaForLLM]`, `[agent_tools.go:WrapConnectorTextForAgentContext]`: Exact `id`/`slug` MCP selector matching, `[UNTRUSTED_REMOTE_PARAM] ` schema sanitization, and fence-safe untrusted MCP output envelopes.
- `[agent_plan.go:IsURLAllowedByConstraint]`, `[agent_plan.go:FilterSafeAgentBrowserActions]`, `[agent_plan.go:ParseEffortBudgets]`, `[agent_plan.go:ParseAgentLocation]`, `[agent_plan.go:BuildAgentTools]`, `[agent_plan.go:BuildAgentInitialMessages]`, `[agent_plan.go:FormatPublicAgentResponse]`: Scope guardrails, effort/location parsers, prompt/tool builders, and public response formatting.
- `[agent_runner.go:RunAgentLoop]`: Callback-driven (`LLMTransportFunc`, `ToolExecutorFunc`) autonomous BYO-LLM and zero-key deterministic `/v1/agent` loop engine.

## Invariants
- `[llm_config.go:ResolveLLMConfig]`: Releases provider-specific env keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`) only when `inferredProvider` and case-sensitive `baseUrl` path prefix match the official or operator-configured prefix (`C1`/`M1`), releases `EDGEFETCH_LLM_API_KEY` only when neither `provider` nor `baseUrl` was overridden, blocks non-public/IP-literal per-request `baseUrl` values unless matching `EDGEFETCH_LLM_BASE_URL` or explicit `EDGEFETCH_ALLOW_LOCAL_LLM_OVERRIDE=true` loopback ports (`11434`, `1234`, `8000`, `8080`), and rejects `..`, `;`, double-encoded separators, and empty segments in `baseUrl` and `model`.
- `[llm_redact.go:RedactLLMURLForLog]`, `[llm_redact.go:RedactLLMConfigForLog]`: Replaces every non-allowlisted or percent-encoded path segment and non-RPC `:suffix` with `[REDACTED]`, strips userinfo/query/hash, and omits `apiKey`.
- `[llm_parse.go:ParseProviderHTTPResponse]`, `[llm_parse.go:StripThinkBlocksLinear]`, `[llm_parse.go:ParseFallbackTextToolCalls]`: Fails closed on HTTP `3xx` redirects and responses `> 4 MiB` (`MaxLLMResponseBytes`), and terminates in `O(1)` on unclosed `<think>` / `<tool_call>` runs (`M12`).
- `[agent_tools.go:DoesMCPServerSelectorMatchRow]`, `[agent_tools.go:SanitizeRemoteToolSchemaJSON]`, `[agent_plan.go:BuildAgentInitialMessages]`, `[agent_plan.go:FilterSafeAgentBrowserActions]`: Matches `mcpServers` strictly by exact `id` or `slug` (`S7`), strips `title`/`default`/`examples`/`$defs`/`$comment`/`const`/raw `enum` and prefixes descriptions with `[UNTRUSTED_REMOTE_PARAM] ` (`P7`), never interpolates remote tool or property names into the `system` prompt (`H4`), and allowlists only `{click, fill, write, type, press, scroll, wait, select}` browser actions (`M8`).
- `[agent_runner.go:RunAgentLoop]`: Enforces `strictConstrainToURLs` before invoking `ExecuteTool`, escalates `Visibility` to `"private"` when touching connected MCPs, sets `Partial`/`PartialSchemaValid` on `maxSteps`/`maxPages` exhaustion, and skips persistence and `ThreadMemory` when `ZeroDataRetention` is true.

## Side Effects
- Pure in-memory computation; all network I/O, storage persistence, and event streaming occur exclusively through caller-supplied callbacks (`LLMTransportFunc`, `ToolExecutorFunc`, `OnPersist`, `OnEvent`).

## Verification
- Run: `go test -race -count=1 ./internal/agentloop`
- WASM check: `GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go vet ./cmd/edgefetch-wasm`
