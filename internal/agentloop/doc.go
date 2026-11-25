// Package agentloop implements EdgeFetch's vendor-neutral BYO-LLM configuration,
// origin/path-prefix API key isolation, SSRF validation, log redaction, provider
// wire codecs (OpenAI/OpenRouter/Compatible, Anthropic, Gemini, Ollama, Workers AI),
// JSON Schema validation, <1ms dynamic BM25 adapter intent routing, remote MCP tool
// schema sanitization, and the callback-driven /v1/agent research loop engine.
//
// The package has zero net/http or crypto/tls dependencies so it compiles cleanly to
// both WASI WASM (GOOS=wasip1 GOARCH=wasm) and native Go binaries (--mode=hub).
package agentloop
