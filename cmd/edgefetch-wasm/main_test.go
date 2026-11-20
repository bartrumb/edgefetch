package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunWasmCLIExtractsMarkdownAndJSON(t *testing.T) {
	html := `<!doctype html><html><head><title>WASI Extractor</title></head><body><nav>Menu</nav><main><h1>WASI Extractor</h1><p>Preserves <code>Result&lt;T&gt;</code> in Wasm.</p></main></body></html>`

	var out, errBuf bytes.Buffer
	rc := runWasmCLI([]string{"--url=https://example.com/docs"}, strings.NewReader(html), &out, &errBuf)
	if rc != 0 || !strings.Contains(out.String(), "`Result<T>`") || strings.Contains(out.String(), "Menu") {
		t.Fatalf("unexpected wasm markdown output (rc=%d): %s", rc, out.String())
	}

	out.Reset()
	rcJSON := runWasmCLI([]string{"--json", "--url=https://example.com/docs"}, strings.NewReader(html), &out, &errBuf)
	if rcJSON != 0 || !strings.Contains(out.String(), `"title": "WASI Extractor"`) || !strings.Contains(out.String(), "Result<T>") {
		t.Fatalf("unexpected wasm json output (rc=%d): %s", rcJSON, out.String())
	}
}
