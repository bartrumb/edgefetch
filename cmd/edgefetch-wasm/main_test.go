package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestRunWasmCLIExtractsMarkdownAndJSON(t *testing.T) {
	html := `<!doctype html><html><head><title>WASI Extractor</title><meta name="theme-color" content="#112233"></head><body><nav>Menu</nav><main><h1>WASI Extractor</h1><p>Preserves <code>Result&lt;T&gt;</code> in Wasm. Contact alice@example.com for details.</p><img src="https://example.com/a.png" alt="Logo"></main></body></html>`

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

	// --full preserves <nav>Menu</nav>
	out.Reset()
	rcFull := runWasmCLI([]string{"--full"}, strings.NewReader(html), &out, &errBuf)
	if rcFull != 0 || !strings.Contains(out.String(), "Menu") {
		t.Fatalf("expected --full to preserve nav content (rc=%d): %s", rcFull, out.String())
	}

	// --branding includes branding metadata in JSON
	out.Reset()
	rcBrand := runWasmCLI([]string{"--branding", "--json", "--url=https://example.com/docs"}, strings.NewReader(html), &out, &errBuf)
	if rcBrand != 0 || !strings.Contains(out.String(), `"branding"`) || !strings.Contains(out.String(), "#112233") {
		t.Fatalf("expected --branding output (rc=%d): %s", rcBrand, out.String())
	}

	// --images includes image markdown
	out.Reset()
	rcImg := runWasmCLI([]string{"--images", "--url=https://example.com/docs"}, strings.NewReader(html), &out, &errBuf)
	if rcImg != 0 || !strings.Contains(out.String(), "https://example.com/a.png") {
		t.Fatalf("expected --images output (rc=%d): %s", rcImg, out.String())
	}

	// --redact-pii redacts email addresses
	out.Reset()
	rcPII := runWasmCLI([]string{"--redact-pii"}, strings.NewReader(html), &out, &errBuf)
	if rcPII != 0 || strings.Contains(out.String(), "alice@example.com") {
		t.Fatalf("expected --redact-pii to redact email (rc=%d): %s", rcPII, out.String())
	}

	// --query and --max-chars (valid, invalid, non-positive)
	out.Reset()
	rcQuery := runWasmCLI([]string{"--query=Wasm", "--max-chars=20"}, strings.NewReader(html), &out, &errBuf)
	if rcQuery != 0 || len(strings.TrimSpace(out.String())) == 0 || len(strings.TrimSpace(out.String())) > 20 {
		t.Fatalf("unexpected --query/--max-chars output (rc=%d): %q", rcQuery, out.String())
	}
	out.Reset()
	if rcInvalidMax := runWasmCLI([]string{"--max-chars=0", "--max-chars=-5", "--max-chars=abc"}, strings.NewReader("<main><p>Keep</p></main>"), &out, &errBuf); rcInvalidMax != 0 || !strings.Contains(out.String(), "Keep") {
		t.Fatalf("expected non-positive/invalid --max-chars to be ignored (rc=%d): %s", rcInvalidMax, out.String())
	}

	// --help and -h
	for _, flag := range []string{"--help", "-h"} {
		out.Reset()
		if rcHelp := runWasmCLI([]string{flag}, strings.NewReader(""), &out, &errBuf); rcHelp != 0 || !strings.Contains(out.String(), "Usage: edgefetch-wasm") {
			t.Fatalf("expected usage for %s (rc=%d): %s", flag, rcHelp, out.String())
		}
	}

	// Empty stdin without --json produces empty stdout (false branch of out != "")
	out.Reset()
	if rcEmpty := runWasmCLI(nil, strings.NewReader(""), &out, &errBuf); rcEmpty != 0 || out.Len() != 0 {
		t.Fatalf("expected empty output for empty stdin (rc=%d): %q", rcEmpty, out.String())
	}

	// Stdin read error returns 1 and writes error to stderr
	out.Reset()
	errBuf.Reset()
	if rcErr := runWasmCLI(nil, iotest.ErrReader(errors.New("boom")), &out, &errBuf); rcErr != 1 || !strings.Contains(errBuf.String(), "read stdin: boom") {
		t.Fatalf("expected read stdin error rc=1, got rc=%d stderr=%q", rcErr, errBuf.String())
	}
}

func TestWasmReactorExportsRoundTrip(t *testing.T) {
	_ = efInPtr(1024)

	pat := `(?i)(?P<word>[a-z]+)-\d+`
	copy(wasmInBuf, pat)
	id := efRe2Compile(uint32(len(pat)))
	if id <= 0 {
		t.Fatalf("expected positive re2 handle, got %d", id)
	}
	subj := "🚀 HELLO-42!"
	copy(wasmInBuf, subj)
	if efRe2Test(id, uint32(len(subj))) != 1 {
		t.Fatal("expected efRe2Test match")
	}
	execLen := efRe2Exec(id, uint32(len(subj)))
	if execLen == 0 || efOutLen() != execLen {
		t.Fatalf("expected non-empty efRe2Exec JSON, got %d", execLen)
	}
	_ = efOutPtr()

	rpcReq := `{"op":"sanitize_meta","payload":{"text":"Hello <script>x</script>"}}`
	copy(wasmInBuf, rpcReq)
	callLen := efCall(uint32(len(rpcReq)))
	if callLen == 0 || !strings.Contains(string(wasmOutBuf[:callLen]), "&lt;script>") {
		t.Fatalf("unexpected efCall output: %q", string(wasmOutBuf[:callLen]))
	}

	rawMeta := `{"op":"has_unicode_tag","meta":null}`
	rawBody := "clean text"
	copy(wasmInBuf, rawMeta)
	copy(wasmInBuf[len(rawMeta):], rawBody)
	rawLen := efCallRaw(uint32(len(rawMeta)), uint32(len(rawMeta)+len(rawBody)))
	if rawLen == 0 || !strings.Contains(string(wasmOutBuf[:rawLen]), `"hit":false`) {
		t.Fatalf("unexpected efCallRaw output: %q", string(wasmOutBuf[:rawLen]))
	}

	strMeta := `{"op":"sanitize_markdown","meta":{"baseUrl":"https://example.com/"}}`
	strBody := "Hi <script>alert(1)</script>"
	copy(wasmInBuf, strMeta)
	copy(wasmInBuf[len(strMeta):], strBody)
	strLen := efCallRawStr(uint32(len(strMeta)), uint32(len(strMeta)+len(strBody)))
	if strLen == 0 || strings.Contains(string(wasmOutBuf[:strLen]), "<script") || !strings.HasPrefix(string(wasmOutBuf[:strLen]), "Hi") {
		t.Fatalf("unexpected efCallRawStr output: %q", string(wasmOutBuf[:strLen]))
	}
}
