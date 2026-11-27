package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateServerSecurity(t *testing.T) {
	t.Parallel()
	// Non-loopback without token or explicit opt-in must fail closed.
	if err := validateServerSecurity(":8080", "", false); err == nil {
		t.Fatal("SECURITY: expected unauthenticated :8080 bind to fail closed")
	}
	if err := validateServerSecurity("0.0.0.0:8080", "", false); err == nil {
		t.Fatal("SECURITY: expected unauthenticated 0.0.0.0:8080 bind to fail closed")
	}
	// Short token (< 24 chars) must fail closed even on loopback.
	if err := validateServerSecurity("127.0.0.1:8080", "too-short", false); err == nil {
		t.Fatal("SECURITY: expected < 24 char server token to be rejected")
	}
	// Strong token (>= 24 chars) on 0.0.0.0:8080 is allowed.
	if err := validateServerSecurity(":8080", "0123456789abcdef0123456789abcdef", false); err != nil {
		t.Fatalf("expected strong token accepted: %v", err)
	}
	// Strict loopback bind without token is allowed for local development.
	if err := validateServerSecurity("127.0.0.1:8080", "", false); err != nil {
		t.Fatalf("expected loopback 127.0.0.1:8080 accepted: %v", err)
	}
	if err := validateServerSecurity("localhost:8080", "", false); err != nil {
		t.Fatalf("expected loopback localhost:8080 accepted: %v", err)
	}
	if err := validateServerSecurity("[::1]:8080", "", false); err != nil {
		t.Fatalf("expected loopback [::1]:8080 accepted: %v", err)
	}
	// Explicit isolated-bridge opt-in (--allow-unauthenticated) is allowed.
	if err := validateServerSecurity(":8080", "", true); err != nil {
		t.Fatalf("expected explicit allowUnauthenticated accepted: %v", err)
	}
}

func TestNewHTTPServerAndTransports(t *testing.T) {
	t.Parallel()
	srv := newHTTPServer("127.0.0.1:8080", http.NotFoundHandler())
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("expected ReadHeaderTimeout=10s, got %s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 30*time.Second {
		t.Fatalf("expected ReadTimeout=30s, got %s", srv.ReadTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Fatalf("expected IdleTimeout=120s, got %s", srv.IdleTimeout)
	}

	ct := newCrawlTransport(45*time.Second, 3)
	if !ct.ForceAttemptHTTP2 || ct.MaxIdleConnsPerHost != 3 || ct.Proxy != nil {
		t.Fatalf("unexpected crawl transport settings: %+v", ct)
	}
	ht := newHubTransport()
	if !ht.ForceAttemptHTTP2 || ht.MaxIdleConnsPerHost != 2 || ht.Proxy != nil {
		t.Fatalf("unexpected hub transport settings: %+v", ht)
	}
}

func TestFlagEnvAndAgentModeHelpers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	haOpts := filepath.Join(dir, "options.json")
	if err := os.WriteFile(haOpts, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if !shouldRunAgent([]string{"--mode=agent"}, "", "") {
		t.Fatal("expected --mode=agent to select agent mode")
	}
	if shouldRunAgent([]string{"--mode=server"}, "agent", haOpts) {
		t.Fatal("expected explicit --mode=server flag to override env and HAOS file")
	}
	if !shouldRunAgent(nil, "AGENT", "") {
		t.Fatal("expected EDGEFETCH_MODE=agent to select agent mode")
	}
	if shouldRunAgent(nil, "server", haOpts) {
		t.Fatal("expected EDGEFETCH_MODE=server to override HAOS file")
	}
	if !shouldRunAgent(nil, "", haOpts) {
		t.Fatal("expected existing /data/options.json to default to agent mode")
	}
	if shouldRunAgent(nil, "", filepath.Join(dir, "missing.json")) {
		t.Fatal("expected missing options.json to default to server mode")
	}
	if m := resolveRuntimeModes([]string{"--mode=hub,agent"}, "", ""); !m.hub || !m.agent || m.server {
		t.Fatalf("expected hybrid hub+agent modes, got %+v", m)
	}
	if m := resolveRuntimeModes(nil, "controller", ""); !m.hub || m.agent {
		t.Fatalf("expected controller alias to enable hub mode, got %+v", m)
	}

	if got := firstNonEmpty("  ", "", " alpha ", "beta"); got != "alpha" {
		t.Fatalf("firstNonEmpty = %q, want alpha", got)
	}
	if !hasFlag([]string{"--foo", "--allow-unauthenticated"}, "--allow-unauthenticated") {
		t.Fatal("hasFlag missed --allow-unauthenticated")
	}
	if got := flagValue([]string{"--addr=127.0.0.1:9090"}, "--addr="); got != "127.0.0.1:9090" {
		t.Fatalf("flagValue = %q", got)
	}
	if !isTruthyEnv("YES") || !isTruthyEnv("1") || isTruthyEnv("0") || isTruthyEnv("") {
		t.Fatal("isTruthyEnv mismatch")
	}
	if isLoopbackBind("bad-addr") {
		t.Fatal("expected invalid bind addr not treated as loopback")
	}
	hosts := splitCSV(" docs.example.com, , api.example.com ")
	if len(hosts) != 2 || hosts[0] != "docs.example.com" || hosts[1] != "api.example.com" {
		t.Fatalf("splitCSV = %+v", hosts)
	}
	if splitCSV("   ") != nil {
		t.Fatal("expected empty splitCSV to return nil")
	}
}

func TestCLIVersionHelpAndDoctor(t *testing.T) {
	t.Parallel()
	if !isOneShotCLI([]string{"version"}) || !isOneShotCLI([]string{"doctor"}) || !isOneShotCLI([]string{"scrape"}) || !isOneShotCLI([]string{"--help"}) {
		t.Fatal("expected one-shot CLI args recognized")
	}
	if isOneShotCLI([]string{"--mode=server"}) || isOneShotCLI(nil) {
		t.Fatal("daemon flags must not be intercepted as one-shot CLI")
	}

	var out, errBuf bytes.Buffer
	if code := runOneShotCLI(context.Background(), []string{"help"}, &out, &errBuf, cliDeps{}); code != 0 || !strings.Contains(out.String(), "edgefetch scrape") {
		t.Fatalf("help failed: code=%d out=%q", code, out.String())
	}

	out.Reset()
	if code := runOneShotCLI(context.Background(), []string{"version", "--json"}, &out, &errBuf, cliDeps{}); code != 0 {
		t.Fatalf("version --json failed: code=%d", code)
	}
	var ver map[string]any
	if err := json.Unmarshal(out.Bytes(), &ver); err != nil || ver["version"] == "" {
		t.Fatalf("unexpected version JSON: %s (%v)", out.String(), err)
	}

	// Doctor passes with valid wss:// Hub config.
	out.Reset()
	errBuf.Reset()
	code := runOneShotCLI(context.Background(), []string{"doctor", "--json"}, &out, &errBuf, cliDeps{
		getenv: func(k string) string {
			switch k {
			case "EDGEFETCH_HUB_URL":
				return "wss://edgefetch.example.com/agent/ws"
			case "EDGEFETCH_AGENT_TOKEN":
				return "0123456789abcdef0123456789abcdef"
			case "EDGEFETCH_SITE_ID":
				return "mac-mini-1"
			default:
				return ""
			}
		},
	})
	if code != 0 {
		t.Fatalf("doctor --json failed: code=%d stderr=%q out=%s", code, errBuf.String(), out.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc["ok"] != true {
		t.Fatalf("unexpected doctor JSON: %s (%v)", out.String(), err)
	}

	// Doctor fails closed when EDGEFETCH_HUB_URL is invalid / short token.
	out.Reset()
	errBuf.Reset()
	badCode := runOneShotCLI(context.Background(), []string{"doctor"}, &out, &errBuf, cliDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_HUB_URL" {
				return "http://insecure.example.com"
			}
			return ""
		},
	})
	if badCode == 0 {
		t.Fatal("expected doctor to return non-zero on invalid EDGEFETCH_HUB_URL")
	}
}

func TestCLIScrapeOneShotMarkdownAndJSON(t *testing.T) {
	t.Parallel()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("content-type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private/\n"))
		case "/llms.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/docs/guide":
			w.Header().Set("content-type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>CLI Scrape Guide</title></head><body><main><h1>CLI Scrape Guide</h1><p>Returns <code>Promise&lt;void&gt;</code> over HTTP/2.</p></main></body></html>`))
		case "/private/secret":
			w.Header().Set("content-type", "text/html")
			_, _ = w.Write([]byte(`<html><body>secret</body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer origin.Close()

	originAddr := origin.Listener.Addr().String()
	tlsCfg := origin.Client().Transport.(*http.Transport).TLSClientConfig
	mockTransport := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, originAddr)
		},
	}

	deps := cliDeps{
		getenv:    func(string) string { return "" },
		transport: mockTransport,
		allow:     func(*url.URL) error { return nil },
	}

	var out, errBuf bytes.Buffer
	code := runOneShotCLI(context.Background(), []string{"scrape", "--query=Promise", "--max-chars=200", "https://docs.example.com/docs/guide"}, &out, &errBuf, deps)
	if code != 0 {
		t.Fatalf("scrape failed: code=%d stderr=%s", code, errBuf.String())
	}
	// The CLI now shares the hub's full-document extractor, whose sanitizer escapes `<` inside inline code spans
	// fail-closed (pinned in internal/extract/sanitize_test.go); the generic type itself must still be preserved.
	if !strings.Contains(out.String(), "`Promise&lt;void>`") {
		t.Fatalf("expected preserved generic type in CLI markdown, got: %q", out.String())
	}

	// JSON output mode
	out.Reset()
	errBuf.Reset()
	codeJSON := runOneShotCLI(context.Background(), []string{"scrape", "--json", "https://docs.example.com/docs/guide"}, &out, &errBuf, deps)
	if codeJSON != 0 {
		t.Fatalf("scrape --json failed: code=%d stderr=%s", codeJSON, errBuf.String())
	}
	if !strings.Contains(out.String(), `"outcome": "ok"`) {
		t.Fatalf("expected outcome ok in JSON output, got: %s", out.String())
	}

	// Robots.txt disallowed path must return non-zero exit code!
	out.Reset()
	errBuf.Reset()
	codeBlocked := runOneShotCLI(context.Background(), []string{"scrape", "https://docs.example.com/private/secret"}, &out, &errBuf, deps)
	if codeBlocked == 0 {
		t.Fatal("expected robots.txt disallowed URL to return non-zero exit code")
	}

	// Test zero-port stdio MCP server (`edgefetch mcp`) over stdin/stdout JSON-RPC 2.0!
	stdioInput := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scrape","arguments":{"url":"https://docs.example.com/docs/guide"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"doctor","arguments":{}}}`,
	}, "\n") + "\n"

	var stdioOut, stdioErr bytes.Buffer
	if rc := runMCPStdio(context.Background(), strings.NewReader(stdioInput), &stdioOut, &stdioErr, deps); rc != 0 {
		t.Fatalf("runMCPStdio failed: rc=%d stderr=%s", rc, stdioErr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdioOut.String()), "\n")
	// 4 request IDs -> exactly 4 newline-delimited JSON-RPC responses (notification emitted 0 lines)!
	if len(lines) != 4 {
		t.Fatalf("expected 4 JSON-RPC lines, got %d:\n%s", len(lines), stdioOut.String())
	}
	if !strings.Contains(lines[1], `"fetch_batch"`) || !strings.Contains(lines[1], `"map"`) {
		t.Fatalf("expected fetch_batch and map in stdio tools/list: %s", lines[1])
	}
	if !strings.Contains(lines[2], "Promise&lt;void>") || !strings.Contains(lines[3], "ssrf_guard") {
		t.Fatalf("unexpected stdio tool results:\nscrape=%s\ndoctor=%s", lines[2], lines[3])
	}
	if got := truncateUTF8Safe("Hello 世界🚀", 7); got != "Hello 世" {
		t.Fatalf("truncateUTF8Safe split UTF-8 rune: got %q", got)
	}

	// Test `edgefetch install-mcp --config=...` safely preserves existing MCP servers!
	cfgFile := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	if err := os.WriteFile(cfgFile, []byte(`{"mcpServers":{"filesystem":{"command":"npx"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errBuf.Reset()
	if rc := runInstallMCP([]string{"--config=" + cfgFile, "--exe=/usr/local/bin/edgefetch"}, &out, &errBuf); rc != 0 {
		t.Fatalf("runInstallMCP failed: rc=%d stderr=%s", rc, errBuf.String())
	}
	mergedRaw, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mergedRaw), `"filesystem"`) || !strings.Contains(string(mergedRaw), `"/usr/local/bin/edgefetch"`) {
		t.Fatalf("install-mcp did not merge cleanly: %s", string(mergedRaw))
	}
	// Verify `.bak` backup was created before modifying existing config file!
	if _, bakErr := os.Stat(cfgFile + ".bak"); bakErr != nil {
		t.Fatalf("expected .bak backup file for modified config: %v", bakErr)
	}

	// Test `edgefetch init` with Codex TOML (`config.toml`) and `edgefetch crawl --out`!
	codexToml := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(codexToml, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errBuf.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"init", "--config=" + codexToml, `--exe=C:\Users\Dev\bin\edgefetch.exe`}, &out, &errBuf, deps); rc != 0 {
		t.Fatalf("edgefetch init codex toml failed: rc=%d stderr=%s", rc, errBuf.String())
	}
	tomlBytes, _ := os.ReadFile(codexToml)
	if !strings.Contains(string(tomlBytes), "[mcp_servers.edgefetch]") ||
		!strings.Contains(string(tomlBytes), `model = "gpt-5"`) ||
		!strings.Contains(string(tomlBytes), `command = "C:\\Users\\Dev\\bin\\edgefetch.exe"`) {
		t.Fatalf("unexpected codex config.toml output: %s", string(tomlBytes))
	}

	crawlDir := filepath.Join(t.TempDir(), "crawled-md")
	out.Reset()
	errBuf.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"crawl", "--limit=2", "--max-depth=1", "--out=" + crawlDir, "https://docs.example.com/docs/guide"}, &out, &errBuf, deps); rc != 0 {
		t.Fatalf("edgefetch crawl failed: rc=%d stderr=%s", rc, errBuf.String())
	}
	entries, _ := os.ReadDir(crawlDir)
	if len(entries) == 0 {
		t.Fatalf("expected crawl --out=%s to write Markdown files", crawlDir)
	}

	// Test `edgefetch install-service --dry-run` across darwin, linux, and windows templates!
	for _, targetOS := range []string{"darwin", "linux", "windows"} {
		out.Reset()
		errBuf.Reset()
		if rc := runOneShotCLI(context.Background(), []string{"install-service", "--dry-run", "--os=" + targetOS, "--exe=/opt/edgefetch", "--port=9898"}, &out, &errBuf, deps); rc != 0 {
			t.Fatalf("install-service --os=%s failed: %s", targetOS, errBuf.String())
		}
		if !strings.Contains(out.String(), "desktop") || !strings.Contains(out.String(), "9898") {
			t.Fatalf("unexpected install-service output for %s: %s", targetOS, out.String())
		}
	}

	// Test `edgefetch bug-report` redacts secret env values & URL query tokens while emitting sanitized OTLP JSON!
	secretDeps := deps
	secretDeps.getenv = func(k string) string {
		if k == "EDGEFETCH_AGENT_TOKEN" {
			return "top-secret-agent-token-do-not-print"
		}
		if k == "EDGEFETCH_HUB_URL" {
			return "https://private-hub.internal.example"
		}
		return ""
	}
	out.Reset()
	errBuf.Reset()
	if rc := runOneShotCLI(context.Background(), []string{"bug-report", "https://docs.example.com/docs/guide?api_key=leak_me_not#frag"}, &out, &errBuf, secretDeps); rc != 0 {
		t.Fatalf("edgefetch bug-report failed: rc=%d stderr=%s", rc, errBuf.String())
	}
	reportText := out.String()
	if strings.Contains(reportText, "top-secret-agent-token-do-not-print") ||
		strings.Contains(reportText, "private-hub.internal.example") ||
		strings.Contains(reportText, "leak_me_not") ||
		strings.Contains(reportText, "frag") {
		t.Fatalf("SECURITY: bug-report leaked secret token or query/fragment! output:\n%s", reportText)
	}
	if !strings.Contains(reportText, `"resourceSpans"`) || !strings.Contains(reportText, "W3C Traceparent") {
		t.Fatalf("expected sanitized OTLP resourceSpans and W3C Traceparent in bug-report output:\n%s", reportText)
	}
}

func TestBugReportUnreachableURLScrubsEmbeddedQueryAndFragment(t *testing.T) {
	t.Parallel()
	failTransport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial tcp: simulated unreachable host timeout")
		},
	}
	deps := cliDeps{
		getenv:    func(string) string { return "" },
		transport: failTransport,
	}

	target := "https://unreachable.example.com/api/v1/items?api_key=TOP_SECRET_12345#frag"
	for _, args := range [][]string{
		{"bug-report", target},
		{"bug-report", "--json", target},
	} {
		var out, errBuf bytes.Buffer
		rc := runOneShotCLI(context.Background(), args, &out, &errBuf, deps)
		if rc != 0 {
			t.Fatalf("runBugReportCLI(%v) returned %d: stderr=%s", args, rc, errBuf.String())
		}
		combined := out.String() + "\n" + errBuf.String()
		if strings.Contains(combined, "TOP_SECRET_12345") || strings.Contains(combined, "frag") {
			t.Fatalf("SECURITY (M11): bug-report leaked embedded error URL query/fragment for %v:\n%s", args, combined)
		}
		if !strings.Contains(out.String(), "https://unreachable.example.com/api/v1/items") {
			t.Fatalf("expected scrubbed origin+path preserved in bug-report output:\n%s", out.String())
		}
	}
}
