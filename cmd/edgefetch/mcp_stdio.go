package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/hub"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
)

// runMCPStdio implements a zero-daemon, zero-port, zero-token Model Context Protocol (MCP) server over stdin/stdout
// (`{"command": "edgefetch", "args": ["mcp"]}`) for Claude Desktop, Cursor, VS Code, Windsurf, Zed, and LM Studio.
func runMCPStdio(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, deps cliDeps) int {
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	if deps.transport == nil {
		deps.transport = newCrawlTransport(60*time.Second, 2)
	}
	if deps.allow == nil {
		deps.allow = crawl.PublicHTTPS
	}

	ua := firstNonEmpty(deps.getenv("EDGEFETCH_USER_AGENT"), deps.getenv("CRAWLER_USER_AGENT"), crawl.DefaultUserAgent)
	if err := crawl.ValidateUserAgent(ua); err != nil {
		ua = crawl.DefaultUserAgent
	}

	// Never log to stdout in stdio MCP mode; stdout belongs strictly to newline-delimited JSON-RPC 2.0 frames.
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(deps.transport, deps.allow, ua, silentLog)
	otelExp := otel.NewExporterFromEnv(deps.getenv, "edgefetch-mcp-stdio", agent.Version, newHubTransport())
	crawler.SetOtelExporter(otelExp)
	defer func() { _ = crawler.Close() }()

	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)

	writeRPC := func(obj map[string]any) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(obj); err != nil {
			return
		}
		_, _ = stdout.Write(buf.Bytes())
	}

	for scanner.Scan() {
		if ctx.Err() != nil {
			return 0
		}
		rawLine := strings.TrimSpace(scanner.Text())
		if rawLine == "" {
			continue
		}

		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      any             `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal([]byte(rawLine), &req); err != nil {
			writeRPC(map[string]any{
				"jsonrpc": "2.0",
				"id":      nil,
				"error":   map[string]any{"code": -32700, "message": "Parse error"},
			})
			continue
		}

		// JSON-RPC notifications (no id or notifications/*) produce zero output frames.
		if strings.HasPrefix(req.Method, "notifications/") || req.ID == nil {
			continue
		}

		switch req.Method {
		case "ping":
			writeRPC(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{}})

		case "initialize":
			var initParams struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(req.Params, &initParams)
			proto := "2025-03-26"
			if initParams.ProtocolVersion == "2024-11-05" || initParams.ProtocolVersion == "2025-06-18" || initParams.ProtocolVersion == "2025-11-25" {
				proto = initParams.ProtocolVersion
			}
			writeRPC(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"protocolVersion": proto,
					"capabilities":    map[string]any{"tools": map[string]any{}},
					"serverInfo":      map[string]any{"name": "edgefetch-local", "version": agent.Version},
				},
			})

		case "tools/list":
			writeRPC(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"tools": []map[string]any{
						{
							"name":        "scrape",
							"description": "Polite HTTP/2 + optional OS Chrome/Edge JS-rendered scrape of a public HTTPS URL into clean GFM Markdown.",
							"inputSchema": map[string]any{
								"type":     "object",
								"required": []string{"url"},
								"properties": map[string]any{
									"url":      map[string]any{"type": "string", "description": "Public https:// URL to scrape"},
									"render":   map[string]any{"type": "boolean", "description": "Render JS using local headless Chrome/Edge/Chromium"},
									"query":    map[string]any{"type": "string", "description": "Optional BM25 passage filter query"},
									"maxChars": map[string]any{"type": "integer", "description": "Optional Markdown character limit"},
								},
							},
						},
						{
							"name":        "fetch_url",
							"description": "Low-level HTTP/2 fetch returning status, httptrace phase timings, headers, and extracted metadata.",
							"inputSchema": map[string]any{
								"type":     "object",
								"required": []string{"url"},
								"properties": map[string]any{
									"url":  map[string]any{"type": "string"},
									"kind": map[string]any{"type": "string", "enum": []string{"scrape", "render", "pdf", "json", "page", "text"}},
								},
							},
						},
						{
							"name":        "fetch_batch",
							"description": "Politely fetch up to 25 public HTTPS URLs with per-host serialization, positive jitter, and robots.txt checks.",
							"inputSchema": map[string]any{
								"type":     "object",
								"required": []string{"urls"},
								"properties": map[string]any{
									"urls":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": 25},
									"includeBody": map[string]any{"type": "boolean", "default": false},
									"kind":        map[string]any{"type": "string", "enum": []string{"scrape", "json", "page", "text"}},
								},
							},
						},
						{
							"name":        "map",
							"description": "Zero-cost site URL discovery across /llms.txt, /robots.txt Sitemap directives, /sitemap.xml, and homepage links.",
							"inputSchema": map[string]any{
								"type":     "object",
								"required": []string{"url"},
								"properties": map[string]any{
									"url":    map[string]any{"type": "string", "description": "Origin or page https:// URL to map"},
									"search": map[string]any{"type": "string", "description": "Optional substring filter on discovered URLs"},
									"limit":  map[string]any{"type": "integer", "default": 100},
								},
							},
						},
						{
							"name":        "doctor",
							"description": "Verify local SSRF guard, loopback CONNECT proxy, OS Chrome/Edge/Chromium binary, and pdftotext.",
							"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
						},
					},
				},
			})

		case "tools/call":
			var cp struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
				Meta      struct {
					Traceparent string `json:"traceparent"`
					TraceID     string `json:"x-trace-id"`
					SpanID      string `json:"x-span-id"`
				} `json:"_meta"`
			}
			if err := json.Unmarshal(req.Params, &cp); err != nil {
				writeRPC(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"error":   map[string]any{"code": -32602, "message": "Invalid params"},
				})
				continue
			}
			var metaHdr http.Header
			if cp.Meta.Traceparent != "" || cp.Meta.TraceID != "" || cp.Meta.SpanID != "" {
				metaHdr = http.Header{}
				if cp.Meta.Traceparent != "" {
					metaHdr.Set("Traceparent", cp.Meta.Traceparent)
				}
				if cp.Meta.TraceID != "" {
					metaHdr.Set("X-Trace-Id", cp.Meta.TraceID)
				}
				if cp.Meta.SpanID != "" {
					metaHdr.Set("X-Span-Id", cp.Meta.SpanID)
				}
			}
			writeRPC(executeMCPStdioToolCall(ctx, req.ID, cp.Name, cp.Arguments, metaHdr, crawler, otelExp, deps, silentLog))

		default:
			writeRPC(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"error":   map[string]any{"code": -32601, "message": "Method not found"},
			})
		}
	}
	_ = stderr
	return 0
}

func executeMCPStdioToolCall(
	ctx context.Context,
	id any,
	name string,
	arguments json.RawMessage,
	metaHdr http.Header,
	crawler *crawl.Crawler,
	otelExp *otel.Exporter,
	deps cliDeps,
	silentLog *slog.Logger,
) map[string]any {
	tc := otel.ExtractOrNew(metaHdr)
	toolSpan := otel.StartSpan(otelExp, tc, "edgefetch.mcp.tool", 2, map[string]any{
		"mcp.tool.name": name,
		"mcp.transport": "stdio",
	})
	traceHdr := http.Header{}
	otel.InjectHeaders(traceHdr, tc, tc.SpanID)
	callCtx := otel.WithTraceContext(ctx, tc)

	isErr := false
	errMsg := ""
	defer func() {
		toolSpan.End(!isErr, errMsg)
	}()

	switch name {
	case "doctor":
		var docOut bytes.Buffer
		rc := runDoctor([]string{"--json"}, &docOut, io.Discard, deps)
		if rc != 0 {
			isErr = true
			errMsg = "doctor failed"
		}
		return stdioToolResult(id, strings.TrimSpace(docOut.String()), false)

	case "scrape":
		var sp struct {
			URL      string `json:"url"`
			Render   bool   `json:"render"`
			Query    string `json:"query"`
			MaxChars int    `json:"maxChars"`
		}
		_ = json.Unmarshal(arguments, &sp)
		if sp.URL != "" {
			toolSpan.SetAttribute("url.full", otel.SanitizeURL(sp.URL))
		}
		kind := classify.KindScrape
		renderMode := "auto"
		if browser.FindChromeBinary() == "" {
			renderMode = "off"
		}
		if sp.Render {
			kind = classify.KindRender
			renderMode = "always"
		}
		call := crawl.FetchCall{
			MaxSeconds: 45,
			Options: crawl.Options{
				Concurrency:   1,
				RespectRobots: crawl.Bool(true),
				DiscoverLlms:  crawl.Bool(true),
			},
			Requests: []crawl.Request{{
				ID:              "stdio-1",
				URL:             strings.TrimSpace(sp.URL),
				Kind:            kind,
				Formats:         []string{"markdown", "links"},
				OnlyMainContent: crawl.Bool(true),
				DiscoverLlms:    crawl.Bool(true),
				Query:           sp.Query,
				RenderMode:      renderMode,
			}},
		}
		if code, msg, ok := crawl.ValidateCallWithCrawler(crawler, call, deps.allow); !ok {
			isErr = true
			errMsg = code + ": " + msg
			return stdioToolResult(id, errMsg, true)
		}
		rep := crawl.ExecuteCallWithTrace(callCtx, crawler, call, traceHdr, silentLog, nil)
		if len(rep.Results) == 0 {
			isErr = true
			errMsg = "empty_reply"
			return stdioToolResult(id, "empty_reply", true)
		}
		res := rep.Results[0]
		if sp.MaxChars > 0 {
			res.Markdown = truncateUTF8Safe(res.Markdown, sp.MaxChars)
		}
		txt := marshalJSONNoEscapeHTML(res, "  ")
		isErr = res.Outcome != classify.OutcomeOK
		if isErr {
			errMsg = res.Problem
			if errMsg == "" {
				errMsg = string(res.Outcome)
			}
		}
		return stdioToolResult(id, txt, isErr)

	case "fetch_url":
		var fp struct {
			URL  string `json:"url"`
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(arguments, &fp)
		if fp.URL != "" {
			toolSpan.SetAttribute("url.full", otel.SanitizeURL(fp.URL))
		}
		k := classify.Kind(fp.Kind)
		if k == "" {
			k = classify.KindScrape
		}
		call := crawl.FetchCall{
			MaxSeconds: 45,
			Options:    crawl.Options{Concurrency: 1, IncludeBody: true, RespectRobots: crawl.Bool(true)},
			Requests:   []crawl.Request{{ID: "stdio-1", URL: strings.TrimSpace(fp.URL), Kind: k}},
		}
		if code, msg, ok := crawl.ValidateCallWithCrawler(crawler, call, deps.allow); !ok {
			isErr = true
			errMsg = code + ": " + msg
			return stdioToolResult(id, errMsg, true)
		}
		rep := crawl.ExecuteCallWithTrace(callCtx, crawler, call, traceHdr, silentLog, nil)
		txt := marshalJSONNoEscapeHTML(rep, "  ")
		return stdioToolResult(id, txt, false)

	case "fetch_batch":
		var bp struct {
			URLs        []string `json:"urls"`
			IncludeBody bool     `json:"includeBody"`
			Kind        string   `json:"kind"`
		}
		_ = json.Unmarshal(arguments, &bp)
		toolSpan.SetAttribute("crawler.requests", len(bp.URLs))
		if len(bp.URLs) == 0 || len(bp.URLs) > 25 {
			isErr = true
			errMsg = "invalid_urls: provide 1 to 25 https:// URLs"
			return stdioToolResult(id, errMsg, true)
		}
		toolSpan.SetAttribute("url.full", otel.SanitizeURL(bp.URLs[0]))
		k := classify.Kind(bp.Kind)
		if k == "" {
			k = classify.KindPage
		}
		reqs := make([]crawl.Request, 0, len(bp.URLs))
		for i, rawU := range bp.URLs {
			reqs = append(reqs, crawl.Request{
				ID:   fmt.Sprintf("batch-%d", i+1),
				URL:  strings.TrimSpace(rawU),
				Kind: k,
			})
		}
		call := crawl.FetchCall{
			MaxSeconds: 60,
			Options:    crawl.Options{Concurrency: 2, IncludeBody: bp.IncludeBody, RespectRobots: crawl.Bool(true)},
			Requests:   reqs,
		}
		if code, msg, ok := crawl.ValidateCallWithCrawler(crawler, call, deps.allow); !ok {
			isErr = true
			errMsg = code + ": " + msg
			return stdioToolResult(id, errMsg, true)
		}
		rep := crawl.ExecuteCallWithTrace(callCtx, crawler, call, traceHdr, silentLog, nil)
		if bp.IncludeBody {
			for i := range rep.Results {
				rep.Results[i].Body = truncateUTF8Safe(rep.Results[i].Body, 3072)
			}
		}
		txt := marshalJSONNoEscapeHTML(rep, "  ")
		return stdioToolResult(id, txt, false)

	case "map":
		var mp struct {
			URL    string `json:"url"`
			Search string `json:"search"`
			Limit  int    `json:"limit"`
		}
		_ = json.Unmarshal(arguments, &mp)
		if mp.URL != "" {
			toolSpan.SetAttribute("url.full", otel.SanitizeURL(mp.URL))
		}
		uParsed, err := url.Parse(strings.TrimSpace(mp.URL))
		if err != nil || uParsed.Scheme != "https" || uParsed.Host == "" {
			isErr = true
			errMsg = "invalid_url: provide a valid https:// URL"
			return stdioToolResult(id, errMsg, true)
		}
		if mp.Limit <= 0 || mp.Limit > 500 {
			mp.Limit = 100
		}
		origin := "https://" + uParsed.Host
		call := crawl.FetchCall{
			MaxSeconds: 30,
			Options:    crawl.Options{Concurrency: 2, IncludeBody: true, RespectRobots: crawl.Bool(true)},
			Requests: []crawl.Request{
				{ID: "llms", URL: origin + "/llms.txt", Kind: classify.KindText, Accept: "text/plain"},
				{ID: "sitemap", URL: origin + "/sitemap.xml", Kind: classify.KindText, Accept: "application/xml"},
				{ID: "home", URL: strings.TrimSpace(mp.URL), Kind: classify.KindScrape, Formats: []string{"links"}},
			},
		}
		if code, msg, ok := crawl.ValidateCallWithCrawler(crawler, call, deps.allow); !ok {
			isErr = true
			errMsg = code + ": " + msg
			return stdioToolResult(id, errMsg, true)
		}
		rep := crawl.ExecuteCallWithTrace(callCtx, crawler, call, traceHdr, silentLog, nil)
		seen := map[string]struct{}{}
		var links []string
		filterLower := strings.ToLower(strings.TrimSpace(mp.Search))
		addCandidate := func(cand string) {
			cand = strings.TrimSpace(cand)
			if !strings.HasPrefix(cand, "https://") || len(links) >= mp.Limit {
				return
			}
			if filterLower != "" && !strings.Contains(strings.ToLower(cand), filterLower) {
				return
			}
			if _, exists := seen[cand]; !exists {
				seen[cand] = struct{}{}
				links = append(links, cand)
			}
		}
		for _, r := range rep.Results {
			for _, l := range r.Links {
				addCandidate(l)
			}
			for _, m := range reSitemapLocURL.FindAllStringSubmatch(r.Body, 500) {
				if len(m) > 1 {
					addCandidate(m[1])
				}
			}
			for _, m := range reMarkdownHTTPURL.FindAllStringSubmatch(r.Body, 500) {
				if len(m) > 1 {
					addCandidate(m[1])
				}
			}
		}
		out := map[string]any{
			"ok":    true,
			"url":   origin,
			"total": len(links),
			"links": links,
		}
		return stdioToolResult(id, marshalJSONNoEscapeHTML(out, "  "), false)

	default:
		isErr = true
		errMsg = "Unknown tool: " + name
		return map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"error":   map[string]any{"code": -32601, "message": errMsg},
		}
	}
}

var (
	reSitemapLocURL   = regexp.MustCompile(`(?i)<loc>\s*(https://[^<\s]+)\s*</loc>`)
	reMarkdownHTTPURL = regexp.MustCompile(`\]\((https://[^)\s]+)\)`)
)

// truncateUTF8Safe slices a UTF-8 string cleanly at `maxRunes` characters without ever splitting a multi-byte UTF-8 rune.
func truncateUTF8Safe(s string, maxRunes int) string {
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	count := 0
	for idx := range s {
		if count == maxRunes {
			return s[:idx]
		}
		count++
	}
	return s
}

func marshalJSONNoEscapeHTML(v any, indent string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	if err := enc.Encode(v); err != nil {
		return "{}"
	}
	return strings.TrimRight(buf.String(), "\n")
}

func stdioToolResult(id any, text string, isErr bool) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"isError": isErr,
			"content": []map[string]any{
				{"type": "text", "text": text},
			},
		},
	}
}

type mcpClientTarget struct {
	slug   string
	client string
	path   string
	format string // "json" or "toml"
}

// allMCPClientTargets returns the 6 major AI coding/desktop harness config locations (`edgefetch init` / `install-mcp`).
func allMCPClientTargets(goos, homeDir, appData string) []mcpClientTarget {
	var out []mcpClientTarget
	switch goos {
	case "windows":
		if appData != "" {
			out = append(out, mcpClientTarget{"claude-desktop", "Claude Desktop", filepath.Join(appData, "Claude", "claude_desktop_config.json"), "json"})
		}
	case "darwin":
		if homeDir != "" {
			out = append(out, mcpClientTarget{"claude-desktop", "Claude Desktop", filepath.Join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "json"})
		}
	default:
		if homeDir != "" {
			out = append(out, mcpClientTarget{"claude-desktop", "Claude Desktop", filepath.Join(homeDir, ".config", "Claude", "claude_desktop_config.json"), "json"})
		}
	}
	if homeDir != "" {
		out = append(out,
			mcpClientTarget{"cursor", "Cursor", filepath.Join(homeDir, ".cursor", "mcp.json"), "json"},
			mcpClientTarget{"claude-code", "Claude Code", filepath.Join(homeDir, ".claude.json"), "json"},
			mcpClientTarget{"windsurf", "Windsurf", filepath.Join(homeDir, ".codeium", "windsurf", "mcp_config.json"), "json"},
			mcpClientTarget{"gemini", "Gemini CLI", filepath.Join(homeDir, ".gemini", "settings.json"), "json"},
			mcpClientTarget{"codex", "Codex", filepath.Join(homeDir, ".codex", "config.toml"), "toml"},
		)
	}
	return out
}

func upsertCodexTomlMCP(existing string, exePath string, enableDevTelemetry ...bool) string {
	wantTelemetry := len(enableDevTelemetry) > 0 && enableDevTelemetry[0]
	block := fmt.Sprintf("[mcp_servers.edgefetch]\ncommand = %q\nargs = [\"mcp\"]\n", exePath)
	if wantTelemetry {
		block += "env = { EDGEFETCH_DEV_TELEMETRY = \"1\" }\n"
	}
	// Strip any prior [mcp_servers.edgefetch] (or [mcp_servers.edgefetch.env]) section cleanly before appending updated block
	lines := strings.Split(strings.ReplaceAll(existing, "\r\n", "\n"), "\n")
	var kept []string
	skipping := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if trimmed == "[mcp_servers.edgefetch]" || trimmed == "[mcp_servers.edgefetch.env]" {
				skipping = true
				continue
			}
			skipping = false
		}
		if !skipping {
			kept = append(kept, line)
		}
	}
	cleaned := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if cleaned == "" {
		return block
	}
	return cleaned + "\n\n" + block
}

func isInteractiveStdinTTY(stdin io.Reader, deps cliDeps) bool {
	if deps.stdinIsTTY != nil {
		return *deps.stdinIsTTY
	}
	f, ok := stdin.(*os.File)
	if !ok || f == nil {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}

func runInstallMCP(args []string, stdout, stderr io.Writer) int {
	return runInstallMCPWithDeps(args, nil, stdout, stderr, cliDeps{getenv: os.Getenv})
}

func runInstallMCPWithDeps(args []string, stdin io.Reader, stdout, stderr io.Writer, deps cliDeps) int {
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	dryRun := hasFlag(args, "--dry-run")
	explicitTelemetryOn := hasFlag(args, "--telemetry")
	explicitTelemetryOff := hasFlag(args, "--no-telemetry")
	agentFilter := strings.ToLower(strings.TrimSpace(flagValue(args, "--agent=")))
	exePath := flagValue(args, "--exe=")
	if exePath == "" {
		resolved, err := os.Executable()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "resolve executable path: %v\n", err)
			return 1
		}
		exePath = resolved
	}

	homeDir, _ := os.UserHomeDir()
	allCandidates := allMCPClientTargets(runtime.GOOS, homeDir, os.Getenv("APPDATA"))
	var targets []mcpClientTarget

	if customTarget := flagValue(args, "--config="); customTarget != "" {
		fmtType := "json"
		if strings.HasSuffix(strings.ToLower(customTarget), ".toml") {
			fmtType = "toml"
		}
		targets = []mcpClientTarget{{"custom", "Custom", customTarget, fmtType}}
	} else {
		for _, c := range allCandidates {
			if agentFilter == "all" {
				targets = append(targets, c)
				continue
			}
			if agentFilter != "" {
				if c.slug == agentFilter || strings.Contains(strings.ToLower(c.client), agentFilter) {
					targets = append(targets, c)
				}
				continue
			}
			// Auto-detect installed AI harnesses (parent dir or config file exists), plus always include Claude Desktop & Cursor
			_, fileErr := os.Stat(c.path)
			_, dirErr := os.Stat(filepath.Dir(c.path))
			if c.slug == "claude-desktop" || c.slug == "cursor" || fileErr == nil || (c.slug != "claude-code" && dirErr == nil) {
				targets = append(targets, c)
			}
		}
	}

	// Strict Opt-In Telemetry Prompt:
	//  - Hard disabled when `DO_NOT_TRACK=1` (even if `--telemetry` or `EDGEFETCH_DEV_TELEMETRY=1` is set).
	//  - Strictly skipped when `stdin` is non-TTY (piped/CI/unattended) or `--dry-run` / `--no-telemetry` is passed.
	enableDevTelemetry := false
	if !otel.IsDoNotTrack(deps.getenv("DO_NOT_TRACK")) && !explicitTelemetryOff {
		if explicitTelemetryOn || otel.IsDevTelemetryEnabled(deps.getenv) {
			enableDevTelemetry = true
		} else if !dryRun && stdin != nil && isInteractiveStdinTTY(stdin, deps) {
			_, _ = fmt.Fprint(stdout, "Share anonymous structural adapter & WAF error codes (zero URLs/content; DO_NOT_TRACK=1 honored) to help fix broken extractors? [y/N]: ")
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			ans := strings.ToLower(strings.TrimSpace(line))
			if ans == "y" || ans == "yes" {
				enableDevTelemetry = true
			}
		}
	}

	entry := map[string]any{
		"command": exePath,
		"args":    []string{"mcp"},
	}
	if enableDevTelemetry {
		entry["env"] = map[string]any{
			"EDGEFETCH_DEV_TELEMETRY": "1",
		}
	}

	for _, t := range targets {
		var outBytes []byte
		existingBytes, readErr := os.ReadFile(t.path)

		if t.format == "toml" {
			updated := upsertCodexTomlMCP(string(existingBytes), exePath, enableDevTelemetry)
			outBytes = []byte(updated)
		} else {
			root := map[string]any{}
			if readErr == nil && len(bytes.TrimSpace(existingBytes)) > 0 {
				if jErr := json.Unmarshal(existingBytes, &root); jErr != nil {
					_, _ = fmt.Fprintf(stderr, "skipping %s (%s has invalid JSON: %v)\n", t.client, t.path, jErr)
					continue
				}
			}
			servers, ok := root["mcpServers"].(map[string]any)
			if !ok || servers == nil {
				servers = map[string]any{}
			}
			servers["edgefetch"] = entry
			root["mcpServers"] = servers

			formatted, _ := json.MarshalIndent(root, "", "  ")
			outBytes = append(formatted, '\n')
		}

		if dryRun {
			_, _ = fmt.Fprintf(stdout, "# %s (%s)\n%s", t.client, t.path, string(outBytes))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
			_, _ = fmt.Fprintf(stderr, "mkdir %s: %v\n", filepath.Dir(t.path), err)
			continue
		}
		// Save a .bak backup before modifying an existing harness config file
		if readErr == nil && len(existingBytes) > 0 {
			_ = os.WriteFile(t.path+".bak", existingBytes, 0o600)
		}
		if err := os.WriteFile(t.path, outBytes, 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "write %s: %v\n", t.path, err)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "[OK] Configured %s -> %s\n", t.client, t.path)
	}
	return 0
}

// runServeMode starts a local loopback Firecrawl-compatible + EdgeFetch HTTP server (`edgefetch serve [--port=3002]`).
// Unlike `firecrawl-local` (which disables private-network SSRF protection by default in local MCP mode), EdgeFetch
// enforces public-only dial-time SSRF protection by default unless `--allow-private` is explicitly passed.
func runServeMode(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runServeModeWithDeps(ctx, args, stdout, stderr, cliDeps{getenv: os.Getenv})
}

func runServeModeWithDeps(ctx context.Context, args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	port := flagValue(args, "--port=")
	if port == "" {
		port = "3002"
	}
	allowPrivate := hasFlag(args, "--allow-private")
	addr := "127.0.0.1:" + port

	allowFn, transport := resolveCrawlPolicy(allowPrivate, 60*time.Second, 2)
	var rt http.RoundTripper = transport
	if !allowPrivate {
		if deps.allow != nil {
			allowFn = deps.allow
		}
		if deps.transport != nil {
			rt = deps.transport
		}
	}

	ln, listenErr := net.Listen("tcp", addr)
	if listenErr != nil {
		_, _ = fmt.Fprintf(stderr, "serve failed: %v\n", listenErr)
		return 1
	}
	boundPort := port
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok && tcpAddr.Port > 0 {
		boundPort = strconv.Itoa(tcpAddr.Port)
	}
	urlStr := "http://127.0.0.1:" + boundPort

	log := slog.New(slog.NewJSONHandler(stdout, nil))
	crawler := crawl.NewCrawler(rt, allowFn, crawl.DefaultUserAgent, log)
	otelExp := otel.NewExporterFromEnv(deps.getenv, "edgefetch-serve", agent.Version, newHubTransport())
	crawler.SetOtelExporter(otelExp)
	defer func() { _ = crawler.Close() }()

	goHub := hub.NewServer(hub.Config{
		FallbackCrawler:     crawler,
		AllowedLoopbackPort: boundPort,
		Allow:               allowFn,
		Logger:              log,
		OtelExporter:        otelExp,
	})
	defer func() { _ = goHub.Close() }()

	srv := newHTTPServer(ln.Addr().String(), goHub)
	srv.ReadTimeout = 0

	errCh := make(chan error, 1)
	go func() {
		_, _ = fmt.Fprintf(stdout, "EdgeFetch local API server listening on %s (/v1/scrape, /v2/scrape, /v2/map, /mcp; public-only SSRF=%v)\n", urlStr, !allowPrivate)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		_, _ = fmt.Fprintf(stderr, "serve failed: %v\n", err)
		return 1
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return 0
	}
}

func runDesktopMode(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runDesktopModeWithDeps(ctx, args, stdout, stderr, cliDeps{getenv: os.Getenv})
}

func runDesktopModeWithDeps(ctx context.Context, args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	port := flagValue(args, "--port=")
	if port == "" {
		port = "8787"
	}
	noOpen := hasFlag(args, "--no-open")
	addr := "127.0.0.1:" + port

	allowFn := crawl.PublicHTTPS
	var rt http.RoundTripper = newCrawlTransport(60*time.Second, 2)
	if deps.allow != nil {
		allowFn = deps.allow
	}
	if deps.transport != nil {
		rt = deps.transport
	}

	ln, listenErr := net.Listen("tcp", addr)
	if listenErr != nil {
		_, _ = fmt.Fprintf(stderr, "desktop server failed: %v\n", listenErr)
		return 1
	}
	boundPort := port
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok && tcpAddr.Port > 0 {
		boundPort = strconv.Itoa(tcpAddr.Port)
	}
	urlStr := "http://127.0.0.1:" + boundPort

	log := slog.New(slog.NewJSONHandler(stdout, nil))
	crawler := crawl.NewCrawler(rt, allowFn, crawl.DefaultUserAgent, log)
	otelExp := otel.NewExporterFromEnv(deps.getenv, "edgefetch-desktop", agent.Version, newHubTransport())
	crawler.SetOtelExporter(otelExp)
	defer func() { _ = crawler.Close() }()

	goHub := hub.NewServer(hub.Config{
		FallbackCrawler:     crawler,
		AllowedLoopbackPort: boundPort,
		Allow:               allowFn,
		Logger:              log,
		OtelExporter:        otelExp,
	})
	defer func() { _ = goHub.Close() }()

	srv := newHTTPServer(ln.Addr().String(), goHub)
	srv.ReadTimeout = 0

	errCh := make(chan error, 1)
	go func() {
		_, _ = fmt.Fprintf(stdout, "EdgeFetch Desktop MCP Launchpad listening on %s (MCP endpoint: %s/mcp)\n", urlStr, urlStr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	if !noOpen {
		openBrowserBestEffort(urlStr)
	}

	select {
	case err := <-errCh:
		_, _ = fmt.Fprintf(stderr, "desktop server failed: %v\n", err)
		return 1
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return 0
	}
}

func openBrowserBestEffort(targetURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	case "darwin":
		cmd = exec.Command("open", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	_ = cmd.Start()
}

// runInstallService generates (or writes) a user-level background startup service (`launchd` on macOS,
// `systemd --user` on Linux, or Startup `.cmd` launcher on Windows) running `edgefetch desktop --no-open`.
func runInstallService(args []string, stdout, stderr io.Writer) int {
	dryRun := hasFlag(args, "--dry-run")
	port := flagValue(args, "--port=")
	if port == "" {
		port = "8787"
	}
	exePath := flagValue(args, "--exe=")
	if exePath == "" {
		resolved, err := os.Executable()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "resolve executable path: %v\n", err)
			return 1
		}
		exePath = resolved
	}
	targetOS := flagValue(args, "--os=")
	if targetOS == "" {
		targetOS = runtime.GOOS
	}
	home, _ := os.UserHomeDir()

	var destPath, content string
	switch targetOS {
	case "darwin":
		destPath = filepath.Join(home, "Library", "LaunchAgents", "com.bartrumb.edgefetch.desktop.plist")
		content = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.bartrumb.edgefetch.desktop</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>desktop</string>
    <string>--no-open</string>
    <string>--port=%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`, exePath, port)

	case "windows":
		appData := os.Getenv("APPDATA")
		destPath = filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "EdgeFetchDesktop.cmd")
		content = fmt.Sprintf("@echo off\r\nstart \"\" /B \"%s\" desktop --no-open --port=%s\r\n", exePath, port)

	default:
		destPath = filepath.Join(home, ".config", "systemd", "user", "edgefetch-desktop.service")
		content = fmt.Sprintf(`[Unit]
Description=EdgeFetch Local Loopback MCP & Scrape Service
After=network-online.target

[Service]
ExecStart=%s desktop --no-open --port=%s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
`, exePath, port)
	}

	if dryRun {
		_, _ = fmt.Fprintf(stdout, "# %s (%s)\n%s", targetOS, destPath, content)
		return 0
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		_, _ = fmt.Fprintf(stderr, "mkdir %s: %v\n", filepath.Dir(destPath), err)
		return 1
	}
	if err := os.WriteFile(destPath, []byte(content), 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "write %s: %v\n", destPath, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "[OK] Installed user startup service -> %s\n", destPath)
	return 0
}
