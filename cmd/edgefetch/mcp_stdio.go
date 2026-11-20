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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/internal/agent"
	"github.com/bartrumb/edgefetch/internal/browser"
	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/crawl"
	"github.com/bartrumb/edgefetch/internal/hub"
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
			}
			if err := json.Unmarshal(req.Params, &cp); err != nil {
				writeRPC(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"error":   map[string]any{"code": -32602, "message": "Invalid params"},
				})
				continue
			}

			switch cp.Name {
			case "doctor":
				var docOut bytes.Buffer
				_ = runDoctor([]string{"--json"}, &docOut, io.Discard, deps)
				writeRPC(stdioToolResult(req.ID, strings.TrimSpace(docOut.String()), false))

			case "scrape":
				var sp struct {
					URL      string `json:"url"`
					Render   bool   `json:"render"`
					Query    string `json:"query"`
					MaxChars int    `json:"maxChars"`
				}
				_ = json.Unmarshal(cp.Arguments, &sp)
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
					writeRPC(stdioToolResult(req.ID, code+": "+msg, true))
					continue
				}
				rep := crawl.ExecuteCall(ctx, crawler, call, silentLog)
				if len(rep.Results) == 0 {
					writeRPC(stdioToolResult(req.ID, "empty_reply", true))
					continue
				}
				res := rep.Results[0]
				if sp.MaxChars > 0 && len(res.Markdown) > sp.MaxChars {
					res.Markdown = res.Markdown[:sp.MaxChars]
				}
				txt := marshalJSONNoEscapeHTML(res, "  ")
				writeRPC(stdioToolResult(req.ID, txt, res.Outcome != classify.OutcomeOK))

			case "fetch_url":
				var fp struct {
					URL  string `json:"url"`
					Kind string `json:"kind"`
				}
				_ = json.Unmarshal(cp.Arguments, &fp)
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
					writeRPC(stdioToolResult(req.ID, code+": "+msg, true))
					continue
				}
				rep := crawl.ExecuteCall(ctx, crawler, call, silentLog)
				txt := marshalJSONNoEscapeHTML(rep, "  ")
				writeRPC(stdioToolResult(req.ID, txt, false))

			default:
				writeRPC(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"error":   map[string]any{"code": -32601, "message": "Unknown tool: " + cp.Name},
				})
			}

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

// defaultMCPConfigPaths returns standard Claude Desktop and Cursor MCP config file locations for the current OS.
func defaultMCPConfigPaths(goos, homeDir, appData string) []struct {
	client string
	path   string
} {
	var out []struct {
		client string
		path   string
	}
	switch goos {
	case "windows":
		if appData != "" {
			out = append(out, struct{ client, path string }{"Claude Desktop", filepath.Join(appData, "Claude", "claude_desktop_config.json")})
		}
	case "darwin":
		if homeDir != "" {
			out = append(out, struct{ client, path string }{"Claude Desktop", filepath.Join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json")})
		}
	default:
		if homeDir != "" {
			out = append(out, struct{ client, path string }{"Claude Desktop", filepath.Join(homeDir, ".config", "Claude", "claude_desktop_config.json")})
		}
	}
	if homeDir != "" {
		out = append(out, struct{ client, path string }{"Cursor", filepath.Join(homeDir, ".cursor", "mcp.json")})
	}
	return out
}

func runInstallMCP(args []string, stdout, stderr io.Writer) int {
	dryRun := hasFlag(args, "--dry-run")
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
	targets := defaultMCPConfigPaths(runtime.GOOS, homeDir, os.Getenv("APPDATA"))
	if customTarget := flagValue(args, "--config="); customTarget != "" {
		targets = []struct{ client, path string }{{"Custom", customTarget}}
	}

	entry := map[string]any{
		"command": exePath,
		"args":    []string{"mcp"},
	}

	for _, t := range targets {
		root := map[string]any{}
		if raw, err := os.ReadFile(t.path); err == nil && len(bytes.TrimSpace(raw)) > 0 {
			if jErr := json.Unmarshal(raw, &root); jErr != nil {
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
		formatted = append(formatted, '\n')

		if dryRun {
			_, _ = fmt.Fprintf(stdout, "# %s (%s)\n%s", t.client, t.path, string(formatted))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
			_, _ = fmt.Fprintf(stderr, "mkdir %s: %v\n", filepath.Dir(t.path), err)
			continue
		}
		if err := os.WriteFile(t.path, formatted, 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "write %s: %v\n", t.path, err)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "[OK] Configured %s -> %s\n", t.client, t.path)
	}
	return 0
}

func runDesktopMode(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	port := flagValue(args, "--port=")
	if port == "" {
		port = "8787"
	}
	noOpen := hasFlag(args, "--no-open")
	addr := "127.0.0.1:" + port
	urlStr := "http://" + addr

	log := slog.New(slog.NewJSONHandler(stdout, nil))
	crawler := crawl.NewCrawler(newCrawlTransport(60*time.Second, 2), crawl.PublicHTTPS, crawl.DefaultUserAgent, log)
	defer func() { _ = crawler.Close() }()

	goHub := hub.NewServer(hub.Config{
		FallbackCrawler: crawler,
		Allow:           crawl.PublicHTTPS,
		Logger:          log,
	})
	defer func() { _ = goHub.Close() }()

	srv := newHTTPServer(addr, goHub)
	srv.ReadTimeout = 0

	errCh := make(chan error, 1)
	go func() {
		_, _ = fmt.Fprintf(stdout, "EdgeFetch Desktop MCP Launchpad listening on %s (MCP endpoint: %s/mcp)\n", urlStr, urlStr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
