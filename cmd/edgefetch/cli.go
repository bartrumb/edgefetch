package main

import (
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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/botauth"
	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

type cliDeps struct {
	getenv    func(string) string
	transport http.RoundTripper
	allow     func(*url.URL) error
	haPath    string
}

func isOneShotCLI(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "version", "--version", "-v",
		"doctor", "--doctor",
		"scrape",
		"mcp",
		"install-mcp",
		"install-service",
		"keygen-bot-auth",
		"desktop",
		"help", "--help", "-h":
		return true
	}
	return false
}

func runOneShotCLI(ctx context.Context, args []string, stdout, stderr io.Writer, deps cliDeps) int {
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	if deps.transport == nil {
		deps.transport = newCrawlTransport(30*time.Second, 2)
	}
	if deps.allow == nil {
		deps.allow = crawl.PublicHTTPS
	}
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}

	switch args[0] {
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	case "version", "--version", "-v":
		return runVersion(args[1:], stdout)
	case "doctor", "--doctor":
		return runDoctor(args[1:], stdout, stderr, deps)
	case "scrape":
		return runScrapeCLI(ctx, args[1:], stdout, stderr, deps)
	case "mcp":
		return runMCPStdio(ctx, os.Stdin, stdout, stderr, deps)
	case "install-mcp":
		return runInstallMCP(args[1:], stdout, stderr)
	case "install-service":
		return runInstallService(args[1:], stdout, stderr)
	case "keygen-bot-auth":
		return runKeygenBotAuth(args[1:], stdout, stderr)
	case "desktop":
		return runDesktopMode(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown subcommand %q (try 'edgefetch help')\n", args[0])
		return 2
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `EdgeFetch %s — Polite HTTP/2 + SSRF-Proxied Headless Chromium Web Crawler

Usage:
  edgefetch [flags]                              Start authenticated HTTP server (default --mode=server)
  edgefetch --mode=agent                         Start outbound WebSocket worker (supports EDGEFETCH_HUB_URLS HA)
  edgefetch --mode=hub                           Start self-hosted Go WebSocket Hub + /v1/scrape + /mcp controller
  edgefetch --mode=hub,agent                     Hybrid mesh node: local standby Hub + outbound upstream Agent
  edgefetch desktop [--port=8787]                Start loopback Desktop MCP Launchpad & open browser (Win/macOS/Linux)
  edgefetch mcp                                  Run local stdio MCP server (zero ports/tokens — Claude Desktop/Cursor)
  edgefetch install-mcp [--dry-run]              Auto-configure EdgeFetch stdio MCP in Claude Desktop & Cursor
  edgefetch scrape [flags] <https://url>         Scrape one public HTTPS URL to clean Markdown (or --json)
  edgefetch doctor [--json]                      Verify SSRF guard, loopback proxy, Chromium, pdftotext & config
  edgefetch version [--json]                     Print binary version, Go toolchain, and host capabilities
  edgefetch help                                 Show this help text

Scrape Flags:
  --json               Emit structured crawl.Result JSON (status, httptrace timing, llms.txt, markdown)
  --render             Render JavaScript in sandboxed headless Chromium (requires Chromium in PATH)
  --query=<text>       BM25 passage rerank against <text>
  --max-chars=<n>      Truncate output Markdown to <n> characters
  --timeout-ms=<n>     Per-request timeout in milliseconds (default: 30000)

Environment Variables (Agent Mode):
  EDGEFETCH_HUB_URL       Cloudflare Hub origin or wss:// endpoint (e.g. https://edgefetch.example.com)
  EDGEFETCH_AGENT_TOKEN   Shared secret (>= 24 characters) matching AGENT_SHARED_SECRET on Hub
  EDGEFETCH_SITE_ID       Unique lowercase node identifier (e.g. site-mac-mini-1)
`, agent.Version)
}

func runVersion(args []string, stdout io.Writer) int {
	chromeBin := browser.FindChromeBinary()
	hasPDF := extract.HasPDFToText()
	caps := []string{"http2-v1", "scrape-v2", "llms-v1"}
	if chromeBin != "" {
		caps = append(caps, "browser-v1", "interact-v1")
	}
	if hasPDF {
		caps = append(caps, "pdf-v1")
	} else {
		caps = append(caps, "pdf-lite-v1")
	}

	if hasFlag(args, "--json") {
		payload := map[string]any{
			"version":      agent.Version,
			"goVersion":    runtime.Version(),
			"os":           runtime.GOOS,
			"arch":         runtime.GOARCH,
			"capabilities": caps,
			"chromium":     chromeBin != "",
			"pdftotext":    hasPDF,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(payload)
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "edgefetch %s (%s %s/%s) capabilities=%s\n",
		agent.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH, strings.Join(caps, ","))
	return 0
}

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "ok", "optional", "fail"
	Detail string `json:"detail"`
}

func runDoctor(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	var checks []doctorCheck
	failed := false

	// 1. Verify dial-time SSRF guard invariants.
	ssrfOK := !politeness.IsPublicIP(net.ParseIP("127.0.0.1")) &&
		!politeness.IsPublicIP(net.ParseIP("192.168.1.1")) &&
		!politeness.IsPublicIP(net.ParseIP("100.64.0.1")) &&
		!politeness.IsPublicIP(net.ParseIP("169.254.169.254")) &&
		!politeness.IsPublicIP(net.ParseIP("::ffff:127.0.0.1")) &&
		!politeness.IsPublicIP(net.ParseIP("64:ff9b::7f00:1")) &&
		politeness.IsPublicIP(net.ParseIP("93.184.216.34")) &&
		politeness.IsPublicIP(net.ParseIP("2606:4700:4700::1111"))
	if ssrfOK {
		checks = append(checks, doctorCheck{
			Name:   "ssrf_guard",
			Status: "ok",
			Detail: "Dial-time netip SSRF filter blocks loopback/RFC1918/CGNAT/link-local/NAT64 and permits public unicast",
		})
	} else {
		failed = true
		checks = append(checks, doctorCheck{
			Name:   "ssrf_guard",
			Status: "fail",
			Detail: "politeness.IsPublicIP self-test failed",
		})
	}

	// 2. Verify loopback SSRF CONNECT proxy listener.
	proxy, proxyErr := browser.NewSSRFProxy(crawl.PublicHTTPS, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("doctor probe")
	})
	if proxyErr != nil {
		failed = true
		checks = append(checks, doctorCheck{
			Name:   "ssrf_connect_proxy",
			Status: "fail",
			Detail: proxyErr.Error(),
		})
	} else {
		addr := proxy.Addr()
		_ = proxy.Close()
		checks = append(checks, doctorCheck{
			Name:   "ssrf_connect_proxy",
			Status: "ok",
			Detail: "Loopback CONNECT proxy bound cleanly on " + addr,
		})
	}

	// 3. Optional headless Chromium binary check.
	if chrome := browser.FindChromeBinary(); chrome != "" {
		checks = append(checks, doctorCheck{
			Name:   "chromium",
			Status: "ok",
			Detail: chrome + " (browser-v1 + interact-v1 enabled)",
		})
	} else {
		checks = append(checks, doctorCheck{
			Name:   "chromium",
			Status: "optional",
			Detail: "not installed (HTTP/2 + Markdown + pure-Go PDF active; use ghcr.io/bartrumb/edgefetch-agent:latest for JS rendering)",
		})
	}

	// 4. Optional Poppler pdftotext binary check.
	if extract.HasPDFToText() {
		checks = append(checks, doctorCheck{
			Name:   "pdftotext",
			Status: "ok",
			Detail: "poppler pdftotext found in PATH (pdf-v1 layout streaming enabled)",
		})
	} else {
		checks = append(checks, doctorCheck{
			Name:   "pdftotext",
			Status: "optional",
			Detail: "not installed (pure-Go FlateDecode PDF fallback active)",
		})
	}

	// 5. Optional Hub configuration check when env or HAOS options file is present.
	hasHubEnv := strings.TrimSpace(deps.getenv("EDGEFETCH_HUB_URL")) != "" ||
		strings.TrimSpace(deps.getenv("EDGEFETCH_HUB_URLS")) != "" ||
		strings.TrimSpace(deps.getenv("CRAWLER_HUB_URL")) != "" ||
		strings.TrimSpace(deps.getenv("CRAWLER_HUB_URLS")) != ""
	hasHAFile := false
	if deps.haPath != "" {
		if _, err := os.Stat(deps.haPath); err == nil {
			hasHAFile = true
		}
	}
	if hasHubEnv || hasHAFile {
		cfg, err := agent.LoadConfigFrom(deps.haPath, deps.getenv)
		if err != nil {
			failed = true
			checks = append(checks, doctorCheck{
				Name:   "agent_config",
				Status: "fail",
				Detail: err.Error(),
			})
		} else {
			checks = append(checks, doctorCheck{
				Name:   "agent_config",
				Status: "ok",
				Detail: fmt.Sprintf("site=%s hub=%s", cfg.SiteID, cfg.HubURL),
			})
		}
	}

	if hasFlag(args, "--json") {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ok":      !failed,
			"version": agent.Version,
			"checks":  checks,
		})
	} else {
		for _, c := range checks {
			tag := "[OK]      "
			switch c.Status {
			case "optional":
				tag = "[OPTIONAL]"
			case "fail":
				tag = "[FAIL]    "
			}
			_, _ = fmt.Fprintf(stdout, "%s %-20s %s\n", tag, c.Name, c.Detail)
		}
	}

	if failed {
		_, _ = fmt.Fprintln(stderr, "doctor found failing checks")
		return 1
	}
	return 0
}

func runScrapeCLI(ctx context.Context, args []string, stdout, stderr io.Writer, deps cliDeps) int {
	var (
		jsonOut   bool
		render    bool
		query     string
		maxChars  int
		timeoutMs = 30_000
		targetURL string
	)

	for _, a := range args {
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--render":
			render = true
		case strings.HasPrefix(a, "--query="):
			query = strings.TrimSpace(strings.TrimPrefix(a, "--query="))
		case strings.HasPrefix(a, "--max-chars="):
			v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(a, "--max-chars=")))
			if err != nil || v < 0 {
				_, _ = fmt.Fprintf(stderr, "invalid --max-chars value %q\n", a)
				return 2
			}
			maxChars = v
		case strings.HasPrefix(a, "--timeout-ms="):
			v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(a, "--timeout-ms=")))
			if err != nil || v <= 0 {
				_, _ = fmt.Fprintf(stderr, "invalid --timeout-ms value %q\n", a)
				return 2
			}
			timeoutMs = v
		case strings.HasPrefix(a, "-"):
			_, _ = fmt.Fprintf(stderr, "unknown scrape flag %q (try 'edgefetch help')\n", a)
			return 2
		default:
			if targetURL != "" {
				_, _ = fmt.Fprintln(stderr, "scrape accepts exactly one URL")
				return 2
			}
			targetURL = strings.TrimSpace(a)
		}
	}

	if targetURL == "" {
		_, _ = fmt.Fprintln(stderr, "usage: edgefetch scrape [--json] [--render] [--query=...] <https://url>")
		return 2
	}

	ua := firstNonEmpty(deps.getenv("EDGEFETCH_USER_AGENT"), deps.getenv("CRAWLER_USER_AGENT"), crawl.DefaultUserAgent)
	if err := crawl.ValidateUserAgent(ua); err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid user_agent: %v\n", err)
		return 2
	}

	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(deps.transport, deps.allow, ua, silentLog)
	defer func() { _ = crawler.Close() }()

	kind := classify.KindScrape
	renderMode := "off"
	if render {
		kind = classify.KindRender
		renderMode = "always"
	}

	call := crawl.FetchCall{
		MaxSeconds: (timeoutMs / 1000) + 15,
		Options: crawl.Options{
			TimeoutMs:     timeoutMs,
			Concurrency:   1,
			RespectRobots: crawl.Bool(true),
			DiscoverLlms:  crawl.Bool(true),
		},
		Requests: []crawl.Request{
			{
				ID:              "cli-1",
				URL:             targetURL,
				Kind:            kind,
				Formats:         []string{"markdown", "links"},
				OnlyMainContent: crawl.Bool(true),
				DiscoverLlms:    crawl.Bool(true),
				Query:           query,
				RenderMode:      renderMode,
			},
		},
	}

	if code, problem, ok := crawl.ValidateCallWithCrawler(crawler, call, deps.allow); !ok {
		_, _ = fmt.Fprintf(stderr, "%s: %s\n", code, problem)
		return 2
	}

	reply := crawl.ExecuteCall(ctx, crawler, call, silentLog)
	if len(reply.Results) == 0 {
		_, _ = fmt.Fprintln(stderr, "scrape produced no result")
		return 1
	}
	res := reply.Results[0]
	if maxChars > 0 && len(res.Markdown) > maxChars {
		res.Markdown = res.Markdown[:maxChars]
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if res.Outcome != classify.OutcomeOK {
			return 1
		}
		return 0
	}

	if res.Outcome != classify.OutcomeOK {
		msg := res.Problem
		if msg == "" {
			msg = fmt.Sprintf("outcome=%s status=%d", res.Outcome, res.Status)
		}
		_, _ = fmt.Fprintf(stderr, "scrape failed (%s): %s\n", res.Outcome, msg)
		return 1
	}

	out := res.Markdown
	if out == "" {
		out = res.Text
	}
	if out == "" {
		out = res.Body
	}
	_, _ = fmt.Fprintln(stdout, strings.TrimSpace(out))
	return 0
}

func runKeygenBotAuth(args []string, stdout, stderr io.Writer) int {
	kp, err := botauth.GenerateKeyPair()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "keygen-bot-auth failed: %v\n", err)
		return 1
	}
	if hasFlag(args, "--json") {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(kp)
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "# RFC 9421 Web Bot Auth (Ed25519) Keypair\n")
	_, _ = fmt.Fprintf(stdout, "EDGEFETCH_BOT_SIGNING_KEY=%s\n", kp.PrivateKeySeedB64URL)
	_, _ = fmt.Fprintf(stdout, "BOT_SIGNING_PUBLIC_KEY=%s\n", kp.PublicKeyB64URL)
	_, _ = fmt.Fprintf(stdout, "BOT_KEY_ID=%s\n", kp.KeyID)
	return 0
}
