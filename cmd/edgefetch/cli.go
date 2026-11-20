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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/botauth"
	"github.com/bartrumb/edgefetch/v2/internal/browser"
	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/extract"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
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
		"map",
		"crawl",
		"mcp",
		"init",
		"install-mcp",
		"install-service",
		"keygen-bot-auth",
		"bug-report",
		"serve",
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
	case "map":
		return runMapCLI(ctx, args[1:], stdout, stderr, deps)
	case "crawl":
		return runCrawlCLI(ctx, args[1:], stdout, stderr, deps)
	case "mcp":
		return runMCPStdio(ctx, os.Stdin, stdout, stderr, deps)
	case "init", "install-mcp":
		return runInstallMCP(args[1:], stdout, stderr)
	case "install-service":
		return runInstallService(args[1:], stdout, stderr)
	case "keygen-bot-auth":
		return runKeygenBotAuth(args[1:], stdout, stderr)
	case "bug-report":
		return runBugReportCLI(ctx, args[1:], stdout, stderr, deps)
	case "serve":
		return runServeMode(ctx, args[1:], stdout, stderr)
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
  edgefetch serve [--port=3002]                  Start local loopback /v1/* + /v2/* Firecrawl-compatible API server
  edgefetch desktop [--port=8787]                Start loopback Desktop MCP Launchpad & open browser (Win/macOS/Linux)
  edgefetch mcp                                  Run local stdio MCP server (zero ports/tokens — Claude/Cursor/Codex)
  edgefetch init [--agent=all] [--dry-run]       Auto-configure MCP in Claude Code, Claude Desktop, Cursor, Windsurf, Gemini & Codex
  edgefetch scrape [flags] <https://url>         Scrape one public HTTPS URL to clean Markdown (or --json)
  edgefetch map [flags] <https://url>            Discover URLs across /llms.txt, /sitemap.xml & homepage links
  edgefetch crawl [flags] <https://url>          Breadth-first polite site crawl (supports --out=./pages Markdown export)
  edgefetch bug-report [--render] [https://url]  Generate a token-scrubbed GitHub Issue bundle + sanitized OTel trace
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
		cut := maxChars
		for cut > 0 && !utf8.RuneStart(res.Markdown[cut]) {
			cut--
		}
		res.Markdown = res.Markdown[:cut]
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

func runMapCLI(ctx context.Context, args []string, stdout, stderr io.Writer, deps cliDeps) int {
	var (
		jsonOut   bool
		search    string
		limit     = 100
		targetURL string
	)
	for _, a := range args {
		switch {
		case a == "--json":
			jsonOut = true
		case strings.HasPrefix(a, "--search="):
			search = strings.TrimSpace(strings.TrimPrefix(a, "--search="))
		case strings.HasPrefix(a, "--limit="):
			v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(a, "--limit=")))
			if err != nil || v <= 0 {
				_, _ = fmt.Fprintf(stderr, "invalid --limit value %q\n", a)
				return 2
			}
			limit = v
		case strings.HasPrefix(a, "-"):
			_, _ = fmt.Fprintf(stderr, "unknown map flag %q\n", a)
			return 2
		default:
			if targetURL != "" {
				_, _ = fmt.Fprintln(stderr, "map accepts exactly one URL")
				return 2
			}
			targetURL = strings.TrimSpace(a)
		}
	}
	if targetURL == "" {
		_, _ = fmt.Fprintln(stderr, "usage: edgefetch map [--json] [--search=...] [--limit=100] <https://url>")
		return 2
	}
	if limit > 1000 {
		limit = 1000
	}
	parsedU, err := url.Parse(targetURL)
	if err != nil || deps.allow(parsedU) != nil {
		_, _ = fmt.Fprintf(stderr, "invalid_url: %s\n", targetURL)
		return 2
	}

	ua := firstNonEmpty(deps.getenv("EDGEFETCH_USER_AGENT"), deps.getenv("CRAWLER_USER_AGENT"), crawl.DefaultUserAgent)
	if err := crawl.ValidateUserAgent(ua); err != nil {
		ua = crawl.DefaultUserAgent
	}
	silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
	crawler := crawl.NewCrawler(deps.transport, deps.allow, ua, silentLog)
	defer func() { _ = crawler.Close() }()

	origin := parsedU.Scheme + "://" + parsedU.Host
	call := crawl.FetchCall{
		MaxSeconds: 30,
		Options:    crawl.Options{Concurrency: 2, IncludeBody: true, RespectRobots: crawl.Bool(true)},
		Requests: []crawl.Request{
			{ID: "llms", URL: origin + "/llms.txt", Kind: classify.KindText},
			{ID: "sitemap", URL: origin + "/sitemap.xml", Kind: classify.KindText},
			{ID: "home", URL: targetURL, Kind: classify.KindScrape, Formats: []string{"links"}},
		},
	}
	if code, msg, ok := crawl.ValidateCallWithCrawler(crawler, call, deps.allow); !ok {
		_, _ = fmt.Fprintf(stderr, "%s: %s\n", code, msg)
		return 2
	}
	rep := crawl.ExecuteCall(ctx, crawler, call, silentLog)
	seen := map[string]struct{}{}
	var links []string
	filterLower := strings.ToLower(search)
	addCand := func(cand string) {
		cand = strings.TrimSpace(cand)
		if !strings.HasPrefix(cand, "https://") || len(links) >= limit {
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
			addCand(l)
		}
		for _, m := range reSitemapLocURL.FindAllStringSubmatch(r.Body, 1000) {
			if len(m) > 1 {
				addCand(m[1])
			}
		}
		for _, m := range reMarkdownHTTPURL.FindAllStringSubmatch(r.Body, 1000) {
			if len(m) > 1 {
				addCand(m[1])
			}
		}
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"ok": true, "url": origin, "total": len(links), "links": links})
		return 0
	}
	for _, l := range links {
		_, _ = fmt.Fprintln(stdout, l)
	}
	return 0
}

func slugifyURLForFilename(rawURL string, idx int) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("page-%03d.md", idx)
	}
	clean := strings.Trim(u.Path, "/")
	if clean == "" {
		clean = "index"
	}
	var b strings.Builder
	for _, r := range clean {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > 80 {
		slug = slug[:80]
	}
	if slug == "" {
		slug = fmt.Sprintf("page-%03d", idx)
	}
	return fmt.Sprintf("%03d-%s.md", idx, slug)
}

func runCrawlCLI(ctx context.Context, args []string, stdout, stderr io.Writer, deps cliDeps) int {
	var (
		jsonOut   bool
		render    bool
		limit     = 20
		maxDepth  = 2
		outDir    string
		targetURL string
	)
	for _, a := range args {
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--render":
			render = true
		case strings.HasPrefix(a, "--limit="):
			v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(a, "--limit=")))
			if err != nil || v <= 0 {
				_, _ = fmt.Fprintf(stderr, "invalid --limit value %q\n", a)
				return 2
			}
			limit = v
		case strings.HasPrefix(a, "--max-depth="):
			v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(a, "--max-depth=")))
			if err != nil || v < 0 {
				_, _ = fmt.Fprintf(stderr, "invalid --max-depth value %q\n", a)
				return 2
			}
			maxDepth = v
		case strings.HasPrefix(a, "--out="):
			outDir = strings.TrimSpace(strings.TrimPrefix(a, "--out="))
		case strings.HasPrefix(a, "-"):
			_, _ = fmt.Fprintf(stderr, "unknown crawl flag %q\n", a)
			return 2
		default:
			if targetURL != "" {
				_, _ = fmt.Fprintln(stderr, "crawl accepts exactly one root URL")
				return 2
			}
			targetURL = strings.TrimSpace(a)
		}
	}
	if targetURL == "" {
		_, _ = fmt.Fprintln(stderr, "usage: edgefetch crawl [--json] [--limit=20] [--max-depth=2] [--out=./pages] [--render] <https://url>")
		return 2
	}
	if limit > 100 {
		limit = 100
	}
	if maxDepth > 5 {
		maxDepth = 5
	}
	rootParsed, err := url.Parse(targetURL)
	if err != nil || deps.allow(rootParsed) != nil {
		_, _ = fmt.Fprintf(stderr, "invalid_url: %s\n", targetURL)
		return 2
	}
	if outDir != "" {
		if mkErr := os.MkdirAll(outDir, 0o755); mkErr != nil {
			_, _ = fmt.Fprintf(stderr, "mkdir %s: %v\n", outDir, mkErr)
			return 1
		}
	}

	ua := firstNonEmpty(deps.getenv("EDGEFETCH_USER_AGENT"), deps.getenv("CRAWLER_USER_AGENT"), crawl.DefaultUserAgent)
	if err := crawl.ValidateUserAgent(ua); err != nil {
		ua = crawl.DefaultUserAgent
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

	visited := map[string]bool{rootParsed.String(): true}
	frontier := []string{rootParsed.String()}
	var pages []crawl.Result

	for depth := 0; depth <= maxDepth && len(frontier) > 0 && len(pages) < limit; depth++ {
		rem := limit - len(pages)
		wave := frontier
		if len(wave) > rem {
			wave = wave[:rem]
		}
		if len(wave) > 10 {
			wave = wave[:10]
		}
		var nextFrontier []string
		reqs := make([]crawl.Request, 0, len(wave))
		for i, u := range wave {
			reqs = append(reqs, crawl.Request{
				ID:              fmt.Sprintf("c-%d-%d", depth, i),
				URL:             u,
				Kind:            kind,
				Formats:         []string{"markdown", "links"},
				OnlyMainContent: crawl.Bool(true),
				RenderMode:      renderMode,
			})
		}
		call := crawl.FetchCall{
			MaxSeconds: 60,
			Options:    crawl.Options{Concurrency: 2, RespectRobots: crawl.Bool(true), PauseMs: 800, PauseJitterMs: 200},
			Requests:   reqs,
		}
		if _, _, ok := crawl.ValidateCallWithCrawler(crawler, call, deps.allow); !ok {
			break
		}
		rep := crawl.ExecuteCall(ctx, crawler, call, silentLog)
		for _, r := range rep.Results {
			pages = append(pages, r)
			if r.Outcome == classify.OutcomeOK && outDir != "" && r.Markdown != "" {
				fname := filepath.Join(outDir, slugifyURLForFilename(r.URL, len(pages)))
				doc := fmt.Sprintf("---\nurl: %q\ntitle: %q\nstatus: %d\n---\n\n%s\n", r.URL, r.Title, r.Status, strings.TrimSpace(r.Markdown))
				_ = os.WriteFile(fname, []byte(doc), 0o644)
			}
			if depth < maxDepth && r.Outcome == classify.OutcomeOK {
				for _, lnk := range r.Links {
					lu, lErr := url.Parse(lnk)
					if lErr != nil || lu.Scheme != "https" || !strings.EqualFold(lu.Hostname(), rootParsed.Hostname()) {
						continue
					}
					lu.Fragment = ""
					clean := lu.String()
					if !visited[clean] && len(visited) < limit*3 {
						visited[clean] = true
						nextFrontier = append(nextFrontier, clean)
					}
				}
			}
		}
		frontier = nextFrontier
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"ok": true, "rootUrl": rootParsed.String(), "fetched": len(pages), "pages": pages})
		return 0
	}
	for _, p := range pages {
		_, _ = fmt.Fprintf(stdout, "[%s %d] %s (%d chars)\n", p.Outcome, p.Status, p.URL, len(p.Markdown))
	}
	if outDir != "" {
		_, _ = fmt.Fprintf(stdout, "Saved Markdown pages to %s\n", outDir)
	}
	return 0
}

func sanitizeURLForBugReport(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "<invalid-url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func runBugReportCLI(ctx context.Context, args []string, stdout, stderr io.Writer, deps cliDeps) int {
	wantRender := hasFlag(args, "--render")
	wantJSON := hasFlag(args, "--json")

	targetURL := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			targetURL = strings.TrimSpace(a)
			break
		}
	}

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

	// Record boolean-only presence of configuration keys (NEVER inspect or print secret values!).
	envKeys := []string{
		"EDGEFETCH_HUB_URL",
		"EDGEFETCH_HUB_URLS",
		"EDGEFETCH_AGENT_TOKEN",
		"EDGEFETCH_SERVER_TOKEN",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"EDGEFETCH_OTEL_STDOUT",
	}
	envPresence := make(map[string]string, len(envKeys))
	for _, k := range envKeys {
		if strings.TrimSpace(deps.getenv(k)) != "" {
			envPresence[k] = "set (redacted)"
		} else {
			envPresence[k] = "unset"
		}
	}

	tc := otel.ExtractOrNew(nil)
	traceparent := otel.FormatTraceparent(tc)
	var spans []otel.Span
	var probeSummary map[string]any
	safeTarget := ""

	if targetURL != "" {
		parsed, pErr := url.Parse(targetURL)
		if pErr != nil {
			_, _ = fmt.Fprintf(stderr, "invalid URL: %v\n", pErr)
			return 2
		}
		if aErr := deps.allow(parsed); aErr != nil {
			_, _ = fmt.Fprintf(stderr, "URL rejected by SSRF guard: %v\n", aErr)
			return 2
		}
		safeTarget = sanitizeURLForBugReport(targetURL)

		silentLog := slog.New(slog.NewJSONHandler(io.Discard, nil))
		crawler := crawl.NewCrawler(deps.transport, deps.allow, crawl.DefaultUserAgent, silentLog)
		defer func() { _ = crawler.Close() }()

		kind := classify.KindScrape
		renderMode := "auto"
		if wantRender {
			kind = classify.KindRender
			renderMode = "always"
		}

		spanStart := time.Now()
		rep := crawl.ExecuteCall(ctx, crawler, crawl.FetchCall{
			MaxSeconds: 45,
			Options:    crawl.Options{Concurrency: 1, RespectRobots: crawl.Bool(true), TimeoutMs: 30000},
			Requests: []crawl.Request{
				{
					ID:              "bug-report-1",
					URL:             targetURL,
					Kind:            kind,
					Formats:         []string{"markdown"},
					OnlyMainContent: crawl.Bool(true),
					RenderMode:      renderMode,
				},
			},
		}, silentLog)
		spanEnd := time.Now()

		if len(rep.Results) > 0 {
			r := rep.Results[0]
			wafVendor := ""
			if r.WAF != nil {
				wafVendor = r.WAF.Vendor
			}
			attrs := map[string]any{
				"url.full":                  safeTarget,
				"http.response.status_code": r.Status,
				"edgefetch.kind":            string(r.Kind),
				"edgefetch.outcome":         string(r.Outcome),
				"edgefetch.rendered":        r.Rendered,
				"edgefetch.bytes":           r.Bytes,
				"edgefetch.markdown_chars":  len(r.Markdown),
				"edgefetch.dns_ms":          r.Timing.DNSMs,
				"edgefetch.connect_ms":      r.Timing.ConnectMs,
				"edgefetch.tls_ms":          r.Timing.TLSMs,
				"edgefetch.ttfb_ms":         r.Timing.TTFBMs,
				"edgefetch.robots_ms":       r.Timing.RobotsMs,
				"edgefetch.duration_ms":     r.DurationMs,
				"network.protocol.name":     r.Timing.Proto,
			}
			if wafVendor != "" {
				attrs["edgefetch.waf.vendor"] = wafVendor
			}
			spans = append(spans, otel.Span{
				TraceID:      tc.TraceID,
				SpanID:       tc.SpanID,
				Name:         "edgefetch.bug_report.scrape",
				Kind:         3,
				Start:        spanStart,
				End:          spanEnd,
				StatusOK:     r.Outcome == classify.OutcomeOK,
				ErrorMessage: r.Problem,
				Attributes:   attrs,
			})
			probeSummary = map[string]any{
				"sanitizedUrl":  safeTarget,
				"outcome":       r.Outcome,
				"status":        r.Status,
				"contentType":   r.ContentType,
				"rendered":      r.Rendered,
				"bytes":         r.Bytes,
				"markdownChars": len(r.Markdown),
				"wafVendor":     wafVendor,
				"problem":       r.Problem,
				"timing": map[string]any{
					"dnsMs":      r.Timing.DNSMs,
					"connectMs":  r.Timing.ConnectMs,
					"tlsMs":      r.Timing.TLSMs,
					"ttfbMs":     r.Timing.TTFBMs,
					"robotsMs":   r.Timing.RobotsMs,
					"durationMs": r.DurationMs,
					"proto":      r.Timing.Proto,
					"reused":     r.Timing.Reused,
				},
			}
		}
	} else {
		now := time.Now()
		spans = append(spans, otel.Span{
			TraceID:  tc.TraceID,
			SpanID:   tc.SpanID,
			Name:     "edgefetch.bug_report.environment",
			Kind:     1,
			Start:    now,
			End:      now,
			StatusOK: true,
			Attributes: map[string]any{
				"host.os":   runtime.GOOS,
				"host.arch": runtime.GOARCH,
			},
		})
	}

	otlpBytes, _ := otel.BuildOTLPJSON("edgefetch-cli", agent.Version, spans)
	var prettyOTLP any
	_ = json.Unmarshal(otlpBytes, &prettyOTLP)
	prettyOTLPBytes, _ := json.MarshalIndent(prettyOTLP, "", "  ")

	if wantJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"version":      agent.Version,
			"goVersion":    runtime.Version(),
			"os":           runtime.GOOS,
			"arch":         runtime.GOARCH,
			"capabilities": caps,
			"traceparent":  traceparent,
			"envPresence":  envPresence,
			"probe":        probeSummary,
			"otlp":         prettyOTLP,
		})
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "### EdgeFetch Diagnostic Bundle (Sanitized — Safe for Public GitHub Issues)\n\n")
	_, _ = fmt.Fprintf(stdout, "- **Version:** `v%s` (`%s` `%s/%s`)\n", agent.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	_, _ = fmt.Fprintf(stdout, "- **Capabilities:** `%s`\n", strings.Join(caps, ", "))
	_, _ = fmt.Fprintf(stdout, "- **W3C Traceparent:** `%s`\n", traceparent)
	_, _ = fmt.Fprintf(stdout, "- **Config Presence (values redacted):** `HUB_URL=%s`, `AGENT_TOKEN=%s`, `OTEL_ENDPOINT=%s`\n",
		envPresence["EDGEFETCH_HUB_URL"], envPresence["EDGEFETCH_AGENT_TOKEN"], envPresence["OTEL_EXPORTER_OTLP_ENDPOINT"])
	if probeSummary != nil {
		probeJSON, _ := json.MarshalIndent(probeSummary, "", "  ")
		_, _ = fmt.Fprintf(stdout, "\n#### Sanitized Probe Summary (`%s`)\n```json\n%s\n```\n", safeTarget, string(probeJSON))
	}
	_, _ = fmt.Fprintf(stdout, "\n<details>\n<summary>OpenTelemetry OTLP/JSON Trace Span (Sanitized)</summary>\n\n```json\n%s\n```\n</details>\n", string(prettyOTLPBytes))
	return 0
}
