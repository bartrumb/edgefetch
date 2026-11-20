// Command edgefetch is a minimal-supply-chain HTTP/2 crawler (one Go dependency, with no transitive dependencies)
// that runs in three modes from one static binary:
//   - server mode (default): listens on $EDGEFETCH_BIND_ADDR or :$PORT (GET /healthz, POST /fetch) authenticated via
//     EDGEFETCH_SERVER_TOKEN (unless bound strictly to loopback or EDGEFETCH_ALLOW_UNAUTHENTICATED=1).
//   - agent mode (--mode=agent, EDGEFETCH_MODE=agent, or /data/options.json on Home Assistant OS): opens zero inbound
//     ports; drops root privileges (65532:65532), dials outbound wss:// to AgentHubDO, and executes pull jobs on demand.
//   - one-shot CLI mode (edgefetch scrape <url>, edgefetch doctor, edgefetch version): polite terminal scraper and
//     self-diagnostics tool.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/botauth"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/hub"
	"github.com/bartrumb/edgefetch/v2/internal/otel"
	"github.com/bartrumb/edgefetch/v2/internal/politeness"
	"github.com/bartrumb/edgefetch/v2/internal/priv"
	"github.com/bartrumb/edgefetch/v2/internal/ws"
)

const maxResponseHeaderBytes = 64 << 10 // 64 KiB cap prevents giant origin response headers from exhausting memory.

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    maxResponseHeaderBytes,
	}
}

func newCrawlTransport(idleTimeout time.Duration, maxIdlePerHost int) *http.Transport {
	return &http.Transport{
		Proxy: nil, // Never inherit ambient HTTP_PROXY / HTTPS_PROXY environment variables.
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   politeness.RejectNonPublicPeer,
		}).DialContext,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		MaxIdleConns:           32,
		MaxIdleConnsPerHost:    maxIdlePerHost,
		IdleConnTimeout:        idleTimeout,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        ws.ClassicTLSConfig(),
	}
}

func newHubTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        90 * time.Second,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        ws.ClassicTLSConfig(),
	}
}

type runtimeModes struct {
	server bool
	agent  bool
	hub    bool
}

func resolveRuntimeModes(args []string, envMode, haOptionsPath string) runtimeModes {
	rawMode := ""
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--mode="):
			rawMode = strings.TrimPrefix(a, "--mode=")
		case strings.HasPrefix(a, "-mode="):
			rawMode = strings.TrimPrefix(a, "-mode=")
		case a == "agent" || a == "server" || a == "hub" || a == "controller":
			rawMode = a
		}
	}
	if rawMode == "" {
		rawMode = strings.TrimSpace(envMode)
	}
	if rawMode != "" {
		var m runtimeModes
		for _, part := range strings.Split(strings.ToLower(rawMode), ",") {
			switch strings.TrimSpace(part) {
			case "agent":
				m.agent = true
			case "hub", "controller":
				m.hub = true
			case "server":
				m.server = true
			}
		}
		if m.agent || m.hub || m.server {
			return m
		}
	}
	if haOptionsPath != "" {
		if _, err := os.Stat(haOptionsPath); err == nil {
			return runtimeModes{agent: true}
		}
	}
	return runtimeModes{server: true}
}

func shouldRunAgent(args []string, envMode, haOptionsPath string) bool {
	m := resolveRuntimeModes(args, envMode, haOptionsPath)
	return m.agent && !m.hub && !m.server
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func hasFlag(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func flagValue(args []string, prefix string) string {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(a, prefix))
		}
	}
	return ""
}

func isTruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateServerSecurity(addr, serverToken string, allowUnauthenticated bool) error {
	tok := strings.TrimSpace(serverToken)
	if tok != "" {
		if len(tok) < 24 {
			return errors.New("EDGEFETCH_SERVER_TOKEN must be at least 24 characters")
		}
		return nil
	}
	if isLoopbackBind(addr) || allowUnauthenticated {
		return nil
	}
	return errors.New("refusing unauthenticated non-loopback bind: set EDGEFETCH_SERVER_TOKEN (>= 24 chars), bind --addr=127.0.0.1:8080, or pass --allow-unauthenticated inside an isolated container bridge")
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if clean := strings.TrimSpace(p); clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if isOneShotCLI(os.Args[1:]) {
		code := runOneShotCLI(ctx, os.Args[1:], os.Stdout, os.Stderr, cliDeps{
			getenv: os.Getenv,
			haPath: agent.DefaultHAOptionsPath,
		})
		if code != 0 {
			os.Exit(code)
		}
		return
	}

	// Zero-setup Desktop Double-Click Experience (Windows / macOS): when launched with zero CLI args and no server/agent
	// env vars configured, start the loopback-only Desktop Launchpad (`127.0.0.1:8787`) and open the browser!
	if len(os.Args) == 1 && (runtime.GOOS == "windows" || runtime.GOOS == "darwin") &&
		firstNonEmpty(
			os.Getenv("EDGEFETCH_MODE"),
			os.Getenv("CRAWLER_MODE"),
			os.Getenv("PORT"),
			os.Getenv("EDGEFETCH_BIND_ADDR"),
			os.Getenv("EDGEFETCH_SERVER_TOKEN"),
			os.Getenv("EDGEFETCH_CALLER_TOKEN"),
			os.Getenv("CALLER_TOKEN"),
			os.Getenv("EDGEFETCH_HUB_URL"),
			os.Getenv("EDGEFETCH_HUB_URLS"),
		) == "" {
		if code := runDesktopMode(ctx, nil, os.Stdout, os.Stderr); code != 0 {
			os.Exit(code)
		}
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	envMode := firstNonEmpty(os.Getenv("EDGEFETCH_MODE"), os.Getenv("CRAWLER_MODE"))
	modes := resolveRuntimeModes(os.Args[1:], envMode, agent.DefaultHAOptionsPath)
	hubTr := newHubTransport()

	if modes.agent && !modes.hub && !modes.server {
		cfg, err := agent.LoadConfig(agent.DefaultHAOptionsPath)
		if err != nil {
			log.Error("agent_config", slog.String("error", err.Error()))
			os.Exit(2)
		}
		if err := priv.DropRoot(); err != nil {
			log.Error("agent_drop_privileges", slog.String("error", err.Error()))
			os.Exit(2)
		}

		allow := crawl.WithAllowedHosts(crawl.PublicHTTPS, cfg.AllowedHosts)
		for _, hURL := range cfg.HubURLs {
			if hubParsed, pErr := url.Parse(hURL); pErr == nil && hubParsed.Hostname() != "" {
				allow = crawl.WithBlockedHost(allow, hubParsed.Hostname())
			}
		}
		siteLog := log.With(slog.String("site", cfg.SiteID))
		siteLog.Info("agent_startup",
			slog.Int("controllers", len(cfg.HubURLs)),
			slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)),
			slog.String("go", runtime.Version()))
		crawler := crawl.NewCrawler(newCrawlTransport(90*time.Second, 4), allow, cfg.UserAgent, siteLog)
		defer func() { _ = crawler.Close() }()
		crawler.SetRobotsBypassHosts(splitCSV(os.Getenv("EDGEFETCH_ROBOTS_BYPASS_HOSTS")))
		crawler.SetOtelExporter(otel.NewExporterFromEnv(os.Getenv, "edgefetch-agent-"+cfg.SiteID, agent.Version, hubTr))
		configureCrawlerBotAuth(crawler, cfg.HubURLs, siteLog)

		if err := agent.RunAll(ctx, cfg, crawler, allow, hubTr, siteLog, agent.RuntimeOpts{}); err != nil {
			log.Error("agent_stopped", slog.String("error", err.Error()))
			os.Exit(1)
		}
		return
	}

	port := firstNonEmpty(os.Getenv("PORT"), "8080")
	addr := firstNonEmpty(os.Getenv("EDGEFETCH_BIND_ADDR"), ":"+port)
	serverToken := firstNonEmpty(os.Getenv("EDGEFETCH_CALLER_TOKEN"), os.Getenv("CALLER_TOKEN"), os.Getenv("EDGEFETCH_SERVER_TOKEN"), os.Getenv("CRAWLER_TOKEN"))
	allowUnauth := hasFlag(os.Args[1:], "--allow-unauthenticated") || isTruthyEnv(os.Getenv("EDGEFETCH_ALLOW_UNAUTHENTICATED"))
	if flagAddr := flagValue(os.Args[1:], "--addr="); flagAddr != "" {
		addr = flagAddr
	}
	if err := validateServerSecurity(addr, serverToken, allowUnauth); err != nil {
		log.Error("server_security_config", slog.String("error", err.Error()))
		os.Exit(2)
	}

	ua := firstNonEmpty(os.Getenv("EDGEFETCH_USER_AGENT"), os.Getenv("CRAWLER_USER_AGENT"), crawl.DefaultUserAgent)
	if err := crawl.ValidateUserAgent(ua); err != nil {
		log.Error("invalid_user_agent", slog.String("error", err.Error()))
		os.Exit(2)
	}

	allow := crawl.PublicHTTPS
	var agentCfg agent.Config
	if modes.agent {
		var err error
		agentCfg, err = agent.LoadConfig(agent.DefaultHAOptionsPath)
		if err != nil {
			log.Error("hybrid_agent_config", slog.String("error", err.Error()))
			os.Exit(2)
		}
		allow = crawl.WithAllowedHosts(allow, agentCfg.AllowedHosts)
		for _, hURL := range agentCfg.HubURLs {
			if hubParsed, pErr := url.Parse(hURL); pErr == nil && hubParsed.Hostname() != "" {
				allow = crawl.WithBlockedHost(allow, hubParsed.Hostname())
			}
		}
	}

	defaultOtelSvc := "edgefetch-server"
	if modes.hub {
		defaultOtelSvc = "edgefetch-go-hub"
	}
	crawler := crawl.NewCrawler(newCrawlTransport(60*time.Second, 2), allow, ua, log)
	defer func() { _ = crawler.Close() }()
	crawler.SetRobotsBypassHosts(splitCSV(os.Getenv("EDGEFETCH_ROBOTS_BYPASS_HOSTS")))
	crawler.SetOtelExporter(otel.NewExporterFromEnv(os.Getenv, defaultOtelSvc, agent.Version, hubTr))
	botSigner := configureCrawlerBotAuth(crawler, agentCfg.HubURLs, log)

	var handler http.Handler
	var goHub *hub.Server
	if modes.hub {
		agentTokensMap, tokErr := hub.ParseAgentTokensJSON(firstNonEmpty(os.Getenv("EDGEFETCH_AGENT_TOKENS"), os.Getenv("AGENT_TOKENS")))
		if tokErr != nil {
			log.Error("hub_agent_tokens_config", slog.String("error", tokErr.Error()))
			os.Exit(2)
		}
		sharedAgentTok := firstNonEmpty(os.Getenv("EDGEFETCH_AGENT_TOKEN"), os.Getenv("AGENT_TOKEN"))
		if sharedAgentTok != "" && len(sharedAgentTok) < agent.MinTokenLength {
			log.Error("hub_agent_token_config", slog.String("error", "EDGEFETCH_AGENT_TOKEN must be at least 24 characters"))
			os.Exit(2)
		}
		goHub = hub.NewServer(hub.Config{
			CallerToken:     serverToken,
			AgentToken:      sharedAgentTok,
			AgentTokens:     agentTokensMap,
			PeerURLs:        splitCSV(os.Getenv("EDGEFETCH_PEERS")),
			PeerToken:       firstNonEmpty(os.Getenv("EDGEFETCH_PEER_TOKEN"), serverToken),
			FallbackCrawler: crawler,
			BotSigner:       botSigner,
			BotContactURL:   os.Getenv("BOT_CONTACT_URL"),
			UserAgent:       ua,
			Allow:           allow,
			Logger:          log,
		})
		defer func() { _ = goHub.Close() }()
		handler = goHub
	} else {
		handler = crawl.NewAuthenticatedHandler(crawler, allow, serverToken)
	}

	ln, listenErr := net.Listen("tcp", addr)
	if listenErr != nil {
		log.Error("listen", slog.String("addr", addr), slog.String("error", listenErr.Error()))
		os.Exit(1)
	}
	// Drop root privileges after reading /data/options.json and binding the TCP listener so hybrid/server/hub modes
	// run unprivileged (65532:65532) just like pure agent mode!
	if err := priv.DropRoot(); err != nil {
		log.Error("drop_privileges", slog.String("error", err.Error()))
		_ = ln.Close()
		os.Exit(2)
	}

	srv := newHTTPServer(addr, handler)
	if modes.hub {
		// Long-lived /agent/ws WebSockets must not be killed by a 30s HTTP ReadTimeout!
		srv.ReadTimeout = 0
	}

	go func() {
		log.Info("listening",
			slog.String("addr", srv.Addr),
			slog.Bool("hub_mode", modes.hub),
			slog.Bool("hybrid_agent", modes.agent),
			slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)),
			slog.String("go", runtime.Version()))
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	if modes.agent {
		go func() {
			siteLog := log.With(slog.String("site", agentCfg.SiteID))
			if err := agent.RunAll(ctx, agentCfg, crawler, allow, hubTr, siteLog, agent.RuntimeOpts{}); err != nil {
				siteLog.Error("hybrid_agent_stopped", slog.String("error", err.Error()))
			}
		}()
	}

	<-ctx.Done()

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", slog.String("error", err.Error()))
	}
}

func configureCrawlerBotAuth(c *crawl.Crawler, hubURLs []string, log *slog.Logger) *botauth.Signer {
	privKey := firstNonEmpty(os.Getenv("EDGEFETCH_BOT_SIGNING_KEY"), os.Getenv("BOT_SIGNING_PRIVATE_KEY"))
	if privKey == "" {
		return nil
	}
	dirURL := firstNonEmpty(os.Getenv("EDGEFETCH_BOT_DIRECTORY_URL"), os.Getenv("BOT_DIRECTORY_URL"))
	if dirURL == "" && len(hubURLs) > 0 {
		if u, err := url.Parse(hubURLs[0]); err == nil && u.Host != "" {
			scheme := "https"
			if u.Scheme == "ws" || u.Scheme == "http" {
				scheme = "http"
			}
			dirURL = scheme + "://" + u.Host + "/.well-known/http-message-signatures-directory"
		}
	}
	signer, err := botauth.NewSigner(privKey, dirURL)
	if err != nil {
		log.Error("bot_auth_config_invalid", slog.String("error", err.Error()))
		os.Exit(2)
	}
	c.SetBotSigner(signer)
	log.Info("bot_auth_enabled", slog.String("kid", signer.KeyID()), slog.String("directory", dirURL))
	return signer
}
