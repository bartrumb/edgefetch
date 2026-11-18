// Command edgefetch is a minimal-supply-chain HTTP/2 crawler (one Go dependency, with no transitive dependencies)
// that runs in two modes from one static binary:
//   - server mode (default): listens on $EDGEFETCH_BIND_ADDR or :$PORT (GET /healthz, POST /fetch) authenticated via
//     EDGEFETCH_SERVER_TOKEN (unless bound strictly to loopback or EDGEFETCH_ALLOW_UNAUTHENTICATED=1).
//   - agent mode (--mode=agent, EDGEFETCH_MODE=agent, or /data/options.json on Home Assistant OS): opens zero inbound
//     ports; drops root privileges (65532:65532), dials outbound wss:// to AgentHubDO, and executes pull jobs on demand.
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

	"github.com/bartrumb/edgefetch/internal/agent"
	"github.com/bartrumb/edgefetch/internal/crawl"
	"github.com/bartrumb/edgefetch/internal/politeness"
	"github.com/bartrumb/edgefetch/internal/priv"
	"github.com/bartrumb/edgefetch/internal/ws"
)

const maxResponseHeaderBytes = 64 << 10 // 64 KiB cap prevents giant origin response headers from exhausting memory.

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

func shouldRunAgent(args []string, envMode, haOptionsPath string) bool {
	for _, a := range args {
		switch a {
		case "--mode=agent", "-mode=agent", "agent":
			return true
		case "--mode=server", "-mode=server", "server":
			return false
		}
	}
	switch strings.ToLower(strings.TrimSpace(envMode)) {
	case "agent":
		return true
	case "server":
		return false
	}
	if haOptionsPath != "" {
		if _, err := os.Stat(haOptionsPath); err == nil {
			return true
		}
	}
	return false
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

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	envMode := firstNonEmpty(os.Getenv("EDGEFETCH_MODE"), os.Getenv("CRAWLER_MODE"))
	if shouldRunAgent(os.Args[1:], envMode, agent.DefaultHAOptionsPath) {
		cfg, err := agent.LoadConfig(agent.DefaultHAOptionsPath)
		if err != nil {
			log.Error("agent_config", slog.String("error", err.Error()))
			os.Exit(2)
		}
		if err := priv.DropRoot(); err != nil {
			log.Error("agent_drop_privileges", slog.String("error", err.Error()))
			os.Exit(2)
		}

		hubParsed, _ := url.Parse(cfg.HubURL)
		hubHost := ""
		if hubParsed != nil {
			hubHost = hubParsed.Hostname()
		}
		allow := crawl.WithBlockedHost(crawl.WithAllowedHosts(crawl.PublicHTTPS, cfg.AllowedHosts), hubHost)
		siteLog := log.With(slog.String("site", cfg.SiteID))
		siteLog.Info("agent_startup", slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)), slog.String("go", runtime.Version()))
		crawler := crawl.NewCrawler(newCrawlTransport(90*time.Second, 4), allow, cfg.UserAgent, siteLog)

		if err := agent.Run(ctx, cfg, crawler, allow, newHubTransport(), siteLog, agent.RuntimeOpts{}); err != nil {
			log.Error("agent_stopped", slog.String("error", err.Error()))
			os.Exit(1)
		}
		return
	}

	port := firstNonEmpty(os.Getenv("PORT"), "8080")
	addr := firstNonEmpty(os.Getenv("EDGEFETCH_BIND_ADDR"), ":"+port)
	serverToken := firstNonEmpty(os.Getenv("EDGEFETCH_SERVER_TOKEN"), os.Getenv("CRAWLER_TOKEN"))
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

	crawler := crawl.NewCrawler(newCrawlTransport(60*time.Second, 2), crawl.PublicHTTPS, ua, log)
	srv := &http.Server{
		Addr:              addr,
		Handler:           crawl.NewAuthenticatedHandler(crawler, crawl.PublicHTTPS, serverToken),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    maxResponseHeaderBytes,
	}

	go func() {
		log.Info("listening", slog.String("addr", srv.Addr), slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)), slog.String("go", runtime.Version()))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	<-ctx.Done()

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", slog.String("error", err.Error()))
	}
}
