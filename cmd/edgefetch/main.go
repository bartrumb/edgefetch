// Command edgefetch is a zero-dependency, security-hardened HTTP/2 crawler that runs in two modes from one ~9 MB
// static binary:
//   - `server` mode (default): listens on `:$PORT` (`GET /healthz`, `POST /fetch`) for Cloudflare Containers or Docker.
//   - `agent` mode (`--mode=agent`, `EDGEFETCH_MODE=agent`, or `/data/options.json` on Home Assistant OS): opens ZERO
//     inbound ports; drops root privileges (`65532:65532`), dials outbound `wss://` to a Cloudflare Hibernating
//     WebSocket Durable Object (`AgentHubDO`), and executes polite cold-standby fetch jobs on demand.
//
// Suggested package reading order for Go developers:
//  1. `cmd/edgefetch/main.go`      — Binary entrypoint, HTTP/2 transport construction, `SIGTERM` graceful drain.
//  2. `internal/politeness`        — Context-aware `chan struct{}` host locks, `robots.txt`, circuit breakers, SSRF guard.
//  3. `internal/classify`          — Zero-cost defined string enums (`Kind`, `Outcome`) and dynamic JSON assertions.
//  4. `internal/crawl`             — Worker pool (`WaitGroup`, lock-free slice writes), `httptrace`, HTTP `/fetch` server.
//  5. `internal/ws`                — Pure stdlib RFC 6455 TLS WebSocket client (`crypto/tls` + frame masking).
//  6. `internal/priv`              — Linux `prctl(PR_SET_NO_NEW_PRIVS)` + `AllThreadsSyscall` root privilege drop.
//  7. `internal/agent`             — Outbound supervisor loop, reconnect backoff, and gzipped `POST /agent/reply` uploader.
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
		crawler := crawl.NewCrawler(newCrawlTransport(90*time.Second, 4), allow, cfg.UserAgent, siteLog)

		if err := agent.Run(ctx, cfg, crawler, allow, newHubTransport(), siteLog, agent.RuntimeOpts{}); err != nil {
			log.Error("agent_stopped", slog.String("error", err.Error()))
			os.Exit(1)
		}
		return
	}

	port := firstNonEmpty(os.Getenv("PORT"), "8080")
	ua := firstNonEmpty(os.Getenv("EDGEFETCH_USER_AGENT"), os.Getenv("CRAWLER_USER_AGENT"), crawl.DefaultUserAgent)
	if err := crawl.ValidateUserAgent(ua); err != nil {
		log.Error("invalid_user_agent", slog.String("error", err.Error()))
		os.Exit(2)
	}

	crawler := crawl.NewCrawler(newCrawlTransport(60*time.Second, 2), crawl.PublicHTTPS, ua, log)
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           crawl.NewHandler(crawler, crawl.PublicHTTPS),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    maxResponseHeaderBytes,
	}

	go func() {
		log.Info("listening", slog.String("addr", srv.Addr))
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
