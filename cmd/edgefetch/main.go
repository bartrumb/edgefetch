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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
	return newHubTransportWithPool(90*time.Second, 2)
}

func newHubTransportWithPool(idleTimeout time.Duration, maxIdlePerHost int) *http.Transport {
	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}
	if maxIdlePerHost <= 0 {
		maxIdlePerHost = 2
	}
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
		MaxIdleConns:           32,
		MaxIdleConnsPerHost:    maxIdlePerHost,
		IdleConnTimeout:        idleTimeout,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        ws.ClassicTLSConfig(),
	}
}

func shouldAllowPrivateOrigin(args []string, getenv func(string) string) bool {
	if hasFlag(args, "--allow-private") {
		return true
	}
	if getenv != nil && isTruthyEnv(getenv("EDGEFETCH_ALLOW_PRIVATE_ORIGIN")) {
		return true
	}
	return false
}

func parseCanonicalAddr(host string) (netip.Addr, bool) {
	clean := politeness.CanonicalHost(strings.Trim(strings.TrimSpace(host), "[]"))
	if clean == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(clean); err == nil {
		return addr.WithZone("").Unmap(), true
	}
	if ip := net.ParseIP(clean); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			return addr.WithZone("").Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func allowHTTPAndHTTPSNoUserInfo(u *url.URL) error {
	if u == nil {
		return errors.New("nil URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("only http/https URLs permitted: %s", u.Redacted())
	}
	if u.User != nil {
		return errors.New("URL with user info")
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return errors.New("URL missing host")
	}
	if addr, ok := parseCanonicalAddr(host); ok && addr.IsUnspecified() {
		return fmt.Errorf("unspecified IP host %q not permitted", host)
	}
	return nil
}

func isLoopbackHostname(h string) bool {
	clean := politeness.CanonicalHost(strings.Trim(strings.TrimSpace(h), "[]"))
	if clean == "localhost" || strings.HasSuffix(clean, ".localhost") {
		return true
	}
	if addr, ok := parseCanonicalAddr(clean); ok {
		return addr.IsLoopback() || addr.IsUnspecified()
	}
	return false
}

func canonicalPort(raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		return ""
	}
	if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
		return strconv.Itoa(n)
	}
	return p
}

func normalizeURLPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return canonicalPort(p)
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	default:
		return ""
	}
}

const blockedHubResolveTTL = 30 * time.Second

type blockedHubRule struct {
	authority   string
	host        string
	port        string
	isLoopback  bool
	literalAddr netip.Addr
	lookupFn    func(context.Context, string, string) ([]netip.Addr, error)
	nowFn       func() time.Time

	mu          sync.Mutex
	resolved    bool
	resolvedAt  time.Time
	resolvedIPs []netip.Addr
	resolvedLB  bool
}

func (r *blockedHubRule) ensureResolved() ([]netip.Addr, bool) {
	if r.isLoopback || r.literalAddr.IsValid() || r.host == "" {
		return nil, false
	}
	nowFn := r.nowFn
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn()

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.resolved && now.Sub(r.resolvedAt) < blockedHubResolveTTL {
		return r.resolvedIPs, r.resolvedLB
	}

	lookup := r.lookupFn
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	ips, err := lookup(ctx, "ip", r.host)
	if err != nil {
		return r.resolvedIPs, r.resolvedLB
	}

	var cleanIPs []netip.Addr
	lb := false
	seen := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		clean := ip.WithZone("").Unmap()
		if !clean.IsValid() {
			continue
		}
		if clean.IsLoopback() || clean.IsUnspecified() {
			lb = true
		}
		if _, ok := seen[clean]; !ok {
			seen[clean] = struct{}{}
			cleanIPs = append(cleanIPs, clean)
		}
	}
	if len(cleanIPs) == 0 {
		return r.resolvedIPs, r.resolvedLB
	}
	r.resolvedIPs = cleanIPs
	r.resolvedLB = lb
	r.resolvedAt = now
	r.resolved = true
	return cleanIPs, lb
}

func newAgentPrivateControl(hubURLs []string) func(network, address string, c syscall.RawConn) error {
	return newAgentPrivateControlWithLookup(hubURLs, nil)
}

func newAgentPrivateControlWithLookup(hubURLs []string, lookupFn func(context.Context, string, string) ([]netip.Addr, error)) func(network, address string, c syscall.RawConn) error {
	rules := make([]*blockedHubRule, 0, len(hubURLs))
	for _, hURL := range hubURLs {
		hubParsed, pErr := url.Parse(hURL)
		if pErr != nil {
			continue
		}
		hubHost := politeness.CanonicalHost(hubParsed.Hostname())
		if hubHost == "" {
			continue
		}
		hubPort := normalizeURLPort(hubParsed)
		hubAddr, isLiteral := parseCanonicalAddr(hubHost)
		if !isLiteral {
			hubAddr = netip.Addr{}
		}
		rules = append(rules, &blockedHubRule{
			authority:   hubParsed.Host,
			host:        hubHost,
			port:        hubPort,
			isLoopback:  isLoopbackHostname(hubHost),
			literalAddr: hubAddr,
			lookupFn:    lookupFn,
		})
	}

	return func(_, address string, _ syscall.RawConn) error {
		host, rawPort, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("invalid dial address %q: %w", address, err)
		}
		port := canonicalPort(rawPort)
		addr, ok := parseCanonicalAddr(host)
		if !ok {
			return fmt.Errorf("refusing dial to unparseable peer IP %q", host)
		}
		if addr.IsUnspecified() {
			return fmt.Errorf("refusing dial to unspecified IP %q", host)
		}
		for _, r := range rules {
			if r.port != "" && port != r.port {
				continue
			}
			if r.isLoopback {
				if addr.IsLoopback() {
					return fmt.Errorf("refusing dial to coordination hub loopback authority %q (%s)", r.authority, address)
				}
				continue
			}
			if r.literalAddr.IsValid() {
				if addr == r.literalAddr {
					return fmt.Errorf("refusing dial to coordination hub authority %q (%s)", r.authority, address)
				}
				continue
			}
			resolvedIPs, resolvedLB := r.ensureResolved()
			if resolvedLB && addr.IsLoopback() {
				return fmt.Errorf("refusing dial to coordination hub loopback authority %q (%s)", r.authority, address)
			}
			for _, rip := range resolvedIPs {
				if addr == rip {
					return fmt.Errorf("refusing dial to coordination hub authority %q (%s)", r.authority, address)
				}
			}
		}
		return nil
	}
}

func newAgentPrivateTransportWithPool(idleTimeout time.Duration, maxIdlePerHost int, hubURLs []string) *http.Transport {
	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}
	if maxIdlePerHost <= 0 {
		maxIdlePerHost = 2
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   newAgentPrivateControl(hubURLs),
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

func withBlockedAuthority(base func(*url.URL) error, hubURL *url.URL) func(*url.URL) error {
	if hubURL == nil {
		return base
	}
	hubHost := politeness.CanonicalHost(hubURL.Hostname())
	hubPort := normalizeURLPort(hubURL)
	if hubHost == "" || hubPort == "" {
		return crawl.WithBlockedHost(base, hubHost)
	}
	hubIsLoopback := isLoopbackHostname(hubHost)
	return func(u *url.URL) error {
		if err := base(u); err != nil {
			return err
		}
		targetHost := politeness.CanonicalHost(u.Hostname())
		targetPort := normalizeURLPort(u)
		hostMatches := targetHost == hubHost || (hubIsLoopback && isLoopbackHostname(targetHost))
		if hostMatches && targetPort == hubPort {
			return fmt.Errorf("refusing recursive fetch of coordination hub %q", hubURL.Host)
		}
		return nil
	}
}

func resolveCrawlPolicy(allowPrivate bool, idleTimeout time.Duration, maxIdlePerHost int) (func(*url.URL) error, *http.Transport) {
	if !allowPrivate {
		return crawl.PublicHTTPS, newCrawlTransport(idleTimeout, maxIdlePerHost)
	}
	return allowHTTPAndHTTPSNoUserInfo, newAgentPrivateTransportWithPool(idleTimeout, maxIdlePerHost, nil)
}

func newAgentCrawlPolicy(allowPrivate bool, allowedHosts, hubURLs []string, idleTimeout time.Duration, maxIdlePerHost int) (func(*url.URL) error, *http.Transport) {
	var baseAllow func(*url.URL) error
	var crawlTr *http.Transport
	if !allowPrivate {
		baseAllow, crawlTr = resolveCrawlPolicy(false, idleTimeout, maxIdlePerHost)
	} else {
		baseAllow = allowHTTPAndHTTPSNoUserInfo
		crawlTr = newAgentPrivateTransportWithPool(idleTimeout, maxIdlePerHost, hubURLs)
	}
	allow := crawl.WithAllowedHosts(baseAllow, allowedHosts)
	for _, hURL := range hubURLs {
		hubParsed, pErr := url.Parse(hURL)
		if pErr != nil || hubParsed.Hostname() == "" {
			continue
		}
		if allowPrivate && isLoopbackHostname(hubParsed.Hostname()) && normalizeURLPort(hubParsed) != "" {
			allow = withBlockedAuthority(allow, hubParsed)
		} else {
			allow = crawl.WithBlockedHost(allow, hubParsed.Hostname())
		}
	}
	return allow, crawlTr
}

type runtimeModes struct {
	server bool
	agent  bool
	hub    bool
	mcp    bool
}

func extractRawMode(args []string) (rawMode string, hasModeFlag bool, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--mode="):
			rawMode = strings.TrimPrefix(a, "--mode=")
			hasModeFlag = true
		case strings.HasPrefix(a, "-mode="):
			rawMode = strings.TrimPrefix(a, "-mode=")
			hasModeFlag = true
		case a == "--mode" || a == "-mode":
			hasModeFlag = true
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return "", true, fmt.Errorf("missing value for %s", a)
			}
			i++
			rawMode = args[i]
		case a == "agent" || a == "server" || a == "hub" || a == "controller":
			rawMode = a
		}
	}
	return rawMode, hasModeFlag, nil
}

func isMCPModeFlag(args []string) bool {
	rawMode, hasModeFlag, err := extractRawMode(args)
	if err != nil || !hasModeFlag {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(rawMode), "mcp")
}

func parseRuntimeModes(args []string, envMode, haOptionsPath string) (runtimeModes, error) {
	rawMode, hasModeFlag, err := extractRawMode(args)
	if err != nil {
		return runtimeModes{}, err
	}
	if !hasModeFlag && rawMode == "" {
		rawMode = strings.TrimSpace(envMode)
	}
	if hasModeFlag && strings.TrimSpace(rawMode) == "" {
		return runtimeModes{}, errors.New("empty --mode value")
	}
	if rawMode != "" {
		var m runtimeModes
		for _, part := range strings.Split(strings.ToLower(rawMode), ",") {
			tok := strings.TrimSpace(part)
			if tok == "" {
				continue
			}
			switch tok {
			case "agent":
				m.agent = true
			case "hub", "controller":
				m.hub = true
			case "server":
				m.server = true
			case "mcp":
				m.mcp = true
			default:
				return runtimeModes{}, fmt.Errorf("unknown mode %q in %q", tok, rawMode)
			}
		}
		if m.mcp && (m.agent || m.hub || m.server) {
			return runtimeModes{}, fmt.Errorf("invalid mode %q: mcp cannot be combined with other modes", rawMode)
		}
		if m.mcp || m.agent || m.hub || m.server {
			return m, nil
		}
		return runtimeModes{}, fmt.Errorf("invalid mode %q", rawMode)
	}
	if haOptionsPath != "" {
		if _, err := os.Stat(haOptionsPath); err == nil {
			return runtimeModes{agent: true}, nil
		}
	}
	return runtimeModes{server: true}, nil
}

func resolveRuntimeModes(args []string, envMode, haOptionsPath string) runtimeModes {
	m, err := parseRuntimeModes(args, envMode, haOptionsPath)
	if err != nil {
		return runtimeModes{}
	}
	return m
}

func shouldRunAgent(args []string, envMode, haOptionsPath string) bool {
	m := resolveRuntimeModes(args, envMode, haOptionsPath)
	return m.agent && !m.hub && !m.server && !m.mcp
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

type mainDeps struct {
	getenv          func(string) string
	goos            string
	haPath          string
	lockDownSecrets func(...string) error
	dropRoot        func() error
	runAgent        func(context.Context, agent.Config, *crawl.Crawler, func(*url.URL) error, http.RoundTripper, *slog.Logger, agent.RuntimeOpts) error
	runDesktop      func(context.Context, []string, io.Writer, io.Writer) int
	stdin           io.Reader
	onListen        func(net.Addr)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if code := runMain(ctx, os.Args, os.Stdout, os.Stderr, mainDeps{}); code != 0 {
		os.Exit(code)
	}
}

func runMain(ctx context.Context, args []string, stdout, stderr io.Writer, deps mainDeps) int {
	if selfExe, err := os.Executable(); err == nil {
		_ = RecoverInterruptedUpdate(selfExe)
	}
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	if deps.goos == "" {
		deps.goos = runtime.GOOS
	}
	if deps.haPath == "" {
		deps.haPath = agent.DefaultHAOptionsPath
	}
	if deps.lockDownSecrets == nil {
		deps.lockDownSecrets = priv.LockDownSecretPaths
	}
	if deps.dropRoot == nil {
		deps.dropRoot = priv.DropRoot
	}
	if deps.runAgent == nil {
		deps.runAgent = agent.RunAll
	}
	if deps.runDesktop == nil {
		deps.runDesktop = runDesktopMode
	}

	var cliArgs []string
	if len(args) > 1 {
		cliArgs = args[1:]
	}

	if isOneShotCLI(cliArgs) {
		return runOneShotCLI(ctx, cliArgs, stdout, stderr, cliDeps{
			getenv: deps.getenv,
			haPath: deps.haPath,
			stdin:  deps.stdin,
		})
	}

	// Zero-setup Desktop Double-Click Experience (Windows / macOS): when launched with zero CLI args and no server/agent
	// env vars configured, start the loopback-only Desktop Launchpad (`127.0.0.1:8787`) and open the browser!
	if len(args) <= 1 && (deps.goos == "windows" || deps.goos == "darwin") &&
		firstNonEmpty(
			deps.getenv("EDGEFETCH_MODE"),
			deps.getenv("CRAWLER_MODE"),
			deps.getenv("PORT"),
			deps.getenv("EDGEFETCH_BIND_ADDR"),
			deps.getenv("EDGEFETCH_SERVER_TOKEN"),
			deps.getenv("EDGEFETCH_CALLER_TOKEN"),
			deps.getenv("CALLER_TOKEN"),
			deps.getenv("EDGEFETCH_HUB_URL"),
			deps.getenv("EDGEFETCH_HUB_URLS"),
		) == "" {
		return deps.runDesktop(ctx, nil, stdout, stderr)
	}

	envMode := firstNonEmpty(deps.getenv("EDGEFETCH_MODE"), deps.getenv("CRAWLER_MODE"))
	modes, modeErr := parseRuntimeModes(cliArgs, envMode, deps.haPath)
	if modeErr != nil {
		_, _ = fmt.Fprintf(stderr, "invalid mode configuration: %v\n", modeErr)
		return 2
	}
	if modes.mcp {
		return runOneShotCLI(ctx, []string{"mcp"}, stdout, stderr, cliDeps{
			getenv: deps.getenv,
			haPath: deps.haPath,
			stdin:  deps.stdin,
		})
	}

	log := slog.New(slog.NewJSONHandler(stdout, nil))
	hubTr := newHubTransport()

	if modes.agent && !modes.hub && !modes.server {
		cfg, err := agent.LoadConfigFrom(deps.haPath, deps.getenv)
		if err != nil {
			log.Error("agent_config", slog.String("error", err.Error()))
			return 2
		}
		if err := deps.lockDownSecrets(deps.haPath); err != nil {
			log.Error("agent_lockdown_secrets", slog.String("error", err.Error()))
			return 2
		}
		if err := deps.dropRoot(); err != nil {
			log.Error("agent_drop_privileges", slog.String("error", err.Error()))
			return 2
		}

		allowPrivate := shouldAllowPrivateOrigin(cliArgs, deps.getenv)
		allow, crawlTr := newAgentCrawlPolicy(allowPrivate, cfg.AllowedHosts, cfg.HubURLs, 90*time.Second, 4)
		siteLog := log.With(slog.String("site", cfg.SiteID))
		siteLog.Info("agent_startup",
			slog.Int("controllers", len(cfg.HubURLs)),
			slog.Bool("allow_private", allowPrivate),
			slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)),
			slog.String("go", runtime.Version()))
		crawler := crawl.NewCrawler(crawlTr, allow, cfg.UserAgent, siteLog)
		defer func() { _ = crawler.Close() }()
		crawler.SetRobotsBypassHosts(cfg.RobotsBypassHosts)
		crawler.SetOtelExporter(otel.NewExporterFromEnv(deps.getenv, "edgefetch-agent-"+cfg.SiteID, agent.Version, hubTr))
		if _, err := configureCrawlerBotAuth(crawler, cfg.HubURLs, deps.getenv, siteLog); err != nil {
			return 2
		}
		warmCtx, cancelWarm := context.WithTimeout(ctx, 6*time.Second)
		_ = crawler.WarmUp(warmCtx)
		cancelWarm()

		if err := deps.runAgent(ctx, cfg, crawler, allow, hubTr, siteLog, agent.RuntimeOpts{}); err != nil {
			log.Error("agent_stopped", slog.String("error", err.Error()))
			return 1
		}
		return 0
	}

	port := firstNonEmpty(deps.getenv("PORT"), "8080")
	addr := firstNonEmpty(deps.getenv("EDGEFETCH_BIND_ADDR"), ":"+port)
	serverToken := firstNonEmpty(deps.getenv("EDGEFETCH_CALLER_TOKEN"), deps.getenv("CALLER_TOKEN"), deps.getenv("EDGEFETCH_SERVER_TOKEN"), deps.getenv("CRAWLER_TOKEN"))
	allowUnauth := hasFlag(cliArgs, "--allow-unauthenticated") || isTruthyEnv(deps.getenv("EDGEFETCH_ALLOW_UNAUTHENTICATED"))
	if flagAddr := flagValue(cliArgs, "--addr="); flagAddr != "" {
		addr = flagAddr
	}
	if err := validateServerSecurity(addr, serverToken, allowUnauth); err != nil {
		log.Error("server_security_config", slog.String("error", err.Error()))
		return 2
	}

	ua := firstNonEmpty(deps.getenv("EDGEFETCH_USER_AGENT"), deps.getenv("CRAWLER_USER_AGENT"), crawl.DefaultUserAgent)
	if err := crawl.ValidateUserAgent(ua); err != nil {
		log.Error("invalid_user_agent", slog.String("error", err.Error()))
		return 2
	}

	allowPrivate := shouldAllowPrivateOrigin(cliArgs, deps.getenv)
	var (
		allow    func(*url.URL) error
		crawlTr  *http.Transport
		agentCfg agent.Config
	)
	if modes.agent {
		var err error
		agentCfg, err = agent.LoadConfigFrom(deps.haPath, deps.getenv)
		if err != nil {
			log.Error("hybrid_agent_config", slog.String("error", err.Error()))
			return 2
		}
		allow, crawlTr = newAgentCrawlPolicy(allowPrivate, agentCfg.AllowedHosts, agentCfg.HubURLs, 60*time.Second, 2)
	} else {
		allow, crawlTr = resolveCrawlPolicy(allowPrivate, 60*time.Second, 2)
	}

	defaultOtelSvc := "edgefetch-server"
	if modes.hub {
		defaultOtelSvc = "edgefetch-go-hub"
	}
	crawler := crawl.NewCrawler(crawlTr, allow, ua, log)
	defer func() { _ = crawler.Close() }()
	bypassHosts := splitCSV(firstNonEmpty(deps.getenv("EDGEFETCH_ROBOTS_BYPASS_HOSTS"), deps.getenv("CRAWLER_ROBOTS_BYPASS_HOSTS")))
	if len(bypassHosts) == 0 && len(agentCfg.RobotsBypassHosts) > 0 {
		bypassHosts = agentCfg.RobotsBypassHosts
	}
	crawler.SetRobotsBypassHosts(bypassHosts)
	otelExp := otel.NewExporterFromEnv(deps.getenv, defaultOtelSvc, agent.Version, hubTr)
	crawler.SetOtelExporter(otelExp)
	botSigner, botErr := configureCrawlerBotAuth(crawler, agentCfg.HubURLs, deps.getenv, log)
	if botErr != nil {
		return 2
	}

	var handler http.Handler
	var goHub *hub.Server
	if modes.hub {
		agentTokensMap, tokErr := hub.ParseAgentTokensJSON(firstNonEmpty(deps.getenv("EDGEFETCH_AGENT_TOKENS"), deps.getenv("AGENT_TOKENS")))
		if tokErr != nil {
			log.Error("hub_agent_tokens_config", slog.String("error", tokErr.Error()))
			return 2
		}
		sharedAgentTok := firstNonEmpty(deps.getenv("EDGEFETCH_AGENT_TOKEN"), deps.getenv("AGENT_TOKEN"))
		if sharedAgentTok != "" && len(sharedAgentTok) < agent.MinTokenLength {
			log.Error("hub_agent_token_config", slog.String("error", "EDGEFETCH_AGENT_TOKEN must be at least 24 characters"))
			return 2
		}
		goHub = hub.NewServer(hub.Config{
			CallerToken:     serverToken,
			AgentToken:      sharedAgentTok,
			AgentTokens:     agentTokensMap,
			PeerURLs:        splitCSV(deps.getenv("EDGEFETCH_PEERS")),
			PeerToken:       firstNonEmpty(deps.getenv("EDGEFETCH_PEER_TOKEN"), serverToken),
			FallbackCrawler: crawler,
			BotSigner:       botSigner,
			BotContactURL:   deps.getenv("BOT_CONTACT_URL"),
			UserAgent:       ua,
			Allow:           allow,
			Logger:          log,
			OtelExporter:    otelExp,
		})
		defer func() { _ = goHub.Close() }()
		handler = goHub
	} else {
		handler = crawl.NewAuthenticatedHandler(crawler, allow, serverToken)
	}

	ln, listenErr := net.Listen("tcp", addr)
	if listenErr != nil {
		log.Error("listen", slog.String("addr", addr), slog.String("error", listenErr.Error()))
		return 1
	}
	if deps.onListen != nil {
		deps.onListen(ln.Addr())
	}
	// Drop root privileges after reading /data/options.json, locking down /data, and binding the TCP listener so
	// hybrid/server/hub modes run unprivileged (65532:65532) just like pure agent mode!
	if err := deps.lockDownSecrets(deps.haPath); err != nil {
		log.Error("lockdown_secrets", slog.String("error", err.Error()))
		_ = ln.Close()
		return 2
	}
	if err := deps.dropRoot(); err != nil {
		log.Error("drop_privileges", slog.String("error", err.Error()))
		_ = ln.Close()
		return 2
	}

	srv := newHTTPServer(addr, handler)
	if modes.hub {
		// Long-lived /agent/ws WebSockets must not be killed by a 30s HTTP ReadTimeout!
		srv.ReadTimeout = 0
	}

	serveErrCh := make(chan error, 1)
	go func() {
		log.Info("listening",
			slog.String("addr", ln.Addr().String()),
			slog.Bool("hub_mode", modes.hub),
			slog.Bool("hybrid_agent", modes.agent),
			slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)),
			slog.String("go", runtime.Version()))
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", slog.String("error", err.Error()))
			serveErrCh <- err
		}
	}()

	var hybridWg sync.WaitGroup
	if modes.agent {
		hybridWg.Add(1)
		go func() {
			defer hybridWg.Done()
			siteLog := log.With(slog.String("site", agentCfg.SiteID))
			if err := deps.runAgent(ctx, agentCfg, crawler, allow, hubTr, siteLog, agent.RuntimeOpts{}); err != nil {
				siteLog.Error("hybrid_agent_stopped", slog.String("error", err.Error()))
			}
		}()
	}

	exitCode := 0
	select {
	case <-ctx.Done():
	case <-serveErrCh:
		exitCode = 1
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", slog.String("error", err.Error()))
	}
	hybridWg.Wait()
	return exitCode
}

func configureCrawlerBotAuth(c *crawl.Crawler, hubURLs []string, getenv func(string) string, log *slog.Logger) (*botauth.Signer, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	privKey := firstNonEmpty(getenv("EDGEFETCH_BOT_SIGNING_KEY"), getenv("BOT_SIGNING_PRIVATE_KEY"))
	if privKey == "" {
		return nil, nil
	}
	dirURL := firstNonEmpty(getenv("EDGEFETCH_BOT_DIRECTORY_URL"), getenv("BOT_DIRECTORY_URL"))
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
		return nil, err
	}
	c.SetBotSigner(signer)
	log.Info("bot_auth_enabled", slog.String("kid", signer.KeyID()), slog.String("directory", dirURL))
	return signer, nil
}
