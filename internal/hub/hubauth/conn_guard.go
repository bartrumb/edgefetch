package hubauth

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultMaxTotalConns    = 512
	DefaultMaxConnsPerIP    = 64
	DefaultLoopbackReserved = 32
	DefaultPreHeaderTimeout = 10 * time.Second
)

var (
	reStrictSingleHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::([1-9]\d{0,4}))?$`)
	reStrictFlyAppName = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ConnGuardOptions configures socket admission and pre-header timeout limits.
type ConnGuardOptions struct {
	MaxTotal         int
	MaxPerIP         int
	LoopbackReserved int
	PreHeaderTimeout time.Duration
	IdleTimeout      time.Duration
}

func (o ConnGuardOptions) normalized() ConnGuardOptions {
	if o.MaxTotal <= 0 {
		o.MaxTotal = DefaultMaxTotalConns
	}
	if o.MaxPerIP <= 0 {
		o.MaxPerIP = DefaultMaxConnsPerIP
	}
	if o.LoopbackReserved <= 0 {
		o.LoopbackReserved = DefaultLoopbackReserved
	}
	if o.PreHeaderTimeout <= 0 {
		o.PreHeaderTimeout = DefaultPreHeaderTimeout
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 60 * time.Second
	}
	return o
}

// GuardedListener wraps a net.Listener with global and per-IP active socket caps
// while preserving dedicated loopback headroom so local /health probes never starve.
type GuardedListener struct {
	net.Listener
	opts           ConnGuardOptions
	mu             sync.Mutex
	activeTotal    int
	activeLoopback int
	activeByIP     map[string]int
	rejectedTotal  atomic.Int64
	rejectedPerIP  atomic.Int64
}

// WrapListener wraps ln with per-IP and global socket limits plus loopback reservation.
func WrapListener(ln net.Listener, opts ConnGuardOptions) *GuardedListener {
	return &GuardedListener{Listener: ln, opts: opts.normalized(), activeByIP: make(map[string]int)}
}

// Accept waits for and returns the next admitted connection to the listener.
func (g *GuardedListener) Accept() (net.Conn, error) {
	for {
		conn, err := g.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, isLoopback := classifyRemoteAddr(conn.RemoteAddr())
		if !g.admit(ip, isLoopback) {
			_ = conn.Close()
			continue
		}
		return &guardedConn{Conn: conn, parent: g, ip: ip, isLoopback: isLoopback}, nil
	}
}

func (g *GuardedListener) admit(ip string, isLoopback bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if isLoopback {
		maxLoop := max(g.opts.MaxPerIP+g.opts.LoopbackReserved, g.opts.LoopbackReserved)
		if g.activeLoopback >= maxLoop {
			g.rejectedTotal.Add(1)
			return false
		}
		g.activeLoopback++
		return true
	}
	if g.activeTotal >= g.opts.MaxTotal {
		g.rejectedTotal.Add(1)
		return false
	}
	if g.activeByIP[ip] >= g.opts.MaxPerIP {
		g.rejectedPerIP.Add(1)
		return false
	}
	g.activeTotal++
	g.activeByIP[ip]++
	return true
}

func (g *GuardedListener) release(ip string, isLoopback bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if isLoopback {
		if g.activeLoopback > 0 {
			g.activeLoopback--
		}
		return
	}
	if g.activeTotal > 0 {
		g.activeTotal--
	}
	if cur := g.activeByIP[ip]; cur <= 1 {
		delete(g.activeByIP, ip)
	} else {
		g.activeByIP[ip] = cur - 1
	}
}

// Stats returns a snapshot of active and rejected socket counters.
func (g *GuardedListener) Stats() (nonLoopbackActive, loopbackActive int, rejectedTotal, rejectedPerIP int64) {
	g.mu.Lock()
	nonLoopbackActive, loopbackActive = g.activeTotal, g.activeLoopback
	g.mu.Unlock()
	return nonLoopbackActive, loopbackActive, g.rejectedTotal.Load(), g.rejectedPerIP.Load()
}

type guardedConn struct {
	net.Conn
	parent     *GuardedListener
	ip         string
	isLoopback bool
	once       sync.Once
}

func (c *guardedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.parent.release(c.ip, c.isLoopback) })
	return err
}

// TrackConnState installs pre-header timeout and per-IP/global pre-header socket tracking onto srv.
func TrackConnState(srv *http.Server, opts ConnGuardOptions) {
	if srv == nil {
		return
	}
	o := opts.normalized()
	if srv.ReadHeaderTimeout <= 0 {
		srv.ReadHeaderTimeout = o.PreHeaderTimeout
	}
	if srv.IdleTimeout <= 0 {
		srv.IdleTimeout = o.IdleTimeout
	}
	prevHook := srv.ConnState
	var (
		mu          sync.Mutex
		preByConn   = make(map[net.Conn]string)
		preByIP     = make(map[string]int)
		preNonLoop  int
		preLoopback int
	)
	clearPreHeader := func(c net.Conn) {
		mu.Lock()
		if ip, tracked := preByConn[c]; tracked {
			delete(preByConn, c)
			if ip == "" {
				preLoopback = max(preLoopback-1, 0)
			} else {
				preNonLoop = max(preNonLoop-1, 0)
				if preByIP[ip] <= 1 {
					delete(preByIP, ip)
				} else {
					preByIP[ip]--
				}
			}
		}
		mu.Unlock()
	}
	srv.ConnState = func(c net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			ip, isLoop := classifyRemoteAddr(c.RemoteAddr())
			admitted := true
			mu.Lock()
			if isLoop {
				if preLoopback >= o.MaxPerIP+o.LoopbackReserved {
					admitted = false
				} else {
					preLoopback++
					preByConn[c] = ""
				}
			} else if preNonLoop >= o.MaxTotal || preByIP[ip] >= o.MaxPerIP {
				admitted = false
			} else {
				preNonLoop++
				preByIP[ip]++
				preByConn[c] = ip
			}
			mu.Unlock()
			if !admitted {
				_ = c.Close()
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(o.PreHeaderTimeout))
		case http.StateActive:
			clearPreHeader(c)
			if srv.ReadTimeout > 0 {
				_ = c.SetReadDeadline(time.Now().Add(srv.ReadTimeout))
			} else {
				_ = c.SetReadDeadline(time.Time{})
			}
		case http.StateIdle:
			clearPreHeader(c)
			_ = c.SetReadDeadline(time.Now().Add(o.IdleTimeout))
		case http.StateHijacked, http.StateClosed:
			clearPreHeader(c)
		}
		if prevHook != nil {
			prevHook(c, state)
		}
	}
}

func classifyRemoteAddr(addr net.Addr) (ip string, isLoopback bool) {
	if addr == nil {
		return "127.0.0.1", true
	}
	parsed, ok := parseNormalizedAddr(addr.String())
	if !ok {
		return "127.0.0.1", true
	}
	return parsed.String(), parsed.IsLoopback()
}

func parseNormalizedAddr(raw string) (netip.Addr, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, false
	}
	if strings.HasPrefix(s, "[") {
		if idx := strings.IndexByte(s, ']'); idx > 1 {
			s = s[1:idx]
		}
	} else if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if idx := strings.IndexByte(s, '%'); idx >= 0 {
		s = s[:idx]
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// ResolveClientIP extracts the canonical client IP for rate limiting and audit logging.
func ResolveClientIP(r *http.Request, trustProxy, trustFly bool) string {
	if r == nil {
		return "127.0.0.1"
	}
	if trustFly {
		if vals := r.Header.Values("Fly-Client-IP"); len(vals) > 0 {
			if last := strings.TrimSpace(vals[len(vals)-1]); last != "" && !strings.Contains(last, ",") {
				if addr, ok := parseNormalizedAddr(last); ok {
					return addr.String()
				}
			}
		}
	}
	if trustProxy {
		if vals := r.Header.Values("X-Forwarded-For"); len(vals) > 0 {
			parts := strings.Split(strings.Join(vals, ","), ",")
			for i := len(parts) - 1; i >= 0; i-- {
				cand := strings.TrimSpace(parts[i])
				if cand == "" {
					continue
				}
				if addr, ok := parseNormalizedAddr(cand); ok {
					return addr.String()
				}
				break
			}
		}
	}
	if addr, ok := parseNormalizedAddr(r.RemoteAddr); ok {
		return addr.String()
	}
	return "127.0.0.1"
}

func parseStrictSingleHost(raw string) (string, bool) {
	if strings.Contains(raw, ",") || strings.Contains(raw, "..") || strings.Contains(raw, "[") || strings.Contains(raw, "]") {
		return "", false
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 255 || strings.ContainsAny(trimmed, " \t\r\n") {
		return "", false
	}
	lower := strings.ToLower(trimmed)
	m := reStrictSingleHost.FindStringSubmatch(lower)
	if len(m) == 0 {
		return "", false
	}
	if m[1] != "" {
		if portNum, err := strconv.Atoi(m[1]); err != nil || portNum < 1 || portNum > 65535 {
			return "", false
		}
	}
	return lower, true
}

func isLoopbackHostname(h string) bool {
	clean := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(h)), "["), "]")
	return clean == "127.0.0.1" || clean == "localhost" || clean == "::1"
}

func formatCanonicalOrigin(scheme, host string) (string, error) {
	scheme = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(scheme), ":"))
	if scheme != "http" && scheme != "https" {
		return "", errors.New("unsupported scheme")
	}
	u, err := url.Parse(scheme + "://" + strings.TrimSpace(host))
	if err != nil || u.Host == "" || u.User != nil {
		return "", errors.New("invalid origin host")
	}
	hostname, port := strings.ToLower(u.Hostname()), u.Port()
	if port != "" {
		portNum, pErr := strconv.Atoi(port)
		if pErr != nil || portNum < 1 || portNum > 65535 {
			return "", errors.New("invalid port")
		}
		if (scheme == "http" && portNum == 80) || (scheme == "https" && portNum == 443) {
			port = ""
		}
	}
	authority := hostname
	if strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}
	if port != "" {
		authority += ":" + port
	}
	return scheme + "://" + authority, nil
}

func parseOriginCandidate(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" || strings.ContainsAny(trimmed, " \t\r\n") {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || strings.Contains(u.Host, "@") {
		return ""
	}
	if _, ok := parseStrictSingleHost(u.Host); !ok && !isLoopbackHostname(u.Hostname()) {
		return ""
	}
	orig, err := formatCanonicalOrigin(u.Scheme, u.Host)
	if err != nil {
		return ""
	}
	return orig
}

// ResolveConfiguredPublicOrigin resolves explicit or platform-injected public origin env vars.
func ResolveConfiguredPublicOrigin(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}
	for _, key := range []string{"EDGEFETCH_PUBLIC_ORIGIN", "RENDER_EXTERNAL_URL"} {
		if v := parseOriginCandidate(getenv(key)); v != "" {
			return v
		}
	}
	for _, key := range []string{"RENDER_EXTERNAL_HOSTNAME", "RAILWAY_PUBLIC_DOMAIN"} {
		if h, ok := parseStrictSingleHost(getenv(key)); ok && strings.Contains(h, ".") {
			if orig, err := formatCanonicalOrigin("https", h); err == nil {
				return orig
			}
		}
	}
	if rs := parseOriginCandidate(getenv("RAILWAY_STATIC_URL")); rs != "" {
		return rs
	}
	if rh, ok := parseStrictSingleHost(getenv("RAILWAY_STATIC_URL")); ok && strings.Contains(rh, ".") {
		if orig, err := formatCanonicalOrigin("https", rh); err == nil {
			return orig
		}
	}
	if flyApp := strings.TrimSpace(getenv("FLY_APP_NAME")); flyApp != "" && reStrictFlyAppName.MatchString(flyApp) {
		return "https://" + strings.ToLower(flyApp) + ".fly.dev"
	}
	return ""
}

func validateRawHostHeader(raw string) (hostname, port, authority string, ok bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", "", true
	}
	if len(trimmed) > 255 || strings.ContainsAny(trimmed, ",/\\@ \t\r\n") || strings.Contains(trimmed, "..") {
		return "", "", "", false
	}
	if strings.HasPrefix(trimmed, "[") {
		end := strings.IndexByte(trimmed, ']')
		if end <= 1 || strings.Contains(trimmed[1:end], "%") {
			return "", "", "", false
		}
		addr, err := netip.ParseAddr(trimmed[1:end])
		if err != nil || !addr.Is6() {
			return "", "", "", false
		}
		lowerInner := strings.ToLower(trimmed[1:end])
		rem := trimmed[end+1:]
		if rem != "" {
			if !strings.HasPrefix(rem, ":") {
				return "", "", "", false
			}
			pNum, pErr := strconv.Atoi(rem[1:])
			if pErr != nil || pNum < 1 || pNum > 65535 {
				return "", "", "", false
			}
			port = strconv.Itoa(pNum)
			return lowerInner, port, "[" + lowerInner + "]:" + port, true
		}
		return lowerInner, "", "[" + lowerInner + "]", true
	}
	if h, okStrict := parseStrictSingleHost(trimmed); okStrict {
		u, err := url.Parse("http://" + h)
		if err != nil {
			return "", "", "", false
		}
		return u.Hostname(), u.Port(), h, true
	}
	return "", "", "", false
}

// ResolveRequestPublicOrigin resolves the canonical origin for r while rejecting malformed or multi-Host headers.
func ResolveRequestPublicOrigin(r *http.Request, configuredOrigin, fallbackOrigin string, trustProxy bool) (origin string, validHost bool) {
	if r != nil {
		hostVals := r.Header.Values("Host")
		if len(hostVals) > 1 {
			return "", false
		}
		if len(hostVals) == 1 {
			if _, _, _, ok := validateRawHostHeader(hostVals[0]); !ok {
				return "", false
			}
		}
		if r.Host != "" {
			if _, _, _, ok := validateRawHostHeader(r.Host); !ok {
				return "", false
			}
		}
	}
	if cfgOrig := parseOriginCandidate(configuredOrigin); cfgOrig != "" {
		return cfgOrig, true
	}
	baseOrig := parseOriginCandidate(fallbackOrigin)
	if baseOrig == "" {
		baseOrig = "http://127.0.0.1:8787"
	}
	baseURL, err := url.Parse(baseOrig)
	if err != nil {
		return "http://127.0.0.1:8787", true
	}
	baseScheme, basePort := strings.ToLower(baseURL.Scheme), baseURL.Port()
	if basePort == "" {
		if baseScheme == "https" {
			basePort = "443"
		} else {
			basePort = "80"
		}
	}
	var reqHostname, reqPort, reqAuthority string
	if r != nil && strings.TrimSpace(r.Host) != "" {
		h, p, auth, ok := validateRawHostHeader(r.Host)
		if !ok {
			return "", false
		}
		reqHostname, reqPort, reqAuthority = h, p, auth
	}
	samePortLoopback := ""
	if reqAuthority != "" && (isLoopbackHostname(baseURL.Hostname()) || strings.EqualFold(baseURL.Hostname(), "hub.local")) {
		candPort := reqPort
		if candPort == "" {
			candPort = "80"
		}
		if isLoopbackHostname(reqHostname) && candPort == basePort {
			samePortLoopback = reqAuthority
		}
	}
	if !trustProxy {
		authority := baseURL.Host
		if samePortLoopback != "" {
			authority = samePortLoopback
		}
		if orig, fErr := formatCanonicalOrigin(baseScheme, authority); fErr == nil {
			return orig, true
		}
		return baseOrig, true
	}
	proto := baseScheme
	if r != nil && r.TLS != nil {
		proto = "https"
	}
	if r != nil {
		parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-Proto"), ","), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if tok := strings.ToLower(strings.TrimSpace(parts[i])); tok != "" {
				if tok == "https" || tok == "http" {
					proto = tok
				}
				break
			}
		}
	}
	allowLoopback := samePortLoopback != "" || (reqAuthority != "" && isLoopbackHostname(baseURL.Hostname()) && isLoopbackHostname(reqHostname))
	authority := baseURL.Host
	if allowLoopback && reqAuthority != "" {
		authority = reqAuthority
	}
	if orig, fErr := formatCanonicalOrigin(proto, authority); fErr == nil {
		return orig, true
	}
	return baseOrig, true
}

// ApplySecurityHeaders sets baseline browser security headers on w.
func ApplySecurityHeaders(w http.ResponseWriter, isHTTPS bool) {
	if w == nil {
		return
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	if isHTTPS {
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

// ParseRedirectAllowlist splits a comma/whitespace OAUTH_REDIRECT_ALLOWLIST env value.
func ParseRedirectAllowlist(raw string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) {
		if s := strings.TrimSpace(f); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func normalizeOAuthResource(raw, origin string) (string, bool) {
	canon := strings.TrimRight(origin, "/") + "/mcp"
	if strings.TrimSpace(raw) == "" {
		return canon, true
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", false
	}
	candOrig, oErr := formatCanonicalOrigin(u.Scheme, u.Host)
	if oErr != nil || !strings.EqualFold(candOrig, strings.TrimRight(origin, "/")) {
		return "", false
	}
	if u.Path == "" || u.Path == "/" || u.Path == "/mcp" {
		return canon, true
	}
	return "", false
}
