package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/crawl"
)

const (
	DefaultHAOptionsPath = "/data/options.json"
	DefaultPauseMs       = 3000
	DefaultPauseJitterMs = 1500
	MinTokenLength       = 24
)

var validSiteID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Config holds validated settings for outbound `agent` mode (including multi-controller HA via `HubURLs`).
type Config struct {
	HubURL        string   `json:"hub_url"`
	HubURLs       []string `json:"hub_urls,omitempty"`
	AgentToken    string   `json:"agent_token"`
	SiteID        string   `json:"site_id"`
	UserAgent     string   `json:"user_agent"`
	PauseMs       int      `json:"pause_ms"`
	PauseJitterMs int      `json:"pause_jitter_ms"`
	AllowedHosts  []string `json:"allowed_hosts"`
}

// LoadConfig loads `/data/options.json` (when present) and overlays `EDGEFETCH_*` (or `CRAWLER_*`) environment variables.
func LoadConfig(optionsPath string) (Config, error) {
	return LoadConfigFrom(optionsPath, os.Getenv)
}

func firstEnv(getenv func(string) string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "127.0.0.1" || h == "::1" || h == "localhost"
}

func isDockerBridgeHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" {
		return false
	}
	if h == "host.docker.internal" {
		return true
	}
	// Single-label Docker Compose service name (e.g. "hub" or "edgefetch-hub"), never a public multi-label FQDN.
	return !strings.Contains(h, ".") && !strings.Contains(h, ":")
}

// normalizeHubURL accepts `https://...` or `wss://...` (and `http://`/`ws://` for local loopback tests) and strips any
// trailing `/agent/ws` path so users can pass either the Hub origin or full WebSocket endpoint URL interchangeably.
func normalizeHubURL(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "wss://"):
		s = "https://" + s[len("wss://"):]
	case strings.HasPrefix(lower, "ws://"):
		s = "http://" + s[len("ws://"):]
	}
	if strings.HasSuffix(strings.ToLower(s), "/agent/ws") {
		s = strings.TrimRight(s[:len(s)-len("/agent/ws")], "/")
	}
	return s
}

// LoadConfigFrom is the pure, testable configuration loader used by `LoadConfig`.
func LoadConfigFrom(optionsPath string, getenv func(string) string) (Config, error) {
	cfg := Config{
		UserAgent:     crawl.DefaultUserAgent,
		PauseMs:       DefaultPauseMs,
		PauseJitterMs: DefaultPauseJitterMs,
	}

	if optionsPath != "" {
		raw, err := os.ReadFile(optionsPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Config{}, fmt.Errorf("read %s: %w", optionsPath, err)
		}
		if err == nil {
			// Best-effort zeroing of the raw read slice on return (note: json.Unmarshal still allocates immutable Go
			// string copies for parsed fields on the heap).
			defer func() {
				for i := range raw {
					raw[i] = 0
				}
			}()
			if len(strings.TrimSpace(string(raw))) > 0 {
				if err := json.Unmarshal(raw, &cfg); err != nil {
					return Config{}, fmt.Errorf("parse %s: %w", optionsPath, err)
				}
			}
		}
	}

	if v := firstEnv(getenv, "EDGEFETCH_HUB_URL", "CRAWLER_HUB_URL"); v != "" {
		cfg.HubURL = v
	}
	if v := firstEnv(getenv, "EDGEFETCH_HUB_URLS", "CRAWLER_HUB_URLS"); v != "" {
		parts := strings.Split(v, ",")
		urls := make([]string, 0, len(parts))
		for _, p := range parts {
			if clean := strings.TrimSpace(p); clean != "" {
				urls = append(urls, clean)
			}
		}
		if len(urls) > 0 {
			cfg.HubURLs = urls
		}
	}
	if v := firstEnv(getenv, "EDGEFETCH_AGENT_TOKEN", "CRAWLER_AGENT_TOKEN"); v != "" {
		cfg.AgentToken = v
	}
	if v := firstEnv(getenv, "EDGEFETCH_SITE_ID", "CRAWLER_SITE_ID"); v != "" {
		cfg.SiteID = v
	}
	if v := firstEnv(getenv, "EDGEFETCH_USER_AGENT", "CRAWLER_USER_AGENT"); v != "" {
		cfg.UserAgent = v
	}
	if v := firstEnv(getenv, "EDGEFETCH_PAUSE_MS", "CRAWLER_PAUSE_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid pause_ms %q: %w", v, err)
		}
		cfg.PauseMs = n
	}
	if v := firstEnv(getenv, "EDGEFETCH_PAUSE_JITTER_MS", "CRAWLER_PAUSE_JITTER_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid pause_jitter_ms %q: %w", v, err)
		}
		cfg.PauseJitterMs = n
	}
	if v := firstEnv(getenv, "EDGEFETCH_ALLOWED_HOSTS", "CRAWLER_ALLOWED_HOSTS"); v != "" {
		parts := strings.Split(v, ",")
		hosts := make([]string, 0, len(parts))
		for _, p := range parts {
			if h := strings.TrimSpace(p); h != "" {
				hosts = append(hosts, h)
			}
		}
		cfg.AllowedHosts = hosts
	}

	var rawHubs []string
	if len(cfg.HubURLs) > 0 {
		rawHubs = append(rawHubs, cfg.HubURLs...)
	}
	if strings.TrimSpace(cfg.HubURL) != "" {
		rawHubs = append(rawHubs, cfg.HubURL)
	}

	// Security Invariant: NEVER allow cleartext `http://` to a public FQDN or LAN IP, even if a test env var is set,
	// so `Bearer <agent_token>` can never traverse a LAN or WAN interface unencrypted.
	allowLoopbackHTTP := firstEnv(getenv, "EDGEFETCH_ALLOW_INSECURE_HUB", "CRAWLER_ALLOW_INSECURE_HUB") == "1"
	allowDockerHTTP := firstEnv(getenv, "EDGEFETCH_ALLOW_INSECURE_DOCKER_HUB") == "1"

	seenHubs := make(map[string]bool, len(rawHubs))
	normalizedHubs := make([]string, 0, len(rawHubs))
	for _, rh := range rawHubs {
		norm := normalizeHubURL(rh)
		if norm == "" || seenHubs[norm] {
			continue
		}
		u, err := url.Parse(norm)
		if err != nil || u.Host == "" {
			return Config{}, fmt.Errorf("invalid hub_url %q", rh)
		}
		allowedCleartext := u.Scheme == "http" && ((allowLoopbackHTTP && isLoopbackHost(u.Hostname())) || (allowDockerHTTP && isDockerBridgeHost(u.Hostname())))
		if u.Scheme != "https" && !allowedCleartext {
			return Config{}, fmt.Errorf("hub_url must use https or wss (cleartext http/ws allowed only on 127.0.0.1/::1 in local tests; got %q)", u.Redacted())
		}
		seenHubs[norm] = true
		normalizedHubs = append(normalizedHubs, norm)
	}
	if len(normalizedHubs) == 0 {
		return Config{}, errors.New("hub_url is required (e.g. https://your-hub.workers.dev)")
	}
	cfg.HubURLs = normalizedHubs
	cfg.HubURL = normalizedHubs[0]

	cfg.SiteID = strings.ToLower(strings.TrimSpace(cfg.SiteID))
	cfg.AgentToken = strings.TrimSpace(cfg.AgentToken)
	if strings.TrimSpace(cfg.UserAgent) == "" {
		cfg.UserAgent = crawl.DefaultUserAgent
	} else {
		cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	}

	if err := crawl.ValidateUserAgent(cfg.UserAgent); err != nil {
		return Config{}, err
	}
	if cfg.PauseMs < 1000 {
		cfg.PauseMs = 1000
	}
	if cfg.PauseMs > 60_000 {
		cfg.PauseMs = 60_000
	}
	if cfg.PauseJitterMs < 0 {
		cfg.PauseJitterMs = 0
	}
	if cfg.PauseJitterMs > crawl.MaxPauseJitterMs {
		cfg.PauseJitterMs = crawl.MaxPauseJitterMs
	}
	if len(cfg.AgentToken) < MinTokenLength {
		return Config{}, fmt.Errorf("agent_token must be at least %d characters", MinTokenLength)
	}
	if !validSiteID.MatchString(cfg.SiteID) {
		return Config{}, fmt.Errorf("site_id %q must match %s", cfg.SiteID, validSiteID.String())
	}

	return cfg, nil
}
