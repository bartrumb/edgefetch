// Package agent implements the outbound-only WebSocket worker loop for Home Assistant OS and edge standby nodes.
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

	"github.com/bartrumb/edgefetch/internal/crawl"
)

const (
	DefaultHAOptionsPath = "/data/options.json"
	DefaultPauseMs       = 3000
	DefaultPauseJitterMs = 1500
	MinTokenLength       = 24
)

var validSiteID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Config holds validated settings for outbound `agent` mode.
type Config struct {
	HubURL        string   `json:"hub_url"`
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

	cfg.HubURL = strings.TrimRight(strings.TrimSpace(cfg.HubURL), "/")
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

	if cfg.HubURL == "" {
		return Config{}, errors.New("hub_url is required (e.g. https://your-hub.workers.dev)")
	}
	u, err := url.Parse(cfg.HubURL)
	if err != nil || u.Host == "" {
		return Config{}, fmt.Errorf("invalid hub_url %q", cfg.HubURL)
	}

	// Security Invariant: NEVER allow cleartext `http://` to a non-loopback address, even if a test env var is set,
	// so `Bearer <agent_token>` can never traverse a LAN or WAN interface unencrypted.
	allowLoopbackHTTP := firstEnv(getenv, "EDGEFETCH_ALLOW_INSECURE_HUB", "CRAWLER_ALLOW_INSECURE_HUB") == "1"
	if u.Scheme != "https" && !(allowLoopbackHTTP && u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return Config{}, fmt.Errorf("hub_url must use https (cleartext http allowed only on 127.0.0.1/::1 in local tests; got %q)", u.Redacted())
	}
	if len(cfg.AgentToken) < MinTokenLength {
		return Config{}, fmt.Errorf("agent_token must be at least %d characters", MinTokenLength)
	}
	if !validSiteID.MatchString(cfg.SiteID) {
		return Config{}, fmt.Errorf("site_id %q must match %s", cfg.SiteID, validSiteID.String())
	}

	return cfg, nil
}
