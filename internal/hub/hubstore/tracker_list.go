package hubstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/extract"
)

const (
	EasyPrivacySourceURL       = "https://easylist.to/easylist/easyprivacy.txt"
	EasyPrivacyLicenseURL      = "https://easylist.to/pages/licence.html"
	TrackerListUserAgent       = "EdgeFetch/2.7"
	DefaultTrackerInitialDelay = 3 * time.Minute
	DefaultTrackerPollInterval = 6 * time.Hour
	DefaultTrackerRefreshAge   = 24 * time.Hour
	MinTrackerListBytes        = 200 * 1024
	MaxTrackerListBytes        = 10 * 1024 * 1024
	MinTrackerHostCount        = 5000
	MaxTrackerHostCount        = 200000
	MaxTrackerHostDeltaRatio   = 0.20
	MaxSingleTrackerFrameBytes = 768 * 1024
	TrackerChunkB64Chars       = 450000

	trackerBlobNamespace = "system_tracker"
	trackerMetaSetting   = "tracker_list_meta"
)

var (
	reTrackerVersionVal = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

	neverBlockHostSuffixes = map[string]bool{
		"challenges.cloudflare.com": true, "datadome.co": true, "captcha-delivery.com": true,
		"perimeterx.net": true, "px-cdn.net": true, "px-cloud.net": true, "pxchk.net": true,
		"humansecurity.com": true, "hsprotect.net": true, "akamaihd.net": true, "akamaized.net": true,
		"akstat.io": true, "go-mpulse.net": true, "arkoselabs.com": true, "funcaptcha.com": true,
		"recaptcha.net": true, "google.com": true, "gstatic.com": true, "hcaptcha.com": true,
		"launchdarkly.com": true, "optimizely.com": true, "statsig.com": true, "statsigapi.net": true,
		"featureassets.org": true, "split.io": true, "growthbook.io": true,
	}
)

type persistedTrackerMeta struct {
	Version            string `json:"version"`
	LastModified       string `json:"lastModified,omitempty"`
	ETag               string `json:"etag,omitempty"`
	FetchedAt          int64  `json:"fetchedAt"`
	HostCount          int    `json:"hostCount"`
	RawParsedHostCount int    `json:"rawParsedHostCount"`
	SHA256             string `json:"sha256"`
	BlobSHA            string `json:"blobSha"`
	SourceURL          string `json:"sourceUrl"`
	LicenseURL         string `json:"licenseUrl"`
}

// TrackerConfig configures TrackerManager lifecycle, storage, HTTP transport, and update notifications.
type TrackerConfig struct {
	Store         *Store
	SourceURL     string
	Client        *http.Client
	InitialDelay  time.Duration
	PollInterval  time.Duration
	RefreshMaxAge time.Duration
	SelfHost      string
	PublicOrigin  string
	Getenv        func(string) string
	OnUpdate      func(version string, hosts []string)
}

// TrackerManager manages runtime EasyPrivacy validation, persistence, and delayed background refreshes.
type TrackerManager struct {
	mu            sync.RWMutex
	store         *Store
	sourceURL     string
	client        *http.Client
	initialDelay  time.Duration
	pollInterval  time.Duration
	refreshMaxAge time.Duration
	extraAllow    map[string]bool
	getenv        func(string) string
	onUpdate      func(version string, hosts []string)

	meta  persistedTrackerMeta
	hosts []string

	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}
}

func isTrackerDisabledFlag(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "off", "false", "0", "disabled", "no":
		return true
	}
	return false
}

func normalizeTrackerDomainHost(raw string) (string, bool) {
	clean := strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), ".")
	if clean == "" || len(clean) > 253 || strings.HasPrefix(clean, ".") || !strings.Contains(clean, ".") {
		return "", false
	}
	labels := strings.Split(clean, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", false
			}
		}
	}
	tld := labels[len(labels)-1]
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			return clean, true
		}
	}
	return "", false
}

func hostMatchesSuffixMap(host string, set map[string]bool) bool {
	for cur := host; len(set) > 0 && cur != ""; {
		if set[cur] {
			return true
		}
		dot := strings.IndexByte(cur, '.')
		if dot < 0 {
			return false
		}
		cur = cur[dot+1:]
	}
	return false
}

func buildExtraNeverBlockSet(selfHost, publicOrigin string) map[string]bool {
	out := make(map[string]bool)
	addCandidate := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		if u, err := url.Parse(trimmed); err == nil && u.Hostname() != "" {
			trimmed = u.Hostname()
		} else if h, _, hasPort := strings.Cut(trimmed, ":"); hasPort {
			trimmed = h
		}
		if clean, ok := normalizeTrackerDomainHost(trimmed); ok {
			out[clean] = true
		}
	}
	addCandidate(selfHost)
	for _, part := range strings.Split(publicOrigin, ",") {
		addCandidate(part)
	}
	return out
}

// ValidateEasyPrivacyList parses and validates raw EasyPrivacy text enforcing size, header, PSL, allowlist, count, and <=20% drop/delta invariants.
func ValidateEasyPrivacyList(rawBytes []byte, previousHostCount int, extraNeverBlock map[string]bool) (version, headerLastMod string, hosts []string, rawParsedCount int, err error) {
	if len(rawBytes) < MinTrackerListBytes {
		return "", "", nil, 0, fmt.Errorf("tracker list too small (%d < %d bytes)", len(rawBytes), MinTrackerListBytes)
	}
	if len(rawBytes) > MaxTrackerListBytes {
		return "", "", nil, 0, fmt.Errorf("tracker list exceeds maximum size (%d > %d bytes)", len(rawBytes), MaxTrackerListBytes)
	}
	rawText := string(rawBytes)
	headSample := strings.ToLower(strings.TrimLeft(rawText[:min(512, len(rawText))], " \t\r\n"))
	if strings.HasPrefix(headSample, "<!doctype") || strings.HasPrefix(headSample, "<html") || strings.HasPrefix(headSample, "<head") {
		return "", "", nil, 0, errors.New("HTML document received instead of EasyPrivacy text list")
	}

	sawTitle := false
	headerLinesSeen := 0
	skippedAllow := make(map[string]bool)
	surviving := make(map[string]bool)

	for pos, n := 0, len(rawText); pos <= n; {
		nlRel := strings.IndexByte(rawText[pos:], '\n')
		lineEnd := n
		if nlRel >= 0 {
			lineEnd = pos + nlRel
		}
		line := strings.TrimSpace(strings.TrimSuffix(rawText[pos:lineEnd], "\r"))
		pos = lineEnd + 1

		if line != "" {
			if headerLinesSeen < 30 && (line[0] == '!' || line[0] == '[') {
				headerLinesSeen++
				if colon := strings.IndexByte(line, ':'); colon > 0 && line[0] == '!' {
					key := strings.ToLower(strings.TrimSpace(line[1:colon]))
					val := strings.TrimSpace(line[colon+1:])
					switch key {
					case "title":
						if val == "EasyPrivacy" || strings.HasPrefix(val, "EasyPrivacy ") {
							sawTitle = true
						}
					case "version":
						if version == "" && reTrackerVersionVal.MatchString(val) {
							version = val
						}
					case "last modified":
						if headerLastMod == "" && len(val) <= 128 {
							headerLastMod = val
						}
					}
				}
			} else if len(line) >= 6 && line[0] == '|' && line[1] == '|' && line[len(line)-1] == '^' {
				body := strings.ToLower(line[2 : len(line)-1])
				pureDomain := true
				for i := 0; i < len(body); i++ {
					if c := body[i]; !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
						pureDomain = false
						break
					}
				}
				if pureDomain {
					if host, ok := normalizeTrackerDomainHost(body); ok && extract.GetRegistrableDomain(host) != "" {
						if hostMatchesSuffixMap(host, neverBlockHostSuffixes) || hostMatchesSuffixMap(host, extraNeverBlock) {
							skippedAllow[host] = true
						} else {
							surviving[host] = true
						}
					}
				}
			}
		}
		if nlRel < 0 {
			break
		}
	}

	if !sawTitle {
		return "", "", nil, 0, errors.New(`missing required "! Title: EasyPrivacy" header`)
	}
	if version == "" {
		return "", "", nil, 0, errors.New(`missing required "! Version:" header`)
	}

	survivingCount := len(surviving)
	rawParsedCount = survivingCount + len(skippedAllow)
	if rawParsedCount < MinTrackerHostCount || survivingCount < MinTrackerHostCount {
		return "", "", nil, 0, fmt.Errorf("parsed host count (%d) below minimum (%d)", survivingCount, MinTrackerHostCount)
	}
	if rawParsedCount > MaxTrackerHostCount || survivingCount > MaxTrackerHostCount {
		return "", "", nil, 0, fmt.Errorf("parsed host count (%d) exceeds maximum (%d)", survivingCount, MaxTrackerHostCount)
	}
	if previousHostCount > 0 {
		if delta := math.Abs(float64(survivingCount-previousHostCount)) / float64(previousHostCount); delta > MaxTrackerHostDeltaRatio {
			return "", "", nil, 0, fmt.Errorf("parsed host count (%d) differs from previous (%d) by %.1f%% (> 20%%)", survivingCount, previousHostCount, delta*100)
		}
	}

	hosts = make([]string, 0, survivingCount)
	for h := range surviving {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	return version, headerLastMod, hosts, rawParsedCount, nil
}

// BuildTrackerListFrames builds WebSocket JSON frames (`tracker_list` when <= 768 KiB, else `tracker_list_chunk` frames).
func BuildTrackerListFrames(version string, hosts []string) [][]byte {
	if strings.TrimSpace(version) == "" || len(hosts) == 0 {
		return nil
	}
	fetchedAtMs := time.Now().UnixMilli()
	rawBytes := []byte(strings.Join(hosts, "\n"))
	sha := sha256Hex(rawBytes)
	gzBytes, err := gzipCompressBytes(rawBytes)
	if err != nil {
		return nil
	}
	b64 := base64.StdEncoding.EncodeToString(gzBytes)

	singleFrame, err := json.Marshal(map[string]any{
		"type": "tracker_list", "version": version, "sha256": sha,
		"hostCount": len(hosts), "fetchedAt": fetchedAtMs, "hostsGzipB64": b64,
	})
	if err == nil && len(singleFrame) <= MaxSingleTrackerFrameBytes {
		return [][]byte{singleFrame}
	}

	totalChunks := (len(b64) + TrackerChunkB64Chars - 1) / TrackerChunkB64Chars
	frames := make([][]byte, 0, totalChunks)
	for idx := 0; idx < totalChunks; idx++ {
		start, end := idx*TrackerChunkB64Chars, min(len(b64), (idx+1)*TrackerChunkB64Chars)
		frameBytes, err := json.Marshal(map[string]any{
			"type": "tracker_list_chunk", "version": version, "sha256": sha,
			"hostCount": len(hosts), "fetchedAt": fetchedAtMs,
			"chunkIndex": idx, "totalChunks": totalChunks, "data": b64[start:end],
		})
		if err != nil {
			return nil
		}
		frames = append(frames, frameBytes)
	}
	return frames
}

// NewTrackerManager creates a TrackerManager, loading any persisted list from Store with ZERO network I/O.
func NewTrackerManager(cfg TrackerConfig) (*TrackerManager, error) {
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	srcURL := strings.TrimSpace(cfg.SourceURL)
	if srcURL == "" {
		srcURL = EasyPrivacySourceURL
	}
	initDelay := cfg.InitialDelay
	if initDelay <= 0 {
		initDelay = DefaultTrackerInitialDelay
	}
	if envMs := strings.TrimSpace(getenv("EDGEFETCH_TRACKER_INITIAL_DELAY_MS")); envMs != "" && (cfg.InitialDelay <= 0 || cfg.InitialDelay == DefaultTrackerInitialDelay) {
		if ms, err := strconv.ParseInt(envMs, 10, 64); err == nil && ms >= 0 {
			initDelay = max(time.Millisecond, time.Duration(ms)*time.Millisecond)
		}
	}
	pollInt := cfg.PollInterval
	if pollInt <= 0 {
		pollInt = DefaultTrackerPollInterval
	}
	maxAge := cfg.RefreshMaxAge
	if maxAge <= 0 {
		maxAge = DefaultTrackerRefreshAge
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	tm := &TrackerManager{
		store: cfg.Store, sourceURL: srcURL, client: client,
		initialDelay: initDelay, pollInterval: pollInt, refreshMaxAge: maxAge,
		extraAllow: buildExtraNeverBlockSet(cfg.SelfHost, cfg.PublicOrigin),
		getenv:     getenv, onUpdate: cfg.OnUpdate, stopCh: make(chan struct{}),
	}
	if tm.IsEnabled() && tm.store != nil {
		tm.loadPersistedFromStore()
	}
	return tm, nil
}

// IsEnabled reports whether runtime EasyPrivacy tracker blocking is enabled via env and Hub settings.
func (tm *TrackerManager) IsEnabled() bool {
	if isTrackerDisabledFlag(tm.getenv("EDGEFETCH_TRACKER_LIST")) {
		return false
	}
	if tm.store != nil {
		if v, ok := tm.store.GetSetting("tracker_list"); ok && isTrackerDisabledFlag(v) {
			return false
		}
	}
	return true
}

func (tm *TrackerManager) loadPersistedFromStore() {
	rawMeta, ok := tm.store.GetSetting(trackerMetaSetting)
	if !ok || strings.TrimSpace(rawMeta) == "" {
		return
	}
	var meta persistedTrackerMeta
	if json.Unmarshal([]byte(rawMeta), &meta) != nil || meta.Version == "" || !isValidSHA256Hex(meta.BlobSHA) || !isValidSHA256Hex(meta.SHA256) {
		return
	}
	decoded, found, err := tm.store.GetDecodedBlob(trackerBlobNamespace, meta.BlobSHA, MaxArtifactContentBytes)
	if !found || err != nil || sha256Hex(decoded) != meta.SHA256 {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	hosts := make([]string, 0, len(lines))
	for _, l := range lines {
		if h := strings.TrimSpace(l); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) < MinTrackerHostCount || len(hosts) > MaxTrackerHostCount {
		return
	}
	meta.HostCount = len(hosts)
	tm.mu.Lock()
	tm.meta, tm.hosts = meta, hosts
	tm.mu.Unlock()
}

// Status returns the current tracker list readiness and metadata snapshot.
func (tm *TrackerManager) Status() map[string]any {
	enabled := tm.IsEnabled()
	tm.mu.RLock()
	meta, hostCount := tm.meta, len(tm.hosts)
	tm.mu.RUnlock()
	if !enabled {
		return map[string]any{
			"available": false, "enabled": false, "version": "", "hostCount": 0,
			"fetchedAt": int64(0), "sourceUrl": tm.sourceURL, "licenseUrl": EasyPrivacyLicenseURL,
		}
	}
	return map[string]any{
		"available": meta.Version != "" && hostCount > 0, "enabled": true, "version": meta.Version,
		"hostCount": hostCount, "fetchedAt": meta.FetchedAt, "sourceUrl": tm.sourceURL,
		"licenseUrl": EasyPrivacyLicenseURL, "sha256": meta.SHA256, "lastModified": meta.LastModified,
	}
}

// CurrentList returns the active tracker list version and a copy of the host slice.
func (tm *TrackerManager) CurrentList() (version string, hosts []string) {
	if !tm.IsEnabled() {
		return "", nil
	}
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if tm.meta.Version == "" || len(tm.hosts) == 0 {
		return "", nil
	}
	return tm.meta.Version, slices.Clone(tm.hosts)
}

func (tm *TrackerManager) needsScheduledRefresh() bool {
	if !tm.IsEnabled() {
		return false
	}
	tm.mu.RLock()
	fetchedAt, hasHosts := tm.meta.FetchedAt, len(tm.hosts) > 0
	tm.mu.RUnlock()
	return !hasHosts || fetchedAt <= 0 || time.Since(time.UnixMilli(fetchedAt)) >= tm.refreshMaxAge
}

// RefreshNow downloads, validates, persists, and activates the EasyPrivacy list immediately.
func (tm *TrackerManager) RefreshNow(ctx context.Context) (updated bool, err error) {
	if !tm.IsEnabled() {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tm.mu.RLock()
	prevMeta, prevCount := tm.meta, len(tm.hosts)
	tm.mu.RUnlock()

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, tm.sourceURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", TrackerListUserAgent)
	req.Header.Set("Accept", "text/plain")
	if prevMeta.ETag != "" {
		req.Header.Set("If-None-Match", prevMeta.ETag)
	}
	if prevMeta.LastModified != "" {
		req.Header.Set("If-Modified-Since", prevMeta.LastModified)
	}

	resp, err := tm.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		if prevCount == 0 {
			return false, errors.New("unexpected 304 Not Modified without cached list")
		}
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))); ct != "" && !strings.HasPrefix(ct, "text/plain") {
		return false, fmt.Errorf("invalid content-type %q (expected text/plain)", ct)
	}

	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxTrackerListBytes+1))
	if err != nil {
		return false, err
	}
	version, hdrLastMod, hosts, rawParsedCount, err := ValidateEasyPrivacyList(rawBytes, prevCount, tm.extraAllow)
	if err != nil {
		return false, err
	}

	joined := []byte(strings.Join(hosts, "\n"))
	contentSHA := sha256Hex(joined)
	var blobSHA string
	if tm.store != nil {
		if blobSHA, _, _, _, err = tm.store.PutRawBlob(trackerBlobNamespace, joined); err != nil {
			return false, err
		}
	}

	lastMod := strings.TrimSpace(resp.Header.Get("Last-Modified"))
	if lastMod == "" {
		lastMod = hdrLastMod
	}
	nextMeta := persistedTrackerMeta{
		Version: version, LastModified: lastMod, ETag: strings.TrimSpace(resp.Header.Get("ETag")),
		FetchedAt: time.Now().UnixMilli(), HostCount: len(hosts), RawParsedHostCount: rawParsedCount,
		SHA256: contentSHA, BlobSHA: blobSHA, SourceURL: tm.sourceURL, LicenseURL: EasyPrivacyLicenseURL,
	}
	if tm.store != nil {
		if metaJSON, err := json.Marshal(nextMeta); err == nil {
			tm.store.SetSetting(trackerMetaSetting, string(metaJSON))
		}
	}

	changed := prevMeta.Version != nextMeta.Version || prevMeta.SHA256 != nextMeta.SHA256
	tm.mu.Lock()
	tm.meta, tm.hosts = nextMeta, hosts
	cb := tm.onUpdate
	tm.mu.Unlock()
	if changed && cb != nil {
		cb(version, slices.Clone(hosts))
	}
	return changed, nil
}

// StartBackground schedules the initial delayed refresh (`InitialDelay`) followed by `PollInterval` checks.
func (tm *TrackerManager) StartBackground(ctx context.Context) {
	if !tm.IsEnabled() {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tm.startOnce.Do(func() {
		go func() {
			timer := time.NewTimer(tm.initialDelay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-tm.stopCh:
				return
			case <-timer.C:
				if tm.needsScheduledRefresh() {
					_, _ = tm.RefreshNow(ctx)
				}
			}
			ticker := time.NewTicker(tm.pollInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tm.stopCh:
					return
				case <-ticker.C:
					if tm.needsScheduledRefresh() {
						_, _ = tm.RefreshNow(ctx)
					}
				}
			}
		}()
	})
}

// Stop halts background refresh timers.
func (tm *TrackerManager) Stop() {
	tm.stopOnce.Do(func() { close(tm.stopCh) })
}
