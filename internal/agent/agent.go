package agent

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/classify"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
	"github.com/bartrumb/edgefetch/v2/internal/ws"
)

// Version is the EdgeFetch binary/add-on release version reported in X-Agent-Version and agent_hello.
// Overridable at build time via -ldflags="-X github.com/bartrumb/edgefetch/v2/internal/agent.Version=...".
var Version = "2.8.18"

const (
	DefaultPingInterval          = 30 * time.Second
	DefaultReadWatchdog          = 50 * time.Second
	DefaultHealthyResetDur       = 30 * time.Second
	DefaultShutdownDrain         = 25 * time.Second
	DefaultUploadTimeout         = 45 * time.Second
	DefaultShutdownUploadTimeout = 10 * time.Second
	maxReconnectBackoff          = 30 * time.Second
)

// RuntimeOpts allows integration tests to shorten keepalive/drain timers without altering production defaults.
type RuntimeOpts struct {
	PingInterval          time.Duration
	ReadWatchdog          time.Duration
	HealthyResetDur       time.Duration
	ShutdownDrain         time.Duration
	UploadTimeout         time.Duration
	ShutdownUploadTimeout time.Duration
	WarmUpOnStart         bool
	OnConnected           func()
}

func (o RuntimeOpts) withDefaults() RuntimeOpts {
	if o.PingInterval <= 0 {
		o.PingInterval = DefaultPingInterval
	}
	if o.ReadWatchdog <= 0 {
		o.ReadWatchdog = DefaultReadWatchdog
	}
	if o.HealthyResetDur <= 0 {
		o.HealthyResetDur = DefaultHealthyResetDur
	}
	if o.ShutdownDrain <= 0 {
		o.ShutdownDrain = DefaultShutdownDrain
	}
	if o.UploadTimeout <= 0 {
		o.UploadTimeout = DefaultUploadTimeout
	}
	if o.ShutdownUploadTimeout <= 0 {
		o.ShutdownUploadTimeout = DefaultShutdownUploadTimeout
	}
	return o
}

type artifactDispatchPolicy struct {
	Mode            string `json:"mode"`
	Retention       string `json:"retention"`
	MaxContentBytes int    `json:"maxContentBytes"`
}

type controlMessage struct {
	Type            string                  `json:"type"`
	JobID           string                  `json:"jobId"`
	JobNonce        string                  `json:"jobNonce"`
	Trace           map[string]string       `json:"trace,omitempty"`
	Artifacts       *artifactDispatchPolicy `json:"artifacts,omitempty"`
	Call            crawl.FetchCall         `json:"call"`
	Version         string                  `json:"version,omitempty"`
	SHA256          string                  `json:"sha256,omitempty"`
	HostCount       int                     `json:"hostCount,omitempty"`
	HostsGzipB64    string                  `json:"hostsGzipB64,omitempty"`
	ChunkIndex      int                     `json:"chunkIndex,omitempty"`
	TotalChunks     int                     `json:"totalChunks,omitempty"`
	ChunkData       string                  `json:"data,omitempty"`
	NeverBlockHosts []string                `json:"neverBlockHosts,omitempty"`
}

const (
	maxTrackerListGunzipBytes  = 16 << 20
	maxTrackerListChunks       = 16
	maxTrackerChunkB64Bytes    = 600_000
	maxTrackerJoinedB64Bytes   = 4 << 20
	maxTrackerHostCount        = 200_000
	trackerChunkReassemblyWait = 30 * time.Second
)

func isValidHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func applyGzippedTrackerList(crawler *crawl.Crawler, version, expectedSHA256, b64Payload string, neverBlockHosts []string) error {
	ver := strings.TrimSpace(version)
	wantSHA := strings.ToLower(strings.TrimSpace(expectedSHA256))
	trimmedB64 := strings.TrimSpace(b64Payload)
	if ver == "" || trimmedB64 == "" {
		return errors.New("empty tracker_list version or payload")
	}
	if !isValidHexSHA256(wantSHA) {
		return errors.New("missing or malformed tracker_list sha256")
	}
	if len(trimmedB64) > maxTrackerJoinedB64Bytes {
		return errors.New("encoded tracker_list exceeds 4 MiB cap")
	}
	gzBytes, err := base64.StdEncoding.DecodeString(trimmedB64)
	if err != nil {
		return fmt.Errorf("base64 decode tracker_list: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		return fmt.Errorf("gzip open tracker_list: %w", err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(zr, maxTrackerListGunzipBytes+1))
	_ = zr.Close()
	if readErr != nil {
		return fmt.Errorf("gzip read tracker_list: %w", readErr)
	}
	if len(raw) > maxTrackerListGunzipBytes {
		return errors.New("decompressed tracker_list exceeds 16 MiB cap")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != wantSHA {
		return errors.New("tracker_list sha256 mismatch")
	}
	hosts := make([]string, 0, 1024)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 1024), 4096)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(hosts) >= maxTrackerHostCount {
			return errors.New("tracker_list host count exceeds 200000 cap")
		}
		hosts = append(hosts, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan tracker_list: %w", err)
	}
	crawler.SetTrackerList(ver, hosts, neverBlockHosts...)
	return nil
}

func warmUpCrawlerBounded(ctx context.Context, crawler *crawl.Crawler) {
	if crawler == nil || ctx.Err() != nil {
		return
	}
	warmCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	_ = crawler.WarmUp(warmCtx)
	cancel()
}

var runHubFn = Run

// RunAll maintains persistent outbound WebSocket sessions to every controller in `cfg.HubURLs` (falling back to
// `cfg.HubURL`), sharing one `*crawl.Crawler` and `*politeness.Registry` across active-active controllers with zero
// coordination overhead.
func RunAll(
	ctx context.Context,
	cfg Config,
	crawler *crawl.Crawler,
	allow func(*url.URL) error,
	hubTransport http.RoundTripper,
	log *slog.Logger,
	rtOpts RuntimeOpts,
) error {
	if rtOpts.WarmUpOnStart {
		warmUpCrawlerBounded(ctx, crawler)
		rtOpts.WarmUpOnStart = false
	}
	hubs := cfg.HubURLs
	if len(hubs) == 0 && strings.TrimSpace(cfg.HubURL) != "" {
		hubs = []string{cfg.HubURL}
	}
	if len(hubs) <= 1 {
		if len(hubs) == 1 {
			cfg.HubURL = hubs[0]
		}
		return runHubFn(ctx, cfg, crawler, allow, hubTransport, log, rtOpts)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(hubs))
	for _, hURL := range hubs {
		subCfg := cfg
		subCfg.HubURL = hURL
		subCfg.HubURLs = []string{hURL}
		subLog := log.With(slog.String("controller", hURL))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runHubFn(ctx, subCfg, crawler, allow, hubTransport, subLog, rtOpts); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

const maxQueuedDispatches = 8

type dispatchQueue struct {
	mu             sync.Mutex
	items          []controlMessage
	wake           chan struct{}
	closed         bool
	latestNonce    map[string]string
	inflightCancel map[string]context.CancelFunc
}

func newDispatchQueue() *dispatchQueue {
	return &dispatchQueue{
		items:          make([]controlMessage, 0, maxQueuedDispatches),
		wake:           make(chan struct{}, 1),
		latestNonce:    make(map[string]string),
		inflightCancel: make(map[string]context.CancelFunc),
	}
}

func (q *dispatchQueue) enqueue(msg controlMessage) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	for i := range q.items {
		if q.items[i].JobID == msg.JobID {
			prev := q.latestNonce[msg.JobID]
			q.items[i] = msg
			q.latestNonce[msg.JobID] = msg.JobNonce
			if prev != "" && prev != msg.JobNonce {
				if cancelFn := q.inflightCancel[msg.JobID]; cancelFn != nil {
					cancelFn()
				}
			}
			return true
		}
	}
	if len(q.items) >= maxQueuedDispatches {
		return false
	}
	prev := q.latestNonce[msg.JobID]
	q.latestNonce[msg.JobID] = msg.JobNonce
	if prev != "" && prev != msg.JobNonce {
		if cancelFn := q.inflightCancel[msg.JobID]; cancelFn != nil {
			cancelFn()
		}
	}
	q.items = append(q.items, msg)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

func (q *dispatchQueue) pop() (controlMessage, bool) {
	for {
		q.mu.Lock()
		for len(q.items) > 0 {
			msg := q.items[0]
			q.items[0] = controlMessage{}
			q.items = q.items[1:]
			superseded := q.latestNonce[msg.JobID] != msg.JobNonce
			q.mu.Unlock()
			if superseded {
				continue
			}
			return msg, true
		}
		if q.closed {
			q.mu.Unlock()
			return controlMessage{}, false
		}
		q.mu.Unlock()
		<-q.wake
	}
}

func (q *dispatchQueue) registerInflight(jobID, jobNonce string, cancelFn context.CancelFunc) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.latestNonce[jobID] != jobNonce {
		return false
	}
	q.inflightCancel[jobID] = cancelFn
	return true
}

func (q *dispatchQueue) finishInflight(jobID, jobNonce string) (superseded bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflightCancel, jobID)
	cur, exists := q.latestNonce[jobID]
	if exists && cur != jobNonce {
		return true
	}
	if cur == jobNonce {
		delete(q.latestNonce, jobID)
	}
	return false
}

func (q *dispatchQueue) close() {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.wake)
	}
	q.mu.Unlock()
}

// Run maintains a persistent outbound WebSocket session to `cfg.HubURL/agent/ws`, automatically reconnecting with
// full-jitter exponential backoff on network drops and draining in-flight work cleanly on `SIGTERM`.
func Run(
	ctx context.Context,
	cfg Config,
	crawler *crawl.Crawler,
	allow func(*url.URL) error,
	hubTransport http.RoundTripper,
	log *slog.Logger,
	rtOpts RuntimeOpts,
) error {
	rtOpts = rtOpts.withDefaults()
	if rtOpts.WarmUpOnStart {
		warmUpCrawlerBounded(ctx, crawler)
	}
	replyClient := &http.Client{
		Transport: hubTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	queue := newDispatchQueue()
	busySem := make(chan struct{}, maxQueuedDispatches)
	var dispatchWG sync.WaitGroup
	dispatchWG.Add(1)
	go func() {
		defer dispatchWG.Done()
		for {
			msg, ok := queue.pop()
			if !ok {
				return
			}
			handleQueuedDispatch(ctx, cfg, crawler, allow, replyClient, log, rtOpts, msg, queue)
		}
	}()
	defer func() {
		queue.close()
		dispatchWG.Wait()
	}()

	attempt := 0
	lastErr := ""
	for {
		if ctx.Err() != nil {
			return nil
		}

		connectedAt := time.Now()
		err := runSession(ctx, cfg, crawler, allow, replyClient, log, rtOpts, attempt, lastErr, queue, busySem, &dispatchWG)
		if ctx.Err() != nil {
			log.Info("agent_exit", slog.String("reason", "context_cancelled"))
			return nil
		}

		if time.Since(connectedAt) >= rtOpts.HealthyResetDur {
			attempt = 0
		}
		attempt++
		lastErr = errString(err)
		ceil := time.Second << minInt(attempt-1, 5)
		if ceil > maxReconnectBackoff {
			ceil = maxReconnectBackoff
		}
		wait := crawler.Jitter(ceil)
		if wait < 250*time.Millisecond {
			wait = 250 * time.Millisecond
		}
		log.Warn("agent_disconnected",
			slog.String("error", lastErr),
			slog.Int("attempt", attempt),
			slog.Int64("reconnect_ms", wait.Milliseconds()))

		if sleepErr := crawl.SleepCtx(ctx, wait); sleepErr != nil {
			return nil
		}
	}
}

func runSession(
	ctx context.Context,
	cfg Config,
	crawler *crawl.Crawler,
	allow func(*url.URL) error,
	replyClient *http.Client,
	log *slog.Logger,
	rtOpts RuntimeOpts,
	reconnectAttempt int,
	lastError string,
	queue *dispatchQueue,
	busySem chan struct{},
	dispatchWG *sync.WaitGroup,
) error {
	caps := crawler.Capabilities()
	bVer, bSandbox := crawler.BrowserInfo()
	wsHeaders := map[string]string{
		"Authorization":        "Bearer " + cfg.AgentToken,
		"X-Agent-Site":         cfg.SiteID,
		"X-Agent-Arch":         runtime.GOARCH,
		"X-Agent-Version":      Version,
		"X-Agent-Capabilities": strings.Join(caps, ","),
	}
	if bSandbox != "" {
		wsHeaders["X-Agent-Browser-Sandbox"] = bSandbox
	}
	conn, err := ws.Dial(ctx, cfg.HubURL+"/agent/ws", cfg.UserAgent, wsHeaders)
	if err != nil {
		return err
	}
	defer func() { _ = conn.CloseNow() }()
	log.Info("agent_connected",
		slog.String("hub", cfg.HubURL),
		slog.String("arch", runtime.GOARCH),
		slog.String("version", Version),
		slog.String("capabilities", strings.Join(caps, ",")))

	helloMap := map[string]any{
		"type":             "agent_hello",
		"version":          Version,
		"arch":             runtime.GOARCH,
		"goVersion":        runtime.Version(),
		"capabilities":     caps,
		"reconnectAttempt": reconnectAttempt,
		"lastError":        lastError,
	}
	if bVer != "" {
		helloMap["browserVersion"] = bVer
	}
	if bSandbox != "" {
		helloMap["browserSandbox"] = bSandbox
	}
	if curTrkVer := crawler.TrackerListVersion(); curTrkVer != "" {
		helloMap["trackerListVersion"] = curTrkVer
	}
	helloPayload, _ := json.Marshal(helloMap)
	_ = conn.WriteText(string(helloPayload))
	if rtOpts.OnConnected != nil {
		rtOpts.OnConnected()
	}

	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	stopClose := context.AfterFunc(sessionCtx, func() { _ = conn.CloseCleanly() })
	defer stopClose()

	go runPingLoop(sessionCtx, rtOpts.PingInterval, conn.WriteText, conn.CloseNow)

	defer func() {
		cancelSession()
		_ = conn.CloseNow()
	}()

	var (
		chunkVer       string
		chunkSHA       string
		chunkTotal     int
		chunkAllow     []string
		chunkParts     []string
		chunkStartedAt time.Time
	)
	resetChunks := func() {
		chunkVer = ""
		chunkSHA = ""
		chunkTotal = 0
		chunkAllow = nil
		chunkParts = nil
		chunkStartedAt = time.Time{}
	}

	for {
		raw, err := conn.ReadText(rtOpts.ReadWatchdog)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if chunkVer != "" && !chunkStartedAt.IsZero() && time.Since(chunkStartedAt) > trackerChunkReassemblyWait {
			resetChunks()
		}
		if raw == "pong" || raw == "" {
			continue
		}

		var msg controlMessage
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			log.Warn("agent_bad_message", slog.String("error", err.Error()))
			continue
		}

		switch msg.Type {
		case "hello", "pong":
			continue
		case "tracker_list":
			resetChunks()
			if err := applyGzippedTrackerList(crawler, msg.Version, msg.SHA256, msg.HostsGzipB64, msg.NeverBlockHosts); err != nil {
				log.Warn("agent_tracker_list_invalid", slog.String("error", err.Error()))
				continue
			}
			ackBytes, _ := json.Marshal(map[string]string{
				"type":    "tracker_list_ack",
				"version": strings.TrimSpace(msg.Version),
			})
			_ = conn.WriteText(string(ackBytes))
		case "tracker_list_chunk":
			cleanMsgVer := strings.TrimSpace(msg.Version)
			cleanMsgSHA := strings.ToLower(strings.TrimSpace(msg.SHA256))
			if msg.TotalChunks <= 0 ||
				msg.TotalChunks > maxTrackerListChunks ||
				msg.ChunkIndex < 0 ||
				msg.ChunkIndex >= msg.TotalChunks ||
				cleanMsgVer == "" ||
				!isValidHexSHA256(cleanMsgSHA) ||
				msg.ChunkData == "" ||
				len(msg.ChunkData) > maxTrackerChunkB64Bytes {
				log.Warn("agent_tracker_list_chunk_bounds")
				resetChunks()
				continue
			}
			if chunkVer != cleanMsgVer || chunkSHA != cleanMsgSHA || len(chunkParts) != msg.TotalChunks {
				chunkVer = cleanMsgVer
				chunkSHA = cleanMsgSHA
				chunkTotal = msg.TotalChunks
				chunkAllow = nil
				chunkParts = make([]string, msg.TotalChunks)
				chunkStartedAt = time.Now()
			}
			if len(msg.NeverBlockHosts) > 0 {
				chunkAllow = append([]string(nil), msg.NeverBlockHosts...)
			}
			chunkParts[msg.ChunkIndex] = msg.ChunkData
			complete := true
			totalB64Len := 0
			for i := 0; i < chunkTotal; i++ {
				if chunkParts[i] == "" {
					complete = false
					break
				}
				totalB64Len += len(chunkParts[i])
			}
			if totalB64Len > maxTrackerJoinedB64Bytes {
				log.Warn("agent_tracker_list_chunk_oversize")
				resetChunks()
				continue
			}
			if complete {
				joinedB64 := strings.Join(chunkParts, "")
				verDone := chunkVer
				shaDone := chunkSHA
				allowDone := chunkAllow
				resetChunks()
				if err := applyGzippedTrackerList(crawler, verDone, shaDone, joinedB64, allowDone); err != nil {
					log.Warn("agent_tracker_list_invalid", slog.String("error", err.Error()))
					continue
				}
				ackBytes, _ := json.Marshal(map[string]string{
					"type":    "tracker_list_ack",
					"version": verDone,
				})
				_ = conn.WriteText(string(ackBytes))
			}
		case "dispatch":
			if msg.JobID == "" || msg.JobNonce == "" {
				log.Warn("agent_missing_job_id")
				continue
			}
			if !queue.enqueue(msg) {
				// Queue full: refuse immediately instead of blocking the WebSocket read loop so dead sockets are detected promptly.
				log.Warn("agent_dispatch_queue_full", slog.String("job_id", msg.JobID))
				select {
				case busySem <- struct{}{}:
					dispatchWG.Add(1)
					go func(m controlMessage) {
						defer dispatchWG.Done()
						defer func() { <-busySem }()
						bctx, bcancel := context.WithTimeout(context.Background(), rtOpts.ShutdownUploadTimeout)
						stopOnShutdown := context.AfterFunc(ctx, func() {
							time.AfterFunc(rtOpts.ShutdownDrain, bcancel)
						})
						defer func() {
							stopOnShutdown()
							bcancel()
						}()
						results := make([]crawl.Result, len(m.Call.Requests))
						for i, r := range m.Call.Requests {
							results[i] = crawl.Result{
								ID:      r.ID,
								URL:     r.URL,
								Kind:    r.Kind,
								Outcome: classify.OutcomeError,
								Problem: "agent_busy: dispatch queue full",
							}
						}
						_ = uploadReply(bctx, replyClient, cfg, m.JobID, m.JobNonce, crawl.FetchReply{
							Results: results,
							Summary: crawl.Summarize(results),
						})
					}(msg)
				default:
				}
			}
		default:
			log.Warn("agent_unknown_type", slog.String("type", msg.Type))
		}
	}
}

func runPingLoop(ctx context.Context, interval time.Duration, writePing func(string) error, closeNow func() error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if werr := writePing("ping"); werr != nil {
				_ = closeNow()
				return
			}
		}
	}
}

func newR2ArtifactSink(
	replyClient *http.Client,
	cfg Config,
	jobID, jobNonce string,
	retention string,
	maxContent int,
	uploadTimeout time.Duration,
	jobLog *slog.Logger,
) crawl.ResultSink {
	var uploadMu sync.Mutex
	return func(_ int, res crawl.Result) crawl.Result {
		if res.Body == "" {
			return res
		}
		rawBytes, decErr := res.DecodeBody()
		// Always clear inline Body immediately so bodies never pass through AgentHubDO or accumulate in RAM.
		res.Body = ""
		res.BodyEncoding = ""
		if decErr != nil {
			res.BodyOmitted = true
			res.ArtifactError = "decode body: " + decErr.Error()
			return res
		}
		if len(rawBytes) > maxContent {
			res.BodyOmitted = true
			res.Truncated = true
			res.ArtifactError = fmt.Sprintf("body (%d bytes) exceeds artifact maxContentBytes (%d)", len(rawBytes), maxContent)
			return res
		}
		uploadMu.Lock()
		upStart := time.Now()
		artCtx, cancelArt := context.WithTimeout(context.Background(), uploadTimeout)
		artRef, upErr := uploadArtifact(artCtx, replyClient, cfg, jobID, jobNonce, res.ID, retention, rawBytes)
		cancelArt()
		res.Timing.ArtifactUploadMs = time.Since(upStart).Milliseconds()
		uploadMu.Unlock()
		if upErr != nil {
			res.BodyOmitted = true
			res.ArtifactError = upErr.Error()
			jobLog.Warn("agent_artifact_upload_failed", slog.String("request_id", res.ID), slog.String("error", upErr.Error()))
			return res
		}
		res.Artifact = artRef
		return res
	}
}

func handleDispatch(
	parentCtx context.Context,
	cfg Config,
	crawler *crawl.Crawler,
	allow func(*url.URL) error,
	replyClient *http.Client,
	baseLog *slog.Logger,
	shutdownDrain time.Duration,
	msg controlMessage,
) {
	handleDispatchWithOpts(parentCtx, cfg, crawler, allow, replyClient, baseLog, RuntimeOpts{
		ShutdownDrain: shutdownDrain,
	}.withDefaults(), msg)
}

func handleDispatchWithOpts(
	parentCtx context.Context,
	cfg Config,
	crawler *crawl.Crawler,
	allow func(*url.URL) error,
	replyClient *http.Client,
	baseLog *slog.Logger,
	rtOpts RuntimeOpts,
	msg controlMessage,
) {
	handleQueuedDispatch(parentCtx, cfg, crawler, allow, replyClient, baseLog, rtOpts, msg, nil)
}

func handleQueuedDispatch(
	parentCtx context.Context,
	cfg Config,
	crawler *crawl.Crawler,
	allow func(*url.URL) error,
	replyClient *http.Client,
	baseLog *slog.Logger,
	rtOpts RuntimeOpts,
	msg controlMessage,
	queue *dispatchQueue,
) {
	rtOpts = rtOpts.withDefaults()
	jobBaseCtx, cancelDrain := context.WithCancel(context.Background())
	if queue != nil && !queue.registerInflight(msg.JobID, msg.JobNonce, cancelDrain) {
		cancelDrain()
		baseLog.Warn("agent_stale_job_dropped", slog.String("job_id", msg.JobID))
		return
	}
	stopForward := context.AfterFunc(parentCtx, func() {
		time.AfterFunc(rtOpts.ShutdownDrain, cancelDrain)
	})
	defer func() {
		stopForward()
		cancelDrain()
	}()

	hdr := http.Header{}
	for k, v := range msg.Trace {
		hdr.Set(k, v)
	}
	jobLog := crawl.CallLogger(baseLog, hdr).With(slog.String("job_id", msg.JobID))

	call := msg.Call
	if len(call.Requests) <= 1 {
		call.Options.Concurrency = 1
	} else if call.Options.Concurrency <= 0 || call.Options.Concurrency > crawl.MaxConcurrency {
		call.Options.Concurrency = crawl.MaxConcurrency
	}
	if call.Options.PauseMs < cfg.PauseMs {
		call.Options.PauseMs = cfg.PauseMs
	}
	if call.Options.PauseJitterMs < cfg.PauseJitterMs {
		call.Options.PauseJitterMs = cfg.PauseJitterMs
	}
	minGap := minInt(cfg.PauseMs, 250)
	if call.Options.GapMs < minGap {
		call.Options.GapMs = minGap
	}

	var reply crawl.FetchReply
	if code, problem, ok := crawl.ValidateCallWithCrawler(crawler, call, allow); !ok {
		results := make([]crawl.Result, len(call.Requests))
		for i, r := range call.Requests {
			results[i] = crawl.Result{
				ID:      r.ID,
				URL:     r.URL,
				Kind:    r.Kind,
				Outcome: classify.OutcomeError,
				Problem: fmt.Sprintf("%s: %s", code, problem),
			}
		}
		reply = crawl.FetchReply{Results: results, Summary: crawl.Summarize(results)}
	} else {
		var sink crawl.ResultSink
		if msg.Artifacts != nil && msg.Artifacts.Mode == "r2" && call.Options.IncludeBody {
			retention := msg.Artifacts.Retention
			if retention != "stored" {
				retention = "transient"
			}
			maxContent := msg.Artifacts.MaxContentBytes
			if maxContent <= 0 || maxContent > crawl.MaxMaxBytes {
				maxContent = crawl.MaxMaxBytes
			}
			sink = newR2ArtifactSink(replyClient, cfg, msg.JobID, msg.JobNonce, retention, maxContent, rtOpts.UploadTimeout, jobLog)
		}
		reply = crawl.ExecuteCallWithTrace(jobBaseCtx, crawler, call, hdr, jobLog, sink)
	}

	if queue != nil && queue.finishInflight(msg.JobID, msg.JobNonce) {
		jobLog.Warn("agent_stale_reply_suppressed", slog.String("job_id", msg.JobID))
		return
	}

	// Normal uploads get the full UploadTimeout (default 45s) across retries; only active SIGTERM shutdown drains
	// clamp the upload window to ShutdownUploadTimeout (default 10s) so container stop deadlines are respected.
	uploadLimit := rtOpts.UploadTimeout
	if parentCtx.Err() != nil {
		uploadLimit = rtOpts.ShutdownUploadTimeout
	}
	uploadCtx, cancelUpload := context.WithTimeout(context.Background(), uploadLimit)
	defer cancelUpload()
	if err := uploadReply(uploadCtx, replyClient, cfg, msg.JobID, msg.JobNonce, reply); err != nil {
		jobLog.Error("agent_reply_failed", slog.String("error", err.Error()))
	}
}

func uploadArtifact(
	ctx context.Context,
	client *http.Client,
	cfg Config,
	jobID, jobNonce, requestID, retention string,
	rawBytes []byte,
) (*crawl.ArtifactRef, error) {
	contentDigest := sha256.Sum256(rawBytes)
	contentSHA := hex.EncodeToString(contentDigest[:])

	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(rawBytes); err != nil {
		_ = gz.Close()
		return nil, fmt.Errorf("gzip artifact: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}
	gzBytes := gzBuf.Bytes()
	blobDigest := sha256.Sum256(gzBytes)
	blobSHA := hex.EncodeToString(blobDigest[:])

	endpoint := cfg.HubURL + "/agent/artifacts/" + blobSHA
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if err := crawl.SleepCtx(ctx, time.Duration(attempt)*400*time.Millisecond); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(gzBytes))
		if err != nil {
			return nil, err
		}
		req.ContentLength = int64(len(gzBytes))
		req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
		req.Header.Set("User-Agent", cfg.UserAgent)
		req.Header.Set("Content-Type", "application/gzip")
		req.Header.Set("X-Agent-Site", cfg.SiteID)
		req.Header.Set("X-Job-Id", jobID)
		req.Header.Set("X-Job-Nonce", jobNonce)
		req.Header.Set("X-Request-Id", requestID)
		req.Header.Set("X-Content-Sha256", contentSHA)
		req.Header.Set("X-Content-Bytes", strconv.Itoa(len(rawBytes)))
		req.Header.Set("X-Artifact-Retention", retention)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &crawl.ArtifactRef{
				BlobSHA256:    blobSHA,
				ContentSHA256: contentSHA,
				ContentBytes:  len(rawBytes),
				StoredBytes:   len(gzBytes),
				Encoding:      "gzip",
				Retention:     retention,
			}, nil
		}
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusGatewayTimeout && resp.StatusCode != http.StatusConflict {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

func uploadReply(
	ctx context.Context,
	client *http.Client,
	cfg Config,
	jobID, jobNonce string,
	reply crawl.FetchReply,
) error {
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if err := json.NewEncoder(gz).Encode(reply); err != nil {
		_ = gz.Close()
		return fmt.Errorf("encode reply: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	payload := gzBuf.Bytes()

	endpoint := cfg.HubURL + "/agent/reply"
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if err := crawl.SleepCtx(ctx, time.Duration(attempt)*500*time.Millisecond); err != nil {
				return err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
		req.Header.Set("User-Agent", cfg.UserAgent)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("X-Agent-Site", cfg.SiteID)
		req.Header.Set("X-Job-Id", jobID)
		req.Header.Set("X-Job-Nonce", jobNonce)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusGatewayTimeout {
			return lastErr
		}
	}
	return lastErr
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	return err.Error()
}
