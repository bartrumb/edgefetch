package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
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
	"time"

	"github.com/bartrumb/edgefetch/internal/classify"
	"github.com/bartrumb/edgefetch/internal/crawl"
	"github.com/bartrumb/edgefetch/internal/ws"
)

// Version is the EdgeFetch binary/add-on release version reported in X-Agent-Version and agent_hello.
// Overridable at build time via -ldflags="-X github.com/bartrumb/edgefetch/internal/agent.Version=...".
var Version = "2.0.3"

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
	Type      string                  `json:"type"`
	JobID     string                  `json:"jobId"`
	JobNonce  string                  `json:"jobNonce"`
	Trace     map[string]string       `json:"trace,omitempty"`
	Artifacts *artifactDispatchPolicy `json:"artifacts,omitempty"`
	Call      crawl.FetchCall         `json:"call"`
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
	replyClient := &http.Client{
		Transport: hubTransport,
	}

	attempt := 0
	lastErr := ""
	for {
		if ctx.Err() != nil {
			return nil
		}

		connectedAt := time.Now()
		err := runSession(ctx, cfg, crawler, allow, replyClient, log, rtOpts, attempt, lastErr)
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
) error {
	caps := crawler.Capabilities()
	conn, err := ws.Dial(ctx, cfg.HubURL+"/agent/ws", cfg.UserAgent, map[string]string{
		"Authorization":        "Bearer " + cfg.AgentToken,
		"X-Agent-Site":         cfg.SiteID,
		"X-Agent-Arch":         runtime.GOARCH,
		"X-Agent-Version":      Version,
		"X-Agent-Capabilities": strings.Join(caps, ","),
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.CloseNow() }()
	log.Info("agent_connected",
		slog.String("hub", cfg.HubURL),
		slog.String("arch", runtime.GOARCH),
		slog.String("version", Version),
		slog.String("capabilities", strings.Join(caps, ",")))

	helloPayload, _ := json.Marshal(map[string]any{
		"type":             "agent_hello",
		"version":          Version,
		"arch":             runtime.GOARCH,
		"goVersion":        runtime.Version(),
		"capabilities":     caps,
		"reconnectAttempt": reconnectAttempt,
		"lastError":        lastError,
	})
	_ = conn.WriteText(string(helloPayload))
	if rtOpts.OnConnected != nil {
		rtOpts.OnConnected()
	}

	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	stopClose := context.AfterFunc(sessionCtx, func() { _ = conn.CloseCleanly() })
	defer stopClose()

	go func() {
		ticker := time.NewTicker(rtOpts.PingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				if werr := conn.WriteText("ping"); werr != nil {
					_ = conn.CloseNow()
					return
				}
			}
		}
	}()

	for {
		raw, err := conn.ReadText(rtOpts.ReadWatchdog)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
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
		case "dispatch":
			if msg.JobID == "" || msg.JobNonce == "" {
				log.Warn("agent_missing_job_id")
				continue
			}
			handleDispatchWithOpts(ctx, cfg, crawler, allow, replyClient, log, rtOpts, msg)
		default:
			log.Warn("agent_unknown_type", slog.String("type", msg.Type))
		}
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
	rtOpts = rtOpts.withDefaults()
	jobBaseCtx, cancelDrain := context.WithCancel(context.Background())
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
	call.Options.Concurrency = 1
	if call.Options.PauseMs < cfg.PauseMs {
		call.Options.PauseMs = cfg.PauseMs
	}
	if call.Options.PauseJitterMs < cfg.PauseJitterMs {
		call.Options.PauseJitterMs = cfg.PauseJitterMs
	}
	if call.Options.GapMs < cfg.PauseMs {
		call.Options.GapMs = cfg.PauseMs
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
			sink = func(_ int, res crawl.Result) crawl.Result {
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
				artCtx, cancelArt := context.WithTimeout(context.Background(), rtOpts.UploadTimeout)
				artRef, upErr := uploadArtifact(artCtx, replyClient, cfg, msg.JobID, msg.JobNonce, res.ID, retention, rawBytes)
				cancelArt()
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
		reply = crawl.ExecuteCallWithSink(jobBaseCtx, crawler, call, jobLog, sink)
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
