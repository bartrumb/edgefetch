// Package ws wraps github.com/coder/websocket behind EdgeFetch's outbound control-plane contract:
// HTTP/1.1 ALPN upgrade, classic ECDHE TLS curves, zero ambient proxy inheritance, no redirect token leakage,
// disabled per-message compression, 1 MiB message ceiling, and io.EOF peer-close normalization.
package ws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	MaxMessageBytes = 1 << 20 // 1 MiB ceiling on Hub control-plane frames
	dialTimeout     = 15 * time.Second
	writeTimeout    = 15 * time.Second
)

// ClassicTLSConfig pins ECDHE curves (`X25519`, `P-256`, `P-384`) so post-quantum hybrid key shares do not push
// TLS `ClientHello` packets past PPPoE, WireGuard, or VM NAT bridge MTU limits.
func ClassicTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	}
}

// Conn wraps an active outbound client WebSocket connection.
type Conn struct {
	conn *websocket.Conn
}

// DialOptions allows tests to supply custom TLS root CAs while preserving all transport hardening invariants.
type DialOptions struct {
	TLSConfig *tls.Config
}

// Dial opens an outbound HTTP/1.1 WebSocket connection (`wss://`, `https://`, `ws://`, or `http://`).
func Dial(ctx context.Context, rawURL, userAgent string, extraHeaders map[string]string) (*Conn, error) {
	return DialWithOptions(ctx, rawURL, userAgent, extraHeaders, DialOptions{})
}

// DialWithOptions opens an outbound WebSocket connection with optional TLS root CA overrides for local TLS tests.
func DialWithOptions(ctx context.Context, rawURL, userAgent string, extraHeaders map[string]string, opts DialOptions) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse ws url: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		u.Scheme = "wss"
	case "ws", "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("unsupported websocket scheme %q", u.Scheme)
	}

	tlsCfg := ClassicTLSConfig()
	if opts.TLSConfig != nil {
		tlsCfg = opts.TLSConfig.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
		if len(tlsCfg.CurvePreferences) == 0 {
			tlsCfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
		}
	}
	// RFC 6455 Upgrade requires HTTP/1.1; ForceAttemptHTTP2 must stay false so ALPN never negotiates h2.
	tlsCfg.NextProtos = []string{"http/1.1"}

	tr := &http.Transport{
		Proxy: nil, // Never inherit ambient HTTP_PROXY / HTTPS_PROXY environment variables.
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: dialTimeout,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     tlsCfg,
	}
	httpClient := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Never follow redirects on /agent/ws so Authorization: Bearer <agent_token> cannot leak off-origin.
			return http.ErrUseLastResponse
		},
	}

	hdr := make(http.Header)
	if userAgent != "" && !strings.ContainsAny(userAgent, "\r\n") {
		hdr.Set("User-Agent", userAgent)
	}
	for k, v := range extraHeaders {
		if !strings.ContainsAny(k+v, "\r\n") {
			hdr.Set(k, v)
		}
	}

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	c, resp, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{
		HTTPClient:      httpClient,
		HTTPHeader:      hdr,
		CompressionMode: websocket.CompressionDisabled,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}

	c.SetReadLimit(MaxMessageBytes)
	return &Conn{conn: c}, nil
}

// SetReadLimit overrides the maximum incoming WebSocket message size in bytes.
func (c *Conn) SetReadLimit(limit int64) {
	c.conn.SetReadLimit(limit)
}

// WriteText sends a UTF-8 text message (preserving Cloudflare's Hibernating WebSocket `"ping"` -> `"pong"` auto-response).
func (c *Conn) WriteText(s string) error {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return c.conn.Write(ctx, websocket.MessageText, []byte(s))
}

// ReadText reads the next message with `readTimeout`, mapping any peer WebSocket close frame cleanly to `io.EOF`.
func (c *Conn) ReadText(readTimeout time.Duration) (string, error) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if readTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, readTimeout)
		defer cancel()
	}
	_, data, err := c.conn.Read(ctx)
	if err != nil {
		if websocket.CloseStatus(err) != -1 || errors.Is(err, io.EOF) {
			return "", io.EOF
		}
		return "", err
	}
	return string(data), nil
}

// CloseCleanly sends an RFC 6455 `1000` normal closure frame and closes the underlying connection.
func (c *Conn) CloseCleanly() error {
	return c.conn.Close(websocket.StatusNormalClosure, "")
}

// CloseNow closes the underlying TCP/TLS socket immediately without waiting for a close handshake.
func (c *Conn) CloseNow() error {
	return c.conn.CloseNow()
}
