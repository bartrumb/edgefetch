package browser

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/ws"
	"github.com/coder/websocket"
)

const (
	maxCDPFrameBytes = 24 << 20  // 24 MiB ceiling for hydrated DOM + base64 PNG screenshots
	maxCDPDrainBytes = 256 << 20 // 256 MiB runaway stream safety valve when draining an oversized frame
)

var errCDPFrameTooLarge = errors.New("cdp frame exceeds maxCDPFrameBytes")

type cdpOversizedFrameError struct {
	id int64
}

func (e *cdpOversizedFrameError) Error() string {
	return errCDPFrameTooLarge.Error()
}

func (e *cdpOversizedFrameError) Unwrap() error {
	return errCDPFrameTooLarge
}

// cdpStreamingIDScanner extracts the top-level JSON-RPC integer "id" field across arbitrary byte chunks
// with zero heap allocations while ignoring nested objects/arrays.
type cdpStreamingIDScanner struct {
	started         bool
	invalid         bool
	found           bool
	id              int64
	depth           int
	inStr           bool
	esc             bool
	expectKey       bool
	capturingKey    bool
	keyBuf          [3]byte
	keyLen          int
	afterIDKey      bool
	readingIDDigits bool
	hasIDDigits     bool
}

func (s *cdpStreamingIDScanner) feed(chunk []byte) {
	if s.invalid || s.found {
		return
	}
	for i := 0; i < len(chunk); i++ {
		b := chunk[i]
		if !s.started {
			if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
				continue
			}
			s.started = true
			if b != '{' {
				s.invalid = true
				return
			}
			s.depth = 1
			s.expectKey = true
			continue
		}

		if s.inStr {
			if s.esc {
				s.esc = false
				if s.capturingKey && s.keyLen < len(s.keyBuf) {
					s.keyLen = len(s.keyBuf)
				}
				continue
			}
			if !s.capturingKey || s.keyLen == len(s.keyBuf) {
				sub := chunk[i:]
				qIdx := bytes.IndexByte(sub, '"')
				bIdx := bytes.IndexByte(sub, '\\')
				if qIdx < 0 && bIdx < 0 {
					return
				}
				if bIdx >= 0 && (qIdx < 0 || bIdx < qIdx) {
					s.esc = true
					i += bIdx
					continue
				}
				s.inStr = false
				s.capturingKey = false
				s.expectKey = false
				i += qIdx
				continue
			}
			if b == '\\' {
				s.esc = true
				continue
			}
			if b == '"' {
				s.inStr = false
				if s.capturingKey {
					s.capturingKey = false
					s.expectKey = false
					if s.keyLen == 2 && s.keyBuf[0] == 'i' && s.keyBuf[1] == 'd' {
						s.afterIDKey = true
					}
				}
				continue
			}
			if s.capturingKey && s.keyLen < len(s.keyBuf) {
				s.keyBuf[s.keyLen] = b
				s.keyLen++
			}
			continue
		}

		if s.depth == 1 && s.readingIDDigits {
			if !s.hasIDDigits && (b == ' ' || b == '\t' || b == '\r' || b == '\n') {
				continue
			}
			if b >= '0' && b <= '9' {
				s.hasIDDigits = true
				digit := int64(b - '0')
				if s.id <= (math.MaxInt64-digit)/10 {
					s.id = s.id*10 + digit
				}
				continue
			}
			s.readingIDDigits = false
			if s.hasIDDigits && s.id > 0 {
				s.found = true
				return
			}
			s.hasIDDigits = false
			s.id = 0
		}

		if s.depth == 1 && s.afterIDKey {
			if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
				continue
			}
			s.afterIDKey = false
			if b == ':' {
				s.readingIDDigits = true
				s.hasIDDigits = false
				s.id = 0
				continue
			}
		}

		switch b {
		case '"':
			s.inStr = true
			if s.depth == 1 && s.expectKey {
				s.capturingKey = true
				s.keyLen = 0
			}
		case '{', '[':
			if s.depth == 1 {
				s.expectKey = false
			}
			s.depth++
		case '}', ']':
			s.depth--
			if s.depth <= 0 {
				return
			}
		case ',':
			if s.depth == 1 {
				s.expectKey = true
			}
		}
	}
}

func (s *cdpStreamingIDScanner) resultID() int64 {
	if s.found || (s.readingIDDigits && s.hasIDDigits && s.id > 0) {
		return s.id
	}
	return 0
}

type cdpRequest struct {
	ID        int64  `json:"id"`
	SessionID string `json:"sessionId,omitempty"`
	Method    string `json:"method"`
	Params    any    `json:"params,omitempty"`
}

type cdpEnvelope struct {
	ID        int64           `json:"id,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
	localErr error `json:"-"`
}

type cdpEvent struct {
	SessionID string
	Method    string
	Params    json.RawMessage
}

type cdpTransport interface {
	readFrame() ([]byte, error)
	writeFrame(ctx context.Context, payload []byte) error
	close() error
}

type wsCDPTransport struct {
	conn    *websocket.Conn
	readBuf [32 * 1024]byte
}

func (t *wsCDPTransport) readFrame() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	_, r, err := t.conn.Reader(ctx)
	if err != nil {
		if websocket.CloseStatus(err) != -1 || errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, err
	}

	var buf []byte
	for {
		n, rErr := r.Read(t.readBuf[:])
		if n > 0 {
			if len(buf)+n > maxCDPFrameBytes {
				var scanner cdpStreamingIDScanner
				scanner.feed(buf)
				buf = nil // release buffer before draining remainder of WebSocket message
				scanner.feed(t.readBuf[:n])
				if !scanner.started || scanner.invalid {
					_ = t.conn.CloseNow()
					return nil, errCDPFrameTooLarge
				}
				for !errors.Is(rErr, io.EOF) {
					if rErr != nil {
						if websocket.CloseStatus(rErr) != -1 {
							return nil, io.EOF
						}
						return nil, rErr
					}
					dn, dErr := r.Read(t.readBuf[:])
					if dn > 0 {
						scanner.feed(t.readBuf[:dn])
					}
					rErr = dErr
				}
				return nil, &cdpOversizedFrameError{id: scanner.resultID()}
			}
			buf = append(buf, t.readBuf[:n]...)
		}
		if errors.Is(rErr, io.EOF) {
			return buf, nil
		}
		if rErr != nil {
			if websocket.CloseStatus(rErr) != -1 {
				return nil, io.EOF
			}
			return nil, rErr
		}
	}
}

func (t *wsCDPTransport) writeFrame(ctx context.Context, payload []byte) error {
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return t.conn.Write(wctx, websocket.MessageText, payload)
}

func (t *wsCDPTransport) close() error {
	return t.conn.Close(websocket.StatusNormalClosure, "")
}

// pipeCDPTransport speaks Chromium's native `--remote-debugging-pipe` NUL-delimited JSON-RPC framing directly over
// anonymous OS pipes (FD 3 / FD 4), opening zero listening TCP ports in either Go or Chromium.
type pipeCDPTransport struct {
	r         *os.File
	w         *os.File
	onClose   func()
	writeCh   chan []byte
	closedCh  chan struct{}
	closeOnce sync.Once
	readBuf   [32 * 1024]byte
	chunk     []byte
	pending   []byte
}

func newPipeCDPTransport(toChrome, fromChrome *os.File, onClose func()) *pipeCDPTransport {
	pt := &pipeCDPTransport{
		r:        fromChrome,
		w:        toChrome,
		onClose:  onClose,
		writeCh:  make(chan []byte, 16),
		closedCh: make(chan struct{}),
	}
	go pt.writeLoop()
	return pt
}

func (t *pipeCDPTransport) writeLoop() {
	for {
		select {
		case <-t.closedCh:
			return
		case framed, ok := <-t.writeCh:
			if !ok {
				return
			}
			_ = t.w.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := t.w.Write(framed); err != nil {
				_ = t.close()
				return
			}
		}
	}
}

func (t *pipeCDPTransport) writeFrame(ctx context.Context, payload []byte) error {
	framed := make([]byte, len(payload)+1)
	copy(framed, payload)
	framed[len(payload)] = 0
	select {
	case <-t.closedCh:
		return errors.New("cdp pipe closed")
	case <-ctx.Done():
		return ctx.Err()
	case t.writeCh <- framed:
		return nil
	}
}

func (t *pipeCDPTransport) drainOversizedPipeFrame(nulIdx int) error {
	var scanner cdpStreamingIDScanner
	scanner.feed(t.pending)
	discarded := int64(len(t.pending))
	t.pending = nil

	if nulIdx >= 0 {
		scanner.feed(t.chunk[:nulIdx])
		discarded += int64(nulIdx)
		t.chunk = t.chunk[nulIdx+1:]
		if !scanner.started || scanner.invalid || discarded > maxCDPDrainBytes {
			_ = t.close()
			return errCDPFrameTooLarge
		}
		return &cdpOversizedFrameError{id: scanner.resultID()}
	}

	scanner.feed(t.chunk)
	discarded += int64(len(t.chunk))
	t.chunk = nil
	if !scanner.started || scanner.invalid || discarded > maxCDPDrainBytes {
		_ = t.close()
		return errCDPFrameTooLarge
	}

	_ = t.r.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		n, err := t.r.Read(t.readBuf[:])
		if n > 0 {
			if nul := bytes.IndexByte(t.readBuf[:n], 0); nul >= 0 {
				discarded += int64(nul)
				if discarded > maxCDPDrainBytes {
					_ = t.close()
					return errCDPFrameTooLarge
				}
				scanner.feed(t.readBuf[:nul])
				t.chunk = t.readBuf[nul+1 : n]
				_ = t.r.SetReadDeadline(time.Time{})
				if !scanner.started || scanner.invalid {
					_ = t.close()
					return errCDPFrameTooLarge
				}
				return &cdpOversizedFrameError{id: scanner.resultID()}
			}
			discarded += int64(n)
			if discarded > maxCDPDrainBytes {
				_ = t.close()
				return errCDPFrameTooLarge
			}
			scanner.feed(t.readBuf[:n])
			if scanner.invalid {
				_ = t.close()
				return errCDPFrameTooLarge
			}
		}
		if err != nil {
			_ = t.close()
			return err
		}
	}
}

func (t *pipeCDPTransport) readFrame() ([]byte, error) {
	for {
		for len(t.chunk) > 0 {
			nul := bytes.IndexByte(t.chunk, 0)
			if nul >= 0 {
				if len(t.pending)+nul > maxCDPFrameBytes {
					return nil, t.drainOversizedPipeFrame(nul)
				}
				var frame []byte
				if len(t.pending) == 0 {
					frame = make([]byte, nul)
					copy(frame, t.chunk[:nul])
				} else {
					frame = append(t.pending, t.chunk[:nul]...)
					t.pending = nil
				}
				t.chunk = t.chunk[nul+1:]
				if len(frame) == 0 {
					continue
				}
				return frame, nil
			}
			if len(t.pending)+len(t.chunk) > maxCDPFrameBytes {
				return nil, t.drainOversizedPipeFrame(-1)
			}
			t.pending = append(t.pending, t.chunk...)
			t.chunk = nil
		}
		n, err := t.r.Read(t.readBuf[:])
		if n > 0 {
			t.chunk = t.readBuf[:n]
			continue
		}
		if err != nil {
			_ = t.close()
			return nil, err
		}
	}
}

func (t *pipeCDPTransport) close() error {
	t.closeOnce.Do(func() {
		close(t.closedCh)
		if t.w != nil {
			_ = t.w.SetDeadline(time.Now())
			_ = t.w.Close()
		}
		if t.r != nil {
			_ = t.r.SetDeadline(time.Now())
			_ = t.r.Close()
		}
		if t.onClose != nil {
			t.onClose()
		}
	})
	return nil
}

// cdpConn multiplexes Chrome DevTools Protocol JSON-RPC 2.0 calls and async events over a pipe or WebSocket transport.
type cdpConn struct {
	tr     cdpTransport
	nextID atomic.Int64

	mu      sync.Mutex
	pending map[int64]chan cdpEnvelope
	subs    map[int]chan cdpEvent
	nextSub int
	closed  bool
	closeCh chan struct{}

	crashMu  sync.Mutex
	crashMsg string

	writeOverride func(string) error
}

func newCDPConn(tr cdpTransport) *cdpConn {
	c := &cdpConn{
		tr:      tr,
		pending: make(map[int64]chan cdpEnvelope),
		subs:    make(map[int]chan cdpEvent),
		closeCh: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func newPipeCDPConn(toChrome, fromChrome *os.File, onClose func()) *cdpConn {
	return newCDPConn(newPipeCDPTransport(toChrome, fromChrome, onClose))
}

func (c *cdpConn) setCrashReason(line string) {
	c.crashMu.Lock()
	c.crashMsg = startupReason(c.crashMsg, line)
	c.crashMu.Unlock()
}

func (c *cdpConn) crashError(suffix string) error {
	c.crashMu.Lock()
	msg := c.crashMsg
	c.crashMu.Unlock()
	base := "cdp connection closed"
	if suffix != "" {
		base += " " + suffix
	}
	if msg != "" {
		base += ": " + msg
	}
	return errors.New(base)
}

func dialCDP(ctx context.Context, wsURL string) (*cdpConn, error) {
	u, err := url.Parse(wsURL)
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

	tlsCfg := ws.ClassicTLSConfig()
	tlsCfg.NextProtos = []string{"http/1.1"}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     tlsCfg,
	}
	httpClient := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	conn, resp, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{
		HTTPClient:      httpClient,
		CompressionMode: websocket.CompressionDisabled,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	conn.SetReadLimit(maxCDPDrainBytes)
	_ = tls.VersionTLS12
	return newCDPConn(&wsCDPTransport{conn: conn}), nil
}

func (c *cdpConn) readLoop() {
	defer func() {
		c.mu.Lock()
		c.closed = true
		close(c.closeCh)
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
	}()

	for {
		raw, err := c.tr.readFrame()
		if err != nil {
			var overErr *cdpOversizedFrameError
			if errors.As(err, &overErr) {
				if overErr.id != 0 {
					c.mu.Lock()
					ch := c.pending[overErr.id]
					delete(c.pending, overErr.id)
					c.mu.Unlock()
					if ch != nil {
						ch <- cdpEnvelope{ID: overErr.id, localErr: errCDPFrameTooLarge}
					}
				}
				continue
			}
			return
		}
		var env cdpEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		if env.ID != 0 {
			c.mu.Lock()
			ch := c.pending[env.ID]
			delete(c.pending, env.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- env
			}
			continue
		}
		if env.Method != "" {
			ev := cdpEvent{SessionID: env.SessionID, Method: env.Method, Params: env.Params}
			c.mu.Lock()
			for _, sub := range c.subs {
				select {
				case sub <- ev:
				default:
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *cdpConn) subscribe() (<-chan cdpEvent, func()) {
	ch := make(chan cdpEvent, 64)
	c.mu.Lock()
	id := c.nextSub
	c.nextSub++
	c.subs[id] = ch
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		delete(c.subs, id)
		c.mu.Unlock()
	}
}

func (c *cdpConn) call(ctx context.Context, sessionID, method string, params any, out any) error {
	id := c.nextID.Add(1)
	replyCh := make(chan cdpEnvelope, 1)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.crashError("")
	}
	c.pending[id] = replyCh
	c.mu.Unlock()

	payload, err := json.Marshal(cdpRequest{
		ID:        id,
		SessionID: sessionID,
		Method:    method,
		Params:    params,
	})
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return err
	}

	var writeErr error
	if c.writeOverride != nil {
		writeErr = c.writeOverride(string(payload))
	} else {
		writeErr = c.tr.writeFrame(ctx, payload)
	}
	if writeErr != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return writeErr
	}

	select {
	case env, ok := <-replyCh:
		if !ok {
			return c.crashError("while awaiting " + method)
		}
		if env.localErr != nil {
			return fmt.Errorf("cdp %s: %w", method, env.localErr)
		}
		if env.Error != nil {
			return fmt.Errorf("cdp %s error %d: %s", method, env.Error.Code, env.Error.Message)
		}
		if out != nil && len(env.Result) > 0 {
			return json.Unmarshal(env.Result, out)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

func (c *cdpConn) isClosed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *cdpConn) close() error {
	return c.tr.close()
}
