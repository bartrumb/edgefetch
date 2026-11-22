package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/ws"
)

const maxCDPFrameBytes = 24 << 20 // 24 MiB ceiling for hydrated DOM + base64 PNG screenshots

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
	ws *ws.Conn
}

func (t *wsCDPTransport) readFrame() ([]byte, error) {
	raw, err := t.ws.ReadText(120 * time.Second)
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

func (t *wsCDPTransport) writeFrame(_ context.Context, payload []byte) error {
	return t.ws.WriteText(string(payload))
}

func (t *wsCDPTransport) close() error {
	return t.ws.CloseCleanly()
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

func (t *pipeCDPTransport) readFrame() ([]byte, error) {
	for {
		for len(t.chunk) > 0 {
			nul := bytes.IndexByte(t.chunk, 0)
			if nul >= 0 {
				if len(t.pending)+nul > maxCDPFrameBytes {
					_ = t.close()
					return nil, errors.New("cdp pipe frame exceeds maxCDPFrameBytes")
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
				_ = t.close()
				return nil, errors.New("cdp pipe frame exceeds maxCDPFrameBytes")
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
	conn, err := ws.Dial(ctx, wsURL, "", nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(maxCDPFrameBytes)
	return newCDPConn(&wsCDPTransport{ws: conn}), nil
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
