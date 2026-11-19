package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bartrumb/edgefetch/internal/ws"
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

// cdpConn multiplexes Chrome DevTools Protocol JSON-RPC 2.0 calls and async events over a single loopback WebSocket.
type cdpConn struct {
	ws     *ws.Conn
	nextID atomic.Int64

	mu      sync.Mutex
	pending map[int64]chan cdpEnvelope
	subs    map[int]chan cdpEvent
	nextSub int
	closed  bool
	closeCh chan struct{}

	crashMu  sync.Mutex
	crashMsg string
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

	c := &cdpConn{
		ws:      conn,
		pending: make(map[int64]chan cdpEnvelope),
		subs:    make(map[int]chan cdpEvent),
		closeCh: make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
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
		raw, err := c.ws.ReadText(120 * time.Second)
		if err != nil {
			return
		}
		var env cdpEnvelope
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
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

	if err := c.ws.WriteText(string(payload)); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return err
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
	return c.ws.CloseCleanly()
}
