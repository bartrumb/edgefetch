// Package ws implements a zero-dependency RFC 6455 client WebSocket over crypto/tls and net, retaining the
// post-handshake bufio.Reader across HTTP/1.1 101 Switching Protocols upgrades and enforcing a 1 MiB frame ceiling.
package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	magicGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	MaxMessageBytes = 1 << 20 // 1 MiB ceiling on control-plane frames

	OpContinuation byte = 0x0
	OpText         byte = 0x1
	OpBinary       byte = 0x2
	OpClose        byte = 0x8
	OpPing         byte = 0x9
	OpPong         byte = 0xA
)

// ClassicTLSConfig pins ECDHE curves (`X25519`, `P-256`, `P-384`) so Go 1.23+'s default post-quantum key share does not
// push TLS `ClientHello` packets past PPPoE, WireGuard, or VM NAT bridge MTU limits.
func ClassicTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	}
}

// ComputeAccept calculates the RFC 6455 `Sec-WebSocket-Accept` header expected for `secKey`.
func ComputeAccept(secKey string) string {
	sum := sha1.Sum([]byte(secKey + magicGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// MaskBytes XOR-masks `dst` in place with a 4-byte RFC 6455 client masking key.
func MaskBytes(dst []byte, mask [4]byte) {
	for i := range dst {
		dst[i] ^= mask[i&3]
	}
}

// Conn wraps an active outbound client WebSocket connection.
type Conn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
}

// Dial opens a TCP/TLS connection to `rawURL` (`wss://` / `https://` or loopback `ws://` / `http://`) and completes the
// RFC 6455 HTTP/1.1 `101 Switching Protocols` handshake.
func Dial(ctx context.Context, rawURL, userAgent string, extraHeaders map[string]string) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse ws url: %w", err)
	}

	useTLS := false
	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		useTLS = true
	case "ws", "http":
		useTLS = false
	default:
		return nil, fmt.Errorf("unsupported websocket scheme %q", u.Scheme)
	}

	hostPort := u.Host
	if u.Port() == "" {
		if useTLS {
			hostPort = net.JoinHostPort(u.Hostname(), "443")
		} else {
			hostPort = net.JoinHostPort(u.Hostname(), "80")
		}
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	var conn net.Conn
	if useTLS {
		tlsCfg := ClassicTLSConfig()
		tlsCfg.ServerName = u.Hostname()
		// RFC 6455 `Upgrade: websocket` requires an HTTP/1.1 connection; advertising `h2` would negotiate binary HTTP/2.
		tlsCfg.NextProtos = []string{"http/1.1"}
		conn, err = tls.DialWithDialer(dialer, "tcp", hostPort, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", hostPort)
	}
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	var keyRaw [16]byte
	if _, err := io.ReadFull(rand.Reader, keyRaw[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("rand key: %w", err)
	}
	secKey := base64.StdEncoding.EncodeToString(keyRaw[:])

	reqURI := u.RequestURI()
	if reqURI == "" {
		reqURI = "/"
	}

	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "GET %s HTTP/1.1\r\n", reqURI)
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", u.Host)
	reqBuf.WriteString("Upgrade: websocket\r\n")
	reqBuf.WriteString("Connection: Upgrade\r\n")
	reqBuf.WriteString("Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&reqBuf, "Sec-WebSocket-Key: %s\r\n", secKey)
	if userAgent != "" && !strings.ContainsAny(userAgent, "\r\n") {
		fmt.Fprintf(&reqBuf, "User-Agent: %s\r\n", userAgent)
	}
	for k, v := range extraHeaders {
		if !strings.ContainsAny(k+v, "\r\n") {
			fmt.Fprintf(&reqBuf, "%s: %s\r\n", k, v)
		}
	}
	reqBuf.WriteString("\r\n")

	if _, err := io.WriteString(conn, reqBuf.String()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write upgrade: %w", err)
	}

	br := bufio.NewReaderSize(conn, 8192)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet, URL: u})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("websocket upgrade HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	if got := strings.TrimSpace(resp.Header.Get("Sec-WebSocket-Accept")); got != ComputeAccept(secKey) {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid Sec-WebSocket-Accept %q", got)
	}

	_ = conn.SetDeadline(time.Time{})
	return &Conn{conn: conn, br: br}, nil
}

// WriteFrame writes a masked client-to-server WebSocket frame safely across concurrent goroutines.
func (c *Conn) WriteFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	var mask [4]byte
	if _, err := io.ReadFull(rand.Reader, mask[:]); err != nil {
		return err
	}

	n := len(payload)
	buf := make([]byte, 0, 14+n)
	buf = append(buf, 0x80|(opcode&0x0F))
	switch {
	case n < 126:
		buf = append(buf, 0x80|byte(n))
	case n <= 65535:
		buf = append(buf, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(n))
	default:
		buf = append(buf, 0x80|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(buf[len(buf)-8:], uint64(n))
	}
	buf = append(buf, mask[:]...)
	start := len(buf)
	buf = append(buf, payload...)
	MaskBytes(buf[start:], mask)

	_ = c.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := c.conn.Write(buf)
	return err
}

// WriteText sends a single masked UTF-8 text frame.
func (c *Conn) WriteText(s string) error {
	return c.WriteFrame(OpText, []byte(s))
}

// CloseCleanly sends an RFC 6455 `1000` normal-closure frame and closes the underlying socket.
func (c *Conn) CloseCleanly() error {
	var code [2]byte
	binary.BigEndian.PutUint16(code[:], 1000)
	_ = c.WriteFrame(OpClose, code[:])
	return c.conn.Close()
}

// CloseNow closes the underlying socket immediately without sending a close frame.
func (c *Conn) CloseNow() error {
	return c.conn.Close()
}

// ReadText reads the next complete text message, automatically answering server `OpPing` control frames even if
// interleaved mid-fragmentation, and enforcing both `readTimeout` and `MaxMessageBytes`.
func (c *Conn) ReadText(readTimeout time.Duration) (string, error) {
	var msgBuf []byte
	inFragment := false

	for {
		if readTimeout > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))
		}
		var hdr [2]byte
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return "", err
		}
		fin := (hdr[0] & 0x80) != 0
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		length := uint64(hdr[1] & 0x7F)

		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return "", err
			}
			length = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return "", err
			}
			length = binary.BigEndian.Uint64(ext[:])
		}

		if length > MaxMessageBytes || uint64(len(msgBuf))+length > MaxMessageBytes {
			_ = c.CloseNow()
			return "", fmt.Errorf("websocket message exceeds %d bytes", MaxMessageBytes)
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
				return "", err
			}
		}

		payload := make([]byte, int(length))
		if length > 0 {
			if _, err := io.ReadFull(c.br, payload); err != nil {
				return "", err
			}
			if masked {
				MaskBytes(payload, maskKey)
			}
		}

		switch opcode {
		case OpPing:
			_ = c.WriteFrame(OpPong, payload)
			continue
		case OpPong:
			continue
		case OpClose:
			_ = c.CloseCleanly()
			return "", io.EOF
		case OpText, OpBinary:
			if inFragment {
				return "", errors.New("unexpected new websocket data frame during fragmentation")
			}
			msgBuf = append(msgBuf[:0], payload...)
			if fin {
				return string(msgBuf), nil
			}
			inFragment = true
		case OpContinuation:
			if !inFragment {
				return "", errors.New("unexpected websocket continuation frame")
			}
			msgBuf = append(msgBuf, payload...)
			if fin {
				return string(msgBuf), nil
			}
		default:
			return "", fmt.Errorf("unsupported websocket opcode 0x%x", opcode)
		}
	}
}
