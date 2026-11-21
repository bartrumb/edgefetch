# ws

## Overview
Package `ws` wraps `github.com/coder/websocket` behind a hardened outbound WebSocket control-plane client pinned to HTTP/1.1 ALPN, classic ECDHE TLS curves, disabled `permessage-deflate` compression, and zero proxy/redirect credential leakage.

## Interface
- `[client.go:MaxMessageBytes]`: `const MaxMessageBytes = 1 << 20` — default 1 MiB inbound WebSocket frame ceiling.
- `[client.go:ClassicTLSConfig]`: `func ClassicTLSConfig() *tls.Config` — returns a TLS 1.2+ configuration pinned to classic `X25519`, `CurveP256`, and `CurveP384` ECDHE curves.
- `[client.go:Conn]`: `type Conn struct` — wraps an outbound `*websocket.Conn`.
- `[client.go:DialOptions]`: `type DialOptions struct { TLSConfig *tls.Config }`.
- `[client.go:Dial]`: `func Dial(ctx context.Context, rawURL, userAgent string, extraHeaders map[string]string) (*Conn, error)`.
- `[client.go:DialWithOptions]`: `func DialWithOptions(ctx context.Context, rawURL, userAgent string, extraHeaders map[string]string, opts DialOptions) (*Conn, error)`.
- `[client.go:Conn.SetReadLimit]`: `func (c *Conn) SetReadLimit(limit int64)`.
- `[client.go:Conn.WriteText]`: `func (c *Conn) WriteText(s string) error`.
- `[client.go:Conn.ReadText]`: `func (c *Conn) ReadText(readTimeout time.Duration) (string, error)`.
- `[client.go:Conn.CloseCleanly]`: `func (c *Conn) CloseCleanly() error`.
- `[client.go:Conn.CloseNow]`: `func (c *Conn) CloseNow() error`.

## Invariants
- `[client.go:DialWithOptions]`: Accepts only `wss`/`https` (normalized to `wss`) and `ws`/`http` (normalized to `ws`) URL schemes; rejects all others.
- `[client.go:ClassicTLSConfig]`, `[client.go:DialWithOptions]`: Enforces `MinVersion >= tls.VersionTLS12`, defaults `CurvePreferences` to `X25519`/`CurveP256`/`CurveP384` (cloning `opts.TLSConfig` before mutation), and forces `NextProtos = []string{"http/1.1"}` with `ForceAttemptHTTP2 = false`.
- `[client.go:DialWithOptions]`: Sets `http.Transport.Proxy = nil` and `CheckRedirect` returning `http.ErrUseLastResponse` so `Authorization` headers never traverse ambient proxies or redirects.
- `[client.go:DialWithOptions]`: Drops `userAgent` and any `extraHeaders` key/value containing `\r` or `\n`, disables RFC 7692 compression (`websocket.CompressionDisabled`), initializes read limit to `MaxMessageBytes` (`1 MiB`), and bounds dial/TLS handshake timeouts to `dialTimeout` (`15s`).
- `[client.go:Conn.WriteText]`, `[client.go:Conn.ReadText]`: `WriteText` bounds writes to `writeTimeout` (`15s`); `ReadText` maps peer close statuses (`websocket.CloseStatus(err) != -1`) or `io.EOF` to `("", io.EOF)`.

## Side Effects
- `[client.go:Dial]`, `[client.go:DialWithOptions]`: Opens outbound TCP/TLS sockets, performs an HTTP/1.1 RFC 6455 WebSocket upgrade handshake, and closes idle transport connections on dial failure.
- `[client.go:Conn.SetReadLimit]`: Mutates the inbound frame limit on the underlying `*websocket.Conn`.
- `[client.go:Conn.WriteText]`, `[client.go:Conn.ReadText]`: Transmits and receives WebSocket frames over the network socket.
- `[client.go:Conn.CloseCleanly]`, `[client.go:Conn.CloseNow]`: Sends an RFC 6455 `StatusNormalClosure` (`1000`) frame (`CloseCleanly`) or immediately closes the underlying TCP/TLS socket (`CloseNow`).

## Verification
- Run: `go test ./internal/ws`
