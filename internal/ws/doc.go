// Package ws wraps `github.com/coder/websocket` (EdgeFetch's sole external Go dependency) behind a minimal,
// hardened outbound WebSocket control-plane client.
//
// # Transport Hardening
//
//   - Forces HTTP/1.1 ALPN (`NextProtos: ["http/1.1"]`) required for RFC 6455 `Upgrade: websocket` handshakes.
//   - Restricts TLS key exchange to classic ECDHE curves ([ClassicTLSConfig]) to avoid 1.2 KiB post-quantum
//     `X25519MLKEM768` ClientHello middlebox drops on residential ISP routers.
//   - Ignores ambient `HTTP_PROXY` / `HTTPS_PROXY` variables (`Proxy: nil`) and refuses HTTP redirects so
//     `Authorization: Bearer <agent_token>` headers can never leak to third-party hosts.
//   - Disables RFC 7692 `permessage-deflate` compression (`CompressionDisabled`) to prevent sliding-window RAM
//     overhead and decompression-bomb amplification, with a strict 1 MiB inbound frame cap.
package ws
