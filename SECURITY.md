# Security Policy & Threat Model

EdgeFetch is designed to run safely inside private networks (such as Home Assistant OS servers, homelabs, or branch offices) without exposing those networks to lateral movement, inbound attacks, or privilege escalation.

## Threat Model & Defense-in-Depth Controls

### 1. Zero Inbound Attack Surface
- **Outbound-only sockets in `agent` mode:** `edgefetch --mode=agent` never calls `net.Listen`. Router port-forwarding, UPnP, and VPN/tunnel daemons are unnecessary.
- **No generic proxy protocol:** EdgeFetch is **not** an HTTP `CONNECT` or SOCKS5 relay. It accepts structured JSON `FetchCall` dispatches over a single authenticated TLS 1.2/1.3 WebSocket and executes bounded HTTP `GET` requests only.

### 2. Least-Privilege Token Separation (`CALLER_TOKEN` vs. `AGENT_TOKENS`)
- **Caller Token (`CALLER_TOKEN`):** Authorizes upstream workflows to submit `POST /fetch` batches and view `GET /agents`. Never place `CALLER_TOKEN` on standby nodes.
- **Per-Site Agent Tokens (`AGENT_TOKENS`):** Standby nodes hold site-scoped tokens (`{"site-1":"...","site-2":"..."}`) accepted **only** on `GET /agent/ws` and `POST /agent/reply`.
  - Comparisons use length-independent constant-time byte XOR (`sameBytes`), failing closed whenever a token is unset or `< 24` characters.
  - `siteId` is bound to the matched token key on the server so `site-1` cannot spoof `site-2`.
  - Every `POST /agent/reply` must present both the server-generated `X-Job-Id` and one-time `X-Job-Nonce` actively pending for that exact `siteId` (`hasPendingJob` pre-checked before decompressing request streams).
- **Mandatory TLS for Non-Loopback Hubs:** `internal/agent/config.go` refuses cleartext `http://` / `ws://` hub URLs on any non-loopback address (`127.0.0.1` / `::1`), even if `EDGEFETCH_ALLOW_INSECURE_HUB=1` is set in the environment, preventing accidental transmission of bearer tokens in cleartext.

### 3. Multi-Layer SSRF & DNS-Rebinding Protection
Even if a caller token were compromised, an agent cannot be used to probe local LAN devices, Home Assistant APIs, Tailscale peers, or cloud metadata endpoints:
1. **Pre-Request URL Validation (`crawl.PublicHTTPS` + `WithBlockedHost` + `WithAllowedHosts`):**
   - Requires `https://` on port `443` with a multi-label DNS name (rejecting IP literals, `localhost`, `.localhost`, and `user:pass@` URLs) on the initial URL **and** every HTTP `3xx` redirect (max 5).
   - Automatically blocks the agent's own `hub_url` hostname to prevent recursive fetch loops, and supports an explicit `allowed_hosts` domain allowlist.
2. **Kernel-Time Socket Peer Inspection (`politeness.RejectNonPublicPeer` via `net.Dialer.Control`):**
   - Runs *after* DNS resolution creates the OS socket and *immediately before* the `connect()` syscall fires — eliminating DNS-rebinding TOCTOU races.
   - Blocks loopback (`127.0.0.0/8`, `::1`), RFC 1918 private LANs (`10.0.0.0/8`, `172.16.0.0/12` including Home Assistant OS's `172.30.32.0/23` internal network, `192.168.0.0/16`), RFC 6598 CGNAT / Tailscale (`100.64.0.0/10`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), IPv6 Unique Local (`fc00::/7`), and **IPv6-to-IPv4 transition prefixes** (`64:ff9b::/96` NAT64, `64:ff9b:1::/48`, `2002::/16` 6to4, `2001::/32` Teredo, `100::/64`).

### 4. Container Hardening & Irreversible Privilege Drop
- **Distroless Runtime:** Production images use `gcr.io/distroless/static-debian12` (~9 MB total) containing **no `/bin/sh`, no package manager, and no dynamic libc**.
- **Linux `PR_SET_NO_NEW_PRIVS` + `AllThreadsSyscall` (`internal/priv/priv_linux.go`):** On Home Assistant OS (where Supervisor mounts `/data/options.json` as `0600 root:root`), the binary reads the file into memory, zeroes the raw byte slice, invokes `prctl(PR_SET_NO_NEW_PRIVS, 1)`, clears supplementary groups (`Setgroups([])`), transitions all OS threads to UID/GID `65532:65532`, and verifies `uid == 65532` **before** opening any socket.
- **AppArmor Profile (`edgefetch_agent/apparmor.txt`):** Denies raw/packet sockets, `mount`, `ptrace`, `sys_admin`, `net_admin`, and `/proc/kcore` / `/sys/firmware` access, paired with `hassio_api: false`, `homeassistant_api: false`, and `host_network: false`.
- **Bounded Memory & Header Caps:** Enforces `MaxResponseHeaderBytes = 64 KiB`, `io.LimitReader(maxBytes + 1)` body caps, `1 MiB` WebSocket control frame caps, `20 MiB` streaming gunzip caps on the hub, and `GOMEMLIMIT=128MiB`.

## Safe Deployment Checklist

1. Generate tokens with at least 32 bytes of cryptographic randomness (`openssl rand -hex 32`).
2. Use per-site `AGENT_TOKENS` JSON so a decommissioned device can be revoked individually without rotating other sites.
3. Set `allowed_hosts` in your Home Assistant Add-on configuration whenever your workload targets a known set of domains.

## Reporting a Vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/bartrumb/edgefetch/security/advisories/new) rather than opening a public issue.
