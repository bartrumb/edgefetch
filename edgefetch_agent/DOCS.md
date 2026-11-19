# EdgeFetch Cold-Standby Worker — Lite (`edgefetch_agent`)

An **outbound-only Go HTTP/2 fetcher** (one Go dependency, with no transitive dependencies) that connects to your Cloudflare Hibernating WebSocket Durable Object (`AgentHubDO`).

> Need Headless Chromium JS rendering (`browser-v1` / `interact`) or Poppler layout PDF extraction (`pdf-v1`)? Install the sibling **EdgeFetch Fat Worker (`edgefetch_fat`)** add-on from this same repository!

## Security Highlights

- **Zero Inbound Ports & Zero Proxy Surface:** Nothing listens on TCP/UDP. The worker dials outbound `wss://` (TLS 1.2/1.3) to your Cloudflare Worker hub and only executes signed jobs issued over that authenticated socket.
- **Least-Privilege Authentication:** Uses a dedicated `agent_token` (`AGENT_TOKENS` / `AGENT_TOKEN`), never your caller API token.
- **Irreversible Root Drop + AppArmor Confinement:** Reads Home Assistant Supervisor's `0600 root:root` `/data/options.json` into memory, scrubs the raw read buffer, sets `PR_SET_NO_NEW_PRIVS` across all Go runtime OS threads (`AllThreadsSyscall6`), clears supplementary groups, and drops all OS threads to UID/GID `65532:65532` inside a shell-free ~9 MB `distroless` container confined by a custom AppArmor profile (`deny network raw`, `deny mount`, `deny ptrace`).
- **Dial-Time LAN & IPv6-Transition SSRF Guard:** `net.Dialer.Control` (`RejectNonPublicPeer` via `net/netip`) inspects the resolved peer IP right before `connect()`, permitting IPv6 strictly within `2000::/3` global unicast and blocking `0.0.0.0/8`, loopback (`127.0.0.0/8`, `::1`), RFC 1918 LANs (`10/8`, `172.16/12` including Home Assistant's `172.30.32.0/23` internal bridge, `192.168/16`), Tailscale/CGNAT (`100.64/10`), cloud metadata (`169.254/16`), 6to4 relay (`192.88.99.0/24`), ORCHID/ORCHIDv2 (`2001:10::/28`, `2001:20::/28`), documentation (`2001:db8::/32`, `3fff::/20`), SRv6 (`5f00::/16`), deprecated site-local (`fec0::/10`), and IPv6-to-IPv4 transition prefixes (`::/96`, `0:0:0:0:ffff:0::/96`, `64:ff9b::/96`, `2002::/16`, `2001::/32`).

## 1-Click Installation in Home Assistant

[![Open your Home Assistant instance and show the add app repository dialog with EdgeFetch pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fbartrumb%2Fedgefetch)

1. Click the **My Home Assistant** button above (or go to **Settings -> Add-ons -> Add-on Store -> ⋮ (top right) -> Repositories** and add `https://github.com/bartrumb/edgefetch`).
2. Click **EdgeFetch Cold-Standby Worker -> Install**.
4. Open **Configuration** and fill in:
   - `hub_url`: Your Cloudflare Worker URL (e.g., `https://your-edgefetch-hub.workers.dev`)
   - `agent_token`: Your per-site secret token (`>= 24` random characters)
   - `site_id`: Unique slug per server (`site-1`, `site-arm64`, `site-x86`)
   - `user_agent`: Honest bot identifier for your application
   - `pause_ms` (`3000`) & `pause_jitter_ms` (`1500`): Polite `3.0–4.5 s` randomized pacing
   - `allowed_hosts`: Optional domain allowlist (leave empty to allow any public HTTPS host)
5. Enable **Start on boot** and **Watchdog**, then click **Start**.
