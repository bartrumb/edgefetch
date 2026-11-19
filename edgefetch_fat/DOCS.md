# EdgeFetch Fat Worker (`edgefetch_fat`)

`edgefetch_fat` is the full-featured Home Assistant OS Add-on sibling to `edgefetch_agent` (Lite). It runs the exact same static Go binary plus **Headless Chromium** (`browser-v1`) and **Poppler `pdftotext`** (`pdf-v1`) inside an AppArmor-confined Alpine container with **zero inbound ports**.

## Capabilities Advertised to Hub

- `artifacts-v1` — Direct streaming gzip uploads to Cloudflare R2 (`PUT /agent/artifacts/<blobSha256>`).
- `browser-v1` — Headless Chromium CDP rendering (`renderMode: "auto" | "always"`) and stateful `interact` sessions (`click`, `fill`, `press`, `scroll`, `wait`, PNG screenshots).
- `pdf-v1` — Layout-preserving UTF-8 PDF text extraction via `pdftotext -layout` over `stdin`/`stdout` (zero temp files on disk).

## Defense-in-Depth Browser Isolation

1. **Pre-Render `robots.txt` Gate:** Every URL (and every `interact` `navigate` action) checks `/robots.txt` and per-host rate limits **before** Chromium navigates.
2. **Loopback SSRF `CONNECT` Tunnel (`SSRFProxy`):** Chromium runs with `--proxy-server=http://127.0.0.1:<port>`, `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`, and `--disable-quic`, forcing 100% of browser subresources through `politeness.RejectNonPublicPeer` so untrusted page JS can never reach Home Assistant (`:8123`), RFC1918 LAN IPs, or cloud metadata endpoints.
3. **Anti-Challenge Stop:** If a rendered page displays a CAPTCHA or anti-bot challenge, EdgeFetch halts immediately (`outcome: "challenge"`) and never attempts to solve, click through, or wait out challenges.
