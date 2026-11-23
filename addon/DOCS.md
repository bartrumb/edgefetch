# EdgeFetch Home Assistant Add-on

`EdgeFetch` runs a single static Go HTTP/2 worker, **streaming Poppler `pdftotext`** (`pdf-v1`, up to 256 MiB PDFs), and **all 57 keyless YAML site adapters** inside an AppArmor-confined, privilege-dropped (`65532:65532`, `NoNewPrivs=1`, `PR_SET_DUMPABLE=0`) Alpine container with **zero inbound ports** (~15 MB steady-state RAM).

## Home Assistant OS Browser Sandbox Policy (Fail-Closed by Default)

On Home Assistant OS, Home Assistant Supervisor prohibits custom per-add-on seccomp profiles and blocks unprivileged user namespaces (`CLONE_NEWUSER`) required by Chromium's Linux process sandbox. Rather than weakening host security with `--no-sandbox` or recommending unprotected Portainer overrides, EdgeFetch keeps Chromium rendering **off by default (fail-closed)** on Home Assistant OS while running HTTP/2 scraping, `pdf-v1`, `artifacts-v1`, and all 57 keyless YAML adapters locally at full speed.

Users who also want headless JavaScript rendering (`browser-v1` / `interact`) should pair a standard Docker, Linux, macOS, or Windows `edgefetch-agent` worker running with `--security-opt seccomp=chromium-sandbox.json` (from `deploy/seccomp/chromium-sandbox.json`), where Chromium runs with its full OS user/PID/network namespace + seccomp-BPF sandbox enabled (`sandbox: "on"`).

## Capabilities Advertised to Hub

- `artifacts-v1` — Direct streaming gzip uploads to Cloudflare R2 (`PUT /agent/artifacts/<blobSha256>`).
- `pdf-v1` — Layout-preserving UTF-8 PDF text extraction via `pdftotext -layout` over `stdin`/`stdout` (zero temp files on disk).
- `browser-v1` — Advertised only on hosts where Chromium's OS process sandbox initializes cleanly (`sandbox: "on"`); automatically disabled (fail-closed) under Home Assistant OS Supervisor MAC/seccomp policy.

## Defense-in-Depth Isolation

1. **Privilege Drop & Secret Lockdown:** At startup, `/data` (`0700`) and `/data/options.json` (`0600`) are locked to `root:root` via `O_NOFOLLOW` file descriptors before all Go runtime threads irreversibly drop to `65532:65532` with `PR_SET_NO_NEW_PRIVS=1` and `PR_SET_DUMPABLE=0`.
2. **Pre-Fetch & Pre-Render `robots.txt` Gate:** Every URL (and every `interact` `navigate` action on browser-capable workers) checks `/robots.txt` and per-host rate limits before dialing.
3. **Loopback SSRF Guard (`RejectNonPublicPeer` & `SSRFProxy`):** Both the Go HTTP/2 dialer and Chromium's `CONNECT` tunnel (`--proxy-server=http://127.0.0.1:<port>`, `--proxy-bypass-list=<-loopback>`, `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`, `--disable-quic`) enforce `politeness.RejectNonPublicPeer` so untrusted origins can never reach Home Assistant (`:8123`), RFC1918 LAN IPs, or cloud metadata endpoints.
4. **Anti-Challenge Stop:** If a page displays a CAPTCHA or anti-bot challenge, EdgeFetch halts immediately (`outcome: "challenge"`) and never attempts to solve, click through, or wait out challenges.
