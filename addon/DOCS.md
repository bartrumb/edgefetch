# EdgeFetch Home Assistant Add-on

`EdgeFetch` runs a single static Go HTTP/2 worker, **streaming Poppler `pdftotext`** (`pdf-v1`, up to 256 MiB PDFs), and **all 56 keyless YAML site adapters** inside an AppArmor-confined, privilege-dropped (`65532:65532`, `NoNewPrivs=1`, `PR_SET_DUMPABLE=0`) Alpine container with **zero inbound ports** (~15 MB steady-state RAM).

## Upgrading from pre-`v2.7.2` (`EdgeFetch Fat`)

In `v2.7.2`, the add-on slug changed from `edgefetch_fat` to `edgefetch`. Because Home Assistant Supervisor identifies installed add-ons by slug, upgrading from an older *EdgeFetch Fat* installation requires a one-time cutover:

1. In Home Assistant, open **Settings → Add-ons → Add-on Store** and click **⋮ → Check for updates**.
2. Select and install **EdgeFetch** (`slug: edgefetch`) from the repository.
3. Copy your `hub_url`, `agent_token`, and `site_id` values from *EdgeFetch Fat* into the new **EdgeFetch** add-on configuration and start **EdgeFetch**.
4. Stop and uninstall the retired *EdgeFetch Fat* (`edgefetch_fat`) entry.

## Home Assistant OS Browser Sandbox Policy (Fail-Closed by Default, Opt-In Toggle)

On Home Assistant OS, Home Assistant Supervisor prohibits custom per-add-on seccomp profiles and blocks unprivileged user namespaces (`CLONE_NEWUSER`) required by Chromium's Linux process sandbox. By default, EdgeFetch keeps Chromium rendering **off (fail-closed)** (`allow_no_sandbox_browser: false`) while running HTTP/2 scraping, `pdf-v1`, `artifacts-v1`, and all 56 keyless YAML adapters locally at full speed.

- **Option A — Enable on Home Assistant OS (`allow_no_sandbox_browser: true`):** In the add-on **Configuration** tab, enable **Allow Browser Without User-Namespace Sandbox (Home Assistant OS)** (`allow_no_sandbox_browser: true`) and restart the add-on. Chromium will advertise `browser-v1` (`interact` and `renderMode: "always"`/`"auto"`) while still confined by Home Assistant OS AppArmor, irreversible `65532:65532` privilege drop (`NoNewPrivs=1`), and the loopback `SSRFProxy`.
- **Option B — Full OS Process Sandbox on Docker / Linux / macOS / Windows:** Pair a standard `edgefetch-agent` worker running with `--security-opt seccomp=chromium-sandbox.json` (from `deploy/seccomp/chromium-sandbox.json`), where Chromium runs with its full OS user/PID/network namespace + seccomp-BPF sandbox enabled (`sandbox: "on"`).

## Capabilities Advertised to Hub

- `artifacts-v1` — Direct streaming gzip uploads to Cloudflare R2 (`PUT /agent/artifacts/<blobSha256>`).
- `pdf-v1` — Layout-preserving UTF-8 PDF text extraction via `pdftotext -layout` over `stdin`/`stdout` (zero temp files on disk).
- `browser-v1` — Advertised automatically when Chromium's OS process sandbox initializes cleanly (`sandbox: "on"`), or on Home Assistant OS when `allow_no_sandbox_browser: true` is enabled in add-on configuration.

## Defense-in-Depth Isolation

1. **Privilege Drop & Secret Lockdown:** At startup, `/data` (`0700`) and `/data/options.json` (`0600`) are locked to `root:root` via `O_NOFOLLOW` file descriptors before all Go runtime threads irreversibly drop to `65532:65532` with `PR_SET_NO_NEW_PRIVS=1` and `PR_SET_DUMPABLE=0`.
2. **Pre-Fetch & Pre-Render `robots.txt` Gate:** Every URL (and every `interact` `navigate` action on browser-capable workers) checks `/robots.txt` and per-host rate limits before dialing.
3. **Loopback SSRF Guard (`RejectNonPublicPeer` & `SSRFProxy`):** Both the Go HTTP/2 dialer and Chromium's `CONNECT` tunnel (`--proxy-server=http://127.0.0.1:<port>`, `--proxy-bypass-list=<-loopback>`, `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`, `--disable-quic`) enforce `politeness.RejectNonPublicPeer` so untrusted origins can never reach Home Assistant (`:8123`), RFC1918 LAN IPs, or cloud metadata endpoints.
4. **Anti-Challenge Stop:** If a page displays a CAPTCHA or anti-bot challenge, EdgeFetch halts immediately (`outcome: "challenge"`) and never attempts to solve, click through, or wait out challenges.
