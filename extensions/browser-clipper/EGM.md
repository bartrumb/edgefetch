# EdgeFetch Browser Clipper & Residential Node (`extensions/browser-clipper`)

## Overview

Implements a Chrome/Edge Manifest V3 browser extension (`v2.5.3`) with two roles: (1) an interactive tab clipper (`popup.html` / `popup.js`) that captures the active tab's rendered DOM and submits it to an EdgeFetch Hub's `/v1/ingest-tab` endpoint, and (2) an opt-in residential outbound worker node (`service-worker.js` + `offscreen.html` / `offscreen.js`) that maintains a persistent WebSocket connection to `/agent/ws`, executes SSRF-guarded unauthenticated HTTPS `GET` dispatches, and posts bounded response payloads to `/agent/reply`.

## Interface

- `[manifest.json:manifest_version]`: Manifest V3 extension (`version: "2.5.3"`) declaring `permissions` (`["activeTab", "scripting", "storage", "offscreen"]`), `host_permissions` (`["http://127.0.0.1/*", "http://localhost/*"]`), `optional_host_permissions` (`["https://*/*"]`), `action.default_popup` (`"popup.html"`), and module background worker `"service-worker.js"`.
- `[service-worker.js:ensureOffscreenDocument]`: Ensures a single Chrome MV3 offscreen document exists at `"offscreen.html"` with reason `["WORKERS"]`.
- `[service-worker.js:syncOffscreenState]`: Reconciles offscreen document lifecycle and node connection state from `{ nodeEnabled, hubUrl, agentToken }`.
- `[service-worker.js:chrome.runtime.onMessage]`: Handles `{ type: "SYNC_NODE_CONFIG", cfg }` (returning `{ connected: boolean }`) and `{ type: "NODE_STATUS_CHANGED", connected }` runtime messages.
- `[offscreen.js:chrome.runtime.onMessage]`: Handles `{ type: "OFFSCREEN_CONNECT", cfg }` and `{ type: "OFFSCREEN_DISCONNECT" }` control messages inside `offscreen.html`.
- `[offscreen.js:connect]` / `[offscreen.js:disconnect]`: Opens and tears down the outbound WebSocket to `ws(s)://<hub>/agent/ws` (sending initial handshake frame `{ type: "agent_hello", version: "2.5.3", arch: "browser-mv3", goVersion: "mv3-extension", capabilities: [], reconnectAttempt: 0 }`), sends `"ping"` every 25s, ignores `"pong"`, and routes `{ type: "dispatch", jobId, nonce, payload }` frames.
- `[offscreen.js:executeDispatchedJob]`: Executes dispatched URL fetches and posts `{ results }` to `<hubUrl>/agent/reply` with headers `authorization: Bearer <agentToken>`, `x-agent-site: <siteId || "browser-ext-1">`, `x-job-id`, and `x-job-nonce`.
- `[offscreen.js:isSafePublicExtensionUrl]` / `[offscreen.js:readStreamTextBounded]`: Enforces public HTTPS URL validation and bounded stream consumption (`{ text, bytes, truncated }`).
- `[popup.js:loadSettings]` / `[popup.js:saveSettings]` / `[popup.js:updateBadge]` / `[popup.js:showStatus]`: Manages popup configuration UI (`popup.html`), persists `hubUrl`, `callerToken`, `collectionId`, `agentToken`, `siteId`, and `nodeEnabled` to `chrome.storage.local`, and triggers `{ type: "SYNC_NODE_CONFIG", cfg }`.
- `[popup.js:els.clipBtn]`: Captures `{ url, title, html }` from the active tab via `chrome.scripting.executeScript` and `POST`s `{ url, title, html, collectionId }` to `<hubUrl>/v1/ingest-tab`.

## Invariants

- `[service-worker.js:syncOffscreenState]`: Whenever `!cfg.nodeEnabled || !cfg.hubUrl || !cfg.agentToken`, any active offscreen connection is disconnected, the offscreen document is closed, and `chrome.storage.local.nodeConnected` is set to `false`.
- `[offscreen.js:isSafePublicExtensionUrl]`: Every dispatched URL and redirect hop must use `https:`, empty URL credentials (`username` and `password`), empty port or `"443"`, hostname length `<= 253` containing `.` with no `:`, `[`, or `]` (rejecting IPv6 literals), valid non-empty DNS labels without leading/trailing `-`, and a non-numeric/non-hex TLD (rejecting IPv4 dotted/octal/hex/integer literals).
- `[offscreen.js:DISALLOWED_EXACT_HOSTS]` / `[offscreen.js:DISALLOWED_HOST_SUFFIXES]`: Dispatched fetches block `cfg.hubUrl`'s own `selfHost`, cloud metadata/loopback/rebinding hosts (`localhost`, `metadata.goog`, `metadata.google.internal`, `instance-data.ec2.internal`, `nip.io`, `sslip.io`, `xip.io`, `localtest.me`, `lvh.me`, `vcap.me`, `traefik.me`, `1u.ms`, `rebind.network`), and suffixes (`.localhost`, `.local`, `.internal`, `.arpa`, `.intranet`, `.corp`, `.lan`, plus DNS-rebinding suffixes).
- `[offscreen.js:MAX_EXT_REDIRECTS]` / `[offscreen.js:executeDispatchedJob]`: Dispatched fetches run with `credentials: "omit"`, `redirect: "manual"`, and `AbortSignal.timeout(25000)`, permitting at most `5` manually re-validated redirect hops and failing closed on `opaqueredirect` or missing `Location` headers.
- `[offscreen.js:MAX_EXT_BODY_BYTES]` / `[offscreen.js:readStreamTextBounded]`: Response streams are capped at `4 * 1024 * 1024` bytes (4 MiB); responses exceeding the cap cancel the stream and report `outcome: "error"`, `truncated: true`, and `body: ""`.
- `[offscreen.js:executeDispatchedJob]`: Replies to `<hubUrl>/agent/reply` enforce `redirect: "error"` and execute only for frames carrying `frame.type === "dispatch"`, `frame.jobId`, and `frame.nonce`.

## Side Effects

- `[service-worker.js:ensureOffscreenDocument]` / `[service-worker.js:syncOffscreenState]`: Creates and closes Chrome MV3 offscreen documents via `chrome.offscreen.createDocument` and `chrome.offscreen.closeDocument`.
- `[popup.js:saveSettings]` / `[service-worker.js:chrome.runtime.onMessage]`: Reads and writes extension settings (`hubUrl`, `callerToken`, `collectionId`, `agentToken`, `siteId`, `nodeEnabled`) and `nodeConnected` status in `chrome.storage.local`.
- `[offscreen.js:connect]`: Maintains a long-lived outbound WebSocket connection to `ws(s)://<hub>/agent/ws` with a 25-second `setInterval` keepalive timer and mutates module-scoped `ws`, `pingTimer`, and `activeCfg`.
- `[offscreen.js:executeDispatchedJob]`: Issues unauthenticated (`credentials: "omit"`) HTTPS `GET` requests to public web targets and authenticated `POST` requests to `<hubUrl>/agent/reply`.
- `[popup.js:els.clipBtn]`: Injects a DOM snapshot function into the active browser tab via `chrome.scripting.executeScript` and sends an HTTP(S) `POST` request to `<hubUrl>/v1/ingest-tab`.

## Verification

- Run: `npm --prefix hub test`
