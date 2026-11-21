// Package browser drives a headless Chromium process over the Chrome DevTools Protocol (CDP)
// while forcing every subresource TCP socket through an in-process SSRF-guarded loopback CONNECT proxy.
//
// # OS Process Sandbox & Container Fallback
//
// Chromium's native OS process sandbox (AppContainer/Restricted Token on Windows, Seatbelt on macOS, and
// user/PID/network namespaces + seccomp-bpf on Linux) is enabled by default. On Linux, [Renderer.ProbeStartup]
// and `ensureBrowser` probe native sandbox support first and automatically fall back to container-isolated flags
// when container MAC profiles (such as AppArmor `edgefetch_fat`), `NO_NEW_PRIVS`, or restricted user namespaces
// block unprivileged namespace creation — unless `EDGEFETCH_REQUIRE_BROWSER_SANDBOX=1` is set, in which case
// browser rendering fails closed (`Available() == false`). Active browser version and sandbox state (`"on"`,
// `"off"`, or `"unknown"`) are reported via [Renderer.BrowserInfo].
//
// # SSRF Isolation Model
//
// Untrusted JavaScript executing inside a headless browser can attempt `fetch("http://192.168.1.1/")`,
// cloud-metadata probes (`169.254.169.254`), or DNS-rebinding subresource loads. EdgeFetch launches Chromium
// with `--proxy-server=http://127.0.0.1:<port>`, `--proxy-bypass-list=<-loopback>`, and
// `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`, disabling Chromium's internal DNS resolver so
// every socket traverses [SSRFProxy]:
//
//  1. Plain-HTTP proxy requests (`GET http://...`) are rejected with `403 Forbidden`; only `CONNECT host:443`
//     tunnels are permitted.
//  2. Target authorities are validated against the caller's URL allowlist (blocking recursive coordination-hub
//     fetches, non-443 ports, and IP literals).
//  3. Outbound TCP dials attach `politeness.RejectNonPublicPeer` (`net.Dialer.Control`) so DNS-rebinding targets
//     resolving to RFC 1918, loopback, link-local, CGNAT, NAT64, or IPv6 transition prefixes abort before SYN.
//  4. Rendered DOMs are checked via `extract.DetectRenderedChallenge`; anti-bot/CAPTCHA challenges halt
//     immediately with [ErrChallengeDetected] and are never clicked through or waited out.
package browser
