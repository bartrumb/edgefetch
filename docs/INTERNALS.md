# EdgeFetch Go Internals & Concurrency Guide

This guide walks through how EdgeFetch works under the hood — written both as an architectural reference and as a practical tour of idiomatic Go systems patterns (goroutines, channel locks, zero-allocation string scanning, `net/http/httptrace`, WebSocket transport hardening, and Linux syscalls).

---

## 1. Mental Model for Engineers Coming from TypeScript / Node.js / Python

| Concept | Event-Loop Languages (TS / Python) | Go (`edgefetch`) | Why It Matters Here |
|---|---|---|---|
| **Package Compilation** | File-by-file module imports | Every `.go` file in a directory shares one `package` namespace | `internal/*` enforces strict compiler-checked encapsulation (`internal/` packages cannot be imported outside this module). |
| **Visibility** | `export` keyword | **Uppercase** (`NewCrawler`, `IsPublicIP`) = exported; **lowercase** (`robotsMatch`) = package-private | Every call site shows at a glance whether a symbol crosses package boundaries. |
| **Zero Values** | `undefined` / `None` | Every type has a deterministic zeroed memory layout (`0`, `""`, `false`, `nil`, unlocked `sync.Mutex`) | `crawl.Options{}` is immediately valid and normalized by a value receiver `(o Options) Normalize()`. |
| **Values vs. Pointers** | Heap references everywhere | Structs copy by value unless passed as `*T` | Value copies prevent accidental shared-state mutation; `*Crawler` pointers signal `sync.Mutex` ownership (`go vet` flags mutex copies!). |
| **Concurrency** | Single-threaded `async`/`await` | Preemptive M:N goroutines (~2 KiB initial stack) + typed `chan` + `sync.Mutex` | Sequential blocking code scales across cores without callback chains, guarded by Go's ThreadSanitizer (`go test -race`). |

---

## 2. Context-Cancellable Per-Host Locks (`chan struct{}` vs `sync.Mutex`)

In [`internal/politeness/politeness.go`](../internal/politeness/politeness.go), `HostState` uses **both** `inFlight chan struct{}` (capacity `1`) and `mu sync.Mutex`:

- **`sync.Mutex.Lock()` cannot be cancelled by a `context.Context`!** If goroutine A is waiting 25 seconds on a slow origin and goroutine B arrives for the same host with a 3-second request timeout, `mu.Lock()` would stall goroutine B for all 25 seconds.
- A 1-element buffered channel of zero-byte empty structs (`make(chan struct{}, 1)`) acts as a **context-aware mutex**:
  ```go
  func (h *HostState) Acquire(ctx context.Context) error {
      select {
      case h.inFlight <- struct{}{}:
          return nil
      case <-ctx.Done():
          return ctx.Err()
      }
  }
  ```
- Meanwhile, `mu sync.Mutex` protects sub-microsecond reads/writes to `nextAllowed`, `consecutiveErrors`, and `robots` where blocking never occurs.

---

## 3. Zero-Allocation `robots.txt` Wildcard Matching (`0 B/op`, `0 allocs/op`)

Standard regex engines risk catastrophic backtracking on adversarial `/robots.txt` patterns, while `strings.Split(pattern, "*")` allocates a new `[]string` slice on the heap on every call.

In `politeness.go`, `robotsMatch` walks `*`-delimited segments iteratively with `strings.Cut(rem, "*")` — which slices into the existing immutable `pattern` string header `(ptr, len)` on the stack, achieving **`52 ns/op` and `0 allocs/op`**.

---

## 4. Lock-Free Disjoint Slice Indexing & `io.LimitReader(maxBytes + 1)`

In [`internal/crawl/crawl.go`](../internal/crawl/crawl.go):

1. **Race-free result assembly:** `results := make([]Result, len(reqs))` pre-allocates the exact output slice before spawning host goroutines. Because request indices are grouped by hostname (`byHost[host]`), two goroutines **never** write to the same index `results[i]` — verified race-free by `go test -race` without lock contention.
2. **Exact truncation detection + HTTP/2 socket reuse:** Wrapping `resp.Body` in `io.LimitReader(resp.Body, int64(opts.MaxBytes)+1)` reads at most 1 byte past the cap:
   - Normal responses (`<= MaxBytes`) read through `EOF`, allowing `net/http` to return the underlying TLS/HTTP2 stream cleanly to its idle pool (`Timing.Reused = true`, `0 ms` DNS/TCP/TLS on the next page).
   - Oversized responses (`== MaxBytes + 1`) are flagged `Truncated: true` and sliced back without ever buffering unbounded gigabytes in RAM.

---

## 5. Why `net.Dialer.Control` Beats Pre-Dial `net.LookupIP` Against SSRF

Checking `net.LookupIP(hostname)` *before* calling `http.Client.Do(req)` has two classic flaws:
1. **DNS-rebinding TOCTOU race:** An attacker's authoritative DNS server with `TTL=0` can return `93.184.216.34` on the check lookup and `192.168.1.1` milliseconds later when `http.Transport` dials.
2. **Broken Happy Eyeballs & `httptrace`:** Rewriting URLs to raw IP literals breaks TLS SNI, `Host` headers, IPv6->IPv4 fallback, and `DNSMs` tracing.

Hooking `net.Dialer.Control` (`RejectNonPublicPeer`) runs inside Go's dialer *after* DNS resolution creates the socket descriptor and *immediately before* the kernel `connect()` syscall executes — inspecting the exact `IP:port` tuple (`127.0.0.1`, RFC 1918, Tailscale `100.64/10`, link-local, or NAT64/6to4 IPv6 transition prefixes) with zero race window.

---

## 6. Hardened `coder/websocket` Client & Linux Privilege Drop

- **TLS ALPN Pinning ([`internal/ws/client.go`](../internal/ws/client.go)):** `tlsCfg.NextProtos = []string{"http/1.1"}` ensures Cloudflare's edge negotiates HTTP/1.1 for the `101 Switching Protocols` upgrade (whereas `newHubTransport()` negotiates `h2` for multiplexed `POST /agent/reply` gzip uploads).
- **Classic ECDHE Curves (`X25519`, `P-256`, `P-384`):** Go 1.23+ enables `X25519MLKEM768` post-quantum hybrid key shares by default, enlarging TLS `ClientHello` beyond single-packet PPPoE / VM bridge MTUs where middleboxes can stall handshakes. Pinning classic curves keeps handshakes single-packet and fast across residential links.
- **Linux Privilege Drop ([`internal/priv/priv_linux.go`](../internal/priv/priv_linux.go)):** Home Assistant OS Supervisor mounts `/data/options.json` as `0600 root:root`. Reading config first, zeroing the raw byte slice, setting `prctl(PR_SET_NO_NEW_PRIVS, 1)`, clearing supplementary groups, and calling `syscall.Setgid(65532)` + `syscall.Setuid(65532)` transitions every OS thread in the Go runtime (`AllThreadsSyscall` since Go 1.16) to `nonroot` before a single network socket opens — keeping the final container image a shell-free ~9 MB `distroless` binary.
