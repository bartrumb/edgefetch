package browser

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/politeness"
)

// SSRFProxy is a loopback-only HTTP CONNECT tunnel (`127.0.0.1:0`) paired with Chromium's
// `--proxy-server` + `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"` flags.
//
// Why this matters on Home Assistant OS:
// Untrusted JavaScript executing inside a headless browser can call `fetch("http://192.168.1.1/...")`, open WebSockets,
// or trigger DNS-rebinding subresources. By disabling Chromium's own DNS resolver (`MAP * ~NOTFOUND`) and forcing all
// connections through `SSRFProxy`, every subresource TCP dial passes through both `allow(*url.URL)` and
// `politeness.RejectNonPublicPeer` BEFORE the TCP SYN leaves the kernel.
type SSRFProxy struct {
	ln     net.Listener
	srv    *http.Server
	allow  func(*url.URL) error
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	closed sync.Once
}

// NewSSRFProxy starts a loopback CONNECT proxy enforcing `allow` and `politeness.RejectNonPublicPeer` on every tunnel.
func NewSSRFProxy(allow func(*url.URL) error, customDial func(ctx context.Context, network, addr string) (net.Conn, error)) (*SSRFProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen ssrf proxy: %w", err)
	}
	dialFn := customDial
	if dialFn == nil {
		d := &net.Dialer{
			Timeout:   12 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   politeness.RejectNonPublicPeer,
		}
		dialFn = d.DialContext
	}

	p := &SSRFProxy{
		ln:    ln,
		allow: allow,
		dial:  dialFn,
	}
	p.srv = &http.Server{
		Handler:           http.HandlerFunc(p.serveHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = p.srv.Serve(ln)
	}()
	return p, nil
}

// Addr returns `127.0.0.1:<port>` suitable for `--proxy-server=http://<Addr()>`.
func (p *SSRFProxy) Addr() string {
	return p.ln.Addr().String()
}

// Close shuts down the loopback proxy listener.
func (p *SSRFProxy) Close() error {
	var err error
	p.closed.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = p.srv.Shutdown(ctx)
		_ = p.ln.Close()
	})
	return err
}

func (p *SSRFProxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// Reject plain-HTTP proxy requests (`GET http://192.168.1.1/`): only TLS `CONNECT host:443` tunnels are permitted.
	if r.Method != http.MethodConnect {
		http.Error(w, "only HTTPS CONNECT tunnels are permitted", http.StatusForbidden)
		return
	}

	host, port, err := net.SplitHostPort(strings.TrimSpace(r.Host))
	if err != nil || host == "" || port == "" {
		http.Error(w, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}

	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
		Path:   "/",
	}
	if port == "443" {
		u.Host = host
	}
	if p.allow != nil {
		if err := p.allow(u); err != nil {
			http.Error(w, "blocked by SSRF policy: "+err.Error(), http.StatusForbidden)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	upstream, err := p.dial(ctx, "tcp", net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		http.Error(w, "upstream dial rejected: "+err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		buffered := make([]byte, clientBuf.Reader.Buffered())
		n, _ := clientBuf.Read(buffered)
		if n > 0 {
			_, _ = upstream.Write(buffered[:n])
		}
	}

	_ = clientConn.SetDeadline(time.Now().Add(90 * time.Second))
	_ = upstream.SetDeadline(time.Now().Add(90 * time.Second))

	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go pump(upstream, clientConn)
	go pump(clientConn, upstream)
	wg.Wait()
	_ = clientConn.Close()
	_ = upstream.Close()
}

// ErrBrowserUnavailable indicates no headless Chromium binary is installed in the current runtime (e.g. distroless Lite).
var ErrBrowserUnavailable = errors.New("headless Chromium is not installed on this node (deploy edgefetch_fat to enable browser rendering)")
