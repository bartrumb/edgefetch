package ws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestDialTLSHTTP1UpgradeHeadersPingAndPeerCloseEOF(t *testing.T) {
	// Ensure ambient proxy env vars are ignored (`Proxy: nil`).
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	var gotProto, gotUA, gotAuth string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Proto
		gotUA = r.UserAgent()
		gotAuth = r.Header.Get("Authorization")

		sc, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer sc.CloseNow()

		typ, msg, err := sc.Read(r.Context())
		if err != nil {
			t.Errorf("server Read: %v", err)
			return
		}
		if typ != websocket.MessageText || string(msg) != "ping" {
			t.Errorf("expected text 'ping', got type=%v msg=%q", typ, msg)
			return
		}
		_ = sc.Write(r.Context(), websocket.MessageText, []byte("pong"))
		_ = sc.Close(websocket.StatusNormalClosure, "bye")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	clientTLS := srv.Client().Transport.(*http.Transport).TLSClientConfig
	conn, err := DialWithOptions(context.Background(), srv.URL+"/agent/ws", "EdgeFetchTest/1.0", map[string]string{
		"Authorization": "Bearer throwaway-test-token-0123456789",
	}, DialOptions{TLSConfig: clientTLS})
	if err != nil {
		t.Fatalf("DialWithOptions failed: %v", err)
	}
	defer conn.CloseNow()

	if gotProto != "HTTP/1.1" {
		t.Fatalf("expected HTTP/1.1 upgrade over h2-capable TLS server, got %q", gotProto)
	}
	if gotUA != "EdgeFetchTest/1.0" || gotAuth != "Bearer throwaway-test-token-0123456789" {
		t.Fatalf("unexpected headers: ua=%q auth=%q", gotUA, gotAuth)
	}

	if err := conn.WriteText("ping"); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	reply, err := conn.ReadText(2 * time.Second)
	if err != nil || reply != "pong" {
		t.Fatalf("ReadText = (%q, %v), want ('pong', nil)", reply, err)
	}

	// Peer StatusNormalClosure must normalize to io.EOF.
	if _, err := conn.ReadText(2 * time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on peer close, got %v", err)
	}
	_ = conn.CloseCleanly()
}

func TestRedirectDoesNotFollowOrLeakBearerToken(t *testing.T) {
	var leaked atomic.Bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusFound)
	}))
	defer hub.Close()

	_, err := Dial(context.Background(), strings.Replace(hub.URL, "http://", "ws://", 1)+"/agent/ws", "EdgeFetch/1.0", map[string]string{
		"Authorization": "Bearer secret-hub-token-do-not-leak",
	})
	if err == nil {
		t.Fatal("expected redirect handshake to fail")
	}
	if leaked.Load() {
		t.Fatal("Authorization token leaked across HTTP redirect")
	}
}

func TestReadLimit1MiBAndTimeoutBehavior(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer sc.CloseNow()

		switch r.URL.Query().Get("case") {
		case "oversized":
			big := bytes.Repeat([]byte("x"), MaxMessageBytes+64)
			_ = sc.Write(r.Context(), websocket.MessageText, big)
		case "custom":
			big := bytes.Repeat([]byte("y"), MaxMessageBytes+64)
			_ = sc.Write(r.Context(), websocket.MessageText, big)
		case "hang":
			<-r.Context().Done()
		}
	}))
	defer srv.Close()

	// 1. Default 1 MiB cap rejects > 1 MiB messages (and proves library 32 KiB default was raised).
	c1, err := Dial(context.Background(), srv.URL+"?case=oversized", "", nil)
	if err != nil {
		t.Fatalf("Dial c1: %v", err)
	}
	defer c1.CloseNow()
	if _, err := c1.ReadText(2 * time.Second); err == nil {
		t.Fatal("expected > 1 MiB frame to fail default MaxMessageBytes limit")
	}

	// 2. SetReadLimit allows larger messages when explicitly raised.
	c2, err := Dial(context.Background(), srv.URL+"?case=custom", "", nil)
	if err != nil {
		t.Fatalf("Dial c2: %v", err)
	}
	defer c2.CloseNow()
	c2.SetReadLimit(2 << 20)
	got, err := c2.ReadText(2 * time.Second)
	if err != nil || len(got) != MaxMessageBytes+64 {
		t.Fatalf("expected custom SetReadLimit read to succeed, got len=%d err=%v", len(got), err)
	}

	// 3. Read timeout returns non-nil error.
	c3, err := Dial(context.Background(), srv.URL+"?case=hang", "", nil)
	if err != nil {
		t.Fatalf("Dial c3: %v", err)
	}
	defer c3.CloseNow()
	if _, err := c3.ReadText(35 * time.Millisecond); err == nil {
		t.Fatal("expected ReadText timeout error")
	}

	// 4. Invalid scheme rejected immediately.
	if _, err := Dial(context.Background(), "ftp://example.com/ws", "", nil); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
	if _, err := Dial(context.Background(), "://bad-url", "", nil); err == nil {
		t.Fatal("expected parse error")
	}
}
