package main

import (
	"net/http"
	"testing"
	"time"
)

func TestValidateServerSecurity(t *testing.T) {
	// Non-loopback without token or explicit opt-in must fail closed.
	if err := validateServerSecurity(":8080", "", false); err == nil {
		t.Fatal("SECURITY: expected unauthenticated :8080 bind to fail closed")
	}
	if err := validateServerSecurity("0.0.0.0:8080", "", false); err == nil {
		t.Fatal("SECURITY: expected unauthenticated 0.0.0.0:8080 bind to fail closed")
	}
	// Short token (< 24 chars) must fail closed even on loopback.
	if err := validateServerSecurity("127.0.0.1:8080", "too-short", false); err == nil {
		t.Fatal("SECURITY: expected < 24 char server token to be rejected")
	}
	// Strong token (>= 24 chars) on 0.0.0.0:8080 is allowed.
	if err := validateServerSecurity(":8080", "0123456789abcdef0123456789abcdef", false); err != nil {
		t.Fatalf("expected strong token accepted: %v", err)
	}
	// Strict loopback bind without token is allowed for local development.
	if err := validateServerSecurity("127.0.0.1:8080", "", false); err != nil {
		t.Fatalf("expected loopback 127.0.0.1:8080 accepted: %v", err)
	}
	if err := validateServerSecurity("[::1]:8080", "", false); err != nil {
		t.Fatalf("expected loopback [::1]:8080 accepted: %v", err)
	}
	// Explicit isolated-bridge opt-in (--allow-unauthenticated) is allowed.
	if err := validateServerSecurity(":8080", "", true); err != nil {
		t.Fatalf("expected explicit allowUnauthenticated accepted: %v", err)
	}
}

func TestNewHTTPServerTimeouts(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:8080", http.NotFoundHandler())
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("expected ReadHeaderTimeout=10s, got %s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 30*time.Second {
		t.Fatalf("expected ReadTimeout=30s, got %s", srv.ReadTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Fatalf("expected IdleTimeout=120s, got %s", srv.IdleTimeout)
	}
}
