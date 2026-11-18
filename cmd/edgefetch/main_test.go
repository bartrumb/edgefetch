package main

import "testing"

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
