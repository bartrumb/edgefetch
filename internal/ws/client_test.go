package ws

import (
	"bytes"
	"testing"
)

func TestComputeAcceptRFC6455Vector(t *testing.T) {
	// Official test vector from RFC 6455 Section 1.3.
	const rfcKey = "dGhlIHNhbXBsZSBub25jZQ=="
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := ComputeAccept(rfcKey); got != want {
		t.Fatalf("ComputeAccept(%q) = %q, want %q", rfcKey, got, want)
	}
}

func TestMaskBytesRoundTrip(t *testing.T) {
	orig := []byte(`{"type":"dispatch","jobId":"12345"}`)
	buf := append([]byte(nil), orig...)
	mask := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	MaskBytes(buf, mask)
	if bytes.Equal(buf, orig) {
		t.Fatal("expected masked payload to differ from plaintext")
	}
	MaskBytes(buf, mask)
	if !bytes.Equal(buf, orig) {
		t.Fatalf("double XOR failed to restore original bytes: %q", buf)
	}
}

func BenchmarkMaskBytes1KiB(b *testing.B) {
	payload := bytes.Repeat([]byte("a"), 1024)
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MaskBytes(payload, mask)
	}
}
