// Package hubstore implements the pure-Go storage, search, and tracker-list
// subsystem for the self-contained EdgeFetch Hub (`edgefetch --hub`).
//
// It provides:
//   - Store: atomic disk-backed or bounded in-memory gzip blob storage,
//     sanitized Markdown slice-paged artifacts, ETag/304 scrape response cache,
//     per-host WAF/adapter gap telemetry, tenant-isolated async job state,
//     hub settings, and bounded operational events.
//   - CollectionIndex: multi-tenant BM25 inverted search index over chunked
//     Markdown documents with prefix-match fallback.
//   - ExecuteWebSearch: Reciprocal Rank Fusion (RRF, k=60) search across local
//     collections and external JSON APIs (SearXNG, Serper, Brave, Tavily) with
//     secret-free OTLP child spans.
//   - TrackerManager: zero-startup-fetch EasyPrivacy third-party tracker list
//     validator, background refresher, and WebSocket frame builder.
package hubstore

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultMaxMemBytes      = 64 << 20
	MaxArtifactContentBytes = 16 << 20
	MaxArtifactStoredBytes  = 18 << 20
	DefaultArtifactPageSize = 65536
	MaxArtifactPageSize     = 1 << 20
	MaxScrapeCacheEntries   = 2048
	MaxTrackedHostRecords   = 4096
	MaxRetainedEvents       = 500
)

var (
	ErrInvalidSHA256       = errors.New("hubstore: invalid sha256 hex digest")
	ErrBlobDigestMismatch  = errors.New("hubstore: compressed blob sha256 mismatch")
	ErrContentHashMismatch = errors.New("hubstore: uncompressed content sha256 mismatch")
	ErrBlobTooLarge        = errors.New("hubstore: blob exceeds byte limit")
	ErrCorruptGzip         = errors.New("hubstore: corrupt gzip payload")
)

func nonNilMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return make(map[K]V)
	}
	return m
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	b, _ := json.Marshal(in)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return nonNilMap(out)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func isValidSHA256Hex(raw string) bool {
	_, err := hex.DecodeString(raw)
	return len(raw) == 64 && strings.ToLower(raw) == raw && err == nil
}

func sanitizeIdentifier(raw, fallback string, maxLen int) string {
	var sb strings.Builder
	for i, s := 0, strings.TrimSpace(raw); i < len(s) && sb.Len() < maxLen; i++ {
		if c := s[i]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' || c == '-' {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('_')
		}
	}
	if out := sb.String(); out != "" && out != "." && out != ".." {
		return out
	}
	return fallback
}

func atomicWriteFile(destPath string, data []byte) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_ = f.Chmod(0o600)
	_, wErr := f.Write(data)
	if err := errors.Join(wErr, f.Sync(), f.Close()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if os.Rename(tmp, destPath) != nil {
		_ = os.Remove(destPath)
		if err := os.Rename(tmp, destPath); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}

func gzipCompressBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, wErr := zw.Write(raw)
	if err := errors.Join(wErr, zw.Close()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzipCapped(gzBytes []byte, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxArtifactContentBytes
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		return nil, ErrCorruptGzip
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, int64(maxBytes)+1))
	if err != nil {
		return nil, ErrCorruptGzip
	}
	if len(out) > maxBytes {
		return nil, ErrBlobTooLarge
	}
	return out, nil
}
