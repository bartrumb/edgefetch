package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
	"github.com/bartrumb/edgefetch/v2/internal/crawl"
)

// ReleaseSigningPublicKeyPEM is the pinned Ed25519 SPKI public key (`keys/release-signing-pub.pem`)
// used to cryptographically verify `checksums.txt.sig` before any release archive is trusted.
const ReleaseSigningPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAv8+ZT9d/404KI0pY1PILOVBzsUvTHWaL0aLghciWy90=
-----END PUBLIC KEY-----`

const (
	defaultGitHubAPIBaseURL      = "https://api.github.com"
	defaultGitHubDownloadBaseURL = "https://github.com"
	githubReleaseRepo            = "bartrumb/edgefetch"
	maxReleaseJSONBytes          = 256 << 10 // 256 KiB
	maxChecksumsBytes            = 1 << 20   // 1 MiB
	maxSignatureBytes            = 4 << 10   // 4 KiB
	maxArchiveDownloadBytes      = 128 << 20 // 128 MiB
	maxExtractedBinaryBytes      = 128 << 20 // 128 MiB
)

var (
	reReleaseTag        = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z._-]+))?$`)
	reSHA256Hex         = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	ErrBadSignature     = errors.New("ed25519 signature verification failed for checksums.txt")
	ErrBadArchiveSHA    = errors.New("archive SHA-256 mismatch against verified checksums.txt")
	ErrDowngradeRefused = errors.New("refusing version downgrade without --allow-downgrade")
)

type updateDeps struct {
	httpClient      *http.Client
	allow           func(*url.URL) error
	apiBaseURL      string
	downloadBaseURL string
	publicKeyPEM    string
	currentVersion  string
	exePath         string
	goos            string
	goarch          string
}

// ParseEd25519PublicKeyPEM parses a PKIX PEM-encoded Ed25519 public key using Go stdlib `encoding/pem` + `crypto/x509`.
func ParseEd25519PublicKeyPEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid PEM public key block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("public key is not a valid 32-byte Ed25519 key")
	}
	return pub, nil
}

// VerifyChecksumsSignature verifies `checksums.txt.sig` over `checksums.txt` using `crypto/ed25519.Verify`.
func VerifyChecksumsSignature(pubKey ed25519.PublicKey, checksums, rawSig []byte) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key length")
	}
	if len(checksums) == 0 {
		return errors.New("empty checksums.txt")
	}
	sig := rawSig
	if len(sig) != ed25519.SignatureSize {
		trimmed := strings.TrimSpace(string(rawSig))
		if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.SignatureSize {
			sig = decoded
		} else {
			return fmt.Errorf("%w: invalid signature byte length %d", ErrBadSignature, len(rawSig))
		}
	}
	if !ed25519.Verify(pubKey, checksums, sig) {
		return ErrBadSignature
	}
	return nil
}

// LookupArchiveSHA256 extracts the expected 64-hex SHA-256 digest for `archiveName` from a verified `checksums.txt`.
func LookupArchiveSHA256(checksums []byte, archiveName string) (string, error) {
	want := strings.TrimSpace(archiveName)
	if want == "" {
		return "", errors.New("empty archive filename")
	}
	for _, rawLine := range strings.Split(strings.ReplaceAll(string(checksums), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		digest := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[1], "*")
		name = path.Base(strings.ReplaceAll(name, "\\", "/"))
		if name == want {
			if !reSHA256Hex.MatchString(digest) {
				return "", fmt.Errorf("malformed SHA-256 digest in checksums.txt for %s", want)
			}
			return digest, nil
		}
	}
	return "", fmt.Errorf("archive %q not found in verified checksums.txt", want)
}

// VerifyBytesSHA256 verifies that `SHA-256(data)` matches `expectedHex` in constant time.
func VerifyBytesSHA256(data []byte, expectedHex string) error {
	cleanExpected := strings.ToLower(strings.TrimSpace(expectedHex))
	if !reSHA256Hex.MatchString(cleanExpected) {
		return errors.New("invalid expected SHA-256 hex digest")
	}
	sum := sha256.Sum256(data)
	gotHex := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(gotHex), []byte(cleanExpected)) != 1 {
		return fmt.Errorf("%w: got %s, want %s", ErrBadArchiveSHA, gotHex, cleanExpected)
	}
	return nil
}

func normalizeReleaseTag(raw string) (tag string, verNoV string, err error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", "", errors.New("empty version string")
	}
	if !strings.HasPrefix(clean, "v") {
		clean = "v" + clean
	}
	if !reReleaseTag.MatchString(clean) {
		return "", "", fmt.Errorf("invalid semantic version tag %q", raw)
	}
	return clean, strings.TrimPrefix(clean, "v"), nil
}

func compareSemverTags(a, b string) int {
	ma := reReleaseTag.FindStringSubmatch(strings.TrimSpace(ensureVPrefix(a)))
	mb := reReleaseTag.FindStringSubmatch(strings.TrimSpace(ensureVPrefix(b)))
	if len(ma) < 5 || len(mb) < 5 {
		if a == b {
			return 0
		}
		return strings.Compare(a, b)
	}
	for i := 1; i <= 3; i++ {
		na, _ := strconv.Atoi(ma[i])
		nb, _ := strconv.Atoi(mb[i])
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
	}
	preA, preB := ma[4], mb[4]
	if preA == preB {
		return 0
	}
	// Stable release > prerelease (`v2.7.0` > `v2.7.0-rc.1`)
	if preA == "" {
		return 1
	}
	if preB == "" {
		return -1
	}
	return strings.Compare(preA, preB)
}

func ensureVPrefix(v string) string {
	t := strings.TrimSpace(v)
	if t == "" {
		return ""
	}
	if strings.HasPrefix(t, "v") {
		return t
	}
	return "v" + t
}

func releaseArchiveFilename(verNoV, goos, goarch string) string {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("edgefetch_%s_%s_%s.%s", verNoV, goos, goarch, ext)
}

func expectedBinaryBasename(goos string) string {
	if goos == "windows" {
		return "edgefetch.exe"
	}
	return "edgefetch"
}

// ExtractBinaryFromArchive extracts the `edgefetch` (or `edgefetch.exe`) executable from a `.tar.gz` or `.zip` release archive.
func ExtractBinaryFromArchive(archiveBytes []byte, archiveName, goos string) ([]byte, error) {
	wantBin := expectedBinaryBasename(goos)
	lowerName := strings.ToLower(archiveName)
	switch {
	case strings.HasSuffix(lowerName, ".zip"):
		return extractFromZip(archiveBytes, wantBin)
	case strings.HasSuffix(lowerName, ".tar.gz") || strings.HasSuffix(lowerName, ".tgz"):
		return extractFromTarGz(archiveBytes, wantBin)
	default:
		return nil, fmt.Errorf("unsupported archive format %q", archiveName)
	}
}

func isSafeArchiveEntryPath(entryName, wantBin string) bool {
	norm := strings.ReplaceAll(strings.TrimSpace(entryName), "\\", "/")
	if norm == "" || strings.HasPrefix(norm, "/") || strings.Contains(norm, "..") {
		return false
	}
	cleaned := path.Clean(norm)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return false
	}
	return path.Base(cleaned) == wantBin
}

func extractFromTarGz(archiveBytes []byte, wantBin string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !isSafeArchiveEntryPath(hdr.Name, wantBin) {
			continue
		}
		if hdr.Size <= 0 || hdr.Size > maxExtractedBinaryBytes {
			return nil, fmt.Errorf("refusing extracted binary size %d bytes", hdr.Size)
		}
		data, rErr := io.ReadAll(io.LimitReader(tr, maxExtractedBinaryBytes+1))
		if rErr != nil {
			return nil, fmt.Errorf("read binary from tar.gz: %w", rErr)
		}
		if len(data) == 0 || len(data) > maxExtractedBinaryBytes {
			return nil, errors.New("extracted binary exceeded size limit")
		}
		return data, nil
	}
	return nil, fmt.Errorf("binary %q not found in tar.gz archive", wantBin)
}

func extractFromZip(archiveBytes []byte, wantBin string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
	if err != nil {
		return nil, fmt.Errorf("open zip archive: %w", err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || (f.Mode()&os.ModeSymlink) != 0 {
			continue
		}
		if !isSafeArchiveEntryPath(f.Name, wantBin) {
			continue
		}
		if f.UncompressedSize64 == 0 || f.UncompressedSize64 > maxExtractedBinaryBytes {
			return nil, fmt.Errorf("refusing extracted zip binary size %d bytes", f.UncompressedSize64)
		}
		rc, oErr := f.Open()
		if oErr != nil {
			return nil, fmt.Errorf("open zip entry: %w", oErr)
		}
		data, rErr := io.ReadAll(io.LimitReader(rc, maxExtractedBinaryBytes+1))
		_ = rc.Close()
		if rErr != nil {
			return nil, fmt.Errorf("read zip entry: %w", rErr)
		}
		if len(data) == 0 || len(data) > maxExtractedBinaryBytes {
			return nil, errors.New("extracted zip binary exceeded size limit")
		}
		return data, nil
	}
	return nil, fmt.Errorf("binary %q not found in zip archive", wantBin)
}

// RecoverInterruptedUpdate heals an interrupted Windows two-step rename (`exe -> exe.old`, crash before `tmp -> exe`)
// when `exePath` is missing and a regular `exePath + ".old"` backup exists, and cleans up stale `.old` files once
// `exePath` is healthy.
func RecoverInterruptedUpdate(exePath string) error {
	trimmed := strings.TrimSpace(exePath)
	if trimmed == "" {
		return nil
	}
	targetPath := filepath.Clean(trimmed)
	if resolved, err := filepath.EvalSymlinks(trimmed); err == nil && strings.TrimSpace(resolved) != "" {
		targetPath = filepath.Clean(resolved)
	}
	oldPath := targetPath + ".old"
	oldInfo, oldErr := os.Lstat(oldPath)
	if oldErr != nil {
		return nil
	}
	if !oldInfo.Mode().IsRegular() {
		return nil
	}
	if _, tgtErr := os.Stat(targetPath); errors.Is(tgtErr, os.ErrNotExist) {
		if err := os.Rename(oldPath, targetPath); err != nil {
			return fmt.Errorf("restore %s from %s: %w", targetPath, oldPath, err)
		}
		return nil
	} else if tgtErr == nil {
		_ = os.Remove(oldPath)
	}
	return nil
}

// AtomicReplaceExecutable writes `newBinary` to a sibling temp file in `filepath.Dir(exePath)`, fsyncs, and atomically
// swaps it over `exePath` (single-step `rename(2)` on Unix; rollback-protected `.old` swap on Windows).
func AtomicReplaceExecutable(exePath string, newBinary []byte, goos string) error {
	if strings.TrimSpace(exePath) == "" {
		return errors.New("empty executable path")
	}
	if len(newBinary) == 0 {
		return errors.New("empty replacement binary")
	}
	_ = RecoverInterruptedUpdate(exePath)
	targetPath := exePath
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil && strings.TrimSpace(resolved) != "" {
		targetPath = resolved
	}
	targetPath = filepath.Clean(targetPath)
	dir := filepath.Dir(targetPath)

	perm := os.FileMode(0o755)
	if st, err := os.Stat(targetPath); err == nil && st.Mode().Perm() != 0 {
		perm = st.Mode().Perm() | 0o111
	}

	tmpFile, err := os.CreateTemp(dir, ".edgefetch-update-*")
	if err != nil {
		return fmt.Errorf("create temp executable in %s: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(newBinary); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp executable: %w", err)
	}
	if err := tmpFile.Chmod(perm); err != nil && goos != "windows" {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp executable: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("fsync temp executable: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp executable: %w", err)
	}

	if goos == "windows" {
		oldPath := targetPath + ".old"
		if st, lErr := os.Lstat(oldPath); lErr == nil {
			if st.IsDir() {
				_ = os.RemoveAll(oldPath)
			} else {
				_ = os.Remove(oldPath)
			}
		}
		hadExisting := false
		if _, stErr := os.Stat(targetPath); stErr == nil {
			if rErr := os.Rename(targetPath, oldPath); rErr != nil {
				return fmt.Errorf("move running executable to %s: %w", oldPath, rErr)
			}
			hadExisting = true
		}
		if err := os.Rename(tmpPath, targetPath); err != nil {
			if hadExisting {
				if rbErr := os.Rename(oldPath, targetPath); rbErr != nil {
					return fmt.Errorf("activate updated executable: %w (rollback also failed: %v)", err, rbErr)
				}
			}
			return fmt.Errorf("activate updated executable: %w", err)
		}
		cleanupTmp = false
		_ = os.Remove(oldPath)
		return nil
	}

	// Single-step POSIX atomic rename(2) over targetPath — zero window where targetPath is absent!
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("atomic rename onto %s: %w", targetPath, err)
	}
	cleanupTmp = false
	return nil
}

func newUpdateHTTPClient(allow func(*url.URL) error, transport http.RoundTripper) *http.Client {
	if allow == nil {
		allow = crawl.PublicHTTPS
	}
	if transport == nil {
		transport = newCrawlTransport(30*time.Second, 2)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects during update download")
			}
			if err := allow(req.URL); err != nil {
				return fmt.Errorf("redirect blocked by SSRF guard: %w", err)
			}
			return nil
		},
	}
}

func fetchBytesBounded(ctx context.Context, client *http.Client, allow func(*url.URL) error, rawURL string, maxBytes int64, accept string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid update URL: %w", err)
	}
	if allow != nil {
		if err := allow(u); err != nil {
			return nil, fmt.Errorf("update URL blocked by SSRF guard: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "EdgeFetch-Updater/"+agent.Version)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, u.Redacted())
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response from %s exceeded %d-byte limit", u.Redacted(), maxBytes)
	}
	return data, nil
}

func runUpdateCLI(ctx context.Context, args []string, stdout, stderr io.Writer, cdeps cliDeps) int {
	return runUpdateWithDeps(ctx, args, stdout, stderr, updateDeps{
		allow: cdeps.allow,
	})
}

func runUpdateWithDeps(ctx context.Context, args []string, stdout, stderr io.Writer, deps updateDeps) int {
	var (
		checkOnly      bool
		jsonOut        bool
		allowDowngrade bool
		wantVersion    string
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--check":
			checkOnly = true
		case a == "--json":
			jsonOut = true
		case a == "--allow-downgrade":
			allowDowngrade = true
		case strings.HasPrefix(a, "--version="):
			wantVersion = strings.TrimSpace(strings.TrimPrefix(a, "--version="))
		case a == "--version":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				_, _ = fmt.Fprintln(stderr, "missing value for --version (expected vX.Y.Z)")
				return 2
			}
			i++
			wantVersion = strings.TrimSpace(args[i])
		default:
			_, _ = fmt.Fprintf(stderr, "unknown update flag %q (usage: edgefetch update [--check] [--version vX.Y.Z] [--allow-downgrade])\n", a)
			return 2
		}
	}

	if deps.exePath != "" {
		_ = RecoverInterruptedUpdate(deps.exePath)
	} else if selfExe, eErr := os.Executable(); eErr == nil {
		_ = RecoverInterruptedUpdate(selfExe)
	}

	if deps.allow == nil {
		deps.allow = crawl.PublicHTTPS
	}
	client := deps.httpClient
	if client == nil {
		client = newUpdateHTTPClient(deps.allow, nil)
	}
	apiBase := strings.TrimRight(firstNonEmpty(deps.apiBaseURL, defaultGitHubAPIBaseURL), "/")
	dlBase := strings.TrimRight(firstNonEmpty(deps.downloadBaseURL, defaultGitHubDownloadBaseURL), "/")
	pubPEM := firstNonEmpty(deps.publicKeyPEM, ReleaseSigningPublicKeyPEM)
	curVer := strings.TrimPrefix(firstNonEmpty(deps.currentVersion, agent.Version), "v")
	goos := firstNonEmpty(deps.goos, runtime.GOOS)
	goarch := firstNonEmpty(deps.goarch, runtime.GOARCH)

	pubKey, err := ParseEd25519PublicKeyPEM(pubPEM)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "update failed: %v\n", err)
		return 1
	}

	var targetTag, targetVerNoV string
	if wantVersion != "" {
		targetTag, targetVerNoV, err = normalizeReleaseTag(wantVersion)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "invalid --version: %v\n", err)
			return 2
		}
	} else {
		relURL := fmt.Sprintf("%s/repos/%s/releases/latest", apiBase, githubReleaseRepo)
		relBytes, fErr := fetchBytesBounded(ctx, client, deps.allow, relURL, maxReleaseJSONBytes, "application/vnd.github+json")
		if fErr != nil {
			_, _ = fmt.Fprintf(stderr, "failed to check latest release: %v\n", fErr)
			return 1
		}
		var relMeta struct {
			TagName string `json:"tag_name"`
		}
		if jErr := json.Unmarshal(relBytes, &relMeta); jErr != nil {
			_, _ = fmt.Fprintf(stderr, "invalid release metadata JSON: %v\n", jErr)
			return 1
		}
		targetTag, targetVerNoV, err = normalizeReleaseTag(relMeta.TagName)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "invalid upstream tag_name: %v\n", err)
			return 1
		}
	}

	curTag, _, curValidSemver := normalizeReleaseTag(curVer)
	cmp := 0
	if curValidSemver == nil {
		cmp = compareSemverTags(targetTag, curTag)
	} else {
		cmp = compareSemverTags("v"+targetVerNoV, "v"+curVer)
	}
	updateAvailable := cmp > 0

	if !checkOnly && curValidSemver == nil && cmp < 0 && !allowDowngrade {
		_, _ = fmt.Fprintf(stderr, "SECURITY: %v (target %s < current %s; pass --allow-downgrade to roll back intentionally)\n", ErrDowngradeRefused, targetTag, curTag)
		return 1
	}

	// Always fetch & verify signed checksums.txt + checksums.txt.sig for the target release!
	checksumsURL := fmt.Sprintf("%s/%s/releases/download/%s/checksums.txt", dlBase, githubReleaseRepo, targetTag)
	sigURL := checksumsURL + ".sig"

	checksumsBytes, err := fetchBytesBounded(ctx, client, deps.allow, checksumsURL, maxChecksumsBytes, "text/plain")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to download checksums.txt for %s: %v\n", targetTag, err)
		return 1
	}
	sigBytes, err := fetchBytesBounded(ctx, client, deps.allow, sigURL, maxSignatureBytes, "application/octet-stream")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to download checksums.txt.sig for %s: %v\n", targetTag, err)
		return 1
	}
	if err := VerifyChecksumsSignature(pubKey, checksumsBytes, sigBytes); err != nil {
		_, _ = fmt.Fprintf(stderr, "SECURITY: %v\n", err)
		return 1
	}

	archiveName := releaseArchiveFilename(targetVerNoV, goos, goarch)
	expectedSHA, err := LookupArchiveSHA256(checksumsBytes, archiveName)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "release verification failed: %v\n", err)
		return 1
	}

	if checkOnly {
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{
				"ok":                true,
				"currentVersion":    "v" + curVer,
				"latestVersion":     targetTag,
				"updateAvailable":   updateAvailable,
				"signatureVerified": true,
				"archive":           archiveName,
				"sha256":            expectedSHA,
			})
			return 0
		}
		if updateAvailable {
			_, _ = fmt.Fprintf(stdout, "Update available (%s -> %s, Ed25519 signature verified)\n", "v"+curVer, targetTag)
		} else {
			_, _ = fmt.Fprintf(stdout, "Up to date (v%s, Ed25519 signature verified)\n", curVer)
		}
		return 0
	}

	if wantVersion == "" && !updateAvailable {
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{
				"ok":                true,
				"updated":           false,
				"currentVersion":    "v" + curVer,
				"latestVersion":     targetTag,
				"signatureVerified": true,
			})
			return 0
		}
		_, _ = fmt.Fprintf(stdout, "Up to date (v%s)\n", curVer)
		return 0
	}

	exePath := deps.exePath
	if exePath == "" {
		resolved, eErr := os.Executable()
		if eErr != nil {
			_, _ = fmt.Fprintf(stderr, "resolve executable path: %v\n", eErr)
			return 1
		}
		exePath = resolved
	}

	archiveURL := fmt.Sprintf("%s/%s/releases/download/%s/%s", dlBase, githubReleaseRepo, targetTag, archiveName)
	archiveBytes, err := fetchBytesBounded(ctx, client, deps.allow, archiveURL, maxArchiveDownloadBytes, "application/octet-stream")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to download %s: %v\n", archiveName, err)
		return 1
	}
	if err := VerifyBytesSHA256(archiveBytes, expectedSHA); err != nil {
		_, _ = fmt.Fprintf(stderr, "SECURITY: %v\n", err)
		return 1
	}

	newBin, err := ExtractBinaryFromArchive(archiveBytes, archiveName, goos)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "extract %s failed: %v\n", archiveName, err)
		return 1
	}
	if err := AtomicReplaceExecutable(exePath, newBin, goos); err != nil {
		_, _ = fmt.Fprintf(stderr, "replace executable failed: %v\n", err)
		return 1
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ok":                true,
			"updated":           true,
			"previousVersion":   "v" + curVer,
			"version":           targetTag,
			"executable":        exePath,
			"archive":           archiveName,
			"sha256":            expectedSHA,
			"signatureVerified": true,
		})
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "Updated edgefetch v%s -> %s (%s)\n", curVer, targetTag, exePath)
	return 0
}
