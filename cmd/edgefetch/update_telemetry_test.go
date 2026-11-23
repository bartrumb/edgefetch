package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func buildTestTarGz(t *testing.T, entryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name:     entryName,
		Mode:     0o755,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

func buildTestZip(t *testing.T, entryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{
		Name:   entryName,
		Method: zip.Deflate,
	}
	hdr.SetMode(0o755)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func generateTestSigningKeyPEM(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	return priv, string(pemBytes)
}

func TestPinnedReleaseSigningKeyMatchesRepoKeyFile(t *testing.T) {
	repoKeyBytes, err := os.ReadFile(filepath.Join("..", "..", "keys", "release-signing-pub.pem"))
	if err != nil {
		t.Fatalf("read keys/release-signing-pub.pem: %v", err)
	}
	if strings.TrimSpace(string(repoKeyBytes)) != strings.TrimSpace(ReleaseSigningPublicKeyPEM) {
		t.Fatalf("embedded ReleaseSigningPublicKeyPEM drifted from keys/release-signing-pub.pem")
	}
	pub, err := ParseEd25519PublicKeyPEM(ReleaseSigningPublicKeyPEM)
	if err != nil {
		t.Fatalf("ParseEd25519PublicKeyPEM failed on pinned key: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("expected 32-byte Ed25519 public key, got %d", len(pub))
	}
}

func TestEdgeFetchUpdateEd25519VerifiedAndTamperRejected(t *testing.T) {
	priv, pubPEM := generateTestSigningKeyPEM(t)
	_, wrongPubPEM := generateTestSigningKeyPEM(t)

	newLinuxPayload := []byte("#!/bin/sh\necho edgefetch-v2.7.0-linux\n")
	newWinPayload := []byte("MZ-mock-edgefetch-v2.7.0-windows-binary")

	linuxArchive := buildTestTarGz(t, "edgefetch", newLinuxPayload)
	winArchive := buildTestZip(t, "edgefetch.exe", newWinPayload)

	linuxSHA := sha256.Sum256(linuxArchive)
	winSHA := sha256.Sum256(winArchive)

	checksumsTxt := fmt.Sprintf(
		"%s  edgefetch_2.7.0_linux_amd64.tar.gz\n%s  edgefetch_2.7.0_windows_amd64.zip\n",
		hex.EncodeToString(linuxSHA[:]),
		hex.EncodeToString(winSHA[:]),
	)
	validSig := ed25519.Sign(priv, []byte(checksumsTxt))

	var tamperMode string // "", "sig", "checksums", "archive"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/bartrumb/edgefetch/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"v2.7.0"}`))
		case "/bartrumb/edgefetch/releases/download/v2.7.0/checksums.txt":
			if tamperMode == "checksums" {
				fakeSHA := strings.Repeat("a", 64)
				_, _ = fmt.Fprintf(w, "%s  edgefetch_2.7.0_linux_amd64.tar.gz\n", fakeSHA)
				return
			}
			_, _ = w.Write([]byte(checksumsTxt))
		case "/bartrumb/edgefetch/releases/download/v2.7.0/checksums.txt.sig":
			sigCopy := append([]byte(nil), validSig...)
			if tamperMode == "sig" {
				sigCopy[0] ^= 0xff
			}
			_, _ = w.Write(sigCopy)
		case "/bartrumb/edgefetch/releases/download/v2.7.0/edgefetch_2.7.0_linux_amd64.tar.gz":
			if tamperMode == "archive" {
				bad := append([]byte(nil), linuxArchive...)
				bad[len(bad)-1] ^= 0xff
				_, _ = w.Write(bad)
				return
			}
			_, _ = w.Write(linuxArchive)
		case "/bartrumb/edgefetch/releases/download/v2.7.0/edgefetch_2.7.0_windows_amd64.zip":
			_, _ = w.Write(winArchive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	srvAddr := srv.Listener.Addr().String()
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
			},
		},
	}

	tmpDir := t.TempDir()
	linuxExe := filepath.Join(tmpDir, "edgefetch")
	originalBytes := []byte("original-v2.6.3-binary")
	if err := os.WriteFile(linuxExe, originalBytes, 0o755); err != nil {
		t.Fatalf("write original exe: %v", err)
	}

	baseDeps := updateDeps{
		httpClient:      tlsClient,
		allow:           func(*url.URL) error { return nil },
		apiBaseURL:      srv.URL,
		downloadBaseURL: srv.URL,
		publicKeyPEM:    pubPEM,
		currentVersion:  "2.6.3",
		exePath:         linuxExe,
		goos:            "linux",
		goarch:          "amd64",
	}

	// 1. `--check --json` verifies signature without modifying executable on disk.
	var outBuf, errBuf bytes.Buffer
	if rc := runUpdateWithDeps(context.Background(), []string{"--check", "--json"}, &outBuf, &errBuf, baseDeps); rc != 0 {
		t.Fatalf("update --check failed: rc=%d stderr=%s", rc, errBuf.String())
	}
	var checkOut map[string]any
	if err := json.Unmarshal(outBuf.Bytes(), &checkOut); err != nil {
		t.Fatalf("unmarshal check json: %v", err)
	}
	if checkOut["updateAvailable"] != true || checkOut["signatureVerified"] != true || checkOut["latestVersion"] != "v2.7.0" {
		t.Fatalf("unexpected --check output: %+v", checkOut)
	}
	gotDisk, _ := os.ReadFile(linuxExe)
	if !bytes.Equal(gotDisk, originalBytes) {
		t.Fatal("expected --check not to modify binary on disk")
	}

	// 2. Tampered Ed25519 signature MUST fail closed and leave binary untouched!
	for _, mode := range []string{"sig", "checksums", "archive"} {
		tamperMode = mode
		outBuf.Reset()
		errBuf.Reset()
		rc := runUpdateWithDeps(context.Background(), nil, &outBuf, &errBuf, baseDeps)
		if rc == 0 {
			t.Fatalf("SECURITY: expected update to fail on tamperMode=%q", mode)
		}
		gotAfterFail, _ := os.ReadFile(linuxExe)
		if !bytes.Equal(gotAfterFail, originalBytes) {
			t.Fatalf("SECURITY: binary modified despite failed %s verification!", mode)
		}
	}
	tamperMode = ""

	// 3. Wrong pinned Ed25519 public key MUST fail closed!
	wrongKeyDeps := baseDeps
	wrongKeyDeps.publicKeyPEM = wrongPubPEM
	errBuf.Reset()
	if rc := runUpdateWithDeps(context.Background(), nil, &outBuf, &errBuf, wrongKeyDeps); rc == 0 {
		t.Fatal("SECURITY: expected update with wrong Ed25519 public key to fail")
	}

	// 4. Valid Ed25519 signature + valid SHA-256 -> atomic tar.gz extraction & replacement!
	outBuf.Reset()
	errBuf.Reset()
	if rc := runUpdateWithDeps(context.Background(), nil, &outBuf, &errBuf, baseDeps); rc != 0 {
		t.Fatalf("valid Linux update failed: rc=%d stderr=%s", rc, errBuf.String())
	}
	updatedLinux, err := os.ReadFile(linuxExe)
	if err != nil || !bytes.Equal(updatedLinux, newLinuxPayload) {
		t.Fatalf("expected updated Linux binary payload, got %q (err=%v)", string(updatedLinux), err)
	}

	// 5. Already up-to-date no-op (`v2.7.0` == `v2.7.0`).
	upToDateDeps := baseDeps
	upToDateDeps.currentVersion = "2.7.0"
	outBuf.Reset()
	errBuf.Reset()
	if rc := runUpdateWithDeps(context.Background(), nil, &outBuf, &errBuf, upToDateDeps); rc != 0 {
		t.Fatalf("up-to-date run failed: rc=%d stderr=%s", rc, errBuf.String())
	}
	if !strings.Contains(outBuf.String(), "Up to date (v2.7.0)") {
		t.Fatalf("expected Up to date message, got %q", outBuf.String())
	}

	// 6. Explicit `--version v2.7.0` on Windows `.zip` archive with `.old` atomic swap!
	winExe := filepath.Join(tmpDir, "edgefetch.exe")
	if err := os.WriteFile(winExe, []byte("old-win-exe"), 0o755); err != nil {
		t.Fatalf("write winExe: %v", err)
	}
	winDeps := baseDeps
	winDeps.exePath = winExe
	winDeps.goos = "windows"
	winDeps.goarch = "amd64"
	outBuf.Reset()
	errBuf.Reset()
	if rc := runUpdateWithDeps(context.Background(), []string{"--version", "v2.7.0"}, &outBuf, &errBuf, winDeps); rc != 0 {
		t.Fatalf("valid Windows .zip update failed: rc=%d stderr=%s", rc, errBuf.String())
	}
	updatedWin, err := os.ReadFile(winExe)
	if err != nil || !bytes.Equal(updatedWin, newWinPayload) {
		t.Fatalf("expected updated Windows binary payload, got %q (err=%v)", string(updatedWin), err)
	}
}

func TestEdgeFetchInitTelemetryPromptTTYAndDoNotTrackInvariants(t *testing.T) {
	tmpDir := t.TempDir()
	jsonCfg := filepath.Join(tmpDir, "mcp.json")
	tomlCfg := filepath.Join(tmpDir, "config.toml")
	fakeExe := filepath.Join(tmpDir, "edgefetch")

	// 1. Non-TTY stdin (even if stdin contains "y\n") MUST skip interactive prompt and leave telemetry OFF!
	var stdout, stderr bytes.Buffer
	rc := runOneShotCLI(
		context.Background(),
		[]string{"init", "--exe=" + fakeExe, "--config=" + jsonCfg},
		&stdout,
		&stderr,
		cliDeps{
			getenv: func(string) string { return "" },
			stdin:  strings.NewReader("y\n"), // strings.Reader is non-TTY!
		},
	)
	if rc != 0 {
		t.Fatalf("non-TTY init failed: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "[y/N]") {
		t.Fatalf("non-TTY init must NOT prompt on stdout: %s", stdout.String())
	}
	rawNonTTY, _ := os.ReadFile(jsonCfg)
	if strings.Contains(string(rawNonTTY), "EDGEFETCH_DEV_TELEMETRY") {
		t.Fatalf("SECURITY: non-TTY init enabled telemetry unexpectedly:\n%s", string(rawNonTTY))
	}

	// 2. Interactive TTY with default Enter ("\n") leaves telemetry OFF!
	isTTY := true
	stdout.Reset()
	stderr.Reset()
	if rc := runInstallMCPWithDeps(
		[]string{"--exe=" + fakeExe, "--config=" + jsonCfg},
		strings.NewReader("\n"),
		&stdout,
		&stderr,
		cliDeps{getenv: func(string) string { return "" }, stdinIsTTY: &isTTY},
	); rc != 0 {
		t.Fatalf("TTY default-No init failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "[y/N]") {
		t.Fatalf("expected interactive [y/N] prompt on TTY: %s", stdout.String())
	}
	rawDefaultNo, _ := os.ReadFile(jsonCfg)
	if strings.Contains(string(rawDefaultNo), "EDGEFETCH_DEV_TELEMETRY") {
		t.Fatalf("SECURITY: default Enter in TTY init must keep telemetry OFF:\n%s", string(rawDefaultNo))
	}

	// 3. Interactive TTY with explicit "y\n" enables EDGEFETCH_DEV_TELEMETRY=1 in both JSON and Codex TOML!
	for _, cfgPath := range []string{jsonCfg, tomlCfg} {
		stdout.Reset()
		stderr.Reset()
		if rc := runInstallMCPWithDeps(
			[]string{"--exe=" + fakeExe, "--config=" + cfgPath},
			strings.NewReader("y\n"),
			&stdout,
			&stderr,
			cliDeps{getenv: func(string) string { return "" }, stdinIsTTY: &isTTY},
		); rc != 0 {
			t.Fatalf("TTY yes init failed for %s: %s", cfgPath, stderr.String())
		}
		written, _ := os.ReadFile(cfgPath)
		if !strings.Contains(string(written), "EDGEFETCH_DEV_TELEMETRY") {
			t.Fatalf("expected EDGEFETCH_DEV_TELEMETRY in %s after explicit 'y':\n%s", cfgPath, string(written))
		}
	}

	// 4. `DO_NOT_TRACK=1` acts as hard override even if `--telemetry` AND TTY "y\n" AND `EDGEFETCH_DEV_TELEMETRY=1`!
	dntCfg := filepath.Join(tmpDir, "dnt-mcp.json")
	stdout.Reset()
	stderr.Reset()
	if rc := runInstallMCPWithDeps(
		[]string{"--exe=" + fakeExe, "--config=" + dntCfg, "--telemetry"},
		strings.NewReader("y\n"),
		&stdout,
		&stderr,
		cliDeps{
			getenv: func(k string) string {
				switch k {
				case "DO_NOT_TRACK":
					return "1"
				case "EDGEFETCH_DEV_TELEMETRY":
					return "1"
				default:
					return ""
				}
			},
			stdinIsTTY: &isTTY,
		},
	); rc != 0 {
		t.Fatalf("DO_NOT_TRACK=1 init failed: %s", stderr.String())
	}
	rawDNT, _ := os.ReadFile(dntCfg)
	if strings.Contains(string(rawDNT), "EDGEFETCH_DEV_TELEMETRY") {
		t.Fatalf("SECURITY: DO_NOT_TRACK=1 failed to override telemetry in init:\n%s", string(rawDNT))
	}
}

func TestWorkflowsPinExact40HexCommitSHAs(t *testing.T) {
	reUses := regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)`)
	rePinned := regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$`)

	wfDir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("readdir %s: %v", wfDir, err)
	}
	checkedCount := 0
	for _, ent := range entries {
		if ent.IsDir() || (!strings.HasSuffix(ent.Name(), ".yml") && !strings.HasSuffix(ent.Name(), ".yaml")) {
			continue
		}
		checkedCount++
		wfPath := filepath.Join(wfDir, ent.Name())
		raw, err := os.ReadFile(wfPath)
		if err != nil {
			t.Fatalf("read %s: %v", wfPath, err)
		}
		if strings.Contains(string(raw), "ubuntu-latest") {
			t.Fatalf("SECURITY: unpinned runner 'ubuntu-latest' in %s (must pin e.g. ubuntu-24.04)", ent.Name())
		}
	}
	if checkedCount < 6 {
		t.Fatalf("expected >= 6 workflow files in %s, got %d", wfDir, checkedCount)
	}

	for _, wf := range []string{"deploy-hub.yml", "upstream-sync.yml", "vouch.yml"} {
		wfPath := filepath.Join(wfDir, wf)
		raw, err := os.ReadFile(wfPath)
		if err != nil {
			t.Fatalf("read %s: %v", wfPath, err)
		}
		matches := reUses.FindAllStringSubmatch(string(raw), -1)
		if len(matches) == 0 {
			t.Fatalf("expected at least one uses: step in %s", wf)
		}
		for _, m := range matches {
			if !rePinned.MatchString(m[1]) {
				t.Fatalf("SECURITY: unpinned GitHub Action %q in %s (must be 40-hex commit SHA)", m[1], wf)
			}
		}
	}
}

func TestR7UpdateDowngradeGuardAndAtomicCrashRecovery(t *testing.T) {
	priv, pubPEM := generateTestSigningKeyPEM(t)

	oldLinuxPayload := []byte("#!/bin/sh\necho edgefetch-v2.6.2-old\n")
	oldArchive := buildTestTarGz(t, "edgefetch", oldLinuxPayload)
	oldSHA := sha256.Sum256(oldArchive)
	checksums262 := fmt.Sprintf("%s  edgefetch_2.6.2_linux_amd64.tar.gz\n", hex.EncodeToString(oldSHA[:]))
	sig262 := ed25519.Sign(priv, []byte(checksums262))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/bartrumb/edgefetch/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"v2.6.2"}`))
		case "/bartrumb/edgefetch/releases/download/v2.6.2/checksums.txt":
			_, _ = w.Write([]byte(checksums262))
		case "/bartrumb/edgefetch/releases/download/v2.6.2/checksums.txt.sig":
			_, _ = w.Write(sig262)
		case "/bartrumb/edgefetch/releases/download/v2.6.2/edgefetch_2.6.2_linux_amd64.tar.gz":
			_, _ = w.Write(oldArchive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	srvAddr := srv.Listener.Addr().String()
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
			},
		},
	}

	tmpDir := t.TempDir()
	linuxExe := filepath.Join(tmpDir, "edgefetch")
	curBytes := []byte("current-v2.7.0-binary")
	if err := os.WriteFile(linuxExe, curBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	deps := updateDeps{
		httpClient:      tlsClient,
		allow:           func(*url.URL) error { return nil },
		apiBaseURL:      srv.URL,
		downloadBaseURL: srv.URL,
		publicKeyPEM:    pubPEM,
		currentVersion:  "2.7.0",
		exePath:         linuxExe,
		goos:            "linux",
		goarch:          "amd64",
	}

	// 1. Implicit rollback via /releases/latest returning older tag v2.6.2 MUST fail closed without --allow-downgrade!
	var outBuf, errBuf bytes.Buffer
	if rc := runUpdateWithDeps(context.Background(), nil, &outBuf, &errBuf, deps); rc == 0 {
		t.Fatal("SECURITY: expected implicit downgrade via /releases/latest to be refused")
	}
	if !strings.Contains(errBuf.String(), ErrDowngradeRefused.Error()) {
		t.Fatalf("expected ErrDowngradeRefused on stderr, got %q", errBuf.String())
	}
	if got, _ := os.ReadFile(linuxExe); !bytes.Equal(got, curBytes) {
		t.Fatal("SECURITY: binary modified despite refused implicit downgrade")
	}

	// 2. Explicit `--version v2.6.2` (< v2.7.0) without `--allow-downgrade` MUST also fail closed!
	outBuf.Reset()
	errBuf.Reset()
	if rc := runUpdateWithDeps(context.Background(), []string{"--version", "v2.6.2"}, &outBuf, &errBuf, deps); rc == 0 {
		t.Fatal("SECURITY: expected explicit --version v2.6.2 downgrade without --allow-downgrade to fail")
	}
	if !strings.Contains(errBuf.String(), ErrDowngradeRefused.Error()) {
		t.Fatalf("expected ErrDowngradeRefused on stderr, got %q", errBuf.String())
	}
	if got, _ := os.ReadFile(linuxExe); !bytes.Equal(got, curBytes) {
		t.Fatal("SECURITY: binary modified despite refused explicit downgrade")
	}

	// 3. `--check --json` on older /releases/latest succeeds cleanly with updateAvailable=false.
	outBuf.Reset()
	errBuf.Reset()
	if rc := runUpdateWithDeps(context.Background(), []string{"--check", "--json"}, &outBuf, &errBuf, deps); rc != 0 {
		t.Fatalf("expected --check to succeed when upstream tag is older: %s", errBuf.String())
	}
	if !strings.Contains(outBuf.String(), `"updateAvailable": false`) {
		t.Fatalf("expected updateAvailable:false in --check output: %s", outBuf.String())
	}

	// 4. Explicit `--version v2.6.2 --allow-downgrade` succeeds via single-step Unix rename (no .old left behind)!
	outBuf.Reset()
	errBuf.Reset()
	if rc := runUpdateWithDeps(context.Background(), []string{"--version", "v2.6.2", "--allow-downgrade"}, &outBuf, &errBuf, deps); rc != 0 {
		t.Fatalf("expected --allow-downgrade to succeed: rc=%d stderr=%s", rc, errBuf.String())
	}
	if got, _ := os.ReadFile(linuxExe); !bytes.Equal(got, oldLinuxPayload) {
		t.Fatalf("expected downgraded payload after --allow-downgrade, got %q", string(got))
	}
	if _, err := os.Lstat(linuxExe + ".old"); !os.IsNotExist(err) {
		t.Fatalf("expected zero .old file on Unix single-step rename, got err=%v", err)
	}

	// 5. RecoverInterruptedUpdate heals missing target from .old and removes stale .old when target exists!
	winExe := filepath.Join(tmpDir, "edgefetch-win.exe")
	winOld := winExe + ".old"
	backupBytes := []byte("healthy-previous-win-exe")
	if err := os.WriteFile(winOld, backupBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RecoverInterruptedUpdate(winExe); err != nil {
		t.Fatalf("RecoverInterruptedUpdate restore failed: %v", err)
	}
	if got, err := os.ReadFile(winExe); err != nil || !bytes.Equal(got, backupBytes) {
		t.Fatalf("expected RecoverInterruptedUpdate to restore %s from .old, got %q err=%v", winExe, string(got), err)
	}
	if _, err := os.Lstat(winOld); !os.IsNotExist(err) {
		t.Fatalf("expected .old moved back to targetPath, got err=%v", err)
	}

	// Stale .old when target is healthy -> removed cleanly.
	if err := os.WriteFile(winOld, []byte("stale-old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverInterruptedUpdate(winExe); err != nil {
		t.Fatalf("RecoverInterruptedUpdate cleanup failed: %v", err)
	}
	if _, err := os.Lstat(winOld); !os.IsNotExist(err) {
		t.Fatalf("expected stale .old removed, got err=%v", err)
	}

	// Pre-existing directory at .old is cleaned up on Windows AtomicReplaceExecutable.
	if err := os.MkdirAll(filepath.Join(winOld, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := AtomicReplaceExecutable(winExe, []byte("updated-win-exe"), "windows"); err != nil {
		t.Fatalf("AtomicReplaceExecutable windows with directory .old failed: %v", err)
	}
	if got, _ := os.ReadFile(winExe); string(got) != "updated-win-exe" {
		t.Fatalf("unexpected winExe content: %q", string(got))
	}
}

func TestMCPBackgroundUpdateCheckDefaultOffAndOptInInvariants(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/repos/bartrumb/edgefetch/releases/latest" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"v9.9.9"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	srvAddr := srv.Listener.Addr().String()
	tlsTr := &http.Transport{
		TLSClientConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
		},
	}

	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "update-check.json")
	pingFrame := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"

	// 1. Default (`EDGEFETCH_CHECK_UPDATES` unset): ZERO background phone-home calls!
	var stdout, stderr bytes.Buffer
	rc := runOneShotCLI(context.Background(), []string{"mcp"}, &stdout, &stderr, cliDeps{
		getenv:          func(string) string { return "" },
		transport:       tlsTr,
		allow:           func(*url.URL) error { return nil },
		stdin:           strings.NewReader(pingFrame),
		updateAPIBase:   srv.URL,
		updateCachePath: cachePath,
	})
	if rc != 0 {
		t.Fatalf("default mcp failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if hits.Load() != 0 {
		t.Fatalf("PRIVACY: expected 0 GitHub API calls when EDGEFETCH_CHECK_UPDATES is unset, got %d", hits.Load())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr by default, got %q", stderr.String())
	}

	// 2. `EDGEFETCH_CHECK_UPDATES=1` + `DO_NOT_TRACK=1` OR `EDGEFETCH_DISABLE_UPDATE_CHECK=1`: ZERO calls!
	for _, overrideKey := range []string{"DO_NOT_TRACK", "EDGEFETCH_DISABLE_UPDATE_CHECK"} {
		stdout.Reset()
		stderr.Reset()
		rc = runOneShotCLI(context.Background(), []string{"mcp"}, &stdout, &stderr, cliDeps{
			getenv: func(k string) string {
				if k == "EDGEFETCH_CHECK_UPDATES" || k == overrideKey {
					return "1"
				}
				return ""
			},
			transport:       tlsTr,
			allow:           func(*url.URL) error { return nil },
			stdin:           strings.NewReader(pingFrame),
			updateAPIBase:   srv.URL,
			updateCachePath: cachePath,
		})
		if rc != 0 || hits.Load() != 0 {
			t.Fatalf("PRIVACY: expected 0 GitHub API calls when %s=1, got hits=%d rc=%d", overrideKey, hits.Load(), rc)
		}
	}

	// 3. Explicit opt-in `EDGEFETCH_CHECK_UPDATES=true`: checks once, writes notice strictly to stderr (never stdout), and caches 24h!
	donePing, releaseStdin := net.Pipe()
	go func() {
		_, _ = releaseStdin.Write([]byte(pingFrame))
		deadline := time.Now().Add(2500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, statErr := os.Stat(cachePath); statErr == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = releaseStdin.Close()
	}()
	stdout.Reset()
	stderr.Reset()
	rc = runOneShotCLI(context.Background(), []string{"mcp"}, &stdout, &stderr, cliDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_CHECK_UPDATES" {
				return "true"
			}
			return ""
		},
		transport:       tlsTr,
		allow:           func(*url.URL) error { return nil },
		stdin:           donePing,
		updateAPIBase:   srv.URL,
		updateCachePath: cachePath,
	})
	if rc != 0 {
		t.Fatalf("opt-in mcp failed: rc=%d stderr=%s", rc, stderr.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 GitHub API call with EDGEFETCH_CHECK_UPDATES=true, got %d", hits.Load())
	}
	if strings.Contains(stdout.String(), "Update available") {
		t.Fatalf("update notice must NEVER pollute MCP JSON-RPC stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "v9.9.9") {
		t.Fatalf("expected update notice on stderr, got %q", stderr.String())
	}

	// Second launch within 24h reads cache without making a network request!
	stdout.Reset()
	stderr.Reset()
	rc = runOneShotCLI(context.Background(), []string{"mcp"}, &stdout, &stderr, cliDeps{
		getenv: func(k string) string {
			if k == "EDGEFETCH_CHECK_UPDATES" {
				return "1"
			}
			return ""
		},
		transport:       tlsTr,
		allow:           func(*url.URL) error { return nil },
		stdin:           strings.NewReader(pingFrame),
		updateAPIBase:   srv.URL,
		updateCachePath: cachePath,
	})
	if rc != 0 || hits.Load() != 1 {
		t.Fatalf("expected 24h cache hit (still 1 network call), got hits=%d rc=%d", hits.Load(), rc)
	}
	if !strings.Contains(stderr.String(), "v9.9.9") {
		t.Fatalf("expected cached update notice on stderr, got %q", stderr.String())
	}
}

func TestR9UpdateFloorFailClosedOnBuildMetaDevAndUnparseableVersions(t *testing.T) {
	priv, pubPEM := generateTestSigningKeyPEM(t)

	payload262 := []byte("#!/bin/sh\necho edgefetch-v2.6.2\n")
	archive262 := buildTestTarGz(t, "edgefetch", payload262)
	sha262 := sha256.Sum256(archive262)
	checksums262 := fmt.Sprintf("%s  edgefetch_2.6.2_linux_amd64.tar.gz\n", hex.EncodeToString(sha262[:]))
	sig262 := ed25519.Sign(priv, []byte(checksums262))

	payload274 := []byte("#!/bin/sh\necho edgefetch-v2.7.4\n")
	archive274 := buildTestTarGz(t, "edgefetch", payload274)
	sha274 := sha256.Sum256(archive274)
	checksums274 := fmt.Sprintf("%s  edgefetch_2.7.4_linux_amd64.tar.gz\n", hex.EncodeToString(sha274[:]))
	sig274 := ed25519.Sign(priv, []byte(checksums274))

	latestTag := "v2.6.2"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/bartrumb/edgefetch/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"tag_name":%q}`, latestTag)
		case "/bartrumb/edgefetch/releases/download/v2.6.2/checksums.txt":
			_, _ = w.Write([]byte(checksums262))
		case "/bartrumb/edgefetch/releases/download/v2.6.2/checksums.txt.sig":
			_, _ = w.Write(sig262)
		case "/bartrumb/edgefetch/releases/download/v2.6.2/edgefetch_2.6.2_linux_amd64.tar.gz":
			_, _ = w.Write(archive262)
		case "/bartrumb/edgefetch/releases/download/v2.7.4/checksums.txt":
			_, _ = w.Write([]byte(checksums274))
		case "/bartrumb/edgefetch/releases/download/v2.7.4/checksums.txt.sig":
			_, _ = w.Write(sig274)
		case "/bartrumb/edgefetch/releases/download/v2.7.4/edgefetch_2.7.4_linux_amd64.tar.gz":
			_, _ = w.Write(archive274)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	srvAddr := srv.Listener.Addr().String()
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
			},
		},
	}

	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "edgefetch")
	origBytes := []byte("original-protected-binary")
	if err := os.WriteFile(exePath, origBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	makeDeps := func(curVer string) updateDeps {
		return updateDeps{
			httpClient:      tlsClient,
			allow:           func(*url.URL) error { return nil },
			apiBaseURL:      srv.URL,
			downloadBaseURL: srv.URL,
			publicKeyPEM:    pubPEM,
			currentVersion:  curVer,
			exePath:         exePath,
			goos:            "linux",
			goarch:          "amd64",
		}
	}

	// 1. SemVer +buildmetadata (`v2.7.3+git.abc123`, `2.7.3+20261123`) strips +build cleanly:
	//    - Downgrade to v2.6.2 (both implicit /releases/latest and explicit --version v2.6.2) MUST fail closed!
	for _, curWithBuild := range []string{"2.7.3+git.abc123", "v2.7.3+20261123.dirty", "2.7.3-rc.1+sha.deadbeef"} {
		for _, cliArgs := range [][]string{nil, {"--version", "v2.6.2"}} {
			var outBuf, errBuf bytes.Buffer
			rc := runUpdateWithDeps(context.Background(), cliArgs, &outBuf, &errBuf, makeDeps(curWithBuild))
			if rc == 0 {
				t.Fatalf("SECURITY: expected downgrade from %q (args=%v) to v2.6.2 to fail closed!", curWithBuild, cliArgs)
			}
			if !strings.Contains(errBuf.String(), ErrDowngradeRefused.Error()) {
				t.Fatalf("expected ErrDowngradeRefused for %q, got %q", curWithBuild, errBuf.String())
			}
			if got, _ := os.ReadFile(exePath); !bytes.Equal(got, origBytes) {
				t.Fatalf("SECURITY: binary modified despite refused downgrade from %q", curWithBuild)
			}
		}
	}

	// 2. Unparseable or "dev" current binary version MUST NEVER fail open (both implicit and explicit --version)!
	for _, unparseableCur := range []string{"dev", "0-custom", "main-snapshot", "2.7.3+", "2.7.3+bad/meta", "not-a-semver"} {
		for _, cliArgs := range [][]string{nil, {"--version", "v2.6.2"}, {"--version", "v2.7.4"}} {
			var outBuf, errBuf bytes.Buffer
			rc := runUpdateWithDeps(context.Background(), cliArgs, &outBuf, &errBuf, makeDeps(unparseableCur))
			if rc == 0 {
				t.Fatalf("SECURITY: expected update from unparseable current version %q (args=%v) without --allow-downgrade to fail closed!", unparseableCur, cliArgs)
			}
			if !strings.Contains(errBuf.String(), ErrDowngradeRefused.Error()) {
				t.Fatalf("expected ErrDowngradeRefused for current=%q, got %q", unparseableCur, errBuf.String())
			}
			if got, _ := os.ReadFile(exePath); !bytes.Equal(got, origBytes) {
				t.Fatalf("SECURITY: binary modified on unparseable current version %q", unparseableCur)
			}
		}
	}

	// 3. Unparseable target versions (both --version and upstream tag_name, including +build in tag) MUST always fail closed even with --allow-downgrade!
	for _, badTarget := range []string{"dev", "latest", "v2.7", "v2.7.3+build1", "v2.7.3/../../pwn"} {
		var outBuf, errBuf bytes.Buffer
		if rc := runUpdateWithDeps(context.Background(), []string{"--version", badTarget, "--allow-downgrade"}, &outBuf, &errBuf, makeDeps("2.7.3")); rc == 0 {
			t.Fatalf("SECURITY: expected invalid --version %q to fail closed even with --allow-downgrade", badTarget)
		}
		latestTag = badTarget
		outBuf.Reset()
		errBuf.Reset()
		if rc := runUpdateWithDeps(context.Background(), []string{"--allow-downgrade"}, &outBuf, &errBuf, makeDeps("2.7.3")); rc == 0 {
			t.Fatalf("SECURITY: expected invalid upstream tag_name %q to fail closed even with --allow-downgrade", badTarget)
		}
	}

	// 4. Valid upgrade from `2.7.3+git.abc` -> `v2.7.4` succeeds cleanly, and numeric prerelease ordering (`rc.10 > rc.2`) holds!
	if cmp, err := compareSemverTagsChecked("v2.7.4-rc.10", "v2.7.4-rc.2"); err != nil || cmp <= 0 {
		t.Fatalf("expected v2.7.4-rc.10 > v2.7.4-rc.2, got cmp=%d err=%v", cmp, err)
	}
	if cmp, err := compareSemverTagsChecked("v2.7.4", "v2.7.4-rc.10"); err != nil || cmp <= 0 {
		t.Fatalf("expected stable v2.7.4 > v2.7.4-rc.10, got cmp=%d err=%v", cmp, err)
	}
	latestTag = "v2.7.4"
	var outBuf, errBuf bytes.Buffer
	if rc := runUpdateWithDeps(context.Background(), nil, &outBuf, &errBuf, makeDeps("2.7.3+git.abc")); rc != 0 {
		t.Fatalf("expected upgrade from 2.7.3+git.abc -> v2.7.4 to succeed: rc=%d stderr=%s", rc, errBuf.String())
	}
	if got, _ := os.ReadFile(exePath); !bytes.Equal(got, payload274) {
		t.Fatalf("expected updated v2.7.4 payload, got %q", string(got))
	}

	// 5. Explicit `--allow-downgrade` from `"dev"` binary succeeds when operator intentionally opts in.
	if err := os.WriteFile(exePath, origBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	outBuf.Reset()
	errBuf.Reset()
	if rc := runUpdateWithDeps(context.Background(), []string{"--allow-downgrade"}, &outBuf, &errBuf, makeDeps("dev")); rc != 0 {
		t.Fatalf("expected explicit --allow-downgrade on 'dev' binary to succeed: rc=%d stderr=%s", rc, errBuf.String())
	}
	if got, _ := os.ReadFile(exePath); !bytes.Equal(got, payload274) {
		t.Fatalf("expected v2.7.4 installed over 'dev' with --allow-downgrade, got %q", string(got))
	}
}
