//go:build linux

// Package priv implements irreversible root privilege dropping and pre-drop secret file lockdown on Linux containers.
// At startup (while still UID 0), LockDownSecretPaths enforces 0600 root:root on /data/options.json and 0700 root:root
// on /data; then DropRoot invokes PR_SET_NO_NEW_PRIVS + Setgroups([]) + Setgid(65532) + Setuid(65532) + PR_SET_DUMPABLE(0)
// across all Go runtime OS threads (AllThreadsSyscall6) before any network socket opens or Chromium subprocess spawns,
// guaranteeing VFS DAC blocks UID 65532 (and all child processes) from reading /data/options.json and marking
// /proc/<pid>/environ + /proc/<pid>/mem non-dumpable (`Dumpable: 0`) on every Linux kernel.
package priv

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	nonrootUID     = 65532
	prSetDumpable  = 4  // Linux <sys/prctl.h> PR_SET_DUMPABLE
	prSetNoNewPriv = 38 // Linux <sys/prctl.h> PR_SET_NO_NEW_PRIVS
)

// LockDownSecretPaths restricts secret configuration files (such as Home Assistant `/data/options.json`) to `0600`
// owned by `0:0` (`root:root`) and locks `/data` to `0700` while the process is still UID 0, right before DropRoot().
// Once DropRoot() transitions the process to UID/GID 65532, Linux VFS DAC unconditionally denies access to `/data`
// and `/data/options.json` for both `/edgefetch` and any spawned Chromium / helper child processes.
func LockDownSecretPaths(paths ...string) {
	if os.Geteuid() != 0 {
		return
	}
	for _, raw := range paths {
		if raw == "" {
			continue
		}
		clean := filepath.Clean(raw)
		st, err := os.Lstat(clean)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			continue
		}
		_ = os.Chown(clean, 0, 0)
		if st.IsDir() {
			_ = os.Chmod(clean, 0o700)
			continue
		}
		_ = os.Chmod(clean, 0o600)
		dir := filepath.Dir(clean)
		if dir == "/data" {
			if dst, dErr := os.Lstat(dir); dErr == nil && dst.IsDir() && dst.Mode()&os.ModeSymlink == 0 {
				_ = os.Chown(dir, 0, 0)
				_ = os.Chmod(dir, 0o700)
			}
		}
	}
}

// DropRoot permanently transitions UID/GID 0 down to unprivileged `65532:65532` (`nonroot`), sets `NO_NEW_PRIVS`,
// and marks the process non-dumpable (`PR_SET_DUMPABLE=0`).
func DropRoot() error {
	if os.Geteuid() != 0 {
		// Best-effort hardening when started directly as unprivileged UID (e.g. USER 65532 or su-exec 65532:65532);
		// ignores ENOTSUP when running under `go test -race` (CGO_ENABLED=1).
		_, _, _ = syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetNoNewPriv, 1, 0, 0, 0, 0)
		_, _, _ = syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0)
		return nil
	}
	// Prevent any future `execve` across ALL Go runtime OS threads from gaining privileges via setuid/file-cap bits.
	// Note: Linux kernel `prctl(PR_SET_NO_NEW_PRIVS)` requires arg3..arg5 == 0 (`AllThreadsSyscall6`).
	if _, _, errno := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetNoNewPriv, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", errno)
	}
	// Clear supplementary root groups BEFORE dropping GID/UID (once UID is non-zero, `setgroups` is no longer permitted).
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups([]): %w", err)
	}
	if err := syscall.Setgid(nonrootUID); err != nil {
		return fmt.Errorf("setgid(%d): %w", nonrootUID, err)
	}
	if err := syscall.Setuid(nonrootUID); err != nil {
		return fmt.Errorf("setuid(%d): %w", nonrootUID, err)
	}
	// Apply PR_SET_DUMPABLE=0 AFTER setgid/setuid because Linux commit_creds resets mm->dumpable to fs.suid_dumpable
	// during UID/GID transitions (which may be 2 on hosts with apport/coredumpd).
	if _, _, errno := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", errno)
	}
	if os.Geteuid() != nonrootUID || os.Getuid() != nonrootUID || os.Getegid() != nonrootUID || os.Getgid() != nonrootUID {
		return errors.New("privilege drop verification failed: uid/euid/gid/egid did not transition to 65532")
	}
	if groups, gErr := os.Getgroups(); gErr != nil {
		return fmt.Errorf("verify supplementary groups: %w", gErr)
	} else {
		for _, g := range groups {
			if g == 0 {
				return errors.New("privilege drop verification failed: supplementary group 0 still present")
			}
		}
	}
	return nil
}
