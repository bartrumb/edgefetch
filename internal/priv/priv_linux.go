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

// LockDownSecretPaths restricts `/data` (`0700` owned by `0:0`) first and then restricts secret configuration files
// (such as Home Assistant `/data/options.json`, `0600` owned by `0:0`) while the process is still UID 0, right before
// DropRoot(). Uses `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` + `Fstat` + `Fchown`/`Fchmod` on the opened file descriptor so
// concurrent symlink swaps or hardlinks (`nlink > 1`) can never redirect ownership or mode changes onto another inode.
func LockDownSecretPaths(paths ...string) error {
	return lockDownSecretPathsWith(os.Geteuid(), "/data", nil, nil, paths...)
}

// LockDownSecretPathsStrict enforces LockDownSecretPaths and returns any symlink, hardlink, or permission-lockdown error.
func LockDownSecretPathsStrict(paths ...string) error {
	return LockDownSecretPaths(paths...)
}

func openNoFollowSecretFD(clean string, dirOnly bool) (int, syscall.Stat_t, bool, error) {
	var st syscall.Stat_t
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	if dirOnly {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Open(clean, flags, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return -1, st, false, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			if dirOnly {
				return -1, st, false, fmt.Errorf("refusing symlink secret directory %s: %w", clean, err)
			}
			return -1, st, false, fmt.Errorf("refusing symlink secret path %s: %w", clean, err)
		}
		if dirOnly && errors.Is(err, syscall.ENOTDIR) {
			// Distinguish symlink vs regular file at dataDir when O_DIRECTORY|O_NOFOLLOW returns ENOTDIR on Linux.
			if lst, lErr := os.Lstat(clean); lErr == nil && lst.Mode()&os.ModeSymlink != 0 {
				return -1, st, false, fmt.Errorf("refusing symlink secret directory %s", clean)
			}
			return -1, st, false, fmt.Errorf("secret path %s is not a directory: %w", clean, err)
		}
		return -1, st, false, fmt.Errorf("open %s: %w", clean, err)
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return -1, st, false, fmt.Errorf("fstat %s: %w", clean, err)
	}
	ftype := st.Mode & syscall.S_IFMT
	if dirOnly {
		if ftype != syscall.S_IFDIR {
			_ = syscall.Close(fd)
			return -1, st, false, fmt.Errorf("secret path %s is not a directory", clean)
		}
	} else {
		if ftype != syscall.S_IFREG && ftype != syscall.S_IFDIR {
			_ = syscall.Close(fd)
			return -1, st, false, fmt.Errorf("refusing non-regular secret path %s (mode=0%o)", clean, st.Mode)
		}
		if ftype == syscall.S_IFREG && st.Nlink > 1 {
			_ = syscall.Close(fd)
			return -1, st, false, fmt.Errorf("refusing hardlinked secret path %s (nlink=%d)", clean, st.Nlink)
		}
	}
	return fd, st, true, nil
}

func lockDownFD(
	clean string,
	fd int,
	st syscall.Stat_t,
	mode os.FileMode,
	chownFn func(string, int, int) error,
	chmodFn func(string, os.FileMode) error,
) error {
	if chownFn != nil {
		if err := chownFn(clean, 0, 0); err != nil {
			return fmt.Errorf("chown %s: %w", clean, err)
		}
	} else {
		if err := syscall.Fchown(fd, 0, 0); err != nil {
			return fmt.Errorf("chown %s: %w", clean, err)
		}
	}
	if chmodFn != nil {
		if err := chmodFn(clean, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", clean, err)
		}
	} else {
		if err := syscall.Fchmod(fd, uint32(mode.Perm())); err != nil {
			return fmt.Errorf("chmod %s: %w", clean, err)
		}
	}
	var after syscall.Stat_t
	if err := syscall.Lstat(clean, &after); err != nil {
		return fmt.Errorf("verify lstat %s: %w", clean, err)
	}
	if (after.Mode&syscall.S_IFMT) == syscall.S_IFLNK || after.Dev != st.Dev || after.Ino != st.Ino {
		return fmt.Errorf("secret path %s was replaced during lockdown", clean)
	}
	return nil
}

func lockDownSecretPathsWith(
	euid int,
	dataDir string,
	chownFn func(string, int, int) error,
	chmodFn func(string, os.FileMode) error,
	paths ...string,
) error {
	if euid != 0 {
		return nil
	}
	if dataDir != "" {
		cleanData := filepath.Clean(dataDir)
		fd, st, exists, err := openNoFollowSecretFD(cleanData, true)
		if err != nil {
			return err
		}
		if exists {
			err := lockDownFD(cleanData, fd, st, 0o700, chownFn, chmodFn)
			_ = syscall.Close(fd)
			if err != nil {
				return err
			}
		}
	}

	for _, raw := range paths {
		if raw == "" {
			continue
		}
		clean := filepath.Clean(raw)
		if dataDir != "" && clean == filepath.Clean(dataDir) {
			continue
		}
		fd, st, exists, err := openNoFollowSecretFD(clean, false)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		mode := os.FileMode(0o600)
		if (st.Mode & syscall.S_IFMT) == syscall.S_IFDIR {
			mode = 0o700
		}
		lErr := lockDownFD(clean, fd, st, mode, chownFn, chmodFn)
		_ = syscall.Close(fd)
		if lErr != nil {
			return lErr
		}
	}
	return nil
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
