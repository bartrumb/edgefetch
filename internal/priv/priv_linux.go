//go:build linux

// Package priv implements irreversible root privilege dropping on Linux containers.
// Home Assistant OS Supervisor mounts /data/options.json as 0600 root:root; reading config first, zeroing the raw
// buffer, and invoking PR_SET_NO_NEW_PRIVS + Setgroups([]) + Setgid(65532) + Setuid(65532) drops root across all Go
// runtime OS threads (AllThreadsSyscall) before any network socket opens, keeping the runtime image distroless.
package priv

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

const (
	nonrootUID     = 65532
	prSetNoNewPriv = 38 // Linux <sys/prctl.h> PR_SET_NO_NEW_PRIVS
)

// DropRoot permanently transitions UID/GID 0 down to unprivileged `65532:65532` (`nonroot`) and sets `NO_NEW_PRIVS`.
func DropRoot() error {
	if os.Geteuid() != 0 {
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
