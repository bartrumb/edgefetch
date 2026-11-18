//go:build linux

// Package priv implements irreversible root privilege dropping on Linux containers.
//
// For Go learners reading this package:
//   - Notice the `//go:build linux` build constraint on line 1 (paired with `//go:build !linux` in `priv_other.go`).
//     Go's build system selects OS-specific files at compile time cleanly without C preprocessor `#ifdef` blocks.
//   - Why drop root in Go rather than setting `USER 65532` in the Home Assistant Add-on Dockerfile?
//     Home Assistant OS Supervisor mounts `/data/options.json` owned by `root:root` (`0600`). Reading the config file
//     into memory first, zeroing the raw buffer, and immediately invoking `PR_SET_NO_NEW_PRIVS` + `Setgroups([])` +
//     `Setgid(65532)` + `Setuid(65532)` drops root across EVERY Go runtime OS thread (`AllThreadsSyscall`) BEFORE any
//     network socket is opened — allowing a shell-free `distroless` image with zero `su-exec` or `/bin/sh` surface.
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
	// Prevent any future `execve` (impossible in distroless anyway, defense in depth) from gaining privileges via setuid bits.
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPriv, 1, 0, 0, 0, 0); errno != 0 {
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
	if os.Geteuid() != nonrootUID || os.Getuid() != nonrootUID {
		return errors.New("privilege drop verification failed: uid/euid did not transition to 65532")
	}
	return nil
}
