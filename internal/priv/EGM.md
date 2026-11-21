# priv

## Overview
Package `priv` drops root OS privileges on Linux process startup (`UID 0` to `65532:65532` with `PR_SET_NO_NEW_PRIVS` across all Go runtime OS threads) and provides a no-op stub on non-Linux platforms.

## Interface
- `[priv_linux.go:LockDownSecretPaths]` (`//go:build linux`): `func LockDownSecretPaths(paths ...string)` — restricts secret configuration files (such as `/data/options.json`) to `0600` `0:0` and `/data` to `0700` `0:0` while `os.Geteuid() == 0` right before `DropRoot()`.
- `[priv_other.go:LockDownSecretPaths]` (`//go:build !linux`): `func LockDownSecretPaths(_ ...string)` — no-op stub on non-Linux targets.
- `[priv_linux.go:DropRoot]` (`//go:build linux`): `func DropRoot() error` — transitions real, effective, and saved UID/GID `0` to `65532:65532` and enables `PR_SET_NO_NEW_PRIVS` across all Go OS threads; returns `nil` immediately when `os.Geteuid() != 0`.
- `[priv_other.go:DropRoot]` (`//go:build !linux`): `func DropRoot() error` — no-op stub returning `nil` on non-Linux targets.

## Invariants
- `[priv_linux.go://go:build linux]`, `[priv_other.go://go:build !linux]`: Mutually exclusive build constraints partition the Linux syscall implementation from the non-Linux stub.
- `[priv_linux.go:DropRoot]`: Applies best-effort `PR_SET_NO_NEW_PRIVS` and `PR_SET_DUMPABLE=0` when started directly as non-root (`os.Geteuid() != 0`), and enforces strict drop ordering when `euid == 0`: (1) `syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetNoNewPriv, 1, 0, 0, 0, 0)` (`prSetNoNewPriv = 38`), (2) `syscall.Setgroups([]int{})`, (3) `syscall.Setgid(nonrootUID)` (`65532`), (4) `syscall.Setuid(nonrootUID)` (`65532`), and (5) `syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0)` (`prSetDumpable = 4`, executed after `Setuid` so Linux `commit_creds` cannot reset `mm->dumpable`).
- `[priv_linux.go:DropRoot]`: Post-drop verification requires `os.Geteuid() == 65532`, `os.Getuid() == 65532`, `os.Getegid() == 65532`, `os.Getgid() == 65532`, and `os.Getgroups()` containing no group `0`.

## Side Effects
- `[priv_linux.go:DropRoot]`: Invokes `syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0)` to set `PR_SET_NO_NEW_PRIVS` irreversibly across all Go runtime OS threads.
- `[priv_linux.go:DropRoot]`: Invokes `syscall.Setgroups([]int{})`, `syscall.Setgid(65532)`, and `syscall.Setuid(65532)`, clearing supplementary groups and permanently transitioning process GID/UID to `65532`.
- `[priv_linux.go:DropRoot]`: Queries OS process credentials via `os.Geteuid`, `os.Getuid`, `os.Getegid`, `os.Getgid`, and `os.Getgroups`.

## Verification
- Run: `go test ./internal/priv`
