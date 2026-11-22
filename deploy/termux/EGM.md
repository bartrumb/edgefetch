# Termux Agent Installer (`deploy/termux`)

## Overview

Provides a turnkey shell installer (`install-termux-agent.sh`) that provisions an Android device running Termux and Termux:Boot as an outbound-only EdgeFetch worker node (`edgefetch --mode=agent`). The script verifies GitHub release artifacts with a pinned Ed25519 public key and SHA-256 checksums before installing the binary, persisting credentials, registering a boot startup script, and launching the background agent daemon.

## Interface

- `[install-termux-agent.sh:EDGEFETCH_HUB_URL]`: Required environment variable specifying the target EdgeFetch Hub endpoint URL; exported into `$HOME/.config/edgefetch/agent.env`.
- `[install-termux-agent.sh:EDGEFETCH_AGENT_TOKEN]`: Required environment variable specifying the shared or site-scoped agent authentication secret; exported into `$HOME/.config/edgefetch/agent.env`.
- `[install-termux-agent.sh:EDGEFETCH_VERSION]`: Optional environment variable (assigned to `VERSION`, default `2.7.1`) selecting the GitHub release tag (`v${VERSION}`) to download.
- `[install-termux-agent.sh:EDGEFETCH_SITE_ID]`: Optional environment variable (assigned to `SITE_ID`, default `android-termux-1`) identifying the worker node; exported into `$HOME/.config/edgefetch/agent.env`.
- `[install-termux-agent.sh:PREFIX]`: Termux runtime prefix environment variable used to locate `BIN_DIR="$PREFIX/bin"` and invoked in `$HOME/.termux/boot/start-edgefetch.sh`.
- `[install-termux-agent.sh:sq_escape]`: Internal shell helper function that single-quotes strings and escapes embedded single quotes before writing `export` statements to `agent.env`.

## Invariants

- `[install-termux-agent.sh:set -euo pipefail]`: Aborts immediately on non-zero command exits, unset variables, or pipeline failures, cleaning up `tmp_dir` via `trap 'rm -rf "$tmp_dir"' EXIT`.
- `[install-termux-agent.sh:EDGEFETCH_HUB_URL]` / `[install-termux-agent.sh:EDGEFETCH_AGENT_TOKEN]`: Both variables must be non-empty at invocation or the installer exits with status `1`.
- `[install-termux-agent.sh:VERSION]`: Release version string must match `^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$` before constructing `BASE_URL` or `ARCHIVE`.
- `[install-termux-agent.sh:openssl pkeyutl]` / `[install-termux-agent.sh:sha256sum]`: `checksums.txt` must pass raw Ed25519 signature verification (`checksums.txt.sig`) against the pinned public key (`MCowBQYDK2VwAyEAv8+ZT9d/404KI0pY1PILOVBzsUvTHWaL0aLghciWy90=`), contain an exact filename entry for `edgefetch_${VERSION}_linux_${GOARCH}.tar.gz` (`EXPECTED_LINE`), and pass `sha256sum -c -` prior to `tar` extraction.
- `[install-termux-agent.sh:umask 077]` / `[install-termux-agent.sh:chmod 0600]`: Credential file `$HOME/.config/edgefetch/agent.env` is created under `umask 077`, explicitly restricted to mode `0600`, and pins `GOMEMLIMIT='96MiB'`.

## Side Effects

- `[install-termux-agent.sh:pkg]`: Updates Termux package metadata (`pkg update -y`) and installs `coreutils`, `curl`, `openssl-tool`, `tar`, `termux-api`, and `termux-services`.
- `[install-termux-agent.sh:curl]` / `[install-termux-agent.sh:tmp_dir]`: Creates a temporary directory via `mktemp -d` and fetches `checksums.txt`, `checksums.txt.sig`, and `edgefetch_${VERSION}_linux_${GOARCH}.tar.gz` over HTTPS from `https://github.com/bartrumb/edgefetch/releases/download/v${VERSION}`.
- `[install-termux-agent.sh:BIN_DIR]`: Extracts `edgefetch` into `$PREFIX/bin/edgefetch` with mode `0755`.
- `[install-termux-agent.sh:HOME]`: Creates `$HOME/.config/edgefetch` and `$HOME/.termux/boot`, writes `$HOME/.config/edgefetch/agent.env` (`0600`), and writes `$HOME/.termux/boot/start-edgefetch.sh` (`0755`).
- `[install-termux-agent.sh:termux-wake-lock]` / `[install-termux-agent.sh:pkill]` / `[install-termux-agent.sh:nohup]`: Acquires an Android wake lock, terminates existing `edgefetch --mode=agent` processes, sources `agent.env`, and spawns `$BIN_DIR/edgefetch --mode=agent` in the background redirecting stdout/stderr to `$HOME/.config/edgefetch/agent.log`.

## Verification

- Run: `bash -n deploy/termux/install-termux-agent.sh`
