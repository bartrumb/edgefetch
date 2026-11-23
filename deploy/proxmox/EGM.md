# Proxmox VE LXC Provisioner (`deploy/proxmox`)

## Overview

Provides a turnkey Proxmox VE host provisioner (`create-edgefetch-lxc.sh`) that creates an unprivileged Alpine Linux 3.21+ LXC container (`lite` 64 MiB HTTP/2 profile or `fat` 512 MiB Headless Chromium + Poppler PDF profile) running `edgefetch --mode=agent` under OpenRC (`/etc/init.d/edgefetch`). Release tarballs are cryptographically verified via a pinned Ed25519 signature and SHA-256 checksum inside the container before installation.

## Interface

- `[create-edgefetch-lxc.sh:EDGEFETCH_HUB_URL]`: Required environment variable specifying the EdgeFetch Hub URL; streamed to `/etc/conf.d/edgefetch` and exported to the agent daemon.
- `[create-edgefetch-lxc.sh:EDGEFETCH_AGENT_TOKEN]`: Required environment variable specifying the agent authentication secret; streamed to `/etc/conf.d/edgefetch` and exported to the agent daemon.
- `[create-edgefetch-lxc.sh:CTID]`: Optional environment variable (default `$(pvesh get /cluster/nextid)`) selecting the Proxmox LXC container ID.
- `[create-edgefetch-lxc.sh:EDGEFETCH_SITE_ID]`: Optional environment variable (assigned to `HOSTNAME`, default `edgefetch-lxc`) setting both the container `--hostname` and runtime `EDGEFETCH_SITE_ID`.
- `[create-edgefetch-lxc.sh:STORAGE]` / `[create-edgefetch-lxc.sh:TEMPLATE_STORAGE]` / `[create-edgefetch-lxc.sh:BRIDGE]`: Optional Proxmox host configuration environment variables defaulting to `local-lvm` (container rootfs), `local` (LXC template storage), and `vmbr0` (`eth0` network bridge).
- `[create-edgefetch-lxc.sh:EDGEFETCH_PROFILE]`: Optional sizing profile environment variable (assigned to `PROFILE`, default `fat`): `fat` allocates 512 MiB RAM, 2 GiB disk, 2 CPU cores, and installs `chromium`, `chromium-swiftshader`, `font-noto`, `poppler-utils`, and `ttf-freefont`; `lite` allocates 64 MiB RAM, 1 GiB disk, and 1 CPU core.
- `[create-edgefetch-lxc.sh:EDGEFETCH_VERSION]`: Optional environment variable (assigned to `VERSION`, default `2.7.7`) selecting the GitHub release version (`v${VERSION}`) to install.
- `[create-edgefetch-lxc.sh:sq_escape]`: Internal shell helper function that single-quotes strings and escapes embedded single quotes before streaming configuration over `pct exec` stdin.
- `[create-edgefetch-lxc.sh:name]` / `[create-edgefetch-lxc.sh:depend]` / `[create-edgefetch-lxc.sh:start_pre]`: Generated OpenRC service `/etc/init.d/edgefetch` executing `/usr/local/bin/edgefetch --mode=agent` in background as `edgefetch:edgefetch` after `net` and `firewall`, sourcing `/etc/conf.d/edgefetch` and exporting `EDGEFETCH_HUB_URL`, `EDGEFETCH_AGENT_TOKEN`, `EDGEFETCH_SITE_ID`, and `GOMEMLIMIT`.

## Invariants

- `[create-edgefetch-lxc.sh:set -euo pipefail]`: Enforces strict fail-fast execution on the Proxmox host and `sh -euc` inside `pct exec` guest subshells.
- `[create-edgefetch-lxc.sh:EDGEFETCH_HUB_URL]` / `[create-edgefetch-lxc.sh:EDGEFETCH_AGENT_TOKEN]`: Both variables must be non-empty or the script exits with status `1` prior to container provisioning.
- `[create-edgefetch-lxc.sh:PROFILE]` / `[create-edgefetch-lxc.sh:VERSION]` / `[create-edgefetch-lxc.sh:HOSTNAME]`: `PROFILE` must equal `fat` or `lite`; `VERSION` must match `^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$`; `HOSTNAME` must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$` or execution aborts with status `1`.
- `[create-edgefetch-lxc.sh:GOMEMLIMIT_VAL]`: `GOMEMLIMIT` is derived deterministically as `$((RAM_MB * 3 / 4))MiB` (`384MiB` for `fat`, `48MiB` for `lite`).
- `[create-edgefetch-lxc.sh:CTID]` / `[create-edgefetch-lxc.sh:command_user]`: Container is provisioned unprivileged (`--unprivileged 1 --features nesting=1`) and runs the worker daemon as unprivileged system account `edgefetch:edgefetch`.
- `[create-edgefetch-lxc.sh:archive]` / `[create-edgefetch-lxc.sh:expected_line]`: `checksums.txt` must pass OpenSSL raw Ed25519 verification (`checksums.txt.sig`) against pinned public key `MCowBQYDK2VwAyEAv8+ZT9d/404KI0pY1PILOVBzsUvTHWaL0aLghciWy90=` and `edgefetch_${VERSION}_linux_${GOARCH}.tar.gz` must pass `sha256sum -c -` before extraction to `/usr/local/bin/edgefetch`.
- `[create-edgefetch-lxc.sh:sq_escape]`: Secrets in `/etc/conf.d/edgefetch` are piped via stdin (never interpolated into `sh -c` command arguments) under `umask 077` with mode `0600`.

## Side Effects

- `[create-edgefetch-lxc.sh:CTID]` / `[create-edgefetch-lxc.sh:ALPINE_TPL]`: Queries `pvesh get /cluster/nextid` (if `CTID` is unset), refreshes the Proxmox appliance catalog (`pveam update`), downloads the latest `alpine-3.2x` template (`pveam download`), and creates/starts LXC container `CTID` via `pct create` (`--onboot 1 --start 1`).
- `[create-edgefetch-lxc.sh:PROFILE]`: Executes `apk update` and `apk add` inside `CTID` (`ca-certificates`, `curl`, `openssl`, `tar`, `tzdata`, plus Chromium/Poppler packages when `PROFILE="fat"`) and creates system group/user `edgefetch`.
- `[create-edgefetch-lxc.sh:base_url]`: Downloads `checksums.txt`, `checksums.txt.sig`, and `edgefetch_${VERSION}_linux_${GOARCH}.tar.gz` over HTTPS from GitHub Releases inside `CTID` into a trap-cleaned temporary directory and installs `/usr/local/bin/edgefetch` (`0755`).
- `[create-edgefetch-lxc.sh:name]`: Writes `/etc/conf.d/edgefetch` (`0600`) and `/etc/init.d/edgefetch` (`0755`), enables `edgefetch` in the `default` OpenRC runlevel (`rc-update add edgefetch default`), and starts the service (`rc-service edgefetch start`).

## Verification

- Run: `bash -n deploy/proxmox/create-edgefetch-lxc.sh`
