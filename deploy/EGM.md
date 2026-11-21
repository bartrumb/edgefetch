# Deployment & Provisioning (`deploy`)

## Overview

Groups host-level provisioning scripts and deployment definitions for running outbound-only EdgeFetch worker nodes (`edgefetch --mode=agent`). Executable shell provisioners with EGM contracts live under `proxmox` and `termux`; both enforce strict `set -euo pipefail` execution, pinned Ed25519 signature (`checksums.txt.sig`) plus SHA-256 verification of GitHub release archives prior to installation, and `0600` shell-escaped credential files (`EDGEFETCH_HUB_URL`, `EDGEFETCH_AGENT_TOKEN`, `EDGEFETCH_SITE_ID`, `GOMEMLIMIT`). Alongside those scripted installers, this directory also contains static declarative manifest subdirectories without executable source code or `EGM.md` contracts: `casaos` (`docker-compose.yml`), `k8s` (`agent-deployment.yaml`), `unraid` (`edgefetch-agent.xml`), and `winget` (`BartrumB.EdgeFetch.yaml`).

## Subdirectories & Boundaries

- [proxmox](./proxmox/EGM.md) - Turnkey Proxmox VE unprivileged Alpine Linux 3.21+ LXC provisioner (`create-edgefetch-lxc.sh`) supporting `fat` (512 MiB RAM, Chromium + Poppler) and `lite` (64 MiB RAM, HTTP/2) profiles supervised by OpenRC (`/etc/init.d/edgefetch`).
- [termux](./termux/EGM.md) - Turnkey Android Termux + Termux:Boot installer (`install-termux-agent.sh`) that verifies and installs the `edgefetch` binary into `$PREFIX/bin`, configures `$HOME/.config/edgefetch/agent.env`, registers `$HOME/.termux/boot/start-edgefetch.sh`, and starts the background worker under `termux-wake-lock`.
