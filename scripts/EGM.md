# scripts

## Overview

`scripts` contains the POSIX shell container entrypoint (`all-in-one-entrypoint.sh`) for the all-in-one EdgeFetch image (`Dockerfile.all-in-one`). It bootstraps the Pure-Go Hub server (`/usr/local/bin/edgefetch --mode=hub` as UID `1000:1000`, with `EDGEFETCH_DISABLE_FALLBACK_CRAWLER=1` when the worker is active) alongside an optional sandboxed local Go agent (`/usr/local/bin/edgefetch --mode=agent` as UID `65532:65532`) with `env -i` secret isolation and signal forwarding.

## Interface

- `[all-in-one-entrypoint.sh:#!/bin/sh]` — POSIX shell container entrypoint script (`/bin/sh`).
- `[all-in-one-entrypoint.sh:PORT]` — Exported environment variable configuring the Hub listen port and local agent target port (default `8787`).
- `[all-in-one-entrypoint.sh:CALLER_TOKEN]` — Hub caller authentication token environment variable (exported from `EDGEFETCH_CALLER_TOKEN` if `CALLER_TOKEN` is unset or empty).
- `[all-in-one-entrypoint.sh:EDGEFETCH_CALLER_TOKEN]` — Fallback caller authentication environment variable aliased into `CALLER_TOKEN`.
- `[all-in-one-entrypoint.sh:AGENT_TOKEN]` — Hub/agent authentication token environment variable (auto-generated as 48 hex characters from `/dev/urandom` if unset or empty, exported to Hub, and passed to the local agent as `EDGEFETCH_AGENT_TOKEN`).
- `[all-in-one-entrypoint.sh:EDGEFETCH_DISABLE_LOCAL_AGENT]` — Environment toggle (default `0`); setting `"1"` skips launching the local Go agent.
- `[all-in-one-entrypoint.sh:EDGEFETCH_CHROME_BIN]` — Chromium binary path passed to the local agent (default `/usr/lib/chromium/chromium`).
- `[all-in-one-entrypoint.sh:GOMEMLIMIT]` — Go runtime memory limit passed to the local agent (default `384MiB`).
- `[all-in-one-entrypoint.sh:EDGEFETCH_SITE_ID]` — Site identifier passed to the local agent (default `local-fat-1`).
- `[all-in-one-entrypoint.sh:OTEL_EXPORTER_OTLP_ENDPOINT]` — OTLP telemetry endpoint passed through to the local agent (default `""`).
- `[all-in-one-entrypoint.sh:--mode=agent]` — Launches `/usr/local/bin/edgefetch --mode=agent` targeting `http://127.0.0.1:${PORT}` with `EDGEFETCH_ALLOW_INSECURE_HUB=1`.
- `[all-in-one-entrypoint.sh:cleanup]` — `INT` and `TERM` trap handler forwarding `SIGTERM` to `HUB_PID` and `AGENT_PID` before waiting.

## Invariants

- `[all-in-one-entrypoint.sh:set -eu]` — Executes with fail-on-error (`-e`) and fail-on-unset-variable (`-u`) enabled.
- `[all-in-one-entrypoint.sh:AGENT_TOKEN]` — Guarantees `AGENT_TOKEN` is non-empty before spawning either the Hub or the local agent.
- `[all-in-one-entrypoint.sh:env -i]` — H9 Security Invariant: launches `/usr/local/bin/edgefetch --mode=agent` under `env -i` with an explicit variable allowlist (`PATH`, `HOME=/tmp`, `TMPDIR=/tmp`, `EDGEFETCH_CHROME_BIN`, `GOMEMLIMIT`, `EDGEFETCH_ALLOW_INSECURE_HUB=1`, `EDGEFETCH_HUB_URL`, `EDGEFETCH_AGENT_TOKEN`, `EDGEFETCH_SITE_ID`, `OTEL_EXPORTER_OTLP_ENDPOINT`) so Hub secrets (`CALLER_TOKEN`, LLM keys, `BOT_SIGNING_PRIVATE_KEY`, `TURSO_AUTH_TOKEN`, S3 keys) never enter the worker or Chromium process environment.
- `[all-in-one-entrypoint.sh:HUB_PID]` — Blocks in the foreground on `wait "$HUB_PID"`, binding container lifecycle to the Hub server process.
- `[all-in-one-entrypoint.sh:cleanup]` — Ensures `INT` and `TERM` traps send `SIGTERM` to both `HUB_PID` and `AGENT_PID` (when running) and `wait` before exiting.

## Side Effects

- `[all-in-one-entrypoint.sh:PORT]` — Exports `PORT` (and conditionally `CALLER_TOKEN` and `AGENT_TOKEN`) in the shell environment.
- `[all-in-one-entrypoint.sh:/dev/urandom]` — Reads 24 random bytes from `/dev/urandom` via `head`, `od`, and `tr` when `AGENT_TOKEN` is unset or empty.
- `[all-in-one-entrypoint.sh:HUB_PID]` — Spawns `/usr/local/bin/edgefetch --mode=hub --addr="0.0.0.0:${PORT}"` under `su-exec 1000:1000` in the background.
- `[all-in-one-entrypoint.sh:trap]` — Installs `INT` and `TERM` signal handlers on the entrypoint shell.
- `[all-in-one-entrypoint.sh:AGENT_PID]` — Sleeps 1 second (`sleep 1`) and spawns `/usr/local/bin/edgefetch --mode=agent` in the background connecting to `http://127.0.0.1:${PORT}` unless `EDGEFETCH_DISABLE_LOCAL_AGENT="1"`.
- `[all-in-one-entrypoint.sh:cleanup]` — Sends `SIGTERM` (`kill -TERM`) to `$HUB_PID` and `$AGENT_PID` upon termination signals.

## Verification

- Run: `make test`
