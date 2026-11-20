#!/bin/sh
set -eu

PORT="${PORT:-8787}"
export PORT

if [ -z "${CALLER_TOKEN:-}" ] && [ -n "${EDGEFETCH_CALLER_TOKEN:-}" ]; then
  export CALLER_TOKEN="$EDGEFETCH_CALLER_TOKEN"
fi

# Generate an ephemeral internal loopback agent token when external AGENT_TOKEN is unset so the bundled Go worker
# connects immediately out-of-the-box on Fly.io / Railway / Render / Docker!
if [ -z "${AGENT_TOKEN:-}" ]; then
  AGENT_TOKEN="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  export AGENT_TOKEN
fi

node /app/hub/dist/portable-server.mjs &
HUB_PID=$!

cleanup() {
  kill -TERM "$HUB_PID" 2>/dev/null || true
  if [ -n "${AGENT_PID:-}" ]; then
    kill -TERM "$AGENT_PID" 2>/dev/null || true
  fi
  wait
}
trap cleanup INT TERM

if [ "${EDGEFETCH_DISABLE_LOCAL_AGENT:-0}" != "1" ]; then
  sleep 1
  # H9 Security Invariant: Launch the local worker with `env -i` so Hub secrets (`CALLER_TOKEN`, LLM API keys,
  # `BOT_SIGNING_PRIVATE_KEY`, `TURSO_AUTH_TOKEN`, S3 keys) are NEVER present in the worker or Chromium `/proc/self/environ`!
  env -i \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME="/tmp" \
    TMPDIR="/tmp" \
    EDGEFETCH_CHROME_BIN="${EDGEFETCH_CHROME_BIN:-/usr/lib/chromium/chromium}" \
    GOMEMLIMIT="${GOMEMLIMIT:-384MiB}" \
    EDGEFETCH_ALLOW_INSECURE_HUB=1 \
    EDGEFETCH_HUB_URL="http://127.0.0.1:${PORT}" \
    EDGEFETCH_AGENT_TOKEN="${AGENT_TOKEN}" \
    EDGEFETCH_SITE_ID="${EDGEFETCH_SITE_ID:-local-fat-1}" \
    OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-}" \
    /usr/local/bin/edgefetch --mode=agent &
  AGENT_PID=$!
fi

wait "$HUB_PID"
