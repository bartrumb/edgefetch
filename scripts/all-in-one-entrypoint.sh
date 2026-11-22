#!/bin/sh
set -eu

validate_otel_endpoint() {
  _val="${1:-}"
  [ -n "$_val" ] || return 1
  _clean="$(printf '%sX' "$_val" | LC_ALL=C tr -d '\001-\040\177')"
  [ "$_clean" = "${_val}X" ] || return 1
  case "$_val" in
    stdout|stderr) return 0 ;;
    http://*|https://*)
      _rest="${_val#https://}"
      [ "$_rest" = "$_val" ] && _rest="${_val#http://}"
      _host="${_rest%%[/?#]*}"
      [ -n "$_host" ] && return 0
      return 1
      ;;
    *) return 1 ;;
  esac
}

validate_otel_headers() {
  _raw="${1:-}"
  [ -n "$_raw" ] || return 1
  _clean="$(printf '%sX' "$_raw" | LC_ALL=C tr -d '\001-\037\177')"
  [ "$_clean" = "${_raw}X" ] || return 1
  case "$_raw" in
    ,*|*,|*,,*) return 1 ;;
  esac
  _rest="$_raw"
  while :; do
    case "$_rest" in
      *,*)
        _item="${_rest%%,*}"
        _rest="${_rest#*,}"
        ;;
      *)
        _item="$_rest"
        _rest=""
        ;;
    esac
    case "$_item" in
      *=*) ;;
      *) return 1 ;;
    esac
    _key="${_item%%=*}"
    while :; do case "$_key" in ' '*) _key="${_key# }" ;; *) break ;; esac; done
    while :; do case "$_key" in *' ') _key="${_key% }" ;; *) break ;; esac; done
    [ -n "$_key" ] || return 1
    _bad_key="$(printf '%s' "$_key" | LC_ALL=C tr -d 'A-Za-z0-9!#$%&*+.^_`|~\047-')"
    [ -z "$_bad_key" ] || return 1
    [ -n "$_rest" ] || break
  done
  return 0
}

if [ "${EDGEFETCH_ENTRYPOINT_LIB_ONLY:-0}" = "1" ]; then
  return 0 2>/dev/null || exit 0
fi

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

CUR_UID="$(id -u)"
if [ "$CUR_UID" != "0" ] && [ "${EDGEFETCH_DISABLE_LOCAL_AGENT:-0}" != "1" ] && [ "${EDGEFETCH_ALLOW_SHARED_UID:-0}" != "1" ]; then
  echo "ERROR: running EdgeFetch all-in-one with --user != 0 (uid=${CUR_UID}) disables UID separation between Hub and Chromium; set EDGEFETCH_ALLOW_SHARED_UID=1 or EDGEFETCH_DISABLE_LOCAL_AGENT=1 to override." >&2
  exit 1
fi
if [ "$CUR_UID" = "0" ]; then
  # H3 UID Isolation: keep Hub SQLite + artifacts inside `0700` `node:node` `/data/hub` (with `0710` `root:node` `/data`
  # so UID `65532` has zero `---` traverse/read/write bits on `/data` itself, even across upgrades from older volumes).
  if [ -z "${EDGEFETCH_DATA_DIR:-}" ] || [ "${EDGEFETCH_DATA_DIR}" = "/data" ]; then
    EDGEFETCH_DATA_DIR="/data/hub"
  fi
  export EDGEFETCH_DATA_DIR
  mkdir -p /data "$EDGEFETCH_DATA_DIR"
  if [ "$EDGEFETCH_DATA_DIR" = "/data/hub" ] && [ -f /data/edgefetch-hub.sqlite ] && [ ! -f /data/hub/edgefetch-hub.sqlite ]; then
    for legacy in /data/edgefetch-hub.sqlite /data/edgefetch-hub.sqlite-wal /data/edgefetch-hub.sqlite-shm /data/artifacts; do
      [ -e "$legacy" ] && mv "$legacy" /data/hub/
    done
  fi
  chown root:node /data
  chmod 0710 /data
  chown -R node:node "$EDGEFETCH_DATA_DIR"
  chmod 0700 "$EDGEFETCH_DATA_DIR"

  su-exec node:node node /app/hub/dist/portable-server.mjs &
  HUB_PID=$!
else
  EDGEFETCH_DATA_DIR="${EDGEFETCH_DATA_DIR:-/data/hub}"
  export EDGEFETCH_DATA_DIR
  mkdir -p "$EDGEFETCH_DATA_DIR" 2>/dev/null || true
  node /app/hub/dist/portable-server.mjs &
  HUB_PID=$!
fi

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
  # H3 + H9 + M7 Security Invariant: Launch the local worker as isolated UID `65532:65532` with `env -i` so Hub
  # secrets (`CALLER_TOKEN`, LLM API keys, `BOT_SIGNING_PRIVATE_KEY`, `TURSO_AUTH_TOKEN`, S3 keys) are NEVER present
  # in the worker or Chromium `/proc/self/environ`, while forwarding explicit worker-scoped settings cleanly.
  set -- \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME="/tmp" \
    TMPDIR="/tmp" \
    EDGEFETCH_CHROME_BIN="${EDGEFETCH_CHROME_BIN:-/usr/lib/chromium/chromium}" \
    GOMEMLIMIT="${GOMEMLIMIT:-384MiB}" \
    EDGEFETCH_ALLOW_INSECURE_HUB=1 \
    EDGEFETCH_HUB_URL="http://127.0.0.1:${PORT}" \
    EDGEFETCH_AGENT_TOKEN="${AGENT_TOKEN}" \
    EDGEFETCH_SITE_ID="${EDGEFETCH_SITE_ID:-local-fat-1}" \
    EDGEFETCH_ALLOWED_HOSTS="${EDGEFETCH_ALLOWED_HOSTS:-}" \
    EDGEFETCH_ROBOTS_BYPASS_HOSTS="${EDGEFETCH_ROBOTS_BYPASS_HOSTS:-${CRAWLER_ROBOTS_BYPASS_HOSTS:-}}" \
    EDGEFETCH_REQUIRE_BROWSER_SANDBOX="${EDGEFETCH_REQUIRE_BROWSER_SANDBOX:-}" \
    EDGEFETCH_ALLOW_NO_SANDBOX="${EDGEFETCH_ALLOW_NO_SANDBOX:-}" \
    EDGEFETCH_USER_AGENT="${EDGEFETCH_USER_AGENT:-}" \
    EDGEFETCH_PAUSE_MS="${EDGEFETCH_PAUSE_MS:-}" \
    EDGEFETCH_PAUSE_JITTER_MS="${EDGEFETCH_PAUSE_JITTER_MS:-}"
  [ -n "${TZ:-}" ] && set -- "$@" TZ="$TZ"
  [ -n "${SSL_CERT_FILE:-}" ] && set -- "$@" SSL_CERT_FILE="$SSL_CERT_FILE"
  if [ -n "${OTEL_EXPORTER_OTLP_ENDPOINT:-}" ]; then
    if validate_otel_endpoint "$OTEL_EXPORTER_OTLP_ENDPOINT"; then
      set -- "$@" OTEL_EXPORTER_OTLP_ENDPOINT="$OTEL_EXPORTER_OTLP_ENDPOINT"
    else
      echo "WARN: ignoring invalid OTEL_EXPORTER_OTLP_ENDPOINT for isolated worker" >&2
    fi
  fi
  if [ -n "${OTEL_EXPORTER_OTLP_HEADERS:-}" ]; then
    if validate_otel_headers "$OTEL_EXPORTER_OTLP_HEADERS"; then
      set -- "$@" OTEL_EXPORTER_OTLP_HEADERS="$OTEL_EXPORTER_OTLP_HEADERS"
    else
      echo "WARN: ignoring invalid OTEL_EXPORTER_OTLP_HEADERS for isolated worker" >&2
    fi
  fi

  if [ "$CUR_UID" = "0" ]; then
    su-exec 65532:65532 env -i "$@" /usr/local/bin/edgefetch --mode=agent &
  else
    env -i "$@" /usr/local/bin/edgefetch --mode=agent &
  fi
  AGENT_PID=$!
fi

wait "$HUB_PID"
