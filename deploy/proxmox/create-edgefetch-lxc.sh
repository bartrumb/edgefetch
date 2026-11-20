#!/usr/bin/env bash
# Proxmox VE Turnkey Unprivileged Alpine Linux LXC Provisioner for EdgeFetch (`deploy/proxmox/create-edgefetch-lxc.sh`).
#
# Creates a lightweight unprivileged Alpine LXC (`64 MiB` RAM in Lite mode or `512 MiB` RAM in Chromium Fat mode)
# supervised by OpenRC (`/etc/init.d/edgefetch`) — zero Docker VM overhead, zero open inbound router ports!
# Verifies both SHA-256 and the owner's Ed25519 signature (`checksums.txt.sig`) before extracting the release archive.
#
# Usage (run on your Proxmox VE host shell):
#   EDGEFETCH_HUB_URL="https://edgefetch.example.com" \
#   EDGEFETCH_AGENT_TOKEN="<32-char-secret>" \
#   EDGEFETCH_SITE_ID="pve-lxc-1" \
#   bash create-edgefetch-lxc.sh
set -euo pipefail

CTID="${CTID:-$(pvesh get /cluster/nextid)}"
HOSTNAME="${EDGEFETCH_SITE_ID:-edgefetch-lxc}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
BRIDGE="${BRIDGE:-vmbr0}"
PROFILE="${EDGEFETCH_PROFILE:-fat}" # "fat" (Chromium + Poppler, 512 MiB RAM) or "lite" (HTTP/2 + pure-Go PDF, 64 MiB RAM)
VERSION="${EDGEFETCH_VERSION:-2.5.4}"

if [[ -z "${EDGEFETCH_HUB_URL:-}" || -z "${EDGEFETCH_AGENT_TOKEN:-}" ]]; then
  echo "ERROR: EDGEFETCH_HUB_URL and EDGEFETCH_AGENT_TOKEN must be set." >&2
  exit 1
fi

if [[ "$PROFILE" != "fat" && "$PROFILE" != "lite" ]]; then
  echo "ERROR: EDGEFETCH_PROFILE must be 'fat' or 'lite' (got '${PROFILE}')." >&2
  exit 1
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
  echo "ERROR: Invalid EDGEFETCH_VERSION '${VERSION}'." >&2
  exit 1
fi

if [[ ! "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]]; then
  echo "ERROR: EDGEFETCH_SITE_ID must be a safe hostname identifier." >&2
  exit 1
fi

RAM_MB=512
DISK_GB=2
CORES=2
if [[ "$PROFILE" == "lite" ]]; then
  RAM_MB=64
  DISK_GB=1
  CORES=1
fi
GOMEMLIMIT_VAL="$((RAM_MB * 3 / 4))MiB"

echo "==> Updating Proxmox template catalog and locating Alpine 3.21+ template..."
pveam update >/dev/null
ALPINE_TPL="$(pveam available -section system | awk '/alpine-3\.(2[0-9])/{print $2}' | sort -V | tail -n1)"
if [[ -z "$ALPINE_TPL" ]]; then
  echo "ERROR: Could not find Alpine 3.21+ LXC template in pveam." >&2
  exit 1
fi
pveam download "$TEMPLATE_STORAGE" "$ALPINE_TPL"

echo "==> Creating unprivileged Alpine LXC CT ${CTID} (${HOSTNAME}, ${PROFILE} profile, ${RAM_MB} MiB RAM)..."
pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${ALPINE_TPL}" \
  --hostname "$HOSTNAME" \
  --unprivileged 1 \
  --features nesting=1 \
  --cores "$CORES" \
  --memory "$RAM_MB" \
  --swap 128 \
  --rootfs "${STORAGE}:${DISK_GB}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp,ip6=auto" \
  --onboot 1 \
  --start 1

sleep 3

ARCH="$(uname -m)"
GOARCH="amd64"
[[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && GOARCH="arm64"

echo "==> Verifying Ed25519 release signature & installing EdgeFetch v${VERSION} (${GOARCH}) inside CT ${CTID}..."
pct exec "$CTID" -- env PROFILE="$PROFILE" VERSION="$VERSION" GOARCH="$GOARCH" sh -euc '
  apk update
  apk add --no-cache ca-certificates curl openssl tar tzdata
  if [ "$PROFILE" = "fat" ]; then
    apk add --no-cache chromium chromium-swiftshader font-noto poppler-utils ttf-freefont
  fi
  addgroup -S edgefetch || true
  adduser -S -D -H -G edgefetch edgefetch || true

  tmp_dir="$(mktemp -d)"
  trap "rm -rf \"$tmp_dir\"" EXIT
  archive="edgefetch_${VERSION}_linux_${GOARCH}.tar.gz"
  base_url="https://github.com/bartrumb/edgefetch/releases/download/v${VERSION}"

  cat >"$tmp_dir/release-signing-pub.pem" <<'\''PUBEOF'\''
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAeTr4Ryc8TmHsN8gDk0mC61tN3BFD2dHUfqCBrMeoex0=
-----END PUBLIC KEY-----
PUBEOF

  curl -fsSL "${base_url}/checksums.txt" -o "$tmp_dir/checksums.txt"
  curl -fsSL "${base_url}/checksums.txt.sig" -o "$tmp_dir/checksums.txt.sig"
  openssl pkeyutl -verify -pubin -inkey "$tmp_dir/release-signing-pub.pem" \
    -rawin -in "$tmp_dir/checksums.txt" -sigfile "$tmp_dir/checksums.txt.sig"

  curl -fsSL "${base_url}/${archive}" -o "$tmp_dir/${archive}"
  expected_line="$(awk -v f="$archive" '\''$2 == f { print $1 "  " $2 }'\'' "$tmp_dir/checksums.txt")"
  if [ -z "$expected_line" ]; then
    echo "ERROR: ${archive} missing from verified checksums.txt" >&2
    exit 1
  fi
  (cd "$tmp_dir" && printf "%s\n" "$expected_line" | sha256sum -c -)
  tar -xzf "$tmp_dir/${archive}" -C /usr/local/bin edgefetch
  chmod 0755 /usr/local/bin/edgefetch
'

# Write /etc/conf.d/edgefetch via stdin with strict single-quote shell escaping (never interpolating secrets into sh -c).
sq_escape() {
  printf "'%s'" "${1//\'/\'\"\'\"\'}"
}

{
  printf 'EDGEFETCH_HUB_URL=%s\n' "$(sq_escape "$EDGEFETCH_HUB_URL")"
  printf 'EDGEFETCH_AGENT_TOKEN=%s\n' "$(sq_escape "$EDGEFETCH_AGENT_TOKEN")"
  printf 'EDGEFETCH_SITE_ID=%s\n' "$(sq_escape "$HOSTNAME")"
  printf 'GOMEMLIMIT=%s\n' "$(sq_escape "$GOMEMLIMIT_VAL")"
} | pct exec "$CTID" -- sh -euc 'umask 077; cat >/etc/conf.d/edgefetch; chmod 0600 /etc/conf.d/edgefetch'

pct exec "$CTID" -- sh -euc '
  cat >/etc/init.d/edgefetch <<'\''EOF'\''
#!/sbin/openrc-run
name="edgefetch"
description="EdgeFetch Outbound WebSocket Crawl Worker"
command="/usr/local/bin/edgefetch"
command_args="--mode=agent"
command_user="edgefetch:edgefetch"
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/edgefetch.log"
error_log="/var/log/edgefetch.err"

depend() {
  need net
  after firewall
}

start_pre() {
  set -a
  [ -f /etc/conf.d/edgefetch ] && . /etc/conf.d/edgefetch
  set +a
  export EDGEFETCH_HUB_URL EDGEFETCH_AGENT_TOKEN EDGEFETCH_SITE_ID GOMEMLIMIT
}
EOF
  chmod 0755 /etc/init.d/edgefetch
  rc-update add edgefetch default
  rc-service edgefetch start
'

echo "==> Done! EdgeFetch CT ${CTID} (${HOSTNAME}) is online and connected to ${EDGEFETCH_HUB_URL}."
