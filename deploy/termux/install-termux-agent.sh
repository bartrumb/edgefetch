#!/data/data/com.termux/files/usr/bin/bash
# Android Termux + Termux:Boot 1-Command Installer (`deploy/termux/install-termux-agent.sh`).
#
# Turns any spare Android phone or tablet (plugged into USB power on home Wi-Fi or 5G SIM)
# into an always-on ~15 MiB RAM `linux/arm64` EdgeFetch outbound worker node!
# Verifies both SHA-256 and the owner's Ed25519 signature (`checksums.txt.sig`) before extracting the release archive.
#
# Usage inside Termux:
#   EDGEFETCH_HUB_URL="https://edgefetch.example.com" \
#   EDGEFETCH_AGENT_TOKEN="<32-char-secret>" \
#   EDGEFETCH_SITE_ID="pixel-5g-node" \
#   bash install-termux-agent.sh
set -euo pipefail

VERSION="${EDGEFETCH_VERSION:-2.5.3}"
if [[ -z "${EDGEFETCH_HUB_URL:-}" || -z "${EDGEFETCH_AGENT_TOKEN:-}" ]]; then
  echo "ERROR: Set EDGEFETCH_HUB_URL and EDGEFETCH_AGENT_TOKEN before running." >&2
  exit 1
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
  echo "ERROR: Invalid EDGEFETCH_VERSION '${VERSION}'." >&2
  exit 1
fi
SITE_ID="${EDGEFETCH_SITE_ID:-android-termux-1}"

pkg update -y
pkg install -y coreutils curl openssl-tool tar termux-api termux-services

ARCH="$(uname -m)"
GOARCH="arm64"
[[ "$ARCH" == "x86_64" ]] && GOARCH="amd64"
[[ "$ARCH" == "armv7l" || "$ARCH" == "armv8l" ]] && GOARCH="armv7"

BIN_DIR="$PREFIX/bin"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

ARCHIVE="edgefetch_${VERSION}_linux_${GOARCH}.tar.gz"
BASE_URL="https://github.com/bartrumb/edgefetch/releases/download/v${VERSION}"

cat >"$tmp_dir/release-signing-pub.pem" <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAeTr4Ryc8TmHsN8gDk0mC61tN3BFD2dHUfqCBrMeoex0=
-----END PUBLIC KEY-----
EOF

echo "==> Downloading and verifying Ed25519 signature + SHA-256 for EdgeFetch v${VERSION} (${GOARCH})..."
curl -fsSL "${BASE_URL}/checksums.txt" -o "$tmp_dir/checksums.txt"
curl -fsSL "${BASE_URL}/checksums.txt.sig" -o "$tmp_dir/checksums.txt.sig"
openssl pkeyutl -verify -pubin -inkey "$tmp_dir/release-signing-pub.pem" \
  -rawin -in "$tmp_dir/checksums.txt" -sigfile "$tmp_dir/checksums.txt.sig"

curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "$tmp_dir/${ARCHIVE}"
EXPECTED_LINE="$(awk -v f="$ARCHIVE" '$2 == f { print $1 "  " $2 }' "$tmp_dir/checksums.txt")"
if [[ -z "$EXPECTED_LINE" ]]; then
  echo "ERROR: ${ARCHIVE} missing from verified checksums.txt" >&2
  exit 1
fi
(cd "$tmp_dir" && printf '%s\n' "$EXPECTED_LINE" | sha256sum -c -)
tar -xzf "$tmp_dir/${ARCHIVE}" -C "$BIN_DIR" edgefetch
chmod 0755 "$BIN_DIR/edgefetch"

sq_escape() {
  printf "'%s'" "${1//\'/\'\"\'\"\'}"
}

mkdir -p "$HOME/.config/edgefetch" "$HOME/.termux/boot"
umask 077
{
  printf 'export EDGEFETCH_HUB_URL=%s\n' "$(sq_escape "$EDGEFETCH_HUB_URL")"
  printf 'export EDGEFETCH_AGENT_TOKEN=%s\n' "$(sq_escape "$EDGEFETCH_AGENT_TOKEN")"
  printf 'export EDGEFETCH_SITE_ID=%s\n' "$(sq_escape "$SITE_ID")"
  printf 'export GOMEMLIMIT=%s\n' "'96MiB'"
} >"$HOME/.config/edgefetch/agent.env"
chmod 0600 "$HOME/.config/edgefetch/agent.env"

cat >"$HOME/.termux/boot/start-edgefetch.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
. "$HOME/.config/edgefetch/agent.env"
nohup "$PREFIX/bin/edgefetch" --mode=agent >"$HOME/.config/edgefetch/agent.log" 2>&1 &
EOF
chmod 0755 "$HOME/.termux/boot/start-edgefetch.sh"

echo "==> Acquiring wake-lock and starting EdgeFetch (${SITE_ID})..."
termux-wake-lock || true
pkill -f "edgefetch --mode=agent" || true
# shellcheck disable=SC1091
. "$HOME/.config/edgefetch/agent.env"
nohup "$BIN_DIR/edgefetch" --mode=agent >"$HOME/.config/edgefetch/agent.log" 2>&1 &
echo "==> EdgeFetch Android node '${SITE_ID}' started! Logs: ~/.config/edgefetch/agent.log"
