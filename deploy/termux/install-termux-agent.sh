#!/data/data/com.termux/files/usr/bin/bash
# Android Termux + Termux:Boot 1-Command Installer (`deploy/termux/install-termux-agent.sh`).
#
# Turns any spare Android phone or tablet (plugged into USB power on home Wi-Fi or 5G SIM)
# into an always-on ~15 MiB RAM `linux/arm64` EdgeFetch outbound worker node!
#
# Usage inside Termux:
#   EDGEFETCH_HUB_URL="https://edgefetch.example.com" \
#   EDGEFETCH_AGENT_TOKEN="<32-char-secret>" \
#   EDGEFETCH_SITE_ID="pixel-5g-node" \
#   bash install-termux-agent.sh
set -euo pipefail

VERSION="${EDGEFETCH_VERSION:-2.2.0}"
if [[ -z "${EDGEFETCH_HUB_URL:-}" || -z "${EDGEFETCH_AGENT_TOKEN:-}" ]]; then
  echo "ERROR: Set EDGEFETCH_HUB_URL and EDGEFETCH_AGENT_TOKEN before running." >&2
  exit 1
fi
SITE_ID="${EDGEFETCH_SITE_ID:-android-termux-1}"

pkg update -y
pkg install -y curl tar termux-api termux-services

ARCH="$(uname -m)"
GOARCH="arm64"
[[ "$ARCH" == "x86_64" ]] && GOARCH="amd64"
[[ "$ARCH" == "armv7l" || "$ARCH" == "armv8l" ]] && GOARCH="armv7"

BIN_DIR="$PREFIX/bin"
curl -fsSL "https://github.com/bartrumb/edgefetch/releases/download/v${VERSION}/edgefetch_${VERSION}_linux_${GOARCH}.tar.gz" \
  | tar -xz -C "$BIN_DIR" edgefetch
chmod 0755 "$BIN_DIR/edgefetch"

mkdir -p "$HOME/.config/edgefetch" "$HOME/.termux/boot"
cat >"$HOME/.config/edgefetch/agent.env" <<EOF
export EDGEFETCH_HUB_URL="${EDGEFETCH_HUB_URL}"
export EDGEFETCH_AGENT_TOKEN="${EDGEFETCH_AGENT_TOKEN}"
export EDGEFETCH_SITE_ID="${SITE_ID}"
export GOMEMLIMIT="96MiB"
EOF
chmod 0600 "$HOME/.config/edgefetch/agent.env"

cat >"$HOME/.termux/boot/start-edgefetch.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
. "$HOME/.config/edgefetch/agent.env"
nohup "$PREFIX/bin/edgefetch" --mode=agent >"$HOME/.config/edgefetch/agent.log" 2>&1 &
EOF
chmod +x "$HOME/.termux/boot/start-edgefetch.sh"

echo "==> Acquiring wake-lock and starting EdgeFetch (${SITE_ID})..."
termux-wake-lock || true
pkill -f "edgefetch --mode=agent" || true
# shellcheck disable=SC1091
. "$HOME/.config/edgefetch/agent.env"
nohup "$BIN_DIR/edgefetch" --mode=agent >"$HOME/.config/edgefetch/agent.log" 2>&1 &
echo "==> EdgeFetch Android node '${SITE_ID}' started! Logs: ~/.config/edgefetch/agent.log"
