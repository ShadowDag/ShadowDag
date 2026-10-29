#!/usr/bin/env bash
# Bare-metal ShadowDAG testnet deploy (Ubuntu/Debian, no Docker).
# Builds the node, installs it as a systemd service, and starts it.
#
#   git clone https://github.com/ShadowDag/ShadowDag.git
#   cd ShadowDag/deploy/testnet
#   sudo ./deploy.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA_DIR="/var/lib/shadowdag-testnet"
BIN_DST="/usr/local/bin/shadowdag-node"

echo "==> Installing build deps"
apt-get update -y
apt-get install -y build-essential pkg-config libclang-dev curl git

echo "==> Installing Rust (if missing)"
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

echo "==> Building shadowdag-node (release)"
cd "$REPO_ROOT"
cargo build --release --bin shadowdag-node

echo "==> Installing binary -> $BIN_DST"
install -m 0755 "$REPO_ROOT/target/release/shadowdag-node" "$BIN_DST"

echo "==> Creating 'shadowdag' user + data dir"
id -u shadowdag >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin shadowdag
mkdir -p "$DATA_DIR"
chown -R shadowdag:shadowdag "$DATA_DIR"

echo "==> Installing systemd service"
install -m 0644 "$REPO_ROOT/deploy/testnet/shadowdag-testnet.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now shadowdag-testnet

echo "==> Done. Node is starting on testnet (P2P 19333, RPC 19332 local)."
echo "    Logs:  journalctl -u shadowdag-testnet -f"
echo "    Open the firewall for P2P:  sudo ufw allow 19333/tcp"
