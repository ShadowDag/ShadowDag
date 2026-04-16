#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
#  ShadowDAG systemd installer
#
#  Usage (run on the server as root, from /opt/ShadowDag):
#      bash deploy/install-systemd.sh ST1your_full_miner_address [threads]
#
#  This replaces the old nohup/screen approach with a proper systemd setup:
#   - shadowdag-node.service      (auto-restart, graceful shutdown)
#   - shadowdag-miner.service     (depends on node, waits for RPC)
#   - /etc/shadowdag/miner.env    (miner address + thread count)
#   - /usr/local/bin/sd           (status / logs / restart helper)
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

SHADOWDAG_DIR="${SHADOWDAG_DIR:-/opt/ShadowDag}"
SYSTEMD_DIR="/etc/systemd/system"
ENV_DIR="/etc/shadowdag"
ENV_FILE="${ENV_DIR}/node.env"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo)" >&2
    exit 1
fi

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <miner_address> [threads] [network]" >&2
    echo "Example: $0 SD1abc123... 1 mainnet" >&2
    echo "         $0 ST1abc123... 1 testnet" >&2
    exit 1
fi

MINER_ADDRESS="$1"
MINER_THREADS="${2:-1}"
NETWORK="${3:-mainnet}"

# Set default ports based on network
case "$NETWORK" in
    mainnet) RPC_PORT=9332;  P2P_PORT=9333  ;;
    testnet) RPC_PORT=19332; P2P_PORT=19333 ;;
    regtest) RPC_PORT=29332; P2P_PORT=29333 ;;
    *) echo "ERROR: unknown network '$NETWORK'" >&2; exit 1 ;;
esac

if [[ ! -d "$SHADOWDAG_DIR" ]]; then
    echo "ERROR: $SHADOWDAG_DIR does not exist" >&2
    exit 1
fi

if [[ ! -x "$SHADOWDAG_DIR/target/release/shadowdag-node" ]]; then
    echo "ERROR: shadowdag-node binary not found — run 'cargo build --release' first" >&2
    exit 1
fi

if [[ ! -x "$SHADOWDAG_DIR/target/release/shadowdag-miner" ]]; then
    echo "ERROR: shadowdag-miner binary not found — run 'cargo build --release' first" >&2
    exit 1
fi

echo "═══════════════════════════════════════════"
echo "  ShadowDAG systemd install"
echo "═══════════════════════════════════════════"
echo "  Shadowdag dir:  $SHADOWDAG_DIR"
echo "  Network:        $NETWORK"
echo "  Miner address:  $MINER_ADDRESS"
echo "  Miner threads:  $MINER_THREADS"
echo "  RPC port:       $RPC_PORT"
echo "  P2P port:       $P2P_PORT"
echo

# ── 1. Stop any running processes from the old setup ───────────────────
echo "[1/6] Stopping any existing processes..."
pkill -TERM -f shadowdag-miner 2>/dev/null || true
pkill -TERM -f shadowdag-node  2>/dev/null || true
sleep 5
if pgrep -f "shadowdag-(node|miner)" > /dev/null; then
    echo "  ⚠  some processes still running, waiting 10 more seconds..."
    sleep 10
    pkill -KILL -f shadowdag-miner 2>/dev/null || true
    pkill -KILL -f shadowdag-node  2>/dev/null || true
fi
echo "  ✓ clean"

# ── 2. Write node environment file ─────────────────────────────────────
echo "[2/6] Writing $ENV_FILE..."
mkdir -p "$ENV_DIR"
cat > "$ENV_FILE" <<EOF
# ShadowDAG node configuration (managed by install-systemd.sh)
NETWORK=$NETWORK
RPC_PORT=$RPC_PORT
P2P_PORT=$P2P_PORT
MINER_ADDRESS=$MINER_ADDRESS
MINER_THREADS=$MINER_THREADS
EOF
chmod 600 "$ENV_FILE"
echo "  ✓ wrote $ENV_FILE"

# ── 3. Install unit files ──────────────────────────────────────────────
echo "[3/6] Installing systemd unit files..."
install -m 644 "$SHADOWDAG_DIR/deploy/systemd/shadowdag-node.service"  "$SYSTEMD_DIR/shadowdag-node.service"
install -m 644 "$SHADOWDAG_DIR/deploy/systemd/shadowdag-miner.service" "$SYSTEMD_DIR/shadowdag-miner.service"
echo "  ✓ installed to $SYSTEMD_DIR/"

# ── 4. Install the sd helper CLI ───────────────────────────────────────
echo "[4/6] Installing /usr/local/bin/sd helper..."
install -m 755 "$SHADOWDAG_DIR/deploy/sd" /usr/local/bin/sd
echo "  ✓ installed"

# ── 5. Reload systemd and enable services ──────────────────────────────
echo "[5/6] Reloading systemd and enabling services..."
systemctl daemon-reload
systemctl enable shadowdag-node.service  > /dev/null
systemctl enable shadowdag-miner.service > /dev/null
echo "  ✓ services enabled (will auto-start on boot)"

# ── 6. Start services ──────────────────────────────────────────────────
echo "[6/6] Starting services..."
systemctl start shadowdag-node.service
echo "  ✓ shadowdag-node started, waiting for RPC..."
sleep 10
systemctl start shadowdag-miner.service
echo "  ✓ shadowdag-miner started"

echo
echo "═══════════════════════════════════════════"
echo "  Install complete!"
echo "═══════════════════════════════════════════"
echo
systemctl --no-pager status shadowdag-node shadowdag-miner | head -30
echo
echo "Next steps:"
echo "  sd status        # full health snapshot"
echo "  sd both          # live logs (both node + miner)"
echo "  sd restart       # restart everything"
echo "  sd stop          # stop everything"
echo
