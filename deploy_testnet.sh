#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
#  ShadowDAG Testnet Deployment Script
#  Run this on each server after uploading the source code
# ═══════════════════════════════════════════════════════════════════════════

set -e

echo "═══════════════════════════════════════════"
echo "  ShadowDAG Testnet Deployment"
echo "═══════════════════════════════════════════"

# Step 1: Stop existing node and miner
echo "[1/5] Stopping existing processes..."
pkill -f shadowdag-node 2>/dev/null || true
pkill -f shadowdag-miner 2>/dev/null || true
sleep 2

# Step 2: Wipe old database (REQUIRED — genesis changed)
echo "[2/5] Wiping old database..."
rm -rf /root/.shadowdag-testnet/db
rm -rf /root/.shadowdag/db
echo "  ✓ Database wiped"

# Step 3: Build release
echo "[3/5] Building release (this may take a few minutes)..."
cd /home/shadowdag
cargo build --release 2>&1 | tail -3

# Step 4: Start node
echo "[4/5] Starting testnet node..."
nohup ./target/release/shadowdag-node --network=testnet > /var/log/shadowdag-node.log 2>&1 &
sleep 3
echo "  ✓ Node started (PID: $(pgrep -f shadowdag-node || echo 'unknown'))"

# Step 5: Start miner (on first server only)
if [[ "$1" == "--mine" ]]; then
    echo "[5/5] Starting miner..."
    MINER_ADDR="${2:-ST1ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00}"
    nohup ./target/release/shadowdag-miner \
        --network=testnet \
        --address="$MINER_ADDR" \
        --rpc=127.0.0.1:19332 \
        > /var/log/shadowdag-miner.log 2>&1 &
    echo "  ✓ Miner started (PID: $(pgrep -f shadowdag-miner || echo 'unknown'))"
else
    echo "[5/5] Skipping miner (pass --mine to start)"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "  Deployment complete!"
echo "  Node log: tail -f /var/log/shadowdag-node.log"
echo "  Miner log: tail -f /var/log/shadowdag-miner.log"
echo "═══════════════════════════════════════════"
