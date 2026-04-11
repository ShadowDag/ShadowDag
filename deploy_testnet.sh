#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
#  ShadowDAG Testnet Deployment Script
#  Run this on each server after uploading the source code
# ═══════════════════════════════════════════════════════════════════════════

# `set -e`         — abort on first failed command
# `set -u`         — treat unset variables as errors (catches typos)
# `set -o pipefail` — propagate the FIRST nonzero exit through a pipe so
#                    `cargo build … | tail -3` no longer hides build
#                    failures behind tail's exit status (the original
#                    script lost build errors because the shell only
#                    saw tail's exit code, which is always 0)
set -euo pipefail

echo "═══════════════════════════════════════════"
echo "  ShadowDAG Testnet Deployment"
echo "═══════════════════════════════════════════"

# Step 1: Stop existing node and miner
echo "[1/5] Stopping existing processes..."
pkill -f shadowdag-node 2>/dev/null || true
pkill -f shadowdag-miner 2>/dev/null || true
sleep 2

# Step 2: Wipe TESTNET database only (REQUIRED — genesis changed).
#
# The previous version of this script also ran:
#
#     rm -rf /root/.shadowdag/db
#
# which is the DEFAULT (mainnet/local) data directory, NOT the
# testnet one. A testnet deployment script that nukes a non-testnet
# database is exactly the kind of cross-network blast radius that
# can wipe production data on a server that happens to host both.
# This script now touches ONLY the testnet path. If a previous
# default-network database needs to be wiped, that is a separate,
# explicitly-requested operation.
echo "[2/5] Wiping old testnet database..."
TESTNET_DB="/root/.shadowdag-testnet/db"
if [[ -d "$TESTNET_DB" ]]; then
    rm -rf "$TESTNET_DB"
    echo "  ✓ Testnet database wiped: $TESTNET_DB"
else
    echo "  ✓ No prior testnet database at $TESTNET_DB (clean slate)"
fi

# Step 3: Build release
#
# `cargo build --release 2>&1 | tail -3` would have hidden a real
# build failure because tail's exit code is always 0. With
# `set -o pipefail` (above) the pipeline now propagates cargo's
# exit code, AND we also check $? and bail out explicitly so the
# next step doesn't try to start a binary that was never built.
echo "[3/5] Building release (this may take a few minutes)..."
cd /home/shadowdag
if ! cargo build --release 2>&1 | tail -3; then
    echo "  ✗ cargo build failed — see full output above" >&2
    exit 1
fi

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
