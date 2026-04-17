#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
#  ShadowDAG — One-liner Installer
#
#  Usage:
#    curl -sSf https://raw.githubusercontent.com/ShadowDag/ShadowDag/main/install.sh | bash
#
#  Or with options:
#    curl -sSf ... | bash -s -- --network testnet --mine SD1your_address
#
#  What it does:
#    1. Detects OS and architecture
#    2. Downloads the latest release from GitHub
#    3. Extracts binaries to /usr/local/bin
#    4. Creates data directory
#    5. Optionally installs systemd services
#    6. Starts the node
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO="ShadowDag/ShadowDag"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="$HOME/.shadowdag"
NETWORK="mainnet"
MINER_ADDR=""
THREADS=1

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --network) NETWORK="$2"; shift 2 ;;
        --mine) MINER_ADDR="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --dir) DATA_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

echo "╔══════════════════════════════════════════════╗"
echo "║     S H A D O W D A G  —  Installer         ║"
echo "║     Privacy • Speed • Decentralization        ║"
echo "╚══════════════════════════════════════════════╝"
echo

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)  PLATFORM="linux" ;;
    darwin) PLATFORM="macos" ;;
    *)      echo "ERROR: Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)             echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "[1/5] Detecting system: ${PLATFORM}-${ARCH}"

# Get latest release tag
echo "[2/5] Finding latest release..."
LATEST=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)

if [ -z "$LATEST" ]; then
    echo "  No release found. Building from source..."
    echo
    echo "  Prerequisites: Rust 1.75+ (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)"
    echo
    echo "  Build:"
    echo "    git clone https://github.com/${REPO}.git"
    echo "    cd ShadowDag"
    echo "    cargo build --release"
    echo "    sudo cp target/release/shadowdag-* /usr/local/bin/"
    echo
    echo "  Then run: shadowdag-node --network=${NETWORK} --enable-explorer --enable-ide"
    exit 0
fi

TARBALL="shadowdag-${LATEST}-${PLATFORM}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${TARBALL}"

echo "  Latest version: ${LATEST}"
echo "  Download: ${TARBALL}"

# Download
echo "[3/5] Downloading..."
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

if ! curl -sSfL -o "${TMPDIR}/${TARBALL}" "$URL"; then
    echo "  Download failed. Try building from source:"
    echo "    git clone https://github.com/${REPO}.git && cd ShadowDag && cargo build --release"
    exit 1
fi

# Extract
echo "[4/5] Installing to ${INSTALL_DIR}..."
tar xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"
EXTRACTED=$(ls -d ${TMPDIR}/shadowdag-* | head -1)

if [ -w "$INSTALL_DIR" ]; then
    cp "$EXTRACTED/bin/"* "$INSTALL_DIR/"
else
    sudo cp "$EXTRACTED/bin/"* "$INSTALL_DIR/"
fi

# Create data directory
mkdir -p "$DATA_DIR"

echo "[5/5] Installation complete!"
echo
echo "═══════════════════════════════════════════"
echo "  ShadowDAG ${LATEST} installed!"
echo "═══════════════════════════════════════════"
echo
echo "  Binaries:"
echo "    shadowdag-node    — Full node"
echo "    shadowdag-miner   — Miner"
echo "    shadowdag-wallet  — Wallet"
echo "    shadowasm         — Smart contract assembler"
echo
echo "  Quick start:"
echo "    shadowdag-node --network=${NETWORK} --enable-explorer --enable-ide"
echo
echo "  Create wallet:"
echo "    shadowdag-wallet new ${NETWORK}"
echo
echo "  Start mining:"
echo "    shadowdag-miner --network=${NETWORK} --address=YOUR_ADDRESS --threads=${THREADS}"
echo
echo "  Explorer:     http://localhost:8080"
echo "  Contract IDE: http://localhost:3000"
echo
echo "  Documentation: https://github.com/${REPO}"
echo

# Start node if requested
if [ -n "$MINER_ADDR" ]; then
    echo "Starting node + miner..."
    shadowdag-node --network="$NETWORK" --enable-explorer --enable-ide --enable-stratum &
    sleep 10
    shadowdag-miner --network="$NETWORK" --address="$MINER_ADDR" --threads="$THREADS" &
    echo "Node and miner started!"
fi
