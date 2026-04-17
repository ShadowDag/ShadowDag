# ═══════════════════════════════════════════════════════════════════════════
#  ShadowDAG — Multi-stage Docker build
#
#  Usage:
#    docker build -t shadowdag .
#    docker run -d --name shadowdag-node \
#      -p 9332:9332 -p 9333:9333 -p 8080:8080 -p 3000:3000 -p 7779:7779 \
#      shadowdag
#
#  With mining:
#    docker run -d --name shadowdag-node \
#      -e MINER_ADDRESS=SD0your_address_here \
#      -e MINER_THREADS=2 \
#      -p 9332:9332 -p 9333:9333 -p 8080:8080 \
#      shadowdag
# ═══════════════════════════════════════════════════════════════════════════

# ── Stage 1: Build ────────────────────────────────────────────────────────
FROM rust:1.78-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    libclang-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash shadowdag

# Copy binaries
COPY --from=builder /build/target/release/shadowdag-node   /usr/local/bin/
COPY --from=builder /build/target/release/shadowdag-miner  /usr/local/bin/
COPY --from=builder /build/target/release/shadowdag-wallet /usr/local/bin/
COPY --from=builder /build/target/release/shadowasm        /usr/local/bin/

# Copy examples
COPY examples/ /opt/shadowdag/examples/

# Data directory
RUN mkdir -p /data && chown shadowdag:shadowdag /data
VOLUME /data

# Environment
ENV SHADOWDAG_DATA_DIR=/data
ENV NETWORK=mainnet
ENV MINER_ADDRESS=""
ENV MINER_THREADS=1

# Ports
# 9332: RPC  |  9333: P2P  |  7779: Stratum  |  8080: Explorer  |  3000: IDE
EXPOSE 9332 9333 7779 8080 3000

USER shadowdag

# Entrypoint script
COPY <<'ENTRYPOINT' /usr/local/bin/docker-entrypoint.sh
#!/bin/bash
set -e

# Start the node with all services
ARGS="--network=${NETWORK} --enable-explorer --enable-ide --enable-stratum"
ARGS="${ARGS} --data-dir=/data"

echo "═══════════════════════════════════════════"
echo "  ShadowDAG Node (Docker)"
echo "═══════════════════════════════════════════"
echo "  Network:  ${NETWORK}"
echo "  Data:     /data"
echo "  Explorer: http://localhost:8080"
echo "  IDE:      http://localhost:3000"
echo "  RPC:      localhost:9332"
echo "  P2P:      0.0.0.0:9333"
echo "  Stratum:  0.0.0.0:7779"
echo "═══════════════════════════════════════════"

# Start miner in background if address is set
if [ -n "$MINER_ADDRESS" ]; then
    echo "  Mining to: ${MINER_ADDRESS}"
    echo "  Threads:   ${MINER_THREADS}"
    shadowdag-miner --network="${NETWORK}" \
        --address="${MINER_ADDRESS}" \
        --threads="${MINER_THREADS}" \
        --rpc=127.0.0.1:9332 &
fi

exec shadowdag-node $ARGS "$@"
ENTRYPOINT

ENTRYPOINT ["bash", "/usr/local/bin/docker-entrypoint.sh"]
