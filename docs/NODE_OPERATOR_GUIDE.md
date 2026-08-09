# ShadowDAG — Node Operator Guide

How to build, run, mine, and operate a ShadowDAG node. Flags here are taken from
`bin/node.rs`; ports from the default config / Dockerfile.

> ⚠️ Before running a **mainnet** with real value, read `docs/MAINNET_READINESS.md`.
> The protocol still needs an external audit + public testnet.

## 1. Build

```bash
# Native
cargo build --release
# Binaries land in target/release/: shadowdag-node, shadowdag-miner,
# shadowdag-wallet, shadowasm, ...
```

Requires a recent stable Rust, `libclang`, and `pkg-config` (see the Dockerfile).

## 2. Run a node

```bash
shadowdag-node                       # mainnet
shadowdag-node --network=testnet
shadowdag-node --network=regtest     # local single-node dev
```

Inspect without starting:

```bash
shadowdag-node info       # network parameters
shadowdag-node genesis    # genesis block details
shadowdag-node --version
shadowdag-node --help
```

### Flags

| Flag | Meaning | Default |
|---|---|---|
| `--network=<mainnet\|testnet\|regtest>` | Network | mainnet |
| `--data-dir=<path>` | Data directory (DB + keys) | OS default |
| `--rpc-port=<n>` | JSON-RPC port | 9332 |
| `--p2p-port=<n>` | P2P port | 9333 |
| `--enable-stratum` / `--stratum-port=<n>` | Stratum mining pool | off / 7779 |
| `--enable-explorer` / `--explorer-port=<n>` | Block explorer | off / 8080 |
| `--enable-wallet-ui` / `--wallet-ui-port=<n>` | Browser wallet UI | off |
| `--enable-ide` / `--ide-port=<n>` | Contract IDE | off / 3000 |
| `--devnet` | Dev/test convenience mode | off |

### Ports (defaults)

| Port | Service | Expose publicly? |
|---|---|---|
| 9333 | P2P | **Yes** (so peers can reach you) |
| 9332 | JSON-RPC | **No** — keep private / firewalled / localhost |
| 7779 | Stratum pool | Only if running a pool |
| 8080 | Explorer | Optional (read-only) |
| 3000 | Contract IDE | **No** — dev tool, loopback-only by design |

Open **9333** inbound on your firewall. Do **not** expose 9332 (RPC) to the
public internet — it controls mining/tx submission and is token-gated but should
still be private.

## 3. RPC authentication

On first boot the node generates an admin RPC credential and writes it to
`<data_dir>/rpc_password`. Use the `login` method to obtain a bearer token, then
send `Authorization: Bearer <token>` (see `docs/RPC_REFERENCE.md`).

Rotate it:

```bash
shadowdag-rotate-rpc-password --db-path <data_dir>/db
# next node boot regenerates a fresh credential
```

## 4. Mining

```bash
shadowdag-miner --address=SD1<your_reward_address> \
                --network=mainnet \
                --threads=4 \
                --rpc=127.0.0.1:9332
```

Create the reward address first with `shadowdag-wallet new`. For pool mining,
start the node with `--enable-stratum` and point miners at port 7779.

## 5. Docker (easiest)

```bash
# Build + run a node with explorer/IDE/stratum
docker compose up -d
docker compose logs -f node

# With mining
MINER_ADDRESS=SD1<addr> MINER_THREADS=2 docker compose up -d
```

The compose file maps 9332/9333/7779/8080/3000 and persists `/data` in a volume.
Env vars: `NETWORK`, `MINER_ADDRESS`, `MINER_THREADS`.

## 6. Seed / bootstrap

Mainnet seed nodes are compiled in (`config/network/bootstrap_nodes.rs`). To run
your own seed for a network, give it a static IP/DNS and ensure 9333 is reachable;
peers discover it via the configured seed list. For testnet, point the
`seedN-testnet.shadowdag.network` A-records at your servers.

## 7. Health & monitoring

- `gethealth`, `getsyncstatus`, `getnodeinfo`, `getmetrics`, `getpeerinfo` via RPC.
- `getprometheusurl` advertises the metrics endpoint (see the monitoring setup).

## 8. Data & recovery

- All state lives under `--data-dir`. Back it up while the node is stopped.
- The block store is the source of truth; DAG/UTXO are rebuilt on recovery if a
  crash leaves them behind (see `daemon::verify_and_recover`).
- A corrupt DB? Start with a fresh `--data-dir` and re-sync.

## 9. Upgrades

Stop the node (`stop` RPC or signal), replace the binary, restart with the same
`--data-dir`. Watch release notes for any consensus-affecting change (which would
require a coordinated network upgrade).
