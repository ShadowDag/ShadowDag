# ShadowDAG

**Hybrid BlockDAG Privacy Coin with Smart Contracts**

A next-generation cryptocurrency combining DAG-based high throughput, Monero-level privacy, and Ethereum-level smart contracts in a single unified architecture.

## Key Specifications

| Feature | Value |
|---------|-------|
| **Architecture** | BlockDAG (GHOSTDAG consensus, K=180) |
| **Max Supply** | 21 billion SDAG |
| **Block Time** | 1 second target |
| **Blocks Per Second** | 10 (default), configurable 1/10/32 |
| **Max TPS** | 100,000+ (10 BPS x 10,000 txs/block) |
| **Finality** | 200 blocks (~20s), dynamic 100-2,000 |
| **Privacy** | CLSAG Ring Signatures + Pedersen Commitments + Stealth Addresses + Dandelion++ |
| **Smart Contracts** | ShadowVM (90+ opcodes, deterministic, gas-metered) |
| **Mining** | ShadowHash (ASIC-resistant, 256KB scratchpad) |
| **Post-Quantum** | Falcon + Dilithium signature support |
| **Emission** | Smooth decay (0.38%/month, ~5.5yr halving) |
| **Fee Market** | EIP-1559 style with exponential surge pricing |

## Consensus Parameters

| Parameter | Value |
|-----------|-------|
| GHOSTDAG K | 180 (at 10 BPS) |
| Max Parents | 80 (at 10 BPS) |
| Max Block Size | 2 MB |
| Max Block TXs | 10,000 |
| Min Relay Fee | 100 satoshis |
| Max Reorg Depth | 1,000 blocks |
| Economic Finality | 10,000 difficulty units |
| Coinbase Maturity | 1,000 blocks |
| Miner Reward | 95% |
| Developer Fund | 5% |

## Emission Schedule

Smooth exponential decay (no hard halvings):

| Period | Block Reward | Monthly Decay |
|--------|-------------|---------------|
| Genesis | 10.0000 SDAG | - |
| 6 months | 9.7741 SDAG | -0.38% |
| 1 year | 9.5533 SDAG | -0.38% |
| 3 years | 8.7096 SDAG | -0.38% |
| 5.5 years | ~5.0 SDAG | Half of initial |
| 11 years | ~2.5 SDAG | Quarter of initial |

## Network Configuration

| Network | P2P Port | RPC Port | Magic Bytes | Address Prefix |
|---------|----------|----------|-------------|----------------|
| Mainnet | 9333 | 9332 | `SDAG` | SD1 |
| Testnet | 19333 | 19332 | `SDTN` | ST1 |
| Regtest | 29333 | 29332 | `SDRT` | SR1 |

## Address Types

| Prefix | Type | Example |
|--------|------|---------|
| SD1 | Standard | SD1a1b2c3d4e5f... |
| SD1s | Stealth | SD1s8f7e6d5c4b... |
| SD1c | Contract | SD1c0a1b2c3d4e... |
| SD1m | Multisig | SD1m9e8d7c6b5a... |

## Project Structure

```
shadowdag/                    130,415 lines of Rust across 328 files
|
+-- bin/                      5 binaries
|   +-- node.rs               Full node (daemon + consensus + RPC + P2P)
|   +-- miner.rs              GPU/CPU miner with multi-threaded ShadowHash
|   +-- wallet.rs             HD wallet CLI (stealth, invisible, multisig)
|   +-- loadtest.rs           Network load testing tool
|   +-- mine_genesis.rs       Genesis block miner utility
|
+-- config/                   Consensus, network, genesis configuration
|   +-- consensus/            Block time, emission, mempool, difficulty
|   +-- network/              Ports, magic bytes, peer limits
|   +-- genesis/              Genesis block definition
|   +-- checkpoints.rs        Hardcoded + dynamic checkpoints
|
+-- domain/                   Core data types
|   +-- block/                Block, header, merkle tree, merkle proof
|   +-- transaction/          Transaction, TxType, validator, builder
|   +-- address/              HD derivation, stealth, invisible wallet
|   +-- utxo/                 UTXO set, spending, validation, snapshots
|   +-- types/                Amount, difficulty, hash, timestamp
|
+-- engine/                   Processing engines
|   +-- consensus/            Validation (4-layer), difficulty, rewards, finality
|   +-- crypto/               SHA3, Blake3, Keccak, Ed25519, Falcon, Dilithium
|   +-- dag/                  GHOSTDAG, blue/red sets, tips, sync, security
|   +-- mining/               ShadowHash, GPU (CUDA/OpenCL), Stratum pool
|   +-- privacy/              CLSAG, Pedersen, Bulletproofs, stealth scanner
|   +-- swap/                 Atomic swaps (HTLC)
|   +-- dex/                  On-chain order book
|
+-- infrastructure/           RocksDB storage layer
|   +-- storage/rocksdb/      Blocks, DAG, UTXO, transactions, peers, state
|
+-- runtime/                  Execution environment
|   +-- vm/                   ShadowVM (90+ opcodes, U256, gas, precompiles)
|   +-- wasm/                 WASM SDK (browser-compatible wallet functions)
|   +-- event_bus/            Pub-sub event system
|   +-- scheduler/            Async task scheduling
|
+-- service/                  High-level services
|   +-- mempool/              TX pool (RBF, CPFP, surge pricing, eviction)
|   +-- network/              P2P, RPC, gRPC, WebSocket, reputation, DoS guard
|   +-- wallet/               HD wallet, key manager, multisig, hardware wallet
|
+-- telemetry/                Logging (structured), Prometheus metrics, tracing
+-- indexes/                  Explorer, TX index, UTXO index
+-- benches/                  Criterion benchmarks (ShadowHash, TPS, merkle)
+-- tests/                    Integration tests (21 test files)
```

## Quick Start

### Build
```bash
cargo build --release
```

### Run a Node
```bash
# Mainnet
./target/release/shadowdag-node --network=mainnet

# Testnet
./target/release/shadowdag-node --network=testnet

# Custom data directory
./target/release/shadowdag-node --data-dir=/path/to/data

# Show node info
./target/release/shadowdag-node info
```

### Create a Wallet
```bash
./target/release/shadowdag-wallet new
./target/release/shadowdag-wallet stealth
./target/release/shadowdag-wallet invisible
./target/release/shadowdag-wallet balance
./target/release/shadowdag-wallet send <address> <amount>
```

### Mine
```bash
# Start mining (connects to local node RPC)
./target/release/shadowdag-miner --address=SD1your_address --threads=8

# Custom RPC
./target/release/shadowdag-miner --address=SD1... --rpc=127.0.0.1:9332
```

### Run Tests
```bash
cargo test
cargo bench
```

### Load Test
```bash
./target/release/shadowdag-loadtest --tps=1000 --duration=60 --rpc=127.0.0.1:9332
```

## Security Model

### Validation Pipeline (4 layers, strictly separated)

```
Phase 1 (STATELESS): L1 Network -> PoW -> L2 Structural -> L3 Consensus
  - No DB/UTXO reads. Fully deterministic.
  - Merkle tree parallel (rayon) but deterministic.

Phase 2 (DAG): Parent existence + DAG insertion
  - Only after Phase 1 passes.

Phase 3 (UTXO): Execute transactions in GHOSTDAG order
  - Sequential, single-threaded, atomic rollback on failure.
```

### Anti-Attack Protections

| Attack | Protection |
|--------|-----------|
| Selfish Mining | Red block penalty (20% reward), late decay (5%/sec), MIN_PARENTS=2 |
| Sybil | PoW connection puzzle (4096 hashes), subnet diversity, peer reputation |
| Timewarp | 6-rule timestamp validation, strict monotonic, DAG-dense caps |
| Difficulty Manipulation | Strict match (no tolerance), blue score rate stabilizer |
| DoS | Token bucket (800/sec), per-peer bandwidth (100MB/min), global limits |
| Eclipse | Max 2 peers per /16 subnet, 8 anchor peers, Ed25519 identity |
| Replay | Timestamp range + payload_hash anti-replay |
| Double Spend | UTXO model + key images + intra-block detection |

### Data Integrity

- **RocksDB WAL**: Always enabled (18 explicit `disable_wal(false)` calls)
- **Atomic writes**: All UTXO/block operations use WriteBatch
- **Reorg safety**: Full chain rollback + fail-stop on any error
- **Deterministic VM**: 10 invariants enforced (no float, no I/O, no random)

## Architecture Overview

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

```
+---------------------------------------------------+
| CLI: shadowdag-node / shadowdag-miner / wallet     |
+---------------------------------------------------+
| Service: Mempool, P2P, RPC, gRPC, WebSocket        |
+---------------------------------------------------+
| Engine: Consensus, GHOSTDAG, Mining, Privacy        |
+---------------------------------------------------+
| Runtime: ShadowVM (90+ opcodes), Event Bus          |
+---------------------------------------------------+
| Domain: Blocks, Transactions, UTXO, Addresses       |
+---------------------------------------------------+
| Infrastructure: RocksDB (WAL, atomic flush)          |
+---------------------------------------------------+
```

## Design Principles

1. **Integer math only** in consensus-critical code (no f64)
2. **RocksDB WAL always on** for crash safety
3. **Atomic writes** via WriteBatch for state consistency
4. **Fail-stop** on any consensus error (no continue-on-error)
5. **Deterministic execution** in ShadowVM (same input = same output)
6. **DAG-aware** difficulty, finality, and timestamp validation
7. **Economic incentives** aligned (penalties for misbehavior, rewards for cooperation)

## Genesis Block

```
Network:  Mainnet
Hash:     000052e21b49be471d03d78d68ebc4d2e5ec65853c1642ab242ebff37ddd40f9
Nonce:    43879 (mined with real PoW)
Reward:   10 SDAG (9.5 miner + 0.5 developer)
Message:  "ShadowDAG/Genesis/2026-01-01/Privacy-is-a-right-not-a-privilege"
```

## CI Pipeline

6 parallel jobs on every push/PR:

| Job | Command |
|-----|---------|
| Check | `cargo check --all-targets` |
| Unit Tests | `cargo test --lib --bins` |
| Integration Tests | `cargo test --test shadowdag` |
| VM Contract Tests | `cargo test --lib -- execution_env v1_spec contract_e2e ...` |
| Clippy | `cargo clippy --all-targets -- -D warnings` |
| shadowasm Check | `shadowasm build --check` on sample |

## License

MIT
