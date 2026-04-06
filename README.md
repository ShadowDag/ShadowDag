# ShadowDAG

**Hybrid BlockDAG Privacy Coin with Smart Contracts**

A next-generation cryptocurrency combining DAG-based high throughput, Monero-level privacy, and Ethereum-level smart contracts in a single unified architecture.

## Key Features

| Feature | Specification |
|---------|---------------|
| Architecture | BlockDAG (not blockchain) |
| Throughput | Up to 320,000 TPS (32 BPS mode) |
| Block Time | ~1 second (configurable: 1/10/32 BPS) |
| Privacy | 7 layers (Ring Signatures, Stealth, Bulletproofs, Shadow Pool, Shadow Nodes, Invisible Wallets, Confidential TX) |
| Smart Contracts | ShadowVM — 119 opcodes, gas metering, ABI, assembler |
| Mining | ShadowHash (ASIC-resistant, GPU-friendly) |
| Post-Quantum | Falcon + Dilithium signature support |
| Max Supply | 21 billion SDAG (halving every 210M blocks) |

## Project Structure

```
shadowdag/
├── bin/                    # Executable binaries (node, miner, wallet, loadtest)
├── config/                 # Genesis block, consensus params, network config
├── domain/                 # Core data types (blocks, transactions, UTXO, addresses)
├── engine/                 # Processing engines
│   ├── consensus/          #   Consensus validation, difficulty, rewards
│   ├── crypto/             #   Cryptographic primitives (hashing, signatures)
│   ├── dag/                #   BlockDAG engine (GHOSTDAG, tips, traversal, simulator)
│   ├── mining/             #   PoW mining (ShadowHash, GPU, Stratum pool)
│   └── privacy/            #   Privacy layer (RingCT, Bulletproofs, Shadow Pool)
├── infrastructure/         # Storage layer (RocksDB)
├── runtime/                # Execution runtime
│   ├── event_bus/          #   Event publishing/subscription
│   ├── scheduler/          #   Task scheduling
│   └── vm/                 #   ShadowVM smart contract engine
├── service/                # High-level services
│   ├── events/             #   Pub-sub notification system
│   ├── mempool/            #   Transaction pool (fees, eviction, orphans)
│   ├── network/            #   P2P networking (peers, relay, RPC, sync)
│   └── wallet/             #   HD wallet (keys, multi-sig, stealth)
├── telemetry/              # Logging, metrics, Prometheus
├── indexes/                # Block explorer, TX/UTXO indexes
└── tests/                  # Integration test suite (21 test files)
```

## Quick Start

### Build
```bash
cargo build --release
```

### Run a Node
```bash
# Mainnet
cargo run --release --bin shadowdag-node

# Testnet
cargo run --release --bin shadowdag-node -- --network=testnet

# Show genesis block info
cargo run --release --bin shadowdag-node -- genesis
```

### Create a Wallet
```bash
cargo run --release --bin shadowdag-wallet -- new
cargo run --release --bin shadowdag-wallet -- stealth
cargo run --release --bin shadowdag-wallet -- invisible
```

### Mine
```bash
# Benchmark hashrate
cargo run --release --bin shadowdag-miner -- --benchmark

# Start mining
cargo run --release --bin shadowdag-miner -- --address=SD1your_address_here
```

### Run Tests
```bash
cargo test
```

### Load Test
```bash
cargo run --release --bin shadowdag-loadtest -- --tps=1000 --duration=60
```

## Architecture Overview

See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete technical documentation.

### Layers (top to bottom)

```
┌─────────────────────────────────────────────────┐
│  CLI: shadowdag-node / shadowdag-miner / wallet  │
├─────────────────────────────────────────────────┤
│  Service: Mempool, Network (P2P/RPC), Wallet     │
├─────────────────────────────────────────────────┤
│  Engine: Consensus, DAG, Mining, Privacy, Crypto │
├─────────────────────────────────────────────────┤
│  Runtime: ShadowVM, Event Bus, Scheduler         │
├─────────────────────────────────────────────────┤
│  Domain: Blocks, Transactions, UTXO, Addresses   │
├─────────────────────────────────────────────────┤
│  Infrastructure: RocksDB Storage                 │
└─────────────────────────────────────────────────┘
```

### Design Rules
1. **RocksDB only** — no in-memory-only state for consensus data
2. **Atomic writes** — all UTXO/block operations use WriteBatch
3. **No double-spend** — enforced at UTXO, mempool, and key image levels
4. **Deterministic execution** — ShadowVM produces same output for same input
5. **DAG parallel blocks** — multiple blocks per second, GHOSTDAG ordering
6. **Integer math only** — no floating-point in consensus-critical code

## Genesis Block

```
Network:  Mainnet
Hash:     000052e21b49be471d03d78d68ebc4d2e5ec65853c1642ab242ebff37ddd40f9
Nonce:    43879 (mined with real PoW)
Reward:   10 SDAG (95% miner / 5% developer)
Message:  "ShadowDAG/Genesis/2026-01-01/Privacy-is-a-right-not-a-privilege"
```

## License

MIT
