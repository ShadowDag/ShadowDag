# ShadowDAG — Architecture Guide

Complete reference for developers. Every directory, every file, and what it does.

---

## Directory Map

### `bin/` — Executable Binaries
Entry points for running the node, miner, wallet, and tools.

| File | Binary Name | Purpose |
|------|-------------|---------|
| `node.rs` | `shadowdag-node` | Full node with P2P, RPC, consensus |
| `miner.rs` | `shadowdag-miner` | GPU miner with benchmark |
| `wallet.rs` | `shadowdag-wallet` | Wallet CLI (create, send, stealth, invisible) |
| `loadtest.rs` | `shadowdag-loadtest` | Transaction stress tester |
| `mine_genesis.rs` | `mine-genesis` | Genesis block mining utility |

---

### `config/` — Configuration
Static configuration for consensus, genesis, and network.

```
config/
├── consensus/
│   ├── consensus_params.rs    # Chain ID, max supply, block reward, GHOSTDAG K
│   └── emission_schedule.rs   # Halving schedule (every 210M blocks)
├── genesis/
│   └── genesis.rs             # Genesis block (hardcoded PoW, hash, nonce)
├── network/
│   ├── network_params.rs      # Ports, magic bytes, max peers
│   └── bootstrap_nodes.rs     # DNS seeds for peer discovery
├── node/
│   ├── node_config.rs         # Node configuration (Mainnet/Testnet/Regtest)
│   └── node_roles.rs          # Node types (Full/Light/Shadow)
└── checkpoints.rs             # Block hash checkpoints
```

---

### `domain/` — Core Data Types
Pure data structures with no side effects. The foundation of everything.

```
domain/
├── address/
│   ├── address.rs             # Address types (Standard/Stealth/MultiSig/Contract)
│   ├── stealth_address.rs     # One-time stealth address generation (ECDH)
│   ├── key_derivation.rs      # HMAC-SHA256 HD key derivation
│   └── invisible_wallet.rs    # Auto-rotating invisible wallets
├── block/
│   ├── block.rs               # Block = Header + Body
│   ├── block_header.rs        # Header: hash, parents, merkle_root, nonce, difficulty
│   ├── block_body.rs          # Body: list of transactions
│   ├── block_builder.rs       # Construct blocks from mempool
│   ├── block_rules.rs         # Full block validation (header + PoW + transactions)
│   ├── merkle_tree.rs         # SHA-256 Merkle tree with domain separation
│   ├── merkle_proof.rs        # Merkle inclusion proof
│   └── merkle_verifier.rs     # Verify Merkle proofs
├── transaction/
│   ├── transaction.rs         # Transaction: inputs, outputs, fee, hash
│   ├── tx_builder.rs          # Build and sign transactions
│   ├── tx_validator.rs        # Validate signatures, UTXO, amounts
│   ├── tx_hash.rs             # Chain-ID-aware transaction hashing
│   ├── tx_fee.rs              # Fee calculation (checked arithmetic)
│   ├── tx_receipt.rs          # Transaction status tracking (7 states)
│   └── decoy_transaction.rs   # Ring signature decoy transactions
├── types/
│   ├── amount.rs              # Integer-only amount math (no float)
│   ├── difficulty.rs          # Difficulty range validation
│   ├── hash.rs                # Hash utilities
│   └── timestamp.rs           # Timestamp validation, median, ranges
└── utxo/
    ├── utxo.rs                # UTXO data structure
    ├── utxo_set.rs            # UTXO set with cache + RocksDB
    ├── utxo_spend.rs          # Spend/rollback UTXO operations
    ├── utxo_validator.rs      # Ownership + double-spend validation
    └── utxo_snapshot.rs       # UTXO snapshots every 1000 blocks
```

---

### `engine/` — Processing Engines
Core algorithms: consensus, DAG, mining, privacy, crypto.

```
engine/
├── consensus/
│   ├── core/
│   │   ├── consensus.rs           # Consensus state (RocksDB)
│   │   ├── consensus_manager.rs   # Tip management
│   │   └── fork_choice.rs         # Fork choice by blue score
│   ├── difficulty/
│   │   ├── difficulty.rs          # Difficulty math (u128 safe)
│   │   ├── difficulty_adjustment.rs # EMA-based adjustment (RocksDB)
│   │   ├── difficulty_window.rs   # Tiered window sizing
│   │   └── retarget.rs           # LWMA + EMA retargeting
│   ├── rewards/
│   │   ├── reward.rs             # 95%/5% split logic
│   │   ├── miner_reward.rs       # Miner portion
│   │   ├── developer_reward.rs   # Developer portion
│   │   └── emission.rs           # Emission with halving
│   ├── validation/
│   │   ├── block_validator.rs    # Full block validation pipeline
│   │   ├── block_context.rs      # Block context wrapper
│   │   └── consensus_validator.rs # Consensus state validation
│   ├── state.rs                  # Consensus state tracking
│   ├── reorg.rs                  # Chain reorganization handling
│   ├── chain_manager.rs          # Chain comparison + tip selection
│   └── block_processor.rs        # Block processing pipeline
│
├── crypto/
│   ├── hash/
│   │   ├── shadowhash.rs        # ShadowHash store (RocksDB)
│   │   ├── blake3.rs            # Blake3 store
│   │   ├── keccak.rs            # Keccak store
│   │   └── sha3.rs              # SHA3 store
│   ├── keys/
│   │   ├── keypair.rs           # Key pair store
│   │   ├── private_key.rs       # Private key store
│   │   └── public_key.rs        # Public key store
│   ├── signatures/
│   │   ├── ed25519.rs           # Ed25519 signature store
│   │   ├── schnorr.rs           # Schnorr signature store
│   │   ├── falcon.rs            # Post-quantum Falcon
│   │   └── dilithium.rs         # Post-quantum Dilithium
│   ├── random/
│   │   ├── csprng.rs            # Cryptographic RNG state
│   │   └── entropy.rs           # Entropy collection
│   └── serialization.rs         # Deterministic serialization
│
├── dag/
│   ├── core/
│   │   ├── dag.rs               # BlockDAG (RocksDB)
│   │   ├── dag_manager.rs       # DAG block management
│   │   ├── dag_state.rs         # Blue/red score tracking
│   │   ├── block_graph.rs       # In-memory DAG graph
│   │   └── bps_engine.rs        # Multi-BPS engine (1/10/32 BPS)
│   ├── ghostdag/
│   │   ├── ghostdag.rs          # GHOSTDAG consensus (K=18)
│   │   ├── blue_set.rs          # Blue block set
│   │   ├── red_set.rs           # Red block set
│   │   └── ordering.rs          # Deterministic block ordering
│   ├── tips/
│   │   └── tip_manager.rs       # DAG tip management (thread-safe)
│   ├── security/
│   │   ├── dag_shield.rs        # Combined security validation
│   │   ├── dos_protection.rs    # Block/TX DoS validation
│   │   ├── flood_protection.rs  # Anti-flood (nonce, timestamp)
│   │   ├── selfish_mining_guard.rs # Anti-selfish-mining
│   │   └── spam_filter.rs       # Transaction spam filter
│   ├── sync/
│   │   ├── dag_sync.rs          # DAG synchronization
│   │   ├── header_sync.rs       # Header-first sync
│   │   └── block_locator.rs     # Block locator protocol
│   ├── validation/
│   │   ├── dag_validator.rs     # DAG structure validation
│   │   ├── conflict_detector.rs # Conflict detection
│   │   └── parent_validator.rs  # Parent relationship validation
│   ├── simulator/
│   │   └── network_simulator.rs # Full DAG network simulator
│   ├── traversal/mod.rs         # BFS/DFS/topological traversal + LCA
│   └── conflicts/mod.rs         # Conflict resolution (blue/red)
│
├── mining/
│   ├── algorithms/
│   │   ├── shadowhash.rs        # ShadowHash PoW (3-round, memory-hard)
│   │   ├── anti_asic.rs         # ASIC resistance (4-stage hardening)
│   │   └── hash_mix.rs          # Block data mixing
│   ├── gpu/
│   │   ├── gpu_miner.rs         # Rayon parallel GPU mining
│   │   ├── cuda_miner.rs        # CUDA mining
│   │   └── opencl_miner.rs      # OpenCL mining
│   ├── miner/
│   │   ├── miner.rs             # Miner implementation
│   │   ├── block_template.rs    # Block template construction
│   │   ├── miner_controller.rs  # Mining job persistence
│   │   └── miner_stats.rs       # Hashrate statistics
│   ├── pow/
│   │   ├── pow_difficulty.rs    # Hybrid Dual EMA difficulty adjustment
│   │   ├── pow_engine.rs        # PoW data persistence
│   │   └── pow_validator.rs     # PoW validation (numeric target)
│   └── stratum/
│       └── stratum_server.rs    # Built-in mining pool (Stratum V1)
│
├── privacy/
│   ├── ringct/
│   │   ├── ring_signature.rs    # LSAG ring signatures v3
│   │   ├── ring_builder.rs      # Ring construction (random position)
│   │   ├── ring_validator.rs    # Ring signature verification
│   │   └── key_image.rs         # Key images + RocksDB persistence
│   ├── confidential/
│   │   ├── bulletproofs.rs      # Fiat-Shamir range proofs
│   │   ├── confidential_tx.rs   # Confidential transactions
│   │   └── pedersen_commitment.rs # Pedersen commitments (Ristretto)
│   ├── shadow_pool/
│   │   ├── shadow_pool.rs       # Transaction mixing pool
│   │   ├── shadow_transaction.rs # Shadow TX with delay tiers
│   │   ├── mixer.rs             # Temporal mixing engine
│   │   └── pool_manager.rs      # Privacy level routing
│   └── stealth/
│       ├── stealth_address.rs   # Stealth address generation
│       ├── stealth_scanner.rs   # Blockchain scanning with view key
│       └── view_key.rs          # HMAC-SHA256 view keys
│
├── orphans/mod.rs               # Orphan block management
├── anti_double_spend/mod.rs     # Double-spend protection (RocksDB)
├── tx_validation/mod.rs         # Multi-stage TX validation pipeline
├── pruning/
│   ├── mod.rs                   # Basic pruning
│   └── pruning_engine.rs        # Advanced pruning (4 levels + UTXO proofs)
└── state_snapshot/mod.rs        # UTXO state snapshots
```

---

### `infrastructure/` — Storage Layer
RocksDB database wrapper and all persistent stores.

```
infrastructure/storage/rocksdb/
├── core/
│   ├── db.rs                # NodeDB wrapper (WAL, recovery, error handling)
│   ├── column_families.rs   # Column family definitions
│   └── migrations.rs        # Schema versioning (v1-v6)
├── blocks/
│   ├── block_store.rs       # Block persistence
│   ├── header_store.rs      # Header persistence
│   └── block_index.rs       # Height-to-hash index
├── transactions/
│   ├── tx_store.rs          # Transaction persistence
│   └── tx_index.rs          # Transaction index
├── utxo/
│   ├── utxo_store.rs        # UTXO persistence + address index
│   └── utxo_index.rs        # UTXO ownership index
├── dag/
│   ├── dag_store.rs         # DAG block relationships
│   └── dag_index.rs         # DAG index
├── state/
│   └── state_store.rs       # Contract state (Merkle roots)
└── peers/
    └── peer_store.rs        # Peer address persistence
```

---

### `runtime/` — Execution Runtime

```
runtime/
├── vm/                          # ShadowVM Smart Contract Engine
│   ├── core/
│   │   ├── vm.rs                # Main execution engine (119 opcodes)
│   │   ├── u256.rs              # 256-bit unsigned integer
│   │   ├── opcodes.rs           # Opcode definitions + gas costs
│   │   ├── assembler.rs         # ASM <-> bytecode + disassembler
│   │   ├── executor.rs          # Contract deployment + calls
│   │   ├── journal.rs           # State rollback (checkpoints)
│   │   └── vm_context.rs        # Storage context
│   ├── contracts/
│   │   ├── contract.rs          # Contract call wrapper
│   │   ├── contract_abi.rs      # ABI encode/decode + selectors
│   │   ├── contract_storage.rs  # RocksDB contract state
│   │   └── token_standard.rs    # SRC-20 token standard
│   └── gas/
│       ├── gas_meter.rs         # Gas tracking (RocksDB)
│       └── gas_rules.rs         # Gas limits + refunds
├── event_bus/
│   ├── event_bus.rs             # Event publication (RocksDB)
│   ├── event_dispatcher.rs      # Event dispatch
│   └── event_types.rs           # Event type definitions
├── node_runtime/
│   ├── runtime.rs               # Runtime wrapper
│   ├── runtime_manager.rs       # Runtime lifecycle
│   └── lifecycle.rs             # Start/stop/panic handlers
└── scheduler/
    ├── task_scheduler.rs        # Task persistence
    └── async_runtime.rs         # Thread-based async runtime
```

---

### `service/` — High-Level Services

```
service/
├── mempool/
│   ├── core/
│   │   ├── mempool.rs           # Main mempool (RocksDB, 50K cap)
│   │   └── mempool_manager.rs   # Mempool orchestrator
│   ├── fees/
│   │   ├── fee_market.rs        # Dynamic fee estimation
│   │   └── tx_prioritizer.rs    # Fee-based TX sorting
│   ├── pools/
│   │   ├── tx_pool.rs           # Transaction pool
│   │   └── orphan_pool.rs       # Orphan transaction pool
│   ├── index/mod.rs             # Mempool index (fee, spend tracking)
│   └── eviction/mod.rs          # Eviction policies (age, fee)
│
├── network/
│   ├── p2p/
│   │   ├── p2p.rs               # P2P network layer (TCP)
│   │   ├── peer.rs              # Peer connection state
│   │   ├── peer_manager.rs      # Peer registry (RocksDB, bans, scoring)
│   │   ├── protocol.rs          # Protocol messages + validation
│   │   └── message.rs           # Network message types
│   ├── nodes/
│   │   ├── boot.rs              # Node bootstrap sequence
│   │   ├── full_node.rs         # Full node implementation
│   │   ├── light_node.rs        # SPV light node
│   │   └── shadow_node.rs       # Privacy relay node
│   ├── relay/
│   │   ├── block_relay.rs       # Block broadcast + orphan pool
│   │   ├── tx_relay.rs          # Transaction broadcast (dedup)
│   │   └── inv_relay.rs         # Inventory announcements
│   ├── rpc/
│   │   ├── rpc_server.rs        # JSON-RPC server (16+ methods)
│   │   ├── grpc_server.rs       # Binary gRPC server (18 methods)
│   │   └── health.rs            # Health check + Prometheus metrics
│   ├── discovery/               # Peer discovery (DNS seeds)
│   ├── sync/mod.rs              # Block synchronization
│   ├── connection_manager/mod.rs # Connection lifecycle
│   ├── address_manager/mod.rs   # Address table (new/tried)
│   ├── reputation/mod.rs        # Peer reputation scoring
│   ├── dos_guard/mod.rs         # DoS protection
│   └── ...                      # Additional network modules
│
├── wallet/
│   ├── core/
│   │   ├── wallet.rs            # HD wallet (AES-256-GCM encrypted)
│   │   ├── wallet_manager.rs    # Wallet lifecycle
│   │   └── wallet_sync.rs       # Wallet-chain sync
│   ├── keys/
│   │   ├── key_manager.rs       # Key storage (encrypted)
│   │   ├── hd_wallet.rs         # Hierarchical deterministic derivation
│   │   └── multisig.rs          # M-of-N multi-signature
│   └── storage/
│       ├── wallet_db.rs         # Wallet persistence
│       └── address_book.rs      # Address book
│
├── events/
│   ├── mod.rs                   # Event bus + node events
│   └── pubsub.rs               # Pub-sub notification (10 topics)
│
└── rpc/auth/mod.rs              # RPC authentication (SHA-256 + tokens)
```

---

### `telemetry/` — Monitoring

```
telemetry/
├── logging/
│   ├── logger.rs                # Log recording (RocksDB)
│   └── log_config.rs           # env_logger initialization
├── metrics/
│   ├── metrics.rs              # Metrics collection (RocksDB)
│   └── prometheus.rs           # Prometheus HTTP exporter
└── tracing/
    └── tracing.rs              # Distributed tracing
```

---

### `tests/` — Integration Tests

| Test File | What It Tests |
|-----------|---------------|
| `consensus_tests.rs` | Block validation, fork choice |
| `dag_tests.rs` | DAG operations, GHOSTDAG |
| `db_tests.rs` | RocksDB read/write/batch |
| `determinism_tests.rs` | Deterministic execution |
| `dos_tests.rs` | DoS protection |
| `genesis_tests.rs` | Genesis block integrity |
| `mempool_tests.rs` | Mempool operations |
| `mempool_advanced_tests.rs` | Fee markets, eviction |
| `p2p_network_tests.rs` | Peer connections, messages |
| `performance_tests.rs` | Throughput benchmarks |
| `pow_genesis_tests.rs` | PoW mining verification |
| `recovery_tests.rs` | Crash recovery |
| `rpc_tests.rs` | JSON-RPC methods |
| `security_tests.rs` | Security properties |
| `stress_tests.rs` | High-load scenarios |
| `transaction_tests.rs` | TX creation, signing |
| `tx_layer_tests.rs` | TX pipeline |
| `tx_validator_tests.rs` | Signature verification |
| `utxo_tests.rs` | UTXO operations |
| `utxo_layer_tests.rs` | UTXO set management |
| `utxo_state_tests.rs` | UTXO state consistency |

---

## Data Flow

```
User/Miner
    │
    ▼
┌─────────┐    ┌──────────┐    ┌────────────┐
│   RPC   │───▶│ Mempool  │───▶│   Block    │
│ Server  │    │          │    │  Builder   │
└─────────┘    └──────────┘    └────────────┘
                                     │
                                     ▼
                              ┌────────────┐
                              │   Mining   │
                              │ (PoW/GPU)  │
                              └────────────┘
                                     │
                                     ▼
┌─────────┐    ┌──────────┐    ┌────────────┐
│   P2P   │◀──▶│   DAG    │◀──│ Consensus  │
│ Network │    │ Manager  │    │ Validator  │
└─────────┘    └──────────┘    └────────────┘
                    │
                    ▼
              ┌──────────┐
              │ RocksDB  │
              │ Storage  │
              └──────────┘
```

## Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| Max Supply | 21 billion SDAG | `config/consensus/consensus_params.rs` |
| Block Reward | 10 SDAG | `config/consensus/consensus_params.rs` |
| Halving Interval | 210M blocks | `config/consensus/emission_schedule.rs` |
| Miner Share | 95% | `config/consensus/consensus_params.rs` |
| Dev Share | 5% | `config/consensus/consensus_params.rs` |
| GHOSTDAG K | 18 | `config/consensus/consensus_params.rs` |
| Max Parents | 8 | `config/consensus/consensus_params.rs` |
| Max Block Size | 2 MB | `config/consensus/consensus_params.rs` |
| Max TX per Block | 5,000 | `config/consensus/consensus_params.rs` |
| Dust Limit | 546 satoshis | `domain/transaction/tx_validator.rs` |
| Coinbase Maturity | 100 blocks | `domain/utxo/utxo_set.rs` |
| Max Gas per TX | 10M | `runtime/vm/gas/gas_rules.rs` |
| Target Block Time | 1 second | `engine/mining/pow/pow_difficulty.rs` |
| Short EMA Window | 144 blocks | `engine/mining/pow/pow_difficulty.rs` |
| Long EMA Window | 2016 blocks | `engine/mining/pow/pow_difficulty.rs` |
| Min Ring Size | 3 | `engine/privacy/ringct/ring_signature.rs` |
| Default Ring Size | 11 | `engine/privacy/ringct/ring_signature.rs` |
