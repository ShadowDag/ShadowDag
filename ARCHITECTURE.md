# ShadowDAG Architecture Guide

Complete technical reference. All constants from the actual codebase.

---

## Codebase Statistics

| Metric | Value |
|--------|-------|
| Total Rust files | 328 |
| Total lines of code | 130,415 |
| Binary targets | 5 |
| Library modules | 12 top-level |
| Test files | 21 |
| Benchmark suites | 2 |

---

## 1. Binaries (`bin/`)

| Binary | File | Purpose |
|--------|------|---------|
| `shadowdag-node` | `node.rs` | Full node: P2P + RPC + consensus + GHOSTDAG + Explorer + Wallet UI |
| `shadowdag-miner` | `miner.rs` | Multi-threaded ShadowHash miner via RPC |
| `shadowdag-wallet` | `wallet.rs` | HD wallet CLI: stealth, invisible, multisig, send/receive, contracts |
| `shadowdag-loadtest` | `loadtest.rs` | HTTP RPC load tester with auth token support |
| `mine-genesis` | `mine_genesis.rs` | One-shot genesis block miner for all networks |

**Node flags for web UIs:**

| Flag | Default Port | Description |
|------|-------------|-------------|
| `--enable-explorer` | 8080 | Block explorer with DAG visualization |
| `--enable-wallet-ui` | 8081 | Desktop wallet UI (localhost only) |
| `--enable-ide` | 3000 | Smart contract IDE |
| `--enable-stratum` | 7779 | Stratum V1 mining pool |

---

## 2. Consensus (`config/consensus/` + `engine/consensus/`)

### Core Parameters (`consensus_params.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `CHAIN_ID` | `0xDA0C_0001` | Network identifier (wire protocol) |
| `BLOCKS_PER_SECOND` | 10 | Target block production rate |
| `BLOCK_TIME` | 1 second | Target inter-block time |
| `GHOSTDAG_K` | 180 | Blue set anticone limit (18 x BPS) |
| `MAX_PARENTS` | 80 | Maximum DAG parents per block (8 x BPS) |
| `MAX_BLOCK_SIZE` | 2 MB | Maximum serialized block size |
| `MAX_BLOCK_TXS` | 10,000 | Maximum transactions per block |
| `COINBASE_MATURITY` | 1,000 blocks | Blocks before coinbase is spendable |
| `MIN_FEE` | 100 satoshis | Minimum transaction fee |
| `DUST_LIMIT` | 1,000 satoshis | Minimum output amount |

### Emission Schedule (`emission_schedule.rs`)

Smooth exponential decay (no hard halvings):

| Parameter | Value |
|-----------|-------|
| Initial Reward | 10 SDAG (1,000,000,000 satoshis) |
| Max Supply | 21,000,000,000 SDAG |
| Decay Rate | 99.62% per step (0.38% reduction) |
| Step Interval | ~30 days (2,592,000 seconds) |
| Half-life | ~5.5 years (~182 steps) |
| Minimum Reward | 1 satoshi |
| Precision | 10^18 fixed-point |

### Reward Split (`engine/consensus/rewards/reward.rs`)

| Recipient | Share |
|-----------|-------|
| Miner | 95% |
| Developer Fund | 5% |

**Selfish Mining Penalties:**

| Condition | Penalty |
|-----------|---------|
| Red block (anticone > K) | 80% reduction (keeps 20%) |
| Late block (per second) | 5% compounded decay |
| Minimum floor | 10% of normal reward |

### Difficulty Adjustment (`engine/consensus/difficulty/retarget.rs`)

| Parameter | Value |
|-----------|-------|
| Target Block Time | 1 second |
| Short Window | max(144, BPS x 15) blocks |
| Long Window | max(2016, BPS x 200) blocks |
| EMA Alpha | 1/20 |
| Max Adjust Up/Down | 4x per retarget |
| DAG Rate Correction | Uses `dag_block_count` + `blue_score_rate` |
| Match Rule | Strict equality (no tolerance) |

### Finality (`engine/consensus/finality.rs` + `reorg/mod.rs`)

| Parameter | Value |
|-----------|-------|
| Base Finality Depth | 200 blocks (~20s at 10 BPS) |
| Min Finality Depth | 100 blocks |
| Max Finality Depth | 2,000 blocks |
| Finality Epoch | 1,000 blocks (metric recalculation) |
| Checkpoint Interval | 10,000 blocks (auto) |
| Max Reorg Depth | 1,000 blocks |
| Economic Finality | 10,000 difficulty units |
| Work Ratio | 100/100 (integer, >=1x required) |

---

## 3. GHOSTDAG (`engine/dag/ghostdag/`)

### Blue/Red Classification

- Block is **blue** if anticone size <= K (180)
- Block is **red** if anticone size > K
- Blue blocks get full rewards; red blocks get 20%
- Selected parent: highest blue_score -> height -> lowest hash

### Storage (RocksDB prefixes)

| Prefix | Data |
|--------|------|
| `gd:blk:` | Block metadata |
| `gd:par:` | Parent links |
| `gd:chl:` | Children links |
| `gd:blue:` | Blue set (diff per block) |
| `gd:red:` | Red markers |
| `gd:score:` | Blue scores |
| `gd:sel:` | Selected parent |
| `gd:order:` | Execution order index |

---

## 4. Mining (`engine/mining/`)

### ShadowHash Algorithm (`algorithms/shadowhash.rs`)

4-stage ASIC-resistant pipeline:

| Stage | Algorithm | Purpose |
|-------|-----------|---------|
| 1 | SHA-256 | Compute-bound seed |
| 2 | Blake3 + 256KB scratchpad | Memory-hard (16 mix rounds) |
| 3 | SHA3-256 | ASIC-breaking combiner |
| 4 | Anti-ASIC nonce mixing | Dynamic data-dependent access |

**Key constants:**
- `SCRATCHPAD_SIZE`: 262,144 bytes (256 KB)
- `MIX_ROUNDS`: 16

### PoW Validation (`pow/pow_validator.rs`)

- Method: `hash_bytes <= target_bytes` (256-bit comparison)
- Target: `MAX_TARGET / difficulty` (256-bit division)
- NOT leading zeros — proper numeric comparison

---

## 5. ShadowVM (`runtime/vm/`)

### Architecture

- Stack-based (256-bit U256 elements)
- 90+ opcodes in 16 categories
- Deterministic execution (10 invariants enforced)
- Gas-first: every opcode checked BEFORE execution
- Atomic state: WriteBatch commits only on STOP/RETURN

### Limits

| Limit | Value |
|-------|-------|
| Max Contract Size | 24 KB |
| Max Memory | 1 MB |
| Default Gas Limit | 10,000,000 |
| Max Gas Per TX | 10,000,000 |
| Max Gas Per Block | 100,000,000 |
| Min Opcode Cost | 1 gas |
| Memory Cost | 3 gas/word + words^2/512 |
| SSTORE Cost | 5,000 gas |
| CREATE Cost | 32,000 gas |

### Opcode Categories

| Range | Category | Examples |
|-------|----------|---------|
| 0x00-0x0F | Control | STOP, NOP, GAS |
| 0x10-0x1F | Stack | PUSH1-32, POP, DUP, SWAP |
| 0x20-0x2F | Arithmetic | ADD, SUB, MUL, DIV, EXP |
| 0x30-0x3F | Comparison | LT, GT, EQ, ISZERO |
| 0x40-0x4F | Bitwise | AND, OR, XOR, SHL, SHR |
| 0x50-0x5F | Storage | SLOAD(200), SSTORE(5000) |
| 0x60-0x6F | Crypto | SHA256(30), ECRECOVER(3000) |
| 0x70-0x7F | Context | CALLER, TIMESTAMP, BLOCKHASH |
| 0x80-0x8F | Flow | JUMP, JUMPI |
| 0x90-0x9F | Memory | MLOAD, MSTORE |
| 0xA0-0xAF | Logging | LOG0-LOG4 |
| 0xE0-0xEF | ShadowVM Extensions | STEALTHCHECK, RINGPROOF, DAGTIPS |

### Determinism Invariants

1. No floating point (f32/f64)
2. No system time (TIMESTAMP from block header)
3. No random (BLOCKHASH is only source)
4. No I/O (no filesystem/network/process)
5. Integer-only arithmetic (U256 wrapping)
6. Deterministic storage parsing
7. Pre-execution gas metering
8. `has_gas()` restricted to VM internals
9. All opcodes cost >= 1 gas
10. Atomic state commits

---

## 6. P2P Network (`service/network/`)

### Wire Protocol (`p2p/protocol.rs`)

**Header format** (13 bytes):
```
[Magic 4B][CommandID 1B][Length 4B BE][Checksum 4B SHA256]
```

| Protocol Constant | Value |
|-------------------|-------|
| Protocol Version | 1 |
| Chain ID | 0xDA0C_0001 |
| Max Message Size | 4 MB |
| Handshake Timeout | 10 seconds |
| Puzzle Timeout | 30 seconds |

### Connection Puzzle (Anti-Sybil)

| Parameter | Value |
|-----------|-------|
| Difficulty | 3 leading hex zeros |
| Average hashes | ~4,096 |
| Expiry | 300 seconds |

### DoS Guard (`dos_guard/mod.rs`)

**Token Bucket:**
- Refill: 800 tokens/second
- Capacity: 4,000 tokens

**Message Costs:**
- TX: 3 tokens, Block: 8 tokens, GetBlocks: 5 tokens, Mempool: 10 tokens

**Global Limits:**
- Max TX/sec: 50,000
- Max blocks/sec: 200

### Reputation (`reputation/mod.rs`)

- Initial score: 100, ban at -50, auto-ban at -80
- Invalid block: -20, spam: -5, misbehavior: -50
- Valid block: +2, valid TX: +1
- Age bonus: +2/hour (max +48)
- Reputation-aware eviction when at capacity

### Peer Limits

| Limit | Mainnet | Testnet | Regtest |
|-------|---------|---------|---------|
| Max Peers | 64 | 32 | 8 |
| Max Inbound | 56 | 28 | 7 |
| Max Outbound | 8 | 4 | 1 |
| Per IP | 3 | 3 | 3 |
| Per /16 Subnet | 2 | 2 | 2 |

---

## 7. Mempool (`service/mempool/`)

### Admission Pipeline

```
L1   Network:     Size, hash, input validation (no crypto)
L1.5 Anti-replay: Timestamp range + payload_hash
L1.6 Type-specific: SwapTx 2x fee, DexOrder 1.5x fee
L2   Structural:  Signature verification
L4   Execution:   Fee >= MIN_RELAY_FEE, fee_rate >= surge_price
L5   Anti-spam:   Per-sender limit (25 TXs max)
```

### Surge Pricing (exponential)

```
Multiplier = 2^(utilization x 6), capped at 64x

  0% full:  1.0x base rate
 25% full:  2.8x
 50% full:  8.0x
 75% full: 22.6x
 90% full: 39.4x
100% full: 64.0x (cap)
```

### Eviction

- CPFP-aware: descendant-package fee rate, not individual fee
- Batch size: 256 TXs per eviction cycle
- Max age: 72 hours
- RBF: min 1,000 sat bump, max 25 ancestor depth

---

## 8. Privacy (`engine/privacy/`)

| Layer | Implementation | Purpose |
|-------|---------------|---------|
| CLSAG Ring Signatures | `ringct/clsag.rs` | Sender anonymity (ring of decoys) |
| Key Images | `ringct/key_image.rs` | Double-spend prevention |
| Pedersen Commitments | `confidential/pedersen.rs` | Hidden amounts |
| Bulletproofs | `confidential/bulletproofs.rs` | Range proofs (amount >= 0) |
| Stealth Addresses | `stealth/stealth_address.rs` | One-time receive addresses |
| Shadow Pool | `shadow_pool/` | Privacy-first TX aggregation |
| Dandelion++ | `service/network/propagation/` | Network-layer anonymity |

---

## 9. Validation Pipeline (`engine/consensus/validation/`)

### Block Validation (4 layers, strictly separated)

| Layer | Checks | State Access |
|-------|--------|-------------|
| L1 Network | Size, format, DoS, duplicates | None |
| PoW | ShadowHash recompute + target comparison | None |
| L2 Structural | Merkle root, signatures, timestamps (6 rules) | None |
| L3 Consensus | Difficulty match (strict), checkpoints, coinbase | None |
| L4 Execution | UTXO apply in GHOSTDAG order | UTXO set |

**SAFETY INVARIANT**: L1-L3 are 100% stateless. No DB reads.

### Timestamp Rules

| Rule | Check |
|------|-------|
| R1 | `ts <= now + 120s` (future cap) |
| R2 | `ts >= now - 600s` (wall-clock anchor) |
| R3 | `ts > MTP` (weighted median, no dedup) |
| R4 | `ts > max_ancestor_ts` (strict monotonic) |
| R5 | `ts <= max_parent + 30s` (jump cap) |
| R6 | `ts <= max_parent + 10s` when >= 3 parents (DAG-dense) |

---

## 10. Storage (`infrastructure/storage/rocksdb/`)

### RocksDB Configuration

- WAL: Always enabled (`disable_wal(false)` x18)
- Recovery mode: `TolerateCorruptedTailRecords`
- Atomic flush: Enabled
- Consensus writes: `sync=true`
- Cache writes: `sync=false` (rebuildable)

### Key Namespaces

| Prefix | Store | Data |
|--------|-------|------|
| `blk:` | BlockStore | Serialized blocks |
| `blk:height:` | BlockStore | Height index |
| `blk:best_hash` | BlockStore | Current chain tip |
| `tx:` | Mempool | Pending transactions |
| `fee:` | Mempool | Fee index (inverted) |
| `gd:*` | GhostDAG | DAG topology + scores |
| `addr:` | UtxoStore | Address -> UTXO index |
| `ban:` | PeerManager | Peer bans |
| `chkpt:` | FinalityManager | Auto-checkpoints |

---

## 11. Web UIs (`service/network/explorer/`, `wallet_ui/`, `contract_ide/`)

Three embedded web interfaces served directly from the node binary. No external dependencies or separate frontend builds required.

### Block Explorer (`service/network/explorer/`)

Advanced single-page application for browsing the blockchain.

| Component | Details |
|-----------|---------|
| Default Port | 8080 (`--explorer-port`) |
| Bind | Configurable via `SHADOWDAG_EXPLORER_BIND` (default: 127.0.0.1) |
| Flag | `--enable-explorer` |
| Architecture | Thread-per-connection HTTP (max 100 concurrent) |
| Frontend | Embedded HTML/CSS/JS SPA (dark theme, responsive) |

**API Endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /` | Explorer SPA (auto-refreshing dashboard) |
| `GET /api/stats` | Network statistics (height, peers, mempool, chain info) |
| `GET /api/blocks` | Latest 40 blocks with metadata |
| `GET /api/block/{id}` | Block detail (by hash or height) with transactions |
| `GET /api/tx/{hash}` | Transaction detail (inputs, outputs, type, status) |
| `GET /api/address/{addr}` | Address balance (SDAG + satoshis) |
| `GET /api/mempool` | Pending transactions list + total fees |
| `GET /api/dag` | DAG graph data (nodes + edges for visualization) |
| `GET /api/network` | Network info (peers, version, ports) |
| `GET /api/richlist` | Top addresses by balance |
| `GET /api/pool` | Mining pool status (Stratum) |
| `GET /api/search/{query}` | Universal search (block/tx/address auto-detect) |

**Frontend Features:**
- Dashboard with live stats (auto-refresh every 5s)
- Block list with detail view and parent chain navigation
- Transaction viewer with inputs/outputs and confirmation status
- DAG visualization (interactive Canvas-based graph)
- Mempool viewer with fee statistics
- Rich list (top addresses)
- Network info with Stratum pool status
- Universal search (hash, height, address)

### Desktop Wallet UI (`service/network/wallet_ui/`)

Browser-based wallet interface for managing SDAG. Runs on **localhost only** for security.

| Component | Details |
|-----------|---------|
| Default Port | 8081 (`--wallet-ui-port`) |
| Bind | 127.0.0.1 only (hardcoded, never network-exposed) |
| Flag | `--enable-wallet-ui` |
| Architecture | Thread-per-connection HTTP (max 10 concurrent) |
| Methods | GET + POST (JSON body for send operations) |
| Max Body | 64 KB |

**API Endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /` | Wallet SPA (sidebar navigation) |
| `GET /api/wallet/overview` | Node status + chain info |
| `GET /api/wallet/balance/{addr}` | Address balance query |
| `GET /api/wallet/network` | Network connection details |
| `POST /api/wallet/send` | Prepare transaction (JSON: `{to, amount}`) |

**Frontend Features:**
- Overview with balance display and quick actions
- Send form with address validation (SD/ST/SR prefixes)
- Receive view with address display and QR pattern
- Transaction history (CLI integration reference)
- Address book with quick balance check
- Settings with node connection info and CLI command reference

### Contract IDE (`service/network/contract_ide/`)

Web-based ShadowASM editor with syntax highlighting and in-process compilation.

| Component | Details |
|-----------|---------|
| Default Port | 3000 (`--ide-port`) |
| Flag | `--enable-ide` |

---

## 12. RPC & gRPC (`service/network/rpc/`)

### JSON-RPC over HTTP

- Endpoint: `POST /` or `POST /rpc`
- Auth: Bearer token for write methods
- Request validation: method, headers (64 lines/16KB max), body size
- HTTP status codes: 200/400/401/404/429/500 (not always 200)

### gRPC

- Binary length-prefixed protocol
- Method dispatch via registered handlers
- Non-blocking accept loop with graceful stop

---

## 13. CI/CD (`.github/workflows/ci.yml`)

| Job | Command |
|-----|---------|
| Check | `cargo check --all-targets` |
| Test | `cargo test --lib --bins` |
| Clippy | `cargo clippy -- -D warnings` |

Triggered on: push to main/develop, PRs to main.

---

## Design Rules

1. **Integer math only** in consensus code (no f64 in critical paths)
2. **RocksDB WAL always on** for crash safety
3. **Atomic WriteBatch** for all multi-key state changes
4. **Fail-stop** on consensus errors (no continue-on-error)
5. **Stateless validation** in Phase 1 (L1-L3 read no state)
6. **DAG-aware** everything (difficulty, finality, timestamps, fees)
7. **Economic penalties** for misbehavior (red blocks, late blocks)
8. **Deterministic VM** (10 invariants, no float/IO/random)
9. **Defense in depth** (puzzle + reputation + diversity + DoS guard)
10. **Smooth emission** (no halving cliffs, predictable supply curve)
