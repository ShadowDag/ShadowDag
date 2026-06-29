# ShadowDAG — External Audit Scope & Reviewer Brief

Purpose: give an external crypto + consensus auditor the fastest path to the
parts that matter. ~163k LOC Rust BlockDAG privacy coin (GHOSTDAG consensus,
custom ShadowVM, RingCT-style privacy, ShadowHash PoW, RocksDB).

An internal hardening pass fixed 22+ vulnerabilities (see
`docs/MAINNET_READINESS.md` and `docs/superpowers/audits/`). This brief points at
what an external review must independently verify — especially the items that
were NOT in scope for the internal pass.

---

## 1. Highest priority — crypto SOUNDNESS (NOT verified internally)

The internal pass checked crypto *implementation* pitfalls (RNG, point/identity
validation, constant-time, encoding) but did NOT verify mathematical soundness.
A cryptographer must review:

- **Dual-key CLSAG** ring signature: `engine/privacy/ringct/dual_clsag.rs`
  (`sign`, `verify`, `agg_coeff`, `challenge`, `key_image`). Verify the
  aggregation, the challenge construction (domain separation `CLSAG2_*_v1`), and
  linkability/unforgeability.
- **Pedersen commitments + generator**: `engine/privacy/confidential/pedersen.rs`.
- **Range proofs / Borromean / bulletproofs** usage: `engine/privacy/ringct/`,
  `bulletproofs` crate integration.
- **Amount encryption (ECDH)** + **stealth addresses**: `engine/privacy/ringct/`,
  `domain/address/invisible_wallet.rs`.
- **Balance / commitment conservation** at consensus:
  `engine/privacy/ringct/confidential_consensus.rs` (`verify_confidential_tx`).

## 2. Consensus — fork choice & finality (NEW code, needs review)

- **FC1 cumulative-work fork choice (NEW this pass):**
  `service/network/nodes/full_node.rs` — `cumulative_work` / `cumulative_work_inner`,
  `select_best_tip` / `select_best_tip_inner`, `should_keep_current_tip_on_tie`,
  `recompute_virtual_chain`; recovery uses the same `select_best_tip_inner` in
  `daemon/mod.rs` (`rebuild_ghostdag`). Verify determinism across nodes and that
  the tie-breaks + finality window are sound.
- **Finality:** deep-reorg rejection at `full_node.rs` (`MAX_REORG_DEPTH = 200`,
  checked pre-write on both new-chain length and rollback depth). The
  `FinalityManager` (`engine/consensus/finality.rs`) auto-checkpoints are computed
  but NOT consulted by the reorg path (see DEFERRED item G/FC2 enhancement).
- **GHOSTDAG**: `engine/dag/ghostdag/ghostdag.rs` (`add_block`, blue-set
  classification, `blue_score`, `chain_height`, ordering).
- **Difficulty / retarget**: `engine/consensus/difficulty/`,
  `full_node.rs::build_retarget_from_canonical` + `expected_difficulty_for_block`.
- **Live block-accept path** (single most important control flow):
  `full_node.rs::process_block_inner` → `validate_block_full_with_difficulty`
  (stateless L1–L3) → `recompute_virtual_chain` → UTXO apply
  (`domain/utxo/utxo_set.rs::apply_block_dag_ordered`). NOTE: `validate_block_utxos`
  runs on genesis + `apply_block_full`, NOT on the live peer path — confirm every
  stateful gate is present on the live path.

## 3. ShadowVM / smart contracts

- Live VM: `runtime/vm/core/execution_env.rs` (`execute_frame` / `execute_frame_guarded`)
  via `runtime/vm/core/executor.rs`. (`runtime/vm/core/vm.rs` is a legacy engine,
  no live caller.)
- Review: gas metering completeness, value/balance conservation in the CALL/CREATE
  family, reentrancy guard coverage, storage isolation, determinism, EVM-semantic
  conformance (SHL/SHR/offset handling were fixed this pass).
- State: `runtime/vm/core/state_manager.rs` (journaling/rollback, `state_root`).

## 4. DEFERRED items requiring design + review before mainnet

- **G — contract state-root not in consensus.** `state_root` is deterministic
  (`state_manager.rs`, BTreeMap-backed) but emitted as `None` and never validated;
  binding it requires changing block hashing + the mining flow. Decide whether
  contract state must be consensus-committed.
- **ST1 — cross-store write atomicity.** `block/DAG/UTXO/indexes` share one RocksDB
  (`daemon/mod.rs`: `node_db.shared()`); `contract_storage` is a SEPARATE DB.
  Within the shared DB, per-block writes use separate WriteBatches (mitigated by
  block-store-first + recovery rebuild + the contract `applied` marker). Evaluate a
  unified WriteBatch / column-family design and whether contract storage should
  move into the shared DB.

## 5. Crash recovery

- `daemon/mod.rs::verify_and_recover` + `rebuild_ghostdag`. The block store is the
  source of truth; DAG/UTXO are rebuilt from it. Verify recovery is total and that
  the count-based integrity check is sufficient.

## 6. P2P / DoS surface

- `service/network/p2p/p2p.rs` + `peer_manager.rs` (per-IP caps, `MAX_STORED_PEERS`,
  Addr validation, bounded deserialization), `service/network/relay/block_relay.rs`
  (orphan pool admission now binds the recomputed hash).

## 7. Known disabled features (confirm intended)

Multisig threshold aggregation (stub), SDK HTTPS (unsupported), gRPC partial,
pq-dilithium (off). See `docs/MAINNET_READINESS.md`.

---

## How to reproduce the baseline

```
cargo build --all-targets
cargo test --lib              # ~2218 unit + integration/e2e/proptest/security tests
cargo test --doc
cargo clippy --all-targets -- -D warnings
```
All green as of the hardening pass. CI: `.github/workflows/ci.yml`.
