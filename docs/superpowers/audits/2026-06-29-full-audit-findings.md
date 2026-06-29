# Full Project Audit — Findings & Remediation Tracker

**Date:** 2026-06-29
**Scope:** 5 parallel adversarial audits (RingCT phase-1 consensus changes, unreviewed
pre-session WIP in consensus / network / RPC, new HD-wallet crypto, general bug sweep)
plus maintainer spot-verification of the highest-severity items.

**Baseline health:** `cargo build --all-targets` clean · `cargo test --lib` 2150 pass ·
`cargo clippy --all-targets` clean. The bugs below are runtime/logic issues the build
and tests did not catch.

Status legend: ✅ fixed · 🔧 in progress · ⏳ planned · 🔎 needs design decision

---

## RingCT phase-1 (work done this session) — INCOMPLETE / not consensus-enforced

| ID | Sev | Status | Location | Issue | Fix |
|----|-----|--------|----------|-------|-----|
| R0 | — | ✅ | README/ARCHITECTURE | False "sender privacy enabled in consensus" claim | Corrected to "mempool-only / experimental" |
| R1 | CRIT | 🔎 | `block_validator.rs:351`, `utxo_validator.rs:111`, `full_node.rs` | `validate_confidential` runs only in mempool path; block validation/apply never call it → ring sigs unenforced in blocks + mempool/block rule divergence | Call `validate_confidential` for confidential TXs inside `validate_block_utxos`; gate the apply path too |
| R2 | CRIT | 🔎 | `utxo_set.rs` (recording in `apply_block_write_with_commitment`), live path is `apply_block_dag_ordered` | `ki:`/`okey:` recording is in the non-live apply fn; live path records nothing → key-image double-spend not caught; `okey:` empty → mempool rejects all confidential TXs | Record `ki:`/`okey:` in `apply_block_dag_ordered` in the same atomic WriteBatch |
| R3 | HIGH | 🔎 | `utxo_set.rs` okey recording | `okey:` indexes `ephemeral_pubkey` (sender R), but ring members are one-time output pubkeys — never match | Define + record the canonical one-time output key; wallets draw decoys from same set |
| R4 | HIGH | ⏳ | `clsag.rs:39-50` | CLSAG challenge omits key image + ring; soundness currently rests on the message layer (brittle; breaks for phase-2 dual-key) | Fold `key_image` and all `ring[i]` into `challenge_hash` (CLSAG paper); add cross-ring rejection test |
| R5 | MED | ⏳ | `ring_validator.rs` verify_clsag | No dedup / identity-point rejection of ring members → ring of all-attacker-key, shrinks anonymity set | Reject duplicate + identity/low-order members |
| R6 | MED | 🔎 | `tx_validator.rs` validate_tx_for_network | Transparent input model (get_utxo + Ed25519 ownership) stapled to ring model — confidential input still needs a visible outpoint + transparent sig, defeating privacy | Decide phase-1 model: either keep transparent (document "no privacy yet") or bypass transparent input checks for confidential inputs and rely on ring + key image |

> **Recommendation:** RingCT phase-1 as merged is not coherent. Either (a) do a focused
> phase-1b that wires the gate + recording into the block path and fixes R3/R5/R6, with
> dedicated review, or (b) keep the CLSAG code but mark it experimental and out of the
> consensus path until phase-1b. R4 (dual-key challenge) is a prerequisite for phase-2
> (amount hiding).

---

## CRITICAL (pre-existing) 

| ID | Status | Location | Issue | Fix |
|----|--------|----------|-------|-----|
| C1 | ✅ | `runtime/vm/core/execution_env.rs` MLOAD/MSTORE/MSTORE8/LOG/CREATE2/CALLDATALOAD | `offset + N` wraps in release → slips past MAX_MEMORY_SIZE guard → slice panic; any contract halts every node | Routed through `checked_add` like COPY/RETURNDATACOPY; regression test added |
| C4 | ✅ | `service/network/sync/chain_verifier.rs:159/160/208` | Byte-slicing peer hash `&s[..16]` panics on multibyte UTF-8 → any peer crashes sync | `short_hash()` char-based truncation; regression tests added |
| C2 | ⏳ | `engine/dag/core/block_graph.rs:644` `dfs_has_cycle` | Unbounded recursion (1 frame/ancestor) → stack overflow on deep chain → uncatchable abort | Rewrite as explicit work-stack loop |
| C3 | ⏳ | `engine/state_snapshot/mod.rs:355-379` | Snapshot restore clears UTXO set then restores in two separate `db.write`s; crash between = zero-UTXO set | Merge clear + restore into one `WriteBatch` with `set_sync(true)` |

---

## HIGH (pre-existing)

| ID | Location | Issue | Fix |
|----|----------|-------|-----|
| H-coinbase | `block_validator.rs:936-968` | Coinbase upper bound trusts *declared* fees → phantom-fee inflation unless a post-execution check re-bounds to emission+applied_fees | Verify/ add authoritative post-execution coinbase amount check |
| H-net | `utxo_validator.rs:239-252` | `validate_block_utxos` infers network from first input owner (defaults Mainnet) → wrong chain-id verification on testnet/regtest | Pass authoritative `NetworkMode` in; reject mismatches |
| H-sig | `tx_validator.rs:1022` | Block path uses non-strict `verify()` + manual low-order list; mempool path uses `verify_strict` → divergent signature acceptance | Use `verify_strict` uniformly |
| H-dos | `service/network/dos_guard/mod.rs:486` | `is_banned` inserts a record on every read (pre-auth) → address-rotating memory DoS | Make read-only; hard-cap the map |
| H-utxostore | `infrastructure/storage/rocksdb/utxo/utxo_store.rs:42/50` | `add_utxo` writes record + addr index as two non-atomic puts → crash = orphan/invisible UTXO | Single WriteBatch |
| H-tip | `infrastructure/storage/rocksdb/blocks/block_store.rs:101/130/349` | `best_hash`/utxo_commitment/height are lone non-sync puts → crash can advance tip past unpersisted commitment | Sync-write commitment first, tip last (`put_sync`) |
| H-receipt | `indexes/receipt_index/mod.rs:127` | `rollback_block` does `unwrap_or_default()` on corrupt data → returns Ok, serves stale receipts after reorg | Propagate the error |
| H-maps | `service/network/propagation/mod.rs:31`, `sync_engine/mod.rs:252` | `peer_seen` / `retry_counts` grow unbounded → memory DoS from a connected peer | Cap/evict both |

---

## MEDIUM / LOW (pre-existing) — summary

- **MED** reorg state mutated before work validation (`reorg/mod.rs:202`); difficulty persist write swallowed (`difficulty_adjustment.rs:205`); topological in-degree decrement underflow (`dag/traversal/mod.rs:224`); ZeroConfGuard `block_inputs` unbounded + partial insert (`zero_conf_guard.rs`); pool payout unchecked mul/underflow (`stratum_server.rs:1189/1226`); global state Mutex held across VM simulation in contract RPC (`rpc_server.rs:4288+`); RPC auth compares formatted string not decoded hash (`auth/mod.rs:493`).
- **HD wallet (this session):** seed `[u8;64]` + unused `password: String` not zeroized (`hd_wallet.rs`); `Mnemonic`/entropy not zeroized (`mnemonic.rs`); decrypted plaintext buffer not zeroized (`key_manager.rs:97`); unknown-network → silent Mainnet in derivation.
- **LOW** header-locator `step *= 2` unchecked; clock-regression `now - x` underflows in gossip/dandelion timers (use `saturating_sub`); `estimategas` vs `estimate_gas` method-name mismatch (`contract_ide`); IPv6 `[::1]` Host parsing rejects loopback (explorer/wallet_ui — fails closed); some stores bypass `db.rs::safe_options` WAL/atomic-flush.

---

## Verified-correct (do not re-investigate)
Amount/fee/merkle/difficulty core hardened (checked/saturating math) · RPC auth has no bypass (constant-time compare, decoy hash, fail-closed) · wire-frame + gRPC validate length before alloc · CLSAG/serialization/stealth validate lengths before alloc, `Option` decoders (no unwrap on untrusted bytes) · COPY/RETURNDATACOPY memory ops already `checked_add`-guarded · no parking_lot guard held across `.await` · genesis deterministic + cross-network distinct + mainnet refuses re-mine.

---

## Suggested order
1. ✅ R0 (docs), C1, C4 — done this session.
2. C2, C3 — contained CRITICALs.
3. Decide RingCT direction (R1/R2/R3/R6) — phase-1b or mark experimental.
4. HIGH batch (H-coinbase post-exec check first, then H-net, H-sig, storage atomicity).
5. R4/R5, then MEDIUM/LOW + HD-wallet zeroization.
