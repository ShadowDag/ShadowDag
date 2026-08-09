# Confidential Output Index + Decoy Selection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a sequential, enumerable index of confidential outputs (Monero-style global output index) and a `select_decoys` function, so wallets can build privacy rings from real on-chain outputs.

**Architecture:** A counter + `N → pubkey` entries on `UtxoSet`, written in the same atomic batch as `okey:`/`ki:` during `apply_block_dag_ordered`. A new `decoy.rs` samples random distinct members (pubkey + authentic commitment). Acceptance: a tx whose ring comes from `select_decoys` passes `verify_confidential_tx`.

**Tech Stack:** Rust, RocksDB raw store, curve25519-dalek (Ristretto), sub-projects 1-4b.

**Spec:** `docs/superpowers/specs/2026-06-29-ringct-decoy-index-design.md`

**Confirmed seams:** `UtxoSet::{ki_key, okey_key}` (private `Vec<u8>` key builders), `store.get_raw(&[u8]) -> Option<Vec<u8>>`, `store.put_raw`, `BatchWrite::Put { key, value }`; `output_key_commitment(pk) -> Option<String>`; the confidential branch in `apply_block_dag_ordered` (utxo_set.rs, pushes `okey:` ops); `dual_clsag::RingMember { public_key, commitment }`; `serialization::point_from_hex`; `confidential_consensus::verify_confidential_tx`; `builder::{build_confidential_transaction, OwnedInput, ConfRecipient}`.

---

### Task 1: Indexed confidential-output store on UtxoSet

**Files:**
- Modify: `domain/utxo/utxo_set.rs`

- [ ] **Step 1: Write the failing test**

Add to the `ringct_phase1_store_tests` module in `utxo_set.rs`:
```rust
    #[test]
    fn confidential_output_index_counts_and_indexes() {
        let set = UtxoSet::new_empty();
        assert_eq!(set.confidential_output_count(), 0);
        assert!(set.confidential_output_at(0).is_none());

        set.record_confidential_output_indexed(&"aa".repeat(32), &"11".repeat(32)).unwrap();
        set.record_confidential_output_indexed(&"bb".repeat(32), &"22".repeat(32)).unwrap();

        assert_eq!(set.confidential_output_count(), 2);
        assert_eq!(set.confidential_output_at(0), Some("aa".repeat(32)));
        assert_eq!(set.confidential_output_at(1), Some("bb".repeat(32)));
        assert!(set.confidential_output_at(2).is_none());
        // okey P->C also recorded by the indexed writer.
        assert_eq!(set.output_key_commitment(&"aa".repeat(32)), Some("11".repeat(32)));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib utxo_set::ringct_phase1_store_tests::confidential_output_index 2>&1 | head`
Expected: FAIL — methods undefined.

- [ ] **Step 3: Implement the index key builders + accessors + indexed writer**

Add to `impl UtxoSet` (near `okey_key`/`record_output_key`):
```rust
    fn okeyidx_count_key() -> Vec<u8> {
        b"okeyidx:count".to_vec()
    }
    fn okeyidx_at_key(n: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + 20);
        v.extend_from_slice(b"okeyidx:");
        v.extend_from_slice(n.to_string().as_bytes());
        v
    }

    /// Number of confidential outputs recorded in the global index.
    pub fn confidential_output_count(&self) -> u64 {
        match self.store.get_raw(&Self::okeyidx_count_key()) {
            Some(v) if v.len() == 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&v);
                u64::from_le_bytes(a)
            }
            _ => 0,
        }
    }

    /// One-time pubkey (hex) at global index `n`, if present.
    pub fn confidential_output_at(&self, n: u64) -> Option<String> {
        self.store
            .get_raw(&Self::okeyidx_at_key(n))
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// Record a confidential output into BOTH the okey P->C map and the global
    /// sequential index (count + index→pubkey). Non-atomic convenience used by
    /// tests; the live apply path inlines the same writes into its WriteBatch.
    pub fn record_confidential_output_indexed(
        &self,
        pk_hex: &str,
        commitment_hex: &str,
    ) -> Result<(), StorageError> {
        self.record_output_key(pk_hex, commitment_hex)?;
        let n = self.confidential_output_count();
        self.store.put_raw(&Self::okeyidx_at_key(n), pk_hex.as_bytes())?;
        self.store
            .put_raw(&Self::okeyidx_count_key(), &(n + 1).to_le_bytes())
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --lib utxo_set::ringct_phase1_store_tests::confidential_output_index`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add domain/utxo/utxo_set.rs
git commit -m "feat(privacy): sequential confidential-output index on UtxoSet"
```

---

### Task 2: Record the index in the live apply path (atomic)

**Files:**
- Modify: `domain/utxo/utxo_set.rs` (`apply_block_dag_ordered` confidential branch)

- [ ] **Step 1: Locate the confidential apply branch**

In `apply_block_dag_ordered`, the confidential branch currently pushes
`okey:{pubkey} → commitment` ops for each output. The index must be written in
the SAME batch, with the counter read once before the tx loop.

- [ ] **Step 2: Initialise a local index counter before the tx loop**

Just before `for tx in transactions {` in `apply_block_dag_ordered`, add:
```rust
        // RingCT global confidential-output index counter (advanced per
        // confidential output, flushed once at the end into the same batch).
        let mut conf_out_index = self.confidential_output_count();
        let conf_out_index_start = conf_out_index;
```

- [ ] **Step 3: Append index entries in the confidential output loop**

In the confidential branch, change the output recording loop so each recorded
output also gets an index entry:
```rust
                for output in &tx.outputs {
                    if let (Some(otk), Some(c)) = (&output.one_time_pubkey, &output.commitment) {
                        ops.push(BatchWrite::Put {
                            key: Self::okey_key(otk),
                            value: c.as_bytes().to_vec(),
                        });
                        ops.push(BatchWrite::Put {
                            key: Self::okeyidx_at_key(conf_out_index),
                            value: otk.as_bytes().to_vec(),
                        });
                        conf_out_index += 1;
                    }
                }
```

- [ ] **Step 4: Flush the counter once, after the tx loop, only if it advanced**

After the `for tx in transactions` loop ends (before the atomic
`store.write_batch(ops)`), add:
```rust
        if conf_out_index != conf_out_index_start {
            ops.push(BatchWrite::Put {
                key: Self::okeyidx_count_key(),
                value: conf_out_index.to_le_bytes().to_vec(),
            });
        }
```
> Place this where `ops` is still in scope and before it is consumed by
> `write_batch`. If the function has multiple `write_batch` call sites, target the
> one that commits this `ops` vector.

- [ ] **Step 5: Write the integration test**

Add to `engine/privacy/ringct/confidential_consensus.rs` tests (it already has
`valid_conf_tx` + apply round-trip helpers):
```rust
    #[test]
    fn apply_advances_confidential_output_index() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100); // has 1 confidential output
        let before = set.confidential_output_count();
        set.apply_block_dag_ordered(std::slice::from_ref(&tx), 1, "blk").unwrap();
        assert_eq!(set.confidential_output_count(), before + 1);
        let last = set.confidential_output_count() - 1;
        assert_eq!(
            set.confidential_output_at(last),
            tx.outputs[0].one_time_pubkey.clone()
        );
    }
```

- [ ] **Step 6: Run**

Run: `cargo test --lib ringct::confidential_consensus::tests::apply_advances 2>&1 | grep -E "test result|FAILED"`
Expected: PASS. Then `cargo test --lib utxo_set 2>&1 | grep "test result"` — existing UtxoSet tests still pass.

- [ ] **Step 7: Commit**

```bash
git add domain/utxo/utxo_set.rs engine/privacy/ringct/confidential_consensus.rs
git commit -m "feat(privacy): record confidential-output index atomically in apply_block_dag_ordered"
```

---

### Task 3: `select_decoys`

**Files:**
- Create: `engine/privacy/ringct/decoy.rs`
- Modify: `lib.rs` (declare `pub mod decoy;` under ringct)

- [ ] **Step 1: Declare the module** — add `pub mod decoy;` in the ringct block of `lib.rs`.

- [ ] **Step 2: Write the module with impl + tests**

Create `engine/privacy/ringct/decoy.rs`:
```rust
// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Decoy (ring member) selection for confidential transactions. Samples real
//! on-chain confidential outputs uniformly from the global output index. The
//! distribution is uniform; a recency-weighted policy (Monero gamma) is a later
//! refinement and is not a consensus concern (consensus only checks members are
//! real).

use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::privacy::ringct::dual_clsag::RingMember;
use crate::engine::privacy::ringct::serialization::point_from_hex;
use std::collections::HashSet;

/// Select `count` distinct real confidential outputs as ring members, skipping
/// any one-time pubkey hex in `exclude`. Returns None if fewer than `count`
/// eligible outputs exist or the index is malformed.
pub fn select_decoys(
    utxo_set: &UtxoSet,
    count: usize,
    exclude: &[String],
) -> Option<Vec<RingMember>> {
    use rand::rngs::OsRng;
    use rand::Rng;

    if count == 0 {
        return Some(Vec::new());
    }
    let total = utxo_set.confidential_output_count();
    if total == 0 {
        return None;
    }
    let excluded: HashSet<&str> = exclude.iter().map(|s| s.as_str()).collect();

    let mut chosen_keys: HashSet<String> = HashSet::new();
    let mut members: Vec<RingMember> = Vec::with_capacity(count);
    // Bounded attempts: enough to almost surely fill when eligible >= count,
    // and to terminate (returning None) when it can't.
    let max_attempts = total.saturating_mul(8).max(64);
    let mut attempts = 0u64;
    let mut rng = OsRng;

    while members.len() < count && attempts < max_attempts {
        attempts += 1;
        let idx = rng.gen_range(0..total);
        let pk = match utxo_set.confidential_output_at(idx) {
            Some(p) => p,
            None => continue,
        };
        if excluded.contains(pk.as_str()) || chosen_keys.contains(&pk) {
            continue;
        }
        let c_hex = match utxo_set.output_key_commitment(&pk) {
            Some(c) => c,
            None => continue,
        };
        let public_key = match point_from_hex(&pk) {
            Some(p) => p,
            None => continue,
        };
        let commitment = match point_from_hex(&c_hex) {
            Some(c) => c,
            None => continue,
        };
        chosen_keys.insert(pk);
        members.push(RingMember { public_key, commitment });
    }

    if members.len() == count {
        Some(members)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn hx(p: &curve25519_dalek::ristretto::RistrettoPoint) -> String {
        hex::encode(p.compress().as_bytes())
    }

    /// Record `n` random confidential outputs; return their pubkey hexes.
    fn seed_outputs(set: &UtxoSet, n: usize) -> Vec<String> {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = crate::engine::privacy::confidential::pedersen::generator_h();
        let mut keys = Vec::new();
        for _ in 0..n {
            let pk = Scalar::random(&mut OsRng) * g;
            let c = Scalar::from(5u64) * h + Scalar::random(&mut OsRng) * g;
            set.record_confidential_output_indexed(&hx(&pk), &hx(&c)).unwrap();
            keys.push(hx(&pk));
        }
        keys
    }

    #[test]
    fn selects_distinct_real_members_excluding() {
        let set = UtxoSet::new_empty();
        let keys = seed_outputs(&set, 10);
        let exclude = vec![keys[0].clone(), keys[1].clone()];
        let ring = select_decoys(&set, 4, &exclude).expect("enough outputs");
        assert_eq!(ring.len(), 4);
        // Distinct + not excluded + commitment matches the recorded one.
        let mut seen = std::collections::HashSet::new();
        for m in &ring {
            let pk = hx(&m.public_key);
            assert!(seen.insert(pk.clone()), "distinct members");
            assert!(!exclude.contains(&pk), "excluded key must not appear");
            assert_eq!(set.output_key_commitment(&pk), Some(hx(&m.commitment)));
        }
    }

    #[test]
    fn returns_none_when_insufficient() {
        let set = UtxoSet::new_empty();
        let keys = seed_outputs(&set, 3);
        // Exclude all but 1 → cannot pick 3.
        let exclude = vec![keys[0].clone(), keys[1].clone()];
        assert!(select_decoys(&set, 3, &exclude).is_none());
        // Empty index.
        let empty = UtxoSet::new_empty();
        assert!(select_decoys(&empty, 1, &[]).is_none());
        // count 0 is trivially Some(empty).
        assert_eq!(select_decoys(&set, 0, &[]).map(|v| v.len()), Some(0));
    }
}
```

- [ ] **Step 3: Run** — `cargo test --lib ringct::decoy 2>&1 | grep -E "test result|FAILED"` → PASS.
- [ ] **Step 4: Commit** — `git add engine/privacy/ringct/decoy.rs lib.rs && git commit -m "feat(privacy): select_decoys — uniform real-output ring selection"`

---

### Task 4: Integration — build with selected decoys passes consensus

**Files:**
- Modify: `engine/privacy/ringct/decoy.rs` (tests)

- [ ] **Step 1: Write the integration test**

Append to `decoy.rs` tests:
```rust
    #[test]
    fn ring_from_select_decoys_builds_consensus_valid_tx() {
        use crate::config::node::node_config::NetworkMode;
        use crate::engine::privacy::ringct::builder::{build_confidential_transaction, ConfRecipient, OwnedInput};
        use crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx;
        use crate::engine::privacy::ringct::dual_clsag::RingMember;
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = crate::engine::privacy::confidential::pedersen::generator_h();
        let set = UtxoSet::new_empty();
        // Seed a pool of decoy-eligible outputs.
        seed_outputs(&set, 20);

        // The spender's real output (amount 100), also recorded + indexed.
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let real_pk = spend * g;
        let real_c = Scalar::from(100u64) * h + bl * g;
        set.record_confidential_output_indexed(&hx(&real_pk), &hx(&real_c)).unwrap();

        // Build a ring: 4 decoys from the index (excluding the real key) + real.
        let mut ring: Vec<RingMember> =
            select_decoys(&set, 4, &[hx(&real_pk)]).expect("decoys");
        ring.push(RingMember { public_key: real_pk, commitment: real_c });
        let real_index = ring.len() - 1;

        let owned = OwnedInput {
            spend_secret: spend,
            amount: 100,
            blinding: bl,
            ring,
            real_index,
        };
        let net = NetworkMode::Mainnet;
        let (v, vp) = { let s = Scalar::random(&mut OsRng); (s, s * g) };
        let (s2, sp) = { let s = Scalar::random(&mut OsRng); (s, s * g) };
        let _ = (v, s2);
        let tx = build_confidential_transaction(
            vec![owned],
            vec![ConfRecipient { view_pub: vp, spend_pub: sp, amount: 100 }],
            0, &net,
        ).unwrap();

        let mut seen = std::collections::HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok(),
            "a ring built from select_decoys must be consensus-valid");
    }
```

- [ ] **Step 2: Run** — `cargo test --lib ringct::decoy::tests::ring_from_select_decoys 2>&1 | grep -E "test result|FAILED"` → PASS.
- [ ] **Step 3: Commit** — `git add engine/privacy/ringct/decoy.rs && git commit -m "test(privacy): select_decoys ring builds a consensus-valid confidential tx"`

---

### Task 5: Final gate
- [ ] `cargo build --all-targets` → Finished.
- [ ] `cargo clippy --all-targets -- -D warnings` → clean (fix inline; `rng.gen_range` import is `rand::Rng`).
- [ ] `cargo test --lib` → all pass (additive; index only written for confidential outputs).
- [ ] Commit fixups: `git add -A && git commit -m "chore(privacy): decoy index + selection green (build+clippy+suite)"`

---

## Self-review notes (coverage vs spec)
- Sequential index (`okeyidx:count` + `okeyidx:{N}`) + accessors → Task 1. ✓
- Atomic recording in `apply_block_dag_ordered` → Task 2. ✓
- `select_decoys(count, exclude)` uniform, distinct, real members, None on
  insufficient → Task 3. ✓
- Integration oracle (ring from select_decoys → verify_confidential_tx) → Task 4. ✓
- Counter only bumped for confidential outputs; transparent/coinbase unaffected →
  Task 2 (branch is confidential-only). ✓
- Non-goals (CLI/RPC/wallet, gamma distribution, pruning) → absent. ✓
- Type/seam names: `confidential_output_count`, `confidential_output_at`,
  `record_confidential_output_indexed`, `okeyidx_*`, `select_decoys`,
  `output_key_commitment`, `RingMember`, `point_from_hex` — consistent. ✓

## Sharp edges
- Task 2: read the counter ONCE before the tx loop and flush ONCE after, using a
  local that advances per confidential output — do not read/write the counter
  per-output (would read stale uncommitted values from the batch).
- `rng.gen_range(0..total)` needs `use rand::Rng;` in scope (added in the fn).
- The test seed helper uses `record_confidential_output_indexed` (the Task-1
  convenience), not the apply path, to keep decoy tests fast and focused.
