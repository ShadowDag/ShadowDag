# Confidential TX Consensus Verification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. **HIGHEST-RISK consensus crypto in the project — never skip a verification step; the adversarial tests ARE the proof.** Steps use checkbox (`- [ ]`).

**Goal:** Soundly verify confidential (RingCT) transactions in the block path — dual-key CLSAG + on-chain ring-member authenticity + key-image uniqueness + per-output range proofs + homomorphic balance `Σ C'_in == Σ C_out + fee·H` — and record key images / output keys in the live apply path.

**Architecture:** A pure `verify_confidential_tx` gate (no chain mutation) wired into `validate_block_utxos` (the single block gate) and `TxValidator` (mempool), with `apply_block_dag_ordered` recording `ki:`/`okey:` atomically. Two separate worlds: confidential txs spend confidential outputs only; double-spend via key images. No transparent checks on confidential inputs.

**Tech Stack:** Rust, curve25519-dalek (Ristretto), sub-projects 1+2 (`dual_clsag`, `tx_confidential` parse views, RangeProof serde), `pedersen::verify_balance`, `range_proof::verify`.

**Spec:** `docs/superpowers/specs/2026-06-29-ringct-consensus-design.md`

**Confirmed seams:** `apply_block_dag_ordered(&self, &[Transaction], u64, &str) -> Result<(usize,usize,u64), StorageError>` builds `ops: Vec<BatchWrite>` (utxo_set.rs:650); `validate_block_utxos(block, utxo_set, block_height)` (utxo_validator.rs:111, callers at utxo_set.rs:360/394, full_node.rs:2494); `tx.is_confidential()` (transaction.rs:170); `pedersen::verify_balance(&[RistrettoPoint], &[RistrettoPoint], u64) -> bool`; `range_proof::verify(&RistrettoPoint, &RangeProof) -> bool`; `dual_clsag::verify(&[u8], &[RingMember], &RistrettoPoint, &DualCLSAGSignature) -> bool`; `tx_confidential::{parse_confidential_input, parse_confidential_output}`; `UtxoSet::{key_image_seen, record_key_image, output_key_exists, record_output_key}` (currently set-valued; Task 2 makes okey a P→C map).

---

### Task 1: Bind new fields in the confidential signing message

**Files:**
- Modify: `domain/transaction/tx_hash.rs`

- [ ] **Step 1: Write the failing binding tests**

Add to the `tx_hash` test module (the `make_confidential_tx` helper there already
builds a confidential tx; extend it or build inline):
```rust
    #[test]
    fn conf_message_binds_one_time_pubkey_and_ring_commitments() {
        let net = NetworkMode::Mainnet;
        let mut tx = make_confidential_tx();
        let base = TxHash::confidential_signing_message_for_network(&tx, &net);

        tx.outputs[0].one_time_pubkey = Some("ab".repeat(32));
        let after_otk = TxHash::confidential_signing_message_for_network(&tx, &net);
        assert_ne!(base, after_otk);

        tx.inputs[0].ring_commitments = Some(vec!["cd".repeat(32)]);
        let after_rc = TxHash::confidential_signing_message_for_network(&tx, &net);
        assert_ne!(after_otk, after_rc);

        tx.inputs[0].pseudo_commitment = Some("ef".repeat(32));
        assert_ne!(after_rc, TxHash::confidential_signing_message_for_network(&tx, &net));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib tx_hash::tests::conf_message_binds 2>&1 | head`
Expected: FAIL (current message ignores the new fields → equal hashes).

- [ ] **Step 3: Extend the message + bump the domain tag**

In `confidential_signing_message_for_network`: change the domain tag from
`b"SHADOW_TX_CONF_SIGN_V1"` to `b"SHADOW_TX_CONF_SIGN_V2"`. In the per-output
loop, after binding `commitment`/`ephemeral_pubkey`, also bind `one_time_pubkey`:
```rust
            match &o.one_time_pubkey {
                Some(s) => { h.update([1u8]); h.update((s.len() as u32).to_le_bytes()); h.update(s.as_bytes()); }
                None => h.update([0u8]),
            }
```
In the per-input loop, after binding `ring_members`, also bind
`ring_commitments` and `pseudo_commitment`:
```rust
            match &inp.ring_commitments {
                Some(cs) => {
                    h.update([1u8]);
                    h.update((cs.len() as u32).to_le_bytes());
                    for c in cs { h.update((c.len() as u32).to_le_bytes()); h.update(c.as_bytes()); }
                }
                None => h.update([0u8]),
            }
            match &inp.pseudo_commitment {
                Some(pc) => { h.update([1u8]); h.update((pc.len() as u32).to_le_bytes()); h.update(pc.as_bytes()); }
                None => h.update([0u8]),
            }
```

- [ ] **Step 4: Run to verify pass + existing conf-message tests**

Run: `cargo test --lib tx_hash::tests`
Expected: new test + existing confidential-message tests PASS.

- [ ] **Step 5: Commit**

```bash
git add domain/transaction/tx_hash.rs
git commit -m "feat(privacy): bind one_time_pubkey + ring_commitments + pseudo in CONF_SIGN_V2"
```

---

### Task 2: Make the `okey:` store bind P → C

**Files:**
- Modify: `domain/utxo/utxo_set.rs`

- [ ] **Step 1: Write the failing test**

Add (near the existing `ringct_phase1_store_tests`):
```rust
    #[test]
    fn okey_binds_pubkey_to_commitment() {
        let set = UtxoSet::new_empty();
        let pk = "ab".repeat(32);
        let c = "cd".repeat(32);
        assert!(set.output_key_commitment(&pk).is_none());
        set.record_output_key(&pk, &c).unwrap();
        assert_eq!(set.output_key_commitment(&pk), Some(c.clone()));
        assert!(set.output_key_exists(&pk));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib utxo_set::ringct_phase1_store_tests::okey_binds 2>&1 | head`
Expected: FAIL — `output_key_commitment` undefined / `record_output_key` arity.

- [ ] **Step 3: Change the okey API to a P→C map**

Replace the existing `record_output_key` / `output_key_exists` with:
```rust
    /// Record a confidential output's one-time pubkey → its commitment.
    pub fn record_output_key(&self, pk_hex: &str, commitment_hex: &str) -> Result<(), StorageError> {
        self.store.put_raw(&Self::okey_key(pk_hex), commitment_hex.as_bytes())
    }
    /// The recorded commitment for a one-time output pubkey, if it exists on-chain.
    pub fn output_key_commitment(&self, pk_hex: &str) -> Option<String> {
        self.store
            .get_raw(&Self::okey_key(pk_hex))
            .and_then(|v| String::from_utf8(v).ok())
    }
    /// True if this one-time output pubkey exists on-chain.
    pub fn output_key_exists(&self, pk_hex: &str) -> bool {
        self.store.get_raw(&Self::okey_key(pk_hex)).is_some()
    }
```
Update the existing `output_key_membership` test (sub-project audit) to call
`record_output_key(&pk, &"00".repeat(32))`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --lib utxo_set::ringct_phase1_store_tests`
Expected: PASS (both okey tests).

- [ ] **Step 5: Commit**

```bash
git add domain/utxo/utxo_set.rs
git commit -m "feat(privacy): okey store binds one-time pubkey -> commitment"
```

---

### Task 3: `verify_confidential_tx` gate (pure, no chain mutation)

**Files:**
- Create: `engine/privacy/ringct/confidential_consensus.rs`
- Modify: `lib.rs` (declare `pub mod confidential_consensus;` under ringct)

- [ ] **Step 1: Declare the module**

In `lib.rs` `pub mod ringct { ... }`, add `pub mod confidential_consensus;`.

- [ ] **Step 2: Write the module with impl + the full test battery**

Create `engine/privacy/ringct/confidential_consensus.rs`:
```rust
// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Confidential (RingCT) transaction verification for consensus.
//!
//! Pure: reads the UTXO set's `okey:`/`ki:` stores but performs NO mutation.
//! Two worlds: a confidential tx spends confidential outputs only; double-spend
//! is prevented solely by key-image uniqueness. SECURITY: external review
//! required before mainnet.

use crate::config::node::node_config::NetworkMode;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::transaction::tx_hash::TxHash;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::privacy::confidential::pedersen;
use crate::engine::privacy::confidential::range_proof;
use crate::engine::privacy::ringct::dual_clsag;
use crate::engine::privacy::ringct::tx_confidential::{
    parse_confidential_input, parse_confidential_output,
};
use crate::errors::StorageError;
use std::collections::HashSet;

fn err(msg: String) -> StorageError {
    StorageError::Other(msg)
}

/// Verify all confidential aspects of one tx. `seen_ki` accumulates key images
/// across the block for intra-block double-spend detection. No chain mutation.
pub fn verify_confidential_tx(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    network: &NetworkMode,
    seen_ki: &mut HashSet<String>,
) -> Result<(), StorageError> {
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err(err(format!("confidential tx {} empty inputs/outputs", tx.hash)));
    }

    let msg = TxHash::confidential_signing_message_for_network(tx, network);

    // ── Inputs: ring authenticity + CLSAG + key-image uniqueness ──
    let mut pseudo_outs = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let view = parse_confidential_input(input)
            .ok_or_else(|| err(format!("confidential tx {}: malformed input", tx.hash)))?;

        // Every ring member must be a real on-chain output with the authentic
        // commitment (binds P AND C).
        for (member, p_hex) in view.ring.iter().zip(
            input.ring_members.as_ref().expect("parsed").iter(),
        ) {
            let c_hex = hex::encode(member.commitment.compress().as_bytes());
            match utxo_set.output_key_commitment(p_hex) {
                Some(recorded) if recorded == c_hex => {}
                _ => {
                    return Err(err(format!(
                        "confidential tx {}: ring member not a real output (or commitment mismatch)",
                        tx.hash
                    )))
                }
            }
        }

        // Key image: matches signature, unseen on-chain, unique within block.
        let ki_hex = hex::encode(view.key_image.compress().as_bytes());
        if ki_hex != hex::encode(view.signature.key_image.as_bytes()) {
            return Err(err(format!("confidential tx {}: key image mismatch", tx.hash)));
        }
        if utxo_set.key_image_seen(&ki_hex) {
            return Err(err(format!("confidential tx {}: key image already spent", tx.hash)));
        }
        if !seen_ki.insert(ki_hex) {
            return Err(err(format!("confidential tx {}: duplicate key image in block", tx.hash)));
        }

        // Dual-key CLSAG over the canonical message.
        if !dual_clsag::verify(&msg, &view.ring, &view.pseudo_out, &view.signature) {
            return Err(err(format!("confidential tx {}: CLSAG verify failed", tx.hash)));
        }

        pseudo_outs.push(view.pseudo_out);
    }

    // ── Outputs: range proofs ──
    let mut output_commitments = Vec::with_capacity(tx.outputs.len());
    for output in &tx.outputs {
        let view = parse_confidential_output(output)
            .ok_or_else(|| err(format!("confidential tx {}: malformed output", tx.hash)))?;
        if !range_proof::verify(&view.commitment, &view.range_proof) {
            return Err(err(format!("confidential tx {}: range proof failed", tx.hash)));
        }
        output_commitments.push(view.commitment);
    }

    // ── Homomorphic balance: Σ C'_in == Σ C_out + fee·H ──
    if !pedersen::verify_balance(&pseudo_outs, &output_commitments, tx.fee) {
        return Err(err(format!("confidential tx {}: commitments do not balance", tx.hash)));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{TxInput, TxOutput, TxType};
    use crate::engine::privacy::confidential::pedersen::generator_h;
    use crate::engine::privacy::confidential::range_proof::prove;
    use crate::engine::privacy::ringct::dual_clsag::RingMember;
    use crate::engine::privacy::ringct::serialization::range_proof_to_hex;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn hexp(p: &RistrettoPoint) -> String {
        hex::encode(p.compress().as_bytes())
    }

    /// Build a valid 1-input / 1-output confidential tx (amount `amt`), seeding
    /// the ring members into `okey:`. Ring size 4, signer at index 1.
    /// Returns the tx (its signature is over the final message).
    fn valid_conf_tx(set: &UtxoSet, amt: u64) -> Transaction {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let net = NetworkMode::Mainnet;

        // Ring of 4 real outputs, each recorded in okey with its commitment.
        let mut ring = Vec::new();
        for _ in 0..4 {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            let pk = sk * g;
            let c = Scalar::from(amt) * h + bl * g;
            set.record_output_key(&hexp(&pk), &hexp(&c)).unwrap();
            ring.push(RingMember { public_key: pk, commitment: c });
        }
        // Signer (index 1): known spend secret + known input commitment.
        let idx = 1usize;
        let spend = Scalar::random(&mut OsRng);
        let r_in = Scalar::random(&mut OsRng);
        let pk = spend * g;
        let c_in = Scalar::from(amt) * h + r_in * g;
        set.record_output_key(&hexp(&pk), &hexp(&c_in)).unwrap();
        ring[idx] = RingMember { public_key: pk, commitment: c_in };

        // Pseudo-output: same amount, blinding r_prime. z = r_in - r_prime.
        let r_prime = Scalar::random(&mut OsRng);
        let pseudo = Scalar::from(amt) * h + r_prime * g;
        let z = r_in - r_prime;

        // Single output: amount = amt - fee (fee public). Output blinding MUST
        // make balance hold: Σ C'_in = Σ C_out + fee·H  ⇒  r_prime = r_out.
        let fee = 0u64; // keep amt all in one output for a clean 1-in/1-out
        let out_amt = amt - fee;
        let r_out = r_prime; // forces balance for the single-input single-output case
        let out_commit = Scalar::from(out_amt) * h + r_out * g;
        let proof = prove(out_amt, &r_out);
        let one_time = Scalar::random(&mut OsRng) * g;
        let eph = Scalar::random(&mut OsRng) * g;

        let mut tx = Transaction {
            hash: "c".repeat(64),
            inputs: vec![TxInput {
                txid: "0".repeat(64),
                index: 0,
                owner: String::new(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,         // filled after signing
                ring_members: Some(ring.iter().map(|m| hexp(&m.public_key)).collect()),
                ring_signature: None,    // filled after signing
                ring_commitments: Some(ring.iter().map(|m| hexp(&m.commitment)).collect()),
                pseudo_commitment: Some(hexp(&pseudo)),
            }],
            outputs: vec![TxOutput {
                address: "SD1s".into(),
                amount: 0,
                commitment: Some(hexp(&out_commit)),
                range_proof: Some(range_proof_to_hex(&proof)),
                ephemeral_pubkey: Some(hexp(&eph)),
                one_time_pubkey: Some(hexp(&one_time)),
            }],
            fee,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Confidential,
            payload_hash: None,
            ..Default::default()
        };
        // Key image is deterministic; set it BEFORE computing the message.
        let ki = dual_clsag::key_image(&spend, &pk);
        tx.inputs[0].key_image = Some(hexp(&ki));
        let msg = TxHash::confidential_signing_message_for_network(&tx, &net);
        let sig = dual_clsag::sign(&msg, &ring, &pseudo, idx, &spend, &z).unwrap();
        tx.inputs[0].ring_signature = Some(dual_clsag::to_hex(&sig));
        tx
    }

    fn net() -> NetworkMode { NetworkMode::Mainnet }

    #[test]
    fn accepts_valid_confidential_tx() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_ok());
    }

    #[test]
    fn rejects_unbalanced() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        // Replace the output commitment with one for a different amount → balance breaks.
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let bad = Scalar::from(999u64) * h + Scalar::random(&mut OsRng) * g;
        tx.outputs[0].commitment = Some(hexp(&bad));
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_ring_member_not_recorded() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        // Swap one ring member to a fresh key never recorded in okey.
        let stray = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        tx.inputs[0].ring_members.as_mut().unwrap()[0] = hexp(&stray);
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_commitment_mismatch_for_real_pubkey() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        // Keep ring member 0's pubkey, but supply a different commitment.
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let fake_c = Scalar::from(100u64) * h + Scalar::random(&mut OsRng) * g;
        tx.inputs[0].ring_commitments.as_mut().unwrap()[0] = hexp(&fake_c);
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_already_spent_key_image() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);
        let ki = tx.inputs[0].key_image.clone().unwrap();
        set.record_key_image(&ki).unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_duplicate_key_image_in_block() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);
        let mut seen = HashSet::new();
        seen.insert(tx.inputs[0].key_image.clone().unwrap());
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_tampered_signature() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        tx.inputs[0].ring_signature = Some("00".repeat(200));
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_bad_range_proof() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        // Range proof for a different value than the committed one.
        let other = prove(50u64, &Scalar::random(&mut OsRng));
        tx.outputs[0].range_proof = Some(range_proof_to_hex(&other));
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }
}
```

- [ ] **Step 3: Run to verify**

Run: `cargo test --lib ringct::confidential_consensus 2>&1 | grep -E "test |result"`
Expected: `accepts_valid_confidential_tx` PASS and all 7 `rejects_*` PASS. If
`accepts_valid` fails, the balance/message wiring is off — diagnose (likely the
output blinding vs pseudo blinding relationship in the helper). If a `rejects_*`
passes-when-it-should-fail, STOP — a defense is missing.

- [ ] **Step 4: Commit**

```bash
git add engine/privacy/ringct/confidential_consensus.rs lib.rs
git commit -m "feat(privacy): verify_confidential_tx gate (CLSAG+balance+range+ki+okey)"
```

---

### Task 4: Wire into block validation + apply path

**Files:**
- Modify: `domain/utxo/utxo_validator.rs` (branch in `validate_block_utxos`)
- Modify: `domain/utxo/utxo_set.rs` (record in `apply_block_dag_ordered`; add `infer_block_network`)

- [ ] **Step 1: Add `infer_block_network` helper**

In `utxo_validator.rs` (or a shared spot), add:
```rust
/// Best-effort network inference from a block's output address prefixes
/// (ST1*=Testnet, SR1*=Regtest, else Mainnet). Used only to pick the chain_id
/// for the confidential signing message. (Proper threading is audit follow-up H-net.)
fn infer_block_network(block: &Block) -> NetworkMode {
    for tx in &block.body.transactions {
        for o in &tx.outputs {
            if o.address.starts_with("ST1") { return NetworkMode::Testnet; }
            if o.address.starts_with("SR1") { return NetworkMode::Regtest; }
            if o.address.starts_with("SD1") { return NetworkMode::Mainnet; }
        }
    }
    NetworkMode::Mainnet
}
```
Ensure `NetworkMode` and `Block` are imported in `utxo_validator.rs`.

- [ ] **Step 2: Write a failing block-level test**

Add to a test module in `utxo_validator.rs` (or `tests/suite/`), building a block
whose single tx is a confidential tx from the Task-3 helper pattern (factor the
helper into a `#[cfg(test)] pub(crate)` fn if reused). Assert:
```rust
    // valid confidential block passes validate_block_utxos
    // (construct `block` with the confidential tx + a coinbase as required)
    assert!(UtxoValidator::validate_block_utxos(&block, &set, 1).is_ok());
```
> If building a full `Block` in a unit test is heavy, place this test in
> `tests/suite/` where block builders exist, or test the branch via a thin
> wrapper that calls `verify_confidential_tx` with the block's inferred network.

- [ ] **Step 3: Add the confidential branch to `validate_block_utxos`**

Near the top of `validate_block_utxos`, compute the network and a block-level
key-image set:
```rust
        let network = infer_block_network(block);
        let mut seen_key_images: std::collections::HashSet<String> = std::collections::HashSet::new();
```
Inside the per-tx loop, after the coinbase branch and before the transparent
input handling:
```rust
            if tx.is_confidential() {
                crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx(
                    tx, utxo_set, &network, &mut seen_key_images,
                )?;
                // Confidential outputs live in the confidential world; do not
                // stage them into the transparent staged_outputs map.
                continue;
            }
```

- [ ] **Step 4: Record ki/okey in `apply_block_dag_ordered`**

In `apply_block_dag_ordered`, in the per-tx processing where `ops` is built, add
for confidential txs (push into the same `ops` batch):
```rust
            if tx.is_confidential() {
                for input in &tx.inputs {
                    if let Some(ki) = &input.key_image {
                        ops.push(BatchWrite::Put { key: Self::ki_key(ki), value: vec![1u8] });
                    }
                }
                for output in &tx.outputs {
                    if let (Some(otk), Some(c)) = (&output.one_time_pubkey, &output.commitment) {
                        ops.push(BatchWrite::Put {
                            key: Self::okey_key(otk),
                            value: c.as_bytes().to_vec(),
                        });
                    }
                }
            }
```
> Place this so it runs for confidential txs without also running the transparent
> input-spend / output-create logic on them (mirror the structure used by the
> existing branches; confidential txs do not spend transparent UTXOs).

- [ ] **Step 5: Run tests**

Run: `cargo test --lib utxo_validator utxo_set::ringct 2>&1 | grep -E "test result|FAILED"`
Expected: PASS. Then `cargo build --all-targets` clean.

- [ ] **Step 6: Commit**

```bash
git add domain/utxo/utxo_validator.rs domain/utxo/utxo_set.rs
git commit -m "feat(privacy): wire confidential gate into block validate + apply (R1/R2/R6)"
```

---

### Task 5: One code path for mempool + block

**Files:**
- Modify: `domain/transaction/tx_validator.rs`

- [ ] **Step 1: Re-point `validate_confidential` to the new gate**

Replace the body of `TxValidator::validate_confidential` so the mempool path uses
the same verification as the block path (no divergence):
```rust
    pub fn validate_confidential(
        tx: &Transaction,
        utxo_set: &UtxoSet,
        network: &NetworkMode,
    ) -> bool {
        let mut seen = std::collections::HashSet::new();
        crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx(
            tx, utxo_set, network, &mut seen,
        )
        .is_ok()
    }
```

- [ ] **Step 2: Update the old single-key tests**

The audit-era `ringct_phase1` integration tests in `tx_validator.rs` were written
for the single-key gate (structural + single CLSAG + okey-as-set). They will no
longer construct valid txs for the dual-key gate. Replace that test module's
happy-path construction with a call to the dual-key helper (or delete those
tests and rely on Task 3's battery, which supersedes them). Keep at least one
mempool-path test: build a valid dual-key confidential tx (Task-3 helper) and
assert `TxValidator::validate_confidential(&tx, &set, &NetworkMode::Mainnet)` is
true, plus one tamper case returns false.

- [ ] **Step 3: Run**

Run: `cargo test --lib tx_validator 2>&1 | grep -E "test result|FAILED"`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add domain/transaction/tx_validator.rs
git commit -m "refactor(privacy): mempool + block share one confidential verification path"
```

---

### Task 6: Final gate

**Files:** none (verification)

- [ ] **Step 1: Build all targets** — `cargo build --all-targets` → `Finished`.
- [ ] **Step 2: Clippy** — `cargo clippy --all-targets -- -D warnings` → clean; fix inline.
- [ ] **Step 3: Full lib suite** — `cargo test --lib` → all pass (transparent path,
  genesis, coinbase unaffected; confidential battery green). If a transparent
  fixture changed, confirm it is only the message-tag/field bytes and update it.
- [ ] **Step 4: Commit** any fixups:
```bash
git add -A
git commit -m "chore(privacy): RingCT consensus verification gate green (build+clippy+suite)"
```

---

## Self-review notes (coverage vs spec)
- Extended confidential message binds new fields, tag→V2 → Task 1. ✓
- okey P→C map + `output_key_commitment` → Task 2. ✓
- `verify_confidential_tx`: parse, ring authenticity (P+C), CLSAG, key-image
  unseen+unique, range proofs, homomorphic balance, no transparent checks →
  Task 3. ✓
- Wire into `validate_block_utxos` (single gate) + record in
  `apply_block_dag_ordered` (live path, atomic) → Task 4. ✓
- Mempool + block one path → Task 5. ✓
- Adversarial battery (unbalanced, bad range, unrecorded member, commitment
  mismatch, spent/duplicate ki, tampered sig) → Task 3. ✓
- Statelessness (reads in L4/UTXO stage only) → Task 4 (branch is inside
  `validate_block_utxos`). ✓
- Non-goals (wallet build/scan, shield/unshield, fee privacy, deleting legacy
  single-key) → not present. ✓
- Type consistency: `verify_confidential_tx`, `output_key_commitment`,
  `record_output_key(pk, c)`, `parse_confidential_*`, `dual_clsag::verify`,
  `pedersen::verify_balance`, `range_proof::verify` — names match sub-projects
  1+2 and the confirmed seams. ✓

## Known sharp edge for the executor
The Task-3 helper sets `fee = 0` and `r_out = r_prime` for a clean 1-in/1-out
balance. A multi-output or non-zero-fee test must choose output blindings so that
`Σ r'_in == Σ r_out` (the H terms cancel only when `Σ in_amounts == Σ out_amounts
+ fee`). This blinding-balancing is exactly what the wallet (sub-project 4) will
do; tests here hand-balance it. Do NOT "fix" a failing balance test by weakening
`verify_balance`.
