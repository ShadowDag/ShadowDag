# Confidential TX Builder — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. The acceptance oracle is `verify_confidential_tx` (sub-project 3) — a built tx that passes it is consensus-valid. Steps use checkbox (`- [ ]`).

**Goal:** Add `build_confidential_transaction` that, given the spender's secrets + a decoy ring per input, produces a `Transaction` that passes the RingCT consensus gate (balanced pseudo-outputs, stealth outputs with commitments + range proofs, valid dual-key CLSAG per input).

**Architecture:** A pure builder in a new `engine/privacy/ringct/builder.rs`. It reuses stealth-address generation, Pedersen/H, range proofs, and dual-CLSAG signing. Blinding balance: the last output absorbs the difference so `Σ C'_in == Σ C_out + fee·H`. No amount-encoding (4b), no decoy selection / CLI (4c).

**Tech Stack:** Rust, curve25519-dalek (Ristretto), sub-projects 1-3.

**Spec:** `docs/superpowers/specs/2026-06-29-ringct-wallet-build-design.md`

**Confirmed seams:** `StealthAddress::generate_full_for_network(&RistrettoPoint, &RistrettoPoint, &str) -> Result<StealthAddressResult{one_time_address, ephemeral_pubkey, one_time_pubkey}, CryptoError>`; `NetworkMode::short_name() -> &'static str`; `dual_clsag::{RingMember, sign, key_image, to_hex}`; `range_proof::prove(u64,&Scalar)`; `serialization::range_proof_to_hex`; `pedersen::generator_h`; `RealPedersenCommitment::verify_balance`; `TxHash::{confidential_signing_message_for_network, hash_for_network}`; `confidential_consensus::verify_confidential_tx`.

---

### Task 1: Builder module + types + `build_confidential_transaction` + 1-in/1-out acceptance

**Files:**
- Create: `engine/privacy/ringct/builder.rs`
- Modify: `lib.rs` (declare `pub mod builder;` under ringct)

- [ ] **Step 1: Declare the module**

In `lib.rs` `pub mod ringct { ... }`, add `pub mod builder;`.

- [ ] **Step 2: Write the module with impl + the 1-in/1-out acceptance test**

Create `engine/privacy/ringct/builder.rs`:
```rust
// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Confidential (RingCT) transaction builder. Given the spender's secrets and a
//! decoy ring per input, produces a Transaction that passes the consensus gate
//! `verify_confidential_tx`. No amount-encoding for the receiver (sub-project 4b)
//! and no automatic decoy selection / wallet wiring (4c).

use crate::config::node::node_config::NetworkMode;
use crate::domain::address::stealth_address::StealthAddress;
use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
use crate::domain::transaction::tx_hash::TxHash;
use crate::engine::privacy::confidential::pedersen::generator_h;
use crate::engine::privacy::confidential::range_proof;
use crate::engine::privacy::ringct::dual_clsag::{self, RingMember};
use crate::engine::privacy::ringct::serialization::range_proof_to_hex;
use crate::errors::CryptoError;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::time::{SystemTime, UNIX_EPOCH};

/// What the spender knows about one real input being spent.
pub struct OwnedInput {
    pub spend_secret: Scalar, // x: one-time spend key of the real output
    pub amount: u64,
    pub blinding: Scalar, // r_real: blinding of the real input commitment
    pub ring: Vec<RingMember>, // decoys + real, as (P_i, C_i)
    pub real_index: usize,
}

/// A confidential recipient (stealth target + amount).
pub struct ConfRecipient {
    pub view_pub: RistrettoPoint,
    pub spend_pub: RistrettoPoint,
    pub amount: u64,
}

fn hexp(p: &RistrettoPoint) -> String {
    hex::encode(p.compress().as_bytes())
}

/// Build a confidential transaction. The returned tx is consensus-valid
/// (passes `verify_confidential_tx`) when the ring members are recorded on-chain.
pub fn build_confidential_transaction(
    inputs: Vec<OwnedInput>,
    recipients: Vec<ConfRecipient>,
    fee: u64,
    network: &NetworkMode,
) -> Result<Transaction, CryptoError> {
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

    if inputs.is_empty() || recipients.is_empty() {
        return Err(CryptoError::Other(
            "confidential tx needs >= 1 input and >= 1 recipient".into(),
        ));
    }
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = generator_h();

    // 1. Amount balance (u128 to avoid overflow).
    let in_sum: u128 = inputs.iter().map(|i| i.amount as u128).sum();
    let out_sum: u128 = recipients.iter().map(|r| r.amount as u128).sum();
    if in_sum != out_sum + fee as u128 {
        return Err(CryptoError::Other(
            "confidential build: inputs != outputs + fee".into(),
        ));
    }
    // Each input's real commitment must open to (amount, blinding).
    for inp in &inputs {
        if inp.real_index >= inp.ring.len() {
            return Err(CryptoError::InvalidRingIndex {
                index: inp.real_index,
                ring_size: inp.ring.len(),
            });
        }
        let expected = Scalar::from(inp.amount) * h + inp.blinding * g;
        if inp.ring[inp.real_index].commitment != expected {
            return Err(CryptoError::Other(
                "confidential build: input commitment does not open to (amount, blinding)".into(),
            ));
        }
    }

    // 2. Pseudo-output blindings (random per input) and output blindings
    //    (random except the last, which absorbs the difference so the
    //    commitments balance: Σ r'_in == Σ r_out).
    let mut pseudo_blindings: Vec<Scalar> =
        (0..inputs.len()).map(|_| Scalar::random(&mut OsRng)).collect();
    let sum_pseudo: Scalar = pseudo_blindings.iter().sum();

    let n_out = recipients.len();
    let mut out_blindings: Vec<Scalar> =
        (0..n_out).map(|_| Scalar::random(&mut OsRng)).collect();
    let sum_other: Scalar = out_blindings[..n_out - 1].iter().sum();
    out_blindings[n_out - 1] = sum_pseudo - sum_other;

    // 3. Outputs: stealth one-time address + commitment + range proof.
    let mut tx_outputs = Vec::with_capacity(n_out);
    for (i, r) in recipients.iter().enumerate() {
        let stealth = StealthAddress::generate_full_for_network(
            &r.view_pub,
            &r.spend_pub,
            network.short_name(),
        )?;
        let c_out = Scalar::from(r.amount) * h + out_blindings[i] * g;
        let proof = range_proof::prove(r.amount, &out_blindings[i]);
        tx_outputs.push(TxOutput {
            address: stealth.one_time_address,
            amount: 0,
            commitment: Some(hexp(&c_out)),
            range_proof: Some(range_proof_to_hex(&proof)),
            ephemeral_pubkey: Some(stealth.ephemeral_pubkey),
            one_time_pubkey: Some(stealth.one_time_pubkey),
        });
    }

    // 4. Inputs: pseudo-output + ring + key image (no signature yet).
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut pseudo_points = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        let pseudo = Scalar::from(inp.amount) * h + pseudo_blindings[i] * g;
        pseudo_points.push(pseudo);
        let ki = dual_clsag::key_image(&inp.spend_secret, &inp.ring[inp.real_index].public_key);
        tx_inputs.push(TxInput {
            txid: "0".repeat(64), // outpoint is meaningless for confidential inputs
            index: i as u32,      // keep (txid,index) distinct per input
            owner: String::new(),
            signature: String::new(),
            pub_key: String::new(),
            key_image: Some(hexp(&ki)),
            ring_members: Some(inp.ring.iter().map(|m| hexp(&m.public_key)).collect()),
            ring_signature: None,
            ring_commitments: Some(inp.ring.iter().map(|m| hexp(&m.commitment)).collect()),
            pseudo_commitment: Some(hexp(&pseudo)),
        });
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut tx = Transaction {
        hash: String::new(),
        inputs: tx_inputs,
        outputs: tx_outputs,
        fee,
        timestamp,
        is_coinbase: false,
        tx_type: TxType::Confidential,
        payload_hash: None,
        ..Default::default()
    };

    // 5. Sign each input (key images already set ⇒ message is stable).
    let msg = TxHash::confidential_signing_message_for_network(&tx, network);
    for (i, inp) in inputs.iter().enumerate() {
        let mut z = inp.blinding - pseudo_blindings[i];
        let sig = dual_clsag::sign(
            &msg,
            &inp.ring,
            &pseudo_points[i],
            inp.real_index,
            &inp.spend_secret,
            &z,
        )
        .map_err(|e| CryptoError::Other(format!("confidential build: clsag sign: {e:?}")))?;
        tx.inputs[i].ring_signature = Some(dual_clsag::to_hex(&sig));
        z.zeroize();
    }
    tx.hash = TxHash::hash_for_network(&tx, network);

    for b in pseudo_blindings.iter_mut() {
        b.zeroize();
    }
    for b in out_blindings.iter_mut() {
        b.zeroize();
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx;
    use rand::rngs::OsRng;
    use std::collections::HashSet;

    /// Build one OwnedInput holding `amount`: a ring of `ring_size` real
    /// on-chain outputs (all recorded into `set`'s okey), signer at `idx`.
    fn owned_input(set: &UtxoSet, amount: u64, ring_size: usize, idx: usize) -> OwnedInput {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let mut ring = Vec::new();
        for _ in 0..ring_size {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            let pk = sk * g;
            let c = Scalar::from(amount) * h + bl * g;
            set.record_output_key(&hexp(&pk), &hexp(&c)).unwrap();
            ring.push(RingMember { public_key: pk, commitment: c });
        }
        let spend = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);
        let pk = spend * g;
        let c = Scalar::from(amount) * h + blinding * g;
        set.record_output_key(&hexp(&pk), &hexp(&c)).unwrap();
        ring[idx] = RingMember { public_key: pk, commitment: c };
        OwnedInput { spend_secret: spend, amount, blinding, ring, real_index: idx }
    }

    fn recipient(amount: u64) -> ConfRecipient {
        let g = RISTRETTO_BASEPOINT_POINT;
        ConfRecipient {
            view_pub: Scalar::random(&mut OsRng) * g,
            spend_pub: Scalar::random(&mut OsRng) * g,
            amount,
        }
    }

    #[test]
    fn builds_consensus_valid_1in_1out() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 4, 1);
        let tx = build_confidential_transaction(vec![inp], vec![recipient(100)], 0, &net).unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok());
    }
}
```

- [ ] **Step 3: Run to verify the acceptance oracle**

Run: `cargo test --lib ringct::builder::tests::builds_consensus_valid_1in_1out 2>&1 | grep -E "test |result|error"`
Expected: PASS. If it FAILS at `verify_confidential_tx`, the blinding-balance or
message wiring is off — diagnose against `confidential_consensus` (do not weaken
the gate).

- [ ] **Step 4: Commit**

```bash
git add engine/privacy/ringct/builder.rs lib.rs
git commit -m "feat(privacy): confidential TX builder (1-in/1-out passes consensus gate)"
```

---

### Task 2: Multi-input / multi-output + balance + reject tests

**Files:**
- Modify: `engine/privacy/ringct/builder.rs` (tests only)

- [ ] **Step 1: Add the tests**

Append to the test module:
```rust
    #[test]
    fn builds_valid_2in_2out() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inputs = vec![owned_input(&set, 70, 4, 0), owned_input(&set, 30, 4, 3)];
        // 100 in total; 2 outputs 60 + 40, fee 0.
        let tx = build_confidential_transaction(
            inputs,
            vec![recipient(60), recipient(40)],
            0,
            &net,
        )
        .unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok());
    }

    #[test]
    fn builds_valid_1in_3out_with_fee() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 8, 5);
        // 100 = 50 + 30 + 18 + fee 2 (3 outputs exercise blinding balance).
        let tx = build_confidential_transaction(
            vec![inp],
            vec![recipient(50), recipient(30), recipient(18)],
            2,
            &net,
        )
        .unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok());
    }

    #[test]
    fn rejects_amount_imbalance() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 4, 1);
        // 100 in, 90 out + fee 0 → imbalance.
        assert!(build_confidential_transaction(vec![inp], vec![recipient(90)], 0, &net).is_err());
    }

    #[test]
    fn rejects_input_opening_mismatch() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let mut inp = owned_input(&set, 100, 4, 1);
        // Corrupt the declared blinding so it no longer opens the commitment.
        inp.blinding += Scalar::ONE;
        assert!(build_confidential_transaction(vec![inp], vec![recipient(100)], 0, &net).is_err());
    }

    #[test]
    fn tampered_output_breaks_consensus() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 4, 2);
        let mut tx =
            build_confidential_transaction(vec![inp], vec![recipient(100)], 0, &net).unwrap();
        // Flip the output commitment after building → balance/gate must fail.
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let bad = Scalar::from(123u64) * h + Scalar::random(&mut OsRng) * g;
        tx.outputs[0].commitment = Some(hexp(&bad));
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_err());
    }
```

- [ ] **Step 2: Run**

Run: `cargo test --lib ringct::builder::tests 2>&1 | grep -E "test result|FAILED"`
Expected: all PASS (6 tests). The multi-output tests prove the blinding-balance
last-output absorption is correct.

- [ ] **Step 3: Commit**

```bash
git add engine/privacy/ringct/builder.rs
git commit -m "test(privacy): confidential builder multi-in/out, balance, and reject cases"
```

---

### Task 3: Final gate

**Files:** none (verification)

- [ ] **Step 1: Build all targets** — `cargo build --all-targets` → `Finished`.
- [ ] **Step 2: Clippy** — `cargo clippy --all-targets -- -D warnings` → clean; fix inline.
- [ ] **Step 3: Full lib suite** — `cargo test --lib` → all pass (no regressions; transparent/genesis unaffected — builder is additive).
- [ ] **Step 4: Commit** any fixups:
```bash
git add -A
git commit -m "chore(privacy): confidential builder green (build+clippy+suite)"
```

---

## Self-review notes (coverage vs spec)
- `OwnedInput` / `ConfRecipient` / `build_confidential_transaction` → Task 1. ✓
- Amount-balance check + per-input opening check → Task 1 (asserted by reject
  tests in Task 2). ✓
- Stealth outputs (one-time address + ephemeral + one_time_pubkey) + commitment
  + range proof → Task 1. ✓
- Blinding balance (last output absorbs) → Task 1; proven by multi-output Task 2. ✓
- Pseudo-output + z + dual-CLSAG sign per input → Task 1. ✓
- Acceptance oracle = `verify_confidential_tx` → Tasks 1, 2. ✓
- Secrets zeroized (z, blindings) → Task 1. ✓
- Non-goals (amount encoding 4b, decoy selection / CLI 4c, fee privacy) → absent. ✓
- Type/seam names match sub-projects 1-3 + confirmed signatures. ✓

## Sharp edge
The single-output path also runs the "last output absorbs" code (`out_blindings[0]
= sum_pseudo`), so there is no special-case branch — the multi-output tests and
the 1-out test exercise the same code path. Do not add a 1-output shortcut.
