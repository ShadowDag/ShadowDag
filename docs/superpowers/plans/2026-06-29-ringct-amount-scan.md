# Confidential Amount Encoding + Scan/Recover — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. The strongest oracle is the full round-trip: build → scan → recover → spend → `verify_confidential_tx`. Steps use checkbox (`- [ ]`).

**Goal:** Let a recipient detect, decrypt, and spend confidential outputs — by deriving the output blinding + amount mask from the ECDH shared secret, publishing a masked `encrypted_amount`, and adding scan/recover; and by flipping the builder's blinding balance to the input side so output blindings can be derived.

**Architecture:** New `amount_encoding.rs` (derive blinding/mask, encrypt/decrypt). New `scan.rs` (scan + recover). `stealth_address` gains an ss-returning generator + a recipient ss helper. `TxOutput` gains `encrypted_amount`. `builder.rs` derives output blindings from ss and moves balance absorption to the last input pseudo-output.

**Tech Stack:** Rust, curve25519-dalek (Ristretto), sha2 (SHA-512/256), sub-projects 1-4a.

**Spec:** `docs/superpowers/specs/2026-06-29-ringct-amount-scan-design.md`

**Confirmed seams:** `stealth_address::derive_hash_scalar(&ss) -> Result<Scalar,CryptoError>` (pub); `StealthAddress::derive_one_time_private_key(&R, &view_priv, &spend_priv) -> Result<Scalar,CryptoError>`; `StealthAddress::generate_full_for_network(view,spend,net) -> Result<StealthAddressResult,_>` (computes `ss = r·V` internally, discards it); `serialization::point_from_hex`; `pedersen::generator_h`; 4a `builder.rs`; `confidential_consensus::verify_confidential_tx`.

---

### Task 1: `amount_encoding` module

**Files:**
- Create: `engine/privacy/ringct/amount_encoding.rs`
- Modify: `lib.rs` (declare `pub mod amount_encoding;` under ringct)

- [ ] **Step 1: Declare the module** — add `pub mod amount_encoding;` in the ringct block of `lib.rs`.

- [ ] **Step 2: Write the failing tests**

Create `engine/privacy/ringct/amount_encoding.rs`:
```rust
// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! RingCT amount encoding: derive the output blinding and an amount one-time-pad
//! from the ECDH shared secret, so the recipient (who recomputes the same shared
//! secret) recovers both. Domain-separated from the stealth address derivation.

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn ss() -> curve25519_dalek::ristretto::RistrettoPoint {
        Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let s = ss();
        for amt in [0u64, 1, 42, u64::MAX] {
            let mask = amount_mask(&s, 0);
            let enc = encrypt_amount(amt, &mask);
            assert_eq!(decrypt_amount(&enc, &mask), amt);
        }
    }

    #[test]
    fn mask_and_blinding_depend_on_ss_and_index() {
        let a = ss();
        let b = ss();
        assert_ne!(amount_mask(&a, 0), amount_mask(&b, 0));
        assert_ne!(amount_mask(&a, 0), amount_mask(&a, 1));
        assert_ne!(derive_blinding(&a, 0), derive_blinding(&b, 0));
        assert_ne!(derive_blinding(&a, 0), derive_blinding(&a, 1));
        // deterministic
        assert_eq!(derive_blinding(&a, 3), derive_blinding(&a, 3));
    }

    #[test]
    fn hex_round_trips() {
        let mask = amount_mask(&ss(), 2);
        let enc = encrypt_amount(7, &mask);
        let h = enc_to_hex(&enc);
        assert_eq!(enc_from_hex(&h), Some(enc));
        assert!(enc_from_hex("zz").is_none());
        assert!(enc_from_hex("00").is_none()); // wrong length
    }
}
```

- [ ] **Step 3: Run to verify it fails** — `cargo test --lib ringct::amount_encoding 2>&1 | head` → FAIL (undefined).

- [ ] **Step 4: Implement**

Add ABOVE the tests:
```rust
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};

/// Output commitment blinding, derived from the ECDH shared secret + index.
pub fn derive_blinding(shared_secret: &RistrettoPoint, index: u32) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"ShadowDAG_RingCT_commit_mask_v1");
    h.update(shared_secret.compress().as_bytes());
    h.update(index.to_le_bytes());
    Scalar::from_hash(h)
}

/// 8-byte one-time pad for the amount, derived from the shared secret + index.
pub fn amount_mask(shared_secret: &RistrettoPoint, index: u32) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_RingCT_amount_v1");
    h.update(shared_secret.compress().as_bytes());
    h.update(index.to_le_bytes());
    let full: [u8; 32] = h.finalize().into();
    let mut m = [0u8; 8];
    m.copy_from_slice(&full[..8]);
    m
}

/// XOR-encrypt the amount with the mask (one-time pad).
pub fn encrypt_amount(amount: u64, mask: &[u8; 8]) -> [u8; 8] {
    let a = amount.to_le_bytes();
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = a[i] ^ mask[i];
    }
    out
}

/// Decrypt the masked amount.
pub fn decrypt_amount(enc: &[u8; 8], mask: &[u8; 8]) -> u64 {
    let mut a = [0u8; 8];
    for i in 0..8 {
        a[i] = enc[i] ^ mask[i];
    }
    u64::from_le_bytes(a)
}

pub fn enc_to_hex(enc: &[u8; 8]) -> String {
    hex::encode(enc)
}

pub fn enc_from_hex(h: &str) -> Option<[u8; 8]> {
    let bytes = hex::decode(h).ok()?;
    let arr: [u8; 8] = bytes.try_into().ok()?;
    Some(arr)
}
```

- [ ] **Step 5: Run** — `cargo test --lib ringct::amount_encoding` → 3 PASS.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(privacy): RingCT amount encoding (derive blinding/mask, encrypt/decrypt)"`

---

### Task 2: `encrypted_amount` field + canonical_bytes + message V3

**Files:**
- Modify: `domain/transaction/transaction.rs`, `domain/transaction/tx_hash.rs`

- [ ] **Step 1: Failing test** — add to `transaction.rs` tests:
```rust
    #[test]
    fn encrypted_amount_changes_canonical_bytes() {
        let mut tx = Transaction::new(String::new(), vec![], vec![TxOutput::new("SD1x".into(), 10)], 1, 0);
        let base = tx.canonical_bytes();
        tx.outputs[0].encrypted_amount = Some("0011223344556677".into());
        assert_ne!(base, tx.canonical_bytes());
    }
```

- [ ] **Step 2: Run** — FAIL (no field `encrypted_amount`).

- [ ] **Step 3: Add the field** — in `struct TxOutput`, after `one_time_pubkey`:
```rust
    /// RingCT: amount masked with a one-time pad derived from the ECDH shared
    /// secret (hex, 8 bytes). Lets the recipient recover the amount. None for
    /// transparent outputs.
    #[serde(default)]
    pub encrypted_amount: Option<String>,
```

- [ ] **Step 4: Bind in `canonical_bytes`** — in the output loop, after the `one_time_pubkey` block:
```rust
            if let Some(ref ea) = out.encrypted_amount {
                buf.push(0x01);
                buf.extend_from_slice(&(ea.len() as u32).to_le_bytes());
                buf.extend_from_slice(ea.as_bytes());
            } else {
                buf.push(0x00);
            }
```

- [ ] **Step 5: Bind in the confidential message (tx_hash.rs)** — bump the tag
`b"SHADOW_TX_CONF_SIGN_V2"` → `b"SHADOW_TX_CONF_SIGN_V3"`, and in the per-output
`for opt in [...]` array add `&o.encrypted_amount`:
```rust
            for opt in [&o.commitment, &o.ephemeral_pubkey, &o.one_time_pubkey, &o.encrypted_amount] {
```

- [ ] **Step 6: Update TxOutput constructors + all literals** — add `encrypted_amount: None,` to `TxOutput::new`, `TxOutput::new_confidential`, then build-then-fix:
```
cargo build --lib 2>&1 | grep "missing field \`encrypted_amount\`" -A1 | grep -oE "[a-zA-Z0-9_/\\\\.]+\.rs:[0-9]+"
```
sed each reported file (after the `one_time_pubkey: None,` line):
```
sed -i -E 's/^([[:space:]]*)one_time_pubkey: None,$/\1one_time_pubkey: None,\n\1encrypted_amount: None,/' <files>
```
then repeat for `--no-run` tests and `--all-targets` until clean. Handle any
`one_time_pubkey: Some(...)` literal sites manually.

- [ ] **Step 7: Run** — `cargo test --lib transaction::tests::encrypted_amount tx_hash::tests` → PASS.
- [ ] **Step 8: Commit** — `git add -A && git commit -m "feat(privacy): TxOutput.encrypted_amount + canonical_bytes + CONF_SIGN_V3"`

---

### Task 3: Stealth shared-secret exposure

**Files:**
- Modify: `domain/address/stealth_address.rs`

- [ ] **Step 1: Failing test** — add to the `stealth_address` test module:
```rust
    #[test]
    fn sender_and_recipient_derive_same_shared_secret() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let g = RISTRETTO_BASEPOINT_POINT;
        let view_priv = Scalar::random(&mut OsRng);
        let spend_priv = Scalar::random(&mut OsRng);
        let (res, ss_sender) = StealthAddress::generate_full_for_network_with_secret(
            &(view_priv * g), &(spend_priv * g), "mainnet",
        ).unwrap();
        let r_point = crate::engine::privacy::ringct::serialization::point_from_hex(&res.ephemeral_pubkey).unwrap();
        let ss_recipient = StealthAddress::recipient_shared_secret(&r_point, &view_priv);
        assert_eq!(ss_sender, ss_recipient);
    }
```

- [ ] **Step 2: Run** — FAIL (undefined).

- [ ] **Step 3: Implement** — add to `impl StealthAddress`:
```rust
    /// Like `generate_full_for_network` but also returns the ECDH shared secret
    /// `ss = r·V`, so the caller can derive the output blinding + amount mask.
    pub fn generate_full_for_network_with_secret(
        recipient_view_pub: &RistrettoPoint,
        recipient_spend_pub: &RistrettoPoint,
        network: &str,
    ) -> Result<(StealthAddressResult, RistrettoPoint), CryptoError> {
        let r = Scalar::random(&mut OsRng);
        let big_r = r * g();
        let shared_secret = r * recipient_view_pub;
        let hs = derive_hash_scalar(&shared_secret)?;
        let one_time_pub = hs * g() + recipient_spend_pub;
        let compressed = one_time_pub.compress();
        let prefix = stealth_prefix(network);
        let addr = format!("{}{}", prefix, hex::encode(&compressed.as_bytes()[..20]));
        Ok((
            StealthAddressResult {
                one_time_address: addr,
                ephemeral_pubkey: hex::encode(big_r.compress().as_bytes()),
                one_time_pubkey: hex::encode(compressed.as_bytes()),
            },
            shared_secret,
        ))
    }

    /// Recipient side: ss = view_priv · R.
    pub fn recipient_shared_secret(
        ephemeral_r: &RistrettoPoint,
        view_priv: &Scalar,
    ) -> RistrettoPoint {
        view_priv * ephemeral_r
    }
```
> `derive_hash_scalar`, `g()`, `stealth_prefix` are already in scope in this file.

- [ ] **Step 4: Run** — `cargo test --lib stealth_address::tests::sender_and_recipient` → PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(privacy): stealth shared-secret exposure (sender + recipient)"`

---

### Task 4: Builder — derive output blindings, absorb on the input side, set encrypted_amount

**Files:**
- Modify: `engine/privacy/ringct/builder.rs`

- [ ] **Step 1: Change output construction + balance direction**

In `build_confidential_transaction`:
- Remove the `out_blindings` random-vector + last-output-absorb code.
- In the output loop, use the ss-returning generator and derive the blinding +
  encrypted amount:
```rust
    let mut out_blinding_sum = Scalar::ZERO;
    let mut tx_outputs = Vec::with_capacity(n_out);
    for (i, r) in recipients.iter().enumerate() {
        let (stealth, ss) = StealthAddress::generate_full_for_network_with_secret(
            &r.view_pub, &r.spend_pub, network.short_name(),
        )?;
        let blinding = amount_encoding::derive_blinding(&ss, i as u32);
        out_blinding_sum += blinding;
        let c_out = Scalar::from(r.amount) * h + blinding * g;
        let proof = range_proof::prove(r.amount, &blinding);
        let mask = amount_encoding::amount_mask(&ss, i as u32);
        let enc = amount_encoding::encrypt_amount(r.amount, &mask);
        tx_outputs.push(TxOutput {
            address: stealth.one_time_address,
            amount: 0,
            commitment: Some(hexp(&c_out)),
            range_proof: Some(range_proof_to_hex(&proof)),
            ephemeral_pubkey: Some(stealth.ephemeral_pubkey),
            one_time_pubkey: Some(stealth.one_time_pubkey),
            encrypted_amount: Some(amount_encoding::enc_to_hex(&enc)),
        });
    }
```
- Pseudo-output blindings: random for all but the LAST input, which absorbs so
  `Σ r'_in == Σ out_blindings`:
```rust
    let mut pseudo_blindings: Vec<Scalar> =
        (0..inputs.len()).map(|_| Scalar::random(&mut OsRng)).collect();
    let last = inputs.len() - 1;
    let sum_other_pseudo: Scalar = pseudo_blindings[..last].iter().sum();
    pseudo_blindings[last] = out_blinding_sum - sum_other_pseudo;
```
  (Place this BEFORE the input loop that builds `pseudo_points`. Delete the old
  `sum_pseudo` / `out_blindings` lines.)

Add `use crate::engine::privacy::ringct::amount_encoding;` at the top.

- [ ] **Step 2: Run 4a's existing builder tests (balance must still hold)**

Run: `cargo test --lib ringct::builder::tests 2>&1 | grep -E "test result|FAILED"`
Expected: all 6 PASS (now with derived output blindings + input-side absorption).
If a multi-output test fails on balance, the absorption is on the wrong side —
fix (absorb on the LAST INPUT, not an output).

- [ ] **Step 3: Commit** — `git add -A && git commit -m "feat(privacy): builder derives output blindings from ss + encrypted_amount; absorb on input side"`

---

### Task 5: `scan` module (detect + recover)

**Files:**
- Create: `engine/privacy/ringct/scan.rs`
- Modify: `lib.rs` (declare `pub mod scan;`)

- [ ] **Step 1: Declare the module** — add `pub mod scan;` under ringct.

- [ ] **Step 2: Write the module with impl + tests**

Create `engine/privacy/ringct/scan.rs`:
```rust
// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Recipient-side scanning + recovery of confidential outputs.

use crate::domain::address::stealth_address::{derive_hash_scalar, StealthAddress};
use crate::domain::transaction::transaction::TxOutput;
use crate::engine::privacy::confidential::pedersen::generator_h;
use crate::engine::privacy::ringct::amount_encoding;
use crate::engine::privacy::ringct::serialization::point_from_hex;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// A recovered confidential output the wallet owns.
pub struct RecoveredOutput {
    pub amount: u64,
    pub blinding: Scalar,
    pub one_time_pubkey: RistrettoPoint,
}

/// Returns Some iff `output` is addressed to (view_priv, spend_pub) AND its
/// commitment opens to the decrypted amount with the derived blinding.
pub fn scan_confidential_output(
    output: &TxOutput,
    output_index: u32,
    view_priv: &Scalar,
    spend_pub: &RistrettoPoint,
) -> Option<RecoveredOutput> {
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = generator_h();

    let r_point = point_from_hex(output.ephemeral_pubkey.as_ref()?)?;
    let commitment = point_from_hex(output.commitment.as_ref()?)?;
    let one_time_pubkey = point_from_hex(output.one_time_pubkey.as_ref()?)?;
    let enc = amount_encoding::enc_from_hex(output.encrypted_amount.as_ref()?)?;

    // Shared secret + ownership: P' = Hs(ss)·G + S must equal the output's P.
    let ss = StealthAddress::recipient_shared_secret(&r_point, view_priv);
    let hs = derive_hash_scalar(&ss).ok()?;
    if (hs * g + spend_pub) != one_time_pubkey {
        return None;
    }

    // Decrypt amount + derive blinding; commitment must open to them.
    let mask = amount_encoding::amount_mask(&ss, output_index);
    let amount = amount_encoding::decrypt_amount(&enc, &mask);
    let blinding = amount_encoding::derive_blinding(&ss, output_index);
    if (Scalar::from(amount) * h + blinding * g) != commitment {
        return None;
    }

    Some(RecoveredOutput {
        amount,
        blinding,
        one_time_pubkey,
    })
}

/// Derive the one-time spend secret `x` (x·G == one_time_pubkey). Needs the
/// wallet spend private key. Returns None if not owned.
pub fn recover_spend_secret(
    output: &TxOutput,
    view_priv: &Scalar,
    spend_priv: &Scalar,
) -> Option<Scalar> {
    let r_point = point_from_hex(output.ephemeral_pubkey.as_ref()?)?;
    let x = StealthAddress::derive_one_time_private_key(&r_point, view_priv, spend_priv).ok()?;
    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::node::node_config::NetworkMode;
    use crate::engine::privacy::ringct::builder::{
        build_confidential_transaction, ConfRecipient,
    };
    use rand::rngs::OsRng;

    fn keypair() -> (Scalar, RistrettoPoint) {
        let s = Scalar::random(&mut OsRng);
        (s, s * RISTRETTO_BASEPOINT_POINT)
    }

    // Builds a tx paying `to`, returns it (single output). The single input is
    // a throwaway owned input recorded in `set`.
    fn pay(
        set: &crate::domain::utxo::utxo_set::UtxoSet,
        to: &(Scalar, RistrettoPoint),  // (view_priv, view_pub) ... see below
        amount: u64,
    ) -> crate::domain::transaction::transaction::Transaction {
        use crate::engine::privacy::ringct::builder::OwnedInput;
        use crate::engine::privacy::ringct::dual_clsag::RingMember;
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        // One owned input of `amount`, ring size 2.
        let mut ring = Vec::new();
        for _ in 0..2 {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            let pk = sk * g;
            let c = Scalar::from(amount) * h + bl * g;
            crate::engine::privacy::ringct::builder::record_for_test(set, &pk, &c);
            ring.push(RingMember { public_key: pk, commitment: c });
        }
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let pk = spend * g;
        let c = Scalar::from(amount) * h + bl * g;
        crate::engine::privacy::ringct::builder::record_for_test(set, &pk, &c);
        ring[0] = RingMember { public_key: pk, commitment: c };
        let owned = OwnedInput { spend_secret: spend, amount, blinding: bl, ring, real_index: 0 };
        // recipient: view + spend keypairs
        let (_vpriv, vpub) = *to;
        let (_spriv, spub) = keypair();
        let _ = (vpub, spub);
        unreachable!("replaced below")
    }

    #[test]
    fn scan_recovers_amount_and_spend_key() {
        let set = crate::domain::utxo::utxo_set::UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();

        // Recipient keys.
        let (view_priv, view_pub) = keypair();
        let (spend_priv, spend_pub) = keypair();

        // One owned input of 100, ring size 2, recorded in okey.
        use crate::engine::privacy::ringct::builder::{OwnedInput};
        use crate::engine::privacy::ringct::dual_clsag::RingMember;
        let mut ring = Vec::new();
        for _ in 0..2 {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            let pk = sk * g; let c = Scalar::from(100u64) * h + bl * g;
            set.record_output_key(&hex::encode(pk.compress().as_bytes()), &hex::encode(c.compress().as_bytes())).unwrap();
            ring.push(RingMember { public_key: pk, commitment: c });
        }
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let pk = spend * g; let c = Scalar::from(100u64) * h + bl * g;
        set.record_output_key(&hex::encode(pk.compress().as_bytes()), &hex::encode(c.compress().as_bytes())).unwrap();
        ring[0] = RingMember { public_key: pk, commitment: c };
        let owned = OwnedInput { spend_secret: spend, amount: 100, blinding: bl, ring, real_index: 0 };

        let tx = build_confidential_transaction(
            vec![owned],
            vec![ConfRecipient { view_pub, spend_pub, amount: 100 }],
            0, &net,
        ).unwrap();

        // Recipient scans output 0.
        let rec = scan_confidential_output(&tx.outputs[0], 0, &view_priv, &spend_pub)
            .expect("should own this output");
        assert_eq!(rec.amount, 100);
        assert_eq!(Scalar::from(100u64) * h + rec.blinding * g,
                   point_from_hex(tx.outputs[0].commitment.as_ref().unwrap()).unwrap());

        // Spend-key recovery: x·G == one_time_pubkey.
        let x = recover_spend_secret(&tx.outputs[0], &view_priv, &spend_priv).unwrap();
        assert_eq!(x * g, rec.one_time_pubkey);

        // Not owned by a different recipient.
        let (other_v, _) = keypair();
        assert!(scan_confidential_output(&tx.outputs[0], 0, &other_v, &spend_pub).is_none());

        // Tampered encrypted_amount → amount no longer opens commitment → None.
        let mut bad = tx.outputs[0].clone();
        bad.encrypted_amount = Some("ffffffffffffffff".into());
        assert!(scan_confidential_output(&bad, 0, &view_priv, &spend_pub).is_none());
    }
}
```
> Delete the broken `pay` helper stub above before finalizing — the
> `scan_recovers_amount_and_spend_key` test is self-contained. (It is included
> here only to show the owned-input construction; keep just the real test.)

- [ ] **Step 3: Run** — `cargo test --lib ringct::scan 2>&1 | grep -E "test result|FAILED"` → PASS.
- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(privacy): confidential output scan + amount/spend-key recovery"`

---

### Task 6: Full round-trip integration test

**Files:**
- Modify: `engine/privacy/ringct/scan.rs` (tests)

- [ ] **Step 1: Add the round-trip test**

```rust
    #[test]
    fn round_trip_build_scan_recover_spend_verify() {
        use crate::engine::privacy::ringct::builder::{OwnedInput};
        use crate::engine::privacy::ringct::dual_clsag::RingMember;
        use crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx;
        use std::collections::HashSet;
        let set = crate::domain::utxo::utxo_set::UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();

        // --- A pays B 100 (B's keys) ---
        let (b_view_priv, b_view_pub) = keypair();
        let (b_spend_priv, b_spend_pub) = keypair();
        // A's owned input (100), recorded.
        let mut ring = Vec::new();
        for _ in 0..3 {
            let sk = Scalar::random(&mut OsRng); let bl = Scalar::random(&mut OsRng);
            let pk = sk*g; let c = Scalar::from(100u64)*h + bl*g;
            set.record_output_key(&hex::encode(pk.compress().as_bytes()), &hex::encode(c.compress().as_bytes())).unwrap();
            ring.push(RingMember{public_key:pk,commitment:c});
        }
        let a_spend = Scalar::random(&mut OsRng); let a_bl = Scalar::random(&mut OsRng);
        let a_pk = a_spend*g; let a_c = Scalar::from(100u64)*h + a_bl*g;
        set.record_output_key(&hex::encode(a_pk.compress().as_bytes()), &hex::encode(a_c.compress().as_bytes())).unwrap();
        ring[1] = RingMember{public_key:a_pk,commitment:a_c};
        let a_owned = OwnedInput{spend_secret:a_spend, amount:100, blinding:a_bl, ring, real_index:1};
        let tx1 = build_confidential_transaction(
            vec![a_owned],
            vec![ConfRecipient{view_pub:b_view_pub, spend_pub:b_spend_pub, amount:100}],
            0, &net,
        ).unwrap();
        // tx1 must be consensus-valid.
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx1, &set, &net, &mut seen).is_ok());
        // Record tx1's output as a real on-chain confidential output.
        let out = &tx1.outputs[0];
        set.record_output_key(out.one_time_pubkey.as_ref().unwrap(), out.commitment.as_ref().unwrap()).unwrap();

        // --- B scans, recovers, and spends 100 to C ---
        let rec = scan_confidential_output(out, 0, &b_view_priv, &b_spend_pub).expect("B owns it");
        let x = recover_spend_secret(out, &b_view_priv, &b_spend_priv).unwrap();
        // Build B's ring: real = (one_time_pubkey, commitment); add 2 decoys, all recorded.
        let mut bring = Vec::new();
        for _ in 0..2 {
            let sk=Scalar::random(&mut OsRng); let bl=Scalar::random(&mut OsRng);
            let pk=sk*g; let c=Scalar::from(rec.amount)*h+bl*g;
            set.record_output_key(&hex::encode(pk.compress().as_bytes()), &hex::encode(c.compress().as_bytes())).unwrap();
            bring.push(RingMember{public_key:pk,commitment:c});
        }
        bring.push(RingMember{ public_key: rec.one_time_pubkey, commitment: point_from_hex(out.commitment.as_ref().unwrap()).unwrap() });
        let real_idx = bring.len()-1;
        let b_owned = OwnedInput{ spend_secret:x, amount:rec.amount, blinding:rec.blinding, ring:bring, real_index:real_idx };
        let (c_view_priv, c_view_pub) = keypair();
        let (_c_spend_priv, c_spend_pub) = keypair();
        let _ = c_view_priv;
        let tx2 = build_confidential_transaction(
            vec![b_owned],
            vec![ConfRecipient{view_pub:c_view_pub, spend_pub:c_spend_pub, amount:100}],
            0, &net,
        ).unwrap();
        let mut seen2 = HashSet::new();
        assert!(verify_confidential_tx(&tx2, &set, &net, &mut seen2).is_ok(),
            "B's recovered output must be spendable and consensus-valid");
    }
```

- [ ] **Step 2: Run** — `cargo test --lib ringct::scan::tests::round_trip 2>&1 | grep -E "test result|FAILED"` → PASS.
- [ ] **Step 3: Commit** — `git add -A && git commit -m "test(privacy): full RingCT round-trip build->scan->recover->spend->verify"`

---

### Task 7: Final gate
- [ ] `cargo build --all-targets` → Finished.
- [ ] `cargo clippy --all-targets -- -D warnings` → clean (fix inline).
- [ ] `cargo test --lib` → all pass (transparent/genesis unaffected; CONF_SIGN_V3 + new field additive).
- [ ] Commit any fixups: `git add -A && git commit -m "chore(privacy): RingCT amount-encoding + scan green (build+clippy+suite)"`

---

## Self-review notes (coverage vs spec)
- Derive blinding/mask + encrypt/decrypt → Task 1. ✓
- `encrypted_amount` field + canonical + V3 message → Task 2. ✓
- Stealth ss exposure (sender + recipient) → Task 3. ✓
- Builder: derived output blindings + input-side absorption + encrypted_amount →
  Task 4 (4a tests re-run as regression). ✓
- Scan (ownership + decrypt + commitment-open) + spend-key recovery → Task 5. ✓
- Full round-trip oracle → Task 6. ✓
- Non-goals (decoy index, CLI, subaddresses) → absent. ✓
- Balance-flip is single-strategy (input side only) → Task 4 deletes the old
  output-absorb code. ✓
- Type/seam names match: `derive_blinding`, `amount_mask`, `encrypt_amount`,
  `enc_to_hex`/`enc_from_hex`, `generate_full_for_network_with_secret`,
  `recipient_shared_secret`, `scan_confidential_output`, `recover_spend_secret`,
  `RecoveredOutput`. ✓

## Sharp edges for the executor
- Delete the illustrative broken `pay` stub in Task 5 before running; keep the
  real self-contained test.
- The builder requires ≥1 input (last absorbs) — already guaranteed by the
  empty-check. Output blindings are now fully derived; do NOT also randomize them.
- Range proof uses the DERIVED blinding (so the recipient's recomputed blinding
  opens the same commitment the proof covers).
