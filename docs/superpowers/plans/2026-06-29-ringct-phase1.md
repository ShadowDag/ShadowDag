# RingCT Phase 1 (Sender Privacy) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task with review between tasks. This is a CONSENSUS-CRITICAL change — do NOT batch-execute. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make consensus cryptographically verify the *sender-privacy* of confidential transactions (CLSAG ring signatures + key images + on-chain ring-member authenticity) and remove the blanket rejection gate. **Amounts stay plaintext; the existing balance check is unchanged.**

**Architecture:** Build bottom-up. Foundational, isolated, low-risk pieces first (serialization, signing message, a `ring_signature` field, two RocksDB-backed sets), each TDD-tested alone. Then wire verification into `RingValidator` (pure crypto, no DB) and the confidential branch of `TxValidator` (DB-backed: ring-member membership + key-image uniqueness), and record key images + output keys during block execution. Finally remove the gate behind an integration test that exercises every defense.

**Tech Stack:** Rust, `curve25519-dalek` v4 (Ristretto), `hmac`/`sha2`, RocksDB via the existing `UtxoSet` store, `bincode`.

**Spec:** `docs/superpowers/specs/2026-06-29-ringct-phase1-design.md`

**Confirmed integration seams (from code audit):**
- `clsag::sign(message,&ring,idx,&sk)->Result<CLSAGSignature,_>`, `clsag::verify(message,&[RistrettoPoint],&CLSAGSignature)->bool`; `CLSAGSignature{c0:Scalar,s:Vec<Scalar>,key_image:CompressedRistretto}` (`engine/privacy/ringct/clsag.rs`).
- `RingValidator::validate(tx)` called at `tx_validator.rs:473` (in `validate_tx_for_network`) and `:722` (in `validate_transaction`).
- `validate_transaction(tx,&UtxoSet)->Result<(),StorageError>`; `validate_tx_for_network(tx,&UtxoSet,&NetworkMode)->bool`.
- UTXO write path: `UtxoSet::apply_block_write_with_commitment(&[Transaction],u64,&str)->Result<String,StorageError>`; builds ops as `BatchWrite::{Put,Delete}` then `store.write_batch(ops)`. Store also has `get_raw(&[u8])->Option<Vec<u8>>`, `put_raw`, `delete_raw`.
- curve25519 v4: `Scalar::as_bytes()->&[u8;32]`, `Scalar::from_canonical_bytes(arr)->CtOption` (`.into()`), `CompressedRistretto(arr).decompress()->Option<RistrettoPoint>`, `point.compress().as_bytes()`.
- `tx_hash::signing_message_for_network(tx,&NetworkMode)->Vec<u8>` is the transparent template to mirror.

---

### Task 1: CLSAG signature serialization

**Files:**
- Create: `engine/privacy/ringct/serialization.rs`
- Modify: `lib.rs` (declare `pub mod serialization;` under `engine::privacy::ringct`)
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Declare the module**

In `lib.rs`, find the `ringct` module block (search `pub mod ringct`) and add
`pub mod serialization;` alongside `clsag`, `ring_validator`, etc.

- [ ] **Step 2: Write failing round-trip + rejection tests**

Create `engine/privacy/ringct/serialization.rs`:
```rust
//! Byte (de)serialization for CLSAG signatures — curve types are not serde.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::privacy::ringct::clsag;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn sample_sig() -> clsag::CLSAGSignature {
        let pairs: Vec<(Scalar, _)> = (0..4)
            .map(|_| {
                let sk = Scalar::random(&mut OsRng);
                (sk, sk * RISTRETTO_BASEPOINT_POINT)
            })
            .collect();
        let ring: Vec<_> = pairs.iter().map(|(_, pk)| *pk).collect();
        clsag::sign(b"msg", &ring, 1, &pairs[1].0).unwrap()
    }

    #[test]
    fn clsag_hex_round_trips() {
        let sig = sample_sig();
        let hex = clsag_sig_to_hex(&sig);
        let back = clsag_sig_from_hex(&hex).unwrap();
        assert_eq!(sig.c0, back.c0);
        assert_eq!(sig.s, back.s);
        assert_eq!(sig.key_image, back.key_image);
    }

    #[test]
    fn rejects_truncated() {
        assert!(clsag_sig_from_hex("deadbeef").is_none());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(clsag_sig_from_hex("zzzz").is_none());
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test --lib ringct::serialization 2>&1 | head -20`
Expected: FAIL — `clsag_sig_to_hex` / `clsag_sig_from_hex` undefined.

- [ ] **Step 4: Implement serialization**

Add ABOVE the tests:
```rust
use crate::engine::privacy::ringct::clsag::CLSAGSignature;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

/// Wire format: c0(32) || count(u32 LE) || s_i(32)* || key_image(32).
pub fn clsag_sig_to_bytes(sig: &CLSAGSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 4 + sig.s.len() * 32 + 32);
    out.extend_from_slice(sig.c0.as_bytes());
    out.extend_from_slice(&(sig.s.len() as u32).to_le_bytes());
    for s in &sig.s {
        out.extend_from_slice(s.as_bytes());
    }
    out.extend_from_slice(sig.key_image.as_bytes());
    out
}

pub fn clsag_sig_from_bytes(b: &[u8]) -> Option<CLSAGSignature> {
    if b.len() < 36 {
        return None;
    }
    let c0 = scalar_from(&b[0..32])?;
    let count = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    let need = 36 + count * 32 + 32;
    if b.len() != need {
        return None;
    }
    let mut s = Vec::with_capacity(count);
    for i in 0..count {
        let off = 36 + i * 32;
        s.push(scalar_from(&b[off..off + 32])?);
    }
    let ki_off = 36 + count * 32;
    let mut ki = [0u8; 32];
    ki.copy_from_slice(&b[ki_off..ki_off + 32]);
    // Must decompress to a valid point.
    let key_image = CompressedRistretto(ki);
    key_image.decompress()?;
    Some(CLSAGSignature { c0, s, key_image })
}

pub fn clsag_sig_to_hex(sig: &CLSAGSignature) -> String {
    hex::encode(clsag_sig_to_bytes(sig))
}

pub fn clsag_sig_from_hex(h: &str) -> Option<CLSAGSignature> {
    clsag_sig_from_bytes(&hex::decode(h).ok()?)
}

fn scalar_from(b: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = b.try_into().ok()?;
    let ct = Scalar::from_canonical_bytes(arr);
    Option::<Scalar>::from(ct)
}

/// Parse a hex compressed-Ristretto point, requiring it to decompress.
pub fn point_from_hex(h: &str) -> Option<curve25519_dalek::ristretto::RistrettoPoint> {
    let bytes = hex::decode(h).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    CompressedRistretto(arr).decompress()
}
```

> Note: `CLSAGSignature.c0`/`s` are `Scalar`; `key_image` is `CompressedRistretto`.
> The `PartialEq` asserts in tests rely on dalek's derived `PartialEq` for these.
> If `CLSAGSignature` lacks the field visibility, they are already `pub` per
> `clsag.rs`.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --lib ringct::serialization -- --nocapture`
Expected: all three PASS.

- [ ] **Step 6: Commit**

```bash
git add engine/privacy/ringct/serialization.rs lib.rs
git commit -m "feat(privacy): CLSAG signature byte/hex serialization with canonical checks"
```

---

### Task 2: Confidential signing message

**Files:**
- Modify: `domain/transaction/tx_hash.rs` (add a new function + tests)

- [ ] **Step 1: Write the failing determinism tests**

Append to the `#[cfg(test)]` module in `tx_hash.rs`:
```rust
    #[test]
    fn confidential_message_is_deterministic() {
        let tx = sample_confidential_tx(); // helper below
        let net = NetworkMode::Mainnet;
        let a = TxHash::confidential_signing_message_for_network(&tx, &net);
        let b = TxHash::confidential_signing_message_for_network(&tx, &net);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn confidential_message_differs_from_transparent() {
        let tx = sample_confidential_tx();
        let net = NetworkMode::Mainnet;
        let conf = TxHash::confidential_signing_message_for_network(&tx, &net);
        let transp = TxHash::signing_message_for_network(&tx, &net);
        assert_ne!(conf, transp);
    }

    #[test]
    fn confidential_message_binds_key_image() {
        let mut tx = sample_confidential_tx();
        let net = NetworkMode::Mainnet;
        let before = TxHash::confidential_signing_message_for_network(&tx, &net);
        tx.inputs[0].key_image = Some("ff".repeat(32));
        let after = TxHash::confidential_signing_message_for_network(&tx, &net);
        assert_ne!(before, after);
    }
```
And add this helper inside the same test module (adjust imports to the file's
existing `Transaction`/`TxInput`/`TxOutput` paths):
```rust
    fn sample_confidential_tx() -> Transaction {
        use crate::domain::transaction::transaction::{TxInput, TxOutput, TxType};
        let mut tx = Transaction {
            hash: "a".repeat(64),
            inputs: vec![TxInput {
                txid: "b".repeat(64),
                index: 0,
                owner: "SD1owner".into(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: Some("11".repeat(32)),
                ring_members: Some(vec!["22".repeat(32), "33".repeat(32),
                                        "44".repeat(32), "55".repeat(32)]),
                ring_signature: None,
            }],
            outputs: vec![TxOutput::new("SD1dest".into(), 1000)],
            fee: 100,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Confidential,
            payload_hash: None,
            ..Default::default()
        };
        tx.hash = "a".repeat(64);
        tx
    }
```

> This test references `TxInput.ring_signature`, added in Task 3. If executing
> strictly in order, do Task 3's struct change first, then return here. (Listed in
> this order because the message format is the conceptual foundation.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib tx_hash::tests::confidential 2>&1 | head -20`
Expected: FAIL — function undefined (and/or `ring_signature` field missing → do Task 3 first).

- [ ] **Step 3: Implement the message function**

Add to `impl TxHash` in `tx_hash.rs` (mirroring `signing_message_for_network`,
but binding key images + ring members + output address/commitment/ephemeral, and
using a distinct domain tag):
```rust
    /// Canonical signing message for confidential (ring-signed) inputs.
    /// Binds outputs (addr/commitment/ephemeral), each input's outpoint +
    /// key_image + ring_members, chain id, fee, timestamp, payload_hash.
    /// EXCLUDES ring_signature and signature (circularity).
    pub fn confidential_signing_message_for_network(
        tx: &Transaction,
        network: &NetworkMode,
    ) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"SHADOW_TX_CONF_SIGN_V1");
        h.update(Self::chain_id_for(network).to_le_bytes());
        h.update(tx.timestamp.to_le_bytes());
        h.update(tx.fee.to_le_bytes());

        h.update((tx.outputs.len() as u32).to_le_bytes());
        for o in &tx.outputs {
            let a = o.address.as_bytes();
            h.update((a.len() as u32).to_le_bytes());
            h.update(a);
            h.update(o.amount.to_le_bytes());
            for opt in [&o.commitment, &o.ephemeral_pubkey] {
                match opt {
                    Some(s) => {
                        h.update([1u8]);
                        h.update((s.len() as u32).to_le_bytes());
                        h.update(s.as_bytes());
                    }
                    None => h.update([0u8]),
                }
            }
        }

        // Inputs sorted by (txid, index) for determinism.
        let mut idx: Vec<usize> = (0..tx.inputs.len()).collect();
        idx.sort_by(|&i, &j| {
            (tx.inputs[i].txid.as_str(), tx.inputs[i].index)
                .cmp(&(tx.inputs[j].txid.as_str(), tx.inputs[j].index))
        });
        h.update((tx.inputs.len() as u32).to_le_bytes());
        for &i in &idx {
            let inp = &tx.inputs[i];
            let t = inp.txid.as_bytes();
            h.update((t.len() as u32).to_le_bytes());
            h.update(t);
            h.update(inp.index.to_le_bytes());
            match &inp.key_image {
                Some(k) => {
                    h.update([1u8]);
                    h.update((k.len() as u32).to_le_bytes());
                    h.update(k.as_bytes());
                }
                None => h.update([0u8]),
            }
            match &inp.ring_members {
                Some(members) => {
                    h.update([1u8]);
                    h.update((members.len() as u32).to_le_bytes());
                    for m in members {
                        h.update((m.len() as u32).to_le_bytes());
                        h.update(m.as_bytes());
                    }
                }
                None => h.update([0u8]),
            }
        }
        match &tx.payload_hash {
            Some(p) => {
                h.update([1u8]);
                h.update((p.len() as u32).to_le_bytes());
                h.update(p.as_bytes());
            }
            None => h.update([0u8]),
        }
        h.finalize().to_vec()
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --lib tx_hash::tests::confidential -- --nocapture`
Expected: all three PASS.

- [ ] **Step 5: Commit**

```bash
git add domain/transaction/tx_hash.rs
git commit -m "feat(privacy): canonical confidential signing message (v1)"
```

---

### Task 3: Add `ring_signature` field to TxInput

**Files:**
- Modify: `domain/transaction/transaction.rs` (struct + constructors + `canonical_bytes`)

- [ ] **Step 1: Write a failing canonical-bytes test**

Add to the `transaction.rs` test module:
```rust
    #[test]
    fn ring_signature_changes_canonical_bytes() {
        let mut tx = Transaction::new(
            vec![],
            vec![TxOutput::new("SD1x".into(), 10)],
            1,
            0,
        );
        tx.inputs.push(TxInput {
            txid: "b".repeat(64),
            index: 0,
            owner: "SD1o".into(),
            signature: String::new(),
            pub_key: String::new(),
            key_image: Some("11".repeat(32)),
            ring_members: Some(vec!["22".repeat(32)]),
            ring_signature: None,
        });
        let before = tx.canonical_bytes();
        tx.inputs[0].ring_signature = Some("abcd".into());
        let after = tx.canonical_bytes();
        assert_ne!(before, after);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib transaction::tests::ring_signature 2>&1 | head`
Expected: FAIL — no field `ring_signature`.

- [ ] **Step 3: Add the field**

In `struct TxInput`, after `ring_members`, add:
```rust
    /// Serialized CLSAG signature (hex) for confidential inputs. None for
    /// transparent inputs (which use `signature` = Ed25519 hex).
    #[serde(default)]
    pub ring_signature: Option<String>,
```
Update EVERY `TxInput { ... }` literal in `transaction.rs` (constructors
`new`, `new_confidential`, and any others) to set `ring_signature: None` (or the
provided value in `new_confidential` if extended). Then in `canonical_bytes()`,
in the per-input section after `ring_members`, append deterministically:
```rust
        match &input.ring_signature {
            Some(rs) => {
                out.push(1u8);
                out.extend_from_slice(&(rs.len() as u32).to_le_bytes());
                out.extend_from_slice(rs.as_bytes());
            }
            None => out.push(0u8),
        }
```

- [ ] **Step 4: Fix all other `TxInput { ... }` constructions repo-wide**

Run: `cargo build --lib 2>&1 | grep -A2 "missing field .ring_signature"`
For each reported site, add `ring_signature: None,`. Re-run until it builds.

- [ ] **Step 5: Run tests to verify pass**

Run: `cargo test --lib transaction::tests -- --nocapture`
Expected: new test PASS; existing transaction tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(privacy): add TxInput.ring_signature + bind it in canonical_bytes"
```

---

### Task 4: Key-image store + output-key index on UtxoSet

**Files:**
- Modify: `domain/utxo/utxo_set.rs` (add keyed helpers + record during apply)
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing tests for the two sets**

Add to `utxo_set.rs` tests (use the crate's existing test-DB helper; if none,
use `tempfile` like other UtxoSet tests):
```rust
    #[test]
    fn key_image_recorded_and_detected() {
        let set = test_utxo_set(); // existing helper or tempfile-based ctor
        let ki = "ab".repeat(32);
        assert!(!set.key_image_seen(&ki));
        set.record_key_image(&ki).unwrap();
        assert!(set.key_image_seen(&ki));
    }

    #[test]
    fn output_key_membership() {
        let set = test_utxo_set();
        let pk = "cd".repeat(32);
        assert!(!set.output_key_exists(&pk));
        set.record_output_key(&pk).unwrap();
        assert!(set.output_key_exists(&pk));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib utxo_set::tests::key_image 2>&1 | head`
Expected: FAIL — methods undefined.

- [ ] **Step 3: Implement the helpers**

Add to `impl UtxoSet` (using the store's `get_raw`/`put_raw`):
```rust
    fn ki_key(ki_hex: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(3 + ki_hex.len());
        v.extend_from_slice(b"ki:");
        v.extend_from_slice(ki_hex.as_bytes());
        v
    }
    fn okey_key(pk_hex: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + pk_hex.len());
        v.extend_from_slice(b"okey:");
        v.extend_from_slice(pk_hex.as_bytes());
        v
    }

    pub fn key_image_seen(&self, ki_hex: &str) -> bool {
        self.store.get_raw(&Self::ki_key(ki_hex)).is_some()
    }
    pub fn record_key_image(&self, ki_hex: &str) -> Result<(), StorageError> {
        self.store.put_raw(&Self::ki_key(ki_hex), &[1u8])
    }
    pub fn output_key_exists(&self, pk_hex: &str) -> bool {
        self.store.get_raw(&Self::okey_key(pk_hex)).is_some()
    }
    pub fn record_output_key(&self, pk_hex: &str) -> Result<(), StorageError> {
        self.store.put_raw(&Self::okey_key(pk_hex), &[1u8])
    }
```

- [ ] **Step 4: Record both during block apply (atomic with UTXO writes)**

In `apply_block_write_with_commitment`, build `BatchWrite::Put` entries (NOT
separate `put_raw`, to keep atomicity) for:
- each confidential input's `key_image` → `ki:` key, value `[1]`;
- each output's one-time pubkey (`ephemeral_pubkey` for confidential outputs) →
  `okey:` key, value `[1]`.
Add inside the existing per-tx loops:
```rust
        for input in &tx.inputs {
            if let Some(ki) = &input.key_image {
                ops.push(BatchWrite::Put { key: Self::ki_key(ki), value: vec![1u8] });
            }
        }
        for output in &tx.outputs {
            if let Some(pk) = &output.ephemeral_pubkey {
                ops.push(BatchWrite::Put { key: Self::okey_key(pk), value: vec![1u8] });
            }
        }
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --lib utxo_set::tests -- --nocapture`
Expected: new tests PASS; existing UtxoSet tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add domain/utxo/utxo_set.rs
git commit -m "feat(privacy): key-image store + output-key index on UtxoSet (atomic apply)"
```

---

### Task 5: CLSAG crypto verification in RingValidator (no DB)

**Files:**
- Modify: `engine/privacy/ringct/ring_validator.rs`
- Test: inline `#[cfg(feature = "ringct_bypass")]`-free positive test using real sign

- [ ] **Step 1: Write a failing crypto-verify test**

Add to `ring_validator.rs` tests:
```rust
    #[test]
    fn accepts_valid_clsag_and_rejects_tamper() {
        use crate::engine::privacy::ringct::clsag;
        use crate::engine::privacy::ringct::serialization::{clsag_sig_to_hex};
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::scalar::Scalar;
        use rand::rngs::OsRng;

        // Build a ring of 4 real keys, signer at index 2.
        let pairs: Vec<(Scalar, _)> = (0..4).map(|_| {
            let sk = Scalar::random(&mut OsRng);
            (sk, sk * RISTRETTO_BASEPOINT_POINT)
        }).collect();
        let ring_hex: Vec<String> = pairs.iter()
            .map(|(_, pk)| hex::encode(pk.compress().as_bytes())).collect();

        let mut tx = make_confidential_tx(1);
        tx.inputs[0].ring_members = Some(ring_hex);
        let net = crate::config::node::node_config::NetworkMode::Mainnet;
        let msg = crate::domain::transaction::tx_hash::TxHash
            ::confidential_signing_message_for_network(&tx, &net);
        let sig = clsag::sign(&msg, &pairs.iter().map(|(_,p)|*p).collect::<Vec<_>>(),
                              2, &pairs[2].0).unwrap();
        tx.inputs[0].key_image = Some(hex::encode(sig.key_image.as_bytes()));
        tx.inputs[0].ring_signature = Some(clsag_sig_to_hex(&sig));

        assert!(RingValidator::verify_clsag(&tx, &net));

        // Tamper: flip ring_signature
        let mut bad = tx.clone();
        bad.inputs[0].ring_signature = Some("00".repeat(100));
        assert!(!RingValidator::verify_clsag(&bad, &net));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib ring_validator::tests::accepts_valid_clsag 2>&1 | head`
Expected: FAIL — `verify_clsag` undefined.

- [ ] **Step 3: Implement `verify_clsag` (pure crypto, no DB)**

Add to `impl RingValidator`:
```rust
    /// Cryptographic CLSAG verification for every confidential input.
    /// Deserializes ring_members + ring_signature and checks the ring closes
    /// over the canonical confidential message. No DB access.
    pub fn verify_clsag(
        tx: &crate::domain::transaction::transaction::Transaction,
        network: &crate::config::node::node_config::NetworkMode,
    ) -> bool {
        use crate::domain::transaction::tx_hash::TxHash;
        use crate::engine::privacy::ringct::serialization::{clsag_sig_from_hex, point_from_hex};

        let msg = TxHash::confidential_signing_message_for_network(tx, network);
        for input in &tx.inputs {
            let members = match &input.ring_members { Some(m) => m, None => return false };
            let mut ring = Vec::with_capacity(members.len());
            for m in members {
                match point_from_hex(m) { Some(p) => ring.push(p), None => return false }
            }
            let sig = match &input.ring_signature {
                Some(rs) => match clsag_sig_from_hex(rs) { Some(s) => s, None => return false },
                None => return false,
            };
            // key_image field must match the signature's key image.
            match &input.key_image {
                Some(ki) if *ki == hex::encode(sig.key_image.as_bytes()) => {}
                _ => return false,
            }
            if !crate::engine::privacy::ringct::clsag::verify(&msg, &ring, &sig) {
                return false;
            }
        }
        true
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --lib ring_validator::tests::accepts_valid_clsag -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add engine/privacy/ringct/ring_validator.rs
git commit -m "feat(privacy): RingValidator::verify_clsag (real CLSAG, no DB)"
```

---

### Task 6: Wire DB-backed checks + remove the gate in TxValidator

**Files:**
- Modify: `engine/privacy/ringct/ring_validator.rs` (remove the rejection gate)
- Modify: `domain/transaction/tx_validator.rs` (confidential branch at L473 + L722)

- [ ] **Step 1: Remove the blanket rejection gate**

In `ring_validator.rs::validate`, delete the
`#[cfg(not(feature = "ringct_bypass"))] { slog_error!... return false; }` block
and the trailing `#[allow(unreachable_code)] true`. Keep the structural checks
(steps 1–6) and end with `true`. The `ringct_bypass` feature and its compile_error
guard in `lib.rs` may now be removed (separate cleanup commit acceptable).

- [ ] **Step 2: Add a DB-backed confidential validator**

In `tx_validator.rs`, add a helper that runs the full confidential gate:
```rust
    /// Full confidential-input validation: structural + crypto + on-chain
    /// ring-member authenticity + key-image uniqueness. Amounts handled by the
    /// normal (plaintext) balance path — unchanged.
    pub fn validate_confidential(
        tx: &Transaction,
        utxo_set: &UtxoSet,
        network: &NetworkMode,
    ) -> bool {
        if !RingValidator::validate(tx) { return false; }           // structural
        if !RingValidator::verify_clsag(tx, network) { return false; } // crypto

        let mut seen_in_tx = std::collections::HashSet::new();
        for input in &tx.inputs {
            // ring members must be real on-chain output keys
            if let Some(members) = &input.ring_members {
                for m in members {
                    if !utxo_set.output_key_exists(m) { return false; }
                }
            } else { return false; }
            // key image unseen (chain) + unique (this tx)
            if let Some(ki) = &input.key_image {
                if utxo_set.key_image_seen(ki) { return false; }
                if !seen_in_tx.insert(ki.clone()) { return false; }
            } else { return false; }
        }
        true
    }
```

- [ ] **Step 3: Call it from both validation entry points**

Replace the call at `tx_validator.rs:473`:
```rust
        if tx.is_confidential() && !Self::validate_confidential(tx, utxo_set, network) {
            return false;
        }
```
And at `:722` (in `validate_transaction`, which lacks a `network` param — use the
mainnet default or thread the network through; confirm the function's available
context):
```rust
        if tx.is_confidential()
            && !Self::validate_confidential(tx, utxo_set, &NetworkMode::Mainnet)
        {
            return Err(StorageError::Other(format!(
                "confidential verification failed for tx {}", tx.hash
            )));
        }
```
> Confirm whether `validate_transaction` can access the real network; if it is
> only ever called for the local node's network, pass that. Otherwise prefer
> `validate_tx_for_network` as the consensus path and keep `validate_transaction`
> for mainnet/local use.

- [ ] **Step 4: Build**

Run: `cargo build --lib`
Expected: `Finished`.

- [ ] **Step 5: Commit**

```bash
git add engine/privacy/ringct/ring_validator.rs domain/transaction/tx_validator.rs
git commit -m "feat(privacy): wire confidential consensus checks; remove rejection gate"
```

---

### Task 7: End-to-end integration test (every defense fails closed)

**Files:**
- Create: `tests/ringct_phase1.rs` (or add to an existing integration test file)

- [ ] **Step 1: Write the integration test**

Build a valid confidential TX against a real `UtxoSet` (tempfile-backed) with the
ring members pre-recorded via `record_output_key`, then assert accept + each
tampered variant rejects:
```rust
// Pseudocode skeleton — fill with the crate's real constructors.
// 1. set = UtxoSet::new(tempdir)
// 2. build 4 ring keypairs; record each pubkey hex via set.record_output_key()
// 3. craft confidential tx (1 input, ring of those 4, signer idx k)
// 4. msg = TxHash::confidential_signing_message_for_network(&tx, &net)
// 5. sign with clsag::sign; set key_image + ring_signature hex
// 6. assert TxValidator::validate_confidential(&tx, &set, &net) == true
// 7. variant A: ring member not recorded -> false
// 8. variant B: tampered ring_signature -> false
// 9. variant C: key image pre-seeded via set.record_key_image() -> false
// 10. variant D: duplicate key image across two inputs -> false
// 11. variant E: message mismatch (sign over different fee) -> false
```

- [ ] **Step 2: Run**

Run: `cargo test --test ringct_phase1 -- --nocapture`
Expected: all assertions PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/ringct_phase1.rs
git commit -m "test(privacy): RingCT phase 1 end-to-end accept + fail-closed defenses"
```

---

### Task 8: Regenerate fixtures + full gate

**Files:** none new (verification + any fixture regen)

- [ ] **Step 1: Re-run full suite (canonical_bytes changed!)**

Run: `cargo test --lib`
Expected: PASS. If any transparent-TX hash fixtures fail because `canonical_bytes`
now appends the `ring_signature` tag byte, update those expected hashes (they are
test fixtures, not consensus data) — confirm each delta is exactly the appended
`0x00` per input.

- [ ] **Step 2: Regenerate genesis if its hash is affected**

Run: `cargo test --lib genesis 2>&1 | tail -20`
If genesis verification fails, re-mine via `cargo run --bin mine-genesis` and
update `config/genesis/genesis.rs` hashes/nonces. (Pre-launch network: acceptable.)

- [ ] **Step 3: Clippy**

Run: `cargo clippy --lib -- -D warnings`
Expected: clean; fix inline.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore(privacy): regenerate fixtures/genesis after canonical_bytes change; clippy clean"
```

---

## Self-review notes (coverage vs spec, sender-privacy scope)

- CLSAG serialization → Task 1. ✓
- Confidential signing message (binds key images + ring members + outputs, NOT
  commitments) → Task 2. ✓
- `ring_signature` field + canonical_bytes → Task 3. ✓
- Output-key index (`okey:`) + key-image store (`ki:`), atomic apply → Task 4. ✓
- CLSAG verify (no DB) → Task 5; DB-backed membership + key-image + gate removal →
  Task 6. ✓
- Fail-closed defenses (forge / fake decoy / double-spend / replay) → Task 7. ✓
- Canonical-bytes/genesis fixture regen → Task 8. ✓
- DEFERRED (not in this plan, per soundness decision): Pedersen balance, range
  proofs, dual-key CLSAG, UTXO commitment storage, wallet build/scan. ✓

## Risk callouts for the executor

- **Consensus-critical.** Execute task-by-task with review; never skip the
  fail-closed integration test (Task 7) before relying on the gate removal.
- `validate_transaction` lacks a `network` param — Step 6.3 must resolve which
  network it validates against; do not guess silently.
- Changing `canonical_bytes` changes every TX id and the genesis hash — Task 8 is
  mandatory, not optional.
- Stateless invariant: all new DB reads (`okey:`/`ki:`) live in the L4/UTXO stage
  via `TxValidator` (which already holds `&UtxoSet`); do NOT move them into the
  stateless L1–L3 block-validation layers.
