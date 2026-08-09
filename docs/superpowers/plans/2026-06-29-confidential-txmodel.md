# Confidential TX Data Model + Serialization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. This touches the consensus `canonical_bytes` encoding — run the full suite at the end. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Extend `TxInput`/`TxOutput` with the RingCT fields (ring commitments, pseudo-output commitment, one-time output pubkey), add Borromean `RangeProof` byte/hex serialization, and expose typed validated views (`parse_confidential_input`/`parse_confidential_output`) for sub-projects 3/4.

**Architecture:** Additive data-model change with TDD. New `Option<String>` fields (hex) on the existing structs, bound in `canonical_bytes`; range-proof serialization in `serialization.rs`; a new `tx_confidential.rs` decoder module that turns the hex fields into validated curve types. No consensus verification, no wallet construction.

**Tech Stack:** Rust, `curve25519-dalek` v4 (Ristretto/Scalar), `serde`/`bincode`, sub-project 1's `dual_clsag`.

**Spec:** `docs/superpowers/specs/2026-06-29-confidential-txmodel-design.md`

**Confirmed facts:** `RangeProof { bit_commitments: Vec<RistrettoPoint>, challenges: Vec<Scalar>, responses: Vec<[Scalar;2]> }`, `RANGE_BITS = 64`, `range_proof::prove(value: u64, blinding: &Scalar) -> RangeProof`, `range_proof::verify(&RistrettoPoint, &RangeProof) -> bool` (engine/privacy/confidential/range_proof.rs). `dual_clsag::{RingMember, DualCLSAGSignature, from_hex, to_hex}` exist. Adding a non-`Option`-defaulted field to a struct breaks every literal repo-wide — each task uses a build-then-fix loop.

---

### Task 1: Add `TxInput` RingCT fields + bind in canonical_bytes

**Files:**
- Modify: `domain/transaction/transaction.rs`

- [ ] **Step 1: Write the failing canonical-bytes test**

Add to the `#[cfg(test)] mod tests` in `transaction.rs`:
```rust
    #[test]
    fn ringct_input_fields_change_canonical_bytes() {
        let mut tx = Transaction::new(
            String::new(),
            vec![TxInput {
                txid: "b".repeat(64),
                index: 0,
                owner: "SD1o".into(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: Some("11".repeat(32)),
                ring_members: Some(vec!["22".repeat(32)]),
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
            }],
            vec![TxOutput::new("SD1x".into(), 10)],
            1,
            0,
        );
        let base = tx.canonical_bytes();
        tx.inputs[0].ring_commitments = Some(vec!["33".repeat(32)]);
        let after_rc = tx.canonical_bytes();
        assert_ne!(base, after_rc);
        tx.inputs[0].pseudo_commitment = Some("44".repeat(32));
        assert_ne!(after_rc, tx.canonical_bytes());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib transaction::tests::ringct_input_fields 2>&1 | head`
Expected: FAIL — no fields `ring_commitments` / `pseudo_commitment`.

- [ ] **Step 3: Add the fields**

In `struct TxInput`, after `ring_signature`:
```rust
    /// RingCT: commitment C_i for each ring member, parallel to `ring_members`
    /// (same length). ring_members[i] = P_i, ring_commitments[i] = C_i. Hex
    /// compressed Ristretto. None for transparent inputs.
    #[serde(default)]
    pub ring_commitments: Option<Vec<String>>,
    /// RingCT: per-input pseudo-output commitment C' (hex compressed Ristretto).
    /// None for transparent inputs.
    #[serde(default)]
    pub pseudo_commitment: Option<String>,
```

- [ ] **Step 4: Bind in `canonical_bytes`**

In `canonical_bytes()`, in the per-input section immediately after the
`ring_signature` block (the one ending with `} else { out.push(0x00); }` you added
earlier), append:
```rust
            match &input.ring_commitments {
                Some(cs) => {
                    out.push(0x01);
                    out.extend_from_slice(&(cs.len() as u32).to_le_bytes());
                    for c in cs {
                        let cb = c.as_bytes();
                        out.extend_from_slice(&(cb.len() as u32).to_le_bytes());
                        out.extend_from_slice(cb);
                    }
                }
                None => out.push(0x00),
            }
            match &input.pseudo_commitment {
                Some(pc) => {
                    out.push(0x01);
                    let pb = pc.as_bytes();
                    out.extend_from_slice(&(pb.len() as u32).to_le_bytes());
                    out.extend_from_slice(pb);
                }
                None => out.push(0x00),
            }
```

- [ ] **Step 5: Add fields to the two TxInput constructors**

In `TxInput::new(...)` and `TxInput::new_confidential(...)`, add to each struct
literal: `ring_commitments: None,` and `pseudo_commitment: None,`.

- [ ] **Step 6: Fix all other TxInput literals repo-wide (build-then-fix loop)**

Run: `cargo build --lib 2>&1 | grep -E "missing field (ring_commitments|pseudo_commitment)" -A1 | grep -oE "[a-zA-Z0-9_/\\\\.]+\.rs:[0-9]+"`
For each reported site, add `ring_commitments: None,` and `pseudo_commitment: None,`
to the literal. A `sed` for the common single-line case:
```bash
for f in <reported files>; do \
  sed -i -E 's/^([[:space:]]*)ring_signature: None,$/\1ring_signature: None,\n\1ring_commitments: None,\n\1pseudo_commitment: None,/' "$f"; done
```
Re-run `cargo build --lib` until it compiles. (Literals using `..Default::default()`
or `TxInput::new*` need no change.)

- [ ] **Step 7: Run the test + transaction suite**

Run: `cargo test --lib transaction::tests`
Expected: new test PASS; existing transaction tests PASS.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(privacy): TxInput ring_commitments + pseudo_commitment (canonical_bytes)"
```

---

### Task 2: Add `TxOutput.one_time_pubkey` + bind in canonical_bytes

**Files:**
- Modify: `domain/transaction/transaction.rs`

- [ ] **Step 1: Write the failing test**

Add to the test module:
```rust
    #[test]
    fn ringct_output_one_time_pubkey_changes_canonical_bytes() {
        let mut tx = Transaction::new(
            String::new(),
            vec![],
            vec![TxOutput::new("SD1x".into(), 10)],
            1,
            0,
        );
        let base = tx.canonical_bytes();
        tx.outputs[0].one_time_pubkey = Some("55".repeat(32));
        assert_ne!(base, tx.canonical_bytes());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib transaction::tests::ringct_output_one_time_pubkey 2>&1 | head`
Expected: FAIL — no field `one_time_pubkey`.

- [ ] **Step 3: Add the field**

In `struct TxOutput`, after `ephemeral_pubkey`:
```rust
    /// RingCT: full one-time output public key P (hex compressed Ristretto).
    /// The `address` is a truncated hash and cannot be a ring member; this
    /// carries the full point so the output can be a decoy and be recorded in
    /// the on-chain output-key index. None for transparent outputs.
    #[serde(default)]
    pub one_time_pubkey: Option<String>,
```

- [ ] **Step 4: Bind in `canonical_bytes`**

In `canonical_bytes()`, in the per-output section after the `ephemeral_pubkey`
handling, append:
```rust
            match &out.one_time_pubkey {
                Some(otk) => {
                    out_buf_push_one_time(&mut buf, otk);
                }
                None => buf.push(0x00),
            }
```
where you add a tiny local helper near `canonical_bytes` (or inline it):
```rust
fn out_buf_push_one_time(buf: &mut Vec<u8>, otk: &str) {
    buf.push(0x01);
    let b = otk.as_bytes();
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}
```
> Use the exact accumulator variable name from `canonical_bytes` (it is `buf` in
> the output loop per the existing code). If the existing output loop uses a
> different name, match it. Inline the bytes if you prefer no helper.

- [ ] **Step 5: Add to TxOutput constructors**

In `TxOutput::new(...)` and `TxOutput::new_confidential(...)`, add
`one_time_pubkey: None,` to each struct literal.

- [ ] **Step 6: Fix all other TxOutput literals repo-wide (build-then-fix loop)**

Run: `cargo build --lib 2>&1 | grep "missing field \`one_time_pubkey\`" -A1 | grep -oE "[a-zA-Z0-9_/\\\\.]+\.rs:[0-9]+"`
For the common `ephemeral_pubkey: None,` single-line case across reported files:
```bash
for f in <reported files>; do \
  sed -i -E 's/^([[:space:]]*)ephemeral_pubkey: None,$/\1ephemeral_pubkey: None,\n\1one_time_pubkey: None,/' "$f"; done
```
Then handle any remaining sites where `ephemeral_pubkey` is `Some(...)` or
multi-line manually. Re-run `cargo build --lib` (and later `--all-targets`) until
clean.

- [ ] **Step 7: Run tests**

Run: `cargo test --lib transaction::tests`
Expected: new test PASS; existing PASS.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(privacy): TxOutput one_time_pubkey field (canonical_bytes)"
```

---

### Task 3: Borromean RangeProof serialization

**Files:**
- Modify: `engine/privacy/ringct/serialization.rs`

- [ ] **Step 1: Write the failing test**

Add to `serialization.rs` tests:
```rust
    #[test]
    fn range_proof_round_trips_and_rejects_malformed() {
        use crate::engine::privacy::confidential::range_proof::{prove, verify};
        use curve25519_dalek::scalar::Scalar;
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use crate::engine::privacy::confidential::pedersen::generator_h;
        use rand::rngs::OsRng;

        let blind = Scalar::random(&mut OsRng);
        let proof = prove(42u64, &blind);
        let bytes = range_proof_to_bytes(&proof);
        let back = range_proof_from_bytes(&bytes).expect("decode");
        // Re-verify the decoded proof against the same commitment.
        let commitment = Scalar::from(42u64) * generator_h() + blind * RISTRETTO_BASEPOINT_POINT;
        assert!(verify(&commitment, &back));
        // Malformed
        assert!(range_proof_from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert!(range_proof_from_hex("zz").is_none());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib ringct::serialization::tests::range_proof 2>&1 | head`
Expected: FAIL — `range_proof_to_bytes` undefined.

- [ ] **Step 3: Implement RangeProof serialization**

Add to `serialization.rs`:
```rust
use crate::engine::privacy::confidential::range_proof::{RangeProof, RANGE_BITS};

/// Wire: nbits(u32 LE) || bit_commitments[nbits]·32 || challenges[nbits]·32
///       || responses[nbits]·64 (two scalars each).
pub fn range_proof_to_bytes(p: &RangeProof) -> Vec<u8> {
    let n = p.bit_commitments.len();
    let mut out = Vec::with_capacity(4 + n * (32 + 32 + 64));
    out.extend_from_slice(&(n as u32).to_le_bytes());
    for c in &p.bit_commitments {
        out.extend_from_slice(c.compress().as_bytes());
    }
    for e in &p.challenges {
        out.extend_from_slice(e.as_bytes());
    }
    for [s0, s1] in &p.responses {
        out.extend_from_slice(s0.as_bytes());
        out.extend_from_slice(s1.as_bytes());
    }
    out
}

pub fn range_proof_from_bytes(b: &[u8]) -> Option<RangeProof> {
    if b.len() < 4 {
        return None;
    }
    let n = u32::from_le_bytes(b[0..4].try_into().ok()?) as usize;
    if n != RANGE_BITS {
        return None;
    }
    let need = 4 + n * (32 + 32 + 64);
    if b.len() != need {
        return None;
    }
    let mut off = 4;
    let mut bit_commitments = Vec::with_capacity(n);
    for _ in 0..n {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b[off..off + 32]);
        bit_commitments.push(CompressedRistretto(arr).decompress()?);
        off += 32;
    }
    let mut challenges = Vec::with_capacity(n);
    for _ in 0..n {
        challenges.push(scalar_from(&b[off..off + 32])?);
        off += 32;
    }
    let mut responses = Vec::with_capacity(n);
    for _ in 0..n {
        let s0 = scalar_from(&b[off..off + 32])?;
        let s1 = scalar_from(&b[off + 32..off + 64])?;
        responses.push([s0, s1]);
        off += 64;
    }
    Some(RangeProof { bit_commitments, challenges, responses })
}

pub fn range_proof_to_hex(p: &RangeProof) -> String {
    hex::encode(range_proof_to_bytes(p))
}

pub fn range_proof_from_hex(h: &str) -> Option<RangeProof> {
    range_proof_from_bytes(&hex::decode(h).ok()?)
}
```
> `scalar_from`, `CompressedRistretto`, and `hex` are already in scope in
> `serialization.rs`. If `RangeProof`'s fields are not `pub`, this needs them
> public — they are (`pub bit_commitments`, `pub challenges`, `pub responses`).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --lib ringct::serialization::tests::range_proof`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add engine/privacy/ringct/serialization.rs
git commit -m "feat(privacy): Borromean RangeProof byte/hex serialization"
```

---

### Task 4: Typed validated views (`tx_confidential.rs`)

**Files:**
- Create: `engine/privacy/ringct/tx_confidential.rs`
- Modify: `lib.rs` (declare `pub mod tx_confidential;` under ringct)

- [ ] **Step 1: Declare the module**

In `lib.rs`, inside `pub mod ringct { ... }`, add `pub mod tx_confidential;`.

- [ ] **Step 2: Write the failing tests**

Create `engine/privacy/ringct/tx_confidential.rs`:
```rust
// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Typed, validated views of a confidential transaction's input/output fields.
//! Pure decoders: they turn the hex fields into curve types and reject anything
//! malformed. NO chain state and NO cryptographic verification (sub-project 3).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{TxInput, TxOutput};
    use crate::engine::privacy::ringct::dual_clsag::{self, RingMember};
    use crate::engine::privacy::ringct::serialization::range_proof_to_hex;
    use crate::engine::privacy::confidential::pedersen::generator_h;
    use crate::engine::privacy::confidential::range_proof::prove;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn hexp(p: &RistrettoPoint) -> String { hex::encode(p.compress().as_bytes()) }

    fn make_conf_input() -> (TxInput, Vec<RingMember>, RistrettoPoint) {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let n = 4usize;
        let idx = 1usize;
        let mut ring = Vec::new();
        for _ in 0..n {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            ring.push(RingMember { public_key: sk * g, commitment: Scalar::from(7u64) * h + bl * g });
        }
        let spend = Scalar::random(&mut OsRng);
        let r_pi = Scalar::random(&mut OsRng);
        ring[idx].public_key = spend * g;
        ring[idx].commitment = Scalar::from(7u64) * h + r_pi * g;
        let r_prime = Scalar::random(&mut OsRng);
        let pseudo = Scalar::from(7u64) * h + r_prime * g;
        let z = r_pi - r_prime;
        let sig = dual_clsag::sign(b"m", &ring, &pseudo, idx, &spend, &z).unwrap();

        let input = TxInput {
            txid: "0".repeat(64), index: 0, owner: String::new(),
            signature: String::new(), pub_key: String::new(),
            key_image: Some(hex::encode(sig.key_image.as_bytes())),
            ring_members: Some(ring.iter().map(|m| hexp(&m.public_key)).collect()),
            ring_signature: Some(dual_clsag::to_hex(&sig)),
            ring_commitments: Some(ring.iter().map(|m| hexp(&m.commitment)).collect()),
            pseudo_commitment: Some(hexp(&pseudo)),
        };
        (input, ring, pseudo)
    }

    #[test]
    fn parse_input_happy_path() {
        let (input, ring, pseudo) = make_conf_input();
        let view = parse_confidential_input(&input).expect("parse");
        assert_eq!(view.ring.len(), ring.len());
        assert_eq!(view.ring[0].public_key, ring[0].public_key);
        assert_eq!(view.ring[2].commitment, ring[2].commitment);
        assert_eq!(view.pseudo_out, pseudo);
    }

    #[test]
    fn parse_input_rejects_length_mismatch_and_garbage() {
        let (mut input, _, _) = make_conf_input();
        let mut rc = input.ring_commitments.clone().unwrap();
        rc.pop(); // length mismatch vs ring_members
        input.ring_commitments = Some(rc);
        assert!(parse_confidential_input(&input).is_none());

        let (mut input2, _, _) = make_conf_input();
        input2.pseudo_commitment = Some("00".repeat(32)); // not a valid point
        assert!(parse_confidential_input(&input2).is_none());

        let (mut input3, _, _) = make_conf_input();
        input3.ring_commitments = None; // missing
        assert!(parse_confidential_input(&input3).is_none());
    }

    #[test]
    fn parse_output_happy_and_reject() {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let blind = Scalar::random(&mut OsRng);
        let commitment = Scalar::from(9u64) * h + blind * g;
        let otk = Scalar::random(&mut OsRng) * g;
        let eph = Scalar::random(&mut OsRng) * g;
        let proof = prove(9u64, &blind);
        let output = TxOutput {
            address: "SD1s".into(), amount: 0,
            commitment: Some(hexp(&commitment)),
            range_proof: Some(range_proof_to_hex(&proof)),
            ephemeral_pubkey: Some(hexp(&eph)),
            one_time_pubkey: Some(hexp(&otk)),
        };
        let view = parse_confidential_output(&output).expect("parse");
        assert_eq!(view.commitment, commitment);
        assert_eq!(view.one_time_pubkey, otk);

        let mut bad = output.clone();
        bad.one_time_pubkey = Some("00".repeat(32)); // not a point
        assert!(parse_confidential_output(&bad).is_none());
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test --lib ringct::tx_confidential 2>&1 | head`
Expected: FAIL — `parse_confidential_input` / views undefined.

- [ ] **Step 4: Implement the views + parsers**

Add ABOVE the test module:
```rust
use crate::domain::transaction::transaction::{TxInput, TxOutput};
use crate::engine::privacy::ringct::dual_clsag::{self, DualCLSAGSignature, RingMember};
use crate::engine::privacy::ringct::serialization::{point_from_hex, range_proof_from_hex};
use crate::engine::privacy::confidential::range_proof::RangeProof;
use curve25519_dalek::ristretto::RistrettoPoint;

pub struct ConfidentialInputView {
    pub ring: Vec<RingMember>,
    pub pseudo_out: RistrettoPoint,
    pub signature: DualCLSAGSignature,
    pub key_image: RistrettoPoint,
}

pub struct ConfidentialOutputView {
    pub commitment: RistrettoPoint,
    pub one_time_pubkey: RistrettoPoint,
    pub ephemeral_pubkey: RistrettoPoint,
    pub range_proof: RangeProof,
}

/// Decode + validate a confidential input. `None` if any field is missing, the
/// ring/commitment/response lengths disagree, or any point/scalar is malformed.
pub fn parse_confidential_input(input: &TxInput) -> Option<ConfidentialInputView> {
    let members = input.ring_members.as_ref()?;
    let commits = input.ring_commitments.as_ref()?;
    if members.is_empty() || members.len() != commits.len() {
        return None;
    }
    let mut ring = Vec::with_capacity(members.len());
    for (p_hex, c_hex) in members.iter().zip(commits.iter()) {
        ring.push(RingMember {
            public_key: point_from_hex(p_hex)?,
            commitment: point_from_hex(c_hex)?,
        });
    }
    let pseudo_out = point_from_hex(input.pseudo_commitment.as_ref()?)?;
    let signature = dual_clsag::from_hex(input.ring_signature.as_ref()?)?;
    if signature.s.len() != ring.len() {
        return None;
    }
    let key_image = signature.key_image.decompress()?;
    Some(ConfidentialInputView { ring, pseudo_out, signature, key_image })
}

/// Decode + validate a confidential output. `None` on missing/malformed fields.
pub fn parse_confidential_output(output: &TxOutput) -> Option<ConfidentialOutputView> {
    let commitment = point_from_hex(output.commitment.as_ref()?)?;
    let one_time_pubkey = point_from_hex(output.one_time_pubkey.as_ref()?)?;
    let ephemeral_pubkey = point_from_hex(output.ephemeral_pubkey.as_ref()?)?;
    let range_proof = range_proof_from_hex(output.range_proof.as_ref()?)?;
    Some(ConfidentialOutputView { commitment, one_time_pubkey, ephemeral_pubkey, range_proof })
}
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --lib ringct::tx_confidential`
Expected: 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add engine/privacy/ringct/tx_confidential.rs lib.rs
git commit -m "feat(privacy): typed validated confidential input/output views"
```

---

### Task 5: serde round-trip + full gate

**Files:**
- Modify: `domain/transaction/transaction.rs` (one serde test)

- [ ] **Step 1: Write the serde round-trip test**

Add to the transaction test module:
```rust
    #[test]
    fn confidential_tx_serde_round_trips() {
        let mut tx = Transaction::new(
            String::new(),
            vec![TxInput {
                txid: "b".repeat(64), index: 0, owner: "o".into(),
                signature: String::new(), pub_key: String::new(),
                key_image: Some("11".repeat(32)),
                ring_members: Some(vec!["22".repeat(32), "33".repeat(32)]),
                ring_signature: Some("aa".repeat(40)),
                ring_commitments: Some(vec!["44".repeat(32), "55".repeat(32)]),
                pseudo_commitment: Some("66".repeat(32)),
            }],
            vec![TxOutput {
                address: "SD1s".into(), amount: 0,
                commitment: Some("77".repeat(32)),
                range_proof: Some("88".repeat(10)),
                ephemeral_pubkey: Some("99".repeat(32)),
                one_time_pubkey: Some("aa".repeat(32)),
            }],
            5, 1_700_000_000,
        );
        tx.tx_type = TxType::Confidential;
        let bytes = bincode::serialize(&tx).unwrap();
        let back: Transaction = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.inputs[0].ring_commitments, tx.inputs[0].ring_commitments);
        assert_eq!(back.inputs[0].pseudo_commitment, tx.inputs[0].pseudo_commitment);
        assert_eq!(back.outputs[0].one_time_pubkey, tx.outputs[0].one_time_pubkey);
        assert_eq!(back.canonical_bytes(), tx.canonical_bytes());
    }
```

- [ ] **Step 2: Run**

Run: `cargo test --lib transaction::tests::confidential_tx_serde_round_trips`
Expected: PASS.

- [ ] **Step 3: Build all targets + fix any remaining missing-field literals**

Run: `cargo build --all-targets 2>&1 | tail -20`
Expected: `Finished`. If any bin/test literal still lacks the new fields, add them
(build-then-fix loop) until clean.

- [ ] **Step 4: Full lib suite (canonical_bytes changed)**

Run: `cargo test --lib 2>&1 | tail -3`
Expected: all pass. Coinbase/genesis unaffected (no inputs, transparent outputs).
If a transparent-TX hash fixture changed, confirm the delta is exactly the
appended `0x00` markers and update the fixture.

- [ ] **Step 5: Clippy**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: clean. Fix inline.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "test(privacy): confidential TX serde round-trip; data-model gate green"
```

---

## Self-review notes (coverage vs spec)
- TxInput `ring_commitments` + `pseudo_commitment` → Task 1. ✓
- TxOutput `one_time_pubkey` → Task 2. ✓
- canonical_bytes binds all new fields → Tasks 1, 2 (+ asserted in 1, 2, 5). ✓
- RangeProof byte/hex serialization, reject malformed → Task 3. ✓
- `parse_confidential_input` / `parse_confidential_output` + views, reject
  malformed/length-mismatch → Task 4. ✓
- serde round-trip; transparent/coinbase unaffected → Task 5. ✓
- ring members inline as parallel P_i/C_i arrays → Task 1 + Task 4 parser. ✓
- Non-goals (consensus verify, balance, wallet, removing single-key path,
  bincode v2) → not present. ✓
- Type consistency: `RingMember`, `DualCLSAGSignature`, `from_hex`/`to_hex`,
  `point_from_hex`, `range_proof_*` names match sub-project 1 + Task 3. ✓
